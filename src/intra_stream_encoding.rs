use anyhow::{Result, anyhow};

use crate::{
    array_array::{ArrayArray, IpPacketBuffer}, constants::MAX_IP_PACKET_LENGTH, cursors::{ReadCursor, ReadCursorContiguous, WriteCursorContiguous}, serdes::{Deserializable, DeserializeError, Serializable, SerializableLength}, socks5_serdes::SocksDestination
};

pub(crate) fn make_encoder(destination: &SocksDestination) -> EncoderNeedsOutput {
    let mut write_cursor = WriteCursorContiguous::new(ArrayArray::new_empty(destination.serialized_length()));
    destination.serialize(&mut write_cursor);
    EncoderNeedsOutput {
        cursor: ReadCursorContiguous::new(write_cursor.into_inner())
    }
}

#[derive(Debug)]
pub(crate) enum Encoder {
    NeedsInput(EncoderNeedsInput),
    NeedsOutput(EncoderNeedsOutput),
}

/// An encoder that needs more input before it can proceed
#[derive(Debug)]
pub(crate) struct EncoderNeedsInput {}

#[derive(Debug)]
pub(crate) struct EncoderNeedsOutput {
    cursor: ReadCursorContiguous<IpPacketBuffer>,
}

impl EncoderNeedsInput {
    pub(crate) fn write(self, packet: &[u8]) -> EncoderNeedsOutput {
        // at some point in the future we may add scheduling framing information here
        EncoderNeedsOutput {
            cursor: ReadCursorContiguous::new(IpPacketBuffer::new(packet)),
        }
    }
}

impl EncoderNeedsOutput {
    /// Return how much of the output was filled, and a new Encoder
    pub(crate) fn read(mut self, output: &mut [u8]) -> (usize, Encoder) {
        let num_bytes_written = self.cursor.read_as_much_as_possible(output);
        let new_encoder = if self.cursor.empty() {
            Encoder::NeedsInput(EncoderNeedsInput {})
        } else {
            Encoder::NeedsOutput(self)
        };
        (num_bytes_written, new_encoder)
    }
}

pub(crate) enum Decoder {
    Destination,
    Body,
}

pub(crate) enum T2IEvent {
    StreamOpened { destination: SocksDestination },
    StreamData { data: IpPacketBuffer },
}

impl Decoder {
    pub(crate) fn new() -> Self {
        Decoder::Destination
    }

    pub(crate) fn decode(&mut self, input: &[u8]) -> Result<Option<(usize, T2IEvent)>> {
        match self {
            Decoder::Destination => {
                let mut read_cursor = ReadCursorContiguous::new(input);
                match SocksDestination::deserialize(&mut read_cursor) {
                    Ok(destination) => {
                        let num_bytes_read = read_cursor.position();
                        Ok(Some((
                            num_bytes_read,
                            T2IEvent::StreamOpened { destination },
                        )))
                    }
                    Err(DeserializeError::Truncated) => Ok(None),
                    Err(e) => Err(anyhow!(e)),
                }
            }
            Decoder::Body => {
                let amount_to_read = std::cmp::min(input.len(), MAX_IP_PACKET_LENGTH);
                Ok(Some((
                    amount_to_read,
                    T2IEvent::StreamData {
                        data: IpPacketBuffer::new(&input[0..amount_to_read]),
                    },
                )))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::socks5_serdes::{SocksAddress, SocksDestination};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn round_trip() {
        // 1. Setup destination and some data
        let destination = SocksDestination { address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), port: 5678 };
        let data1 = b"hello world";
        let data2 = b"goodbye world";

        // 2. Encode destination
        let mut encoder = Encoder::NeedsOutput(make_encoder(&destination));
        let mut encoded_buffer = Vec::new();
        let mut temp_buf = [0u8; 4]; // small buffer to test partial reads

        while let Encoder::NeedsOutput(needs_output) = encoder {
            let (bytes_written, new_encoder) = needs_output.read(&mut temp_buf);
            encoded_buffer.extend_from_slice(&temp_buf[..bytes_written]);
            encoder = new_encoder;
        }

        // 3. Decode destination
        let mut decoder = Decoder::new();
        let (bytes_read, event) = decoder.decode(&encoded_buffer).unwrap().unwrap();
        assert_eq!(bytes_read, encoded_buffer.len());
        if let T2IEvent::StreamOpened {
            destination: decoded_dest,
        } = event
        {
            assert_eq!(destination, decoded_dest);
        } else {
            panic!("Expected StreamOpened event");
        }
        // Manually transition state.
        decoder = Decoder::Body;

        // 4. Encode data1
        let encoder_needs_input = match encoder {
            Encoder::NeedsInput(e) => e,
            _ => panic!("Expected NeedsInput state"),
        };
        encoder = Encoder::NeedsOutput(encoder_needs_input.write(data1));
        let mut encoded_buffer = Vec::new();
        while let Encoder::NeedsOutput(needs_output) = encoder {
            let (bytes_written, new_encoder) = needs_output.read(&mut temp_buf);
            encoded_buffer.extend_from_slice(&temp_buf[..bytes_written]);
            encoder = new_encoder;
        }

        // 5. Decode data1
        let (bytes_read, event) = decoder.decode(&encoded_buffer).unwrap().unwrap();
        assert_eq!(bytes_read, data1.len());
        assert_eq!(bytes_read, encoded_buffer.len());
        if let T2IEvent::StreamData { data } = event {
            assert_eq!(data.as_ref(), data1);
        } else {
            panic!("Expected StreamData event");
        }

        // 6. Encode data2
        let encoder_needs_input = match encoder {
            Encoder::NeedsInput(e) => e,
            _ => panic!("Expected NeedsInput state"),
        };
        encoder = Encoder::NeedsOutput(encoder_needs_input.write(data2));
        let mut encoded_buffer = Vec::new();
        while let Encoder::NeedsOutput(needs_output) = encoder {
            let (bytes_written, new_encoder) = needs_output.read(&mut temp_buf);
            encoded_buffer.extend_from_slice(&temp_buf[..bytes_written]);
            encoder = new_encoder;
        }

        // 7. Decode data2
        let (bytes_read, event) = decoder.decode(&encoded_buffer).unwrap().unwrap();
        assert_eq!(bytes_read, data2.len());
        assert_eq!(bytes_read, encoded_buffer.len());
        if let T2IEvent::StreamData { data } = event {
            assert_eq!(data.as_ref(), data2);
        } else {
            panic!("Expected StreamData event");
        }
    }

    #[test]
    fn decode_partial_destination() {
        let destination = SocksDestination { address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), port: 5678 };
        let mut encoder = Encoder::NeedsOutput(make_encoder(&destination));
        let mut encoded_buffer = Vec::new();
        let mut temp_buf = [0u8; 256];

        // Get the full encoded destination
        if let Encoder::NeedsOutput(needs_output) = encoder {
            let (bytes_written, new_encoder) = needs_output.read(&mut temp_buf);
            encoded_buffer.extend_from_slice(&temp_buf[..bytes_written]);
            encoder = new_encoder;
        } else {
            panic!("should be NeedsOutput");
        }
        // It should be fully read and now NeedsInput
        assert!(matches!(encoder, Encoder::NeedsInput(_)));

        let mut decoder = Decoder::new();
        // Feed one byte less than required
        let result = decoder
            .decode(&encoded_buffer[..encoded_buffer.len() - 1])
            .unwrap();
        assert!(result.is_none());

        // Feed full buffer
        let (bytes_read, event) = decoder.decode(&encoded_buffer).unwrap().unwrap();
        assert_eq!(bytes_read, encoded_buffer.len());
        if let T2IEvent::StreamOpened {
            destination: decoded_dest,
        } = event
        {
            assert_eq!(destination, decoded_dest);
        } else {
            panic!("Expected StreamOpened event");
        }
    }

    #[test]
    fn decode_data_larger_than_max_packet() {
        let mut decoder = Decoder::Body;
        let large_data = vec![0u8; MAX_IP_PACKET_LENGTH + 100];
        let (bytes_read, event) = decoder.decode(&large_data).unwrap().unwrap();
        assert_eq!(bytes_read, MAX_IP_PACKET_LENGTH);
        if let T2IEvent::StreamData { data } = event {
            assert_eq!(data.len(), MAX_IP_PACKET_LENGTH);
            assert_eq!(data.as_ref(), &large_data[..MAX_IP_PACKET_LENGTH]);
        } else {
            panic!("Expected StreamData");
        }
    }

    #[test]
    fn round_trip_empty_data() {
        let mut encoder = Encoder::NeedsInput(EncoderNeedsInput {});
        let data = b"";

        // Encode
        let encoder_needs_input = match encoder {
            Encoder::NeedsInput(e) => e,
            _ => panic!("Expected NeedsInput state"),
        };
        encoder = Encoder::NeedsOutput(encoder_needs_input.write(data));
        let mut encoded_buffer = Vec::new();
        let mut temp_buf = [0u8; 4];
        while let Encoder::NeedsOutput(needs_output) = encoder {
            let (bytes_written, new_encoder) = needs_output.read(&mut temp_buf);
            assert_eq!(bytes_written, 0);
            encoded_buffer.extend_from_slice(&temp_buf[..bytes_written]);
            encoder = new_encoder;
        }
        assert!(encoded_buffer.is_empty());
        assert!(matches!(encoder, Encoder::NeedsInput(_)));

        // Decode
        let mut decoder = Decoder::Body;
        let (bytes_read, event) = decoder.decode(&encoded_buffer).unwrap().unwrap();
        assert_eq!(bytes_read, 0);
        if let T2IEvent::StreamData { data } = event {
            assert!(data.is_empty());
        } else {
            panic!("Expected StreamData");
        }
    }
}
