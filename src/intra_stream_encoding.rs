use anyhow::{Result, anyhow};

use crate::{
    array_array::{ArrayArray, IpPacketBuffer},
    constants::MAX_IP_PACKET_LENGTH,
    cursors::{ReadCursor, ReadCursorContiguous, WriteCursorContiguous},
    serdes::{Deserializable, DeserializeError, Serializable, SerializableLength},
    socks5_serdes::SocksDestination,
};

pub(crate) fn make_encoder(destination: &SocksDestination) -> InitiatorEncoderNeedsOutput {
    let mut write_cursor =
        WriteCursorContiguous::new(ArrayArray::new_empty(destination.serialized_length()));
    destination.serialize(&mut write_cursor);
    InitiatorEncoderNeedsOutput {
        cursor: ReadCursorContiguous::new(write_cursor.into_inner()),
    }
}

/// Encoder for the "initiator" side of the connection, that sends destination address.
#[derive(Debug)]
pub(crate) enum InitiatorEncoder {
    NeedsInput(InitiatorEncoderNeedsInput),
    NeedsOutput(InitiatorEncoderNeedsOutput),
}

#[derive(Debug)]
pub(crate) struct InitiatorEncoderNeedsInput {
    _zst: (),
}

#[derive(Debug)]
pub(crate) struct InitiatorEncoderNeedsOutput {
    cursor: ReadCursorContiguous<IpPacketBuffer>,
}

impl InitiatorEncoderNeedsInput {
    pub(crate) fn encode(self, packet: &[u8]) -> InitiatorEncoderNeedsOutput {
        // at some point in the future we may add scheduling framing information here
        InitiatorEncoderNeedsOutput {
            cursor: ReadCursorContiguous::new(IpPacketBuffer::new(packet)),
        }
    }
}

impl InitiatorEncoderNeedsOutput {
    /// Return how much of the output was filled, and a new Encoder
    pub(crate) fn encode(mut self, output: &mut [u8]) -> (usize, InitiatorEncoder) {
        let num_bytes_written = self.cursor.read_as_much_as_possible(output);
        let new_encoder = if self.cursor.empty() {
            InitiatorEncoder::NeedsInput(InitiatorEncoderNeedsInput { _zst: () })
        } else {
            InitiatorEncoder::NeedsOutput(self)
        };
        (num_bytes_written, new_encoder)
    }
}

#[derive(Debug)]
pub(crate) enum InitiatorDecoder {
    Destination(InitiatorDestinationDecoder),
    Body(InitiatorBodyDecoder),
}

#[derive(Debug)]
pub(crate) struct InitiatorDestinationDecoder {
    _zst: (),
}

impl InitiatorDestinationDecoder {
    pub(crate) fn new() -> Self {
        InitiatorDestinationDecoder { _zst: () }
    }
}

impl InitiatorDestinationDecoder {
    pub(crate) fn decode(
        self,
        read_cursor: &mut impl ReadCursor,
    ) -> Result<(InitiatorDecoder, Option<SocksDestination>)> {
        match SocksDestination::deserialize(read_cursor) {
            Ok(destination) => Ok((
                InitiatorDecoder::Body(InitiatorBodyDecoder { _zst: () }),
                Some(destination),
            )),
            Err(DeserializeError::Truncated) => Ok((InitiatorDecoder::Destination(self), None)),
            Err(e) => Err(anyhow!(e)),
        }
    }
}

// no actual methods, just exists as a token so that you can't use it until you've read a destination
#[derive(Debug)]
pub(crate) struct InitiatorBodyDecoder {
    _zst: (),
}

impl InitiatorBodyDecoder {
    pub(crate) fn decode(&mut self, read_cursor: &mut impl ReadCursor) -> Option<IpPacketBuffer> {
        (!read_cursor.empty()).then(|| {
            // TODO split out IpPacketBuffer from read_cursor construction?
            let mut buffer = IpPacketBuffer::new_empty(std::cmp::min(
                read_cursor.num_read_bytes_left(),
                MAX_IP_PACKET_LENGTH,
            ));
            read_cursor.read_as_much_as_possible(&mut buffer);
            buffer
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cursors::ReadCursorContiguous;
    use crate::socks5_serdes::{SocksAddress, SocksDestination};
    use std::net::{IpAddr, Ipv4Addr};

    const SOCKS_DESTINATION: SocksDestination = SocksDestination {
        address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        port: 8080,
    };

    #[test]
    fn simple_round_trip() {
        const DESTINATION_LENGTH: usize = 7;

        let mut buffer = [0u8; 1024];
        let encoder = make_encoder(&SOCKS_DESTINATION);
        let (bytes_written, encoder) = encoder.encode(&mut buffer);
        assert_eq!(bytes_written, DESTINATION_LENGTH);
        // pretty impressive: copilot converted 8080 to 31, 144 correctly!
        assert_eq!(&buffer[..DESTINATION_LENGTH], &[1, 192, 168, 1, 1, 31, 144]);
        let InitiatorEncoder::NeedsInput(encoder) = encoder else {
            panic!();
        };
        let encoder = encoder.encode(&[1, 2, 3, 4]);
        let (bytes_written, InitiatorEncoder::NeedsOutput(encoder)) =
            encoder.encode(&mut buffer[DESTINATION_LENGTH..DESTINATION_LENGTH + 2])
        else {
            panic!();
        };
        assert_eq!(bytes_written, 2);
        assert_eq!(&buffer[DESTINATION_LENGTH..DESTINATION_LENGTH + 2], &[1, 2]);
        let (bytes_written, InitiatorEncoder::NeedsInput(_)) =
            encoder.encode(&mut buffer[DESTINATION_LENGTH + 2..DESTINATION_LENGTH + 4])
        else {
            panic!();
        };
        assert_eq!(bytes_written, 2);
        assert_eq!(
            &buffer[DESTINATION_LENGTH + 2..DESTINATION_LENGTH + 4],
            &[3, 4]
        );

        let decoder = InitiatorDestinationDecoder::new();
        let mut short_read_cursor =
            ReadCursorContiguous::new(IpPacketBuffer::new(&buffer[..DESTINATION_LENGTH - 1]));
        let (decoder, destination) = decoder.decode(&mut short_read_cursor).unwrap();
        assert!(destination.is_none());
        let InitiatorDecoder::Destination(decoder) = decoder else {
            panic!();
        };

        let mut full_read_cursor =
            ReadCursorContiguous::new(IpPacketBuffer::new(&buffer[..DESTINATION_LENGTH + 4]));
        let (decoder, destination) = decoder.decode(&mut full_read_cursor).unwrap();
        assert_eq!(destination, Some(SOCKS_DESTINATION));
        let InitiatorDecoder::Body(mut decoder) = decoder else {
            panic!();
        };
        let body = decoder.decode(&mut full_read_cursor).unwrap();
        assert_eq!(body.as_ref(), &[1, 2, 3, 4]);
    }
}
