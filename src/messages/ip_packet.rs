use enumflags2::{BitFlag, BitFlags, bitflags};
use thiserror::Error;

use crate::array_array::IpPacketBuffer;
use crate::messages::serdes::SerializableLength as _;
use crate::messages::{DeserializeMessageErr, ReadCursor, deserialize_type_byte, serdes};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct IpPacket {
    schedule: Option<u64>, // timestamp
    fragmentation: Option<IpPacketFragmentation>,
    packet: IpPacketBuffer,
}

impl IpPacket {
    pub const TYPE_BYTE: u8 = 10;

    pub(crate) fn new(packet: IpPacketBuffer, schedule: Option<u64>) -> IpPacket {
        IpPacket {
            schedule,
            fragmentation: None,
            packet,
        }
    }

    /// Take a (possibly already fragmented) packet and fragment it into one packet less than the
    /// requested size, and then a "remainder" packet (which may be larger than the requested
    /// fragment size and should be further fragmented if needed).
    ///
    /// next_identification is the identification of the next newly fragmented packet. When
    /// fragmenting an already-fragmented message, the identification of the input message is used
    /// instead of `next_identification`
    fn fragment(
        self,
        fragment_length: usize,
        mut next_identification: u16,
    ) -> Result<Fragments, FragmentationError> {
        // No need to fragment:
        if self.serialized_length() <= fragment_length {
            return Ok(Fragments {
                first_fragment: self,
                second_fragment: None,
                next_identification,
            });
        }

        // We need to fragment further. If we don't already have fragmentation info, add it.
        let first_fragment_fragmentation = match self.fragmentation {
            Some(fragmentation) => fragmentation,
            None => {
                let identification = next_identification;
                next_identification = next_identification.wrapping_add(1);
                IpPacketFragmentation {
                    identification,
                    offset: 0,
                }
            }
        };

        // Figure out the "base size" of the current IP packet, without any content. This makes the
        // (currently true) assumption that there is no variable-length encoding of the content
        // length or anything (ie, the only dependency of the overall message length on the inner
        // packet length is the packet field itself).
        let base_length = self.serialized_length() - self.packet.len();
        let minimum_fragment_length = base_length.checked_add(1).unwrap();

        if fragment_length < minimum_fragment_length {
            return Err(FragmentationError::FragmentLengthTooSmall(
                fragment_length,
                minimum_fragment_length,
            ));
        }

        let first_fragment_packet_length = fragment_length.checked_sub(base_length).unwrap();
        let first_fragment = IpPacket {
            packet: IpPacketBuffer::new(&self.packet[..first_fragment_packet_length]),
            fragmentation: Some(first_fragment_fragmentation),
            ..self
        };

        let second_fragment = IpPacket {
            packet: IpPacketBuffer::new(&self.packet[first_fragment_packet_length..]),
            fragmentation: Some(IpPacketFragmentation {
                identification: first_fragment_fragmentation.identification,
                offset: first_fragment_fragmentation
                    .offset
                    .checked_add(first_fragment_packet_length.try_into().unwrap())
                    .unwrap(),
            }),
            ..self
        };

        Ok(Fragments {
            first_fragment,
            second_fragment: Some(second_fragment),
            next_identification,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fragments {
    /// The start of the packet, fragmented to be less than or equal to the requested fragment size.
    first_fragment: IpPacket,
    /// The remainder of the packet, if the packet had to be fragmented further.
    second_fragment: Option<IpPacket>,
    /// Should be passed as `identification` to the next call of `fragment`, whether that's on this
    /// packet or another one.
    next_identification: u16,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub(crate) enum FragmentationError {
    #[error(
        "The requested fragment size {0} was too small for a useful fragment; needs to be at least {1}"
    )]
    FragmentLengthTooSmall(usize, usize),
}

/// despite the name, this is /our/ custom fragmentation implementation, we don't attempt to piggy
/// back off actual IP fragmentation at all, in the name of not messing with the underlying IP
/// packets at all.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct IpPacketFragmentation {
    pub(crate) identification: u16,
    pub(crate) offset: u16,
}

#[bitflags]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum IpPacketFlags {
    Fragmented = 1 << 0,
    Scheduled = 1 << 1,
}

impl serdes::Serializable for IpPacket {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);

        let mut flags = IpPacketFlags::empty();
        if self.fragmentation.is_some() {
            flags |= IpPacketFlags::Fragmented;
        }
        if self.schedule.is_some() {
            flags |= IpPacketFlags::Scheduled;
        }
        flags.bits().serialize(serializer);

        if let Some(fragmentation) = self.fragmentation {
            fragmentation.identification.serialize(serializer);
            fragmentation.offset.serialize(serializer);
        }

        if let Some(schedule) = self.schedule {
            schedule.serialize(serializer);
        }

        self.packet.serialize(serializer);
    }
}

impl serdes::Deserializable for IpPacket {
    fn deserialize<T: AsRef<[u8]>>(
        read_cursor: &mut ReadCursor<T>,
    ) -> Result<Self, DeserializeMessageErr> {
        deserialize_type_byte!(read_cursor);

        let flag_bits = read_cursor.read()?;
        let flags: BitFlags<IpPacketFlags> = BitFlags::try_from(flag_bits)
            .map_err(|_| DeserializeMessageErr::UnknownIPFlagBytes(flag_bits))?;

        let fragmentation = if flags.contains(IpPacketFlags::Fragmented) {
            Some(IpPacketFragmentation {
                identification: read_cursor.read()?,
                offset: read_cursor.read()?,
            })
        } else {
            None
        };

        let schedule = if flags.contains(IpPacketFlags::Scheduled) {
            Some(read_cursor.read()?)
        } else {
            None
        };

        Ok(IpPacket {
            fragmentation,
            schedule,
            packet: read_cursor.read()?,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::array_array::IpPacketBuffer;
    use crate::messages::ip_packet::{FragmentationError, Fragments};
    use crate::messages::serdes::SerializableLength as _;
    use crate::messages::{
        Message,
        ip_packet::{IpPacket, IpPacketFragmentation},
        test::assert_roundtrip_message,
    };

    #[test]
    fn roundtrip_ip_packet() {
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation: None,
            schedule: None,
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation: Some(IpPacketFragmentation {
                identification: 1234,
                offset: 4321,
            }),
            schedule: Some(99),
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation: None,
            schedule: Some(99),
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        let mut test_vec = Vec::new();
        for i in 0..500 {
            test_vec.push((i % 256).try_into().unwrap());
        }
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation: None,
            schedule: None,
            packet: IpPacketBuffer::new(test_vec.as_ref()),
        }));
    }

    /// Fragment an IP packet that is not already fragmented.
    #[test]
    fn fragment_ip_packet() {
        let ip_packet = IpPacket::new(IpPacketBuffer::new(&[1, 2, 3, 4]), Some(42));
        let ip_message_length = 16;
        assert!(ip_packet.serialized_length() == ip_message_length);

        // first, try a no-op fragment
        let noop_fragment = ip_packet.clone().fragment(ip_message_length, 0).unwrap();
        assert_eq!(
            noop_fragment,
            Fragments {
                first_fragment: ip_packet.clone(),
                second_fragment: None,
                next_identification: 0,
            }
        );

        // now try fragmenting it too short
        let too_short_error = ip_packet
            .clone()
            .fragment(ip_message_length - 4, 0)
            .expect_err("Should result in error when fragment_length is too short");
        assert_eq!(
            too_short_error,
            FragmentationError::FragmentLengthTooSmall(
                ip_message_length - 4,
                ip_message_length - 3
            )
        );

        // now just right!
        let fragments = ip_packet
            .clone()
            .fragment(ip_message_length - 2, 0)
            .unwrap();
        assert_eq!(fragments.first_fragment, IpPacket {
            schedule: Some(42),
            fragmentation: Some(IpPacketFragmentation {
                identification: 0,
                offset: 0,
            }),
            packet: IpPacketBuffer::new(&[1, 2]),
        });
    }
}
