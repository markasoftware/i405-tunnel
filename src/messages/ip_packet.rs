use enumflags2::{BitFlag, BitFlags, bitflags};

use crate::array_array::IpPacketBuffer;
use crate::messages::{DeserializeMessageErr, ReadCursor, deserialize_type_byte, serdes};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct IpPacket {
    schedule: Option<u64>, // timestamp
    fragmentation_id: Option<u16>,
    packet: IpPacketBuffer,
}

// Type bytes 0x10 through 0x1F are reserved for IP packet start. The low bit indicates whether the
// packet shall be fragmented, and the second lowest bit indicates whether the packet is scheduled.
// The next two bits shall not be set.

impl IpPacket {
    const TYPE_BYTE_LOW: u8 = 0x10;
    const TYPE_BYTE_HIGH: u8 = 0x1F;

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        Self::TYPE_BYTE_LOW <= type_byte && type_byte <= Self::TYPE_BYTE_HIGH
    }
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
        let mut flags = IpPacketFlags::empty();
        if self.fragmentation_id.is_some() {
            flags |= IpPacketFlags::Fragmented;
        }
        if self.schedule.is_some() {
            flags |= IpPacketFlags::Scheduled;
        }
        let type_byte = Self::TYPE_BYTE_LOW | flags.bits();
        type_byte.serialize(serializer);

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
        let type_byte: u8 = read_cursor.read()?;
        assert!(Self::TYPE_BYTE_LOW <= type_byte && type_byte <= Self::TYPE_BYTE_HIGH, "type byte out of range for IP packet");

        let flag_bits = type_byte & (Self::TYPE_BYTE_LOW-1);
        let flags: BitFlags<IpPacketFlags> = BitFlags::try_from(flag_bits)
            .map_err(|_| DeserializeMessageErr::UnknownIPFlagBytes(flag_bits))?;

        let fragmentation_id = if flags.contains(IpPacketFlags::Fragmented) {
            Some(read_cursor.read()?)
        } else {
            None
        };

        let schedule = if flags.contains(IpPacketFlags::Scheduled) {
            Some(read_cursor.read()?)
        } else {
            None
        };

        Ok(IpPacket {
            fragmentation_id,
            schedule,
            packet: read_cursor.read()?,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::array_array::IpPacketBuffer;
    use crate::messages::serdes::SerializableLength as _;
    use crate::messages::{
        Message,
        ip_packet::IpPacket,
        test::assert_roundtrip_message,
    };

    #[test]
    fn roundtrip_ip_packet() {
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: None,
            schedule: None,
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: Some(258),
            schedule: Some(99),
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: None,
            schedule: Some(99),
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        let mut test_vec = Vec::new();
        for i in 0..500 {
            test_vec.push((i % 256).try_into().unwrap());
        }
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: None,
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
