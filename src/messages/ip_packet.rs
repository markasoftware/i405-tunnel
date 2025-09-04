use enumflags2::{BitFlag, BitFlags, bitflags};

use crate::messages::ReadCursor;
use crate::reliability::ReliabilityAction;
use crate::{array_array::IpPacketBuffer, serdes::DeserializeError};

use super::MessageTrait;
use crate::serdes::{Deserializable, Serializable, SerializableLength as _, Serializer};
use anyhow::{Result, anyhow};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct IpPacket {
    pub(crate) fragmentation_id: Option<u16>,
    pub(crate) packet: IpPacketBuffer,
}

// Type bytes 0x10 through 0x1F are reserved for IP packet start. The low bit indicates whether the
// packet shall be fragmented, and the second lowest bit indicates whether the packet is scheduled.
// The next two bits shall not be set.

impl IpPacket {
    const TYPE_BYTE_LOW: u8 = 0x10;
    const TYPE_BYTE_HIGH: u8 = 0x1F;

    /// The size of a serialized IpPacket is the return value of this function plus the length of
    /// the packet.
    pub(crate) fn base_length(fragmentation_id: Option<u16>) -> usize {
        Self {
            fragmentation_id,
            packet: IpPacketBuffer::new_empty(0),
        }
        .serialized_length()
    }

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        (Self::TYPE_BYTE_LOW..=Self::TYPE_BYTE_HIGH).contains(&type_byte)
    }
}

#[bitflags]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum IpPacketFlags {
    Fragmented = 1 << 0,
}

impl MessageTrait for IpPacket {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for IpPacket {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        let mut flags = IpPacketFlags::empty();
        if self.fragmentation_id.is_some() {
            flags |= IpPacketFlags::Fragmented;
        }
        let type_byte = Self::TYPE_BYTE_LOW | flags.bits();
        type_byte.serialize(serializer);

        if let Some(fragmentation_id) = self.fragmentation_id {
            fragmentation_id.serialize(serializer);
        }

        self.packet.serialize(serializer);
    }
}

impl Deserializable for IpPacket {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        let type_byte: u8 = read_cursor.read()?;
        assert!(
            (Self::TYPE_BYTE_LOW..=Self::TYPE_BYTE_HIGH).contains(&type_byte),
            "type byte out of range for IP packet"
        );

        let flag_bits = type_byte & (Self::TYPE_BYTE_LOW - 1);
        let flags: BitFlags<IpPacketFlags> = BitFlags::try_from(flag_bits)
            .map_err(|_| anyhow!("Unknown IP flags: {flag_bits:#x}"))?;

        let fragmentation_id = if flags.contains(IpPacketFlags::Fragmented) {
            Some(read_cursor.read()?)
        } else {
            None
        };

        Ok(IpPacket {
            fragmentation_id,
            packet: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct IpPacketFragment {
    pub(crate) is_last: bool,
    pub(crate) fragmentation_id: u16,
    pub(crate) offset: u16,
    pub(crate) fragment: IpPacketBuffer,
}

impl IpPacketFragment {
    const TYPE_BYTE_NOT_FINAL: u8 = 0x20;
    /// indicates this is the last fragment of the original packet.
    const TYPE_BYTE_FINAL: u8 = 0x21;

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE_NOT_FINAL || type_byte == Self::TYPE_BYTE_FINAL
    }

    /// The length of a serilaized IpPacketFragment will be the return value of this function plus
    /// the length of the fragment.
    pub(crate) fn base_length() -> usize {
        Self {
            is_last: false,
            fragmentation_id: 0,
            offset: 0,
            fragment: IpPacketBuffer::new_empty(0),
        }
        .serialized_length()
    }
}

impl MessageTrait for IpPacketFragment {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for IpPacketFragment {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        let type_byte = if self.is_last {
            Self::TYPE_BYTE_FINAL
        } else {
            Self::TYPE_BYTE_NOT_FINAL
        };
        type_byte.serialize(serializer);

        self.fragmentation_id.serialize(serializer);
        self.offset.serialize(serializer);

        self.fragment.serialize(serializer);
    }
}

impl Deserializable for IpPacketFragment {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        let type_byte: u8 = read_cursor.read()?;
        let is_last = match type_byte {
            Self::TYPE_BYTE_FINAL => true,
            Self::TYPE_BYTE_NOT_FINAL => false,
            _ => panic!(
                "Unrecognized type byte while deserializing fragment: {}",
                type_byte
            ),
        };

        Ok(Self {
            is_last,
            fragmentation_id: read_cursor.read()?,
            offset: read_cursor.read()?,
            fragment: read_cursor.read()?,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::array_array::IpPacketBuffer;
    use crate::messages::{
        Message,
        ip_packet::{IpPacket, IpPacketFragment},
        test::assert_roundtrip_message,
    };

    #[test]
    fn roundtrip_ip_packet() {
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: None,
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: Some(258),
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: None,
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        let mut test_vec = Vec::new();
        for i in 0..500 {
            test_vec.push((i % 256).try_into().unwrap());
        }
        assert_roundtrip_message(&Message::IpPacket(IpPacket {
            fragmentation_id: None,
            packet: IpPacketBuffer::new(test_vec.as_ref()),
        }));
    }

    #[test]
    fn roundtrip_ip_packet_fragment() {
        assert_roundtrip_message(&Message::IpPacketFragment(IpPacketFragment {
            is_last: false,
            fragmentation_id: 377,
            offset: 889,
            fragment: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        assert_roundtrip_message(&Message::IpPacketFragment(IpPacketFragment {
            is_last: true,
            fragmentation_id: 377,
            offset: 889,
            fragment: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        let mut test_vec = Vec::new();
        for i in 0..500 {
            test_vec.push((i % 256).try_into().unwrap());
        }
        assert_roundtrip_message(&Message::IpPacketFragment(IpPacketFragment {
            is_last: false,
            fragmentation_id: 377,
            offset: 889,
            fragment: IpPacketBuffer::new(test_vec.as_ref()),
        }));
    }
}
