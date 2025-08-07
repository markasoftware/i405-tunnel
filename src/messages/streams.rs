use super::MessageTrait;
use crate::array_array::IpPacketBuffer;
use crate::messages;
use crate::messages::serdes::{Deserializable, Serializable, Serializer};
use crate::messages::{ReadCursor, deserialize_type_byte};
use crate::reliability::{ReliabilityAction, ReliableMessage};

use anyhow::Result;

type StreamId = u16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct StreamData {
    pub(crate) stream_id: StreamId,
    pub(crate) offset: u64,
    pub(crate) data: IpPacketBuffer,
}

impl StreamData {
    const TYPE_BYTE: u8 = messages::STREAM_DATA_TYPE_BYTE;

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

/// Close our sending side of the connection, like TCP FIN.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct StreamFin {
    pub(crate) stream_id: StreamId,
    pub(crate) offset: u64,
}

impl StreamFin {
    const TYPE_BYTE: u8 = messages::STREAM_FIN_TYPE_BYTE;

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

/// Abnormally close the connection in both directions. Can be due to resource exhaustion, or
/// because a corresponding socket was also closed abnormally.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct StreamRst {
    pub(crate) stream_id: StreamId,
}

impl StreamRst {
    const TYPE_BYTE: u8 = messages::STREAM_RST_TYPE_BYTE;

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

/// Advertisement that we can receive up to the given offset
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct StreamWindowUpdate {
    pub(crate) stream_id: StreamId,
    pub(crate) new_window_offset: u64,
}

// we do a lil' boilerplate. seriously, one could automate this with a proc macro, but why do that
// when you can automate it with gemini 2.5 flash?

impl StreamWindowUpdate {
    const TYPE_BYTE: u8 = messages::STREAM_WINDOW_UPDATE_TYPE_BYTE;

    pub(crate) fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for StreamData {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for StreamData {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.stream_id.serialize(serializer);
        self.offset.serialize(serializer);
        self.data.serialize(serializer);
    }
}

impl Deserializable for StreamData {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);
        Ok(StreamData {
            stream_id: read_cursor.read()?,
            offset: read_cursor.read()?,
            data: read_cursor.read()?,
        })
    }
}

impl MessageTrait for StreamFin {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        Some(ReliabilityAction::ReliableMessage(
            ReliableMessage::StreamFin(self.clone()),
        ))
    }
}

impl Serializable for StreamFin {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.stream_id.serialize(serializer);
        self.offset.serialize(serializer);
    }
}

impl Deserializable for StreamFin {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);
        Ok(StreamFin {
            stream_id: read_cursor.read()?,
            offset: read_cursor.read()?,
        })
    }
}

impl MessageTrait for StreamRst {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        Some(ReliabilityAction::ReliableMessage(
            ReliableMessage::StreamRst(self.clone()),
        ))
    }
}

impl Serializable for StreamRst {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.stream_id.serialize(serializer);
    }
}

impl Deserializable for StreamRst {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);
        Ok(StreamRst {
            stream_id: read_cursor.read()?,
        })
    }
}

impl MessageTrait for StreamWindowUpdate {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        Some(ReliabilityAction::ReliableMessage(
            ReliableMessage::StreamWindowUpdate(self.clone()),
        ))
    }
}

impl Serializable for StreamWindowUpdate {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.stream_id.serialize(serializer);
        self.new_window_offset.serialize(serializer);
    }
}

impl Deserializable for StreamWindowUpdate {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);
        Ok(StreamWindowUpdate {
            stream_id: read_cursor.read()?,
            new_window_offset: read_cursor.read()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::array_array::IpPacketBuffer;
    use crate::messages::Message;
    use crate::messages::test::assert_roundtrip_message;

    #[test]
    fn roundtrip_stream_data() {
        assert_roundtrip_message(&Message::StreamData(StreamData {
            stream_id: 922,
            offset: 1000,
            data: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
    }

    #[test]
    fn roundtrip_stream_fin() {
        assert_roundtrip_message(&Message::StreamFin(StreamFin {
            stream_id: 373,
            offset: 1992,
        }));
    }

    #[test]
    fn roundtrip_stream_rst() {
        assert_roundtrip_message(&Message::StreamRst(StreamRst { stream_id: 28388 }));
    }

    #[test]
    fn roundtrip_stream_window_update() {
        assert_roundtrip_message(&Message::StreamWindowUpdate(StreamWindowUpdate {
            stream_id: 288,
            new_window_offset: 1000,
        }));
    }
}
