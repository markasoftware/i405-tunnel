#![allow(clippy::four_forward_slashes)]

mod ip_packet;
mod streams;

use anyhow::{Result, anyhow};
use declarative_enum_dispatch::enum_dispatch;
use enumflags2::{BitFlag, BitFlags, bitflags};

use crate::array_array::IpPacketBuffer;
use crate::cursors::{ReadCursor, WriteCursor, WriteCursorContiguous};
use crate::reliability::{ReliabilityAction, ReliabilityActionBuilder, ReliableMessage};
use crate::serdes::{
    Deserializable, DeserializeError, Serializable, SerializableLength as _, Serializer,
};
pub(crate) use ip_packet::{IpPacket, IpPacketFragment};
pub(crate) use streams::{StreamData, StreamFin, StreamRst, StreamWindowUpdate};

const SERDES_VERSION: u32 = 0;
const MAGIC_VALUE: u32 = 0x14051405;

// putting these all up here to ensure we don't add conflicts
const CLIENT_TO_SERVER_HANDSHAKE_TYPE_BYTE: u8 = 0x01;
const SERVER_TO_CLIENT_HANDSHAKE_TYPE_BYTE: u8 = 0x02;
const ACK_TYPE_BYTE: u8 = 0x03;
const SEQUENCE_NUMBER_TYPE_BYTE: u8 = 0x04;
const TX_EPOCH_TIME_TYPE_BYTE: u8 = 0x05;
const PACKET_STATUS_TYPE_BYTE: u8 = 0x06;
// IpPacket takes 0x10 to 0x1F
// IpPacketFragment takes 0x20 and 0x21
const STREAM_DATA_TYPE_BYTE: u8 = 0x30;
const STREAM_FIN_TYPE_BYTE: u8 = 0x31;
const STREAM_RST_TYPE_BYTE: u8 = 0x32;
const STREAM_WINDOW_UPDATE_TYPE_BYTE: u8 = 0x33;

pub(crate) struct PacketBuilder {
    write_cursor: WriteCursorContiguous<IpPacketBuffer>,
}

impl PacketBuilder {
    /// Create a PacketBuilder that will eventually fill the passed-in buffer with messages
    pub(crate) fn new(packet_size: usize) -> PacketBuilder {
        PacketBuilder {
            write_cursor: WriteCursorContiguous::new(IpPacketBuffer::new_empty(packet_size)),
        }
    }

    pub(crate) fn into_inner(self) -> IpPacketBuffer {
        // Already initialized it to zero, so remaining bytes are padding
        self.write_cursor.into_inner()
    }

    pub(crate) fn can_add_message(&mut self, message: &Message) -> bool {
        message.serialized_length() <= self.write_cursor.num_bytes_left()
    }

    /// If there's space to add the given message to the packet, do so.
    pub(crate) fn try_add_message(
        &mut self,
        message: &Message,
        reliability_builder: &mut ReliabilityActionBuilder<'_>,
    ) -> Result<bool> {
        let (added, ra) = self.try_add_message_explicit_reliability(message);
        if let Some(ra) = ra {
            reliability_builder.add_reliability_action(ra)?;
        }
        Ok(added)
    }

    // TODO would like to make the return type here more type safe, since (false, Some(..)) is be
    // impossible. Should return a custom enum instead
    pub(crate) fn try_add_message_explicit_reliability(
        &mut self,
        message: &Message,
    ) -> (bool, Option<ReliabilityAction>) {
        if !self.can_add_message(message) {
            return (false, None);
        }

        message.serialize(&mut self.write_cursor);
        (true, message.reliability_action())
    }

    pub(crate) fn try_add_message_no_reliability(&mut self, message: &Message) -> bool {
        let (added, reliability_action) = self.try_add_message_explicit_reliability(message);
        assert!(
            reliability_action.is_none(),
            "unexpected reliability action while building packet"
        );
        added
    }

    pub(crate) fn write_cursor(&mut self) -> &mut WriteCursorContiguous<IpPacketBuffer> {
        &mut self.write_cursor
    }
}

pub(crate) trait PacketReader {
    fn try_read_message(&mut self, ack_elicited: &mut bool) -> Result<Option<Message>>;
    fn try_read_message_no_ack(&mut self) -> Result<Option<Message>>;
}

impl<T: ReadCursor> PacketReader for T {
    fn try_read_message(&mut self, ack_elicited: &mut bool) -> Result<Option<Message>> {
        if has_message(self) {
            let msg: Message = self.read()?;
            // this is a little weird. We really shouldn't be trying to generate the reliability
            // actions on the read side at all. But while the logic is simple, it works.
            if msg.reliability_action().is_some() {
                *ack_elicited = true;
            }
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    fn try_read_message_no_ack(&mut self) -> Result<Option<Message>> {
        let mut ack_elicited = false;
        let result = self.try_read_message(&mut ack_elicited);
        assert!(
            !ack_elicited,
            "unexpected elicited ack while reading packet"
        );
        result
    }
}

enum_dispatch! {
    pub(crate) trait MessageTrait {
        fn reliability_action(&self) -> Option<ReliabilityAction>;
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub(crate) enum Message {
        ClientToServerHandshake(ClientToServerHandshake),
        ServerToClientHandshake(ServerToClientHandshake),
        Ack(Ack),
        SequenceNumber(SequenceNumber),
        TxEpochTime(TxEpochTime),
        PacketStatus(PacketStatus),
        IpPacket(IpPacket),
        IpPacketFragment(IpPacketFragment),
        StreamData(StreamData),
        StreamFin(StreamFin),
        StreamRst(StreamRst),
        StreamWindowUpdate(StreamWindowUpdate),
    }
}

// You can do this implementation using enum_dispatch, but its complete breakage of many IDE
// features is too much for me. And the fact that we're splitting it over modules means we can't use
// declarative_enum_dispatch either. Maybe we should just get rid of the serdes modules...
impl Serializable for Message {
    /// Try to serialize into the given buffer (if we fit), returning how many bytes were written if
    /// we did fit. We avoid std::Write because it returns a whole-ass Result we don't need.
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        macro_rules! serialize_variants {
            ($($enum_item:ident);+) => {
                match self {
                    $(
                        Message::$enum_item(msg) => {
                            msg.serialize(serializer);
                        }
                    ),+
                }
            };
        }

        serialize_variants!(
            ClientToServerHandshake;
            ServerToClientHandshake;
            Ack;
            SequenceNumber;
            TxEpochTime;
            PacketStatus;
            IpPacket;
            IpPacketFragment;
            StreamData;
            StreamFin;
            StreamRst;
            StreamWindowUpdate
        );
    }
}

macro_rules! deserialize_type_byte {
    ($read_cursor:ident) => {
        let type_byte: u8 = $read_cursor.read()?;
        assert!(
            type_byte == Self::TYPE_BYTE,
            "Wrong type byte in deserializer"
        );
    };
}
pub(crate) use deserialize_type_byte;

//// INITIAL HANDSHAKE /////////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ClientToServerHandshake {
    /// Need not be an exact match, it's more of a negotiation.
    pub(crate) protocol_version: u32,
    pub(crate) oldest_compatible_protocol_version: u32,
    pub(crate) s2c_packet_length: u16,
    pub(crate) s2c_packet_interval_min: u64,
    pub(crate) s2c_packet_interval_max: u64,
    pub(crate) c2s_packet_interval_min: u64,
    pub(crate) s2c_packet_finalize_delta: u64,
    pub(crate) server_timeout: u64,
    pub(crate) monitor_packets: bool,
}

#[bitflags]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum C2SHandshakeFlags {
    MonitorPackets = 1 << 0,
}

impl ClientToServerHandshake {
    const TYPE_BYTE: u8 = CLIENT_TO_SERVER_HANDSHAKE_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

// If we ever switch to using packet type bytes, then the handshakes will have different type bytes,
// and we can remove the MessageTrait implementation.
impl MessageTrait for ClientToServerHandshake {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for ClientToServerHandshake {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        let mut flags = C2SHandshakeFlags::empty();
        if self.monitor_packets {
            flags |= C2SHandshakeFlags::MonitorPackets;
        }

        Self::TYPE_BYTE.serialize(serializer);
        MAGIC_VALUE.serialize(serializer);
        SERDES_VERSION.serialize(serializer);
        self.protocol_version.serialize(serializer);
        self.oldest_compatible_protocol_version
            .serialize(serializer);
        flags.bits().serialize(serializer);
        self.s2c_packet_length.serialize(serializer);
        self.s2c_packet_interval_min.serialize(serializer);
        self.s2c_packet_interval_max.serialize(serializer);
        self.c2s_packet_interval_min.serialize(serializer);
        self.s2c_packet_finalize_delta.serialize(serializer);
        self.server_timeout.serialize(serializer);
    }
}

impl Deserializable for ClientToServerHandshake {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        deserialize_type_byte!(read_cursor);

        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            return Err(anyhow!("Wrong magic value in handshake message: Got {magic_value:#x}, wanted {MAGIC_VALUE:#x}").into());
        }

        // If this is not an exact match between client/server, we cannot even proceed with
        // deserialization. We could theoretically put this in the TYPE_BYTE instead, but I'd prefer
        // not to clutter the limited space of available types.
        let serdes_version: u32 = read_cursor.read()?;
        if serdes_version != SERDES_VERSION {
            return Err(anyhow!("Unsupported serdes version; peer has {serdes_version}, but we have {SERDES_VERSION}").into());
        }

        let protocol_version = read_cursor.read()?;
        let oldest_compatible_protocol_version = read_cursor.read()?;
        let flag_bits: u32 = read_cursor.read()?;
        let flags: BitFlags<C2SHandshakeFlags> = BitFlags::try_from(flag_bits)
            .map_err(|_| anyhow!("Unknown C2S handshake flags: {flag_bits:#x}"))?;

        Ok(ClientToServerHandshake {
            protocol_version,
            oldest_compatible_protocol_version,
            s2c_packet_length: read_cursor.read()?,
            s2c_packet_interval_min: read_cursor.read()?,
            s2c_packet_interval_max: read_cursor.read()?,
            c2s_packet_interval_min: read_cursor.read()?,
            s2c_packet_finalize_delta: read_cursor.read()?,
            server_timeout: read_cursor.read()?,
            monitor_packets: flags.contains(C2SHandshakeFlags::MonitorPackets),
        })
    }
}

/// The server will send this message after receiving a ClientToServerHandshake, even if the
/// versions are incompatible.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ServerToClientHandshake {
    pub(crate) protocol_version: u32,
    /// If false, the client should abandon the connection.
    pub(crate) success: bool,
}

impl ServerToClientHandshake {
    const TYPE_BYTE: u8 = SERVER_TO_CLIENT_HANDSHAKE_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for ServerToClientHandshake {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for ServerToClientHandshake {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        MAGIC_VALUE.serialize(serializer);
        self.protocol_version.serialize(serializer);
        self.success.serialize(serializer);
    }
}

impl Deserializable for ServerToClientHandshake {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        deserialize_type_byte!(read_cursor);

        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            return Err(anyhow!("Wrong magic value in handshake message: Got {magic_value:#x}, wanted {MAGIC_VALUE:#x}").into());
        }

        Ok(ServerToClientHandshake {
            protocol_version: read_cursor.read()?,
            success: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Ack {
    pub(crate) first_acked_seqno: u64,
    pub(crate) last_acked_seqno: u64,
}

impl Ack {
    const TYPE_BYTE: u8 = ACK_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for Ack {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for Ack {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.first_acked_seqno.serialize(serializer);
        self.last_acked_seqno.serialize(serializer);
    }
}

impl Deserializable for Ack {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        deserialize_type_byte!(read_cursor);

        Ok(Ack {
            first_acked_seqno: read_cursor.read()?,
            last_acked_seqno: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct SequenceNumber {
    pub(crate) seqno: u64,
}

impl SequenceNumber {
    const TYPE_BYTE: u8 = SEQUENCE_NUMBER_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for SequenceNumber {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for SequenceNumber {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.seqno.serialize(serializer);
    }
}

impl Deserializable for SequenceNumber {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        deserialize_type_byte!(read_cursor);
        Ok(SequenceNumber {
            seqno: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct TxEpochTime {
    pub(crate) timestamp: u64,
}

impl TxEpochTime {
    const TYPE_BYTE: u8 = TX_EPOCH_TIME_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for TxEpochTime {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        None
    }
}

impl Serializable for TxEpochTime {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.timestamp.serialize(serializer);
    }
}

impl Deserializable for TxEpochTime {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        deserialize_type_byte!(read_cursor);
        Ok(TxEpochTime {
            timestamp: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct PacketStatus {
    pub(crate) seqno: u64,
    /// The PacketStatus is sent from the side that received the packet being referenced, to the
    /// side that sent it. The tx_time is the time that the sender of the original packet (ie, the
    /// recipient of the PacketStatus message) sent the original packet, and the rx_time is the time
    /// that the recipient of the original packet (ie, the sender of the PacketStatus message)
    /// received the original packet.
    pub(crate) tx_rx_epoch_times: Option<(u64, u64)>,
}

impl PacketStatus {
    const TYPE_BYTE: u8 = PACKET_STATUS_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for PacketStatus {
    fn reliability_action(&self) -> Option<ReliabilityAction> {
        Some(ReliabilityAction::ReliableMessage(
            ReliableMessage::PacketStatus(self.clone()),
        ))
    }
}

impl Serializable for PacketStatus {
    fn serialize<S: Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.seqno.serialize(serializer);
        let (tx_time, rx_time) = self.tx_rx_epoch_times.unwrap_or((0, 0));
        tx_time.serialize(serializer);
        rx_time.serialize(serializer);
    }
}

impl Deserializable for PacketStatus {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        deserialize_type_byte!(read_cursor);

        let seqno = read_cursor.read()?;
        let raw_tx_time = read_cursor.read()?;
        let raw_rx_time = read_cursor.read()?;
        let tx_rx_epoch_times =
            (raw_tx_time != 0 || raw_rx_time != 0).then_some((raw_tx_time, raw_rx_time));

        Ok(PacketStatus {
            seqno,
            tx_rx_epoch_times,
        })
    }
}

impl Deserializable for Message {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        let message_type = match read_cursor.peek_exact_comptime::<1>() {
            Some(message_type_bytes) => message_type_bytes[0],
            None => return Err(DeserializeError::Truncated),
        };
        assert!(
            message_type != 0,
            "Message type was 0, ie padding. Padding should be skipped in outer loop."
        );

        macro_rules! deserialize_messages {
            ($($msg:ident);+) => {
                $(
                    if $msg::does_type_byte_match(message_type) {
                        return Ok(Message::$msg($msg::deserialize(read_cursor)?));
                    }
                )+
            };
        }
        deserialize_messages!(ClientToServerHandshake; ServerToClientHandshake; Ack; SequenceNumber; TxEpochTime; PacketStatus; IpPacket; IpPacketFragment; StreamData; StreamFin; StreamRst; StreamWindowUpdate);
        Err(anyhow!("Unknown message type byte: {message_type:#x}").into())
    }
}

/// Return whether there's another message to be read from this cursor. Does not move the cursor.
fn has_message<T: ReadCursor>(read_cursor: &T) -> bool {
    read_cursor
        .peek_exact_comptime::<1>()
        .is_some_and(|x| x != [0])
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        array_array::ArrayArray, constants::MAX_IP_PACKET_LENGTH, cursors::ReadCursorContiguous,
    };
    use anyhow::anyhow;
    use test_case::test_case;

    pub(crate) fn assert_roundtrip_message(msg: &Message) {
        let mut builder = PacketBuilder::new(MAX_IP_PACKET_LENGTH);
        assert!(
            builder.try_add_message_explicit_reliability(msg).0,
            "Failed to add message {:#?}",
            msg
        );
        let buf = builder.into_inner();
        let mut cursor = ReadCursorContiguous::new(buf);
        assert!(
            has_message(&cursor),
            "Message should be available in cursor"
        );
        let roundtripped_msg = cursor.read().expect("Message should deserialize correctly");
        assert_eq!(
            msg, &roundtripped_msg,
            "Original should equal deserilaized message"
        );
    }

    #[test_case(true)]
    #[test_case(false)]
    fn roundtrip_c2s_handshake(monitor_packets: bool) {
        assert_roundtrip_message(&Message::ClientToServerHandshake(ClientToServerHandshake {
            // make sure they're all long enough that endianness matters
            protocol_version: 5502,
            oldest_compatible_protocol_version: 8322,
            s2c_packet_length: 2277,
            s2c_packet_interval_min: 992828,
            s2c_packet_interval_max: 1002838,
            c2s_packet_interval_min: 2838239,
            s2c_packet_finalize_delta: 1_000_000,
            server_timeout: 2773818,
            monitor_packets,
        }));
    }

    #[test]
    fn roundtrip_s2c_handshake() {
        assert_roundtrip_message(&Message::ServerToClientHandshake(ServerToClientHandshake {
            success: true,
            protocol_version: 5502,
        }));
        assert_roundtrip_message(&Message::ServerToClientHandshake(ServerToClientHandshake {
            success: false,
            protocol_version: 5502,
        }));
    }

    /// Ensure that s2c and c2s handshakes error out if the magic values or serdes versions are not
    /// equal
    #[test_case(ClientToServerHandshake::TYPE_BYTE)]
    #[test_case(ServerToClientHandshake::TYPE_BYTE)]
    fn magic_value_error(type_byte: u8) {
        let arr_arr = ArrayArray::<u8, 100>::new_empty(100);
        let mut write_cursor = WriteCursorContiguous::new(arr_arr);
        // TODO Test both handshakes
        write_cursor.write(type_byte);
        #[allow(clippy::unnecessary_cast)]
        write_cursor.write(MAGIC_VALUE + 1 as u32);
        let buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursorContiguous::new(buf);
        assert!(
            has_message(&read_cursor),
            "Should be a message to deserialize"
        );
        let err = read_cursor.read::<Message>().unwrap_err();
        assert_eq!(
            err.to_string(),
            anyhow!(
                "Wrong magic value in handshake message: Got {:#x}, wanted {:#x}",
                MAGIC_VALUE + 1,
                MAGIC_VALUE
            )
            .to_string(),
            "Magic values should not match"
        );
    }

    #[test]
    fn serdes_version_error() {
        let arr_arr = ArrayArray::<u8, 100>::new_empty(100);
        let mut write_cursor = WriteCursorContiguous::new(arr_arr);
        write_cursor.write(ClientToServerHandshake::TYPE_BYTE);
        #[allow(clippy::unnecessary_cast)]
        write_cursor.write(MAGIC_VALUE as u32);
        #[allow(clippy::unnecessary_cast)]
        write_cursor.write(SERDES_VERSION + 1 as u32);
        let buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursorContiguous::new(buf);
        assert!(
            has_message(&read_cursor),
            "Should be a message to deserialize"
        );
        let err = read_cursor.read::<Message>().unwrap_err();
        assert_eq!(
            err.to_string(),
            anyhow!(
                "Unsupported serdes version; peer has {}, but we have {}",
                SERDES_VERSION + 1,
                SERDES_VERSION
            )
            .to_string(),
            "Serdes versions should not match"
        );
    }

    #[test]
    fn roundtrip_ack() {
        assert_roundtrip_message(&Message::Ack(Ack {
            first_acked_seqno: 2773,
            last_acked_seqno: 92899,
        }));
    }

    #[test]
    fn roundtrip_sequence_number() {
        assert_roundtrip_message(&Message::SequenceNumber(SequenceNumber { seqno: 1234 }));
    }

    #[test]
    fn roundtrip_send_system_timestamp() {
        assert_roundtrip_message(&Message::TxEpochTime(TxEpochTime { timestamp: 1234 }))
    }

    #[test]
    fn roundtrip_packet_status() {
        assert_roundtrip_message(&Message::PacketStatus(PacketStatus {
            seqno: 2888,
            tx_rx_epoch_times: Some((277, 9929)),
        }));
        assert_roundtrip_message(&Message::PacketStatus(PacketStatus {
            seqno: 2888,
            tx_rx_epoch_times: None,
        }));
    }

    // TODO: test packet builder actually returns false when a packet would overrun the buffer
}
