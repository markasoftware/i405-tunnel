mod ip_packet;

use anyhow::{Result, anyhow, bail};
use declarative_enum_dispatch::enum_dispatch;

use crate::array_array::{ArrayArray, IpPacketBuffer};
pub(crate) use ip_packet::{IpPacket, IpPacketFragment};
pub(crate) use serdes::{Serializable, SerializableLength as _};

const SERDES_VERSION: u32 = 0;
const MAGIC_VALUE: u32 = 0x14051405;

// putting these all up here to ensure we don't add conflicts
const CLIENT_TO_SERVER_HANDSHAKE_TYPE_BYTE: u8 = 0x01;
const SERVER_TO_CLIENT_HANDSHAKE_TYPE_BYTE: u8 = 0x02;
const ACK_TYPE_BYTE: u8 = 0x03;
const SEQUENCE_NUMBER_TYPE_BYTE: u8 = 0x04;
const SEND_SYSTEM_TIMESTAMP_TYPE_BYTE: u8 = 0x05;
const PACKET_STATUS_TYPE_BYTE: u8 = 0x06;
// IpPacket takes 0x10 to 0x1F
// IpPacketFragment takes 0x20 and 0x21

pub(crate) struct PacketBuilder {
    write_cursor: WriteCursor<IpPacketBuffer>,
}

impl PacketBuilder {
    /// Create a PacketBuilder that will eventually fill the passed-in buffer with messages
    pub(crate) fn new(packet_size: usize) -> PacketBuilder {
        PacketBuilder {
            write_cursor: WriteCursor::new(IpPacketBuffer::new_empty(packet_size)),
        }
    }

    pub(crate) fn into_inner(self) -> IpPacketBuffer {
        // Already initialized it to zero, so remaining bytes are padding
        self.write_cursor.into_inner()
    }

    /// If there's space to add the given message to the packet, do so.
    pub(crate) fn try_add_message(&mut self, message: &Message) -> bool {
        if message.serialized_length() > self.write_cursor.num_bytes_left() {
            return false;
        }

        message.serialize(&mut self.write_cursor);
        true
    }

    pub(crate) fn write_cursor(&mut self) -> &mut WriteCursor<IpPacketBuffer> {
        &mut self.write_cursor
    }
}

enum_dispatch! {
    pub(crate) trait MessageTrait {
        fn is_ack_eliciting(&self) -> bool;
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub(crate) enum Message {
        ClientToServerHandshake(ClientToServerHandshake),
        ServerToClientHandshake(ServerToClientHandshake),
        Ack(Ack),
        SequenceNumber(SequenceNumber),
        SendSystemTimestamp(SendSystemTimestamp),
        PacketStatus(PacketStatus),
        IpPacket(IpPacket),
        IpPacketFragment(IpPacketFragment),
    }
}

// You can do this implementation using enum_dispatch, but its complete breakage of many IDE
// features is too much for me. And the fact that we're splitting it over modules means we can't use
// declarative_enum_dispatch either. Maybe we should just get rid of the serdes modules...
impl serdes::Serializable for Message {
    /// Try to serialize into the given buffer (if we fit), returning how many bytes were written if
    /// we did fit. We avoid std::Write because it returns a whole-ass Result we don't need.
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
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
            SendSystemTimestamp;
            PacketStatus;
            IpPacket;
            IpPacketFragment
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
    pub(crate) s2c_packet_finalize_delta: u64,
    pub(crate) server_timeout: u64,
}

impl ClientToServerHandshake {
    const TYPE_BYTE: u8 = CLIENT_TO_SERVER_HANDSHAKE_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

// TODO should probably just remove this when/if we add packet type bytes
impl MessageTrait for ClientToServerHandshake {
    fn is_ack_eliciting(&self) -> bool {
        false
    }
}

impl serdes::Serializable for ClientToServerHandshake {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        MAGIC_VALUE.serialize(serializer);
        SERDES_VERSION.serialize(serializer);
        self.protocol_version.serialize(serializer);
        self.oldest_compatible_protocol_version
            .serialize(serializer);
        self.s2c_packet_length.serialize(serializer);
        self.s2c_packet_interval_min.serialize(serializer);
        self.s2c_packet_interval_max.serialize(serializer);
        self.s2c_packet_finalize_delta.serialize(serializer);
        self.server_timeout.serialize(serializer);
    }
}

impl serdes::Deserializable for ClientToServerHandshake {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);

        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            bail!(
                "Wrong magic value in handshake message: Got {magic_value:#x}, wanted {MAGIC_VALUE:#x}"
            );
        }

        // If this is not an exact match between client/server, we cannot even proceed with
        // deserialization. We could theoretically put this in the TYPE_BYTE instead, but I'd prefer
        // not to clutter the limited space of available types.
        let serdes_version: u32 = read_cursor.read()?;
        if serdes_version != SERDES_VERSION {
            bail!(
                "Unsupported serdes version; peer has {serdes_version}, but we have {SERDES_VERSION}"
            );
        }

        Ok(ClientToServerHandshake {
            protocol_version: read_cursor.read()?,
            oldest_compatible_protocol_version: read_cursor.read()?,
            s2c_packet_length: read_cursor.read()?,
            s2c_packet_interval_min: read_cursor.read()?,
            s2c_packet_interval_max: read_cursor.read()?,
            s2c_packet_finalize_delta: read_cursor.read()?,
            server_timeout: read_cursor.read()?,
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
    fn is_ack_eliciting(&self) -> bool {
        false
    }
}

impl serdes::Serializable for ServerToClientHandshake {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        MAGIC_VALUE.serialize(serializer);
        self.protocol_version.serialize(serializer);
        self.success.serialize(serializer);
    }
}

impl serdes::Deserializable for ServerToClientHandshake {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);

        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            bail!(
                "Wrong magic value in handshake message: Got {magic_value:#x}, wanted {MAGIC_VALUE:#x}"
            );
        }

        Ok(ServerToClientHandshake {
            protocol_version: read_cursor.read()?,
            success: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Ack {
    pub(crate) first_acked_seqno: u32,
    pub(crate) last_acked_seqno: u32,
}

impl Ack {
    const TYPE_BYTE: u8 = ACK_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for Ack {
    fn is_ack_eliciting(&self) -> bool {
        false
    }
}

impl serdes::Serializable for Ack {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.first_acked_seqno.serialize(serializer);
        self.last_acked_seqno.serialize(serializer);
    }
}

impl serdes::Deserializable for Ack {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
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
    fn is_ack_eliciting(&self) -> bool {
        false
    }
}

impl serdes::Serializable for SequenceNumber {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.seqno.serialize(serializer);
    }
}

impl serdes::Deserializable for SequenceNumber {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);
        Ok(SequenceNumber {
            seqno: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct SendSystemTimestamp {
    pub(crate) timestamp: u64,
}

impl SendSystemTimestamp {
    const TYPE_BYTE: u8 = SEND_SYSTEM_TIMESTAMP_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for SendSystemTimestamp {
    fn is_ack_eliciting(&self) -> bool {
        false
    }
}

impl serdes::Serializable for SendSystemTimestamp {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.timestamp.serialize(serializer);
    }
}

impl serdes::Deserializable for SendSystemTimestamp {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);
        Ok(SendSystemTimestamp {
            timestamp: read_cursor.read()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct PacketStatus {
    pub(crate) seqno: u64,
    // if set, then the packet was received after the given delay (may be negative due to clock
    // skew). If unset, the packet was dropped.
    pub(crate) delay: Option<i64>,
}

impl PacketStatus {
    const TYPE_BYTE: u8 = PACKET_STATUS_TYPE_BYTE;

    fn does_type_byte_match(type_byte: u8) -> bool {
        type_byte == Self::TYPE_BYTE
    }
}

impl MessageTrait for PacketStatus {
    fn is_ack_eliciting(&self) -> bool {
        true
    }
}

impl serdes::Serializable for PacketStatus {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.seqno.serialize(serializer);
        match self.delay {
            None => i64::MIN.serialize(serializer),
            Some(delay) => {
                assert_ne!(
                    delay,
                    i64::MIN,
                    "Can't serialize PacketStatus with Received(i64::MIN)"
                );
                delay.serialize(serializer);
            }
        }
    }
}

impl serdes::Deserializable for PacketStatus {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        deserialize_type_byte!(read_cursor);

        let seqno = read_cursor.read()?;
        let raw_delay: i64 = read_cursor.read()?;
        let delay = (raw_delay != i64::MIN).then_some(raw_delay);

        Ok(PacketStatus { seqno, delay })
    }
}

impl serdes::Deserializable for Message {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
        let message_type = match read_cursor.peek_exact_comptime::<1>() {
            Some(message_type_bytes) => message_type_bytes[0],
            None => bail!("Truncated message"),
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
        deserialize_messages!(ClientToServerHandshake; ServerToClientHandshake; Ack; SequenceNumber; SendSystemTimestamp; PacketStatus; IpPacket; IpPacketFragment);
        Err(anyhow!("Unknown message type byte: {message_type:#x}"))
    }
}

/// Return whether there's another message to be read from this cursor. Does not move the cursor.
pub(crate) fn has_message<T: AsRef<[u8]>>(read_cursor: &ReadCursor<T>) -> bool {
    read_cursor
        .peek_exact_comptime::<1>()
        .is_some_and(|x| x != [0])
}

//// CURSOR ////////////////////////////////////////////////////////////////////////////////////////

// Similar signature to std::io::Cursor but slightly nicer signatures, support for ArrayArray
// writing, and no std::io::Result crap

pub(crate) struct ReadCursor<T> {
    underlying: T,
    position: usize,
}

impl<T> ReadCursor<T>
where
    T: AsRef<[u8]>,
{
    pub(crate) fn new(underlying: T) -> ReadCursor<T> {
        ReadCursor {
            underlying,
            position: 0,
        }
    }

    fn num_bytes_left(&self) -> usize {
        self.underlying.as_ref().len() - self.position
    }

    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]> {
        if self.num_bytes_left() >= NUM {
            Some(
                self.underlying.as_ref()[self.position..self.position + NUM]
                    .try_into()
                    .unwrap(),
            )
        } else {
            None
        }
    }

    fn read_exact_comptime<const NUM: usize>(&mut self) -> Option<[u8; NUM]> {
        let result = self.peek_exact_comptime::<NUM>();
        if result.is_some() {
            self.position += NUM;
        }
        result
    }

    // creating a peek_exact_runtime in the same way as above is harder, because if it's returning a
    // reference into self, we can't then modify the position afterwards.

    fn read_exact_runtime(&mut self, len: usize) -> Option<&[u8]> {
        if self.num_bytes_left() >= len {
            let start_position = self.position;
            self.position = start_position + len;
            Some(&self.underlying.as_ref()[start_position..self.position])
        } else {
            None
        }
    }

    pub(crate) fn read<D: serdes::Deserializable>(&mut self) -> Result<D> {
        D::deserialize(self)
    }
}

#[derive(Debug)]
pub(crate) struct WriteCursor<T> {
    underlying: T,
    position: usize,
}

impl<T> WriteCursor<T> {
    pub(crate) fn new(underlying: T) -> WriteCursor<T> {
        WriteCursor {
            underlying,
            position: 0,
        }
    }

    pub(crate) fn into_inner(self) -> T {
        self.underlying
    }
}

impl<const C: usize> WriteCursor<ArrayArray<u8, C>> {
    pub(crate) fn num_bytes_left(&self) -> usize {
        self.underlying.len() - self.position
    }

    fn write_exact(&mut self, buf: &[u8]) -> bool {
        if self.num_bytes_left() >= buf.len() {
            self.position += buf.len();
            self.underlying[self.position - buf.len()..self.position].copy_from_slice(buf);
            true
        } else {
            false
        }
    }

    fn write<S: serdes::Serializable>(&mut self, thing: S) {
        thing.serialize(self)
    }
}

//// SERDES ////////////////////////////////////////////////////////////////////////////////////////

mod serdes {
    use crate::array_array::ArrayArray;

    use crate::messages::{ReadCursor, WriteCursor};
    use anyhow::{Result, anyhow};

    pub(crate) trait Serializer {
        fn serialize(&mut self, data: &[u8]);
    }

    pub(crate) trait Serializable {
        fn serialize<S: Serializer>(&self, serializer: &mut S);
    }

    impl Serializable for bool {
        fn serialize<S: Serializer>(&self, serializer: &mut S) {
            (if *self { 1u8 } else { 0u8 }).serialize(serializer);
        }
    }

    type SerializedArrayArrayLength = u16;

    impl<const C: usize> Serializable for ArrayArray<u8, C> {
        fn serialize<S: Serializer>(&self, serializer: &mut S) {
            let len = SerializedArrayArrayLength::try_from(self.len()).unwrap();
            len.serialize(serializer);
            serializer.serialize(self); // I think deref coercion here?
        }
    }

    /// doesn't actually serialize; just figures out how long a message will be once serialized
    pub(crate) struct LengthDeterminingSerializer {
        length: usize,
    }

    impl LengthDeterminingSerializer {
        pub(crate) fn new() -> Self {
            Self { length: 0 }
        }

        pub(crate) fn into_inner(self) -> usize {
            self.length
        }
    }

    impl Serializer for LengthDeterminingSerializer {
        fn serialize(&mut self, data: &[u8]) {
            self.length += data.len();
        }
    }

    pub(crate) trait SerializableLength {
        fn serialized_length(&self) -> usize;
    }

    impl<T: Serializable> SerializableLength for T {
        fn serialized_length(&self) -> usize {
            let mut length_serializer = LengthDeterminingSerializer::new();
            self.serialize(&mut length_serializer);
            length_serializer.into_inner()
        }
    }

    impl<const C: usize> Serializer for WriteCursor<ArrayArray<u8, C>> {
        fn serialize(&mut self, data: &[u8]) {
            // we could just write this as assert!, since assert! is never optimized out like in C
            if !self.write_exact(data) {
                panic!("Destination not long enough to serialize into");
            }
        }
    }

    pub(crate) trait Deserializable
    where
        Self: Sized,
    {
        // could theoretically make this more generic than just ReadCursor, just like how Serialize
        // is generic over Serializers, but let's not do it until we need it.
        fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self>;
    }

    impl<const C: usize> Deserializable for ArrayArray<u8, C> {
        fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
            let len: SerializedArrayArrayLength = read_cursor.read()?;
            Ok(Self::new(
                read_cursor
                    .read_exact_runtime(len.into())
                    .ok_or(anyhow!("Truncated message"))?,
            ))
        }
    }

    impl Deserializable for bool {
        fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Result<Self> {
            let byte: u8 = read_cursor.read()?;
            match byte {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(anyhow!("Invalid bool byte {byte:#x}")),
            }
        }
    }

    macro_rules! serdes_integral {
        ($integral_type:ident) => {
            impl Serializable for $integral_type {
                fn serialize<S: Serializer>(&self, serializer: &mut S) {
                    serializer.serialize(&self.to_be_bytes());
                }
            }

            impl Deserializable for $integral_type {
                fn deserialize<T: AsRef<[u8]>>(
                    read_cursor: &mut ReadCursor<T>,
                ) -> Result<$integral_type> {
                    // I keep getting syntax errors trying to inline this into the <...> below
                    const SIZE: usize = size_of::<$integral_type>();
                    let read_bytes = read_cursor
                        .read_exact_comptime::<SIZE>()
                        .ok_or(anyhow!("Truncated message"))?;
                    Ok($integral_type::from_be_bytes(read_bytes))
                }
            }
        };
    }

    serdes_integral!(u8);
    serdes_integral!(u16);
    serdes_integral!(u32);
    serdes_integral!(u64);
    serdes_integral!(i8);
    serdes_integral!(i16);
    serdes_integral!(i32);
    serdes_integral!(i64);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{array_array::ArrayArray, constants::MAX_IP_PACKET_LENGTH};
    use anyhow::anyhow;
    use test_case::test_case;

    pub(crate) fn assert_roundtrip_message(msg: &Message) {
        let mut builder = PacketBuilder::new(MAX_IP_PACKET_LENGTH);
        assert!(
            builder.try_add_message(msg),
            "Failed to add message {:#?}",
            msg
        );
        let buf = builder.into_inner();
        let mut cursor = ReadCursor::new(buf);
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

    #[test]
    fn roundtrip_c2s_handshake() {
        assert_roundtrip_message(&Message::ClientToServerHandshake(ClientToServerHandshake {
            // make sure they're all long enough that endianness matters
            protocol_version: 5502,
            oldest_compatible_protocol_version: 8322,
            s2c_packet_length: 2277,
            s2c_packet_interval_min: 992828,
            s2c_packet_interval_max: 1002838,
            s2c_packet_finalize_delta: 1_000_000,
            server_timeout: 2773818,
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
        let mut write_cursor = WriteCursor::new(arr_arr);
        // TODO Test both handshakes
        write_cursor.write(type_byte);
        write_cursor.write(MAGIC_VALUE + 1 as u32);
        let buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursor::new(buf);
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
        let mut write_cursor = WriteCursor::new(arr_arr);
        write_cursor.write(ClientToServerHandshake::TYPE_BYTE);
        write_cursor.write(MAGIC_VALUE as u32);
        write_cursor.write(SERDES_VERSION + 1 as u32);
        let buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursor::new(buf);
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
        assert_roundtrip_message(&Message::SendSystemTimestamp(SendSystemTimestamp {
            timestamp: 1234,
        }))
    }

    #[test]
    fn roundtrip_packet_status() {
        assert_roundtrip_message(&Message::PacketStatus(PacketStatus {
            seqno: 2888,
            delay: Some(-2299),
        }));
        assert_roundtrip_message(&Message::PacketStatus(PacketStatus {
            seqno: 2888,
            delay: Some(2299),
        }));
        assert_roundtrip_message(&Message::PacketStatus(PacketStatus {
            seqno: 2888,
            delay: None,
        }));
    }

    // TODO: test packet builder actually returns false when a packet would overrun the buffer
}
