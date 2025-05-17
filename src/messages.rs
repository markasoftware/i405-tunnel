use crate::array_array::{ArrayArray, IpPacketBuffer};
use serdes::Serializable as _;

const SERDES_VERSION: u32 = 0;
const MAGIC_VALUE: u32 = 0x14051405;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpPacket {
    // TODO
}

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
        let mut length_serializer = serdes::LengthDeterminingSerializer::new();
        message.serialize(&mut length_serializer);

        let length = length_serializer.into_inner();
        if length > self.write_cursor.num_bytes_left() {
            return false;
        }

        message.serialize(&mut self.write_cursor);
        true
    }
}

type MessageType = u8;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Message {
    ClientToServerHandshake(ClientToServerHandshake),
    ServerToClientHandshake(ServerToClientHandshake),
    UnscheduledPacket(UnscheduledPacket),
}

impl Message {
    /// Try to serialize into the given buffer (if we fit), returning how many bytes were written if
    /// we did fit. We avoid std::Write because it returns a whole-ass Result we don't need.
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        macro_rules! serialize_variants {
            ($($enum_item:ident);+) => {
                match self {
                    $(
                        Message::$enum_item(msg) => {
                            $enum_item::TYPE_BYTE.serialize(serializer);
                            msg.serialize(serializer);
                        }
                    ),+
                }
            };
        }

        serialize_variants!(
            ClientToServerHandshake;
            ServerToClientHandshake;
            UnscheduledPacket
        );
    }
}

//// INITIAL HANDSHAKE /////////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ClientToServerHandshake {
    /// Need not be an exact match, it's more of a negotiation.
    protocol_version: u32,
    s2c_packet_length: u16,
    s2c_packet_interval_ns: u64,
}

impl ClientToServerHandshake {
    const TYPE_BYTE: u8 = 1;
}

impl serdes::Serializable for ClientToServerHandshake {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        MAGIC_VALUE.serialize(serializer);
        SERDES_VERSION.serialize(serializer);
        self.protocol_version.serialize(serializer);
        self.s2c_packet_length.serialize(serializer);
        self.s2c_packet_interval_ns.serialize(serializer);
    }
}

impl serdes::Deserializable for ClientToServerHandshake {
    fn deserialize<T: AsRef<[u8]>>(
        read_cursor: &mut ReadCursor<T>,
    ) -> Result<Self, DeserializeMessageErr> {
        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            return Err(DeserializeMessageErr::WrongMagicValue(magic_value));
        }

        // If this is not an exact match between client/server, we cannot even proceed with
        // deserialization. We could theoretically put this in the TYPE_BYTE instead, but I'd prefer
        // not to clutter the limited space of available types.
        let serdes_version: u32 = read_cursor.read()?;
        if serdes_version != SERDES_VERSION {
            return Err(DeserializeMessageErr::UnsupportedSerdesVersion(
                serdes_version,
            ));
        }

        Ok(ClientToServerHandshake {
            protocol_version: read_cursor.read()?,
            s2c_packet_length: read_cursor.read()?,
            s2c_packet_interval_ns: read_cursor.read()?,
        })
    }
}

/// The server will send this message after receiving a ClientToServerHandshake, even if the
/// versions are incompatible.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ServerToClientHandshake {
    protocol_version: u32,
    /// If false, the client should abandon the connection.
    success: bool,
}

impl ServerToClientHandshake {
    const TYPE_BYTE: u8 = 2;
}

impl serdes::Serializable for ServerToClientHandshake {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        MAGIC_VALUE.serialize(serializer);
        SERDES_VERSION.serialize(serializer);
        self.protocol_version.serialize(serializer);
        self.success.serialize(serializer);
    }
}

impl serdes::Deserializable for ServerToClientHandshake {
    fn deserialize<T: AsRef<[u8]>>(
        read_cursor: &mut ReadCursor<T>,
    ) -> Result<Self, DeserializeMessageErr> {
        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            return Err(DeserializeMessageErr::WrongMagicValue(magic_value));
        }

        // TODO do we really need to check in this direction?
        let serdes_version: u32 = read_cursor.read()?;
        if serdes_version != SERDES_VERSION {
            return Err(DeserializeMessageErr::UnsupportedSerdesVersion(
                serdes_version,
            ));
        }

        Ok(ServerToClientHandshake {
            protocol_version: read_cursor.read()?,
            success: read_cursor.read()?,
        })
    }
}

//// UNSCHEDULED PACKET ////////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct UnscheduledPacket {
    packet: IpPacketBuffer,
}

impl UnscheduledPacket {
    const TYPE_BYTE: u8 = 10;
}

impl serdes::Serializable for UnscheduledPacket {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        self.packet.serialize(serializer);
    }
}

impl serdes::Deserializable for UnscheduledPacket {
    fn deserialize<T: AsRef<[u8]>>(
        read_cursor: &mut ReadCursor<T>,
    ) -> Result<Self, DeserializeMessageErr> {
        Ok(UnscheduledPacket {
            packet: read_cursor.read()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeserializeMessageErr {
    UnknownMessageType(MessageType),
    Truncated(Option<MessageType>),
    InvalidBool(u8),
    UnsupportedSerdesVersion(u32),
    WrongMagicValue(u32),
}

impl std::fmt::Display for DeserializeMessageErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DeserializeMessageErr::UnknownMessageType(message_type) => {
                write!(f, "Unknown message type byte: {:#x}", message_type)
            }
            DeserializeMessageErr::Truncated(Some(message_type)) => {
                write!(f, "Truncated message of type {:#x}", message_type)
            }
            DeserializeMessageErr::Truncated(None) => write!(f, "Truncated message (unknown type)"),
            DeserializeMessageErr::InvalidBool(byte) => write!(f, "Invalid bool byte {:#x}", byte),
            DeserializeMessageErr::UnsupportedSerdesVersion(peer_version) => write!(
                f,
                "Unsupported serdes version; peer has {}, but we have {}",
                peer_version, SERDES_VERSION
            ),
            DeserializeMessageErr::WrongMagicValue(peer_magic_value) => write!(
                f,
                "Wrong magic value; peer has {}, expected {}",
                peer_magic_value, MAGIC_VALUE
            ),
        }
    }
}

impl serdes::Deserializable for Message {
    fn deserialize<T: AsRef<[u8]>>(
        read_cursor: &mut ReadCursor<T>,
    ) -> Result<Self, DeserializeMessageErr> {
        let message_type = match read_cursor.read_exact_comptime::<1>() {
            Some(message_type_bytes) => message_type_bytes[0],
            None => return Err(DeserializeMessageErr::Truncated(None)),
        };
        assert!(
            message_type != 0,
            "Message type was 0, ie padding. Padding should be skipped in outer loop."
        );

        macro_rules! deserialize_messages {
            ($($msg:ident);+) => {
                $(
                    if message_type == $msg::TYPE_BYTE {
                        return Ok(Message::$msg($msg::deserialize(read_cursor)?));
                    }
                )+
            };
        }
        deserialize_messages!(ClientToServerHandshake; ServerToClientHandshake; UnscheduledPacket);
        Err(DeserializeMessageErr::UnknownMessageType(message_type))
    }
}

/// Return whether there's another message to be read from this cursor. Does not move the cursor.
fn has_message<T: AsRef<[u8]>>(read_cursor: &ReadCursor<T>) -> bool {
    read_cursor
        .peek_exact_comptime::<1>()
        .is_some_and(|x| x != [0])
}

//// CURSOR ////////////////////////////////////////////////////////////////////////////////////////

// Similar signature to std::io::Cursor but slightly nicer signatures, support for ArrayArray
// writing, and no std::io::Result crap

struct ReadCursor<T> {
    underlying: T,
    position: usize,
}

impl<T> ReadCursor<T>
where
    T: AsRef<[u8]>,
{
    fn new(underlying: T) -> ReadCursor<T> {
        ReadCursor {
            underlying,
            position: 0,
        }
    }

    fn num_bytes_left(&self) -> usize {
        self.underlying.as_ref().len() - self.position
    }

    fn peek_exact_comptime<const num: usize>(&self) -> Option<[u8; num]> {
        if self.num_bytes_left() >= num {
            Some(
                self.underlying.as_ref()[self.position..self.position + num]
                    .try_into()
                    .unwrap(),
            )
        } else {
            None
        }
    }

    fn read_exact_comptime<const num: usize>(&mut self) -> Option<[u8; num]> {
        let result = self.peek_exact_comptime::<num>();
        if result.is_some() {
            self.position += num;
        }
        result
    }

    // creating a peek_exact_runtime in the same way as above is harder, because if it's returning a
    // reference into self, we can't then modify the position afterwards.

    fn read_exact_runtime(&mut self, len: usize) -> Option<&[u8]> {
        if self.num_bytes_left() >= len {
            self.position += len;
            Some(&self.underlying.as_ref()[self.position - len..self.position])
        } else {
            None
        }
    }

    fn read_exact_runtime_to(&mut self, dest: &mut [u8]) -> bool {
        match self.read_exact_runtime(dest.len()) {
            Some(read_bytes) => {
                dest.copy_from_slice(read_bytes);
                true
            }
            None => false,
        }
    }

    fn read<D: serdes::Deserializable>(&mut self) -> Result<D, DeserializeMessageErr> {
        D::deserialize(self)
    }
}

struct WriteCursor<T> {
    underlying: T,
    position: usize,
}

impl<T> WriteCursor<T> {
    fn new(underlying: T) -> WriteCursor<T> {
        WriteCursor {
            underlying,
            position: 0,
        }
    }

    fn into_inner(self) -> T {
        self.underlying
    }
}

impl<const C: usize> WriteCursor<ArrayArray<u8, C>> {
    fn num_bytes_left(&self) -> usize {
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

    use crate::messages::{DeserializeMessageErr, ReadCursor, WriteCursor};

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
        fn deserialize<T: AsRef<[u8]>>(
            read_cursor: &mut ReadCursor<T>,
        ) -> Result<Self, DeserializeMessageErr>;
    }

    impl<const C: usize> Deserializable for ArrayArray<u8, C> {
        fn deserialize<T: AsRef<[u8]>>(
            read_cursor: &mut ReadCursor<T>,
        ) -> Result<Self, DeserializeMessageErr> {
            let len: SerializedArrayArrayLength = read_cursor.read()?;
            Ok(Self::new(
                read_cursor
                    .read_exact_runtime(len.into())
                    .ok_or(DeserializeMessageErr::Truncated(None))?,
            ))
        }
    }

    impl Deserializable for bool {
        fn deserialize<T: AsRef<[u8]>>(
            read_cursor: &mut ReadCursor<T>,
        ) -> Result<Self, DeserializeMessageErr> {
            let byte: u8 = read_cursor.read()?;
            match byte {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(DeserializeMessageErr::InvalidBool(byte)),
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
                ) -> Result<$integral_type, DeserializeMessageErr> {
                    // I keep getting syntax errors trying to inline this into the <...> below
                    const SIZE: usize = size_of::<$integral_type>();
                    let read_bytes = read_cursor
                        .read_exact_comptime::<SIZE>()
                        .ok_or(DeserializeMessageErr::Truncated(None))?;
                    Ok($integral_type::from_be_bytes(read_bytes))
                }
            }
        };
    }

    serdes_integral!(u8);
    serdes_integral!(u16);
    serdes_integral!(u32);
    serdes_integral!(u64);
}

#[cfg(test)]
mod test {
    use crate::{
        array_array::{ArrayArray, IpPacketBuffer},
        constants::MAX_IP_PACKET_LENGTH,
        messages::{
            DeserializeMessageErr, MAGIC_VALUE, ReadCursor, SERDES_VERSION, WriteCursor,
            has_message,
        },
    };

    use super::{
        ClientToServerHandshake, Message, PacketBuilder, ServerToClientHandshake, UnscheduledPacket,
    };

    fn assert_roundtrip_message(msg: &Message) {
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
            s2c_packet_length: 2277,
            s2c_packet_interval_ns: 992828,
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

    #[test]
    fn roundtrip_unscheduled_packet() {
        assert_roundtrip_message(&Message::UnscheduledPacket(UnscheduledPacket {
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        }));
        let mut test_vec = Vec::new();
        for i in 0..500 {
            test_vec.push((i % 256).try_into().unwrap());
        }
        assert_roundtrip_message(&Message::UnscheduledPacket(UnscheduledPacket {
            packet: IpPacketBuffer::new(test_vec.as_ref()),
        }));
    }

    /// Ensure that s2c and c2s handshakes error out if the magic values or serdes versions are not
    /// equal
    #[test]
    fn magic_value_error() {
        let arr_arr = ArrayArray::<u8, 100>::new_empty(100);
        let mut write_cursor = WriteCursor::new(arr_arr);
        // TODO Test both handshakes
        write_cursor.write(ClientToServerHandshake::TYPE_BYTE);
        write_cursor.write(MAGIC_VALUE + 1 as u32);
        let buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursor::new(buf);
        assert!(
            has_message(&read_cursor),
            "Should be a message to deserialize"
        );
        assert!(
            read_cursor.read::<Message>()
                == Err(DeserializeMessageErr::WrongMagicValue(MAGIC_VALUE + 1)),
            "Magic values should not match"
        );
    }

    #[test]
    fn serdes_version_error() {
        let arr_arr = ArrayArray::<u8, 100>::new_empty(100);
        let mut write_cursor = WriteCursor::new(arr_arr);
        // TODO Test both handshakes
        write_cursor.write(ClientToServerHandshake::TYPE_BYTE);
        write_cursor.write(MAGIC_VALUE as u32);
        write_cursor.write(SERDES_VERSION + 1 as u32);
        let buf = write_cursor.into_inner();

        let mut read_cursor = ReadCursor::new(buf);
        assert!(
            has_message(&read_cursor),
            "Should be a message to deserialize"
        );
        assert!(
            read_cursor.read::<Message>()
                == Err(DeserializeMessageErr::UnsupportedSerdesVersion(
                    SERDES_VERSION + 1
                )),
            "Serdes versions should not match"
        );
    }

    // TODO: test packet builder actually returns false when a packet would overrun the buffer
}
