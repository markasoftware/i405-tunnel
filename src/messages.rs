use crate::array_array::{ArrayArray, IpPacketBuffer};
use serdes::{Serializable as _, Deserializable as _};

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

    pub(crate) fn finalize(self) -> IpPacketBuffer {
        // Already initialized it to zero, so remaining bytes are padding
        self.write_cursor.into_inner()
    }

    /// If there's space to add the given message to the packet, do so.
    pub(crate) fn try_add_message(&mut self, message: Message) -> bool {
        let mut length_serializer = serdes::LengthDeterminingSerializer::new();
        message.serialize(&mut length_serializer);

        let length = length_serializer.finalize();
        if length > self.write_cursor.num_bytes_left() {
            return false;
        }

        message.serialize(&mut self.write_cursor);
        true
    }
}

type MessageType = u8;

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

impl serdes::Deserializable<'_> for ClientToServerHandshake {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Option<Self> {
        let magic_value: u32 = read_cursor.read()?;
        if magic_value != MAGIC_VALUE {
            return Err(DeserializeMessageErr::WrongMagicValue(magic_value));
        }

        // If this is not an exact match between client/server, we cannot even proceed with
        // deserialization. We could theoretically put this in the TYPE_BYTE instead, but I'd prefer
        // not to clutter the limited space of available types.
        let serdes_version: u32 = read_cursor.read()?;
        if serdes_version != SERDES_VERSION {
            return Err(DeserializeMessageErr::)
        }
    }
}

/// The server will send this message after receiving a ClientToServerHandshake, even if the
/// versions are incompatible.
pub(crate) struct ServerToClientHandshake {
    /// same as from the client, just to make sure we're both talking the same protocol
    magic_value: u32,
    serdes_version: u32,
    protocol_version: u32,
    /// If false, the client should abandon the connection.
    success: bool,
}

impl ServerToClientHandshake {
    const TYPE_BYTE: u8 = 2;
}

impl serdes::Serializable for ServerToClientHandshake {
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        self.success.serialize(serializer);
    }
}

//// UNSCHEDULED PACKET ////////////////////////////////////////////////////////////////////////////

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

impl serdes::Deserializable<'_> for UnscheduledPacket {
    fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Option<Self> {
        Some(UnscheduledPacket { packet: read_cursor.read()? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeserializeMessageErr {
    UnknownMessageType(MessageType),
    Truncated(Option<MessageType>),
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

fn deserialize_message(read_cursor: &mut ReadCursor<&[u8]>) -> Result<Message, DeserializeMessageErr> {
    let message_type = match read_cursor.read_exact_comptime::<1>() {
        Some(message_type_bytes) => message_type_bytes[0],
        None => return Err(DeserializeMessageErr::Truncated(None)),
    };
    assert!(message_type != 0, "Message type was 0, ie padding. Padding should be skipped in outer loop.");

    macro_rules! deserialize_messages {
        ($($msg:ident);+) => {
            $(
                if message_type == $msg::TYPE_BYTE {
                    return match $msg::deserialize(read_cursor) {
                        Some(deserialized) => Ok(deserialized),
                        None => Err(DeserializeMessageErr::Truncated(Some(message_type))),
                    }
                }
            )+
        };
    }
    deserialize_messages!(ClientToServerHandshake; ServerToClientHandshake; UnscheduledPacket);
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

    fn read_exact_comptime<const num: usize>(&mut self) -> Option<[u8; num]> {
        if self.num_bytes_left() >= num {
            self.position += num;
            Some(
                self.underlying.as_ref()[self.position - num..self.position]
                    .try_into()
                    .unwrap(),
            )
        } else {
            None
        }
    }

    fn read_exact_runtime(&mut self, len: usize) -> Option<&[u8]> {
        if self.num_bytes_left() >= len {
            self.position += len;
            Some(&self.underlying.as_ref()[self.position-len..self.position])
        } else {
            None
        }
    }

    fn read_exact_runtime_to(&mut self, dest: &mut [u8]) -> bool {
        match self.read_exact_runtime(dest.len()) {
            Some(read_bytes) => {
                dest.copy_from_slice(read_bytes);
                true
            },
            None => false,
        }
    }

    fn read<'a, D: serdes::Deserializable<'a>>(&mut self) -> Option<D> {
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
}

//// SERDES ////////////////////////////////////////////////////////////////////////////////////////

mod serdes {
    use crate::messages::array_array::ArrayArray;

    use crate::messages::{ReadCursor, WriteCursor};

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

    type VariableLengthBufferLength = u16;

    pub(crate) struct VariableLengthBuffer<'a> {
        data: &'a [u8],
    }

    impl<'a> VariableLengthBuffer<'a> {
        pub(crate) fn new(data: &'a [u8]) -> VariableLengthBuffer<'a> {
            VariableLengthBuffer { data }
        }

        pub(crate) fn into_inner(self) -> &'a [u8] {
            self.data
        }
    }

    impl<'a> Serializable for VariableLengthBuffer<'a> {
        fn serialize<S: Serializer>(&self, serializer: &mut S) {
            let len = VariableLengthBufferLength::try_from(self.data.len()).unwrap();
            len.serialize(serializer);
            serializer.serialize(self.data);
        }
    }

    impl<const C: usize> Serializable for ArrayArray<u8, C> {
        fn serialize<S: Serializer>(&self, serializer: &mut S) {
            VariableLengthBuffer::new(&*self).serialize(serializer);
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

        pub(crate) fn finalize(self) -> usize {
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

    pub(crate) trait Deserializable<'a> where Self: Sized {
        // could theoretically make this more generic than just ReadCursor, just like how Serialize
        // is generic over Serializers, but let's not do it until we need it.
        fn deserialize<T: AsRef<[u8]> + 'a>(read_cursor: &mut ReadCursor<T>) -> Option<Self>;
    }

    impl<'a> Deserializable<'a> for VariableLengthBuffer<'a> {
        fn deserialize<T: AsRef<[u8]> + 'a>(read_cursor: &mut ReadCursor<T>) -> Option<VariableLengthBuffer<'a>> {
            let len: u16 = read_cursor.read()?;
            Some(VariableLengthBuffer::new(read_cursor.read_exact_runtime(len.into())?))
        }
    }

    impl<const C: usize> Deserializable<'_> for ArrayArray<u8, C> {
        fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Option<Self> {
            // I have no idea how it's able to do type inference here and it might break catastrophically one day:
            read_cursor.read()?.into_inner()
        }
    }

    macro_rules! serdes_integral {
        ($integral_type:ident) => {
            impl Serializable for $integral_type {
                fn serialize<S: Serializer>(&self, serializer: &mut S) {
                    serializer.serialize(&self.to_be_bytes());
                }
            }

            impl Deserializable<'_> for $integral_type {
                fn deserialize<T: AsRef<[u8]>>(read_cursor: &mut ReadCursor<T>) -> Option<$integral_type> {
                    // I keep getting syntax errors trying to inline this into the <...> below
                    const SIZE: usize = size_of::<$integral_type>();
                    let read_bytes = read_cursor.read_exact_comptime::<SIZE>()?;
                    Some($integral_type::from_be_bytes(read_bytes))
                }
            }
        };
    }

    serdes_integral!(u8);
    serdes_integral!(u16);
    serdes_integral!(u32);
    serdes_integral!(u64);
}
