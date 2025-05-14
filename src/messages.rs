use array_array::ArrayArray;
use serdes::Serializable as _;

const MAX_IP_PACKET_LENGTH: usize = 1472; // TODO may want to remove this to support jumbo frames?

/// A buffer that is no larger than an IP packet (stored on stack)
type IpPacketBuffer = ArrayArray<u8, MAX_IP_PACKET_LENGTH>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpPacket {
    // TODO
}

pub(crate) struct PacketBuilder {
    output_bytes: IpPacketBuffer,
    num_bytes_written: usize,
}

impl PacketBuilder {
    /// Create a PacketBuilder that will eventually fill the passed-in buffer with messages
    pub(crate) fn new(packet_size: usize) -> PacketBuilder {
        PacketBuilder {
            output_bytes: IpPacketBuffer::new_empty(packet_size),
            num_bytes_written: 0,
        }
    }

    fn remaining_space(&self) -> usize {
        self.output_bytes.len() - self.num_bytes_written
    }

    pub(crate) fn finalize(self) -> IpPacketBuffer {
        // Already initialized it to zero, so remaining bytes are padding
        self.output_bytes
    }

    /// If there's space to add the given message to the packet, do so.
    pub(crate) fn try_add_message(&mut self, message: Message) -> bool {
        let mut length_serializer = serdes::LengthDeterminingSerializer::new();
        message.serialize(&mut length_serializer);

        let length = length_serializer.finalize();
        if length > self.remaining_space() {
            return false;
        }

        let mut actual_serializer = serdes::ActualSerializer::new(&mut self.output_bytes.as_mut()[self.num_bytes_written..]);
        message.serialize(&mut actual_serializer);
        // TODO consider using a Cursor-like class here to avoid keeping track of length manually
        self.num_bytes_written += length;
        true
    }
}

type MessageType = u8;

pub(crate) enum Message {
    UnscheduledPacket(UnscheduledPacket),
}

impl Message {
    /// Try to serialize into the given buffer (if we fit), returning how many bytes were written if
    /// we did fit. We avoid std::Write because it returns a whole-ass Result we don't need.
    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        match self {
            Message::UnscheduledPacket(unscheduled_packet) => unscheduled_packet.serialize(serializer),
        }
    }
}

pub(crate) struct UnscheduledPacket {
    length: u16,
    packet: IpPacketBuffer,
}

impl UnscheduledPacket {
    const TYPE_BYTE: u8 = 1;

    fn serialize<S: serdes::Serializer>(&self, serializer: &mut S) {
        Self::TYPE_BYTE.serialize(serializer);
        self.packet.serialize(serializer);
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum DeserializeMessageErr {
    UnknownMessageType(MessageType),
    Truncated,
}

fn deserialize_message(message_bytes: &[u8]) -> Result<Message, DeserializeMessageErr> {
    if message_bytes.len() == 0 {
        return Err(DeserializeMessageErr::Truncated)
    }

    let message_type = message_bytes[0];
    assert!(message_type != 0, "Message type was 0, ie padding. Padding should be skipped in outer loop.");

}

////////////////
// ARRAYARRAY //
////////////////

mod array_array {
    /// runtime-fixed length array inside a comptime-known fixed length array. Like a shitty
    /// ArrayVec, hence the name.
    pub(crate) struct ArrayArray<T, const COMPTIME_LENGTH: usize> {
        underlying: [T; COMPTIME_LENGTH],
        runtime_length: usize,
    }

    impl<T: Default + Copy, const COMPTIME_LENGTH: usize> ArrayArray<T, COMPTIME_LENGTH> {
        pub(crate) fn new(other: &[T]) -> ArrayArray<T, COMPTIME_LENGTH> {
            assert!(other.len() <= COMPTIME_LENGTH, "Tried to create ArrayArray from too long of a slice. Requested: {}, capacity: {}", other.len(), COMPTIME_LENGTH);

            let mut result = ArrayArray {
                underlying: [T::default(); COMPTIME_LENGTH], // there are ways to loosen the T: Copy bound but why bother
                runtime_length: other.len(),
            };
            result.underlying.copy_from_slice(other);
            result
        }

        /// New ArrayArray of given length of T::default()
        pub(crate) fn new_empty(length: usize) -> ArrayArray<T, COMPTIME_LENGTH> {
            assert!(length <= COMPTIME_LENGTH, "Tried to create ArrayArray from too long of a length. Requested: {}, capacity: {}", length, COMPTIME_LENGTH);
            ArrayArray {
                underlying: [T::default(); COMPTIME_LENGTH],
                runtime_length: length,
            }
        }

        pub(crate) fn len(&self) -> usize {
            self.runtime_length
        }
    }

    impl<T, const COMPTIME_LENGTH: usize> std::ops::Deref for ArrayArray<T, COMPTIME_LENGTH> {
        type Target = [T];

        fn deref(&self) -> &[T] {
            &self.underlying[0..self.runtime_length]
        }
    }

    impl<T, const COMPTIME_LENGTH: usize> std::ops::DerefMut for ArrayArray<T, COMPTIME_LENGTH> {
        fn deref_mut(&mut self) -> &mut [T] {
            &mut self.underlying[0..self.runtime_length]
        }
    }
}

////////////
// SERDES //
////////////

mod serdes {
    use crate::messages::array_array::ArrayArray;

    pub(crate) trait Serializer {
        fn serialize(&mut self, data: &[u8]);
    }

    pub(crate) trait Serializable {
        fn serialize<S: Serializer>(&self, serializer: &mut S);
    }

    macro_rules! serialize_integral {
        ($integral_type:ident) => {
            impl Serializable for $integral_type {
                fn serialize<S: Serializer>(&self, serializer: &mut S) {
                    serializer.serialize(&self.to_be_bytes());
                }
            }
        };
    }

    serialize_integral!(u8);
    serialize_integral!(u16);
    serialize_integral!(u32);
    serialize_integral!(u64);

    type VariableLengthBufferLength = u16;

    pub(crate) struct VariableLengthBuffer<'a> {
        data: &'a [u8],
    }

    impl<'a> VariableLengthBuffer<'a> {
        pub(crate) fn new(data: &'a [u8]) -> VariableLengthBuffer<'a> {
            VariableLengthBuffer { data }
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
            Self {
                length: 0,
            }
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

    pub(crate) struct ActualSerializer<'a> {
        target: &'a mut [u8],
        position: usize,
    }

    impl<'a> ActualSerializer<'a> {
        pub(crate) fn new(target: &'a mut [u8]) -> ActualSerializer<'a> {
            ActualSerializer {
                target,
                position: 0,
            }
        }
    }

    impl<'a> Serializer for ActualSerializer<'a> {
        fn serialize(&mut self, data: &[u8]) {
            let len = data.len();
            self.target[self.position..].copy_from_slice(data);
            self.position += len;
        }
    }
}
