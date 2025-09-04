use crate::array_array::ArrayArray;
use crate::cursors::{ReadCursor, WriteCursor};

use anyhow::anyhow;

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

impl<T: WriteCursor> Serializer for T {
    fn serialize(&mut self, data: &[u8]) {
        // we could just write this as assert!, since assert! is never optimized out like in C
        if !self.write_exact(data) {
            panic!("Destination not long enough to serialize into");
        }
    }
}

// it's important for us to be able to tell when an error is specifically Truncation in some stream
// handling code, where we repeatedly try to deserialize data from a stream every time we get more
// data, until we get success or a non-truncation error
#[derive(Debug)]
pub(crate) enum DeserializeError {
    Truncated,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for DeserializeError {
    fn from(value: anyhow::Error) -> Self {
        Self::Other(value)
    }
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "Truncated message cannot be deserialized"),
            Self::Other(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for DeserializeError {}

pub(crate) trait Deserializable
where
    Self: Sized,
{
    // could theoretically make this more generic than just ReadCursor, just like how Serialize
    // is generic over Serializers, but let's not do it until we need it.
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError>;
}

impl<const C: usize> Deserializable for ArrayArray<u8, C> {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        let len: SerializedArrayArrayLength = read_cursor.read()?;
        let mut result = ArrayArray::new_empty(len.into());
        if !read_cursor.read_exact_runtime(&mut result) {
            return Err(DeserializeError::Truncated);
        }
        Ok(result)
    }
}

impl Deserializable for bool {
    fn deserialize(read_cursor: &mut impl ReadCursor) -> Result<Self, DeserializeError> {
        let byte: u8 = read_cursor.read()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(anyhow!("Invalid bool byte {byte:#x}").into()),
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
            fn deserialize(
                read_cursor: &mut impl ReadCursor,
            ) -> Result<$integral_type, DeserializeError> {
                // I keep getting syntax errors trying to inline this into the <...> below
                const SIZE: usize = size_of::<$integral_type>();
                let read_bytes = read_cursor
                    .read_exact_comptime::<SIZE>()
                    .ok_or(DeserializeError::Truncated)?;
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
