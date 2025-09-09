use crate::array_array::ArrayArray;
use crate::rw::{LengthLimitedWriter, Reader, WriteCursor, Writer};

use anyhow::anyhow;

pub(crate) trait Serializable {
    fn serialize<W: Writer>(&self, writer: &mut W);
}

impl Serializable for bool {
    fn serialize<W: Writer>(&self, writer: &mut W) {
        (if *self { 1u8 } else { 0u8 }).serialize(writer);
    }
}

type SerializedArrayArrayLength = u16;

impl<const C: usize> Serializable for ArrayArray<u8, C> {
    fn serialize<W: Writer>(&self, writer: &mut W) {
        let len = SerializedArrayArrayLength::try_from(self.len()).unwrap();
        len.serialize(writer);
        writer.write_unchecked(self); // I think deref coercion here?
    }
}

/// doesn't actually serialize; just figures out how long a message will be once serialized
pub(crate) struct LengthDeterminingWriter {
    length: usize,
}

impl LengthDeterminingWriter {
    pub(crate) fn new() -> Self {
        Self { length: 0 }
    }

    pub(crate) fn into_inner(self) -> usize {
        self.length
    }
}

impl Writer for LengthDeterminingWriter {
    fn write_unchecked(&mut self, data: &[u8]) {
        self.length += data.len();
    }

    fn num_write_bytes_left(&self) -> usize {
        usize::MAX
    }
}

pub(crate) trait SerializableLength {
    fn serialized_length(&self) -> usize;
}

impl<T: Serializable> SerializableLength for T {
    fn serialized_length(&self) -> usize {
        let mut length_writer = LengthDeterminingWriter::new();
        self.serialize(&mut length_writer);
        length_writer.into_inner()
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
    fn deserialize(reader: &mut impl Reader) -> Result<Self, DeserializeError>;
}

pub(crate) fn deserialize_arrayarray_len_prior_knowledge<const C: usize>(
    reader: &mut impl Reader,
    inner_len: usize,
) -> Result<ArrayArray<u8, C>, DeserializeError> {
    let mut result = ArrayArray::new_empty(inner_len);
    let amount_read = reader.read_as_much_as_possible(&mut WriteCursor::new(&mut result));
    if amount_read == inner_len {
        Ok(result)
    } else {
        Err(DeserializeError::Truncated)
    }
}

impl<const C: usize> Deserializable for ArrayArray<u8, C> {
    fn deserialize(reader: &mut impl Reader) -> Result<Self, DeserializeError> {
        let len: SerializedArrayArrayLength = reader.read()?;
        let mut result = ArrayArray::new_empty(len.into());
        if reader.read_as_much_as_possible(&mut LengthLimitedWriter::new(
            WriteCursor::new(&mut result),
            len.into(),
        )) != len.into()
        {
            return Err(DeserializeError::Truncated);
        }
        Ok(result)
    }
}

impl Deserializable for bool {
    fn deserialize(read_cursor: &mut impl Reader) -> Result<Self, DeserializeError> {
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
            fn serialize<W: Writer>(&self, writer: &mut W) {
                writer.write(&self.to_be_bytes());
            }
        }

        impl Deserializable for $integral_type {
            fn deserialize(
                read_cursor: &mut impl Reader,
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
