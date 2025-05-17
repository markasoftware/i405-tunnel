use crate::constants::MAX_IP_PACKET_LENGTH;

/// runtime-fixed length array inside a comptime-known fixed length array. Like a shitty
/// ArrayVec, hence the name.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ArrayArray<T, const COMPTIME_LENGTH: usize> {
    underlying: [T; COMPTIME_LENGTH],
    runtime_length: usize,
}

impl<T: Default + Copy, const COMPTIME_LENGTH: usize> ArrayArray<T, COMPTIME_LENGTH> {
    pub(crate) fn new(other: &[T]) -> ArrayArray<T, COMPTIME_LENGTH> {
        assert!(
            other.len() <= COMPTIME_LENGTH,
            "Tried to create ArrayArray from too long of a slice. Requested: {}, capacity: {}",
            other.len(),
            COMPTIME_LENGTH
        );

        let mut result = ArrayArray {
            underlying: [T::default(); COMPTIME_LENGTH], // there are ways to loosen the T: Copy bound but why bother
            runtime_length: other.len(),
        };
        result.underlying[..other.len()].copy_from_slice(other);
        result
    }

    /// New ArrayArray of given length of T::default()
    pub(crate) fn new_empty(length: usize) -> ArrayArray<T, COMPTIME_LENGTH> {
        assert!(
            length <= COMPTIME_LENGTH,
            "Tried to create ArrayArray from too long of a length. Requested: {}, capacity: {}",
            length,
            COMPTIME_LENGTH
        );
        ArrayArray {
            underlying: [T::default(); COMPTIME_LENGTH],
            runtime_length: length,
        }
    }

    pub(crate) fn shrink(&mut self, new_length: usize) {
        assert!(new_length <= self.runtime_length, "shrink should only be used to actually shrink");
        self.runtime_length = new_length;
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

impl<T, const COMPTIME_LENGTH: usize> AsRef<[T]> for ArrayArray<T, COMPTIME_LENGTH> {
    fn as_ref(&self) -> &[T] {
        &*self
    }
}

pub(crate) type IpPacketBuffer = ArrayArray<u8, MAX_IP_PACKET_LENGTH>;
