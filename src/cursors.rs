use std::collections::VecDeque;

use crate::{
    array_array::ArrayArray,
    serdes::{Deserializable, DeserializeError, Serializable},
};

pub(crate) trait ReadCursor {
    fn num_read_bytes_left(&self) -> usize;
    /// Return Something if we are able to read the full NUM bytes
    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]>;
    fn read_exact_comptime<const NUM: usize>(&mut self) -> Option<[u8; NUM]>;
    /// Return whether destination could be filled
    #[must_use]
    fn read_exact_runtime(&mut self, destination: &mut [u8]) -> bool;

    fn read_as_much_as_possible(&mut self, destination: &mut [u8]) -> usize {
        let num_bytes_to_read = std::cmp::min(self.num_read_bytes_left(), destination.len());
        let success = self.read_exact_runtime(&mut destination[..num_bytes_to_read]);
        assert!(success);
        num_bytes_to_read
    }

    fn empty(&self) -> bool {
        self.num_read_bytes_left() == 0
    }

    fn read<D: Deserializable>(&mut self) -> Result<D, DeserializeError>
    where
        Self: Sized,
    {
        D::deserialize(self)
    }
}

#[derive(Debug)]
pub(crate) struct ReadCursorContiguous<T> {
    underlying: T,
    position: usize,
}

impl<T: AsRef<[u8]>> ReadCursorContiguous<T> {
    pub(crate) fn new(underlying: T) -> Self {
        Self {
            underlying,
            position: 0,
        }
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }
}

impl<T: AsRef<[u8]>> ReadCursor for ReadCursorContiguous<T> {
    fn num_read_bytes_left(&self) -> usize {
        self.underlying.as_ref().len() - self.position
    }

    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]> {
        (self.num_read_bytes_left() >= NUM).then(|| {
            self.underlying.as_ref()[self.position..self.position + NUM]
                .try_into()
                .unwrap()
        })
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

    fn read_exact_runtime(&mut self, destination: &mut [u8]) -> bool {
        let have_enough_bytes = self.num_read_bytes_left() >= destination.len();
        if have_enough_bytes {
            let start_position = self.position;
            self.position = start_position + destination.len();
            destination.copy_from_slice(&self.underlying.as_ref()[start_position..self.position]);
        }
        have_enough_bytes
    }
}

/// Moves the start of the VecDeque forward as bytes are read.
impl ReadCursor for VecDeque<u8> {
    fn num_read_bytes_left(&self) -> usize {
        self.len()
    }

    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]> {
        (self.len() >= NUM).then(|| {
            // TODO consider using as_slices here instead for performance.
            let mut result = [0u8; NUM];
            for i in 0..NUM {
                result[i] = self[i];
            }
            result
        })
    }

    fn read_exact_comptime<const NUM: usize>(&mut self) -> Option<[u8; NUM]> {
        let result = self.peek_exact_comptime::<NUM>();
        // TODO Consider `ringbuf` package, it'll be much faster. Or, we can use rotate_left +
        // truncate, or wait for truncate_front stabilization.
        if result.is_some() {
            for _ in 0..NUM {
                self.pop_front();
            }
        }
        result
    }

    fn read_exact_runtime(&mut self, destination: &mut [u8]) -> bool {
        let have_enough_bytes = self.len() >= destination.len();
        if have_enough_bytes {
            for i in 0..destination.len() {
                // TODO once again, can use as_slices + rotate_left + truncate
                destination[i] = self.pop_front().unwrap()
            }
        }
        have_enough_bytes
    }
}

pub(crate) trait WriteCursor {
    fn num_write_bytes_left(&self) -> usize;
    fn write_exact(&mut self, buf: &[u8]) -> bool;

    fn write(&mut self, thing: impl Serializable)
    where
        Self: Sized,
    {
        thing.serialize(self)
    }
}

#[derive(Debug)]
pub(crate) struct WriteCursorContiguous<T> {
    underlying: T,
    position: usize,
}

impl<T> WriteCursorContiguous<T> {
    pub(crate) fn new(underlying: T) -> Self {
        Self {
            underlying,
            position: 0,
        }
    }

    pub(crate) fn into_inner(self) -> T {
        self.underlying
    }
}

impl<const C: usize> WriteCursor for WriteCursorContiguous<ArrayArray<u8, C>> {
    fn num_write_bytes_left(&self) -> usize {
        self.underlying.len() - self.position
    }

    fn write_exact(&mut self, buf: &[u8]) -> bool {
        let have_enough_space = self.num_write_bytes_left() >= buf.len();
        if have_enough_space {
            self.position += buf.len();
            self.underlying[self.position - buf.len()..self.position].copy_from_slice(buf);
        }
        have_enough_space
    }
}

impl WriteCursor for VecDeque<u8> {
    fn num_write_bytes_left(&self) -> usize {
        // assume we don't want to resize the vecdeques, which is generally accurate for us.
        self.capacity() - self.len()
    }

    fn write_exact(&mut self, buf: &[u8]) -> bool {
        let have_enough_space = self.num_write_bytes_left() >= buf.len();
        if have_enough_space {
            // TODO consider ringbuf package instead for performance.
            for byte in buf {
                self.push_back(*byte);
            }
        }
        have_enough_space
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn read_contiguous() {
        let mut cursor = ReadCursorContiguous::new([1u8, 2, 3, 4, 5]);
        assert_eq!(cursor.peek_exact_comptime::<3>(), Some([1, 2, 3]));
        assert_eq!(cursor.peek_exact_comptime::<6>(), None);
        assert_eq!(cursor.read_exact_comptime::<3>(), Some([1, 2, 3]));
        assert_eq!(cursor.read_exact_comptime::<3>(), None);
        assert_eq!(cursor.peek_exact_comptime::<2>(), Some([4, 5]));
        assert_eq!(cursor.peek_exact_comptime::<3>(), None);

        let mut buf = [0u8; 2];
        assert!(cursor.read_exact_runtime(&mut buf));
        assert_eq!(buf, [4, 5]);
        assert!(!cursor.read_exact_runtime(&mut buf));
    }

    #[test]
    fn write_contiguous() {
        let mut cursor = WriteCursorContiguous::new(ArrayArray::<u8, 5>::new_empty(5));
        assert!(cursor.write_exact(&[1, 2, 3]));
        assert!(!cursor.write_exact(&[4, 5, 6]));
        assert!(cursor.write_exact(&[4, 5]));
        assert_eq!(cursor.into_inner().as_ref(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn vec_deque() {
        let mut cursor = VecDeque::from([1u8, 2, 3, 4, 5]);
        cursor.rotate_left(1); // doesn't affect current impl, but in future might use as_slices
        assert_eq!(cursor.peek_exact_comptime::<3>(), Some([2, 3, 4]));
        assert_eq!(cursor.peek_exact_comptime::<6>(), None);
        assert_eq!(cursor.read_exact_comptime::<3>(), Some([2, 3, 4]));
        assert_eq!(cursor.read_exact_comptime::<3>(), None);
        assert_eq!(cursor.peek_exact_comptime::<2>(), Some([5, 1]));
        assert_eq!(cursor.peek_exact_comptime::<3>(), None);

        let mut buf = [0u8; 2];
        assert!(cursor.read_exact_runtime(&mut buf));
        assert_eq!(buf, [5, 1]);
        assert!(!cursor.read_exact_runtime(&mut buf));
        // If we switch to as_slices, would want even more tests here.
    }
}
