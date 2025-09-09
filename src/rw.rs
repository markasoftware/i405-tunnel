use std::collections::VecDeque;

use crate::{
    array_array::ArrayArray,
    serdes::{Deserializable, DeserializeError, Serializable},
};

/// Similar to std::io::Reader, but without the possibility af failure.
pub(crate) trait Reader {
    fn num_read_bytes_left(&self) -> usize;
    /// Return Something if we are able to read the full NUM bytes
    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]>;
    fn read_exact_comptime<const NUM: usize>(&mut self) -> Option<[u8; NUM]>;
    fn read_as_much_as_possible(&mut self, destination: &mut impl Writer) -> usize;

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

/// Similar to std::io::Writer, but without the possibility af failure.
pub(crate) trait Writer {
    fn write_unchecked(&mut self, data: &[u8]);
    // can return usize::MAX to be effectively unlimited
    fn num_write_bytes_left(&self) -> usize;

    fn write(&mut self, data: &[u8]) -> bool {
        let can_write = data.len() <= self.num_write_bytes_left();
        if can_write {
            self.write_unchecked(data);
        }
        can_write
    }

    fn serialize(&mut self, thing: impl Serializable)
    where
        Self: Sized,
    {
        thing.serialize(self)
    }
}

impl<W: Writer> Writer for &mut W {
    fn num_write_bytes_left(&self) -> usize {
        (**self).num_write_bytes_left()
    }

    fn write_unchecked(&mut self, buf: &[u8]) {
        (**self).write_unchecked(buf)
    }
}

#[derive(Debug)]
pub(crate) struct ReadCursor<T> {
    underlying: T,
    position: usize,
}

impl<T: AsRef<[u8]>> ReadCursor<T> {
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

impl<T: AsRef<[u8]>> Reader for ReadCursor<T> {
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

    fn read_as_much_as_possible(&mut self, destination: &mut impl Writer) -> usize {
        let amount_to_read = std::cmp::min(
            destination.num_write_bytes_left(),
            self.num_read_bytes_left(),
        );
        let start_position = self.position;
        self.position += amount_to_read;
        destination.write_unchecked(&self.underlying.as_ref()[start_position..self.position]);
        amount_to_read
    }
}

pub(crate) struct DestructiveVecDequeReader<'a> {
    underlying: &'a mut VecDeque<u8>,
}

impl<'a> DestructiveVecDequeReader<'a> {
    pub(crate) fn new(underlying: &'a mut VecDeque<u8>) -> Self {
        Self { underlying }
    }
}

/// Moves the start of the VecDeque forward as bytes are read.
impl<'a> Reader for DestructiveVecDequeReader<'a> {
    fn num_read_bytes_left(&self) -> usize {
        self.underlying.len()
    }

    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]> {
        (self.num_read_bytes_left() >= NUM).then(|| {
            // TODO consider using as_slices here instead for performance.
            let mut result = [0u8; NUM];
            for i in 0..NUM {
                result[i] = self.underlying[i];
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
                self.underlying.pop_front();
            }
        }
        result
    }

    fn read_as_much_as_possible(&mut self, destination: &mut impl Writer) -> usize {
        let num_bytes_to_read = std::cmp::min(
            destination.num_write_bytes_left(),
            self.num_read_bytes_left(),
        );

        let mut num_bytes_to_read_remaining = num_bytes_to_read;
        let (s1, s2) = self.underlying.as_slices();
        for slice in [s1, s2] {
            if num_bytes_to_read_remaining > 0 {
                let amount_from_this_slice = std::cmp::min(num_bytes_to_read, slice.len());
                destination.write_unchecked(&slice[..amount_from_this_slice]);
                num_bytes_to_read_remaining -= amount_from_this_slice;
            }
        }
        self.underlying.rotate_left(num_bytes_to_read);
        self.underlying
            .truncate(self.underlying.len() - num_bytes_to_read);
        num_bytes_to_read
    }
}

pub(crate) struct NonDestructiveVecDequeReader<'a> {
    underlying: &'a VecDeque<u8>,
    position: usize,
}

impl<'a> NonDestructiveVecDequeReader<'a> {
    pub(crate) fn new(underlying: &'a VecDeque<u8>) -> Self {
        Self {
            underlying,
            position: 0,
        }
    }
}

impl<'a> Reader for NonDestructiveVecDequeReader<'a> {
    fn num_read_bytes_left(&self) -> usize {
        self.underlying.len() - self.position
    }

    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]> {
        (self.num_read_bytes_left() >= NUM).then(|| {
            let mut result = [0u8; NUM];
            for i in 0..NUM {
                result[i] = self.underlying[self.position + i];
            }
            result
        })
    }

    fn read_exact_comptime<const NUM: usize>(&mut self) -> Option<[u8; NUM]> {
        let result = self.peek_exact_comptime::<NUM>();
        if result.is_some() {
            self.position += NUM;
        }
        result
    }

    fn read_as_much_as_possible(&mut self, destination: &mut impl Writer) -> usize {
        let amount_to_read = std::cmp::min(
            destination.num_write_bytes_left(),
            self.num_read_bytes_left(),
        );
        let start_position = self.position;
        let end_position = start_position + amount_to_read;
        self.position += amount_to_read;

        let (s1, s2) = self.underlying.as_slices();
        let mut cur_slice_position = 0;
        for slice in [s1, s2] {
            // does the request slice overlap with this slice at all?
            if start_position <= cur_slice_position + slice.len()
                && end_position > cur_slice_position
            {
                let slice_start = if start_position > cur_slice_position {
                    start_position - cur_slice_position
                } else {
                    0
                };
                let slice_end = std::cmp::min(slice.len(), end_position - cur_slice_position);
                destination.write_unchecked(&slice[slice_start..slice_end]);
            }

            cur_slice_position += slice.len();
        }
        amount_to_read
    }
}

pub(crate) struct LengthLimitedReader<R> {
    inner: R,
    limit: usize,
}

impl<R> LengthLimitedReader<R> {
    pub(crate) fn new(inner: R, limit: usize) -> Self {
        Self { inner, limit }
    }

    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Reader> Reader for LengthLimitedReader<R> {
    fn num_read_bytes_left(&self) -> usize {
        std::cmp::min(self.inner.num_read_bytes_left(), self.limit)
    }

    fn peek_exact_comptime<const NUM: usize>(&self) -> Option<[u8; NUM]> {
        (NUM <= self.limit)
            .then(|| self.inner.peek_exact_comptime::<NUM>())
            .flatten()
    }

    fn read_exact_comptime<const NUM: usize>(&mut self) -> Option<[u8; NUM]> {
        (NUM <= self.limit)
            .then(|| {
                let result = self.inner.read_exact_comptime::<NUM>();
                if result.is_some() {
                    self.limit -= NUM;
                }
                result
            })
            .flatten()
    }

    fn read_as_much_as_possible(&mut self, destination: &mut impl Writer) -> usize {
        let mut limited_destination = LengthLimitedWriter::new(destination, self.limit);
        let amount_read = self
            .inner
            .read_as_much_as_possible(&mut limited_destination);
        self.limit -= amount_read;
        amount_read
    }
}

#[derive(Debug)]
pub(crate) struct WriteCursor<T> {
    underlying: T,
    position: usize,
}

impl<T> WriteCursor<T> {
    pub(crate) fn new(underlying: T) -> Self {
        Self {
            underlying,
            position: 0,
        }
    }

    pub(crate) fn into_inner(self) -> T {
        self.underlying
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }
}

impl<const C: usize> Writer for WriteCursor<ArrayArray<u8, C>> {
    fn num_write_bytes_left(&self) -> usize {
        self.underlying.len() - self.position
    }

    fn write_unchecked(&mut self, buf: &[u8]) {
        let new_position = self.position + buf.len();
        self.underlying[self.position..new_position].copy_from_slice(buf);
        self.position = new_position;
    }
}

impl<const C: usize> Writer for WriteCursor<&mut ArrayArray<u8, C>> {
    fn num_write_bytes_left(&self) -> usize {
        self.underlying.len() - self.position
    }

    fn write_unchecked(&mut self, buf: &[u8]) {
        let new_position = self.position + buf.len();
        self.underlying[self.position..new_position].copy_from_slice(buf);
        self.position = new_position;
    }
}

/// We don't implement Writer directly on VecDeque in order to force the user to always specify a
/// max capacity. (We can't just rely on the VecDeque's inner capacity, because Rust doesn't
/// guarantee that the VecDeque capacity will be exactly what's requested)
pub(crate) struct VecDequeWriter<'a> {
    // this could be phrased as a LengthLimitingWriter around an un-restricted VecDeque writer, but
    // it's actually less code to just use monolithic vecdeque-writing + length-limiting logic
    // together.
    inner: &'a mut VecDeque<u8>,
    capacity: usize,
}

impl<'a> VecDequeWriter<'a> {
    pub(crate) fn new(inner: &'a mut VecDeque<u8>, capacity: usize) -> Self {
        assert!(
            inner.len() <= capacity,
            "Tried to construct VecDequeWriter with capacity shorter than length of VecDeque"
        );
        Self { inner, capacity }
    }
}

impl Writer for VecDequeWriter<'_> {
    fn num_write_bytes_left(&self) -> usize {
        self.capacity - self.inner.len()
    }

    fn write_unchecked(&mut self, buf: &[u8]) {
        assert!(
            buf.len() <= self.num_write_bytes_left(),
            "tried to write too many bytes into VecDeque"
        );
        // hopefully the rest of this optimizes well
        self.inner.resize(self.inner.len() + buf.len(), 0u8);
        self.inner.rotate_right(buf.len());
        let mut num_bytes_written = 0;
        let (s1, s2) = self.inner.as_mut_slices();
        for slice in [s1, s2] {
            if num_bytes_written < buf.len() {
                let amount_from_this_slice =
                    std::cmp::min(buf.len() - num_bytes_written, slice.len());
                slice[..amount_from_this_slice].copy_from_slice(
                    &buf[num_bytes_written..num_bytes_written + amount_from_this_slice],
                );
                num_bytes_written += amount_from_this_slice;
            }
        }
        self.inner.rotate_left(buf.len());
    }
}

/// Discard first `skip` bytes written
pub(crate) struct SkipWriter<W: Writer> {
    inner: W,
    skip: usize,
}

impl<W: Writer> SkipWriter<W> {
    pub(crate) fn new(inner: W, skip: usize) -> Self {
        Self { inner, skip }
    }
}

impl<W: Writer> Writer for SkipWriter<W> {
    fn num_write_bytes_left(&self) -> usize {
        self.skip + self.inner.num_write_bytes_left()
    }

    fn write_unchecked(&mut self, data: &[u8]) {
        if self.skip < data.len() {
            self.inner.write_unchecked(&data[self.skip..]);
        }
        self.skip = self.skip.saturating_sub(data.len());
    }
}

/// If underlying writer runs out of space, allow unlimited extra writes and just discard them.
pub(crate) struct DiscardExcessWriter<W> {
    inner: W,
    // once the inner is full, we never write anything more to it, even if it un-fills later
    is_inner_exhausted: bool,
    num_bytes_forwarded: usize,
}

impl<W: Writer> DiscardExcessWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            is_inner_exhausted: false,
            num_bytes_forwarded: 0,
        }
    }

    pub(crate) fn num_bytes_forwarded(&self) -> usize {
        self.num_bytes_forwarded
    }
}

impl<W: Writer> Writer for DiscardExcessWriter<W> {
    fn num_write_bytes_left(&self) -> usize {
        usize::MAX
    }

    fn write_unchecked(&mut self, data: &[u8]) {
        if self.is_inner_exhausted {
            return;
        }

        let num_inner_bytes_left = self.inner.num_write_bytes_left();
        let num_bytes_to_forward = std::cmp::min(num_inner_bytes_left, data.len());
        self.num_bytes_forwarded += num_bytes_to_forward;
        self.inner.write(&data[..num_bytes_to_forward]);
        if num_bytes_to_forward == num_inner_bytes_left {
            self.is_inner_exhausted = true;
        }
    }
}

pub(crate) struct LengthLimitedWriter<W> {
    inner: W,
    limit: usize,
}

impl<W> LengthLimitedWriter<W> {
    pub(crate) fn new(inner: W, limit: usize) -> Self {
        Self { inner, limit }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Writer> Writer for LengthLimitedWriter<W> {
    fn num_write_bytes_left(&self) -> usize {
        std::cmp::min(self.inner.num_write_bytes_left(), self.limit)
    }

    fn write_unchecked(&mut self, buf: &[u8]) {
        assert!(
            buf.len() <= self.num_write_bytes_left(),
            "tried to write too many bytes into LengthLimitedWriter"
        );
        self.inner.write_unchecked(buf);
        self.limit -= buf.len();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn read_contiguous() {
        let mut cursor = ReadCursor::new([1u8, 2, 3, 4, 5]);
        assert_eq!(cursor.peek_exact_comptime::<3>(), Some([1, 2, 3]));
        assert_eq!(cursor.peek_exact_comptime::<6>(), None);
        assert_eq!(cursor.read_exact_comptime::<3>(), Some([1, 2, 3]));
        assert_eq!(cursor.read_exact_comptime::<3>(), None);
        assert_eq!(cursor.peek_exact_comptime::<2>(), Some([4, 5]));
        assert_eq!(cursor.peek_exact_comptime::<3>(), None);

        let mut wc1 = WriteCursor::new(ArrayArray::<u8, 2>::new_empty(2));
        cursor.read_as_much_as_possible(&mut wc1);
        assert_eq!(wc1.into_inner()[..], [4, 5]);

        // should be nothing left to write; let's assert that.
        let mut wc2 = WriteCursor::new(ArrayArray::<u8, 2>::new_empty(2));
        cursor.read_as_much_as_possible(&mut wc2);
        assert_eq!(wc2.into_inner()[..], [0, 0]);
    }

    #[test]
    fn write_contiguous() {
        let mut cursor = WriteCursor::new(ArrayArray::<u8, 5>::new_empty(5));
        assert!(cursor.write(&[1, 2, 3]));
        assert!(!cursor.write(&[4, 5, 6]));
        assert!(cursor.write(&[4, 5]));
        assert_eq!(cursor.into_inner().as_ref(), &[1, 2, 3, 4, 5]);
    }

    fn deque_test_inner(cursor: &mut impl Reader) {
        assert_eq!(cursor.peek_exact_comptime::<3>(), Some([2, 3, 4]));
        assert_eq!(cursor.peek_exact_comptime::<6>(), None);
        assert_eq!(cursor.read_exact_comptime::<3>(), Some([2, 3, 4]));
        assert_eq!(cursor.read_exact_comptime::<3>(), None);
        assert_eq!(cursor.peek_exact_comptime::<2>(), Some([5, 1]));
        assert_eq!(cursor.peek_exact_comptime::<3>(), None);

        let mut wc1 = WriteCursor::new(ArrayArray::<u8, 2>::new_empty(2));
        cursor.read_as_much_as_possible(&mut wc1);
        assert_eq!(wc1.into_inner()[..], [5, 1]);

        let mut wc2 = WriteCursor::new(ArrayArray::<u8, 2>::new_empty(2));
        cursor.read_as_much_as_possible(&mut wc2);
        assert_eq!(wc2.into_inner()[..], [0, 0]);
        // If we switch to as_slices, would want even more tests here.
        // TODO we did this ^^ so add more tests!
    }

    #[test]
    fn vec_deque_destructive_reader() {
        let mut deque = VecDeque::from([1u8, 2, 3, 4, 5]);
        deque.rotate_left(1);
        let mut cursor = DestructiveVecDequeReader::new(&mut deque);
        deque_test_inner(&mut cursor);
        assert!(deque.is_empty());
    }

    #[test]
    fn vec_deque_non_destructive_reader() {
        let mut deque = VecDeque::from([1u8, 2, 3, 4, 5]);
        deque.rotate_left(1);
        let mut cursor = NonDestructiveVecDequeReader::new(&mut deque);
        deque_test_inner(&mut cursor);
        assert_eq!(deque.make_contiguous(), &[2, 3, 4, 5, 1]);
    }

    #[test]
    fn vec_deque_writer() {
        let mut deque = VecDeque::new();
        let mut writer = VecDequeWriter::new(&mut deque, 5);
        // TODO test when rotated
        writer.write_unchecked(&[1, 2, 3]);
        writer.write_unchecked(&[4, 5]);
        assert_eq!(deque.make_contiguous(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn length_limited_writer() {
        let mut cursor =
            LengthLimitedWriter::new(WriteCursor::new(ArrayArray::<u8, 5>::new_empty(5)), 2);
        assert_eq!(cursor.num_write_bytes_left(), 2);
        cursor.write_unchecked(&[1]);
        assert_eq!(cursor.num_write_bytes_left(), 1);
        cursor.write_unchecked(&[2]);
        assert_eq!(cursor.num_write_bytes_left(), 0);
        assert_eq!(&cursor.into_inner().into_inner()[..], &[1, 2, 0, 0, 0]);
    }

    #[test]
    fn length_limited_reader() {
        let array = [1u8, 2, 3, 4, 5];
        let mut cursor = LengthLimitedReader::new(ReadCursor::new(&array), 2);
        assert_eq!(cursor.num_read_bytes_left(), 2);
        assert_eq!(cursor.peek_exact_comptime::<3>(), None);
        assert_eq!(cursor.peek_exact_comptime::<2>(), Some([1, 2]));
        assert_eq!(cursor.read_exact_comptime::<3>(), None);
        assert_eq!(cursor.read_exact_comptime::<2>(), Some([1, 2]));
        assert_eq!(cursor.num_read_bytes_left(), 0);

        // now test read_as_much_as_possible
        let array = [1u8, 2, 3, 4, 5];
        let mut cursor = LengthLimitedReader::new(ReadCursor::new(&array), 2);
        let mut buf = ArrayArray::<u8, 2>::new_empty(2);
        assert_eq!(
            cursor.read_as_much_as_possible(&mut WriteCursor::new(&mut buf)),
            2
        );
        assert_eq!(&buf[..], &[1, 2]);
        assert_eq!(cursor.num_read_bytes_left(), 0);
    }

    #[test]
    fn skip_writer() {
        let mut deque = VecDeque::<u8>::new();
        let mut writer = SkipWriter::new(VecDequeWriter::new(&mut deque, 100), 4);
        writer.write(&[1, 2, 3]);
        writer.write(&[4, 5, 6, 7]);
        assert_eq!(deque.make_contiguous(), &[5, 6, 7]);
    }

    #[test]
    fn discard_excess_writer() {
        let mut deque = VecDeque::<u8>::new();
        let mut writer = DiscardExcessWriter::new(VecDequeWriter::new(&mut deque, 5));
        writer.write(&[1, 2, 3]);
        assert_eq!(writer.num_bytes_forwarded(), 3);
        writer.write(&[4, 5, 6, 7]);
        assert_eq!(writer.num_bytes_forwarded(), 5);
        writer.write(&[8]);
        assert_eq!(writer.num_bytes_forwarded(), 5);
        assert_eq!(deque.make_contiguous(), &[1, 2, 3, 4, 5]);
        // this doesn't exercise the `is_inner_exhausted` logic bc no existing writers can reset
        // their state and accept more input after filling up.
    }
}
