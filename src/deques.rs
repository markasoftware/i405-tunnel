use std::{
    collections::VecDeque,
    ops::{Index, IndexMut},
};

use bitvec::{slice::BitSlice, vec::BitVec};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct BitArrDeque {
    bitvec: BitVec,
    head: usize,
    len: usize,
}

/// A few things here: Fixed max length, but it can be less than that size as well (initially).
/// There's also no public API to pop, instead `push` returns the item that got knocked off when you
/// go over capacity.
impl BitArrDeque {
    pub(crate) fn new(capacity: usize) -> BitArrDeque {
        let mut bitvec = BitVec::with_capacity(capacity);
        // there's probably a better way to do this
        for _ in 0..capacity {
            bitvec.push(false);
        }
        BitArrDeque {
            bitvec,
            head: 0,
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bitvec.len()
    }

    pub(crate) fn set(&mut self, index: usize, value: bool) {
        let internal_index = self.external_to_internal_index(index);
        self.bitvec.set(internal_index, value);
    }

    pub(crate) fn push(&mut self, value: bool) -> Option<bool> {
        let result = if self.len() == self.bitvec.len() {
            Some(self.pop())
        } else {
            None
        };
        let push_idx = (self.head + self.len) % self.bitvec.len();
        self.bitvec.set(push_idx, value);
        self.len += 1;
        result
    }

    fn pop(&mut self) -> bool {
        debug_assert!(self.len() > 0, "Tried to pop from empty BitArrDeque");
        let result = self.bitvec[self.head];
        self.head = (self.head + 1) % self.bitvec.len();
        self.len -= 1;
        result
    }

    fn external_to_internal_index(&self, external_index: usize) -> usize {
        assert!(
            external_index < self.len(),
            "index {} out of range for BitArrDeque with length {}",
            external_index,
            self.len()
        );
        (self.head + external_index) % self.bitvec.len()
    }

    fn slices_after(&self, start_idx: usize) -> (&BitSlice, Option<&BitSlice>) {
        // start_idx < self.len() is enforced by external_to_internal_index
        let internal_start_idx = self.external_to_internal_index(start_idx);
        let capacity = self.bitvec.len();
        let num_to_check = self.len() - start_idx;

        // First part of search: from internal_start_idx to end of bitvec
        let first_part_len = std::cmp::min(num_to_check, capacity - internal_start_idx);
        let slice1 = &self.bitvec[internal_start_idx..internal_start_idx + first_part_len];

        // Second part of search (if wrapped around)
        let second_part_len = num_to_check - first_part_len;
        let slice2 = if second_part_len > 0 {
            Some(&self.bitvec[0..second_part_len])
        } else {
            None
        };

        (slice1, slice2)
    }

    /// find first one after the given index. As a precondition you must make sure the index is
    /// within bounds.
    pub(crate) fn first_one_after(&self, start_idx: usize) -> Option<usize> {
        let (slice1, slice2) = self.slices_after(start_idx);

        slice1
            .first_one()
            .map(|rel_idx| start_idx + rel_idx)
            .or(slice2.and_then(|s2| {
                s2.first_one()
                    .map(|rel_idx| start_idx + slice1.len() + rel_idx)
            }))
    }

    pub(crate) fn first_zero_after(&self, start_idx: usize) -> Option<usize> {
        let (slice1, slice2) = self.slices_after(start_idx);

        slice1
            .first_zero()
            .map(|rel_idx| start_idx + rel_idx)
            .or(slice2.and_then(|s2| {
                s2.first_zero()
                    .map(|rel_idx| start_idx + slice1.len() + rel_idx)
            }))
    }
}

impl Index<usize> for BitArrDeque {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        self.bitvec.index(self.external_to_internal_index(index))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct GlobalBitArrDeque {
    bit_arr_deque: BitArrDeque,
    head_global_idx: u64,
}

impl GlobalBitArrDeque {
    pub(crate) fn new(capacity: usize) -> GlobalBitArrDeque {
        GlobalBitArrDeque {
            bit_arr_deque: BitArrDeque::new(capacity),
            head_global_idx: 0,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bit_arr_deque.capacity()
    }

    /// If the deque filled up, report what got popped out
    pub(crate) fn push(&mut self, value: bool) -> Option<(u64, bool)> {
        self.bit_arr_deque.push(value).map(|popped| {
            let popped_idx = self.head_global_idx;
            self.head_global_idx += 1;
            (popped_idx, popped)
        })
    }

    pub(crate) fn head_index(&self) -> u64 {
        self.head_global_idx
    }

    /// one past the end
    pub(crate) fn tail_index(&self) -> u64 {
        self.head_global_idx + u64::try_from(self.bit_arr_deque.len()).unwrap()
    }

    pub(crate) fn set(&mut self, index: u64, value: bool) {
        // debug because subtraction below will check the same thing
        debug_assert!(
            index >= self.head_index(),
            "Tried to `set` index {}, less than head_index() {}",
            index,
            self.head_index()
        );
        // this is a unnecessary because the length will be checked in the main BitArrDeque
        debug_assert!(
            index < self.tail_index(),
            "Tried to `set` index {}, greater than tail_index() {}",
            index,
            self.tail_index()
        );
        self.bit_arr_deque
            .set(usize::try_from(index - self.head_index()).unwrap(), value);
    }

    pub(crate) fn first_one_after(&self, start_idx: u64) -> Option<u64> {
        let local_start_idx = usize::try_from(start_idx - self.head_global_idx).unwrap();
        self.bit_arr_deque
            .first_one_after(local_start_idx)
            .map(|local_idx| self.head_global_idx + u64::try_from(local_idx).unwrap())
    }

    pub(crate) fn first_zero_after(&self, start_idx: u64) -> Option<u64> {
        let local_start_idx = usize::try_from(start_idx - self.head_global_idx).unwrap();
        self.bit_arr_deque
            .first_zero_after(local_start_idx)
            .map(|local_idx| self.head_global_idx + u64::try_from(local_idx).unwrap())
    }
}

impl Index<u64> for GlobalBitArrDeque {
    type Output = bool;

    fn index(&self, index: u64) -> &Self::Output {
        self.bit_arr_deque.index(
            usize::try_from(
                index
                    .checked_sub(self.head_global_idx)
                    .expect("Tried to index before head index in global bit deque"),
            )
            .unwrap(),
        )
    }
}

/// Like a VecDeque, but with size fixed at construction time (note: not compile time)
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ArrDeque<T> {
    arr_deque: VecDeque<T>,
}

impl<T> ArrDeque<T> {
    pub(crate) fn new(capacity: usize) -> ArrDeque<T> {
        assert!(capacity > 0);
        ArrDeque {
            arr_deque: VecDeque::with_capacity(capacity),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.arr_deque.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.arr_deque.capacity()
    }

    pub(crate) fn push(&mut self, value: T) -> Option<T> {
        let result = if self.len() == self.arr_deque.capacity() {
            self.arr_deque.pop_front()
        } else {
            None
        };
        self.arr_deque.push_back(value);
        result
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.arr_deque.pop_front()
    }
}

impl<T> Index<usize> for ArrDeque<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.arr_deque.index(index)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct GlobalArrDeque<T> {
    arr_deque: VecDeque<T>,
    head_global_idx: u64,
}

impl<T> GlobalArrDeque<T> {
    pub(crate) fn new(capacity: usize) -> GlobalArrDeque<T> {
        assert!(capacity > 0);
        GlobalArrDeque {
            arr_deque: VecDeque::with_capacity(capacity),
            head_global_idx: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.arr_deque.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.arr_deque.capacity()
    }

    pub(crate) fn push(&mut self, value: T) -> Option<(u64, T)> {
        let result = if self.len() == self.capacity() {
            let popped_idx = self.head_global_idx;
            self.head_global_idx += 1;
            let popped = self.arr_deque.pop_front().unwrap();
            Some((popped_idx, popped))
        } else {
            None
        };
        self.arr_deque.push_back(value);
        result
    }

    pub(crate) fn pop(&mut self) -> (u64, T) {
        debug_assert!(self.len() > 0, "Tried to pop from empty GlobalArrDeque");
        let popped_idx = self.head_global_idx;
        self.head_global_idx += 1;
        let popped = self.arr_deque.pop_front().unwrap();
        (popped_idx, popped)
    }

    pub(crate) fn head_index(&self) -> u64 {
        self.head_global_idx
    }

    pub(crate) fn tail_index(&self) -> u64 {
        self.head_global_idx + u64::try_from(self.arr_deque.len()).unwrap()
    }
}

impl<T> Index<u64> for GlobalArrDeque<T> {
    type Output = T;

    fn index(&self, index: u64) -> &Self::Output {
        debug_assert!(
            index >= self.head_index(),
            "Tried to `set` index {}, less than head_index() {}",
            index,
            self.head_index()
        );
        debug_assert!(
            index < self.tail_index(),
            "Tried to `set` index {}, greater than tail_index() {}",
            index,
            self.tail_index()
        );
        self.arr_deque
            .index(usize::try_from(index - self.head_index()).unwrap())
    }
}

impl<T> IndexMut<u64> for GlobalArrDeque<T> {
    fn index_mut(&mut self, index: u64) -> &mut Self::Output {
        debug_assert!(
            index >= self.head_index(),
            "Tried to `set` index {}, less than head_index() {}",
            index,
            self.head_index()
        );
        debug_assert!(
            index < self.tail_index(),
            "Tried to `set` index {}, greater than tail_index() {}",
            index,
            self.tail_index()
        );
        self.arr_deque
            .index_mut(usize::try_from(index - self.head_index()).unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn arr_deque() {
        let mut ad = ArrDeque::<i32>::new(3);
        assert_eq!(ad.len(), 0);
        assert_eq!(ad.capacity(), 3);

        assert_eq!(ad.push(1), None);
        assert_eq!(ad.push(2), None);
        assert_eq!(ad.push(3), None);
        assert_eq!(ad.len(), 3);
        assert_eq!(ad[1], 2);

        assert_eq!(ad.push(4), Some(1));
        assert_eq!(ad.len(), 3);

        assert_eq!(ad.pop(), Some(2));
        assert_eq!(ad.pop(), Some(3));
        assert_eq!(ad.pop(), Some(4));
        assert_eq!(ad.pop(), None);
        assert_eq!(ad.len(), 0);
    }

    #[test]
    fn bit_arr_deque() {
        let mut bad = BitArrDeque::new(3);
        assert_eq!(bad.len(), 0);
        assert_eq!(bad.capacity(), 3);
        assert_eq!(bad.push(true), None);
        assert_eq!(bad.push(false), None);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad.push(true), None);
        assert_eq!(bad.push(true), Some(true));
        bad.set(2, false);
        assert_eq!(bad.push(false), Some(false));
        assert_eq!(bad.push(true), Some(true));
        assert_eq!(bad.push(true), Some(false));
        assert_eq!(bad.len(), 3);
        assert_eq!(bad.pop(), false);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad[0], true);
    }

    #[test]
    fn bit_arr_deque_first_one_zero_after() {
        let mut bad = BitArrDeque::new(5);
        assert_eq!(bad.capacity(), 5);

        // [t, f, t, f]
        bad.push(true);
        bad.push(false);
        bad.push(true);
        bad.push(false);
        assert_eq!(bad.len(), 4);

        assert_eq!(bad.first_one_after(0), Some(0));
        assert_eq!(bad.first_one_after(1), Some(2));
        assert_eq!(bad.first_one_after(2), Some(2));
        assert_eq!(bad.first_one_after(3), None);

        assert_eq!(bad.first_zero_after(0), Some(1));
        assert_eq!(bad.first_zero_after(1), Some(1));
        assert_eq!(bad.first_zero_after(2), Some(3));
        assert_eq!(bad.first_zero_after(3), Some(3));

        // wrap around: push some more to make it wrap
        // capacity 5.
        // initial state: head=0, len=4, data=[t,f,t,f,?]
        // push(t): len=5, data=[t,f,t,f,t]
        assert_eq!(bad.push(true), None);
        assert_eq!(bad.len(), 5);
        // push(f): pop t, head=1, len=5.
        // deque is [f, t, f, t, f]
        assert_eq!(bad.push(false), Some(true));
        assert_eq!(bad[0], false);
        assert_eq!(bad[1], true);
        assert_eq!(bad[2], false);
        assert_eq!(bad[3], true);
        assert_eq!(bad[4], false);

        assert_eq!(bad.first_one_after(0), Some(1));
        assert_eq!(bad.first_one_after(1), Some(1));
        assert_eq!(bad.first_one_after(2), Some(3));
        assert_eq!(bad.first_one_after(3), Some(3));
        assert_eq!(bad.first_one_after(4), None);

        assert_eq!(bad.first_zero_after(0), Some(0));
        assert_eq!(bad.first_zero_after(1), Some(2));
        assert_eq!(bad.first_zero_after(2), Some(2));
        assert_eq!(bad.first_zero_after(3), Some(4));
        assert_eq!(bad.first_zero_after(4), Some(4));
    }

    #[test]
    fn global_bit_arr_deque() {
        let mut gbad = GlobalBitArrDeque::new(3);
        assert_eq!(gbad.head_index(), 0);
        assert_eq!(gbad.tail_index(), 0);
        assert_eq!(gbad.capacity(), 3);
        assert_eq!(gbad.push(true), None); // 0
        assert_eq!(gbad.push(false), None); // 1
        assert_eq!(gbad.push(true), None); // 2
        assert_eq!(gbad.head_index(), 0);
        assert_eq!(gbad.tail_index(), 3);
        assert_eq!(gbad.push(true), Some((0, true))); // 3
        assert_eq!(gbad.push(false), Some((1, false))); // 4
        assert_eq!(gbad.head_index(), 2);
        assert_eq!(gbad.tail_index(), 5);
        assert_eq!(gbad[3], true);
        assert_eq!(gbad[4], false);
        gbad.set(3, false);
        assert_eq!(gbad.push(true), Some((2, true))); // 5
        assert_eq!(gbad.push(true), Some((3, false))); // 6
    }

    #[test]
    fn global_bit_arr_deque_first_one_zero_after() {
        let mut gbad = GlobalBitArrDeque::new(3);

        // push some values
        gbad.push(false); // 0
        gbad.push(true); // 1
        gbad.push(false); // 2
        // deque: [f, t, f], head_global_idx: 0, tail_index: 3
        assert_eq!(gbad.first_one_after(0), Some(1));
        assert_eq!(gbad.first_one_after(1), Some(1));
        assert_eq!(gbad.first_one_after(2), None);

        assert_eq!(gbad.first_zero_after(0), Some(0));
        assert_eq!(gbad.first_zero_after(1), Some(2));
        assert_eq!(gbad.first_zero_after(2), Some(2));

        // push to wrap
        gbad.push(true); // 3, pops (0, f)
        // deque: [t, f, t], head_global_idx: 1, tail_index: 4
        // indices 1, 2, 3
        assert_eq!(gbad.first_one_after(1), Some(1));
        assert_eq!(gbad.first_one_after(2), Some(3));
        assert_eq!(gbad.first_one_after(3), Some(3));

        assert_eq!(gbad.first_zero_after(1), Some(2));
        assert_eq!(gbad.first_zero_after(2), Some(2));
        assert_eq!(gbad.first_zero_after(3), None);
    }

    #[test]
    fn global_arr_deque() {
        let mut gbad = GlobalArrDeque::<bool>::new(3);
        assert_eq!(gbad.head_index(), 0);
        assert_eq!(gbad.tail_index(), 0);
        assert_eq!(gbad.capacity(), 3);
        assert_eq!(gbad.push(true), None); // 0
        assert_eq!(gbad.push(false), None); // 1
        assert_eq!(gbad.push(true), None); // 2
        assert_eq!(gbad.head_index(), 0);
        assert_eq!(gbad.tail_index(), 3);
        assert_eq!(gbad.push(true), Some((0, true))); // 3
        assert_eq!(gbad.push(false), Some((1, false))); // 4
        assert_eq!(gbad.head_index(), 2);
        assert_eq!(gbad.tail_index(), 5);
        assert_eq!(gbad[3], true);
        assert_eq!(gbad[4], false);
        gbad[3] = false;
        assert_eq!(gbad.push(true), Some((2, true))); // 5
        assert_eq!(gbad.push(true), Some((3, false))); // 6
    }
}
