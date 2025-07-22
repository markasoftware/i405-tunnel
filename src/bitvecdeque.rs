use std::ops::{Index, IndexMut};

use bitvec::vec::BitVec;

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
}

pub(crate) struct GlobalBitArrDeque {
    bit_arr_deque: BitArrDeque,
    head_global_idx: usize,
}

impl GlobalBitArrDeque {
    pub(crate) fn new(capacity: usize) -> GlobalBitArrDeque {
        GlobalBitArrDeque {
            bit_arr_deque: BitArrDeque::new(capacity),
            head_global_idx: 0,
        }
    }

    /// If the deque filled up, report what got popped out
    pub(crate) fn push(&mut self, value: bool) -> Option<(usize, bool)> {
        self.bit_arr_deque.push(value).map(|popped| {
            let popped_idx = self.head_global_idx;
            self.head_global_idx += 1;
            (popped_idx, popped)
        })
    }

    pub(crate) fn head_index(&self) -> usize {
        self.head_global_idx
    }

    /// one past the end
    pub(crate) fn tail_index(&self) -> usize {
        self.head_global_idx + self.bit_arr_deque.len()
    }

    pub(crate) fn set(&mut self, index: usize, value: bool) {
        // debug because subtraction below will check the same thing
        debug_assert!(
            index >= self.head_index(),
            "Tried to `set` index {}, less than head_index() {}",
            index,
            self.head_index()
        );
        // this is a unnecessary because the length will be checked in the main BitArrDeque
        debug_assert!(
            index < self.head_index() + self.bit_arr_deque.len(),
            "Tried to `set` index {}, greater than tail_index() {}",
            index,
            self.tail_index()
        );
        self.bit_arr_deque.set(index - self.head_index(), value);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bit_arr_deque() {
        let mut bad = BitArrDeque::new(3);
        assert_eq!(bad.len(), 0);
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
    }

    #[test]
    fn global_bit_arr_deque() {
        let mut gbad = GlobalBitArrDeque::new(3);
        assert_eq!(gbad.head_index(), 0);
        assert_eq!(gbad.tail_index(), 0);
        assert_eq!(gbad.push(true), None); // 0
        assert_eq!(gbad.push(false), None); // 1
        assert_eq!(gbad.push(true), None); // 2
        assert_eq!(gbad.head_index(), 0);
        assert_eq!(gbad.tail_index(), 3);
        assert_eq!(gbad.push(true), Some((0, true))); // 3
        assert_eq!(gbad.push(true), Some((1, false))); // 4
        assert_eq!(gbad.head_index(), 2);
        assert_eq!(gbad.tail_index(), 5);
        gbad.set(3, false);
        assert_eq!(gbad.push(true), Some((2, true))); // 5
        assert_eq!(gbad.push(true), Some((3, false))); // 6
    }
}
