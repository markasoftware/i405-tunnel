use std::sync::{atomic::Ordering, mpsc, Arc};

// an mpsc queue that notifies a Parker whenever an item is added to a queue the first time after it
// was observed as being empty. For our Cores: They consume data from multiple queues until there is
// no more work to do, at which point they park. "No more work to do" doesn't mean all queues are
// empty, though. Sometimes the Core is blocked on another queue, or a timer (eg TUN is generating
// traffic faster than configured tx rate). Thus, we don't want to notify on every queue addition,
// else we'd get lots of spurious wakeups (tun going faster than tx rate is common). At the same
// time, we can't just do "wake up every time we add to an empty queue" because high performance
// multithreaded queues just don't have "check length" or "peek" apis for performance reasons.
// Further, that wouldn't be perfect behavior anyway: Even if a queue is empty, it may not have been
// /observed empty/ yet -- the Core may have read the final item from the queue, rendering it empty,
// but did not attempt to read from it again, and therefore does not need to be woken on the next
// item.

// traits only exist for easy Loom testing

trait Unparker {
    fn unpark(&self);
}

impl Unparker for parking::Unparker {
    fn unpark(&self) {
        parking::Unparker::unpark(self);
    }
}

trait AtomicBool {
    fn store(&self, val: bool);
    fn load(&self) -> bool;
    fn new(val: bool) -> Self;
}

impl AtomicBool for std::sync::atomic::AtomicBool {
    fn store(&self, val: bool) {
        Self::store(self, val, Ordering::SeqCst);
    }

    fn load(&self) -> bool {
        Self::load(self, Ordering::SeqCst)
    }

    fn new(val: bool) -> Self {
        Self::new(val)
    }
}

// don't need traits for mpsc::Sender or mpsc::Receiver because we only use the non-blocking `try_*`
// methods on these, so loom wouldn't have anything to reorder wrt sending and receiving.

pub(crate) struct Sender<T, U: Unparker, A: AtomicBool> {
    inner: mpsc::Sender<T>,
    unparker: U,
    observed_empty: Arc<A>,
}

pub(crate) struct Receiver<T, A: AtomicBool> {
    inner: mpsc::Receiver<T>,
    observed_empty: Arc<A>,
}

fn channel<T, U: Unparker, A: AtomicBool>(unparker: U) -> (Sender<T, U, A>, Receiver<T, A>) {
    let (inner_sender, inner_receiver) = mpsc::channel();
    let observed_empty = Arc::new(A::new(false));
    (
        Sender {
            inner: inner_sender,
            unparker,
            observed_empty: observed_empty.clone(),
        },
        Receiver {
            inner: inner_receiver,
            observed_empty,
        }
    )
}

impl<T, U: Unparker, A: AtomicBool> Sender<T, U, A> {
    fn send(self: &mut Sender<T, U, A>, item: T) -> Result<(), mpsc::SendError<T>> {
        // send first so we can't possibly wake up other side and they observe empty again before we
        // even sent it
        self.inner.send(item)?;
        // don't really need seqcst, but it ensures that loom is deterministic
        if self.observed_empty.load() {
            self.unparker.unpark();
        }
        Ok(())
    }
}

impl<T, A: AtomicBool> Receiver<T, A> {
    pub(crate) fn try_recv(self: &mut Self) -> Result<T, mpsc::TryRecvError> {
        match self.inner.try_recv() {
            Ok(item) => {
                Ok(item)
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.observed_empty.store(true);
                // try to read once more
                match self.inner.try_recv() {
                    Ok(item) => {
                        // not really needed, but might avoid an extra spurious wakeup
                        self.observed_empty.store(false);
                        Ok(item)
                    }
                    Err(mpsc::TryRecvError::Empty) => Err(mpsc::TryRecvError::Empty),
                    Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::TryRecvError::Disconnected),
                }
            },
            Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::TryRecvError::Disconnected),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{cell::Cell, sync::{atomic::AtomicU64, mpsc}};
    use std::sync::atomic::AtomicBool as StdAtomicBool;
    use loom::sync::atomic::AtomicBool as LoomAtomicBool;
    use parking::Parker;

    impl AtomicBool for LoomAtomicBool {
        fn store(&self, val: bool) {
            Self::store(self, val, Ordering::SeqCst);
        }

        fn load(&self) -> bool {
            Self::load(self, Ordering::SeqCst)
        }

        fn new(val: bool) -> Self {
            Self::new(val)
        }
    }

    struct MockUnparker {
        num_times_unparked: Cell<u64>,
    }

    impl MockUnparker {
        fn new() -> Self {
            Self {
                num_times_unparked: Cell::new(0),
            }
        }

        fn num_times_unparked(&self) -> u64 {
            self.num_times_unparked.get()
        }
    }

    impl Unparker for MockUnparker {
        fn unpark(&self) {
            self.num_times_unparked.set(self.num_times_unparked.get() + 1);
        }
    }

    #[test]
    fn send_recv_no_parker() {
        let unparker = MockUnparker::new();
        let (mut sender, mut receiver) = channel::<u64, MockUnparker, StdAtomicBool>(unparker);
        // assert_eq vs unwrap, the eternal debate
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
        // why not twice?
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));

        sender.send(0).unwrap();
        assert_eq!(receiver.try_recv(), Ok(0));

        sender.send(1).unwrap();
        sender.send(2).unwrap();
        assert_eq!(receiver.try_recv(), Ok(1));
        sender.send(3).unwrap();
        assert_eq!(receiver.try_recv(), Ok(2));
        assert_eq!(receiver.try_recv(), Ok(3));
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn send_recv_parker() {
        let unparker = MockUnparker::new();
        let (mut sender, mut receiver) = channel::<u64, MockUnparker, StdAtomicBool>(unparker);
    }
}
