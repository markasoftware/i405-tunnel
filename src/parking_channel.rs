use std::sync::{Arc, atomic::Ordering, mpsc};

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

trait MpscSender<T> {
    fn send(&self, item: T) -> Result<(), mpsc::SendError<T>>;
}

trait MpscReceiver<T> {
    fn try_recv(&self) -> Result<T, mpsc::TryRecvError>;
}

trait Mpsc<T> {
    type Sender: MpscSender<T>;
    type Receiver: MpscReceiver<T>;

    fn channel() -> (Self::Sender, Self::Receiver);
}

impl<T> MpscSender<T> for mpsc::Sender<T> {
    fn send(&self, item: T) -> Result<(), mpsc::SendError<T>> {
        self.send(item)
    }
}

impl<T> MpscReceiver<T> for mpsc::Receiver<T> {
    fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
        self.try_recv()
    }
}

struct StdMpsc;

impl<T> Mpsc<T> for StdMpsc {
    type Sender = mpsc::Sender<T>;
    type Receiver = mpsc::Receiver<T>;

    fn channel() -> (Self::Sender, Self::Receiver) {
        mpsc::channel()
    }
}

// don't need traits for mpsc::Sender or mpsc::Receiver because we only use the non-blocking `try_*`
// methods on these, so loom wouldn't have anything to reorder wrt sending and receiving.

pub(crate) struct Sender<T, M: Mpsc<T>, U: Unparker, A: AtomicBool> {
    inner: M::Sender,
    unparker: U,
    observed_empty: Arc<A>,
}

pub(crate) struct Receiver<T, M: Mpsc<T>, A: AtomicBool> {
    inner: M::Receiver,
    observed_empty: Arc<A>,
}

fn channel<T, M: Mpsc<T>, U: Unparker, A: AtomicBool>(
    unparker: U,
) -> (Sender<T, M, U, A>, Receiver<T, M, A>) {
    let (inner_sender, inner_receiver) = M::channel();
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
        },
    )
}

impl<T, M: Mpsc<T>, U: Unparker, A: AtomicBool> Sender<T, M, U, A> {
    fn send(self: &mut Sender<T, M, U, A>, item: T) -> Result<(), mpsc::SendError<T>> {
        // send first so we can't possibly wake up other side and they observe empty again before we
        // even sent it
        self.inner.send(item)?;
        // don't really need seqcst, but it ensures that loom is deterministic
        if self.observed_empty.load() {
            self.observed_empty.store(false);
            self.unparker.unpark();
        }
        Ok(())
    }
}

impl<T, M: Mpsc<T>, A: AtomicBool> Receiver<T, M, A> {
    pub(crate) fn try_recv(self: &mut Self) -> Result<T, mpsc::TryRecvError> {
        match self.inner.try_recv() {
            Ok(item) => Ok(item),
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
            }
            Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::TryRecvError::Disconnected),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use loom::sync::atomic::AtomicBool as LoomAtomicBool;
    use parking::Parker;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool as StdAtomicBool;
    use std::{
        cell::Cell,
        sync::{atomic::AtomicU64, mpsc},
    };

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

    impl Unparker for &MockUnparker {
        fn unpark(&self) {
            self.num_times_unparked
                .set(self.num_times_unparked.get() + 1);
        }
    }

    // a little cursed but it works for us; doing a blanket impl over AsRef<Notify> makes it worried
    // about conflicts due to future crates implementing AsRef<Notify> eg on parking::Unparker
    impl Unparker for Arc<loom::sync::Notify> {
        fn unpark(&self) {
            self.notify()
        }
    }

    // gigacursed: We can't use `loom::mpsc` because of what I interpret as a bug in loom: It
    // doesn't properly branch / schedule / recognize cross-thread dependencies or whatever on
    // try_recv and so only does one iteration if you use `loom::sync::mpsc`. Using a mutex
    // explicitly like here lets it know for sure there is a cross-thread dependency.

    impl<T> MpscSender<T> for Arc<loom::sync::Mutex<VecDeque<T>>> {
        fn send(&self, item: T) -> Result<(), mpsc::SendError<T>> {
            self.lock().unwrap().push_back(item);
            Ok(())
        }
    }

    impl<T> MpscReceiver<T> for Arc<loom::sync::Mutex<VecDeque<T>>> {
        fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
            self.lock()
                .unwrap()
                .pop_front()
                .ok_or(mpsc::TryRecvError::Empty)
        }
    }

    struct LoomMpsc;

    impl<T> Mpsc<T> for LoomMpsc {
        type Sender = Arc<loom::sync::Mutex<VecDeque<T>>>;
        type Receiver = Arc<loom::sync::Mutex<VecDeque<T>>>;

        fn channel() -> (Self::Sender, Self::Receiver) {
            let sender = Arc::new(loom::sync::Mutex::new(VecDeque::new()));
            (sender.clone(), sender)
        }
    }

    // just mocks out the unparker and verifies it's unparked the correct number of times (rule out spurious wakeups)
    #[test]
    fn send_recv_one_thread() {
        let unparker = MockUnparker::new();
        let (mut sender, mut receiver) =
            channel::<u64, StdMpsc, &MockUnparker, StdAtomicBool>(&unparker);
        // assert_eq vs unwrap, the eternal debate
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
        // why not twice?
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));

        assert_eq!(unparker.num_times_unparked(), 0);
        sender.send(0).unwrap();
        assert_eq!(unparker.num_times_unparked(), 1);
        assert_eq!(receiver.try_recv(), Ok(0));

        sender.send(1).unwrap();
        sender.send(2).unwrap();
        assert_eq!(receiver.try_recv(), Ok(1));
        sender.send(3).unwrap();
        assert_eq!(receiver.try_recv(), Ok(2));
        assert_eq!(receiver.try_recv(), Ok(3));
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
        // final count check
        assert_eq!(unparker.num_times_unparked(), 1);
    }

    // what does an effective loom test for the parking channel look like? The tricky bits are
    // around ensuring that no matter how you're reading from the channel, you're consistently
    // awoken enough to read everything. We won't assert against spurious wakeups here; the tests
    // using MockUnparker above should handle that.
    #[test]
    fn loom_two_threads() {
        loom::model(|| {
            let notify = Arc::new(loom::sync::Notify::new());
            let (mut sender, mut receiver) =
                channel::<u64, LoomMpsc, Arc<loom::sync::Notify>, LoomAtomicBool>(notify.clone());
            let num_items = 2;
            // SENDER
            loom::thread::spawn(move || {
                for i in 0..num_items {
                    sender.send(i);
                }
            });
            // RECEIVER
            loom::thread::spawn(move || {
                let mut next_expected: u64 = 0;
                while next_expected < num_items {
                    match receiver.try_recv() {
                        Ok(i) => {
                            assert_eq!(i, next_expected);
                            next_expected += 1;
                        }
                        // block until we can read sth
                        Err(mpsc::TryRecvError::Empty) => notify.wait(),
                        Err(mpsc::TryRecvError::Disconnected) => panic!("Disconnected!"),
                    }
                }
            });
            // no need to `.join` the threads; loom::model always waits until spawned threads exit
        });
    }
}
