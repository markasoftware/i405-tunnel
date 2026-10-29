use std::sync::atomic::AtomicBool as StdAtomicBool;

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

// This file is laughably complicated because I wanted to try out Loom. So this file is very
// thoroughly tested by Loom, and in the process I discovered that Loom is not very good about
// exploration. It's mpsc implementation does not have proper exploration hooks everywhere, so we
// have to wrap an mpsc queue with random mutex locks and unlocks just to convince it that threads
// are interacting. Loom's mpsc is especially bad because it will never emit a Disconnected, it just
// goes to Empty indefinitely, which would break our test. So we're actually testing using a hacky
// wrapper around std mpsc with extra loom mutex locks and unlocks :| but at the end of the day,
// this fairly simple structure here is extremely thoroughly tested!

pub(crate) type Sender<T> = detail::Sender<T, detail::StdMpsc, parking::Unparker, StdAtomicBool>;
pub(crate) type Receiver<T> = detail::Receiver<T, detail::StdMpsc, StdAtomicBool>;

pub(crate) fn channel<T>(unparker: parking::Unparker) -> (Sender<T>, Receiver<T>) {
    detail::channel(unparker)
}

pub(crate) mod sync {
    use super::{StdAtomicBool, detail};

    pub(crate) type Sender<T, const N: usize> =
        detail::Sender<T, detail::StdSyncMpsc<N>, parking::Unparker, StdAtomicBool>;
    pub(crate) type Receiver<T, const N: usize> =
        detail::Receiver<T, detail::StdSyncMpsc<N>, StdAtomicBool>;

    pub(crate) fn channel<T, const N: usize>(
        unparker: parking::Unparker,
    ) -> (Sender<T, N>, Receiver<T, N>) {
        detail::channel(unparker)
    }
}

mod detail {

    use std::sync::atomic::AtomicBool as StdAtomicBool;
    use std::sync::{Arc, atomic::Ordering, mpsc};

    pub(crate) trait Unparker {
        fn unpark(&self);
    }

    impl Unparker for parking::Unparker {
        fn unpark(&self) {
            parking::Unparker::unpark(self);
        }
    }

    pub(crate) trait AtomicBool {
        fn store(&self, val: bool);
        fn load(&self) -> bool;
        fn new(val: bool) -> Self;
    }

    impl AtomicBool for StdAtomicBool {
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

    pub(crate) trait MpscSender<T> {
        fn send(&self, item: T) -> Result<(), mpsc::SendError<T>>;
    }

    pub(crate) trait MpscReceiver<T> {
        fn try_recv(&self) -> Result<T, mpsc::TryRecvError>;
    }

    pub(crate) trait Mpsc<T> {
        type Sender: MpscSender<T>;
        type Receiver: MpscReceiver<T>;

        fn channel() -> (Self::Sender, Self::Receiver);
    }

    impl<T> MpscSender<T> for mpsc::Sender<T> {
        fn send(&self, item: T) -> Result<(), mpsc::SendError<T>> {
            self.send(item)
        }
    }

    impl<T> MpscSender<T> for mpsc::SyncSender<T> {
        fn send(&self, item: T) -> Result<(), mpsc::SendError<T>> {
            self.send(item)
        }
    }

    impl<T> MpscReceiver<T> for mpsc::Receiver<T> {
        fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
            self.try_recv()
        }
    }

    pub(crate) struct StdMpsc;

    impl<T> Mpsc<T> for StdMpsc {
        type Sender = mpsc::Sender<T>;
        type Receiver = mpsc::Receiver<T>;

        fn channel() -> (Self::Sender, Self::Receiver) {
            mpsc::channel()
        }
    }

    pub(crate) struct StdSyncMpsc<const N: usize>;

    impl<T, const N: usize> Mpsc<T> for StdSyncMpsc<N> {
        type Sender = mpsc::SyncSender<T>;
        type Receiver = mpsc::Receiver<T>;

        fn channel() -> (Self::Sender, Self::Receiver) {
            mpsc::sync_channel(N)
        }
    }

    // don't need traits for mpsc::Sender or mpsc::Receiver because we only use the non-blocking `try_*`
    // methods on these, so loom wouldn't have anything to reorder wrt sending and receiving.

    pub(crate) struct Sender<T, M: Mpsc<T>, U: Unparker, A: AtomicBool> {
        // option so we can drop it before sending out the notification on Drop
        inner: Option<M::Sender>,
        unparker: U,
        observed_empty: Arc<A>,
    }

    pub(crate) struct Receiver<T, M: Mpsc<T>, A: AtomicBool> {
        inner: M::Receiver,
        observed_empty: Arc<A>,
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn channel<T, M: Mpsc<T>, U: Unparker, A: AtomicBool>(
        unparker: U,
    ) -> (Sender<T, M, U, A>, Receiver<T, M, A>) {
        let (inner_sender, inner_receiver) = M::channel();
        let observed_empty = Arc::new(A::new(false));
        (
            Sender {
                inner: Some(inner_sender),
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
        pub(crate) fn send(
            self: &mut Sender<T, M, U, A>,
            item: T,
        ) -> Result<(), mpsc::SendError<T>> {
            // send first so we can't possibly wake up other side and they observe empty again before we
            // even sent it
            self.inner.as_ref().unwrap().send(item)?;
            // don't really need seqcst, but it ensures that loom is deterministic
            if self.observed_empty.load() {
                self.observed_empty.store(false);
                self.unparker.unpark();
            }
            Ok(())
        }
    }

    impl<T, M: Mpsc<T>, U: Unparker, A: AtomicBool> Drop for Sender<T, M, U, A> {
        fn drop(&mut self) {
            // drop the mpsc sender first so we're guaranteed that by the time the receiver observes
            // it, they'll be able to read the Disconnected error.
            self.inner = None;
            self.unparker.unpark();
        }
    }

    impl<T, M: Mpsc<T>, A: AtomicBool> Receiver<T, M, A> {
        pub(crate) fn try_recv(&mut self) -> Result<T, mpsc::TryRecvError> {
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
                        Err(mpsc::TryRecvError::Disconnected) => {
                            Err(mpsc::TryRecvError::Disconnected)
                        }
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
        use std::{cell::Cell, sync::mpsc};

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

        // a little cursed but it works for us; doing a blanket impl over AsRef<Notify> makes it
        // worried about conflicts due to future crates implementing AsRef<Notify> eg on
        // parking::Unparker
        impl Unparker for Arc<loom::sync::Notify> {
            fn unpark(&self) {
                self.notify()
            }
        }

        // gigacursed: We can't use `loom::mpsc` because of what I interpret as a bug in loom: It
        // doesn't properly branch / schedule / recognize cross-thread dependencies or whatever on
        // try_recv and so only does one iteration if you use `loom::sync::mpsc`. Using a mutex
        // explicitly like here lets it know for sure there is a cross-thread dependency.

        struct LoomMpsc;

        struct LoomSender<T> {
            inner: Option<mpsc::Sender<T>>,
            mutex: Arc<loom::sync::Mutex<()>>,
        }

        impl<T> MpscSender<T> for LoomSender<T> {
            fn send(&self, item: T) -> Result<(), mpsc::SendError<T>> {
                let _guard = self.mutex.lock().unwrap();
                self.inner.as_ref().unwrap().send(item)
            }
        }

        // we need to do mutex ops around the drop in order for loom to properly fail when we swap
        // the order of the operations in the ParkingChannel Drop implementation.
        impl<T> Drop for LoomSender<T> {
            fn drop(&mut self) {
                let _guard = self.mutex.lock().unwrap();
                drop(self.inner.take());
            }
        }

        struct LoomReceiver<T> {
            inner: mpsc::Receiver<T>,
            mutex: Arc<loom::sync::Mutex<()>>,
        }

        impl<T> MpscReceiver<T> for LoomReceiver<T> {
            fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
                let _guard = self.mutex.lock().unwrap();
                self.inner.try_recv()
            }
        }

        impl<T> Mpsc<T> for LoomMpsc {
            type Sender = LoomSender<T>;
            type Receiver = LoomReceiver<T>;

            fn channel() -> (Self::Sender, Self::Receiver) {
                let (sender, receiver) = mpsc::channel::<T>();
                let mutex = Arc::new(loom::sync::Mutex::new(()));
                let sender = LoomSender {
                    inner: Some(sender),
                    mutex: mutex.clone(),
                };
                let receiver = LoomReceiver {
                    inner: receiver,
                    mutex,
                };
                (sender, receiver)
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

        #[test]
        fn sender_drop() {
            let unparker = MockUnparker::new();
            let (sender, mut receiver) =
                channel::<u64, StdMpsc, &MockUnparker, StdAtomicBool>(&unparker);
            assert_eq!(unparker.num_times_unparked(), 0);
            std::mem::drop(sender);
            assert_eq!(unparker.num_times_unparked(), 1);
            assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Disconnected));
        }

        // what does an effective loom test for the parking channel look like? The tricky bits are
        // around ensuring that no matter how you're reading from the channel, you're consistently
        // awoken enough to read everything. We won't assert against spurious wakeups here; the tests
        // using MockUnparker above should handle that.

        // Generally the best way to verify that loom is actually testing what you want it to test
        // is by mutation test: Modify the code in a way that should subtly break the test, and
        // verify that it actually breaks. For example, for us, that means eg changing the order at
        // which we add to the queue, and reset the "observed empty" atomic bool, and observing that
        // the test fails. I'm not gonna automate that, but if you modify any of this code,
        // definitely do some mutations and check that the loom tests fail!
        #[test]
        #[ignore]
        fn loom_two_threads() {
            loom::model(|| {
                let notify = Arc::new(loom::sync::Notify::new());
                let (mut sender, mut receiver) =
                    channel::<u64, LoomMpsc, Arc<loom::sync::Notify>, LoomAtomicBool>(
                        notify.clone(),
                    );
                // it took a very long time (about 15 minutes), but this passed at 3 as well.
                let num_items = 2;
                let send_thread = loom::thread::spawn(move || {
                    for i in 0..num_items {
                        sender.send(i).unwrap();
                    }
                    sender
                });
                let recv_thread = loom::thread::spawn(move || {
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
                // in loom, you generally don't need to explicitly `join` the threads; the
                // loom::model will implicitly go until all threads have completed. The reason we
                // wait is subtle: We want to make sure `sender` is not dropped until after both
                // threads are done, because on Drop, the sender does an extra explicit `unpark`! We
                // want to make sure everything stays live / the receiver gets appropriately
                // unparked even without the extra unpark from the drop.
                recv_thread.join().unwrap();
                // type annotation just to make sure it's actually returned and wasn't dropped
                // earlier
                let _sender: super::Sender<u64, LoomMpsc, Arc<loom::sync::Notify>, LoomAtomicBool> =
                    send_thread.join().unwrap();
            });
        }

        #[test]
        #[ignore]
        fn loom_shutdown() {
            loom::model(|| {
                let notify = Arc::new(loom::sync::Notify::new());
                let (mut sender, mut receiver) =
                    channel::<u64, LoomMpsc, Arc<loom::sync::Notify>, LoomAtomicBool>(
                        notify.clone(),
                    );
                // I think this tests everything we want (mutation eg in the order of operations in
                // the ParkingChannel Sender Drop impl causes this to fail)
                let num_items = 1;
                loom::thread::spawn(move || {
                    for i in 0..num_items {
                        sender.send(i).unwrap();
                    }
                });
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
                    // now, unlike the simple test, the sender could be dropped. Let's make sure
                    // that eventually happens, and wakes us up!
                    while receiver.try_recv().unwrap_err() != mpsc::TryRecvError::Disconnected {
                        notify.wait();
                    }
                });
            });
        }
    }
}
