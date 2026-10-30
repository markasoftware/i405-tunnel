use std::{
    cell::{Cell, RefCell},
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};

use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    core,
    deviation_stats::DeviationStatsThread,
    hardware::Hardware,
    monitor_packets::MonitorPacketsThread,
    parking_channel::{self, Unparker},
    utils::{ChannelThread, RelativeDirection, instant_to_timestamp, timestamp_to_instant},
};

use super::{
    ReadIncomingPacket, ReadOutgoingPacket, ShutdownRequested,
    real::{QdiscSettings, configure_qdisc, epoch_timestamp},
};

const SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(100);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_millis(1);
const OVERSLEEP_WARNING: Duration = Duration::from_micros(250);
const OUTGOING_READS_CHANNEL_QLEN: usize = 2;

pub(crate) struct RealHardware<T: HardwareTime> {
    epoch: Instant,
    // we increment this when event listeners are cleared, and include it in all requests to other
    // for interval tracking
    next_outgoing_packet_id: Cell<u64>,
    // we'll "connect" to this address to disconnect:
    _disconnect_addr: SocketAddr,

    timer: Cell<Option<u64>>,
    socket: Arc<UdpSocket>,
    tun: Arc<tun_rs::SyncDevice>,
    tun_interrupt_event: Arc<tun_rs::InterruptEvent>,

    _outgoing_read_thread: ChannelThread<()>,
    // don't need to send anything here, we are always listening to incoming reads. It's still
    // useful to have a ChannelThread so that we can use channel closure as an effective stop token.
    // There are simpler ways to do a stop token (eg, weak Arc) but we already have the
    // ChannelThread, may's well use it.
    _incoming_read_thread: ChannelThread<()>,
    deviation_stats_thread: Option<DeviationStatsThread>,
    monitor_packets_thread: Option<MonitorPacketsThread>,

    incoming_reads_rx: RefCell<parking_channel::Receiver<ReadIncomingPacket>>,
    outgoing_reads_rx:
        RefCell<parking_channel::SyncReceiver<ReadOutgoingPacket, OUTGOING_READS_CHANNEL_QLEN>>,

    parker: T::Parker,

    shutdown_requested: ShutdownRequested,
}

impl<T: HardwareTime> RealHardware<T> {
    pub(crate) fn new(
        listen_addr: SocketAddr,
        tun: tun_rs::SyncDevice,
        deviation_stats: Option<Duration>,
        monitor_packets_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let (parker, unparker) = T::parker_pair();
        let (outgoing_reads_channel_tx, outgoing_reads_channel_rx) = mpsc::channel();
        let (incoming_reads_channel_tx, incoming_reads_channel_rx) = mpsc::channel();
        let (outgoing_reads_tx, outgoing_reads_rx) =
            parking_channel::sync_channel(unparker.clone());
        let (incoming_reads_tx, incoming_reads_rx) = parking_channel::channel(unparker.clone());

        let socket = Arc::new(UdpSocket::bind(listen_addr)?);
        // we set a read timeout so that the read thread can't block indefinitely, which would
        // prevent the thread from being able to terminate cooperatively because it's just stuck in
        // a syscall.
        socket
            .set_read_timeout(Some(SOCKET_READ_TIMEOUT))
            .map_err(|err| anyhow!(err).context("Failed to set UDP socket read timeout"))?;
        // I'm not sure what causes udp sockets to fail to be able to write immediately, but let's
        // make sure it doesn't hang on that either.
        socket
            .set_write_timeout(Some(SOCKET_WRITE_TIMEOUT))
            .map_err(|err| anyhow!(err).context("Failed to set UDP socket write timeout"))?;
        let incoming_read_socket = socket.clone();

        let tun = Arc::new(tun);
        let tun_interrupt_event = Arc::new(tun_rs::InterruptEvent::new()?);

        let epoch = Instant::now();

        let shutdown_requested = ShutdownRequested::new();
        ctrlc::set_handler({
            let shutdown_requested = shutdown_requested.clone();
            let unparker = unparker.clone();
            move || {
                log::info!("Shutting down I405 due to received signal");
                shutdown_requested.user_request_shutdown();
                unparker.unpark();
            }
        })
        .expect("Error installing signal handlers");

        Ok(Self {
            epoch,
            next_outgoing_packet_id: Cell::new(0),
            _disconnect_addr: crate::hardware::real::disconnect_addr(listen_addr),

            timer: Cell::new(None),
            socket,
            tun: tun.clone(),
            tun_interrupt_event: tun_interrupt_event.clone(),

            shutdown_requested,

            incoming_reads_rx: RefCell::new(incoming_reads_rx),
            outgoing_reads_rx: RefCell::new(outgoing_reads_rx),
            parker,

            _outgoing_read_thread: ChannelThread::spawn(outgoing_reads_channel_tx, move || {
                outgoing_read_thread(
                    outgoing_reads_channel_rx,
                    outgoing_reads_tx,
                    tun,
                    tun_interrupt_event,
                    epoch,
                )
            }),
            _incoming_read_thread: ChannelThread::spawn(incoming_reads_channel_tx, move || {
                incoming_read_thread(
                    incoming_reads_channel_rx,
                    incoming_reads_tx,
                    incoming_read_socket,
                )
            }),
            deviation_stats_thread: deviation_stats.map(DeviationStatsThread::spawn),
            monitor_packets_thread: monitor_packets_dir
                .map(MonitorPacketsThread::spawn)
                .transpose()?,
        })
    }

    /// Run our poor excuse for an event loop until interrupted by SIGINT
    // TODO this doesn't really need to be generic, could just use ConcreteCore
    pub(crate) fn run(&self, mut core: impl core::Core) {
        while !self.shutdown_requested.has_core_requested_shutdown() {
            // we don't do precise sleep for timers, because everything time-sensitive that the Core
            // does is done via timestamps on other core methods. It's never important that the core
            // itself do something at a precise timestamp.

            // only set if the user requested a timer, /and/ that timer is short enough that we're
            // actually able to use it.
            match self.timer.get() {
                Some(timer_nanos) => {
                    let timeout_instant = timestamp_to_instant(self.epoch, timer_nanos);
                    let overshoot_duration =
                        Instant::now().saturating_duration_since(timeout_instant);
                    // why won't this happen every time? first of all, idk, and second of all,
                    // usually park_deadline() will wake up a bit after the deadline hopefully,
                    // which means the on_event will see that the timer passed, and clear it, before
                    // we loop around again here.
                    if !overshoot_duration.is_zero() {
                        log::warn!(
                            "Timer set in the past, by {}",
                            humantime::format_duration(overshoot_duration)
                        );
                        // don't park if timer passed
                    } else {
                        self.parker.park_deadline(timeout_instant);
                    }
                }
                // TODO before on_event merge: how did user-iniated shutdown work before? i didn't
                // see it pushing to the event queue from the ctrlc handler.
                None => self.parker.park(),
            };
            core.on_event(self);
        }
    }
}

impl<T: HardwareTime> Drop for RealHardware<T> {
    fn drop(&mut self) {
        // shuts down the in-progress tun.recv. I believe it's `poll`-ing on a pipe. `trigger()`
        // doesn't just trigger inflight `recv_intr` calls -- all future `recv_inter` will
        // immediately interrupt until the event is `reset`, so there's no race here: Even if the
        // outgoing read thread loops around and passes the next channel_rx.try_recv after the first
        // time the tun event is interrupted, it will get interrupted immediately again, etc, until
        // it observes channel_rx.try_recv = Disconnected.
        self.tun_interrupt_event
            .trigger()
            .expect("Failed to trigger tun_rs InterruptEvent during sleepy shutdown");
    }
}

fn outgoing_read_thread<U: Unparker>(
    rx: mpsc::Receiver<()>,
    mut tx: parking_channel::SyncSender<ReadOutgoingPacket, U, OUTGOING_READS_CHANNEL_QLEN>,
    tun: Arc<tun_rs::SyncDevice>,
    tun_interrupt_event: Arc<tun_rs::InterruptEvent>,
    epoch: Instant,
) {
    loop {
        match rx.try_recv() {
            Ok(()) => panic!("Should never receive actual data in outgoing_read_thread"),
            Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {
                let mut buf = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
                // tun_interrupt_event is triggered on shutdown, which will cause next loop and then Disconnected.
                match tun.recv_intr(&mut buf, &tun_interrupt_event) {
                    Ok(len) => {
                        buf.shrink(len);
                        // synchronous send without timeout is OK here: will disconnect on shutdown.
                        if tx
                            .send(ReadOutgoingPacket {
                                packet: buf,
                                recv_timestamp: instant_to_timestamp(epoch, Instant::now()),
                            })
                            .is_err()
                        {
                            // disconnected is only err here
                            return;
                        }
                    }
                    Err(err) => {
                        // if we are shutting down, ignore ConnectionAborted -- that's normal
                        if err.kind() != std::io::ErrorKind::Interrupted {
                            log::error!("Outgoing read error (from tun): {err:?}");
                        }
                    }
                }
            }
        }
    }
    log::trace!("outgoing read thread quitting");
}

fn incoming_read_thread<U: Unparker>(
    rx: mpsc::Receiver<()>,
    mut tx: parking_channel::Sender<ReadIncomingPacket, U>,
    socket: Arc<UdpSocket>,
) {
    let mut last_block = Instant::now() - SOCKET_READ_TIMEOUT;
    // keep reading packets until the channel disconnects
    loop {
        match rx.try_recv() {
            Ok(()) => panic!("Should never receive actual data in incoming_read_thread"),
            Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {
                let mut buf = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
                match socket.recv_from(&mut buf) {
                    Ok((len_recvd, addr)) => {
                        buf.shrink(len_recvd);
                        tx.send(ReadIncomingPacket {
                            peer: addr,
                            packet: buf,
                        })
                        .unwrap();
                    }
                    // TODO somehow signal the error more seriously?
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            // this is fairly normal, just make we aren't somehow in fully non-blocking mode.
                            let now = Instant::now();
                            if now.saturating_duration_since(last_block) < SOCKET_READ_TIMEOUT / 8 {
                                log::error!("WouldBlock too frequently!");
                            }
                            last_block = now;
                        } else {
                            log::error!("Incoming read error (from udp socket): {err:?}");
                        }
                    }
                }
            }
        }
    }
    log::trace!("incoming read thread quitting");
}

impl<T: HardwareTime> Hardware for RealHardware<T> {
    fn timestamp(&self) -> u64 {
        instant_to_timestamp(self.epoch, Instant::now())
    }

    fn epoch_timestamp(&self) -> u64 {
        epoch_timestamp()
    }

    fn set_timer(&self, timestamp: u64) -> Option<u64> {
        self.timer.replace(Some(timestamp))
    }

    fn socket_connect(&self, _socket_addr: &std::net::SocketAddr) -> Result<()> {
        // TODO disconnection doesn't work right now so we don't connect at all:
        // self.socket.connect(socket_addr)?;
        Ok(())
    }

    fn read_outgoing_packet(&self) -> Option<ReadOutgoingPacket> {
        // borrow_mut safe: Result is not a reference nor does it hold any reference so cannot
        // possibly hold the refcell open.
        match self.outgoing_reads_rx.borrow_mut().try_recv() {
            Ok(pkt) => Some(pkt),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("Outgoing read thread disconnected while main thread still running")
            }
        }
    }

    // TODO consider remove Result from signature since it always succeeds (or, at least, we don't
    // want to fatally fail on a send error)
    fn send_outgoing_packet(
        &self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()> {
        if let Some(timestamp) = timestamp {
            T::sleep_until(timestamp_to_instant(self.epoch, timestamp));
        }
        let actual_socket_send_instant = Instant::now();
        match self.socket.send_to(packet, destination) {
            Ok(len) => {
                if len != packet.len() {
                    log::error!(
                        "Length mismatch sending outgoing packet over udp socket: Actually sent {}, tried to send {} bytes",
                        len,
                        packet.len(),
                    );
                }
            }
            Err(err) => log::error!("Outgoing send error (to udp socket): {err:?}"),
        }
        if let Some(deviation_stats_thread) = &self.deviation_stats_thread {
            deviation_stats_thread.register_packet(
                self.next_outgoing_packet_id.get(),
                instant_to_timestamp(self.epoch, actual_socket_send_instant),
            );
        }
        self.next_outgoing_packet_id
            .replace(self.next_outgoing_packet_id.get() + 1);
        Ok(())
    }

    // TODO like above, consider changing the signature, since this always succeeds.
    fn send_incoming_packet(&self, packet: &[u8]) -> Result<()> {
        match self.tun.send(packet) {
            Ok(len) => {
                if len != packet.len() {
                    log::error!(
                        "Length mismatch sending incoming packet over tun: Actually sent {}, tried to send {} bytes",
                        len,
                        packet.len()
                    );
                }
            }
            Err(err) => log::error!("Incoming send error (over tun): {err:?}"),
        };
        Ok(())
    }

    // TODO before merge on_event: do we need this anymore? or should it just be clear_timer?
    fn clear_event_listeners(&self) -> Result<()> {
        self.timer.replace(None);
        // self.socket.connect(self.disconnect_addr)?;
        Ok(())
    }

    fn mtu(&self, peer: SocketAddr) -> Result<u16> {
        Ok(u16::try_from(mtu::interface_and_mtu(peer.ip())?.1).unwrap_or(u16::MAX))
    }

    fn register_interval(&self, duration: u64) {
        assert!(
            self.next_outgoing_packet_id.get() > 0,
            "Must send an outgoing packet before calling register_interval"
        );
        if let Some(deviation_stats_thread) = &self.deviation_stats_thread {
            let next_outgoing_packet_id = self.next_outgoing_packet_id.get();
            deviation_stats_thread.register_interval(
                next_outgoing_packet_id - 1,
                next_outgoing_packet_id,
                duration,
            );
        }
    }

    fn register_packet_status(
        &self,
        direction: RelativeDirection,
        seqno: u64,
        tx_rx_epoch_times: Option<(u64, u64)>,
    ) {
        self.monitor_packets_thread
            .as_ref()
            .expect("Tried to register packet status on hardware that isn't set up to record them")
            .register_packet_status(direction, seqno, tx_rx_epoch_times);
    }

    fn configure_qdisc(&self, settings: &QdiscSettings) -> Result<()> {
        configure_qdisc(&self.tun.name()?, &self.tun, settings)
    }

    fn has_user_requested_shutdown(&self) -> bool {
        self.shutdown_requested.has_user_requested_shutdown()
    }

    fn shutdown(&self) {
        self.shutdown_requested.core_request_shutdown();
    }

    fn read_incoming_packet(&self) -> Option<ReadIncomingPacket> {
        // borrow_mut safe: Result is not a reference nor does it hold any reference so cannot
        // possibly hold the refcell open.
        match self.incoming_reads_rx.borrow_mut().try_recv() {
            Ok(pkt) => Some(pkt),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("Incoming read thread disconnected while main thread still running")
            }
        }
    }
}

// functions that are supposed to have a connection with time, which makes the difference between
// sleepy mode and spinny mode.
trait HardwareTime {
    type Parker: Parker + 'static;
    type Unparker: Unparker + Clone + Send + 'static;

    fn parker_pair() -> (Self::Parker, Self::Unparker);
    fn sleep_until(wake_at: Instant);
}

trait Parker {
    fn park(&self);
    fn park_deadline(&self, deadline: Instant);
}

impl Parker for parking::Parker {
    fn park(&self) {
        self.park();
    }

    fn park_deadline(&self, deadline: Instant) {
        self.park_deadline(deadline);
    }
}

pub(crate) struct SleepyHardwareTime;

impl HardwareTime for SleepyHardwareTime {
    type Parker = parking::Parker;
    type Unparker = parking::Unparker;

    fn parker_pair() -> (Self::Parker, Self::Unparker) {
        parking::pair()
    }

    fn sleep_until(wake_at: Instant) {
        let now = Instant::now();
        if now < wake_at {
            std::thread::sleep(wake_at.saturating_duration_since(now));
            let oversleep_duration = Instant::now().saturating_duration_since(wake_at);
            if oversleep_duration > OVERSLEEP_WARNING {
                log::warn!(
                    "sleep_until sleepy overslept by {}",
                    humantime::format_duration(oversleep_duration)
                );
            }
        } else {
            log::warn!(
                "sleep_until sleepy called too late (by {})",
                humantime::format_duration(now - wake_at)
            );
        }
    }
}

pub(crate) struct SpinnyHardwareTime;

impl HardwareTime for SpinnyHardwareTime {
    type Parker = SpinnyParker;
    type Unparker = SpinnyParker;

    fn parker_pair() -> (Self::Parker, Self::Unparker) {
        let woken = Arc::new(AtomicBool::new(false));
        (
            SpinnyParker {
                woken: woken.clone(),
            },
            SpinnyParker { woken },
        )
    }

    fn sleep_until(wake_at: Instant) {
        let start_delay = Instant::now().saturating_duration_since(wake_at);
        if !start_delay.is_zero() {
            log::warn!(
                "sleep_until called too late (spinny), by {}",
                humantime::format_duration(start_delay)
            )
        }
        while Instant::now() < wake_at {
            // TODO investigate whether the hint causes VMs to deschedule more often due to PLE (pause-).
            std::hint::spin_loop();
        }
        let oversleep_duration = Instant::now().saturating_duration_since(wake_at);
        if oversleep_duration > OVERSLEEP_WARNING {
            log::warn!(
                "Overslept during spinny sleep_until, by {}",
                humantime::format_duration(oversleep_duration)
            );
        }
    }
}

#[derive(Debug, Clone)]
struct SpinnyParker {
    woken: Arc<AtomicBool>,
}

impl SpinnyParker {
    fn compare_exchange_woken(&self) -> bool {
        self.woken
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

impl Parker for SpinnyParker {
    fn park(&self) {
        while !self.compare_exchange_woken() {
            std::hint::spin_loop();
        }
    }

    fn park_deadline(&self, deadline: Instant) {
        while !self.compare_exchange_woken() && Instant::now() < deadline {
            std::hint::spin_loop();
        }
    }
}

impl Unparker for SpinnyParker {
    fn unpark(&self) {
        self.woken.store(true, Ordering::SeqCst);
    }
}
