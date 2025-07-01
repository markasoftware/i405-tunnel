use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, atomic::AtomicBool, mpsc},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};

use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    core,
    deviation_stats::DeviationStatsThread,
    hardware::Hardware,
    utils::{ChannelThread, instant_to_timestamp, timestamp_to_instant},
};

const SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(100);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_millis(1);
const OVERSLEEP_WARNING: Duration = Duration::from_micros(250);

pub(crate) struct SleepyHardware {
    epoch: Instant,
    // we increment this when event listeners are cleared, and include it in all requests to other
    // for interval tracking
    next_outgoing_packet_id: u64,
    // we'll "connect" to this address to disconnect:
    disconnect_addr: SocketAddr,

    timer: Option<u64>,
    socket: Arc<UdpSocket>,
    tun: Arc<tun_rs::SyncDevice>,
    tun_is_shutdown: Arc<AtomicBool>,

    outgoing_read_thread: ChannelThread<()>,
    // don't need to send anything here, we are always listening to incoming reads. It's still
    // useful to have a ChannelThread so that we can use channel closure as an effective stop token.
    incoming_read_thread: ChannelThread<()>,
    deviation_stats_thread: Option<DeviationStatsThread>,

    // events_rx should be listed after the threads, because if it's dropped before the threads are
    // dropped, then the threads may try to send to their events_txs after the receiver has been
    // dropped, and get errors.
    events_rx: mpsc::Receiver<Event>,
}

impl SleepyHardware {
    pub(crate) fn new(
        listen_addr: SocketAddr,
        tun: tun_rs::SyncDevice,
        deviation_stats: Option<Duration>,
    ) -> Result<Self> {
        let (outgoing_read_requests_tx, outgoing_read_requests_rx) = mpsc::channel();
        let (incoming_reads_tx, incoming_reads_rx) = mpsc::channel();

        let (events_tx, events_rx) = mpsc::channel();
        let tx_for_outgoing_read_thread = events_tx.clone();
        let tx_for_incoming_read_thread = events_tx.clone();
        let tx_for_signal_handler = events_tx;

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
        let tun_for_outgoing_read_thread = tun.clone();
        let tun_is_shutdown = Arc::new(AtomicBool::new(false));
        let tun_is_shutdown_for_outgoing_read_thread = tun_is_shutdown.clone();

        let epoch = Instant::now();

        ctrlc::set_handler(move || {
            log::info!("Shutting down I405 due to received signal");
            tx_for_signal_handler.send(Event::Terminate).unwrap();
        })
        .expect("Error installing signal handlers");

        Ok(Self {
            epoch,
            next_outgoing_packet_id: 0,
            disconnect_addr: crate::hardware::real::disconnect_addr(listen_addr),

            timer: None,
            socket,
            tun,
            tun_is_shutdown,

            events_rx,

            outgoing_read_thread: ChannelThread::spawn(outgoing_read_requests_tx, move || {
                outgoing_read_thread(
                    outgoing_read_requests_rx,
                    tx_for_outgoing_read_thread,
                    tun_for_outgoing_read_thread,
                    tun_is_shutdown_for_outgoing_read_thread,
                    epoch,
                )
            }),
            incoming_read_thread: ChannelThread::spawn(incoming_reads_tx, move || {
                incoming_read_thread(
                    incoming_reads_rx,
                    tx_for_incoming_read_thread,
                    incoming_read_socket,
                )
            }),
            deviation_stats_thread: deviation_stats
                .map(|duration| DeviationStatsThread::spawn(duration)),
        })
    }

    /// Run our poor excuse for an event loop until interrupted by SIGINT
    // TODO this doesn't really need to be generic, could just use ConcreteCore
    pub(crate) fn run(&mut self, mut core: impl core::Core) {
        loop {
            // we don't do precise sleep for timers, because everything time-sensitive that the Core
            // does is done via timestamps on other core methods. It's never important that the core
            // itself do something at a precise timestamp.

            // only set if the user requested a timer, /and/ that timer is short enough that we're
            // actually able to use it.
            let event_or_timeout = match self.timer {
                Some(timer_nanos) => {
                    let timeout_instant = timestamp_to_instant(self.epoch, timer_nanos);
                    let overshoot_duration =
                        Instant::now().saturating_duration_since(timeout_instant);
                    if !overshoot_duration.is_zero() {
                        log::warn!(
                            "Timer set in the past, by {}",
                            humantime::format_duration(overshoot_duration)
                        );
                    }
                    let timeout_duration_from_now =
                        timeout_instant.saturating_duration_since(Instant::now());
                    // TODO don't keep trying to recv events if we are late for the next timer, give
                    // precedence to the timer. Probably want to do so even if we aren't quite at the timer time yet.
                    self.events_rx.recv_timeout(timeout_duration_from_now)
                }
                None => self
                    .events_rx
                    .recv()
                    .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            };
            match event_or_timeout {
                Ok(Event::OutgoingRead { timestamp, packet }) => {
                    // TODO the packet comes to us as &[u8], then we wrap it in an
                    // IpPacketBuffer, then we deref it here, then it'll almost certainly be
                    // made back into an IpPacketBuffer again later. Does explicitly converting
                    // it back and forth between a slice and an IpPacketBuffer cause even more
                    // copying than necessary? Probably depends on inlining and stuff but I'm
                    // not sure!
                    core.on_read_outgoing_packet(self, &packet, timestamp);
                }
                Ok(Event::IncomingRead { addr, packet }) => {
                    core.on_read_incoming_packet(self, &packet, addr);
                }
                Ok(Event::Terminate) => return core.on_terminate(self),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let activated_timer = std::mem::take(&mut self.timer);
                    core.on_timer(self, activated_timer.unwrap());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("events_rx shouldn't disconnect as long as the hardware lives.")
                }
            }
        }
    }
}

// HACK: The outgoing read thread does a blocking `recv` on the tun, and there's no way to add a
// timeout. We could get the fd out of the tun, and then poll it using the `nix` package. However,
// we avoid an extra dependency by just shutting down the TUN, which at least on my system does
// cause the recv to be interrupted.
impl Drop for SleepyHardware {
    fn drop(&mut self) {
        self.tun_is_shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.tun.shutdown().expect("Error closing TUN");
    }
}

enum Event {
    OutgoingRead {
        timestamp: u64,
        packet: IpPacketBuffer,
    },
    IncomingRead {
        addr: SocketAddr,
        packet: IpPacketBuffer,
    },
    Terminate,
}

fn outgoing_read_thread(
    read_request_rx: mpsc::Receiver<()>,
    tx: mpsc::Sender<Event>,
    tun: Arc<tun_rs::SyncDevice>,
    tun_is_shutdown: Arc<AtomicBool>,
    epoch: Instant,
) {
    while let Ok(read_request) = read_request_rx.recv() {
        let mut buf = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
        match tun.recv(&mut buf) {
            Ok(len) => {
                buf.shrink(len);
                if tx
                    .send(Event::OutgoingRead {
                        packet: buf,
                        timestamp: instant_to_timestamp(epoch, Instant::now()),
                    })
                    .is_err()
                {
                    // the thread got disconnected
                    return;
                }
            }
            Err(err) => {
                // if we are shutting down, ignore ConnectionAborted error -- that's normal.
                if !(err.kind() == std::io::ErrorKind::ConnectionAborted
                    && tun_is_shutdown.load(std::sync::atomic::Ordering::SeqCst))
                {
                    log::error!("Outgoing read error (from tun): {err:?}");
                }
            }
        }
    }
    log::trace!("outgoing read thread quitting");
}

fn incoming_read_thread(rx: mpsc::Receiver<()>, tx: mpsc::Sender<Event>, socket: Arc<UdpSocket>) {
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
                        tx.send(Event::IncomingRead { addr, packet: buf }).unwrap();
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

fn precise_sleep(wake_at: Instant) {
    let now = Instant::now();
    if now < wake_at {
        std::thread::sleep(wake_at.saturating_duration_since(now));
        let oversleep_duration = Instant::now().saturating_duration_since(wake_at);
        if oversleep_duration > OVERSLEEP_WARNING {
            log::warn!(
                "precise_sleep overslept by {}",
                humantime::format_duration(oversleep_duration)
            );
        }
    } else {
        log::warn!(
            "precise_sleep called too late (by {})",
            humantime::format_duration(now - wake_at)
        );
    }
}

impl Hardware for SleepyHardware {
    fn timestamp(&self) -> u64 {
        instant_to_timestamp(self.epoch, Instant::now())
    }

    fn set_timer(&mut self, timestamp: u64) -> Option<u64> {
        std::mem::replace(&mut self.timer, Some(timestamp))
    }

    fn socket_connect(&mut self, _socket_addr: &std::net::SocketAddr) -> Result<()> {
        // TODO disconnection doesn't work right now so we don't connect at all:
        // self.socket.connect(socket_addr)?;
        Ok(())
    }

    fn read_outgoing_packet(&mut self) {
        self.outgoing_read_thread.tx().send(()).unwrap();
    }

    // TODO consider remove Result from signature since it always succeeds (or, at least, we don't
    // want to fatally fail on a send error)
    fn send_outgoing_packet(
        &mut self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()> {
        if let Some(timestamp) = timestamp {
            precise_sleep(timestamp_to_instant(self.epoch, timestamp));
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
                self.next_outgoing_packet_id,
                instant_to_timestamp(self.epoch, actual_socket_send_instant),
            );
        }
        self.next_outgoing_packet_id += 1;
        Ok(())
    }

    // TODO like above, consider changing the signature, since this always succeeds.
    fn send_incoming_packet(&mut self, packet: &[u8]) -> Result<()> {
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

    fn clear_event_listeners(&mut self) -> Result<()> {
        self.timer = None;
        // self.socket.connect(self.disconnect_addr)?;
        Ok(())
    }

    fn mtu(&self, peer: SocketAddr) -> Result<u16> {
        Ok(u16::try_from(mtu::interface_and_mtu(peer.ip())?.1).unwrap_or(u16::MAX))
    }

    fn register_interval(&mut self, duration: u64) {
        assert!(
            self.next_outgoing_packet_id > 0,
            "Must send an outgoing packet before calling register_interval"
        );
        if let Some(deviation_stats_thread) = &self.deviation_stats_thread {
            deviation_stats_thread.register_interval(
                self.next_outgoing_packet_id - 1,
                self.next_outgoing_packet_id,
                duration,
            );
        }
    }
}
