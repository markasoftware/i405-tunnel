use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use crate::{
    array_array::IpPacketBuffer, constants::MAX_IP_PACKET_LENGTH, core, hardware::Hardware,
};

pub(crate) struct RealHardware {
    epoch: Instant,
    // we increment this when event listeners are cleared, and include it in all requests to other
    // threads, so that we can identify when an event is from a "previous" generation
    generation: u64,
    // we'll "connect" to this address to disconnect:
    disconnect_addr: SocketAddr,

    timer: Option<u64>,
    socket: Arc<UdpSocket>,

    events_rx: mpsc::Receiver<Event>,

    outgoing_read_thread: ChannelThread<OutgoingReadRequest>,
    outgoing_send_thread: ChannelThread<OutgoingSend>,
    // don't need to send anything here, we are always listening to incoming reads. It's still
    // useful to have a ChannelThread so that we can use channel closure as an effective stop token.
    incoming_read_thread: ChannelThread<()>,
    incoming_send_thread: ChannelThread<IncomingSend>,
}

impl RealHardware {
    pub(crate) fn new(
        listen_addr: SocketAddr,
        tun_name: String,
        tun_mtu: Option<u16>,
        tun_ipv4_net: Option<ipnet::Ipv4Net>,
        tun_ipv6_net: Option<ipnet::Ipv6Net>,
    ) -> std::io::Result<Self> {
        let disconnect_addr = match listen_addr {
            SocketAddr::V4(_) => {
                SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::from_bits(0), 0))
            }
            SocketAddr::V6(_) => {
                SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::from_bits(0), 0, 0, 0))
            }
        };

        let (outgoing_read_requests_tx, outgoing_read_requests_rx) = mpsc::channel();
        let (outgoing_sends_tx, outgoing_sends_rx) = mpsc::channel();
        let (incoming_reads_tx, incoming_reads_rx) = mpsc::channel();
        let (incoming_sends_tx, incoming_sends_rx) = mpsc::channel();

        let (events_tx, events_rx) = mpsc::channel();
        let tx_for_outgoing_read_thread = events_tx.clone();
        let tx_for_incoming_read_thread = events_tx;

        let socket = Arc::new(UdpSocket::bind(listen_addr)?);
        let outgoing_send_socket = socket.clone();
        let incoming_read_socket = socket.clone();

        let mut tun_builder = tun_rs::DeviceBuilder::new().name(tun_name);
        if let Some(mtu) = tun_mtu {
            tun_builder = tun_builder.mtu(mtu);
        }
        if let Some(ipv4_net) = tun_ipv4_net {
            tun_builder = tun_builder.ipv4(ipv4_net.addr(), ipv4_net.netmask(), None);
        }
        if let Some(ipv6_net) = tun_ipv6_net {
            tun_builder = tun_builder.ipv6(ipv6_net.addr(), ipv6_net.netmask());
        }
        let tun = Arc::new(tun_builder.build_sync()?);
        let outgoing_read_tun = tun.clone();
        let incoming_send_tun = tun;

        let epoch = Instant::now();

        Ok(Self {
            epoch,
            generation: 0,
            disconnect_addr,

            timer: None,
            socket,

            events_rx,

            outgoing_read_thread: ChannelThread::spawn(outgoing_read_requests_tx, move || {
                outgoing_read_thread(
                    outgoing_read_requests_rx,
                    tx_for_outgoing_read_thread,
                    outgoing_read_tun,
                    epoch,
                )
            }),
            outgoing_send_thread: ChannelThread::spawn(outgoing_sends_tx, move || {
                outgoing_send_thread(outgoing_sends_rx, outgoing_send_socket, epoch)
            }),
            incoming_read_thread: ChannelThread::spawn(incoming_reads_tx, move || {
                incoming_read_thread(
                    incoming_reads_rx,
                    tx_for_incoming_read_thread,
                    incoming_read_socket,
                )
            }),
            incoming_send_thread: ChannelThread::spawn(incoming_sends_tx, move || {
                incoming_send_thread(incoming_sends_rx, incoming_send_tun, epoch)
            }),
        })
    }

    /// Run our poor excuse for an event loop until interrupted by SIGINT
    // TODO this doesn't really need to be generic, could just use ConcreteCore
    pub(crate) fn run(&mut self, core: &mut impl core::Core) {
        loop {
            // we don't do precise sleep for timers, because everything time-sensitive that the Core
            // does is done via timestamps on other core methods. It's never important that the core
            // itself do something at a precise timestamp.

            // Always use `recv_timeout` so that we can handle SIGINT in a timely fashion.
            let max_timeout_duration_from_now = Duration::from_secs(1);
            // only set if the user requested a timer, /and/ that timer is short enough that we're
            // actually able to use it.
            let user_timeout_duration_from_now = self.timer.and_then(|timer| {
                let dur = self
                    .epoch
                    .checked_add(Duration::from_nanos(timer))
                    .unwrap()
                    .saturating_duration_since(Instant::now());
                (dur <= max_timeout_duration_from_now).then_some(dur)
            });
            let timeout_duration_from_now =
                user_timeout_duration_from_now.unwrap_or(max_timeout_duration_from_now);
            if timeout_duration_from_now == Duration::ZERO {
                log::warn!(
                    "Timer set in the past? Timer set for {}, current ns since epoch is {}",
                    self.timer.unwrap(),
                    Instant::now()
                        .checked_duration_since(self.epoch)
                        .unwrap()
                        .as_nanos()
                );
            }
            match self.events_rx.recv_timeout(timeout_duration_from_now) {
                Ok(Event::OutgoingRead {
                    timestamp,
                    packet,
                    generation,
                }) => {
                    if generation == self.generation {
                        // TODO the packet comes to us as &[u8], then we wrap it in an
                        // IpPacketBuffer, then we deref it here, then it'll almost certainly be
                        // made back into an IpPacketBuffer again later. Does explicitly converting
                        // it back and forth between a slice and an IpPacketBuffer cause even more
                        // copying than necessary? Probably depends on inlining and stuff but I'm
                        // not sure!
                        core.on_read_outgoing_packet(self, &packet, timestamp);
                    }
                }
                Ok(Event::IncomingRead { addr, packet }) => {
                    core.on_read_incoming_packet(self, &packet, addr);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if user_timeout_duration_from_now.is_some() {
                        let activated_timer = std::mem::take(&mut self.timer);
                        core.on_timer(self, activated_timer.unwrap());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("events_rx shouldn't disconnect as long as the RealHardware lives.")
                }
            }
        }
    }
}

/// Automatically joins thread on drop.
struct JThread {
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl JThread {
    fn spawn<F: FnOnce() -> () + Send + 'static>(f: F) -> Self {
        Self {
            join_handle: Some(std::thread::spawn(f)),
        }
    }
}

impl Drop for JThread {
    fn drop(&mut self) {
        if let Err(panic_payload) = std::mem::take(&mut self.join_handle).unwrap().join() {
            std::panic::resume_unwind(panic_payload);
        }
    }
}

// A channel that we can send stuff to. This is designed for threads that have internal logic which
// shuts down the thread once the channel closes; this way, as the ChannelThread is dropped, the
// channel will close, then we attempt to join the thread, and then the thread will cooperatively
// close, giving us a fully RAII-based cooperative thread closing mechanism.
struct ChannelThread<TX> {
    tx: mpsc::Sender<TX>,
    jthread: JThread,
}

impl<TX> ChannelThread<TX> {
    fn spawn<F: FnOnce() -> () + Send + 'static>(tx: mpsc::Sender<TX>, f: F) -> Self {
        Self {
            tx,
            jthread: JThread::spawn(f),
        }
    }
}

struct OutgoingReadRequest {
    generation: u64,
    no_earlier_than: Option<u64>,
}

struct OutgoingSend {
    packet: IpPacketBuffer,
    addr: SocketAddr,
    timestamp: Option<u64>,
}

struct IncomingSend {
    packet: IpPacketBuffer,
    timestamp: Option<u64>,
}

enum Event {
    OutgoingRead {
        timestamp: u64,
        packet: IpPacketBuffer,
        generation: u64,
    },
    IncomingRead {
        addr: SocketAddr,
        packet: IpPacketBuffer,
    },
}

fn outgoing_read_thread(
    read_request_rx: mpsc::Receiver<OutgoingReadRequest>,
    tx: mpsc::Sender<Event>,
    tun: Arc<tun_rs::SyncDevice>,
    epoch: Instant,
) {
    while let Ok(read_request) = read_request_rx.recv() {
        let mut buf = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
        if let Some(no_earlier_than) = read_request.no_earlier_than {
            precise_sleep(epoch + Duration::from_nanos(no_earlier_than));
        }
        match tun.recv(&mut buf) {
            Ok(len) => {
                buf.shrink(len);
                if tx
                    .send(Event::OutgoingRead {
                        generation: read_request.generation,
                        packet: buf,
                        timestamp: (Instant::now() - epoch).as_nanos().try_into().unwrap(),
                    })
                    .is_err()
                {
                    // the thread got disconnected
                    return;
                }
            }
            Err(err) => log::error!("Outgoing read error (from tun): {err:?}"),
        }
    }
}

fn outgoing_send_thread(rx: mpsc::Receiver<OutgoingSend>, socket: Arc<UdpSocket>, epoch: Instant) {
    while let Ok(outgoing_send) = rx.recv() {
        if let Some(timestamp) = outgoing_send.timestamp {
            precise_sleep(epoch + Duration::from_nanos(timestamp));
        }
        match socket.send_to(&outgoing_send.packet, outgoing_send.addr) {
            Ok(len) => {
                if len != outgoing_send.packet.len() {
                    log::error!(
                        "Length mismatch sending outgoing packet over udp socket: Actually sent {}, tried to send {} bytes",
                        len,
                        outgoing_send.packet.len(),
                    );
                }
            }
            Err(err) => log::error!("Outgoing send error (to udp socket): {err:?}"),
        }
    }
}

fn incoming_read_thread(rx: mpsc::Receiver<()>, tx: mpsc::Sender<Event>, socket: Arc<UdpSocket>) {
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
                    Err(err) => log::error!("Incoming read error (from udp socket): {err:?}"),
                }
            }
        }
    }
}

fn incoming_send_thread(
    rx: mpsc::Receiver<IncomingSend>,
    tun: Arc<tun_rs::SyncDevice>,
    epoch: Instant,
) {
    while let Ok(incoming_send) = rx.recv() {
        if let Some(timestamp) = incoming_send.timestamp {
            precise_sleep(epoch + Duration::from_nanos(timestamp));
        }
        match tun.send(&incoming_send.packet) {
            Ok(len) => {
                if len != incoming_send.packet.len() {
                    log::error!(
                        "Length mismatch sending incoming packet over tun: Actually sent {}, tried to send {} bytes",
                        len,
                        incoming_send.packet.len()
                    );
                }
            }
            Err(err) => log::error!("Incoming send error (over tun): {err:?}"),
        }
    }
}

fn precise_sleep(wake_at: Instant) {
    // this used to wake up N nanoseconds before wake_at and then do a spinloop the rest of the way,
    // but real-world testing showed that packet intervals actually had substantially /higher/
    // standard deviations.
    let now = Instant::now();
    if now < wake_at {
        std::thread::sleep(wake_at.saturating_duration_since(now));
    } else {
        log::warn!(
            "precise_sleep called too late: Requested wake up at {wake_at:?}, but it's already {now:?}"
        );
    }
}

impl Hardware for RealHardware {
    fn timestamp(&self) -> u64 {
        Instant::now()
            .duration_since(self.epoch)
            .as_nanos()
            .try_into()
            .unwrap()
    }

    fn set_timer(&mut self, timestamp: u64) -> Option<u64> {
        std::mem::replace(&mut self.timer, Some(timestamp))
    }

    fn socket_connect(&mut self, socket_addr: &std::net::SocketAddr) -> super::Result<()> {
        self.socket.connect(socket_addr)?;
        Ok(())
    }

    fn socket_disconnect(&mut self) -> super::Result<()> {
        self.socket.connect(self.disconnect_addr)?;
        Ok(())
    }

    fn read_outgoing_packet(&mut self, no_earlier_than: Option<u64>) {
        self.outgoing_read_thread
            .tx
            .send(OutgoingReadRequest {
                generation: self.generation,
                no_earlier_than,
            })
            .unwrap();
    }

    fn send_outgoing_packet(
        &mut self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> super::Result<()> {
        // TODO consider changing signature to unconditionnal (), since errors are async anyway.
        self.outgoing_send_thread
            .tx
            .send(OutgoingSend {
                packet: IpPacketBuffer::new(packet),
                addr: destination,
                timestamp,
            })
            .unwrap();
        Ok(())
    }

    // TODO like above, consider changing the signature, since this always succeeds.
    fn send_incoming_packet(&mut self, packet: &[u8], timestamp: Option<u64>) -> super::Result<()> {
        self.incoming_send_thread
            .tx
            .send(IncomingSend {
                packet: IpPacketBuffer::new(packet),
                timestamp,
            })
            .unwrap();
        Ok(())
    }

    fn clear_event_listeners(&mut self) {
        self.timer = None;
        self.generation = self.generation.checked_add(1).unwrap();
    }
}
