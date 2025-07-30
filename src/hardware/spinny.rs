use std::{
    cell::Cell,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};

use super::{
    Hardware,
    real::{QdiscSettings, configure_qdisc},
};
use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    core,
    deviation_stats::DeviationStatsThread,
    monitor_packets::MonitorPacketsThread,
    utils::{AbsoluteDirection, instant_to_timestamp, timestamp_to_instant},
};

const OVERSLEEP_WARNING: Duration = Duration::from_micros(10);

pub(crate) struct SpinnyHardware {
    epoch: Instant,
    _disconnect_addr: SocketAddr,

    timer: Cell<Option<u64>>,
    // whether we are actively polling for an outgoing read
    read_outgoing: Cell<bool>,
    // set to true if we should shut down when able
    shutting_down: Arc<AtomicBool>,

    next_outgoing_packet_id: Cell<u64>,
    deviation_stats_thread: Option<DeviationStatsThread>,
    monitor_packets_thread: Option<MonitorPacketsThread>,

    socket: UdpSocket,
    tun: tun_rs::SyncDevice,
}

impl SpinnyHardware {
    pub(crate) fn new(
        listen_addr: SocketAddr,
        tun: tun_rs::SyncDevice,
        deviation_stats: Option<Duration>,
        monitor_packets_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr)?;
        socket
            .set_nonblocking(true)
            .map_err(|err| anyhow!(err).context("Failed to set UDP socket as nonblocking"))?;

        tun.set_nonblocking(true)
            .map_err(|err| anyhow!(err).context("Failed to set TUN as nonblocking"))?;

        let epoch = Instant::now();

        let shutting_down = Arc::new(AtomicBool::new(false));
        let shutting_down_for_ctrlc_thread = shutting_down.clone();

        ctrlc::set_handler(move || {
            log::info!("Shutting down I405 due to received signal");
            shutting_down_for_ctrlc_thread.store(true, std::sync::atomic::Ordering::Relaxed);
        })
        .map_err(|err| anyhow!(err).context("Failed to set ctrl-c handler"))?;

        Ok(Self {
            epoch,
            _disconnect_addr: crate::hardware::real::disconnect_addr(listen_addr),

            timer: Cell::new(None),
            read_outgoing: Cell::new(false),
            shutting_down,

            next_outgoing_packet_id: Cell::new(0),
            deviation_stats_thread: deviation_stats.map(DeviationStatsThread::spawn),
            // I love that `transpose()` exists
            monitor_packets_thread: monitor_packets_dir
                .map(MonitorPacketsThread::spawn)
                .transpose()?,

            socket,
            tun,
        })
    }

    pub(crate) fn run(&self, mut core: impl core::Core) {
        // 1. Check if we should shut down
        while !self
            .shutting_down
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // 1. Timer
            if let Some(timer) = self.timer.get() {
                if Instant::now() >= timestamp_to_instant(self.epoch, timer) {
                    core.on_timer(self, timer);
                }
            }

            // 2. Read Outgoing
            if self.read_outgoing.get() {
                // ideally we'd put this recv outside the loop, but given how small it is I
                // don't think it matters.
                let mut tun_recv_buf = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
                match self.tun.recv(&mut tun_recv_buf) {
                    Ok(len) => {
                        self.read_outgoing.replace(false);
                        tun_recv_buf.shrink(len);
                        core.on_read_outgoing_packet(
                            self,
                            &tun_recv_buf,
                            instant_to_timestamp(self.epoch, Instant::now()),
                        );
                    }
                    Err(err) => {
                        if err.kind() != std::io::ErrorKind::WouldBlock {
                            log::error!("Outgoing read error (from TUN): {err:?}");
                        }
                    }
                }
            }

            // 3. Read Incoming
            let mut socket_recv_buf = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
            match self.socket.recv_from(&mut socket_recv_buf) {
                Ok((len, peer)) => {
                    socket_recv_buf.shrink(len);
                    core.on_read_incoming_packet(self, &socket_recv_buf, peer);
                }
                Err(err) => {
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        log::error!("Incoming read error (from socket): {err:?}");
                    }
                }
            }

            // send in both directions are initaited by the core, not here.
            // I suspect an std::hint::spin_loop() would be kinda useless here because the syscalls
            // above already make this into not quite a busy loop.
        }

        // we got shutting down signal, finish up here.
        core.on_terminate(self);
    }
}

impl Hardware for SpinnyHardware {
    // first few are the same as in SleepyHardware
    fn timestamp(&self) -> u64 {
        Instant::now()
            .duration_since(self.epoch)
            .as_nanos()
            .try_into()
            .unwrap()
    }

    fn set_timer(&self, timestamp: u64) -> Option<u64> {
        self.timer.replace(Some(timestamp))
    }

    fn socket_connect(&self, _socket_addr: &std::net::SocketAddr) -> Result<()> {
        // Socket disconnection doesn't work right now so we don't connect at all:
        // self.socket.connect(socket_addr)?;
        Ok(())
    }

    // remaining are different than in SleepyHardware
    fn read_outgoing_packet(&self) {
        self.read_outgoing.replace(true);
    }

    fn send_outgoing_packet(
        &self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()> {
        if let Some(timestamp) = timestamp {
            precise_sleep(timestamp_to_instant(self.epoch, timestamp));
        }
        let socket_send_instant = Instant::now();
        if let Err(err) = self.socket.send_to(packet, destination) {
            log::error!("Error sending outgoing packet (over UdpSocket): {err:?}");
        }
        if let Some(deviation_stats_thread) = &self.deviation_stats_thread {
            deviation_stats_thread.register_packet(
                self.next_outgoing_packet_id.get(),
                instant_to_timestamp(self.epoch, socket_send_instant),
            );
        }
        self.next_outgoing_packet_id
            .set(self.next_outgoing_packet_id.get() + 1);
        Ok(())
    }

    fn send_incoming_packet(&self, packet: &[u8]) -> Result<()> {
        if let Err(err) = self.tun.send(packet) {
            log::error!("Error sending incoming packet (over TUN): {err:?}");
        }
        Ok(())
    }

    fn clear_event_listeners(&self) -> Result<()> {
        self.timer.replace(None);
        self.read_outgoing.replace(false);
        // self.socket.connect(self.disconnect_addr)?;
        Ok(())
    }

    fn mtu(&self, peer: SocketAddr) -> Result<u16> {
        Ok(u16::try_from(mtu::interface_and_mtu(peer.ip())?.1).unwrap_or(u16::MAX))
    }

    fn register_interval(&self, duration: u64) {
        assert!(
            self.next_outgoing_packet_id.get() > 0,
            "Must send an outgoing packet before registering an interval"
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
        direction: AbsoluteDirection,
        seqno: u64,
        tx_rx_epoch_times: Option<(u64, u64)>,
    ) {
        self.monitor_packets_thread
            .as_ref()
            .expect("Tried to register_packet_status on hardware that isn't set up record them")
            .register_packet_status(direction, seqno, tx_rx_epoch_times);
    }

    fn configure_qdisc(&self, settings: &QdiscSettings) -> Result<()> {
        configure_qdisc(&self.tun.name()?, &self.tun, settings)
    }
}

fn precise_sleep(wake_at: Instant) {
    let start_delay = Instant::now().saturating_duration_since(wake_at);
    if !start_delay.is_zero() {
        log::warn!(
            "precise_sleep called too late (spinny), by {}",
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
            "Overslept during spinny precise_sleep, by {}",
            humantime::format_duration(oversleep_duration)
        );
    }
}
