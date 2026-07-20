pub(crate) mod real;
#[cfg(test)]
pub(crate) mod simulated;
pub(crate) mod sleepy;
pub(crate) mod spinny;

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU8},
};

use anyhow::Result;
use real::QdiscSettings;

use crate::{array_array::IpPacketBuffer, utils::RelativeDirection};

pub(crate) struct ReadOutgoingPacket {
    // Unfortunately since we just use standard references to the Hardware, there's no reasonable
    // way to have this be borrowed from the hardware (it'll be tied to &impl Hardware, which is the
    // same as other methods that would modify the hardware and eg pop it off). But if we can figure
    // that out and transition to having proper distinction between mut and non-mut, we should move
    // this to be &'a [u8] and then have peek_outgoing_packet + pop_outgoing_packet etc.

    // could also do a with_read_outgoing_packet(callback: impl FnOnce(&[u8], u64) -> A) ->
    // Option<A> but really that's not the elegant solution.
    pub(crate) packet: IpPacketBuffer,
    pub(crate) recv_timestamp: u64,
}

pub(crate) struct ReadIncomingPacket {
    pub(crate) packet: IpPacketBuffer,
    pub(crate) peer: SocketAddr,
}

/// The typical shutdown pattern is that the user requests shutdown, and then the core reads from
/// the hardware that the user requested shutdown, and eventually requests its own shutdown, and
/// finally the hardware shuts down when it sees the core has requested such. This helper
/// facilitates those transitions. Clones affect each other.
#[derive(Debug, Clone)]
pub(crate) struct ShutdownRequested {
    inner: Arc<AtomicU8>,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ShutdownRequestedState {
    Running,
    UserRequestedShutdown,
    CoreRequestedShutdown,
}

impl ShutdownRequested {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(AtomicU8::new(ShutdownRequestedState::Running as u8)),
        }
    }

    pub(crate) fn user_request_shutdown(&self) {
        // TODO determine if it should be Relaxed
        // `Result` just tells us whether it compared equal or not; we don't care, since state is shutdown in progress regardless.
        let _ = self.inner.compare_exchange(
            ShutdownRequestedState::Running as u8,
            ShutdownRequestedState::UserRequestedShutdown as u8,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub(crate) fn core_request_shutdown(&self) {
        assert!(
            self.has_user_requested_shutdown(),
            "Core should not request shutdown until user requests it"
        );
        self.inner.store(
            ShutdownRequestedState::CoreRequestedShutdown as u8,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub(crate) fn has_user_requested_shutdown(&self) -> bool {
        match self.inner.load(std::sync::atomic::Ordering::Relaxed) {
            // very unfortunate can't actually match on the enum, oh well
            val if val == ShutdownRequestedState::Running as u8 => false,
            val if val == ShutdownRequestedState::UserRequestedShutdown as u8 => true,
            val if val == ShutdownRequestedState::CoreRequestedShutdown as u8 => true,
            _ => panic!("impossible value"),
        }
    }

    pub(crate) fn has_core_requested_shutdown(&self) -> bool {
        match self.inner.load(std::sync::atomic::Ordering::Relaxed) {
            val if val == ShutdownRequestedState::Running as u8 => false,
            val if val == ShutdownRequestedState::UserRequestedShutdown as u8 => false,
            val if val == ShutdownRequestedState::CoreRequestedShutdown as u8 => true,
            _ => panic!("impossible value"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TimerTracker {
    timer: Option<u64>,
}

impl TimerTracker {
    pub(crate) fn new() -> Self {
        Self { timer: None }
    }

    pub(crate) fn with_timer(hardware: &impl Hardware, timer: u64) -> Self {
        let mut result = Self::new();
        result.set_timer(hardware, timer);
        result
    }

    pub(crate) fn get_fired_timer(&self, hardware: &impl Hardware) -> Option<u64> {
        self.timer
            .and_then(|timer| (hardware.timestamp() >= timer).then_some(timer))
    }

    pub(crate) fn has_fired(&self, hardware: &impl Hardware) -> bool {
        self.get_fired_timer(hardware).is_some()
    }

    pub(crate) fn set_timer(&mut self, hardware: &impl Hardware, timer: u64) {
        self.timer = Some(timer);
        hardware.set_timer(timer);
    }
}

/// A completely abstract interface to the outside world, for easy testing. The core I405 logic is
/// only able to interact with the outside world through an instance of `Hardware`
pub(crate) trait Hardware {
    /// Request an on_event as soon as possible after the given timestamp. It's guaranteed that
    /// on_event will be called at a time where timestamp() returns >= the requested timestamp.
    fn set_timer(&self, timestamp: u64) -> Option<u64>;
    /// Return the current timestamp. This is monotonic and should be used for all precise purposes.
    fn timestamp(&self) -> u64;
    /// Return nanos since unix epoch. May go backwards and all that fun.
    fn epoch_timestamp(&self) -> u64;

    /// Core should shut down quickly and then call `shutdown` at some point after this starts
    /// returning true. Events etc will continue to be processed normally until `shutdown` is
    /// called, though.
    fn has_user_requested_shutdown(&self) -> bool;
    /// Indicate that the core is ready to shut down. The hardware may choose to stop calling
    /// on_event at any point after this call is made. Must observe `has_user_requested_shutdown()
    /// == true` at some point before calling this. This function /does/ return, and the core should
    /// be able to handle additional on_event calls without error even after calling shutdown.
    fn shutdown(&self);

    // possible TODO: Would be good to move the queueing logic for these into the core. But then
    // we'd need to push from the hardware into the core instead of pull from the core. To make that
    // happen, we'd need to split the Core into two parts, a Core and a CorePusher, where the Core's
    // only thing is an on_event, and the CorePusher has some spsc queues into the Core and
    // maintains their lengths.
    /// Hardware maintains a small queue. The hardware won't actually drop/overwrite in the queue,
    /// but the actual TUN probably will.
    fn read_outgoing_packet(&self) -> Option<ReadOutgoingPacket>;
    /// Hardware maintains a small queue, will drop and warn for incoming packets when the queue is
    /// full so don't let that happen!
    fn read_incoming_packet(&self) -> Option<ReadIncomingPacket>;

    /// Write an IP packet to the physical network interface at the given time. Should be called only shortly before the given time.
    fn send_outgoing_packet(
        &self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()>;

    fn send_incoming_packet(&self, packet: &[u8]) -> Result<()>;

    /// Filter out future traffic from addrs other than the one specified.
    fn socket_connect(&self, socket_addr: &std::net::SocketAddr) -> Result<()>;

    /// delete any running timers, and disconnect the socket if connected.
    fn clear_event_listeners(&self) -> Result<()>;

    /// mtu, including ip and udp headers, in bytes. Not clamped to MAX_IP_PACKET_LENGTH. This isn't
    /// used by any business logic, it is just needed to configure the MTU for wolfSSL
    fn mtu(&self, peer: SocketAddr) -> Result<u16>;

    /// Report to the hardware the planned duration from the last sent packet (send_outgoing_packet
    /// called before this) until the next sent packet. Not used functionally, just for reporting.
    fn register_interval(&self, duration: u64);

    /// See
    /// https://www.bufferbloat.net/projects/codel/wiki/Best_practices_for_benchmarking_Codel_and_FQ_Codel/
    /// and the tc-codel man pages. Tries to set up the qdisc and txlen to minimize latency while
    /// also preventing starvation.
    fn configure_qdisc(&self, settings: &QdiscSettings) -> Result<()>;

    /// When monitor packets mode is on and we are the client, use this to inform the hardware of
    /// the status of each packet (typically the hardware will just write it to a file).
    fn register_packet_status(
        &self,
        direction: RelativeDirection,
        seqno: u64,
        tx_rx_epoch_times: Option<(u64, u64)>,
    );
}
