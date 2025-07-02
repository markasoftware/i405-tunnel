pub(crate) mod real;
#[cfg(test)]
pub(crate) mod simulated;
pub(crate) mod sleepy;
pub(crate) mod spinny;

use std::net::SocketAddr;

use anyhow::Result;
use real::QdiscSettings;

/// A completely abstract interface to the outside world, for easy testing. The core I405 logic is
/// only able to interact with the outside world through an instance of `Hardware`
pub(crate) trait Hardware {
    /// Request a call to Core::on_timer at the given timestamp. If we're replacing an existing
    /// timer, returns the old timer.
    fn set_timer(&mut self, timestamp: u64) -> Option<u64>;
    /// Return the current timestamp
    fn timestamp(&self) -> u64;

    /// Request to read an IP packet that the local system is trying to send through the tunnel. If
    /// Request a call to Core::on_read_outgoing_packet with a packet received no earlier than the
    /// requested timestamp.
    fn read_outgoing_packet(&mut self);
    /// Write an IP packet to the physical network interface at the given time. Should be called only shortly before the given time.
    fn send_outgoing_packet(
        &mut self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()>;

    fn send_incoming_packet(&mut self, packet: &[u8]) -> Result<()>;

    /// Filter out future traffic from addrs other than the one specified.
    fn socket_connect(&mut self, socket_addr: &std::net::SocketAddr) -> Result<()>;

    /// delete any running timers, and disconnect the socket if connected.
    fn clear_event_listeners(&mut self) -> Result<()>;

    /// mtu, including ip and udp headers, in bytes. Not clamped to MAX_IP_PACKET_LENGTH. This isn't
    /// used by any business logic, it is just needed to configure the MTU for wolfSSL
    fn mtu(&self, peer: SocketAddr) -> Result<u16>;

    /// Report to the hardware the planned duration from the last sent packet (send_outgoing_packet
    /// called before this) until the next sent packet. Not used functionally, just for reporting.
    fn register_interval(&mut self, duration: u64);

    /// See
    /// https://www.bufferbloat.net/projects/codel/wiki/Best_practices_for_benchmarking_Codel_and_FQ_Codel/
    /// and the tc-codel man pages
    /// Used to inform the
    fn configure_qdisc(&mut self, settings: &QdiscSettings) -> Result<()>;
}
