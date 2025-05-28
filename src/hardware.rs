// mod simulated;

use crate::messages::IpPacket;

use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    IOErr(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

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
    fn read_outgoing_packet(&mut self, no_earlier_than: Option<u64>);
    /// Write an IP packet to the physical network interface at the given time. Should be called only shortly before the given time.
    fn send_outgoing_packet(
        &mut self,
        packet: &[u8],
        destination: std::net::SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()>;

    fn read_incoming_packet(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(usize, std::net::SocketAddr)>;
    fn send_incoming_packet(
        &mut self,
        packet: &[u8],
        timestamp: Option<u64>,
    ) -> Result<()>;

    /// Filter out future traffic from addrs other than the one specified.
    fn socket_connect(&mut self, socket_addr: &std::net::SocketAddr) -> Result<()>;
    /// Remove restrictions on which addrs we receive traffic from.
    fn socket_disconnect(&mut self) -> Result<()>;

    /// delete any timers and read_outgoing_
    fn clear_event_listeners(&mut self);
}

/// Basically std::net::UdpSocket
pub(crate) trait Socket {
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)>;
    fn send_to(&self, buf: &[u8], addr: &std::net::SocketAddr) -> std::io::Result<usize>;
}
