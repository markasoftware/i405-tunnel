// mod simulated;

use crate::messages::IpPacket;

/// A completely abstract interface to the outside world, for easy testing. The core I405 logic is
/// only able to interact with the outside world through an instance of `Hardware`
pub(crate) trait Hardware {
    type Err;

    /// Request that Core::Wakeup be called as soon as possible after the given timestamp (given in epoch nanoseconds).
    fn wake_up_at(&mut self, timestamp: u64);
    /// Return the current timestamp
    fn timestamp(&self) -> u64;

    /// Read an IP packet that the local system is trying to send through the tunnel.
    // TODO scheduled reads to avoid deanonymizing ourselves by dequeing packets at the network frequency?
    fn read_outgoing_packet(&mut self) -> Result<Option<IpPacket>, Self::Err>; // TODO is there a way to get a simpler Result type trait-wide?
    /// Write an IP packet to the physical network interface at the given time. Should be called only shortly before the given time.
    fn send_outgoing_packet(&mut self, packet: &[u8], destination: std::net::SocketAddr, timestamp: Option<u64>) -> std::io::Result<usize>;

    fn read_incoming_packet(&mut self, packet: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)>;
    fn send_incoming_packet(&mut self, packet: &[u8], timestamp: Option<u64>) -> Result<(), Self::Err>;

    /// Filter out future traffic from addrs other than the one specified.
    fn socket_connect(&mut self, socket_addr: &std::net::SocketAddr) -> std::io::Result<()>;
    /// Remove restrictions on which addrs we receive traffic from.
    fn socket_disconnect(&mut self) -> std::io::Result<()>;
}

/// Basically std::net::UdpSocket
pub(crate) trait Socket {
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)>;
    fn send_to(&self, buf: &[u8], addr: &std::net::SocketAddr) -> std::io::Result<usize>;
}
