#[cfg(not(feature = "jumbo-packets"))]
pub(crate) const MAX_IP_PACKET_LENGTH: usize = 1500;
#[cfg(feature = "jumbo-packets")]
pub(crate) const MAX_IP_PACKET_LENGTH: usize = 9000;

// how many extra bytes a DTLS header adds to a normal application data message
pub(crate) const DTLS_HEADER_LENGTH: u16 = 22;
pub(crate) const UDP_HEADER_LENGTH: u16 = 8;
// this can be wrong if IP options are used, but that's very rare these days, and only really on
// private networks.
pub(crate) const IPV4_HEADER_LENGTH: u16 = 20;
pub(crate) const IPV6_HEADER_LENGTH: u16 = 40;
