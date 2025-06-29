#[cfg(not(feature = "jumbo-packets"))]
pub(crate) const MAX_IP_PACKET_LENGTH: usize = 1500;
#[cfg(feature = "jumbo-packets")]
pub(crate) const MAX_IP_PACKET_LENGTH: usize = 9000;

// how many extra bytes a DTLS header adds to a normal application data message
pub(crate) const DTLS_TYPICAL_HEADER_LENGTH: u16 = 22;
// I've never actually seen wolfSSL produce an application data packet with header longer than 22
// (in fact, there's an assertion in dtls.rs to ensure that it doesn't), but wolfssl still enforces
// a lower maximum cleartext length by 12 bytes; see https://github.com/wolfSSL/wolfssl/issues/8939
pub(crate) const DTLS_MAX_HEADER_LENGTH: u16 = DTLS_TYPICAL_HEADER_LENGTH + 12;
pub(crate) const UDP_HEADER_LENGTH: u16 = 8;
// this can be wrong if IP options are used, but that's very rare these days, and only really on
// private networks.
pub(crate) const IPV4_HEADER_LENGTH: u16 = 20;
pub(crate) const IPV6_HEADER_LENGTH: u16 = 40;
