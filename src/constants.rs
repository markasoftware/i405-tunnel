#[cfg(not(feature = "jumbo_packets"))]
pub(crate) const MAX_IP_PACKET_LENGTH: usize = 1472; // TODO may want to remove this to support jumbo frames?
#[cfg(feature = "jumbo_packets")]
pub(crate) const MAX_IP_PACKET_LENGTH: usize = 8972;
