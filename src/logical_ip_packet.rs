use crate::array_array::IpPacketBuffer;

/// A logical IP packet that is being tunneled over I405
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct LogicalIpPacket {
    pub(crate) packet: IpPacketBuffer,
    pub(crate) schedule: Option<u64>,
}
