use crate::{array_array::IpPacketBuffer, logical_ip_packet::LogicalIpPacket, messages};

/// A logical IP packet that we are trying to send out, but haven't completely sent over the wire
/// yet.
#[derive(Debug, PartialEq, Eq, Clone)]
struct QueuedIpPacket {
    packet: IpPacketBuffer,
    schedule: Option<u64>,
    fragmentation: Option<Fragmentation>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Fragmentation {
    /// How many bytes from the buffer have already been transmitted (in earlier fragments)
    num_bytes_sent: usize,
    fragmentation_id: u16,
}

impl From<QueuedIpPacket> for LogicalIpPacket {
    fn from(value: QueuedIpPacket) -> Self {
        Self {
            packet: value.packet,
            schedule: value.schedule,
        }
    }
}

impl From<LogicalIpPacket> for QueuedIpPacket {
    fn from(value: LogicalIpPacket) -> Self {
        Self::new(&value.packet[..], value.schedule)
    }
}

impl QueuedIpPacket {
    fn new(packet: &[u8], schedule: Option<u64>) -> QueuedIpPacket {
        QueuedIpPacket {
            packet: IpPacketBuffer::new(packet),
            schedule,
            fragmentation: None,
        }
    }

    /// Produce one message containing as much as possible of the remaining data in the
    /// QueuedIpPacket as can fit in `max_length`. `unused_fragmentation_id` should just be a u16
    /// that hasn't been used frequently as the fragment id anywhere else -- we just use a wrapping
    /// counter that we increment every time we call `fragment`. Hence our fragment IDs aren't
    /// consecutive, but that doesn't matter.
    fn fragment(self, max_length: usize, unused_fragmentation_id: u16) -> FragmentResult {
        match self.fragmentation {
            // Haven't sent any messages for this packet yet, send the initial IpPacket
            None => {
                // Make the first fragmented message
                // 1. Determine the "base size" of the IpPacket message
                // 2. If base size + inner packet length is <= max_size, make it and return
                //    Else, set fragmented flag, make an initial packet, and return
                let base_length =
                    messages::IpPacket::base_length(self.schedule, Some(unused_fragmentation_id));
                let one_packet_length = base_length.checked_add(self.packet.len()).unwrap();
                if one_packet_length <= max_length {
                    FragmentResult::Done(messages::Message::IpPacket(messages::IpPacket::new(
                        self.schedule,
                        None,
                        &self.packet[..],
                    )))
                } else {
                    let fragment_inner_packet_length = max_length.checked_sub(base_length).unwrap();
                    let message = messages::Message::IpPacket(messages::IpPacket::new(
                        self.schedule,
                        Some(unused_fragmentation_id),
                        &self.packet[..fragment_inner_packet_length],
                    ));
                    FragmentResult::Partial(
                        message,
                        Self {
                            fragmentation: Some(Fragmentation {
                                num_bytes_sent: fragment_inner_packet_length,
                                fragmentation_id: unused_fragmentation_id,
                            }),
                            ..self
                        },
                    )
                }
            }
            // We've already emitted the first message (IpPacket) for this packet, so we'll emit an
            // IpPacketFragment message instead.
            Some(Fragmentation {
                num_bytes_sent,
                fragmentation_id,
            }) => {
                // 1. Determine the base size of a IpPacketFragment message
                // 2. If base size + remaining inner packet length <= max_size, make it and return.
                //    Else, don't!
                let base_length = messages::IpPacketFragment::base_length();
                let one_packet_length = base_length
                    .checked_add(self.packet.len())
                    .unwrap()
                    .checked_sub(num_bytes_sent)
                    .unwrap();
                if one_packet_length <= max_length {
                    FragmentResult::Done(messages::Message::IpPacketFragment(
                        messages::IpPacketFragment::new(
                            true,
                            fragmentation_id,
                            num_bytes_sent.try_into().unwrap(),
                            &self.packet[num_bytes_sent..],
                        ),
                    ))
                } else {
                    let fragment_inner_packet_length = max_length.checked_sub(base_length).unwrap();
                    let message =
                        messages::Message::IpPacketFragment(messages::IpPacketFragment::new(
                            false,
                            fragmentation_id,
                            num_bytes_sent.try_into().unwrap(),
                            &self.packet[num_bytes_sent..num_bytes_sent + one_packet_length],
                        ));
                    FragmentResult::Partial(
                        message,
                        Self {
                            fragmentation: Some(Fragmentation {
                                num_bytes_sent: num_bytes_sent
                                    .checked_add(fragment_inner_packet_length)
                                    .unwrap(),
                                fragmentation_id,
                            }),
                            ..self
                        },
                    )
                }
            }
        }
    }
}

enum FragmentResult {
    /// The remaining packet fit into a single message, contained within
    Done(messages::Message),
    /// The remaining packet did not fit into a single message. Here's the next message, and the
    /// QueuedIpPacket you should fragment next.
    Partial(messages::Message, QueuedIpPacket),
}

#[cfg(test)]
mod test {
    use crate::queued_ip_packet::QueuedIpPacket;
}
