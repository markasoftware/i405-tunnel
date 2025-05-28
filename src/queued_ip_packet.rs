use crate::{array_array::IpPacketBuffer, logical_ip_packet::LogicalIpPacket, messages};

/// A logical IP packet that we are trying to send out, but haven't completely sent over the wire
/// yet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct QueuedIpPacket {
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
    pub(crate) fn new(packet: &[u8], schedule: Option<u64>) -> QueuedIpPacket {
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
    pub(crate) fn fragment(
        self,
        max_length: usize,
        unused_fragmentation_id: u16,
    ) -> FragmentResult {
        match self.fragmentation {
            // Haven't sent any messages for this packet yet, send the initial IpPacket
            None => {
                // Make the first fragmented message
                // 1. Determine the "base size" of the IpPacket message
                // 2. If base size + inner packet length is <= max_size, make it and return
                //    Else, set fragmented flag, make an initial packet, and return
                let fragmented_base_length =
                    messages::IpPacket::base_length(self.schedule, Some(unused_fragmentation_id));
                let min_useful_fragmented_length = fragmented_base_length.checked_add(1).unwrap();
                let unfragmented_base_length = messages::IpPacket::base_length(self.schedule, None);
                let one_packet_length = unfragmented_base_length
                    .checked_add(self.packet.len())
                    .unwrap();
                if one_packet_length <= max_length {
                    FragmentResult::Done(messages::Message::IpPacket(messages::IpPacket {
                        schedule: self.schedule,
                        fragmentation_id: None,
                        packet: self.packet.clone(),
                    }))
                } else if max_length < min_useful_fragmented_length {
                    FragmentResult::MaxLengthTooShort(self)
                } else {
                    let fragment_inner_packet_length =
                        max_length.checked_sub(fragmented_base_length).unwrap();
                    let message = messages::Message::IpPacket(messages::IpPacket {
                        schedule: self.schedule,
                        fragmentation_id: Some(unused_fragmentation_id),
                        packet: IpPacketBuffer::new(&self.packet[..fragment_inner_packet_length]),
                    });
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
                let min_useful_length = base_length.checked_add(1).unwrap();
                let one_packet_length = base_length
                    .checked_add(self.packet.len())
                    .unwrap()
                    .checked_sub(num_bytes_sent)
                    .unwrap();
                if one_packet_length <= max_length {
                    FragmentResult::Done(messages::Message::IpPacketFragment(
                        messages::IpPacketFragment {
                            is_last: true,
                            fragmentation_id,
                            offset: num_bytes_sent.try_into().unwrap(),
                            fragment: IpPacketBuffer::new(&self.packet[num_bytes_sent..]),
                        },
                    ))
                } else if max_length < min_useful_length {
                    FragmentResult::MaxLengthTooShort(self)
                } else {
                    let fragment_inner_packet_length = max_length.checked_sub(base_length).unwrap();
                    let fragment_past_end = num_bytes_sent
                        .checked_add(fragment_inner_packet_length)
                        .unwrap();
                    let message = messages::Message::IpPacketFragment(messages::IpPacketFragment {
                        is_last: false,
                        fragmentation_id,
                        offset: num_bytes_sent.try_into().unwrap(),
                        fragment: IpPacketBuffer::new(
                            &self.packet[num_bytes_sent..fragment_past_end],
                        ),
                    });
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum FragmentResult {
    /// The remaining packet fit into a single message, contained within
    Done(messages::Message),
    /// The remaining packet did not fit into a single message. Here's the next message, and the
    /// QueuedIpPacket you should fragment next.
    Partial(messages::Message, QueuedIpPacket),
    /// The maximum length specified is too short.
    MaxLengthTooShort(QueuedIpPacket),
}

#[cfg(test)]
mod test {
    use crate::{
        array_array::IpPacketBuffer,
        messages::{IpPacket, IpPacketFragment, Message},
        queued_ip_packet::{FragmentResult, QueuedIpPacket},
    };

    #[test]
    fn doesnt_need_fragment() {
        let queued_packet = QueuedIpPacket::new(&[1, 2, 3, 4], None);
        let fragment_result = queued_packet.fragment(1000, 42);
        assert_eq!(
            fragment_result,
            FragmentResult::Done(Message::IpPacket(IpPacket {
                fragmentation_id: None,
                schedule: None,
                packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
            }))
        );
    }

    // could theoretically change these to be based on the `base_length`, but prat of the point is
    // to test that lol.

    // type byte, schedule, fragment ID, length
    const IP_PACKET_START_FRAGMENT_BASE_LENGTH: usize = 1 + 8 + 2 + 2;
    // same as above, but no fragment ID
    const IP_PACKET_SOLO_BASE_LENGTH: usize = 1 + 8 + 2;
    // type byte, fragment ID, offset, length.
    const IP_PACKET_FRAGMENT_BASE_LENGTH: usize = 1 + 2 + 2 + 2;

    #[test]
    fn needs_three_fragments() {
        let queued_packet = QueuedIpPacket::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9], Some(9299));
        let fragment_result = queued_packet.fragment(IP_PACKET_START_FRAGMENT_BASE_LENGTH + 3, 5);
        // is there any way to more ergonomically do a sort of "unwrap" on a custom type?
        if let FragmentResult::Partial(message, queued_packet) = fragment_result {
            assert_eq!(
                message,
                Message::IpPacket(IpPacket {
                    schedule: Some(9299),
                    fragmentation_id: Some(5),
                    packet: IpPacketBuffer::new(&[1, 2, 3])
                })
            );
            let fragment_result = queued_packet.fragment(IP_PACKET_FRAGMENT_BASE_LENGTH + 3, 6);
            if let FragmentResult::Partial(message, queued_packet) = fragment_result {
                assert_eq!(
                    message,
                    Message::IpPacketFragment(IpPacketFragment {
                        is_last: false,
                        fragmentation_id: 5,
                        offset: 3,
                        fragment: IpPacketBuffer::new(&[4, 5, 6]),
                    })
                );

                let fragment_result = queued_packet.fragment(IP_PACKET_FRAGMENT_BASE_LENGTH + 3, 7);
                assert_eq!(
                    fragment_result,
                    FragmentResult::Done(Message::IpPacketFragment(IpPacketFragment {
                        is_last: true,
                        fragmentation_id: 5,
                        offset: 6,
                        fragment: IpPacketBuffer::new(&[7, 8, 9])
                    }))
                );
            } else {
                panic!(
                    "Wrong fragment result (2nd fragment call): {:?}",
                    fragment_result
                );
            }
        } else {
            panic!(
                "Wrong fragment result (1st fragment call): {:?}",
                fragment_result
            );
        }
    }

    #[test]
    fn max_size_too_small_one_packet() {
        // first, test the first packet length
        let queued_packet = QueuedIpPacket::new(&[1], Some(1100));
        assert_eq!(
            queued_packet
                .clone()
                .fragment(IP_PACKET_SOLO_BASE_LENGTH, 0),
            FragmentResult::MaxLengthTooShort(queued_packet.clone())
        );
        assert_eq!(
            queued_packet.fragment(IP_PACKET_SOLO_BASE_LENGTH + 1, 0),
            FragmentResult::Done(Message::IpPacket(IpPacket {
                schedule: Some(1100),
                fragmentation_id: None,
                packet: IpPacketBuffer::new(&[1])
            }))
        );
    }

    #[test]
    fn max_size_too_small_two_fragments() {
        // have to make it 4 long, because IP_PACKET_START_FRAGMENT_BASE_LENGTH+1 is long enough to
        // fit 3 bytes into a standalone IpPacket message.
        let queued_packet = QueuedIpPacket::new(&[1, 2, 3, 4], Some(1100));
        assert_eq!(
            queued_packet
                .clone()
                .fragment(IP_PACKET_START_FRAGMENT_BASE_LENGTH, 0),
            FragmentResult::MaxLengthTooShort(queued_packet.clone())
        );
        let fragment_result = queued_packet.fragment(IP_PACKET_START_FRAGMENT_BASE_LENGTH + 1, 0);
        if let FragmentResult::Partial(message, queued_packet) = fragment_result {
            assert_eq!(
                message,
                Message::IpPacket(IpPacket {
                    schedule: Some(1100),
                    fragmentation_id: Some(0),
                    packet: IpPacketBuffer::new(&[1])
                })
            );
            assert_eq!(
                queued_packet
                    .clone()
                    .fragment(IP_PACKET_FRAGMENT_BASE_LENGTH, 1),
                FragmentResult::MaxLengthTooShort(queued_packet.clone())
            );
            assert_eq!(
                queued_packet.fragment(IP_PACKET_FRAGMENT_BASE_LENGTH + 3, 1),
                FragmentResult::Done(Message::IpPacketFragment(IpPacketFragment {
                    is_last: true,
                    fragmentation_id: 0,
                    offset: 1,
                    fragment: IpPacketBuffer::new(&[2, 3, 4])
                }))
            )
        } else {
            panic!("Didn't allow fragmenting: {:?}", fragment_result);
        }
    }
}
