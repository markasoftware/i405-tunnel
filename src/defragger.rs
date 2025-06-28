use bitvec::{BitArr, bitarr};

use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    messages::{IpPacket, IpPacketFragment},
};

/// the maximum number of fragmented packets we can keep track of at once. 8 may seem low, but you'd
/// need hell a lot of re-ordering or packet drops to have more than 8 outstanding buffers.
const MAX_ACTIVE_FRAGMENTATION_IDS: usize = 8;
/// A fragmentation ID will be dropped after we see this many other fragmentation IDs. Higher
/// numbers are more robust to reordering, but 100 is already pretty high and the failure mode is
/// just dropping a packet. If it's set way too high, could mean that a fragmentation ID will be
/// re-used and still be in our data structure, resulting in it...probably getting dropped, but
/// worst case being corrupted (which is still not a /huge/ deal, as a layer 3 tunnel, corrupted
/// packets are acceptable occasionally).
const MAX_FRAGMENTATION_ID_AGE: u64 = 100;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Defragger {
    defrag_packets: Vec<DefragPacket>,
    counter: u64,
}

/// A partially defragmented packet
#[derive(Debug, PartialEq, Eq, Clone)]
struct DefragPacket {
    fragmentation_id: u16,
    packet_so_far: IpPacketBuffer,
    /// Which bytes in packet_so_far have been written. You may be tempted to just store an integer
    /// number of how many bytes have been written rather than exactly which bytes have been
    /// written, and then be done when the number of written bytes equals the unfragmented length --
    /// but keeping track of the individulaly written bytes helps protect against the (admittedly
    /// rare) case when a fragmentation ID gets reused. It also protects against the unlikely case
    /// that our DTLS implementation doesn't have replay protection (it's not actually required by
    /// the RFC, implementations just "SHOULD" implement replay protection)
    written_bytes: BitArr!(for MAX_IP_PACKET_LENGTH),
    /// Info that's stored only in the first packet, filled in once we receive the first packet.
    details: Option<PacketDetails>,
    /// Once we learn the length of the unfragmented packet, put it here.
    unfragmented_length: Option<u16>,
    /// Incrementing counter assigned to new packets so that we are able to kick the
    /// least-recently-used packet out of defrag_packets.
    counter: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct PacketDetails {}

impl Defragger {
    pub(crate) fn new() -> Defragger {
        Defragger {
            defrag_packets: Vec::with_capacity(MAX_ACTIVE_FRAGMENTATION_IDS),
            counter: 0,
        }
    }

    /// Remove the oldest defrag packet, limited to counter<=max_counter if provided
    fn remove_oldest_defrag_packet(&mut self, max_counter: Option<u64>) -> bool {
        let mut oldest_i: Option<usize> = None;
        let mut oldest_counter = max_counter.unwrap_or(u64::MAX);
        for i in 0..self.defrag_packets.len() {
            if self.defrag_packets[i].counter <= oldest_counter {
                oldest_counter = self.defrag_packets[i].counter;
                oldest_i = Some(i);
            }
        }

        match oldest_i {
            Some(oldest_i) => {
                self.defrag_packets.swap_remove(oldest_i);
                true
            }
            None => false,
        }
    }

    /// Shrink defrag_packets by one element if full
    fn ensure_space_for_defrag_packet(&mut self) {
        if self.defrag_packets.len() == MAX_ACTIVE_FRAGMENTATION_IDS {
            let removed = self.remove_oldest_defrag_packet(None);
            assert!(removed, "Failed to remove oldest defrag packet??");
        }
    }

    fn remove_expired_defrag_packets(&mut self) {
        if self.counter > MAX_FRAGMENTATION_ID_AGE {
            while self.remove_oldest_defrag_packet(Some(self.counter - MAX_FRAGMENTATION_ID_AGE)) {}
        }
    }

    fn remove_specific_defrag_packet(&mut self, fragmentation_id: u16) {
        self.defrag_packets.remove(
            self.defrag_packets
                .iter()
                .position(|dp| dp.fragmentation_id == fragmentation_id)
                .expect("Called remove_specific_defrag_packet on non-existent fragmentation_id"),
        );
    }

    fn ensure_defrag_packet(&mut self, fragmentation_id: u16) -> &mut DefragPacket {
        // tried to match iter_mut().find(..) the first time, but then the None branch was giving
        // ownership errors
        match self
            .defrag_packets
            .iter()
            .position(|dp| dp.fragmentation_id == fragmentation_id)
        {
            Some(defrag_packet_idx) => &mut self.defrag_packets[defrag_packet_idx],
            None => {
                self.ensure_space_for_defrag_packet();
                let counter = self.next_counter();
                self.defrag_packets
                    .push(DefragPacket::new(fragmentation_id, counter));
                let last_idx = self.defrag_packets.len() - 1;
                &mut self.defrag_packets[last_idx]
            }
        }
    }

    fn next_counter(&mut self) -> u64 {
        self.counter += 1;
        self.remove_expired_defrag_packets();
        self.counter
    }

    /// Take an IP packet message and returns the inner IP packet content if it's unfragmented.
    /// Else, updates internal data structures to account for the fragment, and returns None.
    pub(crate) fn handle_ip_packet(&mut self, message: &IpPacket) -> Option<IpPacketBuffer> {
        let fragmentation_id = match message.fragmentation_id {
            Some(fragmentation_id) => fragmentation_id,
            // the packet is not fragmented
            None => {
                // this ensures that we kick out old fragments
                self.next_counter();
                return Some(message.packet.clone());
            }
        };

        let defrag_packet = self.ensure_defrag_packet(fragmentation_id);

        if defrag_packet.details.is_some() {
            log::warn!(
                "Got an IpPacket message but the existing fragmented packet already has `details` set. Dropping the old fragmented packet."
            );
            self.remove_specific_defrag_packet(fragmentation_id);
            return self.handle_ip_packet(message);
        }
        if defrag_packet.written_bytes[..message.packet.len()].any() {
            log::warn!(
                "Got an IpPacket message that had bytes which were already written for the existing fragmented packet. Dropping the old fragmented packet."
            );
            self.remove_specific_defrag_packet(fragmentation_id);
            return self.handle_ip_packet(message);
        }

        defrag_packet.details = Some(PacketDetails {});
        defrag_packet.written_bytes[..message.packet.len()].fill(true);
        defrag_packet.packet_so_far[..message.packet.len()].copy_from_slice(&message.packet[..]);

        match defrag_packet.try_complete() {
            Some(packet) => {
                self.remove_specific_defrag_packet(fragmentation_id);
                Some(packet)
            }
            None => None,
        }
    }

    /// Given an IP packet fragment message, if it completes a packet, return the packet, else just
    /// update internal data structures and return None.
    pub(crate) fn handle_ip_packet_fragment(
        &mut self,
        message: &IpPacketFragment,
    ) -> Option<IpPacketBuffer> {
        // actually one past the end
        let message_offset_past_end = usize::from(message.offset) + message.fragment.len();

        let defrag_packet = self.ensure_defrag_packet(message.fragmentation_id);

        if message.is_last && defrag_packet.unfragmented_length.is_some() {
            log::warn!(
                "Got an IpPacketFragment with is_last set, but the existing fragmented packet already had unfragmented_length set. Dropping the old fragmented packet"
            );
            self.remove_specific_defrag_packet(message.fragmentation_id);
            return self.handle_ip_packet_fragment(message);
        }
        if defrag_packet.written_bytes[message.offset.into()..message_offset_past_end].any() {
            log::warn!(
                "Got an IpPacketFragment with bytes that were already written for the existing fragmented packet. Dropping the old fragmented packet."
            );
            self.remove_specific_defrag_packet(message.fragmentation_id);
            return self.handle_ip_packet_fragment(message);
        }

        if message.is_last {
            defrag_packet.unfragmented_length = Some(message_offset_past_end.try_into().unwrap());
            defrag_packet.packet_so_far.shrink(message_offset_past_end);
        }
        defrag_packet.written_bytes[message.offset.into()..message_offset_past_end].fill(true);
        defrag_packet.packet_so_far[message.offset.into()..message_offset_past_end]
            .copy_from_slice(&message.fragment[..]);

        // TODO we could be a bit more type-safe here, instead of getting an &mut to the
        // defrag_packet and then having to remember to delete it when doing try_complete, we could
        // take it out of the vec, then try_complete consumes it, and then put the result back into
        // the vec if not complete. More similar to DTLS handling.
        match defrag_packet.try_complete() {
            Some(packet) => {
                self.remove_specific_defrag_packet(message.fragmentation_id);
                Some(packet)
            }
            None => None,
        }
    }
}

impl DefragPacket {
    fn new(fragmentation_id: u16, counter: u64) -> Self {
        DefragPacket {
            fragmentation_id,
            packet_so_far: IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH),
            written_bytes: bitarr!(0; MAX_IP_PACKET_LENGTH),
            details: None,
            unfragmented_length: None,
            counter,
        }
    }

    /// If the fragment is complete, return the buffer within!
    fn try_complete(&self) -> Option<IpPacketBuffer> {
        match (&self.details, self.unfragmented_length) {
            (Some(_details), Some(unfragmented_length)) => {
                if self.written_bytes[..unfragmented_length.into()].all() {
                    assert!(
                        self.packet_so_far.len() == unfragmented_length.into(),
                        "Packet to return in try_complete was not the expected length; it should be shrunk when unfragmented_length is set"
                    );
                    Some(self.packet_so_far.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Defragger, MAX_ACTIVE_FRAGMENTATION_IDS, MAX_FRAGMENTATION_ID_AGE};
    use crate::array_array::IpPacketBuffer;
    use crate::messages::{IpPacket, IpPacketFragment};

    #[test]
    fn defrag_non_fragmented_packet() {
        let mut defragger = Defragger::new();
        let message = IpPacket {
            fragmentation_id: None,
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        };
        let defrag_result = defragger.handle_ip_packet(&message);
        assert_eq!(defrag_result, Some(message.packet.clone()));
    }

    #[test]
    fn defrag_three_packets_all_orders() {
        let mut defragger = Defragger::new();
        let message_0 = IpPacket {
            fragmentation_id: Some(42),
            packet: IpPacketBuffer::new(&[1, 2, 3, 4]),
        };
        let message_1 = IpPacketFragment {
            is_last: false,
            fragmentation_id: 42,
            offset: 4,
            fragment: IpPacketBuffer::new(&[5, 6]),
        };
        let message_2 = IpPacketFragment {
            is_last: true,
            fragmentation_id: 42,
            offset: 6,
            fragment: IpPacketBuffer::new(&[7, 8, 9]),
        };

        let mut handle_message = |which| match which {
            0 => defragger.handle_ip_packet(&message_0),
            1 => defragger.handle_ip_packet_fragment(&message_1),
            2 => defragger.handle_ip_packet_fragment(&message_2),
            _ => panic!("Bad which"),
        };

        // hacky way to do all permutations
        let mut num_permutations = 0;
        for i in 0..3 {
            for j in 0..3 {
                // this last loop is pretty stupid because we can just calculate k...oh well
                for k in 0..3 {
                    if i != j && i != k && j != k {
                        eprintln!("Starting case: {} {} {}", i, j, k);
                        num_permutations += 1;
                        assert_eq!(handle_message(i), None);
                        assert_eq!(handle_message(j), None);
                        assert_eq!(
                            handle_message(k),
                            Some(IpPacketBuffer::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9])),
                        );
                    }
                }
            }
        }
        assert_eq!(num_permutations, 6);
    }

    // When there are more than MAX_ACTIVE_FRAGMENTATION_IDs many fragments, the oldest one gets
    // dropped.
    #[test]
    fn defrag_many_active_fragments() {
        let mut defragger = Defragger::new();
        for fid in 0..u16::try_from(MAX_ACTIVE_FRAGMENTATION_IDS).unwrap() + 1 {
            defragger.handle_ip_packet(&IpPacket {
                fragmentation_id: Some(fid),
                packet: IpPacketBuffer::new(&[8, 9, 0]),
            });
        }
        // it's important to test this one first; if we test fid 0 first, then it'll have to
        // reallocate space for it and kick out 1.
        assert!(
            defragger
                .handle_ip_packet_fragment(&IpPacketFragment {
                    is_last: true,
                    fragmentation_id: 1,
                    offset: 3,
                    fragment: IpPacketBuffer::new(&[1]),
                })
                .is_some()
        );
        assert!(
            defragger
                .handle_ip_packet_fragment(&IpPacketFragment {
                    is_last: true,
                    fragmentation_id: 0,
                    offset: 3,
                    fragment: IpPacketBuffer::new(&[1]),
                })
                .is_none()
        );
    }

    #[test]
    fn defrag_drop_old_fragment() {
        let mut defragger = Defragger::new();

        // first, insert the start of the packet we'll allow to get old.
        let old_fid = 8;
        let old_start = IpPacket {
            fragmentation_id: Some(old_fid),
            packet: IpPacketBuffer::new(&[8]),
        };
        defragger.handle_ip_packet(&old_start);

        let old_fid_2 = 9;
        let old_start_2 = IpPacket {
            fragmentation_id: Some(old_fid_2),
            packet: IpPacketBuffer::new(&[8]),
        };
        defragger.handle_ip_packet(&old_start_2);

        for _ in 0..MAX_FRAGMENTATION_ID_AGE - 5 {
            // push through unfragmented packets
            let buf = IpPacketBuffer::new(&[2, 9]);
            let defragged = defragger.handle_ip_packet(&IpPacket {
                fragmentation_id: None,
                packet: buf.clone(),
            });
            // we don't care that much about the result but why not check
            assert_eq!(defragged, Some(buf));
        }
        for new_fid in 990..995 {
            // push through fragmented packets. The idea here is we want to check that both
            // fragmented and unfragmented packets increase the counter
            defragger.handle_ip_packet(&IpPacket {
                fragmentation_id: Some(new_fid),
                packet: IpPacketBuffer::new(&[1, 2]),
            });
            defragger.handle_ip_packet_fragment(&IpPacketFragment {
                is_last: true,
                fragmentation_id: new_fid,
                offset: 2,
                fragment: IpPacketBuffer::new(&[3, 4]),
            });
            // second-to-last: Ensure it hasn't been kicked out yet.
            if new_fid == 993 {
                assert!(
                    defragger
                        .handle_ip_packet_fragment(&IpPacketFragment {
                            is_last: true,
                            fragmentation_id: old_fid_2,
                            offset: 1,
                            fragment: IpPacketBuffer::new(&[10]),
                        })
                        .is_some()
                );
            }
        }

        assert!(
            defragger
                .handle_ip_packet_fragment(&IpPacketFragment {
                    is_last: true,
                    fragmentation_id: old_fid,
                    offset: 1,
                    fragment: IpPacketBuffer::new(&[9])
                })
                .is_none()
        );
    }
}
