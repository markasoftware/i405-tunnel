use bitvec::{BitArr, bitarr};

use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    logical_ip_packet::LogicalIpPacket,
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

pub(crate) struct Defragger {
    defrag_packets: Vec<DefragPacket>,
    counter: u64,
}

/// A partially defragmented packet
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

struct PacketDetails {
    schedule: Option<u64>,
}

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
            while self.remove_oldest_defrag_packet(Some(
                self.counter.checked_sub(MAX_FRAGMENTATION_ID_AGE).unwrap(),
            )) {}
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
        self.counter
    }

    /// Take an IP packet message and returns the inner IP packet content if it's unfragmented.
    /// Else, updates internal data structures to account for the fragment, and returns None.
    pub(crate) fn handle_ip_packet(&mut self, message: &IpPacket) -> Option<LogicalIpPacket> {
        let fragmentation_id = match message.fragmentation_id {
            Some(fragmentation_id) => fragmentation_id,
            // the packet is not fragmented
            None => {
                return Some(LogicalIpPacket {
                    packet: message.packet.clone(),
                    schedule: message.schedule,
                });
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

        defrag_packet.details = Some(PacketDetails {
            schedule: message.schedule,
        });
        defrag_packet.written_bytes[..message.packet.len()].fill(true);

        match defrag_packet.try_complete() {
            Some(logical_packet) => {
                self.remove_specific_defrag_packet(fragmentation_id);
                Some(logical_packet)
            }
            None => None,
        }
    }

    /// Given an IP packet fragment message, if it completes a packet, return the packet, else just
    /// update internal data structures and return None.
    // TODO on both this and `handle_ip_packet`: Indicate warnings such as a IpPacketFragment that
    // doesn't have any entry, or when we kick an incomplete fragment out of the ring buffer (which
    // indicates drop), or when we receive an extra fragment for an already-completed packet.
    pub(crate) fn handle_ip_packet_fragment(
        &mut self,
        message: &IpPacketFragment,
    ) -> Option<LogicalIpPacket> {
        // actually one past the end
        let message_offset_past_end = usize::from(message.offset)
            .checked_add(message.fragment.len())
            .unwrap();

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
        }
        defrag_packet.written_bytes[message.offset.into()..message_offset_past_end].fill(true);

        // TODO we could be a bit more type-safe here, instead of getting an &mut to the
        // defrag_packet and then having to remember to delete it when doing try_complete, we could
        // take it out of the vec, then try_complete consumes it, and then put the result back into
        // the vec if not complete. More similar to DTLS handling.
        match defrag_packet.try_complete() {
            Some(logical_packet) => {
                self.remove_specific_defrag_packet(message.fragmentation_id);
                Some(logical_packet)
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
    fn try_complete(&self) -> Option<LogicalIpPacket> {
        match (&self.details, self.unfragmented_length) {
            (Some(details), Some(unfragmented_length)) => {
                if self.written_bytes[..unfragmented_length.into()].all() {
                    assert!(
                        self.packet_so_far.len() == unfragmented_length.into(),
                        "Packet to return in try_complete was not the expected length; it should be shrunk when unfragmented_length is set"
                    );
                    Some(LogicalIpPacket {
                        packet: self.packet_so_far.clone(),
                        schedule: details.schedule,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn is_complete(&self) -> bool {
        // you could ask, do we /really/ need to check self.details.is_some(), if we're already checking that every byte has been written? Apart from the fact that, yes, we do,
        self.details.is_some()
            && self.unfragmented_length.is_some_and(|unfragmented_length| {
                self.written_bytes[..unfragmented_length.into()].all()
            })
    }
}
