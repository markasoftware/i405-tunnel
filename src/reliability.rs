use anyhow::{Result, bail};

use crate::{
    deques::{GlobalArrDeque, GlobalBitArrDeque},
    messages::{self, Message},
};

// If we ever have reliable datagrams that are substantially different in size, we may want to store
// the binary messages in the queues above and have them be byte-based, rather than message-based.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum ReliableMessage {
    // I'm not sure how I feel about including the literal PacketStatus message itself in here :|
    PacketStatus(messages::PacketStatus),
}

impl From<ReliableMessage> for Message {
    fn from(value: ReliableMessage) -> Self {
        // there's probably some way to automate the creation of this, punting until we have more
        // types of messages.
        match value {
            ReliableMessage::PacketStatus(msg) => Message::PacketStatus(msg),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum ReliabilityAction {
    ReliableMessage(ReliableMessage),
}

/// Keeps track of which ack-eliciting remote packets need to be acked, and can generate the correct
/// sequence of acks to acknowledge all of them.
#[derive(Debug)]
pub(crate) struct LocalAckGenerator {
    locally_acked_packets: GlobalBitArrDeque,
}

impl LocalAckGenerator {
    /// `capacity` is the maximum age (measured in number of incoming packets) between the latest
    /// received incoming packet and the earliest incoming packet we will attempt to send an ack for
    /// if received later.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            locally_acked_packets: GlobalBitArrDeque::new(capacity),
        }
    }

    // it's not strictly necessary to call this function for non-ack-eliciting packets, since the
    // ack-eliciting variant of the function appends to `locally_acked_packets` as necessary. But
    // imagine that we receive millions of non-ack-eliciting packets, then an ack-eliciting packet
    // -- it will rotate the queue millions of times. To keep performance more consistent, just call
    // it on every incoming packet.
    pub(crate) fn on_incoming_packet(&mut self, seqno: u64, ack_eliciting: bool) {
        if seqno < self.locally_acked_packets.head_index() {
            return;
        }
        // Consider all packets received
        for _ in self.locally_acked_packets.tail_index()..=seqno {
            self.locally_acked_packets.push(true);
        }
        if ack_eliciting && seqno >= self.locally_acked_packets.head_index() {
            self.locally_acked_packets.set(seqno, false);
        }
    }

    pub(crate) fn local_acks(&mut self) -> LocalAckIterator<'_> {
        LocalAckIterator {
            seqno: self.locally_acked_packets.head_index(),
            locally_acked_packets: &mut self.locally_acked_packets,
        }
    }
}

/// Iterator of acks we need to send
pub(crate) struct LocalAckIterator<'a> {
    locally_acked_packets: &'a mut GlobalBitArrDeque,
    seqno: u64,
}

impl Iterator for LocalAckIterator<'_> {
    type Item = messages::Ack;

    fn next(&mut self) -> Option<messages::Ack> {
        if self.seqno >= self.locally_acked_packets.tail_index() {
            return None;
        }
        self.locally_acked_packets
            .first_zero_after(self.seqno)
            .map(|first_zero_seqno| {
                let tail_seqno = self.locally_acked_packets.tail_index();
                self.seqno = first_zero_seqno;
                while self.seqno < tail_seqno && !self.locally_acked_packets[self.seqno] {
                    self.locally_acked_packets.set(self.seqno, true);
                    self.seqno += 1;
                }
                messages::Ack {
                    first_acked_seqno: first_zero_seqno,
                    last_acked_seqno: self.seqno - 1,
                }
            })
    }
}

/// Keeps track of which "reliability actions" need to be performed when an outgoing packet needs is
/// either acked by the remote or assumed lost. Able to keep track of multiple reliability actions
/// per outgoing packet, with only a global limit on the total number of reliability actions across
/// all inflight outgoing packets.
#[derive(Debug)]
pub(crate) struct RemoteAckHandler {
    outgoing_packet_ack_statuses: GlobalArrDeque<RemoteAckStatus>,
    reliability_actions: GlobalArrDeque<Option<ReliabilityAction>>,
    // if there's currently a builder associated with this handler, here's its head index.
    current_builder_head_index: Option<u64>,
}

impl RemoteAckHandler {
    /// An outgoing packet is considered lost if no acks for it are received after
    /// `outgoing_packets_capacity` many more outgoing packets have been sent.
    pub(crate) fn new(
        outgoing_packets_capacity: usize,
        reliability_actions_capacity: usize,
    ) -> Self {
        Self {
            outgoing_packet_ack_statuses: GlobalArrDeque::new(outgoing_packets_capacity),
            reliability_actions: GlobalArrDeque::new(reliability_actions_capacity),
            current_builder_head_index: None,
        }
    }

    pub(crate) fn outgoing_packet_builder(&mut self) -> ReliabilityActionBuilder<'_> {
        ReliabilityActionBuilder::new(self)
    }

    /// Returns ACK'd reliability actions.
    pub(crate) fn on_remote_ack(
        &mut self,
        acked_seqno: u64,
    ) -> Result<ReliabilityActionIterator<'_>> {
        // it's too late to ack this packet :(
        if acked_seqno < self.outgoing_packet_ack_statuses.head_index() {
            return Ok(ReliabilityActionIterator::new_empty(
                &mut self.reliability_actions,
            ));
        }
        if acked_seqno >= self.outgoing_packet_ack_statuses.tail_index() {
            bail!("Received an ACK for a packet that we never sent");
        }
        // typical case: Acking a packet that we have in store
        match std::mem::replace(
            &mut self.outgoing_packet_ack_statuses[acked_seqno],
            RemoteAckStatus::Acked,
        ) {
            RemoteAckStatus::Acked => {
                // TODO investigate whether this can happen under normal conditions. It's of course
                // possible for the UDP packet containing the ack to be duplicated by the network,
                // but will wolfSSL deliver it to us twice or does it have some protection against
                // this since it's similar to a replay attack?
                log::error!("Received a duplicate ack");
                Ok(ReliabilityActionIterator::new_empty(
                    &mut self.reliability_actions,
                ))
            }
            RemoteAckStatus::Unacked {
                head_reliability_action_index,
                tail_reliability_action_index,
            } => Ok(ReliabilityActionIterator::new(
                &mut self.reliability_actions,
                head_reliability_action_index,
                tail_reliability_action_index,
            )),
        }
    }
}

pub(crate) struct ReliabilityActionBuilder<'a> {
    ack_handler: &'a mut RemoteAckHandler,
}

// this impl is tightly coupled with that of the RemoteAckHandler
impl<'a> ReliabilityActionBuilder<'a> {
    fn new(ack_handler: &'a mut RemoteAckHandler) -> Self {
        assert!(
            ack_handler.current_builder_head_index.is_none(),
            "Cannot create a builder before finalize()ing the previous one"
        );

        // Clear out any old reliability actions that we can
        while ack_handler.reliability_actions.len() > 0
            && ack_handler.reliability_actions[ack_handler.reliability_actions.head_index()]
                .is_none()
        {
            ack_handler.reliability_actions.pop();
        }

        ack_handler.current_builder_head_index = Some(ack_handler.reliability_actions.tail_index());
        Self { ack_handler }
    }

    pub(crate) fn add_reliability_action(&mut self, ra: ReliabilityAction) -> Result<()> {
        let popped_ra = self.ack_handler.reliability_actions.push(Some(ra));
        if popped_ra.is_some() {
            // TODO maybe revisit. One could argue that we shouldn't completely bail out here. Maybe
            // we should just allocate memory instead?
            bail!("Ran out of space for reliability actions -- cannot guarantee reliable delivery");
        }
        Ok(())
    }

    // When all reliability actions have been added, call this to add the outgoing packet to the
    // list of those we're keeping track of. Returns an iterator over all RAs that got "clocked out"
    // by the new packed and are considered NACK'd.
    pub(crate) fn finalize(self) -> ReliabilityActionIterator<'a> {
        let tail_reliability_action_index = self.ack_handler.reliability_actions.tail_index();

        let popped_ack_status = self
            .ack_handler
            .outgoing_packet_ack_statuses
            .push(RemoteAckStatus::Unacked {
                head_reliability_action_index: std::mem::take(
                    &mut self.ack_handler.current_builder_head_index,
                )
                .unwrap(),
                tail_reliability_action_index,
            })
            .map(|(_, b)| b);

        if let Some(RemoteAckStatus::Unacked {
            head_reliability_action_index,
            tail_reliability_action_index,
        }) = popped_ack_status
        {
            ReliabilityActionIterator::new(
                &mut self.ack_handler.reliability_actions,
                head_reliability_action_index,
                tail_reliability_action_index,
            )
        } else {
            // either packet had already been acked, or we just started up so nothing got clocked out yet.
            ReliabilityActionIterator::new_empty(&mut self.ack_handler.reliability_actions)
        }
    }
}

#[must_use]
pub(crate) struct ReliabilityActionIterator<'a> {
    reliability_actions: &'a mut GlobalArrDeque<Option<ReliabilityAction>>,
    next_index: u64,
    // tail of what we're going to return, not tail of the whole deque
    tail_index: u64,
}

impl<'a> ReliabilityActionIterator<'a> {
    fn new(
        reliability_actions: &'a mut GlobalArrDeque<Option<ReliabilityAction>>,
        head_index: u64,
        tail_index: u64,
    ) -> Self {
        Self {
            reliability_actions,
            next_index: head_index,
            tail_index,
        }
    }

    // it's a bit silly that we even need the argument; oh well
    fn new_empty(reliability_actions: &'a mut GlobalArrDeque<Option<ReliabilityAction>>) -> Self {
        Self::new(reliability_actions, 0, 0)
    }
}

impl Iterator for ReliabilityActionIterator<'_> {
    // TODO there's probably some way to return references instead of copying out the
    // ReliabilityActions, but I'm not sure exactly how.
    type Item = ReliabilityAction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index != self.tail_index {
            let result = std::mem::take(&mut self.reliability_actions[self.next_index])
                .expect("ReliabilityActionIterator over a range where not all actions were set.");
            self.next_index += 1;
            Some(result)
        } else {
            None
        }
    }
}

#[derive(Debug)]
enum RemoteAckStatus {
    /// Already received an ack for this packet, or the packet is not ack-eliciting
    Acked,
    Unacked {
        /// Index of first callback related to this packet
        head_reliability_action_index: u64,
        /// One past the index of the last callback related to this packet
        tail_reliability_action_index: u64,
    },
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::messages::Ack;

    fn generator_local_acks(generator: &mut LocalAckGenerator) -> Vec<Ack> {
        generator.local_acks().collect::<Vec<Ack>>()
    }

    #[test]
    fn local_ack_generator() {
        let mut generator = LocalAckGenerator::new(7);
        generator.on_incoming_packet(1, true);
        generator.on_incoming_packet(2, true);
        generator.on_incoming_packet(5, true);
        // This also tests that we can correctly compute acks when the generator isn't "full" yet
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[
                Ack {
                    first_acked_seqno: 1,
                    last_acked_seqno: 2,
                },
                Ack {
                    first_acked_seqno: 5,
                    last_acked_seqno: 5,
                },
            ],
        );
        assert_eq!(&generator_local_acks(&mut generator), &[]);
        // make sure it also works after it gets rotated
        generator.on_incoming_packet(8, true);
        generator.on_incoming_packet(9, true);
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[Ack {
                first_acked_seqno: 8,
                last_acked_seqno: 9,
            },],
        );
        assert_eq!(&generator_local_acks(&mut generator), &[]);
    }

    #[test]
    fn local_ack_generator_all_unacked() {
        let mut generator = LocalAckGenerator::new(3);
        generator.on_incoming_packet(0, true);
        generator.on_incoming_packet(1, true);
        generator.on_incoming_packet(2, true);
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[Ack {
                first_acked_seqno: 0,
                last_acked_seqno: 2
            }]
        );
        assert_eq!(&generator_local_acks(&mut generator), &[]);
    }

    // If we only consume part of the iterator, ensure that the remaining acks are returned the next time.
    #[test]
    fn compute_local_acks_partial() {
        let mut generator = LocalAckGenerator::new(7);
        generator.on_incoming_packet(1, true);
        generator.on_incoming_packet(2, true);
        generator.on_incoming_packet(5, true);
        let mut iter = generator.local_acks();
        assert_eq!(
            iter.next(),
            Some(Ack {
                first_acked_seqno: 1,
                last_acked_seqno: 2,
            })
        );
        // now let's generate a new iterator and make sure it returns the remaining ack
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[Ack {
                first_acked_seqno: 5,
                last_acked_seqno: 5,
            }]
        );
    }

    // test what happens when we get an incoming packet with seqno that's already "clocked out" of
    // our incoming packet tracker.
    #[test]
    fn compute_local_acks_ancient_incoming_packets() {
        let mut generator = LocalAckGenerator::new(3);
        generator.on_incoming_packet(7, true);
        // should do absolutely nothing, just making sure it doesn't panic or nothin'
        generator.on_incoming_packet(2, false);
        generator.on_incoming_packet(3, false);
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[Ack {
                first_acked_seqno: 7,
                last_acked_seqno: 7
            }]
        );
    }

    #[test]
    fn compute_local_acks_clocking_out() {
        let mut generator = LocalAckGenerator::new(3);
        // first, sanity check
        generator.on_incoming_packet(3, true);
        generator.on_incoming_packet(5, false);
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[Ack {
                first_acked_seqno: 3,
                last_acked_seqno: 3
            }]
        );
        generator.on_incoming_packet(13, true);
        generator.on_incoming_packet(16, false);
        assert_eq!(&generator_local_acks(&mut generator), &[]);
        // and make sure ack-eliciting packets do the same (though how could they not)
        generator.on_incoming_packet(23, true);
        generator.on_incoming_packet(26, true);
        assert_eq!(
            &generator_local_acks(&mut generator),
            &[Ack {
                first_acked_seqno: 26,
                last_acked_seqno: 26,
            }]
        );
    }

    /// Return a Reliability action which is different iff the id passed is different
    fn eg_ra(id: u64) -> ReliabilityAction {
        ReliabilityAction::ReliableMessage(ReliableMessage::PacketStatus(messages::PacketStatus {
            seqno: id,
            tx_rx_epoch_times: None,
        }))
    }

    macro_rules! ras {
        ($($id:expr),*) => {
            vec![$(eg_ra($id)),*]
        };
    }

    fn vec_collect<I>(iter: I) -> Vec<I::Item>
    where
        I: Iterator,
    {
        iter.collect()
    }

    fn on_outgoing_packet(
        handler: &mut RemoteAckHandler,
        ras: impl IntoIterator<Item = ReliabilityAction>,
    ) -> ReliabilityActionIterator<'_> {
        let mut builder = handler.outgoing_packet_builder();
        for ra in ras {
            builder.add_reliability_action(ra).unwrap();
        }
        builder.finalize()
    }

    // just put a few reliability actions in a handler, and then ack it and make sure the same ones come back out
    #[test]
    fn remote_ack_handler_single_ack() {
        let mut handler = RemoteAckHandler::new(1, 3);
        let nacked = on_outgoing_packet(&mut handler, ras!(0, 1, 3));
        assert!(vec_collect(nacked).is_empty());
        let acked = handler.on_remote_ack(0).unwrap();
        assert_eq!(ras!(0, 1, 3), vec_collect(acked));
    }

    // multiple acks, but still no nacks
    #[test]
    fn remote_ack_handler_several_acks() {
        let mut handler = RemoteAckHandler::new(8, 16);
        let nacked = on_outgoing_packet(&mut handler, ras!(1, 2));
        assert!(vec_collect(nacked).is_empty());
        let nacked = on_outgoing_packet(&mut handler, ras!(3));
        assert!(vec_collect(nacked).is_empty());
        let nacked = on_outgoing_packet(&mut handler, ras!());
        assert!(vec_collect(nacked).is_empty());

        let acked = handler.on_remote_ack(0).unwrap();
        assert_eq!(ras!(1, 2), vec_collect(acked));

        let nacked = on_outgoing_packet(&mut handler, ras!(4, 5, 6, 7));
        assert!(vec_collect(nacked).is_empty());

        let acked = handler.on_remote_ack(3).unwrap();
        assert_eq!(ras!(4, 5, 6, 7), vec_collect(acked));

        let acked = handler.on_remote_ack(2).unwrap();
        assert!(vec_collect(acked).is_empty());
    }

    // there's actually something to nack
    #[test]
    fn remote_ack_handler_nack() {
        let mut handler = RemoteAckHandler::new(2, 16);
        let nacked = on_outgoing_packet(&mut handler, ras!(1, 2));
        assert!(vec_collect(nacked).is_empty());
        let nacked = on_outgoing_packet(&mut handler, ras!(3));
        assert!(vec_collect(nacked).is_empty());
        let nacked = on_outgoing_packet(&mut handler, ras!(4, 5));
        assert_eq!(ras!(1, 2), vec_collect(nacked));
        // but if we ack the next one manually, it shouldn't get subsequently clocked out
        let acked = handler.on_remote_ack(1).unwrap();
        assert_eq!(ras!(3), vec_collect(acked));
        let nacked = on_outgoing_packet(&mut handler, ras!(6));
        assert!(vec_collect(nacked).is_empty());
        // just to make sure we're still operating normally, nack once more
        let nacked = on_outgoing_packet(&mut handler, ras!());
        assert_eq!(ras!(4, 5), vec_collect(nacked));
    }

    #[test]
    #[should_panic(expected = "out of space for reliability actions")]
    fn remote_ack_handler_max_reliability_actions() {
        let mut handler = RemoteAckHandler::new(4, 8);
        for i in 0..4 {
            let nacked = on_outgoing_packet(&mut handler, ras!(2 * i, 2 * i + 1));
            assert!(vec_collect(nacked).is_empty());
        }
        // boom!
        let _ = on_outgoing_packet(&mut handler, ras!(69));
    }

    // test that space in the reliability actions ring buffer is cleared up after RAs are read.
    #[test]
    fn remote_ack_handler_clears_out_reliability_actions() {
        let mut handler = RemoteAckHandler::new(4, 8);
        for i in 0..4 {
            let nacked = on_outgoing_packet(&mut handler, ras!(2 * i, 2 * i + 1));
            assert!(vec_collect(nacked).is_empty());
        }
        // we should be at max capacity now.
        // ack out of order for good measure
        let acked = handler.on_remote_ack(1).unwrap();
        assert_eq!(ras!(2, 3), vec_collect(acked));
        let acked = handler.on_remote_ack(0).unwrap();
        assert_eq!(ras!(0, 1), vec_collect(acked));

        let nacked = on_outgoing_packet(&mut handler, ras!(8, 9));
        assert!(vec_collect(nacked).is_empty());
        let nacked = on_outgoing_packet(&mut handler, ras!(10, 11));
        assert!(vec_collect(nacked).is_empty());

        // it's full again. Let's test if nack'ing frees up space. Now, you might think that just
        // sending another outgoing packet with 2 RAs would work here, since we clock 2 out and
        // clock 2 in. However, that's not true, since the 2 that were clocked out are going to
        // remain in the deque until we drop the iterator returned by the nack (a reference to them
        // has to be maintained somehow). So instead, let's clock in an empty packet, then 2 should
        // get clocked out. We can test that 2 got clocked out by then clocking 2 more in.
        let nacked = on_outgoing_packet(&mut handler, ras!());
        assert_eq!(ras!(4, 5), vec_collect(nacked));
        let nacked = on_outgoing_packet(&mut handler, ras!(69, 69));
        assert_eq!(ras!(6, 7), vec_collect(nacked));
        // TODO we may one day want a way to feedback into EstablishedConnection how many RA spots
        // are left, in that case this test can probably be improved.
    }
}
