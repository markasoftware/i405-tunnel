use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    defragger::Defragger,
    deques::{GlobalArrDeque, GlobalBitArrDeque},
    dtls,
    hardware::Hardware,
    jitter::Jitterator,
    messages::{self, Message, Serializable as _},
    queued_ip_packet::{FragmentResult, QueuedIpPacket},
    utils::{AbsoluteDirection, ip_to_i405_length},
    wire_config::WireConfig,
};

use anyhow::{Result, anyhow, bail};

const MAX_QUEUED_IP_PACKETS: usize = 64;
const MAX_AVERAGE_MESSAGES_PER_PACKET: usize = 8;
// TODO revisit this, and maybe it should scale inversely to the outgoing packet interval?
const RELIABLE_MESSAGE_QUEUE_LENGTH: usize = 128;

#[derive(Debug)]
pub(crate) struct EstablishedConnection {
    session: dtls::EstablishedSession,
    config: Config,
    last_incoming_packet_timestamp: u64,
    next_outgoing_seqno: u64,
    jitterator: Jitterator,
    outgoing_connection: OutgoingConnection,
    i405_packet_length: u16,
    defragger: Defragger,

    local_ack_generator: LocalAckGenerator,
    remote_ack_handler: RemoteAckHandler,

    /// Either untransmitted packets or retransmissions
    reliable_message_queue: VecDeque<ReliableMessage>,

    // For packet monitoring only: Set to 1 when we receive a packet with given seqno.
    incoming_packets: GlobalBitArrDeque,
}

// TODO move this somewhere else probably. In fact, if we ever have reliable datagrams that are
// substantially different in size, we may want to store the binary messages in the queues above and
// have them be byte-based, rather than message-based.
#[derive(Debug, PartialEq, Eq, Clone)]
enum ReliableMessage {
    // I'm not sure how I feel about including the literal PacketStatus message itself in here :|
    PacketStatus(messages::PacketStatus),
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum ReliabilityAction {
    ReliableMessage(ReliableMessage),
}

// OutgoingConnection is sort of historical cruft, there was once a grand plan for a "scheduled"
// mode where outbound packets would be read off the TUN at predetermined times also, in order to
// hide even from userspace applications the details of the tunnel, and there would be both
// scheduled and unscheduled OutgoingConnection implementations. In a world with Acks, it's even
// more confusing exactly what the role of the OutgoingConnection should be.
/// The OutgoingConnection is responsible for reading outgoing packets.
#[derive(Debug)]
struct OutgoingConnection {
    queued_packets: VecDeque<QueuedIpPacket>,
    fragmentation_id: u16,
}

impl OutgoingConnection {
    fn new(hardware: &impl Hardware) -> Self {
        // unless we have a queued packet (which we don't yet), we want the hardware to always know
        // we are ready to read an outgoing packet.
        hardware.read_outgoing_packet();
        Self {
            queued_packets: VecDeque::with_capacity(MAX_QUEUED_IP_PACKETS),
            fragmentation_id: 0,
        }
    }

    /// When a new send outgoing packet is created, call this so that any internal queued packets
    /// can be flushed into the new buffer.
    fn try_to_dequeue(
        &mut self,
        hardware: &impl Hardware,
        packet_builder: &mut messages::PacketBuilder,
        _ack_elicited: &mut bool, // no IP messages are ack-eliciting
    ) {
        let write_cursor = packet_builder.write_cursor();
        'dequeue_loop: while let Some(old_queued_packet) = self.queued_packets.pop_front() {
            let bytes_left = write_cursor.num_bytes_left();
            self.fragmentation_id = self.fragmentation_id.wrapping_add(1);
            let fragment = old_queued_packet.fragment(bytes_left, self.fragmentation_id);
            match fragment {
                FragmentResult::Done(msg) => msg.serialize(write_cursor),
                FragmentResult::Partial(msg, new_queued_packet) => {
                    msg.serialize(write_cursor);
                    // we just popped off the queued packets, so won't go over capacity
                    self.queued_packets.push_front(new_queued_packet);
                    break 'dequeue_loop;
                }
                FragmentResult::MaxLengthTooShort(new_queued_packet) => {
                    self.queued_packets.push_front(new_queued_packet);
                    break 'dequeue_loop;
                }
            }
        }
        self.maybe_request_outgoing_read(hardware);
    }

    fn on_read_outgoing_packet<H: Hardware>(
        &mut self,
        hardware: &H,
        packet: &[u8],
        _recv_timestamp: u64,
    ) {
        assert!(
            self.queued_packets.len() < MAX_QUEUED_IP_PACKETS,
            "We never request to read outgoing packets when the queue of IP packets is already full"
        );
        self.queued_packets.push_back(QueuedIpPacket::new(packet));
        self.maybe_request_outgoing_read(hardware);
    }

    /// If there is room left for another queued packet, queue one!
    fn maybe_request_outgoing_read<H: Hardware>(&mut self, hardware: &H) {
        let mut queued_bytes = 0;
        'summation_loop: for packet in self.queued_packets.iter() {
            let len = packet.len();
            if len == 0 {
                break 'summation_loop;
            }
            queued_bytes += len;
        }
        if queued_bytes < MAX_IP_PACKET_LENGTH {
            hardware.read_outgoing_packet();
        }
    }
}

impl EstablishedConnection {
    pub(crate) fn new(
        hardware: &impl Hardware,
        session: dtls::EstablishedSession,
        config: Config,
    ) -> Result<Self> {
        let mut jitterator = config.wire.jitterator();
        hardware.clear_event_listeners()?;
        hardware.socket_connect(&config.peer)?;
        hardware.set_timer(
            hardware.timestamp() + jitterator.next_interval() - config.wire.packet_finalize_delta,
        );
        // TODO make configurable. How long after sending a packet we will assume it to be dropped
        // if we haven't received an ack (and it's ack-eliciting)
        let outgoing_timeout = Duration::from_secs(1);
        let remote_ack_capacity = std::cmp::max(
            3,
            outgoing_timeout.div_duration_f64(Duration::from_nanos(config.wire.packet_interval_min))
                as usize
                + 1,
        );
        let local_ack_capacity = std::cmp::max(
            3,
            usize::try_from(
                2 * config.wire.packet_interval_max / config.reverse_packet_interval_min,
            )
            .unwrap(),
        );
        Ok(Self {
            session,
            outgoing_connection: OutgoingConnection::new(hardware),
            i405_packet_length: ip_to_i405_length(config.wire.packet_length, config.peer).into(),
            defragger: Defragger::new(),
            config,
            // this is a tiny bit jank in the client case, because the server won't start sending us
            // packets until it receives our first post-handshake packet. If we have fast incoming
            // intervals but long roundtrip time, it's possible that quite a few incoming intervals
            // will elapse before we start receiving anything from the server. We can't just set
            // this to None though and wait for the first server packet, because the server could
            // theoretically crash even now!
            last_incoming_packet_timestamp: hardware.timestamp(),
            next_outgoing_seqno: 0,
            jitterator,

            local_ack_generator: LocalAckGenerator::new(local_ack_capacity),
            remote_ack_handler: RemoteAckHandler::new(
                remote_ack_capacity,
                remote_ack_capacity * MAX_AVERAGE_MESSAGES_PER_PACKET,
            ),

            reliable_message_queue: VecDeque::with_capacity(RELIABLE_MESSAGE_QUEUE_LENGTH),

            incoming_packets: GlobalBitArrDeque::new(local_ack_capacity),
        })
    }

    pub(crate) fn peer(&self) -> std::net::SocketAddr {
        self.config.peer
    }

    pub(crate) fn on_timer(
        &mut self,
        hardware: &impl Hardware,
        timer_timestamp: u64,
    ) -> Result<IsConnectionOpen> {
        // timer means that it's about time to send a packet -- let's finalize the packet and send
        // it to the hardware!
        let send_timestamp = timer_timestamp + self.config.wire.packet_finalize_delta;
        let seqno = self.next_outgoing_seqno;
        self.next_outgoing_seqno += 1;

        let mut ack_elicited = false;
        let mut packet_builder = messages::PacketBuilder::new(self.i405_packet_length as usize);
        let mut reliability_builder = self.remote_ack_handler.outgoing_packet_builder();

        let could_add_seqno = packet_builder.try_add_message(
            &Message::SequenceNumber(messages::SequenceNumber { seqno }),
            &mut ack_elicited,
        );
        assert!(
            could_add_seqno,
            "Wasn't able to add seqno to packet (it's smaller than handshake, so this shouldn't be possible)"
        );

        if self.config.monitor_packets != MonitorPackets::No {
            let timestamp = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            )
            .unwrap();
            let could_add_tx_epoch_time = packet_builder.try_add_message(
                &Message::TxEpochTime(messages::TxEpochTime { timestamp }),
                &mut ack_elicited,
            );
            assert!(
                could_add_tx_epoch_time,
                "Wasn't able to add tx epoch time to packet"
            );
        }

        // TODO I'm still a little worried that even when only 1 or 2 acks needs to be sent that
        // computing the local acks is a substantial portion of the overall cost of building a new
        // packet; it causes the jitter test to go measurably faster when this is commented out
        // (even in release mode, though you have to increase the timespan of the jitter test to
        // slow it down more)

        // HACK: Every time the local_acks() iterator returns a new ack, it removes that ack from
        // the generator. So we don't want to step through it until we're sure we have space to
        // serialize the ack. So we have a dummy ack and make sure there's space for that each time.
        // This would break for example if the acks became variable size (let's hope not!)
        let dummy_ack = Message::Ack(messages::Ack {
            first_acked_seqno: 0,
            last_acked_seqno: 0,
        });
        let mut local_ack_iter = self.local_ack_generator.local_acks();
        'local_ack_loop: while packet_builder.can_add_message(&dummy_ack) {
            // it would be natural to have `... && let Some(local_ack) = ...` in the while
            // condition, but that's not stable Rust yet.
            if let Some(local_ack) = local_ack_iter.next() {
                packet_builder.try_add_message(&Message::Ack(local_ack), &mut ack_elicited);
            } else {
                break 'local_ack_loop;
            }
        }

        self.outgoing_connection
            .try_to_dequeue(hardware, &mut packet_builder, &mut ack_elicited);

        let outgoing_cleartext_packet = packet_builder.into_inner();
        let outgoing_packet = self.session.encrypt_datagram(&outgoing_cleartext_packet)?;
        hardware.send_outgoing_packet(
            outgoing_packet.as_ref(),
            self.config.peer,
            Some(send_timestamp),
        )?;

        // TODO pass in the reliability actions here!
        for nack_action in reliability_builder.finalize() {
            // just like in the ack case, I'd love to split this logic out into another function on
            // `self`, but then `self` would be mutably borrowed multiple times. Let's just nest it
            // for now. (Aside: I think the cool solution here would be )
        }

        // this is mainly to make sure that if we ever change the semantics of send_outgoing_packet,
        // we don't forget to update here:
        // TODO enable this assertion, or ensure our code does not rely on send_outgoing_packet blocking until the designated send time
        // assert!(
        //     hardware.timestamp() >= send_timestamp,
        //     "hardware.send_outgoing_packet returned too early"
        // );
        let next_interval = self.jitterator.next_interval();
        hardware.register_interval(next_interval);
        hardware.set_timer(send_timestamp + next_interval - self.config.wire.packet_finalize_delta);

        // check if the incoming connection timed out
        if hardware.timestamp() > self.last_incoming_packet_timestamp + self.config.wire.timeout {
            return Ok(IsConnectionOpen::TimedOut);
        }

        Ok(IsConnectionOpen::Yes)
    }

    pub(crate) fn on_read_outgoing_packet<H: Hardware>(
        &mut self,
        hardware: &H,
        packet: &[u8],
        recv_timestamp: u64,
    ) {
        self.outgoing_connection
            .on_read_outgoing_packet(hardware, packet, recv_timestamp);
    }

    /// Returns an error if something unexpected happened, vs Ok(IsConnectionOpen::No) means the
    /// other side terminated the connection normally in this packet.
    pub(crate) fn on_read_incoming_packet<H: Hardware>(
        &mut self,
        hardware: &H,
        packet: &[u8],
    ) -> Result<IsConnectionOpen> {
        match self.session.decrypt_datagram(packet) {
            dtls::DecryptResult::Decrypted(cleartext_packet) => {
                // notice how we only update the last_incoming_packet_timestamp on a successful
                // decryption. Otherwise, eg if the client restarts unexpectedly, it might keep
                // attempting a handshake so we won't time out.
                self.last_incoming_packet_timestamp = hardware.timestamp();
                self.on_read_incoming_cleartext_packet(hardware, &cleartext_packet)?;
                Ok(IsConnectionOpen::Yes)
            }
            dtls::DecryptResult::SendThese(send_these) => {
                for packet in send_these {
                    hardware.send_outgoing_packet(&packet, self.config.peer, None)?;
                }
                Ok(IsConnectionOpen::Yes)
            }
            dtls::DecryptResult::Terminated => Ok(IsConnectionOpen::TerminatedNormally),
            dtls::DecryptResult::Err(err) => Err(err.into()),
        }
    }

    pub(crate) fn on_read_incoming_cleartext_packet<H: Hardware>(
        &mut self,
        hardware: &H,
        packet: &[u8],
    ) -> Result<()> {
        let mut reader = messages::PacketReader::new(packet);
        let mut incoming_seqno = None;
        let mut tx_epoch_time = None;
        let mut ack_elicited = false;
        while let Some(msg) = reader.try_read_message(&mut ack_elicited)? {
            match msg {
                Message::ClientToServerHandshake(_) => {
                    log::warn!(
                        "Received ClientToServerHandshake during established session -- retransmission?"
                    );
                    return Ok(());
                }
                Message::ServerToClientHandshake(_) => {
                    log::warn!(
                        "Received ServerToClientHandshake during established session -- retransmission?"
                    );
                    return Ok(());
                }
                Message::IpPacket(ip_packet) => {
                    if let Some(defragged_packet) = self.defragger.handle_ip_packet(&ip_packet) {
                        hardware.send_incoming_packet(&defragged_packet)?;
                    }
                }
                Message::IpPacketFragment(ip_packet_fragment) => {
                    if let Some(defragged_packet) = self
                        .defragger
                        .handle_ip_packet_fragment(&ip_packet_fragment)
                    {
                        hardware.send_incoming_packet(&defragged_packet)?;
                    }
                }
                Message::Ack(ack) => {
                    for acked_seqno in ack.first_acked_seqno..=ack.last_acked_seqno {
                        // TODO handle ack actions
                        let ack_action_iter = self.remote_ack_handler.on_remote_ack(acked_seqno)?;
                        for ack_action in ack_action_iter {
                            // it would be nice to split this out into another function, but there's
                            // issues because `self` is mutably borrowed here by the iterator. While
                            // the logic is simple, let's just tank the deep nesting.
                            match ack_action {
                                ReliabilityAction::ReliableMessage(_) => (),
                            }
                        }
                    }
                }
                Message::SequenceNumber(messages::SequenceNumber { seqno }) => {
                    if let Some(existing_incoming_seqno) = incoming_seqno {
                        bail!(
                            "Multiple sequence numbers in the same packet: {}, then {}",
                            existing_incoming_seqno,
                            seqno
                        );
                    }
                    incoming_seqno = Some(seqno);
                }
                Message::TxEpochTime(messages::TxEpochTime { timestamp }) => {
                    if let Some(existing_tx_epoch_time) = tx_epoch_time {
                        bail!(
                            "Multiple send system timestamps in the same packet: {}, then {}",
                            existing_tx_epoch_time,
                            timestamp
                        );
                    }
                    tx_epoch_time = Some(timestamp);
                }
                Message::PacketStatus(packet_status) => {
                    assert!(
                        self.config.monitor_packets == MonitorPackets::Local,
                        "Unexpected PacketStatus message since we aren't monitoring packets (or aren't the client)"
                    );
                    // TODO don't hardcode absolute directions
                    hardware.register_packet_status(
                        AbsoluteDirection::C2S,
                        packet_status.seqno,
                        packet_status.tx_rx_epoch_times,
                    );
                }
            }
        }
        // TODO I at one point considered having a "packet header" that would contain the sequence
        // number in a fixed location to make inclusion of seqno more "safe". Chose not to implement
        // until we do FEC because those both require changes to the packet format.
        let incoming_seqno = incoming_seqno.ok_or(anyhow!(
            "No sequence number in established session packet -- protocol violation"
        ))?;

        self.local_ack_generator
            .on_incoming_packet(incoming_seqno, ack_elicited);

        Ok(())
    }

    // When I name this just `on_terminate`, there's a conflict with the name of the same method
    // defined on EstablishedConnection as part of the connection state traits. This is likely a bug
    // with the declarative_enum_dispatch crate. Not sure why it doesn't affect the other methods.
    pub(crate) fn on_terminate_inner(self) -> Result<Vec<IpPacketBuffer>> {
        self.session.terminate()
    }
}

#[must_use]
pub(crate) enum IsConnectionOpen {
    Yes,
    TimedOut,
    TerminatedNormally,
}

/// Keeps track of which ack-eliciting remote packets need to be acked, and can generate the correct
/// sequence of acks to acknowledge all of them.
#[derive(Debug)]
struct LocalAckGenerator {
    locally_acked_packets: GlobalBitArrDeque,
}

impl LocalAckGenerator {
    /// `capacity` is the maximum age (measured in number of incoming packets) between the latest
    /// received incoming packet and the earliest incoming packet we will attempt to send an ack for
    /// if received later.
    fn new(capacity: usize) -> Self {
        Self {
            locally_acked_packets: GlobalBitArrDeque::new(capacity),
        }
    }

    // it's not strictly necessary to call this function for non-ack-eliciting packets, since the
    // ack-eliciting variant of the function appends to `locally_acked_packets` as necessary. But
    // imagine that we receive millions of non-ack-eliciting packets, then an ack-eliciting packet
    // -- it will rotate the queue millions of times. To keep performance more consistent, just call
    // it on every incoming packet.
    fn on_incoming_packet(&mut self, seqno: u64, ack_eliciting: bool) {
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

    fn local_acks(&mut self) -> LocalAckIterator<'_> {
        LocalAckIterator {
            seqno: self.locally_acked_packets.head_index(),
            locally_acked_packets: &mut self.locally_acked_packets,
        }
    }
}

/// Iterator of acks we need to send
struct LocalAckIterator<'a> {
    locally_acked_packets: &'a mut GlobalBitArrDeque,
    seqno: u64,
}

impl<'a> Iterator for LocalAckIterator<'a> {
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
struct RemoteAckHandler {
    outgoing_packet_ack_statuses: GlobalArrDeque<RemoteAckStatus>,
    reliability_actions: GlobalArrDeque<Option<ReliabilityAction>>,
    // if there's currently a builder associated with this handler, here's its head index.
    current_builder_head_index: Option<u64>,
}

impl RemoteAckHandler {
    /// An outgoing packet is considered lost if no acks for it are received after
    /// `outgoing_packets_capacity` many more outgoing packets have been sent.
    fn new(outgoing_packets_capacity: usize, reliability_actions_capacity: usize) -> Self {
        Self {
            outgoing_packet_ack_statuses: GlobalArrDeque::new(outgoing_packets_capacity),
            reliability_actions: GlobalArrDeque::new(reliability_actions_capacity),
            current_builder_head_index: None,
        }
    }

    fn outgoing_packet_builder(&mut self) -> OutgoingPacketReliabilityActionBuilder<'_> {
        OutgoingPacketReliabilityActionBuilder::new(self)
    }

    /// Returns ACK'd reliability actions.
    fn on_remote_ack(&mut self, acked_seqno: u64) -> Result<ReliabilityActionIterator<'_>> {
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

struct OutgoingPacketReliabilityActionBuilder<'a> {
    ack_handler: &'a mut RemoteAckHandler,
}

// this impl is tightly coupled with that of the RemoteAckHandler
impl<'a> OutgoingPacketReliabilityActionBuilder<'a> {
    fn new(ack_handler: &'a mut RemoteAckHandler) -> Self {
        assert!(
            ack_handler.current_builder_head_index.is_none(),
            "Cannot create a builder before finalize()ing the previous one"
        );
        ack_handler.current_builder_head_index = Some(ack_handler.reliability_actions.tail_index());
        Self { ack_handler }
    }

    fn add_reliability_action(&mut self, ra: ReliabilityAction) {
        let popped_ra = self.ack_handler.reliability_actions.push(Some(ra));
        // TODO handle more gracefully.
        assert!(
            popped_ra.is_none(),
            "Ran out of space for reliability actions"
        );
    }

    // When all reliability actions have been added, call this to add the outgoing packet to the
    // list of those we're keeping track of. Returns an iterator over all RAs that got "clocked out"
    // by the new packed and are considered NACK'd.
    fn finalize(self) -> ReliabilityActionIterator<'a> {
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
struct ReliabilityActionIterator<'a> {
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

impl<'a> Iterator for ReliabilityActionIterator<'a> {
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

// this logic could also be put in the RemoteAckHandler
impl<'a> Drop for ReliabilityActionIterator<'a> {
    fn drop(&mut self) {
        // rotate the actions array as far as we can to free up space.
        while self.reliability_actions.len() > 0
            && self.reliability_actions[self.reliability_actions.head_index()].is_none()
        {
            self.reliability_actions.pop();
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

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) wire: WireConfig,
    /// The packet_interval_max from the complementary WireConfig, used to set appropriate ack
    /// timeout.
    pub(crate) reverse_packet_interval_min: u64,
    pub(crate) peer: SocketAddr,
    pub(crate) monitor_packets: MonitorPackets,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MonitorPackets {
    No,
    /// measure packet delays and drops, but do not send them to the hardware; instead, send
    /// PacketStatus messages to the other side with info about the drops/delays.
    Remote,
    /// measure packet delays and drops, including those read from PacketStatus messages, and
    /// immediately report to hardware
    Local,
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
            builder.add_reliability_action(ra);
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
