use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    array_array::IpPacketBuffer,
    constants::MAX_IP_PACKET_LENGTH,
    defragger::Defragger,
    deques::GlobalBitArrDeque,
    dtls,
    hardware::Hardware,
    jitter::Jitterator,
    messages::{self, Message, Serializable as _},
    queued_ip_packet::{FragmentResult, QueuedIpPacket},
    utils::ip_to_i405_length,
    wire_config::WireConfig,
};

use anyhow::{Result, anyhow, bail};

const MAX_QUEUED_IP_PACKETS: usize = 64;

#[derive(Debug)]
pub(crate) struct EstablishedConnection {
    session: dtls::EstablishedSession,
    config: Config,
    last_incoming_packet_timestamp: u64,
    next_outgoing_seqno: u64,
    jitterator: Jitterator,
    outgoing_connection: OutgoingConnection,
    /// which incoming packets we have already acked, or don't need to be acked (either because they
    /// are not ack-eliciting, or we have not received them).
    acked_incoming_packets: GlobalBitArrDeque,
    /// Which outgoing packets we have received an ack back from.
    acked_outgoing_packets: GlobalBitArrDeque,
    i405_packet_length: u16,
    defragger: Defragger,
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
        let outgoing_ack_capacity = std::cmp::max(
            3,
            outgoing_timeout.div_duration_f64(Duration::from_nanos(config.wire.packet_interval_min))
                as usize
                + 1,
        );
        let incoming_ack_capacity = std::cmp::max(
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
            // TODO the length of this should probably be chosen more intelligently; it should be at
            // least the number of incoming packets we receive for each outgoing packet we send
            // times a decent safety factor. May need to include reverse packet interval in the
            // handshake.
            acked_incoming_packets: GlobalBitArrDeque::new(incoming_ack_capacity),
            acked_outgoing_packets: GlobalBitArrDeque::new(outgoing_ack_capacity),
            // this is a tiny bit jank in the client case, because the server won't start sending us
            // packets until it receives our first post-handshake packet. If we have fast incoming
            // intervals but long roundtrip time, it's possible that quite a few incoming intervals
            // will elapse before we start receiving anything from the server. We can't just set
            // this to None though and wait for the first server packet, because the server could
            // theoretically crash even now!
            last_incoming_packet_timestamp: hardware.timestamp(),
            next_outgoing_seqno: 0,
            jitterator,
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
        // this is a substantial portion of the overall cost of building a new packet; it causes the
        // jitter test to go measurably faster when this is commented out (even in release mode,
        // though you have to increase the timespan of the jitter test to slow it down more)
        for ack in outgoing_acks(&mut self.acked_incoming_packets) {
            packet_builder.try_add_message(&Message::Ack(ack), &mut ack_elicited);
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

        debug_assert_eq!(self.acked_outgoing_packets.tail_index(), seqno);
        let popped_outgoing_ack = self.acked_outgoing_packets.push(!ack_elicited);
        if let Some((popped_seqno, false)) = popped_outgoing_ack {
            self.on_nack(popped_seqno);
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
        let mut send_system_timestamp = None;
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
                        if acked_seqno >= self.next_outgoing_seqno {
                            bail!("Received an ack of a seqno we haven't sent yet");
                        }
                        debug_assert_eq!(
                            self.next_outgoing_seqno,
                            self.acked_outgoing_packets.tail_index()
                        );
                        if self.acked_outgoing_packets.head_index() <= acked_seqno {
                            if self.acked_outgoing_packets[acked_seqno] {
                                // I'm not sure if there's any legitimate way for this to happen --
                                // does wolfssl automatically filter out DTLS retransmissions for
                                // us?
                                log::error!(
                                    "Got an ack for a packet that's already been acked, or didn't need to be acked."
                                );
                            } else {
                                self.on_ack(acked_seqno);
                            }
                            self.acked_outgoing_packets.set(acked_seqno, true);
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
                    if let Some(existing_timestamp) = send_system_timestamp {
                        bail!(
                            "Multiple send system timestamps in the same packet: {}, then {}",
                            existing_timestamp,
                            timestamp
                        );
                    }
                    send_system_timestamp = Some(timestamp);
                }
                Message::PacketStatus(_packet_status) => {
                    todo!("handle packet status")
                }
            }
        }
        // TODO I at one point considered having a "packet header" that would contain the sequence
        // number in a fixed location to make inclusion of seqno more "safe". Chose not to implement
        // until we do FEC because those both require changes to the packet format.
        let incoming_seqno = incoming_seqno.ok_or(anyhow!(
            "No sequence number in established session packet -- protocol violation"
        ))?;

        // update ack board
        for _ in self.acked_incoming_packets.tail_index()..=incoming_seqno {
            // we don't care about pushed-off acks; that just means we failed to ack it. The other
            // side will send the contents again if this is important. TODO privacy concerns if this
            // causes a packet drop equivalent?
            self.acked_incoming_packets.push(true);
        }
        debug_assert!(self.acked_incoming_packets.tail_index() > incoming_seqno);
        // mark that it needs an ack if necessary
        // TODO how can we unit-test this logic in the core tests? Ie, make we aren't needlessly
        // ack'ing packets that don't elicit acks.
        if incoming_seqno >= self.acked_incoming_packets.head_index() && ack_elicited {
            self.acked_incoming_packets.set(incoming_seqno, false);
        }

        Ok(())
    }

    /// Called when our packet with the given seqno gets acknowledged
    fn on_ack(&mut self, seqno: u64) {
        todo!();
    }

    /// Called when our packet with the given seqno is assumed to be lost by the other side
    fn on_nack(&mut self, seqno: u64) {
        todo!();
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

    // this function isn't strictly necessary, since the ack-eliciting variant of the function also
    // appends to `locally_acked_packets` as necessary. But imagine that we receive millions of
    // non-ack-eliciting packets, then an ack-eliciting packet -- it will rotate the queue millions
    // of times, causing a huge latency burst. So we want to keep rotating it continuously.
    fn on_non_ack_eliciting_incoming_packet(&mut self, seqno: u64) {
        for _ in self.locally_acked_packets.tail_index()..=seqno {
            self.locally_acked_packets.push(true);
        }
    }

    fn on_ack_eliciting_incoming_packet(&mut self, seqno: u64) {
        if seqno < self.locally_acked_packets.head_index() {
            return;
        }
        // Consider all packets received
        for _ in self.locally_acked_packets.tail_index()..=seqno {
            self.locally_acked_packets.push(true);
        }
        self.locally_acked_packets.set(seqno, false);
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
}

impl RemoteAckHandler {
    /// An outgoing packet is considered lost if no acks for it are received after
    /// `outgoing_packets_capacity` many more outgoing packets have been sent.
    fn new(outgoing_packets_capacity: usize, reliability_actions_capacity: usize) -> Self {
        Self {
            outgoing_packet_ack_statuses: GlobalArrDeque::new(outgoing_packets_capacity),
            reliability_actions: GlobalArrDeque::new(reliability_actions_capacity),
        }
    }

    /// Be sure to call this even if there were no reliability actions in an outgoing packet, to
    /// ensure that old outgoing packets get "clocked out" and considered lost. Returns NACK'd
    /// reliability actions.
    fn on_outgoing_packet(
        &mut self,
        reliability_actions: impl IntoIterator<Item = ReliabilityAction>,
    ) -> ReliabilityActionIterator<'_> {
        let head_reliability_action_index = self.reliability_actions.tail_index();
        for reliability_action in reliability_actions {
            // TODO handle this case more gracefully. If we put a limit on the reliability actions
            // per message, we may be able to guarantee this never happens.
            let popped_action = self.reliability_actions.push(Some(reliability_action));
            assert!(
                popped_action.is_none(),
                "Ran out of space for reliability actions!"
            );
        }
        let tail_reliability_action_index = self.reliability_actions.tail_index();
        let popped_ack_status = self
            .outgoing_packet_ack_statuses
            .push(RemoteAckStatus::Unacked {
                head_reliability_action_index,
                tail_reliability_action_index,
            })
            .map(|(_, b)| b);
        if let Some(RemoteAckStatus::Unacked { head_reliability_action_index, tail_reliability_action_index }) = popped_ack_status {
            ReliabilityActionIterator::new(&mut self.reliability_actions, head_reliability_action_index, tail_reliability_action_index)
        } else {  // either packet had already been acked, or we just started up so nothing got clocked out yet.
            ReliabilityActionIterator::new_empty(&mut self.reliability_actions)
        }
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
                Ok(ReliabilityActionIterator::new_empty(&mut self.reliability_actions))
            }
            RemoteAckStatus::Unacked {
                head_reliability_action_index,
                tail_reliability_action_index,
            } => {
                Ok(ReliabilityActionIterator::new(
                    &mut self.reliability_actions,
                    head_reliability_action_index,
                    tail_reliability_action_index,
                ))
            }
        }
    }
}

struct ReliabilityActionIterator<'a> {
    reliability_actions: &'a mut GlobalArrDeque<Option<ReliabilityAction>>,
    head_index: u64,
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
            head_index,
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
        while self.reliability_actions.len() > 0 && self.reliability_actions[0].is_none() {
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

    fn assert_outgoing_acks(pre_rotation: u64, incoming_acks: &[u8], expected_acks: &[Ack]) {
        let mut deque = GlobalBitArrDeque::new(incoming_acks.len());
        for _ in 0..pre_rotation {
            deque.push(true);
        }
        for incoming_ack in incoming_acks {
            deque.push(if *incoming_ack > 0 { true } else { false });
        }
        assert_eq!(
            outgoing_acks(&mut deque).collect::<Vec<Ack>>(),
            expected_acks
        );
        for i in pre_rotation..pre_rotation + u64::try_from(incoming_acks.len()).unwrap() {
            assert_eq!(deque[i], true);
        }
    }

    #[test]
    fn compute_outgoing_acks() {
        assert_outgoing_acks(
            0,
            &[1, 0, 0, 1, 1, 0, 1],
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
        assert_outgoing_acks(
            2,
            &[1, 0, 0, 1, 1, 0, 1],
            &[
                Ack {
                    first_acked_seqno: 3,
                    last_acked_seqno: 4,
                },
                Ack {
                    first_acked_seqno: 7,
                    last_acked_seqno: 7,
                },
            ],
        );
        assert_outgoing_acks(
            0,
            &[0, 0, 0],
            &[Ack {
                first_acked_seqno: 0,
                last_acked_seqno: 2,
            }],
        );
        assert_outgoing_acks(
            0,
            &[0, 1, 0],
            &[
                Ack {
                    first_acked_seqno: 0,
                    last_acked_seqno: 0,
                },
                Ack {
                    first_acked_seqno: 2,
                    last_acked_seqno: 2,
                },
            ],
        )
    }

    #[test]
    fn compute_outgoing_acks_partial() {
        let mut deque = GlobalBitArrDeque::new(3);
        deque.push(false);
        deque.push(true);
        deque.push(false);
        let mut iter = outgoing_acks(&mut deque);
        iter.next();
        assert_eq!(deque[0], true);
        assert_eq!(deque[1], true);
        assert_eq!(deque[2], false);
    }
}
