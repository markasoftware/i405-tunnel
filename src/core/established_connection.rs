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
    reliability::{
        LocalAckGenerator, OutgoingPacketReliabilityActionBuilder, ReliabilityAction,
        ReliableMessage, RemoteAckHandler,
    },
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
        _reliability_builder: &mut OutgoingPacketReliabilityActionBuilder<'_>, // no IP messages are ack-eliciting
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

        let mut packet_builder = messages::PacketBuilder::new(self.i405_packet_length as usize);
        let mut reliability_builder = self.remote_ack_handler.outgoing_packet_builder();

        let could_add_seqno = packet_builder.try_add_message(
            &Message::SequenceNumber(messages::SequenceNumber { seqno }),
            &mut reliability_builder,
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
                &mut reliability_builder,
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
                packet_builder.try_add_message(&Message::Ack(local_ack), &mut reliability_builder);
            } else {
                break 'local_ack_loop;
            }
        }

        self.outgoing_connection.try_to_dequeue(
            hardware,
            &mut packet_builder,
            &mut reliability_builder,
        );

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
            match nack_action {
                ReliabilityAction::ReliableMessage(_reliable_message) => {
                    // add it back on to the reliable messages queue
                    todo!();
                }
            }
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
