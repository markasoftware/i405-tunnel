use std::{collections::VecDeque, net::SocketAddr, time::Duration};

use crate::{
    array_array::IpPacketBuffer,
    defragger::Defragger,
    deques::{ArrDeque, GlobalBitArrDeque},
    dtls,
    hardware::Hardware,
    jitter::Jitterator,
    messages::{self, Message, Serializable as _},
    queued_ip_packet::{FragmentResult, QueuedIpPacket},
    reliability::{
        LocalAckGenerator, ReliabilityAction, ReliabilityActionBuilder, ReliableMessage,
        RemoteAckHandler,
    },
    utils::{AbsoluteDirection, ip_to_i405_length},
    wire_config::WireConfig,
};

use anyhow::{Result, anyhow, bail};

// TODO this number shouldn't be quite so fixed. At high bitrates, it might be small enough to cause
// starvation. At low bitrates, it might cause a little bit of extra bufferbloat. We should probably
// make it based on buffer size instead, but last time I tried that actually somehow slowed things
// down.
const MAX_QUEUED_IP_PACKETS: usize = 3;
const MAX_AVERAGE_MESSAGES_PER_PACKET: usize = 8;
// TODO revisit this!!!
const RELIABLE_MESSAGE_RTX_QUEUE_LENGTH: usize = 1024;
// TODO also revisit this, should be long enough to queue all the incoming packets we get between outgoing packets.
const PACKET_STATUS_QUEUE_LENGTH: usize = 1024;

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

    reliable_message_rtx_queue: VecDeque<ReliableMessage>,

    packet_monitor: PacketMonitor,
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
        _reliability_builder: &mut ReliabilityActionBuilder<'_>, // no IP messages are ack-eliciting
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
        if self.queued_packets.len() < MAX_QUEUED_IP_PACKETS {
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
            i405_packet_length: ip_to_i405_length(config.wire.packet_length, config.peer),
            defragger: Defragger::new(),
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

            reliable_message_rtx_queue: VecDeque::with_capacity(RELIABLE_MESSAGE_RTX_QUEUE_LENGTH),

            packet_monitor: PacketMonitor::new(config.monitor_packets, local_ack_capacity),

            config,
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

        self.packet_monitor.top_of_outgoing_packet(
            hardware,
            &mut packet_builder,
            &mut reliability_builder,
            send_timestamp,
        );

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

        // add PacketStatus messages
        self.packet_monitor
            .body_of_outgoing_packet(&mut packet_builder, &mut reliability_builder);

        // Retransmit reliable messages from rtx queue (after acks, before general IP packets)
        while let Some(reliable_message) = self.reliable_message_rtx_queue.pop_front() {
            let message = Message::from(reliable_message.clone());
            let could_add = packet_builder.try_add_message(&message, &mut reliability_builder);
            if could_add {
                log::debug!("Retransmitting message {message:?}");
            } else {
                // No space left in packet, put the message back at the front of the queue
                self.reliable_message_rtx_queue.push_front(reliable_message);
                break;
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

        // Handle nacked reliability actions by adding them back to the rtx queue
        for nack_action in reliability_builder.finalize() {
            // just like in the ack case, I'd love to split this logic out into another function on
            // `self`, but then `self` would be mutably borrowed multiple times. Let's just nest it
            // for now. (Aside: I think the cool solution here would be )
            match nack_action {
                ReliabilityAction::ReliableMessage(reliable_message) => {
                    // add it back on to the reliable messages queue, respecting capacity limit
                    if self.reliable_message_rtx_queue.len() < RELIABLE_MESSAGE_RTX_QUEUE_LENGTH {
                        log::debug!("NACK, pushing {reliable_message:?} onto rtx queue");
                        self.reliable_message_rtx_queue.push_back(reliable_message);
                    } else {
                        // Queue is full, return an error
                        bail!(
                            "Reliable message RTX queue is full (capacity: {}), cannot add nacked message",
                            RELIABLE_MESSAGE_RTX_QUEUE_LENGTH
                        );
                    }
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
            dtls::DecryptResult::Err(err) => Err(err),
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
                    // It's very important that we instantly return here without trying to do the
                    // rest of the logic -- eg, monitor packets will fail later because it expects
                    // all established packets to have a tx epoch time, and we also look for seqnos.
                    // TODO add a test with monitor packets on and a handshake rtx?
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
                    self.packet_monitor
                        .on_incoming_packet_status(hardware, &packet_status)?;
                }
            }
        }
        // I at one point considered having a "packet header" that would contain the sequence number
        // in a fixed location to make inclusion of seqno more "safe". Chose not to implement until
        // we do FEC because those both require changes to the packet format.
        let incoming_seqno = incoming_seqno.ok_or(anyhow!(
            "No sequence number in established session packet -- protocol violation"
        ))?;

        self.local_ack_generator
            .on_incoming_packet(incoming_seqno, ack_elicited);

        self.packet_monitor
            .on_incoming_packet(hardware, incoming_seqno, tx_epoch_time)?;

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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) enum MonitorPackets {
    No,
    /// measure packet delays and drops, but do not send them to the hardware; instead, send
    /// PacketStatus messages to the other side with info about the drops/delays.
    Remote,
    /// measure packet delays and drops, including those read from PacketStatus messages, and
    /// immediately report to hardware
    Local,
}

#[derive(Debug)]
enum PacketMonitor {
    No,
    Yes {
        received_incoming_packets: GlobalBitArrDeque,
        // is set iff we should send packet statuses remotely
        queued_packet_status_messages: Option<ArrDeque<messages::PacketStatus>>,
    },
}

impl PacketMonitor {
    fn new(monitor_packets: MonitorPackets, local_ack_capacity: usize) -> PacketMonitor {
        match monitor_packets {
            MonitorPackets::No => PacketMonitor::No,
            MonitorPackets::Remote => PacketMonitor::Yes {
                received_incoming_packets: GlobalBitArrDeque::new(local_ack_capacity),
                queued_packet_status_messages: Some(ArrDeque::new(PACKET_STATUS_QUEUE_LENGTH)),
            },
            MonitorPackets::Local => PacketMonitor::Yes {
                received_incoming_packets: GlobalBitArrDeque::new(local_ack_capacity),
                queued_packet_status_messages: None,
            },
        }
    }

    /// Add the tx time to the top of outgoing packets. `send_timestamp` is the intended time the
    /// packet will be sent, not in epoch time. The tx epoch time will be based on this.
    fn top_of_outgoing_packet(
        &self,
        hardware: &impl Hardware,
        packet_builder: &mut messages::PacketBuilder,
        reliability_builder: &mut ReliabilityActionBuilder<'_>,
        send_timestamp: u64,
    ) {
        match self {
            PacketMonitor::No => (),
            _ => {
                let send_epoch_time = send_timestamp.saturating_sub(hardware.timestamp())
                    + hardware.epoch_timestamp();
                let could_add_tx_epoch_time = packet_builder.try_add_message(
                    &Message::TxEpochTime(messages::TxEpochTime {
                        timestamp: send_epoch_time,
                    }),
                    reliability_builder,
                );
                // we really should be adding this very close to the top of the packet, above acks and stuff.
                assert!(
                    could_add_tx_epoch_time,
                    "Wasn't able to add tx epoch time to packet"
                );
            }
        }
    }

    fn body_of_outgoing_packet(
        &mut self,
        packet_builder: &mut messages::PacketBuilder,
        reliability_builder: &mut ReliabilityActionBuilder<'_>,
    ) {
        if let PacketMonitor::Yes {
            received_incoming_packets: _,
            queued_packet_status_messages: Some(queued_packet_status_messages),
        } = self
        {
            'queue_loop: while queued_packet_status_messages.len() > 0 {
                // eww don't love this clone but oh well
                let msg = Message::PacketStatus(queued_packet_status_messages[0].clone());
                let could_add = packet_builder.try_add_message(&msg, reliability_builder);
                if could_add {
                    queued_packet_status_messages.pop();
                } else {
                    break 'queue_loop;
                }
            }
        }
    }

    fn on_incoming_packet(
        &mut self,
        hardware: &impl Hardware,
        seqno: u64,
        tx_epoch_time: Option<u64>,
    ) -> Result<()> {
        if let PacketMonitor::Yes {
            received_incoming_packets,
            queued_packet_status_messages,
        } = self
        {
            let rx_epoch_time = hardware.epoch_timestamp();
            let tx_epoch_time = tx_epoch_time.ok_or(anyhow!(
                "We are set up to monitor packets, but a packet was missing a tx time"
            ))?;
            let tx_rx_epoch_times = Some((tx_epoch_time, rx_epoch_time));
            match queued_packet_status_messages {
                Some(queued_packet_status_messages) => {
                    let popped_status =
                        queued_packet_status_messages.push(messages::PacketStatus {
                            seqno,
                            tx_rx_epoch_times,
                        });
                    // TODO not this
                    assert!(
                        popped_status.is_none(),
                        "Ran out of space for packet statuses"
                    );
                }
                // TODO do not hardcode direction
                None => hardware.register_packet_status(
                    AbsoluteDirection::S2C,
                    seqno,
                    tx_rx_epoch_times,
                ),
            }
            // mark any packets between the current tail and the new seqno as not having been
            // received yet, and also treat any un-received packets that are "clocked out" of
            // received_incoming_packets as part of this process as lost.
            for _ in received_incoming_packets.tail_index()..=seqno {
                let popped = received_incoming_packets.push(false);
                if let Some((lost_seqno, false)) = popped {
                    match queued_packet_status_messages {
                        Some(queued_packet_status_messages) => {
                            let popped_status =
                                queued_packet_status_messages.push(messages::PacketStatus {
                                    seqno: lost_seqno,
                                    tx_rx_epoch_times: None,
                                });
                            // TODO not this
                            assert!(
                                popped_status.is_none(),
                                "Ran out of space for packet statuses"
                            )
                        }
                        // TODO do not hardcode direction
                        None => hardware.register_packet_status(
                            AbsoluteDirection::S2C,
                            lost_seqno,
                            None,
                        ),
                    }
                }
            }
            // mark that this one isn't lost
            received_incoming_packets.set(seqno, true);
        }
        Ok(())
    }

    fn on_incoming_packet_status(
        &mut self,
        hardware: &impl Hardware,
        packet_status: &messages::PacketStatus,
    ) -> Result<()> {
        match self {
            PacketMonitor::Yes {
                received_incoming_packets: _,
                queued_packet_status_messages: None,
            } => {
                // TODO don't hardcode direction
                hardware.register_packet_status(
                    AbsoluteDirection::C2S,
                    packet_status.seqno,
                    packet_status.tx_rx_epoch_times,
                );
                Ok(())
            }
            _ => bail!(
                "Received a PacketStatus message but we aren't in the right packet monitoring mode"
            ),
        }
    }
}
