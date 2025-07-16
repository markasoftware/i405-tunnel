use crate::{
    array_array::IpPacketBuffer,
    defragger::Defragger,
    dtls,
    hardware::Hardware,
    jitter::Jitterator,
    messages::{self, Message, Serializable as _},
    queued_ip_packet::{FragmentResult, QueuedIpPacket},
    utils::ip_to_i405_length,
    wire_config::WireConfig,
};

use anyhow::Result;

#[derive(Debug)]
pub(crate) struct EstablishedConnection {
    session: dtls::EstablishedSession,
    peer: std::net::SocketAddr,
    wire_config: WireConfig,
    last_incoming_packet_timestamp: u64,
    jitterator: Jitterator,
    outgoing_connection: OutgoingConnection,
    partial_outgoing_packet: messages::WriteCursor<IpPacketBuffer>,
    defragger: Defragger,
}

// OutgoingConnection is sort of historical cruft, there was once a grand plan for a "scheduled"
// mode where outbound packets would be read off the TUN at predetermined times also, in order to
// hide even from userspace applications the details of the tunnel, and there would be both
// scheduled and unscheduled OutgoingConnection implementations.
/// The OutgoingConnection is responsible for reading outgoing packets.
#[derive(Debug)]
struct OutgoingConnection {
    queued_packet: Box<Option<QueuedIpPacket>>,
    fragmentation_id: u16,
}

impl OutgoingConnection {
    fn new(hardware: &impl Hardware) -> Self {
        // unless we have a queued packet (which we don't yet), we want the hardware to always know
        // we are ready to read an outgoing packet.
        hardware.read_outgoing_packet();
        Self {
            queued_packet: Box::new(None),
            fragmentation_id: 0,
        }
    }

    /// When a new send outgoing packet is created, call this so that any internal queued packets
    /// can be flushed into the new buffer.
    fn try_to_dequeue(
        &mut self,
        hardware: &impl Hardware,
        write_cursor: &mut messages::WriteCursor<IpPacketBuffer>,
    ) {
        // this indirection is me being afraid that we're going to accidentally reallocate
        // the box if we try to `take` the `queued_packet` directly (it might try to `take`
        // the `Box` and then `expect` will still work due to deref coercion?).
        let queued_packet_mut: &mut Option<QueuedIpPacket> = &mut self.queued_packet;
        if let Some(old_queued_packet) = std::mem::take(queued_packet_mut) {
            let bytes_left = write_cursor.num_bytes_left();
            self.fragmentation_id = self.fragmentation_id.wrapping_add(1);
            let fragment = old_queued_packet.fragment(bytes_left, self.fragmentation_id);
            match fragment {
                FragmentResult::Done(msg) => {
                    msg.serialize(write_cursor);
                    // queue is empty, let's ask for another packet!
                    hardware.read_outgoing_packet();
                }
                FragmentResult::Partial(msg, new_queued_packet) => {
                    msg.serialize(write_cursor);
                    *queued_packet_mut = Some(new_queued_packet);
                }
                FragmentResult::MaxLengthTooShort(new_queued_packet) => {
                    *queued_packet_mut = Some(new_queued_packet);
                }
            }
        }
    }

    fn on_read_outgoing_packet<H: Hardware>(
        &mut self,
        hardware: &H,
        write_cursor: &mut messages::WriteCursor<IpPacketBuffer>,
        packet: &[u8],
        _recv_timestamp: u64,
    ) {
        // strategy: queue the packet, then dequeue it!
        assert!(
            self.queued_packet.is_none(),
            "We never request to read an outgoing packet while we have a queued packet"
        );
        *self.queued_packet = Some(QueuedIpPacket::new(packet));
        self.try_to_dequeue(hardware, write_cursor);
    }
}

impl EstablishedConnection {
    pub(crate) fn new(
        hardware: &impl Hardware,
        session: dtls::EstablishedSession,
        peer: std::net::SocketAddr,
        outgoing_wire_config: WireConfig,
    ) -> Result<Self> {
        let mut jitterator = outgoing_wire_config.jitterator();
        hardware.clear_event_listeners()?;
        hardware.socket_connect(&peer)?;
        hardware.set_timer(
            hardware.timestamp() + jitterator.next_interval()
                - outgoing_wire_config.packet_finalize_delta,
        );
        Ok(Self {
            session,
            peer,
            outgoing_connection: OutgoingConnection::new(hardware),
            partial_outgoing_packet: messages::WriteCursor::new(IpPacketBuffer::new_empty(
                ip_to_i405_length(outgoing_wire_config.packet_length, peer).into(),
            )),
            defragger: Defragger::new(),
            wire_config: outgoing_wire_config,
            // this is a tiny bit jank in the client case, because the server won't start sending us
            // packets until it receives our first post-handshake packet. If we have fast incoming
            // intervals but long roundtrip time, it's possible that quite a few incoming intervals
            // will elapse before we start receiving anything from the server. We can't just set
            // this to None though and wait for the first server packet, because the server could
            // theoretically crash even now!
            last_incoming_packet_timestamp: hardware.timestamp(),
            jitterator,
        })
    }

    pub(crate) fn peer(&self) -> std::net::SocketAddr {
        self.peer
    }

    pub(crate) fn on_timer(
        &mut self,
        hardware: &impl Hardware,
        timer_timestamp: u64,
    ) -> Result<IsConnectionOpen> {
        // timer means that it's about time to send a packet -- let's finalize the packet and send
        // it to the hardware!
        let send_timestamp = timer_timestamp + self.wire_config.packet_finalize_delta;
        let outgoing_cleartext_packet = std::mem::replace(
            &mut self.partial_outgoing_packet,
            messages::WriteCursor::new(IpPacketBuffer::new_empty(
                ip_to_i405_length(self.wire_config.packet_length, self.peer).into(),
            )),
        )
        .into_inner();
        let outgoing_packet = self.session.encrypt_datagram(&outgoing_cleartext_packet)?;
        hardware.send_outgoing_packet(outgoing_packet.as_ref(), self.peer, Some(send_timestamp))?;
        // this is mainly to make sure that if we ever change the semantics of send_outgoing_packet,
        // we don't forget to update here:
        // TODO enable this assertion, or ensure our code does not rely on send_outgoing_packet blocking until the designated send time
        // assert!(
        //     hardware.timestamp() >= send_timestamp,
        //     "hardware.send_outgoing_packet returned too early"
        // );
        let next_interval = self.jitterator.next_interval();
        hardware.register_interval(next_interval);
        self.outgoing_connection
            .try_to_dequeue(hardware, &mut self.partial_outgoing_packet);
        hardware.set_timer(send_timestamp + next_interval - self.wire_config.packet_finalize_delta);

        // check if the incoming connection timed out
        if hardware.timestamp() > self.last_incoming_packet_timestamp + self.wire_config.timeout {
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
        self.outgoing_connection.on_read_outgoing_packet(
            hardware,
            &mut self.partial_outgoing_packet,
            packet,
            recv_timestamp,
        );
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
                    hardware.send_outgoing_packet(&packet, self.peer, None)?;
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
        let mut cursor = messages::ReadCursor::new(packet);
        while messages::has_message(&cursor) {
            let msg = cursor.read()?;
            match msg {
                Message::ClientToServerHandshake(_) => log::warn!(
                    "Received ClientToServerHandshake during established session -- retransmission?"
                ),
                Message::ServerToClientHandshake(_) => log::warn!(
                    "Received ServerToClientHandshake during established session -- retransmission?"
                ),
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
            }
        }
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
