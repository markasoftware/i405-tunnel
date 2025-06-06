use std::collections::VecDeque;

use crate::{
    array_array::IpPacketBuffer,
    defragger::Defragger,
    dtls,
    hardware::{self, Hardware},
    messages::{self, DeserializeMessageErr, Message, Serializable as _},
    queued_ip_packet::{FragmentResult, QueuedIpPacket},
    wire_config::WireConfig,
};

use thiserror::Error;

/// How long before one of the constant-size packets is supposed to be sent should we hand it off to
/// the Hardware struct (in nanoseconds)? Setting this lower increases the chance that a packet will
/// be delayed due to high system load and not be sent at the right time, but setting it higher
/// could increase latency because read packets may be unnecessarily delayed to the next packet.
// TODO ensure there are no issues when this is greater than the inter-packet interval
const PACKET_FINALIZE_TO_PACKET_SEND_DELAY: u64 = 100_000;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) struct EstablishedConnection {
    session: dtls::EstablishedSession,
    peer: std::net::SocketAddr,
    outgoing_wire_config: WireConfig,
    outgoing_connection: OutgoingConnection,
    partial_outgoing_packet: messages::WriteCursor<IpPacketBuffer>,
    defragger: Defragger,
}

/// The OutgoingConnection is responsible for reading outgoing packets.
#[derive(Debug)]
enum OutgoingConnection {
    Unscheduled {
        queued_packet: Box<Option<QueuedIpPacket>>,
        fragmentation_id: u16,
    },
    Scheduled {
        // TODO maybe more settings than this:
        send_rate_bytes_per_second: u64,
        next_expected_outgoing_read_timestamp: u64,
        queued_packets: VecDeque<QueuedIpPacket>,
        fragmentation_id: u16,
    },
    MeasureLatency(),
}

impl OutgoingConnection {
    fn new_unscheduled(hardware: &mut impl Hardware) -> Self {
        // unless we have a queued packet (which we don't yet), we want the hardware to always know
        // we are ready to read an outgoing packet.
        hardware.read_outgoing_packet(None);
        Self::Unscheduled {
            queued_packet: Box::new(None),
            fragmentation_id: 0,
        }
    }

    fn new_scheduled(hardware: &mut impl Hardware) -> Self {
        unimplemented!();
    }

    fn new_measure_latency() -> Self {
        Self::MeasureLatency()
    }

    /// When a new send outgoing packet is created, call this so that any internal queued packets
    /// can be flushed into the new buffer.
    fn try_to_dequeue(
        &mut self,
        hardware: &mut impl Hardware,
        write_cursor: &mut messages::WriteCursor<IpPacketBuffer>,
    ) {
        match self {
            OutgoingConnection::Unscheduled {
                queued_packet,
                fragmentation_id,
            } => {
                // this indirection is me being afraid that we're going to accidentally reallocate
                // the box if we try to `take` the `queued_packet` directly (it might try to `take`
                // the `Box` and then `expect` will still work due to deref coercion?).
                let queued_packet_mut: &mut Option<QueuedIpPacket> = queued_packet;
                if let Some(old_queued_packet) = std::mem::take(queued_packet_mut) {
                    let bytes_left = write_cursor.num_bytes_left();
                    *fragmentation_id = fragmentation_id.wrapping_add(1);
                    let fragment = old_queued_packet.fragment(bytes_left, *fragmentation_id);
                    match fragment {
                        FragmentResult::Done(msg) => {
                            msg.serialize(write_cursor);
                            // queue is empty, let's ask for another packet!
                            hardware.read_outgoing_packet(None);
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
            OutgoingConnection::Scheduled { .. } => {
                unimplemented!("Scheduled outgoing connection not implemented yet")
            }
            OutgoingConnection::MeasureLatency() => (),
        }
    }

    fn on_read_outgoing_packet<H: Hardware>(
        &mut self,
        hardware: &mut H,
        write_cursor: &mut messages::WriteCursor<IpPacketBuffer>,
        packet: &[u8],
        _recv_timestamp: u64,
    ) {
        match self {
            OutgoingConnection::Unscheduled {
                queued_packet,
                fragmentation_id: _,
            } => {
                // strategy: queue the packet, then dequeue it!
                assert!(
                    queued_packet.is_none(),
                    "We never request to read an outgoing packet while we have a queued packet"
                );
                **queued_packet = Some(QueuedIpPacket::new(packet, None));
                self.try_to_dequeue(hardware, write_cursor);
            }
            OutgoingConnection::Scheduled { .. } => {
                unimplemented!("Scheduled outgoing connection not implemented yet")
            }
            OutgoingConnection::MeasureLatency() => panic!(
                "MeasureLatency outgoing connection never asks to read outgoing packets but we just got one"
            ),
        }
    }
}

impl EstablishedConnection {
    pub(crate) fn new(
        hardware: &mut impl Hardware,
        session: dtls::EstablishedSession,
        peer: std::net::SocketAddr,
        outgoing_wire_config: WireConfig,
    ) -> Result<Self> {
        // TODO this could return Self (can't fail)
        hardware.clear_event_listeners();
        hardware.set_timer(next_outgoing_timer(
            &outgoing_wire_config,
            hardware.timestamp(),
        ));
        Ok(Self {
            session,
            peer,
            outgoing_connection: OutgoingConnection::new_unscheduled(hardware),
            partial_outgoing_packet: messages::WriteCursor::new(IpPacketBuffer::new_empty(
                outgoing_wire_config.packet_length.into(),
            )),
            defragger: Defragger::new(),
            outgoing_wire_config,
        })
    }

    pub(crate) fn peer(&self) -> std::net::SocketAddr {
        self.peer
    }

    pub(crate) fn on_timer(
        &mut self,
        hardware: &mut impl Hardware,
        timer_timestamp: u64,
    ) -> Result<()> {
        // timer means that it's about time to send a packet -- let's finalize the packet and send
        // it to the hardware!
        let outgoing_cleartext_packet = std::mem::replace(
            &mut self.partial_outgoing_packet,
            messages::WriteCursor::new(IpPacketBuffer::new_empty(
                self.outgoing_wire_config.packet_length.into(),
            )),
        )
        .into_inner();
        let outgoing_packet = self.session.encrypt_datagram(&outgoing_cleartext_packet)?;
        hardware.send_outgoing_packet(
            outgoing_packet.as_ref(),
            self.peer,
            Some(
                timer_timestamp
                    .checked_add(PACKET_FINALIZE_TO_PACKET_SEND_DELAY)
                    .unwrap(),
            ),
        )?;
        self.outgoing_connection
            .try_to_dequeue(hardware, &mut self.partial_outgoing_packet);
        hardware.set_timer(next_outgoing_timer(
            &self.outgoing_wire_config,
            hardware.timestamp(),
        ));
        Ok(())
    }

    pub(crate) fn on_read_outgoing_packet<H: Hardware>(
        &mut self,
        hardware: &mut H,
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

    pub(crate) fn on_read_incoming_packet<H: Hardware>(
        &mut self,
        hardware: &mut H,
        packet: &[u8],
    ) -> Result<()> {
        match self.session.decrypt_datagram(packet) {
            dtls::DecryptResult::Decrypted(cleartext_packet) => {
                self.on_read_incoming_cleartext_packet(hardware, &cleartext_packet)
            }
            dtls::DecryptResult::SendThese(send_these) => {
                for packet in send_these {
                    hardware.send_outgoing_packet(&packet, self.peer, None)?;
                }
                Ok(())
            }
            dtls::DecryptResult::Err(err) => Err(err.into()),
        }
    }

    pub(crate) fn on_read_incoming_cleartext_packet<H: Hardware>(
        &mut self,
        hardware: &mut H,
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
                    if let Some(defragged_logical_packet) =
                        self.defragger.handle_ip_packet(&ip_packet)
                    {
                        hardware.send_incoming_packet(
                            &defragged_logical_packet.packet,
                            defragged_logical_packet.schedule,
                        )?;
                    }
                }
                Message::IpPacketFragment(ip_packet_fragment) => {
                    if let Some(defragged_logical_packet) = self
                        .defragger
                        .handle_ip_packet_fragment(&ip_packet_fragment)
                    {
                        hardware.send_incoming_packet(
                            &defragged_logical_packet.packet,
                            defragged_logical_packet.schedule,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("Error deserializing message: {0:?}")]
    DeserializeMessage(#[from] DeserializeMessageErr),
    #[error("std::io::Error {0:?}")]
    IO(#[from] std::io::Error),
    #[error("wolfssl error {0:?}")]
    Wolf(#[from] wolfssl::Error),
    #[error("hardware error: {0:?}")]
    Hardware(#[from] hardware::Error),
}

/// Return the next packet send time strictly after `timestamp`
fn next_outgoing_timestamp(wire_config: &WireConfig, timestamp: u64) -> u64 {
    assert!(wire_config.packet_interval > wire_config.packet_interval_offset);
    // for those of you who can't read checked_ math as quickly as real math:
    // let x = timestamp + packet_interval - packet_interval_offset
    // return x - (x%packet_interval) + packet_interval_offset
    let x = timestamp
        .checked_add(wire_config.packet_interval)
        .unwrap()
        .checked_sub(wire_config.packet_interval_offset)
        .unwrap();
    x.checked_sub(x.checked_rem(wire_config.packet_interval).unwrap())
        .unwrap()
        .checked_add(wire_config.packet_interval_offset)
        .unwrap()
}

/// When should we next prepare a packet and submit it to the hardware?
fn next_outgoing_timer(wire_config: &WireConfig, timestamp: u64) -> u64 {
    next_outgoing_timestamp(
        wire_config,
        timestamp
            .checked_add(PACKET_FINALIZE_TO_PACKET_SEND_DELAY.checked_mul(2).unwrap())
            .unwrap(),
    )
    .checked_sub(PACKET_FINALIZE_TO_PACKET_SEND_DELAY)
    .unwrap()
}

#[cfg(test)]
mod test {
    use crate::wire_config::WireConfig;

    #[test]
    fn next_outgoing_timestamp() {
        let wire_config = WireConfig {
            packet_length: 1500,
            packet_interval: 10,
            packet_interval_offset: 3,
        };

        assert_eq!(super::next_outgoing_timestamp(&wire_config, 0), 3);
        assert_eq!(super::next_outgoing_timestamp(&wire_config, 2), 3);
        assert_eq!(super::next_outgoing_timestamp(&wire_config, 3), 13);
        assert_eq!(super::next_outgoing_timestamp(&wire_config, 12), 13);
        assert_eq!(super::next_outgoing_timestamp(&wire_config, 13), 23);
    }

    #[test]
    fn next_outgoing_timer() {
        // just so we remember to fix the test if it goes bad:
        assert_eq!(
            super::PACKET_FINALIZE_TO_PACKET_SEND_DELAY,
            100_000,
            "update test if this changes"
        );

        let wire_config = WireConfig {
            packet_length: 1500,
            packet_interval: 1_400_000,
            packet_interval_offset: 3,
        };
        assert_eq!(
            super::next_outgoing_timer(&wire_config, 2_000_000),
            2_700_003
        );
        assert_eq!(
            super::next_outgoing_timer(&wire_config, 2_600_002),
            2_700_003
        );
        assert_eq!(
            super::next_outgoing_timer(&wire_config, 2_600_003),
            4_100_003
        );
    }
}
