use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::{array_array::IpPacketBuffer, core::WireConfig, dtls, hardware::Hardware, messages};

use super::{
    OLDEST_COMPATIBLE_PROTOCOL_VERSION, PROTOCOL_VERSION,
    established_connection::EstablishedConnection,
};

pub(crate) struct ServerCore {
    config: Config,
    state: ConnectionState,
}

type Result<T> = std::result::Result<T, ConnectionStateError>;

#[derive(Error, Debug)]
struct ConnectionStateError {}

#[enum_dispatch(ConnectionStateTrait)]
enum ConnectionState {
    NoConnection(NoConnection),
    /// The DTLS connection has been established, now we just keep responding to C2S handshakes
    /// until we get the first message after a C2S handshake, which indicates ready.
    InProtocolHandshake(InProtocolHandshake),
    EstablishedConnection(EstablishedConnection),
}

struct NoConnection {
    negotiations: Vec<Negotiation>,
}

struct Negotiation {
    peer: std::net::SocketAddr,
    session: dtls::NegotiatingSession,
    timeout: u64,
    // TODO info so we can remove inactive negotiations.
}

impl NoConnection {
    fn new() -> Self {
        NoConnection {
            negotiations: Vec::new(),
        }
    }
}

impl<H: Hardware> ConnectionStateTrait<H> for NoConnection {
    fn on_timer(
        mut self,
        _config: &Config,
        hardware: &mut H,
        _timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        // to simplify the Hardware struct, it only supports one timer. However, we may have
        // multiple ongoing negotiations, each with different timestamps. What we do is simply
        // ask the hardware to ping us every second, and then check explicitly which
        // negotiations have expired.
        let now = hardware.timestamp();

        self.negotiations = self
            .negotiations
            .into_iter()
            .filter_map(|negotiation| {
                if now < negotiation.timeout {
                    Some(negotiation)
                } else {
                    match negotiation.session.has_timed_out(now) {
                        Ok((new_session, to_send, new_timeout)) => {
                            // TODO send to_send
                            Some(Negotiation {
                                peer: negotiation.peer,
                                session: new_session,
                                timeout: new_timeout,
                            })
                        }
                        Err(err) => {
                            log::error!(
                                "DTLS negotiation with {} failed during timeout: {:?}",
                                negotiation.peer,
                                err
                            );
                            None
                        }
                    }
                }
            })
            .collect();
        Ok(ConnectionState::NoConnection(self))
    }

    fn on_read_outgoing_packet(
        self,
        _config: &Config,
        _hardware: &mut H,
        _packet: &[u8],
        _recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        // shouldn't be any outgoing packets here
        panic!("Outgoing packets in NoConnection state!");
    }

    fn on_read_incoming_packet(
        self,
        _config: &Config,
        hardware: &mut H,
        packet: &[u8],
        peer: std::net::SocketAddr,
    ) -> Result<ConnectionState> {
        let mut new_negotiations = Vec::with_capacity(self.negotiations.len());
        for negotiation in self.negotiations {
            if negotiation.peer == peer {
                match negotiation
                    .session
                    .make_progress(packet, hardware.timestamp())
                {
                    dtls::NegotiateResult::Ready(new_session, to_send) => {
                        // TODO send to_send
                        return Ok(ConnectionState::InProtocolHandshake(
                            InProtocolHandshake::new(new_session, peer),
                        ));
                    }
                    dtls::NegotiateResult::NeedRead(new_session, to_send, next_timeout) => {
                        // TODO send to_send
                        new_negotiations.push(Negotiation {
                            peer,
                            session: new_session,
                            timeout: next_timeout,
                        });
                    }
                    dtls::NegotiateResult::Err(err) => {
                        log::error!(
                            "DTLS negotiation with {} failed during make_progress: {:?}",
                            peer,
                            err
                        );
                    }
                }
            } else {
                new_negotiations.push(negotiation);
            }
        }

        Ok(ConnectionState::NoConnection(NoConnection {
            negotiations: new_negotiations,
        }))
    }
}

struct InProtocolHandshake {
    session: dtls::EstablishedSession,
    peer: std::net::SocketAddr,
    c2s_handshake: Option<messages::ClientToServerHandshake>,
}

impl InProtocolHandshake {
    fn new(session: dtls::EstablishedSession, peer: std::net::SocketAddr) -> InProtocolHandshake {
        InProtocolHandshake {
            session,
            peer,
            c2s_handshake: None,
        }
    }

    fn send_s2c_handshake<H: Hardware>(
        &self,
        hardware: &mut H,
        c2s_handshake: &messages::ClientToServerHandshake,
    ) -> std::result::Result<(), InProtocolHandshakeError> {
        let mut send_response = |success| {
            let response = messages::ServerToClientHandshake {
                protocol_version: PROTOCOL_VERSION,
                success,
            };
            let mut builder = messages::PacketBuilder::new(c2s_handshake.s2c_packet_length.into());
            let did_add =
                builder.try_add_message(&messages::Message::ServerToClientHandshake(response));
            if !did_add {
                return Err(InProtocolHandshakeError::PacketsTooShortForS2CHandshake);
            }
            let packet = builder.into_inner();
            hardware.send_outgoing_packet(&packet[..], self.peer, None);
            Ok(())
        };

        if self
            .c2s_handshake
            .as_ref()
            .is_some_and(|old_c2s_handshake| old_c2s_handshake != c2s_handshake)
        {
            send_response(false)?;
            return Err(InProtocolHandshakeError::DifferentC2SHandshakes(
                self.c2s_handshake.clone().unwrap(),
                c2s_handshake.clone(),
            ));
        }

        if PROTOCOL_VERSION < c2s_handshake.oldest_compatible_protocol_version {
            send_response(false)?;
            return Err(InProtocolHandshakeError::IncompatibleProtocolVersions(
                c2s_handshake.protocol_version,
                c2s_handshake.oldest_compatible_protocol_version,
                PROTOCOL_VERSION,
            ));
        }

        send_response(true)
    }
}

#[derive(Error, Debug)]
enum InProtocolHandshakeError {
    #[error("IO error: {0:?}")]
    IOError(#[from] std::io::Error),
    #[error(
        "Client with protocol version {0} wanted protocol version at least {1}, but we have {2}"
    )]
    IncompatibleProtocolVersions(u32, u32, u32),
    #[error(
        "Client requested us to send packets that are too short for the server-to-client handshake -- this will never work"
    )]
    PacketsTooShortForS2CHandshake,
    #[error(
        "Got multiple C2S handshakes and they weren't the same: First time {0:?}, second time {1:?}"
    )]
    DifferentC2SHandshakes(
        messages::ClientToServerHandshake,
        messages::ClientToServerHandshake,
    ),
}

impl<H: Hardware> ConnectionStateTrait<H> for InProtocolHandshake {
    fn on_timer(
        self,
        _config: &Config,
        _hardware: &mut H,
        _timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        panic!("No timers set but we got on_timer'd!");
    }

    fn on_read_outgoing_packet(
        self,
        _config: &Config,
        _hardware: &mut H,
        _packet: &[u8],
        _recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        panic!("No outgoing packets are read while awaiting C2S handshake");
    }

    fn on_read_incoming_packet(
        mut self,
        _config: &Config,
        hardware: &mut H,
        packet: &[u8],
        peer: std::net::SocketAddr,
    ) -> Result<ConnectionState> {
        assert!(peer == self.peer, "handshake peer was not as expected");

        let cleartext_packet = match self.session.try_read(packet) {
            Ok(cleartext_packet) => cleartext_packet,
            Err(err) => {
                log::error!(
                    "wolfSSL error reading incoming packet during handshake, aborting connection: {:?}",
                    err
                );
                return Ok(ConnectionState::NoConnection(NoConnection::new()));
            }
        };

        let mut read_cursor = messages::ReadCursor::new(cleartext_packet.clone());
        if !messages::has_message(&read_cursor) {
            log::error!("Empty packet from {}, aborting connection", self.peer);
            return Ok(ConnectionState::NoConnection(NoConnection::new()));
        }

        let message = read_cursor.read();
        match message {
            Ok(messages::Message::ClientToServerHandshake(c2s_handshake)) => {
                match self.send_s2c_handshake(hardware, &c2s_handshake) {
                    Ok(()) => Ok(ConnectionState::InProtocolHandshake(InProtocolHandshake {
                        session: self.session,
                        peer: self.peer,
                        c2s_handshake: Some(c2s_handshake),
                    })),
                    Err(err) => {
                        log::error!(
                            "Error processing C2S handshake from {}, aborting connection: {:?}",
                            self.peer,
                            err
                        );
                        Ok(ConnectionState::NoConnection(NoConnection::new()))
                    }
                }
            }
            Ok(other_message) => {
                match self.c2s_handshake {
                    Some(c2s_handshake) => {
                        let s2c_wire_config = WireConfig {
                            packet_length: c2s_handshake.s2c_packet_length,
                            packet_interval: c2s_handshake.s2c_packet_interval,
                            // TODO randomize?
                            packet_interval_offset: 123,
                        };
                        let mut established_connection =
                            EstablishedConnection::new(self.session, peer, s2c_wire_config);
                        match established_connection
                            .on_read_incoming_cleartext_packet(hardware, &cleartext_packet)
                        {
                            Ok(()) => (),
                            Err(err) => {
                                log::warn!(
                                    "Error reading incoming first round of real messages from peer {}, aborting connection: {:?}",
                                    self.peer,
                                    err
                                );
                                return Ok(ConnectionState::NoConnection(NoConnection::new()));
                            }
                        }
                        // connection established! TODO construct an EstablishedSession and then
                        // process the messages in the packet.
                        Ok(ConnectionState::EstablishedConnection(
                            established_connection,
                        ))
                    }
                    None => {
                        log::error!(
                            "Got a non-handshake message before getting a C2S handshake from {}, aborting connection: {:?}",
                            self.peer,
                            other_message
                        );
                        Ok(ConnectionState::NoConnection(NoConnection::new()))
                    }
                }
            }
            Err(err) => {
                log::error!(
                    "Error deserializing handshake message from {}, aborting connection: {:?}",
                    self.peer,
                    err
                );
                Ok(ConnectionState::NoConnection(NoConnection::new()))
            }
        }
    }
}

impl<H: Hardware> ConnectionStateTrait<H> for EstablishedConnection {
    fn on_timer(
        mut self,
        _config: &Config,
        hardware: &mut H,
        timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        match EstablishedConnection::on_timer(&mut self, hardware, timer_timestamp) {
            Ok(()) => Ok(ConnectionState::EstablishedConnection(self)),
            Err(err) => {
                log::error!(
                    "EstablishedConnection error with peer {}, aborting connection: {:?}",
                    self.peer(),
                    err
                );
                Ok(ConnectionState::NoConnection(NoConnection::new()))
            }
        }
    }

    fn on_read_outgoing_packet(
        mut self,
        _config: &Config,
        hardware: &mut H,
        packet: &[u8],
        recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        EstablishedConnection::on_read_outgoing_packet(&mut self, hardware, packet, recv_timestamp);
        Ok(ConnectionState::EstablishedConnection(self))
    }

    fn on_read_incoming_packet(
        mut self,
        _config: &Config,
        hardware: &mut H,
        packet: &[u8],
        peer: std::net::SocketAddr,
    ) -> Result<ConnectionState> {
        // TODO actually call .connect or whatever on the hardware
        assert_eq!(
            peer,
            self.peer(),
            "should only be receiving from the correct peer once established"
        );
        match EstablishedConnection::on_read_incoming_packet(&mut self, hardware, packet) {
            Ok(()) => Ok(ConnectionState::EstablishedConnection(self)),
            Err(err) => {
                log::error!(
                    "EstablishedConnection error with peer {}, aborting connection: {:?}",
                    self.peer(),
                    err
                );
                Ok(ConnectionState::NoConnection(NoConnection::new()))
            }
        }
    }
}

struct Config {
    allowed_peers: Vec<std::net::SocketAddr>,
}

#[enum_dispatch]
trait ConnectionStateTrait<H: Hardware> {
    fn on_timer(
        self,
        config: &Config,
        hardware: &mut H,
        timer_timestamp: u64,
    ) -> Result<ConnectionState>;
    fn on_read_outgoing_packet(
        self,
        config: &Config,
        hardware: &mut H,
        packet: &[u8],
        recv_timestamp: u64,
    ) -> Result<ConnectionState>;
    fn on_read_incoming_packet(
        self,
        config: &Config,
        hardware: &mut H,
        packet: &[u8],
        peer: std::net::SocketAddr,
    ) -> Result<ConnectionState>;
}
