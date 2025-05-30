use std::net::SocketAddr;

use declarative_enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::{
    core::WireConfig,
    dtls,
    hardware::{self, Hardware},
    messages,
};

use super::{
    PROTOCOL_VERSION,
    established_connection::{self, EstablishedConnection},
};

#[derive(Debug)]
pub(crate) struct Core {
    config: Config,
    state: Option<ConnectionState>,
}

impl Core {
    pub(crate) fn new(config: Config) -> Result<Self> {
        Ok(Self {
            state: Some(ConnectionState::NoConnection(NoConnection::new())),
            config,
        })
    }
}

fn replace_state_with_result<F: FnOnce(ConnectionState) -> Result<ConnectionState>>(
    state: &mut Option<ConnectionState>,
    f: F,
) {
    match f(std::mem::take(state).unwrap()) {
        Ok(new_state) => std::mem::replace(state, Some(new_state)),
        Err(err) => {
            // TODO don't panic, instead use the config to decide whether to quit or retry.
            panic!("Connection state error! {}", err);
        }
    };
}

impl super::Core for Core {
    fn on_timer(&mut self, hardware: &mut impl Hardware, timer_timestamp: u64) {
        replace_state_with_result(&mut self.state, |state| {
            state.on_timer(&self.config, hardware, timer_timestamp)
        });
    }

    fn on_read_outgoing_packet(
        &mut self,
        hardware: &mut impl Hardware,
        packet: &[u8],
        recv_timestamp: u64,
    ) {
        replace_state_with_result(&mut self.state, |state| {
            state.on_read_outgoing_packet(&self.config, hardware, packet, recv_timestamp)
        });
    }

    fn on_read_incoming_packet(
        &mut self,
        hardware: &mut impl Hardware,
        packet: &[u8],
        peer: SocketAddr,
    ) {
        replace_state_with_result(&mut self.state, |state| {
            state.on_read_incoming_packet(&self.config, hardware, packet, peer)
        });
    }
}

type Result<T> = std::result::Result<T, ConnectionStateError>;

// To keep the code here relatively simple, the different server connection states emit errors, but
// these never actually cause the process to exit. Instead, they all just cause the server to revert
// to the NoConnection state. Truly fatal errors should simply panic.

#[derive(Error, Debug)]
pub(crate) enum ConnectionStateError {
    #[error("IO error: {0}")]
    IOErr(#[from] std::io::Error),
    #[error("New session DTLS error: {0}")]
    NewSessionErr(#[from] dtls::NewSessionError),
    #[error("wolfSSL error: {0}")]
    WolfErr(#[from] wolfssl::Error),
    #[error("hardware error: {0}")]
    HardwareErr(#[from] hardware::Error),
    #[error("established connection error: {0}")]
    EstablishedConnectionErr(#[from] established_connection::Error),
    #[error("deserialize error: {0}")]
    DeserializeMessageErr(#[from] messages::DeserializeMessageErr),
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
        Box<messages::ClientToServerHandshake>,
        Box<messages::ClientToServerHandshake>,
    ),
    #[error("Got a non-handshake message before the C2S handshake")]
    // i don't care that the option is inside the box, don't @ me
    OtherMessageBeforeC2SHandshake(Box<Option<messages::Message>>),
}

enum_dispatch! {
    trait ServerConnectionStateTrait {
        fn on_timer(
            self,
            config: &Config,
            hardware: &mut impl Hardware,
            timer_timestamp: u64,
        ) -> Result<ConnectionState>;
        fn on_read_outgoing_packet(
            self,
            config: &Config,
            hardware: &mut impl Hardware,
            packet: &[u8],
            recv_timestamp: u64,
        ) -> Result<ConnectionState>;
        fn on_read_incoming_packet(
            self,
            config: &Config,
            hardware: &mut impl Hardware,
            packet: &[u8],
            peer: SocketAddr,
        ) -> Result<ConnectionState>;
    }

    #[derive(Debug)]
    enum ConnectionState {
        NoConnection(NoConnection),
        /// The DTLS connection has been established, now we just keep responding to C2S handshakes
        /// until we get the first message after a C2S handshake, which indicates ready.
        InProtocolHandshake(InProtocolHandshake),
        EstablishedConnection(EstablishedConnection),
    }
}

#[derive(Debug)]
struct NoConnection {
    negotiations: Vec<Negotiation>,
}

#[derive(Debug)]
struct Negotiation {
    peer: SocketAddr,
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

impl ServerConnectionStateTrait for NoConnection {
    fn on_timer(
        mut self,
        _config: &Config,
        hardware: &mut impl Hardware,
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
                        Ok((new_session, to_send, new_timeout)) => 'timeout_success: {
                            for packet in to_send {
                                match hardware.send_outgoing_packet(&packet, negotiation.peer, None) {
                                    Ok(()) => (),
                                    Err(err) => {
                                        log::error!("Error sending packet to {} during DTLS handshake timeout: {:?}", negotiation.peer, err);
                                        break 'timeout_success None;
                                    }
                                }
                            }
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
        _hardware: &mut impl Hardware,
        _packet: &[u8],
        _recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        // shouldn't be any outgoing packets here
        panic!("Outgoing packets in NoConnection state!");
    }

    fn on_read_incoming_packet(
        mut self,
        config: &Config,
        hardware: &mut impl Hardware,
        packet: &[u8],
        peer: SocketAddr,
    ) -> Result<ConnectionState> {
        if self
            .negotiations
            .iter()
            .find(|negotiation| negotiation.peer == peer)
            .is_none()
        {
            // start a negotiation
            log::info!("New DTLS handshake started with {}", peer);
            self.negotiations.push(Negotiation {
                peer,
                session: dtls::NegotiatingSession::new_server(&config.pre_shared_key)?,
                timeout: u64::MAX,
            });
        }

        let mut new_negotiations = Vec::with_capacity(self.negotiations.len());
        for negotiation in self.negotiations {
            if negotiation.peer == peer {
                match negotiation
                    .session
                    .make_progress(packet, hardware.timestamp())
                {
                    dtls::NegotiateResult::Ready(new_session, to_send) => {
                        // at this very line of code, the handshake is complete, and the peer has
                        // been selected, so it's reasonable to actually return an error if we have
                        // an issue sending the packets. (the idea is we just log and retry from
                        // within the connection state if we haven't chosen a peer yet, so that ie
                        // some rando trying the wrong passwords doesn't make it impossible to
                        // connect with the right password).
                        log::info!(
                            "DTLS handshake complete with {}, proceeding to in-protocol handshake",
                            peer
                        );
                        for packet in to_send {
                            hardware.send_outgoing_packet(&packet, peer, None)?;
                        }
                        return Ok(ConnectionState::InProtocolHandshake(
                            InProtocolHandshake::new(new_session, peer),
                        ));
                    }
                    dtls::NegotiateResult::NeedRead(new_session, to_send, next_timeout) => {
                        // The peer doesn't necessarily have the right password yet, so we want to
                        // make sure to just drop the connection on error, not reset the entire
                        // connection state.
                        'need_read: {
                            for packet in to_send {
                                match hardware.send_outgoing_packet(&packet, peer, None) {
                                    Ok(()) => (),
                                    Err(err) => {
                                        log::error!(
                                            "Error sending packet during DTLS handshake with {}: {:?}",
                                            peer,
                                            err
                                        );
                                        break 'need_read;
                                    }
                                }
                            }
                            new_negotiations.push(Negotiation {
                                peer,
                                session: new_session,
                                timeout: next_timeout,
                            });
                        }
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

#[derive(Debug)]
struct InProtocolHandshake {
    session: dtls::EstablishedSession,
    peer: SocketAddr,
    c2s_handshake: Option<messages::ClientToServerHandshake>,
}

impl InProtocolHandshake {
    fn new(session: dtls::EstablishedSession, peer: SocketAddr) -> InProtocolHandshake {
        InProtocolHandshake {
            session,
            peer,
            c2s_handshake: None,
        }
    }

    fn send_s2c_handshake(
        &mut self,
        hardware: &mut impl Hardware,
        c2s_handshake: &messages::ClientToServerHandshake,
    ) -> Result<()> {
        let mut send_response = |success| {
            let response = messages::ServerToClientHandshake {
                protocol_version: PROTOCOL_VERSION,
                success,
            };
            let mut builder = messages::PacketBuilder::new(c2s_handshake.s2c_packet_length.into());
            let did_add =
                builder.try_add_message(&messages::Message::ServerToClientHandshake(response));
            if !did_add {
                return Err(ConnectionStateError::PacketsTooShortForS2CHandshake);
            }
            let cleartext_packet = builder.into_inner();
            let ciphertext_packet = self.session.encrypt_datagram(&cleartext_packet)?;
            hardware.send_outgoing_packet(&ciphertext_packet, self.peer, None)?;
            Ok(())
        };

        if self
            .c2s_handshake
            .as_ref()
            .is_some_and(|old_c2s_handshake| old_c2s_handshake != c2s_handshake)
        {
            send_response(false)?;
            return Err(ConnectionStateError::DifferentC2SHandshakes(
                Box::new(self.c2s_handshake.clone().unwrap()),
                Box::new(c2s_handshake.clone()),
            ));
        }

        if PROTOCOL_VERSION < c2s_handshake.oldest_compatible_protocol_version {
            send_response(false)?;
            return Err(ConnectionStateError::IncompatibleProtocolVersions(
                c2s_handshake.protocol_version,
                c2s_handshake.oldest_compatible_protocol_version,
                PROTOCOL_VERSION,
            ));
        }

        send_response(true)
    }
}

impl ServerConnectionStateTrait for InProtocolHandshake {
    fn on_timer(
        self,
        _config: &Config,
        _hardware: &mut impl Hardware,
        _timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        panic!("No timers set but we got on_timer'd!");
    }

    fn on_read_outgoing_packet(
        self,
        _config: &Config,
        _hardware: &mut impl Hardware,
        _packet: &[u8],
        _recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        panic!("No outgoing packets are read while awaiting C2S handshake");
    }

    fn on_read_incoming_packet(
        mut self,
        _config: &Config,
        hardware: &mut impl Hardware,
        packet: &[u8],
        peer: SocketAddr,
    ) -> Result<ConnectionState> {
        assert!(peer == self.peer, "handshake peer was not as expected");

        let cleartext_packet = self.session.decrypt_datagram(packet)?;

        let mut read_cursor = messages::ReadCursor::new(cleartext_packet.clone());

        let message = if messages::has_message(&read_cursor) {
            Some(read_cursor.read()?)
        } else {
            None
        };
        match message {
            Some(messages::Message::ClientToServerHandshake(c2s_handshake)) => {
                log::debug!("Got C2S handshake, as expected. Sending S2C handshake.");
                self.send_s2c_handshake(hardware, &c2s_handshake)?;
                Ok(ConnectionState::InProtocolHandshake(InProtocolHandshake {
                    session: self.session,
                    peer: self.peer,
                    c2s_handshake: Some(c2s_handshake),
                }))
            }
            other => {
                let c2s_handshake = self.c2s_handshake.ok_or(
                    ConnectionStateError::OtherMessageBeforeC2SHandshake(Box::new(other)),
                )?;
                let s2c_wire_config = WireConfig {
                    packet_length: c2s_handshake.s2c_packet_length,
                    packet_interval: c2s_handshake.s2c_packet_interval,
                    // TODO randomize or specify in C2S handshake?
                    packet_interval_offset: 123,
                };
                log::info!(
                    "Handshake complete with {}, proceeding to established connection with {:?}",
                    peer,
                    s2c_wire_config
                );
                let mut established_connection =
                    EstablishedConnection::new(hardware, self.session, peer, s2c_wire_config)?;
                established_connection
                    .on_read_incoming_cleartext_packet(hardware, &cleartext_packet)?;
                Ok(ConnectionState::EstablishedConnection(
                    established_connection,
                ))
            }
        }
    }
}

impl ServerConnectionStateTrait for EstablishedConnection {
    fn on_timer(
        mut self,
        _config: &Config,
        hardware: &mut impl Hardware,
        timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        EstablishedConnection::on_timer(&mut self, hardware, timer_timestamp)?;
        Ok(ConnectionState::EstablishedConnection(self))
    }

    fn on_read_outgoing_packet(
        mut self,
        _config: &Config,
        hardware: &mut impl Hardware,
        packet: &[u8],
        recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        EstablishedConnection::on_read_outgoing_packet(&mut self, hardware, packet, recv_timestamp);
        Ok(ConnectionState::EstablishedConnection(self))
    }

    fn on_read_incoming_packet(
        mut self,
        _config: &Config,
        hardware: &mut impl Hardware,
        packet: &[u8],
        peer: SocketAddr,
    ) -> Result<ConnectionState> {
        // TODO actually call .connect or whatever on the hardware
        assert_eq!(
            peer,
            self.peer(),
            "should only be receiving from the correct peer once established"
        );
        EstablishedConnection::on_read_incoming_packet(&mut self, hardware, packet)?;
        Ok(ConnectionState::EstablishedConnection(self))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Config {
    pub(crate) pre_shared_key: Vec<u8>,
    // TODO
    // allowed_peers: Vec<SocketAddr>,
}
