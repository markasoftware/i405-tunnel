const PROTOCOL_VERSION: u32 = 0;
const OLDEST_COMPATIBLE_PROTOCOL_VERSION: u32 = 0;

/// C2S handshake will be resent after this long if S2C handshake not received, then exponentially
/// backs off.
const C2S_RETRANSMIT_TIMEOUT: u64 = 1_000_000_000;
/// How many times to retransmit the C2S handshake before failing.
const C2S_MAX_RETRANSMITS: u32 = 4;
const C2S_MAX_TIMEOUT: u64 = 60_000_000_000;

pub(crate) struct WireConfig {
    packet_length: u16,
    packet_interval: u64,
}

mod client {
    use enum_dispatch::enum_dispatch;
    use thiserror::Error;

    use crate::array_array::IpPacketBuffer;
    use crate::core::{
        C2S_RETRANSMIT_TIMEOUT, OLDEST_COMPATIBLE_PROTOCOL_VERSION, PROTOCOL_VERSION, WireConfig,
    };
    use crate::hardware::Hardware;
    use crate::{dtls, messages};

    use super::{C2S_MAX_RETRANSMITS, C2S_MAX_TIMEOUT};

    struct ClientCore {
        config: Config,
        state: ConnectionState,
    }

    #[enum_dispatch(ClientConnectionStateTrait)]
    enum ConnectionState {
        NoConnection(NoConnection),
        C2SHandshakeSent(C2SHandshakeSent),
        EstablishedConnection(EstablishedConnection),
    }

    #[derive(Error, Debug)]
    enum ConnectionStateError {
        #[error("DTLS Negotiation error: {0:?}")]
        NegotiateError(#[from] dtls::NegotiateError),
        #[error("std::io::Error {0:?}")]
        IOError(#[from] std::io::Error),
        #[error("DTLS new session error: {0:?}")]
        NewSessionError(#[from] dtls::NewSessionError),
        #[error("Error deserializing a message: {0:?}")]
        DeserializeMessageErr(#[from] messages::DeserializeMessageErr),
        #[error("S2C handshake indicated failure on the server-side. Remote protocol version: {0} (vs ours {protocol_version})", protocol_version = PROTOCOL_VERSION)]
        S2CHandshakeError(u32),
        #[error("The server sent an empty packet when it should have sent an S2C handshake")]
        S2CHandshakeEmpty,
        #[error("The server sent a different message instead of S2C handshake: {0:?}")]
        S2CHandshakeWasnt(messages::Message),
        #[error("There were other messages in the packet with the S2C handshake")]
        S2CHandshakeNotAlone,
        #[error("The server sent an incompatible protocol version, {0} (vs ours {protocol_version})", protocol_version = PROTOCOL_VERSION)]
        S2CHandshakeIncompatibleProtocolVersion(u32),
    }

    type Result<T> = std::result::Result<T, ConnectionStateError>;

    struct NoConnection {
        negotiation: dtls::NegotiatingSession,
    }

    fn send_packets<H: Hardware>(
        config: &Config,
        hardware: &mut H,
        packets_to_send: &Vec<IpPacketBuffer>,
    ) -> Result<()> {
        for packet in packets_to_send {
            hardware.send_outgoing_packet(&packet[..], config.peer_address, None)?;
        }
        Ok(())
    }

    impl NoConnection {
        fn new<H: Hardware>(config: &Config, hardware: &mut H) -> Result<NoConnection> {
            let (new_session, initial_packets, timeout) =
                dtls::NegotiatingSession::new_client(&config.pre_shared_key, hardware.timestamp())?;
            Self::from_triple(config, hardware, new_session, &initial_packets, timeout)
        }

        fn from_triple<H: Hardware>(
            config: &Config,
            hardware: &mut H,
            session: dtls::NegotiatingSession,
            packets_to_send: &Vec<IpPacketBuffer>,
            timeout: u64,
        ) -> Result<NoConnection> {
            send_packets(config, hardware, &packets_to_send)?;
            hardware.set_timer(timeout);
            Ok(NoConnection {
                negotiation: session,
            })
        }
    }

    impl<H: Hardware> ConnectionStateTrait<H> for NoConnection {
        fn on_timer(
            self,
            config: &Config,
            hardware: &mut H,
            _timer_timestamp: u64,
        ) -> Result<ConnectionState> {
            let (new_negotiation, packets_to_send, next_timeout) =
                self.negotiation.has_timed_out(hardware.timestamp())?;
            Self::from_triple(
                config,
                hardware,
                new_negotiation,
                &packets_to_send,
                next_timeout,
            )
            .map(ConnectionState::NoConnection)
        }

        fn on_read_outgoing_packet(
            self,
            _config: &Config,
            _hardware: &mut H,
            _packet: &[u8],
            _recv_timestamp: u64,
        ) -> Result<ConnectionState> {
            panic!(
                "on_read_outgoing_packet shouldn't happen during NoConnection -- we never ask for outgoing packets"
            );
        }

        fn on_read_incoming_packet(
            self,
            config: &Config,
            hardware: &mut H,
            packet: &[u8],
        ) -> Result<ConnectionState> {
            match self.negotiation.make_progress(packet, hardware.timestamp()) {
                dtls::NegotiateResult::Ready(session, to_send) => {
                    send_packets(config, hardware, &to_send)?;
                    C2SHandshakeSent::new(config, hardware, session)
                        .map(ConnectionState::C2SHandshakeSent)
                }
                dtls::NegotiateResult::NeedRead(session, to_send, timeout) => {
                    Self::from_triple(config, hardware, session, &to_send, timeout)
                        .map(ConnectionState::NoConnection)
                }
                dtls::NegotiateResult::Err(err) => Err(ConnectionStateError::NegotiateError(err)),
            }
        }
    }

    struct C2SHandshakeSent {
        session: dtls::EstablishedSession,
        next_timeout_instant: u64,
        /// how long between the last timeout and `next_timeout_instant` (to compute backoff)
        current_timeout_interval: u64,
        /// How many times we've timed out
        num_timeouts_happened: u32,
    }

    impl C2SHandshakeSent {
        fn new<H: Hardware>(
            config: &Config,
            hardware: &mut H,
            session: dtls::EstablishedSession,
        ) -> Result<C2SHandshakeSent> {
            let mut result = C2SHandshakeSent {
                session,
                next_timeout_instant: hardware.timestamp() + C2S_RETRANSMIT_TIMEOUT,
                current_timeout_interval: C2S_RETRANSMIT_TIMEOUT,
                num_timeouts_happened: 0,
            };
            result.send_one_handshake(config, hardware)?;
            Ok(result)
        }

        fn send_one_handshake<H: Hardware>(
            &mut self,
            config: &Config,
            hardware: &mut H,
        ) -> Result<()> {
            let mut builder =
                messages::PacketBuilder::new(config.c2s_wire_config.packet_length.into());
            let c2s_handshake = messages::ClientToServerHandshake {
                protocol_version: PROTOCOL_VERSION,
                oldest_compatible_protocol_version: OLDEST_COMPATIBLE_PROTOCOL_VERSION,
                // TODO split out the WireConfig class and have it be a field on the message
                s2c_packet_length: config.s2c_wire_config.packet_length,
                s2c_packet_interval: config.s2c_wire_config.packet_interval,
            };
            let did_add =
                builder.try_add_message(&messages::Message::ClientToServerHandshake(c2s_handshake));
            assert!(
                did_add,
                "Wasn't able to fit the C2S handshake in a single packet -- this will never work. Try increasing client-to-server packet size."
            );
            let buf = builder.into_inner();
            hardware.send_outgoing_packet(&buf[..], config.peer_address, None)?;
            Ok(())
        }
    }

    impl<H: Hardware> ConnectionStateTrait<H> for C2SHandshakeSent {
        fn on_timer(
            mut self,
            config: &Config,
            hardware: &mut H,
            _timer_timestamp: u64,
        ) -> Result<ConnectionState> {
            // we timed out :|
            self.send_one_handshake(config, hardware);
            if self.num_timeouts_happened >= C2S_MAX_RETRANSMITS {
                // time to go back to the stone age
                log::warn!(
                    "Ran out of all {} C2S handshake retries -- going back to DTLS negotiation",
                    C2S_MAX_RETRANSMITS
                );
                return Ok(ConnectionState::NoConnection(NoConnection::new(
                    config, hardware,
                )?));
            }

            self.num_timeouts_happened = self.num_timeouts_happened.checked_add(1).unwrap();
            self.current_timeout_interval = self.current_timeout_interval.checked_mul(2).unwrap();
            if self.current_timeout_interval > C2S_MAX_TIMEOUT {
                self.current_timeout_interval = C2S_MAX_TIMEOUT;
            }
            self.next_timeout_instant = hardware
                .timestamp()
                .checked_add(self.current_timeout_interval)
                .unwrap();
            Ok(ConnectionState::C2SHandshakeSent(self))
        }

        fn on_read_outgoing_packet(
            self,
            _config: &Config,
            _hardware: &mut H,
            _packet: &[u8],
            _recv_timestamp: u64,
        ) -> Result<ConnectionState> {
            panic!("During C2S handshake we don't read outgoing packets -- something's wrong");
        }

        fn on_read_incoming_packet(
            self,
            _config: &Config,
            _hardware: &mut H,
            packet: &[u8],
        ) -> Result<ConnectionState> {
            // It really should be an S2C handshake. The server shouldn't send us anything but an
            // S2C handshake until we send it /another/ packet after receiving their S2C handshake,
            // so we can't get anything out-of-order here.
            let mut read_cursor = messages::ReadCursor::new(packet);
            // TODO I'm not totally happy that we have to do `has_message` rather than being able to
            // use `read`
            if !messages::has_message(&read_cursor) {
                return Err(ConnectionStateError::S2CHandshakeEmpty);
            }

            let message = read_cursor.read()?;
            match message {
                messages::Message::ServerToClientHandshake(s2c_handshake) => {
                    // first, ensure there's nothing left in the cursor
                    if messages::has_message(&read_cursor) {
                        return Err(ConnectionStateError::S2CHandshakeNotAlone);
                    }

                    if !s2c_handshake.success {
                        return Err(ConnectionStateError::S2CHandshakeError(
                            s2c_handshake.protocol_version,
                        ));
                    }

                    if s2c_handshake.protocol_version != PROTOCOL_VERSION {
                        return Err(
                            ConnectionStateError::S2CHandshakeIncompatibleProtocolVersion(
                                s2c_handshake.protocol_version,
                            ),
                        );
                    }

                    // maybe one day will pass in the server's protocol version here?
                    Ok(ConnectionState::EstablishedConnection(
                        EstablishedConnection::new(self.session),
                    ))
                }
                other_msg => Err(ConnectionStateError::S2CHandshakeWasnt(other_msg)),
            }
        }
    }

    struct EstablishedConnection {
        session: dtls::EstablishedSession,
        // scheduling stuff will go here eventually
    }

    impl EstablishedConnection {
        fn new(session: dtls::EstablishedSession) -> Self {
            EstablishedConnection { session }
        }
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
        ) -> Result<ConnectionState>;
    }

    struct Config {
        c2s_wire_config: WireConfig,
        s2c_wire_config: WireConfig,
        peer_address: std::net::SocketAddr,
        pre_shared_key: Vec<u8>,
    }
}

mod server {
    use enum_dispatch::enum_dispatch;
    use thiserror::Error;

    use crate::{array_array::IpPacketbuffer, dtls, hardware::Hardware, messages};

    use super::{OLDEST_COMPATIBLE_PROTOCOL_VERSION, PROTOCOL_VERSION};

    struct ServerCore {
        config: Config,
        state: ConnectionState,
    }

    type Result<T> = std::result::Result<T, ConnectionStateError>;

    #[derive(Error, Debug)]
    struct ConnectionStateError {}

    #[enum_dispatch(ServerConnectionStateTrait)]
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

    impl<H: Hardware> ConnectionStateTrait for NoConnection {
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
            mut self,
            config: &Config,
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
                            return Ok(ConnectionState::AwaitingC2SHandshake(
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
        fn new(
            session: dtls::EstablishedSession,
            peer: std::net::SocketAddr,
        ) -> InProtocolHandshake {
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
                let mut builder =
                    messages::PacketBuilder::new(c2s_handshake.s2c_packet_length.into());
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
            config: &Config,
            hardware: &mut H,
            packet: &[u8],
            recv_timestamp: u64,
        ) -> Result<ConnectionState> {
            panic!("No outgoing packets are read while awaiting C2S handshake");
        }

        fn on_read_incoming_packet(
            self,
            _config: &Config,
            hardware: &mut H,
            packet: &[u8],
            peer: std::net::SocketAddr,
        ) -> Result<ConnectionState> {
            assert!(peer == self.peer, "handshake peer was not as expected");

            let mut read_cursor = messages::ReadCursor::new(packet);
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
                        Some(_) => {
                            // connection established! TODO construct an EstablishedSession and then
                            // process the messages in the packet.
                            Ok(ConnectionState::NoConnection(NoConnection::new()))
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
}

pub(crate) enum Core {
    ClientCore(client::ClientCore),
    ServerCore(server::ServerCore),
}
