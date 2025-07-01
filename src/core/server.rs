use std::net::SocketAddr;

use anyhow::{Result, anyhow, bail};
use declarative_enum_dispatch::enum_dispatch;

use crate::{
    constants::MAX_IP_PACKET_LENGTH,
    core::established_connection::IsConnectionOpen,
    dtls,
    hardware::Hardware,
    messages,
    utils::{ip_to_dtls_length, ip_to_i405_length},
    wire_config::WireConfig,
};

use super::{PROTOCOL_VERSION, established_connection::EstablishedConnection};

#[derive(Debug)]
pub(crate) struct Core {
    config: Config,
    state: Option<ConnectionState>,
}

impl Core {
    pub(crate) fn new(config: Config, hardware: &mut impl Hardware) -> Result<Self> {
        Ok(Self {
            state: Some(ConnectionState::NoConnection(NoConnection::new(hardware)?)),
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

    fn on_terminate(self, hardware: &mut impl Hardware) {
        if let Err(err) = self.state.unwrap().on_terminate(hardware) {
            log::error!("Error while terminating: {err:?}")
        }
    }
}

// To keep the code here relatively simple, the different server connection states emit errors, but
// these never actually cause the process to exit. Instead, they all just cause the server to revert
// to the NoConnection state. Truly fatal errors should simply panic.

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
        fn on_terminate(self, hardware: &mut impl Hardware) -> Result<()>;
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
    fn new(hardware: &mut impl Hardware) -> Result<Self> {
        hardware.clear_event_listeners()?;
        NoConnection::set_timer(hardware);
        Ok(NoConnection {
            negotiations: Vec::new(),
        })
    }

    fn set_timer(hardware: &mut impl Hardware) {
        hardware.set_timer(hardware.timestamp() + 1_000_000_000);
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
                    log::debug!("Handshake timeout with {}, informing wolfSSL", negotiation.peer);
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
        Self::set_timer(hardware);
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
            let dtls_mtu = ip_to_dtls_length(
                hardware
                    .mtu(peer)?
                    .clamp(0, MAX_IP_PACKET_LENGTH.try_into().unwrap()),
                peer,
            );
            self.negotiations.push(Negotiation {
                peer,
                session: dtls::NegotiatingSession::new_server(&config.pre_shared_key, dtls_mtu)?,
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
                            InProtocolHandshake::new(hardware, new_session, peer)?,
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
                    dtls::NegotiateResult::Terminated => {
                        log::info!(
                            "DTLS negotiation with {peer} ended because the peer terminated the connection normally."
                        );
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

    fn on_terminate(self, hardware: &mut impl Hardware) -> Result<()> {
        for negotiation in self.negotiations {
            let peer = negotiation.peer.clone();
            match negotiation.session.terminate() {
                Ok(send_these) => {
                    for packet in send_these {
                        hardware
                            .send_outgoing_packet(&packet, peer, None)
                            .unwrap_or_else(|err| {
                                log::error!(
                                    "Error sending packet during termination for {peer}: {err:?}"
                                )
                            });
                    }
                }
                Err(err) => log::error!("Error terminating connection for {peer}: {err:?}"),
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct InProtocolHandshake {
    session: dtls::EstablishedSession,
    peer: SocketAddr,
    c2s_handshake: Option<messages::ClientToServerHandshake>,
}

impl InProtocolHandshake {
    fn new(
        hardware: &mut impl Hardware,
        session: dtls::EstablishedSession,
        peer: SocketAddr,
    ) -> Result<InProtocolHandshake> {
        hardware.clear_event_listeners()?;
        hardware.socket_connect(&peer)?;
        Ok(InProtocolHandshake {
            session,
            peer,
            c2s_handshake: None,
        })
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
            let mut builder = messages::PacketBuilder::new(
                ip_to_i405_length(c2s_handshake.s2c_packet_length, self.peer).into(),
            );
            let did_add =
                builder.try_add_message(&messages::Message::ServerToClientHandshake(response));
            if !did_add {
                bail!(
                    "Client requested us to send packets that are too short for the server-to-client handshake -- this will never work"
                );
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
            bail!(
                "Got multiple C2S handshakes and they weren't the same: First time {:?}, second time {:?}",
                self.c2s_handshake.as_ref().unwrap(),
                c2s_handshake
            );
        }

        if PROTOCOL_VERSION < c2s_handshake.oldest_compatible_protocol_version {
            send_response(false)?;
            bail!(
                "Client with protocol version {} wanted protocol version at least {}, but we have {}",
                c2s_handshake.protocol_version,
                c2s_handshake.oldest_compatible_protocol_version,
                PROTOCOL_VERSION
            );
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

        let cleartext_packet = match self.session.decrypt_datagram(packet) {
            dtls::DecryptResult::Decrypted(cleartext_packet) => cleartext_packet,
            dtls::DecryptResult::SendThese(send_these) => {
                for packet in send_these {
                    hardware.send_outgoing_packet(&packet, self.peer, None)?;
                }
                return Ok(ConnectionState::InProtocolHandshake(self));
            }
            dtls::DecryptResult::Terminated => {
                return Ok(ConnectionState::NoConnection(NoConnection::new(hardware)?));
            }
            dtls::DecryptResult::Err(err) => return Err(err.into()),
        };

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
                // TODO this shouldn't be an error, but let's write a test for it before fixing:
                let c2s_handshake = self.c2s_handshake.ok_or_else(|| {
                    anyhow!(
                        "Got a non-handshake message before the C2S handshake: {:?}",
                        other
                    )
                })?;
                let s2c_wire_config = WireConfig {
                    packet_length: c2s_handshake.s2c_packet_length,
                    packet_interval_min: c2s_handshake.s2c_packet_interval_min,
                    packet_interval_max: c2s_handshake.s2c_packet_interval_max,
                    packet_finalize_delta: c2s_handshake.s2c_packet_finalize_delta,
                    timeout: c2s_handshake.server_timeout,
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

    fn on_terminate(self, hardware: &mut impl Hardware) -> Result<()> {
        for packet in self.session.terminate()? {
            hardware.send_outgoing_packet(&packet, self.peer, None)?;
        }
        Ok(())
    }
}

impl EstablishedConnection {
    // stupid naming _s because enum_dispatch won't let us use the same name here and in client
    fn handle_is_connection_open_s(
        self,
        hardware: &mut impl Hardware,
        is_connection_open: IsConnectionOpen,
    ) -> Result<ConnectionState> {
        match is_connection_open {
            IsConnectionOpen::Yes => Ok(ConnectionState::EstablishedConnection(self)),
            IsConnectionOpen::TimedOut => {
                log::warn!(
                    "Received no packets from client in a while -- returning to NoConnection state"
                );
                Ok(ConnectionState::NoConnection(NoConnection::new(hardware)?))
            }
            IsConnectionOpen::TerminatedNormally => {
                log::info!(
                    "Client terminated connection normally -- returning to NoConnection state"
                );
                Ok(ConnectionState::NoConnection(NoConnection::new(hardware)?))
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
        let is_connection_open =
            EstablishedConnection::on_timer(&mut self, hardware, timer_timestamp)?;
        self.handle_is_connection_open_s(hardware, is_connection_open)
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
        // TODO actually call .connect on the hardware
        assert_eq!(
            peer,
            self.peer(),
            "should only be receiving from the correct peer once established"
        );
        let is_connection_open =
            EstablishedConnection::on_read_incoming_packet(&mut self, hardware, packet)?;
        self.handle_is_connection_open_s(hardware, is_connection_open)
    }

    fn on_terminate(self, hardware: &mut impl Hardware) -> Result<()> {
        let peer = self.peer();
        for packet in EstablishedConnection::on_terminate_inner(self)? {
            hardware.send_outgoing_packet(&packet, peer, None)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Config {
    pub(crate) pre_shared_key: Vec<u8>,
    // TODO
    // allowed_peers: Vec<SocketAddr>,
}
