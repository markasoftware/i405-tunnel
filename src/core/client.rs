use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, bail};
use declarative_enum_dispatch::enum_dispatch;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::core::{C2S_RETRANSMIT_TIMEOUT, OLDEST_COMPATIBLE_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::hardware::Hardware;
use crate::hardware::real::QdiscSettings;
use crate::utils::{ip_to_dtls_length, ip_to_i405_length, ns_to_str};
use crate::wire_config::WireConfig;
use crate::{dtls, messages};

use super::established_connection::IsConnectionOpen;
use super::{C2S_MAX_RETRANSMITS, C2S_MAX_TIMEOUT, established_connection::EstablishedConnection};

#[derive(Debug)]
pub(crate) struct Core {
    config: Config,
    // this option should never really be empty; we just need to be able to std::mem::take out of it
    // temporarily.
    state: Option<ConnectionState>,
}

impl Core {
    pub(crate) fn new(config: Config, hardware: &impl Hardware) -> Result<Self> {
        if config.should_configure_qdisc {
            hardware.configure_qdisc(&QdiscSettings::new(Duration::from_nanos(
                config.client_wire_config.packet_interval_max,
            )))?;
        }
        Ok(Self {
            state: Some(ConnectionState::NoConnection(NoConnection::new(
                &config, hardware,
            )?)),
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
    fn on_timer(&mut self, hardware: &impl Hardware, timer_timestamp: u64) {
        replace_state_with_result(&mut self.state, |state| {
            state.on_timer(&self.config, hardware, timer_timestamp)
        });
    }

    fn on_read_outgoing_packet(
        &mut self,
        hardware: &impl Hardware,
        packet: &[u8],
        recv_timestamp: u64,
    ) {
        replace_state_with_result(&mut self.state, |state| {
            state.on_read_outgoing_packet(&self.config, hardware, packet, recv_timestamp)
        });
    }

    fn on_read_incoming_packet(
        &mut self,
        hardware: &impl Hardware,
        packet: &[u8],
        _peer: SocketAddr,
    ) {
        replace_state_with_result(&mut self.state, |state| {
            state.on_read_incoming_packet(&self.config, hardware, packet)
        });
    }

    fn on_terminate(self, hardware: &impl Hardware) {
        if let Err(err) = self.state.unwrap().on_terminate(&self.config, hardware) {
            log::error!("Error while terminating connection: {:?}", err);
        }
    }
}

enum_dispatch! {
    trait ConnectionStateTrait {
        fn on_timer(
            self,
            config: &Config,
            hardware: &impl Hardware,
            timer_timestamp: u64,
        ) -> Result<ConnectionState>;
        fn on_read_outgoing_packet(
            self,
            config: &Config,
            hardware: &impl Hardware,
            packet: &[u8],
        recv_timestamp: u64,
        ) -> Result<ConnectionState>;
        fn on_read_incoming_packet(
            self,
            config: &Config,
            hardware: &impl Hardware,
            packet: &[u8],
        ) -> Result<ConnectionState>;
        fn on_terminate(self, config: &Config, hardware: &impl Hardware) -> Result<()>;
    }

    #[derive(Debug)]
    enum ConnectionState {
        NoConnection(NoConnection),
        C2SHandshakeSent(C2SHandshakeSent),
        EstablishedConnection(EstablishedConnection),
    }
}

#[derive(Debug)]
struct NoConnection {
    negotiation: dtls::NegotiatingSession,
}

fn send_packets(
    config: &Config,
    hardware: &impl Hardware,
    packets_to_send: &Vec<IpPacketBuffer>,
) -> Result<()> {
    for packet in packets_to_send {
        hardware.send_outgoing_packet(&packet[..], config.peer_address, None)?;
    }
    Ok(())
}

impl NoConnection {
    fn new(config: &Config, hardware: &impl Hardware) -> Result<NoConnection> {
        hardware.clear_event_listeners()?;
        hardware.socket_connect(&config.peer_address)?;
        let dtls_mtu = ip_to_dtls_length(
            hardware
                .mtu(config.peer_address)?
                .clamp(0, MAX_IP_PACKET_LENGTH.try_into().unwrap()),
            config.peer_address,
        );
        let (new_session, initial_packets, timeout) = dtls::NegotiatingSession::new_client(
            &config.pre_shared_key,
            dtls_mtu,
            hardware.timestamp(),
        )?;
        Self::from_triple(config, hardware, new_session, &initial_packets, timeout)
    }

    fn from_triple(
        config: &Config,
        hardware: &impl Hardware,
        session: dtls::NegotiatingSession,
        packets_to_send: &Vec<IpPacketBuffer>,
        timeout: u64,
    ) -> Result<NoConnection> {
        send_packets(config, hardware, packets_to_send)?;
        hardware.set_timer(timeout);
        Ok(NoConnection {
            negotiation: session,
        })
    }
}

impl ConnectionStateTrait for NoConnection {
    fn on_timer(
        self,
        config: &Config,
        hardware: &impl Hardware,
        _timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        let (new_negotiation, packets_to_send, next_timeout) =
            self.negotiation.has_timed_out(hardware.timestamp())?;
        log::warn!(
            "DTLS handshake timeout, retrying now. Next timeout in {}. Is the server running?",
            // unfortunate hackery to get integer seconds
            ns_to_str(
                (next_timeout - hardware.timestamp() + 1_000_000) / 1_000_000_000 * 1_000_000_000
            )
        );
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
        _hardware: &impl Hardware,
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
        hardware: &impl Hardware,
        packet: &[u8],
    ) -> Result<ConnectionState> {
        match self.negotiation.make_progress(packet, hardware.timestamp()) {
            dtls::NegotiateResult::Ready(session, to_send) => {
                log::info!("DTLS handshake complete, proceeding to in-protocol handshake");
                send_packets(config, hardware, &to_send)?;
                C2SHandshakeSent::new(config, hardware, session)
                    .map(ConnectionState::C2SHandshakeSent)
            }
            dtls::NegotiateResult::NeedRead(session, to_send, timeout) => {
                Self::from_triple(config, hardware, session, &to_send, timeout)
                    .map(ConnectionState::NoConnection)
            }
            dtls::NegotiateResult::Terminated => Ok(ConnectionState::NoConnection(
                NoConnection::new(config, hardware)?,
            )),
            dtls::NegotiateResult::Err(err) => Err(err),
        }
    }

    fn on_terminate(self, config: &Config, hardware: &impl Hardware) -> Result<()> {
        for packet in self.negotiation.terminate()? {
            hardware.send_outgoing_packet(&packet[..], config.peer_address, None)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct C2SHandshakeSent {
    session: dtls::EstablishedSession,
    /// how long between the last timeout and `next_timeout_instant` (to compute backoff)
    current_timeout_interval: u64,
    /// How many times we've timed out
    num_timeouts_happened: u32,
}

impl C2SHandshakeSent {
    fn new(
        config: &Config,
        hardware: &impl Hardware,
        session: dtls::EstablishedSession,
    ) -> Result<C2SHandshakeSent> {
        hardware.clear_event_listeners()?;
        hardware.socket_connect(&config.peer_address)?;
        let next_timeout_instant = hardware.timestamp() + C2S_RETRANSMIT_TIMEOUT;
        hardware.set_timer(next_timeout_instant);
        let mut result = C2SHandshakeSent {
            session,
            current_timeout_interval: C2S_RETRANSMIT_TIMEOUT,
            num_timeouts_happened: 0,
        };
        result.send_one_handshake(config, hardware)?;
        Ok(result)
    }

    fn send_one_handshake(&mut self, config: &Config, hardware: &impl Hardware) -> Result<()> {
        let mut builder = messages::PacketBuilder::new(
            ip_to_i405_length(config.client_wire_config.packet_length, config.peer_address).into(),
        );
        let c2s_handshake = messages::ClientToServerHandshake {
            protocol_version: PROTOCOL_VERSION,
            oldest_compatible_protocol_version: OLDEST_COMPATIBLE_PROTOCOL_VERSION,
            s2c_packet_length: config.server_wire_config.packet_length,
            s2c_packet_interval_min: config.server_wire_config.packet_interval_min,
            s2c_packet_interval_max: config.server_wire_config.packet_interval_max,
            s2c_packet_finalize_delta: config.server_wire_config.packet_finalize_delta,
            server_timeout: config.server_wire_config.timeout,
        };
        let did_add =
            builder.try_add_message(&messages::Message::ClientToServerHandshake(c2s_handshake));
        assert!(
            did_add,
            "Wasn't able to fit the C2S handshake in a single packet -- this will never work. Try increasing client-to-server packet size."
        );
        let cleartext_packet = builder.into_inner();
        let packet = self.session.encrypt_datagram(&cleartext_packet)?;
        hardware.send_outgoing_packet(&packet, config.peer_address, None)?;
        Ok(())
    }
}

impl ConnectionStateTrait for C2SHandshakeSent {
    fn on_timer(
        mut self,
        config: &Config,
        hardware: &impl Hardware,
        _timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        log::warn!(
            "In-protocol handshake timeout; we sent C2S handshake {} ago and received no response, trying again.",
            ns_to_str(self.current_timeout_interval),
        );
        self.send_one_handshake(config, hardware)?;
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

        self.num_timeouts_happened += 1;
        self.current_timeout_interval =
            (self.current_timeout_interval * 2).clamp(0, C2S_MAX_TIMEOUT);
        let next_timeout_instant = hardware.timestamp() + self.current_timeout_interval;
        hardware.set_timer(next_timeout_instant);
        Ok(ConnectionState::C2SHandshakeSent(self))
    }

    fn on_read_outgoing_packet(
        self,
        _config: &Config,
        _hardware: &impl Hardware,
        _packet: &[u8],
        _recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        panic!("During C2S handshake we don't read outgoing packets -- something's wrong");
    }

    fn on_read_incoming_packet(
        mut self,
        config: &Config,
        hardware: &impl Hardware,
        packet: &[u8],
    ) -> Result<ConnectionState> {
        let cleartext_packet = match self.session.decrypt_datagram(packet) {
            dtls::DecryptResult::Decrypted(cleartext_packet) => cleartext_packet,
            dtls::DecryptResult::SendThese(send_these) => {
                for packet in send_these {
                    hardware.send_outgoing_packet(&packet, config.peer_address, None)?;
                }
                return Ok(ConnectionState::C2SHandshakeSent(self));
            }
            dtls::DecryptResult::Terminated => {
                return Ok(ConnectionState::NoConnection(NoConnection::new(
                    config, hardware,
                )?));
            }
            dtls::DecryptResult::Err(err) => return Err(err),
        };
        // It really should be an S2C handshake. The server shouldn't send us anything but an
        // S2C handshake until we send it /another/ packet after receiving their S2C handshake,
        // so we can't get anything out-of-order here.
        let mut read_cursor = messages::ReadCursor::new(&cleartext_packet);
        // TODO I'm not totally happy that we have to do `has_message` rather than being able to
        // use `read`
        if !messages::has_message(&read_cursor) {
            bail!("The server sent an empty packet when it should have sent an S2C handshake");
        }

        let message = read_cursor.read()?;
        match message {
            messages::Message::ServerToClientHandshake(s2c_handshake) => {
                // first, ensure there's nothing left in the cursor
                if messages::has_message(&read_cursor) {
                    bail!("There were other messages in the packet with the S2C handshake");
                }

                if !s2c_handshake.success {
                    bail!(
                        "S2C handshake indicated failure on the server-side. Remote protocol version: {} (vs ours {})",
                        s2c_handshake.protocol_version,
                        PROTOCOL_VERSION
                    );
                }

                if s2c_handshake.protocol_version != PROTOCOL_VERSION {
                    bail!(
                        "The server sent an incompatible protocol version, {} (vs ours {})",
                        s2c_handshake.protocol_version,
                        PROTOCOL_VERSION
                    );
                }

                log::info!(
                    "In-protocol handshake complete, remote protocol version {}, proceeding to established connection",
                    s2c_handshake.protocol_version
                );

                // maybe one day will pass in the server's protocol version here?
                Ok(ConnectionState::EstablishedConnection(
                    EstablishedConnection::new(
                        hardware,
                        self.session,
                        config.peer_address,
                        config.client_wire_config.clone(),
                    )?,
                ))
            }
            other_msg => bail!(
                "The server sent a different message instead of S2C handshake: {:?}",
                other_msg
            ),
        }
    }

    fn on_terminate(self, config: &Config, hardware: &impl Hardware) -> Result<()> {
        for packet in self.session.terminate()? {
            hardware.send_outgoing_packet(&packet, config.peer_address, None)?;
        }
        Ok(())
    }
}

impl EstablishedConnection {
    // stupid naming _s because enum_dispatch won't let us use the same name here and in server
    fn handle_is_connection_open_c(
        self,
        config: &Config,
        hardware: &impl Hardware,
        is_connection_open: IsConnectionOpen,
    ) -> Result<ConnectionState> {
        match is_connection_open {
            IsConnectionOpen::Yes => Ok(ConnectionState::EstablishedConnection(self)),
            IsConnectionOpen::TimedOut => {
                log::warn!(
                    "Received no packets from server in a while -- returning to NoConnection state"
                );
                Ok(ConnectionState::NoConnection(NoConnection::new(
                    config, hardware,
                )?))
            }
            IsConnectionOpen::TerminatedNormally => {
                log::info!(
                    "Client terminated connection normally -- returning to NoConnection state"
                );
                Ok(ConnectionState::NoConnection(NoConnection::new(
                    config, hardware,
                )?))
            }
        }
    }
}

impl ConnectionStateTrait for EstablishedConnection {
    fn on_timer(
        mut self,
        config: &Config,
        hardware: &impl Hardware,
        timer_timestamp: u64,
    ) -> Result<ConnectionState> {
        let is_connection_open =
            EstablishedConnection::on_timer(&mut self, hardware, timer_timestamp)?;
        self.handle_is_connection_open_c(config, hardware, is_connection_open)
    }

    fn on_read_outgoing_packet(
        mut self,
        _config: &Config,
        hardware: &impl Hardware,
        packet: &[u8],
        recv_timestamp: u64,
    ) -> Result<ConnectionState> {
        EstablishedConnection::on_read_outgoing_packet(&mut self, hardware, packet, recv_timestamp);
        Ok(ConnectionState::EstablishedConnection(self))
    }

    fn on_read_incoming_packet(
        mut self,
        config: &Config,
        hardware: &impl Hardware,
        packet: &[u8],
    ) -> Result<ConnectionState> {
        let is_connection_open =
            EstablishedConnection::on_read_incoming_packet(&mut self, hardware, packet)?;
        self.handle_is_connection_open_c(config, hardware, is_connection_open)
    }

    fn on_terminate(self, config: &Config, hardware: &impl Hardware) -> Result<()> {
        for packet in EstablishedConnection::on_terminate_inner(self)? {
            hardware.send_outgoing_packet(&packet, config.peer_address, None)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Config {
    pub(crate) client_wire_config: WireConfig,
    pub(crate) server_wire_config: WireConfig,
    pub(crate) peer_address: SocketAddr,
    pub(crate) pre_shared_key: Vec<u8>,
    pub(crate) should_configure_qdisc: bool,
}
