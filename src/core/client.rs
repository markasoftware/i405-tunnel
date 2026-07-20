use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, bail};
use declarative_enum_dispatch::enum_dispatch;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::core::{
    C2S_RETRANSMIT_TIMEOUT, OLDEST_COMPATIBLE_PROTOCOL_VERSION, PROTOCOL_VERSION,
    established_connection,
};
use crate::hardware::real::QdiscSettings;
use crate::hardware::{Hardware, ReadIncomingPacket, TimerTracker};
use crate::utils::{ip_to_dtls_length, ip_to_i405_length, ns_to_str};
use crate::wire_config::WireConfig;
use crate::{dtls, messages};

use super::established_connection::OnEventResult;
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
    fn on_event(&mut self, hardware: &impl Hardware) {
        // keep calling the state's on_event until it makes no progress.
        loop {
            match std::mem::take(&mut self.state)
                .unwrap()
                .on_event_client(&self.config, hardware)
            {
                // made progress, keep looping
                Ok((true, new_state)) => self.state = Some(new_state),
                // made no progress, terminate
                Ok((false, new_state)) => {
                    self.state = Some(new_state);
                    return;
                }
                // TODO don't panic, instead use the config to decide to quit or retry
                Err(err) => panic!("Connection state error! {}", err),
            }
        }
    }
}

enum_dispatch! {
    trait ConnectionStateTrait {
        // only has to do one itsy bit of work; outer loop will keep calling it as long as the first
        // component of the retval stays true.
        // _client in name to avoid name conflicts that enum_dispatch hates
        fn on_event_client(self, config: &Config, hardware: &impl Hardware) -> Result<(bool, ConnectionState)>;
    }

    #[derive(Debug)]
    enum ConnectionState {
        NoConnection(NoConnection),
        C2SHandshakeSent(C2SHandshakeSent),
        EstablishedConnection(EstablishedConnection),
        Shutdown(Shutdown),
    }
}

#[derive(Debug)]
struct Shutdown {}

impl ConnectionStateTrait for Shutdown {
    fn on_event_client(
        self,
        _config: &Config,
        hardware: &impl Hardware,
    ) -> Result<(bool, ConnectionState)> {
        hardware.shutdown();
        Ok((false, ConnectionState::Shutdown(self)))
    }
}

#[derive(Debug)]
struct NoConnection {
    negotiation: dtls::NegotiatingSession,
    timer_tracker: TimerTracker,
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
        Ok(NoConnection {
            negotiation: session,
            timer_tracker: TimerTracker::with_timer(hardware, timeout),
        })
    }
}

impl ConnectionStateTrait for NoConnection {
    fn on_event_client(
        self,
        config: &Config,
        hardware: &impl Hardware,
    ) -> Result<(bool, ConnectionState)> {
        //// TERMINATING
        if hardware.has_user_requested_shutdown() {
            for packet in self.negotiation.terminate()? {
                hardware.send_outgoing_packet(&packet[..], config.peer_address, None)?;
            }
            return Ok((true, ConnectionState::Shutdown(Shutdown {})));
        }

        //// TIMER
        if self.timer_tracker.has_fired(hardware) {
            let (new_negotiation, packets_to_send, next_timeout) =
                self.negotiation.has_timed_out(hardware.timestamp())?;
            log::warn!(
                "DTLS handshake timeout, retrying now. Next timeout in {}. Is the server running?",
                // unfortunate hackery to get integer seconds
                ns_to_str(
                    (next_timeout - hardware.timestamp() + 1_000_000) / 1_000_000_000
                        * 1_000_000_000
                )
            );
            return Ok((
                true,
                ConnectionState::NoConnection(Self::from_triple(
                    config,
                    hardware,
                    new_negotiation,
                    &packets_to_send,
                    next_timeout,
                )?),
            ));
        }

        //// READ INCOMING PACKET
        if let Some(ReadIncomingPacket { packet, peer: _ }) = hardware.read_incoming_packet() {
            return Ok((
                true,
                match self
                    .negotiation
                    .make_progress(&packet, hardware.timestamp())
                {
                    dtls::NegotiateResult::Ready(session, to_send) => {
                        log::info!("DTLS handshake complete, proceeding to in-protocol handshake");
                        send_packets(config, hardware, &to_send)?;
                        C2SHandshakeSent::new(config, hardware, session)
                            .map(ConnectionState::C2SHandshakeSent)?
                    }
                    dtls::NegotiateResult::NeedRead(session, to_send, timeout) => {
                        Self::from_triple(config, hardware, session, &to_send, timeout)
                            .map(ConnectionState::NoConnection)?
                    }
                    dtls::NegotiateResult::Terminated => {
                        ConnectionState::NoConnection(NoConnection::new(config, hardware)?)
                    }
                    dtls::NegotiateResult::Err(err) => return Err(err),
                },
            ));
        }

        Ok((false, ConnectionState::NoConnection(self)))
    }
}

#[derive(Debug)]
struct C2SHandshakeSent {
    session: dtls::EstablishedSession,
    /// how long between the last timeout and `next_timeout_instant` (to compute backoff)
    current_timeout_interval: u64,
    /// How many times we've timed out
    num_timeouts_happened: u32,
    timer_tracker: TimerTracker,
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
        let mut result = C2SHandshakeSent {
            session,
            current_timeout_interval: C2S_RETRANSMIT_TIMEOUT,
            num_timeouts_happened: 0,
            timer_tracker: TimerTracker::with_timer(hardware, next_timeout_instant),
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
            c2s_packet_interval_min: config.client_wire_config.packet_interval_min,
            s2c_packet_finalize_delta: config.server_wire_config.packet_finalize_delta,
            server_timeout: config.server_wire_config.timeout,
            monitor_packets: config.monitor_packets,
        };
        let did_add = builder.try_add_message_no_reliability(
            &messages::Message::ClientToServerHandshake(c2s_handshake),
        );
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
    fn on_event_client(
        mut self,
        config: &Config,
        hardware: &impl Hardware,
    ) -> Result<(bool, ConnectionState)> {
        //// TERMINATING
        if hardware.has_user_requested_shutdown() {
            for packet in self.session.terminate()? {
                hardware.send_outgoing_packet(&packet, config.peer_address, None)?;
            }
            return Ok((true, ConnectionState::Shutdown(Shutdown {})));
        }

        //// TIMER
        if self.timer_tracker.has_fired(hardware) {
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
                return Ok((
                    true,
                    ConnectionState::NoConnection(NoConnection::new(config, hardware)?),
                ));
            }

            self.num_timeouts_happened += 1;
            self.current_timeout_interval =
                (self.current_timeout_interval * 2).clamp(0, C2S_MAX_TIMEOUT);
            let next_timeout = hardware.timestamp() + self.current_timeout_interval;
            self.timer_tracker.set_timer(hardware, next_timeout);
            return Ok((true, ConnectionState::C2SHandshakeSent(self)));
        }

        //// READ INCOMING PACKET
        if let Some(ReadIncomingPacket { packet, peer: _ }) = hardware.read_incoming_packet() {
            let cleartext_packet = match self.session.decrypt_datagram(&packet) {
                dtls::DecryptResult::Decrypted(cleartext_packet) => cleartext_packet,
                dtls::DecryptResult::SendThese(send_these) => {
                    for packet in send_these {
                        hardware.send_outgoing_packet(&packet, config.peer_address, None)?;
                    }
                    return Ok((true, ConnectionState::C2SHandshakeSent(self)));
                }
                dtls::DecryptResult::Terminated => {
                    return Ok((
                        true,
                        ConnectionState::NoConnection(NoConnection::new(config, hardware)?),
                    ));
                }
                dtls::DecryptResult::Err(err) => return Err(err),
            };
            // It really should be an S2C handshake. The server shouldn't send us anything but an
            // S2C handshake until we send it /another/ packet after receiving their S2C handshake,
            // so we can't get anything out-of-order here.
            let mut reader = messages::PacketReader::new(&cleartext_packet);
            match reader.try_read_message_no_ack()? {
                Some(messages::Message::ServerToClientHandshake(s2c_handshake)) => {
                    if let Some(extra_msg) = reader.try_read_message_no_ack()? {
                        bail!(
                            "There were other messages in the packet with the S2C handshake: {extra_msg:?}"
                        );
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
                    let config = established_connection::Config {
                        wire: config.client_wire_config.clone(),
                        reverse_packet_interval_min: config.server_wire_config.packet_interval_max,
                        peer: config.peer_address,
                        monitor_packets: if config.monitor_packets {
                            established_connection::MonitorPackets::Local
                        } else {
                            established_connection::MonitorPackets::No
                        },
                    };
                    return Ok((
                        true,
                        ConnectionState::EstablishedConnection(EstablishedConnection::new(
                            hardware,
                            self.session,
                            config,
                        )?),
                    ));
                }
                Some(other_msg) => bail!(
                    "The server sent a different message instead of S2C handshake: {:?}",
                    other_msg
                ),
                None => {
                    bail!("Server sent an empty packet when it should have sent an S2C handshake")
                }
            }
        }

        Ok((false, ConnectionState::C2SHandshakeSent(self)))
    }
}

impl ConnectionStateTrait for EstablishedConnection {
    fn on_event_client(
        self,
        config: &Config,
        hardware: &impl Hardware,
    ) -> Result<(bool, ConnectionState)> {
        let (made_progress, on_event_result) = EstablishedConnection::on_event(self, hardware)?;
        let new_connection_state = match on_event_result {
            OnEventResult::StillConnected(established_connection) => {
                ConnectionState::EstablishedConnection(established_connection)
            }
            OnEventResult::TimedOut => {
                log::warn!(
                    "Received no packets from server in a while -- returning to NoConnection state"
                );
                ConnectionState::NoConnection(NoConnection::new(config, hardware)?)
            }
            OnEventResult::RemoteTerminatedNormally => {
                log::info!(
                    "Server terminated connection normally -- returning to NoConnection state"
                );
                ConnectionState::NoConnection(NoConnection::new(config, hardware)?)
            }
            OnEventResult::LocalTerminatedNormally => {
                log::info!("Local shutdown -- entering Shutdown state");
                ConnectionState::Shutdown(Shutdown {})
            }
        };
        Ok((made_progress, new_connection_state))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Config {
    pub(crate) client_wire_config: WireConfig,
    pub(crate) server_wire_config: WireConfig,
    pub(crate) peer_address: SocketAddr,
    pub(crate) pre_shared_key: Vec<u8>,
    pub(crate) should_configure_qdisc: bool,
    pub(crate) monitor_packets: bool,
}
