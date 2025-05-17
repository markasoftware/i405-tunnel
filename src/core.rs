use std::net::SocketAddr;

use thiserror::Error;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::hardware::Hardware;
use crate::messages::Message;

enum ClientServer {
    Client,
    Server,
}

enum ConnectionState {
    NoConnection(NoConnection),
    EstablishedConnection(EstablishedConnection),
}

struct NoConnection {
    /// All currently open sockets, which may be at various stages in the DTLS negotiation.
    handshakes: Vec<DTLSNegotiatingSession>,
}

/// The part of the core that is mostly client/server agnostic, and is used as soon as a DTLS
/// negotiation finishes.
struct EstablishedConnection {
    client_server: ClientServer,
    peer_addr: SocketAddr,

    // messages we'd like to send in the next network packet if at all possible
    pending_outgoing_messages: Vec<Message>,
}

pub(crate) struct Core {
    connection: ConnectionState,
}

// impl Core {
//     pub(crate) fn new() -> Self {
//         Core {
//             // TODO real values
//             packet_interval_ns: 42,
//             packet_length: 1400,

//             // quite larger than we should need, we only insert one packet of messages at a time
//             pending_outgoing_messages: Vec::with_capacity(100),
//             // Eventually: scheduled_incoming_messages
//         }
//     }

//     pub(crate) fn on_wake<H: Hardware>(&mut self, hardware: &mut H) -> Result<()> {
//         // Is it time to send
//     }
// }

//// WOLFSSL HELPERS ///////////////////////////////////////////////////////////////////////////////

struct DTLSNegotiatingSession {
    underlying: wolfssl::Session<DTLSCallbacks>,
}

impl std::fmt::Debug for DTLSNegotiatingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DTLSNegotiatingSession(...)")
    }
}

impl DTLSNegotiatingSession {
    /// Construct a new client, and also returns the initial handshake packets that should be sent.
    pub(crate) fn new_client(
        pre_shared_key: &[u8],
    ) -> Result<(Self, Vec<IpPacketBuffer>), NewDTLSSessionError> {
        let wolf_session = wolfssl::ContextBuilder::new(wolfssl::Method::DtlsClientV1_3)?
            .with_pre_shared_key(pre_shared_key)
            .build()
            .new_session(wolfssl::SessionConfig::new(DTLSCallbacks::new()))?;
        let session = DTLSNegotiatingSession {
            underlying: wolf_session,
        };
        match session.inner_try_negotiate(None) {
            DTLSNegotiateResult::Ready(_, _) => Err(NewDTLSSessionError::ReadyImmediately),
            DTLSNegotiateResult::NeedRead(new_session, packets) => Ok((new_session, packets)),
            DTLSNegotiateResult::UnexpectedAppData => Err(NewDTLSSessionError::UnexpectedAppData),
            DTLSNegotiateResult::WolfSSLErr(e) => Err(NewDTLSSessionError::from(e)),
        }
    }

    pub(crate) fn new_server(pre_shared_key: &[u8]) -> Result<Self, NewDTLSSessionError> {
        let session = wolfssl::ContextBuilder::new(wolfssl::Method::DtlsServerV1_3)?
            .with_pre_shared_key(pre_shared_key)
            .build()
            .new_session(wolfssl::SessionConfig::new(DTLSCallbacks::new()))?;
        Ok(DTLSNegotiatingSession {
            underlying: session,
        })
    }

    /// Negotiate as far as we can. Pass in the most recently read packet off the network. If we
    /// need more packets, we'll tell you. If the return value indicates packets need to be sent,
    /// please send them.
    fn inner_try_negotiate(mut self, read_packet: Option<&[u8]>) -> DTLSNegotiateResult {
        match read_packet {
            Some(packet) => self
                .underlying
                .io_cb_mut()
                .set_next_packet_to_receive(packet),
            None => (),
        }

        let mut written_packets = Vec::new();

        // TODO understand: If I capture `self` instead of taking it as an argument, then the borrow
        // checker complains that add_written_packet has a mutable borrow of `self` for the rest of
        // the function. Why is that the case? Why doesn't the mutable borrow of `self` simply occur
        // when `add_written_packet` is called, rather than being persistent?
        let mut add_written_packets = |session_obj: &mut Self| {
            written_packets.extend(session_obj.underlying.io_cb_mut().last_sent_packets())
        };

        loop {
            println!("About to try negotiating");
            match self.underlying.try_negotiate() {
                Err(err) => return DTLSNegotiateResult::WolfSSLErr(err),
                // We don't use secure renegotiation, so this shouldn't happen!
                Ok(wolfssl::Poll::AppData(_)) => return DTLSNegotiateResult::UnexpectedAppData,
                Ok(wolfssl::Poll::PendingWrite) => add_written_packets(&mut self),
                Ok(wolfssl::Poll::PendingRead) => {
                    add_written_packets(&mut self);
                    return DTLSNegotiateResult::NeedRead(self, written_packets);
                }
                Ok(wolfssl::Poll::Ready(())) => {
                    add_written_packets(&mut self);
                    return DTLSNegotiateResult::Ready(
                        DTLSEstablishedSession {
                            underlying: self.underlying,
                        },
                        written_packets,
                    );
                }
            }
        }
    }

    pub(crate) fn make_progress(self, read_packet: &[u8]) -> DTLSNegotiateResult {
        self.inner_try_negotiate(Some(read_packet))
    }
}

#[derive(Error, Debug)]
enum NewDTLSSessionError {
    // TODO why do we need these error() messages? The docs make it seem like you don't when you have #[from]
    #[error("NewSessionError {0:?}")]
    NewSessionError(#[from] wolfssl::NewSessionError),
    #[error("NewContextBuilderError {0:?}")]
    NewContextBuilderError(#[from] wolfssl::NewContextBuilderError),
    #[error("WolfError {0:?}")]
    WolfError(#[from] wolfssl::Error),
    #[error("Client was ready immediately")]
    ReadyImmediately,
    #[error("Unexpected AppData")]
    UnexpectedAppData,
}

#[derive(Debug)]
enum DTLSNegotiateResult {
    /// Negotiation is completely done as soon as you send these packets!
    Ready(DTLSEstablishedSession, Vec<IpPacketBuffer>),
    /// Send these packets, then read more packets and get back to us
    NeedRead(DTLSNegotiatingSession, Vec<IpPacketBuffer>),
    WolfSSLErr(wolfssl::Error),
    UnexpectedAppData, // an error, but we can't cleanly fit it into WolfSSLErr
}

struct DTLSEstablishedSession {
    underlying: wolfssl::Session<DTLSCallbacks>,
}

impl std::fmt::Debug for DTLSEstablishedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DTLSEstablishedSession(...)")
    }
}

impl DTLSEstablishedSession {
    /// Call try_write on the underlying session, and return the encrypted bytes.
    fn try_write(
        &mut self,
        cleartext_packet: &[u8],
    ) -> std::result::Result<IpPacketBuffer, wolfssl::Error> {
        match self.underlying.try_write_slice(cleartext_packet)? {
            wolfssl::Poll::Ready(len) => {
                // TODO better pre-checking that packet is the right length to fit in a single IP packet when encrypted
                assert!(
                    len == cleartext_packet.len(),
                    "Only {} bytes of packet of length {} were written",
                    len,
                    cleartext_packet.len()
                );
                let written_packets = self
                    .underlying
                    .io_cb_mut()
                    .last_sent_packets();
                let result = written_packets[0].clone(); // TODO NO NO NO
                // TODO verify this size is exactly what we expect. We need to put more robust
                // checks all around that only packets of the correct size can get passed through to
                // here.
                assert!(
                    result.len() > len,
                    "Ciphertext length {} is shorter than cleartext {}, probably means it would have been too large for MTU!",
                    len,
                    result.len()
                );
                Ok(result)
            }
            poll_result => panic!(
                "try_write should always complete immediately, but got {:#?}",
                poll_result
            ),
        }
    }

    // TODO consider writing the result to an &mut [u8] argument instead

    // TODO investigate whether wolfssl supports putting multiple dtls messages into the same
    // packet, which could break our logic on the read side which really assumes one dtls
    // message/packet

    /// Call try_read on the underlying session, and return the cleartext bytes.
    fn try_read(
        &mut self,
        ciphertext_packet: &[u8],
    ) -> std::result::Result<IpPacketBuffer, wolfssl::Error> {
        self.underlying
            .io_cb_mut()
            .set_next_packet_to_receive(ciphertext_packet);
        let mut result = IpPacketBuffer::new_empty(MAX_IP_PACKET_LENGTH);
        match self.underlying.try_read_slice(result.as_mut())? {
            wolfssl::Poll::Ready(len) => {
                // TODO verify that len is what we expect it to be
                result.shrink(len);
                Ok(result)
            }
            poll_result => panic!(
                "try_read should always complete immediately, but got {:#?}",
                poll_result
            ),
        }
    }
}

#[derive(Debug)]
struct DTLSCallbacks {
    // could make this a teensy bit faster by having a BytesMut instead that we can write to, but oh
    // well.
    last_sent_packets: Vec<IpPacketBuffer>,
    // and this could be a Bytes
    next_packet_to_receive: Option<IpPacketBuffer>,
}

impl DTLSCallbacks {
    const SENT_CAPACITY: usize = 10;

    fn new() -> DTLSCallbacks {
        DTLSCallbacks {
            last_sent_packets: Vec::with_capacity(Self::SENT_CAPACITY),
            next_packet_to_receive: None,
        }
    }

    fn last_sent_packets(&mut self) -> Vec<IpPacketBuffer> {
        std::mem::take(&mut self.last_sent_packets)
    }

    fn set_next_packet_to_receive(&mut self, buf: &[u8]) {
        match self.next_packet_to_receive {
            Some(_) => panic!(
                "set_next_packet_to_receive called even though the last packet to receive was never read!"
            ),
            None => {
                self.next_packet_to_receive = Some(IpPacketBuffer::new(buf));
            }
        }
    }
}

impl wolfssl::IOCallbacks for DTLSCallbacks {
    fn send(&mut self, buf: &[u8]) -> wolfssl::IOCallbackResult<usize> {
        if self.last_sent_packets.len() < Self::SENT_CAPACITY {
            self.last_sent_packets.push(IpPacketBuffer::new(buf));
            wolfssl::IOCallbackResult::Ok(buf.len())
        } else {
            wolfssl::IOCallbackResult::WouldBlock
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> wolfssl::IOCallbackResult<usize> {
        match self.next_packet_to_receive.as_ref() {
            Some(next_packet_to_receive) => {
                let result = next_packet_to_receive.len();
                buf[..next_packet_to_receive.len()].copy_from_slice(next_packet_to_receive);
                self.next_packet_to_receive = None;
                wolfssl::IOCallbackResult::Ok(result)
            }
            None => wolfssl::IOCallbackResult::WouldBlock,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::array_array::IpPacketBuffer;

    use super::{DTLSEstablishedSession, DTLSNegotiateResult, DTLSNegotiatingSession};

    fn negotiate_multiple_packets(
        mut session: DTLSNegotiatingSession,
        packets: impl std::iter::IntoIterator<Item = IpPacketBuffer>,
    ) -> DTLSNegotiateResult {
        let mut out_packets = Vec::new();
        for packet in packets {
            match session.make_progress(&packet) {
                DTLSNegotiateResult::NeedRead(new_session, cur_out_packets) => {
                    out_packets.extend(cur_out_packets);
                    session = new_session;
                }
                DTLSNegotiateResult::Ready(new_session, cur_out_packets) => {
                    out_packets.extend(cur_out_packets);
                    return DTLSNegotiateResult::Ready(new_session, out_packets);
                }
                e => panic!("Unexpected DTLSNegotiateResult: {:?}", e),
            }
        }
        DTLSNegotiateResult::NeedRead(session, out_packets)
    }

    /// Test that we can negotiate and send a packet using our wolfssl wrapper
    #[test]
    fn wolfssl_wrapper() {
        let psk = b"password";

        //// FIRST ROUNDTRIP ////
        let (mut client, c2s_packets_1) = DTLSNegotiatingSession::new_client(psk).unwrap();
        let mut server = DTLSNegotiatingSession::new_server(psk).unwrap();

        for packet in &c2s_packets_1 {
            println!("cs packet {}", packet.len());
        }

        let mut s2c_packets_1 = Vec::new();
        match negotiate_multiple_packets(server, c2s_packets_1) {
            DTLSNegotiateResult::NeedRead(new_server, cur_s2c_packets) => {
                s2c_packets_1 = cur_s2c_packets;
                server = new_server;
            }
            DTLSNegotiateResult::Ready(_, _) => panic!("Ready too early"),
            e => panic!("Unexpected result {:?}", e),
        }

        for packet in &s2c_packets_1 {
            println!("sc packet {}", packet.len());
        }

        //// SECOND ROUNDTRIP ////
        let mut c2s_packets_2 = Vec::new();
        match negotiate_multiple_packets(client, s2c_packets_1) {
            DTLSNegotiateResult::NeedRead(new_client, cur_c2s_packets) => {
                c2s_packets_2 = cur_c2s_packets;
                client = new_client;
            }
            DTLSNegotiateResult::Ready(_, _) => panic!("Ready too early"),
            e => panic!("Unexpected result {:?}", e),
        }

        for packet in &c2s_packets_2 {
            println!("cs packet {}", packet.len());
        }

        let mut s2c_packets_2 = Vec::new();
        let mut server_established = None;
        match negotiate_multiple_packets(server, c2s_packets_2) {
            DTLSNegotiateResult::NeedRead(_, _) => panic!("Wasn't ready in time"),
            DTLSNegotiateResult::Ready(new_server, cur_s2c_packets) => {
                s2c_packets_2 = cur_s2c_packets;
                server_established = Some(new_server);
            }
            e => panic!("Unexpected result {:?}", e),
        }

        //// CLIENT -> SERVER APPLICATION DATA ////
        // let msg = b"howdy howdy lil cutie";
        // let c2s_packet = client.try_write(msg).unwrap();
        // let roundtripped = server.try_read(&c2s_packet).unwrap();
        // assert_eq!(
        //     &roundtripped[..],
        //     msg,
        //     "Roundtripped should equal original msg (client->server)"
        // );

        // //// SERVER -> CLIENT APPLICATION DATA ////
        // let msg2 = b"im buying weed on the internet";
        // let s2c_packet = server.try_write(msg2).unwrap();
        // let roundtripped2 = client.try_read(&s2c_packet).unwrap();
        // assert_eq!(
        //     &roundtripped2[..],
        //     msg2,
        //     "Roundtripped should equal original msg (server->client)"
        // );

        // assert!(num_roundtrips == 2, "Should take 2 roundtrips to complete the handshake, not {}.", num_roundtrips);
    }
}
