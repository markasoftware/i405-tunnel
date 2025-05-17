use std::net::SocketAddr;

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
    handshakes: Vec<TLSSession>,
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

/// An easier to use wrapper around wolfssl::Session. Mainly, it has negotiate, write, and read
/// functions that simply take or return buffers, rather than the typical pattern of having io
/// callbacks that immediately do network I/O.
struct TLSSession {
    underlying: wolfssl::Session<TLSCallbacks>,
    handshake_complete: bool,
    handshake_just_requested_read: bool,
}

impl TLSSession {
    fn new(context: &wolfssl::Context) -> Result<Self, wolfssl::NewSessionError> {
        let session = context.new_session(wolfssl::SessionConfig::new(TLSCallbacks::new()))?;
        // TODO arguments for other options.
        // TODO look into ssl_verify_mode, see if we need anything other than the default for psk
        Ok(Self {
            underlying: session,
            handshake_complete: false,
            handshake_just_requested_read: false,
        })
    }

    fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Negotiate as far as we can. Pass in the most recently read packet off the network. If we
    /// need more packets, we'll tell you. If the return value indicates packets need to be sent,
    /// please send them. Don't pass in any read packets until requested.
    fn try_negotiate(&mut self, read_packet: Option<&[u8]>) -> TLSNegotiateResult {
        assert!(
            !self.handshake_complete,
            "try_negotiate called after handshake already complete"
        );

        match read_packet {
            Some(buf) => {
                assert!(
                    self.handshake_just_requested_read,
                    "try_negotiate received a read_packet but didn't ask for a read"
                );
                self.underlying.io_cb_mut().set_next_packet_to_receive(buf);
            }
            None => {
                // TODO remove ,it doesn't matter
                assert!(
                    !(self.handshake_just_requested_read && read_packet.is_none()),
                    "try_negotiate requested a read packet but didn't get one"
                );
            }
        }
        self.handshake_just_requested_read = false;

        let mut written_packets = Vec::new();

        // TODO understand: If I capture `self` instead of taking it as an argument, then the borrow
        // checker complains that add_written_packet has a mutable borrow of `self` for the rest of
        // the function. Why is that the case? Why doesn't the mutable borrow of `self` simply occur
        // when `add_written_packet` is called, rather than being persistent?
        let mut add_written_packet = |session_obj: &mut Self| match session_obj
            .underlying
            .io_cb_mut()
            .pop_last_sent_packet()
        {
            Some(last_sent_packet) => written_packets.push(last_sent_packet),
            None => (),
        };

        loop {
            println!("About to try negotiating");
            match self.underlying.try_negotiate() {
                Err(err) => return TLSNegotiateResult::WolfSSLErr(err),
                // We don't use secure renegotiation, so this shouldn't happen!
                Ok(wolfssl::Poll::AppData(_)) => return TLSNegotiateResult::UnexpectedAppData,
                Ok(wolfssl::Poll::PendingWrite) => add_written_packet(self),
                Ok(wolfssl::Poll::PendingRead) => {
                    self.handshake_just_requested_read = true;
                    add_written_packet(self);
                    return TLSNegotiateResult::NeedRead(written_packets);
                }
                Ok(wolfssl::Poll::Ready(())) => {
                    self.handshake_complete = true;
                    add_written_packet(self);
                    return TLSNegotiateResult::Ready(written_packets);
                }
            }
        }
    }

    /// Call try_write on the underlying session, and return the encrypted bytes.
    fn try_write(
        &mut self,
        cleartext_packet: &[u8],
    ) -> std::result::Result<IpPacketBuffer, wolfssl::Error> {
        assert!(
            self.handshake_complete,
            "Handshake must be complete before calling `try_write`"
        );
        match self.underlying.try_write_slice(cleartext_packet)? {
            wolfssl::Poll::Ready(len) => {
                // TODO better pre-checking that packet is the right length to fit in a single IP packet when encrypted
                assert!(
                    len == cleartext_packet.len(),
                    "Only {} bytes of packet of length {} were written",
                    len,
                    cleartext_packet.len()
                );
                let result = self
                    .underlying
                    .io_cb_mut()
                    .pop_last_sent_packet()
                    .expect("Should be a sent packet after try_write");
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
        assert!(
            self.handshake_complete,
            "Handshake must be complete before calling `try_read`"
        );
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
enum TLSNegotiateResult {
    /// Negotiation is completely done as soon as you send these packets!
    Ready(Vec<IpPacketBuffer>),
    /// Send these packets, then read more packets and get back to us
    NeedRead(Vec<IpPacketBuffer>),
    WolfSSLErr(wolfssl::Error),
    UnexpectedAppData, // an error, but we can't cleanly fit it into WolfSSLErr
}

struct TLSCallbacks {
    // could make this a teensy bit faster by having a BytesMut instead that we can write to, but oh
    // well.
    last_sent_packet: Option<IpPacketBuffer>,
    // and this could be a Bytes
    next_packet_to_receive: Option<IpPacketBuffer>,
}

impl TLSCallbacks {
    fn new() -> TLSCallbacks {
        TLSCallbacks {
            last_sent_packet: None,
            next_packet_to_receive: None,
        }
    }

    /// Get the last sent packet, if any.
    fn pop_last_sent_packet(&mut self) -> Option<IpPacketBuffer> {
        std::mem::take(&mut self.last_sent_packet)
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

impl wolfssl::IOCallbacks for TLSCallbacks {
    fn send(&mut self, buf: &[u8]) -> wolfssl::IOCallbackResult<usize> {
        match self.last_sent_packet {
            Some(_) => wolfssl::IOCallbackResult::WouldBlock,
            None => {
                let result = buf.len();
                self.last_sent_packet = Some(IpPacketBuffer::new(buf));
                wolfssl::IOCallbackResult::Ok(result)
            }
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
    use std::collections::LinkedList;

    use crate::array_array::IpPacketBuffer;

    use super::{TLSNegotiateResult, TLSSession};

    /// Test that we can negotiate and send a packet using our wolfssl wrapper
    #[test]
    fn wolfssl_wrapper() {
        let client_context = wolfssl::ContextBuilder::new(wolfssl::Method::DtlsClientV1_3)
            .unwrap()
            .with_pre_shared_key(b"password")
            .build();
        let server_context = wolfssl::ContextBuilder::new(wolfssl::Method::DtlsServerV1_3)
            .unwrap()
            .with_pre_shared_key(b"password")
            .build();

        let mut client = TLSSession::new(&client_context).unwrap();
        let mut server = TLSSession::new(&server_context).unwrap();

        let mut c2s_packets = LinkedList::<IpPacketBuffer>::new();
        let mut s2c_packets = LinkedList::<IpPacketBuffer>::new();

        let mut c_needs_read = false;
        let mut s_needs_read = false;

        //// NEGOTIATE ////
        while !(client.handshake_complete() && server.handshake_complete()) {
            if !client.handshake_complete() {
                println!("About to negotiate from client");
                let read_packet = if c_needs_read {
                    s2c_packets.pop_front()
                } else {
                    None
                };
                if c_needs_read == read_packet.is_some() {
                    match client.try_negotiate(read_packet.as_deref()) {
                        TLSNegotiateResult::Ready(packets) => c2s_packets.extend(packets),
                        TLSNegotiateResult::NeedRead(packets) => {
                            c2s_packets.extend(packets);
                            c_needs_read = true;
                        }
                        e => panic!("Unexpected result from client negotiate: {:#?}", e),
                    }
                }
            }

            if c2s_packets.len() > 0 {
                println!("Client->Server {} packets", c2s_packets.len());
            }

            if !server.handshake_complete() {
                println!("About to negotiate from server");
                let read_packet = if s_needs_read {
                    c2s_packets.pop_front()
                } else {
                    None
                };
                if s_needs_read == read_packet.is_some() {
                    match server.try_negotiate(read_packet.as_deref()) {
                        TLSNegotiateResult::Ready(packets) => s2c_packets.extend(packets),
                        TLSNegotiateResult::NeedRead(packets) => {
                            s2c_packets.extend(packets);
                            s_needs_read = true;
                        }
                        e => panic!("Unexpected result from server negotiate: {:#?}", e),
                    }
                }
            }

            if s2c_packets.len() > 0 {
                println!("Server->Client {} packets", s2c_packets.len());
            }
        }

        assert!(
            c2s_packets.is_empty(),
            "client->server packets should be empty after handshake"
        );
        assert!(
            s2c_packets.is_empty(),
            "server->client packets should be empty after handshake"
        );

        //// CLIENT -> SERVER APPLICATION DATA ////
        let msg = b"howdy howdy lil cutie";
        let c2s_packet = client.try_write(msg).unwrap();
        let roundtripped = server.try_read(&c2s_packet).unwrap();
        assert_eq!(
            &roundtripped[..],
            msg,
            "Roundtripped should equal original msg (client->server)"
        );

        //// SERVER -> CLIENT APPLICATION DATA ////
        let msg2 = b"im buying weed on the internet";
        let s2c_packet = server.try_write(msg2).unwrap();
        let roundtripped2 = client.try_read(&s2c_packet).unwrap();
        assert_eq!(
            &roundtripped2[..],
            msg2,
            "Roundtripped should equal original msg (server->client)"
        );
    }
}
