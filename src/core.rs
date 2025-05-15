use bytes::BytesMut;
use std::net::SocketAddr;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::hardware::Hardware;
use crate::messages::Message;

enum Err {}

type Result<T> = std::result::Result<T, Err>;
type SSLSession = wolfssl::Session<SSLIOCallbacks>;

enum ClientServer {
    Client,
    Server,
}

enum ConnectionState<H: Hardware> {
    NoConnection(NoConnection<H>),
    EstablishedConnection(EstablishedConnection<H>),
}

struct NoConnection<'a, H: Hardware> {
    /// All currently open sockets, which may be at various stages in the DTLS negotiation.
    handshakes: Vec<TLSSession<'a>>
}

/// The part of the core that is mostly client/server agnostic, and is used as soon as a DTLS
/// negotiation finishes.
struct EstablishedConnection<H> {
    client_server: ClientServer,
    socket: H::Socket,
    peer_addr: SocketAddr,

    // messages we'd like to send in the next network packet if at all possible
    pending_outgoing_messages: Vec<Message>,
}

pub(crate) struct Core<H: Hardware> {
    connection: ConnectionState<H>,
}

impl Core {
    pub(crate) fn new() -> Self {
        Core {
            packet_interval_ns: u64,
            packet_length: u64,

            // quite larger than we should need, we only insert one packet of messages at a time
            pending_outgoing_messages: Vec::with_capacity(100),
            // Eventually: scheduled_incoming_messages
        }
    }

    pub(crate) fn on_wake<H: Hardware>(&mut self, hardware: &mut H) -> Result<()> {
        // Is it time to send
    }
}

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
    fn new(session: wolfssl::Session<TLSCallbacks>) -> Self {
        Self {
            underlying: session,
            handshake_complete: false,
            handshake_just_requested_read: false,
        }
    }

    /// Negotiate as far as we can. Pass in the most recently read packet off the network. If we
    /// need more packets, we'll tell you. If the return value indicates packets need to be sent,
    /// please send them. Don't pass in any read packets until requested.
    fn try_negotiate(&mut self, read_packet: Option<&[u8]>) -> TLSNegotiateResult {
        assert!(!self.handshake_complete, "try_negotiate called after handshake already complete");

        match read_packet {
            Some(buf) => {
                assert!(self.handshake_just_requested_read, "try_negotiate received a read_packet but didn't ask for a read");
                self.underlying.io_cb_mut().set_next_packet_to_receive(buf);
            }
            None => (),
        }
        self.handshake_just_requested_read = false;

        let mut written_packets = Vec::new();

        // TODO understand: If I capture `self` instead of taking it as an argument, then the borrow
        // checker complains that add_written_packet has a mutable borrow of `self` for the rest of
        // the function. Why is that the case? Why doesn't the mutable borrow of `self` simply occur
        // when `add_written_packet` is called, rather than being persistent?
        let mut add_written_packet = |session_obj: &mut Self| {
            match session_obj.underlying.io_cb_mut().pop_last_sent_packet() {
                Some(last_sent_packet) => written_packets.push(last_sent_packet),
                None => (),
            }
        };

        loop {
            match self.underlying.try_negotiate() {
                Err(err) => return TLSNegotiateResult::WolfSSLErr(err),
                // We don't use secure renegotiation, so this shouldn't happen!
                Ok(wolfssl::Poll::AppData(_)) => return TLSNegotiateResult::UnexpectedAppData,
                Ok(wolfssl::Poll::PendingWrite) => add_written_packet(self),
                Ok(wolfssl::Poll::PendingRead) => {
                    self.handshake_just_requested_read = true;
                    add_written_packet(self);
                    return TLSNegotiateResult::NeedRead(written_packets);
                },
                Ok(wolfssl::Poll::Ready(())) => {
                    self.handshake_complete = true;
                    add_written_packet(self);
                    return TLSNegotiateResult::Ready(written_packets);
                },
            }
        }
    }

    /// Call try_write on the underlying session, and return the encrypted bytes.
    fn try_write(&mut self, cleartext_packet: &[u8]) -> std::result::Result<IpPacketBuffer, wolfssl::Error> {
        assert!(self.handshake_complete, "Handshake must be complete before calling `try_write`");
        match self.underlying.try_write(&mut bytes_mut)? {
            wolfssl::Poll::Ready(len) => {
                // TODO better pre-checking that packet is the right length to fit in a single IP packet when encrypted
                assert!(len == cleartext_packet.len(), "Only {} bytes of packet of length {} were consumed", len, cleartext_packet.len());
                Ok(self.underlying.io_cb_mut().pop_last_sent_packet().expect("Should be a sent packet after try_write"))
            },
            poll_result => panic!("try_write should always complete immediately, but got {:#?}", poll_result),
        }
    }

    // TODO consider writing the result to an &mut [u8] argument instead
    /// Call try_read on the underlying session, and return the cleartext bytes.
    fn try_read(&mut self, ciphertext_packet: &[u8]) -> std::result::Result<IpPacketBuffer, wolfssl::Error> {
        assert!(self.handshake_complete, "Handshake must be complete before calling `try_read`");
        let mut bytes_mut = bytes::BytesMut::
        self.underlying.try_read(result.as_mut());
    }
}

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
            Some(_) => panic!("set_next_packet_to_receive called even though the last packet to receive was never read!"),
            None => {
                self.next_packet_to_receive = Some(IpPacketBuffer::new(buf));
            },
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
            },
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> wolfssl::IOCallbackResult<usize> {
        match self.next_packet_to_receive.as_ref() {
            Some(next_packet_to_receive) => {
                let result = next_packet_to_receive.len();
                buf.copy_from_slice(next_packet_to_receive);
                self.next_packet_to_receive = None;
                wolfssl::IOCallbackResult::Ok(result)
            },
            None => wolfssl::IOCallbackResult::WouldBlock,
        }
    }
}
