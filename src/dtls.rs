/// More ergonomic wrappers around wolfssl-rs DTLS that closely fit our usecase. Rather than a
/// single "context" object which lives through the entire DTLS connection lifecycle, this crate has
/// a DTLSNegotiatingSession that you should construct first. Then, call `make_progress` on this
/// negotiating session until it turns into a DTLSEstablishedSession. The DTLSEstablishedSession has
/// a very simple and usable interface that abstracts over the "IO Callbacks" that wolfssl (and most
/// other TLS libraries) like to think about: Simply `encrypt_datagram(cleartext_packet) ->
/// ciphertext_packet` or `decrypt_datagram(ciphertext_packet) -> cleartext_packet`.
///
/// Not sure where to put this comment, so putting it here: wolfSSL internally has a function
/// LowResTimer that it uses to get...the low resolution time. It's possible to configure this to a
/// user-defined function at compile time, but we don't, since its default behavior is honestly good
/// enough for us. This timer is used for things like checking certificat expiry, and, importantly,
/// ensuring that DTLS doesn't retransmit more than once per second. This affects our tests because
/// it means we can't test multiple packet drops from the same side of the connection. But since
/// this is really the only complication, I'm fine not doing the work to change wolfSSL compile time
/// to insert a custom time function. But I do think this is a design issue on their part, and that
/// it should be part of the IO callbacks to simplify things for users.
// TODO add logging and tests for DTLS timestamps
use thiserror::Error;

use crate::{array_array::IpPacketBuffer, constants::MAX_IP_PACKET_LENGTH};

pub(crate) struct NegotiatingSession {
    underlying: wolfssl::Session<IOCallbacks>,
}

impl std::fmt::Debug for NegotiatingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NegotiatingSession(...)")
    }
}

impl NegotiatingSession {
    /// Construct a new client, and also returns the initial handshake packets that should be sent and the first timeout.
    pub(crate) fn new_client(
        pre_shared_key: &[u8],
        timestamp: u64,
    ) -> Result<(Self, Vec<IpPacketBuffer>, u64), NewSessionError> {
        let wolf_session = wolfssl::ContextBuilder::new(wolfssl::Method::DtlsClientV1_3)?
            .with_pre_shared_key(pre_shared_key)
            .build()
            .new_session(wolfssl::SessionConfig::new(IOCallbacks::new()))?;
        let session = NegotiatingSession {
            underlying: wolf_session,
        };
        match session.inner_try_negotiate(None, timestamp) {
            NegotiateResult::Ready(_, _) => Err(NewSessionError::ReadyImmediately),
            NegotiateResult::NeedRead(new_session, packets, next_timeout) => {
                Ok((new_session, packets, next_timeout))
            }
            NegotiateResult::Err(e) => Err(NewSessionError::from(e)),
        }
    }

    /// There's no initial timeout for the server, since it's just waiting for a client.
    pub(crate) fn new_server(pre_shared_key: &[u8]) -> Result<Self, NewSessionError> {
        let session = wolfssl::ContextBuilder::new(wolfssl::Method::DtlsServerV1_3)?
            .with_pre_shared_key(pre_shared_key)
            .build()
            .new_session(wolfssl::SessionConfig::new(IOCallbacks::new()))?;
        Ok(NegotiatingSession {
            underlying: session,
        })
    }

    fn add_written_packet(&mut self, vec: &mut Vec<IpPacketBuffer>) {
        if let Some(last_sent_packet) = self.underlying.io_cb_mut().pop_last_sent_packet() {
            vec.push(last_sent_packet);
        }
    }

    /// Negotiate as far as we can. Pass in the most recently read packet off the network. If we
    /// need more packets, we'll tell you. If the return value indicates packets need to be sent,
    /// please send them.
    fn inner_try_negotiate(
        mut self,
        read_packet: Option<&[u8]>,
        timestamp: u64,
    ) -> NegotiateResult {
        if let Some(packet) = read_packet {
            self.underlying
                .io_cb_mut()
                .set_next_packet_to_receive(packet);
        }

        let mut written_packets = Vec::new();

        loop {
            match self.underlying.try_negotiate() {
                Err(err) => return NegotiateResult::Err(NegotiateError::WolfError(err)),
                // We don't use secure renegotiation, so this shouldn't happen!
                Ok(wolfssl::Poll::AppData(_)) => {
                    return NegotiateResult::Err(NegotiateError::UnexpectedAppData);
                }
                Ok(wolfssl::Poll::PendingWrite) => self.add_written_packet(&mut written_packets),
                Ok(wolfssl::Poll::PendingRead) => {
                    self.add_written_packet(&mut written_packets);
                    let next_timeout = self.next_timeout(timestamp);
                    return NegotiateResult::NeedRead(self, written_packets, next_timeout);
                }
                Ok(wolfssl::Poll::Ready(())) => {
                    self.add_written_packet(&mut written_packets);
                    return NegotiateResult::Ready(
                        EstablishedSession {
                            underlying: self.underlying,
                        },
                        written_packets,
                    );
                }
            }
        }
    }

    fn next_timeout(&mut self, current_timestamp: u64) -> u64 {
        current_timestamp
            + TryInto::<u64>::try_into(self.underlying.dtls_current_timeout().as_nanos()).unwrap()
    }

    pub(crate) fn make_progress(self, read_packet: &[u8], timestamp: u64) -> NegotiateResult {
        self.inner_try_negotiate(Some(read_packet), timestamp)
    }

    /// Call if the timeout returned from the constructor or `make_progress` expires.
    pub(crate) fn has_timed_out(
        mut self,
        timestamp: u64,
    ) -> Result<(NegotiatingSession, Vec<IpPacketBuffer>, u64), NegotiateError> {
        // dtls_has_timed_out, if blocked by a PendingWrite, won't do anything the next time it's
        // called -- you're supposed to enter back into a negotiation loop. So that's what we do!

        let mut written_packets = Vec::new();

        match self.underlying.dtls_has_timed_out() {
            wolfssl::Poll::Ready(false) => self.add_written_packet(&mut written_packets),
            wolfssl::Poll::PendingWrite => self.add_written_packet(&mut written_packets),
            wolfssl::Poll::PendingRead => {
                return Err(NegotiateError::PendingReadDuringTimeout);
            }
            wolfssl::Poll::AppData(_) => {
                return Err(NegotiateError::UnexpectedAppData);
            }
            // this means some wolfssl error, but the wolfssl-rs api won't tell us which :|
            wolfssl::Poll::Ready(true) => {
                return Err(NegotiateError::UnknownWolfErrorDuringTimeout);
            }
        }

        // this is a bit annoying, because we have to add the at-most-1 packet that was written
        // during timeout handling onto those returned by negotiation.
        match self.inner_try_negotiate(None, timestamp) {
            // I believe this would be a state machine error:
            NegotiateResult::Ready(_, _) => Err(NegotiateError::NegotiationReadyDuringTimeout),
            NegotiateResult::NeedRead(new_session, later_written_packets, timeout) => {
                written_packets.extend(later_written_packets);
                Ok((new_session, written_packets, timeout))
            }
            NegotiateResult::Err(e) => Err(e),
        }
    }
}

#[derive(Error, Debug)]
pub(crate) enum NewSessionError {
    // TODO why do we need these error() messages? The docs make it seem like you don't when you have #[from]
    #[error("NewSessionError {0:?}")]
    WolfNewSessionError(#[from] wolfssl::NewSessionError),
    #[error("NewContextBuilderError {0:?}")]
    WolfNewContextBuilderError(#[from] wolfssl::NewContextBuilderError),
    #[error("NegotiateError {0:?}")]
    NegotiateError(#[from] NegotiateError),
    #[error("Negotiation was reported as complete immediately upon session creation??")]
    ReadyImmediately,
}

#[derive(Error, Debug)]
pub(crate) enum NegotiateError {
    // TODO also why do we need these error() messages? (see above)
    #[error("wolfSSL error {0:?}")]
    WolfError(#[from] wolfssl::Error),
    #[error("Unexpected AppData during negotiation")]
    UnexpectedAppData,
    #[error("wolfSSL error during DTLS timeout (no further details available)")]
    UnknownWolfErrorDuringTimeout,
    #[error("wolfSSL tried to read during DTLS timeout")]
    PendingReadDuringTimeout,
    #[error("Negotiation finished during timeout processing???")]
    NegotiationReadyDuringTimeout,
}

#[derive(Debug)]
pub(crate) enum NegotiateResult {
    /// Negotiation is completely done as soon as you send these packets!
    Ready(EstablishedSession, Vec<IpPacketBuffer>),
    /// Send these packets, then read more packets and get back to us. Last tuple element is the timeout timestamp.
    NeedRead(NegotiatingSession, Vec<IpPacketBuffer>, u64),
    Err(NegotiateError),
}

pub(crate) struct EstablishedSession {
    underlying: wolfssl::Session<IOCallbacks>,
}

impl std::fmt::Debug for EstablishedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "EstablishedSession(...)")
    }
}

impl EstablishedSession {
    /// Call try_write on the underlying session, and return the encrypted bytes.
    pub(crate) fn encrypt_datagram(
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
    pub(crate) fn decrypt_datagram(
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
struct IOCallbacks {
    // could make this a teensy bit faster by having a BytesMut instead that we can write to, but oh
    // well.
    last_sent_packet: Option<IpPacketBuffer>,
    // and this could be a Bytes
    next_packet_to_receive: Option<IpPacketBuffer>,
}

impl IOCallbacks {
    fn new() -> IOCallbacks {
        IOCallbacks {
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

impl wolfssl::IOCallbacks for IOCallbacks {
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
    use crate::array_array::IpPacketBuffer;

    use super::{EstablishedSession, NegotiateResult, NegotiatingSession};

    fn negotiate_multiple_packets<'a>(
        mut session: NegotiatingSession,
        packets: impl std::iter::IntoIterator<Item = &'a IpPacketBuffer>,
        timestamp: u64,
    ) -> NegotiateResult {
        let mut out_packets = Vec::new();
        let mut new_timeout = None;
        for packet in packets {
            match session.make_progress(&packet, timestamp) {
                NegotiateResult::NeedRead(new_session, cur_out_packets, cur_new_timeout) => {
                    out_packets.extend(cur_out_packets);
                    new_timeout = Some(cur_new_timeout);
                    session = new_session;
                }
                NegotiateResult::Ready(new_session, cur_out_packets) => {
                    out_packets.extend(cur_out_packets);
                    return NegotiateResult::Ready(new_session, out_packets);
                }
                e => panic!("Unexpected NegotiateResult: {:?}", e),
            }
        }
        NegotiateResult::NeedRead(
            session,
            out_packets,
            new_timeout.expect("`packets` should not be empty"),
        )
    }

    /// Make handshake progress, asserting that the handshake is not complete.
    fn make_progress(
        session: NegotiatingSession,
        incoming_packets: &Vec<IpPacketBuffer>,
        timestamp: u64,
    ) -> (NegotiatingSession, Vec<IpPacketBuffer>, u64) {
        match negotiate_multiple_packets(session, incoming_packets, timestamp) {
            NegotiateResult::NeedRead(new_session, outgoing_packets, new_timeout) => {
                (new_session, outgoing_packets, new_timeout)
            }
            NegotiateResult::Ready(_, _) => panic!("Ready too early"),
            e => panic!("Unexpected result {:?}", e),
        }
    }

    /// Make handshake progress, asserting that the handshake is complete at the end.
    fn make_progress_final(
        session: NegotiatingSession,
        incoming_packets: &Vec<IpPacketBuffer>,
    ) -> (EstablishedSession, Vec<IpPacketBuffer>) {
        // timestamp doesn't matter here, since we're final
        match negotiate_multiple_packets(session, incoming_packets, 0) {
            NegotiateResult::NeedRead(_, _, _) => panic!("Not ready in time"),
            NegotiateResult::Ready(new_session, outgoing_packets) => {
                (new_session, outgoing_packets)
            }
            e => panic!("Unexpected result {:?}", e),
        }
    }

    #[test]
    fn negotiate_and_roundtrip() {
        #[cfg(feature = "wolfssl-debug")]
        wolfssl::enable_debugging(true);

        let psk = b"password";

        // I'm not sure why so many roundtrips are necessary. My understanding is there need to only
        // be 2 completed handshake roundtrips, and then the client can start sending application
        // data on the 3rd roundtrip. And with PSK, I think this should, if anything, be even
        // faster. However, as you can see here, there are 3 roundtrips before we start sending
        // data. I'm not super inclined to dig into it. At one point I thought this might be caused
        // by the weird way we're doing the IO callbacks, and maybe if the IO write callback blocks
        // a lot, wolfSSL decides to just wait for ACKs rather than proceeding with a flight...but I
        // have a branch where I changed the IO callbacks to have a buffer of 10 packets instead of
        // 1, and the behavior is the same.
        let server = NegotiatingSession::new_server(psk).unwrap();
        let (client, c2s_packets, _) = NegotiatingSession::new_client(psk, 0).unwrap();

        let (server, s2c_packets, _) = make_progress(server, &c2s_packets, 0);
        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);
        let (server, s2c_packets, _) = make_progress(server, &c2s_packets, 0);
        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);
        let (mut server, s2c_packets) = make_progress_final(server, &c2s_packets);
        let (mut client, c2s_packets) = make_progress_final(client, &s2c_packets);

        assert!(
            c2s_packets.is_empty(),
            "Client shouldn't send any packets to finish the connection"
        );

        //// CLIENT -> SERVER APPLICATION DATA ////
        let msg = b"howdy howdy lil cutie";
        let c2s_packet = client.encrypt_datagram(msg).unwrap();
        let roundtripped = server.decrypt_datagram(&c2s_packet).unwrap();
        assert_eq!(
            &roundtripped[..],
            msg,
            "Roundtripped should equal original msg (client->server)"
        );

        //// SERVER -> CLIENT APPLICATION DATA ////
        let msg2 = b"im buying weed on the internet";
        let s2c_packet = server.encrypt_datagram(msg2).unwrap();
        let roundtripped2 = client.decrypt_datagram(&s2c_packet).unwrap();
        assert_eq!(
            &roundtripped2[..],
            msg2,
            "Roundtripped should equal original msg (server->client)"
        );
    }

    #[test]
    fn timeout_dropped_client_packet() {
        #[cfg(feature = "wolfssl-debug")]
        wolfssl::enable_debugging(true);

        let psk = b"password";

        let server = NegotiatingSession::new_server(psk).unwrap();
        // drop an initial handshake message
        let (client, _, _) = NegotiatingSession::new_client(psk, 0).unwrap();
        let (client, c2s_packets, _) = client.has_timed_out(0).unwrap();
        assert!(!c2s_packets.is_empty());
        let (server, s2c_packets, _) = make_progress(server, &c2s_packets, 0);
        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);
        let (server, s2c_packets, _) = make_progress(server, &c2s_packets, 0);
        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);
        let (_, s2c_packets) = make_progress_final(server, &c2s_packets);
        make_progress_final(client, &s2c_packets);
    }

    // this one requires us to sleep for a couple seconds in order to get past the rtx timer
    // described at the top of this file. Honestly, I'm very confused about the exact details of the
    // behavior wolfSSL exhibits in this test; I originally wanted only to drop one of the client
    // initial handshake messages, then drop one of the server responses later, then continue the
    // rest like usual. However, after the server drops, it only wants to send /2/ packets instead
    // of 3 that it sent before the timeout, which isn't enough for the client to say anything back.
    // Maybe because wolf doesn't think it's likely all 3 packets would be dropped at the same time,
    // and is optimizing for a case where say only the first or second packet got dropped? Anyway,
    // if we simulate everyone involved having timeouts and retransimtting stuff, it eventually
    // works.
    #[test]
    #[ignore]
    fn timeout_more_dropped_packets() {
        #[cfg(feature = "wolfssl-debug")]
        wolfssl::enable_debugging(true);

        let psk = b"password";

        let server = NegotiatingSession::new_server(psk).unwrap();

        // drop an initial handshake message
        let (client, _, _) = NegotiatingSession::new_client(psk, 0).unwrap();
        let (client, c2s_packets, _) = client.has_timed_out(0).unwrap();
        assert!(!c2s_packets.is_empty());

        let (server, s2c_packets, _) = make_progress(server, &c2s_packets, 0);

        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);

        // now drop a server message
        let (server, _, _) = make_progress(server, &c2s_packets, 0);
        // this first one will be empty due to fast retry crap
        let (server, s2c_packets, _) = server.has_timed_out(0).unwrap();
        assert!(s2c_packets.is_empty());
        let (server, s2c_packets, _) = server.has_timed_out(0).unwrap();
        // usually two packets here, instead of the 3 that would have originally been sent. REALLY
        // not sure why that is.
        assert!(!s2c_packets.is_empty());

        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);
        // honestly not sure why the client isn't able to respond just because there's 1 fewer s2c
        // packet than usual.
        assert!(c2s_packets.is_empty());
        let (client, c2s_packets, _) = client.has_timed_out(0).unwrap();
        assert!(!c2s_packets.is_empty());

        let (server, s2c_packets, _) = make_progress(server, &c2s_packets, 0);
        assert!(s2c_packets.is_empty());
        // the server already did some retransmitting not long ago, so we have to do this to get it
        // to retransmit again.
        std::thread::sleep(std::time::Duration::from_secs(2));
        let (server, s2c_packets, _) = server.has_timed_out(0).unwrap();
        assert!(!s2c_packets.is_empty());

        let (client, c2s_packets, _) = make_progress(client, &s2c_packets, 0);
        let (_, s2c_packets) = make_progress_final(server, &c2s_packets);
        make_progress_final(client, &s2c_packets);
    }
}
