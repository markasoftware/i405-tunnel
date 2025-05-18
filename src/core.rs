use std::net::SocketAddr;

use crate::hardware::Hardware;
use crate::messages::Message;
use crate::dtls::{DTLSNegotiatingSession, DTLSEstablishedSession};

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

