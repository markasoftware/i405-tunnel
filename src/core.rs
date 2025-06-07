use std::net::SocketAddr;

use declarative_enum_dispatch::enum_dispatch;

use crate::hardware::Hardware;

pub(crate) mod client;
mod established_connection;
pub(crate) mod noop;
pub(crate) mod server;
#[cfg(test)]
mod test;

const PROTOCOL_VERSION: u32 = 0;
const OLDEST_COMPATIBLE_PROTOCOL_VERSION: u32 = 0;

/// C2S handshake will be resent after this long if S2C handshake not received, then exponentially
/// backs off.
const C2S_RETRANSMIT_TIMEOUT: u64 = 1_000_000_000;
/// How many times to retransmit the C2S handshake before failing.
const C2S_MAX_RETRANSMITS: u32 = 4;
const C2S_MAX_TIMEOUT: u64 = 60_000_000_000;

// Core is not dyn-compatible because it's generic on Hardware
enum_dispatch! {
    pub(crate) trait Core {
        fn on_timer(&mut self, hardware: &mut impl Hardware, timer_timestamp: u64);
        fn on_read_outgoing_packet(
            &mut self,
            hardware: &mut impl Hardware,
            packet: &[u8],
            recv_timestamp: u64,
        );
        fn on_read_incoming_packet(&mut self, hardware: &mut impl Hardware, packet: &[u8], peer: SocketAddr);
    }

    pub(crate) enum ConcreteCore {
        Client(client::Core),
        Server(server::Core),
        NoOp(noop::Core)
    }
}
