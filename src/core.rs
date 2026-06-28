use declarative_enum_dispatch::enum_dispatch;

use crate::hardware::Hardware;

pub(crate) mod client;
mod established_connection;
#[cfg(test)]
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
        /// When the hardware state changes in such a way that the output of a method on the
        /// Hardware's output would be different than that at the last time on_event was called in a
        /// way that may unblock the core. For example, if a read of an outgoing packet has been
        /// requested, and a new one is read, on_event will be called shortly afterwards. However,
        /// if the timestamp has changed (but no timer has been triggered) on_event will not be
        /// called. Importantly, if multiple "events" have happened (eg, timer triggered + new
        /// outgoing packet readable), on_event will /not/ necessarily be called multiple times;
        /// this is standard practice for this kind of pattern (eg look at zeromq's documentation
        /// for the situations in which the file descriptor associated with a zmq socket will become
        /// readable). Therefore, the correct pattern to follow is: Every time on_event is called,
        /// call every method on the Hardware that you could possibly be interested in until all
        /// changes have been accounted for. If you do so, you will have handled at least all the
        /// events that caused this on_event call, and anything further will trigger another
        /// on_event call. The anti-pattern is to only try and process one event per on_event call
        /// (do NOT do that).
        fn on_event(&mut self, hardware: &impl Hardware);
    }

    pub(crate) enum ConcreteCore {
        Client(client::Core),
        Server(server::Core),
        #[cfg(test)]
        NoOp(noop::Core)
    }
}
