use std::net::SocketAddr;

use crate::hardware::Hardware;

/// An empty core that doesn't register any event listeners or do anything.
pub(crate) struct Core {}

impl Core {
    pub(crate) fn new(hardware: &mut impl Hardware) -> Core {
        // At first, I thought we might not want to clear the listeners here because in a test we
        // might want to install a Core, replace it with a noop for a while, then re-replace it with
        // a Core...but this could break certain expectations of the Core, for example Cores rely on
        // that on_timer is called exactly once per set_timer. Since we don't have a concrete test
        // that does that, let's clear the listeners!
        hardware.clear_event_listeners();
        Core {}
    }
}

impl super::Core for Core {
    fn on_timer(&mut self, _hardware: &mut impl Hardware, _timer_timestamp: u64) {
        panic!("noop core shouldn't have timer triggered");
    }

    fn on_read_outgoing_packet(
        &mut self,
        _hardware: &mut impl Hardware,
        _packet: &[u8],
        _recv_timestamp: u64,
    ) {
        panic!("noop core shouldn't receive outgoing packets");
    }

    fn on_read_incoming_packet(
        &mut self,
        _hardware: &mut impl Hardware,
        _packet: &[u8],
        _peer: SocketAddr,
    ) {
    }
}
