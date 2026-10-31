use std::net::SocketAddr;

use anyhow::Result;

use crate::hardware::Hardware;

/// An empty core that doesn't register any event listeners or do anything.
pub(crate) struct Core {}

impl Core {
    pub(crate) fn new(hardware: &impl Hardware) -> Result<Core> {
        // At first, I thought we might not want to clear the listeners here because in a test we
        // might want to install a Core, replace it with a noop for a while, then re-replace it with
        // a Core...but this could break certain expectations of the Core, for example Cores rely on
        // that on_timer is called exactly once per set_timer. Since we don't have a concrete test
        // that does that, let's clear the listeners!
        hardware.clear_event_listeners()?;
        Ok(Core {})
    }
}

impl super::Core for Core {
    fn on_event(&mut self, hardware: &impl Hardware) {
        if hardware.has_user_requested_shutdown() {
            hardware.shutdown();
        }
    }
}
