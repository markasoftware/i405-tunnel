use anyhow::Result;

use crate::hardware::Hardware;

/// An empty core that doesn't register any event listeners or do anything.
pub(crate) struct Core<H: Hardware> {
    hardware: H,
}

impl<'h, H: Hardware + 'h> Core<H> {
    pub(crate) fn new(hardware: H) -> Result<Core<H>> {
        // At first, I thought we might not want to clear the listeners here because in a test we
        // might want to install a Core, replace it with a noop for a while, then re-replace it with
        // a Core...but this could break certain expectations of the Core, for example Cores rely on
        // that on_timer is called exactly once per set_timer. Since we don't have a concrete test
        // that does that, let's clear the listeners!
        hardware.clear_event_listeners()?;
        Ok(Core { hardware })
    }

    pub(crate) fn new_boxed(hardware: H) -> Result<Box<dyn super::Core + 'h>> {
        Self::new(hardware).map(|c| Box::new(c) as _)
    }
}

impl<H: Hardware> super::Core for Core<H> {
    fn on_event(&mut self) {
        if self.hardware.has_user_requested_shutdown() {
            self.hardware.shutdown();
        }
    }
}
