use crate::{
    policy::{Action, Syscall},
    wrapper::{SeccompWrapper, TraceAction},
    SeccompError,
};

use super::RestrictFilter;

/// seccomp fiters duh!
pub struct TracerFilter {
    syscall: Syscall,
    callback: Box<dyn Fn(Syscall) -> TraceAction>,
}
impl TracerFilter {
    /// declare a new filter
    pub fn new<F>(syscall: Syscall, callback: F) -> Self
    where
        F: Fn(Syscall) -> TraceAction + 'static,
    {
        Self {
            syscall,
            callback: Box::new(callback),
        }
    }
}
impl RestrictFilter for TracerFilter {
    fn apply(&self, ctx: &mut SeccompWrapper) -> Result<(), SeccompError> {
        ctx.add_rule(Action::Trace, self.syscall)
    }
    fn syscall(&self) -> Syscall {
        self.syscall
    }
    fn callback(&self) -> Option<&Box<dyn Fn(Syscall) -> TraceAction>> {
        Some(&self.callback)
    }
}
