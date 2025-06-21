use crate::{
    policy::{Action, Syscall},
    wrapper::SeccompWrapper,
    SeccompError,
};

use super::RestrictFilter;

/// seccomp fiters duh!
#[derive(Debug)]
pub(crate) struct SeccompFilter {
    syscall: Syscall,
    action: Action,
}
impl SeccompFilter {
    /// declare a new filter
    pub fn new(syscall: Syscall, action: Action) -> Self {
        Self { syscall, action }
    }
    pub fn syscall(&self) -> Syscall {
        self.syscall
    }

    pub fn action(&self) -> Action {
        self.action
    }
}
impl RestrictFilter for SeccompFilter {
    fn apply(&self, ctx: &mut SeccompWrapper) -> Result<(), SeccompError> {
        ctx.add_rule(self.action, self.syscall)
    }
}
