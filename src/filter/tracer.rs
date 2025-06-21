use crate::{
    policy::{Action, Syscall},
    wrapper::{SeccompWrapper, TraceAction},
    SeccompError,
};

use super::RestrictFilter;

/// seccomp fiters duh!
pub(crate) struct TracerFilter {
    syscall: Syscall,
    callback: Box<dyn Fn(Syscall) -> TraceAction>,
}

impl Debug for TracerFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TracerFilter({:?}), ", self.syscall)
    }
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

    pub fn syscall(&self) -> Syscall {
        self.syscall
    }

    pub fn to_map(self) -> (Syscall, Box<dyn Fn(Syscall) -> TraceAction>) {
        (self.syscall, self.callback)
    }
}
impl RestrictFilter for TracerFilter {
    fn apply(&self, ctx: &mut SeccompWrapper) -> Result<(), SeccompError> {
        ctx.add_rule(Action::Trace, self.syscall)
    }
}
/// This is the struct that holds all the syscalls with their handlers
/// it can be optimised to be more performant
pub struct TracerMap(Vec<(Syscall, Box<dyn Fn(Syscall) -> TraceAction>)>);
use core::fmt::Debug;
impl Debug for TracerMap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TracerMap({}), ", self.0.len())
    }
}
impl TracerMap {
    /// Build this type from a vec of filters
    pub(crate) fn from(tracers_vec: Vec<TracerFilter>) -> Self {
        TracerMap(
            tracers_vec
                .into_iter()
                .map(|x| x.to_map())
                .collect::<Vec<_>>(),
        )
    }
    /// find a syscall
    pub fn find_by_syscall(
        &self,
        syscall: Syscall,
    ) -> Option<&Box<dyn Fn(Syscall) -> TraceAction>> {
        self.0.iter().find(|(s, _)| *s == syscall).map(|(_, cb)| cb)
    }
}
