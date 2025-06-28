use crate::{
    interceptor::Interceptor,
    policy::{Action, Syscall},
    wrapper::{SeccompWrapper, TraceAction},
    SeccompError,
};

use super::RestrictFilter;

/// seccomp fiters duh!
pub(crate) struct InterceptorFilter {
    syscall: Syscall,
    callback: Box<dyn Fn(Interceptor) -> TraceAction>,
}

// impl Debug for TracerFilter {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         write!(f, "TracerFilter({:?}), ", self.syscall)
//     }
// }
impl InterceptorFilter {
    /// declare a new filter
    pub fn new<F>(syscall: Syscall, callback: F) -> Self
    where
        F: Fn(Interceptor) -> TraceAction + 'static,
    {
        Self {
            syscall,
            callback: Box::new(callback),
        }
    }

    pub fn syscall(&self) -> Syscall {
        self.syscall
    }

    pub fn to_map(self) -> (Syscall, Box<dyn Fn(Interceptor) -> TraceAction>) {
        (self.syscall, self.callback)
    }
}
impl RestrictFilter for InterceptorFilter {
    fn apply(&self, ctx: &mut SeccompWrapper) -> Result<(), SeccompError> {
        ctx.add_rule(Action::Trace, self.syscall)
    }
}
/// This is the struct that holds all the syscalls with their handlers
/// it can be optimised to be more performant
pub struct InterceptorMap(Vec<(Syscall, Box<dyn Fn(Interceptor) -> TraceAction>)>);
use core::fmt::Debug;
impl Debug for InterceptorMap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TracerMap({}), ", self.0.len())
    }
}
impl InterceptorMap {
    /// Build this type from a vec of filters
    pub(crate) fn from(intercepters_vec: Vec<InterceptorFilter>) -> Self {
        InterceptorMap(
            intercepters_vec
                .into_iter()
                .map(|x| x.to_map())
                .collect::<Vec<_>>(),
        )
    }
    /// find a syscall
    pub fn find_by_syscall(
        &self,
        syscall: Syscall,
    ) -> Option<&Box<dyn Fn(Interceptor) -> TraceAction>> {
        self.0.iter().find(|(s, _)| *s == syscall).map(|(_, cb)| cb)
    }
}
