use crate::{
    error::SeccompError,
    policy::Syscall,
    wrapper::{SeccompWrapper, TraceAction},
};

/// seccomp filters
pub mod seccomp;
/// tracer filter(ptrace)
pub mod tracer;
/// define a Restrict filter trait
pub(crate) trait RestrictFilter {
    /// this method defines the behavior of applying a filter on the context(eg, seccomp context)
    fn apply(&self, ctx: &mut SeccompWrapper) -> Result<(), SeccompError>;
    /// getting the syscall
    fn syscall(&self) -> Syscall;
    /// tracer callback
    fn callback(&self) -> Option<&Box<dyn Fn(Syscall) -> TraceAction>> {
        return None;
    }
}
