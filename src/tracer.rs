use libc::pid_t;

use crate::{
    policy::Policy,
    wrapper::{self, ForkResult, PtraceWrapper},
    SeccompError,
};

/// This struct keeps track of Child and Parent after forking
pub(crate) enum TracingHandle {
    /// indicates the child process
    Child,
    /// the parent process
    Parent {
        /// the child_pid
        child_pid: pid_t,
        ///// ptrace wrapper
        // tracer: PtraceWrapper,
        // todo todo todo, am ashamed
        // filters: Vec<Box<dyn RestrictFilter>>,
    },
}
impl Policy {
    /// this forks the current process and returns a `TracingHandle`
    /// before returning the child enables tracing(PTRACE_TRACEME)
    /// TODO(x0rw): move this
    pub(crate) fn spawn_traced(&mut self) -> Result<TracingHandle, SeccompError> {
        let result = PtraceWrapper::fork()?;
        match result.get_process() {
            ForkResult::Child => {
                // child process
                // enable_tracing is setting PTRACE_TRACEME option
                wrapper::PtraceWrapper::with_pid(0).enable_tracing()?;
                return Ok(TracingHandle::Child);
            }
            ForkResult::Parent(pid) => {
                // println!("pid: {_pid}");
                // the caller shoould already have 'trace_rules'
                // let filters = std::mem::take(&mut self.trace_rules);
                return Ok(TracingHandle::Parent {
                    child_pid: pid.to_owned(),
                    // tracer: result,
                });
                // std::process::exit(0);
            }
        }
    }
}
