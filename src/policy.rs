pub use crate::{error::SeccompError, syscall::Syscall, wrapper::Action};
use crate::{
    filter::{
        seccomp::{self, SeccompFilter},
        tracer::{TracerFilter, TracerMap},
        RestrictFilter,
    },
    restrict_counter, restrict_info, restrict_warn,
    tracer::TracingHandle,
    wrapper::{PtraceWrapper, SeccompWrapper, TraceAction},
};
use libc::{raise, SIGSTOP};

#[cfg(feature = "logging")]
use tracing_subscriber::fmt;

/// Restrict policy
pub struct Policy {
    context: Option<SeccompWrapper>,
    pub(crate) seccomp_rules: Vec<SeccompFilter>,
    pub(crate) trace_rules: Vec<TracerFilter>,
    trace: bool,
    verbose: bool,
}
/// Policy implementation
impl Policy {
    /// decclare a new filter with default policy
    fn new(default: Action) -> Result<Self, SeccompError> {
        restrict_info!("Declaring a new policy with the default: {default:?}");
        Ok(Self {
            context: Some(SeccompWrapper::init_context(default)?),
            seccomp_rules: Vec::new(),
            trace_rules: Vec::new(),
            trace: false,
            verbose: false,
        })
    }

    /// Allow all syscall by default.
    pub fn allow_all() -> Result<Self, SeccompError> {
        restrict_counter!("restrict.policy.default.allow", 1);
        Self::new(Action::Allow)
    }

    /// Deny all syscalls by default.
    pub fn deny_all() -> Result<Self, SeccompError> {
        restrict_counter!("restrict.policy.default.deny", 1);
        Self::new(Action::Kill)
    }

    /// Syscall fail with a custom error no
    pub fn fail_with(&mut self, syscall: Syscall, errno: u16) -> &mut Self {
        restrict_counter!("restrict.policy.rule.fail", 1,
                 "syscall_name" => format!("{:#?}",syscall), 
                 "errno" => errno.to_string());
        restrict_info!("Fail syscall: {syscall:?} with code: {errno}");
        self.seccomp_rules
            .push(seccomp::SeccompFilter::new(syscall, Action::Errno(errno)));
        self
    }

    /// tracing syscalls
    pub fn trace<T>(&mut self, syscall: Syscall, tracer: T) -> &mut Self
    where
        T: Fn(Syscall) -> TraceAction + 'static,
    {
        restrict_counter!("restrict.policy.rule.trace", 1,
                 "syscall_name" => format!("{:#?}",syscall));
        restrict_info!("Trace syscall: {syscall:?}");
        self.trace_rules.push(TracerFilter::new(syscall, tracer));
        self.trace = true;
        self
    }

    /// allow a syscall
    pub fn allow(&mut self, syscall: Syscall) -> &mut Self {
        restrict_counter!("restrict.policy.rule.allow", 1,
                 "syscall_name" => format!("{:#?}",syscall));
        restrict_info!("Allow syscall: {syscall:?}");
        self.seccomp_rules
            .push(seccomp::SeccompFilter::new(syscall, Action::Allow));
        self
    }

    /// deny a syscall
    pub fn deny(&mut self, syscall: Syscall) -> &mut Self {
        restrict_counter!("restrict.policy.rule.deny", 1,
                 "syscall_name" => format!("{:#?}",syscall));
        self.seccomp_rules
            .push(seccomp::SeccompFilter::new(syscall, Action::Kill));
        self
    }
    /// disable io-uring bypass
    pub fn disable_iouring_bypass(&mut self) -> &mut Self {
        restrict_counter!("restrict.policy.disaable.iouring", 1);
        restrict_warn!("Disable IoUring bypass");
        self.deny(Syscall::IoUringEnter)
            .deny(Syscall::IoUringSetup)
            .deny(Syscall::IoUringRegister)
    }
    /// apply
    pub fn apply(&mut self) -> Result<(), SeccompError> {
        let mut context = self.context.take().ok_or(SeccompError::Fork)?;
        // in bpf the order of filters is important
        // but we shouldn't care because we ensure no conflicts happen

        // apply seccomp rules
        for filter in self.seccomp_rules.iter() {
            restrict_info!(format!(
                "Applying {:?} filter for {:?}",
                filter.action(),
                filter.syscall()
            ));
            filter.apply(&mut context)?;
        }
        // apply seccomp TRACE rule specificallt
        for filter in self.trace_rules.iter() {
            restrict_info!(format!(
                "[+] Applying Traceing filter for {:?}",
                filter.syscall()
            ));
            filter.apply(&mut context)?;
        }
        if self.trace {
            // Fork the current process:
            // - The parent enters an event loop to trace system calls made by the child.
            // - The child sets ptrace options and installs the seccomp filter,
            //   then returns immediately to avoid blocking the parent.
            //
            // Important notes:
            // - If the child crashes or receives an unexpected signal, it exits
            //   immediately to prevent leaving behind a zombie process.

            restrict_info!("[+] Forking the current process");

            restrict_counter!("restrict.policy.action.fork", 1);
            let spawned = self.spawn_traced().unwrap();
            match spawned {
                TracingHandle::Child => {
                    restrict_info!("== [Child-process]: tracing is enabled(PTRACE_TRACEME)");
                    restrict_info!("== [Child-process]: Raising SIGSTOP signal to sync with the parent process");
                    // here tracing is already enabled
                    //
                    //loading the context in the child(only)

                    // - The child raises a SIGSTOP to sync with the parent
                    unsafe { raise(SIGSTOP) };

                    restrict_counter!("restrict.policy.action.child_process.sigstop", 1);
                    // After this point the parent and the child are in sync so we
                    // load the accumulated filters and start tracing
                    context.load()?;

                    restrict_info!("== [Child-process]: Synced, LOADING filters succeded");
                }
                TracingHandle::Parent {
                    child_pid,
                    // filters: _,
                } => {
                    // this is more 'verbosy' atm.
                    // here goes the event loop //
                    // wait for sync signal from the child

                    restrict_info!("[Parent-process]: Waiting for sync signal");
                    PtraceWrapper::with_pid(child_pid).wait_for_signal(SIGSTOP)?;
                    PtraceWrapper::with_pid(child_pid).set_traceseccomp_option()?;
                    PtraceWrapper::with_pid(child_pid).syscall_trace()?;

                    restrict_counter!("restrict.policy.action.install_seccompfilters", 1);

                    restrict_info!("[Parent-process]: Synced successfully");
                    // now its finally time for the loop

                    let trace_r = std::mem::take(&mut self.trace_rules);
                    let mapped_tracers = TracerMap::from(trace_r);

                    restrict_info!("[Parent-process]: Listening to incoming syscalls from child process: {child_pid}");
                    PtraceWrapper::with_pid(child_pid).event_loop(mapped_tracers)?;

                    restrict_counter!("restrict.policy.action.parent.exit", 1);
                    std::process::exit(0);
                }
            }
        } else {
            restrict_info!("[+] Loading Seccomp Context");
            // if there is no tracing just load the filters directly
            context.load()?;
        }
        Ok(())
    }
    /// verbose mode
    pub fn verbose(mut self, enable: bool) -> Self {
        self.verbose = enable;
        #[cfg(not(feature = "logging"))]
        eprintln!("'loading' feature is not enabled for verbose() to work");
        #[cfg(feature = "logging")]
        if enable {
            let _subscriber = fmt::Subscriber::builder()
                .with_writer(std::io::stderr)
                .with_thread_ids(true)
                .compact()
                .init();
        }
        self
    }
}
