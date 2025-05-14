use libc::{raise, SIGSTOP};

pub use crate::{error::SeccompError, syscall::Syscall, wrapper::Action};
use crate::{
    filter::{
        seccomp::{self, SeccompFilter},
        tracer::{TracerFilter, TracerMap},
        RestrictFilter,
    },
    tracer::TracingHandle,
    wrapper::{PtraceWrapper, SeccompWrapper, TraceAction},
};

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
        Self::new(Action::Allow)
    }

    /// Deny all syscalls by default.
    pub fn deny_all() -> Result<Self, SeccompError> {
        Self::new(Action::Kill)
    }

    /// Syscall fail with a custom error no
    pub fn fail_with(&mut self, syscall: Syscall, errno: u16) -> &mut Self {
        self.seccomp_rules
            .push(seccomp::SeccompFilter::new(syscall, Action::Errno(errno)));
        self
    }

    /// tracing syscalls
    pub fn trace<T>(&mut self, syscall: Syscall, tracer: T) -> &mut Self
    where
        T: Fn(Syscall) -> TraceAction + 'static,
    {
        self.trace_rules.push(TracerFilter::new(syscall, tracer));
        self.trace = true;
        self
    }

    /// allow a syscall
    pub fn allow(&mut self, syscall: Syscall) -> &mut Self {
        self.seccomp_rules
            .push(seccomp::SeccompFilter::new(syscall, Action::Allow));
        self
    }

    /// deny a syscall
    pub fn deny(&mut self, syscall: Syscall) -> &mut Self {
        self.seccomp_rules
            .push(seccomp::SeccompFilter::new(syscall, Action::Kill));
        self
    }
    /// apply
    pub fn apply(&mut self) -> Result<(), SeccompError> {
        let mut context = self.context.take().ok_or(SeccompError::Fork)?;
        // in bpf the order of filters is important
        // but we shouldn't care because we ensure no conflicts happen

        // apply seccomp rules
        for filter in self.seccomp_rules.iter() {
            if self.verbose {
                println!(
                    "[+] Applying {:?} filter for {:?}",
                    filter.action(),
                    filter.syscall()
                );
            }
            filter.apply(&mut context)?;
        }
        // apply seccomp TRACE rule specificallt
        for filter in self.trace_rules.iter() {
            if self.verbose {
                println!("[+] Applying Traceing filter for {:?}", filter.syscall());
            }
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

            if self.verbose {
                println!("[+] Forking the current process");
            }
            let spawned = self.spawn_traced().unwrap();
            match spawned {
                TracingHandle::Child => {
                    if self.verbose {
                        println!("== [Child-process]: tracing is enabled(PTRACE_TRACEME)");
                        println!("== [Child-process]: Raising SIGSTOP signal to sync with the parent process");
                    }
                    // here tracing is already enabled
                    //
                    //loading the context in the child(only)

                    // - The child raises a SIGSTOP to sync with the parent
                    unsafe { raise(SIGSTOP) };
                    // After this point the parent and the child are in sync so we
                    // load the accumulated filters and start tracing
                    context.load()?;

                    if self.verbose {
                        println!("== [Child-process]: Synced, LOADING filters succeded");
                    }
                }
                TracingHandle::Parent {
                    child_pid,
                    // filters: _,
                } => {
                    // this is more 'verbosy' atm.
                    // here goes the event loop //
                    // wait for sync signal from the child

                    if self.verbose {
                        println!("[Parent-process]: Waiting for sync signal");
                    }
                    PtraceWrapper::with_pid(child_pid).wait_for_signal(SIGSTOP)?;
                    PtraceWrapper::with_pid(child_pid).set_traceseccomp_option()?;
                    PtraceWrapper::with_pid(child_pid).syscall_trace()?;

                    if self.verbose {
                        println!("[Parent-process]: Synced successfully");
                    }
                    // now its finally time for the loop

                    let trace_r = std::mem::take(&mut self.trace_rules);
                    let mapped_tracers = TracerMap::from(trace_r);

                    if self.verbose {
                        println!("[Parent-process]: Listening to incoming syscalls");
                    }
                    PtraceWrapper::with_pid(child_pid).event_loop(mapped_tracers)?;

                    std::process::exit(0);
                }
            }
        } else {
            println!("[+] Loading Seccomp Context");
            // if there is no tracing just load the filters directly
            context.load()?;
        }
        Ok(())
    }
    /// verbose mode
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }
}

// }
// /// /// Seccomp filters of syscall and actions
// /// #[derive()]
// /// pub struct SeccompFilter {
// ///     syscall: Syscall,
// ///     action: Action,
// ///     /// Tracer callback
// ///     pub tracer: Option<Box<dyn Fn(Syscall) -> TraceAction>>,
// /// }
// ///
// /// impl SeccompFilter {
// ///     /// Print the filter
// ///     pub fn print(&self) {
// ///         println!(
// ///             "Syscall: {:?} -- Action: {:?}",
// ///             self.get_syscall(),
// ///             self.get_action()
// ///         );
// ///     }
// ///     /// Declare a new filter
// ///     const fn new(syscall: Syscall, action: Action) -> Self {
// ///         Self {
// ///             syscall,
// ///             action,
// ///             tracer: None,
// ///         }
// ///     }
// ///
// ///     fn new_tracer<T>(syscall: Syscall, default_action: Action, handler: T) -> Self
// ///     where
// ///         T: Fn(Syscall) -> TraceAction + 'static,
// ///     {
// ///         Self {
// ///             syscall,
// ///             action: default_action,
// ///             tracer: Some(Box::new(handler)),
// ///         }
// ///     }
// ///     /// get this filter's target syscall
// ///     fn get_syscall(&self) -> Syscall {
// ///         return self.syscall;
// ///     }
// ///
// ///     /// get this filter's action
// ///     fn get_action(&self) -> Action {
// ///         return self.action;
// ///     }
// /// }
//
// #[derive()]
// Policy manager struct to keep track of all the filters
// pub struct Policy {
//     rules: Vec<SeccompFilter>,
//     context: Option<SeccompWrapper>,
// }
//
// /// High-level seccomp policy manager.
// /// Safe wrapper: no unsafe blocks or raw pointers.
// impl Policy {
//     /// use modules
//     // pub fn use_module(module: Modules) {}
//     /// Create a new policy with the given default action.
//     fn new(default_action: Action) -> Result<Self, SeccompError> {
//         let context = SeccompWrapper::init_context(default_action)?;
//         Ok(Self {
//             rules: Vec::new(),
//             context: Some(context),
//         })
//     }
//
//     /// Allow all syscall by default.
//     pub fn allow_all() -> Result<Self, SeccompError> {
//         Self::new(Action::Allow)
//     }
//
//     /// Deny all syscalls by default.
//     pub fn deny_all() -> Result<Self, SeccompError> {
//         Self::new(Action::Kill)
//     }
//
//     /// Syscall fail with a custom error no
//     pub fn fail_with(&mut self, syscall: Syscall, errno: u16) -> Result<&mut Self, SeccompError> {
//         if let Some(ref wrapper) = self.context {
//             if wrapper.default_action == Action::Errno(errno) {
//                 return Err(SeccompError::RedundantAllowRule(syscall));
//             }
//             self.rules
//                 .push(SeccompFilter::new(syscall, Action::Errno(errno)));
//             Ok(self)
//         } else {
//             Err(SeccompError::EmptyContext)
//         }
//     }
//     /// Trace
//     pub fn trace<T>(&mut self, syscall: Syscall, tracer: T) -> Result<&mut Self, SeccompError>
//     where
//         T: Fn(Syscall) -> TraceAction + 'static,
//     {
//         self.rules
//             .push(SeccompFilter::new_tracer(syscall, Action::Trace, tracer));
//         Ok(self)
//     }
//
//     /// Mark a syscall as allowed.
//     pub fn allow(&mut self, syscall: Syscall) -> Result<&mut Self, SeccompError> {
//         if let Some(ref wrapper) = self.context {
//             if wrapper.default_action == Action::Allow {
//                 return Err(SeccompError::RedundantAllowRule(syscall));
//             }
//             self.rules.push(SeccompFilter::new(syscall, Action::Allow));
//             Ok(self)
//         } else {
//             Err(SeccompError::EmptyContext)
//         }
//     }
//
//     /// Mark a syscall as denied.
//     pub fn deny(&mut self, syscall: Syscall) -> Result<&mut Self, SeccompError> {
//         if let Some(ref wrapper) = self.context {
//             if wrapper.default_action == Action::Kill {
//                 return Err(SeccompError::RedundantDenyRule(syscall));
//             }
//             self.rules.push(SeccompFilter::new(syscall, Action::Kill));
//             Ok(self)
//         } else {
//             Err(SeccompError::EmptyContext)
//         }
//     }
//
//     /// Apply all collected rules to the seccomp context.
//     // todo(x0rw): Add a supervisor process that spawns once to handle tracing
//     //
//     pub fn apply(&mut self) -> Result<(), SeccompError> {
//         let context_option = self.context.as_mut();
//         let context = context_option.ok_or(SeccompError::EmptyContext)?;
//
//         let mut is_trace = false;
//         let mut trace: Vec<&SeccompFilter> = Vec::new();
//         for rule in &self.rules {
//             if rule.action == Action::Trace {
//                 is_trace = true;
//                 trace.push(rule);
//             } else {
//                 println!(
//                     "Applying {:?} filter for {:?}",
//                     rule.get_action(),
//                     rule.get_syscall()
//                 );
//                 context.add_rule(rule.get_action(), rule.get_syscall())?;
//             }
//         }
//         if !trace.is_empty() {
//             for rule in trace {
//                 println!("Applying Trace filter");
//                 let result = PtraceWrapper::fork()?;
//                 match result.get_process() {
//                     ForkResult::Child => {
//                         // child process
//                         wrapper::PtraceWrapper::new(0).enable_tracing()?;
//
//                         // let temp_context = SeccompWrapper::init_context(Action::Allow)?;
//                         context.add_rule(rule.get_action(), rule.get_syscall())?;
//                         context.add_rule(rule.get_action(), Syscall::Write)?;
//
//                         // return Ok(());
//                     }
//                     ForkResult::Parent(_pid) => {
//                         // println!("pid: {_pid}");
//                         result.wait_for_signal(SIGSTOP)?;
//
//                         result.set_traceseccomp()?.syscall_trace()?;
//                         let tracer = rule.tracer.as_ref().unwrap();
//                         result.wait_for_syscall(tracer)?;
//
//                         std::process::exit(0);
//                     }
//                 }
//             }
//         }
//
//         context.load()?; // Finalize and load the seccomp filters.
//         if is_trace {
//             // println!("raising signal SIGSTOP");
//             unsafe { raise(SIGSTOP) };
//         }
//         Ok(())
//     }
//
//    /// the number of filters/rules
//    pub fn rules_len(&self) -> usize {
//        self.rules.len()
//    }
//
//    /// List allowed syscalls
//    pub fn list_policies(&self) {
//        let rules = &self.rules;
//        rules.iter().for_each(|rule: &SeccompFilter| rule.print())
//    }
//
//    /// List allowed syscalls
//    pub fn list_killed_syscalls(&self) -> Vec<Syscall> {
//        let rules = &self.rules;
//        rules
//            .iter()
//            .filter(|x| x.action == Action::Kill)
//            .map(|filter| filter.get_syscall())
//            .collect()
//    }
//}
