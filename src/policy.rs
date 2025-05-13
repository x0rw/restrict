use libc::{raise, SIGSTOP};

pub use crate::{error::SeccompError, syscall::Syscall, wrapper::Action};
use crate::{
    filter::{seccomp, tracer::TracerFilter, RestrictFilter},
    tracer::TracingHandle,
    wrapper::{self, ForkResult, PtraceWrapper, SeccompWrapper, TraceAction},
};

/// Restrict policy
pub struct Policy {
    context: Option<SeccompWrapper>,
    rules: Vec<Box<dyn RestrictFilter>>,
    trace: bool,
}
impl Policy {
    /// decclare a new filter with default policy
    pub fn new(default: Action) -> Result<Self, SeccompError> {
        Ok(Self {
            context: Some(SeccompWrapper::init_context(default)?),
            rules: Vec::new(),
            trace: false,
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
        self.rules.push(Box::new(seccomp::SeccompFilter::new(
            syscall,
            Action::Errno(errno),
        )));
        self
    }

    pub fn trace<T>(&mut self, syscall: Syscall, tracer: T) -> &mut Self
    where
        T: Fn(Syscall) -> TraceAction + 'static,
    {
        self.rules
            .push(Box::new(TracerFilter::new(syscall, tracer)));
        self.trace = true;
        self
    }

    /// allow a syscall
    pub fn allow(&mut self, syscall: Syscall) -> &mut Self {
        self.rules.push(Box::new(seccomp::SeccompFilter::new(
            syscall,
            Action::Allow,
        )));
        self
    }

    /// deny a syscall
    pub fn deny(&mut self, syscall: Syscall) -> &mut Self {
        self.rules
            .push(Box::new(seccomp::SeccompFilter::new(syscall, Action::Kill)));
        self
    }
    /// apply
    pub fn apply(&mut self) -> Result<(), SeccompError> {
        let mut context = self.context.take().ok_or(SeccompError::Fork)?;
        for filter in self.rules.iter() {
            filter.apply(&mut context)?;
        }
        if self.trace {
            let spawned = self.spawn_traced().unwrap();
            match spawned {
                TracingHandle::Child => {
                    // here tracing is already enabled
                    //
                    //loading the context in the child(only)
                    unsafe { raise(SIGSTOP) };
                    context.load()?;
                }
                TracingHandle::Parent {
                    pid: _,
                    tracer,
                    filters: _,
                } => {
                    // here goes the event loop

                    // print!("\n parent waiting for signal");
                    tracer.wait_for_signal(SIGSTOP)?;
                    // print!("\n found a signal");
                    tracer.set_traceseccomp()?.syscall_trace()?;
                    let tracer_h = |sys| {
                        println!("\n caught {:#?}", sys);
                        return TraceAction::Continue;
                    };
                    tracer.wait_for_syscall(tracer_h)?;

                    print!("exiting -- ");

                    std::process::exit(0);
                }
            }
        } else {
            context.load()?;
        }
        Ok(())
    }
    ///spawn tracer
    pub fn spawn_traced(&mut self) -> Result<TracingHandle, SeccompError> {
        println!("Applying Trace filter");
        let result = PtraceWrapper::fork()?;
        match result.get_process() {
            ForkResult::Child => {
                // child process
                wrapper::PtraceWrapper::new(0).enable_tracing()?;
                return Ok(TracingHandle::Child);
            }
            ForkResult::Parent(pid) => {
                // println!("pid: {_pid}");
                let filters = std::mem::take(&mut self.rules);
                return Ok(TracingHandle::Parent {
                    pid: pid.to_owned(),
                    tracer: result,
                    filters,
                });
                // std::process::exit(0);
            }
        }
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
