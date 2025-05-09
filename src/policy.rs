use libc::{raise, SIGSTOP};

use crate::wrapper::{self, ForkResult, PtraceWrapper, SeccompWrapper, TraceAction};
pub use crate::{error::SeccompError, syscall::Syscall, wrapper::Action};

/// Seccomp filters of syscall and actions
#[derive()]
pub struct SeccompFilter {
    syscall: Syscall,
    action: Action,
    /// Tracer callback
    pub tracer: Option<Box<dyn Fn(Syscall) -> TraceAction>>,
}

impl SeccompFilter {
    /// Declare a new filter
    const fn new(syscall: Syscall, action: Action) -> Self {
        Self {
            syscall,
            action,
            tracer: None,
        }
    }

    fn new_tracer<T>(syscall: Syscall, default_action: Action, handler: T) -> Self
    where
        T: Fn(Syscall) -> TraceAction + 'static,
    {
        Self {
            syscall: syscall,
            action: default_action,
            tracer: Some(Box::new(handler)),
        }
    }
    /// get this filter's target syscall
    fn get_syscall(&self) -> Syscall {
        return self.syscall;
    }

    /// get this filter's action
    fn get_action(&self) -> Action {
        return self.action;
    }
}

#[derive()]
/// Policy manager struct to keep track of all the Libseccomp filters
pub struct Policy {
    rules: Vec<SeccompFilter>,
    context: Option<SeccompWrapper>,
}

/// High-level seccomp policy manager.
/// Safe wrapper: no unsafe blocks or raw pointers.
impl Policy {
    /// use modules
    // pub fn use_module(module: Modules) {}
    /// Create a new policy with the given default action.
    fn new(default_action: Action) -> Result<Self, SeccompError> {
        let context = SeccompWrapper::init_context(default_action)?;
        Ok(Self {
            rules: Vec::new(),
            context: Some(context),
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
    pub fn fail_with(&mut self, syscall: Syscall, errno: u16) -> Result<&mut Self, SeccompError> {
        if let Some(ref wrapper) = self.context {
            if wrapper.default_action == Action::Errno(errno) {
                return Err(SeccompError::RedundantAllowRule(syscall));
            }
            self.rules
                .push(SeccompFilter::new(syscall, Action::Errno(errno)));
            Ok(self)
        } else {
            Err(SeccompError::EmptyContext)
        }
    }
    /// Trace
    pub fn trace<T>(&mut self, syscall: Syscall, tracer: T) -> Result<&mut Self, SeccompError>
    where
        T: Fn(Syscall) -> TraceAction + 'static,
    {
        self.rules
            .push(SeccompFilter::new_tracer(syscall, Action::Trace, tracer));
        Ok(self)
    }

    /// Mark a syscall as allowed.
    pub fn allow(&mut self, syscall: Syscall) -> Result<&mut Self, SeccompError> {
        if let Some(ref wrapper) = self.context {
            if wrapper.default_action == Action::Allow {
                return Err(SeccompError::RedundantAllowRule(syscall));
            }
            self.rules.push(SeccompFilter::new(syscall, Action::Allow));
            Ok(self)
        } else {
            Err(SeccompError::EmptyContext)
        }
    }

    /// Mark a syscall as denied.
    pub fn deny(&mut self, syscall: Syscall) -> Result<&mut Self, SeccompError> {
        if let Some(ref wrapper) = self.context {
            if wrapper.default_action == Action::Kill {
                return Err(SeccompError::RedundantDenyRule(syscall));
            }
            self.rules.push(SeccompFilter::new(syscall, Action::Kill));
            Ok(self)
        } else {
            Err(SeccompError::EmptyContext)
        }
    }

    /// Apply all collected rules to the seccomp context.
    pub fn apply(&mut self) -> Result<(), SeccompError> {
        let context_option = self.context.as_mut();
        let context = context_option.ok_or(SeccompError::EmptyContext)?;

        for rule in &self.rules {
            if rule.action == Action::Trace {
                let result = PtraceWrapper::fork().unwrap();
                match result.get_process() {
                    ForkResult::Child => {
                        // child process
                        wrapper::PtraceWrapper::new(0).enable_tracing().unwrap();

                        context.add_rule(rule.get_action(), rule.get_syscall())?;
                        context.load().unwrap();
                        unsafe { raise(SIGSTOP) };

                        return Ok(());
                    }
                    ForkResult::Parent(pid) => {
                        println!("pid: {pid}");
                        result.wait_for_signal(SIGSTOP).unwrap();

                        result.set_traceseccomp().unwrap().syscall_trace().unwrap();
                        let tracer = rule.tracer.as_ref().unwrap();
                        result.wait_for_syscall(tracer);

                        std::process::exit(0);
                    }
                }
            } else {
                context.add_rule(rule.get_action(), rule.get_syscall())?;
            }
        }

        context.load()?; // Finalize and load the seccomp filters.

        Ok(())
    }

    /// the number of filters/rules
    pub fn rules_len(&self) -> usize {
        self.rules.len()
    }

    /// List allowed syscalls
    pub fn list_allowed_syscalls(&self) -> Vec<Syscall> {
        let rules = &self.rules;
        rules
            .iter()
            .filter(|x| x.action == Action::Allow)
            .map(SeccompFilter::get_syscall)
            .collect()
    }

    /// List allowed syscalls
    pub fn list_killed_syscalls(&self) -> Vec<Syscall> {
        let rules = &self.rules;
        rules
            .iter()
            .filter(|x| x.action == Action::Kill)
            .map(|filter| filter.get_syscall())
            .collect()
    }
}
