use crate::wrapper::SeccompWrapper;
pub use crate::{error::SeccompError, syscall::Syscall, wrapper::Action};

/// Seccomp filters of syscall and actions
#[derive(Debug)]
pub struct SeccompFilter {
    syscall: Syscall,
    action: Action,
}

impl SeccompFilter {
    /// Declare a new filter
    const fn new(syscall: Syscall, action: Action) -> Self {
        Self { syscall, action }
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

#[derive(Debug)]
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
    pub fn new(default_action: Action) -> Result<Self, SeccompError> {
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
        println!("Applying filters");
        let context_option = self.context.as_mut();
        let context = context_option.ok_or(SeccompError::EmptyContext)?;

        for rule in &self.rules {
            context.add_rule(rule.get_action(), rule.get_syscall())?;
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
