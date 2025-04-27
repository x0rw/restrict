use crate::{
    error::SeccompError,
    modules::module::Modules,
    syscalls::Syscall,
    wrapper::{Action, SeccompWrapper},
};

///
/// Seccomp filters of allowed and disallowed syscalls
#[derive(Debug)]
pub struct SeccompFilter {
    syscall: Syscall,
    action: Action,
}

impl SeccompFilter {
    const fn new(syscall: Syscall, action: Action) -> Self {
        Self { syscall, action }
    }
}

pub struct SeccompPolicy {
    rules: Vec<SeccompFilter>,
    context: Option<SeccompWrapper>,
}

/// High-level seccomp policy manager.
/// Safe wrapper: no unsafe blocks or raw pointers.
impl SeccompPolicy {
    /// use modules
    pub fn use_module(module: Modules) {}
    /// Create a new policy with the given default action.
    pub fn new(default_action: Action) -> Result<Self, SeccompError> {
        let context = SeccompWrapper::init_context(default_action)?;
        Ok(Self {
            rules: Vec::new(),
            context: Some(context),
        })
    }

    /// Allow all syscalls by default.
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
                return Err(SeccompError::RedundantAllowRule(syscall));
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
            context.add_rule(rule.action, rule.syscall)?;
        }

        context.load()?; // Finalize and load the seccomp filters.
        println!("Filters applied");

        Ok(())
    }
}
