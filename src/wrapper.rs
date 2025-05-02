use std::{ffi::c_void, ptr::NonNull};

use libseccomp_sys::*;

use crate::{error::SeccompError, syscall::Syscall};

/// Todo(x0rw): here make emums for libseccomp-sys that interact with it
#[derive(Debug)]
pub struct SeccompWrapper {
    pub context: NonNull<c_void>,
    pub default_action: Action,
}
impl SeccompWrapper {
    /// Create a new seccomp context with the given default action.
    pub fn init_context(default_action: Action) -> Result<Self, SeccompError> {
        // SAFETY: `seccomp_init` returns a raw context. Assumes `default_action` is valid.
        let context_ptr = unsafe { seccomp_init(default_action.to_raw()) };
        let context = NonNull::new(context_ptr).ok_or(SeccompError::InitContextFailed)?;

        Ok(Self {
            context,
            default_action,
        })
    }

    #[cfg(test)]
    /// Convert a syscall name to its numeric ID.
    pub fn resolve_syscall(name: &str) -> Result<i32, SeccompError> {
        use std::ffi::CString;
        let c_name = CString::new(name).unwrap();

        // SAFETY: `name` is a valid null-terminated C string.
        let num = unsafe { seccomp_syscall_resolve_name(c_name.as_ptr()) };
        if num == __NR_SCMP_ERROR {
            return Err(SeccompError::UnsupportedSyscall(name.to_string()));
        }
        Ok(num)
    }

    /// Add a rule to the seccomp context.
    pub fn add_rule(&mut self, action: Action, syscall: Syscall) -> Result<(), SeccompError> {
        let context = self.context.as_ptr();
        // let syscall = Self::resolve_syscall(syscall)?;
        let syscall = syscall as i32;
        let action = action.to_raw();

        // SAFETY: `context` is valid, and `action` and `syscall` are well-formed.
        let seccomp_add_result = unsafe { seccomp_rule_add(context, action, syscall, 0) };

        if seccomp_add_result != 0 {
            return Err(SeccompError::Unknown);
        }

        Ok(())
    }

    /// Load the context and enforce the rules.
    pub fn load(&mut self) -> Result<(), SeccompError> {
        let context_ptr = self.context.as_ptr();

        // SAFETY: `context_ptr` is a valid context initialized with `seccomp_init`.
        let load_result = unsafe { seccomp_load(context_ptr) };
        if load_result != 0 {
            return Err(SeccompError::LoadError);
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Action {
    Allow = SCMP_ACT_ALLOW,
    Kill = SCMP_ACT_KILL_PROCESS,
    Errno(u16),
}

impl Action {
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Allow => SCMP_ACT_ALLOW,
            Self::Kill => SCMP_ACT_KILL_PROCESS,
            Self::Errno(code) => SCMP_ACT_ERRNO(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_resolve_syscall() {
        let open_syscall = SeccompWrapper::resolve_syscall("open").unwrap();
        // compare with the generated syscall.rs
        assert_eq!(open_syscall, Syscall::Open as i32);
    }

    #[test]
    fn invalid_resolve_syscall() {
        let syscall_name = "InvalidSyscall";
        let open_syscall = SeccompWrapper::resolve_syscall(syscall_name);
        assert_eq!(
            open_syscall.unwrap_err(),
            SeccompError::UnsupportedSyscall(syscall_name.to_string())
        );
    }
}
