use std::{
    ffi::c_void,
    io::{self},
    mem::MaybeUninit,
    ptr::NonNull,
};

use libseccomp_sys::*;
use tracing::error;

use crate::{error::SeccompError, filter::tracer::TracerMap, syscall::Syscall};

#[allow(dead_code)]
/// Todo(x0rw): here make emums for libseccomp-sys that interact with it
#[derive(Debug)]
pub(crate) struct SeccompWrapper {
    pub context: NonNull<c_void>,
    pub default_action: Action,
}
impl SeccompWrapper {
    /// Create a new seccomp context with the given default action.
    pub(crate) fn init_context(default_action: Action) -> Result<Self, SeccompError> {
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
    pub(crate) fn resolve_syscall(name: &str) -> Result<i32, SeccompError> {
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
    pub(crate) fn add_rule(&self, action: Action, syscall: Syscall) -> Result<(), SeccompError> {
        let context = self.context.as_ptr();
        // let syscall = Self::resolve_syscall(syscall)?;
        let syscall = syscall as i32;
        let action = action.to_raw();

        // SAFETY: `context` is valid, and `action` and `syscall` are well-formed.
        let seccomp_add_result = unsafe { seccomp_rule_add(context, action, syscall, 0) };

        if seccomp_add_result != 0 {
            return Err(SeccompError::FailedToAddResultToSeccompFilter);
        }

        Ok(())
    }

    /// Load the context and enforce the rules.
    pub(crate) fn load(&self) -> Result<(), SeccompError> {
        let context_ptr = self.context.as_ptr();

        // SAFETY: `context_ptr` is a valid context initialized with `seccomp_init`.
        let load_result = unsafe { seccomp_load(context_ptr) };
        if load_result != 0 {
            return Err(SeccompError::LoadError);
        }
        Ok(())
    }
}

/// Action that can be applied to a context or a syscall
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// allowing all in the context or allowing a syscall
    Allow = SCMP_ACT_ALLOW,
    /// kill all in the context or kill a syscall
    Kill = SCMP_ACT_KILL_PROCESS,
    /// custom sig
    Errno(u16),
    /// set tracing
    Trace = SCMP_ACT_TRACE(0),
}

impl Action {
    /// from action to libseccomp const
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Allow => SCMP_ACT_ALLOW,
            Self::Kill => SCMP_ACT_KILL_PROCESS,
            Self::Errno(code) => SCMP_ACT_ERRNO(code),
            Self::Trace => SCMP_ACT_TRACE(0),
        }
    }
}

use libc::{
    kill, pid_t, ptrace, waitpid, PTRACE_CONT, PTRACE_GETREGS, PTRACE_KILL, PTRACE_O_TRACESECCOMP,
    PTRACE_SETOPTIONS, PTRACE_SYSCALL, PTRACE_TRACEME, SIGKILL, WIFEXITED, WIFSIGNALED, WIFSTOPPED,
    WSTOPSIG,
};
/// Fork
#[derive(Debug)]
pub enum ForkResult {
    /// parent
    Parent(pid_t),
    /// Child process always with the pid -
    Child,
}
impl ForkResult {
    /// get pid
    pub fn get_pid(&self) -> pid_t {
        match self {
            ForkResult::Parent(pid) => pid.to_owned(),
            ForkResult::Child => 0,
        }
    }
}

/// Ptrace wrapper
#[derive(Debug)]
pub struct PtraceWrapper {
    process: ForkResult,
}
impl PtraceWrapper {
    /// get process
    pub fn get_process(&self) -> &ForkResult {
        &self.process
    }
    /// fork
    pub fn fork() -> Result<Self, SeccompError> {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SeccompError::Fork);
        }

        if pid == 0 {
            return Ok(Self {
                process: ForkResult::Child,
            });
        }
        Ok(Self {
            process: ForkResult::Parent(pid),
        })
    }
    /// new
    pub fn with_pid(child_pid: pid_t) -> Self {
        Self {
            process: ForkResult::Parent(child_pid),
        }
    }

    /// wait for the child to raise the signal
    /// this is crucial to sync the child with the parent
    /// and set the PTRACE_O_TRACESECCOMP flag at the right time
    /// why do we quit when we the signal doesn't match?
    /// - in `apply()` function after forking, the child raises SIGSTOP to stop itself
    /// waiting for the parent to catch this signal
    pub fn wait_for_signal(&self, expected: i32) -> Result<(), io::Error> {
        let mut status = 0;
        let ret = unsafe { libc::waitpid(self.get_process().get_pid(), &mut status, 0) };
        if ret == -1 {
            error!("waitpid failed");
            return Err(io::Error::last_os_error());
        }
        // we are looking for a specific signal that the child raised
        if !WIFSTOPPED(status) || WSTOPSIG(status) != expected {
            // if this is triggered this means either an external(process | thread) signal triggered this
            // if none of those triggered this fallure check the parent execution flow from forking
            // to wait_for_signal()
            error!(
                "  Unexpected signal: got {}, expected {}. Raw status = {:#x}",
                WSTOPSIG(status),
                expected,
                status
            );
            return Err(io::Error::new(io::ErrorKind::Other, "Unexpected signal"));
        }
        Ok(())
    }

    /// event loop

    #[tracing::instrument]
    pub fn event_loop(&self, trace_map: TracerMap) -> Result<(), SeccompError> {
        let child = self.get_process().get_pid();
        let wrapper = PtraceWrapper::with_pid(child);
        // println!("[!] child pid {}", wrapper.get_process().get_pid());
        loop {
            let mut status = 0;
            let ret = unsafe { waitpid(child, &mut status, 0) };
            if ret == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD) {
                    break;
                }
                panic!("waitpid failed: {}", err);
                // return Err(SeccompError::Unknown);
            }
            if WIFEXITED(status) || WIFSIGNALED(status) {
                break;
            }

            if WIFSTOPPED(status) {
                let sig = WSTOPSIG(status);
                if sig == libc::SIGTRAP && (status >> 16) == libc::PTRACE_EVENT_SECCOMP {
                    let regs = wrapper.get_registers()?;

                    // get Syscall from regs.orig_rax
                    let caught_syscall = Syscall::try_from(regs.orig_rax as i32)?;
                    // Getting the syscall handler
                    let mapped_fn = trace_map.find_by_syscall(caught_syscall).take().unwrap();
                    match mapped_fn(caught_syscall) {
                        TraceAction::Continue => wrapper.continue_execution()?,
                        TraceAction::Kill => {
                            wrapper.kill_execution()?;
                            // if the child is killed the parent should be killed too
                            // todo(z0rw): exit gracefully
                            std::process::exit(SIGKILL);
                        }
                    }
                } else {
                    wrapper.syscall_trace()?;
                }
            }
        }
        Ok(())
    }
    /// Set `PTRACE_O_TRACESECCOMP` option
    /// to
    pub fn set_traceseccomp_option(&self) -> Result<&Self, SeccompError> {
        let ret = unsafe {
            ptrace(
                PTRACE_SETOPTIONS,
                self.process.get_pid(),
                std::ptr::null_mut::<c_void>(),
                PTRACE_O_TRACESECCOMP as *mut c_void,
            )
        };
        if ret == -1 {
            return Err(SeccompError::PtraceOptionsSet(
                self.process.get_pid(),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(self)
    }

    /// enable ptrace tracing for the child process
    pub fn enable_tracing(&self) -> Result<&Self, SeccompError> {
        let ret = unsafe {
            ptrace(
                PTRACE_TRACEME,
                self.process.get_pid(),
                std::ptr::null_mut::<c_void>(),
                0 as *mut c_void,
            )
        };
        if ret == -1 {
            return Err(SeccompError::PtraceSyscall(
                self.process.get_pid(),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(self)
    }

    /// tete
    pub fn get_registers(&self) -> Result<libc::user_regs_struct, SeccompError> {
        let mut regs = MaybeUninit::<libc::user_regs_struct>::uninit();

        let ret = unsafe {
            ptrace(
                PTRACE_GETREGS,
                self.get_process().get_pid(),
                std::ptr::null_mut::<c_void>(),
                regs.as_mut_ptr() as *mut c_void,
            )
        };

        if ret == -1 {
            return Err(io::Error::last_os_error().into());
        }

        let regs = unsafe { regs.assume_init() };
        Ok(regs)
    }

    /// cont
    pub fn continue_execution(&self) -> Result<(), SeccompError> {
        unsafe {
            ptrace(
                PTRACE_CONT,
                self.process.get_pid(),
                std::ptr::null_mut::<c_void>(),
                0 as *mut c_void,
            );
        }
        Ok(())
    }

    /// killing after ptrace traps the syscall
    // TODO(x0rw): instead of killing facilitate setting orig_rax to -1 (-EPREM)
    pub fn kill_execution(&self) -> Result<(), SeccompError> {
        // println!("[Child-process] killing {}", self.process.get_pid());
        let kill_res = unsafe { kill(self.process.get_pid(), SIGKILL) };
        // println!("[Child-process] killing {}", self.process.get_pid());

        if kill_res == -1 {
            error!("[Child-process] Failed to kill the child");
            error!("[Child-process] Fallback to PTRACE_KILL");
            let _ret = unsafe {
                ptrace(
                    PTRACE_KILL,
                    self.process.get_pid(),
                    std::ptr::null_mut::<c_void>(),
                    0 as *mut c_void,
                )
            };
        }

        Ok(())
    }
    /// syscall tracing
    pub fn syscall_trace(&self) -> Result<(), SeccompError> {
        unsafe {
            ptrace(
                PTRACE_SYSCALL,
                self.process.get_pid(),
                std::ptr::null_mut::<c_void>(),
                0 as *mut c_void,
            );
        }
        Ok(())
    }
}
/// Action taken by the handler function after a syscall is caught
#[derive(Debug)]
pub enum TraceAction {
    /// continue syscall execution
    Continue,
    /// kill the target syscall process
    Kill,
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
        let result = SeccompWrapper::resolve_syscall(syscall_name);

        match result {
            Err(SeccompError::UnsupportedSyscall(name)) => {
                assert_eq!(name, syscall_name);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => panic!("Expected an error for an invalid syscall, but got Ok"),
        }
    }
}
