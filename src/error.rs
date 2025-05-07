use std::io;

use libc::pid_t;
use thiserror::Error;

use crate::syscall::Syscall;
/// Set of errors enums returned from libseccomp wrapper and the public api
#[derive(Debug, Error)]
pub enum SeccompError {
    /// triggered when initilizing a libseccomp filter fails (duplicated)
    #[error("Failed to initilize seccomp context")]
    InitFailed,

    /// triggered when adding a libseccomp rule fails
    #[error("Failed to initilize seccomp context {0:?}")]
    AddRuleFailed(Syscall),

    /// triggered when we fail to resolve a syscall from a string
    #[error("Unsupported syscall name: {0:?}")]
    UnsupportedSyscall(String),

    /// triggered when the low-level libseccomp returns an error
    /// todo(x0rw) explicitly handle it especially for error num -13
    #[error("libseccomp returned error code {0}")]
    LibSeccompError(i32),

    /// triggered when loading metadata fails
    #[error("Failed to load syscall metadata")]
    MetadataError,

    /// Unknown error, this should never happen
    #[error("Unknown error")]
    Unknown,

    /// triggered when initilizing a libseccomp filter fails
    #[error("Failed to init context")]
    InitContextFailed,

    /// triggered when you try to apply a filter without defining a context
    #[error("Cannot find a context, please specify a context(.allow_all() or .deny_all())")]
    EmptyContext,

    /// triggered when you encounter an error while loading the filter
    #[error("Failed to load the context")]
    LoadError,

    /// triggered when you deny() but the context is deny_all()
    #[error("Redundant deny rule for {0:?} when default is Deny all.")]
    RedundantDenyRule(Syscall),

    /// triggered when you allow() but the context is allow_all()
    #[error("Redundant allow rule for {0:?} when default is Allow all.")]
    RedundantAllowRule(Syscall),

    /// Triggered when ptrace fails to set ptrace options witg `PTRACE_O_TRACESECCOMP`
    #[error("Failed to set ptrace options for process child {0:?} ")]
    PtraceOptionsSet(pid_t, io::Error),

    /// Triggered when ptrace fails to `PTRACE_SYSCALL`
    #[error("Failed to start tracing syscalls for the child: {0:?} ")]
    PtraceSyscall(pid_t, io::Error),

    /// Fork returned a negative error
    #[error("Failed to fork the process")]
    Fork,

    /// Io error
    #[error("IO error occured: {0:?}")]
    IO(#[from] io::Error),

    /// Unsupported syscall
    #[error("Unsupported syscall id {0}")]
    UnsupportedSyscallID(i32),
}
