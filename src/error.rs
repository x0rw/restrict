use thiserror::Error;

use crate::syscalls::Syscall;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeccompError {
    #[error("Failed to initilize seccomp context")]
    InitFailed,

    #[error("Failed to initilize seccomp context {0:?}")]
    AddRuleFailed(Syscall),

    #[error("Unsupported syscall name: {0:?}")]
    UnsupportedSyscall(Syscall),

    #[error("libseccomp returned error code {0}")]
    LibSeccompError(i32),

    #[error("Failed to load syscall metadata")]
    MetadataError,

    #[error("Unknown error")]
    Unknown,

    #[error("Failed to init context")]
    InitContextFailed,

    #[error("Cannot find a context, please specify a context(.allow_all() or .deny_all())")]
    EmptyContext,

    #[error("Failed to load the context")]
    LoadError,

    #[error("Redundant deny rule for {0:?} when default is Deny all.")]
    RedundantDenyRule(Syscall),

    #[error("Redundant allow rule for {0:?} when default is Allow all.")]
    RedundantAllowRule(Syscall),
}
