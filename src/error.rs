use thiserror::Error;

use crate::syscall::Syscall;
/// Set of errors enums returned from libseccomp wrapper and the public api
#[derive(Debug, Error, PartialEq, Eq)]
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
}
