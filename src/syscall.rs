/// Syscalls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syscall {
    ///  int open(const char *pathname, int flags);
    Open,
    ///  int close(int fd);
    Close,
    /// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
    OpenAt,
    /// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
    Write,
    Read,
    Mmap,
    Fstat,
    Access,
    Sigaltstack,
}
impl Syscall {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::OpenAt => "openat",
            Self::Write => "write",
            Self::Read => "read",
            Self::Mmap => "mmap",
            Self::Access => "access",
            Self::Fstat => "Fstat",
            Self::Sigaltstack => "sigaltstack",
        }
    }
}
