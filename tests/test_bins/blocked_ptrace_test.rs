use std::io::Error;

use libc::{ptrace, PTRACE_TRACEME};
use restrict::policy::{Policy, Syscall};

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
#[cfg(target_arch = "x86_64")]
fn main() {
    let mut policy = Policy::allow_all().unwrap();
    policy
        .fail_with(Syscall::Ptrace, libc::EPERM as u16)
        .apply()
        .unwrap();

    let result = unsafe { ptrace(PTRACE_TRACEME, 0, 0, 0) };
    let last_error = Error::last_os_error();
    println!("result:{}\nlast_os_error:{}", result, last_error.kind());
    // assert_eq!(last_error.raw_os_error(), Some(libc::EPERM));
}
