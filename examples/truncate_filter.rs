//! Example: Seccomp filter that truncates writes to a specific file descriptor.
//!
//! This standalone Rust example demonstrates how to:
//! 1. Create a pipe to obtain a read and write file descriptor.
//! 2. Install a seccomp-based interceptor that truncates
//!    all `write()` syscalls on the write-end of the pipe to 12 bytes.
//! 3. Perform a `write()` of a longer message, then read and print
//!    only the truncated output.
//!
//! Usage:
//! ```bash
//! cargo run --example truncate_filter
//! ```
//!
//!
use restrict::{
    policy::{Policy, Syscall},
    TraceAction,
};

pub fn install_truncating_filter(write_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    let mut filter = Policy::allow_all()?;

    filter.entry_intercept(Syscall::Write, move |mut interceptor| {
        // only truncate writes to our target fd
        if interceptor.registers.get("rdi").unwrap() as i32 == write_fd {
            interceptor.registers.set("rdx", 12).unwrap();
            interceptor.commit_regs().unwrap();
        }
        TraceAction::Continue
    });

    filter.apply()?;
    Ok(())
}
fn main() {
    // we create a pipe to get two fds
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        panic!("pipe() failed: {}", std::io::Error::last_os_error());
    }

    let r = fds[0];
    let w = fds[1];

    install_truncating_filter(w).unwrap();

    // write
    let msg = b"This is a really long message but only the first 5 bytes should be printed";
    let wrote = unsafe { libc::write(w, msg.as_ptr() as *const _, msg.len()) };
    println!("write() returned {wrote}");

    // read
    let mut buf = [0u8; 100];
    let read_bytes = unsafe { libc::read(r, buf.as_mut_ptr() as *mut _, buf.len()) };
    println!("read() should see 12 bytes: {}", read_bytes);
    println!("buffer: {}", String::from_utf8_lossy(&buf));

    // clean up
    unsafe {
        libc::close(r);
        libc::close(w);
    }
}
