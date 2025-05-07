use libc::{
    c_void, pid_t, ptrace, raise, waitpid, PTRACE_CONT, PTRACE_O_TRACESECCOMP, PTRACE_SETOPTIONS,
    PTRACE_SYSCALL, PTRACE_TRACEME, SIGSTOP, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG,
};

use libseccomp_sys::{
    seccomp_init, seccomp_load, seccomp_release, seccomp_rule_add, SCMP_ACT_ALLOW, SCMP_ACT_TRACE,
};

use restrict::policy::Syscall;
use std::fs::File;
use std::io;
use std::process::exit;

fn install_seccomp_filter() {
    let ctx = unsafe { seccomp_init(SCMP_ACT_ALLOW) };
    if ctx.is_null() {
        panic!("Failed to initialize seccomp filter");
    }

    let syscall = Syscall::Openat as i32;
    let ret = unsafe { seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), syscall, 0) };
    if ret != 0 {
        panic!("Failed to add seccomp rule for syscall trace");
    }

    let ret = unsafe { seccomp_load(ctx) };
    if ret != 0 {
        panic!("Failed to load seccomp filter");
    }

    unsafe { seccomp_release(ctx) };
}

fn attach_ptrace_and_set_options(child: pid_t) {
    let ret = unsafe {
        // trace seccomp syscalls only
        ptrace(
            PTRACE_SETOPTIONS,
            child,
            std::ptr::null_mut::<c_void>(),
            (PTRACE_O_TRACESECCOMP) as *mut c_void,
        )
    };
    if ret == -1 {
        panic!(
            "Failed to set ptrace options: {}",
            io::Error::last_os_error()
        );
    }
    // Start syscall tracing
    let ret = unsafe {
        ptrace(
            PTRACE_SYSCALL,
            child,
            std::ptr::null_mut::<c_void>(),
            0 as *mut c_void,
        )
    };
    if ret == -1 {
        panic!(
            "Failed to start syscall tracing: {}",
            io::Error::last_os_error()
        );
    }
}

fn wait_for_syscall(child: pid_t) {
    loop {
        let mut status = 0;
        let ret = unsafe { waitpid(child, &mut status, 0) };
        if ret == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                break;
            }
            panic!("waitpid failed: {}", err);
        }
        if WIFEXITED(status) || WIFSIGNALED(status) {
            break;
        }
        if WIFSTOPPED(status) {
            let sig = WSTOPSIG(status);
            if sig == libc::SIGTRAP && (status >> 16) == libc::PTRACE_EVENT_SECCOMP {
                let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                unsafe {
                    ptrace(
                        libc::PTRACE_GETREGS,
                        child,
                        std::ptr::null_mut::<c_void>(),
                        &mut regs as *mut _ as *mut c_void,
                    );
                }
                println!("Intercepted syscall number: {}", regs.orig_rax);
                unsafe {
                    ptrace(
                        PTRACE_CONT,
                        child,
                        std::ptr::null_mut::<c_void>(),
                        0 as *mut c_void,
                    );
                }
            } else {
                unsafe {
                    ptrace(
                        PTRACE_SYSCALL,
                        child,
                        std::ptr::null_mut::<c_void>(),
                        0 as *mut c_void,
                    );
                }
            }
        }
    }
}

fn main() {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        panic!("fork failed");
    }
    if pid == 0 {
        let ret = unsafe {
            ptrace(
                PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            )
        };

        if ret == -1 {
            panic!("PTRACE_TRACEME failed: {}", io::Error::last_os_error());
        }

        unsafe { raise(SIGSTOP) };
        install_seccomp_filter();

        let mut file = File::create("test-seccomp.txt").expect("Failed to open file");
        use std::io::Write;
        writeln!(file, "Hello Seccomp").unwrap();
        exit(0);
    }

    let mut status = 0;
    let ret = unsafe { waitpid(pid, &mut status, 0) };
    if ret == -1 || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP {
        panic!(
            "Child did not stop as expected: {}",
            io::Error::last_os_error()
        );
    }
    attach_ptrace_and_set_options(pid);
    wait_for_syscall(pid);
}
