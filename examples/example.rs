use libc::{
    c_void, pid_t, ptrace, raise, waitpid, PTRACE_CONT, PTRACE_O_TRACESECCOMP, PTRACE_SETOPTIONS,
    PTRACE_SYSCALL, PTRACE_TRACEME, SIGSTOP, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG,
};

use restrict::policy::{Policy, Syscall};
use restrict::wrapper::{self, *};
use std::fs::File;
use std::io::{self};

fn wait_for_signal(pid: pid_t, expected: i32) -> Result<(), io::Error> {
    let mut status = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    if !WIFSTOPPED(status) || WSTOPSIG(status) != expected {
        return Err(io::Error::new(io::ErrorKind::Other, "Unexpected signal"));
    }
    Ok(())
}

fn do_f() {
    let handler = |syscall| {
        println!("syscall: {syscall}");
        return TraceAction::Continue;
    };
    let result = PtraceWrapper::fork().unwrap();
    match result.get_process() {
        ForkResult::Child => {
            // child process
            wrapper::PtraceWrapper::new(0).enable_tracing().unwrap();

            unsafe { raise(SIGSTOP) };

            let mut policy = Policy::allow_all().unwrap();
            policy.trace(Syscall::Openat).unwrap();
            policy.apply().unwrap();

            return;
        }
        ForkResult::Parent(pid) => {
            println!("pid: {pid}");
            let pid = pid.to_owned();
            wait_for_signal(pid, SIGSTOP).unwrap();

            result.set_traceseccomp().unwrap().syscall_trace().unwrap();
            result.wait_for_syscall(handler);

            std::process::exit(0);
        }
    }
}

fn main() {
    do_f();

    let mut file = File::create("test-seccomp.txt").expect("Failed to open file");
    use std::io::Write;
    writeln!(file, "Hello Seccomp").unwrap();
}
