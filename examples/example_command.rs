use std::{
    os::unix::process::{CommandExt, ExitStatusExt},
    process::Command,
};

use restrict::{
    policy::{Policy, Syscall},
    SeccompError, TraceAction,
};

fn main() -> Result<(), SeccompError> {
    let mut child = unsafe {
        println!("> Running ls");
        Command::new("ls")
            .pre_exec(|| {
                let mut policy = Policy::allow_all().unwrap();
                policy
                    .trace(Syscall::Openat, |syscall| {
                        println!("Syscall {:?} triggered ", syscall);
                        return TraceAction::Continue;
                    })
                    .trace(Syscall::Read, |syscall| {
                        println!("Syscall {:?} triggered ", syscall);
                        return TraceAction::Continue;
                    });
                policy.apply().unwrap();
                Ok(())
            })
            .spawn()
            .expect("Failed to start process")
    };

    let status = child.wait().expect("Failed to wait on process");
    if let Some(signal) = status.signal() {
        println!("Child killed by signal: {}", signal);
    } else {
        println!("Child exited normally: {}", status);
    }
    println!("Child exited with status: {status}");
    Ok(())
}
