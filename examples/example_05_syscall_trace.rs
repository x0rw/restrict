use std::fs;

use restrict::{
    policy::{self, Policy, Syscall},
    SeccompError, TraceAction,
};

fn main() -> Result<(), SeccompError> {
    let mut policy = Policy::allow_all()?;
    policy.deny(Syscall::Munmap);
    policy.deny(Syscall::ExitGroup);
    // policy.allow(Syscall::ExitGroup);
    // policy.deny(Syscall::Write)?;
    policy.trace(policy::Syscall::Openat, |syscall| {
        println!("Syscall {:?} triggered", syscall);
        return TraceAction::Continue; // we can return TraceAction::Kill to kill the process
    });

    // apply
    policy.apply()?;
    let open_file = fs::File::open("test.txt");
    println!("Opened file {:?}", open_file);
    // sleep(Duration::from_secs(5));
    Ok(())
}
