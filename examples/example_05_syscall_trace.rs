use std::fs;

use restrict::{
    policy::{self, Policy},
    wrapper::TraceAction,
    SeccompError,
};

fn main() -> Result<(), SeccompError> {
    let mut policy = Policy::allow_all()?;
    policy.trace(policy::Syscall::Openat, |syscall| {
        println!("Syscall {:?} triggered", syscall);
        return TraceAction::Kill; // we can return TraceAction::Kill to kill the process
    })?;

    // .list_policies();
    policy.apply()?;
    let open_file = fs::File::open("test.txt");
    println!("Opened file {:?}", open_file);
    Ok(())
}
