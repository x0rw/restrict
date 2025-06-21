use std::fs;

use restrict::{
    policy::{self, Policy, Syscall},
    SeccompError, TraceAction,
};
use tracing_subscriber::fmt;

fn main() -> Result<(), SeccompError> {
    //init the subscriber
    let _subscriber = fmt::Subscriber::builder()
        .with_writer(std::io::stderr)
        .with_thread_ids(true)
        .compact()
        .init();

    let mut policy = Policy::allow_all()?;
    policy.deny(Syscall::Munmap);
    policy.deny(Syscall::ExitGroup);
    policy.trace(policy::Syscall::Openat, |syscall| {
        println!("Syscall {:?} triggered", syscall);
        return TraceAction::Continue;
    });

    // apply
    policy.apply()?;
    let open_file = fs::File::open("test.txt");
    println!("Opened file {:?}", open_file);
    Ok(())
}
