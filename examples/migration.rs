use std::fs;

use restrict::{policy::Policy, wrapper::TraceAction, *};

fn main() -> Result<(), SeccompError> {
    println!("This process will be killed at the end!");

    let mut filter = Policy::new(policy::Action::Allow)?;
    // filter.allow(Syscall::Write);
    // filter.allow(Syscall::Openat);
    // filter.allow(Syscall::Sigaltstack);
    // filter.allow(Syscall::Munmap);

    filter.trace(policy::Syscall::Openat, |syscall| {
        println!("Syscall {:?} triggered", syscall);
        return TraceAction::Continue;
    });
    filter.trace(policy::Syscall::Write, |syscall| {
        println!("Syscall {:?} triggered", syscall);
        return TraceAction::Kill;
    });

    filter.apply()?;

    // openat() syscall
    let _read_fs = fs::read("test.txt").unwrap();
    println!(
        "The current proccess should be killed before this is displayed because this uses openat() syscall"
    );
    Ok(())
}
