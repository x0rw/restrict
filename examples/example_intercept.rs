use std::fs;

use restrict::{interceptor::Interceptor, *};

use policy::Policy;
use syscall::Syscall;
use tracing_subscriber::fmt;
fn main() -> Result<(), SeccompError> {
    let _subscriber = fmt::Subscriber::builder()
        .with_writer(std::io::stderr)
        .with_thread_ids(true)
        .compact()
        .init();
    println!("This process will be killed at the end!");

    let mut filter = Policy::allow_all()?;

    filter.exit_intercept(Syscall::Write, |mut interceptor| {
        println!("write() returned {}", interceptor.registers.return_value());
        // interceptor.registers.set_return_value(1000);
        // interceptor.commit_regs().unwrap();
        TraceAction::Continue
    });

    filter.entry_intercept(Syscall::Write, |mut interceptor| {
        println!("intercepted write() syscall");

        // interceptor.registers.set_rip(1);
        // interceptor.commit_regs().unwrap();

        println!("rdi {}", interceptor.registers.rdi());
        println!("rsi {}", interceptor.registers.rsi());
        println!("rdx {}", interceptor.registers.rdx());
        TraceAction::Continue
    });

    filter.apply()?;

    // openat() syscall
    let _read_fs = fs::read("test.txt").unwrap();
    println!("____{}____", String::from_utf8_lossy(_read_fs.as_slice()));
    // println!(
    // "The current proccess should be killed before this is displayed because this uses openat() syscall"
    // );
    Ok(())
}
