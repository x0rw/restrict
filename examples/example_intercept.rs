use restrict::*;

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

    // filter.exit_intercept(Syscall::Write, |interceptor| {
    //     // println!("write() returned {}", interceptor.registers.return_value());
    //     // interceptor.registers.set_return_value(1000);
    //     // interceptor.commit_regs().unwrap();
    //     TraceAction::Continue
    // });

    filter.entry_intercept(Syscall::Write, move |mut interceptor| {
        if interceptor.registers.rdi() == 1 as u64 {
            interceptor.registers.set_rdx(12);
            interceptor.commit_regs().unwrap();
        }

        // println!("rdi {}", interceptor.registers.rdi());
        // println!("rsi {}", interceptor.registers.rsi());
        // println!("rdx {}", interceptor.registers.rdx());
        TraceAction::Continue
    });

    filter.apply()?;

    let msg = b"Hello, restrict world! only the first 12 char should be printed ";
    let n = unsafe { libc::write(1, msg.as_ptr() as *const _, msg.len()) };

    // let _read_fs = fs::read("test.txt").unwrap();
    // println!("____{}____", String::from_utf8_lossy(_read_fs.as_slice()));
    Ok(())
}
