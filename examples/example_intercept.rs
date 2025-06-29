use restrict::*;

use policy::Policy;
use syscall::Syscall;
fn main() -> Result<(), SeccompError> {
    let mut filter = Policy::allow_all()?;

    filter.entry_intercept(Syscall::Write, move |mut interceptor| {
        if interceptor.registers.get("rdi").unwrap() == 1 as u64 {
            interceptor.registers.set("rdx", 12).unwrap();
            interceptor.commit_regs().unwrap();
        }
        TraceAction::Continue
    });

    filter.apply()?;

    let msg = b"Hello, restrict world! only the first 12 char should be printed ";
    let _ = unsafe { libc::write(1, msg.as_ptr() as *const _, msg.len()) };

    // let _read_fs = fs::read("test.txt").unwrap();
    // println!("____{}____", String::from_utf8_lossy(_read_fs.as_slice()));
    Ok(())
}
