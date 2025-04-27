use restrict::*;

use policy::SeccompPolicy;
// use syscall::Syscall;
use syscalls::Syscall;
fn main() -> Result<(), SeccompError> {
    println!("This will process will be killed!");

    let mut filter = SeccompPolicy::allow_all()?;
    filter.deny(Syscall::Write)?;
    filter.deny(Syscall::Open)?;

    println!("This should work");
    filter.apply()?;
    println!(
        "The current proccess should be killed before this is displayed because this uses write() syscall"
    );
    Ok(())
}
