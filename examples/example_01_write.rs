use restrict::*;

use policy::Policy;
// use syscall::Syscall;
use syscall::Syscall;
fn main() -> Result<(), SeccompError> {
    println!("This will process will be killed!");

    let mut filter = Policy::allow_all()?;
    filter.deny(Syscall::Write)?;
    filter.deny(Syscall::Open)?;

    println!("This should work");
    filter.apply()?;
    println!(
        "The current proccess should be killed before this is displayed because this uses write() syscall"
    );
    Ok(())
}
