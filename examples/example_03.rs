use std::fs;

use restrict::*;

use policy::SeccompPolicy;
use syscall::Syscall;
fn main() -> Result<(), SeccompError> {
    println!("This will process will be killed!");

    let mut filter = SeccompPolicy::allow_all()?;
    filter.deny(Syscall::OpenAt)?;

    println!("This should work");
    filter.apply()?;

    // openat() syscall
    let _read_fs = fs::read("test.txt").unwrap();
    println!(
        "The current proccess should be killed before this is displayed because this uses openat() syscall"
    );
    Ok(())
}
