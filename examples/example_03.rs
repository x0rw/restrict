use std::fs;

use restrict::*;

use policy::Policy;
use syscall::Syscall;
fn main() -> Result<(), SeccompError> {
    println!("This process will be killed at the end!");

    let mut filter = Policy::allow_all()?;
    filter.deny(Syscall::Openat);

    println!("This should work");
    filter.apply()?;

    // openat() syscall
    let _read_fs = fs::read("test.txt").unwrap();
    println!(
        "The current proccess should be killed before this is displayed because this uses openat() syscall"
    );
    Ok(())
}
