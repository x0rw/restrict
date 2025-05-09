use std::fs;

use restrict::{syscall::Syscall, *};

use policy::Policy;
fn main() -> Result<(), SeccompError> {
    let mut filter = Policy::allow_all()?;

    filter
        // Openat syscall should fail with errno 44
        .fail_with(Syscall::Openat, 44)?;
    filter.apply()?;

    // openat() syscall
    let _read_fs = fs::read("test.txt").unwrap();
    println!("This read will fail with errno 44 `Channel number is out of range`");
    Ok(())
}
