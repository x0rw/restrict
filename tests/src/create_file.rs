use std::fs::File;
use std::io::Write;
use std::process;

use restrict::policy::Policy;
use restrict::syscall::Syscall;

fn main() {
    let mut policy = Policy::allow_all().expect("Failed to create policy");
    policy
        .deny(Syscall::Write)
        .expect("Failed to deny write syscall");
    policy.apply().expect("could not apply the policy");
    let file = File::create("test.txt");
    if let Ok(mut file) = file {
        if let Err(e) = writeln!(file, "This is a test.") {
            eprintln!("Error writing to file: {}", e);
            process::exit(1);
        }
    } else {
        eprintln!("Failed to create file.");
        process::exit(1);
    }

    // If write and file creation succeed, print a success message
    println!("File operations successful!");
}
