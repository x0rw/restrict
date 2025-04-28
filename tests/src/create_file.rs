use std::fs::File;
use std::io::{self, Write};
use std::process;

fn main() {
    // Try to open a file (for testing purposes)
    let file = File::create("test.txt");

    // If this succeeds, write some data to the file
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
