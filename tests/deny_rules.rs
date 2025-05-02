mod tests {
    use std::process::{Command, Stdio};

    #[test]
    fn test_deny_write_syscall_kills_process() {
        // Run a test process that tries to make a denied syscall
        let mut child = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg("create_file_test") // in src/create_file.rs
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start process");

        // std::thread::sleep(std::time::Duration::from_secs(2));

        // The process should be killed when trying to make a 'write' syscall
        let status = child.wait().expect("Failed to wait on process");

        println!("{}", status);
        assert!(
            !status.success(),
            "The process should have been killed due to denied syscalls"
        );
    }
}
