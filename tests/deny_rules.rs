mod tests {
    use std::io::{self, Read};
    use std::process::{Command, Stdio};

    use restrict::policy::SeccompPolicy;
    use restrict::syscalls::Syscall;

    #[test]
    fn test_deny_write_syscall_kills_process() {
        let mut policy = SeccompPolicy::allow_all().expect("Failed to create policy");
        policy
            .deny(Syscall::Write)
            .expect("Failed to deny write syscall");
        // Run a test process that tries to make a denied syscall
        let mut child = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg("create_file_test") // in src/create_file.rs
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start process");

        // Capture the output from stdout and stderr
        let mut stdout = String::new();
        let mut stderr = String::new();

        if let Some(mut out) = child.stdout.take() {
            out.read_to_string(&mut stdout)
                .expect("Failed to read stdout");
        }

        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr)
                .expect("Failed to read stderr");
        }

        // Wait a little while to ensure the process hits the filter
        std::thread::sleep(std::time::Duration::from_secs(2));

        // The process should be killed when trying to make a 'write' syscall
        let status = child.wait().expect("Failed to wait on process");

        // Print the captured stdout and stderr
        println!("stdout:\n{}", stdout);
        println!("stderr:\n{}", stderr);

        // Check the exit status
        println!("{}", status);
        assert!(
            !status.success(),
            "The process should have been killed due to denied syscalls"
        );
    }
}
