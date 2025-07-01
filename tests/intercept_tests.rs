use assert_cmd::prelude::*;
use std::process::Command;

#[cfg(target_arch = "x86_64")]
#[test]
fn fake_getpid_test() {
    let mut cmd = Command::cargo_bin("fake_getpid").unwrap();
    cmd.assert().success().stdout("pid: 56\n");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fake_getuid_test() {
    let mut cmd = Command::cargo_bin("fake_getuid").unwrap();
    let output = cmd.output().expect("failed to run fake_getuid");

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if unsafe { libc::getuid() } == 0 {
        // running as root: accept either 0 or 999
        assert!(
            stdout == "0" || stdout == "999",
            "Unexpected output: {}",
            stdout
        );
        assert!(output.status.success());
    } else {
        // non-root: expect exactly 999
        cmd.assert().success().stdout("999\n");
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fake_time_test() {
    let mut cmd = Command::cargo_bin("fake_time").unwrap();
    cmd.assert().success().stdout("3\n");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn trace_count_test() {
    let mut cmd = Command::cargo_bin("count_trace").unwrap();
    cmd.assert()
        .success()
        .stdout("test\ntest\ntest\ntest2\nFinal count: 4\n");
}

#[cfg(target_arch = "x86_64")]
#[test]
// fail ptrace syscall itself with a custom perm error
fn test_custom_errno() {
    let mut cmd = Command::cargo_bin("blocked_ptrace").unwrap();
    cmd.assert()
        .success()
        .stdout("result:-1\nlast_os_error:permission denied\n");
}
#[cfg(target_arch = "x86_64")]
#[test]
fn test_trace_interception() {}
