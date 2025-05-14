# restrict

[![Crates.io](https://img.shields.io/crates/v/restrict.svg)](https://crates.io/crates/restrict)
[![Docs.rs](https://docs.rs/restrict/badge.svg)](https://docs.rs/restrict)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/x0rw/restrict/actions/workflows/rust.yml/badge.svg)](https://github.com/x0rw/restrict/actions/workflows/rust.yml)


**Ergonomic and DX-first Linux syscall filtering crate**

`restrict` offers a clean, expressive API to allow or deny syscalls on Linux. It generates a system-aware `Syscall` enum at build time and exposes a safe policy manager to configure syscall rules for your application.

---

## Features

* **Auto-generated** `Syscall` enum matched to your host architecture
* **Ergonomic API** (e.g., `policy.allow(Syscall::Write)?;`)
* **Safe wrappers**: all unsafe code is isolated in `wrapper.rs`
* Select either **allow-by-default** or **deny-by-default** mode
* Attach custom handlers to intercept and manage specific syscalls

---

## Prerequisites

On Linux, install the development headers for seccomp:

```bash
sudo apt-get update
sudo apt-get install -y libseccomp-dev
```

---

## Quickstart

It’s usually safest to start with all syscalls permitted, then explicitly block the ones you don’t want:

```rust
use restrict::{Policy, Syscall};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Begin with everything allowed
    let mut policy = Policy::allow_all()?;

    // Block process creation and tracing
    policy
        .deny(Syscall::Execve)
        .deny(Syscall::Ptrace)
        .apply()?;  // Load the final rule set into the kernel

    // Your program continues here with the policy enforced
    Ok(())
}
```

If you prefer blocked syscalls to return a specific errno instead of killing the process:

```rust
let mut policy = Policy::allow_all()?;
policy
    .fail_with(Syscall::Execve, 5)   // Execve returns errno 5 (EIO)
    .fail_with(Syscall::Ptrace, 5)
    .apply()?;
```

For a stricter default that denies everything except what you explicitly allow:

```rust
let mut policy = Policy::deny_all()?;
policy
    .allow(Syscall::Read)
    .allow(Syscall::Write)
    .apply()?;
```

To trace or log a syscall at runtime, register a handler:

```rust

let mut policy = Policy::allow_all()?;
policy
    .trace(Syscall::Openat, |syscall| {
        println!("Intercepted syscall: {:?}", syscall);
        TraceAction::Continue
    })
    .apply()?;

// Attempt to open a file; your handler will run first
let result = fs::File::open("test.txt");
println!("File open result: {:?}", result);

```

The handler must return either `TraceAction::Continue` (allow the syscall) or `TraceAction::Kill` (abort the process).

---

## API Reference

* **`Policy::allow_all()`**
  Start with every syscall allowed; use `.deny(syscall)` or `.fail_with(syscall, errno)` to restrict.

* **`Policy::deny_all()`**
  Start with every syscall blocked; use `.allow(syscall)` to permit only what you need.

* **`policy.allow(syscall: Syscall)`**
  Permit the specified syscall.

* **`policy.deny(syscall: Syscall)`**
  Block the specified syscall, causing immediate process termination on invocation.

* **`policy.fail_with(syscall: Syscall, errno: u16)`**
  Block the syscall but return the given `errno` instead of killing the process.

* **`policy.trace(syscall: Syscall, handler: Fn(Syscall) -> TraceAction)`**
  Register a callback to run before the syscall; choose whether to continue or kill.

* **`policy.apply()`**
  Compile and load your configured rules into the kernel.


## Generated Syscall Enum
During build, `restrict` parses your system headers (e.g. /usr/include/asm/unistd_64.h) and emits:
```rust
/// System call list generated from `/usr/include/asm/unistd_64.h`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syscall {
    Read = 0,
    Write = 1,
    Open = 2,
    // … etc …
}
```

This ensures accuracy across architectures (x86_64, aarch64, etc.).
To override the header location:

```sh
SYSCALL_INCLUDE_DIR=/path/to/other/asm cargo build
```

## License

This project is licensed under the terms of the [MIT license](LICENSE).

See the [LICENSE](LICENSE) file for more details.
