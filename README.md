# restrict

[![Crates.io](https://img.shields.io/crates/v/restrict.svg)](https://crates.io/crates/restrict)
[![Docs.rs](https://docs.rs/restrict/badge.svg)](https://docs.rs/restrict)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/x0rw/restrict/actions/workflows/rust.yml/badge.svg)](https://github.com/x0rw/restrict/actions/workflows/rust.yml)


**`restrict`  is an advanced Rust crate providing ergonomic and developer-friendly Linux syscall filtering.** 

It empowers you to precisely control, monitor, and even dynamically alter system calls at runtime through a clean, expressive API. With an auto-generated, system-aware `Syscall` enum and a robust policy manager, `restrict` offers built-in metrics, structured logging, and powerful interception hooks for advanced security and observability.

---

## Features

- **Auto‑generated** `Syscall` enum matched to your host architecture  
- **Ergonomic API** (e.g., `policy.allow(Syscall::Write)?;`)  
- **Safe wrappers**: all unsafe code is isolated in `wrapper.rs`  
- **Dual policy modes**: choose **allow‑by‑default** or **deny‑by‑default**  
- **Interception hooks**:  
  - `entry_intercept` & `exit_intercept` — inspect, modify, or skip individual syscalls  
  - **Registers manipulation** — read/write syscall arguments and return values  
- **Built‑in metrics**: Prometheus‑compatible counters, gauges, and histograms  
- **Structured logging**: plug into `tracing_subscriber` (or your own logger)  

---

## Prerequisites

On Linux, install the development headers for seccomp:

```bash
sudo apt-get update
sudo apt-get install -y libseccomp-dev
```

---

## Examples

Check out the `examples/` directory for runnable demos showcasing different features:

```bash
$ tree examples
examples
├── example_01_write.rs            # Simple write and open deny policy
├── example_02_openat.rs           # openat deny 
├── example_openat_errno.rs     # openat with custom errno
├── example_mul_tracing.rs      # Multiple syscall tracers
├── example_command.rs          # Execve sandbox
├── example_intercept.rs           # Write syscall Registers manipulation example
├── example_logs.rs                # Structured logging via tracing
├── prometheus_metrics.rs          # Prometheus metrics exporter example
└── truncate_filter.rs             # Truncate write() syscall demo similar to example_intercept
```

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
### Syscall Blocking:

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
### Syscall Tracing:

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
### Advanced syscall interception and register manipulation:
To intercept and manipulate a syscall arguments/return values and registers at entry and exit:
```rust
    let mut filter = Policy::allow_all().unwrap();
    // intercept time() syscall at exit and replace its return value with 3
    filter.exit_intercept(Syscall::Time, |mut interceptor| {
        interceptor.registers.set_return_value(3);  // set the return register to 3 (rax in x86-64)
        interceptor.commit_regs().unwrap();         // do this after every change
        TraceAction::Continue                       // Continue tracing
    });
    filter.apply().unwrap();
```
another example:
```rust
    // intercept write() syscall at entry
    filter.entry_intercept(Syscall::Write, move |mut interceptor| {
        // compare rdi register to 1 
        if interceptor.registers.get("rdi").unwrap() as i32 == 1 {
            interceptor.registers.set("rdx", 12).unwrap();  // change rdx to 12
            interceptor.commit_regs().unwrap();
        }
        TraceAction::Continue 
    });
```

make sure to check the `tests/` and `examples/`

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
