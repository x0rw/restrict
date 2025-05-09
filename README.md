# restrict

[![Crates.io](https://img.shields.io/crates/v/restrict.svg)](https://crates.io/crates/restrict)
[![Docs.rs](https://docs.rs/restrict/badge.svg)](https://docs.rs/restrict)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/x0rw/restrict/actions/workflows/rust.yml/badge.svg)](https://github.com/x0rw/restrict/actions/workflows/rust.yml)


**Ergonomic and DX-first Linux syscall filtering crate**

`restrict` offers a clean, expressive API to allow or deny syscalls on Linux. It generates a system-aware `Syscall` enum at build time and exposes a safe policy manager to configure syscall rules for your application.

---

## ✨ Features

- **Auto-generated** `Syscall` enum tailored to your host architecture  
- **Ergonomic API**: `policy.allow(Syscall::Write)?;`  
- **Safe wrapper**: Unsafe wrappers are in `wrapper.rs`
- **Allow-by-default** or **deny-by-default** policy modes  
- **Hook functions** Hook a function to control a syscall

---
## Prerequisites

You need `libseccomp-dev` installed in your Linux

```bash
sudo apt-get update && sudo apt-get install -y libseccomp-dev
```




## 🚀 Quickstart

> ✅ **`allow_all()` is the recommended default for most use cases to avoid unintentionally blocking essential syscalls.**

```rust
use restrict::{Policy, Syscall, Action};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start with all syscalls allowed
    let mut policy = Policy::allow_all()?; // recommended

    policy
        .deny(Syscall::Execve)?   // prevent process spawning
        .deny(Syscall::Ptrace)?   // prevent tracing/hijacking
        .apply()?;                // apply the final filter set

    // Your program continues safely here
    Ok(())
}
```
Or fail the syscall with a specific error number:
```rust
    let mut policy = Policy::allow_all()?;
    policy
        .fail_with(Syscall::Execve, 5)?   // this syscall will return errno 5
        .fail_with(Syscall::Ptrace, 5)? 
        .apply()?;             
```

Or, for a stricter base policy:

```rust
    let mut policy = Policy::deny_all()?;  
    policy
        .allow(Syscall::Read)?
        .allow(Syscall::Write)?
        .apply()?;  
```

Or, execute a function when a syscall is invoked:
`trace<T>(&mut self, syscall: Syscall, handler: T) where T: Fn(Syscall) -> TraceAction,`
```rust
    let mut policy = Policy::allow_all()?;
    policy
        .trace(Syscall::Openat, |syscall| {
            println!("Syscall {:?} triggered", syscall);
            return TraceAction::Continue;
        })?
        .apply()?;
    let open_file = fs::File::open("test.txt");
    println!("Opened file {:?}", open_file);
```
possible return variants are `TraceAction::Continue` and `TraceAction::Kill`

## 🛠️ API Overview

- `Policy::allow_all()`
Starts with all syscalls allowed; then call `.deny(...)` for any you want to block.

- `Policy::deny_all()`
Starts with all syscalls denied; then call `.allow(...)` for any you need.

- `policy.allow(syscall: Syscall)`
Will allow this syscall

- `policy.fail_with(syscall: Syscall, errno: u16)`
Will fail this syscall

- `policy.trace(syscall: Syscall, handler: Fn(Syscall) -> TraceAction)`
Hook a handler before the running the target syscall


- `policy.deny(syscall: Syscall)` 
Will kill this syscall

- `policy.apply()` 
Finalize and load all collected filters into the kernel.

- `policy.list_allowed_syscalls()` -> `Vec<Syscall>`
Retrieve the list of syscalls you’ve allowed(by `allow()`).

- `policy.list_killed_syscalls()` -> `Vec<Syscall>`
Retrieve the list of syscalls you’ve denied(by `deny()`).

## 📦 Generated Syscall Enum
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
