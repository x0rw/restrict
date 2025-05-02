# restrict

**Ergonomic and DX-first Linux syscall filtering crate**

`restrict` offers a clean, expressive API to allow or deny syscalls on Linux. It generates a system-aware `Syscall` enum at build time and exposes a safe policy manager to configure syscall rules for your application.

---

## ✨ Features

- 🚀 **Auto-generated** `Syscall` enum tailored to your host architecture  
- 📝 **Ergonomic API**: `policy.allow(Syscall::Write)?;`  
- 🔒 **Safe wrapper**: no `unsafe` blocks or raw pointers  
- 🎛️ **Allow-by-default** or **deny-by-default** policy modes  
- 🔍 **Runtime inspection**: list allowed or killed syscalls  

---

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

Or, for a stricter base policy:

```rust
use restrict::{Policy, Syscall};

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut policy = Policy::deny_all()?;  
    policy
        .allow(Syscall::Read)?
        .allow(Syscall::Write)?
        .apply()?;  

    // only allow read and write
    Ok(())
}
```

## 🛠️ API Overview

- `Policy::allow_all()`
Starts with all syscalls allowed; then call `.deny(...)` for any you want to block.

- `Policy::deny_all()`
Starts with all syscalls denied; then call `.allow(...)` for any you need.

- `policy.allow(syscall: Syscall)` → `&mut Self`
Mark a syscall as allowed.

- `policy.deny(syscall: Syscall)` → `&mut Self`
Mark a syscall as killed.

- `policy.apply()` → `()`
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
