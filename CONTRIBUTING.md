# Contributing to `restrict`

🎉 Thanks for your interest in contributing to `restrict`! We welcome improvements, bug fixes, feature suggestions, and community involvement of all kinds.

## 🛠 What is `restrict`?

`restrict` is a developer-friendly Rust crate for controlling Linux syscalls using **seccomp**. It provides a clean and ergonomic API, prioritizing **safety**, **clarity**, and **DX** (developer experience).

---



## 🧩 How to Contribute

### Understand the Project

- Read the [README](README.md)
- Review the [API docs](https://docs.rs/restrict)
- Familiarize yourself with `libseccomp` and if you're working on advanced features

### Reporting Bugs

Please include:

- A minimal reproducible example (if possible)
- Your OS and architecture
- The `restrict` version
- Steps to reproduce

Create an issue [here](https://github.com/x0rw/restrict/issues).

### Proposing Features

When opening a feature request:

- Explain your use case and why this feature is important
- Keep it focused: one feature per issue
- Bonus: suggest a rough API shape!

### Building Locally

```bash
# Install libseccomp
sudo apt install libseccomp-dev

# Build the crate
cargo build

# Run tests
cargo test
```


## ✅ Reviewing

- Clear and minimal APIs
- No runtime surprises
- Good error messages
- Secure defaults


## License
By contributing, you agree that your contributions will be licensed under the same license as the project: MIT.

Thanks again for your interest! ❤️

