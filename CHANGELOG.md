# Changelog

## [0.1.1] - 2025-05-02
### Changed
- Removed debug `println!()` that was triggering unnecessary `write()` syscall.

## [0.1.2] - 2025-05-02
### Changed
- Dockerfile
- CI/CD improvements
- Update README.md

## [0.1.3] - 2025-05-06
### Added 
- Add fail_with(Syscall, errno) to fail with specific errno instead of killing the process

## [0.1.4] - 2025-05-09
### Added 
- Add Syscall tracing trace(Syscall, Fn(Syscall) -> TraceAction ) with custom hook function
- Example tracing usage
- Low level Ptrace wrapper

## [0.1.5] - 2025-05-15
### Added 
- Add support for Tracing multiple syscalls at the same time
- Fix Issues

