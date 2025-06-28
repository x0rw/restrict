use libc::pid_t;

use crate::{policy::Syscall, registers::Registers, SeccompError};

/// The Interceptor callback arguments
pub struct Interceptor {
    /// syscall
    pub syscall: Syscall,
    /// registers
    pub registers: Registers,
    /// child_pid
    pub child_pid: pid_t,
}

impl Interceptor {
    /// start a new global interceptor per syscall(in the event loop)
    pub fn new(sc: Syscall, regs: Registers, child_pid: pid_t) -> Self {
        Self {
            syscall: sc,
            registers: regs,
            child_pid: child_pid,
        }
    }
    /// commit registers
    pub fn commit_regs(&self) -> Result<(), SeccompError> {
        self.registers.commit_regs(self.child_pid)?;
        Ok(())
    }
}
