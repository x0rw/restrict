use libc::pid_t;

use crate::{wrapper::PtraceWrapper, SeccompError};

#[derive(Clone)]
/// registers
pub struct Registers {
    inner: libc::user_regs_struct,
}

impl Registers {
    /// encapsulate libc user_regs_struct in Registers
    pub fn from_raw(raw: libc::user_regs_struct) -> Self {
        Registers { inner: raw }
    }
    /// Change the syscall registers
    pub(crate) fn commit_regs(&self, child_pid: pid_t) -> Result<(), SeccompError> {
        PtraceWrapper::set_registers(child_pid, self.inner).unwrap();
        Ok(())
    }

    /// convert it back
    pub fn into_raw(self) -> libc::user_regs_struct {
        self.inner
    }

    /// rip
    pub fn rip(&self) -> u64 {
        self.inner.rip
    }

    /// rax
    pub fn rax(&self) -> u64 {
        self.inner.rax
    }

    /// rdx
    pub fn rdx(&self) -> u64 {
        self.inner.rdx
    }

    /// rsi
    pub fn rsi(&self) -> u64 {
        self.inner.rsi
    }

    /// set rip
    pub fn set_rip(&mut self, val: u64) {
        self.inner.rip = val;
    }

    /// set rdx
    pub fn set_rdx(&mut self, val: u64) {
        self.inner.rdx = val;
    }
    /// set rax
    pub fn set_rax(&mut self, val: u64) {
        self.inner.rax = val;
    }

    /// rsp
    pub fn rsp(&self) -> u64 {
        self.inner.rsp
    }

    /// set rsp
    pub fn set_rsp(&mut self, val: u64) -> u64 {
        self.inner.rsp = val;
        val
    }

    /// rdi
    pub fn rdi(&self) -> u64 {
        self.inner.rdi
    }

    /// syscall number
    pub fn syscall_number(&self) -> u64 {
        self.inner.orig_rax
    }

    /// ret value
    pub fn return_value(&self) -> u64 {
        self.inner.rax
    }

    /// set ret value
    pub fn set_return_value(&mut self, val: u64) {
        self.inner.rax = val;
    }

    /// rdi
    pub fn arg0(&self) -> u64 {
        self.inner.rdi
    }

    /// rsi
    pub fn arg1(&self) -> u64 {
        self.inner.rsi
    }

    /// rdx
    pub fn arg2(&self) -> u64 {
        self.inner.rdx
    }

    /// r10
    pub fn arg3(&self) -> u64 {
        self.inner.r10
    }
}
