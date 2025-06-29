use libc::pid_t;

use crate::{wrapper::PtraceWrapper, SeccompError};

#[derive(Clone)]
/// registers
pub struct Registers {
    inner: libc::user_regs_struct,
}

#[cfg(target_arch = "x86_64")]
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

    /// get a map of all registers
    pub fn as_map(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("rax", self.inner.rax),
            ("rbx", self.inner.rbx),
            ("rcx", self.inner.rcx),
            ("rdx", self.inner.rdx),
            ("rsi", self.inner.rsi),
            ("rdi", self.inner.rdi),
            ("rbp", self.inner.rbp),
            ("rsp", self.inner.rsp),
            ("r8", self.inner.r8),
            ("r9", self.inner.r9),
            ("r10", self.inner.r10),
            ("r11", self.inner.r11),
            ("r12", self.inner.r12),
            ("r13", self.inner.r13),
            ("r14", self.inner.r14),
            ("r15", self.inner.r15),
            ("rip", self.inner.rip),
            ("eflags", self.inner.eflags),
        ]
    }
    /// get syscall by name
    pub fn get(&self, reg_name: &str) -> Option<u64> {
        self.as_map()
            .into_iter()
            .find(|(x, _)| *x == reg_name)
            .map(|(_, y)| y)
    }

    /// set a syscall value by spesifying its name
    pub fn set(&mut self, name: &str, val: u64) -> Result<(), SeccompError> {
        match name {
            "rax" => self.inner.rax = val,
            "rbx" => self.inner.rbx = val,
            "rcx" => self.inner.rcx = val,
            "rdx" => self.inner.rdx = val,
            "rsi" => self.inner.rsi = val,
            "rdi" => self.inner.rdi = val,
            "rbp" => self.inner.rbp = val,
            "rsp" => self.inner.rsp = val,
            "r8" => self.inner.r8 = val,
            "r9" => self.inner.r9 = val,
            "r10" => self.inner.r10 = val,
            "r11" => self.inner.r11 = val,
            "r12" => self.inner.r12 = val,
            "r13" => self.inner.r13 = val,
            "r14" => self.inner.r14 = val,
            "r15" => self.inner.r15 = val,
            "rip" => self.inner.rip = val,
            "eflags" => self.inner.eflags = val,
            _ => return Err(SeccompError::Unknown),
        };
        Ok(())
    }

    /// convert it back
    pub fn into_raw(self) -> libc::user_regs_struct {
        self.inner
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
}

#[cfg(target_arch = "aarch64")]
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

    /// get a map of all registers
    pub fn as_map(&self) -> Vec<(&'static str, u64)> {
        let mut regs: Vec<(&'static str, u64)> = Vec::new();
        for i in 0..31 {
            regs.push((format!("x{}", i).leak(), self.inner.regs[i]));
        }
        regs.extend_from_slice(&[
            ("sp", self.inner.sp),
            ("pc", self.inner.pc),
            ("pstate", self.inner.pstate),
        ]);
        regs
    }
    /// get syscall by name
    pub fn get(&self, reg_name: &str) -> Option<u64> {
        if let Some(xn) = reg_name
            .strip_prefix("x")
            .and_then(|n| n.parse::<usize>().ok())
        {
            if xn < 31 {
                return Some(self.inner.regs[xn]);
            }
        }
        match reg_name {
            "sp" => Some(self.inner.sp),
            "pc" => Some(self.inner.pc),
            "pstate" => Some(self.inner.pstate),
            _ => None,
        }
    }

    /// set a syscall value by spesifying its name
    pub fn set(&mut self, name: &str, val: u64) -> Result<(), SeccompError> {
        if let Some(xn) = name.strip_prefix("x").and_then(|n| n.parse::<usize>().ok()) {
            if xn < 31 {
                self.inner.regs[xn] = val;
                return Ok(());
            }
        }
        match name {
            "sp" => self.inner.sp = val,
            "pc" => self.inner.pc = val,
            "pstate" => self.inner.pstate = val,
            _ => return Err(SeccompError::Unknown),
        };
        Ok(())
    }

    /// convert it back
    pub fn into_raw(self) -> libc::user_regs_struct {
        self.inner
    }

    /// syscall number
    pub fn syscall_number(&self) -> u64 {
        self.get("x8").unwrap()
    }

    /// ret value
    pub fn return_value(&self) -> u64 {
        self.get("x0").unwrap()
    }

    /// set ret value
    pub fn set_return_value(&mut self, val: u64) {
        self.set("x0", val).unwrap()
    }
}
