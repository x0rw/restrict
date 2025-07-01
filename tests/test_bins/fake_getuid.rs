use restrict::policy::Policy;
use restrict::{TraceAction, syscall::Syscall};

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
#[cfg(target_arch = "x86_64")]
fn main() {
    let mut filter = Policy::allow_all().unwrap();
    filter.exit_intercept(Syscall::Getuid, |mut i| {
        i.registers.set_return_value(999);
        i.commit_regs().unwrap();
        TraceAction::Continue
    });
    filter.apply().unwrap();
    let uid = unsafe { syscall_uid(Syscall::Getuid) };
    println!("{}", uid);
}
// this may look weird, why calling a syscall from asm instead of using libc::getuid()
// this is mainly because of VDSO(virtual dynamic shared object) which instead of calling the real
// syscall it uses a shared object in user space to look up the getuid value, the more mmodern the kernel and glibc is, the
// more syscall are VDSO'd, this issue doesn't happen locally but it happens undeterministically in
// github actions
#[cfg(target_arch = "x86_64")]
unsafe fn syscall_uid(syscall_num: Syscall) -> u64 {
    let nr = syscall_num as u64;
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
        );
    }
    ret
}
