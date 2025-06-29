use restrict::policy::Policy;
use restrict::{syscall::Syscall, TraceAction};

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
    println!("{}", unsafe { libc::getuid() });
}
