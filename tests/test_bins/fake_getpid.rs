use restrict::policy::Policy;
use restrict::{syscall::Syscall, TraceAction};

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
#[cfg(target_arch = "x86_64")]
fn main() {
    let mut filter = Policy::allow_all().unwrap();

    filter.exit_intercept(Syscall::Getpid, move |mut interceptor| {
        interceptor.registers.set_return_value(56);
        interceptor.commit_regs().unwrap();
        TraceAction::Continue
    });

    filter.apply().unwrap();

    let pid = unsafe { libc::getpid() };
    println!("pid: {}", pid);
}
