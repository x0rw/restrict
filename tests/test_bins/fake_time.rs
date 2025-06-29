use restrict::policy::Policy;
use restrict::{syscall::Syscall, TraceAction};

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
#[cfg(target_arch = "x86_64")]
fn main() {
    let mut filter = Policy::allow_all().unwrap();
    filter.exit_intercept(Syscall::Time, |mut i| {
        i.registers.set_return_value(3);
        i.commit_regs().unwrap();
        TraceAction::Continue
    });
    filter.apply().unwrap();

    // using time() from a libc wrapper actually reads directly from a shared memory page without
    // switching to kernel so although our hook function detects the entry and exit, changing the
    // return register won't be reflected as a real return  so we use libc::syscall directly here
    // for testing
    // let t = unsafe { libc::time(std::ptr::null_mut()) }; // wont work

    let t = unsafe { libc::syscall(Syscall::Time as i64, std::ptr::null_mut::<libc::time_t>()) };
    println!("{}", t);
}
