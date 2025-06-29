use std::sync::atomic::{AtomicUsize, Ordering};

use restrict::{
    policy::{Policy, Syscall},
    TraceAction,
};

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
#[cfg(target_arch = "x86_64")]
fn main() {
    // crate a shared memory that survives the forking
    let shared_mem = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<AtomicUsize>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if shared_mem == libc::MAP_FAILED {
        panic!("Failed to create shared memory");
    }
    let trace_count = unsafe { &*(shared_mem as *const AtomicUsize) };
    trace_count.store(0, Ordering::SeqCst);

    let mut policy = Policy::allow_all().unwrap();
    policy
        .trace(Syscall::Write, |_| {
            trace_count.fetch_add(1, Ordering::SeqCst);
            TraceAction::Continue
        })
        .apply()
        .unwrap();

    // Trigger some writes
    println!("test");
    println!("test");
    println!("test");
    println!("test2");

    let count = trace_count.load(Ordering::SeqCst);
    println!("Final count: {}", count);

    assert_eq!(trace_count.load(Ordering::SeqCst), 5);
    std::process::exit(0);
}
