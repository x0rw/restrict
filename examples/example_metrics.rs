use metrics_exporter_prometheus::PrometheusBuilder;
use restrict::{
    policy::{Policy, Syscall},
    SeccompError, TraceAction,
};
use std::fs;
fn main() -> Result<(), SeccompError> {
    // Initialize Prometheus exporter
    let recorder = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install recorder");

    // Same example from example/example_05_syscall_trace.rs

    let mut policy = Policy::allow_all()?;
    policy.deny(Syscall::Munmap);
    policy.deny(Syscall::ExitGroup);
    policy.trace(Syscall::Openat, |syscall| {
        println!("Syscall {:?} triggered", syscall);
        return TraceAction::Continue;
    });
    policy.apply()?;
    let open_file = fs::File::open("test.txt");
    println!("Opened file {:?}", open_file);

    // render the metrics
    println!("{}", recorder.render());
    Ok(())
}
