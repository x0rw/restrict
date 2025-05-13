use libc::pid_t;

use crate::{filter::RestrictFilter, wrapper::PtraceWrapper};

/// tracing struct

pub enum TracingHandle {
    Child,
    Parent {
        pid: pid_t,
        tracer: PtraceWrapper,
        // todo todo todo, am ashamed
        filters: Vec<Box<dyn RestrictFilter>>,
    },
}
