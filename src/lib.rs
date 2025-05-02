#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::missing_safety_doc)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod error;
pub mod policy;
mod wrapper;
pub use error::SeccompError;
pub mod modules;
pub mod syscall;
