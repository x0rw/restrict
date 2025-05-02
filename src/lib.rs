#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::missing_safety_doc)]
#![deny(clippy::missing_document)]

pub mod error;
pub mod policy;
mod wrapper;
pub use error::SeccompError;
pub mod modules;
pub mod syscall;
