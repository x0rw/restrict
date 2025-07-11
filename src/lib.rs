/*
MIT License

Copyright (c) 2025 x0rw

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

//! Restrict
#![deny(missing_docs)]

/// Error handling module
pub mod error;
/// filters
mod filter;
/// interceptors
pub mod interceptor;
/// Modules for most common rules
// this should be called profiles
// pub mod modules;
/// Safer, unsafe-free and ergonomic wrapper around wrapper module
pub mod policy;
/// registers
pub mod registers;
/// Strongly tyoed system calls enum
pub mod syscall;
/// Tracer
mod tracer;
/// unsafe bindings
mod wrapper;
pub use error::SeccompError;
pub use wrapper::TraceAction;
pub(crate) mod logging;
pub(crate) mod metrics;
