//! `classis-admin` — the operator's commands for Spaces: the program `classis-cli`, and
//! the socket server the Server answers its requests on. Its only other Classis dependency is
//! `classis-core`, for the version this build reports; the Server reaches it through the `Spaces`
//! port.

#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod cli;
#[cfg(unix)]
pub mod client;
pub mod protocol;
pub mod render;
#[cfg(unix)]
pub mod server;
pub mod spaces;
