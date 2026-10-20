//! The OpAMP Fleet Client, as a library (ADR-0010).
//!
//! Every module of the Client lives here and `src/main.rs` is reduced to starting a process. The
//! reason is testability rather than reuse: Cargo will only hand a test the path of a helper binary
//! when that test is an *integration* test, and an integration test can only reach a package's
//! **library** — so the supervision code and the cross-platform stub it needs to spawn could not be
//! in the same test as long as this crate was a binary alone. What that cost was 22 tests gated to
//! Unix, covering the operations that write to a host: the binary swap, the health gate, the
//! rollback, and the ADR-0026 tree install.
//!
//! Nothing here is a published interface — the package is `publish = false`, and `pub` means
//! "another target in this workspace has to reach it" rather than "this is the shape of the
//! Client". The seam that *is* designed is ADR-0017's: the Ports and the plugin registry in
//! [`supervisor`].

pub mod archive;
pub mod cli;
pub mod config;
pub mod config_file;
pub mod config_init;
pub mod connection;
pub mod csr;
pub mod engine;
pub mod gateway;
pub mod host;
pub mod install;
pub mod logging;
pub mod packages;
pub mod product;
pub mod reconfigure;
pub mod service;
pub mod shutdown;
pub mod span;
pub mod storage;
pub mod supervisor;
pub mod telemetry;
pub mod tls;
pub mod transport;
pub mod update;
