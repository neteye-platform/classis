//! A stub Managed Process that will not stay up — the other half of what the health gate needs to
//! be testable (ADR-0017's apply grace, ADR-0026's rollback of a file and of a tree).
//!
//! It exits non-zero at once, whatever it is called with, and that is the whole point: what those
//! tests install is an **artifact**, and what they assert is that installing bad bytes puts the good
//! bytes back. The behaviour therefore has to be *in the bytes*. `stub_agent --exit-code 1` cannot
//! serve — arguments belong to the Supervisor's configuration, and swapping a program never changes
//! them, so a crash driven by arguments would crash the version before the update too.
//!
//! Pure Rust and argument-free, so it behaves identically on Linux, macOS and Windows CI.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(1)
}
