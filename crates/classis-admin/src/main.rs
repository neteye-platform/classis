//! `classis-cli` — the operator's commands for Spaces.

#![forbid(unsafe_code)]

#[cfg(unix)]
use std::process::ExitCode;

#[cfg(unix)]
fn main() -> ExitCode {
    let code = classis_admin::cli::run(
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(code)
}

#[cfg(not(unix))]
fn main() {
    eprintln!("classis-cli: Unix domain sockets are required");
    std::process::exit(1);
}
