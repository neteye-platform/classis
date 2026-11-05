//! The Client's own log file, driven through the real binary (ADR-0019).
//!
//! The unit tests cover the writer and the rotation; what they cannot show is the thing the
//! decision exists for — that a process started the way a service manager starts it actually
//! produces a readable file, and that a process started by a person does not.
//!
//! **Unix only, and not because Windows does not matter — it is the platform that does.** On
//! Windows `run --service` enters the SCM dispatcher, which fails outside a real service context,
//! so the equivalent proof there belongs to `service_smoke.rs`, which installs a service for real.

#![cfg(unix)]

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Runs the Client the way `service install` writes the command line, against an endpoint nothing
/// answers on: it must still log, because the failures worth reading are exactly the ones where
/// there is no Server.
fn spawn(dir: &Path, args: &[&str]) -> Child {
    let config = dir.join("supervisor.toml");
    std::fs::write(
        &config,
        // Port 1 answers nothing, so this Client stays in its reconnect loop for the whole test.
        format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {:?}\n{}",
            dir.join("state").to_string_lossy(),
            common::client_identity(dir)
        ),
    )
    .expect("write config");
    Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("run")
        .args(args)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the client")
}

/// Waits for a file to appear under `dir`, or gives up.
fn wait_for_log(dir: &Path, within: Duration) -> Option<std::path::PathBuf> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("supervisor"))
                    && std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > 0
                {
                    return Some(path);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// The whole point: started as a service, the Client writes a log somebody can read — which on
/// Windows is the only copy that exists, since the SCM discards stderr.
/// Verifies: ADR-0019
#[test]
fn a_service_run_writes_a_log_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = spawn(dir.path(), &["--service"]);

    let logs = dir.path().join("state").join("logs");
    let found = wait_for_log(&logs, Duration::from_secs(20));
    let _ = child.kill();
    let _ = child.wait();

    let path = found.unwrap_or_else(|| panic!("no log file appeared in {}", logs.display()));
    let body = std::fs::read_to_string(&path).expect("read the log");
    assert!(
        body.contains("logging to file"),
        "the log says where it is going: {body}"
    );
    // Written without ANSI colour: this file is read with a pager, not a terminal.
    assert!(!body.contains('\u{1b}'), "no escape sequences in the file");
}

/// A person at a terminal is already reading stderr, so nothing is written to disk. This is the
/// half that keeps the feature from quietly leaving files behind every time somebody runs the
/// Client by hand.
/// Verifies: ADR-0019
#[test]
fn a_foreground_run_writes_no_log_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = spawn(dir.path(), &[]);

    // Long enough that the Client is well past start-up and into its reconnect loop.
    std::thread::sleep(Duration::from_secs(3));
    let _ = child.kill();
    let _ = child.wait();

    let logs = dir.path().join("state").join("logs");
    assert!(
        !logs.exists() || std::fs::read_dir(&logs).into_iter().flatten().count() == 0,
        "a foreground run left files in {}",
        logs.display()
    );
}
