//! Regression test for ADR-0019's graceful shutdown: a service manager stops the Client with
//! `SIGTERM` (systemd, launchd) — the process must exit cleanly (code 0, goodbye path) instead of
//! dying on the default signal disposition.

#![cfg(unix)]

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

/// Verifies: ADR-0019
#[test]
fn sigterm_shuts_the_client_down_cleanly() {
    let dir = tempfile::tempdir().expect("create a tempdir");
    let config = dir.path().join("supervisor.toml");
    // Port 9 (discard) refuses immediately: the client sits in its poll backoff when the signal
    // arrives — exactly where a service stop usually catches it.
    std::fs::write(
        &config,
        format!(
            "endpoint = \"http://127.0.0.1:9\"\nstate_dir = \"{}\"\n{}",
            dir.path().join("state").display(),
            common::client_identity(dir.path())
        ),
    )
    .expect("write the config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("--config")
        .arg(&config)
        .spawn()
        .expect("spawn the client");

    // Give it time to install the signal handlers and enter the transport loop.
    std::thread::sleep(Duration::from_millis(800));
    let kill = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(kill.success(), "kill -TERM failed");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            assert!(status.success(), "the client exited with {status}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the client did not exit within 10s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
