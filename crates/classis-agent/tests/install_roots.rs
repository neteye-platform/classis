//! `service install` against a `supervisor.toml` the service's account rewrote (ADR-0053, ADR-0042
//! clause 2): driven through the real command line, because the refusal is only worth anything
//! if it comes before the install has created, restricted or handed over a thing.
//!
//! Linux only: the command is run at `--user` scope with every per-user location in a temporary
//! directory, so that it can never register anything on the host running the test. On macOS a
//! user-scope install would load a job into the real user session, and Windows has no user-scope
//! service at all.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

/// Runs `service install --user --root <root>` against `config`, with every per-user location
/// pointed into `home` so that nothing outside the test's directory is touched.
fn install(config: &Path, root: &Path, home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("--config")
        .arg(config)
        .args(["service", "install", "--user", "--root"])
        .arg(root)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .output()
        .expect("run the client")
}

/// A state directory the file names outside the install's roots is refused, naming it and
/// `--state-dir`, and the install has created nothing: not the root, not that directory.
/// Verifies: ADR-0053, ADR-0042
#[test]
fn an_install_refuses_a_state_directory_the_file_names_outside_its_roots_before_any_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let root = dir.path().join("root");
    let outside = dir.path().join("elsewhere");
    let config = dir.path().join("supervisor.toml");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::write(&config, format!("state_dir = '{}'\n", outside.display())).expect("write");

    let output = install(&config, &root, &home);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the install went ahead: {stderr}");
    assert!(
        stderr.contains("refusing the state directory")
            && stderr.contains(&outside.display().to_string())
            && stderr.contains("--state-dir"),
        "{stderr}"
    );
    assert!(
        !root.exists(),
        "the install created its root before refusing"
    );
    assert!(
        !outside.exists(),
        "the install created the refused directory"
    );
}
