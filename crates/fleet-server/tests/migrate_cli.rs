//! `server migrate` as an operator runs it (ADR-0037 clause 14): three named directories, what it
//! did on standard output, and an exit code a script can act on.

use std::process::Command;

fn migrate(config_dir: &std::path::Path, data_dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_server"))
        .arg("migrate")
        .arg("--config-dir")
        .arg(config_dir)
        .arg("--packages-dir")
        .arg(config_dir.with_file_name("fleet-packages"))
        .arg("--data-dir")
        .arg(data_dir)
        .output()
        .expect("run the server binary")
}

/// An old layout migrates into a new data directory, which the command names for `server.toml`;
/// the same data directory a second time is refused, non-zero, and a call missing a directory is
/// a usage error.
/// Verifies: ADR-0037
#[test]
fn migrate_writes_a_new_data_directory_once_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_dir = dir.path().join("fleet-configs");
    std::fs::create_dir_all(config_dir.join("revocation")).expect("dir");
    std::fs::write(config_dir.join("revocation/revocations.json"), "[]").expect("list");
    let data_dir = dir.path().join("fleet-data");

    let out = migrate(&config_dir, &data_dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout.contains("carried: the revocation list"), "{stdout}");
    assert!(stdout.contains("set data_dir to it"), "{stdout}");
    assert!(data_dir.join("revocations.json").is_file());

    let again = migrate(&config_dir, &data_dir);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("not empty"),
        "{again:?}"
    );

    let usage = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["migrate", "--config-dir", "x"])
        .output()
        .expect("run the server binary");
    assert_eq!(usage.status.code(), Some(2));
}
