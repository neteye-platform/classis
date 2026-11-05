//! `server --version` states the version this build actually is (ADR-0012).
//!
//! The regression: it printed `CARGO_PKG_VERSION`, which is the number in `Cargo.toml` and so the
//! release this build is *heading for* — a development build claimed to be the release, and the
//! commit it came from appeared nowhere. The Client had reported the baked version all along, so
//! the two binaries of one workspace disagreed about what version they were.

use std::process::Command;

#[test]
fn the_version_flag_prints_the_baked_version_and_nothing_of_its_own() {
    let out = Command::new(env!("CARGO_BIN_EXE_server"))
        .arg("--version")
        .output()
        .expect("run the server binary");
    assert!(out.status.success(), "--version exited {:?}", out.status);

    let printed = String::from_utf8(out.stdout).expect("utf-8 output");
    assert_eq!(
        printed.trim(),
        format!("server {}", fleet_core::version::current()),
        "the flag must read the one helper every surface reads, not a second source"
    );
}

/// What the first assertion is worth depends on the helper not being the bare manifest number:
/// `CARGO_PKG_VERSION` would satisfy an equality check against itself. A build inside a repository
/// always carries the commit as build metadata, and outside one `build.rs` fails rather than
/// guessing — so this holds wherever the suite can run at all.
#[test]
fn the_baked_version_says_more_than_the_manifest_does() {
    let baked = fleet_core::version::current();
    let parsed =
        fleet_core::version::parse(baked).unwrap_or_else(|| panic!("{baked:?} is not a version"));
    assert_eq!(
        parsed.base,
        env!("CARGO_PKG_VERSION"),
        "a different release"
    );
    assert!(
        parsed.build.is_some(),
        "{baked:?} carries no commit, so it cannot be told apart from the manifest number"
    );
}
