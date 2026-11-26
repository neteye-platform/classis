//! `classis-cli --version` states the version this build actually is, with no Server in front of
//! it.

#![cfg(unix)]

use classis_admin::cli;

fn run(args: &[&str]) -> (u8, String, String) {
    let mut argv = vec!["classis-cli".to_owned()];
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(argv, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn printed() -> String {
    format!("classis-cli {}\n", classis_core::version::current())
}

#[test]
fn both_version_flags_print_the_baked_version_alone() {
    for flag in ["--version", "-V"] {
        let (code, out, err) = run(&[flag]);
        assert_eq!(code, 0, "{flag} exited {code} with {err:?}");
        assert_eq!(out, printed(), "{flag}");
        assert_eq!(err, "", "{flag}");
    }
}

/// The flag answers before anything reaches the socket, so an absent one changes nothing — which is
/// also what keeps `--version` usable on a host with no Server.
#[test]
fn the_version_flag_needs_no_server() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent.sock");

    let (code, out, err) = run(&["--socket", absent.to_str().unwrap(), "--version"]);

    assert_eq!(code, 0);
    assert_eq!(out, printed());
    assert_eq!(err, "");
}
