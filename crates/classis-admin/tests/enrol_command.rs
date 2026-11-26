//! `classis-cli enrol-command` end to end, over a Unix socket in a temporary directory, against an
//! in-memory `Spaces`.

#![cfg(unix)]

mod common;
use common::{run_cli, start};

const ENDPOINT: &str = "https://neteye.example/neteye/classis";

fn key() -> String {
    format!("cle1_acme_{}", "A".repeat(43))
}

fn linux() -> String {
    format!(
        "curl --proto '=https' --tlsv1.2 -fsSL {ENDPOINT}/install.sh | sudo sh -s -- --token '{}'",
        key()
    )
}

fn windows() -> String {
    format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm {ENDPOINT}/install.ps1))) -Token '{}'",
        key()
    )
}

async fn with_acme(args: &[&str]) -> common::Outcome {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    start(&socket);
    assert_eq!(run_cli(&socket, &["space", "create", "acme"]).await.code, 0);
    run_cli(&socket, args).await
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_command_for_linux_prints_the_curl_line() {
    let outcome = with_acme(&["enrol-command", "--space", "acme", "--os", "linux"]).await;

    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.out, format!("{}\n", linux()));
    assert_eq!(outcome.err, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_command_for_windows_prints_the_powershell_line() {
    let outcome = with_acme(&["enrol-command", "--space", "acme", "--os", "windows"]).await;

    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.out, format!("{}\n", windows()));
    assert_eq!(outcome.err, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn with_key_prints_the_key_alone_before_the_command() {
    for (os, command) in [("linux", linux()), ("windows", windows())] {
        let outcome =
            with_acme(&["enrol-command", "--space", "acme", "--os", os, "--with-key"]).await;

        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.out, format!("{}\n{command}\n", key()));
        assert_eq!(outcome.err, "");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_command_carries_the_key_and_never_a_space() {
    for os in ["linux", "windows"] {
        let outcome = with_acme(&["enrol-command", "--space", "acme", "--os", os]).await;

        assert!(outcome.out.contains(&key()), "{}", outcome.out);
        for space_argument in ["--space", "-Space", "SPACE="] {
            assert!(
                !outcome.out.contains(space_argument),
                "{space_argument} in {}",
                outcome.out
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_command_of_an_unknown_space_is_a_refusal() {
    let outcome = with_acme(&["enrol-command", "--space", "ghost", "--os", "linux"]).await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert_eq!(outcome.err, "classis-cli: the space ghost does not exist\n");
}
