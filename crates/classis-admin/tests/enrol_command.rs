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
        "curl --proto '=https' --tlsv1.3 -fsS '{ENDPOINT}/v1/install.sh' | sudo sh -s -- --url '{ENDPOINT}' --key '{}'",
        key()
    )
}

fn windows() -> String {
    format!(
        "[Net.ServicePointManager]::SecurityProtocol = 12288; & ([scriptblock]::Create((Invoke-RestMethod -Uri '{ENDPOINT}/v1/install.ps1' -MaximumRedirection 0))) -Url '{ENDPOINT}' -Key '{}'",
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
async fn the_key_is_an_argument_never_part_of_the_script_url() {
    for os in ["linux", "windows"] {
        let outcome = with_acme(&["enrol-command", "--space", "acme", "--os", os]).await;

        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.out.matches(&key()).count(), 1, "{}", outcome.out);
        let script_url = outcome
            .out
            .split_whitespace()
            .find(|word| word.contains("/v1/install."))
            .expect("the script URL");
        assert!(
            script_url.starts_with(&format!("'{ENDPOINT}/v1/install.")),
            "{script_url}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_command_of_an_unknown_space_is_a_refusal() {
    let outcome = with_acme(&["enrol-command", "--space", "ghost", "--os", "linux"]).await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert_eq!(outcome.err, "classis-cli: the space ghost does not exist\n");
}
