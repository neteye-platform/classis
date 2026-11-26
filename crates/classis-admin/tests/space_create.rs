//! `classis-cli space create` end to end: the real command tree, client and socket server over a
//! Unix socket in a temporary directory, against an in-memory `Spaces`.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use classis_admin::protocol::{Response, MAX_MESSAGE_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

mod common;
use common::{run_cli, start};

#[tokio::test(flavor = "multi_thread")]
async fn space_create_prints_the_key_alone() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let fake = start(&socket);

    let outcome = run_cli(&socket, &["space", "create", "acme"]).await;

    let key = format!("cle1_acme_{}", "A".repeat(43));
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.out, format!("{key}\n"));
    assert_eq!(outcome.err, "");
    assert_eq!(fake.0.lock().unwrap().get("acme"), Some(&key));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_is_a_non_zero_exit_with_its_message_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    start(&socket);

    assert_eq!(run_cli(&socket, &["space", "create", "acme"]).await.code, 0);
    let second = run_cli(&socket, &["space", "create", "acme"]).await;

    assert_eq!(second.code, 1);
    assert_eq!(second.out, "");
    assert!(
        second.err.contains("the space acme exists already"),
        "{}",
        second.err
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_server_on_the_socket_is_a_non_zero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("nobody.sock");

    let outcome = run_cli(&socket, &["space", "create", "acme"]).await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert!(
        outcome
            .err
            .starts_with("classis-cli: cannot reach the Server at"),
        "{}",
        outcome.err
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_socket_is_restricted_to_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    start(&socket);

    let mode = std::fs::metadata(&socket).unwrap().permissions().mode();

    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_request_is_refused_without_reaching_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let fake = start(&socket);

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let request = vec![b' '; usize::try_from(MAX_MESSAGE_BYTES).unwrap() + 1];
    stream.write_all(&request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();

    assert_eq!(
        serde_json::from_slice::<Response>(&answer).unwrap(),
        Response::Refused {
            message: "the request is too large".to_owned()
        }
    );
    assert!(fake.0.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_command_does_not_expect_is_a_non_zero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream
                .write_all(br#"{"response":"names","names":[]}"#)
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    let outcome = run_cli(&socket, &["space", "create", "acme"]).await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert_eq!(
        outcome.err,
        "classis-cli: the Server gave an unexpected answer\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_cli_cannot_parse_is_a_non_zero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream.write_all(b"not json").await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    let outcome = run_cli(&socket, &["space", "create", "acme"]).await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert!(
        outcome
            .err
            .starts_with("classis-cli: the Server's answer is not understood:"),
        "{}",
        outcome.err
    );
}
