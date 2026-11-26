//! `classis-cli space list` and `space rotate-key` end to end, over a Unix socket in a temporary
//! directory, against an in-memory `Spaces`.

#![cfg(unix)]

mod common;
use common::{run_cli, start};

#[tokio::test(flavor = "multi_thread")]
async fn space_list_prints_each_name_on_its_own_line() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    start(&socket);
    assert_eq!(run_cli(&socket, &["space", "create", "beta"]).await.code, 0);
    assert_eq!(run_cli(&socket, &["space", "create", "acme"]).await.code, 0);

    let outcome = run_cli(&socket, &["space", "list"]).await;

    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.out, "acme\nbeta\n");
    assert_eq!(outcome.err, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn space_list_with_no_spaces_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    start(&socket);

    let outcome = run_cli(&socket, &["space", "list"]).await;

    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.out, "");
    assert_eq!(outcome.err, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn space_rotate_key_prints_a_new_key_alone() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let fake = start(&socket);
    let created = run_cli(&socket, &["space", "create", "acme"]).await;

    let outcome = run_cli(&socket, &["space", "rotate-key", "acme"]).await;

    let new_key = format!("cle1_acme_{}", "B".repeat(43));
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.out, format!("{new_key}\n"));
    assert_ne!(outcome.out, created.out);
    assert_eq!(outcome.err, "");
    assert_eq!(fake.0.lock().unwrap().get("acme"), Some(&new_key));
}

#[tokio::test(flavor = "multi_thread")]
async fn space_rotate_key_of_an_unknown_space_is_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    start(&socket);

    let outcome = run_cli(&socket, &["space", "rotate-key", "ghost"]).await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert_eq!(outcome.err, "classis-cli: the space ghost does not exist\n");
}
