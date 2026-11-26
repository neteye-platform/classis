//! Who the operator's socket serves, and that a failed accept costs it nothing.
//!
//! The failed accept is a starved descriptor limit, which a whole process shares: the listener
//! therefore runs in a child of this binary, so no other test feels either the limit or its
//! restore.

#![cfg(all(unix, target_os = "linux"))]

use std::path::PathBuf;
use std::time::Duration;

use classis_admin::protocol::{Request, Response};
use classis_admin::server::admit;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

mod common;
use common::start;

/// Set for the child of [`an_accept_error_does_not_stop_the_socket`] to the socket it serves.
const SOCKET: &str = "CLASSIS_TEST_ACCEPT_RETRY_SOCKET";

/// The descriptor ceiling the child drives itself down to. A handful of opened files exhausts it,
/// however many the runtime already holds open.
const CEILING: libc::rlim_t = 64;

/// How long the starved listener is left to its own devices: several times the sleep its accept
/// error takes, so the failure has certainly been taken before the descriptors come back.
const STARVED: Duration = Duration::from_millis(500);

/// How long a recovered listener's answer is waited for. A listener that stopped instead of
/// retrying spends all of it before the test fails.
const RECOVERY: Duration = Duration::from_secs(5);

/// The socket serves its owner and root — the account `sudo classis-cli` runs as — and no other.
#[test]
fn the_socket_serves_its_owner_and_root() {
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    let owner = unsafe { libc::geteuid() };
    assert!(admit(owner, owner).is_ok(), "the Server's own account");
    assert!(admit(0, owner).is_ok(), "root");
    assert!(
        admit(owner.wrapping_add(1), owner).is_err(),
        "any other account"
    );
}

#[tokio::test]
async fn socket_owner_is_the_process_effective_user() {
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    let owner = unsafe { libc::geteuid() };
    assert_eq!(classis_admin::server::effective_uid().unwrap(), owner);
}

/// A connection the listener cannot accept is not the end of the listener: once there is a
/// descriptor again it takes the queued connection and answers it.
#[test]
fn an_accept_error_does_not_stop_the_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("admin.sock");
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "the_starved_listener_answers_again",
            "--exact",
            "--nocapture",
        ])
        .env(SOCKET, &socket)
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The child of [`an_accept_error_does_not_stop_the_socket`]: serves the socket with its own
/// descriptors driven empty, then gives them back. Run on its own, with no socket named, it passes
/// trivially.
#[tokio::test]
async fn the_starved_listener_answers_again() {
    let Some(socket) = std::env::var_os(SOCKET).map(PathBuf::from) else {
        return;
    };
    let fake = start(&socket);
    let limit = Limit::lower(CEILING);

    // One descriptor is handed back: enough for a client to connect, none for a listener to accept.
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(
        held.len() > 1,
        "the ceiling of {CEILING} leaves nothing to hand back"
    );
    let _ = held.pop();

    let mut client = UnixStream::connect(&socket).await.expect("connect");
    client
        .write_all(&serde_json::to_vec(&Request::SpaceList).expect("request"))
        .await
        .expect("write");
    client.shutdown().await.expect("shutdown");

    let mut answer = Vec::new();
    let starved = tokio::time::timeout(STARVED, client.read_to_end(&mut answer)).await;
    assert!(
        starved.is_err(),
        "a listener with no descriptor left answered {answer:?}"
    );
    assert!(fake.0.lock().expect("the fake").is_empty());

    limit.restore();
    tokio::time::timeout(RECOVERY, client.read_to_end(&mut answer))
        .await
        .expect("the listener stopped instead of retrying its accept")
        .expect("read the answer");

    assert_eq!(
        serde_json::from_slice::<Response>(&answer).expect("an answer"),
        Response::Names { names: Vec::new() }
    );
}

/// The process's descriptor limit, its soft half lowered for the test and raised back.
struct Limit {
    soft: libc::rlim_t,
    hard: libc::rlim_t,
}

impl Limit {
    /// Reads this process's limit and lowers its soft half to at most `ceiling`.
    fn lower(ceiling: libc::rlim_t) -> Self {
        let mut found = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit(2) writes the two fields behind a valid pointer.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut found) };
        assert_eq!(rc, 0, "getrlimit");
        let limit = Limit {
            soft: found.rlim_cur,
            hard: found.rlim_max,
        };
        limit.set(ceiling.min(limit.soft));
        limit
    }

    /// Puts the soft half back.
    fn restore(&self) {
        self.set(self.soft);
    }

    fn set(&self, soft: libc::rlim_t) {
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: self.hard,
        };
        // SAFETY: setrlimit(2) only reads the struct. The hard limit goes back as it was, so
        // neither lowering nor restoring the soft half needs a privilege.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        assert_eq!(rc, 0, "setrlimit");
    }
}
