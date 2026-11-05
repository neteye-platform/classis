//! What bounds a connection before it is a request (ADR-0013).
//!
//! Every other limit this Server enforces starts at a request. These tests drive the two rules that
//! apply earlier: a peer that never finishes its headers is hung up on, and a peer that finishes
//! them is left alone for as long as its exchange takes — a WebSocket session outliving the bound
//! is the regression this measure could plausibly cause.

use std::sync::Arc;
use std::time::Duration;

use fleet_server::fleet::AppState;
use fleet_server::transport::Admission;
use futures_util::{SinkExt, StreamExt};
use opamp::frame;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::listen::Handle;
use opamp::uid::InstanceUid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Short enough for a test to wait it out, and the reason `with_header_read_timeout` exists:
/// the Server's own bound is 30 seconds, which no suite should sit through.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// The Agent plane on an ephemeral port, with the header-read timeout tightened.
async fn spawn() -> (std::net::SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs")).expect("open the configuration store"),
    );
    let app = fleet_server::agent_app(state, Admission::open());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Agent plane");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(
        fleet_server::listen::plane(listener, None, 64, Handle::new())
            .with_header_read_timeout(HEADER_READ_TIMEOUT)
            .serve(app),
    );
    (addr, dir)
}

/// The measure itself: a connection that sends a request line and then falls silent is closed by
/// the Server. Without that measure it would be held open indefinitely — hyper's own default
/// timeout resolves to nothing while no timer is installed, and neither `axum::serve` nor
/// `axum_server` installs one.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_connection_that_never_finishes_its_headers_is_hung_up_on() {
    let (addr, _dir) = spawn().await;
    let mut socket = TcpStream::connect(addr).await.expect("connect");
    // A request line and one header, with no blank line to end them: valid so far, never complete.
    socket
        .write_all(b"GET /v1/opamp HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write a partial request");

    // Generous against a slow machine, and still far below the 30-second bound a Server applies —
    // so a failure here means "not bounded", not "bounded differently".
    let mut buffer = Vec::new();
    let closed =
        tokio::time::timeout(HEADER_READ_TIMEOUT * 8, socket.read_to_end(&mut buffer)).await;

    assert!(
        closed.is_ok(),
        "the Server left a connection open that never finished its headers"
    );
    closed.expect("within the bound").expect("read to EOF");
}

/// The other half, and the one worth guarding: the bound is on connection *setup*, so an
/// established WebSocket session may sit idle far longer than it and stay up. This is what a
/// request-level timeout would have broken.
/// Verifies: ADR-0013
#[tokio::test]
async fn an_established_session_outlives_the_header_bound() {
    let (addr, _dir) = spawn().await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
        .await
        .expect("connect");

    tokio::time::sleep(HEADER_READ_TIMEOUT * 3).await;

    let uid = InstanceUid::default();
    let report = AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num: 1,
        ..Default::default()
    };
    socket
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            frame::encode_within(&report, frame::DEFAULT_MAX_MESSAGE_SIZE)
                .expect("within the limit")
                .into(),
        ))
        .await
        .expect("the session is still up");

    let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("a reply arrives")
        .expect("an open connection")
        .expect("a frame");
    let payload = match message {
        tokio_tungstenite::tungstenite::Message::Binary(bytes) => bytes,
        other => panic!("expected a binary frame, got {other:?}"),
    };
    let reply: ServerToAgent =
        frame::decode(&payload, frame::DEFAULT_MAX_MESSAGE_SIZE).expect("decode the reply");
    assert_eq!(reply.instance_uid, uid.as_bytes());
}
