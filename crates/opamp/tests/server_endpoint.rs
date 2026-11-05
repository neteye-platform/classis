//! The endpoint's contract, against a handler that does the least it can: it echoes each report's
//! `instance_uid`, refuses what it is told to, and pushes whatever its outbound channel carries.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use opamp::frame;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::{
    Handler, Outbound, Rejection, Reply, RequestInfo, Settings, Transport, Transports, Unreadable,
};
use prost::Message as _;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;

const LIMIT: usize = 4096;

struct Pushes(mpsc::Receiver<ServerToAgent>);

impl Outbound for Pushes {
    type Item = ServerToAgent;

    async fn next(&mut self) -> Option<ServerToAgent> {
        self.0.recv().await
    }
}

#[derive(Default)]
struct Echo {
    /// Hands each WebSocket connection's push sender to the test.
    pushers: Mutex<Vec<mpsc::Sender<ServerToAgent>>>,
    closed: Mutex<Vec<Transport>>,
}

struct Conn {
    transport: Transport,
}

impl Handler for Echo {
    type Connection = Conn;
    type Outbound = Pushes;

    fn on_connecting(
        &self,
        request: &RequestInfo<'_>,
    ) -> Result<(Conn, Option<Pushes>), Rejection> {
        if request.headers.contains_key("x-refuse") {
            return Err(Rejection {
                status: StatusCode::UNAUTHORIZED,
                headers: vec![(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static("Bearer"),
                )],
                message: "refused".to_string(),
            });
        }
        let outbound = (request.transport == Transport::WebSocket).then(|| {
            let (tx, rx) = mpsc::channel(4);
            self.pushers.lock().unwrap().push(tx);
            Pushes(rx)
        });
        Ok((
            Conn {
                transport: request.transport,
            },
            outbound,
        ))
    }

    async fn on_message(&self, _: &mut Conn, message: AgentToServer) -> Reply {
        if message.sequence_num == 99 {
            return Reply::Refuse(StatusCode::BAD_GATEWAY, "no upstream".to_string());
        }
        if message.sequence_num == 7 {
            return Reply::Nothing;
        }
        Reply::Send(ServerToAgent {
            instance_uid: message.instance_uid,
            ..Default::default()
        })
    }

    fn on_outbound(&self, _: &mut Conn, item: ServerToAgent) -> Vec<ServerToAgent> {
        vec![item]
    }

    fn on_unreadable(&self, _: &mut Conn, _: &Unreadable) -> Reply {
        Reply::Send(ServerToAgent {
            instance_uid: b"unreadable".to_vec(),
            ..Default::default()
        })
    }

    fn on_closed(&self, connection: Conn) {
        self.closed.lock().unwrap().push(connection.transport);
    }
}

async fn serve(settings: Settings) -> (SocketAddr, Arc<Echo>) {
    let handler = Arc::new(Echo::default());
    let app = opamp::server::router(handler.clone(), settings);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    (addr, handler)
}

fn report(uid: &[u8], sequence_num: u64) -> AgentToServer {
    AgentToServer {
        instance_uid: uid.to_vec(),
        sequence_num,
        ..Default::default()
    }
}

/// The workspace builds reqwest without a TLS provider of its own (ADR-0013); install the one every
/// binary installs, once, even though these exchanges are plaintext.
fn client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::new()
}

async fn post(addr: SocketAddr, path: &str, body: Vec<u8>) -> reqwest::Response {
    client()
        .post(format!("http://{addr}{path}"))
        .header("Content-Type", "application/x-protobuf")
        .body(body)
        .send()
        .await
        .expect("post")
}

async fn next_reply<S>(socket: &mut S) -> Message
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("a message in time")
        .expect("an open socket")
        .expect("a message")
}

fn decoded(message: Message) -> ServerToAgent {
    let Message::Binary(data) = message else {
        panic!("expected a binary frame, got {message:?}");
    };
    frame::decode(&data, LIMIT).expect("a framed ServerToAgent")
}

// Verifies: ADR-0010
#[tokio::test]
async fn a_plain_http_exchange_is_answered_by_the_handler() {
    let (addr, handler) = serve(Settings::new(LIMIT)).await;
    let response = post(addr, "/v1/opamp", report(b"agent-a", 1).encode_to_vec()).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/x-protobuf");
    let reply = ServerToAgent::decode(response.bytes().await.expect("body")).expect("protobuf");
    assert_eq!(reply.instance_uid, b"agent-a");
    assert_eq!(*handler.closed.lock().unwrap(), [Transport::Http]);
}

// Verifies: ADR-0010
#[tokio::test]
async fn plain_http_refusals_and_empty_replies_keep_their_shape() {
    let (addr, _) = serve(Settings::new(LIMIT)).await;
    let refused = post(addr, "/v1/opamp", report(b"a", 99).encode_to_vec()).await;
    assert_eq!(refused.status(), 502);
    assert_eq!(refused.text().await.expect("text"), "no upstream");

    let nothing = post(addr, "/v1/opamp", report(b"a", 7).encode_to_vec()).await;
    assert_eq!(nothing.status(), 200, "an exchange always has a response");
    let reply = ServerToAgent::decode(nothing.bytes().await.expect("body")).expect("protobuf");
    assert_eq!(reply, ServerToAgent::default());

    let unreadable = post(addr, "/v1/opamp", vec![0xff, 0xff, 0xff]).await;
    let reply = ServerToAgent::decode(unreadable.bytes().await.expect("body")).expect("protobuf");
    assert_eq!(reply.instance_uid, b"unreadable");
}

// Verifies: ADR-0010
#[tokio::test]
async fn the_body_rules_are_the_specifications() {
    let (addr, _) = serve(Settings::new(LIMIT)).await;
    let wrong_type = client()
        .post(format!("http://{addr}/v1/opamp"))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("post");
    assert_eq!(wrong_type.status(), 415);

    let too_big = post(addr, "/v1/opamp", vec![0u8; LIMIT + 1]).await;
    assert_eq!(too_big.status(), 413);

    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gzip, &report(b"zipped", 1).encode_to_vec()).expect("gzip");
    let zipped = client()
        .post(format!("http://{addr}/v1/opamp"))
        .header("Content-Type", "application/x-protobuf")
        .header("Content-Encoding", "gzip")
        .body(gzip.finish().expect("gzip"))
        .send()
        .await
        .expect("post");
    assert_eq!(zipped.status(), 200, "gzip is a MUST");
    let reply = ServerToAgent::decode(zipped.bytes().await.expect("body")).expect("protobuf");
    assert_eq!(reply.instance_uid, b"zipped");
}

// Verifies: ADR-0010
#[tokio::test]
async fn a_refused_connection_gets_the_handlers_status_and_headers() {
    let (addr, _) = serve(Settings::new(LIMIT)).await;
    let refused = client()
        .post(format!("http://{addr}/v1/opamp"))
        .header("Content-Type", "application/x-protobuf")
        .header("x-refuse", "1")
        .body(report(b"a", 1).encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(refused.status(), 401);
    assert_eq!(refused.headers()["www-authenticate"], "Bearer");
}

// Verifies: ADR-0010
#[tokio::test]
async fn a_websocket_carries_replies_and_pushes() {
    let (addr, handler) = serve(Settings::new(LIMIT)).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
        .await
        .expect("connect");
    socket
        .send(Message::Binary(
            frame::encode_within(&report(b"agent-b", 1), LIMIT)
                .expect("frame")
                .into(),
        ))
        .await
        .expect("send");
    assert_eq!(
        decoded(next_reply(&mut socket).await).instance_uid,
        b"agent-b"
    );

    // A refusal on a WebSocket sends nothing and keeps the connection; the next reply proves it.
    for sequence_num in [99, 7, 2] {
        socket
            .send(Message::Binary(
                frame::encode_within(&report(b"agent-b", sequence_num), LIMIT)
                    .expect("frame")
                    .into(),
            ))
            .await
            .expect("send");
    }
    assert_eq!(
        decoded(next_reply(&mut socket).await).instance_uid,
        b"agent-b"
    );

    // The outbound side reaches the peer without being asked.
    let pusher = handler.pushers.lock().unwrap()[0].clone();
    pusher
        .send(ServerToAgent {
            instance_uid: b"pushed".to_vec(),
            ..Default::default()
        })
        .await
        .expect("push");
    assert_eq!(
        decoded(next_reply(&mut socket).await).instance_uid,
        b"pushed"
    );

    // And when it ends, the connection does.
    drop(pusher);
    handler.pushers.lock().unwrap().clear();
    assert!(matches!(next_reply(&mut socket).await, Message::Close(_)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*handler.closed.lock().unwrap(), [Transport::WebSocket]);
}

// Verifies: ADR-0010
#[tokio::test]
async fn an_oversized_websocket_message_is_closed_with_1009() {
    let (addr, _) = serve(Settings::new(LIMIT)).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
        .await
        .expect("connect");
    socket
        .send(Message::Binary(vec![0u8; LIMIT * 2].into()))
        .await
        .expect("send");
    let Message::Close(Some(close)) = next_reply(&mut socket).await else {
        panic!("expected a close frame");
    };
    assert_eq!(close.code, CloseCode::Size);
}

// Verifies: ADR-0010
#[tokio::test]
async fn a_websocket_only_endpoint_on_any_path_serves_no_plain_http() {
    let (addr, _) = serve(Settings {
        max_message_size: LIMIT,
        transports: Transports::WebSocketOnly,
        any_path: true,
    })
    .await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/anything"))
        .await
        .expect("any path upgrades");
    socket
        .send(Message::Binary(
            frame::encode_within(&report(b"c", 1), LIMIT)
                .expect("frame")
                .into(),
        ))
        .await
        .expect("send");
    assert_eq!(decoded(next_reply(&mut socket).await).instance_uid, b"c");

    let post = post(addr, "/v1/opamp", report(b"c", 1).encode_to_vec()).await;
    assert_eq!(post.status(), 405, "no plain-HTTP transport here");
}
