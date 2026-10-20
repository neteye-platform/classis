//! The listener an OpAMP endpoint is served on (ADR-0010): the bound on connection setup, the
//! client-certificate rules, and what the handshake carries into a request.

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::routing::get;
use axum::{Extension, Router};
use opamp::server::listen::{ClientAuth, Handle, Listener, PeerCertificate, ServerTls};
use opamp::tls::Identity;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A throwaway CA that issues the server's and the clients' certificates.
struct Pki {
    ca_pem: String,
    ca_key_pem: String,
}

impl Pki {
    fn new() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec!["opamp-test-ca".to_string()]).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        Pki {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    fn issue(&self, name: &str) -> Identity {
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).expect("ca key");
        let issuer = Issuer::from_ca_cert_pem(&self.ca_pem, ca_key).expect("issuer");
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec![name.to_string()]).expect("params");
        let cert = params.signed_by(&key, &issuer).expect("signed");
        Identity {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        }
    }
}

/// Answers with what the listener put into the request.
fn router() -> Router {
    Router::new().route(
        "/",
        get(
            |Extension(peer): Extension<PeerCertificate>,
             ConnectInfo(addr): ConnectInfo<SocketAddr>| async move {
                format!("certificate={} peer={}", peer.present(), addr.ip())
            },
        ),
    )
}

fn spawn(listener: Listener) {
    tokio::spawn(async move { listener.serve(router()).await.expect("serve") });
}

fn bind() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

/// A TLS listener on an ephemeral port, with `client_auth`, and the port it is on.
fn spawn_tls(pki: &Pki, client_auth: ClientAuth) -> u16 {
    opamp::tls::install_ring_provider();
    let tls = ServerTls {
        identity: pki.issue("localhost"),
        client_auth,
    }
    .rustls_config()
    .expect("server config");
    let (listener, port) = bind();
    spawn(Listener::new(listener, Handle::new()).with_tls(tls));
    port
}

fn client(pki: &Pki, identity: Option<&Identity>) -> reqwest::Client {
    opamp::tls::install_ring_provider();
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).expect("ca")]);
    if let Some(identity) = identity {
        let mut pem = identity.key_pem.clone();
        pem.extend_from_slice(&identity.cert_pem);
        builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("identity"));
    }
    builder.build().expect("client")
}

async fn get_text(client: &reqwest::Client, port: u16) -> reqwest::Result<String> {
    client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

/// A peer that sends a request line and then falls silent is hung up on, rather than holding the
/// connection for as long as it likes.
/// Verifies: ADR-0010, ADR-0013
#[tokio::test]
async fn a_connection_that_never_finishes_its_headers_is_hung_up_on() {
    let bound = Duration::from_secs(1);
    let (listener, port) = bind();
    spawn(Listener::new(listener, Handle::new()).with_header_read_timeout(bound));

    let mut socket = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write a partial request");
    let mut buffer = Vec::new();
    let closed = tokio::time::timeout(bound * 8, socket.read_to_end(&mut buffer)).await;
    assert!(closed.is_ok(), "the listener left a silent connection open");
}

/// A plain listener puts the peer's address into the request, and no certificate.
#[tokio::test]
async fn a_plain_listener_carries_the_peer_and_no_certificate() {
    opamp::tls::install_ring_provider();
    let (listener, port) = bind();
    spawn(Listener::new(listener, Handle::new()));
    let text = reqwest::get(format!("http://127.0.0.1:{port}/"))
        .await
        .expect("get")
        .text()
        .await
        .expect("text");
    assert_eq!(text, "certificate=false peer=127.0.0.1");
}

/// With an optional client certificate the handshake succeeds either way, and the request says
/// whether a verified certificate came with it — so the application can require one per route.
/// Verifies: ADR-0010
#[tokio::test]
async fn an_optional_client_certificate_is_carried_into_the_request() {
    let pki = Pki::new();
    let port = spawn_tls(
        &pki,
        ClientAuth::Optional {
            ca_pem: pki.ca_pem.clone().into_bytes(),
        },
    );
    let with = get_text(&client(&pki, Some(&pki.issue("agent"))), port)
        .await
        .expect("with a certificate");
    assert_eq!(with, "certificate=true peer=127.0.0.1");
    let without = get_text(&client(&pki, None), port)
        .await
        .expect("without a certificate");
    assert_eq!(without, "certificate=false peer=127.0.0.1");
}

/// With a required client certificate, a peer without one never gets past the handshake, and one
/// from another CA neither.
/// Verifies: ADR-0010
#[tokio::test]
async fn a_required_client_certificate_refuses_the_handshake_without_one() {
    let pki = Pki::new();
    let port = spawn_tls(
        &pki,
        ClientAuth::Required {
            ca_pem: pki.ca_pem.clone().into_bytes(),
        },
    );
    assert!(get_text(&client(&pki, None), port).await.is_err());
    let stranger = Pki::new().issue("agent");
    assert!(get_text(&client(&pki, Some(&stranger)), port)
        .await
        .is_err());
    let with = get_text(&client(&pki, Some(&pki.issue("agent"))), port)
        .await
        .expect("with a certificate");
    assert_eq!(with, "certificate=true peer=127.0.0.1");
}

/// Material that cannot be used is refused before anything listens, naming the part.
#[test]
fn unusable_material_names_the_part() {
    let pki = Pki::new();
    let mut identity = pki.issue("localhost");
    identity.key_pem = b"no key here".to_vec();
    let error = ServerTls {
        identity,
        client_auth: ClientAuth::None,
    }
    .rustls_config()
    .expect_err("no key");
    assert!(error.starts_with("the TLS key:"), "{error}");
}

/// A client that offers TLS 1.2 alone never completes the handshake: the listener speaks TLS 1.3
/// and nothing older. The client is built from the full ring provider, which still has its TLS 1.2
/// suites, so the refusal is the listener's.
/// Verifies: ADR-0010, ADR-0013, ADR-0015, Q-3
#[tokio::test]
async fn a_client_offering_only_tls_1_2_is_refused() {
    let pki = Pki::new();
    let port = spawn_tls(&pki, ClientAuth::None);
    let mut roots = rustls::RootCertStore::empty();
    for cert in opamp::tls::certificates(pki.ca_pem.as_bytes()).expect("ca") {
        roots.add(cert).expect("anchor");
    }
    let old = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .expect("tls 1.2")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connected = tokio_tungstenite::connect_async_tls_with_config(
        format!("wss://localhost:{port}/"),
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
            old,
        ))),
    )
    .await;
    let error = connected
        .expect_err("a TLS 1.2 client was accepted")
        .to_string();
    assert!(
        error.contains("version") || error.contains("Version") || error.contains("alert"),
        "{error}"
    );
}

/// A listener at its cap closes the next connection on accept, keeps the ones it holds, and takes
/// a new one once a held one has gone.
/// Verifies: ADR-0013
#[tokio::test]
async fn connections_past_the_cap_are_refused_while_established_ones_keep_working() {
    opamp::tls::install_ring_provider();
    let (listener, port) = bind();
    spawn(Listener::new(listener, Handle::new()).with_max_connections(2));

    let first = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("first");
    let second = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("second");
    // Give the listener time to accept both before the third arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut third = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("third");
    let mut buffer = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), third.read_to_end(&mut buffer)).await;
    assert!(closed.is_ok(), "a connection past the cap was held open");

    // A held connection still answers.
    let mut held = first;
    held.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request");
    let mut answer = Vec::new();
    held.read_to_end(&mut answer).await.expect("answer");
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    drop(second);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Both slots are free again, so a new peer is served.
    let text = reqwest::get(format!("http://127.0.0.1:{port}/"))
        .await
        .expect("a freed slot serves")
        .text()
        .await
        .expect("text");
    assert_eq!(text, "certificate=false peer=127.0.0.1");
}

/// A listener without TLS on an address other than the loopback literals is refused before it
/// accepts anything: plaintext is for the loopback alone.
/// Verifies: ADR-0013, Q-1
#[tokio::test]
async fn a_plaintext_listener_off_the_loopback_is_refused() {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind");
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        Listener::new(listener, Handle::new()).serve(router()),
    )
    .await
    .expect("serve returns rather than listening")
    .expect_err("a plaintext listener off the loopback was served");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    assert!(error.to_string().contains("without TLS"), "{error}");
}

/// A short floor, so the tests below take milliseconds rather than minutes.
const WINDOW: Duration = Duration::from_millis(300);
const FLOOR: u64 = 1024;

/// A plain listener held to the short floor, answering `/echo` with the length of the body it read
/// and serving the OpAMP endpoint for the WebSocket cases.
fn spawn_paced() -> u16 {
    let (listener, port) = bind();
    let router = Router::new()
        .route(
            "/echo",
            axum::routing::post(|body: axum::body::Bytes| async move { body.len().to_string() }),
        )
        .merge(opamp::server::router(
            std::sync::Arc::new(Silent),
            opamp::server::Settings::new(1 << 20),
        ));
    let listener = Listener::new(listener, Handle::new()).with_pace(WINDOW, FLOOR);
    tokio::spawn(async move { listener.serve(router).await.expect("serve") });
    port
}

/// An OpAMP handler that answers nothing and pushes nothing.
struct Silent;

struct Never;

impl opamp::server::Outbound for Never {
    type Item = ();
    async fn next(&mut self) -> Option<()> {
        std::future::pending().await
    }
}

impl opamp::server::Handler for Silent {
    type Connection = ();
    type Outbound = Never;

    fn on_connecting(
        &self,
        _request: &opamp::server::RequestInfo<'_>,
    ) -> Result<((), Option<Never>), opamp::server::Rejection> {
        Ok(((), None))
    }

    async fn on_message(
        &self,
        _connection: &mut (),
        _message: opamp::proto::AgentToServer,
    ) -> opamp::server::Reply {
        opamp::server::Reply::Nothing
    }

    fn on_outbound(&self, _connection: &mut (), _item: ()) -> Vec<opamp::proto::ServerToAgent> {
        Vec::new()
    }
}

/// Sends the headers of a `POST /echo` announcing `length` bytes.
async fn post_headers(port: u16, length: usize) -> TcpStream {
    let mut socket = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket
        .write_all(
            format!("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("write the headers");
    socket
}

/// The status line of the response, within a few windows.
async fn status_of(socket: &mut TcpStream) -> String {
    let mut buffer = vec![0u8; 1024];
    let read = tokio::time::timeout(WINDOW * 10, socket.read(&mut buffer))
        .await
        .expect("an answer in time")
        .expect("read");
    String::from_utf8_lossy(&buffer[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// A body announced in the headers and never sent is answered `408`, not waited for.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_body_that_never_arrives_is_answered_408() {
    let port = spawn_paced();
    let mut socket = post_headers(port, 10_000).await;
    assert!(status_of(&mut socket).await.contains("408"));
}

/// A body that keeps arriving, but below the floor, is answered `408` the same way.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_body_that_trickles_is_answered_408() {
    let port = spawn_paced();
    let socket = post_headers(port, 10_000).await;
    let (mut reader, mut writer) = socket.into_split();
    tokio::spawn(async move {
        // Until the Server hangs up: a write failing is the trickle being cut off.
        while writer.write_all(b"x").await.is_ok() {
            tokio::time::sleep(WINDOW / 4).await;
        }
    });
    let mut buffer = vec![0u8; 1024];
    let read = tokio::time::timeout(WINDOW * 10, reader.read(&mut buffer))
        .await
        .expect("an answer in time")
        .expect("read");
    assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 408"));
}

/// A slow body that keeps above the floor is taken whole, however many windows it spans.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_slow_body_above_the_floor_is_taken_whole() {
    let port = spawn_paced();
    let chunk = vec![b'x'; 2 * FLOOR as usize];
    let mut socket = post_headers(port, chunk.len() * 6).await;
    for _ in 0..6 {
        socket.write_all(&chunk).await.expect("write");
        tokio::time::sleep(WINDOW / 3).await;
    }
    let mut buffer = vec![0u8; 1024];
    let read = tokio::time::timeout(WINDOW * 10, socket.read(&mut buffer))
        .await
        .expect("an answer in time")
        .expect("read");
    let answer = String::from_utf8_lossy(&buffer[..read]).to_string();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with(&(chunk.len() * 6).to_string()), "{answer}");
}

/// Upgrades a raw connection to a WebSocket on the OpAMP endpoint.
async fn websocket(port: u16) -> TcpStream {
    let mut socket = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket
        .write_all(
            b"GET /v1/opamp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .expect("upgrade");
    let mut buffer = vec![0u8; 1024];
    let read = socket.read(&mut buffer).await.expect("read");
    assert!(
        String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 101"),
        "no upgrade"
    );
    socket
}

/// The close code of the close frame the endpoint sends, if it sends one in time.
async fn close_code(socket: &mut TcpStream, within: Duration) -> Option<u16> {
    let mut frame = [0u8; 4];
    tokio::time::timeout(within, socket.read_exact(&mut frame))
        .await
        .ok()?
        .ok()?;
    (frame[0] == 0x88).then(|| u16::from_be_bytes([frame[2], frame[3]]))
}

/// A WebSocket message that has begun and trickles below the floor closes its connection with
/// `1008`.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_websocket_message_that_trickles_closes_with_1008() {
    let port = spawn_paced();
    let mut socket = websocket(port).await;
    // A masked binary frame announcing 5000 bytes, then its payload a byte at a time.
    socket
        .write_all(&[0x82, 0xFE, 0x13, 0x88, 1, 2, 3, 4])
        .await
        .expect("frame header");
    let (mut reader, mut writer) = socket.split();
    let trickle = async {
        for _ in 0..200 {
            if writer.write_all(b"x").await.is_err() {
                break;
            }
            tokio::time::sleep(WINDOW / 4).await;
        }
    };
    let closed = async {
        let mut frame = [0u8; 4];
        reader.read_exact(&mut frame).await.ok()?;
        (frame[0] == 0x88).then(|| u16::from_be_bytes([frame[2], frame[3]]))
    };
    let code = tokio::select! {
        () = trickle => None,
        code = closed => code,
    };
    assert_eq!(code, Some(1008));
}

/// A WebSocket with nothing in flight is left open, however many windows pass.
/// Verifies: ADR-0013
#[tokio::test]
async fn an_idle_websocket_stays_open() {
    let port = spawn_paced();
    let mut socket = websocket(port).await;
    assert_eq!(close_code(&mut socket, WINDOW * 6).await, None);
}

/// A masked Ping carrying the most a control frame may: 125 bytes.
fn full_ping() -> Vec<u8> {
    let mut ping = vec![0x89, 0x80 | 125, 1, 2, 3, 4];
    ping.extend(std::iter::repeat_n(5u8, 125));
    ping
}

/// A message whose fragments are interleaved with Pings, which RFC 6455 allows, is judged by its
/// data alone: the Pings are no progress on it, and it closes its connection with `1008`.
/// Verifies: ADR-0013, ADR-0010
#[tokio::test]
async fn a_message_kept_open_by_pings_between_its_fragments_closes_with_1008() {
    let port = spawn_paced();
    let socket = websocket(port).await;
    let (mut reader, mut writer) = socket.into_split();
    tokio::spawn(async move {
        // A first fragment of one byte, then a masked empty Ping and a one-byte continuation
        // fragment, over and over — never the final fragment.
        if writer
            .write_all(&[0x02, 0x81, 1, 2, 3, 4, 9])
            .await
            .is_err()
        {
            return;
        }
        // Nine full Pings a quarter window: several times the floor in control frames, which
        // must not count.
        let pings: Vec<u8> = std::iter::repeat_n(full_ping(), 9).flatten().collect();
        loop {
            let more = [0x00, 0x81, 1, 2, 3, 4, 9];
            if writer.write_all(&pings).await.is_err() || writer.write_all(&more).await.is_err() {
                return;
            }
            tokio::time::sleep(WINDOW / 4).await;
        }
    });
    let mut frame = [0u8; 4];
    let closed = tokio::time::timeout(WINDOW * 10, async {
        // Skip the Pongs the endpoint answers with, up to its close frame.
        loop {
            reader.read_exact(&mut frame[..2]).await.ok()?;
            let len = usize::from(frame[1] & 0x7F);
            if frame[0] == 0x88 {
                reader.read_exact(&mut frame[2..4]).await.ok()?;
                return Some(u16::from_be_bytes([frame[2], frame[3]]));
            }
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload).await.ok()?;
        }
    })
    .await
    .ok()
    .flatten();
    assert_eq!(closed, Some(1008));
}

/// A peer that only pings has no message in flight, and is left open.
/// Verifies: ADR-0010
#[tokio::test]
async fn a_websocket_that_only_pings_stays_open() {
    let port = spawn_paced();
    let socket = websocket(port).await;
    let (mut reader, mut writer) = socket.into_split();
    tokio::spawn(async move {
        while writer.write_all(&full_ping()).await.is_ok() {
            tokio::time::sleep(WINDOW / 4).await;
        }
    });
    let deadline = tokio::time::Instant::now() + WINDOW * 6;
    let mut frame = [0u8; 2];
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, reader.read_exact(&mut frame)).await {
            Err(_) => break,
            Ok(Err(e)) => panic!("the connection ended: {e}"),
            Ok(Ok(_)) => {
                assert_ne!(frame[0], 0x88, "a peer that only pings was closed");
                let mut payload = vec![0u8; usize::from(frame[1] & 0x7F)];
                reader.read_exact(&mut payload).await.expect("pong payload");
            }
        }
    }
}

/// An OpAMP handler whose every message never finishes: a session stuck in its handler.
struct Stuck(std::sync::Arc<std::sync::atomic::AtomicBool>);

/// Sets its flag when dropped — when the task holding it is cut.
struct CutFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for CutFlag {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl opamp::server::Handler for Stuck {
    type Connection = ();
    type Outbound = Never;

    fn on_connecting(
        &self,
        _request: &opamp::server::RequestInfo<'_>,
    ) -> Result<((), Option<Never>), opamp::server::Rejection> {
        Ok(((), None))
    }

    async fn on_message(
        &self,
        _connection: &mut (),
        _message: opamp::proto::AgentToServer,
    ) -> opamp::server::Reply {
        let _flag = CutFlag(self.0.clone());
        std::future::pending().await
    }

    fn on_outbound(&self, _connection: &mut (), _item: ()) -> Vec<opamp::proto::ServerToAgent> {
        Vec::new()
    }
}

/// A WebSocket session outlives the HTTP connection it was upgraded from, so the drain must reach
/// it separately: one stuck in its handler is cut at the drain's deadline, and `serve` returns only
/// once it is — whatever follows a listener's shutdown sees no session still at work.
///
/// Verifies: ADR-0013, ADR-0010
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drain_cuts_a_stuck_websocket_session_at_its_deadline() {
    use futures_util::SinkExt;

    let cut = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (listener, port) = bind();
    let router = opamp::server::router(
        std::sync::Arc::new(Stuck(cut.clone())),
        opamp::server::Settings::new(1 << 20),
    );
    let handle = Handle::new();
    let serving = tokio::spawn(Listener::new(listener, handle.clone()).serve(router));

    let (mut socket, _) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/v1/opamp"))
            .await
            .expect("connect");
    let report = opamp::frame::encode_within(
        &opamp::proto::AgentToServer {
            instance_uid: vec![7; 16],
            ..Default::default()
        },
        1 << 20,
    )
    .expect("encode");
    socket
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            report.into(),
        ))
        .await
        .expect("send");
    // The session is now inside its handler, and will never come out on its own.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!cut.load(std::sync::atomic::Ordering::SeqCst));

    let drain = Duration::from_millis(300);
    let started = std::time::Instant::now();
    handle.graceful_shutdown(Some(drain));
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve returns soon after the deadline")
        .expect("the serve task")
        .expect("serve");
    assert!(
        cut.load(std::sync::atomic::Ordering::SeqCst),
        "the stuck session outlived serve"
    );
    assert!(started.elapsed() >= drain, "cut before its deadline");
}
