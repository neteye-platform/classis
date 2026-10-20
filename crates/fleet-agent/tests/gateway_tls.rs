//! The downstream hop's TLS (ADR-0015, ADR-0021): a Gateway serves the downstream endpoint over
//! mutual TLS 1.3 only, and *requires* a downstream Agent to present a certificate that chains to
//! `client_ca_file`. Without the full `[gateway.tls]` section it does not start. That handshake is
//! the admission: nothing a downstream peer presents beyond it travels upstream.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_agent::config::ClientConfig;
use fleet_agent::shutdown::shutdown_channel;
use fleet_server::fleet::AppState;
use opamp::proto::{AgentCapabilities, AgentToServer, ServerToAgent};
use opamp::uid::InstanceUid;
use prost::Message as _;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

/// A throwaway PKI: one CA that both signs the Gateway's server certificate and mints the client
/// certificates a downstream Agent presents.
struct Pki {
    ca_pem: String,
    ca_key_pem: String,
}

impl Pki {
    fn new() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec!["opamp-fleet-gateway-test-ca".to_string()])
            .expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        Pki {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    fn issuer(&self) -> Issuer<'static, KeyPair> {
        let key = KeyPair::from_pem(&self.ca_key_pem).expect("ca key");
        Issuer::from_ca_cert_pem(&self.ca_pem, key).expect("issuer")
    }

    /// A certificate and key signed by this CA for `name` — an IP like `127.0.0.1` becomes an IP
    /// SAN, which is what lets a client verify the Gateway it dialled by address.
    fn issue(&self, name: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec![name.to_string()]).expect("params");
        let cert = params.signed_by(&key, &self.issuer()).expect("signed");
        (cert.pem(), key.serialize_pem())
    }
}

/// What the Server was sent, seen in front of it: every `Authorization` header and every WebSocket
/// upgrade, which is one upstream connection each.
#[derive(Default)]
struct Seen {
    authorization: Mutex<Vec<String>>,
    upgrades: AtomicUsize,
}

/// The real Server on an ephemeral plaintext port — the upstream a Gateway folds onto.
async fn spawn_server() -> (SocketAddr, Arc<AppState>, tempfile::TempDir) {
    let (addr, state, _seen, dir) = spawn_watched_server().await;
    (addr, state, dir)
}

/// [`spawn_server`], with what reaches it recorded.
async fn spawn_watched_server() -> (SocketAddr, Arc<AppState>, Arc<Seen>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("state"));
    let seen = Arc::new(Seen::default());
    let recorder = seen.clone();
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open())
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let seen = recorder.clone();
                async move {
                    let headers = request.headers();
                    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
                        seen.authorization
                            .lock()
                            .expect("seen lock")
                            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
                    }
                    if headers.contains_key(axum::http::header::UPGRADE) {
                        seen.upgrades.fetch_add(1, Ordering::SeqCst);
                    }
                    next.run(request).await
                }
            },
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, state, seen, dir)
}

/// The Gateway's TOML, `[gateway.tls]` naming the files in `dir`; `client_ca` adds
/// `client_ca_file`.
fn gateway_toml(
    server: SocketAddr,
    listen: SocketAddr,
    pki: &Pki,
    dir: &std::path::Path,
    client_ca: bool,
    upstream_connections: usize,
) -> String {
    let (cert, key) = pki.issue("127.0.0.1");
    let cert_file = dir.join("gateway-cert.pem");
    let key_file = dir.join("gateway-key.pem");
    let ca_file = dir.join("ca.pem");
    std::fs::write(&cert_file, &cert).expect("write cert");
    std::fs::write(&key_file, &key).expect("write key");
    std::fs::write(&ca_file, &pki.ca_pem).expect("write ca");
    let client_ca_line = if client_ca {
        format!("client_ca_file = {:?}", ca_file.display().to_string())
    } else {
        String::new()
    };
    format!(
        r#"
        endpoint = "ws://{server}/v1/opamp"
        [gateway]
        listen = "{listen}"
        upstream_connections = {upstream_connections}
        [gateway.tls]
        cert_file = {:?}
        key_file = {:?}
        {client_ca_line}
        "#,
        cert_file.display().to_string(),
        key_file.display().to_string(),
    )
}

/// A Gateway whose downstream endpoint serves mutual TLS with `pki`'s CA as `client_ca_file`.
async fn spawn_tls_gateway(
    server: SocketAddr,
    pki: &Pki,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tempfile::TempDir,
) {
    spawn_bounded_gateway(server, pki, opamp::server::listen::HEADER_READ_TIMEOUT, 4).await
}

/// [`spawn_tls_gateway`], with the header bound tightened to `header_read_timeout`.
async fn spawn_bounded_gateway(
    server: SocketAddr,
    pki: &Pki,
    header_read_timeout: Duration,
    upstream_connections: usize,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tempfile::TempDir,
) {
    // What the binary does first (`main.rs`): the Gateway fetches its revocation list as soon as it
    // starts, and reqwest refuses to build that client before a provider is installed — which,
    // left to the test's own `client()`, happened only when another test had got there first.
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    // Bound here and handed over, so no parallel test can take the port before the Gateway uses it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let listen = listener.local_addr().expect("addr");
    let toml = gateway_toml(server, listen, pki, dir.path(), true, upstream_connections);
    let config: ClientConfig = toml::from_str(&toml).expect("gateway config");
    let (tx, shutdown) = shutdown_channel();
    tokio::spawn(async move {
        fleet_agent::gateway::run_on_bounded(
            Arc::new(config),
            listener,
            shutdown,
            header_read_timeout,
        )
        .await
        .expect("gateway");
    });
    // Wait for the listener to accept before anyone dials it.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(listen).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (listen, tx, dir)
}

fn report(uid: &InstanceUid) -> AgentToServer {
    AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num: 1,
        capabilities: AgentCapabilities::ReportsStatus as u64,
        ..Default::default()
    }
}

/// A reqwest client that trusts `pki`'s CA and, given an identity, presents it as a client
/// certificate.
fn client(pki: &Pki, identity: Option<(String, String)>) -> reqwest::Client {
    opamp::tls::install_ring_provider();
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).expect("ca")]);
    if let Some((cert, key)) = identity {
        let mut pem = key.into_bytes();
        pem.extend_from_slice(cert.as_bytes());
        builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("identity"));
    }
    builder.build().expect("client")
}

/// With a client CA configured, a downstream Agent that presents a certificate reaches the Server
/// through the Gateway over TLS — and its reply comes back addressed to it. This is the hop working
/// end to end, encrypted, with the CA accepting a valid peer.
/// Verifies: ADR-0015, ADR-0021, G-15, G-17
#[tokio::test]
async fn a_downstream_agent_with_a_certificate_reaches_the_server_over_tls() {
    let (server, state, _server_dir) = spawn_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;

    let (cert, key) = pki.issue("edge-01");
    let uid = InstanceUid::default();
    let response = client(&pki, Some((cert, key)))
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report(&uid).encode_to_vec())
        .send()
        .await
        .expect("the TLS request reaches the gateway");
    assert!(response.status().is_success(), "{:?}", response.status());
    let reply =
        ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode the reply");
    assert_eq!(
        InstanceUid::from_wire(&reply.instance_uid),
        Some(uid),
        "the reply came back addressed to the Agent that asked"
    );
    assert_eq!(
        state.snapshot().len(),
        1,
        "the Server saw the Agent behind the Gateway"
    );
}

/// Two downstream peers, each with a certificate of its own, ride one upstream connection: with a
/// cap of one, both Agents reach the Server over the single connection the Gateway opened. The pool
/// is not divided by downstream peer, because nothing sent upstream depends on which peer an Agent
/// came through.
/// Verifies: ADR-0015, G-15
#[tokio::test]
async fn downstream_peers_with_different_certificates_share_one_upstream_connection() {
    let (server, state, seen, _server_dir) = spawn_watched_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) =
        spawn_bounded_gateway(server, &pki, opamp::server::listen::HEADER_READ_TIMEOUT, 1).await;

    let mut uids = Vec::new();
    for name in ["edge-01", "edge-02"] {
        let uid = InstanceUid::default();
        let response = client(&pki, Some(pki.issue(name)))
            .post(format!("https://{gateway}/v1/opamp"))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(report(&uid).encode_to_vec())
            .send()
            .await
            .expect("the TLS request reaches the gateway");
        assert!(
            response.status().is_success(),
            "{name}: {:?}",
            response.status()
        );
        uids.push(uid.to_string());
    }

    let agents: Vec<String> = state
        .snapshot()
        .iter()
        .map(|agent| agent.instance_uid.clone())
        .collect();
    assert_eq!(
        agents.len(),
        2,
        "both Agents reached the Server: {agents:?}"
    );
    for uid in &uids {
        assert!(agents.contains(uid), "{uid} is missing from {agents:?}");
    }
    assert_eq!(
        seen.upgrades.load(Ordering::SeqCst),
        1,
        "both peers rode the one upstream connection"
    );
}

/// A downstream peer that sends an `Authorization` header is admitted by its certificate as any
/// other, and the Server receives no `Authorization` from the Gateway: not that one, and none in
/// its place.
/// Verifies: ADR-0015, ADR-0021
#[tokio::test]
async fn a_downstream_authorization_header_is_ignored_and_not_forwarded() {
    let (server, state, seen, _server_dir) = spawn_watched_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;

    let uid = InstanceUid::default();
    let response = client(&pki, Some(pki.issue("edge-01")))
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::AUTHORIZATION, "Bearer left-over")
        .body(report(&uid).encode_to_vec())
        .send()
        .await
        .expect("the TLS request reaches the gateway");
    assert!(
        response.status().is_success(),
        "the header is ignored, never refused: {:?}",
        response.status()
    );
    assert_eq!(
        state.snapshot().len(),
        1,
        "the Agent behind the Gateway reached the Server"
    );
    assert!(
        seen.upgrades.load(Ordering::SeqCst) >= 1,
        "the pool connected"
    );
    let authorization = seen.authorization.lock().expect("seen lock").clone();
    assert!(
        authorization.is_empty(),
        "the Server was sent {authorization:?}"
    );
}

/// The same on the other transport: a downstream WebSocket peer whose upgrade carries an
/// `Authorization` header is admitted by its certificate and answered, and the Server receives no
/// `Authorization` from the Gateway.
/// Verifies: ADR-0015, ADR-0021
#[tokio::test]
async fn a_downstream_websocket_authorization_header_is_ignored_and_not_forwarded() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest as _, Message as WsMessage};

    let (server, state, seen, _server_dir) = spawn_watched_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;

    opamp::tls::install_ring_provider();
    let (cert, key) = pki.issue("edge-01");
    let config = opamp::tls::client_builder()
        .with_root_certificates(opamp::tls::root_store(pki.ca_pem.as_bytes()).expect("roots"))
        .with_client_auth_cert(
            opamp::tls::certificates(cert.as_bytes()).expect("cert"),
            opamp::tls::private_key(key.as_bytes()).expect("key"),
        )
        .expect("client config");
    let mut request = format!("wss://{gateway}/v1/opamp")
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        reqwest::header::AUTHORIZATION,
        "Bearer left-over".parse().expect("header value"),
    );
    let (mut socket, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))),
    )
    .await
    .expect("the header is ignored, never refused");

    let uid = InstanceUid::default();
    let frame = opamp::frame::encode_within(&report(&uid), 64 << 20).expect("encode");
    socket
        .send(WsMessage::Binary(frame.into()))
        .await
        .expect("send");
    let reply = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("a reply in time")
        .expect("a message")
        .expect("no error");
    let WsMessage::Binary(payload) = reply else {
        panic!("expected a binary reply")
    };
    let reply = opamp::frame::decode::<ServerToAgent>(&payload, 64 << 20).expect("decode");
    assert_eq!(
        InstanceUid::from_wire(&reply.instance_uid),
        Some(uid),
        "the reply came back addressed to the Agent that asked"
    );
    assert_eq!(
        state.snapshot().len(),
        1,
        "the Agent behind the Gateway reached the Server"
    );
    assert!(
        seen.upgrades.load(Ordering::SeqCst) >= 1,
        "the pool connected"
    );
    let authorization = seen.authorization.lock().expect("seen lock").clone();
    assert!(
        authorization.is_empty(),
        "the Server was sent {authorization:?}"
    );
}

/// A peer presenting *no* certificate is turned away at the handshake.
///
/// Verifies: ADR-0015, ADR-0021
#[tokio::test]
async fn a_downstream_peer_without_a_certificate_is_refused() {
    let (server, _state, _server_dir) = spawn_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;

    let result = client(&pki, None)
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "a peer with no client certificate must not be admitted, got {result:?}"
    );
}

/// A Gateway serving TLS does not also answer plaintext on the same port: a cleartext HTTP request
/// fails rather than exposing the hop the section was configured to protect.
/// Verifies: ADR-0015
#[tokio::test]
async fn the_tls_endpoint_does_not_answer_plaintext() {
    opamp::tls::install_ring_provider();
    let (server, _state, _server_dir) = spawn_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;

    let result = reqwest::Client::new()
        .post(format!("http://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "a plaintext request to a TLS endpoint must fail, got {result:?}"
    );
}

/// A peer presenting a certificate from *another* CA is turned away at the handshake: only the
/// configured `client_ca_file` admits.
///
/// Verifies: ADR-0015
#[tokio::test]
async fn a_downstream_peer_with_a_certificate_from_another_ca_is_refused() {
    let (server, state, _server_dir) = spawn_server().await;
    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;

    let stranger = Pki::new().issue("edge-01");
    let result = client(&pki, Some(stranger))
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "a peer with a certificate from another CA must not be admitted, got {result:?}"
    );
    assert!(state.snapshot().is_empty(), "nothing reached the Server");
}

/// A Gateway whose `[gateway.tls]` lacks `client_ca_file` does not start: the load refuses the
/// file, and `run_on` refuses the configuration rather than serving without client certificates.
///
/// Verifies: ADR-0015
#[tokio::test]
async fn a_gateway_without_a_client_ca_does_not_start() {
    let (server, _state, _server_dir) = spawn_server().await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let listen = listener.local_addr().expect("addr");
    let toml = gateway_toml(server, listen, &pki, dir.path(), false, 4);

    let path = dir.path().join("supervisor.toml");
    std::fs::write(&path, &toml).expect("write config");
    let err =
        ClientConfig::load(&path).expect_err("the load refuses a Gateway without a client CA");
    assert!(err.contains("client_ca_file"), "{err}");

    let config: ClientConfig = toml::from_str(&toml).expect("gateway config");
    let (_stop, shutdown) = shutdown_channel();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        fleet_agent::gateway::run_on(Arc::new(config), listener, shutdown),
    )
    .await
    .expect("run_on returns rather than serving");
    let err = result.expect_err("a Gateway without a client CA must not serve");
    assert!(err.contains("client_ca_file"), "{err}");
}

/// A Gateway without `[gateway.tls]` does not start, on the loopback too: `run_on` refuses the
/// configuration rather than serving the downstream endpoint in plaintext.
///
/// Verifies: ADR-0015
#[tokio::test]
async fn a_gateway_without_tls_on_loopback_does_not_start() {
    let (server, _state, _server_dir) = spawn_server().await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let listen = listener.local_addr().expect("addr");
    let toml = format!(
        "endpoint = \"ws://{server}/v1/opamp\"\n[gateway]\nlisten = \"{listen}\"\n\
         upstream_connections = 4\n"
    );
    let config: ClientConfig = toml::from_str(&toml).expect("gateway config");
    let (_stop, shutdown) = shutdown_channel();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        fleet_agent::gateway::run_on(Arc::new(config), listener, shutdown),
    )
    .await
    .expect("run_on returns rather than serving");
    let err = result.expect_err("a Gateway without TLS must not serve");
    assert!(err.contains("[gateway.tls] is required"), "{err}");
}

/// The connection-setup bound on the Gateway's own surface (H18): a downstream peer that completes
/// the mutual-TLS handshake and then never finishes its request headers is hung up on, as the
/// Server's Agent plane does (`connection_setup.rs`). The handshake bound is 10 seconds; closing well
/// inside it shows the header bound did the work.
/// Verifies: ADR-0010, ADR-0015
#[tokio::test]
async fn a_downstream_connection_that_never_finishes_its_headers_is_hung_up_on() {
    use std::io::{Read as _, Write as _};
    let (server, _state, _server_dir) = spawn_server().await;
    let pki = Pki::new();
    let (listen, _shutdown, _dir) =
        spawn_bounded_gateway(server, &pki, Duration::from_secs(1), 4).await;
    let (cert, key) = pki.issue("edge-01");
    let ca = pki.ca_pem.clone();
    let (read, elapsed) = tokio::task::spawn_blocking(move || {
        opamp::tls::install_ring_provider();
        let config = opamp::tls::client_builder()
            .with_root_certificates(opamp::tls::root_store(ca.as_bytes()).expect("roots"))
            .with_client_auth_cert(
                opamp::tls::certificates(cert.as_bytes()).expect("cert"),
                opamp::tls::private_key(key.as_bytes()).expect("key"),
            )
            .expect("client auth");
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").expect("name");
        let connection = rustls::ClientConnection::new(Arc::new(config), name).expect("tls");
        let tcp = std::net::TcpStream::connect(listen).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(8)))
            .expect("read timeout");
        let mut tls = rustls::StreamOwned::new(connection, tcp);
        // The handshake runs on the first write; a request line and one header, never ended.
        tls.write_all(b"GET /v1/opamp HTTP/1.1\r\nHost: localhost\r\n")
            .expect("handshake and a partial request");
        tls.flush().expect("flush");
        let started = std::time::Instant::now();
        let mut buffer = Vec::new();
        (tls.read_to_end(&mut buffer), started.elapsed())
    })
    .await
    .expect("join");
    let timed_out = matches!(&read, Err(e) if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    assert!(
        !timed_out,
        "the Gateway left a connection open that never finished its headers"
    );
    assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
}

/// A Gateway serves on its download route only what it relayed an offer of: the Server behind it
/// serves the artifact, and the Gateway, which relayed no offer of it, answers `404`
/// (ADR-0026 clause 45).
/// Verifies: ADR-0026
#[tokio::test]
async fn the_gateway_serves_no_artifact_it_relayed_no_offer_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        fleet_server::packages::PackageStore::open(dir.path().join("packages")).expect("store");
    let id = fleet_server::packages::PackageId::new("otelcol", "1.0.0").expect("id");
    store.create(&id).expect("create");
    store
        .put_entry(
            &id,
            &fleet_server::packages::Platform::new("linux", "amd64").expect("platform"),
            b"the-binary".to_vec(),
        )
        .expect("entry");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("state")
            .with_packages(Some(
                fleet_server::fleet::PackageOffering::new(&dir.path().join("packages"), store)
                    .expect("deployments"),
            )),
    );
    let app = fleet_server::agent_app(state, fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let server = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let path = "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64";
    let direct = reqwest::Client::new()
        .get(format!("http://{server}{path}"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        direct.status(),
        reqwest::StatusCode::OK,
        "the Server serves it"
    );

    let pki = Pki::new();
    let (gateway, _stop, _dir) = spawn_tls_gateway(server, &pki).await;
    let response = client(&pki, Some(pki.issue("edge-01")))
        .get(format!("https://{gateway}{path}"))
        .send()
        .await
        .expect("the TLS request reaches the gateway");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_ne!(
        response.bytes().await.expect("body").as_ref(),
        b"the-binary"
    );
}
