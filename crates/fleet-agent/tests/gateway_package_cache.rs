//! A Gateway's package cache (ADR-0026 clauses 42 to 48): the Gateway fetches each uploaded artifact
//! it relays an offer of once, verifies it against the offered hash, and passes it on only to a
//! downstream host whose Agent it relayed that offer to. Most tests run against an upstream the test
//! controls, which counts and can hold back every fetch; the last one runs against the real Server
//! on mutual TLS, with the Gateway's host marked.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_agent::config::ClientConfig;
use fleet_agent::shutdown::shutdown_channel;
use opamp::proto::{
    AgentCapabilities, AgentToServer, DownloadableFile, PackageAvailable, PackagesAvailable,
    ServerToAgent,
};
use opamp::server::{Handler, Rejection, Reply, RequestInfo, Settings};
use opamp::uid::InstanceUid;
use prost::Message as _;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair, SanType};
use sha2::Digest as _;

/// The bound on every wait in these tests: a deadline that fails the test, never a pause that
/// orders it.
const DEADLINE: Duration = Duration::from_secs(20);

const PATH_1: &str = "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64";
const PATH_2: &str = "/api/v1/packages/otelcol/2.0.0/file?os=linux&arch=amd64";

fn sha256(bytes: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(bytes).to_vec()
}

/// One CA that signs the Gateway's listener certificate and every downstream peer's.
struct Pki {
    ca_pem: String,
    ca_key_pem: String,
}

impl Pki {
    fn new() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params =
            CertificateParams::new(vec!["gateway-cache-test-ca".to_string()]).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        Pki {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    /// A certificate and key for `name`, naming `host` with the Server's SAN URI when given.
    fn issue(&self, name: &str, host: Option<&str>) -> (String, String) {
        let issuer = Issuer::from_ca_cert_pem(
            &self.ca_pem,
            KeyPair::from_pem(&self.ca_key_pem).expect("ca key"),
        )
        .expect("issuer");
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        if let Some(host) = host {
            params.subject_alt_names.push(SanType::URI(
                format!("urn:opamp-fleet:host:{host}")
                    .try_into()
                    .expect("uri"),
            ));
        }
        let cert = params.signed_by(&key, &issuer).expect("signed");
        (cert.pem(), key.serialize_pem())
    }
}

/// A downstream peer's client, trusting `ca_pem` and presenting `(cert, key)`.
fn client(ca_pem: &str, (cert, key): (String, String)) -> reqwest::Client {
    opamp::tls::install_ring_provider();
    let mut pem = key.into_bytes();
    pem.extend_from_slice(cert.as_bytes());
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca")])
        .identity(reqwest::Identity::from_pem(&pem).expect("identity"))
        .build()
        .expect("client")
}

/// An offer of one file per entry, under the package name given.
fn offer(files: &[(&str, &str, Vec<u8>)]) -> PackagesAvailable {
    PackagesAvailable {
        packages: files
            .iter()
            .map(|(name, url, hash)| {
                (
                    (*name).to_string(),
                    PackageAvailable {
                        version: "1.0.0".to_string(),
                        file: Some(DownloadableFile {
                            download_url: (*url).to_string(),
                            content_hash: hash.clone(),
                            signature: vec![1; 64],
                            headers: None,
                        }),
                        ..Default::default()
                    },
                )
            })
            .collect(),
        all_packages_hash: vec![9; 32],
    }
}

/// The upstream the test controls: what it offers each Agent, what it serves on the download
/// route, and every fetch it saw.
#[derive(Default)]
struct Upstream {
    offers: Mutex<HashMap<Vec<u8>, PackagesAvailable>>,
    artifacts: Mutex<HashMap<String, Vec<u8>>>,
    /// The path and query of every request on the download route and the other path.
    fetched: Mutex<Vec<String>>,
    /// Bumped on every fetch, so a test can wait for one.
    fetches: Option<tokio::sync::watch::Sender<usize>>,
    /// Held fetches wait for a permit here, when set.
    gate: Option<Arc<tokio::sync::Semaphore>>,
    /// Answer the revocation list with `500`, so the Gateway holds none.
    no_revocation_list: bool,
    /// The certificates the list names, as issuer hash and serial.
    revoked: Vec<(String, String)>,
    /// Serve artifacts as a stream without `Content-Length`.
    chunked: bool,
    /// Answer no report; replies are pushed with [`Upstream::push`] instead.
    silent: bool,
    /// Bumped on every report, so a test can wait for one.
    messages: Option<tokio::sync::watch::Sender<usize>>,
    pushes: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ServerToAgent>>>,
}

impl Upstream {
    fn offer(&self, uid: &InstanceUid, offer: PackagesAvailable) {
        self.offers
            .lock()
            .expect("offers")
            .insert(uid.as_bytes().to_vec(), offer);
    }

    fn serve(&self, path: &str, bytes: &[u8]) {
        self.artifacts
            .lock()
            .expect("artifacts")
            .insert(path.to_string(), bytes.to_vec());
    }

    fn fetched(&self) -> Vec<String> {
        self.fetched.lock().expect("fetched").clone()
    }

    /// Sends `uid` its offer down the Gateway's upstream connection.
    fn push(&self, uid: &InstanceUid) {
        let offer = self
            .offers
            .lock()
            .expect("offers")
            .get(uid.as_bytes().as_slice())
            .cloned();
        self.pushes
            .lock()
            .expect("pushes")
            .as_ref()
            .expect("the Gateway connected")
            .send(ServerToAgent {
                instance_uid: uid.as_bytes().to_vec(),
                packages_available: offer,
                ..Default::default()
            })
            .expect("push");
    }
}

/// What the upstream sends a connection unasked.
struct Pushes(tokio::sync::mpsc::UnboundedReceiver<ServerToAgent>);

impl opamp::server::Outbound for Pushes {
    type Item = ServerToAgent;

    async fn next(&mut self) -> Option<ServerToAgent> {
        self.0.recv().await
    }
}

struct Answering(Arc<Upstream>);

impl Handler for Answering {
    type Connection = ();
    type Outbound = Pushes;

    fn on_connecting(&self, request: &RequestInfo<'_>) -> Result<((), Option<Pushes>), Rejection> {
        if request.transport != opamp::server::Transport::WebSocket {
            return Ok(((), None));
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        *self.0.pushes.lock().expect("pushes") = Some(tx);
        Ok(((), Some(Pushes(rx))))
    }

    async fn on_message(&self, _: &mut (), report: AgentToServer) -> Reply {
        if let Some(messages) = &self.0.messages {
            messages.send_modify(|count| *count += 1);
        }
        if self.0.silent {
            return Reply::Nothing;
        }
        let offer = self
            .0
            .offers
            .lock()
            .expect("offers")
            .get(&report.instance_uid)
            .cloned();
        Reply::Send(ServerToAgent {
            instance_uid: report.instance_uid,
            packages_available: offer,
            ..Default::default()
        })
    }

    fn on_outbound(&self, _: &mut (), item: ServerToAgent) -> Vec<ServerToAgent> {
        vec![item]
    }
}

async fn artifact(
    axum::extract::State(upstream): axum::extract::State<Arc<Upstream>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let path = request
        .uri()
        .path_and_query()
        .map_or(String::new(), |path| path.as_str().to_string());
    upstream.fetched.lock().expect("fetched").push(path.clone());
    if let Some(fetches) = &upstream.fetches {
        fetches.send_modify(|count| *count += 1);
    }
    if let Some(gate) = &upstream.gate {
        let _permit = gate.acquire().await.expect("gate");
    }
    let bytes = upstream
        .artifacts
        .lock()
        .expect("artifacts")
        .get(&path)
        .cloned();
    match bytes {
        Some(bytes) if upstream.chunked => {
            let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
                bytes.chunks(8).map(|chunk| Ok(chunk.to_vec())).collect();
            axum::body::Body::from_stream(futures_util::stream::iter(chunks)).into_response()
        }
        Some(bytes) => bytes.into_response(),
        None => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

async fn revocations(
    axum::extract::State(upstream): axum::extract::State<Arc<Upstream>>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if upstream.no_revocation_list {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let certificates: Vec<serde_json::Value> = upstream
        .revoked
        .iter()
        .map(|(issuer, serial)| serde_json::json!({ "issuer": issuer, "serial": serial }))
        .collect();
    axum::Json(serde_json::json!({ "certificates": certificates })).into_response()
}

/// Serves `upstream` on an ephemeral plaintext loopback port.
async fn spawn_upstream(upstream: Arc<Upstream>) -> SocketAddr {
    let routes = axum::Router::new()
        .route(
            "/api/v1/packages/{agent_type}/{version}/file",
            axum::routing::get(artifact),
        )
        .route("/mirror/{file}", axum::routing::get(artifact))
        .route("/v1/gateway/revocations", axum::routing::get(revocations))
        .with_state(upstream.clone());
    let app = opamp::server::router(
        Arc::new(Answering(upstream)),
        Settings::new(opamp::frame::DEFAULT_MAX_MESSAGE_SIZE),
    )
    .merge(routes);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    addr
}

/// A Gateway in front of `server`, its listener certificate and client CA from `pki`, its state in
/// `dir`.
async fn spawn_gateway(
    server: SocketAddr,
    pki: &Pki,
    dir: &Path,
    package_cache_bytes: u64,
) -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
    // What the binary does first (`main.rs`): the Gateway fetches its revocation list as soon as it
    // starts, before the test's own `client()` would install the provider.
    opamp::tls::install_ring_provider();
    let (cert, key) = pki.issue("127.0.0.1", None);
    let write = |file: &str, content: &str| {
        let path = dir.join(file);
        std::fs::write(&path, content).expect("write");
        path.display().to_string()
    };
    let cert_file = write("gateway.pem", &cert);
    let key_file = write("gateway-key.pem", &key);
    let ca_file = write("ca.pem", &pki.ca_pem);
    // Bound here and handed over: a connection made before the Gateway serves waits in the backlog.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let listen = listener.local_addr().expect("addr");
    let config: ClientConfig = toml::from_str(&format!(
        r#"
        endpoint = "ws://{server}/v1/opamp"
        state_dir = {state:?}
        [gateway]
        listen = "{listen}"
        package_cache_bytes = {package_cache_bytes}
        [gateway.tls]
        cert_file = {cert_file:?}
        key_file = {key_file:?}
        client_ca_file = {ca_file:?}
        "#,
        state = dir.join("state").display().to_string(),
    ))
    .expect("gateway config");
    let (stop, shutdown) = shutdown_channel();
    tokio::spawn(async move {
        fleet_agent::gateway::run_on(Arc::new(config), listener, shutdown)
            .await
            .expect("gateway");
    });
    (listen, stop)
}

/// One plain-HTTP report for `uid` through the Gateway, and the reply it hands back.
async fn report(client: &reqwest::Client, gateway: SocketAddr, uid: &InstanceUid) -> ServerToAgent {
    let response = client
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(
            AgentToServer {
                instance_uid: uid.as_bytes().to_vec(),
                sequence_num: 1,
                capabilities: AgentCapabilities::ReportsStatus as u64,
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode")
}

/// One request, answered as it is.
async fn get_now(client: &reqwest::Client, gateway: SocketAddr, path: &str) -> reqwest::Response {
    client
        .get(format!("https://{gateway}{path}"))
        .send()
        .await
        .expect("send")
}

/// A request asked again while the Gateway answers that it is fetching the artifact, as a Client
/// would after `Retry-After` — what it is answered once no fetch runs.
async fn get(client: &reqwest::Client, gateway: SocketAddr, path: &str) -> reqwest::Response {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let response = get_now(client, gateway, path).await;
            let fetching = response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .is_some()
                && response.content_length() == Some(FETCHING.len() as u64);
            if !fetching {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("no fetch runs any more")
}

/// The body of the Gateway's `503` while it fetches.
const FETCHING: &str = "the Gateway is fetching this artifact";

/// Status, headers and body, the `Date` header aside.
async fn answer(response: reqwest::Response) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(name, _)| *name != reqwest::header::DATE)
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    (
        status,
        headers,
        response.bytes().await.expect("body").to_vec(),
    )
}

/// The files held in the Gateway's cache directory.
fn held(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir.join("state").join("gateway-packages"))
        .map(|entries| {
            entries
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Two Agents of one host are offered the same artifact. The Gateway fetches it as soon as it
/// relays the first offer, before anyone asks; requests while that fetch runs are answered `503`
/// with `Retry-After: 30`, the second offer starts no fetch of its own, and the upstream serves
/// the artifact once.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_relayed_artifact_is_fetched_once_before_any_request_and_served_to_its_host() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (fetches, mut fetched) = tokio::sync::watch::channel(0usize);
    let upstream = Arc::new(Upstream {
        fetches: Some(fetches),
        gate: Some(gate.clone()),
        ..Upstream::default()
    });
    let bytes = b"the-binary-of-otelcol-1.0.0".to_vec();
    upstream.serve(PATH_1, &bytes);
    let (one, two) = (InstanceUid::default(), InstanceUid::default());
    for uid in [&one, &two] {
        upstream.offer(uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    }
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let first = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    let second = client(&pki.ca_pem, pki.issue("edge-02", Some("h1")));

    let reply = report(&first, gateway, &one).await;
    assert!(
        reply.packages_available.is_some(),
        "the offer was relayed unchanged"
    );
    tokio::time::timeout(DEADLINE, fetched.wait_for(|count| *count >= 1))
        .await
        .expect("the Gateway fetched before any request")
        .expect("watch");
    report(&second, gateway, &two).await;

    for client in [&first, &second] {
        let response = get_now(client, gateway, PATH_1).await;
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(reqwest::header::RETRY_AFTER),
            Some(&reqwest::header::HeaderValue::from_static("30"))
        );
    }
    gate.add_permits(16);
    for client in [&first, &second] {
        let response = get(client, gateway, PATH_1).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.bytes().await.expect("body").as_ref(),
            bytes.as_slice()
        );
    }
    assert_eq!(upstream.fetched(), vec![PATH_1.to_string()], "one fetch");
}

/// A peer of another host, and a peer whose certificate names no host, are answered exactly as a
/// request for an artifact nobody was offered: the Gateway does not say what it holds.
/// Verifies: ADR-0026, ADR-0015
#[tokio::test]
async fn another_host_and_a_certificate_naming_no_host_are_answered_as_for_an_artifact_not_held() {
    let upstream = Arc::new(Upstream::default());
    let bytes = b"the-binary".to_vec();
    upstream.serve(PATH_1, &bytes);
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let own = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    report(&own, gateway, &uid).await;
    let served = get(&own, gateway, PATH_1).await;
    assert_eq!(served.status(), reqwest::StatusCode::OK, "held");

    let not_offered = answer(get(&own, gateway, PATH_2).await).await;
    assert_eq!(not_offered.0, 404);
    let other = client(&pki.ca_pem, pki.issue("edge-02", Some("h2")));
    assert_eq!(
        answer(get(&other, gateway, PATH_1).await).await,
        not_offered
    );
    let nameless = client(&pki.ca_pem, pki.issue("edge-03", None));
    assert_eq!(
        answer(get(&nameless, gateway, PATH_1).await).await,
        not_offered
    );
    assert_eq!(upstream.fetched(), vec![PATH_1.to_string()]);
}

/// An Agent's offer is the last one relayed to it: a later offer of another version replaces it,
/// and the artifact it no longer names is not served, though the Gateway still holds it.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_later_offer_replaces_what_an_agent_was_offered() {
    let upstream = Arc::new(Upstream::default());
    let (old, new) = (b"version-one".to_vec(), b"version-two".to_vec());
    upstream.serve(PATH_1, &old);
    upstream.serve(PATH_2, &new);
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(&old))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    report(&peer, gateway, &uid).await;
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 200);

    upstream.offer(&uid, offer(&[("otelcol", PATH_2, sha256(&new))]));
    report(&peer, gateway, &uid).await;
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    let response = get(&peer, gateway, PATH_2).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        new.as_slice()
    );
}

/// The Gateway caches an artifact offered as the Server's path, and an offered file with an
/// absolute URL — which only a foreign Server would send, here a path the upstream also serves —
/// is neither fetched nor served (ADR-0033).
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn the_servers_path_is_cached_and_an_absolute_url_is_neither_fetched_nor_served() {
    let upstream = Arc::new(Upstream::default());
    let bytes = b"the-binary".to_vec();
    upstream.serve(PATH_1, &bytes);
    let server = spawn_upstream(upstream.clone()).await;
    let absolute = format!("http://{server}/mirror/otelcol.tar.gz");
    upstream.serve("/mirror/otelcol.tar.gz", b"absolute");
    let uid = InstanceUid::default();
    upstream.offer(
        &uid,
        offer(&[
            ("absolute", &absolute, sha256(b"absolute")),
            ("otelcol", PATH_1, sha256(&bytes)),
        ]),
    );
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    report(&peer, gateway, &uid).await;
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 200);
    assert_eq!(
        get(&peer, gateway, "/mirror/otelcol.tar.gz").await.status(),
        404
    );
    assert_eq!(
        upstream.fetched(),
        vec![PATH_1.to_string()],
        "the absolute URL was never asked"
    );
}

/// Bytes that do not match the offered hash are deleted, never held, and never served.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_artifact_that_fails_its_hash_is_neither_stored_nor_served() {
    let upstream = Arc::new(Upstream::default());
    upstream.serve(PATH_1, b"tampered");
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(b"the-binary"))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    report(&peer, gateway, &uid).await;
    let response = get(&peer, gateway, PATH_1).await;
    assert_eq!(response.status(), 404);
    assert_ne!(response.bytes().await.expect("body").as_ref(), b"tampered");
    assert_eq!(
        held(dir.path()),
        Vec::<String>::new(),
        "nothing held or staged"
    );
}

/// An artifact larger than `package_cache_bytes` is not stored and not streamed through: it is
/// answered `404`, and fetched once, not again on the next request.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_artifact_larger_than_the_cache_is_refused_and_not_fetched_again() {
    let upstream = Arc::new(Upstream::default());
    let bytes = vec![7u8; 64];
    upstream.serve(PATH_1, &bytes);
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 16).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    report(&peer, gateway, &uid).await;
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    assert_eq!(upstream.fetched(), vec![PATH_1.to_string()], "one attempt");
    assert_eq!(held(dir.path()), Vec::<String>::new());
}

/// The download route admits as `/v1/opamp` does: while the Gateway holds no revocation list it
/// answers `503`, on both.
/// Verifies: ADR-0026, ADR-0015
#[tokio::test]
async fn the_download_route_answers_503_while_the_gateway_holds_no_revocation_list() {
    let upstream = Arc::new(Upstream {
        no_revocation_list: true,
        ..Upstream::default()
    });
    let server = spawn_upstream(upstream).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    let response = get_now(&peer, gateway, PATH_1).await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        response.headers().get(reqwest::header::RETRY_AFTER),
        Some(&reqwest::header::HeaderValue::from_static("30"))
    );
    let opamp = peer
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(Vec::new())
        .send()
        .await
        .expect("send");
    assert_eq!(opamp.status(), 503);
}

/// Host B reports host A's `instance_uid` while A waits for the Server's reply. The `instance_uid`
/// is A's, bound by A's first report: B's report is answered `403` and never reaches the Server,
/// the reply goes to A, and B is answered for the artifact exactly as for one nobody was offered.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_host_reporting_another_hosts_instance_uid_before_the_reply_is_not_served() {
    let (messages, seen) = tokio::sync::watch::channel(0usize);
    let upstream = Arc::new(Upstream {
        silent: true,
        messages: Some(messages),
        ..Upstream::default()
    });
    let bytes = b"the-binary".to_vec();
    upstream.serve(PATH_1, &bytes);
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let a = client(&pki.ca_pem, pki.issue("edge-a", Some("host-a")));
    let b = client(&pki.ca_pem, pki.issue("edge-b", Some("host-b")));

    // A reports and waits for its reply; B reports the same `instance_uid` before the reply.
    let first = {
        let a = a.clone();
        tokio::spawn(async move { report(&a, gateway, &uid).await })
    };
    tokio::time::timeout(DEADLINE, seen.clone().wait_for(|count| *count >= 1))
        .await
        .expect("A's report reached the upstream")
        .expect("watch");
    let stolen = b
        .post(format!("https://{gateway}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(
            AgentToServer {
                instance_uid: uid.as_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(stolen.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(*seen.borrow(), 1, "B's report reached the upstream");

    upstream.push(&uid);
    let reply = tokio::time::timeout(DEADLINE, first)
        .await
        .expect("A got the reply")
        .expect("join");
    assert!(reply.packages_available.is_some(), "relayed to A unchanged");
    let not_held = answer(get(&b, gateway, PATH_2).await).await;
    assert_eq!(not_held.0, 404);
    assert_eq!(answer(get(&b, gateway, PATH_1).await).await, not_held);
    let response = get(&a, gateway, PATH_1).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        bytes.as_slice()
    );
}

/// A fetch that fails is not repeated by the requests that follow, nor by offers of the same
/// artifact relayed again to the same Agent: each request is answered `404` and the upstream sees
/// the one fetch. When the artifact newly appears in an Agent's offer it is fetched again.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_failed_fetch_is_not_repeated_by_requests_or_re_offers_and_is_retried_when_newly_offered()
{
    let (fetches, mut fetched) = tokio::sync::watch::channel(0usize);
    let upstream = Arc::new(Upstream {
        fetches: Some(fetches),
        ..Upstream::default()
    });
    let bytes = b"the-binary".to_vec();
    let (uid, other) = (InstanceUid::default(), InstanceUid::default());
    for uid in [&uid, &other] {
        upstream.offer(uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    }
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));

    report(&peer, gateway, &uid).await;
    tokio::time::timeout(DEADLINE, fetched.wait_for(|count| *count >= 1))
        .await
        .expect("the offer fetched")
        .expect("watch");
    for _ in 0..3 {
        assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    }
    for _ in 0..3 {
        report(&peer, gateway, &uid).await;
        assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    }
    assert_eq!(
        upstream.fetched(),
        vec![PATH_1.to_string()],
        "one fetch, not one per request or re-offer"
    );

    upstream.serve(PATH_1, &bytes);
    report(&peer, gateway, &other).await;
    tokio::time::timeout(DEADLINE, fetched.wait_for(|count| *count >= 2))
        .await
        .expect("fetched again when newly offered")
        .expect("watch");
    let response = get(&peer, gateway, PATH_1).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        bytes.as_slice()
    );
    assert_eq!(upstream.fetched().len(), 2);
}

/// A downstream Client on a WebSocket receives its offer over the socket, and then the artifact
/// over the download route with the same certificate.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_websocket_downstream_receives_the_offer_and_the_artifact() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let upstream = Arc::new(Upstream::default());
    let bytes = b"the-binary-over-a-socket".to_vec();
    upstream.serve(PATH_1, &bytes);
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let (cert, key) = pki.issue("edge-01", Some("h1"));

    opamp::tls::install_ring_provider();
    let tls = opamp::tls::client_builder()
        .with_root_certificates(opamp::tls::root_store(pki.ca_pem.as_bytes()).expect("roots"))
        .with_client_auth_cert(
            opamp::tls::certificates(cert.as_bytes()).expect("cert"),
            opamp::tls::private_key(key.as_bytes()).expect("key"),
        )
        .expect("client config");
    let request = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("wss://{gateway}/v1/opamp"),
    )
    .expect("request");
    let (mut socket, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(tls))),
    )
    .await
    .expect("connect through the gateway");
    let report = AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num: 1,
        capabilities: AgentCapabilities::ReportsStatus as u64,
        ..Default::default()
    };
    socket
        .send(WsMessage::Binary(
            opamp::frame::encode_within(&report, opamp::frame::DEFAULT_MAX_MESSAGE_SIZE)
                .expect("frame")
                .into(),
        ))
        .await
        .expect("send");
    let reply = tokio::time::timeout(DEADLINE, async {
        loop {
            match socket.next().await.expect("open").expect("frame") {
                WsMessage::Binary(payload) => {
                    break opamp::frame::decode::<ServerToAgent>(
                        &payload,
                        opamp::frame::DEFAULT_MAX_MESSAGE_SIZE,
                    )
                    .expect("decode")
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("a reply");
    assert!(reply.packages_available.is_some());

    let response = get(&client(&pki.ca_pem, (cert, key)), gateway, PATH_1).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        bytes.as_slice()
    );
}

/// A body sent without `Content-Length` is cut where it passes the limit: nothing is held, the
/// request is answered `404`, and the artifact is not fetched again.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_body_without_content_length_is_cut_at_the_limit() {
    let upstream = Arc::new(Upstream {
        chunked: true,
        ..Upstream::default()
    });
    let bytes = vec![7u8; 64];
    upstream.serve(PATH_1, &bytes);
    let uid = InstanceUid::default();
    upstream.offer(&uid, offer(&[("otelcol", PATH_1, sha256(&bytes))]));
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 16).await;
    let peer = client(&pki.ca_pem, pki.issue("edge-01", Some("h1")));
    report(&peer, gateway, &uid).await;
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    assert_eq!(get(&peer, gateway, PATH_1).await.status(), 404);
    assert_eq!(upstream.fetched(), vec![PATH_1.to_string()]);
    assert_eq!(held(dir.path()), Vec::<String>::new());
}

/// A certificate the Server revoked is refused `401` on the download route, as on `/v1/opamp`.
/// Verifies: ADR-0026, ADR-0015
#[tokio::test]
async fn a_revoked_certificate_is_refused_on_the_download_route() {
    let pki = Pki::new();
    let (cert, key) = pki.issue("edge-01", Some("h1"));
    let der = opamp::tls::certificates(cert.as_bytes()).expect("pem");
    let (_, parsed) = x509_parser::parse_x509_certificate(der[0].as_ref()).expect("parse");
    let serial = hex::encode(parsed.raw_serial());
    let serial = serial.trim_start_matches('0').to_string();
    let issuer = hex::encode(sha2::Sha256::digest(parsed.issuer().as_raw()));
    let upstream = Arc::new(Upstream {
        revoked: vec![(issuer, serial)],
        ..Upstream::default()
    });
    let server = spawn_upstream(upstream).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let revoked = client(&pki.ca_pem, (cert, key));
    assert_eq!(get(&revoked, gateway, PATH_1).await.status(), 401);
    let other = client(&pki.ca_pem, pki.issue("edge-02", Some("h1")));
    assert_eq!(get(&other, gateway, PATH_1).await.status(), 404, "admitted");
}

/// The Client's waits on `Retry-After`, made short for a test.
const SHORT_WAITS: fleet_agent::packages::Patience = fleet_agent::packages::Patience {
    per_wait: Duration::from_millis(20),
    total: Duration::from_secs(20),
};

/// The upstream holds the artifact back until the Client's own download has been asked to wait:
/// the Gateway answers it `503` with `Retry-After` instead of keeping it waiting for headers, the
/// Client says so in its log and asks again as told, and once the fetch completes its own download
/// code fetches and verifies the artifact. The Client's log line is told apart from other tests'
/// by the Gateway's address it names.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_client_behind_a_gateway_installs_from_an_upstream_slower_than_its_read_timeout() {
    let log = captured_log();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (fetches, mut fetched) = tokio::sync::watch::channel(0usize);
    let upstream = Arc::new(Upstream {
        fetches: Some(fetches),
        gate: Some(gate.clone()),
        ..Upstream::default()
    });
    let bytes = b"the-binary-over-a-slow-link".to_vec();
    upstream.serve(PATH_1, &bytes);
    let rng = ring::rand::SystemRandom::new();
    let signing = ring::signature::Ed25519KeyPair::from_pkcs8(
        ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("pkcs8")
            .as_ref(),
    )
    .expect("key pair");
    let statement = fleet_core::package::statement("otelcol", "1.0.0", &sha256(&bytes));
    let signature = signing.sign(&statement).as_ref().to_vec();
    let uid = InstanceUid::default();
    let mut offered = offer(&[("otelcol", PATH_1, sha256(&bytes))]);
    if let Some(file) = offered
        .packages
        .get_mut("otelcol")
        .and_then(|package| package.file.as_mut())
    {
        file.signature = signature.clone();
    }
    upstream.offer(&uid, offered);
    let server = spawn_upstream(upstream.clone()).await;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (gateway, _stop) = spawn_gateway(server, &pki, dir.path(), 1 << 20).await;
    let (cert, key) = pki.issue("edge-01", Some("h1"));
    let peer = client(&pki.ca_pem, (cert.clone(), key.clone()));
    report(&peer, gateway, &uid).await;
    tokio::time::timeout(DEADLINE, fetched.wait_for(|count| *count >= 1))
        .await
        .expect("the Gateway fetches")
        .expect("watch");
    let probe = get_now(&peer, gateway, PATH_1).await;
    assert_eq!(probe.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    let write = |file: &str, content: &str| {
        let path = dir.path().join(file);
        std::fs::write(&path, content).expect("write");
        path.display().to_string()
    };
    let mut config: ClientConfig = toml::from_str(&format!(
        r#"
        endpoint = "wss://{gateway}/v1/opamp"
        state_dir = {:?}
        [tls]
        ca_file = {:?}
        cert_file = {:?}
        key_file = {:?}
        "#,
        dir.path().join("edge-state").display().to_string(),
        write("edge-ca.pem", &pki.ca_pem),
        write("edge.pem", &cert),
        write("edge-key.pem", &key),
    ))
    .expect("edge config");
    config.package_key = Some(
        ring::signature::KeyPair::public_key(&signing)
            .as_ref()
            .to_vec(),
    );
    let package = fleet_agent::supervisor::agent::PackageDownload {
        name: "otelcol".to_string(),
        version: "1.0.0".to_string(),
        hash: Vec::new(),
        download_url: PATH_1.to_string(),
        content_hash: sha256(&bytes),
        signature,
        headers: Vec::new(),
    };
    let staging = dir.path().join("edge-staging");
    let download = tokio::spawn(async move {
        fleet_agent::packages::download_and_verify_patiently(
            &package,
            &config,
            &staging,
            &fleet_agent::packages::Progress::default(),
            SHORT_WAITS,
        )
        .await
    });
    tokio::time::timeout(DEADLINE, async {
        loop {
            let asked = String::from_utf8_lossy(&log.lock().expect("log"))
                .lines()
                .any(|line| {
                    line.contains("the download is asked to wait")
                        && line.contains(&gateway.to_string())
                });
            if asked {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the Client's download was answered 503 and waits");
    gate.add_permits(16);
    let staged = tokio::time::timeout(DEADLINE, download)
        .await
        .expect("finished")
        .expect("join")
        .expect("downloaded from the Gateway and verified");
    assert_eq!(std::fs::read(staged).expect("staged"), bytes);
    assert_eq!(upstream.fetched(), vec![PATH_1.to_string()]);
}

/// The log of this test binary, captured once for all its tests.
fn captured_log() -> Arc<Mutex<Vec<u8>>> {
    static LOG: std::sync::OnceLock<Arc<Mutex<Vec<u8>>>> = std::sync::OnceLock::new();
    LOG.get_or_init(|| {
        let log: Arc<Mutex<Vec<u8>>> = Arc::default();
        let sink = log.clone();
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Captured(sink.clone()))
            .try_init()
            .expect("the test binary's log");
        log
    })
    .clone()
}

/// A log writer into a shared buffer.
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---- Against the real Server ----

/// A Client behind a marked Gateway receives an uploaded artifact through it: the Server offers it
/// to the Agent behind the Gateway, the Gateway fetches it with its own certificate — which the
/// Server lets a marked Gateway do for what is offered to any Agent — and the Client's own download
/// code, resolving the offered path against its endpoint (the Gateway), fetches it from there and
/// verifies its hash and signature.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_client_behind_a_marked_gateway_receives_an_uploaded_artifact_through_it() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = dir.path();
    let path = |file: &str| pki.join(file).display().to_string();

    // The fleet's client CA, which also issues both listeners' certificates.
    let ca_key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "gateway cache test CA");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).expect("ca");
    std::fs::write(pki.join("ca.pem"), ca.pem()).expect("write");
    std::fs::write(pki.join("ca-key.pem"), ca_key.serialize_pem()).expect("write");
    let issuer = Issuer::from_ca_cert_pem(&ca.pem(), ca_key).expect("issuer");
    for file in ["server", "gateway-listener"] {
        let key = KeyPair::generate().expect("key");
        let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("signed");
        std::fs::write(pki.join(format!("{file}.pem")), cert.pem()).expect("write");
        std::fs::write(pki.join(format!("{file}-key.pem")), key.serialize_pem()).expect("write");
    }

    let clock: Arc<dyn fleet_server::fleet::Clock> = Arc::new(fleet_server::clock::SystemClock);
    let der = opamp::tls::certificates(ca.pem().as_bytes()).expect("pem");
    let facts = fleet_server::ca::facts(der[0].as_ref()).expect("facts");
    let revocations = Arc::new(
        fleet_server::revocation::Revocations::open(
            Box::new(
                fleet_server::fs::FsLedgerStore::open(&pki.join("fleet-configs")).expect("ledger"),
            ),
            clock,
            vec![fleet_server::revocation::Authority {
                role: "client".to_string(),
                subject: facts.id.issuer,
                name: facts.issuer_name,
            }],
        )
        .expect("revocations"),
    );
    let signer = fleet_server::ca::ClientCa::from_config(
        &toml::from_str::<fleet_server::config::ClientCaConfig>(&format!(
            "cert_file = {:?}\nkey_file = {:?}\n",
            path("ca.pem"),
            path("ca-key.pem"),
        ))
        .expect("client_ca config"),
    )
    .expect("client ca");
    // Certificates the Server issued, so that each names its host: the Gateway's, registered and
    // marked, and a downstream peer's.
    let issue = |host: &str| {
        let key = KeyPair::generate().expect("key");
        let csr = CertificateParams::new(vec![host.to_string()])
            .expect("params")
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("pem");
        (
            signer
                .sign(
                    &csr,
                    host,
                    &fleet_server::revocation::SubjectValues::default(),
                )
                .expect("sign"),
            key.serialize_pem(),
        )
    };
    let (gateway_cert, gateway_key) = issue("gateway-host");
    std::fs::write(pki.join("gateway-cert.pem"), &gateway_cert.pem).expect("write");
    std::fs::write(pki.join("gateway-cert-key.pem"), gateway_key).expect("write");
    let gateway_host = gateway_cert.facts.host.clone().expect("a host");
    revocations
        .record(gateway_cert.facts, &[7; 16], None)
        .expect("register");
    assert!(revocations.set_gateway(&gateway_host, true).expect("mark"));
    let (edge_cert, edge_key) = issue("edge-host");
    std::fs::write(pki.join("edge.pem"), &edge_cert.pem).expect("write");
    std::fs::write(pki.join("edge-key.pem"), &edge_key).expect("write");

    let store = fleet_server::packages::PackageStore::open(pki.join("packages")).expect("store");
    let state = Arc::new(
        fleet_server::fleet::AppState::new(pki.join("fleet-configs"))
            .expect("state")
            .with_client_ca(Some(signer))
            .with_revocations(Some(revocations.clone()))
            .with_packages(Some(
                fleet_server::fleet::PackageOffering::new(&pki.join("packages"), store)
                    .expect("deployments"),
            )),
    );
    let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
        "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
        path("server.pem"),
        path("server-key.pem"),
        path("ca.pem"),
    ))
    .expect("tls config");
    let planes = fleet_server::tls::server_tls(&tls, None, None).expect("server material");
    let admission = fleet_server::transport::Admission::new(true)
        .with_enrolment(planes.issuers, None)
        .with_revocations(Some(revocations));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let server = listener.local_addr().expect("addr");
    tokio::spawn(
        opamp::server::listen::Listener::new(listener, opamp::server::listen::Handle::new())
            .with_tls(planes.agent.rustls_config().expect("agent plane"))
            .serve(fleet_server::agent_app(state.clone(), admission)),
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let gateway = listener.local_addr().expect("addr");
    let config: ClientConfig = toml::from_str(&format!(
        r#"
        endpoint = "wss://{server}/v1/opamp"
        state_dir = {:?}
        [tls]
        ca_file = {:?}
        cert_file = {:?}
        key_file = {:?}
        [gateway]
        listen = "{gateway}"
        [gateway.tls]
        cert_file = {:?}
        key_file = {:?}
        client_ca_file = {:?}
        "#,
        path("gateway-state"),
        path("ca.pem"),
        path("gateway-cert.pem"),
        path("gateway-cert-key.pem"),
        path("gateway-listener.pem"),
        path("gateway-listener-key.pem"),
        path("ca.pem"),
    ))
    .expect("gateway config");
    let (_stop, shutdown) = shutdown_channel();
    tokio::spawn(async move {
        fleet_agent::gateway::run_on(Arc::new(config), listener, shutdown)
            .await
            .expect("gateway");
    });

    let ca_pem = ca.pem();
    let edge = client(&ca_pem, (edge_cert.pem, edge_key));
    let uid = InstanceUid::default();
    let package_report = || {
        let attr = opamp::attributes::string_attr;
        AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            sequence_num: 1,
            agent_description: Some(opamp::proto::AgentDescription {
                identifying_attributes: vec![attr("service.name", "otelcol")],
                non_identifying_attributes: vec![
                    attr("os.type", "linux"),
                    attr("host.arch", "amd64"),
                ],
            }),
            capabilities: AgentCapabilities::ReportsStatus as u64
                | AgentCapabilities::AcceptsPackages as u64,
            ..Default::default()
        }
    };
    let exchange = |report: AgentToServer| {
        let edge = edge.clone();
        async move {
            let response = edge
                .post(format!("https://{gateway}/v1/opamp"))
                .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
                .body(report.encode_to_vec())
                .send()
                .await
                .expect("send");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode")
        }
    };
    exchange(package_report()).await;

    // `otelcol@1.0.0` for linux/amd64, signed into the channel that claims every `otelcol`, and
    // released by the press to the one Agent there — the one behind the Gateway.
    let bytes = b"the-binary-the-server-hosts".to_vec();
    let id = fleet_server::packages::PackageId::new("otelcol", "1.0.0").expect("id");
    let linux = fleet_server::packages::Platform::new("linux", "amd64").expect("platform");
    let packages = state.packages().expect("package delivery");
    packages.create(&id).expect("create");
    packages
        .put_entry(&id, &linux, bytes.clone())
        .expect("entry");
    state
        .deployment_store()
        .expect("deployments")
        .put(
            "stable",
            [("service.name".to_string(), "otelcol".to_string())].into(),
        )
        .expect("deployment");
    state
        .put_deployment_package("stable", &id, true)
        .expect("package");
    let rng = ring::rand::SystemRandom::new();
    let signing = ring::signature::Ed25519KeyPair::from_pkcs8(
        ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("pkcs8")
            .as_ref(),
    )
    .expect("key pair");
    let statement = fleet_core::package::statement("otelcol", "1.0.0", &sha256(&bytes));
    state
        .put_package_entry_signature(&id, &linux, signing.sign(&statement).as_ref().to_vec())
        .expect("signature");
    assert_eq!(state.rollout_deployment("stable").expect("the press"), 1);

    let reply = exchange(package_report()).await;
    let offered = reply
        .packages_available
        .expect("the offer reached the Agent through the Gateway");
    let file = offered.packages["otelcol"].file.clone().expect("file");
    assert_eq!(file.download_url, PATH_1);

    // The Client behind the Gateway, as its download code sees it: its endpoint is the Gateway.
    let mut edge_config: ClientConfig = toml::from_str(&format!(
        r#"
        endpoint = "wss://{gateway}/v1/opamp"
        state_dir = {:?}
        [tls]
        ca_file = {:?}
        cert_file = {:?}
        key_file = {:?}
        "#,
        path("edge-state"),
        path("ca.pem"),
        path("edge.pem"),
        path("edge-key.pem"),
    ))
    .expect("edge config");
    edge_config.package_key = Some(
        ring::signature::KeyPair::public_key(&signing)
            .as_ref()
            .to_vec(),
    );
    let package = fleet_agent::supervisor::agent::PackageDownload {
        name: "otelcol".to_string(),
        version: "1.0.0".to_string(),
        hash: offered.packages["otelcol"].hash.clone(),
        download_url: file.download_url.clone(),
        content_hash: file.content_hash.clone(),
        signature: file.signature.clone(),
        headers: Vec::new(),
    };
    let staged = tokio::time::timeout(
        DEADLINE,
        fleet_agent::packages::download_and_verify_patiently(
            &package,
            &edge_config,
            &pki.join("edge-staging"),
            &fleet_agent::packages::Progress::default(),
            SHORT_WAITS,
        ),
    )
    .await
    .expect("served")
    .expect("downloaded from the Gateway and verified");
    assert_eq!(std::fs::read(staged).expect("staged"), bytes);
}
