//! A host's enrolment and the token it is admitted by (ADR-0064 clause 7), end to end: the real
//! Server in-process, admitting by bearer token as the binary does, against the real Client binary.
//!
//! - `enrol` takes the base URL and the key and no Space, writes `state.json` owner-only, and is
//!   refused on a host that has one;
//! - the Client sends its token on every OpAMP exchange on both transports, on a package download
//!   (a header the offer names cannot replace it), and on its own telemetry only to the Server's
//!   origin;
//! - a new token is asked for after a `401` whose Bearer challenge says `invalid_token`, and after
//!   nothing else: not a bare `401`, not `invalid_request`, not `invalid_client`;
//! - `revoke` never asks the Server, refuses while the service runs, deletes the state directory
//!   whole — `--keep-cache` spares `config/` and `packages/` — and keeps the service from starting
//!   at boot;
//! - the Client does not start without a `state.json`, and `enrol` is what starts the service.
//!
//! The service manager is stood in for by a [`ServiceHost`] of the test's own: nothing here
//! registers, starts or stops a service of the machine it runs on.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{any, post};
use axum::Router;
use classis_agent::enrolment::{self, Installed, ServiceHost};
use classis_agent::service::{ServiceControl, ServiceState};
use classis_server::fleet::AppState;
use opamp::client::ClientTls;

/// What the Server saw of a request: its method, its path and its `Authorization`.
type Seen = (String, String, Option<String>);

/// What an origin saw of a download: its `Authorization` and its `X-Fleet`.
type Download = (Option<String>, Option<String>);

/// The Server under test: the Agent plane as the binary builds it (`agent_app`, with its
/// Enrolment), a route for own telemetry beside it, and a record of every request it was sent.
struct Server {
    addr: SocketAddr,
    state: Arc<AppState>,
    admission: common::Admission,
    seen: Arc<Mutex<Vec<Seen>>>,
    dir: tempfile::TempDir,
}

async fn record(
    State(seen): State<Arc<Mutex<Vec<Seen>>>>,
    request: Request,
    next: Next,
) -> Response {
    seen.lock().expect("the record").push((
        request.method().to_string(),
        request.uri().path().to_string(),
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
    ));
    next.run(request).await
}

async fn server() -> Server {
    server_offering(|_| None).await
}

/// A Server that offers own-telemetry destinations: `offer` is told its own address.
async fn server_offering(
    offer: impl FnOnce(SocketAddr) -> Option<classis_server::fleet::TelemetryOffer>,
) -> Server {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the server");
    let addr = listener.local_addr().expect("local addr");
    let mut state = common::fleet_state(dir.path());
    if let Some(offer) = offer(addr) {
        state = state.with_telemetry_offer(offer);
    }
    let state = Arc::new(state);
    let admission = common::Admission::new(dir.path());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = admission
        .app(state.clone())
        .route("/v1/logs", post(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(seen.clone(), record));
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    Server {
        addr,
        state,
        admission,
        seen,
        dir,
    }
}

impl Server {
    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request the Server was sent so far.
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("the record").clone()
    }

    /// How many requests to `path` the Server was sent.
    fn count(&self, path: &str) -> usize {
        self.requests().iter().filter(|(_, p, _)| p == path).count()
    }

    /// The `Authorization` of every request to `path`.
    fn authorizations(&self, path: &str) -> Vec<Option<String>> {
        self.requests()
            .into_iter()
            .filter(|(_, p, _)| p == path)
            .map(|(_, _, authorization)| authorization)
            .collect()
    }

    /// A host of the Space, enrolled through the real `enrol`, with its `state.json` in
    /// `<dir>/<name>`.
    async fn host(&self, name: &str) -> PathBuf {
        let state_dir = self.dir.path().join(name);
        self.admission.enrol(self.addr, &state_dir).await;
        state_dir
    }
}

/// What a state directory's `state.json` holds, as JSON.
fn state_json(state_dir: &Path) -> serde_json::Map<String, serde_json::Value> {
    let text = std::fs::read_to_string(state_dir.join("state.json")).expect("state.json");
    serde_json::from_str(&text).expect("state.json is JSON")
}

fn token_on_file(state_dir: &Path) -> String {
    state_json(state_dir)["access_token"]
        .as_str()
        .expect("a token")
        .to_string()
}

async fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The Client binary with `args`, to its end, with no terminal.
async fn supervisor(args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .expect("run the Client")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The Client binary, left running.
fn run_client(config: &Path) -> tokio::process::Child {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the Client")
}

/// A configuration whose OpAMP endpoint is `endpoint`, with the state directory `state_dir`.
fn write_config(dir: &Path, endpoint: &str, state_dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("supervisor.toml");
    std::fs::write(
        &path,
        format!(
            "endpoint = {endpoint:?}\nstate_dir = {state:?}\nheartbeat_interval_secs = 1\n\
             poll_interval_secs = 1\n{extra}",
            state = state_dir.to_string_lossy(),
        ),
    )
    .expect("write supervisor.toml");
    path
}

/// A service manager of the test's own: it records what it is asked, and answers `state`.
struct Fake {
    state: ServiceState,
    asked: Arc<Mutex<Vec<String>>>,
    /// What must hold when the service is asked to start or to be enabled.
    state_file: Option<PathBuf>,
}

impl Fake {
    fn note(&self, what: &str) {
        if what == "start" || what == "enable" {
            if let Some(file) = &self.state_file {
                assert!(file.exists(), "{what} came before state.json was written");
            }
        }
        self.asked.lock().expect("asked").push(what.to_string());
    }
}

impl ServiceControl for Fake {
    fn start(&self) -> Result<(), String> {
        self.note("start");
        Ok(())
    }
    fn stop(&self) -> Result<(), String> {
        self.note("stop");
        Ok(())
    }
    fn enable(&self) -> Result<(), String> {
        self.note("enable");
        Ok(())
    }
    fn disable(&self) -> Result<(), String> {
        self.note("disable");
        Ok(())
    }
    fn state(&self) -> Result<ServiceState, String> {
        Ok(self.state)
    }
}

struct FakeHost {
    state: ServiceState,
    asked: Arc<Mutex<Vec<String>>>,
    state_file: Option<PathBuf>,
}

impl FakeHost {
    fn new(state: ServiceState, state_file: Option<PathBuf>) -> FakeHost {
        FakeHost {
            state,
            asked: Arc::default(),
            state_file,
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

impl ServiceHost for FakeHost {
    fn registered(&self, _: &Path) -> Result<Option<Installed>, String> {
        Ok(Some(Installed {
            control: Box::new(Fake {
                state: self.state,
                asked: self.asked.clone(),
                state_file: self.state_file.clone(),
            }),
            run_as: None,
        }))
    }
}

/// `enrol` takes the base URL and the key and no Space, writes `state.json` with the five values
/// of clause 7 and nothing else, owner-only, and refuses a host that has one: the file is not
/// touched and the Server is not asked again.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrol_takes_no_space_writes_state_json_owner_only_and_refuses_a_second_run() {
    let server = server().await;
    let state_dir = server.dir.path().join("host");
    let (state_arg, base) = (state_dir.to_string_lossy().into_owned(), server.base());

    let with_space = supervisor(&[
        "--state-dir",
        &state_arg,
        "enrol",
        "--space",
        "lab",
        &base,
        &server.admission.key,
    ])
    .await;
    assert!(!with_space.status.success(), "a Space on the command line");
    assert!(
        stderr(&with_space).contains("--space"),
        "{}",
        stderr(&with_space)
    );
    assert!(!state_dir.join("state.json").exists());
    assert_eq!(server.count("/v1/enrol"), 0, "nobody was asked");

    let enrolled = supervisor(&[
        "--state-dir",
        &state_arg,
        "enrol",
        &base,
        &server.admission.key,
    ])
    .await;
    assert!(enrolled.status.success(), "{}", stderr(&enrolled));
    let mut keys: Vec<String> = state_json(&state_dir).keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "access_token",
            "client_secret",
            "device_id",
            "endpoint",
            "space"
        ]
    );
    let file = state_json(&state_dir);
    assert_eq!(file["space"], common::SPACE, "the Space the key names");
    assert_eq!(file["endpoint"], base);
    assert!(!file["device_id"].as_str().unwrap().is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(state_dir.join("state.json"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "owner-only");
    }
    // The token on file is the Server's: it admits an exchange.
    let admitted = reqwest::Client::new()
        .post(format!("{base}/v1/opamp"))
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .bearer_auth(token_on_file(&state_dir))
        .body(Vec::new())
        .send()
        .await
        .expect("post");
    assert_ne!(admitted.status(), StatusCode::UNAUTHORIZED);

    let before = std::fs::read(state_dir.join("state.json")).expect("read");
    let again = supervisor(&[
        "--state-dir",
        &state_arg,
        "enrol",
        &base,
        &server.admission.key,
    ])
    .await;
    assert!(!again.status.success(), "a second enrol");
    assert!(
        stderr(&again).contains("enrolled already"),
        "{}",
        stderr(&again)
    );
    assert_eq!(
        std::fs::read(state_dir.join("state.json")).expect("read"),
        before,
        "the file was written once"
    );
    assert_eq!(
        server.count("/v1/enrol"),
        1,
        "the Server was not asked again"
    );
}

/// A wrong key enrols nothing and leaves no `state.json`.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_key_leaves_no_state_json() {
    let server = server().await;
    let state_dir = server.dir.path().join("host");
    let refused = supervisor(&[
        "--state-dir",
        &state_dir.to_string_lossy(),
        "enrol",
        &server.base(),
        "cle1_lab_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ])
    .await;
    assert!(!refused.status.success());
    assert!(!state_dir.join("state.json").exists());
}

/// `enrol` writes `state.json` before it lets the service start at boot and starts it, and
/// installing starts nothing: the registered service is asked for nothing until `enrol`.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrol_enables_and_starts_the_registered_service_after_state_json() {
    let server = server().await;
    let state_dir = server.dir.path().join("host");
    let host = FakeHost::new(ServiceState::Stopped, Some(state_dir.join("state.json")));
    assert!(host.asked().is_empty(), "an install starts nothing");

    let enrolled = enrolment::enrol(
        &server.base(),
        &server.admission.key,
        &state_dir,
        ClientTls::default(),
        &host,
    )
    .await
    .expect("enrolled");
    assert!(enrolled.service_started);
    assert_eq!(host.asked(), ["enable", "start"]);

    // And a host that refuses (a second `enrol`) asks the service for nothing.
    let host = FakeHost::new(ServiceState::Stopped, None);
    enrolment::enrol(
        &server.base(),
        &server.admission.key,
        &state_dir,
        ClientTls::default(),
        &host,
    )
    .await
    .expect_err("enrolled already");
    assert!(host.asked().is_empty());
}

/// The Client sends the token on every OpAMP exchange, on the WebSocket and on plain HTTP: every
/// request the Server was sent carries the token on file, and the Agent is admitted.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_sends_its_token_on_opamp_over_both_transports() {
    for scheme in ["ws", "http"] {
        let server = server().await;
        let state_dir = server.host("client-state").await;
        let token = token_on_file(&state_dir);
        let config = write_config(
            server.dir.path(),
            &format!("{scheme}://{}/v1/opamp", server.addr),
            &state_dir,
            "",
        );
        let _client = run_client(&config);
        wait_until("the Agent to connect", || {
            server
                .state
                .snapshot()
                .iter()
                .any(|a| a.connected)
                .then_some(())
        })
        .await;
        let sent = server.authorizations("/v1/opamp");
        assert!(!sent.is_empty(), "{scheme}");
        assert!(
            sent.iter()
                .all(|authorization| authorization.as_deref() == Some(&format!("Bearer {token}"))),
            "{scheme}: {sent:?}"
        );
    }
}

/// A download carries the token, and a header the offer names `Authorization` cannot replace it;
/// the other headers of the offer still go.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packages_offered_authorization_cannot_replace_the_clients_token() {
    opamp::tls::install_ring_provider();
    let seen: Arc<Mutex<Vec<Download>>> = Arc::default();
    let record = seen.clone();
    let origin = Router::new().route(
        "/artifact",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let record = record.clone();
            async move {
                let pick = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string)
                };
                record
                    .lock()
                    .expect("record")
                    .push((pick("authorization"), pick("x-fleet")));
                vec![0u8; 16]
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, origin).await.expect("serve") });

    let dir = tempfile::tempdir().expect("tempdir");
    common::write_state_json(dir.path(), &format!("http://{addr}"));
    let mut config = classis_agent::config::ClientConfig {
        endpoint: format!("ws://{addr}/v1/opamp"),
        state_dir: dir.path().to_path_buf(),
        package_key: Some(vec![7u8; 32]),
        ..Default::default()
    };
    config.credentials = Some(enrolment::required(dir.path()).expect("state.json"));
    let package = classis_agent::supervisor::agent::PackageDownload {
        name: "otelcol".to_string(),
        version: "1.0.0".to_string(),
        hash: b"pkg".to_vec(),
        download_url: format!("http://{addr}/artifact"),
        // The body is not the artifact: the download fails on its hash, after the request.
        content_hash: vec![0u8; 32],
        signature: vec![1u8; 64],
        headers: vec![
            (
                "Authorization".to_string(),
                "Bearer from-the-offer".to_string(),
            ),
            ("X-Fleet".to_string(), "kept".to_string()),
        ],
    };
    let error = classis_agent::packages::download_and_verify(
        &package,
        &config,
        &dir.path().join("staging"),
        &classis_agent::packages::Progress::default(),
    )
    .await
    .expect_err("the body is not the artifact");
    assert!(!error.contains("401"), "{error}");
    assert_eq!(
        *seen.lock().expect("record"),
        [(
            Some("Bearer a-token-nobody-issued".to_string()),
            Some("kept".to_string())
        )]
    );
}

/// The Server's offer of own telemetry is followed, and the token goes to the destination that has
/// the Server's own origin and to no other.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_telemetry_carries_the_token_only_to_the_servers_origin() {
    opamp::tls::install_ring_provider();
    // Another collector, on another port of the loopback: another origin.
    let elsewhere: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
    let record = elsewhere.clone();
    let collector = Router::new().route(
        "/v1/metrics",
        post(move |headers: axum::http::HeaderMap| {
            let record = record.clone();
            async move {
                record.lock().expect("record").push(
                    headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string),
                );
                StatusCode::OK
            }
        }),
    );
    let collector_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let collector_addr = collector_listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(collector_listener, collector)
            .await
            .expect("serve")
    });

    let server = server_offering(|addr| {
        let offer = format!(
            "metrics_endpoint = \"http://{collector_addr}/v1/metrics\"\n\
             logs_endpoint = \"http://{addr}/v1/logs\"\n\
             [headers]\nAuthorization = \"Bearer offered-for-the-collector\"\n"
        );
        Some(classis_server::fleet::TelemetryOffer::from_config(
            &toml::from_str::<classis_server::config::TelemetryOfferConfig>(&offer)
                .expect("the offer"),
        ))
    })
    .await;
    let state_dir = server.host("client-state").await;
    let token = token_on_file(&state_dir);
    let config = write_config(
        server.dir.path(),
        &format!("ws://{}/v1/opamp", server.addr),
        &state_dir,
        "",
    );
    let _client = run_client(&config);

    wait_until("own logs at the Server's origin", || {
        (server.count("/v1/logs") > 0).then_some(())
    })
    .await;
    wait_until("own metrics at the other collector", || {
        (!elsewhere.lock().expect("record").is_empty()).then_some(())
    })
    .await;
    assert!(
        server
            .authorizations("/v1/logs")
            .iter()
            .all(|a| a.as_deref() == Some(&format!("Bearer {token}"))),
        "the Server's own origin got the host's token in place of the offered header: {:?}",
        server.authorizations("/v1/logs")
    );
    let other = elsewhere.lock().expect("record").clone();
    assert!(
        other
            .iter()
            .all(|a| a.as_deref() == Some("Bearer offered-for-the-collector")),
        "the host's token reached another origin: {other:?}"
    );
}

/// A token replaced on the Server is met with `401 invalid_token`, and the Client then asks for a
/// new one with its client credentials, keeps it in `state.json`, and reconnects — once, on either
/// transport.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_token_is_met_with_one_new_one() {
    for scheme in ["ws", "http"] {
        let server = server().await;
        let state_dir = server.host("client-state").await;
        let old = token_on_file(&state_dir);
        let credentials = enrolment::required(&state_dir).expect("state.json");
        let config = write_config(
            server.dir.path(),
            &format!("{scheme}://{}/v1/opamp", server.addr),
            &state_dir,
            "",
        );
        let _client = run_client(&config);
        wait_until("the Agent to connect", || {
            server
                .state
                .snapshot()
                .iter()
                .any(|a| a.connected)
                .then_some(())
        })
        .await;
        assert_eq!(
            server.count("/v1/token"),
            1,
            "the token of `enrol`, and no other"
        );

        // The Server replaces the host's token — which ends its session on the WebSocket — and the
        // old one is no token any more.
        let http = reqwest::Client::new();
        oauth_token::client::request_token(
            &http,
            format!("{}/v1/token", server.base()),
            &credentials.device_id,
            &credentials.client_secret,
        )
        .await
        .expect("a replacement");
        assert_eq!(server.count("/v1/token"), 2);

        wait_until("the Client to keep a new token", || {
            (token_on_file(&state_dir) != old).then_some(())
        })
        .await;
        wait_until("the Agent to be connected again", || {
            let latest = server.authorizations("/v1/opamp").pop().flatten();
            (latest.as_deref() == Some(&format!("Bearer {}", token_on_file(&state_dir)))
                && server.state.snapshot().iter().any(|a| a.connected))
            .then_some(())
        })
        .await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(
            server.count("/v1/token"),
            3,
            "{scheme}: one request for a new token, after the replaced one was refused"
        );
        let file = state_json(&state_dir);
        assert_eq!(file["client_secret"], credentials.client_secret.as_str());
        assert_eq!(file["device_id"], credentials.device_id.as_str());
    }
}

/// How a stub Server refuses the OpAMP endpoint.
#[derive(Clone, Copy, Debug)]
enum Refusal {
    Bare401,
    InvalidRequest,
    InvalidClient,
    InvalidToken,
}

/// How a stub Server answers the token endpoint.
#[derive(Clone, Copy, Debug)]
enum Token {
    Issues,
    InvalidClient,
}

struct Watched {
    opamp: usize,
    token: usize,
    on_file: String,
}

/// A stub Server that refuses every OpAMP request as `refusal` says and answers the token endpoint
/// as `token` says, a Client that is enrolled with it, and what happened in `window`.
async fn watch(refusal: Refusal, token: Token, scheme: &str, window: Duration) -> Watched {
    opamp::tls::install_ring_provider();
    let opamp_hits = Arc::new(AtomicUsize::new(0));
    let token_hits = Arc::new(AtomicUsize::new(0));
    let (opamp_count, token_count) = (opamp_hits.clone(), token_hits.clone());
    let refuse = move || {
        let opamp_count = opamp_count.clone();
        async move {
            opamp_count.fetch_add(1, Ordering::SeqCst);
            let (status, challenge): (StatusCode, Option<&'static str>) = match refusal {
                Refusal::Bare401 => (StatusCode::UNAUTHORIZED, None),
                Refusal::InvalidRequest => (
                    StatusCode::BAD_REQUEST,
                    Some("Bearer error=\"invalid_request\""),
                ),
                Refusal::InvalidClient => (
                    StatusCode::UNAUTHORIZED,
                    Some("Bearer error=\"invalid_client\""),
                ),
                Refusal::InvalidToken => (
                    StatusCode::UNAUTHORIZED,
                    Some("Bearer error=\"invalid_token\""),
                ),
            };
            let mut response = Response::new(axum::body::Body::from("refused"));
            *response.status_mut() = status;
            if let Some(challenge) = challenge {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(challenge),
                );
            }
            response
        }
    };
    let issue = move || {
        let token_count = token_count.clone();
        async move {
            token_count.fetch_add(1, Ordering::SeqCst);
            match token {
                Token::Issues => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"access_token":"a-replacement-token","token_type":"Bearer"}"#,
                ),
                Token::InvalidClient => (
                    StatusCode::UNAUTHORIZED,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"invalid_client"}"#,
                ),
            }
        }
    };
    let app = Router::new()
        .route("/v1/opamp", any(refuse))
        .route("/v1/token", post(issue));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("client-state");
    common::write_state_json(&state_dir, &format!("http://{addr}"));
    let config = write_config(
        dir.path(),
        &format!("{scheme}://{addr}/v1/opamp"),
        &state_dir,
        "",
    );
    let client = run_client(&config);
    tokio::time::sleep(window).await;
    drop(client);
    Watched {
        opamp: opamp_hits.load(Ordering::SeqCst),
        token: token_hits.load(Ordering::SeqCst),
        on_file: token_on_file(&state_dir),
    }
}

/// A new token is asked for after a `401` whose Bearer challenge says `invalid_token` and after
/// nothing else: a bare `401`, `invalid_request` and `invalid_client` leave the token endpoint
/// alone and `state.json` as it is, on either transport, and the Client goes on trying.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_token_is_asked_for_after_invalid_token_and_nothing_else() {
    const WINDOW: Duration = Duration::from_millis(3500);
    let mut runs = Vec::new();
    for scheme in ["ws", "http"] {
        for refusal in [
            Refusal::Bare401,
            Refusal::InvalidRequest,
            Refusal::InvalidClient,
        ] {
            runs.push((scheme, refusal));
        }
    }
    let watched = futures_util::future::join_all(
        runs.iter()
            .map(|(scheme, refusal)| watch(*refusal, Token::Issues, scheme, WINDOW)),
    )
    .await;
    for ((scheme, refusal), watched) in runs.iter().zip(&watched) {
        assert!(watched.opamp >= 1, "{scheme} {refusal:?}: the Client tried");
        assert_eq!(
            watched.token, 0,
            "{scheme} {refusal:?}: no new token was asked for"
        );
        assert_eq!(
            watched.on_file, "a-token-nobody-issued",
            "{scheme} {refusal:?}: state.json is as it was"
        );
    }

    // The same Client, refused for its token, asks and keeps what it is given.
    for scheme in ["ws", "http"] {
        let renewed = watch(Refusal::InvalidToken, Token::Issues, scheme, WINDOW).await;
        assert!(renewed.token >= 1, "{scheme}: a new token was asked for");
        assert_eq!(renewed.on_file, "a-replacement-token", "{scheme}");

        // And a Server that refuses its client credentials gives it none: `state.json` stays, and
        // the Client goes on asking now and then rather than ending.
        let denied = watch(Refusal::InvalidToken, Token::InvalidClient, scheme, WINDOW).await;
        assert!(denied.token >= 1, "{scheme}: it asked");
        assert_eq!(denied.on_file, "a-token-nobody-issued", "{scheme}");
    }
}

/// A host that has none of what `revoke` deletes: the state directory of a host that ran, with the
/// entries the Client keeps there and one a later version might.
fn leave_traces(state_dir: &Path) {
    for (path, contents) in [
        ("instance-uid", "x"),
        ("connection-settings.pb", "x"),
        ("package-high-water.json", "{}"),
        ("config/entry.yaml", "x"),
        ("packages/self.staged", "x"),
        ("logs/client.log", "x"),
        ("supervisors/a/program/bin", "x"),
        ("added-in-a-later-version", "x"),
    ] {
        let path = state_dir.join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, contents).expect("write");
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// `revoke` never contacts the Server and deletes the state directory whole — `state.json`, the
/// Agents' identities, the connection settings, the logs; with `--keep-cache` everything but
/// `config/` and `packages/`, whatever else the directory comes to hold; and without `--force` and
/// without a terminal it refuses rather than blocks.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_never_contacts_the_server_and_deletes_the_whole_state_directory() {
    let server = server().await;
    let state_dir = server.host("client-state").await;
    leave_traces(&state_dir);
    let state_arg = state_dir.to_string_lossy().into_owned();
    let asked = server.requests().len();

    let unasked = supervisor(&["--state-dir", &state_arg, "revoke"]).await;
    assert!(!unasked.status.success());
    assert!(
        stderr(&unasked).contains("terminal"),
        "{}",
        stderr(&unasked)
    );
    assert!(state_dir.join("state.json").exists(), "nothing was deleted");

    let kept = supervisor(&[
        "--state-dir",
        &state_arg,
        "revoke",
        "--force",
        "--keep-cache",
    ])
    .await;
    assert!(kept.status.success(), "{}", stderr(&kept));
    assert_eq!(entries(&state_dir), ["config", "packages"]);
    assert!(state_dir.join("config/entry.yaml").exists());

    // Enrolled again — a new host — and then revoked whole.
    std::fs::remove_dir_all(&state_dir).expect("start again");
    server.admission.enrol(server.addr, &state_dir).await;
    let asked_after_enrol = server.requests().len();
    leave_traces(&state_dir);
    let whole = supervisor(&["--state-dir", &state_arg, "revoke", "--force"]).await;
    assert!(whole.status.success(), "{}", stderr(&whole));
    assert!(entries(&state_dir).is_empty(), "{:?}", entries(&state_dir));

    assert!(
        asked_after_enrol > asked,
        "the second `enrol` asked the Server"
    );
    assert_eq!(
        server.requests().len(),
        asked_after_enrol,
        "`revoke` asked the Server for nothing"
    );
}

/// `revoke` refuses while the service runs, and a stopped one is kept from starting at boot before
/// anything is deleted; the service is never started or stopped by it.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_refuses_while_the_service_runs_and_leaves_it_disabled() {
    let server = server().await;
    let state_dir = server.host("client-state").await;
    leave_traces(&state_dir);

    let running = FakeHost::new(ServiceState::Running, None);
    let error = classis_agent::revoke::revoke(&state_dir, true, false, &running, &mut |_| Ok(true))
        .expect_err("the service runs");
    assert!(error.contains("running"), "{error}");
    assert!(running.asked().is_empty(), "{:?}", running.asked());
    assert!(state_dir.join("state.json").exists());

    let stopped = FakeHost::new(ServiceState::Stopped, None);
    let revoked =
        classis_agent::revoke::revoke(&state_dir, true, false, &stopped, &mut |_| Ok(true))
            .expect("revoked");
    assert!(revoked.service_disabled);
    assert_eq!(stopped.asked(), ["disable"]);
    assert!(entries(&state_dir).is_empty());
}

/// The Client does not start without a `state.json`, in the foreground or by a bare invocation, and
/// the error names `enrol`.
/// Verifies: ADR-0064
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_refuses_to_start_without_state_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("client-state");
    let config = write_config(dir.path(), "ws://127.0.0.1:9/v1/opamp", &state_dir, "");
    let config_arg = config.to_string_lossy().into_owned();
    for args in [
        vec!["--config", &config_arg, "run"],
        vec!["--config", &config_arg],
    ] {
        let output = tokio::time::timeout(Duration::from_secs(20), supervisor(&args))
            .await
            .expect("it ended on its own");
        assert!(!output.status.success(), "{args:?}");
        let error = stderr(&output);
        assert!(error.contains("supervisor enrol"), "{args:?}: {error}");
    }
}
