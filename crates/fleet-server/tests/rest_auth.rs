//! Basic authentication on the Operator plane (ADR-0021): the REST API, the API docs, and the UI
//! behind one credential set — and the Agent plane deliberately untouched by it.

mod support;

use base64::Engine as _;
use fleet_server::api::OperatorAuth;
use fleet_server::config::RestAuthConfig;
use fleet_server::fleet::{AppState, PackageOffering};
use fleet_server::packages::PackageStore;
use opamp::uid::InstanceUid;
use prost::Message as _;
use std::sync::Arc;
use support::{full_report, TestServer};

const PROTOBUF: &str = "application/x-protobuf";

/// A Server whose Operator plane accepts one operator, with package delivery armed so the Agent
/// plane has an artifact to serve.
async fn spawn_guarded() -> TestServer {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            )),
    );
    let auth: RestAuthConfig = toml::from_str(&format!(
        "[basic_users]\nfleet-admin = {:?}\n",
        fleet_server::credentials::hash_basic("secret").expect("hash"),
    ))
    .expect("parse");
    let (addr, rest_addr) = support::serve_guarded(
        state.clone(),
        fleet_server::transport::Admission::open(),
        Some(OperatorAuth::from_config(&auth).expect("auth")),
    )
    .await;
    TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    }
}

fn basic(user: &str, password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

async fn get(server: &TestServer, path: &str, authorization: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new().get(format!("http://{}{path}", server.rest_addr));
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    request.send().await.expect("get")
}

/// Verifies: ADR-0021
#[tokio::test]
async fn a_request_without_credentials_is_answered_401_with_a_basic_challenge() {
    let server = spawn_guarded().await;

    let response = get(&server, "/api/v1/agents", None).await;
    assert_eq!(response.status(), 401);
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .expect("a WWW-Authenticate challenge");
    assert!(
        challenge.starts_with("Basic realm="),
        "the challenge is what makes a browser prompt: {challenge:?}"
    );

    // A wrong password and an unknown user fare no better than none.
    assert_eq!(
        get(
            &server,
            "/api/v1/agents",
            Some(&basic("fleet-admin", "wrong"))
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        get(&server, "/api/v1/agents", Some(&basic("nobody", "secret")))
            .await
            .status(),
        401
    );
}

/// Verifies: ADR-0021
#[tokio::test]
async fn the_configured_operator_reaches_the_api() {
    let server = spawn_guarded().await;
    let credential = basic("fleet-admin", "secret");

    let response = get(&server, "/api/v1/agents", Some(&credential)).await;
    assert_eq!(response.status(), 200);
    let fleet: serde_json::Value = response.json().await.expect("json");
    assert_eq!(fleet.as_array().expect("array").len(), 0);

    // And writing is no different from reading — one credential, the whole plane.
    let stored = reqwest::Client::new()
        .put(format!(
            "http://{}/api/v1/configurations/base",
            server.rest_addr
        ))
        .header("authorization", &credential)
        .json(&serde_json::json!({ "body": "receivers: {}", "service_name": "otelcol" }))
        .send()
        .await
        .expect("put");
    assert_eq!(stored.status(), 200);
}

/// The operator tools take one `--server` base URL and build paths onto it, so the credential has
/// to travel in that URL — `http://user:password@host:4321`. This pins that it does: the HTTP
/// client turns the URL's userinfo into the Basic header, which is why no tool needed a new flag.
#[tokio::test]
async fn a_credential_in_the_server_url_authenticates() {
    let server = spawn_guarded().await;
    let response = reqwest::Client::new()
        .get(format!(
            "http://fleet-admin:secret@{}/api/v1/agents",
            server.rest_addr
        ))
        .send()
        .await
        .expect("get");
    assert_eq!(response.status(), 200);
}

/// The guard covers the *plane*, not `/api/v1`: the UI and the API docs are as much of it as the
/// API is, and Basic is what lets a browser answer for them without a login page (ADR-0021).
/// Verifies: ADR-0021
#[tokio::test]
async fn the_ui_and_the_api_docs_are_guarded_too() {
    let server = spawn_guarded().await;
    let credential = basic("fleet-admin", "secret");

    for path in [
        "/",
        "/ui.css",
        "/ui-carbon.css",
        "/ui-quiet.css",
        "/shiki.js",
        "/api/v1/docs",
        "/api/v1/openapi.json",
    ] {
        assert_eq!(
            get(&server, path, None).await.status(),
            401,
            "{path} must not be served without a credential"
        );
        assert_eq!(
            get(&server, path, Some(&credential)).await.status(),
            200,
            "{path} must be served with one"
        );
    }
}

/// The half that must NOT change: guarding the operator's plane locks nothing out of the fleet's.
/// An Agent carries no operator credential, and a Client downloading a package carries none either
/// (ADR-0013, ADR-0021) — so a rollout keeps working.
/// Verifies: ADR-0021
#[tokio::test]
async fn the_agent_plane_is_untouched_by_the_operator_credential() {
    let server = spawn_guarded().await;
    let credential = basic("fleet-admin", "secret");
    let client = reqwest::Client::new();

    // The Agent reports without any credential at all.
    let uid = InstanceUid::default();
    let reported = client
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .body(full_report(&uid, "edge-01", 1).encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(reported.status(), 200);

    // The operator uploads an artifact through the guarded plane …
    let set = format!(
        "http://{}/api/v1/packages/{}/1.2.3",
        server.rest_addr,
        support::AGENT_TYPE
    );
    let created = client
        .put(&set)
        .header("authorization", &credential)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(created.status(), 200);
    let uploaded = client
        .put(format!("{set}/entries/linux/amd64"))
        .header("authorization", &credential)
        .body(b"the-binary".to_vec())
        .send()
        .await
        .expect("put entry");
    assert_eq!(uploaded.status(), 200);

    // … and the Agent downloads it from its own plane with nothing to present.
    let downloaded = client
        .get(format!(
            "http://{}/api/v1/packages/{}/1.2.3/file?os=linux&arch=amd64",
            server.addr,
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("download");
    assert_eq!(downloaded.status(), 200);
    assert_eq!(
        downloaded.bytes().await.expect("bytes").as_ref(),
        b"the-binary"
    );
}
