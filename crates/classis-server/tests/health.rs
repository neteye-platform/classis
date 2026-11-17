//! `/livez` and `/readyz` on the Operator plane (ADR-0063): answered without a credential beside
//! a guarded plane, the rest of which stays guarded.

mod support;

use classis_server::api::OperatorAuth;
use classis_server::config::RestAuthConfig;
use classis_server::fleet::{AppState, RecordsReady};
use std::sync::Arc;
use support::TestServer;

async fn spawn(records_ready: Option<RecordsReady>) -> TestServer {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_records_ready(records_ready),
    );
    let auth: RestAuthConfig = toml::from_str(&format!(
        "[basic_users]\nfleet-admin = {:?}\n",
        classis_server::credentials::hash_basic("secret").expect("hash"),
    ))
    .expect("parse");
    let (addr, rest_addr) = support::serve_guarded(
        state.clone(),
        classis_server::transport::Admission::open(),
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

async fn get(server: &TestServer, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://{}{path}", server.rest_addr))
        .send()
        .await
        .expect("get")
}

/// Verifies: ADR-0063
#[tokio::test]
async fn the_probes_answer_without_a_credential_and_the_rest_of_the_plane_stays_guarded() {
    let server = spawn(None).await;

    for path in ["/livez", "/readyz"] {
        let response = get(&server, path).await;
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(response.text().await.expect("body"), "ok");
    }
    let head = reqwest::Client::new()
        .head(format!("http://{}/readyz", server.rest_addr))
        .send()
        .await
        .expect("head");
    assert_eq!(head.status(), 200);
    let post = reqwest::Client::new()
        .post(format!("http://{}/readyz", server.rest_addr))
        .send()
        .await
        .expect("post");
    assert_eq!(post.status(), 405, "only GET and HEAD");

    for path in ["/api/v1/agents", "/", "/api/v1/docs"] {
        assert_eq!(get(&server, path).await.status(), 401, "{path}");
    }
}

/// Verifies: ADR-0063
#[tokio::test]
async fn readiness_names_the_failed_check_and_nothing_else() {
    let server = spawn(Some(Arc::new(|| {
        Err("password authentication failed for user fleet at 10.0.0.5".to_string())
    })))
    .await;

    let response = get(&server, "/readyz").await;
    assert_eq!(response.status(), 503);
    assert_eq!(response.text().await.expect("body"), "database");
    assert_eq!(
        get(&server, "/livez").await.status(),
        200,
        "a database that fails leaves the process alive"
    );
}

/// Verifies: ADR-0063
#[tokio::test]
async fn probes_are_not_counted_by_the_admission_throttle() {
    let server = spawn(None).await;
    // Far more requests than the throttle allows failures: none of them is one.
    for _ in 0..50 {
        assert_eq!(get(&server, "/livez").await.status(), 200);
    }
    assert_eq!(get(&server, "/api/v1/agents").await.status(), 401);
}
