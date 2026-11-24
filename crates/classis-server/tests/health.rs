//! `/livez` and `/readyz` on the Operator plane: answered without a credential beside
//! a guarded plane, the rest of which stays guarded.

mod support;

use classis_server::api::OperatorAuth;
use classis_server::config::RestAuthConfig;
use classis_server::fleet::{AppState, RecordsReady};
use classis_server::throttle::{Limits, Throttle};
use std::sync::Arc;
use support::TestServer;

async fn spawn(records_ready: Option<RecordsReady>) -> TestServer {
    spawn_with(records_ready, None).await
}

/// [`spawn`], the Operator plane's sign-ins counted by `throttle` when one is given.
async fn spawn_with(
    records_ready: Option<RecordsReady>,
    throttle: Option<Arc<Throttle>>,
) -> TestServer {
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
        Some(throttle.into_iter().fold(
            OperatorAuth::from_config(&auth).expect("auth"),
            OperatorAuth::with_throttle,
        )),
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

#[tokio::test]
async fn probes_are_not_counted_by_the_admission_throttle() {
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    let throttle = Arc::new(Throttle::new(
        Limits {
            max_failures: 3,
            window_secs: 60,
            backoff_secs: 60,
        },
        clock,
    ));
    let server = spawn_with(None, Some(throttle)).await;
    // Far more probes than the throttle allows failures: none of them is one.
    for _ in 0..50 {
        assert_eq!(get(&server, "/livez").await.status(), 200);
        assert_eq!(get(&server, "/readyz").await.status(), 200);
    }
    // The budget is whole: three refused sign-ins, not fewer, put the address in back-off.
    for _ in 0..3 {
        assert_eq!(sign_in(&server, "wrong").await.status(), 401);
    }
    assert_eq!(
        sign_in(&server, "secret").await.status(),
        429,
        "the throttle counts sign-ins"
    );
    // And an address in back-off is still probed.
    assert_eq!(get(&server, "/livez").await.status(), 200);
    assert_eq!(get(&server, "/readyz").await.status(), 200);
}

async fn sign_in(server: &TestServer, password: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://{}/api/v1/agents", server.rest_addr))
        .basic_auth("fleet-admin", Some(password))
        .send()
        .await
        .expect("get")
}
