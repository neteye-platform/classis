//! The Agent plane behind a reverse proxy that terminates TLS: plain HTTP, and no
//! authentication in the Server — it admits every request, and what admits an Agent lives in the
//! proxy. The peer the throttle counts is the address in `X-Forwarded-For`, on either plane.

mod support;

use std::sync::Arc;

use base64::Engine as _;
use classis_server::api::OperatorAuth;
use classis_server::config::RestAuthConfig;
use classis_server::throttle::{Limits, Throttle};
use classis_server::transport::Admission;
use opamp::uid::InstanceUid;
use prost::Message as _;

const OPAMP: &str = "/v1/opamp";

/// Serves the two planes as the binary does behind a proxy: the Agent plane with the authenticator
/// that admits every request, the Operator plane with Basic credentials and, when given, a throttle.
async fn served(throttle: Option<Arc<Throttle>>) -> support::TestServer {
    // What main() does at startup: without a process provider, reqwest refuses to build a client.
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(support::state_on(dir.path()));
    let admission =
        Admission::open().with_authenticator(Arc::new(classis_server::agent_auth::AdmitEveryone));
    let auth: RestAuthConfig = toml::from_str(&format!(
        "[basic_users]\nfleet-admin = {:?}\n",
        classis_server::credentials::hash_basic("secret").expect("hash"),
    ))
    .expect("parse");
    let mut operator_auth = OperatorAuth::from_config(&auth).expect("auth");
    if let Some(throttle) = throttle {
        operator_auth = operator_auth.with_throttle(throttle);
    }
    let (addr, rest_addr) =
        support::serve_guarded(state.clone(), admission, Some(operator_auth)).await;
    support::TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    }
}

fn report() -> Vec<u8> {
    support::full_report(&InstanceUid::default(), "agent-1", 1).encode_to_vec()
}

async fn post(server: &support::TestServer, authorization: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("http://{}{OPAMP}", server.addr))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report());
    if let Some(value) = authorization {
        request = request.header(reqwest::header::AUTHORIZATION, value);
    }
    request.send().await.expect("post")
}

/// A report is admitted over plain HTTP with no credential at all, and a credential it carries is
/// ignored, never refused: the Server authenticates no Agent.
#[tokio::test]
async fn the_agent_plane_admits_a_request_without_credentials() {
    let served = served(None).await;
    assert!(post(&served, None).await.status().is_success());
    for credential in [
        "Bearer a-random-string",
        "Bearer",
        "Basic Zm9vOmJhcg==",
        "garbage",
    ] {
        let response = post(&served, Some(credential)).await;
        assert!(
            response.status().is_success(),
            "{credential}: {}",
            response.status()
        );
    }
}

/// The package download is on the same plane and asks nothing either: the route answers for what
/// it was asked, not for who asks.
#[tokio::test]
async fn the_package_download_asks_nothing_either() {
    let served = served(None).await;
    let url = format!("http://{}/api/v1/packages/type/1.0.0/file", served.addr);
    let response = reqwest::Client::new().get(&url).send().await.expect("get");
    assert_ne!(response.status(), 401, "admitted without a credential");
    assert!(
        response.status().is_client_error(),
        "and nothing is offered there"
    );
}

fn basic(password: &str) -> String {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("fleet-admin:{password}"));
    format!("Basic {encoded}")
}

async fn get_agents(
    served: &support::TestServer,
    password: &str,
    forwarded_for: Option<&str>,
) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .get(format!("http://{}/api/v1/agents", served.rest_addr))
        .header(reqwest::header::AUTHORIZATION, basic(password));
    if let Some(forwarded_for) = forwarded_for {
        request = request.header("X-Forwarded-For", forwarded_for);
    }
    request.send().await.expect("get")
}

/// Failed sign-ins are counted against the address in `X-Forwarded-For`, from any source: the third
/// failure from one address puts that address in back-off, and another address behind the same
/// proxy is served. The header is trusted whoever sends it.
#[tokio::test]
async fn failures_are_counted_per_forwarded_address() {
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    let throttle = Arc::new(Throttle::new(
        Limits {
            max_failures: 3,
            window_secs: 60,
            backoff_secs: 60,
        },
        clock,
    ));
    let served = served(Some(throttle)).await;
    for _ in 0..3 {
        let refused = get_agents(&served, "wrong", Some("203.0.113.7")).await;
        assert_eq!(refused.status(), 401);
    }
    let throttled = get_agents(&served, "secret", Some("203.0.113.7")).await;
    assert_eq!(
        throttled.status(),
        429,
        "even the right password, from that address"
    );
    assert!(throttled
        .headers()
        .contains_key(reqwest::header::RETRY_AFTER));

    let other = get_agents(&served, "secret", Some("203.0.113.8")).await;
    assert!(other.status().is_success(), "another address is served");
    let chain = get_agents(&served, "secret", Some("garbage, 203.0.113.9, 10.0.0.1")).await;
    assert!(
        chain.status().is_success(),
        "the left-most valid address counts"
    );
    let again = get_agents(&served, "secret", Some("garbage, 203.0.113.7")).await;
    assert_eq!(
        again.status(),
        429,
        "an invalid entry is skipped, the first valid one counts"
    );
}

/// Without the header the address of the connection is the peer, as before.
#[tokio::test]
async fn without_the_header_the_connection_is_the_peer() {
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    let throttle = Arc::new(Throttle::new(
        Limits {
            max_failures: 2,
            window_secs: 60,
            backoff_secs: 60,
        },
        clock,
    ));
    let served = served(Some(throttle)).await;
    for _ in 0..2 {
        assert_eq!(get_agents(&served, "wrong", None).await.status(), 401);
    }
    assert_eq!(get_agents(&served, "secret", None).await.status(), 429);
}
