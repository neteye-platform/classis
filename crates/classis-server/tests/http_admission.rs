//! The Agent plane behind a reverse proxy that terminates TLS: plain HTTP, and every request of
//! the Agent plane admitted by a bearer access token alone. The peer the throttle counts is the
//! address in `X-Forwarded-For`, on either plane.

mod support;

use std::sync::Arc;

use base64::Engine as _;
use classis_server::api::OperatorAuth;
use classis_server::config::RestAuthConfig;
use classis_server::enrolment::Enrolment;
use classis_server::throttle::{Limits, Throttle};
use opamp::uid::InstanceUid;
use prost::Message as _;

const OPAMP: &str = "/v1/opamp";

/// Limits no test here reaches unless it means to.
const GENEROUS: Limits = Limits {
    max_failures: 1000,
    window_secs: 60,
    backoff_secs: 60,
};

/// Serves the two planes as the binary does behind a proxy: the Agent plane admitting by bearer
/// token, its refusals counted by `agent_limits`; the Operator plane with Basic credentials and,
/// when given, a throttle.
async fn served_with(
    agent_limits: Limits,
    operator_throttle: Option<Arc<Throttle>>,
) -> support::TestServer {
    // What main() does at startup: without a process provider, reqwest refuses to build a client.
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    classis_server::fs::open_data_dir(&data, true).expect("the data directory");
    let records = classis_server::Records::Files(data);
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    let enrolment = Arc::new(
        Enrolment::on(
            &records,
            oauth_token::server::Lifetime::Never,
            clock.clone(),
            Arc::new(Throttle::new(agent_limits, clock)),
        )
        .expect("the enrolment"),
    );
    let state = Arc::new(support::state_on(dir.path()));
    let auth: RestAuthConfig = toml::from_str(&format!(
        "[basic_users]\nfleet-admin = {:?}\n",
        classis_server::credentials::hash_basic("secret").expect("hash"),
    ))
    .expect("parse");
    let mut operator_auth = OperatorAuth::from_config(&auth).expect("auth");
    if let Some(throttle) = operator_throttle {
        operator_auth = operator_auth.with_throttle(throttle);
    }
    let (addr, rest_addr) =
        support::serve_enrolled(state.clone(), enrolment, Some(operator_auth)).await;
    support::TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    }
}

async fn served(operator_throttle: Option<Arc<Throttle>>) -> support::TestServer {
    served_with(GENEROUS, operator_throttle).await
}

fn report() -> Vec<u8> {
    support::full_report(&InstanceUid::default(), "agent-1", 1).encode_to_vec()
}

async fn post(
    server: &support::TestServer,
    authorization: Option<&str>,
    forwarded_for: Option<&str>,
) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("http://{}{OPAMP}", server.addr))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report());
    if let Some(value) = authorization {
        request = request.header(reqwest::header::AUTHORIZATION, value);
    }
    if let Some(value) = forwarded_for {
        request = request.header("X-Forwarded-For", value);
    }
    request.send().await.expect("post")
}

/// Over plain HTTP no report is admitted without a token the Server issued: none at all, a token it
/// never issued, or another scheme is refused `401` with a Bearer challenge. Nothing admits an
/// unauthenticated Agent.
/// Verifies: G-17, Q-1
#[tokio::test]
async fn the_agent_plane_refuses_a_request_without_a_valid_token() {
    let served = served(None).await;
    for credential in [
        None,
        Some("Bearer a-random-string-the-server-never-issued"),
        Some("Basic Zm9vOmJhcg=="),
        Some("garbage"),
    ] {
        let response = post(&served, credential, None).await;
        assert_eq!(response.status(), 401, "{credential:?}");
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            challenge.starts_with("Bearer"),
            "{credential:?}: {challenge}"
        );
    }
}

/// The package download is on the same plane and is refused the same way: without a token nothing
/// is served, and the refusal does not say whether the package exists.
/// Verifies: Q-1
#[tokio::test]
async fn the_package_download_asks_for_a_token_too() {
    let served = served(None).await;
    let url = format!("http://{}/api/v1/packages/type/1.0.0/file", served.addr);
    let response = reqwest::Client::new().get(&url).send().await.expect("get");
    assert_eq!(response.status(), 401, "served without a token");
}

/// Refused tokens on the Agent plane are counted against the address in `X-Forwarded-For`: the
/// second refusal from one address puts it in back-off, and another address behind the same proxy
/// is still only refused.
#[tokio::test]
async fn agent_plane_refusals_are_counted_per_forwarded_address() {
    let served = served_with(
        Limits {
            max_failures: 2,
            window_secs: 60,
            backoff_secs: 60,
        },
        None,
    )
    .await;
    let unissued = Some("Bearer a-random-string-the-server-never-issued");
    for _ in 0..2 {
        assert_eq!(
            post(&served, unissued, Some("203.0.113.7")).await.status(),
            401
        );
    }
    let throttled = post(&served, unissued, Some("203.0.113.7")).await;
    assert_eq!(throttled.status(), 429, "that address is in back-off");
    assert!(throttled
        .headers()
        .contains_key(reqwest::header::RETRY_AFTER));
    assert_eq!(
        post(&served, unissued, Some("203.0.113.8")).await.status(),
        401,
        "another address is not"
    );
}

/// The address counted is the right-most entry — the one the proxy appends — so what the client
/// wrote to its left neither escapes the back-off nor puts another host's address in it.
#[tokio::test]
async fn the_address_counted_is_the_one_the_proxy_appended() {
    let served = served_with(
        Limits {
            max_failures: 2,
            window_secs: 60,
            backoff_secs: 60,
        },
        None,
    )
    .await;
    let unissued = Some("Bearer a-random-string-the-server-never-issued");
    for spoofed in ["198.51.100.1", "198.51.100.2"] {
        let forwarded = format!("{spoofed}, 203.0.113.7");
        assert_eq!(
            post(&served, unissued, Some(&forwarded)).await.status(),
            401
        );
    }
    assert_eq!(
        post(&served, unissued, Some("198.51.100.1, 203.0.113.7"))
            .await
            .status(),
        429,
        "the proxy's address is in back-off, whatever was written before it"
    );
    assert_eq!(
        post(&served, unissued, Some("203.0.113.7, 203.0.113.8"))
            .await
            .status(),
        401,
        "naming that address to its left does not put another's in back-off"
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
