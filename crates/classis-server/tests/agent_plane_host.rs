//! What the Agent plane does by the host a request was admitted as (ADR-0026, ADR-0013,
//! ADR-0022): the artifact a host may fetch, whose bucket a message draws on, and what is logged
//! when a session starts. Admission by token is the business of `enrolment.rs`; these serve the
//! plane with every request admitted as a host the test names ([`support::serve_admitted_as`]), so
//! that they decide what the plane does by the host and not how a host is admitted.

mod support;

use std::sync::Arc;

use classis_server::agent_rate::{AgentRate, Limits};
use classis_server::fleet::AppState;
use classis_server::packages::{PackageId, Platform};
use opamp::proto::{
    AgentCapabilities, AgentDescription, AgentToServer, ServerErrorResponseType, ServerToAgent,
};
use opamp::uid::InstanceUid;
use prost::Message as _;
use support::ManualClock;

const PROTOBUF: &str = "application/x-protobuf";

/// The Agent type the delivery tests release.
const OTELCOL: &str = "otelcol";

/// One host's connection to the Agent plane: every request it sends is admitted as that host.
struct Host {
    client: reqwest::Client,
    base: String,
}

impl Host {
    async fn post(&self, message: &AgentToServer) -> ServerToAgent {
        let response = self
            .client
            .post(format!("{}/v1/opamp", self.base))
            .header("content-type", PROTOBUF)
            .body(message.encode_to_vec())
            .send()
            .await
            .expect("post");
        assert_eq!(response.status(), 200);
        ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
    }

    /// `GET` of the download route for `otelcol@<version>`, with a raw query.
    async fn fetch(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .expect("fetch")
    }
}

/// A connection admitted as `host` to the Agent plane of `state`, or as none.
async fn admitted_as(state: &Arc<AppState>, host: Option<&str>) -> Host {
    let (addr, _) = support::serve_admitted_as(state.clone(), host).await;
    Host {
        client: reqwest::Client::new(),
        base: format!("http://{addr}"),
    }
}

/// A Server with package delivery armed, on a store in `dir`.
fn delivering(dir: &std::path::Path) -> Arc<AppState> {
    opamp::tls::install_ring_provider();
    Arc::new(support::state_on(dir))
}

/// A Server with package delivery armed and a rate limit of `burst` messages refilling one a
/// second, on a clock the test holds.
fn delivering_with_rate(dir: &std::path::Path, burst: u32) -> Arc<AppState> {
    opamp::tls::install_ring_provider();
    let limits = Limits {
        messages_per_sec: 1,
        burst,
    };
    Arc::new(
        support::state_on(dir)
            .with_agent_rate(Some(Arc::new(AgentRate::new(limits, ManualClock::new())))),
    )
}

/// A report of an Agent that accepts packages, an `otelcol` on linux/amd64.
fn package_report(uid: &InstanceUid) -> AgentToServer {
    let attr = opamp::attributes::string_attr;
    AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num: 1,
        agent_description: Some(AgentDescription {
            identifying_attributes: vec![attr("service.name", OTELCOL)],
            non_identifying_attributes: vec![attr("os.type", "linux"), attr("host.arch", "amd64")],
        }),
        capabilities: AgentCapabilities::ReportsStatus as u64
            | AgentCapabilities::AcceptsPackages as u64,
        ..Default::default()
    }
}

fn linux() -> Platform {
    Platform::new("linux", "amd64").expect("platform")
}

/// Uploads `artifact` as `otelcol@<version>` for linux/amd64, signs it, and puts it into the
/// `stable` channel that claims every `otelcol` — saved, released to nobody.
fn save(state: &AppState, version: &str, artifact: &[u8]) {
    let id = PackageId::new(OTELCOL, version).expect("id");
    let store = state.packages().expect("package delivery");
    store.create(&id).expect("create");
    store
        .put_entry(&id, &linux(), artifact.to_vec())
        .expect("entry");
    state
        .deployment_store()
        .expect("deployments")
        .put(
            "stable",
            [("service.name".to_string(), OTELCOL.to_string())].into(),
        )
        .expect("deployment");
    store
        .put_signature(&id, &linux(), vec![1; 64])
        .expect("signature");
    state
        .put_deployment_package("stable", &id, true)
        .expect("package");
}

fn artifact_path(version: &str) -> String {
    format!("/api/v1/packages/{OTELCOL}/{version}/file?os=linux&arch=amd64")
}

/// One Agent reports over `host`, and `version` is saved and released to it by the press.
async fn released_to(state: &AppState, host: &Host, version: &str, artifact: &[u8]) {
    host.post(&package_report(&InstanceUid([1; 16]))).await;
    save(state, version, artifact);
    assert_eq!(state.rollout_deployment("stable").expect("the press"), 1);
}

/// A host fetches the artifact released to the Agent that reported over it.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_host_fetches_the_artifact_offered_to_its_own_agent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering(dir.path());
    let host = admitted_as(&state, Some("h1")).await;
    released_to(&state, &host, "1.0.0", b"the-binary").await;
    let response = host.fetch(&artifact_path("1.0.0")).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("bytes").as_ref(),
        b"the-binary"
    );
}

/// Another host is answered `404` for what was released to one host's Agent alone.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_host_is_answered_404_for_an_artifact_offered_only_to_another_host() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering(dir.path());
    released_to(
        &state,
        &admitted_as(&state, Some("h1")).await,
        "1.0.0",
        b"the-binary",
    )
    .await;
    let other = admitted_as(&state, Some("h2")).await;
    other
        .post(&support::full_report(&InstanceUid([2; 16]), "collector", 1))
        .await;
    let response = other.fetch(&artifact_path("1.0.0")).await;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_ne!(
        response.bytes().await.expect("bytes").as_ref(),
        b"the-binary"
    );
}

/// Status, headers and body of a response, the `Date` header aside: it tells the time of the
/// answer, never what the store holds.
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

/// The same request is answered byte for byte alike whether the store holds nothing under it,
/// holds only an unsigned entry (ADR-0033), holds an artifact released to nobody, or holds one
/// released to another host's Agent.
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn an_artifact_not_offered_and_one_not_held_are_answered_alike() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering(dir.path());
    let other = admitted_as(&state, Some("h2")).await;
    other
        .post(&support::full_report(&InstanceUid([2; 16]), "collector", 1))
        .await;

    let not_held = answer(other.fetch(&artifact_path("1.0.0")).await).await;
    assert_eq!(not_held.0, 404);

    let unsigned = PackageId::new(OTELCOL, "1.0.0").expect("id");
    let store = state.packages().expect("package delivery");
    store.create(&unsigned).expect("create");
    store
        .put_entry(&unsigned, &linux(), b"the-binary".to_vec())
        .expect("entry");
    let only_unsigned = answer(other.fetch(&artifact_path("1.0.0")).await).await;
    assert_eq!(only_unsigned, not_held, "an unsigned entry");
    store.delete_set(&unsigned).expect("delete");

    let host = admitted_as(&state, Some("h1")).await;
    host.post(&package_report(&InstanceUid([1; 16]))).await;
    save(&state, "1.0.0", b"the-binary");
    let released_to_nobody = answer(other.fetch(&artifact_path("1.0.0")).await).await;
    assert_eq!(
        released_to_nobody, not_held,
        "an artifact released to nobody"
    );

    state.rollout_deployment("stable").expect("the press");
    let released_to_another = answer(other.fetch(&artifact_path("1.0.0")).await).await;
    assert_eq!(
        released_to_another, not_held,
        "an artifact of another host's Agent"
    );
    assert_eq!(
        host.fetch(&artifact_path("1.0.0")).await.status(),
        reqwest::StatusCode::OK
    );
}

/// A request admitted as no host speaks for no Agent — not even the one it reported, to which the
/// artifact was released.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_request_admitted_as_no_host_fetches_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering(dir.path());
    let nameless = admitted_as(&state, None).await;
    released_to(&state, &nameless, "1.0.0", b"the-binary").await;
    assert_eq!(
        nameless.fetch(&artifact_path("1.0.0")).await.status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

/// A malformed identity or Platform token is a `400`, decided before any offer is tested: the host
/// is offered nothing, which would be a `404`.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_malformed_token_is_answered_400_before_the_offer_is_tested() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering(dir.path());
    let other = admitted_as(&state, Some("h2")).await;
    for path in [
        "/api/v1/packages/otel@col/1.0.0/file?os=linux&arch=amd64",
        "/api/v1/packages/otelcol/1.0.0/file?os=lin%2Fux&arch=amd64",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux",
    ] {
        assert_eq!(
            other.fetch(path).await.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
}

/// Whether `reply` is the `Unavailable` of the rate limit or any other.
fn is_unavailable(reply: &ServerToAgent) -> bool {
    reply
        .error_response
        .as_ref()
        .is_some_and(|error| error.r#type == ServerErrorResponseType::Unavailable as i32)
}

/// A download takes a token from the bucket of the host it was admitted as — the bucket its
/// Agent's messages draw on.
/// Verifies: ADR-0026, ADR-0013
#[tokio::test]
async fn a_download_costs_a_token_of_the_hosts_bucket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering_with_rate(dir.path(), 2);
    let host = admitted_as(&state, Some("h1")).await;
    released_to(&state, &host, "1.0.0", b"the-binary").await;
    assert_eq!(
        host.fetch(&artifact_path("1.0.0")).await.status(),
        reqwest::StatusCode::OK
    );
    assert!(
        is_unavailable(&host.post(&package_report(&InstanceUid([1; 16]))).await),
        "the download took the host's second token"
    );
    assert_eq!(
        host.fetch(&artifact_path("1.0.0")).await.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS
    );
}

/// Two connections admitted as one host draw on one bucket, whichever of them a message comes
/// over; a connection of another host has a bucket of its own.
/// Verifies: ADR-0013
#[tokio::test]
async fn two_connections_of_one_host_share_a_bucket_and_two_hosts_do_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering_with_rate(dir.path(), 3);
    let first = admitted_as(&state, Some("h1")).await;
    let second = admitted_as(&state, Some("h1")).await;
    let report = |n: u8| support::full_report(&InstanceUid([n; 16]), "collector", 1);

    assert!(!is_unavailable(&first.post(&report(1)).await));
    assert!(!is_unavailable(&second.post(&report(2)).await));
    assert!(!is_unavailable(&first.post(&report(1)).await));
    assert!(is_unavailable(&first.post(&report(1)).await));
    assert!(
        is_unavailable(&second.post(&report(2)).await),
        "the second connection drew on the same, empty bucket"
    );

    let other = admitted_as(&state, Some("h2")).await;
    assert!(!is_unavailable(&other.post(&report(3)).await));
}

/// A writer the log goes to, for a test to read back.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// What was logged so far at `INFO` that names `event`.
    fn info(&self, event: &str) -> Vec<String> {
        String::from_utf8(self.0.lock().expect("log lock").clone())
            .expect("utf-8")
            .lines()
            .filter(|line| line.contains(" INFO ") && line.contains(event))
            .map(str::to_string)
            .collect()
    }
}

/// A WebSocket session is logged at `info` once the upgrade is accepted, and only then: a request
/// that merely carries `Upgrade: websocket`, which a peer can send at will, is refused by the
/// endpoint and leaves no `info` line (ADR-0022 clause 3). The test's runtime runs on one thread,
/// the Server's tasks included, so the subscriber set for it sees their events.
/// Verifies: ADR-0022
#[tokio::test]
async fn only_a_websocket_session_is_logged_at_info() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;

    let log = Captured::default();
    let _logging = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer({
                let log = log.clone();
                move || log.clone()
            })
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let state = delivering(dir.path());
    let (addr, _) = support::serve_admitted_as(state, Some("h1")).await;

    let http1 = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("client");
    for _ in 0..3 {
        let refused = http1
            .get(format!("http://{addr}/v1/opamp"))
            .header(reqwest::header::UPGRADE, "websocket")
            .send()
            .await
            .expect("send");
        assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    assert!(
        log.info("session.started").is_empty(),
        "a refused upgrade was logged at info: {:?}",
        log.info("")
    );

    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
        .await
        .expect("upgrade");
    let message = support::full_report(&InstanceUid::default(), "collector", 1);
    let framed = opamp::frame::encode_within(&message, usize::MAX).expect("frame");
    socket.send(Ws::Binary(framed.into())).await.expect("send");
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("a reply in time")
        {
            Some(Ok(Ws::Binary(_))) => break,
            Some(Ok(_)) => continue,
            other => panic!("the session ended early: {other:?}"),
        }
    }
    let started = log.info("session.started");
    assert_eq!(started.len(), 1, "{started:?}");
}
