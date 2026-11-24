//! A host enrols with its Space's key and is admitted by a bearer token: the routes `/v1/enrol` and
//! `/v1/token`, the admission of `/v1/opamp` on both transports and of the package download, the
//! end of a session whose token is replaced, the ownership of an `instance_uid`, and the
//! per-address back-off. Over the plaintext loopback, since TLS terminates elsewhere,
//! but for the one test that serves the Agent plane over TLS to show that it asks for no client
//! certificate.

mod support;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use classis_server::enrolment::Enrolment;
use classis_server::fleet::AppState;
use classis_server::packages::{PackageId, Platform};
use classis_server::throttle::{Limits, Throttle};
use futures_util::{SinkExt, StreamExt};
use opamp::frame;
use opamp::proto::{
    AgentCapabilities, AgentDescription, AgentToServer, ServerErrorResponseType, ServerToAgent,
};
use opamp::uid::InstanceUid;
use prost::Message as _;
use sha2::Digest as _;
use support::ManualClock;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;

const PROTOBUF: &str = "application/x-protobuf";
const OTELCOL: &str = "otelcol";
const LIMIT: usize = frame::DEFAULT_MAX_MESSAGE_SIZE;

/// Three refused authentications put an address in back-off for five minutes.
const LIMITS: Limits = Limits {
    max_failures: 3,
    window_secs: 60,
    backoff_secs: 300,
};

/// So many refusals that no test not about the back-off meets it.
const GENEROUS: Limits = Limits {
    max_failures: u32::MAX,
    window_secs: 60,
    backoff_secs: 300,
};

/// One Server with a Space called `lab`, on a clock the test moves.
struct Rig {
    addr: SocketAddr,
    rest_addr: SocketAddr,
    state: Arc<AppState>,
    enrolment: Arc<Enrolment>,
    clock: Arc<ManualClock>,
    /// The Space's key.
    key: String,
    dir: tempfile::TempDir,
}

struct Setup {
    lifetime: oauth_token::server::Lifetime,
    limits: Limits,
    operator_auth: Option<classis_server::api::OperatorAuth>,
    agent_rate: Option<classis_server::agent_rate::Limits>,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            lifetime: oauth_token::server::Lifetime::Never,
            limits: GENEROUS,
            operator_auth: None,
            agent_rate: None,
        }
    }
}

fn real_now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_millis(),
    )
    .expect("fits")
}

async fn rig(setup: Setup) -> Rig {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    classis_server::fs::open_data_dir(&data, true).expect("the data directory");
    let records = classis_server::Records::Files(data);
    // The clock starts at the real time: a token's expiry is made from it by the token endpoint.
    let clock = Arc::new(ManualClock(AtomicU64::new(real_now_ms())));
    let enrolment = Arc::new(
        Enrolment::on(
            &records,
            setup.lifetime,
            clock.clone(),
            Arc::new(Throttle::new(setup.limits, clock.clone())),
        )
        .expect("the enrolment"),
    );
    let key = enrolment
        .spaces()
        .create("lab")
        .expect("a space")
        .to_string();
    let state = Arc::new(
        support::state_on(dir.path()).with_agent_rate(setup.agent_rate.map(|limits| {
            Arc::new(classis_server::agent_rate::AgentRate::new(
                limits,
                clock.clone(),
            ))
        })),
    );
    let (addr, rest_addr) =
        support::serve_enrolled(state.clone(), enrolment.clone(), setup.operator_auth).await;
    Rig {
        addr,
        rest_addr,
        state,
        enrolment,
        clock,
        key,
        dir,
    }
}

impl Rig {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// A host registered and given its first token, through the real OAuth clients.
    async fn enrol(&self) -> Host {
        let http = reqwest::Client::new();
        let registered =
            oauth_registration::client::register(&http, self.url("/v1/enrol"), &self.key)
                .await
                .expect("enrolled");
        let mut host = Host {
            client_id: registered.client_id,
            secret: registered.client_secret.to_string(),
            token: String::new(),
        };
        self.renew(&mut host).await;
        host
    }

    /// Asks for a new token for `host`, which replaces the one it holds.
    async fn renew(&self, host: &mut Host) -> Option<u64> {
        let issued = oauth_token::client::request_token(
            &reqwest::Client::new(),
            self.url("/v1/token"),
            &host.client_id,
            &host.secret,
        )
        .await
        .expect("a token");
        host.token = issued.access_token.to_string();
        issued.expires_in
    }

    /// One plain-HTTP OpAMP exchange under `token`.
    async fn post(&self, token: &str, message: &AgentToServer) -> reqwest::Response {
        reqwest::Client::new()
            .post(self.url("/v1/opamp"))
            .header("content-type", PROTOBUF)
            .bearer_auth(token)
            .body(message.encode_to_vec())
            .send()
            .await
            .expect("post")
    }

    /// A report that is answered, decoded.
    async fn report(&self, token: &str, message: &AgentToServer) -> ServerToAgent {
        let response = self.post(token, message).await;
        assert_eq!(response.status(), 200);
        ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
    }

    async fn fetch(&self, token: Option<&str>, path: &str) -> reqwest::Response {
        let mut request = reqwest::Client::new().get(self.url(path));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().await.expect("fetch")
    }

    /// The fleet's view of the Agent `uid`, as the REST API serializes it.
    fn view_of(&self, uid: &InstanceUid) -> serde_json::Value {
        let view = self
            .state
            .snapshot()
            .into_iter()
            .find(|agent| agent.instance_uid == uid.to_string())
            .expect("the Agent is in the fleet");
        serde_json::to_value(view).expect("the view serializes")
    }

    /// The `host` the fleet records for the Agent `uid`.
    fn host_of(&self, uid: &InstanceUid) -> Option<String> {
        self.state
            .snapshot()
            .into_iter()
            .find(|agent| agent.instance_uid == uid.to_string())
            .map(|agent| agent.host)
    }
}

struct Host {
    client_id: String,
    secret: String,
    token: String,
}

fn report(uid: &InstanceUid, sequence_num: u64) -> AgentToServer {
    support::full_report(uid, "collector", sequence_num)
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn websocket(
    rig: &Rig,
    token: Option<&str>,
) -> Result<Socket, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{}/v1/opamp", rig.addr)
        .into_client_request()
        .expect("request");
    if let Some(token) = token {
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("header"),
        );
    }
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(socket, _)| socket)
}

async fn send(socket: &mut Socket, message: &AgentToServer) {
    socket
        .send(Message::Binary(
            frame::encode_within(message, LIMIT)
                .expect("a frame")
                .into(),
        ))
        .await
        .expect("send");
}

async fn recv(socket: &mut Socket) -> ServerToAgent {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("a message within five seconds")
            .expect("an open connection")
            .expect("a frame");
        if let Message::Binary(data) = message {
            return frame::decode(&data, LIMIT).expect("decode");
        }
    }
}

/// The status and `WWW-Authenticate` of a WebSocket upgrade that was refused.
fn refused(result: Result<Socket, tokio_tungstenite::tungstenite::Error>) -> (u16, Option<String>) {
    match result {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => (
            response.status().as_u16(),
            response
                .headers()
                .get("www-authenticate")
                .map(|value| value.to_str().expect("ascii").to_string()),
        ),
        Ok(_) => panic!("the upgrade was accepted"),
        Err(other) => panic!("the upgrade failed without an answer: {other}"),
    }
}

fn challenge(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().expect("ascii").to_string())
}

const NOT_ADMITTED: &str = "Bearer error=\"invalid_token\"";

// ---- Enrolment ----

/// A valid key enrols at once; an unknown key, a key of an unknown Space and text that is no key
/// do not; a rotated key stops enrolling and the new one enrols, and a host enrolled under the old
/// key keeps its client and its token.
#[tokio::test]
async fn a_valid_key_enrols_and_an_unknown_or_replaced_key_does_not() {
    let rig = rig(Setup::default()).await;
    let http = reqwest::Client::new();
    let register = |key: String| {
        let (http, url) = (http.clone(), rig.url("/v1/enrol"));
        async move { oauth_registration::client::register(&http, url, &key).await }
    };

    let registered = register(rig.key.clone()).await.expect("a valid key enrols");
    assert_eq!(registered.fields["space"], "lab", "the Space the key named");
    uuid_v7(&registered.client_id);

    let secret = "A".repeat(43);
    for (what, key) in [
        ("another secret", format!("cle1_lab_{secret}")),
        ("an unknown space", format!("cle1_nowhere_{secret}")),
        ("no key", "a-token-of-no-kind".to_string()),
    ] {
        let oauth_registration::client::Error::Rejected(rejection) =
            register(key).await.expect_err(what)
        else {
            panic!("{what}: not a refusal");
        };
        assert_eq!(rejection.status, 401, "{what}");
        assert_eq!(
            rejection.challenges[0].error(),
            Some("invalid_token"),
            "{what}"
        );
    }

    let enrolled = rig.enrol().await;
    let old_key = rig.key.clone();
    let new_key = rig.enrolment.spaces().rotate("lab").expect("rotated");
    assert_ne!(*new_key, old_key);
    let oauth_registration::client::Error::Rejected(rejection) = register(old_key)
        .await
        .expect_err("a replaced key enrols nothing")
    else {
        panic!("a replaced key: not a refusal");
    };
    assert_eq!(rejection.status, 401, "a replaced key");
    assert_eq!(
        rejection.challenges[0].error(),
        Some("invalid_token"),
        "a replaced key"
    );
    let again = register(new_key.to_string())
        .await
        .expect("the new key enrols");
    assert_eq!(again.fields["space"], "lab");
    assert_eq!(
        rig.post(&enrolled.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200,
        "a host enrolled under the old key keeps its token"
    );
}

fn uuid_v7(id: &str) {
    let bytes = id.as_bytes();
    assert_eq!(id.len(), 36, "{id}");
    assert_eq!(bytes[14], b'7', "a UUID version 7: {id}");
}

// ---- Tokens ----

/// A new token makes the previous one invalid, on every route.
#[tokio::test]
async fn a_new_token_makes_the_previous_one_invalid() {
    let rig = rig(Setup::default()).await;
    let mut host = rig.enrol().await;
    let first = host.token.clone();
    assert_eq!(
        rig.post(&first, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200
    );
    rig.renew(&mut host).await;
    assert_ne!(first, host.token);

    let response = rig.post(&first, &report(&InstanceUid::default(), 1)).await;
    assert_eq!(response.status(), 401);
    assert_eq!(challenge(&response).as_deref(), Some(NOT_ADMITTED));
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200
    );
}

/// With `token_lifetime_secs` unset a token has no `expires_in`, and with a finite one it has.
#[tokio::test]
async fn a_token_expires_in_what_the_lifetime_says_and_never_by_default() {
    let never = rig(Setup::default()).await;
    let mut host = never.enrol().await;
    assert_eq!(
        never.renew(&mut host).await,
        None,
        "no expires_in by default"
    );
    never
        .clock
        .advance(Duration::from_secs(10 * 365 * 24 * 3600));
    assert_eq!(
        never
            .post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200,
        "a token that never expires, after ten years"
    );

    let finite = rig(Setup {
        lifetime: oauth_token::server::Lifetime::Seconds(60.try_into().expect("non-zero")),
        ..Setup::default()
    })
    .await;
    let mut host = finite.enrol().await;
    assert_eq!(finite.renew(&mut host).await, Some(60));
}

/// An expired token and a replaced one are refused on `/v1/opamp` over both transports and on the
/// download route, each time with `invalid_token`.
#[tokio::test]
async fn an_expired_or_replaced_token_is_refused_on_every_admitted_route() {
    let rig = rig(Setup {
        lifetime: oauth_token::server::Lifetime::Seconds(60.try_into().expect("non-zero")),
        ..Setup::default()
    })
    .await;
    let path = artifact_path("1.0.0");
    let mut host = rig.enrol().await;
    let replaced = host.token.clone();
    rig.renew(&mut host).await;
    let other = rig.enrol().await;

    // Admitted before it expires, on all three.
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200
    );
    drop(websocket(&rig, Some(&host.token)).await.expect("admitted"));
    assert_ne!(rig.fetch(Some(&host.token), &path).await.status(), 401);

    let refused_everywhere = |token: String| {
        let (rig, path) = (&rig, path.clone());
        async move {
            let response = rig.post(&token, &report(&InstanceUid::default(), 1)).await;
            assert_eq!(response.status(), 401, "plain HTTP");
            assert_eq!(challenge(&response).as_deref(), Some(NOT_ADMITTED));
            assert_eq!(
                refused(websocket(rig, Some(&token)).await),
                (401, Some(NOT_ADMITTED.to_string())),
                "WebSocket"
            );
            let response = rig.fetch(Some(&token), &path).await;
            assert_eq!(response.status(), 401, "download");
            assert_eq!(challenge(&response).as_deref(), Some(NOT_ADMITTED));
        }
    };
    refused_everywhere(replaced).await;

    rig.clock.advance(Duration::from_secs(120));
    refused_everywhere(host.token.clone()).await;
    refused_everywhere(other.token.clone()).await;
}

/// An open WebSocket session outlives its token's expiry, and is closed with 1008 when the token is
/// replaced; another host's session is not touched.
#[tokio::test]
async fn an_open_session_outlives_its_tokens_expiry_and_ends_with_1008_when_it_is_replaced() {
    let rig = rig(Setup {
        lifetime: oauth_token::server::Lifetime::Seconds(60.try_into().expect("non-zero")),
        ..Setup::default()
    })
    .await;
    let mut host = rig.enrol().await;
    let mut bystander = rig.enrol().await;
    let mut socket = websocket(&rig, Some(&host.token)).await.expect("admitted");
    let mut neighbour = websocket(&rig, Some(&bystander.token))
        .await
        .expect("admitted");
    let (uid, other_uid) = (InstanceUid::default(), InstanceUid::default());
    send(&mut socket, &report(&uid, 1)).await;
    recv(&mut socket).await;
    send(&mut neighbour, &report(&other_uid, 1)).await;
    recv(&mut neighbour).await;

    rig.clock.advance(Duration::from_secs(600));
    assert_eq!(
        rig.post(&host.token, &report(&uid, 2)).await.status(),
        401,
        "the token has expired for a new exchange"
    );
    send(&mut socket, &support::compressed_report(&uid, 2)).await;
    let reply = recv(&mut socket).await;
    assert_eq!(
        reply.instance_uid,
        uid.as_bytes(),
        "the open session lives on"
    );

    rig.renew(&mut host).await;
    let closed = loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("the session is ended within five seconds")
        {
            Some(Ok(Message::Close(frame))) => break frame,
            Some(Ok(_)) => continue,
            other => panic!("the session was not closed with a frame: {other:?}"),
        }
    };
    assert_eq!(
        closed.expect("a close frame").code,
        CloseCode::Policy,
        "1008"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), neighbour.next())
            .await
            .is_err(),
        "another host's session goes on"
    );
    send(&mut neighbour, &support::compressed_report(&other_uid, 2)).await;
    recv(&mut neighbour).await;
    rig.renew(&mut bystander).await;
}

/// The Agent plane completes an OpAMP exchange on both transports with a bearer token and no
/// client certificate: the Server speaks plain HTTP and reads none.
#[tokio::test]
async fn the_agent_plane_completes_an_exchange_without_a_client_certificate() {
    let rig = rig(Setup::default()).await;
    let host = rig.enrol().await;
    let uid = InstanceUid::default();
    let reply = rig.report(&host.token, &report(&uid, 1)).await;
    assert_eq!(reply.instance_uid, uid.as_bytes());

    let mut socket = websocket(&rig, Some(&host.token)).await.expect("admitted");
    let socket_uid = InstanceUid::default();
    send(&mut socket, &report(&socket_uid, 1)).await;
    assert_eq!(recv(&mut socket).await.instance_uid, socket_uid.as_bytes());
}

// ---- What is stored ----

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files
}

fn sha256_hex(text: &str) -> String {
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// A client's persisted record holds the hash of its secret and of its one active token, and
/// nothing that could be presented; a new token overwrites the hash of the old.
#[tokio::test]
async fn a_clients_record_holds_only_hashes_of_its_secret_and_its_one_active_token() {
    let rig = rig(Setup::default()).await;
    let mut host = rig.enrol().await;
    let first_token = host.token.clone();
    rig.renew(&mut host).await;

    let records = files_under(&rig.dir.path().join("data").join("clients"));
    assert_eq!(records.len(), 1, "one client, one file: {records:?}");
    let stored = std::fs::read_to_string(&records[0]).expect("the record");
    assert!(stored.contains(&host.client_id));
    assert!(
        stored.contains(&sha256_hex(&host.secret)),
        "the secret's hash"
    );
    assert!(
        stored.contains(&sha256_hex(&host.token)),
        "the active token's hash"
    );
    assert!(
        !stored.contains(&sha256_hex(&first_token)),
        "a replaced token's hash is gone"
    );
    for (what, value) in [
        ("the client secret", &host.secret),
        ("the active token", &host.token),
        ("the replaced token", &first_token),
        ("the enrolment key", &rig.key),
    ] {
        assert!(!stored.contains(value.as_str()), "{what} is in the record");
    }
    // The key never reaches a client's record, nor the Agent records.
    for file in files_under(&rig.dir.path().join("data").join("clients"))
        .into_iter()
        .chain(files_under(&rig.dir.path().join("fleet-configs")))
    {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        assert!(!text.contains(&rig.key), "{}", file.display());
    }
}

// ---- Who an Agent belongs to ----

/// An Agent's record names the client it reported under, in memory and on disk, whichever
/// transport it came over.
#[tokio::test]
async fn an_agents_record_names_the_client_it_reported_under() {
    let rig = rig(Setup::default()).await;
    let host = rig.enrol().await;
    let over_http = InstanceUid::default();
    rig.report(&host.token, &report(&over_http, 1)).await;
    let over_websocket = InstanceUid::default();
    let mut socket = websocket(&rig, Some(&host.token)).await.expect("admitted");
    send(&mut socket, &report(&over_websocket, 1)).await;
    recv(&mut socket).await;

    for uid in [&over_http, &over_websocket] {
        assert_eq!(rig.host_of(uid).as_deref(), Some(host.client_id.as_str()));
    }
    rig.state.flush_agents();
    let on_disk = files_under(&rig.dir.path().join("fleet-configs"))
        .iter()
        .filter_map(|file| std::fs::read_to_string(file).ok())
        .filter(|text| text.contains(&host.client_id))
        .count();
    assert_eq!(on_disk, 2, "each Agent's persisted record names the client");
}

/// A report for an `instance_uid` recorded under another client is refused outright, on both
/// transports: it is answered with an error, the reporter is adopted under no identity, nothing is
/// recorded for it, and the record of the Agent it claimed is untouched.
#[tokio::test]
async fn a_report_for_an_instance_uid_recorded_under_another_client_is_refused() {
    let rig = rig(Setup::default()).await;
    let (owner, claimant) = (rig.enrol().await, rig.enrol().await);
    let uid = InstanceUid::default();
    let own = rig.report(&owner.token, &report(&uid, 1)).await;
    assert!(own.agent_identification.is_none());
    let owned = rig.view_of(&uid);
    assert_eq!(owned["host"], owner.client_id.as_str());

    let refused_with_an_error = |reply: ServerToAgent| {
        assert!(
            reply.agent_identification.is_none(),
            "no identity is offered"
        );
        assert_eq!(
            reply.error_response.expect("an error").r#type,
            ServerErrorResponseType::BadRequest as i32
        );
    };

    refused_with_an_error(rig.report(&claimant.token, &report(&uid, 7)).await);
    // Not even with the request to be given an identity of its own.
    let mut asking = report(&uid, 8);
    asking.flags = opamp::proto::AgentToServerFlags::RequestInstanceUid as u64;
    refused_with_an_error(rig.report(&claimant.token, &asking).await);
    assert_eq!(
        rig.state.snapshot().len(),
        1,
        "nothing is recorded for the reporter"
    );
    assert_eq!(rig.view_of(&uid), owned, "the owner's record is untouched");

    // The same refusal on the other transport.
    let mut socket = websocket(&rig, Some(&claimant.token))
        .await
        .expect("admitted");
    send(&mut socket, &report(&uid, 9)).await;
    refused_with_an_error(recv(&mut socket).await);
    assert_eq!(
        rig.state.snapshot().len(),
        1,
        "nothing is recorded for the reporter"
    );
    assert_eq!(rig.view_of(&uid), owned, "the owner's record is untouched");

    // The owner is not locked out of its own Agent by the attempts.
    let again = rig.report(&owner.token, &report(&uid, 2)).await;
    assert!(again.error_response.is_none());
}

/// A client owns at most 256 `instance_uid`s: the 257th is refused, the 256 it has keep reporting,
/// and another client is not held back by it.
#[tokio::test]
async fn a_clients_257th_instance_uid_is_refused() {
    let rig = rig(Setup::default()).await;
    let (busy, other) = (rig.enrol().await, rig.enrol().await);
    let uid = |n: u16| {
        let mut bytes = [9u8; 16];
        bytes[..2].copy_from_slice(&n.to_be_bytes());
        InstanceUid(bytes)
    };
    for n in 0..256 {
        let reply = rig.report(&busy.token, &report(&uid(n), 1)).await;
        assert!(reply.error_response.is_none(), "uid {n}");
    }
    let refused = rig.report(&busy.token, &report(&uid(256), 1)).await;
    assert_eq!(
        refused.error_response.expect("refused").r#type,
        ServerErrorResponseType::BadRequest as i32
    );
    assert_eq!(rig.host_of(&uid(256)), None, "no record was made");
    let known = rig
        .report(&busy.token, &support::compressed_report(&uid(0), 2))
        .await;
    assert!(
        known.error_response.is_none(),
        "an Agent it owns keeps reporting"
    );
    let reply = rig.report(&other.token, &report(&uid(300), 1)).await;
    assert!(
        reply.error_response.is_none(),
        "another client has its own count"
    );
}

// ---- Package downloads ----

fn artifact_path(version: &str) -> String {
    format!("/api/v1/packages/{OTELCOL}/{version}/file?os=linux&arch=amd64")
}

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

/// Offers the package `otelcol` 1.0.0 to every Agent of type `otelcol` that has reported by now.
fn offer_otelcol(rig: &Rig) {
    let id = PackageId::new(OTELCOL, "1.0.0").expect("id");
    let platform = Platform::new("linux", "amd64").expect("platform");
    let packages = rig.state.packages().expect("package delivery");
    packages.create(&id).expect("create");
    packages
        .put_entry(&id, &platform, b"the-binary".to_vec())
        .expect("entry");
    packages
        .put_signature(
            &id,
            &platform,
            support::test_root().1.sign_artifact(
                OTELCOL,
                "1.0.0",
                &<sha2::Sha256 as sha2::Digest>::digest(b"the-binary"),
            ),
        )
        .expect("signature");
    rig.state
        .deployment_store()
        .expect("deployments")
        .put(
            "stable",
            [("service.name".to_string(), OTELCOL.to_string())].into(),
        )
        .expect("deployment");
    rig.state
        .put_deployment_package("stable", &id, true)
        .expect("package");
    assert_eq!(rig.state.rollout_deployment("stable").expect("rollout"), 1);
}

/// A host downloads the artifact offered to one of its own Agents, and nothing offered only to
/// another host's; with no token, or a bad one, it downloads nothing.
#[tokio::test]
async fn a_host_downloads_only_what_its_own_agents_are_offered() {
    let rig = rig(Setup::default()).await;
    let (owner, stranger) = (rig.enrol().await, rig.enrol().await);
    rig.report(&owner.token, &package_report(&InstanceUid([1; 16])))
        .await;
    rig.report(&stranger.token, &report(&InstanceUid([2; 16]), 1))
        .await;

    offer_otelcol(&rig);

    let path = artifact_path("1.0.0");
    let response = rig.fetch(Some(&owner.token), &path).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.expect("bytes").as_ref(),
        b"the-binary"
    );
    assert_eq!(rig.fetch(Some(&stranger.token), &path).await.status(), 404);
    assert_eq!(rig.fetch(None, &path).await.status(), 401);
    assert_eq!(
        rig.fetch(Some("not-a-token-of-ours"), &path).await.status(),
        401
    );
}

/// A member over its rate is answered `429` with `Retry-After: 30` and not served the artifact;
/// once its bucket refills the download is served again, and the refusals counted no failure
/// toward the Agent plane's back-off, which here backs off after a single one: the host is admitted
/// by its token throughout.
#[tokio::test]
async fn a_download_past_the_limit_is_answered_429_after_thirty_seconds() {
    let rig = rig(Setup {
        limits: Limits {
            max_failures: 1,
            window_secs: 60,
            backoff_secs: 300,
        },
        agent_rate: Some(classis_server::agent_rate::Limits {
            messages_per_sec: 1,
            burst: 1,
        }),
        ..Setup::default()
    })
    .await;
    let host = rig.enrol().await;
    rig.report(&host.token, &package_report(&InstanceUid([1; 16])))
        .await;
    offer_otelcol(&rig);
    let path = artifact_path("1.0.0");
    // The report took the bucket's one token.
    rig.clock.advance(Duration::from_secs(1));

    assert_eq!(rig.fetch(Some(&host.token), &path).await.status(), 200);
    for _ in 0..2 {
        let refused = rig.fetch(Some(&host.token), &path).await;
        assert_eq!(refused.status(), 429);
        assert_eq!(
            refused
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30"),
            "the rate limit's 30 s, never the failure back-off's 300"
        );
        assert_ne!(refused.bytes().await.expect("body").as_ref(), b"the-binary");
    }
    rig.clock.advance(Duration::from_secs(1));
    let served = rig.fetch(Some(&host.token), &path).await;
    assert_eq!(
        served.status(),
        200,
        "no back-off for a member over its rate"
    );
    assert_eq!(served.bytes().await.expect("bytes").as_ref(), b"the-binary");
}

/// A download that is not offered to the host is answered `404` and counts for nothing toward the
/// Agent plane's back-off, which here backs off after one refused authentication: the host is
/// still admitted after two such fetches, while a refused credential does count.
#[tokio::test]
async fn a_refused_fetch_is_no_failure_the_throttle_counts() {
    let rig = rig(Setup {
        limits: Limits {
            max_failures: 1,
            window_secs: 60,
            backoff_secs: 300,
        },
        ..Setup::default()
    })
    .await;
    let (owner, other) = (rig.enrol().await, rig.enrol().await);
    rig.report(&owner.token, &package_report(&InstanceUid([1; 16])))
        .await;
    rig.report(&other.token, &report(&InstanceUid([2; 16]), 1))
        .await;
    offer_otelcol(&rig);
    let path = artifact_path("1.0.0");

    for _ in 0..2 {
        assert_eq!(rig.fetch(Some(&other.token), &path).await.status(), 404);
    }
    // Past the back-off's one failure, the same address is still admitted.
    assert_eq!(rig.fetch(Some(&other.token), &path).await.status(), 404);
    rig.report(&other.token, &report(&InstanceUid([2; 16]), 2))
        .await;
    assert_eq!(rig.fetch(Some(&owner.token), &path).await.status(), 200);

    // A refused credential does count, so the back-off above was armed.
    assert_eq!(
        rig.fetch(Some("not-a-token-of-ours"), &path).await.status(),
        401
    );
    assert_eq!(rig.fetch(Some(&owner.token), &path).await.status(), 429);
}

/// A message and a download both draw on the bucket of the client that was admitted, which is not
/// another client's.
#[tokio::test]
async fn messages_and_downloads_are_counted_for_the_admitted_client() {
    let rig = rig(Setup {
        agent_rate: Some(classis_server::agent_rate::Limits {
            messages_per_sec: 1,
            burst: 3,
        }),
        ..Setup::default()
    })
    .await;
    let (host, other) = (rig.enrol().await, rig.enrol().await);
    let is_unavailable = |reply: &ServerToAgent| {
        reply
            .error_response
            .as_ref()
            .is_some_and(|error| error.r#type == ServerErrorResponseType::Unavailable as i32)
    };
    let uid = InstanceUid::default();
    assert!(!is_unavailable(
        &rig.report(&host.token, &report(&uid, 1)).await
    ));
    let download = rig.fetch(Some(&host.token), &artifact_path("1.0.0")).await;
    assert_ne!(download.status(), 429, "the download took the second token");
    assert!(!is_unavailable(
        &rig.report(&host.token, &report(&uid, 2)).await
    ));
    assert!(
        is_unavailable(&rig.report(&host.token, &report(&uid, 3)).await),
        "the bucket of the admitted client is empty"
    );
    assert_eq!(
        rig.fetch(Some(&host.token), &artifact_path("1.0.0"))
            .await
            .status(),
        429
    );
    assert!(
        !is_unavailable(
            &rig.report(&other.token, &report(&InstanceUid::default(), 1))
                .await
        ),
        "another client has a bucket of its own"
    );
}

// ---- The challenges ----

#[derive(Clone, Copy, Debug)]
enum Route {
    Enrol,
    OpampPost,
    OpampUpgrade,
    Download,
}

const ROUTES: [Route; 4] = [
    Route::Enrol,
    Route::OpampPost,
    Route::OpampUpgrade,
    Route::Download,
];

impl Route {
    /// A request to this route with exactly these `Authorization` headers and this query.
    fn request(self, rig: &Rig, authorization: &[&str], query: &str) -> reqwest::RequestBuilder {
        let http = reqwest::Client::builder()
            .http1_only()
            .build()
            .expect("client");
        let mut request = match self {
            Route::Enrol => http
                .post(rig.url(&format!("/v1/enrol{query}")))
                .header("content-type", "application/json")
                .body(r#"{"grant_types":["client_credentials"]}"#),
            Route::OpampPost => http
                .post(rig.url(&format!("/v1/opamp{query}")))
                .header("content-type", PROTOBUF)
                .body(AgentToServer::default().encode_to_vec()),
            Route::OpampUpgrade => http
                .get(rig.url(&format!("/v1/opamp{query}")))
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
            Route::Download => http.get(rig.url(&format!(
                "/api/v1/packages/{OTELCOL}/1.0.0/file{}",
                if query.is_empty() {
                    "?os=linux&arch=amd64".to_string()
                } else {
                    format!("{query}&os=linux&arch=amd64")
                }
            ))),
        };
        for value in authorization {
            request = request.header("authorization", *value);
        }
        request
    }
}

/// The challenges: `realm="fleet"` with no error for absent or unsupported authentication,
/// `invalid_token` for a malformed or unknown credential, `invalid_request` for two methods — on
/// the registration, OpAMP (both transports) and download routes alike.
#[tokio::test]
async fn the_routes_send_the_bearer_challenges_of_clauses_2_and_6() {
    let rig = rig(Setup::default()).await;
    let unknown = format!("Bearer {}", "A".repeat(43));
    let cases: [(&str, Vec<&str>, &str, u16, &str); 8] = [
        ("no credential", vec![], "", 401, "Bearer realm=\"fleet\""),
        (
            "another scheme",
            vec!["Basic dXNlcjpwYXNz"],
            "",
            401,
            "Bearer realm=\"fleet\"",
        ),
        ("no token", vec!["Bearer"], "", 401, NOT_ADMITTED),
        (
            "a malformed token",
            vec!["Bearer ***"],
            "",
            401,
            NOT_ADMITTED,
        ),
        (
            "an unknown token",
            vec![&unknown[..]],
            "",
            401,
            NOT_ADMITTED,
        ),
        (
            "two Authorization headers",
            vec!["Bearer one", "Bearer two"],
            "",
            400,
            "Bearer error=\"invalid_request\"",
        ),
        (
            "a token in the query as well",
            vec!["Bearer one"],
            "?access_token=two",
            400,
            "Bearer error=\"invalid_request\"",
        ),
        (
            "a token in the query alone",
            vec![],
            "?access_token=two",
            401,
            "Bearer realm=\"fleet\"",
        ),
    ];
    for route in ROUTES {
        for (what, authorization, query, status, expected) in &cases {
            let response = route
                .request(&rig, authorization, query)
                .send()
                .await
                .expect("send");
            assert_eq!(response.status(), *status, "{route:?}: {what}");
            assert_eq!(
                challenge(&response).as_deref(),
                Some(*expected),
                "{route:?}: {what}"
            );
        }
    }
}

/// The Agent plane built as the binary builds it — from an enrolment and nothing else, no rate
/// limit, no back-off, no package offering — answers a request without a credential at the OpAMP
/// endpoint (both transports) and at the download with `401` and the realm's challenge: there is no
/// open path, whatever else the state carries.
#[tokio::test]
async fn the_agent_plane_as_built_for_production_has_no_open_path() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    classis_server::fs::open_data_dir(&data, true).expect("the data directory");
    let enrolment = Arc::new(
        Enrolment::on(
            &classis_server::Records::Files(data),
            oauth_token::server::Lifetime::Never,
            ManualClock::new(),
            Arc::new(Throttle::new(GENEROUS, ManualClock::new())),
        )
        .expect("the enrolment"),
    );
    let state = Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("state"));
    let (addr, _) = support::serve_enrolled(state.clone(), enrolment, None).await;
    let http = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("client");
    let at = |path: &str| format!("http://{addr}{path}");
    let attempts = [
        (
            "an OpAMP exchange",
            http.post(at("/v1/opamp"))
                .header("content-type", PROTOBUF)
                .body(report(&InstanceUid::default(), 1).encode_to_vec()),
        ),
        (
            "a WebSocket upgrade",
            http.get(at("/v1/opamp"))
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ),
        (
            "a download",
            http.get(at(&format!(
                "/api/v1/packages/{OTELCOL}/1.0.0/file?os=linux&arch=amd64"
            ))),
        ),
    ];
    for (what, request) in attempts {
        let response = request.send().await.expect("send");
        assert_eq!(response.status(), 401, "{what}");
        assert_eq!(
            challenge(&response).as_deref(),
            Some("Bearer realm=\"fleet\""),
            "{what}"
        );
    }
    assert!(
        state.snapshot().is_empty(),
        "no Agent was recorded by a request that was not admitted"
    );
}

/// The Server binary cannot serve the Agent plane open: it names no `*_for_tests` constructor, and
/// the one that exists is compiled only under the `test-support` feature, which no build of the
/// binary enables.
#[test]
fn the_server_binary_names_no_constructor_for_tests() {
    let main = include_str!("../src/main.rs");
    assert!(!main.contains("for_tests"), "main.rs reaches a test seam");
    assert!(main.contains("classis_server::agent_app("));
}

/// The scheme is case-insensitive and the credential is not: `bEaReR` admits, a token with its
/// letters recased does not — for a key at `/v1/enrol` as for a token at `/v1/opamp`.
#[tokio::test]
async fn the_scheme_is_case_insensitive_and_the_credential_value_is_not() {
    let rig = rig(Setup::default()).await;
    let host = rig.enrol().await;
    let recased = |text: &str| {
        let changed = text.to_ascii_uppercase();
        assert_ne!(changed, text, "a credential with lower case letters");
        changed
    };

    for scheme in ["bEaReR", "BEARER", "bearer"] {
        let admitted = Route::OpampPost
            .request(&rig, &[&format!("{scheme} {}", host.token)], "")
            .send()
            .await
            .expect("send");
        assert_eq!(admitted.status(), 200, "{scheme}");
        let enrolled = Route::Enrol
            .request(&rig, &[&format!("{scheme} {}", rig.key)], "")
            .send()
            .await
            .expect("send");
        assert_eq!(enrolled.status(), 201, "{scheme}");
    }
    let wrong_token = Route::OpampPost
        .request(&rig, &[&format!("Bearer {}", recased(&host.token))], "")
        .send()
        .await
        .expect("send");
    assert_eq!(wrong_token.status(), 401);
    assert_eq!(challenge(&wrong_token).as_deref(), Some(NOT_ADMITTED));
    let wrong_key = Route::Enrol
        .request(&rig, &[&format!("Bearer {}", recased(&rig.key))], "")
        .send()
        .await
        .expect("send");
    assert_eq!(wrong_key.status(), 401);
}

// ---- The back-off ----

/// A request that is refused on `route`, as an address with no credential makes it.
async fn refused_attempt(rig: &Rig, route: Route) -> reqwest::Response {
    route.request(rig, &[], "").send().await.expect("send")
}

async fn refused_token_request(rig: &Rig) -> reqwest::Response {
    token_request(
        rig,
        "no-such-client",
        "wrong",
        "grant_type=client_credentials",
    )
    .await
}

async fn token_request(rig: &Rig, id: &str, secret: &str, body: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(rig.url("/v1/token"))
        .basic_auth(id, Some(secret))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .expect("send")
}

/// Repeated refusals from one address put it in back-off on each of the three routes, and it is
/// then answered `429` with `Retry-After` on all of them — the table is one — until the back-off
/// ends.
#[tokio::test]
async fn repeated_refusals_put_an_address_in_back_off_on_each_route() {
    for route in [
        Some(Route::Enrol),
        Some(Route::OpampPost),
        Some(Route::OpampUpgrade),
        Some(Route::Download),
        None,
    ] {
        let rig = rig(Setup {
            limits: LIMITS,
            ..Setup::default()
        })
        .await;
        let host = rig.enrol().await;
        for attempt in 0..3 {
            let response = match route {
                Some(route) => refused_attempt(&rig, route).await,
                None => refused_token_request(&rig).await,
            };
            assert_eq!(response.status(), 401, "{route:?} attempt {attempt}");
        }
        for (what, response) in [
            ("a token request", refused_token_request(&rig).await),
            (
                "an exchange",
                rig.post(&host.token, &report(&InstanceUid::default(), 1))
                    .await,
            ),
            ("an enrolment", refused_attempt(&rig, Route::Enrol).await),
        ] {
            assert_eq!(
                response.status(),
                429,
                "{route:?}: {what} after the back-off"
            );
            assert_eq!(
                response
                    .headers()
                    .get("retry-after")
                    .map(|v| v.to_str().expect("ascii")),
                Some("300"),
                "{route:?}: {what}"
            );
        }
        rig.clock.advance(Duration::from_secs(301));
        assert_eq!(
            rig.post(&host.token, &report(&InstanceUid::default(), 1))
                .await
                .status(),
            200,
            "{route:?}: the back-off ends"
        );
    }
}

/// A Bearer `400 invalid_request` is a refused authentication too and counts.
#[tokio::test]
async fn a_bearer_invalid_request_counts_as_a_refusal() {
    let rig = rig(Setup {
        limits: LIMITS,
        ..Setup::default()
    })
    .await;
    for _ in 0..3 {
        let response = Route::OpampPost
            .request(&rig, &["Bearer one", "Bearer two"], "")
            .send()
            .await
            .expect("send");
        assert_eq!(response.status(), 400);
    }
    assert_eq!(refused_attempt(&rig, Route::OpampPost).await.status(), 429);
}

/// What comes after authentication does not count: an enrolment with a valid key and metadata the
/// Server does not support, and a token request with a missing grant, are `400`s however often they
/// repeat; and a success clears nothing of the failures before it.
#[tokio::test]
async fn refusals_after_authentication_are_not_counted_and_a_success_clears_nothing() {
    let rig = rig(Setup {
        limits: LIMITS,
        ..Setup::default()
    })
    .await;
    let host = rig.enrol().await;
    for _ in 0..5 {
        let metadata = reqwest::Client::new()
            .post(rig.url("/v1/enrol"))
            .bearer_auth(&rig.key)
            .header("content-type", "application/json")
            .body(r#"{"grant_types":["authorization_code"]}"#)
            .send()
            .await
            .expect("send");
        assert_eq!(metadata.status(), 400);
        let grantless = token_request(&rig, &host.client_id, &host.secret, "").await;
        assert_eq!(grantless.status(), 400);
        let scoped = token_request(
            &rig,
            &host.client_id,
            &host.secret,
            "grant_type=client_credentials&scope=admin",
        )
        .await;
        assert_eq!(scoped.status(), 400);
    }
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200,
        "no address was put in back-off by them"
    );

    // Two failures, a success, a third failure: the success did not clear the first two.
    refused_attempt(&rig, Route::OpampPost).await;
    refused_attempt(&rig, Route::OpampPost).await;
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200
    );
    refused_attempt(&rig, Route::OpampPost).await;
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        429
    );
}

/// The Operator plane counts its failures in a table of its own: an address in back-off on one
/// plane is still answered on the other.
#[tokio::test]
async fn the_agent_planes_back_off_is_a_table_of_its_own() {
    let auth: classis_server::config::RestAuthConfig = toml::from_str(&format!(
        "[basic_users]\nops = {:?}\n",
        classis_server::credentials::hash_basic("s3cret").expect("hash")
    ))
    .expect("rest auth config");
    let operator_clock = ManualClock::new();
    let operator_auth = classis_server::api::OperatorAuth::from_config(&auth)
        .expect("operator auth")
        .with_throttle(Arc::new(Throttle::new(LIMITS, operator_clock)));
    let rig = rig(Setup {
        limits: LIMITS,
        operator_auth: Some(operator_auth),
        ..Setup::default()
    })
    .await;
    let host = rig.enrol().await;
    let operator = |sign_in: bool| {
        let request = reqwest::Client::new().get(format!("http://{}/api/v1/agents", rig.rest_addr));
        async move {
            if sign_in {
                request.basic_auth("ops", Some("s3cret"))
            } else {
                request
            }
            .send()
            .await
            .expect("send")
        }
    };

    for _ in 0..3 {
        assert_eq!(refused_attempt(&rig, Route::OpampPost).await.status(), 401);
    }
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        429
    );
    assert_eq!(
        operator(true).await.status(),
        200,
        "the Operator plane is not in back-off"
    );

    rig.clock.advance(Duration::from_secs(301));
    for _ in 0..3 {
        assert_eq!(operator(false).await.status(), 401);
    }
    assert_eq!(
        operator(true).await.status(),
        429,
        "the Operator plane is in back-off"
    );
    assert_eq!(
        rig.post(&host.token, &report(&InstanceUid::default(), 1))
            .await
            .status(),
        200,
        "the Agent plane is not"
    );
}
