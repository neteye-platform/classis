//! Package delivery (ADR-0026): the REST Set + entry routes,
//! and the hash-gated `PackagesAvailable` offer toward capable Agents.

mod support;

use fleet_server::fleet::{AppState, PackageOffering};
use fleet_server::packages::PackageStore;
use opamp::proto::{
    AgentCapabilities, AgentToServer, PackageStatus, PackageStatusEnum, PackageStatuses,
    ServerCapabilities, ServerToAgent,
};
use opamp::uid::InstanceUid;
use prost::Message as _;
use std::sync::Arc;
use support::{full_report, TestServer};

const PROTOBUF: &str = "application/x-protobuf";

/// A Server with package delivery armed over a temp store; returns the server and its temp dir.
async fn spawn_with_packages() -> (TestServer, tempfile::TempDir) {
    // What main() does at startup: without a process provider, reqwest refuses to build a client.
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
    let (addr, rest_addr) =
        support::serve(state.clone(), fleet_server::transport::Admission::open()).await;
    (
        TestServer {
            addr,
            rest_addr,
            state,
            _dir: dir,
        },
        tempfile::tempdir().expect("scratch"),
    )
}

/// A host of the fleet on an Agent plane that requires a client certificate, as the binary serves
/// it: its client presents a certificate naming the host (ADR-0021 clause 7), so a download is
/// tested for an offer (ADR-0026).
struct Member {
    client: reqwest::Client,
    /// `https://localhost:<port>` — the Agent plane.
    base: String,
}

impl Member {
    async fn exchange(&self, msg: &AgentToServer) -> ServerToAgent {
        let response = self
            .client
            .post(format!("{}/v1/opamp", self.base))
            .header("content-type", PROTOBUF)
            .body(msg.encode_to_vec())
            .send()
            .await
            .expect("post");
        assert_eq!(response.status(), 200);
        ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
    }

    async fn download(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .expect("download")
    }
}

/// A Server with package delivery armed and a host register, its Agent plane over mutual TLS and
/// its Operator plane open, plus one member host.
async fn spawn_with_packages_for_a_host() -> (TestServer, Member) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair, SanType};
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "packages-test-ca");
    ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_pem = ca.self_signed(&ca_key).expect("ca").pem();
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).expect("issuer");
    let leaf = |params: CertificateParams| {
        let key = KeyPair::generate().expect("key");
        let cert = params.signed_by(&key, &issuer).expect("signed");
        (cert.pem(), key.serialize_pem())
    };
    let (server_cert, server_key) =
        leaf(CertificateParams::new(vec!["localhost".to_string()]).expect("params"));
    let mut host = CertificateParams::new(Vec::<String>::new()).expect("params");
    host.subject_alt_names.push(SanType::URI(
        format!("{}edge-01", fleet_server::ca::HOST_URI_PREFIX)
            .try_into()
            .expect("uri"),
    ));
    let (host_cert, host_key) = leaf(host);

    let files = dir.path().join("tls");
    std::fs::create_dir_all(&files).expect("tls dir");
    for (name, pem) in [
        ("cert.pem", &server_cert),
        ("key.pem", &server_key),
        ("ca.pem", &ca_pem),
    ] {
        std::fs::write(files.join(name), pem).expect("write");
    }
    let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
        "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
        files.join("cert.pem").display().to_string(),
        files.join("key.pem").display().to_string(),
        files.join("ca.pem").display().to_string(),
    ))
    .expect("tls config");
    let planes = fleet_server::tls::server_tls(&tls, None, None).expect("server material");
    let agent_tls = planes.agent.rustls_config().expect("agent plane config");

    let revocations = Arc::new(
        fleet_server::revocation::Revocations::open(
            Box::new(
                fleet_server::fs::FsLedgerStore::open(&dir.path().join("fleet-configs"))
                    .expect("ledger"),
            ),
            Arc::new(fleet_server::clock::SystemClock),
            Vec::new(),
        )
        .expect("revocations"),
    );
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_revocations(Some(revocations.clone()))
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            )),
    );
    let admission = fleet_server::transport::Admission::new(true)
        .with_enrolment(planes.issuers, None)
        .with_revocations(Some(revocations));
    let handle = opamp::server::listen::Handle::new();
    let agent_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let operator_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let (addr, rest_addr) = (
        agent_listener.local_addr().expect("addr"),
        operator_listener.local_addr().expect("addr"),
    );
    tokio::spawn(
        fleet_server::listen::plane(agent_listener, Some(agent_tls), 64, handle.clone())
            .serve(fleet_server::agent_app(state.clone(), admission)),
    );
    tokio::spawn(
        fleet_server::listen::plane(operator_listener, None, 64, handle)
            .serve(fleet_server::operator_app(state.clone(), None)),
    );

    let mut identity = host_key.into_bytes();
    identity.extend_from_slice(host_cert.as_bytes());
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca")])
        .resolve("localhost", addr)
        .identity(reqwest::Identity::from_pem(&identity).expect("identity"))
        .build()
        .expect("client");
    (
        TestServer {
            addr,
            rest_addr,
            state,
            _dir: dir,
        },
        Member {
            client,
            base: format!("https://localhost:{}", addr.port()),
        },
    )
}

async fn exchange(server: &TestServer, msg: &opamp::proto::AgentToServer) -> ServerToAgent {
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .body(msg.encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
}

/// The platform the test fleet reports (see `support::full_report`), and therefore the only one
/// an entry may be stored under for these Agents to be offered it (ADR-0026).
const HOST: &str = "linux/amd64";

/// The base of one Package's routes: `/api/v1/packages/<agent type>/<version>` (ADR-0026) — the
/// identity **is** the path, stated at creation and never edited. There is no name beside the two.
fn set_url(server: &TestServer, agent_type: &str, version: &str) -> String {
    format!(
        "http://{}/api/v1/packages/{agent_type}/{version}",
        server.rest_addr
    )
}

/// The artifact download of one Set — on the **Agent plane** (ADR-0013), which is where the
/// `download_url` in an offer points and the one `/api/v1` route the Operator plane does not serve.
fn download_url(server: &TestServer, agent_type: &str, version: &str) -> String {
    format!(
        "http://{}/api/v1/packages/{agent_type}/{version}/file",
        server.addr
    )
}

/// `PUT /api/v1/packages/{agent type}/{version}` — creates the Package; saved, distributed to nobody.
async fn create_set(server: &TestServer, agent_type: &str, version: &str) {
    let response = reqwest::Client::new()
        .put(set_url(server, agent_type, version))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(response.status(), 200, "creating the set should succeed");
}

/// `PUT …/entries/{os}/{arch}` — stores one platform's artifact into a Set.
async fn upload_entry(
    server: &TestServer,
    agent_type: &str,
    version: &str,
    platform: &str,
    artifact: &[u8],
) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!(
            "{}/entries/{platform}",
            set_url(server, agent_type, version)
        ))
        .body(artifact.to_vec())
        .send()
        .await
        .expect("put entry")
}

/// `POST /api/v1/deployments/<channel>/rollout` — the one act that distributes (ADR-0025): the channel's
/// Package is assigned to every Agent it claims. Returns the outcome body.
/// One channel as the API answers with it — where the reach counts live (ADR-0026).
async fn ring_view(server: &TestServer, channel: &str) -> serde_json::Value {
    reqwest::Client::new()
        .get(deployment_url(server, channel))
        .send()
        .await
        .expect("get deployment")
        .json()
        .await
        .expect("json")
}

async fn rollout_ring(server: &TestServer, channel: &str) -> serde_json::Value {
    let response = reqwest::Client::new()
        .post(format!("{}/rollout", deployment_url(server, channel)))
        .send()
        .await
        .expect("post rollout");
    assert_eq!(response.status(), 200, "the rollout should succeed");
    response.json().await.expect("json")
}

/// A channel aiming at `pairs`, holding this Package. Aim lives on the Deployment (ADR-0026), so a
/// test that wants something delivered says which hosts are in the channel — and `replace` because a
/// channel holds one Package per Agent type, so pointing it at another version is a swap.
async fn ring_holding(
    server: &TestServer,
    channel: &str,
    pairs: &[(&str, &str)],
    version: &str,
) -> String {
    assert_eq!(put_deployment(server, channel, pairs).await.status(), 200);
    let response = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/{version}?replace=true",
            deployment_url(server, channel),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(response.status(), 200, "the channel takes the package");
    sign_every_entry(server, support::AGENT_TYPE, version).await;
    channel.to_string()
}

/// Signs every entry of the Package that carries no signature yet, as an operator does before a
/// rollout: the Server offers nothing unsigned (ADR-0033). Without `[packages] verification_key`
/// the Server checks nothing — the Agent does — so a placeholder serves every test here that is
/// not about it.
async fn sign_every_entry(server: &TestServer, agent_type: &str, version: &str) {
    let set: serde_json::Value = reqwest::Client::new()
        .get(set_url(server, agent_type, version))
        .send()
        .await
        .expect("get package")
        .json()
        .await
        .expect("json");
    // What is signed already stays as it is: an assigned Package's entries are frozen.
    for entry in set["entries"].as_array().into_iter().flatten() {
        if entry["signature_state"] != "missing" {
            continue;
        }
        let (os, arch) = (
            entry["os"].as_str().unwrap_or(""),
            entry["arch"].as_str().unwrap_or(""),
        );
        let response = sign_entry(server, agent_type, version, os, arch, &"01".repeat(64)).await;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        assert_eq!(status, 200, "the entry takes the signature: {body}");
    }
}

/// `PUT …/entries/{os}/{arch}/signature` with `{signature}` (ADR-0033).
async fn sign_entry(
    server: &TestServer,
    agent_type: &str,
    version: &str,
    os: &str,
    arch: &str,
    signature_hex: &str,
) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!(
            "{}/entries/{os}/{arch}/signature",
            set_url(server, agent_type, version)
        ))
        .json(&serde_json::json!({ "signature": signature_hex }))
        .send()
        .await
        .expect("put signature")
}

/// The channel every test that does not care about aim uses: it claims every Agent of the type this
/// fleet reports.
async fn everyone(server: &TestServer, version: &str) -> String {
    ring_holding(
        server,
        "stable",
        &[("service.name", support::AGENT_TYPE)],
        version,
    )
    .await
}

/// Create + upload in one go: the Set is complete — and still reaches nobody until a rollout act
/// names it (ADR-0025).
async fn upload(server: &TestServer, agent_type: &str, version: &str, artifact: &[u8]) {
    create_set(server, agent_type, version).await;
    let response = upload_entry(server, agent_type, version, HOST, artifact).await;
    assert_eq!(response.status(), 200, "upload should succeed");
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}

/// ADR-0026's versions under ADR-0025: versions are first-class Sets, and the act names the one
/// the operator releases — no one produces an old artifact again, and no publication state is
/// juggled. An Agent that has reported nothing installed takes either of them; what happens once
/// it *has* reported is ADR-0025's, tested below.
#[tokio::test]
async fn the_act_names_the_version_it_releases() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let server_ref = &server;
    let offered = |sequence: u64| async move {
        let mut report = full_report(&uid, "collector", sequence);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        exchange(server_ref, &report).await.packages_available
    };

    // The Agent is known first — a rollout act assigns to the fleet as it is.
    assert!(offered(1).await.is_none());
    upload(&server, support::AGENT_TYPE, "0.156.0", b"old-binary").await;
    upload(&server, support::AGENT_TYPE, "0.157.0", b"new-binary").await;

    // Both versions are saved; the act names the one the operator releases.
    assert_eq!(
        rollout_ring(&server, &everyone(&server, "0.157.0").await).await["assigned_agents"],
        1
    );
    assert_eq!(
        offered(2).await.expect("an offer").packages[support::AGENT_TYPE].version,
        "0.157.0"
    );

    // The same act, pointed at the older version. This Agent reports no package statuses, so it
    // has nothing installed to be held against (ADR-0025) and the older Set still reaches it —
    // and its artifact is still here.
    assert_eq!(
        rollout_ring(&server, &everyone(&server, "0.156.0").await).await["assigned_agents"],
        1
    );
    let fallback = offered(3).await.expect("the fallback offer");
    assert_eq!(fallback.packages[support::AGENT_TYPE].version, "0.156.0");
    let served = reqwest::Client::new()
        .get(format!(
            "{}?os=linux&arch=amd64",
            download_url(&server, support::AGENT_TYPE, "0.156.0")
        ))
        .send()
        .await
        .expect("download")
        .bytes()
        .await
        .expect("bytes");
    assert_eq!(served.as_ref(), b"old-binary");
}

/// ADR-0013: the offered `download_url` is a path the Client resolves against **its own OpAMP
/// endpoint**, so the artifact has to be served by the listener the Agents already talk to — not by
/// the Operator plane, which is where authentication is going and where no Agent will ever look.
/// Verifies: ADR-0026, ADR-0013
#[tokio::test]
async fn the_artifact_is_served_where_the_agents_are_and_not_on_the_operator_plane() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.2.3", b"the-new-binary").await;
    let path = format!(
        "/api/v1/packages/{}/1.2.3/file?os=linux&arch=amd64",
        support::AGENT_TYPE
    );

    let served = reqwest::Client::new()
        .get(format!("http://{}{path}", server.addr))
        .send()
        .await
        .expect("download");
    assert_eq!(served.status(), 200);
    assert_eq!(
        served.bytes().await.expect("bytes").as_ref(),
        b"the-new-binary"
    );

    let elsewhere = reqwest::Client::new()
        .get(format!("http://{}{path}", server.rest_addr))
        .send()
        .await
        .expect("request");
    assert_eq!(
        elsewhere.status(),
        404,
        "one resource, one address: the Operator plane does not serve artifacts"
    );
}

/// Verifies: ADR-0026
#[tokio::test]
async fn an_uploaded_set_is_offered_downloaded_and_gated() {
    let (server, member) = spawn_with_packages_for_a_host().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "collector", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;

    // Nothing uploaded yet: no offer, and the capability is not declared.
    let reply = member.exchange(&report).await;
    assert!(reply.packages_available.is_none());
    assert_eq!(
        reply.capabilities & ServerCapabilities::OffersPackages as u64,
        0
    );

    upload(&server, support::AGENT_TYPE, "1.2.3", b"the-new-binary").await;
    assert_eq!(
        rollout_ring(&server, &everyone(&server, "1.2.3").await).await["assigned_agents"],
        1,
        "the act assigns the one known Agent"
    );

    // Now the offer arrives, declares the capability, and carries a working download URL.
    let reply = member.exchange(&report).await;
    assert_ne!(
        reply.capabilities & ServerCapabilities::OffersPackages as u64,
        0
    );
    let offer = reply.packages_available.expect("an offer");
    assert!(!offer.all_packages_hash.is_empty());
    let available = &offer.packages[support::AGENT_TYPE];
    assert_eq!(available.version, "1.2.3");
    let file = available.file.as_ref().expect("a downloadable file");
    // The URL is a path the Client resolves against its own endpoint (ADR-0033) —
    // and it names the whole identity, so two versions never serve each other's bytes.
    assert_eq!(
        file.download_url,
        format!(
            "/api/v1/packages/{}/1.2.3/file?os=linux&arch=amd64",
            support::AGENT_TYPE
        )
    );
    assert_eq!(file.content_hash, sha256(b"the-new-binary"));

    // The artifact downloads byte-for-byte, over the certificate of the host whose Agent it
    // is offered to.
    let downloaded = member
        .download(&file.download_url)
        .await
        .bytes()
        .await
        .expect("bytes");
    assert_eq!(downloaded.as_ref(), b"the-new-binary");

    // Reporting the offered aggregate hash as installed silences the offer (the Baseline's gate).
    let mut installed = full_report(&uid, "collector", 2);
    installed.capabilities |= AgentCapabilities::AcceptsPackages as u64
        | AgentCapabilities::ReportsPackageStatuses as u64;
    installed.package_statuses = Some(PackageStatuses {
        packages: [(
            support::AGENT_TYPE.to_string(),
            PackageStatus {
                name: support::AGENT_TYPE.to_string(),
                agent_has_version: "1.2.3".to_string(),
                status: PackageStatusEnum::Installed as i32,
                ..Default::default()
            },
        )]
        .into(),
        server_provided_all_packages_hash: offer.all_packages_hash.clone(),
        error_message: String::new(),
    });
    let reply = member.exchange(&installed).await;
    assert!(
        reply.packages_available.is_none(),
        "a matching reported hash stops the offer"
    );
}

/// Verifies: ADR-0026
#[tokio::test]
async fn no_offer_without_the_capability() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    // full_report declares no AcceptsPackages.
    exchange(&server, &full_report(&uid, "incapable", 1)).await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"bin").await;
    rollout_ring(&server, &everyone(&server, "1.0.0").await).await;
    let reply = exchange(&server, &full_report(&uid, "incapable", 2)).await;
    assert!(
        reply.packages_available.is_none(),
        "capability negotiation is binding, whatever is assigned"
    );
}

/// An entry belongs to a Set: uploading toward an identity nobody created is a 404, not a package
/// conjured out of a URL (ADR-0026 — the identity is stated at creation).
/// Verifies: ADR-0026
#[tokio::test]
async fn an_entry_needs_its_set_first() {
    let (server, _scratch) = spawn_with_packages().await;
    let response = upload_entry(&server, support::AGENT_TYPE, "1.0.0", HOST, b"bytes").await;
    assert_eq!(response.status(), 404);
}

/// A package is a *program*: an `otelcol-contrib` binary weighs hundreds of megabytes, so the
/// entry route must not be bounded by the framework's 2 MiB default, and the artifact must reach
/// the Agent unchanged whatever its size.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_artifact_larger_than_the_framework_default_uploads_and_downloads_intact() {
    let (server, member) = spawn_with_packages_for_a_host().await;
    let mut report = full_report(&InstanceUid::default(), "collector", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    member.exchange(&report).await;

    // Past axum's 2 MiB default body limit — the limit that would make a real binary undeliverable
    // — and not a round number, so a truncation would show.
    let artifact: Vec<u8> = (0..(5 * 1024 * 1024 + 17))
        .map(|i| (i % 251) as u8)
        .collect();
    upload(&server, support::AGENT_TYPE, "1.2.3", &artifact).await;
    rollout_ring(&server, &everyone(&server, "1.2.3").await).await;

    let downloaded = member
        .download(&format!(
            "/api/v1/packages/{}/1.2.3/file?os=linux&arch=amd64",
            support::AGENT_TYPE
        ))
        .await;
    assert_eq!(
        downloaded
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(artifact.len().to_string().as_str()),
        "the length is advertised, so the Agent can size the transfer"
    );
    let bytes = downloaded.bytes().await.expect("bytes");
    assert_eq!(bytes.len(), artifact.len());
    assert_eq!(bytes.as_ref(), artifact.as_slice(), "byte-identical");
}

/// A version saved into the channel and signed, but not yet released by the operator's press, is
/// no one's offer and cannot be fetched — while the version released before it still can. The
/// press makes it fetchable.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_version_waiting_for_its_rollout_cannot_be_fetched() {
    let (server, member) = spawn_with_packages_for_a_host().await;
    let mut report = full_report(&InstanceUid::default(), "collector", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    member.exchange(&report).await;
    let path = |version: &str| {
        format!(
            "/api/v1/packages/{}/{version}/file?os=linux&arch=amd64",
            support::AGENT_TYPE
        )
    };

    upload(&server, support::AGENT_TYPE, "1.0.0", b"released").await;
    rollout_ring(&server, &everyone(&server, "1.0.0").await).await;
    upload(&server, support::AGENT_TYPE, "2.0.0", b"waiting").await;
    let channel = everyone(&server, "2.0.0").await;

    assert_eq!(member.download(&path("2.0.0")).await.status(), 404);
    let released = member.download(&path("1.0.0")).await;
    assert_eq!(released.status(), 200);
    assert_eq!(released.bytes().await.expect("bytes").as_ref(), b"released");

    rollout_ring(&server, &channel).await;
    let pressed = member.download(&path("2.0.0")).await;
    assert_eq!(pressed.status(), 200);
    assert_eq!(pressed.bytes().await.expect("bytes").as_ref(), b"waiting");
}

/// The upload limit is a configured bound, not an accident of the framework: past it the API
/// refuses rather than buffering whatever arrives.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_artifact_past_the_configured_limit_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            ))
            .with_max_package_size(4096),
    );
    let (addr, rest_addr) =
        support::serve(state.clone(), fleet_server::transport::Admission::open()).await;
    let server = TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    };

    create_set(&server, support::AGENT_TYPE, "1.0.0").await;
    let response = upload_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        HOST,
        &vec![0u8; 8192],
    )
    .await;
    assert_eq!(response.status(), 413);
}

/// The point of ADR-0026: the channel decides whom the rollout act assigns, so a binary rollout can
/// be tried on part of the fleet first — and nobody outside it is touched by the act.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_selector_aims_a_rollout_at_part_of_the_fleet() {
    let (server, _scratch) = spawn_with_packages().await;

    // full_report describes an Agent with os.type = linux (see the test scaffolding).
    let targeted = InstanceUid::default();
    let mut report = full_report(&targeted, "collector", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    // A second Agent that reports another platform.
    let other = InstanceUid::default();
    let mut elsewhere = full_report(&other, "windows-box", 1);
    elsewhere.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    if let Some(description) = elsewhere.agent_description.as_mut() {
        for attribute in &mut description.non_identifying_attributes {
            if attribute.key == "os.type" {
                attribute.value = Some(opamp::proto::AnyValue {
                    value: Some(opamp::proto::any_value::Value::StringValue(
                        "windows".to_string(),
                    )),
                });
            }
        }
    }
    exchange(&server, &elsewhere).await;

    upload(&server, support::AGENT_TYPE, "2.0.0", b"the-new-binary").await;
    let channel = ring_holding(&server, "linux-channel", &[("os.type", "linux")], "2.0.0").await;
    assert_eq!(
        rollout_ring(&server, &channel).await["assigned_agents"],
        1,
        "the act reaches exactly the channel"
    );

    let mut report = full_report(&targeted, "collector", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("the matching Agent is offered it");
    assert!(offer.packages.contains_key(support::AGENT_TYPE));
    assert!(!offer.all_packages_hash.is_empty());

    // The Agent outside the aim is offered nothing at all — not an empty offer, no offer: it
    // keeps running what it runs (goal 9, applied to software).
    let mut elsewhere2 = full_report(&other, "windows-box", 2);
    elsewhere2.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let reply = exchange(&server, &elsewhere2).await;
    assert!(
        reply.packages_available.is_none(),
        "an Agent outside the channel is offered nothing"
    );
}

/// The aggregate hash gates re-offering, and it is per Agent: computed over the whole store it
/// would never match what a targeted Agent was actually sent, and the Server would re-offer for ever.
#[tokio::test]
async fn the_aggregate_hash_an_agent_echoes_is_the_one_it_was_offered() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "collector", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64
        | AgentCapabilities::ReportsPackageStatuses as u64;
    exchange(&server, &report).await;

    // Two Packages of one Agent type differ by version (ADR-0026) — there is no name to tell them
    // apart, which is the point: what distinguishes two artifacts is what they are and which
    // release they belong to.
    upload(&server, support::AGENT_TYPE, "2.0.0", b"for-linux").await;
    upload(&server, support::AGENT_TYPE, "2.1.0", b"for-windows").await;
    // Two channels, disjoint by platform — which is what a partition looks like when the attribute
    // that separates the hosts is one they all report (ADR-0026 point 25).
    let linux = ring_holding(&server, "linux-channel", &[("os.type", "linux")], "2.0.0").await;
    let windows = ring_holding(
        &server,
        "windows-channel",
        &[("os.type", "windows")],
        "2.1.0",
    )
    .await;
    assert_eq!(rollout_ring(&server, &linux).await["assigned_agents"], 1);
    assert_eq!(
        rollout_ring(&server, &windows).await["assigned_agents"],
        0,
        "the act toward the windows channel assigns nobody in this fleet"
    );

    let mut report = full_report(&uid, "collector", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64
        | AgentCapabilities::ReportsPackageStatuses as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("an offer");
    assert_eq!(
        offer.packages.len(),
        1,
        "only the Package the act assigned this Agent"
    );

    // Echoing exactly that aggregate settles it — the Server must not keep re-offering.
    let mut installed = full_report(&uid, "collector", 3);
    installed.capabilities |= AgentCapabilities::AcceptsPackages as u64
        | AgentCapabilities::ReportsPackageStatuses as u64;
    installed.package_statuses = Some(PackageStatuses {
        packages: [(
            support::AGENT_TYPE.to_string(),
            PackageStatus {
                name: support::AGENT_TYPE.to_string(),
                agent_has_version: "2.0.0".to_string(),
                status: PackageStatusEnum::Installed as i32,
                ..Default::default()
            },
        )]
        .into(),
        server_provided_all_packages_hash: offer.all_packages_hash.clone(),
        error_message: String::new(),
    });
    assert!(
        exchange(&server, &installed)
            .await
            .packages_available
            .is_none(),
        "the Agent is in sync with what it was offered"
    );
}

/// The canary shape an operator actually wants, under ADR-0026: **two channels, disjoint by a label**
/// — because a Selector is equality and cannot say "not", so the fleet-wide-plus-narrower-override
/// shape is a conflict (ADR-0026 clause 26). Each channel holds its own version; the rollout
/// finishes by moving the canary host's label back and rolling the stable channel out again. Nobody
/// moves without an act.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_canary_ring_is_a_selector_aim_and_two_acts() {
    let (server, _scratch) = spawn_with_packages().await;
    let canary = InstanceUid::default();
    let ordinary = InstanceUid::default();
    for (uid, name) in [(&canary, "canary-host"), (&ordinary, "ordinary-host")] {
        let mut report = full_report(uid, name, 1);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        exchange(&server, &report).await;
    }

    upload(&server, support::AGENT_TYPE, "2.0.0", b"the-fleet-binary").await;
    upload(&server, support::AGENT_TYPE, "3.0.0", b"the-canary-binary").await;
    // The partition: one host is in the canary channel, the other in the stable one. Disjoint by
    // construction, which is what makes exactly one Deployment claim each Agent.
    let stable = ring_holding(
        &server,
        "stable",
        &[("service.instance.name", "ordinary-host")],
        "2.0.0",
    )
    .await;
    let canary_ring = ring_holding(
        &server,
        "canary",
        &[("service.instance.name", "canary-host")],
        "3.0.0",
    )
    .await;

    async fn version_offered_to(
        server: &TestServer,
        uid: &InstanceUid,
        name: &str,
        sequence: u64,
    ) -> String {
        let mut report = full_report(uid, name, sequence);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        let offer = exchange(server, &report)
            .await
            .packages_available
            .expect("an offer");
        offer.packages[support::AGENT_TYPE].version.clone()
    }

    // Each act reaches exactly its own channel.
    assert_eq!(rollout_ring(&server, &stable).await["assigned_agents"], 1);
    assert_eq!(
        rollout_ring(&server, &canary_ring).await["assigned_agents"],
        1
    );
    assert_eq!(
        version_offered_to(&server, &canary, "canary-host", 2).await,
        "3.0.0",
        "the named host gets the canary version"
    );
    assert_eq!(
        version_offered_to(&server, &ordinary, "ordinary-host", 2).await,
        "2.0.0",
        "everyone else keeps the fleet-wide version"
    );

    // The rollout finishes by giving the stable channel the canary's version — which distributes
    // nothing by itself — and pressing once more. Widening the canary channel instead would make both
    // claim the same host, which is a conflict, not a rollout.
    ring_holding(
        &server,
        "stable",
        &[("service.instance.name", "ordinary-host")],
        "3.0.0",
    )
    .await;
    assert_eq!(rollout_ring(&server, &stable).await["assigned_agents"], 1);
    assert_eq!(
        version_offered_to(&server, &ordinary, "ordinary-host", 3).await,
        "3.0.0"
    );
}

/// The one case with no defensible answer (ADR-0026 clause 26). It is not about versions or
/// specificity — **any** two channels claiming one Agent is a conflict, however narrow or wide
/// either is. The Server offers nothing and the fleet view names both.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_agent_two_rings_claim_is_offered_nothing_and_the_view_says_why() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "2.0.0", b"one").await;
    upload(&server, support::AGENT_TYPE, "3.0.0", b"two").await;
    // Two channels that overlap on the Agent below. With a specificity ranking the second would
    // have won by being no less specific, or lost by being no more; ADR-0026 clause 26 ranks neither.
    ring_holding(&server, "by-platform", &[("os.type", "linux")], "2.0.0").await;
    ring_holding(
        &server,
        "by-os",
        &[("os.description", "Testix 1.0 LTS")],
        "3.0.0",
    )
    .await;

    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "collector", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let reply = exchange(&server, &report).await;
    assert!(
        reply.packages_available.is_none(),
        "an Agent two channels claim is offered nothing"
    );

    let view = &server.state.snapshot()[0];
    let conflict = view
        .package_conflict
        .as_ref()
        .expect("the fleet view says why");
    assert!(
        conflict.contains("by-platform") && conflict.contains("by-os"),
        "the reason names every channel in the way: {conflict}"
    );
}

/// ADR-0026, with no late typing: the Agent type is identity, stated at creation —
/// there is no untyped state — and a Set built for another type fits nobody here: its rollout
/// act assigns no one, whatever its Selector says.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_set_reaches_only_agents_of_its_type() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    // A Set for a different kind of Agent, complete — and its act assigns nobody.
    let response = reqwest::Client::new()
        .put(format!(
            "http://{}/api/v1/packages/promtail/1.0.0",
            server.rest_addr
        ))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(response.status(), 200);
    let response = reqwest::Client::new()
        .put(format!(
            "http://{}/api/v1/packages/promtail/1.0.0/entries/{HOST}",
            server.rest_addr
        ))
        .body(b"the-binary".to_vec())
        .send()
        .await
        .expect("put entry");
    assert_eq!(response.status(), 200);
    // A channel that claims this Agent, holding only a Package built for another type. The channel is
    // right, the Agent is in it, and it still gets nothing — because fit is by type, before any
    // channel is consulted (ADR-0026).
    assert_eq!(
        put_deployment(&server, "stable", &[("service.name", support::AGENT_TYPE)])
            .await
            .status(),
        200
    );
    let response = reqwest::Client::new()
        .put(format!(
            "{}/packages/promtail/1.0.0",
            deployment_url(&server, "stable")
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(response.status(), 200);
    sign_every_entry(&server, "promtail", "1.0.0").await;
    let outcome = rollout_ring(&server, "stable").await;
    assert_eq!(
        outcome["assigned_agents"], 0,
        "a Package built for another type fits nobody here"
    );

    let mut report = full_report(&uid, "edge-01", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    assert!(
        exchange(&server, &report)
            .await
            .packages_available
            .is_none(),
        "nothing was assigned, so nothing is offered"
    );

    // The same artifact under this fleet's type reaches it.
    upload(&server, support::AGENT_TYPE, "1.0.0", b"the-binary").await;
    assert_eq!(
        rollout_ring(&server, &everyone(&server, "1.0.0").await).await["assigned_agents"],
        1
    );
    let mut report = full_report(&uid, "edge-01", 3);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("an offer");
    assert!(offer.packages.contains_key(support::AGENT_TYPE));
}

/// ADR-0025 end to end: a Set reaches an Agent only as an **upgrade**. What the Agent reports
/// installed is the fourth matching test, so the count, the per-Agent act and the bulk act all
/// refuse to move a host backwards — or to move it nowhere at all. The assignment path is
/// deliberately exempt: an installed package stays in the Agent's offer, or the Agent would be
/// told the package is no longer wanted.
// Verifies: ADR-0025
#[tokio::test]
async fn a_set_reaches_an_agent_only_as_an_upgrade() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();

    /// A report that says "I run this version of this package".
    fn running(uid: &InstanceUid, sequence: u64, version: &str) -> AgentToServer {
        let mut report = full_report(uid, "collector", sequence);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64
            | AgentCapabilities::ReportsPackageStatuses as u64;
        report.package_statuses = Some(PackageStatuses {
            packages: [(
                support::AGENT_TYPE.to_string(),
                PackageStatus {
                    name: support::AGENT_TYPE.to_string(),
                    agent_has_version: version.to_string(),
                    status: PackageStatusEnum::Installed as i32,
                    ..Default::default()
                },
            )]
            .into(),
            // Empty: this Agent is never in sync with an offer, so the hash gate never silences
            // one and every exchange shows what it would be offered.
            server_provided_all_packages_hash: Vec::new(),
            error_message: String::new(),
        });
        report
    }

    /// The two counts the Set view carries (ADR-0025 point 19): whom it aims at, and whom it
    /// would actually reach.
    async fn counts(server: &TestServer, version: &str) -> (i64, i64) {
        let list: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{}/api/v1/deployments", server.rest_addr))
            .send()
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
        let row = list
            .as_array()
            .expect("array")
            .iter()
            .find(|d| d["packages"][0]["version"] == version)
            .unwrap_or_else(|| panic!("no channel holding {version} in the list"))
            .clone();
        (
            row["claiming_agents"].as_i64().expect("claiming_agents"),
            row["targeted_agents"].as_i64().expect("targeted_agents"),
        )
    }

    exchange(&server, &running(&uid, 1, "1.0.0")).await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"what-it-runs").await;

    // The channel claims the one Agent there is, and reaches nobody: the Agent already runs it.
    let channel = everyone(&server, "1.0.0").await;
    assert_eq!(counts(&server, "1.0.0").await, (1, 0));
    assert_eq!(
        rollout_ring(&server, &channel).await["assigned_agents"],
        0,
        "the bulk act skips an Agent it would not move"
    );

    // The per-Agent act says so rather than doing nothing quietly.
    let refused = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/agents/{uid}/rollout",
            server.rest_addr
        ))
        .json(&serde_json::json!({ "deployment": channel }))
        .send()
        .await
        .expect("rollout to agent");
    assert_eq!(refused.status(), 409);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("not an upgrade"),
        "{body}"
    );

    // A greater version in the same channel reaches it. The channel is the constant; what it holds is
    // what an operator changes (ADR-0026) — two channels claiming this Agent would be a conflict.
    upload(&server, support::AGENT_TYPE, "2.0.0", b"the-next-one").await;
    let channel = everyone(&server, "2.0.0").await;
    assert_eq!(counts(&server, "2.0.0").await, (1, 1));
    assert_eq!(rollout_ring(&server, &channel).await["assigned_agents"], 1);
    let offer = exchange(&server, &running(&uid, 2, "1.0.0"))
        .await
        .packages_available
        .expect("an offer");
    assert_eq!(offer.packages[support::AGENT_TYPE].version, "2.0.0");

    // And once the Agent reports it installed, the assignment keeps composing the offer — the
    // Set the Agent runs must not vanish from its desired state (ADR-0025 point 17).
    let offer = exchange(&server, &running(&uid, 3, "2.0.0"))
        .await
        .packages_available
        .expect("the assignment still composes an offer");
    assert_eq!(offer.packages[support::AGENT_TYPE].version, "2.0.0");

    // But it is no longer waiting for anything: the channel still claims it and proposes nothing.
    assert_eq!(counts(&server, "2.0.0").await, (1, 0));
    // And pointing the channel back at the older version proposes nothing either — a Package that
    // would move this Agent backwards is no candidate, whichever channel holds it (ADR-0025).
    everyone(&server, "1.0.0").await;
    assert_eq!(counts(&server, "1.0.0").await, (1, 0));
}

/// The silent no-op ADR-0026 named: a Set can target nobody through a mistyped Agent type, a
/// platform the fleet does not run, or a Selector that matches no one — and none of the three is
/// a rejected upload, so without a count nothing says it.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_set_says_how_many_agents_it_reaches() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    exchange(&server, &support::full_report(&uid, "one", 1)).await;

    async fn list(server: &TestServer) -> serde_json::Value {
        reqwest::Client::new()
            .get(format!("http://{}/api/v1/deployments", server.rest_addr))
            .send()
            .await
            .expect("list deployments")
            .json()
            .await
            .expect("json")
    }

    async fn reach(server: &TestServer, version: &str) -> i64 {
        list(server)
            .await
            .as_array()
            .expect("array")
            .iter()
            .find(|d| d["packages"][0]["version"] == version)
            .unwrap_or_else(|| panic!("no channel holding {version} in the list"))
            ["targeted_agents"]
            .as_i64()
            .expect("targeted_agents")
    }

    // Uploaded under the type this fleet reports, in a channel that claims it: one Agent.
    upload(&server, support::AGENT_TYPE, "1.0.0", b"binary").await;
    everyone(&server, "1.0.0").await;
    assert_eq!(reach(&server, "1.0.0").await, 1);

    // A second Agent on the same platform doubles it.
    exchange(
        &server,
        &support::full_report(&InstanceUid::default(), "two", 1),
    )
    .await;
    assert_eq!(reach(&server, "1.0.0").await, 2);

    // A Selector that matches nobody: still stored, still valid, reaching no one — the case that
    // was invisible before.
    ring_holding(&server, "stable", &[("env", "prod")], "1.0.0").await;
    assert_eq!(reach(&server, "1.0.0").await, 0);

    // An entry for a platform this fleet does not run reaches nobody either — the same channel,
    // pointed back at the whole fleet, holding a Package none of these hosts can take.
    create_set(&server, support::AGENT_TYPE, "2.0.0").await;
    let response = upload_entry(
        &server,
        support::AGENT_TYPE,
        "2.0.0",
        "windows/amd64",
        b"exe",
    )
    .await;
    assert_eq!(response.status(), 200);
    ring_holding(
        &server,
        "stable",
        &[("service.name", support::AGENT_TYPE)],
        "2.0.0",
    )
    .await;
    assert_eq!(reach(&server, "2.0.0").await, 0);
}

/// ADR-0024 reaches packages, not just Configurations — which is the case it exists for. A binary
/// rollout starts on the hosts an operator moved into the canary channel, and moving one in needs no
/// access to that host.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_label_aims_a_set_at_part_of_the_fleet() {
    let (server, _scratch) = spawn_with_packages().await;
    let canary = InstanceUid::default();
    let rest = InstanceUid::default();
    exchange(&server, &full_report(&canary, "canary-host", 1)).await;
    exchange(&server, &full_report(&rest, "other-host", 1)).await;

    upload(&server, support::AGENT_TYPE, "2.0.0", b"the-new-binary").await;
    ring_holding(&server, "stable", &[("rollout", "canary")], "2.0.0").await;

    // Nobody reports `rollout`, so the channel claims no one — and the count says so.
    async fn reach(server: &TestServer) -> i64 {
        let list: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{}/api/v1/deployments", server.rest_addr))
            .send()
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
        list[0]["targeted_agents"].as_i64().expect("count")
    }
    assert_eq!(reach(&server).await, 0);

    // One call moves the first host into the channel.
    let labelled = reqwest::Client::new()
        .put(format!(
            "http://{}/api/v1/agents/{canary}/labels",
            server.rest_addr
        ))
        .json(&serde_json::json!({ "labels": { "rollout": "canary" } }))
        .send()
        .await
        .expect("put labels");
    assert_eq!(labelled.status(), 200);
    assert_eq!(
        reach(&server).await,
        1,
        "exactly the channel, and nothing else"
    );

    // The label only aims (ADR-0025); the act distributes — to the channel, and nobody else.
    assert_eq!(rollout_ring(&server, "stable").await["assigned_agents"], 1);
    let mut report = full_report(&canary, "canary-host", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("the canary host is offered the package");
    assert!(offer.packages.contains_key(support::AGENT_TYPE));

    let mut report = full_report(&rest, "other-host", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    assert!(
        exchange(&server, &report)
            .await
            .packages_available
            .is_none(),
        "the host outside the channel is offered nothing"
    );
}

/// ADR-0025 through the API, from the operator's side: a saved Set waits, rolling out an empty
/// one is refused, the act is its own request — and an assigned Set's entries are immutable
/// while its Selector stays editable.
#[tokio::test]
async fn a_set_waits_until_rolled_out_and_is_immutable_while_assigned() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    exchange(&server, &full_report(&uid, "edge-01", 1)).await;

    async fn offered_now(
        server: &TestServer,
        uid: &InstanceUid,
        sequence: u64,
    ) -> Option<opamp::proto::PackagesAvailable> {
        let mut report = full_report(uid, "edge-01", sequence);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        exchange(server, &report).await.packages_available
    }
    async fn view(server: &TestServer, version: &str) -> serde_json::Value {
        reqwest::Client::new()
            .get(format!("http://{}/api/v1/packages", server.rest_addr))
            .send()
            .await
            .expect("list")
            .json::<serde_json::Value>()
            .await
            .expect("json")
            .as_array()
            .expect("array")
            .iter()
            .find(|p| p["agent_type"] == support::AGENT_TYPE && p["version"] == version)
            .unwrap_or_else(|| panic!("no package at {version}"))
            .clone()
    }

    // A channel holding no Package cannot be rolled out: there would be nothing to release.
    assert_eq!(
        put_deployment(&server, "stable", &[("service.name", support::AGENT_TYPE)])
            .await
            .status(),
        200
    );
    let hollow = reqwest::Client::new()
        .post(format!("{}/rollout", deployment_url(&server, "stable")))
        .send()
        .await
        .expect("rollout");
    assert_eq!(
        hollow.status(),
        409,
        "an empty channel cannot be rolled out"
    );

    // A Package with no entries is a different case, and it is **not** an error: the channel is
    // rolled out, and the Agent is simply not among those it moves. Refusing here would make an
    // operator's half-finished upload look like a broken channel.
    create_set(&server, support::AGENT_TYPE, "2.0.0").await;
    let channel = everyone(&server, "2.0.0").await;
    assert_eq!(
        rollout_ring(&server, &channel).await["assigned_agents"],
        0,
        "a Package holding no entry for this host moves nobody"
    );

    let response = upload_entry(&server, support::AGENT_TYPE, "2.0.0", HOST, b"the-binary").await;
    assert_eq!(response.status(), 200);
    // An entry uploaded after the rollout reaches nobody until it is signed (ADR-0033).
    sign_every_entry(&server, support::AGENT_TYPE, "2.0.0").await;

    let staged = view(&server, "2.0.0").await;
    assert!(
        staged.get("published").is_none(),
        "ADR-0025: there is no publication state to show: {staged}"
    );
    assert_eq!(
        staged["deployments"],
        serde_json::json!(["stable"]),
        "the Package says which channels hold it — it aims at nobody by itself (ADR-0026)"
    );
    assert_eq!(
        ring_view(&server, "stable").await["targeted_agents"],
        1,
        "and the channel says whom the act would move, before the act"
    );
    assert!(
        offered_now(&server, &uid, 2).await.is_none(),
        "a saved Set reaches nobody, however complete it is"
    );

    // Its entries are still editable: nothing is assigned yet.
    let editable = upload_entry(
        &server,
        support::AGENT_TYPE,
        "2.0.0",
        HOST,
        b"the-binary-v2",
    )
    .await;
    assert_eq!(editable.status(), 200, "an unassigned set is editable");
    // New bytes took the old signature with them (ADR-0033), so the entry is signed again.
    sign_every_entry(&server, support::AGENT_TYPE, "2.0.0").await;

    // The act is its own request, and the fleet has the package on the next exchange.
    assert_eq!(rollout_ring(&server, "stable").await["assigned_agents"], 1);
    let offer = offered_now(&server, &uid, 3)
        .await
        .expect("the released package");
    assert!(offer.packages.contains_key(support::AGENT_TYPE));

    // While assigned, the bytes are frozen: writing or deleting an entry answers 409 —
    // the Server's rule, which is exactly what the UI renders as a greyed-out control.
    let frozen = upload_entry(&server, support::AGENT_TYPE, "2.0.0", HOST, b"other-bytes").await;
    assert_eq!(frozen.status(), 409, "assigned entries are immutable");
    let frozen_delete = reqwest::Client::new()
        .delete(format!(
            "{}/entries/{HOST}",
            set_url(&server, support::AGENT_TYPE, "2.0.0")
        ))
        .send()
        .await
        .expect("delete entry");
    assert_eq!(frozen_delete.status(), 409);
    // The Selector is not bytes, and stays editable.
    ring_holding(&server, "stable", &[("os.type", "linux")], "2.0.0").await;

    // Deleting the assigned Set is refused (ADR-0034 clause 8): a deletion must not change what
    // a running Agent receives, so the offer stands.
    let deleted = reqwest::Client::new()
        .delete(set_url(&server, support::AGENT_TYPE, "2.0.0"))
        .send()
        .await
        .expect("delete set");
    assert_eq!(deleted.status(), 409);
    assert!(
        offered_now(&server, &uid, 4).await.is_some(),
        "the refused deletion withdrew nothing"
    );

    // Rolling out a Set that does not exist is a 404, not a Set conjured out of a URL.
    let missing = reqwest::Client::new()
        .post(format!(
            "{}/rollout",
            set_url(&server, support::AGENT_TYPE, "9.9.9")
        ))
        .send()
        .await
        .expect("rollout");
    assert_eq!(missing.status(), 404);
}

/// The store has a whole-store ceiling, so a caller cannot fill the disk by uploading artifact after
/// artifact under distinct names: once the store is at its limit, the next upload is refused.
/// Verifies: ADR-0026
#[tokio::test]
async fn the_package_store_has_a_total_size_ceiling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    // A ceiling of 10 KiB: the first 8 KiB artifact fits, a second does not.
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            ))
            .with_max_total_package_bytes(10 * 1024),
    );
    let (addr, rest_addr) =
        support::serve(state.clone(), fleet_server::transport::Admission::open()).await;
    let server = TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    };

    // The first artifact fits under the ceiling.
    create_set(&server, support::AGENT_TYPE, "1.0.0").await;
    let first = upload_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        HOST,
        &vec![0u8; 8 * 1024],
    )
    .await;
    assert_eq!(
        first.status(),
        200,
        "the first artifact is within the ceiling"
    );

    // A second Package would take the store past the ceiling — refused, and nothing is left staged
    // for it. It has to be a second *version*: two artifacts of one Agent type are told apart by
    // version now (ADR-0026), and writing 1.0.0 again would replace the entry above rather than
    // add to it — which would have this test pass without the store ever growing.
    create_set(&server, support::AGENT_TYPE, "2.0.0").await;
    let second = upload_entry(
        &server,
        support::AGENT_TYPE,
        "2.0.0",
        HOST,
        &vec![0u8; 8 * 1024],
    )
    .await;
    assert_eq!(
        second.status(),
        507,
        "the second upload is refused: it would exceed the store ceiling"
    );
}

// -------------------------------------------------------------------------------------------
// Deployments (ADR-0026)
// -------------------------------------------------------------------------------------------

fn deployment_url(server: &TestServer, name: &str) -> String {
    format!("http://{}/api/v1/deployments/{name}", server.rest_addr)
}

async fn put_deployment(
    server: &TestServer,
    name: &str,
    pairs: &[(&str, &str)],
) -> reqwest::Response {
    let selector: std::collections::BTreeMap<&str, &str> = pairs.iter().copied().collect();
    reqwest::Client::new()
        .put(deployment_url(server, name))
        .json(&serde_json::json!({ "selector": selector }))
        .send()
        .await
        .expect("put deployment")
}

/// A Deployment must name the channel it aims at. There is no fleet-wide default, and the refusal
/// says what to write instead — an empty Selector is what a forgotten field looks like, and it
/// would collide with every other channel (ADR-0026 point 24).
/// Verifies: ADR-0026
#[tokio::test]
async fn a_deployment_without_a_selector_is_refused() {
    let (server, _scratch) = spawn_with_packages().await;
    let refused = reqwest::Client::new()
        .put(deployment_url(&server, "everyone"))
        .json(&serde_json::json!({ "selector": {} }))
        .send()
        .await
        .expect("put");
    assert_eq!(refused.status(), 400);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert!(
        body["error"].as_str().expect("error").contains("channel"),
        "the refusal tells the operator what to write: {body}"
    );

    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{}/api/v1/deployments", server.rest_addr))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed.as_array().expect("array").len(), 0, "nothing stored");
}

/// A channel cannot offer what the store does not hold, and it holds one Package per Agent type.
/// Both refusals happen at the write, where the mistake is, rather than at resolution.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_deployment_holds_one_uploaded_package_per_agent_type() {
    let (server, _scratch) = spawn_with_packages().await;
    assert_eq!(
        put_deployment(&server, "stable", &[("channel", "stable")])
            .await
            .status(),
        200
    );

    let missing = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/1.0.0",
            deployment_url(&server, "stable"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(
        missing.status(),
        404,
        "a package nobody uploaded cannot be offered"
    );

    upload(&server, support::AGENT_TYPE, "1.0.0", b"v1").await;
    upload(&server, support::AGENT_TYPE, "2.0.0", b"v2").await;
    let added = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/1.0.0",
            deployment_url(&server, "stable"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(added.status(), 200);

    let taken = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/2.0.0",
            deployment_url(&server, "stable"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(
        taken.status(),
        409,
        "a second package of one type is refused"
    );
    let body: serde_json::Value = taken.json().await.expect("json");
    assert!(
        body["error"].as_str().expect("error").contains("1.0.0"),
        "the refusal names what is in the way: {body}"
    );

    // Replacing is a separate, explicit ask — and then the channel runs the other version.
    let replaced = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/2.0.0?replace=true",
            deployment_url(&server, "stable"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("replace");
    assert_eq!(replaced.status(), 200);
    let view: serde_json::Value = replaced.json().await.expect("json");
    assert_eq!(view["packages"][0]["version"], "2.0.0");
    assert_eq!(
        view["packages"][0]["display_name"],
        format!("{} 2.0.0", support::AGENT_TYPE)
    );
}

/// The signature belongs to the entry (ADR-0033 clause 6): written and removed through the entry's
/// own route, shown on the entry with its `signature_state`, and absent from the Deployment's view.
/// A signature for an entry that does not exist is `404`, an empty or malformed one `400`.
/// Verifies: ADR-0033
#[tokio::test]
async fn an_entry_carries_its_signature_and_says_its_state() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"v1").await;
    put_deployment(&server, "stable", &[("channel", "stable")]).await;
    let base = deployment_url(&server, "stable");
    let held = reqwest::Client::new()
        .put(format!("{base}/packages/{}/1.0.0", support::AGENT_TYPE))
        .send()
        .await
        .expect("put package");
    let view: serde_json::Value = held.json().await.expect("json");
    assert!(
        view["packages"][0].get("signed_platforms").is_none(),
        "a Deployment holds no signature of its own: {view}"
    );

    let set: serde_json::Value = reqwest::Client::new()
        .get(set_url(&server, support::AGENT_TYPE, "1.0.0"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(set["entries"][0]["signature_state"], "missing");
    assert!(set["entries"][0].get("signature").is_none());

    let signed = sign_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        "linux",
        "amd64",
        &hex::encode([7u8; 64]),
    )
    .await;
    assert_eq!(signed.status(), 200);
    let set: serde_json::Value = signed.json().await.expect("json");
    assert_eq!(set["entries"][0]["signature"], hex::encode([7u8; 64]));
    assert_eq!(
        set["entries"][0]["signature_state"], "unchecked",
        "without [packages] verification_key the Server checks nothing"
    );

    // A signature needs an entry to attach to.
    for (version, os) in [("9.9.9", "linux"), ("1.0.0", "windows")] {
        let orphan = sign_entry(
            &server,
            support::AGENT_TYPE,
            version,
            os,
            "amd64",
            &hex::encode([7u8; 64]),
        )
        .await;
        assert_eq!(orphan.status(), 404, "{version} {os}");
    }
    // And it has to be one.
    for malformed in ["", "not-hex", &hex::encode([7u8; 63])] {
        let refused = sign_entry(
            &server,
            support::AGENT_TYPE,
            "1.0.0",
            "linux",
            "amd64",
            malformed,
        )
        .await;
        assert_eq!(refused.status(), 400, "{malformed:?}");
    }

    let entry_signature = format!(
        "{}/entries/linux/amd64/signature",
        set_url(&server, support::AGENT_TYPE, "1.0.0")
    );
    let removed = reqwest::Client::new()
        .delete(&entry_signature)
        .send()
        .await
        .expect("delete signature");
    assert_eq!(removed.status(), 200);
    let set: serde_json::Value = removed.json().await.expect("json");
    assert_eq!(set["entries"][0]["signature_state"], "missing");
    let again = reqwest::Client::new()
        .delete(&entry_signature)
        .send()
        .await
        .expect("delete signature");
    assert_eq!(again.status(), 404, "there is no signature left to remove");
}

/// New bytes on an entry remove its signature, because a signature covers the hash (ADR-0033
/// clause 6): the entry is offered to nobody until it is signed again.
/// Verifies: ADR-0033
#[tokio::test]
async fn new_bytes_on_an_entry_remove_its_signature() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"first").await;
    sign_every_entry(&server, support::AGENT_TYPE, "1.0.0").await;
    let replaced = upload_entry(&server, support::AGENT_TYPE, "1.0.0", HOST, b"second").await;
    assert_eq!(replaced.status(), 200);
    let set: serde_json::Value = replaced.json().await.expect("json");
    assert_eq!(set["entries"][0]["signature_state"], "missing");
    assert!(set["entries"][0].get("signature").is_none());
}

/// The routes ADR-0033 removed answer `404`, as for anything that does not exist: the entry's
/// `…/source`, and the Deployment's `…/signatures/…` (ADR-0033 clause 9).
/// Verifies: ADR-0033
#[tokio::test]
async fn the_source_route_and_the_deployment_signature_routes_are_gone() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"v1").await;
    put_deployment(&server, "stable", &[("channel", "stable")]).await;
    let client = reqwest::Client::new();
    let source = format!(
        "{}/entries/{HOST}/source",
        set_url(&server, support::AGENT_TYPE, "1.0.0")
    );
    let response = client
        .put(&source)
        .json(&serde_json::json!({
            "url": "https://example.com/otelcol.tar.gz",
            "sha256": "00".repeat(32),
        }))
        .send()
        .await
        .expect("put source");
    assert_eq!(response.status(), 404, "PUT {source}");
    let signatures = format!(
        "{}/signatures/{}/1.0.0/linux/amd64",
        deployment_url(&server, "stable"),
        support::AGENT_TYPE
    );
    let response = client
        .put(&signatures)
        .json(&serde_json::json!({ "signature": hex::encode([7u8; 64]) }))
        .send()
        .await
        .expect("put signature");
    assert_eq!(response.status(), 404, "PUT {signatures}");
    let response = client
        .delete(&signatures)
        .send()
        .await
        .expect("delete signature");
    assert_eq!(response.status(), 404, "DELETE {signatures}");
}

/// With `[packages] verification_key` armed, the Server reports a signature over the entry's
/// statement `valid` and a wrong one `invalid` — and stores both, because it only reports
/// (ADR-0033 clause 7). The wrong one is offered all the same: the Agent's check decides.
/// Verifies: ADR-0033
#[tokio::test]
async fn with_a_verification_key_the_server_reports_valid_and_invalid_and_stores_both() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair");
    let public = ring::signature::KeyPair::public_key(&keypair)
        .as_ref()
        .to_vec();
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PackageStore::open(dir.path().join("packages"))
        .expect("store")
        .with_verifier(Some(Box::new(fleet_server::config::Ed25519Verifier::new(
            public,
        ))));
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            )),
    );
    let (addr, rest_addr) =
        support::serve(state.clone(), fleet_server::transport::Admission::open()).await;
    let server = TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    };

    create_set(&server, support::AGENT_TYPE, "1.0.0").await;
    for (platform, bytes) in [
        ("linux/amd64", b"linux".as_slice()),
        ("windows/amd64", b"windows"),
    ] {
        let response = upload_entry(&server, support::AGENT_TYPE, "1.0.0", platform, bytes).await;
        assert_eq!(response.status(), 200);
    }
    let statement =
        |bytes: &[u8]| fleet_core::package::statement(support::AGENT_TYPE, "1.0.0", &sha256(bytes));
    let good = hex::encode(keypair.sign(&statement(b"linux")));
    // Signed over the other entry's bytes: a real signature, for something else.
    let wrong = hex::encode(keypair.sign(&statement(b"linux")));
    for (os, signature) in [("linux", good), ("windows", wrong)] {
        let response = sign_entry(
            &server,
            support::AGENT_TYPE,
            "1.0.0",
            os,
            "amd64",
            &signature,
        )
        .await;
        assert_eq!(
            response.status(),
            200,
            "{os}: an invalid one is not refused"
        );
    }
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{}/api/v1/packages", server.rest_addr))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let entries = &listed[0]["entries"];
    assert_eq!(entries[0]["os"], "linux");
    assert_eq!(entries[0]["signature_state"], "valid");
    assert_eq!(entries[1]["os"], "windows");
    assert_eq!(entries[1]["signature_state"], "invalid");
    assert!(entries[1]["signature"].is_string(), "and stored");
}

/// Has `stable` hold `version` and signs its entry with a fixed signature.
async fn hold_and_sign(server: &TestServer, version: &str) {
    let held = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/{version}",
            deployment_url(server, "stable"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(held.status(), 200);
    let signed = reqwest::Client::new()
        .put(format!(
            "{}/entries/linux/amd64/signature",
            set_url(server, support::AGENT_TYPE, version)
        ))
        .json(&serde_json::json!({ "signature": hex::encode([7u8; 64]) }))
        .send()
        .await
        .expect("sign");
    assert_eq!(signed.status(), 200);
}

/// Whether `stable` holds `version`.
async fn stable_holds(server: &TestServer, version: &str) -> bool {
    let view: serde_json::Value = reqwest::Client::new()
        .get(deployment_url(server, "stable"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    view["packages"]
        .as_array()
        .expect("array")
        .iter()
        .any(|package| package["version"] == version)
}

/// A deleted Package leaves the Deployments that held it, and its signature with it: a Package
/// created again under the same identity, with other bytes, is held by nobody and signed by
/// nobody until an operator says so.
/// Verifies: ADR-0033, ADR-0034
#[tokio::test]
async fn a_deleted_package_leaves_every_deployment_with_its_signatures() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"v1").await;
    put_deployment(&server, "stable", &[("channel", "stable")]).await;
    hold_and_sign(&server, "1.0.0").await;

    let deleted = reqwest::Client::new()
        .delete(set_url(&server, support::AGENT_TYPE, "1.0.0"))
        .send()
        .await
        .expect("delete");
    assert!(deleted.status().is_success(), "{}", deleted.status());
    assert!(!stable_holds(&server, "1.0.0").await);

    upload(&server, support::AGENT_TYPE, "1.0.0", b"other bytes").await;
    assert!(
        !stable_holds(&server, "1.0.0").await,
        "the new Package is not held by the Deployment the old one was"
    );
    let package: serde_json::Value = reqwest::Client::new()
        .get(set_url(&server, support::AGENT_TYPE, "1.0.0"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(package["entries"][0]["signature_state"], "missing");
}

/// The aim stays editable and the channel keeps what it holds — moving a Deployment between channels is
/// how a rollout proceeds, and it is not a change of bytes.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_deployments_aim_is_editable_and_deleting_it_is_its_own_act() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"v1").await;
    put_deployment(&server, "canary", &[("channel", "canary")]).await;
    let base = deployment_url(&server, "canary");
    reqwest::Client::new()
        .put(format!("{base}/packages/{}/1.0.0", support::AGENT_TYPE))
        .send()
        .await
        .expect("put package");

    let widened = reqwest::Client::new()
        .put(format!("{base}/selector"))
        .json(&serde_json::json!({ "selector": { "channel": "stable" } }))
        .send()
        .await
        .expect("re-aim");
    assert_eq!(widened.status(), 200);
    let view: serde_json::Value = widened.json().await.expect("json");
    assert_eq!(view["selector"]["channel"], "stable");
    assert_eq!(
        view["packages"][0]["agent_type"],
        support::AGENT_TYPE,
        "re-aiming keeps what the channel holds"
    );

    // Re-aiming something that is not there is a 404, not a Deployment conjured out of a URL.
    let missing = reqwest::Client::new()
        .put(format!("{}/selector", deployment_url(&server, "nosuch")))
        .json(&serde_json::json!({ "selector": { "channel": "stable" } }))
        .send()
        .await
        .expect("re-aim");
    assert_eq!(missing.status(), 404);

    let deleted = reqwest::Client::new()
        .delete(&base)
        .send()
        .await
        .expect("delete");
    assert_eq!(deleted.status(), 204);
    let again = reqwest::Client::new()
        .delete(&base)
        .send()
        .await
        .expect("delete");
    assert_eq!(again.status(), 404);
}

/// A Deployment that has released something cannot be deleted while the assignment names it, nor
/// can the Package it pinned (ADR-0034 clause 8). The refusal says how many Agents pin it, and the
/// offer stands with the entry's own signature (ADR-0033). Once the Agent is released through
/// another Deployment, both go, and the deleted Package leaves the channel that held it.
/// Verifies: ADR-0033, ADR-0034
#[tokio::test]
async fn a_deployment_that_released_a_package_refuses_to_be_deleted() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    upload(&server, support::AGENT_TYPE, "1.0.0", b"the-binary").await;
    let signed = sign_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        "linux",
        "amd64",
        &hex::encode([7u8; 64]),
    )
    .await;
    assert_eq!(signed.status(), 200);
    let channel = everyone(&server, "1.0.0").await;
    assert_eq!(rollout_ring(&server, &channel).await["assigned_agents"], 1);

    let refused = reqwest::Client::new()
        .delete(deployment_url(&server, &channel))
        .send()
        .await
        .expect("delete");
    assert_eq!(refused.status(), 409);
    let why = refused.text().await.expect("body");
    assert!(why.contains("1 Agent"), "the refusal says how many: {why}");

    // The offer is untouched, signature and all.
    let mut report = full_report(&uid, "edge-01", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("an offer");
    assert_eq!(
        offer.packages[support::AGENT_TYPE]
            .file
            .as_ref()
            .expect("a file")
            .signature,
        vec![7u8; 64]
    );

    // The Package it pinned is not deleted either.
    let package = reqwest::Client::new()
        .delete(set_url(&server, support::AGENT_TYPE, "1.0.0"))
        .send()
        .await
        .expect("delete package");
    assert_eq!(package.status(), 409);
    let why = package.text().await.expect("body");
    assert!(why.contains("1 Agent"), "the refusal says how many: {why}");

    // Released through another Deployment that carries only a Configuration, the Agent pins
    // neither any more — and then both go.
    assert_eq!(
        put_deployment(&server, &channel, &[("channel", "nobody")])
            .await
            .status(),
        200
    );
    support::save_configuration(server.rest_addr, "base", "receivers: {}", "").await;
    support::deploy(
        server.rest_addr,
        "other",
        &[("service.name", support::AGENT_TYPE)],
        &["base"],
    )
    .await;
    let package = reqwest::Client::new()
        .delete(set_url(&server, support::AGENT_TYPE, "1.0.0"))
        .send()
        .await
        .expect("delete package");
    assert_eq!(package.status(), 204);
    let emptied = ring_view(&server, &channel).await;
    assert_eq!(
        emptied["packages"],
        serde_json::json!([]),
        "a deleted Package leaves every Deployment that held it"
    );
    let deleted = reqwest::Client::new()
        .delete(deployment_url(&server, &channel))
        .send()
        .await
        .expect("delete");
    assert_eq!(deleted.status(), 204);
}

/// One Package held by two Deployments is offered with the same signature through both: the
/// signature is the entry's, and one serves every Deployment that holds it (ADR-0033 clause 6).
/// Verifies: ADR-0033
#[tokio::test]
async fn one_package_in_two_deployments_is_offered_with_the_same_signature() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "1.0.0", b"the-binary").await;
    let signed = sign_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        "linux",
        "amd64",
        &hex::encode([3u8; 64]),
    )
    .await;
    assert_eq!(signed.status(), 200);

    // Two hosts, two disjoint channels, one Package signed once.
    let a = InstanceUid::default();
    let b = InstanceUid::default();
    for (uid, name) in [(&a, "host-a"), (&b, "host-b")] {
        let mut report = full_report(uid, name, 1);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        exchange(&server, &report).await;
    }
    for (channel, host) in [("channel-a", "host-a"), ("channel-b", "host-b")] {
        ring_holding(
            &server,
            channel,
            &[("service.instance.name", host)],
            "1.0.0",
        )
        .await;
        assert_eq!(rollout_ring(&server, channel).await["assigned_agents"], 1);
    }

    for (uid, name) in [(&a, "host-a"), (&b, "host-b")] {
        let mut report = full_report(uid, name, 2);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        let offer = exchange(&server, &report)
            .await
            .packages_available
            .expect("an offer");
        assert_eq!(
            offer.packages[support::AGENT_TYPE]
                .file
                .as_ref()
                .expect("a file")
                .signature,
            vec![3u8; 64],
            "{name} is offered the entry's one signature"
        );
    }
}

/// **The rule the whole conflict model turns on.** A conflict takes the *candidate* away and never
/// a standing assignment: an Agent already rolled out to keeps its offer, because nothing
/// distributes — or un-distributes — by itself (ADR-0025). Creating an overlapping channel must not
/// withdraw software from a running host, and that is one `if` away from being wrong.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_conflict_takes_the_candidate_away_and_leaves_the_assignment_standing() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    upload(&server, support::AGENT_TYPE, "1.0.0", b"the-binary").await;
    let channel = everyone(&server, "1.0.0").await;
    assert_eq!(rollout_ring(&server, &channel).await["assigned_agents"], 1);
    async fn offered(
        server: &TestServer,
        uid: &InstanceUid,
        sequence: u64,
    ) -> Option<opamp::proto::PackagesAvailable> {
        let mut report = full_report(uid, "edge-01", sequence);
        report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
        exchange(server, &report).await.packages_available
    }
    let before = offered(&server, &uid, 2)
        .await
        .expect("the released package");

    // A second channel that claims the same Agent. Now nothing new can be proposed to it…
    upload(&server, support::AGENT_TYPE, "2.0.0", b"the-next-one").await;
    ring_holding(&server, "second", &[("os.type", "linux")], "2.0.0").await;
    let view = &server.state.snapshot()[0];
    assert!(
        view.package_conflict.is_some(),
        "the view says why nothing new is proposed"
    );
    assert!(
        view.pending_packages.is_empty(),
        "and proposes nothing while it stands"
    );

    // …but what it already has is untouched: the same version, the same hash, still offered.
    assert_eq!(
        view.assigned_package,
        format!("{}@1.0.0", support::AGENT_TYPE)
    );
    let after = offered(&server, &uid, 3)
        .await
        .expect("the assignment still composes an offer");
    assert_eq!(
        after.packages[support::AGENT_TYPE].version,
        before.packages[support::AGENT_TYPE].version
    );
    assert_eq!(after.all_packages_hash, before.all_packages_hash);
}

/// The per-Agent act refuses to pick a side (ADR-0026 point 30): naming a channel while a second one
/// also claims the Agent is `409`, even though the operator has said which they mean. Honouring it
/// would sidestep the conflict for good and make this path the way into a state the channel-wide act
/// forbids.
/// Verifies: ADR-0026
#[tokio::test]
async fn the_per_agent_act_refuses_to_pick_a_side() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    upload(&server, support::AGENT_TYPE, "1.0.0", b"one").await;
    upload(&server, support::AGENT_TYPE, "2.0.0", b"two").await;
    ring_holding(
        &server,
        "by-name",
        &[("service.name", support::AGENT_TYPE)],
        "1.0.0",
    )
    .await;

    // With one channel the per-Agent act works, which is what makes the refusal below meaningful.
    let ok = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/agents/{uid}/rollout",
            server.rest_addr
        ))
        .json(&serde_json::json!({ "deployment": "by-name" }))
        .send()
        .await
        .expect("rollout to agent");
    assert_eq!(ok.status(), 200);

    ring_holding(&server, "by-platform", &[("os.type", "linux")], "2.0.0").await;
    for named in ["by-name", "by-platform"] {
        let refused = reqwest::Client::new()
            .post(format!(
                "http://{}/api/v1/agents/{uid}/rollout",
                server.rest_addr
            ))
            .json(&serde_json::json!({ "deployment": named }))
            .send()
            .await
            .expect("rollout to agent");
        assert_eq!(
            refused.status(),
            409,
            "naming {named:?} is not a way past the conflict"
        );
    }
}

/// What a standing offer travels with is frozen. The entry's signature is a write to an assigned
/// Package's entries and refused `409` like any other (ADR-0033 clause 6, ADR-0025): the re-offer
/// gate does not cover the signature, so one changed under a standing offer would never reach the
/// Agent. **The channel freezes nothing** (ADR-0034 clause 7): the assignment pins the Package
/// itself, so taking it out of the channel or swapping the version it holds leaves every standing
/// offer exactly as it was, and is how a rollout proceeds.
/// Verifies: ADR-0033, ADR-0034
#[tokio::test]
async fn a_released_package_freezes_its_entries_and_not_the_ring() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    upload(&server, support::AGENT_TYPE, "1.0.0", b"the-binary").await;
    upload(&server, support::AGENT_TYPE, "2.0.0", b"the-next-one").await;
    let signed = sign_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        "linux",
        "amd64",
        &hex::encode([7u8; 64]),
    )
    .await;
    assert_eq!(
        signed.status(),
        200,
        "before the act, the entry is editable"
    );
    let channel = everyone(&server, "1.0.0").await;
    assert_eq!(rollout_ring(&server, &channel).await["assigned_agents"], 1);

    // Now every write against what it released answers 409, and says what to do instead.
    let entry_signature = format!(
        "{}/entries/linux/amd64/signature",
        set_url(&server, support::AGENT_TYPE, "1.0.0")
    );
    let refused = sign_entry(
        &server,
        support::AGENT_TYPE,
        "1.0.0",
        "linux",
        "amd64",
        &hex::encode([9u8; 64]),
    )
    .await;
    assert_eq!(
        refused.status(),
        409,
        "PUT {entry_signature} must be frozen"
    );
    let unsigned = reqwest::Client::new()
        .delete(&entry_signature)
        .send()
        .await
        .expect("remove the signature");
    assert_eq!(
        unsigned.status(),
        409,
        "DELETE {entry_signature} must be frozen"
    );
    let removal = format!(
        "{}/packages/{}/1.0.0",
        deployment_url(&server, &channel),
        support::AGENT_TYPE
    );
    let removed = reqwest::Client::new()
        .delete(&removal)
        .send()
        .await
        .expect("remove");
    assert_eq!(removed.status(), 200, "DELETE {removal} is not frozen");

    // Nor is pointing the channel at the next version — that is the ordinary upgrade.
    let swapped = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/2.0.0?replace=true",
            deployment_url(&server, &channel),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("swap");
    assert_eq!(
        swapped.status(),
        200,
        "a channel must stay updatable, or a fleet cannot be updated at all"
    );

    // Deleting the signature is frozen too, and the offer still carries the one that was released.
    let frozen = reqwest::Client::new()
        .delete(&entry_signature)
        .send()
        .await
        .expect("delete signature");
    assert_eq!(frozen.status(), 409);
    let mut report = full_report(&uid, "edge-01", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("an offer");
    assert_eq!(
        offer.packages[support::AGENT_TYPE]
            .file
            .as_ref()
            .expect("a file")
            .signature,
        vec![7u8; 64]
    );
}

/// ADR-0026 point 17: the hash an Agent verifies against is readable off the package, so "did this
/// host take my bytes" is answerable without trusting a status field.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_packages_entry_shows_the_hash_an_agent_verifies_against() {
    let (server, _scratch) = spawn_with_packages().await;
    let artifact = b"the-binary";
    upload(&server, support::AGENT_TYPE, "1.0.0", artifact).await;

    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{}/api/v1/packages", server.rest_addr))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let entry = &listed[0]["entries"][0];
    assert_eq!(
        entry["content_hash"].as_str().expect("content_hash"),
        hex::encode(sha256(artifact)),
        "the SHA-256 an Agent checks what it downloaded against"
    );

    // And the package hash is the one the offer carries, so the two can be compared by eye.
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;
    let channel = everyone(&server, "1.0.0").await;
    assert_eq!(rollout_ring(&server, &channel).await["assigned_agents"], 1);
    let mut report = full_report(&uid, "edge-01", 2);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let offer = exchange(&server, &report)
        .await
        .packages_available
        .expect("an offer");
    assert_eq!(
        entry["package_hash"].as_str().expect("package_hash"),
        hex::encode(&offer.packages[support::AGENT_TYPE].hash),
        "the hash the Agent echoes back once it is in sync"
    );
}

/// ADR-0026 point 25: the fleet view tells apart the states that would otherwise be one empty row,
/// because the operator's next move differs in each. An Agent in **no channel** has to be labelled;
/// one in a channel that holds nothing for it needs a package uploaded; one with something waiting
/// needs a press.
/// Verifies: ADR-0026
#[tokio::test]
async fn the_fleet_view_tells_no_ring_apart_from_a_ring_with_nothing_for_this_agent() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    // 1. No channel claims it — the ordinary state right after an enrolment.
    let view = &server.state.snapshot()[0];
    assert_eq!(view.deployment, "", "no channel claims it");
    assert_eq!(view.assigned_deployment, "");
    assert!(view.pending_packages.is_empty());
    assert!(
        view.package_conflict.is_none(),
        "and that is not a conflict"
    );

    // 2. A channel claims it, but holds nothing it can take: a Package for another Agent type.
    assert_eq!(
        put_deployment(&server, "stable", &[("service.name", support::AGENT_TYPE)])
            .await
            .status(),
        200
    );
    create_set(&server, "promtail", "1.0.0").await;
    let response = upload_entry(&server, "promtail", "1.0.0", HOST, b"p").await;
    assert_eq!(response.status(), 200);
    let response = reqwest::Client::new()
        .put(format!(
            "{}/packages/promtail/1.0.0",
            deployment_url(&server, "stable")
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(response.status(), 200);

    let view = &server.state.snapshot()[0];
    assert_eq!(view.deployment, "stable", "the channel claims it now");
    assert!(
        view.pending_packages.is_empty(),
        "but proposes nothing — the distinction the operator needs"
    );

    // 3. Give the channel something it can take: now it waits for a press.
    upload(&server, support::AGENT_TYPE, "1.0.0", b"the-binary").await;
    let response = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/1.0.0",
            deployment_url(&server, "stable"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(response.status(), 200);
    let view = &server.state.snapshot()[0];
    assert_eq!(view.deployment, "stable");
    assert_eq!(view.pending_packages.len(), 1, "now something waits");
    assert_eq!(view.pending_packages[0].deployment, "stable");
}

/// A Deployment holding a Package with an unsigned entry is not rolled out: `409`, naming the
/// Package and the platform, and nothing is released (ADR-0026 clause 29, ADR-0033).
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn a_rollout_of_a_deployment_with_an_unsigned_package_is_refused_naming_it() {
    let (server, _scratch) = spawn_with_packages().await;
    upload(&server, support::AGENT_TYPE, "3.0.0", b"the-binary").await;
    assert_eq!(
        put_deployment(
            &server,
            "unsigned",
            &[("service.name", support::AGENT_TYPE)]
        )
        .await
        .status(),
        200
    );
    let response = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/3.0.0",
            deployment_url(&server, "unsigned"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(response.status(), 200);

    let refused = reqwest::Client::new()
        .post(format!("{}/rollout", deployment_url(&server, "unsigned")))
        .send()
        .await
        .expect("rollout");
    assert_eq!(refused.status(), 409);
    let body = refused.text().await.expect("body");
    assert!(
        body.contains("3.0.0") && body.contains("linux/amd64"),
        "{body}"
    );
}

/// The per-Agent act is refused the same way: naming a Deployment holding a Package with an
/// unsigned entry is `409`, naming the Package and the platform, and the Agent is offered nothing.
/// Once the entry is signed, the same act goes through.
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn the_per_agent_act_refuses_a_deployment_with_an_unsigned_package() {
    let (server, _scratch) = spawn_with_packages().await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "edge-01", 1);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    exchange(&server, &report).await;

    upload(&server, support::AGENT_TYPE, "3.0.0", b"the-binary").await;
    assert_eq!(
        put_deployment(
            &server,
            "unsigned",
            &[("service.name", support::AGENT_TYPE)]
        )
        .await
        .status(),
        200
    );
    let response = reqwest::Client::new()
        .put(format!(
            "{}/packages/{}/3.0.0",
            deployment_url(&server, "unsigned"),
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(response.status(), 200);

    let act = || {
        reqwest::Client::new()
            .post(format!(
                "http://{}/api/v1/agents/{uid}/rollout",
                server.rest_addr
            ))
            .json(&serde_json::json!({ "deployment": "unsigned" }))
            .send()
    };
    let refused = act().await.expect("rollout to agent");
    assert_eq!(refused.status(), 409);
    let body = refused.text().await.expect("body");
    assert!(
        body.contains("3.0.0") && body.contains("linux/amd64"),
        "{body}"
    );
    let mut next = full_report(&uid, "edge-01", 2);
    next.capabilities |= AgentCapabilities::AcceptsPackages as u64;
    let answer = exchange(&server, &next).await;
    assert!(
        answer
            .packages_available
            .is_none_or(|offer| offer.packages.is_empty()),
        "nothing unsigned is offered"
    );

    sign_every_entry(&server, support::AGENT_TYPE, "3.0.0").await;
    assert_eq!(act().await.expect("rollout to agent").status(), 200);
}

/// Every `upload-*.tmp` file under `dir` — what an upload in progress stages its artifact into.
fn staged_uploads(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("upload-") && name.ends_with(".tmp"))
            {
                found.push(path);
            }
        }
    }
    found
}

/// An upload that stops arriving is answered `408` and leaves nothing staged behind: the floor
/// on every body holds on the Operator plane's longest route too (ADR-0013 clause 14).
/// Verifies: ADR-0013
#[tokio::test]
async fn an_upload_that_stops_is_answered_408_and_leaves_nothing_staged() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    opamp::tls::install_ring_provider();
    let window = std::time::Duration::from_millis(300);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            )),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let operators = fleet_server::operator_app(state, None);
    tokio::spawn(
        opamp::server::listen::Listener::new(listener, opamp::server::listen::Handle::new())
            .with_pace(window, 1024)
            .serve(operators),
    );
    let set = format!(
        "http://127.0.0.1:{port}/api/v1/packages/{}/1.0.0",
        support::AGENT_TYPE
    );
    let created = reqwest::Client::new()
        .put(&set)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(created.status(), 200);

    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket
        .write_all(
            format!(
                "PUT /api/v1/packages/{}/1.0.0/entries/linux/amd64 HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Length: 100000\r\n\r\npartial",
                support::AGENT_TYPE
            )
            .as_bytes(),
        )
        .await
        .expect("write");
    let mut buffer = vec![0u8; 1024];
    let read = tokio::time::timeout(window * 10, socket.read(&mut buffer))
        .await
        .expect("an answer in time")
        .expect("read");
    assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 408"));
    assert!(
        staged_uploads(dir.path()).is_empty(),
        "{:?}",
        staged_uploads(dir.path())
    );
}

/// Two uploads of one entry at once each stream to a staging file of their own: the one that ends
/// last is stored whole, and the other neither corrupts nor deletes it.
/// Verifies: ADR-0026
#[tokio::test]
async fn two_uploads_of_one_entry_at_once_do_not_share_a_staging_file() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(
        opamp::server::listen::Listener::new(listener, opamp::server::listen::Handle::new())
            .serve(fleet_server::operator_app(state, None)),
    );
    let set = format!(
        "http://127.0.0.1:{port}/api/v1/packages/{}/1.0.0",
        support::AGENT_TYPE
    );
    let created = reqwest::Client::new()
        .put(&set)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(created.status(), 200);

    // The first upload sends half its body and waits.
    let first = vec![b'a'; 200];
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket
        .write_all(
            format!(
                "PUT /api/v1/packages/{}/1.0.0/entries/linux/amd64 HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                support::AGENT_TYPE,
                first.len()
            )
            .as_bytes(),
        )
        .await
        .expect("write");
    socket.write_all(&first[..100]).await.expect("write");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while staged_uploads(dir.path()).is_empty() {
        assert!(std::time::Instant::now() < deadline, "nothing was staged");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // A second upload of the same entry runs from start to end meanwhile.
    let second = reqwest::Client::new()
        .put(format!("{set}/entries/linux/amd64"))
        .body(vec![b'b'; 50])
        .send()
        .await
        .expect("put entry");
    assert_eq!(second.status(), 200);

    socket.write_all(&first[100..]).await.expect("write");
    let mut answer = Vec::new();
    socket.read_to_end(&mut answer).await.expect("read");
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    // The blobs: the second upload's went with the entry the first one replaced (ADR-0037).
    let stored: Vec<_> = std::fs::read_dir(dir.path().join("packages/blobs"))
        .expect("blobs")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| !path.to_string_lossy().ends_with(".tmp"))
        .collect();
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(
        std::fs::read(&stored[0]).expect("artifact"),
        first,
        "the upload that ended last is stored whole"
    );
    assert!(staged_uploads(dir.path()).is_empty());
}

/// An upload still arriving counts against the store's ceiling, so uploads sent at once cannot
/// pass it together; and one cut off mid-body — here by the listener shutting down, which drops
/// the request — leaves nothing staged behind.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_upload_in_progress_counts_against_the_ceiling_and_a_cancelled_one_leaves_nothing() {
    use tokio::io::AsyncWriteExt as _;

    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            ))
            .with_max_total_package_bytes(150),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = opamp::server::listen::Handle::new();
    let served = tokio::spawn(
        opamp::server::listen::Listener::new(listener, handle.clone())
            .serve(fleet_server::operator_app(state, None)),
    );
    let set = format!(
        "http://127.0.0.1:{port}/api/v1/packages/{}/1.0.0",
        support::AGENT_TYPE
    );
    let created = reqwest::Client::new()
        .put(&set)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(created.status(), 200);

    // A hundred bytes of an announced two hundred, and then nothing.
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    socket
        .write_all(
            format!(
                "PUT /api/v1/packages/{}/1.0.0/entries/linux/amd64 HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Length: 200\r\n\r\n{}",
                support::AGENT_TYPE,
                "x".repeat(100)
            )
            .as_bytes(),
        )
        .await
        .expect("write");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while staged_uploads(dir.path())
        .iter()
        .map(|path| std::fs::metadata(path).map_or(0, |m| m.len()))
        .sum::<u64>()
        < 100
    {
        assert!(std::time::Instant::now() < deadline, "nothing was staged");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let second = reqwest::Client::new()
        .put(format!("{set}/entries/linux/arm64"))
        .body(vec![b'y'; 60])
        .send()
        .await
        .expect("put entry");
    assert_eq!(
        second.status(),
        507,
        "an upload passed the ceiling beside one still arriving"
    );

    handle.shutdown();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), served).await;
    drop(socket);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !staged_uploads(dir.path()).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "a cancelled upload stayed staged: {:?}",
            staged_uploads(dir.path())
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A member over its rate is answered `429` with `Retry-After: 30` and not served the artifact;
/// once its bucket refills the download is served again, and the refusals counted no failure
/// toward the failed-admission throttle, which here backs off after a single one.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_download_past_the_limit_is_answered_429_after_thirty_seconds() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = support::ManualClock::new();
    let store = PackageStore::open(dir.path().join("packages")).expect("store");
    let limits = fleet_server::agent_rate::Limits {
        messages_per_sec: 1,
        burst: 1,
        gateway_messages_per_sec: 1,
        gateway_burst: 1,
    };
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(&dir.path().join("packages"), store).expect("deployments"),
            ))
            .with_agent_rate(Some(Arc::new(fleet_server::agent_rate::AgentRate::new(
                limits,
                100,
                clock.clone(),
            )))),
    );
    let throttle = fleet_server::throttle::Throttle::new(
        fleet_server::throttle::Limits {
            max_failures: 1,
            window_secs: 60,
            backoff_secs: 300,
        },
        clock.clone(),
    );
    let (addr, rest_addr) = support::serve(
        state.clone(),
        fleet_server::transport::Admission::open().with_throttle(Arc::new(throttle)),
    )
    .await;
    let server = TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    };
    upload(&server, support::AGENT_TYPE, "1.2.3", b"the-new-binary").await;
    let url = format!(
        "http://{addr}/api/v1/packages/{}/1.2.3/file?os=linux&arch=amd64",
        support::AGENT_TYPE
    );
    let download = || reqwest::Client::new().get(&url).send();

    assert_eq!(download().await.expect("download").status(), 200);
    for _ in 0..2 {
        let refused = download().await.expect("download");
        assert_eq!(refused.status(), 429);
        assert_eq!(
            refused
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30"),
            "the rate limit's 30 s, never the failure back-off's 300"
        );
        assert_ne!(
            refused.bytes().await.expect("body").as_ref(),
            b"the-new-binary"
        );
    }
    clock.advance(std::time::Duration::from_secs(1));
    let served = download().await.expect("download");
    assert_eq!(
        served.status(),
        200,
        "no back-off for a member over its rate"
    );
    assert_eq!(
        served.bytes().await.expect("bytes").as_ref(),
        b"the-new-binary"
    );
}

/// A new Package takes only a SemVer version, and the refusal says so (ADR-0043 clause 1).
/// Verifies: ADR-0043
#[tokio::test]
async fn a_package_is_created_only_under_a_semver_version() {
    let (server, _scratch) = spawn_with_packages().await;
    let refused = reqwest::Client::new()
        .put(set_url(&server, "otelcol", "1.19"))
        .send()
        .await
        .expect("put set");
    assert_eq!(refused.status(), 400);
    let body: serde_json::Value = refused.json().await.expect("json");
    let why = body["error"].as_str().expect("an error text");
    assert!(
        why.contains("\"1.19\"") && why.contains("SemVer") && why.contains("1.19.0"),
        "the refusal names the version and the rule: {why}"
    );
    assert!(server.state.packages().expect("store").list().is_empty());

    create_set(&server, "otelcol", "1.19.0").await;
}

/// A Package an older Server stored under `1.19` is read, and nothing new is done with it: an
/// entry, a signature and adding it to a Deployment are each refused `400`, while it can be read
/// and deleted once nothing pins it (ADR-0043 clause 3).
/// Verifies: ADR-0043
#[tokio::test]
async fn a_stored_package_whose_version_is_not_semver_takes_no_write_and_can_be_deleted() {
    use fleet_server::packages::{PackageId, Platform};

    async fn refused_naming_semver(response: reqwest::Response, what: &str) {
        assert_eq!(response.status(), 400, "{what}");
        let body: serde_json::Value = response.json().await.expect("json");
        let why = body["error"].as_str().expect("an error text");
        assert!(
            why.contains("\"1.19\"") && why.contains("SemVer"),
            "{what}: {why}"
        );
    }

    let (server, _scratch) = spawn_with_packages().await;
    let store = server.state.packages().expect("store");
    let legacy = PackageId::load(support::AGENT_TYPE, "1.19").expect("a token");
    store.create(&legacy).expect("create");
    store
        .put_entry(
            &legacy,
            &Platform::new("linux", "amd64").expect("platform"),
            b"old".to_vec(),
        )
        .expect("entry");

    let read = reqwest::Client::new()
        .get(set_url(&server, support::AGENT_TYPE, "1.19"))
        .send()
        .await
        .expect("get");
    assert_eq!(read.status(), 200, "it is read");

    refused_naming_semver(
        upload_entry(&server, support::AGENT_TYPE, "1.19", HOST, b"new").await,
        "an entry",
    )
    .await;
    refused_naming_semver(
        sign_entry(
            &server,
            support::AGENT_TYPE,
            "1.19",
            "linux",
            "amd64",
            &"01".repeat(64),
        )
        .await,
        "a signature",
    )
    .await;
    assert_eq!(
        put_deployment(&server, "stable", &[("service.name", support::AGENT_TYPE)])
            .await
            .status(),
        200
    );
    refused_naming_semver(
        reqwest::Client::new()
            .put(format!(
                "{}/packages/{}/1.19",
                deployment_url(&server, "stable"),
                support::AGENT_TYPE
            ))
            .send()
            .await
            .expect("put deployment package"),
        "adding it to a Deployment",
    )
    .await;

    let deleted = reqwest::Client::new()
        .delete(set_url(&server, support::AGENT_TYPE, "1.19"))
        .send()
        .await
        .expect("delete");
    assert_eq!(deleted.status(), 204, "nothing pins it, so it is deleted");
    assert!(store.summary(&legacy).is_none());
}
