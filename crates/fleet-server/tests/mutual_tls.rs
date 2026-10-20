//! Mutual TLS, enrolment and the CSR flow, end to end over the real listener (ADR-0021).
//!
//! What these cover is the part that cannot be unit-tested: the handshake actually carrying a
//! client certificate into the OpAMP route, and the admission rule that the certificate is the
//! whole of it. The signing itself is covered where it lives, in `fleet_server::ca`.

use std::sync::Arc;

use fleet_server::ca::ClientCa;
use fleet_server::fleet::AppState;
use fleet_server::revocation::{CertId, Revocations};
use fleet_server::transport::Admission;
use opamp::proto::{
    AgentCapabilities, AgentToServer, CertificateRequest, ConnectionSettingsRequest,
    OpAmpConnectionSettingsRequest, ServerErrorResponseType, ServerToAgent,
};
use opamp::uid::InstanceUid;
use prost::Message;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

/// A throwaway PKI: one CA, a server certificate for `localhost`, and the ability to mint a client
/// certificate from it — the shape an operator's `[client_ca]` has.
struct Pki {
    ca_pem: String,
    ca_key_pem: String,
}

impl Pki {
    fn new() -> Self {
        Pki::named("opamp-fleet-test-ca")
    }

    /// A CA of its own subject — what a bootstrap CA must have to be told apart from the client CA.
    fn named(subject: &str) -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec![subject.to_string()]).expect("ca params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, subject);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        Pki {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    fn issuer(&self) -> Issuer<'static, KeyPair> {
        let key = KeyPair::from_pem(&self.ca_key_pem).expect("ca key");
        Issuer::from_ca_cert_pem(&self.ca_pem, key).expect("issuer")
    }

    /// A CA whose subject has several parts, one with a comma in it — what an issuer typed as
    /// text would fail to match.
    fn with_organisation() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params
            .distinguished_name
            .push(rcgen::DnType::CountryName, "DE");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Acme, Inc.");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fleet client CA");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        Pki {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    /// A certificate and key signed by this CA naming `host` the way the Server's own signer does
    /// (ADR-0021 clause 7): `urn:opamp-fleet:host:<host>`, and no other name.
    fn issue_to_host(&self, host: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("{}{host}", fleet_server::ca::HOST_URI_PREFIX)
                .try_into()
                .expect("uri"),
        ));
        let cert = params.signed_by(&key, &self.issuer()).expect("signed");
        (cert.pem(), key.serialize_pem())
    }

    /// A certificate and key naming `host` like [`issue_to_host`](Self::issue_to_host), whose
    /// subject carries `subject` — an operator's provisioned certificate with the values a Host
    /// carries (ADR-0035 clause 1).
    fn issue_to_host_with(
        &self,
        host: &str,
        subject: &[(rcgen::DnType, &str)],
    ) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        for (kind, value) in subject {
            params.distinguished_name.push(kind.clone(), *value);
        }
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("{}{host}", fleet_server::ca::HOST_URI_PREFIX)
                .try_into()
                .expect("uri"),
        ));
        let cert = params.signed_by(&key, &self.issuer()).expect("signed");
        (cert.pem(), key.serialize_pem())
    }

    /// A certificate and key signed by this CA, for `name`.
    fn issue(&self, name: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec![name.to_string()]).expect("params");
        let cert = params.signed_by(&key, &self.issuer()).expect("signed");
        (cert.pem(), key.serialize_pem())
    }

    /// A bootstrap certificate and key signed by this CA, for `name`, naming the customer and the
    /// site an approval requires of every bootstrap certificate (ADR-0036 clause 3).
    fn issue_bootstrap(&self, name: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Kunde GmbH");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, "Werk Nord");
        let cert = params.signed_by(&key, &self.issuer()).expect("signed");
        (cert.pem(), key.serialize_pem())
    }
}

fn report(uid: &InstanceUid) -> AgentToServer {
    AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num: 1,
        capabilities: AgentCapabilities::ReportsStatus as u64,
        ..Default::default()
    }
}

fn csr_for(name: &str) -> (Vec<u8>, KeyPair) {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("csr pem");
    (csr.into_bytes(), key)
}

/// What a test serves with, as `main` would build it from `server.toml`.
#[derive(Default)]
struct Setup<'a> {
    client_ca: Option<ClientCa>,
    /// The bootstrap CA of `[enrolment]`.
    bootstrap: Option<&'a Pki>,
    throttle: Option<fleet_server::throttle::Limits>,
    /// `[connection_offer]`.
    offer: Option<fleet_server::fleet::ConnectionOffer>,
    /// `[rest.auth]`, guarding the Operator plane.
    operator_auth: Option<fleet_server::api::OperatorAuth>,
    /// The register and the revocation list (ADR-0021).
    revocations: bool,
    /// The audit record (ADR-0022).
    audit: Option<Arc<dyn fleet_server::audit::Audit>>,
    /// `[agent_rate_limit]` (ADR-0013).
    agent_rate: Option<fleet_server::agent_rate::Limits>,
    /// `max_agents`.
    max_agents: Option<usize>,
    /// The clock the enrolment window and the rate limit run on; the system's by default.
    clock: Option<Arc<dyn fleet_server::fleet::Clock>>,
    /// Package delivery over an empty store (ADR-0026).
    packages: bool,
    /// The bootstrap CA's key on the Server, which then issues bootstrap certificates (ADR-0028).
    issue_bootstrap: bool,
    /// The CA of `[rest.tls]`: the Operator plane then serves a certificate it issued (ADR-0032).
    operator_pki: Option<&'a Pki>,
    /// `[enrolment] max_pending_per_bootstrap` (ADR-0046); its default when `None`.
    max_pending_per_bootstrap: Option<usize>,
}

/// The CAs a revocation can name, as `main` takes them from `[tls]` and `[enrolment]`.
fn authorities(pki: &Pki, bootstrap: Option<&Pki>) -> Vec<fleet_server::revocation::Authority> {
    let of = |role: &str, ca: &Pki| {
        let der = opamp::tls::certificates(ca.ca_pem.as_bytes()).expect("pem");
        let facts = fleet_server::ca::facts(der[0].as_ref()).expect("facts");
        fleet_server::revocation::Authority {
            role: role.to_string(),
            subject: facts.id.issuer,
            name: facts.issuer_name,
        }
    };
    let mut authorities = vec![of("client", pki)];
    authorities.extend(bootstrap.map(|b| of("bootstrap", b)));
    authorities
}

/// What `serve` hands a test.
struct Served {
    endpoint: String,
    operator_port: u16,
    ca_pem: String,
    state: Arc<AppState>,
    revocations: Option<Arc<Revocations>>,
    enrolment: Option<Arc<fleet_server::enrolment::Enrolment>>,
    /// The directory the Server keeps what it persists in: its data directory is `fleet-configs`
    /// beneath it.
    config_dir: std::path::PathBuf,
}

/// Serves both planes over TLS on ephemeral ports (ADR-0013), the Agent plane requiring a client
/// certificate in the handshake (ADR-0021) and the Operator plane asking for none, exactly as the
/// binary builds them.
async fn serve(pki: &Pki, setup: Setup<'_>) -> Served {
    // Before anything a test builds: a reqwest or rustls client made without a process provider
    // panics, and which test reaches that first depends on the order the tests run in.
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let clock: Arc<dyn fleet_server::fleet::Clock> = Arc::new(fleet_server::clock::SystemClock);
    let test_clock = setup.clock.clone().unwrap_or_else(|| clock.clone());
    let enrolment = setup.bootstrap.map(|_| {
        Arc::new(
            fleet_server::enrolment::Enrolment::new(test_clock.clone())
                .with_max_pending_per_bootstrap(
                    setup
                        .max_pending_per_bootstrap
                        .unwrap_or(fleet_server::enrolment::DEFAULT_MAX_PENDING_PER_BOOTSTRAP),
                ),
        )
    });
    let revocations = setup.revocations.then(|| {
        Arc::new(
            Revocations::open(
                Box::new(
                    fleet_server::fs::FsLedgerStore::open(&dir.path().join("fleet-configs"))
                        .expect("ledger"),
                ),
                clock.clone(),
                authorities(pki, setup.bootstrap),
            )
            .expect("revocations"),
        )
    });
    let enrolment_config = setup.bootstrap.map(|bootstrap| {
        let file = dir.path().join("bootstrap-ca.pem");
        std::fs::write(&file, &bootstrap.ca_pem).expect("write bootstrap ca");
        let key_file = setup.issue_bootstrap.then(|| {
            let key_file = dir.path().join("bootstrap-ca-key.pem");
            std::fs::write(&key_file, &bootstrap.ca_key_pem).expect("write bootstrap ca key");
            key_file
        });
        fleet_server::config::EnrolmentConfig {
            bootstrap_ca_file: file,
            bootstrap_ca_key_file: key_file,
            max_pending_per_bootstrap: fleet_server::enrolment::DEFAULT_MAX_PENDING_PER_BOOTSTRAP,
        }
    });
    let bootstrap = enrolment_config.as_ref().map(|config| {
        let signer = fleet_server::ca::BootstrapCa::from_config(config, None)
            .expect("bootstrap CA")
            .map(|ca| Box::new(ca) as Box<dyn fleet_server::bootstrap::BootstrapSigner>);
        Arc::new(
            fleet_server::bootstrap::BootstrapCertificates::on_disk(
                signer,
                &dir.path().join("fleet-configs"),
                clock.clone(),
            )
            .expect("bootstrap record"),
        )
    });
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("state")
            .with_bootstrap(bootstrap)
            .with_client_ca(setup.client_ca)
            .with_connection_offer(setup.offer)
            .with_enrolment(enrolment.clone())
            .with_revocations(revocations.clone())
            .with_audit(setup.audit.clone())
            .with_packages(setup.packages.then(|| {
                fleet_server::fleet::PackageOffering::new(
                    &dir.path().join("packages"),
                    fleet_server::packages::PackageStore::open(dir.path().join("packages"))
                        .expect("package store"),
                )
                .expect("deployments")
            }))
            .with_max_agents(
                setup
                    .max_agents
                    .unwrap_or(fleet_server::fleet::DEFAULT_MAX_AGENTS),
            )
            .with_agent_rate(setup.agent_rate.map(|limits| {
                Arc::new(fleet_server::agent_rate::AgentRate::new(
                    limits,
                    100,
                    test_clock.clone(),
                ))
            })),
    );
    let (server_cert, server_key) = pki.issue("localhost");

    let cert_file = dir.path().join("server-cert.pem");
    let key_file = dir.path().join("server-key.pem");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&cert_file, &server_cert).expect("write cert");
    std::fs::write(&key_file, &server_key).expect("write key");
    std::fs::write(&ca_file, &pki.ca_pem).expect("write ca");
    let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
        "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
        cert_file.display().to_string(),
        key_file.display().to_string(),
        ca_file.display().to_string(),
    ))
    .expect("tls config");
    let rest_tls = setup.operator_pki.map(|operator_pki| {
        let (cert, key) = operator_pki.issue("localhost");
        let cert_file = dir.path().join("operator-cert.pem");
        let key_file = dir.path().join("operator-key.pem");
        std::fs::write(&cert_file, cert).expect("write operator cert");
        std::fs::write(&key_file, key).expect("write operator key");
        fleet_server::config::RestTlsConfig {
            cert_file,
            key_file,
        }
    });
    let planes = fleet_server::tls::server_tls(&tls, rest_tls.as_ref(), enrolment_config.as_ref())
        .expect("server material");
    let agent_tls = planes.agent.rustls_config().expect("agent plane config");
    let operator_tls = planes
        .operator
        .rustls_config()
        .expect("operator plane config");

    let mut admission = Admission::new(true)
        .with_enrolment(planes.issuers, enrolment.clone())
        .with_revocations(revocations.clone())
        .with_audit(setup.audit.clone());
    if let Some(limits) = setup.throttle {
        admission = admission.with_throttle(Arc::new(fleet_server::throttle::Throttle::new(
            limits,
            clock.clone(),
        )));
    }

    let handle = opamp::server::listen::Handle::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Agent plane");
    let addr = listener.local_addr().expect("addr");
    let agents = fleet_server::agent_app(state.clone(), admission);
    tokio::spawn(
        fleet_server::listen::plane(listener, Some(agent_tls), 64, handle.clone()).serve(agents),
    );
    let operator_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Operator plane");
    let operator_addr = operator_listener.local_addr().expect("addr");
    let operators = fleet_server::operator_app(state.clone(), setup.operator_auth);
    tokio::spawn(
        fleet_server::listen::plane(operator_listener, Some(operator_tls), 64, handle)
            .serve(operators),
    );
    // The temp dir must outlive the server task; leak it deliberately for the test's lifetime.
    let config_dir = dir.path().to_path_buf();
    std::mem::forget(dir);
    Served {
        endpoint: format!("https://localhost:{}/v1/opamp", addr.port()),
        operator_port: operator_addr.port(),
        ca_pem: pki.ca_pem.clone(),
        state,
        revocations,
        enrolment,
        config_dir,
    }
}

/// The files of the bootstrap certificate `serial` in the Server's `bootstrap/`, named
/// `<issuer>-<serial>.json` and `.p12` (ADR-0037).
fn bootstrap_files(served: &Served, serial: &str) -> Vec<String> {
    std::fs::read_dir(served.config_dir.join("fleet-configs/bootstrap"))
        .expect("bootstrap/")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .filter(|name| {
            name.strip_suffix(".json")
                .or_else(|| name.strip_suffix(".p12"))
                .is_some_and(|stem| stem.ends_with(&format!("-{serial}")))
        })
        .collect()
}

/// The password the tests issue bootstrap certificates under.
const BOOTSTRAP_PASSWORD: &str = "a password of the operator";

/// The customer and the site every bootstrap certificate names (ADR-0036 clause 1).
fn customer_and_site() -> serde_json::Value {
    serde_json::json!({ "organization": "Kunde GmbH", "organizational_unit": "Werk Nord" })
}

/// The key of the bootstrap certificate `serial`, as PEM, out of the PKCS#12 file the Server keeps
/// for it under [`BOOTSTRAP_PASSWORD`] — the only place the key leaves the Server (ADR-0036
/// clause 8).
async fn bootstrap_key(served: &Served, operator_client: &reqwest::Client, serial: &str) -> String {
    let file = operator_client
        .get(operator(
            served,
            &format!("/api/v1/bootstrap-certificates/{serial}/p12"),
        ))
        .send()
        .await
        .expect("download")
        .bytes()
        .await
        .expect("body");
    let opened = fleet_core::pkcs12::file::open(&file, BOOTSTRAP_PASSWORD).expect("opens");
    KeyPair::try_from(opened.private_key_der.as_slice())
        .expect("key")
        .serialize_pem()
}

fn client(ca_pem: &str, identity: Option<(&str, &str)>) -> reqwest::Client {
    opamp::tls::install_ring_provider();
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca")])
        // The certificate is for `localhost`, the listener is on 127.0.0.1.
        .resolve(
            "localhost",
            "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
        );
    if let Some((cert, key)) = identity {
        let mut pem = key.as_bytes().to_vec();
        pem.extend_from_slice(cert.as_bytes());
        builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("identity"));
    }
    builder.build().expect("client")
}

async fn post(
    client: &reqwest::Client,
    endpoint: &str,
    message: AgentToServer,
) -> reqwest::Response {
    client
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(message.encode_to_vec())
        .send()
        .await
        .expect("send")
}

/// The handshake half: a peer without a certificate, or with one from a CA the Server does not
/// trust, never reaches the Agent plane — neither the OpAMP endpoint nor the package download —
/// while the Operator plane on its own listener serves a browser that presents none (ADR-0013,
/// ADR-0021).
/// Verifies: ADR-0021, ADR-0013, G-17
#[tokio::test]
async fn a_client_certificate_is_required_in_the_handshake_on_the_agent_plane() {
    let pki = Pki::new();
    let served = serve(&pki, Setup::default()).await;
    let (cert, key) = pki.issue("edge-01");

    let with_certificate = client(&served.ca_pem, Some((&cert, &key)));
    let response = post(
        &with_certificate,
        &served.endpoint,
        report(&InstanceUid::default()),
    )
    .await;
    assert!(response.status().is_success(), "{:?}", response.status());

    let without = client(&served.ca_pem, None);
    let refused = without
        .post(&served.endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await;
    assert!(
        refused.is_err(),
        "a peer without a certificate passed the handshake"
    );
    let (stranger_cert, stranger_key) = Pki::named("another-ca").issue("edge-01");
    let stranger = client(&served.ca_pem, Some((&stranger_cert, &stranger_key)));
    let refused = stranger
        .post(&served.endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await;
    assert!(
        refused.is_err(),
        "a certificate from another CA passed the handshake"
    );

    let download = served.endpoint.replace(
        "/v1/opamp",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64",
    );
    assert!(
        without.get(&download).send().await.is_err(),
        "the download sits behind the same handshake"
    );
    let response = with_certificate.get(&download).send().await.expect("send");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "a member reaches the download handler"
    );

    let agents = format!("https://localhost:{}/api/v1/agents", served.operator_port);
    let response = without.get(&agents).send().await.expect("send");
    assert!(response.status().is_success(), "{:?}", response.status());
}

/// The certificate is the whole of admission: a member presenting one is admitted on both
/// transports with no `Authorization` header, as the binary builds the Agent plane — revocation,
/// throttle and all.
/// Verifies: ADR-0021, G-17
#[tokio::test]
async fn a_member_is_admitted_on_its_certificate_alone() {
    let pki = Pki::new();
    let served = serve(
        &pki,
        Setup {
            throttle: Some(fleet_server::throttle::Limits::default()),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let response = post(&http, &served.endpoint, report(&InstanceUid::default())).await;
    assert!(response.status().is_success(), "{:?}", response.status());

    let mut socket = websocket(&served, &cert, &key, None)
        .await
        .expect("admitted on the upgrade");
    exchange(&mut socket, &InstanceUid::default()).await;
}

/// An `Authorization` header is never read on the Agent plane: whatever it holds, a member is
/// admitted on its certificate, on both transports and on the download, and a refusal carries no
/// challenge — so a Client of the previous version keeps connecting.
/// Verifies: ADR-0021
#[tokio::test]
async fn an_authorization_header_is_ignored() {
    let pki = Pki::new();
    let served = serve(
        &pki,
        Setup {
            throttle: Some(fleet_server::throttle::Limits {
                max_failures: 2,
                window_secs: 60,
                backoff_secs: 300,
            }),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let download = served.endpoint.replace(
        "/v1/opamp",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64",
    );
    // More attempts than the throttle allows failures: none of them is one.
    for authorization in [
        "Bearer an-old-fleet-token",
        "Basic ZmxlZXQ6c2VjcmV0",
        "Bearer",
        "garbage",
    ] {
        let response = http
            .post(&served.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .header(reqwest::header::AUTHORIZATION, authorization)
            .body(report(&InstanceUid::default()).encode_to_vec())
            .send()
            .await
            .expect("send");
        assert!(
            response.status().is_success(),
            "{authorization}: {:?}",
            response.status()
        );
        let mut socket = websocket(&served, &cert, &key, Some(authorization))
            .await
            .expect("admitted on the upgrade");
        exchange(&mut socket, &InstanceUid::default()).await;
        let response = http
            .get(&download)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .send()
            .await
            .expect("send");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{authorization}: the download handler is reached"
        );
    }

    // A refusal behind the handshake carries no challenge: no header could answer it.
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("client", &cert_id(&cert).serial)
        .expect("revoke");
    let refused = http
        .post(&served.endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::AUTHORIZATION, "Bearer an-old-fleet-token")
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await
        .expect("send");
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(!refused
        .headers()
        .contains_key(reqwest::header::WWW_AUTHENTICATE));
}

/// Renewal: a member that asks over a connection it was admitted on gets a certificate back at
/// once, in an ordinary connection-settings offer, and the Server declares the capability that
/// says so (ADR-0021 clause 9).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_csr_is_answered_with_an_issued_certificate() {
    let pki = Pki::new();
    let ca_cert = pki.ca_pem.clone();
    let ca_key = pki.ca_key_pem.clone();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("ca.pem"), &ca_cert).expect("write");
    std::fs::write(dir.path().join("ca-key.pem"), &ca_key).expect("write");
    let client_ca = ClientCa::from_config(
        &toml::from_str::<fleet_server::config::ClientCaConfig>(&format!(
            "cert_file = {:?}\nkey_file = {:?}\nvalidity_days = 30\n",
            dir.path().join("ca.pem").display().to_string(),
            dir.path().join("ca-key.pem").display().to_string(),
        ))
        .expect("client_ca config"),
    )
    .expect("client ca");

    let Served {
        endpoint, ca_pem, ..
    } = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca),
            ..Setup::default()
        },
    )
    .await;
    let (member_cert, member_key) = pki.issue("edge-01");
    let http = client(&ca_pem, Some((&member_cert, &member_key)));

    let (csr, _key) = csr_for("edge-01");
    let mut message = report(&InstanceUid::default());
    message.connection_settings_request = Some(ConnectionSettingsRequest {
        opamp: Some(OpAmpConnectionSettingsRequest {
            certificate_request: Some(CertificateRequest { csr }),
        }),
    });
    let response = post(&http, &endpoint, message).await;
    assert!(response.status().is_success());
    let reply = ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode");

    assert_ne!(
        reply.capabilities
            & opamp::proto::ServerCapabilities::AcceptsConnectionSettingsRequest as u64,
        0,
        "a Server with a [client_ca] declares that it signs"
    );
    let settings = reply
        .connection_settings
        .expect("an offer")
        .opamp
        .expect("opamp settings");
    let certificate = settings.certificate.expect("an issued certificate");
    let issued = String::from_utf8(certificate.cert).expect("pem");
    assert!(
        issued.starts_with("-----BEGIN CERTIFICATE-----"),
        "{issued}"
    );
    assert!(
        certificate.private_key.is_empty(),
        "the Agent keeps its own key — the Server has none to send"
    );
}

/// The Baseline's MUST: a request the Server cannot act on is answered with a `BadRequest` error
/// response. Here the Server signs nothing at all, so no Agent should be asking.
/// Verifies: ADR-0021, ADR-0014
#[tokio::test]
async fn a_csr_to_a_server_that_signs_nothing_is_a_bad_request() {
    let pki = Pki::new();
    let Served {
        endpoint, ca_pem, ..
    } = serve(&pki, Setup::default()).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&ca_pem, Some((&cert, &key)));

    let (csr, _key) = csr_for("edge-01");
    let mut message = report(&InstanceUid::default());
    message.connection_settings_request = Some(ConnectionSettingsRequest {
        opamp: Some(OpAmpConnectionSettingsRequest {
            certificate_request: Some(CertificateRequest { csr }),
        }),
    });
    let response = post(&http, &endpoint, message).await;
    let reply = ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode");
    let error = reply.error_response.expect("an error response");
    assert_eq!(error.r#type, ServerErrorResponseType::BadRequest as i32);
    assert!(reply.connection_settings.is_none());
}

/// A report carrying a CSR, as an enrolling Client sends it.
fn csr_report(csr: Vec<u8>) -> AgentToServer {
    let mut message = report(&InstanceUid::default());
    message.connection_settings_request = Some(ConnectionSettingsRequest {
        opamp: Some(OpAmpConnectionSettingsRequest {
            certificate_request: Some(CertificateRequest { csr }),
        }),
    });
    message
}

/// A CA of its own for the CSRs an enrolment approves.
fn client_ca_of(pki: &Pki) -> ClientCa {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("ca.pem"), &pki.ca_pem).expect("write");
    std::fs::write(dir.path().join("ca-key.pem"), &pki.ca_key_pem).expect("write");
    let ca = ClientCa::from_config(
        &toml::from_str::<fleet_server::config::ClientCaConfig>(&format!(
            "cert_file = {:?}\nkey_file = {:?}\nvalidity_days = 30\n",
            dir.path().join("ca.pem").display().to_string(),
            dir.path().join("ca-key.pem").display().to_string(),
        ))
        .expect("client_ca config"),
    )
    .expect("client ca");
    std::mem::forget(dir);
    ca
}

fn operator(served: &Served, path: &str) -> String {
    format!("https://localhost:{}{path}", served.operator_port)
}

async fn decode(response: reqwest::Response) -> ServerToAgent {
    assert!(response.status().is_success(), "{:?}", response.status());
    ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode")
}

/// A bootstrap certificate opens nothing outside an enrolment window: the handshake passes, and
/// the endpoint answers `503` — the handshake proved the certificate, so it is no failure
/// (ADR-0021 clauses 20, 21, 24).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_bootstrap_certificate_is_refused_outside_an_enrolment_window() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            ..Setup::default()
        },
    )
    .await;
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let response = post(
        &enrolling,
        &served.endpoint,
        report(&InstanceUid::default()),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

/// The whole enrolment: an operator opens the window, the host's request waits in the queue
/// without becoming an Agent, an operator approves it, and the host is handed its certificate. A
/// bootstrap certificate never reaches the package download, and the standing offer the fleet's
/// members get never reaches an enrolling host (ADR-0021 clauses 4, 20 to 23).
/// Verifies: ADR-0021
#[tokio::test]
async fn an_enrolment_request_waits_for_an_operator_and_is_issued_on_approval() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let offer = toml::from_str::<fleet_server::config::ConnectionOfferConfig>(
        "heartbeat_interval_secs = 15\n",
    )
    .expect("offer config");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            offer: Some(fleet_server::fleet::ConnectionOffer::from_config(&offer)),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let opened = operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    assert_eq!(opened.status(), 200);

    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    // A first report without a CSR is told the Server signs, and nothing else.
    let hello = decode(
        post(
            &enrolling,
            &served.endpoint,
            report(&InstanceUid::default()),
        )
        .await,
    )
    .await;
    assert_ne!(
        hello.capabilities
            & opamp::proto::ServerCapabilities::AcceptsConnectionSettingsRequest as u64,
        0
    );
    assert!(
        hello.connection_settings.is_none() && hello.remote_config.is_none(),
        "an enrolling host is offered neither the standing offer nor a configuration"
    );

    let (csr, _key) = csr_for("edge-01");
    let waiting = decode(post(&enrolling, &served.endpoint, csr_report(csr.clone())).await).await;
    assert!(
        waiting.connection_settings.is_none(),
        "nothing is issued before an operator decides"
    );
    assert!(
        served.state.snapshot().is_empty(),
        "an enrolling host is no Agent of the fleet"
    );

    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let pending = pending.as_array().expect("array");
    assert_eq!(pending.len(), 1, "{pending:?}");
    let id = pending[0]["id"].as_str().expect("id").to_string();
    assert!(
        pending[0].get("subject").is_none(),
        "the request's own subject is neither trusted nor listed: {pending:?}"
    );

    let download = served.endpoint.replace(
        "/v1/opamp",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64",
    );
    let response = enrolling.get(&download).send().await.expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let approved = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/approve"),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(approved.status(), 204);

    let issued = decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    let certificate = issued
        .connection_settings
        .and_then(|offer| offer.opamp)
        .and_then(|opamp| opamp.certificate)
        .expect("the issued certificate");
    assert!(String::from_utf8_lossy(&certificate.cert).starts_with("-----BEGIN CERTIFICATE-----"));
}

/// A rejected request is answered `BadRequest`, and closing the window shuts out every bootstrap
/// certificate again (ADR-0021 clauses 20, 21).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_rejected_request_is_refused_and_closing_the_window_shuts_enrolment() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let (csr, _key) = csr_for("edge-02");
    decode(post(&enrolling, &served.endpoint, csr_report(csr.clone())).await).await;
    let id = served.state.enrolment().expect("enrolment").pending()[0]
        .id
        .clone();
    let rejected = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/reject"),
        ))
        .send()
        .await
        .expect("reject");
    assert_eq!(rejected.status(), 204);
    let answer = decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    assert_eq!(
        answer.error_response.expect("an error").r#type,
        ServerErrorResponseType::BadRequest as i32
    );

    let closed = operator_client
        .delete(operator(&served, "/api/v1/enrolment/window"))
        .send()
        .await
        .expect("close");
    assert_eq!(closed.status(), 204);
    let response = post(
        &enrolling,
        &served.endpoint,
        report(&InstanceUid::default()),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

/// A peer address that fails admission too often — a revoked certificate retried — is answered
/// `429` with `Retry-After`, a valid certificate from the same address included (ADR-0021 clause
/// 24).
/// Verifies: ADR-0021
#[tokio::test]
async fn repeated_failures_from_one_address_are_throttled() {
    let pki = Pki::new();
    let served = serve(
        &pki,
        Setup {
            throttle: Some(fleet_server::throttle::Limits {
                max_failures: 3,
                window_secs: 60,
                backoff_secs: 300,
            }),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("client", &cert_id(&cert).serial)
        .expect("revoke");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    for _ in 0..3 {
        let response = post(&http, &served.endpoint, report(&InstanceUid::default())).await;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    let (valid_cert, valid_key) = pki.issue("edge-02");
    let valid = client(&served.ca_pem, Some((&valid_cert, &valid_key)));
    let response = post(&valid, &served.endpoint, report(&InstanceUid::default())).await;
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let wait: u64 = response.headers()[reqwest::header::RETRY_AFTER]
        .to_str()
        .expect("text")
        .parse()
        .expect("seconds");
    assert!(wait > 0 && wait <= 300, "{wait}");
}

/// A bootstrap CA must be told apart from the client CA by its subject, so one that shares a
/// subject with it is refused when the Server builds its TLS material (ADR-0021 clause 19).
/// Verifies: ADR-0021
#[test]
fn a_bootstrap_ca_sharing_its_subject_with_the_client_ca_is_refused() {
    let pki = Pki::new();
    let twin = Pki::named("opamp-fleet-test-ca");
    let dir = tempfile::tempdir().expect("tempdir");
    let (server_cert, server_key) = pki.issue("localhost");
    let file = |name: &str, body: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, body).expect("write");
        path.display().to_string()
    };
    let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
        "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
        file("server-cert.pem", &server_cert),
        file("server-key.pem", &server_key),
        file("ca.pem", &pki.ca_pem),
    ))
    .expect("tls config");
    let enrolment = fleet_server::config::EnrolmentConfig {
        bootstrap_ca_file: file("bootstrap-ca.pem", &twin.ca_pem).into(),
        bootstrap_ca_key_file: None,
        max_pending_per_bootstrap: fleet_server::enrolment::DEFAULT_MAX_PENDING_PER_BOOTSTRAP,
    };
    let Err(err) = fleet_server::tls::server_tls(&tls, None, Some(&enrolment)) else {
        panic!("a bootstrap CA indistinguishable from the client CA was accepted");
    };
    assert!(
        err.contains("shares a CA with [tls] client_ca_file"),
        "{err}"
    );
}

/// An operator deciding a request that is not pending is told so: an unknown id is `404` for an
/// approval and a rejection alike (ADR-0021 clause 22).
/// Verifies: ADR-0021
#[tokio::test]
async fn an_unknown_enrolment_request_is_answered_404() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    for decision in ["approve", "reject"] {
        let response = operator_client
            .post(operator(
                &served,
                &format!("/api/v1/enrolments/no-such-request/{decision}"),
            ))
            .send()
            .await
            .expect("send");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{decision}"
        );
    }
}

/// The Operator plane counts its own `401`s in a table of its own: an address in back-off there
/// is still admitted on the Agent plane (ADR-0021 clause 24).
/// Verifies: ADR-0021
#[tokio::test]
async fn the_operator_plane_counts_its_failures_in_a_table_of_its_own() {
    let pki = Pki::new();
    let limits = || fleet_server::throttle::Limits {
        max_failures: 3,
        window_secs: 60,
        backoff_secs: 300,
    };
    let rest_auth = toml::from_str::<fleet_server::config::RestAuthConfig>(&format!(
        "[basic_users]\nops = {:?}\n",
        fleet_server::credentials::hash_basic("s3cret").expect("hash")
    ))
    .expect("rest auth config");
    let operator_auth = fleet_server::api::OperatorAuth::from_config(&rest_auth)
        .expect("operator auth")
        .with_throttle(Arc::new(fleet_server::throttle::Throttle::new(
            limits(),
            Arc::new(fleet_server::clock::SystemClock),
        )));
    let served = serve(
        &pki,
        Setup {
            throttle: Some(limits()),
            operator_auth: Some(operator_auth),
            ..Setup::default()
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let agents = operator(&served, "/api/v1/agents");
    for _ in 0..3 {
        let response = http.get(&agents).send().await.expect("send");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    let response = http
        .get(&agents)
        .basic_auth("ops", Some("s3cret"))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let response = post(&http, &served.endpoint, report(&InstanceUid::default())).await;
    assert!(
        response.status().is_success(),
        "the Agent plane's count is its own: {:?}",
        response.status()
    );
}

// ---- Revocation and the end of a session (ADR-0021) ----

/// The issuer and serial of a certificate in PEM.
fn cert_id(pem: &str) -> CertId {
    let der = opamp::tls::certificates(pem.as_bytes()).expect("pem");
    fleet_server::ca::facts(der[0].as_ref()).expect("facts").id
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A WebSocket to the Agent plane presenting `cert`, sending `authorization` as an `Authorization`
/// header when given — what a Client of the previous version still sends.
async fn websocket(
    served: &Served,
    cert: &str,
    key: &str,
    authorization: Option<&str>,
) -> Result<Socket, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    opamp::tls::install_ring_provider();
    let config = opamp::tls::client_builder()
        .with_root_certificates(opamp::tls::root_store(served.ca_pem.as_bytes()).expect("roots"))
        .with_client_auth_cert(
            opamp::tls::certificates(cert.as_bytes()).expect("cert"),
            opamp::tls::private_key(key.as_bytes()).expect("key"),
        )
        .expect("client auth");
    let mut request = served
        .endpoint
        .replace("https://", "wss://")
        .into_client_request()
        .expect("request");
    if let Some(authorization) = authorization {
        request
            .headers_mut()
            .insert("authorization", authorization.parse().expect("header"));
    }
    let port = served
        .endpoint
        .rsplit(':')
        .next()
        .and_then(|rest| rest.split('/').next())
        .expect("port")
        .to_string();
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("tcp");
    tokio_tungstenite::client_async_tls_with_config(
        request,
        tcp,
        None,
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))),
    )
    .await
    .map(|(socket, _)| socket)
}

/// Sends one report and waits for its reply, so the session is known to be up.
async fn exchange(socket: &mut Socket, uid: &InstanceUid) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;
    let framed = opamp::frame::encode_within(&report(uid), usize::MAX).expect("frame");
    socket.send(Ws::Binary(framed.into())).await.expect("send");
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("a reply in time")
        {
            Some(Ok(Ws::Binary(_))) => return,
            Some(Ok(_)) => continue,
            other => panic!("the session ended early: {other:?}"),
        }
    }
}

/// The close frame the Server ends `socket` with, within `secs`.
async fn closed_with(socket: &mut Socket, secs: u64) -> (u16, String) {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as Ws;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let message = tokio::time::timeout_at(deadline, socket.next())
            .await
            .expect("closed in time");
        match message {
            Some(Ok(Ws::Close(Some(frame)))) => {
                return (frame.code.into(), frame.reason.to_string())
            }
            Some(Ok(Ws::Close(None))) | None => panic!("closed without a code"),
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("{e}"),
        }
    }
}

/// Whether `socket` is still open after `millis`: nothing arrives that ends it.
async fn still_open(socket: &mut Socket, millis: u64) -> bool {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as Ws;
    match tokio::time::timeout(std::time::Duration::from_millis(millis), socket.next()).await {
        Err(_) => true,
        Ok(Some(Ok(Ws::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => false,
        Ok(Some(Ok(_))) => true,
    }
}

fn revocations_setup(pki: &Pki) -> Setup<'static> {
    Setup {
        client_ca: Some(client_ca_of(pki)),
        revocations: true,
        ..Setup::default()
    }
}

/// A revoked certificate is refused on plain HTTP, on the WebSocket upgrade and on the download,
/// without a challenge and without saying it was revoked; revoking it through the REST API lists
/// it, and lifting it admits the certificate again (ADR-0021 clauses 34, 38, 39).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_revoked_certificate_is_refused_on_both_transports_and_the_download() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let uid = InstanceUid::default();
    assert!(post(&http, &served.endpoint, report(&uid))
        .await
        .status()
        .is_success());

    let id = cert_id(&cert);
    let operator = client(&served.ca_pem, None);
    let revocations = format!(
        "https://localhost:{}/api/v1/revocations",
        served.operator_port
    );
    let response = operator
        .post(&revocations)
        .json(&serde_json::json!({"certificate": {"authority": "client", "serial": id.serial}}))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let entry: serde_json::Value = response.json().await.expect("json");

    let refused = post(&http, &served.endpoint, report(&uid)).await;
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        !refused
            .headers()
            .contains_key(reqwest::header::WWW_AUTHENTICATE),
        "the Agent plane sends no challenge"
    );
    assert!(!refused.text().await.expect("body").contains("revoked"));
    assert!(
        websocket(&served, &cert, &key, None).await.is_err(),
        "a revoked certificate passed the upgrade"
    );
    let download = served.endpoint.replace(
        "/v1/opamp",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64",
    );
    let response = http.get(&download).send().await.expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(!response
        .headers()
        .contains_key(reqwest::header::WWW_AUTHENTICATE));

    let listed: serde_json::Value = operator
        .get(&revocations)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(listed[0]["id"], entry["id"]);
    let lifted = operator
        .delete(format!(
            "{revocations}/{}",
            entry["id"].as_str().expect("id")
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(lifted.status(), reqwest::StatusCode::NO_CONTENT);
    assert!(post(&http, &served.endpoint, report(&uid))
        .await
        .status()
        .is_success());
}

/// There is no credential to revoke: naming one is answered `400`, naming the field, and the list
/// is left as it was (ADR-0021 clause 36).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_credential_revocation_is_answered_400() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let url = operator(&served, "/api/v1/revocations");
    let operator = client(&served.ca_pem, None);
    for body in [
        serde_json::json!({"credential": "Bearer an-old-fleet-token"}),
        serde_json::json!({
            "credential": "Bearer an-old-fleet-token",
            "certificate": {"authority": "client", "serial": "ab"}
        }),
    ] {
        let response = operator.post(&url).json(&body).send().await.expect("send");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{body}"
        );
        let text = response.text().await.expect("body");
        assert!(text.contains("credential"), "names the field: {text}");
        assert!(
            text.contains("admits by client certificate alone"),
            "says why: {text}"
        );
        assert!(!text.contains("an-old-fleet-token"), "{text}");
    }
    assert!(served
        .revocations
        .as_ref()
        .expect("armed")
        .list()
        .is_empty());
    let listed: serde_json::Value = operator
        .get(&url)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(listed, serde_json::json!([]));
}

/// A body that names no certificate, or carries a field the route does not know, is malformed and
/// answered `400`, like every other malformed body; the list is left as it was.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_revocation_naming_no_certificate_is_answered_400() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let url = operator(&served, "/api/v1/revocations");
    let operator = client(&served.ca_pem, None);
    for body in [
        serde_json::json!({}),
        serde_json::json!({"certificate": {"authority": "client"}}),
        serde_json::json!({
            "certificate": {"authority": "client", "serial": "ab"},
            "reason": "an unknown field"
        }),
    ] {
        let response = operator.post(&url).json(&body).send().await.expect("send");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    assert!(served
        .revocations
        .as_ref()
        .expect("armed")
        .list()
        .is_empty());
}

/// A revocation closes the sessions it concerns at once and leaves every other one running
/// (ADR-0021 clause 40).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_revocation_closes_the_session_it_concerns_and_no_other() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (revoked_cert, revoked_key) = pki.issue("edge-01");
    let (kept_cert, kept_key) = pki.issue("edge-02");
    let mut revoked = websocket(&served, &revoked_cert, &revoked_key, None)
        .await
        .expect("admitted");
    let mut kept = websocket(&served, &kept_cert, &kept_key, None)
        .await
        .expect("admitted");
    exchange(&mut revoked, &InstanceUid::default()).await;
    let kept_uid = InstanceUid::default();
    exchange(&mut kept, &kept_uid).await;

    let id = cert_id(&revoked_cert);
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("client", &id.serial)
        .expect("revoke");
    assert_eq!(
        closed_with(&mut revoked, 5).await,
        (1008, "revoked".to_string())
    );
    assert!(
        still_open(&mut kept, 300).await,
        "an unrelated session was closed"
    );
    exchange(&mut kept, &kept_uid).await;
}

/// A session ends when the certificate that admitted it expires (ADR-0021 clause 41).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_session_is_closed_when_its_certificate_expires() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["edge-01".to_string()]).expect("params");
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::seconds(3);
    let cert = params.signed_by(&key, &pki.issuer()).expect("signed").pem();
    let mut socket = websocket(&served, &cert, &key.serialize_pem(), None)
        .await
        .expect("admitted");
    exchange(&mut socket, &InstanceUid::default()).await;
    assert_eq!(
        closed_with(&mut socket, 10).await,
        (1008, "certificate expired".to_string())
    );
}

/// A client presenting a certificate that expires in ten seconds, and the instant it expires —
/// `not_after` in whole seconds, as the certificate carries it.
fn expiring_client(pki: &Pki, served: &Served) -> (reqwest::Client, time::OffsetDateTime) {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["edge-01".to_string()]).expect("params");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = (now + time::Duration::seconds(10))
        .replace_nanosecond(0)
        .expect("whole second");
    let cert = params.signed_by(&key, &pki.issuer()).expect("signed").pem();
    (
        client(&served.ca_pem, Some((&cert, &key.serialize_pem()))),
        params.not_after,
    )
}

/// Waits until a second past `not_after`.
async fn sleep_past(not_after: time::OffsetDateTime) {
    let wait = not_after + time::Duration::seconds(1) - time::OffsetDateTime::now_utc();
    tokio::time::sleep(wait.try_into().unwrap_or_default()).await;
}

/// A connection that outlives its certificate is admitted no further: plain HTTP keeps one
/// connection across polls, and the handshake that checked the certificate's validity is not
/// repeated, so each request on it is refused once the certificate has expired
/// (ADR-0021 clauses 6, 40, 41).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_kept_alive_connection_is_refused_once_its_certificate_expires() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (http, not_after) = expiring_client(&pki, &served);
    let uid = InstanceUid::default();
    assert!(post(&http, &served.endpoint, report(&uid))
        .await
        .status()
        .is_success());

    sleep_past(not_after).await;
    // An answer at all proves the pooled connection was reused: a new one would fail the
    // handshake on the expired certificate, and `post` would panic on the send.
    assert_eq!(
        post(&http, &served.endpoint, report(&uid)).await.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an expired certificate was admitted on a kept-alive connection"
    );
}

/// The download is held to the same: a kept-alive connection reaches it no further once its
/// certificate has expired (ADR-0021 clauses 6, 23).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_kept_alive_connection_reaches_the_download_no_further_once_its_certificate_expires() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (http, not_after) = expiring_client(&pki, &served);
    let download = served.endpoint.replace(
        "/v1/opamp",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64",
    );
    assert_ne!(
        http.get(&download).send().await.expect("send").status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    sleep_past(not_after).await;
    // As above, an answer at all proves the connection was reused.
    assert_eq!(
        http.get(&download).send().await.expect("send").status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an expired certificate reached the download on a kept-alive connection"
    );
}

/// A certificate renewed before its predecessor was revoked is revoked with it: the register
/// records the presented certificate as the issued one's predecessor (ADR-0021 clauses 32, 33, 35).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_revocation_reaches_a_certificate_renewed_before_it() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (old_cert, old_key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&old_cert, &old_key)));
    let uid = InstanceUid::default();
    let (csr, new_key) = csr_for("edge-01");
    let mut message = report(&uid);
    message.connection_settings_request = Some(ConnectionSettingsRequest {
        opamp: Some(OpAmpConnectionSettingsRequest {
            certificate_request: Some(CertificateRequest { csr }),
        }),
    });
    let reply = decode(post(&http, &served.endpoint, message).await).await;
    let new_cert = String::from_utf8(
        reply
            .connection_settings
            .and_then(|s| s.opamp)
            .and_then(|o| o.certificate)
            .expect("renewed")
            .cert,
    )
    .expect("pem");

    let register: serde_json::Value = client(&served.ca_pem, None)
        .get(format!(
            "https://localhost:{}/api/v1/certificates",
            served.operator_port
        ))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let old = cert_id(&old_cert);
    let new = cert_id(&new_cert);
    assert_eq!(register[0]["serial"], new.serial.as_str());
    assert_eq!(register[0]["predecessor"]["serial"], old.serial.as_str());
    assert_eq!(register[0]["instance_uid"], hex::encode(uid.as_bytes()));

    let renewed = client(&served.ca_pem, Some((&new_cert, &new_key.serialize_pem())));
    assert!(post(&renewed, &served.endpoint, report(&uid))
        .await
        .status()
        .is_success());
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("client", &old.serial)
        .expect("revoke");
    let refused = post(&renewed, &served.endpoint, report(&uid)).await;
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a renewal escaped the revocation of its predecessor"
    );
}

/// A renewal of a certificate an operator provisioned names a host of its own; the operator
/// sees the host, what it speaks for, and can mark it as a Gateway (ADR-0021 clause 7).
/// Verifies: ADR-0021
#[tokio::test]
async fn an_operator_sees_each_host_and_can_mark_a_gateway() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let uid = InstanceUid::default();
    let (csr, _) = csr_for("edge-01");
    let reply = decode(post(&http, &served.endpoint, with_csr(&uid, csr)).await).await;
    assert!(reply
        .connection_settings
        .and_then(|s| s.opamp)
        .and_then(|o| o.certificate)
        .is_some());

    let operator = client(&served.ca_pem, None);
    let hosts: serde_json::Value = operator
        .get(format!(
            "https://localhost:{}/api/v1/hosts",
            served.operator_port
        ))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(hosts.as_array().expect("a list").len(), 1, "{hosts}");
    assert_eq!(hosts[0]["certificates"], 1);
    assert_eq!(hosts[0]["gateway"], false);
    let host = hosts[0]["host"].as_str().expect("a host").to_string();

    let gateway = |host: &str| {
        operator
            .put(format!(
                "https://localhost:{}/api/v1/hosts/{host}/gateway",
                served.operator_port
            ))
            .json(&serde_json::json!({"gateway": true}))
            .send()
    };
    assert_eq!(
        gateway(&host).await.expect("send").status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        gateway("nobody").await.expect("send").status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

/// A CSR in `renewal` of `old_cert`, proven with `old_key` as ADR-0021 clause 27 describes.
fn renewal_csr(old_cert: &str, old_key: &str) -> Vec<u8> {
    use base64::Engine as _;
    use rcgen::{PublicKeyData as _, SigningKey as _};
    use sha2::{Digest as _, Sha256};
    let old_key = KeyPair::from_pem(old_key).expect("old key");
    let new_key = KeyPair::generate().expect("new key");
    let old_der = opamp::tls::certificates(old_cert.as_bytes()).expect("pem")[0].to_vec();
    let signature = old_key
        .sign(&fleet_core::renewal::statement(&Sha256::digest(
            new_key.subject_public_key_info(),
        )))
        .expect("sign");
    let proof = format!(
        "{}{}",
        fleet_core::renewal::URI_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(fleet_core::renewal::encode(&old_der, &signature))
    );
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .subject_alt_names
        .push(rcgen::SanType::URI(proof.try_into().expect("uri")));
    params
        .serialize_request(&new_key)
        .expect("csr")
        .pem()
        .expect("pem")
        .into_bytes()
}

/// The certificate a reply issued, if it issued one.
fn issued(reply: opamp::proto::ServerToAgent) -> Option<String> {
    reply
        .connection_settings
        .and_then(|s| s.opamp)
        .and_then(|o| o.certificate)
        .map(|c| String::from_utf8(c.cert).expect("pem"))
}

/// Over a Gateway's certificate a CSR without a renewal proof is refused and signs nothing, so a
/// member behind the Gateway cannot take on the Gateway's host and its mark; a CSR whose proof
/// names a downstream certificate is still issued, to that certificate's host.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_csr_over_a_gateways_certificate_needs_a_renewal_proof() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (gateway_cert, gateway_key) =
        pki.issue_to_host_with("gw", &[(rcgen::DnType::CommonName, "gw")]);
    let (member_cert, member_key) =
        pki.issue_to_host_with("h-1", &[(rcgen::DnType::CommonName, "edge-01")]);
    let gateway = client(&served.ca_pem, Some((&gateway_cert, &gateway_key)));
    let uid = InstanceUid::default();
    assert!(post(&gateway, &served.endpoint, report(&uid))
        .await
        .status()
        .is_success());
    let revocations = served.revocations.as_ref().expect("armed");
    assert!(revocations.set_gateway("gw", true).expect("mark"));
    let before = revocations.issued().len();

    let (csr, _) = csr_for("edge-02");
    let refused = decode(post(&gateway, &served.endpoint, with_csr(&uid, csr)).await).await;
    let error = refused.error_response.clone().expect("an error response");
    assert_eq!(error.r#type, ServerErrorResponseType::BadRequest as i32);
    assert!(
        error.error_message.contains("renewal proof"),
        "{}",
        error.error_message
    );
    assert!(issued(refused).is_none());
    assert_eq!(
        revocations.issued().len(),
        before,
        "a certificate was signed"
    );

    let csr = renewal_csr(&member_cert, &member_key);
    let reply = decode(post(&gateway, &served.endpoint, with_csr(&uid, csr)).await).await;
    let renewed = issued(reply).expect("a proven renewal through a Gateway is issued");
    let entry = revocations
        .issued_entry(&cert_id(&renewed))
        .expect("registered");
    assert_eq!(
        entry.predecessor,
        Some(cert_id(&member_cert)),
        "the proven certificate is the predecessor"
    );
    assert_eq!(
        fleet_server::ca::facts(
            opamp::tls::certificates(renewed.as_bytes()).expect("pem")[0].as_ref()
        )
        .expect("facts")
        .host
        .as_deref(),
        Some("h-1"),
        "the proven certificate's host, never the Gateway's"
    );

    // Over a certificate whose host is not marked, a CSR without a proof still renews it.
    let member = client(&served.ca_pem, Some((&member_cert, &member_key)));
    let (csr, _) = csr_for("edge-01");
    let reply = decode(post(&member, &served.endpoint, with_csr(&uid, csr)).await).await;
    assert!(
        issued(reply).is_some(),
        "an unmarked host's proofless renewal"
    );
}

// ---- Hosts (ADR-0035) ----

async fn hosts(served: &Served) -> serde_json::Value {
    client(&served.ca_pem, None)
        .get(operator(served, "/api/v1/hosts"))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json")
}

/// A report describing itself with `pairs`.
fn described(uid: &InstanceUid, pairs: &[(&str, &str)]) -> AgentToServer {
    AgentToServer {
        agent_description: Some(opamp::proto::AgentDescription {
            identifying_attributes: vec![opamp::attributes::string_attr("service.name", "otelcol")],
            non_identifying_attributes: pairs
                .iter()
                .map(|(key, value)| opamp::attributes::string_attr(key, value))
                .collect(),
        }),
        ..report(uid)
    }
}

/// Approving an enrolment writes the Host before the host has reported once as a member.
/// Verifies: ADR-0035
#[tokio::test]
async fn an_approval_writes_the_host_before_its_first_report() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let opened = operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    assert_eq!(opened.status(), 200);
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let (csr, _key) = csr_for("edge-01");
    let _ = decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    assert_eq!(hosts(&served).await, serde_json::json!([]), "no Host yet");

    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let id = pending[0]["id"].as_str().expect("id").to_string();
    let approved = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/approve"),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(approved.status(), 204);

    let listed = hosts(&served).await;
    assert_eq!(listed.as_array().expect("a list").len(), 1, "{listed}");
    assert!(listed[0]["approved_ms"].as_u64().is_some(), "{listed}");
    assert_eq!(listed[0]["certificates"], 1);
    assert_eq!(listed[0]["agents"], serde_json::json!([]));
    assert_eq!(
        listed[0]["name"], listed[0]["host"],
        "no Client Agent named it yet"
    );
    let host = listed[0]["host"].as_str().expect("a host id");
    let written = std::fs::read_to_string(
        served
            .config_dir
            .join("fleet-configs/hosts")
            .join(format!("{host}.json")),
    )
    .expect("the Host is written, one file per Host (ADR-0037)");
    assert!(written.contains(host), "{written}");
}

/// `GET /api/v1/hosts` lists a Host's subject values and its Agents, grouped under their Client
/// Agent, and an Agent behind a Gateway under the Gateway's Host; the fleet view carries the Host's
/// values on a direct Agent and none behind a Gateway.
/// Verifies: ADR-0035
#[tokio::test]
async fn the_hosts_list_carries_subject_values_and_the_agents_behind_a_gateway() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue_to_host_with(
        "h-direct",
        &[
            (rcgen::DnType::CountryName, "AT"),
            (rcgen::DnType::OrganizationName, "Kunde GmbH"),
            (rcgen::DnType::OrganizationalUnitName, "Werk Nord"),
            (rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]), "VATAT-U1"),
            (rcgen::DnType::CommonName, "edge-01"),
        ],
    );
    let direct = client(&served.ca_pem, Some((&cert, &key)));
    let client_agent = InstanceUid::default();
    let supervisor = InstanceUid::default();
    for (uid, pairs) in [
        (
            client_agent,
            vec![
                ("supervisor.kind.collector", "true"),
                ("host.name", "edge-01.example"),
            ],
        ),
        (supervisor, vec![("host.name", "edge-01.example")]),
    ] {
        let _ = decode(post(&direct, &served.endpoint, described(&uid, &pairs)).await).await;
    }

    let (cert, key) =
        pki.issue_to_host_with("h-gw", &[(rcgen::DnType::OrganizationName, "Gateway GmbH")]);
    let gateway = client(&served.ca_pem, Some((&cert, &key)));
    let own = InstanceUid::default();
    let _ = decode(post(&gateway, &served.endpoint, described(&own, &[])).await).await;
    let marked = client(&served.ca_pem, None)
        .put(operator(&served, "/api/v1/hosts/h-gw/gateway"))
        .json(&serde_json::json!({"gateway": true}))
        .send()
        .await
        .expect("send");
    assert_eq!(marked.status(), reqwest::StatusCode::NO_CONTENT);
    let downstream = InstanceUid::default();
    let _ = decode(
        post(
            &gateway,
            &served.endpoint,
            described(&downstream, &[("host.id", "m-1")]),
        )
        .await,
    )
    .await;

    let listed = hosts(&served).await;
    let row = |host: &str| {
        listed
            .as_array()
            .expect("a list")
            .iter()
            .find(|row| row["host"] == host)
            .unwrap_or_else(|| panic!("{host} in {listed}"))
            .clone()
    };
    let direct_row = row("h-direct");
    assert_eq!(direct_row["name"], "edge-01.example");
    assert_eq!(direct_row["gateway"], false);
    assert_eq!(direct_row["subject"]["country"], "AT");
    assert_eq!(direct_row["subject"]["organization"], "Kunde GmbH");
    assert_eq!(direct_row["subject"]["organizational_unit"], "Werk Nord");
    assert_eq!(direct_row["subject"]["organization_identifier"], "VATAT-U1");
    let agents = direct_row["agents"].as_array().expect("agents");
    assert_eq!(agents.len(), 2, "{direct_row}");
    for agent in agents {
        assert_eq!(agent["client_agent"], client_agent.to_string(), "{agent}");
    }

    let gateway_row = row("h-gw");
    assert_eq!(gateway_row["gateway"], true);
    assert_eq!(gateway_row["name"], "h-gw");
    let carried: Vec<&str> = gateway_row["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .map(|agent| agent["instance_uid"].as_str().expect("uid"))
        .collect();
    assert!(
        carried.contains(&downstream.to_string().as_str()),
        "{gateway_row}"
    );

    let fleet: Vec<serde_json::Value> = client(&served.ca_pem, None)
        .get(operator(&served, "/api/v1/agents"))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let agent = |uid: &InstanceUid| {
        fleet
            .iter()
            .find(|agent| agent["instance_uid"] == uid.to_string())
            .expect("in the fleet")
            .clone()
    };
    assert_eq!(
        agent(&supervisor)["host_attributes"]["fleet.host.organization"],
        "Kunde GmbH"
    );
    assert_eq!(agent(&supervisor)["host"], "h-direct");
    assert_eq!(agent(&downstream)["host"], "h-gw");
    assert_eq!(agent(&downstream)["host_attributes"], serde_json::json!({}));
}

// ---- A CSR's claim to an instance_uid (ADR-0021) ----

fn csr_claiming(subject: &str) -> Vec<u8> {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, subject);
    params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("csr pem")
        .into_bytes()
}

fn with_csr(uid: &InstanceUid, csr: Vec<u8>) -> AgentToServer {
    let mut message = report(uid);
    message.connection_settings_request = Some(ConnectionSettingsRequest {
        opamp: Some(OpAmpConnectionSettingsRequest {
            certificate_request: Some(CertificateRequest { csr }),
        }),
    });
    message
}

/// Verifies: ADR-0021
#[tokio::test]
async fn a_csr_claiming_another_instance_uid_is_a_bad_request() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let sender = InstanceUid::default();
    let other = InstanceUid::default();
    let reply = decode(
        post(
            &http,
            &served.endpoint,
            with_csr(&sender, csr_claiming(&format!("agent {other}"))),
        )
        .await,
    )
    .await;
    let error = reply.error_response.expect("an error");
    assert_eq!(error.r#type, ServerErrorResponseType::BadRequest as i32);
    assert!(reply.connection_settings.is_none(), "nothing was signed");
    assert!(served
        .revocations
        .as_ref()
        .expect("armed")
        .issued()
        .is_empty());
}

/// Verifies: ADR-0021
#[tokio::test]
async fn a_csr_claiming_its_own_instance_uid_is_signed() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let sender = InstanceUid::default();
    let reply = decode(
        post(
            &http,
            &served.endpoint,
            with_csr(&sender, csr_claiming(&format!("urn:uuid:{sender}"))),
        )
        .await,
    )
    .await;
    assert!(reply.error_response.is_none(), "{:?}", reply.error_response);
    assert!(reply.connection_settings.is_some(), "signed");
}

/// The regression guard: this project's own Client claims nothing (ADR-0021 clause 31).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_csr_claiming_nothing_is_signed_as_before() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let reply = decode(
        post(
            &http,
            &served.endpoint,
            with_csr(&InstanceUid::default(), csr_claiming("edge-01")),
        )
        .await,
    )
    .await;
    assert!(reply.error_response.is_none(), "{:?}", reply.error_response);
    assert!(reply.connection_settings.is_some(), "signed");
}

/// Verifies: ADR-0021
#[tokio::test]
async fn an_enrolment_csr_claiming_another_instance_uid_never_reaches_the_queue() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            ..Setup::default()
        },
    )
    .await;
    let enrolment = served.state.enrolment().expect("enrolment").clone();
    enrolment.open(60).expect("open");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let other = InstanceUid::default();
    let reply = decode(
        post(
            &enrolling,
            &served.endpoint,
            with_csr(&InstanceUid::default(), csr_claiming(&other.to_string())),
        )
        .await,
    )
    .await;
    let error = reply.error_response.expect("an error");
    assert_eq!(error.r#type, ServerErrorResponseType::BadRequest as i32);
    assert!(enrolment.pending().is_empty(), "it reached the queue");
}

/// The issuer is named by its role, so a CA whose subject has several parts — and a comma inside
/// one — is revoked as simply as any other; a role the Server does not have is refused (ADR-0021
/// clause 3).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_revocation_names_its_issuer_by_role_whatever_the_issuer_is_called() {
    let pki = Pki::with_organisation();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let revocations = format!(
        "https://localhost:{}/api/v1/revocations",
        served.operator_port
    );
    let operator = client(&served.ca_pem, None);
    let unknown = operator
        .post(&revocations)
        .json(&serde_json::json!({"certificate": {"authority": "bootstrap", "serial": "01"}}))
        .send()
        .await
        .expect("send");
    assert_eq!(unknown.status(), reqwest::StatusCode::BAD_REQUEST);
    let serial = cert_id(&cert).serial;
    let colons: String = serial
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("hex").to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let response = operator
        .post(&revocations)
        .json(&serde_json::json!({"certificate": {"authority": "client", "serial": colons}}))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let refused = post(&http, &served.endpoint, report(&InstanceUid::default())).await;
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// A CSR descends from the certificate the connection presented, whichever Agent the message
/// names: a self-asserted `instance_uid` cannot lift a renewal out of its chain, and behind a
/// Gateway revoking the Gateway reaches what was renewed through it (ADR-0021 clauses 33, 42).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_csr_for_another_agent_still_descends_from_the_presented_certificate() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (cert, key) = pki.issue("gateway-01");
    let mut socket = websocket(&served, &cert, &key, None)
        .await
        .expect("admitted");
    exchange(&mut socket, &InstanceUid::default()).await;
    let downstream = InstanceUid::default();
    let framed =
        opamp::frame::encode_within(&with_csr(&downstream, csr_claiming("edge-02")), usize::MAX)
            .expect("frame");
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
    let revocations = served.revocations.as_ref().expect("armed");
    let issued = revocations.issued();
    assert_eq!(issued.len(), 1, "the CSR was signed");
    let presented = cert_id(&cert);
    assert_eq!(issued[0].predecessor.as_ref(), Some(&presented));
    assert_eq!(issued[0].instance_uid, hex::encode(downstream.as_bytes()));
    revocations
        .revoke_certificate("client", &presented.serial)
        .expect("revoke");
    assert!(
        revocations.is_certificate_revoked(&issued[0].facts.id),
        "a renewal under another instance_uid escaped its chain"
    );
}

// ---- The audit record (ADR-0022) ----

/// An audit record on the filesystem, in `dir`.
fn audit_in(dir: &std::path::Path) -> Arc<dyn fleet_server::audit::Audit> {
    Arc::new(
        fleet_server::audit_log::AuditLog::start(
            Box::new(fleet_server::fs::FsAuditStore::open(dir).expect("store")),
            fleet_server::audit_log::Limits::default(),
            Arc::new(fleet_server::clock::SystemClock),
        )
        .expect("audit"),
    )
}

/// Every entry written so far, once `count` entries named `until` are among them.
async fn entries(dir: &std::path::Path, until: &str, count: usize) -> Vec<serde_json::Value> {
    // The writer keeps the order the entries were queued in, so once `count` entries named `until`
    // are on disk, everything queued before the last of them is too.
    let read = || -> Vec<serde_json::Value> {
        fleet_server::fs::audit_files(&dir.join("audit"))
            .expect("files")
            .iter()
            .flat_map(|file| {
                std::fs::read_to_string(file)
                    .expect("read")
                    .lines()
                    .map(|line| serde_json::from_str(line).expect("json"))
                    .collect::<Vec<serde_json::Value>>()
            })
            .collect()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let all = read();
        if named(&all, until).len() >= count {
            return all;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no {count} {until} entries were written: {all:#?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn named<'a>(entries: &'a [serde_json::Value], event: &str) -> Vec<&'a serde_json::Value> {
    entries.iter().filter(|e| e["event"] == event).collect()
}

/// A WebSocket admission and a refusal each leave exactly one entry, the refusal naming the
/// check that refused — here a revoked certificate.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_admission_and_its_refusal_each_leave_one_entry() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let mut socket = websocket(&served, &cert, &key, None)
        .await
        .expect("admitted");
    exchange(&mut socket, &InstanceUid::default()).await;
    let (revoked_cert, revoked_key) = pki.issue("edge-02");
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("client", &cert_id(&revoked_cert).serial)
        .expect("revoke");
    assert!(websocket(&served, &revoked_cert, &revoked_key, None)
        .await
        .is_err());

    let all = entries(dir.path(), "admission.refused", 1).await;
    let admitted = named(&all, "admission.admitted");
    assert_eq!(admitted.len(), 1, "{all:#?}");
    assert_eq!(admitted[0]["transport"], "websocket");
    assert_eq!(admitted[0]["serial"], cert_id(&cert).serial.as_str());
    let refused = named(&all, "admission.refused");
    assert_eq!(refused.len(), 1, "{all:#?}");
    assert_eq!(refused[0]["check"], "revoked");
}

/// An `Authorization` header a Client of the previous version sends is never written to the
/// record, neither its value nor any hash of it: the admission entry holds the certificate alone.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_authorization_an_older_client_sends_is_never_written() {
    use sha2::Digest as _;
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let token = "an-old-fleet-token-of-32-characters";
    let authorization = format!("Bearer {token}");
    let mut socket = websocket(&served, &cert, &key, Some(&authorization))
        .await
        .expect("admitted on its certificate");
    exchange(&mut socket, &InstanceUid::default()).await;
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let response = http
        .post(&served.endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::AUTHORIZATION, &authorization)
        .body(report(&InstanceUid::default()).encode_to_vec())
        .send()
        .await
        .expect("send");
    assert!(response.status().is_success(), "{:?}", response.status());

    let all = entries(dir.path(), "admission.admitted", 2).await;
    let admitted = named(&all, "admission.admitted");
    assert_eq!(admitted.len(), 2, "{all:#?}");
    let text = std::fs::read_dir(dir.path().join("audit"))
        .expect("dir")
        .map(|file| std::fs::read_to_string(file.expect("entry").path()).expect("read"))
        .collect::<String>();
    for secret in [
        token.to_string(),
        hex::encode(sha2::Sha256::digest(token.as_bytes())),
        hex::encode(sha2::Sha256::digest(authorization.as_bytes())),
    ] {
        assert!(!text.contains(&secret), "{secret} in {text}");
    }
    assert!(!text.contains("Bearer"), "{text}");
}

/// A renewal is recorded with the certificate it issued and the one it renewed.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_issued_certificate_is_recorded_with_its_predecessor() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    let reply = decode(
        post(
            &http,
            &served.endpoint,
            with_csr(&InstanceUid::default(), csr_claiming("edge-01")),
        )
        .await,
    )
    .await;
    assert!(reply.connection_settings.is_some(), "signed");
    let all = entries(dir.path(), "issuance.signed", 1).await;
    let signed = named(&all, "issuance.signed");
    assert_eq!(signed.len(), 1, "{all:#?}");
    assert_eq!(signed[0]["kind"], "renewal");
    assert_eq!(
        signed[0]["predecessor_serial"],
        cert_id(&cert).serial.as_str()
    );
}

/// A revocation records the session it ended.
/// Verifies: ADR-0022
#[tokio::test]
async fn a_revocation_records_the_sessions_it_ended() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let mut socket = websocket(&served, &cert, &key, None)
        .await
        .expect("admitted");
    exchange(&mut socket, &InstanceUid::default()).await;
    let serial = cert_id(&cert).serial;
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("client", &serial)
        .expect("revoke");
    closed_with(&mut socket, 5).await;
    let all = entries(dir.path(), "session.ended", 1).await;
    let ended = named(&all, "session.ended");
    assert_eq!(ended.len(), 1, "{all:#?}");
    assert_eq!(ended[0]["reason"], "revoked");
    assert_eq!(ended[0]["serial"], serial.as_str());
}

/// An operator's act is recorded with the operator's name before it runs and with its outcome
/// after, and a refused sign-in is recorded too.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_operator_act_names_the_operator() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = audit_in(dir.path());
    let rest_auth = toml::from_str::<fleet_server::config::RestAuthConfig>(&format!(
        "[basic_users]\nops = {:?}\n",
        fleet_server::credentials::hash_basic("s3cret").expect("hash")
    ))
    .expect("rest auth config");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit.clone()),
            operator_auth: Some(
                fleet_server::api::OperatorAuth::from_config(&rest_auth)
                    .expect("operator auth")
                    .with_audit(Some(audit)),
            ),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let operator = client(&served.ca_pem, None);
    let url = format!(
        "https://localhost:{}/api/v1/revocations",
        served.operator_port
    );
    let response = operator
        .post(&url)
        .basic_auth("ops", Some("s3cret"))
        .json(&serde_json::json!({"certificate": {"authority": "client", "serial": "abc123"}}))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let refused = operator
        .get(&url)
        .basic_auth("ops", Some("guess"))
        .send()
        .await
        .expect("send");
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);

    let all = entries(dir.path(), "operator.refused", 1).await;
    let acts = named(&all, "operator.act");
    assert_eq!(acts.len(), 2, "{all:#?}");
    assert_eq!(acts[0]["outcome"], "requested");
    assert_eq!(acts[0]["operator"], "ops");
    assert_eq!(acts[0]["path"], "/api/v1/revocations");
    assert_eq!(acts[1]["outcome"], "completed");
    assert_eq!(acts[1]["status"], 201);
    assert_eq!(named(&all, "revocation.revoked")[0]["serial"], "abc123");
    let refused = named(&all, "operator.refused");
    assert_eq!(refused.len(), 1, "{all:#?}");
    assert_eq!(refused[0]["operator"], "ops");
    assert!(!serde_json::to_string(&all).expect("json").contains("guess"));
}

/// A record that cannot be written stops admission: no Agent is admitted without its entry.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_audit_that_cannot_write_refuses_admission() {
    struct Broken;
    impl fleet_server::audit_log::AuditStore for Broken {
        fn tail(&mut self) -> Result<Option<fleet_server::audit_log::Tail>, String> {
            Ok(None)
        }
        fn append(&mut self, _: u64, _: &str) -> Result<(), String> {
            Err("disk full".to_string())
        }
        fn current_bytes(&self) -> u64 {
            0
        }
        fn rotate(&mut self, _: usize) -> Result<Vec<(String, String)>, String> {
            Ok(Vec::new())
        }
    }
    let pki = Pki::new();
    let audit: Arc<dyn fleet_server::audit::Audit> = Arc::new(
        fleet_server::audit_log::AuditLog::start(
            Box::new(Broken),
            fleet_server::audit_log::Limits::default(),
            Arc::new(fleet_server::clock::SystemClock),
        )
        .expect("audit"),
    );
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let http = client(&served.ca_pem, Some((&cert, &key)));
    // The first admission is queued; its write fails, and from then on nothing is admitted.
    let _ = post(&http, &served.endpoint, report(&InstanceUid::default())).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let other = client(
        &served.ca_pem,
        Some(pki.issue("edge-02"))
            .as_ref()
            .map(|(c, k)| (c.as_str(), k.as_str())),
    );
    let refused = post(&other, &served.endpoint, report(&InstanceUid::default())).await;
    assert_eq!(refused.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

/// A record that cannot be written stops issuance: a member whose session was admitted while the
/// record worked is handed no certificate once it fails.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_audit_that_cannot_write_issues_no_certificate() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Failing(Arc<AtomicBool>);
    impl fleet_server::audit_log::AuditStore for Failing {
        fn tail(&mut self) -> Result<Option<fleet_server::audit_log::Tail>, String> {
            Ok(None)
        }
        fn append(&mut self, _: u64, _: &str) -> Result<(), String> {
            if self.0.load(Ordering::SeqCst) {
                Err("disk full".to_string())
            } else {
                Ok(())
            }
        }
        fn current_bytes(&self) -> u64 {
            0
        }
        fn rotate(&mut self, _: usize) -> Result<Vec<(String, String)>, String> {
            Ok(Vec::new())
        }
    }
    let pki = Pki::new();
    let failing = Arc::new(AtomicBool::new(false));
    let audit: Arc<dyn fleet_server::audit::Audit> = Arc::new(
        fleet_server::audit_log::AuditLog::start(
            Box::new(Failing(failing.clone())),
            fleet_server::audit_log::Limits::default(),
            Arc::new(fleet_server::clock::SystemClock),
        )
        .expect("audit"),
    );
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let mut socket = websocket(&served, &cert, &key, None)
        .await
        .expect("admitted while the record works");
    let uid = InstanceUid::default();
    exchange(&mut socket, &uid).await;

    // The record fails at its next write — another peer's admission — and stays failed.
    failing.store(true, Ordering::SeqCst);
    let (other_cert, other_key) = pki.issue("edge-02");
    let _ = post(
        &client(&served.ca_pem, Some((&other_cert, &other_key))),
        &served.endpoint,
        report(&InstanceUid::default()),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;
    let (csr, _) = csr_for("edge-01");
    let framed = opamp::frame::encode_within(&with_csr(&uid, csr), usize::MAX).expect("frame");
    socket.send(Ws::Binary(framed.into())).await.expect("send");
    let reply = loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("a reply in time")
        {
            Some(Ok(Ws::Binary(bytes))) => {
                break opamp::frame::decode::<ServerToAgent>(&bytes, usize::MAX).expect("decode")
            }
            Some(Ok(_)) => continue,
            other => panic!("the session ended early: {other:?}"),
        }
    };
    assert!(
        reply
            .connection_settings
            .and_then(|s| s.opamp)
            .and_then(|o| o.certificate)
            .is_none(),
        "a certificate was issued without its record"
    );
    let error = reply.error_response.expect("the request is held back");
    assert_eq!(
        error.r#type,
        opamp::proto::ServerErrorResponseType::Unavailable as i32,
        "a record that cannot be written is the Server's to recover from, so the Agent retries"
    );
    assert!(
        matches!(
            error.details,
            Some(opamp::proto::server_error_response::Details::RetryInfo(ref info))
                if info.retry_after_nanoseconds > 0
        ),
        "the Agent is told when to ask again: {:?}",
        error.details
    );
    assert!(served
        .revocations
        .as_ref()
        .expect("armed")
        .issued()
        .is_empty());
}

// ---- The list a Gateway refuses by (ADR-0021 clause 43) ----

/// The certificate a CSR from `client` is answered with, and the key it was requested for.
async fn issued_through(served: &Served, client: &reqwest::Client, name: &str) -> (String, String) {
    let (csr, key) = csr_for(name);
    let reply = decode(
        post(
            client,
            &served.endpoint,
            with_csr(&InstanceUid::default(), csr),
        )
        .await,
    )
    .await;
    let cert = reply
        .connection_settings
        .and_then(|s| s.opamp)
        .and_then(|o| o.certificate)
        .expect("an issued certificate")
        .cert;
    (String::from_utf8(cert).expect("pem"), key.serialize_pem())
}

async fn fetch_list(
    served: &Served,
    client: &reqwest::Client,
    etag: Option<&str>,
) -> reqwest::Response {
    let mut request = client.get(
        served
            .endpoint
            .replace("/v1/opamp", "/v1/gateway/revocations"),
    );
    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    request.send().await.expect("send")
}

/// A member whose host is not marked as a Gateway and asks for the list is refused, and the refusal
/// is recorded with the host that asked.
/// Verifies: ADR-0022
#[tokio::test]
async fn an_unmarked_member_asking_for_the_list_leaves_a_refusal() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (provisioned, provisioned_key) = pki.issue("edge-01");
    let (cert, key) = issued_through(
        &served,
        &client(&served.ca_pem, Some((&provisioned, &provisioned_key))),
        "edge-01",
    )
    .await;
    let member = client(&served.ca_pem, Some((&cert, &key)));
    assert_eq!(
        fetch_list(&served, &member, None).await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let host = fleet_server::ca::facts(
        opamp::tls::certificates(cert.as_bytes()).expect("pem")[0].as_ref(),
    )
    .expect("facts")
    .host
    .expect("a host");

    let all = entries(dir.path(), "gateway_list.refused", 1).await;
    let refused = named(&all, "gateway_list.refused");
    assert_eq!(refused.len(), 1, "{all:#?}");
    assert_eq!(refused[0]["host"], host.as_str());
    assert_eq!(refused[0]["check"], "not a gateway");
}

/// Only a host marked as a Gateway is handed the list — admitted by its certificate alone — and
/// what it is handed names every revoked certificate of the client CA with its renewals resolved;
/// an unchanged list is answered `304`.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_marked_gateway_is_handed_the_revoked_certificates_with_their_renewals() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let revocations = served.revocations.clone().expect("armed");

    // The Gateway's own certificate, issued by the Server so that it names a host.
    let (provisioned, provisioned_key) = pki.issue("gateway-01");
    let (gateway_cert, gateway_key) = issued_through(
        &served,
        &client(&served.ca_pem, Some((&provisioned, &provisioned_key))),
        "gateway-01",
    )
    .await;
    let gateway = client(&served.ca_pem, Some((&gateway_cert, &gateway_key)));
    assert_eq!(
        fetch_list(&served, &gateway, None).await.status(),
        reqwest::StatusCode::FORBIDDEN,
        "an unmarked member is handed the list"
    );
    let host = fleet_server::ca::facts(
        opamp::tls::certificates(gateway_cert.as_bytes()).expect("pem")[0].as_ref(),
    )
    .expect("facts")
    .host
    .expect("a host");
    assert!(revocations.set_gateway(&host, true).expect("mark"));

    let empty = fetch_list(&served, &gateway, None).await;
    assert_eq!(empty.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = empty.json().await.expect("json");
    assert_eq!(body["certificates"], serde_json::json!([]));

    // A member that renewed, and then the certificate it renewed from is revoked.
    let (member, member_key) = pki.issue("edge-02");
    let (renewed, _) = issued_through(
        &served,
        &client(&served.ca_pem, Some((&member, &member_key))),
        "edge-02",
    )
    .await;
    revocations
        .revoke_certificate("client", &cert_id(&member).serial)
        .expect("revoke");

    let listed = fetch_list(&served, &gateway, None).await;
    let etag = listed
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("an ETag")
        .to_string();
    let body: serde_json::Value = listed.json().await.expect("json");
    let named: Vec<(String, String)> = body["certificates"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|c| {
            (
                c["issuer"].as_str().expect("issuer").to_string(),
                c["serial"].as_str().expect("serial").to_string(),
            )
        })
        .collect();
    for id in [cert_id(&member), cert_id(&renewed)] {
        assert!(
            named.contains(&(id.issuer.clone(), id.serial.clone())),
            "{id:?} not in {named:?}"
        );
    }
    assert_eq!(named.len(), 2, "{named:?}");

    assert_eq!(
        fetch_list(&served, &gateway, Some(&etag)).await.status(),
        reqwest::StatusCode::NOT_MODIFIED
    );
}

/// A bootstrap certificate is admitted, while the window is open, to enrol and to nothing else:
/// the list a Gateway refuses by is not for it.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_bootstrap_certificate_is_not_handed_the_list() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            bootstrap: Some(&bootstrap),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let opened = client(&served.ca_pem, None)
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    assert_eq!(opened.status(), 200);
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    assert_eq!(
        fetch_list(&served, &enrolling, None).await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
}

// ---- The rate limit on the Agent plane (ADR-0013) ----

/// A clock a test moves by hand, started at the real time so certificates and entries read true.
struct Manual(std::sync::atomic::AtomicU64);

impl fleet_server::fleet::Clock for Manual {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Manual {
    fn now() -> Arc<Self> {
        use fleet_server::fleet::Clock as _;
        Arc::new(Manual(std::sync::atomic::AtomicU64::new(
            fleet_server::clock::SystemClock.now_ms(),
        )))
    }

    fn advance(&self, secs: u64) {
        self.0
            .fetch_add(secs * 1000, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A bucket of `burst` messages that refills one a second.
fn burst(burst: u32) -> fleet_server::agent_rate::Limits {
    fleet_server::agent_rate::Limits {
        messages_per_sec: 1,
        burst,
        gateway_messages_per_sec: 1,
        gateway_burst: burst,
    }
}

/// Whether `reply` is the `Unavailable` of the rate limit or any other.
fn is_unavailable(reply: &ServerToAgent) -> bool {
    reply
        .error_response
        .as_ref()
        .is_some_and(|error| error.r#type == ServerErrorResponseType::Unavailable as i32)
}

/// The host a certificate in PEM names.
fn host_of(pem: &str) -> String {
    let der = opamp::tls::certificates(pem.as_bytes()).expect("pem");
    fleet_server::ca::facts(der[0].as_ref())
        .expect("facts")
        .host
        .expect("a host")
}

/// One report from `client`, answered.
async fn reported(served: &Served, client: &reqwest::Client) -> ServerToAgent {
    decode(post(client, &served.endpoint, report(&InstanceUid::default())).await).await
}

/// Two certificates of one host draw on one bucket, whichever of them a message comes over; a
/// certificate of another host has a bucket of its own.
/// Verifies: ADR-0013
#[tokio::test]
async fn two_certificates_of_one_host_share_a_bucket_and_two_hosts_do_not() {
    let pki = Pki::new();
    let served = serve(
        &pki,
        Setup {
            agent_rate: Some(burst(3)),
            clock: Some(Manual::now()),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (provisioned, provisioned_key) = pki.issue("edge-01");
    let (first, first_key) = issued_through(
        &served,
        &client(&served.ca_pem, Some((&provisioned, &provisioned_key))),
        "edge-01",
    )
    .await;
    let first_client = client(&served.ca_pem, Some((&first, &first_key)));
    // Its renewal names the same host, and takes the host's first token.
    let (second, second_key) = issued_through(&served, &first_client, "edge-01").await;
    assert_eq!(host_of(&first), host_of(&second));
    let second_client = client(&served.ca_pem, Some((&second, &second_key)));

    assert!(!is_unavailable(&reported(&served, &first_client).await));
    assert!(!is_unavailable(&reported(&served, &second_client).await));
    assert!(is_unavailable(&reported(&served, &first_client).await));
    assert!(
        is_unavailable(&reported(&served, &second_client).await),
        "the second certificate drew on the same, empty bucket"
    );

    let (other, other_key) = pki.issue("edge-02");
    let (third, third_key) = issued_through(
        &served,
        &client(&served.ca_pem, Some((&other, &other_key))),
        "edge-02",
    )
    .await;
    assert_ne!(host_of(&third), host_of(&first));
    let third_client = client(&served.ca_pem, Some((&third, &third_key)));
    assert!(!is_unavailable(&reported(&served, &third_client).await));
}

/// One bootstrap certificate presented from two addresses is two buckets: an enrolling host is
/// counted by where it connects from, not by a certificate the whole fleet may share.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_bootstrap_certificate_shared_by_two_addresses_is_two_buckets() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            agent_rate: Some(burst(1)),
            clock: Some(Manual::now()),
            ..Setup::default()
        },
    )
    .await;
    served
        .enrolment
        .as_ref()
        .expect("enrolment")
        .open(600)
        .expect("open the window");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap");
    let from = |address: &str| {
        let mut pem = key.as_bytes().to_vec();
        pem.extend_from_slice(cert.as_bytes());
        reqwest::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([reqwest::Certificate::from_pem(served.ca_pem.as_bytes()).expect("ca")])
            .resolve(
                "localhost",
                "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
            )
            .local_address(Some(address.parse().expect("address")))
            .identity(reqwest::Identity::from_pem(&pem).expect("identity"))
            .build()
            .expect("client")
    };
    let (one, two) = (from("127.0.0.1"), from("127.0.0.2"));
    assert!(!is_unavailable(&reported(&served, &one).await));
    assert!(is_unavailable(&reported(&served, &one).await));
    assert!(
        !is_unavailable(&reported(&served, &two).await),
        "another address, another bucket"
    );
}

/// The record's lines, in memory: no disk to wait on.
#[derive(Clone, Default)]
struct Lines(Arc<std::sync::Mutex<Vec<String>>>);

impl fleet_server::audit_log::AuditStore for Lines {
    fn tail(&mut self) -> Result<Option<fleet_server::audit_log::Tail>, String> {
        Ok(None)
    }
    fn append(&mut self, _: u64, line: &str) -> Result<(), String> {
        self.0.lock().expect("lines").push(line.to_string());
        Ok(())
    }
    fn current_bytes(&self) -> u64 {
        0
    }
    fn rotate(&mut self, _: usize) -> Result<Vec<(String, String)>, String> {
        Ok(Vec::new())
    }
}

/// Every throttled message is passed to the record as a refusal naming the host; past ten a second
/// from one address the rest are counted in `agent_rate.throttled.aggregated`. The record runs on
/// the Server's frozen clock, so every refusal falls into one second: ten are written and the
/// other fifteen are counted once the clock has moved past it.
/// Verifies: ADR-0013, ADR-0022
#[tokio::test]
async fn a_throttled_message_leaves_an_aggregated_refusal_naming_the_host() {
    const REFUSED: u64 = 25;
    let pki = Pki::new();
    let lines = Lines::default();
    // Frozen, so the bucket stays empty and every refusal is recorded in the same second.
    let clock = Manual::now();
    let audit: Arc<dyn fleet_server::audit::Audit> = Arc::new(
        fleet_server::audit_log::AuditLog::start(
            Box::new(lines.clone()),
            fleet_server::audit_log::Limits::default(),
            clock.clone(),
        )
        .expect("audit"),
    );
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit),
            agent_rate: Some(burst(1)),
            clock: Some(clock.clone()),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let (provisioned, provisioned_key) = pki.issue("edge-01");
    let (cert, key) = issued_through(
        &served,
        &client(&served.ca_pem, Some((&provisioned, &provisioned_key))),
        "edge-01",
    )
    .await;
    let host = host_of(&cert);
    let member = client(&served.ca_pem, Some((&cert, &key)));
    assert!(!is_unavailable(&reported(&served, &member).await));
    for _ in 0..REFUSED {
        assert!(is_unavailable(&reported(&served, &member).await));
    }
    clock.advance(1);

    // The writer counts a second's excess on its next tick after that second has passed.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let (written, aggregated) = loop {
        let all: Vec<serde_json::Value> = lines
            .0
            .lock()
            .expect("lines")
            .iter()
            .map(|line| serde_json::from_str(line).expect("json"))
            .collect();
        let aggregated: Vec<_> = named(&all, "agent_rate.throttled.aggregated")
            .into_iter()
            .cloned()
            .collect();
        if !aggregated.is_empty() {
            let written: Vec<_> = named(&all, "agent_rate.throttled")
                .into_iter()
                .cloned()
                .collect();
            break (written, aggregated);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no aggregate was written: {all:#?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert_eq!(written.len(), 10, "ten a second are written");
    assert_eq!(aggregated.len(), 1, "{aggregated:#?}");
    assert_eq!(aggregated[0]["count"].as_u64(), Some(REFUSED - 10));
    for entry in &written {
        assert_eq!(entry["outcome"], "throttled");
        assert_eq!(entry["host"], host.as_str());
        assert_eq!(entry["bucket"], "host");
        assert_eq!(entry["route"], "opamp");
        assert_eq!(entry["transport"], "http");
        assert_eq!(entry["peer"], "127.0.0.1");
        assert_eq!(entry["instance_uid"].as_str().map(str::len), Some(32));
    }
    for entry in &aggregated {
        assert_eq!(entry["peer"], "127.0.0.1");
    }
}

/// One bootstrap certificate holds at most its share of the enrolment queue: past it, a request
/// for a fresh key is answered `Unavailable` with `retry_info` and audited once for the window,
/// a request of another bootstrap certificate is still queued, and a re-sent request of the first
/// still joins its own entry.
/// Verifies: ADR-0046
#[tokio::test]
async fn one_bootstrap_certificate_holds_at_most_its_share_of_the_queue() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let lines = Lines::default();
    let clock = Manual::now();
    let audit: Arc<dyn fleet_server::audit::Audit> = Arc::new(
        fleet_server::audit_log::AuditLog::start(
            Box::new(lines.clone()),
            fleet_server::audit_log::Limits::default(),
            clock.clone(),
        )
        .expect("audit"),
    );
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            audit: Some(audit),
            clock: Some(clock),
            max_pending_per_bootstrap: Some(2),
            ..Setup::default()
        },
    )
    .await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    enrolment.open(600).expect("open the window");
    let (first_cert, first_key) = bootstrap.issue_bootstrap("bootstrap-1");
    let first = client(&served.ca_pem, Some((&first_cert, &first_key)));
    let uid = InstanceUid::default();
    let send = |client: &reqwest::Client, csr: Vec<u8>| {
        let message = with_csr(&uid, csr);
        let client = client.clone();
        let endpoint = served.endpoint.clone();
        async move { decode(post(&client, &endpoint, message).await).await }
    };
    let (kept, _) = csr_for("edge-01");
    assert!(!is_unavailable(&send(&first, kept.clone()).await));
    assert!(!is_unavailable(&send(&first, csr_for("edge-02").0).await));
    for _ in 0..2 {
        let refused = send(&first, csr_for("edge-03").0).await;
        assert!(is_unavailable(&refused), "{refused:?}");
        assert!(
            refused
                .error_response
                .as_ref()
                .is_some_and(|error| error.details.is_some()),
            "told when to retry: {refused:?}"
        );
    }
    assert!(
        !is_unavailable(&send(&first, kept).await),
        "a re-sent request joins its own entry"
    );
    let (other_cert, other_key) = bootstrap.issue_bootstrap("bootstrap-2");
    let other = client(&served.ca_pem, Some((&other_cert, &other_key)));
    assert!(
        !is_unavailable(&send(&other, csr_for("edge-04").0).await),
        "another bootstrap certificate is still queued"
    );
    assert_eq!(enrolment.pending().len(), 3);

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let refused = loop {
        let all: Vec<serde_json::Value> = lines
            .0
            .lock()
            .expect("lines")
            .iter()
            .map(|line| serde_json::from_str(line).expect("json"))
            .collect();
        if named(&all, "enrolment.queued").len() == 3 {
            break named(&all, "enrolment.refused")
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the queued requests were never recorded: {all:#?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(
        refused.len(),
        1,
        "once per certificate and window: {refused:#?}"
    );
    assert_eq!(refused[0]["outcome"], "refused");
    assert_eq!(refused[0]["reason"], "bootstrap_share");
    assert_eq!(refused[0]["peer"], "127.0.0.1");
    assert!(refused[0]["bootstrap_serial"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

/// Each `Unavailable` this Server sends carries the `instance_uid` of the message it answers — the
/// field the Client and a Gateway route a reply by: the rate limit's, the Agent-record ceiling's, a
/// CSR held back for its record, the full enrolment queue and the closed enrolment window.
/// Verifies: ADR-0013, ADR-0021, ADR-0022
#[tokio::test]
async fn every_unavailable_reply_names_the_agent_it_answers() {
    let names_its_agent = |reply: &ServerToAgent, uid: &InstanceUid, case: &str| {
        assert!(is_unavailable(reply), "{case}: {reply:?}");
        assert_eq!(reply.instance_uid, uid.as_bytes(), "{case}");
    };
    let pki = Pki::new();

    // The rate limit.
    let served = serve(
        &pki,
        Setup {
            agent_rate: Some(burst(1)),
            clock: Some(Manual::now()),
            ..Setup::default()
        },
    )
    .await;
    let (cert, key) = pki.issue("edge-01");
    let member = client(&served.ca_pem, Some((&cert, &key)));
    reported(&served, &member).await;
    let uid = InstanceUid::default();
    let reply = decode(post(&member, &served.endpoint, report(&uid)).await).await;
    names_its_agent(&reply, &uid, "throttled");

    // The Agent-record ceiling.
    let served = serve(
        &pki,
        Setup {
            max_agents: Some(1),
            ..Setup::default()
        },
    )
    .await;
    let member = client(&served.ca_pem, Some((&cert, &key)));
    reported(&served, &member).await;
    let uid = InstanceUid::default();
    let reply = decode(post(&member, &served.endpoint, report(&uid)).await).await;
    names_its_agent(&reply, &uid, "ceiling");

    // A CSR held back for its audit record. A plain-HTTP member's admission is recorded once an
    // hour, so the member is still admitted after the record fails; its CSR is not signed.
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Failing(Arc<std::sync::atomic::AtomicBool>);
    impl fleet_server::audit_log::AuditStore for Failing {
        fn tail(&mut self) -> Result<Option<fleet_server::audit_log::Tail>, String> {
            Ok(None)
        }
        fn append(&mut self, _: u64, _: &str) -> Result<(), String> {
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                Err("disk full".to_string())
            } else {
                Ok(())
            }
        }
        fn current_bytes(&self) -> u64 {
            0
        }
        fn rotate(&mut self, _: usize) -> Result<Vec<(String, String)>, String> {
            Ok(Vec::new())
        }
    }
    let audit: Arc<dyn fleet_server::audit::Audit> = Arc::new(
        fleet_server::audit_log::AuditLog::start(
            Box::new(Failing(failing.clone())),
            fleet_server::audit_log::Limits::default(),
            Arc::new(fleet_server::clock::SystemClock),
        )
        .expect("audit"),
    );
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit.clone()),
            ..revocations_setup(&pki)
        },
    )
    .await;
    let member = client(&served.ca_pem, Some((&cert, &key)));
    reported(&served, &member).await;
    failing.store(true, std::sync::atomic::Ordering::SeqCst);
    // The record turns unavailable once its writer has failed to append; wait for that, not for
    // a fixed time.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while audit
        .record(fleet_server::audit::Entry::new("probe", "probe"))
        .is_ok()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the record never turned unavailable"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let uid = InstanceUid::default();
    let (csr, _) = csr_for("edge-01");
    let reply = decode(post(&member, &served.endpoint, with_csr(&uid, csr)).await).await;
    names_its_agent(&reply, &uid, "a CSR held back");

    // The full enrolment queue, and the window that closed while a host was connected.
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let clock = Manual::now();
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            clock: Some(clock.clone()),
            ..Setup::default()
        },
    )
    .await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    enrolment.open(60).expect("open the window");
    for n in 0..fleet_server::enrolment::MAX_PENDING {
        let request = fleet_server::enrolment::Request {
            csr_pem: String::new(),
            subject: format!("CN=filler-{n}"),
            key_fingerprint: format!("{n:064x}"),
            instance_uid: vec![0; 16],
        };
        let requester = fleet_server::enrolment::Requester {
            bootstrap_subject: String::new(),
            carried: Ok(fleet_server::revocation::SubjectValues::default()),
            bootstrap_fingerprint: String::new(),
            // One bootstrap certificate holds a quarter of the queue at most (ADR-0046): the
            // fillers come with one each, so they fill it all.
            bootstrap: fleet_server::revocation::CertId {
                issuer: String::new(),
                serial: format!("{n:x}"),
            },
            peer: None,
            gateway: None,
        };
        assert_eq!(
            enrolment.submit(request, requester),
            fleet_server::enrolment::Submitted::Waiting
        );
    }
    let (bootstrap_cert, bootstrap_key) = bootstrap.issue_bootstrap("bootstrap");
    let enrolling = client(&served.ca_pem, Some((&bootstrap_cert, &bootstrap_key)));
    let uid = InstanceUid::default();
    let (csr, _) = csr_for("edge-03");
    let reply = decode(post(&enrolling, &served.endpoint, with_csr(&uid, csr)).await).await;
    names_its_agent(&reply, &uid, "the full enrolment queue");

    enrolment.close().expect("close");
    enrolment.open(60).expect("open the window");
    let mut socket = websocket(&served, &bootstrap_cert, &bootstrap_key, None)
        .await
        .expect("admitted while the window is open");
    clock.advance(61);
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;
    let uid = InstanceUid::default();
    let (csr, _) = csr_for("edge-04");
    let framed = opamp::frame::encode_within(&with_csr(&uid, csr), usize::MAX).expect("frame");
    socket.send(Ws::Binary(framed.into())).await.expect("send");
    let reply = loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("a reply in time")
        {
            Some(Ok(Ws::Binary(bytes))) => {
                break opamp::frame::decode::<ServerToAgent>(&bytes, usize::MAX).expect("decode")
            }
            Some(Ok(_)) => continue,
            other => panic!("the session ended before its reply: {other:?}"),
        }
    };
    names_its_agent(&reply, &uid, "the closed enrolment window");
}

// ---- A host fetches only what is offered to its own Agents (ADR-0026) ----

/// The Agent type the delivery tests release.
const OTELCOL: &str = "otelcol";

/// A Server with package delivery, a host register and the client CA.
fn delivery_setup(pki: &Pki) -> Setup<'static> {
    Setup {
        packages: true,
        ..revocations_setup(pki)
    }
}

/// A host's client: a certificate naming `host`.
fn host_client(served: &Served, pki: &Pki, host: &str) -> reqwest::Client {
    let (cert, key) = pki.issue_to_host(host);
    client(&served.ca_pem, Some((&cert, &key)))
}

/// A report of an `otelcol` Agent on linux/amd64 that accepts packages.
fn package_report(uid: &InstanceUid) -> AgentToServer {
    let attr = opamp::attributes::string_attr;
    AgentToServer {
        agent_description: Some(opamp::proto::AgentDescription {
            identifying_attributes: vec![attr("service.name", OTELCOL)],
            non_identifying_attributes: vec![attr("os.type", "linux"), attr("host.arch", "amd64")],
        }),
        capabilities: AgentCapabilities::ReportsStatus as u64
            | AgentCapabilities::AcceptsPackages as u64,
        ..report(uid)
    }
}

fn linux() -> fleet_server::packages::Platform {
    fleet_server::packages::Platform::new("linux", "amd64").expect("platform")
}

/// Uploads `artifact` as `otelcol@<version>` for linux/amd64, signs it, and puts it into the
/// `stable` channel that claims every `otelcol` — saved, released to nobody.
fn save(served: &Served, version: &str, artifact: &[u8]) {
    let id = fleet_server::packages::PackageId::new(OTELCOL, version).expect("id");
    let store = served.state.packages().expect("package delivery");
    store.create(&id).expect("create");
    store
        .put_entry(&id, &linux(), artifact.to_vec())
        .expect("entry");
    served
        .state
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
    served
        .state
        .put_deployment_package("stable", &id, true)
        .expect("package");
}

/// `GET` of the download route for `otelcol@<version>`, with a raw query.
async fn fetch(served: &Served, client: &reqwest::Client, path: &str) -> reqwest::Response {
    client
        .get(served.endpoint.replace("/v1/opamp", path))
        .send()
        .await
        .expect("send")
}

fn artifact_path(version: &str) -> String {
    format!("/api/v1/packages/{OTELCOL}/{version}/file?os=linux&arch=amd64")
}

/// One host's Agent is reported, and `version` is saved and released to it by the press.
async fn released_to(served: &Served, host: &reqwest::Client, version: &str, artifact: &[u8]) {
    post(
        host,
        &served.endpoint,
        package_report(&InstanceUid([1; 16])),
    )
    .await;
    save(served, version, artifact);
    assert_eq!(
        served
            .state
            .rollout_deployment("stable")
            .expect("the press"),
        1
    );
}

/// A host fetches the artifact released to the Agent that reported with its certificate.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_host_fetches_the_artifact_offered_to_its_own_agent() {
    let pki = Pki::new();
    let served = serve(&pki, delivery_setup(&pki)).await;
    let host = host_client(&served, &pki, "h1");
    released_to(&served, &host, "1.0.0", b"the-binary").await;
    let response = fetch(&served, &host, &artifact_path("1.0.0")).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("bytes").as_ref(),
        b"the-binary"
    );
}

/// Another member of the fleet is answered `404` for what was released to one host's Agent alone.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_host_is_answered_404_for_an_artifact_offered_only_to_another_host() {
    let pki = Pki::new();
    let served = serve(&pki, delivery_setup(&pki)).await;
    released_to(
        &served,
        &host_client(&served, &pki, "h1"),
        "1.0.0",
        b"the-binary",
    )
    .await;
    let other = host_client(&served, &pki, "h2");
    post(&other, &served.endpoint, report(&InstanceUid([2; 16]))).await;
    let response = fetch(&served, &other, &artifact_path("1.0.0")).await;
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
    let pki = Pki::new();
    let served = serve(&pki, delivery_setup(&pki)).await;
    let other = host_client(&served, &pki, "h2");
    post(&other, &served.endpoint, report(&InstanceUid([2; 16]))).await;

    let not_held = answer(fetch(&served, &other, &artifact_path("1.0.0")).await).await;
    assert_eq!(not_held.0, 404);

    let unsigned = fleet_server::packages::PackageId::new(OTELCOL, "1.0.0").expect("id");
    let store = served.state.packages().expect("package delivery");
    store.create(&unsigned).expect("create");
    store
        .put_entry(&unsigned, &linux(), b"the-binary".to_vec())
        .expect("entry");
    let only_unsigned = answer(fetch(&served, &other, &artifact_path("1.0.0")).await).await;
    assert_eq!(only_unsigned, not_held, "an unsigned entry");
    store.delete_set(&unsigned).expect("delete");

    let host = host_client(&served, &pki, "h1");
    post(
        &host,
        &served.endpoint,
        package_report(&InstanceUid([1; 16])),
    )
    .await;
    save(&served, "1.0.0", b"the-binary");
    let released_to_nobody = answer(fetch(&served, &other, &artifact_path("1.0.0")).await).await;
    assert_eq!(
        released_to_nobody, not_held,
        "an artifact released to nobody"
    );

    served
        .state
        .rollout_deployment("stable")
        .expect("the press");
    let released_to_another = answer(fetch(&served, &other, &artifact_path("1.0.0")).await).await;
    assert_eq!(
        released_to_another, not_held,
        "an artifact of another host's Agent"
    );
    assert_eq!(
        fetch(&served, &host, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::OK
    );
}

/// A host marked as a Gateway speaks for any Agent, so it fetches what is offered to any; before
/// it is marked, it fetches nothing of another host's.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_marked_gateway_fetches_what_is_offered_to_any_agent() {
    let pki = Pki::new();
    let served = serve(&pki, delivery_setup(&pki)).await;
    released_to(
        &served,
        &host_client(&served, &pki, "h1"),
        "1.0.0",
        b"the-binary",
    )
    .await;
    let gateway = host_client(&served, &pki, "gw");
    post(&gateway, &served.endpoint, report(&InstanceUid([9; 16]))).await;
    assert_eq!(
        fetch(&served, &gateway, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert!(served
        .revocations
        .as_ref()
        .expect("register")
        .set_gateway("gw", true)
        .expect("mark"));
    let response = fetch(&served, &gateway, &artifact_path("1.0.0")).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("bytes").as_ref(),
        b"the-binary"
    );
}

/// A certificate that names no host speaks for no Agent — not even the one it reported, to which
/// the artifact was released.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_certificate_naming_no_host_fetches_nothing() {
    let pki = Pki::new();
    let served = serve(&pki, delivery_setup(&pki)).await;
    let (cert, key) = pki.issue("edge-01");
    let provisioned = client(&served.ca_pem, Some((&cert, &key)));
    released_to(&served, &provisioned, "1.0.0", b"the-binary").await;
    assert_eq!(
        fetch(&served, &provisioned, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

/// A fetch that is not offered leaves one `download.refused` entry naming the check, the host, the
/// certificate's serial and the artifact asked for; it is no failure the admission throttle counts,
/// which here backs off after one.
/// Verifies: ADR-0026, ADR-0022
#[tokio::test]
async fn a_refused_fetch_leaves_one_download_refused_entry_naming_its_check() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            throttle: Some(fleet_server::throttle::Limits {
                max_failures: 1,
                window_secs: 60,
                backoff_secs: 300,
            }),
            ..delivery_setup(&pki)
        },
    )
    .await;
    released_to(
        &served,
        &host_client(&served, &pki, "h1"),
        "1.0.0",
        b"the-binary",
    )
    .await;
    let (cert, key) = pki.issue_to_host("h2");
    let other = client(&served.ca_pem, Some((&cert, &key)));
    assert_eq!(
        fetch(&served, &other, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    let all = entries(dir.path(), "download.refused", 1).await;
    let refused = named(&all, "download.refused");
    assert_eq!(refused.len(), 1, "{all:#?}");
    assert_eq!(refused[0]["outcome"], "refused");
    assert_eq!(refused[0]["check"], "not offered");
    assert_eq!(refused[0]["host"], "h2");
    assert_eq!(refused[0]["serial"], cert_id(&cert).serial.as_str());
    assert_eq!(refused[0]["agent_type"], OTELCOL);
    assert_eq!(refused[0]["version"], "1.0.0");
    assert_eq!(refused[0]["platform"], "linux-amd64");

    // Past the throttle's one failure, the same address is still admitted.
    assert_eq!(
        fetch(&served, &other, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert!(
        post(&other, &served.endpoint, report(&InstanceUid([2; 16])))
            .await
            .status()
            .is_success()
    );
}

/// A malformed identity or Platform token is a `400`, decided before any offer is tested: no
/// `download.refused` entry follows it.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_malformed_token_is_answered_400_before_the_offer_is_tested() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            audit: Some(audit_in(dir.path())),
            ..delivery_setup(&pki)
        },
    )
    .await;
    let other = host_client(&served, &pki, "h2");
    for path in [
        "/api/v1/packages/otel@col/1.0.0/file?os=linux&arch=amd64",
        "/api/v1/packages/otelcol/1.0.0/file?os=lin%2Fux&arch=amd64",
        "/api/v1/packages/otelcol/1.0.0/file?os=linux",
    ] {
        assert_eq!(
            fetch(&served, &other, path).await.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    // One more admission, queued after whatever the three caused: once it is on disk, so is that.
    fetch(
        &served,
        &other,
        "/api/v1/packages/otelcol/1.0.0/file?os=linux",
    )
    .await;
    let all = entries(dir.path(), "download.admitted", 4).await;
    assert!(named(&all, "download.refused").is_empty(), "{all:#?}");
}

/// A download takes a token from the bucket of the host its certificate names — the bucket its
/// Agent's messages draw on.
/// Verifies: ADR-0026, ADR-0013
#[tokio::test]
async fn a_download_costs_a_token_of_the_hosts_bucket() {
    let pki = Pki::new();
    let served = serve(
        &pki,
        Setup {
            agent_rate: Some(burst(2)),
            clock: Some(Manual::now()),
            ..delivery_setup(&pki)
        },
    )
    .await;
    let host = host_client(&served, &pki, "h1");
    released_to(&served, &host, "1.0.0", b"the-binary").await;
    assert_eq!(
        fetch(&served, &host, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert!(
        is_unavailable(
            &decode(
                post(
                    &host,
                    &served.endpoint,
                    package_report(&InstanceUid([1; 16]))
                )
                .await
            )
            .await
        ),
        "the download took the host's second token"
    );
    assert_eq!(
        fetch(&served, &host, &artifact_path("1.0.0"))
            .await
            .status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS
    );
}

/// A bootstrap certificate the Server issues carries the subject the operator named into the
/// enrolment queue, is listed until it is revoked by its serial, and once revoked opens nothing
/// (ADR-0028 clauses 21, 22 and 24 and ADR-0021 clause 10).
/// Verifies: ADR-0028
#[tokio::test]
async fn an_issued_bootstrap_certificate_enrols_is_listed_and_revoked_by_its_serial() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let audit_dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            revocations: true,
            audit: Some(audit_in(audit_dir.path())),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let response = operator_client
        .post(operator(&served, "/api/v1/bootstrap-certificates"))
        .json(&serde_json::json!({
            "subject": { "organization": "Kunde GmbH", "organizational_unit": "Wien" },
            "validity_days": 3,
            "password": BOOTSTRAP_PASSWORD
        }))
        .send()
        .await
        .expect("issue");
    assert_eq!(response.status(), 201);
    assert_eq!(
        response.headers()["cache-control"],
        "no-store",
        "the answer is not kept on the way"
    );
    let issued: serde_json::Value = response.json().await.expect("json");
    assert!(
        issued.get("private_key_pem").is_none(),
        "an issue never answers the key: {issued}"
    );
    let serial = issued["serial"].as_str().expect("serial").to_string();
    let subject = issued["subject"].as_str().expect("subject");
    assert!(
        subject == "O=Kunde GmbH, OU=Wien, CN=acme bootstrap Certificate",
        "{subject}"
    );
    let cert = issued["certificate_pem"].as_str().expect("cert");
    let key = &bootstrap_key(&served, &operator_client, &serial).await;
    let recorded = entries(audit_dir.path(), "enrolment.bootstrap_issued", 1).await;
    let recorded = named(&recorded, "enrolment.bootstrap_issued");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0]["serial"], serial.as_str());
    // The key is in no file the Server writes in the clear (ADR-0036 clause 8).
    let key_body = key
        .lines()
        .find(|line| !line.starts_with("-----"))
        .expect("key body");
    for root in [served.config_dir.as_path(), audit_dir.path()] {
        for file in walk(root) {
            let text = String::from_utf8_lossy(&std::fs::read(&file).expect("read")).into_owned();
            assert!(!text.contains(key_body), "{} holds the key", file.display());
        }
    }

    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed[0]["serial"], serial.as_str());
    assert_eq!(listed[0]["revoked"], false);
    assert!(
        listed[0].get("private_key_pem").is_none(),
        "the key is not kept"
    );

    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let enrolling = client(&served.ca_pem, Some((cert, key)));
    let (csr, _key) = csr_for("edge-01");
    decode(post(&enrolling, &served.endpoint, csr_report(csr.clone())).await).await;
    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("pending")
        .json()
        .await
        .expect("json");
    assert_eq!(
        pending[0]["bootstrap_subject"],
        serde_json::json!({
            "country": "", "state": "", "locality": "",
            "organization": "Kunde GmbH", "organizational_unit": "Wien",
            "organization_identifier": ""
        }),
        "the approver sees whose certificate the request carries"
    );
    assert_eq!(
        pending[0]["bootstrap_serial"], listed[0]["serial"],
        "the request names the issued certificate as the record lists it"
    );

    let revoked = operator_client
        .post(operator(&served, "/api/v1/revocations"))
        .json(&serde_json::json!({
            "certificate": { "authority": "bootstrap", "serial": serial }
        }))
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), 201);
    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed[0]["revoked"], true);
    let enrolling = client(&served.ca_pem, Some((cert, key)));
    let refused = post(&enrolling, &served.endpoint, csr_report(csr)).await;
    assert!(
        !refused.status().is_success(),
        "a revoked bootstrap certificate opens nothing: {}",
        refused.status()
    );
}

/// A request waits only while the bootstrap certificate it came with stands: revoking that
/// certificate takes its waiting requests out of the queue, and no approval signs one afterwards —
/// a CSR is signed only once its certificate has been checked again (ADR-0021 clause 35).
/// Verifies: ADR-0021
#[tokio::test]
async fn revoking_a_bootstrap_certificate_withdraws_the_requests_waiting_with_it() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let audit_dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            revocations: true,
            audit: Some(audit_in(audit_dir.path())),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let issued: serde_json::Value = operator_client
        .post(operator(&served, "/api/v1/bootstrap-certificates"))
        .json(&serde_json::json!({
            "subject": customer_and_site(),
            "password": BOOTSTRAP_PASSWORD
        }))
        .send()
        .await
        .expect("issue")
        .json()
        .await
        .expect("json");
    let serial = issued["serial"].as_str().expect("serial");
    let cert = issued["certificate_pem"].as_str().expect("cert");
    let key = &bootstrap_key(&served, &operator_client, serial).await;
    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let enrolling = client(&served.ca_pem, Some((cert, key)));
    let (csr, _key) = csr_for("edge-01");
    decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    let pending = |served: &Served| {
        let operator_client = operator_client.clone();
        let url = operator(served, "/api/v1/enrolments");
        async move {
            operator_client
                .get(url)
                .send()
                .await
                .expect("pending")
                .json::<Vec<serde_json::Value>>()
                .await
                .expect("json")
        }
    };
    let waiting = pending(&served).await;
    assert_eq!(waiting.len(), 1, "the request waits: {waiting:?}");
    let id = waiting[0]["id"].as_str().expect("id").to_string();

    let revoked = operator_client
        .post(operator(&served, "/api/v1/revocations"))
        .json(&serde_json::json!({
            "certificate": { "authority": "bootstrap", "serial": serial }
        }))
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), 201);
    assert!(
        pending(&served).await.is_empty(),
        "the revoked certificate's request no longer waits"
    );
    let approved = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/approve"),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(
        approved.status(),
        404,
        "no approval signs a request whose bootstrap certificate is revoked"
    );
    let recorded = entries(audit_dir.path(), "revocation.revoked", 1).await;
    let recorded = named(&recorded, "revocation.revoked");
    assert_eq!(
        recorded[0]["withdrawn_requests"], 1,
        "the revocation's record counts the request it withdrew"
    );
}

/// The issuing route answers a password of 7 characters `400`, naming the rule, and issues a
/// bootstrap certificate under one of 8.
/// Verifies: ADR-0048
#[tokio::test]
async fn a_bootstrap_password_is_at_least_eight_characters() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let issue = |password: &'static str| {
        operator_client
            .post(operator(&served, "/api/v1/bootstrap-certificates"))
            .json(&serde_json::json!({ "subject": customer_and_site(), "password": password }))
            .send()
    };
    let refused = issue("seven c").await.expect("issue");
    assert_eq!(refused.status(), 400);
    let body = refused.text().await.expect("body");
    assert!(
        body.contains("password must be 8 to 128 characters"),
        "{body}"
    );
    let issued = issue("eight ch").await.expect("issue");
    assert_eq!(issued.status(), 201);
}

/// Issued with a password, a bootstrap certificate's key is in no answer: the Server keeps a
/// PKCS#12 file of it under the password and hands it out as often as asked, each download on the
/// record, until the certificate is revoked — and the file enrols like the pair. The password is
/// in no file the Server writes (ADR-0029 clauses 2 to 4).
/// Verifies: ADR-0029
#[tokio::test]
async fn a_bootstrap_certificate_issued_with_a_password_is_a_pkcs12_file_until_revoked() {
    const PASSWORD: &str = "a password of the operator";
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let audit_dir = tempfile::tempdir().expect("tempdir");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            revocations: true,
            audit: Some(audit_in(audit_dir.path())),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    for short in ["abc", "tab\tin a long password"] {
        let refused = operator_client
            .post(operator(&served, "/api/v1/bootstrap-certificates"))
            .json(&serde_json::json!({ "subject": customer_and_site(), "password": short }))
            .send()
            .await
            .expect("issue");
        assert_eq!(refused.status(), 400, "{short:?}");
    }
    let response = operator_client
        .post(operator(&served, "/api/v1/bootstrap-certificates"))
        .json(&serde_json::json!({
            "subject": customer_and_site(),
            "password": PASSWORD
        }))
        .send()
        .await
        .expect("issue");
    assert_eq!(response.status(), 201);
    let issued: serde_json::Value = response.json().await.expect("json");
    assert!(
        issued.get("private_key_pem").is_none(),
        "no PEM key: {issued}"
    );
    let serial = issued["serial"].as_str().expect("serial").to_string();
    let cert = issued["certificate_pem"]
        .as_str()
        .expect("cert")
        .to_string();

    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed[0]["p12"], true);

    let download = |client: reqwest::Client| {
        let url = operator(
            &served,
            &format!("/api/v1/bootstrap-certificates/{serial}/p12"),
        );
        async move { client.get(url).send().await.expect("download") }
    };
    let mut file = Vec::new();
    for _ in 0..2 {
        let response = download(operator_client.clone()).await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "application/x-pkcs12");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["content-disposition"],
            "attachment; filename=\"bootstrap.p12\""
        );
        file = response.bytes().await.expect("body").to_vec();
    }
    let opened = fleet_core::pkcs12::file::open(&file, PASSWORD).expect("opens");
    assert_eq!(
        opened.certificate_der,
        opamp::tls::certificates(cert.as_bytes()).expect("pem")[0].as_ref(),
        "the certificate issued"
    );
    let recorded = entries(audit_dir.path(), "enrolment.bootstrap_p12_downloaded", 2).await;
    let issuance = named(&recorded, "enrolment.bootstrap_issued");
    assert_eq!(issuance[0]["p12"], "true");
    assert_eq!(
        named(&recorded, "enrolment.bootstrap_p12_downloaded").len(),
        2,
        "each download is on the record"
    );
    for root in [served.config_dir.as_path(), audit_dir.path()] {
        for written in walk(root) {
            let bytes = std::fs::read(&written).expect("read");
            assert!(
                !String::from_utf8_lossy(&bytes).contains(PASSWORD),
                "{} holds the password",
                written.display()
            );
        }
    }

    // The file enrols as the pair would.
    let key = KeyPair::try_from(opened.private_key_der.as_slice())
        .expect("key")
        .serialize_pem();
    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let (csr, _key) = csr_for("edge-01");
    decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("pending")
        .json()
        .await
        .expect("json");
    assert_eq!(pending[0]["bootstrap_serial"], serial.as_str());

    let revoked = operator_client
        .post(operator(&served, "/api/v1/revocations"))
        .json(&serde_json::json!({
            "certificate": { "authority": "bootstrap", "serial": serial }
        }))
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), 201);
    assert_eq!(download(operator_client.clone()).await.status(), 404);
    let kept = bootstrap_files(&served, &serial);
    assert!(
        !kept.iter().any(|name| name.ends_with(".p12")),
        "the revocation removed {kept:?}"
    );
    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed[0]["p12"], false);
    let unknown = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates/../p12"))
        .send()
        .await
        .expect("download");
    assert_eq!(unknown.status(), 404);
}

/// An audit record that can be made to refuse, to see what a route does without one.
struct Refusable {
    inner: Arc<dyn fleet_server::audit::Audit>,
    refuse: std::sync::atomic::AtomicBool,
}

impl fleet_server::audit::Audit for Refusable {
    fn record(
        &self,
        entry: fleet_server::audit::Entry,
    ) -> Result<(), fleet_server::audit::Unavailable> {
        // Only the deletion, so the operator's act passes and the route's own refusal is seen.
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst)
            && entry.event == "enrolment.bootstrap_deleted"
        {
            return Err(fleet_server::audit::Unavailable);
        }
        self.inner.record(entry)
    }
}

/// A revoked bootstrap certificate's entry can be deleted, with its PKCS#12 file, and the deletion
/// is on the record; its revocation stays, so it is still refused. A valid one is not deleted, an
/// unknown serial is not found, and without an audit record nothing is deleted (ADR-0029 clause 15).
/// Verifies: ADR-0029
#[tokio::test]
async fn a_revoked_bootstrap_certificate_is_deleted_from_the_list_and_stays_refused() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let audit_dir = tempfile::tempdir().expect("tempdir");
    let audit = Arc::new(Refusable {
        inner: audit_in(audit_dir.path()),
        refuse: std::sync::atomic::AtomicBool::new(false),
    });
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            revocations: true,
            audit: Some(audit.clone()),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let issued: serde_json::Value = operator_client
        .post(operator(&served, "/api/v1/bootstrap-certificates"))
        .json(&serde_json::json!({
            "subject": customer_and_site(),
            "password": "a password of the operator"
        }))
        .send()
        .await
        .expect("issue")
        .json()
        .await
        .expect("json");
    let serial = issued["serial"].as_str().expect("serial").to_string();
    let cert = issued["certificate_pem"]
        .as_str()
        .expect("cert")
        .to_string();
    let file: Vec<u8> = operator_client
        .get(operator(
            &served,
            &format!("/api/v1/bootstrap-certificates/{serial}/p12"),
        ))
        .send()
        .await
        .expect("download")
        .bytes()
        .await
        .expect("body")
        .to_vec();
    let opened =
        fleet_core::pkcs12::file::open(&file, "a password of the operator").expect("opens");
    let key = KeyPair::try_from(opened.private_key_der.as_slice())
        .expect("key")
        .serialize_pem();
    let delete = |serial: String| {
        let client = operator_client.clone();
        let url = operator(&served, &format!("/api/v1/bootstrap-certificates/{serial}"));
        async move { client.delete(url).send().await.expect("delete").status() }
    };

    assert_eq!(
        delete(serial.clone()).await,
        409,
        "a valid one is revoked first"
    );
    assert_eq!(delete("abcdef".to_string()).await, 404);
    let revoked = operator_client
        .post(operator(&served, "/api/v1/revocations"))
        .json(&serde_json::json!({
            "certificate": { "authority": "bootstrap", "serial": serial }
        }))
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), 201);

    audit
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(delete(serial.clone()).await, 503);
    audit
        .refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(
        listed[0]["serial"],
        serial.as_str(),
        "kept without a record"
    );

    assert_eq!(delete(serial.clone()).await, 204);
    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed, serde_json::json!([]), "gone from the list");
    assert_eq!(bootstrap_files(&served, &serial), Vec::<String>::new());
    let recorded = entries(audit_dir.path(), "enrolment.bootstrap_deleted", 1).await;
    let deleted = named(&recorded, "enrolment.bootstrap_deleted");
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["serial"], serial.as_str());
    assert_eq!(deleted[0]["subject"], issued["subject"]);
    let revocations: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/revocations"))
        .send()
        .await
        .expect("revocations")
        .json()
        .await
        .expect("json");
    assert_eq!(
        revocations[0]["certificate"]["serial"],
        serial.as_str(),
        "the revocation stays"
    );

    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let (csr, _key) = csr_for("edge-01");
    let refused = post(&enrolling, &served.endpoint, csr_report(csr)).await;
    assert!(
        !refused.status().is_success(),
        "a deleted entry's certificate stays refused: {}",
        refused.status()
    );
}

/// Without the bootstrap CA's key the Server issues nothing and says why, a request outside the
/// bounds is refused, and one naming only a customer, a site and a password is issued (ADR-0028
/// clauses 22 and 23, ADR-0021 clause 19 and ADR-0036 clauses 1 and 8).
/// Verifies: ADR-0028
#[tokio::test]
async fn issuing_needs_the_key_and_a_request_within_bounds() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let without_key = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&without_key.ca_pem, None);
    let smallest = serde_json::json!({
        "subject": customer_and_site(),
        "password": BOOTSTRAP_PASSWORD
    });
    let response = operator_client
        .post(operator(&without_key, "/api/v1/bootstrap-certificates"))
        .json(&smallest)
        .send()
        .await
        .expect("issue");
    assert_eq!(response.status(), 409);
    let body: serde_json::Value = response.json().await.expect("json");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("bootstrap_ca_key_file")),
        "{body}"
    );

    let with_key = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            ..Setup::default()
        },
    )
    .await;
    let with_subject = |extra: serde_json::Value| {
        let mut subject = customer_and_site();
        for (key, value) in extra.as_object().expect("an object") {
            subject[key] = value.clone();
        }
        serde_json::json!({ "subject": subject, "password": BOOTSTRAP_PASSWORD })
    };
    let mut too_long = smallest.clone();
    too_long["validity_days"] = 91.into();
    for refused in [
        too_long,
        with_subject(serde_json::json!({ "common_name": "anything" })),
        with_subject(serde_json::json!({ "email": "ops@example.org" })),
        with_subject(serde_json::json!({ "organization": "" })),
    ] {
        let response = operator_client
            .post(operator(&with_key, "/api/v1/bootstrap-certificates"))
            .json(&refused)
            .send()
            .await
            .expect("issue");
        assert_eq!(response.status(), 400, "{refused}");
    }
    let issued = operator_client
        .post(operator(&with_key, "/api/v1/bootstrap-certificates"))
        .json(&smallest)
        .send()
        .await
        .expect("issue");
    assert_eq!(issued.status(), 201);
    let issued: serde_json::Value = issued.json().await.expect("json");
    assert_eq!(
        issued["subject"], "O=Kunde GmbH, OU=Werk Nord, CN=acme bootstrap Certificate",
        "the Server sets the common name from the CA's (ADR-0028 clause 28)"
    );
}

/// A bootstrap certificate names a customer and a site and is issued under a password: a
/// request without `organization`, without `organizational_unit` or without `password` is `400`
/// naming the field, issues nothing, and no answer ever carries a private key (ADR-0036 clauses
/// 1 and 8).
/// Verifies: ADR-0036
#[tokio::test]
async fn issuing_without_a_customer_a_site_or_a_password_is_refused_naming_it() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    for (request, field) in [
        (
            serde_json::json!({
                "subject": { "organizational_unit": "Werk Nord" },
                "password": BOOTSTRAP_PASSWORD
            }),
            "subject.organization ",
        ),
        (
            serde_json::json!({
                "subject": { "organization": "Kunde GmbH" },
                "password": BOOTSTRAP_PASSWORD
            }),
            "subject.organizational_unit ",
        ),
        (
            serde_json::json!({ "password": BOOTSTRAP_PASSWORD }),
            "subject.organization ",
        ),
        (
            serde_json::json!({ "subject": customer_and_site() }),
            "password ",
        ),
    ] {
        let response = operator_client
            .post(operator(&served, "/api/v1/bootstrap-certificates"))
            .json(&request)
            .send()
            .await
            .expect("issue");
        assert_eq!(response.status(), 400, "{request}");
        let body: serde_json::Value = response.json().await.expect("json");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|e| e.starts_with(field) && e.contains("required")),
            "the refusal names {field}: {body}"
        );
        assert!(body.get("private_key_pem").is_none(), "{body}");
    }
    let listed: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/bootstrap-certificates"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed, serde_json::json!([]), "nothing was issued");
}

/// Each rule a subject value is issued by is answered `400` over the API, naming the attribute:
/// a lower-case or three-letter country, an empty value, one of 65 characters, and one holding a
/// control character. A value of 64 characters is issued.
/// Verifies: ADR-0036
#[tokio::test]
async fn a_subject_value_outside_the_rules_is_refused_400() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let issue = |extra: serde_json::Value| {
        let mut subject = customer_and_site();
        for (key, value) in extra.as_object().expect("an object") {
            subject[key] = value.clone();
        }
        let request = operator_client
            .post(operator(&served, "/api/v1/bootstrap-certificates"))
            .json(&serde_json::json!({ "subject": subject, "password": BOOTSTRAP_PASSWORD }));
        async move { request.send().await.expect("issue") }
    };
    for (subject, attribute) in [
        (serde_json::json!({ "country": "at" }), "country"),
        (serde_json::json!({ "country": "AUT" }), "country"),
        (serde_json::json!({ "locality": "" }), "locality"),
        (
            serde_json::json!({ "organizational_unit": "x".repeat(65) }),
            "organizational_unit",
        ),
        (serde_json::json!({ "state": "Wien\u{7}" }), "state"),
    ] {
        let response = issue(subject.clone()).await;
        assert_eq!(response.status(), 400, "{subject}");
        let body: serde_json::Value = response.json().await.expect("json");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|e| e.contains(attribute)),
            "the refusal names {attribute}: {body}"
        );
    }
    let at_the_bound = issue(serde_json::json!({ "organizational_unit": "x".repeat(64) })).await;
    assert_eq!(at_the_bound.status(), 201);
}

/// Every file below `dir`.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// With `[rest.tls]` the Operator plane serves the certificate the operator's own PKI issued, and
/// the Agent plane keeps `[tls]`'s: a browser trusts the one, a Client the other, and neither
/// trust reaches the other plane. Without the section both planes serve `[tls]`'s
/// (ADR-0032 clauses 1 and 2).
/// Verifies: ADR-0032
#[tokio::test]
async fn the_operator_plane_serves_its_own_certificate_and_the_agent_plane_keeps_the_fleets() {
    let pki = Pki::new();
    let company = Pki::named("company PKI");
    let served = serve(
        &pki,
        Setup {
            operator_pki: Some(&company),
            ..Setup::default()
        },
    )
    .await;
    let agents = operator(&served, "/api/v1/agents");
    let answered = client(&company.ca_pem, None)
        .get(&agents)
        .send()
        .await
        .expect("the PKI's CA vouches for the Operator plane");
    assert!(answered.status().is_success(), "{}", answered.status());
    assert!(
        client(&pki.ca_pem, None).get(&agents).send().await.is_err(),
        "the fleet's server CA does not vouch for the Operator plane's certificate"
    );
    let (cert, key) = pki.issue("host-1");
    assert!(
        client(&pki.ca_pem, Some((&cert, &key)))
            .post(&served.endpoint)
            .send()
            .await
            .is_ok(),
        "a Client trusting the fleet's CA still reaches the Agent plane"
    );
    assert!(
        client(&company.ca_pem, Some((&cert, &key)))
            .post(&served.endpoint)
            .send()
            .await
            .is_err(),
        "the PKI's CA does not vouch for the Agent plane's certificate"
    );

    let without = serve(&pki, Setup::default()).await;
    let answered = client(&pki.ca_pem, None)
        .get(operator(&without, "/api/v1/agents"))
        .send()
        .await
        .expect("without [rest.tls] the Operator plane serves [tls]'s certificate");
    assert!(answered.status().is_success(), "{}", answered.status());
}

// ---- A bootstrap certificate's subject, carried into the host certificate (ADR-0036) ----

/// A renewal through its proof — the branch a Gateway-carried renewal takes — carries the values
/// of the certificate the proof names, not those of the certificate the connection presented.
/// Verifies: ADR-0036
#[tokio::test]
async fn a_renewal_by_its_proof_carries_the_proven_certificates_values() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (old_cert, old_key) = pki.issue_to_host_with(
        "h-1",
        &[
            (rcgen::DnType::CountryName, "AT"),
            (rcgen::DnType::OrganizationName, "Kunde GmbH"),
            (rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]), "K-4711"),
            (rcgen::DnType::CommonName, "edge-01"),
        ],
    );
    let (carrier_cert, carrier_key) = pki.issue_to_host_with(
        "gw",
        &[
            (rcgen::DnType::OrganizationName, "Gateway GmbH"),
            (rcgen::DnType::CommonName, "gw"),
        ],
    );
    let csr = renewal_csr(&old_cert, &old_key);

    let http = client(&served.ca_pem, Some((&carrier_cert, &carrier_key)));
    let uid = InstanceUid::default();
    let reply = decode(post(&http, &served.endpoint, with_csr(&uid, csr)).await).await;
    let new_cert = String::from_utf8(
        reply
            .connection_settings
            .and_then(|s| s.opamp)
            .and_then(|o| o.certificate)
            .expect("renewed")
            .cert,
    )
    .expect("pem");
    let carried = values_of(&new_cert);
    assert_eq!(carried, values_of(&old_cert));
    assert_eq!(carried.organization, "Kunde GmbH");
    assert_eq!(carried.organization_identifier, "K-4711");
}

/// The six subject values of a certificate in PEM.
fn values_of(pem: &str) -> fleet_server::revocation::SubjectValues {
    let der = opamp::tls::certificates(pem.as_bytes()).expect("pem");
    fleet_server::ca::facts(der[0].as_ref())
        .expect("facts")
        .subject_values
}

/// A CSR whose own subject names a customer, which nothing may copy.
fn csr_naming_another_customer() -> (Vec<u8>, KeyPair) {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    for (kind, value) in [
        (rcgen::DnType::CountryName, "DE"),
        (rcgen::DnType::OrganizationName, "Another Customer"),
        (rcgen::DnType::CommonName, "edge-01"),
    ] {
        params.distinguished_name.push(kind, value);
    }
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("csr pem");
    (csr.into_bytes(), key)
}

/// The values every test below issues a bootstrap certificate with.
fn six_values() -> serde_json::Value {
    serde_json::json!({
        "country": "AT",
        "state": "Oberösterreich",
        "locality": "Linz",
        "organization": "Kunde GmbH",
        "organizational_unit": "Werk Nord",
        "organization_identifier": "6f1c0b9e-2a4d-4c55-9b1e-0d2f3a4b5c6d"
    })
}

/// End to end: a bootstrap certificate issued with all six values enrols; the queue lists those
/// values and not the request's subject; the approval signs them into the host certificate and
/// ignores the CSR's; the Host carries them, and an Agent arriving with the issued certificate is
/// described by them as `fleet.host.*`.
/// Verifies: ADR-0036
#[tokio::test]
async fn an_enrolment_carries_the_bootstrap_subject_into_the_host_and_its_agents() {
    let pki = Pki::new();
    let bootstrap = Pki::named("acme bootstrap CA");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            issue_bootstrap: true,
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let operator_client = client(&served.ca_pem, None);
    let response = operator_client
        .post(operator(&served, "/api/v1/bootstrap-certificates"))
        .json(&serde_json::json!({ "subject": six_values(), "password": BOOTSTRAP_PASSWORD }))
        .send()
        .await
        .expect("issue");
    assert_eq!(response.status(), 201);
    let issued: serde_json::Value = response.json().await.expect("json");
    let cert = issued["certificate_pem"].as_str().expect("cert");
    let serial = issued["serial"].as_str().expect("serial");
    let key = &bootstrap_key(&served, &operator_client, serial).await;
    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");

    let enrolling = client(&served.ca_pem, Some((cert, key)));
    let (csr, host_key) = csr_naming_another_customer();
    decode(post(&enrolling, &served.endpoint, csr_report(csr.clone())).await).await;
    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("pending")
        .json()
        .await
        .expect("json");
    assert_eq!(pending[0]["bootstrap_subject"], six_values(), "{pending}");
    assert!(
        pending[0].get("subject_refusal").is_none(),
        "a subject that can be carried is listed with no refusal: {pending}"
    );
    assert!(pending[0].get("subject").is_none(), "{pending}");
    assert!(
        !pending.to_string().contains("Another Customer"),
        "the CSR's subject is not listed: {pending}"
    );
    let id = pending[0]["id"].as_str().expect("id").to_string();
    let approved = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/approve"),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(approved.status(), 204);

    let collected = decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    let host_cert = String::from_utf8(
        collected
            .connection_settings
            .and_then(|offer| offer.opamp)
            .and_then(|opamp| opamp.certificate)
            .expect("the issued certificate")
            .cert,
    )
    .expect("pem");
    let values = values_of(&host_cert);
    assert_eq!(
        serde_json::to_value(&values).expect("json"),
        six_values(),
        "the host certificate carries the bootstrap certificate's values"
    );
    let listed = hosts(&served).await;
    assert_eq!(listed[0]["subject"], six_values(), "{listed}");

    let member = client(
        &served.ca_pem,
        Some((&host_cert, &host_key.serialize_pem())),
    );
    let uid = InstanceUid::default();
    let _ = decode(post(&member, &served.endpoint, described(&uid, &[])).await).await;
    let fleet: Vec<serde_json::Value> = operator_client
        .get(operator(&served, "/api/v1/agents"))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let agent = fleet
        .iter()
        .find(|agent| agent["instance_uid"] == uid.to_string())
        .expect("in the fleet");
    assert_eq!(
        agent["host_attributes"],
        serde_json::json!({
            "fleet.host.country": "AT",
            "fleet.host.state": "Oberösterreich",
            "fleet.host.locality": "Linz",
            "fleet.host.organization": "Kunde GmbH",
            "fleet.host.site": "Werk Nord",
            "fleet.host.organization_id": "6f1c0b9e-2a4d-4c55-9b1e-0d2f3a4b5c6d"
        }),
        "{agent}"
    );
}

/// A bootstrap certificate from another CA whose subject names OU twice enrols, but its approval
/// is refused with `409` naming the attribute, and nothing is signed.
/// Verifies: ADR-0036
#[tokio::test]
async fn a_foreign_bootstrap_certificate_with_ou_twice_is_refused_at_approval() {
    let pki = Pki::new();
    let bootstrap = Pki::named("foreign bootstrap CA");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    // rcgen keeps one value per type, so the second OU goes in under its OID.
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationalUnitName, "Wien");
    params
        .distinguished_name
        .push(rcgen::DnType::CustomDnType(vec![2, 5, 4, 11]), "Linz");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "foreign bootstrap");
    let cert = params
        .signed_by(&key, &bootstrap.issuer())
        .expect("signed")
        .pem();
    let operator_client = client(&served.ca_pem, None);
    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let enrolling = client(&served.ca_pem, Some((&cert, &key.serialize_pem())));
    let (csr, _) = csr_for("edge-01");
    decode(post(&enrolling, &served.endpoint, csr_report(csr.clone())).await).await;
    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("pending")
        .json()
        .await
        .expect("json");
    let id = pending[0]["id"].as_str().expect("id").to_string();
    assert!(
        pending[0].get("bootstrap_subject").is_none(),
        "no values are listed that the approval would not carry: {pending}"
    );
    let listed = pending[0]["subject_refusal"]
        .as_str()
        .expect("the queue says why before the operator approves")
        .to_string();
    assert!(listed.contains("organizational_unit"), "{listed}");

    let refused = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/approve"),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(refused.status(), 409);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("organizational_unit") && e.contains(&listed)),
        "the approval refuses with the reason the queue listed: {body}"
    );
    assert_eq!(hosts(&served).await, serde_json::json!([]), "no Host");
    let register: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/certificates"))
        .send()
        .await
        .expect("register")
        .json()
        .await
        .expect("json");
    assert_eq!(register, serde_json::json!([]), "nothing was signed");
    let waiting = decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    assert!(
        waiting.connection_settings.is_none(),
        "no certificate is handed out"
    );
}

/// A bootstrap certificate from another CA that names a customer but no site enrols, but the queue
/// says why it cannot be carried and its approval is refused with `409` naming
/// `organizational_unit`; nothing is signed and no Host is written.
/// Verifies: ADR-0036
#[tokio::test]
async fn a_foreign_bootstrap_certificate_without_ou_is_refused_at_approval() {
    let pki = Pki::new();
    let bootstrap = Pki::named("foreign bootstrap CA");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Kunde GmbH");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "foreign bootstrap");
    let cert = params
        .signed_by(&key, &bootstrap.issuer())
        .expect("signed")
        .pem();
    let operator_client = client(&served.ca_pem, None);
    operator_client
        .post(operator(&served, "/api/v1/enrolment/window"))
        .json(&serde_json::json!({ "open_for_secs": 600 }))
        .send()
        .await
        .expect("open window");
    let enrolling = client(&served.ca_pem, Some((&cert, &key.serialize_pem())));
    let (csr, _) = csr_for("edge-01");
    decode(post(&enrolling, &served.endpoint, csr_report(csr)).await).await;
    let pending: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("pending")
        .json()
        .await
        .expect("json");
    let id = pending[0]["id"].as_str().expect("id").to_string();
    assert!(
        pending[0].get("bootstrap_subject").is_none(),
        "no values are listed that the approval would not carry: {pending}"
    );
    let listed = pending[0]["subject_refusal"]
        .as_str()
        .expect("the queue says why before the operator approves")
        .to_string();
    assert!(
        listed.contains("organizational_unit is missing"),
        "{listed}"
    );

    let refused = operator_client
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{id}/approve"),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(refused.status(), 409);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("organizational_unit is missing")),
        "the approval names the missing attribute: {body}"
    );
    assert_eq!(hosts(&served).await, serde_json::json!([]), "no Host");
    let register: serde_json::Value = operator_client
        .get(operator(&served, "/api/v1/certificates"))
        .send()
        .await
        .expect("register")
        .json()
        .await
        .expect("json");
    assert_eq!(register, serde_json::json!([]), "nothing was signed");
}

/// A renewal carries the values of the certificate it renews, and only those: neither the CSR's
/// nor anything else.
/// Verifies: ADR-0036
#[tokio::test]
async fn a_renewal_carries_the_predecessors_values_unchanged() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let (old_cert, old_key) = pki.issue_to_host_with(
        "h-1",
        &[
            (rcgen::DnType::CountryName, "AT"),
            (rcgen::DnType::OrganizationName, "Kunde GmbH"),
            (rcgen::DnType::OrganizationalUnitName, "Werk Nord"),
            (rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]), "K-4711"),
            (rcgen::DnType::CommonName, "edge-01"),
        ],
    );
    let http = client(&served.ca_pem, Some((&old_cert, &old_key)));
    let uid = InstanceUid::default();
    let (csr, _) = csr_naming_another_customer();
    let reply = decode(post(&http, &served.endpoint, with_csr(&uid, csr)).await).await;
    let new_cert = String::from_utf8(
        reply
            .connection_settings
            .and_then(|s| s.opamp)
            .and_then(|o| o.certificate)
            .expect("renewed")
            .cert,
    )
    .expect("pem");
    assert_eq!(values_of(&new_cert), values_of(&old_cert));
    assert_eq!(values_of(&new_cert).organization_identifier, "K-4711");
}

// ---- The bootstrap proof (ADR-0039) ----

/// A CSR for a new key carrying a bootstrap proof of `cert`, signed with `signing_key` — the
/// certificate's own key unless a test forges it — and, with `renewal`, a renewal proof beside it.
fn bootstrap_csr(cert: &str, signing_key: &str, renewal: Option<(&str, &str)>) -> Vec<u8> {
    use base64::Engine as _;
    use rcgen::{PublicKeyData as _, SigningKey as _};
    use sha2::{Digest as _, Sha256};
    let new_key = KeyPair::generate().expect("new key");
    let new_key_sha256 = Sha256::digest(new_key.subject_public_key_info());
    let proof = |prefix: &str, statement: Vec<u8>, cert: &str, key: &str| {
        let der = opamp::tls::certificates(cert.as_bytes()).expect("pem")[0].to_vec();
        let signature = KeyPair::from_pem(key)
            .expect("key")
            .sign(&statement)
            .expect("sign");
        let uri = format!(
            "{prefix}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(fleet_core::bootstrap_proof::encode(&der, &signature))
        );
        rcgen::SanType::URI(uri.try_into().expect("uri"))
    };
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "edge-01");
    params.subject_alt_names.push(proof(
        fleet_core::bootstrap_proof::URI_PREFIX,
        fleet_core::bootstrap_proof::statement(&new_key_sha256),
        cert,
        signing_key,
    ));
    if let Some((old_cert, old_key)) = renewal {
        params.subject_alt_names.push(proof(
            fleet_core::renewal::URI_PREFIX,
            fleet_core::renewal::statement(&new_key_sha256),
            old_cert,
            old_key,
        ));
    }
    params
        .serialize_request(&new_key)
        .expect("csr")
        .pem()
        .expect("pem")
        .into_bytes()
}

/// The error a reply carries, as its type and message.
fn error_of(reply: &ServerToAgent) -> Option<(i32, String)> {
    reply
        .error_response
        .as_ref()
        .map(|error| (error.r#type, error.error_message.clone()))
}

/// On an enrolment connection a request proves the certificate of the handshake: one whose proof
/// names another bootstrap certificate, whose signature does not verify, or that carries a renewal
/// proof too is answered `BadRequest` and queued nowhere; one without a proof is queued under the
/// handshake's certificate, and so is one whose proof names it — and its approval carries that
/// certificate's values into the host certificate.
/// Verifies: ADR-0039
#[tokio::test]
async fn an_enrolment_request_proves_the_handshakes_bootstrap_certificate() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    enrolment.open(600).expect("open");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    let (other_cert, other_key) = bootstrap.issue_bootstrap("bootstrap-b");
    let (member_cert, member_key) = pki.issue_to_host("h-1");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let send = |csr: Vec<u8>| {
        let enrolling = enrolling.clone();
        let endpoint = served.endpoint.clone();
        async move { decode(post(&enrolling, &endpoint, csr_report(csr)).await).await }
    };

    for (csr, what) in [
        (
            bootstrap_csr(&other_cert, &other_key, None),
            "a proof of another bootstrap certificate",
        ),
        (
            bootstrap_csr(&cert, &other_key, None),
            "a proof whose signature does not verify",
        ),
        (
            bootstrap_csr(&cert, &key, Some((&member_cert, &member_key))),
            "a renewal proof beside the bootstrap proof",
        ),
    ] {
        let reply = send(csr).await;
        let (kind, message) = error_of(&reply).unwrap_or_else(|| panic!("{what} was taken"));
        assert_eq!(kind, ServerErrorResponseType::BadRequest as i32, "{what}");
        assert!(message.contains("proof"), "{what}: {message}");
        assert!(enrolment.pending().is_empty(), "{what} was queued");
    }

    let serial = cert_id(&cert).serial;
    let (csr, _) = csr_for("edge-00");
    assert!(error_of(&send(csr).await).is_none());
    let csr = bootstrap_csr(&cert, &key, None);
    assert!(error_of(&send(csr.clone()).await).is_none());
    let pending = enrolment.pending();
    assert_eq!(pending.len(), 2, "both requests wait");
    for request in &pending {
        assert_eq!(request.requester.bootstrap.serial, serial);
        assert_eq!(
            request
                .requester
                .carried
                .as_ref()
                .map(|v| v.organizational_unit.clone()),
            Ok("Werk Nord".to_string())
        );
    }
    let proven_id =
        fleet_server::ca::enrolment_request(std::str::from_utf8(&csr).expect("utf-8"), &[])
            .expect("request")
            .key_fingerprint;
    assert!(pending.iter().any(|request| request.id == proven_id));
    served.state.approve_enrolment(&proven_id).expect("approve");
    let issued = issued(send(csr).await).expect("the issued certificate");
    let der = opamp::tls::certificates(issued.as_bytes()).expect("pem");
    let values = fleet_server::ca::facts(der[0].as_ref())
        .expect("facts")
        .subject_values;
    assert_eq!(
        (
            values.organization.as_str(),
            values.organizational_unit.as_str()
        ),
        ("Kunde GmbH", "Werk Nord"),
        "the approval carries the proven certificate's values"
    );
}

/// A bootstrap certificate the Server revoked enrols no further: its request is refused and
/// queued nowhere.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_revoked_bootstrap_certificates_request_is_refused() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let served = serve(
        &pki,
        Setup {
            client_ca: Some(client_ca_of(&pki)),
            bootstrap: Some(&bootstrap),
            revocations: true,
            ..Setup::default()
        },
    )
    .await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    enrolment.open(600).expect("open");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("bootstrap", &cert_id(&cert).serial)
        .expect("revoke");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let response = post(
        &enrolling,
        &served.endpoint,
        csr_report(bootstrap_csr(&cert, &key, None)),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(enrolment.pending().is_empty());
}

// ---- Enrolment through a Gateway (ADR-0039) ----

/// A Server with enrolment and the register, a Gateway host `gw` marked, its window open, and the
/// Gateway's client: what a request a Gateway relays arrives on.
async fn behind_a_gateway(
    pki: &Pki,
    bootstrap: &Pki,
    audit: Option<Arc<dyn fleet_server::audit::Audit>>,
    agent_rate: Option<fleet_server::agent_rate::Limits>,
) -> (Served, reqwest::Client) {
    let (served, gateway, _) = gateway_presenting(pki, bootstrap, audit, agent_rate).await;
    (served, gateway)
}

/// [`behind_a_gateway`], and the certificate (PEM) the Gateway presents.
async fn gateway_presenting(
    pki: &Pki,
    bootstrap: &Pki,
    audit: Option<Arc<dyn fleet_server::audit::Audit>>,
    agent_rate: Option<fleet_server::agent_rate::Limits>,
) -> (Served, reqwest::Client, String) {
    let served = serve(
        pki,
        Setup {
            client_ca: Some(client_ca_of(pki)),
            bootstrap: Some(bootstrap),
            revocations: true,
            audit,
            agent_rate,
            ..Setup::default()
        },
    )
    .await;
    let (gateway_cert, gateway_key) = pki.issue_to_host("gw");
    let gateway = client(&served.ca_pem, Some((&gateway_cert, &gateway_key)));
    assert!(
        post(&gateway, &served.endpoint, report(&InstanceUid::default()))
            .await
            .status()
            .is_success()
    );
    assert!(served
        .revocations
        .as_ref()
        .expect("armed")
        .set_gateway("gw", true)
        .expect("mark"));
    served
        .enrolment
        .as_ref()
        .expect("enrolment")
        .open(600)
        .expect("open");
    (served, gateway, gateway_cert)
}

/// A CSR with a bootstrap proof over a marked Gateway's certificate is an enrolment request: it
/// waits in the queue naming the Gateway's host in place of a peer address, there and in the audit,
/// becomes no Agent, and its approval mints a host of its own — never the Gateway's — whose
/// certificate the enrolling host collects in a later reply, addressed to it.
/// Verifies: ADR-0039
#[tokio::test]
async fn an_enrolment_through_a_gateway_is_decided_as_any_enrolment() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let dir = tempfile::tempdir().expect("tempdir");
    let (served, gateway) =
        behind_a_gateway(&pki, &bootstrap, Some(audit_in(dir.path())), None).await;
    let agents = served.state.snapshot().len();
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    let uid = InstanceUid::default();
    let csr = bootstrap_csr(&cert, &key, None);
    let waiting = decode(post(&gateway, &served.endpoint, with_csr(&uid, csr.clone())).await).await;
    assert_eq!(error_of(&waiting), None);
    assert_eq!(
        waiting.instance_uid,
        uid.as_bytes(),
        "routed back by its uid"
    );
    assert!(issued(waiting).is_none());

    let pending = served.enrolment.as_ref().expect("enrolment").pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requester.gateway.as_deref(), Some("gw"));
    assert_eq!(pending[0].requester.peer, None);
    assert_eq!(pending[0].requester.bootstrap.serial, cert_id(&cert).serial);
    let listed: serde_json::Value = client(&served.ca_pem, None)
        .get(operator(&served, "/api/v1/enrolments"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed[0]["gateway"], "gw", "{listed}");
    assert!(listed[0].get("peer").is_none(), "{listed}");
    assert_eq!(
        served.state.snapshot().len(),
        agents,
        "an enrolling host is no Agent of the fleet"
    );

    let approved = client(&served.ca_pem, None)
        .post(operator(
            &served,
            &format!("/api/v1/enrolments/{}/approve", pending[0].id),
        ))
        .send()
        .await
        .expect("approve");
    assert_eq!(approved.status(), 204);
    let reply = decode(post(&gateway, &served.endpoint, with_csr(&uid, csr)).await).await;
    assert_eq!(reply.instance_uid, uid.as_bytes());
    let certificate = issued(reply).expect("the issued certificate");
    let host = fleet_server::ca::facts(
        opamp::tls::certificates(certificate.as_bytes()).expect("pem")[0].as_ref(),
    )
    .expect("facts")
    .host
    .expect("a host");
    assert_ne!(host, "gw", "the Gateway's host was handed out");

    let all = entries(dir.path(), "enrolment.approved", 1).await;
    for event in ["enrolment.queued", "enrolment.approved"] {
        let entry = named(&all, event);
        assert_eq!(entry.len(), 1, "{event}: {all:#?}");
        assert_eq!(entry[0]["gateway"], "gw", "{event}");
    }
}

/// Through a Gateway, without an open window the request is answered `Unavailable`; a bootstrap
/// proof whose certificate is revoked, or not one of the bootstrap CA, is answered `BadRequest`
/// and queued nowhere — every answer addressed to the message's `instance_uid`.
/// Verifies: ADR-0039
#[tokio::test]
async fn an_enrolment_through_a_gateway_is_refused_as_any_enrolment() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let (served, gateway) = behind_a_gateway(&pki, &bootstrap, None, None).await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    let uid = InstanceUid::default();

    let (revoked, revoked_key) = bootstrap.issue_bootstrap("bootstrap-revoked");
    served
        .revocations
        .as_ref()
        .expect("armed")
        .revoke_certificate("bootstrap", &cert_id(&revoked).serial)
        .expect("revoke");
    let foreign = Pki::named("not the bootstrap CA");
    let (stranger, stranger_key) = foreign.issue_bootstrap("bootstrap-foreign");
    for (csr, what) in [
        (bootstrap_csr(&revoked, &revoked_key, None), "revoked"),
        (
            bootstrap_csr(&stranger, &stranger_key, None),
            "not issued by the bootstrap CA",
        ),
    ] {
        let reply = decode(post(&gateway, &served.endpoint, with_csr(&uid, csr)).await).await;
        assert_eq!(reply.instance_uid, uid.as_bytes(), "{what}");
        let (kind, message) = error_of(&reply).unwrap_or_else(|| panic!("{what} was taken"));
        assert_eq!(kind, ServerErrorResponseType::BadRequest as i32, "{what}");
        assert!(message.contains(what), "{what}: {message}");
    }
    assert!(enrolment.pending().is_empty());

    enrolment.close().expect("close");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    let reply = decode(
        post(
            &gateway,
            &served.endpoint,
            with_csr(&uid, bootstrap_csr(&cert, &key, None)),
        )
        .await,
    )
    .await;
    assert_eq!(reply.instance_uid, uid.as_bytes());
    assert_eq!(
        error_of(&reply).map(|(kind, _)| kind),
        Some(ServerErrorResponseType::Unavailable as i32)
    );
    assert!(enrolment.pending().is_empty());
}

/// A member does not enrol: a CSR with a bootstrap proof over the certificate of a host that is
/// not marked as a Gateway is answered `BadRequest`, and one with neither proof over a Gateway's
/// certificate is answered `BadRequest` naming both proofs. Nothing is signed or queued. A proof of
/// the presented certificate itself — what a Client on a certificate an operator provisioned
/// sends — renews it as a request without a proof does.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_member_does_not_enrol_and_a_gateway_needs_a_proof() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let (served, gateway) = behind_a_gateway(&pki, &bootstrap, None, None).await;
    let revocations = served.revocations.clone().expect("armed");
    let enrolment = served.enrolment.clone().expect("enrolment");
    let before = revocations.issued().len();
    let uid = InstanceUid::default();
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    let (member_cert, member_key) = pki.issue_to_host("h-1");
    let member = client(&served.ca_pem, Some((&member_cert, &member_key)));

    let reply = decode(
        post(
            &member,
            &served.endpoint,
            with_csr(&uid, bootstrap_csr(&cert, &key, None)),
        )
        .await,
    )
    .await;
    let (kind, message) = error_of(&reply).expect("refused");
    assert_eq!(kind, ServerErrorResponseType::BadRequest as i32);
    assert!(message.contains("a member does not enrol"), "{message}");

    let (csr, _) = csr_for("edge-02");
    let reply = decode(post(&gateway, &served.endpoint, with_csr(&uid, csr)).await).await;
    let (kind, message) = error_of(&reply).expect("refused");
    assert_eq!(kind, ServerErrorResponseType::BadRequest as i32);
    assert!(
        message.contains("renewal proof") && message.contains("bootstrap proof"),
        "{message}"
    );
    assert_eq!(
        revocations.issued().len(),
        before,
        "a certificate was signed"
    );
    assert!(enrolment.pending().is_empty(), "a request was queued");

    let own = bootstrap_csr(&member_cert, &member_key, None);
    let reply = decode(post(&member, &served.endpoint, with_csr(&uid, own)).await).await;
    assert!(
        issued(reply).is_some(),
        "a proof of the presented certificate renews it"
    );
}

/// What a relayed enrolment request was answered: throttled by the rate limit, told the queue is
/// full or its window closed, refused, or taken. Both of the first two are `Unavailable`; only the
/// message tells them apart.
#[derive(Debug, PartialEq)]
enum Answered {
    Throttled,
    Unavailable(String),
    BadRequest(String),
    Taken,
}

fn answered(reply: &ServerToAgent) -> Answered {
    match error_of(reply) {
        None => Answered::Taken,
        Some((kind, message)) if kind == ServerErrorResponseType::Unavailable as i32 => {
            if message == "too many messages arrive from this sender — retry later" {
                Answered::Throttled
            } else {
                Answered::Unavailable(message)
            }
        }
        Some((kind, message)) if kind == ServerErrorResponseType::BadRequest as i32 => {
            Answered::BadRequest(message)
        }
        Some((kind, message)) => panic!("answered {kind}: {message}"),
    }
}

/// Enrolments through a Gateway never spend the aggregate its members are counted in. One whose
/// certificate no bootstrap CA issued is counted in the Gateway's bucket for unchecked enrolments
/// alone: exactly its burst is answered `BadRequest` and the rest throttled. A checked one is
/// counted in its bootstrap certificate's bucket and the Gateway's enrolment aggregate: one
/// certificate past its burst is throttled while a second bootstrap certificate is still taken and
/// queued, and a member reporting through the same Gateway is still heard.
/// Verifies: ADR-0039
#[tokio::test]
async fn enrolments_through_a_gateway_cannot_starve_its_members() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let (served, gateway) = behind_a_gateway(
        &pki,
        &bootstrap,
        None,
        Some(fleet_server::agent_rate::Limits {
            messages_per_sec: 1,
            burst: 3,
            gateway_messages_per_sec: 1,
            gateway_burst: 6,
        }),
    )
    .await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    let relay = |csr: Vec<u8>| {
        let gateway = gateway.clone();
        let endpoint = served.endpoint.clone();
        async move {
            answered(
                &decode(post(&gateway, &endpoint, with_csr(&InstanceUid::default(), csr)).await)
                    .await,
            )
        }
    };

    let foreign = Pki::named("not the bootstrap CA");
    let (forged, forged_key) = foreign.issue_bootstrap("bootstrap-forged");
    let mut forgeries = Vec::new();
    for _ in 0..5 {
        forgeries.push(relay(bootstrap_csr(&forged, &forged_key, None)).await);
    }
    assert_eq!(
        forgeries[3..],
        [Answered::Throttled, Answered::Throttled],
        "{forgeries:?}"
    );
    for answer in &forgeries[..3] {
        assert!(
            matches!(answer, Answered::BadRequest(why) if why.contains("not issued by the bootstrap CA")),
            "{forgeries:?}"
        );
    }
    assert!(enrolment.pending().is_empty(), "a forgery was queued");

    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    let csr = bootstrap_csr(&cert, &key, None);
    let mut genuine = Vec::new();
    for _ in 0..5 {
        genuine.push(relay(csr.clone()).await);
    }
    assert_eq!(
        genuine,
        [
            Answered::Taken,
            Answered::Taken,
            Answered::Taken,
            Answered::Throttled,
            Answered::Throttled
        ],
        "its bucket's burst, and no more"
    );
    assert_eq!(enrolment.pending().len(), 1, "the genuine request waits");

    let (other, other_key) = bootstrap.issue_bootstrap("bootstrap-b");
    assert_eq!(
        relay(bootstrap_csr(&other, &other_key, None)).await,
        Answered::Taken,
        "one bootstrap certificate spent another's tokens"
    );
    let pending = enrolment.pending();
    assert_eq!(pending.len(), 2, "the second certificate's request waits");
    assert!(pending
        .iter()
        .any(|request| request.requester.bootstrap.serial == cert_id(&other).serial));

    let member =
        decode(post(&gateway, &served.endpoint, report(&InstanceUid::default())).await).await;
    assert_ne!(
        answered(&member),
        Answered::Throttled,
        "enrolments spent the members' aggregate"
    );
}

/// A bootstrap proof through a Gateway names the Gateway's own certificate only when it embeds it
/// byte for byte: one embedding a certificate of the Gateway's issuer name and serial, made by
/// whoever copied them, is an enrolment request whose certificate fails the check — counted in
/// the bucket for unchecked enrolments, answered `BadRequest`, and spending nothing of the
/// aggregate the Gateway's members are counted in.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_proof_copying_the_gateways_issuer_and_serial_spends_no_members_tokens() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let (served, gateway, gateway_cert) = gateway_presenting(
        &pki,
        &bootstrap,
        None,
        Some(fleet_server::agent_rate::Limits {
            messages_per_sec: 1,
            burst: 3,
            gateway_messages_per_sec: 1,
            gateway_burst: 4,
        }),
    )
    .await;
    // A CA of the fleet's client CA's name — not its key — and a certificate of the Gateway's
    // serial under it.
    let impostor = Pki::new();
    let presented = opamp::tls::certificates(gateway_cert.as_bytes()).expect("pem")[0].to_vec();
    let (_, parsed) = x509_parser::parse_x509_certificate(&presented).expect("parses");
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["gw".to_string()]).expect("params");
    params.serial_number = Some(rcgen::SerialNumber::from_slice(parsed.raw_serial()));
    let twin = params.signed_by(&key, &impostor.issuer()).expect("signed");
    let twin_pem = twin.pem();
    assert_eq!(cert_id(&twin_pem), cert_id(&gateway_cert));
    assert_ne!(twin.der().as_ref(), presented.as_slice());

    let mut answers = Vec::new();
    for _ in 0..5 {
        let csr = bootstrap_csr(&twin_pem, &key.serialize_pem(), None);
        let reply = decode(
            post(
                &gateway,
                &served.endpoint,
                with_csr(&InstanceUid::default(), csr),
            )
            .await,
        )
        .await;
        answers.push(answered(&reply));
    }
    assert_eq!(answers[3..], [Answered::Throttled, Answered::Throttled]);
    for answer in &answers[..3] {
        assert!(
            matches!(answer, Answered::BadRequest(why) if why.contains("not issued by the bootstrap CA")),
            "{answers:?}"
        );
    }
    let member =
        decode(post(&gateway, &served.endpoint, report(&InstanceUid::default())).await).await;
    assert_ne!(
        answered(&member),
        Answered::Throttled,
        "a copied issuer and serial spent the members' aggregate"
    );
}

// ---- One request, one PEM block (ADR-0021 clause 27, ADR-0039) ----

/// `victim`'s proofs, copied into a request of a key of the attacker's own — and the attacker's
/// key.
fn grafted(victim: &[u8]) -> (String, KeyPair) {
    let proofs = rcgen::CertificateSigningRequestParams::from_pem(
        std::str::from_utf8(victim).expect("utf-8"),
    )
    .expect("victim")
    .params
    .subject_alt_names;
    let key = KeyPair::generate().expect("attacker key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.subject_alt_names = proofs;
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");
    (csr, key)
}

/// The two inputs two PEM readers can read differently: the attacker's request behind a prefix
/// one reader skips the line of and the other does not, the victim's after it; and the two as two
/// blocks.
fn crafted(attacker: &str, victim: &[u8]) -> [(Vec<u8>, &'static str); 2] {
    let victim = std::str::from_utf8(victim).expect("utf-8");
    [
        (format!("x{attacker}{victim}").into_bytes(), "prefixed"),
        (format!("{attacker}{victim}").into_bytes(), "two blocks"),
    ]
}

/// What a reply that should have refused handed out instead, for the failure message.
fn handed_out(reply: &ServerToAgent, attacker: &KeyPair) -> String {
    use rcgen::PublicKeyData as _;
    let Some(pem) = issued(reply.clone()) else {
        return format!("no certificate, {:?}", reply.error_response);
    };
    let der = opamp::tls::certificates(pem.as_bytes()).expect("pem")[0].to_vec();
    let facts = fleet_server::ca::facts(&der).expect("facts");
    let attackers = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(attacker.der_bytes()))
    };
    format!(
        "a certificate for host {:?} over {} key",
        facts.host,
        if facts.key_fingerprint == attackers {
            "the attacker's"
        } else {
            "another"
        }
    )
}

/// Another host's renewal proof cannot be carried over to a key of the sender's: a renewal
/// request read from anything but exactly one PEM block — the attacker's request with the proof
/// copied into it, behind a prefix or as the first of two blocks, the victim's request after it —
/// is answered `BadRequest` naming it, and nothing is signed.
/// Verifies: ADR-0021
#[tokio::test]
async fn a_renewal_request_is_read_from_exactly_one_pem_block() {
    let pki = Pki::new();
    let served = serve(&pki, revocations_setup(&pki)).await;
    let revocations = served.revocations.clone().expect("armed");
    let (victim_cert, victim_key) = pki.issue_to_host("h-1");
    let (attacker_cert, attacker_key) = pki.issue_to_host("h-2");
    let sender = client(&served.ca_pem, Some((&attacker_cert, &attacker_key)));
    let uid = InstanceUid::default();
    assert!(post(&sender, &served.endpoint, report(&uid))
        .await
        .status()
        .is_success());
    let before = revocations.issued().len();
    let victim = renewal_csr(&victim_cert, &victim_key);
    let (attacker, key) = grafted(&victim);
    for (csr, what) in crafted(&attacker, &victim) {
        let reply = decode(post(&sender, &served.endpoint, with_csr(&uid, csr)).await).await;
        let refused = error_of(&reply);
        assert!(
            refused.as_ref().is_some_and(|(kind, message)| *kind
                == ServerErrorResponseType::BadRequest as i32
                && message.contains("exactly one PEM block")),
            "{what}: {}",
            handed_out(&reply, &key)
        );
    }
    assert_eq!(
        revocations.issued().len(),
        before,
        "a certificate was signed"
    );
}

/// An enrolment request read from anything but exactly one PEM block — on an enrolment connection
/// and through a Gateway — is answered `BadRequest` naming it and queued nowhere.
/// Verifies: ADR-0039
/// Verifies: ADR-0039
#[tokio::test]
async fn an_enrolment_request_is_read_from_exactly_one_pem_block() {
    let pki = Pki::new();
    let bootstrap = Pki::named("opamp-fleet-test-bootstrap-ca");
    let (served, gateway) = behind_a_gateway(&pki, &bootstrap, None, None).await;
    let enrolment = served.enrolment.clone().expect("enrolment");
    let (cert, key) = bootstrap.issue_bootstrap("bootstrap-a");
    let enrolling = client(&served.ca_pem, Some((&cert, &key)));
    let uid = InstanceUid::default();
    let victim = bootstrap_csr(&cert, &key, None);
    let (attacker, attacker_key) = grafted(&victim);
    for (csr, what) in crafted(&attacker, &victim) {
        for (sender, path) in [(&enrolling, "directly"), (&gateway, "through a Gateway")] {
            let reply =
                decode(post(sender, &served.endpoint, with_csr(&uid, csr.clone())).await).await;
            let refused = error_of(&reply);
            assert!(
                refused.as_ref().is_some_and(|(kind, message)| *kind
                    == ServerErrorResponseType::BadRequest as i32
                    && message.contains("exactly one PEM block")),
                "{what}, {path}: {refused:?}, {}",
                handed_out(&reply, &attacker_key)
            );
        }
    }
    assert!(
        enrolment.pending().is_empty(),
        "queued: {:?}",
        enrolment.pending()
    );
}
