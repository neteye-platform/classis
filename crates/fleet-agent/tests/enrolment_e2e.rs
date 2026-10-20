//! Enrolment and the renewals after it, end to end (ADR-0021 clauses 9, 11, 21 and 22): the real
//! Client binary enrols with a bootstrap certificate over mutual TLS, an operator approves its
//! request, and it renews what it was issued — each step costing the register exactly one
//! certificate.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::AppState;
use fleet_server::revocation::Revocations;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

struct ClientUnderTest(Child);

impl Drop for ClientUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A throwaway CA, written into `dir` as `<name>.pem` and `<name>-key.pem`.
struct Ca {
    pem: String,
    key_pem: String,
}

impl Ca {
    fn new(dir: &Path, name: &str) -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        let ca = Ca {
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
        };
        std::fs::write(dir.join(format!("{name}.pem")), &ca.pem).expect("write");
        std::fs::write(dir.join(format!("{name}-key.pem")), &ca.key_pem).expect("write");
        ca
    }

    /// A leaf certificate and its key, written into `dir` as `<name>.pem` and `<name>-key.pem`.
    fn issue(&self, dir: &Path, name: &str) {
        let issuer =
            Issuer::from_ca_cert_pem(&self.pem, KeyPair::from_pem(&self.key_pem).expect("ca key"))
                .expect("issuer");
        let key = KeyPair::generate().expect("key");
        let cert = CertificateParams::new(vec![name.to_string()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("signed");
        std::fs::write(dir.join(format!("{name}.pem")), cert.pem()).expect("write");
        std::fs::write(dir.join(format!("{name}-key.pem")), key.serialize_pem()).expect("write");
    }

    /// A bootstrap certificate and its key like [`issue`](Self::issue), naming the customer and
    /// the site an approval requires of every bootstrap certificate (ADR-0036 clause 3).
    fn issue_bootstrap(&self, dir: &Path, name: &str) {
        let issuer =
            Issuer::from_ca_cert_pem(&self.pem, KeyPair::from_pem(&self.key_pem).expect("ca key"))
                .expect("issuer");
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Kunde GmbH");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, "Werk Nord");
        let cert = params.signed_by(&key, &issuer).expect("signed");
        std::fs::write(dir.join(format!("{name}.pem")), cert.pem()).expect("write");
        std::fs::write(dir.join(format!("{name}-key.pem")), key.serialize_pem()).expect("write");
    }

    fn authority(&self, role: &str) -> fleet_server::revocation::Authority {
        let der = opamp::tls::certificates(self.pem.as_bytes()).expect("pem");
        let facts = fleet_server::ca::facts(der[0].as_ref()).expect("facts");
        fleet_server::revocation::Authority {
            role: role.to_string(),
            subject: facts.id.issuer,
            name: facts.issuer_name,
        }
    }
}

/// The serial of the certificate the Client holds, if it holds one.
fn held(state_dir: &Path) -> Option<Vec<u8>> {
    let pem = std::fs::read(state_dir.join("client-cert.pem")).ok()?;
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem).ok()?;
    let cert = block.parse_x509().ok()?;
    Some(cert.raw_serial().to_vec())
}

async fn until<T>(what: &str, within: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(found) = probe() {
            return found;
        }
        assert!(Instant::now() < deadline, "{what} did not happen in time");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The newest message the Server has taken from the Agent, once it is an Agent of the fleet.
fn last_message(state: &AppState) -> Option<u64> {
    state.snapshot().first().map(|agent| agent.sequence_num)
}

/// Waits until the Server has taken a message after `after`: one connection's messages are taken
/// in order, so everything `after` caused — a certificate signed on it included — is done.
async fn past(state: &AppState, after: u64) {
    until("a later message", Duration::from_secs(10), || {
        last_message(state).filter(|seq| *seq > after)
    })
    .await;
}

/// A host enrols with a bootstrap certificate and an operator's approval, and then renews, over the
/// WebSocket transport: the approval issues one certificate and the renewal one more. The request
/// proves the bootstrap certificate it is queued under.
/// Verifies: ADR-0021, ADR-0039
#[tokio::test]
async fn an_enrolment_and_a_renewal_each_issue_one_certificate_over_websocket() {
    enrol_and_renew("wss").await;
}

/// The same over plain HTTP polling.
/// Verifies: ADR-0021, ADR-0039
#[tokio::test]
async fn an_enrolment_and_a_renewal_each_issue_one_certificate_over_http() {
    enrol_and_renew("https").await;
}

/// With heartbeats off, the request still reaches the queue at once: it never waits for a message
/// that would carry it, and the certificate is pushed to the host on approval.
/// Verifies: ADR-0021
#[tokio::test]
async fn an_enrolment_needs_no_heartbeat() {
    let served = Served::start(60).await;
    let _client = served.client("wss", "heartbeat_interval_secs = 0\n");
    let id = until("an enrolment request", Duration::from_secs(10), || {
        served
            .enrolment
            .pending()
            .first()
            .map(|pending| pending.id.clone())
    })
    .await;
    served.state.approve_enrolment(&id).expect("approve");
    until("the issued certificate", Duration::from_secs(10), || {
        held(&served.state_dir)
    })
    .await;
}

/// The questionnaire's enrolment (ADR-0019 clause 17) carries a host to its first certificate with
/// the bootstrap pair where it lies: it returns once an operator approved the request, the issued
/// certificate is in the state directory, and nothing was copied beside the configuration.
/// Verifies: ADR-0019
#[tokio::test]
async fn the_questionnaires_enrolment_stores_the_issued_certificate_and_copies_nothing() {
    let served = Served::start(600).await;
    let pki = served.dir.path();
    let data_root = pki.join("data");
    std::fs::create_dir_all(&data_root).expect("data root");
    let config_path = data_root.join("supervisor.toml");
    std::fs::write(
        &config_path,
        format!(
            "endpoint = \"wss://localhost:{}/v1/opamp\"\nstate_dir = {:?}\n\
             [tls]\nca_file = {:?}\n",
            served.port,
            served.state_dir.display().to_string(),
            pki.join("client-ca.pem").display().to_string(),
        ),
    )
    .expect("write");
    let config = fleet_agent::config::ClientConfig::load(&config_path).expect("load");
    assert!(!config.is_enrolled());

    let (_stop, shutdown) = fleet_agent::shutdown::shutdown_channel();
    let enrolling = tokio::spawn(fleet_agent::service::enrol::enrol(
        config,
        fleet_agent::config_init::Bootstrap::Pair {
            cert: pki.join("bootstrap.pem"),
            key: pki.join("bootstrap-key.pem"),
        },
        shutdown,
    ));
    let id = until("an enrolment request", Duration::from_secs(20), || {
        served
            .enrolment
            .pending()
            .first()
            .map(|pending| pending.id.clone())
    })
    .await;
    assert_eq!(
        fleet_agent::csr::pending_fingerprint(&served.state_dir).as_deref(),
        Some(id.as_str()),
        "a resumed enrolment prints the id the operator approves by"
    );
    served.state.approve_enrolment(&id).expect("approve");
    tokio::time::timeout(Duration::from_secs(20), enrolling)
        .await
        .expect("the enrolment ends once the certificate is stored")
        .expect("task")
        .expect("enrolled");

    assert!(held(&served.state_dir).is_some(), "the issued certificate");
    let config = fleet_agent::config::ClientConfig::load(&config_path).expect("load");
    assert!(config.is_enrolled());
    config
        .check_admission()
        .expect("the service starts on the issued certificate alone");
    let beside: Vec<_> = std::fs::read_dir(&data_root)
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(beside, ["supervisor.toml"], "nothing copied beside it");
}

/// A `bootstrap.p12` enrols as the pair does, from memory: the questionnaire's enrolment opens it
/// under its password and stores the issued certificate, and the bootstrap key it decrypted is in
/// no file it writes (ADR-0029 clauses 7 and 8).
/// Verifies: ADR-0029
#[tokio::test]
async fn a_bootstrap_p12_enrols_and_its_key_is_never_written() {
    const PASSWORD: &str = "a password of the operator";
    let served = Served::start(600).await;
    let pki = served.dir.path();
    let key_pem = std::fs::read_to_string(pki.join("bootstrap-key.pem")).expect("key");
    let cert_pem = std::fs::read(pki.join("bootstrap.pem")).expect("cert");
    let key = KeyPair::from_pem(&key_pem).expect("key");
    let cert_der = opamp::tls::certificates(&cert_pem).expect("cert")[0].to_vec();
    let p12_dir = pki.join("fleet-files");
    std::fs::create_dir_all(&p12_dir).expect("dir");
    let p12 = p12_dir.join("bootstrap.p12");
    std::fs::write(
        &p12,
        fleet_core::pkcs12::file::seal(&cert_der, &key.serialize_der(), PASSWORD).expect("seal"),
    )
    .expect("write");
    // The key leaves the file: the PEM files a pair would use are gone.
    std::fs::remove_file(pki.join("bootstrap-key.pem")).expect("remove");

    let data_root = pki.join("data");
    std::fs::create_dir_all(&data_root).expect("data root");
    let config_path = data_root.join("supervisor.toml");
    std::fs::write(
        &config_path,
        format!(
            "endpoint = \"wss://localhost:{}/v1/opamp\"\nstate_dir = {:?}\n\
             [tls]\nca_file = {:?}\n",
            served.port,
            served.state_dir.display().to_string(),
            pki.join("client-ca.pem").display().to_string(),
        ),
    )
    .expect("write");
    let config = fleet_agent::config::ClientConfig::load(&config_path).expect("load");
    let beside = fleet_agent::config_init::Beside::in_named_dir(&p12_dir).expect("dir");
    let bootstrap = beside
        .unasked_enrolment(&config, Some(PASSWORD))
        .expect("opens")
        .expect("taken");

    let (_stop, shutdown) = fleet_agent::shutdown::shutdown_channel();
    let enrolling = tokio::spawn(fleet_agent::service::enrol::enrol(
        config, bootstrap, shutdown,
    ));
    let id = until("an enrolment request", Duration::from_secs(20), || {
        served
            .enrolment
            .pending()
            .first()
            .map(|pending| pending.id.clone())
    })
    .await;
    served.state.approve_enrolment(&id).expect("approve");
    tokio::time::timeout(Duration::from_secs(20), enrolling)
        .await
        .expect("the enrolment ends once the certificate is stored")
        .expect("task")
        .expect("enrolled");
    assert!(held(&served.state_dir).is_some(), "the issued certificate");

    let key_body: String = key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    for dir in [data_root.as_path(), served.state_dir.as_path()] {
        for entry in std::fs::read_dir(dir).expect("list") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                let text: String = std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .lines()
                    .collect();
                assert!(
                    !text.contains(&key_body),
                    "{} holds the bootstrap key",
                    path.display()
                );
            }
        }
    }
}

/// Enrols the real Client and lets it renew once, checking after each step that the register holds
/// one certificate per step, and that the one an approval issued is registered under the key
/// fingerprint the request was listed and approved by.
async fn enrol_and_renew(scheme: &str) {
    const LIFE: i64 = 20;
    let served = Served::start(LIFE).await;
    let _client = served.client(
        scheme,
        "heartbeat_interval_secs = 1\npoll_interval_secs = 1\n",
    );
    let (state, revocations, state_dir) = (&served.state, &served.revocations, &served.state_dir);

    let id = until("an enrolment request", Duration::from_secs(20), || {
        served
            .enrolment
            .pending()
            .first()
            .map(|pending| pending.id.clone())
    })
    .await;
    // The request proves the bootstrap certificate it was queued under (ADR-0039).
    let csr = std::fs::read(state_dir.join(fleet_agent::tls::PENDING_CSR_FILE)).expect("csr");
    assert!(
        fleet_core::csr::requested_uri(
            &fleet_core::csr::der(&csr).expect("one PEM block"),
            fleet_core::bootstrap_proof::URI_PREFIX
        )
        .expect("a request")
        .is_some(),
        "the enrolment request carries no bootstrap proof"
    );
    assert_eq!(
        served.enrolment.pending()[0]
            .requester
            .bootstrap_fingerprint,
        {
            use sha2::Digest as _;
            let pem = std::fs::read(served.dir.path().join("bootstrap.pem")).expect("bootstrap");
            hex::encode(sha2::Sha256::digest(
                opamp::tls::certificates(&pem).expect("pem")[0].as_ref(),
            ))
        },
        "queued under the bootstrap certificate it proves"
    );
    state.approve_enrolment(&id).expect("approve");
    let first = until("the issued certificate", Duration::from_secs(10), || {
        held(state_dir)
    })
    .await;
    // An enrolling host is no Agent of the fleet, so the first message the Server keeps is the
    // first on a member connection: the one a request answered already would ride.
    let first_member = until("a member connection", Duration::from_secs(10), || {
        last_message(state)
    })
    .await;
    past(state, first_member).await;
    let issued = revocations.issued();
    assert_eq!(issued.len(), 1, "an approval issued {}", issued.len());
    assert_eq!(
        issued[0].facts.key_fingerprint, id,
        "the register knows the key by another fingerprint than the approved request"
    );

    let second = until("a renewal", Duration::from_secs(LIFE as u64), || {
        held(state_dir).filter(|serial| *serial != first)
    })
    .await;
    // The renewed certificate is stored before the Client reconnects with it, so the message after
    // this one is the first on the new connection, and the one after that proves it was taken.
    let stored = last_message(state).expect("an Agent");
    past(state, stored + 1).await;
    let issued = revocations.issued();
    assert_eq!(
        issued.len(),
        2,
        "enrolment and one renewal issued {}",
        issued.len()
    );
    assert_eq!(
        held(state_dir),
        Some(second),
        "the Client stays on its renewal"
    );
}

/// A Server on mutual TLS with a client CA whose certificates live `life` seconds, a bootstrap CA,
/// the register, and an open enrolment window, as `main` builds them from `server.toml`.
struct Served {
    dir: tempfile::TempDir,
    port: u16,
    state: Arc<AppState>,
    enrolment: Arc<fleet_server::enrolment::Enrolment>,
    revocations: Arc<Revocations>,
    state_dir: std::path::PathBuf,
}

impl Served {
    async fn start(life: i64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = dir.path();
        let client_ca = Ca::new(pki, "client-ca");
        let bootstrap_ca = Ca::new(pki, "bootstrap-ca");
        client_ca.issue(pki, "localhost");
        bootstrap_ca.issue_bootstrap(pki, "bootstrap");

        let clock: Arc<dyn fleet_server::fleet::Clock> = Arc::new(fleet_server::clock::SystemClock);
        let enrolment = Arc::new(fleet_server::enrolment::Enrolment::new(clock.clone()));
        let revocations = Arc::new(
            Revocations::open(
                Box::new(
                    fleet_server::fs::FsLedgerStore::open(&pki.join("fleet-configs"))
                        .expect("ledger"),
                ),
                clock,
                vec![
                    client_ca.authority("client"),
                    bootstrap_ca.authority("bootstrap"),
                ],
            )
            .expect("revocations"),
        );
        let signer = fleet_server::ca::ClientCa::from_config(
            &toml::from_str::<fleet_server::config::ClientCaConfig>(&format!(
                "cert_file = {:?}\nkey_file = {:?}\n",
                pki.join("client-ca.pem").display().to_string(),
                pki.join("client-ca-key.pem").display().to_string(),
            ))
            .expect("client_ca config"),
        )
        .expect("client ca")
        .with_validity(time::Duration::seconds(life));
        let state = Arc::new(
            AppState::new(pki.join("fleet-configs"))
                .expect("state")
                .with_client_ca(Some(signer))
                .with_enrolment(Some(enrolment.clone()))
                .with_revocations(Some(revocations.clone())),
        );

        let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
            "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
            pki.join("localhost.pem").display().to_string(),
            pki.join("localhost-key.pem").display().to_string(),
            pki.join("client-ca.pem").display().to_string(),
        ))
        .expect("tls config");
        let planes = fleet_server::tls::server_tls(
            &tls,
            None,
            Some(&fleet_server::config::EnrolmentConfig {
                bootstrap_ca_file: pki.join("bootstrap-ca.pem"),
                bootstrap_ca_key_file: None,
                max_pending_per_bootstrap:
                    fleet_server::enrolment::DEFAULT_MAX_PENDING_PER_BOOTSTRAP,
            }),
        )
        .expect("server material");
        let admission = fleet_server::transport::Admission::new(true)
            .with_enrolment(planes.issuers, Some(enrolment.clone()))
            .with_revocations(Some(revocations.clone()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(
            fleet_server::listen::plane(
                listener,
                Some(planes.agent.rustls_config().expect("agent plane config")),
                64,
                opamp::server::listen::Handle::new(),
            )
            .serve(fleet_server::agent_app(state.clone(), admission)),
        );
        enrolment.open(600).expect("open the window");
        let state_dir = pki.join("client-state");
        Served {
            dir,
            port,
            state,
            enrolment,
            revocations,
            state_dir,
        }
    }

    /// The real Client on its bootstrap certificate, over `scheme`, with `settings` added to the
    /// top of its `supervisor.toml`.
    fn client(&self, scheme: &str, settings: &str) -> ClientUnderTest {
        let pki = self.dir.path();
        let config_path = pki.join("supervisor.toml");
        std::fs::write(
            &config_path,
            format!(
                "endpoint = \"{scheme}://localhost:{}/v1/opamp\"\nstate_dir = {:?}\n{settings}\n\
                 [tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
                self.port,
                self.state_dir.display().to_string(),
                pki.join("client-ca.pem").display().to_string(),
                pki.join("bootstrap.pem").display().to_string(),
                pki.join("bootstrap-key.pem").display().to_string(),
            ),
        )
        .expect("write");
        ClientUnderTest(
            Command::new(env!("CARGO_BIN_EXE_supervisor"))
                .arg("--config")
                .arg(&config_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the client"),
        )
    }
}
