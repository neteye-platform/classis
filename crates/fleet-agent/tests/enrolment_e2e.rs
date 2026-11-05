//! Enrolment and the renewals after it, end to end (ADR-0021 clauses 9, 11, 21 and 22): the real
//! Client binary enrols with a bootstrap certificate over mutual TLS, an operator approves its
//! request, and it renews what it was issued — each step costing the register exactly one
//! certificate.

mod enrolling;

use std::path::Path;
use std::time::{Duration, Instant};

use enrolling::Served;
use fleet_server::fleet::AppState;
use rcgen::KeyPair;

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
