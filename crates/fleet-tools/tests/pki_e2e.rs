//! The certificates `opamp-fleetctl pki init` makes are all a fleet needs (ADR-0028):
//! a Server configured from `server.toml.fragment` issues the bootstrap certificate as a PKCS#12
//! file, `opamp-fleetctl pki p12-extract` writes its pair where `supervisor.toml.fragment` names
//! it, and the Server admits the real Client configured from that fragment with it once its
//! enrolment is approved, with no certificate made by anything else. The program is run as an operator runs it; the Server and the Client run in this process.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::AppState;
use fleet_server::revocation::Revocations;

/// The sections of `server.toml.fragment`, read as the Server reads them.
#[derive(serde::Deserialize)]
struct Fragment {
    tls: fleet_server::config::TlsConfig,
    client_ca: fleet_server::config::ClientCaConfig,
    enrolment: fleet_server::config::EnrolmentConfig,
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

fn authority(file: &Path, role: &str) -> fleet_server::revocation::Authority {
    let pem = std::fs::read(file).expect("read the CA");
    let der = opamp::tls::certificates(&pem).expect("pem");
    let facts = fleet_server::ca::facts(der[0].as_ref()).expect("facts");
    fleet_server::revocation::Authority {
        role: role.to_string(),
        subject: facts.id.issuer,
        name: facts.issuer_name,
    }
}

// Verifies: ADR-0028
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fleet_made_by_pki_init_admits_an_enrolled_host() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let server_dir = dir.path().join("server");
    let offline_dir = dir.path().join("offline");
    let made = Command::new(env!("CARGO_BIN_EXE_opamp-fleetctl"))
        .args(["pki", "init", "--name", "localhost", "--server-dir"])
        .arg(&server_dir)
        .arg("--offline-dir")
        .arg(&offline_dir)
        .output()
        .expect("run opamp-fleetctl");
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );

    // The Server, built from the fragment as `main` builds it from `server.toml`.
    let fragment: Fragment = toml::from_str(
        &std::fs::read_to_string(server_dir.join("server.toml.fragment")).expect("fragment"),
    )
    .expect("the server fragment parses as server.toml sections");
    let clock: Arc<dyn fleet_server::fleet::Clock> = Arc::new(fleet_server::clock::SystemClock);
    let enrolment = Arc::new(fleet_server::enrolment::Enrolment::new(clock.clone()));
    let revocations = Arc::new(
        Revocations::open(
            Box::new(
                fleet_server::fs::FsLedgerStore::open(&dir.path().join("fleet-configs"))
                    .expect("ledger"),
            ),
            clock,
            vec![
                authority(&fragment.client_ca.cert_file, "client"),
                authority(&fragment.enrolment.bootstrap_ca_file, "bootstrap"),
            ],
        )
        .expect("revocations"),
    );
    let signer = fleet_server::ca::ClientCa::from_config(&fragment.client_ca)
        .expect("the client CA pki init made loads");
    // The Server issues the host's bootstrap certificate from the bootstrap CA key pki init gave
    // it, as a PKCS#12 file only (ADR-0036 clause 8), and the operator extracts its pair where
    // supervisor.toml.fragment names it (ADR-0031).
    let bootstrap_ca =
        fleet_server::ca::BootstrapCa::from_config(&fragment.enrolment, Some(&fragment.client_ca))
            .expect("the bootstrap CA pki init made loads")
            .expect("pki init gives the Server the bootstrap CA's key");
    let bootstrap = fleet_server::bootstrap::BootstrapCertificates::on_disk(
        Some(Box::new(bootstrap_ca)),
        &dir.path().join("fleet-configs"),
        Arc::new(fleet_server::clock::SystemClock),
    )
    .expect("bootstrap record");
    let request: fleet_server::bootstrap::IssueRequest =
        serde_json::from_value(serde_json::json!({
            "subject": { "organization": "Kunde GmbH", "organizational_unit": "Werk Nord" },
            "password": "a password of the operator"
        }))
        .expect("request");
    let issued = bootstrap.issue(&request).expect("a bootstrap certificate");
    let files = dir.path().join("files");
    std::fs::create_dir_all(&files).expect("files");
    std::fs::write(files.join("bootstrap.p12"), &issued.pkcs12).expect("write");
    std::fs::write(files.join("password"), "a password of the operator\n").expect("write");
    let extracted = Command::new(env!("CARGO_BIN_EXE_opamp-fleetctl"))
        .args(["pki", "p12-extract"])
        .arg(files.join("bootstrap.p12"))
        .arg("--out")
        .arg(&offline_dir)
        .arg("--password-file")
        .arg(files.join("password"))
        .output()
        .expect("run opamp-fleetctl");
    assert!(
        extracted.status.success(),
        "{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("state")
            .with_client_ca(Some(signer))
            .with_enrolment(Some(enrolment.clone()))
            .with_revocations(Some(revocations.clone())),
    );
    let planes = fleet_server::tls::server_tls(&fragment.tls, None, Some(&fragment.enrolment))
        .expect("the Server accepts the material pki init made");
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

    // The real Client, on the supervisor fragment as written.
    let state_dir = dir.path().join("client-state");
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(
        &config_path,
        format!(
            "endpoint = \"wss://localhost:{port}/v1/opamp\"\nstate_dir = {:?}\n\
             heartbeat_interval_secs = 1\n{}",
            state_dir.display().to_string(),
            std::fs::read_to_string(offline_dir.join("supervisor.toml.fragment"))
                .expect("fragment"),
        ),
    )
    .expect("write supervisor.toml");
    let (stop, shutdown) = fleet_agent::shutdown::shutdown_channel();
    let client = tokio::spawn(fleet_agent::service::runtime::run_until_shutdown(
        fleet_agent::service::runtime::RunSpec {
            config_path,
            state_dir: None,
            service: false,
        },
        shutdown,
    ));

    let id = until("an enrolment request", Duration::from_secs(20), || {
        enrolment
            .pending()
            .first()
            .map(|pending| pending.id.clone())
    })
    .await;
    state.approve_enrolment(&id).expect("approve");
    until(
        "the host as a member of the fleet",
        Duration::from_secs(20),
        || (!state.snapshot().is_empty()).then_some(()),
    )
    .await;
    assert!(
        state_dir.join("client-cert.pem").exists(),
        "the host stores the certificate it was issued"
    );
    assert_eq!(
        revocations.issued().len(),
        1,
        "one approval, one certificate"
    );
    let _ = stop.send(true);
    client
        .await
        .expect("the Client task")
        .expect("the Client ran until it was stopped");
}
