//! The certificates `classisctl pki init` makes are all a Server and a host need to talk (ADR-0028):
//! a Server configured from `server.toml.fragment` serves the server certificate and key it names,
//! and a host that trusts the CA `supervisor.toml.fragment` names enrols at it over TLS, with no
//! certificate made by anything else. The program is run as an operator runs it; the Server and
//! the Client's `enrol` run in this process.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use classis_agent::enrolment::{enrol, Installed, ServiceHost};
use classis_server::enrolment::Enrolment;
use classis_server::fleet::AppState;
use classis_server::throttle::{Limits, Throttle};

/// The sections of `server.toml.fragment`, read as the Server reads them.
#[derive(serde::Deserialize)]
struct ServerFragment {
    tls: classis_server::config::TlsConfig,
}

/// The sections of `supervisor.toml.fragment` that name what a host trusts.
#[derive(serde::Deserialize)]
struct HostFragment {
    tls: HostTls,
    packages: Packages,
}

#[derive(serde::Deserialize)]
struct HostTls {
    ca_file: std::path::PathBuf,
}

#[derive(serde::Deserialize)]
struct Packages {
    verification_key: String,
}

/// No service is registered for the test's state directory, whatever the machine has.
struct NoService;

impl ServiceHost for NoService {
    fn registered(&self, _: &Path) -> Result<Option<Installed>, String> {
        Ok(None)
    }
}

// Verifies: ADR-0028
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fleet_made_by_pki_init_lets_a_host_enrol_over_tls() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let server_dir = dir.path().join("server");
    let offline_dir = dir.path().join("offline");
    let made = Command::new(env!("CARGO_BIN_EXE_classisctl"))
        .args(["pki", "init", "--name", "localhost", "--server-dir"])
        .arg(&server_dir)
        .arg("--offline-dir")
        .arg(&offline_dir)
        .output()
        .expect("run classisctl");
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );

    // The Server, built from the fragment as `main` builds it from `server.toml`.
    let fragment: ServerFragment = toml::from_str(
        &std::fs::read_to_string(server_dir.join("server.toml.fragment")).expect("fragment"),
    )
    .expect("the server fragment parses as server.toml sections");
    let planes = classis_server::tls::server_tls(&fragment.tls, None)
        .expect("the Server accepts the material pki init made");
    let data = dir.path().join("data");
    classis_server::fs::open_data_dir(&data, true).expect("the data directory");
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    let enrolment = Arc::new(
        Enrolment::on(
            &classis_server::Records::Files(data),
            toml::from_str::<classis_server::config::ServerConfig>("")
                .expect("the default configuration")
                .token_lifetime(),
            clock.clone(),
            Arc::new(Throttle::new(Limits::default(), clock)),
        )
        .expect("the enrolment"),
    );
    let key = enrolment
        .spaces()
        .create("lab")
        .expect("a space")
        .to_string();
    let state = Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("state"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(
        classis_server::listen::plane(
            listener,
            Some(planes.agent.rustls_config().expect("agent plane config")),
            64,
            opamp::server::listen::Handle::new(),
        )
        .serve(classis_server::agent_app(state.clone(), enrolment)),
    );

    // The host, trusting the CA the supervisor fragment names and nothing else, enrols through the
    // Client's own `enrol`.
    let host: HostFragment = toml::from_str(
        &std::fs::read_to_string(offline_dir.join("supervisor.toml.fragment")).expect("fragment"),
    )
    .expect("the supervisor fragment parses");
    assert_eq!(
        host.tls.ca_file,
        offline_dir.join("server-ca.pem"),
        "the fragment names the CA where `pki init` wrote it"
    );
    assert_eq!(
        host.packages.verification_key,
        std::fs::read_to_string(offline_dir.join("package-signing-key.pub"))
            .expect("the public key")
            .trim(),
        "the fragment names the public half of the signing key pki init made"
    );
    let state_dir = dir.path().join("client-state");
    let enrolled = enrol(
        &format!("https://localhost:{port}"),
        &key,
        &state_dir,
        opamp::client::ClientTls {
            ca_pem: Some(std::fs::read(&host.tls.ca_file).expect("the CA")),
        },
        &NoService,
    )
    .await
    .expect(
        "a host that trusts the CA the fragment names enrols at the Server the fragment configures",
    );
    assert_eq!(enrolled.space, "lab");
    assert!(enrolled.state_file.is_file(), "the host holds its state");
}
