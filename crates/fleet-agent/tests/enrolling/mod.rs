//! A Server that enrols, for the tests that enrol the real Client binary against it: the end-to-end
//! enrolment test, and the service smoke test that installs with a bootstrap certificate.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use fleet_server::fleet::AppState;
use fleet_server::revocation::Revocations;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

pub struct ClientUnderTest(Child);

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

/// A Server on mutual TLS with a client CA whose certificates live `life` seconds, a bootstrap CA,
/// the register, and an open enrolment window, as `main` builds them from `server.toml`.
pub struct Served {
    pub dir: tempfile::TempDir,
    pub port: u16,
    pub state: Arc<AppState>,
    pub enrolment: Arc<fleet_server::enrolment::Enrolment>,
    pub revocations: Arc<Revocations>,
    pub state_dir: PathBuf,
    /// The runtime it is served on, when it owns one ([`start_on_its_own`](Self::start_on_its_own)).
    _runtime: Option<tokio::runtime::Runtime>,
}

impl Served {
    /// Started on the runtime the caller runs on.
    pub async fn start(life: i64) -> Self {
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
            _runtime: None,
        }
    }

    /// Started on a runtime of its own, for a test that runs on none; served as long as it lives.
    #[allow(dead_code)] // each integration-test binary uses a different subset of this support
    pub fn start_on_its_own(life: i64) -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let served = runtime.block_on(Self::start(life));
        Served {
            _runtime: Some(runtime),
            ..served
        }
    }

    /// The real Client on its bootstrap certificate, over `scheme`, with `settings` added to the
    /// top of its `supervisor.toml`.
    #[allow(dead_code)] // each integration-test binary uses a different subset of this support
    pub fn client(&self, scheme: &str, settings: &str) -> ClientUnderTest {
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
