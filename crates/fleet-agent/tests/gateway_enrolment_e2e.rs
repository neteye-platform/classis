//! Enrolment through a Gateway, end to end (ADR-0039): the real Server with enrolment and its
//! register, the real Gateway in front of it trusting the bootstrap CA, and an enrolling host
//! behind it — a raw plain-HTTP peer, and the real Client binary.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_agent::config::ClientConfig;
use fleet_agent::gateway::Timings;
use fleet_agent::shutdown::shutdown_channel;
use fleet_server::fleet::AppState;
use fleet_server::revocation::Revocations;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::uid::InstanceUid;
use prost::Message as _;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

/// A throwaway CA, written into the directory as `<name>.pem` and `<name>-key.pem`.
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

    fn issuer(&self) -> Issuer<'static, KeyPair> {
        Issuer::from_ca_cert_pem(&self.pem, KeyPair::from_pem(&self.key_pem).expect("ca key"))
            .expect("issuer")
    }

    /// A leaf for `name`, written as `<file>.pem` and `<file>-key.pem`; returns certificate and key.
    fn issue(&self, dir: &Path, file: &str, name: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let cert = CertificateParams::new(vec![name.to_string()])
            .expect("params")
            .signed_by(&key, &self.issuer())
            .expect("signed");
        std::fs::write(dir.join(format!("{file}.pem")), cert.pem()).expect("write");
        std::fs::write(dir.join(format!("{file}-key.pem")), key.serialize_pem()).expect("write");
        (cert.pem(), key.serialize_pem())
    }

    /// A bootstrap certificate naming the customer and the site an approval requires (ADR-0036
    /// clause 3), written like [`issue`](Self::issue).
    fn issue_bootstrap(&self, dir: &Path, file: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![file.to_string()]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Kunde GmbH");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, "Werk Nord");
        let cert = params.signed_by(&key, &self.issuer()).expect("signed");
        std::fs::write(dir.join(format!("{file}.pem")), cert.pem()).expect("write");
        std::fs::write(dir.join(format!("{file}-key.pem")), key.serialize_pem()).expect("write");
        (cert.pem(), key.serialize_pem())
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

struct ClientUnderTest(Child);

impl Drop for ClientUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

/// The Server with enrolment and an open window, a marked Gateway in front of it, and what a test
/// needs of both.
struct Fleet {
    dir: tempfile::TempDir,
    client_ca: Ca,
    bootstrap_ca: Ca,
    state: Arc<AppState>,
    enrolment: Arc<fleet_server::enrolment::Enrolment>,
    gateway_host: String,
    gateway: std::net::SocketAddr,
    _stop: tokio::sync::watch::Sender<bool>,
}

impl Fleet {
    /// `bootstrap` names the Gateway's `[gateway.tls] bootstrap_ca_file`, or leaves it out.
    async fn start(bootstrap: bool) -> Self {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = dir.path();
        let client_ca = Ca::new(pki, "client-ca");
        let bootstrap_ca = Ca::new(pki, "bootstrap-ca");
        client_ca.issue(pki, "server", "127.0.0.1");
        client_ca.issue(pki, "gateway-listener", "127.0.0.1");

        let clock: Arc<dyn fleet_server::fleet::Clock> = Arc::new(fleet_server::clock::SystemClock);
        let revocations = Arc::new(
            Revocations::open(
                Box::new(
                    fleet_server::fs::FsLedgerStore::open(&pki.join("fleet-configs"))
                        .expect("ledger"),
                ),
                clock.clone(),
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
        .expect("client ca");

        // The Gateway's own certificate, issued by the Server so that it names a host, marked.
        let key = KeyPair::generate().expect("key");
        let csr = CertificateParams::new(vec!["gateway".to_string()])
            .expect("params")
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("pem");
        let signed = signer
            .sign(
                &csr,
                "gateway-host",
                &fleet_server::revocation::SubjectValues::default(),
            )
            .expect("sign");
        std::fs::write(pki.join("gateway-cert.pem"), &signed.pem).expect("write");
        std::fs::write(pki.join("gateway-cert-key.pem"), key.serialize_pem()).expect("write");
        let gateway_host = signed.facts.host.clone().expect("a host");
        revocations
            .record(signed.facts, &[7; 16], None)
            .expect("register");
        assert!(revocations.set_gateway(&gateway_host, true).expect("mark"));

        let enrolment = Arc::new(fleet_server::enrolment::Enrolment::new(clock));
        let state = Arc::new(
            AppState::new(pki.join("fleet-configs"))
                .expect("state")
                .with_client_ca(Some(signer))
                .with_enrolment(Some(enrolment.clone()))
                .with_revocations(Some(revocations.clone())),
        );
        let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
            "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
            pki.join("server.pem").display().to_string(),
            pki.join("server-key.pem").display().to_string(),
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
        let server = listener.local_addr().expect("addr");
        tokio::spawn(
            opamp::server::listen::Listener::new(listener, opamp::server::listen::Handle::new())
                .with_tls(planes.agent.rustls_config().expect("agent plane"))
                .serve(fleet_server::agent_app(state.clone(), admission)),
        );
        enrolment.open(600).expect("open the window");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let gateway = listener.local_addr().expect("addr");
        let path = |file: &str| pki.join(file).display().to_string();
        let bootstrap_line = if bootstrap {
            format!("bootstrap_ca_file = {:?}\n", path("bootstrap-ca.pem"))
        } else {
            String::new()
        };
        let config: ClientConfig = toml::from_str(&format!(
            r#"
            endpoint = "wss://{server}/v1/opamp"
            state_dir = {:?}
            [tls]
            ca_file = {:?}
            cert_file = {:?}
            key_file = {:?}
            [gateway]
            listen = "{gateway}"
            [gateway.tls]
            cert_file = {:?}
            key_file = {:?}
            client_ca_file = {:?}
            {bootstrap_line}
            "#,
            path("gateway-state"),
            path("client-ca.pem"),
            path("gateway-cert.pem"),
            path("gateway-cert-key.pem"),
            path("gateway-listener.pem"),
            path("gateway-listener-key.pem"),
            path("client-ca.pem"),
        ))
        .expect("gateway config");
        let (stop, shutdown) = shutdown_channel();
        let timings = Timings {
            revocation_refresh: Duration::from_millis(200),
            ..Timings::default()
        };
        tokio::spawn(async move {
            fleet_agent::gateway::run_on_timed(Arc::new(config), listener, shutdown, timings)
                .await
                .expect("gateway");
        });
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(gateway).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Fleet {
            dir,
            client_ca,
            bootstrap_ca,
            state,
            enrolment,
            gateway_host,
            gateway,
            _stop: stop,
        }
    }

    /// A plain-HTTP client through the Gateway as the peer `(cert, key)`.
    fn http(&self, cert: &str, key: &str) -> reqwest::Client {
        let mut pem = key.as_bytes().to_vec();
        pem.extend_from_slice(cert.as_bytes());
        reqwest::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([
                reqwest::Certificate::from_pem(self.client_ca.pem.as_bytes()).expect("ca"),
            ])
            .identity(reqwest::Identity::from_pem(&pem).expect("identity"))
            .build()
            .expect("client")
    }

    /// One plain-HTTP report through the Gateway: its status and, on `200`, the reply.
    async fn post(
        &self,
        client: &reqwest::Client,
        report: &AgentToServer,
    ) -> Result<(reqwest::StatusCode, Option<ServerToAgent>), reqwest::Error> {
        let response = client
            .post(format!("https://{}/v1/opamp", self.gateway))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(report.encode_to_vec())
            .send()
            .await?;
        let status = response.status();
        let reply = if status.is_success() {
            Some(ServerToAgent::decode(response.bytes().await?).expect("decode"))
        } else {
            None
        };
        Ok((status, reply))
    }

    /// A WebSocket upgrade through the Gateway as the peer `(cert, key)`: the status it is refused
    /// with, or `None` when it upgraded.
    async fn upgrade(&self, cert: &str, key: &str) -> Option<u16> {
        let config = opamp::tls::client_builder()
            .with_root_certificates(
                opamp::tls::root_store(self.client_ca.pem.as_bytes()).expect("roots"),
            )
            .with_client_auth_cert(
                opamp::tls::certificates(cert.as_bytes()).expect("cert"),
                opamp::tls::private_key(key.as_bytes()).expect("key"),
            )
            .expect("client config");
        let request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                format!("wss://{}/v1/opamp", self.gateway),
            )
            .expect("request");
        match tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))),
        )
        .await
        {
            Ok(_) => None,
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                Some(response.status().as_u16())
            }
            Err(e) => panic!("the upgrade failed otherwise: {e}"),
        }
    }
}

/// A CSR for a new key with a bootstrap proof of `(cert, key)`, as the Client builds one.
fn bootstrap_csr(cert: &str, key: &str) -> Vec<u8> {
    use base64::Engine as _;
    use rcgen::{PublicKeyData as _, SigningKey as _};
    use sha2::{Digest as _, Sha256};
    let new_key = KeyPair::generate().expect("new key");
    let der = opamp::tls::certificates(cert.as_bytes()).expect("pem")[0].to_vec();
    let signature = KeyPair::from_pem(key)
        .expect("key")
        .sign(&fleet_core::bootstrap_proof::statement(&Sha256::digest(
            new_key.subject_public_key_info(),
        )))
        .expect("sign");
    let uri = format!(
        "{}{}",
        fleet_core::bootstrap_proof::URI_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(fleet_core::bootstrap_proof::encode(&der, &signature))
    );
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .subject_alt_names
        .push(rcgen::SanType::URI(uri.try_into().expect("uri")));
    params
        .serialize_request(&new_key)
        .expect("csr")
        .pem()
        .expect("pem")
        .into_bytes()
}

/// A report of `uid` carrying `csr`.
fn with_csr(uid: &InstanceUid, csr: Vec<u8>) -> AgentToServer {
    AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num: 1,
        connection_settings_request: Some(opamp::proto::ConnectionSettingsRequest {
            opamp: Some(opamp::proto::OpAmpConnectionSettingsRequest {
                certificate_request: Some(opamp::proto::CertificateRequest { csr }),
            }),
        }),
        ..Default::default()
    }
}

/// A Gateway with `bootstrap_ca_file` admits a bootstrap certificate for one thing: a plain-HTTP
/// report carrying a CSR with a bootstrap proof, which reaches the Server's queue naming the
/// Gateway's host. Its WebSocket upgrade is refused `403`, and so is a report that carries more
/// than the CSR or a CSR without a proof.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_gateway_admits_a_bootstrap_certificate_for_one_enrolment_request() {
    let fleet = Fleet::start(true).await;
    let (cert, key) = fleet
        .bootstrap_ca
        .issue_bootstrap(fleet.dir.path(), "bootstrap");
    let enrolling = fleet.http(&cert, &key);
    let uid = InstanceUid::default();

    assert_eq!(fleet.upgrade(&cert, &key).await, Some(403));
    let described = AgentToServer {
        agent_description: Some(opamp::proto::AgentDescription::default()),
        ..with_csr(&uid, bootstrap_csr(&cert, &key))
    };
    let unproven = CertificateParams::new(vec!["edge".to_string()])
        .expect("params")
        .serialize_request(&KeyPair::generate().expect("key"))
        .expect("csr")
        .pem()
        .expect("pem")
        .into_bytes();
    for (report, what) in [
        (
            AgentToServer {
                instance_uid: uid.as_bytes().to_vec(),
                ..Default::default()
            },
            "a report without a CSR",
        ),
        (described, "a report carrying a description beside the CSR"),
        (with_csr(&uid, unproven), "a CSR without a bootstrap proof"),
    ] {
        let (status, _) = fleet.post(&enrolling, &report).await.expect("send");
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{what}");
    }
    assert!(fleet.enrolment.pending().is_empty());

    let (status, reply) = fleet
        .post(&enrolling, &with_csr(&uid, bootstrap_csr(&cert, &key)))
        .await
        .expect("send");
    assert_eq!(status, reqwest::StatusCode::OK);
    let reply = reply.expect("a reply");
    assert_eq!(
        reply.instance_uid,
        uid.as_bytes(),
        "routed back to the peer"
    );
    assert!(reply.error_response.is_none(), "{:?}", reply.error_response);
    let pending = fleet.enrolment.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].requester.gateway.as_deref(),
        Some(fleet.gateway_host.as_str())
    );

    // The member certificates the Gateway carries are untouched by it.
    let (member_cert, member_key) = fleet.client_ca.issue(fleet.dir.path(), "edge", "edge");
    assert_eq!(fleet.upgrade(&member_cert, &member_key).await, None);
}

/// A Gateway without `bootstrap_ca_file` refuses a bootstrap certificate in the handshake.
/// Verifies: ADR-0039
#[tokio::test]
async fn a_gateway_without_a_bootstrap_ca_refuses_a_bootstrap_certificate() {
    let fleet = Fleet::start(false).await;
    let (cert, key) = fleet
        .bootstrap_ca
        .issue_bootstrap(fleet.dir.path(), "bootstrap");
    let report = with_csr(&InstanceUid::default(), bootstrap_csr(&cert, &key));
    assert!(
        fleet.post(&fleet.http(&cert, &key), &report).await.is_err(),
        "the handshake admitted a bootstrap certificate"
    );
}

/// The real Client enrols through the Gateway: its request waits in the queue naming the Gateway's
/// host, an approval mints a new host, the Client collects its certificate in a later reply, and
/// then reports through the Gateway as a member under its own `instance_uid`.
/// Verifies: ADR-0039
#[tokio::test]
async fn the_client_enrols_through_a_gateway_and_then_reports_through_it() {
    let fleet = Fleet::start(true).await;
    let pki = fleet.dir.path();
    fleet.bootstrap_ca.issue_bootstrap(pki, "bootstrap");
    let state_dir = pki.join("client-state");
    let config_path = pki.join("supervisor.toml");
    std::fs::write(
        &config_path,
        format!(
            "endpoint = \"https://{}/v1/opamp\"\nstate_dir = {:?}\npoll_interval_secs = 1\n\
             [tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
            fleet.gateway,
            state_dir.display().to_string(),
            pki.join("client-ca.pem").display().to_string(),
            pki.join("bootstrap.pem").display().to_string(),
            pki.join("bootstrap-key.pem").display().to_string(),
        ),
    )
    .expect("write");
    let _client = ClientUnderTest(
        Command::new(env!("CARGO_BIN_EXE_supervisor"))
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the client"),
    );

    let pending = until("an enrolment request", Duration::from_secs(20), || {
        fleet.enrolment.pending().into_iter().next()
    })
    .await;
    assert_eq!(
        pending.requester.gateway.as_deref(),
        Some(fleet.gateway_host.as_str()),
        "the request names the Gateway's host"
    );
    assert_eq!(pending.requester.peer, None);
    assert!(
        fleet.state.snapshot().is_empty(),
        "an enrolling host is no Agent"
    );
    fleet.state.approve_enrolment(&pending.id).expect("approve");

    let issued = until("the issued certificate", Duration::from_secs(20), || {
        std::fs::read(state_dir.join("client-cert.pem")).ok()
    })
    .await;
    let host = fleet_server::ca::facts(opamp::tls::certificates(&issued).expect("pem")[0].as_ref())
        .expect("facts")
        .host
        .expect("a host");
    assert_ne!(host, fleet.gateway_host, "a host of its own");

    let uid = std::fs::read_to_string(state_dir.join("instance-uid")).expect("uid");
    let uid = uid.trim().to_string();
    let first = until("a report as a member", Duration::from_secs(20), || {
        fleet
            .state
            .snapshot()
            .into_iter()
            .find(|agent| agent.instance_uid == uid)
            .map(|agent| agent.sequence_num)
    })
    .await;
    until("a later report", Duration::from_secs(20), || {
        fleet
            .state
            .snapshot()
            .into_iter()
            .find(|agent| agent.instance_uid == uid && agent.sequence_num > first)
    })
    .await;
}
