//! Which certificate each plane serves (ADR-0032): with `[rest.tls]` the Operator plane serves the
//! certificate the operator's own PKI issued and the Agent plane keeps `[tls]`'s, so a browser
//! trusts the one, a Client the other, and neither trust reaches the other plane. Without the
//! section both planes serve `[tls]`'s.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use classis_server::config::{RestTlsConfig, TlsConfig};
use classis_server::fleet::AppState;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

/// A CA, and what it issues for `localhost`.
struct Pki {
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Pki {
    fn named(name: &str) -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_pem = params.self_signed(&key).expect("ca").pem();
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).expect("issuer");
        Pki { ca_pem, issuer }
    }

    /// The certificate and key for `localhost`, written under `dir` as `<name>.pem` and
    /// `<name>-key.pem`.
    fn serving(&self, dir: &Path, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let key = KeyPair::generate().expect("key");
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .signed_by(&key, &self.issuer)
            .expect("signed");
        let (cert_file, key_file) = (
            dir.join(format!("{name}.pem")),
            dir.join(format!("{name}-key.pem")),
        );
        std::fs::write(&cert_file, cert.pem()).expect("write");
        std::fs::write(&key_file, key.serialize_pem()).expect("write");
        (cert_file, key_file)
    }
}

/// Serves both planes over TLS: `[tls]` from `fleet`, and `[rest.tls]` from `operator` when given.
/// Answers the address of each plane.
async fn serve(
    dir: &Path,
    fleet: &Pki,
    operator: Option<&Pki>,
    state: Arc<AppState>,
) -> (SocketAddr, SocketAddr) {
    opamp::tls::install_ring_provider();
    let (cert_file, key_file) = fleet.serving(dir, "server");
    let tls = TlsConfig {
        cert_file,
        key_file,
    };
    let rest_tls = operator.map(|pki| {
        let (cert_file, key_file) = pki.serving(dir, "ui");
        RestTlsConfig {
            cert_file,
            key_file,
        }
    });
    let planes = classis_server::tls::server_tls(&tls, rest_tls.as_ref()).expect("server material");
    let agent_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Agent plane");
    let operator_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Operator plane");
    let addrs = (
        agent_listener.local_addr().expect("local addr"),
        operator_listener.local_addr().expect("local addr"),
    );
    let handle = opamp::server::listen::Handle::new();
    tokio::spawn(
        classis_server::listen::plane(
            agent_listener,
            Some(planes.agent.rustls_config().expect("agent plane config")),
            64,
            handle.clone(),
        )
        .serve(classis_server::agent_app_open_for_tests(state.clone())),
    );
    tokio::spawn(
        classis_server::listen::plane(
            operator_listener,
            Some(
                planes
                    .operator
                    .rustls_config()
                    .expect("operator plane config"),
            ),
            64,
            handle,
        )
        .serve(classis_server::operator_app(state, None)),
    );
    addrs
}

/// A client that trusts `ca_pem` alone and reaches `localhost` at the listeners' address.
fn trusting(ca_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca")])
        .resolve(
            "localhost",
            "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        )
        .build()
        .expect("client")
}

/// With `[rest.tls]` the Operator plane serves the PKI's certificate and the Agent plane keeps
/// `[tls]`'s; without it both serve `[tls]`'s.
/// Verifies: ADR-0032
#[tokio::test]
async fn the_operator_plane_serves_its_own_certificate_and_the_agent_plane_keeps_the_fleets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = || {
        Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("open the configurations"))
    };
    let fleet = Pki::named("fleet server CA");
    let company = Pki::named("company PKI");
    let (agent, operator) = serve(dir.path(), &fleet, Some(&company), state()).await;
    let agents = format!("https://localhost:{}/api/v1/agents", operator.port());
    let opamp_endpoint = format!("https://localhost:{}/v1/opamp", agent.port());

    let answered = trusting(&company.ca_pem)
        .get(&agents)
        .send()
        .await
        .expect("the PKI's CA vouches for the Operator plane");
    assert!(answered.status().is_success(), "{}", answered.status());
    assert!(
        trusting(&fleet.ca_pem).get(&agents).send().await.is_err(),
        "the fleet's server CA does not vouch for the Operator plane's certificate"
    );
    assert!(
        trusting(&fleet.ca_pem)
            .post(&opamp_endpoint)
            .send()
            .await
            .is_ok(),
        "a Client trusting the fleet's CA reaches the Agent plane"
    );
    assert!(
        trusting(&company.ca_pem)
            .post(&opamp_endpoint)
            .send()
            .await
            .is_err(),
        "the PKI's CA does not vouch for the Agent plane's certificate"
    );

    let without = tempfile::tempdir().expect("tempdir");
    let (_, operator) = serve(
        without.path(),
        &fleet,
        None,
        Arc::new(AppState::new(without.path().join("fleet-configs")).expect("configurations")),
    )
    .await;
    let answered = trusting(&fleet.ca_pem)
        .get(format!(
            "https://localhost:{}/api/v1/agents",
            operator.port()
        ))
        .send()
        .await
        .expect("without [rest.tls] the Operator plane serves [tls]'s certificate");
    assert!(answered.status().is_success(), "{}", answered.status());
}
