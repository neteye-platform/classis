//! One upstream connection built from its description (ADR-0010): the client's TLS, credential and
//! transport against the server's listener, through the probe and through a full run.

use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, StatusCode};
use axum::routing::post;
use opamp::client::{AfterReply, ClientTls, Connection, Ended, ReportSink, Session, StopSignal};
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::listen::{ClientAuth, Handle, Listener, PeerCertificate, ServerTls};
use opamp::server::{Handler, NoOutbound, Rejection, Reply, RequestInfo, Settings};
use opamp::tls::Identity;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

struct Pki {
    ca_pem: String,
    ca_key_pem: String,
}

impl Pki {
    fn new() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec!["opamp-test-ca".to_string()]).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        Pki {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    fn issue(&self, name: &str) -> Identity {
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).expect("ca key");
        let issuer = Issuer::from_ca_cert_pem(&self.ca_pem, ca_key).expect("issuer");
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec![name.to_string()]).expect("params");
        let cert = params.signed_by(&key, &issuer).expect("signed");
        Identity {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        }
    }
}

/// Admits a connection that brings the credential and a client certificate, and answers every
/// report with its own `instance_uid`.
struct Gate;

impl Handler for Gate {
    type Connection = ();
    type Outbound = NoOutbound;

    fn on_connecting(
        &self,
        request: &RequestInfo<'_>,
    ) -> Result<((), Option<NoOutbound>), Rejection> {
        let certificate = request
            .extensions
            .get::<PeerCertificate>()
            .is_some_and(PeerCertificate::present);
        let credential = request
            .headers
            .get(header::AUTHORIZATION)
            .is_some_and(|value| value == "Bearer secret");
        if certificate && credential {
            Ok(((), None))
        } else {
            Err(Rejection {
                status: StatusCode::UNAUTHORIZED,
                headers: Vec::new(),
                message: "refused".to_string(),
            })
        }
    }

    async fn on_message(&self, _: &mut (), message: AgentToServer) -> Reply {
        Reply::Send(ServerToAgent {
            instance_uid: message.instance_uid,
            ..Default::default()
        })
    }

    fn on_outbound(&self, _: &mut (), item: std::convert::Infallible) -> Vec<ServerToAgent> {
        match item {}
    }
}

/// The endpoint over TLS with an optional client certificate, plus a route that redirects.
fn serve(pki: &Pki) -> u16 {
    opamp::tls::install_ring_provider();
    let tls = ServerTls {
        identity: pki.issue("localhost"),
        client_auth: ClientAuth::Optional {
            ca_pem: pki.ca_pem.clone().into_bytes(),
        },
    }
    .rustls_config()
    .expect("server config");
    let router = opamp::server::router(Arc::new(Gate), Settings::new(4096)).route(
        "/moved",
        post(|| async {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "/v1/opamp")],
            )
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(
        Listener::new(listener, Handle::new())
            .with_tls(tls)
            .serve(router),
    );
    port
}

fn connection(endpoint: String, pki: &Pki, identity: Option<Identity>) -> Connection {
    Connection {
        endpoint,
        authorization: Some("Bearer secret".to_string()),
        tls: ClientTls {
            ca_pem: Some(pki.ca_pem.clone().into_bytes()),
            identity,
        },
        max_message_size: 4096,
        heartbeat: None,
        poll: Duration::from_millis(50),
    }
}

fn report() -> Option<AgentToServer> {
    Some(AgentToServer {
        instance_uid: vec![7; 16],
        sequence_num: 1,
        ..Default::default()
    })
}

/// The probe proves a connection over either transport with the trust, the identity and the
/// credential the description names — and fails without the identity the server asks for.
/// Verifies: ADR-0010
#[tokio::test]
async fn the_probe_connects_with_the_described_material_on_both_transports() {
    let pki = Pki::new();
    let port = serve(&pki);
    for scheme in ["wss", "https"] {
        let endpoint = format!("{scheme}://localhost:{port}/v1/opamp");
        let with = connection(endpoint.clone(), &pki, Some(pki.issue("agent")));
        opamp::client::connection::probe(&with, report)
            .await
            .unwrap_or_else(|e| panic!("{scheme}: {e}"));
        let without = connection(endpoint, &pki, None);
        assert!(
            opamp::client::connection::probe(&without, report)
                .await
                .is_err(),
            "{scheme}: a connection without the client certificate was admitted"
        );
    }
}

/// An OpAMP endpoint never legitimately redirects, so the client does not follow one.
/// Verifies: ADR-0010
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let pki = Pki::new();
    let port = serve(&pki);
    let moved = connection(
        format!("https://localhost:{port}/moved"),
        &pki,
        Some(pki.issue("agent")),
    );
    let error = opamp::client::connection::probe(&moved, report)
        .await
        .expect_err("a redirect is a failure");
    assert!(error.contains("307"), "{error}");
}

/// One report, then the session ends the run.
#[derive(Default)]
struct Once {
    replies: usize,
}

impl Session for Once {
    fn connected(&mut self) -> Vec<AgentToServer> {
        report().into_iter().collect()
    }
    fn routine(&mut self) -> Vec<AgentToServer> {
        Vec::new()
    }
    fn owed(&mut self) -> Vec<AgentToServer> {
        Vec::new()
    }
    fn on_reply(&mut self, _: &ServerToAgent) -> Option<Duration> {
        self.replies += 1;
        None
    }
    async fn after_reply<S: ReportSink>(&mut self, _: &mut S) -> AfterReply {
        AfterReply::End
    }
    async fn changed(&mut self) {
        std::future::pending::<()>().await;
    }
    fn exchange_failed(&mut self) {}
    async fn stop(&mut self) {}
    fn goodbyes(&mut self) -> Vec<AgentToServer> {
        Vec::new()
    }
}

struct Never;

impl StopSignal for Never {
    fn requested(&mut self) -> impl std::future::Future<Output = ()> + Send {
        std::future::pending()
    }
}

/// `run` picks the transport by scheme and carries a session over it.
#[tokio::test]
async fn a_run_carries_the_session_over_the_transport_the_scheme_names() {
    let pki = Pki::new();
    let port = serve(&pki);
    for scheme in ["wss", "https"] {
        let described = connection(
            format!("{scheme}://localhost:{port}/v1/opamp"),
            &pki,
            Some(pki.issue("agent")),
        );
        let mut session = Once::default();
        let ended = tokio::time::timeout(
            Duration::from_secs(10),
            opamp::client::connection::run(&described, &mut session, &mut Never),
        )
        .await
        .expect("within the bound")
        .expect("run");
        assert_eq!(ended, Ended::End, "{scheme}");
        assert!(
            session.replies >= 1,
            "{scheme}: no reply reached the session"
        );
    }
}

/// A server that speaks TLS 1.2 alone never completes the handshake with this client, on either
/// transport: the client offers TLS 1.3 and nothing older. The server is built from the full ring
/// provider, so the refusal is the client's.
/// Verifies: ADR-0013, Q-3
#[tokio::test]
async fn a_tls12_only_server_fails_the_handshake() {
    opamp::tls::install_ring_provider();
    let pki = Pki::new();
    let identity = pki.issue("localhost");
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .expect("tls 1.2")
    .with_no_client_auth()
    .with_single_cert(
        opamp::tls::certificates(&identity.cert_pem).expect("cert"),
        opamp::tls::private_key(&identity.key_pem).expect("key"),
    )
    .expect("server config");
    let router = opamp::server::router(Arc::new(Gate), Settings::new(4096));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(
        Listener::new(listener, Handle::new())
            .with_tls(Arc::new(tls))
            .serve(router),
    );
    for scheme in ["wss", "https"] {
        let described = connection(
            format!("{scheme}://localhost:{port}/v1/opamp"),
            &pki,
            Some(pki.issue("agent")),
        );
        let error = opamp::client::connection::probe(&described, report)
            .await
            .expect_err("a TLS 1.2 server was reached");
        assert!(error.starts_with("cannot reach"), "{scheme}: {error}");
    }
}
