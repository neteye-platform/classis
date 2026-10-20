//! A Gateway refuses what its Server revoked, end to end (ADR-0015 clause 14, ADR-0021 clause 43):
//! the real Server on mutual TLS with its register, the real Gateway fetching the list from it,
//! and a downstream peer whose certificate the Server revokes.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fleet_agent::config::ClientConfig;
use fleet_agent::gateway::Timings;
use fleet_agent::shutdown::shutdown_channel;
use fleet_server::fleet::AppState;
use fleet_server::revocation::Revocations;
use futures_util::StreamExt as _;
use opamp::proto::AgentToServer;
use opamp::uid::InstanceUid;
use prost::Message as _;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const REFRESH: Duration = Duration::from_millis(200);
const MAX_AGE: Duration = Duration::from_secs(2);

/// The fleet's client CA, which also issues the listeners' certificates here.
struct Ca {
    pem: String,
    key_pem: String,
}

impl Ca {
    fn new(dir: &Path) -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "gateway test CA");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        let ca = Ca {
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
        };
        std::fs::write(dir.join("ca.pem"), &ca.pem).expect("write");
        std::fs::write(dir.join("ca-key.pem"), &ca.key_pem).expect("write");
        ca
    }

    /// A leaf for `name`, written as `<file>.pem` and `<file>-key.pem`; returns the certificate.
    fn issue(&self, dir: &Path, file: &str, name: &str) -> String {
        let issuer =
            Issuer::from_ca_cert_pem(&self.pem, KeyPair::from_pem(&self.key_pem).expect("ca key"))
                .expect("issuer");
        let key = KeyPair::generate().expect("key");
        let cert = CertificateParams::new(vec![name.to_string()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("signed");
        std::fs::write(dir.join(format!("{file}.pem")), cert.pem()).expect("write");
        std::fs::write(dir.join(format!("{file}-key.pem")), key.serialize_pem()).expect("write");
        cert.pem()
    }
}

/// The Server, the Gateway in front of it, and what a test needs of both.
struct Fleet {
    dir: tempfile::TempDir,
    ca: Ca,
    revocations: Arc<Revocations>,
    gateway_host: String,
    gateway: std::net::SocketAddr,
    _stop: tokio::sync::watch::Sender<bool>,
}

impl Fleet {
    async fn start(mark: bool) -> Self {
        Fleet::start_with(mark, None).await
    }

    /// The same, with the Server's rate limit on the Agent plane armed (ADR-0013).
    async fn start_with(mark: bool, agent_rate: Option<fleet_server::agent_rate::Limits>) -> Self {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = dir.path();
        let ca = Ca::new(pki);
        ca.issue(pki, "server", "127.0.0.1");
        ca.issue(pki, "gateway-listener", "127.0.0.1");

        let clock: Arc<dyn fleet_server::fleet::Clock> = Arc::new(fleet_server::clock::SystemClock);
        let der = opamp::tls::certificates(ca.pem.as_bytes()).expect("pem");
        let facts = fleet_server::ca::facts(der[0].as_ref()).expect("facts");
        let revocations = Arc::new(
            Revocations::open(
                Box::new(
                    fleet_server::fs::FsLedgerStore::open(&pki.join("fleet-configs"))
                        .expect("ledger"),
                ),
                clock.clone(),
                vec![fleet_server::revocation::Authority {
                    role: "client".to_string(),
                    subject: facts.id.issuer,
                    name: facts.issuer_name,
                }],
            )
            .expect("revocations"),
        );
        let signer = fleet_server::ca::ClientCa::from_config(
            &toml::from_str::<fleet_server::config::ClientCaConfig>(&format!(
                "cert_file = {:?}\nkey_file = {:?}\n",
                pki.join("ca.pem").display().to_string(),
                pki.join("ca-key.pem").display().to_string(),
            ))
            .expect("client_ca config"),
        )
        .expect("client ca");

        // The Gateway's own certificate, issued by the Server so that it names a host.
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
        if mark {
            assert!(revocations.set_gateway(&gateway_host, true).expect("mark"));
        }

        let state = Arc::new(
            AppState::new(pki.join("fleet-configs"))
                .expect("state")
                .with_client_ca(Some(signer))
                .with_revocations(Some(revocations.clone()))
                .with_agent_rate(agent_rate.map(|limits| {
                    Arc::new(fleet_server::agent_rate::AgentRate::new(limits, 100, clock))
                })),
        );
        let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
            "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
            pki.join("server.pem").display().to_string(),
            pki.join("server-key.pem").display().to_string(),
            pki.join("ca.pem").display().to_string(),
        ))
        .expect("tls config");
        let planes = fleet_server::tls::server_tls(&tls, None, None).expect("server material");
        let admission = fleet_server::transport::Admission::new(true)
            .with_enrolment(planes.issuers, None)
            .with_revocations(Some(revocations.clone()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = listener.local_addr().expect("addr");
        tokio::spawn(
            opamp::server::listen::Listener::new(listener, opamp::server::listen::Handle::new())
                .with_tls(planes.agent.rustls_config().expect("agent plane"))
                .serve(fleet_server::agent_app(state, admission)),
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let gateway = listener.local_addr().expect("addr");
        let path = |file: &str| pki.join(file).display().to_string();
        let config: ClientConfig = toml::from_str(&format!(
            r#"
            endpoint = "wss://{server}/v1/opamp"
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
            "#,
            path("ca.pem"),
            path("gateway-cert.pem"),
            path("gateway-cert-key.pem"),
            path("gateway-listener.pem"),
            path("gateway-listener-key.pem"),
            path("ca.pem"),
        ))
        .expect("gateway config");
        let (stop, shutdown) = shutdown_channel();
        let timings = Timings {
            revocation_refresh: REFRESH,
            revocation_max_age: MAX_AGE,
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
            ca,
            revocations,
            gateway_host,
            gateway,
            _stop: stop,
        }
    }

    /// A downstream peer's certificate and key, and its serial as the register names it.
    fn peer(&self, name: &str) -> (String, String, String) {
        let cert = self.ca.issue(self.dir.path(), name, name);
        let key =
            std::fs::read_to_string(self.dir.path().join(format!("{name}-key.pem"))).expect("key");
        let der = opamp::tls::certificates(cert.as_bytes()).expect("pem");
        let serial = fleet_server::ca::facts(der[0].as_ref())
            .expect("facts")
            .id
            .serial;
        (cert, key, serial)
    }

    /// One plain-HTTP report through the Gateway as the peer `(cert, key)`; the status it gets.
    async fn post(&self, cert: &str, key: &str) -> reqwest::StatusCode {
        let mut pem = key.as_bytes().to_vec();
        pem.extend_from_slice(cert.as_bytes());
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([reqwest::Certificate::from_pem(self.ca.pem.as_bytes()).expect("ca")])
            .identity(reqwest::Identity::from_pem(&pem).expect("identity"))
            .build()
            .expect("client");
        let report = AgentToServer {
            instance_uid: InstanceUid::default().as_bytes().to_vec(),
            sequence_num: 1,
            ..Default::default()
        };
        client
            .post(format!("https://{}/v1/opamp", self.gateway))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(report.encode_to_vec())
            .send()
            .await
            .expect("send")
            .status()
    }

    /// One plain-HTTP report for `uid` through the Gateway as the peer `(cert, key)`, and the reply
    /// the Gateway hands back.
    async fn exchange(
        &self,
        cert: &str,
        key: &str,
        uid: &InstanceUid,
        sequence_num: u64,
    ) -> opamp::proto::ServerToAgent {
        let mut pem = key.as_bytes().to_vec();
        pem.extend_from_slice(cert.as_bytes());
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([reqwest::Certificate::from_pem(self.ca.pem.as_bytes()).expect("ca")])
            .identity(reqwest::Identity::from_pem(&pem).expect("identity"))
            .build()
            .expect("client");
        let report = AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            sequence_num,
            ..Default::default()
        };
        let response = client
            .post(format!("https://{}/v1/opamp", self.gateway))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(report.encode_to_vec())
            .send()
            .await
            .expect("send");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        opamp::proto::ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode")
    }

    /// A WebSocket through the Gateway as the peer `(cert, key)`.
    async fn websocket(
        &self,
        cert: &str,
        key: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        self.try_websocket(cert, key)
            .await
            .expect("connect through the gateway")
    }

    /// The same, or the error the upgrade failed with.
    async fn try_websocket(
        &self,
        cert: &str,
        key: &str,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::Error,
    > {
        let config = opamp::tls::client_builder()
            .with_root_certificates(opamp::tls::root_store(self.ca.pem.as_bytes()).expect("roots"))
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
        tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))),
        )
        .await
        .map(|(socket, _)| socket)
    }
}

/// The close a socket receives within `within`, as its code and reason.
async fn closed_with(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    within: Duration,
) -> Option<(CloseCode, String)> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, socket.next()).await {
            Ok(Some(Ok(WsMessage::Close(Some(frame))))) => {
                return Some((frame.code, frame.reason.to_string()))
            }
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

/// A certificate the Server revokes is refused behind the Gateway within one refresh, and the
/// session it holds there is closed with `1008` and the reason `revoked`; another is unaffected.
/// Verifies: ADR-0015, ADR-0021, G-15
#[tokio::test]
async fn a_certificate_the_server_revokes_is_refused_behind_the_gateway() {
    let fleet = Fleet::start(true).await;
    let (cert, key, serial) = fleet.peer("edge-revoked");
    let (other_cert, other_key, _) = fleet.peer("edge-kept");
    assert_eq!(fleet.post(&cert, &key).await, reqwest::StatusCode::OK);
    let mut socket = fleet.websocket(&cert, &key).await;

    let revocation = fleet
        .revocations
        .revoke_certificate("client", &serial)
        .expect("revoke");
    let closed = closed_with(&mut socket, REFRESH * 10).await;
    assert_eq!(closed, Some((CloseCode::Policy, "revoked".to_string())));
    assert_eq!(
        fleet.post(&cert, &key).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
    match fleet.try_websocket(&cert, &key).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 401);
        }
        other => panic!("a revoked certificate upgraded: {:?}", other.map(|_| ())),
    }
    assert_eq!(
        fleet.post(&other_cert, &other_key).await,
        reqwest::StatusCode::OK
    );

    // Lifted, it is admitted again within a refresh.
    assert!(fleet.revocations.lift(&revocation.id).expect("lift"));
    let mut status = reqwest::StatusCode::UNAUTHORIZED;
    for _ in 0..20 {
        status = fleet.post(&cert, &key).await;
        if status == reqwest::StatusCode::OK {
            break;
        }
        tokio::time::sleep(REFRESH / 2).await;
    }
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "a lifted revocation is still refused"
    );
}

/// A Gateway whose host the operator has not marked is handed no list, and so admits nobody.
/// Verifies: ADR-0015, ADR-0021
#[tokio::test]
async fn an_unmarked_gateway_admits_nobody() {
    let fleet = Fleet::start(false).await;
    let (cert, key, _) = fleet.peer("edge");
    assert_eq!(
        fleet.post(&cert, &key).await,
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
}

/// A Gateway that cannot renew its list for longer than the maximum age admits nobody, and ends
/// the sessions it holds with `1008` and the reason `revocation list stale`.
/// Verifies: ADR-0015
#[tokio::test]
async fn a_gateway_whose_list_goes_stale_admits_nobody() {
    let fleet = Fleet::start(true).await;
    let (cert, key, _) = fleet.peer("edge");
    let mut socket = fleet.websocket(&cert, &key).await;
    assert!(fleet
        .revocations
        .set_gateway(&fleet.gateway_host, false)
        .expect("unmark"));
    let closed = closed_with(&mut socket, MAX_AGE + REFRESH * 10).await;
    assert_eq!(
        closed,
        Some((CloseCode::Policy, "revocation list stale".to_string()))
    );
    assert_eq!(
        fleet.post(&cert, &key).await,
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
}

/// Two Agents ride the Gateway's folded connection to the Server, and one floods. Only it is told
/// `Unavailable`, routed back to it by its `instance_uid`; its neighbour's reports keep being
/// processed, because behind a marked Gateway each Agent has a bucket of its own inside the
/// Gateway's aggregate.
/// Verifies: ADR-0013, ADR-0015
#[tokio::test]
async fn a_throttled_agent_behind_a_gateway_hears_unavailable_and_its_neighbour_does_not() {
    let unavailable = |reply: &opamp::proto::ServerToAgent| {
        reply.error_response.as_ref().is_some_and(|error| {
            error.r#type == opamp::proto::ServerErrorResponseType::Unavailable as i32
        })
    };
    let fleet = Fleet::start_with(
        true,
        Some(fleet_server::agent_rate::Limits {
            messages_per_sec: 1,
            burst: 3,
            gateway_messages_per_sec: 1_000,
            gateway_burst: 1_000,
        }),
    )
    .await;
    let (cert, key, _) = fleet.peer("edge");
    let (flooding, neighbour) = (InstanceUid::default(), InstanceUid::default());

    let mut throttled = 0;
    for sequence in 1..=20 {
        let reply = fleet.exchange(&cert, &key, &flooding, sequence).await;
        assert_eq!(
            reply.instance_uid,
            flooding.as_bytes(),
            "routed to the sender"
        );
        if unavailable(&reply) {
            throttled += 1;
        }
    }
    assert!(
        throttled > 0,
        "twenty messages at once passed a burst of three"
    );

    for sequence in 1..=2 {
        let reply = fleet.exchange(&cert, &key, &neighbour, sequence).await;
        assert_eq!(reply.instance_uid, neighbour.as_bytes());
        assert!(
            reply.error_response.is_none(),
            "the neighbour was throttled: {:?}",
            reply.error_response
        );
    }
}
