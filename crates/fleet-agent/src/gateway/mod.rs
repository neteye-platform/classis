//! Gateway Mode (ADR-0015): the Client at a network boundary.
//!
//! It is an OpAMP **server** downstream and an OpAMP **client** upstream, and it folds many
//! downstream connections onto a small pool of upstream ones. What it does *not* do is as
//! load-bearing as what it does: it forwards messages unchanged, holds no admission policy of its
//! own — the one admission refusal beyond its handshake is a certificate its Server revoked
//! ([`revocations`]); beyond admission it refuses a report for another host's Agent
//! ([`registry`]), anything but one plain-HTTP enrolment request from an enrolling peer
//! ([`Members`]), and a download the Server did not offer to the requesting host through this
//! Gateway ([`cache`]) — forwards no `Authorization`, and
//! never speaks in an Agent's name, not even to say the goodbye a vanished Agent did not send.
//!
//! The pieces: this module serves the downstream endpoint on both transports (a downstream Client
//! picks its transport by URL scheme, so serving only one would silently exclude half of them),
//! [`pool`] holds the upstream connections, [`registry`] routes replies back by `instance_uid`, and
//! [`cache`] holds the uploaded artifacts the Gateway relays offers of and serves them on the
//! download route to the hosts they were offered to (ADR-0026).
//! The endpoint's communication is `opamp::server`'s, the one the Server sits on too (ADR-0010);
//! what is the Gateway's is the [`Forwarding`] handler behind it.

pub mod cache;
pub mod policy;
pub mod pool;
pub mod registry;
pub mod revocations;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::http::{header, StatusCode};
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::listen::{
    ClientAuth, Handle, Listener, PeerCertificate, ServerTls, HEADER_READ_TIMEOUT,
};
use opamp::server::{
    Closing, Handler, Outbound, Rejection, Reply, RequestInfo, Settings, Transport, Unreadable,
};
use opamp::tls::Identity;
use opamp::uid::InstanceUid;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::config::{ClientConfig, GatewayTlsConfig};
use crate::shutdown::Shutdown;
use pool::Pool;
use registry::Registry;
use revocations::{
    RevocationList, Verdict, REVOCATION_FIRST_WAIT, REVOCATION_MAX_AGE, REVOCATION_REFRESH,
};

/// How long the downstream endpoint has to drain in-flight exchanges once shutdown is requested,
/// before connections are dropped. One [`EXCHANGE_TIMEOUT`] plus a little, so an exchange already
/// waiting on the Server is not cut short by the stop it did not cause.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(35);

/// How long a plain-HTTP peer waits for its reply to come back through the pool. Beyond this the
/// exchange fails and the peer retries, which is what its transport already does on any error.
const EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The Gateway's handler behind the downstream endpoint: what arrives goes upstream, what the
/// Server says comes back down.
struct Forwarding {
    pool: Pool,
    registry: Arc<Registry>,
    /// The most distinct Agents one downstream connection may carry (ADR-0015): past it a report
    /// for a *new* Agent is dropped, so a single peer cannot grow the routing state without bound.
    max_agents: usize,
    /// What the Server revoked, which this Gateway refuses (ADR-0015 clause 14).
    revocations: RevocationList,
    /// Tells a member from an enrolling peer (ADR-0039 clause 4).
    members: Members,
}

/// What tells a downstream member from an **enrolling peer** (ADR-0039 clause 4). Without
/// `bootstrap_ca_file` the handshake trusts the client CA alone, so every peer that passed it is a
/// member. With it, a member is a peer whose certificate a CA of `client_ca_file` issued directly —
/// named as its issuer and signed with its key, as the Server tells the two apart — and any other
/// peer that passed the handshake chains to the bootstrap CA alone: it is enrolling.
#[derive(Clone, Default)]
pub struct Members {
    /// The CAs of `client_ca_file`, while a bootstrap CA is trusted too.
    client_cas: Option<Arc<Vec<Ca>>>,
}

/// One CA certificate of a PEM file, as far as it is read: its subject (DER and text) and its
/// `SubjectPublicKeyInfo` (DER).
struct Ca {
    subject: Vec<u8>,
    key: Vec<u8>,
    name: String,
}

impl Members {
    /// Whether the peer presenting `certificate` (DER, verified by the handshake) is enrolling.
    #[must_use]
    pub fn enrolling(&self, certificate: &[u8]) -> bool {
        use x509_parser::prelude::{FromDer as _, SubjectPublicKeyInfo};
        let Some(cas) = &self.client_cas else {
            return false;
        };
        // One the handshake verified always parses; one that does not is no member.
        let Ok((_, parsed)) = x509_parser::parse_x509_certificate(certificate) else {
            return true;
        };
        !cas.iter().any(|ca| {
            parsed.issuer().as_raw() == ca.subject.as_slice()
                && SubjectPublicKeyInfo::from_der(&ca.key)
                    .is_ok_and(|(_, key)| parsed.verify_signature(Some(&key)).is_ok())
        })
    }
}

/// Why a plain-HTTP report of an enrolling peer is not forwarded, or `None` when it is the one
/// thing an enrolling peer sends (ADR-0039 clause 11): its identity, its sequence number and
/// capabilities, and a certificate signing request carrying a bootstrap proof (ADR-0039 clause 7)
/// — nothing a member reports, no description, health, effective configuration, configuration
/// status, package statuses, components, connection-settings status, flags, goodbye or custom
/// message — whose proof embeds, byte for byte, the certificate `presented` the peer presented in
/// the handshake, so that a peer spends no other certificate's share at the Server. The Gateway
/// does not check the proof's signature: the Server does.
fn not_an_enrolment(report: &AgentToServer, presented: &[u8]) -> Option<&'static str> {
    use opamp::proto::{
        CertificateRequest, ConnectionSettingsRequest, OpAmpConnectionSettingsRequest,
    };
    let Some(csr) = report
        .connection_settings_request
        .as_ref()
        .and_then(|request| request.opamp.as_ref())
        .and_then(|opamp| opamp.certificate_request.as_ref())
    else {
        return Some("an enrolling peer sends a certificate signing request and nothing else");
    };
    let only = AgentToServer {
        instance_uid: report.instance_uid.clone(),
        sequence_num: report.sequence_num,
        capabilities: report.capabilities,
        connection_settings_request: Some(ConnectionSettingsRequest {
            opamp: Some(OpAmpConnectionSettingsRequest {
                certificate_request: Some(CertificateRequest {
                    csr: csr.csr.clone(),
                }),
            }),
        }),
        ..AgentToServer::default()
    };
    if *report != only {
        return Some("an enrolling peer sends a certificate signing request and nothing else");
    }
    // Read as the Server reads it: one PEM block, nothing around it (ADR-0039).
    let Ok(Some(encoded)) = fleet_core::csr::der(&csr.csr).and_then(|der| {
        fleet_core::csr::requested_uri(&der, fleet_core::bootstrap_proof::URI_PREFIX)
    }) else {
        return Some("an enrolling peer's certificate signing request carries no bootstrap proof");
    };
    let content = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)
    };
    match content
        .ok()
        .as_deref()
        .and_then(fleet_core::bootstrap_proof::decode)
    {
        Some((certificate, _)) if certificate == presented => None,
        _ => Some("an enrolling peer's bootstrap proof does not name the certificate it presented"),
    }
}

/// The time bounds a Gateway runs with: the constants, unless a test drives them short.
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    pub header_read_timeout: std::time::Duration,
    pub revocation_refresh: std::time::Duration,
    pub revocation_max_age: std::time::Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Timings {
            header_read_timeout: HEADER_READ_TIMEOUT,
            revocation_refresh: REVOCATION_REFRESH,
            revocation_max_age: REVOCATION_MAX_AGE,
        }
    }
}

/// Serves the downstream endpoint until `shutdown` fires.
///
/// Mutual TLS is per hop (ADR-0039 clause 4): the downstream hop serves TLS 1.3 from
/// `[gateway.tls]`, and every downstream peer must present a certificate that chains to its
/// `client_ca_file`, or to its `bootstrap_ca_file` where one is named — the access-control boundary
/// of the hop. Downstream Agents travel upstream under this Gateway's own member certificate, so
/// `client_ca_file` must be the fleet's client CA and never a bootstrap CA; a peer of the bootstrap
/// CA may only relay an enrolment request.
///
/// # Errors
/// Returns an error when the configured address cannot be bound — at startup, so a taken port is
/// loud rather than a Gateway that quietly carries nobody — or when the TLS material cannot be read.
pub async fn run(config: Arc<ClientConfig>, shutdown: Shutdown) -> Result<(), String> {
    let Some(gateway) = &config.gateway else {
        return Ok(());
    };
    let listen = gateway.listen;
    let listener = std::net::TcpListener::bind(listen)
        .map_err(|e| format!("cannot bind the gateway endpoint {listen}: {e}"))?;
    run_on(config, listener, shutdown).await
}

/// Serves the downstream endpoint on a listener that is already bound, until `shutdown` fires —
/// what [`run`] does once it has bound the configured address. A caller that picks the port itself
/// binds first and hands the listener over, so the port cannot be taken in between.
///
/// # Errors
/// Returns an error when the listener cannot be used or the TLS material cannot be read.
pub async fn run_on(
    config: Arc<ClientConfig>,
    listener: std::net::TcpListener,
    shutdown: Shutdown,
) -> Result<(), String> {
    run_on_bounded(config, listener, shutdown, HEADER_READ_TIMEOUT).await
}

/// [`run_on`] with the header bound tightened — what a test waits out instead of the 30 seconds
/// every OpAMP listener applies (ADR-0010).
///
/// # Errors
/// As [`run_on`].
pub async fn run_on_bounded(
    config: Arc<ClientConfig>,
    listener: std::net::TcpListener,
    shutdown: Shutdown,
    header_read_timeout: std::time::Duration,
) -> Result<(), String> {
    let timings = Timings {
        header_read_timeout,
        ..Timings::default()
    };
    run_on_timed(config, listener, shutdown, timings).await
}

/// [`run_on`] with every time bound stated — what a test drives short.
///
/// # Errors
/// As [`run_on`].
pub async fn run_on_timed(
    config: Arc<ClientConfig>,
    listener: std::net::TcpListener,
    shutdown: Shutdown,
    timings: Timings,
) -> Result<(), String> {
    let header_read_timeout = timings.header_read_timeout;
    let Some(gateway) = &config.gateway else {
        return Ok(());
    };
    let listen = listener
        .local_addr()
        .map_err(|e| format!("cannot read the gateway endpoint's address: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot prepare the gateway endpoint {listen}: {e}"))?;
    let cache = cache::PackageCache::open(config.clone(), shutdown.clone()).await?;
    let registry = Arc::new(Registry::new(cache.clone()));
    let revocations = RevocationList::new(timings.revocation_max_age);
    // Its first peers are not refused for want of a list, nor kept waiting for a Server that does
    // not answer (ADR-0015 clause 14).
    let _ = tokio::time::timeout(
        REVOCATION_FIRST_WAIT,
        revocations::update(&revocations, &config),
    )
    .await;
    tokio::spawn(revocations::refresh(
        revocations.clone(),
        config.clone(),
        shutdown.clone(),
        timings.revocation_refresh,
    ));
    // Mutual TLS 1.3 and nothing less (ADR-0015); the load refused a Gateway without it.
    let tls = gateway
        .tls
        .as_ref()
        .ok_or("[gateway.tls] is required — a Gateway admits Agents over mutual TLS only")?;
    let (server_tls, members) = server_tls(tls)?;
    let downloads = Arc::new(cache::Downloads {
        cache,
        revocations: revocations.clone(),
        members: members.clone(),
    });
    let handler = Arc::new(Forwarding {
        pool: Pool::new(config.clone(), registry.clone()),
        registry,
        max_agents: gateway.max_carried_agents,
        revocations,
        members,
    });
    // The receive and send limits the Baseline requires, enforced per hop; beside the OpAMP
    // endpoint, the download route the Agents behind this Gateway resolve their offers against
    // (ADR-0026 clause 45).
    let app = opamp::server::router(handler, Settings::new(config.max_message_size_bytes))
        .merge(cache::router(downloads));

    let upstream_cap = gateway.upstream_connections;
    let config = server_tls
        .rustls_config()
        .map_err(|e| format!("the gateway endpoint: {e}"))?;
    let handle = Handle::new();
    let downstream = Listener::new(listener, handle.clone())
        .with_tls(config)
        .with_header_read_timeout(header_read_timeout);
    info!(%listen, upstream_cap, "gateway listening over mutual TLS");
    // The listener drains rather than drops: on shutdown in-flight exchanges finish, up to the
    // grace, instead of every downstream connection being torn down mid-message.
    let mut shutdown = shutdown;
    tokio::spawn(async move {
        shutdown.requested().await;
        handle.graceful_shutdown(Some(DRAIN_GRACE));
    });
    downstream
        .serve(app)
        .await
        .map_err(|e| format!("the gateway endpoint stopped: {e}"))
}

/// The material the downstream endpoint serves with (ADR-0039 clause 4), and what tells its members
/// from its enrolling peers: a client certificate that chains to `client_ca_file` — or, where
/// `bootstrap_ca_file` names one, to that bootstrap CA — is **mandatory** in the handshake. A CA in
/// both files could not be told apart, so it fails startup naming both keys.
fn server_tls(tls: &GatewayTlsConfig) -> Result<(ServerTls, Members), String> {
    let ca_file = tls
        .client_ca_file
        .as_ref()
        .ok_or("[gateway.tls] client_ca_file is required")?;
    let mut ca_pem = crate::tls::certificates_file(ca_file)?;
    let mut members = Members::default();
    if let Some(bootstrap_file) = &tls.bootstrap_ca_file {
        let bootstrap_pem = crate::tls::certificates_file(bootstrap_file)?;
        let client_cas = cas_of(ca_file, &ca_pem)?;
        let bootstrap_cas = cas_of(bootstrap_file, &bootstrap_pem)?;
        if let Some(Ca { name, .. }) = bootstrap_cas
            .iter()
            .find(|ca| client_cas.iter().any(|other| other.subject == ca.subject))
        {
            return Err(format!(
                "[gateway.tls] client_ca_file {} and bootstrap_ca_file {} both hold the CA {name} — \
                 a bootstrap certificate must be told apart from a member's",
                ca_file.display(),
                bootstrap_file.display()
            ));
        }
        if !ca_pem.ends_with(b"\n") {
            ca_pem.push(b'\n');
        }
        ca_pem.extend_from_slice(&bootstrap_pem);
        members.client_cas = Some(Arc::new(client_cas));
    }
    Ok((
        ServerTls {
            identity: Identity {
                cert_pem: crate::tls::certificates_file(&tls.cert_file)?,
                key_pem: crate::tls::key_file(&tls.key_file)?,
            },
            client_auth: ClientAuth::Required { ca_pem },
        },
        members,
    ))
}

/// Each CA certificate of a PEM file.
fn cas_of(path: &std::path::Path, pem: &[u8]) -> Result<Vec<Ca>, String> {
    opamp::tls::certificates(pem)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .iter()
        .map(|der| {
            x509_parser::parse_x509_certificate(der.as_ref())
                .map(|(_, cert)| Ca {
                    subject: cert.subject().as_raw().to_vec(),
                    key: cert.public_key().raw.to_vec(),
                    name: cert.subject().to_string(),
                })
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))
        })
        .collect()
}

/// One downstream connection: a socket, or one plain-HTTP exchange.
struct Downstream {
    transport: Transport,
    peer: String,
    /// Where the registry routes this socket's replies; `None` on plain HTTP, whose one reply
    /// comes back through a `oneshot` instead.
    replies: Option<mpsc::Sender<ServerToAgent>>,
    /// Every Agent this peer turned out to carry, so all of them are released when it goes. A set,
    /// not a list: membership is checked per report, and the cap bounds how large it grows.
    carried: HashSet<InstanceUid>,
    /// Why the socket was ended from this side, for its close frame (ADR-0015 clause 14).
    ended: Arc<Mutex<Option<&'static str>>>,
    /// The certificate it was admitted with, which every report is judged by again.
    certificate: Vec<u8>,
    /// The host that certificate names, which the offers relayed over it are recorded for
    /// (ADR-0039 clause 6).
    host: Option<String>,
    /// The host that certificate speaks as, which the `instance_uid`s it reports for are bound to
    /// (ADR-0039 clause 6): the one it names, else the one the Server derives for it.
    speaker: String,
    /// The certificate chains to the bootstrap CA alone (ADR-0039 clause 4): this peer may relay
    /// one enrolment request and nothing else, and binds nothing.
    enrolling: bool,
}

/// Releases a plain-HTTP exchange's route when the exchange ends, unless its reply took it.
struct Abandon<'a> {
    registry: &'a Registry,
    uid: InstanceUid,
    exchange: u64,
}

impl Drop for Abandon<'_> {
    fn drop(&mut self) {
        self.registry.abandon(self.uid, self.exchange);
    }
}

/// Releases an enrolling peer's place on the upstream connections when its exchange ends.
struct Release<'a> {
    pool: &'a Pool,
    uid: InstanceUid,
}

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.pool.release([self.uid]);
    }
}

/// What the Server says about the Agents a socket carries, routed back to it by the registry —
/// until the revocation list no longer admits the certificate the socket was opened with.
struct Replies {
    replies: mpsc::Receiver<ServerToAgent>,
    revocations: RevocationList,
    changes: tokio::sync::watch::Receiver<u64>,
    certificate: Vec<u8>,
    ended: Arc<Mutex<Option<&'static str>>>,
}

impl Outbound for Replies {
    type Item = ServerToAgent;

    async fn next(&mut self) -> Option<ServerToAgent> {
        loop {
            tokio::select! {
                reply = self.replies.recv() => return reply,
                changed = self.changes.changed() => {
                    if changed.is_err() {
                        return self.replies.recv().await;
                    }
                    if let Some(reason) = self.revocations.verdict(&self.certificate).reason() {
                        info!(reason, "ending a downstream session");
                        *self.ended.lock().expect("ended lock") = Some(reason);
                        return None;
                    }
                }
            }
        }
    }
}

impl Handler for Forwarding {
    type Connection = Downstream;
    type Outbound = Replies;

    fn on_connecting(
        &self,
        request: &RequestInfo<'_>,
    ) -> Result<(Downstream, Option<Replies>), Rejection> {
        // The one admission refusal beyond the handshake, and it is the Server's (ADR-0015 clause 14).
        let certificate = request
            .extensions
            .get::<PeerCertificate>()
            .and_then(|peer| peer.0.as_ref())
            .map(|cert| cert.as_ref().to_vec())
            .unwrap_or_default();
        match self.revocations.verdict(&certificate) {
            Verdict::Admit => {}
            Verdict::Revoked => {
                return Err(Rejection {
                    status: StatusCode::UNAUTHORIZED,
                    headers: Vec::new(),
                    message: "this certificate is revoked".to_string(),
                })
            }
            Verdict::Stale => {
                return Err(Rejection {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    headers: vec![(header::RETRY_AFTER, header::HeaderValue::from_static("30"))],
                    message: "the Gateway holds no current revocation list".to_string(),
                })
            }
        }
        // A certificate the revocation list could judge can be read, so this refuses nothing the
        // handshake and the list admitted; it only gives the binding its host (ADR-0039 clause 6).
        let Some(speaker) = cache::speaker_of(&certificate) else {
            return Err(Rejection {
                status: StatusCode::UNAUTHORIZED,
                headers: Vec::new(),
                message: "this certificate cannot be read".to_string(),
            });
        };
        // An `Authorization` the peer sends is ignored, never refused, and nothing is forwarded in
        // its place (ADR-0015 clause 11).
        let peer = request
            .peer
            .map_or_else(|| "unknown".to_string(), |peer| peer.to_string());
        let enrolling = self.members.enrolling(&certificate);
        if enrolling && request.transport == Transport::WebSocket {
            let why = "an enrolment through a Gateway is a plain-HTTP exchange";
            self.registry
                .cache()
                .log_enrolment_refusal(&speaker, &peer, why);
            return Err(Rejection {
                status: StatusCode::FORBIDDEN,
                headers: Vec::new(),
                message: why.to_string(),
            });
        }
        let ended = Arc::new(Mutex::new(None));
        let (replies, outbound) = match request.transport {
            Transport::WebSocket => {
                debug!(%peer, "a downstream client connected");
                let (tx, rx) = mpsc::channel::<ServerToAgent>(64);
                let mut changes = self.revocations.subscribe();
                changes.mark_unchanged();
                (
                    Some(tx),
                    Some(Replies {
                        replies: rx,
                        revocations: self.revocations.clone(),
                        changes,
                        certificate: certificate.clone(),
                        ended: ended.clone(),
                    }),
                )
            }
            Transport::Http => (None, None),
        };
        Ok((
            Downstream {
                transport: request.transport,
                peer,
                replies,
                carried: HashSet::new(),
                ended,
                // An enrolling peer is offered nothing, so nothing is recorded for its host.
                host: (!enrolling).then(|| cache::host_of(&certificate)).flatten(),
                speaker,
                certificate,
                enrolling,
            },
            outbound,
        ))
    }

    fn closing(&self, downstream: &Downstream) -> Option<Closing> {
        (*downstream.ended.lock().expect("ended lock")).map(Closing::policy)
    }

    async fn on_message(&self, downstream: &mut Downstream, report: AgentToServer) -> Reply {
        match downstream.transport {
            Transport::WebSocket => self.forward_from_socket(downstream, report).await,
            Transport::Http if downstream.enrolling => {
                self.forward_enrolment(downstream, report).await
            }
            Transport::Http => self.forward_exchange(downstream, report).await,
        }
    }

    fn on_outbound(&self, _: &mut Downstream, reply: ServerToAgent) -> Vec<ServerToAgent> {
        vec![reply]
    }

    /// An unreadable report is dropped, never answered: the Gateway invents nothing (ADR-0015). A
    /// plain-HTTP exchange still needs a response, and it says why.
    fn on_unreadable(&self, downstream: &mut Downstream, error: &Unreadable) -> Reply {
        warn!(peer = %downstream.peer, %error, "dropping an unreadable downstream report");
        match downstream.transport {
            Transport::WebSocket => Reply::Nothing,
            Transport::Http => Reply::Refuse(StatusCode::BAD_REQUEST, "unreadable report".into()),
        }
    }

    /// The peer is gone. Its Agents stop being routable here — and nothing is said upstream on
    /// their behalf, because they said nothing (ADR-0015 clause 10).
    fn on_closed(&self, downstream: Downstream) {
        if let Some(replies) = &downstream.replies {
            let count = downstream.carried.len();
            self.registry
                .detach_all(downstream.carried.iter().copied(), replies);
            self.pool.release(downstream.carried);
            debug!(peer = %downstream.peer, agents = count, "a downstream client disconnected");
        }
    }
}

impl Forwarding {
    /// A socket's report goes upstream; whatever the Server answers comes back through the
    /// registry, so nothing is replied here.
    async fn forward_from_socket(
        &self,
        downstream: &mut Downstream,
        report: AgentToServer,
    ) -> Reply {
        let peer = &downstream.peer;
        // A session the list no longer admits is being closed; what it still sends goes nowhere.
        if self.revocations.verdict(&downstream.certificate) != Verdict::Admit {
            return Reply::Nothing;
        }
        let Some(uid) = InstanceUid::from_wire(&report.instance_uid) else {
            warn!(%peer, "dropping a downstream report with a malformed instance_uid");
            return Reply::Nothing;
        };
        let carried = downstream.carried.contains(&uid);
        // Bound the routing state one connection can create: past the cap a report for a new
        // Agent is dropped, while the Agents already carried keep being served.
        if !carried && downstream.carried.len() >= self.max_agents {
            warn!(
                %peer, agent = %uid, cap = self.max_agents,
                "a downstream connection reached its Agent cap; dropping a report for a new Agent"
            );
            return Reply::Nothing;
        }
        // Forwarded only for an `instance_uid` bound to the host that sent it; the binding logs
        // a refusal (ADR-0039 clause 5).
        let Some(replies) = &downstream.replies else {
            return Reply::Nothing;
        };
        if !self.registry.attach(
            uid,
            replies.clone(),
            downstream.host.clone(),
            &downstream.speaker,
        ) {
            return Reply::Nothing;
        }
        if !carried {
            downstream.carried.insert(uid);
            info!(agent = %uid, %peer, "carrying an Agent");
        }
        if let Err(e) = self.pool.forward(uid, &report).await {
            warn!(agent = %uid, error = %e, "cannot forward a report upstream");
        }
        Reply::Nothing
    }

    /// An enrolling peer's one report (ADR-0039 clauses 5, 11): forwarded only when it is an
    /// enrolment request and nothing else, binding nothing, its exchange its route for its one
    /// reply. Any other report is answered `403` and logged.
    async fn forward_enrolment(&self, downstream: &Downstream, report: AgentToServer) -> Reply {
        let refuse = |why: &str| {
            self.registry
                .cache()
                .log_enrolment_refusal(&downstream.speaker, &downstream.peer, why);
            Reply::Refuse(StatusCode::FORBIDDEN, why.to_string())
        };
        if self.revocations.verdict(&downstream.certificate) != Verdict::Admit {
            return Reply::Refuse(
                StatusCode::UNAUTHORIZED,
                "this certificate is revoked".into(),
            );
        }
        let Some(uid) = InstanceUid::from_wire(&report.instance_uid) else {
            return Reply::Refuse(
                StatusCode::BAD_REQUEST,
                "instance_uid must be 16 bytes".into(),
            );
        };
        if let Some(why) = not_an_enrolment(&report, &downstream.certificate) {
            return refuse(why);
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let Some(exchange) = self.registry.expect_enrolment(uid, reply_tx) else {
            return refuse("this instance_uid is not this host's to report for");
        };
        // However the exchange ends, its route goes first and then its place upstream: an
        // enrolling peer is carried for one reply.
        let _place = Release {
            pool: &self.pool,
            uid,
        };
        let _route = Abandon {
            registry: &self.registry,
            uid,
            exchange,
        };
        if let Err(e) = self.pool.forward(uid, &report).await {
            warn!(agent = %uid, error = %e, "cannot forward an enrolment request upstream");
            return Reply::Refuse(StatusCode::BAD_GATEWAY, "cannot reach the Server".into());
        }
        match tokio::time::timeout(EXCHANGE_TIMEOUT, reply_rx).await {
            Ok(Ok(reply)) => Reply::Send(reply),
            _ => Reply::Refuse(
                StatusCode::GATEWAY_TIMEOUT,
                "no reply from the Server".into(),
            ),
        }
    }

    /// The plain-HTTP half: one report in, one reply out, with the pool in between.
    async fn forward_exchange(&self, downstream: &Downstream, report: AgentToServer) -> Reply {
        let Some(uid) = InstanceUid::from_wire(&report.instance_uid) else {
            return Reply::Refuse(
                StatusCode::BAD_REQUEST,
                "instance_uid must be 16 bytes".into(),
            );
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        // Forwarded only for an `instance_uid` bound to the host that sent it; the binding logs
        // a refusal (ADR-0039 clause 5).
        let Some(exchange) =
            self.registry
                .expect_once(uid, reply_tx, downstream.host.clone(), &downstream.speaker)
        else {
            return Reply::Refuse(
                StatusCode::FORBIDDEN,
                "this instance_uid is not this host's to report for".into(),
            );
        };
        // However the exchange ends — no reply in time, no Server, or the peer gone — its route
        // goes with it.
        let _route = Abandon {
            registry: &self.registry,
            uid,
            exchange,
        };
        if let Err(e) = self.pool.forward(uid, &report).await {
            warn!(agent = %uid, error = %e, "cannot forward a report upstream");
            return Reply::Refuse(StatusCode::BAD_GATEWAY, "cannot reach the Server".into());
        }
        match tokio::time::timeout(EXCHANGE_TIMEOUT, reply_rx).await {
            Ok(Ok(reply)) => Reply::Send(reply),
            _ => {
                debug!(agent = %uid, "no reply came back for a forwarded report");
                Reply::Refuse(
                    StatusCode::GATEWAY_TIMEOUT,
                    "no reply from the Server".into(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Server that takes every report and answers none.
    async fn silent_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use futures_util::StreamExt;
                    if let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await {
                        while socket.next().await.is_some() {}
                    }
                });
            }
        });
        addr
    }

    /// A certificate that names no host: each one a host of its own.
    fn certificate() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("key");
        rcgen::CertificateParams::new(vec!["edge".into()])
            .expect("params")
            .self_signed(&key)
            .expect("cert")
            .der()
            .to_vec()
    }

    /// A certificate that names `host`, as one the Server issues does.
    fn certificate_naming(host: &str) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("urn:opamp-fleet:host:{host}")
                .try_into()
                .expect("uri"),
        ));
        params.self_signed(&key).expect("cert").der().to_vec()
    }

    /// A Gateway's handler in front of a silent upstream, with a fresh, empty revocation list.
    async fn forwarding(state: &std::path::Path) -> Forwarding {
        opamp::tls::install_ring_provider();
        let server = silent_upstream().await;
        let config: Arc<ClientConfig> = Arc::new(
            toml::from_str(&format!(
                "endpoint = \"ws://{server}/v1/opamp\"\nstate_dir = {:?}\n\
                 [gateway]\nlisten = \"127.0.0.1:9\"\nmax_carried_agents = 3\n",
                state.display().to_string()
            ))
            .expect("config"),
        );
        let (stop, shutdown) = crate::shutdown::shutdown_channel();
        std::mem::forget(stop);
        let cache = cache::PackageCache::open(config.clone(), shutdown)
            .await
            .expect("cache");
        let registry = Arc::new(Registry::new(cache));
        let revocations = RevocationList::new(REVOCATION_MAX_AGE);
        revocations.replace(HashSet::new(), None);
        Forwarding {
            pool: Pool::new(config, registry.clone()),
            registry,
            max_agents: 10,
            revocations,
            members: Members::default(),
        }
    }

    fn downstream(
        transport: Transport,
        replies: Option<mpsc::Sender<ServerToAgent>>,
        certificate: Vec<u8>,
    ) -> Downstream {
        Downstream {
            transport,
            peer: "test".to_string(),
            replies,
            carried: HashSet::new(),
            ended: Arc::default(),
            host: cache::host_of(&certificate),
            speaker: cache::speaker_of(&certificate).expect("a readable certificate"),
            certificate,
            enrolling: false,
        }
    }

    fn report(uid: InstanceUid) -> AgentToServer {
        AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    /// A peer that goes takes its Agents' places on the upstream connections with it, so a peer
    /// coming back under ever new `instance_uid`s grows nothing; an Agent another socket of the
    /// same host carries by then keeps its place and its route.
    /// Verifies: ADR-0015
    #[tokio::test]
    async fn the_agents_a_departed_peer_carried_are_released_from_the_pool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        let host = certificate();
        let (first_tx, _first_rx) = mpsc::channel(64);
        let mut first = downstream(Transport::WebSocket, Some(first_tx), host.clone());
        let uids: Vec<InstanceUid> = (0..3).map(|_| InstanceUid::default()).collect();
        for uid in &uids {
            forwarding
                .forward_from_socket(&mut first, report(*uid))
                .await;
        }
        let (second_tx, _second_rx) = mpsc::channel(64);
        let mut second = downstream(Transport::WebSocket, Some(second_tx), host);
        forwarding
            .forward_from_socket(&mut second, report(uids[0]))
            .await;
        assert_eq!(forwarding.pool.assignments().0.len(), 3);

        forwarding.on_closed(first);

        assert_eq!(
            forwarding.pool.assignments(),
            (HashSet::from([uids[0]]), 1),
            "only the Agent still carried keeps its place"
        );
        assert!(forwarding.registry.routes(&uids[0]), "and its route");
        assert!(!forwarding.registry.routes(&uids[1]));
    }

    /// A plain-HTTP exchange that ends without its reply leaves no route behind.
    /// Verifies: ADR-0015
    #[tokio::test]
    async fn an_exchange_that_ends_without_its_reply_leaves_no_route() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        let uid = InstanceUid::default();
        let peer = downstream(Transport::Http, None, certificate());

        let waited = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            forwarding.forward_exchange(&peer, report(uid)),
        )
        .await;

        assert!(waited.is_err(), "the silent upstream sent no reply");
        assert!(!forwarding.registry.routes(&uid), "the route is gone");
    }

    /// A reply for `uid`, as the Server would send one.
    fn reply_for(uid: InstanceUid) -> ServerToAgent {
        ServerToAgent {
            instance_uid: uid.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    /// A second host reporting for an `instance_uid` bound to the first is not forwarded and takes
    /// no route, over WebSocket and over plain HTTP (`403`): the Server's next reply still reaches
    /// the first host. Two certificates that name no host are two hosts.
    /// Verifies: ADR-0039
    #[tokio::test]
    async fn a_report_for_another_hosts_instance_uid_is_not_forwarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        let uid = InstanceUid::default();
        let (owner_tx, mut owner_rx) = mpsc::channel(64);
        let mut owner = downstream(Transport::WebSocket, Some(owner_tx), certificate());
        forwarding
            .forward_from_socket(&mut owner, report(uid))
            .await;
        assert!(owner.carried.contains(&uid));

        let (thief_tx, mut thief_rx) = mpsc::channel(64);
        let mut thief = downstream(Transport::WebSocket, Some(thief_tx), certificate());
        forwarding
            .forward_from_socket(&mut thief, report(uid))
            .await;
        assert!(!thief.carried.contains(&uid), "the other host carries it");
        let exchange = downstream(Transport::Http, None, certificate());
        match forwarding.forward_exchange(&exchange, report(uid)).await {
            Reply::Refuse(status, _) => assert_eq!(status, StatusCode::FORBIDDEN),
            _ => panic!("a plain-HTTP report for another host's Agent was not refused"),
        }

        forwarding.registry.deliver(uid, reply_for(uid)).await;
        assert!(
            owner_rx.try_recv().is_ok(),
            "the reply reached the bound host"
        );
        assert!(thief_rx.try_recv().is_err(), "and not the other one");
    }

    /// A host past its `max_carried_agents` brings no further Agent upstream.
    /// Verifies: ADR-0039
    #[tokio::test]
    async fn a_report_past_the_hosts_bindings_is_not_forwarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        let (tx, _rx) = mpsc::channel(64);
        let mut peer = downstream(Transport::WebSocket, Some(tx), certificate());
        let uids: Vec<InstanceUid> = (0..4).map(|_| InstanceUid::default()).collect();
        for uid in &uids {
            forwarding
                .forward_from_socket(&mut peer, report(*uid))
                .await;
        }
        assert_eq!(peer.carried.len(), 3, "max_carried_agents is 3");
        assert!(!peer.carried.contains(&uids[3]));
        assert!(!forwarding.registry.routes(&uids[3]));
    }

    /// A certificate that names no host and the one its renewal brings, naming the host the Server
    /// derived for it, are one host: its Agents stay bound across the renewal.
    /// Verifies: ADR-0039
    #[tokio::test]
    async fn a_renewal_naming_the_derived_host_keeps_the_agents_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        let provisioned = certificate();
        // The host the Server names in the renewal, from the certificate's issuer and serial.
        let (issuer, serial) = revocations::certificate_id(&provisioned).expect("an id");
        let derived = fleet_core::host::derived(&issuer, &serial);
        assert_eq!(cache::host_of(&provisioned), None);
        let uid = InstanceUid::default();
        let (before_tx, _before_rx) = mpsc::channel(64);
        let mut before = downstream(Transport::WebSocket, Some(before_tx), provisioned);
        forwarding
            .forward_from_socket(&mut before, report(uid))
            .await;
        assert!(before.carried.contains(&uid));

        let (after_tx, mut after_rx) = mpsc::channel(64);
        let mut after = downstream(
            Transport::WebSocket,
            Some(after_tx),
            certificate_naming(&derived),
        );
        forwarding
            .forward_from_socket(&mut after, report(uid))
            .await;
        assert!(
            after.carried.contains(&uid),
            "the renewed certificate was refused"
        );
        forwarding.registry.deliver(uid, reply_for(uid)).await;
        assert!(after_rx.try_recv().is_ok());
    }

    /// A CSR for a fresh key whose SANs ask for `uri`.
    fn csr_with_uri(uri: &str) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .subject_alt_names
            .push(rcgen::SanType::URI(uri.try_into().expect("uri")));
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("pem")
            .into_bytes()
    }

    /// A CSR for a fresh key with a bootstrap proof embedding `certificate` (DER). Its signature
    /// is no signature at all: the Gateway does not check it.
    fn proof_of(certificate: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        csr_with_uri(&format!(
            "{}{}",
            fleet_core::bootstrap_proof::URI_PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(fleet_core::bootstrap_proof::encode(certificate, b"sig"))
        ))
    }

    /// A request with a bootstrap proof is an enrolment only as exactly one PEM block, the rule
    /// the Server reads it by: behind a prefix, beside a second block, or after another request it
    /// is not forwarded.
    /// Verifies: ADR-0039
    #[test]
    fn an_enrolment_request_is_exactly_one_pem_block() {
        let uid = InstanceUid::default();
        let presented = certificate();
        let proof = || proof_of(&presented);
        let other = csr_with_uri("urn:example:other");
        assert_eq!(not_an_enrolment(&enrolment(uid, proof()), &presented), None);
        for crafted in [
            [b"x".to_vec(), proof()].concat(),
            [b"x".to_vec(), other.clone(), proof()].concat(),
            [proof(), other.clone()].concat(),
            [other, proof()].concat(),
        ] {
            let why = not_an_enrolment(&enrolment(uid, crafted), &presented).expect("forwarded");
            assert!(why.contains("bootstrap proof"), "{why}");
        }
    }

    /// An enrolling peer's request is forwarded only when its bootstrap proof embeds the very
    /// certificate the peer presented: one naming another certificate — one with that
    /// certificate's issuer and serial included — one whose proof does not parse, and one carrying
    /// the presented certificate with a byte changed are answered `403` and reach no route.
    /// Verifies: ADR-0039
    #[tokio::test]
    async fn an_enrolling_peer_proves_the_certificate_it_presented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        // Two certificates of one issuer name and one serial, over keys of their own.
        let twin = || {
            let key = rcgen::KeyPair::generate().expect("key");
            let mut params = rcgen::CertificateParams::new(vec!["edge".into()]).expect("params");
            params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x2a; 8]));
            params.self_signed(&key).expect("cert").der().to_vec()
        };
        let presented = twin();
        let forged = twin();
        assert_eq!(
            revocations::certificate_id(&forged),
            revocations::certificate_id(&presented)
        );
        let peer = Downstream {
            enrolling: true,
            host: None,
            ..downstream(Transport::Http, None, presented.clone())
        };
        let mut altered = presented.clone();
        let last = altered.len() - 1;
        altered[last] ^= 0x01;
        let uid = InstanceUid::default();
        for csr in [
            proof_of(&certificate()),
            proof_of(&forged),
            proof_of(&altered),
            proof_of(&[presented.as_slice(), b"\0"].concat()),
            csr_with_uri(&format!("{}AAAA", fleet_core::bootstrap_proof::URI_PREFIX)),
        ] {
            match forwarding
                .forward_enrolment(&peer, enrolment(uid, csr))
                .await
            {
                Reply::Refuse(status, why) => {
                    assert_eq!(status, StatusCode::FORBIDDEN, "{why}");
                    assert!(why.contains("the certificate it presented"), "{why}");
                }
                _ => panic!("a proof of another certificate was forwarded"),
            }
            assert!(!forwarding.registry.routes(&uid));
        }
    }

    /// A report of `uid` carrying `csr` and nothing else.
    fn enrolment(uid: InstanceUid, csr: Vec<u8>) -> AgentToServer {
        AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            sequence_num: 1,
            capabilities: 1,
            connection_settings_request: Some(opamp::proto::ConnectionSettingsRequest {
                opamp: Some(opamp::proto::OpAmpConnectionSettingsRequest {
                    certificate_request: Some(opamp::proto::CertificateRequest { csr }),
                }),
            }),
            ..Default::default()
        }
    }

    /// An enrolling peer's report is forwarded only when it carries a CSR with a bootstrap proof
    /// and nothing a member reports; any other is answered `403`. The one it forwards binds
    /// nothing: its exchange is its route until it ends, and an `instance_uid` bound to a host is
    /// not an enrolling peer's to report for.
    /// Verifies: ADR-0039
    #[tokio::test]
    async fn an_enrolling_peer_relays_one_enrolment_request_and_binds_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forwarding = forwarding(dir.path()).await;
        let presented = certificate();
        let peer = Downstream {
            enrolling: true,
            host: None,
            ..downstream(Transport::Http, None, presented.clone())
        };
        let proof = proof_of(&presented);
        let refused = |reply: Reply| match reply {
            Reply::Refuse(status, why) => {
                assert_eq!(status, StatusCode::FORBIDDEN, "{why}");
                why
            }
            _ => panic!("forwarded"),
        };

        let uid = InstanceUid::default();
        let described = AgentToServer {
            agent_description: Some(opamp::proto::AgentDescription::default()),
            ..enrolment(uid, proof.clone())
        };
        let health = AgentToServer {
            health: Some(opamp::proto::ComponentHealth::default()),
            ..enrolment(uid, proof.clone())
        };
        let flagged = AgentToServer {
            flags: 1,
            ..enrolment(uid, proof.clone())
        };
        for report in [
            report(uid),
            described,
            health,
            flagged,
            enrolment(uid, csr_with_uri("urn:example:nothing")),
            enrolment(
                uid,
                csr_with_uri(&format!("{}AAAA", fleet_core::renewal::URI_PREFIX)),
            ),
        ] {
            let why = refused(forwarding.forward_enrolment(&peer, report).await);
            assert!(why.contains("enrolling peer"), "{why}");
            assert!(!forwarding.registry.routes(&uid));
        }

        let mut exchange =
            Box::pin(forwarding.forward_enrolment(&peer, enrolment(uid, proof.clone())));
        tokio::select! {
            _ = &mut exchange => panic!("the silent upstream answered"),
            () = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
        }
        assert!(
            forwarding.registry.routes(&uid),
            "its exchange is its route"
        );
        assert!(
            !forwarding.registry.cache().is_bound(&uid),
            "it binds nothing"
        );
        drop(exchange);
        assert!(!forwarding.registry.routes(&uid), "gone with the exchange");
        assert!(
            !forwarding.pool.assignments().0.contains(&uid),
            "and its place upstream"
        );

        // An Agent a member bound is not an enrolling peer's to report for.
        let bound = InstanceUid::default();
        let (tx, _rx) = mpsc::channel(64);
        let mut member = downstream(Transport::WebSocket, Some(tx), certificate());
        forwarding
            .forward_from_socket(&mut member, report(bound))
            .await;
        refused(
            forwarding
                .forward_enrolment(&peer, enrolment(bound, proof))
                .await,
        );
    }

    /// Writes a self-signed CA named `name` into `dir` as `<file>.pem`; returns it.
    fn ca_file(
        dir: &std::path::Path,
        file: &str,
        name: &str,
    ) -> (std::path::PathBuf, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca");
        let path = dir.join(format!("{file}.pem"));
        std::fs::write(&path, cert.pem()).expect("write");
        (path, rcgen::Issuer::new(params, key))
    }

    /// `[gateway.tls]` with `client_ca_file` and, optionally, `bootstrap_ca_file`.
    fn gateway_tls(
        dir: &std::path::Path,
        client: &std::path::Path,
        bootstrap: Option<&std::path::Path>,
    ) -> GatewayTlsConfig {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["gateway".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        std::fs::write(dir.join("listener.pem"), cert.pem()).expect("write");
        std::fs::write(dir.join("listener-key.pem"), key.serialize_pem()).expect("write");
        GatewayTlsConfig {
            cert_file: dir.join("listener.pem"),
            key_file: dir.join("listener-key.pem"),
            client_ca_file: Some(client.to_path_buf()),
            bootstrap_ca_file: bootstrap.map(std::path::Path::to_path_buf),
        }
    }

    /// With `bootstrap_ca_file` a peer of the client CA is a member and one of the bootstrap CA is
    /// enrolling; without it every peer is a member, as the handshake admits the client CA's alone.
    /// A CA in both files fails startup naming both keys.
    /// Verifies: ADR-0039
    #[test]
    fn a_bootstrap_ca_makes_its_peers_enrolling_and_may_not_be_the_client_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (client, client_ca) = ca_file(dir.path(), "client-ca", "fleet client CA");
        let (bootstrap, bootstrap_ca) = ca_file(dir.path(), "bootstrap-ca", "fleet bootstrap CA");
        let leaf = |issuer: &rcgen::Issuer<'static, rcgen::KeyPair>| {
            let key = rcgen::KeyPair::generate().expect("key");
            rcgen::CertificateParams::new(vec!["edge".to_string()])
                .expect("params")
                .signed_by(&key, issuer)
                .expect("signed")
                .der()
                .to_vec()
        };
        let (member, enrolling) = (leaf(&client_ca), leaf(&bootstrap_ca));

        let (_, members) =
            server_tls(&gateway_tls(dir.path(), &client, Some(&bootstrap))).expect("serves");
        assert!(!members.enrolling(&member));
        assert!(members.enrolling(&enrolling));
        let (_, without) = server_tls(&gateway_tls(dir.path(), &client, None)).expect("serves");
        assert!(
            !without.enrolling(&enrolling),
            "no bootstrap CA, no enrolling peer"
        );

        let Err(error) = server_tls(&gateway_tls(dir.path(), &client, Some(&client))) else {
            panic!("a CA in both files was taken");
        };
        assert!(
            error.contains("client_ca_file") && error.contains("bootstrap_ca_file"),
            "{error}"
        );
    }
}
