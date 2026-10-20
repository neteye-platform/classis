//! The OpAMP endpoint — both transports on one path (ADR-0013).
//!
//! `/v1/opamp` serves the whole protocol: a request carrying the protobuf `Content-Type` is the
//! plain-HTTP transport, a WebSocket upgrade is the other — exactly the detection the Baseline
//! describes. The communication is `opamp::server`'s, shared with the Gateway and the Supervisor
//! Endpoint (ADR-0010); what is the Server's is the [`Fleet`] handler, which hands every decoded
//! report to the same [`AppState::process`], so transport is carriage, never semantics.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::listen::PeerCertificate;
use opamp::server::{
    Closing, Handler, Outbound, Rejection, Reply, RequestInfo, Settings, Unreadable,
};
use opamp::uid::InstanceUid;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::agent_rate::{AgentRate, Bucket, Subject};
use crate::audit::{Audit, Entry};
use crate::enrolment::{Enrolment, Requester, Submitted};
use crate::fleet::{bad_request, unavailable, AppState, ConnId, Transport};
use crate::revocation::{CertId, Presented, Revocations};
use crate::throttle::Throttle;
use crate::tls::{Issuers, Peer};

/// The endpoint path the Baseline names as the default, and the protobuf media type it requires —
/// both from the shared crate, because the Gateway serves the same endpoint (ADR-0010).
pub use opamp::endpoint::{OPAMP_PATH, PROTOBUF_CONTENT_TYPE};

/// What a peer must prove to reach `/v1/opamp` (ADR-0021 clauses 1, 6): a client certificate the
/// handshake verified, not revoked — the whole of admission. No `Authorization` header is read; one
/// that is sent is ignored, never refused, and no refusal carries a `WWW-Authenticate` challenge. A
/// certificate from the bootstrap CA admits an enrolling host, and only while an operator holds the
/// enrolment window open. Repeated failures from one peer address are throttled.
#[derive(Default)]
pub struct Admission {
    /// The connection must have carried a certificate. The certificate itself is already verified
    /// — rustls refuses one it cannot chain — so this is a presence check, never a second
    /// verification.
    require_client_certificate: bool,
    issuers: Issuers,
    enrolment: Option<Arc<Enrolment>>,
    throttle: Option<Arc<Throttle>>,
    revocations: Option<Arc<Revocations>>,
    audit: Option<Arc<dyn Audit>>,
    /// When a plain-HTTP peer presenting a certificate was last recorded as admitted.
    admitted: Mutex<HashMap<(IpAddr, Option<String>), Instant>>,
}

/// How often a plain-HTTP peer's admission is recorded: once per address and certificate per
/// hour, so a poll every few seconds does not crowd the record (ADR-0022 clause 1).
const ADMITTED_EVERY: Duration = Duration::from_secs(3600);

/// The plain-HTTP peers remembered as recorded at most.
const ADMITTED_MAX: usize = 100_000;

/// What admitted a connection (ADR-0021 clause 40): the certificate, with when it expires. A
/// WebSocket session ends when it is revoked, or when it expires.
#[derive(Clone, Debug, Default)]
pub struct Proofs {
    pub certificate: Option<(CertId, u64)>,
    /// The certificate itself (DER), which a bootstrap proof naming it must embed byte for byte
    /// (ADR-0039 clause 12).
    pub der: Option<Arc<[u8]>>,
    /// The host the certificate was issued to, when it names one (ADR-0021 clause 7).
    pub host: Option<String>,
    /// The certificate's subject values, which a Host made at its first report carries
    /// (ADR-0035 clause 1).
    pub subject_values: crate::revocation::SubjectValues,
}

impl Proofs {
    fn revoked(&self, revocations: &Revocations) -> bool {
        self.certificate
            .as_ref()
            .is_some_and(|(id, _)| revocations.is_certificate_revoked(id))
    }

    /// Who a member's messages and downloads are counted for (ADR-0013 clause 22): the host its
    /// certificate names, else the certificate, else — with no certificate at all — the peer.
    fn subject(&self, peer: Option<IpAddr>) -> Subject {
        match (&self.host, &self.certificate) {
            (Some(host), _) => Subject::Host(host.clone()),
            (None, Some((id, _))) => Subject::Certificate(id.clone()),
            (None, None) => Subject::peer(peer),
        }
    }

    /// The refusal of a message or a download past the limit (ADR-0013 clause 27): the host, or the
    /// certificate's serial and the role of the CA that issued it.
    fn throttled_entry(
        &self,
        peer: Option<IpAddr>,
        revocations: Option<&Arc<Revocations>>,
        bucket: Bucket,
    ) -> Entry {
        let entry = Entry::new("agent_rate.throttled", "throttled")
            .peer(peer)
            .with("plane", "agent")
            .with("bucket", bucket.as_str());
        match (&self.host, &self.certificate) {
            (Some(host), _) => entry.with("host", host.clone()),
            (None, Some((id, _))) => entry.with("serial", id.serial.clone()).with(
                "authority",
                revocations
                    .and_then(|revocations| revocations.authority_of(&id.issuer))
                    .map(|authority| authority.role.clone()),
            ),
            (None, None) => entry,
        }
    }
}

/// Whether `subject` is a host marked as a Gateway, read at each message (ADR-0013 clause 22).
fn is_gateway(subject: &Subject, revocations: Option<&Arc<Revocations>>) -> bool {
    match (subject, revocations) {
        (Subject::Host(host), Some(revocations)) => revocations.is_gateway(host),
        _ => false,
    }
}

/// What a message past the limit is answered (ADR-0013 clause 23).
const THROTTLED: &str = "too many messages arrive from this sender — retry later";

impl Admission {
    /// No proof required — what a test that is not about admission serves with. A Server never
    /// does: its configuration requires the client CA (ADR-0021).
    pub fn open() -> Self {
        Admission::default()
    }

    pub fn new(require_client_certificate: bool) -> Self {
        Admission {
            require_client_certificate,
            ..Admission::default()
        }
    }

    /// Tells a member's certificate from an enrolling host's, and admits the latter only while
    /// `enrolment`'s window is open.
    #[must_use]
    pub fn with_enrolment(mut self, issuers: Issuers, enrolment: Option<Arc<Enrolment>>) -> Self {
        self.issuers = issuers;
        self.enrolment = enrolment;
        self
    }

    /// Throttles repeated failures from one peer address (ADR-0021 clause 24).
    #[must_use]
    pub fn with_throttle(mut self, throttle: Arc<Throttle>) -> Self {
        self.throttle = Some(throttle);
        self
    }

    /// Records every decision in `audit` (ADR-0022).
    #[must_use]
    pub fn with_audit(mut self, audit: Option<Arc<dyn Audit>>) -> Self {
        self.audit = audit;
        self
    }

    /// `client` or `bootstrap` for a certificate one of this Server's CAs issued.
    fn issuers_role(&self, issuer: &str) -> Option<String> {
        self.revocations
            .as_ref()
            .and_then(|revocations| revocations.authority_of(issuer))
            .map(|authority| authority.role.clone())
    }

    /// Whether this admission is recorded: every WebSocket session, and a plain-HTTP peer once per
    /// address — an IPv6 one by its /64 — and certificate per [`ADMITTED_EVERY`].
    fn worth_recording(&self, websocket: bool, peer: Option<IpAddr>, serial: Option<&str>) -> bool {
        let (false, Some(peer)) = (websocket, peer) else {
            return true;
        };
        let key = (crate::throttle::peer_key(peer), serial.map(str::to_string));
        self.admitted
            .lock()
            .expect("admitted lock")
            .get(&key)
            .is_none_or(|at| at.elapsed() >= ADMITTED_EVERY)
    }

    /// Notes that a plain-HTTP peer's admission was recorded — only once it was, so a peer
    /// refused for want of a record is recorded when it is admitted.
    fn recorded(&self, peer: Option<IpAddr>, serial: Option<&str>) {
        let Some(peer) = peer else {
            return;
        };
        let mut admitted = self.admitted.lock().expect("admitted lock");
        if admitted.len() >= ADMITTED_MAX {
            admitted.retain(|_, at| at.elapsed() < ADMITTED_EVERY);
            if admitted.len() >= ADMITTED_MAX {
                // Forgetting only means recording again; it never means admitting unrecorded.
                admitted.clear();
            }
        }
        admitted.insert(
            (crate::throttle::peer_key(peer), serial.map(str::to_string)),
            Instant::now(),
        );
    }

    /// Refuses a revoked certificate (ADR-0021 clause 39).
    #[must_use]
    pub fn with_revocations(mut self, revocations: Option<Arc<Revocations>>) -> Self {
        self.revocations = revocations;
        self
    }

    fn required(&self) -> bool {
        self.require_client_certificate || self.throttle.is_some() || self.revocations.is_some()
    }
}

/// Milliseconds since the Unix epoch, on the host's clock.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether a certificate whose `not_after` is `not_after_ms` has expired: from that instant on it
/// admits nothing, as it ends a WebSocket session then (ADR-0021 clause 41).
fn expired(not_after_ms: u64) -> bool {
    not_after_ms <= now_ms()
}

/// `401` without a challenge: the Agent plane admits by certificate, which no header can supply
/// (ADR-0021 clause 1).
fn unauthorized(text: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, text).into_response()
}

/// What the package download route asks of a peer (ADR-0021 clause 23): the same handshake as
/// `/v1/opamp`, and a certificate from the client CA — a bootstrap certificate is not enough.
#[derive(Clone, Default)]
pub struct DownloadGuard {
    require_client_certificate: bool,
    issuers: Issuers,
    throttle: Option<Arc<Throttle>>,
    revocations: Option<Arc<Revocations>>,
    audit: Option<Arc<dyn Audit>>,
    agent_rate: Option<Arc<AgentRate>>,
}

impl Admission {
    /// The download route's share of these rules.
    #[must_use]
    pub fn download_guard(&self) -> DownloadGuard {
        DownloadGuard {
            require_client_certificate: self.require_client_certificate,
            issuers: self.issuers.clone(),
            throttle: self.throttle.clone(),
            revocations: self.revocations.clone(),
            audit: self.audit.clone(),
            agent_rate: None,
        }
    }
}

impl DownloadGuard {
    /// Counts every admitted download against the sender's rate (ADR-0013 clause 21).
    #[must_use]
    pub fn with_agent_rate(mut self, agent_rate: Option<Arc<AgentRate>>) -> Self {
        self.agent_rate = agent_rate;
        self
    }
}

/// Wraps the download route in its guard.
pub fn guard_download(router: Router, guard: DownloadGuard) -> Router {
    if !guard.require_client_certificate && guard.throttle.is_none() && guard.agent_rate.is_none() {
        return router;
    }
    router.layer(middleware::from_fn_with_state(
        Arc::new(guard),
        admit_download,
    ))
}

async fn admit_download(
    State(guard): State<Arc<DownloadGuard>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = peer_ip(&request);
    let path = request.uri().path().to_string();
    let record = |event: &str, outcome: &str| {
        guard.audit.as_ref().map(|audit| {
            audit.record(
                Entry::new(event, outcome)
                    .peer(peer)
                    .with("plane", "agent")
                    .with("path", path.clone()),
            )
        })
    };
    if let (Some(throttle), Some(peer)) = (&guard.throttle, peer) {
        if let Some(wait) = throttle.retry_after(peer) {
            let _ = record("download.throttled", "throttled");
            return throttled(wait);
        }
    }
    let certificate = request
        .extensions()
        .get::<PeerCertificate>()
        .and_then(|peer| peer.0.as_ref());
    let facts = certificate.and_then(|cert| crate::ca::facts(cert.as_ref()).ok());
    let member = match certificate {
        Some(cert) => {
            guard.issuers.classify(cert.as_ref()) == Peer::Member
                && !facts
                    .as_ref()
                    .is_some_and(|facts| expired(facts.not_after_ms))
                && !guard.revocations.as_ref().is_some_and(|revocations| {
                    facts
                        .as_ref()
                        .is_none_or(|facts| revocations.is_certificate_revoked(&facts.id))
                })
        }
        None => !guard.require_client_certificate,
    };
    if !member {
        if let (Some(throttle), Some(peer)) = (&guard.throttle, peer) {
            throttle.failed(peer);
        }
        let _ = record("download.refused", "refused");
        return unauthorized("the package download requires a certificate of the fleet");
    }
    // What the certificate proves, read once: counted here, and handed to the route, which serves
    // only what is offered to an Agent of the host it names (ADR-0026 clause 37).
    let proofs = certificate.map(|cert| Proofs {
        der: Some(Arc::from(cert.as_ref())),
        host: facts.as_ref().and_then(|facts| facts.host.clone()),
        subject_values: facts
            .as_ref()
            .map(|facts| facts.subject_values.clone())
            .unwrap_or_default(),
        certificate: facts.map(|facts| (facts.id, facts.not_after_ms)),
    });
    if let Some(agent_rate) = &guard.agent_rate {
        let proofs = proofs.clone().unwrap_or_default();
        let subject = proofs.subject(peer);
        let gateway = is_gateway(&subject, guard.revocations.as_ref());
        // A download names no Agent, so through a Gateway it counts in the aggregate alone. Over
        // the limit is no failure: the throttle of ADR-0021 clause 24 is not fed.
        if let Err(bucket) = agent_rate.admit(&subject, gateway, None) {
            if let Some(audit) = &guard.audit {
                audit.refusal(
                    proofs
                        .throttled_entry(peer, guard.revocations.as_ref(), bucket)
                        .with("route", "download"),
                );
            }
            return over_rate();
        }
    }
    if record("download.admitted", "admitted") == Some(Err(crate::audit::Unavailable)) {
        return busy();
    }
    if let Some(proofs) = proofs {
        request.extensions_mut().insert(proofs);
    }
    next.run(request).await
}

/// Where a Gateway fetches the revoked certificates it refuses (ADR-0021 clause 43).
pub const GATEWAY_REVOCATIONS_PATH: &str = "/v1/gateway/revocations";

pub fn router(state: Arc<AppState>, admission: Admission) -> Router {
    // The limits the Baseline requires of the Server, on both transports and in both directions.
    let settings = Settings::new(state.max_message_size());
    let gateways = Router::new()
        .route(
            GATEWAY_REVOCATIONS_PATH,
            axum::routing::get(gateway_revocations),
        )
        .with_state(state.clone());
    let fleet = Fleet(state, admission.issuers.clone());
    let mut router = opamp::server::router(Arc::new(fleet), settings).merge(gateways);
    if admission.required() {
        // The outermost layer: every plain-HTTP POST and the upgrade GET — checked before the
        // WebSocket upgrade completes — answers 401 without a certificate that admits.
        router = router.layer(middleware::from_fn_with_state(Arc::new(admission), admit));
    }
    router
}

/// The revoked certificates of the client CA, chains resolved, for a host marked as a Gateway
/// (ADR-0021 clause 43). Admitted as `/v1/opamp` is, by the layer around both; what is checked
/// here is that the member is a Gateway. The `ETag` is the SHA-256 of the body, so it changes with
/// the list and survives a restart.
async fn gateway_revocations(State(state): State<Arc<AppState>>, request: Request) -> Response {
    use sha2::Digest as _;

    let forbidden = || {
        (
            StatusCode::FORBIDDEN,
            "the revocation list is for hosts marked as Gateways",
        )
            .into_response()
    };
    // Without a register nothing is revoked, so the empty list reveals nothing to anyone. With one,
    // the list is a member's whose host is marked as a Gateway, and nobody else's.
    let certificates: Vec<serde_json::Value> = match state.revocations() {
        None => Vec::new(),
        Some(revocations) => {
            let host = match request.extensions().get::<Peer>() {
                Some(Peer::Member) => request
                    .extensions()
                    .get::<Proofs>()
                    .and_then(|proofs| proofs.host.clone()),
                _ => None,
            };
            if !host
                .as_ref()
                .is_some_and(|host| revocations.is_gateway(host))
            {
                // A member asking for what only a Gateway is handed is a refusal like any other
                // (ADR-0022 clause 1).
                state.audit_refusal(
                    Entry::new("gateway_list.refused", "refused")
                        .peer(peer_ip(&request))
                        .with("plane", "agent")
                        .with("host", host)
                        .with("check", "not a gateway"),
                );
                return forbidden();
            }
            revocations
                .revoked_certificates("client")
                .into_iter()
                .map(|id| serde_json::json!({ "issuer": id.issuer, "serial": id.serial }))
                .collect()
        }
    };
    let body = serde_json::json!({ "certificates": certificates }).to_string();
    let etag = format!("\"{}\"", hex::encode(sha2::Sha256::digest(body.as_bytes())));
    if request
        .headers()
        .get(header::IF_NONE_MATCH)
        .is_some_and(|value| value.as_bytes() == etag.as_bytes())
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::ETAG, etag),
        ],
        body,
    )
        .into_response()
}

/// The peer's address, as the listener put it into the request.
pub fn peer_ip(request: &Request) -> Option<std::net::IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

/// The answer while the Server cannot take a decision now — too many password hashes under way on
/// the Operator plane, or the audit record unavailable: `503`, try again in a second.
pub fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1".to_string())],
        "the Server cannot take this now — retry in a moment",
    )
        .into_response()
}

/// The answer to a download past the sender's rate (ADR-0013 clause 24): `429`, retry in 30 s.
fn over_rate() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            header::RETRY_AFTER,
            crate::fleet::RETRY_AFTER.as_secs().to_string(),
        )],
        "too many requests from this sender — retry later",
    )
        .into_response()
}

/// The answer to a peer in back-off: `429` with the seconds it still has to wait.
pub fn throttled(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        "too many failed attempts from this address — retry later",
    )
        .into_response()
}

async fn admit(
    State(admission): State<Arc<Admission>>,
    mut request: Request,
    next: Next,
) -> Response {
    // What this gate proves is *fleet membership* and the host, not which Agent is speaking:
    // `instance_uid` stays self-asserted behind the certificate (ADR-0021 clauses 7, 14). Admission
    // is the trust boundary; the host is the only bound between admitted Agents. An
    // `Authorization` header is not read here or anywhere behind it (ADR-0021 clause 1).
    let peer = peer_ip(&request);
    let record_refusal = |event: &str, outcome: &str, check: &str| {
        if let Some(audit) = &admission.audit {
            audit.refusal(
                Entry::new(event, outcome)
                    .peer(peer)
                    .with("plane", "agent")
                    .with("check", check),
            );
        }
    };
    if let (Some(throttle), Some(peer)) = (&admission.throttle, peer) {
        if let Some(wait) = throttle.retry_after(peer) {
            record_refusal("admission.throttled", "throttled", "throttle");
            return throttled(wait);
        }
    }
    let refuse = |check: &str, response: Response| {
        if let (Some(throttle), Some(peer)) = (&admission.throttle, peer) {
            throttle.failed(peer);
        }
        record_refusal("admission.refused", "refused", check);
        response
    };
    let websocket = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let certificate = request
        .extensions()
        .get::<PeerCertificate>()
        .and_then(|peer| peer.0.clone());
    if admission.require_client_certificate && certificate.is_none() {
        debug!("refused: the OpAMP endpoint requires a client certificate");
        return refuse(
            "certificate",
            (
                StatusCode::UNAUTHORIZED,
                "the OpAMP endpoint requires a client certificate",
            )
                .into_response(),
        );
    }
    let presented = match certificate
        .as_ref()
        .map(|cert| crate::ca::facts(cert.as_ref()))
    {
        None => None,
        Some(Ok(facts)) => Some(facts),
        // The handshake verified it, so it parses; one that does not is not admitted.
        Some(Err(_)) => {
            return refuse(
                "certificate",
                unauthorized("the OpAMP endpoint requires a certificate of the fleet"),
            )
        }
    };
    // The handshake checked the certificate's validity once per connection; a kept-alive one
    // outlives it, so each request is checked again (ADR-0021 clauses 6, 41).
    if presented
        .as_ref()
        .is_some_and(|facts| expired(facts.not_after_ms))
    {
        debug!("refused: an expired certificate");
        return refuse(
            "expired",
            unauthorized("the OpAMP endpoint requires a certificate of the fleet"),
        );
    }
    if let Some(revocations) = &admission.revocations {
        let proofs = Proofs {
            der: None,
            certificate: presented
                .as_ref()
                .map(|facts| (facts.id.clone(), facts.not_after_ms)),
            host: None,
            subject_values: crate::revocation::SubjectValues::default(),
        };
        // That the certificate was revoked is not said (ADR-0021 clause 39).
        if proofs.revoked(revocations) {
            debug!("refused: a revoked certificate");
            if let Some(audit) = &admission.audit {
                audit.refusal(
                    Entry::new("admission.revoked_proof", "refused")
                        .peer(peer)
                        .with(
                            "serial",
                            presented.as_ref().map(|facts| facts.id.serial.clone()),
                        ),
                );
            }
            return refuse(
                "revoked",
                unauthorized("the OpAMP endpoint requires a certificate of the fleet"),
            );
        }
    }
    let classified = certificate
        .as_ref()
        .map(|cert| admission.issuers.classify(cert.as_ref()))
        .unwrap_or(Peer::Member);
    if let Peer::Enrolling { .. } = &classified {
        // A bootstrap certificate opens nothing outside an enrolment window (ADR-0021 clause 21).
        // The handshake proved the certificate, so this is no guess and counts as no failure:
        // hosts that wait for an operator must not throttle the members behind the same address.
        if !admission.enrolment.as_ref().is_some_and(|e| e.is_open()) {
            debug!("refused: a bootstrap certificate outside an enrolment window");
            record_refusal("admission.refused", "refused", "enrolment_window");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "no enrolment window is open",
            )
                .into_response();
        }
    }
    if let Some(audit) = &admission.audit {
        let serial = presented.as_ref().map(|facts| facts.id.serial.as_str());
        if admission.worth_recording(websocket, peer, serial) {
            let entry = Entry::new("admission.admitted", "admitted")
                .peer(peer)
                .with("plane", "agent")
                .with("transport", if websocket { "websocket" } else { "http" })
                .with(
                    "as",
                    match &classified {
                        Peer::Member => "member",
                        Peer::Enrolling { .. } => "enrolling",
                    },
                )
                .with(
                    "authority",
                    presented
                        .as_ref()
                        .and_then(|facts| admission.issuers_role(&facts.id.issuer)),
                )
                .with("serial", serial.map(str::to_string));
            // Not admitted without its record (ADR-0022 clause 6).
            if audit.record(entry).is_err() {
                return busy();
            }
            if !websocket {
                admission.recorded(peer, serial);
            }
        }
    }
    request.extensions_mut().insert(classified);
    request.extensions_mut().insert(Proofs {
        der: certificate.map(|cert| Arc::from(cert.as_ref())),
        host: presented.as_ref().and_then(|facts| facts.host.clone()),
        subject_values: presented
            .as_ref()
            .map(|facts| facts.subject_values.clone())
            .unwrap_or_default(),
        certificate: presented.map(|facts| (facts.id, facts.not_after_ms)),
    });
    next.run(request).await
}

/// The Server's handler behind the endpoint: every report goes to the fleet, and a WebSocket is
/// also sent what the fleet wants its Agents to have when that changes. The CAs of the Agent plane
/// tell which bootstrap certificates an enrolment request through a Gateway may prove (ADR-0039).
struct Fleet(Arc<AppState>, Issuers);

/// One connection as the fleet sees it.
struct Carrier {
    transport: Transport,
    /// Set on an enrolment connection (ADR-0021 clause 21): the bootstrap certificate it carried,
    /// where from, and the key its request asks to be certified, once it has sent one.
    enrolling: Option<Enrolling>,
    /// This connection's identity — what the duplicate detection tells connections apart by. Plain
    /// HTTP is stateless polling, so there is none to pass.
    conn: Option<ConnId>,
    /// The Agents this socket carried, any number of them told apart by `instance_uid` alone
    /// (ADR-0015), so all of them are marked unreachable when it goes.
    seen: Vec<InstanceUid>,
    /// What admitted the connection: re-checked before a CSR is signed, and the presented
    /// certificate is the predecessor of one it renews (ADR-0021 clauses 33, 35).
    proofs: Proofs,
    /// Where the connection comes from.
    peer: Option<IpAddr>,
    /// Who its messages are counted for (ADR-0013 clause 22).
    subject: Subject,
    /// Why the session was ended, once its [`Guard`] has ended it.
    ended: Arc<Mutex<Option<&'static str>>>,
}

/// What an enrolling connection carried, and what it has asked for.
struct Enrolling {
    requester: Requester,
    request: Arc<Mutex<Option<crate::enrolment::Request>>>,
    instance_uid: Arc<Mutex<Vec<u8>>>,
}

/// What a connection is sent without asking. A member hears of every change to the fleet's
/// desired state — the "within seconds" of the control loop. An enrolling host hears of its own
/// request's decision, and its connection ends when the window closes or the request is rejected.
enum Pushes {
    Desired(watch::Receiver<u64>),
    Enrolment {
        changes: watch::Receiver<u64>,
        enrolment: Arc<Enrolment>,
        request: Arc<Mutex<Option<crate::enrolment::Request>>>,
    },
}

/// A WebSocket session's outbound side, and what ends it: a revocation of what admitted it, or the
/// expiry of its certificate (ADR-0021 clauses 40, 41).
struct Session {
    pushes: Pushes,
    guard: Option<Guard>,
}

struct Guard {
    revocations: Arc<Revocations>,
    audit: Option<Arc<dyn Audit>>,
    changes: watch::Receiver<u64>,
    proofs: Proofs,
    expires: Option<tokio::time::Instant>,
    ended: Arc<Mutex<Option<&'static str>>>,
}

impl Guard {
    fn new(
        revocations: Arc<Revocations>,
        audit: Option<Arc<dyn Audit>>,
        proofs: Proofs,
        ended: Arc<Mutex<Option<&'static str>>>,
    ) -> Self {
        let expires = proofs.certificate.as_ref().map(|(_, not_after_ms)| {
            tokio::time::Instant::now()
                + std::time::Duration::from_millis(not_after_ms.saturating_sub(now_ms()))
        });
        let mut changes = revocations.subscribe();
        // A revocation that landed between admission and here is checked at once.
        changes.mark_changed();
        Guard {
            changes,
            revocations,
            audit,
            proofs,
            expires,
            ended,
        }
    }

    /// Waits until the session must end, and says why.
    async fn tripped(&mut self) -> &'static str {
        let Guard {
            revocations,
            changes,
            proofs,
            expires,
            ..
        } = self;
        let expiry = async {
            match expires {
                Some(at) => tokio::time::sleep_until(*at).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(expiry);
        loop {
            tokio::select! {
                () = &mut expiry => return "certificate expired",
                changed = changes.changed() => {
                    if changed.is_err() {
                        // The list is gone with the Server; only the expiry is left to wait for.
                        (&mut expiry).await;
                        return "certificate expired";
                    }
                    if proofs.revoked(revocations) {
                        return "revoked";
                    }
                }
            }
        }
    }
}

impl Outbound for Session {
    type Item = Push;

    async fn next(&mut self) -> Option<Push> {
        let Session { pushes, guard } = self;
        let Some(guard) = guard else {
            return pushes.next().await;
        };
        let ended = guard.ended.clone();
        let audit = guard.audit.clone();
        let serial = guard
            .proofs
            .certificate
            .as_ref()
            .map(|(id, _)| id.serial.clone());
        tokio::select! {
            item = pushes.next() => item,
            reason = guard.tripped() => {
                info!(reason, "ending a session");
                if let Some(audit) = audit {
                    audit.refusal(
                        Entry::new("session.ended", "ended")
                            .with("reason", reason)
                            .with("serial", serial),
                    );
                }
                *ended.lock().expect("ended lock") = Some(reason);
                None
            }
        }
    }
}

/// One occasion to push.
enum Push {
    Desired,
    Enrolment,
}

impl Pushes {
    async fn next(&mut self) -> Option<Push> {
        match self {
            Pushes::Desired(changes) => changes.changed().await.ok().map(|()| Push::Desired),
            Pushes::Enrolment {
                changes,
                enrolment,
                request,
            } => {
                changes.changed().await.ok()?;
                let key = request
                    .lock()
                    .expect("request lock")
                    .as_ref()
                    .map(|r| r.key_fingerprint.clone());
                if !enrolment.is_open() || key.is_some_and(|key| enrolment.is_rejected(&key)) {
                    return None;
                }
                Some(Push::Enrolment)
            }
        }
    }
}

impl Handler for Fleet {
    type Connection = Carrier;
    type Outbound = Session;

    fn on_connecting(
        &self,
        request: &RequestInfo<'_>,
    ) -> Result<(Carrier, Option<Session>), Rejection> {
        let proofs = request
            .extensions
            .get::<Proofs>()
            .cloned()
            .unwrap_or_default();
        let ended = Arc::new(Mutex::new(None));
        let session = |pushes: Pushes| Session {
            pushes,
            guard: self.0.revocations().map(|revocations| {
                Guard::new(
                    revocations.clone(),
                    self.0.audit().cloned(),
                    proofs.clone(),
                    ended.clone(),
                )
            }),
        };
        let websocket = request.transport == opamp::server::Transport::WebSocket;
        let peer = request.peer.map(|peer| peer.ip());
        if let (
            Some(Peer::Enrolling {
                subject,
                carried,
                fingerprint,
                id,
            }),
            Some(enrolment),
        ) = (request.extensions.get::<Peer>(), self.0.enrolment())
        {
            let enrolling = Enrolling {
                requester: Requester {
                    bootstrap_subject: subject.clone(),
                    carried: (**carried).clone(),
                    bootstrap_fingerprint: fingerprint.clone(),
                    bootstrap: id.clone(),
                    peer: request.peer.map(|peer| peer.ip()),
                    gateway: None,
                },
                request: Arc::new(Mutex::new(None)),
                instance_uid: Arc::new(Mutex::new(Vec::new())),
            };
            let outbound = websocket.then(|| {
                session(Pushes::Enrolment {
                    changes: enrolment.subscribe(),
                    enrolment: enrolment.clone(),
                    request: enrolling.request.clone(),
                })
            });
            return Ok((
                Carrier {
                    transport: if websocket {
                        Transport::WebSocket
                    } else {
                        Transport::Http
                    },
                    enrolling: Some(enrolling),
                    conn: None,
                    seen: Vec::new(),
                    proofs: proofs.clone(),
                    peer,
                    // A bootstrap certificate may be the whole fleet's, so an enrolling host is
                    // counted by its address.
                    subject: Subject::peer(peer),
                    ended,
                },
                outbound,
            ));
        }
        let (transport, conn, outbound) = if websocket {
            (
                Transport::WebSocket,
                Some(self.0.connection_id()),
                Some(session(Pushes::Desired(self.0.subscribe()))),
            )
        } else {
            (Transport::Http, None, None)
        };
        Ok((
            Carrier {
                transport,
                enrolling: None,
                conn,
                seen: Vec::new(),
                subject: proofs.subject(peer),
                proofs,
                peer,
                ended,
            },
            outbound,
        ))
    }

    async fn on_message(&self, carrier: &mut Carrier, report: AgentToServer) -> Reply {
        // An enrolment request through a Gateway (ADR-0039 clause 12); counted in the Gateway's
        // enrolment aggregate and, once checked, by the bootstrap certificate it names (clause 6).
        let through_gateway = self.enrolment_through_gateway(carrier, &report);
        // Before anything else: enrolment, the CSR, and the fleet lock (ADR-0013 clause 21).
        if self.over_rate(
            carrier,
            Some(&report.instance_uid),
            through_gateway.as_ref(),
        ) {
            return Reply::Send(unavailable(&report.instance_uid, THROTTLED));
        }
        if let Some(enrolling) = &carrier.enrolling {
            return Reply::Send(self.enrol(enrolling, &report));
        }
        if through_gateway.is_some() {
            return Reply::Send(self.enrol_through_gateway(carrier, &report));
        }
        let csr = report
            .connection_settings_request
            .as_ref()
            .and_then(|request| request.opamp.as_ref())
            .is_some_and(|opamp| opamp.certificate_request.is_some());
        if csr {
            if let Some(revocations) = self.0.revocations() {
                // A session whose proof was revoked a moment ago is not handed a certificate
                // before its guard closes it (ADR-0021 clause 35).
                if carrier.proofs.revoked(revocations) {
                    return Reply::Send(bad_request("this connection is no longer admitted"));
                }
            }
        }
        // The connection's own certificate, whatever the message claims to be: behind a Gateway
        // that is the Gateway's, which renews nothing without a renewal proof (ADR-0039).
        let presented = carrier
            .proofs
            .certificate
            .as_ref()
            .map(|(id, not_after_ms)| Presented {
                id: id.clone(),
                host: carrier.proofs.host.clone(),
                subject_values: carrier.proofs.subject_values.clone(),
                not_after_ms: *not_after_ms,
            });
        let outcome =
            self.0
                .process_presented(report, carrier.transport, carrier.conn, presented.as_ref());
        if let (Some(uid), Some(_)) = (outcome.uid, carrier.conn) {
            if outcome.disconnected {
                carrier.seen.retain(|s| s != &uid);
            } else if !carrier.seen.contains(&uid) {
                carrier.seen.push(uid);
            }
        }
        Reply::Send(outcome.reply)
    }

    fn on_outbound(&self, carrier: &mut Carrier, push: Push) -> Vec<ServerToAgent> {
        if let (Push::Enrolment, Some(enrolling)) = (push, &carrier.enrolling) {
            // A decision reached while the host waits: an approval is handed over at once.
            let Some(request) = enrolling.request.lock().expect("request lock").clone() else {
                return Vec::new();
            };
            let Some(enrolment) = self.0.enrolment() else {
                return Vec::new();
            };
            let uid = enrolling.instance_uid.lock().expect("uid lock").clone();
            return match enrolment.submit(request, enrolling.requester.clone()) {
                Submitted::Issued(cert) => vec![self.0.enrolment_answer(&uid, Some(cert))],
                _ => Vec::new(),
            };
        }
        let mut messages = Vec::new();
        for uid in &carrier.seen {
            // A queued restart goes first, as its own message — the Baseline's command message is
            // never combined with an offer.
            if let Some(command) = self.0.restart_command_for(uid) {
                debug!(agent = %uid, "pushing a restart command");
                messages.push(command);
            }
            if let Some(offer) = self.0.offer_for(uid) {
                debug!(agent = %uid, "pushing a configuration offer");
                messages.push(offer);
            }
        }
        messages
    }

    fn on_unreadable(&self, carrier: &mut Carrier, _error: &Unreadable) -> Reply {
        // It names no Agent, so its reply reaches none (ADR-0013 clause 25).
        if self.over_rate(carrier, None, None) {
            return Reply::Send(unavailable(&[], THROTTLED));
        }
        Reply::Send(bad_request(match carrier.transport {
            Transport::Http => "the request body is not a valid AgentToServer message",
            Transport::WebSocket => "the frame is not a valid OpAMP message",
        }))
    }

    fn closing(&self, carrier: &Carrier) -> Option<Closing> {
        let reason = (*carrier.ended.lock().expect("ended lock"))?;
        Some(Closing::policy(reason))
    }

    /// The connection is gone; every Agent it carried is unreachable until it reports again.
    /// An enrolling host was never one of the fleet's Agents, so there is nothing to mark.
    fn on_closed(&self, carrier: Carrier) {
        if let Some(conn) = carrier.conn {
            self.0.mark_disconnected(&carrier.seen, conn);
        }
    }
}

/// An enrolment request through a Gateway, as the throttle keys it (ADR-0039 clause 13).
enum Relayed {
    /// Its proof embeds a certificate a bootstrap CA of `[enrolment]` issued: its own bucket.
    Checked(CertId),
    /// Its proof embeds no such certificate, or does not parse: the enrolment aggregate alone, and
    /// refused.
    Unchecked,
}

impl Fleet {
    /// Takes the message's token (ADR-0013) — for an enrolment request through a Gateway, from the
    /// Gateway's enrolment aggregate and the bucket of the bootstrap certificate it names, once
    /// checked (ADR-0039 clause 13) — and records a message past the limit.
    fn over_rate(
        &self,
        carrier: &Carrier,
        instance_uid: Option<&[u8]>,
        enrolment: Option<&Relayed>,
    ) -> bool {
        let Some(agent_rate) = self.0.agent_rate() else {
            return false;
        };
        let revocations = self.0.revocations();
        let gateway = is_gateway(&carrier.subject, revocations);
        let taken = match enrolment {
            Some(relayed) => agent_rate.admit_enrolment(
                &carrier.subject,
                gateway,
                match relayed {
                    Relayed::Checked(bootstrap) => Some(bootstrap),
                    Relayed::Unchecked => None,
                },
            ),
            None => agent_rate.admit(&carrier.subject, gateway, instance_uid),
        };
        let Err(bucket) = taken else {
            return false;
        };
        debug!(bucket = bucket.as_str(), "a message past the rate limit");
        let uid = instance_uid
            .filter(|uid| InstanceUid::from_wire(uid).is_some())
            .map(hex::encode);
        self.0.audit_refusal(
            carrier
                .proofs
                .throttled_entry(carrier.peer, revocations, bucket)
                .with("instance_uid", uid)
                .with("route", "opamp")
                .with("transport", carrier.transport.as_str()),
        );
        true
    }

    /// One message on an enrolment connection (ADR-0021 clause 21). Nothing in it is read but the
    /// certificate signing request: no Agent record is created and nothing is offered but the
    /// issued certificate.
    fn enrol(&self, enrolling: &Enrolling, report: &AgentToServer) -> ServerToAgent {
        let Some(enrolment) = self.0.enrolment() else {
            return bad_request("this Server does not enrol");
        };
        // A session whose bootstrap certificate was revoked a moment ago neither queues a request
        // nor collects a certificate before its guard closes it (ADR-0021 clause 35).
        if self.0.revocations().is_some_and(|revocations| {
            revocations.is_certificate_revoked(&enrolling.requester.bootstrap)
        }) {
            return bad_request("this connection is no longer admitted");
        }
        *enrolling.instance_uid.lock().expect("uid lock") = report.instance_uid.clone();
        let Some(csr) = report
            .connection_settings_request
            .as_ref()
            .and_then(|request| request.opamp.as_ref())
            .and_then(|opamp| opamp.certificate_request.as_ref())
        else {
            // The capabilities say a request may be sent; nothing else is answered.
            return self.0.enrolment_answer(&report.instance_uid, None);
        };
        // A request claiming another identity never reaches the queue (ADR-0021), nor does one
        // proving another bootstrap certificate than the handshake's (ADR-0039 clause 9).
        let request = match String::from_utf8(csr.csr.clone())
            .map_err(|_| "the certificate signing request is not PEM".to_string())
            .and_then(|pem| {
                crate::ca::check_claims(&pem, &report.instance_uid)?;
                proves_the_handshake(&pem, &enrolling.requester)?;
                crate::ca::enrolment_request(&pem, &report.instance_uid)
            }) {
            Ok(request) => request,
            Err(e) => return bad_request(&e),
        };
        *enrolling.request.lock().expect("request lock") = Some(request.clone());
        self.file(
            enrolment,
            request,
            &enrolling.requester,
            &report.instance_uid,
        )
    }

    /// Whether a message is an enrolment request through a Gateway (ADR-0039 clause 12): a CSR
    /// carrying a bootstrap proof over the certificate of a host marked as a Gateway, unless the
    /// proof names that certificate itself — then it is the Gateway's own CSR, which `renews`
    /// decides; it names that certificate only when it embeds it byte for byte. Its certificate is
    /// checked as cheaply as the throttle allows before it keys a bucket (clause 6): it parses, and
    /// it is one a bootstrap CA of `[enrolment]` issued as the handshake checks one — its issuer,
    /// that CA's signature over it, `CA:FALSE`, its validity, and the `clientAuth` extended key
    /// usage where it names any ([`Issuers::bootstrap_issued`]). The proof itself is checked by
    /// [`enrol_through_gateway`].
    ///
    /// [`enrol_through_gateway`]: Self::enrol_through_gateway
    /// [`Issuers::bootstrap_issued`]: crate::tls::Issuers::bootstrap_issued
    fn enrolment_through_gateway(
        &self,
        carrier: &Carrier,
        report: &AgentToServer,
    ) -> Option<Relayed> {
        if carrier.enrolling.is_some() || !is_gateway(&carrier.subject, self.0.revocations()) {
            return None;
        }
        let csr = report
            .connection_settings_request
            .as_ref()?
            .opamp
            .as_ref()?
            .certificate_request
            .as_ref()?;
        // A request that is not one PEM block is refused where any CSR is.
        let pem = std::str::from_utf8(&csr.csr).ok()?;
        fleet_core::csr::der(pem.as_bytes()).ok()?;
        let der = match crate::ca::bootstrap_proof_certificate(pem) {
            Ok(None) => return None,
            Ok(Some(der)) => der,
            Err(_) => return Some(Relayed::Unchecked),
        };
        // The very certificate presented, byte for byte: an issuer and serial alone are anyone's
        // to copy into a certificate of their own.
        if carrier.proofs.der.as_deref() == Some(der.as_slice()) {
            return None;
        }
        Some(match self.1.bootstrap_issued(&der) {
            Ok(Peer::Enrolling { id, .. }) => Relayed::Checked(id),
            _ => Relayed::Unchecked,
        })
    }

    /// An enrolment request through a Gateway (ADR-0039 clause 12): decided as any enrolment. The
    /// proof is checked — a bootstrap certificate of `[enrolment]`, valid, not revoked, its key
    /// having signed the request's (ADR-0039 clause 8) — and the request is filed under the
    /// certificate it proves, naming the Gateway's host in place of a peer address. Nothing in the
    /// message is read but the certificate signing request, and no Agent record is made. Every
    /// answer is addressed to the message's `instance_uid`, by which the Gateway routes it back.
    fn enrol_through_gateway(&self, carrier: &Carrier, report: &AgentToServer) -> ServerToAgent {
        let uid = &report.instance_uid;
        let gateway = carrier.proofs.host.clone();
        let refuse = |e: &str| {
            info!(gateway = gateway.as_deref().unwrap_or(""), error = %e, "refused an enrolment request through a Gateway");
            self.0.audit_refusal(
                Entry::new("enrolment.refused", "refused")
                    .with("gateway", gateway.clone())
                    .with("reason", e.to_string())
                    .with("instance_uid", hex::encode(uid)),
            );
            let mut reply = bad_request(e);
            reply.instance_uid.clone_from(uid);
            reply
        };
        let Some(enrolment) = self.0.enrolment() else {
            return refuse("this Server does not enrol");
        };
        if self
            .0
            .revocations()
            .is_some_and(|revocations| carrier.proofs.revoked(revocations))
        {
            return refuse("this connection is no longer admitted");
        }
        let Some(csr) = report
            .connection_settings_request
            .as_ref()
            .and_then(|request| request.opamp.as_ref())
            .and_then(|opamp| opamp.certificate_request.as_ref())
        else {
            return refuse("the message carries no certificate signing request");
        };
        let filed = String::from_utf8(csr.csr.clone())
            .map_err(|_| "the certificate signing request is not PEM".to_string())
            .and_then(|pem| {
                crate::ca::check_claims(&pem, uid)?;
                let der = crate::ca::bootstrap_proof(&pem)?
                    .ok_or_else(|| "the bootstrap proof does not parse".to_string())?;
                let Peer::Enrolling {
                    subject,
                    carried,
                    fingerprint,
                    id,
                } = self
                    .1
                    .bootstrap_issued(&der)
                    .map_err(|why| format!("the bootstrap proof does not hold: {why}"))?
                else {
                    return Err("the bootstrap proof does not hold".to_string());
                };
                if self
                    .0
                    .revocations()
                    .is_some_and(|revocations| revocations.is_certificate_revoked(&id))
                {
                    return Err(
                        "the bootstrap proof does not hold: its certificate is revoked".to_string(),
                    );
                }
                let requester = Requester {
                    bootstrap_subject: subject,
                    carried: *carried,
                    bootstrap_fingerprint: fingerprint,
                    bootstrap: id,
                    peer: None,
                    gateway: gateway.clone(),
                };
                Ok((crate::ca::enrolment_request(&pem, uid)?, requester))
            });
        match filed {
            Ok((request, requester)) => self.file(enrolment, request, &requester, uid),
            Err(e) => refuse(&e),
        }
    }

    /// Takes in an enrolment request, or answers it once it has been decided (ADR-0021 clauses
    /// 21, 22): what both an enrolment connection and a Gateway's relay are answered.
    fn file(
        &self,
        enrolment: &Enrolment,
        request: crate::enrolment::Request,
        requester: &Requester,
        instance_uid: &[u8],
    ) -> ServerToAgent {
        let key = request.key_fingerprint.clone();
        let new = !enrolment.pending().iter().any(|pending| pending.id == key);
        let subject = request.subject.clone();
        let answer = match enrolment.submit(request, requester.clone()) {
            Submitted::Waiting => {
                info!(key = %key, "an enrolment request waits for an operator");
                if let (true, Some(audit)) = (new, self.0.audit()) {
                    audit.refusal(
                        Entry::new("enrolment.queued", "queued")
                            .peer(requester.peer)
                            .with("gateway", requester.gateway.clone())
                            .with("id", key.clone())
                            .with("subject", subject)
                            .with("bootstrap_subject", requester.bootstrap_subject.clone())
                            .with("instance_uid", hex::encode(instance_uid)),
                    );
                }
                self.0.enrolment_answer(instance_uid, None)
            }
            Submitted::Issued(cert) => {
                info!(key = %key, "handed an enrolling host its certificate");
                self.0.enrolment_answer(instance_uid, Some(cert))
            }
            Submitted::Rejected => bad_request("an operator rejected this enrolment request"),
            Submitted::Full => {
                unavailable(instance_uid, "the enrolment queue is full — retry later")
            }
            Submitted::OverShare { first } => {
                // Audited once per certificate and window (ADR-0046): a host re-sending its
                // refused request does not flood the record.
                if let (true, Some(audit)) = (first, self.0.audit()) {
                    audit.refusal(
                        Entry::new("enrolment.refused", "refused")
                            .peer(requester.peer)
                            .with("gateway", requester.gateway.clone())
                            .with("reason", "bootstrap_share")
                            .with("bootstrap_serial", requester.bootstrap.serial.clone())
                            .with("bootstrap_subject", requester.bootstrap_subject.clone()),
                    );
                }
                unavailable(
                    instance_uid,
                    "this bootstrap certificate holds its share of the enrolment queue — retry \
                     later",
                )
            }
            Submitted::Closed => unavailable(instance_uid, "no enrolment window is open"),
        };
        // Addressed to the message, so a Gateway routes even a refusal back (ADR-0039 clause 5).
        ServerToAgent {
            instance_uid: instance_uid.to_vec(),
            ..answer
        }
    }
}

/// Whether a request on an enrolment connection proves the certificate of its handshake (ADR-0039
/// clause 3): a bootstrap proof there must name that certificate, and hold; a request without one
/// proves the handshake's certificate alone.
///
/// # Errors
/// Returns the `BadRequest` text for a proof that does not hold or names another certificate.
fn proves_the_handshake(csr_pem: &str, handshake: &Requester) -> Result<(), String> {
    use sha2::{Digest as _, Sha256};
    match crate::ca::bootstrap_proof(csr_pem)? {
        Some(der) if hex::encode(Sha256::digest(&der)) != handshake.bootstrap_fingerprint => Err(
            "the bootstrap proof names another certificate than the one this connection presented"
                .to_string(),
        ),
        _ => Ok(()),
    }
}
