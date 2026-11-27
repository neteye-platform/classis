//! The OpAMP endpoint — both transports on one path.
//!
//! `/v1/opamp` serves the whole protocol: a request carrying the protobuf `Content-Type` is the
//! plain-HTTP transport, a WebSocket upgrade is the other — exactly the detection the Baseline
//! describes. The communication is `opamp::server`'s, shared with the Supervisor Endpoint; what is
//! the Server's is the [`Fleet`] handler, which hands every decoded report to the same
//! [`AppState::process_for_host`], so transport is carriage, never semantics.
//!
//! Admission is a layer round the endpoint and the download route:
//! [`admit`] reads the Bearer credential and hands what it proves on as [`Proofs`], and
//! [`back_off`] round the whole Agent plane counts its refusals per peer address.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::{
    Closing, Handler, Outbound, Rejection, Reply, RequestInfo, Settings, Unreadable,
};
use opamp::uid::InstanceUid;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::agent_rate::{AgentRate, Subject};
use crate::enrolment::{Enrolment, SessionWatch, ENROL_PATH, TOKEN_PATH};
use crate::fleet::{bad_request, unavailable, AppState, ConnId, Transport};
use crate::throttle::Throttle;

/// The endpoint path the Baseline names as the default, and the protobuf media type it requires —
/// both from the shared crate, because the Supervisor Endpoint serves the same protocol.
pub use opamp::endpoint::{OPAMP_PATH, PROTOBUF_CONTENT_TYPE};

/// What admitted a connection: the host it arrived over, when one did — the `client_id` of the
/// client holding the token it presented. A request without one is counted by
/// its peer address.
#[derive(Clone, Debug, Default)]
pub struct Proofs {
    pub host: Option<String>,
}

impl Proofs {
    /// Who a connection's messages are counted for: the host it arrived over,
    /// else the peer.
    fn subject(&self, peer: Option<IpAddr>) -> Subject {
        match &self.host {
            Some(host) => Subject::Host(host.clone()),
            None => Subject::peer(peer),
        }
    }
}

/// What a message past the limit is answered.
const THROTTLED: &str = "too many messages arrive from this sender — retry later";

pub fn router(state: Arc<AppState>) -> Router {
    // The limits the Baseline requires of the Server, on both transports and in both directions.
    let settings = Settings::new(state.max_message_size());
    opamp::server::router(Arc::new(Fleet(state)), settings)
}

/// Admits every request of `router` by its Bearer credential: every plain-HTTP
/// exchange and every download, and a WebSocket session once, at its upgrade. What the token
/// proves — the host — reaches the handlers as [`Proofs`].
pub fn admit(router: Router, enrolment: Arc<Enrolment>) -> Router {
    router.layer(middleware::from_fn_with_state(enrolment, admit_request))
}

async fn admit_request(
    State(enrolment): State<Arc<Enrolment>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = peer_ip(&request);
    // Read as the endpoint reads it, so that no request it upgrades is admitted as plain HTTP.
    let websocket =
        opamp::server::header_has_token(request.headers(), &header::UPGRADE, "websocket");
    match enrolment
        .admit(request.headers(), request.uri(), websocket)
        .await
    {
        Ok(admitted) => {
            // At `debug`: a plain-HTTP poll comes every few seconds, and a request that asks for
            // an upgrade is not yet a session — the endpoint may refuse it. A session is logged
            // once it is accepted (`session.started`).
            debug!(
                event = "admission.admitted",
                peer = peer.map(tracing::field::display),
                transport = if websocket { "websocket" } else { "http" },
                client = %admitted.client_id,
                "admitted a request"
            );
            request.extensions_mut().insert(Proofs {
                host: Some(admitted.client_id),
            });
            if let Some(watch) = admitted.watch {
                request.extensions_mut().insert(watch);
            }
            next.run(request).await
        }
        Err(refused) => {
            // At `debug`: a peer that was not admitted repeats a refusal at will. Which check
            // refused, never the presented value.
            debug!(
                event = "admission.refused",
                peer = peer.map(tracing::field::display),
                check = refused.check(),
                "refused admission"
            );
            refused.into_response()
        }
    }
}

/// The per-peer back-off of the Agent plane round `router`: a peer in back-off
/// is answered `429` before anything else is checked, and every refused authentication — a `401`,
/// or a Bearer `400 invalid_request` — counts as a failure of the peer's address. A refusal that
/// comes after authentication, such as `invalid_client_metadata`, counts for nothing, and a success
/// clears nothing.
pub fn back_off(router: Router, throttle: Arc<Throttle>) -> Router {
    router.layer(middleware::from_fn_with_state(throttle, count_refusals))
}

async fn count_refusals(
    State(throttle): State<Arc<Throttle>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = peer_ip(&request);
    if let Some(wait) = peer.and_then(|peer| throttle.retry_after(peer)) {
        debug!(
            event = "admission.throttled",
            peer = peer.map(tracing::field::display),
            "refused: the address is in back-off"
        );
        return throttled(wait);
    }
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    let status = response.status();
    // At `debug`: a peer repeats a refused request at will.
    if status.is_client_error() {
        if path == ENROL_PATH {
            debug!(
                event = "enrolment.refused",
                peer = peer.map(tracing::field::display),
                status = status.as_u16(),
                "refused an enrolment request"
            );
        } else if path == TOKEN_PATH {
            debug!(
                event = "token.refused",
                peer = peer.map(tracing::field::display),
                status = status.as_u16(),
                "refused a token request"
            );
        }
    }
    let authentication_refused = status == StatusCode::UNAUTHORIZED
        || (status == StatusCode::BAD_REQUEST
            && response.headers().contains_key(header::WWW_AUTHENTICATE));
    if let (true, Some(peer)) = (authentication_refused, peer) {
        throttle.failed(peer);
    }
    response
}

/// Counts every download against the sender's rate; without a limit the
/// route is served as it is.
pub fn limit_downloads(router: Router, agent_rate: Option<Arc<AgentRate>>) -> Router {
    match agent_rate {
        Some(agent_rate) => router.layer(middleware::from_fn_with_state(agent_rate, rate_download)),
        None => router,
    }
}

async fn rate_download(
    State(agent_rate): State<Arc<AgentRate>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = peer_ip(&request);
    let proofs = request.extensions().get::<Proofs>().cloned();
    let subject = proofs.clone().unwrap_or_default().subject(peer);
    if !agent_rate.admit(&subject) {
        debug!(
            event = "agent_rate.throttled",
            route = "download",
            peer = peer.map(tracing::field::display),
            host = proofs.and_then(|proofs| proofs.host),
            "a download past the rate limit"
        );
        return over_rate();
    }
    next.run(request).await
}

/// The answer to a download past the sender's rate: `429`, retry in 30 s.
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

/// The peer's address: the right-most valid address of `X-Forwarded-For` when the request has the
/// header, else the address of the connection the listener put into the request.
///
/// The Server is reached through a reverse proxy, which appends the address it saw to the header
/// (or replaces the header with it): the right-most entry is the one the proxy wrote. Every entry
/// to its left was sent by the client, who can name any address there — so only the right-most
/// is trusted, and the manual requires a proxy that writes it.
pub fn peer_ip(request: &Request) -> Option<IpAddr> {
    forwarded_for(request.headers()).or_else(|| {
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
    })
}

/// The last entry of the `X-Forwarded-For` values, in the order they were sent, when it is an
/// address: a bare address, an address with a port, or a bracketed IPv6 address. An earlier entry
/// is never reached for when the last is not one — it is the client's.
fn forwarded_for(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .next_back()
        .and_then(|entry| {
            entry
                .parse::<IpAddr>()
                .ok()
                .or_else(|| entry.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
                .or_else(|| {
                    entry
                        .strip_prefix('[')
                        .and_then(|rest| rest.strip_suffix(']'))
                        .and_then(|inner| inner.parse::<IpAddr>().ok())
                })
        })
}

/// The answer while the Server cannot take a decision now — too many password hashes under way on
/// the Operator plane: `503`, try again in a second.
pub fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1".to_string())],
        "the Server cannot take this now — retry in a moment",
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

/// The Server's handler behind the endpoint: every report goes to the fleet, and a WebSocket is
/// also sent what the fleet wants its Agents to have when that changes.
struct Fleet(Arc<AppState>);

/// One connection as the fleet sees it.
struct Carrier {
    transport: Transport,
    /// This connection's identity — what the duplicate detection tells connections apart by. Plain
    /// HTTP is stateless polling, so there is none to pass.
    conn: Option<ConnId>,
    /// The Agents this socket carried, any number of them told apart by `instance_uid` alone, so
    /// all of them are marked unreachable when it goes.
    seen: Vec<InstanceUid>,
    /// The host the connection arrived over, when one is named.
    host: Option<String>,
    /// Where the connection comes from.
    peer: Option<IpAddr>,
    /// Who its messages are counted for.
    subject: Subject,
    /// Why the session was ended, once its [`Session`] has ended it.
    ended: Arc<Mutex<Option<&'static str>>>,
}

/// Why a session ends when the token it was admitted with is replaced.
const TOKEN_REPLACED: &str = "token replaced";

/// A WebSocket session's outbound side: it hears of every change to the fleet's desired state —
/// the "within seconds" of the control loop — and ends when the token it was admitted with is
/// replaced. It does not end when that token merely expires.
struct Session {
    changes: watch::Receiver<u64>,
    token: Option<SessionWatch>,
    client: Option<String>,
    ended: Arc<Mutex<Option<&'static str>>>,
}

/// One occasion to push.
struct Push;

impl Outbound for Session {
    type Item = Push;

    async fn next(&mut self) -> Option<Push> {
        let Session {
            changes,
            token,
            client,
            ended,
        } = self;
        let Some(token) = token else {
            return changes.changed().await.ok().map(|()| Push);
        };
        tokio::select! {
            changed = changes.changed() => changed.ok().map(|()| Push),
            () = token.replaced() => {
                info!(
                    event = "session.ended",
                    reason = TOKEN_REPLACED,
                    client = client.as_deref(),
                    "ending a session"
                );
                *ended.lock().expect("ended lock") = Some(TOKEN_REPLACED);
                None
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
        let websocket = request.transport == opamp::server::Transport::WebSocket;
        let peer = request.peer.map(|peer| peer.ip());
        if websocket {
            // The endpoint has checked the upgrade and is about to accept it: a session, at
            // `info`.
            info!(
                event = "session.started",
                peer = peer.map(tracing::field::display),
                client = proofs.host.as_deref(),
                "a WebSocket session starts"
            );
        }
        let ended = Arc::new(Mutex::new(None));
        let (transport, conn, outbound) = if websocket {
            (
                Transport::WebSocket,
                Some(self.0.connection_id()),
                Some(Session {
                    changes: self.0.subscribe(),
                    token: request.extensions.get::<SessionWatch>().cloned(),
                    client: proofs.host.clone(),
                    ended: ended.clone(),
                }),
            )
        } else {
            (Transport::Http, None, None)
        };
        Ok((
            Carrier {
                transport,
                conn,
                seen: Vec::new(),
                subject: proofs.subject(peer),
                host: proofs.host,
                peer,
                ended,
            },
            outbound,
        ))
    }

    async fn on_message(&self, carrier: &mut Carrier, report: AgentToServer) -> Reply {
        if self.over_rate(carrier, Some(&report.instance_uid)) {
            return Reply::Send(unavailable(&report.instance_uid, THROTTLED));
        }
        let outcome = self.0.process_for_host(
            report,
            carrier.transport,
            carrier.conn,
            carrier.host.as_deref(),
        );
        if let (Some(uid), Some(_)) = (outcome.uid, carrier.conn) {
            if outcome.disconnected {
                carrier.seen.retain(|s| s != &uid);
            } else if !carrier.seen.contains(&uid) {
                carrier.seen.push(uid);
            }
        }
        Reply::Send(outcome.reply)
    }

    fn on_outbound(&self, carrier: &mut Carrier, _push: Push) -> Vec<ServerToAgent> {
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
        // It names no Agent, so its reply reaches none.
        if self.over_rate(carrier, None) {
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
    fn on_closed(&self, carrier: Carrier) {
        if let Some(conn) = carrier.conn {
            self.0.mark_disconnected(&carrier.seen, conn);
        }
    }
}

impl Fleet {
    /// Takes the message's token and logs a message past the limit.
    fn over_rate(&self, carrier: &Carrier, instance_uid: Option<&[u8]>) -> bool {
        let Some(agent_rate) = self.0.agent_rate() else {
            return false;
        };
        if agent_rate.admit(&carrier.subject) {
            return false;
        }
        let uid = instance_uid
            .filter(|uid| InstanceUid::from_wire(uid).is_some())
            .map(hex::encode);
        debug!(
            event = "agent_rate.throttled",
            route = "opamp",
            peer = carrier.peer.map(tracing::field::display),
            host = carrier.host.as_deref(),
            instance_uid = uid,
            transport = carrier.transport.as_str(),
            "a message past the rate limit"
        );
        true
    }
}
