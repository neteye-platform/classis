//! The OpAMP endpoint — both transports on one path (ADR-0013).
//!
//! `/v1/opamp` serves the whole protocol: a request carrying the protobuf `Content-Type` is the
//! plain-HTTP transport, a WebSocket upgrade is the other — exactly the detection the Baseline
//! describes. The communication is `opamp::server`'s, shared with the Gateway and the Supervisor
//! Endpoint (ADR-0010); what is the Server's is the [`Fleet`] handler, which hands every decoded
//! report to the same [`AppState::process_for_host`], so transport is carriage, never semantics.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::server::{Handler, Outbound, Rejection, Reply, RequestInfo, Settings, Unreadable};
use opamp::uid::InstanceUid;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::agent_rate::{AgentRate, Subject};
use crate::fleet::{bad_request, unavailable, AppState, ConnId, Transport};

/// The endpoint path the Baseline names as the default, and the protobuf media type it requires —
/// both from the shared crate, because the Gateway serves the same endpoint (ADR-0010).
pub use opamp::endpoint::{OPAMP_PATH, PROTOBUF_CONTENT_TYPE};

/// What admitted a connection: the host it arrived over, when one did. Nothing admits a connection
/// at present, so a request carries none and every message is counted by its peer address.
#[derive(Clone, Debug, Default)]
pub struct Proofs {
    pub host: Option<String>,
}

impl Proofs {
    /// Who a connection's messages are counted for (ADR-0013 clause 22): the host it arrived over,
    /// else the peer.
    fn subject(&self, peer: Option<IpAddr>) -> Subject {
        match &self.host {
            Some(host) => Subject::Host(host.clone()),
            None => Subject::peer(peer),
        }
    }
}

/// What a message past the limit is answered (ADR-0013 clause 23).
const THROTTLED: &str = "too many messages arrive from this sender — retry later";

pub fn router(state: Arc<AppState>) -> Router {
    // The limits the Baseline requires of the Server, on both transports and in both directions.
    let settings = Settings::new(state.max_message_size());
    opamp::server::router(Arc::new(Fleet(state)), settings)
}

/// Counts every download against the sender's rate (ADR-0013 clause 21); without a limit the
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

/// The peer's address, as the listener put it into the request.
pub fn peer_ip(request: &Request) -> Option<std::net::IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
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
    /// The Agents this socket carried, any number of them told apart by `instance_uid` alone
    /// (ADR-0015), so all of them are marked unreachable when it goes.
    seen: Vec<InstanceUid>,
    /// The host the connection arrived over, when one is named.
    host: Option<String>,
    /// Where the connection comes from.
    peer: Option<IpAddr>,
    /// Who its messages are counted for (ADR-0013 clause 22).
    subject: Subject,
}

/// A WebSocket session's outbound side: it hears of every change to the fleet's desired state —
/// the "within seconds" of the control loop.
struct Session(watch::Receiver<u64>);

/// One occasion to push.
struct Push;

impl Outbound for Session {
    type Item = Push;

    async fn next(&mut self) -> Option<Push> {
        self.0.changed().await.ok().map(|()| Push)
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
            // `info` (ADR-0022 clause 3).
            info!(
                event = "session.started",
                peer = peer.map(tracing::field::display),
                "a WebSocket session starts"
            );
        }
        let (transport, conn, outbound) = if websocket {
            (
                Transport::WebSocket,
                Some(self.0.connection_id()),
                Some(Session(self.0.subscribe())),
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
        // It names no Agent, so its reply reaches none (ADR-0013 clause 25).
        if self.over_rate(carrier, None) {
            return Reply::Send(unavailable(&[], THROTTLED));
        }
        Reply::Send(bad_request(match carrier.transport {
            Transport::Http => "the request body is not a valid AgentToServer message",
            Transport::WebSocket => "the frame is not a valid OpAMP message",
        }))
    }

    /// The connection is gone; every Agent it carried is unreachable until it reports again.
    fn on_closed(&self, carrier: Carrier) {
        if let Some(conn) = carrier.conn {
            self.0.mark_disconnected(&carrier.seen, conn);
        }
    }
}

impl Fleet {
    /// Takes the message's token (ADR-0013) and logs a message past the limit.
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
