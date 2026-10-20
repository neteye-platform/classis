//! One OpAMP server endpoint, for every surface that speaks the Server side of the protocol
//! (ADR-0010). Behind the `server` feature.
//!
//! This crate carries the communication and nothing else: it tells a WebSocket upgrade from a
//! plain-HTTP exchange as the specification describes, applies the media type, gzip and the
//! receive limit on both transports, frames WebSocket messages, closes with 1009 on an oversized
//! one, and never puts an oversized reply on the wire. What a message *means* is the
//! application's: it implements [`Handler`], and the endpoint calls it.
//!
//! [`router`] hands out an axum [`Router`], so a surface can add its admission layers and
//! neighbouring routes. [`listen`] serves the result, with its TLS and its bounds on connection
//! setup.

pub mod listen;
pub mod pace;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::endpoint::{BodyError, OPAMP_PATH, PROTOBUF_CONTENT_TYPE};
use crate::frame::{self, FrameError};
use crate::proto::{AgentToServer, ServerToAgent};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, Extensions, HeaderMap, StatusCode, Version};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, MethodRouter};
use axum::Router;
use futures_util::{SinkExt as _, StreamExt as _};
use prost::Message as _;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::warn;

/// The transport one connection arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    WebSocket,
    /// One plain-HTTP exchange: a request carrying one report, a response carrying one reply.
    Http,
}

/// Which transports an endpoint serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transports {
    Both,
    WebSocketOnly,
}

/// How an endpoint is served.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The largest message accepted or sent, on both transports — after decompression on plain
    /// HTTP, framing header included on a WebSocket.
    pub max_message_size: usize,
    pub transports: Transports,
    /// Answer on any path instead of the specification's `/v1/opamp` only — for an endpoint that
    /// serves exactly one local client and has nothing to route by.
    pub any_path: bool,
}

impl Settings {
    /// Both transports on `/v1/opamp`, with the given limit.
    #[must_use]
    pub fn new(max_message_size: usize) -> Self {
        Settings {
            max_message_size,
            transports: Transports::Both,
            any_path: false,
        }
    }
}

/// What a handler sees of a new connection, to accept or refuse it by.
pub struct RequestInfo<'a> {
    pub transport: Transport,
    pub headers: &'a HeaderMap,
    /// The request's extensions — where a TLS acceptor puts the peer certificate.
    pub extensions: &'a Extensions,
    /// The peer, when the listener was served with connect info.
    pub peer: Option<SocketAddr>,
}

/// What the endpoint does with one message the handler was given.
// Returned once per message and moved straight to the wire, never stored: boxing the message would
// cost an allocation per reply to save stack space nobody holds on to.
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    /// Send this message.
    Send(ServerToAgent),
    /// Send nothing. On plain HTTP the response then carries an empty `ServerToAgent`, since an
    /// exchange always has a response.
    Nothing,
    /// Refuse the exchange: on plain HTTP this status and text are the response; on a WebSocket
    /// nothing is sent and the connection stays open.
    Refuse(StatusCode, String),
}

/// A refused connection: the status, any headers to send with it (`WWW-Authenticate`,
/// `Retry-After`), and a sentence saying why.
pub struct Rejection {
    pub status: StatusCode,
    pub headers: Vec<(header::HeaderName, header::HeaderValue)>,
    pub message: String,
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.message).into_response();
        response.headers_mut().extend(self.headers);
        response
    }
}

/// Why a message could not be read — handed to [`Handler::on_unreadable`].
#[derive(Debug)]
pub enum Unreadable {
    /// A WebSocket frame that is not a framed OpAMP message.
    Frame(FrameError),
    /// A plain-HTTP body that is not an `AgentToServer`.
    Body(prost::DecodeError),
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreadable::Frame(e) => e.fmt(f),
            Unreadable::Body(e) => e.fmt(f),
        }
    }
}

/// What a connection is sent without being asked: it waits for the next occasion and yields it,
/// and [`Handler::on_outbound`] turns that into messages. `None` ends the connection.
pub trait Outbound: Send + 'static {
    type Item: Send;

    fn next(&mut self) -> impl Future<Output = Option<Self::Item>> + Send;
}

/// An endpoint whose connections are sent nothing unasked.
pub struct NoOutbound;

impl Outbound for NoOutbound {
    type Item = std::convert::Infallible;

    async fn next(&mut self) -> Option<Self::Item> {
        std::future::pending().await
    }
}

/// The application's half of an endpoint. The endpoint never calls two of these concurrently for
/// the same connection; it may for different connections.
pub trait Handler: Send + Sync + 'static {
    /// The application's own state for one connection — one plain-HTTP exchange, or one socket.
    type Connection: Send + 'static;
    /// What a WebSocket connection is sent unasked.
    type Outbound: Outbound;

    /// Accept a new connection, or refuse it with the response to send. The outbound side is
    /// asked for only on a WebSocket; return `None` for one that is sent nothing unasked.
    ///
    /// # Errors
    /// The refusal to answer with.
    fn on_connecting(
        &self,
        request: &RequestInfo<'_>,
    ) -> Result<(Self::Connection, Option<Self::Outbound>), Rejection>;

    /// One decoded message, and what to reply.
    fn on_message(
        &self,
        connection: &mut Self::Connection,
        message: AgentToServer,
    ) -> impl Future<Output = Reply> + Send;

    /// The messages one outbound occasion becomes.
    fn on_outbound(
        &self,
        connection: &mut Self::Connection,
        item: <Self::Outbound as Outbound>::Item,
    ) -> Vec<ServerToAgent>;

    /// A message that could not be decoded. By default it is dropped and the connection read on.
    fn on_unreadable(&self, _connection: &mut Self::Connection, _error: &Unreadable) -> Reply {
        Reply::Nothing
    }

    /// The close frame to send when the outbound side ends the connection; by default one with no
    /// code.
    fn closing(&self, _connection: &Self::Connection) -> Option<Closing> {
        None
    }

    /// The connection is gone: after its one exchange on plain HTTP, when the socket closes on a
    /// WebSocket.
    fn on_closed(&self, _connection: Self::Connection) {}
}

/// Why the endpoint closes a WebSocket: a close code of RFC 6455 and a reason for the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Closing {
    pub code: u16,
    pub reason: String,
}

impl Closing {
    /// `1008`: the connection violates the endpoint's policy — what a revoked proof does.
    #[must_use]
    pub fn policy(reason: &str) -> Self {
        Closing {
            code: u16::from(CloseCode::Policy),
            reason: reason.to_string(),
        }
    }
}

struct Endpoint<H> {
    handler: Arc<H>,
    limit: usize,
}

/// The endpoint for `handler`, as a router to serve or to merge into one.
pub fn router<H: Handler>(handler: Arc<H>, settings: Settings) -> Router {
    let endpoint = Arc::new(Endpoint {
        handler,
        limit: settings.max_message_size,
    });
    let methods: MethodRouter<Arc<Endpoint<H>>> = match settings.transports {
        Transports::Both => get(upgrade::<H>).post(exchange::<H>),
        Transports::WebSocketOnly => get(upgrade::<H>),
    };
    let router = if settings.any_path {
        Router::new().fallback(methods)
    } else {
        Router::new().route(OPAMP_PATH, methods)
    };
    router
        // The receive limit on the plain-HTTP transport: a body past it never reaches a handler,
        // and axum answers it with the 413 the specification prescribes.
        .layer(DefaultBodyLimit::max(settings.max_message_size))
        .with_state(endpoint)
}

fn peer_of(extensions: &Extensions) -> Option<SocketAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| *peer)
}

/// The WebSocket upgrade, answered here and taken over through hyper, so that `opamp` reads the
/// frames itself and can judge a message by its data (ADR-0010 clause 5).
async fn upgrade<H: Handler>(
    State(endpoint): State<Arc<Endpoint<H>>>,
    mut request: Request,
) -> Response {
    let refuse = |why: &str| (StatusCode::BAD_REQUEST, why.to_string()).into_response();
    // `get` routes HEAD here too; an upgrade is a GET (RFC 6455 §4.1).
    if request.method() != axum::http::Method::GET {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            "a WebSocket upgrade is a GET",
        )
            .into_response();
    }
    let headers = request.headers();
    let has_token = |name: &header::HeaderName, token: &str| {
        headers.get_all(name).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
        })
    };
    if request.version() != Version::HTTP_11 {
        return refuse("a WebSocket upgrade needs HTTP/1.1");
    }
    if !has_token(&header::CONNECTION, "upgrade") || !has_token(&header::UPGRADE, "websocket") {
        return refuse("expected a WebSocket upgrade");
    }
    if header_str(headers, &header::SEC_WEBSOCKET_VERSION) != "13" {
        return refuse("the WebSocket version must be 13");
    }
    let Some(key) = headers.get(header::SEC_WEBSOCKET_KEY) else {
        return refuse("the WebSocket key is missing");
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let info = RequestInfo {
        transport: Transport::WebSocket,
        headers,
        extensions: request.extensions(),
        peer: peer_of(request.extensions()),
    };
    let (connection, outbound) = match endpoint.handler.on_connecting(&info) {
        Ok(accepted) => accepted,
        Err(refusal) => return refusal.into_response(),
    };
    let floor = request.extensions().get::<pace::Pace>().copied();
    let Some(on_upgrade) = request
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>()
    else {
        endpoint.handler.on_closed(connection);
        return (
            StatusCode::UPGRADE_REQUIRED,
            "this connection cannot be upgraded",
        )
            .into_response();
    };
    let limit = endpoint.limit;
    // A session served by a `Listener` closes when the listener asks it to; one served any other
    // way runs until its peer leaves.
    let sessions = request.extensions().get::<listen::Sessions>().cloned();
    let session = {
        let sessions = sessions.clone();
        async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(e) => {
                    warn!(error = %e, "a WebSocket upgrade failed");
                    endpoint.handler.on_closed(connection);
                    return;
                }
            };
            let stream = pace::FrameMeter::new(hyper_util::rt::TokioIo::new(upgraded));
            // The transport's own guard, so an oversized frame is refused before it is buffered whole;
            // the loop still checks, because that is what turns the refusal into the 1009 close. The
            // per-frame cap moves with it: left at its default it would refuse messages *below* the
            // configured limit, which is the limit's business.
            let config = WebSocketConfig::default()
                .max_message_size(Some(limit))
                .max_frame_size(Some(limit));
            let socket = WebSocketStream::from_raw_socket(stream, Role::Server, Some(config)).await;
            let messages = floor.map(pace::Messages::new);
            serve_socket(socket, endpoint, connection, outbound, messages, sessions).await;
        }
    };
    match &sessions {
        Some(listener) => listener.spawn(session),
        None => {
            tokio::spawn(session);
        }
    }
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// One WebSocket connection, until the peer closes it, it fails, or its outbound side ends.
async fn serve_socket<H: Handler, S>(
    mut socket: WebSocketStream<pace::FrameMeter<S>>,
    endpoint: Arc<Endpoint<H>>,
    mut connection: H::Connection,
    mut outbound: Option<H::Outbound>,
    mut messages: Option<pace::Messages>,
    mut sessions: Option<listen::Sessions>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let handler = &endpoint.handler;
    let limit = endpoint.limit;
    // A listener that holds its connections to a floor (ADR-0013 clause 14) is judged once a window.
    let mut check = messages.as_ref().map(|messages| {
        let mut check = tokio::time::interval_at(
            tokio::time::Instant::now() + messages.window(),
            messages.window(),
        );
        // Checks a busy loop missed are not made up in a burst: two in a row would judge a message
        // by what arrived in no time at all.
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        check
    });
    loop {
        tokio::select! {
            // A shutdown comes first, so a peer that keeps sending cannot hold its session past it.
            // Then what has arrived is read before a check judges it, so bytes that waited on this
            // side while the loop was busy count for the peer.
            biased;
            () = next_closing(&mut sessions) => {
                // The listener is shutting down: the peer is told so, and reconnects to whatever
                // serves this endpoint next.
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Away,
                        reason: "the server is shutting down".into(),
                    })))
                    .await;
                break;
            }
            incoming = socket.next() => {
                let message = match incoming {
                    Some(Ok(message)) => message,
                    // The upgrade capped what this socket will buffer, so a peer past the limit
                    // surfaces here as a receive error rather than as a frame. Answer it with the
                    // 1009 close, and let the send fail harmlessly when the connection is simply
                    // gone or already closing.
                    Some(Err(e)) => {
                        warn!(error = %e, "closing the WebSocket after a receive error");
                        let _ = socket.send(too_big_close()).await;
                        break;
                    }
                    None => break,
                };
                let data = match message {
                    Message::Binary(data) => data,
                    Message::Close(_) => break,
                    // The library answers pings itself; pongs and text need nothing from us.
                    _ => continue,
                };
                let reply = match frame::decode::<AgentToServer>(&data, limit) {
                    Ok(report) => handler.on_message(&mut connection, report).await,
                    // An oversized frame is malformed, and the specification's answer to it is
                    // not an error message but the 1009 close.
                    Err(e @ FrameError::TooLarge(..)) => {
                        warn!(error = %e, "closing the WebSocket: the peer sent an oversized message");
                        let _ = socket.send(too_big_close()).await;
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "undecodable frame on the WebSocket transport");
                        handler.on_unreadable(&mut connection, &Unreadable::Frame(e))
                    }
                };
                if let Reply::Send(reply) = reply {
                    if !send_framed(&mut socket, &reply, limit).await {
                        break;
                    }
                }
            }
            item = next_outbound(&mut outbound) => {
                let Some(item) = item else {
                    let frame = handler.closing(&connection).map(|closing| CloseFrame {
                        code: CloseCode::from(closing.code),
                        reason: closing.reason.into(),
                    });
                    let _ = socket.send(Message::Close(frame)).await;
                    break;
                };
                let mut gone = false;
                for message in handler.on_outbound(&mut connection, item) {
                    if !send_framed(&mut socket, &message, limit).await {
                        gone = true;
                        break;
                    }
                }
                if gone {
                    break;
                }
            }
            scheduled = next_check(&mut check) => {
                let Some(messages) = messages.as_mut() else { continue };
                let now = socket.get_ref().progress();
                // A check this late means the loop was busy and read nothing meanwhile: the peer is
                // judged from here, not by what waited on this side.
                if scheduled.elapsed() > messages.window() / 4 {
                    messages.rebase(now);
                    continue;
                }
                if messages.check(now) {
                    warn!("closing the WebSocket: a message fell below its pace");
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Policy,
                            reason: "message below its pace".into(),
                        })))
                        .await;
                    break;
                }
            }
        }
    }
    handler.on_closed(connection);
}

/// Resolves when the listener asks its sessions to close; never, for a session without one.
async fn next_closing(sessions: &mut Option<listen::Sessions>) {
    match sessions {
        Some(sessions) => sessions.closing().await,
        None => std::future::pending().await,
    }
}

/// The next check of a paced socket, and when it was due; never, for one without a floor.
async fn next_check(check: &mut Option<tokio::time::Interval>) -> tokio::time::Instant {
    match check {
        Some(check) => check.tick().await,
        None => std::future::pending().await,
    }
}

async fn next_outbound<O: Outbound>(outbound: &mut Option<O>) -> Option<O::Item> {
    match outbound {
        Some(outbound) => outbound.next().await,
        None => std::future::pending().await,
    }
}

/// Sends one framed message under the size limit. A message that would exceed it is **not** sent —
/// the specification's MUST for the outbound direction — but discarded with a log line, since the
/// fault is on this end and the connection is fine. Returns `false` only when the connection is
/// gone.
async fn send_framed<S>(
    socket: &mut WebSocketStream<S>,
    message: &ServerToAgent,
    limit: usize,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match frame::encode_within(message, limit) {
        Ok(framed) => socket.send(Message::Binary(framed.into())).await.is_ok(),
        Err(e) => {
            warn!(error = %e, "discarding a message that exceeds the size limit");
            true
        }
    }
}

/// The close the specification names for a message past the size limit: 1009, Message Too Big.
fn too_big_close() -> Message {
    Message::Close(Some(CloseFrame {
        code: CloseCode::Size,
        reason: frame::TOO_BIG_CLOSE_REASON.into(),
    }))
}

/// One plain-HTTP exchange: protobuf `AgentToServer` in (gzip accepted — a MUST), protobuf
/// `ServerToAgent` out.
async fn exchange<H: Handler>(
    State(endpoint): State<Arc<Endpoint<H>>>,
    headers: HeaderMap,
    extensions: Extensions,
    body: Bytes,
) -> Response {
    let content_type = header_str(&headers, &header::CONTENT_TYPE);
    if !crate::endpoint::is_protobuf(content_type) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!(
                "the OpAMP plain-HTTP transport requires Content-Type: {PROTOBUF_CONTENT_TYPE}"
            ),
        )
            .into_response();
    }
    let limit = endpoint.limit;
    let raw = match crate::endpoint::decode_body(
        &body,
        header_str(&headers, &header::CONTENT_ENCODING),
        limit,
    ) {
        Ok(raw) => raw,
        Err(e @ BodyError::TooLarge) => {
            warn!(
                limit,
                "rejecting a request body that decompresses past the limit"
            );
            return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response();
        }
        Err(e @ BodyError::UndecodableGzip) => {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
        Err(e @ BodyError::UnsupportedEncoding(_)) => {
            return (StatusCode::UNSUPPORTED_MEDIA_TYPE, e.to_string()).into_response();
        }
    };

    let request = RequestInfo {
        transport: Transport::Http,
        headers: &headers,
        extensions: &extensions,
        peer: peer_of(&extensions),
    };
    let handler = &endpoint.handler;
    let mut connection = match handler.on_connecting(&request) {
        Ok((connection, _)) => connection,
        Err(refusal) => return refusal.into_response(),
    };
    let reply = match AgentToServer::decode(raw.as_slice()) {
        Ok(report) => handler.on_message(&mut connection, report).await,
        Err(e) => {
            warn!(error = %e, "undecodable report on the plain-HTTP transport");
            handler.on_unreadable(&mut connection, &Unreadable::Body(e))
        }
    };
    handler.on_closed(connection);

    let reply = match reply {
        Reply::Send(reply) => reply,
        Reply::Nothing => ServerToAgent::default(),
        Reply::Refuse(status, why) => return (status, why).into_response(),
    };
    // The send side of the same limit: an oversized response is never put on the wire, so a reply
    // that outgrew it is discarded — recorded here rather than shipped — and the client sees a
    // failed exchange instead of a body it must refuse.
    let encoded = reply.encode_to_vec();
    if encoded.len() > limit {
        warn!(
            size = encoded.len(),
            limit, "discarding a response that exceeds the message size limit"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "the response exceeds the message size limit",
        )
            .into_response();
    }
    ([(header::CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)], encoded).into_response()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}
