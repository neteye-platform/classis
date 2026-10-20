//! The WebSocket transport: one connection, reconnected with backoff, carrying every Agent of the
//! session — the *n* over one of ADR-0015.

use std::time::Duration;

use crate::frame;
use crate::proto::{AgentToServer, ServerToAgent};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderMap, StatusCode};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async_tls_with_config, MaybeTlsStream, WebSocketStream};
use tracing::{info, warn};

pub use tokio_tungstenite::Connector;

use super::{AfterReply, Backoff, Ended, ReportSink, Session, StopSignal};

/// One open WebSocket to a server.
pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One WebSocket connection's material, built by the application.
pub struct Settings {
    /// `ws://` or `wss://`.
    pub endpoint: String,
    /// Sent with every upgrade request — the `Authorization` header, typically, which the Server
    /// checks before the WebSocket comes up.
    pub headers: HeaderMap,
    /// The TLS configuration for `wss://`; `None` takes the transport's default.
    pub connector: Option<Connector>,
    /// The largest message received or sent, framing header included.
    pub max_message_size: usize,
    /// A routine report per Agent this often; `None` sends none.
    pub heartbeat: Option<Duration>,
}

/// How one connection ended.
enum Served {
    Stopped,
    ConnectionLost,
    Reconnect,
    End,
}

/// Runs the session over a WebSocket until it is stopped or asks to end, reconnecting with backoff
/// whenever the connection is lost.
///
/// # Errors
/// Returns an error when the endpoint is not a valid URL.
pub async fn run<S: Session, X: StopSignal>(
    settings: &Settings,
    session: &mut S,
    stop: &mut X,
) -> Result<Ended, String> {
    let mut backoff = Backoff::new();
    loop {
        match connect(
            &settings.endpoint,
            &settings.headers,
            settings.connector.clone(),
            settings.max_message_size,
        )
        .await
        {
            Ok(socket) => {
                info!(endpoint = %settings.endpoint, "connected");
                backoff.reset();
                match serve(socket, settings, session, stop).await {
                    Served::Stopped => {
                        // Usually already stopped before the goodbyes went out; idempotent.
                        session.stop().await;
                        return Ok(Ended::Stopped);
                    }
                    Served::Reconnect => return Ok(Ended::Reconnect),
                    Served::End => return Ok(Ended::End),
                    Served::ConnectionLost => warn!("connection lost; reconnecting"),
                }
            }
            Err(Connect::Refused(WsError::Http(response)))
                if response.status() == StatusCode::UNAUTHORIZED =>
            {
                warn!(
                    endpoint = %settings.endpoint,
                    "admission failed: the server refused this client (HTTP 401)"
                );
            }
            Err(Connect::Refused(e)) => {
                warn!(endpoint = %settings.endpoint, error = %e, "cannot connect");
            }
            Err(Connect::InvalidEndpoint(e)) => return Err(e),
        }

        let delay = backoff.advance();
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = stop.requested() => {
                // Stopped while disconnected: no goodbyes to send, but what the Agents run still
                // stops before the run ends.
                session.stop().await;
                return Ok(Ended::Stopped);
            }
        }
    }
}

/// Why [`connect`] failed.
#[derive(Debug)]
pub enum Connect {
    /// The endpoint is not a WebSocket URL; trying again will not help.
    InvalidEndpoint(String),
    /// The server could not be reached, or it refused the upgrade.
    Refused(WsError),
}

impl std::fmt::Display for Connect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Connect::InvalidEndpoint(e) => f.write_str(e),
            Connect::Refused(e) => e.fmt(f),
        }
    }
}

/// Opens one WebSocket to `endpoint`, sending `headers` with the upgrade request.
///
/// The receive limit the specification requires of an Agent is set on the socket: the transport
/// refuses to buffer a message past it, so an oversized server can never make this process
/// allocate without bound. The per-frame cap moves with it: left at its default it would refuse
/// messages below the limit, which is the limit's business, not the framing's.
///
/// # Errors
/// Returns why the socket could not be opened.
pub async fn connect(
    endpoint: &str,
    headers: &HeaderMap,
    connector: Option<Connector>,
    max_message_size: usize,
) -> Result<Socket, Connect> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(max_message_size))
        .max_frame_size(Some(max_message_size));
    let mut request = endpoint
        .into_client_request()
        .map_err(|e| Connect::InvalidEndpoint(format!("invalid endpoint {endpoint}: {e}")))?;
    request.headers_mut().extend(headers.clone());
    connect_async_tls_with_config(request, Some(config), false, connector)
        .await
        .map(|(socket, _)| socket)
        .map_err(Connect::Refused)
}

async fn serve<S: Session, X: StopSignal>(
    mut socket: Socket,
    settings: &Settings,
    session: &mut S,
    stop: &mut X,
) -> Served {
    let limit = settings.max_message_size;

    // A (re)connected Server may know nothing about us: every Agent starts from a full snapshot.
    if send_all(&mut socket, session.connected(), limit)
        .await
        .is_err()
    {
        return Served::ConnectionLost;
    }

    // The heartbeat: a routine report per Agent, so `sequence_num` advances and the Server's
    // liveness view stays fresh without any state change. Starts one period from now — the connect
    // snapshot just went out.
    let mut heartbeat = settings
        .heartbeat
        .map(|period| tokio::time::interval_at(tokio::time::Instant::now() + period, period));

    loop {
        let heartbeat_due = async {
            match heartbeat.as_mut() {
                Some(interval) => {
                    interval.tick().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            incoming = socket.next() => {
                let message = match incoming {
                    Some(Ok(message)) => message,
                    // The connection was capped at the receive limit, so a Server past it arrives
                    // as an error rather than as a message. The specification's answer is the 1009
                    // close; on a merely broken connection the frame never leaves, which is fine.
                    Some(Err(e)) => {
                        warn!(error = %e, "closing the connection after a receive error");
                        let _ = socket.close(Some(too_big_close())).await;
                        return Served::ConnectionLost;
                    }
                    None => return Served::ConnectionLost,
                };
                match message {
                    Message::Binary(data) => {
                        let reply: ServerToAgent = match frame::decode(&data, limit) {
                            Ok(reply) => reply,
                            // Oversized is malformed: refuse the message and close with 1009
                            // rather than act on a partial read of it.
                            Err(e @ frame::FrameError::TooLarge(..)) => {
                                warn!(error = %e, "the server sent an oversized message");
                                let _ = socket.close(Some(too_big_close())).await;
                                return Served::ConnectionLost;
                            }
                            Err(e) => {
                                warn!(error = %e, "undecodable message from the server");
                                continue;
                            }
                        };
                        if let Some(delay) = session.on_reply(&reply) {
                            // The server is throttling: drop the connection and come back later.
                            let _ = socket.close(None).await;
                            tokio::select! {
                                () = tokio::time::sleep(delay) => {}
                                () = stop.requested() => return Served::Stopped,
                            }
                            return Served::ConnectionLost;
                        }
                        if send_all(&mut socket, session.owed(), limit).await.is_err() {
                            return Served::ConnectionLost;
                        }
                        let mut sink = FrameSink { socket: &mut socket, limit };
                        match session.after_reply(&mut sink).await {
                            AfterReply::Continue => {}
                            AfterReply::Reconnect => {
                                let _ = socket.close(None).await;
                                return Served::Reconnect;
                            }
                            // End *cleanly*: stop what the Agents run and send the goodbyes over
                            // this connection, exactly as a stop does.
                            AfterReply::End => {
                                say_goodbye(&mut socket, session, limit).await;
                                info!("disconnected; the session ended the run");
                                return Served::End;
                            }
                            AfterReply::ConnectionLost => return Served::ConnectionLost,
                        }
                    }
                    Message::Close(_) => return Served::ConnectionLost,
                    // tungstenite answers pings on the next write; text frames are not OpAMP.
                    _ => {}
                }
            }
            // Something changed that the Server should hear about: push it now, not at the next
            // heartbeat.
            () = session.changed() => {
                if send_all(&mut socket, session.owed(), limit).await.is_err() {
                    return Served::ConnectionLost;
                }
            }
            () = heartbeat_due => {
                if send_all(&mut socket, session.routine(), limit).await.is_err() {
                    return Served::ConnectionLost;
                }
            }
            () = stop.requested() => {
                say_goodbye(&mut socket, session, limit).await;
                info!("disconnected");
                return Served::Stopped;
            }
        }
    }
}

/// Ends the connection the way the specification asks: what the Agents run stops first, then the
/// final messages go out — one `agent_disconnect` per Agent — and the socket closes. Best effort,
/// because the run is ending either way.
async fn say_goodbye<S: Session>(socket: &mut Socket, session: &mut S, limit: usize) {
    session.stop().await;
    let _ = send_all(socket, session.goodbyes(), limit).await;
    let _ = socket.close(None).await;
}

/// Sends the reports, each under the send limit. A report past it is dropped with a log line
/// rather than put on the wire — the specification forbids sending one — while the connection
/// stays up; `Err` means the connection is gone, which is a different thing entirely.
async fn send_all(
    socket: &mut Socket,
    reports: Vec<AgentToServer>,
    limit: usize,
) -> Result<(), ()> {
    for report in reports {
        let framed = match frame::encode_within(&report, limit) {
            Ok(framed) => framed,
            Err(e) => {
                warn!(error = %e, "discarding a report that exceeds the size limit");
                continue;
            }
        };
        socket
            .send(Message::Binary(framed.into()))
            .await
            .map_err(|e| {
                warn!(error = %e, "cannot send a report");
            })?;
    }
    Ok(())
}

/// The close the specification names for a message past the size limit: 1009, Message Too Big.
fn too_big_close() -> CloseFrame {
    CloseFrame {
        code: CloseCode::Size,
        reason: frame::TOO_BIG_CLOSE_REASON.into(),
    }
}

/// This transport's way of putting reports on the wire, for jobs that report while they run.
struct FrameSink<'a> {
    socket: &'a mut Socket,
    limit: usize,
}

impl ReportSink for FrameSink<'_> {
    async fn send(&mut self, reports: Vec<AgentToServer>) -> Result<(), ()> {
        send_all(self.socket, reports, self.limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::accept_async;

    /// A session of one Agent that reports an empty message and asks nothing else.
    struct Quiet;

    impl Session for Quiet {
        fn connected(&mut self) -> Vec<AgentToServer> {
            vec![AgentToServer::default()]
        }
        fn routine(&mut self) -> Vec<AgentToServer> {
            Vec::new()
        }
        fn owed(&mut self) -> Vec<AgentToServer> {
            Vec::new()
        }
        fn on_reply(&mut self, _: &ServerToAgent) -> Option<Duration> {
            None
        }
        async fn after_reply<K: ReportSink>(&mut self, _: &mut K) -> AfterReply {
            AfterReply::Continue
        }
        async fn changed(&mut self) {
            std::future::pending().await
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

    /// The specification: a `ServerToAgent` past the receive limit is malformed — the Agent refuses
    /// it and closes with 1009 rather than acting on it.
    #[tokio::test]
    async fn an_oversized_message_from_the_server_closes_with_1009() {
        const LIMIT: usize = 4096;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // A Server that answers the connect snapshot with a message twice the Agent's limit, then
        // waits for what the Agent does about it.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = accept_async(stream).await.expect("handshake");
            // The full report on connect; ignored beyond keeping the stream moving.
            let _ = socket.next().await;
            socket
                .send(Message::Binary(vec![0u8; LIMIT * 2].into()))
                .await
                .expect("send an oversized message");
            // The close frame is the answer under test.
            loop {
                match socket.next().await {
                    Some(Ok(Message::Close(frame))) => return frame,
                    Some(Ok(_)) => continue,
                    _ => return None,
                }
            }
        });

        let settings = Settings {
            endpoint: format!("ws://{addr}/v1/opamp"),
            headers: HeaderMap::new(),
            connector: None,
            max_message_size: LIMIT,
            heartbeat: None,
        };
        let (socket, _) = tokio_tungstenite::connect_async(&settings.endpoint)
            .await
            .expect("connect");

        let outcome = serve(socket, &settings, &mut Quiet, &mut Never).await;
        assert!(
            matches!(outcome, Served::ConnectionLost),
            "an oversized message ends the connection"
        );

        let close = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the server sees the close in time")
            .expect("the server task")
            .expect("a close frame with a status code");
        assert_eq!(
            u16::from(close.code),
            1009,
            "the specification names 1009 (Message Too Big)"
        );
    }
}
