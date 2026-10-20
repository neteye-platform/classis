//! The Supervisor Endpoint (ADR-0015, ADR-0017): the loopback OpAMP endpoint every Supervisor
//! exposes, WebSocket-only — what a Managed Process carrying an OpAMP client of its own
//! (notably the Collector's `opampextension`) connects to.
//!
//! It folds **content, not identity**: the process's description, health, and effective
//! configuration become [`ProcessEvent`]s for the owning Agent, whose `instance_uid` stays the
//! Supervisor's. It is not a Server in the specification's sense — it manages no fleet, holds
//! no configuration, and serves exactly one local process; for a Foreign Agent nothing ever
//! connects, and that is the whole of the handling. The communication itself is
//! `opamp::server`'s, the same endpoint the Server and the Gateway sit on (ADR-0010).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opamp::proto::{AgentToServer, ServerCapabilities, ServerToAgent};
use opamp::server::listen::{Handle, Listener, HEADER_READ_TIMEOUT};
use opamp::server::{Handler, Outbound, Rejection, Reply, RequestInfo, Settings, Transports};
use tracing::{debug, info, warn};

use crate::shutdown::Shutdown;
use crate::supervisor::ports::{EventSender, ProcessEvent};

/// What this endpoint declares to the connecting client: it takes status reports and effective
/// configuration; it offers nothing (no remote config — that flows through the Supervisor).
const ENDPOINT_CAPABILITIES: u64 =
    ServerCapabilities::AcceptsStatus as u64 | ServerCapabilities::AcceptsEffectiveConfig as u64;

pub struct Endpoint {
    listener: std::net::TcpListener,
    name: String,
    events: EventSender,
    /// The message size limit this endpoint enforces in both directions. It speaks the Server
    /// side of the protocol, so the Baseline's limits bind it exactly as they bind the Server.
    max_message_size: usize,
    /// How long a connection may take to send its request headers.
    header_read_timeout: Duration,
    /// What a connection must present as `Authorization: Bearer …` (ADR-0015); empty asks nothing.
    token: String,
}

impl Endpoint {
    /// Binds `127.0.0.1:<port>` (`0` = ephemeral) — at startup, so a taken port fails loudly.
    ///
    /// # Errors
    /// Returns an error when the loopback port cannot be bound.
    pub fn bind(
        name: String,
        port: u16,
        events: EventSender,
        max_message_size: usize,
    ) -> Result<Self, String> {
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| format!("supervisor {name:?}: cannot bind 127.0.0.1:{port}: {e}"))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("supervisor {name:?}: cannot prepare the endpoint: {e}"))?;
        Ok(Endpoint {
            listener: std_listener,
            name,
            events,
            max_message_size,
            header_read_timeout: HEADER_READ_TIMEOUT,
            token: String::new(),
        })
    }

    /// Asks every connection for `token` (ADR-0015).
    #[must_use]
    pub fn with_token(mut self, token: String) -> Self {
        self.token = token;
        self
    }

    /// Tightens the header bound — what a test waits out instead of the 30 seconds every OpAMP
    /// listener applies (ADR-0010).
    #[must_use]
    pub fn with_header_read_timeout(mut self, timeout: Duration) -> Self {
        self.header_read_timeout = timeout;
        self
    }

    /// The bound address — logged so an operator can point the `opampextension` at it.
    ///
    /// # Errors
    /// Returns an error when the local address cannot be read back.
    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|e| format!("supervisor {:?}: no endpoint address: {e}", self.name))
    }

    /// Serves connections until shutdown, which also closes a session still open.
    pub async fn run(self, mut shutdown: Shutdown) {
        let handler = Arc::new(Folding {
            name: self.name.clone(),
            events: self.events,
            shutdown: shutdown.clone(),
            expected: (!self.token.is_empty()).then(|| format!("Bearer {}", self.token)),
        });
        // WebSocket-only, and on any path: this listener serves exactly one local process, so
        // there is nothing to route by.
        let app = opamp::server::router(
            handler,
            Settings {
                max_message_size: self.max_message_size,
                transports: Transports::WebSocketOnly,
                any_path: true,
            },
        );
        // On the listener every OpAMP endpoint is served on (ADR-0010), so a local process that
        // falls silent mid-request is bounded as a remote one is.
        let handle = Handle::new();
        let trigger = handle.clone();
        tokio::spawn(async move {
            shutdown.requested().await;
            trigger.graceful_shutdown(None);
        });
        let served = Listener::new(self.listener, handle)
            .with_header_read_timeout(self.header_read_timeout)
            .serve(app)
            .await;
        if let Err(e) = served {
            warn!(supervisor = %self.name, error = %e, "the endpoint stopped");
        }
    }
}

/// The endpoint's handler: every `AgentToServer` is folded into the owning Agent and answered with
/// this endpoint's capability set, so the client keeps reporting what we accept.
struct Folding {
    name: String,
    events: EventSender,
    shutdown: Shutdown,
    /// The `Authorization` value a connection must carry; `None` asks nothing.
    expected: Option<String>,
}

/// A fresh token for one Supervisor start (ADR-0015): 32 bytes from the system's secure random
/// source, hex.
///
/// # Errors
/// Returns an error when no secure random source is available.
pub fn new_token() -> Result<String, String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no secure random source for the supervisor endpoint's token".to_string())?;
    Ok(hex::encode(bytes))
}

/// Compares in time that depends on the lengths alone, so an answer never tells how far a guess
/// matched.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// A session ends when the Client does: a socket the extension holds open is closed on shutdown
/// rather than outliving the listener.
struct UntilShutdown(Shutdown);

impl Outbound for UntilShutdown {
    type Item = std::convert::Infallible;

    async fn next(&mut self) -> Option<Self::Item> {
        self.0.requested().await;
        None
    }
}

impl Handler for Folding {
    type Connection = ();
    type Outbound = UntilShutdown;

    fn on_connecting(
        &self,
        request: &RequestInfo<'_>,
    ) -> Result<((), Option<UntilShutdown>), Rejection> {
        if let Some(expected) = &self.expected {
            let presented = request
                .headers
                .get("authorization")
                .map(|value| value.as_bytes())
                .unwrap_or_default();
            if !same(presented, expected.as_bytes()) {
                warn!(
                    supervisor = %self.name,
                    "refused a local connection without the endpoint's token"
                );
                return Err(Rejection {
                    status: axum::http::StatusCode::UNAUTHORIZED,
                    headers: Vec::new(),
                    message: "the supervisor endpoint requires its token".to_string(),
                });
            }
        }
        debug!(supervisor = %self.name, "endpoint connection");
        Ok(((), Some(UntilShutdown(self.shutdown.clone()))))
    }

    async fn on_message(&self, _: &mut (), report: AgentToServer) -> Reply {
        let reply = ServerToAgent {
            instance_uid: report.instance_uid.clone(),
            capabilities: ENDPOINT_CAPABILITIES,
            ..Default::default()
        };
        self.fold(report).await;
        Reply::Send(reply)
    }

    fn on_outbound(&self, _: &mut (), item: std::convert::Infallible) -> Vec<ServerToAgent> {
        match item {}
    }
}

impl Folding {
    /// Content, not identity: what the process reported about itself becomes events for the
    /// owning Agent; the process's own `instance_uid` stays local to this session.
    async fn fold(&self, report: AgentToServer) {
        if let Some(description) = report.agent_description {
            self.events
                .send(ProcessEvent::Description(description))
                .await;
        }
        if let Some(health) = report.health {
            self.events.send(ProcessEvent::Health(health)).await;
        }
        if let Some(effective) = report.effective_config {
            self.events
                .send(ProcessEvent::EffectiveConfig(effective))
                .await;
        }
        if let Some(components) = report.available_components {
            self.events
                .send(ProcessEvent::AvailableComponents(components))
                .await;
        }
    }
}

/// Bind and start an endpoint task, returning the bound address.
///
/// # Errors
/// Returns an error when the port cannot be bound.
pub fn start(
    name: String,
    port: u16,
    events: EventSender,
    shutdown: Shutdown,
    max_message_size: usize,
    token: String,
) -> Result<SocketAddr, String> {
    let endpoint = Endpoint::bind(name.clone(), port, events, max_message_size)?.with_token(token);
    let addr = endpoint.local_addr()?;
    info!(supervisor = %name, endpoint = %format!("ws://{addr}/v1/opamp"), "supervisor endpoint ready");
    tokio::spawn(endpoint.run(shutdown));
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::shutdown_channel;
    use futures_util::{SinkExt, StreamExt};
    use opamp::frame;
    use opamp::proto::{AgentDescription, ComponentHealth, EffectiveConfig};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;

    /// A fake `opampextension`: connects, reports, and expects the capability echo.
    /// Verifies: ADR-0015
    #[tokio::test]
    async fn extension_reports_are_folded_into_process_events() {
        let (event_tx, mut events) = mpsc::channel(16);
        let (_shutdown_tx, shutdown) = shutdown_channel();
        let addr = start(
            "test".to_string(),
            0,
            EventSender::new(0, event_tx),
            shutdown,
            opamp::frame::DEFAULT_MAX_MESSAGE_SIZE,
            String::new(),
        )
        .expect("endpoint starts");

        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
            .await
            .expect("the fake extension connects");

        let report = AgentToServer {
            instance_uid: opamp::uid::InstanceUid::default().as_bytes().to_vec(),
            agent_description: Some(AgentDescription::default()),
            health: Some(ComponentHealth {
                healthy: true,
                ..Default::default()
            }),
            effective_config: Some(EffectiveConfig::default()),
            available_components: Some(opamp::proto::AvailableComponents {
                components: Default::default(),
                hash: b"h".to_vec(),
            }),
            ..Default::default()
        };
        socket
            .send(Message::Binary(
                frame::encode_within(&report, opamp::frame::DEFAULT_MAX_MESSAGE_SIZE)
                    .expect("within the limit")
                    .into(),
            ))
            .await
            .expect("send the report");

        let mut kinds = Vec::new();
        for _ in 0..4 {
            let (index, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
                .await
                .expect("an event in time")
                .expect("an open channel");
            assert_eq!(index, 0);
            kinds.push(match event {
                ProcessEvent::Description(_) => "description",
                ProcessEvent::Pid(_) => "pid",
                ProcessEvent::Health(_) => "health",
                ProcessEvent::EffectiveConfig(_) => "effective",
                ProcessEvent::AvailableComponents(_) => "components",
                ProcessEvent::ConfigApplied { .. } => "applied",
                ProcessEvent::PackageApplied { .. } => "package",
                ProcessEvent::Uninstalled { .. } => "uninstalled",
            });
        }
        assert_eq!(
            kinds,
            vec!["description", "health", "effective", "components"]
        );

        // The reply echoes the extension's uid and declares what this endpoint accepts.
        let reply = tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("a reply in time")
            .expect("an open socket")
            .expect("a frame");
        let Message::Binary(data) = reply else {
            panic!("expected a binary reply");
        };
        let decoded: ServerToAgent =
            frame::decode(&data, opamp::frame::DEFAULT_MAX_MESSAGE_SIZE).expect("decodable");
        assert_eq!(decoded.instance_uid, report.instance_uid);
        assert_eq!(decoded.capabilities, ENDPOINT_CAPABILITIES);
    }

    /// Verifies: ADR-0015
    #[tokio::test]
    async fn shutdown_stops_the_endpoint() {
        let (event_tx, _events) = mpsc::channel(16);
        let (shutdown_tx, shutdown) = shutdown_channel();
        let addr = start(
            "test".to_string(),
            0,
            EventSender::new(0, event_tx),
            shutdown,
            opamp::frame::DEFAULT_MAX_MESSAGE_SIZE,
            String::new(),
        )
        .expect("endpoint starts");
        shutdown_tx.send(true).expect("signal shutdown");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
                .await
                .is_err(),
            "a stopped endpoint accepts no connections"
        );
    }

    /// A connection that completes the upgrade and is answered: the endpoint is serving.
    async fn served(addr: SocketAddr) {
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
            .await
            .expect("connects");
        let report = AgentToServer {
            instance_uid: opamp::uid::InstanceUid::default().as_bytes().to_vec(),
            ..Default::default()
        };
        let framed = frame::encode_within(&report, frame::DEFAULT_MAX_MESSAGE_SIZE).expect("frame");
        socket
            .send(Message::Binary(framed.into()))
            .await
            .expect("send");
        let reply = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("answered in time");
        assert!(matches!(reply, Some(Ok(Message::Binary(_)))), "{reply:?}");
    }

    /// The connection-setup bound on this surface (H18): a local connection that never completes
    /// the WebSocket upgrade is dropped, other connections are served while it hangs, and the
    /// endpoint serves the next one afterwards — the measure, since a listener that died would
    /// drop the first connection too.
    /// Verifies: ADR-0010
    #[tokio::test]
    async fn a_half_finished_upgrade_is_dropped_and_the_endpoint_keeps_serving() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (event_tx, _events) = mpsc::channel(16);
        let (_shutdown_tx, shutdown) = shutdown_channel();
        let endpoint = Endpoint::bind(
            "test".to_string(),
            0,
            EventSender::new(0, event_tx),
            frame::DEFAULT_MAX_MESSAGE_SIZE,
        )
        .expect("binds")
        .with_header_read_timeout(Duration::from_secs(1));
        let addr = endpoint.local_addr().expect("addr");
        tokio::spawn(endpoint.run(shutdown));

        let mut stalled = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stalled
            .write_all(b"GET /v1/opamp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n")
            .await
            .expect("a partial upgrade");
        served(addr).await;

        let mut buffer = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_secs(8), stalled.read_to_end(&mut buffer)).await;
        assert!(
            closed.is_ok(),
            "the endpoint left a half-finished upgrade open"
        );
        served(addr).await;
    }

    /// Only the Managed Process reports through the endpoint: a connection without the token
    /// handed to the process is refused before the upgrade, one with it is served.
    /// Verifies: ADR-0015
    #[tokio::test]
    async fn the_endpoint_admits_only_the_token_it_handed_out() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let (event_tx, _events) = mpsc::channel(16);
        let (_shutdown_tx, shutdown) = shutdown_channel();
        let token = new_token().expect("token");
        assert_eq!(token.len(), 64);
        let addr = start(
            "test".to_string(),
            0,
            EventSender::new(0, event_tx),
            shutdown,
            opamp::frame::DEFAULT_MAX_MESSAGE_SIZE,
            token.clone(),
        )
        .expect("endpoint starts");
        let url = format!("ws://{addr}/v1/opamp");
        assert!(
            tokio_tungstenite::connect_async(&url).await.is_err(),
            "a local process without the token was admitted"
        );
        let mut wrong = url.as_str().into_client_request().expect("request");
        wrong
            .headers_mut()
            .insert("authorization", "Bearer guess".parse().expect("header"));
        assert!(tokio_tungstenite::connect_async(wrong).await.is_err());
        let mut right = url.as_str().into_client_request().expect("request");
        right.headers_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("header"),
        );
        tokio_tungstenite::connect_async(right)
            .await
            .expect("the Managed Process is admitted");
    }
}
