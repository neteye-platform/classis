//! How the Server's two planes are served (ADR-0013). The listener, its TLS and its bounds on
//! connection setup are `opamp`'s (ADR-0010); what is the Server's is that both planes share one
//! handle and one idea of shutting down.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use opamp::server::listen::{Handle, Listener};
use rustls::ServerConfig;

/// How long connections are given to finish once shutdown has been asked for.
///
/// Bounded on purpose: an Agent's WebSocket is idle most of the time and would otherwise decide
/// how long a restart takes. Its session is told to close at once, with the close code for a server
/// going away; whatever has not ended by the deadline is cut, and only then does the record flush
/// that follows shutdown (ADR-0024) run.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(10);

/// A plane on an already-bound listener, over TLS when `tls` is given, holding at most
/// `max_connections` at once (ADR-0013). `handle` is shared by both planes, so one signal drains
/// both.
#[must_use]
pub fn plane(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    max_connections: usize,
    handle: Handle,
) -> Listener {
    let plane = Listener::new(listener, handle).with_max_connections(max_connections);
    match tls {
        Some(config) => plane.with_tls(config),
        None => plane,
    }
}

/// A plane on an already-bound listener, served in plaintext on any address: the Server sits
/// behind a reverse proxy that terminates TLS (ADR-0064), so the connection it accepts is the
/// proxy's. `handle` is shared by both planes, as for [`plane`].
#[must_use]
pub fn plain_plane(listener: TcpListener, max_connections: usize, handle: Handle) -> Listener {
    Listener::new(listener, handle)
        .with_max_connections(max_connections)
        .with_plaintext_anywhere()
}

/// Asks both planes to stop and gives their connections [`SHUTDOWN_DRAIN`] to end.
///
/// A free function rather than a call at the signal site, so the two planes cannot end up with
/// different ideas of what shutting down means.
pub fn shut_down(handle: &Handle) {
    handle.graceful_shutdown(Some(SHUTDOWN_DRAIN));
}
