//! How the Server's two planes are served. The listener and its bounds on connection setup are
//! `opamp`'s; what is the Server's is that both planes share one
//! handle and one idea of shutting down.

use std::net::TcpListener;
use std::time::Duration;

use opamp::server::listen::{Handle, Listener};

/// How long connections are given to finish once shutdown has been asked for.
///
/// Bounded on purpose: an Agent's WebSocket is idle most of the time and would otherwise decide
/// how long a restart takes. Its session is told to close at once, with the close code for a server
/// going away; whatever has not ended by the deadline is cut, and only then does the record flush
/// that follows shutdown run.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(10);

/// A plane on an already-bound listener, served in plain HTTP on any address and holding at most
/// `max_connections` at once: the Server sits behind a reverse proxy that terminates TLS, so the
/// connection it accepts is the proxy's. `handle` is shared by both planes, so one signal drains
/// both.
#[must_use]
pub fn plane(listener: TcpListener, max_connections: usize, handle: Handle) -> Listener {
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
