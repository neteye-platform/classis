//! An OpAMP agent's side of the protocol (ADR-0010): one Agent's state machine, and the
//! connection that carries any number of them to a Server. Behind the `client` feature.
//!
//! - [`protocol`] — the state machine, without I/O: which fields a report carries, and what a reply
//!   means for the protocol.
//! - [`ws`] and [`http`] — the two transports, each a driver for one connection: connecting with
//!   backoff, the heartbeat or poll interval, framing, the message size limit in both directions,
//!   the 1009 close, throttling, and the goodbye.
//! - [`connection`] — one connection described once, from which the transport, its TLS, its HTTP
//!   client and its headers are built; the probe that proves offered settings.
//!
//! What the Agents report and what is done with a reply is the application's: it implements
//! [`Session`], and a driver calls it. Which material a connection uses is the application's too:
//! it fills in a [`Connection`], and this module builds the rest.

use std::future::Future;
use std::time::Duration;

use crate::proto::{AgentToServer, ServerToAgent};

mod backoff;
pub mod connection;
pub mod http;
pub mod protocol;
pub mod ws;

pub use backoff::Backoff;
pub use connection::{ClientTls, Connection};

/// The application's side of one connection, carrying any number of Agents. A driver never calls
/// two of these at once.
#[allow(async_fn_in_trait)]
pub trait Session {
    /// Every Agent's full snapshot — after a (re)connect, when the Server may know nothing.
    fn connected(&mut self) -> Vec<AgentToServer>;

    /// A routine report per Agent: the heartbeat on a WebSocket, one poll on plain HTTP.
    fn routine(&mut self) -> Vec<AgentToServer>;

    /// What the Agents owe the Server now.
    fn owed(&mut self) -> Vec<AgentToServer>;

    /// One reply. `Some` asks the driver to stay away that long first — the Server is throttling.
    fn on_reply(&mut self, reply: &ServerToAgent) -> Option<Duration>;

    /// What the replies left to do, run once they are handled; the driver goes on as it says.
    async fn after_reply<S: ReportSink>(&mut self, sink: &mut S) -> AfterReply;

    /// Resolves when something changed that the Server should hear about now.
    async fn changed(&mut self);

    /// An exchange was lost: the Server may be missing state, so the next reports are full ones.
    fn exchange_failed(&mut self);

    /// The connection is ending: stop what the Agents run, before their goodbyes go out. Also
    /// called when a run ends while disconnected, with no goodbyes to send.
    async fn stop(&mut self);

    /// The last messages, one `agent_disconnect` per Agent.
    fn goodbyes(&mut self) -> Vec<AgentToServer>;
}

/// What the connection does after [`Session::after_reply`].
#[derive(Debug, PartialEq, Eq)]
pub enum AfterReply {
    /// Go on.
    Continue,
    /// Drop the connection and end the run, so the application reconnects — with new settings.
    Reconnect,
    /// Say goodbye and end the run. The application knows why it asked.
    End,
    /// The connection failed while sending what was owed.
    ConnectionLost,
}

/// Why a driver's run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// The stop signal fired; the goodbyes are sent where there was a connection to send them on.
    Stopped,
    /// The session asked to reconnect.
    Reconnect,
    /// The session asked to end; the goodbyes are sent.
    End,
}

/// How a driver puts reports on the wire, for a job that reports while it runs — a download
/// reporting its progress, say — and for what [`Session::after_reply`] owes.
#[allow(async_fn_in_trait)]
pub trait ReportSink {
    /// `Err` means the connection is gone, not that one report was refused.
    async fn send(&mut self, reports: Vec<AgentToServer>) -> Result<(), ()>;

    /// Whether owed reports should go out through this sink at once. A driver whose own loop sends
    /// them — and handles the replies to them — says no, and leaves them owed.
    fn sends_owed_now(&self) -> bool {
        true
    }
}

/// What tells a driver to stop.
pub trait StopSignal {
    /// Resolves once a stop is requested, and at once on every call after that.
    fn requested(&mut self) -> impl Future<Output = ()> + Send;
}
