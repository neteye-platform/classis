//! The shutdown handle every long-running task selects on (ADR-0019): the transports, the
//! Gateway, the Supervisor and its Plugins. It is a value of the core rather than of the service
//! runtime that flips it, so a Port can name it without depending on how a process is stopped.

use tokio::sync::watch;

/// A multi-use shutdown handle: resolves once shutdown is requested, immediately when it already
/// was — the transports await it at several points in their loops.
#[derive(Debug, Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// Wait until shutdown has been requested (returns immediately if it already was).
    pub async fn requested(&mut self) {
        while !*self.0.borrow_and_update() {
            if self.0.changed().await.is_err() {
                // The requesting side is gone; treat that as a shutdown rather than hang.
                return;
            }
        }
    }
}

/// Create the pair: the sender flips shutdown on, every [`Shutdown`] clone observes it.
#[must_use]
pub fn shutdown_channel() -> (watch::Sender<bool>, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (tx, Shutdown(rx))
}
