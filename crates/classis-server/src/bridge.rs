//! A synchronous port over an asynchronous client (ADR-0049 clause 1, ADR-0050): the bridge the S3
//! blob store and the PostgreSQL record store share.
//!
//! The ports are synchronous and the clients are not. An adapter owns a small Tokio runtime of its
//! own, and every operation is spawned onto it while the calling thread waits on a plain channel.
//! None of the callers can deadlock the Server's runtime: the work never needs a thread of the
//! runtime that waits for it, and a channel, unlike `Handle::block_on`, may be waited on from
//! inside an asynchronous context. What the client spawns for itself — a connection's task — runs
//! on the adapter's runtime too, since it is spawned from the work.

use std::future::Future;

/// An adapter's own runtime. Two workers carry every request of the adapter; a caller waits for
/// its result on a channel.
pub struct Bridge {
    /// `Some` until dropped: a runtime is shut down in the background, because the last handle to
    /// the adapter may well be dropped on a thread of the Server's own runtime, where a blocking
    /// shutdown panics.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Bridge {
    /// Starts the runtime, its threads named after `name`.
    ///
    /// # Errors
    /// Returns an error when the runtime cannot be started.
    pub fn new(name: &str) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name(name)
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the {name} runtime: {e}"))?;
        Ok(Bridge {
            runtime: Some(runtime),
        })
    }

    /// Runs `future` on the adapter's runtime and waits for its output.
    pub fn run<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.runtime
            .as_ref()
            .expect("the runtime lives as long as the bridge")
            .spawn(async move {
                let _ = sender.send(future.await);
            });
        receiver
            .recv()
            .expect("a task of the adapter's runtime runs to its end")
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}
