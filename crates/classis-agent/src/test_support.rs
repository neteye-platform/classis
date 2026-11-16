//! Helpers the unit tests of this crate share.

use std::cell::RefCell;
use std::sync::OnceLock;

thread_local! {
    /// The log lines of the `capture_logs` call running on this thread, if one is.
    static CAPTURED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Writes into this thread's capture, and nowhere when none is running.
struct ThreadWriter;

impl std::io::Write for ThreadWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        CAPTURED.with(|captured| {
            if let Some(buffer) = captured.borrow_mut().as_mut() {
                buffer.extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `body` and returns what it logged on this thread, as the fmt layer writes it.
///
/// One process-wide subscriber, installed once, rather than one `with_default` per test: tracing
/// caches a callsite's interest globally, and a test that reaches a callsite first on a thread
/// without a subscriber of its own would cache it as "never", so a `with_default` test running in
/// parallel would capture nothing. A global subscriber answers for every thread, and its writer
/// keeps each test's lines apart.
pub(crate) fn capture_logs<T>(body: impl FnOnce() -> T) -> (T, String) {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(|| ThreadWriter)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other global subscriber in the unit tests");
    });
    CAPTURED.with(|captured| *captured.borrow_mut() = Some(Vec::new()));
    let result = body();
    let bytes = CAPTURED
        .with(|captured| captured.borrow_mut().take())
        .unwrap_or_default();
    (result, String::from_utf8(bytes).expect("utf-8 log"))
}
