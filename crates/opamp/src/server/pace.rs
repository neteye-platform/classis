//! The floor on the pace of every request body and every WebSocket message (ADR-0013 clause 14).
//!
//! Nothing a listener serves has a deadline: a large upload over a slow link and a long-lived
//! session are both legitimate. What is not is a body or a message that has begun and then stalls
//! or trickles, holding its connection for as long as the peer likes. So once one has begun it must
//! deliver [`MIN_PACE_BYTES`] within every [`PACE_WINDOW`], or it is cut off: a body is answered
//! `408`, a WebSocket message closes its connection with `1008`. A connection with nothing in flight
//! is left alone.
//!
//! A message is judged by its data frames, read as they arrive (ADR-0010 clause 5): a Ping between
//! two fragments of a message is not progress on it, and a peer that only pings has no message in
//! flight.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The window a body or a message must make progress within.
pub const PACE_WINDOW: Duration = Duration::from_secs(60);

/// What it must deliver in each window: 64 KiB, about a kilobyte a second.
pub const MIN_PACE_BYTES: u64 = 64 * 1024;

/// The floor one listener holds its bodies and messages to, attached to every request it serves.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pace {
    pub(crate) window: Duration,
    pub(crate) min_bytes: u64,
}

/// Holds every request body to its listener's floor, and answers one that fell below it `408`.
/// Whatever the handler made of the cut-off body — an extractor's refusal, a removed staging file —
/// is replaced by that answer.
pub(crate) async fn bodies(request: Request, next: Next) -> Response {
    let Some(pace) = request.extensions().get::<Pace>().copied() else {
        return next.run(request).await;
    };
    let stalled = Arc::new(AtomicBool::new(false));
    let request = request.map(|body| paced(body, pace, stalled.clone()));
    let response = next.run(request).await;
    if stalled.load(Ordering::Acquire) {
        return (
            StatusCode::REQUEST_TIMEOUT,
            format!(
                "the request body fell below {} bytes in {} s",
                pace.min_bytes,
                pace.window.as_secs()
            ),
        )
            .into_response();
    }
    response
}

/// `body`, ending in an error once a window passes with less than the floor delivered. The first
/// window starts here, when the headers have ended.
fn paced(body: Body, pace: Pace, stalled: Arc<AtomicBool>) -> Body {
    struct State {
        data: axum::body::BodyDataStream,
        pace: Pace,
        window_end: tokio::time::Instant,
        in_window: u64,
        stalled: Arc<AtomicBool>,
        done: bool,
    }
    let state = State {
        data: body.into_data_stream(),
        pace,
        window_end: tokio::time::Instant::now() + pace.window,
        in_window: 0,
        stalled,
        done: false,
    };
    Body::from_stream(futures_util::stream::unfold(
        state,
        |mut state| async move {
            if state.done {
                return None;
            }
            // A handler that took longer than a window before this read is not the peer's delay: the
            // peer is judged from here.
            let now = tokio::time::Instant::now();
            if now >= state.window_end {
                state.window_end = now + state.pace.window;
                state.in_window = 0;
            }
            loop {
                match tokio::time::timeout_at(state.window_end, state.data.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        state.in_window += chunk.len() as u64;
                        return Some((Ok::<Bytes, std::io::Error>(chunk), state));
                    }
                    Ok(Some(Err(e))) => {
                        state.done = true;
                        return Some((Err(std::io::Error::other(e)), state));
                    }
                    Ok(None) => return None,
                    Err(_) if state.in_window < state.pace.min_bytes => {
                        state.stalled.store(true, Ordering::Release);
                        state.done = true;
                        return Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "the request body fell below its pace",
                            )),
                            state,
                        ));
                    }
                    Err(_) => {
                        state.window_end = tokio::time::Instant::now() + state.pace.window;
                        state.in_window = 0;
                    }
                }
            }
        },
    ))
}

/// What the frame reader has learned of one socket's data messages.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct Progress {
    /// A data message has begun and its final frame has not yet arrived whole.
    in_flight: bool,
    /// Payload bytes of data frames, in total.
    data_bytes: u64,
    /// Data messages completed, in total.
    completed: u64,
}

/// A WebSocket's stream, read through: it follows the frame headers as the bytes arrive and
/// records the progress of data messages, leaving the bytes themselves to the WebSocket library.
pub(crate) struct FrameMeter<S> {
    inner: S,
    parser: Parser,
}

impl<S> FrameMeter<S> {
    pub(crate) fn new(inner: S) -> Self {
        FrameMeter {
            inner,
            parser: Parser::default(),
        }
    }

    pub(crate) fn progress(&self) -> Progress {
        self.parser.progress
    }
}

/// Where the reader is in the frame sequence (RFC 6455 §5.2).
#[derive(Default)]
struct Parser {
    progress: Progress,
    header: [u8; 14],
    have: usize,
    need: usize,
    payload_left: u64,
    data: bool,
    fin: bool,
    message_open: bool,
}

impl Parser {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.payload_left > 0 {
                let taken = self.payload_left.min(bytes.len() as u64);
                if self.data {
                    self.progress.data_bytes += taken;
                }
                self.payload_left -= taken;
                bytes = &bytes[usize::try_from(taken).unwrap_or(bytes.len())..];
                if self.payload_left == 0 {
                    self.frame_done();
                }
                continue;
            }
            self.header[self.have] = bytes[0];
            self.have += 1;
            bytes = &bytes[1..];
            if self.have == 1 {
                // Opcodes below 8 are data and continuation frames; a message begins with the
                // first byte of its first one.
                if self.header[0] & 0x08 == 0 && !self.message_open {
                    self.message_open = true;
                    self.progress.in_flight = true;
                }
                continue;
            }
            if self.have == 2 {
                let extended = match self.header[1] & 0x7F {
                    126 => 2,
                    127 => 8,
                    _ => 0,
                };
                let mask = if self.header[1] & 0x80 == 0 { 0 } else { 4 };
                self.need = 2 + extended + mask;
            }
            if self.have == self.need {
                self.payload_left = match self.header[1] & 0x7F {
                    126 => u64::from(u16::from_be_bytes([self.header[2], self.header[3]])),
                    127 => u64::from_be_bytes(self.header[2..10].try_into().unwrap_or([0; 8])),
                    short => u64::from(short),
                };
                self.data = self.header[0] & 0x08 == 0;
                self.fin = self.header[0] & 0x80 != 0;
                self.have = 0;
                if self.payload_left == 0 {
                    self.frame_done();
                }
            }
        }
    }

    fn frame_done(&mut self) {
        if self.data && self.fin {
            self.message_open = false;
            self.progress.in_flight = false;
            self.progress.completed += 1;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FrameMeter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let this = &mut *self;
        this.parser.feed(&buf.filled()[before..]);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FrameMeter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The WebSocket half of the floor, judged once per window. A message in flight at two checks in
/// a row, with no message completed between them and less than the floor of data read, has fallen
/// below it. A message that begins just before a check is therefore given at least one whole
/// window.
pub(crate) struct Messages {
    pace: Pace,
    at_check: Progress,
}

impl Messages {
    pub(crate) fn new(pace: Pace) -> Self {
        Messages {
            pace,
            at_check: Progress::default(),
        }
    }

    pub(crate) fn window(&self) -> Duration {
        self.pace.window
    }

    /// One window passed, and `now` is what the reader has seen. `true` when a message in flight
    /// has fallen below the floor.
    pub(crate) fn check(&mut self, now: Progress) -> bool {
        let behind = now.in_flight
            && self.at_check.in_flight
            && now.completed == self.at_check.completed
            && now.data_bytes - self.at_check.data_bytes < self.pace.min_bytes;
        self.at_check = now;
        behind
    }

    /// The loop was busy past a check and read nothing meanwhile, so the peer's bytes waited on this
    /// side: the next window is the peer's to make, from here.
    pub(crate) fn rebase(&mut self, now: Progress) {
        self.at_check = Progress {
            in_flight: false,
            ..now
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fed(frames: &[&[u8]]) -> Progress {
        let mut parser = Parser::default();
        for frame in frames {
            // A byte at a time, as a peer that trickles would send it.
            for byte in *frame {
                parser.feed(std::slice::from_ref(byte));
            }
        }
        parser.progress
    }

    /// A masked Ping carrying the most a control frame may: 125 bytes.
    fn full_ping() -> Vec<u8> {
        let mut ping = vec![0x89, 0x80 | 125, 1, 2, 3, 4];
        ping.extend(std::iter::repeat_n(5u8, 125));
        ping
    }

    /// A message is in flight from the first byte of its first data frame until its final frame
    /// has arrived whole, and only its data counts as progress; control frames between its
    /// fragments change neither.
    /// Verifies: ADR-0010
    #[test]
    fn data_frames_carry_a_message_and_control_frames_do_not() {
        // A masked binary frame without FIN carrying 3 bytes, then a masked Ping with a payload.
        let first: &[u8] = &[0x02, 0x83, 1, 2, 3, 4, 9, 9, 9];
        let ping = full_ping();
        let ping: &[u8] = &ping;
        let progress = fed(&[first, ping]);
        assert!(progress.in_flight);
        assert_eq!(progress.data_bytes, 3, "a Ping's payload is no data");
        assert_eq!(progress.completed, 0);

        // The final continuation frame, with a 16-bit length of 200 bytes.
        let mut last = vec![0x80, 0xFE, 0x00, 0xC8, 1, 2, 3, 4];
        last.extend(std::iter::repeat_n(7u8, 200));
        let progress = fed(&[first, ping, &last]);
        assert!(!progress.in_flight);
        assert_eq!(progress.data_bytes, 203);
        assert_eq!(progress.completed, 1);
    }

    /// A socket that only pings has no message in flight.
    /// Verifies: ADR-0010
    #[test]
    fn pings_alone_put_no_message_in_flight() {
        let ping = full_ping();
        let progress = fed(&[&ping, &ping, &ping]);
        assert!(!progress.in_flight);
        assert_eq!(progress.data_bytes, 0);
    }
}
