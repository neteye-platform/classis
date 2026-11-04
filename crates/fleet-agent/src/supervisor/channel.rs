//! The channel between the Client and the second service (ADR-0059): the private protocol both ends
//! speak, the second service that starts, signals and stops programs on the Client's request, and
//! the Client's end, through which [`Spawner::Channel`](super::process::Spawner) starts a Managed
//! Process.
//!
//! The protocol is private to the build (ADR-0059 clause 5): both ends run from the same `current`,
//! so a message is a length-prefixed JSON document — a four-byte big-endian length, then the body —
//! and the first message each way is a handshake that names the build. A peer that names another
//! build is refused.
//!
//! The second service admits one peer, the Client's account, checked by the socket's peer
//! credentials or the pipe client's token, and serves one connection at a time. When that
//! connection closes it stops every program it started, by the program's process group on Unix and
//! its job object on Windows, so a Client that restarts finds no process it did not start
//! (ADR-0059 clause 4).
//!
//! On Linux and macOS the channel is a Unix socket and an account is its uid; on Windows it is a
//! named pipe ([`windows`]) and an account is its SID. The protocol, and everything the two ends do
//! with it, is the same.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitStatus;
#[cfg(unix)]
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Child;
#[cfg(unix)]
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::supervisor::process::Launch;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{bind, Account};
#[cfg(windows)]
use windows::{
    close, exit_status, raw_status, signal_program, start, stop_program, Listener, ServerStream,
    Tree,
};

/// An account as the channel knows it: its uid.
#[cfg(unix)]
pub type Account = u32;

/// What the second service listens on.
#[cfg(unix)]
type Listener = UnixListener;

/// The second service's end of one connection.
#[cfg(unix)]
type ServerStream = UnixStream;

/// The next connection on `listener`.
#[cfg(unix)]
async fn accept(listener: &mut Listener) -> io::Result<ServerStream> {
    listener.accept().await.map(|(stream, _)| stream)
}

#[cfg(windows)]
async fn accept(listener: &mut Listener) -> io::Result<ServerStream> {
    listener.accept().await
}

/// The largest message either end accepts. A request carries one program's command line and
/// environment, a reply one line of output; neither comes near it.
const MAX_FRAME: u32 = 1 << 20;

/// The longest line of a program's output relayed as one message; a longer one arrives in pieces.
const MAX_LINE: usize = 16 * 1024;

/// How long the handshake may take before the connection is dropped.
const HANDSHAKE: Duration = Duration::from_secs(5);

/// The largest handshake either end reads: a build name, or a refusal's reason. Until a peer is
/// served it gets no more of the service's memory than this.
const MAX_HANDSHAKE: u32 = 4 * 1024;

/// How often a refused connection is logged at most; the refusals in between are counted into the
/// next warning. A process that can reach the socket cannot fill the log with them.
const REFUSAL_LOG_EVERY: Duration = Duration::from_secs(60);

/// How long a program has to end on `SIGTERM` when the Client's connection closes, before its
/// group is killed. The service manager's stop timeout for the second service is longer, so a stop
/// of the service ends its programs itself rather than having the manager kill it first.
pub(crate) const CLOSE_GRACE: Duration = Duration::from_secs(10);

/// How long the Client waits for the service to answer a signal. The service sends one at once;
/// it answers late only while it stops its programs, on shutting down, and a stop or a reload that
/// waited for that would wait out [`CLOSE_GRACE`] before its own bound began.
pub(crate) const SIGNAL_ANSWER: Duration = Duration::from_secs(2);

/// How long the Client waits for the end of a program it asked the service to kill: an answer's
/// time and the [`OUTPUT_DRAIN`] the exit report waits for the program's last output.
pub(crate) const KILL_ANSWER: Duration = SIGNAL_ANSWER.saturating_add(OUTPUT_DRAIN);

/// How many lines of output may wait to be written to the Client. A program that writes faster
/// than they go out waits on its pipe, as it would on a slow terminal; nothing else waits on it.
const OUTPUT_QUEUE: usize = 256;

/// How long the exit report waits for the rest of a program's output. A process the program left
/// behind may hold its pipes open; its output is still relayed, after the exit, until the
/// connection ends.
pub(crate) const OUTPUT_DRAIN: Duration = Duration::from_secs(1);

/// How long the end of a connection waits for what its programs' trees still hold to end, once
/// ended: on Windows a job's processes end asynchronously after `TerminateJobObject`.
pub(crate) const TREES_END: Duration = Duration::from_secs(5);

/// Ends every process the trees hold and waits, up to [`TREES_END`], until none holds one — so that
/// a stop that reports the second service stopped leaves nothing it started holding a handle
/// (ADR-0059 clause 4). Unix holds no tree and waits for nothing.
async fn end_trees(trees: Vec<Tree>) {
    for tree in &trees {
        tree.end();
    }
    let until = tokio::time::Instant::now() + TREES_END;
    while trees.iter().any(Tree::holds_processes) {
        if tokio::time::Instant::now() >= until {
            warn!("a program's processes had not ended when the connection's end stopped waiting");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How long a start waits for the second service to come back when it finds the connection gone:
/// twice the delay after which the service manager restarts a service that failed, so a start
/// outlasts one restart of the second service.
const RECONNECT: Duration =
    Duration::from_secs(2 * crate::service::manager::RESTART_DELAY_SECS as u64);

/// How often a start tries to reach the second service again while it waits for it.
const RECONNECT_EVERY: Duration = Duration::from_millis(200);

/// How much of each stream a program run to its end keeps — the version probe, the preflight: the
/// last bytes, where a version banner is short and the reason a program did not run is its last
/// line.
pub(crate) const CAPTURED: usize = 64 * 1024;

/// What a program run to its end wrote, kept rather than logged.
#[derive(Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Captured {
    fn push(&mut self, stream: Stream, line: &str) {
        let kept = match stream {
            Stream::Stdout => &mut self.stdout,
            Stream::Stderr => &mut self.stderr,
        };
        kept.extend_from_slice(line.as_bytes());
        kept.push(b'\n');
        if kept.len() > CAPTURED {
            let excess = kept.len() - CAPTURED;
            kept.drain(..excess);
        }
    }
}

/// How long the Client waits for the service to remove what the process account wrote under the
/// directories of the Supervisors one apply purges, all of them together and reaching the service
/// included: as long as a program has to end when the Client's connection closes. However many
/// Supervisors are purged and however much the process account wrote, a purge that
/// outlasts it leaves an orphan, as one the Client cannot delete does (ADR-0017 clause 36), and
/// the Client's management goes on (ADR-0059 clause 2).
pub(crate) const PURGE_ANSWER: Duration = CLOSE_GRACE;

/// What the Client asks of the second service.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Request {
    /// The first message: the Client's build.
    Hello { version: String },
    /// Start a program. `id` is the Client's name for it in every later message.
    Start { id: u64, launch: Launch },
    /// Send `signal` to the program, or, with `group`, to its process group where the program was
    /// asked to lead one ([`Launch::own_process_group`]). Answered, in order, by
    /// [`Reply::Signalled`] or [`Reply::SignalFailed`].
    Signal { id: u64, signal: i32, group: bool },
    /// Kill the program, and its process group where it was asked to lead one.
    Stop { id: u64 },
    /// Remove what the process account wrote under `dir`, the directory of the Supervisor named
    /// `supervisor`, when the Supervisor is purged (ADR-0059 clause 5): what the Client cannot
    /// remove itself. `shared` names, relative to `dir`, the Client's directories the process
    /// account's group writes, where alone the process account can have written; the service
    /// looks for its own entries there itself. Answered by [`Reply::Purged`].
    Purge {
        id: u64,
        supervisor: String,
        dir: PathBuf,
        shared: Vec<PathBuf>,
    },
}

/// What the second service tells the Client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Reply {
    /// The answer to [`Request::Hello`]: the service's build, the same as the Client's.
    Hello { version: String },
    /// The connection is not served, and why. The service closes it after this. `version` is the
    /// service's build where the Client is refused for being another; one of the few messages a
    /// peer of another build reads, so it may be absent.
    Refused {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// The program runs, as `pid`.
    Started { id: u64, pid: u32 },
    /// The program did not start. `os_error` keeps the kind of failure — a missing file, a program
    /// momentarily busy — that the Client's supervision tells apart.
    StartFailed {
        id: u64,
        error: String,
        os_error: Option<i32>,
    },
    /// The signal was sent — or the program has ended, and there was nothing to signal.
    Signalled { id: u64 },
    /// The signal could not be sent, and why.
    SignalFailed { id: u64, error: String },
    /// The answer to [`Request::Purge`]: removed, or why not.
    Purged { id: u64, result: Result<(), String> },
    /// One line the program wrote, without its line end.
    Output {
        id: u64,
        stream: Stream,
        line: String,
    },
    /// The program ended: its raw wait status, or why waiting for it failed. `closing` says that
    /// the service stopped it because the connection or the service itself ends: the program went
    /// with the service and did not exit on its own (ADR-0059 clause 2).
    Exited {
        id: u64,
        status: Result<i32, String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        closing: bool,
    },
}

/// Which of a program's output streams a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    fn name(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }
}

/// The build both ends must share (ADR-0059 clause 5).
fn this_build() -> &'static str {
    fleet_core::version::current()
}

/// One message as it goes on the wire: its length, then its body.
///
/// # Errors
/// Returns `InvalidInput` for a message larger than [`MAX_FRAME`], which no peer would read.
pub(crate) fn encode<T: Serialize>(message: &T) -> io::Result<Zeroizing<Vec<u8>>> {
    // A start carries the Supervisor Endpoint's token, so every frame is wiped (ADR-0057). The
    // frame is sized before it is written: a buffer that grew would leave copies behind unwiped.
    let mut count = Count(0);
    serde_json::to_writer(&mut count, message).map_err(io::Error::other)?;
    let len = u32::try_from(count.0)
        .ok()
        .filter(|len| *len <= MAX_FRAME)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + count.0));
    frame.extend_from_slice(&len.to_be_bytes());
    serde_json::to_writer(&mut *frame, message).map_err(io::Error::other)?;
    debug_assert_eq!(frame.capacity(), 4 + count.0, "the frame grew");
    Ok(frame)
}

/// Counts the bytes written to it and keeps none.
struct Count(usize);

impl io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) async fn write_frame<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode(message)?;
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Reads one message; `None` when the peer closed the connection between two messages.
///
/// Not cancel-safe: each end reads in a task of its own and hands the messages on.
pub(crate) async fn read_frame<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_frame_within(reader, MAX_FRAME).await
}

/// [`read_frame`] for a message of at most `max` bytes: a longer one is refused before its body
/// is read.
async fn read_frame_within<R, T>(reader: &mut R, max: u32) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len);
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = Zeroizing::new(vec![0; len as usize]);
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------------------------
// The second service
// ---------------------------------------------------------------------------------------------

/// Whether a connecting peer is the Client's account (ADR-0059 clause 4): only its uid is served.
///
/// # Errors
/// Returns why the peer is refused.
#[cfg(unix)]
pub fn admit(peer_uid: u32, client_uid: u32) -> Result<(), String> {
    if peer_uid == client_uid {
        Ok(())
    } else {
        Err(format!(
            "uid {peer_uid} is not the Client's account (uid {client_uid})"
        ))
    }
}

/// Whether the service, running as `own_uid`, may serve `client_uid` as the Client's account
/// (ADR-0059 clause 1): the service itself never runs as root, the Client's account is never root,
/// and never the process account the service runs as — a service that served its own account
/// would separate nothing.
///
/// # Errors
/// Returns why the service does not start.
#[cfg(unix)]
pub fn check_client_uid(client_uid: u32, own_uid: u32) -> Result<(), String> {
    if own_uid == 0 {
        return Err(
            "the second service runs as root: it runs under the process account, never as root"
                .to_string(),
        );
    }
    if client_uid == 0 {
        return Err("--client-uid 0: the Client's account is never root".to_string());
    }
    if client_uid == own_uid {
        return Err(format!(
            "--client-uid {client_uid} is the account this service runs as: the process account \
             is never the Client's"
        ));
    }
    Ok(())
}

/// Binds the second service's socket at `path`.
///
/// A socket left behind by an earlier run is removed first; anything else at that path is not, and
/// the bind fails on it. The socket is made `0660`: the Client's account reaches it through the
/// process account's group (ADR-0059 clause 6), and the peer check decides who is served.
///
/// # Errors
/// Returns an error when the path holds something other than a socket, or the bind fails.
#[cfg(unix)]
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// How the second service ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// `SIGTERM` or `SIGINT`: a clean exit, and the service manager leaves it stopped.
    Stopped,
    /// The Client's connection ended — it is another build, or the self-update restarts it — and
    /// `current` no longer names the version this service runs: the self-update switched it. The
    /// process exits non-zero so the service manager starts the version `current` names, as it does
    /// for the Client (ADR-0059 clause 2).
    Superseded,
}

/// `supervisor run --agents <socket> --client-uid <uid>`: the second service (ADR-0059), until
/// `SIGTERM` or `SIGINT`, or until a self-update leaves it behind. `SIGHUP` is ignored, as the
/// Client ignores it (ADR-0019 clause 12): its default disposition would end the service and leave
/// its programs running.
///
/// # Errors
/// Returns an error when the service is dumpable or traced (on Linux), runs as root, `client_uid`
/// is root's or the service's own, the runtime cannot be built, or the socket cannot be bound.
#[cfg(unix)]
pub fn run_service(socket: &Path, client_uid: u32) -> Result<Served, String> {
    #[cfg(target_os = "linux")]
    check_closed()?;
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    check_client_uid(client_uid, unsafe { libc::geteuid() })?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;
    runtime.block_on(async {
        // Before the socket is bound: whoever sees it may already signal the service.
        crate::service::runtime::ignore_sighup();
        let terminated = terminated();
        let listener =
            bind(socket).map_err(|e| format!("cannot listen on {}: {e}", socket.display()))?;
        #[cfg(target_os = "linux")]
        info!(
            socket = %socket.display(),
            client_uid,
            // SAFETY: prctl(2) with no argument to read; no memory is touched.
            dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) },
            "second service listening"
        );
        #[cfg(not(target_os = "linux"))]
        info!(socket = %socket.display(), client_uid, "second service listening");
        let served = serve(listener, client_uid, superseded, terminated).await;
        let _ = std::fs::remove_file(socket);
        if served == Served::Superseded {
            info!(
                "the Client is another build and current names another version; exiting so the \
                 service manager starts that one"
            );
        }
        Ok(served)
    })
}

/// Whether the command line `args`, the program's name left out, runs the second service
/// (`run --agents`): read before anything else, so that its program marks itself not dumpable
/// first ([`mark_not_dumpable`]).
pub fn runs_the_second_service(mut args: impl Iterator<Item = std::ffi::OsString>) -> bool {
    args.any(|arg| {
        arg == "--agents" || arg.to_str().is_some_and(|arg| arg.starts_with("--agents="))
    })
}

/// Closes the second service's process to the Managed Processes (ADR-0059 clause 4): marked not
/// dumpable, no process of its account without `CAP_SYS_PTRACE` attaches to it, reads or writes its
/// memory, or takes its descriptors, whatever `kernel.yama.ptrace_scope` says. The first thing its
/// program does, before it parses its command line or sets up its log; the programs it starts are
/// dumpable as usual, since `execve(2)` resets the mark. [`run_service`] does not listen where the
/// mark is not set.
#[cfg(target_os = "linux")]
pub fn mark_not_dumpable() {
    // SAFETY: prctl(2) with an integer argument; no memory is touched.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, libc::c_ulong::from(0u8)) };
}

/// Whether the second service's process is closed (ADR-0059 clause 4): it is not dumpable, and no
/// process traces it. A tracer attached before the mark stays attached, so a service that is traced
/// does not listen, and the service manager starts it again.
///
/// # Errors
/// Returns that the process is dumpable, or that a process traces it.
#[cfg(target_os = "linux")]
fn check_closed() -> Result<(), String> {
    // SAFETY: prctl(2) with no argument to read; no memory is touched.
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } != 0 {
        return Err(
            "the second service is dumpable: its program did not mark it otherwise at its start"
                .to_string(),
        );
    }
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status for a tracer: {e}"))?;
    match tracer(&status) {
        Some(0) => Ok(()),
        Some(tracer) => Err(format!(
            "the second service is traced by process {tracer}, and does not listen while it is"
        )),
        None => Err("/proc/self/status names no TracerPid".to_string()),
    }
}

/// The process `/proc/<pid>/status` names as the tracer: 0 for none.
#[cfg(target_os = "linux")]
fn tracer(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|pid| pid.trim().parse().ok())
}

/// Whether `current` names a version other than the one this program runs from: a self-update
/// switched it. `false` outside a layout, where there is nothing to switch to, and where the
/// pointer cannot be resolved: the second service, under the process account, ends on nothing
/// but evidence of a switch.
pub(crate) fn superseded() -> bool {
    use crate::service::layout::{running_exe, Layout};
    running_exe()
        .ok()
        .and_then(|exe| Layout::enclosing(&exe))
        .is_some_and(|(layout, running_dir)| layout.names_another(&running_dir))
}

/// `SIGTERM` (what a service manager stops with) or `SIGINT`. Both handlers are in place when this
/// returns, not when the future is first polled: a signal that comes in between would otherwise
/// end the service by its default disposition, its socket left behind. It must be called inside
/// the runtime.
#[cfg(unix)]
fn terminated() -> impl Future<Output = ()> {
    use tokio::signal::unix::{signal, SignalKind};
    let terminate = signal(SignalKind::terminate());
    let interrupt = signal(SignalKind::interrupt());
    async move {
        let (Ok(mut terminate), Ok(mut interrupt)) = (terminate, interrupt) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    }
}

/// Serves the Client on `listener` until `shutdown` resolves, one connection at a time. When a
/// connection closes, or at the shutdown, every program it started is stopped.
///
/// A Client of another build is refused. When a connection of the Client's account has ended —
/// refused for another build, or closed because the self-update restarts the Client — and
/// `superseded` says that this service is the one a self-update left behind, it ends with
/// [`Served::Superseded`], so the version `current` names takes its place. A peer of another
/// account is refused before it is served, and ends nothing.
pub async fn serve(
    mut listener: Listener,
    client: Account,
    superseded: impl Fn() -> bool,
    shutdown: impl Future<Output = ()>,
) -> Served {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut refusals = Refusals::default();
    loop {
        let stream = tokio::select! {
            accepted = accept(&mut listener) => match accepted {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(error = %e, "cannot accept a connection");
                    // Out of descriptors, typically: do not spin on it.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = shutdown.as_mut() => return Served::Stopped,
        };
        // A pipe's client is known only once it has written (`windows::client_of`): there the
        // check follows the handshake's read.
        #[cfg(unix)]
        {
            let peer = stream
                .peer_cred()
                .map_err(|e| format!("cannot read the peer's credentials: {e}"))
                .and_then(|cred| admit(cred.uid(), client));
            if let Err(reason) = peer {
                refuse(stream, reason, &mut refusals);
                continue;
            }
        }
        match serve_connection(
            stream,
            &mut listener,
            &client,
            shutdown.as_mut(),
            &mut refusals,
        )
        .await
        {
            Ended::Shutdown => return Served::Stopped,
            // The Client's connection closed — the self-update restarts it — or it is another
            // build: either way a service that `current` no longer names makes way for the one it
            // does, beside the Client rather than after it.
            Ended::Closed | Ended::OtherBuild if superseded() => return Served::Superseded,
            Ended::Closed | Ended::OtherBuild => {}
        }
    }
}

/// Tells a peer why it is not served, and closes the connection — at once, reading nothing from
/// it: the refusal goes into the socket's empty buffer without waiting, so no refused peer holds a
/// task, a descriptor or a read of the service's.
#[cfg(unix)]
fn refuse(stream: UnixStream, reason: String, refusals: &mut Refusals) {
    if let Some(unlogged) = refusals.note(std::time::Instant::now()) {
        warn!(reason = %reason, unlogged, "refused a connection");
    }
    // Written straight to the socket: a stream just accepted has no readiness yet, so tokio's own
    // `try_write` would only ever answer that it would block.
    if let (Ok(frame), Ok(stream)) = (
        encode(&Reply::Refused {
            reason,
            version: None,
        }),
        stream.into_std(),
    ) {
        use std::io::Write as _;
        let _ = (&stream).write(&frame);
    }
}

/// The refusals logged so far: one warning per [`REFUSAL_LOG_EVERY`] at most.
#[derive(Default)]
struct Refusals {
    logged: Option<std::time::Instant>,
    unlogged: u64,
}

impl Refusals {
    /// Counts one refusal at `now`; `Some` with the refusals not logged since the last warning
    /// when this one is to be logged.
    fn note(&mut self, now: std::time::Instant) -> Option<u64> {
        if self
            .logged
            .is_some_and(|logged| now.duration_since(logged) < REFUSAL_LOG_EVERY)
        {
            self.unlogged += 1;
            return None;
        }
        self.logged = Some(now);
        Some(std::mem::take(&mut self.unlogged))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Closed,
    /// The Client is another build, and was refused.
    OtherBuild,
    Shutdown,
}

/// What the connection asks of one running program.
enum Control {
    Signal {
        signal: i32,
        group: bool,
    },
    Stop,
    /// The connection closed: stop the program's whole group, gracefully first.
    Close,
}

async fn serve_connection<F: Future<Output = ()>>(
    mut stream: ServerStream,
    listener: &mut Listener,
    client: &Account,
    mut shutdown: Pin<&mut F>,
    refusals: &mut Refusals,
) -> Ended {
    let hello = tokio::time::timeout(
        HANDSHAKE,
        read_frame_within::<_, Request>(&mut stream, MAX_HANDSHAKE),
    )
    .await;
    // The pipe's client, known from what it wrote, before anything it said counts: a peer of
    // another account ends no superseded service.
    #[cfg(windows)]
    if let Ok(Ok(Some(_))) = &hello {
        if let Err(reason) = windows::admit(&stream, client) {
            windows::refuse(stream, reason, refusals);
            return Ended::Closed;
        }
    }
    let refusal = match hello {
        Ok(Ok(Some(Request::Hello { version }))) if version == this_build() => None,
        Ok(Ok(Some(Request::Hello { version }))) => Some((
            format!(
                "the Client is build {version}, this service is build {}",
                this_build()
            ),
            Ended::OtherBuild,
        )),
        Ok(Ok(Some(_))) => Some((
            "the first message must be the handshake".to_string(),
            Ended::Closed,
        )),
        Ok(Ok(None)) => return Ended::Closed,
        Ok(Err(e)) => Some((format!("unreadable handshake: {e}"), Ended::Closed)),
        Err(_) => Some(("no handshake in time".to_string(), Ended::Closed)),
    };
    if let Some((reason, ended)) = refusal {
        warn!(reason = %reason, "refused a connection");
        let version = (ended == Ended::OtherBuild).then(|| this_build().to_string());
        let _ = write_frame(&mut stream, &Reply::Refused { reason, version }).await;
        return ended;
    }
    let welcome = Reply::Hello {
        version: this_build().to_string(),
    };
    if write_frame(&mut stream, &welcome).await.is_err() {
        return Ended::Closed;
    }
    let (mut read, mut write) = tokio::io::split(stream);
    info!("the Client connected");

    let (replies, mut reply_rx) = Replies::new();
    let writer = tokio::spawn(async move {
        while let Some(Queued { reply, permit }) = reply_rx.recv().await {
            // A reply too large to send is lost alone; only a broken connection ends the writer.
            let frame = match encode(&reply) {
                Ok(frame) => frame,
                Err(e) => {
                    warn!(error = %e, "cannot send a reply to the Client");
                    continue;
                }
            };
            if write.write_all(&frame).await.is_err() {
                break;
            }
            drop(permit);
        }
    });
    let (request_tx, mut requests) = mpsc::channel::<Request>(64);
    let reader = tokio::spawn(async move {
        while let Ok(Some(request)) = read_frame::<_, Request>(&mut read).await {
            if request_tx.send(request).await.is_err() {
                break;
            }
        }
    });

    let mut programs: HashMap<u64, mpsc::UnboundedSender<Control>> = HashMap::new();
    let mut running: JoinSet<Supervised> = JoinSet::new();
    // The output of processes the programs left behind, still relayed after their exit until the
    // connection ends.
    let mut left_behind: Vec<JoinHandle<()>> = Vec::new();
    // The process trees of programs that ended while something they started still runs: held, so
    // that it ends with the connection too (ADR-0059 clause 4).
    let mut trees: Vec<Tree> = Vec::new();
    let ended = loop {
        tokio::select! {
            request = requests.recv() => match request {
                // An id names one program until it has ended: another start under it would take
                // over the control of the one that runs.
                Some(Request::Start { id, .. }) if programs.contains_key(&id) => {
                    warn!(id, "a start under the id of a running program; refused");
                    replies.send(Reply::StartFailed {
                        id,
                        error: format!("id {id} names a running program"),
                        os_error: None,
                    });
                }
                Some(Request::Start { id, launch }) => match start(&launch) {
                    Ok((child, tree)) => {
                        let pid = child.id().unwrap_or_default();
                        info!(id, pid, program = %launch.program.display(), "program started");
                        replies.send(Reply::Started { id, pid });
                        let (control_tx, control_rx) = mpsc::unbounded_channel();
                        programs.insert(id, control_tx);
                        running.spawn(supervise(
                            id,
                            child,
                            tree,
                            launch.own_process_group,
                            control_rx,
                            replies.clone(),
                        ));
                    }
                    Err(e) => {
                        warn!(id, program = %launch.program.display(), error = %e, "cannot start a program");
                        replies.send(Reply::StartFailed {
                            id,
                            error: e.to_string(),
                            os_error: e.raw_os_error(),
                        });
                    }
                },
                Some(Request::Signal { id, signal, group }) => match programs.get(&id) {
                    Some(control) => {
                        let _ = control.send(Control::Signal { signal, group });
                    }
                    // Ended, as far as this connection knows: nothing to signal, as for a program
                    // the Client has waited for itself.
                    None => replies.send(Reply::Signalled { id }),
                },
                Some(Request::Stop { id }) => {
                    if let Some(control) = programs.get(&id) {
                        let _ = control.send(Control::Stop);
                    }
                }
                // Off the connection's loop: a tree takes as long to remove as it is large, and the
                // programs' output and signals do not wait for it.
                Some(Request::Purge { id, supervisor, dir, shared }) => {
                    let replies = replies.clone();
                    #[cfg(unix)]
                    let client = *client;
                    tokio::task::spawn_blocking(move || {
                        #[cfg(unix)]
                        let result = purge(client, &supervisor, &dir, &shared);
                        #[cfg(windows)]
                        let result = windows::purge(&supervisor, &dir, &shared);
                        match &result {
                            Ok(()) => info!(supervisor = %supervisor, dir = %dir.display(), "removed what the process account wrote"),
                            Err(e) => warn!(supervisor = %supervisor, dir = %dir.display(), error = %e, "cannot remove what the process account wrote"),
                        }
                        replies.send(Reply::Purged { id, result });
                    });
                }
                Some(Request::Hello { .. }) => warn!("a second handshake on one connection; ignored"),
                None => break Ended::Closed,
            },
            Some(done) = running.join_next() => {
                if let Ok(Supervised { id, mut unanswered, relays, tree }) = done {
                    programs.remove(&id);
                    left_behind.retain(|relay| !relay.is_finished());
                    left_behind.extend(relays);
                    trees.retain(Tree::holds_processes);
                    if tree.holds_processes() {
                        trees.push(tree);
                    }
                    // Signals that came after the program ended still get their answer, here, in
                    // the order they were asked.
                    unanswered.close();
                    while let Ok(control) = unanswered.try_recv() {
                        if let Control::Signal { .. } = control {
                            replies.send(Reply::Signalled { id });
                        }
                    }
                }
            }
            accepted = accept(listener) => {
                if let Ok(stream) = accepted {
                    #[cfg(unix)]
                    refuse(stream, "another connection is being served".to_string(), refusals);
                    #[cfg(windows)]
                    windows::refuse(stream, "another connection is being served".to_string(), refusals);
                }
            }
            () = shutdown.as_mut() => break Ended::Shutdown,
        }
    };
    // Whatever ended the connection, nothing it started outlives it (ADR-0059 clause 4).
    for control in programs.values() {
        let _ = control.send(Control::Close);
    }
    while let Some(done) = running.join_next().await {
        if let Ok(Supervised { relays, tree, .. }) = done {
            left_behind.extend(relays);
            trees.push(tree);
        }
    }
    // What the programs left running ends here, and is waited for: before a stop reports the
    // service stopped, nothing it started holds a handle any more (ADR-0059 clause 4).
    end_trees(trees).await;
    // A process that left its program's group — through `setsid` — outlives the stop, and its pipe
    // would hold a relay and a descriptor of the service's for as long as it keeps the pipe open.
    // Its output ends with the connection it was relayed to.
    for relay in &left_behind {
        relay.abort();
    }
    reader.abort();
    // The exits go out before the connection does — bounded, since output a left-behind process
    // still relays holds a sender too.
    drop(replies);
    let writing = writer.abort_handle();
    if tokio::time::timeout(OUTPUT_DRAIN, writer).await.is_err() {
        writing.abort();
    }
    info!("the Client's connection ended; its programs are stopped");
    ended
}

/// The replies to the Client, written in the order they are queued. Queuing never waits, so the
/// connection's loop and a program's supervision never wait on the Client; only output, which a
/// program can make without end, is held to [`OUTPUT_QUEUE`] lines, and the program's relay waits
/// for room.
#[derive(Clone)]
struct Replies {
    queue: mpsc::UnboundedSender<Queued>,
    output: Arc<Semaphore>,
}

/// A reply on its way to the Client; an output line holds its place in the output queue until it
/// is written.
struct Queued {
    reply: Reply,
    permit: Option<OwnedSemaphorePermit>,
}

impl Replies {
    fn new() -> (Replies, mpsc::UnboundedReceiver<Queued>) {
        let (queue, queued) = mpsc::unbounded_channel();
        let replies = Replies {
            queue,
            output: Arc::new(Semaphore::new(OUTPUT_QUEUE)),
        };
        (replies, queued)
    }

    /// Queues a reply that is not output: one per request or per program, never waiting.
    fn send(&self, reply: Reply) {
        let _ = self.queue.send(Queued {
            reply,
            permit: None,
        });
    }

    /// Queues a line of output once there is room for it; `false` once the connection is gone.
    async fn output(&self, reply: Reply) -> bool {
        let Ok(permit) = Arc::clone(&self.output).acquire_owned().await else {
            return false;
        };
        self.queue
            .send(Queued {
                reply,
                permit: Some(permit),
            })
            .is_ok()
    }
}

/// Starts a program as the leader of a process group of its own, always: whatever its own
/// [`Launch::own_process_group`] says, the stop at the connection's end takes its whole tree.
///
/// Its environment is the service's own, with the process account's `HOME`, `USER` and `LOGNAME`,
/// and the request's environment laid over it — the block's `env`, then the Supervisor Endpoint's
/// token (ADR-0059 clause 7).
#[cfg(unix)]
fn start(launch: &Launch) -> io::Result<(Child, Tree)> {
    let mut command = Command::new(&launch.program);
    command
        .args(&launch.args)
        .envs(account_env().iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    launch.set_env(&mut command);
    if let Some(dir) = &launch.working_dir {
        command.current_dir(dir);
    }
    // The program keeps the service's own umask, never one widened for the Client's sake
    // (ADR-0059 clause 5): what it makes that the Client cannot remove, the service removes for
    // it when the Supervisor is purged (`Request::Purge`).
    let child = command.spawn()?;
    let group = child.id();
    Ok((child, Tree(group)))
}

/// The process group a program leads, by its id: what a stop signals.
#[cfg(unix)]
struct Tree(Option<u32>);

#[cfg(unix)]
impl Tree {
    /// Whether the connection must hold on to the tree after its program ended: never on Unix,
    /// where nothing is held, and a stop signals the group of a program that runs.
    #[allow(clippy::unused_self)]
    fn holds_processes(&self) -> bool {
        false
    }

    /// Ends what is left of the tree: nothing on Unix, which holds none.
    #[allow(clippy::unused_self)]
    fn end(&self) {}
}

/// Removes what the process account wrote under `dir`, the directory of the Supervisor named
/// `supervisor`, which the Client purges (ADR-0059 clause 5): every entry this service's account
/// owns in each of the directories `shared` names relative to `dir`, and in the directories beneath
/// them it can read, with everything beneath it. The service holds the request to that and no
/// more:
///
/// - `dir` is absolute, the tombstone of the Supervisor
///   ([`crate::reconfigure::tombstone_name`]) — never its own directory, which a Supervisor added
///   again under the same name gets afresh — and the Client's account owns it and the directory
///   it is in, the Supervisors' root;
/// - `dir` itself is no link, and a link on the way to the Supervisors' root is followed only
///   where root or the Client's account owns it, as the Client follows it
///   ([`crate::storage::handle::open_beneath`]) — never one of the process account's, this
///   service's own;
/// - each of `shared` is a path beneath it, of plain names alone;
/// - no link is followed beneath `dir`, and an entry, a link included, is removed as what it is;
/// - only what this service's account owns is removed.
///
/// What cannot be reached is passed over, and the rest goes on. What is gone already — the
/// tombstone, or anything in it, which a start and a purge may each be removing — is no error.
///
/// # Errors
/// Returns why the request is refused, or the first entry that cannot be reached or removed.
#[cfg(unix)]
pub(crate) fn purge(
    client_uid: u32,
    supervisor: &str,
    dir: &Path,
    shared: &[PathBuf],
) -> Result<(), String> {
    use crate::storage::handle;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let named = dir
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| crate::config::tombstone_of(name) == Some(supervisor));
    let (Some(root), true) = (dir.parent().filter(|_| dir.is_absolute()), named) else {
        return Err(format!(
            "{} is not the tombstone of the Supervisor {supervisor}",
            dir.display()
        ));
    };
    let at = |e: io::Error| format!("{}: {e}", dir.display());
    let parent = handle::open_beneath(root, root, handle::SEARCH, None, client_uid).map_err(at)?;
    // Gone already: a start and a purge each remove a tombstone left behind, and the one that
    // comes second finds nothing left to do.
    let top = match handle::open_beneath(root, dir, handle::SEARCH, None, client_uid) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        top => top.map_err(at)?,
    };
    for (what, handle) in [(root, &parent), (dir, &top)] {
        let owner = handle::fstat(handle).map_err(at)?.st_uid;
        if owner != client_uid {
            return Err(format!(
                "{} belongs to uid {owner}, not to the Client's account",
                what.display()
            ));
        }
    }
    let mut first = None;
    for relative in shared {
        let path = dir.join(relative);
        let names = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => std::ffi::CString::new(name.as_bytes()).ok(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .filter(|names| !names.is_empty());
        let Some(names) = names else {
            first.get_or_insert_with(|| {
                format!(
                    "{} is not a path beneath the Supervisor's directory",
                    relative.display()
                )
            });
            continue;
        };
        let (last, parents) = names.split_last().expect("not empty");
        let reached = parents
            .iter()
            .try_fold(top.try_clone().map_err(at)?, |parent, name| {
                handle::open(parent.as_raw_fd(), name, handle::SEARCH)
            })
            .and_then(|parent| handle::open(parent.as_raw_fd(), last, handle::DIRECTORY));
        let result = match reached {
            Ok(shared) => remove_own(&shared, &path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        };
        if let Err(e) = result {
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), Err)
}

/// Removes every entry this service's account owns in `dir`, with everything beneath it, and
/// looks the same way into each directory there that it can read: never through a link.
#[cfg(unix)]
fn remove_own(dir: &std::os::fd::OwnedFd, path: &Path) -> Result<(), String> {
    use crate::storage::handle;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    let me = unsafe { libc::geteuid() };
    let mut first = None;
    for name in handle::entries(dir).map_err(|e| format!("{}: {e}", path.display()))? {
        let child = path.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let result = match handle::lstat_at(dir.as_raw_fd(), &name) {
            Ok(st) if st.st_uid == me => match handle::remove_tree_at(dir, &name, &child) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            },
            Ok(st) if handle::is(&st, libc::S_IFDIR) => {
                // A directory of the Client's it may not read holds nothing of its own.
                match handle::open(dir.as_raw_fd(), &name, handle::DIRECTORY) {
                    Ok(inner) => remove_own(&inner, &child),
                    Err(_) => Ok(()),
                }
            }
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", child.display())),
        };
        if let Err(e) = result {
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), Err)
}

/// `HOME`, `USER` and `LOGNAME` of the account this service runs as — the process account — from
/// the password database, whatever the environment the service was started with says. Empty
/// where the database names no such account.
///
/// Under systemd this repeats what the service manager already sets for a unit with `User=`
/// (`SetLoginEnvironment=`, systemd.exec(5)), unless an operator's drop-in turns that off. It
/// stays for launchd, whose plist names the account in `UserName` and whose manual does not say
/// that it sets these variables for it, and so that clause 7 holds whatever the service manager
/// does.
#[cfg(unix)]
fn account_env() -> &'static [(String, std::ffi::OsString)] {
    static ACCOUNT: std::sync::OnceLock<Vec<(String, std::ffi::OsString)>> =
        std::sync::OnceLock::new();
    ACCOUNT.get_or_init(|| {
        // SAFETY: geteuid(2) cannot fail and touches no memory.
        let uid = unsafe { libc::geteuid() };
        match crate::service::run_as::account_of(uid) {
            Ok(Some(account)) => vec![
                ("HOME".to_string(), account.home.into_os_string()),
                ("USER".to_string(), account.name.clone().into()),
                ("LOGNAME".to_string(), account.name.into()),
            ],
            Ok(None) => {
                warn!(uid, "the password database names no account for this service's uid; its programs keep HOME, USER and LOGNAME as the service has them");
                Vec::new()
            }
            Err(e) => {
                warn!(uid, error = %e, "cannot look up this service's account; its programs keep HOME, USER and LOGNAME as the service has them");
                Vec::new()
            }
        }
    })
}

/// A program that has ended, as its supervision hands it back to the connection.
struct Supervised {
    id: u64,
    /// What was asked of the program that it did not get to.
    unanswered: mpsc::UnboundedReceiver<Control>,
    /// The relays of its output that did not finish within [`OUTPUT_DRAIN`]: a process it left
    /// behind holds the pipe.
    relays: Vec<JoinHandle<()>>,
    /// Its process tree, which may outlive it.
    tree: Tree,
}

/// Watches one program: relays its output, carries out what the connection asks, and reports its
/// exit. Returns once the program has ended.
async fn supervise(
    id: u64,
    mut child: Child,
    tree: Tree,
    own_process_group: bool,
    mut control: mpsc::UnboundedReceiver<Control>,
    replies: Replies,
) -> Supervised {
    let stdout = child
        .stdout
        .take()
        .map(|pipe| tokio::spawn(relay(id, Stream::Stdout, pipe, replies.clone())));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| tokio::spawn(relay(id, Stream::Stderr, pipe, replies.clone())));
    let (status, closing) = loop {
        tokio::select! {
            status = child.wait() => break (status, false),
            Some(request) = control.recv() => match request {
                Control::Signal { signal, group } => {
                    let sent = signal_program(&child, signal, group && own_process_group);
                    replies.send(match sent {
                        Ok(()) => Reply::Signalled { id },
                        Err(e) => Reply::SignalFailed {
                            id,
                            error: e.to_string(),
                        },
                    });
                }
                Control::Stop => stop_program(&tree, &mut child, own_process_group),
                // A program that has already ended exited on its own, whichever of the two the
                // select saw first: the stop at the connection's end never passes a crash off as
                // one it caused.
                Control::Close => match child.try_wait() {
                    Ok(Some(status)) => break (Ok(status), false),
                    _ => break (close(&mut child, &tree).await, true),
                },
            },
        }
    };
    let mut relays = Vec::new();
    let drained = tokio::time::Instant::now() + OUTPUT_DRAIN;
    for mut relay in [stdout, stderr].into_iter().flatten() {
        if tokio::time::timeout_at(drained, &mut relay).await.is_err() {
            relays.push(relay);
        }
    }
    let status = status.map(raw_status).map_err(|e| e.to_string());
    replies.send(Reply::Exited {
        id,
        status,
        closing,
    });
    Supervised {
        id,
        unanswered: control,
        relays,
        tree,
    }
}

/// Sends `signal` to the program, or with `group` to its process group; nothing once it ended.
#[cfg(unix)]
fn signal_program(child: &Child, signal: i32, group: bool) -> io::Result<()> {
    match child.id() {
        Some(pid) => send_signal(pid, signal, group),
        None => Ok(()),
    }
}

/// Kills the program, and its process group where it was asked to lead one.
#[cfg(unix)]
fn stop_program(_tree: &Tree, child: &mut Child, own_process_group: bool) {
    if let Some(pid) = child.id() {
        let _ = send_signal(pid, libc::SIGKILL, own_process_group);
    }
    let _ = child.start_kill();
}

/// An exit as the protocol carries it: the raw wait status.
#[cfg(unix)]
fn raw_status(status: ExitStatus) -> i32 {
    status.into_raw()
}

/// An exit the protocol carried, as the Client's supervision reads it.
#[cfg(unix)]
fn exit_status(raw: i32) -> ExitStatus {
    ExitStatus::from_raw(raw)
}

/// The stop at the connection's end: `SIGTERM` to the program's group, a bounded wait, then
/// `SIGKILL` to the group — sent even when the program ended in time, for anything it left behind.
#[cfg(unix)]
async fn close(child: &mut Child, tree: &Tree) -> io::Result<std::process::ExitStatus> {
    let group = tree.0;
    if let Some(pgid) = group {
        let _ = send_signal(pgid, libc::SIGTERM, true);
    }
    let status = match tokio::time::timeout(CLOSE_GRACE, child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            let _ = child.start_kill();
            child.wait().await
        }
    };
    if let Some(pgid) = group {
        let _ = send_signal(pgid, libc::SIGKILL, true);
    }
    status
}

#[cfg(unix)]
fn send_signal(pid: u32, signal: i32, group: bool) -> io::Result<()> {
    let pid = pid as libc::pid_t;
    // SAFETY: plain kill(2); no memory is touched.
    match unsafe { libc::kill(if group { -pid } else { pid }, signal) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Relays a program's output, line by line, until the pipe closes or the connection is gone.
async fn relay(id: u64, stream: Stream, pipe: impl AsyncRead + Unpin, replies: Replies) {
    let mut reader = tokio::io::BufReader::new(pipe);
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_line_bounded(&mut reader, &mut line, MAX_LINE).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        let line = String::from_utf8_lossy(&line).into_owned();
        if !replies.output(Reply::Output { id, stream, line }).await {
            break;
        }
    }
}

/// Reads up to and including the next line end, or `max` bytes, whichever comes first.
async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> io::Result<usize> {
    let mut total = 0;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total);
        }
        let room = max - buf.len();
        let (take, done) = match available.iter().take(room).position(|b| *b == b'\n') {
            Some(end) => (end + 1, true),
            None => {
                let take = available.len().min(room);
                (take, take == room)
            }
        };
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        total += take;
        if done {
            return Ok(total);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The Client's end
// ---------------------------------------------------------------------------------------------

const CLOSED: &str = "the second service closed the channel";

/// The Client's channel to the second service, one connection at a time. Cloning shares it. A
/// start that finds the connection gone — the service restarted — connects again, waiting up to
/// [`RECONNECT`] for the service to come back; the programs started through the old connection
/// have ended with it.
///
/// The connection closes, and the service stops whatever still runs, when the service goes or
/// when the last clone and the last program started through it are dropped.
#[derive(Clone)]
pub struct Channel {
    shared: Arc<Shared>,
}

struct Shared {
    socket: PathBuf,
    /// The account the socket must be served by: the process account (ADR-0059 clause 4).
    service: Account,
    /// Who names the process the socket must be served by: the second service's (ADR-0059 clause
    /// 4).
    process: ServiceProcess,
    state: tokio::sync::Mutex<State>,
    /// Whether `current` names a version other than the one this Client runs from.
    superseded: fn() -> bool,
    /// Set once the second service is another build and `current` no longer names this Client's
    /// version: the self-update left this Client behind (ADR-0059 clause 2).
    left_behind: tokio::sync::watch::Sender<bool>,
}

#[derive(Default)]
struct State {
    connection: Option<Arc<Connection>>,
    /// When the last wait for the service ended without reaching it: a start in the same outage
    /// tries once rather than waiting out [`RECONNECT`] again behind every Supervisor before it.
    gave_up: Option<Instant>,
    /// The refusals met so far, logged sparingly: a start meets one every [`RECONNECT_EVERY`].
    refusals: Refusals,
    /// The peers refused as not the second service, logged sparingly too, apart from the
    /// refusals: a warning about a build or an account never holds back the error that names an
    /// impostor (ADR-0059 clause 4).
    impostors: Refusals,
}

/// A wait for the service, holding the channel's state: dropped after it tried in vain — out of
/// time, or cut short — it notes the wait as given up on.
struct Waiting<'a> {
    state: tokio::sync::MutexGuard<'a, State>,
    in_vain: bool,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if self.in_vain {
            self.state.gave_up = Some(Instant::now());
        }
    }
}

/// One connection to the second service.
struct Connection {
    /// Requests, encoded: one too large for a message is refused before it is queued.
    requests: mpsc::UnboundedSender<Zeroizing<Vec<u8>>>,
    /// The task that writes them; ended once the service is gone, which closes the connection on
    /// the Client's side too.
    writer: AbortHandle,
    next_id: AtomicU64,
    routes: Mutex<Routes>,
}

#[derive(Default)]
struct Routes {
    /// Set once the service is gone: no route is added after that.
    closed: bool,
    by_id: HashMap<u64, Route>,
    /// The purges asked and not yet answered.
    purges: HashMap<u64, oneshot::Sender<Result<(), String>>>,
}

/// Where the replies about one program go, for as long as its [`RemoteChild`] lives.
struct Route {
    /// The Supervisor the program runs for, which its output is logged under.
    supervisor: String,
    started: Option<oneshot::Sender<io::Result<u32>>>,
    exited: Option<oneshot::Sender<Result<i32, String>>>,
    /// The signals sent and not yet answered, in the order they were sent.
    signals: VecDeque<oneshot::Sender<Result<(), String>>>,
    /// Where the output of a program run to its end is kept instead of logged.
    captured: Option<Arc<Mutex<Captured>>>,
}

impl Channel {
    /// The channel to the second service at `socket`, served by the account `service` and by the
    /// process `process` names. Nothing is connected until the first start.
    #[must_use]
    pub fn new(socket: &Path, service: Account, process: ServiceProcess) -> Channel {
        Channel::with_superseded(socket, service, process, superseded)
    }

    /// [`Channel::new`], told by `superseded` whether a self-update switched `current`.
    pub(crate) fn with_superseded(
        socket: &Path,
        service: Account,
        process: ServiceProcess,
        superseded: fn() -> bool,
    ) -> Channel {
        Channel {
            shared: Arc::new(Shared {
                socket: socket.to_path_buf(),
                service,
                process,
                state: tokio::sync::Mutex::new(State::default()),
                superseded,
                left_behind: tokio::sync::watch::channel(false).0,
            }),
        }
    }

    /// Resolves once the second service turned out to be another build while `current` no longer
    /// names the version this Client runs: the self-update left the Client behind, and it ends for
    /// the restart that starts the version `current` names, as the service does in its place
    /// (ADR-0059 clause 2). Only the process account's socket can tell it so (clause 4).
    pub async fn left_behind(&self) {
        let mut left_behind = self.shared.left_behind.subscribe();
        let _ = left_behind.wait_for(|left| *left).await;
    }

    /// [`Channel::new`], connected now, once.
    ///
    /// # Errors
    /// Returns an error when the socket cannot be reached, is not served by `service` or by the
    /// process `process` names, the service refuses the connection, or it is another build.
    pub async fn connect(
        socket: &Path,
        service: Account,
        process: ServiceProcess,
    ) -> io::Result<Channel> {
        let connection = Connection::open(socket, &service, &process).await?;
        let channel = Channel::new(socket, service, process);
        channel.shared.state.lock().await.connection = Some(connection);
        Ok(channel)
    }

    /// Asks the service to start `launch` for the Supervisor named `supervisor`, and waits until it
    /// runs or did not start.
    ///
    /// Cancel-safe: a start dropped before the answer asks the service to stop the program it may
    /// have started, as dropping its [`RemoteChild`] would.
    ///
    /// # Errors
    /// Returns the service's reason the program did not start, keeping its OS error, or why the
    /// service could not be reached.
    ///
    /// A start that does not reach the service — it cannot be connected to, refuses the Client, or
    /// goes during the start as well as before it — fails with an error [`is_unreachable`] tells
    /// apart from a program that did not start.
    pub(crate) async fn start(&self, supervisor: &str, launch: Launch) -> io::Result<RemoteChild> {
        self.start_keeping(supervisor, launch, None).await
    }

    /// Asks the service to run `launch` for the Supervisor named `supervisor` to its end, and
    /// returns what it wrote — the last [`CAPTURED`] bytes of each stream — with how it ended: the
    /// version probe and the preflight, run under the process account (ADR-0059 clause 3).
    ///
    /// Cancel-safe: dropped before the end, it asks the service to stop the program.
    ///
    /// # Errors
    /// Returns what [`Channel::start`] returns, or that the service went before the program
    /// ended.
    pub(crate) async fn output(
        &self,
        supervisor: &str,
        launch: Launch,
    ) -> io::Result<std::process::Output> {
        let captured = Arc::new(Mutex::new(Captured::default()));
        let mut child = self
            .start_keeping(supervisor, launch, Some(Arc::clone(&captured)))
            .await?;
        let status = child.wait().await?;
        // The service sends a program's output before its exit, on the one connection.
        let captured = std::mem::take(
            &mut *captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        Ok(std::process::Output {
            status,
            stdout: captured.stdout,
            stderr: captured.stderr,
        })
    }

    /// [`Channel::start`], keeping the program's output in `captured` where one is given.
    async fn start_keeping(
        &self,
        supervisor: &str,
        launch: Launch,
        captured: Option<Arc<Mutex<Captured>>>,
    ) -> io::Result<RemoteChild> {
        let connection = self.connection().await.map_err(unreachable)?;
        match Arc::clone(&connection)
            .start(supervisor, launch.clone(), captured.clone())
            .await
        {
            // The service went while the start was on its way, and what it started went with it:
            // the start goes to the service that comes back.
            Err(e) if connection.is_closed() => {
                debug!(error = %e, "the second service went during a start; connecting again");
                let connection = self.connection().await.map_err(unreachable)?;
                match Arc::clone(&connection)
                    .start(supervisor, launch, captured)
                    .await
                {
                    Err(e) if connection.is_closed() => Err(unreachable(e)),
                    started => started,
                }
            }
            started => started,
        }
    }

    /// Reaches the service: the open connection, or a new one once the last is gone.
    ///
    /// # Errors
    /// Returns why the service was not reached, an error [`is_unreachable`] holds for.
    pub(crate) async fn reach(&self) -> io::Result<()> {
        self.connection().await.map(|_| ()).map_err(unreachable)
    }

    /// Asks the service to remove what the process account wrote in each of `removed` — the
    /// Supervisor's name and its directory — and the Client cannot remove itself (ADR-0059
    /// clause 5), one request per Supervisor: the service looks for its own entries in the
    /// directories the Client shares for writing beneath the directory
    /// ([`crate::storage::handle::shared_for_writing`]). A file the process account owns in a
    /// directory of the Client's is the Client's to remove too, and the purge that follows removes
    /// it where the service did not.
    ///
    /// All of them are asked at once and waited for [`PURGE_ANSWER`] together, reaching the
    /// service included, however many there are: one apply waits for the service once.
    ///
    /// # Errors
    /// Each answer, in the order of `removed`, is what the service could not remove, or why it
    /// was not reached — in time, too.
    pub(crate) async fn purge(&self, removed: &[(String, PathBuf)]) -> Vec<io::Result<()>> {
        let deadline = Instant::now() + PURGE_ANSWER;
        let asked = removed.iter().map(|(supervisor, dir)| async move {
            let one = async {
                let shared = {
                    let dir = dir.clone();
                    tokio::task::spawn_blocking(move || {
                        #[cfg(unix)]
                        return crate::storage::handle::shared_for_writing(&dir);
                        #[cfg(windows)]
                        return windows::directories_beneath(&dir);
                    })
                    .await
                    .map_err(io::Error::other)?
                };
                // Gone already, as the service answers too: a start and a purge each remove a
                // tombstone left behind.
                let shared = match shared {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                    shared => shared?,
                };
                if shared.is_empty() {
                    return Ok(());
                }
                let connection = self.connection().await.map_err(unreachable)?;
                connection.purge(supervisor, dir, shared).await
            };
            tokio::time::timeout_at(deadline, one)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "the second service did not remove what the process account wrote under {} within {}s",
                            dir.display(),
                            PURGE_ANSWER.as_secs()
                        ),
                    ))
                })
        });
        futures_util::future::join_all(asked).await
    }

    /// The open connection, or a new one once the last is gone.
    ///
    /// A wait that tried and did not reach the service is noted as given up on, however it ends:
    /// out of time, or cut short by whoever waited — a purge's deadline — so that the next wait
    /// in the same outage tries once.
    async fn connection(&self) -> io::Result<Arc<Connection>> {
        let mut state = self.shared.state.lock().await;
        if let Some(connection) = state.connection.as_ref().filter(|c| !c.is_closed()) {
            return Ok(Arc::clone(connection));
        }
        state.connection = None;
        let waited_in_vain = state.gave_up.is_some_and(|at| at.elapsed() < RECONNECT);
        let deadline = Instant::now()
            + if waited_in_vain {
                Duration::ZERO
            } else {
                RECONNECT
            };
        let mut waiting = Waiting {
            state,
            in_vain: false,
        };
        loop {
            match Connection::open(
                &self.shared.socket,
                &self.shared.service,
                &self.shared.process,
            )
            .await
            {
                Ok(connection) => {
                    waiting.state.gave_up = None;
                    waiting.state.connection = Some(Arc::clone(&connection));
                    waiting.in_vain = false;
                    return Ok(connection);
                }
                Err(e) if is_other_build(&e) && (self.shared.superseded)() => {
                    info!(
                        error = %e,
                        "the second service is another build and current names another version; \
                         this Client is the one left behind"
                    );
                    self.shared.left_behind.send_replace(true);
                    waiting.in_vain = true;
                    return Err(e);
                }
                Err(e) => {
                    waiting.in_vain = true;
                    // Whoever serves the socket is not the second service: it heard nothing, and
                    // the service is waited for as one that is away (ADR-0059 clause 4).
                    if let Some(peer) = other_process(&e) {
                        if let Some(unlogged) =
                            waiting.state.impostors.note(std::time::Instant::now())
                        {
                            error!(
                                socket = %self.shared.socket.display(),
                                peer_pid = %peer.map_or_else(|| "unread".to_string(), |pid| pid.to_string()),
                                error = %e, unlogged,
                                "refused a peer that is not the second service, before writing anything to it; no program starts until the service manager's second service serves the socket"
                            );
                        }
                    }
                    // Not an outage that ends by itself: the operator is to hear of it.
                    if is_refusal(&e) {
                        if let Some(unlogged) =
                            waiting.state.refusals.note(std::time::Instant::now())
                        {
                            warn!(
                                socket = %self.shared.socket.display(), error = %e, unlogged,
                                "the second service is refused; no program starts until the process account serves this build on its socket"
                            );
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                    debug!(socket = %self.shared.socket.display(), error = %e, "the second service cannot be reached yet");
                    tokio::time::sleep(RECONNECT_EVERY).await;
                }
            }
        }
    }

    /// The connection open now, for a test to look into.
    #[cfg(all(test, unix))]
    async fn open_connection(&self) -> Option<Arc<Connection>> {
        self.shared.state.lock().await.connection.clone()
    }
}

impl Connection {
    /// Connects to the second service at `socket` and exchanges the handshake.
    ///
    /// The socket's peer is checked before anything is written: whoever serves it learns every
    /// program's command line and environment, the Supervisor Endpoint's token among them, so only
    /// the process account is told (ADR-0059 clause 4), and of its processes only the one `process`
    /// names as the second service (ADR-0059 clause 4).
    async fn open(
        socket: &Path,
        service: &Account,
        process: &ServiceProcess,
    ) -> io::Result<Arc<Connection>> {
        #[cfg(unix)]
        let (stream, peer, peer_process) = {
            use std::os::fd::AsFd as _;
            let stream = UnixStream::connect(socket).await?;
            let peer = stream.peer_cred()?.uid();
            let peer_process = peer_process(stream.as_fd());
            (stream, peer, peer_process)
        };
        #[cfg(windows)]
        let (stream, peer, peer_process) = {
            let stream = windows::connect(socket)?;
            let peer = windows::server_of(&stream)?;
            let peer_process = windows::server_process(&stream);
            (stream, peer, peer_process)
        };
        check_service(&peer, service, socket)
            .map_err(|e| io::Error::new(e.kind(), Refusal(e.to_string())))?;
        check_process(peer_process, process, socket).await?;
        #[cfg(unix)]
        let (mut read, mut write) = stream.into_split();
        #[cfg(windows)]
        let (mut read, mut write) = tokio::io::split(stream);
        let hello = Request::Hello {
            version: this_build().to_string(),
        };
        // A refused Client may find the connection closed before its handshake is written; the
        // refusal is read all the same, and says why.
        let sent = write_frame(&mut write, &hello).await;
        let answer = tokio::time::timeout(
            HANDSHAKE,
            read_frame_within::<_, Reply>(&mut read, MAX_HANDSHAKE),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no handshake in time"));
        let answer = match (answer, sent) {
            (Ok(Ok(Some(refused @ Reply::Refused { .. }))), _) => Some(refused),
            (_, Err(e)) => return Err(e),
            (answer, Ok(())) => answer??,
        };
        match answer {
            Some(Reply::Hello { version }) if version == this_build() => {}
            // What the peer says is quoted, bounded and escaped: whoever serves the socket says it,
            // a Managed Process of the process account among them, and it reaches the Server in
            // the Supervisor's health.
            Some(Reply::Hello { version }) => {
                return Err(io::Error::other(OtherBuild(format!(
                    "the second service is build {}, this Client is build {}",
                    peer_text(&version),
                    this_build()
                ))))
            }
            Some(Reply::Refused {
                reason,
                version: Some(version),
            }) if version != this_build() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    OtherBuild(format!(
                        "the second service refused this Client: {}",
                        peer_text(&reason)
                    )),
                ))
            }
            Some(Reply::Refused { reason, .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    Refusal(format!(
                        "the second service refused this Client: {}",
                        peer_text(&reason)
                    )),
                ))
            }
            Some(_) => return Err(io::Error::other("the second service skipped the handshake")),
            None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, CLOSED)),
        }

        Ok(Connection::pumped(read, write))
    }

    /// The connection over `read` and `write`, its handshake made: a task that writes the requests
    /// and one that dispatches the replies.
    fn pumped<R, W>(mut read: R, mut write: W) -> Arc<Connection>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (requests, mut outgoing) = mpsc::unbounded_channel::<Zeroizing<Vec<u8>>>();
        let (reader_tx, reader_rx) = oneshot::channel::<Weak<Connection>>();
        let (writer_tx, writer_rx) = oneshot::channel::<Weak<Connection>>();
        // Holds the connection weakly, so it does not keep the senders below alive.
        let reader = tokio::spawn(async move {
            let Ok(weak) = reader_rx.await else {
                return;
            };
            while let Ok(Some(reply)) = read_frame::<_, Reply>(&mut read).await {
                let Some(connection) = weak.upgrade() else {
                    return;
                };
                connection.dispatch(reply);
            }
            if let Some(connection) = Weak::upgrade(&weak) {
                connection.fail_all();
            }
        })
        .abort_handle();
        // Ends when every sender is gone — the last `Channel` and `RemoteChild` dropped — or when
        // the service is. Where the senders are gone the read half goes too, and with both halves
        // the connection: a named pipe has no half to close, so the service learns that the
        // Client is gone only once the pipe is closed, and nobody waits for a reply any more.
        // Where a write fails the service is gone, and what waits for it fails at once, whether
        // or not the reader has seen the end yet.
        let writer = tokio::spawn(async move {
            let Ok(weak) = writer_rx.await else {
                return;
            };
            while let Some(frame) = outgoing.recv().await {
                if write.write_all(&frame).await.is_err() {
                    if let Some(connection) = weak.upgrade() {
                        connection.fail_all();
                    }
                    return;
                }
            }
            reader.abort();
        })
        .abort_handle();
        let connection = Arc::new(Connection {
            requests,
            writer,
            next_id: AtomicU64::new(1),
            routes: Mutex::new(Routes::default()),
        });
        let _ = reader_tx.send(Arc::downgrade(&connection));
        let _ = writer_tx.send(Arc::downgrade(&connection));
        connection
    }

    /// Whether the service is gone: its replies have ended, or a request could not be written.
    fn is_closed(&self) -> bool {
        self.routes().closed || self.requests.is_closed()
    }

    async fn start(
        self: Arc<Self>,
        supervisor: &str,
        launch: Launch,
        captured: Option<Arc<Mutex<Captured>>>,
    ) -> io::Result<RemoteChild> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (started_tx, started) = oneshot::channel();
        let (exited_tx, exited) = oneshot::channel();
        {
            let mut routes = self.routes();
            if routes.closed {
                return Err(closed());
            }
            routes.by_id.insert(
                id,
                Route {
                    supervisor: supervisor.to_string(),
                    started: Some(started_tx),
                    exited: Some(exited_tx),
                    signals: VecDeque::new(),
                    captured,
                },
            );
        }
        if let Err(e) = self.send(&Request::Start { id, launch }) {
            self.routes().by_id.remove(&id);
            return Err(e);
        }
        let pending = Pending {
            connection: &self,
            id,
        };
        let answer = started.await;
        std::mem::forget(pending);
        let pid = answer.map_err(|_| closed())??;
        Ok(RemoteChild {
            connection: self,
            id,
            pid,
            exited: Some(exited),
            outcome: None,
        })
    }

    async fn purge(
        self: Arc<Self>,
        supervisor: &str,
        dir: &Path,
        shared: Vec<PathBuf>,
    ) -> io::Result<()> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (purged_tx, purged) = oneshot::channel();
        {
            let mut routes = self.routes();
            if routes.closed {
                return Err(closed());
            }
            routes.purges.insert(id, purged_tx);
        }
        let request = Request::Purge {
            id,
            supervisor: supervisor.to_string(),
            dir: dir.to_path_buf(),
            shared,
        };
        // Forgotten however the wait ends: answered, failed, or given up on at the purge's
        // deadline, after which no answer is waited for.
        let _route = PurgeRoute {
            connection: &self,
            id,
        };
        self.send(&request)?;
        purged
            .await
            .map_err(|_| closed())?
            .map_err(|e| io::Error::other(peer_text(&e)))
    }

    /// Queues `request`. A request too large for a message fails here, with `InvalidInput`, and
    /// the connection carries on.
    fn send(&self, request: &Request) -> io::Result<()> {
        let frame = encode(request)?;
        self.requests.send(frame).map_err(|_| closed())
    }

    fn routes(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn dispatch(&self, reply: Reply) {
        match reply {
            Reply::Started { id, pid } => {
                if let Some(started) = self
                    .routes()
                    .by_id
                    .get_mut(&id)
                    .and_then(|route| route.started.take())
                {
                    let _ = started.send(Ok(pid));
                }
            }
            Reply::StartFailed {
                id,
                error,
                os_error,
            } => {
                // Only a start still waiting is answered: under the id of a running program the
                // route is that program's, and stays.
                let started = {
                    let mut routes = self.routes();
                    let started = routes
                        .by_id
                        .get_mut(&id)
                        .and_then(|route| route.started.take());
                    if started.is_some() {
                        routes.by_id.remove(&id);
                    }
                    started
                };
                if let Some(started) = started {
                    // Quoted as a refusal is: whoever serves the socket says it (ADR-0059
                    // clauses 4 and 5), and from here it reaches the log and the Server.
                    let error = match os_error {
                        Some(code) => io::Error::from_raw_os_error(code),
                        None => io::Error::other(peer_text(&error)),
                    };
                    let _ = started.send(Err(error));
                }
            }
            // Logged, not written to the Client's own streams: under the Supervisor it belongs to,
            // and escaped, so a program cannot pass a line of its own off as one of the Client's.
            Reply::Output { id, stream, line } => {
                let route = self
                    .routes()
                    .by_id
                    .get(&id)
                    .map(|route| (route.supervisor.clone(), route.captured.clone()));
                match route {
                    // Kept for the one who asked, who reads it, rather than logged.
                    Some((_, Some(captured))) => captured
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(stream, &line),
                    Some((supervisor, None)) => {
                        info!(supervisor = %supervisor, stream = %stream.name(), line = ?line, "output");
                    }
                    // A process the program left behind, still writing after the program's end.
                    None => {
                        info!(program = id, stream = %stream.name(), line = ?line, "output after the program ended");
                    }
                }
            }
            Reply::Purged { id, result } => {
                if let Some(purged) = self.routes().purges.remove(&id) {
                    let _ = purged.send(result);
                }
            }
            Reply::Signalled { id } => self.answer_signal(id, Ok(())),
            Reply::SignalFailed { id, error } => self.answer_signal(id, Err(peer_text(&error))),
            Reply::Exited {
                id,
                status,
                closing,
            } => {
                if let Some(exited) = self
                    .routes()
                    .by_id
                    .get_mut(&id)
                    .and_then(|route| route.exited.take())
                {
                    // Stopped because the service goes: no exit of the program's, but the same
                    // as the channel closing under it, which a Supervisor waits out.
                    let _ = exited.send(if closing {
                        Err(CLOSED.to_string())
                    } else {
                        status.map_err(|e| peer_text(&e))
                    });
                }
            }
            Reply::Hello { .. } | Reply::Refused { .. } => {
                warn!("the second service repeated the handshake; ignored");
            }
        }
    }

    fn answer_signal(&self, id: u64, answer: Result<(), String>) {
        if let Some(signalled) = self
            .routes()
            .by_id
            .get_mut(&id)
            .and_then(|route| route.signals.pop_front())
        {
            let _ = signalled.send(answer);
        }
    }

    /// The service is gone: every program started through it is reported ended, and the
    /// connection is closed on this side too, so the service — should it still read — stops what
    /// it started for it.
    fn fail_all(&self) {
        let mut routes = self.routes();
        routes.closed = true;
        routes.by_id.clear();
        routes.purges.clear();
        self.writer.abort();
    }
}

/// Why the second service was not reached, wrapped so that a program that did not start — whose
/// error may carry the same kind, `NotFound` for one — is told apart from it. `refused` where it
/// was reached and one end refused the other: a socket of another account, a service of another
/// build, or a refusal of the Client — a cause of its own, which no restart of the service mends.
#[derive(Debug)]
struct Unreachable {
    error: io::Error,
    refused: bool,
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.refused {
            write!(f, "the second service is refused: {}", self.error)
        } else {
            write!(f, "the second service cannot be reached: {}", self.error)
        }
    }
}

impl std::error::Error for Unreachable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The socket is served by another account than the process account's, or the service refused
/// the Client.
#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// Whether `error` is a refusal by either end of the handshake: the peer is another account or
/// another build, or it refused the Client.
fn is_refusal(error: &io::Error) -> bool {
    is_other_build(error) || error.get_ref().is_some_and(|inner| inner.is::<Refusal>())
}

/// At most this many characters of what a peer says go into an error.
const PEER_TEXT: usize = 120;

/// What a peer said, quoted for an error: at most [`PEER_TEXT`] characters, and everything but
/// printable ASCII escaped, so that it can neither pass off a line of its own in the Client's log
/// nor carry a long text of its own choosing to the Server.
fn peer_text(text: &str) -> String {
    let mut quoted: String = text
        .chars()
        .take(PEER_TEXT)
        .flat_map(char::escape_default)
        .collect();
    if text.chars().nth(PEER_TEXT).is_some() {
        quoted.push_str("...");
    }
    format!("\"{quoted}\"")
}

/// The second service is another build: it said so, or named another in its handshake.
#[derive(Debug)]
struct OtherBuild(String);

impl std::fmt::Display for OtherBuild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OtherBuild {}

/// Whether `error` is the handshake's refusal of another build.
fn is_other_build(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<OtherBuild>())
}

/// `error`, marked as the second service not reached; its kind is kept.
fn unreachable(error: io::Error) -> io::Error {
    if is_unreachable(&error) {
        return error;
    }
    let refused = is_refusal(&error);
    io::Error::new(error.kind(), Unreachable { error, refused })
}

/// Whether `error` says that the second service was not reached, rather than that a program did
/// not start or failed: a start or a wait that ended so is no failure of the program's, and a
/// Supervisor tries again once the service is back (ADR-0059 clause 2).
#[must_use]
pub fn is_unreachable(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<Unreachable>())
}

/// Whether `error` says that the second service was reached and one end refused the other — a
/// socket of another account, another build, or a refusal of the Client — rather than that it
/// is down. [`is_unreachable`] holds for it too: it is no failure of the program's either.
#[must_use]
pub fn is_refused(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Unreachable>())
        .is_some_and(|unreachable| unreachable.refused)
}

/// Whether the socket is served by the process account (ADR-0059 clause 4). Its directory belongs
/// to that account, so any process the account runs could put a socket of its own in its place;
/// only one of another account is told apart here — the Managed Processes share the account, and
/// read one another's environment already (ADR-0059, Consequences).
///
/// # Errors
/// Returns `PermissionDenied` naming both accounts.
fn check_service(peer: &Account, service: &Account, socket: &Path) -> io::Result<()> {
    if peer == service {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is served by {} {peer}, not by the process account ({} {service})",
            socket.display(),
            ACCOUNT_IS,
            ACCOUNT_IS
        ),
    ))
}

/// How an account is named in a message: by its uid, or its SID.
#[cfg(unix)]
const ACCOUNT_IS: &str = "uid";
#[cfg(windows)]
const ACCOUNT_IS: &str = "SID";

/// Names the process the service manager runs as the second service (ADR-0059 clause 4): systemd
/// the unit's `MainPID`, launchd the job's `pid`, the SCM the service's process id — `None` where
/// it runs none. Asked anew at every connection; a test names one in its place.
#[derive(Clone)]
pub struct ServiceProcess(Arc<dyn Fn() -> Result<Option<u32>, String> + Send + Sync>);

impl ServiceProcess {
    /// The one the native service manager names ([`crate::service::manager::agents_process`]).
    #[must_use]
    pub fn manager() -> ServiceProcess {
        ServiceProcess::named(crate::service::manager::agents_process)
    }

    /// The one `named` names.
    #[must_use]
    pub fn named(
        named: impl Fn() -> Result<Option<u32>, String> + Send + Sync + 'static,
    ) -> ServiceProcess {
        ServiceProcess(Arc::new(named))
    }

    /// Asks once, off the runtime's threads: the service manager is asked through a program it
    /// ships, or the SCM.
    async fn ask(&self) -> Result<Option<u32>, String> {
        let named = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || named())
            .await
            .unwrap_or_else(|e| Err(format!("the question was cut short: {e}")))
    }
}

/// The process at the other end of a connection, as the platform reports it (ADR-0059 clause 4).
pub(crate) struct PeerProcess {
    pub(crate) pid: u32,
    /// On Linux from 6.5, a pidfd for that process: it refers to that process alone, never to a
    /// later holder of its id.
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl PeerProcess {
    /// Whether the process still runs: where there is a pidfd, it has not ended (the pidfd polls
    /// readable once it has, poll(2)); without one there is nothing to tell it by.
    ///
    /// # Errors
    /// Returns why the pidfd could not be polled.
    fn running(&self) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        if let Some(pidfd) = &self.pidfd {
            use std::os::fd::AsRawFd as _;
            let mut poll = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one pollfd, valid for the call, and no wait.
            if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(poll.revents == 0);
        }
        Ok(true)
    }
}

/// The process at the other end of the connected socket `socket`: its pidfd (`SO_PEERPIDFD`) and
/// its id (`SO_PEERCRED`), both as they were when it called `listen(2)`. Without a pidfd only where
/// the kernel does not know the option (`ENOPROTOOPT`, before Linux 6.5); any other error is a
/// process that cannot be read, and nothing is fallen back to.
///
/// # Errors
/// Returns why the process could not be read.
#[cfg(target_os = "linux")]
fn peer_process(socket: std::os::fd::BorrowedFd<'_>) -> io::Result<PeerProcess> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    /// `SO_PEERPIDFD`, as `asm-generic/socket.h` numbers it for the architectures the Client is
    /// built for; the libc crate has no name for it.
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: an int and its length, both valid for the call.
    let got = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            std::ptr::from_mut(&mut fd).cast(),
            &mut len,
        )
    };
    let pidfd = if got == 0 {
        // SAFETY: a descriptor the kernel just opened for this process, owned from here.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOPROTOOPT) {
            return Err(e);
        }
        None
    };
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a ucred and its length, both valid for the call.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerProcess {
        pid: process_id(cred.pid)?,
        pidfd,
    })
}

/// The process at the other end of the connected socket `socket` (`LOCAL_PEERPID`), as it was
/// when it called `listen(2)`.
///
/// # Errors
/// Returns why the process could not be read.
#[cfg(target_os = "macos")]
fn peer_process(socket: std::os::fd::BorrowedFd<'_>) -> io::Result<PeerProcess> {
    use std::os::fd::AsRawFd as _;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: a pid_t and its length, both valid for the call.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::from_mut(&mut pid).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerProcess {
        pid: process_id(pid)?,
    })
}

/// `pid` as a process id: never 0 or below, which names no process.
#[cfg(unix)]
fn process_id(pid: libc::pid_t) -> io::Result<u32> {
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| io::Error::other(format!("the socket names process {pid}")))
}

/// Whether the socket is served by the process the service manager runs as the second service
/// (ADR-0059 clause 4). The account alone cannot tell: the Managed Processes run under the process
/// account too, and can put a socket of their own in its place, or an instance of the pipe beside
/// its own. A peer whose process cannot be read, or for which the manager names no process, is
/// refused as one whose process differs. With a pidfd its process must still run once the manager
/// has answered, so that its id cannot have passed to the second service in between.
///
/// # Errors
/// Returns a refusal [`other_process`] reads the peer's process id from.
async fn check_process(
    peer: io::Result<PeerProcess>,
    process: &ServiceProcess,
    socket: &Path,
) -> io::Result<()> {
    let refused = |pid: Option<u32>, reason: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            OtherProcess { pid, reason },
        )
    };
    let socket = socket.display();
    let peer = peer.map_err(|e| {
        refused(
            None,
            format!("the process serving {socket} cannot be read: {e}"),
        )
    })?;
    let pid = peer.pid;
    match process.ask().await {
        Err(e) => Err(refused(
            Some(pid),
            format!(
                "{socket} is served by process {pid}, and the service manager cannot be asked which process is the second service: {e}"
            ),
        )),
        Ok(None) => Err(refused(
            Some(pid),
            format!(
                "{socket} is served by process {pid}, and the service manager runs no process as the second service"
            ),
        )),
        Ok(Some(named)) if named != pid => Err(refused(
            Some(pid),
            format!("{socket} is served by process {pid}, not by the second service (process {named})"),
        )),
        Ok(Some(_)) => match peer.running() {
            Ok(true) => Ok(()),
            Ok(false) => Err(refused(
                Some(pid),
                format!(
                    "{socket} was served by process {pid}, which has ended: its id names another process now"
                ),
            )),
            Err(e) => Err(refused(
                Some(pid),
                format!("whether process {pid}, which serves {socket}, still runs cannot be read: {e}"),
            )),
        },
    }
}

/// The socket is served by a process other than the second service's, or by one that cannot be
/// read (ADR-0059 clause 4).
#[derive(Debug)]
struct OtherProcess {
    pid: Option<u32>,
    reason: String,
}

impl std::fmt::Display for OtherProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OtherProcess {}

/// Where `error` is the refusal of a peer that is not the second service: `Some` with its process
/// id, where it could be read.
fn other_process(error: &io::Error) -> Option<Option<u32>> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<OtherProcess>())
        .map(|other| other.pid)
}

/// A start sent and not yet answered. Dropped — the start abandoned — it stops the program the
/// service may already run and forgets its route; an answered start forgets the guard instead.
struct Pending<'a> {
    connection: &'a Connection,
    id: u64,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.connection.routes().by_id.remove(&self.id);
        let _ = self.connection.send(&Request::Stop { id: self.id });
    }
}

/// A purge asked and waited for: its route is forgotten once the wait ends, however it ends.
struct PurgeRoute<'a> {
    connection: &'a Connection,
    id: u64,
}

impl Drop for PurgeRoute<'_> {
    fn drop(&mut self) {
        self.connection.routes().purges.remove(&self.id);
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, CLOSED)
}

/// A program the second service started for the Client: what [`tokio::process::Child`] is to a
/// program the Client started itself.
pub struct RemoteChild {
    /// The connection it was started on, which its replies come back on.
    connection: Arc<Connection>,
    id: u64,
    pid: u32,
    exited: Option<oneshot::Receiver<Result<i32, String>>>,
    outcome: Option<Result<ExitStatus, String>>,
}

impl RemoteChild {
    /// The program's pid, until its exit has been seen.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.outcome.is_none().then_some(self.pid)
    }

    /// Waits for the program to end. Cancel-safe; once it has ended, answers at once.
    ///
    /// # Errors
    /// Returns an error when the service could not wait for it, or the channel closed first or
    /// the service stopped the program on going — the service went, and the program with it,
    /// which [`is_unreachable`] says.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        if self.outcome.is_none() {
            let reported = match self.exited.as_mut() {
                Some(exited) => exited.await.unwrap_or_else(|_| Err(CLOSED.to_string())),
                None => Err(CLOSED.to_string()),
            };
            self.exited = None;
            self.outcome = Some(reported.map(exit_status));
        }
        match &self.outcome {
            Some(Ok(status)) => Ok(*status),
            Some(Err(e)) if e == CLOSED => Err(unreachable(closed())),
            Some(Err(e)) => Err(io::Error::other(e.clone())),
            None => Err(unreachable(closed())),
        }
    }

    /// Sends `signal` to the program, or with `group` to its process group where it leads one, and
    /// waits for the service's answer, up to [`SIGNAL_ANSWER`]. Once the program has ended there is
    /// nothing to signal.
    ///
    /// # Errors
    /// Returns why the service could not send the signal, that it did not answer in time, or that
    /// the channel is closed.
    pub async fn signal(&self, signal: i32, group: bool) -> io::Result<()> {
        if self.outcome.is_some() {
            return Ok(());
        }
        let (signalled, answer) = oneshot::channel();
        {
            let mut routes = self.connection.routes();
            let Some(route) = routes.by_id.get_mut(&self.id) else {
                return Err(closed());
            };
            self.connection.send(&Request::Signal {
                id: self.id,
                signal,
                group,
            })?;
            route.signals.push_back(signalled);
        }
        // A late answer still finds its place in the queue, and goes nowhere; the order holds.
        match tokio::time::timeout(SIGNAL_ANSWER, answer).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(e))) => Err(io::Error::other(e)),
            Ok(Err(_)) => Err(closed()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the second service did not answer the signal in time",
            )),
        }
    }

    /// Kills the program and waits for its end to be reported, up to [`KILL_ANSWER`]: the
    /// service kills at once, except while it stops its programs on shutting down, and then it
    /// ends this one itself.
    ///
    /// # Errors
    /// Returns an error when the channel closed before the exit was reported, or the report did
    /// not come in time.
    pub async fn kill(&mut self) -> io::Result<()> {
        if self.outcome.is_none() {
            self.connection.send(&Request::Stop { id: self.id })?;
        }
        match tokio::time::timeout(KILL_ANSWER, self.wait()).await {
            Ok(waited) => waited.map(|_| ()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the second service did not report the program's end in time",
            )),
        }
    }
}

impl Drop for RemoteChild {
    /// Takes the program along, as `kill_on_drop` does for a program the Client started itself.
    fn drop(&mut self) {
        self.connection.routes().by_id.remove(&self.id);
        if self.outcome.is_none() {
            let _ = self.connection.send(&Request::Stop { id: self.id });
        }
    }
}

/// A stand-in for the second service, for the cases its real behaviour cannot be steered into: it
/// shakes hands, then answers each request with what `answer` makes of it.
#[cfg(all(test, unix))]
pub(crate) mod peer {
    use super::*;

    /// A connection to the stand-in, and the directory its socket lives in.
    pub(crate) struct Peer {
        pub(crate) channel: Channel,
        _dir: tempfile::TempDir,
    }

    /// Serves one connection with `answer` and connects the Client's end to it.
    pub(crate) async fn connect(
        mut answer: impl FnMut(Request) -> Vec<Reply> + Send + 'static,
    ) -> Peer {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            while let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await {
                let replies = match request {
                    Request::Hello { .. } => vec![hello()],
                    request => answer(request),
                };
                for reply in replies {
                    if write_frame(&mut stream, &reply).await.is_err() {
                        return;
                    }
                }
            }
        });
        let channel = Channel::connect(&socket, own_uid(), this_process())
            .await
            .expect("connect");
        Peer { channel, _dir: dir }
    }

    /// The second service itself, in process: it runs as this test's uid and serves the Client
    /// of this test's uid, until it is dropped.
    pub(crate) struct Real {
        pub(crate) socket: PathBuf,
        _stop: oneshot::Sender<()>,
        _dir: tempfile::TempDir,
    }

    /// Starts [`Real`].
    pub(crate) fn real() -> Real {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = bind(&socket).expect("bind");
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(serve(listener, own_uid(), || false, async {
            let _ = stopped.await;
        }));
        Real {
            socket,
            _stop: stop,
            _dir: dir,
        }
    }

    /// The stand-in's answer to the Client's handshake.
    pub(crate) fn hello() -> Reply {
        Reply::Hello {
            version: this_build().to_string(),
        }
    }

    /// The process this test runs as, named as the second service's: it serves the stand-ins and
    /// the in-process services (ADR-0059 clause 4).
    pub(crate) fn this_process() -> ServiceProcess {
        ServiceProcess::named(|| Ok(Some(std::process::id())))
    }

    /// The uid this test runs as, which serves its stand-ins and its in-process services.
    pub(crate) fn own_uid() -> u32 {
        // SAFETY: getuid(2) cannot fail and touches no memory.
        unsafe { libc::getuid() }
    }

    /// Starts every program as a pid nobody has, kills it on a stop, and never answers a signal —
    /// as the second service does not while it stops its programs on shutting down.
    pub(crate) fn mute(request: Request) -> Vec<Reply> {
        match request {
            Request::Start { id, .. } => vec![Reply::Started { id, pid: u32::MAX }],
            Request::Stop { id } => vec![Reply::Exited {
                id,
                status: Ok(libc::SIGKILL),
                closing: false,
            }],
            _ => Vec::new(),
        }
    }

    /// Starts every program as a pid nobody has, and answers nothing else: not a signal and not a
    /// stop.
    pub(crate) fn deaf(request: Request) -> Vec<Reply> {
        match request {
            Request::Start { id, .. } => vec![Reply::Started { id, pid: u32::MAX }],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod pump_tests {
    use super::*;

    /// A write half whose every write fails, as one to a service that went does.
    struct Gone;

    impl AsyncWrite for Gone {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A request the Client cannot write fails what waits for the service at once, before the
    /// reader has seen the service go — here it never does: a start must not wait for ever.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_write_that_fails_fails_what_waits() {
        let (read, _open) = tokio::io::duplex(64);
        let connection = Connection::pumped(read, Gone);
        let launch = Launch {
            program: PathBuf::from("agent"),
            args: Vec::new(),
            env: Vec::new(),
            endpoint_token: None,
            working_dir: None,
            own_process_group: false,
        };
        let started = tokio::time::timeout(
            Duration::from_secs(5),
            Arc::clone(&connection).start("test", launch, None),
        )
        .await
        .expect("the start ends");
        assert!(started.is_err());
        assert!(connection.is_closed());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::peer::{own_uid, this_process};
    use super::*;

    fn sh(script: &str) -> Launch {
        Launch {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), script.to_string()],
            env: Vec::new(),
            endpoint_token: None,
            working_dir: None,
            own_process_group: false,
        }
    }

    struct Service {
        _dir: tempfile::TempDir,
        socket: PathBuf,
        stop: Option<oneshot::Sender<()>>,
        task: JoinHandle<Served>,
    }

    fn service(client_uid: u32) -> Service {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let (stop, task) = listen(&socket, client_uid, || false);
        Service {
            _dir: dir,
            socket,
            stop: Some(stop),
            task,
        }
    }

    /// The service on `socket`, until the sender is used or dropped.
    fn listen(
        socket: &Path,
        client_uid: u32,
        superseded: fn() -> bool,
    ) -> (oneshot::Sender<()>, JoinHandle<Served>) {
        let listener = bind(socket).expect("bind");
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, client_uid, superseded, async {
            let _ = stopped.await;
        }));
        (stop, task)
    }

    async fn connect_raw(socket: &Path, version: &str) -> UnixStream {
        let mut stream = UnixStream::connect(socket).await.expect("connect");
        write_frame(
            &mut stream,
            &Request::Hello {
                version: version.to_string(),
            },
        )
        .await
        .expect("hello");
        stream
    }

    async fn next(stream: &mut UnixStream) -> Option<Reply> {
        tokio::time::timeout(Duration::from_secs(10), read_frame(stream))
            .await
            .expect("a reply in time")
            .expect("a readable reply")
    }

    /// A program the service starts has the process account's `HOME`, `USER` and `LOGNAME` from
    /// the password database, the block's `env` over the service's own environment, and the
    /// Supervisor Endpoint's token last, so no `env` can replace it (ADR-0059 clause 7). Its output
    /// comes back to the one who ran it.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_program_has_the_process_accounts_home_and_the_token_last() {
        let account = crate::service::run_as::account_of(own_uid())
            .expect("look up this test's account")
            .expect("this test's account has an entry");
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        let mut launch = sh("echo \"$HOME|$USER|$LOGNAME|$KEPT|$OPAMP_SUPERVISOR_TOKEN\"");
        launch.env = vec![
            ("KEPT".to_string(), "from the block".to_string()),
            (
                "OPAMP_SUPERVISOR_TOKEN".to_string(),
                "from the block".to_string(),
            ),
            (
                "OPAMP_SUPERVISOR_TOKEN".to_string(),
                "the token".to_string(),
            ),
        ];
        let output = channel.output("test", launch).await.expect("ran");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!(
                "{}|{}|{}|from the block|the token\n",
                account.home.display(),
                account.name,
                account.name
            )
        );
    }

    /// A program the second service starts keeps the service's own umask, never one widened for
    /// the Client's sake (ADR-0059 clause 5): what it creates has the modes what the service
    /// itself creates has.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_program_keeps_the_services_umask() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        let made = dir.path().join("made");
        let launch = sh(&format!("mkdir {0} && : > {0}/file", made.display()));
        let output = channel.output("test", launch).await.expect("ran");
        assert!(output.status.success(), "{output:?}");
        let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
        // What this process — the service, here — makes at its own umask.
        let reference = dir.path().join("reference");
        std::fs::create_dir(&reference).expect("mkdir");
        std::fs::write(reference.join("file"), b"").expect("write");
        assert_eq!(mode(&made), mode(&reference));
        assert_eq!(mode(&made.join("file")), mode(&reference.join("file")));
    }

    /// A Supervisor's directory as a Managed Process leaves it under the process account: a data
    /// directory the Client shares for writing, holding a directory it made with `MkdirAll`'s
    /// `0755`, a read-only one inside it as a Go module cache makes them, files, and a link out of
    /// the directory.
    fn written_by_an_agent(supervisor: &Path, outside: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        let data = supervisor.join("data");
        let made = data.join("made");
        let cache = made.join("cache");
        std::fs::create_dir_all(&cache).expect("mkdir");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o2770)).expect("chmod");
        std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(cache.join("module"), b"x").expect("write");
        std::os::unix::fs::symlink(outside, made.join("out")).expect("a link");
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    }

    /// The second service removes what a purged Supervisor's Managed Processes wrote — read-only
    /// directories included, a link as a link — so the Client's purge that follows leaves
    /// nothing (ADR-0059 clause 5, ADR-0017 clause 34).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn the_second_service_removes_what_a_purged_supervisors_processes_wrote() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"kept").expect("write");
        let supervisor = dir
            .path()
            .join("supervisors")
            .join(crate::reconfigure::tombstone_name("agent"));
        written_by_an_agent(&supervisor, &outside);
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");

        let purged = channel
            .purge(&[("agent".to_string(), supervisor.clone())])
            .await;
        assert!(purged.iter().all(Result::is_ok), "{purged:?}");
        std::fs::remove_dir_all(&supervisor).expect("the Client's purge");
        assert!(!supervisor.exists());
        assert_eq!(std::fs::read(&outside).expect("outside"), b"kept");
    }

    /// The service removes no more than a purge asks of it: its own entries in directories beneath
    /// the tombstone of the Supervisor it names, of plain names, reached through no link, in a
    /// directory the Client's account owns (ADR-0059 clause 5).
    /// Verifies: ADR-0059
    #[test]
    fn a_purge_removes_nothing_outside_the_supervisors_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).expect("mkdir");
        std::fs::write(outside.join("keep"), b"kept").expect("write");
        let tomb = crate::reconfigure::tombstone_name("agent");
        let supervisor = dir.path().join("supervisors").join(&tomb);
        let relative = Path::new("supervisors").join(&tomb);
        let data = supervisor.join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("state"), b"x").expect("write");
        std::os::unix::fs::symlink(&outside, data.join("out")).expect("a link in data");
        std::os::unix::fs::symlink(&outside, supervisor.join("link")).expect("a link");
        let me = own_uid();
        let shared = |path: &str| vec![PathBuf::from(path)];

        for (name, at, within) in [
            ("other", supervisor.as_path(), shared("data")),
            ("agent", relative.as_path(), shared("data")),
            ("agent", supervisor.as_path(), shared("../outside")),
            ("agent", supervisor.as_path(), shared("data/../../outside")),
            ("agent", supervisor.as_path(), vec![outside.clone()]),
            ("agent", supervisor.as_path(), shared("")),
            ("agent", supervisor.as_path(), shared("link")),
            ("agent", supervisor.as_path(), shared("link/keep")),
        ] {
            let refused = purge(me, name, at, &within);
            assert!(refused.is_err(), "{name} {} {within:?}", at.display());
        }
        assert!(purge(me.wrapping_add(1), "agent", &supervisor, &shared("data")).is_err());
        assert_eq!(std::fs::read(outside.join("keep")).expect("kept"), b"kept");
        assert!(data.join("state").exists());

        // Its own entries go, a link as a link; the directory the Client shares stays.
        purge(me, "agent", &supervisor, &shared("data")).expect("the data directory's");
        assert_eq!(std::fs::read(outside.join("keep")).expect("kept"), b"kept");
        assert!(data.is_dir());
        assert_eq!(std::fs::read_dir(&data).expect("read").count(), 0);
    }

    /// The service purges the tombstone of the Supervisor it names, a directory the Client moved
    /// aside beneath the Supervisors' root, and nothing that only looks like one: another
    /// Supervisor's tombstone, a name of no tombstone, a link of that name, or the Supervisor's
    /// own directory, which a Supervisor added again under the same name holds (ADR-0059 clause
    /// 5, ADR-0017 clause 34).
    /// Verifies: ADR-0059
    #[test]
    fn a_purge_takes_only_the_tombstone_of_the_supervisor_it_names() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("supervisors");
        let tomb = root.join(crate::reconfigure::tombstone_name("agent"));
        let data = tomb.join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o2770)).expect("chmod");
        std::fs::write(data.join("state"), b"x").expect("write");
        let linked = root.join(crate::reconfigure::tombstone_name("agent"));
        std::os::unix::fs::symlink(&tomb, &linked).expect("a link");
        let live = root.join("agent").join("data");
        std::fs::create_dir_all(&live).expect("mkdir");
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o2770)).expect("chmod");
        std::fs::write(live.join("state"), b"new").expect("write");
        let me = own_uid();
        let shared = vec![PathBuf::from("data")];

        for (name, at) in [
            ("other", tomb.clone()),
            ("agent", root.join(".purge-agent-")),
            ("agent", root.join(".purge-agent-xyz")),
            ("agent", root.join(".purge-other-1f")),
            ("agent", linked),
            ("agent", root.join("agent")),
        ] {
            assert!(
                purge(me, name, &at, &shared).is_err(),
                "{name} {}",
                at.display()
            );
        }
        assert!(data.join("state").exists());
        assert!(live.join("state").exists());

        purge(me, "agent", &tomb, &shared).expect("the tombstone's");
        assert!(!data.join("state").exists());
        assert!(live.join("state").exists());
    }

    /// The second service passes through the Supervisors' root and the tombstone, which the
    /// process account may search and not read (`0710`, ADR-0059 clause 6), to the data its
    /// programs wrote: on Linux through a path-only handle, on macOS through `O_SEARCH`. Run
    /// unprivileged, the test's own account holds the search right alone on both.
    /// Verifies: ADR-0059
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_purge_passes_through_directories_it_may_only_search() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("supervisors");
        let tomb = root.join(crate::reconfigure::tombstone_name("agent"));
        let data = tomb.join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("state"), b"x").expect("write");
        let chmod = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        };
        chmod(&tomb, 0o100);
        chmod(&root, 0o100);
        let unreadable = own_uid() == 0 || std::fs::read_dir(&root).is_err();
        let purged = purge(own_uid(), "agent", &tomb, &[PathBuf::from("data")]);
        chmod(&root, 0o700);
        chmod(&tomb, 0o700);
        assert!(unreadable, "the root is searched, never read");
        purged.expect("passed through");
        assert!(!data.join("state").exists());
    }

    /// A tombstone a start and a purge both set out to remove is gone for whichever comes second:
    /// neither the service nor the Client asking it takes that for what the process account
    /// wrote and could not be removed (ADR-0059 clause 12).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_tombstone_gone_already_is_no_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("supervisors");
        std::fs::create_dir_all(&root).expect("mkdir");
        let gone = root.join(crate::reconfigure::tombstone_name("agent"));
        let tomb = root.join(crate::reconfigure::tombstone_name("agent"));
        std::fs::create_dir_all(&tomb).expect("mkdir");

        purge(own_uid(), "agent", &gone, &[PathBuf::from("data")]).expect("gone already");
        purge(own_uid(), "agent", &tomb, &[PathBuf::from("data")]).expect("its data gone");
        let channel = Channel::new(&dir.path().join("nobody.sock"), own_uid(), this_process());
        let answers = channel.purge(&[("agent".to_string(), gone)]).await;
        assert!(answers.iter().all(Result::is_ok), "{answers:?}");
    }

    /// On the way to the Supervisors' root the service follows the links the Client follows —
    /// root's and the Client's account's — and not its own: it runs as the process account, which
    /// is not the Client's. Run unprivileged, a link of this test's own account is refused where
    /// the Client is another account; run as root, a link of the Client's account is followed and
    /// one of a third account is refused (ADR-0059 clause 5, ADR-0017 clause 35).
    /// Verifies: ADR-0059
    #[test]
    fn a_purge_follows_the_clients_links_above_the_root_and_not_the_services() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        let tomb = crate::reconfigure::tombstone_name("agent");
        let data = real.join("supervisors").join(&tomb).join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("state"), b"x").expect("write");
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).expect("a link above the root");
        let through = linked.join("supervisors").join(&tomb);
        let shared = vec![PathBuf::from("data")];
        let me = own_uid();
        if me != 0 {
            let error = purge(me + 1, "agent", &through, &shared)
                .expect_err("the service's own link, for another Client");
            assert!(error.contains("not trusted"), "{error}");
            assert!(data.join("state").exists());
            return;
        }
        let (client, other) = (4242, 4243);
        let owned_by = |path: &Path, uid: u32| {
            std::os::unix::fs::lchown(path, Some(uid), None).expect("lchown");
        };
        owned_by(&real.join("supervisors"), client);
        owned_by(&real.join("supervisors").join(&tomb), client);
        owned_by(&linked, other);
        let error = purge(client, "agent", &through, &shared).expect_err("a third account's link");
        assert!(error.contains("not trusted"), "{error}");
        assert!(data.join("state").exists());
        owned_by(&linked, client);
        purge(client, "agent", &through, &shared).expect("the Client's own link");
        assert!(!data.join("state").exists());
    }

    /// The Client asks once per purged Supervisor, naming the directories it shares for writing,
    /// so whoever serves the process account's socket holds it [`PURGE_ANSWER`] and no longer,
    /// however many entries the process account wrote: a service that answers each request just
    /// before the Client gives up on it is asked once, and one that never answers is given up on
    /// (ADR-0059 clause 2, ADR-0017 clause 36).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_purge_waits_for_the_service_once_however_much_was_written() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("supervisors").join("agent");
        let data = supervisor.join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o2770)).expect("chmod");
        for n in 0..20 {
            std::fs::create_dir(data.join(n.to_string())).expect("an entry");
        }
        tokio::time::pause();
        for answers in [true, false] {
            let socket = dir.path().join(format!("agents-{answers}.sock"));
            let listener = UnixListener::bind(&socket).expect("bind");
            let asked = Arc::new(Mutex::new(Vec::new()));
            let heard = Arc::clone(&asked);
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                while let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await {
                    let reply = match request {
                        Request::Hello { .. } => peer::hello(),
                        Request::Purge { id, shared, .. } => {
                            heard.lock().expect("lock").push(shared);
                            if !answers {
                                continue;
                            }
                            tokio::time::sleep(PURGE_ANSWER - Duration::from_secs(1)).await;
                            Reply::Purged { id, result: Ok(()) }
                        }
                        _ => continue,
                    };
                    if write_frame(&mut stream, &reply).await.is_err() {
                        return;
                    }
                }
            });
            let channel = Channel::connect(&socket, own_uid(), this_process())
                .await
                .expect("connect");
            let started = tokio::time::Instant::now();
            let mut purged = channel
                .purge(&[("agent".to_string(), supervisor.clone())])
                .await;
            let purged = purged.pop().expect("one answer");
            let elapsed = started.elapsed();
            assert!(
                elapsed < PURGE_ANSWER + Duration::from_secs(1),
                "{elapsed:?}"
            );
            match purged {
                Ok(()) => assert!(answers),
                Err(e) => assert!(!answers && e.kind() == io::ErrorKind::TimedOut, "{e}"),
            }
            assert_eq!(
                *asked.lock().expect("lock"),
                vec![vec![PathBuf::from("data")]]
            );
        }
    }

    /// A purge the service does not answer in time is forgotten with the wait: the connection
    /// keeps no route for an answer nobody waits for (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_purge_given_up_on_leaves_no_route_behind() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("supervisors").join("agent");
        let data = supervisor.join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o2770)).expect("chmod");
        let peer = peer::connect(peer::mute).await;
        tokio::time::pause();
        let purged = peer
            .channel
            .purge(&[("agent".to_string(), supervisor.clone())])
            .await;
        assert!(purged[0].is_err(), "the mute service answered");
        let connection = peer.channel.open_connection().await.expect("connected");
        assert!(connection.routes().purges.is_empty());
    }

    /// What a program run to its end writes is kept up to its last [`CAPTURED`] bytes per stream,
    /// so a program that writes without end costs the Client no more than that.
    /// Verifies: ADR-0059
    #[test]
    fn what_a_program_run_to_its_end_writes_is_kept_to_its_tail() {
        let mut captured = Captured::default();
        let line = "x".repeat(1000);
        for _ in 0..200 {
            captured.push(Stream::Stdout, &line);
        }
        captured.push(Stream::Stdout, "the last line");
        captured.push(Stream::Stderr, "said on stderr");
        assert_eq!(captured.stdout.len(), CAPTURED);
        assert!(captured.stdout.ends_with(b"the last line\n"));
        assert_eq!(captured.stderr, b"said on stderr\n");
    }

    /// The admission rule itself: the Client's uid, and nobody else's — root included.
    /// Verifies: ADR-0059
    #[test]
    fn only_the_clients_uid_is_admitted() {
        assert!(admit(1000, 1000).is_ok());
        assert!(admit(1001, 1000).is_err());
        assert!(admit(0, 1000).is_err(), "not even root");
    }

    /// The service serves neither root nor its own account as the Client's.
    /// Verifies: ADR-0059
    #[test]
    fn the_client_uid_is_neither_root_nor_the_services_own() {
        assert!(check_client_uid(998, 997).is_ok());
        assert!(check_client_uid(0, 997).is_err());
        assert!(check_client_uid(997, 997).is_err());
    }

    /// The second service never runs as root, whichever account it is told to serve.
    /// Verifies: ADR-0059
    #[test]
    fn the_service_refuses_to_run_as_root() {
        let refused = check_client_uid(998, 0).expect_err("it ran as root");
        assert!(refused.contains("root"), "{refused}");
    }

    /// The Client tells a Managed Process's environment and the Supervisor Endpoint's token to the
    /// process account alone: a socket served by another uid is refused before anything is written
    /// to it. Run without a second account by naming another uid as the process account's.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn the_client_talks_only_to_the_process_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let heard = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut heard = Vec::new();
            let _ = stream.read_to_end(&mut heard).await;
            heard
        });
        let refused = Channel::connect(&socket, own_uid().wrapping_add(1), this_process())
            .await
            .err()
            .expect("refused");
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        assert!(refused.to_string().contains("process account"), "{refused}");
        let heard = tokio::time::timeout(Duration::from_secs(5), heard)
            .await
            .expect("the Client closed the connection")
            .expect("the listener");
        assert!(heard.is_empty(), "the Client wrote {} bytes", heard.len());
        assert!(check_service(&7, &7, &socket).is_ok());
    }

    /// The second service restarted — its programs ended with it — and the next start reaches the
    /// service that came back instead of failing on the channel that went.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_start_reaches_the_service_after_it_restarted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let (stop, task) = listen(&socket, own_uid(), || false);
        let channel = Channel::new(&socket, own_uid(), this_process());
        let mut first = channel.start("test", sh("sleep 300")).await.expect("start");
        let _ = stop.send(());
        assert_eq!(task.await.expect("the service ended"), Served::Stopped);
        let _ = tokio::time::timeout(Duration::from_secs(15), first.wait())
            .await
            .expect("the program ended with the service");

        // The service manager brings it back a moment later.
        let again = socket.clone();
        let back = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            listen(&again, own_uid(), || false)
        });
        let mut second = channel
            .start("test", sh("exit 7"))
            .await
            .expect("the start reached the restarted service");
        let status = tokio::time::timeout(Duration::from_secs(10), second.wait())
            .await
            .expect("in time")
            .expect("a status");
        assert_eq!(status.code(), Some(7));
        drop(back.await.expect("the service came back"));
    }

    /// A kill the service does not report — it is shutting down, or gone quiet — gives up after
    /// [`KILL_ANSWER`] instead of holding up the stop that sent it for ever.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_kill_the_service_does_not_report_gives_up_in_time() {
        let peer = peer::connect(peer::deaf).await;
        let mut child = peer.channel.start("test", sh("true")).await.expect("start");
        let killed = tokio::time::timeout(KILL_ANSWER * 2, child.kill())
            .await
            .expect("the kill gives up in time");
        assert_eq!(
            killed.err().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
    }

    /// A Client of another build ends a service that a self-update left behind, so the version
    /// `current` names takes its place; a service that is current itself only refuses it.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn another_build_ends_only_a_superseded_service() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let (_stop, task) = listen(&socket, own_uid(), || true);
        let mut stream = connect_raw(&socket, "0.0.0-another-build").await;
        assert!(matches!(
            next(&mut stream).await,
            Some(Reply::Refused { .. })
        ));
        let served = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the service ended")
            .expect("cleanly");
        assert_eq!(served, Served::Superseded);
    }

    /// Only a peer of the Client's account can make a superseded service end: one of another
    /// account that names another build is refused before it is served, and the service goes on
    /// (ADR-0059 clauses 2 and 4).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_peer_of_another_account_ends_no_superseded_service() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let (stop, task) = listen(&socket, own_uid().wrapping_add(1), || true);
        let mut stream = connect_raw(&socket, "0.0.0-another-build").await;
        assert!(matches!(
            next(&mut stream).await,
            Some(Reply::Refused { version: None, .. })
        ));
        drop(stream);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!task.is_finished(), "a foreign peer ended the service");
        let _ = stop.send(());
        let served = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the service ended")
            .expect("cleanly");
        assert_eq!(served, Served::Stopped);
    }

    /// The service goes while a start is on its way: the start goes to the service that comes back
    /// rather than failing on the connection that went (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_start_the_service_cut_short_goes_to_the_service_that_comes_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        // The first connection goes on the start; the second runs it.
        let service = tokio::spawn(async move {
            for served in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                while let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await {
                    let reply = match request {
                        Request::Hello { .. } => peer::hello(),
                        Request::Start { .. } if served == 0 => break,
                        Request::Start { id, .. } => Reply::Started { id, pid: 4242 },
                        _ => continue,
                    };
                    if write_frame(&mut stream, &reply).await.is_err() {
                        break;
                    }
                }
            }
        });
        let channel = Channel::new(&socket, own_uid(), this_process());
        let child =
            tokio::time::timeout(Duration::from_secs(10), channel.start("test", sh("true")))
                .await
                .expect("in time")
                .expect("the start reached the service that came back");
        assert_eq!(child.id(), Some(4242));
        drop(child);
        drop(channel);
        service.abort();
    }

    /// A start that waited for the service in vain makes the next ones in the same outage try
    /// once, rather than each waiting out the reconnect again; once that has passed, a start waits
    /// again. Every one fails as not reaching the service.
    /// Verifies: ADR-0059
    #[tokio::test(start_paused = true)]
    async fn a_start_in_an_outage_that_was_waited_out_tries_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let channel = Channel::new(&dir.path().join("agents.sock"), own_uid(), this_process());
        let timed = || async {
            let started = Instant::now();
            let failed = channel
                .start("test", sh("true"))
                .await
                .err()
                .expect("no service");
            assert!(is_unreachable(&failed), "{failed}");
            started.elapsed()
        };
        assert!(
            timed().await >= RECONNECT,
            "the first start waits for the service"
        );
        assert!(
            timed().await < RECONNECT_EVERY,
            "the next one in the same outage tries once"
        );
        tokio::time::advance(RECONNECT).await;
        assert!(
            timed().await >= RECONNECT,
            "a later outage is waited out again"
        );
    }

    /// The self-update restarts the Client, whose connection closes: a service that `current` no
    /// longer names ends then, beside the Client, rather than only once the new Client has met it.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_superseded_service_ends_when_the_clients_connection_closes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let (_stop, task) = listen(&socket, own_uid(), || true);
        let mut stream = connect_raw(&socket, this_build()).await;
        assert!(matches!(next(&mut stream).await, Some(Reply::Hello { .. })));
        drop(stream);
        let served = tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .expect("the service ended")
            .expect("cleanly");
        assert_eq!(served, Served::Superseded);
    }

    /// A stand-in for a second service of another build: it answers every handshake with the
    /// refusal the real one sends.
    fn another_build(socket: &Path) -> JoinHandle<()> {
        let listener = UnixListener::bind(socket).expect("bind");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = read_frame::<_, Request>(&mut stream).await;
                let refused = Reply::Refused {
                    reason: "the Client is build a, this service is build b".to_string(),
                    version: Some("0.0.0-another-build".to_string()),
                };
                let _ = write_frame(&mut stream, &refused).await;
            }
        })
    }

    /// A Client that meets a second service of another build while `current` no longer names its
    /// own version is the one a self-update left behind, and is told so; one that `current` still
    /// names is only refused (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_client_left_behind_by_a_self_update_is_told_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let service = another_build(&socket);

        // Refused, and trying again for as long as a start waits for the service.
        let current = Channel::with_superseded(&socket, own_uid(), this_process(), || false);
        let trying = current.clone();
        let start = tokio::spawn(async move { trying.start("test", sh("true")).await.err() });
        assert!(
            tokio::time::timeout(Duration::from_millis(500), current.left_behind())
                .await
                .is_err(),
            "a Client current still names is not left behind"
        );
        assert!(!start.is_finished(), "the start waits for the service");
        start.abort();

        let behind = Channel::with_superseded(&socket, own_uid(), this_process(), || true);
        let refused =
            tokio::time::timeout(Duration::from_secs(5), behind.start("test", sh("true")))
                .await
                .expect("a Client left behind gives up at once")
                .err()
                .expect("refused");
        assert!(refused.to_string().contains("build"), "{refused}");
        tokio::time::timeout(Duration::from_secs(1), behind.left_behind())
            .await
            .expect("the Client left behind is told so");
        service.abort();
    }

    /// A process that left its program's group — through `setsid` — and holds its pipe open
    /// keeps no relay and no descriptor of the service's once the connection has ended.
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_output_of_a_process_left_behind_ends_with_the_connection() {
        let service = service(own_uid());
        let mut stream = connect_raw(&service.socket, this_build()).await;
        assert!(matches!(next(&mut stream).await, Some(Reply::Hello { .. })));
        write_frame(
            &mut stream,
            &Request::Start {
                id: 1,
                launch: sh("setsid sleep 300 & echo $!"),
            },
        )
        .await
        .expect("start");
        let left = loop {
            match next(&mut stream).await.expect("open") {
                Reply::Output { line, .. } => break line.trim().parse::<u32>().expect("a pid"),
                Reply::Started { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        };
        // Whatever happens below, the process left behind does not outlive the test.
        struct Reap(u32);
        impl Drop for Reap {
            fn drop(&mut self) {
                // SAFETY: plain kill(2); no memory is touched.
                unsafe { libc::kill(self.0 as libc::pid_t, libc::SIGKILL) };
            }
        }
        let _reap = Reap(left);
        let pipe = std::fs::read_link(format!("/proc/{left}/fd/1")).expect("its stdout");
        let held = || {
            std::fs::read_dir("/proc/self/fd").is_ok_and(|fds| {
                fds.flatten()
                    .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|to| to == pipe))
            })
        };
        // The program's exit is reported while the process it left still holds the pipe.
        loop {
            match next(&mut stream).await.expect("open") {
                Reply::Exited { .. } => break,
                Reply::Output { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(held(), "the relay is gone before the connection ended");

        drop(stream);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while held() {
            assert!(
                std::time::Instant::now() < deadline,
                "the service still holds the pipe of a process left behind"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            alive(left),
            "the process left behind is not the service's to stop"
        );
    }

    /// A listener on `socket` that keeps what each peer wrote before it closed the connection.
    fn heard_on(socket: &Path) -> JoinHandle<Vec<u8>> {
        heard_by(UnixListener::bind(socket).expect("bind"))
    }

    /// What the first peer `listener` accepts wrote before it closed the connection.
    fn heard_by(listener: UnixListener) -> JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut heard = Vec::new();
            let _ = stream.read_to_end(&mut heard).await;
            heard
        })
    }

    /// Whether `refused` is the refusal of a peer that is not the second service, whose process
    /// is `pid`, and the listener heard nothing from the Client.
    async fn refused_unheard(refused: &io::Error, pid: Option<u32>, heard: JoinHandle<Vec<u8>>) {
        assert_eq!(other_process(refused), Some(pid), "{refused}");
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
        let heard = tokio::time::timeout(Duration::from_secs(5), heard)
            .await
            .expect("the Client closed the connection")
            .expect("the listener");
        assert!(heard.is_empty(), "the Client wrote {} bytes", heard.len());
    }

    /// The Client accepts a socket served by the process account only where its process is the
    /// one the service manager names as the second service's. One whose process differs, one the
    /// manager names no process for, one the manager cannot be asked about and one whose process
    /// cannot be read are refused before anything is written to them.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn the_client_speaks_only_to_the_process_the_manager_names() {
        let service = service(own_uid());
        Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("the process the manager names is spoken to");

        let me = std::process::id();
        let differing = ServiceProcess::named(move || Ok(Some(me.wrapping_add(1))));
        let none = ServiceProcess::named(|| Ok(None));
        let unasked = ServiceProcess::named(|| Err("systemd is not there".to_string()));
        for (named, says) in [
            (differing, "not by the second service"),
            (none, "runs no process as the second service"),
            (unasked, "systemd is not there"),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let socket = dir.path().join("agents.sock");
            let heard = heard_on(&socket);
            let refused = Channel::connect(&socket, own_uid(), named)
                .await
                .err()
                .expect("refused");
            assert!(refused.to_string().contains(says), "{refused}");
            assert!(
                refused.to_string().contains(&format!("process {me}")),
                "{refused}"
            );
            refused_unheard(&refused, Some(me), heard).await;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let unread = check_process(
            Err(io::Error::other("no such option")),
            &this_process(),
            &dir.path().join("agents.sock"),
        )
        .await
        .expect_err("refused");
        assert_eq!(other_process(&unread), Some(None), "{unread}");
        assert!(unread.to_string().contains("cannot be read"), "{unread}");
    }

    /// A peer that is not the second service is no refusal of the service's, which no restart
    /// mends: the service is away, and is tried again on a new connection, checked anew, until the
    /// process the manager names serves the socket.
    /// Verifies: ADR-0059
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_is_not_the_second_service_is_away_and_tried_anew() {
        let service = service(own_uid());
        let me = std::process::id();
        let asked = Arc::new(AtomicU64::new(0));
        let impostor = {
            let asked = Arc::clone(&asked);
            ServiceProcess::named(move || {
                asked.fetch_add(1, Ordering::SeqCst);
                Ok(Some(me.wrapping_add(1)))
            })
        };
        let away = Channel::new(&service.socket, own_uid(), impostor)
            .start("test", sh("exit 3"))
            .await
            .err()
            .expect("refused");
        assert!(is_unreachable(&away), "{away}");
        assert!(!is_refused(&away), "{away}");
        assert!(
            asked.load(Ordering::SeqCst) > 1,
            "asked once: the peer was not tried again"
        );

        let asked = Arc::new(AtomicU64::new(0));
        let restarted = {
            let asked = Arc::clone(&asked);
            ServiceProcess::named(move || {
                let at = asked.fetch_add(1, Ordering::SeqCst);
                Ok(Some(if at < 2 { me.wrapping_add(1) } else { me }))
            })
        };
        Channel::new(&service.socket, own_uid(), restarted)
            .start("test", sh("exit 3"))
            .await
            .expect("the second service is reached once the manager names it");
        assert_eq!(
            asked.load(Ordering::SeqCst),
            3,
            "each connection is checked anew"
        );
    }

    /// A socket whose listening process ends, while another process holds it, before the manager
    /// has answered is refused although the manager names a process of that id: the pidfd
    /// (`SO_PEERPIDFD`) refers to the process that listened, never to a later holder of its id, and
    /// is looked at once the manager has answered. The kernel must know the option, or this fails
    /// rather than passes on the id alone.
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_listener_that_ended_is_refused_though_its_id_is_named() {
        use std::os::fd::{AsFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;

        let service = service(own_uid());
        let live = UnixStream::connect(&service.socket).await.expect("connect");
        let read = peer_process(live.as_fd()).expect("the peer's process");
        assert_eq!(read.pid, std::process::id());
        assert!(
            read.pidfd.is_some(),
            "the kernel has no SO_PEERPIDFD (Linux 6.5): this cannot be decided"
        );
        drop(live);

        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        // SAFETY: socket(2) with constant arguments; the descriptor is owned below.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: a descriptor just opened, owned from here.
        let held = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        // SAFETY: a zeroed sockaddr_un is a valid one; its path is filled in below.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (to, from) in address
            .sun_path
            .iter_mut()
            .zip(socket.as_os_str().as_bytes())
        {
            *to = *from as libc::c_char;
        }
        // SAFETY: the address above, its size, and the descriptor held.
        let bound = unsafe {
            libc::bind(
                fd,
                std::ptr::from_ref(&address).cast(),
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(bound, 0, "bind: {}", io::Error::last_os_error());
        // A child listens on the socket, says so, and waits; this process holds the socket on.
        let mut ready = [0 as libc::c_int; 2];
        // SAFETY: pipe(2) fills the two descriptors; both are closed below.
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: the child calls listen(2), write(2) and pause(2) alone, all async-signal-safe.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: as above.
            unsafe {
                libc::listen(fd, 8);
                libc::write(ready[1], [1u8].as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            }
        }
        assert!(child > 0, "fork: {}", io::Error::last_os_error());
        let mut byte = 0u8;
        // SAFETY: reads one byte into `byte`, then closes the pipe this process holds.
        unsafe {
            assert_eq!(
                libc::read(ready[0], std::ptr::from_mut(&mut byte).cast(), 1),
                1
            );
            libc::close(ready[0]);
            libc::close(ready[1]);
        }
        let listener = std::os::unix::net::UnixListener::from(held);
        listener.set_nonblocking(true).expect("nonblocking");
        let heard = heard_by(UnixListener::from_std(listener).expect("listener"));

        // The manager is asked once the Client has read the peer, which still runs then: the
        // process ends, and is reaped, before the manager names its id.
        let listened = child.cast_unsigned();
        let named = ServiceProcess::named(move || {
            // SAFETY: kill(2) and waitpid(2) on this test's own child.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(child, &mut status, 0);
            }
            Ok(Some(listened))
        });
        let refused = Channel::connect(&socket, own_uid(), named)
            .await
            .err()
            .expect("the process that listened has ended");
        assert!(refused.to_string().contains("has ended"), "{refused}");
        refused_unheard(&refused, Some(listened), heard).await;
    }

    /// A second service whose program did not mark it not dumpable does not listen: this test's
    /// process, which nothing marked, is refused as dumpable (ADR-0059 clause 4).
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[test]
    fn a_second_service_that_is_dumpable_does_not_listen() {
        let refused = check_closed().expect_err("a dumpable process passed");
        assert!(refused.contains("is dumpable"), "{refused}");
    }

    /// The second service's command line is told by `--agents` alone, before it is parsed, so
    /// that its program marks itself not dumpable first; the Client's `--agents-socket` is not it
    /// (ADR-0059 clause 4).
    /// Verifies: ADR-0059
    #[test]
    fn the_second_services_command_line_is_known_before_it_is_parsed() {
        let args = |line: &[&str]| {
            line.iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert!(runs_the_second_service(args(&[
            "run",
            "--agents",
            "/run/x/agents.sock",
            "--client-uid",
            "998"
        ])));
        assert!(runs_the_second_service(args(&[
            "run",
            "--agents=/run/x/agents.sock"
        ])));
        assert!(!runs_the_second_service(args(&[
            "run",
            "--agents-socket",
            "/run/x/agents.sock",
            "--process-uid",
            "999"
        ])));
        assert!(!runs_the_second_service(args(&["run"])));
    }

    /// An error of `SO_PEERPIDFD` other than `ENOPROTOOPT` is the error the peer is refused with:
    /// nothing is fallen back to, and no process id read another way.
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[test]
    fn an_error_of_so_peerpidfd_falls_back_to_nothing() {
        use std::os::fd::{AsFd as _, FromRawFd as _};
        // A socket connected to nothing has no peer: `ENODATA`.
        // SAFETY: socket(2) with constant arguments; the descriptor is owned below.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: a descriptor just opened, owned from here.
        let unconnected = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let unread = peer_process(unconnected.as_fd())
            .err()
            .expect("no peer to read");
        assert_eq!(unread.raw_os_error(), Some(libc::ENODATA), "{unread}");
    }

    /// A peer whose uid is not the Client's is refused at the socket, before any request. Run
    /// without a second account by naming another uid as the Client's: this process is then the
    /// stranger.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_peer_of_another_uid_is_refused() {
        let service = service(own_uid().wrapping_add(1));
        let mut stream = connect_raw(&service.socket, this_build()).await;
        match next(&mut stream).await {
            Some(Reply::Refused { reason, .. }) => {
                assert!(reason.contains("not the Client"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let refused = Channel::connect(&service.socket, own_uid(), this_process()).await;
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }

    /// Both ends read the other's account on Linux and on macOS alike: `peer_cred` is
    /// `SO_PEERCRED` on Linux and `getpeereid` on macOS, and either end finds the other's uid there
    /// for the checks of ADR-0059 clause 4. Run as one account, the test cannot tell an effective
    /// uid from a real one: that both calls give the effective uid is their documentation's.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_peer_is_known_by_its_uid_at_either_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("peer.sock");
        let listener = bind(&socket).expect("bind");
        let client = UnixStream::connect(&socket).await.expect("connect");
        let (served, _) = listener.accept().await.expect("accept");
        // SAFETY: geteuid(2) cannot fail and touches no memory.
        let me = unsafe { libc::geteuid() };
        assert_eq!(served.peer_cred().expect("the Client's").uid(), me);
        assert_eq!(client.peer_cred().expect("the service's").uid(), me);
        assert!(admit(me, me).is_ok());
        assert!(admit(me, me.wrapping_add(1)).is_err());
    }

    /// Nothing is read from a refused peer and nothing waits on it: a stranger that says nothing
    /// is told and dropped at once, however many of them connect, rather than each holding a
    /// descriptor for the length of a handshake.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_refused_peer_is_dropped_at_once() {
        let service = service(own_uid().wrapping_add(1));
        let mut strangers = Vec::new();
        for _ in 0..20 {
            strangers.push(UnixStream::connect(&service.socket).await.expect("connect"));
        }
        for stranger in &mut strangers {
            let reply =
                tokio::time::timeout(Duration::from_secs(1), read_frame::<_, Reply>(stranger))
                    .await
                    .expect("refused without waiting for a handshake");
            assert!(
                matches!(reply, Ok(Some(Reply::Refused { .. }))),
                "{reply:?}"
            );
            let mut rest = Vec::new();
            let closed =
                tokio::time::timeout(Duration::from_secs(1), stranger.read_to_end(&mut rest))
                    .await
                    .expect("closed at once");
            assert!(closed.map_or(true, |n| n == 0), "more after the refusal");
        }
    }

    /// The handshake is a few bytes: a first message that claims more is refused without waiting
    /// for it.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_handshake_larger_than_a_handshake_is_refused_at_once() {
        let service = service(own_uid());
        let mut stream = UnixStream::connect(&service.socket).await.expect("connect");
        stream
            .write_all(&(64 * 1024u32).to_be_bytes())
            .await
            .expect("a length");
        let reply =
            tokio::time::timeout(Duration::from_secs(1), read_frame::<_, Reply>(&mut stream))
                .await
                .expect("refused without waiting for the body");
        assert!(
            matches!(reply, Ok(Some(Reply::Refused { .. }))),
            "{reply:?}"
        );
    }

    /// Repeated refusals are logged once in a while, with how many went unlogged since.
    #[test]
    fn refusals_are_logged_sparingly() {
        let start = std::time::Instant::now();
        let mut refusals = Refusals::default();
        assert_eq!(refusals.note(start), Some(0));
        assert_eq!(refusals.note(start + Duration::from_secs(1)), None);
        assert_eq!(refusals.note(start + Duration::from_secs(2)), None);
        assert_eq!(refusals.note(start + REFUSAL_LOG_EVERY), Some(2));
        assert_eq!(refusals.note(start + REFUSAL_LOG_EVERY), None);
    }

    /// Both ends are one build: a peer that names another is refused.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_peer_of_another_build_is_refused() {
        let service = service(own_uid());
        let mut stream = connect_raw(&service.socket, "0.0.0-another-build").await;
        match next(&mut stream).await {
            Some(Reply::Refused { reason, version }) => {
                assert!(reason.contains("build"), "{reason}");
                assert_eq!(version.as_deref(), Some(this_build()), "it names its own");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And the service still serves the right build afterwards.
        Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("the Client's own build");
    }

    /// A refusal is told apart from an outage, and what the refusing peer says reaches the error —
    /// and through it the Supervisor's health on the Server — bounded and escaped: a Managed
    /// Process of the process account can put a socket of its own in the service's place, and
    /// say up to a handshake's worth of anything.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_refusal_is_no_outage_and_quotes_the_peer_bounded_and_escaped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = read_frame::<_, Request>(&mut stream).await;
                let refused = Reply::Refused {
                    reason: "\u{1b}[2Jforged log line\n".repeat(150),
                    version: None,
                };
                let _ = write_frame(&mut stream, &refused).await;
            }
        });
        let refused = Channel::new(&socket, own_uid(), this_process())
            .start("test", sh("true"))
            .await
            .err()
            .expect("refused");
        assert!(is_unreachable(&refused), "{refused}");
        assert!(is_refused(&refused), "{refused}");
        let text = refused.to_string();
        assert!(
            !text.contains('\n') && !text.contains('\u{1b}'),
            "unescaped: {text}"
        );
        assert!(text.len() < 2 * PEER_TEXT + 200, "{} bytes", text.len());
        assert!(text.contains("forged log line\\n"), "{text}");
    }

    /// What a peer says of a program — why it did not start, why waiting for it failed, why a
    /// signal was not sent — reaches the Client's errors bounded and escaped: whoever serves the
    /// socket says it, a program of the process account among them.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn what_a_peer_says_of_a_program_is_quoted_bounded_and_escaped() {
        const FORGED: &str = "\u{1b}[2Jforged log line\nsecond line";
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_frame::<_, Request>(&mut stream).await;
            let hello = Reply::Hello {
                version: this_build().to_string(),
            };
            write_frame(&mut stream, &hello).await.expect("hello");
            while let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await {
                let replies = match request {
                    Request::Start { id: 1, .. } => vec![Reply::StartFailed {
                        id: 1,
                        error: FORGED.to_string(),
                        os_error: None,
                    }],
                    Request::Start { id, .. } => vec![Reply::Started { id, pid: 4242 }],
                    Request::Signal { id, .. } => vec![
                        Reply::SignalFailed {
                            id,
                            error: FORGED.to_string(),
                        },
                        Reply::Exited {
                            id,
                            status: Err(FORGED.to_string()),
                            closing: false,
                        },
                    ],
                    Request::Hello { .. } | Request::Stop { .. } | Request::Purge { .. } => {
                        Vec::new()
                    }
                };
                for reply in replies {
                    write_frame(&mut stream, &reply).await.expect("reply");
                }
            }
        });
        let quoted = |text: String| {
            assert!(
                !text.contains('\n') && !text.contains('\u{1b}'),
                "unescaped: {text}"
            );
            assert!(text.contains("forged log line\\n"), "{text}");
        };
        let channel = Channel::new(&socket, own_uid(), this_process());

        let not_started = channel
            .start("test", sh("true"))
            .await
            .err()
            .expect("the start fails");
        assert!(!is_unreachable(&not_started), "{not_started}");
        quoted(not_started.to_string());

        let mut child = channel.start("test", sh("true")).await.expect("started");
        let not_signalled = child
            .signal(libc::SIGHUP, false)
            .await
            .expect_err("the signal fails");
        quoted(not_signalled.to_string());
        let not_waited = child.wait().await.expect_err("waiting fails");
        assert!(!is_unreachable(&not_waited), "{not_waited}");
        quoted(not_waited.to_string());
    }

    /// A program that has ended by the time the connection closes is reported as the exit it is,
    /// never as one the close caused: the close cannot pass a crash off as a stop.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn an_exit_that_meets_the_close_is_the_programs_own() {
        for _ in 0..32 {
            let (child, tree) = start(&sh("exit 3")).expect("start");
            let pid = child.id().expect("a pid");
            // Until it has ended, without reaping it.
            // SAFETY: waitid(2) on our own child with WNOWAIT writes only into `info`.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let waited =
                unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
            assert_eq!(waited, 0, "{}", io::Error::last_os_error());
            let (control, unanswered) = mpsc::unbounded_channel();
            assert!(control.send(Control::Close).is_ok(), "queued");
            let (replies, mut queued) = Replies::new();
            supervise(1, child, tree, false, unanswered, replies).await;
            loop {
                match queued.recv().await.expect("a reply").reply {
                    Reply::Exited {
                        status, closing, ..
                    } => {
                        assert!(!closing, "the close was taken for the exit");
                        assert_eq!(
                            ExitStatus::from_raw(status.expect("a status")).code(),
                            Some(3)
                        );
                        break;
                    }
                    Reply::Output { .. } => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }

    /// One connection is served at a time; a second is refused while the first is open.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_second_connection_is_refused_while_one_is_served() {
        let service = service(own_uid());
        let _first = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("first");
        let second = Channel::connect(&service.socket, own_uid(), this_process()).await;
        assert!(second.is_err(), "the second connection was served");
    }

    /// A program started through the channel runs, its output comes back line by line from both
    /// streams, and its exit status arrives last.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_started_program_reports_its_output_and_exit() {
        let service = service(own_uid());
        let mut stream = connect_raw(&service.socket, this_build()).await;
        assert!(matches!(next(&mut stream).await, Some(Reply::Hello { .. })));
        let mut launch = sh("echo \"out $GREETING\"; echo err >&2; exit 3");
        launch.env = vec![("GREETING".to_string(), "hello".to_string())];
        write_frame(&mut stream, &Request::Start { id: 7, launch })
            .await
            .expect("start");

        let mut output = Vec::new();
        let status = loop {
            match next(&mut stream).await.expect("the connection stays open") {
                Reply::Started { id, pid } => assert!(id == 7 && pid > 0),
                Reply::Output { id, stream, line } => {
                    assert_eq!(id, 7);
                    output.push((stream, line));
                }
                Reply::Exited { id, status, .. } => {
                    assert_eq!(id, 7);
                    break ExitStatus::from_raw(status.expect("a status"));
                }
                other => panic!("unexpected {other:?}"),
            }
        };
        output.sort_by_key(|(stream, _)| *stream == Stream::Stderr);
        assert_eq!(
            output,
            vec![
                (Stream::Stdout, "out hello".to_string()),
                (Stream::Stderr, "err".to_string())
            ]
        );
        assert_eq!(status.code(), Some(3));
    }

    /// An id names one program: a start that names a running one fails, and the running program
    /// is still the one its id stops.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_start_that_reuses_a_running_id_fails() {
        let service = service(own_uid());
        let mut stream = connect_raw(&service.socket, this_build()).await;
        assert!(matches!(next(&mut stream).await, Some(Reply::Hello { .. })));
        for script in ["sleep 300", "exit 5"] {
            write_frame(
                &mut stream,
                &Request::Start {
                    id: 1,
                    launch: sh(script),
                },
            )
            .await
            .expect("start");
        }
        assert!(matches!(
            next(&mut stream).await,
            Some(Reply::Started { id: 1, .. })
        ));
        match next(&mut stream).await {
            Some(Reply::StartFailed { id: 1, error, .. }) => {
                assert!(error.contains("id"), "{error}")
            }
            other => panic!("expected the second start to fail, got {other:?}"),
        }
        write_frame(&mut stream, &Request::Stop { id: 1 })
            .await
            .expect("stop");
        match next(&mut stream).await {
            Some(Reply::Exited { id: 1, status, .. }) => assert_eq!(
                ExitStatus::from_raw(status.expect("a status")).signal(),
                Some(libc::SIGKILL),
                "the stop reached another program"
            ),
            other => panic!("expected the exit, got {other:?}"),
        }
    }

    /// A program's output reaches the Client's log as events of the Supervisor it runs for, one
    /// per line and escaped, so no line a program writes reads as one of the Client's.
    /// Verifies: ADR-0059
    #[test]
    fn output_is_logged_under_its_supervisor_and_escaped() {
        // A current-thread runtime: every task of the test runs on this thread, whose log
        // `capture_logs` keeps.
        let ((), log) = crate::test_support::capture_logs(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    let service = service(own_uid());
                    let channel = Channel::connect(&service.socket, own_uid(), this_process())
                        .await
                        .expect("connect");
                    let forged =
                        r#"printf 'plain\n'; printf 'ERROR fleet_agent: forged\033[0m\r\n' >&2"#;
                    let mut child = channel
                        .start("telegraf-1", sh(forged))
                        .await
                        .expect("start");
                    child.wait().await.expect("ended");
                });
        });

        let output: Vec<&str> = log.lines().filter(|l| l.contains(" output ")).collect();
        assert_eq!(output.len(), 2, "{log}");
        assert!(
            output.iter().any(|l| l.contains("supervisor=telegraf-1")
                && l.contains("stream=stdout")
                && l.contains(r#"line="plain""#)),
            "{log}"
        );
        assert!(
            output.iter().any(|l| l.contains("stream=stderr")
                && l.contains(r#"line="ERROR fleet_agent: forged\u{1b}[0m\r""#)),
            "{log}"
        );
        assert!(!log.contains('\u{1b}'), "an escape reached the log raw");
    }

    /// A signal the service could not send is an error at the Client, as it is when the Client
    /// signals a program itself, so a reload that cannot be signalled falls back to the restart.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_signal_that_cannot_be_sent_is_an_error() {
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        let mut child = channel.start("test", sh("sleep 300")).await.expect("start");
        child.signal(0, false).await.expect("signal 0 is sent");
        // No such signal: kill(2) fails with EINVAL.
        assert!(child.signal(999, false).await.is_err());
        child.kill().await.expect("kill");
        // Once the program has been waited for there is nothing to signal, and nothing fails.
        child
            .signal(libc::SIGTERM, false)
            .await
            .expect("nothing to do");
    }

    /// A signal the service does not answer — it is stopping its programs on shutting down — fails
    /// after [`SIGNAL_ANSWER`] instead of holding up the stop or the reload that sent it.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_signal_the_service_does_not_answer_fails_in_time() {
        let peer = peer::connect(peer::mute).await;
        let child = peer.channel.start("test", sh("true")).await.expect("start");
        let sent = tokio::time::timeout(SIGNAL_ANSWER * 3, child.signal(libc::SIGTERM, true))
            .await
            .expect("the signal gives up in time");
        assert!(sent.is_err(), "an unanswered signal is not taken as sent");
    }

    /// A start that failed answers only a start still waiting: one that names a running program
    /// takes nothing from it, and its exit still reaches it.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_failed_start_under_a_running_id_leaves_its_program_alone() {
        let peer = peer::connect(|request| match request {
            Request::Start { id, .. } => vec![
                Reply::Started { id, pid: u32::MAX },
                Reply::StartFailed {
                    id,
                    error: format!("id {id} names a running program"),
                    os_error: None,
                },
            ],
            request => peer::mute(request),
        })
        .await;
        let mut child = peer.channel.start("test", sh("true")).await.expect("start");
        child
            .kill()
            .await
            .expect("the exit reaches the running program");
    }

    /// A program that cannot start is reported with its OS error, so the Client still tells a
    /// missing program from any other failure.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_program_that_cannot_start_keeps_its_os_error() {
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        let mut launch = sh("");
        launch.program = PathBuf::from("/nonexistent/program");
        let error = channel
            .start("test", launch)
            .await
            .err()
            .expect("a start failure");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    /// A start too large for one message fails alone, with `InvalidInput`: the connection, and every
    /// program it runs, carries on.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_start_too_large_for_a_message_fails_alone() {
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        let mut running = channel.start("test", sh("sleep 300")).await.expect("start");

        let mut huge = sh("true");
        huge.env = vec![("BULK".to_string(), "x".repeat(2 << 20))];
        let error = channel.start("test", huge).await.err().expect("refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut next = channel
            .start("test", sh("exit 4"))
            .await
            .expect("a later start still runs");
        let status = tokio::time::timeout(Duration::from_secs(10), next.wait())
            .await
            .expect("in time")
            .expect("a status");
        assert_eq!(status.code(), Some(4));
        assert!(
            running.id().is_some(),
            "the running program was reported ended"
        );
        running.kill().await.expect("kill");
    }

    /// A frame is written into a buffer of its final size, so no outgrown copy of a start's token
    /// is left unwiped.
    /// Verifies: ADR-0057
    #[test]
    fn a_frame_never_outgrows_its_buffer() {
        for size in [0, 1, 100, 4_000, 70_000] {
            let mut launch = sh("true");
            launch.env = vec![("BULK".to_string(), "x".repeat(size))];
            let frame = encode(&launch).expect("encode");
            assert_eq!(frame.capacity(), frame.len(), "size {size}");
        }
    }

    /// A start abandoned before the service answered leaves nothing behind: the program it may
    /// have started is stopped, and its route is gone.
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_abandoned_start_stops_its_program() {
        let service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        // A duration no other process on the host sleeps for, to find this one by.
        let marker = unique_marker();
        let launch = Launch {
            program: PathBuf::from("sleep"),
            args: vec![marker.clone()],
            ..sh("")
        };
        {
            let mut start = std::pin::pin!(channel.start("test", launch));
            // One poll sends the request; the answer cannot be there yet.
            std::future::poll_fn(|cx| {
                assert!(start.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert!(
            channel
                .open_connection()
                .await
                .expect("connected")
                .routes()
                .by_id
                .is_empty(),
            "the abandoned start kept its route"
        );
        // The service answers in order: once a later start is answered, the abandoned one has run
        // and been asked to stop.
        let mut later = channel
            .start("test", sh("exit 0"))
            .await
            .expect("a later start");
        later.wait().await.expect("the later program ended");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while running_with_arg(&marker) {
            assert!(
                std::time::Instant::now() < deadline,
                "the abandoned start's program kept running"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A Client slow to read a program's output holds up that program alone: the service still
    /// starts and stops programs while the output waits — here it stops the flood itself, with
    /// nothing read from the connection at all.
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn output_the_client_has_not_read_holds_up_no_request() {
        let service = service(own_uid());
        let mut stream = connect_raw(&service.socket, this_build()).await;
        assert!(matches!(next(&mut stream).await, Some(Reply::Hello { .. })));
        let marker = unique_marker();
        let flood = Launch {
            program: PathBuf::from("yes"),
            args: vec![marker.clone()],
            ..sh("")
        };
        write_frame(
            &mut stream,
            &Request::Start {
                id: 1,
                launch: flood,
            },
        )
        .await
        .expect("start");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !running_with_arg(&marker) {
            assert!(std::time::Instant::now() < deadline, "the flood never ran");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Long enough for the flood to fill the socket and every queue in front of it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for request in [
            Request::Start {
                id: 2,
                launch: sh("true"),
            },
            Request::Stop { id: 1 },
        ] {
            write_frame(&mut stream, &request).await.expect("a request");
        }
        while running_with_arg(&marker) {
            assert!(
                std::time::Instant::now() < deadline,
                "the stop waited for the Client to read the output"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// An argument no other process on the host carries, to find a test's program by.
    #[cfg(target_os = "linux")]
    fn unique_marker() -> String {
        format!(
            "299.{}{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        )
    }

    /// Whether a live process has `arg` among its arguments.
    #[cfg(target_os = "linux")]
    fn running_with_arg(arg: &str) -> bool {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return false;
        };
        entries.flatten().any(|entry| {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                return false;
            };
            std::fs::read(entry.path().join("cmdline")).is_ok_and(|cmdline| {
                cmdline
                    .split(|b| *b == 0)
                    .any(|word| word == arg.as_bytes())
            }) && alive(pid)
        })
    }

    /// Closing the Client's connection stops every program the service started, with everything
    /// in its process group — here a shell and the `sleep` it started.
    /// Verifies: ADR-0059
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closing_the_connection_stops_the_whole_process_group() {
        let service = service(own_uid());
        let mut stream = connect_raw(&service.socket, this_build()).await;
        assert!(matches!(next(&mut stream).await, Some(Reply::Hello { .. })));
        write_frame(
            &mut stream,
            &Request::Start {
                id: 1,
                launch: sh("sleep 300 & echo $!; wait"),
            },
        )
        .await
        .expect("start");
        let (mut shell, mut worker) = (None, None);
        while shell.is_none() || worker.is_none() {
            match next(&mut stream).await.expect("open") {
                Reply::Started { pid, .. } => shell = Some(pid),
                Reply::Output { line, .. } => worker = line.trim().parse::<u32>().ok(),
                other => panic!("unexpected {other:?}"),
            }
        }
        let (shell, worker) = (shell.expect("shell"), worker.expect("worker"));
        assert!(alive(shell) && alive(worker));

        drop(stream);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while alive(shell) || alive(worker) {
            assert!(
                std::time::Instant::now() < deadline,
                "the program's group outlived the connection"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Whether `pid` is a live process: present and not a zombie, which a container's init may
    /// leave unreaped.
    #[cfg(target_os = "linux")]
    fn alive(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .is_some_and(|state| state != "Z" && state != "X")
        })
    }

    /// The shutdown of the service is a close too: what it started does not outlive it, and its
    /// end is the service's going, not an exit of the program's own (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn the_service_stops_its_programs_when_it_shuts_down() {
        let mut service = service(own_uid());
        let channel = Channel::connect(&service.socket, own_uid(), this_process())
            .await
            .expect("connect");
        let mut child = channel.start("test", sh("sleep 300")).await.expect("start");
        let _ = service.stop.take().expect("stop").send(());
        let gone = tokio::time::timeout(Duration::from_secs(15), child.wait())
            .await
            .expect("the program ended in time")
            .expect_err("no exit of the program's own");
        assert!(is_unreachable(&gone), "{gone}");
        tokio::time::timeout(Duration::from_secs(5), &mut service.task)
            .await
            .expect("the service ended")
            .expect("cleanly");
    }

    /// A line longer than a message holds arrives in pieces, none lost.
    #[tokio::test]
    async fn a_long_line_is_split_not_lost() {
        let data = vec![b'x'; MAX_LINE * 2 + 5];
        let mut reader = tokio::io::BufReader::new(data.as_slice());
        let mut lengths = Vec::new();
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = read_line_bounded(&mut reader, &mut buf, MAX_LINE)
                .await
                .expect("read");
            if n == 0 {
                break;
            }
            lengths.push(n);
        }
        assert_eq!(lengths, vec![MAX_LINE, MAX_LINE, 5]);
    }
}
