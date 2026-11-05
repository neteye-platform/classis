//! The Gateway's package cache (ADR-0026 clauses 42 to 48): each uploaded artifact the Gateway
//! relays an offer of is fetched from the Server once, with the Gateway's own certificate, and
//! passed on only to a downstream host whose Agent it relayed that offer to.
//!
//! What is kept here:
//! - the **bindings**: each `instance_uid` to the host of the first report for it, as the Server
//!   binds on first report (ADR-0021 clause 7), kept across restarts in the store beside the held
//!   artifacts ([`store`](crate::gateway::store), ADR-0058 clause 3) and relied on only once the
//!   store holds them;
//! - the **offers**: per `instance_uid`, the Server-hosted artifacts its last recorded
//!   `packages_available` named, indexed by host;
//! - the **held** artifacts, one file per stored copy under `<state_dir>/gateway-packages` beside the
//!   store, which is none of them, verified
//!   against the offered hash before it is renamed into place, and the room reserved for the
//!   fetches in flight and counted for the files being deleted;
//! - what each artifact's fetch came to: in flight, failed (not repeated until the artifact newly
//!   appears in an offer), too large (not repeated at all), and whether a request may still
//!   trigger one refetch of it under the current offer.
//!
//! What a downstream peer may fetch is decided from the bindings and the offers alone, by the host
//! its certificate names. A request never waits for a fetch: while one runs it is answered `503`
//! with `Retry-After`, and everything else the route does not serve is answered with one `404`.
//! No file operation runs while the shared state is locked.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use opamp::proto::{DownloadableFile, ServerToAgent};
use opamp::server::listen::PeerCertificate;
use opamp::uid::InstanceUid;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::config::ClientConfig;
use crate::gateway::policy::{Bindings, Bound, Change, End, Limits};
use crate::gateway::revocations::{RevocationList, Verdict};
use crate::gateway::store::{self, Journal};
use crate::nofollow::HeldDir;
use crate::packages::{Patience, Waits};
use crate::shutdown::Shutdown;

/// The cache's directory under the Client's `state_dir`.
pub const DIR: &str = "gateway-packages";

/// The download route, as the Server serves it and as the Gateway serves it downstream.
pub const ROUTE: &str = "/api/v1/packages/{agent_type}/{version}/file";

/// What every offered path on the Server's download route begins with.
const ROUTE_PREFIX: &str = "/api/v1/packages/";

/// The SAN URI prefix naming the host a certificate was issued to (ADR-0021 clause 7), as the
/// Server writes it.
const HOST_URI_PREFIX: &str = "urn:opamp-fleet:host:";

/// How many fetches run at a time (ADR-0026 clause 42): a rollout rarely offers more distinct
/// artifacts at once, and each one holds a reservation of up to the per-artifact limit.
const CONCURRENT_FETCHES: usize = 4;

/// The most `instance_uid`s bound at once, over all hosts (ADR-0026 clause 45).
const MAX_BINDINGS: usize = 1_000_000;

/// How many lines per host and minute are logged one by one (ADR-0026 clause 46).
const LINES_PER_MINUTE: u32 = 5;

/// What a request is told to wait while a fetch runs (ADR-0026 clause 45).
const RETRY_AFTER_SECS: &str = "30";

/// The pace a fetch keeps up after its grace, or it is cut (ADR-0026 clause 42).
const PACE_FLOOR_BYTES_PER_SEC: u64 = 64 * 1024;
const PACE_GRACE: Duration = Duration::from_secs(60);

/// Whether a fetch that has received `bytes` in `elapsed` has fallen below the pace floor: after
/// the grace, at least 64 KiB for every second past it (ADR-0026 clause 42).
fn below_pace(bytes: u64, elapsed: Duration) -> bool {
    let Some(past) = elapsed.checked_sub(PACE_GRACE) else {
        return false;
    };
    u128::from(bytes) < past.as_millis() * u128::from(PACE_FLOOR_BYTES_PER_SEC) / 1000
}

/// One artifact as an offer names it: the path on the Server's route, query included, and the
/// content hash the offer carries (ADR-0026 clause 44).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Artifact {
    pub path: String,
    pub hash: Vec<u8>,
}

impl Artifact {
    /// The artifact a relayed file names, when it is one the Server hosts: a path on its download
    /// route (ADR-0033). The Server offers every artifact as such a path. An absolute URL, which only
    /// a foreign Server could send, is `None`: a downstream Client refuses it, since its only source
    /// is its own origin, this Gateway. So is a hash that is no SHA-256 and could never verify.
    #[must_use]
    pub fn of(file: &DownloadableFile) -> Option<Artifact> {
        let url = &file.download_url;
        let path = url.split('?').next().unwrap_or_default();
        (url.starts_with(ROUTE_PREFIX) && path.ends_with("/file") && file.content_hash.len() == 32)
            .then(|| Artifact {
                path: url.clone(),
                hash: file.content_hash.clone(),
            })
    }

    fn route_path(&self) -> &str {
        self.path.split('?').next().unwrap_or_default()
    }
}

/// The host a certificate names (`urn:opamp-fleet:host:<id>`), if it names one.
#[must_use]
pub fn host_of(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|name| match name {
        x509_parser::extensions::GeneralName::URI(uri) => {
            uri.strip_prefix(HOST_URI_PREFIX).map(str::to_string)
        }
        _ => None,
    })
}

/// The host a downstream certificate speaks as (ADR-0039 clause 6): the one it names, else the
/// one the Server derives for it from its issuer and serial and names in its first renewal.
#[must_use]
pub fn speaker_of(der: &[u8]) -> Option<String> {
    host_of(der).or_else(|| {
        crate::gateway::revocations::certificate_id(der)
            .map(|(issuer, serial)| fleet_core::host::derived(&issuer, &serial))
    })
}

/// Where a downstream certificate ends, as the Gateway keeps it for its host (ADR-0058 clause 3):
/// its `notAfter`, and the certificate as the revocation list names it.
#[must_use]
pub fn end_of(der: &[u8]) -> Option<End> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let (issuer, serial) = crate::gateway::revocations::certificate_id(der)?;
    Some(End {
        not_after: cert.validity().not_after.timestamp(),
        issuer,
        serial,
    })
}

/// A certificate's serial in hex, for a log line.
fn serial_of(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(hex::encode(cert.raw_serial()))
}

/// One held artifact.
#[derive(Clone, Copy, Debug)]
struct Held {
    len: u64,
    /// When it was last stored or served, as a tick of [`Inner::tick`].
    used: u64,
    /// Which stored copy: part of its file name, so deleting an old copy never touches a new one.
    copy: u64,
}

/// What one line of a host is to the log (ADR-0026 clause 46).
#[derive(Debug, PartialEq, Eq)]
enum Note {
    /// Log it.
    Log,
    /// Log it, and that this many more were counted in the host's last minute.
    LogAfter(u64),
    /// Count it.
    Count,
}

/// The lines of the last minute, per host: the first few are logged, the rest counted.
#[derive(Default)]
struct RefusalLog {
    windows: HashMap<String, Window>,
}

struct Window {
    started: Instant,
    logged: u32,
    counted: u64,
}

impl RefusalLog {
    /// The most hosts tracked at once; past it the table starts over.
    const HOSTS: usize = 4096;

    fn note(&mut self, host: &str, now: Instant) -> Note {
        if let Some(window) = self.windows.get_mut(host) {
            if now.duration_since(window.started) < Duration::from_secs(60) {
                if window.logged < LINES_PER_MINUTE {
                    window.logged += 1;
                    return Note::Log;
                }
                window.counted += 1;
                return Note::Count;
            }
        } else if self.windows.len() >= Self::HOSTS {
            self.windows.clear();
        }
        let counted = self
            .windows
            .insert(
                host.to_string(),
                Window {
                    started: now,
                    logged: 1,
                    counted: 0,
                },
            )
            .map_or(0, |window| window.counted);
        if counted > 0 {
            Note::LogAfter(counted)
        } else {
            Note::Log
        }
    }
}

/// Answered once the changes it waits for are written and synced, with whether they were.
pub type Ticket = tokio::sync::oneshot::Receiver<bool>;

/// What a report's binding came to before the store is asked (ADR-0058 clause 3).
pub enum Begun {
    /// Bound to the reporting host, with nothing new to write.
    Bound,
    /// Not bound to the reporting host; logged.
    Refused,
    /// Bound once the store holds what the ticket waits for.
    Writing(Ticket),
    /// Undecided until the store's next write settles the host's moved end: ask again then.
    Waiting(tokio::sync::watch::Receiver<u64>),
}

#[derive(Default)]
struct Inner {
    /// Each `instance_uid` to the host of its first report (ADR-0026 clause 45).
    bindings: Bindings,
    /// The changes to the bindings not yet handed to the store, in the order they were made.
    queue: Vec<Change>,
    /// Who waits for them.
    waiting: Vec<tokio::sync::oneshot::Sender<bool>>,
    offers: HashMap<InstanceUid, Vec<Artifact>>,
    /// The `instance_uid`s with a current offer, by the host they are bound to.
    by_host: HashMap<String, HashSet<InstanceUid>>,
    held: HashMap<Vec<u8>, Held>,
    /// Files being deleted, still counted until they are gone.
    deleting: HashMap<PathBuf, u64>,
    /// Files whose deletion failed: still on disk, still counted, deleted again later.
    doomed: HashMap<PathBuf, u64>,
    /// The room reserved for each fetch in flight.
    reserved: HashMap<Vec<u8>, u64>,
    fetching: HashSet<Vec<u8>>,
    /// Fetches that failed, not repeated until the artifact newly appears in an offer.
    failed: HashSet<Vec<u8>>,
    /// Artifacts a request may still fetch once under the current offer.
    armed: HashSet<Vec<u8>>,
    /// Artifacts too large for the cache, not fetched again while the Gateway runs.
    refused: HashSet<Vec<u8>>,
    refusals: RefusalLog,
    tick: u64,
    copies: u64,
}

impl Inner {
    fn bytes_counted(&self) -> u64 {
        self.held.values().map(|held| held.len).sum::<u64>() + self.other_counted()
    }

    /// What is counted beside the held artifacts.
    fn other_counted(&self) -> u64 {
        self.deleting.values().sum::<u64>()
            + self.doomed.values().sum::<u64>()
            + self.reserved.values().sum::<u64>()
    }

    fn offered(&self) -> HashSet<Vec<u8>> {
        self.offers
            .values()
            .flat_map(|artifacts| artifacts.iter().map(|artifact| artifact.hash.clone()))
            .collect()
    }

    /// Whether a new fetch of `hash` may start now.
    fn may_fetch(&self, hash: &[u8]) -> bool {
        !self.held.contains_key(hash)
            && !self.fetching.contains(hash)
            && !self.refused.contains(hash)
            && !self.failed.contains(hash)
    }
}

/// The artifacts to delete so that `need` more bytes fit within `capacity` beside `other` bytes
/// already counted (ADR-0026 clause 47): those no current offer names first, then offered ones,
/// each least recently used first. `None` when deleting every held artifact is not enough.
fn victims(
    held: &HashMap<Vec<u8>, Held>,
    offered: &HashSet<Vec<u8>>,
    other: u64,
    need: u64,
    capacity: u64,
) -> Option<Vec<Vec<u8>>> {
    let mut order: Vec<(&Vec<u8>, &Held)> = held.iter().collect();
    order.sort_by_key(|(hash, held)| (offered.contains(*hash), held.used));
    let mut total: u64 = other + held.values().map(|held| held.len).sum::<u64>();
    let mut out = Vec::new();
    for (hash, held) in order {
        if total.saturating_add(need) <= capacity {
            break;
        }
        total -= held.len;
        out.push(hash.clone());
    }
    (total.saturating_add(need) <= capacity).then_some(out)
}

/// Why a fetch stored nothing.
enum Failure {
    /// Past the bound of clause 13: remembered for the run, and not fetched again.
    TooLarge(u64),
    Other(String),
}

/// What the state says to do for a request of an offered artifact.
enum Decision {
    /// Open this stored copy.
    Open(u64),
    Busy,
    /// Start the one refetch the current offer allows; it is marked as being fetched.
    Start,
    Nothing,
}

/// What a request for an offered artifact gets.
enum Answer {
    File(std::fs::File),
    /// A fetch of it runs, or was just started: ask again later.
    Busy,
    Nothing,
}

/// Removes `uid`'s current offer, recorded for `host`, whose binding went.
fn drop_offer(inner: &mut Inner, uid: InstanceUid, host: &str) {
    inner.offers.remove(&uid);
    if let Some(offered) = inner.by_host.get_mut(host) {
        offered.remove(&uid);
        if offered.is_empty() {
            inner.by_host.remove(host);
        }
    }
}

/// The cache that writes each store in this process. A Gateway restarted in the same process —
/// when an offer moves its endpoint — opens its store while the cache it replaces may still be
/// held by its last tasks; only one of them may write it.
fn owners() -> MutexGuard<'static, Vec<(PathBuf, Weak<PackageCache>)>> {
    static OWNERS: Mutex<Vec<(PathBuf, Weak<PackageCache>)>> = Mutex::new(Vec::new());
    OWNERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Stops the cache that wrote the store in `dir` until now from writing it again: it waits for
/// a write in progress and then holds no store, so its later reports bind nothing. Paths are
/// compared as given, unresolved: a Gateway restarted in the same process opens its store under
/// the same `state_dir` from the same configuration, and that is the case this guards.
fn retire(dir: &Path) {
    let retired: Vec<Arc<PackageCache>> = {
        let mut owners = owners();
        owners.retain(|(_, owner)| owner.strong_count() > 0);
        owners
            .iter()
            .filter(|(owned, _)| owned == dir)
            .filter_map(|(_, owner)| owner.upgrade())
            .collect()
    };
    for cache in retired {
        *cache
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// How many lines of reports a store may hold per live line before it is rewritten whole: the
/// order of reports is written once a minute, and an Agent reports more often, so these lines grow
/// with the Agents carried rather than with the bindings made, and are not counted with them.
const REPORT_LINES_PER_LIVE: usize = 8;

/// The one task that writes a cache's store: whoever queues changes wakes it, and each wake
/// writes everything queued by then in one append and one sync. It ends with the cache, whose
/// drop wakes it a last time.
async fn write_store(cache: Weak<PackageCache>, wake: Arc<tokio::sync::Notify>) {
    loop {
        wake.notified().await;
        let Some(cache) = cache.upgrade() else {
            return;
        };
        let _ = tokio::task::spawn_blocking(move || cache.flush()).await;
    }
}

/// Deletes a file; `true` once it is gone.
fn remove_file(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// What a test changes about a cache; the defaults otherwise.
struct Knobs {
    /// How a file is deleted.
    remove: fn(&Path) -> bool,
    /// How long a fetch waits out the Server's `Retry-After`.
    patience: Patience,
    max_bindings: usize,
    /// How the bindings' store is rewritten at start.
    create_journal: fn(HeldDir, &[Change]) -> std::io::Result<Journal>,
}

impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            remove: remove_file,
            patience: Patience::default(),
            max_bindings: MAX_BINDINGS,
            create_journal: Journal::create,
        }
    }
}

/// The package cache of one Gateway.
pub struct PackageCache {
    config: Arc<ClientConfig>,
    dir: PathBuf,
    capacity: u64,
    /// The largest artifact fetched: the cache's capacity, or `max_artifact_size_bytes` when
    /// smaller.
    limit: u64,
    slots: tokio::sync::Semaphore,
    /// The most `instance_uid`s one host may bind: `max_carried_agents`.
    per_host_bindings: usize,
    /// Ends every fetch, waiting or not.
    shutdown: Shutdown,
    knobs: Knobs,
    /// The bindings' store, written by one at a time and never while `inner` is locked; `None`
    /// while it cannot be read.
    journal: Mutex<Option<Journal>>,
    /// Counts the store's writes, each announced once what it wrote is settled.
    writes: tokio::sync::watch::Sender<u64>,
    /// Wakes the one task that writes the store ([`write_store`]).
    wake: Arc<tokio::sync::Notify>,
    /// Why the store could not be read at start, while it cannot: the Gateway then carries no
    /// downstream Agent (ADR-0058 clause 3).
    unreadable: Option<String>,
    inner: Mutex<Inner>,
}

/// Clears a fetch's entry and its reservation when its task ends without settling — a panic
/// included — so that the artifact is not left marked as being fetched by nobody.
struct Landing {
    cache: Arc<PackageCache>,
    hash: Vec<u8>,
    settled: bool,
}

impl Drop for PackageCache {
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

impl Drop for Landing {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let mut inner = self.cache.inner();
        inner.fetching.remove(&self.hash);
        inner.reserved.remove(&self.hash);
    }
}

/// The Gateway's directory as it was found at start.
enum Opened {
    /// The bindings the store holds, and the store rewritten whole from them.
    Store(Box<(Bindings, Journal)>),
    /// Why the store cannot be read, or cannot be rewritten.
    Unreadable(String),
}

/// Opens the Gateway's directory `dir` without following a link, empties it of every artifact an
/// earlier run left (ADR-0026 clause 47) and keeps the store, reads the bindings from it and
/// rewrites it whole from what they are with `create` (ADR-0058 clause 3). A store that cannot
/// be read or rewritten is [`Opened::Unreadable`]: the Gateway does not rely on it.
fn open_dir(
    dir: &Path,
    create: fn(HeldDir, &[Change]) -> std::io::Result<Journal>,
) -> Result<Opened, String> {
    let held = match HeldDir::create(dir, 0o700) {
        Ok(held) => held,
        Err(e) => return Ok(Opened::Unreadable(format!("{}: {e}", dir.display()))),
    };
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot empty {}: {e}", dir.display()));
    for entry in entries? {
        let entry = entry.map_err(|e| format!("cannot empty {}: {e}", dir.display()))?;
        if entry.file_name() == store::NAME {
            continue;
        }
        let path = entry.path();
        let removed = match entry.file_type() {
            Ok(kind) if kind.is_dir() => std::fs::remove_dir_all(&path),
            _ => std::fs::remove_file(&path),
        };
        removed.map_err(|e| format!("cannot empty {}: {e}", dir.display()))?;
    }
    let path = dir.join(store::NAME);
    let mut bindings = match store::load(&held).and_then(Bindings::replay) {
        Ok(bindings) => bindings,
        Err(e) => return Ok(Opened::Unreadable(format!("{}: {e}", path.display()))),
    };
    // What ended while the Gateway was down ends now, and the rewrite below leaves it out
    // (ADR-0058 clause 4); the revocation list is asked once the Gateway holds one.
    for (host, uids) in bindings.end(now(), None) {
        log_ended(&host, uids.len());
    }
    match create(held, &bindings.snapshot()) {
        Ok(journal) => Ok(Opened::Store(Box::new((bindings, journal)))),
        Err(e) => Ok(Opened::Unreadable(format!(
            "cannot rewrite {}: {e}",
            path.display()
        ))),
    }
}

/// The Gateway's clock, which its handshake checks validity by, in seconds since the Unix epoch.
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Logs that a host's bindings ended with its certificate (ADR-0058 clause 4).
fn log_ended(host: &str, count: usize) {
    info!(
        %host, bindings = count,
        "ended the bindings of a host whose certificate has expired or is revoked"
    );
}

/// Logs that the Gateway carries no downstream Agent while its store cannot be read, and what
/// lets it start again: at start, and once an hour (ADR-0058 clause 3).
pub fn log_unreadable(why: &str, store: &Path) {
    error!(
        reason = %why,
        "the Gateway cannot read or rewrite the store of its bindings and carries no Agent behind \
         it; remove {} and restart the Client to start with no binding",
        store.display()
    );
}

impl PackageCache {
    /// The cache of the Gateway `config` arms, its directory emptied of artifacts (ADR-0026
    /// clause 47) and its bindings read from the store (ADR-0058 clause 3).
    ///
    /// # Errors
    /// Returns an error when a directory left by an earlier run cannot be emptied. A store that
    /// cannot be read or rewritten is no error: the cache then carries no downstream Agent
    /// ([`PackageCache::unreadable`]).
    pub async fn open(config: Arc<ClientConfig>, shutdown: Shutdown) -> Result<Arc<Self>, String> {
        Self::open_with(config, shutdown, Knobs::default()).await
    }

    async fn open_with(
        config: Arc<ClientConfig>,
        shutdown: Shutdown,
        knobs: Knobs,
    ) -> Result<Arc<Self>, String> {
        let capacity = config
            .gateway
            .as_ref()
            .map_or(1, |gateway| gateway.package_cache_bytes);
        let per_host_bindings = config
            .gateway
            .as_ref()
            .map_or(1, |gateway| gateway.max_carried_agents);
        let dir = config.state_dir.join(DIR);
        let opened = dir.clone();
        let create = knobs.create_journal;
        let opened = tokio::task::spawn_blocking(move || {
            retire(&opened);
            open_dir(&opened, create)
        })
        .await
        .map_err(|e| e.to_string())??;
        let (bindings, journal, unreadable) = match opened {
            Opened::Store(opened) => {
                let (bindings, journal) = *opened;
                info!(
                    bindings = bindings.len(),
                    "read the bindings of the Agents behind this Gateway"
                );
                (bindings, Some(journal), None)
            }
            Opened::Unreadable(why) => {
                log_unreadable(&why, &dir.join(store::NAME));
                (Bindings::default(), None, Some(why))
            }
        };
        let cache = Arc::new(PackageCache {
            limit: capacity.min(config.max_artifact_size_bytes),
            capacity,
            dir,
            config,
            slots: tokio::sync::Semaphore::new(CONCURRENT_FETCHES),
            per_host_bindings,
            shutdown,
            knobs,
            journal: Mutex::new(journal),
            writes: tokio::sync::watch::Sender::new(0),
            wake: Arc::default(),
            unreadable,
            inner: Mutex::new(Inner {
                bindings,
                ..Inner::default()
            }),
        });
        owners().push((cache.dir.clone(), Arc::downgrade(&cache)));
        tokio::spawn(write_store(Arc::downgrade(&cache), cache.wake.clone()));
        Ok(cache)
    }

    /// The state, whether or not a task panicked while holding it: every update leaves it whole.
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn file(&self, hash: &[u8], copy: u64) -> PathBuf {
        self.dir.join(format!("{}.{copy}", hex::encode(hash)))
    }

    /// Binds `uid` to `host` unless it is bound already: the first report wins, and every report
    /// refreshes when it was last reported (ADR-0058 clause 2). `host` is the one a downstream
    /// certificate speaks as ([`speaker_of`]), `end` where that certificate ends ([`end_of`]). A host
    /// binds at most `max_carried_agents`, the Gateway at most its global cap; past either the
    /// host's own least recently reported binding whose `instance_uid` has neither a route
    /// (`routed`) nor a current offer makes room, never another host's, and without one nothing is
    /// bound.
    ///
    /// The first half of a bind: [`PackageCache::written`] waits for the ticket of a
    /// [`Begun::Writing`], and [`PackageCache::finish_bind`] decides. A report for an `instance_uid`
    /// bound to another host, or one that could not be bound, is logged and [`Begun::Refused`].
    /// Beside it, the `instance_uid`s whose bindings made room, whichever the answer.
    pub fn begin_bind(
        &self,
        uid: InstanceUid,
        host: &str,
        end: &End,
        routed: impl Fn(&InstanceUid) -> bool,
    ) -> (Begun, Vec<InstanceUid>) {
        let limits = Limits {
            per_host: self.per_host_bindings,
            total: self.knobs.max_bindings,
        };
        let mut guard = self.inner();
        let inner = &mut *guard;
        let offers = &inner.offers;
        let outcome = inner.bindings.bind(uid, host, end, now(), limits, |uid| {
            !routed(uid) && !offers.contains_key(uid)
        });
        let evicted = outcome.evicted;
        if outcome.bound == Bound::Waiting {
            return (Begun::Waiting(self.writes.subscribe()), evicted);
        }
        if let Bound::Refused(why) = outcome.bound {
            if inner.refusals.note(host, Instant::now()) != Note::Count {
                warn!(agent = %uid, %host, "not forwarding a report: not binding its instance_uid: {why}");
            }
            return (Begun::Refused, evicted);
        }
        if outcome.bound == Bound::Kept && inner.bindings.host_of(&uid) != Some(host) {
            let bound = inner.bindings.host_of(&uid).unwrap_or("none").to_string();
            if inner.refusals.note(host, Instant::now()) != Note::Count {
                warn!(
                    agent = %uid, %host, %bound,
                    "not forwarding a report for an instance_uid bound to another host"
                );
            }
            return (Begun::Refused, evicted);
        }
        if outcome.changes.is_empty() {
            return (Begun::Bound, evicted);
        }
        if outcome
            .changes
            .iter()
            .any(|change| store::line(change).is_none())
        {
            inner.bindings.ends_written(&outcome.changes, false);
            let removals = outcome
                .changes
                .into_iter()
                .filter(|change| matches!(change, Change::Unbound(_)));
            inner.queue.extend(removals);
            let changes = inner.bindings.abort(&uid);
            inner.queue.extend(changes);
            warn!(
                agent = %uid, %host,
                "not forwarding a report: its binding is too long to be stored"
            );
            return (Begun::Refused, evicted);
        }
        let ticket = self.enqueue(inner, outcome.changes);
        (Begun::Writing(ticket), evicted)
    }

    /// Queues `changes` for the store and wakes its writer; the ticket answers once they are
    /// written. Called under the lock, so the store takes them in the order they were made.
    fn enqueue(&self, inner: &mut Inner, changes: impl IntoIterator<Item = Change>) -> Ticket {
        let (done, ticket) = tokio::sync::oneshot::channel();
        inner.queue.extend(changes);
        inner.waiting.push(done);
        self.wake.notify_one();
        ticket
    }

    /// Whether the changes `ticket` waits for are written and synced (ADR-0058 clause 3): by the
    /// store's one writer, off the async workers, with whatever else is queued by then.
    pub async fn written(ticket: Ticket) -> bool {
        ticket.await.unwrap_or(false)
    }

    /// The second half of a bind: whether `uid` is now bound to `host` and its report may be
    /// forwarded and its reply routed back (ADR-0039 clause 5). A new binding the store could not
    /// take, `written` false, is not made, and that is logged. Called under the same lock as the
    /// route it decides on, so no binding gives way between the two.
    pub fn finish_bind(&self, uid: InstanceUid, host: &str, written: bool) -> bool {
        let mut inner = self.inner();
        if written {
            inner.bindings.commit(&uid);
            return inner.bindings.holds(&uid, host);
        }
        let changes = inner.bindings.abort(&uid);
        if !changes.is_empty() {
            drop_offer(&mut inner, uid, host);
            // Should the store hold the binding after all, its removal follows.
            drop(self.enqueue(&mut inner, changes));
        }
        if inner.refusals.note(host, Instant::now()) != Note::Count {
            warn!(agent = %uid, %host, "not forwarding a report: the bindings' store cannot be written");
        }
        false
    }

    /// Writes the queued changes and answers who waits for them. A store that cannot take an
    /// append is rewritten whole from the bindings, which hold the queued changes too; so is one
    /// that has grown to twice the lines it holds live, or whose lines of reports have outgrown
    /// [`REPORT_LINES_PER_LIVE`] times them (ADR-0058 clause 3). Each call is announced once its
    /// moved ends are settled.
    fn flush(&self) {
        let mut guard = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (changes, waiting) = {
            let mut inner = self.inner();
            (
                std::mem::take(&mut inner.queue),
                std::mem::take(&mut inner.waiting),
            )
        };
        if changes.is_empty() && waiting.is_empty() {
            return;
        }
        let written = match guard.as_mut() {
            None => {
                self.inner().bindings.ends_written(&changes, false);
                false
            }
            Some(journal) => match journal.append(&changes) {
                Ok(()) => {
                    self.inner().bindings.ends_written(&changes, true);
                    true
                }
                Err(e) => {
                    debug!(error = %e, "cannot append to the bindings' store; rewriting it whole");
                    self.compact(journal)
                }
            },
        };
        for waiter in waiting {
            let _ = waiter.send(written);
        }
        if let Some(journal) = guard.as_mut() {
            let live = self.inner().bindings.live();
            let grown = journal.lines() > 0 && journal.lines() >= 2 * live;
            let reported = journal.reports() > REPORT_LINES_PER_LIVE * live.max(1);
            if written && (grown || reported) {
                self.compact(journal);
            }
        }
        self.writes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Rewrites the store whole from the bindings, the queued changes taken in with them. The
    /// bindings are copied under the lock and ordered after it is released.
    fn compact(&self, journal: &mut Journal) -> bool {
        let (raw, moving, waiting) = {
            let mut inner = self.inner();
            inner.queue.clear();
            (
                inner.bindings.raw(),
                inner.bindings.moving(),
                std::mem::take(&mut inner.waiting),
            )
        };
        let written = match journal.compact(&raw.changes()) {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "cannot write the bindings' store");
                false
            }
        };
        self.inner().bindings.compacted(&moving, written);
        for waiter in waiting {
            let _ = waiter.send(written);
        }
        written
    }

    /// Writes the order in which the bindings were reported since the last call (ADR-0058
    /// clause 3): once a minute and at shutdown.
    pub async fn write_reports(&self) {
        let reports = self.inner().bindings.reports();
        if reports.is_empty() {
            return;
        }
        let changes = reports.changes();
        let ticket = {
            let mut inner = self.inner();
            self.enqueue(&mut inner, changes)
        };
        if !Self::written(ticket).await {
            warn!("cannot write the order of the bindings' reports");
        }
    }

    /// Ends every binding of each host whose kept certificate end has passed by `now`, or, when
    /// `revoked` is given, whose certificate it says the revocation list names (ADR-0058 clause
    /// 3), each host logged with how many went. Their current offers go with them, and their
    /// removals are queued for the store. Returns the `instance_uid`s whose bindings ended, whose
    /// routes and places upstream the caller releases, and the ticket their removals are written
    /// under.
    pub fn end_certificates(
        &self,
        now: i64,
        revoked: Option<&dyn Fn(&End) -> bool>,
    ) -> (Vec<InstanceUid>, Option<Ticket>) {
        let mut inner = self.inner();
        let ended = inner.bindings.end(now, revoked);
        if ended.is_empty() {
            return (Vec::new(), None);
        }
        let mut uids = Vec::new();
        for (host, held) in ended {
            log_ended(&host, held.len());
            for uid in &held {
                drop_offer(&mut inner, *uid, &host);
            }
            uids.extend(held);
        }
        let removals: Vec<Change> = uids.iter().map(|uid| Change::Unbound(*uid)).collect();
        let ticket = self.enqueue(&mut inner, removals);
        (uids, Some(ticket))
    }

    /// Waits until the write under way, if any, has ended: a flush holds the journal's lock from
    /// its append through the rewrite that may follow it, after it has answered who waited.
    #[cfg(test)]
    pub(crate) fn settled(&self) {
        drop(
            self.journal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    /// Makes every later write of the bindings' store fail.
    #[cfg(test)]
    pub(crate) fn refuse_writes(&self) {
        self.inject(|faults| faults.all = true);
    }

    /// Sets where the bindings' store fails next.
    #[cfg(test)]
    fn inject(&self, set: impl FnOnce(&mut store::Faults)) {
        if let Some(journal) = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            set(&mut journal.faults);
        }
    }

    /// A bind start to end, outside any route: what the tests of this module bind with.
    #[cfg(test)]
    async fn bind(
        self: &Arc<Self>,
        uid: InstanceUid,
        host: &str,
        routed: impl Fn(&InstanceUid) -> bool,
    ) -> (bool, Vec<InstanceUid>) {
        self.bind_until(uid, host, i64::MAX, routed).await
    }

    /// [`PackageCache::bind`] under a certificate whose `notAfter` is `not_after`.
    #[cfg(test)]
    async fn bind_until(
        self: &Arc<Self>,
        uid: InstanceUid,
        host: &str,
        not_after: i64,
        routed: impl Fn(&InstanceUid) -> bool,
    ) -> (bool, Vec<InstanceUid>) {
        let end = End {
            not_after,
            issuer: "ab".repeat(32),
            serial: "1".to_string(),
        };
        let (begun, evicted) = self.begin_bind(uid, host, &end, routed);
        let written = match begun {
            Begun::Refused | Begun::Waiting(_) => return (false, evicted),
            Begun::Bound => true,
            Begun::Writing(ticket) => Self::written(ticket).await,
        };
        (self.finish_bind(uid, host, written), evicted)
    }

    /// Records what a `ServerToAgent` relayed to `uid` offers, over a downstream connection whose
    /// certificate names `host`, and starts fetching each Server-hosted artifact it names that may
    /// be fetched (ADR-0026 clauses 42, 45). A message without `packages_available` leaves the offer
    /// standing; an offer over a certificate that names no host, or for an `instance_uid` bound to
    /// another host, is not recorded and starts nothing.
    pub fn observe(
        self: &Arc<Self>,
        uid: InstanceUid,
        host: Option<String>,
        reply: &ServerToAgent,
    ) {
        let Some(available) = &reply.packages_available else {
            return;
        };
        let Some(host) = host else {
            debug!(agent = %uid, "not recording an offer relayed over a certificate that names no host");
            return;
        };
        let artifacts: Vec<Artifact> = available
            .packages
            .values()
            .filter_map(|package| package.file.as_ref())
            .filter_map(Artifact::of)
            .collect();
        let start = {
            let mut inner = self.inner();
            // Recorded only for a binding the store holds: never for one still being written.
            if !inner.bindings.holds(&uid, &host) {
                let bound = inner.bindings.host_of(&uid).map(str::to_string);
                if inner.refusals.note(&host, Instant::now()) != Note::Count {
                    warn!(
                        agent = %uid, bound = bound.as_deref().unwrap_or("none"), relayed_for = %host,
                        "not recording an offer relayed for an instance_uid bound to another host"
                    );
                }
                return;
            }
            let previous = inner.offers.remove(&uid).unwrap_or_default();
            if artifacts.is_empty() {
                if let Some(uids) = inner.by_host.get_mut(&host) {
                    uids.remove(&uid);
                    if uids.is_empty() {
                        inner.by_host.remove(&host);
                    }
                }
                return;
            }
            let mut start = Vec::new();
            for artifact in &artifacts {
                if !previous.iter().any(|old| old.hash == artifact.hash) {
                    inner.failed.remove(&artifact.hash);
                }
                inner.armed.insert(artifact.hash.clone());
                if inner.may_fetch(&artifact.hash) {
                    inner.fetching.insert(artifact.hash.clone());
                    start.push(artifact.clone());
                }
            }
            inner.offers.insert(uid, artifacts);
            inner.by_host.entry(host).or_default().insert(uid);
            start
        };
        for artifact in start {
            self.spawn_fetch(artifact);
        }
    }

    /// The artifact at `path` in a current offer to an Agent bound to `host`.
    pub(crate) fn offered_to(&self, host: &str, path: &str) -> Option<Artifact> {
        let inner = self.inner();
        inner
            .by_host
            .get(host)?
            .iter()
            .filter_map(|uid| inner.offers.get(uid))
            .flat_map(|artifacts| artifacts.iter())
            .find(|artifact| artifact.path == path)
            .cloned()
    }

    /// What a request for an offered artifact gets (ADR-0026 clause 45): the held file, opened;
    /// `Busy` while a fetch of it runs, or once a request starts the one refetch the current offer
    /// allows; otherwise `Nothing`. A held copy whose file is gone when it is opened — evicted in
    /// between, or removed from under the cache — is forgotten, and the request decided again.
    async fn request(self: &Arc<Self>, artifact: &Artifact) -> Answer {
        let mut decision = Self::decide(&mut self.inner(), artifact);
        loop {
            match decision {
                Decision::Busy => return Answer::Busy,
                Decision::Nothing => return Answer::Nothing,
                Decision::Start => {
                    self.spawn_fetch(artifact.clone());
                    return Answer::Busy;
                }
                Decision::Open(copy) => {
                    match tokio::fs::File::open(self.file(&artifact.hash, copy)).await {
                        Ok(file) => return Answer::File(file.into_std().await),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            let mut inner = self.inner();
                            if inner.held.get(&artifact.hash).map(|held| held.copy) == Some(copy) {
                                inner.held.remove(&artifact.hash);
                            }
                            decision = Self::decide(&mut inner, artifact);
                            if matches!(decision, Decision::Open(again) if again == copy) {
                                return Answer::Nothing;
                            }
                        }
                        Err(_) => return Answer::Nothing,
                    }
                }
            }
        }
    }

    /// The decision for a request, under the lock.
    fn decide(inner: &mut Inner, artifact: &Artifact) -> Decision {
        if inner.held.contains_key(&artifact.hash) {
            inner.tick += 1;
            let tick = inner.tick;
            return inner
                .held
                .get_mut(&artifact.hash)
                .map_or(Decision::Nothing, |held| {
                    held.used = tick;
                    Decision::Open(held.copy)
                });
        }
        if inner.fetching.contains(&artifact.hash) {
            return Decision::Busy;
        }
        if inner.refused.contains(&artifact.hash)
            || inner.failed.contains(&artifact.hash)
            || !inner.armed.remove(&artifact.hash)
        {
            return Decision::Nothing;
        }
        inner.fetching.insert(artifact.hash.clone());
        Decision::Start
    }

    /// Runs the one fetch of `artifact`, marked as being fetched by the caller, on a task of its
    /// own, so that it completes whether or not anyone asks for it meanwhile.
    fn spawn_fetch(self: &Arc<Self>, artifact: Artifact) {
        let cache = self.clone();
        let mut shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let work = cache.clone().fetch(artifact);
            tokio::select! {
                () = work => {}
                () = shutdown.requested() => {}
            }
        });
    }

    /// One fetch, from its first request to its settling.
    async fn fetch(self: Arc<Self>, artifact: Artifact) {
        let cache = self;
        {
            let mut landing = Landing {
                cache: cache.clone(),
                hash: artifact.hash.clone(),
                settled: false,
            };
            let copy = {
                let mut inner = cache.inner();
                inner.copies += 1;
                inner.copies
            };
            let staged = cache
                .dir
                .join(format!("{}.{copy}.staged", hex::encode(&artifact.hash)));
            let outcome = match cache.download(&artifact, &staged).await {
                Ok(len) => match tokio::fs::rename(&staged, cache.file(&artifact.hash, copy)).await
                {
                    Ok(()) => Ok(len),
                    Err(e) => Err(Failure::Other(format!(
                        "cannot store the fetched artifact: {e}"
                    ))),
                },
                Err(failure) => Err(failure),
            };
            if outcome.is_err() {
                let _ = tokio::fs::remove_file(&staged).await;
            }
            cache.settle(&artifact, copy, outcome);
            landing.settled = true;
        }
    }

    /// Records what a fetch came to.
    fn settle(&self, artifact: &Artifact, copy: u64, outcome: Result<u64, Failure>) {
        let mut inner = self.inner();
        inner.reserved.remove(&artifact.hash);
        inner.fetching.remove(&artifact.hash);
        let path = artifact.route_path();
        match outcome {
            Ok(len) => {
                inner.tick += 1;
                let used = inner.tick;
                inner
                    .held
                    .insert(artifact.hash.clone(), Held { len, used, copy });
                info!(
                    %path, bytes = len, counted = inner.bytes_counted(),
                    "cached an artifact for the Agents behind this Gateway"
                );
            }
            Err(Failure::TooLarge(limit)) => {
                inner.refused.insert(artifact.hash.clone());
                warn!(
                    %path, limit,
                    "an offered artifact is larger than the package cache allows and is not \
                     delivered through this Gateway — raise [gateway] package_cache_bytes"
                );
            }
            Err(Failure::Other(e)) => {
                inner.failed.insert(artifact.hash.clone());
                warn!(
                    %path, error = %e,
                    "cannot fetch an offered artifact for the Agents behind this Gateway; it is \
                     fetched again when it is next newly offered"
                );
            }
        }
    }

    /// Reserves `need` bytes for the fetch of `hash`, deleting held artifacts to make room
    /// (ADR-0026 clause 47). Files whose deletion failed before are deleted again first. The
    /// victims are chosen under the lock and deleted after it is released; until they are gone
    /// they stay counted.
    async fn reserve(&self, hash: &[u8], need: u64) -> Result<(), String> {
        let retry: Vec<(PathBuf, u64)> = {
            let mut inner = self.inner();
            let retry: Vec<(PathBuf, u64)> = inner.doomed.drain().collect();
            for (path, len) in &retry {
                inner.deleting.insert(path.clone(), *len);
            }
            retry
        };
        self.delete(retry).await?;
        let victims: Vec<(PathBuf, u64)> = {
            let mut inner = self.inner();
            let other = inner.other_counted();
            let victims = victims(&inner.held, &inner.offered(), other, need, self.capacity)
                .ok_or_else(|| {
                    "the package cache has no room while other fetches run".to_string()
                })?;
            let mut deleting = Vec::new();
            for victim in victims {
                if let Some(held) = inner.held.remove(&victim) {
                    debug!(artifact = %hex::encode(&victim), "evicting a cached artifact");
                    let path = self.file(&victim, held.copy);
                    inner.deleting.insert(path.clone(), held.len);
                    deleting.push((path, held.len));
                }
            }
            inner.reserved.insert(hash.to_vec(), need);
            deleting
        };
        self.delete(victims).await?;
        let mut inner = self.inner();
        if inner.bytes_counted() > self.capacity {
            inner.reserved.remove(hash);
            return Err("the package cache cannot delete what it must to make room".to_string());
        }
        Ok(())
    }

    /// Deletes files marked as being deleted, off the async workers, and settles each: gone, or
    /// kept counted for a later attempt.
    async fn delete(&self, files: Vec<(PathBuf, u64)>) -> Result<(), String> {
        if files.is_empty() {
            return Ok(());
        }
        let remove = self.knobs.remove;
        let results = tokio::task::spawn_blocking(move || {
            files
                .into_iter()
                .map(|(path, len)| {
                    let gone = remove(&path);
                    (path, len, gone)
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| e.to_string())?;
        let mut inner = self.inner();
        for (path, len, gone) in results {
            inner.deleting.remove(&path);
            if !gone {
                warn!(file = %path.display(), "cannot delete a cached artifact; it stays counted");
                inner.doomed.insert(path, len);
            }
        }
        Ok(())
    }

    /// Streams the artifact from the Server into `staged`, hashing on the way, and checks the hash
    /// (ADR-0026 clauses 42, 44, 47). Returns its length.
    async fn download(&self, artifact: &Artifact, staged: &Path) -> Result<u64, Failure> {
        use tokio::io::AsyncWriteExt as _;

        let config = self.config.clone();
        let path = artifact.path.clone();
        // This Gateway's own certificate to its Server's origin, as every Client's download
        // (ADR-0033 clause 13), and no offered headers. The material is read from disk, so off the
        // async workers.
        let (url, origin, identified) = tokio::task::spawn_blocking(move || {
            let url = crate::packages::resolve_url(&path, &config.endpoint)?;
            let origin = crate::packages::ServerOrigin::new(&config)?;
            let identified =
                crate::tls::client_tls(&config).and_then(crate::packages::download_client)?;
            Ok::<_, String>((url, origin, identified))
        })
        .await
        .map_err(|e| Failure::Other(e.to_string()))?
        .map_err(Failure::Other)?;
        // A `429` or `503` with `Retry-After` defers the fetch, as it does a Client's download; the
        // slot is given back while it waits, and taken again before it asks anew.
        let waits = Waits::new(self.knobs.patience);
        let (mut response, _slot) = loop {
            let slot = self
                .slots
                .acquire()
                .await
                .map_err(|e| Failure::Other(e.to_string()))?;
            let response = crate::packages::send_download(&origin, &identified, &url, &[])
                .await
                .map_err(Failure::Other)?;
            match waits.asked(&url, &response).map_err(Failure::Other)? {
                Some(wait) => {
                    drop(slot);
                    tokio::time::sleep(wait).await;
                }
                None => break (response, slot),
            }
        };
        if !response.status().is_success() {
            return Err(Failure::Other(format!(
                "the Server answered {} — a Gateway fetches only once its host is marked as one",
                response.status()
            )));
        }
        let need = response.content_length().unwrap_or(self.limit);
        if need > self.limit {
            return Err(Failure::TooLarge(self.limit));
        }
        self.reserve(&artifact.hash, need)
            .await
            .map_err(Failure::Other)?;
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(|e| Failure::Other(format!("cannot create {}: {e}", self.dir.display())))?;
        // Owner-only, as a Client's own staging directory: what is held here is installed by the
        // Agents behind this Gateway.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|e| {
                    Failure::Other(format!("cannot restrict {}: {e}", self.dir.display()))
                })?;
        }
        let mut file = tokio::fs::File::create(staged)
            .await
            .map_err(|e| Failure::Other(format!("cannot create {}: {e}", staged.display())))?;
        // The pace floor: a fetch that trickles cannot hold a slot and a reservation for ever; the
        // read timeout cuts a silent one.
        let started = tokio::time::Instant::now();
        let mut hasher = Sha256::new();
        let mut len = 0u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Failure::Other(format!("cannot read the download: {e}")))?
        {
            len += chunk.len() as u64;
            // The reservation is the bound: a body longer than its `Content-Length`, or one
            // without, is cut where it would pass it.
            if len > need {
                return Err(if len > self.limit {
                    Failure::TooLarge(self.limit)
                } else {
                    Failure::Other("the body is longer than its Content-Length".to_string())
                });
            }
            if below_pace(len, started.elapsed()) {
                return Err(Failure::Other(format!(
                    "the fetch fell below {PACE_FLOOR_BYTES_PER_SEC} bytes per second"
                )));
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|e| Failure::Other(format!("cannot write {}: {e}", staged.display())))?;
        }
        file.flush()
            .await
            .map_err(|e| Failure::Other(format!("cannot write {}: {e}", staged.display())))?;
        let digest = hasher.finalize();
        if digest.as_slice() != artifact.hash.as_slice() {
            return Err(Failure::Other(
                "the fetched artifact does not match the offered content hash".to_string(),
            ));
        }
        Ok(len)
    }

    /// Why the bindings' store could not be read at start, while the Gateway carries no downstream
    /// Agent for it (ADR-0058 clause 3).
    #[must_use]
    pub fn unreadable(&self) -> Option<&str> {
        self.unreadable.as_deref()
    }

    /// The store's path, for the log.
    #[must_use]
    pub fn store_path(&self) -> PathBuf {
        self.dir.join(store::NAME)
    }

    /// Whether `uid` is bound to a host (ADR-0039 clause 6).
    pub fn is_bound(&self, uid: &InstanceUid) -> bool {
        self.inner().bindings.host_of(uid).is_some()
    }

    /// Logs one refusal of an enrolling peer's report or upgrade, aggregated per host it speaks as,
    /// as every refusal of the Gateway is (ADR-0026 clause 46, ADR-0039 clause 11).
    pub fn log_enrolment_refusal(&self, speaker: &str, peer: &str, why: &str) {
        match self.inner().refusals.note(speaker, Instant::now()) {
            Note::Log => warn!(host = %speaker, %peer, "refusing an enrolling peer: {why}"),
            Note::LogAfter(more) => warn!(
                host = %speaker, %peer, counted_last_minute = more,
                "refusing an enrolling peer: {why}; more lines of this host were counted in the \
                 minute before"
            ),
            Note::Count => {}
        }
    }

    /// Logs one refused download request, aggregated per host (ADR-0026 clause 46).
    fn log_refusal(&self, host: Option<&str>, serial: Option<&str>, path: &str) {
        let host = host.unwrap_or("none");
        let serial = serial.unwrap_or("none");
        let note = self.inner().refusals.note(host, Instant::now());
        match note {
            Note::Log => {
                info!(%host, %serial, %path, "refusing a download not offered to an Agent of this host");
            }
            Note::LogAfter(more) => {
                info!(
                    %host, %serial, %path, counted_last_minute = more,
                    "refusing a download not offered to an Agent of this host; more lines of this \
                     host were counted in the minute before"
                );
            }
            Note::Count => {}
        }
    }
}

/// What the downstream download route needs.
pub struct Downloads {
    pub cache: Arc<PackageCache>,
    pub revocations: RevocationList,
    /// Tells an enrolling peer, which is served no download, from a member (ADR-0039 clause 11).
    pub members: crate::gateway::Members,
}

/// The download route on the downstream listener (ADR-0026 clause 45).
pub fn router(downloads: Arc<Downloads>) -> axum::Router {
    axum::Router::new()
        .route(ROUTE, axum::routing::get(serve))
        .with_state(downloads)
}

/// The one answer for every artifact the route does not serve, whatever the reason.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// The answer while a fetch runs: ask again, rather than wait past a read timeout.
fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECS),
        )],
        "the Gateway is fetching this artifact",
    )
        .into_response()
}

/// What every downstream request but an enrolling peer's is answered while the bindings' store
/// cannot be read (ADR-0058 clause 3).
pub const STORE_UNREADABLE: &str = "the Gateway cannot read the store of its bindings";

fn store_unreadable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, STORE_UNREADABLE).into_response()
}

async fn serve(
    axum::extract::State(downloads): axum::extract::State<Arc<Downloads>>,
    request: Request,
) -> Response {
    // No Agent is carried while the bindings' store cannot be read (ADR-0058 clause 3).
    if downloads.cache.unreadable().is_some() {
        return store_unreadable();
    }
    let certificate = request
        .extensions()
        .get::<PeerCertificate>()
        .and_then(|peer| peer.0.as_ref())
        .map(|cert| cert.as_ref().to_vec())
        .unwrap_or_default();
    // The admission of `/v1/opamp`, and nothing beyond it (ADR-0015 clauses 11, 14).
    match downloads.revocations.verdict(&certificate) {
        Verdict::Admit => {}
        Verdict::Revoked => {
            return (StatusCode::UNAUTHORIZED, "this certificate is revoked").into_response()
        }
        Verdict::Stale => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, HeaderValue::from_static("30"))],
                "the Gateway holds no current revocation list",
            )
                .into_response()
        }
    }
    let path = request
        .uri()
        .path_and_query()
        .map_or("", |path| path.as_str());
    // An enrolling peer is offered nothing, so it is served nothing (ADR-0039 clause 11), whatever
    // host its certificate names.
    let host = (!downloads.members.enrolling(&certificate))
        .then(|| host_of(&certificate))
        .flatten();
    let Some(artifact) = host
        .as_deref()
        .and_then(|host| downloads.cache.offered_to(host, path))
    else {
        downloads.cache.log_refusal(
            host.as_deref(),
            serial_of(&certificate).as_deref(),
            request.uri().path(),
        );
        return not_found();
    };
    let file = match downloads.cache.request(&artifact).await {
        Answer::File(file) => file,
        Answer::Busy => return busy(),
        Answer::Nothing => return not_found(),
    };
    let file = tokio::fs::File::from_std(file);
    let mut response = Response::builder().header(header::CONTENT_TYPE, "application/octet-stream");
    if let Ok(metadata) = file.metadata().await {
        response = response.header(header::CONTENT_LENGTH, metadata.len());
    }
    response
        .body(Body::from_stream(read_chunks(file)))
        .unwrap_or_else(|_| not_found())
}

/// The file in chunks, never whole in memory.
fn read_chunks(
    file: tokio::fs::File,
) -> impl futures_util::Stream<Item = std::io::Result<Vec<u8>>> {
    futures_util::stream::unfold(file, |mut file| async move {
        let mut buffer = vec![0u8; 64 * 1024];
        match tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await {
            Ok(0) => None,
            Ok(read) => {
                buffer.truncate(read);
                Some((Ok(buffer), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DEADLINE: Duration = Duration::from_secs(20);

    fn held(len: u64, used: u64) -> Held {
        Held { len, used, copy: 0 }
    }

    /// To make room the cache deletes what no current offer names before what one does, each
    /// least recently used first, no more than the room it needs, and nothing when even deleting
    /// everything would not make room beside what other fetches reserved.
    /// Verifies: ADR-0026
    #[test]
    fn room_is_made_from_artifacts_no_longer_offered_first() {
        let held = HashMap::from([
            (vec![1], held(4, 1)), // offered, oldest
            (vec![2], held(4, 5)), // not offered, newer
            (vec![3], held(4, 2)), // not offered, older
            (vec![4], held(4, 9)), // offered, newest
        ]);
        let offered = HashSet::from([vec![1], vec![4]]);

        assert_eq!(victims(&held, &offered, 0, 4, 20), Some(vec![]), "it fits");
        assert_eq!(victims(&held, &offered, 0, 4, 16), Some(vec![vec![3]]));
        assert_eq!(
            victims(&held, &offered, 0, 8, 16),
            Some(vec![vec![3], vec![2]])
        );
        assert_eq!(
            victims(&held, &offered, 0, 12, 16),
            Some(vec![vec![3], vec![2], vec![1]]),
            "offered ones go only once nothing else is left, the least recently used first"
        );
        assert_eq!(
            victims(&held, &offered, 8, 12, 16),
            None,
            "reserved by other fetches"
        );
    }

    /// Every path on the Server's own download route with a SHA-256 is an artifact the Gateway
    /// caches; an absolute URL is not, whichever host it names (ADR-0033 clause 11).
    /// Verifies: ADR-0026, ADR-0033
    #[test]
    fn only_a_path_on_the_servers_route_is_cached() {
        let file = |url: &str, hash: Vec<u8>| DownloadableFile {
            download_url: url.to_string(),
            content_hash: hash,
            ..Default::default()
        };
        let path = "/api/v1/packages/otelcol/1.0.0/file?os=linux&arch=amd64";
        assert_eq!(
            Artifact::of(&file(path, vec![7; 32])),
            Some(Artifact {
                path: path.to_string(),
                hash: vec![7; 32]
            })
        );
        assert_eq!(Artifact::of(&file(path, vec![7; 20])), None, "no SHA-256");
        assert_eq!(
            Artifact::of(&file(&format!("https://fleet.example{path}"), vec![7; 32])),
            None,
            "an absolute URL naming the Server"
        );
        assert_eq!(
            Artifact::of(&file("https://mirror.example/otelcol.tar.gz", vec![7; 32])),
            None,
            "another host"
        );
        assert_eq!(
            Artifact::of(&file("/api/v1/packages", vec![7; 32])),
            None,
            "not the file route"
        );
    }

    /// The first five lines of a host in a minute are logged, the rest counted, and the count is
    /// logged with the host's first line of the next minute. Hosts are counted apart.
    /// Verifies: ADR-0026
    #[test]
    fn refusals_are_logged_five_a_minute_per_host_and_the_rest_counted() {
        let mut log = RefusalLog::default();
        let start = Instant::now();
        for _ in 0..5 {
            assert_eq!(log.note("h1", start), Note::Log);
        }
        assert_eq!(log.note("h1", start), Note::Count);
        assert_eq!(log.note("h1", start + Duration::from_secs(30)), Note::Count);
        assert_eq!(log.note("h2", start), Note::Log, "another host");
        assert_eq!(
            log.note("h1", start + Duration::from_secs(61)),
            Note::LogAfter(2)
        );
        assert_eq!(log.note("h1", start + Duration::from_secs(62)), Note::Log);
    }

    fn path(version: &str) -> String {
        format!("/api/v1/packages/otelcol/{version}/file?os=linux&arch=amd64")
    }

    /// An upstream serving each of `artifacts` (path and bytes) once `gate` lets a request
    /// through; returns its address and the count of requests per path.
    async fn upstream(
        artifacts: Vec<(String, Vec<u8>)>,
        gate: Arc<tokio::sync::Semaphore>,
    ) -> (std::net::SocketAddr, Arc<Mutex<HashMap<String, usize>>>) {
        let count: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let seen = count.clone();
        let artifacts = Arc::new(artifacts.into_iter().collect::<HashMap<_, _>>());
        let app = axum::Router::new().route(
            ROUTE,
            axum::routing::get(move |request: Request| {
                let (artifacts, gate, seen) = (artifacts.clone(), gate.clone(), seen.clone());
                async move {
                    let path = request
                        .uri()
                        .path_and_query()
                        .map_or(String::new(), |path| path.as_str().to_string());
                    *seen.lock().expect("seen").entry(path.clone()).or_default() += 1;
                    let _permit = gate.acquire().await.expect("gate");
                    match artifacts.get(&path) {
                        Some(bytes) => bytes.clone().into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        (addr, count)
    }

    /// A shutdown that never fires.
    fn shutdown() -> Shutdown {
        let (stop, shutdown) = crate::shutdown::shutdown_channel();
        std::mem::forget(stop);
        shutdown
    }

    async fn open_cache(config: Arc<ClientConfig>) -> Arc<PackageCache> {
        PackageCache::open(config, shutdown()).await.expect("cache")
    }

    fn config(server: std::net::SocketAddr, state: &Path, capacity: u64) -> Arc<ClientConfig> {
        opamp::tls::install_ring_provider();
        Arc::new(
            toml::from_str(&format!(
                "endpoint = \"ws://{server}/v1/opamp\"\nstate_dir = {:?}\n\
                 [gateway]\nlisten = \"127.0.0.1:9\"\npackage_cache_bytes = {capacity}\n",
                state.display().to_string()
            ))
            .expect("config"),
        )
    }

    fn artifact(version: &str, bytes: &[u8]) -> Artifact {
        Artifact {
            path: path(version),
            hash: Sha256::digest(bytes).to_vec(),
        }
    }

    /// A relayed offer of `artifacts` to `uid`.
    fn offer(uid: InstanceUid, artifacts: &[&Artifact]) -> ServerToAgent {
        ServerToAgent {
            instance_uid: uid.as_bytes().to_vec(),
            packages_available: Some(opamp::proto::PackagesAvailable {
                packages: artifacts
                    .iter()
                    .enumerate()
                    .map(|(n, artifact)| {
                        (
                            format!("p{n}"),
                            opamp::proto::PackageAvailable {
                                file: Some(DownloadableFile {
                                    download_url: artifact.path.clone(),
                                    content_hash: artifact.hash.clone(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
                all_packages_hash: vec![1; 32],
            }),
            ..Default::default()
        }
    }

    /// Relays an offer of `artifacts` to a new `instance_uid` bound to `h1`.
    async fn offer_to_new_agent(cache: &Arc<PackageCache>, artifacts: &[&Artifact]) -> InstanceUid {
        let uid = InstanceUid::default();
        assert!(cache.bind(uid, "h1", |_| false).await.0);
        cache.observe(uid, Some("h1".to_string()), &offer(uid, artifacts));
        uid
    }

    /// Waits until `condition` holds on the cache's state, failing the test past the deadline.
    async fn until(cache: &PackageCache, what: &str, condition: impl Fn(&Inner) -> bool) {
        tokio::time::timeout(DEADLINE, async {
            while !condition(&cache.inner()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}"));
    }

    fn fetches(count: &Mutex<HashMap<String, usize>>, version: &str) -> usize {
        count
            .lock()
            .expect("count")
            .get(&path(version))
            .copied()
            .unwrap_or(0)
    }

    /// Requests for an artifact being fetched are told to come back instead of waiting, and the
    /// upstream serves the one fetch.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn requests_while_fetching_are_answered_busy_and_the_upstream_serves_one() {
        let bytes = b"the-binary".to_vec();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (server, count) = upstream(vec![(path("1"), bytes.clone())], gate.clone()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        let one = artifact("1", &bytes);
        offer_to_new_agent(&cache, &[&one]).await;
        tokio::time::timeout(DEADLINE, async {
            while fetches(&count, "1") < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the fetch reached the upstream");
        for _ in 0..2 {
            assert!(matches!(cache.request(&one).await, Answer::Busy));
        }
        gate.add_permits(8);
        until(&cache, "held", |inner| inner.held.contains_key(&one.hash)).await;
        let Answer::File(file) = cache.request(&one).await else {
            panic!("served once held");
        };
        assert_eq!(
            std::io::read_to_string(file).expect("read").into_bytes(),
            bytes
        );
        assert_eq!(fetches(&count, "1"), 1);
    }

    /// What an earlier run left in the cache directory is gone once the Gateway opens it, the
    /// bindings' store aside, which is none of the cache's artifacts; and the directory is the
    /// owner's alone.
    /// Verifies: ADR-0026, ADR-0058
    #[tokio::test]
    async fn the_cache_is_emptied_at_start_and_owner_only() {
        let bytes = b"the-binary".to_vec();
        let (server, _) = upstream(
            vec![(path("1"), bytes.clone())],
            Arc::new(tokio::sync::Semaphore::new(8)),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let left = dir.path().join(DIR);
        std::fs::create_dir_all(left.join("staged-tree")).expect("dir");
        std::fs::write(left.join("left-over"), b"stale").expect("write");
        let names = || {
            let mut names: Vec<String> = std::fs::read_dir(&left)
                .expect("dir")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            names.sort();
            names
        };
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        assert_eq!(names(), vec![store::NAME], "emptied at start");

        let one = artifact("1", &bytes);
        let uid = offer_to_new_agent(&cache, &[&one]).await;
        until(&cache, "held", |inner| inner.held.contains_key(&one.hash)).await;
        let names = names();
        assert_eq!(names.len(), 2);
        assert!(names[0].starts_with(&hex::encode(&one.hash)), "{names:?}");
        assert_eq!(names[1], store::NAME);
        drop(cache);
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        assert!(cache.is_bound(&uid), "the store outlives the emptying");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&left)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    /// Two offered artifacts that do not fit together: a request fetches an evicted one again,
    /// but only once per relayed offer of it, so requests cannot make the two evict each other in a
    /// loop. The next relayed offer re-arms it.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn an_evicted_offered_artifact_is_fetched_again_on_a_request_once_per_offer() {
        let (a_bytes, b_bytes) = (vec![1u8; 10], vec![2u8; 10]);
        let (server, count) = upstream(
            vec![(path("1"), a_bytes.clone()), (path("2"), b_bytes.clone())],
            Arc::new(tokio::sync::Semaphore::new(64)),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config(server, dir.path(), 16)).await;
        let (a, b) = (artifact("1", &a_bytes), artifact("2", &b_bytes));
        let first = offer_to_new_agent(&cache, &[&a]).await;
        until(&cache, "a held", |inner| inner.held.contains_key(&a.hash)).await;
        offer_to_new_agent(&cache, &[&b]).await;
        until(&cache, "b held, a evicted", |inner| {
            inner.held.contains_key(&b.hash) && !inner.held.contains_key(&a.hash)
        })
        .await;

        assert!(matches!(cache.request(&a).await, Answer::Busy), "refetched");
        until(&cache, "a held again", |inner| {
            inner.held.contains_key(&a.hash)
        })
        .await;
        assert!(matches!(cache.request(&b).await, Answer::Busy), "refetched");
        until(&cache, "b held again", |inner| {
            inner.held.contains_key(&b.hash)
        })
        .await;
        assert!(
            matches!(cache.request(&a).await, Answer::Nothing),
            "no second refetch under the same offer"
        );
        assert_eq!((fetches(&count, "1"), fetches(&count, "2")), (2, 2));

        cache.observe(first, Some("h1".to_string()), &offer(first, &[&a]));
        until(&cache, "a held after the next offer", |inner| {
            inner.held.contains_key(&a.hash)
        })
        .await;
        assert_eq!(fetches(&count, "1"), 3);
    }

    /// A file whose deletion fails stays counted, so the room it takes is not handed out, and is
    /// deleted on a later attempt — without touching a newer copy of the same artifact.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_file_whose_deletion_fails_stays_counted_until_deleted() {
        static FAILURES: AtomicUsize = AtomicUsize::new(1);
        fn flaky(path: &Path) -> bool {
            if FAILURES
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return false;
            }
            remove_file(path)
        }
        let (a_bytes, b_bytes) = (vec![1u8; 10], vec![2u8; 8]);
        let (server, _) = upstream(
            vec![(path("1"), a_bytes.clone()), (path("2"), b_bytes.clone())],
            Arc::new(tokio::sync::Semaphore::new(64)),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = PackageCache::open_with(
            config(server, dir.path(), 16),
            shutdown(),
            Knobs {
                remove: flaky,
                ..Knobs::default()
            },
        )
        .await
        .expect("cache");
        let (a, b) = (artifact("1", &a_bytes), artifact("2", &b_bytes));
        offer_to_new_agent(&cache, &[&a]).await;
        until(&cache, "a held", |inner| inner.held.contains_key(&a.hash)).await;
        let a_file = cache.file(&a.hash, cache.inner().held[&a.hash].copy);

        // b needs a's room; a's deletion fails, so a stays counted and b gets no room.
        offer_to_new_agent(&cache, &[&b]).await;
        until(&cache, "b settled", |inner| inner.fetching.is_empty()).await;
        {
            let inner = cache.inner();
            assert_eq!(inner.doomed.get(&a_file), Some(&10), "still counted");
            assert!(a_file.exists());
            assert!(inner.failed.contains(&b.hash), "no room for b");
            assert!(inner.bytes_counted() <= 16, "{}", inner.bytes_counted());
        }

        // A newer copy of a is stored; the next deletion removes the old copy only.
        offer_to_new_agent(&cache, &[&a]).await;
        until(&cache, "a held again", |inner| {
            inner.held.contains_key(&a.hash)
        })
        .await;
        let newer = cache.file(&a.hash, cache.inner().held[&a.hash].copy);
        assert_ne!(newer, a_file);
        assert!(
            !a_file.exists(),
            "the old copy is deleted on the next attempt"
        );
        assert!(newer.exists(), "the newer copy stays");
        assert!(cache.inner().doomed.is_empty());
    }

    /// A held artifact whose file disappeared is not served, and is forgotten; with no refetch left
    /// under the current offer the request is answered `Nothing`.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_held_artifact_whose_file_disappeared_is_forgotten() {
        let bytes = b"the-binary".to_vec();
        let (server, _) = upstream(
            vec![(path("1"), bytes.clone())],
            Arc::new(tokio::sync::Semaphore::new(8)),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        let one = artifact("1", &bytes);
        offer_to_new_agent(&cache, &[&one]).await;
        until(&cache, "held", |inner| inner.held.contains_key(&one.hash)).await;
        let file = cache.file(&one.hash, cache.inner().held[&one.hash].copy);
        std::fs::remove_file(file).expect("remove");
        cache.inner().armed.clear();
        assert!(matches!(cache.request(&one).await, Answer::Nothing));
        assert!(!cache.inner().held.contains_key(&one.hash));
    }

    /// An offered artifact evicted between the lookup and the open — its file gone — is decided
    /// again: the refetch the current offer allows starts, and the request is told to come back.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn an_artifact_evicted_between_lookup_and_open_is_fetched_again() {
        let bytes = b"the-binary".to_vec();
        let (server, count) = upstream(
            vec![(path("1"), bytes.clone())],
            Arc::new(tokio::sync::Semaphore::new(8)),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        let one = artifact("1", &bytes);
        offer_to_new_agent(&cache, &[&one]).await;
        until(&cache, "held", |inner| inner.held.contains_key(&one.hash)).await;
        let file = cache.file(&one.hash, cache.inner().held[&one.hash].copy);
        std::fs::remove_file(file).expect("remove");
        assert!(matches!(cache.request(&one).await, Answer::Busy));
        until(&cache, "held again", |inner| {
            inner.held.contains_key(&one.hash) && inner.fetching.is_empty()
        })
        .await;
        assert!(matches!(cache.request(&one).await, Answer::File(_)));
        assert_eq!(fetches(&count, "1"), 2);
    }

    /// One host reporting fresh `instance_uid`s binds no more than its share, and hosts that fill
    /// the Gateway's total cannot free another host's binding to claim it: at the total a host
    /// without an idle binding of its own binds nothing and every binding stays, while a host with
    /// one gives it up for its new Agent, whose offer is then recorded.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn at_the_total_a_new_binding_never_takes_another_hosts_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config: Arc<ClientConfig> = Arc::new(
            toml::from_str(&format!(
                "endpoint = \"ws://127.0.0.1:9/v1/opamp\"\nstate_dir = {:?}\n\
                 [gateway]\nlisten = \"127.0.0.1:9\"\nmax_carried_agents = 3\n",
                dir.path().display().to_string()
            ))
            .expect("config"),
        );
        let cache = PackageCache::open_with(
            config,
            shutdown(),
            Knobs {
                max_bindings: 4,
                ..Knobs::default()
            },
        )
        .await
        .expect("cache");
        let flood: Vec<InstanceUid> = (0..5).map(|_| InstanceUid::default()).collect();
        for uid in &flood {
            cache.bind(*uid, "flood", |_| false).await;
        }
        assert_eq!(
            cache.inner().bindings.count_of("flood"),
            3,
            "its share and no more"
        );
        let other = InstanceUid::default();
        assert!(cache.bind(other, "other", |_| false).await.0);
        assert_eq!(cache.inner().bindings.len(), 4, "the global cap");

        let shut_out = InstanceUid::default();
        let (bound, evicted) = cache.bind(shut_out, "new-host", |_| false).await;
        assert!(
            !bound && evicted.is_empty(),
            "no other host's binding made room"
        );
        let held = cache.inner().bindings.snapshot();
        assert_eq!(
            held.len(),
            2 + 4,
            "two hosts' ends, four bindings: nothing of the new host"
        );

        let real = InstanceUid::default();
        let (bound, evicted) = cache.bind(real, "other", |_| false).await;
        assert!(bound);
        assert_eq!(evicted, vec![other], "its own idle binding made room");
        assert_eq!(cache.inner().bindings.count_of("flood"), 3);
        let one = artifact("1", b"x");
        cache.inner().refused.insert(one.hash.clone());
        cache.observe(real, Some("other".to_string()), &offer(real, &[&one]));
        assert_eq!(cache.offered_to("other", &one.path), Some(one));
    }

    /// Past its grace a fetch must keep an average of 64 KiB/s since the grace ended.
    /// Verifies: ADR-0026
    #[test]
    fn a_fetch_below_the_pace_floor_is_cut() {
        let kib64 = 64 * 1024;
        assert!(!below_pace(0, Duration::from_secs(59)), "within the grace");
        assert!(!below_pace(0, Duration::from_secs(60)));
        assert!(below_pace(10 * kib64 - 1, Duration::from_secs(70)));
        assert!(!below_pace(10 * kib64, Duration::from_secs(70)));
    }

    /// A fetch the Server defers with `503` and `Retry-After` gives its slot back while it waits,
    /// asks again, and completes.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_deferred_fetch_gives_its_slot_back_while_it_waits() {
        let bytes = b"the-binary".to_vec();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let served = bytes.clone();
        let app = axum::Router::new().route(
            ROUTE,
            axum::routing::get(move || {
                let (seen, served) = (seen.clone(), served.clone());
                async move {
                    if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            [(header::RETRY_AFTER, "1")],
                        )
                            .into_response()
                    } else {
                        served.into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = PackageCache::open_with(
            config(server, dir.path(), 1 << 20),
            shutdown(),
            Knobs {
                patience: Patience {
                    per_wait: Duration::from_secs(5),
                    total: Duration::from_secs(20),
                },
                ..Knobs::default()
            },
        )
        .await
        .expect("cache");
        let one = artifact("1", &bytes);
        offer_to_new_agent(&cache, &[&one]).await;
        tokio::time::timeout(DEADLINE, async {
            loop {
                let waiting = count.load(Ordering::SeqCst) == 1
                    && cache.slots.available_permits() == CONCURRENT_FETCHES
                    && cache.inner().fetching.contains(&one.hash);
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the fetch waits without its slot");
        until(&cache, "held", |inner| inner.held.contains_key(&one.hash)).await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    /// A shutdown ends a fetch that waits out the Server's `Retry-After`: nothing is left marked as
    /// being fetched.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_shutdown_ends_a_fetch_that_waits_out_retry_after() {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let app = axum::Router::new().route(
            ROUTE,
            axum::routing::get(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        [(header::RETRY_AFTER, "30")],
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let dir = tempfile::tempdir().expect("tempdir");
        let (stop, shutdown) = crate::shutdown::shutdown_channel();
        let cache = PackageCache::open(config(server, dir.path(), 1 << 20), shutdown)
            .await
            .expect("cache");
        let one = artifact("1", b"x");
        offer_to_new_agent(&cache, &[&one]).await;
        tokio::time::timeout(DEADLINE, async {
            while count.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("asked");
        stop.send(true).expect("stop");
        until(&cache, "the fetch ended", |inner| inner.fetching.is_empty()).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// A fetch cannot reserve room that other fetches hold.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_fetch_cannot_reserve_room_other_fetches_hold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config("127.0.0.1:9".parse().expect("addr"), dir.path(), 16)).await;
        cache.reserve(&[1], 10).await.expect("room");
        let err = cache
            .reserve(&[2], 10)
            .await
            .expect_err("held by the first");
        assert!(err.contains("no room"), "{err}");
        assert_eq!(cache.inner().reserved.len(), 1);
    }

    /// At most four fetches run at once; a fifth waits for a slot.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn no_more_than_four_fetches_run_at_once() {
        let versions = ["1", "2", "3", "4", "5"];
        let artifacts: Vec<(String, Vec<u8>)> = versions
            .iter()
            .map(|version| (path(version), version.as_bytes().to_vec()))
            .collect();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (server, count) = upstream(artifacts.clone(), gate.clone()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        let offered: Vec<Artifact> = versions
            .iter()
            .map(|version| artifact(version, version.as_bytes()))
            .collect();
        offer_to_new_agent(&cache, &offered.iter().collect::<Vec<_>>()).await;
        let total = || count.lock().expect("count").values().sum::<usize>();
        tokio::time::timeout(DEADLINE, async {
            while total() < 4 || cache.slots.available_permits() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("four fetches reached the upstream");
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        assert_eq!(total(), 4, "the fifth waits for a slot");
        gate.add_permits(16);
        until(&cache, "all held", |inner| inner.held.len() == 5).await;
        assert_eq!(total(), 5);
    }

    /// An offer relayed over a certificate that names no host is not recorded and starts no fetch,
    /// although its Agent is bound under the host derived for it: that host binds for routing only.
    /// Verifies: ADR-0039
    #[tokio::test]
    async fn an_offer_over_a_certificate_naming_no_host_records_nothing_and_fetches_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config("127.0.0.1:9".parse().expect("addr"), dir.path(), 16)).await;
        let uid = InstanceUid::default();
        let one = artifact("1", b"x");
        assert!(cache.bind(uid, "derived-host", |_| false).await.0);
        cache.observe(uid, None, &offer(uid, &[&one]));
        let inner = cache.inner();
        assert_eq!(inner.bindings.host_of(&uid), Some("derived-host"));
        assert!(inner.offers.is_empty() && inner.fetching.is_empty());
    }

    /// A fetch whose task ends without settling leaves no entry and no reservation behind.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn an_unfinished_fetch_leaves_no_entry_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = open_cache(config("127.0.0.1:9".parse().expect("addr"), dir.path(), 16)).await;
        {
            let mut inner = cache.inner();
            inner.fetching.insert(vec![1]);
            inner.reserved.insert(vec![1], 8);
        }
        drop(Landing {
            cache: cache.clone(),
            hash: vec![1],
            settled: false,
        });
        let inner = cache.inner();
        assert!(inner.fetching.is_empty() && inner.reserved.is_empty());
    }

    /// A cache in `dir` whose hosts bind at most `per_host` `instance_uid`s.
    async fn cache_binding(dir: &Path, per_host: usize) -> Arc<PackageCache> {
        let config: Arc<ClientConfig> = Arc::new(
            toml::from_str(&format!(
                "endpoint = \"ws://127.0.0.1:9/v1/opamp\"\nstate_dir = {:?}\n\
                 [gateway]\nlisten = \"127.0.0.1:9\"\nmax_carried_agents = {per_host}\n",
                dir.display().to_string()
            ))
            .expect("config"),
        );
        open_cache(config).await
    }

    /// What the store under `dir` reads back to.
    fn stored(dir: &Path) -> Vec<Change> {
        let held = HeldDir::open(&dir.join(DIR)).expect("held");
        Bindings::replay(store::load(&held).expect("load"))
            .expect("replay")
            .snapshot()
    }

    /// Waits for the store's writer to finish what it is writing: a rewrite runs after the report
    /// that grew the store is answered.
    fn settled(cache: &PackageCache) {
        drop(
            cache
                .journal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    /// How many lines the store under `dir` holds, its first line not counted.
    fn store_lines(dir: &Path) -> usize {
        std::fs::read_to_string(dir.join(DIR).join(store::NAME))
            .expect("read")
            .lines()
            .count()
            - 1
    }

    /// The store is rewritten whole at start, to one line per binding and per host, and again once
    /// it has grown to twice that; either way it reads back to the bindings the Gateway holds.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn the_store_is_compacted_at_start_and_at_twice_its_live_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        for _ in 0..3 {
            assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        }
        assert_eq!(store_lines(dir.path()), 4, "one end, three bindings");
        // Each new binding past the host's share gives up its oldest: a removal and a binding.
        assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        assert_eq!(store_lines(dir.path()), 6);
        assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        settled(&cache);
        assert_eq!(store_lines(dir.path()), 4, "eight lines for four live ones");
        assert_eq!(stored(dir.path()), cache.inner().bindings.snapshot());

        assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        let held = cache.inner().bindings.snapshot();
        drop(cache);
        let cache = cache_binding(dir.path(), 3).await;
        assert_eq!(store_lines(dir.path()), 4, "rewritten at start");
        assert_eq!(stored(dir.path()), held);
        assert_eq!(cache.inner().bindings.snapshot(), held);
    }

    /// The order in which bindings were reported is written, and outlasts a restart: past its
    /// share a host still gives up its least recently reported binding.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn the_order_of_reports_outlasts_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 2).await;
        let [first, second] = [(); 2].map(|()| InstanceUid::default());
        cache.bind(first, "h1", |_| false).await;
        cache.bind(second, "h1", |_| false).await;
        cache.bind(first, "h1", |_| false).await;
        cache.write_reports().await;
        drop(cache);

        let cache = cache_binding(dir.path(), 2).await;
        let (bound, evicted) = cache.bind(InstanceUid::default(), "h1", |_| false).await;
        assert!(bound);
        assert_eq!(
            evicted,
            vec![second],
            "the least recently reported gave way"
        );
    }

    /// While the store cannot be read, every download is answered `503`, an offered one too, and
    /// the store is not rewritten.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn an_unreadable_store_answers_every_download_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join(DIR).join(store::NAME);
        std::fs::create_dir_all(store.parent().expect("dir")).expect("dir");
        HeldDir::open(&dir.path().join(DIR))
            .expect("held")
            .write(store::NAME, b"opamp-fleet-gateway-bindings 9\n", 0o600)
            .expect("write");
        let cache = open_cache(config("127.0.0.1:9".parse().expect("addr"), dir.path(), 16)).await;
        assert!(cache
            .unreadable()
            .is_some_and(|why| why.contains("version 9")));
        let revocations = RevocationList::new(Duration::from_secs(300));
        revocations.replace(HashSet::new(), None);
        let downloads = Arc::new(Downloads {
            cache,
            revocations,
            members: crate::gateway::Members::default(),
        });
        let mut request = Request::new(Body::empty());
        *request.uri_mut() = path("1").parse().expect("uri");
        let response = serve(axum::extract::State(downloads), request).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            std::fs::read(&store).expect("read"),
            b"opamp-fleet-gateway-bindings 9\n"
        );
    }

    /// A store that fails an append is rewritten whole, and the binding is made: what the failed
    /// append wrote is cut back, and the store reads back to the bindings held.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn a_failed_append_falls_back_to_a_rewrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        cache.inject(|faults| faults.append = true);
        let uid = InstanceUid::default();
        assert!(
            cache.bind(uid, "h1", |_| false).await.0,
            "bound by the rewrite"
        );
        assert_eq!(stored(dir.path()), cache.inner().bindings.snapshot());
        assert_eq!(store_lines(dir.path()), 3);
    }

    /// A rewrite that fails once its new file is in place makes nothing: the report is refused,
    /// and nothing is appended afterwards to a file that may no longer be the store; the next
    /// report's binding is written by a rewrite and outlasts a restart.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn a_rewrite_that_fails_after_its_rename_binds_nothing_and_appends_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        cache.inject(|faults| {
            faults.append = true;
            faults.after_rename = true;
        });
        let refused = InstanceUid::default();
        assert!(!cache.bind(refused, "h1", |_| false).await.0, "not written");
        let next = InstanceUid::default();
        assert!(cache.bind(next, "h1", |_| false).await.0);
        drop(cache);
        let cache = cache_binding(dir.path(), 3).await;
        assert!(cache.is_bound(&next), "the binding outlasts a restart");
        assert!(!cache.is_bound(&refused));
    }

    /// A store that cannot be rewritten at start is not relied on: the Gateway carries no
    /// downstream Agent, as for one it cannot read.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn a_store_that_cannot_be_rewritten_at_start_carries_no_agent() {
        fn full(_: HeldDir, _: &[Change]) -> std::io::Result<Journal> {
            Err(std::io::Error::other("no space left"))
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = PackageCache::open_with(
            config("127.0.0.1:9".parse().expect("addr"), dir.path(), 16),
            shutdown(),
            Knobs {
                create_journal: full,
                ..Knobs::default()
            },
        )
        .await
        .expect("the Gateway starts");
        assert!(cache
            .unreadable()
            .is_some_and(|why| why.contains("cannot rewrite")));
    }

    /// An offer relayed while an `instance_uid`'s binding is still being written is not recorded,
    /// and a binding the store could not take leaves no offer behind; once the store holds the
    /// binding, its offers are recorded.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn an_offer_is_recorded_only_for_a_binding_the_store_holds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        let one = artifact("1", b"x");
        cache.inner().refused.insert(one.hash.clone());
        let uid = InstanceUid::default();
        let end = End {
            not_after: i64::MAX,
            issuer: "ab".repeat(32),
            serial: "1".to_string(),
        };
        let (begun, _) = cache.begin_bind(uid, "h1", &end, |_| false);
        assert!(matches!(begun, Begun::Writing(_)));
        cache.observe(uid, Some("h1".to_string()), &offer(uid, &[&one]));
        assert_eq!(
            cache.offered_to("h1", &one.path),
            None,
            "still being written"
        );
        assert!(!cache.finish_bind(uid, "h1", false));
        assert_eq!(cache.offered_to("h1", &one.path), None);
        assert!(cache.inner().offers.is_empty());

        assert!(cache.bind(uid, "h1", |_| false).await.0);
        cache.observe(uid, Some("h1".to_string()), &offer(uid, &[&one]));
        assert_eq!(cache.offered_to("h1", &one.path), Some(one));
    }

    /// A report under a renewed certificate is forwarded only once the store holds the host's
    /// moved end; when the store cannot take it the report is refused and the end the store holds
    /// stands, also in memory.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn a_moved_end_the_store_cannot_take_is_undone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        let later = now() + 3600;
        let uid = InstanceUid::default();
        assert!(cache.bind_until(uid, "h1", later, |_| false).await.0);
        cache.refuse_writes();
        assert!(
            !cache.bind_until(uid, "h1", later + 3600, |_| false).await.0,
            "forwarded before its end was written"
        );
        let ends = |changes: Vec<Change>| -> Vec<i64> {
            changes
                .into_iter()
                .filter_map(|change| match change {
                    Change::Ends(_, end) => Some(end.not_after),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            ends(cache.inner().bindings.snapshot()),
            vec![later],
            "undone"
        );
        assert_eq!(ends(stored(dir.path())), vec![later]);
    }

    /// A Gateway restarted in the same process takes its store over from the cache it replaces,
    /// which binds nothing more: nothing it writes can land beside or over the store.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn a_cache_that_replaces_another_alone_writes_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = cache_binding(dir.path(), 3).await;
        let first = InstanceUid::default();
        assert!(old.bind(first, "h1", |_| false).await.0);
        let new = cache_binding(dir.path(), 3).await;
        assert!(new.is_bound(&first));
        let before = std::fs::read(dir.path().join(DIR).join(store::NAME)).expect("read");
        let refused = InstanceUid::default();
        assert!(
            !old.bind(refused, "h1", |_| false).await.0,
            "the replaced cache binds nothing"
        );
        settled(&old);
        assert_eq!(
            std::fs::read(dir.path().join(DIR).join(store::NAME)).expect("read"),
            before,
            "and writes nothing to the store"
        );
        let second = InstanceUid::default();
        assert!(new.bind(second, "h1", |_| false).await.0);
        settled(&new);
        assert_eq!(stored(dir.path()), new.inner().bindings.snapshot());
        drop((old, new));
        let again = cache_binding(dir.path(), 3).await;
        assert!(again.is_bound(&first) && again.is_bound(&second));
    }

    /// A host's report refreshes its own binding's order, and another host's report for it does
    /// not: neither its order nor the reports the store is told of.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn only_the_bound_hosts_report_orders_its_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 2).await;
        let [first, second] = [(); 2].map(|()| InstanceUid::default());
        cache.bind(first, "h1", |_| false).await;
        cache.bind(second, "h1", |_| false).await;
        assert!(!cache.bind(first, "h2", |_| false).await.0);
        assert!(
            cache.inner().bindings.reports().is_empty(),
            "nothing reported"
        );
        let (bound, evicted) = cache.bind(InstanceUid::default(), "h1", |_| false).await;
        assert!(bound);
        assert_eq!(evicted, vec![first], "still the least recently reported");
    }

    /// The lines of reports, which grow with the Agents carried, do not count toward the rewrite
    /// at twice the live lines; the store is rewritten once they pass their own bound.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn reports_are_rewritten_by_a_bound_of_their_own() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        let uid = InstanceUid::default();
        assert!(cache.bind(uid, "h1", |_| false).await.0);
        let live = 2;
        for written in 1..=REPORT_LINES_PER_LIVE * live {
            assert!(cache.bind(uid, "h1", |_| false).await.0);
            cache.write_reports().await;
            settled(&cache);
            assert_eq!(store_lines(dir.path()), live + written, "no rewrite yet");
        }
        assert!(cache.bind(uid, "h1", |_| false).await.0);
        cache.write_reports().await;
        settled(&cache);
        assert_eq!(store_lines(dir.path()), live, "rewritten past their bound");
    }

    /// The task that writes a cache's store ends once the cache is gone, so a Gateway restarted
    /// in the same process leaves none behind.
    /// Verifies: ADR-0058
    #[tokio::test]
    async fn the_stores_writer_ends_with_its_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_binding(dir.path(), 3).await;
        assert!(cache.bind(InstanceUid::default(), "h1", |_| false).await.0);
        let wake = Arc::downgrade(&cache.wake);
        drop(cache);
        tokio::time::timeout(DEADLINE, async {
            while wake.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the writer ended");
    }
}
