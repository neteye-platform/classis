//! The Gateway's package cache (ADR-0026 clauses 42 to 48): each uploaded artifact the Gateway
//! relays an offer of is fetched from the Server once, with the Gateway's own certificate, and
//! passed on only to a downstream host whose Agent it relayed that offer to.
//!
//! What is kept here:
//! - the **bindings**: each `instance_uid` to the host of the first report for it since the
//!   Gateway started, as the Server binds on first report (ADR-0021 clause 7);
//! - the **offers**: per `instance_uid`, the Server-hosted artifacts its last recorded
//!   `packages_available` named, indexed by host;
//! - the **held** artifacts, one file per stored copy under `<state_dir>/gateway-packages`, verified
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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use opamp::proto::{DownloadableFile, ServerToAgent};
use opamp::server::listen::PeerCertificate;
use opamp::uid::InstanceUid;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::ClientConfig;
use crate::gateway::policy::{Bindings, Bound, Limits};
use crate::gateway::revocations::{RevocationList, Verdict};
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

#[derive(Default)]
struct Inner {
    /// Each `instance_uid` to the host of its first report (ADR-0026 clause 45).
    bindings: Bindings,
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
}

impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            remove: remove_file,
            patience: Patience::default(),
            max_bindings: MAX_BINDINGS,
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
    inner: Mutex<Inner>,
}

/// Clears a fetch's entry and its reservation when its task ends without settling — a panic
/// included — so that the artifact is not left marked as being fetched by nobody.
struct Landing {
    cache: Arc<PackageCache>,
    hash: Vec<u8>,
    settled: bool,
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

impl PackageCache {
    /// The cache of the Gateway `config` arms, its directory emptied (ADR-0026 clause 47). The
    /// directory itself is created by the first fetch.
    ///
    /// # Errors
    /// Returns an error when a directory left by an earlier run cannot be emptied.
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
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot empty {}: {e}", dir.display())),
        }
        Ok(Arc::new(PackageCache {
            limit: capacity.min(config.max_artifact_size_bytes),
            capacity,
            dir,
            config,
            slots: tokio::sync::Semaphore::new(CONCURRENT_FETCHES),
            per_host_bindings,
            shutdown,
            knobs,
            inner: Mutex::new(Inner::default()),
        }))
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
    /// refreshes when it was last reported (ADR-0039 clause 6). `host` is the one a downstream
    /// certificate speaks as ([`speaker_of`]). A host binds at most `max_carried_agents`; at the
    /// global cap the least recently reported binding whose `instance_uid` has neither a route
    /// (`routed`) nor a current offer makes room, and without one nothing is bound.
    ///
    /// Whether `uid` is now bound to `host`: only then is its report forwarded and its reply
    /// routed back (ADR-0039 clause 5). A report for an `instance_uid` bound to another host, or
    /// one that could not be bound, is logged and answered `false`.
    pub fn bind(
        &self,
        uid: InstanceUid,
        host: &str,
        routed: impl Fn(&InstanceUid) -> bool,
    ) -> bool {
        let limits = Limits {
            per_host: self.per_host_bindings,
            total: self.knobs.max_bindings,
        };
        let mut guard = self.inner();
        let inner = &mut *guard;
        let offers = &inner.offers;
        let bound = inner.bindings.bind(uid, host, limits, |uid| {
            !routed(uid) && !offers.contains_key(uid)
        });
        if let Bound::Refused(why) = bound {
            if inner.refusals.note(host, Instant::now()) != Note::Count {
                warn!(agent = %uid, %host, "not forwarding a report: not binding its instance_uid: {why}");
            }
            return false;
        }
        match inner.bindings.host_of(&uid) {
            Some(bound) if bound == host => true,
            bound => {
                let bound = bound.unwrap_or("none").to_string();
                if inner.refusals.note(host, Instant::now()) != Note::Count {
                    warn!(
                        agent = %uid, %host, %bound,
                        "not forwarding a report for an instance_uid bound to another host"
                    );
                }
                false
            }
        }
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
            let bound = inner.bindings.host_of(&uid).map(str::to_string);
            if bound.as_deref() != Some(host.as_str()) {
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
    fn offered_to(&self, host: &str, path: &str) -> Option<Artifact> {
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

async fn serve(
    axum::extract::State(downloads): axum::extract::State<Arc<Downloads>>,
    request: Request,
) -> Response {
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
    fn offer_to_new_agent(cache: &Arc<PackageCache>, artifacts: &[&Artifact]) -> InstanceUid {
        let uid = InstanceUid::default();
        assert!(cache.bind(uid, "h1", |_| false));
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
        offer_to_new_agent(&cache, &[&one]);
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

    /// What an earlier run left in the cache directory is gone once the Gateway opens it, and the
    /// directory the first fetch creates is the owner's alone.
    /// Verifies: ADR-0026
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
        std::fs::create_dir_all(&left).expect("dir");
        std::fs::write(left.join("left-over"), b"stale").expect("write");
        let cache = open_cache(config(server, dir.path(), 1 << 20)).await;
        assert!(!left.exists(), "emptied at start");

        let one = artifact("1", &bytes);
        offer_to_new_agent(&cache, &[&one]);
        until(&cache, "held", |inner| inner.held.contains_key(&one.hash)).await;
        let names: Vec<String> = std::fs::read_dir(&left)
            .expect("dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].starts_with(&hex::encode(&one.hash)), "{names:?}");
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
        let first = offer_to_new_agent(&cache, &[&a]);
        until(&cache, "a held", |inner| inner.held.contains_key(&a.hash)).await;
        offer_to_new_agent(&cache, &[&b]);
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
        offer_to_new_agent(&cache, &[&a]);
        until(&cache, "a held", |inner| inner.held.contains_key(&a.hash)).await;
        let a_file = cache.file(&a.hash, cache.inner().held[&a.hash].copy);

        // b needs a's room; a's deletion fails, so a stays counted and b gets no room.
        offer_to_new_agent(&cache, &[&b]);
        until(&cache, "b settled", |inner| inner.fetching.is_empty()).await;
        {
            let inner = cache.inner();
            assert_eq!(inner.doomed.get(&a_file), Some(&10), "still counted");
            assert!(a_file.exists());
            assert!(inner.failed.contains(&b.hash), "no room for b");
            assert!(inner.bytes_counted() <= 16, "{}", inner.bytes_counted());
        }

        // A newer copy of a is stored; the next deletion removes the old copy only.
        offer_to_new_agent(&cache, &[&a]);
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
        offer_to_new_agent(&cache, &[&one]);
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
        offer_to_new_agent(&cache, &[&one]);
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

    /// One host reporting fresh `instance_uid`s binds no more than its share, and at the global cap
    /// an idle binding makes room: another host's new Agent is still bound and its offer recorded.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_host_flooding_instance_uids_cannot_keep_another_hosts_agent_from_being_bound() {
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
            cache.bind(*uid, "flood", |_| false);
        }
        assert_eq!(
            cache.inner().bindings.count_of("flood"),
            3,
            "its share and no more"
        );
        let other = InstanceUid::default();
        cache.bind(other, "other", |_| false);
        assert_eq!(cache.inner().bindings.len(), 4, "the global cap");

        let real = InstanceUid::default();
        cache.bind(real, "real", |uid| *uid == other);
        {
            let inner = cache.inner();
            assert_eq!(
                inner.bindings.host_of(&real),
                Some("real"),
                "an idle binding made room"
            );
            assert!(
                inner.bindings.host_of(&other).is_some(),
                "a routed one did not"
            );
            assert!(
                inner.bindings.host_of(&flood[0]).is_none(),
                "the least recently reported did"
            );
        }
        let one = artifact("1", b"x");
        cache.inner().refused.insert(one.hash.clone());
        cache.observe(real, Some("real".to_string()), &offer(real, &[&one]));
        assert_eq!(cache.offered_to("real", &one.path), Some(one));
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
        offer_to_new_agent(&cache, &[&one]);
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
        offer_to_new_agent(&cache, &[&one]);
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
        offer_to_new_agent(&cache, &offered.iter().collect::<Vec<_>>());
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
        assert!(cache.bind(uid, "derived-host", |_| false));
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
}
