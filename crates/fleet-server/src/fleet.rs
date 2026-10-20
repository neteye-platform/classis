//! In-memory fleet state and the OpAMP control loop, keyed by Instance UID — never by the
//! connection that carried a message (ADR-0015).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opamp::attributes;
use opamp::proto::{
    any_value, AgentConfigMap, AgentConfigObject, AgentDescription, AgentIdentification,
    AgentRemoteConfig, AgentToServer, AgentToServerFlags, AvailableComponents, ComponentHealth,
    ConnectionSettingsOffers, ConnectionSettingsStatus, KeyValue, OpAmpConnectionSettings,
    PackageStatuses, PackagesAvailable, RemoteConfigStatus, RemoteConfigStatuses,
    ServerCapabilities, ServerErrorResponse, ServerErrorResponseType, ServerToAgent,
    ServerToAgentFlags, TelemetryConnectionSettings, TlsCertificate,
};
use opamp::uid::InstanceUid;
use prost::Message as _;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::agent_store::{AgentStore, PersistedAgent, Pin};
use crate::audit::{Audit, Entry};
use crate::configs::{ConfigBackend, ConfigStore, Configuration, DesiredConfig, Revision};
use crate::deployments::{self, deployment_for, Deployment, DeploymentError, DeploymentStore};
use crate::enrolment::{DecisionError, Enrolment};
use crate::labels::{LabelError, Sources};
use crate::packages::{InstalledVersions, PackageId, PackageStore, Platform, SignatureState};
use crate::revocation::{CertId, Facts, Presented, Revocations, Signed, SpeaksFor, SubjectValues};

/// The package upload limit in force when nothing configures one — roomy, because a real agent
/// binary is (see `server.toml`, `max_package_size_bytes`).
pub const DEFAULT_MAX_PACKAGE_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB

/// The whole-store limit in force when nothing configures one: sixteen per-artifact budgets, room
/// for a real package set across platforms with rollback copies, while still bounding the disk a
/// caller can fill by uploading under many names (see `server.toml`, `max_total_package_bytes`).
pub const DEFAULT_MAX_TOTAL_PACKAGE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB

/// Three times the Baseline's own default heartbeat of 30 seconds (ADR-0024).
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(90);

/// The most Agent records the fleet holds when nothing configures a ceiling (see `server.toml`,
/// `max_agents`). Generous enough that a real fleet never meets it, low enough that the in-memory
/// map and the per-Agent files it mirrors to disk stay bounded when an unauthenticated endpoint is
/// flooded with fresh, self-asserted UIDs (ADR-0021).
pub const DEFAULT_MAX_AGENTS: usize = 100_000;

/// The Capability Set this Server declares (see docs/CONFORMANCE.md).
pub const SERVER_CAPABILITIES: u64 = ServerCapabilities::AcceptsStatus as u64
    | ServerCapabilities::OffersRemoteConfig as u64
    | ServerCapabilities::AcceptsEffectiveConfig as u64;

/// Identifies one WebSocket connection for the duplicate detection the Baseline asks of the
/// Server. Never a routing key — Agents are routed by `instance_uid` alone (ADR-0015); this only
/// answers "is this identity already alive on *another* connection?".
pub type ConnId = u64;

/// Which transport a report arrived on. Recorded for the operator; it never keys any state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    WebSocket,
}

impl Transport {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::WebSocket => "websocket",
        }
    }

    /// The inverse of [`as_str`](Self::as_str). Anything but `websocket` reads as HTTP: the
    /// transport is recorded for the operator and keys nothing, so an unknown spelling is not
    /// worth refusing a stored record over.
    pub(crate) fn parse(text: &str) -> Self {
        match text {
            "websocket" => Transport::WebSocket,
            _ => Transport::Http,
        }
    }
}

/// Everything the Server knows about one Agent.
pub struct AgentRecord {
    pub sequence_num: u64,
    pub capabilities: u64,
    pub description: Option<AgentDescription>,
    pub health: Option<ComponentHealth>,
    pub effective_config: Option<String>,
    pub remote_config_status: Option<RemoteConfigStatus>,
    pub transport: Transport,
    pub connected: bool,
    pub last_seen_ms: u64,
    /// An operator-requested restart not yet delivered. Lives on the record, not a connection,
    /// so it reaches the Agent on its next exchange whichever transport carries it.
    pub restart_pending: bool,
    /// The Agent's available components — hash-only until the full map was demanded and arrived.
    pub available_components: Option<AvailableComponents>,
    /// The outcome of the last connection-settings offer this Agent reported (ADR-0014); its
    /// hash is what gates re-offering.
    pub connection_settings_status: Option<ConnectionSettingsStatus>,
    /// The package statuses this Agent last reported (ADR-0026); the
    /// `server_provided_all_packages_hash` inside is what gates re-offering packages.
    pub package_statuses: Option<PackageStatuses>,
    /// The WebSocket connection currently carrying this Agent; `None` for plain HTTP, whose
    /// polling is stateless. Only the owning connection may mark the Agent disconnected, and a
    /// report from a *different* live connection is the duplicate the Baseline wants detected.
    pub owner: Option<ConnId>,
    /// The operator's labels for this Agent (ADR-0024), part of its persisted record (ADR-0035
    /// clause 6): they follow a re-key and leave with a forget.
    pub labels: BTreeMap<String, String>,
    /// The Host this Agent last arrived over (ADR-0035 clause 2): its own on a direct connection,
    /// the Gateway's behind one. For the fleet view and label inheritance; it grants nothing.
    pub host: Option<String>,
    /// Where the Host and the Client Agent place this Agent — derived, never persisted.
    pub placement: Placement,
    /// What the operator's last rollout released to this Agent (ADR-0034 clause 5). **Every offer
    /// is composed from this**; matching only proposes. Written by the rollout acts, persisted like
    /// `restart_pending` — operator intent that survives a restart (ADR-0024). `None` is what it
    /// says: nothing has been rolled out.
    pub assignment: Option<Assignment>,
}

/// One Agent's assignment (ADR-0034 clause 5): one release, pinned as of the press that wrote it
/// and replaced whole by the next.
///
/// The Deployment is carried alongside the release rather than derived from it, because a
/// Deployment re-aimed or edited after the act must not change what an Agent was given, nor what
/// the fleet view says it was given through. The signature a package offer travels with is the
/// entry's own (ADR-0033).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// The Deployment the release went through.
    pub deployment: String,
    /// The Package pinned, if any — at most one, because an Agent belongs to at most one
    /// Deployment and a Deployment holds one Package per Agent type. The Baseline's "one top-level
    /// package" is structural here rather than enforced by a rule at the write.
    pub package: Option<PackageId>,
    /// Every Configuration released: its name → the content hash of the revision released, one
    /// of the `ConfigStore`'s retained revisions.
    pub configurations: BTreeMap<String, String>,
}

/// The configuration map of an Agent nothing was rolled out to.
static NO_CONFIGURATIONS: BTreeMap<String, String> = BTreeMap::new();

/// The Agents one Client presents (ADR-0035 clause 4), as far as the Server can tell them apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    /// On a direct connection: the Agents arriving over the same Host.
    Host(String),
    /// Behind a Gateway: the Agents arriving over the same Gateway Host that report the same
    /// machine — `host.id`, else `host.name` ([`crate::labels::machine`]).
    Behind { gateway: String, machine: String },
}

/// What the Host an Agent arrived over and its Client Agent add to its effective description
/// (ADR-0035 clauses 3 and 4). Derived from the records and the host register whenever either
/// changes; never persisted.
#[derive(Clone, Debug, Default)]
pub struct Placement {
    /// The `fleet.host.*` values of the Host it arrived over directly; empty behind a Gateway.
    pub host_values: BTreeMap<String, String>,
    /// The Client it belongs to, when the Server can tell.
    pub group: Option<Group>,
    /// Its Client Agent — itself, for the Client Agent — when its group holds exactly one.
    pub client_agent: Option<InstanceUid>,
    /// The labels of its Client Agent; empty for the Client Agent itself.
    pub inherited: BTreeMap<String, String>,
    /// Its group holds more than one Client Agent, so nothing is inherited.
    pub ambiguous: bool,
}

impl AgentRecord {
    /// What a Selector is matched against (ADR-0035 clause 3): the Host's values, what the Agent
    /// reported, its own labels and its Client Agent's, each key from the first that has it.
    ///
    /// Borrowed when it adds nothing to the report, which is the overwhelming majority of Agents —
    /// labelling should cost the fleet view nothing on the hosts nobody has labelled.
    pub fn effective_description(&self) -> Option<Cow<'_, AgentDescription>> {
        let sources = self.sources();
        if sources.adds_nothing() {
            return self.description.as_ref().map(Cow::Borrowed);
        }
        crate::labels::effective_description(&sources).map(Cow::Owned)
    }

    fn sources(&self) -> Sources<'_> {
        Sources {
            host: &self.placement.host_values,
            reported: self.description.as_ref(),
            own: &self.labels,
            inherited: &self.placement.inherited,
        }
    }

    /// The Package rolled out to this Agent, if any.
    fn assigned_package(&self) -> Option<&PackageId> {
        self.assignment.as_ref().and_then(|a| a.package.as_ref())
    }

    /// The Configurations rolled out to this Agent, name → pinned revision hash; empty when
    /// nothing was.
    fn assigned_configurations(&self) -> &BTreeMap<String, String> {
        self.assignment
            .as_ref()
            .map_or(&NO_CONFIGURATIONS, |a| &a.configurations)
    }

    /// What this Agent last reported as installed, per package name (ADR-0025): the versions
    /// the upgrade test measures a Package against. A package reported with an empty
    /// `agent_has_version` — offered, not yet installed — carries no version and is left out, so
    /// it reads as "nothing installed under that name" rather than as an unorderable value.
    fn installed_package_versions(&self) -> InstalledVersions {
        self.package_statuses
            .iter()
            .flat_map(|statuses| statuses.packages.iter())
            .filter(|(_, status)| !status.agent_has_version.is_empty())
            .map(|(name, status)| (name.clone(), status.agent_has_version.clone()))
            .collect()
    }

    /// What of this record survives a restart (ADR-0024): everything report-derived or
    /// operator-queued, never what a live connection knows.
    fn to_persisted(&self) -> PersistedAgent {
        PersistedAgent {
            sequence_num: self.sequence_num,
            capabilities: self.capabilities,
            description: self.description.clone(),
            health: self.health.clone(),
            effective_config: self.effective_config.clone(),
            remote_config_status: self.remote_config_status.clone(),
            connection_settings_status: self.connection_settings_status.clone(),
            package_statuses: self.package_statuses.clone(),
            available_components: self.available_components.clone(),
            transport: self.transport,
            last_seen_ms: self.last_seen_ms,
            restart_pending: self.restart_pending,
            assignment: self.assignment.clone(),
            labels: self.labels.clone(),
            host: self.host.clone(),
        }
    }

    /// A restored record is **disconnected with no owning connection** until live evidence says
    /// otherwise — connectedness is runtime-only (ADR-0024). Its placement is derived once the
    /// fleet is whole.
    fn from_persisted(persisted: PersistedAgent) -> AgentRecord {
        AgentRecord {
            sequence_num: persisted.sequence_num,
            capabilities: persisted.capabilities,
            description: persisted.description,
            health: persisted.health,
            effective_config: persisted.effective_config,
            remote_config_status: persisted.remote_config_status,
            transport: persisted.transport,
            connected: false,
            last_seen_ms: persisted.last_seen_ms,
            restart_pending: persisted.restart_pending,
            available_components: persisted.available_components,
            connection_settings_status: persisted.connection_settings_status,
            package_statuses: persisted.package_statuses,
            owner: None,
            labels: persisted.labels,
            host: persisted.host,
            placement: Placement::default(),
            assignment: persisted.assignment,
        }
    }
}

/// Why a restart request was refused (`POST /api/v1/agents/{uid}/restart`).
pub enum RestartError {
    /// No Agent of that identity is known.
    UnknownAgent,
    /// The Agent does not declare `AcceptsRestartCommand` — capability negotiation is binding,
    /// so the Server refuses rather than sending a command the Agent would ignore.
    NoCapability,
}

/// Why forgetting an Agent was refused (`DELETE /api/v1/agents/{uid}`, ADR-0024).
pub enum ForgetError {
    /// No Agent of that identity is known.
    UnknownAgent,
    /// The Agent is still reporting — connected, and not stale. Forgetting it would drop the
    /// hashes that stop the Server re-offering, so its next exchange would re-apply its
    /// configuration, which for a managed Agent restarts the Managed Process.
    StillReporting,
}

/// Why a rollout act (ADR-0034 clause 6) was refused.
#[derive(Debug)]
pub enum RolloutError {
    /// No Agent of that identity is known.
    UnknownAgent,
    /// The named Deployment does not exist (or package delivery, which arms the Deployments, is
    /// not configured).
    UnknownResource(String),
    /// The act cannot release here: the Agent is in no Deployment, in a conflict, or in another
    /// Deployment than the one named; or the Deployment holds nothing, or a Package with an
    /// unsigned entry.
    NotApplicable(String),
    /// The act could not be persisted.
    Storage(String),
}

/// Why deleting a Configuration was refused (ADR-0034 clause 8).
#[derive(Debug)]
pub enum DeleteError {
    /// An Agent's assignment pins it; the message says how many.
    Pinned(String),
    /// The store could not be written.
    Storage(String),
}

/// The result of processing one `AgentToServer`: the reply to send back on the same transport, and
/// what the transport layer needs to know for its own bookkeeping.
pub struct Processed {
    pub reply: ServerToAgent,
    /// The identity the Agent goes by *after* this message (it may have been reassigned).
    pub uid: Option<InstanceUid>,
    /// The Agent said goodbye; a WebSocket loop drops it from its connection-local set.
    pub disconnected: bool,
}

/// The one `OpAMPConnectionSettings` this Server offers (ADR-0014), precompiled from the
/// `[connection_offer]` section with the hash that gates its delivery.
pub struct ConnectionOffer {
    settings: OpAmpConnectionSettings,
}

/// The own-telemetry destinations this Server offers (ADR-0016), precompiled from
/// `[telemetry_offer]`. Part of the same `ConnectionSettingsOffers` message the OpAMP settings
/// ride, and hashed with them: one offer, one hash, one acknowledgement.
///
/// A field here is `Some` for every signal the section mentions, **including one it withdraws** —
/// a destination whose endpoint is empty (ADR-0016). That is why a withdrawal counts as something
/// to offer in [`is_empty`](Self::is_empty): it has to reach the Agent to take effect, and a
/// Server that has it to say declares `OffersConnectionSettings` for it like any other offer.
#[derive(Default, Clone)]
pub struct TelemetryOffer {
    pub own_metrics: Option<TelemetryConnectionSettings>,
    pub own_traces: Option<TelemetryConnectionSettings>,
    pub own_logs: Option<TelemetryConnectionSettings>,
}

impl TelemetryOffer {
    fn is_empty(&self) -> bool {
        self.own_metrics.is_none() && self.own_traces.is_none() && self.own_logs.is_none()
    }
}

impl ConnectionOffer {
    /// The offer of `settings`. Its hash is computed over the whole `ConnectionSettingsOffers` at
    /// send time, because an offer carries telemetry destinations too (ADR-0016) and the Agent
    /// acknowledges the message rather than any one part of it.
    pub fn new(settings: OpAmpConnectionSettings) -> Self {
        ConnectionOffer { settings }
    }
}

/// The wall clock's port (ADR-0006): when an Agent was last heard from, and how long ago that
/// is (ADR-0024). The system clock ([`SystemClock`](crate::clock::SystemClock)) is what the
/// composition root wires.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The CSR flow's port (ADR-0021): what signs an Agent's certificate signing request. The local
/// CA ([`ClientCa`](crate::ca::ClientCa)) is the adapter the composition root wires when
/// `[client_ca]` is configured.
pub trait CertificateSigner: Send + Sync {
    /// The signed certificate, PEM, for a CSR in PEM, and what it says about itself. Its subject
    /// carries `subject` — the values copied from the bootstrap certificate or the predecessor
    /// (ADR-0036 clauses 3 and 4) — and never the request's.
    ///
    /// # Errors
    /// Returns an error when the request does not parse or cannot be signed.
    fn sign(&self, csr_pem: &str, host: &str, subject: &SubjectValues) -> Result<Signed, String>;

    /// The certificate a CSR proves it renews, when it carries a renewal proof (ADR-0021
    /// clause 27); `Ok(None)` when it carries none.
    ///
    /// # Errors
    /// Returns the `BadRequest` text for a proof that does not hold.
    fn renewal_proof(&self, csr_pem: &str) -> Result<Option<Facts>, String>;

    /// The issuer and serial of the bootstrap certificate a CSR's bootstrap proof names (ADR-0039
    /// clause 1), read without checking the proof; `Ok(None)` when it carries none.
    ///
    /// # Errors
    /// Returns the `BadRequest` text for a proof that does not parse.
    fn bootstrap_proof_id(&self, csr_pem: &str) -> Result<Option<CertId>, String>;

    /// Checks the request's claims to an `instance_uid` against its sender's (ADR-0021).
    ///
    /// # Errors
    /// Returns the `BadRequest` text for a request that claims another identity.
    fn check_claims(&self, csr_pem: &str, sender: &[u8]) -> Result<(), String>;
}

/// Why the package store refuses an upload: its whole-store ceiling (ADR-0026).
#[derive(Debug, PartialEq, Eq)]
pub enum StoreFull {
    /// The store is already at its ceiling.
    AtLimit { limit: u64 },
    /// Committing an artifact of `size` bytes would take it past the ceiling.
    WouldExceed { size: u64, limit: u64 },
}

impl std::fmt::Display for StoreFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreFull::AtLimit { limit } => write!(
                f,
                "the package store is at its {limit}-byte limit (max_total_package_bytes)"
            ),
            StoreFull::WouldExceed { size, limit } => write!(
                f,
                "storing this {size}-byte artifact would take the package store past its \
                 {limit}-byte limit (max_total_package_bytes)"
            ),
        }
    }
}

/// The bytes of one upload still arriving, counted against the package store's ceiling until it is
/// dropped (ADR-0026). Taken from [`AppState::admit_upload`].
pub struct UploadReservation<'a> {
    state: &'a AppState,
    /// The stored artifacts' bytes when the upload began; walking the store per chunk would cost
    /// more than the chunk.
    stored: u64,
    bytes: u64,
}

impl UploadReservation<'_> {
    /// Counts `more` bytes of this upload as they arrive.
    ///
    /// # Errors
    /// [`StoreFull::WouldExceed`] once the store and every upload in progress pass the ceiling.
    pub fn grow(&mut self, more: u64) -> Result<(), StoreFull> {
        self.bytes += more;
        let uploading = self.state.uploading_bytes.fetch_add(more, Ordering::SeqCst) + more;
        self.within(self.stored, uploading)
    }

    /// Whether the upload, whole now, may be committed: the store as it stands and every upload in
    /// progress, this one included, within the ceiling. With
    /// [`admit_upload`](AppState::admit_upload) before the stream, this is what stops a caller
    /// filling the disk under distinct names.
    ///
    /// # Errors
    /// [`StoreFull::WouldExceed`] when committing it would pass the ceiling.
    pub fn admit_artifact(&self) -> Result<(), StoreFull> {
        self.within(
            self.state.stored_package_bytes(),
            self.state.uploading_bytes.load(Ordering::SeqCst),
        )
    }

    fn within(&self, stored: u64, uploading: u64) -> Result<(), StoreFull> {
        let limit = self.state.max_total_package_bytes;
        if stored.saturating_add(uploading) > limit {
            return Err(StoreFull::WouldExceed {
                size: self.bytes,
                limit,
            });
        }
        Ok(())
    }
}

impl Drop for UploadReservation<'_> {
    fn drop(&mut self) {
        self.state
            .uploading_bytes
            .fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// The package store and the Deployments that release from it (ADR-0026). Every `download_url`
/// is a path the Client resolves against its own endpoint — the Agent plane, where the download
/// is served behind the same handshake as `/v1/opamp` (ADR-0033).
pub struct PackageOffering {
    store: PackageStore,
    deployments: DeploymentStore,
}

impl PackageOffering {
    pub fn with_deployments(store: PackageStore, deployments: DeploymentStore) -> Self {
        PackageOffering { store, deployments }
    }

    pub fn store(&self) -> &PackageStore {
        &self.store
    }

    pub fn deployments(&self) -> &DeploymentStore {
        &self.deployments
    }
}

/// Shared state behind every handler: the fleet, the Configuration store, and the push channel
/// WebSocket loops subscribe to.
pub struct AppState {
    fleet: Mutex<HashMap<InstanceUid, AgentRecord>>,
    /// Where Agent records survive a restart (ADR-0024) — the port, never a concrete backend:
    /// the filesystem adapter is merely what [`AppState::new`] wires by default.
    agent_store: Box<dyn AgentStore>,
    /// Each persisted record's durable digest as last written — the dirty check that keeps a
    /// heartbeat from reaching any storage backend (ADR-0024). Locked strictly after `fleet`.
    written: Mutex<HashMap<InstanceUid, [u8; 32]>>,
    configs: ConfigStore,
    /// Which Agents each [`Group`] holds (ADR-0035 clause 4), so placing one Agent touches its
    /// group alone. Locked strictly after `fleet`, and only while it is held.
    groups: Mutex<HashMap<Group, HashSet<InstanceUid>>>,
    push: watch::Sender<u64>,
    /// Hands every WebSocket connection its identity for the duplicate detection.
    next_conn: AtomicU64,
    /// The connection settings offered to the fleet (ADR-0014); `None` offers nothing and leaves
    /// `OffersConnectionSettings` undeclared.
    connection_offer: Option<ConnectionOffer>,
    /// The packages offered to the fleet (ADR-0026); `None` offers nothing and leaves
    /// `OffersPackages` undeclared.
    packages: Option<PackageOffering>,
    /// The authority that signs Agent CSRs (ADR-0021); `None` signs nothing and leaves
    /// `AcceptsConnectionSettingsRequest` undeclared.
    client_ca: Option<Box<dyn CertificateSigner>>,
    /// The enrolment window and its queue (ADR-0021); `None` while `[enrolment]` is not set, and no
    /// host enrols.
    enrolment: Option<Arc<Enrolment>>,
    /// The bootstrap certificates the Server issued (ADR-0028); `None` while `[enrolment]` is not
    /// set.
    bootstrap: Option<Arc<crate::bootstrap::BootstrapCertificates>>,
    /// What the client CA signed and what is revoked (ADR-0021); `None` only where a test serves
    /// without it.
    revocations: Option<Arc<Revocations>>,
    /// The audit record every security decision goes to (ADR-0022); `None` only in tests.
    audit: Option<Arc<dyn Audit>>,
    /// How often an admitted peer may be heard (ADR-0013); `None` only in tests.
    agent_rate: Option<Arc<crate::agent_rate::AgentRate>>,
    /// When an Agent is heard from, and how long ago that was.
    clock: Box<dyn Clock>,
    /// Where Agents send their own telemetry (ADR-0016); empty offers no destination.
    telemetry_offer: TelemetryOffer,
    /// The message size limit both transports enforce, in each direction (the Baseline's MUST).
    max_message_size: usize,
    /// The largest package artifact the REST API accepts on upload (ADR-0026) — a program, not a
    /// message, so it is bounded separately and far more generously.
    max_package_size: usize,
    /// The total size of all stored artifacts the REST API keeps before it refuses a new upload
    /// (ADR-0026): what bounds the store — and so the disk — against many uploads under distinct
    /// names, where `max_package_size` bounds only one.
    max_total_package_bytes: u64,
    /// The bytes of uploads still arriving, counted against `max_total_package_bytes` beside the
    /// stored artifacts, so uploads sent at once cannot pass the ceiling together.
    uploading_bytes: AtomicU64,
    /// How long an Agent that promised to report periodically may be silent before the fleet view
    /// calls it stale (ADR-0024). Overridden by an offered heartbeat interval, which is the period
    /// this Server actually asked for.
    stale_after: Duration,
    /// The most Agent records the fleet holds at once. A report bearing a new `instance_uid` past
    /// this ceiling is refused `Unavailable` rather than admitted, so a peer cycling fresh UIDs —
    /// each of which would pin an in-memory record and a persisted file — cannot exhaust memory or
    /// disk (a self-asserted UID is free to mint, ADR-0021). Existing Agents keep reporting; only
    /// growth past the ceiling is refused. The real defence against a flood is admission by client
    /// certificate (ADR-0021); this is the backstop that bounds what an admitted peer can do.
    max_agents: usize,
}

impl AppState {
    /// Builds the state on any backend for the Agent records, their labels included (ADR-0024,
    /// ADR-0035), and the Configurations (ADR-0025). The ports are the only thing the fleet logic
    /// knows about that persistence, so a database or an external store is an implementation of
    /// [`AgentStore`] or [`ConfigBackend`] plus one wiring call.
    pub fn with_stores(
        agent_store: Box<dyn AgentStore>,
        configs: Box<dyn ConfigBackend>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, String> {
        let configs = ConfigStore::open(configs)?;
        let restored = configs.list().len();
        if restored > 0 {
            info!(
                configurations = restored,
                "restored the Configuration store"
            );
        }
        // Every restored Agent comes back disconnected — what it last reported is knowledge,
        // whether it is still there is not (ADR-0024) — and in the channel its labels put it in.
        //
        // A record carrying no assignments is simply one nothing has been rolled out to. There is
        // no seed to run: the store this Server would have migrated from is not supported, so an
        // absent assignment means what it says rather than "not migrated yet".
        let mut fleet = HashMap::new();
        let mut written = HashMap::new();
        for (uid, persisted) in agent_store.load()? {
            written.insert(uid, persisted.durable_digest());
            fleet.insert(uid, AgentRecord::from_persisted(persisted));
        }
        if !fleet.is_empty() {
            info!(agents = fleet.len(), "restored the fleet");
        }
        // A rollout cut short leaves at most a revision no assignment references (ADR-0037
        // clause 3); it is collected here, before anything is offered.
        for config in configs.list() {
            configs.retain_only(
                &config.name,
                &agent_store.referenced_revisions(&config.name),
            )?;
        }
        let state = AppState {
            fleet: Mutex::new(fleet),
            agent_store,
            written: Mutex::new(written),
            configs,
            groups: Mutex::new(HashMap::new()),
            push: watch::channel(0).0,
            next_conn: AtomicU64::new(1),
            connection_offer: None,
            packages: None,
            client_ca: None,
            enrolment: None,
            bootstrap: None,
            revocations: None,
            audit: None,
            agent_rate: None,
            clock,
            telemetry_offer: TelemetryOffer::default(),
            max_message_size: opamp::frame::DEFAULT_MAX_MESSAGE_SIZE,
            max_package_size: DEFAULT_MAX_PACKAGE_SIZE,
            max_total_package_bytes: DEFAULT_MAX_TOTAL_PACKAGE_SIZE,
            uploading_bytes: AtomicU64::new(0),
            stale_after: DEFAULT_STALE_AFTER,
            max_agents: DEFAULT_MAX_AGENTS,
        };
        state.place_all();
        Ok(state)
    }

    /// Sets the message size limit both transports enforce (the Baseline recommends the default
    /// [`opamp::frame::DEFAULT_MAX_MESSAGE_SIZE`] and asks that it be configurable).
    #[must_use]
    pub fn with_max_message_size(mut self, limit: usize) -> Self {
        self.max_message_size = limit;
        self
    }

    /// The message size limit in force, for the transports to enforce in both directions.
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Sets the largest package artifact the REST API accepts on upload (ADR-0026).
    #[must_use]
    pub fn with_max_package_size(mut self, limit: usize) -> Self {
        self.max_package_size = limit;
        self
    }

    /// The package upload limit in force, for the REST API's package route.
    pub fn max_package_size(&self) -> usize {
        self.max_package_size
    }

    /// Sets the whole-store size limit the REST API enforces before accepting a new upload
    /// (ADR-0026).
    #[must_use]
    pub fn with_max_total_package_bytes(mut self, limit: u64) -> Self {
        self.max_total_package_bytes = limit;
        self
    }

    /// The whole-store size limit in force, for the REST API's upload route.
    pub fn max_total_package_bytes(&self) -> u64 {
        self.max_total_package_bytes
    }

    /// The total bytes of stored package artifacts right now, or `0` when package delivery is not
    /// configured. What the upload route checks against [`max_total_package_bytes`](Self::max_total_package_bytes).
    pub fn stored_package_bytes(&self) -> u64 {
        self.packages
            .as_ref()
            .map_or(0, |p| p.store().total_bytes())
    }

    /// Whether the package store takes another upload at all (ADR-0026): one already at its
    /// ceiling, counting the uploads still arriving, takes nothing more. Asked before an upload is
    /// streamed, so a gibibyte that would only be rejected is never read. The upload's bytes are
    /// counted through the answer as they arrive, and no longer once it is dropped.
    ///
    /// # Errors
    /// [`StoreFull::AtLimit`] when the store is at or past [`max_total_package_bytes`](Self::max_total_package_bytes).
    pub fn admit_upload(&self) -> Result<UploadReservation<'_>, StoreFull> {
        let limit = self.max_total_package_bytes;
        let stored = self.stored_package_bytes();
        if stored.saturating_add(self.uploading_bytes.load(Ordering::SeqCst)) >= limit {
            return Err(StoreFull::AtLimit { limit });
        }
        Ok(UploadReservation {
            state: self,
            stored,
            bytes: 0,
        })
    }

    /// Arms the connection-settings offer (ADR-0014); with it the Server declares
    /// `OffersConnectionSettings`.
    #[must_use]
    pub fn with_connection_offer(mut self, offer: Option<ConnectionOffer>) -> Self {
        self.connection_offer = offer;
        self
    }

    /// Sets how long a heartbeating Agent may be silent before it reads as stale (ADR-0024).
    #[must_use]
    pub fn with_stale_after(mut self, stale_after: Duration) -> Self {
        self.stale_after = stale_after;
        self
    }

    /// Sets the most Agent records the fleet holds at once — the backstop against a peer minting
    /// fresh UIDs to exhaust memory and disk (ADR-0021 clause 14).
    #[must_use]
    pub fn with_max_agents(mut self, max_agents: usize) -> Self {
        self.max_agents = max_agents;
        self
    }

    /// The staleness budget in force: the heartbeat interval this Server offered when it offered
    /// one — the period it actually asked for — else the configured default. Three of them, not
    /// one: a single missed heartbeat is a lost packet, and a fleet view that flickers on every
    /// hiccup is one nobody trusts.
    fn stale_after(&self) -> Duration {
        match self
            .connection_offer
            .as_ref()
            .map(|offer| offer.settings.heartbeat_interval_seconds)
            .filter(|seconds| *seconds > 0)
        {
            Some(seconds) => Duration::from_secs(seconds.saturating_mul(3)),
            None => self.stale_after,
        }
    }

    /// Offers the fleet somewhere to send its own telemetry (ADR-0016).
    #[must_use]
    pub fn with_telemetry_offer(mut self, offer: TelemetryOffer) -> Self {
        self.telemetry_offer = offer;
        self
    }

    /// Arms the CSR flow (ADR-0021); with it the Server declares
    /// `AcceptsConnectionSettingsRequest` and signs the requests Agents send.
    #[must_use]
    pub fn with_client_ca(mut self, client_ca: Option<impl CertificateSigner + 'static>) -> Self {
        self.client_ca = client_ca.map(|ca| Box::new(ca) as Box<dyn CertificateSigner>);
        self
    }

    /// Arms enrolment (ADR-0021): a host with a bootstrap certificate may ask for its first one,
    /// and an operator decides.
    #[must_use]
    pub fn with_enrolment(mut self, enrolment: Option<Arc<Enrolment>>) -> Self {
        self.enrolment = enrolment;
        self
    }

    /// Arms the issuing of bootstrap certificates and their record (ADR-0028).
    #[must_use]
    pub fn with_bootstrap(
        mut self,
        bootstrap: Option<Arc<crate::bootstrap::BootstrapCertificates>>,
    ) -> Self {
        self.bootstrap = bootstrap;
        self
    }

    /// The bootstrap certificates the Server issued, while `[enrolment]` is set.
    pub fn bootstrap(&self) -> Option<&Arc<crate::bootstrap::BootstrapCertificates>> {
        self.bootstrap.as_ref()
    }

    /// Arms the register and the revocation list (ADR-0021).
    #[must_use]
    pub fn with_revocations(mut self, revocations: Option<Arc<Revocations>>) -> Self {
        self.revocations = revocations;
        // The Hosts the records name are known now: their values and Gateway marks place them.
        self.place_all();
        self
    }

    /// Marks `host` as a Gateway, or not (ADR-0021 clause 7); answers whether this Server knows
    /// the host. The mark decides whether the Agents arriving over it carry its values and how
    /// they group (ADR-0035 clauses 3 and 4), so every Agent is placed again.
    ///
    /// # Errors
    /// Returns an error when there is no host register or the change cannot be written.
    pub fn set_gateway(&self, host: &str, gateway: bool) -> Result<bool, String> {
        let revocations = self
            .revocations
            .as_ref()
            .ok_or_else(|| "revocation is not configured".to_string())?;
        let known = revocations.set_gateway(host, gateway)?;
        if known {
            self.place_all();
        }
        Ok(known)
    }

    /// Where the Host an Agent arrived over places it (ADR-0035 clauses 3 and 4): the
    /// `fleet.host.*` values of a Host it arrived over directly, and the group its Client is
    /// recognised in. Nothing without a host register, and nothing for an Agent that names no
    /// Host.
    fn locate(&self, record: &AgentRecord) -> (BTreeMap<String, String>, Option<Group>) {
        let (Some(host), Some(revocations)) = (&record.host, &self.revocations) else {
            return (BTreeMap::new(), None);
        };
        let (gateway, subject) = revocations.placement(host);
        if gateway {
            let group =
                crate::labels::machine(record.description.as_ref()).map(|machine| Group::Behind {
                    gateway: host.clone(),
                    machine,
                });
            return (BTreeMap::new(), group);
        }
        let values = subject
            .attributes()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        (values, Some(Group::Host(host.clone())))
    }

    /// Places every Agent again — at startup, once the host register is known, and when a Gateway
    /// mark changes.
    fn place_all(&self) {
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let mut groups = self.groups.lock().expect("groups lock");
        groups.clear();
        for (uid, record) in fleet.iter_mut() {
            let (host_values, group) = self.locate(record);
            record.placement = Placement {
                host_values,
                group: group.clone(),
                ..Placement::default()
            };
            if let Some(group) = group {
                groups.entry(group).or_default().insert(*uid);
            }
        }
        for group in groups.keys() {
            inherit(&mut fleet, &groups, group);
        }
    }

    /// Places one Agent again after what places it may have changed — its Host, its report, or
    /// its identity — and the groups it left and joined with it.
    fn place(&self, fleet: &mut HashMap<InstanceUid, AgentRecord>, uid: &InstanceUid) {
        let Some(record) = fleet.get_mut(uid) else {
            return;
        };
        let (host_values, group) = self.locate(record);
        record.placement.host_values = host_values;
        let left = std::mem::replace(&mut record.placement.group, group.clone());
        if group.is_none() {
            record.placement.client_agent = None;
            record.placement.inherited.clear();
            record.placement.ambiguous = false;
        }
        let mut groups = self.groups.lock().expect("groups lock");
        if left != group {
            if let Some(left) = &left {
                unindex(&mut groups, left, uid);
            }
        }
        if let Some(joined) = &group {
            groups.entry(joined.clone()).or_default().insert(*uid);
            inherit(fleet, &groups, joined);
        }
        if let Some(left) = left.filter(|left| Some(left) != group.as_ref()) {
            inherit(fleet, &groups, &left);
        }
    }

    /// Takes an Agent that left the fleet, or its old identity, out of its group, and places what
    /// is left of the group again.
    fn unplace(
        &self,
        fleet: &mut HashMap<InstanceUid, AgentRecord>,
        uid: &InstanceUid,
        group: Option<Group>,
    ) {
        let Some(group) = group else {
            return;
        };
        let mut groups = self.groups.lock().expect("groups lock");
        unindex(&mut groups, &group, uid);
        inherit(fleet, &groups, &group);
    }

    /// The register and the revocation list.
    pub fn revocations(&self) -> Option<&Arc<Revocations>> {
        self.revocations.as_ref()
    }

    /// Arms the audit record (ADR-0022).
    #[must_use]
    pub fn with_audit(mut self, audit: Option<Arc<dyn Audit>>) -> Self {
        self.audit = audit;
        self
    }

    /// The audit record.
    pub fn audit(&self) -> Option<&Arc<dyn Audit>> {
        self.audit.as_ref()
    }

    /// Arms the rate limit on the Agent plane (ADR-0013).
    #[must_use]
    pub fn with_agent_rate(
        mut self,
        agent_rate: Option<Arc<crate::agent_rate::AgentRate>>,
    ) -> Self {
        self.agent_rate = agent_rate;
        self
    }

    /// The rate limit on the Agent plane.
    pub fn agent_rate(&self) -> Option<&Arc<crate::agent_rate::AgentRate>> {
        self.agent_rate.as_ref()
    }

    /// Records a decision this Server is about to act on; without a record it is not taken
    /// (ADR-0022 clause 6).
    fn audited(&self, entry: Entry) -> Result<(), String> {
        match &self.audit {
            Some(audit) => audit
                .record(entry)
                .map_err(|_| "the audit record is unavailable — retry shortly".to_string()),
            None => Ok(()),
        }
    }

    /// Records a refusal; it is refused either way.
    pub(crate) fn audit_refusal(&self, entry: Entry) {
        if let Some(audit) = &self.audit {
            audit.refusal(entry);
        }
    }

    /// Records a certificate the client CA signed, before it is offered (ADR-0021 clause 33,
    /// ADR-0022 clause 1).
    fn record_issued(
        &self,
        signed: &Signed,
        instance_uid: &[u8],
        predecessor: Option<CertId>,
    ) -> Result<(), String> {
        self.audited(
            Entry::new("issuance.signed", "issued")
                .with(
                    "kind",
                    if predecessor.is_some() {
                        "renewal"
                    } else {
                        "enrolment"
                    },
                )
                .with("issuer", signed.facts.issuer_name.clone())
                .with(
                    "authority",
                    self.revocations.as_ref().and_then(|revocations| {
                        revocations
                            .authority_of(&signed.facts.id.issuer)
                            .map(|authority| authority.role.clone())
                    }),
                )
                .with("serial", signed.facts.id.serial.clone())
                .with("subject", signed.facts.subject.clone())
                .with("key_fingerprint", signed.facts.key_fingerprint.clone())
                .with("instance_uid", hex::encode(instance_uid))
                .with(
                    "predecessor_serial",
                    predecessor.as_ref().map(|id| id.serial.clone()),
                ),
        )?;
        match &self.revocations {
            Some(revocations) => revocations
                .record(signed.facts.clone(), instance_uid, predecessor)
                .map_err(|e| format!("cannot record the issued certificate: {e}")),
            None => Ok(()),
        }
    }

    /// What a CSR renews, the host the new certificate is for (ADR-0021 clause 27), and the
    /// subject values it carries on (ADR-0036 clause 4). A renewal proof names the certificate
    /// whose key signed the new one — through a Gateway too — and the host and the values carry
    /// on from it; without one, the certificate the connection presented is renewed, unless its
    /// host is marked as a Gateway (ADR-0039 clause 1). A bootstrap proof makes the request an
    /// enrolment, which a member does not make (ADR-0039 clause 12) — unless it proves the very
    /// certificate the connection presented: a Client cannot tell a certificate an operator
    /// provisioned from a bootstrap certificate, and proves whichever it holds. A certificate that
    /// names no host — one an operator provisioned — gets a host derived from its issuer and
    /// serial, the same on every retry.
    fn renews(
        &self,
        ca: &dyn CertificateSigner,
        csr: &str,
        presented: Option<&Presented>,
    ) -> Result<(Option<CertId>, String, SubjectValues), String> {
        let derived = |id: &CertId| fleet_core::host::derived(&id.issuer, &id.serial);
        if let Some(old) = ca.renewal_proof(csr)? {
            if self
                .revocations
                .as_ref()
                .is_some_and(|revocations| revocations.is_certificate_revoked(&old.id))
            {
                return Err("the certificate this request renews is revoked".to_string());
            }
            let host = old.host.clone().unwrap_or_else(|| derived(&old.id));
            return Ok((Some(old.id), host, old.subject_values));
        }
        // A proof of the certificate presented is that certificate's renewal, and without a
        // certificate presented — `Admission::open`, which no Server serves — nothing is enrolled.
        let enrols = match (ca.bootstrap_proof_id(csr)?, presented) {
            (Some(named), Some(presented)) => named != presented.id,
            _ => false,
        };
        Ok(match presented {
            Some(presented) => {
                let host = presented
                    .host
                    .clone()
                    .unwrap_or_else(|| derived(&presented.id));
                // Behind a Gateway the presented certificate is the Gateway's, and its host carries
                // the mark: a CSR without a proof would hand the Gateway's powers to whoever sent
                // it (ADR-0039 clause 1).
                let gateway = self
                    .revocations
                    .as_ref()
                    .is_some_and(|revocations| revocations.is_gateway(&host));
                if enrols {
                    return Err(if gateway {
                        "a bootstrap proof through a Gateway is an enrolment request, not a renewal"
                            .to_string()
                    } else {
                        MEMBER_DOES_NOT_ENROL.to_string()
                    });
                }
                if gateway {
                    return Err(NEEDS_A_PROOF.to_string());
                }
                (
                    Some(presented.id.clone()),
                    host,
                    presented.subject_values.clone(),
                )
            }
            None => (
                None,
                InstanceUid::default().to_string(),
                SubjectValues::default(),
            ),
        })
    }

    /// The enrolment window and its queue, while `[enrolment]` is set.
    pub fn enrolment(&self) -> Option<&Arc<Enrolment>> {
        self.enrolment.as_ref()
    }

    /// Approves one pending enrolment request: the client CA signs it (ADR-0021 clause 22), with
    /// the subject values of the bootstrap certificate the request came with (ADR-0036 clause 3).
    ///
    /// # Errors
    /// Returns [`DecisionError::NotFound`] when enrolment is off or the id is unknown,
    /// [`DecisionError::Subject`] when the bootstrap certificate's subject cannot be carried, and
    /// [`DecisionError::Sign`] when no CA is configured or it refuses the request.
    pub fn approve_enrolment(&self, id: &str) -> Result<(), DecisionError> {
        let enrolment = self.enrolment.as_ref().ok_or(DecisionError::NotFound)?;
        let signer = self.client_ca.as_deref().ok_or_else(|| {
            DecisionError::Sign("this Server issues no client certificates".into())
        })?;
        // A new host: its identity is minted here and carried by every renewal (ADR-0021 clause 7).
        let host = InstanceUid::default().to_string();
        let revoked = |bootstrap: &CertId| {
            self.revocations
                .as_ref()
                .is_some_and(|revocations| revocations.is_certificate_revoked(bootstrap))
        };
        enrolment.approve(
            id,
            signer,
            &host,
            &|signed, instance_uid| self.record_issued(signed, instance_uid, None),
            &revoked,
        )
    }

    /// What an enrolment connection is told (ADR-0021 clause 21): the capabilities that say it may
    /// send a CSR, and — once its request is approved — the issued certificate, as an ordinary
    /// connection-settings offer with no private key in it.
    pub fn enrolment_answer(
        &self,
        instance_uid: &[u8],
        certificate: Option<String>,
    ) -> ServerToAgent {
        let mut capabilities = ServerCapabilities::AcceptsStatus as u64;
        if self.client_ca.is_some() {
            capabilities |= ServerCapabilities::AcceptsConnectionSettingsRequest as u64
                | ServerCapabilities::OffersConnectionSettings as u64;
        }
        ServerToAgent {
            instance_uid: instance_uid.to_vec(),
            capabilities,
            connection_settings: certificate.map(|cert| {
                compose_settings_offer(
                    Some(OpAmpConnectionSettings {
                        certificate: Some(TlsCertificate {
                            cert: cert.into_bytes(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    TelemetryOffer::default(),
                )
            }),
            ..Default::default()
        }
    }

    /// Arms package delivery (ADR-0026); with a non-empty store the Server declares
    /// `OffersPackages` and `AcceptsPackagesStatus`.
    #[must_use]
    pub fn with_packages(mut self, packages: Option<PackageOffering>) -> Self {
        self.packages = packages;
        self
    }

    /// Read access to the package store, for the REST API's package routes.
    pub fn packages(&self) -> Option<&PackageStore> {
        self.packages.as_ref().map(PackageOffering::store)
    }

    /// Read access to the Deployment store, armed with the package store (ADR-0026).
    pub fn deployment_store(&self) -> Option<&DeploymentStore> {
        self.packages.as_ref().map(PackageOffering::deployments)
    }

    /// The Capability Set this Server declares: the base set, plus `OffersConnectionSettings`
    /// while there is anything to offer and `OffersPackages` / `AcceptsPackagesStatus`
    /// while a non-empty package store is armed — an undeclared capability is never exercised, a
    /// declared one never hollow.
    fn capabilities(&self) -> u64 {
        let mut caps = SERVER_CAPABILITIES;
        // All three ways a `ConnectionSettingsOffers` leaves this Server (ADR-0014 clause 3): the
        // standing `[connection_offer]`, the own-telemetry destinations of `[telemetry_offer]`, and
        // the certificate a `[client_ca]` issues in answer to a CSR — which travels as an ordinary
        // offer. Keying the bit on the first alone left the other two exercising a capability this
        // Server had not declared, which is exactly what the sentence above promises never happens.
        if self.connection_offer.is_some()
            || !self.telemetry_offer.is_empty()
            || self.client_ca.is_some()
        {
            caps |= ServerCapabilities::OffersConnectionSettings as u64;
        }
        if self.packages.as_ref().is_some_and(|p| !p.store.is_empty()) {
            caps |= ServerCapabilities::OffersPackages as u64
                | ServerCapabilities::AcceptsPackagesStatus as u64;
        }
        if self.client_ca.is_some() {
            caps |= ServerCapabilities::AcceptsConnectionSettingsRequest as u64;
        }
        caps
    }

    /// A fresh identity for one WebSocket connection.
    pub fn connection_id(&self) -> ConnId {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// A receiver that fires whenever any Configuration changes; WebSocket loops use it to push
    /// offers without waiting for the Agent to speak.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.push.subscribe()
    }

    /// Read access to the Configuration store (the REST API's `GET` routes).
    pub fn configurations(&self) -> &ConfigStore {
        &self.configs
    }

    /// Creates a Configuration or replaces its saved revision, and persists it. **Saving only
    /// saves** (ADR-0025): nothing is offered and no WebSocket loop wakes — every Agent keeps
    /// the revision its assignment pins, and the fleet view shows the newer save waiting.
    pub fn save_configuration(
        &self,
        name: &str,
        revision: Revision,
    ) -> Result<Configuration, String> {
        let config = self.configs.put_saved(name, revision)?;
        info!(configuration = %name, "configuration saved — nothing distributed");
        Ok(config)
    }

    /// The Deployment claiming one Agent (ADR-0026), or the conflict that says why none does.
    fn deployment_of(&self, record: &AgentRecord) -> Result<Option<Deployment>, String> {
        let Some(store) = self.deployment_store() else {
            return Ok(None);
        };
        let all = store.snapshot();
        deployment_for(&all, record.effective_description().as_deref()).map(|found| found.cloned())
    }

    /// What a press of `deployment` would release to this Agent (ADR-0034 clause 6) — the
    /// assignment it would write, or `None` when it has nothing for the Agent.
    ///
    /// Two parts, each as of now: the Package the Deployment holds for the Agent's type when it is
    /// a candidate (ADR-0025 clauses 9–13), and every Configuration it holds that fits the Agent's
    /// type, at its saved revision. Where the Deployment holds a Package for the Agent's type that
    /// is no candidate — the Agent already runs it, or it would move the Agent backwards — the
    /// press cannot move the package part, so the Package the assignment pins stays pinned: the
    /// release is replaced whole, and a part the press does not move must not fall out of it
    /// (ADR-0025 clause 17). A Package or Configuration the Deployment no longer holds leaves the
    /// release.
    ///
    /// The rollout acts, the reach counts and the fleet view's waiting changes all ask this one
    /// question, so the count beside a press, the press and the view cannot disagree.
    fn release(
        &self,
        store: &PackageStore,
        deployment: &Deployment,
        record: &AgentRecord,
    ) -> Option<Assignment> {
        let effective = record.effective_description();
        let description = effective.as_deref();
        let configurations = self
            .configs
            .candidates_in(&deployment.configurations, description);
        let agent_type = crate::packages::reported_agent_type(description);
        let held = agent_type.and_then(|agent_type| deployment.package_for(agent_type));
        let package = store
            .candidate(
                deployment,
                description,
                &record.installed_package_versions(),
            )
            .or_else(|| {
                held.and(record.assigned_package())
                    .filter(|pinned| Some(pinned.agent_type.as_str()) == agent_type)
                    .cloned()
            });
        (package.is_some() || !configurations.is_empty()).then(|| Assignment {
            deployment: deployment.name.clone(),
            package,
            configurations,
        })
    }

    /// Writes releases (ADR-0025 clause 2, ADR-0037 clause 3): each Configuration's saved revision
    /// is pinned — copied into the store's retained revisions, its hash the one the assignment
    /// keeps — and the revisions and the records carrying the new assignments go to the store as
    /// one operation. Only once it succeeded are they the fleet's. A failure leaves the fleet's
    /// assignments as they were, the store puts back the records it wrote, and the revisions the
    /// stored assignments do not reference are collected. Answers the Configurations the old and
    /// new assignments name, whose unreferenced revisions the caller collects.
    fn write_releases(
        &self,
        fleet: &mut HashMap<InstanceUid, AgentRecord>,
        releases: Vec<(InstanceUid, Option<Assignment>)>,
    ) -> Result<Vec<String>, RolloutError> {
        let names: BTreeSet<String> = releases
            .iter()
            .flat_map(|(_, release)| release.iter())
            .flat_map(|release| release.configurations.keys().cloned())
            .collect();
        let written = self
            .configs
            .pin(&names, |hashes, revisions| {
                let agents: Vec<(InstanceUid, PersistedAgent)> = releases
                    .into_iter()
                    .map(|(uid, release)| {
                        let mut persisted = fleet[&uid].to_persisted();
                        persisted.assignment = release.map(|mut release| {
                            for (name, hash) in release.configurations.iter_mut() {
                                hash.clone_from(&hashes[name]);
                            }
                            release
                        });
                        (uid, persisted)
                    })
                    .collect();
                self.agent_store.release(revisions, &agents)?;
                Ok(agents)
            })
            .map_err(|e| {
                self.collect_revisions(names);
                RolloutError::Storage(e)
            })?;
        let mut digests = self.written.lock().expect("written lock");
        let mut touched = Vec::new();
        for (uid, persisted) in written {
            let record = fleet.get_mut(&uid).expect("released to a known Agent");
            let previous = std::mem::replace(&mut record.assignment, persisted.assignment.clone());
            touched.extend(
                previous
                    .iter()
                    .chain(record.assignment.iter())
                    .flat_map(|a| a.configurations.keys().cloned()),
            );
            digests.insert(uid, persisted.durable_digest());
        }
        Ok(touched)
    }

    /// Collects every retained revision of `names` no stored assignment references any more — a
    /// question the store answers (ADR-0037 clause 3).
    fn collect_revisions(&self, names: impl IntoIterator<Item = String>) {
        for name in names.into_iter().collect::<BTreeSet<_>>() {
            let referenced = self.agent_store.referenced_revisions(&name);
            if let Err(e) = self.configs.retain_only(&name, &referenced) {
                warn!(configuration = %name, error = %e, "cannot collect unreferenced revisions");
            }
        }
    }

    /// The per-Agent rollout act (ADR-0034 clause 6): releases the Deployment that claims this
    /// Agent to it, replacing its assignment, and wakes the WebSocket loops so a connected Agent
    /// hears it now.
    ///
    /// `named` is what the request body said: nothing, or the Deployment the operator means. Naming
    /// another one is refused, and so is an Agent no Deployment claims or two claim. Naming one is
    /// not a way past a conflict: honouring it would sidestep the conflict for good instead of
    /// fixing it, and make this path the way into a state the fleet-wide act forbids.
    pub fn rollout_to_agent(
        &self,
        uid: &InstanceUid,
        named: Option<&str>,
    ) -> Result<(), RolloutError> {
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let record = fleet.get_mut(uid).ok_or(RolloutError::UnknownAgent)?;
        let deployment = self
            .deployment_of(record)
            .map_err(RolloutError::NotApplicable)?
            .ok_or_else(|| {
                RolloutError::NotApplicable(format!(
                    "agent {uid} is in no deployment — no Deployment's Selector matches it, so \
                     there is nothing to roll out to it; label it or re-aim a Deployment"
                ))
            })?;
        if let Some(name) = named {
            if deployment.name != name {
                return Err(RolloutError::NotApplicable(format!(
                    "agent {uid} belongs to deployment {:?}, not {name:?}",
                    deployment.name
                )));
            }
        }
        let store = self
            .offering()
            .map_err(RolloutError::UnknownResource)?
            .store();
        refuse_unreleasable(store, &deployment)?;
        let release = self.release(store, &deployment, record);
        if release == record.assignment {
            refuse_a_package_left_out(store, &deployment, record, release.as_ref())?;
        }
        let touched = self.write_releases(&mut fleet, vec![(*uid, release)])?;
        // The release may have replaced a pinned revision nothing references any more.
        self.collect_revisions(touched);
        drop(fleet);
        self.push.send_modify(|rev| *rev += 1);
        info!(agent = %uid, deployment = %deployment.name, "rollout to agent");
        Ok(())
    }

    /// The rollout act for a Deployment (ADR-0034 clause 6): releases it to every Agent it claims
    /// and would move, replacing each one's assignment, and returns how many Agents that was.
    ///
    /// An Agent some *other* Deployment also claims is skipped rather than counted — the conflict
    /// is reported on that Agent, and a press that quietly resolved it here would be the ranking
    /// this model removed, wearing a different hat.
    pub fn rollout_deployment(&self, name: &str) -> Result<usize, RolloutError> {
        let offering = self.offering().map_err(RolloutError::UnknownResource)?;
        let store = offering.store();
        // Locked before the Deployments are read, so a delete cannot slip in between and leave
        // assignments naming a channel that is gone (see `delete_deployment`).
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let deployments = offering.deployments().snapshot();
        let deployment = deployments
            .get(name)
            .ok_or_else(|| RolloutError::UnknownResource(format!("no deployment {name:?}")))?;
        refuse_unreleasable(store, deployment)?;
        let mut releases: Vec<(InstanceUid, Option<Assignment>)> = Vec::new();
        for (uid, record) in fleet.iter() {
            let claiming = deployment_for(&deployments, record.effective_description().as_deref());
            match claiming {
                Ok(Some(claimed)) if claimed.name == name => {}
                _ => continue,
            }
            let release = self.release(store, deployment, record);
            if release != record.assignment {
                releases.push((*uid, release));
            }
        }
        // In one order, so a rollout that fails part-way fails the same way every time.
        releases.sort_by_key(|(uid, _)| uid.0);
        let assigned = releases.len();
        let touched = self.write_releases(&mut fleet, releases)?;
        self.collect_revisions(touched);
        drop(fleet);
        self.push.send_modify(|rev| *rev += 1);
        info!(deployment = %name, agents = assigned, "deployment rolled out to every agent it claims");
        Ok(assigned)
    }

    /// Queues a restart for one Agent (`AcceptsRestartCommand`) and wakes the WebSocket loops so
    /// a connected Agent hears it now; a polling one picks it up on its next exchange.
    pub fn request_restart(&self, uid: &InstanceUid) -> Result<(), RestartError> {
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let record = fleet.get_mut(uid).ok_or(RestartError::UnknownAgent)?;
        if record.capabilities & opamp::proto::AgentCapabilities::AcceptsRestartCommand as u64 == 0
        {
            return Err(RestartError::NoCapability);
        }
        record.restart_pending = true;
        // Operator intent survives a Server restart like any other durable state (ADR-0024).
        self.persist_if_dirty(uid, record);
        drop(fleet);
        self.push.send_modify(|rev| *rev += 1);
        info!(agent = %uid, "restart requested");
        Ok(())
    }

    /// Replaces an Agent's labels (ADR-0024), which changes what Selectors match it.
    ///
    /// A key the Agent already reports is **refused**, not applied: `os.type` and `host.arch`
    /// choose which artifact it is offered (ADR-0026) and `service.name` decides which packages fit
    /// it at all (ADR-0026), so a label that outranked them would let a slip here offer this Agent
    /// an artifact built for another machine. Labels annotate; they do not correct.
    ///
    /// A label move changes only what the fleet view **proposes** (ADR-0025): the Agent's
    /// candidates follow its new channel, and nothing is distributed until a rollout act says so.
    ///
    /// The labels are part of the Agent's record (ADR-0035 clause 6) and are written with it before
    /// this answers. A Client Agent's labels hold for its Client's other Agents (clause 4), so its
    /// group is placed again.
    pub fn set_labels(
        &self,
        uid: &InstanceUid,
        set: BTreeMap<String, String>,
    ) -> Result<(), LabelError> {
        crate::labels::check_pairs(&set).map_err(LabelError::Invalid)?;
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let record = fleet.get_mut(uid).ok_or(LabelError::UnknownAgent)?;
        let reported = crate::labels::reported_keys(record.description.as_ref());
        if let Some(clash) = set.keys().find(|key| reported.iter().any(|r| r == *key)) {
            return Err(LabelError::RestatesReported(clash.clone()));
        }
        let previous = std::mem::replace(&mut record.labels, set);
        if let Err(e) = self.persist(uid, record) {
            record.labels = previous;
            return Err(LabelError::Storage(e));
        }
        if let Some(group) = record.placement.group.clone() {
            let groups = self.groups.lock().expect("groups lock");
            inherit(&mut fleet, &groups, &group);
        }
        drop(fleet);
        info!(agent = %uid, "labels set — candidates follow, nothing is distributed");
        Ok(())
    }

    /// Which Deployments hold each Package, keyed by `<agent type>@<version>` — how a Package
    /// answers "whom would this reach", since it does not aim by itself (ADR-0026).
    pub fn deployments_holding(&self) -> BTreeMap<String, Vec<String>> {
        let mut holding: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let Some(store) = self.deployment_store() else {
            return holding;
        };
        // The store lists in name order, so every list is built already sorted.
        for deployment in store.list() {
            for id in deployment.packages.values() {
                holding
                    .entry(id.to_string())
                    .or_default()
                    .push(deployment.name.clone());
            }
        }
        holding
    }

    /// Which Deployments hold each Configuration, by name (ADR-0034 clause 9) — how a
    /// Configuration answers "whom would this reach", since it does not aim by itself.
    pub fn deployments_holding_configurations(&self) -> BTreeMap<String, Vec<String>> {
        let mut holding: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let Some(store) = self.deployment_store() else {
            return holding;
        };
        for deployment in store.list() {
            for name in &deployment.configurations {
                holding
                    .entry(name.clone())
                    .or_default()
                    .push(deployment.name.clone());
            }
        }
        holding
    }

    /// Whom each Deployment reaches, per name — the three counts the fleet view reads.
    ///
    /// Zero has three meanings now, and only the first is a mistake to go hunting for:
    /// `claiming` is zero when the channel aims at nobody (a misspelled label, a Selector nothing
    /// matches); `targeted` is zero when a press would move none of the Agents it claims — each
    /// already holds what it would release — which is nothing to fix; and `conflicting` counts the Agents another Deployment also claims,
    /// which is the one an operator has to resolve before this channel can reach them.
    ///
    /// It answers for the fleet *as reported so far*: a channel aimed at hosts that have not
    /// connected yet legitimately reaches nobody, which is why these are counts to be read rather
    /// than errors to be raised.
    pub fn deployment_reach(&self) -> BTreeMap<String, DeploymentReach> {
        let mut reach: BTreeMap<String, DeploymentReach> = BTreeMap::new();
        let Ok(offering) = self.offering() else {
            return reach;
        };
        let store = offering.store();
        let all = offering.deployments().snapshot();
        for name in all.keys() {
            reach.entry(name.clone()).or_default();
        }
        let fleet = self.fleet.lock().expect("fleet lock");
        for record in fleet.values() {
            let effective = record.effective_description();
            match deployment_for(&all, effective.as_deref()) {
                Ok(Some(deployment)) => {
                    let entry = reach.entry(deployment.name.clone()).or_default();
                    entry.claiming += 1;
                    if self.release(store, deployment, record) != record.assignment {
                        entry.targeted += 1;
                    }
                }
                Ok(None) => {}
                // Every channel in the way carries the count: the operator has to look at all of
                // them, not at whichever one happened to be listed first.
                Err(_) => {
                    for (name, deployment) in &all {
                        if deployments::matches(&deployment.selector, effective.as_deref()) {
                            reach.entry(name.clone()).or_default().conflicting += 1;
                        }
                    }
                }
            }
        }
        reach
    }

    /// Forgets everything this Server knows about one Agent (ADR-0024): the record is dropped and
    /// the row leaves the fleet view. Nothing reaches the host — no process is stopped and no
    /// certificate revoked, since a certificate here proves fleet membership and its host, never
    /// which Agent is speaking (ADR-0021 clause 7). A Client still running therefore reappears on its next
    /// report, which this Server answers with `ReportFullState` as it does for any unknown Agent.
    /// The `instance_uid` is released from the Host it was bound to, so that report binds it to
    /// the host whose certificate carries it (ADR-0047 clause 2).
    ///
    /// Refused while the Agent is still reporting: the record holds the hashes that gate
    /// re-offering, so forgetting a live Agent has it offered its configuration again — and the
    /// Collector plugin restarts its Managed Process when a configuration arrives. An operator who
    /// wants a restart asks for one through [`request_restart`](Self::request_restart).
    ///
    /// `connected` alone would not do. Behind a Gateway the open connection is the *Gateway's*, so
    /// a Gatewayed Agent that died still reads as connected; and plain-HTTP polling has no socket
    /// to close, so an Agent that stops polling without saying goodbye stays connected forever.
    /// Silence is the second half of the test — and it is [`is_silent`], not [`is_stale`]: an
    /// Agent that declared no heartbeat is never called stale, and gating on staleness would leave
    /// its row on a decommissioned host permanently unremovable.
    pub fn forget_agent(&self, uid: &InstanceUid) -> Result<(), ForgetError> {
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let record = fleet.get(uid).ok_or(ForgetError::UnknownAgent)?;
        if record.connected && !is_silent(record, self.stale_after(), self.clock.now_ms()) {
            return Err(ForgetError::StillReporting);
        }
        let removed = fleet.remove(uid);
        // Forgetting that left a stored record behind would be the "remembering under another
        // name" ADR-0024 rejected — the record leaves the store with the row, its labels with it
        // (ADR-0024, ADR-0035 clause 6).
        self.unpersist(uid);
        // Its `instance_uid` leaves the Host it was bound to: whichever host reports it next binds
        // it (ADR-0047 clause 2).
        if let Some(revocations) = &self.revocations {
            if let Err(e) = revocations.release(uid.as_bytes()) {
                warn!(agent = %uid, error = %e, "cannot write the released host binding");
            }
        }
        if let Some(record) = removed {
            // A Client Agent forgotten takes its labels from the Agents that inherited them.
            self.unplace(&mut fleet, uid, record.placement.group.clone());
            // A pinned revision only this Agent referenced is unreferenced now (ADR-0025).
            self.collect_revisions(record.assigned_configurations().keys().cloned());
        }
        drop(fleet);
        self.push.send_modify(|rev| *rev += 1);
        info!(agent = %uid, "agent forgotten");
        Ok(())
    }

    /// The queued restart for this Agent as the Baseline's command-only message, taken exactly
    /// once — `None` when nothing is queued (or the Agent went away).
    pub fn restart_command_for(&self, uid: &InstanceUid) -> Option<ServerToAgent> {
        let mut fleet = self.fleet.lock().expect("fleet lock");
        let record = fleet.get_mut(uid)?;
        if !record.restart_pending || !record.connected {
            return None;
        }
        record.restart_pending = false;
        self.persist_if_dirty(uid, record);
        Some(restart_command(uid, self.capabilities()))
    }

    /// Deletes a Configuration (ADR-0034 clause 8); `false` when none of that name exists.
    /// **Refused while any Agent's assignment pins it** — the message says how many — because a
    /// deletion must not change what a running Agent receives: those Agents are rolled out through
    /// a Deployment without it first, or forgotten. A deleted Configuration leaves every Deployment
    /// that held it.
    ///
    /// The fleet lock is held across the check and the delete, so a rollout cannot pin it in
    /// between.
    pub fn delete_configuration(&self, name: &str) -> Result<bool, DeleteError> {
        let fleet = self.fleet.lock().expect("fleet lock");
        let pinning = self.agent_store.pinning(Pin::Configuration(name));
        if pinning > 0 {
            return Err(DeleteError::Pinned(format!(
                "configuration {name:?} is pinned by the assignment of {pinning} Agent(s) — roll \
                 them out through a Deployment without it, or forget them, before deleting it"
            )));
        }
        let deleted = self.configs.delete(name).map_err(DeleteError::Storage)?;
        if deleted {
            if let Some(store) = self.deployment_store() {
                let left = store
                    .drop_configuration(name)
                    .map_err(|e| DeleteError::Storage(e.to_string()))?;
                if !left.is_empty() {
                    info!(configuration = %name, deployments = ?left, "configuration left the deployments that held it");
                }
            }
            info!(configuration = %name, "configuration deleted");
        }
        drop(fleet);
        Ok(deleted)
    }

    /// Puts a Configuration into a Deployment (ADR-0034 clause 4); a Configuration the Server
    /// does not hold is `Missing`. Distributes nothing. Under the fleet lock, so a Configuration
    /// cannot be deleted between the check and the write.
    pub fn put_deployment_configuration(
        &self,
        name: &str,
        configuration: &str,
    ) -> Result<Deployment, DeploymentError> {
        let store = self.deployment_store().ok_or(DeploymentError::NotFound)?;
        let _fleet = self.fleet.lock().expect("fleet lock");
        if self.configs.get(configuration).is_none() {
            return Err(DeploymentError::Missing(format!(
                "no configuration {configuration:?} — save it before a deployment can hold it"
            )));
        }
        store.put_configuration(name, configuration)
    }

    /// Takes a Configuration out of a Deployment. Not gated: nothing a Deployment holds is frozen
    /// (ADR-0034 clause 7), and an Agent already released keeps its pinned revision until the next
    /// press, which drops it from the Agent's map.
    pub fn remove_deployment_configuration(
        &self,
        name: &str,
        configuration: &str,
    ) -> Result<Deployment, DeploymentError> {
        self.deployment_store()
            .ok_or(DeploymentError::NotFound)?
            .remove_configuration(name, configuration)
    }

    /// Persists one record when — and only when — its durable content changed since it was last
    /// written (ADR-0024). `last_seen_ms` and `sequence_num` are outside the comparison and ride
    /// along on whatever write happens, so the common heartbeat reaches no storage backend at
    /// all; [`flush_agents`](Self::flush_agents) is what makes them current on a graceful stop.
    /// A write that fails is logged, never fatal: a fleet that keeps running on a full disk beats
    /// one that refuses reports.
    fn persist_if_dirty(&self, uid: &InstanceUid, record: &AgentRecord) {
        if let Err(e) = self.persist(uid, record) {
            warn!(agent = %uid, error = %e, "cannot persist the agent record");
        }
    }

    /// Writes one record when its durable content changed since it was last written, and says
    /// whether the write failed — for an operator's act that must not be answered unwritten.
    fn persist(&self, uid: &InstanceUid, record: &AgentRecord) -> Result<(), String> {
        let persisted = record.to_persisted();
        let digest = persisted.durable_digest();
        let mut written = self.written.lock().expect("written lock");
        if written.get(uid) == Some(&digest) {
            return Ok(());
        }
        self.agent_store.put(uid, &persisted)?;
        written.insert(*uid, digest);
        Ok(())
    }

    /// Drops one record from the store and the dirty-check ledger — the storage half of
    /// forgetting (ADR-0024) and of an identity reassignment.
    fn unpersist(&self, uid: &InstanceUid) {
        if let Err(e) = self.agent_store.remove(uid) {
            warn!(agent = %uid, error = %e, "cannot remove the agent record from the store");
        }
        self.written.lock().expect("written lock").remove(uid);
    }

    /// Writes every record's current state, timestamps and sequence numbers included — the
    /// graceful-shutdown flush (ADR-0024) that lets the ordinary restart restore a fleet whose
    /// `last_seen` is current and whose next compressed report is accepted without a gap.
    pub fn flush_agents(&self) {
        let fleet = self.fleet.lock().expect("fleet lock");
        let mut written = self.written.lock().expect("written lock");
        for (uid, record) in fleet.iter() {
            let persisted = record.to_persisted();
            match self.agent_store.put(uid, &persisted) {
                Ok(()) => {
                    written.insert(*uid, persisted.durable_digest());
                }
                Err(e) => warn!(agent = %uid, error = %e, "cannot flush the agent record"),
            }
        }
    }

    /// The control loop for one report, shared by both transports (ADR-0013): update what we know,
    /// then answer with what the Agent still lacks — the config offer gated by the hash comparison.
    /// `conn` identifies the WebSocket connection that carried the report; `None` for plain HTTP.
    ///
    /// The reported `instance_uid` is taken at face value: admission proved fleet membership, not
    /// which Agent is speaking, so within an admitted fleet a report's identity is self-asserted and
    /// not authorized against any other Agent (ADR-0021). The plain-HTTP path in particular offers
    /// nothing to tell two pollers apart; the WebSocket duplicate-`instance_uid` rekey below is
    /// collision handling, not authorization.
    pub fn process(
        &self,
        msg: AgentToServer,
        transport: Transport,
        conn: Option<ConnId>,
    ) -> Processed {
        self.process_presented(msg, transport, conn, None)
    }

    /// [`process`](Self::process) for a connection that presented a certificate: the host it was
    /// issued to binds the Agents it reports for, and a CSR without a renewal proof renews it
    /// unless its host is a Gateway's (ADR-0021 clause 7, ADR-0039).
    pub fn process_presented(
        &self,
        msg: AgentToServer,
        transport: Transport,
        conn: Option<ConnId>,
        presented: Option<&Presented>,
    ) -> Processed {
        let mut sender = msg.instance_uid.clone();
        let Some(mut uid) = InstanceUid::from_wire(&msg.instance_uid) else {
            warn!(
                len = msg.instance_uid.len(),
                "report with a malformed instance_uid"
            );
            return Processed {
                reply: bad_request("instance_uid must be 16 bytes (UUID v7 recommended)"),
                uid: None,
                disconnected: false,
            };
        };
        // The reply is addressed to the identity the Agent reported, even when it is re-keyed
        // below: the Baseline makes a reply's instance_uid match the message's, and the Agent
        // routes by it — a reply addressed to the new identity reaches no one, and the Agent goes
        // on reporting under the old one. The new identity travels in agent_identification alone.
        let reported = uid;

        let mut fleet = self.fleet.lock().expect("fleet lock");
        let mut reply_flags = 0u64;
        let mut identification = None;

        // An instance_uid belongs to the host whose certificate first reported it (ADR-0021
        // clause 7): a certificate of another host does not speak for it, nor re-keys it. Such a
        // reporter is re-keyed — it gets an identity of its own, never the one it claimed. The
        // binding is made only once the report is admitted below.
        let mut binding = None;
        if let (Some(host), Some(revocations)) =
            (presented.and_then(|p| p.host.as_deref()), &self.revocations)
        {
            if revocations.may_report(host, uid.as_bytes()).is_err() {
                let new_uid = InstanceUid::default();
                warn!(
                    claimed = %uid, new = %new_uid, host,
                    "an Agent of another host was claimed; rekeying the reporter"
                );
                self.audit_refusal(
                    Entry::new("identity.claimed", "rekeyed")
                        .with("claimed", uid.to_string())
                        .with("host", host.to_string()),
                );
                identification = Some(AgentIdentification {
                    new_instance_uid: new_uid.as_bytes().to_vec(),
                });
                uid = new_uid;
                // A CSR in the same message must not name the claimed identity either.
                sender = uid.as_bytes().to_vec();
                if let Err(e) = revocations.may_report(host, uid.as_bytes()) {
                    return Processed {
                        reply: bad_request(&e),
                        uid: None,
                        disconnected: false,
                    };
                }
            }
            binding = Some((host, uid));
        }

        // The Agent asked the Server to assign its identity (AgentToServerFlags_RequestInstanceUid):
        // mint a UUID v7 and re-key the record; the reply tells the Agent to adopt it.
        let mut rekeyed = None;
        if identification.is_none()
            && msg.flags & AgentToServerFlags::RequestInstanceUid as u64 != 0
        {
            let new_uid = InstanceUid::default();
            if let Some(mut record) = fleet.remove(&uid) {
                // The labels go with it (ADR-0035 clause 6); the old identity leaves its group,
                // and the new one is placed below.
                let group = record.placement.group.take();
                fleet.insert(new_uid, record);
                self.unplace(&mut fleet, &uid, group);
                // The persisted record follows the identity (ADR-0024): the old key leaves the
                // store now, the new one is written by the dirty check at this exchange's end.
                self.unpersist(&uid);
            }
            info!(old = %uid, new = %new_uid, "assigned a server-generated instance_uid");
            identification = Some(AgentIdentification {
                new_instance_uid: new_uid.as_bytes().to_vec(),
            });
            rekeyed = Some((uid, new_uid));
            uid = new_uid;
        }

        // Duplicate instance_uid detection (a Baseline SHOULD): the same identity alive on
        // *another* WebSocket connection — bad UID generators, cloned VMs — is rekeyed exactly
        // as the Baseline prescribes: mint a fresh uid and answer with AgentIdentification,
        // which the Client adopts. The newcomer starts a record of its own; the incumbent and
        // its connection stay untouched. (Stateless plain-HTTP polling offers nothing to
        // distinguish two pollers by, so detection is WebSocket-only.)
        if let Some(this_conn) = conn {
            let duplicate = fleet.get(&uid).is_some_and(|existing| {
                existing.connected && existing.owner.is_some_and(|owner| owner != this_conn)
            });
            if duplicate {
                let new_uid = InstanceUid::default();
                warn!(duplicate = %uid, new = %new_uid, "duplicate instance_uid; rekeying the newcomer");
                identification = Some(AgentIdentification {
                    new_instance_uid: new_uid.as_bytes().to_vec(),
                });
                uid = new_uid;
            }
        }

        let known = fleet.contains_key(&uid);
        // Admitting a genuinely new Agent past the ceiling would let a peer cycling self-asserted
        // UIDs (ADR-0021) grow the in-memory map and its per-Agent disk mirror without bound. Known
        // Agents keep reporting; only a *new* UID at capacity is refused, `Unavailable` so a Client
        // that legitimately raced in retries rather than gives up. The real gate is admission
        // (ADR-0021); this bounds the damage while the endpoint is open.
        if !known && fleet.len() >= self.max_agents {
            drop(fleet);
            warn!(
                agent = %uid,
                max_agents = self.max_agents,
                "refusing a new agent: the fleet is at its record ceiling"
            );
            return Processed {
                reply: unavailable(
                    &msg.instance_uid,
                    "the Server is at its Agent-record ceiling; retry later",
                ),
                uid: None,
                disconnected: false,
            };
        }
        if let Some(revocations) = &self.revocations {
            if let Some((host, bound)) = binding {
                let subject = presented
                    .map(|p| p.subject_values.clone())
                    .unwrap_or_default();
                // The binding exists only for a presented certificate that names a host.
                let not_after_ms = presented.map_or(0, |p| p.not_after_ms);
                if let Err(e) =
                    revocations.check_report(host, &subject, not_after_ms, bound.as_bytes())
                {
                    return Processed {
                        reply: bad_request(&e),
                        uid: None,
                        disconnected: false,
                    };
                }
            }
            // A re-key an Agent asks for keeps its host (ADR-0021 clause 7).
            if let Some((old, new)) = rekeyed {
                if let Err(e) = revocations.rebind(old.as_bytes(), new.as_bytes()) {
                    warn!(error = %e, "cannot move the host binding to the new instance_uid");
                }
            }
        }
        let record = fleet.entry(uid).or_insert_with(|| {
            info!(agent = %uid, transport = transport.as_str(), "new agent");
            AgentRecord {
                labels: BTreeMap::new(),
                host: None,
                placement: Placement::default(),
                sequence_num: msg.sequence_num,
                capabilities: 0,
                description: None,
                health: None,
                effective_config: None,
                remote_config_status: None,
                transport,
                connected: true,
                last_seen_ms: self.clock.now_ms(),
                restart_pending: false,
                available_components: None,
                connection_settings_status: None,
                package_statuses: None,
                owner: conn,
                // A new Agent waits (ADR-0025 point 6): it is assigned nothing until an
                // operator's rollout act says so, and the fleet view shows what it could get.
                assignment: None,
            }
        });

        // A compressed report (unchanged fields omitted) is only usable if our state is current.
        // A gap in sequence_num — or an Agent we have never seen describing itself with nothing —
        // means state was lost somewhere; the Baseline's recovery is to demand a full report.
        let compressed = msg.agent_description.is_none();
        let gap = known && msg.sequence_num != record.sequence_num.wrapping_add(1);
        if compressed && (!known || gap) {
            reply_flags |= ServerToAgentFlags::ReportFullState as u64;
        }

        // The Host it arrived over (ADR-0035 clause 2) — none without a host register.
        let arrived_over = self
            .revocations
            .as_ref()
            .and(presented.and_then(|p| p.host.clone()));
        let moved = record.host != arrived_over;
        record.host = arrived_over;
        let described = msg.agent_description.is_some();

        record.sequence_num = msg.sequence_num;
        record.transport = transport;
        record.connected = true;
        record.owner = conn;
        record.last_seen_ms = self.clock.now_ms();
        if msg.capabilities != 0 {
            record.capabilities = msg.capabilities;
        }
        if let Some(description) = msg.agent_description {
            record.description = Some(description);
        }
        if let Some(health) = msg.health {
            record.health = Some(health);
        }
        if let Some(effective) = msg.effective_config {
            record.effective_config = Some(config_map_text(effective.config_map.as_ref()));
        }
        if let Some(status) = msg.remote_config_status {
            record.remote_config_status = Some(status);
        }
        if let Some(status) = msg.connection_settings_status {
            if status.status == opamp::proto::ConnectionSettingsStatuses::Failed as i32 {
                warn!(agent = %uid, error = %status.error_message, "connection settings rejected");
            }
            record.connection_settings_status = Some(status);
        }
        if let Some(statuses) = msg.package_statuses {
            use opamp::proto::PackageStatusEnum as P;
            for (name, status) in &statuses.packages {
                let before = record
                    .package_statuses
                    .as_ref()
                    .and_then(|previous| previous.packages.get(name))
                    .map(|previous| (previous.status, previous.agent_has_version.clone()));
                let outcome = if status.status == P::Installed as i32 {
                    Some("installed")
                } else if status.status == P::InstallFailed as i32 {
                    Some("failed")
                } else {
                    None
                };
                if let (Some(outcome), true) = (
                    outcome,
                    before != Some((status.status, status.agent_has_version.clone())),
                ) {
                    self.audit_refusal(
                        Entry::new("package.outcome", outcome)
                            .with("instance_uid", uid.to_string())
                            .with("package", name.clone())
                            .with("version", status.agent_has_version.clone())
                            .with("offered_version", status.server_offered_version.clone())
                            .with(
                                "error",
                                (!status.error_message.is_empty())
                                    .then(|| status.error_message.clone()),
                            ),
                    );
                }
            }
            for status in statuses.packages.values() {
                if status.status == opamp::proto::PackageStatusEnum::InstallFailed as i32 {
                    warn!(agent = %uid, package = %status.name, error = %status.error_message, "package installation failed");
                }
            }
            // An Agent that refuses the offer itself has no package to hang the reason on, so the
            // report carries it. Logged and surfaced, or a Client refusing every offer it is sent
            // would look like one that is simply not installing anything.
            if !statuses.error_message.is_empty() {
                warn!(agent = %uid, error = %statuses.error_message, "the agent refused the package offer");
            }
            record.package_statuses = Some(statuses);
        }
        if let Some(incoming) = msg.available_components {
            // A routine hash-only update must not degrade an already-fetched full map of the
            // same hash; anything else (first sight, or a changed hash) replaces the stored value.
            let keep_stored_full = record.available_components.as_ref().is_some_and(|stored| {
                incoming.components.is_empty()
                    && !stored.components.is_empty()
                    && stored.hash == incoming.hash
            });
            if !keep_stored_full {
                record.available_components = Some(incoming);
            }
        }

        // What places it in its Client and under its Host may have changed (ADR-0035): a new
        // record, a new Host, a new description, or a new identity — a re-key took the old one
        // out of its group, and a compressed message carries no description to place it by.
        if !known || moved || described || rekeyed.is_some() {
            self.place(&mut fleet, &uid);
        }
        let record = fleet.get_mut(&uid).expect("the record was just written");

        // The Agent asked to be issued a client certificate (ADR-0021). Signing it here, on the
        // connection it arrived over, is the whole of the approval: admission already required
        // every proof this endpoint asks of any message, which is what the Baseline's flow means
        // by awaiting one.
        let issued = match msg
            .connection_settings_request
            .as_ref()
            .and_then(|request| request.opamp.as_ref())
            .and_then(|opamp| opamp.certificate_request.as_ref())
        {
            None => None,
            Some(request) => {
                // `Ok(Err(..))` is a request the Server refuses; `Err(..)` a record it cannot write,
                // which the Agent retries (ADR-0022 clause 6).
                let outcome: Result<Result<Signed, String>, String> = match &self.client_ca {
                    // The Baseline's MUST when the Server cannot act on the request. An Agent
                    // reaching here ignored the undeclared capability, so it is a client error.
                    None => Ok(Err("this Server issues no client certificates".to_string())),
                    Some(ca) => match String::from_utf8(request.csr.clone())
                        .map_err(|_| "the certificate signing request is not PEM".to_string())
                        .and_then(|csr| {
                            // The message's own instance_uid, before any re-key (ADR-0021).
                            ca.check_claims(&csr, &sender)?;
                            let (predecessor, host, subject) =
                                self.renews(ca.as_ref(), &csr, presented)?;
                            Ok((ca.sign(&csr, &host, &subject)?, predecessor))
                        }) {
                        Err(e) => Ok(Err(e)),
                        Ok((signed, predecessor)) => self
                            .record_issued(&signed, &sender, predecessor)
                            .map(|()| Ok(signed)),
                    },
                };
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        warn!(agent = %uid, error = %e, "held back a certificate: the audit record is unavailable");
                        self.persist_if_dirty(&uid, record);
                        return Processed {
                            reply: unavailable(&msg.instance_uid, &e),
                            uid: Some(uid),
                            disconnected: false,
                        };
                    }
                };
                match outcome {
                    Ok(signed) => {
                        info!(
                            agent = %uid,
                            serial = %signed.facts.id.serial,
                            "issued a client certificate"
                        );
                        Some(TlsCertificate {
                            cert: signed.pem.into_bytes(),
                            // The Agent generated its own key and keeps it — the point of the CSR
                            // flow — so the Server has nothing to put here and must not invent it.
                            private_key: Vec::new(),
                            ..Default::default()
                        })
                    }
                    Err(e) => {
                        warn!(agent = %uid, error = %e, "refused a certificate signing request");
                        self.audit_refusal(
                            Entry::new("issuance.refused", "refused")
                                .with("instance_uid", uid.to_string())
                                .with("reason", e.clone()),
                        );
                        // The report's updates above are already in the record, so they are
                        // persisted even though the CSR is refused (ADR-0024).
                        self.persist_if_dirty(&uid, record);
                        return Processed {
                            reply: bad_request(&e),
                            uid: Some(uid),
                            disconnected: false,
                        };
                    }
                }
            }
        };

        let disconnected = msg.agent_disconnect.is_some();
        if disconnected {
            info!(agent = %uid, "agent disconnected");
            record.connected = false;
            record.owner = None;
        }

        // A hash without the map is an offer to fetch: demand the full component list from an
        // Agent that declared it can report one (the flag is meaningless toward any other).
        if !disconnected
            && record.capabilities
                & opamp::proto::AgentCapabilities::ReportsAvailableComponents as u64
                != 0
            && record
                .available_components
                .as_ref()
                .is_some_and(|ac| ac.components.is_empty())
        {
            reply_flags |= ServerToAgentFlags::ReportAvailableComponents as u64;
        }

        // A queued restart goes out as the Baseline's command-only message: nothing but
        // identity, capabilities, and the command. Anything else the reply would carry —
        // an identity reassignment, a demanded full report — defers the command to the next
        // exchange instead of being combined with it.
        if record.restart_pending
            && !disconnected
            && identification.is_none()
            && reply_flags == 0
            && record.capabilities & opamp::proto::AgentCapabilities::AcceptsRestartCommand as u64
                != 0
        {
            record.restart_pending = false;
            self.persist_if_dirty(&uid, record);
            return Processed {
                reply: restart_command(&uid, self.capabilities()),
                uid: Some(uid),
                disconnected: false,
            };
        }

        // Everything this report changed is in the record now; persist it if it moved the
        // durable state (ADR-0024) — a heartbeat did not, and writes nothing.
        self.persist_if_dirty(&uid, record);

        // The config offer — composed from this Agent's assignments (ADR-0025), gated by the
        // hash comparison, and only toward an Agent that both said goodbye ≠ true and declared
        // AcceptsRemoteConfig (capability negotiation is binding). Matching proposes; only an
        // operator's rollout act made anything an assignment.
        let remote_config = if disconnected {
            None
        } else {
            let desired = self.configs.compose(record.assigned_configurations());
            offer(record, desired.as_ref())
        };

        // The connection-settings offer (ADR-0014), gated the same way: by capability and by
        // the hash the Agent last reported — the Baseline's own "compare and include" MUST.
        let connection_settings = if disconnected {
            None
        } else {
            self.settings_offer(record, issued)
        };

        // The package offer (ADR-0026), gated by capability and the reported
        // server_provided_all_packages_hash — the Baseline's "compare and include" for packages.
        let packages_available = if disconnected {
            None
        } else {
            self.packages_offer(record)
        };

        Processed {
            reply: ServerToAgent {
                instance_uid: reported.as_bytes().to_vec(),
                capabilities: self.capabilities(),
                flags: reply_flags,
                remote_config,
                connection_settings,
                packages_available,
                agent_identification: identification,
                ..Default::default()
            },
            uid: Some(uid),
            disconnected,
        }
    }

    /// The package offer for one Agent, composed from its **assignments** (ADR-0025), or `None`
    /// when it cannot accept packages, is assigned nothing it fits, or the aggregate hash it last
    /// reported already matches what it is assigned.
    ///
    /// Both the offer and the aggregate are computed over *this Agent's* assignments: comparing
    /// against a fleet-wide aggregate would re-offer, on every exchange, packages this Agent is
    /// never given.
    fn packages_offer(&self, record: &AgentRecord) -> Option<PackagesAvailable> {
        let offering = self.packages.as_ref()?;
        if !accepts_packages(record) {
            return None;
        }
        let effective = record.effective_description();
        let description = effective.as_deref();
        let assigned = record.assigned_package();
        let reported = record
            .package_statuses
            .as_ref()
            .map(|s| s.server_provided_all_packages_hash.as_slice())
            .unwrap_or_default();
        if reported
            == offering
                .store
                .assigned_hash_for(assigned, description)
                .as_slice()
        {
            return None;
        }
        offering.store.offer_for_assigned(assigned, description)
    }

    /// Whether a certificate naming `host` may fetch the artifact `(id, platform)` from the download
    /// route (ADR-0026): it is offered to an Agent the host speaks for. The offer's own test
    /// decides (ADR-0033 clause 10), for each such Agent — the `instance_uid`s bound to the host, or
    /// every Agent for a host marked as a Gateway. Nothing is offered without package delivery or a
    /// host register.
    ///
    /// The package store and the host register are read first and released before the fleet is
    /// locked: no two of those locks are held together here.
    pub fn offers_artifact(&self, host: &str, id: &PackageId, platform: &Platform) -> bool {
        let (Some(offering), Some(revocations)) = (&self.packages, &self.revocations) else {
            return false;
        };
        // What does not depend on the Agent is resolved once, before the fleet is locked.
        let Some(artifact) = offering.store.offerable(id, platform) else {
            return false;
        };
        let speaks_for = revocations.speaks_for(host);
        let fleet = self.fleet.lock().expect("fleet lock");
        let offered = |record: &AgentRecord| {
            // The cheap half of the test first: most Agents are assigned something else.
            accepts_packages(record)
                && record.assigned_package() == Some(id)
                && artifact.offered_to(
                    record.assigned_package(),
                    record.effective_description().as_deref(),
                )
        };
        match speaks_for {
            SpeaksFor::Any => fleet.values().any(offered),
            SpeaksFor::Agents(uids) => uids
                .iter()
                .filter_map(|uid| <[u8; 16]>::try_from(hex::decode(uid).ok()?).ok())
                .filter_map(|uid| fleet.get(&InstanceUid(uid)))
                .any(offered),
        }
    }

    /// Why this Agent is **proposed** nothing: more than one Deployment claims it, and an Agent
    /// belongs to at most one (ADR-0026 point 26). `None` when nothing is wrong. Every Agent can be
    /// in conflict, since a Deployment carries Configurations as well as Packages (ADR-0034).
    ///
    /// A conflict takes the *candidate* away and never a standing assignment: an Agent already
    /// rolled out to keeps its offer, because nothing distributes or un-distributes by itself
    /// (ADR-0025). Creating an overlapping channel must not withdraw anything from a running host.
    ///
    /// `claim` is what [`deployment_for`] answered for this Agent — `Ok(None)` when package
    /// delivery, which arms the Deployments, is not configured.
    fn package_conflict(claim: &Result<Option<&Deployment>, String>) -> Option<String> {
        claim.as_ref().err().cloned()
    }

    /// The connection-settings offer for one Agent, or `None` when it cannot accept one or its
    /// reported hash says it already runs (or refused) exactly this offer.
    ///
    /// `issued` is a certificate just signed for this Agent (ADR-0021). It overrides the hash gate
    /// — the Agent asked for it in this very exchange — and rides whatever else the standing offer
    /// carries, so one message can hand over a certificate and the endpoint or heartbeat that go
    /// with it, exactly as the Baseline describes.
    fn settings_offer(
        &self,
        record: &AgentRecord,
        issued: Option<TlsCertificate>,
    ) -> Option<ConnectionSettingsOffers> {
        // The own-telemetry destinations (ADR-0016), offered only for the signals this Agent says
        // it can report — the protocol's negotiation rule, and an offer for a capability the peer
        // lacks is one nobody will ever act on.
        let telemetry = TelemetryOffer {
            own_metrics: self.telemetry_offer.own_metrics.clone().filter(|_| {
                record.capabilities & opamp::proto::AgentCapabilities::ReportsOwnMetrics as u64 != 0
            }),
            own_traces: self.telemetry_offer.own_traces.clone().filter(|_| {
                record.capabilities & opamp::proto::AgentCapabilities::ReportsOwnTraces as u64 != 0
            }),
            own_logs: self.telemetry_offer.own_logs.clone().filter(|_| {
                record.capabilities & opamp::proto::AgentCapabilities::ReportsOwnLogs as u64 != 0
            }),
        };

        if let Some(certificate) = issued {
            let mut settings = self
                .connection_offer
                .as_ref()
                .map(|offer| offer.settings.clone())
                .unwrap_or_default();
            settings.certificate = Some(certificate);
            // Not gated, and hashed over the settings as sent: the standing offer's hash would
            // tell the Agent nothing changed, and it would never adopt the certificate.
            return Some(compose_settings_offer(Some(settings), telemetry));
        }

        // An Agent that accepts no OpAMP settings may still report telemetry, so the two are
        // gated separately: with only a telemetry destination to offer, that is the whole offer.
        let settings = self
            .connection_offer
            .as_ref()
            .filter(|_| {
                record.capabilities
                    & opamp::proto::AgentCapabilities::AcceptsOpAmpConnectionSettings as u64
                    != 0
            })
            .map(|offer| offer.settings.clone());
        if settings.is_none() && telemetry.is_empty() {
            return None;
        }
        gate(record, compose_settings_offer(settings, telemetry))
    }

    /// The unsolicited offer a WebSocket loop pushes when a rollout act changes an assignment;
    /// `None` when the Agent already runs both (or is assigned nothing, or it cannot accept
    /// one), so nothing redundant crosses the wire.
    pub fn offer_for(&self, uid: &InstanceUid) -> Option<ServerToAgent> {
        let fleet = self.fleet.lock().expect("fleet lock");
        let record = fleet.get(uid)?;
        let desired = self.configs.compose(record.assigned_configurations());
        let remote_config = offer(record, desired.as_ref());
        let packages_available = self.packages_offer(record);
        if remote_config.is_none() && packages_available.is_none() {
            return None;
        }
        Some(ServerToAgent {
            instance_uid: uid.as_bytes().to_vec(),
            capabilities: self.capabilities(),
            remote_config,
            packages_available,
            ..Default::default()
        })
    }

    /// Package delivery, or the error every package route and rollout act answers when it is not
    /// configured.
    fn offering(&self) -> Result<&PackageOffering, String> {
        self.packages
            .as_ref()
            .ok_or_else(|| "package delivery is not configured on this Server".to_string())
    }

    /// The package store, or the same refusal as [`offering`](Self::offering).
    fn package_store(&self) -> Result<&PackageStore, String> {
        self.offering().map(PackageOffering::store)
    }

    /// Whether any Agent's assignment references this Package — the gate that makes an assigned
    /// Package's bytes immutable (ADR-0025 point 8). The Agent store answers it (ADR-0037
    /// clause 3); the fleet lock keeps a rollout from pinning it meanwhile.
    fn package_set_assigned(&self, id: &PackageId) -> bool {
        let _fleet = self.fleet.lock().expect("fleet lock");
        self.agent_store.pinning(Pin::Package(id)) > 0
    }

    /// Puts a Package into a channel (ADR-0026 point 23). Not gated: adding one for an Agent type
    /// the channel does not hold surfaces as waiting on the Agents of that type, and replacing the
    /// one it holds is how a rollout proceeds — an Agent already rolled out to keeps the Package
    /// its assignment pins until the next act.
    pub fn put_deployment_package(
        &self,
        name: &str,
        id: &PackageId,
        replace: bool,
    ) -> Result<Deployment, DeploymentError> {
        self.deployment_store()
            .ok_or(DeploymentError::NotFound)?
            .put_package(name, id, replace)
    }

    /// Takes a Package out of a channel. Not gated: nothing a Deployment holds is frozen
    /// (ADR-0034 clause 7) — an assignment pins the Package itself, so an Agent already released
    /// keeps its offer until the next press.
    pub fn remove_deployment_package(
        &self,
        name: &str,
        id: &PackageId,
    ) -> Result<Deployment, DeploymentError> {
        self.deployment_store()
            .ok_or(DeploymentError::NotFound)?
            .remove_package(name, id)
    }

    /// Deletes a Deployment — **refused while an Agent's assignment names it** (ADR-0034 clause 8).
    ///
    /// An assignment points at the channel it was released through, and the fleet view names it.
    /// So the operator ends that first, by an act that says so: rolling those Agents out through
    /// another Deployment, or forgetting them.
    ///
    /// The fleet lock is held across the check and the delete, so a rollout cannot assign through
    /// the channel in between.
    pub fn delete_deployment(&self, name: &str) -> Result<bool, DeploymentError> {
        let store = self.deployment_store().ok_or(DeploymentError::NotFound)?;
        let fleet = self.fleet.lock().expect("fleet lock");
        let pinning = self.agent_store.pinning(Pin::Deployment(name));
        if pinning > 0 {
            return Err(DeploymentError::Conflict(format!(
                "deployment {name:?} is pinned by the assignment of {pinning} Agent(s) — roll them \
                 out through another deployment, or forget them, before deleting it"
            )));
        }
        let deleted = store.delete(name)?;
        drop(fleet);
        if deleted {
            info!(deployment = %name, "deployment deleted");
        }
        Ok(deleted)
    }

    /// The refusal every write to an assigned Package answers with (ADR-0025 point 8).
    fn refuse_if_assigned(&self, id: &PackageId) -> Result<(), String> {
        if self.package_set_assigned(id) {
            return Err(format!(
                "set {id} is assigned to an Agent and its entries are immutable — create the \
                 next version as a new set and roll that out"
            ));
        }
        Ok(())
    }

    /// Creates a Package (ADR-0026). **Nothing is distributed** (ADR-0025), and there is nothing
    /// to update: a Package is its identity and its entries, so creating one that exists is the
    /// same request arriving twice.
    pub fn create_package_set(&self, id: &PackageId) -> Result<(), String> {
        self.package_store()?.create(id)?;
        info!(package = %id, "package stored — nothing distributed");
        Ok(())
    }

    /// Stores one streamed upload as an entry of a Package (ADR-0026, ADR-0037). Refused while the
    /// Package is assigned to an Agent (ADR-0025 point 8); no push, because saving never
    /// distributes.
    pub fn put_package_entry(
        &self,
        id: &PackageId,
        platform: &Platform,
        bytes: &mut dyn std::io::Read,
    ) -> Result<(), String> {
        self.refuse_if_assigned(id)?;
        self.package_store()?.put_entry_from(id, platform, bytes)?;
        info!(set = %id, platform = %format!("{}-{}", platform.os, platform.arch), "package entry stored");
        Ok(())
    }

    /// Whether an upload for one entry of `id` may begin: the Package exists and is not assigned
    /// to an Agent (ADR-0025 point 8), so a refused upload is refused before its bytes are
    /// streamed.
    pub fn check_package_upload(&self, id: &PackageId) -> Result<(), String> {
        self.refuse_if_assigned(id)?;
        self.package_store()?.writable(id)
    }

    /// Writes the operator's signature onto one entry of a Package (ADR-0033), and answers what the
    /// Server found when it checked it. Refused while the Package is assigned to an Agent, like
    /// any other write to its entries (ADR-0025 point 8): the re-offer gate does not cover the
    /// signature, so one changed under a standing offer would never reach the Agent.
    pub fn put_package_entry_signature(
        &self,
        id: &PackageId,
        platform: &Platform,
        signature: Vec<u8>,
    ) -> Result<SignatureState, String> {
        self.refuse_if_assigned(id)?;
        let state = self
            .package_store()?
            .put_signature(id, platform, signature)?;
        info!(set = %id, platform = %platform.tag(), state = state.as_str(), "package entry signed");
        Ok(state)
    }

    /// Takes one entry's signature away (ADR-0033); `Ok(false)` when it carries none. Refused
    /// while the Package is assigned to an Agent (ADR-0025 point 8).
    pub fn remove_package_entry_signature(
        &self,
        id: &PackageId,
        platform: &Platform,
    ) -> Result<bool, String> {
        self.refuse_if_assigned(id)?;
        let removed = self.package_store()?.remove_signature(id, platform)?;
        if removed {
            info!(set = %id, platform = %platform.tag(), "package entry signature removed");
        }
        Ok(removed)
    }

    /// Deletes one entry of a Package; `Ok(false)` when the Package or entry does not exist.
    /// Refused while the Package is assigned to an Agent (ADR-0025 point 8).
    pub fn delete_package_entry(
        &self,
        id: &PackageId,
        platform: &Platform,
    ) -> Result<bool, String> {
        self.refuse_if_assigned(id)?;
        let deleted = self.package_store()?.delete_entry(id, platform)?;
        if deleted {
            info!(set = %id, "package entry deleted");
        }
        Ok(deleted)
    }

    /// Deletes a Package (ADR-0034 clause 8); `Ok(false)` when none of that identity exists.
    /// **Refused while any Agent's assignment pins it** — the message says how many — because a
    /// deletion must not change what a running Agent receives. A deleted Package leaves every
    /// Deployment that held it. Nothing is uninstalled either way (ADR-0026).
    ///
    /// The fleet lock is held across the check and the delete, so a rollout cannot pin it in
    /// between.
    pub fn delete_package_set(&self, id: &PackageId) -> Result<bool, String> {
        let fleet = self.fleet.lock().expect("fleet lock");
        let pinning = self.agent_store.pinning(Pin::Package(id));
        if pinning > 0 {
            return Err(format!(
                "package {id} is pinned by the assignment of {pinning} Agent(s) — roll them out \
                 through a Deployment without it, or forget them, before deleting it"
            ));
        }
        let deleted = self.package_store()?.delete_set(id)?;
        if deleted {
            if let Some(store) = self.deployment_store() {
                let left = store.drop_package(id).map_err(|e| e.to_string())?;
                if !left.is_empty() {
                    info!(set = %id, deployments = ?left, "package left the deployments that held it");
                }
            }
            info!(set = %id, "package set deleted");
        }
        drop(fleet);
        Ok(deleted)
    }

    /// Marks the Agents a closing WebSocket connection carried as no longer connected — but only
    /// those the connection still *owns*: after a rekey (or a transport switch) another live
    /// connection may legitimately carry an identity this one once saw, and a closing socket
    /// must not take it down. State stays: the fleet remembers what each Agent last reported.
    pub fn mark_disconnected(&self, uids: &[InstanceUid], conn: ConnId) {
        let mut fleet = self.fleet.lock().expect("fleet lock");
        for uid in uids {
            if let Some(record) = fleet.get_mut(uid) {
                if record.owner == Some(conn) {
                    record.connected = false;
                    record.owner = None;
                }
            }
        }
    }

    /// The Agents each Host carries (ADR-0035 clause 7) — those whose record names it as the Host
    /// they last arrived over — and the name it is displayed by: the `host.name` its Client Agent
    /// reports, when it has exactly one on a direct connection. Shown only; it decides nothing.
    pub fn host_agents(&self) -> BTreeMap<String, HostAgents> {
        let fleet = self.fleet.lock().expect("fleet lock");
        let mut hosts: BTreeMap<String, HostAgents> = BTreeMap::new();
        for (uid, record) in fleet.iter() {
            let Some(host) = &record.host else { continue };
            let reported = |key: &str| {
                record
                    .description
                    .as_ref()
                    .and_then(|d| {
                        attributes::string_value(&d.identifying_attributes, key).or_else(|| {
                            attributes::string_value(&d.non_identifying_attributes, key)
                        })
                    })
                    .unwrap_or_default()
                    .to_string()
            };
            let entry = hosts.entry(host.clone()).or_default();
            let is_client_agent = record.placement.client_agent == Some(*uid);
            if is_client_agent && record.placement.group == Some(Group::Host(host.clone())) {
                entry.name = Some(reported("host.name")).filter(|name| !name.is_empty());
            }
            entry.agents.push(HostAgentView {
                instance_uid: uid.to_string(),
                service_name: reported(attributes::SERVICE_NAME),
                service_instance_name: reported(attributes::SERVICE_INSTANCE_NAME),
                host_name: reported("host.name"),
                client: crate::labels::is_client_agent(record.description.as_ref()),
                client_agent: record
                    .placement
                    .client_agent
                    .map(|uid| uid.to_string())
                    .unwrap_or_default(),
                machine: match &record.placement.group {
                    Some(Group::Behind { machine, .. }) => machine.clone(),
                    _ => String::new(),
                },
                ambiguous: record.placement.ambiguous,
                connected: record.connected,
            });
        }
        for entry in hosts.values_mut() {
            entry
                .agents
                .sort_by(|a, b| a.instance_uid.cmp(&b.instance_uid));
        }
        hosts
    }

    /// The REST view of the fleet (`GET /api/v1/agents`).
    pub fn snapshot(&self) -> Vec<AgentView> {
        let fleet = self.fleet.lock().expect("fleet lock");
        // One copy of the Deployments for the whole view, rather than one per Agent.
        let deployments = self.deployment_store().map(DeploymentStore::snapshot);
        let mut agents: Vec<AgentView> = fleet
            .iter()
            .map(|(uid, record)| {
                // One derived description for everything below, so a label can never mean one
                // thing for the offer and another for what the view proposes.
                let effective = record.effective_description();
                let desired = self.configs.compose(record.assigned_configurations());
                let claim = match &deployments {
                    Some(all) => deployment_for(all, effective.as_deref()),
                    None => Ok(None),
                };
                let package_conflict = Self::package_conflict(&claim);
                let claimed = claim.ok().flatten();
                // Which channel claims it *now* — the other half of the answer, so "no channel" and
                // "a channel with nothing for me" are not the same empty row (ADR-0026 point 25).
                let claiming_deployment = claimed.map(|d| d.name.clone()).unwrap_or_default();

                // What a press would release to it now (ADR-0034 clause 6). A conflict, or no
                // channel at all, proposes nothing — `package_conflict` says why.
                let proposed = self
                    .packages()
                    .zip(claimed)
                    .map(|(store, deployment)| self.release(store, deployment, record));
                let matched = proposed
                    .iter()
                    .flatten()
                    .flat_map(|release| release.configurations.keys().cloned())
                    .collect();
                let waits = match (&proposed, claimed) {
                    (Some(release), Some(deployment)) => {
                        waiting(record.assignment.as_ref(), release.as_ref(), deployment)
                    }
                    _ => Waiting::default(),
                };

                AgentView::from_record(
                    uid,
                    record,
                    desired.as_ref(),
                    matched,
                    package_conflict,
                    claiming_deployment,
                    waits,
                    is_stale(record, self.stale_after(), self.clock.now_ms()),
                )
            })
            .collect();
        agents.sort_by(|a, b| a.instance_uid.cmp(&b.instance_uid));
        agents
    }
}

/// Takes `uid` out of `group`, and the group out of the index once it holds nobody.
fn unindex(groups: &mut HashMap<Group, HashSet<InstanceUid>>, group: &Group, uid: &InstanceUid) {
    if let Some(members) = groups.get_mut(group) {
        members.remove(uid);
        if members.is_empty() {
            groups.remove(group);
        }
    }
}

/// Places the members of one group under their Client Agent (ADR-0035 clause 4): with exactly
/// one, the others inherit its labels; with more than one, nobody inherits and every member is
/// marked ambiguous; with none, nobody inherits.
fn inherit(
    fleet: &mut HashMap<InstanceUid, AgentRecord>,
    groups: &HashMap<Group, HashSet<InstanceUid>>,
    group: &Group,
) {
    let Some(members) = groups.get(group) else {
        return;
    };
    let clients: Vec<InstanceUid> = members
        .iter()
        .filter(|uid| {
            fleet
                .get(uid)
                .is_some_and(|record| crate::labels::is_client_agent(record.description.as_ref()))
        })
        .copied()
        .collect();
    let (client_agent, labels) = match clients.as_slice() {
        [one] => (Some(*one), fleet[one].labels.clone()),
        _ => (None, BTreeMap::new()),
    };
    let ambiguous = clients.len() > 1;
    for uid in members {
        if let Some(record) = fleet.get_mut(uid) {
            record.placement.client_agent = client_agent;
            record.placement.inherited = if client_agent == Some(*uid) {
                BTreeMap::new()
            } else {
                labels.clone()
            };
            record.placement.ambiguous = ambiguous;
        }
    }
}

/// What waits for one Agent's next press — every part in which what the claiming Deployment
/// would release differs from what the assignment pins.
#[derive(Default)]
struct Waiting {
    configurations: Vec<PendingConfigurationView>,
    packages: Vec<PendingPackageView>,
    /// The Deployment the press would release through, when the assignment names another one or
    /// none.
    deployment: String,
}

/// What waits for an Agent's next press (ADR-0025 clause 4, ADR-0034 clauses 5 and 6): the
/// difference between what the claiming Deployment would release and what the assignment pins,
/// per Configuration, for the Package, and for the Deployment the release goes through — so
/// whatever makes a press move this Agent shows here, and the reach count agrees with the view.
///
/// `new` is not pinned yet, `update` is pinned at another revision or version, and `remove` is
/// pinned and leaves the release — the Deployment no longer holds it, or no longer fits it to this
/// Agent — while the release keeps something else, so the smaller assignment is applied. `kept` is
/// pinned while the release holds nothing for the Agent at all: the press leaves it with no
/// assignment, it is offered nothing, and it keeps running what it runs (ADR-0034 clause 6).
fn waiting(
    assigned: Option<&Assignment>,
    release: Option<&Assignment>,
    deployment: &Deployment,
) -> Waiting {
    let dropped = if release.is_some() { "remove" } else { "kept" };
    let pinned = assigned.map_or(&NO_CONFIGURATIONS, |a| &a.configurations);
    let released = release.map_or(&NO_CONFIGURATIONS, |a| &a.configurations);
    let mut configurations: Vec<PendingConfigurationView> = released
        .iter()
        .filter_map(|(name, hash)| {
            let change = match pinned.get(name) {
                Some(pinned) if pinned == hash => return None,
                Some(_) => "update",
                None => "new",
            };
            Some(PendingConfigurationView {
                name: name.clone(),
                change: change.to_string(),
            })
        })
        .chain(
            pinned
                .keys()
                .filter(|name| !released.contains_key(*name))
                .map(|name| PendingConfigurationView {
                    name: name.clone(),
                    change: dropped.to_string(),
                }),
        )
        .collect();
    configurations.sort_by(|a, b| a.name.cmp(&b.name));
    let pinned_package = assigned.and_then(|a| a.package.as_ref());
    let released_package = release.and_then(|a| a.package.as_ref());
    let package = match (pinned_package, released_package) {
        (Some(pinned), Some(released)) if pinned == released => None,
        (Some(_), Some(released)) => Some((released, "update")),
        (None, Some(released)) => Some((released, "new")),
        (Some(pinned), None) => Some((pinned, dropped)),
        (None, None) => None,
    };
    let packages = package
        .map(|(id, change)| PendingPackageView {
            deployment: deployment.name.clone(),
            agent_type: id.agent_type.clone(),
            version: id.version.clone(),
            display_name: id.display_name(),
            change: change.to_string(),
        })
        .into_iter()
        .collect();
    let through = release
        .map(|r| r.deployment.as_str())
        .filter(|through| assigned.map(|a| a.deployment.as_str()) != Some(*through))
        .unwrap_or_default();
    Waiting {
        configurations,
        packages,
        deployment: through.to_string(),
    }
}

/// Whether this Agent declared that it accepts packages — the first condition of every offer
/// (ADR-0026 clause 35).
fn accepts_packages(record: &AgentRecord) -> bool {
    record.capabilities & opamp::proto::AgentCapabilities::AcceptsPackages as u64 != 0
}

/// The remote-config offer for one Agent, or `None` when the hash comparison says it already has
/// it — the "no redundant reconfiguration" goal in one place. Every assigned Configuration is one
/// named entry; the Managed Process does its own merging (ADR-0023).
fn offer(record: &AgentRecord, desired: Option<&DesiredConfig>) -> Option<AgentRemoteConfig> {
    let desired = desired?;
    if record.capabilities & opamp::proto::AgentCapabilities::AcceptsRemoteConfig as u64 == 0 {
        return None;
    }
    let reported = record
        .remote_config_status
        .as_ref()
        .map(|s| s.last_remote_config_hash.as_slice())
        .unwrap_or_default();
    if reported == desired.hash.as_slice() {
        return None;
    }
    Some(AgentRemoteConfig {
        config: Some(AgentConfigMap {
            config_map: desired
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.name.clone(),
                        AgentConfigObject {
                            body: entry.body.clone().into_bytes(),
                            content_type: String::new(),
                            // The operator's role, verbatim (ADR-0023). Empty — the default —
                            // leaves the field unset, which is top-level configuration and what
                            // every Configuration predating that decision carries.
                            role: entry.role.clone(),
                        },
                    )
                })
                .collect(),
        }),
        config_hash: desired.hash.clone(),
    })
}

/// The version a reader of the fleet table wants: the release, without the commit the build came
/// from (ADR-0012).
///
/// A value that is not a version is returned as it stands. `service.version` is whatever an Agent
/// puts there, and a Foreign Agent numbers itself however its own project does — trimming a string
/// this Server does not understand would be inventing a version rather than showing one.
fn display_version(reported: &str) -> String {
    fleet_core::version::identity(reported)
        .unwrap_or(reported)
        .to_string()
}

/// The Agents one Host carries, and the name it is shown by (ADR-0035 clause 7).
#[derive(Default)]
pub struct HostAgents {
    /// The `host.name` its Client Agent reports; `None` for a Gateway, and while it has no single
    /// Client Agent.
    pub name: Option<String>,
    pub agents: Vec<HostAgentView>,
}

/// One Agent under the Host it arrived over (ADR-0035 clause 7): enough to group it by its
/// Client Agent.
pub struct HostAgentView {
    pub instance_uid: String,
    pub service_name: String,
    pub service_instance_name: String,
    /// The `host.name` it reports, or empty.
    pub host_name: String,
    /// Whether it is a Client Agent: it reports `supervisor.kind.*`.
    pub client: bool,
    /// The Instance UID of its Client Agent — its own, for the Client Agent — or empty.
    pub client_agent: String,
    /// Behind a Gateway, the machine it is grouped by (`host.id=…` or `host.name=…`); empty on
    /// a direct connection.
    pub machine: String,
    /// Its group holds more than one Client Agent.
    pub ambiguous: bool,
    pub connected: bool,
}

/// One Agent as the REST API and the UI see it.
#[derive(Serialize)]
pub struct AgentView {
    pub instance_uid: String,
    /// The Agent *type* — the Baseline's "reverse FQDN that uniquely identifies the Agent type"
    /// (ADR-0016). For a managed Collector this is the `dist.name` it was built with, so every
    /// Collector of one distribution reports the same value. It answers "what is this", never
    /// "which one is this": that is [`service_instance_name`](Self::service_instance_name).
    pub service_name: String,
    /// The operator's name for this Agent — the `[[supervisor]]` block's `name` (ADR-0016). Empty
    /// for a foreign OpAMP client that reports no `service.instance.name`, which is why the UI
    /// falls back through the type to the UID rather than showing a blank row.
    pub service_instance_name: String,
    /// The release the Agent reports — `MAJOR.MINOR.PATCH`, with the pre-release when it is not a
    /// release build (ADR-0012). This is what belongs in a column headed "Version"; the commit the
    /// build came from is [`service_build`](Self::service_build). A reported value that is not a
    /// version at all is passed through unchanged, since a Foreign Agent numbers itself however it
    /// likes.
    pub service_version: String,
    /// Exactly what the Agent reported, commit metadata and all — the answer to "which build is on
    /// that host", which is a question a fleet exists to answer (ADR-0012).
    pub service_build: String,
    /// The reported `os.description` (e.g. "Ubuntu 24.04.2 LTS"), falling back to `os.type`.
    pub os: String,
    /// Every reported identifying attribute — what a Selector can match on (ADR-0023).
    pub identifying_attributes: BTreeMap<String, String>,
    /// Every reported non-identifying attribute — Selectors match these too.
    pub non_identifying_attributes: BTreeMap<String, String>,
    /// The Configurations a press of the Deployment claiming this Agent would release to it — the
    /// ones it holds that fit this Agent's type (ADR-0034), in name order. Never what it runs;
    /// that is [`assigned_configurations`](Self::assigned_configurations).
    pub matched_configurations: Vec<String>,
    /// The Configurations rolled out to this Agent (ADR-0034 clause 5), in name order — what its
    /// offer is composed from.
    pub assigned_configurations: Vec<String>,
    /// The Deployment that claims this Agent **now** — whose Selector matches it — or empty when
    /// none does.
    ///
    /// This is not [`assigned_deployment`](Self::assigned_deployment), and the difference is what
    /// tells four states apart that would otherwise look alike (ADR-0026 point 25). Empty here with
    /// no conflict means the host is in **no channel**: label it, or give it a `channel` attribute. Set
    /// here with nothing assigned and nothing pending means the channel holds nothing this Agent can
    /// take — no Package for its type, or none for its platform. The operator's next move differs
    /// in each case, which is why the Server says which one it is rather than showing an empty
    /// row three ways.
    pub deployment: String,
    /// The Deployment this Agent's release went **through** (ADR-0034 clause 5), or empty when
    /// nothing has been rolled out to it. Pinned as of that act, so it may name a channel that no
    /// longer claims this Agent.
    pub assigned_deployment: String,
    /// The Package rolled out to this Agent (ADR-0025), as `<agent type>@<version>`, or empty.
    ///
    /// It is pinned as of the act that released it: re-aiming its Deployment afterwards, or
    /// putting a newer Package in that channel, changes what is *proposed* and never what this Agent
    /// was already given.
    pub assigned_package: String,
    /// The Configurations waiting for a rollout act toward this Agent (ADR-0025 point 4,
    /// ADR-0034): one its Deployment holds and it is not assigned (`change: "new"`), one whose
    /// saved revision differs from the assigned one (`change: "update"`), one assigned that the
    /// next press drops from a release that keeps something else (`change: "remove"`), or one
    /// assigned while the release holds nothing for the Agent, so the press leaves it with no
    /// assignment and it keeps running what it runs (`change: "kept"`). The Server never acts on
    /// this by itself.
    pub pending_configurations: Vec<PendingConfigurationView>,
    /// The Package waiting for a rollout act toward this Agent (ADR-0025 point 4) — at most one:
    /// the candidate of the Deployment that claims it, when that is not what it is assigned, or
    /// the assigned one the next press drops (`change: "remove"`, or `"kept"` as for a
    /// Configuration).
    pub pending_packages: Vec<PendingPackageView>,
    /// The Deployment the next press releases through, when the assignment names another one or
    /// none (ADR-0034 clause 6); empty otherwise. A release whose content is unchanged still moves
    /// the assignment to the claiming Deployment.
    pub pending_deployment: String,
    /// Hex hash of the composed configuration this Agent should run; empty when it is assigned
    /// nothing.
    pub desired_hash: String,
    /// The Capability Set this Agent declared, as capability names from the Baseline's
    /// `AgentCapabilities` (see docs/CONFORMANCE.md).
    pub capabilities: Vec<String>,
    /// The Agent's available components (top-level names, sorted); empty until reported.
    pub available_components: Vec<String>,
    /// The Agent's package installations (ADR-0026), in name order; empty until reported.
    pub packages: Vec<PackageStatusView>,
    /// Why this Agent is proposed nothing — more than one Deployment claims it, and an Agent
    /// belongs to at most one (ADR-0026 point 26). The message names every Deployment in the way.
    /// Absent when at most one claims it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_conflict: Option<String>,
    /// What the Agent said about the *offer* rather than about a package it holds — an offer it
    /// refuses outright has no package status to carry the reason, and the Client's own Agent
    /// refusing a package it was not configured to take (ADR-0018) is exactly that case. Empty
    /// when the Agent has nothing to complain about.
    pub package_error: String,
    pub transport: String,
    pub connected: bool,
    pub healthy: bool,
    pub health_status: String,
    /// Why the Agent is unhealthy — `ComponentHealth.last_error`, which the Baseline says SHOULD
    /// be set when `healthy` is false. Empty when the Agent is healthy or gave no reason.
    pub health_error: String,
    pub effective_config: String,
    pub remote_config_status: String,
    pub remote_config_error: String,
    pub in_sync: bool,
    pub sequence_num: u64,
    pub last_seen_ms: u64,
    /// Nothing has been heard from this Agent for longer than its staleness budget (ADR-0024).
    ///
    /// Beside [`connected`](Self::connected), never instead of it: that one says a connection
    /// carrying this Agent is open — behind a Gateway, the *Gateway's* — and this one says whether
    /// the Agent itself is still talking. `connected: true, stale: true` is precisely the gatewayed
    /// case, and precisely what an operator needs to be told.
    ///
    /// Only an Agent declaring `ReportsHeartbeat` can be stale: that capability is the promise that
    /// makes silence mean something. Derived on read, never stored.
    pub stale: bool,
    /// The operator's labels on this Agent (ADR-0024) — matched by Selectors exactly like a
    /// reported attribute, but set here rather than in `supervisor.toml` on the host, so moving a host
    /// between rollout channels is an API call instead of an edit and a restart.
    pub labels: BTreeMap<String, String>,
    /// Labels this Agent's own reports shadow: set, matching nothing, and therefore doing nothing.
    ///
    /// Reported attributes always win (ADR-0024) — they decide which artifact fits this machine.
    /// A collision is refused when the label is set, so this fills only when an Agent *starts*
    /// reporting a key that was labelled earlier. Shown rather than dropped in silence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shadowed_labels: Vec<String>,
    /// The labels of this Agent's Client Agent, which hold for it below its own (ADR-0035
    /// clause 4); empty for the Client Agent itself, for an Agent whose Client the Server cannot
    /// tell, and for an ambiguous one.
    pub inherited_labels: BTreeMap<String, String>,
    /// The Instance UID of this Agent's Client Agent — its own, for the Client Agent — or empty
    /// when the Server cannot tell.
    pub client_agent: String,
    /// The group this Agent's Client is recognised in holds more than one Client Agent, so it
    /// inherits nothing (ADR-0035 clause 4).
    pub ambiguous: bool,
    /// The Host this Agent last arrived over (ADR-0035 clause 2), or empty. Behind a Gateway, the
    /// Gateway's.
    pub host: String,
    /// The `fleet.host.*` values its effective description takes from that Host (ADR-0035
    /// clause 3); empty behind a Gateway.
    pub host_attributes: BTreeMap<String, String>,
    /// Reported attributes in the Server's `fleet.` space, left out of what Selectors match
    /// (ADR-0035 clause 5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ignored_attributes: Vec<String>,
}

/// One Configuration waiting for a rollout act toward one Agent (ADR-0025).
#[derive(Serialize)]
pub struct PendingConfigurationView {
    pub name: String,
    /// `new` — held by the claiming Deployment and not yet assigned; `update` — the saved
    /// revision differs from the assigned one; `remove` — assigned, and dropped by the next press,
    /// which applies the smaller map; `kept` — assigned, and the next press leaves the Agent with no
    /// assignment, so it keeps running it.
    pub change: String,
}

/// Whom one Deployment reaches in the fleet as reported so far (ADR-0026): the Agents it claims,
/// the subset a rollout act would actually change, and those another Deployment also claims.
#[derive(Clone, Copy, Default, Debug)]
pub struct DeploymentReach {
    /// Agents this Deployment claims — and no other does. Zero is the aim mistake worth hunting.
    pub claiming: usize,
    /// Of those, the Agents a press would actually move — what it would release differs from what
    /// their assignment pins (ADR-0034 clause 6). Zero with a non-zero `claiming` means everyone is
    /// up to date.
    pub targeted: usize,
    /// Agents this Deployment matches that **another one matches too**. They are offered nothing
    /// new until an operator narrows a Selector (ADR-0026 point 26).
    pub conflicting: usize,
}

/// The Package waiting for a rollout act toward one Agent (ADR-0025).
#[derive(Serialize)]
pub struct PendingPackageView {
    /// The Deployment that would release it — the channel this Agent belongs to.
    pub deployment: String,
    /// The Agent type this Package is built for — its identity, and its wire name.
    pub agent_type: String,
    pub version: String,
    /// What an operator reads: the Agent type and the version together.
    pub display_name: String,
    /// `new` — nothing is assigned for this Agent type; `update` — another version is; `remove` —
    /// the assigned one, which the next press drops; `kept` — the assigned one, while the next
    /// press leaves the Agent with no assignment.
    pub change: String,
}

/// One package's installation state as the REST API and UI see it (ADR-0026).
#[derive(Serialize)]
pub struct PackageStatusView {
    pub name: String,
    /// The version the Agent has installed; empty if it has none.
    pub version: String,
    /// `Downloading`, `Installing`, `Installed`, `InstallPending`, or `InstallFailed`.
    pub status: String,
    /// The failure reason when `status` is `InstallFailed`.
    pub error: String,
    /// How far the artifact download has got, as a percentage. Present only while `Downloading`,
    /// and only when the download source stated a size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_percent: Option<f64>,
    /// The download's current rate in bytes per second. Present only while `Downloading`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_bytes_per_second: Option<f64>,
}

impl PackageStatusView {
    fn from_status(status: &opamp::proto::PackageStatus) -> Self {
        use opamp::proto::PackageStatusEnum as S;
        let name = match status.status {
            s if s == S::Installed as i32 => "Installed",
            s if s == S::Installing as i32 => "Installing",
            s if s == S::InstallPending as i32 => "InstallPending",
            s if s == S::InstallFailed as i32 => "InstallFailed",
            s if s == S::Downloading as i32 => "Downloading",
            _ => "Unknown",
        };
        // The Baseline carries these only with `Downloading`, and a percentage of zero means the
        // source never said how big the artifact is — not that nothing has arrived.
        let details = status.download_details.filter(|_| name == "Downloading");
        PackageStatusView {
            name: status.name.clone(),
            version: status.agent_has_version.clone(),
            status: name.to_string(),
            error: status.error_message.clone(),
            download_percent: details
                .map(|d| d.download_percent)
                .filter(|percent| *percent > 0.0),
            download_bytes_per_second: details.map(|d| d.download_bytes_per_second),
        }
    }
}

/// A declared capability bitmask as the names from the Baseline's `AgentCapabilities`. Undefined
/// bits are surfaced verbatim rather than dropped — a peer declaring them is worth seeing.
fn capability_names(mask: u64) -> Vec<String> {
    use opamp::proto::AgentCapabilities as C;
    const KNOWN: [(C, &str); 16] = [
        (C::ReportsStatus, "ReportsStatus"),
        (C::AcceptsRemoteConfig, "AcceptsRemoteConfig"),
        (C::ReportsEffectiveConfig, "ReportsEffectiveConfig"),
        (C::AcceptsPackages, "AcceptsPackages"),
        (C::ReportsPackageStatuses, "ReportsPackageStatuses"),
        (C::ReportsOwnTraces, "ReportsOwnTraces"),
        (C::ReportsOwnMetrics, "ReportsOwnMetrics"),
        (C::ReportsOwnLogs, "ReportsOwnLogs"),
        (
            C::AcceptsOpAmpConnectionSettings,
            "AcceptsOpAMPConnectionSettings",
        ),
        (
            C::AcceptsOtherConnectionSettings,
            "AcceptsOtherConnectionSettings",
        ),
        (C::AcceptsRestartCommand, "AcceptsRestartCommand"),
        (C::ReportsHealth, "ReportsHealth"),
        (C::ReportsRemoteConfig, "ReportsRemoteConfig"),
        (C::ReportsHeartbeat, "ReportsHeartbeat"),
        (C::ReportsAvailableComponents, "ReportsAvailableComponents"),
        (
            C::ReportsConnectionSettingsStatus,
            "ReportsConnectionSettingsStatus",
        ),
    ];
    let mut names = Vec::new();
    let mut undefined = mask;
    for (bit, name) in KNOWN {
        if mask & bit as u64 != 0 {
            names.push(name.to_string());
            undefined &= !(bit as u64);
        }
    }
    if undefined != 0 {
        names.push(format!("unknown bits 0x{undefined:x}"));
    }
    names
}

/// Reported attributes as the API shows them: string values as-is, string arrays (the shape the
/// conventions give `host.ip` and `host.mac`, ADR-0016) joined with a comma, other value kinds in
/// their debug form — the view is for reading, the wire keeps the typed original.
fn attr_map(attributes: &[KeyValue]) -> BTreeMap<String, String> {
    fn text(value: &any_value::Value) -> String {
        match value {
            any_value::Value::StringValue(s) => s.clone(),
            any_value::Value::ArrayValue(list) => list
                .values
                .iter()
                .filter_map(|v| v.value.as_ref())
                .map(text)
                .collect::<Vec<_>>()
                .join(", "),
            other => format!("{other:?}"),
        }
    }
    attributes
        .iter()
        .filter_map(|kv| {
            let value = kv.value.as_ref()?.value.as_ref()?;
            Some((kv.key.clone(), text(value)))
        })
        .collect()
}

impl AgentView {
    #[allow(clippy::too_many_arguments)]
    fn from_record(
        uid: &InstanceUid,
        record: &AgentRecord,
        desired: Option<&DesiredConfig>,
        matched_configurations: Vec<String>,
        package_conflict: Option<String>,
        claiming_deployment: String,
        waits: Waiting,
        stale: bool,
    ) -> Self {
        let (identifying, non_identifying) = match &record.description {
            Some(d) => (
                attr_map(&d.identifying_attributes),
                attr_map(&d.non_identifying_attributes),
            ),
            None => (BTreeMap::new(), BTreeMap::new()),
        };
        let lookup = |map: &BTreeMap<String, String>, key: &str| -> String {
            map.get(key).cloned().unwrap_or_default()
        };
        let status = record.remote_config_status.as_ref();
        let status_name = match status.map(|s| s.status) {
            Some(s) if s == RemoteConfigStatuses::Applied as i32 => "APPLIED",
            Some(s) if s == RemoteConfigStatuses::Applying as i32 => "APPLYING",
            Some(s) if s == RemoteConfigStatuses::Failed as i32 => "FAILED",
            _ => "UNSET",
        };
        // In sync means: runs exactly the composed set — trivially true when nothing matches,
        // since an unmatched Agent is deliberately left alone (goal 9).
        let in_sync = match desired {
            None => true,
            Some(d) => {
                status.map(|s| s.last_remote_config_hash.as_slice()) == Some(d.hash.as_slice())
            }
        };
        // What the Agent said, and what a reader of a table wants out of it (ADR-0012).
        let service_build = lookup(&identifying, attributes::SERVICE_VERSION);
        AgentView {
            instance_uid: uid.to_string(),
            service_name: lookup(&identifying, attributes::SERVICE_NAME),
            service_instance_name: lookup(&non_identifying, attributes::SERVICE_INSTANCE_NAME),
            service_version: display_version(&service_build),
            service_build,
            os: match lookup(&non_identifying, attributes::OS_DESCRIPTION) {
                description if !description.is_empty() => description,
                _ => lookup(&non_identifying, attributes::OS_TYPE),
            },
            identifying_attributes: identifying,
            non_identifying_attributes: non_identifying,
            matched_configurations,
            assigned_configurations: record.assigned_configurations().keys().cloned().collect(),
            deployment: claiming_deployment,
            assigned_deployment: record
                .assignment
                .as_ref()
                .map(|a| a.deployment.clone())
                .unwrap_or_default(),
            assigned_package: record
                .assigned_package()
                .map(PackageId::to_string)
                .unwrap_or_default(),
            pending_configurations: waits.configurations,
            pending_packages: waits.packages,
            pending_deployment: waits.deployment,
            desired_hash: desired.map(|d| hex::encode(&d.hash)).unwrap_or_default(),
            capabilities: capability_names(record.capabilities),
            available_components: record
                .available_components
                .as_ref()
                .map(|ac| {
                    let mut names: Vec<String> = ac.components.keys().cloned().collect();
                    names.sort_unstable();
                    names
                })
                .unwrap_or_default(),
            package_conflict,
            package_error: record
                .package_statuses
                .as_ref()
                .map(|s| s.error_message.clone())
                .unwrap_or_default(),
            packages: record
                .package_statuses
                .as_ref()
                .map(|s| {
                    let mut views: Vec<PackageStatusView> = s
                        .packages
                        .values()
                        .map(PackageStatusView::from_status)
                        .collect();
                    views.sort_by(|a, b| a.name.cmp(&b.name));
                    views
                })
                .unwrap_or_default(),
            transport: record.transport.as_str().to_string(),
            connected: record.connected,
            healthy: record.health.as_ref().map(|h| h.healthy).unwrap_or(false),
            health_status: record
                .health
                .as_ref()
                .map(|h| h.status.clone())
                .unwrap_or_default(),
            health_error: record
                .health
                .as_ref()
                .map(|h| h.last_error.clone())
                .unwrap_or_default(),
            effective_config: record.effective_config.clone().unwrap_or_default(),
            remote_config_status: status_name.to_string(),
            remote_config_error: status.map(|s| s.error_message.clone()).unwrap_or_default(),
            in_sync,
            sequence_num: record.sequence_num,
            last_seen_ms: record.last_seen_ms,
            stale,
            shadowed_labels: crate::labels::shadowed(record.description.as_ref(), &record.labels),
            labels: record.labels.clone(),
            inherited_labels: record.placement.inherited.clone(),
            client_agent: record
                .placement
                .client_agent
                .map(|uid| uid.to_string())
                .unwrap_or_default(),
            ambiguous: record.placement.ambiguous,
            host: record.host.clone().unwrap_or_default(),
            host_attributes: record.placement.host_values.clone(),
            ignored_attributes: crate::labels::ignored(record.description.as_ref()),
        }
    }
}

/// Whether nothing has been heard from this Agent for longer than its budget (ADR-0024).
///
/// Gated on `ReportsHeartbeat`: an Agent that never promised to report periodically is not late,
/// however long it has been quiet, and flagging it would train an operator to ignore the flag.
fn is_stale(record: &AgentRecord, stale_after: Duration, now_ms: u64) -> bool {
    if record.capabilities & opamp::proto::AgentCapabilities::ReportsHeartbeat as u64 == 0 {
        return false;
    }
    is_silent(record, stale_after, now_ms)
}

/// Nothing has been heard from this Agent for longer than `budget` — the plain fact, without the
/// promise [`is_stale`] adds on top of it.
///
/// The two are deliberately not the same test. Calling an Agent *stale* accuses it of being late,
/// which is only fair when it declared `ReportsHeartbeat` and so promised to be punctual. Asking
/// whether it is safe to forget (ADR-0024) is a question about evidence, not about promises: an
/// Agent nobody has heard from cannot be disturbed by being forgotten, whatever it once declared.
fn is_silent(record: &AgentRecord, budget: Duration, now_ms: u64) -> bool {
    now_ms.saturating_sub(record.last_seen_ms) > budget.as_millis() as u64
}

/// The Baseline's command-only message: identity, capabilities, and the restart — nothing else.
fn restart_command(uid: &InstanceUid, capabilities: u64) -> ServerToAgent {
    ServerToAgent {
        instance_uid: uid.as_bytes().to_vec(),
        capabilities,
        command: Some(opamp::proto::ServerToAgentCommand {
            r#type: opamp::proto::CommandType::Restart as i32,
        }),
        ..Default::default()
    }
}

/// One `ConnectionSettingsOffers` message, with one hash over everything it carries: the Agent
/// acknowledges the message, not its parts.
fn compose_settings_offer(
    opamp: Option<OpAmpConnectionSettings>,
    telemetry: TelemetryOffer,
) -> ConnectionSettingsOffers {
    let mut offer = ConnectionSettingsOffers {
        opamp,
        own_metrics: telemetry.own_metrics,
        own_traces: telemetry.own_traces,
        own_logs: telemetry.own_logs,
        ..Default::default()
    };
    offer.hash = Sha256::digest(offer.encode_to_vec()).to_vec();
    offer
}

/// The Baseline's gate: send the offer when the Agent's reported hash differs. An APPLYING echo of
/// the same hash keeps it coming — a verification whose outcome was lost (a dropped connection
/// mid-switch) must heal by retry, not hang.
fn gate(record: &AgentRecord, offer: ConnectionSettingsOffers) -> Option<ConnectionSettingsOffers> {
    if let Some(status) = &record.connection_settings_status {
        if status.last_connection_settings_hash == offer.hash
            && status.status != opamp::proto::ConnectionSettingsStatuses::Applying as i32
        {
            return None;
        }
    }
    Some(offer)
}

/// The `ServerToAgent` for a report the Server cannot make sense of.
pub fn bad_request(message: &str) -> ServerToAgent {
    ServerToAgent {
        capabilities: SERVER_CAPABILITIES,
        error_response: Some(ServerErrorResponse {
            r#type: ServerErrorResponseType::BadRequest as i32,
            error_message: message.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// What a CSR with a bootstrap proof over a member's certificate is answered (ADR-0039 clause 12).
pub const MEMBER_DOES_NOT_ENROL: &str =
    "a certificate signing request with a bootstrap proof is an enrolment, and a member does not \
     enrol";

/// What a CSR with neither proof over a Gateway's certificate is answered (ADR-0039 clause 1).
pub const NEEDS_A_PROOF: &str =
    "a certificate requested through a Gateway needs a renewal proof or a bootstrap proof";

/// How long an Agent told `Unavailable` waits before it asks again.
pub const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// The `ServerToAgent` for a report the Server is momentarily unable to accept — the Baseline's
/// `Unavailable`, which unlike `BadRequest` tells the Agent to **retry later** rather than give up,
/// and with `retry_info` says when. It carries the `instance_uid` of the message it answers, the
/// field a Client and a Gateway route a reply by (ADR-0013 clause 25).
pub fn unavailable(instance_uid: &[u8], message: &str) -> ServerToAgent {
    ServerToAgent {
        instance_uid: instance_uid.to_vec(),
        capabilities: SERVER_CAPABILITIES,
        error_response: Some(ServerErrorResponse {
            r#type: ServerErrorResponseType::Unavailable as i32,
            error_message: message.to_string(),
            details: Some(opamp::proto::server_error_response::Details::RetryInfo(
                opamp::proto::RetryInfo {
                    retry_after_nanoseconds: RETRY_AFTER.as_nanos() as u64,
                },
            )),
        }),
        ..Default::default()
    }
}

/// Renders a reported config map for the operator: single unnamed entry as-is, named entries with
/// a `# <name>` heading.
fn config_map_text(map: Option<&AgentConfigMap>) -> String {
    let Some(map) = map else {
        return String::new();
    };
    let mut entries: Vec<_> = map.config_map.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
        .into_iter()
        .map(|(name, file)| {
            let body = String::from_utf8_lossy(&file.body);
            if name.is_empty() {
                body.into_owned()
            } else {
                format!("# {name}\n{body}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Refuses a per-Agent press that would move nothing because the Package the Deployment holds for
/// the Agent's type is not released to it — no upgrade, no entry for its platform — and says why,
/// naming the version it compared against (ADR-0025 clause 16). A press that moves nothing for any
/// other reason is not refused: it is the same request arriving twice.
fn refuse_a_package_left_out(
    store: &crate::packages::PackageStore,
    deployment: &Deployment,
    record: &AgentRecord,
    release: Option<&Assignment>,
) -> Result<(), RolloutError> {
    let effective = record.effective_description();
    let description = effective.as_deref();
    let Some(held) = crate::packages::reported_agent_type(description)
        .and_then(|agent_type| deployment.package_for(agent_type))
    else {
        return Ok(());
    };
    if release.and_then(|r| r.package.as_ref()) == Some(held) {
        return Ok(());
    }
    store
        .fits_agent(held, description, &record.installed_package_versions())
        .map_err(RolloutError::NotApplicable)
}

/// Refuses a rollout of a Deployment that holds nothing, or a Package with an unsigned entry —
/// naming each such Package and its platforms; nothing is released (ADR-0034 clause 6, ADR-0033).
fn refuse_unreleasable(
    store: &crate::packages::PackageStore,
    deployment: &Deployment,
) -> Result<(), RolloutError> {
    if deployment.holds_nothing() {
        return Err(RolloutError::NotApplicable(format!(
            "deployment {:?} holds no package and no configuration — put one in it before rolling \
             it out",
            deployment.name
        )));
    }
    let unsigned = store.unsigned_in(deployment);
    if unsigned.is_empty() {
        return Ok(());
    }
    Err(RolloutError::NotApplicable(format!(
        "deployment {:?} holds packages with unsigned entries: {} — sign every entry on the \
         Packages tab before rolling it out",
        deployment.name,
        unsigned.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The host derived for a certificate that names none is the one this Server derived before
    /// the derivation moved into `fleet-core`: hosts already in the register keep their ids.
    /// Verifies: ADR-0039
    #[test]
    fn a_derived_host_is_the_one_the_register_already_holds() {
        use sha2::Digest as _;
        let (issuer, serial) = ("5f0a", "1c");
        let digest = sha2::Sha256::digest(format!("{issuer}\n{serial}"));
        let before = opamp::uid::InstanceUid::from_wire(&digest[..16])
            .expect("16 bytes")
            .to_string();
        assert_eq!(fleet_core::host::derived(issuer, serial), before);
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// The view of an array-valued attribute — the shape `host.ip` and `host.mac` arrive in
    /// (ADR-0016): joined for reading, not dumped in debug form.
    #[test]
    fn the_view_joins_a_string_array_attribute() {
        let attrs = vec![
            opamp::attributes::string_attr("host.name", "edge-01"),
            opamp::attributes::string_array_attr(
                "host.ip",
                &["10.0.0.7".into(), "192.168.1.140".into()],
            ),
        ];
        let map = super::attr_map(&attrs);
        assert_eq!(map["host.name"], "edge-01");
        assert_eq!(map["host.ip"], "10.0.0.7, 192.168.1.140");
    }

    /// The gatewayed case, which is why this exists: the connection is up — it is the Gateway's —
    /// and the Agent behind it has stopped talking. Both facts are reported, neither overwrites
    /// the other (ADR-0024).
    // Verifies: ADR-0024
    #[test]
    fn an_agent_that_stopped_reporting_is_stale_while_its_connection_is_up() {
        let mut record = record_with(opamp::proto::AgentCapabilities::ReportsHeartbeat as u64);
        record.connected = true;
        record.last_seen_ms = now_ms() - 120_000;
        assert!(is_stale(&record, Duration::from_secs(90), now_ms()));
        assert!(record.connected, "connectedness is a separate fact");
    }

    /// One missed beat is a lost packet. The budget is three intervals, so a report inside it is
    /// not late.
    #[test]
    fn an_agent_inside_its_budget_is_not_stale() {
        let mut record = record_with(opamp::proto::AgentCapabilities::ReportsHeartbeat as u64);
        record.last_seen_ms = now_ms() - 40_000;
        assert!(!is_stale(&record, Duration::from_secs(90), now_ms()));
    }

    /// An Agent that never promised to report periodically is not late, however long it is quiet —
    /// flagging it would train an operator to ignore the flag.
    #[test]
    fn an_agent_that_promised_no_heartbeat_never_goes_stale() {
        let mut record = record_with(opamp::proto::AgentCapabilities::ReportsStatus as u64);
        record.last_seen_ms = now_ms() - 86_400_000;
        assert!(!is_stale(&record, Duration::from_secs(90), now_ms()));
    }

    /// The offered interval wins over the configured default: it is the period this Server actually
    /// asked for, so it is the one silence should be measured against.
    /// Verifies: ADR-0014
    #[test]
    fn an_offered_heartbeat_interval_sets_the_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let offer = ConnectionOffer::from_config(
            &toml::from_str::<crate::config::ConnectionOfferConfig>(
                "heartbeat_interval_secs = 10\n",
            )
            .expect("offer config"),
        );
        let state = AppState::new(dir.path().join("configs"))
            .expect("state")
            .with_connection_offer(Some(offer))
            .with_stale_after(Duration::from_secs(90));
        assert_eq!(
            state.stale_after(),
            Duration::from_secs(30),
            "three intervals"
        );
    }

    /// ADR-0024. The tidy-up case: a host that was decommissioned, its Agent gone with it.
    #[test]
    fn a_disconnected_agent_is_forgotten() {
        let state = forgettable_state();
        let uid = insert(&state, record_with(0));
        assert!(state.forget_agent(&uid).is_ok());
        assert!(state.snapshot().is_empty(), "the row is gone");
    }

    /// The gate: forgetting a live Agent would drop the hashes that stop the Server re-offering,
    /// so its next exchange re-applies its configuration — and a managed process restarts with it.
    #[test]
    fn an_agent_that_is_still_reporting_is_refused() {
        let state = forgettable_state();
        let mut record = record_with(0);
        record.connected = true;
        record.last_seen_ms = now_ms();
        let uid = insert(&state, record);
        assert!(matches!(
            state.forget_agent(&uid),
            Err(ForgetError::StillReporting)
        ));
        assert_eq!(state.snapshot().len(), 1, "the row stays");
    }

    /// The gatewayed case: the connection is up because it is the *Gateway's*, and the Agent behind
    /// it stopped talking long ago. `connected` alone would refuse this forever.
    #[test]
    fn a_connected_agent_that_went_quiet_is_forgotten() {
        let state = forgettable_state();
        let mut record = record_with(opamp::proto::AgentCapabilities::ReportsHeartbeat as u64);
        record.connected = true;
        record.last_seen_ms = now_ms() - 120_000;
        let uid = insert(&state, record);
        assert!(state.forget_agent(&uid).is_ok());
    }

    /// The case that made the rule test silence rather than staleness (ADR-0024): an Agent that
    /// promised no heartbeat is never *stale*, and plain-HTTP polling never clears `connected` —
    /// so gating on the flag would have left this row on a dead host permanently unremovable.
    #[test]
    fn a_silent_agent_is_forgotten_although_it_can_never_be_stale() {
        let state = forgettable_state();
        let mut record = record_with(opamp::proto::AgentCapabilities::ReportsStatus as u64);
        record.connected = true;
        record.transport = Transport::Http;
        record.last_seen_ms = now_ms() - 86_400_000;
        let uid = insert(&state, record);
        assert!(
            !is_stale(
                &record_at(now_ms() - 86_400_000),
                Duration::from_secs(90),
                now_ms()
            ),
            "it declares no heartbeat, so it is never stale"
        );
        assert!(state.forget_agent(&uid).is_ok(), "but it is forgettable");
    }

    #[test]
    fn forgetting_an_agent_that_was_never_known_says_so() {
        let state = forgettable_state();
        assert!(matches!(
            state.forget_agent(&InstanceUid::default()),
            Err(ForgetError::UnknownAgent)
        ));
    }

    fn forgettable_state() -> AppState {
        let dir = tempfile::tempdir().expect("tempdir");
        // The directory outlives the state only for the length of a test; the Configuration store
        // is not what these exercise.
        AppState::new(dir.keep().join("configs"))
            .expect("state")
            .with_stale_after(Duration::from_secs(90))
    }

    fn insert(state: &AppState, record: AgentRecord) -> InstanceUid {
        let uid = InstanceUid::default();
        state.fleet.lock().expect("fleet lock").insert(uid, record);
        uid
    }

    fn record_at(last_seen_ms: u64) -> AgentRecord {
        let mut record = record_with(opamp::proto::AgentCapabilities::ReportsStatus as u64);
        record.last_seen_ms = last_seen_ms;
        record
    }

    fn record_with(capabilities: u64) -> AgentRecord {
        AgentRecord {
            sequence_num: 1,
            capabilities,
            description: None,
            health: None,
            effective_config: None,
            remote_config_status: None,
            transport: Transport::WebSocket,
            connected: false,
            last_seen_ms: now_ms(),
            restart_pending: false,
            available_components: None,
            connection_settings_status: None,
            package_statuses: None,
            owner: None,
            labels: BTreeMap::new(),
            host: None,
            placement: Placement::default(),
            assignment: None,
        }
    }

    /// A full report for the persistence tests: description, capabilities, and a sequence number.
    fn report(uid: &InstanceUid, sequence_num: u64) -> AgentToServer {
        AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            sequence_num,
            capabilities: opamp::proto::AgentCapabilities::ReportsStatus as u64,
            agent_description: Some(AgentDescription {
                identifying_attributes: vec![opamp::attributes::string_attr(
                    "service.name",
                    "otelcol",
                )],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// ADR-0024: the fleet survives a restart — the record is restored with everything the Agent
    /// reported, shown honestly as disconnected until live evidence says otherwise.
    // Verifies: ADR-0024
    #[test]
    fn the_fleet_is_restored_disconnected_after_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        {
            let state = AppState::new(dir.clone()).expect("state");
            state.process(report(&uid, 1), Transport::WebSocket, Some(1));
        }
        let state = AppState::new(dir).expect("reopened state");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.len(), 1, "the row survived the restart");
        assert_eq!(snapshot[0].service_name, "otelcol");
        assert!(
            !snapshot[0].connected,
            "connectedness is runtime-only and never restored"
        );
    }

    /// Every `Unavailable` — a full enrolment queue, the record ceiling, an audit record that cannot
    /// be written — tells the Agent when to ask again, so it retries instead of giving up or
    /// hammering (ADR-0021 clause 21, ADR-0022 clause 6).
    /// Verifies: ADR-0021, ADR-0022, ADR-0013
    #[test]
    fn unavailable_tells_the_agent_when_to_retry() {
        let reply = unavailable(&[7; 16], "busy");
        assert_eq!(reply.instance_uid, [7; 16], "it names the Agent it answers");
        let error = reply.error_response.expect("an error");
        assert_eq!(error.r#type, ServerErrorResponseType::Unavailable as i32);
        match error.details {
            Some(opamp::proto::server_error_response::Details::RetryInfo(info)) => {
                assert_eq!(info.retry_after_nanoseconds, RETRY_AFTER.as_nanos() as u64);
            }
            other => panic!("no retry_info: {other:?}"),
        }
    }

    /// A new `instance_uid` past the record ceiling is refused `Unavailable` and leaves no record,
    /// so a peer minting fresh self-asserted UIDs (ADR-0021) cannot grow the fleet — and its
    /// in-memory map and per-Agent disk mirror — without bound. Agents already known keep reporting.
    #[test]
    fn a_new_agent_past_the_ceiling_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let state = AppState::new(dir).expect("state").with_max_agents(2);

        let a = InstanceUid::default();
        let b = InstanceUid::default();
        state.process(report(&a, 1), Transport::Http, None);
        state.process(report(&b, 1), Transport::Http, None);
        assert_eq!(state.snapshot().len(), 2, "the fleet filled to its ceiling");

        // A third, genuinely new UID: refused, and told to retry rather than give up.
        let c = InstanceUid::default();
        let processed = state.process(report(&c, 1), Transport::Http, None);
        let error = processed.reply.error_response.expect("an error response");
        assert_eq!(
            error.r#type,
            ServerErrorResponseType::Unavailable as i32,
            "a full fleet answers Unavailable, not BadRequest"
        );
        assert!(
            processed.uid.is_none(),
            "the refused report has no identity to route a config to"
        );
        assert_eq!(
            state.snapshot().len(),
            2,
            "no record was created for the refused UID"
        );

        // An Agent already in the fleet keeps reporting even at the ceiling.
        let processed = state.process(report(&a, 2), Transport::Http, None);
        assert!(
            processed.reply.error_response.is_none(),
            "a known Agent is never refused by the ceiling"
        );
        assert_eq!(state.snapshot().len(), 2);
    }

    /// ADR-0024: a restored sequence number means the next compressed heartbeat is accepted in
    /// place of a fleet-wide ReportFullState stampede.
    #[test]
    fn a_restored_agent_is_not_demanded_a_full_report() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        {
            let state = AppState::new(dir.clone()).expect("state");
            state.process(report(&uid, 1), Transport::WebSocket, Some(1));
            state.flush_agents();
        }
        let state = AppState::new(dir).expect("reopened state");
        let heartbeat = AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            sequence_num: 2,
            ..Default::default()
        };
        let processed = state.process(heartbeat, Transport::WebSocket, Some(1));
        assert_eq!(
            processed.reply.flags & ServerToAgentFlags::ReportFullState as u64,
            0,
            "no gap: the restored record carries the sequence"
        );
    }

    /// ADR-0024: a heartbeat exists to change nothing, and it reaches no storage backend — the
    /// stored record still carries the durable state's write, not the heartbeat's.
    // Verifies: ADR-0024
    #[test]
    fn a_heartbeat_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        let state = AppState::new(dir.clone()).expect("state");
        state.process(report(&uid, 1), Transport::WebSocket, Some(1));
        let path = dir.join("agents").join(format!("{uid}.json"));
        let written = std::fs::read_to_string(&path).expect("the report was persisted");
        let heartbeat = AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            sequence_num: 2,
            ..Default::default()
        };
        state.process(heartbeat, Transport::WebSocket, Some(1));
        let after = std::fs::read_to_string(&path).expect("still persisted");
        assert_eq!(written, after, "the heartbeat performed no write");
    }

    /// ADR-0024: forgetting removes the stored record with the row — nothing
    /// remembers under another name.
    #[test]
    fn forgetting_an_agent_removes_its_stored_record() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        let state = AppState::new(dir.clone())
            .expect("state")
            .with_stale_after(Duration::from_secs(90));
        let mut goodbye = report(&uid, 1);
        goodbye.agent_disconnect = Some(opamp::proto::AgentDisconnect {});
        state.process(goodbye, Transport::WebSocket, Some(1));
        let path = dir.join("agents").join(format!("{uid}.json"));
        assert!(path.exists(), "the record was persisted");
        assert!(
            state.forget_agent(&uid).is_ok(),
            "forgettable: disconnected"
        );
        assert!(!path.exists(), "forgetting frees the store too");
    }

    /// ADR-0024: the persisted record follows a reassigned identity — one record, one file.
    #[test]
    fn a_rekeyed_agent_moves_its_stored_record() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        let state = AppState::new(dir.clone()).expect("state");
        state.process(report(&uid, 1), Transport::WebSocket, Some(1));
        let mut rekey = report(&uid, 2);
        rekey.flags = AgentToServerFlags::RequestInstanceUid as u64;
        let processed = state.process(rekey, Transport::WebSocket, Some(1));
        let new_uid = processed.uid.expect("the new identity");
        assert_eq!(
            processed.reply.instance_uid,
            uid.as_bytes().to_vec(),
            "the reply is addressed to the identity the Agent asked under"
        );
        assert!(!dir.join("agents").join(format!("{uid}.json")).exists());
        assert!(dir.join("agents").join(format!("{new_uid}.json")).exists());
    }

    /// A fleet on `dir` whose Deployments are armed: an empty package store under `packages`, and
    /// the `stable` channel claiming every `otelcol` holding the Configuration `fleet`.
    fn configuring_fleet(dir: &std::path::Path) -> AppState {
        let store = PackageStore::open(dir.join("packages")).expect("store");
        let state = AppState::new(dir.join("configs"))
            .expect("state")
            .with_packages(Some(
                PackageOffering::new(&dir.join("packages"), store).expect("offering"),
            ));
        if state.configurations().get("fleet").is_none() {
            state
                .save_configuration("fleet", body("receivers: {}\n"))
                .expect("save a Configuration nobody has released");
            state
                .deployment_store()
                .expect("deployments")
                .put(
                    "stable",
                    BTreeMap::from([("service.name".to_string(), "otelcol".to_string())]),
                )
                .expect("deployment");
            state
                .put_deployment_configuration("stable", "fleet")
                .expect("hold it");
        }
        state
    }

    /// A top-level revision of `text` for the Agent type `report` describes.
    fn body(text: &str) -> Revision {
        Revision {
            body: text.to_string(),
            role: String::new(),
            service_name: "otelcol".to_string(),
        }
    }

    /// There is no seed. A record carrying no assignment loads as **assigned nothing** — the Server
    /// never invents a rollout at startup — and what its Deployment would release shows up as
    /// waiting instead, which is the one thing an operator has to act on.
    /// Verifies: ADR-0026, ADR-0034
    #[test]
    fn a_record_without_assignments_loads_assigned_to_nothing() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        {
            let state = configuring_fleet(&dir);
            state.process(report(&uid, 1), Transport::WebSocket, Some(1));
            state.rollout_deployment("stable").expect("rollout");
        }
        let record_path = dir
            .join("configs")
            .join("agents")
            .join(format!("{uid}.json"));
        let mut record: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&record_path).expect("read"))
                .expect("json");
        let fields = record.as_object_mut().expect("object");
        assert!(fields.remove("assignment").is_some(), "it was assigned");
        std::fs::write(&record_path, serde_json::to_vec(&record).expect("json")).expect("write");

        let state = configuring_fleet(&dir);
        let view = &state.snapshot()[0];
        assert!(
            view.assigned_configurations.is_empty(),
            "an absent assignment means nothing was rolled out, not \"not migrated yet\""
        );
        assert_eq!(
            view.pending_configurations[0].change, "new",
            "what it could receive waits for an explicit act (ADR-0025)"
        );
    }

    /// ADR-0025: saving proposes, the acts assign — and an Agent that appears after the
    /// Deployment's act waits for one of its own (point 6).
    /// Verifies: ADR-0025, ADR-0034
    #[test]
    fn rollout_acts_assign_and_a_late_agent_waits() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let state = configuring_fleet(&dir);
        let early = InstanceUid::default();
        state.process(report(&early, 1), Transport::Http, None);

        let view = &state.snapshot()[0];
        assert!(
            view.assigned_configurations.is_empty(),
            "saving assigns nothing"
        );
        assert_eq!(view.pending_configurations[0].change, "new");

        assert_eq!(
            state.rollout_deployment("stable").expect("rollout"),
            1,
            "the Deployment's act assigns the one known Agent"
        );
        assert_eq!(state.snapshot()[0].assigned_configurations, ["fleet"]);
        assert_eq!(state.snapshot()[0].assigned_deployment, "stable");

        // The latecomer: a candidate, waiting, assigned nothing — until its own act.
        let late = InstanceUid::default();
        state.process(report(&late, 1), Transport::Http, None);
        let late_view = state
            .snapshot()
            .into_iter()
            .find(|v| v.instance_uid == late.to_string())
            .expect("the late agent");
        assert!(late_view.assigned_configurations.is_empty());
        assert_eq!(late_view.pending_configurations[0].change, "new");
        state
            .rollout_to_agent(&late, None)
            .expect("rollout to agent");
        let late_view = state
            .snapshot()
            .into_iter()
            .find(|v| v.instance_uid == late.to_string())
            .expect("the late agent");
        assert_eq!(late_view.assigned_configurations, ["fleet"]);
        assert!(late_view.pending_configurations.is_empty());
    }

    /// A rollout whose store fails part-way leaves disk and memory agreeing: the record it wrote
    /// first is put back as it was, the fleet keeps its assignments, the revision those still pin
    /// stays, and the one nothing pins is collected. The next press, once the store writes again,
    /// releases to both.
    /// Verifies: ADR-0037
    #[test]
    fn a_rollout_that_fails_part_way_leaves_disk_and_memory_as_they_were() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = configuring_fleet(dir.path());
        let (first, second) = (InstanceUid([1; 16]), InstanceUid([2; 16]));
        for uid in [first, second] {
            state.process(report(&uid, 1), Transport::Http, None);
        }
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 2);
        let pinned = state
            .configurations()
            .get("fleet")
            .expect("fleet")
            .retained
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let agents = dir.path().join("configs").join("agents");
        let first_path = agents.join(format!("{first}.json"));
        let before = std::fs::read(&first_path).expect("the first record");

        state
            .save_configuration("fleet", body("receivers: {otlp: {}}\n"))
            .expect("edit");
        // The second record cannot be replaced: a directory holding a file stands in its place.
        let second_path = agents.join(format!("{second}.json"));
        std::fs::remove_file(&second_path).expect("remove");
        std::fs::create_dir_all(second_path.join("in-the-way")).expect("obstacle");

        assert!(matches!(
            state.rollout_deployment("stable"),
            Err(RolloutError::Storage(_))
        ));
        assert_eq!(
            std::fs::read(&first_path).expect("the first record"),
            before,
            "the record written before the failure is put back"
        );
        for view in state.snapshot() {
            assert_eq!(
                view.pending_configurations[0].change, "update",
                "{}",
                view.instance_uid
            );
        }
        let retained = state
            .configurations()
            .get("fleet")
            .expect("fleet")
            .retained
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            retained, pinned,
            "the pinned revision stays, the unpinned one is collected"
        );

        std::fs::remove_dir_all(&second_path).expect("clear the obstacle");
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 2);
    }

    /// ADR-0024: a queued restart is operator intent and survives the Server restarting.
    #[test]
    fn a_queued_restart_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let uid = InstanceUid::default();
        {
            let state = AppState::new(dir.clone()).expect("state");
            let mut msg = report(&uid, 1);
            msg.capabilities |= opamp::proto::AgentCapabilities::AcceptsRestartCommand as u64;
            state.process(msg, Transport::WebSocket, Some(1));
            assert!(state.request_restart(&uid).is_ok(), "queued");
        }
        let state = AppState::new(dir).expect("reopened state");
        let fleet = state.fleet.lock().expect("fleet lock");
        assert!(fleet[&uid].restart_pending, "the intent was restored");
    }

    /// ADR-0012: the fleet table shows the release, and the build stays reachable beside it. A
    /// Foreign Agent that numbers itself in its own way is shown as it reported.
    #[test]
    fn the_displayed_version_drops_the_commit_and_keeps_the_pre_release() {
        assert_eq!(super::display_version("0.1.1+799e36a"), "0.1.1");
        assert_eq!(super::display_version("0.1.1-dev+799e36a"), "0.1.1-dev");
        assert_eq!(super::display_version("0.1.1"), "0.1.1");
        // Not a version this Server understands — shown rather than trimmed into something else.
        assert_eq!(super::display_version("v2.9-nightly"), "v2.9-nightly");
        assert_eq!(super::display_version(""), "");
    }

    use super::*;

    #[test]
    fn capability_names_decode_known_bits_and_surface_undefined_ones() {
        use opamp::proto::AgentCapabilities as C;
        assert!(capability_names(0).is_empty());
        assert_eq!(
            capability_names(C::ReportsStatus as u64 | C::ReportsHealth as u64),
            ["ReportsStatus", "ReportsHealth"]
        );
        let with_undefined = capability_names(C::ReportsStatus as u64 | 1 << 60);
        assert_eq!(
            with_undefined,
            ["ReportsStatus", "unknown bits 0x1000000000000000"]
        );
    }

    /// What an operator sees while a package is on the wire. A status the view does not know
    /// reads as "Unknown", which is worse than useless during a rollout — so `Downloading` and
    /// its progress are part of the view, and the progress belongs to that status alone.
    #[test]
    fn the_package_view_shows_a_download_in_progress() {
        use opamp::proto::{PackageDownloadDetails, PackageStatus, PackageStatusEnum};

        let downloading = PackageStatusView::from_status(&PackageStatus {
            name: "otelcol".to_string(),
            status: PackageStatusEnum::Downloading as i32,
            download_details: Some(PackageDownloadDetails {
                download_percent: 42.5,
                download_bytes_per_second: 1_048_576.0,
            }),
            ..Default::default()
        });
        assert_eq!(downloading.status, "Downloading");
        assert_eq!(downloading.download_percent, Some(42.5));
        assert_eq!(downloading.download_bytes_per_second, Some(1_048_576.0));

        // A percentage is only meaningful when the source stated a size; zero means it did not.
        let sizeless = PackageStatusView::from_status(&PackageStatus {
            name: "otelcol".to_string(),
            status: PackageStatusEnum::Downloading as i32,
            download_details: Some(PackageDownloadDetails {
                download_percent: 0.0,
                download_bytes_per_second: 2048.0,
            }),
            ..Default::default()
        });
        assert_eq!(sizeless.download_percent, None);
        assert_eq!(sizeless.download_bytes_per_second, Some(2048.0));

        // Every other status carries no progress, whatever the Agent sent.
        let installing = PackageStatusView::from_status(&PackageStatus {
            name: "otelcol".to_string(),
            status: PackageStatusEnum::Installing as i32,
            download_details: Some(PackageDownloadDetails {
                download_percent: 99.0,
                download_bytes_per_second: 1.0,
            }),
            ..Default::default()
        });
        assert_eq!(installing.status, "Installing");
        assert_eq!(installing.download_percent, None);
        assert_eq!(installing.download_bytes_per_second, None);
    }

    /// The whole-store ceiling (ADR-0026), decided without a request: a store at its limit takes
    /// no upload, an artifact is refused when it would take the store past it, and an upload still
    /// arriving counts until it is dropped.
    #[test]
    fn the_package_store_ceiling_admits_up_to_its_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(dir.path().join("configs"))
            .expect("state")
            .with_max_total_package_bytes(100);
        {
            let mut upload = state
                .admit_upload()
                .expect("an empty store takes an upload");
            assert_eq!(upload.grow(100), Ok(()));
            assert_eq!(upload.admit_artifact(), Ok(()));
            assert!(
                matches!(state.admit_upload(), Err(StoreFull::AtLimit { limit: 100 })),
                "an upload in progress fills the store as much as a stored one"
            );
            assert_eq!(
                upload.grow(1),
                Err(StoreFull::WouldExceed {
                    size: 101,
                    limit: 100
                })
            );
            assert_eq!(
                upload.admit_artifact(),
                Err(StoreFull::WouldExceed {
                    size: 101,
                    limit: 100
                })
            );
        }
        assert!(
            state.admit_upload().is_ok(),
            "a dropped upload counts no more"
        );
        let full = state.with_max_total_package_bytes(0);
        assert!(matches!(
            full.admit_upload(),
            Err(StoreFull::AtLimit { limit: 0 })
        ));
    }

    /// A certificate of one host does not speak for another host's Agent: the reporter is re-keyed
    /// to an identity of its own, and the Agent it claimed keeps its record.
    /// Verifies: ADR-0021, G-17
    #[test]
    fn a_host_cannot_report_for_another_hosts_agent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let revocations = Arc::new(
            Revocations::open(
                Box::new(crate::fs::FsLedgerStore::open(dir.path()).expect("ledger")),
                Arc::new(crate::clock::SystemClock),
                Vec::new(),
            )
            .expect("revocations"),
        );
        let state = AppState::new(dir.path().join("configs"))
            .expect("state")
            .with_revocations(Some(revocations));
        let presented = |host: &str, serial: &str| Presented {
            id: CertId::new(b"CA", serial),
            host: Some(host.to_string()),
            subject_values: crate::revocation::SubjectValues::default(),
            not_after_ms: u64::MAX,
        };
        let victim = InstanceUid::default();
        let own = state.process_presented(
            {
                let mut first = AgentToServer {
                    instance_uid: victim.as_bytes().to_vec(),
                    ..Default::default()
                };
                first.capabilities = opamp::proto::AgentCapabilities::ReportsStatus as u64;
                first
            },
            Transport::Http,
            None,
            Some(&presented("h1", "01")),
        );
        assert_eq!(own.uid, Some(victim));
        assert!(own.reply.agent_identification.is_none());

        let claimed = state.process_presented(
            AgentToServer {
                instance_uid: victim.as_bytes().to_vec(),
                flags: AgentToServerFlags::RequestInstanceUid as u64,
                ..Default::default()
            },
            Transport::Http,
            None,
            Some(&presented("h2", "02")),
        );
        let new_uid = claimed.uid.expect("an identity");
        assert_ne!(new_uid, victim, "another host spoke for the Agent");
        assert_eq!(
            claimed.reply.instance_uid,
            victim.as_bytes().to_vec(),
            "the reply is addressed to the identity the reporter sent, or it routes to no one"
        );
        assert_eq!(
            claimed
                .reply
                .agent_identification
                .expect("told to adopt it")
                .new_instance_uid,
            new_uid.as_bytes().to_vec()
        );
        assert!(
            state
                .snapshot()
                .iter()
                .any(|agent| agent.instance_uid == victim.to_string()),
            "the claimed Agent's record moved"
        );

        // Having adopted it, the reporter speaks under its new identity and is re-keyed no more:
        // no further record appears for it.
        let adopted = state.process_presented(
            AgentToServer {
                instance_uid: new_uid.as_bytes().to_vec(),
                ..Default::default()
            },
            Transport::Http,
            None,
            Some(&presented("h2", "02")),
        );
        assert_eq!(adopted.uid, Some(new_uid));
        assert!(adopted.reply.agent_identification.is_none());
        assert_eq!(state.snapshot().len(), 2, "one record per Agent, no more");
    }

    /// Forgetting an Agent releases its binding: another host's report for it binds it, under the
    /// identity it reported, where before it would have been re-keyed.
    /// Verifies: ADR-0047
    #[test]
    fn forgetting_an_agent_releases_its_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let revocations = Arc::new(
            Revocations::open(
                Box::new(crate::fs::FsLedgerStore::open(dir.path()).expect("ledger")),
                Arc::new(crate::clock::SystemClock),
                Vec::new(),
            )
            .expect("revocations"),
        );
        let state = AppState::new(dir.path().join("configs"))
            .expect("state")
            .with_revocations(Some(revocations.clone()));
        let presented = |host: &str| Presented {
            id: CertId::new(b"CA", host),
            host: Some(host.to_string()),
            subject_values: crate::revocation::SubjectValues::default(),
            not_after_ms: u64::MAX,
        };
        let uid = InstanceUid::default();
        let message = || AgentToServer {
            instance_uid: uid.as_bytes().to_vec(),
            capabilities: opamp::proto::AgentCapabilities::ReportsStatus as u64,
            ..Default::default()
        };
        let conn = state.connection_id();
        let first = state.process_presented(
            message(),
            Transport::WebSocket,
            Some(conn),
            Some(&presented("h1")),
        );
        assert_eq!(first.uid, Some(uid));
        state.mark_disconnected(&[uid], conn);
        assert!(state.forget_agent(&uid).is_ok(), "forgotten");
        assert_eq!(
            revocations.speaks_for("h1"),
            crate::revocation::SpeaksFor::Agents(std::collections::BTreeSet::new()),
            "released from h1"
        );

        let other = state.process_presented(
            message(),
            Transport::WebSocket,
            Some(state.connection_id()),
            Some(&presented("h2")),
        );
        assert_eq!(other.uid, Some(uid), "bound by h2, not re-keyed");
        assert!(other.reply.agent_identification.is_none());
        assert_eq!(
            revocations.speaks_for("h2"),
            crate::revocation::SpeaksFor::Agents([uid.to_string().replace('-', "")].into())
        );
    }

    /// A report refused at the record ceiling binds no `instance_uid` to the host that sent it,
    /// so it cannot speak for that Agent once there is room — nor lock out the host it belongs to.
    /// Verifies: ADR-0021, ADR-0024
    #[test]
    fn a_report_refused_at_the_ceiling_binds_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let revocations = Arc::new(
            Revocations::open(
                Box::new(crate::fs::FsLedgerStore::open(dir.path()).expect("ledger")),
                Arc::new(crate::clock::SystemClock),
                Vec::new(),
            )
            .expect("revocations"),
        );
        let state = AppState::new(dir.path().join("configs"))
            .expect("state")
            .with_max_agents(1)
            .with_revocations(Some(revocations.clone()));
        let presented = |host: &str| Presented {
            id: CertId::new(b"CA", host),
            host: Some(host.to_string()),
            subject_values: crate::revocation::SubjectValues::default(),
            not_after_ms: u64::MAX,
        };
        let first = InstanceUid::default();
        let accepted = state.process_presented(
            report(&first, 1),
            Transport::Http,
            None,
            Some(&presented("h1")),
        );
        assert!(accepted.reply.error_response.is_none());

        for flags in [0, AgentToServerFlags::RequestInstanceUid as u64] {
            let refused_uid = InstanceUid::default();
            let mut refused = report(&refused_uid, 1);
            refused.flags = flags;
            let refused =
                state.process_presented(refused, Transport::Http, None, Some(&presented("h2")));
            assert_eq!(
                refused.reply.error_response.expect("refused").r#type,
                ServerErrorResponseType::Unavailable as i32
            );
            assert_eq!(
                revocations.speaks_for("h2"),
                SpeaksFor::Agents(BTreeSet::new()),
                "a refused report bound an instance_uid (flags {flags})"
            );
        }
        assert_eq!(
            revocations.speaks_for("h1"),
            SpeaksFor::Agents([hex::encode(first.as_bytes())].into())
        );
    }

    // ---- Who may fetch an uploaded artifact (ADR-0026) ----

    /// A fleet delivering `otelcol@1.0.0`, uploaded and signed for linux/amd64 and held by the
    /// `stable` channel that claims every `otelcol`, with a host register.
    fn delivering_fleet(dir: &std::path::Path) -> (AppState, Arc<Revocations>, PackageId) {
        let store = PackageStore::open(dir.join("packages")).expect("store");
        let id = PackageId::new("otelcol", "1.0.0").expect("id");
        store.create(&id).expect("create");
        store
            .put_entry(&id, &linux(), b"v1".to_vec())
            .expect("entry");
        let revocations = Arc::new(
            Revocations::open(
                Box::new(crate::fs::FsLedgerStore::open(dir).expect("ledger")),
                Arc::new(crate::clock::SystemClock),
                Vec::new(),
            )
            .expect("revocations"),
        );
        let state = AppState::new(dir.join("configs"))
            .expect("state")
            .with_packages(Some(
                PackageOffering::new(&dir.join("packages"), store).expect("offering"),
            ))
            .with_revocations(Some(revocations.clone()));
        state
            .deployment_store()
            .expect("deployments")
            .put(
                "stable",
                BTreeMap::from([("service.name".to_string(), "otelcol".to_string())]),
            )
            .expect("deployment");
        put_signed(&state, &id);
        (state, revocations, id)
    }

    fn linux() -> Platform {
        Platform::new("linux", "amd64").expect("platform")
    }

    /// Signs `id` for linux/amd64 and puts it into the `stable` channel — saved, released to nobody.
    fn put_signed(state: &AppState, id: &PackageId) {
        state
            .put_package_entry_signature(id, &linux(), vec![1; 64])
            .expect("signature");
        state
            .put_deployment_package("stable", id, true)
            .expect("package");
    }

    /// One report of an `otelcol` Agent on linux/amd64 that accepts packages, over a certificate
    /// naming `host`, echoing `echoed` as the aggregate hash it holds.
    fn report_from(state: &AppState, host: &str, uid: InstanceUid, echoed: &[u8]) -> Processed {
        let attr = opamp::attributes::string_attr;
        state.process_presented(
            AgentToServer {
                instance_uid: uid.as_bytes().to_vec(),
                capabilities: opamp::proto::AgentCapabilities::ReportsStatus as u64
                    | opamp::proto::AgentCapabilities::AcceptsPackages as u64
                    | opamp::proto::AgentCapabilities::ReportsPackageStatuses as u64,
                agent_description: Some(AgentDescription {
                    identifying_attributes: vec![attr("service.name", "otelcol")],
                    non_identifying_attributes: vec![
                        attr("os.type", "linux"),
                        attr("host.arch", "amd64"),
                    ],
                }),
                package_statuses: (!echoed.is_empty()).then(|| PackageStatuses {
                    server_provided_all_packages_hash: echoed.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Transport::Http,
            None,
            Some(&Presented {
                id: CertId::new(b"CA", host),
                host: Some(host.to_string()),
                subject_values: crate::revocation::SubjectValues::default(),
                not_after_ms: u64::MAX,
            }),
        )
    }

    /// An artifact is fetched by a host only through an Agent it speaks for: the host whose Agent
    /// it was released to, not another host, not a host the register does not know, and not for
    /// another Platform or version — until that other host is marked as a Gateway.
    /// Verifies: ADR-0026
    #[test]
    fn an_artifact_is_offered_to_a_host_only_through_an_agent_it_speaks_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, revocations, id) = delivering_fleet(dir.path());
        report_from(&state, "h1", InstanceUid([1; 16]), &[]);
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        // h2 reports an Agent of its own, released nothing.
        state.process_presented(
            AgentToServer {
                instance_uid: vec![2; 16],
                capabilities: opamp::proto::AgentCapabilities::ReportsStatus as u64,
                ..Default::default()
            },
            Transport::Http,
            None,
            Some(&Presented {
                id: CertId::new(b"CA", "h2"),
                host: Some("h2".to_string()),
                subject_values: crate::revocation::SubjectValues::default(),
                not_after_ms: u64::MAX,
            }),
        );

        assert!(state.offers_artifact("h1", &id, &linux()));
        assert!(!state.offers_artifact("h2", &id, &linux()));
        assert!(!state.offers_artifact("unknown", &id, &linux()));
        let windows = Platform::new("windows", "amd64").expect("platform");
        assert!(!state.offers_artifact("h1", &id, &windows));
        let v2 = PackageId::new("otelcol", "2.0.0").expect("id");
        assert!(!state.offers_artifact("h1", &v2, &linux()));

        assert!(revocations.set_gateway("h2", true).expect("mark"));
        assert!(
            state.offers_artifact("h2", &id, &linux()),
            "a Gateway speaks for any Agent"
        );
    }

    /// The offer and the download agree on the capability half of the test (ADR-0033 clause 10): an
    /// Agent that does not declare `AcceptsPackages` is offered nothing, and its host may fetch
    /// nothing through it, although its assignment names a signed Package that fits it.
    /// Verifies: ADR-0033
    #[test]
    fn an_agent_that_accepts_no_packages_is_neither_offered_nor_fetched_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _, id) = delivering_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_from(&state, "h1", uid, &[]);
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        assert!(state.offers_artifact("h1", &id, &linux()));
        let attr = opamp::attributes::string_attr;
        let reply = state.process_presented(
            AgentToServer {
                instance_uid: uid.as_bytes().to_vec(),
                sequence_num: 1,
                capabilities: opamp::proto::AgentCapabilities::ReportsStatus as u64,
                agent_description: Some(AgentDescription {
                    identifying_attributes: vec![attr("service.name", "otelcol")],
                    non_identifying_attributes: vec![
                        attr("os.type", "linux"),
                        attr("host.arch", "amd64"),
                    ],
                }),
                ..Default::default()
            },
            Transport::Http,
            None,
            Some(&Presented {
                id: CertId::new(b"CA", "h1"),
                host: Some("h1".to_string()),
                subject_values: crate::revocation::SubjectValues::default(),
                not_after_ms: u64::MAX,
            }),
        );
        assert!(reply.reply.packages_available.is_none(), "no offer");
        assert!(!state.offers_artifact("h1", &id, &linux()), "and no fetch");
    }

    /// An Agent that echoes the aggregate hash of its offer is not sent it again, and can still
    /// fetch it — a retry after a failed install re-reads an offer no longer re-sent.
    /// Verifies: ADR-0026
    #[test]
    fn an_offer_still_stands_after_its_hash_is_echoed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _, id) = delivering_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_from(&state, "h1", uid, &[]);
        state.rollout_deployment("stable").expect("rollout");
        let offer = report_from(&state, "h1", uid, &[])
            .reply
            .packages_available
            .expect("an offer");
        let echoed = report_from(&state, "h1", uid, &offer.all_packages_hash);
        assert!(echoed.reply.packages_available.is_none(), "the hash gate");
        assert!(state.offers_artifact("h1", &id, &linux()));
    }

    /// A version saved into the channel but not yet released by an operator's press is no one's
    /// offer: not the Agent's host's, not a Gateway's — while the version released before stays.
    /// Verifies: ADR-0026
    #[test]
    fn a_version_waiting_for_its_press_is_offered_to_no_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, revocations, v1) = delivering_fleet(dir.path());
        report_from(&state, "h1", InstanceUid([1; 16]), &[]);
        report_from(&state, "gw", InstanceUid([9; 16]), &[]);
        assert!(revocations.set_gateway("gw", true).expect("mark"));
        state.rollout_deployment("stable").expect("rollout");

        let v2 = PackageId::new("otelcol", "2.0.0").expect("id");
        let store = state.packages().expect("store");
        store.create(&v2).expect("create");
        store
            .put_entry(&v2, &linux(), b"v2".to_vec())
            .expect("entry");
        put_signed(&state, &v2);
        for host in ["h1", "gw"] {
            assert!(!state.offers_artifact(host, &v2, &linux()), "{host}");
            assert!(state.offers_artifact(host, &v1, &linux()), "{host}");
        }
        assert_eq!(state.rollout_deployment("stable").expect("the press"), 2);
        assert!(state.offers_artifact("h1", &v2, &linux()));
    }

    // ---- A Deployment carries Configurations beside its Packages (ADR-0034) ----

    /// One report of an `otelcol` Agent on linux/amd64 over a certificate naming `h1` that takes
    /// both remote configuration and packages, echoing the hashes it holds.
    fn report_holding(
        state: &AppState,
        uid: InstanceUid,
        config_hash: &[u8],
        packages_hash: &[u8],
    ) -> Processed {
        use opamp::proto::AgentCapabilities as C;
        let attr = opamp::attributes::string_attr;
        state.process_presented(
            AgentToServer {
                instance_uid: uid.as_bytes().to_vec(),
                capabilities: C::ReportsStatus as u64
                    | C::AcceptsRemoteConfig as u64
                    | C::AcceptsPackages as u64
                    | C::ReportsPackageStatuses as u64,
                agent_description: Some(AgentDescription {
                    identifying_attributes: vec![attr("service.name", "otelcol")],
                    non_identifying_attributes: vec![
                        attr("os.type", "linux"),
                        attr("host.arch", "amd64"),
                    ],
                }),
                remote_config_status: (!config_hash.is_empty()).then(|| RemoteConfigStatus {
                    last_remote_config_hash: config_hash.to_vec(),
                    status: RemoteConfigStatuses::Applied as i32,
                    ..Default::default()
                }),
                package_statuses: (!packages_hash.is_empty()).then(|| PackageStatuses {
                    server_provided_all_packages_hash: packages_hash.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Transport::Http,
            None,
            Some(&Presented {
                id: CertId::new(b"CA", "h1"),
                host: Some("h1".to_string()),
                subject_values: crate::revocation::SubjectValues::default(),
                not_after_ms: u64::MAX,
            }),
        )
    }

    /// The names of the entries a config offer carries.
    fn offered_names(offer: &AgentRemoteConfig) -> Vec<String> {
        let mut names: Vec<String> = offer
            .config
            .as_ref()
            .expect("a map")
            .config_map
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    }

    /// `delivering_fleet` with two Configurations in `stable`: `base`, for the Agent's type, and
    /// `telegraf-conf`, typed for another Agent type.
    fn mixed_fleet(dir: &std::path::Path) -> (AppState, PackageId) {
        let (state, _, id) = delivering_fleet(dir);
        state
            .save_configuration("base", body("receivers: {}\n"))
            .expect("base");
        let mut telegraf = body("[agent]\n");
        telegraf.service_name = "telegraf".to_string();
        state
            .save_configuration("telegraf-conf", telegraf)
            .expect("telegraf");
        for name in ["base", "telegraf-conf"] {
            state
                .put_deployment_configuration("stable", name)
                .expect("hold it");
        }
        (state, id)
    }

    /// A Deployment holding a Package and two Configurations, one typed for another Agent type,
    /// releases to an Agent the Package and the one Configuration that fits it — one act, one
    /// assignment.
    /// Verifies: ADR-0034
    #[test]
    fn a_deployment_releases_its_package_and_the_fitting_configurations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, id) = mixed_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);

        let reply = report_holding(&state, uid, &[], &[]).reply;
        let config = reply.remote_config.expect("a config offer");
        assert_eq!(
            offered_names(&config),
            ["base"],
            "the typed one does not fit"
        );
        let packages = reply.packages_available.expect("a package offer");
        assert_eq!(
            packages.packages.keys().collect::<Vec<_>>(),
            [&id.agent_type]
        );
        let view = &state.snapshot()[0];
        assert_eq!(view.assigned_deployment, "stable");
        assert_eq!(view.assigned_package, id.to_string());
        assert_eq!(view.assigned_configurations, ["base"]);
        assert!(view.pending_configurations.is_empty());
        assert!(view.pending_packages.is_empty());
    }

    /// The hash gates send only what changed: a new body re-sends the config map and no package
    /// offer, and a new Package re-sends the package offer and no config map — though each is
    /// one press of the whole Deployment.
    /// Verifies: ADR-0034
    #[test]
    fn a_second_press_sends_only_the_part_that_changed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _) = mixed_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        state.rollout_deployment("stable").expect("rollout");
        let first = report_holding(&state, uid, &[], &[]).reply;
        let config_hash = first.remote_config.expect("config").config_hash;
        let packages_hash = first
            .packages_available
            .expect("packages")
            .all_packages_hash;
        let settled = report_holding(&state, uid, &config_hash, &packages_hash).reply;
        assert!(settled.remote_config.is_none() && settled.packages_available.is_none());

        state
            .save_configuration("base", body("receivers: {otlp: {}}\n"))
            .expect("edit");
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        let reply = report_holding(&state, uid, &config_hash, &packages_hash).reply;
        let config_hash = reply.remote_config.expect("the new map").config_hash;
        assert!(reply.packages_available.is_none(), "no new package offer");

        let v2 = PackageId::new("otelcol", "2.0.0").expect("id");
        let store = state.packages().expect("store");
        store.create(&v2).expect("create");
        store
            .put_entry(&v2, &linux(), b"v2".to_vec())
            .expect("entry");
        put_signed(&state, &v2);
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        let reply = report_holding(&state, uid, &config_hash, &packages_hash).reply;
        assert!(reply.remote_config.is_none(), "no new config map");
        assert!(reply.packages_available.is_some(), "the new package offer");
    }

    /// A press of a Deployment that no longer holds a Configuration drops it from the Agent's map;
    /// until the press, the view shows the drop waiting.
    /// Verifies: ADR-0034
    #[test]
    fn a_configuration_the_deployment_dropped_leaves_the_map_on_the_next_press() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _) = mixed_fleet(dir.path());
        state
            .save_configuration("extra", body("exporters: {}\n"))
            .expect("extra");
        state
            .put_deployment_configuration("stable", "extra")
            .expect("hold it");
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        state.rollout_deployment("stable").expect("rollout");
        let offer = report_holding(&state, uid, &[], &[])
            .reply
            .remote_config
            .expect("offer");
        assert_eq!(offered_names(&offer), ["base", "extra"]);

        state
            .remove_deployment_configuration("stable", "extra")
            .expect("drop it");
        let view = &state.snapshot()[0];
        assert_eq!(view.assigned_configurations, ["base", "extra"]);
        assert_eq!(
            view.pending_configurations
                .iter()
                .map(|p| (p.name.as_str(), p.change.as_str()))
                .collect::<Vec<_>>(),
            [("extra", "remove")]
        );
        assert_eq!(state.deployment_reach()["stable"].targeted, 1);

        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        assert_eq!(state.snapshot()[0].assigned_configurations, ["base"]);
        let offer = report_holding(&state, uid, &offer.config_hash, &[])
            .reply
            .remote_config
            .expect("the smaller map is offered");
        assert_eq!(offered_names(&offer), ["base"]);
    }

    /// A Deployment that keeps nothing for an Agent leaves it with no assignment on the next press,
    /// and the Agent keeps running what it runs: the view shows what it was given as `kept`, never
    /// as `remove`, and the press makes no offer that would take it away. A Package pinned with no
    /// Configuration sends no config map either, so nothing empty ever replaces a running one.
    /// Verifies: ADR-0034
    #[test]
    fn a_release_holding_nothing_for_an_agent_keeps_what_it_runs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, id) = mixed_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        state.rollout_deployment("stable").expect("rollout");
        let first = report_holding(&state, uid, &[], &[]).reply;
        let config_hash = first.remote_config.expect("config").config_hash;
        let packages_hash = first
            .packages_available
            .expect("packages")
            .all_packages_hash;

        // `telegraf-conf` stays, so the Deployment still holds something and may be pressed; none
        // of it fits this Agent.
        state
            .remove_deployment_configuration("stable", "base")
            .expect("drop base");
        state
            .remove_deployment_package("stable", &id)
            .expect("drop the package");
        let view = &state.snapshot()[0];
        let changes = |view: &AgentView| {
            view.pending_configurations
                .iter()
                .map(|p| (p.name.clone(), p.change.clone()))
                .chain(
                    view.pending_packages
                        .iter()
                        .map(|p| (p.display_name.clone(), p.change.clone())),
                )
                .collect::<Vec<_>>()
        };
        assert_eq!(
            changes(view),
            [
                ("base".to_string(), "kept".to_string()),
                (id.display_name(), "kept".to_string())
            ],
            "nothing is removed from an Agent the press leaves with no assignment"
        );
        assert_eq!(state.deployment_reach()["stable"].targeted, 1);

        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        let view = &state.snapshot()[0];
        assert!(view.assigned_deployment.is_empty() && view.assigned_configurations.is_empty());
        assert!(changes(view).is_empty(), "nothing waits any more");
        let reply = report_holding(&state, uid, &config_hash, &packages_hash).reply;
        assert!(
            reply.remote_config.is_none(),
            "no config map replaces the one it runs"
        );

        // A Package and no Configuration, to an Agent that runs nothing yet: a package offer, and
        // no config map at all.
        state
            .put_deployment_package("stable", &id, true)
            .expect("the package again");
        let fresh = InstanceUid([2; 16]);
        report_holding(&state, fresh, &[], &[]);
        state.rollout_deployment("stable").expect("rollout");
        let reply = report_holding(&state, fresh, &[], &[]).reply;
        assert!(reply.packages_available.is_some(), "the package is offered");
        assert!(
            reply.remote_config.is_none(),
            "an assignment holding no Configuration offers no empty map"
        );
    }

    /// A Deployment that newly claims an Agent with the content its assignment already pins still
    /// moves that assignment on a press, so the view shows the Deployment waiting — the count
    /// beside the press, the per-Agent press and the view agree.
    /// Verifies: ADR-0034
    #[test]
    fn a_new_claiming_deployment_with_the_same_content_waits_in_the_view() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = configuring_fleet(dir.path());
        let uid = InstanceUid::default();
        state.process(report(&uid, 1), Transport::Http, None);
        state.rollout_deployment("stable").expect("rollout");
        let deployments = state.deployment_store().expect("deployments");
        deployments
            .put(
                "stable",
                BTreeMap::from([("service.name".to_string(), "nobody".to_string())]),
            )
            .expect("re-aim stable away");
        deployments
            .put(
                "canary",
                BTreeMap::from([("service.name".to_string(), "otelcol".to_string())]),
            )
            .expect("canary");
        state
            .put_deployment_configuration("canary", "fleet")
            .expect("the same Configuration");

        let view = &state.snapshot()[0];
        assert_eq!(view.assigned_deployment, "stable");
        assert!(view.pending_configurations.is_empty() && view.pending_packages.is_empty());
        assert_eq!(view.pending_deployment, "canary");
        assert_eq!(state.deployment_reach()["canary"].targeted, 1);

        state.rollout_to_agent(&uid, None).expect("the press");
        let view = &state.snapshot()[0];
        assert_eq!(view.assigned_deployment, "canary");
        assert!(view.pending_deployment.is_empty());
        assert_eq!(state.deployment_reach()["canary"].targeted, 0);
    }

    /// Editing a Deployment after a rollout — a Configuration's body, a Configuration added, the
    /// Package swapped — changes no Agent's offer until the next press, and the view shows each
    /// change waiting.
    /// Verifies: ADR-0034
    #[test]
    fn editing_a_deployment_changes_no_offer_until_the_next_press() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _) = mixed_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        state.rollout_deployment("stable").expect("rollout");
        let first = report_holding(&state, uid, &[], &[]).reply;
        let config_hash = first.remote_config.expect("config").config_hash;
        let packages_hash = first
            .packages_available
            .expect("packages")
            .all_packages_hash;

        state
            .save_configuration("base", body("receivers: {otlp: {}}\n"))
            .expect("edit");
        state
            .save_configuration("extra", body("exporters: {}\n"))
            .expect("extra");
        state
            .put_deployment_configuration("stable", "extra")
            .expect("hold it");
        let v2 = PackageId::new("otelcol", "2.0.0").expect("id");
        let store = state.packages().expect("store");
        store.create(&v2).expect("create");
        store
            .put_entry(&v2, &linux(), b"v2".to_vec())
            .expect("entry");
        put_signed(&state, &v2);

        let reply = report_holding(&state, uid, &config_hash, &packages_hash).reply;
        assert!(reply.remote_config.is_none(), "the edits reach nobody yet");
        assert!(
            reply.packages_available.is_none(),
            "the swap reaches nobody yet"
        );
        let view = &state.snapshot()[0];
        assert_eq!(
            view.pending_configurations
                .iter()
                .map(|p| (p.name.as_str(), p.change.as_str()))
                .collect::<Vec<_>>(),
            [("base", "update"), ("extra", "new")]
        );
        assert_eq!(view.pending_packages[0].change, "update");
        assert_eq!(view.pending_packages[0].version, "2.0.0");

        state
            .rollout_to_agent(&uid, Some("stable"))
            .expect("the press");
        let reply = report_holding(&state, uid, &config_hash, &packages_hash).reply;
        assert!(reply.remote_config.is_some() && reply.packages_available.is_some());
    }

    /// The per-Agent act releases only the Deployment that claims the Agent: one in no Deployment,
    /// one two Deployments claim, and naming another Deployment are each refused, as is a
    /// Deployment that holds nothing — and nothing is assigned.
    /// Verifies: ADR-0034
    #[test]
    fn the_per_agent_act_refuses_without_exactly_one_claiming_deployment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _) = mixed_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        let deployments = state.deployment_store().expect("deployments");

        deployments
            .put(
                "canary",
                BTreeMap::from([("channel".into(), "canary".into())]),
            )
            .expect("canary");
        assert!(matches!(
            state.rollout_to_agent(&uid, Some("canary")),
            Err(RolloutError::NotApplicable(why)) if why.contains("\"stable\"")
        ));

        deployments
            .put(
                "linux",
                BTreeMap::from([("os.type".into(), "linux".into())]),
            )
            .expect("a second channel claiming it");
        assert!(matches!(
            state.rollout_to_agent(&uid, None),
            Err(RolloutError::NotApplicable(why)) if why.contains("linux") && why.contains("stable")
        ));
        assert!(matches!(
            state.rollout_to_agent(&uid, Some("stable")),
            Err(RolloutError::NotApplicable(_))
        ));
        assert_eq!(
            state
                .rollout_deployment("stable")
                .expect("the press skips it"),
            0
        );

        state.delete_deployment("linux").expect("delete");
        state.delete_deployment("stable").expect("delete");
        assert!(matches!(
            state.rollout_to_agent(&uid, None),
            Err(RolloutError::NotApplicable(why)) if why.contains("no deployment")
        ));

        deployments
            .put(
                "empty",
                BTreeMap::from([("os.type".into(), "linux".into())]),
            )
            .expect("a channel holding nothing");
        assert!(matches!(
            state.rollout_to_agent(&uid, None),
            Err(RolloutError::NotApplicable(why)) if why.contains("holds no package and no configuration")
        ));
        assert!(matches!(
            state.rollout_deployment("empty"),
            Err(RolloutError::NotApplicable(_))
        ));
        assert!(state.snapshot()[0].assigned_deployment.is_empty());
    }

    /// Nothing an assignment pins can be deleted — a Configuration, a Package, a Deployment — and
    /// the refusal says how many Agents pin it. After a press without it the deletion succeeds,
    /// and a deleted Configuration or Package leaves every Deployment that held it.
    /// Verifies: ADR-0034
    #[test]
    fn nothing_an_assignment_pins_can_be_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, id) = mixed_fleet(dir.path());
        let uid = InstanceUid([1; 16]);
        report_holding(&state, uid, &[], &[]);
        let deployments = state.deployment_store().expect("deployments");
        deployments
            .put(
                "canary",
                BTreeMap::from([("channel".into(), "canary".into())]),
            )
            .expect("canary");
        state
            .put_deployment_configuration("canary", "base")
            .expect("base in canary too");
        state
            .put_deployment_package("canary", &id, false)
            .expect("the package in canary too");
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);

        assert!(matches!(
            state.delete_configuration("base"),
            Err(DeleteError::Pinned(why)) if why.contains("1 Agent")
        ));
        let refused = state.delete_package_set(&id).expect_err("pinned");
        assert!(refused.contains("1 Agent"), "{refused}");
        assert!(matches!(
            state.delete_deployment("stable"),
            Err(DeploymentError::Conflict(why)) if why.contains("1 Agent")
        ));

        // Taking both out of the channel is not refused, and the next press releases without them.
        state
            .remove_deployment_configuration("stable", "base")
            .expect("nothing a Deployment holds is frozen");
        state
            .remove_deployment_package("stable", &id)
            .expect("nothing a Deployment holds is frozen");
        state
            .save_configuration("other", body("exporters: {}\n"))
            .expect("other");
        state
            .put_deployment_configuration("stable", "other")
            .expect("hold it");
        assert_eq!(state.rollout_deployment("stable").expect("rollout"), 1);
        assert!(state.delete_configuration("base").expect("deleted"));
        assert!(state.delete_package_set(&id).expect("deleted"));
        let canary = deployments.get("canary").expect("canary");
        assert!(
            canary.configurations.is_empty() && canary.packages.is_empty(),
            "both left every Deployment that held them"
        );
        assert!(state.configurations().get("base").is_none());

        // The Deployment goes once its Agents are released through another one.
        state
            .put_deployment_configuration("canary", "other")
            .expect("hold it");
        state
            .set_labels(&uid, BTreeMap::from([("channel".into(), "canary".into())]))
            .unwrap_or_else(|_| panic!("label"));
        deployments
            .put(
                "stable",
                BTreeMap::from([("channel".into(), "stable".into())]),
            )
            .expect("re-aim");
        assert_eq!(state.rollout_deployment("canary").expect("rollout"), 1);
        assert!(state.delete_deployment("stable").expect("deleted"));
    }

    // ---- Hosts, the effective description and label inheritance (ADR-0035) ----

    /// A fleet whose host register is kept in `dir`, so a reopen restores both.
    fn hosted_fleet(dir: &std::path::Path) -> AppState {
        let revocations = Arc::new(
            Revocations::open(
                Box::new(crate::fs::FsLedgerStore::open(dir).expect("ledger")),
                Arc::new(crate::clock::SystemClock),
                Vec::new(),
            )
            .expect("revocations"),
        );
        AppState::new(dir.join("configs"))
            .expect("state")
            .with_revocations(Some(revocations))
    }

    fn organization(name: &str) -> crate::revocation::SubjectValues {
        crate::revocation::SubjectValues {
            organization: name.to_string(),
            ..Default::default()
        }
    }

    /// A full report from `uid` describing itself with `pairs`, over a certificate naming `host`
    /// whose subject carries `subject`.
    fn report_over(
        state: &AppState,
        host: &str,
        subject: crate::revocation::SubjectValues,
        uid: InstanceUid,
        pairs: &[(&str, &str)],
    ) -> Processed {
        let mut message = report(&uid, 1);
        message
            .agent_description
            .as_mut()
            .expect("described")
            .non_identifying_attributes = pairs
            .iter()
            .map(|(key, value)| opamp::attributes::string_attr(key, value))
            .collect();
        state.process_presented(
            message,
            Transport::Http,
            None,
            Some(&Presented {
                id: CertId::new(b"CA", host),
                host: Some(host.to_string()),
                subject_values: subject,
                not_after_ms: u64::MAX,
            }),
        )
    }

    /// Whether a Selector of `pairs` matches this Agent — the one test every Selector is decided by.
    fn selects(state: &AppState, uid: &InstanceUid, pairs: &[(&str, &str)]) -> bool {
        let selector: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let fleet = state.fleet.lock().expect("fleet lock");
        let record = fleet.get(uid).expect("known");
        deployments::matches(&selector, record.effective_description().as_deref())
    }

    fn view(state: &AppState, uid: &InstanceUid) -> AgentView {
        state
            .snapshot()
            .into_iter()
            .find(|view| view.instance_uid == uid.to_string())
            .expect("in the view")
    }

    fn label(state: &AppState, uid: &InstanceUid, pairs: &[(&str, &str)]) {
        let set = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        if state.set_labels(uid, set).is_err() {
            panic!("labels refused");
        }
    }

    /// An Agent on a direct connection carries its Host's subject values as `fleet.host.*`; an
    /// Agent that reports `fleet.host.organization` itself is not selected by it, and the attribute
    /// is listed as ignored. Without a host register an Agent names no Host.
    /// Verifies: ADR-0035
    #[test]
    fn a_direct_agent_matches_its_hosts_values_and_none_it_reports_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = hosted_fleet(dir.path());
        let honest = InstanceUid::default();
        report_over(&state, "h1", organization("Kunde GmbH"), honest, &[]);
        assert!(selects(
            &state,
            &honest,
            &[("fleet.host.organization", "Kunde GmbH")]
        ));
        assert_eq!(view(&state, &honest).host, "h1");
        assert_eq!(
            view(&state, &honest).host_attributes["fleet.host.organization"],
            "Kunde GmbH"
        );

        // On a Host of its own whose certificate carries no organization.
        let claimant = InstanceUid::default();
        report_over(
            &state,
            "h2",
            crate::revocation::SubjectValues::default(),
            claimant,
            &[("fleet.host.organization", "Kunde GmbH")],
        );
        assert!(!selects(
            &state,
            &claimant,
            &[("fleet.host.organization", "Kunde GmbH")]
        ));
        assert_eq!(
            view(&state, &claimant).ignored_attributes,
            ["fleet.host.organization"]
        );

        // On the Host whose values it would contradict, the Host's value is what matches.
        let liar = InstanceUid::default();
        report_over(
            &state,
            "h1",
            organization("Kunde GmbH"),
            liar,
            &[("fleet.host.organization", "Mitbewerber AG")],
        );
        assert!(selects(
            &state,
            &liar,
            &[("fleet.host.organization", "Kunde GmbH")]
        ));
        assert!(!selects(
            &state,
            &liar,
            &[("fleet.host.organization", "Mitbewerber AG")]
        ));

        // A Server without a host register has no Hosts, and its records name none.
        let bare = AppState::new(dir.path().join("bare")).expect("state");
        let uid = InstanceUid::default();
        report_over(&bare, "h1", organization("Kunde GmbH"), uid, &[]);
        assert_eq!(view(&bare, &uid).host, "");
        assert!(!selects(
            &bare,
            &uid,
            &[("fleet.host.organization", "Kunde GmbH")]
        ));
    }

    /// A Supervisor Agent matches a Selector on a label set only on its Client Agent, its own label
    /// of the same key wins, the Agents tab is told which labels are inherited, and all of it
    /// survives a restart.
    /// Verifies: ADR-0035
    #[test]
    fn a_supervisor_agent_inherits_its_client_agents_labels_below_its_own() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = InstanceUid::default();
        let supervisor = InstanceUid::default();
        {
            let state = hosted_fleet(dir.path());
            report_over(
                &state,
                "h1",
                organization("Kunde GmbH"),
                client,
                &[("supervisor.kind.collector", "true")],
            );
            report_over(&state, "h1", organization("Kunde GmbH"), supervisor, &[]);
            label(&state, &client, &[("ring", "early"), ("site", "wien")]);
            label(&state, &supervisor, &[("ring", "late")]);
            assert!(selects(&state, &supervisor, &[("site", "wien")]));
            assert!(selects(&state, &supervisor, &[("ring", "late")]));
            assert!(!selects(&state, &supervisor, &[("ring", "early")]));
            assert!(selects(&state, &client, &[("ring", "early")]));
        }
        let state = hosted_fleet(dir.path());
        assert!(
            selects(&state, &supervisor, &[("site", "wien"), ("ring", "late")]),
            "restored with its own labels and its Client Agent's"
        );
        let seen = view(&state, &supervisor);
        assert_eq!(seen.client_agent, client.to_string());
        assert_eq!(
            seen.inherited_labels,
            BTreeMap::from([
                ("ring".to_string(), "early".to_string()),
                ("site".to_string(), "wien".to_string())
            ])
        );
        assert!(view(&state, &client).inherited_labels.is_empty());

        // The Client Agent's labels cleared, nothing is inherited any more.
        label(&state, &client, &[]);
        assert!(!selects(&state, &supervisor, &[("site", "wien")]));
    }

    /// Behind a Gateway an Agent carries no `fleet.host.*`; the Agents sharing a `host.id` inherit
    /// their Client Agent's labels, and two Client Agents with one `host.id` leave every Agent of it
    /// inheriting nothing and marked ambiguous.
    /// Verifies: ADR-0035
    #[test]
    fn behind_a_gateway_agents_sharing_a_host_id_inherit_unless_ambiguous() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = hosted_fleet(dir.path());
        let gateway = InstanceUid::default();
        report_over(
            &state,
            "gw",
            organization("Gateway GmbH"),
            gateway,
            &[("supervisor.kind.collector", "true"), ("host.id", "gw-1")],
        );
        assert!(state.set_gateway("gw", true).expect("marked"));
        assert!(
            !selects(
                &state,
                &gateway,
                &[("fleet.host.organization", "Gateway GmbH")]
            ),
            "nothing arrives over a Gateway directly"
        );

        let client = InstanceUid::default();
        let supervisor = InstanceUid::default();
        let elsewhere = InstanceUid::default();
        let behind = |uid, pairs: &[(&str, &str)]| {
            report_over(&state, "gw", organization("Gateway GmbH"), uid, pairs);
        };
        behind(
            client,
            &[("supervisor.kind.collector", "true"), ("host.id", "m-1")],
        );
        behind(supervisor, &[("host.id", "m-1")]);
        behind(elsewhere, &[("host.id", "m-2")]);
        label(&state, &client, &[("site", "linz")]);
        assert!(selects(&state, &supervisor, &[("site", "linz")]));
        assert!(!selects(&state, &elsewhere, &[("site", "linz")]));
        let seen = view(&state, &supervisor);
        assert_eq!(seen.host, "gw");
        assert!(seen.host_attributes.is_empty());
        assert!(!seen.ambiguous);

        // A second Client on the same machine: nobody of it can be told apart.
        let second = InstanceUid::default();
        behind(
            second,
            &[("supervisor.kind.collector", "true"), ("host.id", "m-1")],
        );
        assert!(!selects(&state, &supervisor, &[("site", "linz")]));
        for uid in [client, supervisor, second] {
            assert!(view(&state, &uid).ambiguous, "{uid}");
        }
        assert!(!view(&state, &elsewhere).ambiguous);
    }

    /// A Client Agent re-keyed by a compressed message — no description to place it by — stays
    /// its group's Client Agent: its Supervisor Agents keep inheriting its labels, and a label set
    /// on its new identity reaches them.
    /// Verifies: ADR-0035
    #[test]
    fn a_client_agent_rekeyed_without_a_description_keeps_its_group_inheriting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = hosted_fleet(dir.path());
        let client = InstanceUid::default();
        let supervisor = InstanceUid::default();
        report_over(
            &state,
            "h1",
            organization("Kunde GmbH"),
            client,
            &[("supervisor.kind.collector", "true")],
        );
        report_over(&state, "h1", organization("Kunde GmbH"), supervisor, &[]);
        label(&state, &client, &[("site", "wien")]);
        assert!(selects(&state, &supervisor, &[("site", "wien")]));

        let rekey = AgentToServer {
            instance_uid: client.as_bytes().to_vec(),
            sequence_num: 2,
            capabilities: opamp::proto::AgentCapabilities::ReportsStatus as u64,
            flags: AgentToServerFlags::RequestInstanceUid as u64,
            ..Default::default()
        };
        let rekeyed = state
            .process_presented(
                rekey,
                Transport::Http,
                None,
                Some(&Presented {
                    id: CertId::new(b"CA", "h1"),
                    host: Some("h1".to_string()),
                    subject_values: organization("Kunde GmbH"),
                    not_after_ms: u64::MAX,
                }),
            )
            .uid
            .expect("the new identity");
        assert_ne!(rekeyed, client);
        assert!(
            selects(&state, &supervisor, &[("site", "wien")]),
            "the Supervisor Agent still inherits"
        );
        assert_eq!(view(&state, &supervisor).client_agent, rekeyed.to_string());
        assert_eq!(view(&state, &rekeyed).client_agent, rekeyed.to_string());

        label(&state, &rekeyed, &[("site", "linz")]);
        assert!(selects(&state, &supervisor, &[("site", "linz")]));
    }

    /// Labels are part of the Agent's record: a re-keyed Agent keeps them, on disk too, and
    /// forgetting it removes them — it comes back unlabelled.
    /// Verifies: ADR-0035
    #[test]
    fn forgetting_an_agent_removes_its_labels_and_a_rekey_keeps_them() {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        let state = AppState::new(dir.clone())
            .expect("state")
            .with_stale_after(Duration::from_secs(90));
        let uid = InstanceUid::default();
        state.process(report(&uid, 1), Transport::WebSocket, Some(1));
        label(&state, &uid, &[("rollout", "canary")]);

        let mut rekey = report(&uid, 2);
        rekey.flags = AgentToServerFlags::RequestInstanceUid as u64;
        let new_uid = state
            .process(rekey, Transport::WebSocket, Some(1))
            .uid
            .expect("the new identity");
        assert_eq!(view(&state, &new_uid).labels["rollout"], "canary");
        let stored = std::fs::read_to_string(dir.join("agents").join(format!("{new_uid}.json")))
            .expect("stored");
        assert!(stored.contains("canary"), "{stored}");

        let mut goodbye = report(&new_uid, 3);
        goodbye.agent_disconnect = Some(opamp::proto::AgentDisconnect {});
        state.process(goodbye, Transport::WebSocket, Some(1));
        assert!(state.forget_agent(&new_uid).is_ok());
        state.process(report(&new_uid, 4), Transport::WebSocket, Some(2));
        assert!(
            view(&state, &new_uid).labels.is_empty(),
            "it comes back unlabelled"
        );
        assert!(!dir.join("labels").exists(), "no label store is written");
    }
}
