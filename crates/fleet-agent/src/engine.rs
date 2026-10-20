//! The Engine: n Agents over one upstream connection (ADR-0015, ADR-0017).
//!
//! This is the Server-facing seam of the hexagonal core. The transports consume it — build
//! reports, hand it every decoded `ServerToAgent`, ask for the goodbyes — and it routes each
//! reply to the owning Agent by `instance_uid` alone, never by connection. With one self-Agent
//! it behaves exactly like the single-Agent Client did; with Supervisors it multiplexes them.

use std::sync::{Arc, Mutex};

use opamp::proto::{AgentRemoteConfig, AgentToServer, ConnectionSettingsOffers, ServerToAgent};
use opamp::uid::InstanceUid;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::supervisor::agent::PackageDownload;
use crate::supervisor::agent::{AgentState, Handled};
use crate::supervisor::ports::{HighWaterMarks, ProcessCommand, ProcessEvent};
use crate::update::{SelfInstall, SelfUpdate, SelfUpdater};

/// The Engine index of the Client's own Agent (ADR-0018). It is built first, so a Supervisor's
/// index is its block's position plus this.
pub const SELF_AGENT_INDEX: usize = 0;

/// One Agent's own metrics: which Agent a series belongs to, and the process to read it from.
///
/// All three names travel together because none answers on its own. The uid is the identity the
/// protocol keys everything by, the instance name is the only part of it an operator recognises,
/// and the type says what the thing *is* (ADR-0016) — a series labelled with one and not the others
/// is either unreadable or ambiguous.
#[derive(Clone)]
pub struct SamplingTarget {
    /// The Agent's `service.instance.id`.
    pub uid: String,
    /// The operator's name for it.
    pub instance_name: String,
    /// The Agent *type* it is reported under — `service.name` (ADR-0016). Per Agent rather than on
    /// the Resource: one Client reports its own `supervisor` beside an `otelcol` and an `icinga2`,
    /// so unlike the platform this differs *within* a single export.
    pub service_name: String,
    /// The process to sample: this one for the Client's own Agent, the Managed Process for a
    /// Supervisor-backed one.
    pub pid: u32,
}

/// One Agent as [`Engine::with_processes`] takes it: the protocol state machine plus the handles
/// the Engine drives its Supervisor with — all `None` for the self-Agent.
pub struct EngineAgent {
    pub state: AgentState,
    /// The command side of its Managed-Process Port.
    pub commands: Option<mpsc::Sender<ProcessCommand>>,
    /// Fires this Supervisor's own shutdown (ADR-0017): its adapter and its Supervisor Endpoint
    /// listen on the receiving side, so one Supervisor can be stopped — port released, process
    /// down — while the rest of the Client runs on.
    pub stop: Option<watch::Sender<bool>>,
    /// The `[[supervisor]]` block name behind this Agent — what package staging and the
    /// Supervisor-set diff are keyed by, since an Engine index stops naming a block position the
    /// moment the set changes at runtime (ADR-0017).
    pub block_name: Option<String>,
}

/// One Agent as the Engine carries it: its protocol state machine, the handles of its
/// Managed-Process Port (absent for the self-Agent), and the bookkeeping of whether it owes the
/// Server a report right now.
struct SupervisedAgent {
    state: AgentState,
    commands: Option<mpsc::Sender<ProcessCommand>>,
    stop: Option<watch::Sender<bool>>,
    block_name: Option<String>,
    /// A handled reply asked for an immediate report (config outcome, demanded full state).
    owes_report: bool,
    /// Retired by a Supervisor-set change (ADR-0017): its goodbye is sent, its adapter is gone,
    /// and it is skipped everywhere. The slot stays — the event channel and package routing are
    /// keyed by index, and a shifted index would misdeliver to a live neighbour.
    retired: bool,
}

impl SupervisedAgent {
    fn live(agent: EngineAgent) -> Self {
        SupervisedAgent {
            state: agent.state,
            commands: agent.commands,
            stop: agent.stop,
            block_name: agent.block_name,
            owes_report: false,
            retired: false,
        }
    }

    /// Records a package's terminal outcome and owes the Server the report that carries it.
    fn package_applied(&mut self, hash: Vec<u8>, result: Result<String, String>) {
        self.state.package_applied(hash, result);
        self.owes_report = true;
    }
}

pub struct Engine {
    agents: Vec<SupervisedAgent>,
    /// The shared event channel every adapter reports into, tagged with the Agent's index.
    events: mpsc::Receiver<(usize, ProcessEvent)>,
    /// The sending side of that channel, kept to start Supervisors at runtime (ADR-0017) — a
    /// fresh adapter needs a tagged sender into the same channel.
    event_tx: mpsc::Sender<(usize, ProcessEvent)>,
    /// The self-Agent's received configuration awaiting the Supervisor-set apply (ADR-0017),
    /// taken by the transport exactly once.
    pending_self_config: Option<AgentRemoteConfig>,
    /// A connection-settings offer awaiting the transport's verification (ADR-0014). The offer
    /// arrives per Agent but the settings are connection-scoped, so the Engine keeps exactly one
    /// pending offer — n Agents receiving the same offer verify and switch once.
    pending_connection_offer: Option<ConnectionSettingsOffers>,
    /// Packages awaiting the transport's download and verification (ADR-0026), each tagged with
    /// the owning Agent's index so the verified artifact routes back to the right Supervisor.
    pending_package_downloads: Vec<(usize, PackageDownload)>,
    /// How the Client updates *itself* (ADR-0018). Unarmed when `[packages] self_update = false`, in
    /// which case the self-Agent accepts no packages anyway.
    self_update: SelfUpdate,
    /// The sampling targets, shared with the own-telemetry sampler (ADR-0016), which runs beside
    /// a transport that holds this Engine mutably for the whole of a connection.
    sampling: Arc<Mutex<Vec<SamplingTarget>>>,
    /// The certificate request last queued on this connection (ADR-0021): a new one goes out at
    /// once, the same one again only with the next report.
    last_csr: Option<Vec<u8>>,
    /// The high-water marks every Supervisor of this Client shares (ADR-0043 clause 8), kept so a
    /// Supervisor a set apply adds at runtime is held to the same marks.
    high_water: Option<Arc<dyn HighWaterMarks>>,
}

impl Engine {
    /// An Engine over Agents without Managed Processes. The Client always builds its self-Agent
    /// *and* its Supervisors through [`with_processes`](Self::with_processes) (ADR-0018), so this
    /// is the tests' constructor — the shape it stands for does not occur in production.
    #[cfg(test)]
    #[must_use]
    pub fn new(agents: Vec<AgentState>) -> Self {
        let (event_tx, events) = mpsc::channel(1);
        Engine::with_processes(
            agents
                .into_iter()
                .map(|state| EngineAgent {
                    state,
                    commands: None,
                    stop: None,
                    block_name: None,
                })
                .collect(),
            events,
            event_tx,
        )
    }

    /// An Engine over Supervisor-backed Agents: each with the handles of its Port, all sharing
    /// one event channel (senders tagged by the Agent's index here). `event_tx` is the sending
    /// side of `events`, kept for Supervisors started at runtime (ADR-0017).
    #[must_use]
    pub fn with_processes(
        agents: Vec<EngineAgent>,
        events: mpsc::Receiver<(usize, ProcessEvent)>,
        event_tx: mpsc::Sender<(usize, ProcessEvent)>,
    ) -> Self {
        let engine = Engine {
            agents: agents.into_iter().map(SupervisedAgent::live).collect(),
            events,
            event_tx,
            pending_self_config: None,
            pending_connection_offer: None,
            pending_package_downloads: Vec::new(),
            self_update: SelfUpdate::default(),
            sampling: Arc::new(Mutex::new(Vec::new())),
            last_csr: None,
            high_water: None,
        };
        // The Client's own Agent samples this process, and that is true from the start — only a
        // Managed Process's pid has to wait for the process to exist.
        engine.refresh_sampling();
        engine
    }

    /// Arms self-update (ADR-0018) with what installs a new version and commits this one if it is
    /// itself freshly installed.
    /// Gives the Engine the high-water marks its Supervisors share (ADR-0043 clause 8).
    pub fn set_high_water(&mut self, marks: Arc<dyn HighWaterMarks>) {
        self.high_water = Some(marks);
    }

    /// The high-water marks a Supervisor started at runtime is held to — `None` only for an
    /// Engine not built by [`build_engine`](crate::supervisor::build_engine).
    pub fn high_water(&self) -> Option<Arc<dyn HighWaterMarks>> {
        self.high_water.clone()
    }

    pub fn arm_self_update(&mut self, updater: impl SelfUpdater + 'static) {
        self.self_update.arm(updater);
    }

    /// Reports a self-update that finished in a previous process (ADR-0018): the install
    /// necessarily completes across a restart, so the terminal status is owed by whichever
    /// version came up — the new one saying `Installed`, or the old one saying why it is back.
    /// `result` is the version now running, or why the install failed.
    pub fn report_self_update_outcome(&mut self, hash: Vec<u8>, result: Result<String, String>) {
        let Some(agent) = self.agents.get_mut(SELF_AGENT_INDEX) else {
            return;
        };
        agent.package_applied(hash, result);
    }

    /// Restores previously applied connection settings on every Agent (ADR-0014), so a restarted
    /// Client reports `APPLIED` and is not re-offered what it already runs.
    pub fn adopt_connection_settings(&mut self, hash: &[u8]) {
        for agent in &mut self.agents {
            agent.state.adopt_connection_settings(hash);
        }
    }

    /// Declares one more capability on every Agent — e.g. `ReportsHeartbeat` once an offered
    /// interval enables what the configuration had disabled.
    pub fn declare_capability_all(&mut self, capability: opamp::proto::AgentCapabilities) {
        for agent in &mut self.agents {
            agent.state.declare_capability(capability);
        }
    }

    /// What own metrics are sampled from (ADR-0016): every Agent, named as the protocol keys it, as
    /// the operator calls it and as its type is reported, paired with the pid to sample for it — this process for the
    /// Client's own Agent, the Managed Process for a Supervisor-backed one, and nothing while that
    /// process is not running.
    pub fn sampling_targets(&self) -> Vec<SamplingTarget> {
        self.agents
            .iter()
            .filter_map(|agent| {
                let pid = agent.state.process_pid()?;
                Some(SamplingTarget {
                    uid: agent.state.uid().to_string(),
                    instance_name: agent.state.instance_name().to_string(),
                    service_name: agent.state.service_name().to_string(),
                    pid,
                })
            })
            .collect()
    }

    /// A handle on [`sampling_targets`](Self::sampling_targets) the metrics sampler can read while
    /// the transport holds the Engine mutably — which it does for the whole of a connection.
    /// Refreshed whenever a pid changes, so a Managed Process that restarts is followed.
    pub fn sampling_handle(&self) -> Arc<Mutex<Vec<SamplingTarget>>> {
        self.sampling.clone()
    }

    fn refresh_sampling(&self) {
        if let Ok(mut shared) = self.sampling.lock() {
            *shared = self.sampling_targets();
        }
    }

    /// The Client's own Agent's description, for the Resource its telemetry carries (ADR-0016).
    pub fn self_description(&self) -> opamp::proto::AgentDescription {
        self.agents
            .iter()
            .find(|agent| !agent.state.is_managed())
            .map(|agent| agent.state.description())
            .unwrap_or_default()
    }

    /// Asks the Server for a client certificate when it signs them and this Client needs one
    /// (ADR-0021). Driven by capability rather than configuration: a Server that declares nothing
    /// is never asked, and one that does hands this host an identity before mutual TLS is switched
    /// on, which is what makes switching it on uneventful.
    ///
    /// The request rides the Client's **own** Agent. The identity belongs to the connection, not to
    /// any one Agent (n Agents share it, ADR-0015), and the self-Agent is the one every Client has.
    ///
    /// `csr` makes the request — called only when one is to be sent, since it generates a key.
    ///
    /// A request this Engine has not queued before is owed at once, so it never waits for a
    /// heartbeat, of which there may be none. One re-sent while it waits for an operator rides the
    /// next report instead: queued after every reply and owed each time, it would answer every
    /// answer.
    pub fn request_certificate(&mut self, csr: impl FnOnce() -> Option<Vec<u8>>) {
        let Some(agent) = self
            .agents
            .iter_mut()
            .find(|agent| agent.state.server_signs_certificates() && !agent.state.is_managed())
        else {
            return;
        };
        if let Some(csr) = csr() {
            if self.last_csr.as_ref() != Some(&csr) {
                agent.owes_report = true;
                self.last_csr = Some(csr.clone());
            }
            agent.state.request_certificate(csr);
        }
    }

    /// The enrolment report (ADR-0039 clause 11): `csr` alone, on the Client's own Agent — the one
    /// the identity of the connection belongs to, as [`request_certificate`] rides it. `None`
    /// without such an Agent.
    ///
    /// [`request_certificate`]: Self::request_certificate
    pub fn enrolment_report(&mut self, csr: Vec<u8>) -> Option<AgentToServer> {
        let agent = self
            .agents
            .iter_mut()
            .find(|agent| !agent.retired && !agent.state.is_managed())?;
        self.last_csr = Some(csr.clone());
        Some(agent.state.csr_report(csr))
    }

    /// The connection-settings offer the transport must verify by actually connecting, taken
    /// exactly once (ADR-0014).
    pub fn take_connection_offer(&mut self) -> Option<ConnectionSettingsOffers> {
        self.pending_connection_offer.take()
    }

    /// The packages the transport must download and verify (ADR-0026), each with its Agent's
    /// index — drained so each is dispatched once.
    pub fn take_package_downloads(&mut self) -> Vec<(usize, PackageDownload)> {
        std::mem::take(&mut self.pending_package_downloads)
    }

    /// Records download progress for the Agent whose package is being fetched (ADR-0026), so the
    /// next report carries `Downloading` with its details instead of a silent `Installing`.
    pub fn package_downloading(
        &mut self,
        index: usize,
        details: opamp::proto::PackageDownloadDetails,
    ) {
        if let Some(agent) = self.agents.get_mut(index) {
            agent.state.package_downloading(details);
            agent.owes_report = true;
        }
    }

    /// Hands a downloaded, verified artifact to the owning Agent's Supervisor to apply (ADR-0026),
    /// or — for the Client's own Agent — installs it as a new version of the Client (ADR-0018).
    /// The Supervisor's `PackageApplied` event closes the lifecycle. A missing adapter, or one not
    /// accepting commands, fails the install (reported, not silent).
    ///
    pub fn apply_package(
        &mut self,
        index: usize,
        staged: std::path::PathBuf,
        version: String,
        hash: Vec<u8>,
        span: &tracing::Span,
    ) {
        if index == SELF_AGENT_INDEX {
            // Entered rather than passed on: the self-update runs here, in this task, so the
            // staging and the probe it does become children of the install by being inside it
            // (ADR-0016). Nothing is awaited under this guard.
            let _install = span.enter();
            self.apply_self_update(&staged, version, hash);
            return;
        }
        let Some(agent) = self.agents.get_mut(index) else {
            return;
        };
        // The bytes are in: the status moves from Downloading to Installing.
        agent.state.package_downloaded();
        let error = match &agent.commands {
            Some(commands) => match commands.try_send(ProcessCommand::ApplyPackage {
                staged,
                version,
                hash: hash.clone(),
                span: span.clone(),
            }) {
                Ok(()) => return,
                Err(e) => {
                    warn!(error = %e, "cannot hand the package to the supervisor");
                    "the supervisor is not accepting commands"
                }
            },
            None => "this agent has no process to install a package into",
        };
        crate::span::failed(span, error);
        agent.package_applied(hash, Err(error.to_string()));
    }

    /// Whether a self-update has moved the `current` pointer and the run must therefore end, so
    /// the service manager restarts into the new version (ADR-0018).
    #[must_use]
    pub fn restart_for_update(&self) -> bool {
        self.self_update.restart_requested()
    }

    /// Installs a verified artifact as a new version of *this Client* (ADR-0018).
    ///
    /// Unlike a Supervisor's install, the outcome cannot be reported from here on success: this
    /// process is about to stop being the one that runs. Only the failure is terminal now — and it
    /// is terminal with the previous version still current and still running.
    fn apply_self_update(&mut self, staged: &std::path::Path, version: String, hash: Vec<u8>) {
        let Some(agent) = self.agents.get_mut(SELF_AGENT_INDEX) else {
            return;
        };
        agent.state.package_downloaded();
        match self.self_update.install(staged, &version, &hash) {
            // `Installing` is already the reported status and the caller flushes it before the run
            // ends. What comes after the restart reports the outcome.
            Ok(SelfInstall::Staged) => {}
            // The version offered is the one running — which is what a freshly updated Client is
            // told every time, since the Server keeps offering until an Agent reports a terminal
            // status for that package. Saying `Installed` is both true and what closes the loop.
            Ok(SelfInstall::AlreadyRunning) => {
                self.agents[SELF_AGENT_INDEX].package_applied(hash, Ok(version));
            }
            Err(e) => {
                warn!(error = %e, "the Client's self-update failed; staying on this version");
                self.agents[SELF_AGENT_INDEX].package_applied(hash, Err(e));
            }
        }
    }

    /// A package download or verification failed (ADR-0026): the owning Agent reports
    /// `InstallFailed` — a rejected package is a report, not a silence.
    pub fn package_download_failed(&mut self, index: usize, hash: Vec<u8>, error: String) {
        if let Some(agent) = self.agents.get_mut(index) {
            agent.package_applied(hash, Err(error));
        }
    }

    /// Closes a verified offer's lifecycle on every Agent: `APPLIED` (the transport switches
    /// next) or `FAILED` with the error; either way every Agent owes the Server the outcome.
    pub fn connection_settings_outcome(&mut self, hash: &[u8], result: Result<(), &str>) {
        for agent in &mut self.agents {
            agent.state.connection_settings_outcome(hash, result);
            agent.owes_report = true;
        }
    }

    /// One Agent's next report, for the plain-HTTP verification probe (ADR-0014): a real
    /// exchange needs a real report. Delivered on success; a failed probe leaves a sequence gap
    /// the Baseline's `ReportFullState` recovery heals on the next exchange.
    pub fn probe_report(&mut self) -> Option<AgentToServer> {
        self.agents
            .first_mut()
            .map(|agent| agent.state.next_report())
    }

    /// The identities carried, for logging.
    pub fn uids(&self) -> impl Iterator<Item = InstanceUid> + '_ {
        self.agents.iter().map(|a| a.state.uid())
    }

    /// Whether any Agent this Engine runs takes Server-offered packages — a self-update or a managed
    /// process's package. What the startup check uses to decide whether an unconfigured verification
    /// key is worth warning about (ADR-0026).
    pub fn installs_packages(&self) -> bool {
        self.agents.iter().any(|a| a.state.accepts_packages())
    }

    /// Every Agent starts over with a full snapshot — after (re)connecting, or when an exchange
    /// was lost and the Server may be missing state. A certificate request may have been lost
    /// with it, so the next one is new to the Server again and goes out at once.
    pub fn force_full_all(&mut self) {
        for agent in &mut self.agents {
            agent.state.force_full();
        }
        self.last_csr = None;
    }

    /// One report per Agent — the routine poll, and the after-connect snapshot when
    /// [`force_full_all`](Self::force_full_all) was called first.
    pub fn poll_reports(&mut self) -> Vec<AgentToServer> {
        self.agents
            .iter_mut()
            .filter(|agent| !agent.retired)
            .map(|agent| {
                agent.owes_report = false;
                agent.state.next_report()
            })
            .collect()
    }

    /// Reports from exactly the Agents that owe one — after a handled reply asked for an
    /// immediate report. Empty when nothing changed.
    pub fn owed_reports(&mut self) -> Vec<AgentToServer> {
        self.agents
            .iter_mut()
            .filter(|agent| agent.owes_report && !agent.retired)
            .map(|agent| {
                agent.owes_report = false;
                agent.state.next_report()
            })
            .collect()
    }

    /// Routes one `ServerToAgent` to the Agent its `instance_uid` names. A reply for an unknown
    /// Agent is dropped with a warning — the protocol's multiplexing provision makes the uid the
    /// sole routing key, so there is nothing else to fall back to.
    pub fn handle(&mut self, reply: &ServerToAgent) -> Handled {
        let Some(uid) = InstanceUid::from_wire(&reply.instance_uid) else {
            warn!("dropping a reply without a valid instance_uid");
            return Handled::default();
        };
        // n is the number of local Supervisors — small; a linear scan beats a map to maintain.
        // A retired Agent (ADR-0017) said goodbye; a straggling reply for it is dropped like one
        // for an Agent that never existed.
        let Some(index) = self
            .agents
            .iter()
            .position(|a| !a.retired && a.state.uid() == uid)
        else {
            warn!(agent = %uid, "dropping a reply for an unknown agent");
            return Handled::default();
        };
        // The Server answered, so this version connected and is being spoken to — which is what a
        // freshly installed one has to manage to stop being on probation (ADR-0018).
        self.self_update.server_answered();
        let agent = &mut self.agents[index];
        let mut handled = agent.state.handle(reply);
        if handled.send_report {
            agent.owes_report = true;
        }
        // The connection-scoped part of the reply moves to the Engine's single pending slot;
        // whichever Agent's reply carried it last wins — they are all the same offer.
        if let Some(offer) = handled.connection_offer.take() {
            self.pending_connection_offer = Some(offer);
        }
        // A package offer is per Agent (each Supervisor has its own binary): queue it with the
        // owning Agent's index so the transport can route the verified artifact back.
        if let Some(download) = handled.package_download.take() {
            self.pending_package_downloads.push((index, download));
        }
        // A stored configuration awaiting application goes to the process adapter; its
        // ConfigApplied event closes the APPLYING → APPLIED/FAILED lifecycle. The self-Agent's
        // goes to the Engine's pending slot instead (assigned after `agent`'s borrow ends): its
        // configuration is the Supervisor set, which the transport applies through
        // [`crate::reconfigure`] (ADR-0017).
        let mut self_config = None;
        if let Some(config) = agent.state.take_pending_apply() {
            if index == SELF_AGENT_INDEX && !agent.state.is_managed() {
                self_config = Some(config);
            } else {
                match &agent.commands {
                    Some(commands) => {
                        // The apply's trace (ADR-0016). It opens where the configuration is handed
                        // over and closes in the adapter, once the Managed Process is back up: the
                        // hand-over is the start of the operation, not the whole of it, and the
                        // phases worth timing — the stop, the restart, the health gate — all happen
                        // on the other side of this channel.
                        let span = tracing::info_span!(
                            "config.apply",
                            agent = %uid,
                            hash = %hex::encode(&config.config_hash),
                            otel.status_code = tracing::field::Empty,
                            otel.status_description = tracing::field::Empty,
                        );
                        let hash = config.config_hash.clone();
                        if let Err(e) = commands.try_send(ProcessCommand::ApplyConfig {
                            config,
                            span: span.clone(),
                        }) {
                            let error = "the supervisor is not accepting commands";
                            warn!(agent = %uid, error = %e, "cannot hand the configuration to the supervisor");
                            crate::span::failed(&span, error);
                            agent.state.config_applied(hash, Err(error.to_string()));
                            agent.owes_report = true;
                        }
                    }
                    None => {
                        warn!(agent = %uid, "a configuration is pending but no process adapter exists")
                    }
                }
            }
        }
        // A Server-commanded restart goes the same way; its outcome is the health cycle the
        // stop/spawn emits, so a dropped command only needs the warning.
        if agent.state.take_pending_restart() {
            match &agent.commands {
                Some(commands) => {
                    if let Err(e) = commands.try_send(ProcessCommand::Restart) {
                        warn!(agent = %uid, error = %e, "cannot hand the restart to the supervisor");
                    }
                }
                None => warn!(agent = %uid, "a restart is pending but no process adapter exists"),
            }
        }
        if let Some(config) = self_config {
            self.pending_self_config = Some(config);
        }
        handled
    }

    /// The self-Agent's received configuration, taken exactly once for the Supervisor-set apply
    /// (ADR-0017).
    pub fn take_self_config(&mut self) -> Option<AgentRemoteConfig> {
        self.pending_self_config.take()
    }

    /// Closes the self-Agent's `APPLYING` → `APPLIED`/`FAILED` lifecycle (ADR-0017): the verdict
    /// of the Supervisor-set apply, where a Managed Process's `ConfigApplied` event would stand.
    pub fn self_config_applied(&mut self, hash: Vec<u8>, result: Result<(), String>) {
        let Some(agent) = self.agents.get_mut(SELF_AGENT_INDEX) else {
            return;
        };
        agent.state.config_applied(hash, result);
        agent.owes_report = true;
    }

    /// Refreshes what the self-Agent reports as its effective configuration — the (redacted)
    /// text of `supervisor.toml`, which an applied Supervisor set just rewrote (ADR-0017).
    pub fn set_self_effective_config(&mut self, source: String) {
        let Some(agent) = self.agents.get_mut(SELF_AGENT_INDEX) else {
            return;
        };
        agent
            .state
            .set_process_effective_config(opamp::proto::EffectiveConfig {
                config_map: Some(opamp::proto::AgentConfigMap {
                    config_map: std::collections::HashMap::from([(
                        "supervisor.toml".to_string(),
                        opamp::proto::AgentConfigObject {
                            role: String::new(),
                            body: source.into_bytes(),
                            content_type: String::new(),
                        },
                    )]),
                }),
            });
        agent.owes_report = true;
    }

    /// The `[[supervisor]]` block name behind the Agent at `index` — `None` for the self-Agent.
    /// What package staging is keyed by (ADR-0017): an Engine index stops naming a block
    /// position once the Agent set has changed at runtime.
    pub fn block_name(&self, index: usize) -> Option<&str> {
        self.agents.get(index)?.block_name.as_deref()
    }

    /// The index the next added Agent will occupy — what its adapter's [`EventSender`] and its
    /// package routing are keyed by.
    #[must_use]
    pub fn next_index(&self) -> usize {
        self.agents.len()
    }

    /// The sending side of the shared event channel, for starting a Supervisor at runtime
    /// (ADR-0017) — its Endpoint and adapter each get a tagged sender into it.
    #[must_use]
    pub fn events_handle(&self) -> mpsc::Sender<(usize, ProcessEvent)> {
        self.event_tx.clone()
    }

    /// Adds a freshly started Supervisor's Agent (ADR-0017). It introduces itself with a full
    /// snapshot on the next flush — a fresh state's first report is a full one.
    pub fn add_supervisor(&mut self, agent: EngineAgent) {
        let mut agent = SupervisedAgent::live(agent);
        agent.owes_report = true;
        self.agents.push(agent);
        self.refresh_sampling();
    }

    /// Retires the Agents whose `[[supervisor]]` blocks left the set (ADR-0017): each one's
    /// adapter stops the Managed Process within the stop budget, its Endpoint releases the port,
    /// the adapter's exit is awaited, and the goodbyes to send are returned. The slots stay (see
    /// [`SupervisedAgent::retired`]); unnamed Agents run on untouched.
    ///
    /// A name in `uninstalling` is leaving the set *for good* (ADR-0017): its adapter is told to
    /// uninstall — stop, undo what installing it did, answer — before the caller purges its
    /// directory (ADR-0017). A name only in `names` merely changed: it is stopped, restarts
    /// under its name, and keeps what it installed. The adapter's own stop budget bounds either
    /// path; an uninstall that cannot be delivered falls back to the plain stop.
    pub async fn retire_supervisors(
        &mut self,
        names: &[String],
        uninstalling: &[String],
    ) -> Vec<AgentToServer> {
        let mut goodbyes = Vec::new();
        for index in 0..self.agents.len() {
            let agent = &mut self.agents[index];
            if agent.retired
                || !agent
                    .block_name
                    .as_ref()
                    .is_some_and(|name| names.contains(name))
            {
                continue;
            }
            let uninstall = agent
                .block_name
                .as_ref()
                .is_some_and(|name| uninstalling.contains(name));
            let commands = agent.commands.take();
            let told_to_uninstall = uninstall
                && commands
                    .as_ref()
                    .is_some_and(|commands| commands.try_send(ProcessCommand::Uninstall).is_ok());
            // A plainly stopped adapter exits on its fired shutdown; one told to uninstall
            // exits on the command itself, and its Endpoint's stop follows below.
            if !told_to_uninstall {
                if let Some(stop) = agent.stop.take() {
                    let _ = stop.send(true);
                }
            }
            if let Some(commands) = commands {
                // The channel closing is how the adapter's exit — and, for an uninstall, its
                // answered outcome — is observed.
                self.drain_events_until_closed(&commands).await;
            }
            let agent = &mut self.agents[index];
            if let Some(stop) = agent.stop.take() {
                let _ = stop.send(true);
            }
            agent.retired = true;
            goodbyes.push(agent.state.disconnect_message());
        }
        self.refresh_sampling();
        goodbyes
    }

    /// The connection's final messages: one `agent_disconnect` per Agent, as the Baseline
    /// requires of the last message each Agent sends. A retired Agent already said its own.
    pub fn disconnect_messages(&mut self) -> Vec<AgentToServer> {
        self.agents
            .iter_mut()
            .filter(|agent| !agent.retired)
            .map(|agent| agent.state.disconnect_message())
            .collect()
    }

    /// Resolves when a Managed Process changed some Agent's state, so the transport can push a
    /// report without waiting for a poll. With no adapters (the self-Agent) it never resolves.
    pub async fn changed(&mut self) {
        match self.events.recv().await {
            Some((index, event)) => self.absorb(index, event),
            // Every sender is gone — nothing will ever change again; don't spin.
            None => std::future::pending().await,
        }
    }

    /// Folds one process event into the owning Agent and marks it as owing a report.
    fn absorb(&mut self, index: usize, event: ProcessEvent) {
        // Set when the event moved a pid: the shared sampling view is refreshed after the
        // borrow of `agent` ends, since refreshing reads every Agent.
        let mut refresh = false;
        let Some(agent) = self.agents.get_mut(index) else {
            warn!(index, "dropping an event for an unknown agent");
            return;
        };
        // A retired Agent's adapter may still flush its last events (its process going down);
        // they are nobody's news — the goodbye already went out (ADR-0017).
        if agent.retired {
            return;
        }
        match event {
            ProcessEvent::Description(description) => {
                agent.state.set_process_description(description);
            }
            ProcessEvent::Pid(pid) => {
                agent.state.set_process_pid(pid);
                refresh = true;
            }
            ProcessEvent::Health(health) => agent.state.set_process_health(health),
            ProcessEvent::EffectiveConfig(config) => {
                agent.state.set_process_effective_config(config);
            }
            ProcessEvent::AvailableComponents(components) => {
                agent.state.set_available_components(components);
            }
            ProcessEvent::ConfigApplied { hash, result } => {
                agent.state.config_applied(hash, result);
            }
            ProcessEvent::PackageApplied { hash, result } => {
                agent.state.package_applied(hash, result);
            }
            // The adapter's last word before retirement (ADR-0017). The goodbye carries no
            // status, so the outcome is the operator's to read here — an `Err` names what the
            // kind could not undo, which nothing else will ever mention again.
            ProcessEvent::Uninstalled { result } => {
                let name = agent.block_name.as_deref().unwrap_or("?");
                match result {
                    Ok(()) => info!(supervisor = %name, "supervisor uninstalled"),
                    Err(e) => warn!(
                        supervisor = %name,
                        error = %e,
                        "the retired supervisor could not undo its installation"
                    ),
                }
            }
        }
        agent.owes_report = true;
        if refresh {
            self.refresh_sampling();
        }
    }

    /// Stops all Managed Processes — each adapter honours `Shutdown` within its stop budget —
    /// before the goodbyes go out.
    pub async fn shutdown_processes(&mut self) {
        let mut stopping = Vec::new();
        for agent in &mut self.agents {
            // The Supervisor's own shutdown fires alongside the command, so its Endpoint task
            // winds down with its adapter rather than with this process (ADR-0017).
            if let Some(stop) = agent.stop.take() {
                let _ = stop.send(true);
            }
            if let Some(commands) = agent.commands.take() {
                let _ = commands.send(ProcessCommand::Shutdown).await;
                stopping.push(commands);
            }
        }
        // Each adapter drops its command receiver once its process is down; awaiting that — while
        // draining events, which a stopping adapter may still be flushing — is what puts the
        // goodbyes after the processes, not beside them. (The Engine itself holds an event sender
        // for runtime-started Supervisors, so "the channel closed" cannot stand in for "every
        // adapter exited".)
        for commands in stopping {
            self.drain_events_until_closed(&commands).await;
        }
    }

    /// Absorbs process events until `commands`' receiving side — the adapter task — is gone.
    async fn drain_events_until_closed(&mut self, commands: &mpsc::Sender<ProcessCommand>) {
        let closed = commands.closed();
        tokio::pin!(closed);
        loop {
            tokio::select! {
                () = &mut closed => return,
                event = self.events.recv() => match event {
                    Some((index, event)) => self.absorb(index, event),
                    None => return,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use opamp::proto::ServerToAgentFlags;

    fn engine_of_two(dir: &std::path::Path) -> Engine {
        let agents = ["left", "right"]
            .into_iter()
            .map(|name| {
                let storage = Storage::new(dir.join(name)).expect("storage");
                AgentState::new(name.to_string(), storage, crate::host::SystemHost).expect("agent")
            })
            .collect();
        Engine::new(agents)
    }

    #[test]
    fn poll_reports_carries_every_agent_with_distinct_identities() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut engine = engine_of_two(dir.path());
        let reports = engine.poll_reports();
        assert_eq!(reports.len(), 2);
        assert_ne!(reports[0].instance_uid, reports[1].instance_uid);
        // Sequence numbers are per Agent, not shared.
        let again = engine.poll_reports();
        assert!(again.iter().all(|r| r.sequence_num == 2));
    }

    #[test]
    fn a_reply_reaches_only_the_agent_its_uid_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut engine = engine_of_two(dir.path());
        let reports = engine.poll_reports();

        let handled = engine.handle(&ServerToAgent {
            instance_uid: reports[0].instance_uid.clone(),
            flags: ServerToAgentFlags::ReportFullState as u64,
            ..Default::default()
        });
        assert!(handled.send_report);

        // Only the addressed agent owes a report, and it is a full one.
        let owed = engine.owed_reports();
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].instance_uid, reports[0].instance_uid);
        assert!(owed[0].agent_description.is_some());
        assert!(engine.owed_reports().is_empty());
    }

    /// A new certificate request is owed at once, so it never waits for a heartbeat; the same one
    /// re-sent while it waits for an operator rides the next report, so it never answers every
    /// answer (ADR-0021 clause 21).
    /// Verifies: ADR-0021
    #[test]
    fn a_new_certificate_request_is_owed_at_once_and_a_repeated_one_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut engine = engine_of_two(dir.path());
        let reports = engine.poll_reports();
        let _ = engine.handle(&ServerToAgent {
            instance_uid: reports[0].instance_uid.clone(),
            capabilities: opamp::proto::ServerCapabilities::AcceptsConnectionSettingsRequest as u64,
            ..Default::default()
        });
        let _ = engine.owed_reports();
        let carries_request = |report: &AgentToServer| report.connection_settings_request.is_some();

        engine.request_certificate(|| Some(b"first".to_vec()));
        let owed = engine.owed_reports();
        assert_eq!(owed.len(), 1);
        assert!(carries_request(&owed[0]), "the new request is sent at once");

        engine.request_certificate(|| Some(b"first".to_vec()));
        assert!(engine.owed_reports().is_empty(), "the same request is not");
        assert!(
            engine.poll_reports().iter().any(carries_request),
            "it rides the next report"
        );

        engine.request_certificate(|| Some(b"second".to_vec()));
        assert!(
            engine.owed_reports().iter().any(carries_request),
            "a request for a new key is"
        );

        // A reconnect or a lost exchange may have taken the last one with it.
        engine.force_full_all();
        engine.request_certificate(|| Some(b"second".to_vec()));
        assert!(
            engine.owed_reports().iter().any(carries_request),
            "the same request is sent at once on a new connection"
        );
    }

    #[test]
    fn replies_for_unknown_or_malformed_uids_are_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut engine = engine_of_two(dir.path());
        let _ = engine.poll_reports();

        let unknown = engine.handle(&ServerToAgent {
            instance_uid: InstanceUid::default().as_bytes().to_vec(),
            flags: ServerToAgentFlags::ReportFullState as u64,
            ..Default::default()
        });
        assert!(!unknown.send_report);
        let malformed = engine.handle(&ServerToAgent {
            instance_uid: vec![1, 2, 3],
            ..Default::default()
        });
        assert!(!malformed.send_report);
        assert!(engine.owed_reports().is_empty());
    }

    #[test]
    fn disconnects_cover_every_agent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut engine = engine_of_two(dir.path());
        let goodbyes = engine.disconnect_messages();
        assert_eq!(goodbyes.len(), 2);
        assert!(goodbyes.iter().all(|g| g.agent_disconnect.is_some()));
    }

    /// ADR-0017 at the Engine seam: a name in `uninstalling` is told to uninstall — its adapter
    /// answers and exits on the command itself — while a name that merely changed is only
    /// stopped, so it keeps what it installed for its restart. Both end retired with a goodbye.
    #[tokio::test]
    async fn retiring_uninstalls_the_removed_and_only_stops_the_changed() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("tempdir");
        let (event_tx, events) = mpsc::channel(8);
        let mut agents = Vec::new();
        let mut saw_uninstall = Vec::new();
        for (index, name) in ["removed", "changed"].into_iter().enumerate() {
            let storage = Storage::new(dir.path().join(name)).expect("storage");
            let state =
                AgentState::new(name.to_string(), storage, crate::host::SystemHost).expect("agent");
            let (commands_tx, mut commands_rx) = mpsc::channel::<ProcessCommand>(4);
            let (stop_tx, mut stop) = crate::shutdown::shutdown_channel();
            let saw = Arc::new(AtomicBool::new(false));
            let events = crate::supervisor::ports::EventSender::new(index, event_tx.clone());
            let flag = saw.clone();
            // A stand-in adapter with the Runner's two exits: the command itself, answered,
            // or the fired shutdown. Dropping the receiver is how either exit is observed.
            tokio::spawn(async move {
                tokio::select! {
                    command = commands_rx.recv() => {
                        if let Some(ProcessCommand::Uninstall) = command {
                            flag.store(true, Ordering::SeqCst);
                            events.send(ProcessEvent::Uninstalled { result: Ok(()) }).await;
                        }
                    }
                    _ = stop.requested() => {}
                }
            });
            saw_uninstall.push(saw);
            agents.push(EngineAgent {
                state,
                commands: Some(commands_tx),
                stop: Some(stop_tx),
                block_name: Some(name.to_string()),
            });
        }
        let mut engine = Engine::with_processes(agents, events, event_tx);

        let goodbyes = engine
            .retire_supervisors(
                &["removed".to_string(), "changed".to_string()],
                &["removed".to_string()],
            )
            .await;

        assert_eq!(goodbyes.len(), 2, "both said their goodbye");
        assert!(
            saw_uninstall[0].load(Ordering::SeqCst),
            "the removed adapter was told to uninstall"
        );
        assert!(
            !saw_uninstall[1].load(Ordering::SeqCst),
            "the changed adapter was only stopped"
        );
    }

    #[test]
    fn a_rekeyed_agent_stays_routable_under_its_new_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut engine = engine_of_two(dir.path());
        let reports = engine.poll_reports();
        let new_uid = InstanceUid::default();

        engine.handle(&ServerToAgent {
            instance_uid: reports[0].instance_uid.clone(),
            agent_identification: Some(opamp::proto::AgentIdentification {
                new_instance_uid: new_uid.as_bytes().to_vec(),
            }),
            ..Default::default()
        });

        let handled = engine.handle(&ServerToAgent {
            instance_uid: new_uid.as_bytes().to_vec(),
            flags: ServerToAgentFlags::ReportFullState as u64,
            ..Default::default()
        });
        assert!(handled.send_report);
    }
}
