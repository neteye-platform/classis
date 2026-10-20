//! One Agent's state machine: builds `AgentToServer` reports and reacts to `ServerToAgent`
//! replies.
//!
//! Transport-agnostic on purpose (ADR-0013): the WebSocket and plain-HTTP loops feed the same
//! state machine, so transport is carriage, never semantics. The [`Engine`](crate::engine)
//! carries n of these over one connection (ADR-0015, ADR-0017) — a Supervisor-backed Agent and
//! the self-Agent fallback are the same state machine.

mod connection_settings;
mod description;
mod packages;
mod remote_config;

use std::time::Duration;

use opamp::attributes;
use opamp::proto::{
    AgentCapabilities, AgentDescription, AgentRemoteConfig, AgentToServer, AvailableComponents,
    ComponentHealth, ConnectionSettingsOffers, ConnectionSettingsStatuses, EffectiveConfig,
    PackageDownloadDetails, PackageStatuses, RemoteConfigStatuses, ServerCapabilities,
    ServerToAgent,
};
use opamp::uid::InstanceUid;
use tracing::{info, warn};

use crate::supervisor::ports::{AgentStorage, HighWaterMarks, HostFacts, InstalledPackage};

use connection_settings::{carries_settings, settings_status};
use opamp::client::protocol::{AgentProtocol, ReportContent};
pub use packages::PackageDownload;
use remote_config::config_status;

/// The base Capability Set every Agent of this Client declares (see docs/CONFORMANCE.md).
/// Individual Agents declare more via [`AgentState::declare_capability`] — e.g. heartbeats when
/// enabled, restartability only where a Managed Process exists.
pub const AGENT_CAPABILITIES: u64 = AgentCapabilities::ReportsStatus as u64
    | AgentCapabilities::AcceptsRemoteConfig as u64
    | AgentCapabilities::ReportsEffectiveConfig as u64
    | AgentCapabilities::ReportsRemoteConfig as u64
    | AgentCapabilities::ReportsHealth as u64
    | AgentCapabilities::AcceptsOpAmpConnectionSettings as u64
    | AgentCapabilities::ReportsConnectionSettingsStatus as u64
    // The Agent's own telemetry (ADR-0016). Declared unconditionally, unlike the capabilities that
    // describe something this end *has*: these say the Client can report to a destination the
    // Server names, which is true before any destination exists — and declaring them only once one
    // is in force would mean the Server could never make the first offer.
    | AgentCapabilities::ReportsOwnMetrics as u64
    | AgentCapabilities::ReportsOwnTraces as u64
    | AgentCapabilities::ReportsOwnLogs as u64;

/// What a Supervisor's Agent declares when the operator switched its remote configuration off
/// (ADR-0017 clause 50): the base set without either remote-configuration bit.
pub const AGENT_CAPABILITIES_WITHOUT_REMOTE_CONFIG: u64 = AGENT_CAPABILITIES
    & !(AgentCapabilities::AcceptsRemoteConfig as u64
        | AgentCapabilities::ReportsRemoteConfig as u64);

/// What a handled `ServerToAgent` asks of the transport loop.
#[derive(Debug, Default, PartialEq)]
pub struct Handled {
    /// Something changed that the Server must hear about now (a config outcome, a demanded full
    /// report) — send the next report immediately instead of waiting for the poll interval.
    pub send_report: bool,
    /// The Server is throttling us (`UNAVAILABLE` + retry info): back off this long first.
    pub retry_after: Option<Duration>,
    /// A connection-settings offer to verify by actually connecting (ADR-0014). The state
    /// machine has already acknowledged `APPLYING`; the transport owns the verification, the
    /// switch, and reporting the outcome back through the [`Engine`](crate::engine).
    pub connection_offer: Option<ConnectionSettingsOffers>,
    /// A package to download, verify, and hand to the Supervisor (ADR-0026). The state machine
    /// has acknowledged `Installing`; the transport owns the download and verification.
    pub package_download: Option<PackageDownload>,
}

/// The Agent type the Client's own Agent presents as `service.name` (ADR-0016, ADR-0019): the role
/// it plays on the host, the Agent that supervises the others. A constant, not the configured
/// instance name — every Client in a fleet is the same kind of thing, and that is what a type says.
///
/// It is also the shipped program's name and its configuration file's (ADR-0019) — see
/// [`layout::COMPONENT`](crate::service::layout::COMPONENT), which holds the same string as a
/// **separate** constant. It is *not* the service's name: ADR-0019 clause 3 gives the service the
/// product's name, and clause 9 keeps this one off
/// [`PRODUCT_NAME`](crate::product::PRODUCT_NAME) deliberately — the archive member a self-update
/// extracts is the same in every variant build, which is what lets one published package Set
/// serve them all. Derive this from the product and the fleet carries N products where it has one.
///
/// The package that carries this Client is named after the type, and the self-update takes no other
/// name (ADR-0018).
pub const CLIENT_AGENT_TYPE: &str = "supervisor";

pub struct AgentState {
    /// What OpAMP defines about this Agent: identity, sequence numbers, the two Capability Sets,
    /// what the next report owes, and the status messages (ADR-0010).
    protocol: AgentProtocol,
    /// What this Client reports about it.
    local: Local,
    storage: Box<dyn AgentStorage>,
    /// A received configuration awaiting dispatch to the process adapter.
    pending_apply: Option<AgentRemoteConfig>,
    /// The self-Agent's configuration in flight (ADR-0017): stored only once the apply succeeded,
    /// so a Client restarted mid-apply reports nothing as applied and is re-offered — a status of
    /// `APPLIED` on restart must mean the file was actually rewritten.
    applying: Option<AgentRemoteConfig>,
    /// A Server-commanded restart awaiting dispatch to the process adapter.
    pending_restart: bool,
    /// The SHA-256 of each remote configuration hash ignored since start, when the operator
    /// switched remote configuration off for this Agent (ADR-0017); `None` when it takes
    /// them. A digest and not the hash itself, and at most [`IGNORED_CONFIGS_CAP`] of them,
    /// because the hash is whatever the Server sends.
    ignored_configs: Option<std::collections::HashSet<[u8; 32]>>,
}

/// How many ignored remote configuration hashes a Supervisor with remote configuration switched
/// off remembers before it starts over (ADR-0017 clause 51).
const IGNORED_CONFIGS_CAP: usize = 1024;

/// A Server-sent hash as a log field: hex, cut after its first 32 bytes, since its length is the
/// Server's to choose.
fn logged_hash(hash: &[u8]) -> String {
    const SHOWN: usize = 32;
    if hash.len() > SHOWN {
        format!("{}…", hex::encode(&hash[..SHOWN]))
    } else {
        hex::encode(hash)
    }
}

/// What this Client reports about one Agent, and the package bookkeeping behind its status — the
/// content the protocol asks for (ADR-0010).
struct Local {
    /// What the host says about itself (ADR-0016).
    host: Box<dyn HostFacts>,
    /// The operator's name for this Agent, reported as `service.instance.name` (ADR-0016): the
    /// `[[supervisor]]` block's `name`, or the top-level one for the Client's own Agent. Never
    /// `service.name` — that is the type below.
    instance_name: String,
    /// The Agent *type*, reported as `service.name`. A Managed Process that reports one of its own
    /// replaces it in the fold; this is what stands until then, and permanently for a process that
    /// reports nothing.
    service_name: String,
    start_time_ns: u64,
    /// The last stored remote configuration; what `effective_config` echoes unless the Managed
    /// Process reported its own.
    applied: Option<AgentRemoteConfig>,
    /// A Managed Process stands behind this Agent: a received configuration is acknowledged
    /// `APPLYING` and handed to the process adapter; `APPLIED`/`FAILED` follow its outcome.
    managed: bool,
    /// The Managed Process's health — derived or self-reported (ADR-0017). Absent for the
    /// self-Agent, whose health is being alive.
    process_health: Option<ComponentHealth>,
    /// The Managed Process's self-reported description, folded into ours (goal 16).
    process_description: Option<AgentDescription>,
    /// The Managed Process's self-reported effective configuration; replaces the echo.
    process_effective_config: Option<EffectiveConfig>,
    /// The Managed Process's available components, relayed from the Supervisor Endpoint.
    /// Routine reports carry only the hash; the full map goes out when the Server asks.
    available_components: Option<AvailableComponents>,
    /// The pid of the Managed Process while it runs (ADR-0016) — what own metrics are sampled
    /// from. `None` for the Client's own Agent, whose process is this one, and for a Supervisor
    /// between restarts.
    process_pid: Option<u32>,
    /// Whether this Agent's Managed Process is updated from Server-offered packages (ADR-0026).
    /// Which package that is, is the Server's choice — this side only consents.
    accepts_packages: bool,
    /// The only package name this Agent will install (ADR-0018); `None` takes whichever top-level
    /// package the Server offers, which is what a Supervisor does.
    expected_package: Option<String>,
    /// The name of the top-level package the Server last offered. Learned from the offer, not
    /// configured: it keys the reported `PackageStatuses` map, which the Baseline requires to name
    /// every package the Agent has or is processing.
    offered_name: Option<String>,
    /// The package currently installed, persisted across restarts.
    installed_package: Option<InstalledPackage>,
    /// Progress of the artifact download in flight (ADR-0026), reported as `Downloading` with
    /// `PackageDownloadDetails`; `None` once the bytes are on disk. `[Development]` upstream.
    downloading: Option<PackageDownloadDetails>,
    /// The package hash currently downloading/installing, so a repeated offer of the same hash is
    /// not re-entered while it is in flight.
    installing: Option<PackageDownload>,
    /// The `all_packages_hash` last offered, echoed as `server_provided_all_packages_hash` once
    /// the Agent's package reaches a terminal state — which is what stops the Server re-offering.
    offered_all_packages_hash: Vec<u8>,
    /// What the Agent reports as `server_provided_all_packages_hash`: the offered aggregate once
    /// terminal, empty (or the previous value) while an install is in flight.
    echoed_all_packages_hash: Vec<u8>,
    /// The version and hash the Server last offered for this Agent's package — reported as
    /// `server_offered_version`/`server_offered_hash` (the Baseline requires them while
    /// installing or after a failure).
    server_offered: Option<(String, Vec<u8>)>,
    /// The last install failure for this Agent's package, reported alongside the status.
    package_error: String,
    /// A failure in processing the *offer itself* rather than one package — the Baseline's
    /// `PackageStatuses.error_message`, "set if the Agent encountered an error when processing the
    /// PackagesAvailable message and that error is not related to any particular single package".
    offer_error: String,
    /// Operator-defined attributes from `supervisor.toml` (ADR-0023), reported as non-identifying
    /// attributes so Selectors can target them. Reported attributes win on key collision.
    configured_attributes: Vec<(String, String)>,
    /// The deployment's `service.namespace`, when it has one. The Baseline asks for it "if it is
    /// used in the environment where the Agent runs" — which only an operator knows, so it is
    /// configured rather than detected, and absent until it is set.
    namespace: Option<String>,
    /// Handling an offer changed the package status; the protocol is told once it is done.
    package_status_owed: bool,
    /// The high-water marks every Supervisor of this Client shares (ADR-0043 clause 8): an offer
    /// below its Agent type's mark is refused, and an `Installed` raises it. `None` for the
    /// Client's own Agent, which keeps no mark (clause 13).
    high_water: Option<std::sync::Arc<dyn HighWaterMarks>>,
}

impl AgentState {
    /// Restores identity and configuration from storage, so a restart reports the same Agent with
    /// the same applied config hash — and is therefore not reconfigured redundantly.
    ///
    /// `instance_name` is the operator's name for this Agent; the type it presents is
    /// [`CLIENT_AGENT_TYPE`], since this constructor builds the Client's own Agent. A
    /// Supervisor-backed one comes from [`supervised`](Self::supervised), which is told its type.
    pub fn new(
        instance_name: String,
        storage: impl AgentStorage + 'static,
        host: impl HostFacts + 'static,
    ) -> std::io::Result<Self> {
        Self::restore(instance_name, storage, host, true)
    }

    /// The Client's own Agent on a host that keeps its Supervisor set from the Server (ADR-0017):
    /// it declares neither `AcceptsRemoteConfig` nor `ReportsRemoteConfig`, restores no stored
    /// set, and ignores a set that arrives anyway. Every other capability is the one
    /// [`new`](Self::new) declares.
    pub fn new_without_remote_config(
        instance_name: String,
        storage: impl AgentStorage + 'static,
        host: impl HostFacts + 'static,
    ) -> std::io::Result<Self> {
        Self::restore(instance_name, storage, host, false)
    }

    /// [`new`](Self::new), with `remote_config` saying whether this Agent takes remote
    /// configuration at all (ADR-0017): without it the Agent declares neither remote-configuration
    /// capability, restores no stored configuration, and ignores every offer.
    fn restore(
        instance_name: String,
        storage: impl AgentStorage + 'static,
        host: impl HostFacts + 'static,
        remote_config: bool,
    ) -> std::io::Result<Self> {
        let uid = storage.load_or_create_uid()?;
        let (capabilities, applied) = if remote_config {
            (AGENT_CAPABILITIES, storage.load_remote_config())
        } else {
            (AGENT_CAPABILITIES_WITHOUT_REMOTE_CONFIG, None)
        };
        let mut protocol = AgentProtocol::new(uid, capabilities);
        if let Some(config) = &applied {
            protocol.restore_remote_config_status(config_status(
                config.config_hash.clone(),
                RemoteConfigStatuses::Applied,
                String::new(),
            ));
        }
        info!(agent = %uid, "agent identity ready");
        Ok(AgentState {
            protocol,
            local: Local {
                start_time_ns: host.now_ns(),
                host: Box::new(host),
                instance_name,
                service_name: CLIENT_AGENT_TYPE.to_string(),
                applied,
                managed: false,
                process_health: None,
                process_description: None,
                process_effective_config: None,
                available_components: None,
                process_pid: None,
                accepts_packages: false,
                expected_package: None,
                offered_name: None,
                installed_package: None,
                downloading: None,
                installing: None,
                offered_all_packages_hash: Vec::new(),
                echoed_all_packages_hash: Vec::new(),
                server_offered: None,
                package_error: String::new(),
                offer_error: String::new(),
                configured_attributes: Vec::new(),
                namespace: None,
                package_status_owed: false,
                high_water: None,
            },
            storage: Box::new(storage),
            pending_apply: None,
            applying: None,
            pending_restart: false,
            ignored_configs: (!remote_config).then(Default::default),
        })
    }

    /// An Agent with a Managed Process behind it (a Supervisor-backed Agent, ADR-0017). Only
    /// such an Agent accepts a restart command — the self-Agent has no process to restart.
    ///
    /// The type is a parameter rather than a builder default because there is no sensible default
    /// for it (ADR-0016): the Client's own type would be a lie, and the instance name in that slot
    /// is exactly the confusion this signature exists to prevent. The caller always knows one —
    /// the block's `service_name`, or the program's file name.
    pub fn supervised(
        instance_name: String,
        service_name: String,
        storage: impl AgentStorage + 'static,
        host: impl HostFacts + 'static,
    ) -> std::io::Result<Self> {
        Self::supervised_with(instance_name, service_name, storage, host, true)
    }

    /// A Supervisor-backed Agent whose remote configuration the operator switched off
    /// (ADR-0017): it declares neither `AcceptsRemoteConfig` nor `ReportsRemoteConfig`, restores
    /// no stored configuration, and ignores an offer that arrives anyway. Built without the bits
    /// rather than stripped of them afterwards, because a declared capability only ever grows.
    pub fn supervised_without_remote_config(
        instance_name: String,
        service_name: String,
        storage: impl AgentStorage + 'static,
        host: impl HostFacts + 'static,
    ) -> std::io::Result<Self> {
        Self::supervised_with(instance_name, service_name, storage, host, false)
    }

    fn supervised_with(
        instance_name: String,
        service_name: String,
        storage: impl AgentStorage + 'static,
        host: impl HostFacts + 'static,
        remote_config: bool,
    ) -> std::io::Result<Self> {
        let mut state = Self::restore(instance_name, storage, host, remote_config)?;
        state.local.service_name = service_name;
        state.local.managed = true;
        state.declare_capability(AgentCapabilities::AcceptsRestartCommand);
        Ok(state)
    }

    /// A restart the Server commanded and the process adapter has not been handed yet.
    pub fn take_pending_restart(&mut self) -> bool {
        std::mem::take(&mut self.pending_restart)
    }

    /// Adds one capability to this Agent's declared set — heartbeats when enabled, and bits an
    /// Agent only earns situationally (a Managed Process to restart, components to report).
    pub fn declare_capability(&mut self, capability: AgentCapabilities) {
        self.protocol.declare(capability);
    }

    pub fn uid(&self) -> InstanceUid {
        self.protocol.uid()
    }

    /// The operator's name for this Agent (ADR-0016). The Supervisor's own value, never the
    /// Managed Process's: a process reporting under that key is ignored in `describe`, so this is
    /// the one answer to "which Agent is this" that a human can read.
    pub fn instance_name(&self) -> &str {
        &self.local.instance_name
    }

    /// The Agent *type* this Agent is reported under — `service.name` (ADR-0016).
    ///
    /// The Managed Process's own word where it gives one, the Supervisor's configured type
    /// otherwise — the fold `describe` performs, mirrored here rather than repeated: what the
    /// fleet view shows for an Agent and what its telemetry is labelled with must be the one
    /// answer, and `describe` is too expensive to call per sample, since it reads the host's
    /// addresses live.
    ///
    /// The two answers differ in exactly one case, deliberately. A process reporting
    /// `service.name = ""` blanks the type in `describe`, because the fold replaces by key without
    /// judging the value; here the empty string is not a value (ADR-0026), so the configured type
    /// stands. A label nobody can read is worse than a stale one, and the Selector consequences of
    /// the other reading are ADR-0026's own subject rather than this accessor's.
    pub fn service_name(&self) -> &str {
        self.local
            .process_description
            .as_ref()
            .and_then(|reported| {
                // Whichever list the process put it in, as the fold reads it (ADR-0041).
                opamp::attributes::string_value(
                    &reported.identifying_attributes,
                    attributes::SERVICE_NAME,
                )
                .or_else(|| {
                    opamp::attributes::string_value(
                        &reported.non_identifying_attributes,
                        attributes::SERVICE_NAME,
                    )
                })
            })
            .unwrap_or(&self.local.service_name)
    }

    /// The Managed Process's health changed — derived or self-reported.
    pub fn set_process_health(&mut self, health: ComponentHealth) {
        self.local.process_health = Some(health);
        self.protocol.health_changed();
    }

    /// The Managed Process reported its own effective configuration; report that instead of
    /// echoing the written files.
    pub fn set_process_effective_config(&mut self, config: EffectiveConfig) {
        self.local.process_effective_config = Some(config);
        self.protocol.effective_config_changed();
    }

    /// The Managed Process reported its available components. Only now does the Agent declare
    /// `ReportsAvailableComponents` — a capability without components would be a false promise —
    /// and the next full report carries the hash (the Server flags for the full map on demand).
    pub fn set_available_components(&mut self, components: AvailableComponents) {
        self.local.available_components = Some(components);
        self.declare_capability(AgentCapabilities::ReportsAvailableComponents);
        self.protocol.force_full();
    }

    /// The next report starts from a full status snapshot again — after (re)connecting, after an
    /// exchange failed, or when the Server demanded it.
    pub fn force_full(&mut self) {
        self.protocol.force_full();
    }

    /// The next `AgentToServer`: which fields it carries is the protocol's to decide, what they
    /// hold is this Agent's (ADR-0010).
    pub fn next_report(&mut self) -> AgentToServer {
        self.protocol.next_report(&self.local)
    }

    /// A report carrying `csr` alone, as an enrolling host sends it (ADR-0039 clause 11).
    pub fn csr_report(&mut self, csr: Vec<u8>) -> AgentToServer {
        self.protocol.csr_report(csr)
    }

    /// The final message of a connection: the Baseline requires `agent_disconnect` in it.
    pub fn disconnect_message(&mut self) -> AgentToServer {
        self.protocol.disconnect_message()
    }

    /// Reacts to one `ServerToAgent`: the protocol settles its part, and what is left — a
    /// command, a configuration, an offer — is this Agent's to decide.
    pub fn handle(&mut self, reply: &ServerToAgent) -> Handled {
        let received = self.protocol.receive(reply);
        let mut handled = Handled {
            send_report: received.report_now,
            retry_after: received.retry_after,
            ..Handled::default()
        };

        if let Some(command) = received.command {
            if command == opamp::proto::CommandType::Restart as i32 && self.local.managed {
                info!("the server commanded a restart");
                self.pending_restart = true;
            } else {
                // Restart is the only command the Baseline defines; and the self-Agent never
                // declares AcceptsRestartCommand, so a command toward it is a Server error.
                warn!(r#type = command, "ignoring an unsupported command");
            }
            return handled;
        }

        if let Some(new_uid) = received.new_uid {
            if let Err(e) = self.storage.save_uid(&new_uid) {
                warn!(error = %e, "cannot persist the new identity");
            }
        }

        if received.components_requested && self.local.available_components.is_some() {
            self.protocol.send_components_full();
            handled.send_report = true;
        }

        if let Some(remote_config) = received.remote_config {
            if let Some(ignored) = &mut self.ignored_configs {
                // Not declared, so not acted on and not reported (ADR-0017 clauses 51
                // and 3); said once per hash, so a Server resending its offer on every exchange
                // does not flood the log.
                use sha2::Digest as _;
                let seen: [u8; 32] = sha2::Sha256::digest(&remote_config.config_hash).into();
                if ignored.len() >= IGNORED_CONFIGS_CAP && !ignored.contains(&seen) {
                    // A Server that sends ever new hashes is answered with an occasional repeat
                    // warning, not with memory that grows without end.
                    ignored.clear();
                }
                if ignored.insert(seen) {
                    if self.local.managed {
                        warn!(
                            supervisor = %self.local.instance_name,
                            hash = %logged_hash(&remote_config.config_hash),
                            "ignoring a remote configuration: remote configuration is switched \
                             off for this supervisor in [supervisors] remote_config_disabled"
                        );
                    } else {
                        // The Client's own Agent, offered a Supervisor set (ADR-0017 clause 43).
                        warn!(
                            hash = %logged_hash(&remote_config.config_hash),
                            "ignoring a supervisor set: this Client keeps its supervisor set \
                             ([supervisors] server_manages_set = false in supervisor.toml)"
                        );
                    }
                }
            } else {
                self.apply(remote_config);
                handled.send_report = true;
            }
        }

        // A connection-settings offer (ADR-0014): acknowledge APPLYING and hand it to the
        // transport, which alone can verify by actually connecting — the Baseline's MUST. Only
        // an offer this Agent already runs (APPLIED, same hash) is not re-entered; a re-offer
        // after FAILED or a lost in-flight verification retries.
        if let Some(offers) = received.connection_settings {
            let applied = self.protocol.connection_settings_status().is_some_and(|s| {
                s.last_connection_settings_hash == offers.hash
                    && s.status == ConnectionSettingsStatuses::Applied as i32
            });
            if carries_settings(offers) && !applied {
                info!(hash = %hex::encode(&offers.hash), "connection settings offered; applying");
                self.protocol.set_connection_settings_status(
                    settings_status(
                        offers.hash.clone(),
                        ConnectionSettingsStatuses::Applying,
                        String::new(),
                    ),
                    true,
                );
                handled.send_report = true;
                handled.connection_offer = Some(offers.clone());
            }
        }

        // A package offer (ADR-0026): act only on this Agent's package. Download and verification
        // are the transport's; the state machine acknowledges Installing and hands over the
        // coordinates.
        if let Some(available) = received.packages_available {
            self.local.handle_package_offer(available, &mut handled);
            if std::mem::take(&mut self.local.package_status_owed) {
                self.protocol.package_status_changed();
            }
        }

        handled
    }

    /// Whether a Managed Process stands behind this Agent — false for the Client's own Agent,
    /// which is the one that carries what belongs to the connection rather than to a process.
    pub fn is_managed(&self) -> bool {
        self.local.managed
    }

    /// This Agent's description, for the Resource of its own telemetry (ADR-0016).
    pub fn description(&self) -> AgentDescription {
        self.describe()
    }

    fn describe(&self) -> AgentDescription {
        self.local.describe(&self.protocol.uid())
    }

    /// The Managed Process's pid changed — it started, or it is gone (ADR-0016).
    pub fn set_process_pid(&mut self, pid: Option<u32>) {
        self.local.process_pid = pid;
    }

    /// The pid own metrics are sampled from: this process for the Client's own Agent, the Managed
    /// Process for a Supervisor-backed one — and nothing while that process is not running.
    pub fn process_pid(&self) -> Option<u32> {
        match self.local.managed {
            false => Some(self.local.host.process_id()),
            true => self.local.process_pid,
        }
    }

    /// Queues a certificate signing request for the next report (ADR-0021).
    pub fn request_certificate(&mut self, csr: Vec<u8>) {
        self.protocol.request_certificate(csr);
    }

    /// Whether this Server signs certificates at all. Starts pessimistic: sending a CSR to a
    /// Server that never declared the capability would be answered with the Baseline's
    /// `BadRequest`, and the protocol's negotiation rule says not to exercise what the peer has not
    /// declared.
    pub fn server_signs_certificates(&self) -> bool {
        self.protocol
            .server_declared(ServerCapabilities::AcceptsConnectionSettingsRequest)
    }
}

impl ReportContent for Local {
    fn description(&self, uid: &InstanceUid) -> AgentDescription {
        self.describe(uid)
    }

    fn health(&self) -> ComponentHealth {
        self.health()
    }

    fn effective_config(&self) -> EffectiveConfig {
        match &self.process_effective_config {
            Some(reported) => reported.clone(),
            None => EffectiveConfig {
                config_map: self.applied.as_ref().and_then(|c| c.config.clone()),
            },
        }
    }

    fn package_statuses(&self) -> Option<PackageStatuses> {
        self.accepts_packages.then(|| self.package_statuses())
    }

    fn available_components(&self) -> Option<&AvailableComponents> {
        self.available_components.as_ref()
    }
}

impl Local {
    fn health(&self) -> ComponentHealth {
        match &self.process_health {
            Some(health) => health.clone(),
            None if self.managed => ComponentHealth {
                healthy: false,
                status: "starting".to_string(),
                status_time_unix_nano: self.host.now_ns(),
                ..Default::default()
            },
            // The self-Agent's health is being alive.
            None => ComponentHealth {
                healthy: true,
                start_time_unix_nano: self.start_time_ns,
                status: "running".to_string(),
                status_time_unix_nano: self.host.now_ns(),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::description::os_type;
    use super::*;
    use crate::storage::Storage;
    use opamp::attributes::string_attr;
    use opamp::proto::{AgentConfigMap, AgentConfigObject, KeyValue, PackageType};
    use opamp::proto::{ServerErrorResponseType, ServerToAgentFlags};
    use std::collections::HashMap;

    /// ADR-0014 clause 4: an offer that names a telemetry destination is actionable, whether or not
    /// it carries OpAMP settings — and one that carries nothing this Client applies is not.
    /// Verifies: ADR-0014
    #[test]
    fn an_offer_carries_settings_when_it_names_anything_this_client_applies() {
        assert!(carries_settings(&ConnectionSettingsOffers {
            own_metrics: Some(opamp::proto::TelemetryConnectionSettings::default()),
            ..Default::default()
        }));
        assert!(carries_settings(&ConnectionSettingsOffers {
            opamp: Some(opamp::proto::OpAmpConnectionSettings::default()),
            ..Default::default()
        }));
        assert!(!carries_settings(&ConnectionSettingsOffers::default()));
    }

    /// `/proc/cpuinfo` always names an x86 model, so on this platform the attribute must be
    /// there — everywhere else it stays best effort.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn the_cpu_model_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let attrs = reported(&make_agent(dir.path()).describe());
        assert!(
            attrs
                .get("host.cpu.model.name")
                .is_some_and(|model| !model.is_empty()),
            "no host.cpu.model.name in {attrs:?}"
        );
    }

    fn make_agent(dir: &std::path::Path) -> AgentState {
        let storage = Storage::new(dir.to_path_buf()).expect("storage");
        AgentState::new("test-agent".to_string(), storage, crate::host::SystemHost).expect("agent")
    }

    fn remote_config(body: &[u8], hash: &[u8]) -> AgentRemoteConfig {
        AgentRemoteConfig {
            config: Some(AgentConfigMap {
                config_map: HashMap::from([(
                    String::new(),
                    AgentConfigObject {
                        role: String::new(),
                        body: body.to_vec(),
                        content_type: String::new(),
                    },
                )]),
            }),
            config_hash: hash.to_vec(),
        }
    }

    /// Verifies: ADR-0041
    #[test]
    fn configured_attributes_are_reported_but_never_shadow_reported_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let agent = AgentState::new("test-agent".to_string(), storage, crate::host::SystemHost)
            .expect("agent")
            .with_attributes(
                [
                    ("env".to_string(), "prod".to_string()),
                    // Collides with what the code reports — the reported value must win.
                    ("os.type".to_string(), "configured".to_string()),
                ]
                .into(),
            );

        let description = agent.describe();
        let value = |key: &str| {
            description
                .non_identifying_attributes
                .iter()
                .find(|kv| kv.key == key)
                .and_then(|kv| kv.value.as_ref())
                .and_then(|v| v.value.as_ref())
                .map(|v| match v {
                    opamp::proto::any_value::Value::StringValue(s) => s.clone(),
                    other => format!("{other:?}"),
                })
        };
        assert_eq!(value("env").as_deref(), Some("prod"));
        assert_eq!(value("os.type").as_deref(), Some(os_type()));
        assert_eq!(
            description
                .non_identifying_attributes
                .iter()
                .filter(|kv| kv.key == "os.type")
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_description_names_the_distribution_not_only_the_kernel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let description = make_agent(dir.path()).describe();
        let os = description
            .non_identifying_attributes
            .iter()
            .find(|kv| kv.key == "os.description")
            .expect("an os.description on a distribution with /etc/os-release");
        let text = match &os.value.as_ref().and_then(|v| v.value.as_ref()) {
            Some(opamp::proto::any_value::Value::StringValue(s)) => s.clone(),
            other => panic!("os.description must be a string, got {other:?}"),
        };
        assert!(!text.is_empty());
        assert_ne!(text, "linux", "the PRETTY_NAME, not the os.type");
    }

    /// Every reported attribute as `key -> value`, both lists together: what the Server actually
    /// receives, and therefore what a Selector matches against. A string array (`host.ip`,
    /// `host.mac`, ADR-0016) reads joined, as the Server's view joins it.
    fn reported(description: &AgentDescription) -> std::collections::BTreeMap<String, String> {
        description
            .identifying_attributes
            .iter()
            .chain(&description.non_identifying_attributes)
            .map(|kv| {
                let value = match kv.value.as_ref().and_then(|v| v.value.as_ref()) {
                    Some(opamp::proto::any_value::Value::StringValue(s)) => s.clone(),
                    Some(opamp::proto::any_value::Value::ArrayValue(list)) => list
                        .values
                        .iter()
                        .filter_map(|v| match v.value.as_ref() {
                            Some(opamp::proto::any_value::Value::StringValue(s)) => {
                                Some(s.as_str())
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    other => panic!("{} must be a string or string array, got {other:?}", kv.key),
                };
                (kv.key.clone(), value)
            })
            .collect()
    }

    /// Best effort means **absent**, never blank. An attribute reported as an empty string is one
    /// a Selector can be written against and match, so a platform that cannot answer — this
    /// container has no `/etc/machine-id`, so it cannot answer `host.id` — must leave the key off
    /// entirely rather than report nothing under it.
    #[test]
    fn nothing_the_platform_cannot_answer_is_reported_as_an_empty_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (key, value) in reported(&make_agent(dir.path()).describe()) {
            assert!(!value.is_empty(), "{key} is reported as an empty value");
        }
    }

    /// The defect ADR-0016 exists for: a Collector's `opampextension` reports the type it was built
    /// with, and folding that into the operator's name for the Supervisor would overwrite it — so
    /// every Collector of one distribution would collapse onto one name in the fleet view. Both
    /// values must survive, each in its own key, each won by the side that actually knows it.
    /// Verifies: ADR-0041
    // Verifies: ADR-0016
    #[test]
    fn a_process_reporting_its_type_does_not_take_the_operators_name_with_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol-edge-01".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");

        let before = reported(&agent.describe());
        assert_eq!(
            before.get("service.name").map(String::as_str),
            Some("otelcol")
        );
        assert_eq!(
            before.get("service.instance.name").map(String::as_str),
            Some("otelcol-edge-01")
        );

        // The extension connects and states its `dist.name` — and, being a Collector, knows
        // nothing about the Supervisor that owns it, so its guess at an instance name is worthless.
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.name", "otelcol-contrib")],
            non_identifying_attributes: vec![string_attr(
                "service.instance.name",
                "some-collector",
            )],
        });

        let after = reported(&agent.describe());
        assert_eq!(
            after.get("service.name").map(String::as_str),
            Some("otelcol-contrib"),
            "the process states the better type and wins the type"
        );
        assert_eq!(
            after.get("service.instance.name").map(String::as_str),
            Some("otelcol-edge-01"),
            "but it cannot rename the Supervisor the operator configured"
        );
    }

    /// And the exemption holds by *key*, not by the list the Supervisor states each one in. A
    /// process reporting either of them among its *identifying* attributes would otherwise win
    /// every Selector — the Server resolves those before the non-identifying ones — while the fleet
    /// row, which reads the other list, went on showing the operator's value.
    /// Verifies: ADR-0041
    #[test]
    fn the_supervisors_own_attributes_survive_whichever_list_a_process_reports_them_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol-edge-01".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        let uid = reported(&agent.describe())
            .get("service.instance.id")
            .cloned()
            .expect("the Supervisor's uid");

        // Both keys, each in the list the fold does *not* exempt it in.
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.instance.name", "some-collector")],
            non_identifying_attributes: vec![string_attr("service.instance.id", "not-the-uid")],
        });

        let description = agent.describe();
        assert!(
            !description
                .identifying_attributes
                .iter()
                .any(|kv| kv.key == "service.instance.name"),
            "an instance name among the identifying attributes would win every Selector"
        );
        let after = reported(&description);
        assert_eq!(
            after.get("service.instance.name").map(String::as_str),
            Some("otelcol-edge-01"),
            "the operator's name stands, wherever the process put its own"
        );
        assert_eq!(
            after.get("service.instance.id"),
            Some(&uid),
            "and identity stays the Supervisor's uid"
        );
    }

    /// The Client's own Agent is one *kind* of thing across the whole fleet, so its type is the
    /// constant `supervisor` (ADR-0019) and not whatever the operator called this instance — which
    /// is what lets one Selector on the type aim at every Client in the fleet at once (ADR-0016).
    /// Verifies: ADR-0019
    #[test]
    fn the_clients_own_agent_reports_its_type_and_its_configured_name_separately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let agent = AgentState::new("edge-fra1".to_string(), storage, crate::host::SystemHost)
            .expect("agent");
        let attributes = reported(&agent.describe());
        assert_eq!(
            attributes.get("service.name").map(String::as_str),
            Some(CLIENT_AGENT_TYPE)
        );
        assert_eq!(
            attributes.get("service.instance.name").map(String::as_str),
            Some("edge-fra1")
        );
    }

    /// ADR-0019 pins the value, not just the separation: the type is `supervisor`. ADR-0019 also
    /// gives the program, its service and its configuration file the same word, so the Agent's
    /// *role* is the one name this thing has anywhere — which is the point, and
    /// which is why the two constants are asserted to agree rather than to differ.
    /// Verifies: ADR-0019
    #[test]
    fn the_clients_own_agent_type_is_the_one_name_this_program_has() {
        assert_eq!(CLIENT_AGENT_TYPE, "supervisor");
        assert_eq!(
            CLIENT_AGENT_TYPE,
            crate::service::layout::COMPONENT,
            "the type, the program and the service are one word (ADR-0019)"
        );
    }

    /// `[supervisor.attributes]` is a fallback for keys nothing else reports, so it must not be a
    /// second way to set the two attributes the Supervisor itself owns.
    /// Verifies: ADR-0041
    // Verifies: ADR-0016
    #[test]
    fn configured_attributes_cannot_restate_the_type_or_the_instance_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let agent = AgentState::supervised(
            "edge-01".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent")
        .with_attributes(
            [
                ("service.name".to_string(), "hijacked".to_string()),
                ("service.instance.name".to_string(), "hijacked".to_string()),
            ]
            .into(),
        );
        let attributes = reported(&agent.describe());
        assert_eq!(
            attributes.get("service.name").map(String::as_str),
            Some("otelcol")
        );
        assert_eq!(
            attributes.get("service.instance.name").map(String::as_str),
            Some("edge-01")
        );
    }

    /// ADR-0026 twice offers "a Selector matching that host's `host.name`" as the way to pin one
    /// host to one artifact. That only works if an Agent reports the attribute, which for a long
    /// time it did not.
    #[cfg(unix)]
    #[test]
    fn the_agent_reports_the_host_name_a_selector_would_pin_it_by() {
        let dir = tempfile::tempdir().expect("tempdir");
        let attributes = reported(&make_agent(dir.path()).describe());
        assert!(
            attributes.contains_key("host.name"),
            "no host.name among {attributes:?}"
        );
    }

    /// The Baseline names `os.version` beside `os.type`. `os.description` does not stand in for it:
    /// it is prose, and nothing can compare prose. Asserted against the file the values are read
    /// from, so this states a fact about the mapping rather than about the machine it runs on.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_os_is_reported_as_a_name_and_a_version_not_only_as_prose() {
        let Ok(release) = std::fs::read_to_string("/etc/os-release") else {
            return;
        };
        let field = |key: &str| {
            release
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .map(|value| value.trim().trim_matches(['"', '\'']).to_string())
                .filter(|value| !value.is_empty())
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let attributes = reported(&make_agent(dir.path()).describe());
        assert_eq!(attributes.get("os.name").cloned(), field("NAME"));
        // `VERSION_ID` is optional in os-release(5) — a rolling distribution carries none — so
        // what is asserted is that the two agree, present or absent.
        assert_eq!(attributes.get("os.version").cloned(), field("VERSION_ID"));
        assert_ne!(
            attributes.get("os.name").map(String::as_str),
            Some(os_type()),
            "the distribution's NAME, not the os.type"
        );
    }

    /// `service.namespace` is the Baseline's one conditional attribute — "if it is used in the
    /// environment where the Agent runs" — so it is silent until an operator configures it, and
    /// then it *identifies* the Agent rather than tagging it.
    #[test]
    fn the_service_namespace_is_absent_until_configured_and_then_identifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let named = |description: &AgentDescription| {
            let in_identifying = description
                .identifying_attributes
                .iter()
                .any(|kv| kv.key == "service.namespace");
            let in_non_identifying = description
                .non_identifying_attributes
                .iter()
                .any(|kv| kv.key == "service.namespace");
            (in_identifying, in_non_identifying)
        };

        let plain = make_agent(&dir.path().join("plain")).describe();
        assert_eq!(named(&plain), (false, false));

        let storage = Storage::new(dir.path().join("configured")).expect("storage");
        let configured =
            AgentState::new("test-agent".to_string(), storage, crate::host::SystemHost)
                .expect("agent")
                .with_namespace(Some("telemetry".to_string()))
                .describe();
        assert_eq!(
            named(&configured),
            (true, false),
            "it belongs among what identifies the Agent, and only there"
        );
        assert_eq!(
            reported(&configured).get("service.namespace").cloned(),
            Some("telemetry".to_string())
        );
    }

    #[test]
    fn only_the_self_agent_carries_the_client_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let version_of = |agent: &AgentState| {
            agent
                .describe()
                .identifying_attributes
                .iter()
                .find(|kv| kv.key == "service.version")
                .and_then(|kv| kv.value.clone())
                .and_then(|v| v.value)
                .map(|v| match v {
                    opamp::proto::any_value::Value::StringValue(s) => s,
                    other => format!("{other:?}"),
                })
        };

        // The self-Agent *is* the Client — its baked version is the Agent's version.
        let this = make_agent(&dir.path().join("self"));
        assert_eq!(
            version_of(&this).as_deref(),
            Some(fleet_core::version::current())
        );

        // A Supervisor-backed Agent reports no version until its Managed Process states one.
        let storage = Storage::new(dir.path().join("supervised")).expect("storage");
        let mut supervised = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        assert_eq!(version_of(&supervised), None);

        supervised.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.version", "0.142.0")],
            non_identifying_attributes: vec![],
        });
        assert_eq!(version_of(&supervised).as_deref(), Some("0.142.0"));
    }

    /// The type the metrics are labelled with is the type the fleet view shows — the process's own
    /// word where it gives one, the configured type otherwise. Two answers to "what is this Agent"
    /// would be worse than none: a series labelled `otelcol` beside a fleet row reading
    /// `otelcol-contrib` is a question, not a fact.
    /// Verifies: ADR-0041
    #[test]
    fn the_reported_type_is_the_processs_own_word_where_it_gives_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("supervised")).expect("storage");
        let mut agent = AgentState::supervised(
            "edge-01".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        assert_eq!(agent.service_name(), "otelcol");

        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.name", "otelcol-contrib")],
            non_identifying_attributes: vec![],
        });
        assert_eq!(agent.service_name(), "otelcol-contrib");
        assert_eq!(
            reported(&agent.describe()).get("service.name").cloned(),
            Some("otelcol-contrib".to_string()),
            "the accessor mirrors the fold rather than diverging from it"
        );

        // The one case where the two part company, asserted so that it is a decision rather than a
        // surprise: an empty string is not a value here (ADR-0026), while the fold replaces by key
        // without judging the value.
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.name", "")],
            non_identifying_attributes: vec![],
        });
        assert_eq!(agent.service_name(), "otelcol");
        assert_eq!(
            reported(&agent.describe()).get("service.name").cloned(),
            Some(String::new())
        );
    }

    /// Two sources describe the same Managed Process — the version probe, which reports
    /// `service.version` alone after every package swap, and the opampextension, which reports
    /// everything else. Replacing rather than merging would make each new probe erase the
    /// extension's self-report, and each self-report erase the probed version.
    #[test]
    fn what_the_process_reports_about_itself_accumulates_across_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("supervised")).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");

        // The extension's self-report: everything but the version, which it happens not to state.
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.name", "otelcol-contrib")],
            non_identifying_attributes: vec![string_attr("service.team", "abc")],
        });
        // The probe, after a swap: the version and nothing else.
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.version", "0.158.0")],
            non_identifying_attributes: vec![],
        });

        let described = agent.describe();
        let value = |attrs: &[KeyValue], key: &str| {
            attrs
                .iter()
                .find(|kv| kv.key == key)
                .and_then(|kv| kv.value.clone())
                .and_then(|v| v.value)
                .map(|v| match v {
                    opamp::proto::any_value::Value::StringValue(s) => s,
                    other => format!("{other:?}"),
                })
        };
        assert_eq!(
            value(&described.identifying_attributes, "service.version").as_deref(),
            Some("0.158.0"),
            "the probed version survives"
        );
        assert_eq!(
            value(&described.identifying_attributes, "service.name").as_deref(),
            Some("otelcol-contrib"),
            "and does not erase what the extension reported"
        );
        assert_eq!(
            value(&described.non_identifying_attributes, "service.team").as_deref(),
            Some("abc")
        );

        // A later self-report of the same key wins — a restarted process states the truth.
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![string_attr("service.version", "0.159.0")],
            non_identifying_attributes: vec![],
        });
        assert_eq!(
            value(&agent.describe().identifying_attributes, "service.version").as_deref(),
            Some("0.159.0")
        );
    }

    fn supervised_agent(dir: &std::path::Path) -> AgentState {
        let storage = Storage::new(dir.to_path_buf()).expect("storage");
        AgentState::supervised(
            "edge-01".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent")
    }

    /// A Managed Process is code the Supervisor does not vouch for, so where the Agent runs and
    /// what kind of Agent it is stay the Supervisor's statement, whichever list the process puts
    /// its claim in: another host would draw that host's Configurations, another platform another
    /// machine's artifact, and a `supervisor.kind.*` key would make a second Client Agent. Only
    /// its `service.*` attributes are laid over the Supervisor's.
    /// Verifies: ADR-0041
    #[test]
    fn a_process_states_its_own_service_attributes_and_nothing_about_the_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = supervised_agent(dir.path());
        let before = reported(&agent.describe());

        let claims = [
            "host.name",
            "host.id",
            "os.type",
            "host.arch",
            "os.description",
            "supervisor.kind.collector",
            "collector.pipeline",
        ];
        let claimed = |list: &str| {
            claims
                .iter()
                .map(|key| string_attr(key, &format!("{list}-claim")))
                .collect::<Vec<_>>()
        };
        let mut identifying = claimed("identifying");
        identifying.push(string_attr("service.name", "otelcol-contrib"));
        identifying.push(string_attr("service.version", "0.142.0"));
        agent.set_process_description(AgentDescription {
            identifying_attributes: identifying,
            non_identifying_attributes: claimed("non-identifying"),
        });

        let described = agent.describe();
        let after = reported(&described);
        for key in claims {
            assert_eq!(
                after.get(key),
                before.get(key),
                "{key} is the Supervisor's to state, or nobody's"
            );
        }
        // Each list on its own as well: Selectors read the identifying list first, so a claim left
        // there would win although the merged view above shows the Supervisor's value.
        for (name, list) in [
            ("identifying", &described.identifying_attributes),
            ("non-identifying", &described.non_identifying_attributes),
        ] {
            let claimed: Vec<&str> = list
                .iter()
                .filter(|kv| {
                    matches!(
                        kv.value.as_ref().and_then(|v| v.value.as_ref()),
                        Some(opamp::proto::any_value::Value::StringValue(s)) if s.ends_with("-claim")
                    )
                })
                .map(|kv| kv.key.as_str())
                .collect();
            assert!(
                claimed.is_empty(),
                "the {name} list carries the process's {claimed:?}"
            );
        }
        assert!(
            after.keys().all(|key| !key.starts_with("supervisor.kind.")),
            "a process made its Agent a Client Agent: {after:?}"
        );
        assert_eq!(
            after.get("service.name").map(String::as_str),
            Some("otelcol-contrib")
        );
        assert_eq!(
            after.get("service.version").map(String::as_str),
            Some("0.142.0")
        );
    }

    /// The operator's values stand against the process, inside `service.*` as outside it: an
    /// `[attributes]` entry the code does not report is the operator's word, and so is
    /// `service.namespace` once `service_namespace` is set. Unset, the namespace is the process's
    /// to state.
    /// Verifies: ADR-0041
    #[test]
    fn a_process_never_overrides_what_the_operator_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = AgentDescription {
            identifying_attributes: vec![string_attr("service.namespace", "the-processs")],
            non_identifying_attributes: vec![
                string_attr("channel", "stable"),
                string_attr("service.team", "x"),
            ],
        };

        let mut agent = supervised_agent(&dir.path().join("configured"))
            .with_attributes(
                [
                    ("channel".to_string(), "canary".to_string()),
                    ("service.team".to_string(), "y".to_string()),
                ]
                .into(),
            )
            .with_namespace(Some("telemetry".to_string()));
        agent.set_process_description(report.clone());
        let configured = reported(&agent.describe());
        assert_eq!(
            configured.get("channel").map(String::as_str),
            Some("canary")
        );
        assert_eq!(
            configured.get("service.team").map(String::as_str),
            Some("y")
        );
        assert_eq!(
            configured.get("service.namespace").map(String::as_str),
            Some("telemetry")
        );

        let mut agent = supervised_agent(&dir.path().join("unset"));
        agent.set_process_description(report);
        let unset = reported(&agent.describe());
        assert_eq!(
            unset.get("service.namespace").map(String::as_str),
            Some("the-processs")
        );
        assert_eq!(unset.get("service.team").map(String::as_str), Some("x"));
        assert_eq!(unset.get("channel"), None, "outside service.*, dropped");
    }

    /// An admitted key replaces the Supervisor's value in the list the Supervisor states it in,
    /// so it is reported once and a Selector and the fleet row read the same value.
    /// Verifies: ADR-0041
    #[test]
    fn an_admitted_key_replaces_the_supervisors_value_in_the_supervisors_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = supervised_agent(dir.path());
        agent.set_process_description(AgentDescription {
            identifying_attributes: vec![],
            non_identifying_attributes: vec![string_attr("service.name", "otelcol-contrib")],
        });

        let description = agent.describe();
        let named = |list: &[KeyValue]| {
            list.iter()
                .filter(|kv| kv.key == "service.name")
                .map(
                    |kv| match kv.value.as_ref().and_then(|v| v.value.as_ref()) {
                        Some(opamp::proto::any_value::Value::StringValue(s)) => s.clone(),
                        other => format!("{other:?}"),
                    },
                )
                .collect::<Vec<_>>()
        };
        assert_eq!(
            named(&description.identifying_attributes),
            ["otelcol-contrib"]
        );
        assert!(named(&description.non_identifying_attributes).is_empty());
        assert_eq!(
            agent.service_name(),
            "otelcol-contrib",
            "the accessor reads it as the fold does"
        );
    }

    #[test]
    fn declared_capabilities_ride_every_report_and_the_goodbye() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let base = agent.next_report().capabilities;
        assert_eq!(base, AGENT_CAPABILITIES);
        assert_eq!(base & AgentCapabilities::ReportsHeartbeat as u64, 0);

        agent.declare_capability(AgentCapabilities::ReportsHeartbeat);
        let declared = agent.next_report().capabilities;
        assert_eq!(declared, base | AgentCapabilities::ReportsHeartbeat as u64);
        assert_eq!(agent.disconnect_message().capabilities, declared);
    }

    #[test]
    fn a_restart_command_is_queued_by_supervised_agents_and_ignores_other_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("supervised")).expect("storage");
        let mut supervised = AgentState::supervised(
            "s".to_string(),
            "s".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        assert_ne!(
            supervised.next_report().capabilities & AgentCapabilities::AcceptsRestartCommand as u64,
            0,
            "a supervised agent declares restartability"
        );

        // A command message per the Baseline: every field besides identity, capabilities, and
        // the command is ignored — the piggybacked remote_config must not be applied.
        let command_with_config = ServerToAgent {
            command: Some(opamp::proto::ServerToAgentCommand {
                r#type: opamp::proto::CommandType::Restart as i32,
            }),
            remote_config: Some(remote_config(b"x: 1\n", b"sneaky")),
            ..Default::default()
        };
        supervised.handle(&command_with_config);
        assert!(supervised.take_pending_restart());
        assert!(!supervised.take_pending_restart(), "taken exactly once");
        assert!(
            supervised.take_pending_apply().is_none(),
            "the piggybacked config is ignored"
        );

        // The self-Agent never declares the capability and ignores the command.
        let mut this = make_agent(&dir.path().join("self"));
        assert_eq!(
            this.next_report().capabilities & AgentCapabilities::AcceptsRestartCommand as u64,
            0
        );
        this.handle(&command_with_config);
        assert!(!this.take_pending_restart());
    }

    /// ADR-0018: the Client's own Agent takes one named package and refuses everything else. A
    /// package with an empty Selector reaches every consenting Agent (ADR-0026), so without this
    /// the first fleet-wide Collector artifact an operator uploads would be written over the
    /// Client and take the host out of reach.
    /// Verifies: ADR-0018
    #[test]
    fn the_self_agent_refuses_a_package_not_named_after_its_agent_type() {
        use opamp::proto::{DownloadableFile, PackageAvailable, PackagesAvailable};

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::new(
            "opamp-fleet-client".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages_named("opamp-client".to_string());
        let _ = agent.next_report();

        let offer = |name: &str| PackagesAvailable {
            packages: [(
                name.to_string(),
                PackageAvailable {
                    version: "2.0.0".to_string(),
                    file: Some(DownloadableFile {
                        download_url: "/x".to_string(),
                        content_hash: b"chash".to_vec(),
                        ..Default::default()
                    }),
                    hash: b"pkg-hash".to_vec(),
                    ..Default::default()
                },
            )]
            .into(),
            all_packages_hash: b"agg-1".to_vec(),
        };

        // A Collector's package, offered fleet-wide: refused, and nothing is downloaded.
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(offer("otelcol")),
            ..Default::default()
        });
        assert!(
            handled.package_download.is_none(),
            "nothing is fetched for a package this Agent does not take"
        );
        assert!(handled.send_report, "the refusal is reported, not silent");
        let statuses = agent
            .next_report()
            .package_statuses
            .expect("a package status");
        assert!(
            statuses.error_message.contains("opamp-client"),
            "the refusal names what this Agent would accept: {:?}",
            statuses.error_message
        );
        assert_eq!(
            statuses.server_provided_all_packages_hash, b"agg-1",
            "the aggregate is echoed so the Server stops re-offering it"
        );

        // The configured one is taken.
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(offer("opamp-client")),
            ..Default::default()
        });
        let download = handled
            .package_download
            .expect("the named package is taken");
        assert_eq!(download.name, "opamp-client");
    }

    /// One offer of a package, by name and hash — the shape both restore tests below hand to the
    /// Agent to ask "would you take this again?".
    fn package_offer(name: &str, version: &str, hash: &[u8]) -> opamp::proto::PackagesAvailable {
        use opamp::proto::{DownloadableFile, PackageAvailable, PackagesAvailable};
        PackagesAvailable {
            packages: [(
                name.to_string(),
                PackageAvailable {
                    version: version.to_string(),
                    file: Some(DownloadableFile {
                        download_url: "/x".to_string(),
                        content_hash: b"chash".to_vec(),
                        ..Default::default()
                    }),
                    hash: hash.to_vec(),
                    ..Default::default()
                },
            )]
            .into(),
            all_packages_hash: b"agg-1".to_vec(),
        }
    }

    /// A record naming a version this binary is not is a record about a binary that is gone:
    /// `service uninstall` keeps the state, so reinstalling an older Client lands on top of what
    /// its successor wrote. Reported, it would tell the Server a version this host does not run —
    /// and the hash gate inside it would stop the package ever being offered here again.
    #[test]
    fn a_package_record_from_another_version_is_discarded_on_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_package(&InstalledPackage {
                name: "opamp-client".to_string(),
                version: "9.9.9".to_string(),
                hash_hex: hex::encode(b"pkg-hash"),
            })
            .expect("store the record a successor left behind");

        let mut agent = AgentState::new(
            "opamp-fleet-client".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages_named("opamp-client".to_string());

        // What is claimed is what this binary *is* — never the version the record named.
        let statuses = agent
            .next_report()
            .package_statuses
            .expect("a package status");
        let reported = statuses
            .packages
            .get("opamp-client")
            .expect("the package this Client consents to is named from the first report");
        assert_eq!(
            Some(reported.agent_has_version.as_str()),
            fleet_core::version::identity(fleet_core::version::current()),
            "a version this Client does not run must not be reported as installed"
        );
        assert!(
            reported.agent_has_hash.is_empty(),
            "and no hash is invented for bytes no package delivered"
        );
        assert!(
            !dir.path().join("installed-package.json").exists(),
            "the stale record is dropped from disk, not only from memory"
        );

        // And the very bytes the record named are taken again, rather than echoed as in sync.
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(package_offer("opamp-client", "9.9.9", b"pkg-hash")),
            ..Default::default()
        });
        let download = handled
            .package_download
            .expect("the package is offered to this Client again");
        assert_eq!(download.name, "opamp-client");
    }

    /// The other half, and the one that matters more: an ordinary restart must keep its record.
    /// A Client that discarded it would reinstall the version it already runs on every start.
    #[test]
    fn a_package_record_for_the_running_version_survives_a_restart() {
        use opamp::proto::PackageStatusEnum;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_package(&InstalledPackage {
                name: "opamp-client".to_string(),
                // What the Server was told to offer: the release, without the build metadata this
                // binary carries (ADR-0012).
                version: fleet_core::version::parse(fleet_core::version::current())
                    .expect("this build's version parses")
                    .identity()
                    .to_string(),
                hash_hex: hex::encode(b"pkg-hash"),
            })
            .expect("store");

        let mut agent = AgentState::new(
            "opamp-fleet-client".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages_named("opamp-client".to_string());

        let statuses = agent
            .next_report()
            .package_statuses
            .expect("a package status");
        let status = statuses.packages.get("opamp-client").expect("the package");
        assert_eq!(status.status, PackageStatusEnum::Installed as i32);
        assert!(dir.path().join("installed-package.json").exists());

        // Offered the version it runs, this Client is in sync and downloads nothing.
        let running =
            fleet_core::version::identity(fleet_core::version::current()).expect("this version");
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(package_offer("opamp-client", running, b"pkg-hash")),
            ..Default::default()
        });
        assert!(
            handled.package_download.is_none(),
            "a restarted Client must not reinstall the version it already runs"
        );
    }

    /// ADR-0025 point 15: for the package that carries this Client, *already installed* is what
    /// this process runs — never a hash in a record. The same bytes can be published under a new
    /// version, and a record about a binary that is gone must not swallow the offer that would
    /// replace it: the Server offers because the Agent reports running something older, and a
    /// Client that answered "in sync" from its record would strand the host on what it runs, for
    /// good.
    // Verifies: ADR-0025
    #[test]
    fn the_clients_own_offer_is_settled_by_the_version_it_runs_not_by_a_recorded_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_package(&InstalledPackage {
                name: "opamp-client".to_string(),
                version: fleet_core::version::identity(fleet_core::version::current())
                    .expect("this version")
                    .to_string(),
                hash_hex: hex::encode(b"pkg-hash"),
            })
            .expect("store");

        let mut agent = AgentState::new(
            "opamp-fleet-client".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages_named("opamp-client".to_string());

        // The record's own hash, under a version this Client does not run: taken, not echoed.
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(package_offer("opamp-client", "9.9.9", b"pkg-hash")),
            ..Default::default()
        });
        let download = handled
            .package_download
            .expect("a version this Client does not run is installed, whatever the record holds");
        assert_eq!(download.version, "9.9.9");

        // A Supervisor keeps the hash test: the Managed Process's version is numbered in whatever
        // space the operator chose, so the same bytes are the same package and nothing else is.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_package(&InstalledPackage {
                name: "otelcol".to_string(),
                version: "2.0.0".to_string(),
                hash_hex: hex::encode(b"pkg-hash"),
            })
            .expect("store");
        let mut supervised = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        supervised.accept_packages();
        let handled = supervised.handle(&ServerToAgent {
            packages_available: Some(package_offer("otelcol", "2.0.0", b"pkg-hash")),
            ..Default::default()
        });
        assert!(
            handled.package_download.is_none(),
            "the same bytes are the package a Supervisor already installed"
        );
    }

    /// Verifies: ADR-0026
    #[test]
    fn a_package_offer_for_the_named_package_is_acknowledged_installing_and_handed_over() {
        use opamp::proto::{
            DownloadableFile, PackageAvailable, PackageStatusEnum, PackagesAvailable,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();
        let _ = agent.next_report();

        // The two package capabilities are declared once a package is accepted.
        let caps = agent.next_report().capabilities;
        assert_ne!(caps & AgentCapabilities::AcceptsPackages as u64, 0);
        assert_ne!(caps & AgentCapabilities::ReportsPackageStatuses as u64, 0);

        let offer = PackagesAvailable {
            packages: [(
                "otelcol".to_string(),
                PackageAvailable {
                    version: "2.0.0".to_string(),
                    file: Some(DownloadableFile {
                        download_url: "/api/v1/packages/otelcol/file".to_string(),
                        content_hash: b"chash".to_vec(),
                        ..Default::default()
                    }),
                    hash: b"pkg-hash".to_vec(),
                    ..Default::default()
                },
            )]
            .into(),
            all_packages_hash: b"agg-1".to_vec(),
        };
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(offer.clone()),
            ..Default::default()
        });
        assert!(handled.send_report);
        let download = handled.package_download.expect("a download");
        assert_eq!(download.name, "otelcol");
        assert_eq!(download.version, "2.0.0");
        assert_eq!(download.content_hash, b"chash");

        // The next report acknowledges Installing.
        let statuses = agent.next_report().package_statuses.expect("statuses");
        assert_eq!(
            statuses.packages["otelcol"].status,
            PackageStatusEnum::Installing as i32
        );

        // While the artifact is on the wire the status is Downloading, carrying how far it has
        // got — the Baseline's interim reporting, which is what keeps a minutes-long transfer
        // distinguishable from a stuck install.
        agent.package_downloading(PackageDownloadDetails {
            download_percent: 42.5,
            download_bytes_per_second: 1_048_576.0,
        });
        let status = agent
            .next_report()
            .package_statuses
            .expect("statuses")
            .packages["otelcol"]
            .clone();
        assert_eq!(status.status, PackageStatusEnum::Downloading as i32);
        let details = status.download_details.expect("details while downloading");
        assert!((details.download_percent - 42.5).abs() < f64::EPSILON);
        assert!((details.download_bytes_per_second - 1_048_576.0).abs() < f64::EPSILON);
        assert_eq!(
            status.server_offered_hash, b"pkg-hash",
            "the Baseline requires the offered hash while downloading"
        );
        assert!(
            status.error_message.is_empty(),
            "downloading is not an error"
        );

        // Bytes in, applying: back to Installing, and the details go with the status they belong
        // to ("should only be set if status is Downloading").
        agent.package_downloaded();
        let status = agent
            .next_report()
            .package_statuses
            .expect("statuses")
            .packages["otelcol"]
            .clone();
        assert_eq!(status.status, PackageStatusEnum::Installing as i32);
        assert!(status.download_details.is_none());

        // A repeat of the same offer while in flight is not re-entered.
        let again = agent.handle(&ServerToAgent {
            packages_available: Some(offer),
            ..Default::default()
        });
        assert!(again.package_download.is_none(), "no re-download in flight");

        // The Supervisor installed it: Installed, at the offered version, aggregate echoed.
        agent.package_applied(b"pkg-hash".to_vec(), Ok("2.0.0".to_string()));
        let statuses = agent.next_report().package_statuses.expect("statuses");
        let status = &statuses.packages["otelcol"];
        assert_eq!(status.status, PackageStatusEnum::Installed as i32);
        assert_eq!(status.agent_has_version, "2.0.0");
        assert_eq!(statuses.server_provided_all_packages_hash, b"agg-1");

        // A re-offer of the same package is now recognised as already installed — no re-download.
        let settled = agent.handle(&ServerToAgent {
            packages_available: Some(PackagesAvailable {
                packages: [(
                    "otelcol".to_string(),
                    PackageAvailable {
                        version: "2.0.0".to_string(),
                        file: Some(DownloadableFile {
                            download_url: "/x".to_string(),
                            content_hash: b"chash".to_vec(),
                            ..Default::default()
                        }),
                        hash: b"pkg-hash".to_vec(),
                        ..Default::default()
                    },
                )]
                .into(),
                all_packages_hash: b"agg-1".to_vec(),
            }),
            ..Default::default()
        });
        assert!(settled.package_download.is_none(), "already installed");
    }

    /// An `Addon` is not a Managed Process's binary, and the only thing this Client can do with a
    /// package is *be* that binary — so an offer carrying nothing but addons is refused rather
    /// than installed over the process they were meant to extend, and the refusal is reported.
    /// Verifies: ADR-0026
    #[test]
    fn an_addon_package_is_refused_instead_of_overwriting_the_binary() {
        use opamp::proto::{DownloadableFile, PackageAvailable, PackagesAvailable};
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();
        let _ = agent.next_report();

        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(PackagesAvailable {
                packages: [(
                    "otelcol".to_string(),
                    PackageAvailable {
                        r#type: PackageType::Addon as i32,
                        version: "2.0.0".to_string(),
                        file: Some(DownloadableFile {
                            download_url: "/api/v1/packages/otelcol/file".to_string(),
                            content_hash: b"chash".to_vec(),
                            ..Default::default()
                        }),
                        hash: b"addon-hash".to_vec(),
                    },
                )]
                .into(),
                all_packages_hash: b"agg-addon".to_vec(),
            }),
            ..Default::default()
        });
        assert!(
            handled.package_download.is_none(),
            "an addon is never downloaded, let alone swapped over the binary"
        );
        assert!(handled.send_report, "the refusal is reported at once");

        // The failure is about the offer, not about one package — which is exactly what the
        // Baseline's `PackageStatuses.error_message` is for ("not related to any particular
        // single package"), so it rides there and the packages map stays empty.
        let statuses = agent.next_report().package_statuses.expect("statuses");
        assert!(
            statuses.error_message.contains("addon"),
            "the reason names what was refused: {}",
            statuses.error_message
        );
        assert!(statuses.packages.is_empty(), "nothing was installed");
        // A refusal is a report, not a loop: the aggregate is echoed so the offer ends.
        assert_eq!(statuses.server_provided_all_packages_hash, b"agg-addon");
    }

    /// An offer of two top-level packages is refused whole: an Agent has one binary to replace,
    /// and picking one of the two would let the order of a map decide what runs.
    /// Verifies: ADR-0026
    #[test]
    fn an_offer_of_two_top_level_packages_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();
        let _ = agent.next_report();

        let mut offer = package_offer("otelcol", "1.0.0", b"one");
        offer
            .packages
            .extend(package_offer("otelcol-extra", "1.0.0", b"two").packages);
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(offer),
            ..Default::default()
        });
        assert!(handled.package_download.is_none(), "neither is fetched");
        assert!(handled.send_report, "the refusal is reported at once");
        let statuses = agent.next_report().package_statuses.expect("statuses");
        assert!(
            statuses.error_message.contains("two top-level packages"),
            "{}",
            statuses.error_message
        );
        assert!(statuses.packages.is_empty(), "nothing was installed");
        assert_eq!(statuses.server_provided_all_packages_hash, b"agg-1");
    }

    /// A Supervisor takes a package only for its own Agent type, and never one older than it
    /// runs: both are refused before anything is downloaded, and the reason is reported.
    /// Verifies: ADR-0026
    #[test]
    fn a_package_for_another_type_or_an_older_version_is_refused() {
        use crate::supervisor::ports::AgentStorage as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_package(&crate::supervisor::ports::InstalledPackage {
                name: "otelcol".to_string(),
                version: "0.110.0".to_string(),
                hash_hex: hex::encode(b"installed"),
            })
            .expect("store");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();
        let _ = agent.next_report();

        for (offer, reason) in [
            (package_offer("telegraf", "1.30.0", b"other"), "telegraf"),
            (package_offer("otelcol", "0.109.0", b"older"), "older"),
        ] {
            let handled = agent.handle(&ServerToAgent {
                packages_available: Some(offer),
                ..Default::default()
            });
            assert!(
                handled.package_download.is_none(),
                "{reason}: nothing is fetched"
            );
            let statuses = agent.next_report().package_statuses.expect("statuses");
            assert!(
                statuses.error_message.contains(reason),
                "{reason}: {}",
                statuses.error_message
            );
        }
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(package_offer("otelcol", "0.111.0", b"newer")),
            ..Default::default()
        });
        assert!(
            handled.package_download.is_some(),
            "a newer one of its own type is taken"
        );
    }

    /// A Supervisor of type `otelcol` over its own directory, holding `marks`, taking packages.
    fn supervisor_with_marks(
        dir: &std::path::Path,
        marks: &std::sync::Arc<dyn HighWaterMarks>,
    ) -> AgentState {
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            Storage::new(dir.to_path_buf()).expect("storage"),
            crate::host::SystemHost,
        )
        .expect("agent")
        .with_high_water(marks.clone());
        agent.accept_packages();
        let _ = agent.next_report();
        agent
    }

    /// Offers `version` and answers whether a download was scheduled, and the reported refusal.
    fn offered(agent: &mut AgentState, version: &str, hash: &[u8]) -> (bool, String) {
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(package_offer("otelcol", version, hash)),
            ..Default::default()
        });
        let statuses = agent.next_report().package_statuses.expect("statuses");
        (handled.package_download.is_some(), statuses.error_message)
    }

    /// A Supervisor with no installed record and no mark refuses an offer at `1.19`: nothing is
    /// downloaded, and the reason names the version (ADR-0043 clause 7).
    /// Verifies: ADR-0043
    #[test]
    fn a_supervisor_refuses_an_offer_whose_version_is_not_semver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marks: std::sync::Arc<dyn HighWaterMarks> =
            std::sync::Arc::new(crate::storage::HighWaterFile::open(dir.path()));
        let mut agent = supervisor_with_marks(&dir.path().join("otelcol"), &marks);
        for version in ["1.19", "24.04.1", "nightly"] {
            let (downloads, why) = offered(&mut agent, version, version.as_bytes());
            assert!(!downloads, "{version}: nothing is fetched");
            assert!(
                why.contains(&format!("{version:?}")) && why.contains("SemVer"),
                "{version}: {why}"
            );
        }
        assert!(
            offered(&mut agent, "1.19.0", b"semver").0,
            "1.19.0 is taken"
        );
    }

    /// The mark rises on `Installed` and on nothing else: a failed apply, which rolled back to the
    /// predecessor, leaves it and the version reported where they were; an `Installed` raises it
    /// and writes the file owner-only (ADR-0043 clause 8).
    /// Verifies: ADR-0043
    #[test]
    fn the_mark_rises_only_when_a_package_is_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join(crate::storage::HIGH_WATER_FILE);
        let marks: std::sync::Arc<dyn HighWaterMarks> =
            std::sync::Arc::new(crate::storage::HighWaterFile::open(dir.path()));
        let mut agent = supervisor_with_marks(&dir.path().join("otelcol"), &marks);

        assert!(offered(&mut agent, "0.110.0", b"v110").0);
        agent.package_applied(b"v110".to_vec(), Ok("0.110.0".to_string()));
        assert_eq!(marks.mark("otelcol"), Ok(Some("0.110.0".to_string())));
        let on_disk: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(&file).expect("the mark file")).expect("json");
        assert_eq!(on_disk["otelcol"], "0.110.0");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner-only");
        }

        assert!(offered(&mut agent, "0.111.0", b"v111").0);
        agent.package_applied(b"v111".to_vec(), Err("would not stay up".to_string()));
        assert_eq!(
            marks.mark("otelcol"),
            Ok(Some("0.110.0".to_string())),
            "a rollback moves nothing"
        );
        let statuses = agent.next_report().package_statuses.expect("statuses");
        assert_eq!(
            statuses.packages["otelcol"].agent_has_version, "0.110.0",
            "the predecessor runs"
        );
    }

    /// An installed record an older Client wrote under `1.19` is dropped at load: the Agent
    /// reports no `agent_has_version`, and nothing enters the mark (ADR-0043 clause 10).
    /// Verifies: ADR-0043
    #[test]
    fn an_installed_record_whose_version_is_not_semver_is_dropped_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("otelcol");
        Storage::new(supervisor.clone())
            .expect("storage")
            .store_package(&InstalledPackage {
                name: "otelcol".to_string(),
                version: "1.19".to_string(),
                hash_hex: hex::encode(b"old"),
            })
            .expect("store");
        let marks: std::sync::Arc<dyn HighWaterMarks> =
            std::sync::Arc::new(crate::storage::HighWaterFile::open(dir.path()));
        let mut agent = supervisor_with_marks(&supervisor, &marks);

        assert!(
            !supervisor.join("installed-package.json").exists(),
            "the record is deleted"
        );
        assert_eq!(marks.mark("otelcol"), Ok(None));
        // The first offer keys the status; it reports nothing installed.
        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(package_offer("otelcol", "1.19.0", b"republished")),
            ..Default::default()
        });
        assert!(handled.package_download.is_some(), "a first rollout");
        let statuses = agent.next_report().package_statuses.expect("statuses");
        assert_eq!(statuses.packages["otelcol"].agent_has_version, "");
    }

    /// A reply declaring a Capability Set, so a test can say what the Server accepts.
    fn declaring(capabilities: u64) -> ServerToAgent {
        ServerToAgent {
            capabilities,
            ..Default::default()
        }
    }

    /// ADR-0014 clause 14: once the Server has declared its capabilities, package status stops
    /// going to one that cannot take it. The Baseline makes this a MUST in both directions.
    /// Verifies: ADR-0014
    #[test]
    fn package_statuses_stop_once_the_server_says_it_accepts_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();

        // A Server that takes status reports and offers configuration, but no package status.
        agent.handle(&declaring(
            ServerCapabilities::AcceptsStatus as u64
                | ServerCapabilities::OffersRemoteConfig as u64,
        ));
        agent.force_full();
        assert!(
            agent.next_report().package_statuses.is_none(),
            "an undeclared capability must not be exercised"
        );

        // …and it comes back the moment the Server declares the bit.
        agent.handle(&declaring(
            ServerCapabilities::AcceptsStatus as u64
                | ServerCapabilities::AcceptsPackagesStatus as u64,
        ));
        agent.force_full();
        assert!(agent.next_report().package_statuses.is_some());
    }

    /// And the optimistic half (clause 1): before the Server has said anything there is nothing to
    /// obey, so the first report — which necessarily precedes any declaration — carries everything.
    /// Verifies: ADR-0014
    #[test]
    fn package_statuses_ride_until_the_server_has_spoken() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();
        assert!(agent.next_report().package_statuses.is_some());
    }

    /// ADR-0014 clause 13, and the reason the naive gate is wrong: a Server may send an offer
    /// *without* declaring `OffersConnectionSettings` — this project's own does exactly that for a
    /// `[telemetry_offer]`-only or `[client_ca]`-only configuration. Withholding the acknowledgement
    /// would leave its hash gate open and have it re-offer for ever, so the offer arms the report.
    /// Verifies: ADR-0014
    #[test]
    fn a_connection_settings_status_is_reported_to_a_server_that_offered_without_declaring_the_bit()
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent =
            AgentState::new("self".to_string(), storage, crate::host::SystemHost).expect("agent");

        agent.handle(&ServerToAgent {
            // Only the one bit every Server MUST set — no OffersConnectionSettings.
            capabilities: ServerCapabilities::AcceptsStatus as u64,
            connection_settings: Some(opamp::proto::ConnectionSettingsOffers {
                hash: b"offer-1".to_vec(),
                own_logs: Some(opamp::proto::TelemetryConnectionSettings {
                    destination_endpoint: "https://collector.example:4318/v1/logs".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        });

        let status = agent
            .next_report()
            .connection_settings_status
            .expect("the offer arms the report whatever the bitmask says");
        assert_eq!(status.last_connection_settings_hash, b"offer-1");
    }

    /// The other side of clause 2, and the only shape where the gate is actually observable: a
    /// **restarted** Client holds a status from its persisted settings (ADR-0014) without any offer
    /// having arrived in this process. Sent to a Server that declares only the mandatory bit, that
    /// status exercises a capability the Server never claimed — so it is withheld until the Server
    /// either declares the bit or offers something.
    /// Verifies: ADR-0014
    #[test]
    fn a_restored_connection_settings_status_is_withheld_from_a_server_that_never_offers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent =
            AgentState::new("self".to_string(), storage, crate::host::SystemHost).expect("agent");
        // What `runtime.rs` does at startup when `connection-settings.pb` exists.
        agent.adopt_connection_settings(b"persisted-1");

        agent.handle(&declaring(ServerCapabilities::AcceptsStatus as u64));
        agent.force_full();
        assert!(
            agent.next_report().connection_settings_status.is_none(),
            "an undeclared capability must not be exercised"
        );

        // Declaring the bit brings it straight back.
        agent.handle(&declaring(
            ServerCapabilities::AcceptsStatus as u64
                | ServerCapabilities::OffersConnectionSettings as u64,
        ));
        agent.force_full();
        assert!(agent.next_report().connection_settings_status.is_some());
    }

    /// ADR-0014 clause 16, written as an assertion so the deliberate non-gate cannot be silently
    /// reversed by someone applying the MUST field by field. `OffersRemoteConfig` says the Server
    /// *can offer* configuration; what licenses this inbound status is `AcceptsStatus`, and gating
    /// it would silence the hash the Server's re-offer decision depends on.
    /// Verifies: ADR-0014
    #[test]
    fn a_remote_config_status_rides_to_a_server_that_offers_no_remote_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");

        // A configuration was offered and acknowledged at some point…
        agent.handle(&ServerToAgent {
            remote_config: Some(AgentRemoteConfig {
                config: Some(AgentConfigMap {
                    config_map: Default::default(),
                }),
                config_hash: b"cfg-1".to_vec(),
            }),
            ..Default::default()
        });
        // …and the Server now declares nothing but the mandatory bit.
        agent.handle(&declaring(ServerCapabilities::AcceptsStatus as u64));
        agent.force_full();

        let status = agent
            .next_report()
            .remote_config_status
            .expect("the config hash must keep flowing, or the Server re-offers for ever");
        assert_eq!(status.last_remote_config_hash, b"cfg-1");
    }

    /// The headers a `DownloadableFile` names travel to the download that has to use them — the
    /// credential a referenced source needs (ADR-0026), which the Server fills from the operator's
    /// configuration.
    /// Verifies: ADR-0026
    #[test]
    fn a_package_offer_hands_its_download_headers_to_the_transport() {
        use opamp::proto::{
            DownloadableFile, Header, Headers, PackageAvailable, PackagesAvailable,
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();

        let handled = agent.handle(&ServerToAgent {
            packages_available: Some(PackagesAvailable {
                packages: [(
                    "otelcol".to_string(),
                    PackageAvailable {
                        r#type: PackageType::TopLevel as i32,
                        version: "1.2.3".to_string(),
                        file: Some(DownloadableFile {
                            download_url: "https://mirror.example/otelcol.tar.gz".to_string(),
                            content_hash: b"hash".to_vec(),
                            signature: Vec::new(),
                            headers: Some(Headers {
                                headers: vec![Header {
                                    key: "X-Api-Key".to_string(),
                                    value: "operator-secret".to_string(),
                                }],
                            }),
                        }),
                        hash: b"pkg".to_vec(),
                    },
                )]
                .into(),
                all_packages_hash: b"agg".to_vec(),
            }),
            ..Default::default()
        });

        let download = handled.package_download.expect("a download");
        assert_eq!(
            download.headers,
            vec![("X-Api-Key".to_string(), "operator-secret".to_string())]
        );
    }

    /// Verifies: ADR-0026
    #[test]
    fn a_failed_package_reports_installed_failed_and_keeps_the_old_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut agent = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        agent.accept_packages();
        agent.local.offered_all_packages_hash = b"agg-2".to_vec();
        agent.local.server_offered = Some(("9.9.9".to_string(), b"bad".to_vec()));
        agent.local.installing = Some(PackageDownload {
            name: "otelcol".to_string(),
            version: "9.9.9".to_string(),
            hash: b"bad".to_vec(),
            download_url: String::new(),
            content_hash: Vec::new(),
            signature: Vec::new(),
            headers: Vec::new(),
        });

        agent.package_applied(b"bad".to_vec(), Err("would not stay up".to_string()));
        let statuses = agent.next_report().package_statuses.expect("statuses");
        let status = &statuses.packages["otelcol"];
        assert_eq!(
            status.status,
            opamp::proto::PackageStatusEnum::InstallFailed as i32
        );
        assert_eq!(status.error_message, "would not stay up");
        // A failure is a report, not a loop: the aggregate is echoed so the Server stops re-offering.
        assert_eq!(statuses.server_provided_all_packages_hash, b"agg-2");
    }

    /// Verifies: ADR-0014
    #[test]
    fn a_connection_offer_is_acknowledged_applying_and_handed_to_the_transport() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let _ = agent.next_report();

        // Every Agent declares it can accept and report on connection settings (ADR-0014).
        let caps = agent.next_report().capabilities;
        assert_ne!(
            caps & AgentCapabilities::AcceptsOpAmpConnectionSettings as u64,
            0
        );
        assert_ne!(
            caps & AgentCapabilities::ReportsConnectionSettingsStatus as u64,
            0
        );

        let offer = ConnectionSettingsOffers {
            hash: b"offer-1".to_vec(),
            opamp: Some(opamp::proto::OpAmpConnectionSettings {
                destination_endpoint: "wss://new/v1/opamp".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let handled = agent.handle(&ServerToAgent {
            connection_settings: Some(offer.clone()),
            ..Default::default()
        });
        assert!(handled.send_report);
        assert_eq!(handled.connection_offer, Some(offer.clone()));

        // The next report acknowledges APPLYING with the offer hash.
        let status = agent
            .next_report()
            .connection_settings_status
            .expect("status");
        assert_eq!(status.last_connection_settings_hash, b"offer-1");
        assert_eq!(status.status, ConnectionSettingsStatuses::Applying as i32);

        // The transport verified: APPLIED, and the same offer is not re-entered.
        agent.connection_settings_outcome(b"offer-1", Ok(()));
        let applied = agent
            .next_report()
            .connection_settings_status
            .expect("status");
        assert_eq!(applied.status, ConnectionSettingsStatuses::Applied as i32);
        let handled = agent.handle(&ServerToAgent {
            connection_settings: Some(offer),
            ..Default::default()
        });
        assert_eq!(
            handled.connection_offer, None,
            "an already-applied offer is not verified again"
        );
    }

    /// Verifies: ADR-0014
    #[test]
    fn a_failed_offer_still_reports_the_hash_so_the_server_stops_reoffering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let _ = agent.next_report();

        let offer = ConnectionSettingsOffers {
            hash: b"offer-2".to_vec(),
            opamp: Some(opamp::proto::OpAmpConnectionSettings::default()),
            ..Default::default()
        };
        agent.handle(&ServerToAgent {
            connection_settings: Some(offer.clone()),
            ..Default::default()
        });
        let _ = agent.next_report();
        agent.connection_settings_outcome(b"offer-2", Err("could not connect"));

        let failed = agent
            .next_report()
            .connection_settings_status
            .expect("status");
        assert_eq!(failed.status, ConnectionSettingsStatuses::Failed as i32);
        assert_eq!(failed.last_connection_settings_hash, b"offer-2");
        assert_eq!(failed.error_message, "could not connect");

        // A re-offer of the failed hash is retried (the Server may have fixed the credential).
        let handled = agent.handle(&ServerToAgent {
            connection_settings: Some(offer),
            ..Default::default()
        });
        assert!(handled.connection_offer.is_some());
    }

    #[test]
    fn available_components_report_the_hash_and_the_map_only_on_demand() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let _ = agent.next_report();

        let full = AvailableComponents {
            components: HashMap::from([(
                "receiver/otlp".to_string(),
                opamp::proto::ComponentDetails::default(),
            )]),
            hash: b"components-hash".to_vec(),
        };
        agent.set_available_components(full.clone());

        // The next (full) report declares the bit and carries the hash only.
        let report = agent.next_report();
        assert_ne!(
            report.capabilities & AgentCapabilities::ReportsAvailableComponents as u64,
            0
        );
        let carried = report.available_components.expect("the hash announcement");
        assert!(carried.components.is_empty());
        assert_eq!(carried.hash, full.hash);

        // The Server demands the full map: exactly the next report carries it, once.
        let handled = agent.handle(&ServerToAgent {
            flags: ServerToAgentFlags::ReportAvailableComponents as u64,
            ..Default::default()
        });
        assert!(handled.send_report);
        let demanded = agent.next_report().available_components.expect("the map");
        assert!(demanded.components.contains_key("receiver/otlp"));
        assert!(agent.next_report().available_components.is_none());
    }

    #[test]
    fn first_report_is_full_then_compressed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());

        let first = agent.next_report();
        assert!(first.agent_description.is_some());
        assert!(first.health.is_some());
        assert_eq!(first.sequence_num, 1);

        let second = agent.next_report();
        assert!(second.agent_description.is_none());
        assert!(second.health.is_none());
        assert_eq!(second.sequence_num, 2);
    }

    /// The self-Agent's offer is acknowledged `APPLYING` and left pending for the Engine's
    /// Supervisor-set apply (ADR-0017); the verdict closes the lifecycle, and only then does the
    /// configuration echo as effective.
    /// Verifies: ADR-0014
    #[test]
    fn an_offer_is_applied_and_acknowledged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let _ = agent.next_report();

        let handled = agent.handle(&ServerToAgent {
            remote_config: Some(remote_config(b"x: 1\n", b"hash-1")),
            ..Default::default()
        });
        assert!(handled.send_report);

        let ack = agent.next_report();
        let status = ack.remote_config_status.expect("status");
        assert_eq!(status.status, RemoteConfigStatuses::Applying as i32);
        assert_eq!(status.last_remote_config_hash, b"hash-1");
        assert!(agent.take_pending_apply().is_some());

        agent.config_applied(b"hash-1".to_vec(), Ok(()));
        let done = agent.next_report();
        let status = done.remote_config_status.expect("status");
        assert_eq!(status.status, RemoteConfigStatuses::Applied as i32);
        assert_eq!(status.last_remote_config_hash, b"hash-1");
        assert!(done.effective_config.is_some());
    }

    /// A restart reports `APPLIED` only for a configuration whose apply actually finished
    /// (ADR-0017): the offer is persisted on the verdict, never on receipt, so a Client
    /// restarted mid-apply reports nothing and the Server offers again.
    #[test]
    fn the_applied_config_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut agent = make_agent(dir.path());
            let _ = agent.next_report();
            agent.handle(&ServerToAgent {
                remote_config: Some(remote_config(b"x: 1\n", b"hash-1")),
                ..Default::default()
            });
        }
        // Interrupted mid-apply: nothing was persisted, the restarted Agent reports no status.
        {
            let mut interrupted = make_agent(dir.path());
            assert!(interrupted.next_report().remote_config_status.is_none());
            interrupted.handle(&ServerToAgent {
                remote_config: Some(remote_config(b"x: 1\n", b"hash-1")),
                ..Default::default()
            });
            interrupted.config_applied(b"hash-1".to_vec(), Ok(()));
        }
        let mut restarted = make_agent(dir.path());
        let report = restarted.next_report();
        let status = report.remote_config_status.expect("status");
        assert_eq!(status.last_remote_config_hash, b"hash-1");
        assert_eq!(status.status, RemoteConfigStatuses::Applied as i32);
    }

    #[test]
    fn report_full_state_forces_a_full_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let _ = agent.next_report();
        let _ = agent.next_report();

        let handled = agent.handle(&ServerToAgent {
            flags: ServerToAgentFlags::ReportFullState as u64,
            ..Default::default()
        });
        assert!(handled.send_report);
        assert!(agent.next_report().agent_description.is_some());
    }

    #[test]
    fn a_server_assigned_identity_is_adopted_and_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let new_uid = InstanceUid::default();
        agent.handle(&ServerToAgent {
            agent_identification: Some(opamp::proto::AgentIdentification {
                new_instance_uid: new_uid.as_bytes().to_vec(),
            }),
            ..Default::default()
        });
        assert_eq!(agent.uid(), new_uid);
        assert_eq!(make_agent(dir.path()).uid(), new_uid);
    }

    #[test]
    fn unavailable_yields_a_retry_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        let handled = agent.handle(&ServerToAgent {
            error_response: Some(opamp::proto::ServerErrorResponse {
                r#type: ServerErrorResponseType::Unavailable as i32,
                details: Some(opamp::proto::server_error_response::Details::RetryInfo(
                    opamp::proto::RetryInfo {
                        retry_after_nanoseconds: 5_000_000_000,
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(handled.retry_after, Some(Duration::from_secs(5)));
        assert!(!handled.send_report);
    }

    /// Verifies: ADR-0014
    #[test]
    fn effective_config_respects_the_servers_capability_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = make_agent(dir.path());
        // A server that only accepts status: stop sending effective config.
        agent.handle(&ServerToAgent {
            capabilities: ServerCapabilities::AcceptsStatus as u64,
            ..Default::default()
        });
        agent.force_full();
        assert!(agent.next_report().effective_config.is_none());
    }

    fn listed_supervisor(dir: &std::path::Path) -> AgentState {
        let storage = Storage::new(dir.to_path_buf()).expect("storage");
        AgentState::supervised_without_remote_config(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent")
    }

    /// A listed Supervisor's Agent is built without either remote-configuration bit, and keeps
    /// every other capability a Supervisor declares (ADR-0017 clause 50).
    /// Verifies: ADR-0017
    #[test]
    fn a_supervisor_with_remote_config_disabled_declares_neither_remote_config_capability() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = listed_supervisor(dir.path());
        agent.accept_packages();
        let declared = agent.next_report().capabilities;
        for absent in [
            AgentCapabilities::AcceptsRemoteConfig,
            AgentCapabilities::ReportsRemoteConfig,
        ] {
            assert_eq!(declared & absent as u64, 0, "{absent:?} is declared");
        }
        for present in [
            AgentCapabilities::ReportsEffectiveConfig,
            AgentCapabilities::AcceptsRestartCommand,
            AgentCapabilities::AcceptsPackages,
            AgentCapabilities::ReportsPackageStatuses,
        ] {
            assert_ne!(declared & present as u64, 0, "{present:?} is missing");
        }
    }

    /// An offer that arrives anyway is ignored: nothing stored, no entry file, nothing pending for
    /// the process adapter, and no status reported (ADR-0017 clause 51).
    /// Verifies: ADR-0017
    #[test]
    fn a_remote_config_offered_anyway_is_neither_stored_nor_applied_nor_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = listed_supervisor(dir.path());
        agent.next_report();
        let handled = agent.handle(&ServerToAgent {
            remote_config: Some(remote_config(b"receivers: {}\n", b"hash-1")),
            ..Default::default()
        });
        assert!(
            !handled.send_report,
            "nothing changed that the Server must hear"
        );
        assert!(agent.take_pending_apply().is_none());
        assert!(!dir.path().join("remote-config.pb").exists());
        assert!(
            !dir.path().join("config").exists()
                || std::fs::read_dir(dir.path().join("config"))
                    .expect("read config/")
                    .next()
                    .is_none(),
            "an entry file was written"
        );
        assert!(agent.next_report().remote_config_status.is_none());
        agent.force_full();
        assert!(agent.next_report().remote_config_status.is_none());
    }

    /// The warning about an ignored offer is said once per hash seen since start (ADR-0017 clause
    /// 31), so a Server resending the same offer does not flood the log.
    /// Verifies: ADR-0017
    #[test]
    fn an_ignored_remote_config_is_logged_once_per_hash() {
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();

        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = listed_supervisor(dir.path());
        tracing::subscriber::with_default(subscriber, || {
            for hash in [b"aaaa", b"aaaa", b"bbbb", b"aaaa", b"bbbb"] {
                agent.handle(&ServerToAgent {
                    remote_config: Some(remote_config(b"x: 1\n", hash)),
                    ..Default::default()
                });
            }
        });
        let log = String::from_utf8(captured.0.lock().expect("lock").clone()).expect("utf-8");
        let ignored: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("ignoring a remote configuration"))
            .collect();
        assert_eq!(ignored.len(), 2, "{log}");
        assert!(ignored[0].contains(&hex::encode(b"aaaa")), "{log}");
        assert!(ignored[1].contains(&hex::encode(b"bbbb")), "{log}");
        assert!(ignored.iter().all(|line| line.contains("otelcol")), "{log}");
    }

    /// What an ignored offer leaves behind is bounded whatever the Server sends: at most
    /// `IGNORED_CONFIGS_CAP` remembered digests however many distinct hashes arrive, and a long
    /// hash cut short in the log (ADR-0017 clause 51).
    /// Verifies: ADR-0017
    #[test]
    fn what_ignored_remote_configs_leave_behind_is_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = listed_supervisor(dir.path());
        for n in 0..=super::IGNORED_CONFIGS_CAP * 2 {
            let hash = vec![b'h'; 4096]
                .into_iter()
                .chain(n.to_be_bytes())
                .collect::<Vec<u8>>();
            agent.handle(&ServerToAgent {
                remote_config: Some(remote_config(b"x: 1\n", &hash)),
                ..Default::default()
            });
            let remembered = agent.ignored_configs.as_ref().expect("listed").len();
            assert!(
                remembered <= super::IGNORED_CONFIGS_CAP,
                "{remembered} after {n}"
            );
        }
        let logged = super::logged_hash(&[0xab; 4096]);
        assert_eq!(logged, format!("{}…", "ab".repeat(32)));
        assert_eq!(super::logged_hash(b"aaaa"), hex::encode(b"aaaa"));
    }

    fn own_agent_of_a_host_that_keeps_its_set(dir: &std::path::Path) -> AgentState {
        let storage = Storage::new(dir.to_path_buf()).expect("storage");
        AgentState::new_without_remote_config(
            "edge-1".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent")
    }

    /// The Client's own Agent on a host that keeps its set is built without either
    /// remote-configuration bit and keeps everything else it declares, self-update included
    /// (ADR-0017 clause 42).
    /// Verifies: ADR-0017
    #[test]
    fn the_own_agent_of_a_host_that_keeps_its_set_declares_neither_remote_config_capability() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = own_agent_of_a_host_that_keeps_its_set(dir.path());
        agent.accept_packages_named(CLIENT_AGENT_TYPE.to_string());
        let declared = agent.next_report().capabilities;
        assert_eq!(
            declared,
            (AGENT_CAPABILITIES
                | AgentCapabilities::AcceptsPackages as u64
                | AgentCapabilities::ReportsPackageStatuses as u64)
                & !(AgentCapabilities::AcceptsRemoteConfig as u64
                    | AgentCapabilities::ReportsRemoteConfig as u64),
            "only the two remote-configuration bits are withdrawn"
        );
        assert_ne!(
            declared & AgentCapabilities::ReportsEffectiveConfig as u64,
            0
        );
        assert_eq!(
            declared & AgentCapabilities::AcceptsRestartCommand as u64,
            0,
            "the Client's own Agent has no process to restart"
        );
    }

    /// A set offered anyway is not stored, not handed to the Supervisor-set apply, and not
    /// answered (ADR-0017 clause 43).
    /// Verifies: ADR-0017
    #[test]
    fn a_set_offered_anyway_to_a_host_that_keeps_it_is_neither_stored_nor_applied_nor_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = own_agent_of_a_host_that_keeps_its_set(dir.path());
        agent.next_report();
        let handled = agent.handle(&ServerToAgent {
            remote_config: Some(remote_config(
                b"[[supervisor]]\ntype = \"command\"\nname = \"x\"\ncommand = \"x\"\n",
                b"set-1",
            )),
            ..Default::default()
        });
        assert!(
            !handled.send_report,
            "nothing changed that the Server must hear"
        );
        assert!(
            agent.take_pending_apply().is_none(),
            "the set would be applied"
        );
        assert!(!dir.path().join("remote-config.pb").exists());
        assert!(
            !dir.path().join("config").exists(),
            "an entry copy was written"
        );
        assert!(agent.next_report().remote_config_status.is_none());
        agent.force_full();
        assert!(agent.next_report().remote_config_status.is_none());
    }

    /// The warning about an ignored set is said once per hash and names the key that keeps the
    /// set on the host (ADR-0017 clause 43).
    /// Verifies: ADR-0017
    #[test]
    fn a_set_ignored_by_a_host_that_keeps_it_is_logged_once_per_hash() {
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();

        let dir = tempfile::tempdir().expect("tempdir");
        let mut agent = own_agent_of_a_host_that_keeps_its_set(dir.path());
        tracing::subscriber::with_default(subscriber, || {
            for hash in [b"aaaa", b"aaaa", b"bbbb", b"bbbb", b"aaaa"] {
                agent.handle(&ServerToAgent {
                    remote_config: Some(remote_config(b"[[supervisor]]\n", hash)),
                    ..Default::default()
                });
            }
        });
        let log = String::from_utf8(captured.0.lock().expect("lock").clone()).expect("utf-8");
        let ignored: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("ignoring a supervisor set"))
            .collect();
        assert_eq!(ignored.len(), 2, "{log}");
        assert!(ignored[0].contains(&hex::encode(b"aaaa")), "{log}");
        assert!(ignored[1].contains(&hex::encode(b"bbbb")), "{log}");
        assert!(
            ignored
                .iter()
                .all(|line| line.contains("server_manages_set = false")),
            "{log}"
        );

        // Bounded however many distinct hashes arrive: full, the next new one starts over.
        let mut agent = own_agent_of_a_host_that_keeps_its_set(dir.path());
        let offer = |agent: &mut AgentState, n: usize| {
            agent.handle(&ServerToAgent {
                remote_config: Some(remote_config(b"[[supervisor]]\n", &n.to_be_bytes())),
                ..Default::default()
            });
            agent.ignored_configs.as_ref().expect("kept").len()
        };
        for n in 0..super::IGNORED_CONFIGS_CAP {
            assert_eq!(offer(&mut agent, n), n + 1);
        }
        assert_eq!(
            offer(&mut agent, 0),
            super::IGNORED_CONFIGS_CAP,
            "a seen hash adds nothing"
        );
        assert_eq!(
            offer(&mut agent, super::IGNORED_CONFIGS_CAP),
            1,
            "the hash past the bound starts over"
        );
    }
}
