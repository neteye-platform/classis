//! The Managed-Process-facing Port (ADR-0017): the boundary the supervision domain defines and
//! depends on. A Plugin is an adapter behind it — a factory that validates its block's settings
//! and starts a task driving one Managed Process.
//!
//! The Port is a message pair, not a trait with async methods: commands flow to the adapter,
//! events flow back. That keeps the [`Plugin`] trait object-safe without an `async-trait`
//! dependency, makes every adapter a plain tokio task, and keeps the domain core free of
//! process handles.

use std::path::PathBuf;
use std::time::Duration;

use opamp::proto::{
    AgentDescription, AgentRemoteConfig, AvailableComponents, ComponentHealth, EffectiveConfig,
};
use opamp::uid::InstanceUid;
use tokio::sync::mpsc;

use crate::shutdown::Shutdown;

/// What the supervision core asks of a Managed Process.
#[derive(Debug)]
pub enum ProcessCommand {
    /// A remote configuration was received and persisted — the entry files are already written
    /// to the adapter's [`config_dir`](SupervisorContext::config_dir). Apply it, which for a
    /// process means restarting on the new files, and answer with
    /// [`ProcessEvent::ConfigApplied`].
    ApplyConfig {
        config: AgentRemoteConfig,
        /// The span of the apply this command is one half of (ADR-0016). The core opens it when the
        /// configuration is handed over and the adapter's phases hang off it, so one trace covers
        /// the restart and its health gate rather than ending where the message does.
        span: tracing::Span,
    },
    /// A package was downloaded and verified (content hash and signature; ADR-0026): swap its
    /// bytes over the Managed Process's binary, restart, and health-gate exactly as `ApplyConfig`
    /// does — a binary that will not stay up is rolled back to the previous one. Answered with
    /// [`ProcessEvent::PackageApplied`]. `staged` is the path of the verified artifact — a file,
    /// not its bytes, since a program is too big to carry through the core; `hash` is the package
    /// hash the status refers to; `version` is what the Agent then reports it has.
    ApplyPackage {
        staged: PathBuf,
        version: String,
        hash: Vec<u8>,
        /// The span of the install (ADR-0016), opened where the download started. Carried rather
        /// than reopened here: staging, preflight, swap, gate and rollback happen in the adapter's
        /// task, and a trace that ended at the hand-over would stop one phase before the failures
        /// worth tracing.
        span: tracing::Span,
    },
    /// The Server commanded a restart (`AcceptsRestartCommand`): stop and respawn on the
    /// *current* files. No configuration changed, so no [`ProcessEvent::ConfigApplied`] follows —
    /// the health events of the stop/spawn cycle are the visible outcome.
    Restart,
    /// Stop the Managed Process gracefully.
    Shutdown,
    /// The Supervisor is retired for good (ADR-0017): stop the Managed Process, undo whatever
    /// installing it left *outside* the Supervisor's directory — the generic implementation has
    /// nothing there, so its uninstall is exactly the graceful stop — answer with
    /// [`ProcessEvent::Uninstalled`], and exit. The directory itself is the core's to purge
    /// (ADR-0017), after the answer.
    Uninstall,
}

/// What a Managed-Process adapter reports back to the core.
#[derive(Debug)]
pub enum ProcessEvent {
    /// The process's own description (reported through the Supervisor Endpoint), folded into
    /// the Agent's — its identity (`service.instance.id`) stays the Supervisor's.
    Description(AgentDescription),
    /// The pid of the running Managed Process, or `None` once it is gone (ADR-0016). It is what
    /// lets this Client sample the process's own CPU and memory from the outside, which is the
    /// only honest reading of "own telemetry" for a process whose configuration it must not touch
    /// (ADR-0017).
    Pid(Option<u32>),
    /// Health — derived from the outside (spawned, exited, spawn failed) or self-reported.
    Health(ComponentHealth),
    /// The process's self-reported effective configuration; replaces the written-files echo.
    EffectiveConfig(EffectiveConfig),
    /// The process's available components (reported through the Supervisor Endpoint by the
    /// Collector's `opampextension`), relayed upstream under the owning Agent.
    AvailableComponents(AvailableComponents),
    /// Outcome of an [`ProcessCommand::ApplyConfig`]: `Ok` acknowledges `APPLIED`, `Err`
    /// reports `FAILED` with the error — a rejected configuration is a report, not a silence.
    ConfigApplied {
        hash: Vec<u8>,
        result: Result<(), String>,
    },
    /// Outcome of an [`ProcessCommand::ApplyPackage`]: `Ok(version)` reports `Installed` at that
    /// version, `Err` reports `InstallFailed` with the error after rolling back (ADR-0026).
    PackageApplied {
        hash: Vec<u8>,
        result: Result<String, String>,
    },
    /// Outcome of a [`ProcessCommand::Uninstall`] (ADR-0017), the adapter's last event. The
    /// Agent's goodbye carries no status, so the outcome is a log line — but an `Err` names what
    /// the retired kind could not undo, which the operator otherwise learns from nothing.
    Uninstalled { result: Result<(), String> },
}

/// The adapter's way back into the core: events tagged with the owning Agent's index on the
/// shared channel the [`Engine`](crate::engine::Engine) drains.
#[derive(Debug, Clone)]
pub struct EventSender {
    index: usize,
    tx: mpsc::Sender<(usize, ProcessEvent)>,
}

impl EventSender {
    #[must_use]
    pub fn new(index: usize, tx: mpsc::Sender<(usize, ProcessEvent)>) -> Self {
        EventSender { index, tx }
    }

    /// Sends one event; a closed channel means the Engine is gone and the event is moot.
    pub async fn send(&self, event: ProcessEvent) {
        let _ = self.tx.send((self.index, event)).await;
    }
}

/// What a package replaces on disk.
///
/// The two shapes share their whole lifecycle — set the old one aside, install the new one, prove
/// it starts, put the old one back if it does not — and differ only in what "it" is. Keeping that
/// difference in this type rather than inside the process adapter's swap is what lets the health
/// gate and the rollback stay one piece of code for both (ADR-0026). How each shape is set aside,
/// installed and put back is the adapter's, in [`process`](super::process).
#[derive(Debug, Clone)]
pub enum InstallTarget {
    /// One file: the artifact is the program, or holds it as its single named member.
    Binary(PathBuf),
    /// A whole directory tree, unpacked beside the running one and swapped by renaming
    /// directories — the same move the single-file case makes, one level up.
    Tree {
        /// This Supervisor's `program/` directory, which holds the live tree and the rolled-back
        /// one under fixed names.
        root: PathBuf,
        /// Where the program sits inside the tree, as written in the configuration.
        program_path: PathBuf,
    },
}

/// The package this Supervisor's Managed Process currently runs (ADR-0026), persisted so a
/// restarted Client reports the version it has and is not re-offered it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub hash_hex: String,
}

/// The highest package version this Client has installed for each Agent type — its **high-water
/// mark** (ADR-0043 clause 8). Shared by every Supervisor of the Client and kept where no purge of
/// a Supervisor's directory reaches it. The filesystem adapter is
/// [`HighWaterFile`](crate::storage::HighWaterFile).
pub trait HighWaterMarks: Send + Sync {
    /// The mark of `agent_type`: `Ok(None)` when this Client has installed nothing of the type,
    /// and `Err` with a reason naming the file when the marks cannot be read — which refuses every
    /// Supervisor package (ADR-0043 clause 11).
    ///
    /// # Errors
    /// Returns the reason the marks cannot be read.
    fn mark(&self, agent_type: &str) -> Result<Option<String>, String>;

    /// Raises the mark of `agent_type` to `version` when that is SemVer and greater; never lowers
    /// it. A write that fails is logged, and the raised mark is kept in memory.
    fn raise(&self, agent_type: &str, version: &str);
}

/// What an Agent persists across restarts (ADR-0006): its identity, the remote configuration it
/// last applied, and the package its Managed Process runs (ADR-0026). The filesystem adapter is
/// [`Storage`](crate::storage::Storage).
pub trait AgentStorage: Send + Sync {
    /// The persisted `instance_uid`, or a new one, persisted, when there is none.
    ///
    /// # Errors
    /// Returns an error when the identity cannot be read or written.
    fn load_or_create_uid(&self) -> std::io::Result<InstanceUid>;

    /// Persists a reassigned `instance_uid` (`RequestInstanceUid`).
    ///
    /// # Errors
    /// Returns an error when the identity cannot be written.
    fn save_uid(&self, uid: &InstanceUid) -> std::io::Result<()>;

    /// The remote configuration last applied, if any.
    fn load_remote_config(&self) -> Option<AgentRemoteConfig>;

    /// Persists an applied remote configuration, with one entry file per config-map entry.
    ///
    /// # Errors
    /// Returns an error when the configuration cannot be written.
    fn store_remote_config(&self, config: &AgentRemoteConfig) -> std::io::Result<()>;

    /// The package the Managed Process runs, if one was installed.
    fn load_package(&self) -> Option<InstalledPackage>;

    /// Persists the package the Managed Process now runs.
    ///
    /// # Errors
    /// Returns an error when the record cannot be written.
    fn store_package(&self, package: &InstalledPackage) -> std::io::Result<()>;

    /// Forgets the installed package.
    ///
    /// # Errors
    /// Returns an error when the record cannot be removed.
    fn forget_package(&self) -> std::io::Result<()>;
}

/// What the operating system says about itself — the Baseline's `os.*`. Read **once** per process
/// and as one answer: two of the three platforms have to be asked by running a program, and asking
/// them once per attribute would start three processes to learn what one printout already holds.
/// A field the platform does not answer stays `None` and is then not reported at all.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OsInfo {
    /// `os.description` — the human-readable line: "Ubuntu 24.04.2 LTS".
    pub description: Option<String>,
    /// `os.name` — the system's own name, without a version: "Ubuntu", "macOS", "Windows".
    pub name: Option<String>,
    /// `os.version` — the version that name is at: "24.04", "15.5", "10.0.26100.2033".
    pub version: Option<String>,
    /// `os.build_id` — the build behind that version, where the platform stamps one: os-release's
    /// `BUILD_ID`, `sw_vers`' BuildVersion ("24F74"), the build components of Windows' version
    /// line ("26100.2033").
    pub build_id: Option<String>,
}

/// What the host says about itself — the Baseline's `os.*` and `host.*` (ADR-0016) — and the
/// time by its clock. Each fact is best effort: what the platform cannot answer is `None` and is
/// then not reported at all. The platform adapter is [`SystemHost`](crate::host::SystemHost).
pub trait HostFacts: Send + Sync {
    /// The operating system's own description of itself.
    fn os(&self) -> &OsInfo;
    /// `host.name`.
    fn host_name(&self) -> Option<&str>;
    /// `host.id` — what still names the machine after it has been renamed.
    fn host_id(&self) -> Option<&str>;
    /// `host.cpu.model.name`.
    fn cpu_model(&self) -> Option<&str>;
    /// `host.ip` and `host.mac`, excluding loopback, read live so a DHCP move is reported.
    fn addresses(&self) -> (Vec<String>, Vec<String>);
    /// The host's wall clock, in nanoseconds since the Unix epoch — what OpAMP's
    /// `*_time_unix_nano` fields carry.
    fn now_ns(&self) -> u64;
    /// The id of this process on the host.
    fn process_id(&self) -> u32;
}

/// Everything a plugin needs to start its adapter task.
pub struct SupervisorContext {
    /// The Supervisor's name (the TOML `name`; the Agent's `service.name`).
    pub name: String,
    /// What the Supervisor Endpoint asks the Managed Process to present (ADR-0015); handed to the
    /// process as [`ENDPOINT_TOKEN_ENV`](crate::supervisor::process::ENDPOINT_TOKEN_ENV).
    pub endpoint_token: String,
    /// Everything this Supervisor owns: its state, its `program/`, its package staging
    /// (ADR-0017). Placed by `supervisor_dir`, so nothing may assume where it is.
    pub supervisor_dir: PathBuf,
    /// Where the received remote configuration's entry files are written — what the Managed
    /// Process is pointed at.
    pub config_dir: PathBuf,
    /// The Managed Process itself, already resolved inside this Supervisor's own `program/`
    /// directory (ADR-0017). The plugin spawns this rather than reading its own
    /// `binary`/`command` key, so the path rule lives in one place instead of once per plugin.
    pub program: PathBuf,
    /// What an offered package replaces (ADR-0026) — resolved beside `program` and for
    /// the same reason: a plugin that decided this for itself could disagree with where the core
    /// put the program.
    pub install: InstallTarget,
    /// Graceful-stop budget before the Managed Process is killed.
    pub stop_timeout: Duration,
    /// How long a freshly (re)started process must survive before `ApplyConfig` is acknowledged
    /// `Ok` — the health-gated acknowledgement (ADR-0017). Zero acknowledges on start.
    pub apply_grace: Duration,
    /// How long the version a successful update supersedes is kept before deletion (ADR-0026),
    /// resolved from the per-Supervisor override or the global `[updates]` default. Zero deletes on
    /// success.
    pub retain_previous: Duration,
    /// The key that opens an encrypted `.7z` package artifact (ADR-0026); `None` when none is
    /// configured. Client-wide, like the package verification key.
    pub archive_key: Option<String>,
    /// The plugin-specific keys of the block, for the strict second-stage parse.
    pub settings: toml::Table,
    /// Where the adapter reports events.
    pub events: EventSender,
    /// The Client's shutdown signal; the adapter stops its process and exits when it fires.
    pub shutdown: Shutdown,
}

impl SupervisorContext {
    /// Expands the placeholders naming this Supervisor's own directories (ADR-0017):
    /// `${supervisor_dir}` and `${config_dir}`.
    ///
    /// They exist because a Custom Supervisor is told where its configuration is *through its own
    /// command line*, and an absolute path written there drifts the moment `supervisor_dir` moves
    /// or the Supervisor is renamed — silently, since the process then starts happily on a file
    /// nobody writes to.
    ///
    /// An unrecognized `${…}` is **left exactly as written**, neither refused nor emptied. A
    /// Foreign Agent's own configuration language may use the same syntax — Fluent Bit's does —
    /// and eating those to catch a typo would break a working deployment. What this substitutes
    /// is the two names below; everything else is the process's business.
    ///
    /// Never applied to the program itself: that key is a bare file name the core resolves inside
    /// this Supervisor's own `program/` directory (ADR-0017), so there is no directory in it for a
    /// placeholder to name.
    #[must_use]
    pub fn expand(&self, value: &str) -> String {
        value
            .replace("${supervisor_dir}", &self.supervisor_dir.to_string_lossy())
            .replace("${config_dir}", &self.config_dir.to_string_lossy())
    }
}

/// What a kind knows about its own agent, so a block does not have to say it (ADR-0017).
///
/// Every field is a `&'static str` resolved **per platform** at compile time, which is the point:
/// a constant can be asserted against the artifact this project packs, where a path written in a
/// manual can only be believed. A kind that knows nothing — `collector`, `command` — returns
/// [`KindDefaults::none`] and its blocks keep saying what they always said.
///
/// A value supplied here is not a default the block may override. It is the answer, and a block
/// naming the key is refused: two sources of truth for a value this Client computes is how a host
/// quietly differs from what the fleet believes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindDefaults {
    /// The program's file name in this Supervisor's own `program/` directory (ADR-0017).
    /// `None` leaves it to the block's program key.
    pub program: Option<&'static str>,
    /// Where the program sits inside an unpacked package tree (ADR-0026); `None` is a single-file
    /// package, or a kind that leaves the question to the block.
    pub program_path: Option<&'static str>,
    /// The Agent *type* this kind presents (ADR-0016). `None` falls back to the program's file
    /// name, which is what the block already said.
    pub service_name: Option<&'static str>,
    /// What this kind corrects about the fleet's timing policy, and whether its block may state
    /// any of it at all (ADR-0017). `None` — an unwrapped kind — leaves the three keys in the
    /// block, because no kind exists there to hold a value; `Some` takes them out of the block and
    /// states the kind's own corrections, each `None` meaning "the fleet's number is right".
    pub timing: Option<KindTiming>,
    /// Whether a block of this kind may pin the Supervisor Endpoint's port. The Endpoint is bound
    /// for every Supervisor (ADR-0015); pinning it only means something where a Managed Process
    /// connects to it, which in practice is a Collector carrying the `opampextension`.
    pub endpoint_port: bool,
}

/// What a wrapped kind says about timing, over the fleet's own policy (ADR-0017).
///
/// Every field is an *agent's* property rather than a host's: how long it needs to shut down, how
/// long a restart of it has to hold before the fleet may believe it, how long its superseded
/// version is worth keeping. A kind that has nothing to correct states three `None`s and still
/// takes the keys out of its block — the value is the fleet's, and there is no host-level answer
/// to a question about an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KindTiming {
    /// Overrides `[supervisors] stop_timeout_secs`.
    pub stop_timeout: Option<Duration>,
    /// Overrides `[supervisors] apply_grace_secs`.
    pub apply_grace: Option<Duration>,
    /// Overrides `[updates] retain_previous_secs` (ADR-0026).
    pub retain_previous: Option<Duration>,
}

impl KindDefaults {
    /// A kind that knows nothing about its agent: the block says everything, as it always has.
    #[must_use]
    pub const fn none() -> Self {
        KindDefaults {
            program: None,
            program_path: None,
            service_name: None,
            timing: None,
            endpoint_port: false,
        }
    }
}

/// A compiled-in Supervisor Plugin (ADR-0017): the adapter factory on the Managed-Process side.
/// A new process kind is a new implementation and one line in
/// [`registry`](crate::supervisor::registry).
pub trait Plugin {
    /// The TOML `type` value this plugin serves.
    fn kind(&self) -> &'static str;

    /// What this kind knows about its agent, so a block need not repeat it (ADR-0017). Stated by
    /// every plugin rather than defaulted, because "this kind knows nothing" is an answer worth
    /// writing down where a reader of the plugin will see it.
    fn defaults(&self) -> KindDefaults;

    /// The block key naming this plugin's Managed Process — `binary` for a Collector, `command`
    /// for the example Custom Supervisor. The core takes that key out of the settings, applies
    /// ADR-0017's path rule to it, and hands the result back as
    /// [`SupervisorContext::program`]; the plugin never sees the raw value.
    fn program_key(&self) -> &'static str;

    /// Validate the settings and start the adapter task, returning the command side of the Port.
    ///
    /// # Errors
    /// Returns an error when the settings do not parse — startup fails loudly, nothing spawns.
    fn start(&self, ctx: SupervisorContext) -> Result<mpsc::Sender<ProcessCommand>, String>;

    /// The strict settings parse [`start`](Self::start) performs, without the side effects
    /// (ADR-0017): what validates an offered Supervisor set *before* any running process is
    /// touched. `settings` is the block's table with the program key already taken out, exactly
    /// as `start` receives it.
    ///
    /// # Errors
    /// Returns an error when the settings do not parse.
    fn check(&self, name: &str, settings: toml::Table) -> Result<(), String>;

    /// What a Server-delivered block of this kind may not say beyond the generic rule on `env` and
    /// `args` (ADR-0017 clause 39): a kind whose settings name files the Supervisor reads confines
    /// them here. `running` is the settings of the running block of the same name, if any. By
    /// default a kind names no such file.
    ///
    /// # Errors
    /// Returns the reason the delivered block is refused.
    fn check_delivered(
        &self,
        _settings: &toml::Table,
        _running: Option<&toml::Table>,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// The strict second-stage parse of a block's plugin settings, shared by every plugin's
/// [`start`](Plugin::start) and [`check`](Plugin::check) so the two cannot disagree (ADR-0017).
///
/// A key the kind has `retired` is refused by name first, with what answers it now — a block
/// carrying one was written against a Client that needed it, and the operator deleting the line
/// deserves to be told where the value went rather than meet serde's "unknown field".
///
/// # Errors
/// Returns an error naming the block when a retired key is present or the settings do not parse.
pub fn parse_settings<T: serde::de::DeserializeOwned>(
    name: &str,
    kind: &str,
    retired: &[(&str, &str)],
    settings: toml::Table,
) -> Result<T, String> {
    for (key, answer) in retired {
        if settings.contains_key(*key) {
            return Err(format!(
                "supervisor {name:?}: `{key}` is no longer a supervisor key for type {kind:?} \
                 — {answer}; remove the line"
            ));
        }
    }
    settings
        .try_into()
        .map_err(|e| format!("supervisor {name:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::shutdown_channel;

    /// A per-Supervisor root that is absolute on *this* platform — on Windows that means naming a
    /// drive (ADR-0017), and it is why nothing below spells a path out with POSIX separators: what
    /// a placeholder expands to is a `PathBuf`, so its separators are the platform's own.
    #[cfg(windows)]
    fn root(place: &str) -> PathBuf {
        PathBuf::from(format!("C:\\{place}\\supervisors\\fluent-bit"))
    }

    #[cfg(not(windows))]
    fn root(place: &str) -> PathBuf {
        PathBuf::from(format!("/{place}/supervisors/fluent-bit"))
    }

    fn context(supervisor_dir: PathBuf) -> SupervisorContext {
        let (_tx, shutdown) = shutdown_channel();
        let (event_tx, _events) = mpsc::channel(1);
        SupervisorContext {
            endpoint_token: String::new(),
            name: "fluent-bit".to_string(),
            config_dir: supervisor_dir.join("config"),
            supervisor_dir,
            program: PathBuf::from("/opt/fluent-bit/bin/fluent-bit"),
            install: crate::supervisor::ports::InstallTarget::Binary(PathBuf::from(
                "/opt/fluent-bit/bin/fluent-bit",
            )),
            stop_timeout: Duration::from_secs(1),
            apply_grace: Duration::from_secs(0),
            retain_previous: Duration::from_secs(0),
            archive_key: None,
            settings: toml::Table::new(),
            events: EventSender::new(0, event_tx),
            shutdown,
        }
    }

    /// The case ADR-0017 exists for: the argument that points a Foreign Agent at its configuration
    /// is derived from the same value the Client derives it from, so relocating `supervisor_dir`
    /// cannot leave the process reading a file nobody writes to.
    #[test]
    fn the_placeholders_name_this_supervisors_own_directories() {
        let ctx = context(root("opt"));
        // The placeholder becomes the directory the Client itself writes to; what the operator
        // wrote after it is a string and survives verbatim, separator included.
        assert_eq!(
            ctx.expand("${config_dir}/fluent-bit-conf"),
            format!("{}/fluent-bit-conf", ctx.config_dir.display())
        );
        // Two different directories, and the configuration's is the one inside.
        let supervisor = ctx.expand("${supervisor_dir}");
        let config = ctx.expand("${config_dir}");
        assert_ne!(supervisor, config);
        assert!(
            config.starts_with(&supervisor),
            "{config} must sit inside {supervisor}"
        );
        // Relocating the root moves the expansion with it — that is the whole point.
        let moved = context(root("var"));
        assert_ne!(
            moved.expand("${config_dir}/x"),
            ctx.expand("${config_dir}/x")
        );
        assert!(
            moved
                .expand("${config_dir}/x")
                .starts_with(&moved.supervisor_dir.display().to_string()),
            "the expansion follows the relocated root"
        );
    }

    /// Anything else is left exactly as written. Fluent Bit's own configuration language uses
    /// `${…}` too, and a Client that ate or refused those would break a working deployment to
    /// catch a typo — which is the trade ADR-0017 makes, deliberately and in this direction.
    #[test]
    fn an_unknown_placeholder_is_passed_through_untouched() {
        let ctx = context(root("opt"));
        for verbatim in [
            "${FLB_LOG_LEVEL}",
            "${config-dir}", // a typo: passed on, not refused
            "-c",
            "",
            "$config_dir",
            "${}",
        ] {
            assert_eq!(
                ctx.expand(verbatim),
                verbatim,
                "must pass through untouched"
            );
        }
        // And a known placeholder still expands when it sits beside an unknown one.
        assert_eq!(
            ctx.expand("${config_dir}/${FLB_ENV}.conf"),
            format!("{}/${{FLB_ENV}}.conf", ctx.config_dir.display())
        );
    }
}
