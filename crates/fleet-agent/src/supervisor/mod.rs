//! The supervision domain (ADR-0017): builds the Agents the [`Engine`](crate::engine) carries.
//!
//! With `[[supervisor]]` blocks configured, each becomes one Supervisor-backed Agent — everything
//! it owns under `<supervisor_dir>/<name>/` (ADR-0017), its Managed Process driven by the plugin
//! the block's `type` selects. Without any, the Client presents itself as the single self-Agent —
//! the same state machine with no Managed Process behind it.

pub mod agent;
pub mod block;
pub mod collector;
pub mod command;
pub mod delivered;
pub mod endpoint;
pub mod ports;
pub mod process;
pub mod restart;

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::config::{ClientConfig, SupervisorBlock};
use crate::engine::{Engine, EngineAgent};
use crate::shutdown::{shutdown_channel, Shutdown};
use crate::storage::{DroppedRemoteConfig, DroppedStoredSet, HighWaterFile, Storage};

use agent::AgentState;
use block::{find_plugin, resolve, take_program, Resolved};
use ports::{EventSender, HighWaterMarks, Plugin, ProcessEvent, SupervisorContext};

pub use crate::engine::SELF_AGENT_INDEX;

/// What a Supervisor's block position must be shifted by to reach its Engine index — and, read
/// the other way, what an Engine index is shifted back by to find the block it came from.
pub const SELF_AGENT_OFFSET: usize = SELF_AGENT_INDEX + 1;

/// The compiled-in plugin registry (ADR-0017 clause 2). A new process kind is a new module and one
/// line here — the supervision core stays untouched (goal 8). A wrapped kind is there only when
/// its feature is, so what a build carries, reports (clause 18) and refuses as unknown all follow
/// from this one list.
fn registry() -> Vec<Box<dyn Plugin>> {
    vec![
        Box::new(collector::CollectorPlugin),
        Box::new(command::CommandPlugin),
    ]
}

/// The kinds this Client was compiled with, as attributes of its own Agent (ADR-0017 clause 18).
///
/// A `type` is something a Client either carries or does not, and a Server rolling a `glpi` set at
/// a Client without that plugin should learn it by not aiming there rather than from a `FAILED`
/// afterwards.
///
/// **One key per kind**, not one list, because of how matching works here: a Selector is equality
/// over string values (`configs.rs::matches`), so a list could only be matched by spelling the
/// whole list — and the question one wants to ask is about *one member* of it. `AvailableComponents`
/// is the Baseline's own home for this and is deliberately not used yet: it is marked *Development*
/// in the schema this project pins, and Selectors resolve over the description, so reporting kinds
/// there would tell the fleet something it could not act on.
///
/// An operator's own attribute of the same name is left alone — configured values are the host's
/// statement about itself, and this function only fills in what nothing else said.
fn kind_attributes(mut attributes: BTreeMap<String, String>) -> BTreeMap<String, String> {
    for plugin in registry() {
        attributes
            .entry(format!("supervisor.kind.{}", plugin.kind()))
            .or_insert_with(|| "true".to_string());
    }
    attributes
}

/// Build the Engine from the configuration, starting one adapter task per Supervisor.
///
/// # Errors
/// Returns an error when an Agent's state cannot be restored, a `[[supervisor]]` block names an
/// unknown plugin, or a plugin rejects its settings — startup fails loudly, nothing runs half.
pub fn build_engine(config: &ClientConfig, shutdown: &Shutdown) -> Result<Engine, String> {
    report_orphaned_supervisor_dirs(config);
    for notice in remote_config_disabled_notices(config) {
        warn!("{notice}");
    }
    let (event_tx, events) = mpsc::channel(64);
    let mut agents = Vec::with_capacity(config.supervisors.len() + 1);

    // The Client is always its own Agent (ADR-0018), whether or not it supervises anything:
    // otherwise it would be invisible on exactly the hosts that manage something, and the Server
    // would have nobody to offer the Client's own package to. It is index 0 so the Supervisors that
    // follow keep a stable, obvious offset.
    let storage = Storage::new(config.state_dir.clone())
        .map_err(|e| format!("cannot prepare {}: {e}", config.state_dir.display()))?;
    // A host that keeps its Supervisor set takes none from the Server, and the set stored from
    // before leaves rather than be reported as applied (ADR-0017 clauses 42 and 44).
    let self_state = if config.server_manages_set() {
        AgentState::new(config.name.clone(), storage, crate::host::SystemHost)
    } else {
        drop_stored_supervisor_set(&storage);
        AgentState::new_without_remote_config(config.name.clone(), storage, crate::host::SystemHost)
    };
    let mut self_state = declare_heartbeat(
        config,
        self_state
            .map_err(|e| format!("cannot restore the agent state: {e}"))?
            .with_attributes(kind_attributes(config.agent_attributes(None)))
            .with_namespace(config.service_namespace.clone()),
    );
    // Consenting to be updated takes one package, the one named after this Client's Agent type —
    // anything else is refused rather than written over this binary (ADR-0018). The consent stands
    // unless `[packages] self_update = false` withdraws it, so this is the ordinary path rather
    // than the opted-into one. And only from a signed package: without a verification key the
    // consent is kept, but nothing is declared — the startup notice names the key.
    if let (Some(package), Some(_)) = (config.self_update_package(), config.package_key()) {
        self_state.accept_packages_named(package.to_string());
    }
    // The self-Agent's effective configuration is its own file — `supervisor.toml` is what this
    // Client runs (a file that fails to load fails startup), so the fleet view can finally answer
    // it. The text was redacted at load; without it, echoing a stored offer would say nothing
    // about this Client. No file means the defaults run, and there is nothing truthful to show.
    if let Some(source) = &config.source {
        self_state.set_process_effective_config(opamp::proto::EffectiveConfig {
            config_map: Some(opamp::proto::AgentConfigMap {
                config_map: std::collections::HashMap::from([(
                    "supervisor.toml".to_string(),
                    opamp::proto::AgentConfigObject {
                        role: String::new(),
                        body: source.clone().into_bytes(),
                        content_type: String::new(),
                    },
                )]),
            }),
        });
    }
    agents.push(EngineAgent {
        state: self_state,
        commands: None,
        stop: None,
        block_name: None,
    });

    // One set of high-water marks for every Supervisor this Client runs, now and after a
    // Supervisor-set apply adds one (ADR-0043 clause 8). Read afresh at every start, and seeded
    // from each Supervisor's installed record as it starts (clause 9).
    let marks: Arc<dyn HighWaterMarks> = Arc::new(HighWaterFile::open(&config.state_dir));
    for (block_index, block) in config.supervisors.iter().enumerate() {
        // The event channel is keyed by position in `agents`, and the self-Agent holds 0.
        let index = block_index + SELF_AGENT_OFFSET;
        agents.push(start_supervisor(
            config, block, index, &event_tx, shutdown, &marks,
        )?);
    }
    let mut engine = Engine::with_processes(agents, events, event_tx);
    engine.set_high_water(marks);
    Ok(engine)
}

/// A directory under the Supervisor root that no `[[supervisor]]` block names is reported, never
/// reaped (ADR-0017): it may be a purge a crash or an error cut short — or an operator's
/// deliberate hand edit, a temporarily commented-out block whose identity and program are not the
/// Client's to delete. The log line makes the leftover visible; removing it stays the operator's
/// call.
fn report_orphaned_supervisor_dirs(config: &ClientConfig) {
    let root = config.supervisors_root();
    let Ok(entries) = std::fs::read_dir(&root) else {
        // No root yet — nothing was ever supervised here, so there is nothing to be orphaned.
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        if config
            .supervisors
            .iter()
            .any(|block| name == std::ffi::OsStr::new(&block.name))
        {
            continue;
        }
        warn!(
            path = %entry.path().display(),
            "no [[supervisor]] block names this directory; leaving it untouched — remove it by \
             hand if its supervisor is gone for good"
        );
    }
}

/// Heartbeats are a Client-wide choice: enabled (interval > 0) every Agent declares the
/// capability; disabled none does — an undeclared capability must never be exercised.
fn declare_heartbeat(config: &ClientConfig, mut state: AgentState) -> AgentState {
    if config.heartbeat_interval_secs > 0 {
        state.declare_capability(opamp::proto::AgentCapabilities::ReportsHeartbeat);
    }
    state
}

/// Validates one `[[supervisor]]` block exactly as [`start_supervisor`] would read it — plugin
/// known, program key present and well-shaped, plugin settings parsing strictly — without
/// touching the filesystem or starting anything (ADR-0017). What an offered Supervisor set is
/// checked against before any running process is stopped.
///
/// # Errors
/// Returns the same error `start_supervisor` would fail with, naming the block.
pub fn validate_block(config: &ClientConfig, block: &SupervisorBlock) -> Result<(), String> {
    let plugins = registry();
    let resolved = resolve(config, block, &plugins)?;
    resolved.plugin.check(&block.name, resolved.settings)
}

/// What a Server-delivered block may not bring (ADR-0017 clauses 38, 39; for a Supervisor whose
/// remote configuration is switched off, ADR-0017 clause 54), checked against `running` — the
/// configuration in force, whose `[supervisors]` section the Server cannot change and whose block
/// of the same name the delivered one may repeat.
///
/// # Errors
/// Returns the reason the delivered block is refused, naming the block and what it brings.
pub fn check_delivered_block(
    running: &ClientConfig,
    block: &SupervisorBlock,
) -> Result<(), String> {
    let root = running.supervisors_root();
    let roots = [
        root.to_string_lossy().into_owned(),
        crate::config_file::absolute(&root)
            .to_string_lossy()
            .into_owned(),
    ];
    delivered::check(running, block, &registry(), &roots)
}

/// The program a block resolves to, for callers that must inspect ownership rather than just
/// spawn it. The Supervisor-set apply uses it to keep a Server-delivered block to a Client-owned
/// program (ADR-0017).
pub fn resolve_block_program(
    config: &ClientConfig,
    block: &SupervisorBlock,
) -> Result<crate::config::Program, String> {
    let plugins = registry();
    let plugin = find_plugin(&plugins, block)?;
    let (_, program, _) = take_program(config, block, plugin)?;
    Ok(program)
}

/// Start one Supervisor at `index`: its state restored, its Endpoint bound, its adapter task
/// running. Used at startup for every configured block and at runtime for a block an applied
/// Supervisor set added or changed (ADR-0017).
///
/// # Errors
/// Returns an error when the block's state cannot be restored, its Endpoint port cannot be
/// bound, or its plugin rejects the settings.
pub fn start_supervisor(
    config: &ClientConfig,
    block: &SupervisorBlock,
    index: usize,
    event_tx: &mpsc::Sender<(usize, ProcessEvent)>,
    shutdown: &Shutdown,
    marks: &Arc<dyn HighWaterMarks>,
) -> Result<EngineAgent, String> {
    let plugins = registry();
    let Resolved {
        plugin,
        settings,
        program,
        program_path,
        service_name,
        timing,
    } = resolve(config, block, &plugins)?;

    let supervisor_dir = config.supervisor_dir(&block.name);
    let storage = Storage::new(supervisor_dir.clone())
        .map_err(|e| format!("cannot prepare {}: {e}", supervisor_dir.display()))?;
    let config_dir = storage.config_dir();

    // What a package replaces: one file, or — when the block says where the program sits
    // inside the package — the whole tree under this Supervisor's `program/` (ADR-0026).
    let install = match program_path {
        Some(program_path) => crate::supervisor::ports::InstallTarget::Tree {
            root: supervisor_dir.join(crate::config::PROGRAM_DIR),
            program_path,
        },
        None => crate::supervisor::ports::InstallTarget::Binary(program.path.clone()),
    };

    // Switched off, the Server's last configuration leaves before the kind starts, and what the
    // operator placed in `config/` stays (ADR-0017 clause 52).
    let remote_config = !config.remote_config_disabled(&block.name);
    if !remote_config {
        drop_stored_remote_config(&block.name, &storage)?;
    }
    let state = if remote_config {
        AgentState::supervised(
            block.name.clone(),
            service_name,
            storage,
            crate::host::SystemHost,
        )
    } else {
        AgentState::supervised_without_remote_config(
            block.name.clone(),
            service_name,
            storage,
            crate::host::SystemHost,
        )
    };
    let mut state = declare_heartbeat(
        config,
        state
            .map_err(|e| format!("cannot restore the state of {:?}: {e}", block.name))?
            .with_attributes(config.agent_attributes(Some(block)))
            .with_namespace(config.service_namespace.clone())
            .with_high_water(marks.clone()),
    );
    // Every Managed Process is the fleet's (ADR-0017), so every Supervisor takes whichever
    // top-level package the Server selects for it (ADR-0026). There is no second branch:
    // a block naming a program on the machine does not parse, so the consent is discharged by the
    // type system rather than by a rule. The log line says *where* the program is, which is the
    // thing an operator reading a startup log actually wants.
    //
    // What the target itself needs — for a tree that is its root and nothing below it, since the
    // live tree arrives by renaming a directory over that name (ADR-0026).
    install.prepare()?;
    // Only a Client holding the operator's verification key takes packages: there is no unsigned
    // posture (ADR-0026). Without it the program stays as installed, and the startup notice says
    // why.
    if config.package_key().is_some() {
        state.accept_packages();
        info!(
            supervisor = %block.name,
            program = %program.path.display(),
            "packages accepted: the program is this supervisor's own"
        );
    }

    // Each Supervisor stops on its own channel (ADR-0017): the Client-wide shutdown is forwarded
    // into it, and retiring the Supervisor fires it alone — its Endpoint releases the port and
    // its adapter stops the Managed Process while the rest of the Client runs on.
    let (stop_tx, stop) = shutdown_channel();
    forward_shutdown(shutdown.clone(), stop_tx.clone());

    // The Supervisor Endpoint is intrinsic to every Supervisor (ADR-0015): bound
    // unconditionally, before the process starts — a taken port fails startup, not later.
    // Only the Managed Process may report through it (ADR-0015): a token fresh for every start,
    // handed to the process in its environment and asked of every connection.
    let endpoint_token = endpoint::new_token()?;
    endpoint::start(
        block.name.clone(),
        block.endpoint_port,
        EventSender::new(index, event_tx.clone()),
        stop.clone(),
        config.max_message_size_bytes,
        endpoint_token.clone(),
    )?;

    let commands = plugin.start(SupervisorContext {
        endpoint_token,
        name: block.name.clone(),
        supervisor_dir,
        config_dir,
        program: program.path,
        install,
        stop_timeout: timing.stop_timeout,
        apply_grace: timing.apply_grace,
        retain_previous: timing.retain_previous,
        archive_key: config.packages.as_ref().and_then(|p| p.archive_key.clone()),
        settings,
        events: EventSender::new(index, event_tx.clone()),
        shutdown: stop,
    })?;
    Ok(EngineAgent {
        state,
        commands: Some(commands),
        stop: Some(stop_tx),
        block_name: Some(block.name.clone()),
    })
}

/// Removes what a remote configuration stored for the Supervisor `name` before its remote
/// configuration was switched off, and says what it did (ADR-0017 clause 52).
///
/// # Errors
/// Returns an error when a file that has to go cannot be deleted — the Supervisor must not start
/// on the Server's configuration under a switch that says it does not.
fn drop_stored_remote_config(name: &str, storage: &Storage) -> Result<(), String> {
    match storage.drop_remote_config().map_err(|e| {
        format!("supervisor {name:?}: cannot remove the stored remote configuration: {e}")
    })? {
        None => {}
        Some(DroppedRemoteConfig::Removed { hash, kept }) => warn!(
            supervisor = %name,
            hash = %hex::encode(hash),
            kept = ?kept,
            "remote configuration is switched off: removed the stored remote configuration and \
             the files it wrote; kept the files whose content had changed"
        ),
        Some(DroppedRemoteConfig::Undecodable) => warn!(
            supervisor = %name,
            "remote configuration is switched off: removed a stored remote configuration that \
             does not decode; config/ is left as it is and may still hold files the Server wrote"
        ),
    }
    Ok(())
}

/// Removes the Supervisor set the Client's own Agent stored before the host kept its set, and says
/// what it did (ADR-0017 clause 44). Nothing runs on those files — the set is already in
/// `supervisor.toml` — so a file that cannot go is a warning, not a reason to stay offline.
fn drop_stored_supervisor_set(storage: &Storage) {
    match storage.drop_stored_set() {
        Ok(None) => {}
        Ok(Some(DroppedStoredSet::Removed {
            hash,
            kept,
            unremoved,
        })) => {
            warn!(
                hash = %hex::encode(hash),
                kept = ?kept,
                "the Server does not manage this Client's supervisor set: removed the stored \
                 supervisor set; the [[supervisor]] blocks in supervisor.toml stay as they are"
            );
            for (file, error) in unremoved {
                warn!(
                    file = %file,
                    error = %error,
                    "cannot remove a copy of the stored supervisor set; nothing reads it"
                );
            }
        }
        Ok(Some(DroppedStoredSet::Undecodable)) => warn!(
            "the Server does not manage this Client's supervisor set: removed a stored supervisor \
             set that does not decode"
        ),
        Err(e) => warn!(
            error = %e,
            "the Server does not manage this Client's supervisor set, and remote-config.pb cannot \
             be removed; it is not reported now, but its hash would be reported as applied again \
             once server_manages_set is true"
        ),
    }
}

/// The startup notices `[supervisors] remote_config_disabled` earns (ADR-0017 clause 49): a listed
/// name no `[[supervisor]]` block carries, since the set may arrive later, and one that is the
/// Client's own name, whose Agent the switch does not cover.
#[must_use]
pub fn remote_config_disabled_notices(config: &ClientConfig) -> Vec<String> {
    config
        .supervisor_defaults
        .remote_config_disabled
        .iter()
        .filter(|name| config.supervisors.iter().all(|block| &block.name != *name))
        .map(|name| {
            if *name == config.name {
                if config.server_manages_set() {
                    format!(
                        "[supervisors] remote_config_disabled names {name:?}, which is this \
                         Client's own name: the Client's own Agent is not covered and keeps \
                         taking its supervisor set; [supervisors] server_manages_set = false \
                         stops that"
                    )
                } else {
                    format!(
                        "[supervisors] remote_config_disabled names {name:?}, which is this \
                         Client's own name: the Client's own Agent is not covered by this key; \
                         server_manages_set = false already keeps its supervisor set on the host"
                    )
                }
            } else {
                format!(
                    "[supervisors] remote_config_disabled names {name:?}, which no \
                     [[supervisor]] block carries yet; it takes effect when one does"
                )
            }
        })
        .collect()
}

/// Forwards the Client-wide shutdown into one Supervisor's own channel, so its adapter and
/// Endpoint stop on whichever fires first — the operator stopping the Client, or the Supervisor
/// being retired (ADR-0017).
fn forward_shutdown(mut global: Shutdown, stop_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        global.requested().await;
        let _ = stop_tx.send(true);
    });
}

#[cfg(test)]
mod tests {
    use super::block::{check_endpoint_port, effective_service_name, effective_timing};
    use super::*;
    use crate::shutdown::shutdown_channel;
    use opamp::proto::AgentCapabilities;
    use std::path::PathBuf;
    use std::time::Duration;

    fn config(root: &std::path::Path, program: &str, supervisor_dir: Option<PathBuf>) -> String {
        format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n{moved}\n\
             [[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = {program:?}\n",
            state = root.join("state").to_string_lossy(),
            moved = supervisor_dir
                .map(|d| format!("supervisor_dir = {:?}\n", d.to_string_lossy()))
                .unwrap_or_default(),
        )
    }

    /// A configuration as `ClientConfig::load` leaves it when `[packages] verification_key` is set:
    /// the decoded key is what decides whether anything takes packages (ADR-0026).
    fn keyed(mut config: ClientConfig) -> ClientConfig {
        config.package_key = Some(vec![7u8; 32]);
        config
    }

    /// The claim of ADR-0017 in one assertion: every wrapped kind's block is `type` and `name`, and
    /// it validates whole — the program resolves inside this Supervisor's own directory, the Agent
    /// type is stated, the timing comes from the fleet, and the kind's own strict parse accepts an
    /// empty table.
    // Verifies: ADR-0017
    #[test]
    fn every_wrapped_kinds_block_is_two_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (kind, _) in WRAPPED.iter().filter(|(_, compiled)| *compiled) {
            let config: ClientConfig = toml::from_str(&format!(
                "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
                 [[supervisor]]\ntype = {kind:?}\nname = {kind:?}\n",
                state = dir.path().join("state").to_string_lossy(),
            ))
            .unwrap_or_else(|e| panic!("{kind}: {e}"));
            validate_block(&config, &config.supervisors[0])
                .unwrap_or_else(|e| panic!("{kind} needs more than two lines: {e}"));
        }
    }

    /// A Client says which kinds it carries, one key per kind (ADR-0017 clause 18), so a Selector
    /// can aim a Supervisor set at the Clients that can actually run it — rather than the Server
    /// learning from a `FAILED` that it aimed at a Client too old to have the plugin.
    /// Which keys those are is `a_build_carries_exactly_the_wrapped_kinds_its_features_name`'s;
    /// this is what the key does to a value the operator already wrote.
    // Verifies: ADR-0017
    #[test]
    fn a_client_reports_the_kinds_it_was_compiled_with() {
        // An operator's own value under the same key is left alone: a configured attribute is the
        // host's statement about itself, and this only fills in what nothing else said.
        let stated = kind_attributes(
            [("supervisor.kind.command".to_string(), "no".to_string())]
                .into_iter()
                .collect(),
        );
        assert_eq!(
            stated.get("supervisor.kind.command").map(String::as_str),
            Some("no")
        );
    }

    /// The wrapped kinds, each with whether this build's features carry it (ADR-0017 clause 2).
    const WRAPPED: [(&str, bool); 0] = [];

    /// A build's kinds are the core's two and the wrapped ones its features name — no more, so a
    /// Selector aimed at `supervisor.kind.glpi` never reaches a build without it, and no fewer
    /// (ADR-0017 clauses 2 and 18).
    // Verifies: ADR-0017
    #[test]
    fn a_build_carries_exactly_the_wrapped_kinds_its_features_name() {
        let mut expected = vec!["collector", "command"];
        expected.extend(WRAPPED.iter().filter(|(_, c)| *c).map(|(kind, _)| *kind));
        expected.sort_unstable();
        let mut compiled: Vec<&str> = registry().iter().map(|plugin| plugin.kind()).collect();
        compiled.sort_unstable();
        assert_eq!(compiled, expected);

        let attributes = kind_attributes(BTreeMap::new());
        assert!(
            attributes.values().all(|value| value == "true"),
            "{attributes:?}"
        );
        let reported: Vec<String> = attributes.into_keys().collect();
        let expected: Vec<String> = expected
            .iter()
            .map(|kind| format!("supervisor.kind.{kind}"))
            .collect();
        assert_eq!(
            reported, expected,
            "BTreeMap keys and the sorted list agree on order"
        );
    }

    /// A wrapped kind this build leaves out is an unknown `type` like any other: startup and an
    /// offered set both refuse the block, naming the kinds the build does carry (ADR-0017 clause
    /// 2). The default build carries every kind, so this decides something in the
    /// `--no-default-features` run of CI.
    // Verifies: ADR-0017
    #[test]
    fn a_kind_left_out_of_the_build_is_an_unknown_type() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (kind, _) in WRAPPED.iter().filter(|(_, compiled)| !*compiled) {
            let config: ClientConfig = toml::from_str(&format!(
                "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
                 [[supervisor]]\ntype = {kind:?}\nname = {kind:?}\n",
                state = dir.path().join("state").to_string_lossy(),
            ))
            .unwrap_or_else(|e| panic!("{kind}: {e}"));
            let error = validate_block(&config, &config.supervisors[0])
                .expect_err(&format!("{kind} is not in this build"));
            assert!(error.contains("unknown type"), "{kind} -> {error}");
            let known = error
                .split_once("(known: ")
                .and_then(|(_, rest)| rest.strip_suffix(')'))
                .unwrap_or_else(|| panic!("{kind}: the refusal names the known kinds: {error}"));
            let compiled: Vec<&str> = registry().iter().map(|plugin| plugin.kind()).collect();
            assert_eq!(known, compiled.join(", "), "{kind} is not among them");
        }
    }

    /// And where a kind states no correction, the fleet's policy reaches the Supervisor unchanged
    /// — including for an unwrapped kind, whose block may still override it because no kind exists
    /// there to hold the value.
    #[test]
    fn the_fleets_timing_reaches_a_supervisor_that_says_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plugins = registry();
        let mut config: ClientConfig =
            toml::from_str(&config(dir.path(), "managed-agent", None)).expect("parse");
        config.supervisor_defaults.stop_timeout_secs = 45;
        config.supervisor_defaults.apply_grace_secs = 7;
        let block = &config.supervisors[0];
        let timing = effective_timing(&config, block, find_plugin(&plugins, block).expect("kind"))
            .expect("resolved");
        assert_eq!(timing.stop_timeout, Duration::from_secs(45));
        assert_eq!(timing.apply_grace, Duration::from_secs(7));

        let stated: ClientConfig = toml::from_str(&format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
             [supervisors]\nstop_timeout_secs = 45\n\
             [[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"x\"\n\
             stop_timeout_secs = 90\n",
            state = dir.path().join("state").to_string_lossy(),
        ))
        .expect("parse");
        let block = &stated.supervisors[0];
        let timing = effective_timing(&stated, block, find_plugin(&plugins, block).expect("kind"))
            .expect("resolved");
        assert_eq!(
            timing.stop_timeout,
            Duration::from_secs(90),
            "an unwrapped kind's block still answers"
        );
    }

    /// The unwrapped kinds are untouched: `command` knows nothing, so its block still says
    /// everything — and a Collector may still pin the port something actually connects to.
    #[test]
    fn an_unwrapped_kind_still_says_everything_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config: ClientConfig =
            toml::from_str(&config(dir.path(), "managed-agent", None)).expect("parse");
        let block = &config.supervisors[0];
        let plugins = registry();
        let plugin = find_plugin(&plugins, block).expect("the kind is known");
        let (_, program, _) = take_program(&config, block, plugin).expect("the block names it");
        assert!(program.path.ends_with("managed-agent"));
        assert_eq!(
            effective_service_name(block, plugin, &program.path).expect("a type"),
            "managed-agent",
            "the program's file name is what the operator already wrote"
        );

        let collector: ClientConfig = toml::from_str(&format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
             [[supervisor]]\ntype = \"collector\"\nname = \"otelcol\"\n\
             binary = \"otelcol\"\nendpoint_port = 4321\n",
            state = dir.path().join("state").to_string_lossy(),
        ))
        .expect("parse");
        assert!(
            check_endpoint_port(
                &collector.supervisors[0],
                find_plugin(&plugins, &collector.supervisors[0]).expect("kind")
            )
            .is_ok(),
            "the opampextension connects to it, so pinning it is a decision"
        );
    }

    /// Two Supervisors, `a` and `b`, of the one Agent type `managed-agent`, taking packages.
    fn two_of_a_type(root: &std::path::Path) -> ClientConfig {
        keyed(
            toml::from_str(&format!(
                "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
                 [[supervisor]]\ntype = \"command\"\nname = \"a\"\ncommand = \"managed-agent\"\n\
                 [[supervisor]]\ntype = \"command\"\nname = \"b\"\ncommand = \"managed-agent\"\n",
                state = root.join("state").to_string_lossy(),
            ))
            .expect("parse"),
        )
    }

    /// Writes the installed-package record of Supervisor `name`, as an install would have.
    fn installed(config: &ClientConfig, name: &str, version: &str) {
        use crate::supervisor::ports::AgentStorage as _;
        Storage::new(config.supervisor_dir(name))
            .expect("storage")
            .store_package(&crate::supervisor::ports::InstalledPackage {
                name: "managed-agent".to_string(),
                version: version.to_string(),
                hash_hex: hex::encode(version),
            })
            .expect("store");
    }

    /// Offers `version` of `managed-agent` to the Agent at `index`: whether a download was
    /// scheduled, and the refusal it reports.
    fn offer_to(engine: &mut Engine, index: usize, version: &str) -> (bool, String) {
        let uid = engine.uids().nth(index).expect("an agent");
        engine.handle(&opamp::proto::ServerToAgent {
            instance_uid: uid.as_bytes().to_vec(),
            packages_available: Some(opamp::proto::PackagesAvailable {
                packages: [(
                    "managed-agent".to_string(),
                    opamp::proto::PackageAvailable {
                        version: version.to_string(),
                        file: Some(opamp::proto::DownloadableFile {
                            download_url: "/x".to_string(),
                            content_hash: b"chash".to_vec(),
                            ..Default::default()
                        }),
                        hash: version.as_bytes().to_vec(),
                        ..Default::default()
                    },
                )]
                .into(),
                all_packages_hash: version.as_bytes().to_vec(),
            }),
            ..Default::default()
        });
        let downloads = !engine.take_package_downloads().is_empty();
        let why = engine.poll_reports()[index]
            .package_statuses
            .as_ref()
            .map(|statuses| statuses.error_message.clone())
            .unwrap_or_default();
        (downloads, why)
    }

    /// With no mark file and `a`'s record at `0.110.0`, the start seeds the mark: `b`, which has
    /// no record of its own, refuses `0.109.0` naming the mark (ADR-0043 clause 9).
    /// Verifies: ADR-0043
    #[tokio::test]
    async fn the_start_seeds_the_mark_from_the_installed_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = two_of_a_type(dir.path());
        installed(&config, "a", "0.110.0");

        let mut engine = build_engine(&config, &shutdown).expect("build");
        let (downloads, why) = offer_to(&mut engine, 2, "0.109.0");
        assert!(!downloads, "nothing below the seeded mark is fetched");
        assert!(why.contains("0.110.0"), "{why}");
        assert!(
            dir.path()
                .join("state")
                .join(crate::storage::HIGH_WATER_FILE)
                .is_file(),
            "the seeded mark is written"
        );
    }

    /// A mark file that does not parse is never read as empty: every Supervisor offer is refused
    /// naming the file, and the Client still starts and reports (ADR-0043 clause 11).
    /// Verifies: ADR-0043
    #[tokio::test]
    async fn an_unreadable_mark_file_refuses_every_supervisor_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = two_of_a_type(dir.path());
        std::fs::create_dir_all(&config.state_dir).expect("state");
        let file = config.state_dir.join(crate::storage::HIGH_WATER_FILE);
        std::fs::write(&file, "{ not json").expect("write");

        let mut engine = build_engine(&config, &shutdown).expect("the Client still starts");
        assert_eq!(engine.poll_reports().len(), 3, "and every Agent reports");
        for index in [1, 2] {
            let (downloads, why) = offer_to(&mut engine, index, "9.0.0");
            assert!(!downloads, "{index}: nothing is fetched");
            assert!(
                why.contains(crate::storage::HIGH_WATER_FILE),
                "{index}: {why}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&file).expect("read"),
            "{ not json",
            "the file is the operator's to repair"
        );

        // A value that is not SemVer is just as unreadable.
        std::fs::write(&file, r#"{"managed-agent": "1.19"}"#).expect("write");
        let mut engine = build_engine(&config, &shutdown).expect("build");
        assert!(!offer_to(&mut engine, 1, "9.0.0").0);
    }

    /// Only the host lowers the mark: with the Client stopped, the operator deletes the type's
    /// entry and the type's installed records, and after the start an offer at `0.109.0` is taken
    /// (ADR-0043 clause 12).
    /// Verifies: ADR-0043
    #[tokio::test]
    async fn the_host_lowers_the_mark_by_deleting_the_entry_and_the_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = two_of_a_type(dir.path());
        installed(&config, "a", "0.110.0");
        let mut engine = build_engine(&config, &shutdown).expect("build");
        assert!(!offer_to(&mut engine, 2, "0.109.0").0, "held by the mark");
        drop(engine);

        std::fs::write(
            config.state_dir.join(crate::storage::HIGH_WATER_FILE),
            r#"{"another-type": "2.0.0"}"#,
        )
        .expect("remove the type's entry");
        std::fs::remove_file(config.supervisor_dir("a").join("installed-package.json"))
            .expect("remove the record");

        let mut engine = build_engine(&config, &shutdown).expect("build");
        let (downloads, why) = offer_to(&mut engine, 2, "0.109.0");
        assert!(downloads, "the lowered mark takes 0.109.0: {why}");
    }

    fn accepts_packages(engine: &mut Engine) -> bool {
        let reports = engine.poll_reports();
        let supervisor = &reports[SELF_AGENT_OFFSET];
        supervisor.capabilities & AgentCapabilities::AcceptsPackages as u64 != 0
    }

    /// ADR-0017 where it becomes visible to the Server: **every** Supervisor declares
    /// `AcceptsPackages`, because every Managed Process is one this Client installed. The
    /// capability is a constant of this Client now, not a function of a path — which is why the
    /// second half of this test is a startup refusal rather than a second capability.
    ///
    /// The `program/` directory is created either way, before the first package: the swap renames
    /// inside it, so it has to exist beforehand rather than after.
    /// Verifies: ADR-0017, ADR-0026
    #[tokio::test]
    async fn every_supervisor_declares_package_acceptance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();

        let owned: ClientConfig =
            keyed(toml::from_str(&config(dir.path(), "managed-agent", None)).expect("parse"));
        let mut engine = build_engine(&owned, &shutdown).expect("build");
        assert!(
            accepts_packages(&mut engine),
            "the program is in this Client's own directory, which is what makes it updatable"
        );
        assert!(
            dir.path().join("state/supervisors/agent/program").is_dir(),
            "the directory the swap renames inside exists before any package arrives"
        );

        // A program on the machine does not start at all (ADR-0017).
        let foreign = dir.path().join("elsewhere/managed-agent");
        let machines: ClientConfig = toml::from_str(&config(
            dir.path(),
            &foreign.to_string_lossy(),
            Some(dir.path().join("other")),
        ))
        .expect("parse");
        let Err(err) = build_engine(&machines, &shutdown) else {
            panic!("a program on the machine must be refused at startup");
        };
        assert!(err.contains("only programs it installs"), "{err}");
    }

    /// Without the operator's verification key, no Agent of this Client takes packages — neither a
    /// Supervisor nor the Client's own Agent, whose self-update consent stands — so nothing can be
    /// installed unsigned (ADR-0026, ADR-0018).
    /// Verifies: ADR-0026, ADR-0018, Q-1
    #[tokio::test]
    async fn without_a_verification_key_no_agent_takes_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let unkeyed: ClientConfig =
            toml::from_str(&config(dir.path(), "managed-agent", None)).expect("parse");
        let mut engine = build_engine(&unkeyed, &shutdown).expect("build");
        assert!(
            !engine.installs_packages(),
            "something takes packages without a key"
        );
        for report in engine.poll_reports() {
            assert_eq!(
                report.capabilities & AgentCapabilities::AcceptsPackages as u64,
                0,
                "an Agent declares AcceptsPackages without a key"
            );
        }
    }

    /// The side-effect-free `installs_packages()` that the startup signature-posture warning reads
    /// (ADR-0026) agrees with the `AcceptsPackages` capability an Agent actually declares.
    #[tokio::test]
    async fn installs_packages_reflects_declared_package_acceptance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();

        let owned: ClientConfig =
            keyed(toml::from_str(&config(dir.path(), "managed-agent", None)).expect("parse"));
        let engine = build_engine(&owned, &shutdown).expect("build");
        assert!(
            engine.installs_packages(),
            "the program is package-updatable, so the Client installs packages"
        );

        // Every Supervisor is package-updatable (ADR-0017), so the only way for an Engine to answer
        // *no* is to have no Supervisor and a withdrawn self-update consent. That is worth keeping
        // green: the startup check this feeds warns about an unconfigured verification key, and a
        // Client that installs nothing has nothing for that key to protect.
        let alone: ClientConfig = toml::from_str(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\n[packages]\nself_update = false\n",
        )
        .expect("parse");
        let engine = build_engine(&alone, &shutdown).expect("build");
        assert!(
            !engine.installs_packages(),
            "no Supervisor and no self-update consent means nothing here takes a package"
        );

        // The Client's own Agent consents by default (ADR-0018), so a Client with no Supervisor at
        // all still installs packages — its own.
        let bare: ClientConfig =
            keyed(toml::from_str("endpoint = \"ws://127.0.0.1:1/v1/opamp\"\n").expect("parse"));
        let engine = build_engine(&bare, &shutdown).expect("build");
        assert!(
            engine.installs_packages(),
            "the Client's own Agent consents by default"
        );
    }

    /// A tree Supervisor owns its `program/` directory and *nothing inside it* (ADR-0026). The
    /// live tree arrives by renaming a staging directory over `program/tree`, and a rename cannot
    /// replace a directory something else created and filled — so preparing the program's parent,
    /// which is right for a single file, would make every first install of a tree fail.
    #[tokio::test]
    async fn a_tree_supervisor_prepares_its_root_and_leaves_the_tree_to_the_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\n\
             [[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"fluent-bit\"\n\
             program_path = \"bin/fluent-bit\"\n",
            state = dir.path().join("state").to_string_lossy(),
        );
        let parsed: ClientConfig = keyed(toml::from_str(&config).expect("parse"));
        let mut engine = build_engine(&parsed, &shutdown).expect("build");

        assert!(
            accepts_packages(&mut engine),
            "a bare name is the consent whether the package is one file or a tree"
        );
        let program_dir = dir.path().join("state/supervisors/agent/program");
        assert!(
            program_dir.is_dir(),
            "the root the tree is renamed into exists"
        );
        assert!(
            !program_dir.join("tree").exists(),
            "nothing occupies the name the first install has to rename onto"
        );
    }

    /// The third case of the rule: refused at startup, not resolved against something.
    #[tokio::test]
    async fn a_program_path_that_is_neither_fails_the_build() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config: ClientConfig =
            toml::from_str(&config(dir.path(), "./managed-agent", None)).expect("parse");
        let Err(err) = build_engine(&config, &shutdown) else {
            panic!("a path that is neither must not start");
        };
        assert!(err.contains("bare file name"), "{err}");
    }

    /// A block that names no program at all is a startup error too — the key moved out of the
    /// plugin's strict parse, and that must not turn a missing one into a default.
    #[tokio::test]
    async fn a_block_without_a_program_fails_the_build() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config: ClientConfig = toml::from_str(&format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
             [[supervisor]]\ntype = \"command\"\nname = \"agent\"\n",
            state = dir.path().join("state").to_string_lossy(),
        ))
        .expect("parse");
        let Err(err) = build_engine(&config, &shutdown) else {
            panic!("a block without a program must not start");
        };
        assert!(err.contains("needs a `command`"), "{err}");
    }

    /// ADR-0017 point 37: a directory no block names survives startup — reported, never reaped.
    /// Startup cannot tell a purge a crash cut short from an operator's deliberate hand edit, and
    /// the destructive reading of that ambiguity would delete an identity and a program that were
    /// not meant to go.
    #[tokio::test]
    async fn an_orphaned_supervisor_directory_is_not_reaped_at_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let orphan = dir.path().join("state/supervisors/orphan");
        std::fs::create_dir_all(&orphan).expect("create");
        std::fs::write(orphan.join("instance-uid"), "uid").expect("write");

        let parsed: ClientConfig =
            toml::from_str(&config(dir.path(), "managed-agent", None)).expect("parse");
        build_engine(&parsed, &shutdown).expect("build");

        assert!(
            orphan.join("instance-uid").is_file(),
            "an orphaned directory is reported, not deleted"
        );
    }

    /// The self-Agent's effective configuration is its own file, not an echo of a stored offer:
    /// the first report carries `supervisor.toml`'s (redacted) text, which is what fills the fleet
    /// view's empty column for every Client.
    #[tokio::test]
    async fn the_self_agent_reports_its_file_as_the_effective_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let path = dir.path().join("supervisor.toml");
        std::fs::write(
            &path,
            format!(
                "# written by the operator\nendpoint = \"ws://127.0.0.1:1/v1/opamp\"\n\
                 state_dir = {state:?}\n[auth]\nbearer_token = \"s3cret\"\n",
                state = dir.path().join("state").to_string_lossy(),
            ),
        )
        .expect("write");
        let config = ClientConfig::load(&path).expect("load");
        let mut engine = build_engine(&config, &shutdown).expect("build");

        let reports = engine.poll_reports();
        let effective = reports[SELF_AGENT_INDEX]
            .effective_config
            .as_ref()
            .expect("the first report is a full one and carries the effective configuration");
        let map = &effective.config_map.as_ref().expect("map").config_map;
        let body = String::from_utf8(map["supervisor.toml"].body.clone()).expect("utf-8");
        assert!(body.contains("# written by the operator"), "{body}");
        assert!(body.contains("endpoint = \"ws://127.0.0.1:1/v1/opamp\""));
        assert!(
            !body.contains("s3cret"),
            "a credential must never leave the host: {body}"
        );
    }

    /// A stored configuration as a remote configuration left it: `fleet` and the roled `ruleset`
    /// as entry files, `.supplementary` naming the role, and the `.pb` beside them.
    fn store_offer(supervisor_dir: &std::path::Path) -> std::path::PathBuf {
        use crate::supervisor::ports::AgentStorage as _;
        let storage = Storage::new(supervisor_dir.to_path_buf()).expect("storage");
        let entry = |body: &str, role: &str| opamp::proto::AgentConfigObject {
            body: body.as_bytes().to_vec(),
            role: role.to_string(),
            content_type: String::new(),
        };
        storage
            .store_remote_config(&opamp::proto::AgentRemoteConfig {
                config: Some(opamp::proto::AgentConfigMap {
                    config_map: std::collections::HashMap::from([
                        ("fleet".to_string(), entry("receivers: {}\n", "")),
                        ("ruleset".to_string(), entry("rules: []\n", "rules")),
                        ("edited".to_string(), entry("server: 1\n", "")),
                    ]),
                }),
                config_hash: b"stored".to_vec(),
            })
            .expect("store");
        storage.config_dir()
    }

    /// One `command` Supervisor named `agent`, with `names` in `[supervisors]
    /// remote_config_disabled` and, when given, the Client's own `name`.
    fn listed_config(root: &std::path::Path, names: &str, name: Option<&str>) -> ClientConfig {
        toml::from_str(&format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n{own}\
             [supervisors]\nremote_config_disabled = {names}\n\
             [[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"managed-agent\"\n",
            state = root.join("state").to_string_lossy(),
            own = name.map(|n| format!("name = {n:?}\n")).unwrap_or_default(),
        ))
        .expect("parse")
    }

    /// A listed name no block carries starts the Client and earns one notice naming it; one equal
    /// to the Client's own name says that Agent is not covered (ADR-0017 clause 49).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_listed_name_without_a_block_is_a_notice_not_a_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = listed_config(dir.path(), "[\"agent\", \"later\"]", None);
        build_engine(&config, &shutdown).expect("a name without a block starts");
        let notices = remote_config_disabled_notices(&config);
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("\"later\""), "{notices:?}");
        assert!(
            notices[0].contains("no [[supervisor]] block"),
            "{notices:?}"
        );
    }

    /// Switching off takes the Server's last configuration out of force before the kind starts:
    /// the entry files it wrote and `.supplementary` go while their bytes are still the stored
    /// ones, an overwritten entry and an operator's own file stay, and the `.pb` goes (ADR-0017
    /// clause 32).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_listed_supervisor_drops_the_stored_remote_config_and_keeps_the_operators_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = listed_config(dir.path(), "[\"agent\"]", None);
        let supervisor_dir = config.supervisor_dir("agent");
        let config_dir = store_offer(&supervisor_dir);
        assert!(config_dir
            .join(crate::storage::SUPPLEMENTARY_FILE)
            .is_file());
        std::fs::write(config_dir.join("edited"), "operator: 1\n").expect("overwrite");
        std::fs::write(config_dir.join("local.yaml"), "mine: 1\n").expect("operator's file");

        build_engine(&config, &shutdown).expect("build");

        assert!(!supervisor_dir.join("remote-config.pb").exists());
        assert!(!config_dir.join("fleet").exists());
        assert!(!config_dir.join("ruleset").exists());
        assert!(!config_dir.join(crate::storage::SUPPLEMENTARY_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(config_dir.join("edited")).expect("kept"),
            "operator: 1\n"
        );
        assert_eq!(
            std::fs::read_to_string(config_dir.join("local.yaml")).expect("kept"),
            "mine: 1\n"
        );
    }

    /// A stored configuration whose files cannot be removed stops the Supervisor before its kind
    /// starts on them, and at startup that fails the whole Client: it fails closed rather than run
    /// the Server's configuration under a switch that says it does not (ADR-0017 clause 52).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_stored_remote_config_that_cannot_be_removed_fails_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = listed_config(dir.path(), "[\"agent\"]", None);
        let supervisor_dir = config.supervisor_dir("agent");
        let config_dir = store_offer(&supervisor_dir);
        // An entry the stored map names that cannot be read, and so cannot be compared or removed.
        std::fs::remove_file(config_dir.join("fleet")).expect("remove");
        std::fs::create_dir(config_dir.join("fleet")).expect("in the way");

        let Err(err) = build_engine(&config, &shutdown) else {
            panic!("started over a stored configuration it could not remove");
        };
        assert!(
            err.contains("\"agent\"")
                && err.contains("cannot remove the stored remote configuration"),
            "{err}"
        );
        assert!(supervisor_dir.join("remote-config.pb").is_file());
    }

    /// A stored `.pb` that does not decode is deleted, and `config/` is left exactly as it is,
    /// since nothing says which of its files the Server wrote (ADR-0017 clause 52).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn an_undecodable_stored_remote_config_is_deleted_and_config_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = listed_config(dir.path(), "[\"agent\"]", None);
        let supervisor_dir = config.supervisor_dir("agent");
        let config_dir = store_offer(&supervisor_dir);
        std::fs::write(supervisor_dir.join("remote-config.pb"), [0xff; 7]).expect("garble");

        build_engine(&config, &shutdown).expect("build");

        assert!(!supervisor_dir.join("remote-config.pb").exists());
        for kept in [
            "fleet",
            "ruleset",
            "edited",
            crate::storage::SUPPLEMENTARY_FILE,
        ] {
            assert!(config_dir.join(kept).is_file(), "{kept} was touched");
        }
    }

    /// A listed Supervisor restarted over a stored configuration reports no status and no hash,
    /// and declares neither remote-configuration capability (ADR-0017 clauses 50 and 52).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_listed_supervisor_reports_no_remote_config_status_after_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = listed_config(dir.path(), "[\"agent\"]", None);
        store_offer(&config.supervisor_dir("agent"));

        let mut engine = build_engine(&config, &shutdown).expect("build");
        let report = &engine.poll_reports()[SELF_AGENT_OFFSET];
        assert!(report.remote_config_status.is_none(), "{report:?}");
        assert_eq!(
            report.capabilities
                & (AgentCapabilities::AcceptsRemoteConfig as u64
                    | AgentCapabilities::ReportsRemoteConfig as u64),
            0
        );

        // Unlisted, the same stored configuration is restored as applied.
        let (_tx, shutdown) = shutdown_channel();
        let other = tempfile::tempdir().expect("tempdir");
        let unlisted = listed_config(other.path(), "[]", None);
        store_offer(&unlisted.supervisor_dir("agent"));
        let mut engine = build_engine(&unlisted, &shutdown).expect("build");
        let status = engine.poll_reports()[SELF_AGENT_OFFSET]
            .remote_config_status
            .clone()
            .expect("restored");
        assert_eq!(status.last_remote_config_hash, b"stored");
    }

    /// The switch covers Supervisors only: the Client's own name in the list earns a notice, and
    /// its Agent still declares `AcceptsRemoteConfig` for its Supervisor set (ADR-0017 clause 49
    /// and out of scope).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn the_clients_own_agent_keeps_accepting_its_supervisor_set_when_its_name_is_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = listed_config(dir.path(), "[\"edge-1\"]", Some("edge-1"));
        let notices = remote_config_disabled_notices(&config);
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(
            notices[0].contains("\"edge-1\"") && notices[0].contains("own Agent is not covered"),
            "{notices:?}"
        );
        let mut engine = build_engine(&config, &shutdown).expect("build");
        let reports = engine.poll_reports();
        let own = reports[SELF_AGENT_INDEX].capabilities;
        assert_ne!(own & AgentCapabilities::AcceptsRemoteConfig as u64, 0);
        assert_ne!(own & AgentCapabilities::ReportsRemoteConfig as u64, 0);
        assert_ne!(
            reports[SELF_AGENT_OFFSET].capabilities & AgentCapabilities::AcceptsRemoteConfig as u64,
            0,
            "an unlisted Supervisor keeps it too"
        );
    }

    /// One `command` Supervisor named `agent`, with `[supervisors] server_manages_set` as given.
    fn kept_set_config(root: &std::path::Path, server_manages_set: bool) -> ClientConfig {
        toml::from_str(&format!(
            "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
             [supervisors]\nserver_manages_set = {server_manages_set}\n\
             [[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"managed-agent\"\n",
            state = root.join("state").to_string_lossy(),
        ))
        .expect("parse")
    }

    /// On a host that keeps its set, the set the Client's own Agent stored before is removed at
    /// start — the `.pb` and the unchanged entry copies, not a copy changed since — and is not
    /// reported; the Agent declares neither remote-configuration bit. With the key `true` the same
    /// stored set is restored as applied (ADR-0017 clauses 42 and 44).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_host_that_keeps_its_set_drops_the_stored_set_and_reports_no_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = kept_set_config(dir.path(), false);
        let config_dir = store_offer(&config.state_dir);
        std::fs::write(config_dir.join("edited"), "changed: 1\n").expect("change a copy");

        let mut engine = build_engine(&config, &shutdown).expect("build");

        assert!(!config.state_dir.join("remote-config.pb").exists());
        assert!(!config_dir.join("fleet").exists());
        assert!(!config_dir.join("ruleset").exists());
        assert!(config_dir.join("edited").is_file(), "a changed copy stays");
        let reports = engine.poll_reports();
        let own = &reports[SELF_AGENT_INDEX];
        assert!(own.remote_config_status.is_none(), "{own:?}");
        assert_eq!(
            own.capabilities
                & (AgentCapabilities::AcceptsRemoteConfig as u64
                    | AgentCapabilities::ReportsRemoteConfig as u64),
            0
        );
        assert_ne!(
            reports[SELF_AGENT_OFFSET].capabilities & AgentCapabilities::AcceptsRemoteConfig as u64,
            0,
            "a Supervisor keeps taking its own configuration"
        );

        let (_tx, shutdown) = shutdown_channel();
        let other = tempfile::tempdir().expect("tempdir");
        let managed = kept_set_config(other.path(), true);
        store_offer(&managed.state_dir);
        let mut engine = build_engine(&managed, &shutdown).expect("build");
        let status = engine.poll_reports()[SELF_AGENT_INDEX]
            .remote_config_status
            .clone()
            .expect("restored");
        assert_eq!(status.last_remote_config_hash, b"stored");
        assert!(managed.state_dir.join("remote-config.pb").is_file());
    }

    /// A `remote-config.pb` that cannot be read or deleted is a warning, not a refusal: nothing
    /// runs on it, and it is still not reported (ADR-0017 clause 44).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_stored_set_that_cannot_be_removed_does_not_stop_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = kept_set_config(dir.path(), false);
        std::fs::create_dir_all(config.state_dir.join("remote-config.pb")).expect("in the way");

        let mut engine = build_engine(&config, &shutdown).expect("starts all the same");
        let own = &engine.poll_reports()[SELF_AGENT_INDEX];
        assert!(own.remote_config_status.is_none(), "{own:?}");
    }

    /// `remote-config.pb` goes before the copies, so a copy that cannot be removed leaves no hash
    /// behind: switched back on, the next start reports none (ADR-0017 clauses 44 and 47).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_copy_that_cannot_be_removed_still_leaves_no_hash_to_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = kept_set_config(dir.path(), false);
        let config_dir = store_offer(&config.state_dir);
        // An entry the stored map names that cannot be read, and so cannot be compared or removed.
        std::fs::remove_file(config_dir.join("fleet")).expect("remove");
        std::fs::create_dir(config_dir.join("fleet")).expect("in the way");

        build_engine(&config, &shutdown).expect("starts all the same");
        assert!(!config.state_dir.join("remote-config.pb").exists());
        assert!(
            !config_dir.join("ruleset").exists(),
            "the other copies still go"
        );

        let (_tx, shutdown) = shutdown_channel();
        let managed = kept_set_config(dir.path(), true);
        let mut engine = build_engine(&managed, &shutdown).expect("build");
        let own = &engine.poll_reports()[SELF_AGENT_INDEX];
        assert!(own.remote_config_status.is_none(), "{own:?}");
        assert_ne!(
            own.capabilities & AgentCapabilities::AcceptsRemoteConfig as u64,
            0
        );
    }

    /// A stored set that does not decode is deleted, and `config/` is left as it is (ADR-0017
    /// clause 24).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn an_undecodable_stored_set_is_deleted_and_config_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_tx, shutdown) = shutdown_channel();
        let config = kept_set_config(dir.path(), false);
        let config_dir = store_offer(&config.state_dir);
        std::fs::write(config.state_dir.join("remote-config.pb"), [0xff; 7]).expect("garble");

        let mut engine = build_engine(&config, &shutdown).expect("build");

        assert!(!config.state_dir.join("remote-config.pb").exists());
        for kept in [
            "fleet",
            "ruleset",
            "edited",
            crate::storage::SUPPLEMENTARY_FILE,
        ] {
            assert!(config_dir.join(kept).is_file(), "{kept} was touched");
        }
        assert!(engine.poll_reports()[SELF_AGENT_INDEX]
            .remote_config_status
            .is_none());
    }

    /// The removal is logged once naming the stored hash, and a set offered to the built Client
    /// anyway is logged once per hash (ADR-0017 clauses 43 and 44).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn the_removed_stored_set_is_logged_naming_its_hash() {
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
        let (_tx, shutdown) = shutdown_channel();
        let config = kept_set_config(dir.path(), false);
        store_offer(&config.state_dir);
        tracing::subscriber::with_default(subscriber, || {
            let mut engine = build_engine(&config, &shutdown).expect("build");
            let uid = engine.poll_reports()[SELF_AGENT_INDEX].instance_uid.clone();
            for hash in [b"set-a", b"set-a", b"set-b", b"set-a"] {
                engine.handle(&opamp::proto::ServerToAgent {
                    instance_uid: uid.clone(),
                    remote_config: Some(opamp::proto::AgentRemoteConfig {
                        config: None,
                        config_hash: hash.to_vec(),
                    }),
                    ..Default::default()
                });
            }
            assert!(
                engine.take_self_config().is_none(),
                "a set reached the apply"
            );
        });
        let log = String::from_utf8(captured.0.lock().expect("lock").clone()).expect("utf-8");
        let removed: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("removed the stored supervisor set"))
            .collect();
        assert_eq!(removed.len(), 1, "{log}");
        assert!(removed[0].contains(&hex::encode(b"stored")), "{log}");
        let ignored: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("ignoring a supervisor set"))
            .collect();
        assert_eq!(ignored.len(), 2, "{log}");
        assert!(ignored[0].contains(&hex::encode(b"set-a")), "{log}");
        assert!(ignored[1].contains(&hex::encode(b"set-b")), "{log}");
    }

    /// The notice for the Client's own name in `remote_config_disabled` (ADR-0017 clause 49) points
    /// at `server_manages_set`, and on a host that keeps its set says the set is the host's
    /// already (ADR-0017).
    /// Verifies: ADR-0017
    #[test]
    fn the_own_name_notice_points_at_server_manages_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = listed_config(dir.path(), "[\"edge-1\"]", Some("edge-1"));
        let notices = remote_config_disabled_notices(&config);
        assert!(
            notices[0].contains("server_manages_set = false stops that"),
            "{notices:?}"
        );
        config.supervisor_defaults.server_manages_set = false;
        let notices = remote_config_disabled_notices(&config);
        assert!(
            notices[0].contains("own Agent is not covered")
                && notices[0].contains("already keeps its supervisor set"),
            "{notices:?}"
        );
    }
}
