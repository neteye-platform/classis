//! How one `[[supervisor]]` block is read (ADR-0017): the plugin its `type` selects, the
//! program it runs, the Agent type it presents and the timings it keeps — the rules the supervision
//! core applies to every kind alike, apart from the registry that knows the kinds and from
//! anything that touches the disk.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{resolve_program, ClientConfig, Program, SupervisorBlock};

use super::ports::Plugin;

/// One `[[supervisor]]` block as the core reads it: the plugin its `type` selects, the settings
/// left for that plugin's strict parse, and everything the core resolves itself.
pub struct Resolved<'a> {
    pub plugin: &'a dyn Plugin,
    pub settings: toml::Table,
    pub program: Program,
    /// Where the program sits inside a package tree (ADR-0026); `None` for a single file.
    pub program_path: Option<PathBuf>,
    pub service_name: String,
    pub timing: Timing,
}

/// Reads a block the one way both [`validate_block`](super::validate_block) and [`start_supervisor`](super::start_supervisor) read it, touching
/// nothing on disk.
///
/// What the core resolves — the program, the Agent type, the Endpoint port and the timings — is
/// checked here, so a Server-delivered set carrying a value its kind supplies is refused before a
/// running process is touched (ADR-0017), exactly as a bad plugin setting is.
pub fn resolve<'a>(
    config: &ClientConfig,
    block: &SupervisorBlock,
    plugins: &'a [Box<dyn Plugin>],
) -> Result<Resolved<'a>, String> {
    let plugin = find_plugin(plugins, block)?;
    let (settings, program, program_path) = take_program(config, block, plugin)?;
    let service_name = effective_service_name(block, plugin, &program.path)?;
    check_endpoint_port(block, plugin)?;
    let timing = effective_timing(config, block, plugin)?;
    Ok(Resolved {
        plugin,
        settings,
        program,
        program_path,
        service_name,
        timing,
    })
}

/// Pinning the Supervisor Endpoint's port is a decision only where something connects to it
/// (ADR-0017).
///
/// The Endpoint itself is bound for every Supervisor and stays that way (ADR-0015) — what is
/// refused is *naming* its port for a kind whose Managed Process speaks no OpAMP, where the value
/// would read as configuration and do nothing. `0` is not refused: it is the default written out,
/// and refusing a no-op teaches nobody anything.
pub fn check_endpoint_port(block: &SupervisorBlock, plugin: &dyn Plugin) -> Result<(), String> {
    if block.endpoint_port != 0 && !plugin.defaults().endpoint_port {
        return Err(format!(
            "supervisor {:?}: `endpoint_port` says nothing for type {:?} — the Supervisor Endpoint \
             is bound for every Supervisor, but only a Managed Process that speaks OpAMP connects \
             to one, and this kind's does not; remove the line",
            block.name,
            plugin.kind()
        ));
    }
    Ok(())
}

pub fn find_plugin<'a>(
    plugins: &'a [Box<dyn Plugin>],
    block: &SupervisorBlock,
) -> Result<&'a dyn Plugin, String> {
    plugins
        .iter()
        .find(|p| p.kind() == block.kind)
        .map(|p| p.as_ref())
        .ok_or_else(|| {
            let known: Vec<&str> = plugins.iter().map(|p| p.kind()).collect();
            format!(
                "supervisor {:?}: unknown type {:?} (known: {})",
                block.name,
                block.kind,
                known.join(", ")
            )
        })
}

/// Takes the program key out of the block's settings and resolves it (ADR-0017) — the
/// path rule belongs to the core, so no plugin can resolve its program differently. Returns the
/// remaining plugin settings, the resolved program, and where the program sits inside a package
/// tree, if it does.
pub fn take_program(
    config: &ClientConfig,
    block: &SupervisorBlock,
    plugin: &dyn Plugin,
) -> Result<(toml::Table, Program, Option<PathBuf>), String> {
    let mut settings = block.settings.clone();
    let key = plugin.program_key();
    let named = settings.remove(key);
    let program_name = match (named, plugin.defaults().program) {
        // A wrapped kind knows its program, so writing it is naming a value this Client computes
        // (ADR-0017 clause 13) — refused with what supplies it now, never quietly overridden.
        (Some(_), Some(derived)) => {
            return Err(format!(
                "supervisor {:?}: `{key}` is no longer a supervisor key for type {:?} — the kind \
                 installs and names its own program ({derived}); remove the line",
                block.name,
                plugin.kind()
            ))
        }
        (Some(raw), None) => raw
            .as_str()
            .ok_or_else(|| {
                format!(
                    "supervisor {:?}: `{key}` must be a path, not {}",
                    block.name,
                    raw.type_str()
                )
            })?
            .to_string(),
        (None, Some(derived)) => derived.to_string(),
        (None, None) => return Err(format!("supervisor {:?}: needs a `{key}`", block.name)),
    };
    let program_path = effective_program_path(block, plugin)?;
    let program = resolve_program(
        key,
        Path::new(&program_name),
        program_path.as_deref(),
        &config.supervisor_dir(&block.name),
        &block.name,
    )?;
    Ok((settings, program, program_path))
}

/// Where the program sits inside a package tree (ADR-0026): the block's answer, or the one the kind
/// knows (ADR-0017). A kind that knows it refuses a block that states it, for the reason
/// [`take_program`] refuses a program name.
///
/// # Errors
/// Returns an error when a block states a `program_path` its kind already supplies.
pub fn effective_program_path(
    block: &SupervisorBlock,
    plugin: &dyn Plugin,
) -> Result<Option<PathBuf>, String> {
    match (&block.program_path, plugin.defaults().program_path) {
        (Some(_), Some(derived)) => Err(format!(
            "supervisor {:?}: `program_path` is no longer a supervisor key for type {:?} — the \
             kind knows where its program sits in the tree it delivers ({derived}); remove the line",
            block.name,
            plugin.kind()
        )),
        (Some(stated), None) => Ok(Some(stated.clone())),
        (None, derived) => Ok(derived.map(PathBuf::from)),
    }
}

/// What this Supervisor's three timings are, and whether its block was allowed to say anything
/// about them (ADR-0017).
///
/// Three layers, outermost first: the fleet's policy in `[supervisors]` and `[updates]`, a wrapped
/// kind's correction of it, and — only where no kind exists to hold the value — the block. A block
/// of a wrapped kind naming one is refused with what supplies it now, on the same terms as every
/// other retired key, so an offered Supervisor set is refused before a process is touched.
pub fn effective_timing(
    config: &ClientConfig,
    block: &SupervisorBlock,
    plugin: &dyn Plugin,
) -> Result<Timing, String> {
    let fleet = Timing {
        stop_timeout: Duration::from_secs(config.supervisor_defaults.stop_timeout_secs),
        apply_grace: Duration::from_secs(config.supervisor_defaults.apply_grace_secs),
        retain_previous: Duration::from_secs(config.updates.retain_previous_secs),
    };
    let stated = [
        ("stop_timeout_secs", block.stop_timeout_secs),
        ("apply_grace_secs", block.apply_grace_secs),
        ("retain_previous_secs", block.retain_previous_secs),
    ];
    let Some(kind) = plugin.defaults().timing else {
        // An unwrapped kind: nothing here knows the agent, so the block still answers.
        return Ok(Timing {
            stop_timeout: block
                .stop_timeout_secs
                .map_or(fleet.stop_timeout, Duration::from_secs),
            apply_grace: block
                .apply_grace_secs
                .map_or(fleet.apply_grace, Duration::from_secs),
            retain_previous: block
                .retain_previous_secs
                .map_or(fleet.retain_previous, Duration::from_secs),
        });
    };
    for (key, value) in stated {
        if value.is_some() {
            return Err(format!(
                "supervisor {:?}: `{key}` is no longer a supervisor key for type {:?} — how long \
                 an agent needs is a property of that agent, which the kind states, over the \
                 fleet's own `[supervisors]`/`[updates]` policy; remove the line",
                block.name,
                plugin.kind()
            ));
        }
    }
    Ok(Timing {
        stop_timeout: kind.stop_timeout.unwrap_or(fleet.stop_timeout),
        apply_grace: kind.apply_grace.unwrap_or(fleet.apply_grace),
        retain_previous: kind.retain_previous.unwrap_or(fleet.retain_previous),
    })
}

/// The three resolved timings of one Supervisor.
pub struct Timing {
    pub stop_timeout: Duration,
    pub apply_grace: Duration,
    pub retain_previous: Duration,
}

/// The Agent type this Supervisor presents until — and unless — its Managed Process reports one of
/// its own (ADR-0016): the block's, the kind's, else the program's file name.
///
/// The file-name fallback is what the operator already wrote in this very block; it is read from
/// configuration and never parsed out of a program's output, where a name has no grammar to
/// recognise it by. A kind that states its type refuses a block that restates it (ADR-0017).
pub fn effective_service_name(
    block: &SupervisorBlock,
    plugin: &dyn Plugin,
    program: &Path,
) -> Result<String, String> {
    match (&block.service_name, plugin.defaults().service_name) {
        (Some(_), Some(derived)) => Err(format!(
            "supervisor {:?}: `service_name` is no longer a supervisor key for type {:?} — the \
             kind states the Agent type it presents ({derived}); remove the line",
            block.name,
            plugin.kind()
        )),
        (Some(stated), None) => Ok(stated.clone()),
        (None, Some(derived)) => Ok(derived.to_string()),
        (None, None) => Ok(program
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()),
    }
}
