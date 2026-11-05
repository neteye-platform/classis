//! What a Server-delivered `[[supervisor]]` block may bring, checked against the configuration
//! in force (ADR-0017 clauses 38, 39 and 54). The rules are the core's; the plugin registry
//! that names the kinds stays with the composition root, which hands the plugins in.

use crate::config::{ClientConfig, SupervisorBlock};

use super::block::find_plugin;
use super::ports::Plugin;

/// The check behind [`check_delivered_block`](super::check_delivered_block), with the compiled-in
/// plugins handed in. `roots` spells the Supervisors' root as configured and as an absolute path:
/// a delivered value may name it either way.
///
/// # Errors
/// Returns the reason the delivered block is refused, naming the block and what it brings.
pub fn check(
    running: &ClientConfig,
    block: &SupervisorBlock,
    plugins: &[Box<dyn Plugin>],
    roots: &[String],
) -> Result<(), String> {
    let plugin = find_plugin(plugins, block)?;
    let current = running
        .supervisors
        .iter()
        .find(|existing| existing.name == block.name && existing.kind == block.kind)
        .map(|existing| &existing.settings);
    if running.remote_config_disabled(&block.name) {
        // A listed Supervisor's block is the operator's whole: repeated as it runs, or added
        // naming its program and nothing else (ADR-0017 clause 54).
        let named = running
            .supervisors
            .iter()
            .find(|existing| existing.name == block.name);
        check_listed_block(block, named, plugin)?;
    } else {
        let policy = &running.supervisor_defaults;
        check_delivered_env(block, current, &policy.delivered_env, roots)?;
        if !policy.delivered_args {
            for key in ["args", "version_args"] {
                if block.settings.get(key) != current.and_then(|settings| settings.get(key)) {
                    return Err(format!(
                        "supervisor {:?}: a delivered block may not set {key} — allow it with \
                         [supervisors] delivered_args = true in this Client's supervisor.toml",
                        block.name
                    ));
                }
            }
        }
    }
    plugin
        .check_delivered(&block.settings, current)
        .map_err(|e| format!("supervisor {:?}: {e}", block.name))
}

/// A delivered block for a Supervisor whose remote configuration is switched off configures
/// nothing, whatever `delivered_args` and `delivered_env` allow: any key it may change would be a
/// configuration by another route (ADR-0017 clause 54). With a block of that name running, the
/// delivered one equals it whole; added, it carries `type`, `name` and — where the kind does not
/// name its own program — the kind's program key, and nothing else.
fn check_listed_block(
    block: &SupervisorBlock,
    current: Option<&SupervisorBlock>,
    plugin: &dyn Plugin,
) -> Result<(), String> {
    let refuse = |key: &str| {
        Err(format!(
            "supervisor {:?}: a delivered block may not set {key} — remote configuration is \
             switched off for it in [supervisors] remote_config_disabled in this Client's \
             supervisor.toml, so the block must stay as the operator wrote it",
            block.name
        ))
    };
    // The keys the core takes out of a block, spelled for comparison; an unset one is `None`.
    let core = |b: &SupervisorBlock| {
        let secs = |value: Option<u64>| value.map(|secs| secs.to_string());
        [
            ("type", Some(b.kind.clone())),
            ("service_name", b.service_name.clone()),
            (
                "endpoint_port",
                (b.endpoint_port != 0).then(|| b.endpoint_port.to_string()),
            ),
            ("stop_timeout_secs", secs(b.stop_timeout_secs)),
            ("apply_grace_secs", secs(b.apply_grace_secs)),
            ("retain_previous_secs", secs(b.retain_previous_secs)),
            (
                "program_path",
                b.program_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
            ),
        ]
    };
    match current {
        Some(current) => {
            if block == current {
                return Ok(());
            }
            for ((key, given), (_, running)) in core(block).into_iter().zip(core(current)) {
                if given != running {
                    return refuse(key);
                }
            }
            let keys = block.settings.keys().chain(current.settings.keys());
            for key in keys {
                if block.settings.get(key) != current.settings.get(key) {
                    return refuse(key);
                }
            }
            // Equal key by key yet unequal as a whole cannot happen; refuse rather than assume.
            refuse("a key")
        }
        None => {
            for (key, given) in core(block) {
                if key != "type" && given.is_some() {
                    return refuse(key);
                }
            }
            let program_key = plugin
                .defaults()
                .program
                .is_none()
                .then(|| plugin.program_key());
            match block
                .settings
                .keys()
                .find(|key| Some(key.as_str()) != program_key)
            {
                Some(key) => refuse(key),
                None => Ok(()),
            }
        }
    }
}

/// Variables that steer which code a program loads — the dynamic loader's, `PATH` and Windows'
/// `PATHEXT` and `COMSPEC`, the hooks and search paths of common runtimes — refused in a delivered
/// block whatever `delivered_env` allows (ADR-0017 clause 38). Compared without regard to case, as
/// Windows compares environment names.
const LOADING_NAMES: &[&str] = &[
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "OPENSSL_CONF",
    "OPENSSL_ENGINES",
    "DOTNET_STARTUP_HOOKS",
    "NODE_OPTIONS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PERLLIB",
    "PERL5LIB",
    "PERL5OPT",
    "PERL5DB",
    "RUBYLIB",
    "RUBYOPT",
    "BASH_ENV",
    "ENV",
];

/// Prefixes of the same kind: the loaders' own and the .NET profilers'.
const LOADING_PREFIXES: &[&str] = &["LD_", "DYLD_", "COR_PROFILER", "CORECLR_PROFILER"];

fn steers_loading(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    LOADING_NAMES.contains(&upper.as_str())
        || LOADING_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
}

/// Whether `value` names `root` or a path under it: each piece between the separators of a path
/// list, an option and its value, or words is compared from its start after lexically resolving
/// `.`, `..` and repeated separators, so `-javaagent:<root>/x.jar` and `<root>/a/../b` are caught
/// alike, and the same directory names further down another path are not. With `windows`, `/` and `\` are one separator and case is ignored, as Windows
/// resolves paths. A false match refuses a value the operator can still write; a missed one would
/// load a file no one signed.
fn names_path_under(value: &str, root: &str, windows: bool) -> bool {
    let separator = if windows { '\\' } else { '/' };
    let fold = |text: &str| {
        if windows {
            text.replace('/', "\\").to_lowercase()
        } else {
            text.to_owned()
        }
    };
    let root = resolve_lexically(&fold(root), separator);
    if root.is_empty() || root == separator.to_string() {
        return false;
    }
    let pieces: &[char] = if windows {
        &[';', ',', '=', '"', '\'', ' ', '\t', '\n', '\r']
    } else {
        &[':', ';', ',', '=', '"', '\'', ' ', '\t', '\n', '\r']
    };
    let starts_at_root = |path: &str| {
        let path = resolve_lexically(path, separator);
        path.strip_prefix(root.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(separator))
    };
    fold(value).split(pieces).any(|piece| {
        starts_at_root(piece)
            // On Windows a path also starts after the `:` that ends an option and precedes a
            // drive letter, as in `-javaagent:C:\…`; on Unix `:` already separates the pieces.
            || (windows
                && piece.match_indices(':').any(|(at, _)| {
                    let rest = &piece[at + 1..];
                    let mut chars = rest.chars();
                    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                        && chars.next() == Some(':')
                        && starts_at_root(rest)
                }))
    })
}

/// `path` with empty and `.` components dropped and each `..` taking the component before it,
/// without touching the filesystem.
fn resolve_lexically(path: &str, separator: char) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split(separator) {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    let joined = parts.join(&separator.to_string());
    if path.starts_with(separator) {
        format!("{separator}{joined}")
    } else {
        joined
    }
}

/// A delivered `env` entry is kept from the running block, or allowed by name — never a variable
/// that steers loading, and never a value pointing into the Supervisors' own directories, by
/// placeholder or by a path under one of `roots`, where the Server delivers files no one signed.
fn check_delivered_env(
    block: &SupervisorBlock,
    current: Option<&toml::Table>,
    allowed: &[String],
    roots: &[String],
) -> Result<(), String> {
    let Some(env) = block.settings.get("env").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let running = current
        .and_then(|settings| settings.get("env"))
        .and_then(toml::Value::as_table);
    for (name, value) in env {
        if running.and_then(|running| running.get(name)) == Some(value) {
            continue;
        }
        if steers_loading(name) {
            return Err(format!(
                "supervisor {:?}: a delivered block may not set {name} — it would steer which \
                 code the program loads",
                block.name
            ));
        }
        if value.as_str().is_some_and(|value| {
            value.contains("${config_dir}")
                || value.contains("${supervisor_dir}")
                || roots
                    .iter()
                    .any(|root| names_path_under(value, root, cfg!(windows)))
        }) {
            return Err(format!(
                "supervisor {:?}: a delivered block may not point {name} into its own \
                 directories — the Server delivers files there that no one signed",
                block.name
            ));
        }
        let upper = name.to_ascii_uppercase();
        let permitted = allowed
            .iter()
            .map(|pattern| pattern.to_ascii_uppercase())
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => upper.starts_with(prefix),
                None => pattern == upper,
            });
        if !permitted {
            return Err(format!(
                "supervisor {:?}: a delivered block may not set {name} — allow it in \
                 [supervisors] delivered_env in this Client's supervisor.toml",
                block.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Windows a path under the Supervisors' root is found whatever its case and whichever
    /// slash it uses, inside a path list or after an option; a sibling and a drive's root are not
    /// under it.
    /// Verifies: ADR-0017
    #[test]
    fn a_windows_path_under_the_root_is_found_without_regard_to_case_or_slash() {
        let root = r"C:\ProgramData\Fleet\supervisors";
        for value in [
            r"c:\programdata\fleet\SUPERVISORS\agent\config\x.dll",
            "C:/ProgramData/Fleet/supervisors/agent/config/x.dll",
            r"C:\Windows;C:\ProgramData\Fleet\Other\..\supervisors\agent",
            r"-javaagent:C:\ProgramData\Fleet\supervisors\agent\config\x.jar",
        ] {
            assert!(names_path_under(value, root, true), "{value}");
        }
        for value in [r"C:\ProgramData\Fleet\supervisors-old\x", r"C:\", "info"] {
            assert!(!names_path_under(value, root, true), "{value}");
        }
        assert!(!names_path_under(r"C:\anything", r"\", true));
        assert!(!names_path_under(
            "http://gw:4318/C:/ProgramData/Fleet/supervisors/x",
            root,
            true
        ));
    }

    /// A path is under the root only when it starts there: the same directory names further down
    /// another path, or in a URL's path, are not the Supervisors' root.
    /// Verifies: ADR-0017
    #[test]
    fn a_path_is_under_the_root_only_when_it_starts_there() {
        let root = "/var/lib/fleet/supervisors";
        for value in [
            "/var/lib/fleet/supervisors/agent/config/x.so",
            "-javaagent:/var/lib/fleet/supervisors/agent/config/x.jar",
            "/opt/lib:/var/lib/fleet/x/../supervisors/agent",
        ] {
            assert!(names_path_under(value, root, false), "{value}");
        }
        for value in [
            "/srv/backup/var/lib/fleet/supervisors/x",
            "http://gw:4318/var/lib/fleet/supervisors/x",
            "relative/var/lib/fleet/supervisors/x",
        ] {
            assert!(!names_path_under(value, root, false), "{value}");
        }
    }
}
