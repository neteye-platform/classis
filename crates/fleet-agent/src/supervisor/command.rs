//! The `command` plugin: the example Custom Supervisor (ADR-0017). It brings a Foreign Agent —
//! any process started by a command-line invocation — under management: spawned as configured,
//! restarted when a remote configuration arrives (the files land in the Supervisor's
//! `config/` directory for the process to re-read), health derived from the outside.

use std::collections::BTreeMap;

use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::debug;

use crate::supervisor::ports::{parse_settings, Plugin, ProcessCommand, SupervisorContext};
use crate::supervisor::process::{Preflight, ProcessSpec, Runner, VersionProbe};

/// The block's plugin-specific keys, parsed strictly — a typo fails startup, per ADR-0010.
///
/// `command` is not among them: the core takes it out and resolves it (ADR-0017), and what
/// arrives here is [`SupervisorContext::program`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandSettings {
    /// Its arguments, verbatim.
    #[serde(default)]
    args: Vec<String>,
    /// Additional environment for the process.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Arguments that make the command print its version (e.g. `["--version"]`). When set, the
    /// command is invoked once with exactly these arguments and the first Semantic Versioning
    /// 2.0.0 version in its output becomes the Agent's `service.version`. A Foreign Agent's
    /// version flag is its own convention — hence opt-in, unlike the Collector's.
    ///
    /// They are also this kind's **preflight** (ADR-0017 clause 57): a package's staged program is run with
    /// them before the running one is stopped, and a non-zero exit refuses the package with the
    /// program's own message. Same arguments, same contract — a check that is cheap and touches
    /// no state — asked where a refusal costs nothing rather than after the swap.
    #[serde(default)]
    version_args: Option<Vec<String>>,
}

/// The keys this kind does not take (ADR-0017), each with what answers it. Refused by name rather
/// than met with serde's "unknown field", for the reason `icinga2` refuses its own: a block
/// carrying one expects a Client that needs it, and the operator deleting the line deserves to be
/// told where the value went.
const RETIRED: &[(&str, &str)] = &[
    (
        "working_dir",
        "a Managed Process starts in the directory its program lives in",
    ),
    (
        "reload_signal",
        "whether a program re-reads its configuration on a signal is the program's own convention \
         and belongs in a kind that knows it — an unwrapped agent applies by restarting",
    ),
];

pub struct CommandPlugin;

impl Plugin for CommandPlugin {
    fn kind(&self) -> &'static str {
        "command"
    }

    fn program_key(&self) -> &'static str {
        "command"
    }

    /// Nothing at all. This is the kind for an agent nobody has written a wrapper for, so every
    /// value is the operator's to state (ADR-0017).
    fn defaults(&self) -> crate::supervisor::ports::KindDefaults {
        crate::supervisor::ports::KindDefaults::none()
    }

    fn start(&self, mut ctx: SupervisorContext) -> Result<mpsc::Sender<ProcessCommand>, String> {
        // Taken out rather than consumed with `ctx`, because the placeholder expansion below is a
        // method on the context and needs it whole.
        let settings: CommandSettings = parse_settings(
            &ctx.name,
            self.kind(),
            RETIRED,
            std::mem::take(&mut ctx.settings),
        )?;
        // Everything the operator wrote about *where* things are goes through the placeholders
        // (ADR-0017) — the program itself deliberately does not.
        let args: Vec<String> = settings.args.iter().map(|a| ctx.expand(a)).collect();
        let env: Vec<(String, String)> = settings
            .env
            .iter()
            .map(|(k, v)| (k.clone(), ctx.expand(v)))
            .collect();
        let command = ctx.program;
        let install = ctx.install;
        let (commands, command_rx) = mpsc::channel(16);
        // Asked at startup and again after every package swap, so a Foreign Agent the Server
        // updated describes the version it now runs rather than the one it replaced.
        let version_probe = settings.version_args.clone().map(|args| VersionProbe {
            program: command.clone(),
            args,
            // A Foreign Agent's version flag is its own convention, and so is its banner: the
            // strict SemVer read stays the default here (ADR-0017 clause 58).
            parse: None,
        });
        // The same arguments, asked of the *staged* program before the running one is stopped
        // (ADR-0017). This kind knows no argument of its own to be safe to run — but an operator
        // who set `version_args` has named one: the contract on that key is that the command may
        // be invoked with exactly these and will print its version, which is precisely a check
        // that is cheap and touches no state. Nothing new is asked of anyone; the arguments that
        // already run after every swap now also run before one, where a refusal is free.
        //
        // Unset, this stays `None` and the kind behaves exactly as it did. No environment either,
        // for the reason the probe has none: these arguments have always been invoked bare, so any
        // that need one to succeed report no version today.
        let preflight = settings.version_args.clone().map(|args| Preflight {
            args,
            env: Vec::new(),
        });
        // What this Foreign Agent will actually be invoked with, after the placeholders were
        // expanded (ADR-0017). The spawn line names the program; the arguments are where a
        // placeholder that did not resolve — or a working directory that is not the one the
        // operator meant — becomes visible, and the process itself usually reports neither.
        //
        // **The environment is logged by key, never by value.** Both are the operator's, and a
        // Foreign Agent's environment is exactly where a token or a password is handed to it
        // (ADR-0021's reasoning, applied to a Managed Process). Which variables are set answers
        // "did my configuration reach it"; their contents answer nothing this line is for.
        debug!(
            supervisor = %ctx.name,
            program = %command.display(),
            args = ?args,
            env = ?env.iter().map(|(key, _)| key.as_str()).collect::<Vec<_>>(),
            "foreign agent invocation"
        );
        let runner = Runner {
            endpoint_token: ctx.endpoint_token.clone(),
            name: ctx.name,
            stop_timeout: ctx.stop_timeout,
            apply_grace: ctx.apply_grace,
            retain_previous: ctx.retain_previous,
            // A package (ADR-0026) swaps this command's program — one file, or a whole tree.
            install: Some(install),
            archive_key: ctx.archive_key,
            version_probe,
            preflight,
            // Not this kind's to know (ADR-0017): an agent nobody wrote a wrapper for applies a
            // configuration by restarting, which is ADR-0017's generic behaviour.
            reload_signal: None,
            events: ctx.events,
            commands: command_rx,
            // A Foreign Agent has its own configuration until told otherwise: it always runs.
            build: Box::new(move || {
                Some(ProcessSpec {
                    program: command.clone(),
                    args: args.clone(),
                    env: env.clone(),
                    // The program's own directory (ADR-0017), resolved at the spawn.
                    working_dir: None,
                    // Whatever the operator points this at is supervised as one process.
                    own_process_group: false,
                    // Nothing: this kind knows no agent, so it knows no directory an
                    // agent of it would write into. An operator whose Foreign Agent needs one
                    // states the path in its own configuration, where the agent can make it.
                    ensure_dirs: Vec::new(),
                })
            }),
        };
        tokio::spawn(runner.run(ctx.shutdown));
        Ok(commands)
    }

    fn check(&self, name: &str, settings: toml::Table) -> Result<(), String> {
        parse_settings::<CommandSettings>(name, self.kind(), RETIRED, settings).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `command` is gone from these settings — the core resolves it (ADR-0017) — so a block that
    /// still carries it here would be an unknown key, which is exactly what must fail.
    #[test]
    fn settings_parse_strictly() {
        let table: toml::Table = toml::from_str(
            r#"
            args = ["--a"]
            version_args = ["--version"]
            [env]
            K = "v"
            "#,
        )
        .expect("table");
        let settings: CommandSettings = table.try_into().expect("settings");
        assert_eq!(settings.env.get("K").map(String::as_str), Some("v"));
        assert_eq!(settings.version_args, Some(vec!["--version".to_string()]));

        let typo: toml::Table = toml::from_str("comand = \"/x\"").expect("table");
        assert!(typo.try_into::<CommandSettings>().is_err());
    }

    /// The two keys ADR-0017 retires are refused by name, on both sides of the seam: at startup,
    /// and in an offered Supervisor set before any running process is touched (ADR-0017). Each
    /// message says what supplies the value now, because a block carrying one was written against
    /// a Client that took it.
    #[test]
    fn the_retired_keys_are_refused_by_name() {
        for (key, line) in [
            ("working_dir", "working_dir = \"/tmp\""),
            ("reload_signal", "reload_signal = \"HUP\""),
        ] {
            let table: toml::Table = toml::from_str(line).expect("table");
            let err = CommandPlugin.check("agent", table).expect_err(key);
            assert!(err.contains(key), "{err}");
            assert!(err.contains("no longer a supervisor key"), "{err}");
        }
    }
}
