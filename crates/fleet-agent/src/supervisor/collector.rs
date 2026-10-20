//! The `collector` plugin: the Collector Supervisor (ADR-0017). It owns an OpenTelemetry
//! Collector: spawns the configured binary with one `--config` flag per written config-map
//! entry — the Collector merges multiple configs itself, so no YAML is touched here — and
//! restarts it when a new remote configuration arrives. Until a configuration exists nothing
//! runs and the Agent reports "awaiting configuration".
//!
//! A Collector carrying the `opampextension` additionally reports its own description, health,
//! and effective configuration to the Supervisor Endpoint; one without it is observed from the
//! outside. Either way it is the same plugin (goal 16 versus plain supervision).

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::debug;

use crate::supervisor::ports::{parse_settings, Plugin, ProcessCommand, SupervisorContext};
use crate::supervisor::process::{Preflight, ProcessSpec, Runner, VersionProbe};

/// The block's plugin-specific keys, parsed strictly — a typo fails startup, per ADR-0010.
///
/// `binary` is not among them: the core takes it out and resolves it (ADR-0017), and what arrives
/// here is [`SupervisorContext::program`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorSettings {
    /// Extra arguments, appended after the `--config` flags.
    #[serde(default)]
    args: Vec<String>,
    /// Additional environment for the Collector process. Environment is not a `command`-only
    /// feature — a Collector's config reads `${env:VAR}` too — so it is honoured here just as the
    /// command plugin honours it, values expanded through the same placeholders (ADR-0017).
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// The Collector's process spec: one `--config` per written entry, then the operator's extra args,
/// with its environment. `None` until a configuration exists — the Collector does not run on
/// nothing. Extracted from the build closure so the environment threading has a regression test.
fn collector_spec(
    program: &Path,
    config_dir: &Path,
    extra_args: &[String],
    env: &[(String, String)],
) -> Option<ProcessSpec> {
    // Only the entries that *are* configuration: supplementary content (ADR-0023) sits in the same
    // directory for the Collector to read by path, and handing it over as `--config` is exactly
    // what the role exists to prevent.
    let entries = crate::storage::config_entries(config_dir);
    if entries.is_empty() {
        return None;
    }
    // Which files the Collector is about to be handed. This spec is rebuilt on every (re)start, so
    // the line stands between "a configuration arrived" and "the Collector restarted" — which is
    // where *"it is still running the old configuration"* is settled: the entries are written
    // before the respawn, so a set that does not match what the Server sent is a storage question
    // and one that matches is a Collector question. Neither is answerable from the outside today.
    debug!(
        config_dir = %config_dir.display(),
        configs = ?entries.iter().map(|e| e.display().to_string()).collect::<Vec<_>>(),
        "collector configuration in force"
    );
    let mut args = Vec::with_capacity(entries.len() * 2 + extra_args.len());
    for entry in entries {
        args.push("--config".to_string());
        args.push(entry.to_string_lossy().into_owned());
    }
    args.extend(extra_args.iter().cloned());
    Some(ProcessSpec {
        program: program.to_path_buf(),
        args,
        env: env.to_vec(),
        working_dir: None,
        // One process, no worker of its own — signalling a group would gain nothing (ADR-0017 clause 56).
        own_process_group: false,
        // A Collector writes nothing outside what the install and the config
        // directory already provide.
        ensure_dirs: Vec::new(),
    })
}

pub struct CollectorPlugin;

impl Plugin for CollectorPlugin {
    fn kind(&self) -> &'static str {
        "collector"
    }

    fn program_key(&self) -> &'static str {
        "binary"
    }

    /// Nothing: a Collector's distribution is a decision the block states (ADR-0017), and a
    /// Foreign Agent is by definition one nobody has written a wrapper for.
    fn defaults(&self) -> crate::supervisor::ports::KindDefaults {
        crate::supervisor::ports::KindDefaults {
            // The one exception to "knows nothing": something *does* connect to a Collector's
            // Endpoint — the `opampextension` — so pinning its port is a decision that has a place.
            endpoint_port: true,
            ..crate::supervisor::ports::KindDefaults::none()
        }
    }

    fn start(&self, mut ctx: SupervisorContext) -> Result<mpsc::Sender<ProcessCommand>, String> {
        // Taken out rather than consumed with `ctx`, because the placeholder expansion below is a
        // method on the context and needs it whole.
        let settings: CollectorSettings = parse_settings(
            &ctx.name,
            self.kind(),
            &[],
            std::mem::take(&mut ctx.settings),
        )?;
        // Everything the operator wrote about *where* things are goes through the placeholders
        // (ADR-0017) — the same for the Collector's extra args and its environment as for a command.
        let extra_args: Vec<String> = settings.args.iter().map(|a| ctx.expand(a)).collect();
        let env: Vec<(String, String)> = settings
            .env
            .iter()
            .map(|(k, v)| (k.clone(), ctx.expand(v)))
            .collect();
        let config_dir = ctx.config_dir;
        let binary = ctx.program;
        let install = ctx.install;
        let (commands, command_rx) = mpsc::channel(16);
        let runner = Runner {
            endpoint_token: ctx.endpoint_token.clone(),
            name: ctx.name,
            stop_timeout: ctx.stop_timeout,
            apply_grace: ctx.apply_grace,
            retain_previous: ctx.retain_previous,
            // A package (ADR-0026) swaps this Collector's program — one file, or a whole tree.
            install: Some(install),
            archive_key: ctx.archive_key,
            // The Collector states its version on `--version`, so even one without the
            // opampextension (which never self-reports) shows its own version rather than none.
            // The Runner asks at startup and again after every swap; an extension's self-report
            // overwrites the probed value.
            version_probe: Some(VersionProbe {
                // The Collector's banner is strict SemVer; the default read is the right one.
                parse: None,
                program: binary.clone(),
                args: vec!["--version".to_string()],
            }),
            // The same `--version`, asked of the *staged* program before the running one is stopped
            // (ADR-0017). It is the same question the probe above asks and the same cost, so asking
            // it early costs nothing: otherwise the swap itself would be the first thing to try a
            // new binary, and a build the host cannot run — one linked against a libc newer than
            // this host's — would pay for that with a stop, a swap, a failed start and a rollback
            // instead of a refusal that touches nothing.
            //
            // No environment: the probe already invokes the live program bare, so a Collector that
            // needs one to answer `--version` would report no version today either.
            preflight: Some(Preflight {
                args: vec!["--version".to_string()],
                env: Vec::new(),
            }),
            // The Collector has no reload convention — a configuration is applied by restart,
            // the generic behaviour (ADR-0017), which is also what the reference supervisor does.
            reload_signal: None,
            events: ctx.events,
            commands: command_rx,
            build: Box::new(move || collector_spec(&binary, &config_dir, &extra_args, &env)),
        };
        tokio::spawn(runner.run(ctx.shutdown));
        Ok(commands)
    }

    fn check(&self, name: &str, settings: toml::Table) -> Result<(), String> {
        parse_settings::<CollectorSettings>(name, self.kind(), &[], settings).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `binary` is gone from these settings — the core resolves it (ADR-0017) — so a block that
    /// still carries it here would be an unknown key, which is exactly what must fail.
    #[test]
    fn settings_parse_strictly() {
        let table: toml::Table = toml::from_str("args = [\"--feature-gates=x\"]\n").expect("table");
        let settings: CollectorSettings = table.try_into().expect("settings");
        assert_eq!(settings.args, vec!["--feature-gates=x".to_string()]);

        let typo: toml::Table = toml::from_str("arg = [\"--x\"]").expect("table");
        assert!(typo.try_into::<CollectorSettings>().is_err());
    }

    /// `[supervisor.env]` is accepted on a collector block — environment is not a `command`-only
    /// feature.
    #[test]
    fn env_parses() {
        let table: toml::Table =
            toml::from_str("[env]\nOTLP_HTTP_ENDPOINT = \"127.0.0.1:4318\"\n").expect("table");
        let settings: CollectorSettings = table.try_into().expect("settings");
        assert_eq!(
            settings.env.get("OTLP_HTTP_ENDPOINT").map(String::as_str),
            Some("127.0.0.1:4318")
        );
    }

    /// The built spec must carry the environment, not an empty vector. A configuration entry has to
    /// exist first, since the Collector does not run on nothing.
    #[test]
    fn the_spec_carries_the_environment() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Empty config directory: no spec at all.
        assert!(collector_spec(Path::new("otelcol"), dir.path(), &[], &[]).is_none());

        // One written configuration entry (a plain, non-dot file), and an environment to pass.
        std::fs::write(dir.path().join("fleet"), b"service: {}\n").expect("write entry");
        let env = vec![(
            "OTLP_HTTP_ENDPOINT".to_string(),
            "127.0.0.1:4318".to_string(),
        )];
        let spec = collector_spec(
            Path::new("otelcol"),
            dir.path(),
            &["--feature-gates=x".to_string()],
            &env,
        )
        .expect("a spec once a configuration exists");

        assert_eq!(
            spec.env, env,
            "the operator's environment reaches the process"
        );
        assert!(
            spec.args.iter().any(|a| a == "--config"),
            "the written entry is passed as --config"
        );
        assert!(
            spec.args.iter().any(|a| a == "--feature-gates=x"),
            "extra args follow the --config flags"
        );
    }
}
