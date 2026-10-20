//! The daemon body (ADR-0019): the same loop whether started standalone in the foreground or
//! under a service manager, stopping cleanly on a shutdown request instead of running forever.
//!
//! systemd and launchd stop a service with `SIGTERM`; the Windows SCM delivers a Stop control.
//! Both funnel into one [`Shutdown`] handle the transports select on, so the clean-shutdown
//! `agent_disconnect` goodbye (the Baseline's final message) fires on every stop path, not only
//! on Ctrl-C.

use std::path::PathBuf;

use crate::shutdown::{shutdown_channel, Shutdown};

use crate::config::ClientConfig;
use crate::connection;
use crate::supervisor;
use crate::transport::{self, RunOutcome};

/// What a daemon run needs to know: where the configuration file is, and an optional state-dir
/// override (`--state-dir`, baked into installed units so they never depend on a relative path).
#[derive(Debug, Clone)]
pub struct RunSpec {
    /// Path to `supervisor.toml` (ADR-0010); defaults apply if the file does not exist.
    pub config_path: PathBuf,
    /// Overrides the configuration file's `state_dir` when present.
    pub state_dir: Option<PathBuf>,
    /// Started by the machine's service manager rather than by a person (ADR-0019). Set from the
    /// hidden `--service` marker `service install` writes into the command line on every platform,
    /// and the whole of the condition for writing the log file: it says no terminal is watching.
    pub service: bool,
}

/// How a daemon run ended, which decides how the process leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The operator stopped it. A clean exit, and the service manager leaves it stopped.
    Normal,
    /// A self-update switched to a new version (ADR-0018). The process must exit *non-zero* so
    /// the manager's restart-on-failure brings the new version up: none of the three managers
    /// offers "restart on success", and issuing the restart from inside the unit deadlocks.
    RestartForUpdate,
}

/// Starts Gateway Mode when `[gateway]` arms it (ADR-0015), or nothing when it does not.
///
/// It runs as its own task rather than inside the transport loop: the downstream endpoint's
/// lifetime is the process's, not one upstream connection's, and an Agent behind the Gateway must
/// not lose its endpoint because this Client's own connection dropped.
fn spawn_gateway(
    config: &ClientConfig,
    shutdown: &Shutdown,
) -> Option<tokio::task::JoinHandle<()>> {
    config.gateway.as_ref()?;
    let config = std::sync::Arc::new(config.clone());
    let shutdown = shutdown.clone();
    Some(tokio::spawn(async move {
        if let Err(e) = crate::gateway::run(config, shutdown).await {
            tracing::error!(error = %e, "gateway mode stopped");
        }
    }))
}

/// The stack of every thread the daemon runs on: the 8 MiB a Linux main thread has, where the
/// daemon has always run. Windows gives its main thread 1 MiB and the thread the SCM starts a
/// service on no more, and the daemon's future overflowed that the moment it applied offered
/// connection settings — so the daemon never runs on a thread whose stack it did not choose.
pub const DAEMON_STACK_SIZE: usize = 8 * 1024 * 1024;

/// The runtime the daemon runs on, its worker threads sized by [`DAEMON_STACK_SIZE`]. Both entry
/// points build it: [`run_foreground`] and the Windows SCM shim.
///
/// # Errors
/// Returns an error if the runtime cannot be built.
pub fn daemon_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(DAEMON_STACK_SIZE)
        .build()
        .map_err(|e| format!("cannot build the tokio runtime: {e}"))
}

/// Runs `daemon` as a task on one of [`daemon_runtime`]'s workers instead of on the thread that
/// blocks on the runtime, whose stack belongs to the platform. A panic in it stays a panic.
pub async fn on_a_worker<F>(daemon: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match tokio::spawn(daemon).await {
        Ok(output) => output,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// Build the runtime and run the daemon until the platform shutdown signal (`SIGTERM`/`SIGINT` on
/// Unix, Ctrl-C on Windows). The standalone foreground path; the Windows SCM shim supplies its own
/// runtime and shutdown source and calls [`run_until_shutdown`] directly.
///
/// # Errors
/// Returns an error if the runtime cannot be built or the daemon fails to start.
pub fn run_foreground(spec: RunSpec) -> Result<(), String> {
    let runtime = daemon_runtime()?;
    let exit = runtime.block_on(async {
        let (tx, shutdown) = shutdown_channel();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = tx.send(true);
        });
        #[cfg(unix)]
        tokio::spawn(ignore_sighup());
        on_a_worker(run_until_shutdown(spec, shutdown)).await
    })?;
    if exit == Exit::RestartForUpdate {
        // Not an error, but it has to look like one: systemd's `Restart=on-failure` and launchd's
        // `KeepAlive{SuccessfulExit:false}` are the only "bring it back" either offers, and a
        // clean exit is precisely what tells them not to (ADR-0019, ADR-0018).
        tracing::info!("exiting so the service manager starts the newly installed version");
        std::process::exit(crate::update::EXIT_RESTART_FOR_UPDATE);
    }
    Ok(())
}

/// Opens the Client's own log file for a service run (ADR-0019).
///
/// **A log that cannot be written never stops the Client.** A directory the installer did not make
/// writable, or a full disk, is reported on stderr — which the SCM discards, which is the whole
/// problem, so it also stays visible to anyone running the same command by hand — and the run
/// continues. A monitoring agent that refuses to start because it could not open its own log has
/// turned a diagnostic into an outage.
fn start_log_file(config: &crate::config::ClientConfig) {
    if !config.logging.enabled {
        return;
    }
    let dir = config
        .logging
        .dir
        .clone()
        .unwrap_or_else(|| crate::logging::default_dir(&config.state_dir));
    match crate::logging::open(&dir, config.logging.keep) {
        Ok(dir) => {
            tracing::info!(dir = %dir.display(), keep = config.logging.keep, "logging to file")
        }
        Err(e) => tracing::warn!(error = %e, "running without a log file"),
    }
}

/// What this process is and what it will use, in one line each, before it uses any of it.
///
/// **The version is the point of the first line.** It rides in every report to the Server and names
/// the directory this binary runs from (ADR-0019), and logged here it lets the file a self-update
/// leaves behind (ADR-0018, ADR-0019) be attributed to the version that wrote it, which is the
/// situation that file exists for. The rest of the line is what an operator otherwise has to
/// reconstruct from the command line of a service they did not start.
///
/// **The second line is the trust and the identity in force**, resolved through the same two
/// accessors the transports build their TLS from (ADR-0013, ADR-0021) rather than read off the
/// configuration — so it states what *will* be presented, including a Server-issued certificate
/// that no `supervisor.toml` mentions. Without it, a handshake that fails because the identity is
/// not the one anybody assumed is diagnosed from the peer's error message, which is written by the
/// end that knows least about it.
fn announce(config: &ClientConfig, config_path: &std::path::Path) {
    // A missing file is not an error — `ClientConfig::load` runs on defaults, deliberately, so a
    // Client can start before anything is written. It is worth a word all the same: a mistyped
    // `--config` produces exactly this, and the result is a Client that starts cleanly, points at
    // the default endpoint and supervises nothing, which reads like a healthy start. Said here
    // rather than in `config`, which parses and does not log.
    if !config_path.exists() {
        tracing::warn!(
            config = %config_path.display(),
            "no configuration file there; running on defaults"
        );
    }
    tracing::info!(
        version = fleet_core::version::current(),
        config = %config_path.display(),
        state_dir = %config.state_dir.display(),
        endpoint = %config.endpoint,
        supervisors = config.supervisors.len(),
        "client starting"
    );
    let (trust, identity) = tls_posture(config);
    tracing::info!(trust = %trust, client_certificate = %identity, "outbound tls");
}

/// What the transports will trust, and what they will present — as the two strings the line above
/// reports.
///
/// Its own function because it makes a claim worth a test: the certificate named here is whichever
/// [`ClientConfig::client_identity`] resolves to, which prefers the **Server-issued** one in the
/// state directory over anything `[tls]` names (ADR-0021). A line that reported the configured
/// certificate while the connection presented the issued one would be worse than no line at all.
fn tls_posture(config: &ClientConfig) -> (String, String) {
    let trust = config.ca_file().map_or_else(
        || "the built-in roots".to_string(),
        |ca| ca.display().to_string(),
    );
    let identity = config.client_identity().map_or_else(
        || "none".to_string(),
        |(cert, _)| cert.display().to_string(),
    );
    (trust, identity)
}

/// What a run does when its configuration cannot be read: resolve the update in flight anyway, so
/// the failure counts (ADR-0018).
///
/// Returns `RestartForUpdate` when that resolution rolled the Client back — the pointer now names
/// the version that *could* read this file, and the manager must start it — and otherwise hands the
/// configuration error back to be reported and exited on, one attempt closer to that rollback.
///
/// Without this, the net catches everything except the one failure a *new* version is most likely
/// to bring: a file it refuses. A removed configuration key is exactly that
/// ([ADR-0017](../../../../docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)), and for some kinds there
/// is no block both versions accept, so the cutover per host cannot be avoided — only caught.
fn unreadable_config(spec: &RunSpec, error: String) -> Result<Exit, String> {
    let state_dir = recovery_state_dir(spec);
    tracing::error!(error = %error, state_dir = %state_dir.display(), "cannot read the configuration");
    match crate::update::installer::on_start(&state_dir) {
        Ok(crate::update::installer::Startup::RolledBack(_)) => Ok(Exit::RestartForUpdate),
        // Counted, or nothing was in flight. Either way this run cannot continue.
        _ => Err(error),
    }
}

/// Where to look for the update marker when the configuration did not load.
///
/// Three sources, in the order of how much they can be trusted to be right. `--state-dir` is what an
/// installed service passes (`service install` bakes it into the unit), so the case that matters —
/// a service updating itself into a file it cannot read — is answered by the command line alone. A
/// foreground run falls back to reading **only** `state_dir` out of the file, leniently: the file
/// that fails to load usually parses as TOML and fails on a key's meaning, so its own answer is
/// still there to be read. What is left is the default, which is right for a Client that never
/// named one.
fn recovery_state_dir(spec: &RunSpec) -> PathBuf {
    if let Some(dir) = &spec.state_dir {
        return dir.clone();
    }
    std::fs::read_to_string(&spec.config_path)
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|table| {
            table
                .get("state_dir")
                .and_then(toml::Value::as_str)
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| ClientConfig::default().state_dir)
}

/// Load the configuration, build the Engine (the configured Supervisors, or the self-Agent when
/// none are), and run the transport the endpoint selects (ADR-0013) until `shutdown` fires.
///
/// # Errors
/// Returns an error if the configuration cannot be loaded or the Agent state cannot be restored.
pub async fn run_until_shutdown(spec: RunSpec, mut shutdown: Shutdown) -> Result<Exit, String> {
    heal_torn_pointer();
    let mut config = match load_effective_config(&spec) {
        Ok(config) => config,
        // A version that cannot read this host's file is a failed update like any other, and one
        // the probation of ADR-0018 would not see on its own: the load happens before `on_start`,
        // so the process would leave before the attempt was counted, the manager would restart it,
        // and the host would stay on a version that never reaches the Server to say so.
        Err(error) => return unreadable_config(&spec, error),
    };
    // A certificate swap a crash cut short is completed before the identity in force is read.
    crate::csr::recover(&config.state_dir)?;
    // Without a client certificate the Server refuses this Client; it says so and stops rather
    // than retrying for ever (ADR-0021).
    config
        .check_admission()
        .map_err(|e| format!("{}: {e}", spec.config_path.display()))?;
    if spec.service {
        start_log_file(&config);
    }
    // After the log file, so the line that says which version is running is the first line *in the
    // file* — a log whose opening line is already about work in progress starts one step too late.
    announce(&config, &spec.config_path);
    // Once per start, not per reconnect: a leftover [auth] is ignored and nothing from it is sent
    // (ADR-0021 clause 3).
    if let Some(notice) = config.leftover_auth_notice() {
        tracing::warn!(config = %spec.config_path.display(), "{notice}");
    }

    // Resolve any self-update in flight before anything else runs (ADR-0018): this process may be
    // a freshly installed version on probation, or the previous one brought back after a rollback.
    let startup = crate::update::installer::on_start(&config.state_dir)?;
    let (probation, owed_outcome) = match startup {
        crate::update::installer::Startup::Ordinary => (None, None),
        crate::update::installer::Startup::OnProbation(marker) => (Some(*marker), None),
        crate::update::installer::Startup::Outcome(outcome) => (None, Some(*outcome)),
        // `current` now names the previous version and this one is not it. Nothing is served
        // from here; the manager restarts and the version it starts reports the failure.
        crate::update::installer::Startup::RolledBack(_) => return Ok(Exit::RestartForUpdate),
    };

    let mut engine = supervisor::build_engine(&config, &shutdown)?;
    if config.self_update_package().is_some() {
        engine.arm_self_update(crate::update::installer::Installer::new(
            config.state_dir.clone(),
            config.packages.as_ref().and_then(|p| p.archive_key.clone()),
            probation,
        ));
    }
    // There is no unsigned posture (ADR-0026, ADR-0018): without `[packages] verification_key` no
    // Agent of this Client takes packages, its own self-update included. Said once at startup, since
    // the Server only sees an Agent that declares no package capability.
    if config.package_key().is_none() {
        tracing::warn!(
            "taking no packages and no self-update: [packages] verification_key is not set, and \
             nothing is installed without a signature. Set it to the hex Ed25519 key \
             your packages are signed with."
        );
    }
    if let Some(outcome) = &owed_outcome {
        // The install finished in another process; this one owes the Server its terminal status.
        engine.report_self_update_outcome(
            hex::decode(&outcome.package_hash_hex).unwrap_or_default(),
            match &outcome.error {
                None => Ok(outcome.version.clone()),
                Some(error) => Err(error.clone()),
            },
        );
        crate::update::installer::clear_outcome(&config.state_dir);
    }
    // Own telemetry (ADR-0016) is owned here rather than by a transport loop, because the
    // destinations outlive a connection: a reconnect must not tear the exporters down, and a
    // verified new offer is what replaces them.
    let telemetry = crate::telemetry::Telemetry::new();
    let mut system = sysinfo::System::new();
    let sampling = engine.sampling_handle();

    // Gateway Mode (ADR-0015), if armed: a downstream endpoint and an upstream pool, running
    // beside everything else. It is restarted when a verified offer moves this Client's endpoint,
    // since the pool dials that endpoint and would otherwise keep reaching for the old one.
    let mut gateway = spawn_gateway(&config, &shutdown);
    if let Some(stored) = connection::load(&config.state_dir) {
        // A restarted Client reports the persisted settings APPLIED, so the Server does not
        // re-offer what it already runs (ADR-0014).
        engine.adopt_connection_settings(&stored.hash);
        // …and resumes reporting to the destinations it was last told about, before it has spoken
        // to anyone: telemetry from a Client that cannot reach the Server is the useful kind.
        let refused = telemetry.apply(&stored, &engine.self_description(), &config);
        if !refused.is_empty() {
            // And the Server hears about it. The line above just reported these settings APPLIED;
            // saying nothing here would have this Client claim, on every reconnect for the life of
            // the state directory, that a destination is in force which it refused to use
            // (ADR-0016: refused *and reported*).
            let error = refused.join("; ");
            tracing::warn!(reason = %error, "not reporting own telemetry");
            engine.connection_settings_outcome(&stored.hash, Err(&error));
        }
    }
    for uid in engine.uids() {
        tracing::info!(agent = %uid, "starting");
    }

    loop {
        // The sampler runs beside the transport, not inside it: process metrics are about the host,
        // and a Client that has lost its connection is exactly when they are worth having.
        let outcome = sample_beside(
            transport::run(&mut engine, &mut config, &mut shutdown, &telemetry),
            telemetry.sample_interval(),
            || telemetry.reporting(),
            || {
                let targets = sampling.lock().map(|t| t.clone()).unwrap_or_default();
                for target in &targets {
                    telemetry.sample(&mut system, target);
                }
            },
        )
        .await?;
        match outcome {
            // Both exits flush first: the batch exporters hold spans and log records that have not
            // left yet, and a process that simply returns drops them. The stop path is exactly when
            // the last records are worth having — a crash-and-restart is what they explain.
            RunOutcome::Shutdown => {
                telemetry.shutdown();
                return Ok(Exit::Normal);
            }
            RunOutcome::RestartForUpdate => {
                telemetry.shutdown();
                return Ok(Exit::RestartForUpdate);
            }
            // Verified connection settings took effect (ADR-0014): re-resolve the effective
            // configuration — endpoint, certificate, intervals, possibly the other transport —
            // and reconnect. The Engine (and its Managed Processes) carries on.
            RunOutcome::Reconfigured => {
                config = load_effective_config(&spec)?;
                // The telemetry destinations of the same offer are already in force: since
                // ADR-0014 `process_connection_offer` applies them before it asks for the
                // reconnect, and it composes the one acknowledgement that names anything refused.
                // Re-applying here would be a no-op through `in_force` whose only visible effect
                // was a `warn!` with no acknowledgement attached — which was the bug.
                if let Some(handle) = gateway.take() {
                    handle.abort();
                    // The listener is only released once the task has unwound; binding the new
                    // one before that races an "address already in use" that nothing retries.
                    let _ = handle.await;
                }
                gateway = spawn_gateway(&config, &shutdown);
                if config.heartbeat_interval_secs > 0 {
                    // An offered interval may enable what the file had disabled; the capability
                    // follows (the reverse never happens — 0 means "not offered").
                    engine
                        .declare_capability_all(opamp::proto::AgentCapabilities::ReportsHeartbeat);
                }
            }
        }
    }
}

/// Drives `transport` to its end, calling `sample` every `interval` while `reporting` says a
/// destination is in force (ADR-0016).
///
/// `reporting` is asked on every tick, not once: a destination offered over the connection that is
/// running comes into force halfway through `transport`. Asked once — as a `select!` precondition,
/// which disables its branch for the whole of the call — sampling started only on the next
/// reconnect, and a Client told where to report over a connection that held reported no metrics.
async fn sample_beside<T>(
    transport: impl std::future::Future<Output = T>,
    interval: std::time::Duration,
    reporting: impl Fn() -> bool,
    mut sample: impl FnMut(),
) -> T {
    tokio::pin!(transport);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // the first tick is immediate; sample on the ones after it
    loop {
        tokio::select! {
            outcome = &mut transport => return outcome,
            _ = tick.tick() => {
                if reporting() {
                    sample();
                }
            }
        }
    }
}

/// The configuration in force: `supervisor.toml` (ADR-0010), the `--state-dir` override, and the
/// persisted Server-offered connection settings on top (ADR-0014).
fn load_effective_config(spec: &RunSpec) -> Result<ClientConfig, String> {
    let mut config = ClientConfig::load(&spec.config_path)?;
    if let Some(state_dir) = &spec.state_dir {
        config.state_dir = state_dir.clone();
    }
    if let Some(stored) = connection::load(&config.state_dir) {
        connection::apply(&mut config, &stored);
    }
    Ok(config)
}

/// ADR-0019 self-heal: when running from a versioned install layout, make sure `current`
/// resolves to the directory this binary actually runs from — a crash mid-switch otherwise
/// leaves the pointer torn. Best-effort: a plain foreground run outside a layout is untouched.
fn heal_torn_pointer() {
    let Ok(exe) = super::layout::running_exe() else {
        return;
    };
    let Some((layout, running_dir)) = super::layout::Layout::enclosing(&exe) else {
        return;
    };
    match layout.heal_current(&running_dir) {
        Ok(true) => tracing::warn!(
            current = %layout.current().display(),
            "repaired the current pointer after a torn version switch"
        ),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "cannot verify the current pointer"),
    }
}

/// Resolve to the platform shutdown signal: `SIGTERM` or `SIGINT` on Unix (what systemd and
/// launchd send on stop), Ctrl-C on Windows (a console run; the SCM path never comes through
/// here).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate =
            signal(SignalKind::terminate()).expect("installing the SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// daemon(7) reserves `SIGHUP` for a configuration reload. Until that exists it is explicitly
/// ignored — the default disposition would terminate the daemon.
#[cfg(unix)]
async fn ignore_sighup() {
    use tokio::signal::unix::{signal, SignalKind};
    let Ok(mut hangup) = signal(SignalKind::hangup()) else {
        return;
    };
    while hangup.recv().await.is_some() {
        tracing::debug!("SIGHUP ignored (reserved for a future configuration reload)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A destination that comes into force while the connection holds is sampled from then on —
    /// not from the next reconnect, which on a healthy connection never comes.
    #[tokio::test(start_paused = true)]
    async fn a_destination_offered_mid_connection_is_sampled_at_once() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        let reporting = AtomicBool::new(false);
        let samples = AtomicUsize::new(0);
        let transport = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            reporting.store(true, Ordering::SeqCst); // the offer arrives over this connection
            tokio::time::sleep(Duration::from_secs(30)).await;
        };
        sample_beside(
            transport,
            Duration::from_secs(10),
            || reporting.load(Ordering::SeqCst),
            || {
                samples.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(
            samples.load(Ordering::SeqCst),
            3,
            "sampled at 10 s, 20 s and 30 s"
        );
    }

    #[tokio::test]
    async fn requested_resolves_after_the_flip_and_immediately_thereafter() {
        let (tx, mut shutdown) = shutdown_channel();
        tx.send(true).expect("send shutdown");
        // Resolves at once — and again on a second await (multi-use).
        shutdown.requested().await;
        shutdown.requested().await;
    }

    #[tokio::test]
    async fn a_dropped_sender_counts_as_shutdown() {
        let (tx, mut shutdown) = shutdown_channel();
        drop(tx);
        shutdown.requested().await;
    }

    /// The three sources, in order. `--state-dir` wins because an installed service always passes
    /// it, which is the case this recovery exists for.
    #[test]
    fn the_recovery_state_dir_prefers_the_flag_then_the_file_then_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("supervisor.toml");
        let named = dir.path().join("from-the-file");
        // Serialised as TOML rather than interpolated: a Windows path is full of backslashes, and
        // in a basic string `\U` is an invalid escape — the file was unparseable there, so the
        // lenient read fell back to the default and the test failed on Windows alone.
        std::fs::write(
            &config_path,
            format!(
                "state_dir = {}\n",
                toml::Value::from(named.to_string_lossy().into_owned())
            ),
        )
        .expect("write");

        let flagged = dir.path().join("from-the-flag");
        let spec = |state_dir: Option<PathBuf>, config: &std::path::Path| RunSpec {
            config_path: config.to_path_buf(),
            state_dir,
            service: false,
        };
        assert_eq!(
            recovery_state_dir(&spec(Some(flagged.clone()), &config_path)),
            flagged
        );
        assert_eq!(recovery_state_dir(&spec(None, &config_path)), named);
        assert_eq!(
            recovery_state_dir(&spec(None, &dir.path().join("absent.toml"))),
            ClientConfig::default().state_dir
        );
    }

    /// A configuration this version cannot read is a failed update attempt, and the marker has to
    /// be resolved rather than stepped over — otherwise the service manager restarts the version
    /// that refuses the file, for ever, and ADR-0018's rollback never fires.
    ///
    /// The test binary does not run from an install layout, so the resolution takes the "the new
    /// version did not take over" path: the marker is cleared and an outcome recorded. What is
    /// asserted is that the marker was *seen at all*.
    /// Verifies: ADR-0018
    #[test]
    fn an_unreadable_configuration_resolves_the_update_in_flight() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let marker = crate::update::installer::UpdateMarker {
            previous_dir: dir.path().join("previous"),
            new_dir: dir.path().join("new"),
            version: "9.9.9".to_string(),
            package_hash_hex: "abcd".to_string(),
            attempts: 1,
            trace: None,
        };
        // `update::installer` owns this file name; the test names it to prove the file was consumed.
        let marker_file = state_dir.join("update-marker.json");
        std::fs::write(
            &marker_file,
            serde_json::to_vec(&marker).expect("serialize"),
        )
        .expect("write the marker");

        let outcome = unreadable_config(
            &RunSpec {
                config_path: dir.path().join("supervisor.toml"),
                state_dir: Some(state_dir.clone()),
                service: true,
            },
            "supervisor \"x\": `main_config` is no longer a supervisor key".to_string(),
        );

        assert!(outcome.is_err(), "the run still ends on the configuration");
        assert!(
            !marker_file.exists(),
            "the update in flight was resolved, not stepped over"
        );
    }

    /// With nothing configured, the line says so in both halves rather than leaving an operator to
    /// read an absent field as "unknown".
    #[test]
    fn the_tls_line_reports_the_defaults_as_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            ..ClientConfig::default()
        };
        let (trust, identity) = tls_posture(&config);
        assert_eq!(trust, "the built-in roots");
        assert_eq!(identity, "none");
    }

    /// And it reports what will actually be presented: a Server-issued pair in the state directory
    /// outranks the configured one (ADR-0021), so the line has to name the issued one — that is the
    /// whole reason it resolves the identity instead of printing `[tls] cert_file`.
    #[test]
    fn the_tls_line_names_the_issued_certificate_over_the_configured_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let configured = dir.path().join("operator-cert.pem");
        std::fs::write(&configured, b"cert").expect("write");
        std::fs::write(dir.path().join("operator-key.pem"), b"key").expect("write");
        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            tls: Some(crate::config::TlsConfig {
                ca_file: None,
                cert_file: Some(configured.clone()),
                key_file: Some(dir.path().join("operator-key.pem")),
            }),
            ..ClientConfig::default()
        };

        // With no issued pair on disk, the operator's is what gets presented.
        let (_, identity) = tls_posture(&config);
        assert_eq!(identity, configured.display().to_string());

        // Once the Server has issued one, that is the pair — and the line must follow.
        let issued = dir.path().join(crate::tls::ISSUED_CERT_FILE);
        std::fs::write(&issued, b"cert").expect("write");
        std::fs::write(dir.path().join(crate::tls::ISSUED_KEY_FILE), b"key").expect("write");
        let (_, identity) = tls_posture(&config);
        assert_eq!(identity, issued.display().to_string());
    }
}
