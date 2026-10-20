//! The shared child runner every plugin drives — the generic implementation of the whole
//! lifecycle vocabulary (ADR-0017): spawn, watch, restart with backoff, apply a new
//! configuration by respawning — or, when the plugin declared a reload mechanism, in place —
//! stop gracefully within the budget, and answer an uninstall before the core purges. Plus the
//! version probe a plugin uses to learn a Managed Process's own version, run at startup and
//! after every swap.
//!
//! Mirrors the reference `opampsupervisor` (ADR-0017): SIGTERM → bounded wait → kill on Unix,
//! `Child::kill` on Windows (which has no SIGTERM equivalent), and exponential backoff for a
//! process that keeps exiting.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use opamp::proto::{AgentDescription, ComponentHealth};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{info, instrument, warn, Instrument as _};

use crate::install;
use crate::shutdown::Shutdown;
use crate::supervisor::ports::{EventSender, InstallTarget, ProcessCommand, ProcessEvent};
use crate::supervisor::restart::{AfterFailure, RestartPolicy};
use opamp::client::Backoff;

/// How a plugin wants its Managed Process invoked, rebuilt whenever the configuration changed.
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Where the process starts. `None` means **the directory the program lives in**, which the
    /// spawn resolves (ADR-0017): a single-file package's `program/`, a tree package's tree root —
    /// the latter being exactly what the GLPI Agent's own Windows launcher does by hand. Before
    /// that rule the process inherited whatever directory the service manager left this Client in,
    /// typically `/`: a default nobody chose. A kind that needs another directory still names one.
    pub working_dir: Option<PathBuf>,
    /// Directories the Managed Process **writes into**, created before every spawn.
    ///
    /// An agent the fleet delivers cannot expect a host prepared by hand: an installation that
    /// fails because a directory is missing is this Client's failure, not the operator's. Many
    /// agents create nothing themselves — Icinga 2 exits when `DataDir` is absent, the GLPI Agent
    /// exits when `--vardir` is — so the kind that knows an agent names what that agent needs, and
    /// the spawn guarantees it.
    ///
    /// **Before every spawn, not once at install**, so a directory removed under a running fleet
    /// comes back on the next restart rather than taking the Supervisor down. Created owner-only,
    /// for the reason [`crate::storage::create_private_dir`] gives: what an agent writes about a
    /// host is not for every local user to read.
    ///
    /// The program's own directories are **not** listed here — the install creates those
    /// ([`InstallTarget::prepare`]). This is for what the agent writes at run time, which lives
    /// outside `program/` precisely because a package swap replaces that whole.
    pub ensure_dirs: Vec<PathBuf>,
    /// Start the process as the leader of its own process group, so the bounded stop can signal
    /// the **group** rather than one pid (ADR-0017 clause 56). A daemon that runs a worker of its own —
    /// Icinga 2's umbrella does — otherwise leaves that worker orphaned and running when the stop
    /// escalates to a kill, holding the very state directory and port the Supervisor manages.
    /// Off by default: a process with no children of its own gains nothing from it.
    pub own_process_group: bool,
}

impl InstallTarget {
    /// What the Managed Process is spawned from.
    fn live(&self) -> PathBuf {
        match self {
            InstallTarget::Binary(path) => path.clone(),
            InstallTarget::Tree { root, .. } => root.join(crate::config::TREE_DIR),
        }
    }

    /// Where the thing being replaced is kept until the new one has proved itself.
    fn backup(&self) -> PathBuf {
        match self {
            InstallTarget::Binary(path) => path.with_extension("rollback"),
            InstallTarget::Tree { root, .. } => {
                root.join(format!("{}.rollback", crate::config::TREE_DIR))
            }
        }
    }

    /// Creates the directories this target needs before anything is installed into it — at
    /// startup, so a Supervisor whose program has not arrived yet still owns its place.
    ///
    /// For a tree that is the `program/` root and **nothing below it**: the live tree is put there
    /// by renaming a staging directory over the name, and a rename cannot replace a directory that
    /// something else has already created and filled. Creating the program's parent — which is what
    /// the single-file case wants — would make every first install of a tree fail.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be created.
    pub fn prepare(&self) -> Result<(), String> {
        let dir = match self {
            InstallTarget::Binary(path) => path.parent().map(std::path::Path::to_path_buf),
            InstallTarget::Tree { root, .. } => Some(root.clone()),
        };
        match dir {
            Some(dir) => std::fs::create_dir_all(&dir)
                .map_err(|e| format!("cannot prepare {}: {e}", dir.display())),
            None => Ok(()),
        }
    }

    /// Moves what runs today aside, so a failed install has something to go back to. `false` means
    /// there was nothing there — a first install, which is the ordinary way an agent arrives.
    fn set_aside(&self) -> Result<bool, String> {
        let (live, backup) = (self.live(), self.backup());
        // A rename never lands on an occupied name: Windows refuses it outright, and a directory
        // rename would nest rather than replace. This also clears any *retained* predecessor
        // (ADR-0026) and its marker — each Supervisor keeps only the immediately previous version.
        self.drop_backup();
        match std::fs::rename(&live, &backup) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("cannot set {} aside: {e}", live.display())),
        }
    }

    /// Unpacks the verified artifact **beside** what runs, without touching it.
    ///
    /// Splitting this from [`commit`](Self::commit) is what buys the preflight of ADR-0017 clause 57: the
    /// staged program can be proved to run *before* the running one is stopped, so a package that
    /// could never have worked costs no downtime at all.
    fn stage(
        &self,
        artifact: &std::path::Path,
        archive_key: Option<&str>,
    ) -> Result<Staged, String> {
        match self {
            InstallTarget::Binary(path) => {
                let temp = stage_executable(artifact, path, archive_key)?;
                Ok(Staged {
                    root: temp
                        .parent()
                        .map(std::path::Path::to_path_buf)
                        .unwrap_or_default(),
                    program: temp.clone(),
                    temp,
                })
            }
            InstallTarget::Tree { root, program_path } => {
                let staging = stage_tree(artifact, root, program_path, archive_key)?;
                Ok(Staged {
                    program: staging.join(program_path),
                    root: staging.clone(),
                    temp: staging,
                })
            }
        }
    }

    /// Moves what was staged into the live name. The live path is free by the time this is called —
    /// [`set_aside`](Self::set_aside) has just moved it — so this is one rename, which is what
    /// makes the swap atomic.
    fn commit(&self, staged: &Staged) -> Result<(), String> {
        let live = self.live();
        std::fs::rename(&staged.temp, &live)
            .map_err(|e| format!("cannot install {}: {e}", live.display()))
    }

    /// Throws a staged package away — after a refused preflight, or a failed commit.
    fn discard(&self, staged: &Staged) {
        self.remove(&staged.temp);
    }

    /// Puts back what ran before.
    fn restore(&self) -> Result<(), String> {
        let (live, backup) = (self.live(), self.backup());
        self.remove(&live);
        std::fs::rename(&backup, &live)
            .map_err(|e| format!("cannot restore {}: {e}", live.display()))
    }

    /// The marker beside a retained backup (ADR-0026): a sibling file holding the Unix-seconds
    /// deadline after which the backup may be swept. A file even for a tree, whose backup is a
    /// directory, so a restart can find the deadline without opening the tree.
    fn backup_marker(&self) -> PathBuf {
        let mut raw = self.backup().into_os_string();
        raw.push(".until");
        PathBuf::from(raw)
    }

    /// Keeps the backup and records when it may be deleted (ADR-0026). Persisted, so the deadline
    /// survives a Client restart the way the self-update outcome marker does (ADR-0018).
    fn retain(&self, deadline_unix: u64) {
        let _ = std::fs::write(self.backup_marker(), deadline_unix.to_string());
    }

    /// Drops the backup — and its retention marker — once it is no longer wanted: immediately when
    /// retention is off, or when a later update supersedes it.
    fn drop_backup(&self) {
        self.remove(&self.backup());
        let _ = std::fs::remove_file(self.backup_marker());
    }

    /// Deletes a retained backup whose deadline has passed (ADR-0026). Best-effort; returns whether
    /// it removed one. An unreadable or absent marker leaves an unretained backup alone — only a
    /// backup this Runner deliberately retained carries a marker, and a marker whose value will not
    /// parse is treated as expired rather than kept forever.
    fn sweep(&self, now_unix: u64) -> bool {
        let marker = self.backup_marker();
        let Ok(text) = std::fs::read_to_string(&marker) else {
            return false;
        };
        let expired = text.trim().parse::<u64>().map_or(true, |d| now_unix >= d);
        if expired {
            self.drop_backup();
        }
        expired
    }

    /// Removes a file or a whole tree, whichever this target deals in. Best-effort throughout:
    /// every caller is already committing to an outcome and has nothing better to do with a
    /// failure than report the one it is already reporting.
    fn remove(&self, path: &std::path::Path) {
        match self {
            InstallTarget::Binary(_) => {
                let _ = std::fs::remove_file(path);
            }
            InstallTarget::Tree { .. } => {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}

/// What an unpacked, not-yet-installed package looks like on disk.
///
/// It exists so the two halves of an install — unpack beside, then rename over — can be separated
/// by a check (ADR-0017).
#[derive(Debug, Clone)]
pub struct Staged {
    /// The staged tree's root, or the staged file's directory. `${staged}` in a
    /// [`Preflight`]'s environment resolves to this.
    root: PathBuf,
    /// The program itself, inside the staged tree.
    program: PathBuf,
    /// What [`InstallTarget::commit`] renames over the live name.
    temp: PathBuf,
}

/// How a plugin proves a staged program can run at all, before it replaces the running one.
///
/// The check is a start, because a start is the definition of "does this run here": it catches a
/// library the host does not have and a libc too old for the build in one go, and the dynamic
/// linker's own message — *"version `GLIBC_2.39' not found"* — is what the fleet gets told
/// (ADR-0017). Whatever is run must be cheap and must not touch state; `--version` is the shape.
pub struct Preflight {
    pub args: Vec<String>,
    /// Environment for the check. `${staged}` in a value resolves to the staged tree's root, so a
    /// tree carrying its own libraries is checked against **those** rather than against the ones
    /// the running version happens to leave behind.
    pub env: Vec<(String, String)>,
}

/// How to ask a Managed Process for its own version — the program to run and the arguments that
/// make it print one. `None` on a Runner whose plugin has no such convention.
pub struct VersionProbe {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// How to read a version out of what the program printed. `None` is [`find_semver`], the strict
    /// Semantic Versioning read. A program whose version banner is not SemVer — Icinga 2 prints
    /// `r2.14.6-1` — would report none at all, so a kind that knows its program's convention says
    /// so here (ADR-0017).
    pub parse: Option<fn(&str) -> Option<String>>,
}

/// The adapter task driving one Managed Process. The plugin supplies `build`: the current
/// [`ProcessSpec`], or `None` while the process should not run (a Collector before any
/// configuration arrived).
/// The environment variable a Managed Process finds the Supervisor Endpoint's token in
/// (ADR-0015): an `opampextension` presents it as `Authorization: Bearer ${env:OPAMP_SUPERVISOR_TOKEN}`.
pub const ENDPOINT_TOKEN_ENV: &str = "OPAMP_SUPERVISOR_TOKEN";

pub struct Runner {
    pub name: String,
    /// Handed to the Managed Process as [`ENDPOINT_TOKEN_ENV`] (ADR-0015).
    pub endpoint_token: String,
    pub stop_timeout: Duration,
    /// How long a freshly (re)started process must survive before `ApplyConfig` is acknowledged
    /// (ADR-0017's health-gated acknowledgement); zero acknowledges on start.
    pub apply_grace: Duration,
    /// What an `ApplyPackage` swap replaces (ADR-0026) — one file, or a whole tree (ADR-0026).
    /// `None` for a plugin with nothing swappable, which then reports a package `InstallFailed`.
    pub install: Option<InstallTarget>,
    /// How long the version a successful update supersedes is kept before deletion (ADR-0026), so
    /// an operator has a fallback window. Zero deletes it on success.
    pub retain_previous: Duration,
    /// Opens an encrypted `.7z` artifact (ADR-0026); `None` when no key is configured.
    pub archive_key: Option<String>,
    /// How to learn the Managed Process's own version, when the plugin knows how to ask.
    pub version_probe: Option<VersionProbe>,
    /// How to prove a staged package runs before it replaces what does (ADR-0017 clause 57). `None` proves
    /// nothing in advance: the swap is the first thing that finds out.
    pub preflight: Option<Preflight>,
    /// The signal that makes the running process re-read its configuration in place (ADR-0017);
    /// `None` — the generic behaviour — applies a configuration by restarting. A reload that
    /// fails, or a process that dies on it, falls back to the restart (`reload-or-restart`).
    pub reload_signal: Option<i32>,
    pub events: EventSender,
    pub commands: mpsc::Receiver<ProcessCommand>,
    pub build: Box<dyn Fn() -> Option<ProcessSpec> + Send + Sync>,
}

impl Runner {
    pub async fn run(mut self, mut shutdown: Shutdown) {
        // Consecutive start failures, and when the current process started (ADR-0026): together they
        // stop a program that keeps crashing from being restarted forever. A process that runs
        // stably clears the streak; a command (config, package, restart) resets it.
        let mut policy = RestartPolicy::new(self.apply_grace, Instant::now());
        let mut backoff = Backoff::new();
        // Clear any predecessor whose retention window already elapsed while the Client was down
        // (ADR-0026) — the deadline is wall-clock, so a restart is exactly when one may have passed.
        self.sweep_backup();
        // What runs today, before it runs: a Collector without the opampextension never reports
        // its own version, and one that is not configured yet never even starts.
        self.probe_version();
        let mut child = self.spawn_if_due().await;

        // Honour the retention window even when the Client stays up past it. Cheap and coarse: a
        // day-long window does not need a tight tick, and the sweep itself is a stat plus a delete.
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        sweep.tick().await; // the first tick is immediate; the startup sweep above already ran

        loop {
            let exited = async {
                match child.as_mut() {
                    Some(c) => c.wait().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = sweep.tick() => self.sweep_backup(),
                command = self.commands.recv() => match command {
                    Some(ProcessCommand::ApplyConfig { config, span }) => {
                        policy.fresh_chance(); // a new configuration (ADR-0026)
                        backoff.reset();
                        // In place first (ADR-0017): a kind that declared a reload keeps its
                        // process — and its in-flight state — across the change; anything short
                        // of a survived grace falls back to the restart below.
                        match self
                            .try_reload(&mut child, &mut shutdown)
                            .instrument(span.clone())
                            .await
                        {
                            Reloaded::Applied => {
                                crate::telemetry::succeeded(&span);
                                self.events
                                    .send(ProcessEvent::ConfigApplied {
                                        hash: config.config_hash,
                                        result: Ok(()),
                                    })
                                    .await;
                                continue;
                            }
                            Reloaded::ShuttingDown => break,
                            Reloaded::NotApplied => {}
                        }
                        // The restart phase. Created and dropped around the two awaits rather than
                        // entered across them: a guard held over an `.await` stays current on the
                        // thread while this task is parked, which would attribute another task's
                        // work to this apply. An unentered span still carries the phase's duration,
                        // which is what this one is here for.
                        let restart = tracing::info_span!(parent: &span, "restart");
                        stop(&mut child, self.stop_timeout, &self.name).await;
                        child = self.spawn_if_due().await;
                        drop(restart);
                        policy.started(Instant::now());
                        // Applying means running on the new files — and surviving the apply
                        // grace (ADR-0017's health-gated acknowledgement): a process that exits
                        // right away has rejected its configuration the only way a process can.
                        let started = child.take();
                        let ran = started.is_some();
                        let outcome = if !ran && (self.build)().is_none() {
                            GraceOutcome::Ok // nothing should run; that is the config
                        } else {
                            self.gate(started, &mut child, &mut shutdown)
                                .instrument(span.clone())
                                .await
                        };
                        let result = match outcome {
                            GraceOutcome::Ok => Ok(()),
                            GraceOutcome::Failed(e) => Err(e),
                            // Shutting down mid-grace: no acknowledgement — the goodbyes carry no
                            // status anyway — just stop gracefully on the way out.
                            GraceOutcome::ShuttingDown => break,
                        };
                        // A process that started and then failed the gate exited within the grace.
                        let exited_in_grace = ran && result.is_err();
                        match &result {
                            Ok(()) => crate::telemetry::succeeded(&span),
                            Err(e) => crate::telemetry::failed(&span, e),
                        }
                        self.events
                            .send(ProcessEvent::ConfigApplied { hash: config.config_hash, result })
                            .await;
                        if exited_in_grace {
                            // Stay supervised: a flaky-but-valid configuration is retried with
                            // backoff — but not forever (ADR-0026): a configuration that will not
                            // start is held after a few tries rather than spun on.
                            if self
                                .respawn_or_hold(&mut child, &mut policy, &mut backoff, &mut shutdown)
                                .await
                            {
                                break;
                            }
                        }
                    }
                    Some(ProcessCommand::ApplyPackage { staged, version, hash, span }) => {
                        // Unpack beside what runs and prove it starts, *before* anything is
                        // stopped (ADR-0017): a package that could never have run costs no
                        // downtime, and the reason it could not is the linker's own.
                        //
                        // The install's trace came with the command (ADR-0016): every phase below
                        // runs inside it, so the download that started it and the rollback that may
                        // end it are one trace across two tasks.
                        let prepared = self.stage_and_check(&staged).instrument(span.clone()).await;
                        let _ = std::fs::remove_file(&staged);
                        let prepared = match prepared {
                            Ok(prepared) => prepared,
                            Err(e) => {
                                warn!(supervisor = %self.name, version = %version, error = %e, "refusing a package that will not run here");
                                crate::telemetry::failed(&span, &e);
                                self.events
                                    .send(ProcessEvent::PackageApplied { hash, result: Err(e) })
                                    .await;
                                continue;
                            }
                        };
                        // Swap the binary, restart, and health-gate on the apply grace — a binary
                        // that will not stay up is rolled back to the bytes it replaced (ADR-0026).
                        stop(&mut child, self.stop_timeout, &self.name).await;
                        policy.fresh_chance(); // a new package (ADR-0026)
                        backoff.reset();
                        let result = self
                            .swap_and_gate(prepared, &version, &mut child, &mut shutdown)
                            .instrument(span.clone())
                            .await;
                        if child.is_none() && !matches!(result, GraceOutcome::ShuttingDown) {
                            child = self.spawn_if_due().await;
                            policy.started(Instant::now());
                        }
                        match result {
                            GraceOutcome::Ok => {
                                policy.started(Instant::now());
                                // A new binary is a new version, and the Agent's `service.version`
                                // is what the program says about itself — so ask it again. Without
                                // this the swap is reported as installed while the Agent goes on
                                // describing the version it replaced, until the Client restarts.
                                self.probe_version();
                                crate::telemetry::succeeded(&span);
                                self.events
                                    .send(ProcessEvent::PackageApplied { hash, result: Ok(version) })
                                    .await;
                            }
                            GraceOutcome::Failed(error) => {
                                crate::telemetry::failed(&span, &error);
                                self.events
                                    .send(ProcessEvent::PackageApplied { hash, result: Err(error) })
                                    .await;
                                // Stay supervised, exactly as a failed ApplyConfig does — and, like
                                // it, held rather than spun on once it keeps failing (ADR-0026).
                                if self
                                     .respawn_or_hold(&mut child, &mut policy, &mut backoff, &mut shutdown)
                                    .await
                                {
                                    break;
                                }
                            }
                            GraceOutcome::ShuttingDown => break,
                        }
                    }
                    Some(ProcessCommand::Restart) => {
                        stop(&mut child, self.stop_timeout, &self.name).await;
                        policy.fresh_chance(); // an operator restart (ADR-0026)
                        backoff.reset();
                        child = self.spawn_if_due().await;
                        policy.started(Instant::now());
                    }
                    Some(ProcessCommand::Uninstall) => {
                        // Retired for good (ADR-0017): the generic uninstall is exactly the
                        // graceful stop — nothing the generic Runner installs lives outside the
                        // Supervisor's directory, and that directory is the core's to purge
                        // (ADR-0017) once this answer is out.
                        stop(&mut child, self.stop_timeout, &self.name).await;
                        self.events
                            .send(ProcessEvent::Uninstalled { result: Ok(()) })
                            .await;
                        return;
                    }
                    Some(ProcessCommand::Shutdown) | None => break,
                },
                status = exited => {
                    let describe = describe_exit(status);
                    warn!(supervisor = %self.name, status = %describe, "process exited unexpectedly");
                    child = None;
                    self.events
                        .send(ProcessEvent::Health(unhealthy(
                            format!("exited unexpectedly ({describe})"),
                            describe,
                        )))
                        .await;
                    // A process that had been up a while is ordinary supervision, not a start loop:
                    // its exit clears the streak (ADR-0026). One that keeps exiting quickly does not,
                    // so it is held after a few tries rather than restarted forever.
                    policy.exited(Instant::now());
                    if self
                        .respawn_or_hold(&mut child, &mut policy, &mut backoff, &mut shutdown)
                        .await
                    {
                        break;
                    }
                }
                _ = shutdown.requested() => break,
            }
        }
        stop(&mut child, self.stop_timeout, &self.name).await;
    }

    /// Unpacks the artifact beside what runs and — when the plugin said how — proves the staged
    /// program starts. Nothing that runs is touched here; that is the whole point (ADR-0017).
    /// The `stage` phase of an install's trace (ADR-0016); the preflight below is its own child.
    #[instrument(name = "stage", skip_all, fields(supervisor = %self.name))]
    async fn stage_and_check(&self, artifact: &std::path::Path) -> Result<Staged, String> {
        let target = self
            .install
            .as_ref()
            .ok_or_else(|| "this supervisor manages nothing a package can replace".to_string())?;
        let staged = target.stage(artifact, self.archive_key.as_deref())?;
        if let Some(preflight) = &self.preflight {
            if let Err(e) = run_preflight(&staged, preflight).await {
                target.discard(&staged);
                return Err(e);
            }
        }
        Ok(staged)
    }

    /// Swaps the staged artifact over the binary, respawns, and health-gates on the apply grace,
    /// rolling the binary back on failure (ADR-0026). The process is already stopped. On success
    /// `child` holds the running process; on failure the previous binary is restored (and the
    /// caller respawns it).
    ///
    /// Everything here moves *files*: the old binary is renamed aside rather than read into
    /// memory, and the artifact is moved or streamed rather than loaded. A program can weigh
    /// hundreds of megabytes, and holding two copies of one in RAM to update it is not a trade
    /// this makes. The artifact may already be gone by the time it is cleaned up —
    /// [`stage_executable`] moves it when it can — so every removal of it is best-effort.
    ///
    /// The `swap` phase, with `gate` and — where it comes to that — `rollback` beneath it.
    #[instrument(name = "swap", skip_all, fields(supervisor = %self.name, version = %version))]
    async fn swap_and_gate(
        &self,
        staged: Staged,
        version: &str,
        child: &mut Option<Child>,
        shutdown: &mut Shutdown,
    ) -> GraceOutcome {
        let Some(target) = &self.install else {
            return GraceOutcome::Failed(
                "this supervisor manages nothing a package can replace".to_string(),
            );
        };
        // Move what runs today aside — a rename, so it is atomic and costs nothing — and it is
        // what a failed package is rolled back from.
        let has_backup = match target.set_aside() {
            Ok(has_backup) => has_backup,
            Err(e) => {
                target.discard(&staged);
                return GraceOutcome::Failed(e);
            }
        };
        if let Err(e) = target.commit(&staged) {
            // Put the old one back before reporting: the process must not be left with none.
            if has_backup {
                let _ = target.restore();
            }
            target.discard(&staged);
            return GraceOutcome::Failed(e);
        }
        info!(supervisor = %self.name, version = %version, program = %target.live().display(), "package staged; restarting");

        let started = self.try_spawn().await;
        // "Nothing started" has two meanings, and only one of them is a failed install. A plugin
        // with no process to run — a Collector that has not been configured yet — has not rejected
        // the artifact: the binary is in place and will be started by the configuration when it
        // arrives. `ApplyConfig` has always drawn this distinction; the package path must too, or
        // installing onto a host that is not yet configured deletes what it just installed.
        let nothing_to_run = started.is_err() && (self.build)().is_none();
        match (&started, nothing_to_run) {
            (Err(_), true) => {
                info!(supervisor = %self.name, version = %version, "package installed; nothing to run until a configuration arrives");
            }
            (Err(e), false) => {
                warn!(supervisor = %self.name, error = %e, "the new binary would not start");
            }
            _ => {}
        }
        let outcome = if nothing_to_run {
            GraceOutcome::Ok
        } else {
            self.gate(started.ok(), child, shutdown).await
        };
        match (&outcome, has_backup) {
            // Roll back to what ran before, so the next respawn is the old, known one.
            (GraceOutcome::Failed(_), true) => {
                // A phase of its own in the trace (ADR-0016): a rollback is the part of a failed
                // install an operator most wants timed, and its own failure is the one that leaves
                // a host with no program at all.
                let _rollback = tracing::info_span!("rollback").entered();
                if let Err(e) = target.restore() {
                    warn!(supervisor = %self.name, error = %e, "cannot roll the program back");
                } else {
                    warn!(supervisor = %self.name, "rolled the program back after a failed package");
                }
            }
            // No predecessor: a first install with nothing behind it. It is *not* rolled back
            // (ADR-0026) — the verified program stays in place, reported InstallFailed, so a first
            // package that will not start does not empty `program/` and set the Server re-offering
            // it in a loop. Discarding it here would make that loop turn.
            (GraceOutcome::Failed(_), false) => {
                warn!(supervisor = %self.name, "the first install would not start; kept in place, not rolled back (nothing to roll back to)");
            }
            // Applied: the predecessor is no longer what runs, but it is kept for the retention
            // window (ADR-0026) so an operator has a fallback, then swept once its deadline passes.
            (_, true) => self.retain_backup(target),
            (_, false) => {}
        }
        outcome
    }

    /// Keeps the version a successful update superseded, or drops it now (ADR-0026). With retention
    /// off it is deleted at once; otherwise the backup stays and a marker records the deadline
    /// `now + retain_previous`, swept once it passes.
    fn retain_backup(&self, target: &InstallTarget) {
        if self.retain_previous.is_zero() {
            target.drop_backup();
            return;
        }
        let deadline = now_unix().saturating_add(self.retain_previous.as_secs());
        target.retain(deadline);
        info!(
            supervisor = %self.name,
            retain_secs = self.retain_previous.as_secs(),
            "keeping the previous version until it may be rolled back to no longer"
        );
    }

    /// Deletes a retained predecessor whose deadline has passed (ADR-0026). Called at startup and on
    /// a periodic tick, so the window is honoured whether or not the Client restarts within it.
    fn sweep_backup(&self) {
        if let Some(target) = &self.install {
            if target.sweep(now_unix()) {
                info!(supervisor = %self.name, "swept the retained previous version past its window");
            }
        }
    }

    /// Respawns after a start failure — or, once the [`RestartPolicy`] says the process keeps
    /// failing to stay up, **holds** it down instead of spinning (ADR-0026). A held Supervisor
    /// reports unhealthy and waits: the next configuration, package, or restart is a fresh chance
    /// and resets the streak. Returns `true` when shutdown was requested mid-wait.
    async fn respawn_or_hold(
        &self,
        child: &mut Option<Child>,
        policy: &mut RestartPolicy,
        backoff: &mut Backoff,
        shutdown: &mut Shutdown,
    ) -> bool {
        let delay = match policy.failed() {
            AfterFailure::Retry => backoff.advance(),
            AfterFailure::Hold(failures) => {
                warn!(
                    supervisor = %self.name, restarts = failures,
                    "not restarting: the program keeps failing to start — holding until a new configuration, package, or restart"
                );
                self.events
                    .send(ProcessEvent::Health(unhealthy(
                        "not restarting: the program keeps failing to start".to_string(),
                        format!("held after {failures} failed starts in a row"),
                    )))
                    .await;
                *child = None;
                return false;
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                *child = self.spawn_if_due().await;
                policy.started(Instant::now());
                false
            }
            _ = shutdown.requested() => true,
        }
    }

    /// The `gate` phase: the apply-grace health gate a configuration apply and a package swap
    /// share (ADR-0017). A freshly started process must survive `apply_grace` to count as applied;
    /// exiting within it fails, and so does a process that never started. `child` is left holding
    /// the running process on success.
    #[instrument(name = "gate", skip_all, fields(supervisor = %self.name))]
    async fn gate(
        &self,
        started: Option<Child>,
        child: &mut Option<Child>,
        shutdown: &mut Shutdown,
    ) -> GraceOutcome {
        match started {
            None => GraceOutcome::Failed("the process did not start".to_string()),
            Some(mut proc) if !self.apply_grace.is_zero() => {
                tokio::select! {
                    status = proc.wait() => {
                        let describe = describe_exit(status);
                        warn!(supervisor = %self.name, status = %describe, "process exited during the apply grace");
                        self.events
                            .send(ProcessEvent::Health(unhealthy(
                                format!("exited during the apply grace ({describe})"),
                                describe.clone(),
                            )))
                            .await;
                        GraceOutcome::Failed(format!("the process exited during the apply grace ({describe})"))
                    }
                    _ = tokio::time::sleep(self.apply_grace) => {
                        *child = Some(proc);
                        GraceOutcome::Ok
                    }
                    _ = shutdown.requested() => {
                        *child = Some(proc);
                        GraceOutcome::ShuttingDown
                    }
                }
            }
            Some(proc) => {
                *child = Some(proc);
                GraceOutcome::Ok
            }
        }
    }

    /// The in-place apply (ADR-0017): sends the declared reload signal to the running process,
    /// which must then survive the apply grace — the same standard the restart path holds a
    /// fresh process to, and the only outside-observable evidence a reload leaves. Everything
    /// short of that is `NotApplied`, and the caller restarts on the new files instead
    /// (`reload-or-restart`): no mechanism declared, nothing running to signal, a failed
    /// signal, or a death within the grace.
    #[instrument(name = "reload", skip_all, fields(supervisor = %self.name))]
    async fn try_reload(&self, child: &mut Option<Child>, shutdown: &mut Shutdown) -> Reloaded {
        let Some(signal) = self.reload_signal else {
            return Reloaded::NotApplied;
        };
        let Some(mut proc) = child.take() else {
            return Reloaded::NotApplied;
        };
        let Some(pid) = proc.id() else {
            // Already exited; the restart path is about to notice and respawn.
            *child = Some(proc);
            return Reloaded::NotApplied;
        };
        if let Err(e) = send_reload_signal(pid, signal) {
            warn!(supervisor = %self.name, signal, error = %e, "cannot signal a reload; restarting instead");
            *child = Some(proc);
            return Reloaded::NotApplied;
        }
        info!(supervisor = %self.name, signal, "reload signalled");
        if self.apply_grace.is_zero() {
            *child = Some(proc);
            return Reloaded::Applied;
        }
        tokio::select! {
            status = proc.wait() => {
                let describe = describe_exit(status);
                warn!(supervisor = %self.name, status = %describe, "process exited on the reload; restarting on the new files");
                Reloaded::NotApplied
            }
            _ = tokio::time::sleep(self.apply_grace) => {
                *child = Some(proc);
                Reloaded::Applied
            }
            _ = shutdown.requested() => {
                *child = Some(proc);
                Reloaded::ShuttingDown
            }
        }
    }

    /// Asks the program for its own version, if the plugin knows how to ask.
    ///
    /// Out of band by design: the answer arrives whenever it arrives, as a Description event, and
    /// a program that will not answer holds nothing up (see [`probe_version`]).
    fn probe_version(&self) {
        if let Some(probe) = &self.version_probe {
            tokio::spawn(probe_version(
                probe.program.clone(),
                probe.args.clone(),
                probe.parse,
                self.events.clone(),
            ));
        }
    }

    /// Spawns when the plugin says something should run, reporting health either way.
    async fn spawn_if_due(&self) -> Option<Child> {
        self.try_spawn().await.ok()
    }

    /// Spawns the Managed Process, keeping the reason when it fails.
    ///
    /// Right after a package swap the reason matters: exec of a freshly written binary can fail
    /// with `ETXTBSY`, which is transient and says nothing about the artifact
    /// ([`install::is_text_file_busy`] states why). So the swap retries briefly rather than rolling
    /// back a binary that is perfectly good.
    async fn try_spawn(&self) -> Result<Child, String> {
        let mut attempt = 0;
        loop {
            match self.spawn_once().await {
                Err(e) if install::is_text_file_busy(&e) && attempt < install::BUSY_RETRIES => {
                    attempt += 1;
                    warn!(
                        supervisor = %self.name, attempt,
                        "the new binary is momentarily busy (another spawn holds it); retrying"
                    );
                    tokio::time::sleep(install::BUSY_DELAY).await;
                }
                other => return other.map_err(|e| e.to_string()),
            }
        }
    }

    async fn spawn_once(&self) -> Result<Child, std::io::Error> {
        let Some(spec) = (self.build)() else {
            self.events
                .send(ProcessEvent::Health(unhealthy(
                    "awaiting configuration".to_string(),
                    String::new(),
                )))
                .await;
            return Err(std::io::Error::other("nothing to run"));
        };
        // What the agent writes into, guaranteed before it runs. A failure here is a spawn failure
        // like any other: the Runner reports it and retries with backoff, rather than the process
        // starting and exiting on a directory nobody made.
        for dir in &spec.ensure_dirs {
            if let Err(e) = crate::storage::create_private_dir(dir) {
                warn!(supervisor = %self.name, dir = %dir.display(), error = %e, "cannot prepare a directory the agent writes into");
                return Err(std::io::Error::other(format!(
                    "cannot prepare {}: {e}",
                    dir.display()
                )));
            }
        }
        // The program's own directory where nothing else was said (ADR-0017). A bare relative
        // name — which ADR-0017's path rule does not produce — yields an empty parent, and an
        // empty `current_dir` fails the spawn, so that case keeps inheriting as it did.
        let derived = spec
            .program
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty());
        let working_dir = spec.working_dir.as_deref().or(derived);
        // **The program is made absolute whenever a working directory is set.** `Command` does
        // `chdir` before `exec` on Unix, so a relative program would be resolved against the
        // directory it was just moved into — `<dir>/<dir>/<program>`, which is nothing. This is
        // not a corner: `state_dir` defaults to the relative `client-state`, so every Managed
        // Process under a default configuration hit it, and the failure arrives as a bare
        // `No such file or directory` naming a file that is plainly there.
        let program = match working_dir {
            Some(_) => crate::config_file::absolute(&spec.program),
            None => spec.program.clone(),
        };
        let mut command = Command::new(&program);
        command.args(&spec.args).envs(spec.env.iter().cloned());
        // Last, so no block's `env` can replace it (ADR-0015).
        if !self.endpoint_token.is_empty() {
            command.env(ENDPOINT_TOKEN_ENV, &self.endpoint_token);
        }
        if let Some(dir) = working_dir {
            command.current_dir(dir);
        }
        // If the runner is dropped without a graceful stop, take the process along.
        command.kill_on_drop(true);
        // Its own process group, so `stop` can signal the group and leave no worker behind
        // (ADR-0017). Unix-only: what Windows offers instead is a job object, which the stop
        // there does not use yet.
        #[cfg(unix)]
        if spec.own_process_group {
            command.process_group(0);
        }
        match command.spawn() {
            Ok(child) => {
                info!(supervisor = %self.name, program = %spec.program.display(), "process started");
                // Before the health report, so a sampler that wakes on it already has the pid.
                self.events.send(ProcessEvent::Pid(child.id())).await;
                self.events
                    .send(ProcessEvent::Health(ComponentHealth {
                        healthy: true,
                        status: "running".to_string(),
                        start_time_unix_nano: now_ns(),
                        status_time_unix_nano: now_ns(),
                        ..Default::default()
                    }))
                    .await;
                Ok(child)
            }
            Err(e) => {
                warn!(supervisor = %self.name, program = %spec.program.display(), error = %e, "cannot spawn");
                // What the Server should read is the *situation*, not the syscall. A binary that
                // is not there — a first install that failed and was undone, or a program never
                // installed — is a Supervisor with no process, and saying so is more use to an
                // operator than "spawn failed".
                let status = if e.kind() == std::io::ErrorKind::NotFound {
                    "no process installed"
                } else {
                    "spawn failed"
                };
                self.events
                    .send(ProcessEvent::Health(unhealthy(
                        status.to_string(),
                        format!("cannot spawn {}: {e}", spec.program.display()),
                    )))
                    .await;
                Err(e)
            }
        }
    }
}

/// How long a version probe may take before it is abandoned — it must never stall startup.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a running Supervisor re-checks whether a retained predecessor's window has passed
/// (ADR-0026). Coarse on purpose: the window is measured in hours to a day, and the startup sweep
/// covers a Client that was down when a deadline elapsed.
const SWEEP_INTERVAL: Duration = Duration::from_secs(600);

/// Runs `<program> <args>` once and reports the Managed Process's version as a Description
/// event, if the output contains one. Best effort by design: a missing binary, a hang, or
/// versionless output is logged and otherwise ignored — probing must never break supervision.
///
/// A later self-report through the Supervisor Endpoint replaces the probed value.
pub async fn probe_version(
    program: PathBuf,
    args: Vec<String>,
    parse: Option<fn(&str) -> Option<String>>,
    events: EventSender,
) {
    let mut command = Command::new(&program);
    command.args(&args).kill_on_drop(true);
    let output = match bounded_output(&mut command).await {
        Some(Ok(output)) => output,
        Some(Err(e)) => {
            warn!(program = %program.display(), error = %e, "version probe cannot run");
            return;
        }
        None => {
            warn!(program = %program.display(), "version probe timed out");
            return;
        }
    };
    // Some tools print their version to stderr; accept either stream.
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match parse.unwrap_or(find_semver)(&text) {
        Some(version) => {
            info!(program = %program.display(), version = %version, "version probed");
            events
                .send(ProcessEvent::Description(AgentDescription {
                    identifying_attributes: vec![opamp::attributes::string_attr(
                        opamp::attributes::SERVICE_VERSION,
                        &version,
                    )],
                    non_identifying_attributes: Vec::new(),
                }))
                .await;
        }
        None => {
            warn!(program = %program.display(), "version probe output contains no semantic version")
        }
    }
}

/// The first Semantic Versioning 2.0.0 version found in free-form text (e.g. the `1.2.3` in
/// "otelcol-contrib version 1.2.3"). A leading `v` and trailing punctuation around a token are
/// tolerated; the extracted version itself is strictly SemVer.
fn find_semver(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|token| {
        let token = token.strip_prefix(['v', 'V']).unwrap_or(token);
        let token = token.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        fleet_core::version::is_semver(token).then(|| token.to_string())
    })
}

/// Graceful stop: SIGTERM and a bounded wait on Unix, then (or on Windows, directly) kill.
async fn stop(child: &mut Option<Child>, timeout: Duration, name: &str) {
    let Some(mut c) = child.take() else {
        return;
    };
    #[cfg(unix)]
    if let Some(pid) = c.id() {
        signal_child(pid, libc::SIGTERM);
        if tokio::time::timeout(timeout, c.wait()).await.is_ok() {
            info!(supervisor = %name, "process stopped");
            return;
        }
        warn!(supervisor = %name, "process ignored SIGTERM; killing it");
        // The group too, so a worker the child spawned does not survive the escalation and go on
        // holding what the Supervisor manages (ADR-0017 clause 56). `Child::kill` below only reaps the one.
        signal_child(pid, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = timeout; // Windows has no SIGTERM equivalent: kill is the stop.
    let _ = c.kill().await;
    info!(supervisor = %name, "process stopped");
}

/// Runs `command` to completion within [`PROBE_TIMEOUT`]; `None` when it does not finish in time.
///
/// A program written moments ago may fail to exec with `ETXTBSY` while another thread's fork still
/// holds it open for writing ([`install::is_text_file_busy`] states why); that is retried briefly,
/// as a spawn is, rather than taken for a program that cannot run.
async fn bounded_output(command: &mut Command) -> Option<std::io::Result<std::process::Output>> {
    let mut attempt = 0;
    loop {
        match tokio::time::timeout(PROBE_TIMEOUT, command.output()).await {
            Err(_) => return None,
            Ok(Err(e)) if install::is_text_file_busy(&e) && attempt < install::BUSY_RETRIES => {
                attempt += 1;
                tokio::time::sleep(install::BUSY_DELAY).await;
            }
            Ok(result) => return Some(result),
        }
    }
}

/// Runs a plugin's preflight against a staged package (ADR-0017 clause 57).
///
/// Bounded like the version probe, because this is the same shape of question asked of a program
/// nobody has run yet. The message on failure is the program's own — a linker error names the
/// library or the symbol version, which is exactly what an operator needs and what an exit status
/// alone destroys.
#[instrument(name = "preflight", skip_all)]
async fn run_preflight(staged: &Staged, preflight: &Preflight) -> Result<(), String> {
    let mut command = Command::new(&staged.program);
    command.args(&preflight.args).kill_on_drop(true);
    for (key, value) in &preflight.env {
        command.env(
            key,
            value.replace("${staged}", &staged.root.to_string_lossy()),
        );
    }
    let output = match bounded_output(&mut command).await {
        Some(Ok(output)) => output,
        Some(Err(e)) => return Err(format!("the packaged program cannot be run: {e}")),
        None => return Err("the packaged program did not answer in time".to_string()),
    };
    if output.status.success() {
        return Ok(());
    }
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let reason = said
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .unwrap_or("no output")
        .to_string();
    Err(format!(
        "the packaged program does not run on this host: {reason}"
    ))
}

/// Signals the Managed Process — **or its whole process group**, when the child leads one.
///
/// Leading a group is what a plugin asks for with [`ProcessSpec::own_process_group`], so the test
/// is the fact rather than a flag threaded through the Runner: a child whose process group id is
/// its own pid is a group the Supervisor created for it, and everything in it descends from the
/// process it started. Anything else is signalled alone (ADR-0017).
#[cfg(unix)]
fn signal_child(pid: u32, signal: i32) {
    let pid = pid as libc::pid_t;
    // SAFETY: plain getpgid(2)/kill(2) on the child's pid; no memory is touched.
    let leads_group = unsafe { libc::getpgid(pid) } == pid;
    unsafe {
        libc::kill(if leads_group { -pid } else { pid }, signal);
    }
}

/// The result of an in-place reload attempt (ADR-0017).
enum Reloaded {
    /// Signalled and survived the grace — applied, the process kept running.
    Applied,
    /// No reload happened (no mechanism, nothing running, a failed signal, or a death within
    /// the grace) — the caller falls back to the restart.
    NotApplied,
    /// A shutdown was requested mid-grace; the caller stops without an acknowledgement.
    ShuttingDown,
}

/// `SIGHUP` where the platform has signals, `None` where it has none — the reload a kind declares
/// for an agent that re-reads its configuration on `SIGHUP` (ADR-0017). Off Unix the Runner then
/// applies by restarting, so one block serves every platform.
#[cfg(unix)]
#[expect(
    dead_code,
    reason = "only the wrapped kinds that reload by signal call it"
)]
pub(crate) fn sighup() -> Option<i32> {
    Some(libc::SIGHUP)
}

#[cfg(not(unix))]
#[expect(
    dead_code,
    reason = "only the wrapped kinds that reload by signal call it"
)]
pub(crate) fn sighup() -> Option<i32> {
    None
}

/// Delivers the reload signal (ADR-0017). Unix-only in substance: a kind declares one only
/// through [`sighup`], which names none anywhere else, so the other arm exists for the compiler,
/// not for a host.
#[cfg(unix)]
fn send_reload_signal(pid: u32, signal: i32) -> Result<(), String> {
    // SAFETY: plain kill(2) on the child's pid; no memory is touched.
    match unsafe { libc::kill(pid as libc::pid_t, signal) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error().to_string()),
    }
}

#[cfg(not(unix))]
fn send_reload_signal(_pid: u32, _signal: i32) -> Result<(), String> {
    Err("this platform has no signal a process can reload on".to_string())
}

/// How a process that exited is described in a log line and a health report: its exit status, or
/// why waiting for it failed.
fn describe_exit(status: std::io::Result<std::process::ExitStatus>) -> String {
    status
        .map(|s| s.to_string())
        .unwrap_or_else(|e| format!("wait failed: {e}"))
}

/// The result of health-gating a freshly (re)started process.
enum GraceOutcome {
    /// The process survived the grace (or the grace is zero) — applied.
    Ok,
    /// The process exited within the grace, or would not start — with the reason.
    Failed(String),
    /// A shutdown was requested mid-grace; the caller stops without an acknowledgement.
    ShuttingDown,
}

/// Installs a downloaded artifact as `path`: put in place beside it, made executable, then renamed
/// over `path` — the final rename being what makes the swap atomic, so a crash mid-install never
/// leaves a half-written program where one is about to be started.
///
/// A raw artifact is **moved** rather than copied when it can be: the download is staged in the
/// same Supervisor directory the program lives in (ADR-0017), so the two are normally on one
/// filesystem and the install costs a metadata update instead of a second full write of several
/// hundred megabytes. The move consumes the artifact — the caller's cleanup of it is best-effort
/// for exactly this reason. A rename across filesystems fails, and so does one out of a staging
/// directory an operator has put elsewhere; either way the stream below is the fallback, and the
/// error that matters is reported from there rather than from the attempt.
///
/// The artifact may be the program or an archive holding it (ADR-0026). An archive is opened here,
/// where the binary's name is known, and the member of that name is what gets installed — nothing
/// upstream of this ever repacked the artifact, which is why the hash an Agent verified is the one
/// its author published. Unpacking always writes; only the raw case can be a move.
fn stage_executable(
    artifact: &std::path::Path,
    path: &std::path::Path,
    archive_key: Option<&str>,
) -> Result<PathBuf, String> {
    let temp = path.with_extension("staged");
    // A raw artifact is already the program, and it was downloaded into this Supervisor's own
    // directory — so it can be renamed into place instead of copied, which the staging path below
    // cannot assume and the Client's own update (whose artifact is not next to its destination)
    // has no equivalent for.
    if crate::archive::detect(artifact)? == crate::archive::Kind::Raw
        && std::fs::rename(artifact, &temp).is_ok()
    {
        info!(artifact = %artifact.display(), "moved the package artifact into place");
        install::make_executable(&temp)?;
    } else {
        let member = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| format!("{} has no file name to look for", path.display()))?;
        install::write_program(artifact, &temp, &member, archive_key)?;
    }
    Ok(temp)
}

/// Unpacks a package that is a whole directory tree into `<root>/tree` (ADR-0026).
///
/// The tree is built in a staging directory first and moved into place by one rename, so the live
/// name is either the old tree or the new one and never a half-written mixture. The live name is
/// already free — the caller set the previous tree aside — and that previous tree is what a failed
/// install is restored from, untouched throughout: nothing here ever writes into it.
///
/// `program_path` decides two things at once: which member of the archive is the program, and
/// which directory prefix is dropped so the unpacked tree starts where the configuration says it
/// does. A raw artifact — no archive at all — is written to that path directly, so an agent
/// configured for a tree does not fail merely because someone uploaded a bare binary.
fn stage_tree(
    artifact: &std::path::Path,
    root: &std::path::Path,
    program_path: &std::path::Path,
    archive_key: Option<&str>,
) -> Result<PathBuf, String> {
    let staging = root.join(".staging");
    // A previous attempt that died between unpacking and the rename would leave this behind.
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .map_err(|e| format!("cannot create {}: {e}", staging.display()))?;

    let unpack = |staging: &std::path::Path| -> Result<(), String> {
        let summary = match crate::archive::detect(artifact)? {
            crate::archive::Kind::Raw => {
                let program = staging.join(program_path);
                if let Some(parent) = program.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                }
                std::fs::copy(artifact, &program)
                    .map_err(|e| format!("cannot write {}: {e}", program.display()))?;
                info!(artifact = %artifact.display(), program = %program_path.display(), "the package is a bare program; placed it where the tree expects it");
                return Ok(());
            }
            crate::archive::Kind::TarGz => {
                crate::archive::extract_tree_tar_gz(artifact, program_path, staging)?
            }
            crate::archive::Kind::SevenZ => {
                crate::archive::extract_tree_7z(artifact, program_path, staging, archive_key)?
            }
            crate::archive::Kind::Zip => {
                crate::archive::extract_tree_zip(artifact, program_path, staging)?
            }
        };
        info!(archive = %artifact.display(), files = summary.files, bytes = summary.bytes, skipped = summary.skipped, "unpacked the package tree");
        Ok(())
    };

    // Whatever went wrong, the staging directory does not survive it: the next install must start
    // from an empty one, and a failed unpack has no value to anyone.
    if let Err(e) = unpack(&staging) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    let program = staging.join(program_path);
    if !program.is_file() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!(
            "the unpacked package holds no file at {}",
            program_path.display()
        ));
    }
    // The tree carries its own modes where the archive had them, but whether the *program* can be
    // executed is not something to inherit from how someone built an archive.
    install::make_executable(&program)?;
    Ok(staging)
}

pub(crate) fn unhealthy(status: String, last_error: String) -> ComponentHealth {
    ComponentHealth {
        healthy: false,
        status,
        last_error,
        status_time_unix_nano: now_ns(),
        ..Default::default()
    }
}

/// Wall-clock nanoseconds since the Unix epoch — what OpAMP's `*_time_unix_nano` fields carry.
pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Wall-clock seconds since the Unix epoch — what a retention deadline (ADR-0026) is written and
/// compared in, so it survives a Client restart.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program held open for writing cannot be exec'd for that moment (`ETXTBSY`); the probe
    /// waits it out instead of reporting a program that cannot run — the race a staged package
    /// meets when another thread forks while it is being written.
    /// Linux alone refuses to exec a file held open for writing, so the race exists only there.
    /// Verifies: ADR-0017
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_program_busy_for_a_moment_is_run_once_it_is_free() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join("true");
        std::fs::copy("/bin/true", &program).expect("copy a program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&program)
            .expect("hold it open for writing");
        let busy = Command::new(&program).output().await;
        assert!(
            busy.as_ref().is_err_and(install::is_text_file_busy),
            "the condition this guards against: {busy:?}"
        );
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            drop(writer);
        });
        let output = bounded_output(&mut Command::new(&program))
            .await
            .expect("in time")
            .expect("run once the writer let go");
        assert!(output.status.success());
    }

    // What remains here are the cases that reach *into* this module — a private helper and the
    // install function — and need no program to spawn. Everything that supervises a running process
    // lives in `tests/supervisor_process.rs`, where a real stub is reachable (ADR-0010) and the
    // cases run on all three platforms.

    #[test]
    fn find_semver_extracts_the_first_strict_version_from_free_text() {
        // The shapes real tools print.
        assert_eq!(
            find_semver("otelcol-contrib version 0.114.0").as_deref(),
            Some("0.114.0")
        );
        assert_eq!(find_semver("thing v1.2.3,").as_deref(), Some("1.2.3"));
        assert_eq!(
            find_semver("agent 2.0.0-rc.1+build.5 (linux/amd64)").as_deref(),
            Some("2.0.0-rc.1+build.5")
        );
        // The first version wins.
        assert_eq!(
            find_semver("v1.0.0 (protocol 3.4.5)").as_deref(),
            Some("1.0.0")
        );
        // A dangling separator counts as trailing punctuation around a valid core.
        assert_eq!(find_semver("version 1.2.3-").as_deref(), Some("1.2.3"));
        // Not SemVer 2: too few parts, leading zeros, invalid prerelease identifiers.
        assert_eq!(find_semver("version 1.2"), None);
        assert_eq!(find_semver("version 01.2.3"), None);
        assert_eq!(find_semver("version 1.2.3-rc.01"), None);
        assert_eq!(find_semver("no version at all"), None);
    }

    /// ADR-0017 stages the download in the same directory the program lives in, so installing a
    /// raw artifact is a move and not a second full write of several hundred megabytes. What makes
    /// that observable is *why* the artifact is gone: it became the program, rather than being
    /// copied and deleted.
    ///
    /// The mode assertion is the one this could genuinely break, and it is Unix's alone. A written
    /// file gets its permissions from the process umask and was always chmod'ed afterwards; a moved
    /// one carries whatever the download had — 0644 here, as `File::create` leaves it — so skipping
    /// the chmod would install a program that cannot be executed.
    #[test]
    fn a_raw_artifact_beside_the_program_is_moved_into_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("packages/agent.staged");
        std::fs::create_dir_all(artifact.parent().expect("parent")).expect("mkdir");
        std::fs::write(&artifact, b"the-program").expect("stage");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }

        let program = dir.path().join("program/agent");
        std::fs::create_dir_all(program.parent().expect("parent")).expect("mkdir");
        let target = InstallTarget::Binary(program.clone());
        let staged = target.stage(&artifact, None).expect("stage");
        target.commit(&staged).expect("commit");

        assert_eq!(std::fs::read(&program).expect("read"), b"the-program");
        assert!(
            !artifact.exists(),
            "the artifact was moved, not copied — the caller's cleanup of it is best-effort"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&program)
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o755,
                "a moved artifact is still made executable"
            );
        }
    }

    /// An archive can never be moved: what belongs at the program's path is one member of it, not
    /// the container. It is unpacked, and the artifact stays for the caller to clean up.
    ///
    /// This is also the stream branch of `stage_executable`. The other way into it — a rename
    /// that fails because the staging directory an operator configured is on another filesystem —
    /// runs the same code and is not forced here; doing so would need a second mount.
    #[test]
    fn an_archive_is_unpacked_and_the_artifact_survives_the_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("release.tar.gz");
        {
            let file = std::fs::File::create(&artifact).expect("create");
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
            let mut builder = tar::Builder::new(encoder);
            let content = b"the-member".as_slice();
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "agent-2.0.0/agent", content)
                .expect("append");
            builder.into_inner().expect("tar").finish().expect("gzip");
        }

        let program = dir.path().join("agent");
        let target = InstallTarget::Binary(program.clone());
        let staged = target.stage(&artifact, None).expect("stage");
        target.commit(&staged).expect("commit");

        assert_eq!(std::fs::read(&program).expect("read"), b"the-member");
        assert!(
            artifact.exists(),
            "the archive is read, never consumed — only its member is installed"
        );
    }

    /// ADR-0026: a retained predecessor is swept only once its deadline passes, never before, and
    /// the marker goes with it.
    /// Verifies: ADR-0026
    #[test]
    fn a_retained_backup_is_swept_only_after_its_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = InstallTarget::Binary(dir.path().join("prog"));
        std::fs::write(target.backup(), b"the previous version").expect("write backup");
        target.retain(1000); // deadline: 1000 unix-seconds
        assert!(
            target.backup_marker().exists(),
            "the marker records the deadline"
        );

        assert!(!target.sweep(999), "before the deadline it is kept");
        assert!(
            target.backup().exists(),
            "the previous version is still there"
        );

        assert!(target.sweep(1000), "at the deadline it is swept");
        assert!(!target.backup().exists(), "the previous version is gone");
        assert!(!target.backup_marker().exists(), "and so is its marker");
    }

    /// A backup with no marker is not something this Runner retained (a half-finished install
    /// leaves one), so a sweep leaves it alone.
    /// Verifies: ADR-0026
    #[test]
    fn a_sweep_leaves_an_unmarked_backup_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = InstallTarget::Binary(dir.path().join("prog"));
        std::fs::write(target.backup(), b"unmarked").expect("write backup");
        assert!(!target.sweep(u64::MAX), "no marker, nothing to sweep");
        assert!(target.backup().exists());
    }

    /// Dropping a backup takes its marker too, so a superseding update does not leave a dangling
    /// deadline behind.
    /// Verifies: ADR-0026
    #[test]
    fn dropping_a_backup_clears_its_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = InstallTarget::Binary(dir.path().join("prog"));
        std::fs::write(target.backup(), b"old").expect("write");
        target.retain(5000);
        assert!(target.backup_marker().exists());
        target.drop_backup();
        assert!(!target.backup().exists());
        assert!(!target.backup_marker().exists());
    }
}
