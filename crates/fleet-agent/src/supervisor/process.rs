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
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{info, instrument, warn, Instrument as _};

use crate::install;
use crate::shutdown::Shutdown;
use crate::supervisor::ports::{
    EventSender, InstallTarget, ProcessCommand, ProcessEvent, REFUSED, UNREACHABLE,
};
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

/// One start of a Managed Process, resolved: the program made absolute, the environment with the
/// Supervisor Endpoint's token last, the working directory decided. What a [`Spawner`] is handed,
/// and what the channel to the second service carries (ADR-0059 clause 5).
#[derive(Clone, Serialize, Deserialize)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// In order; a later entry for the same key wins.
    pub env: Vec<(String, String)>,
    /// The Supervisor Endpoint's token, set as [`ENDPOINT_TOKEN_ENV`] after every entry of
    /// [`Launch::env`], so none can replace it (ADR-0015). Held in a `Zeroizing` buffer; the
    /// copies the spawn and the program keep are beyond this code's reach (ADR-0057 clause 4).
    #[serde(with = "zeroizing_token")]
    pub endpoint_token: Option<zeroize::Zeroizing<String>>,
    pub working_dir: Option<PathBuf>,
    /// [`ProcessSpec::own_process_group`].
    pub own_process_group: bool,
}

impl Launch {
    /// Sets [`Launch::env`] on `command`, and the token after it.
    pub(crate) fn set_env(&self, command: &mut Command) {
        command.envs(self.env.iter().cloned());
        if let Some(token) = &self.endpoint_token {
            command.env(ENDPOINT_TOKEN_ENV, token.as_str());
        }
    }
}

impl std::fmt::Debug for Launch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launch")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env)
            .field(
                "endpoint_token",
                &self.endpoint_token.as_ref().map(|_| "<redacted>"),
            )
            .field("working_dir", &self.working_dir)
            .field("own_process_group", &self.own_process_group)
            .finish()
    }
}

/// The token of a [`Launch`] on the channel: written from its `Zeroizing` buffer, and read into
/// one straight from the string the decoder made (ADR-0057 clause 3).
mod zeroizing_token {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    #[allow(clippy::ref_option)] // the signature `serde(with)` asks for
    pub(super) fn serialize<S: Serializer>(
        token: &Option<Zeroizing<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match token {
            Some(token) => serializer.serialize_some(token.as_str()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Zeroizing<String>>, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.map(Zeroizing::new))
    }
}

/// Who starts a Managed Process (ADR-0059): the Client itself, or the second service under the
/// process account, through its channel. The Client starts its programs itself wherever no process
/// account is registered.
#[derive(Clone, Default)]
pub enum Spawner {
    /// The Client starts the program as a child of its own.
    #[default]
    Local,
    /// The second service starts it, on the Client's request (ADR-0059 clause 3).
    Channel(crate::supervisor::channel::Channel),
}

impl Spawner {
    /// Starts `launch` for the Supervisor named `supervisor`.
    ///
    /// # Errors
    /// Returns why the program did not start, keeping the OS error either way, so a missing
    /// program and one momentarily busy are still told apart.
    pub async fn spawn(&self, supervisor: &str, launch: Launch) -> std::io::Result<ManagedChild> {
        // The name is for the channel, which logs a program's output under it; a program the
        // Client starts itself writes to the Client's own streams.
        match self {
            Spawner::Local => spawn_local(&launch).map(ManagedChild::Local),
            Spawner::Channel(channel) => channel
                .start(supervisor, launch)
                .await
                .map(ManagedChild::Remote),
        }
    }

    /// Reaches the second service now, or says why it is not reached; at once for the Client,
    /// which starts its programs itself. A start may still not reach it: the service can go
    /// between the two.
    ///
    /// # Errors
    /// Returns why the second service was not reached, an error [`is_unreachable`] holds for.
    pub async fn reach(&self) -> std::io::Result<()> {
        match self {
            Spawner::Local => Ok(()),
            Spawner::Channel(channel) => channel.reach().await,
        }
    }

    /// Removes what the Managed Processes wrote in each of `removed` — a Supervisor's name and its
    /// directory — and the Client cannot remove itself, before the Client purges the rest
    /// (ADR-0059 clause 5): through the second service, which runs as their account, all of them
    /// within one wait. Nothing for the Client, which owns what its own programs wrote.
    ///
    /// # Errors
    /// Each answer, in the order of `removed`, is what the second service could not remove, or
    /// why it was not reached.
    pub async fn purge(&self, removed: &[(String, PathBuf)]) -> Vec<std::io::Result<()>> {
        match self {
            Spawner::Local => removed.iter().map(|_| Ok(())).collect(),
            Spawner::Channel(channel) => channel.purge(removed).await,
        }
    }

    /// Runs `launch` to its end, as the version probe and the preflight do, within
    /// [`PROBE_TIMEOUT`] once the second service is reached: `None` when it does not end in time,
    /// and is stopped. A second service that is not reached is an error [`is_unreachable`] holds
    /// for. Its output is what it
    /// wrote, the last [`crate::supervisor::channel::CAPTURED`] bytes of each stream where the
    /// second service relays it.
    ///
    /// A program written moments ago may fail to exec with `ETXTBSY` while another thread's fork
    /// still holds it open for writing ([`install::is_text_file_busy`] states why); that is
    /// retried briefly, as a spawn is, rather than taken for a program that cannot run.
    pub(crate) async fn output(
        &self,
        supervisor: &str,
        launch: &Launch,
    ) -> Option<std::io::Result<std::process::Output>> {
        // Reached first, outside the bound: a start may wait for the second service to come back,
        // and a wait for it that the bound cut short would read as a program that did not answer.
        if let Err(e) = self.reach().await {
            return Some(Err(e));
        }
        let mut attempt = 0;
        loop {
            let run = async {
                match self {
                    Spawner::Local => local_command(launch).output().await,
                    Spawner::Channel(channel) => channel.output(supervisor, launch.clone()).await,
                }
            };
            match tokio::time::timeout(PROBE_TIMEOUT, run).await {
                Err(_) => return None,
                Ok(Err(e)) if install::is_text_file_busy(&e) && attempt < install::BUSY_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(install::BUSY_DELAY).await;
                }
                Ok(result) => return Some(result),
            }
        }
    }
}

/// `launch` as the Client runs it to its end itself.
fn local_command(launch: &Launch) -> Command {
    let mut command = Command::new(&launch.program);
    command.args(&launch.args).kill_on_drop(true);
    launch.set_env(&mut command);
    if let Some(dir) = &launch.working_dir {
        command.current_dir(dir);
    }
    command
}

fn spawn_local(launch: &Launch) -> std::io::Result<Child> {
    let mut command = Command::new(&launch.program);
    command.args(&launch.args);
    launch.set_env(&mut command);
    if let Some(dir) = &launch.working_dir {
        command.current_dir(dir);
    }
    // If the runner is dropped without a graceful stop, take the process along.
    command.kill_on_drop(true);
    // Its own process group, so `stop` can signal the group and leave no worker behind
    // (ADR-0017). Unix-only: what Windows offers instead is a job object, which the stop
    // there does not use yet.
    #[cfg(unix)]
    if launch.own_process_group {
        command.process_group(0);
    }
    command.spawn()
}

/// Whether `error` says that the second service was not reached, rather than that the program did
/// not start or failed (ADR-0059 clause 2). Never so for a program the Client starts itself.
#[must_use]
pub fn is_unreachable(error: &std::io::Error) -> bool {
    crate::supervisor::channel::is_unreachable(error)
}

/// Whether `error` says that the second service was reached and refused, or was refused: another
/// account serves its socket, it is another build, or it refused the Client (ADR-0059 clauses 4
/// and 5). [`is_unreachable`] holds for it too. Never so for a program the Client starts itself.
#[must_use]
pub fn is_refused(error: &std::io::Error) -> bool {
    crate::supervisor::channel::is_refused(error)
}

/// A start that found the second service unreachable, or a program that went with the service:
/// no failed start of the program's, so the [`RestartPolicy`] does not count it and never holds
/// for it. The start is tried again, with a backoff of its own, until the service is back
/// (ADR-0059 clause 2).
struct Waiting {
    /// When the next start is due; `None` while nothing waits for the service.
    due: Option<tokio::time::Instant>,
    /// Whether the last start did not reach the second service. A start made due at once by one
    /// that did reach it (`due_now`) is due without the service being away.
    away: bool,
    backoff: Backoff,
}

impl Waiting {
    fn new() -> Self {
        Waiting {
            due: None,
            away: false,
            backoff: Backoff::new(),
        }
    }

    /// The service was not reached: the next start is due after the backoff.
    fn arm(&mut self) {
        self.due = Some(tokio::time::Instant::now() + self.backoff.advance());
        self.away = true;
    }

    /// The service was reached by a start that decided nothing that waits for it: the start that
    /// does is due now, and the service is not away.
    fn due_now(&mut self) {
        self.due = Some(tokio::time::Instant::now());
        self.away = false;
    }

    /// The service was reached, or nothing is to start: nothing waits.
    fn clear(&mut self) {
        self.due = None;
        self.away = false;
        self.backoff.reset();
    }

    /// Resolves when the next start is due; never while nothing waits.
    async fn due(&self) {
        match self.due {
            Some(due) => tokio::time::sleep_until(due).await,
            None => std::future::pending().await,
        }
    }

    /// Whether the last start did not reach the second service.
    fn armed(&self) -> bool {
        self.away
    }
}

/// A configuration whose start did not reach the second service, or whose program went with the
/// service during the apply grace: neither applied nor failed, so the Agent stays `APPLYING`, and
/// the first start that reaches the service and survives the apply grace acknowledges it
/// (ADR-0059 clause 2).
struct OwedConfig {
    hash: Vec<u8>,
    /// The span of its apply.
    span: tracing::Span,
}

/// A package that arrived while the second service could not be reached, or whose start did not
/// reach it: staged and checked, never swapped in, so what ran before stays in place. It is
/// swapped in, and gated, by the next start that may reach the service (ADR-0059 clause 2); until
/// then the Agent reports it `Installing`.
struct Parked {
    staged: Staged,
    /// Whether the preflight has run on it. One that did not reach the second service is run by
    /// the start that reaches it, before the swap (ADR-0059 clauses 2 and 3).
    checked: bool,
    version: String,
    hash: Vec<u8>,
    span: tracing::Span,
}

/// What the supervision loop of [`Runner::run`] carries from one event to the next.
struct Supervision {
    /// The Managed Process, while one runs.
    child: Option<ManagedChild>,
    /// Consecutive start failures, and when the current process started (ADR-0026): together they
    /// stop a program that keeps crashing from being restarted forever. A process that runs
    /// stably clears the streak; a command (config, package, restart) resets it.
    policy: RestartPolicy,
    backoff: Backoff,
    waiting: Waiting,
    /// A configuration whose acknowledgement waits for a start that reaches the second service
    /// (ADR-0059 clause 2).
    owed: Option<OwedConfig>,
    /// A package that waits for the second service to be swapped in (ADR-0059 clause 2).
    parked: Option<Parked>,
}

/// What the preflight of a package that waited for the second service came to.
enum Checked {
    /// Proved, or nothing to prove: the swap goes ahead.
    Ready(Parked),
    /// Refused, or still waiting; `true` when shutdown was requested meanwhile.
    Done(bool),
}

/// What a swap came to: gated, or taken back out to wait for the second service.
enum Swapped {
    Gated(GraceOutcome),
    Parked(Staged),
}

/// A running Managed Process, whichever [`Spawner`] started it. One per Supervisor, so the size of
/// a Windows `Child` beside a `RemoteChild` costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
pub enum ManagedChild {
    Local(Child),
    Remote(crate::supervisor::channel::RemoteChild),
}

impl ManagedChild {
    /// The process id, until the process has been waited for.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        match self {
            ManagedChild::Local(child) => child.id(),
            ManagedChild::Remote(child) => child.id(),
        }
    }

    /// Waits for the process to end. Cancel-safe.
    ///
    /// # Errors
    /// Returns an error when waiting failed, or the channel to the second service closed first.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self {
            ManagedChild::Local(child) => child.wait().await,
            ManagedChild::Remote(child) => child.wait().await,
        }
    }

    async fn kill(&mut self) -> std::io::Result<()> {
        match self {
            ManagedChild::Local(child) => child.kill().await,
            ManagedChild::Remote(child) => child.kill().await,
        }
    }

    /// Sends `signal` to the process — with `group`, to its whole process group where it leads
    /// one (ADR-0017). Nothing to do once it has been waited for.
    async fn signal(&self, signal: i32, group: bool) -> Result<(), String> {
        match self {
            ManagedChild::Local(child) => {
                let Some(pid) = child.id() else {
                    return Ok(());
                };
                #[cfg(unix)]
                if group {
                    signal_child(pid, signal);
                    return Ok(());
                }
                #[cfg(not(unix))]
                let _ = group;
                send_reload_signal(pid, signal)
            }
            ManagedChild::Remote(child) => {
                child.signal(signal, group).await.map_err(|e| e.to_string())
            }
        }
    }
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
    ///
    /// Where a process account is registered, that directory is `program/`, read by the process
    /// group and written by the Client alone (ADR-0059 clause 6).
    pub fn prepare(
        &self,
        group: Option<crate::storage::ProcessAccountGroup>,
    ) -> Result<(), String> {
        let dir = match self {
            InstallTarget::Binary(path) => path.parent().map(std::path::Path::to_path_buf),
            InstallTarget::Tree { root, .. } => Some(root.clone()),
        };
        let Some(dir) = dir else {
            return Ok(());
        };
        let prepared = match group {
            // Its own root: the process account writes neither in it nor above it.
            Some(_) => {
                crate::storage::create_shared_dir(&dir, &dir, group, crate::storage::Shared::Read)
            }
            None => std::fs::create_dir_all(&dir),
        };
        prepared.map_err(|e| format!("cannot prepare {}: {e}", dir.display()))
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
    ///
    /// A tree is staged in a directory the process account's group reads, where a process account
    /// is registered, so the preflight it runs can reach it, and what is staged — every member of a
    /// tree, or the single program — is given to that group, without write for the group or others
    /// (ADR-0059 clauses 6 and 11).
    fn stage(
        &self,
        artifact: &std::path::Path,
        archive_key: Option<&str>,
        group: Option<crate::storage::ProcessAccountGroup>,
    ) -> Result<Staged, String> {
        match self {
            InstallTarget::Binary(path) => {
                let temp = stage_executable(artifact, path, archive_key)?;
                if let Err(e) = share_staged(&temp, group) {
                    let _ = std::fs::remove_file(&temp);
                    return Err(e);
                }
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
                let staging = stage_tree(artifact, root, program_path, archive_key, group)?;
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

    /// Puts back what ran before. Where nothing is there to put back, what is live stays, so a
    /// failed rollback never empties `program/` (ADR-0026 clause 62).
    fn restore(&self) -> Result<(), String> {
        let (live, backup) = (self.live(), self.backup());
        if let Err(e) = std::fs::symlink_metadata(&backup) {
            return Err(format!("cannot restore {}: {e}", live.display()));
        }
        self.remove(&live);
        std::fs::rename(&backup, &live)
            .map_err(|e| format!("cannot restore {}: {e}", live.display()))
    }

    /// Takes a package that was swapped in back out to its staged name, and puts back what ran
    /// before it (ADR-0059 clause 2). On an error what was live is live again: where the package
    /// cannot be taken out it stays, and where what ran before cannot be put back the package is
    /// put back, so `program/` is never left empty (ADR-0026 clause 62).
    fn take_back(&self, staged: &Staged, has_backup: bool) -> Result<(), String> {
        let live = self.live();
        std::fs::rename(&live, &staged.temp)
            .map_err(|e| format!("cannot take {} back out: {e}", live.display()))?;
        if has_backup {
            if let Err(e) = self.restore() {
                return match std::fs::rename(&staged.temp, &live) {
                    Ok(()) => Err(e),
                    Err(back) => Err(format!("{e}; nor can the package be put back: {back}")),
                };
            }
        }
        Ok(())
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
    ///
    /// The marker is the Client's alone, `0600`, though it stands in `program/`, which the process
    /// account's group reads (ADR-0059 clause 6).
    fn retain(&self, deadline_unix: u64) {
        let _ = crate::storage::write_private(
            &self.backup_marker(),
            deadline_unix.to_string().as_bytes(),
        );
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
    /// Handed to the Managed Process as [`ENDPOINT_TOKEN_ENV`] (ADR-0015); wiped when it is
    /// dropped (ADR-0057).
    pub endpoint_token: zeroize::Zeroizing<String>,
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
    pub archive_key: Option<zeroize::Zeroizing<String>>,
    /// How to learn the Managed Process's own version, when the plugin knows how to ask.
    pub version_probe: Option<VersionProbe>,
    /// How to prove a staged package runs before it replaces what does (ADR-0017 clause 57). `None` proves
    /// nothing in advance: the swap is the first thing that finds out.
    pub preflight: Option<Preflight>,
    /// The signal that makes the running process re-read its configuration in place (ADR-0017);
    /// `None` — the generic behaviour — applies a configuration by restarting. A reload that
    /// fails, or a process that dies on it, falls back to the restart (`reload-or-restart`).
    pub reload_signal: Option<i32>,
    /// Who starts the Managed Process (ADR-0059).
    pub spawner: Spawner,
    /// The process account's primary group, where a process account is registered: the
    /// directories the Managed Process writes into and the preflight's staging belong to it
    /// (ADR-0059 clause 6).
    pub process_account_group: Option<crate::storage::ProcessAccountGroup>,
    /// The Supervisor's own directory (ADR-0017): beneath it, no link is followed on the way to a
    /// directory the Managed Process writes into.
    pub supervisor_dir: PathBuf,
    pub events: EventSender,
    pub commands: mpsc::Receiver<ProcessCommand>,
    pub build: Box<dyn Fn() -> Option<ProcessSpec> + Send + Sync>,
}

impl Runner {
    pub async fn run(mut self, mut shutdown: Shutdown) {
        let mut s = Supervision {
            child: None,
            policy: RestartPolicy::new(self.apply_grace, Instant::now()),
            backoff: Backoff::new(),
            waiting: Waiting::new(),
            owed: None,
            parked: None,
        };
        // Clear any predecessor whose retention window already elapsed while the Client was down
        // (ADR-0026) — the deadline is wall-clock, so a restart is exactly when one may have passed.
        self.sweep_backup();
        // What runs today, before it runs: a Collector without the opampextension never reports
        // its own version, and one that is not configured yet never even starts.
        self.probe_version();
        // A start through the second service may wait for it to come back; a shutdown does not.
        s.child = tokio::select! {
            child = self.spawn_if_due(&mut s.waiting) => child,
            _ = shutdown.requested() => None,
        };

        // Honour the retention window even when the Client stays up past it. Cheap and coarse: a
        // day-long window does not need a tight tick, and the sweep itself is a stat plus a delete.
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        sweep.tick().await; // the first tick is immediate; the startup sweep above already ran

        loop {
            // The retry is the start for what waits for the second service, so it is due with a
            // program running too: one a restart command started on the current files.
            let retry = s.child.is_none() || s.owed.is_some() || s.parked.is_some();
            let exited = async {
                match s.child.as_mut() {
                    Some(c) => c.wait().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = sweep.tick() => self.sweep_backup(),
                // The second service was not reached: try again, as long as no shutdown comes
                // first (ADR-0059 clause 2). A package that waits for it is what is started then,
                // and a configuration owed its acknowledgement is decided by this start.
                () = s.waiting.due(), if retry => {
                    if let Some(package) = s.parked.take() {
                        if self.install(package, &mut s, &mut shutdown).await {
                            break;
                        }
                        continue;
                    }
                    // What a restart command started acknowledges nothing (ADR-0017 clause 8).
                    stop(&mut s.child, self.stop_timeout, &self.name).await;
                    let started = tokio::select! {
                        started = self.spawn_if_due(&mut s.waiting) => started,
                        _ = shutdown.requested() => break,
                    };
                    if self.started(started, &mut s, &mut shutdown).await {
                        break;
                    }
                }
                command = self.commands.recv() => match command {
                    Some(ProcessCommand::ApplyConfig { config, span }) => {
                        s.policy.fresh_chance(); // a new configuration (ADR-0026)
                        s.backoff.reset();
                        // A configuration still owed its acknowledgement is superseded by this
                        // one, whose status the Agent reports from now on.
                        s.owed = None;
                        // A package waits for the second service: the start that swaps it in is
                        // this configuration's start too, and decides it.
                        if let Some(package) = s.parked.take() {
                            s.owed = Some(OwedConfig { hash: config.config_hash, span });
                            if self.install(package, &mut s, &mut shutdown).await {
                                break;
                            }
                            continue;
                        }
                        // In place first (ADR-0017): a kind that declared a reload keeps its
                        // process — and its in-flight state — across the change; anything short
                        // of a survived grace falls back to the restart below.
                        match self
                            .try_reload(&mut s.child, &mut shutdown)
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
                        stop(&mut s.child, self.stop_timeout, &self.name).await;
                        let started = self.spawn_if_due(&mut s.waiting).await;
                        drop(restart);
                        // The configuration is owed its acknowledgement until its start decides
                        // it, exactly as one that waits for the second service is.
                        s.owed = Some(OwedConfig { hash: config.config_hash, span });
                        if self.started(started, &mut s, &mut shutdown).await {
                            break;
                        }
                    }
                    Some(ProcessCommand::ApplyPackage { staged, version, hash, span }) => {
                        // A newer offer replaces the one that waits for the second service: what
                        // was staged for it goes, and nothing is reported for it — the Agent
                        // reports the newer one (ADR-0059 clause 2).
                        if let Some(superseded) = s.parked.take() {
                            info!(supervisor = %self.name, version = %superseded.version, "a package that waited for the second service is replaced by a newer one");
                            self.discard(&superseded);
                        }
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
                        s.policy.fresh_chance(); // a new package (ADR-0026)
                        s.backoff.reset();
                        let (staged, checked) = prepared;
                        let package = Parked { staged, checked, version, hash, span };
                        // The second service is away: staged and kept, never swapped in, so what
                        // ran stays in place until a start can reach the service (ADR-0059
                        // clause 2).
                        if s.waiting.armed() {
                            info!(supervisor = %self.name, version = %package.version, "package staged; it is swapped in once the second service is back");
                            s.parked = Some(package);
                            continue;
                        }
                        if self.install(package, &mut s, &mut shutdown).await {
                            break;
                        }
                    }
                    // A respawn on the current files, and nothing more (ADR-0017 clause 8): it
                    // acknowledges no configuration and swaps in no package that waits for the
                    // second service. Unless it found the service away, the retry for what waits
                    // is due at once (ADR-0059 clause 2).
                    Some(ProcessCommand::Restart) => {
                        stop(&mut s.child, self.stop_timeout, &self.name).await;
                        s.policy.fresh_chance(); // an operator restart (ADR-0026)
                        s.backoff.reset();
                        s.child = self.spawn_if_due(&mut s.waiting).await;
                        if s.child.is_some() {
                            s.policy.started(Instant::now());
                        }
                        if !s.waiting.armed() && (s.owed.is_some() || s.parked.is_some()) {
                            s.waiting.due_now();
                        }
                    }
                    Some(ProcessCommand::Uninstall) => {
                        // Retired for good (ADR-0017): the generic uninstall is exactly the
                        // graceful stop — nothing the generic Runner installs lives outside the
                        // Supervisor's directory, and that directory is the core's to purge
                        // (ADR-0017) once this answer is out.
                        stop(&mut s.child, self.stop_timeout, &self.name).await;
                        self.events
                            .send(ProcessEvent::Uninstalled { result: Ok(()) })
                            .await;
                        return;
                    }
                    Some(ProcessCommand::Shutdown) | None => break,
                },
                status = exited => {
                    // The program went with the second service, which the service manager brings
                    // back: no exit of the program's, and nothing to hold (ADR-0059 clause 2).
                    if status.as_ref().is_err_and(is_unreachable) {
                        warn!(supervisor = %self.name, "the second service went, and the program with it; starting it again once the service is back");
                        s.child = None;
                        self.events
                            .send(ProcessEvent::Health(unhealthy(
                                UNREACHABLE.to_string(),
                                "the second service went, and the program with it".to_string(),
                            )))
                            .await;
                        s.waiting.arm();
                        continue;
                    }
                    let describe = describe_exit(status);
                    warn!(supervisor = %self.name, status = %describe, "process exited unexpectedly");
                    s.child = None;
                    self.events
                        .send(ProcessEvent::Health(unhealthy(
                            format!("exited unexpectedly ({describe})"),
                            describe,
                        )))
                        .await;
                    // A process that had been up a while is ordinary supervision, not a start loop:
                    // its exit clears the streak (ADR-0026). One that keeps exiting quickly does not,
                    // so it is held after a few tries rather than restarted forever.
                    s.policy.exited(Instant::now());
                    if self.respawn_or_hold(&mut s, &mut shutdown).await {
                        break;
                    }
                }
                _ = shutdown.requested() => break,
            }
        }
        stop(&mut s.child, self.stop_timeout, &self.name).await;
        // A package that waits was never swapped in: what runs is what the record names, and its
        // staged files go with the Client (ADR-0059 clause 2). A restarted Client is offered it
        // again.
        if let Some(package) = s.parked.take() {
            self.discard(&package);
        }
    }

    /// Unpacks the artifact beside what runs and — when the plugin said how — proves the staged
    /// program starts. Nothing that runs is touched here; that is the whole point (ADR-0017).
    /// The `stage` phase of an install's trace (ADR-0016); the preflight below is its own child.
    ///
    /// Beside the staged package: whether the preflight ran. One that did not reach the second
    /// service proves nothing either way, and the package waits for the service unchecked
    /// (ADR-0059 clause 2).
    #[instrument(name = "stage", skip_all, fields(supervisor = %self.name))]
    async fn stage_and_check(&self, artifact: &std::path::Path) -> Result<(Staged, bool), String> {
        let target = self
            .install
            .as_ref()
            .ok_or_else(|| "this supervisor manages nothing a package can replace".to_string())?;
        let staged = target.stage(
            artifact,
            self.archive_key.as_deref().map(String::as_str),
            self.process_account_group,
        )?;
        match self.check(&staged).await {
            Preflighted::Passed => Ok((staged, true)),
            Preflighted::Refused(e) => {
                target.discard(&staged);
                Err(e)
            }
            Preflighted::Unreached(e) => {
                info!(supervisor = %self.name, error = %e, "the second service cannot be reached for the preflight; the package waits for it");
                Ok((staged, false))
            }
        }
    }

    /// Runs the plugin's preflight on `staged`, where it has one (ADR-0017 clause 57).
    async fn check(&self, staged: &Staged) -> Preflighted {
        match &self.preflight {
            Some(preflight) => run_preflight(&self.spawner, &self.name, staged, preflight).await,
            None => Preflighted::Passed,
        }
    }

    /// Throws away what was staged for a package that will not be swapped in.
    fn discard(&self, package: &Parked) {
        if let Some(target) = &self.install {
            target.discard(&package.staged);
        }
    }

    /// Swaps a staged package in, starts it and gates it (ADR-0026), and reports the outcome;
    /// a package that fails is rolled back to its predecessor, which is started again.
    ///
    /// Swapped in only once the second service is reached (ADR-0059 clause 2): until then the
    /// package waits in `parked`, and what ran before stays in place, its retained predecessor
    /// with it, so no package is live before a start that can run it — and a Client that ends
    /// meanwhile, however it ends, leaves the program the record names. Where the service goes
    /// after all, before the start reaches it or during the apply grace, the package is taken
    /// back out to wait. A configuration owed its acknowledgement is decided by the start that
    /// reaches the service: the package's, or, where the package fails, its predecessor's.
    /// Returns `true` when shutdown was requested meanwhile.
    async fn install(&self, package: Parked, s: &mut Supervision, shutdown: &mut Shutdown) -> bool {
        let reached = tokio::select! {
            reached = self.spawner.reach() => reached,
            _ = shutdown.requested() => {
                s.parked = Some(package);
                return true;
            }
        };
        if let Err(e) = reached {
            info!(supervisor = %self.name, version = %package.version, error = %e, "the second service cannot be reached; the package waits for it, and what runs stays in place");
            s.waiting.arm();
            self.events
                .send(ProcessEvent::Health(unhealthy(
                    why_unreached(&e).to_string(),
                    format!("a package waits for it: {e}"),
                )))
                .await;
            s.parked = Some(package);
            return false;
        }
        // The preflight the second service was away for runs now, before anything is stopped.
        let package = match self.check_parked(package, s, shutdown).await {
            Checked::Ready(package) => package,
            Checked::Done(shutting_down) => return shutting_down,
        };
        let Parked {
            staged,
            checked: _,
            version,
            hash,
            span,
        } = package;
        // Swap the binary, restart, and health-gate on the apply grace — a binary that will not
        // stay up is rolled back to the bytes it replaced (ADR-0026).
        stop(&mut s.child, self.stop_timeout, &self.name).await;
        let swapped = self
            .swap_and_gate(staged, &version, &mut s.child, &mut s.waiting, shutdown)
            .instrument(span.clone())
            .await;
        let outcome = match swapped {
            Swapped::Gated(outcome) => outcome,
            Swapped::Parked(staged) => {
                let package = Parked {
                    staged,
                    checked: true,
                    version,
                    hash,
                    span,
                };
                s.parked = Some(package);
                return false;
            }
        };
        match outcome {
            GraceOutcome::Ok => {
                if s.child.is_none() {
                    // Nothing to run yet: the configuration that arrives starts it.
                    s.child = self.spawn_if_due(&mut s.waiting).await;
                }
                s.policy.started(Instant::now());
                // A new binary is a new version, and the Agent's `service.version` is what the
                // program says about itself — so ask it again. Without this the swap is reported
                // as installed while the Agent goes on describing the version it replaced, until
                // the Client restarts.
                self.probe_version();
                crate::telemetry::succeeded(&span);
                self.events
                    .send(ProcessEvent::PackageApplied {
                        hash,
                        result: Ok(version),
                    })
                    .await;
                // The start that survived is the owed configuration's too.
                if let Some(config) = s.owed.take() {
                    self.settle(config, Ok(())).await;
                }
                false
            }
            GraceOutcome::Failed(error) => {
                crate::telemetry::failed(&span, &error);
                self.events
                    .send(ProcessEvent::PackageApplied {
                        hash,
                        result: Err(error),
                    })
                    .await;
                // The package's start failed, and counts as a failed start (ADR-0026 clause 63):
                // what runs now — the predecessor, rolled back, or a first install kept in place
                // — is started again once, unless the streak holds it, and stays supervised
                // exactly as after a failed ApplyConfig. That start, not the package's, decides
                // an owed configuration, and one that does not happen is not tried again, whether
                // a configuration is owed or not (see `started`).
                if let AfterFailure::Hold(failures) = s.policy.failed() {
                    self.hold(failures, s).await;
                    return false;
                }
                let started = tokio::select! {
                    started = self.spawn_if_due(&mut s.waiting) => started,
                    _ = shutdown.requested() => return true,
                };
                self.started(started, s, shutdown).await
            }
            GraceOutcome::ShuttingDown => true,
            // Does not occur: the swap returns its gate's `Unreachable` as `Swapped::Parked`,
            // handled above. Nothing to do were it to.
            GraceOutcome::Unreachable => false,
        }
    }

    /// Runs the preflight on a package that waited for the second service without one, now that
    /// the service is reached (ADR-0059 clause 3). A package it refuses is reported failed and
    /// thrown away, and a configuration owed its acknowledgement is decided by a start on the
    /// current program instead, as an apply would decide it; one it cannot run for want of the
    /// service waits on.
    async fn check_parked(
        &self,
        package: Parked,
        s: &mut Supervision,
        shutdown: &mut Shutdown,
    ) -> Checked {
        if package.checked {
            return Checked::Ready(package);
        }
        // A shutdown does not wait for the preflight: the package stays parked, unchecked, and
        // what ran before stays in place.
        let checked = tokio::select! {
            checked = self.check(&package.staged).instrument(package.span.clone()) => checked,
            _ = shutdown.requested() => {
                s.parked = Some(package);
                return Checked::Done(true);
            }
        };
        match checked {
            Preflighted::Passed => Checked::Ready(Parked {
                checked: true,
                ..package
            }),
            Preflighted::Unreached(e) => {
                s.waiting.arm();
                self.events
                    .send(ProcessEvent::Health(unhealthy(
                        why_unreached(&e).to_string(),
                        format!("a package waits for it: {e}"),
                    )))
                    .await;
                s.parked = Some(package);
                Checked::Done(false)
            }
            Preflighted::Refused(e) => {
                warn!(supervisor = %self.name, version = %package.version, error = %e, "refusing a package that will not run here");
                self.discard(&package);
                crate::telemetry::failed(&package.span, &e);
                self.events
                    .send(ProcessEvent::PackageApplied {
                        hash: package.hash,
                        result: Err(e),
                    })
                    .await;
                if s.owed.is_none() {
                    return Checked::Done(false);
                }
                stop(&mut s.child, self.stop_timeout, &self.name).await;
                let started = tokio::select! {
                    started = self.spawn_if_due(&mut s.waiting) => started,
                    _ = shutdown.requested() => return Checked::Done(true),
                };
                Checked::Done(self.started(started, s, shutdown).await)
            }
        }
    }

    /// Swaps the staged artifact over the binary, respawns, and health-gates on the apply grace,
    /// rolling the binary back on failure (ADR-0026). The process is already stopped. On success
    /// `child` holds the running process; on failure the previous binary is restored (and the
    /// caller respawns it). The second service was reached just before; where it has gone by the
    /// start, or goes during the grace, the package is taken back out to its staged name and what
    /// ran before is put back: it is [`Swapped::Parked`], neither installed nor failed (ADR-0059
    /// clause 2).
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
        child: &mut Option<ManagedChild>,
        waiting: &mut Waiting,
        shutdown: &mut Shutdown,
    ) -> Swapped {
        let Some(target) = &self.install else {
            return Swapped::Gated(GraceOutcome::Failed(
                "this supervisor manages nothing a package can replace".to_string(),
            ));
        };
        // Move what runs today aside — a rename, so it is atomic and costs nothing — and it is
        // what a failed package is rolled back from.
        let has_backup = match target.set_aside() {
            Ok(has_backup) => has_backup,
            Err(e) => {
                target.discard(&staged);
                return Swapped::Gated(GraceOutcome::Failed(e));
            }
        };
        if let Err(e) = target.commit(&staged) {
            // Put the old one back before reporting: the process must not be left with none.
            if has_backup {
                let _ = target.restore();
            }
            target.discard(&staged);
            return Swapped::Gated(GraceOutcome::Failed(e));
        }
        info!(supervisor = %self.name, version = %version, program = %target.live().display(), "package staged; restarting");

        // A start through the second service may wait for it to come back; a shutdown does not,
        // and leaves what ran before in place, as the record names it.
        let started = tokio::select! {
            started = self.try_spawn() => started,
            _ = shutdown.requested() => {
                match target.take_back(&staged, has_backup) {
                    Ok(()) => target.discard(&staged),
                    Err(e) => warn!(supervisor = %self.name, error = %e, "cannot take the package back out; it stays live"),
                }
                return Swapped::Gated(GraceOutcome::ShuttingDown);
            }
        };
        let outcome = match started {
            // Not started because the second service was not reached: the package rejected
            // nothing, and waits for the service out of the way (ADR-0059 clause 2).
            Err(e) if is_unreachable(&e) => {
                waiting.arm();
                GraceOutcome::Unreachable
            }
            // "Nothing started" has two meanings, and only one of them is a failed install. A
            // plugin with no process to run — a Collector that has not been configured yet — has
            // not rejected the artifact: the binary is in place and will be started by the
            // configuration when it arrives. `ApplyConfig` has always drawn this distinction; the
            // package path must too, or installing onto a host that is not yet configured deletes
            // what it just installed.
            Err(_) if (self.build)().is_none() => {
                waiting.clear();
                info!(supervisor = %self.name, version = %version, "package installed; nothing to run until a configuration arrives");
                GraceOutcome::Ok
            }
            Err(e) => {
                waiting.clear();
                warn!(supervisor = %self.name, error = %e, "the new binary would not start");
                self.gate(None, child, shutdown).await
            }
            Ok(proc) => {
                waiting.clear();
                let outcome = self.gate(Some(proc), child, shutdown).await;
                if matches!(outcome, GraceOutcome::Unreachable) {
                    waiting.arm();
                }
                outcome
            }
        };
        if matches!(outcome, GraceOutcome::Unreachable) {
            info!(supervisor = %self.name, version = %version, "the second service went before the package proved itself; the package waits for it, and what ran before is put back");
            return match target.take_back(&staged, has_backup) {
                Ok(()) => Swapped::Parked(staged),
                // The package stays live: concluded as a failed install, which puts back what
                // ran before where there is one to put back.
                Err(e) => {
                    warn!(supervisor = %self.name, error = %e, "cannot take the package back out");
                    self.conclude(target, has_backup, GraceOutcome::Failed(e))
                }
            };
        }
        self.conclude(target, has_backup, outcome)
    }

    /// Concludes a swap on its gate's `outcome` (ADR-0026): rolls back to the predecessor after a
    /// failure, keeps it for the retention window after a success.
    fn conclude(&self, target: &InstallTarget, has_backup: bool, outcome: GraceOutcome) -> Swapped {
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
        Swapped::Gated(outcome)
    }

    /// Reports the acknowledgement of a configuration: `APPLIED`, or `FAILED` with the reason.
    async fn settle(&self, config: OwedConfig, result: Result<(), String>) {
        match &result {
            Ok(()) => crate::telemetry::succeeded(&config.span),
            Err(e) => crate::telemetry::failed(&config.span, e),
        }
        self.events
            .send(ProcessEvent::ConfigApplied {
                hash: config.hash,
                result,
            })
            .await;
    }

    /// Takes in a program just started — by an apply, by the retry after the second service was
    /// not reached, or after a failed package — and, where a configuration is owed its
    /// acknowledgement, gates it and settles it (ADR-0017's health-gated acknowledgement): applying
    /// means running on the new files and surviving the apply grace. A start that did not reach
    /// the service leaves it owed (ADR-0059 clause 2). Returns `true` when shutdown was requested
    /// meanwhile.
    ///
    /// Only a program that ran and exited within the grace is started again (ADR-0026 clause 63):
    /// a start that did not happen — the program is not there, or cannot be executed — has
    /// already said why in its health, and starting the same files again would only say so once
    /// more.
    async fn started(
        &self,
        started: Option<ManagedChild>,
        s: &mut Supervision,
        shutdown: &mut Shutdown,
    ) -> bool {
        let ran = started.is_some();
        if ran {
            s.policy.started(Instant::now());
        }
        let Some(config) = s.owed.take() else {
            s.child = started;
            return false;
        };
        let outcome = if !ran && s.waiting.armed() {
            s.owed = Some(config);
            return false; // still away: owed on
        } else if !ran && (self.build)().is_none() {
            GraceOutcome::Ok // nothing should run, as the apply itself would have found
        } else {
            self.gate(started, &mut s.child, shutdown)
                .instrument(config.span.clone())
                .await
        };
        let result = match outcome {
            GraceOutcome::Ok => Ok(()),
            GraceOutcome::Failed(e) => Err(e),
            // Shutting down mid-grace: no acknowledgement — the goodbyes carry no status anyway —
            // just stop gracefully on the way out.
            GraceOutcome::ShuttingDown => return true,
            // Neither applied nor failed: the start that reaches the second service again decides
            // it (ADR-0059 clause 2).
            GraceOutcome::Unreachable => {
                s.waiting.arm();
                s.owed = Some(config);
                return false;
            }
        };
        let exited_in_grace = ran && result.is_err();
        self.settle(config, result).await;
        // Stay supervised: a flaky-but-valid configuration is retried with backoff — but not
        // forever (ADR-0026): a configuration that will not start is held after a few tries
        // rather than spun on.
        exited_in_grace && self.respawn_or_hold(s, shutdown).await
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
    ///
    /// A start that finds the second service unreachable is no failed start: it is left to
    /// `waiting`, and the streak is not counted for it (ADR-0059 clause 2).
    async fn respawn_or_hold(&self, s: &mut Supervision, shutdown: &mut Shutdown) -> bool {
        let delay = match s.policy.failed() {
            AfterFailure::Retry => s.backoff.advance(),
            AfterFailure::Hold(failures) => {
                self.hold(failures, s).await;
                return false;
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.requested() => return true,
        }
        // A start through the second service may wait for it to come back; a shutdown does not.
        tokio::select! {
            started = self.spawn_if_due(&mut s.waiting) => {
                s.child = started;
                s.policy.started(Instant::now());
                false
            }
            _ = shutdown.requested() => true,
        }
    }

    /// Holds the program down after `failures` failed starts in a row, and says so (ADR-0026
    /// clause 63): it is not started again until a new configuration, package, or restart. A
    /// configuration owed its acknowledgement — held after the package that was to be its start
    /// failed — is no longer waited for: no start comes to decide it, so it is `FAILED`
    /// (ADR-0059 clause 2).
    async fn hold(&self, failures: usize, s: &mut Supervision) {
        warn!(
            supervisor = %self.name, restarts = failures,
            "not restarting: the program keeps failing to start — holding until a new configuration, package, or restart"
        );
        let held = format!("held after {failures} failed starts in a row");
        self.events
            .send(ProcessEvent::Health(unhealthy(
                "not restarting: the program keeps failing to start".to_string(),
                held.clone(),
            )))
            .await;
        s.child = None;
        if let Some(config) = s.owed.take() {
            self.settle(config, Err(held)).await;
        }
    }

    /// The `gate` phase: the apply-grace health gate a configuration apply and a package swap
    /// share (ADR-0017). A freshly started process must survive `apply_grace` to count as applied;
    /// exiting within it fails, and so does a process that never started. `child` is left holding
    /// the running process on success.
    #[instrument(name = "gate", skip_all, fields(supervisor = %self.name))]
    async fn gate(
        &self,
        started: Option<ManagedChild>,
        child: &mut Option<ManagedChild>,
        shutdown: &mut Shutdown,
    ) -> GraceOutcome {
        match started {
            None => GraceOutcome::Failed("the process did not start".to_string()),
            Some(mut proc) if !self.apply_grace.is_zero() => {
                tokio::select! {
                    status = proc.wait() => {
                        // The program went with the second service: it rejected nothing, and the
                        // start that reaches the service again decides (ADR-0059 clause 2).
                        if status.as_ref().is_err_and(is_unreachable) {
                            warn!(supervisor = %self.name, "the second service went during the apply grace, and the program with it");
                            self.events
                                .send(ProcessEvent::Health(unhealthy(
                                    UNREACHABLE.to_string(),
                                    "the second service went, and the program with it".to_string(),
                                )))
                                .await;
                            return GraceOutcome::Unreachable;
                        }
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
    async fn try_reload(
        &self,
        child: &mut Option<ManagedChild>,
        shutdown: &mut Shutdown,
    ) -> Reloaded {
        let Some(signal) = self.reload_signal else {
            return Reloaded::NotApplied;
        };
        let Some(mut proc) = child.take() else {
            return Reloaded::NotApplied;
        };
        if proc.id().is_none() {
            // Already exited; the restart path is about to notice and respawn.
            *child = Some(proc);
            return Reloaded::NotApplied;
        }
        // The second service answers a signal at once, but not while it shuts down: a shutdown
        // requested meanwhile does not wait for that answer.
        let sent = tokio::select! {
            sent = proc.signal(signal, false) => sent,
            _ = shutdown.requested() => {
                *child = Some(proc);
                return Reloaded::ShuttingDown;
            }
        };
        if let Err(e) = sent {
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
                self.spawner.clone(),
                self.name.clone(),
                probe.program.clone(),
                probe.args.clone(),
                probe.parse,
                self.events.clone(),
            ));
        }
    }

    /// Spawns when the plugin says something should run, reporting health either way. A start
    /// that does not reach the second service arms `waiting`; any other outcome clears it.
    async fn spawn_if_due(&self, waiting: &mut Waiting) -> Option<ManagedChild> {
        match self.try_spawn().await {
            Ok(child) => {
                waiting.clear();
                Some(child)
            }
            Err(e) if is_unreachable(&e) => {
                waiting.arm();
                None
            }
            Err(_) => {
                waiting.clear();
                None
            }
        }
    }

    /// Spawns the Managed Process, keeping the reason when it fails.
    ///
    /// Right after a package swap the reason matters: exec of a freshly written binary can fail
    /// with `ETXTBSY`, which is transient and says nothing about the artifact
    /// ([`install::is_text_file_busy`] states why). So the swap retries briefly rather than rolling
    /// back a binary that is perfectly good, and a start it retries reports no failed health: only
    /// the last says the program could not be started.
    async fn try_spawn(&self) -> std::io::Result<ManagedChild> {
        let mut attempt = 0;
        loop {
            match self.spawn_once(attempt < install::BUSY_RETRIES).await {
                Err(e) if install::is_text_file_busy(&e) && attempt < install::BUSY_RETRIES => {
                    attempt += 1;
                    warn!(
                        supervisor = %self.name, attempt,
                        "the new binary is momentarily busy (another spawn holds it); retrying"
                    );
                    tokio::time::sleep(install::BUSY_DELAY).await;
                }
                other => return other,
            }
        }
    }

    /// Starts the Managed Process once. With `retried`, a start that fails as busy is retried by
    /// the caller, and reports no health.
    async fn spawn_once(&self, retried: bool) -> Result<ManagedChild, std::io::Error> {
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
        // like any other — reported in the health, and tried again with the next configuration,
        // package, or restart — rather than the process starting and exiting on a directory nobody
        // made.
        for dir in &spec.ensure_dirs {
            // Written by the Managed Process, so shared with its group where a process account
            // is registered (ADR-0059 clause 6), and reached through no link beneath the
            // Supervisor's directory.
            if let Err(e) = crate::storage::create_shared_dir(
                data_root(&self.supervisor_dir, &spec.ensure_dirs, dir),
                dir,
                self.process_account_group,
                crate::storage::Shared::Written,
            ) {
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
        // Set after every entry of `env`, so no block's `env` can replace it (ADR-0015); a
        // `Zeroizing` copy until the spawn hands it on (ADR-0057).
        let endpoint_token = (!self.endpoint_token.is_empty()).then(|| self.endpoint_token.clone());
        let launch = Launch {
            program,
            args: spec.args.clone(),
            env: spec.env.clone(),
            endpoint_token,
            working_dir: working_dir.map(std::path::Path::to_path_buf),
            own_process_group: spec.own_process_group,
        };
        match self.spawner.spawn(&self.name, launch).await {
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
            Err(e) if retried && install::is_text_file_busy(&e) => Err(e),
            Err(e) => {
                warn!(supervisor = %self.name, program = %spec.program.display(), error = %e, "cannot spawn");
                // What the Server should read is the *situation*, not the syscall. A binary that
                // is not there — a first install that failed and was undone, or a program never
                // installed — is a Supervisor with no process, and saying so is more use to an
                // operator than "spawn failed".
                let status = if is_unreachable(&e) {
                    why_unreached(&e)
                } else if e.kind() == std::io::ErrorKind::NotFound {
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

/// Why a start that did not reach the second service did not: [`REFUSED`] or [`UNREACHABLE`].
fn why_unreached(error: &std::io::Error) -> &'static str {
    if is_refused(error) {
        REFUSED
    } else {
        UNREACHABLE
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
///
/// `spawner` runs it, as it starts the Managed Process: under the process account where one is
/// registered (ADR-0059 clause 3), for the Supervisor named `supervisor`.
pub async fn probe_version(
    spawner: Spawner,
    supervisor: String,
    program: PathBuf,
    args: Vec<String>,
    parse: Option<fn(&str) -> Option<String>>,
    events: EventSender,
) {
    let launch = Launch {
        program: program.clone(),
        args,
        env: Vec::new(),
        endpoint_token: None,
        working_dir: None,
        own_process_group: false,
    };
    let output = match spawner.output(&supervisor, &launch).await {
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
async fn stop(child: &mut Option<ManagedChild>, timeout: Duration, name: &str) {
    let Some(mut c) = child.take() else {
        return;
    };
    #[cfg(unix)]
    if c.id().is_some() {
        let _ = c.signal(libc::SIGTERM, true).await;
        if tokio::time::timeout(timeout, c.wait()).await.is_ok() {
            info!(supervisor = %name, "process stopped");
            return;
        }
        warn!(supervisor = %name, "process ignored SIGTERM; killing it");
        // The group too, so a worker the child spawned does not survive the escalation and go on
        // holding what the Supervisor manages (ADR-0017 clause 56). `Child::kill` below only reaps the one.
        let _ = c.signal(libc::SIGKILL, true).await;
    }
    #[cfg(not(unix))]
    let _ = timeout; // Windows has no SIGTERM equivalent: kill is the stop.
    let _ = c.kill().await;
    info!(supervisor = %name, "process stopped");
}

/// Runs a plugin's preflight against a staged package (ADR-0017 clause 57).
///
/// Bounded like the version probe, because this is the same shape of question asked of a program
/// nobody has run yet. The message on failure is the program's own — a linker error names the
/// library or the symbol version, which is exactly what an operator needs and what an exit status
/// alone destroys.
///
/// Run by `spawner`, as the Managed Process is started: under the process account where one is
/// registered (ADR-0059 clause 3). A preflight that does not reach the second service rejects
/// nothing: [`Preflighted::Unreached`].
#[instrument(name = "preflight", skip_all)]
async fn run_preflight(
    spawner: &Spawner,
    supervisor: &str,
    staged: &Staged,
    preflight: &Preflight,
) -> Preflighted {
    let launch = Launch {
        program: staged.program.clone(),
        args: preflight.args.clone(),
        env: preflight
            .env
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value.replace("${staged}", &staged.root.to_string_lossy()),
                )
            })
            .collect(),
        endpoint_token: None,
        working_dir: None,
        own_process_group: false,
    };
    let output = match spawner.output(supervisor, &launch).await {
        Some(Ok(output)) => output,
        Some(Err(e)) if is_unreachable(&e) => return Preflighted::Unreached(e),
        Some(Err(e)) => {
            return Preflighted::Refused(format!("the packaged program cannot be run: {e}"))
        }
        None => {
            return Preflighted::Refused("the packaged program did not answer in time".to_string())
        }
    };
    if output.status.success() {
        return Preflighted::Passed;
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
    Preflighted::Refused(format!(
        "the packaged program does not run on this host: {reason}"
    ))
}

/// What a preflight came to.
enum Preflighted {
    /// The staged program ran and succeeded, or there was nothing to prove.
    Passed,
    /// It does not run here, and why: the package is refused.
    Refused(String),
    /// The second service was not reached: nothing was proved either way, and the package waits
    /// for the service, as one offered while it is away does (ADR-0059 clause 2).
    Unreached(std::io::Error),
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
    /// The start did not reach the second service, or the program went with it during the grace:
    /// neither applied nor failed, and the start that reaches the service again decides
    /// (ADR-0059 clause 2).
    Unreachable,
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
    group: Option<crate::storage::ProcessAccountGroup>,
) -> Result<PathBuf, String> {
    let staging = root.join(".staging");
    // A previous attempt that died between unpacking and the rename would leave this behind.
    let _ = std::fs::remove_dir_all(&staging);
    let created = match group {
        Some(_) => {
            crate::storage::create_shared_dir(root, &staging, group, crate::storage::Shared::Read)
        }
        None => std::fs::create_dir_all(&staging),
    };
    created.map_err(|e| format!("cannot create {}: {e}", staging.display()))?;

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
    // Every member is read and run by the process account through its group, at the mode the
    // archive gave it (ADR-0059 clauses 6 and 11).
    if let Err(e) = share_staged(&staging, group) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    Ok(staging)
}

/// The directory beneath which no link is followed on the way to `dir`, one of `ensure_dirs` a
/// kind names: the Supervisor's directory where `dir` lies in it, else the outermost of
/// `ensure_dirs` that holds `dir`, which an operator placed — `dir` itself where none does.
fn data_root<'a>(
    supervisor_dir: &'a std::path::Path,
    ensure_dirs: &'a [PathBuf],
    dir: &'a std::path::Path,
) -> &'a std::path::Path {
    std::iter::once(supervisor_dir)
        .chain(ensure_dirs.iter().map(PathBuf::as_path))
        .filter(|root| dir.starts_with(root))
        .min_by_key(|root| root.components().count())
        .unwrap_or(dir)
}

/// Gives what is staged at `staging` — the program, or every member of a tree — to the process
/// account's group `group`, without write for the group or others; nothing where no process
/// account is registered.
fn share_staged(
    staging: &std::path::Path,
    group: Option<crate::storage::ProcessAccountGroup>,
) -> Result<(), String> {
    #[cfg(unix)]
    if let Some(group) = group {
        use crate::storage::handle;
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::OpenOptionsExt as _;
        let shared = if std::fs::symlink_metadata(staging).is_ok_and(|meta| meta.is_dir()) {
            handle::open_beneath(staging, staging, handle::DIRECTORY, None, handle::own())
                .and_then(|tree| handle::share_tree(&tree, group, staging))
        } else {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(staging)
                .map(OwnedFd::from)
                .and_then(|program| {
                    let st = handle::fstat(&program)?;
                    handle::share(&program, group, handle::mode(&st) & !0o022)
                })
        };
        shared.map_err(|e| {
            format!(
                "cannot share {} with the process account: {e}",
                staging.display()
            )
        })?;
    }
    // On Windows the account is granted read and execute on what is staged, through each entry's
    // own handle: a program staged elsewhere and renamed into `program/` keeps the DACL it was
    // made with, and inherits nothing from where it lands.
    #[cfg(windows)]
    if let Some(group) = group {
        use crate::win32::files::{grant_tree, Access, Entry};
        let shared = crate::storage::grant_aces(group.0, crate::storage::Shared::Read);
        let Some([_, on_dir, on_file]) = shared else {
            return Ok(());
        };
        Entry::open(staging, Access::Dacl, true)
            .and_then(|top| {
                let on_top = if top.dir { &on_dir } else { &on_file };
                grant_tree(
                    &top,
                    group.0,
                    [on_top.as_slice(), on_dir.as_slice(), on_file.as_slice()],
                    None,
                    true,
                )
            })
            .map_err(|e| {
                format!(
                    "cannot share {} with the process account: {e}",
                    staging.display()
                )
            })?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (staging, group);
    Ok(())
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

    /// On Windows what is staged is granted to the process account — `LocalService` standing in —
    /// itself: a program staged beside `program/` and renamed into it keeps that grant, where it
    /// would inherit nothing on the way (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_what_is_staged_is_granted_to_the_process_account_itself() {
        use crate::win32::files::{Access, Entry};
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("agent.exe.new");
        std::fs::write(&staged, b"MZ").expect("staged");
        let group = crate::storage::ProcessAccountGroup(crate::win32::LOCAL_SERVICE);
        share_staged(&staged, Some(group)).expect("shared");
        let program = dir.path().join("program");
        std::fs::create_dir(&program).expect("program/");
        std::fs::rename(&staged, program.join("agent.exe")).expect("rename");
        let dacl = Entry::open(&program.join("agent.exe"), Access::Dacl, false)
            .and_then(|entry| entry.dacl())
            .expect("dacl");
        assert!(dacl.holds("(A;;0x1200a9;;;S-1-5-19)"), "{dacl:?}");
    }

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
        let launch = Launch {
            program: program.clone(),
            args: Vec::new(),
            env: Vec::new(),
            endpoint_token: None,
            working_dir: None,
            own_process_group: false,
        };
        let output = Spawner::Local
            .output("test", &launch)
            .await
            .expect("in time")
            .expect("run once the writer let go");
        assert!(output.status.success());
    }

    /// A retry made due at once by a start that reached the second service — a restart command's —
    /// is due without the service being away: a package offered before it runs is swapped in, not
    /// parked for a service that is back (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_retry_due_at_once_does_not_say_the_service_is_away() {
        let mut waiting = Waiting::new();
        waiting.arm();
        assert!(waiting.armed(), "a start that did not reach the service");
        waiting.clear();
        waiting.due_now();
        assert!(!waiting.armed(), "the service was reached");
        tokio::time::timeout(Duration::from_secs(1), waiting.due())
            .await
            .expect("the retry is due at once");
    }

    /// A Supervisor held after a package that failed leaves no configuration waiting: one owed its
    /// acknowledgement — its start waited for the second service, and the package was to be its
    /// start — is `FAILED`, not left `APPLYING` while nothing starts (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hold_after_a_failed_package_fails_the_configuration_it_owes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("agent");
        let target = InstallTarget::Binary(live.clone());
        let artifact = dir.path().join("downloaded");
        std::fs::write(&artifact, "#!/bin/sh\nexit 1\n").expect("a program that exits at once");
        let staged = target.stage(&artifact, None, None).expect("stage");
        let (event_tx, mut events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let (_shutdown_tx, mut shutdown) = crate::shutdown::shutdown_channel();
        let apply_grace = Duration::from_millis(300);
        let runner = package_runner(live, apply_grace, event_tx, command_rx);
        let mut s = Supervision {
            child: None,
            policy: RestartPolicy::new(apply_grace, Instant::now()),
            backoff: Backoff::new(),
            waiting: Waiting::new(),
            owed: Some(OwedConfig {
                hash: b"cfg".to_vec(),
                span: tracing::Span::none(),
            }),
            parked: None,
        };
        // Two failed starts already: the package's is the one the streak holds on.
        for _ in 1..crate::supervisor::restart::MAX_CRASH_RESTARTS {
            assert_eq!(s.policy.failed(), AfterFailure::Retry);
        }
        let package = Parked {
            checked: true,
            staged,
            version: "9.9.9".to_string(),
            hash: b"9.9.9".to_vec(),
            span: tracing::Span::none(),
        };
        assert!(!runner.install(package, &mut s, &mut shutdown).await);
        assert!(s.child.is_none(), "held");
        assert!(s.owed.is_none(), "a configuration left waiting");
        let mut config = None;
        while let Ok((_, event)) = events.try_recv() {
            if let ProcessEvent::ConfigApplied { hash, result } = event {
                config = Some((hash, result));
            }
        }
        let (hash, result) = config.expect("the configuration is decided");
        assert_eq!(hash, b"cfg".to_vec());
        let error = result.expect_err("FAILED");
        assert!(error.contains("held after"), "{error}");
    }

    /// After a package that failed, only a predecessor that ran and exited within the grace is
    /// started again: one that does not start at all — its interpreter is missing — has said why
    /// in its health, and is not tried again, with no configuration owed just as with one
    /// (ADR-0026 clause 63).
    /// Verifies: ADR-0026
    #[cfg(unix)]
    #[tokio::test]
    async fn a_predecessor_that_does_not_start_after_a_failed_package_is_not_started_again() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("agent");
        std::fs::write(&live, "#!/nonexistent/interpreter\n").expect("a predecessor");
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let target = InstallTarget::Binary(live.clone());
        let artifact = dir.path().join("downloaded");
        std::fs::write(&artifact, "#!/bin/sh\nexit 1\n").expect("a program that exits at once");
        let staged = target.stage(&artifact, None, None).expect("stage");
        let (event_tx, mut events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let (_shutdown_tx, mut shutdown) = crate::shutdown::shutdown_channel();
        let apply_grace = Duration::from_millis(300);
        let runner = package_runner(live, apply_grace, event_tx, command_rx);
        let mut s = Supervision {
            child: None,
            policy: RestartPolicy::new(apply_grace, Instant::now()),
            backoff: Backoff::new(),
            waiting: Waiting::new(),
            owed: None,
            parked: None,
        };
        let package = Parked {
            checked: true,
            staged,
            version: "9.9.9".to_string(),
            hash: b"9.9.9".to_vec(),
            span: tracing::Span::none(),
        };
        assert!(!runner.install(package, &mut s, &mut shutdown).await);
        assert!(s.child.is_none(), "nothing runs");
        let mut not_started = 0;
        while let Ok((_, event)) = events.try_recv() {
            if let ProcessEvent::Health(health) = event {
                if health.status == "no process installed" {
                    not_started += 1;
                }
            }
        }
        assert_eq!(
            not_started, 1,
            "the predecessor is started once, after the package"
        );
    }

    /// A shutdown requested while the preflight a package waited for runs ends the install at
    /// once, without waiting out the preflight's bound: the package stays parked, unchecked, and
    /// what ran before stays in place (ADR-0059 clauses 2 and 3).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_shutdown_ends_the_preflight_a_parked_package_waited_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("agent");
        std::fs::write(&live, b"what ran before").expect("a predecessor");
        let target = InstallTarget::Binary(live.clone());
        let artifact = dir.path().join("downloaded");
        std::fs::write(&artifact, "#!/bin/sh\nexec sleep 30\n").expect("a program that hangs");
        let staged = target.stage(&artifact, None, None).expect("stage");
        let (event_tx, _events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let (shutdown_tx, mut shutdown) = crate::shutdown::shutdown_channel();
        let apply_grace = Duration::from_millis(300);
        let mut runner = package_runner(live.clone(), apply_grace, event_tx, command_rx);
        runner.preflight = Some(Preflight {
            args: Vec::new(),
            env: Vec::new(),
        });
        let mut s = Supervision {
            child: None,
            policy: RestartPolicy::new(apply_grace, Instant::now()),
            backoff: Backoff::new(),
            waiting: Waiting::new(),
            owed: None,
            parked: None,
        };
        let package = Parked {
            checked: false,
            staged,
            version: "9.9.9".to_string(),
            hash: b"9.9.9".to_vec(),
            span: tracing::Span::none(),
        };
        let shutting_down = {
            let install = runner.install(package, &mut s, &mut shutdown);
            tokio::pin!(install);
            assert!(
                tokio::time::timeout(Duration::from_millis(300), install.as_mut())
                    .await
                    .is_err(),
                "the preflight runs"
            );
            shutdown_tx.send(true).expect("request the shutdown");
            tokio::time::timeout(Duration::from_secs(1), install)
                .await
                .expect("the shutdown is seen at once")
        };
        assert!(shutting_down);
        let parked = s.parked.expect("the package stays parked");
        assert!(!parked.checked, "the preflight did not finish");
        assert_eq!(
            std::fs::read(&live).expect("live"),
            b"what ran before",
            "what ran before stays in place"
        );
    }

    /// A start that finds the program busy — held open for writing, as a fork racing the write of
    /// a fresh binary holds it — and is retried until it starts reports only that it runs: no
    /// failed health in between for a Server to read as a program that does not start. One that
    /// stays busy past the retries says so, once.
    /// Linux alone refuses to exec a file held open for writing, so the race exists only there.
    /// Verifies: ADR-0026
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_start_retried_while_the_program_is_busy_reports_no_failure_in_between() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("agent");
        std::fs::write(&live, "#!/bin/sh\nexit 0\n").expect("a program");
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let (event_tx, mut events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let runner = package_runner(live.clone(), Duration::ZERO, event_tx, command_rx);
        let statuses = |events: &mut mpsc::Receiver<(usize, ProcessEvent)>| {
            let mut statuses = Vec::new();
            while let Ok((_, event)) = events.try_recv() {
                if let ProcessEvent::Health(health) = event {
                    statuses.push(health.status);
                }
            }
            statuses
        };

        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&live)
            .expect("held open for writing");
        let freed = async {
            tokio::time::sleep(install::BUSY_DELAY * 3).await;
            drop(held);
        };
        let (started, ()) = tokio::join!(runner.try_spawn(), freed);
        let mut child = Some(started.expect("started once the program was free"));
        assert_eq!(statuses(&mut events), vec!["running".to_string()]);
        stop(&mut child, Duration::from_secs(1), "test").await;

        let _held = std::fs::OpenOptions::new()
            .write(true)
            .open(&live)
            .expect("held open for writing");
        let error = runner.try_spawn().await.err().expect("busy throughout");
        assert!(install::is_text_file_busy(&error), "{error}");
        assert_eq!(statuses(&mut events), vec!["spawn failed".to_string()]);
    }

    /// A Runner that installs packages over `live` and runs what is there.
    #[cfg(unix)]
    fn package_runner(
        live: PathBuf,
        apply_grace: Duration,
        event_tx: mpsc::Sender<(usize, ProcessEvent)>,
        command_rx: mpsc::Receiver<ProcessCommand>,
    ) -> Runner {
        let program = live.clone();
        Runner {
            name: "test".to_string(),
            endpoint_token: zeroize::Zeroizing::default(),
            stop_timeout: Duration::from_secs(5),
            apply_grace,
            install: Some(InstallTarget::Binary(live)),
            retain_previous: Duration::ZERO,
            archive_key: None,
            version_probe: None,
            preflight: None,
            reload_signal: None,
            spawner: Spawner::Local,
            process_account_group: None,
            supervisor_dir: std::env::temp_dir(),
            events: EventSender::new(0, event_tx),
            commands: command_rx,
            build: Box::new(move || {
                Some(ProcessSpec {
                    program: program.clone(),
                    args: Vec::new(),
                    env: Vec::new(),
                    working_dir: None,
                    ensure_dirs: Vec::new(),
                    own_process_group: false,
                })
            }),
        }
    }

    /// A program in `dir` that exits at once. A script rather than `/bin/true`, which macOS has
    /// only in `/usr/bin`: `/bin/sh` is where every Unix has it.
    #[cfg(unix)]
    fn exiting_at_once(dir: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let program = dir.join("exits-at-once");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("a program that exits at once");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        program
    }

    /// What the stand-in for the second service is asked to start; it runs nothing.
    #[cfg(unix)]
    fn shell(script: &str) -> Launch {
        Launch {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), script.to_string()],
            env: Vec::new(),
            endpoint_token: None,
            working_dir: None,
            own_process_group: true,
        }
    }

    /// The stop's bound holds for a program the second service runs even when the service does not
    /// answer its signals — as while it stops its programs on shutting down: the stop does not wait
    /// out the service's own grace before its timeout begins.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_is_not_held_up_by_a_signal_the_service_does_not_answer() {
        use crate::supervisor::channel::{peer, SIGNAL_ANSWER};
        let peer = peer::connect(peer::mute).await;
        let child = peer
            .channel
            .start("test", shell("true"))
            .await
            .expect("start");
        let timeout = Duration::from_millis(100);
        let mut child = Some(ManagedChild::Remote(child));
        tokio::time::timeout(
            SIGNAL_ANSWER * 2 + timeout + Duration::from_secs(2),
            stop(&mut child, timeout, "test"),
        )
        .await
        .expect("the stop ends within its bound");
        assert!(child.is_none());
    }

    /// The stop's bound holds too when the service reports no end of the program it was asked to
    /// kill: the stop gives up on the report rather than waiting for it without end.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_is_not_held_up_by_a_kill_the_service_does_not_report() {
        use crate::supervisor::channel::{peer, KILL_ANSWER, SIGNAL_ANSWER};
        let peer = peer::connect(peer::deaf).await;
        let child = peer
            .channel
            .start("test", shell("true"))
            .await
            .expect("start");
        let timeout = Duration::from_millis(100);
        let mut child = Some(ManagedChild::Remote(child));
        tokio::time::timeout(
            SIGNAL_ANSWER * 2 + timeout + KILL_ANSWER + Duration::from_secs(2),
            stop(&mut child, timeout, "test"),
        )
        .await
        .expect("the stop ends within its bound");
        assert!(child.is_none());
    }

    /// A shutdown requested while a reload waits for its signal to be answered ends the reload at
    /// once, without the restart a signal that failed would bring.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_shutdown_ends_a_reload_waiting_on_its_signal() {
        use crate::supervisor::channel::peer;
        let peer = peer::connect(peer::mute).await;
        let child = peer
            .channel
            .start("test", shell("true"))
            .await
            .expect("start");
        let (event_tx, _events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(16);
        let runner = Runner {
            endpoint_token: zeroize::Zeroizing::default(),
            name: "test".to_string(),
            stop_timeout: Duration::from_millis(100),
            apply_grace: Duration::from_secs(60),
            retain_previous: Duration::ZERO,
            install: None,
            archive_key: None,
            version_probe: None,
            preflight: None,
            reload_signal: Some(libc::SIGHUP),
            spawner: Spawner::Channel(peer.channel.clone()),
            process_account_group: None,
            supervisor_dir: std::env::temp_dir(),
            events: EventSender::new(0, event_tx),
            commands: command_rx,
            build: Box::new(|| None),
        };
        let (shutdown_tx, mut shutdown) = crate::shutdown::shutdown_channel();
        let mut child = Some(ManagedChild::Remote(child));
        let reloaded = {
            let reload = runner.try_reload(&mut child, &mut shutdown);
            tokio::pin!(reload);
            assert!(
                tokio::time::timeout(Duration::from_millis(200), reload.as_mut())
                    .await
                    .is_err(),
                "the reload waits for the signal's answer"
            );
            shutdown_tx.send(true).expect("request the shutdown");
            tokio::time::timeout(Duration::from_millis(500), reload)
                .await
                .expect("the shutdown is seen at once")
        };
        assert!(matches!(reloaded, Reloaded::ShuttingDown));
        assert!(child.is_some(), "the process is left for the stop");
    }

    /// A Runner whose every start goes to a second service at `socket`, and runs `/bin/true`.
    #[cfg(unix)]
    fn through_the_second_service(
        socket: &std::path::Path,
    ) -> (Runner, mpsc::Receiver<(usize, ProcessEvent)>) {
        let (runner, events, commands) =
            running_through_the_second_service(socket, PathBuf::from("/bin/true"), Vec::new());
        // Never sent on: an end of the commands would end the Runner.
        std::mem::forget(commands);
        (runner, events)
    }

    /// A Runner whose every start goes to a second service at `socket`, and runs `program`; the
    /// sender of its commands.
    #[cfg(unix)]
    fn running_through_the_second_service(
        socket: &std::path::Path,
        program: PathBuf,
        args: Vec<String>,
    ) -> (
        Runner,
        mpsc::Receiver<(usize, ProcessEvent)>,
        mpsc::Sender<ProcessCommand>,
    ) {
        use crate::supervisor::channel::{peer, Channel};
        let (event_tx, events) = mpsc::channel(256);
        let (commands, command_rx) = mpsc::channel(16);
        let runner = Runner {
            endpoint_token: zeroize::Zeroizing::default(),
            name: "test".to_string(),
            stop_timeout: Duration::from_millis(100),
            apply_grace: Duration::ZERO,
            retain_previous: Duration::ZERO,
            install: None,
            archive_key: None,
            version_probe: None,
            preflight: None,
            reload_signal: None,
            spawner: Spawner::Channel(Channel::new(socket, peer::own_uid(), peer::this_process())),
            process_account_group: None,
            supervisor_dir: std::env::temp_dir(),
            events: EventSender::new(0, event_tx),
            commands: command_rx,
            build: Box::new(move || {
                Some(ProcessSpec {
                    program: program.clone(),
                    args: args.clone(),
                    env: Vec::new(),
                    working_dir: None,
                    ensure_dirs: Vec::new(),
                    own_process_group: false,
                })
            }),
        };
        (runner, events, commands)
    }

    /// The real second service on `socket`, until the sender is used or dropped.
    #[cfg(unix)]
    fn second_service(
        socket: &std::path::Path,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<crate::supervisor::channel::Served>,
    ) {
        use crate::supervisor::channel::{bind, peer, serve};
        let listener = bind(socket).expect("bind");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, peer::own_uid(), || false, async {
            let _ = stopped.await;
        }));
        (stop, task)
    }

    /// The next health the Runner reports, within `within`.
    #[cfg(unix)]
    async fn next_health(
        events: &mut mpsc::Receiver<(usize, ProcessEvent)>,
        within: Duration,
    ) -> ComponentHealth {
        loop {
            let (_, event) = tokio::time::timeout(within, events.recv())
                .await
                .expect("a health report in time")
                .expect("an event");
            if let ProcessEvent::Health(health) = event {
                return health;
            }
        }
    }

    /// The second service stopped — its service manager restarts it, an operator stops it, the
    /// host goes down — and stops the programs it started on the way: none of them exited on its
    /// own, so however often the service goes, no exit is counted and the Supervisor is never
    /// held; it starts the program again once the service is back (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_of_the_second_service_is_no_exit_of_the_programs() {
        use crate::supervisor::restart::MAX_CRASH_RESTARTS;
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let mut service = second_service(&socket);
        let (runner, mut events, _commands) = running_through_the_second_service(
            &socket,
            PathBuf::from("/bin/sleep"),
            vec!["300".to_string()],
        );
        let (shutdown_tx, shutdown) = crate::shutdown::shutdown_channel();
        let run = tokio::spawn(runner.run(shutdown));
        for _ in 0..=MAX_CRASH_RESTARTS {
            let running = next_health(&mut events, Duration::from_secs(30)).await;
            assert_eq!(running.status, "running", "{running:?}");
            let (stop, task) = service;
            let _ = stop.send(());
            assert_eq!(
                task.await.expect("the service ended"),
                crate::supervisor::channel::Served::Stopped
            );
            let gone = next_health(&mut events, Duration::from_secs(30)).await;
            assert_eq!(
                gone.status, UNREACHABLE,
                "counted as the program's own exit"
            );
            service = second_service(&socket);
        }
        let running = next_health(&mut events, Duration::from_secs(30)).await;
        assert_eq!(running.status, "running", "held: {running:?}");
        shutdown_tx.send(true).expect("request the shutdown");
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
        drop(service);
    }

    /// A start that finds the second service unreachable is no failed start: the Supervisor says
    /// so and tries again with backoff, past the streak after which a program that keeps failing
    /// is held (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_start_that_finds_the_second_service_unreachable_is_tried_again_and_never_held() {
        use crate::supervisor::restart::MAX_CRASH_RESTARTS;
        let dir = tempfile::tempdir().expect("tempdir");
        let (runner, mut events) = through_the_second_service(&dir.path().join("agents.sock"));
        let (shutdown_tx, shutdown) = crate::shutdown::shutdown_channel();
        let run = tokio::spawn(runner.run(shutdown));
        let mut unreachable = 0;
        while unreachable <= MAX_CRASH_RESTARTS + 1 {
            let (_, event) = tokio::time::timeout(Duration::from_secs(600), events.recv())
                .await
                .expect("the Supervisor keeps trying")
                .expect("an event");
            if let ProcessEvent::Health(health) = event {
                assert!(
                    !health.status.contains("not restarting"),
                    "held: {health:?}"
                );
                if health.status == UNREACHABLE {
                    unreachable += 1;
                }
            }
        }
        shutdown_tx.send(true).expect("request the shutdown");
        tokio::time::timeout(Duration::from_secs(60), run)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
    }

    /// A program that went with the second service did not exit on its own: the Supervisor says
    /// that the service went, counts no failure, and waits for the service (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_program_that_went_with_the_second_service_is_no_failure_of_its_own() {
        use crate::supervisor::channel::{peer, read_frame, write_frame, Reply, Request};
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        // Starts one program, then goes — and stays away.
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            drop(listener);
            while let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await {
                let reply = match request {
                    Request::Hello { .. } => peer::hello(),
                    Request::Start { id, .. } => {
                        let _ =
                            write_frame(&mut stream, &Reply::Started { id, pid: u32::MAX }).await;
                        return;
                    }
                    _ => continue,
                };
                if write_frame(&mut stream, &reply).await.is_err() {
                    return;
                }
            }
        });
        let (runner, mut events) = through_the_second_service(&socket);
        let (shutdown_tx, shutdown) = crate::shutdown::shutdown_channel();
        let run = tokio::spawn(runner.run(shutdown));
        let mut running = false;
        let gone = loop {
            let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
                .await
                .expect("an event in time")
                .expect("an event");
            let ProcessEvent::Health(health) = event else {
                continue;
            };
            assert!(
                !health.status.starts_with("exited unexpectedly"),
                "counted as the program's own exit: {health:?}"
            );
            if health.status == "running" {
                running = true;
            } else if running {
                break health;
            }
        };
        assert_eq!(gone.status, UNREACHABLE);
        shutdown_tx.send(true).expect("request the shutdown");
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
    }

    /// A socket another account serves is no outage: the Supervisor reports it as a refusal of its
    /// own, so the Server tells a misconfigured host from a stopped service (ADR-0059 clause 4).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_of_another_account_is_reported_refused_not_unreachable() {
        use crate::supervisor::channel::{peer, Channel};
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let (_stop, _service) = second_service(&socket);
        let (mut runner, mut events, _commands) =
            running_through_the_second_service(&socket, PathBuf::from("/bin/true"), Vec::new());
        // The socket is served by this test's uid; the process account is said to be another.
        runner.spawner = Spawner::Channel(Channel::new(
            &socket,
            peer::own_uid().wrapping_add(1),
            peer::this_process(),
        ));
        let (shutdown_tx, shutdown) = crate::shutdown::shutdown_channel();
        let run = tokio::spawn(runner.run(shutdown));
        let health = next_health(&mut events, Duration::from_secs(30)).await;
        assert_eq!(health.status, REFUSED, "{health:?}");
        shutdown_tx.send(true).expect("request the shutdown");
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
    }

    /// A start that waits for the second service to come back is cut short by a shutdown: the
    /// Supervisor does not wait out the reconnect before it stops (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_shutdown_ends_a_start_waiting_for_the_second_service() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (runner, _events) = through_the_second_service(&dir.path().join("agents.sock"));
        let (shutdown_tx, shutdown) = crate::shutdown::shutdown_channel();
        let run = tokio::spawn(runner.run(shutdown));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!run.is_finished(), "the start waits for the service");
        shutdown_tx.send(true).expect("request the shutdown");
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("the shutdown ends the waiting start")
            .expect("cleanly");
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
        let staged = target.stage(&artifact, None, None).expect("stage");
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
        let staged = target.stage(&artifact, None, None).expect("stage");
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

    /// A package taken back out whose predecessor cannot be put back — here it is gone — is put
    /// back itself, a file and a tree alike: `program/` is never left empty (ADR-0026 clause 62).
    /// Verifies: ADR-0026
    #[test]
    fn a_package_taken_back_whose_predecessor_cannot_be_put_back_stays_live() {
        let dir = tempfile::tempdir().expect("tempdir");
        let targets = [
            InstallTarget::Binary(dir.path().join("prog")),
            InstallTarget::Tree {
                root: dir.path().join("tree-root"),
                program_path: PathBuf::from("bin/prog"),
            },
        ];
        for target in targets {
            let live = target.live();
            let temp = live.with_extension("staged");
            if matches!(target, InstallTarget::Tree { .. }) {
                std::fs::create_dir_all(live.join("bin")).expect("mkdir");
                std::fs::write(live.join("bin/prog"), b"the package").expect("write");
            } else {
                std::fs::write(&live, b"the package").expect("write");
            }
            let staged = Staged {
                root: dir.path().to_path_buf(),
                program: temp.clone(),
                temp: temp.clone(),
            };
            let error = target
                .take_back(&staged, true)
                .expect_err("nothing to put back");
            assert!(error.contains("cannot restore"), "{error}");
            let program = match &target {
                InstallTarget::Tree { .. } => live.join("bin/prog"),
                InstallTarget::Binary(_) => live.clone(),
            };
            assert_eq!(
                std::fs::read(&program).expect("live"),
                b"the package",
                "{}",
                live.display()
            );
            assert!(!temp.exists(), "{}", temp.display());
        }
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

    /// The retention marker is the Client's alone, `0600`, whatever the umask: it stands in
    /// `program/`, which the process account's group reads (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_retention_marker_is_the_clients_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = InstallTarget::Binary(dir.path().join("prog"));
        std::fs::write(target.backup(), b"old").expect("write");
        target.retain(5000);
        let mode = std::fs::metadata(target.backup_marker())
            .expect("marker")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A stand-in for the second service that runs nothing: every start is reported to `asked`,
    /// writes `line` to `stream` and exits with the raw wait status `status`.
    #[cfg(unix)]
    async fn answering(
        stream: crate::supervisor::channel::Stream,
        line: &'static str,
        status: i32,
    ) -> (
        crate::supervisor::channel::peer::Peer,
        mpsc::UnboundedReceiver<Launch>,
    ) {
        use crate::supervisor::channel::{peer, Reply, Request};
        let (asked_tx, asked) = mpsc::unbounded_channel();
        let peer = peer::connect(move |request| match request {
            Request::Start { id, launch } => {
                let _ = asked_tx.send(launch);
                vec![
                    Reply::Started { id, pid: 4242 },
                    Reply::Output {
                        id,
                        stream,
                        line: line.to_string(),
                    },
                    Reply::Exited {
                        id,
                        status: Ok(status),
                        closing: false,
                    },
                ]
            }
            _ => Vec::new(),
        })
        .await;
        (peer, asked)
    }

    /// With a process account registered, the version probe is run by the second service, not by
    /// the Client — the program it names is not even on this host — and what the service relays
    /// of its output is what the version is read from (ADR-0059 clause 3).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn the_version_probe_runs_through_the_second_service() {
        use crate::supervisor::channel::Stream;
        let (peer, mut asked) = answering(Stream::Stdout, "agent version 1.2.3", 0).await;
        let (event_tx, mut events) = mpsc::channel(4);
        probe_version(
            Spawner::Channel(peer.channel.clone()),
            "test".to_string(),
            PathBuf::from("/nowhere/agent"),
            vec!["--version".to_string()],
            None,
            EventSender::new(0, event_tx),
        )
        .await;
        let launch = asked
            .try_recv()
            .expect("the probe was asked of the service");
        assert_eq!(launch.program, PathBuf::from("/nowhere/agent"));
        assert_eq!(launch.args, vec!["--version".to_string()]);
        let (_, event) = events.try_recv().expect("a probed version");
        let ProcessEvent::Description(description) = event else {
            panic!("expected a Description event, got {event:?}");
        };
        let version = description.identifying_attributes[0]
            .value
            .clone()
            .and_then(|v| v.value);
        assert_eq!(
            version,
            Some(opamp::proto::any_value::Value::StringValue(
                "1.2.3".to_string()
            ))
        );
    }

    /// With a process account registered, the preflight of a staged package is run by the second
    /// service, with `${staged}` resolved in its environment, and what the program said through the
    /// service is the reason it is refused (ADR-0059 clause 3).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn the_preflight_runs_through_the_second_service() {
        use crate::supervisor::channel::Stream;
        let staged = Staged {
            root: PathBuf::from("/nowhere/program/.staging"),
            program: PathBuf::from("/nowhere/program/.staging/bin/agent"),
            temp: PathBuf::from("/nowhere/program/.staging"),
        };
        let preflight = Preflight {
            args: vec!["--version".to_string()],
            env: vec![("LD_LIBRARY_PATH".to_string(), "${staged}/lib".to_string())],
        };

        let (peer, mut asked) = answering(Stream::Stdout, "agent 2.0.0", 0).await;
        let passed = run_preflight(
            &Spawner::Channel(peer.channel.clone()),
            "test",
            &staged,
            &preflight,
        )
        .await;
        assert!(matches!(passed, Preflighted::Passed));
        let launch = asked
            .try_recv()
            .expect("the preflight was asked of the service");
        assert_eq!(launch.program, staged.program);
        assert_eq!(
            launch.env,
            vec![(
                "LD_LIBRARY_PATH".to_string(),
                "/nowhere/program/.staging/lib".to_string()
            )]
        );

        let (peer, _asked) =
            answering(Stream::Stderr, "version GLIBC_2.39 not found", 1 << 8).await;
        let refused = run_preflight(
            &Spawner::Channel(peer.channel.clone()),
            "test",
            &staged,
            &preflight,
        )
        .await;
        let Preflighted::Refused(reason) = refused else {
            panic!("a program that exited 1 passed the preflight");
        };
        assert!(reason.contains("GLIBC_2.39"), "{reason}");
    }

    /// What the Client asks the second service to start carries no environment of the Client's:
    /// the block's `env` and the Supervisor Endpoint's token, last, and nothing else — the program
    /// takes the rest from the second service (ADR-0059 clause 7).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_start_through_the_second_service_carries_only_the_blocks_env_and_the_token() {
        use crate::supervisor::channel::Stream;
        let (peer, mut asked) = answering(Stream::Stdout, "", 0).await;
        let (event_tx, _events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let mut runner = package_runner(
            PathBuf::from("/nowhere/agent"),
            Duration::ZERO,
            event_tx,
            command_rx,
        );
        runner.endpoint_token = zeroize::Zeroizing::new("the token".to_string());
        runner.spawner = Spawner::Channel(peer.channel.clone());
        runner.build = Box::new(|| {
            Some(ProcessSpec {
                program: PathBuf::from("/nowhere/agent"),
                args: Vec::new(),
                env: vec![("FROM_THE_BLOCK".to_string(), "1".to_string())],
                working_dir: None,
                ensure_dirs: Vec::new(),
                own_process_group: false,
            })
        });
        runner.try_spawn().await.expect("started");
        let launch = asked
            .try_recv()
            .expect("the start was asked of the service");
        assert_eq!(
            launch.env,
            vec![("FROM_THE_BLOCK".to_string(), "1".to_string())]
        );
        assert_eq!(
            launch.endpoint_token.as_deref().map(String::as_str),
            Some("the token")
        );
    }

    /// Where a process account is registered, a tree is staged in a directory its group reads, so
    /// the preflight the second service runs reaches it, and a data directory the agent writes
    /// into is made set-group-ID and group-writable (ADR-0059 clause 6). Without one, the staging
    /// is made as it always was.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn the_staging_and_the_data_directories_are_shared_with_the_process_accounts_group() {
        use std::os::unix::fs::MetadataExt as _;
        let mode = |path: &std::path::Path| {
            let meta = std::fs::metadata(path).expect("metadata");
            (meta.mode() & 0o7777, meta.gid())
        };
        // SAFETY: getegid(2) cannot fail and touches no memory.
        let group = crate::storage::ProcessAccountGroup(unsafe { libc::getegid() });
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("downloaded");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("a bare program");
        let root = dir.path().join("program");
        let target = InstallTarget::Tree {
            root: root.clone(),
            program_path: PathBuf::from("bin/agent"),
        };
        target.prepare(Some(group)).expect("prepare");
        assert_eq!(mode(&root), (0o750, group.0));
        let staged = target.stage(&artifact, None, Some(group)).expect("staged");
        assert_eq!(mode(&staged.root), (0o750, group.0));
        target.discard(&staged);

        let reference = dir.path().join("reference");
        std::fs::create_dir(&reference).expect("a plain directory");
        let staged = target.stage(&artifact, None, None).expect("staged");
        assert_eq!(mode(&staged.root), mode(&reference));

        let data = dir.path().join("data").join("inventory");
        let (event_tx, _events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let program = exiting_at_once(dir.path());
        let mut runner = package_runner(program.clone(), Duration::ZERO, event_tx, command_rx);
        runner.process_account_group = Some(group);
        let made = data.clone();
        runner.build = Box::new(move || {
            Some(ProcessSpec {
                program: program.clone(),
                args: Vec::new(),
                env: Vec::new(),
                working_dir: None,
                ensure_dirs: vec![made.clone()],
                own_process_group: false,
            })
        });
        runner.try_spawn().await.expect("started");
        assert_eq!(mode(&data), (0o2770, group.0));
    }

    /// Where the walk to a data directory begins, beneath which no link is followed: the
    /// Supervisor's directory for one inside it, the outermost of the kind's directories that
    /// holds one outside it, and the directory itself where none does. A `..` does not lift a
    /// directory out of the Supervisor's: the walk from there refuses it (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[test]
    fn a_data_directory_is_walked_to_from_the_outermost_root_that_holds_it() {
        use std::path::Path;
        let supervisor = Path::new("/state/supervisors/agent");
        let inside = supervisor.join("data").join("inventory");
        let outer = PathBuf::from("/var/lib/agent");
        let nested = outer.join("spool");
        let alone = PathBuf::from("/srv/cache");
        let escaping = supervisor.join("..").join("other").join("data");
        let ensure_dirs = vec![
            inside.clone(),
            nested.clone(),
            outer.clone(),
            alone.clone(),
            escaping.clone(),
        ];
        assert_eq!(data_root(supervisor, &ensure_dirs, &inside), supervisor);
        assert_eq!(data_root(supervisor, &ensure_dirs, &nested), outer);
        assert_eq!(data_root(supervisor, &ensure_dirs, &outer), outer);
        assert_eq!(data_root(supervisor, &ensure_dirs, &alone), alone);
        assert_eq!(data_root(supervisor, &ensure_dirs, &escaping), supervisor);

        #[cfg(unix)]
        {
            // SAFETY: getegid(2) cannot fail and touches no memory.
            let group = crate::storage::ProcessAccountGroup(unsafe { libc::getegid() });
            let dir = tempfile::tempdir().expect("tempdir");
            let supervisor = dir.path().join("supervisors").join("agent");
            std::fs::create_dir_all(&supervisor).expect("mkdir");
            let escaping = supervisor.join("..").join("other");
            let refused = crate::storage::create_shared_dir(
                data_root(&supervisor, std::slice::from_ref(&escaping), &escaping),
                &escaping,
                Some(group),
                crate::storage::Shared::Written,
            );
            assert!(refused.is_err());
            assert!(!dir.path().join("supervisors").join("other").exists());
        }
    }

    /// Where a process account is registered, a data directory is reached through no link beneath
    /// the Supervisor's directory: a link where `data` should be, placed by an account that writes
    /// there, fails the start, and nothing is made or shared where it points (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_link_on_the_way_to_a_data_directory_fails_the_start() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: getegid(2) cannot fail and touches no memory.
        let group = crate::storage::ProcessAccountGroup(unsafe { libc::getegid() });
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("supervisors").join("agent");
        std::fs::create_dir_all(&supervisor).expect("mkdir");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("mkdir");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        std::os::unix::fs::symlink(&elsewhere, supervisor.join("data")).expect("a link");

        let (event_tx, _events) = mpsc::channel(64);
        let (_commands, command_rx) = mpsc::channel(1);
        let program = exiting_at_once(dir.path());
        let mut runner = package_runner(program.clone(), Duration::ZERO, event_tx, command_rx);
        runner.supervisor_dir = supervisor.clone();
        runner.process_account_group = Some(group);
        let made = supervisor.join("data").join("inventory");
        runner.build = Box::new(move || {
            Some(ProcessSpec {
                program: program.clone(),
                args: Vec::new(),
                env: Vec::new(),
                working_dir: None,
                ensure_dirs: vec![made.clone()],
                own_process_group: false,
            })
        });
        assert!(runner.try_spawn().await.is_err(), "started through a link");
        assert!(!elsewhere.join("inventory").exists());
        let mode = std::fs::metadata(&elsewhere)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700);
    }

    /// A group of this test's account other than its effective one, as the process account's group
    /// is to the Client: `None` where the account is in no other group.
    #[cfg(unix)]
    fn another_group() -> Option<crate::storage::ProcessAccountGroup> {
        // SAFETY: getegid(2) cannot fail and touches no memory.
        let own = unsafe { libc::getegid() };
        let mut groups = vec![0 as libc::gid_t; 256];
        // SAFETY: the buffer holds as many entries as the length passed.
        let count = unsafe { libc::getgroups(256, groups.as_mut_ptr()) };
        let count = usize::try_from(count).ok()?;
        groups[..count]
            .iter()
            .find(|gid| **gid != own)
            .map(|gid| crate::storage::ProcessAccountGroup(*gid))
    }

    /// Where a process account is registered, every member of an unpacked package is given to its
    /// group at the mode the archive gave it, so a package whose members are `0750`, `0640` or
    /// `0700` runs under the process account as the archive meant it to: what the archive grants
    /// the group, the process account has (ADR-0059 clauses 6 and 11). A single program is given
    /// to the group too.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn every_member_of_a_staged_package_is_given_to_the_process_accounts_group() {
        use std::os::unix::fs::MetadataExt as _;
        let Some(group) = another_group() else {
            crate::skipped_unless_ci(
                "every_member_of_a_staged_package_is_given_to_the_process_accounts_group",
                "supplementary group",
            );
            return;
        };
        let stat = |path: &std::path::Path| {
            let meta = std::fs::symlink_metadata(path).expect("metadata");
            (meta.mode() & 0o7777, meta.gid())
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("package.tar.gz");
        {
            let file = std::fs::File::create(&artifact).expect("create");
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
            let mut builder = tar::Builder::new(encoder);
            for (name, mode, content) in [
                ("app/bin/agent", 0o755, &b"the-program"[..]),
                ("app/bin/helper", 0o750, &b"a-helper"[..]),
                ("app/etc/agent.conf", 0o640, &b"settings"[..]),
                ("app/etc/secret", 0o700, &b"the archive's own"[..]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(mode);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, content)
                    .expect("append");
            }
            builder
                .into_inner()
                .expect("finish tar")
                .finish()
                .expect("finish gzip");
        }
        let target = InstallTarget::Tree {
            root: dir.path().join("program"),
            program_path: PathBuf::from("bin/agent"),
        };
        target.prepare(Some(group)).expect("prepare");
        let staged = target.stage(&artifact, None, Some(group)).expect("staged");
        for (member, mode) in [
            ("bin", 0o755),
            ("bin/agent", 0o755),
            ("bin/helper", 0o750),
            ("etc", 0o755),
            ("etc/agent.conf", 0o640),
            ("etc/secret", 0o700),
        ] {
            let (found, gid) = stat(&staged.root.join(member));
            assert_eq!(gid, group.0, "{member}");
            assert_eq!(found & 0o7777 & !0o022, mode & !0o022, "{member}");
            assert_eq!(found & 0o022, 0, "{member} is writable by group or others");
        }

        let program = dir.path().join("single").join("agent");
        let single = InstallTarget::Binary(program.clone());
        single.prepare(Some(group)).expect("prepare");
        let raw = dir.path().join("downloaded");
        std::fs::write(&raw, "#!/bin/sh\nexit 0\n").expect("a bare program");
        let staged = single.stage(&raw, None, Some(group)).expect("staged");
        assert_eq!(stat(&staged.program), (0o755, group.0));
    }

    /// A preflight that does not reach the second service refuses nothing, however long the wait
    /// for the service takes: that wait is no program failing to answer in time, and the package
    /// waits for the service instead of being refused (ADR-0059 clauses 2 and 3).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_preflight_that_does_not_reach_the_second_service_refuses_nothing() {
        use crate::supervisor::channel::{peer, Channel};
        let dir = tempfile::tempdir().expect("tempdir");
        let channel = Channel::new(
            &dir.path().join("agents.sock"),
            peer::own_uid(),
            peer::this_process(),
        );
        let staged = Staged {
            root: dir.path().to_path_buf(),
            program: dir.path().join("agent.staged"),
            temp: dir.path().join("agent.staged"),
        };
        let preflight = Preflight {
            args: vec!["--version".to_string()],
            env: Vec::new(),
        };
        let outcome = run_preflight(&Spawner::Channel(channel), "test", &staged, &preflight).await;
        let Preflighted::Unreached(e) = outcome else {
            panic!("a preflight that did not reach the service refused or passed the package");
        };
        assert!(is_unreachable(&e), "{e}");
    }
}
