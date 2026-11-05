//! What the Client persists across restarts — its identity, the last received remote
//! configuration, and the installed package — on the filesystem: the adapter behind
//! [`AgentStorage`]. Beside it, [`HighWaterFile`] keeps the high-water marks every Supervisor
//! shares (ADR-0043).
//!
//! The identity file keeps the `instance_uid` stable across restarts, as the Baseline recommends.
//! The remote configuration is stored losslessly as the received protobuf, plus one plain file per
//! config-map entry so an operator (and, later, a Managed Process) can read it off disk.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use opamp::proto::AgentRemoteConfig;
use opamp::uid::InstanceUid;
use prost::Message;
use tracing::warn;

use crate::supervisor::ports::{AgentStorage, InstalledPackage};

/// The file that keeps the `instance_uid`.
pub const UID_FILE: &str = "instance-uid";
const CONFIG_PB_FILE: &str = "remote-config.pb";
/// The directory of the configuration entries, in the Client's state directory and in each
/// Supervisor's.
pub(crate) const CONFIG_DIR: &str = "config";
const PACKAGE_FILE: &str = "installed-package.json";

/// The role each delivered entry carries (ADR-0023) — `<name> <role>` per line, written into the
/// config directory beside the entries themselves.
///
/// It lives in that directory because that is where a plugin looks, and it is written only when
/// there is something to say — a fleet that never sets a role never sees this file. The leading
/// dot is what keeps it from colliding with an entry: a Configuration name follows the ADR-0019
/// grammar (lowercase letters, digits, `-`) and [`entry_file_name`] strips leading dots, so no
/// entry file can ever be named this.
///
/// **The value is here because the Baseline says it matters.** `AgentConfigFile.role` is defined as
/// *"Optional role of the content in the body field. The values and their semantics are Agent
/// type-specific"* — so a kind may define its own vocabulary, and to read it the value has to
/// survive the write. A line without a second field — what an older Client wrote — answers only
/// *whether* an entry carries a role.
pub const SUPPLEMENTARY_FILE: &str = ".supplementary";

pub struct Storage {
    dir: PathBuf,
    /// The process account's group, where a process account is registered (ADR-0059 clause 6): the
    /// directory is passed through by it, and what is stored is kept from it.
    group: Option<ProcessAccountGroup>,
    /// Whether `config/` is read by the Managed Process, and so shared with the process account's
    /// group: a Supervisor's, never the Client's own.
    config_shared: bool,
}

impl Storage {
    /// The storage in `dir`, kept to the Client alone, as where no process account is registered:
    /// created owner-only where it is missing. A link at `dir` is refused: an install writes here
    /// as root, and the directory belongs to the service's account (ADR-0054).
    ///
    /// # Errors
    /// Returns an error when the directory cannot be created, or is a link.
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        Storage::open(dir, None, false)
    }

    /// The Client's state directory as an enrolment opens it, which does not know whether a
    /// process account is registered: one a Client with a process account laid out — `0710`,
    /// passed through by that account's group — is kept so, with the group it has, and anything
    /// else is narrowed to the Client alone as [`Storage::new`] does. A running Client's Managed
    /// Processes keep reaching their directories while `service config` enrols, and the next
    /// start lays the directory out as its registration says either way (ADR-0059 clause 6).
    pub fn enrolling(dir: PathBuf) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if let Ok(meta) = std::fs::symlink_metadata(&dir) {
                if meta.is_dir() && meta.mode() & 0o7777 == 0o710 {
                    return Storage::client(dir, Some(ProcessAccountGroup(meta.gid())));
                }
            }
        }
        Storage::new(dir)
    }

    /// The Client's own storage in the state directory: passed through by the process account's
    /// group on the way to the Supervisors' directories, and nothing in it shared (ADR-0059
    /// clause 6).
    pub fn client(dir: PathBuf, group: Option<ProcessAccountGroup>) -> io::Result<Self> {
        Storage::open(dir, group, false)
    }

    /// A Supervisor's storage in its own directory: passed through by the process account's
    /// group, with `config/` read by its Managed Process and the rest kept from it (ADR-0059
    /// clause 6).
    pub fn supervised(dir: PathBuf, group: Option<ProcessAccountGroup>) -> io::Result<Self> {
        Storage::open(dir, group, true)
    }

    fn open(
        dir: PathBuf,
        group: Option<ProcessAccountGroup>,
        config_shared: bool,
    ) -> io::Result<Self> {
        create_shared_dir(&dir, &dir, group, Shared::Traversed)?;
        let storage = Storage {
            dir,
            group,
            config_shared,
        };
        storage.share_config()?;
        Ok(storage)
    }

    /// Shares what `config/` already holds with the process account's group — files written
    /// before a process account was registered, or placed there by the operator — so the Managed
    /// Process reads them before the next configuration is written. Nothing where `config/` is not
    /// shared, or does not exist yet.
    fn share_config(&self) -> io::Result<()> {
        let Some(group) = self.config_group() else {
            return Ok(());
        };
        let config_dir = self.config_dir();
        if !config_dir.is_dir() {
            return Ok(());
        }
        create_shared_dir(&self.dir, &config_dir, Some(group), Shared::Read)?;
        #[cfg(unix)]
        for entry in std::fs::read_dir(&config_dir)? {
            let entry = entry?;
            // Never through a link, and never a directory: only what the Client writes there.
            if entry.file_type()?.is_file() {
                share_file(&entry.path(), group)?;
            }
        }
        Ok(())
    }

    /// The process account's group `config/` is shared with, if it is.
    fn config_group(&self) -> Option<ProcessAccountGroup> {
        self.group.filter(|_| self.config_shared)
    }

    /// Writes one of the Client's own records, never through a link (ADR-0054). In a directory the
    /// process account's group passes through it is kept from that group, `0600`; elsewhere it is
    /// `0644`.
    fn write_record(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        if self.group.is_some() {
            write_private(path, contents)
        } else {
            crate::nofollow::write(path, contents, 0o644)
        }
    }

    /// Where [`store_remote_config`](Self::store_remote_config) writes the plain entry files —
    /// what a Managed Process is pointed at (ADR-0017).
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.dir.join(CONFIG_DIR)
    }

    /// Takes a stored remote configuration out of force for a Supervisor whose remote
    /// configuration is switched off (ADR-0017 clause 52): each entry file, and `.supplementary`,
    /// whose bytes are still the ones the stored map would write is deleted, every other file in
    /// `config/` stays, and `remote-config.pb` goes. A `.pb` that does not decode is deleted and
    /// `config/` is left alone. `None` when nothing was stored.
    ///
    /// # Errors
    /// Returns an error when a file that has to go cannot be read or deleted.
    pub fn drop_remote_config(&self) -> io::Result<Option<DroppedRemoteConfig>> {
        let pb = self.dir.join(CONFIG_PB_FILE);
        let bytes = match std::fs::read(&pb) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let Ok(config) = AgentRemoteConfig::decode(bytes.as_slice()) else {
            std::fs::remove_file(&pb)?;
            return Ok(Some(DroppedRemoteConfig::Undecodable));
        };
        let config_dir = self.config_dir();
        let mut kept = Vec::new();
        for (file_name, body) in written_files(&config) {
            let path = config_dir.join(&file_name);
            match std::fs::read(&path) {
                Ok(on_disk) if on_disk == body => std::fs::remove_file(&path)?,
                Ok(_) => kept.push(file_name),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        std::fs::remove_file(&pb)?;
        Ok(Some(DroppedRemoteConfig::Removed {
            hash: config.config_hash,
            kept,
        }))
    }
}

impl Storage {
    /// Takes the Client's own stored Supervisor set out of the way on a host that keeps its set
    /// (ADR-0017 clause 44): `remote-config.pb` goes **first**, so nothing that fails after it can
    /// leave a hash to report, and then each entry copy in `config/` whose bytes are still the
    /// stored ones goes as far as it can. Nothing runs on the copies, so one that cannot be read
    /// or deleted is named in the result, not an error. A `.pb` that does not decode is deleted
    /// and `config/` is left alone. `None` when nothing was stored.
    ///
    /// # Errors
    /// Returns an error only when `remote-config.pb` itself cannot be read or deleted.
    pub fn drop_stored_set(&self) -> io::Result<Option<DroppedStoredSet>> {
        let pb = self.dir.join(CONFIG_PB_FILE);
        let bytes = match std::fs::read(&pb) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        std::fs::remove_file(&pb)?;
        let Ok(config) = AgentRemoteConfig::decode(bytes.as_slice()) else {
            return Ok(Some(DroppedStoredSet::Undecodable));
        };
        let config_dir = self.config_dir();
        let (mut kept, mut unremoved) = (Vec::new(), Vec::new());
        for (file_name, body) in written_files(&config) {
            let path = config_dir.join(&file_name);
            match std::fs::read(&path) {
                Ok(on_disk) if on_disk == body => {
                    if let Err(e) = std::fs::remove_file(&path) {
                        unremoved.push((file_name, e.to_string()));
                    }
                }
                Ok(_) => kept.push(file_name),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => unremoved.push((file_name, e.to_string())),
            }
        }
        Ok(Some(DroppedStoredSet::Removed {
            hash: config.config_hash,
            kept,
            unremoved,
        }))
    }
}

/// What [`Storage::drop_stored_set`] found and did (ADR-0017 clause 44).
#[derive(Debug, PartialEq, Eq)]
pub enum DroppedStoredSet {
    /// `remote-config.pb` is gone, and so is every entry copy still as stored; `kept` names the
    /// copies whose content had changed, `unremoved` those that could not be read or deleted, each
    /// with the error.
    Removed {
        hash: Vec<u8>,
        kept: Vec<String>,
        unremoved: Vec<(String, String)>,
    },
    /// The stored `remote-config.pb` did not decode and is gone; `config/` was left as it was.
    Undecodable,
}

/// What [`Storage::drop_remote_config`] found and did (ADR-0017 clause 52).
#[derive(Debug, PartialEq, Eq)]
pub enum DroppedRemoteConfig {
    /// The stored configuration and the files it wrote are gone; `kept` names the files
    /// left in place because their content had changed since.
    Removed { hash: Vec<u8>, kept: Vec<String> },
    /// The stored `remote-config.pb` did not decode and is gone; `config/` was left as it was.
    Undecodable,
}

/// The files [`Storage::store_remote_config`] writes into `config/` for `config`, by file name:
/// each entry, then [`SUPPLEMENTARY_FILE`] when any entry carries a role.
fn written_files(config: &AgentRemoteConfig) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut supplementary: Vec<String> = Vec::new();
    if let Some(map) = &config.config {
        for (name, file) in &map.config_map {
            let file_name = entry_file_name(name);
            if !file.role.is_empty() {
                supplementary.push(format!("{file_name} {}", file.role));
            }
            files.push((file_name, file.body.clone()));
        }
    }
    if !supplementary.is_empty() {
        supplementary.sort();
        files.push((
            SUPPLEMENTARY_FILE.to_string(),
            (supplementary.join("\n") + "\n").into_bytes(),
        ));
    }
    files
}

impl AgentStorage for Storage {
    /// The persisted identity, or a fresh UUID v7 persisted on first start.
    fn load_or_create_uid(&self) -> io::Result<InstanceUid> {
        let path = self.dir.join(UID_FILE);
        if let Ok(bytes) = crate::nofollow::read(&path) {
            if let Some(uid) = InstanceUid::parse(&String::from_utf8_lossy(&bytes)) {
                return Ok(uid);
            }
            warn!(file = %path.display(), "unreadable identity; generating a fresh one");
        }
        let uid = InstanceUid::default();
        self.save_uid(&uid)?;
        Ok(uid)
    }

    /// Persists a Server-assigned identity (AgentIdentification) so the reassignment survives a
    /// restart.
    fn save_uid(&self, uid: &InstanceUid) -> io::Result<()> {
        self.write_record(&self.dir.join(UID_FILE), format!("{uid}\n").as_bytes())
    }

    /// The last stored remote configuration, if any survived a previous run.
    fn load_remote_config(&self) -> Option<AgentRemoteConfig> {
        let bytes = std::fs::read(self.dir.join(CONFIG_PB_FILE)).ok()?;
        match AgentRemoteConfig::decode(bytes.as_slice()) {
            Ok(config) => Some(config),
            Err(e) => {
                warn!(error = %e, "stored remote configuration is unreadable; ignoring it");
                None
            }
        }
    }

    /// Stores a received remote configuration: the protobuf for lossless restart, and each
    /// config-map entry as a plain file under `config/`. Entry files from a previous offer are
    /// removed first — the composed entry set changes over time (ADR-0023), and a stale file
    /// would otherwise still be handed to the Managed Process.
    ///
    /// Every entry is written, whatever its role. An entry that carries one (ADR-0023) is content
    /// the process reads *by path* rather than being configured with, so it lands in the same
    /// directory under the same name — that is what makes a `${file:...}` reference resolve — and
    /// its name is recorded in [`SUPPLEMENTARY_FILE`] for the plugin to leave out of what it
    /// starts the process with.
    fn store_remote_config(&self, config: &AgentRemoteConfig) -> io::Result<()> {
        // Refused before the previous offer's files go: a refusal leaves them as they were.
        check_entry_names(config).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // The protobuf and the entry files can carry secret material (a roled `${file:...}` entry
        // that is a certificate or key), so both the config directory and the files are owner-only.
        // Where a process account is registered, a Supervisor's `config/` is what its Managed
        // Process reads: shared with the process account's group to read, never to write (ADR-0059
        // clause 6).
        let config_dir = self.dir.join(CONFIG_DIR);
        create_shared_dir(&self.dir, &config_dir, self.config_group(), Shared::Read)?;
        for entry in std::fs::read_dir(&config_dir)? {
            let path = entry?.path();
            if path.is_file() {
                std::fs::remove_file(path)?;
            }
        }
        for (file_name, body) in written_files(config) {
            write_shared(&config_dir.join(file_name), &body, self.config_group())?;
        }
        // Last: a store cut short leaves the previous `.pb`, never a new one beside the previous
        // offer's files, which `drop_remote_config` would keep as the operator's (ADR-0017
        // clause 32).
        write_private(&self.dir.join(CONFIG_PB_FILE), &config.encode_to_vec())
    }

    /// The installed package (ADR-0026), if one survived a previous run.
    fn load_package(&self) -> Option<InstalledPackage> {
        let bytes = crate::nofollow::read(&self.dir.join(PACKAGE_FILE)).ok()?;
        match serde_json::from_slice(&bytes) {
            Ok(package) => Some(package),
            Err(e) => {
                warn!(error = %e, "stored package record is unreadable; ignoring it");
                None
            }
        }
    }

    /// Records the installed package, so a restarted Client reports what it runs.
    fn store_package(&self, package: &InstalledPackage) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(package).expect("an InstalledPackage serializes");
        self.write_record(&self.dir.join(PACKAGE_FILE), &json)
    }

    /// Drops the record: this Agent does not have that package. No record to drop is the state
    /// asked for, not an error.
    fn forget_package(&self) -> io::Result<()> {
        match std::fs::remove_file(self.dir.join(PACKAGE_FILE)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// The entry files a Managed Process should be **configured with**, in deterministic (sorted)
/// order — the Collector's own merge semantics are order-dependent.
///
/// Everything written by [`Storage::store_remote_config`] except the entries that carry a role
/// (ADR-0023) and the bookkeeping that names them. Those files are deliberately still *there*:
/// supplementary content is read by path, so leaving it out of this list is the whole of what the
/// role changes.
///
/// A free function over the directory rather than a method, because a plugin is handed the
/// directory and not the [`Storage`] that filled it. An unreadable directory is no configuration
/// rather than an error — the caller's process simply has nothing to run on yet.
#[must_use]
pub fn config_entries(config_dir: &std::path::Path) -> Vec<PathBuf> {
    let supplementary = entry_roles(config_dir);
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    warn!(dir = %config_dir.display(), error = %e, "unreadable config entry");
                    return None;
                }
            };
            if !entry.file_type().is_ok_and(|t| t.is_file()) {
                return None;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // No entry file can begin with a dot (`entry_file_name` strips them), so anything
            // that does is this module's own bookkeeping and never configuration.
            if name.starts_with('.') || supplementary.contains_key(&name) {
                return None;
            }
            Some(entry.path())
        })
        .collect();
    files.sort();
    files
}

/// What role each delivered entry carries, by entry file name (ADR-0023).
///
/// A line an older Client wrote carries no role, only a name; it reads back as an empty value —
/// "this entry carries *a* role", which is all that version ever recorded and all that the
/// pass-it-or-not decision needs. A kind that defines its own vocabulary asks for the value and
/// finds it as soon as the next configuration lands.
#[must_use]
pub fn entry_roles(config_dir: &std::path::Path) -> BTreeMap<String, String> {
    let Ok(text) = std::fs::read_to_string(config_dir.join(SUPPLEMENTARY_FILE)) else {
        return BTreeMap::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| match line.split_once(char::is_whitespace) {
            Some((name, role)) => (name.to_string(), role.trim().to_string()),
            None => (line.to_string(), String::new()),
        })
        .collect()
}

/// Create `dir` (and its parents) and, on Unix, narrow it to `0700`.
///
/// The state directory holds the Agent's identity and the Server-pushed configuration, and a
/// config-map entry read by path (`${file:...}`) can be a certificate or a key (ADR-0023). At the
/// umask default the directory is world-listable, so on a multi-user host another local user could
/// read that material; owner-only closes it. Where no process account is registered the Managed
/// Process runs as this same user, so it still reads its own config; where one is, what it reads
/// is shared with its group instead ([`create_shared_dir`]). On Windows the `%ProgramData%` ACL is what protects it (ADR-0019).
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub use crate::supervisor::ports::ProcessAccountGroup;

/// How a directory the Client creates is shared with the process account's group (ADR-0059
/// clause 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shared {
    /// Passed through on the way to what is shared, never listed: `0710`. The state directory, the
    /// Supervisors' root and each Supervisor's directory.
    Traversed,
    /// Read, never written: `0750`. `program/`, the preflight's staging, `config/`.
    Read,
    /// Written by the Managed Processes: `2770`, so what they create there keeps the group and
    /// the Client can remove it. A kind's data directories.
    Written,
}

impl Shared {
    #[cfg(unix)]
    fn mode(self) -> u32 {
        match self {
            Shared::Traversed => 0o710,
            Shared::Read => 0o750,
            Shared::Written => 0o2770,
        }
    }
}

/// Create `dir` (and its parents) shared with `group` as `shared` says: owned by the group, at the
/// mode of ADR-0059 clause 6. Where no process account is registered it is made as before: a
/// kind's data directory ([`Shared::Written`]) by [`create_private_dir`], one of the Client's own
/// directories owner-only and never through a link at its name (ADR-0054).
///
/// `dir` is `root` or beneath it, and `root` is a directory of the Client's that the process
/// account writes neither in nor above: the state directory, the Supervisors' root, a
/// Supervisor's directory. Every component beneath `root` is opened through the handle of the one
/// before it and none through a link, whoever owns it, so a link the process account placed in a
/// directory it writes cannot turn the Client's change on something else of its own (ADR-0059
/// clause 6); on the way to `root` only the links of root's and of the Client's own account are
/// followed, in a directory nobody else may write ([`handle::open_beneath`]). The group and the
/// mode are changed through the directory's own handle. A parent this creates is passed through,
/// `0710`, so the directory is reached; each parent that must be more is named by its own call.
///
/// A data directory (`Written`) that was not yet shared — one a Managed Process wrote while it ran
/// as the Client, before a process account was registered — gives what the Client owns in it to
/// the group too, writable by it, so the Managed Process goes on writing its own state: every
/// directory and every regular file with one name, never through a link.
pub(crate) fn create_shared_dir(
    root: &Path,
    dir: &Path,
    group: Option<ProcessAccountGroup>,
    shared: Shared,
) -> io::Result<()> {
    let Some(group) = group else {
        return match shared {
            Shared::Written => create_private_dir(dir),
            Shared::Traversed | Shared::Read => {
                crate::nofollow::HeldDir::create(dir, 0o700).map(drop)
            }
        };
    };
    #[cfg(unix)]
    {
        let traversed =
            |made: &std::os::fd::OwnedFd| handle::share(made, group, Shared::Traversed.mode());
        let made = handle::open_beneath(
            root,
            dir,
            handle::DIRECTORY,
            Some(&traversed),
            handle::own(),
        )
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
        let before = handle::fstat(&made)?;
        handle::share(&made, group, shared.mode())?;
        if shared == Shared::Written
            && (before.st_gid != group.0 || handle::mode(&before) != shared.mode())
        {
            handle::give_written(&made, group, dir);
        }
    }
    #[cfg(windows)]
    {
        std::fs::create_dir_all(root)?;
        grant(root, dir, group, shared)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
    }
    Ok(())
}

/// The ACEs that grant the process account `sid` what `shared` says, on Windows (ADR-0059
/// clause 6): for the directory itself, for a directory and for a file already in it. `None` for
/// `Traversed`: the process account passes through a directory of the Client's by the
/// `SeChangeNotifyPrivilege` the second service keeps (ADR-0059 clause 2), and is granted nothing
/// there, so it lists nothing and reads nothing of the Client's own.
///
/// `Read` is read and execute, inherited by everything in the directory. `Written` is modify on
/// what is in the directory, inherited, and on the directory itself everything of modify but
/// `DELETE`: as on Unix, where the process account writes in its data directory and cannot remove
/// it, the Client's. Writing its attributes lets the process account make an empty data directory
/// a mount point; every path of the Client's refuses a link or a junction, so that stops the
/// Managed Processes' own directory and nothing of the Client's.
#[cfg(any(windows, test))]
pub(crate) fn grant_aces(sid: &str, shared: Shared) -> Option<[Vec<String>; 3]> {
    use crate::win32::acl::{allow, DELETE, MODIFY, READ_EXECUTE};
    match shared {
        Shared::Traversed => None,
        Shared::Read => Some([
            vec![allow(sid, READ_EXECUTE, "OICI")],
            vec![allow(sid, READ_EXECUTE, "OICI")],
            vec![allow(sid, READ_EXECUTE, "")],
        ]),
        Shared::Written => Some([
            vec![
                allow(sid, MODIFY & !DELETE, ""),
                allow(sid, MODIFY, "OICIIO"),
            ],
            vec![allow(sid, MODIFY, "OICI")],
            vec![allow(sid, MODIFY, "")],
        ]),
    }
}

/// Creates `dir` beneath `root` where it is missing and grants the process account `group` — its
/// SID, on Windows — what `shared` says of it (ADR-0059 clause 6). Every component from `root` to
/// `dir` is opened as itself and held while the next is opened, none a link
/// ([`crate::win32::files::open_beneath`]), and the DACL is set on the handle of `dir`. What is
/// already in it is granted the same where `dir` was not granted it yet — a directory a Managed
/// Process wrote before a process account was registered — walked without entering a link and
/// past what the process account owns, which is its own already.
#[cfg(windows)]
fn grant(root: &Path, dir: &Path, group: ProcessAccountGroup, shared: Shared) -> io::Result<()> {
    use crate::win32::files::{grant_tree, open_beneath, Access};
    let aces = grant_aces(group.0, shared);
    let access = if aces.is_some() {
        Access::Dacl
    } else {
        Access::Pass
    };
    let (_held, made) = open_beneath(root, dir, access, true)?;
    let Some([on_top, on_dir, on_file]) = aces else {
        return Ok(());
    };
    let process = crate::win32::Sid::parse(group.0).map_err(io::Error::other)?;
    let passed = grant_tree(
        &made,
        group.0,
        [on_top.as_slice(), on_dir.as_slice(), on_file.as_slice()],
        Some(&process),
        false,
    )?;
    for passed in passed {
        use crate::win32::files::Passed;
        match passed {
            Passed::Owned(_) => {}
            Passed::HardLinked(path) => warn!(
                file = %path.display(),
                "the file has a second hard link and is not shared with the process account"
            ),
            Passed::Unreadable(path) | Passed::Held(path) => warn!(
                entry = %path.display(),
                "the entry cannot be opened and is not shared with the process account"
            ),
        }
    }
    Ok(())
}

/// Directories reached through handles, never through a link: what the Client changes where the
/// process account may write (ADR-0059 clauses 5, 6 and 10).
#[cfg(unix)]
pub(crate) mod handle {
    use std::ffi::{CStr, CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Component, Path, PathBuf};

    use tracing::warn;

    use super::ProcessAccountGroup;

    /// A directory, opened as one and never through a link.
    pub(crate) const DIRECTORY: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    /// A directory passed through on the way to another, never through a link, opened with no
    /// right to read it, only to search it. Every walk opens each directory it passes this way:
    /// [`open_beneath`] each component before the last, and [`step_trusting`] each on the way to
    /// a root, from `/` on. So the Client passes through what it may only search, and the second
    /// service, as the process account, through a Supervisor's directory (`0710`, ADR-0059
    /// clause 6) to what it purges. On Linux a path-only handle.
    #[cfg(target_os = "linux")]
    pub(crate) const SEARCH: libc::c_int =
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// On macOS `O_SEARCH` (`O_EXEC | O_DIRECTORY`), which XNU authorizes as a search of the
    /// directory and not as a read (`vn_authorize_open_existing`). macOS has it from macOS 13 on,
    /// the oldest macOS a Client runs on (ADR-0059 clause 9); an older kernel would open for
    /// reading (`FFLAGS`), and a walk through a directory it may only search would fail there
    /// rather than reach further.
    #[cfg(target_os = "macos")]
    pub(crate) const SEARCH: libc::c_int = libc::O_SEARCH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// Elsewhere a directory read, as [`DIRECTORY`].
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) const SEARCH: libc::c_int = DIRECTORY;

    /// A regular file, opened to change its owner and mode: never through a link, and never
    /// blocking on a FIFO or taking a terminal.
    const FILE: libc::c_int =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;

    /// `name` in `dir`, opened with `flags`; the last component never follows a link where
    /// `flags` says `O_NOFOLLOW`.
    pub(crate) fn open(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
        // SAFETY: a descriptor or `AT_FDCWD` and a NUL-terminated name; no `O_CREAT`, so no mode.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// What `handle` holds, as the kernel sees it.
    pub(crate) fn fstat(handle: &OwnedFd) -> io::Result<libc::stat> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid descriptor and room for one `stat`.
        if unsafe { libc::fstat(handle.as_raw_fd(), st.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fstat` succeeded and filled it.
        Ok(unsafe { st.assume_init() })
    }

    /// The entry `name` in `dir` itself, a link as a link.
    pub(crate) fn lstat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid descriptor, a NUL-terminated name and room for one `stat`.
        let rc = unsafe {
            libc::fstatat(
                dir,
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fstatat` succeeded and filled it.
        Ok(unsafe { st.assume_init() })
    }

    /// Whether `st` is of the file type `kind` (`S_IFDIR`, `S_IFREG`, `S_IFLNK`).
    pub(crate) fn is(st: &libc::stat, kind: libc::mode_t) -> bool {
        st.st_mode & libc::S_IFMT == kind
    }

    /// The permission bits of `st`, set-ID and sticky bits included.
    pub(crate) fn mode(st: &libc::stat) -> u32 {
        // `mode_t` is `u32` on Linux and `u16` on macOS.
        #[allow(clippy::useless_conversion)]
        let mode = u32::from(st.st_mode);
        mode & 0o7777
    }

    /// This process's effective account: the Client's, where the Client walks its own tree
    /// ([`open_beneath`]).
    pub(crate) fn own() -> libc::uid_t {
        // SAFETY: geteuid(2) cannot fail and touches no memory.
        unsafe { libc::geteuid() }
    }

    /// What [`open_dir`] hands each directory it creates: the creator's own change to it.
    pub(crate) type Made<'a> = Option<&'a dyn Fn(&OwnedFd) -> io::Result<()>>;

    /// Opens the directory `dir`, which is `root` or beneath it, one component at a time, each
    /// through the handle of the one before it: every component searched ([`SEARCH`]), the last
    /// opened with `flags`. `root` is where the Client's own tree begins — the state directory, the
    /// Supervisors' root, a Supervisor's directory — and what the operator configured. On the way
    /// to it a link is followed only where it is trusted ([`trusted_link`]): root or `trusted`,
    /// the Client's account, owns it and the directory it is in, which nobody else may write, so
    /// no other account can have placed or changed it; its target is read once, through the same
    /// handle, and walked to the same way. `trusted` is the Client's account wherever this runs:
    /// the Client passes its own ([`own`]), and the second service the account it serves, never
    /// the process account it runs as, whose links are no more the Client's than any other.
    /// Beneath `root` no link is followed, whoever owns it, since an account that writes a
    /// directory there can place one, and root's own links among them where it can link a file
    /// of root's into it. With `made`, a missing component is created, `0700`, and handed to
    /// `made`, opened to read.
    ///
    /// # Errors
    /// Returns an error when `dir` is not beneath `root` by plain names, or a component is
    /// missing (without `made`), is no directory, is a link on the way to `root` that is not
    /// trusted, or is a link beneath `root`.
    pub(crate) fn open_beneath(
        root: &Path,
        dir: &Path,
        flags: libc::c_int,
        made: Made<'_>,
        trusted: libc::uid_t,
    ) -> io::Result<OwnedFd> {
        let not_beneath = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not beneath {} by plain names",
                    dir.display(),
                    root.display()
                ),
            )
        };
        let beneath = dir
            .strip_prefix(root)
            .map_err(|_| not_beneath())?
            .components()
            .map(|component| match component {
                Component::Normal(name) => CString::new(name.as_bytes()).map_err(io::Error::from),
                _ => Err(not_beneath()),
            })
            .collect::<io::Result<Vec<_>>>()?;
        let start = if root.is_absolute() { c"/" } else { c"." };
        let prefix = root
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                Component::ParentDir => Some(OsStr::new("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .map(|name| CString::new(name.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let total = prefix.len() + beneath.len();
        let flags_at = |at: usize| if at + 1 == total { flags } else { SEARCH };
        let mut handle = open(
            libc::AT_FDCWD,
            start,
            (if total == 0 { flags } else { SEARCH }) & !libc::O_NOFOLLOW,
        )?;
        let mut hops = 0;
        for (at, name) in prefix.iter().enumerate() {
            handle = step_trusting(&handle, name, flags_at(at), made, trusted, &mut hops)?;
        }
        for (at, name) in beneath.iter().enumerate() {
            handle = step(&handle, name, flags_at(prefix.len() + at), made).map_err(|e| {
                if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                    refused(&handle, name, root, e)
                } else {
                    e
                }
            })?;
        }
        Ok(handle)
    }

    /// The links [`step_trusting`] follows in one walk, at most: as many as the kernel follows
    /// in one path (`MAXSYMLINKS` on Linux).
    const MAX_HOPS: u32 = 40;

    /// The directory `name` in `dir`, opened with `flags` as [`step`] opens it, on the way to a
    /// root: a link there is followed where it is trusted ([`trusted_link`]) for the account
    /// `trusted`, its target read once and walked to component by component from `dir`, or from
    /// `/` where it is absolute, by the same rule.
    fn step_trusting(
        dir: &OwnedFd,
        name: &CStr,
        flags: libc::c_int,
        made: Made<'_>,
        trusted: libc::uid_t,
        hops: &mut u32,
    ) -> io::Result<OwnedFd> {
        let st = match lstat_at(dir.as_raw_fd(), name) {
            Ok(st) => st,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                return step(dir, name, flags, made)
            }
            Err(e) => return Err(e),
        };
        if !is(&st, libc::S_IFLNK) {
            // Opened without following: a link swapped in since is refused.
            return step(dir, name, flags, made);
        }
        if !trusted_link(&fstat(dir)?, &st, trusted) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is a link that is not trusted — root or the Client's account must own \
                     it and the directory it is in, which no other account may write — and is \
                     not followed",
                    name.to_string_lossy()
                ),
            ));
        }
        *hops += 1;
        if *hops > MAX_HOPS {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        let target = read_link_at(dir.as_raw_fd(), name)?;
        let mut at = if target.is_absolute() {
            open(libc::AT_FDCWD, c"/", SEARCH & !libc::O_NOFOLLOW)?
        } else {
            dir.try_clone()?
        };
        let names = target
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                Component::ParentDir => Some(OsStr::new("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .map(|name| CString::new(name.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let Some((last, on_the_way)) = names.split_last() else {
            return open(at.as_raw_fd(), c".", flags & !libc::O_NOFOLLOW);
        };
        for name in on_the_way {
            at = step_trusting(&at, name, SEARCH, None, trusted, hops)?;
        }
        step_trusting(&at, last, flags, None, trusted, hops)
    }

    /// Whether the link `link` in the directory `dir` is trusted on the way to a root: root or
    /// `own`, the Client's account, owns each of them, and the directory is not writable by its
    /// group or others, so no other account can have placed or changed it. The system's own —
    /// `/var/run` → `/run`, or `/var` → `private/var` on macOS — and the Client's own, as a link
    /// beneath a data root the hand-over gave the Client, or `~/.local` → `/data` for `--user`: a
    /// link that account placed it could have placed as the root itself.
    pub(crate) fn trusted_link(dir: &libc::stat, link: &libc::stat, own: libc::uid_t) -> bool {
        let trusted = |uid: libc::uid_t| uid == 0 || uid == own;
        trusted(link.st_uid) && trusted(dir.st_uid) && mode(dir) & 0o022 == 0
    }

    /// The target of the link `name` in `dir`, read once.
    fn read_link_at(dir: RawFd, name: &CStr) -> io::Result<PathBuf> {
        use std::os::unix::ffi::OsStringExt as _;
        let mut buf = vec![0_u8; 4096];
        // SAFETY: a valid descriptor, a NUL-terminated name, and a buffer of the length passed.
        let read =
            unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        let Ok(read) = usize::try_from(read) else {
            return Err(io::Error::last_os_error());
        };
        if read == buf.len() {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        buf.truncate(read);
        Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
    }

    /// Why `name` in `dir` was not opened as a directory beneath `root`: a link, which is never
    /// followed there, or something that is no directory.
    fn refused(dir: &OwnedFd, name: &CStr, root: &Path, error: io::Error) -> io::Error {
        let what = match lstat_at(dir.as_raw_fd(), name) {
            Ok(st) if is(&st, libc::S_IFLNK) => {
                format!(
                    "is a link, and no link beneath {} is followed",
                    root.display()
                )
            }
            Ok(_) => "is not a directory".to_string(),
            Err(_) => return error,
        };
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} {what}", name.to_string_lossy()),
        )
    }

    /// The directory `name` in `dir`, opened with `flags`, as [`open_beneath`] takes each
    /// component; with `made`, created first where it is missing.
    fn step(dir: &OwnedFd, name: &CStr, flags: libc::c_int, made: Made<'_>) -> io::Result<OwnedFd> {
        let error = match open(dir.as_raw_fd(), name, flags) {
            Ok(next) => return Ok(next),
            Err(e) => e,
        };
        let Some(made) = made.filter(|_| error.raw_os_error() == Some(libc::ENOENT)) else {
            return Err(error);
        };
        // SAFETY: a valid descriptor and a NUL-terminated name.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            // Opened as `flags` says of links: one swapped in since is refused here too.
            let read = (DIRECTORY & !libc::O_NOFOLLOW) | (flags & libc::O_NOFOLLOW);
            made(&open(dir.as_raw_fd(), name, read)?)?;
        } else if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(io::Error::last_os_error());
        }
        open(dir.as_raw_fd(), name, flags)
    }

    /// Removes the entry `name` in `dir` with everything beneath it, never through a link: a link
    /// is removed as a link. A directory this process owns is made its own to read and write
    /// first, as one an agent made read-only — a Go module cache — needs to be emptied.
    ///
    /// # Errors
    /// Returns the first entry that cannot be removed.
    pub(crate) fn remove_tree_at(dir: &OwnedFd, name: &CStr, path: &Path) -> io::Result<()> {
        let named = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
        let st = lstat_at(dir.as_raw_fd(), name).map_err(named)?;
        if !is(&st, libc::S_IFDIR) {
            // SAFETY: a valid descriptor and a NUL-terminated name.
            if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(named(io::Error::last_os_error()));
            }
            return Ok(());
        }
        // SAFETY: geteuid(2) cannot fail and touches no memory.
        if st.st_uid == unsafe { libc::geteuid() } && mode(&st) & 0o700 != 0o700 {
            // By name, as the directory may not be readable yet: an entry this account owns, in a
            // directory it writes, which only this account could have swapped.
            // SAFETY: a valid descriptor and a NUL-terminated name.
            if unsafe { libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), 0o700, 0) } != 0 {
                return Err(named(io::Error::last_os_error()));
            }
        }
        let inner = open(dir.as_raw_fd(), name, DIRECTORY).map_err(named)?;
        for child in entries(&inner).map_err(named)? {
            // A child gone already was removed by another walk of the same tree (a purge beside
            // the start's), which is what this one wants too; the rest of the tree is still due.
            match remove_tree_at(
                &inner,
                &child,
                &path.join(OsStr::from_bytes(child.as_bytes())),
            ) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                other => other?,
            }
        }
        drop(inner);
        // SAFETY: a valid descriptor and a NUL-terminated name.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(named(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Gives what `handle` holds to `group` at `mode`: the group first, since a change of group
    /// may clear the set-group-ID bit the mode sets.
    pub(crate) fn share(handle: &OwnedFd, group: ProcessAccountGroup, mode: u32) -> io::Result<()> {
        // SAFETY: a valid descriptor; `uid_t::MAX` (-1) leaves the owner as it is.
        if unsafe { libc::fchown(handle.as_raw_fd(), libc::uid_t::MAX, group.0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // The mode is at most `0o7777`, which every `mode_t` holds.
        #[allow(clippy::cast_possible_truncation)]
        let mode = mode as libc::mode_t;
        // SAFETY: a valid descriptor.
        if unsafe { libc::fchmod(handle.as_raw_fd(), mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The names in `dir`, read from the handle, without `.` and `..`.
    pub(crate) fn entries(dir: &OwnedFd) -> io::Result<Vec<CString>> {
        // `fdopendir` takes the descriptor it is given; it gets a duplicate, and `dir` stays ours.
        let raw = dir.try_clone()?.into_raw_fd();
        // SAFETY: `raw` is an open directory descriptor this function owns.
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed, so `raw` is still ours to close.
            unsafe { libc::close(raw) };
            return Err(error);
        }
        // `fdopendir` reads from the descriptor's offset, which a duplicate shares: from the top.
        // SAFETY: `stream` is the open stream from `fdopendir`.
        unsafe { libc::rewinddir(stream) };
        let mut names = Vec::new();
        let result = loop {
            // SAFETY: errno is thread-local; clearing it tells the end of the stream from a
            // failure, which `readdir` both report as null.
            unsafe { *errno() = 0 };
            // SAFETY: `stream` is the open stream from `fdopendir`.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                break match error.raw_os_error() {
                    Some(0) | None => Ok(()),
                    Some(_) => Err(error),
                };
            }
            // SAFETY: `entry` is valid until the next `readdir` on this stream, and `d_name` is
            // NUL-terminated; the name is copied out at once.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        };
        // SAFETY: `stream` is open and closed once; this closes `raw` with it.
        unsafe { libc::closedir(stream) };
        result.map(|()| names)
    }

    #[cfg(target_os = "linux")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno location.
        unsafe { libc::__errno_location() }
    }

    #[cfg(target_os = "macos")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno location.
        unsafe { libc::__error() }
    }

    /// Gives every directory and regular file under `dir` to `group`, each at the mode it has
    /// without the group's and others' write bits: what an unpacked package holds, read and run
    /// by the process account through its group (ADR-0059 clauses 6 and 11). A link, which no
    /// unpacked tree holds, and a file with a second hard link are left as they are.
    ///
    /// # Errors
    /// Returns the first entry that cannot be read or changed: a package whose members the
    /// process account cannot reach would not run.
    pub(crate) fn share_tree(
        dir: &OwnedFd,
        group: ProcessAccountGroup,
        path: &Path,
    ) -> io::Result<()> {
        for name in entries(dir)? {
            let child = path.join(OsStr::from_bytes(name.as_bytes()));
            let named =
                |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", child.display()));
            let st = lstat_at(dir.as_raw_fd(), &name).map_err(named)?;
            let flags = if is(&st, libc::S_IFDIR) {
                DIRECTORY
            } else if is(&st, libc::S_IFREG) && st.st_nlink == 1 {
                FILE
            } else {
                continue;
            };
            let entry = open(dir.as_raw_fd(), &name, flags).map_err(named)?;
            let st = fstat(&entry).map_err(named)?;
            if is(&st, libc::S_IFDIR) {
                share(&entry, group, mode(&st) & !0o022).map_err(named)?;
                share_tree(&entry, group, &child)?;
            } else if is(&st, libc::S_IFREG) && st.st_nlink == 1 {
                share(&entry, group, mode(&st) & !0o022).map_err(named)?;
            }
        }
        Ok(())
    }

    /// The directories beneath `dir` that this account — the Client — owns and lets its group
    /// write, its data directories: the outermost of each branch, by their paths relative to
    /// `dir`. Where alone the process account can have written beneath `dir` (ADR-0059 clause 6).
    /// Walked through handles from `dir`, its own root ([`open_beneath`]), through the Client's
    /// own directories alone and never through a link; one it cannot read is passed over.
    ///
    /// # Errors
    /// Returns an error when `dir` itself cannot be opened.
    pub(crate) fn shared_for_writing(dir: &Path) -> io::Result<Vec<PathBuf>> {
        fn walk(dir: &OwnedFd, at: &Path, me: libc::uid_t, found: &mut Vec<PathBuf>) {
            let Ok(names) = entries(dir) else {
                return;
            };
            for name in names {
                let Ok(st) = lstat_at(dir.as_raw_fd(), &name) else {
                    continue;
                };
                if !is(&st, libc::S_IFDIR) || st.st_uid != me {
                    continue;
                }
                let path = at.join(OsStr::from_bytes(name.as_bytes()));
                if mode(&st) & 0o020 != 0 {
                    found.push(path);
                } else if let Ok(inner) = open(dir.as_raw_fd(), &name, DIRECTORY) {
                    walk(&inner, &path, me, found);
                }
            }
        }
        let top = open_beneath(dir, dir, DIRECTORY, None, own())?;
        let mut found = Vec::new();
        walk(&top, Path::new(""), own(), &mut found);
        found.sort();
        Ok(found)
    }

    /// Gives what the Client owns under the data directory `dir` to `group`, writable by it: each
    /// directory `2770` at least, each regular file with one name group-readable and -writable.
    /// What the Client does not own, a link, and a file with a second hard link are left as they
    /// are. Best-effort: an entry that cannot be changed is named in a warning, and the rest goes
    /// on. `path` names `dir` in those warnings.
    pub(crate) fn give_written(dir: &OwnedFd, group: ProcessAccountGroup, path: &Path) {
        // SAFETY: geteuid(2) cannot fail and touches no memory.
        let me = unsafe { libc::geteuid() };
        let names = match entries(dir) {
            Ok(names) => names,
            Err(e) => {
                warn!(dir = %path.display(), error = %e, "cannot read a data directory to share what it holds");
                return;
            }
        };
        for name in names {
            let child = path.join(OsStr::from_bytes(name.as_bytes()));
            if let Err(e) = give_entry(dir, &name, group, me, &child) {
                warn!(path = %child.display(), error = %e, "cannot share an entry of a data directory with the process account's group");
            }
        }
    }

    fn give_entry(
        dir: &OwnedFd,
        name: &CStr,
        group: ProcessAccountGroup,
        me: libc::uid_t,
        path: &Path,
    ) -> io::Result<()> {
        let st = lstat_at(dir.as_raw_fd(), name)?;
        if st.st_uid != me {
            return Ok(());
        }
        let flags = if is(&st, libc::S_IFDIR) {
            DIRECTORY
        } else if is(&st, libc::S_IFREG) && st.st_nlink == 1 {
            FILE
        } else {
            return Ok(());
        };
        let entry = open(dir.as_raw_fd(), name, flags)?;
        // Read again from the handle: the name may have been swapped since.
        let st = fstat(&entry)?;
        let mode = mode(&st);
        if st.st_uid != me {
            return Ok(());
        }
        if is(&st, libc::S_IFDIR) {
            share(&entry, group, mode | 0o2770)?;
            give_written(&entry, group, path);
        } else if is(&st, libc::S_IFREG) && st.st_nlink == 1 {
            share(&entry, group, mode | 0o060)?;
        }
        Ok(())
    }
}

/// Makes the regular file at `path` readable by `group` and no wider: `0640`, owned by the group.
///
/// A file with a second hard link is left as it is and named in a warning, as the hand-over leaves
/// one (ADR-0059 clause 10): its other name may be one of the Client's own records — a link to
/// `client-key.pem` placed while the Managed Process still ran as the Client — and sharing it would
/// share that record too.
#[cfg(unix)]
fn share_file(path: &Path, group: ProcessAccountGroup) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(());
    }
    if meta.nlink() > 1 {
        warn!(
            file = %path.display(),
            "the file has a second hard link and is not shared with the process account's group"
        );
        return Ok(());
    }
    std::os::unix::fs::fchown(&file, None, Some(group.0))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o640))
}

/// Write `contents` to `path` readable by `group`: `0640`, owned by the group (ADR-0059 clause 6).
/// Written owner-only as [`write_private`] writes it, never through a link, and only then given to
/// the group. Where no process account is registered it is [`write_private`].
pub(crate) fn write_shared(
    path: &Path,
    contents: &[u8],
    group: Option<ProcessAccountGroup>,
) -> io::Result<()> {
    write_private(path, contents)?;
    #[cfg(unix)]
    if let Some(group) = group {
        share_file(path, group)?;
    }
    #[cfg(not(unix))]
    let _ = group;
    Ok(())
}

/// Write `contents` to `path`, owner-only on Unix — for the files that can carry secret material
/// (the stored configuration protobuf, each config-map entry, the private key). Defence in depth
/// beside the `0700` directory: the file is created at that mode, so the bytes are never briefly
/// world-readable, and it replaces a file of any mode whole. Written through a temporary name and a
/// rename in the directory, never through a link at `path` or at its directory's name: an install
/// writes the state directory as root, and the directory belongs to the service's account
/// (ADR-0054).
pub(crate) fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    crate::nofollow::write(path, contents, 0o600)
}

/// Refuses a configuration whose entries cannot each be stored as a file of their own on every
/// host: a configuration means the same wherever it lands, so what Windows cannot hold is refused
/// on Linux and macOS too.
///
/// An entry file name may not be a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
/// `LPT1`–`LPT9`, in any case and with any extension) nor end in a dot, which Windows strips. Two
/// entries may not map to one file name, compared without case, as a case-insensitive file system
/// compares them: which of them was written would depend on the map's iteration order.
///
/// # Errors
/// Returns a sentence naming the entry, or the two entries, refused.
pub fn check_entry_names(config: &AgentRemoteConfig) -> Result<(), String> {
    let Some(map) = &config.config else {
        return Ok(());
    };
    let mut names: Vec<&String> = map.config_map.keys().collect();
    names.sort();
    let mut seen: BTreeMap<String, &String> = BTreeMap::new();
    for name in names {
        let file_name = entry_file_name(name);
        let folded = file_name.to_ascii_lowercase();
        let stem = folded.split('.').next().unwrap_or_default();
        if crate::config::WINDOWS_RESERVED.contains(&stem) {
            return Err(format!(
                "entry {name:?} would be stored as {file_name:?}, a reserved device name on Windows"
            ));
        }
        if file_name.ends_with('.') {
            return Err(format!(
                "entry {name:?} would be stored as {file_name:?}, a name ending in a dot, which \
                 Windows cannot hold"
            ));
        }
        if let Some(other) = seen.insert(folded, name) {
            return Err(format!(
                "entries {other:?} and {name:?} would be stored in one file, {file_name:?}"
            ));
        }
    }
    Ok(())
}

/// Config-map keys are arbitrary peer input; a file name derived from one must never escape the
/// config directory or hide itself.
fn entry_file_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // An empty key, or one of nothing but dots, leaves no name at all — and joined onto the config
    // directory that is the directory itself.
    match sanitized.trim_start_matches('.') {
        "" => "config".to_string(),
        name => name.to_string(),
    }
}

/// The file under `state_dir` that holds the high-water marks (ADR-0043 clause 8). It sits outside
/// `supervisor_dir`, and its name holds a `.`, which no Supervisor name can: no purge of a
/// Supervisor's directory deletes it, even where `supervisor_dir` is `state_dir` itself.
pub const HIGH_WATER_FILE: &str = "package-high-water.json";

/// The high-water marks on the filesystem (ADR-0043 clause 8): `<state_dir>/package-high-water.json`,
/// a JSON object mapping an Agent type to the highest version this Client installed for it,
/// written owner-only through a temporary file and a rename.
///
/// Read once, when the Client starts. A file that exists but does not parse, or that maps a type to
/// a value that is not SemVer, is never read as empty: every mark then answers the reason, which
/// refuses every Supervisor package until the operator repairs or deletes the file (clause 11).
pub struct HighWaterFile {
    path: PathBuf,
    marks: std::sync::Mutex<Result<BTreeMap<String, String>, String>>,
}

impl HighWaterFile {
    /// Reads the marks under `state_dir`. No file is no mark; an unreadable one is logged as an
    /// error naming it.
    #[must_use]
    pub fn open(state_dir: &Path) -> Self {
        let path = state_dir.join(HIGH_WATER_FILE);
        let marks = match std::fs::read(&path) {
            Ok(bytes) => parse_marks(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e.to_string()),
        }
        .map_err(|why| {
            let reason = format!(
                "the high-water file {} cannot be read ({why}) — every Supervisor package is \
                 refused until it is repaired or deleted",
                path.display()
            );
            tracing::error!("{reason}");
            reason
        });
        HighWaterFile {
            path,
            marks: std::sync::Mutex::new(marks),
        }
    }

    fn write(&self, marks: &BTreeMap<String, String>) -> io::Result<()> {
        let mut json = serde_json::to_vec_pretty(marks).expect("a map of strings serializes");
        json.push(b'\n');
        write_private(&self.path, &json)
    }
}

/// The marks a file holds, or why they cannot be read: it must be a JSON object of strings, each
/// a SemVer version.
fn parse_marks(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let marks: BTreeMap<String, String> =
        serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if let Some((agent_type, version)) = marks
        .iter()
        .find(|(_, version)| !fleet_core::version::is_semver(version))
    {
        return Err(format!(
            "the mark of {agent_type:?} is {version:?}, which is not SemVer"
        ));
    }
    Ok(marks)
}

impl crate::supervisor::ports::HighWaterMarks for HighWaterFile {
    fn mark(&self, agent_type: &str) -> Result<Option<String>, String> {
        match &*self.marks.lock().expect("marks lock") {
            Ok(marks) => Ok(marks.get(agent_type).cloned()),
            Err(reason) => Err(reason.clone()),
        }
    }

    fn raise(&self, agent_type: &str, version: &str) {
        if !fleet_core::version::is_semver(version) {
            return;
        }
        let mut guard = self.marks.lock().expect("marks lock");
        // An unreadable file stays as the operator finds it: it is theirs to repair.
        let Ok(marks) = &mut *guard else {
            return;
        };
        let higher = marks.get(agent_type).is_none_or(|mark| {
            fleet_core::version::precedence(version, mark) == Some(std::cmp::Ordering::Greater)
        });
        if !higher {
            return;
        }
        marks.insert(agent_type.to_string(), version.to_string());
        if let Err(e) = self.write(marks) {
            warn!(
                file = %self.path.display(), agent_type, version, error = %e,
                "cannot write the high-water mark; it is kept in memory, and the next start seeds \
                 it again from the installed-package records"
            );
        }
    }
}

#[cfg(test)]
mod windows_grants {
    use super::{grant_aces, Shared};

    /// On Windows a shared directory is reached through no junction: one on the way from the root
    /// is refused, and a data directory is granted to the process account — `LocalService`
    /// standing in — modify for what it holds and everything of it but `DELETE` on itself.
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_a_share_is_made_through_no_junction() {
        use super::{create_shared_dir, ProcessAccountGroup};
        use crate::win32::files::{Access, Entry};
        let group = ProcessAccountGroup(crate::win32::LOCAL_SERVICE);
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("supervisor");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        let linked = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(root.join("link"))
            .arg(&outside)
            .status()
            .expect("run mklink");
        assert!(linked.success(), "cannot make the junction");
        assert!(create_shared_dir(
            &root,
            &root.join("link").join("data"),
            Some(group),
            Shared::Written
        )
        .is_err());
        assert!(!outside.join("data").exists(), "nothing made through it");

        let data = root.join("data");
        create_shared_dir(&root, &data, Some(group), Shared::Written).expect("data");
        let dacl = Entry::open(&data, Access::Dacl, false)
            .and_then(|entry| entry.dacl())
            .expect("dacl");
        assert!(dacl.holds("(A;;0x1201bf;;;S-1-5-19)"), "{dacl:?}");
        assert!(dacl.holds("(A;OICIIO;0x1301bf;;;S-1-5-19)"), "{dacl:?}");
    }

    /// On Windows the split of ADR-0059 clause 6 is made by ACL grants to the process account's
    /// SID: `program/`, the preflight's staging and `config/` read and executed, a kind's data
    /// directory modified beneath it but not removed itself, each inherited by what is in them,
    /// and the directories passed through granted nothing.
    /// Verifies: ADR-0059
    #[test]
    fn the_process_account_is_granted_what_it_reads_and_writes_and_nothing_else() {
        let sid = "S-1-5-80-1-2-3-4-5";
        assert_eq!(
            grant_aces(sid, Shared::Read),
            Some([
                vec![format!("(A;OICI;0x1200a9;;;{sid})")],
                vec![format!("(A;OICI;0x1200a9;;;{sid})")],
                vec![format!("(A;;0x1200a9;;;{sid})")],
            ])
        );
        let [top, dir, file] = grant_aces(sid, Shared::Written).expect("granted");
        assert_eq!(
            top,
            [
                format!("(A;;0x1201bf;;;{sid})"),
                format!("(A;OICIIO;0x1301bf;;;{sid})")
            ],
            "everything of modify on the directory itself but DELETE"
        );
        assert_eq!(dir, [format!("(A;OICI;0x1301bf;;;{sid})")]);
        assert_eq!(file, [format!("(A;;0x1301bf;;;{sid})")]);
        assert_eq!(grant_aces(sid, Shared::Traversed), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opamp::proto::{AgentConfigMap, AgentConfigObject};
    use std::collections::HashMap;

    #[test]
    fn identity_is_stable_across_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let first = storage.load_or_create_uid().expect("uid");
        let second = storage.load_or_create_uid().expect("uid");
        assert_eq!(first, second);
    }

    #[test]
    fn a_forgotten_package_is_gone_and_forgetting_nothing_is_no_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");

        // Nothing recorded yet: the state asked for is the state there is.
        storage.forget_package().expect("forget nothing");

        storage
            .store_package(&InstalledPackage {
                name: "opamp-fleet-client".to_string(),
                version: "1.2.3".to_string(),
                hash_hex: "aabb".to_string(),
            })
            .expect("store");
        assert!(storage.load_package().is_some());

        storage.forget_package().expect("forget");
        assert!(storage.load_package().is_none());
        assert!(!dir.path().join(PACKAGE_FILE).exists());
    }

    /// The state directory holds the identity and the Server-pushed configuration — which can carry
    /// secret material by path (ADR-0023) — so the directories are owner-only and the secret-bearing
    /// files are `0600`, whatever the process umask.
    #[cfg(unix)]
    #[test]
    fn the_state_and_configuration_are_kept_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("state");
        let storage = Storage::new(root.clone()).expect("storage");
        let mode = |p: &std::path::Path| {
            std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
        };
        assert_eq!(mode(&root), 0o700, "the state directory is owner-only");

        storage
            .store_remote_config(&roled_offer(&[("certs", b"PEM-SECRET\n", "supplementary")]))
            .expect("store");
        let config_dir = storage.config_dir();
        assert_eq!(
            mode(&config_dir),
            0o700,
            "the config directory is owner-only"
        );
        assert_eq!(
            mode(&root.join(CONFIG_PB_FILE)),
            0o600,
            "the stored configuration protobuf is owner-only"
        );
        assert_eq!(
            mode(&config_dir.join("certs")),
            0o600,
            "a config entry — which may be a certificate or key — is owner-only"
        );
    }

    /// The group this test may share with: its own primary group, of which it is a member as the
    /// Client is of the process account's.
    #[cfg(unix)]
    fn own_group() -> ProcessAccountGroup {
        // SAFETY: getegid(2) cannot fail and touches no memory.
        ProcessAccountGroup(unsafe { libc::getegid() })
    }

    #[cfg(unix)]
    fn mode_and_group(path: &Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path).expect("metadata");
        (meta.mode() & 0o7777, meta.gid())
    }

    /// Where a process account is registered, the Client shares with the process account's group
    /// what the Managed Process reads and nothing else: the state directory and a Supervisor's
    /// directory are passed through, `0710`; a Supervisor's `config/` and its entries are read,
    /// `0750` and `0640`; a data directory is written, `2770`. The Client's own `config/`, the
    /// stored protobuf, the identity and the package record stay the Client's, `0700` and `0600`.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn with_a_process_account_its_group_reads_only_what_it_runs_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let state = dir.path().join("state");
        let client = Storage::client(state.clone(), Some(group)).expect("the Client's storage");
        client
            .store_remote_config(&roled_offer(&[("set", b"[[supervisor]]\n", "")]))
            .expect("store the Client's own");
        client
            .save_uid(&InstanceUid::default())
            .expect("the Client's identity");
        assert_eq!(mode_and_group(&state), (0o710, group.0));
        assert_eq!(mode_and_group(&client.config_dir()).0, 0o700);
        assert_eq!(mode_and_group(&client.config_dir().join("set")).0, 0o600);
        assert_eq!(mode_and_group(&state.join(UID_FILE)).0, 0o600);

        let supervisor = state.join("supervisors").join("agent");
        let storage =
            Storage::supervised(supervisor.clone(), Some(group)).expect("a Supervisor's storage");
        storage
            .store_remote_config(&roled_offer(&[("certs", b"PEM\n", "supplementary")]))
            .expect("store");
        storage
            .save_uid(&InstanceUid::default())
            .expect("the Supervisor's identity");
        storage
            .store_package(&InstalledPackage {
                name: "agent".to_string(),
                version: "1.0.0".to_string(),
                hash_hex: "01".to_string(),
            })
            .expect("the package record");
        assert_eq!(mode_and_group(&supervisor), (0o710, group.0));
        assert_eq!(mode_and_group(&storage.config_dir()), (0o750, group.0));
        assert_eq!(
            mode_and_group(&storage.config_dir().join("certs")),
            (0o640, group.0)
        );
        assert_eq!(
            mode_and_group(&storage.config_dir().join(SUPPLEMENTARY_FILE)),
            (0o640, group.0)
        );
        assert_eq!(mode_and_group(&supervisor.join(CONFIG_PB_FILE)).0, 0o600);
        assert_eq!(mode_and_group(&supervisor.join(UID_FILE)).0, 0o600);
        assert_eq!(mode_and_group(&supervisor.join(PACKAGE_FILE)).0, 0o600);

        let data = supervisor.join("data");
        create_shared_dir(&supervisor, &data, Some(group), Shared::Written)
            .expect("a data directory");
        assert_eq!(mode_and_group(&data), (0o2770, group.0));
    }

    /// What `config/` held before a process account was registered is shared when the
    /// Supervisor's storage opens, so its Managed Process reads it before the next configuration
    /// arrives; a link there is left alone.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn what_config_held_before_is_shared_when_the_storage_opens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("agent");
        let before = Storage::new(supervisor.clone()).expect("without a process account");
        before
            .store_remote_config(&roled_offer(&[("fleet", b"service: {}\n", "")]))
            .expect("store");
        std::os::unix::fs::symlink("/etc/hostname", before.config_dir().join("link"))
            .expect("a link the operator placed");
        assert_eq!(mode_and_group(&before.config_dir().join("fleet")).0, 0o600);

        let group = own_group();
        let after = Storage::supervised(supervisor, Some(group)).expect("with one");
        assert_eq!(mode_and_group(&after.config_dir()), (0o750, group.0));
        assert_eq!(
            mode_and_group(&after.config_dir().join("fleet")),
            (0o640, group.0)
        );
    }

    /// A link in a directory the process account writes is never followed on the way to a
    /// directory the Client shares: the link is refused, and what it names is neither created nor
    /// changed (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_link_on_the_way_to_a_shared_directory_is_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).expect("mkdir");
        write_private(&outside.join("record"), b"the Client's").expect("write");
        create_private_dir(&outside).expect("owner-only");
        let before = mode_and_group(&outside);

        let supervisor = dir.path().join("agent");
        create_shared_dir(&supervisor, &supervisor, Some(group), Shared::Traversed)
            .expect("the Supervisor's");
        // The Managed Process put a link where its data directory's parent goes.
        std::os::unix::fs::symlink(&outside, supervisor.join("data")).expect("a link");
        let error = create_shared_dir(
            &supervisor,
            &supervisor.join("data").join("certs"),
            Some(group),
            Shared::Written,
        )
        .expect_err("through a link");
        assert!(error.to_string().contains("link"), "{error}");
        assert!(
            !outside.join("certs").exists(),
            "nothing made behind the link"
        );
        assert_eq!(mode_and_group(&outside), before);

        // The last component too: shared through its own handle, never through a link.
        std::fs::remove_file(supervisor.join("data")).expect("unlink");
        std::fs::create_dir(supervisor.join("data")).expect("mkdir");
        std::os::unix::fs::symlink(&outside, supervisor.join("data").join("certs"))
            .expect("a link");
        create_shared_dir(
            &supervisor,
            &supervisor.join("data").join("certs"),
            Some(group),
            Shared::Written,
        )
        .expect_err("a link as the directory itself");
        assert_eq!(mode_and_group(&outside), before);
        assert_eq!(mode_and_group(&outside.join("record")).0, 0o600);
    }

    /// Beneath the Supervisor's directory no link is followed, whoever owns it: a link of root's
    /// in a data directory — one a hard link to a link of root's elsewhere can place — that names a
    /// link of the process account's to the Client's records shares nothing of them. Run as root,
    /// every link here is root's; run as anyone else, the account's own. A link of the Client's
    /// own account on the way to the Supervisor's directory, in a directory only that account
    /// writes, is followed, and a directory that is not beneath it by plain names is refused
    /// (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn no_link_beneath_the_root_is_followed_whoever_owns_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let supervisor = dir.path().join("agent");
        let private = supervisor.join("private");
        create_private_dir(&private).expect("the Client's own");
        write_private(&private.join("client-key.pem"), b"KEY").expect("the key");
        let data = supervisor.join("data");
        create_shared_dir(&supervisor, &data, Some(group), Shared::Written).expect("data");
        std::os::unix::fs::symlink("../private", data.join("evil")).expect("the process's link");
        std::os::unix::fs::symlink("evil", data.join("certs")).expect("a link of another owner");
        let before = (
            mode_and_group(&private),
            mode_and_group(&private.join("client-key.pem")),
        );

        let error = create_shared_dir(
            &supervisor,
            &data.join("certs"),
            Some(group),
            Shared::Written,
        )
        .expect_err("a link beneath the root");
        assert!(error.to_string().contains("no link beneath"), "{error}");
        create_shared_dir(
            &supervisor,
            &data.join("certs").join("ca"),
            Some(group),
            Shared::Written,
        )
        .expect_err("a link on the way beneath the root");
        assert_eq!(
            (
                mode_and_group(&private),
                mode_and_group(&private.join("client-key.pem")),
            ),
            before,
            "nothing of the Client's is shared"
        );

        let through = dir.path().join("through");
        std::os::unix::fs::symlink(&supervisor, &through).expect("a link above the root");
        create_shared_dir(
            &through,
            &through.join("cache"),
            Some(group),
            Shared::Written,
        )
        .expect("the Client's own link above the root is followed");
        assert_eq!(mode_and_group(&supervisor.join("cache")), (0o2770, group.0));

        let error = create_shared_dir(
            &data,
            &data.join("..").join("private"),
            Some(group),
            Shared::Written,
        )
        .expect_err("not beneath by plain names");
        assert!(error.to_string().contains("not beneath"), "{error}");
        create_shared_dir(&data, &private, Some(group), Shared::Written)
            .expect_err("not beneath at all");
        assert_eq!(mode_and_group(&private), before.0);
    }

    /// A link on the way to a root is trusted only where root or the Client's own account owns it
    /// and the directory it is in, and nobody else may write that directory: one another account
    /// placed, or one in a directory its group or anybody may write — `/tmp` among them — is not
    /// (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_link_above_a_root_is_followed_only_where_it_is_trusted() {
        let stat = |uid: libc::uid_t, mode: libc::mode_t| {
            // SAFETY: `stat` is plain data, for which all zeroes is a value.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            st.st_uid = uid;
            st.st_mode = mode;
            st
        };
        let dir = |uid, mode| stat(uid, libc::S_IFDIR | mode);
        let link = |uid| stat(uid, libc::S_IFLNK | 0o777);
        let own = 1000;
        for (owner, by) in [(0, 0), (own, own), (0, own), (own, 0)] {
            assert!(handle::trusted_link(&dir(owner, 0o755), &link(by), own));
            assert!(handle::trusted_link(&dir(owner, 0o700), &link(by), own));
            assert!(!handle::trusted_link(&dir(owner, 0o775), &link(by), own));
            assert!(!handle::trusted_link(&dir(owner, 0o757), &link(by), own));
            assert!(!handle::trusted_link(&dir(owner, 0o1777), &link(by), own));
        }
        assert!(!handle::trusted_link(&dir(0, 0o755), &link(1001), own));
        assert!(!handle::trusted_link(&dir(1001, 0o755), &link(0), own));
        assert!(!handle::trusted_link(&dir(1001, 0o755), &link(own), own));
        assert!(!handle::trusted_link(&dir(own, 0o755), &link(1001), own));
    }

    /// Every entry the Client keeps in its state directory under a name a Supervisor could carry
    /// is one the configuration refuses as a Supervisor's name there: the core's list is the
    /// adapters' constants (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[test]
    fn every_entry_of_the_clients_a_supervisor_could_be_named_after_is_listed() {
        let listed: Vec<&str> = crate::config::CLIENT_ENTRIES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let state = Path::new("/var/lib/opamp-fleet/state");
        let config = crate::config::ClientConfig {
            state_dir: state.to_path_buf(),
            ..crate::config::ClientConfig::default()
        };
        let staging = config.staging_dir_for(None);
        let staged = staging.file_name().and_then(|name| name.to_str());
        let root = config.supervisors_root();
        let default_root = root.file_name().and_then(|name| name.to_str());
        for name in [
            Some(UID_FILE),
            Some(CONFIG_DIR),
            staged,
            Some(crate::logging::DIR_NAME),
            Some(crate::gateway::cache::DIR),
            default_root,
        ] {
            let name = name.expect("a name in the state directory");
            assert!(listed.contains(&name), "{name} is not listed");
        }
    }

    /// A root reached through the system's own link — `/var/run` → `/run` on Linux, `/var` →
    /// `private/var` on macOS — is reached: the link is root's, in a directory only root writes
    /// (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_root_reached_through_a_link_of_the_systems_is_reached() {
        let root = Path::new("/var/run");
        let linked = [Path::new("/var"), root].iter().any(|path| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
        });
        if !linked {
            crate::skipped_unless_ci(
                "a_root_reached_through_a_link_of_the_systems_is_reached",
                "/var/run reached through a link",
            );
            return;
        }
        handle::open_beneath(root, root, handle::SEARCH, None, handle::own())
            .expect("the system's link");
    }

    /// What a purge names to the second service is where alone the process account can have
    /// written: the outermost directories the Client shares for writing, found through the
    /// Client's own directories and through no link (ADR-0059 clauses 5 and 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_directories_shared_for_writing_are_found_through_no_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let supervisor = dir.path().join("agent");
        let written = |path: &Path| {
            create_shared_dir(&supervisor, path, Some(group), Shared::Written).expect("shared");
        };
        written(&supervisor.join("data").join("certs"));
        written(&supervisor.join("var").join("cache"));
        written(&supervisor.join("var").join("cache").join("inner"));
        create_shared_dir(
            &supervisor,
            &supervisor.join("config"),
            Some(group),
            Shared::Read,
        )
        .expect("read");
        let elsewhere = dir.path().join("elsewhere");
        create_shared_dir(&elsewhere, &elsewhere, Some(group), Shared::Written).expect("shared");
        std::os::unix::fs::symlink(&elsewhere, supervisor.join("link")).expect("a link");

        assert_eq!(
            handle::shared_for_writing(&supervisor).expect("found"),
            vec![PathBuf::from("data/certs"), PathBuf::from("var/cache"),]
        );
    }

    /// A parent the Client creates on the way to a shared directory is passed through by the
    /// process account's group, `0710`, and no wider.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_parent_made_on_the_way_is_passed_through_and_no_more() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let data = dir.path().join("agent").join("var").join("data");
        create_shared_dir(
            &dir.path().join("agent"),
            &data,
            Some(group),
            Shared::Written,
        )
        .expect("made");
        assert_eq!(mode_and_group(&data), (0o2770, group.0));
        assert_eq!(
            mode_and_group(data.parent().expect("var")),
            (0o710, group.0)
        );
    }

    /// A data directory a Managed Process wrote while it ran as the Client gives what the Client
    /// owns in it to the process account's group, writable by it, once it is first shared: the
    /// Managed Process goes on writing its own state. A link is not followed, and a file with a
    /// second hard link is left as it is.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_data_directory_written_before_is_given_to_the_group_once_shared() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let outside = dir.path().join("outside");
        write_private(&outside, b"elsewhere").expect("write");
        let data = dir.path().join("agent").join("data");
        let nested = data.join("db");
        create_private_dir(&nested).expect("as it was written");
        create_private_dir(&data).expect("owner-only");
        write_private(&nested.join("state"), b"state").expect("state");
        write_private(&data.join("twice"), b"twice").expect("write");
        std::fs::hard_link(data.join("twice"), dir.path().join("twice")).expect("a second name");
        std::os::unix::fs::symlink(&outside, data.join("link")).expect("a link");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        create_shared_dir(
            &dir.path().join("agent"),
            &data,
            Some(group),
            Shared::Written,
        )
        .expect("shared");
        assert_eq!(mode_and_group(&data), (0o2770, group.0));
        assert_eq!(mode_and_group(&nested), (0o2770, group.0));
        assert_eq!(mode_and_group(&nested.join("state")), (0o660, group.0));
        assert_eq!(mode_and_group(&data.join("twice")).0, 0o600);
        assert_eq!(mode_and_group(&outside).0, 0o600);
    }

    /// An enrolment keeps a state directory a Client with a process account laid out as it is —
    /// `0710`, in the process account's group — and writes its records `0600`; any other state
    /// directory it narrows to the Client alone, as before (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn an_enrolment_keeps_a_shared_state_directory_shared() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group = own_group();
        let shared = dir.path().join("shared");
        Storage::client(shared.clone(), Some(group)).expect("laid out with a process account");
        let enrolling = Storage::enrolling(shared.clone()).expect("enrolling");
        enrolling
            .save_uid(&InstanceUid::default())
            .expect("the identity");
        assert_eq!(mode_and_group(&shared), (0o710, group.0));
        assert_eq!(mode_and_group(&shared.join(UID_FILE)).0, 0o600);

        let private = dir.path().join("private");
        std::fs::create_dir(&private).expect("mkdir at the umask");
        Storage::enrolling(private.clone()).expect("enrolling");
        assert_eq!(mode_and_group(&private).0, 0o700);
    }

    /// A hard link in `config/` to one of the Client's records — placed while the Managed Process
    /// still ran as the Client — is not shared when the storage opens: the record behind it stays
    /// `0600`, and the Client's alone.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_hard_link_in_config_to_a_private_file_is_not_shared() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let supervisor = state.join("agent");
        let before = Storage::new(supervisor.clone()).expect("without a process account");
        before
            .store_remote_config(&roled_offer(&[("fleet", b"service: {}\n", "")]))
            .expect("store");
        let key = state.join("client-key.pem");
        write_private(&key, b"KEY").expect("the Client's key");
        std::fs::hard_link(&key, before.config_dir().join("key"))
            .expect("a link the Managed Process placed");
        let at_first = mode_and_group(&key);
        assert_eq!(at_first.0, 0o600);

        let group = own_group();
        let after = Storage::supervised(supervisor, Some(group)).expect("with one");
        assert_eq!(mode_and_group(&key), at_first, "the key stays the Client's");
        assert_eq!(
            mode_and_group(&after.config_dir().join("fleet")),
            (0o640, group.0)
        );
    }

    /// Without a process account every mode is what it was before there was one: directories
    /// `0700`, the stored configuration `0600`, and the identity and the package record at the
    /// umask, as a plain write leaves them.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn without_a_process_account_every_mode_stays_as_it_was() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reference = dir.path().join("reference");
        std::fs::write(&reference, b"x").expect("a plain write");
        let at_umask = mode_and_group(&reference);

        let supervisor = dir.path().join("agent");
        let storage = Storage::supervised(supervisor.clone(), None).expect("storage");
        storage
            .store_remote_config(&roled_offer(&[("certs", b"PEM\n", "")]))
            .expect("store");
        storage.save_uid(&InstanceUid::default()).expect("identity");
        storage
            .store_package(&InstalledPackage {
                name: "agent".to_string(),
                version: "1.0.0".to_string(),
                hash_hex: "01".to_string(),
            })
            .expect("package");
        assert_eq!(mode_and_group(&supervisor).0, 0o700);
        assert_eq!(mode_and_group(&storage.config_dir()).0, 0o700);
        assert_eq!(mode_and_group(&storage.config_dir().join("certs")).0, 0o600);
        assert_eq!(mode_and_group(&supervisor.join(CONFIG_PB_FILE)).0, 0o600);
        assert_eq!(mode_and_group(&supervisor.join(UID_FILE)), at_umask);
        assert_eq!(mode_and_group(&supervisor.join(PACKAGE_FILE)), at_umask);
        let data = supervisor.join("data");
        create_shared_dir(&supervisor, &data, None, Shared::Written).expect("a data directory");
        assert_eq!(mode_and_group(&data).0, 0o700);
    }

    #[test]
    fn remote_config_round_trips_and_writes_plain_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let config = AgentRemoteConfig {
            config: Some(AgentConfigMap {
                config_map: HashMap::from([(
                    String::new(),
                    AgentConfigObject {
                        role: String::new(),
                        body: b"receivers: {}\n".to_vec(),
                        content_type: String::new(),
                    },
                )]),
            }),
            config_hash: vec![1, 2, 3],
        };
        storage.store_remote_config(&config).expect("store");
        assert_eq!(storage.load_remote_config(), Some(config));
        let plain = std::fs::read(dir.path().join("config").join("config")).expect("plain file");
        assert_eq!(plain, b"receivers: {}\n");
    }

    #[test]
    fn a_new_offer_replaces_the_previous_entry_files() {
        // The composed entry set changes over time (ADR-0023); an entry dropped upstream must
        // not survive on disk, where it would still be handed to the Managed Process.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let offer = |entries: &[(&str, &[u8])]| AgentRemoteConfig {
            config: Some(AgentConfigMap {
                config_map: entries
                    .iter()
                    .map(|(name, body)| {
                        (
                            name.to_string(),
                            AgentConfigObject {
                                role: String::new(),
                                body: body.to_vec(),
                                content_type: String::new(),
                            },
                        )
                    })
                    .collect(),
            }),
            config_hash: vec![1],
        };
        storage
            .store_remote_config(&offer(&[("base", b"a\n"), ("extra", b"b\n")]))
            .expect("store");
        storage
            .store_remote_config(&offer(&[("base", b"a2\n")]))
            .expect("store again");

        let config_dir = dir.path().join("config");
        assert_eq!(
            std::fs::read(config_dir.join("base")).expect("kept entry"),
            b"a2\n"
        );
        assert!(
            !config_dir.join("extra").exists(),
            "the dropped entry is gone"
        );
    }

    /// Moved here with the function itself: what the Collector plugin is started with is now
    /// decided by the module that wrote the files.
    #[test]
    fn config_entries_are_files_only_and_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(config_entries(dir.path()).is_empty());
        std::fs::write(dir.path().join("b.yaml"), "b").expect("write");
        std::fs::write(dir.path().join("a.yaml"), "a").expect("write");
        std::fs::create_dir(dir.path().join("subdir")).expect("mkdir");
        assert_eq!(entry_names(dir.path()), vec!["a.yaml", "b.yaml"]);
    }

    fn entry_names(config_dir: &std::path::Path) -> Vec<String> {
        config_entries(config_dir)
            .into_iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect()
    }

    fn roled_offer(entries: &[(&str, &[u8], &str)]) -> AgentRemoteConfig {
        AgentRemoteConfig {
            config: Some(AgentConfigMap {
                config_map: entries
                    .iter()
                    .map(|(name, body, role)| {
                        (
                            name.to_string(),
                            AgentConfigObject {
                                role: role.to_string(),
                                body: body.to_vec(),
                                content_type: String::new(),
                            },
                        )
                    })
                    .collect(),
            }),
            config_hash: vec![7],
        }
    }

    /// Every entry is written through a temporary name and a rename, and that name is never one an
    /// entry is stored under: an entry named like another's temporary file stays on disk in
    /// whichever order the map yields the two.
    /// Verifies: ADR-0017, ADR-0054
    #[test]
    fn no_entry_is_lost_to_another_entrys_temporary_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        // The map's order is random, so each order is stored in turn: the entry named like the
        // other's temporary file written before it, and after it.
        for round in 0..16 {
            let offer = roled_offer(&[("a", b"a", ""), ("a.tmp", b"a.tmp", "")]);
            storage.store_remote_config(&offer).expect("stored");
            assert!(
                storage.config_dir().join("a.tmp").is_file(),
                "round {round}: a.tmp is on disk"
            );
        }
    }

    /// An entry replaced by a rename is a new file: it belongs to the account the Client runs as,
    /// and it is owner-only like the one it replaces, whatever mode that one was left at.
    /// Verifies: ADR-0017, ADR-0054
    #[cfg(unix)]
    #[test]
    fn a_replaced_entry_is_the_runtimes_own_and_owner_only() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let offer = roled_offer(&[("a", b"first", "")]);
        storage.store_remote_config(&offer).expect("stored");
        let entry = storage.config_dir().join("a");
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o644)).expect("widen");
        storage
            .store_remote_config(&roled_offer(&[("a", b"second", "")]))
            .expect("replaced");
        let meta = std::fs::metadata(&entry).expect("metadata");
        assert_eq!(std::fs::read(&entry).expect("read"), b"second");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // SAFETY: `geteuid` reads the calling process's effective uid and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        assert_eq!(meta.uid(), uid, "the account the Client runs as owns it");
        assert_eq!(meta.gid(), gid);
    }

    /// ADR-0023: a roled entry is written like any other — it has to be on disk for a
    /// `${file:...}` reference to resolve — but it is not among the files the process is
    /// configured with.
    // Verifies: ADR-0023
    #[test]
    fn a_roled_entry_is_written_but_not_offered_as_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_remote_config(&roled_offer(&[
                ("base", b"receivers: {}\n", ""),
                ("ruleset", b"rules: []\n", "supplementary"),
            ]))
            .expect("store");

        let config_dir = storage.config_dir();
        assert_eq!(
            std::fs::read(config_dir.join("ruleset")).expect("written"),
            b"rules: []\n",
            "supplementary content is on disk for the process to read by path"
        );
        assert_eq!(entry_names(&config_dir), vec!["base"]);
    }

    /// Any other value is handled like `supplementary` and never guessed at (ADR-0023).
    #[test]
    fn an_unknown_role_is_treated_like_supplementary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_remote_config(&roled_offer(&[
                ("base", b"a\n", ""),
                ("certs", b"PEM\n", "some-agents-own-word"),
            ]))
            .expect("store");
        assert_eq!(entry_names(&storage.config_dir()), vec!["base"]);
    }

    /// The value survives the write, because a kind may define its own vocabulary — the Baseline
    /// defines `role` as *"Agent type-specific"*, which is only usable if the value comes back.
    #[test]
    fn a_roles_value_is_readable_per_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_remote_config(&roled_offer(&[
                ("base", b"a\n", ""),
                ("root", b"b\n", "main"),
                ("certs", b"PEM\n", "supplementary"),
            ]))
            .expect("store");

        let roles = entry_roles(&storage.config_dir());
        assert_eq!(roles.get("root").map(String::as_str), Some("main"));
        assert_eq!(
            roles.get("certs").map(String::as_str),
            Some("supplementary")
        );
        assert_eq!(roles.get("base"), None, "an unroled entry is not listed");
        // And the older question — is this entry configuration? — answers as it always did.
        assert_eq!(entry_names(&storage.config_dir()), vec!["base"]);
    }

    /// A file an older Client wrote holds names alone. It reads back as "carries a role, value
    /// unknown", which is exactly what that version recorded and all the pass-it-or-not decision
    /// ever needed — so an update in flight does not start handing supplementary content to a
    /// Managed Process as configuration.
    #[test]
    fn a_file_written_before_roles_carried_their_value_still_excludes_its_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_dir = dir.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        for name in ["base", "certs"] {
            std::fs::write(config_dir.join(name), b"x\n").expect("entry");
        }
        std::fs::write(config_dir.join(SUPPLEMENTARY_FILE), "certs\n").expect("old bookkeeping");

        assert_eq!(
            entry_roles(&config_dir).get("certs").map(String::as_str),
            Some(""),
            "a role is recorded, its value is not known"
        );
        assert_eq!(entry_names(&config_dir), vec!["base"]);
    }

    /// The common case writes no bookkeeping at all, and a role that is later removed must not
    /// leave an entry excluded forever.
    #[test]
    fn the_bookkeeping_appears_only_while_a_role_does() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let config_dir = storage.config_dir();

        storage
            .store_remote_config(&roled_offer(&[("base", b"a\n", "")]))
            .expect("store");
        assert!(!config_dir.join(SUPPLEMENTARY_FILE).exists());

        storage
            .store_remote_config(&roled_offer(&[("base", b"a\n", "supplementary")]))
            .expect("store");
        assert!(config_dir.join(SUPPLEMENTARY_FILE).exists());
        assert!(entry_names(&config_dir).is_empty());

        storage
            .store_remote_config(&roled_offer(&[("base", b"a\n", "")]))
            .expect("store");
        assert!(
            !config_dir.join(SUPPLEMENTARY_FILE).exists(),
            "the role is gone, and so is what recorded it"
        );
        assert_eq!(entry_names(&config_dir), vec!["base"]);
    }

    /// A state directory with no bookkeeping file holds configuration alone, so everything in it
    /// reads as configuration (ADR-0023).
    #[test]
    fn entries_without_bookkeeping_are_all_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("base"), "a").expect("write");
        std::fs::write(dir.path().join("extra"), "b").expect("write");
        assert_eq!(entry_names(dir.path()), vec!["base", "extra"]);
    }

    #[test]
    fn entry_names_cannot_escape_the_config_directory() {
        assert_eq!(entry_file_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(entry_file_name(""), "config");
        assert_eq!(entry_file_name("collector.yaml"), "collector.yaml");
        // Nothing but dots strips to nothing, and an empty name would be the config directory
        // itself.
        assert_eq!(entry_file_name("."), "config");
        assert_eq!(entry_file_name("..."), "config");
    }

    /// A configuration means the same on every host, so an entry name Windows cannot hold as a
    /// file — a device name, with or without an extension, or a name ending in a dot — is refused
    /// on every host, and the previous offer's files stay as they were. The refusal is what the
    /// Agent reports `FAILED` with (ADR-0017 clause 7).
    /// Verifies: ADR-0017
    #[test]
    fn an_entry_name_windows_cannot_hold_is_refused_on_every_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_remote_config(&roled_offer(&[("base", b"a\n", "")]))
            .expect("store");

        for name in [
            "CON", "con", "Prn", "aux", "NUL", "nul.yaml", "com1", "COM9.txt", "lpt1", "LPT9.x.y",
            "base.", "a..",
        ] {
            let error = storage
                .store_remote_config(&roled_offer(&[(name, b"x\n", "")]))
                .expect_err(name);
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name}");
            assert!(error.to_string().contains(name), "{name}: {error}");
        }
        assert_eq!(entry_names(&storage.config_dir()), vec!["base"]);
        for name in ["console", "com10", "lpt", "nul-x", "con_"] {
            check_entry_names(&roled_offer(&[(name, b"x\n", "")]))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    /// Two entries that would land in one file — equal once mapped, or equal to a case-insensitive
    /// file system — are refused rather than one silently overwriting the other in an order the map
    /// decides.
    /// Verifies: ADR-0017
    #[test]
    fn entries_that_would_share_a_file_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        for pair in [
            ["A", "a"],
            ["x y", "x_y"],
            ["", "config"],
            ["Base.yaml", "base.YAML"],
        ] {
            let error = storage
                .store_remote_config(&roled_offer(&[
                    (pair[0], b"1\n", ""),
                    (pair[1], b"2\n", ""),
                ]))
                .expect_err(&format!("{pair:?}"));
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{pair:?}");
            assert!(
                !storage.config_dir().exists() || entry_names(&storage.config_dir()).is_empty(),
                "{pair:?}: nothing written"
            );
        }
    }

    #[test]
    fn an_entry_named_only_dots_is_stored_as_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        storage
            .store_remote_config(&roled_offer(&[("...", b"a\n", "")]))
            .expect("store");
        let plain = std::fs::read(dir.path().join("config").join("config")).expect("plain file");
        assert_eq!(plain, b"a\n");
    }

    /// A store cut short leaves the previous `remote-config.pb`, never a new one beside the
    /// previous offer's files: the drop then still reads the previous map and deletes what it
    /// wrote instead of keeping it as the operator's (ADR-0017 clause 52). The store is stopped
    /// by a directory standing where the next offer's entry file goes — `create_private_dir`
    /// resets the mode of `config/`, so a failed removal cannot be staged from here.
    /// Verifies: ADR-0017
    #[test]
    fn a_store_cut_short_leaves_no_previous_entry_file_beside_a_new_pb() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut previous = roled_offer(&[("a", b"1\n", "")]);
        previous.config_hash = vec![1];
        storage.store_remote_config(&previous).expect("store");
        let config_dir = storage.config_dir();
        std::fs::create_dir(config_dir.join("b")).expect("in the way");

        let mut next = roled_offer(&[("b", b"x\n", "")]);
        next.config_hash = vec![2];
        storage
            .store_remote_config(&next)
            .expect_err("the entry file cannot be written");

        assert_eq!(
            storage
                .load_remote_config()
                .map(|stored| stored.config_hash),
            Some(vec![1]),
            "the stored map still describes what is on disk"
        );
        std::fs::remove_dir(config_dir.join("b")).expect("clear the way");
        assert_eq!(
            storage.drop_remote_config().expect("drop"),
            Some(DroppedRemoteConfig::Removed {
                hash: vec![1],
                kept: Vec::new()
            })
        );
        assert!(
            entry_names(&config_dir).is_empty(),
            "{:?}",
            entry_names(&config_dir)
        );
    }
}
