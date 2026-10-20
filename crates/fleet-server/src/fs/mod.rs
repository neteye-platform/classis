//! The filesystem adapters of the Server's stores (ADR-0006), the one data directory they share
//! (ADR-0037), and the moves every one of them makes: a directory only its owner can enter, a file
//! only its owner can read, replaced in one step, so a crash mid-write leaves the old document
//! rather than half a new one.
//!
//! The layout under `data_dir` is fixed (ADR-0037 clause 2), and no other is read: a file or
//! directory it does not name fails startup naming the path.

mod agents;
mod audit;
mod blobs;
mod bootstrap;
mod configs;
mod deployments;
mod enrolment;
mod packages;
mod revocation;

pub use agents::FsAgentStore;
pub use audit::{files_in as audit_files, FsAuditStore};
pub use blobs::FsBlobStore;
pub use bootstrap::FsBootstrapStore;
pub use configs::FsConfigBackend;
pub use deployments::FsDeploymentBackend;
pub use enrolment::FsEnrolmentStore;
pub use packages::FsPackageBackend;
pub use revocation::FsLedgerStore;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// One Configuration per file, its retained revisions inside (ADR-0037 clause 2).
pub const CONFIGURATIONS: &str = "configurations";
/// One Deployment per file.
pub const DEPLOYMENTS: &str = "deployments";
/// One Package per file: its identity and entries, no bytes.
pub const PACKAGES: &str = "packages";
/// The artifacts, each named by its SHA-256.
pub const BLOBS: &str = "blobs";
/// One Agent record per file.
pub const AGENTS: &str = "agents";
/// One Host per file.
pub const HOSTS: &str = "hosts";
/// The certificate register: one file per certificate the Server signed.
pub const CERTIFICATES: &str = "certificates";
/// The bootstrap certificates the Server issued, with their PKCS#12 files.
pub const BOOTSTRAP: &str = "bootstrap";
/// The audit record's files.
pub const AUDIT: &str = "audit";
/// The revocation list.
pub const REVOCATIONS: &str = "revocations.json";
/// The enrolment window and its pending requests.
pub const ENROLMENT: &str = "enrolment.json";

/// Every directory the layout names, in the order the table of ADR-0037 clause 2 lists them.
pub const DIRECTORIES: [&str; 9] = [
    CONFIGURATIONS,
    DEPLOYMENTS,
    PACKAGES,
    BLOBS,
    AGENTS,
    HOSTS,
    CERTIFICATES,
    BOOTSTRAP,
    AUDIT,
];

/// Opens the data directory (ADR-0037): creates it and every directory of the layout owner-only,
/// and refuses one that holds anything the layout does not name. What lies inside each directory
/// is its store's to check, when the store opens.
///
/// # Errors
/// Returns an error naming the path when a directory cannot be created, or when the data
/// directory holds a file or directory the layout does not name.
pub fn open_data_dir(root: &Path) -> Result<(), String> {
    create_private_dir(root)?;
    for (name, path) in entries(root)? {
        let known = if DIRECTORIES.contains(&name.as_str()) {
            path.is_dir()
        } else {
            (name == REVOCATIONS || name == ENROLMENT) && path.is_file()
        };
        if !known {
            return Err(unknown(&path));
        }
    }
    for dir in DIRECTORIES {
        create_private_dir(&root.join(dir))?;
    }
    Ok(())
}

/// The refusal for a path the layout does not name (ADR-0037 clause 2). Skipping it would open a
/// store that merely looks complete.
pub(crate) fn unknown(path: &Path) -> String {
    format!(
        "{} is not part of the data directory's layout — this Server reads no other; move it \
         aside, or run `server migrate` for a layout an older Server wrote",
        path.display()
    )
}

/// The entries of `dir` by name, sorted. A temporary file a crash left behind beside a document
/// ([`replace`]) is removed rather than listed: the rename that would have made it the document
/// never happened, so the document is the one before it. A name that is not UTF-8 is refused.
///
/// # Errors
/// Returns an error when the directory cannot be read, or an entry has a name that is not UTF-8.
pub(crate) fn entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut found = Vec::new();
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            return Err(unknown(&path));
        };
        if name.ends_with(".tmp") && path.is_file() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
            continue;
        }
        found.push((name, path));
    }
    found.sort();
    Ok(found)
}

/// The files `<stem>.json` in `dir`, as `(stem, path)`, sorted; anything else in it fails.
///
/// # Errors
/// Returns an error naming the path of anything that is not such a file.
pub(crate) fn json_files(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    entries(dir)?
        .into_iter()
        .map(|(name, path)| match name.strip_suffix(".json") {
            Some(stem) if !stem.is_empty() && path.is_file() => Ok((stem.to_string(), path)),
            _ => Err(unknown(&path)),
        })
        .collect()
}

/// Removes a file, and is content when it is not there.
pub(crate) fn remove_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("cannot delete {}: {e}", path.display()))
        }
        _ => Ok(()),
    }
}

/// The refusal for a file whose name disagrees with what it holds (ADR-0037 clause 2): a write
/// would land somewhere else, so it is named rather than silently corrected.
pub(crate) fn misnamed(path: &Path, holds: &str) -> String {
    format!(
        "{} does not match the {holds} it holds — rename the file or fix it",
        path.display()
    )
}

/// Creates `dir` if it is missing and, on Unix, restricts it to its owner (`0700`) — whatever it
/// holds may carry credentials, and other local users on the Server host have no business there.
pub fn create_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot restrict {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Replaces `path` with `bytes` by writing `<path>.tmp` beside it, owner-only (`0600`) on Unix, and
/// renaming it into place (ADR-0037 clause 1). The mode is set in the open call rather than after
/// the write, so the content is never briefly readable by another local user, and the rename
/// carries the mode with it.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_temp(path, bytes, false)?;
    rename_into_place(&temp_of(path), path)
}

/// [`replace`], and durable: the content reaches the disk before the rename makes it the document,
/// and on Unix the rename reaches it before this returns, so a power loss leaves the old document
/// or the new one, never an empty file or a revocation lost after it was answered. For a record
/// that answers a security decision (ADR-0037 clause 1).
pub fn replace_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_temp(path, bytes, true)?;
    rename_into_place(&temp_of(path), path)?;
    sync_dir_of(path)
}

/// Writes `<path>.tmp` owner-only, synced to disk when `durable`.
fn write_temp(path: &Path, bytes: &[u8], durable: bool) -> Result<(), String> {
    use std::io::Write as _;
    let temp = temp_of(path);
    let mut file = create_owner_only(&temp)?;
    file.write_all(bytes)
        .and_then(|()| if durable { file.sync_all() } else { Ok(()) })
        .map_err(|e| format!("cannot write {}: {e}", temp.display()))
}

/// Creates (or truncates) `path` for writing, owner-only (`0600`) on Unix.
///
/// # Errors
/// Returns an error naming the path when it cannot be created.
pub(crate) fn create_owner_only(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Makes a rename into `path`'s directory durable by syncing the directory itself.
#[cfg(unix)]
fn sync_dir_of(path: &Path) -> Result<(), String> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("cannot persist {}: {e}", path.display()))
}

/// Windows opens no directory as a file to sync, so the rename is left to the filesystem.
#[cfg(not(unix))]
fn sync_dir_of(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn temp_of(path: &Path) -> PathBuf {
    let mut temp = OsString::from(path.as_os_str());
    temp.push(".tmp");
    PathBuf::from(temp)
}

fn rename_into_place(temp: &Path, path: &Path) -> Result<(), String> {
    std::fs::rename(temp, path).map_err(|e| format!("cannot persist {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Server on an empty `data_dir` lays out every directory of ADR-0037 clause 2, each
    /// owner-only; a file or directory the layout does not name fails the open naming its path,
    /// and a temporary file a crash left beside a document is removed instead.
    /// Verifies: ADR-0037
    #[test]
    fn the_data_directory_has_one_layout_and_no_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("fleet-data");
        open_data_dir(&root).expect("open an empty data directory");
        for name in DIRECTORIES {
            assert!(root.join(name).is_dir(), "{name} was not created");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(root.join(name))
                    .expect("meta")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o700, "{name} is not owner-only");
            }
        }
        std::fs::write(root.join(REVOCATIONS), "[]").expect("list");
        std::fs::write(root.join("enrolment.json.tmp"), "{").expect("leftover");
        open_data_dir(&root).expect("the named files are part of the layout");
        assert!(
            !root.join("enrolment.json.tmp").exists(),
            "the leftover is removed"
        );

        for stray in ["base.json", "labels", "revocation", "fleet-packages"] {
            let path = root.join(stray);
            if stray.ends_with(".json") {
                std::fs::write(&path, "{}").expect("write");
            } else {
                std::fs::create_dir(&path).expect("mkdir");
            }
            let error = open_data_dir(&root).expect_err("a stray entry is refused");
            assert!(error.contains(stray), "{error}");
            assert!(error.contains("server migrate"), "{error}");
            if path.is_dir() {
                std::fs::remove_dir(&path).expect("clean");
            } else {
                std::fs::remove_file(&path).expect("clean");
            }
        }
        std::fs::remove_dir(root.join(AGENTS)).expect("rmdir");
        std::fs::write(root.join(AGENTS), "").expect("a file where a directory belongs");
        assert!(open_data_dir(&root).is_err());
    }

    /// Every record is written owner-only, whether or not the write is synced.
    #[cfg(unix)]
    #[test]
    fn a_plain_replace_is_owner_only_too() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.json");
        replace(&path, b"{}").expect("write");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A durable replace still replaces: the new content under the old name, nothing left beside
    /// it, and on Unix only the owner may read it. That it reached the disk before a power loss is
    /// not observable from a test.
    #[test]
    fn replace_owner_only_replaces_the_document() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("revocations.json");
        replace_owner_only(&path, b"old").expect("first write");
        replace_owner_only(&path, b"new").expect("replace");
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        assert!(
            !temp_of(&path).exists(),
            "the temporary file was left behind"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
