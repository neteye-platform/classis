//! The audit record on the filesystem (ADR-0022): the default adapter behind
//! [`AuditStore`](crate::audit_log::AuditStore).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use crate::audit_log::{AuditStore, Tail};

/// `audit-<first seq>.jsonl` files in a directory only the Server's account can enter, each
/// owner-only, appended to one line at a time.
pub struct FsAuditStore {
    dir: PathBuf,
    current: Option<(std::fs::File, u64)>,
}

impl FsAuditStore {
    /// Opens the store in the data directory `root`, creating `audit/` owner-only (ADR-0037). The
    /// newest file is continued.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be created or read, or holds anything but audit
    /// files.
    pub fn open(root: &Path) -> Result<Self, String> {
        let dir = root.join(super::AUDIT);
        super::create_private_dir(&dir)?;
        // The directory's own name, durable before the first file in it is (ADR-0022).
        super::sync_dir_of(&dir)?;
        for (name, path) in super::entries(&dir)? {
            if !path.is_file() || seq_in(&name).is_none() {
                return Err(super::unknown(&path));
            }
        }
        let mut store = FsAuditStore { dir, current: None };
        if let Some(newest) = store.files()?.pop() {
            let (mut file, mut size) = open_append(&newest)?;
            // A crash mid-write leaves a last line without its newline; the next entry must start
            // on a line of its own, or it would be glued to the torn one.
            if size > 0 && !ends_with_newline(&newest)? {
                file.write_all(b"\n")
                    .map_err(|e| format!("cannot repair {}: {e}", newest.display()))?;
                size += 1;
            }
            store.current = Some((file, size));
        }
        Ok(store)
    }

    /// The record's files, oldest first.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be read.
    pub fn files(&self) -> Result<Vec<PathBuf>, String> {
        files_in(&self.dir)
    }
}

/// The audit files in `dir`, oldest first — ordered by the sequence number in their name.
///
/// # Errors
/// Returns an error when the directory cannot be read.
pub fn files_in(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter_map(|path| {
            let seq = seq_in(path.file_name()?.to_str()?)?;
            Some((seq, path))
        })
        .collect();
    files.sort();
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

/// The sequence number an audit file's name carries: `audit-<first seq>.jsonl`.
fn seq_in(name: &str) -> Option<u64> {
    name.strip_prefix("audit-")?
        .strip_suffix(".jsonl")?
        .parse()
        .ok()
}

fn open_append(path: &Path) -> Result<(std::fs::File, u64), String> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let size = file
        .metadata()
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .len();
    // A new file's name is durable only once its directory is: without that, a crash can take the
    // file and every entry synced into it (ADR-0022).
    if size == 0 {
        super::sync_dir_of(path)?;
    }
    Ok((file, size))
}

fn ends_with_newline(path: &Path) -> Result<bool, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    file.seek(SeekFrom::End(-1))
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(last[0] == b'\n')
}

/// The non-empty lines at the end of `path`.
fn tail_lines(path: &Path) -> Result<Vec<String>, String> {
    Ok(last_chunk(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect())
}

/// The last non-empty line of `path`, read from its end.
fn last_line(path: &Path) -> Result<Option<String>, String> {
    Ok(tail_lines(path)?.pop())
}

fn last_chunk(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let size = file
        .metadata()
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .len();
    // An entry is far below this; the tail of one is all that is ever needed.
    let start = size.saturating_sub(1024 * 1024);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The `seq` an entry line carries, if the line is a whole entry.
fn seq_of(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("seq")?
        .as_u64()
}

/// The number in an audit file's name.
fn first_seq_of(path: &Path) -> u64 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("audit-"))
        .and_then(|name| name.strip_suffix(".jsonl"))
        .and_then(|seq| seq.parse().ok())
        .unwrap_or(0)
}

impl AuditStore for FsAuditStore {
    fn tail(&mut self) -> Result<Option<Tail>, String> {
        // The newest file that holds a line: a rotation that failed its first write leaves an
        // empty one behind, and the chain goes on from the file before it.
        for file in self.files()?.iter().rev() {
            let lines = tail_lines(file)?;
            let Some(last_line) = lines.last().cloned() else {
                continue;
            };
            // The highest seq near the end; a torn last line carries none, and the entries before
            // it still say where the count stands. A file whose tail holds no whole entry counts
            // on from its name.
            let last_seq = lines
                .iter()
                .filter_map(|line| seq_of(line))
                .max()
                .unwrap_or_else(|| first_seq_of(file).saturating_sub(1) + lines.len() as u64);
            let torn = seq_of(&last_line).is_none() || !ends_with_newline(file)?;
            return Ok(Some(Tail {
                last_line,
                last_seq,
                torn,
            }));
        }
        Ok(None)
    }

    fn append(&mut self, seq: u64, line: &str) -> Result<(), String> {
        if self.current.is_none() {
            self.current = Some(open_append(&self.dir.join(format!("audit-{seq}.jsonl")))?);
        }
        let (file, size) = self.current.as_mut().expect("just opened");
        // One write for the line and its newline, so a crash leaves a whole line or a torn last
        // one, never two entries run together.
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        if let Err(e) = file.write_all(&bytes).and_then(|()| file.sync_data()) {
            // A write that failed partway leaves a fragment; cut the file back to its last whole
            // line, so the next entry does not land on it.
            let _ = file.set_len(*size);
            return Err(format!("cannot append to the audit record: {e}"));
        }
        *size += bytes.len() as u64;
        Ok(())
    }

    fn current_bytes(&self) -> u64 {
        self.current.as_ref().map_or(0, |(_, size)| *size)
    }

    fn rotate(&mut self, keep: usize) -> Result<Vec<(String, String)>, String> {
        self.current = None;
        let mut files = self.files()?;
        let mut deleted = Vec::new();
        while files.len() >= keep.max(1) {
            let oldest = files.remove(0);
            let last = last_line(&oldest)?.unwrap_or_default();
            if let Err(e) = std::fs::remove_file(&oldest) {
                // What was deleted already is still told; the rest stays for the next rotation.
                tracing::error!(file = %oldest.display(), error = %e, "cannot delete an audit file");
                break;
            }
            let name = oldest
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            deleted.push((name, last));
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0022
    #[test]
    fn the_record_is_owner_only_and_continues_where_it_ended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("audit");
        {
            let mut store = FsAuditStore::open(dir.path()).expect("open");
            store.append(1, "{\"seq\":1}").expect("append");
            store.append(2, "{\"seq\":2}").expect("append");
        }
        let mut store = FsAuditStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.tail().expect("tail"),
            Some(Tail {
                last_line: "{\"seq\":2}".to_string(),
                last_seq: 2,
                torn: false
            })
        );
        store.append(3, "{\"seq\":3}").expect("append");
        assert_eq!(
            store.files().expect("files").len(),
            1,
            "the newest file is continued"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let file = &store.files().expect("files")[0];
            let mode = std::fs::metadata(file).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let mode = std::fs::metadata(&root).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let deleted = store.rotate(1).expect("rotate");
        assert_eq!(
            deleted,
            vec![("audit-1.jsonl".to_string(), "{\"seq\":3}".to_string())]
        );
        store.append(4, "{\"seq\":4}").expect("append");
        assert_eq!(
            store.files().expect("files"),
            vec![root.join("audit-4.jsonl")]
        );
    }

    /// A record a crash cut mid-line goes on from its last whole entry, on a line of its own, and
    /// says it was torn; an empty newest file is passed over.
    /// Verifies: ADR-0022
    #[test]
    fn a_torn_record_goes_on_from_its_last_whole_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("audit");
        std::fs::create_dir_all(&root).expect("dir");
        std::fs::write(
            root.join("audit-1.jsonl"),
            "{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3,\"pr",
        )
        .expect("write");
        std::fs::write(root.join("audit-9.jsonl"), "").expect("an empty newest file");
        let mut store = FsAuditStore::open(dir.path()).expect("open");
        let tail = store.tail().expect("tail").expect("a tail");
        assert_eq!(tail.last_seq, 2);
        assert!(tail.torn);
        assert_eq!(tail.last_line, "{\"seq\":3,\"pr");
        store.rotate(16).expect("rotate");
        store.append(3, "{\"seq\":3}").expect("append");
        let mut reopened = FsAuditStore::open(dir.path()).expect("reopen");
        assert_eq!(reopened.tail().expect("tail").expect("tail").last_seq, 3);

        // The newest file torn: it is continued on a line of its own.
        let other = dir.path().join("other");
        std::fs::create_dir_all(other.join("audit")).expect("dir");
        std::fs::write(
            other.join("audit/audit-1.jsonl"),
            "{\"seq\":1}\n{\"seq\":2,\"pr",
        )
        .expect("write");
        let mut store = FsAuditStore::open(&other).expect("open");
        store.append(2, "{\"seq\":2}").expect("append");
        let text = std::fs::read_to_string(other.join("audit/audit-1.jsonl")).expect("read");
        assert_eq!(text, "{\"seq\":1}\n{\"seq\":2,\"pr\n{\"seq\":2}\n");
    }
}
