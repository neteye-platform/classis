//! The Space records on the filesystem (ADR-0064 clause 1): the default adapter behind
//! [`SpaceStore`](crate::space_store::SpaceStore).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::space_store::{check_key, SpaceRecord, SpaceStore};

/// One JSON file per Space under `<data_dir>/spaces/`, owner-only, replaced in one step and synced
/// before the act that changed it is answered (ADR-0037 clause 1). The file is named by the
/// *lowercase* name, so two names that differ only in case would be one file even on a filesystem
/// that ignores case, and creating the second finds the first; the name as it was created, case
/// and all, is inside the file. Nothing is kept in memory: every call reads the file.
pub struct FsSpaceStore {
    dir: PathBuf,
    /// One writer at a time, so two creations of one name, or a creation and a rotation, cannot
    /// interleave their check and their write.
    writing: Mutex<()>,
}

/// The on-disk document — this adapter's format, not the port's.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    name: String,
    key: String,
}

#[derive(Serialize)]
struct DocumentRef<'a> {
    name: &'a str,
    key: &'a str,
}

impl FsSpaceStore {
    /// Opens the store in the data directory `root`, creating `spaces/` owner-only, and reads
    /// every Space once so that a file that does not parse, or does not match its name, fails
    /// startup naming it.
    ///
    /// # Errors
    /// Returns an error naming the path when the directory cannot be created or a file in it is
    /// not a Space.
    pub fn open(root: &Path) -> Result<Self, String> {
        let dir = root.join(super::SPACES);
        super::create_private_dir(&dir)?;
        let store = FsSpaceStore {
            dir,
            writing: Mutex::new(()),
        };
        store.load()?;
        Ok(store)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.json", name.to_ascii_lowercase()))
    }

    /// Reads the document at `path`, or `None` where there is none. Whether it is the record of
    /// the Space the file is named for is checked here.
    fn read(path: &Path) -> Result<Option<SpaceRecord>, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let document: Document = serde_json::from_slice(&bytes)
            .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
        let record = SpaceRecord {
            name: document.name,
            key: Zeroizing::new(document.key),
        };
        record
            .check()
            .map_err(|e| format!("cannot restore {}: {e}", path.display()))?;
        let named = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| stem == record.name.to_ascii_lowercase());
        if !named {
            return Err(super::misnamed(path, "Space"));
        }
        Ok(Some(record))
    }

    fn write(&self, name: &str, key: &str) -> Result<(), String> {
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&DocumentRef { name, key }).expect("a space serializes"),
        );
        super::replace_owner_only(&self.path(name), &json)
    }
}

impl SpaceStore for FsSpaceStore {
    fn load(&self) -> Result<Vec<SpaceRecord>, String> {
        let mut spaces = Vec::new();
        for (_, path) in super::json_files(&self.dir)? {
            if let Some(space) = Self::read(&path)? {
                spaces.push(space);
            }
        }
        spaces.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(spaces)
    }

    fn create(&self, space: &SpaceRecord) -> Result<bool, String> {
        space.check()?;
        let _writing = self.writing.lock().expect("spaces lock");
        if self.path(&space.name).exists() {
            return Ok(false);
        }
        self.write(&space.name, &space.key)?;
        Ok(true)
    }

    fn get(&self, name: &str) -> Result<Option<SpaceRecord>, String> {
        if !classis_core::enrolment_key::is_valid_space_name(name) {
            return Ok(None);
        }
        Ok(Self::read(&self.path(name))?.filter(|space| space.name == name))
    }

    fn replace_key(&self, name: &str, key: &str) -> Result<bool, String> {
        check_key(name, key)?;
        let _writing = self.writing.lock().expect("spaces lock");
        if Self::read(&self.path(name))?.is_none_or(|space| space.name != name) {
            return Ok(false);
        }
        self.write(name, key)?;
        Ok(true)
    }
}
