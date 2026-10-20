//! Artifact bytes on the filesystem (ADR-0037 clause 4): the default adapter behind
//! [`BlobStore`](crate::blobs::BlobStore).

use std::collections::BTreeMap;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::blobs::{is_hash, BlobStore};

/// One file per blob under `<data_dir>/blobs/`, named by its SHA-256 and owner-only. An upload is
/// streamed to a staging file beside them, hashed on the way, and renamed to its hash — so a blob
/// is never seen half-written, and a crash leaves at most a staging file, which the next open
/// removes.
pub struct FsBlobStore {
    dir: PathBuf,
    /// Numbers each upload's staging file, so two uploads never share one.
    next_upload: AtomicU64,
}

impl FsBlobStore {
    /// Opens the store in the data directory `root`, creating `blobs/` owner-only. The package
    /// store lists it once when it opens, which hashes every blob again (ADR-0037 clause 4).
    ///
    /// # Errors
    /// Returns an error when the directory cannot be created.
    pub fn open(root: &Path) -> Result<Self, String> {
        let dir = root.join(super::BLOBS);
        super::create_private_dir(&dir)?;
        Ok(FsBlobStore {
            dir,
            next_upload: AtomicU64::new(0),
        })
    }

    fn path(&self, sha256: &str) -> Result<PathBuf, String> {
        if !is_hash(sha256) {
            return Err(format!("{sha256:?} is not the SHA-256 of a blob"));
        }
        Ok(self.dir.join(sha256))
    }

    /// Streams `bytes` into the staging file `staged`, owner-only, and answers their hash and size.
    fn stage(staged: &Path, bytes: &mut dyn Read) -> Result<(String, u64), String> {
        let mut file = super::create_owner_only(staged)?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match bytes.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("the upload failed: {e}")),
            };
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])
                .map_err(|e| format!("cannot write {}: {e}", staged.display()))?;
            size += n as u64;
        }
        file.flush()
            .map_err(|e| format!("cannot write {}: {e}", staged.display()))?;
        Ok((hex::encode(hasher.finalize()), size))
    }
}

impl BlobStore for FsBlobStore {
    fn put(&self, bytes: &mut dyn Read) -> Result<(String, u64), String> {
        let n = self.next_upload.fetch_add(1, Ordering::Relaxed);
        // `.tmp`: what a crash leaves of it is removed when the store next opens.
        let staged = self
            .dir
            .join(format!("upload-{}-{n}.tmp", std::process::id()));
        let result = Self::stage(&staged, bytes).and_then(|(sha256, size)| {
            let path = self.path(&sha256)?;
            if path.is_file() {
                // The same bytes are stored already: once is enough.
                super::remove_file(&staged)?;
            } else {
                std::fs::rename(&staged, &path)
                    .map_err(|e| format!("cannot persist {}: {e}", path.display()))?;
            }
            Ok((sha256, size))
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        result
    }

    fn get(&self, sha256: &str) -> Result<Box<dyn Read + Send>, String> {
        let path = self.path(sha256)?;
        let file = std::fs::File::open(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Ok(Box::new(file))
    }

    fn exists(&self, sha256: &str) -> bool {
        self.path(sha256).is_ok_and(|path| path.is_file())
    }

    fn delete(&self, sha256: &str) -> Result<(), String> {
        super::remove_file(&self.path(sha256)?)
    }

    /// Every blob, each hashed again by streaming it — the startup check of ADR-0037 clause 4. A
    /// blob whose content does not match its name fails naming it, and so does anything in the
    /// directory that is not a blob; a staging file a crash left is removed.
    fn list(&self) -> Result<Vec<(String, u64)>, String> {
        let mut blobs = BTreeMap::new();
        for (name, path) in super::entries(&self.dir)? {
            if !is_hash(&name) || !path.is_file() {
                return Err(super::unknown(&path));
            }
            let mut file = std::fs::File::open(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let (sha256, size) =
                hash(&mut file).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            if sha256 != name {
                return Err(format!(
                    "{} does not match its name — the blob is corrupt; restore it from a backup \
                     or upload the artifact again",
                    path.display()
                ));
            }
            blobs.insert(name, size);
        }
        Ok(blobs.into_iter().collect())
    }
}

/// The SHA-256 and size of what `bytes` yields.
fn hash(bytes: &mut dyn Read) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match bytes.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identical bytes are stored once, under their hash, owner-only; what was stored reads back.
    /// Verifies: ADR-0037
    #[test]
    fn identical_bytes_are_one_blob_named_by_its_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsBlobStore::open(dir.path()).expect("open");
        let (first, size) = store.put(&mut &b"artifact"[..]).expect("put");
        let (second, _) = store.put(&mut &b"artifact"[..]).expect("put again");
        assert_eq!(first, second);
        assert_eq!(size, 8);
        assert_eq!(first, hex::encode(Sha256::digest(b"artifact")));
        assert_eq!(store.list().expect("list"), vec![(first.clone(), 8)]);
        let mut read = Vec::new();
        store
            .get(&first)
            .expect("get")
            .read_to_end(&mut read)
            .expect("read");
        assert_eq!(read, b"artifact");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join("blobs").join(&first))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.delete(&first).expect("delete");
        assert!(!store.exists(&first));
        store.delete(&first).expect("deleting the absent is fine");
        assert!(store.get("../x").is_err(), "only a hash names a blob");
    }

    /// A stream that fails stores nothing and leaves no staging file behind.
    #[test]
    fn a_failed_upload_stores_nothing() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("cut off"))
            }
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsBlobStore::open(dir.path()).expect("open");
        assert!(store.put(&mut Broken).is_err());
        assert_eq!(
            std::fs::read_dir(dir.path().join("blobs"))
                .expect("dir")
                .count(),
            0
        );
    }

    /// A blob whose content does not match its name fails the startup listing naming it, and so
    /// does a file that is no blob; a staging file a crash left is removed.
    /// Verifies: ADR-0037
    #[test]
    fn a_blob_that_does_not_match_its_name_fails_the_open_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsBlobStore::open(dir.path()).expect("open");
        let (sha256, _) = store.put(&mut &b"artifact"[..]).expect("put");
        std::fs::write(dir.path().join("blobs/upload-1-0.tmp"), b"half").expect("leftover");
        store
            .list()
            .expect("a staging file is no blob, and is removed");
        assert!(!dir.path().join("blobs/upload-1-0.tmp").exists());

        std::fs::write(dir.path().join("blobs").join(&sha256), b"tampered").expect("tamper");
        let error = store.list().expect_err("refused");
        assert!(error.contains(&sha256), "{error}");

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("blobs")).expect("dir");
        std::fs::write(dir.path().join("blobs/otelcol.bin"), b"x").expect("loose");
        let error = FsBlobStore::open(dir.path())
            .and_then(|store| store.list())
            .expect_err("refused");
        assert!(error.contains("otelcol.bin"), "{error}");
    }
}
