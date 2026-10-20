//! The bootstrap certificates the Server issued, on the filesystem (ADR-0028, ADR-0037): the
//! default adapter behind [`BootstrapStore`](crate::bootstrap::BootstrapStore).

use std::path::{Path, PathBuf};

use crate::bootstrap::{BootstrapStore, Entry};
use crate::revocation::CertId;

/// One JSON file per certificate under `<data_dir>/bootstrap/`, named after its issuer and serial
/// as the register names a certificate, in a directory only its owner enters, and beside it the
/// certificate's PKCS#12 file, `<issuer>-<serial>.p12`, when one was made (ADR-0029, ADR-0037).
pub struct FsBootstrapStore {
    dir: PathBuf,
}

impl FsBootstrapStore {
    /// Opens the store in the data directory `root`, creating `bootstrap/` owner-only.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be created.
    pub fn open(root: &Path) -> Result<Self, String> {
        let dir = root.join(super::BOOTSTRAP);
        super::create_private_dir(&dir)?;
        Ok(FsBootstrapStore { dir })
    }

    fn named(&self, id: &CertId, extension: &str) -> Result<PathBuf, String> {
        // An issuer hash and a serial are hex the Server wrote; anything else never names a file.
        let hex = |value: &str| !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex(&id.issuer) || !hex(&id.serial) {
            return Err(format!(
                "{}/{} is not an issuer and a serial",
                id.issuer, id.serial
            ));
        }
        Ok(self.dir.join(format!(
            "{}.{extension}",
            super::revocation::cert_file_stem(id)
        )))
    }
}

impl BootstrapStore for FsBootstrapStore {
    /// Every `<issuer>-<serial>.json`; a `.p12` file is accepted only beside the entry it belongs
    /// to, and anything else in the directory fails the load naming it.
    fn load(&self) -> Result<Vec<Entry>, String> {
        let listed = super::entries(&self.dir)?;
        let mut loaded = Vec::new();
        let mut stems = std::collections::BTreeSet::new();
        for (name, path) in &listed {
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let entry: Entry = serde_json::from_str(&text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            if super::revocation::cert_file_stem(&entry.id) != stem {
                return Err(super::misnamed(path, "issuer and serial"));
            }
            stems.insert(stem.to_string());
            loaded.push(entry);
        }
        for (name, path) in &listed {
            let known = name.strip_suffix(".json").is_some()
                || name
                    .strip_suffix(".p12")
                    .is_some_and(|stem| stems.contains(stem));
            if !known || !path.is_file() {
                return Err(super::unknown(path));
            }
        }
        Ok(loaded)
    }

    fn put(&self, entry: &Entry) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(entry).expect("a bootstrap entry serializes");
        super::replace_owner_only(&self.named(&entry.id, "json")?, &json)
    }

    fn remove(&self, id: &CertId) -> Result<(), String> {
        super::remove_file(&self.named(id, "p12")?)?;
        super::remove_file(&self.named(id, "json")?)
    }

    fn put_p12(&self, id: &CertId, file: &[u8]) -> Result<(), String> {
        super::replace_owner_only(&self.named(id, "p12")?, file)
    }

    fn p12(&self, id: &CertId) -> Result<Option<Vec<u8>>, String> {
        let path = self.named(id, "p12")?;
        match std::fs::read(&path) {
            Ok(file) => Ok(Some(file)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    fn remove_p12(&self, id: &CertId) -> Result<(), String> {
        super::remove_file(&self.named(id, "p12")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            id: CertId::new(b"issuer", "a1"),
            serial: "a1".to_string(),
            subject: "O=Kunde, CN=fleet bootstrap".to_string(),
            key_fingerprint: "00".to_string(),
            issued_ms: 1,
            not_after_ms: 2,
            ca_key: "ab".to_string(),
            p12: false,
        }
    }

    /// What was issued is still listed after a restart, under its issuer and serial, and a removal
    /// persists.
    /// Verifies: ADR-0037
    #[test]
    fn entries_survive_a_reopen_and_a_removal_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let entry = entry();
        let store = FsBootstrapStore::open(dir.path()).expect("open");
        store.put(&entry).expect("put");
        let stem = crate::fs::revocation::cert_file_stem(&entry.id);
        assert!(dir.path().join(format!("bootstrap/{stem}.json")).is_file());
        assert!(stem.ends_with("-a1") && stem.len() == 16 + 3, "{stem}");
        let reopened = FsBootstrapStore::open(dir.path()).expect("reopen");
        assert_eq!(reopened.load().expect("load"), vec![entry.clone()]);
        reopened.remove(&entry.id).expect("remove");
        assert!(reopened.load().expect("load").is_empty());
        let mut path = entry.id.clone();
        path.serial = "../x".to_string();
        assert!(
            reopened.remove(&path).is_err(),
            "a serial never names a path"
        );
    }

    /// The PKCS#12 file lies beside its entry, owner-only, and goes with it; one beside no entry
    /// is no part of the layout.
    /// Verifies: ADR-0029, ADR-0037
    #[test]
    fn a_pkcs12_file_is_kept_owner_only_and_removed_with_its_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsBootstrapStore::open(dir.path()).expect("open");
        let entry = entry();
        let id = entry.id.clone();
        let other = CertId::new(b"issuer", "b2");
        store.put(&entry).expect("put");
        store.put_p12(&id, b"file").expect("put");
        assert_eq!(store.p12(&id).expect("read"), Some(b"file".to_vec()));
        assert_eq!(store.p12(&other).expect("read"), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let stem = crate::fs::revocation::cert_file_stem(&id);
            let mode = std::fs::metadata(dir.path().join(format!("bootstrap/{stem}.p12")))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "owner-only");
        }
        assert_eq!(store.load().expect("load").len(), 1, "a file is no entry");
        store.remove_p12(&id).expect("remove");
        assert_eq!(store.p12(&id).expect("read"), None);
        store.put_p12(&id, b"file").expect("put");
        store.remove(&id).expect("remove");
        assert_eq!(store.p12(&id).expect("read"), None, "gone with its entry");

        store.put_p12(&other, b"file").expect("put");
        let error = store.load().expect_err("a file beside no entry is refused");
        assert!(error.contains(".p12"), "{error}");
    }
}
