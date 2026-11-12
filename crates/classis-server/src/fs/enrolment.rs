//! The enrolment window and its queue on the filesystem (ADR-0037 clause 9): the default adapter
//! behind [`EnrolmentStore`](crate::enrolment::EnrolmentStore).

use std::path::{Path, PathBuf};

use crate::enrolment::{EnrolmentStore, Persisted};

/// `<data_dir>/enrolment.json`, owner-only, replaced in one step and synced before the act that
/// changed it is answered.
pub struct FsEnrolmentStore {
    path: PathBuf,
}

impl FsEnrolmentStore {
    /// The store in the data directory `root`.
    #[must_use]
    pub fn open(root: &Path) -> Self {
        FsEnrolmentStore {
            path: root.join(super::ENROLMENT),
        }
    }
}

impl EnrolmentStore for FsEnrolmentStore {
    fn load(&self) -> Result<Option<Persisted>, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("cannot parse {}: {e}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {}: {e}", self.path.display())),
        }
    }

    fn save(&self, persisted: &Persisted) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(persisted).expect("the enrolment serializes");
        super::replace_owner_only(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrolment::Enrolment;
    use std::sync::Arc;

    struct Fixed;
    impl crate::fleet::Clock for Fixed {
        fn now_ms(&self) -> u64 {
            1_000
        }
    }

    /// The window persists in `enrolment.json`, owner-only, and an Enrolment opened on it again
    /// finds it open; a file that does not parse fails the open naming it.
    /// Verifies: ADR-0037
    #[test]
    fn the_window_persists_in_enrolment_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enrolment = Enrolment::open_on(
            Arc::new(Fixed),
            Box::new(FsEnrolmentStore::open(dir.path())),
        )
        .expect("open");
        let until = enrolment.open(60).expect("open the window");
        let path = dir.path().join("enrolment.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let reopened = Enrolment::open_on(
            Arc::new(Fixed),
            Box::new(FsEnrolmentStore::open(dir.path())),
        )
        .expect("reopen");
        assert_eq!(reopened.window(), Some(until));

        std::fs::write(&path, "{").expect("corrupt");
        let error = Enrolment::open_on(
            Arc::new(Fixed),
            Box::new(FsEnrolmentStore::open(dir.path())),
        )
        .map(|_| ())
        .expect_err("refused");
        assert!(error.contains("enrolment.json"), "{error}");
    }
}
