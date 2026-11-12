//! The register, the revocation list and the Hosts on the filesystem (ADR-0021, ADR-0035,
//! ADR-0037): the default adapter behind [`LedgerStore`](crate::revocation::LedgerStore).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::revocation::{CertId, Host, Issued, Ledger, LedgerStore, Revocation};

/// Three places in the data directory, each owner-only: the register in `certificates/`, one file
/// per certificate, so a renewal writes one small file; the list in `revocations.json`; and the
/// Hosts in `hosts/`, one file per Host. Every file is replaced in one step, and synced before the
/// decision it answers is.
pub struct FsLedgerStore {
    certificates: PathBuf,
    revocations: PathBuf,
    hosts: PathBuf,
    /// The Hosts as last written, so a write of the Hosts touches only the files that changed.
    written_hosts: Mutex<BTreeMap<String, Host>>,
}

/// One Host as persisted: `hosts/<host>.json`, its name inside so the file name can be checked
/// against it.
#[derive(Serialize, Deserialize)]
struct HostFile {
    host: String,
    #[serde(flatten)]
    entry: Host,
}

/// The file name of a certificate: the first 16 hex characters of its issuer's name hash, and its
/// serial (ADR-0037 clause 2).
pub(crate) fn cert_file_stem(id: &CertId) -> String {
    format!("{}-{}", &id.issuer[..16.min(id.issuer.len())], id.serial)
}

/// The file stem of a Host. A Host is whatever a certificate's host URI names, so a byte outside
/// `[A-Za-z0-9._-]` — and a leading dot — is written as `%XX`, which no such name holds.
pub(crate) fn host_file_stem(host: &str) -> String {
    let mut stem = String::with_capacity(host.len());
    for (i, byte) in host.bytes().enumerate() {
        let plain =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') || (byte == b'.' && i > 0);
        if plain {
            stem.push(char::from(byte));
        } else {
            stem.push_str(&format!("%{byte:02X}"));
        }
    }
    stem
}

impl FsLedgerStore {
    /// Opens the store in the data directory `root`, creating `certificates/` and `hosts/`
    /// owner-only.
    ///
    /// # Errors
    /// Returns an error when a directory cannot be created.
    pub fn open(root: &Path) -> Result<Self, String> {
        let certificates = root.join(super::CERTIFICATES);
        let hosts = root.join(super::HOSTS);
        super::create_private_dir(&certificates)?;
        super::create_private_dir(&hosts)?;
        Ok(FsLedgerStore {
            certificates,
            revocations: root.join(super::REVOCATIONS),
            hosts,
            written_hosts: Mutex::new(BTreeMap::new()),
        })
    }

    fn path(&self, id: &CertId) -> PathBuf {
        self.certificates
            .join(format!("{}.json", cert_file_stem(id)))
    }

    fn host_path(&self, host: &str) -> PathBuf {
        self.hosts.join(format!("{}.json", host_file_stem(host)))
    }

    /// The list as persisted, without the credential entries a list may still hold: the Agent
    /// plane admits by client certificate alone, so there is no credential to revoke (ADR-0021
    /// clause 5). They are dropped with one log line, and the list is written back without them.
    fn certificate_revocations(&self, bytes: &[u8]) -> Result<Vec<Revocation>, String> {
        let parse =
            |e: serde_json::Error| format!("cannot parse {}: {e}", self.revocations.display());
        let mut entries: Vec<serde_json::Value> = serde_json::from_slice(bytes).map_err(parse)?;
        let before = entries.len();
        entries.retain(|entry| entry.pointer("/revoked/credential").is_none());
        let dropped = before - entries.len();
        let revocations = entries
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<Revocation>, _>>()
            .map_err(parse)?;
        if dropped > 0 {
            tracing::warn!(
                dropped,
                file = %self.revocations.display(),
                "dropped credential revocations: the Agent plane admits by client certificate alone"
            );
            self.save_revocations(&revocations)?;
        }
        Ok(revocations)
    }

    fn load_hosts(&self) -> Result<BTreeMap<String, Host>, String> {
        let mut hosts = BTreeMap::new();
        for (stem, path) in super::json_files(&self.hosts)? {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let file: HostFile = serde_json::from_slice(&bytes)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            if host_file_stem(&file.host) != stem {
                return Err(super::misnamed(&path, "host"));
            }
            hosts.insert(file.host, file.entry);
        }
        Ok(hosts)
    }
}

impl LedgerStore for FsLedgerStore {
    fn load(&self) -> Result<Ledger, String> {
        let mut issued = Vec::new();
        for (stem, path) in super::json_files(&self.certificates)? {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let entry = serde_json::from_slice::<Issued>(&bytes)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            if cert_file_stem(&entry.facts.id) != stem {
                return Err(super::misnamed(&path, "issuer and serial"));
            }
            issued.push(entry);
        }
        let revocations = match std::fs::read(&self.revocations) {
            Ok(bytes) => self.certificate_revocations(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("cannot read {}: {e}", self.revocations.display())),
        };
        let hosts = self.load_hosts()?;
        hosts.clone_into(&mut self.written_hosts.lock().expect("hosts lock"));
        Ok(Ledger {
            issued,
            revocations,
            hosts,
        })
    }

    fn put_issued(&self, issued: &Issued) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(issued).expect("a register entry serializes");
        super::replace_owner_only(&self.path(&issued.facts.id), &json)
    }

    fn remove_issued(&self, id: &CertId) -> Result<(), String> {
        super::remove_file(&self.path(id))
    }

    /// Writes each Host that changed since the last write, and removes each one that is gone.
    fn save_hosts(&self, hosts: &BTreeMap<String, Host>) -> Result<(), String> {
        let mut written = self.written_hosts.lock().expect("hosts lock");
        for (host, entry) in hosts {
            if written.get(host) == Some(entry) {
                continue;
            }
            let json = serde_json::to_vec_pretty(&HostFile {
                host: host.clone(),
                entry: entry.clone(),
            })
            .expect("a Host serializes");
            super::replace_owner_only(&self.host_path(host), &json)?;
            written.insert(host.clone(), entry.clone());
        }
        let gone: Vec<String> = written
            .keys()
            .filter(|host| !hosts.contains_key(*host))
            .cloned()
            .collect();
        for host in gone {
            super::remove_file(&self.host_path(&host))?;
            written.remove(&host);
        }
        Ok(())
    }

    fn save_revocations(&self, revocations: &[Revocation]) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(revocations).expect("the list serializes");
        super::replace_owner_only(&self.revocations, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::{Facts, Revoked};

    /// Verifies: ADR-0021
    #[test]
    fn the_ledger_survives_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsLedgerStore::open(dir.path()).expect("open");
        let issued = Issued {
            facts: Facts {
                id: CertId::new(b"ca", "0a"),
                issuer_name: "CN=ca".into(),
                subject: "CN=edge-01".into(),
                key_fingerprint: "k".into(),
                not_after_ms: 9,
                host: None,
                subject_values: crate::revocation::SubjectValues {
                    organization: "Kunde GmbH".into(),
                    ..Default::default()
                },
            },
            instance_uid: "00".into(),
            predecessor: None,
            issued_ms: 1,
        };
        store.put_issued(&issued).expect("put");
        let revocation = Revocation {
            id: "x".into(),
            revoked: Revoked::Certificate {
                authority: "client".into(),
                issuers: vec![issued.facts.id.issuer.clone()],
                serial: "0a".into(),
            },
            revoked_ms: 2,
        };
        store
            .save_revocations(std::slice::from_ref(&revocation))
            .expect("save");
        let reopened = FsLedgerStore::open(dir.path()).expect("open");
        let ledger = reopened.load().expect("load");
        assert_eq!(ledger.issued, vec![issued.clone()]);
        assert_eq!(ledger.revocations, vec![revocation]);
        reopened.remove_issued(&issued.facts.id).expect("remove");
        assert!(reopened.load().expect("load").issued.is_empty());
    }

    /// Each Host is a file of its own, written when it changes and removed when it goes; a name
    /// no Host maps to is escaped, and a file whose name disagrees with what it holds — or one
    /// the layout does not name — fails the load naming it.
    /// Verifies: ADR-0037
    #[test]
    fn each_host_is_a_file_of_its_own_and_its_name_must_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsLedgerStore::open(dir.path()).expect("open");
        let mut hosts = BTreeMap::from([
            ("0192f0c4-a".to_string(), Host::default()),
            ("../odd/Name".to_string(), Host::default()),
        ]);
        store.save_hosts(&hosts).expect("save");
        assert!(dir.path().join("hosts/0192f0c4-a.json").is_file());
        assert!(dir.path().join("hosts/%2E.%2Fodd%2FName.json").is_file());
        assert_eq!(
            FsLedgerStore::open(dir.path())
                .expect("open")
                .load()
                .expect("load")
                .hosts,
            hosts
        );

        hosts.remove("../odd/Name");
        store.save_hosts(&hosts).expect("save");
        assert!(!dir.path().join("hosts/%2E.%2Fodd%2FName.json").exists());

        std::fs::copy(
            dir.path().join("hosts/0192f0c4-a.json"),
            dir.path().join("hosts/other.json"),
        )
        .expect("copy");
        let error = store.load().expect_err("misnamed");
        assert!(error.contains("other.json"), "{error}");
        std::fs::remove_file(dir.path().join("hosts/other.json")).expect("clean");

        std::fs::write(dir.path().join("certificates/notes.txt"), "x").expect("stray");
        let error = store.load().expect_err("stray");
        assert!(error.contains("notes.txt"), "{error}");
    }

    /// A writer the log goes to, for a test to read back.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_persisted_credential_entry_is_dropped_on_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsLedgerStore::open(dir.path()).expect("open");
        let path = dir.path().join("revocations.json");
        std::fs::write(
            &path,
            r#"[
              {"id": "c1", "revoked": {"credential": {"sha256": "5eed"}}, "revoked_ms": 1},
              {"id": "a2", "revoked": {"certificate":
                {"authority": "client", "issuers": ["ab"], "serial": "a2"}}, "revoked_ms": 2},
              {"id": "c3", "revoked": {"credential": {"sha256": "beef"}}, "revoked_ms": 3}
            ]"#,
        )
        .expect("seed");

        let log = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let log = log.clone();
                move || log.clone()
            })
            .with_ansi(false)
            .finish();
        let ledger = tracing::subscriber::with_default(subscriber, || store.load()).expect("load");

        let certificate = Revocation {
            id: "a2".into(),
            revoked: Revoked::Certificate {
                authority: "client".into(),
                issuers: vec!["ab".into()],
                serial: "a2".into(),
            },
            revoked_ms: 2,
        };
        assert_eq!(ledger.revocations, vec![certificate.clone()]);
        let written = std::fs::read_to_string(&path).expect("read");
        assert!(
            !written.contains("credential"),
            "written back without it: {written}"
        );
        assert_eq!(
            store.load().expect("load again").revocations,
            vec![certificate]
        );
        let log = String::from_utf8(log.0.lock().expect("log lock").clone()).expect("utf-8");
        assert_eq!(
            log.lines().filter(|line| line.contains("dropped")).count(),
            1,
            "one log line: {log}"
        );
        assert!(log.contains("dropped=2"), "names the number dropped: {log}");
    }

    /// A Host file written before a Host had a valid until loads without one, and one written now
    /// keeps it across a reopen.
    /// Verifies: ADR-0047
    #[test]
    fn a_host_file_without_a_valid_until_still_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsLedgerStore::open(dir.path()).expect("open");
        std::fs::write(
            dir.path().join("hosts/h1.json"),
            r#"{"host":"h1","gateway":false,"instance_uids":["01"],"approved_ms":5}"#,
        )
        .expect("write");
        let mut hosts = store.load().expect("load").hosts;
        assert_eq!(hosts["h1"].valid_until_ms, None);
        assert_eq!(hosts["h1"].approved_ms, Some(5));

        hosts.get_mut("h1").expect("h1").valid_until_ms = Some(9);
        store.save_hosts(&hosts).expect("save");
        let reopened = FsLedgerStore::open(dir.path()).expect("open");
        assert_eq!(
            reopened.load().expect("load").hosts["h1"].valid_until_ms,
            Some(9)
        );
    }
}
