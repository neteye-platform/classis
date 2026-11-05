//! `server migrate-to-postgres` (ADR-0050 clause 15): an existing `data_dir` copied into
//! PostgreSQL while the Server is stopped.
//!
//! The database is checked first: it must hold none of the Server's tables, and nothing is created
//! before it has been found so. Every record of the old `data_dir` is then read through the
//! filesystem adapters — from a copy, since they repair what they open — so a record that would
//! fail a Server's startup fails here before anything is written. The audit record and, with the
//! filesystem blob store, the blobs are copied byte for byte into the new `data_dir`; then the
//! schema and every record are written in one transaction, so a copy that fails leaves the
//! database without the Server's tables, and the new `data_dir` as empty as it was. The old
//! `data_dir` is only read — no directory created, no mode changed, no file removed: it stays as
//! the backup. Moving records back from PostgreSQL to files is not provided.

use std::collections::HashMap;
use std::path::Path;

use opamp::uid::InstanceUid;

use super::{client, schema, sql, Database, IMPORT_TIMEOUT};
use crate::agent_store::{AgentStore as _, PersistedAgent};
use crate::blobs::BlobStore as _;
use crate::bootstrap::{BootstrapStore as _, Entry as BootstrapEntry};
use crate::config::PostgresConfig;
use crate::configs::{ConfigBackend as _, Configuration};
use crate::deployments::{Deployment, DeploymentBackend as _};
use crate::enrolment::{EnrolmentStore as _, Persisted};
use crate::fs;
use crate::packages::{Package, PackageBackend as _};
use crate::revocation::{Ledger, LedgerStore as _};

/// What the copy carried, one line per kind, for the operator to read.
#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
}

/// Every record of a `data_dir`, as its filesystem adapters read it.
struct Records {
    configurations: Vec<Configuration>,
    deployments: Vec<Deployment>,
    packages: Vec<Package>,
    agents: HashMap<InstanceUid, PersistedAgent>,
    ledger: Ledger,
    bootstrap: Vec<(BootstrapEntry, Option<Vec<u8>>)>,
    enrolment: Option<Persisted>,
}

impl Records {
    /// Reads every record under `root` through the filesystem adapters, as a Server's startup does.
    fn read(root: &Path) -> Result<Self, String> {
        let bootstrap_store = fs::FsBootstrapStore::open(root)?;
        let mut bootstrap = Vec::new();
        for entry in bootstrap_store.load()? {
            let file = bootstrap_store.p12(&entry.id)?;
            bootstrap.push((entry, file));
        }
        Ok(Records {
            configurations: fs::FsConfigBackend::open(root)?.load()?,
            deployments: fs::FsDeploymentBackend::open(root)?.load()?,
            packages: fs::FsPackageBackend::open(root)?.load()?,
            agents: fs::FsAgentStore::open(root)?.load()?,
            ledger: fs::FsLedgerStore::open(root)?.load()?,
            bootstrap,
            enrolment: fs::FsEnrolmentStore::open(root).load()?,
        })
    }

    fn lines(&self) -> Vec<String> {
        let revisions: usize = self
            .configurations
            .iter()
            .map(|config| config.retained.len())
            .sum();
        let p12 = self
            .bootstrap
            .iter()
            .filter(|(_, file)| file.is_some())
            .count();
        vec![
            format!(
                "{} configurations with {revisions} retained revisions",
                self.configurations.len()
            ),
            format!("{} deployments", self.deployments.len()),
            format!("{} packages", self.packages.len()),
            format!("{} agents", self.agents.len()),
            format!("{} hosts", self.ledger.hosts.len()),
            format!("{} certificates in the register", self.ledger.issued.len()),
            format!("{} revocations", self.ledger.revocations.len()),
            format!(
                "{} bootstrap certificates, {p12} with a PKCS#12 file",
                self.bootstrap.len()
            ),
            format!(
                "the enrolment window and {} pending requests",
                self.enrolment.as_ref().map_or(0, |persisted| {
                    serde_json::to_value(persisted)
                        .ok()
                        .and_then(|value| value.get("requests")?.as_array().map(Vec::len))
                        .unwrap_or(0)
                })
            ),
        ]
    }

    /// Writes every record inside the caller's transaction.
    async fn write(self, client: &impl tokio_postgres::GenericClient) -> Result<(), String> {
        for configuration in &self.configurations {
            super::configs::write(client, configuration).await?;
        }
        for deployment in &self.deployments {
            super::deployments::write(client, deployment).await?;
        }
        for package in &self.packages {
            super::packages::write(client, package).await?;
        }
        for (uid, record) in &self.agents {
            super::agents::write(client, uid, record).await?;
        }
        for issued in &self.ledger.issued {
            super::ledger::write_issued(client, issued).await?;
        }
        let revocations: Vec<(i32, crate::revocation::Revocation)> = self
            .ledger
            .revocations
            .into_iter()
            .enumerate()
            .map(|(position, entry)| (i32::try_from(position).expect("the list is bounded"), entry))
            .collect();
        super::ledger::write_revocations(client, &revocations).await?;
        for (host, entry) in &self.ledger.hosts {
            super::ledger::write_host(client, host, entry).await?;
        }
        for (entry, file) in &self.bootstrap {
            super::bootstrap::write(client, entry, file.as_deref()).await?;
        }
        if let Some(enrolment) = &self.enrolment {
            super::enrolment::write(client, enrolment).await?;
        }
        Ok(())
    }
}

/// Copies the `data_dir` `from` into the database `config` names and the new, empty `data_dir`
/// `to` (ADR-0050 clause 15). `filesystem_blobs` copies `blobs/` too, as the filesystem blob store
/// keeps the artifacts there.
///
/// # Errors
/// Returns an error naming what could not be read or copied, when `to` is not empty, and when the
/// database holds any of the Server's tables; the database then holds none of them.
pub fn run(
    from: &Path,
    to: &Path,
    config: &PostgresConfig,
    filesystem_blobs: bool,
) -> Result<Report, String> {
    run_in(from, to, config, filesystem_blobs, None)
}

/// [`run`] in the schema `schema` rather than the role's default.
pub(crate) fn run_in(
    from: &Path,
    to: &Path,
    config: &PostgresConfig,
    filesystem_blobs: bool,
    schema: Option<&str>,
) -> Result<Report, String> {
    // Nothing is created or changed before the database has been found without the Server's
    // tables, and the old data_dir is only ever read (clause 15).
    if !from.is_dir() {
        return Err(format!("{} is not a data directory", from.display()));
    }
    let existed = to.exists();
    if existed {
        let empty = std::fs::read_dir(to)
            .map_err(|e| format!("cannot read {}: {e}", to.display()))?
            .next()
            .is_none();
        if !empty {
            return Err(format!(
                "{} is not empty — name a new, empty directory as --data-dir",
                to.display()
            ));
        }
    }
    let database = Database::connect(config, schema)?;
    let tables = database.server_tables()?;
    if !tables.is_empty() {
        return Err(format!(
            "the {} already holds the Server's tables ({}) — copy into a database without them",
            database.name(),
            tables.join(", ")
        ));
    }
    let copied = copy(from, to, &database, filesystem_blobs);
    if copied.is_err() {
        // `to` was empty or absent, so whatever is in it now is this copy's.
        let _ = if existed {
            std::fs::read_dir(to).map(|entries| {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let _ = if path.is_dir() {
                        std::fs::remove_dir_all(&path)
                    } else {
                        std::fs::remove_file(&path)
                    };
                }
            })
        } else {
            std::fs::remove_dir_all(to)
        };
    }
    copied
}

/// The copy itself, once the database has been checked. The records are read from a copy of the
/// old `data_dir` made inside `to`: the filesystem adapters create what is missing, remove a
/// leftover temporary file and rewrite what they drop, as a Server's startup does, and the old
/// `data_dir` must not change in any way. The copy is removed once read; an error names the old
/// path, not the copy's.
fn copy(
    from: &Path,
    to: &Path,
    database: &Database,
    filesystem_blobs: bool,
) -> Result<Report, String> {
    fs::create_private_dir(to)?;
    let staging = to.join(STAGING);
    let named = |e: String| e.replace(&staging.display().to_string(), &from.display().to_string());
    copy_records(from, &staging)?;
    let records = fs::check_layout(&staging)
        .and_then(|()| Records::read(&staging))
        .map_err(named);
    std::fs::remove_dir_all(&staging)
        .map_err(|e| format!("cannot remove {}: {e}", staging.display()))?;
    let records = records?;

    let mut report = Report::default();
    let audit = from.join(fs::AUDIT);
    let audit_files = if audit.is_dir() {
        fs::audit_files(&audit)?
    } else {
        Vec::new()
    };
    fs::create_private_dir(&to.join(fs::AUDIT))?;
    for file in &audit_files {
        let name = file.file_name().expect("a file in the audit directory");
        copy_file(file, &to.join(fs::AUDIT).join(name))?;
    }
    report
        .lines
        .push(format!("{} audit files, unchanged", audit_files.len()));
    if filesystem_blobs {
        let blobs = from.join(fs::BLOBS);
        let target = to.join(fs::BLOBS);
        fs::create_private_dir(&target)?;
        if blobs.is_dir() {
            for (name, path) in read_dir(&blobs)? {
                // What a crash left of an upload is no blob, and stays where it is.
                if name.ends_with(".tmp") && path.is_file() {
                    continue;
                }
                if !path.is_file() {
                    return Err(fs::unknown(&path));
                }
                copy_file(&path, &target.join(&name))?;
            }
        }
        // Each copy is hashed against its name, as a Server's startup hashes every blob.
        let listed = fs::FsBlobStore::open(to)
            .and_then(|store| store.list())
            .map_err(|e| e.replace(&target.display().to_string(), &blobs.display().to_string()))?;
        report.lines.push(format!("{} blobs", listed.len()));
    }

    let lines = records.lines();
    let ours = schema::server_version();
    database
        .run_within(IMPORT_TIMEOUT, move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            schema::apply(&*transaction, schema::MIGRATIONS, ours).await?;
            records.write(&*transaction).await?;
            transaction.commit().await.map_err(sql)
        })
        .map_err(|e| {
            format!(
                "{e} — nothing was written into the database or into {}; run the copy again",
                to.display()
            )
        })?;
    report.lines.extend(lines);
    Ok(report)
}

/// Where inside the new `data_dir` the records of the old one are copied to be read.
const STAGING: &str = ".records-being-copied";

/// Copies every entry of the data directory `from` into `to`, but for the files of `audit/` and
/// `blobs/`, which are copied on their own: the layout as it stands, read and nothing else.
fn copy_records(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_private_dir(to)?;
    for (name, path) in read_dir(from)? {
        let target = to.join(&name);
        if path.is_dir() {
            fs::create_private_dir(&target)?;
            if name != fs::AUDIT && name != fs::BLOBS {
                copy_tree(&path, &target)?;
            }
        } else {
            copy_file(&path, &target)?;
        }
    }
    Ok(())
}

/// Copies the directory `from` into the existing directory `to`, every level of it.
fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    for (name, path) in read_dir(from)? {
        let target = to.join(&name);
        if path.is_dir() {
            fs::create_private_dir(&target)?;
            copy_tree(&path, &target)?;
        } else {
            copy_file(&path, &target)?;
        }
    }
    Ok(())
}

/// The entries of `dir` by name, read and nothing else. A name that is not UTF-8 is refused, as
/// the layout refuses it.
fn read_dir(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    let mut found = Vec::new();
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(fs::unknown(&path));
        };
        found.push((name.to_string(), path.clone()));
    }
    found.sort();
    Ok(found)
}

/// Copies one file byte for byte into a new owner-only file.
fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    let mut source =
        std::fs::File::open(from).map_err(|e| format!("cannot read {}: {e}", from.display()))?;
    let mut target = fs::create_owner_only(to)?;
    std::io::copy(&mut source, &mut target)
        .and_then(|_| target.sync_all())
        .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::audit::{Audit as _, Entry};
    use crate::postgres::testing::TestDatabase;
    use crate::revocation::{CertId, Facts, Host, Issued, Revocation, Revoked, SubjectValues};

    /// Every path under `root` with its mode and, for a file, its bytes: what "unchanged" is
    /// checked against — a directory created or removed, a mode changed, a file removed or
    /// rewritten all show.
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Option<Vec<u8>>)> {
        let mode = |path: &Path| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::metadata(path).expect("meta").permissions().mode()
            }
            #[cfg(not(unix))]
            {
                u32::from(
                    std::fs::metadata(path)
                        .expect("meta")
                        .permissions()
                        .readonly(),
                )
            }
        };
        let mut files = BTreeMap::from([(root.to_path_buf(), (mode(root), None))]);
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("read") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    files.insert(path.clone(), (mode(&path), None));
                    dirs.push(path);
                } else {
                    let bytes = std::fs::read(&path).expect("read");
                    files.insert(path.clone(), (mode(&path), Some(bytes)));
                }
            }
        }
        files
    }

    /// What a Server's startup would repair in `root`, and the copy must leave as it is: a
    /// directory of the layout missing, a temporary file a crash left beside a record and at the
    /// root, and a directory whose mode is not the Server's.
    fn unrepaired(root: &Path) {
        std::fs::remove_dir_all(root.join(fs::HOSTS)).expect("no hosts/");
        std::fs::write(root.join("revocations.json.tmp"), "[").expect("leftover");
        let agent = fs::json_files(&root.join(fs::AGENTS)).expect("agents")[0]
            .1
            .clone();
        let mut leftover = agent.into_os_string();
        leftover.push(".tmp");
        std::fs::write(leftover, "{").expect("leftover");
        std::fs::write(root.join(fs::BLOBS).join("upload-1-0.tmp"), "half").expect("leftover");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                root.join(fs::CONFIGURATIONS),
                std::fs::Permissions::from_mode(0o750),
            )
            .expect("chmod");
        }
    }

    /// A `data_dir` holding at least one record of every kind, written through the filesystem
    /// adapters as a Server writes it, with an audit record of three entries.
    fn fixture(root: &Path) {
        fs::open_data_dir(root, true).expect("open");
        let pinned = crate::configs::Revision {
            body: "receivers: {}\n".to_string(),
            role: String::new(),
            service_name: "otelcol".to_string(),
        };
        let hash = crate::configs::revision_hash(&pinned);
        fs::FsConfigBackend::open(root)
            .expect("open")
            .put(&Configuration {
                name: "base".to_string(),
                saved: pinned.clone(),
                retained: BTreeMap::from([(hash.clone(), pinned)]),
            })
            .expect("configuration");
        let id = crate::packages::PackageId::new("otelcol", "1.2.3").expect("id");
        fs::FsDeploymentBackend::open(root)
            .expect("open")
            .put(&Deployment {
                name: "stable".to_string(),
                selector: BTreeMap::from([("fleet.ring".to_string(), "stable".to_string())]),
                packages: BTreeMap::from([(id.agent_type.clone(), id.clone())]),
                configurations: BTreeSet::from(["base".to_string()]),
            })
            .expect("deployment");
        let (sha256, size) = fs::FsBlobStore::open(root)
            .expect("open")
            .put(&mut &b"the artifact"[..])
            .expect("blob");
        let platform = crate::packages::Platform::new("linux", "amd64").expect("platform");
        fs::FsPackageBackend::open(root)
            .expect("open")
            .put(&Package {
                id: id.clone(),
                entries: BTreeMap::from([(
                    platform.clone(),
                    crate::packages::Entry {
                        platform,
                        content_hash: hex::decode(&sha256).expect("hex"),
                        size,
                        signature: Some(vec![7; 64]),
                    },
                )]),
            })
            .expect("package");
        let mut agent = crate::agent_store::tests::record();
        if let Some(assignment) = agent.assignment.as_mut() {
            assignment.configurations = BTreeMap::from([("base".to_string(), hash)]);
            assignment.package = Some(id);
        }
        fs::FsAgentStore::open(root)
            .expect("open")
            .put(&InstanceUid::default(), &agent)
            .expect("agent");
        let ledger = fs::FsLedgerStore::open(root).expect("open");
        let issued = Issued {
            facts: Facts {
                id: CertId::new(b"ca", "0a"),
                issuer_name: "CN=ca".into(),
                subject: "CN=edge-01".into(),
                key_fingerprint: "k".into(),
                not_after_ms: 9,
                host: Some("0192f0c4-host".into()),
                subject_values: SubjectValues::default(),
            },
            instance_uid: "00".into(),
            predecessor: None,
            issued_ms: 1,
        };
        ledger.put_issued(&issued).expect("issued");
        ledger
            .save_revocations(&[Revocation {
                id: "r1".into(),
                revoked: Revoked::Certificate {
                    authority: "client".into(),
                    issuers: vec![issued.facts.id.issuer.clone()],
                    serial: "0b".into(),
                },
                revoked_ms: 2,
            }])
            .expect("revocations");
        ledger
            .save_hosts(&BTreeMap::from([(
                "0192f0c4-host".to_string(),
                Host {
                    instance_uids: BTreeSet::from(["00".to_string()]),
                    ..Host::default()
                },
            )]))
            .expect("hosts");
        fs::FsBootstrapStore::open(root)
            .expect("open")
            .put_with_p12(
                &BootstrapEntry {
                    id: CertId::new(b"bootstrap", "b1"),
                    serial: "b1".into(),
                    subject: "CN=fleet bootstrap".into(),
                    key_fingerprint: "00".into(),
                    issued_ms: 1,
                    not_after_ms: 2,
                    ca_key: "ab".into(),
                    p12: true,
                },
                b"the PKCS#12 file",
            )
            .expect("bootstrap");
        fs::FsEnrolmentStore::open(root)
            .save(
                &serde_json::from_value(serde_json::json!({"window_until_ms": 99, "requests": []}))
                    .expect("window"),
            )
            .expect("enrolment");
        let audit = crate::audit_log::AuditLog::start(
            Box::new(fs::FsAuditStore::open(root).expect("open")),
            crate::audit_log::Limits::default(),
            Arc::new(crate::clock::SystemClock),
        )
        .expect("audit");
        for n in 0..3 {
            audit
                .record(Entry::new("test.event", "ok").with("n", n.to_string()))
                .expect("record");
        }
        assert!(audit.drain(std::time::Duration::from_secs(5)));
    }

    /// How many entries the chain in `dir` holds, verified.
    fn verified(dir: &Path) -> Result<u64, String> {
        let mut texts = Vec::new();
        for file in fs::audit_files(dir)? {
            texts.push((
                file.display().to_string(),
                std::fs::read_to_string(&file).expect("read"),
            ));
        }
        crate::audit_log::verify(texts.iter().flat_map(|(name, text)| {
            text.lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
                .map(move |(index, line)| (format!("{name}:{index}"), line))
        }))
    }

    /// The copy over a fixture `data_dir` carries every record into the database and the audit
    /// record and the blobs into the new `data_dir`, keeps the chain verifiable, leaves the old
    /// `data_dir` unchanged, and refuses a database that holds the Server's tables and a
    /// `--data-dir` that is not empty (ADR-0050 clause 15).
    /// Verifies: ADR-0050
    #[test]
    fn migrate_to_postgres_carries_every_record_and_leaves_the_old_data_dir() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let (old, new) = (dir.path().join("old"), dir.path().join("new"));
        fixture(&old);
        std::fs::remove_dir_all(old.join(fs::HOSTS)).expect("no hosts/");
        // Read before the old data_dir is made unrepaired: the adapters would repair it.
        let expected = Records::read(&old).expect("read");
        unrepaired(&old);
        let before = snapshot(&old);

        std::fs::create_dir(&new).expect("mkdir");
        std::fs::write(new.join("stray"), "x").expect("write");
        let err =
            run_in(&old, &new, &test.config(), true, Some(&test.schema)).expect_err("not empty");
        assert!(err.contains("not empty"), "{err}");
        std::fs::remove_file(new.join("stray")).expect("rm");
        assert_eq!(snapshot(&old), before, "a refused copy changes nothing");

        let report = run_in(&old, &new, &test.config(), true, Some(&test.schema)).expect("copy");
        assert!(
            report.lines.iter().any(|line| line == "1 agents"),
            "{report:?}"
        );
        assert!(report
            .lines
            .iter()
            .any(|line| line == "3 audit files, unchanged"
                || line.ends_with("audit files, unchanged")));
        assert_eq!(snapshot(&old), before, "the old data_dir is unchanged");

        let database = test.open();
        let records = crate::Records::Postgres(database);
        assert_eq!(
            records.configs().expect("c").load().expect("load"),
            expected.configurations
        );
        assert_eq!(
            records.deployments().expect("d").load().expect("load"),
            expected.deployments
        );
        assert!(records.agents().expect("a").load().expect("load") == expected.agents);
        assert_eq!(
            records.ledger().expect("l").load().expect("load"),
            expected.ledger
        );
        let bootstrap = records.bootstrap().expect("b");
        let entries = bootstrap.load().expect("load");
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.clone(), bootstrap.p12(&entry.id).expect("p12")))
                .collect::<Vec<_>>(),
            expected.bootstrap
        );
        assert_eq!(
            records.enrolment().load().expect("load"),
            expected.enrolment
        );
        let packages = records.packages().expect("p").load().expect("load");
        // Every Package whole: its identity and each entry's platform, hash, size and signature.
        let shown = |packages: &[Package]| -> Vec<_> {
            packages
                .iter()
                .map(|package| {
                    let entries: Vec<_> = package
                        .entries
                        .iter()
                        .map(|(platform, entry)| {
                            (
                                platform.tag(),
                                entry.platform.tag(),
                                hex::encode(&entry.content_hash),
                                entry.size,
                                entry.signature.clone(),
                            )
                        })
                        .collect();
                    (package.id.to_string(), entries)
                })
                .collect()
        };
        assert_eq!(shown(&packages), shown(&expected.packages));
        assert!(
            shown(&packages)[0].1[0].4.is_some(),
            "the fixture's entry carries a signature"
        );
        let state_packages = crate::packages::PackageStore::open_on(
            &records,
            &new,
            &crate::config::BlobsConfig::default(),
        )
        .expect("every entry finds its blob in the new data_dir");
        assert!(!state_packages.is_empty());

        assert_eq!(
            verified(&new.join(fs::AUDIT)),
            verified(&old.join(fs::AUDIT))
        );
        assert!(verified(&new.join(fs::AUDIT)).expect("the chain holds") >= 3);
        for file in fs::audit_files(&old.join(fs::AUDIT)).expect("files") {
            let copied = new.join(fs::AUDIT).join(file.file_name().expect("name"));
            assert_eq!(
                std::fs::read(&copied).expect("read"),
                std::fs::read(&file).expect("read")
            );
        }
        drop((records, state_packages, bootstrap));

        // The lock goes with its session, which the server notices once the connection closes.
        let again = dir.path().join("again");
        let mut err = String::new();
        for _ in 0..50 {
            err = run_in(&old, &again, &test.config(), true, Some(&test.schema))
                .expect_err("the tables are there");
            if !err.contains("one Server per database") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(err.contains("already holds the Server's tables"), "{err}");
        assert!(err.contains("agents"), "{err}");
        assert!(
            !again.exists(),
            "nothing is created before the database is checked"
        );
        assert_eq!(snapshot(&old), before, "the old data_dir is unchanged");
    }

    /// The database is checked before anything is touched: one that cannot be reached leaves the
    /// old `data_dir` as it was — no directory created, no mode changed, no leftover removed — and
    /// creates no new one (ADR-0050 clause 15). Needs no database.
    /// Verifies: ADR-0050
    #[test]
    fn a_copy_checks_the_database_before_it_touches_anything() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (old, new) = (dir.path().join("old"), dir.path().join("new"));
        fixture(&old);
        unrepaired(&old);
        let before = snapshot(&old);
        let password = dir.path().join("password");
        std::fs::write(&password, "secret").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        // A port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free port")
            .port();
        let config = PostgresConfig {
            host: "127.0.0.1".to_string(),
            port,
            dbname: "fleet".to_string(),
            user: "fleet".to_string(),
            password_file: password,
            ca_file: None,
            tls: false,
        };
        let err = run(&old, &new, &config, true).expect_err("nothing listens");
        assert!(err.contains(&format!("127.0.0.1:{port}")), "{err}");
        assert_eq!(snapshot(&old), before, "the old data_dir is unchanged");
        assert!(!new.exists(), "no new data_dir");
    }

    /// A copy that fails part-way through its transaction leaves the database without the
    /// Server's tables and the new `data_dir` empty. The failure is an object in the way of the
    /// schema's last table — no table, so the copy starts, and the first tables are created before
    /// the statement fails.
    /// Verifies: ADR-0050
    #[test]
    fn a_copy_that_fails_leaves_the_database_without_the_servers_tables() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let old = dir.path().join("old");
        fixture(&old);
        test.sql("CREATE TYPE enrolment_requests AS (id text)");
        let new = dir.path().join("new");
        let err = run_in(&old, &new, &test.config(), true, Some(&test.schema))
            .expect_err("the last table cannot be created");
        assert!(
            err.contains("nothing was written into the database"),
            "{err}"
        );
        let database = crate::postgres::Database::connect(&test.config(), Some(&test.schema))
            .expect("connect");
        assert!(database.server_tables().expect("tables").is_empty());
        assert!(!new.exists(), "the new data_dir is left as it was: absent");
    }
}
