//! The Agent-record store on the filesystem (ADR-0024): the default adapter behind
//! [`AgentStore`](crate::agent_store::AgentStore).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use opamp::uid::InstanceUid;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::agent_store::{AgentStore, PersistedAgent, Pin};
use crate::configs::Configuration;
use crate::fleet::{Assignment, Transport};
use crate::packages::PackageId;

/// The default adapter (ADR-0024, ADR-0037): one JSON file per Agent under `<data_dir>/agents/`,
/// owner-only — temp file plus atomic rename, loud failure on a file that does not parse or a name
/// that is not an Instance UID. A rollout's revisions go to `<data_dir>/configurations/` first
/// (ADR-0037 clause 3), and the integrity queries are answered from the assignments this adapter
/// last read or wrote.
pub struct FsAgentStore {
    dir: PathBuf,
    configurations: PathBuf,
    /// Every stored record's assignment, as on disk.
    assignments: Mutex<HashMap<InstanceUid, Assignment>>,
}

/// The on-disk envelope — **this adapter's format, not the port's**. Scalars and the
/// effective-config text stay readable; the wire-typed fields are protobuf bytes base64-inline,
/// the one encoding whose compatibility rules the Baseline already defines (ADR-0011, ADR-0024).
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// The envelope shape, so a future change can migrate deliberately.
    version: u32,
    sequence_num: u64,
    capabilities: u64,
    transport: String,
    last_seen_ms: u64,
    restart_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effective_config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    health: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_config_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection_settings_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_statuses: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    available_components: Option<String>,
    /// What the last rollout released to this Agent (ADR-0034 clause 5). Absent means nothing was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assignment: Option<AssignmentMeta>,
    /// The operator's labels (ADR-0035 clause 6). Absent means none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    /// The Host the Agent last arrived over (ADR-0035 clause 2). Absent means none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

/// One Agent's assignment as persisted: the Deployment, the Package as `<agent type>@<version>`,
/// and each Configuration's pinned revision hash.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentMeta {
    deployment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    configurations: BTreeMap<String, String>,
}

/// Version 4 carries the Agent's labels and the Host it last arrived over (ADR-0035 clauses 2 and
/// 6) beside ADR-0034's assignment shape, and there is **no reader for an earlier version**: an
/// envelope this Server did not write is named rather than guessed at.
const ENVELOPE_VERSION: u32 = 4;

fn encode<M: Message>(message: &Option<M>) -> Option<String> {
    message
        .as_ref()
        .map(|m| base64::engine::general_purpose::STANDARD.encode(m.encode_to_vec()))
}

fn decode<M: Message + Default>(field: &Option<String>, what: &str) -> Result<Option<M>, String> {
    field
        .as_ref()
        .map(|text| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|e| format!("{what} is not base64: {e}"))?;
            M::decode(bytes.as_slice()).map_err(|e| format!("{what} does not decode: {e}"))
        })
        .transpose()
}

impl Envelope {
    fn from_record(record: &PersistedAgent) -> Self {
        Envelope {
            version: ENVELOPE_VERSION,
            sequence_num: record.sequence_num,
            capabilities: record.capabilities,
            transport: record.transport.as_str().to_string(),
            last_seen_ms: record.last_seen_ms,
            restart_pending: record.restart_pending,
            effective_config: record.effective_config.clone(),
            description: encode(&record.description),
            health: encode(&record.health),
            remote_config_status: encode(&record.remote_config_status),
            connection_settings_status: encode(&record.connection_settings_status),
            package_statuses: encode(&record.package_statuses),
            available_components: encode(&record.available_components),
            assignment: record.assignment.as_ref().map(|assignment| AssignmentMeta {
                deployment: assignment.deployment.clone(),
                package: assignment.package.as_ref().map(PackageId::to_string),
                configurations: assignment.configurations.clone(),
            }),
            labels: record.labels.clone(),
            host: record.host.clone(),
        }
    }

    fn into_record(self) -> Result<PersistedAgent, String> {
        if self.version != ENVELOPE_VERSION {
            // Loud, and it stops the Server: an Agent record is what the fleet knows about a host,
            // and one silently skipped would look exactly like a host that never enrolled.
            return Err(format!(
                "envelope version {} is not the understood {ENVELOPE_VERSION} — this Server reads \
                 no other record format: since ADR-0035 an Agent record carries its labels and \
                 the Host it arrived over, and since ADR-0034 an assignment is one release per \
                 Agent, its Package and Configurations together. A data directory an older \
                 Server wrote is moved by `server migrate` (ADR-0037)",
                self.version
            ));
        }
        Ok(PersistedAgent {
            sequence_num: self.sequence_num,
            capabilities: self.capabilities,
            description: decode(&self.description, "description")?,
            health: decode(&self.health, "health")?,
            effective_config: self.effective_config,
            remote_config_status: decode(&self.remote_config_status, "remote_config_status")?,
            connection_settings_status: decode(
                &self.connection_settings_status,
                "connection_settings_status",
            )?,
            package_statuses: decode(&self.package_statuses, "package_statuses")?,
            available_components: decode(&self.available_components, "available_components")?,
            transport: Transport::parse(&self.transport),
            last_seen_ms: self.last_seen_ms,
            restart_pending: self.restart_pending,
            assignment: self
                .assignment
                .map(|assignment| {
                    let package = assignment
                        .package
                        .as_deref()
                        .map(PackageId::parse)
                        .transpose()
                        .map_err(|e| format!("invalid package in the assignment: {e}"))?;
                    Ok::<_, String>(crate::fleet::Assignment {
                        deployment: assignment.deployment,
                        package,
                        configurations: assignment.configurations,
                    })
                })
                .transpose()?,
            labels: self.labels,
            host: self.host,
        })
    }
}

impl FsAgentStore {
    /// Opens the store in the data directory `root`, creating `agents/` owner-only — reported
    /// effective configurations may hold credentials (ADR-0024), the same reasoning that guards
    /// every other store (ADR-0037 clause 1).
    pub fn open(root: &std::path::Path) -> Result<Self, String> {
        let dir = root.join(super::AGENTS);
        let configurations = root.join(super::CONFIGURATIONS);
        super::create_private_dir(&dir)?;
        super::create_private_dir(&configurations)?;
        Ok(FsAgentStore {
            dir,
            configurations,
            assignments: Mutex::new(HashMap::new()),
        })
    }

    /// Notes what `uid`'s stored record now pins.
    fn stored(&self, uid: &InstanceUid, assignment: Option<&Assignment>) {
        let mut assignments = self.assignments.lock().expect("assignments lock");
        match assignment {
            Some(assignment) => assignments.insert(*uid, assignment.clone()),
            None => assignments.remove(uid),
        };
    }

    fn path(&self, uid: &InstanceUid) -> PathBuf {
        self.dir.join(format!("{uid}.json"))
    }

    /// Puts the records a failed release wrote back as they were — the bytes, or no file — last
    /// first. One that cannot be put back stays as written, and so does what the store answers
    /// about it.
    fn put_back(&self, written: Vec<(InstanceUid, Option<Vec<u8>>, Option<Assignment>)>) {
        for (uid, previous, assignment) in written.into_iter().rev() {
            let path = self.path(&uid);
            let restored = match &previous {
                Some(bytes) => super::replace(&path, bytes),
                None => super::remove_file(&path),
            };
            match restored {
                Ok(()) => self.stored(&uid, assignment.as_ref()),
                Err(e) => tracing::warn!(
                    agent = %uid,
                    error = %e,
                    "a record a failed rollout wrote cannot be put back"
                ),
            }
        }
    }
}

impl AgentStore for FsAgentStore {
    fn load(&self) -> Result<HashMap<InstanceUid, PersistedAgent>, String> {
        let mut records = HashMap::new();
        for (stem, path) in super::json_files(&self.dir)? {
            let uid = InstanceUid::parse(&stem)
                .ok_or_else(|| format!("{} is not named after an Instance UID", path.display()))?;
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let envelope: Envelope = serde_json::from_str(&text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            let record = envelope
                .into_record()
                .map_err(|e| format!("cannot restore {}: {e}", path.display()))?;
            records.insert(uid, record);
        }
        *self.assignments.lock().expect("assignments lock") = records
            .iter()
            .filter_map(|(uid, record)| Some((*uid, record.assignment.clone()?)))
            .collect();
        Ok(records)
    }

    fn put(&self, uid: &InstanceUid, record: &PersistedAgent) -> Result<(), String> {
        let json =
            serde_json::to_vec_pretty(&Envelope::from_record(record)).expect("agent serialize");
        super::replace(&self.path(uid), &json)?;
        self.stored(uid, record.assignment.as_ref());
        Ok(())
    }

    fn remove(&self, uid: &InstanceUid) -> Result<(), String> {
        super::remove_file(&self.path(uid))?;
        self.stored(uid, None);
        Ok(())
    }

    /// The revisions first, then each record: a crash in between leaves revisions nothing
    /// references, which the next load collects (ADR-0037 clause 3). A record that cannot be
    /// written puts every record this call already wrote back as it was, so a failure leaves the
    /// records as they were; one that cannot be put back stays as written, and so does what the
    /// store answers about it.
    fn release(
        &self,
        revisions: &[Configuration],
        agents: &[(InstanceUid, PersistedAgent)],
    ) -> Result<(), String> {
        for configuration in revisions {
            super::configs::write(&self.configurations, configuration)?;
        }
        let mut written: Vec<(InstanceUid, Option<Vec<u8>>, Option<Assignment>)> = Vec::new();
        for (uid, record) in agents {
            let assignment = self
                .assignments
                .lock()
                .expect("assignments lock")
                .get(uid)
                .cloned();
            let path = self.path(uid);
            let step = match std::fs::read(&path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!("cannot read {}: {e}", path.display())),
            }
            .and_then(|previous| self.put(uid, record).map(|()| previous));
            match step {
                Ok(previous) => written.push((*uid, previous, assignment)),
                Err(e) => {
                    self.put_back(written);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn pinning(&self, pin: Pin<'_>) -> usize {
        self.assignments
            .lock()
            .expect("assignments lock")
            .values()
            .filter(|assignment| pin.pinned_by(assignment))
            .count()
    }

    fn referenced_revisions(&self, name: &str) -> BTreeSet<String> {
        self.assignments
            .lock()
            .expect("assignments lock")
            .values()
            .filter_map(|assignment| assignment.configurations.get(name).cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_store::tests::record;

    /// The round trip the whole decision rests on: what was written is what is restored, wire
    /// types and all.
    #[test]
    fn a_record_survives_the_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let uid = InstanceUid::default();
        store.put(&uid, &record()).expect("put");

        let reopened = FsAgentStore::open(dir.path()).expect("reopen");
        let restored = reopened.load().expect("load");
        assert!(restored[&uid] == record(), "the record round-trips whole");
    }

    /// A record nothing was rolled out to carries no assignment on disk, and restores as `None`
    /// rather than as an empty release.
    /// Verifies: ADR-0034
    #[test]
    fn a_record_without_an_assignment_restores_with_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let uid = InstanceUid::default();
        let mut unassigned = record();
        unassigned.assignment = None;
        store.put(&uid, &unassigned).expect("put");
        let text = std::fs::read_to_string(dir.path().join("agents").join(format!("{uid}.json")))
            .expect("read");
        assert!(
            !text.contains("assignment"),
            "an absent field stays absent on disk: {text}"
        );
        let restored = store.load().expect("load");
        assert!(restored[&uid].assignment.is_none());
    }

    /// A record in the shape before ADR-0034 — a configuration map and a package assignment side
    /// by side — fails the load naming the file and the reason, rather than being read as an Agent
    /// nothing was rolled out to.
    /// Verifies: ADR-0034
    #[test]
    fn a_record_with_the_old_assignment_shape_fails_the_load_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let uid = InstanceUid::default();
        store.put(&uid, &record()).expect("put");
        let path = dir.path().join("agents").join(format!("{uid}.json"));
        let mut old: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        let fields = old.as_object_mut().expect("object");
        fields.remove("assignment");
        fields.insert("version".into(), 2.into());
        fields.insert(
            "config_assignments".into(),
            serde_json::json!({"base": "0123abcd"}),
        );
        fields.insert(
            "package_assignment".into(),
            serde_json::json!({"deployment": "stable", "package": "otelcol@1.2.3"}),
        );
        std::fs::write(&path, serde_json::to_vec(&old).expect("json")).expect("write");

        let error = store.load().expect_err("the old shape is refused");
        assert!(
            error.contains(&format!("{uid}.json")),
            "names the file: {error}"
        );
        assert!(
            error.contains("version 2") && error.contains("ADR-0034"),
            "says why: {error}"
        );
    }

    /// An Agent's labels and the Host it arrived over are part of its record on disk, and a record
    /// written before they were — version 3 — fails the load naming the file and the reason,
    /// rather than being read as an Agent nobody labelled.
    /// Verifies: ADR-0035
    #[test]
    fn labels_and_host_live_in_the_record_and_an_older_envelope_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let uid = InstanceUid::default();
        store.put(&uid, &record()).expect("put");
        let path = dir.path().join("agents").join(format!("{uid}.json"));
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(written["version"], 4);
        assert_eq!(written["labels"]["rollout"], "canary");
        assert_eq!(written["host"], "0192f0c4-host");

        let mut old = written;
        let fields = old.as_object_mut().expect("object");
        fields.remove("labels");
        fields.remove("host");
        fields.insert("version".into(), 3.into());
        std::fs::write(&path, serde_json::to_vec(&old).expect("json")).expect("write");
        let error = store.load().expect_err("version 3 is refused");
        assert!(
            error.contains(&format!("{uid}.json")),
            "names the file: {error}"
        );
        assert!(
            error.contains("version 3") && error.contains("ADR-0035"),
            "says why: {error}"
        );
    }

    /// Forgetting removes the file (ADR-0024 extended); removing the absent is not an error.
    #[test]
    fn remove_deletes_and_tolerates_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let uid = InstanceUid::default();
        store.put(&uid, &record()).expect("put");
        store.remove(&uid).expect("remove");
        assert!(store.load().expect("load").is_empty());
        store.remove(&uid).expect("removing the absent is fine");
    }

    /// The identity reassignment: the record follows the Agent, the old key leaves the store.
    #[test]
    fn rekey_moves_the_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let (old, new) = (InstanceUid::default(), InstanceUid::default());
        store.put(&old, &record()).expect("put");
        store.rekey(&old, &new, &record()).expect("rekey");
        let restored = store.load().expect("load");
        assert!(restored.contains_key(&new) && !restored.contains_key(&old));
    }

    /// The integrity questions are the store's (ADR-0037 clause 3): what the stored assignments
    /// pin and which revisions they reference, kept as records are written, removed and loaded.
    /// Verifies: ADR-0037
    #[test]
    fn the_store_answers_what_its_assignments_pin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let (one, two) = (InstanceUid::default(), InstanceUid::default());
        store.put(&one, &record()).expect("put");
        let mut other = record();
        other.assignment = Some(Assignment {
            deployment: "canary".to_string(),
            package: None,
            configurations: BTreeMap::from([("base".to_string(), "4567cdef".to_string())]),
        });
        store.put(&two, &other).expect("put");
        let otelcol = PackageId::new("otelcol", "1.2.3").expect("id");
        assert_eq!(store.pinning(Pin::Configuration("base")), 2);
        assert_eq!(store.pinning(Pin::Package(&otelcol)), 1);
        assert_eq!(store.pinning(Pin::Deployment("canary")), 1);
        assert_eq!(store.pinning(Pin::Deployment("gone")), 0);
        assert_eq!(
            store.referenced_revisions("base"),
            BTreeSet::from(["0123abcd".to_string(), "4567cdef".to_string()])
        );

        let reopened = FsAgentStore::open(dir.path()).expect("reopen");
        reopened.load().expect("load");
        assert_eq!(reopened.pinning(Pin::Configuration("base")), 2);
        reopened.remove(&two).expect("remove");
        assert_eq!(reopened.pinning(Pin::Deployment("canary")), 0);
        assert_eq!(
            reopened.referenced_revisions("base"),
            BTreeSet::from(["0123abcd".to_string()])
        );
    }

    /// An assignment an older Server wrote, pinning a Package whose version is not SemVer, loads
    /// as it was: the assignment stays in force (ADR-0043 clause 3), and it still pins the Package.
    /// Verifies: ADR-0043
    #[test]
    fn an_assignment_pinning_a_non_semver_package_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let legacy = PackageId::load("otelcol", "1.19").expect("a token");
        let uid = InstanceUid::default();
        let mut agent = record();
        agent.assignment = Some(Assignment {
            deployment: "stable".to_string(),
            package: Some(legacy.clone()),
            configurations: BTreeMap::new(),
        });
        FsAgentStore::open(dir.path())
            .expect("open")
            .put(&uid, &agent)
            .expect("put");

        let reopened = FsAgentStore::open(dir.path()).expect("reopen");
        let loaded = reopened.load().expect("the record loads");
        let assignment = loaded[&uid].assignment.as_ref().expect("an assignment");
        assert_eq!(assignment.package.as_ref(), Some(&legacy));
        assert_eq!(reopened.pinning(Pin::Package(&legacy)), 1);
    }

    /// A rollout writes its revisions before the assignments that pin them, so one cut short in
    /// between leaves a revision nothing references and every record as it was. The next load
    /// accepts that state and collects the orphaned revision, from memory and from disk.
    /// Verifies: ADR-0037
    #[test]
    fn a_rollout_cut_short_after_its_revisions_leaves_a_state_the_next_load_accepts() {
        use crate::configs::{revision_hash, ConfigBackend as _, Revision};
        let dir = tempfile::tempdir().expect("tempdir");
        let revision = |body: &str| Revision {
            body: body.to_string(),
            role: String::new(),
            service_name: "otelcol".to_string(),
        };
        let (pinned, orphan) = (revision("v1\n"), revision("v2\n"));
        let uid = InstanceUid::default();
        let mut agent = record();
        agent.assignment = Some(Assignment {
            deployment: "stable".to_string(),
            package: None,
            configurations: BTreeMap::from([("base".to_string(), revision_hash(&pinned))]),
        });
        {
            let store = FsAgentStore::open(dir.path()).expect("open");
            store
                .put(&uid, &agent)
                .expect("the Agent as the last rollout left it");
            // The next rollout's revisions reach the disk; its records never do.
            let base = Configuration {
                name: "base".to_string(),
                saved: orphan.clone(),
                retained: BTreeMap::from([
                    (revision_hash(&pinned), pinned.clone()),
                    (revision_hash(&orphan), orphan.clone()),
                ]),
            };
            store.release(&[base], &[]).expect("the revisions");
        }

        let state = crate::fleet::AppState::new(dir.path().to_path_buf())
            .expect("the next load accepts it");
        let retained = |base: &Configuration| base.retained.keys().cloned().collect::<Vec<_>>();
        let base = state.configurations().get("base").expect("base");
        assert_eq!(
            retained(&base),
            [revision_hash(&pinned)],
            "the orphan is collected"
        );
        assert_eq!(base.saved, orphan, "the saved revision stays");
        let on_disk = super::super::FsConfigBackend::open(dir.path())
            .expect("open")
            .load()
            .expect("load");
        assert_eq!(
            retained(&on_disk[0]),
            [revision_hash(&pinned)],
            "and from disk"
        );
    }

    /// A file that does not parse fails startup loudly rather than being skipped (ADR-0010's
    /// principle, as every store here applies it).
    #[test]
    fn a_corrupt_record_fails_the_load_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsAgentStore::open(dir.path()).expect("open");
        let uid = InstanceUid::default();
        let path = dir.path().join("agents").join(format!("{uid}.json"));
        std::fs::write(&path, "not json").expect("write");
        let err = store.load().expect_err("must refuse");
        assert!(err.contains(&format!("{uid}")), "names the file: {err}");
    }
}
