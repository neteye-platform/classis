//! Agent records in PostgreSQL (ADR-0050 clauses 3 and 8): the PostgreSQL adapter behind
//! [`AgentStore`](crate::agent_store::AgentStore) — one row per Agent, its scalars as columns, the
//! wire-typed fields as their protobuf bytes, its labels, and its assignment's Configurations in
//! rows of their own. A rollout's revisions and assignments commit together or not at all.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use opamp::uid::InstanceUid;
use prost::Message;
use tokio_postgres::GenericClient;

use super::{client, signed, sql, unsigned, Database};
use crate::agent_store::{AgentStore, PersistedAgent, Pin};
use crate::configs::Configuration;
use crate::fleet::{Assignment, Transport};
use crate::packages::PackageId;

/// The Agents in `agents` and `agent_assignment_configurations`. The integrity queries are
/// answered from the assignments this adapter last read or committed, as the filesystem adapter
/// answers them: the port gives them no way to fail, and an answer that a lost database turned
/// into "nothing pins it" would let a pinned revision go.
pub struct PgAgentStore {
    database: Arc<Database>,
    /// Every stored record's assignment, as committed.
    assignments: Mutex<HashMap<InstanceUid, Assignment>>,
}

impl PgAgentStore {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgAgentStore {
            database,
            assignments: Mutex::new(HashMap::new()),
        }
    }

    /// Notes what the committed records now pin.
    fn stored<'a>(
        &self,
        records: impl IntoIterator<Item = (&'a InstanceUid, Option<&'a Assignment>)>,
    ) {
        let mut assignments = self.assignments.lock().expect("assignments lock");
        for (uid, assignment) in records {
            match assignment {
                Some(assignment) => assignments.insert(*uid, assignment.clone()),
                None => assignments.remove(uid),
            };
        }
    }

    /// Runs `writes` in one transaction.
    fn transaction<F>(
        &self,
        writes: impl FnOnce(deadpool_postgres::Object) -> F + Send + 'static,
    ) -> Result<(), String>
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        self.database
            .run(move |pool| async move { writes(client(&pool).await?).await })
    }
}

impl AgentStore for PgAgentStore {
    fn load(&self) -> Result<HashMap<InstanceUid, PersistedAgent>, String> {
        let records = self.database.run(|pool| async move {
            let client = client(&pool).await?;
            read_all(&**client).await
        })?;
        *self.assignments.lock().expect("assignments lock") = records
            .iter()
            .filter_map(|(uid, record)| Some((*uid, record.assignment.clone()?)))
            .collect();
        Ok(records)
    }

    fn put(&self, uid: &InstanceUid, record: &PersistedAgent) -> Result<(), String> {
        let (uid, record) = (*uid, record.clone());
        let assignment = record.assignment.clone();
        self.transaction(move |mut client| async move {
            let transaction = client.transaction().await.map_err(sql)?;
            write(&*transaction, &uid, &record).await?;
            transaction.commit().await.map_err(sql)
        })?;
        self.stored([(&uid, assignment.as_ref())]);
        Ok(())
    }

    fn remove(&self, uid: &InstanceUid) -> Result<(), String> {
        let uid = *uid;
        self.transaction(move |mut client| async move {
            let transaction = client.transaction().await.map_err(sql)?;
            transaction
                .execute(
                    "DELETE FROM agents WHERE instance_uid = $1",
                    &[&uid.to_string()],
                )
                .await
                .map_err(sql)?;
            transaction.commit().await.map_err(sql)
        })?;
        self.stored([(&uid, None)]);
        Ok(())
    }

    /// One transaction: the record under its new key, and the old key gone.
    fn rekey(
        &self,
        old: &InstanceUid,
        new: &InstanceUid,
        record: &PersistedAgent,
    ) -> Result<(), String> {
        let (old, new, record) = (*old, *new, record.clone());
        let assignment = record.assignment.clone();
        self.transaction(move |mut client| async move {
            let transaction = client.transaction().await.map_err(sql)?;
            transaction
                .execute(
                    "DELETE FROM agents WHERE instance_uid = $1",
                    &[&old.to_string()],
                )
                .await
                .map_err(sql)?;
            write(&*transaction, &new, &record).await?;
            transaction.commit().await.map_err(sql)
        })?;
        self.stored([(&old, None), (&new, assignment.as_ref())]);
        Ok(())
    }

    /// One transaction: the revisions and the records that pin them commit together or not at all
    /// (ADR-0050 clause 3).
    fn release(
        &self,
        revisions: &[Configuration],
        agents: &[(InstanceUid, PersistedAgent)],
    ) -> Result<(), String> {
        let (revisions, records) = (revisions.to_vec(), agents.to_vec());
        let written = revisions.len() + records.len();
        self.database.run_writing(written, move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            for configuration in &revisions {
                super::configs::write(&*transaction, configuration).await?;
            }
            for (uid, record) in &records {
                write(&*transaction, uid, record).await?;
            }
            transaction.commit().await.map_err(sql)
        })?;
        self.stored(
            agents
                .iter()
                .map(|(uid, record)| (uid, record.assignment.as_ref())),
        );
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

/// The columns of a row, in the order [`read_all`] selects and [`write`] inserts them.
const COLUMNS: &str = "instance_uid, sequence_num, capabilities, transport, last_seen_ms, \
     restart_pending, effective_config, description, health, remote_config_status, \
     connection_settings_status, package_statuses, available_components, labels, host, \
     deployment, package_agent_type, package_version";

/// A wire-typed field as its protobuf bytes, the encoding whose compatibility rules the Baseline
/// already governs (clause 8).
fn encode<M: Message>(message: Option<&M>) -> Option<Vec<u8>> {
    message.map(Message::encode_to_vec)
}

fn decode<M: Message + Default>(bytes: Option<Vec<u8>>, what: &str) -> Result<Option<M>, String> {
    bytes
        .map(|bytes| {
            M::decode(bytes.as_slice()).map_err(|e| format!("{what} does not decode: {e}"))
        })
        .transpose()
}

/// Every Agent record. A row that does not decode fails, naming its `instance_uid` (clause 8).
pub(crate) async fn read_all(
    client: &impl GenericClient,
) -> Result<HashMap<InstanceUid, PersistedAgent>, String> {
    let mut released: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    for row in client
        .query(
            "SELECT instance_uid, configuration, revision FROM agent_assignment_configurations",
            &[],
        )
        .await
        .map_err(sql)?
    {
        released
            .entry(row.get(0))
            .or_default()
            .insert(row.get(1), row.get(2));
    }
    let mut records = HashMap::new();
    for row in client
        .query(&format!("SELECT {COLUMNS} FROM agents"), &[])
        .await
        .map_err(sql)?
    {
        let key: String = row.get(0);
        let named = |e: String| format!("agent {key} in the database: {e}");
        let uid =
            InstanceUid::parse(&key).ok_or_else(|| named("not an Instance UID".to_string()))?;
        let labels: BTreeMap<String, String> =
            serde_json::from_value(row.get(13)).map_err(|e| named(format!("labels: {e}")))?;
        let configurations = released.remove(&key).unwrap_or_default();
        let deployment: Option<String> = row.get(15);
        let package = match (
            row.get::<_, Option<String>>(16),
            row.get::<_, Option<String>>(17),
        ) {
            (Some(agent_type), Some(version)) => Some(
                PackageId::load(&agent_type, &version)
                    .map_err(|e| named(format!("invalid package in the assignment: {e}")))?,
            ),
            (None, None) => None,
            _ => return Err(named("half a package in the assignment".to_string())),
        };
        let assignment = match deployment {
            Some(deployment) => Some(Assignment {
                deployment,
                package,
                configurations,
            }),
            None if package.is_none() && configurations.is_empty() => None,
            None => return Err(named("an assignment without its Deployment".to_string())),
        };
        let record = PersistedAgent {
            sequence_num: unsigned(row.get(1)),
            capabilities: unsigned(row.get(2)),
            transport: Transport::parse(row.get(3)),
            last_seen_ms: unsigned(row.get(4)),
            restart_pending: row.get(5),
            effective_config: row
                .get::<_, Option<Vec<u8>>>(6)
                .map(String::from_utf8)
                .transpose()
                .map_err(|e| named(format!("effective_config: {e}")))?,
            description: decode(row.get(7), "description").map_err(named)?,
            health: decode(row.get(8), "health").map_err(named)?,
            remote_config_status: decode(row.get(9), "remote_config_status").map_err(named)?,
            connection_settings_status: decode(row.get(10), "connection_settings_status")
                .map_err(named)?,
            package_statuses: decode(row.get(11), "package_statuses").map_err(named)?,
            available_components: decode(row.get(12), "available_components").map_err(named)?,
            assignment,
            labels,
            host: row.get(14),
        };
        records.insert(uid, record);
    }
    if let Some(key) = released.keys().next() {
        return Err(format!(
            "an assignment in the database names agent {key}, which is not there"
        ));
    }
    Ok(records)
}

/// Creates or replaces one Agent record, its assignment's Configurations exactly the record's,
/// inside the caller's transaction.
pub(crate) async fn write(
    client: &impl GenericClient,
    uid: &InstanceUid,
    record: &PersistedAgent,
) -> Result<(), String> {
    let key = uid.to_string();
    let labels = serde_json::to_value(&record.labels).expect("labels serialize");
    let assignment = record.assignment.as_ref();
    let package = assignment.and_then(|assignment| assignment.package.as_ref());
    let updates = COLUMNS
        .split(", ")
        .skip(1)
        .map(|column| format!("{column} = EXCLUDED.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    client
        .execute(
            &format!(
                "INSERT INTO agents ({COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                 $11, $12, $13, $14, $15, $16, $17, $18) ON CONFLICT (instance_uid) DO UPDATE \
                 SET {updates}"
            ),
            &[
                &key,
                &signed(record.sequence_num),
                &signed(record.capabilities),
                &record.transport.as_str(),
                &signed(record.last_seen_ms),
                &record.restart_pending,
                &record.effective_config.as_deref().map(str::as_bytes),
                &encode(record.description.as_ref()),
                &encode(record.health.as_ref()),
                &encode(record.remote_config_status.as_ref()),
                &encode(record.connection_settings_status.as_ref()),
                &encode(record.package_statuses.as_ref()),
                &encode(record.available_components.as_ref()),
                &labels,
                &record.host,
                &assignment.map(|assignment| assignment.deployment.as_str()),
                &package.map(|id| id.agent_type.as_str()),
                &package.map(|id| id.version.as_str()),
            ],
        )
        .await
        .map_err(sql)?;
    client
        .execute(
            "DELETE FROM agent_assignment_configurations WHERE instance_uid = $1",
            &[&key],
        )
        .await
        .map_err(sql)?;
    for (name, revision) in assignment
        .map(|assignment| &assignment.configurations)
        .into_iter()
        .flatten()
    {
        client
            .execute(
                "INSERT INTO agent_assignment_configurations (instance_uid, configuration, \
                 revision) VALUES ($1, $2, $3)",
                &[&key, name, revision],
            )
            .await
            .map_err(sql)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_store::tests::record;
    use crate::configs::{revision_hash, Revision};
    use crate::fs::{FsAgentStore, FsConfigBackend};
    use crate::postgres::testing::TestDatabase;

    /// The two stores a rollout writes into, opened on one backing store.
    type Open<'a> = &'a dyn Fn() -> (Box<dyn AgentStore>, Box<dyn crate::configs::ConfigBackend>);

    fn revision(body: &str) -> Revision {
        Revision {
            body: body.to_string(),
            role: String::new(),
            service_name: "otelcol".to_string(),
        }
    }

    /// The port's contract on either store: what is written is loaded back whole, wire types and
    /// all; a record without an assignment stays without one; a re-key moves the record; the
    /// integrity queries follow what is stored; and a rollout's revisions and assignments are
    /// both present.
    fn contract(open: Open<'_>) {
        let (store, _) = open();
        assert!(store.load().expect("empty").is_empty());
        let (one, two, three) = (
            InstanceUid::default(),
            InstanceUid::default(),
            InstanceUid::default(),
        );
        let mut full = record();
        // An Agent reports what it likes: a NUL is kept as it is, and fails no write.
        full.effective_config = Some("receivers: {}\n# \0 a NUL an Agent sent\n".to_string());
        let mut bare = record();
        bare.assignment = None;
        bare.labels.clear();
        bare.host = None;
        bare.description = None;
        bare.effective_config = None;
        bare.sequence_num = u64::MAX;
        store.put(&one, &full).expect("put");
        store.put(&two, &bare).expect("put");
        let loaded = open().0.load().expect("load");
        assert!(loaded[&one] == full, "the record round-trips whole");
        assert!(loaded[&two] == bare, "absent stays absent, u64::MAX stays");

        store.rekey(&two, &three, &bare).expect("rekey");
        let loaded = open().0.load().expect("load");
        assert!(loaded.contains_key(&three) && !loaded.contains_key(&two));

        let pinned = revision("v1\n");
        let base = Configuration {
            name: "base".to_string(),
            saved: pinned.clone(),
            retained: BTreeMap::from([(revision_hash(&pinned), pinned.clone())]),
        };
        let mut released = bare.clone();
        released.effective_config = full.effective_config.clone();
        released.assignment = Some(Assignment {
            deployment: "stable".to_string(),
            package: None,
            configurations: BTreeMap::from([("base".to_string(), revision_hash(&pinned))]),
        });
        store
            .release(std::slice::from_ref(&base), &[(three, released.clone())])
            .expect("release");
        let (reopened, configs) = open();
        let loaded = reopened.load().expect("load");
        assert!(loaded[&three] == released);
        assert_eq!(configs.load().expect("revisions"), [base], "both present");
        assert_eq!(reopened.pinning(Pin::Configuration("base")), 2);
        assert_eq!(reopened.pinning(Pin::Deployment("stable")), 2);
        assert_eq!(
            reopened.referenced_revisions("base"),
            BTreeSet::from(["0123abcd".to_string(), revision_hash(&pinned)])
        );

        store.remove(&one).expect("remove");
        store.remove(&one).expect("removing the absent is fine");
        assert_eq!(store.pinning(Pin::Configuration("base")), 1);
        assert_eq!(open().0.load().expect("load").len(), 1);
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_agent_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| {
            (
                Box::new(FsAgentStore::open(dir.path()).expect("open")),
                Box::new(FsConfigBackend::open(dir.path()).expect("open")),
            )
        });
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_agent_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| {
            (
                Box::new(PgAgentStore::new(database.clone())),
                Box::new(super::super::configs::PgConfigBackend::new(
                    database.clone(),
                )),
            )
        });
    }

    /// A rollout whose last record cannot be written leaves none of its assignments behind, on
    /// either store, and what the store answers about pins stays as it was (ADR-0050 clause 3):
    /// the records already written are put back, or never committed. `refuse(uid)` makes the
    /// write of that Agent's record fail; `mend` takes that away. Answers the Configurations the
    /// store holds afterwards, which the caller judges: none with PostgreSQL, at most a revision
    /// nothing references with files.
    fn a_rollout_that_fails(
        open: Open<'_>,
        refuse: &dyn Fn(&InstanceUid),
        mend: &dyn Fn(&InstanceUid),
    ) -> Vec<Configuration> {
        let (store, configs) = open();
        let (one, two) = (InstanceUid::default(), InstanceUid::default());
        let mut before = record();
        before.assignment = None;
        store.put(&one, &before).expect("put");
        store.load().expect("load");

        let pinned = revision("v1\n");
        let base = Configuration {
            name: "base".to_string(),
            saved: pinned.clone(),
            retained: BTreeMap::from([(revision_hash(&pinned), pinned.clone())]),
        };
        let mut released = record();
        released.assignment = Some(Assignment {
            deployment: "stable".to_string(),
            package: None,
            configurations: BTreeMap::from([("base".to_string(), revision_hash(&pinned))]),
        });
        refuse(&two);
        store
            .release(&[base], &[(one, released.clone()), (two, released)])
            .expect_err("the second record cannot be written");
        mend(&two);

        let loaded = open().0.load().expect("load");
        assert!(loaded[&one] == before, "no assignment");
        assert!(!loaded.contains_key(&two));
        assert_eq!(store.pinning(Pin::Deployment("stable")), 0);
        assert_eq!(store.pinning(Pin::Configuration("base")), 0);
        configs.load().expect("load")
    }

    /// Verifies: ADR-0050
    #[test]
    fn a_rollout_that_fails_leaves_no_assignment_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = |uid: &InstanceUid| dir.path().join(format!("agents/{uid}.json"));
        let left = a_rollout_that_fails(
            &|| {
                (
                    Box::new(FsAgentStore::open(dir.path()).expect("open")),
                    Box::new(FsConfigBackend::open(dir.path()).expect("open")),
                )
            },
            &|uid| crate::fs::testing::refuse(&file(uid)),
            &|uid| crate::fs::testing::mend(&file(uid)),
        );
        // The revisions are written first, and nothing references them (the port's contract).
        assert!(left.len() <= 1, "{left:?}");
    }

    /// With PostgreSQL the revisions and the assignments commit together or not at all.
    /// Verifies: ADR-0050
    #[test]
    fn a_rollout_that_fails_leaves_neither_revisions_nor_assignments_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        let left = a_rollout_that_fails(
            &|| {
                (
                    Box::new(PgAgentStore::new(database.clone())),
                    Box::new(super::super::configs::PgConfigBackend::new(
                        database.clone(),
                    )),
                )
            },
            &|uid| test.refuse("agents", &format!("NEW.instance_uid = '{uid}'")),
            &|_| test.mend("agents"),
        );
        assert!(left.is_empty(), "no revision: {left:?}");
    }

    /// A row that does not decode fails startup naming its `instance_uid` (clause 8).
    /// Verifies: ADR-0050
    #[test]
    fn an_agent_row_that_does_not_decode_fails_the_load_naming_it() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let store = PgAgentStore::new(test.open());
        let uid = InstanceUid::default();
        store.put(&uid, &record()).expect("put");
        test.sql("UPDATE agents SET health = '\\xff'::bytea");
        let err = store.load().expect_err("not protobuf");
        assert!(err.contains(&uid.to_string()), "{err}");
        assert!(err.contains("health"), "{err}");
    }
}
