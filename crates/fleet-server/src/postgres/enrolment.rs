//! The enrolment window and its queue in PostgreSQL (ADR-0050 clause 9): the PostgreSQL adapter
//! behind [`EnrolmentStore`](crate::enrolment::EnrolmentStore) — the window's end in one row, each
//! pending request in a row of its own, saved in one transaction before the act that changed them
//! is answered.

use std::sync::Arc;

use serde_json::Value;
use tokio_postgres::GenericClient;

use super::{client, signed, sql, unsigned, Database};
use crate::enrolment::{EnrolmentStore, Persisted};

/// The window in `enrolment_window`, its requests in `enrolment_requests`.
pub struct PgEnrolmentStore {
    database: Arc<Database>,
}

impl PgEnrolmentStore {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgEnrolmentStore { database }
    }
}

impl EnrolmentStore for PgEnrolmentStore {
    fn load(&self) -> Result<Option<Persisted>, String> {
        self.database.run(|pool| async move {
            let client = client(&pool).await?;
            read(&**client).await
        })
    }

    fn save(&self, persisted: &Persisted) -> Result<(), String> {
        let persisted = persisted.clone();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            write(&*transaction, &persisted).await?;
            transaction.commit().await.map_err(sql)
        })
    }
}

/// What was saved last, `None` when nothing was. A request that does not decode fails, naming it.
pub(crate) async fn read(client: &impl GenericClient) -> Result<Option<Persisted>, String> {
    let Some(window) = client
        .query_opt("SELECT until_ms FROM enrolment_window", &[])
        .await
        .map_err(sql)?
    else {
        return Ok(None);
    };
    let mut requests = Vec::new();
    for row in client
        .query(
            "SELECT id, request FROM enrolment_requests ORDER BY position, id",
            &[],
        )
        .await
        .map_err(sql)?
    {
        requests.push(row.get::<_, Value>(1));
    }
    let mut document = serde_json::Map::new();
    if let Some(until) = window.get::<_, Option<i64>>(0) {
        document.insert("window_until_ms".to_string(), unsigned(until).into());
    }
    document.insert("requests".to_string(), Value::Array(requests));
    serde_json::from_value(Value::Object(document))
        .map(Some)
        .map_err(|e| format!("the enrolment queue in the database does not decode: {e}"))
}

/// Replaces the window and its requests inside the caller's transaction.
pub(crate) async fn write(
    client: &impl GenericClient,
    persisted: &Persisted,
) -> Result<(), String> {
    let document = serde_json::to_value(persisted).expect("the enrolment serializes");
    let until = document
        .get("window_until_ms")
        .and_then(Value::as_u64)
        .map(signed);
    client
        .execute(
            "INSERT INTO enrolment_window (singleton, until_ms) VALUES (true, $1) \
             ON CONFLICT (singleton) DO UPDATE SET until_ms = EXCLUDED.until_ms",
            &[&until],
        )
        .await
        .map_err(sql)?;
    client
        .execute("DELETE FROM enrolment_requests", &[])
        .await
        .map_err(sql)?;
    let requests = document
        .get("requests")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (position, request) in requests.iter().enumerate() {
        let id = request
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        client
            .execute(
                "INSERT INTO enrolment_requests (id, position, request) VALUES ($1, $2, $3)",
                &[
                    &id,
                    &i32::try_from(position).expect("the queue is bounded"),
                    request,
                ],
            )
            .await
            .map_err(sql)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FsEnrolmentStore;
    use crate::postgres::testing::TestDatabase;

    fn persisted(until: Option<u64>, ids: &[&str]) -> Persisted {
        let requests: Vec<Value> = ids
            .iter()
            .map(|id| {
                // A host chooses its subject: a NUL is kept, and fails no write.
                let mut requester = crate::enrolment::tests::requester();
                requester.bootstrap_subject = "CN=edge\0".to_string();
                serde_json::json!({
                    "id": id,
                    "arrived_ms": 5,
                    "key_fingerprint": id,
                    "requester": serde_json::to_value(requester).expect("requester"),
                    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----",
                    "instance_uid": "00",
                    "decision": {"approved": "-----BEGIN CERTIFICATE-----"},
                })
            })
            .collect();
        let mut document = serde_json::json!({ "requests": requests });
        if let Some(until) = until {
            document["window_until_ms"] = until.into();
        }
        serde_json::from_value(document).expect("a persisted queue")
    }

    /// The port's contract on either store: nothing saved is `None`; what is saved is loaded back,
    /// the window's end and every request in order; a save replaces the whole.
    fn contract(open: &dyn Fn() -> Box<dyn EnrolmentStore>) {
        let store = open();
        assert_eq!(store.load().expect("nothing"), None);
        let open_window = persisted(Some(u64::MAX - 7), &["b", "a", "c"]);
        store.save(&open_window).expect("save");
        assert_eq!(open().load().expect("load"), Some(open_window));
        let closed = persisted(None, &["a"]);
        store.save(&closed).expect("save");
        assert_eq!(open().load().expect("load"), Some(closed));
        store.save(&Persisted::default()).expect("save");
        assert_eq!(open().load().expect("load"), Some(Persisted::default()));
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_enrolment_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| Box::new(FsEnrolmentStore::open(dir.path())));
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_enrolment_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| Box::new(PgEnrolmentStore::new(database.clone())));
    }

    /// A save that fails part-way leaves the window and the queue as they were, on either store.
    /// `refuse` makes the write of request `z` fail; `mend` takes that away.
    fn fails_part_way(store: &dyn EnrolmentStore, refuse: &dyn Fn(), mend: &dyn Fn()) {
        let before = persisted(Some(10), &["a"]);
        store.save(&before).expect("save");
        refuse();
        store
            .save(&persisted(Some(20), &["b", "z"]))
            .expect_err("z cannot be written");
        mend();
        assert_eq!(store.load().expect("load"), Some(before));
    }

    /// Verifies: ADR-0050
    #[test]
    fn an_enrolment_save_that_fails_part_way_leaves_nothing_of_itself_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("enrolment.json");
        fails_part_way(
            &FsEnrolmentStore::open(dir.path()),
            &|| crate::fs::testing::refuse(&file),
            &|| crate::fs::testing::mend(&file),
        );
    }

    /// Verifies: ADR-0050
    #[test]
    fn an_enrolment_save_that_fails_part_way_leaves_nothing_of_itself_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        fails_part_way(
            &PgEnrolmentStore::new(test.open()),
            &|| test.refuse("enrolment_requests", "NEW.id = 'z'"),
            &|| test.mend("enrolment_requests"),
        );
    }
}
