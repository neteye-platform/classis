//! Configurations in PostgreSQL (ADR-0050 clause 14): the PostgreSQL adapter behind
//! [`ConfigBackend`](crate::configs::ConfigBackend) — one row per Configuration, its retained
//! revisions in rows of their own, each call one transaction.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio_postgres::GenericClient;

use super::{client, sql, Database};
use crate::configs::{check_type, validate_name, ConfigBackend, Configuration, Revision};

/// The Configurations in `configurations` and `configuration_revisions`.
pub struct PgConfigBackend {
    database: Arc<Database>,
}

impl PgConfigBackend {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgConfigBackend { database }
    }
}

impl ConfigBackend for PgConfigBackend {
    fn load(&self) -> Result<Vec<Configuration>, String> {
        self.database.run(|pool| async move {
            let client = client(&pool).await?;
            read_all(&**client).await
        })
    }

    fn put(&self, config: &Configuration) -> Result<(), String> {
        let config = config.clone();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            write(&*transaction, &config).await?;
            transaction.commit().await.map_err(sql)
        })
    }

    /// The Configuration and its revisions go in one statement, the revisions by cascade.
    fn remove(&self, name: &str) -> Result<(), String> {
        let name = name.to_string();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            transaction
                .execute("DELETE FROM configurations WHERE name = $1", &[&name])
                .await
                .map_err(sql)?;
            transaction.commit().await.map_err(sql)
        })
    }
}

/// Every Configuration with its retained revisions. A row that does not decode — a name outside
/// the grammar, a saved revision without its Agent type — fails, naming it.
pub(crate) async fn read_all(client: &impl GenericClient) -> Result<Vec<Configuration>, String> {
    let mut configs: BTreeMap<String, Configuration> = BTreeMap::new();
    for row in client
        .query(
            "SELECT name, body, role, service_name FROM configurations ORDER BY name",
            &[],
        )
        .await
        .map_err(sql)?
    {
        let name: String = row.get(0);
        let named = |e: String| format!("configuration {name:?} in the database: {e}");
        validate_name(&name).map_err(named)?;
        let saved = Revision {
            body: row.get(1),
            role: row.get(2),
            service_name: row.get(3),
        };
        check_type(&saved).map_err(|e| {
            named(format!(
                "{e} — save it again with the Agent type it is written for"
            ))
        })?;
        configs.insert(
            name.clone(),
            Configuration {
                name,
                saved,
                retained: BTreeMap::new(),
            },
        );
    }
    for row in client
        .query(
            "SELECT configuration, hash, body, role, service_name FROM configuration_revisions",
            &[],
        )
        .await
        .map_err(sql)?
    {
        let name: String = row.get(0);
        let config = configs.get_mut(&name).ok_or_else(|| {
            format!("a revision in the database names configuration {name:?}, which is not there")
        })?;
        config.retained.insert(
            row.get(1),
            Revision {
                body: row.get(2),
                role: row.get(3),
                service_name: row.get(4),
            },
        );
    }
    Ok(configs.into_values().collect())
}

/// Creates or replaces one Configuration and makes its retained revisions exactly `config`'s,
/// inside the caller's transaction — the write this store and a rollout's revisions (ADR-0050
/// clause 3) share.
pub(crate) async fn write(
    client: &impl GenericClient,
    config: &Configuration,
) -> Result<(), String> {
    client
        .execute(
            "INSERT INTO configurations (name, body, role, service_name) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (name) DO UPDATE SET body = EXCLUDED.body, role = EXCLUDED.role, \
             service_name = EXCLUDED.service_name",
            &[
                &config.name,
                &config.saved.body,
                &config.saved.role,
                &config.saved.service_name,
            ],
        )
        .await
        .map_err(sql)?;
    let kept: Vec<&str> = config.retained.keys().map(String::as_str).collect();
    client
        .execute(
            "DELETE FROM configuration_revisions WHERE configuration = $1 AND NOT hash = ANY($2)",
            &[&config.name, &kept],
        )
        .await
        .map_err(sql)?;
    for (hash, revision) in &config.retained {
        client
            .execute(
                "INSERT INTO configuration_revisions (configuration, hash, body, role, \
                 service_name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (configuration, hash) DO \
                 UPDATE SET body = EXCLUDED.body, role = EXCLUDED.role, \
                 service_name = EXCLUDED.service_name",
                &[
                    &config.name,
                    hash,
                    &revision.body,
                    &revision.role,
                    &revision.service_name,
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
    use crate::configs::revision_hash;
    use crate::fs::FsConfigBackend;
    use crate::postgres::testing::TestDatabase;

    fn revision(body: &str) -> Revision {
        Revision {
            body: body.to_string(),
            role: String::new(),
            service_name: "otelcol".to_string(),
        }
    }

    fn configuration(name: &str, saved: &str, retained: &[&str]) -> Configuration {
        Configuration {
            name: name.to_string(),
            saved: revision(saved),
            retained: retained
                .iter()
                .map(|body| (revision_hash(&revision(body)), revision(body)))
                .collect(),
        }
    }

    /// The port's contract, whatever keeps the records: what is written is loaded back by another
    /// adapter on the same store, a put replaces the record and its revisions whole, and a removal
    /// takes the revisions with it and tolerates absence.
    fn contract(open: &dyn Fn() -> Box<dyn ConfigBackend>) {
        let store = open();
        assert!(store.load().expect("empty").is_empty());
        let mut base = configuration("base", "v2\n", &["v1\n", "v2\n"]);
        base.saved.role = crate::configs::ROLE_SUPPLEMENTARY.to_string();
        store.put(&base).expect("put");
        store.put(&configuration("other", "x\n", &[])).expect("put");
        assert_eq!(
            open().load().expect("load"),
            [base.clone(), configuration("other", "x\n", &[])]
        );

        let narrowed = configuration("base", "v3\n", &["v2\n"]);
        store.put(&narrowed).expect("replace");
        assert_eq!(
            open().load().expect("load")[0],
            narrowed,
            "the revisions are exactly the new ones"
        );

        store.remove("base").expect("remove");
        store.remove("base").expect("removing the absent is fine");
        assert_eq!(
            open().load().expect("load"),
            [configuration("other", "x\n", &[])]
        );
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_configuration_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| Box::new(FsConfigBackend::open(dir.path()).expect("open")));
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_configuration_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| Box::new(PgConfigBackend::new(database.clone())));
    }

    /// A put that fails part-way leaves the Configuration as it was, on either store: one
    /// transaction per call, one file replaced in one step. `refuse` makes the write of the
    /// second revision fail, after the Configuration's own row; `mend` takes that away.
    fn fails_part_way(store: &dyn ConfigBackend, refuse: &dyn Fn(), mend: &dyn Fn()) {
        let before = configuration("base", "v1\n", &["v1\n"]);
        store.put(&before).expect("put");
        refuse();
        store
            .put(&configuration("base", "v2\n", &["v1\n", "v2\n"]))
            .expect_err("refused part-way");
        mend();
        assert_eq!(store.load().expect("load"), [before]);
    }

    /// Verifies: ADR-0050
    #[test]
    fn a_put_that_fails_part_way_leaves_nothing_of_itself_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("configurations/base.json");
        fails_part_way(
            &FsConfigBackend::open(dir.path()).expect("open"),
            &|| crate::fs::testing::refuse(&file),
            &|| crate::fs::testing::mend(&file),
        );
    }

    /// Run from inside a runtime's own thread, as the Server's handlers call the port: the bridge
    /// never needs the thread that waits for it.
    /// Verifies: ADR-0050
    #[tokio::test(flavor = "current_thread")]
    async fn a_put_that_fails_part_way_leaves_nothing_of_itself_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let second = revision_hash(&revision("v2\n"));
        fails_part_way(
            &PgConfigBackend::new(test.open()),
            &|| test.refuse("configuration_revisions", &format!("NEW.hash = '{second}'")),
            &|| test.mend("configuration_revisions"),
        );
    }

    /// A row that does not decode fails the load naming it, rather than being skipped.
    /// Verifies: ADR-0050
    #[test]
    fn a_configuration_row_that_does_not_decode_fails_the_load_naming_it() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let store = PgConfigBackend::new(test.open());
        test.sql("INSERT INTO configurations VALUES ('untyped', 'x', '', '')");
        let err = store.load().expect_err("no Agent type");
        assert!(err.contains("\"untyped\""), "{err}");
    }
}
