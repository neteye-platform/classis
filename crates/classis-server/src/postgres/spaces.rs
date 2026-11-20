//! Space records in PostgreSQL (ADR-0064 clause 1, ADR-0050): the PostgreSQL adapter behind
//! [`SpaceStore`](crate::space_store::SpaceStore) — one row per Space, the complete enrolment key
//! beside its name. The key is a secret: the role the Server connects as is the access control, as
//! it is for every other record of the database.

use std::sync::Arc;

use tokio_postgres::GenericClient;
use zeroize::Zeroizing;

use super::{client, sql, Database};
use crate::space_store::{check_key, SpaceRecord, SpaceStore};

/// The Spaces in the table `spaces`. Names are unique ignoring ASCII case by a unique index on
/// `lower(name)`, so two creations of one name race to the database, which lets one of them in.
pub struct PgSpaceStore {
    database: Arc<Database>,
}

impl PgSpaceStore {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgSpaceStore { database }
    }
}

/// The record a row holds. A row a write would have refused fails, naming the Space.
fn record(row: &tokio_postgres::Row) -> Result<SpaceRecord, String> {
    let space = SpaceRecord {
        name: row.get(0),
        key: Zeroizing::new(row.get(1)),
    };
    space
        .check()
        .map_err(|e| format!("a space in the database: {e}"))?;
    Ok(space)
}

impl SpaceStore for PgSpaceStore {
    fn load(&self) -> Result<Vec<SpaceRecord>, String> {
        self.database.run(|pool| async move {
            let client = client(&pool).await?;
            client
                .query(
                    "SELECT name, key FROM spaces ORDER BY name COLLATE \"C\"",
                    &[],
                )
                .await
                .map_err(sql)?
                .iter()
                .map(record)
                .collect()
        })
    }

    fn create(&self, space: &SpaceRecord) -> Result<bool, String> {
        space.check()?;
        let space = space.clone();
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            write(&**client, &space).await
        })
    }

    fn get(&self, name: &str) -> Result<Option<SpaceRecord>, String> {
        let name = name.to_string();
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            client
                .query_opt("SELECT name, key FROM spaces WHERE name = $1", &[&name])
                .await
                .map_err(sql)?
                .as_ref()
                .map(record)
                .transpose()
        })
    }

    fn replace_key(&self, name: &str, key: &str) -> Result<bool, String> {
        check_key(name, key)?;
        let (name, key) = (name.to_string(), Zeroizing::new(key.to_string()));
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            let changed = client
                .execute(
                    "UPDATE spaces SET key = $2 WHERE name = $1",
                    &[&name, &*key],
                )
                .await
                .map_err(sql)?;
            Ok(changed == 1)
        })
    }
}

/// Adds one Space inside the caller's transaction, or answers `false` when its name — ignoring
/// ASCII case — is taken.
pub(crate) async fn write(
    client: &impl GenericClient,
    space: &SpaceRecord,
) -> Result<bool, String> {
    let added = client
        .execute(
            "INSERT INTO spaces (name, key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&space.name, &*space.key],
        )
        .await
        .map_err(sql)?;
    Ok(added == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FsSpaceStore;
    use crate::postgres::testing::TestDatabase;
    use crate::space_store::tests::{key_of, space};

    /// What a store holds, as plain values to compare.
    fn held(store: &dyn SpaceStore) -> Vec<(String, String)> {
        store
            .load()
            .expect("load")
            .into_iter()
            .map(|space| (space.name, space.key.to_string()))
            .collect()
    }

    /// The port's contract on either store: a Space is created once, its name unique ignoring ASCII
    /// case, found by its exact name only, its key replaced only by a well-formed key of its own
    /// name, and all of it still there when the store is opened again.
    fn contract(open: &dyn Fn() -> Box<dyn SpaceStore>) {
        let store = open();
        assert!(store.load().expect("empty").is_empty());
        assert!(store.get("prod").expect("get").is_none());

        let prod = space("Prod_EU", 'a');
        assert!(store.create(&prod).expect("create"));
        assert!(store.create(&space("lab", 'b')).expect("create"));
        for clash in ["Prod_EU", "prod_eu", "PROD_EU", "pROD_eu"] {
            assert!(
                !store
                    .create(&space(clash, 'c'))
                    .expect("a clash is no error"),
                "{clash}"
            );
        }
        assert_eq!(
            held(&*store),
            [
                ("Prod_EU".to_string(), prod.key.to_string()),
                ("lab".to_string(), space("lab", 'b').key.to_string()),
            ],
            "the clashes wrote nothing, and the name keeps its case"
        );

        assert_eq!(store.get("Prod_EU").expect("get"), Some(prod.clone()));
        for other in ["prod_eu", "PROD_EU", "Prod", "", "_x", "../x"] {
            assert_eq!(store.get(other).expect("get"), None, "{other:?}");
        }

        let invalid = SpaceRecord {
            name: "_x".to_string(),
            key: key_of("x", 'a'),
        };
        assert!(store.create(&invalid).is_err(), "an invalid name");
        let mut wrong = space("other", 'a');
        wrong.key = key_of("another", 'a');
        assert!(store.create(&wrong).is_err(), "the key of another space");

        let new_key = key_of("Prod_EU", 'z');
        assert!(store.replace_key("Prod_EU", &new_key).expect("replace"));
        assert!(!store
            .replace_key("prod_eu", &key_of("prod_eu", 'z'))
            .expect("exact"));
        assert!(!store
            .replace_key("nobody", &key_of("nobody", 'z'))
            .expect("unknown"));
        for bad in [
            key_of("lab", 'z').to_string(),
            "cle1_Prod_EU_short".to_string(),
            String::new(),
            key_of("prod_eu", 'z').to_string(),
        ] {
            assert!(store.replace_key("Prod_EU", &bad).is_err());
        }
        assert_eq!(
            store
                .get("Prod_EU")
                .expect("get")
                .map(|s| s.key.to_string()),
            Some(new_key.to_string()),
            "the key of a refused replacement is not stored"
        );

        let before = held(&*store);
        drop(store);
        assert_eq!(held(&*open()), before, "what reopening finds");
        assert_eq!(before[0].1, new_key.to_string());
    }

    /// Verifies: ADR-0064
    #[test]
    fn the_space_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| Box::new(FsSpaceStore::open(dir.path()).expect("open")));
    }

    /// Verifies: ADR-0064
    #[test]
    fn the_space_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| Box::new(PgSpaceStore::new(database.clone())));
    }

    /// The Space service over PostgreSQL: the key is recoverable, and enrolling a host leaves it
    /// unchanged; a rotation persists a different key that survives reopening and touches no
    /// client and no token.
    /// Verifies: ADR-0064
    #[test]
    fn the_space_service_keeps_its_key_and_rotates_it_on_request_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        crate::spaces::tests::contract(&|| {
            (
                crate::spaces::Spaces::new(Box::new(PgSpaceStore::new(database.clone()))),
                Box::new(crate::postgres::clients::PgClientStore::new(
                    database.clone(),
                )),
            )
        });
    }

    /// A rotation whose write fails leaves the old key in force, on PostgreSQL.
    /// Verifies: ADR-0064
    #[test]
    fn a_failed_rotation_leaves_the_old_key_in_force_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        crate::spaces::tests::rotation_fails_part_way(
            &crate::spaces::Spaces::new(Box::new(PgSpaceStore::new(test.open()))),
            &|| test.refuse("spaces", "NEW.name = 'prod'"),
            &|| test.mend("spaces"),
        );
    }

    /// A replacement that fails leaves the key as it was, on either store.
    fn fails_part_way(store: &dyn SpaceStore, refuse: &dyn Fn(), mend: &dyn Fn()) {
        let before = space("prod", 'a');
        assert!(store.create(&before).expect("create"));
        refuse();
        store
            .replace_key("prod", &key_of("prod", 'b'))
            .expect_err("the write fails");
        assert_eq!(store.get("prod").expect("get"), Some(before.clone()));
        mend();
        assert!(store
            .replace_key("prod", &key_of("prod", 'b'))
            .expect("replace"));
        assert_eq!(
            store.get("prod").expect("get").map(|s| s.key.to_string()),
            Some(key_of("prod", 'b').to_string())
        );
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_key_replacement_is_whole_or_nothing_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("spaces/prod.json");
        fails_part_way(
            &FsSpaceStore::open(dir.path()).expect("open"),
            &|| crate::fs::testing::refuse(&file),
            &|| crate::fs::testing::mend(&file),
        );
    }

    /// One statement per call, and a row that is no Space fails the read naming it — the key never
    /// shown. The key is in the row whole, as clause 1 says.
    /// Verifies: ADR-0064
    #[test]
    fn a_key_replacement_is_whole_or_nothing_and_a_bad_row_is_named_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let store = PgSpaceStore::new(test.open());
        fails_part_way(
            &store,
            &|| test.refuse("spaces", "NEW.name = 'prod'"),
            &|| test.mend("spaces"),
        );
        let rows = test.rows("SELECT name, key FROM spaces");
        assert_eq!(
            rows,
            [[
                Some("prod".to_string()),
                Some(key_of("prod", 'b').to_string())
            ]],
            "the complete key, in recoverable form"
        );
        test.sql("DROP TRIGGER IF EXISTS fleet_test_refuse ON spaces");
        let case = test.rows(
            "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() \
             AND indexname = 'spaces_name_ignoring_case'",
        );
        assert_eq!(
            case.len(),
            1,
            "case-insensitive uniqueness is the database's"
        );

        test.sql("UPDATE spaces SET key = 'cle1_other_x'");
        let err = store.load().map(|_| ()).expect_err("not a key");
        assert!(err.contains("prod"), "{err}");
        assert!(!err.contains("cle1_other_x"), "{err}");
    }

    /// The Space's file is `<lowercase name>.json`, owner-only in an owner-only directory, holding
    /// the name as it was created and the whole key; every file that is not exactly that fails the
    /// open naming it.
    /// Verifies: ADR-0064
    #[test]
    fn a_space_file_is_owner_only_named_by_the_lowercase_name_and_checked_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsSpaceStore::open(dir.path()).expect("open");
        let prod = space("Prod_EU", 'a');
        assert!(store.create(&prod).expect("create"));
        let path = dir.path().join("spaces/prod_eu.json");
        let text = std::fs::read_to_string(&path).expect("the file is named by the lowercase name");
        assert!(text.contains("\"Prod_EU\""), "{text}");
        assert!(text.contains(&*prod.key), "the complete key is in the file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &std::path::Path| {
                std::fs::metadata(path).expect("meta").permissions().mode() & 0o777
            };
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&dir.path().join("spaces")), 0o700);
        }
        assert!(FsSpaceStore::open(dir.path()).is_ok());

        let write = |name: &str, content: &str| {
            std::fs::write(dir.path().join("spaces").join(name), content).expect("write");
        };
        let document = |name: &str, key: &str| format!("{{\"name\":\"{name}\",\"key\":\"{key}\"}}");
        for (file, content) in [
            ("broken.json", "{".to_string()),
            ("Prod_EU.json", document("Prod_EU", &key_of("Prod_EU", 'a'))),
            ("misnamed.json", document("lab", &key_of("lab", 'a'))),
            ("lab.json", document("lab", &key_of("other", 'a'))),
            ("lab.json", document("lab", "not a key")),
            (
                "lab.json",
                "{\"name\":\"lab\",\"key\":\"x\",\"extra\":1}".to_string(),
            ),
            ("notes.txt", String::new()),
        ] {
            write(file, &content);
            let error = FsSpaceStore::open(dir.path()).map(|_| ()).expect_err(file);
            assert!(
                error.contains(file) || error.contains("lab"),
                "{file}: {error}"
            );
            assert!(!error.contains(&key_of("lab", 'a').to_string()), "{error}");
            std::fs::remove_file(dir.path().join("spaces").join(file)).expect("clean");
        }
        assert!(FsSpaceStore::open(dir.path()).is_ok());
    }
}
