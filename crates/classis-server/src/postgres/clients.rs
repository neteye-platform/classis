//! OAuth-client records in PostgreSQL (ADR-0064 clauses 2 to 4, ADR-0050): the PostgreSQL adapter
//! behind [`ClientStore`](crate::client_store::ClientStore) — one row per client, the hash of its
//! secret and the hash and expiry of its one active token beside its identity. The token's hash
//! has a unique index, which is also how admission finds its client: a query, with no copy of the
//! table in memory.

use std::sync::Arc;

use tokio_postgres::GenericClient;

use super::{client, signed, sql, unsigned, Database};
use crate::client_store::{ActiveToken, Admitted, ClientRecord, ClientStore, Hash, TokenReplaced};

/// The clients in the table `clients`.
pub struct PgClientStore {
    database: Arc<Database>,
}

impl PgClientStore {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgClientStore { database }
    }
}

fn hash_of(bytes: Vec<u8>, what: &str, client_id: &str) -> Result<Hash, String> {
    Hash::try_from(bytes)
        .map_err(|_| format!("client {client_id:?} in the database: {what} is not a SHA-256 hash"))
}

/// The columns of a row, in the order [`COLUMNS`] names them.
const COLUMNS: &str = "client_id, space, secret_hash, issued_at, token_hash, token_expires_at";

/// The record a row holds. A row a write would have refused fails, naming the client.
fn record(row: &tokio_postgres::Row) -> Result<ClientRecord, String> {
    let client_id: String = row.get(0);
    let token = match row.get::<_, Option<Vec<u8>>>(4) {
        Some(hash) => Some(ActiveToken {
            hash: hash_of(hash, "token_hash", &client_id)?,
            expires_at: row.get::<_, Option<i64>>(5).map(unsigned),
        }),
        None => None,
    };
    let record = ClientRecord {
        secret_hash: hash_of(row.get(2), "secret_hash", &client_id)?,
        space: row.get(1),
        issued_at: unsigned(row.get(3)),
        token,
        client_id,
    };
    record
        .check()
        .map_err(|e| format!("a client in the database: {e}"))?;
    Ok(record)
}

impl ClientStore for PgClientStore {
    fn load(&self) -> Result<Vec<ClientRecord>, String> {
        self.database.run(|pool| async move {
            let client = client(&pool).await?;
            client
                .query(
                    &format!("SELECT {COLUMNS} FROM clients ORDER BY client_id"),
                    &[],
                )
                .await
                .map_err(sql)?
                .iter()
                .map(record)
                .collect()
        })
    }

    fn insert(&self, record: &ClientRecord) -> Result<bool, String> {
        record.check()?;
        let record = record.clone();
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            write(&**client, &record).await
        })
    }

    fn secret_hash(&self, client_id: &str) -> Result<Option<Hash>, String> {
        let client_id = client_id.to_string();
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            client
                .query_opt(
                    "SELECT secret_hash FROM clients WHERE client_id = $1",
                    &[&client_id],
                )
                .await
                .map_err(sql)?
                .map(|row| hash_of(row.get(0), "secret_hash", &client_id))
                .transpose()
        })
    }

    fn replace_token(&self, client_id: &str, token: &ActiveToken) -> Result<TokenReplaced, String> {
        let (client_id, token) = (client_id.to_string(), *token);
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            let Some(row) = transaction
                .query_opt(
                    "SELECT token_hash FROM clients WHERE client_id = $1 FOR UPDATE",
                    &[&client_id],
                )
                .await
                .map_err(sql)?
            else {
                return Ok(TokenReplaced::NoSuchClient);
            };
            let previous = row
                .get::<_, Option<Vec<u8>>>(0)
                .map(|hash| hash_of(hash, "token_hash", &client_id))
                .transpose()?;
            transaction
                .execute(
                    "UPDATE clients SET token_hash = $2, token_expires_at = $3 \
                     WHERE client_id = $1",
                    &[
                        &client_id,
                        &token.hash.as_slice(),
                        &token.expires_at.map(signed),
                    ],
                )
                .await
                .map_err(sql)?;
            transaction.commit().await.map_err(sql)?;
            Ok(TokenReplaced::Replaced { previous })
        })
    }

    fn find_by_token(&self, token_hash: &Hash) -> Result<Option<Admitted>, String> {
        let token_hash = *token_hash;
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            Ok(client
                .query_opt(
                    "SELECT client_id, space, token_expires_at FROM clients \
                     WHERE token_hash = $1",
                    &[&token_hash.as_slice()],
                )
                .await
                .map_err(sql)?
                .map(|row| Admitted {
                    client_id: row.get(0),
                    space: row.get(1),
                    expires_at: row.get::<_, Option<i64>>(2).map(unsigned),
                }))
        })
    }
}

/// Adds one client inside the caller's transaction, or answers `false` when its identifier is
/// taken. A token hash another client holds is an error: the unique index refuses it.
pub(crate) async fn write(
    client: &impl GenericClient,
    record: &ClientRecord,
) -> Result<bool, String> {
    let added = client
        .execute(
            "INSERT INTO clients (client_id, space, secret_hash, issued_at, token_hash, \
             token_expires_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (client_id) DO NOTHING",
            &[
                &record.client_id,
                &record.space,
                &record.secret_hash.as_slice(),
                &signed(record.issued_at),
                &record.token.map(|token| token.hash.to_vec()),
                &record.token.and_then(|token| token.expires_at).map(signed),
            ],
        )
        .await
        .map_err(sql)?;
    Ok(added == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_store::tests::client;
    use crate::fs::FsClientStore;
    use crate::postgres::testing::TestDatabase;

    const A: &str = "0192f0c4-7b1e-7d2a-9c3b-4a5d6e7f8091";
    const B: &str = "0192f0c4-7b1e-7d2a-9c3b-4a5d6e7f8092";
    const C: &str = "0192f0c4-7b1e-7d2a-9c3b-4a5d6e7f8093";

    fn token(byte: u8, expires_at: Option<u64>) -> ActiveToken {
        ActiveToken {
            hash: [byte; 32],
            expires_at,
        }
    }

    /// The port's contract on either store: a client is inserted once, found by the hash of the
    /// token it holds, and holds exactly one — overwriting it revokes the one before, which the
    /// call hands back — and all of it is still there when the store is opened again.
    fn contract(open: &dyn Fn() -> Box<dyn ClientStore>) {
        let store = open();
        assert!(store.load().expect("empty").is_empty());
        assert_eq!(store.secret_hash(A).expect("unknown"), None);
        assert_eq!(store.find_by_token(&[1; 32]).expect("unknown"), None);

        let mut with_token = client(B, "lab", 2);
        with_token.token = Some(token(0xb1, None));
        with_token.issued_at = 1 << 63;
        assert!(store.insert(&client(A, "Prod_EU", 1)).expect("insert"));
        assert!(store.insert(&with_token).expect("insert"));
        assert!(
            !store
                .insert(&client(A, "lab", 9))
                .expect("a taken id is no error"),
            "an identifier is taken once"
        );
        let mut thief = client(C, "lab", 3);
        thief.token = Some(token(0xb1, Some(1)));
        store
            .insert(&thief)
            .expect_err("a token another client holds");
        for invalid in [client("A", "lab", 1), client(C, "_lab", 1)] {
            store.insert(&invalid).expect_err("not a record to hold");
        }
        assert_eq!(
            store.load().expect("load"),
            [client(A, "Prod_EU", 1), with_token.clone()],
            "what was refused wrote nothing, and the first insert stands"
        );

        assert_eq!(store.secret_hash(A).expect("hash"), Some([1; 32]));
        assert_eq!(store.secret_hash(B).expect("hash"), Some([2; 32]));
        assert_eq!(
            store.find_by_token(&[0xb1; 32]).expect("find"),
            Some(Admitted {
                client_id: B.to_string(),
                space: "lab".to_string(),
                expires_at: None,
            })
        );

        // The first token of a client revokes nothing.
        assert_eq!(
            store
                .replace_token(A, &token(0xa1, Some(1_790_000_100)))
                .expect("replace"),
            TokenReplaced::Replaced { previous: None }
        );
        assert_eq!(
            store.find_by_token(&[0xa1; 32]).expect("find"),
            Some(Admitted {
                client_id: A.to_string(),
                space: "Prod_EU".to_string(),
                expires_at: Some(1_790_000_100),
            })
        );

        // A new token revokes the previous one and hands its hash back.
        assert_eq!(
            store
                .replace_token(B, &token(0xb2, Some(u64::MAX)))
                .expect("replace"),
            TokenReplaced::Replaced {
                previous: Some([0xb1; 32])
            }
        );
        assert_eq!(store.find_by_token(&[0xb1; 32]).expect("old"), None);
        assert_eq!(
            store
                .find_by_token(&[0xb2; 32])
                .expect("new")
                .map(|a| a.expires_at),
            Some(Some(u64::MAX))
        );
        assert_eq!(
            store.secret_hash(B).expect("hash"),
            Some([2; 32]),
            "the secret is not the token's"
        );

        // A token another client holds is refused and changes nothing; so is an unknown client.
        store
            .replace_token(B, &token(0xa1, None))
            .expect_err("another's token");
        assert_eq!(
            store
                .find_by_token(&[0xb2; 32])
                .expect("still")
                .map(|a| a.client_id),
            Some(B.to_string())
        );
        assert_eq!(
            store.replace_token(C, &token(0xc1, None)).expect("unknown"),
            TokenReplaced::NoSuchClient
        );
        assert_eq!(store.find_by_token(&[0xc1; 32]).expect("none"), None);

        // The same hash again, with another end of life, is a replacement like any other.
        assert_eq!(
            store.replace_token(A, &token(0xa1, None)).expect("again"),
            TokenReplaced::Replaced {
                previous: Some([0xa1; 32])
            }
        );
        assert_eq!(
            store
                .find_by_token(&[0xa1; 32])
                .expect("find")
                .map(|a| a.expires_at),
            Some(None)
        );

        let before = store.load().expect("load");
        assert_eq!(before.len(), 2);
        drop(store);
        assert_eq!(
            open().load().expect("reload"),
            before,
            "what reopening finds"
        );
    }

    /// Verifies: ADR-0064
    #[test]
    fn the_client_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| Box::new(FsClientStore::open(dir.path()).expect("open")));
    }

    /// Verifies: ADR-0064
    #[test]
    fn the_client_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| Box::new(PgClientStore::new(database.clone())));
    }

    /// A replacement that fails leaves the token that was, on either store.
    fn fails_part_way(store: &dyn ClientStore, refuse: &dyn Fn(), mend: &dyn Fn()) {
        let mut before = client(A, "prod", 1);
        before.token = Some(token(0xa1, Some(5)));
        assert!(store.insert(&before).expect("insert"));
        refuse();
        store
            .replace_token(A, &token(0xa2, None))
            .expect_err("the write fails");
        assert_eq!(store.load().expect("load"), [before.clone()]);
        assert!(store.find_by_token(&[0xa1; 32]).expect("old").is_some());
        assert_eq!(store.find_by_token(&[0xa2; 32]).expect("new"), None);
        mend();
        assert_eq!(
            store.replace_token(A, &token(0xa2, None)).expect("replace"),
            TokenReplaced::Replaced {
                previous: Some([0xa1; 32])
            }
        );
        assert_eq!(store.find_by_token(&[0xa1; 32]).expect("old"), None);
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_token_replacement_is_whole_or_nothing_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join(format!("clients/{A}.json"));
        fails_part_way(
            &FsClientStore::open(dir.path()).expect("open"),
            &|| crate::fs::testing::refuse(&file),
            &|| crate::fs::testing::mend(&file),
        );
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_token_replacement_is_whole_or_nothing_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        fails_part_way(
            &PgClientStore::new(test.open()),
            &|| test.refuse("clients", &format!("NEW.client_id = '{A}'")),
            &|| test.mend("clients"),
        );
    }

    /// The plaintext of a client secret and of an access token that the hashes below were made
    /// from. Nothing but their hashes reaches the store.
    const SECRET: &str = "the-client-secret-that-is-never-stored-0123456789";
    const ACCESS_TOKEN: &str = "the-access-token-that-is-never-stored-0123456789a";

    fn hashed_client() -> (ClientRecord, ActiveToken) {
        let mut record = client(A, "prod", 0);
        record.secret_hash = oauth_token::secret::hash(SECRET);
        let token = ActiveToken {
            hash: oauth_token::secret::hash(ACCESS_TOKEN),
            expires_at: Some(1_900_000_000),
        };
        (record, token)
    }

    /// Clause 4: the file of a client holds the hash of its secret and of its one token, the
    /// plaintext of neither, owner-only in an owner-only directory; and a file that is not exactly
    /// a client fails the open naming it.
    /// Verifies: ADR-0064
    #[test]
    fn a_client_file_holds_only_hashes_owner_only_and_is_checked_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FsClientStore::open(dir.path()).expect("open");
        let (record, token) = hashed_client();
        assert!(store.insert(&record).expect("insert"));
        store.replace_token(A, &token).expect("token");
        let path = dir.path().join(format!("clients/{A}.json"));
        let text = std::fs::read_to_string(&path).expect("the file is named by the client");
        for plaintext in [SECRET, ACCESS_TOKEN] {
            assert!(!text.contains(plaintext), "{text}");
        }
        for hash in [record.secret_hash, token.hash] {
            assert!(text.contains(&hex::encode(hash)), "{text}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &std::path::Path| {
                std::fs::metadata(path).expect("meta").permissions().mode() & 0o777
            };
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&dir.path().join("clients")), 0o700);
        }
        let reopened = FsClientStore::open(dir.path()).expect("reopen");
        assert_eq!(
            reopened
                .find_by_token(&token.hash)
                .expect("find")
                .map(|a| a.client_id),
            Some(A.to_string()),
            "the index is rebuilt from the files"
        );

        let good = text.clone();
        let hex_of = |byte: u8| hex::encode([byte; 32]);
        let write = |name: &str, content: &str| {
            std::fs::write(dir.path().join("clients").join(name), content).expect("write");
        };
        let same_token = good.replace(A, B);
        for (file, content) in [
            ("broken.json", "{".to_string()),
            (format!("{B}.json").as_str(), good.clone()),
            (format!("{B}.json").as_str(), same_token),
            (
                "c.json",
                good.replace(A, "c")
                    .replace(&hex::encode(token.hash), &hex_of(7))
                    .replace(&hex::encode(record.secret_hash), "short"),
            ),
            ("notes.txt", String::new()),
        ] {
            write(file, &content);
            let error = FsClientStore::open(dir.path()).map(|_| ()).expect_err(file);
            assert!(error.contains(file) || error.contains(B), "{file}: {error}");
            std::fs::remove_file(dir.path().join("clients").join(file)).expect("clean");
        }
        assert!(FsClientStore::open(dir.path()).is_ok());
    }

    /// Clause 4 on PostgreSQL: the row holds the hash of the secret and of the token and the
    /// plaintext of neither, one token's hash is one client's, and a row that is no client fails
    /// the read naming it.
    /// Verifies: ADR-0064
    #[test]
    fn a_client_row_holds_only_hashes_and_a_bad_row_is_named_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let store = PgClientStore::new(test.open());
        let (record, token) = hashed_client();
        assert!(store.insert(&record).expect("insert"));
        store.replace_token(A, &token).expect("token");
        let whole_row = test.rows("SELECT c::text FROM clients c");
        assert_eq!(whole_row.len(), 1);
        let shown = whole_row[0][0].clone().expect("a row");
        for plaintext in [SECRET, ACCESS_TOKEN] {
            assert!(!shown.contains(plaintext), "{shown}");
        }
        let hashes = test.rows(
            "SELECT encode(secret_hash, 'hex'), encode(token_hash, 'hex'), token_expires_at \
             FROM clients",
        );
        assert_eq!(
            hashes,
            [[
                Some(hex::encode(record.secret_hash)),
                Some(hex::encode(token.hash)),
                Some("1900000000".to_string()),
            ]]
        );

        test.sql("UPDATE clients SET secret_hash = '\\x0102'");
        let err = store.load().map(|_| ()).expect_err("not a hash");
        assert!(err.contains(A), "{err}");
    }
}
