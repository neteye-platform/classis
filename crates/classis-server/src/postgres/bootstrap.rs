//! The bootstrap certificates the Server issued, in PostgreSQL (ADR-0050 clause 12): the
//! PostgreSQL adapter behind [`BootstrapStore`](crate::bootstrap::BootstrapStore) — one row per
//! certificate, its PKCS#12 file in the same row, an issuance written in one transaction.

use std::sync::Arc;

use tokio_postgres::GenericClient;

use super::{client, signed, sql, unsigned, Database};
use crate::bootstrap::{BootstrapStore, Entry};
use crate::revocation::CertId;

/// The record in `bootstrap_certificates`.
pub struct PgBootstrapStore {
    database: Arc<Database>,
}

impl PgBootstrapStore {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgBootstrapStore { database }
    }

    /// Runs one statement on `id`'s row in its own transaction, and answers how many rows it
    /// touched.
    fn on_row(
        &self,
        statement: &'static str,
        id: &CertId,
        file: Option<Vec<u8>>,
    ) -> Result<u64, String> {
        let id = id.clone();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            let touched = match &file {
                Some(file) => {
                    transaction
                        .execute(statement, &[&id.issuer, &id.serial, file])
                        .await
                }
                None => {
                    transaction
                        .execute(statement, &[&id.issuer, &id.serial])
                        .await
                }
            }
            .map_err(sql)?;
            transaction.commit().await.map_err(sql)?;
            Ok(touched)
        })
    }
}

impl BootstrapStore for PgBootstrapStore {
    fn load(&self) -> Result<Vec<Entry>, String> {
        self.database.run(|pool| async move {
            let client = client(&pool).await?;
            Ok(read_all(&**client)
                .await?
                .into_iter()
                .map(|(entry, _)| entry)
                .collect())
        })
    }

    fn put(&self, entry: &Entry) -> Result<(), String> {
        let entry = entry.clone();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            write(&*transaction, &entry, None).await?;
            transaction.commit().await.map_err(sql)
        })
    }

    /// The entry and its file are one row, so this is one statement.
    fn put_with_p12(&self, entry: &Entry, file: &[u8]) -> Result<(), String> {
        let (entry, file) = (entry.clone(), file.to_vec());
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            write(&*transaction, &entry, Some(&file)).await?;
            transaction.commit().await.map_err(sql)
        })
    }

    fn remove(&self, id: &CertId) -> Result<(), String> {
        self.on_row(
            "DELETE FROM bootstrap_certificates WHERE issuer = $1 AND id_serial = $2",
            id,
            None,
        )
        .map(|_| ())
    }

    /// A file is kept in its entry's row; without the row there is nowhere to keep it.
    fn put_p12(&self, id: &CertId, file: &[u8]) -> Result<(), String> {
        let touched = self.on_row(
            "UPDATE bootstrap_certificates SET p12_file = $3 WHERE issuer = $1 AND id_serial = $2",
            id,
            Some(file.to_vec()),
        )?;
        if touched == 0 {
            return Err(format!(
                "no bootstrap certificate {}/{} to keep a PKCS#12 file for",
                id.issuer, id.serial
            ));
        }
        Ok(())
    }

    fn p12(&self, id: &CertId) -> Result<Option<Vec<u8>>, String> {
        let id = id.clone();
        self.database.run(move |pool| async move {
            let client = client(&pool).await?;
            Ok(client
                .query_opt(
                    "SELECT p12_file FROM bootstrap_certificates \
                     WHERE issuer = $1 AND id_serial = $2",
                    &[&id.issuer, &id.serial],
                )
                .await
                .map_err(sql)?
                .and_then(|row| row.get(0)))
        })
    }

    fn remove_p12(&self, id: &CertId) -> Result<(), String> {
        self.on_row(
            "UPDATE bootstrap_certificates SET p12_file = NULL \
             WHERE issuer = $1 AND id_serial = $2",
            id,
            None,
        )
        .map(|_| ())
    }
}

/// Every entry with its PKCS#12 file, if one is kept.
pub(crate) async fn read_all(
    client: &impl GenericClient,
) -> Result<Vec<(Entry, Option<Vec<u8>>)>, String> {
    Ok(client
        .query(
            "SELECT issuer, id_serial, serial, subject, key_fingerprint, issued_ms, not_after_ms, \
             ca_key, p12, p12_file FROM bootstrap_certificates ORDER BY issuer, id_serial",
            &[],
        )
        .await
        .map_err(sql)?
        .into_iter()
        .map(|row| {
            (
                Entry {
                    id: CertId {
                        issuer: row.get(0),
                        serial: row.get(1),
                    },
                    serial: row.get(2),
                    subject: row.get(3),
                    key_fingerprint: row.get(4),
                    issued_ms: unsigned(row.get(5)),
                    not_after_ms: unsigned(row.get(6)),
                    ca_key: row.get(7),
                    p12: row.get(8),
                },
                row.get(9),
            )
        })
        .collect())
}

/// Creates or replaces one entry inside the caller's transaction, with `file` as its PKCS#12 file
/// when one is given and its kept file untouched when none is.
pub(crate) async fn write(
    client: &impl GenericClient,
    entry: &Entry,
    file: Option<&[u8]>,
) -> Result<(), String> {
    let keep = if file.is_some() {
        "p12_file = EXCLUDED.p12_file"
    } else {
        "p12_file = bootstrap_certificates.p12_file"
    };
    client
        .execute(
            &format!(
                "INSERT INTO bootstrap_certificates (issuer, id_serial, serial, subject, \
                 key_fingerprint, issued_ms, not_after_ms, ca_key, p12, p12_file) VALUES ($1, \
                 $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (issuer, id_serial) DO UPDATE \
                 SET serial = EXCLUDED.serial, subject = EXCLUDED.subject, \
                 key_fingerprint = EXCLUDED.key_fingerprint, issued_ms = EXCLUDED.issued_ms, \
                 not_after_ms = EXCLUDED.not_after_ms, ca_key = EXCLUDED.ca_key, \
                 p12 = EXCLUDED.p12, {keep}"
            ),
            &[
                &entry.id.issuer,
                &entry.id.serial,
                &entry.serial,
                &entry.subject,
                &entry.key_fingerprint,
                &signed(entry.issued_ms),
                &signed(entry.not_after_ms),
                &entry.ca_key,
                &entry.p12,
                &file,
            ],
        )
        .await
        .map_err(sql)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FsBootstrapStore;
    use crate::postgres::testing::TestDatabase;

    fn entry(serial: &str, p12: bool) -> Entry {
        Entry {
            id: CertId::new(b"issuer", serial),
            serial: serial.to_string(),
            subject: "O=Kunde, CN=fleet bootstrap".to_string(),
            key_fingerprint: "00".to_string(),
            issued_ms: 1,
            not_after_ms: 2,
            ca_key: "ab".to_string(),
            p12,
        }
    }

    /// The port's contract on either store: an issuance keeps the entry and its file together, an
    /// entry written again keeps its file, the file goes alone or with its entry.
    fn contract(open: &dyn Fn() -> Box<dyn BootstrapStore>) {
        let store = open();
        assert!(store.load().expect("empty").is_empty());
        let (issued, plain) = (entry("a1", true), entry("b2", false));
        store.put_with_p12(&issued, b"file").expect("issue");
        store.put(&plain).expect("put");
        let reopened = open();
        assert_eq!(
            reopened.load().expect("load"),
            [issued.clone(), plain.clone()]
        );
        assert_eq!(
            reopened.p12(&issued.id).expect("p12"),
            Some(b"file".to_vec())
        );
        assert_eq!(reopened.p12(&plain.id).expect("p12"), None);

        let mut forgotten = issued.clone();
        forgotten.p12 = false;
        reopened.put(&forgotten).expect("put");
        assert_eq!(
            reopened.p12(&issued.id).expect("p12"),
            Some(b"file".to_vec()),
            "an entry written again keeps its file until it is removed"
        );
        reopened.remove_p12(&issued.id).expect("remove the file");
        assert_eq!(open().p12(&issued.id).expect("p12"), None);
        assert_eq!(open().load().expect("load")[0], forgotten);

        reopened
            .put_p12(&plain.id, b"other")
            .expect("a file for an entry");
        reopened.remove(&plain.id).expect("remove");
        reopened
            .remove(&plain.id)
            .expect("removing the absent is fine");
        assert_eq!(open().load().expect("load"), [forgotten]);
        assert_eq!(
            open().p12(&plain.id).expect("p12"),
            None,
            "the file went with it"
        );
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_bootstrap_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| Box::new(FsBootstrapStore::open(dir.path()).expect("open")));
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_bootstrap_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| Box::new(PgBootstrapStore::new(database.clone())));
    }

    /// With PostgreSQL the record and the file are one row, written in one transaction: an
    /// issuance that cannot be written leaves neither (ADR-0050 clause 12).
    /// Verifies: ADR-0050
    #[test]
    fn an_issuance_is_one_row_or_none() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let store = PgBootstrapStore::new(test.open());
        let issued = entry("a1", true);
        store.put_with_p12(&issued, b"file").expect("issue");
        assert_eq!(
            test.rows("SELECT count(*), count(p12_file) FROM bootstrap_certificates"),
            [[Some("1".to_string()), Some("1".to_string())]],
            "one row holds both"
        );
        test.sql(
            "ALTER TABLE bootstrap_certificates ADD CONSTRAINT small CHECK (length(p12_file) < 8)",
        );
        store
            .put_with_p12(&entry("b2", true), b"a larger file")
            .expect_err("the file cannot be kept");
        assert_eq!(store.load().expect("load"), [issued]);
    }
}
