//! Package records in PostgreSQL (ADR-0050 clause 13): the PostgreSQL adapter behind
//! [`PackageBackend`](crate::packages::PackageBackend) — one row per Package and one per entry,
//! each entry naming its artifact by hash. The bytes are the blob store's, with either.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio_postgres::GenericClient;

use super::{client, signed, sql, unsigned, Database};
use crate::packages::{Entry, Package, PackageBackend, PackageId, Platform, ED25519_SIGNATURE_LEN};

/// The Packages in `packages` and `package_entries`.
pub struct PgPackageBackend {
    database: Arc<Database>,
}

impl PgPackageBackend {
    /// The adapter on `database`.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        PgPackageBackend { database }
    }
}

impl PackageBackend for PgPackageBackend {
    fn load(&self) -> Result<Vec<Package>, String> {
        self.database.run(|pool| async move {
            let client = client(&pool).await?;
            read_all(&**client).await
        })
    }

    fn put(&self, package: &Package) -> Result<(), String> {
        let package = package.clone();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            write(&*transaction, &package).await?;
            transaction.commit().await.map_err(sql)
        })
    }

    /// The Package and its entries go in one statement, the entries by cascade.
    fn remove(&self, id: &PackageId) -> Result<(), String> {
        let id = id.clone();
        self.database.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            transaction
                .execute(
                    "DELETE FROM packages WHERE agent_type = $1 AND version = $2",
                    &[&id.agent_type, &id.version],
                )
                .await
                .map_err(sql)?;
            transaction.commit().await.map_err(sql)
        })
    }
}

/// Every Package with its entries. A row that does not decode — an identity or platform a write
/// would refuse, a hash that is no blob's name, a signature of the wrong length — fails, naming it.
pub(crate) async fn read_all(client: &impl GenericClient) -> Result<Vec<Package>, String> {
    let mut packages: BTreeMap<PackageId, Package> = BTreeMap::new();
    for row in client
        .query("SELECT agent_type, version FROM packages", &[])
        .await
        .map_err(sql)?
    {
        let (agent_type, version): (String, String) = (row.get(0), row.get(1));
        let id = PackageId::load(&agent_type, &version)
            .map_err(|e| format!("package {agent_type}@{version} in the database: {e}"))?;
        packages.insert(
            id.clone(),
            Package {
                id,
                entries: BTreeMap::new(),
            },
        );
    }
    for row in client
        .query(
            "SELECT agent_type, version, os, arch, sha256, size, signature FROM package_entries",
            &[],
        )
        .await
        .map_err(sql)?
    {
        let (agent_type, version): (String, String) = (row.get(0), row.get(1));
        let named = |e: String| format!("package {agent_type}@{version} in the database: {e}");
        let id = PackageId::load(&agent_type, &version).map_err(named)?;
        let package = packages
            .get_mut(&id)
            .ok_or_else(|| named("an entry of a Package that is not there".to_string()))?;
        let platform = Platform::new(row.get(2), row.get(3))
            .map_err(|e| named(format!("invalid platform: {e}")))?;
        let sha256: String = row.get(4);
        let content_hash = hex::decode(&sha256)
            .ok()
            .filter(|_| crate::blobs::is_hash(&sha256))
            .ok_or_else(|| named(format!("invalid sha256 {sha256:?}")))?;
        let signature: Option<Vec<u8>> = row.get(6);
        if let Some(signature) = &signature {
            if signature.len() != ED25519_SIGNATURE_LEN {
                return Err(named(format!(
                    "invalid signature: {} bytes, not {ED25519_SIGNATURE_LEN}",
                    signature.len()
                )));
            }
        }
        package.entries.insert(
            platform.clone(),
            Entry {
                platform,
                content_hash,
                size: unsigned(row.get(5)),
                signature,
            },
        );
    }
    Ok(packages.into_values().collect())
}

/// Creates or replaces one Package, its entries exactly `package`'s, inside the caller's
/// transaction.
pub(crate) async fn write(client: &impl GenericClient, package: &Package) -> Result<(), String> {
    let id = &package.id;
    client
        .execute(
            "INSERT INTO packages (agent_type, version) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&id.agent_type, &id.version],
        )
        .await
        .map_err(sql)?;
    client
        .execute(
            "DELETE FROM package_entries WHERE agent_type = $1 AND version = $2",
            &[&id.agent_type, &id.version],
        )
        .await
        .map_err(sql)?;
    for entry in package.entries.values() {
        client
            .execute(
                "INSERT INTO package_entries (agent_type, version, os, arch, sha256, size, \
                 signature) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &id.agent_type,
                    &id.version,
                    &entry.platform.os,
                    &entry.platform.arch,
                    &hex::encode(&entry.content_hash),
                    &signed(entry.size),
                    &entry.signature,
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
    use crate::fs::FsPackageBackend;
    use crate::postgres::testing::TestDatabase;

    fn package(version: &str, platforms: &[(&str, &str, u8)]) -> Package {
        let id = PackageId::new("otelcol", version).expect("id");
        Package {
            id,
            entries: platforms
                .iter()
                .map(|(os, arch, byte)| {
                    let platform = Platform::new(os, arch).expect("platform");
                    (
                        platform.clone(),
                        Entry {
                            platform,
                            content_hash: vec![*byte; 32],
                            size: u64::from(*byte) << 40,
                            signature: (*byte % 2 == 0).then(|| vec![*byte; ED25519_SIGNATURE_LEN]),
                        },
                    )
                })
                .collect(),
        }
    }

    /// One entry as plain values: os, arch, hash, size, signature.
    type Shown = (String, String, Vec<u8>, u64, Option<Vec<u8>>);

    /// A Package as plain values, to compare.
    fn shown(package: &Package) -> (String, Vec<Shown>) {
        (
            package.id.to_string(),
            package
                .entries
                .values()
                .map(|entry| {
                    (
                        entry.platform.os.clone(),
                        entry.platform.arch.clone(),
                        entry.content_hash.clone(),
                        entry.size,
                        entry.signature.clone(),
                    )
                })
                .collect(),
        )
    }

    fn loaded(store: &dyn PackageBackend) -> Vec<(String, Vec<Shown>)> {
        let mut packages: Vec<_> = store.load().expect("load").iter().map(shown).collect();
        packages.sort();
        packages
    }

    /// The port's contract on either store: what is written is loaded back, a put replaces the
    /// entries whole, and a removal tolerates absence.
    fn contract(open: &dyn Fn() -> Box<dyn PackageBackend>) {
        let store = open();
        assert!(store.load().expect("empty").is_empty());
        let one = package("1.2.3", &[("linux", "amd64", 1), ("windows", "amd64", 2)]);
        let two = package("2.0.0", &[("darwin", "arm64", 4)]);
        store.put(&one).expect("put");
        store.put(&two).expect("put");
        assert_eq!(loaded(&*open()), [shown(&one), shown(&two)]);
        let narrowed = package("1.2.3", &[("linux", "arm64", 6)]);
        store.put(&narrowed).expect("replace");
        assert_eq!(loaded(&*open()), [shown(&narrowed), shown(&two)]);
        store.remove(&two.id).expect("remove");
        store.remove(&two.id).expect("removing the absent is fine");
        assert_eq!(loaded(&*open()), [shown(&narrowed)]);
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_package_port_contract_holds_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        contract(&|| Box::new(FsPackageBackend::open(dir.path()).expect("open")));
    }

    /// Verifies: ADR-0050
    #[test]
    fn the_package_port_contract_holds_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        contract(&|| Box::new(PgPackageBackend::new(database.clone())));
    }

    /// A put that fails part-way — on the second entry, after the first was written — leaves the
    /// Package as it was, on either store. `refuse` makes the write of the Windows entry fail;
    /// `mend` takes that away.
    fn fails_part_way(store: &dyn PackageBackend, refuse: &dyn Fn(), mend: &dyn Fn()) {
        let before = package("1.2.3", &[("linux", "amd64", 1)]);
        store.put(&before).expect("put");
        refuse();
        let broken = package("1.2.3", &[("linux", "amd64", 3), ("windows", "amd64", 2)]);
        store.put(&broken).expect_err("the second entry fails");
        mend();
        assert_eq!(loaded(store), [shown(&before)]);
    }

    /// Verifies: ADR-0050
    #[test]
    fn a_package_put_is_whole_or_nothing_on_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("packages/otelcol@1.2.3.json");
        fails_part_way(
            &FsPackageBackend::open(dir.path()).expect("open"),
            &|| crate::fs::testing::refuse(&file),
            &|| crate::fs::testing::mend(&file),
        );
    }

    /// One transaction per call, and a row that does not decode fails the load naming the
    /// Package.
    /// Verifies: ADR-0050
    #[test]
    fn a_package_put_is_whole_or_nothing_and_a_bad_row_is_named_on_postgres() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let store = PgPackageBackend::new(test.open());
        fails_part_way(
            &store,
            &|| test.refuse("package_entries", "NEW.os = 'windows'"),
            &|| test.mend("package_entries"),
        );

        test.sql("UPDATE package_entries SET sha256 = 'not-a-hash'");
        let err = store.load().map(|_| ()).expect_err("not a hash");
        assert!(err.contains("otelcol@1.2.3"), "{err}");
    }
}
