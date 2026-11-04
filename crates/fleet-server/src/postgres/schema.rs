//! The Server's schema (ADR-0050 clause 5): embedded as numbered migrations, applied by the Server
//! itself at startup, each recorded in `fleet_schema` with the oldest Server version that
//! understands the schema it leaves.
//!
//! A migration only adds — tables, columns with defaults, indexes — so the release before a change
//! runs on the schema after it. A column or table is removed only by a release after the one that
//! stopped using it. The Server creates tables, indexes and `fleet_schema`, and nothing else: the
//! database, the role, its rights and its extensions are the operator's.

use std::cmp::Ordering;

use tokio_postgres::GenericClient;

/// One step of the schema.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    /// Its number, from 1, one more than the step before it.
    pub version: i32,
    /// The oldest Server version, `MAJOR.MINOR.PATCH`, that understands the schema once this
    /// step is applied.
    pub oldest_server: &'static str,
    /// What it creates.
    pub sql: &'static str,
}

/// The table that records every migration applied.
pub const SCHEMA_TABLE: &str = "fleet_schema";

/// Every table the migrations create, so that a database holding any of them is recognised as one
/// the Server already wrote ([`super::Database::server_tables`]).
pub const TABLES: [&str; 14] = [
    "configurations",
    "configuration_revisions",
    "deployments",
    "packages",
    "package_entries",
    "agents",
    "agent_assignment_configurations",
    "hosts",
    "certificates",
    "revocations",
    "bootstrap_certificates",
    "enrolment_window",
    "enrolment_requests",
    // Not tables of the records, but the Server's all the same.
    SCHEMA_TABLE,
];

/// The schema, in order.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    oldest_server: "0.6.1",
    sql: RECORDS,
}];

/// The first schema: one table per kind of record, the parts of a record that are many in tables
/// of their own (ADR-0050 clauses 3, 8, 10 to 14). Unsigned integers are kept as `bigint` with
/// their bits unchanged, so every value round-trips.
///
/// PostgreSQL's `text` and `jsonb` refuse a NUL character, which a file keeps. Text an Agent or a
/// CSR chose — an Agent's effective configuration, a certificate's subject — is kept as `bytea`,
/// its UTF-8 bytes unchanged, and every JSON document as `json`, which keeps a `\u0000` escape
/// where `jsonb` refuses it (the Server never queries inside one). Either way the same bytes
/// round-trip as with the filesystem store, and one Agent's report can never fail the writes of
/// others or a rollout. The other `text` columns hold names and identities the Server or an
/// operator gave, each checked before it is stored.
const RECORDS: &str = r"
CREATE TABLE configurations (
    name text PRIMARY KEY,
    body text NOT NULL,
    role text NOT NULL,
    service_name text NOT NULL
);
CREATE TABLE configuration_revisions (
    configuration text NOT NULL REFERENCES configurations (name) ON DELETE CASCADE,
    hash text NOT NULL,
    body text NOT NULL,
    role text NOT NULL,
    service_name text NOT NULL,
    PRIMARY KEY (configuration, hash)
);
CREATE TABLE deployments (
    name text PRIMARY KEY,
    selector json NOT NULL,
    packages json NOT NULL,
    configurations text[] NOT NULL
);
CREATE TABLE packages (
    agent_type text NOT NULL,
    version text NOT NULL,
    PRIMARY KEY (agent_type, version)
);
CREATE TABLE package_entries (
    agent_type text NOT NULL,
    version text NOT NULL,
    os text NOT NULL,
    arch text NOT NULL,
    sha256 text NOT NULL,
    size bigint NOT NULL,
    signature bytea,
    PRIMARY KEY (agent_type, version, os, arch),
    FOREIGN KEY (agent_type, version) REFERENCES packages ON DELETE CASCADE
);
CREATE TABLE agents (
    instance_uid text PRIMARY KEY,
    sequence_num bigint NOT NULL,
    capabilities bigint NOT NULL,
    transport text NOT NULL,
    last_seen_ms bigint NOT NULL,
    restart_pending boolean NOT NULL,
    effective_config bytea,
    description bytea,
    health bytea,
    remote_config_status bytea,
    connection_settings_status bytea,
    package_statuses bytea,
    available_components bytea,
    labels json NOT NULL,
    host text,
    deployment text,
    package_agent_type text,
    package_version text
);
CREATE TABLE agent_assignment_configurations (
    instance_uid text NOT NULL REFERENCES agents ON DELETE CASCADE,
    configuration text NOT NULL,
    revision text NOT NULL,
    PRIMARY KEY (instance_uid, configuration)
);
CREATE TABLE hosts (
    host text PRIMARY KEY,
    gateway boolean NOT NULL,
    instance_uids text[] NOT NULL,
    subject json NOT NULL,
    approved_ms bigint,
    valid_until_ms bigint
);
CREATE TABLE certificates (
    issuer text NOT NULL,
    serial text NOT NULL,
    issuer_name text NOT NULL,
    subject bytea NOT NULL,
    key_fingerprint text NOT NULL,
    not_after_ms bigint NOT NULL,
    host text,
    subject_values json NOT NULL,
    instance_uid text NOT NULL,
    predecessor_issuer text,
    predecessor_serial text,
    issued_ms bigint NOT NULL,
    PRIMARY KEY (issuer, serial)
);
CREATE TABLE revocations (
    id text PRIMARY KEY,
    position integer NOT NULL,
    revoked json NOT NULL,
    revoked_ms bigint NOT NULL
);
CREATE TABLE bootstrap_certificates (
    issuer text NOT NULL,
    id_serial text NOT NULL,
    serial text NOT NULL,
    subject text NOT NULL,
    key_fingerprint text NOT NULL,
    issued_ms bigint NOT NULL,
    not_after_ms bigint NOT NULL,
    ca_key text NOT NULL,
    p12 boolean NOT NULL,
    p12_file bytea,
    PRIMARY KEY (issuer, id_serial)
);
CREATE TABLE enrolment_window (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    until_ms bigint
);
CREATE TABLE enrolment_requests (
    id text PRIMARY KEY,
    position integer NOT NULL,
    request json NOT NULL
);
";

/// This Server's version, `MAJOR.MINOR.PATCH`: the base of the version it reports, so a
/// development build understands the schema of the release it is heading for.
#[must_use]
pub fn server_version() -> &'static str {
    let current = fleet_core::version::current();
    fleet_core::version::parse(current).map_or(current, |version| version.base)
}

/// The order of two `MAJOR.MINOR.PATCH` versions; one that does not parse is above every other,
/// so a schema naming it is never taken for one this Server understands.
fn compare(a: &str, b: &str) -> Ordering {
    fleet_core::version::precedence(a, b).unwrap_or_else(|| {
        match (
            fleet_core::version::is_semver(a),
            fleet_core::version::is_semver(b),
        ) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => a.cmp(b),
        }
    })
}

/// What [`apply`] found and did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// The migrations it applied, by number; empty when the schema was current.
    pub versions: Vec<i32>,
}

/// Applies every migration of `migrations` the database has not yet seen, in order, inside the
/// transaction `client` holds, and records each. A schema whose oldest Server is above `ours` is
/// refused before anything is written, naming both versions.
///
/// # Errors
/// Returns an error when the schema needs a newer Server, or a statement fails.
pub async fn apply(
    client: &impl GenericClient,
    migrations: &[Migration],
    ours: &str,
) -> Result<Applied, String> {
    let exists: bool = client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&SCHEMA_TABLE])
        .await
        .map_err(super::sql)?
        .get(0);
    let mut seen = std::collections::BTreeSet::new();
    if exists {
        let rows = client
            .query(
                &format!("SELECT version, oldest_server FROM {SCHEMA_TABLE}"),
                &[],
            )
            .await
            .map_err(super::sql)?;
        let mut needs: Option<String> = None;
        for row in rows {
            seen.insert(row.get::<_, i32>(0));
            let oldest: String = row.get(1);
            if needs
                .as_deref()
                .is_none_or(|known| compare(&oldest, known) == Ordering::Greater)
            {
                needs = Some(oldest);
            }
        }
        if let Some(needs) = needs.filter(|needs| compare(needs, ours) == Ordering::Greater) {
            return Err(format!(
                "its schema needs Server {needs} or later, and this Server is {ours} — run a \
                 Server of {needs} or later; this one changed nothing in the database"
            ));
        }
    } else {
        client
            .batch_execute(&format!(
                "CREATE TABLE {SCHEMA_TABLE} (
                     version integer PRIMARY KEY,
                     oldest_server text NOT NULL,
                     applied_at timestamptz NOT NULL DEFAULT now()
                 )"
            ))
            .await
            .map_err(super::sql)?;
    }
    let mut applied = Applied::default();
    for migration in migrations {
        if seen.contains(&migration.version) {
            continue;
        }
        client
            .batch_execute(migration.sql)
            .await
            .map_err(|e| format!("migration {}: {}", migration.version, super::sql(e)))?;
        client
            .execute(
                &format!("INSERT INTO {SCHEMA_TABLE} (version, oldest_server) VALUES ($1, $2)"),
                &[&migration.version, &migration.oldest_server],
            )
            .await
            .map_err(super::sql)?;
        applied.versions.push(migration.version);
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The migrations are numbered from 1 without a gap, and none names a Server newer than this
    /// one — a build that refused its own schema would never start.
    /// Verifies: ADR-0050
    #[test]
    fn the_migrations_are_numbered_and_this_server_understands_them() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                migration.version,
                i32::try_from(index + 1).expect("few"),
                "numbered from 1 without a gap"
            );
            assert!(
                fleet_core::version::is_semver(migration.oldest_server),
                "{}",
                migration.oldest_server
            );
            assert_ne!(
                compare(migration.oldest_server, server_version()),
                Ordering::Greater,
                "migration {} needs a newer Server than this one",
                migration.version
            );
        }
        assert_eq!(compare("0.10.0", "0.9.0"), Ordering::Greater);
        assert_eq!(compare("not-a-version", "99.0.0"), Ordering::Greater);
    }

    /// A migration only adds (clause 5): nothing in the embedded schema drops, renames or alters a
    /// column away, and every table it creates is one [`TABLES`] knows.
    /// Verifies: ADR-0050
    #[test]
    fn a_migration_only_adds() {
        for migration in MIGRATIONS {
            let sql = migration.sql.to_ascii_uppercase();
            for removing in [
                "DROP ",
                "RENAME ",
                "TRUNCATE ",
                "DELETE FROM",
                "ALTER COLUMN",
            ] {
                assert!(
                    !sql.contains(removing),
                    "migration {} removes: {removing}",
                    migration.version
                );
            }
            for created in sql.split("CREATE TABLE ").skip(1) {
                let name = created
                    .split_whitespace()
                    .next()
                    .expect("a name")
                    .to_ascii_lowercase();
                assert!(TABLES.contains(&name.as_str()), "{name} is not in TABLES");
            }
        }
    }
}
