//! The Server's records in one PostgreSQL database (ADR-0050): the connection every PostgreSQL
//! adapter shares, the lock that keeps one Server per database, and the schema the Server applies
//! itself.
//!
//! The connection is TLS 1.3 on the *ring*-only client of `opamp::tls`, the database's
//! certificate verified against the public roots or the root `ca_file` names and its host name
//! checked — what libpq calls `verify-full`. Plaintext only to a loopback IP literal, and only when
//! `tls = false` says so. Every setting comes from `[database.postgres]`: the configuration is
//! built field by field, never from a connection string, and `tokio-postgres` reads no `PG*`
//! variable.
//!
//! The ports are synchronous and `tokio-postgres` is not, so the database bridges inside itself as
//! the S3 store does ([`Bridge`]): the pool lives on a runtime of its own, and every call waits on
//! a channel for its work there.

pub mod agents;
pub mod bootstrap;
pub mod configs;
pub mod deployments;
pub mod enrolment;
pub mod import;
pub mod ledger;
pub mod packages;
pub mod schema;

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use tokio_postgres::config::SslMode;
use tokio_postgres::NoTls;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::bridge::Bridge;
use crate::config::PostgresConfig;

/// How long a connection may take to be made, at startup and while the Server runs.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a call waits for a pooled connection before it fails, as a failed write fails: one
/// call fails fast rather than queueing behind a database that does not answer.
const WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one call — every round trip of its transaction, the wait for a connection included —
/// may take before it fails. The Server's callers hold their own locks while a record is written
/// (ADR-0024 clause 5), so a database that stops answering holds them this long at most. The
/// database's own timeouts below end a statement it is still working on; this one ends a call
/// whose database, or the network to it, does not answer at all.
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// What a call that writes many records may take beyond [`CALL_TIMEOUT`], per record: a rollout
/// writes every Agent it assigns in one transaction.
pub(crate) const PER_RECORD: Duration = Duration::from_millis(20);

/// What the copy of `server migrate-to-postgres` may take: the whole of an old `data_dir` in one
/// transaction, while no Server runs.
pub(crate) const IMPORT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// The database's own bounds, set on every connection: a statement, a wait for a lock, and a
/// transaction left open by a client that went away. A statement of the Server touches a few
/// rows; one that runs longer is stuck.
const SESSION_TIMEOUTS: &str = "-c statement_timeout=10s -c lock_timeout=5s \
                                -c idle_in_transaction_session_timeout=60s";

/// TCP keepalives on every connection, so a database host that is gone — the advisory lock's
/// idle connection included — is noticed within about half a minute rather than never.
const KEEPALIVES_IDLE: Duration = Duration::from_secs(15);
const KEEPALIVES_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVES_RETRIES: u32 = 3;

/// The connections the pool holds at most. The Server writes one record at a time per act, and
/// the in-memory state answers every read (ADR-0050 clause 4), so a few suffice.
const POOL_SIZE: usize = 8;

/// The name the Server's connections carry in `pg_stat_activity`.
const APPLICATION_NAME: &str = "opamp-fleet-server";

/// One database, reached through a pool, held by this Server alone while it runs.
pub struct Database {
    pool: Pool,
    /// The connection that holds the session-level advisory lock (clause 6), open for as long as
    /// the Server runs.
    _lock: tokio_postgres::Client,
    /// The server process of that connection, as `pg_stat_activity` names it.
    #[cfg_attr(not(test), allow(dead_code))]
    lock_pid: i32,
    /// Set once the lock's connection has ended: from then on another Server may hold the
    /// database, and this one refuses every call ([`run_within`](Self::run_within)).
    lost: Arc<AtomicBool>,
    /// Set while the database is dropped, so the lock's connection ending then is no loss.
    closing: Arc<AtomicBool>,
    /// `database <dbname> on <host>:<port>`, what every error names.
    name: String,
    /// What one call may take ([`CALL_TIMEOUT`]).
    bound: Duration,
    /// Dropped last: the connections' tasks run on it.
    bridge: Bridge,
}

/// The TLS of the connection, or none on the loopback.
#[derive(Clone)]
enum Tls {
    Rustls(MakeRustlsConnect),
    Plain,
}

impl Database {
    /// Connects to the database `config` names, takes its lock and brings its schema up to date
    /// (ADR-0050 clauses 5 to 7).
    ///
    /// # Errors
    /// Returns an error naming the key when the password or CA file cannot be read, naming the host
    /// and the database when it cannot be reached or another Server holds it, and naming both
    /// versions when its schema needs a newer Server.
    pub fn open(config: &PostgresConfig) -> Result<Arc<Self>, String> {
        Self::open_in(config, None)
    }

    /// [`open`](Self::open), in the schema `schema` rather than the role's default: what the tests
    /// work in, one schema each.
    pub(crate) fn open_in(
        config: &PostgresConfig,
        schema: Option<&str>,
    ) -> Result<Arc<Self>, String> {
        let database = Self::connect(config, schema)?;
        let applied = database.apply_schema(schema::MIGRATIONS)?;
        if !applied.versions.is_empty() {
            tracing::info!(
                database = %database.name,
                migrations = ?applied.versions,
                "applied the Server's schema"
            );
        }
        Ok(Arc::new(database))
    }

    /// Connects and takes the lock, and touches nothing else.
    ///
    /// # Errors
    /// As [`open`](Self::open), the schema aside.
    pub(crate) fn connect(config: &PostgresConfig, schema: Option<&str>) -> Result<Self, String> {
        Self::connect_within(config, schema, CALL_TIMEOUT)
    }

    /// [`connect`](Self::connect), its every call bounded by `bound` rather than
    /// [`CALL_TIMEOUT`]: what the tests of a database that stops answering wait for.
    pub(crate) fn connect_within(
        config: &PostgresConfig,
        schema: Option<&str>,
        bound: Duration,
    ) -> Result<Self, String> {
        let name = format!(
            "database {} on {}:{}",
            config.dbname, config.host, config.port
        );
        let password = crate::config::read_secret_file(
            "[database.postgres] password_file",
            &config.password_file,
        )?;
        let tls = tls(config)?;
        // `tokio-postgres` copies the password into its own `Config`; the one read is wiped when it
        // is dropped (ADR-0057 clauses 3 and 4).
        let pg = pg_config(config, &password, schema);
        let bridge = Bridge::new("records-postgres")?;
        let (lost, closing) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let lock = bridge
            .run({
                let (pg, tls) = (pg.clone(), tls.clone());
                let watch = LockWatch {
                    name: name.clone(),
                    lost: lost.clone(),
                    closing: closing.clone(),
                };
                bounded(bound, async move {
                    let client = connect_watched(&pg, &tls, watch).await?;
                    let row = client
                        .query_one(
                            "SELECT pg_try_advisory_lock(hashtextextended('opamp-fleet-server:' \
                             || coalesce(current_schema(), ''), 0)), pg_backend_pid()",
                            &[],
                        )
                        .await
                        .map_err(sql)?;
                    Ok::<_, String>((client, row.get::<_, bool>(0), row.get::<_, i32>(1)))
                })
            })
            .map_err(|e| format!("cannot reach the {name}: {e}"))?;
        let (lock, held, lock_pid) = lock;
        if !held {
            return Err(format!(
                "another Server holds the {name} — one Server per database; stop the other one \
                 first"
            ));
        }
        let manager = match tls {
            Tls::Rustls(tls) => Manager::from_config(
                pg,
                tls,
                ManagerConfig {
                    recycling_method: RecyclingMethod::Fast,
                },
            ),
            Tls::Plain => Manager::from_config(
                pg,
                NoTls,
                ManagerConfig {
                    recycling_method: RecyclingMethod::Fast,
                },
            ),
        };
        let pool = Pool::builder(manager)
            .max_size(POOL_SIZE)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(WAIT_TIMEOUT))
            .create_timeout(Some(CONNECT_TIMEOUT))
            .recycle_timeout(Some(CONNECT_TIMEOUT))
            .build()
            .map_err(|e| format!("cannot pool the connections to the {name}: {e}"))?;
        Ok(Database {
            pool,
            _lock: lock,
            lock_pid,
            lost,
            closing,
            name,
            bound,
            bridge,
        })
    }

    /// What every error of this database names.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Applies `migrations` in one transaction (clause 5).
    ///
    /// # Errors
    /// Returns an error naming the database when the schema needs a newer Server or a statement
    /// fails; the transaction is then rolled back and the database left as it was.
    pub(crate) fn apply_schema(
        &self,
        migrations: &'static [schema::Migration],
    ) -> Result<schema::Applied, String> {
        let ours = schema::server_version();
        self.run(move |pool| async move {
            let mut client = client(&pool).await?;
            let transaction = client.transaction().await.map_err(sql)?;
            let applied = schema::apply(&*transaction, migrations, ours).await?;
            transaction.commit().await.map_err(sql)?;
            Ok(applied)
        })
    }

    /// The Server's tables this database already holds, in the schema the Server works in.
    ///
    /// # Errors
    /// Returns an error naming the database when it cannot be asked.
    pub fn server_tables(&self) -> Result<Vec<String>, String> {
        self.run(|pool| async move {
            let client = client(&pool).await?;
            let names: Vec<String> = schema::TABLES.iter().map(ToString::to_string).collect();
            let rows = client
                .query(
                    "SELECT table_name::text FROM information_schema.tables \
                     WHERE table_schema = current_schema() AND table_name = ANY($1) \
                     ORDER BY table_name",
                    &[&names],
                )
                .await
                .map_err(sql)?;
            Ok(rows.iter().map(|row| row.get(0)).collect())
        })
    }

    /// Runs `work` on the database's runtime with the pool, and waits for it at most
    /// [`CALL_TIMEOUT`]. Every error names the database.
    ///
    /// # Errors
    /// Whatever `work` answers, named, or that it did not answer in time.
    pub(crate) fn run<T, F>(&self, work: impl FnOnce(Pool) -> F) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>> + Send + 'static,
        T: Send + 'static,
    {
        self.run_within(self.bound, work)
    }

    /// [`run`](Self::run) for a call that writes `records` records in one transaction: its bound
    /// grows by [`PER_RECORD`] for each.
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub(crate) fn run_writing<T, F>(
        &self,
        records: usize,
        work: impl FnOnce(Pool) -> F,
    ) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>> + Send + 'static,
        T: Send + 'static,
    {
        let records = u32::try_from(records).unwrap_or(u32::MAX);
        self.run_within(
            self.bound
                .saturating_add(PER_RECORD.saturating_mul(records)),
            work,
        )
    }

    /// [`run`](Self::run), bounded by `bound`.
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub(crate) fn run_within<T, F>(
        &self,
        bound: Duration,
        work: impl FnOnce(Pool) -> F,
    ) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>> + Send + 'static,
        T: Send + 'static,
    {
        if self.lost.load(Ordering::SeqCst) {
            return Err(lost_lock(&self.name));
        }
        self.bridge
            .run(bounded(bound, work(self.pool.clone())))
            .map_err(|e| format!("{}: {e}", self.name))
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::SeqCst);
    }
}

/// Why every call is refused once the lock's connection has ended.
fn lost_lock(name: &str) -> String {
    format!(
        "this Server lost its lock on the {name} — another Server may hold it now (ADR-0050 \
         clause 6), so this one writes nothing more; restart it once the database answers"
    )
}

/// What watches the connection that holds the lock.
struct LockWatch {
    name: String,
    lost: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
}

/// `work`, or an error once `bound` has passed without its answer. What it left unfinished is
/// dropped: a transaction not committed is rolled back by the database.
async fn bounded<T>(
    bound: Duration,
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::time::timeout(bound, work).await.unwrap_or_else(|_| {
        Err(format!(
            "no answer within {} ms — the database or the network to it does not answer",
            bound.as_millis()
        ))
    })
}

/// A pooled connection, or why there is none: a database lost while the Server runs fails the
/// calls that need it (clause 7).
///
/// # Errors
/// Returns an error when no connection can be had within the pool's timeouts.
pub(crate) async fn client(pool: &Pool) -> Result<Object, String> {
    pool.get()
        .await
        .map_err(|e| format!("cannot reach the database: {e}"))
}

/// A database error as text: the server's own message where it sent one.
pub(crate) fn sql(error: tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{}: {} ({})", db.severity(), db.message(), db.code().code()),
        None => match std::error::Error::source(&error) {
            Some(source) => format!("{error}: {source}"),
            None => error.to_string(),
        },
    }
}

/// The connection's settings, every one from `[database.postgres]` (clause 7) — nothing from the
/// environment, and nothing from a connection string. `schema`, when named, is the only schema
/// the connection sees.
fn pg_config(
    config: &PostgresConfig,
    password: &str,
    schema: Option<&str>,
) -> tokio_postgres::Config {
    let mut pg = tokio_postgres::Config::new();
    pg.host(&config.host)
        .port(config.port)
        .dbname(&config.dbname)
        .user(&config.user)
        .password(password)
        .application_name(APPLICATION_NAME)
        .connect_timeout(CONNECT_TIMEOUT)
        .keepalives(true)
        .keepalives_idle(KEEPALIVES_IDLE)
        .keepalives_interval(KEEPALIVES_INTERVAL)
        .keepalives_retries(KEEPALIVES_RETRIES)
        .ssl_mode(if config.tls {
            SslMode::Require
        } else {
            SslMode::Disable
        });
    match schema {
        Some(schema) => pg.options(format!("{SESSION_TIMEOUTS} -c search_path={schema}")),
        None => pg.options(SESSION_TIMEOUTS),
    };
    pg
}

/// The TLS client of clause 7: TLS 1.3 on *ring* alone, the database's certificate verified
/// against the public roots, or against the roots of `ca_file` alone when it names one, and its
/// host name checked by rustls. `None` — plaintext — only where `tls = false`, which the
/// configuration allows on a loopback IP literal alone.
fn tls(config: &PostgresConfig) -> Result<Tls, String> {
    if !config.tls {
        return Ok(Tls::Plain);
    }
    let roots = match &config.ca_file {
        Some(path) => ca_roots(path)?,
        None => rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
    };
    let client = opamp::tls::client_builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Tls::Rustls(MakeRustlsConnect::new(client)))
}

/// The roots of `[database.postgres] ca_file`.
fn ca_roots(path: &Path) -> Result<rustls::RootCertStore, String> {
    let named = |e: String| format!("[database.postgres] ca_file {}: {e}", path.display());
    let pem = std::fs::read(path).map_err(|e| named(e.to_string()))?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in opamp::tls::certificates(&pem).map_err(named)? {
        roots.add(certificate).map_err(|e| named(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(named("holds no certificate".to_string()));
    }
    Ok(roots)
}

/// One connection outside the pool, its task on the current runtime: what the tests reach the
/// database with past every adapter.
#[cfg(test)]
async fn connect(pg: &tokio_postgres::Config, tls: &Tls) -> Result<tokio_postgres::Client, String> {
    match tls {
        Tls::Rustls(tls) => {
            let (client, connection) = pg.connect(tls.clone()).await.map_err(sql)?;
            tokio::spawn(drive(connection));
            Ok(client)
        }
        Tls::Plain => {
            let (client, connection) = pg.connect(NoTls).await.map_err(sql)?;
            tokio::spawn(drive(connection));
            Ok(client)
        }
    }
}

/// The connection that holds the lock, its task on the current runtime. When it ends while the
/// Server runs — the database restarted, the session was ended, the host is gone and the
/// keepalives noticed — the lock is gone with it: the Server refuses every call from then on and
/// logs why, rather than writing on while a second Server may start.
async fn connect_watched(
    pg: &tokio_postgres::Config,
    tls: &Tls,
    watch: LockWatch,
) -> Result<tokio_postgres::Client, String> {
    let ended = move |result: Result<(), tokio_postgres::Error>| {
        if watch.closing.load(Ordering::SeqCst) {
            return;
        }
        watch.lost.store(true, Ordering::SeqCst);
        let why = result
            .err()
            .map_or_else(|| "it was closed".to_string(), sql);
        tracing::error!(
            database = %watch.name,
            error = %why,
            "{}",
            lost_lock(&watch.name)
        );
    };
    match tls {
        Tls::Rustls(tls) => {
            let (client, connection) = pg.connect(tls.clone()).await.map_err(sql)?;
            tokio::spawn(async move { ended(connection.await) });
            Ok(client)
        }
        Tls::Plain => {
            let (client, connection) = pg.connect(NoTls).await.map_err(sql)?;
            tokio::spawn(async move { ended(connection.await) });
            Ok(client)
        }
    }
}

/// Drives one connection until it ends, saying why when it ends in an error.
#[cfg(test)]
async fn drive<C>(connection: C)
where
    C: Future<Output = Result<(), tokio_postgres::Error>>,
{
    if let Err(e) = connection.await {
        tracing::warn!(error = %sql(e), "a connection to the database ended");
    }
}

/// An unsigned integer as the `bigint` that keeps it, its bits unchanged, so every value
/// round-trips.
pub(crate) fn signed(value: u64) -> i64 {
    value.cast_signed()
}

/// The unsigned integer a `bigint` keeps.
pub(crate) fn unsigned(value: i64) -> u64 {
    value.cast_unsigned()
}

#[cfg(test)]
pub(crate) mod testing {
    //! The database the PostgreSQL tests run against (ADR-0050 clause 16): the one the
    //! `FLEET_TEST_POSTGRES_*` variables name, never one the tests start. Each test works in a
    //! schema of its own and drops it afterwards.

    use std::sync::Arc;

    use super::*;

    /// One test's schema in the named database, dropped with it.
    pub(crate) struct TestDatabase {
        pub(crate) config: PostgresConfig,
        pub(crate) schema: String,
    }

    impl TestDatabase {
        /// The database the variables name, in a fresh schema; `None`, said aloud, where none is
        /// named. `FLEET_TEST_POSTGRES_CA_FILE` asks for TLS against that root; without it, the
        /// connection is plaintext, which the configuration allows to a loopback IP literal alone.
        pub(crate) fn named() -> Option<Self> {
            let variable = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
            let (Some(host), Some(dbname), Some(user), Some(password_file)) = (
                variable("FLEET_TEST_POSTGRES_HOST"),
                variable("FLEET_TEST_POSTGRES_DBNAME"),
                variable("FLEET_TEST_POSTGRES_USER"),
                variable("FLEET_TEST_POSTGRES_PASSWORD_FILE"),
            ) else {
                eprintln!(
                    "skipped: no PostgreSQL is named — set FLEET_TEST_POSTGRES_HOST, \
                     FLEET_TEST_POSTGRES_PORT, FLEET_TEST_POSTGRES_DBNAME, \
                     FLEET_TEST_POSTGRES_USER and FLEET_TEST_POSTGRES_PASSWORD_FILE to run the \
                     PostgreSQL store's tests"
                );
                return None;
            };
            let ca_file = variable("FLEET_TEST_POSTGRES_CA_FILE").map(Into::into);
            let config = PostgresConfig {
                host,
                port: variable("FLEET_TEST_POSTGRES_PORT")
                    .map_or(5432, |port| port.parse().expect("FLEET_TEST_POSTGRES_PORT")),
                dbname,
                user,
                password_file: password_file.into(),
                tls: ca_file.is_some(),
                ca_file,
            };
            let mut random = [0u8; 8];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
                .expect("random");
            let test = TestDatabase {
                config,
                schema: format!("fleet_test_{}", hex::encode(random)),
            };
            test.admin(&format!("CREATE SCHEMA {}", test.schema));
            Some(test)
        }

        /// The settings again, as a second Server start would read them.
        pub(crate) fn config(&self) -> PostgresConfig {
            PostgresConfig {
                host: self.config.host.clone(),
                port: self.config.port,
                dbname: self.config.dbname.clone(),
                user: self.config.user.clone(),
                password_file: self.config.password_file.clone(),
                ca_file: self.config.ca_file.clone(),
                tls: self.config.tls,
            }
        }

        /// A Server's database in this schema, its schema applied.
        pub(crate) fn open(&self) -> Arc<Database> {
            Database::open_in(&self.config, Some(&self.schema)).expect("open the test database")
        }

        /// Runs `statements` in this schema, past every adapter.
        pub(crate) fn sql(&self, statements: &str) {
            self.admin(&format!("SET search_path = {};\n{statements}", self.schema));
        }

        /// Makes every insert or update of `table` whose new row meets `condition` fail, as a
        /// write the database refuses part-way through a call: the failure the "fails part-way"
        /// tests inject. [`mend`](Self::mend) takes it away.
        pub(crate) fn refuse(&self, table: &str, condition: &str) {
            self.sql(&format!(
                "CREATE OR REPLACE FUNCTION fleet_test_refuse() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused by the test'; END $$; \
                 CREATE TRIGGER fleet_test_refuse BEFORE INSERT OR UPDATE ON {table} \
                 FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION fleet_test_refuse();"
            ));
        }

        /// Takes away what [`refuse`](Self::refuse) put on `table`.
        pub(crate) fn mend(&self, table: &str) {
            self.sql(&format!("DROP TRIGGER fleet_test_refuse ON {table}"));
        }

        /// The rows `query` answers in this schema, each column as text.
        pub(crate) fn rows(&self, query: &str) -> Vec<Vec<Option<String>>> {
            let (pg, tls) = self.admin_connection();
            let query = format!("SET search_path = {};", self.schema) + query;
            Bridge::new("records-test")
                .expect("runtime")
                .run(async move {
                    let client = connect(&pg, &tls).await?;
                    let messages = client.simple_query(&query).await.map_err(sql)?;
                    Ok::<_, String>(
                        messages
                            .into_iter()
                            .filter_map(|message| match message {
                                tokio_postgres::SimpleQueryMessage::Row(row) => Some(
                                    (0..row.len())
                                        .map(|i| row.get(i).map(str::to_string))
                                        .collect(),
                                ),
                                _ => None,
                            })
                            .collect(),
                    )
                })
                .expect("query")
        }

        fn admin_connection(&self) -> (tokio_postgres::Config, Tls) {
            let password =
                crate::config::read_secret_file("password_file", &self.config.password_file)
                    .expect("the test database's password");
            (
                pg_config(&self.config, &password, None),
                tls(&self.config).expect("tls"),
            )
        }

        fn admin(&self, statements: &str) {
            let (pg, tls) = self.admin_connection();
            let statements = statements.to_string();
            Bridge::new("records-test")
                .expect("runtime")
                .run(async move {
                    let client = connect(&pg, &tls).await?;
                    client.batch_execute(&statements).await.map_err(sql)
                })
                .expect("run on the test database");
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            self.admin(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TestDatabase;
    use super::*;

    fn config(host: &str, tls: bool) -> PostgresConfig {
        PostgresConfig {
            host: host.to_string(),
            port: 5432,
            dbname: "fleet".to_string(),
            user: "fleet".to_string(),
            password_file: "/nonexistent".into(),
            ca_file: None,
            tls,
        }
    }

    /// The marker that makes [`pg_variables_child`] check the environment it was started with.
    const CHILD: &str = "FLEET_TEST_PG_VARIABLES_CHILD";

    /// `PGHOST`, `PGSSLMODE` and their kin, set in the Server's environment, change neither the
    /// database nor whether plaintext is allowed: the connection is built from
    /// `[database.postgres]` alone (ADR-0050 clause 7). The environment is the real one of a child
    /// process.
    /// Verifies: ADR-0050
    #[test]
    fn pg_variables_change_neither_the_database_nor_plaintext() {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "postgres::tests::pg_variables_child",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("PGHOST", "203.0.113.9")
            .env("PGHOSTADDR", "203.0.113.9")
            .env("PGPORT", "6543")
            .env("PGDATABASE", "elsewhere")
            .env("PGUSER", "elsewhere")
            .env("PGPASSWORD", "elsewhere")
            .env("PGSSLMODE", "disable")
            .env("PGOPTIONS", "-c search_path=elsewhere")
            .output()
            .expect("run the child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The child of [`pg_variables_change_neither_the_database_nor_plaintext`]; it passes
    /// trivially when run by itself.
    #[test]
    fn pg_variables_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let pg = pg_config(&config("db.example", true), "secret", None);
        assert_eq!(
            pg.get_hosts(),
            [tokio_postgres::config::Host::Tcp("db.example".to_string())]
        );
        assert!(pg.get_hostaddrs().is_empty());
        assert_eq!(pg.get_ports(), [5432]);
        assert_eq!(pg.get_dbname(), Some("fleet"));
        assert_eq!(pg.get_user(), Some("fleet"));
        assert_eq!(pg.get_password(), Some(b"secret".as_slice()));
        assert_eq!(pg.get_ssl_mode(), SslMode::Require);
        assert_eq!(pg.get_options(), Some(SESSION_TIMEOUTS), "ours alone");
        assert!(matches!(
            tls(&config("db.example", true)),
            Ok(Tls::Rustls(_))
        ));
    }

    /// Without TLS only where `tls = false` says so; a CA file is read as roots and nothing else.
    /// Verifies: ADR-0050
    #[test]
    fn the_connection_requires_tls_unless_the_configuration_waives_it() {
        let pg = pg_config(&config("127.0.0.1", false), "secret", Some("s"));
        assert_eq!(pg.get_ssl_mode(), SslMode::Disable);
        assert_eq!(
            pg.get_options(),
            Some(format!("{SESSION_TIMEOUTS} -c search_path=s").as_str())
        );
        assert!(matches!(tls(&config("127.0.0.1", false)), Ok(Tls::Plain)));

        let dir = tempfile::tempdir().expect("tempdir");
        let mut with_ca = config("db.example", true);
        with_ca.ca_file = Some(dir.path().join("ca.pem"));
        let err = tls(&with_ca).map(|_| ()).expect_err("no file");
        assert!(err.contains("[database.postgres] ca_file"), "{err}");
        std::fs::write(dir.path().join("ca.pem"), "not a certificate").expect("write");
        let err = tls(&with_ca).map(|_| ()).expect_err("no certificate");
        assert!(err.contains("[database.postgres] ca_file"), "{err}");
    }

    /// The password comes from its file, which its owner and group alone may read; one that
    /// others may read or its group may write fails startup naming the key, before any
    /// connection is made.
    /// Verifies: ADR-0050
    #[cfg(unix)]
    #[test]
    fn a_password_file_others_may_read_fails_startup_naming_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("password");
        std::fs::write(&path, "secret\n").expect("write");
        let mut named = config("192.0.2.1", true);
        named.password_file = path.clone();
        // Others may read it, or its group may write it.
        for mode in [0o644, 0o604, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let err = Database::connect(&named, None)
                .map(|_| ())
                .expect_err("readable by others");
            assert!(
                err.contains("[database.postgres] password_file"),
                "{mode:o}: {err}"
            );
            assert!(err.contains(&path.display().to_string()), "{err}");
        }
        // Its group may read it, as an orchestrator's secret mount lets it: accepted.
        for mode in [0o640, 0o440, 0o400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(
                crate::config::read_secret_file("[database.postgres] password_file", &path)
                    .expect("group read is allowed")
                    .as_str(),
                "secret"
            );
        }
    }

    /// A database that cannot be reached fails startup naming the host and the database.
    /// Verifies: ADR-0050
    #[test]
    fn an_unreachable_database_fails_startup_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("password");
        std::fs::write(&path, "secret").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        // A port nothing listens on: the listener is bound, its port read, and dropped.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free port")
            .port();
        let mut gone = config("127.0.0.1", false);
        gone.port = port;
        gone.password_file = path;
        let err = Database::connect(&gone, None)
            .map(|_| ())
            .expect_err("nothing listens");
        assert!(
            err.contains(&format!("database fleet on 127.0.0.1:{port}")),
            "{err}"
        );
    }

    /// A listener that takes every connection and never answers: a database host that hangs.
    fn silent_listener() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepting = listener.try_clone().expect("clone");
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in accepting.incoming() {
                // Kept open, read from never, answered never.
                held.push(stream);
            }
        });
        (listener, port)
    }

    /// A database that takes the connection and never answers fails startup within the bound of
    /// one call, naming it, rather than holding the Server forever (ADR-0050 clause 7).
    /// Verifies: ADR-0050
    #[test]
    fn a_database_that_never_answers_fails_startup_within_the_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("password");
        std::fs::write(&path, "secret").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let (_listener, port) = silent_listener();
        let mut silent = config("127.0.0.1", false);
        silent.port = port;
        silent.password_file = path;
        let started = std::time::Instant::now();
        let err = Database::connect_within(&silent, None, Duration::from_millis(500))
            .map(|_| ())
            .expect_err("no answer");
        assert!(started.elapsed() < Duration::from_secs(5), "{err}");
        assert!(err.contains("no answer within 500 ms"), "{err}");
        assert!(
            err.contains(&format!("database fleet on 127.0.0.1:{port}")),
            "{err}"
        );
    }

    /// Forwards one connection between `client` and `server` until either ends, holding every
    /// byte back while `frozen` is set: a database, or the network to it, that stops answering.
    fn forward(
        client: std::net::TcpStream,
        server: std::net::TcpStream,
        frozen: &Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::io::{Read as _, Write as _};
        for (mut from, mut to) in [
            (
                client.try_clone().expect("clone"),
                server.try_clone().expect("clone"),
            ),
            (server, client),
        ] {
            let frozen = frozen.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let n = match from.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    while frozen.load(std::sync::atomic::Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = to.shutdown(std::net::Shutdown::Both);
            });
        }
    }

    /// A database that stops answering while the Server runs fails the one call that needs it
    /// within that call's bound, and the call after it as fast; the Server is held no longer
    /// (ADR-0050 clause 7). The database is reached through a proxy that is frozen mid-run.
    /// Verifies: ADR-0050
    #[test]
    fn a_database_that_stops_answering_fails_the_call_within_the_bound() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = proxy.local_addr().expect("addr").port();
        let frozen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target = (test.config.host.clone(), test.config.port);
        std::thread::spawn({
            let frozen = frozen.clone();
            move || {
                for client in proxy.incoming().flatten() {
                    let server =
                        std::net::TcpStream::connect((target.0.as_str(), target.1)).expect("db");
                    forward(client, server, &frozen);
                }
            }
        });
        let mut through = test.config();
        through.port = port;
        let bound = Duration::from_secs(1);
        let database = Arc::new(
            Database::connect_within(&through, Some(&test.schema), bound).expect("connect"),
        );
        database.apply_schema(schema::MIGRATIONS).expect("schema");
        let store = configs::PgConfigBackend::new(database.clone());
        crate::configs::ConfigBackend::load(&store).expect("answers while it answers");

        frozen.store(true, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..2 {
            let started = std::time::Instant::now();
            let err = crate::configs::ConfigBackend::remove(&store, "base").expect_err("no answer");
            assert!(
                started.elapsed() < bound + Duration::from_secs(2),
                "{:?}: {err}",
                started.elapsed()
            );
            assert!(err.contains("no answer within 1000 ms"), "{err}");
        }
        frozen.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// The CA `ca_name` and a certificate it signed for `names`, as PEM: (CA, certificate, key).
    fn signed_for(ca_name: &str, names: &[&str]) -> (String, String, String) {
        let ca_key = rcgen::KeyPair::generate().expect("key");
        let mut ca = rcgen::CertificateParams::default();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, ca_name);
        let ca_pem = ca.clone().self_signed(&ca_key).expect("ca").pem();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let key = rcgen::KeyPair::generate().expect("key");
        let names: Vec<String> = names.iter().map(ToString::to_string).collect();
        let certificate = rcgen::CertificateParams::new(names)
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("certificate");
        (ca_pem, certificate.pem(), key.serialize_pem())
    }

    /// A listener that answers PostgreSQL's `SSLRequest` with `S` and then completes a TLS 1.3
    /// handshake with `certificate` — as far as a client's verification of the database reaches.
    /// What follows the handshake is not served. Answers its port, and whether a handshake was
    /// completed.
    fn tls_database(certificate: &str, key: &str) -> (u16, Arc<AtomicBool>) {
        use std::io::{Read as _, Write as _};
        let config = Arc::new(
            opamp::tls::server_builder()
                .with_no_client_auth()
                .with_single_cert(
                    opamp::tls::certificates(certificate.as_bytes()).expect("certificate"),
                    opamp::tls::private_key(key.as_bytes()).expect("key"),
                )
                .expect("server config"),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let completed = Arc::new(AtomicBool::new(false));
        let handshaken = completed.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0u8; 8];
                // Length 8, then the SSLRequest code 80877103.
                if stream.read_exact(&mut request).is_err()
                    || request != [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]
                {
                    continue;
                }
                if stream.write_all(b"S").is_err() {
                    continue;
                }
                let mut tls = rustls::ServerConnection::new(config.clone()).expect("connection");
                while tls.is_handshaking() {
                    if tls.complete_io(&mut stream).is_err() {
                        break;
                    }
                }
                if !tls.is_handshaking() {
                    handshaken.store(true, Ordering::SeqCst);
                }
            }
        });
        (port, completed)
    }

    /// The connection is what libpq calls `verify-full`: a database whose certificate a root of
    /// `ca_file` signed but that does not name `host`, or that names it but no root of
    /// `ca_file` signed, is refused before a password is sent; one that a root signed for `host`
    /// is accepted (ADR-0050 clause 7). Run against a listener that speaks the start of the
    /// protocol, so it needs no database.
    /// Verifies: ADR-0050
    #[test]
    fn the_database_certificate_is_verified_against_its_root_and_its_host_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let password = dir.path().join("password");
        std::fs::write(&password, "secret").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        let attempt = |ca: &str, certificate: &str, key: &str| {
            let ca_file = dir.path().join(format!("ca-{}.pem", ca.len()));
            std::fs::write(&ca_file, ca).expect("write");
            let mut named = config("localhost", true);
            let (port, handshaken) = tls_database(certificate, key);
            named.port = port;
            named.password_file = password.clone();
            named.ca_file = Some(ca_file);
            let err = Database::connect_within(&named, None, Duration::from_secs(5))
                .map(|_| ())
                .expect_err("nothing serves past the handshake");
            (err, handshaken.load(Ordering::SeqCst))
        };

        let (ca, elsewhere, key) = signed_for("database CA", &["db.example"]);
        let (err, handshaken) = attempt(&ca, &elsewhere, &key);
        assert!(err.contains("not valid for name") && !handshaken, "{err}");

        let (_, local, key) = signed_for("database CA", &["localhost"]);
        let (other_ca, _, _) = signed_for("another CA", &["localhost"]);
        let (err, handshaken) = attempt(&other_ca, &local, &key);
        assert!(err.contains("UnknownIssuer") && !handshaken, "{err}");

        let (ca, local, key) = signed_for("database CA", &["localhost"]);
        let (err, handshaken) = attempt(&ca, &local, &key);
        assert!(
            handshaken,
            "a root that signed the host's name is accepted: {err}"
        );
    }

    /// What the tests of this module log, read back: the global subscriber of the test process,
    /// since the database logs from threads of its own runtime.
    fn logged() -> &'static std::sync::Mutex<Vec<u8>> {
        static LOG: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<u8>>>> =
            std::sync::OnceLock::new();
        LOG.get_or_init(|| {
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            let writer = log.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || LogBuffer(writer.clone()))
                .with_ansi(false)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            log
        })
    }

    /// A `tracing` writer into a shared buffer.
    struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A Server whose lock's connection ends while it runs notices: it logs why and refuses every
    /// call from then on, rather than writing on while a second Server may start (ADR-0050
    /// clause 6). The session is ended from the database's side, as a restart or an operator
    /// would end it.
    /// Verifies: ADR-0050
    #[test]
    fn a_server_that_loses_its_lock_logs_it_and_writes_nothing_more() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let log = logged();
        let database = test.open();
        let store = configs::PgConfigBackend::new(database.clone());
        crate::configs::ConfigBackend::remove(&store, "base").expect("writes while it holds it");

        test.sql(&format!(
            "SELECT pg_terminate_backend({})",
            database.lock_pid
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !database.lost.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the loss went unnoticed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let err = crate::configs::ConfigBackend::remove(&store, "base").expect_err("refused");
        assert!(err.contains("lost its lock"), "{err}");
        assert!(err.contains(&test.config.dbname), "{err}");
        // The flag is set before the line is written, so the Server refuses at once; the line
        // follows on the watcher's thread.
        loop {
            let logged = String::from_utf8(log.lock().expect("log").clone()).expect("utf-8");
            if logged
                .lines()
                .any(|line| line.contains("ERROR") && line.contains("lost its lock"))
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "{logged}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A second Server against the same database fails startup naming it; once the first is
    /// gone, the lock is free again.
    /// Verifies: ADR-0050
    #[test]
    fn a_second_server_against_the_same_database_fails_startup_naming_it() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let first = test.open();
        let err = Database::open_in(&test.config(), Some(&test.schema))
            .map(|_| ())
            .expect_err("held by the first");
        assert!(
            err.contains(&format!("database {}", test.config.dbname)),
            "{err}"
        );
        assert!(err.contains("one Server per database"), "{err}");
        drop(first);
        // The lock goes with its session, which the server notices when the connection closes.
        let mut reopened = None;
        for _ in 0..50 {
            if let Ok(database) = Database::open_in(&test.config(), Some(&test.schema)) {
                reopened = Some(database);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(reopened.is_some(), "the lock was not released");
    }

    /// The schema is applied at startup and recorded; a database one migration behind is migrated
    /// at startup; a database whose schema names an oldest Server above this one fails startup
    /// naming both versions and is left unchanged.
    /// Verifies: ADR-0050
    #[test]
    fn the_server_applies_its_schema_and_refuses_a_newer_one() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        static BEHIND: &[schema::Migration] = &[schema::Migration {
            version: 1,
            oldest_server: "0.1.0",
            sql: "CREATE TABLE configurations (name text PRIMARY KEY)",
        }];
        static AHEAD: &[schema::Migration] = &[
            schema::Migration {
                version: 1,
                oldest_server: "0.1.0",
                sql: "CREATE TABLE configurations (name text PRIMARY KEY)",
            },
            schema::Migration {
                version: 2,
                oldest_server: "0.1.0",
                sql: "CREATE TABLE deployments (name text PRIMARY KEY)",
            },
        ];
        {
            let database = Database::connect(&test.config(), Some(&test.schema)).expect("connect");
            assert_eq!(database.apply_schema(BEHIND).expect("first").versions, [1]);
            assert_eq!(
                database.apply_schema(BEHIND).expect("again").versions,
                Vec::<i32>::new(),
                "nothing twice"
            );
            assert_eq!(
                database.apply_schema(AHEAD).expect("one behind").versions,
                [2],
                "the migration it had not seen"
            );
            assert_eq!(
                database.server_tables().expect("tables"),
                ["configurations", "deployments", "fleet_schema"]
            );
        }

        test.sql("INSERT INTO fleet_schema (version, oldest_server) VALUES (99, '999.0.0')");
        let before = test.rows("SELECT version, oldest_server FROM fleet_schema ORDER BY version");
        let err = Database::open_in(&test.config(), Some(&test.schema))
            .map(|_| ())
            .expect_err("a newer schema");
        assert!(err.contains("999.0.0"), "{err}");
        assert!(err.contains(schema::server_version()), "{err}");
        assert!(
            err.contains(&format!("database {}", test.config.dbname)),
            "{err}"
        );
        assert_eq!(
            test.rows("SELECT version, oldest_server FROM fleet_schema ORDER BY version"),
            before,
            "left unchanged"
        );
        assert_eq!(
            test.rows(
                "SELECT count(*) FROM information_schema.tables \
                 WHERE table_schema = current_schema() AND table_name = 'agents'"
            ),
            [[Some("0".to_string())]],
            "no migration of this Server was applied"
        );
    }

    /// The whole schema applies on an empty database, and every table it names is there.
    /// Verifies: ADR-0050
    #[test]
    fn the_embedded_schema_applies_on_an_empty_database() {
        let Some(test) = TestDatabase::named() else {
            return;
        };
        let database = test.open();
        let mut tables = database.server_tables().expect("tables");
        tables.sort();
        let mut expected: Vec<String> = schema::TABLES.iter().map(ToString::to_string).collect();
        expected.sort();
        assert_eq!(tables, expected);
    }
}
