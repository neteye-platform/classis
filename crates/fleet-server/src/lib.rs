//! The OpAMP Fleet Server (ADR-0010, ADR-0013): the control plane that tells Agents which
//! configuration they should run and records what they report back.
//!
//! A library crate so integration tests can assemble the exact router the binary serves.

#![forbid(unsafe_code)]

pub mod agent_rate;
pub mod agent_store;
pub mod api;
pub mod audit;
pub mod audit_log;
pub mod blobs;
pub mod bootstrap;
pub mod bridge;
pub mod ca;
pub mod clock;
pub mod config;
pub mod configs;
pub mod credentials;
pub mod deployments;
pub mod enrolment;
pub mod fleet;
pub mod fs;
pub mod labels;
pub mod listen;
pub mod migrate;
pub mod packages;
pub mod pki;
pub mod postgres;
pub mod revocation;
pub mod s3;
pub mod throttle;
pub mod tls;
pub mod transport;

use std::sync::Arc;

use axum::Router;

use deployments::DeploymentStore;
use fleet::{AppState, PackageOffering};
use fs::{FsAgentStore, FsBlobStore, FsConfigBackend, FsDeploymentBackend, FsPackageBackend};

/// Where the Server keeps its records (ADR-0050 clause 1): files under `data_dir`, or one
/// PostgreSQL database. The composition root asks it for each port's adapter, so the rest of the
/// Server names the ports alone.
pub enum Records {
    /// One file per record under this `data_dir` (ADR-0037).
    Files(std::path::PathBuf),
    /// One PostgreSQL database, held by this Server alone (ADR-0050).
    Postgres(Arc<postgres::Database>),
}

impl Records {
    /// Opens the store `[database]` chooses: the data directory, its layout created owner-only
    /// and checked, and with PostgreSQL the database, its lock taken and its schema applied.
    ///
    /// # Errors
    /// Returns an error naming the path or the key when the data directory or the database cannot
    /// be opened.
    pub fn open(config: &config::ServerConfig) -> Result<Self, String> {
        match config.database.postgres() {
            None => {
                fs::open_data_dir(&config.data_dir, config.blobs.s3().is_none())?;
                Ok(Records::Files(config.data_dir.clone()))
            }
            Some(database) => {
                fs::open_data_dir_beside_database(&config.data_dir, config.blobs.s3().is_none())?;
                Ok(Records::Postgres(postgres::Database::open(database)?))
            }
        }
    }

    /// The Agent records.
    ///
    /// # Errors
    /// Returns an error when the filesystem adapter's directory cannot be created.
    pub fn agents(&self) -> Result<Box<dyn agent_store::AgentStore>, String> {
        Ok(match self {
            Records::Files(dir) => Box::new(FsAgentStore::open(dir)?),
            Records::Postgres(db) => Box::new(postgres::agents::PgAgentStore::new(db.clone())),
        })
    }

    /// The Configurations.
    ///
    /// # Errors
    /// As [`agents`](Self::agents).
    pub fn configs(&self) -> Result<Box<dyn configs::ConfigBackend>, String> {
        Ok(match self {
            Records::Files(dir) => Box::new(FsConfigBackend::open(dir)?),
            Records::Postgres(db) => Box::new(postgres::configs::PgConfigBackend::new(db.clone())),
        })
    }

    /// The Deployments.
    ///
    /// # Errors
    /// As [`agents`](Self::agents).
    pub fn deployments(&self) -> Result<Box<dyn deployments::DeploymentBackend>, String> {
        Ok(match self {
            Records::Files(dir) => Box::new(FsDeploymentBackend::open(dir)?),
            Records::Postgres(db) => {
                Box::new(postgres::deployments::PgDeploymentBackend::new(db.clone()))
            }
        })
    }

    /// The Package records.
    ///
    /// # Errors
    /// As [`agents`](Self::agents).
    pub fn packages(&self) -> Result<Box<dyn packages::PackageBackend>, String> {
        Ok(match self {
            Records::Files(dir) => Box::new(FsPackageBackend::open(dir)?),
            Records::Postgres(db) => {
                Box::new(postgres::packages::PgPackageBackend::new(db.clone()))
            }
        })
    }

    /// The bootstrap certificates the Server issued.
    ///
    /// # Errors
    /// As [`agents`](Self::agents).
    pub fn bootstrap(&self) -> Result<Box<dyn bootstrap::BootstrapStore>, String> {
        Ok(match self {
            Records::Files(dir) => Box::new(fs::FsBootstrapStore::open(dir)?),
            Records::Postgres(db) => {
                Box::new(postgres::bootstrap::PgBootstrapStore::new(db.clone()))
            }
        })
    }

    /// The enrolment window and its queue.
    #[must_use]
    pub fn enrolment(&self) -> Box<dyn enrolment::EnrolmentStore> {
        match self {
            Records::Files(dir) => Box::new(fs::FsEnrolmentStore::open(dir)),
            Records::Postgres(db) => {
                Box::new(postgres::enrolment::PgEnrolmentStore::new(db.clone()))
            }
        }
    }

    /// The register, the revocation list and the Hosts.
    ///
    /// # Errors
    /// As [`agents`](Self::agents).
    pub fn ledger(&self) -> Result<Box<dyn revocation::LedgerStore>, String> {
        Ok(match self {
            Records::Files(dir) => Box::new(fs::FsLedgerStore::open(dir)?),
            Records::Postgres(db) => Box::new(postgres::ledger::PgLedgerStore::new(db.clone())),
        })
    }
}

/// The default wiring of the fleet's state to its storage adapters (ADR-0006): it lives here, in
/// the composition root, so the fleet logic names the port — [`AgentStore`](agent_store::AgentStore)
/// — and never the filesystem behind it.
impl AppState {
    /// Builds the state on the default storage adapters in the data directory `data_dir`
    /// (ADR-0037) — one JSON file per Agent, its labels inside, under `agents/`, and one per
    /// Configuration under `configurations/` — restoring every persisted Configuration and Agent
    /// record. A store that cannot be opened (or holds an unparsable file) fails startup loudly.
    ///
    /// # Errors
    /// Returns an error when a store cannot be opened or holds an unparsable record.
    pub fn new(data_dir: std::path::PathBuf) -> Result<Self, String> {
        let agents = FsAgentStore::open(&data_dir)?;
        let configs = FsConfigBackend::open(&data_dir)?;
        Self::with_stores(
            Box::new(agents),
            Box::new(configs),
            Box::new(clock::SystemClock),
        )
    }

    /// Builds the state on the adapters of `records` (ADR-0050), restoring every persisted
    /// Configuration and Agent record.
    ///
    /// # Errors
    /// Returns an error when a store cannot be opened or holds a record that does not decode.
    pub fn on(records: &Records) -> Result<Self, String> {
        Self::with_stores(
            records.agents()?,
            records.configs()?,
            Box::new(clock::SystemClock),
        )
    }
}

/// The default wiring of the package store to its filesystem adapter (ADR-0006).
impl packages::PackageStore {
    /// Opens the store in the data directory `data_dir`, loading every persisted Package
    /// (ADR-0026, ADR-0037).
    ///
    /// # Errors
    /// Returns an error when the store cannot be opened, or a Package in it cannot be read, does
    /// not match its recorded hash, or is in a layout this Server does not write.
    pub fn open(data_dir: std::path::PathBuf) -> Result<Self, String> {
        Self::with_backend(
            Box::new(FsPackageBackend::open(&data_dir)?),
            Box::new(FsBlobStore::open(&data_dir)?),
        )
    }

    /// Opens the store in the data directory `data_dir` with the artifacts in the store `[blobs]`
    /// chooses (ADR-0049 clause 2): the filesystem as [`open`](Self::open) does, or the bucket of
    /// `[blobs.s3]`. On the bucket, a referenced artifact it lacks and `data_dir/blobs/` holds is
    /// copied into it first (clause 7).
    ///
    /// # Errors
    /// Returns an error when the store cannot be opened, as [`open`](Self::open) does, when the
    /// bucket cannot be reached or listed, or when an artifact to copy does not match its name.
    pub fn open_with(
        data_dir: std::path::PathBuf,
        blobs: &config::BlobsConfig,
    ) -> Result<Self, String> {
        Self::open_on(&Records::Files(data_dir.clone()), &data_dir, blobs)
    }

    /// [`open_with`](Self::open_with), the Package records in `records` (ADR-0050) and the bytes
    /// in the store `[blobs]` chooses, the filesystem's under `data_dir`.
    ///
    /// # Errors
    /// As [`open_with`](Self::open_with).
    pub fn open_on(
        records: &Records,
        data_dir: &std::path::Path,
        blobs: &config::BlobsConfig,
    ) -> Result<Self, String> {
        let backend = records.packages()?;
        let Some(bucket) = blobs.s3() else {
            return Self::with_backend(backend, Box::new(FsBlobStore::open(data_dir)?));
        };
        let store = s3::S3BlobStore::open(bucket)?;
        let referenced: Vec<String> = backend
            .load()?
            .iter()
            .flat_map(|package| package.entries.values())
            .map(|entry| hex::encode(&entry.content_hash))
            .collect();
        s3::copy_from_filesystem(
            &data_dir.join(fs::BLOBS),
            referenced.iter().map(String::as_str),
            &store,
        )?;
        Self::with_backend(backend, Box::new(store))
    }
}

/// The default wiring of the package offering to the Deployments' filesystem adapter (ADR-0006).
impl PackageOffering {
    /// Arms the **Deployments** beside the package store, from `deployments/` in the data
    /// directory `data_dir` (ADR-0026, ADR-0037).
    ///
    /// # Errors
    /// Returns an error when the Deployments cannot be opened or one of them cannot be read.
    pub fn new(data_dir: &std::path::Path, store: packages::PackageStore) -> Result<Self, String> {
        let backend = FsDeploymentBackend::open(data_dir)?;
        let deployments = DeploymentStore::open(Box::new(backend))?;
        Ok(Self::with_deployments(store, deployments))
    }

    /// Arms the Deployments of `records` beside the package store (ADR-0050).
    ///
    /// # Errors
    /// Returns an error when the Deployments cannot be opened or one of them does not decode.
    pub fn on(records: &Records, store: packages::PackageStore) -> Result<Self, String> {
        let deployments = DeploymentStore::open(records.deployments()?)?;
        Ok(Self::with_deployments(store, deployments))
    }
}

/// The default wiring of the bootstrap record to its filesystem adapter (ADR-0006, ADR-0028).
impl bootstrap::BootstrapCertificates {
    /// Opens the record in the data directory `data_dir`, one file per certificate under
    /// `bootstrap/` (ADR-0037), forgetting what has ended.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be opened or a file in it cannot be read.
    pub fn on_disk(
        signer: Option<Box<dyn bootstrap::BootstrapSigner>>,
        data_dir: &std::path::Path,
        clock: Arc<dyn fleet::Clock>,
    ) -> Result<Self, String> {
        Self::open(
            signer,
            Box::new(fs::FsBootstrapStore::open(data_dir)?),
            clock,
        )
    }

    /// Opens the record in `records` (ADR-0050), forgetting what has ended.
    ///
    /// # Errors
    /// Returns an error when the store cannot be opened or read.
    pub fn on(
        signer: Option<Box<dyn bootstrap::BootstrapSigner>>,
        records: &Records,
        clock: Arc<dyn fleet::Clock>,
    ) -> Result<Self, String> {
        Self::open(signer, records.bootstrap()?, clock)
    }
}

/// The **Agent plane** (ADR-0013): the OpAMP endpoint, guarded by Admission (ADR-0021), and the
/// package download route beside it — behind the same handshake, and reached only with a
/// certificate of the fleet (ADR-0021 clause 23).
///
/// The download lives here rather than with the rest of `/api/v1` because the split between the
/// two planes is by *audience*, not by path: this route is the one an Agent calls, and its
/// `download_url` is resolved against the Agent's own endpoint.
pub fn agent_app(state: Arc<AppState>, admission: transport::Admission) -> Router {
    let guard = admission
        .download_guard()
        .with_agent_rate(state.agent_rate().cloned());
    transport::router(state.clone(), admission).merge(transport::guard_download(
        api::download_router(state),
        guard,
    ))
}

/// The **Operator plane** (ADR-0013): the REST API, its OpenAPI document and docs page, and the
/// bundled UI — on their own listener, guarded as a whole by `[rest.auth]` when one is configured
/// (ADR-0021). Without it the plane is open, which is what its loopback default is for.
pub fn operator_app(state: Arc<AppState>, auth: Option<api::OperatorAuth>) -> Router {
    api::router(state, auth)
}
