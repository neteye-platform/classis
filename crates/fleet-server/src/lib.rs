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
pub mod revocation;
pub mod throttle;
pub mod tls;
pub mod transport;

use std::sync::Arc;

use axum::Router;

use deployments::DeploymentStore;
use fleet::{AppState, PackageOffering};
use fs::{FsAgentStore, FsBlobStore, FsConfigBackend, FsDeploymentBackend, FsPackageBackend};

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
