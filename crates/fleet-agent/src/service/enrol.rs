//! The questionnaire's enrolment (ADR-0019 clause 17): a host not yet enrolled is carried to its
//! first certificate before its service is registered, with the bootstrap pair where it lies, or
//! the identity a `bootstrap.p12` opened to, in memory (ADR-0029).
//!
//! Nothing here is a second enrolment. It is the Client's own upstream connection (ADR-0021) —
//! the same CSR, the same pending key, the same acceptance of the offered certificate into the
//! state directory — run with the Client's own Agent alone and ended the moment that certificate
//! is stored. The instance identity it creates in the state directory is the one the service then
//! runs with.

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

use crate::config::ClientConfig;
use crate::config_init::Bootstrap;
use crate::engine::{Engine, EngineAgent};
use crate::service::runtime;
use crate::shutdown::{shutdown_channel, Shutdown};
use crate::storage::Storage;
use crate::supervisor::agent::AgentState;
use crate::transport::{self, RunOutcome};

/// The files an enrolment writes into `state_dir`, the directory included — what `service config`
/// hands to the service's account afterwards, by name rather than by walking a directory that
/// account owns.
#[must_use]
pub fn written(state_dir: &Path) -> Vec<PathBuf> {
    let mut files = vec![state_dir.to_path_buf()];
    files.extend(
        [
            crate::storage::UID_FILE,
            crate::tls::ISSUED_CERT_FILE,
            crate::tls::ISSUED_KEY_FILE,
            crate::tls::PENDING_KEY_FILE,
            crate::tls::PENDING_CSR_FILE,
            crate::connection::SETTINGS_FILE,
        ]
        .map(|name| state_dir.join(name)),
    );
    files
}

/// Enrol on a runtime of its own, until the issued certificate is stored or Ctrl-C ends the wait.
///
/// `config` is the configuration the service will run with, its `state_dir` the service's.
///
/// # Errors
/// Returns an error when the bootstrap pair cannot be read, when the state directory cannot be
/// prepared, or when the wait is interrupted before a certificate arrived.
pub fn run(config: &ClientConfig, bootstrap: &Bootstrap) -> Result<(), String> {
    let config = config.clone();
    let bootstrap = bootstrap.clone();
    runtime::daemon_runtime()?.block_on(async move {
        let (stop, shutdown) = shutdown_channel();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = stop.send(true);
        });
        runtime::on_a_worker(enrol(config, bootstrap, shutdown)).await
    })
}

/// Connect with `bootstrap` as the client identity and keep the connection until the Server's
/// certificate is in the state directory (ADR-0021 clauses 21, 22).
///
/// The request's key fingerprint is logged as the request is generated, and printed here for a
/// request an earlier, interrupted run left in flight — what the operator matches in the
/// enrolment queue. A Server that refuses the request says so in the log, and the wait goes on
/// until `shutdown`: a closed window looks the same from here, and whether to try again is the
/// operator's to decide, not this loop's.
///
/// # Errors
/// Returns an error when the bootstrap pair cannot be read, when the state directory cannot be
/// prepared, or when `shutdown` ends the wait before a certificate arrived.
pub async fn enrol(
    mut config: ClientConfig,
    bootstrap: Bootstrap,
    mut shutdown: Shutdown,
) -> Result<(), String> {
    match bootstrap {
        Bootstrap::Pair { cert, key } => {
            let tls = config.tls.get_or_insert(crate::config::TlsConfig {
                ca_file: None,
                cert_file: None,
                key_file: None,
            });
            tls.cert_file = Some(cert);
            tls.key_file = Some(key);
        }
        // The decrypted key is never written: the connection reads it from memory (ADR-0029
        // clause 7).
        Bootstrap::Pkcs12 { identity, .. } => config.bootstrap_identity = Some(identity),
    }
    // A certificate swap a crash cut short is completed before anything reads the state.
    crate::csr::recover(&config.state_dir)?;
    // Read now, so a pair that is no certificate and key is named before anything connects.
    crate::tls::client_tls(&config)?;

    let storage = Storage::new(config.state_dir.clone())
        .map_err(|e| format!("cannot prepare {}: {e}", config.state_dir.display()))?;
    // The Client's own Agent alone, taking nothing but the certificate: no Supervisor is started,
    // no remote configuration taken, and no package declared.
    let state = AgentState::new_without_remote_config(
        config.name.clone(),
        storage,
        crate::host::SystemHost,
    )
    .map_err(|e| format!("cannot restore the agent state: {e}"))?;
    let (event_tx, events) = mpsc::channel(1);
    let mut engine = Engine::with_processes(
        vec![EngineAgent {
            state,
            commands: None,
            stop: None,
            block_name: None,
        }],
        events,
        event_tx,
    );
    let telemetry = crate::telemetry::Telemetry::new();

    match crate::csr::pending_fingerprint(&config.state_dir) {
        Some(fingerprint) => println!(
            "enrolling with {}: resuming the request with key fingerprint {fingerprint}, which an \
             operator approves (Ctrl-C stops waiting)",
            config.endpoint
        ),
        None => println!(
            "enrolling with {}: an operator approves this host's request by the key fingerprint \
             logged below (Ctrl-C stops waiting)",
            config.endpoint
        ),
    }
    loop {
        let outcome = transport::run(&mut engine, &mut config, &mut shutdown, &telemetry).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(e) => {
                telemetry.shutdown();
                return Err(e);
            }
        };
        if config.is_enrolled() {
            telemetry.shutdown();
            println!(
                "enrolled: the issued certificate is in {}",
                config.state_dir.display()
            );
            return Ok(());
        }
        match outcome {
            // Offered connection settings took effect; the request goes on over the new ones.
            RunOutcome::Reconfigured => {}
            RunOutcome::Shutdown | RunOutcome::RestartForUpdate => {
                telemetry.shutdown();
                return Err(
                    "enrolment stopped before the Server issued a certificate — run the \
                            questionnaire again to resume it"
                        .to_string(),
                );
            }
        }
    }
}
