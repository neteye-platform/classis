//! The remote configuration channel (ADR-0017): a received configuration applied or handed to
//! the process adapter, and its outcome reported.

use opamp::proto::{AgentRemoteConfig, RemoteConfigStatus, RemoteConfigStatuses};
use tracing::{error, info, warn};

use super::AgentState;

impl AgentState {
    /// A configuration stored `APPLYING` and not yet handed to the process adapter, if any.
    pub fn take_pending_apply(&mut self) -> Option<AgentRemoteConfig> {
        self.pending_apply.take()
    }

    /// The verdict on an apply — the process adapter's for a Supervisor-backed Agent, the
    /// Engine's Supervisor-set apply for the self-Agent (ADR-0017): closes the `APPLYING` →
    /// `APPLIED`/`FAILED` lifecycle (goal 4, end to end).
    pub fn config_applied(&mut self, hash: Vec<u8>, result: Result<(), String>) {
        // The self-Agent's offer is persisted only now, on success: its hash is what a restarted
        // Client reports as applied, and that must never get ahead of the file (ADR-0017).
        if let Some(applying) = self.applying.take() {
            if result.is_ok() && applying.config_hash == hash {
                match self.storage.store_remote_config(&applying) {
                    Ok(()) => self.local.applied = Some(applying),
                    Err(e) => warn!(error = %e, "cannot store the applied configuration"),
                }
            }
        }
        self.protocol.set_remote_config_status(match result {
            Ok(()) => config_status(hash, RemoteConfigStatuses::Applied, String::new()),
            Err(error) => config_status(hash, RemoteConfigStatuses::Failed, error),
        });
    }

    /// Takes an offered configuration in and reports `APPLYING`; the outcome closes the
    /// lifecycle through [`config_applied`](Self::config_applied). Success and failure alike
    /// carry the hash the status refers to (a rejected configuration is a report, not a silence).
    ///
    /// For a Supervisor-backed Agent the entry files are stored now — the process adapter is
    /// pointed at them — and the apply is handed over as pending. The self-Agent's configuration
    /// is its Supervisor set (ADR-0017): it is left pending for the Engine's apply and stored
    /// only once that succeeded, so a restart mid-apply reports nothing as applied and the
    /// Server offers again.
    pub(super) fn apply(&mut self, config: &AgentRemoteConfig) {
        let status = if self.local.managed {
            match self.storage.store_remote_config(config) {
                Ok(()) => {
                    info!(hash = %hex::encode(&config.config_hash), "remote configuration stored; applying");
                    self.local.applied = Some(config.clone());
                    self.pending_apply = Some(config.clone());
                    config_status(
                        config.config_hash.clone(),
                        RemoteConfigStatuses::Applying,
                        String::new(),
                    )
                }
                Err(e) => {
                    error!(error = %e, "cannot store the remote configuration");
                    config_status(
                        config.config_hash.clone(),
                        RemoteConfigStatuses::Failed,
                        format!("cannot store the configuration: {e}"),
                    )
                }
            }
        } else {
            info!(hash = %hex::encode(&config.config_hash), "remote configuration received; applying to the supervisor set");
            self.pending_apply = Some(config.clone());
            self.applying = Some(config.clone());
            config_status(
                config.config_hash.clone(),
                RemoteConfigStatuses::Applying,
                String::new(),
            )
        };
        self.protocol.set_remote_config_status(status);
    }
}

/// A remote-configuration status for `hash`. `error_message` is empty except for `FAILED`.
pub(super) fn config_status(
    hash: Vec<u8>,
    status: RemoteConfigStatuses,
    error_message: String,
) -> RemoteConfigStatus {
    RemoteConfigStatus {
        last_remote_config_hash: hash,
        status: status as i32,
        error_message,
    }
}
