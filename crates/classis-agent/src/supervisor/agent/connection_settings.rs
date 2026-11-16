//! The connection settings channel (ADR-0014): a restored outcome, and the transport's verdict on
//! an offer reported.

use opamp::proto::{
    ConnectionSettingsOffers, ConnectionSettingsStatus, ConnectionSettingsStatuses,
};

use super::AgentState;

impl AgentState {
    /// Restores the outcome of a previously applied connection-settings offer (ADR-0014): the
    /// persisted hash reports `APPLIED`, so a restarted Client is not re-offered what it runs.
    pub fn adopt_connection_settings(&mut self, hash: &[u8]) {
        self.protocol.set_connection_settings_status(
            settings_status(
                hash.to_vec(),
                ConnectionSettingsStatuses::Applied,
                String::new(),
            ),
            false,
        );
    }

    /// Closes the connection-settings lifecycle the transport verified (ADR-0014): `APPLIED`
    /// keeps the hash and the switch follows; `FAILED` keeps the hash too — the Baseline's
    /// gating stops the Server re-offering the exact settings this Agent could not use.
    pub fn connection_settings_outcome(&mut self, hash: &[u8], result: Result<(), &str>) {
        let status = match result {
            Ok(()) => settings_status(
                hash.to_vec(),
                ConnectionSettingsStatuses::Applied,
                String::new(),
            ),
            Err(error) => settings_status(
                hash.to_vec(),
                ConnectionSettingsStatuses::Failed,
                error.to_string(),
            ),
        };
        self.protocol.set_connection_settings_status(status, true);
    }
}

/// Whether an offer carries anything this Client can put in force (ADR-0014 clause 4): OpAMP
/// settings, or a destination for one of the three own-telemetry signals.
///
/// `other_connections` deliberately does not count. `AcceptsOtherConnectionSettings` is undeclared,
/// so a conforming Server never sends one — and acknowledging what cannot be applied is the lie this
/// whole path exists to prevent.
pub(super) fn carries_settings(offers: &ConnectionSettingsOffers) -> bool {
    offers.opamp.is_some()
        || offers.own_metrics.is_some()
        || offers.own_traces.is_some()
        || offers.own_logs.is_some()
}

/// A connection-settings status for `hash` (ADR-0014). `error_message` is empty except for
/// `FAILED`.
pub(super) fn settings_status(
    hash: Vec<u8>,
    status: ConnectionSettingsStatuses,
    error_message: String,
) -> ConnectionSettingsStatus {
    ConnectionSettingsStatus {
        last_connection_settings_hash: hash,
        status: status as i32,
        error_message,
    }
}
