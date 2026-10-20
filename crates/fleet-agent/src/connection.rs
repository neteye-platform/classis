//! Server-offered connection settings (ADR-0014): persistence, their precedence over
//! `supervisor.toml`, and the verify-by-actually-connecting the Baseline requires.
//!
//! The persisted file is the Baseline's own `ConnectionSettingsOffers` protobuf — the merged
//! settings currently in force plus the hash that reports them `APPLIED`. It lives at the
//! `state_dir` root because the settings belong to the Client's one upstream connection, not to
//! any single Agent. Deleting the file reverts to `supervisor.toml`.

use std::path::Path;

use opamp::proto::{
    AgentToServer, ConnectionSettingsOffers, OpAmpConnectionSettings, TelemetryConnectionSettings,
};
use prost::Message;
use tracing::warn;

use crate::config::ClientConfig;

/// The persisted connection settings, in the state directory.
pub const SETTINGS_FILE: &str = "connection-settings.pb";

/// The persisted settings in force, or `None` on a fresh state dir (an unreadable file is
/// dropped with a warning — `supervisor.toml` then applies, never a half-read override).
///
/// The settings carry no `headers`: a file may hold an `Authorization` header from a credential
/// rotation, and it is dropped here, so it is never sent (ADR-0014 clause 9). The file is then
/// rewritten without it, best-effort, so the credential leaves the disk and the warning appears
/// once; a failed rewrite is warned about and never fails the load.
pub fn load(state_dir: &Path) -> Option<ConnectionSettingsOffers> {
    let path = state_dir.join(SETTINGS_FILE);
    let bytes = std::fs::read(&path).ok()?;
    match ConnectionSettingsOffers::decode(bytes.as_slice()) {
        Ok(mut stored) => {
            if let Some(headers) = stored.opamp.as_mut().and_then(|s| s.headers.take()) {
                let keys: Vec<&str> = headers.headers.iter().map(|h| h.key.as_str()).collect();
                warn!(
                    file = %path.display(),
                    headers = %keys.join(", "),
                    "persisted connection headers dropped; this Client sends none"
                );
                if let Err(e) = store(state_dir, &stored) {
                    warn!(
                        file = %path.display(),
                        error = %e,
                        "could not rewrite connection settings without the dropped headers"
                    );
                }
            }
            Some(stored)
        }
        Err(e) => {
            warn!(file = %path.display(), error = %e, "unreadable connection settings; ignoring");
            None
        }
    }
}

/// Persists the settings now in force as the Baseline's own protobuf.
///
/// The file outranks `supervisor.toml` (ADR-0014 clause 9) — it decides where this Client connects
/// and which certificate it presents — so it is written no wider than its owner, and the state
/// directory holding it no wider than `0700`. On Windows the directory ACL under `%ProgramData%`
/// protects it (ADR-0019); there is no mode to set.
pub fn store(state_dir: &Path, settings: &ConnectionSettingsOffers) -> std::io::Result<()> {
    crate::storage::create_private_dir(state_dir)?;
    crate::storage::write_private(&state_dir.join(SETTINGS_FILE), &settings.encode_to_vec())
}

/// Folds a verified offer over what was already in force.
///
/// The **OpAMP** settings carry only what changes — a heartbeat-only offer must not erase a
/// previously offered endpoint, and vice versa. Offered `headers` are never folded in: this Client
/// applies none (ADR-0014 clause 8). The **own-telemetry** destinations do not: an offer
/// that names any of them states all three (ADR-0016). The two rules live in one function because
/// one message carries both, and the difference between them is the whole of what this fold does.
pub fn merge(
    stored: Option<&ConnectionSettingsOffers>,
    offer: &ConnectionSettingsOffers,
) -> ConnectionSettingsOffers {
    let previous = stored.and_then(|s| s.opamp.as_ref());
    let offered = offer.opamp.as_ref();
    let pick = |field: fn(&OpAmpConnectionSettings) -> bool| -> Option<OpAmpConnectionSettings> {
        offered.filter(|s| field(s)).or(previous).cloned()
    };
    // The own-telemetry destinations do not fold per signal (ADR-0016). An offer that names any of
    // the three states all three: a signal it leaves out is *stopped*, and a signal whose endpoint
    // it offers empty is withdrawn. An offer that names none of them says nothing about telemetry
    // — an OpAMP endpoint move, a heartbeat, a certificate — and leaves all three alone.
    //
    // The line is between messages, not between fields, and that is what keeps it compatible with
    // the schema's per-field "if this field is not set … the settings are unchanged": unchanged
    // holds for an offer that is silent about telemetry. For one that speaks about it, the message
    // is the whole state — the reading the reference implementation has, and the only one in which
    // a destination can ever be taken away.
    let states_telemetry =
        offer.own_metrics.is_some() || offer.own_traces.is_some() || offer.own_logs.is_some();
    let telemetry = |offered: Option<&TelemetryConnectionSettings>,
                     previous: Option<&TelemetryConnectionSettings>| {
        if states_telemetry {
            offered
                .filter(|s| !s.destination_endpoint.is_empty())
                .cloned()
        } else {
            previous.cloned()
        }
    };
    ConnectionSettingsOffers {
        hash: offer.hash.clone(),
        own_metrics: telemetry(
            offer.own_metrics.as_ref(),
            stored.and_then(|s| s.own_metrics.as_ref()),
        ),
        own_traces: telemetry(
            offer.own_traces.as_ref(),
            stored.and_then(|s| s.own_traces.as_ref()),
        ),
        own_logs: telemetry(
            offer.own_logs.as_ref(),
            stored.and_then(|s| s.own_logs.as_ref()),
        ),
        // Built only when one of the two sides actually has OpAMP settings (ADR-0014 clause 9).
        // Emitting a block unconditionally would have a telemetry-only offer persist the claim that
        // the Server offered OpAMP settings it never offered — a lie in the one file an operator is
        // told to inspect and delete, and one that makes the honest assertion untestable.
        opamp: (offered.is_some() || previous.is_some()).then(|| OpAmpConnectionSettings {
            destination_endpoint: pick(|s| !s.destination_endpoint.is_empty())
                .map(|s| s.destination_endpoint)
                .unwrap_or_default(),
            // The issued client identity (ADR-0021). Folded like every other field: a later offer
            // that says nothing about the certificate leaves the one in force alone, which is what
            // makes an endpoint move safe for a fleet already on mutual TLS.
            certificate: pick(|s| s.certificate.is_some()).and_then(|s| s.certificate),
            heartbeat_interval_seconds: pick(|s| s.heartbeat_interval_seconds != 0)
                .map(|s| s.heartbeat_interval_seconds)
                .unwrap_or_default(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// What to report for an offer that has been verified and applied: `Ok` when the Client honoured
/// all of it, `Err` naming the fields it dropped (ADR-0014 clause 8).
///
/// The Client applies what it understands and then says so. Reporting `APPLIED` for an offer whose
/// `tls`, `proxy` or `headers` it discarded tells the Server the settings are in force when they
/// are not, and the Server has no way to find out. `FAILED` with the field names is the honest
/// answer; the hash is echoed either way, so this does not put the Server into a re-offer loop.
///
/// None of the three is honoured, on purpose. `TLSConnectionSettings` is mostly a way to weaken
/// verification — `insecure_skip_verify` would let a Server switch off the check that proves it is
/// the Server — and trust here is an operator's file (ADR-0013). `ProxyConnectionSettings` has
/// nothing on this Client to configure. Offered `headers` have no reader on the Agent plane, which
/// admits by client certificate alone (ADR-0021): an applied one would be a value the Server plants
/// on every connection of the fleet. They are named by their keys, never their values — the
/// message travels to the Server and into the log file.
pub fn unhonoured(settings: &OpAmpConnectionSettings) -> Result<(), String> {
    let mut dropped = Vec::new();
    if settings.tls.is_some() {
        dropped.push("tls".to_string());
    }
    if settings.proxy.is_some() {
        dropped.push("proxy".to_string());
    }
    if let Some(headers) = &settings.headers {
        let keys: Vec<&str> = headers.headers.iter().map(|h| h.key.as_str()).collect();
        dropped.push(format!("headers ({})", keys.join(", ")));
    }
    if dropped.is_empty() {
        return Ok(());
    }
    Err(format!(
        "applied everything else, but this Client does not implement the offered {} \
         connection settings",
        dropped.join(" and ")
    ))
}

/// Applies persisted settings over the loaded `supervisor.toml` (ADR-0014): the Server's word wins
/// where it spoke — endpoint and heartbeat (on plain HTTP the same value is the polling interval,
/// the Baseline's MUST) — and the file's word stays everywhere else, except for a plaintext
/// endpoint the file does not name (ADR-0040 clause 3).
pub fn apply(config: &mut ClientConfig, stored: &ConnectionSettingsOffers) {
    let Some(settings) = &stored.opamp else {
        return;
    };
    let endpoint = &settings.destination_endpoint;
    if opamp::endpoint::is_plaintext(endpoint) && *endpoint != config.endpoint {
        // A move to plaintext persisted before it was refused: `supervisor.toml` decides where this
        // Client connects, so a host moved there returns at its next start (ADR-0040 clause 3).
        warn!(
            persisted = %endpoint,
            configured = %config.endpoint,
            "not applying a persisted plaintext endpoint; connecting to the configured one"
        );
    } else if !endpoint.is_empty() {
        config.endpoint = endpoint.clone();
    }
    if settings.heartbeat_interval_seconds != 0 {
        config.heartbeat_interval_secs = settings.heartbeat_interval_seconds;
        config.poll_interval_secs = settings.heartbeat_interval_seconds;
    }
}

/// Verifies an offer by actually connecting (the Baseline's MUST) with the candidate settings:
/// offered fields, falling back to the current ones. A WebSocket candidate must complete its
/// handshake; a plain-HTTP candidate must complete a real exchange, fed by `probe_report`. The
/// current TLS trust override applies to the candidate too. Offered `headers` are never used, and
/// no `Authorization` is sent (ADR-0014 clauses 5, 8).
pub async fn verify(
    settings: &OpAmpConnectionSettings,
    config: &ClientConfig,
    probe_report: impl FnOnce() -> Option<AgentToServer>,
) -> Result<(), String> {
    let endpoint = if settings.destination_endpoint.is_empty() {
        config.endpoint.clone()
    } else {
        settings.destination_endpoint.clone()
    };
    // A move to another TLS endpoint is taken only where this Client's own CA file can vouch for
    // it: under the public roots alone, a Server could move the fleet to any host a public CA
    // ever certified, and keep it there (ADR-0014 clause 5).
    let moves = endpoint != config.endpoint;
    // Nor is a move to plaintext taken, on the loopback neither: no certificate would prove the
    // Server, and whoever listens on that port would be it (ADR-0040 clause 2).
    if moves && opamp::endpoint::is_plaintext(&endpoint) {
        return Err(format!(
            "refusing the offered endpoint {endpoint}: an offer never moves this Client to \
             plaintext; a plaintext endpoint on the loopback is set in supervisor.toml"
        ));
    }
    let over_tls = endpoint.starts_with("wss://") || endpoint.starts_with("https://");
    if moves && over_tls && config.ca_file().is_none() {
        return Err(format!(
            "refusing the offered endpoint {endpoint}: a move to another endpoint needs [tls] \
             ca_file, so that only a server certificate from the fleet's own CA is trusted"
        ));
    }
    // An offered client certificate is proved the same way the endpoint is: by connecting with it
    // (ADR-0014 clause 5). Until that succeeds the one in force stays in force, so a
    // certificate that cannot authenticate costs nothing.
    let candidate_cert = settings
        .certificate
        .as_ref()
        .map(|certificate| certificate.cert.as_slice())
        .filter(|cert| !cert.is_empty());

    let tls = crate::tls::client_tls_for(config, candidate_cert)?;
    let mut candidate = crate::transport::connection_with(config, tls);
    candidate.endpoint = endpoint;
    opamp::client::connection::probe(&candidate, probe_report).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use opamp::proto::{Header, Headers, TlsCertificate};

    fn offer_with(
        hash: &[u8],
        endpoint: &str,
        certificate: Option<&str>,
        heartbeat: u64,
    ) -> ConnectionSettingsOffers {
        ConnectionSettingsOffers {
            hash: hash.to_vec(),
            opamp: Some(OpAmpConnectionSettings {
                destination_endpoint: endpoint.to_string(),
                certificate: certificate.map(|pem| TlsCertificate {
                    cert: pem.as_bytes().to_vec(),
                    ..Default::default()
                }),
                heartbeat_interval_seconds: heartbeat,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The certificate an OpAMP settings block carries, as text.
    fn certificate_of(settings: &OpAmpConnectionSettings) -> Option<String> {
        let certificate = settings.certificate.as_ref()?;
        Some(String::from_utf8_lossy(&certificate.cert).into_owned())
    }

    /// Offered headers: an `Authorization` the Server plants, and one more.
    fn planted_headers() -> Headers {
        Headers {
            headers: vec![
                Header {
                    key: "Authorization".to_string(),
                    value: "Bearer planted-value".to_string(),
                },
                Header {
                    key: "X-Fleet".to_string(),
                    value: "other-value".to_string(),
                },
            ],
        }
    }

    fn telemetry_only(hash: &[u8], endpoint: &str) -> ConnectionSettingsOffers {
        ConnectionSettingsOffers {
            hash: hash.to_vec(),
            own_metrics: Some(TelemetryConnectionSettings {
                destination_endpoint: endpoint.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Clause 6: what is persisted says only what was offered. A telemetry-only offer against a
    /// fresh state directory must not leave behind an empty `opamp` block claiming the Server
    /// offered settings it never sent.
    /// Verifies: ADR-0014
    #[test]
    fn merge_leaves_opamp_absent_when_neither_side_has_one() {
        let merged = merge(None, &telemetry_only(b"t1", "https://x/v1/metrics"));
        assert!(merged.opamp.is_none());
        assert!(merged.own_metrics.is_some());
        assert_eq!(merged.hash, b"t1");
    }

    /// ADR-0016 rule 17: an offer that names any telemetry destination states all three. The
    /// traces endpoint in force is *stopped* by a metrics-only offer, not carried forward — which
    /// is the whole difference between a fleet that can turn a signal off and one that cannot.
    /// Verifies: ADR-0016
    #[test]
    fn an_offer_naming_one_signal_stops_the_others() {
        let mut stored = telemetry_only(b"t1", "https://x/v1/metrics");
        stored.own_traces = Some(TelemetryConnectionSettings {
            destination_endpoint: "https://x/v1/traces".to_string(),
            ..Default::default()
        });

        let merged = merge(
            Some(&stored),
            &telemetry_only(b"t2", "https://y/v1/metrics"),
        );

        assert_eq!(
            merged.own_metrics.expect("metrics").destination_endpoint,
            "https://y/v1/metrics",
            "the offered destination replaces the one in force"
        );
        assert!(
            merged.own_traces.is_none(),
            "a signal the offer does not name is stopped"
        );
    }

    /// Rule 2: an offer that names none of the three says nothing about telemetry. An issued
    /// certificate must not take the exporters down with it — that is what keeps the classes of
    /// ADR-0014 independent, and it is the schema's own "not set means unchanged", held at the
    /// level it still holds at.
    /// Verifies: ADR-0016
    #[test]
    fn an_offer_silent_about_telemetry_leaves_all_three_alone() {
        let mut stored = telemetry_only(b"t1", "https://x/v1/metrics");
        stored.own_logs = Some(TelemetryConnectionSettings {
            destination_endpoint: "https://x/v1/logs".to_string(),
            ..Default::default()
        });

        let merged = merge(Some(&stored), &offer_with(b"h2", "", Some("issued"), 0));

        assert_eq!(
            merged.own_metrics.expect("metrics").destination_endpoint,
            "https://x/v1/metrics"
        );
        assert_eq!(
            merged.own_logs.expect("logs").destination_endpoint,
            "https://x/v1/logs"
        );
    }

    /// Rule 3: an endpoint offered empty withdraws that signal — the only way to say "all three
    /// off", since by rule 2 an offer that names nothing means "unchanged". The withdrawal leaves
    /// the persisted state, so a restart does not bring the destination back.
    /// Verifies: ADR-0016
    #[test]
    fn an_empty_endpoint_withdraws_the_signal() {
        let stored = telemetry_only(b"t1", "https://x/v1/metrics");
        let merged = merge(Some(&stored), &telemetry_only(b"t2", ""));

        assert!(
            merged.own_metrics.is_none(),
            "an empty endpoint is a withdrawal, not a destination"
        );
        assert_eq!(merged.hash, b"t2", "and it is acknowledged like any offer");
    }

    /// And the fold still works the other way: a telemetry-only offer arriving over settings
    /// already in force leaves the OpAMP endpoint, heartbeat and certificate exactly where they were.
    /// Verifies: ADR-0014
    #[test]
    fn merge_of_a_telemetry_only_offer_carries_the_opamp_settings_in_force_forward() {
        let stored = offer_with(b"h1", "wss://server/v1/opamp", Some("issued"), 20);
        let merged = merge(
            Some(&stored),
            &telemetry_only(b"t2", "https://x/v1/metrics"),
        );

        let opamp = merged.opamp.expect("the settings in force survive");
        assert_eq!(opamp.destination_endpoint, "wss://server/v1/opamp");
        assert_eq!(opamp.heartbeat_interval_seconds, 20);
        assert_eq!(certificate_of(&opamp).as_deref(), Some("issued"));
        assert!(merged.own_metrics.is_some());
        assert_eq!(merged.hash, b"t2", "the new offer's hash is acknowledged");
    }

    /// Verifies: ADR-0014
    #[test]
    fn load_store_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load(dir.path()).is_none(), "fresh state dir holds nothing");
        let settings = offer_with(b"h1", "wss://x/v1/opamp", Some("issued"), 20);
        store(dir.path(), &settings).expect("store");
        let restored = load(dir.path()).expect("restored");
        assert_eq!(restored.hash, b"h1");
        assert_eq!(
            restored.opamp.unwrap().destination_endpoint,
            "wss://x/v1/opamp"
        );
    }

    /// The persisted file outranks `supervisor.toml` — it decides where this Client connects and
    /// what it presents — so it, and the directory it sits in, are no one else's on the host.
    /// Verifies: ADR-0014
    #[cfg(unix)]
    #[test]
    fn stored_settings_and_their_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("state");
        store(
            &state_dir,
            &offer_with(b"h1", "wss://x/v1/opamp", Some("issued"), 20),
        )
        .expect("store");

        let file_mode = state_dir
            .join(SETTINGS_FILE)
            .metadata()
            .expect("file metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600, "the settings file is owner-only");
        let dir_mode = state_dir
            .metadata()
            .expect("dir metadata")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "the state directory is owner-only");
    }

    /// Verifies: ADR-0014
    #[test]
    fn merge_keeps_unchanged_fields_from_the_previous_settings() {
        let stored = offer_with(b"h1", "wss://old/v1/opamp", Some("old"), 30);
        // A certificate-only offer: a new certificate, no endpoint, no heartbeat.
        let offer = offer_with(b"h2", "", Some("new"), 0);
        let merged = merge(Some(&stored), &offer);
        let settings = merged.opamp.expect("opamp");
        assert_eq!(merged.hash, b"h2", "the merged hash is the new offer's");
        assert_eq!(
            settings.destination_endpoint, "wss://old/v1/opamp",
            "the endpoint carries over"
        );
        assert_eq!(certificate_of(&settings).as_deref(), Some("new"));
        assert_eq!(
            settings.heartbeat_interval_seconds, 30,
            "the heartbeat carries over"
        );
    }

    /// Verifies: ADR-0014
    #[test]
    fn apply_overrides_client_toml_where_the_server_spoke() {
        let mut config = ClientConfig {
            endpoint: "ws://file/v1/opamp".to_string(),
            heartbeat_interval_secs: 30,
            poll_interval_secs: 30,
            ..ClientConfig::default()
        };
        let stored = offer_with(b"h1", "wss://server/v1/opamp", Some("issued"), 12);
        apply(&mut config, &stored);
        assert_eq!(config.endpoint, "wss://server/v1/opamp");
        // On plain HTTP the offered interval is the polling interval too (the Baseline's MUST).
        assert_eq!(config.heartbeat_interval_secs, 12);
        assert_eq!(config.poll_interval_secs, 12);
    }

    /// Verifies: ADR-0014
    #[test]
    fn apply_leaves_untouched_what_the_offer_omits() {
        let mut config = ClientConfig {
            endpoint: "ws://file/v1/opamp".to_string(),
            heartbeat_interval_secs: 30,
            ..ClientConfig::default()
        };
        // Endpoint-only offer: the heartbeat and polling intervals stay whatever the file said.
        let stored = offer_with(b"h1", "wss://server/v1/opamp", None, 0);
        apply(&mut config, &stored);
        assert_eq!(config.endpoint, "wss://server/v1/opamp");
        assert_eq!(config.heartbeat_interval_secs, 30);
        assert_eq!(config.poll_interval_secs, 30);
    }

    /// An offer's `tls` and `proxy` are not taken: what is stored carries neither, so the
    /// connection keeps the operator's trust, and the report names both rather than claiming the
    /// offer was applied whole.
    /// Verifies: ADR-0014
    #[test]
    fn offered_tls_and_proxy_are_neither_stored_nor_claimed() {
        use opamp::proto::{ProxyConnectionSettings, TlsConnectionSettings};
        let mut offer = offer_with(b"h1", "wss://server.example/v1/opamp", None, 0);
        if let Some(settings) = offer.opamp.as_mut() {
            settings.tls = Some(TlsConnectionSettings {
                insecure_skip_verify: true,
                ca_pem_contents: "-----BEGIN CERTIFICATE-----".to_string(),
                ..Default::default()
            });
            settings.proxy = Some(ProxyConnectionSettings {
                url: "http://proxy.example:3128".to_string(),
                ..Default::default()
            });
        }
        let stored = merge(None, &offer);
        let settings = stored.opamp.as_ref().expect("the OpAMP half");
        assert_eq!(
            settings.destination_endpoint,
            "wss://server.example/v1/opamp"
        );
        assert!(settings.tls.is_none(), "an offered tls was stored");
        assert!(settings.proxy.is_none(), "an offered proxy was stored");

        let mut config = ClientConfig::default();
        apply(&mut config, &stored);
        assert_eq!(config.endpoint, "wss://server.example/v1/opamp");

        let reported = unhonoured(offer.opamp.as_ref().expect("offer")).expect_err("named");
        assert!(reported.contains("tls and proxy"), "{reported}");
    }

    /// Offered `headers` are dropped like `tls` and `proxy`: the rest of the offer is stored and
    /// applied, nothing of the headers is, and the report names them by their keys, never by a
    /// value.
    /// Verifies: ADR-0014
    #[test]
    fn offered_headers_are_neither_stored_nor_claimed() {
        let mut offer = offer_with(b"h1", "wss://server.example/v1/opamp", Some("issued"), 15);
        if let Some(settings) = offer.opamp.as_mut() {
            settings.headers = Some(planted_headers());
        }
        let stored = merge(None, &offer);
        let settings = stored.opamp.as_ref().expect("the OpAMP half");
        assert!(settings.headers.is_none(), "offered headers were stored");
        assert_eq!(
            settings.destination_endpoint,
            "wss://server.example/v1/opamp"
        );
        assert_eq!(certificate_of(settings).as_deref(), Some("issued"));
        assert_eq!(settings.heartbeat_interval_seconds, 15);

        let reported = unhonoured(offer.opamp.as_ref().expect("offer")).expect_err("named");
        assert!(reported.contains("headers"), "{reported}");
        assert!(reported.contains("Authorization"), "{reported}");
        assert!(reported.contains("X-Fleet"), "{reported}");
        assert!(!reported.contains("planted-value"), "{reported}");
        assert!(!reported.contains("other-value"), "{reported}");
    }

    /// A persisted file holds the `Authorization` header of a credential rotation. Loading it drops
    /// the header and keeps the rest, so nothing of it is ever sent, and rewrites the file without
    /// it, so the credential leaves the disk.
    /// Verifies: ADR-0014
    #[test]
    fn a_persisted_authorization_header_is_dropped_on_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut earlier = offer_with(b"h1", "wss://x/v1/opamp", None, 20);
        if let Some(settings) = earlier.opamp.as_mut() {
            settings.headers = Some(planted_headers());
        }
        // Written past `store`, headers included.
        std::fs::write(dir.path().join(SETTINGS_FILE), earlier.encode_to_vec()).expect("write");

        let loaded = load(dir.path()).expect("loaded");
        assert_eq!(
            loaded.hash, b"h1",
            "the hash still reports the settings applied"
        );
        let settings = loaded.opamp.as_ref().expect("opamp");
        assert!(
            settings.headers.is_none(),
            "a persisted header survived the load"
        );
        assert_eq!(settings.destination_endpoint, "wss://x/v1/opamp");

        let mut config = ClientConfig::default();
        apply(&mut config, &loaded);
        let connection = crate::transport::connection(&config).expect("connection");
        assert_eq!(connection.authorization, None);

        // The planted credential has left the disk: the file was rewritten without the headers, so
        // a second load finds none to drop and has nothing to warn about.
        let on_disk = std::fs::read(dir.path().join(SETTINGS_FILE)).expect("read back");
        assert!(
            !on_disk
                .windows(b"planted-value".len())
                .any(|w| w == b"planted-value"),
            "the persisted credential is still on disk"
        );
        let reread = ConnectionSettingsOffers::decode(on_disk.as_slice()).expect("decode");
        assert!(reread.opamp.as_ref().expect("opamp").headers.is_none());
        assert_eq!(reread, loaded, "the rewrite keeps every other setting");
    }

    /// Accepts one connection on `listener` and returns its request head, lower-cased; answers a
    /// plain `200` so that a plain-HTTP probe completes.
    async fn request_head(listener: tokio::net::TcpListener) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        String::from_utf8_lossy(&head).to_ascii_lowercase()
    }

    /// The verification connect carries no `Authorization` on either transport — not one an offer
    /// planted in its `headers`, and not one a leftover `[auth]` in the file still names.
    /// Verifies: ADR-0014, ADR-0021
    #[tokio::test]
    async fn verify_sends_no_authorization_even_when_one_is_offered() {
        // The `http` probe builds a reqwest client, which needs a process-wide provider.
        opamp::tls::install_ring_provider();
        for scheme in ["ws", "http"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let seen = tokio::spawn(request_head(listener));

            let config: ClientConfig = toml::from_str(&format!(
                "endpoint = \"{scheme}://127.0.0.1:{port}/v1/opamp\"\n\
                 [auth]\nbearer_token = \"leftover\"\n"
            ))
            .expect("config");
            let offered = OpAmpConnectionSettings {
                headers: Some(planted_headers()),
                ..Default::default()
            };
            // The WebSocket handshake fails against a plain 200; what matters is what was sent.
            let _ = verify(&offered, &config, || Some(AgentToServer::default())).await;

            let head = tokio::time::timeout(std::time::Duration::from_secs(5), seen)
                .await
                .expect("the probe reached the listener")
                .expect("listener");
            assert!(
                head.starts_with("get") || head.starts_with("post"),
                "{head}"
            );
            assert!(!head.contains("authorization"), "{scheme}: {head}");
            assert!(!head.contains("x-fleet"), "{scheme}: {head}");
        }
    }

    fn endpoint_only(endpoint: &str) -> OpAmpConnectionSettings {
        OpAmpConnectionSettings {
            destination_endpoint: endpoint.to_string(),
            ..Default::default()
        }
    }

    fn never_reported() -> Option<AgentToServer> {
        panic!("a refused endpoint must not get as far as a probe report")
    }

    /// A move to another TLS endpoint is refused without the Client's own CA file: the public
    /// roots would let any publicly certified host take the fleet.
    /// Verifies: ADR-0014
    #[tokio::test]
    async fn an_offered_move_needs_the_clients_own_ca() {
        let config: ClientConfig =
            toml::from_str("endpoint = \"wss://fleet.example/v1/opamp\"").expect("config");
        let error = verify(
            &endpoint_only("wss://elsewhere.example/v1/opamp"),
            &config,
            never_reported,
        )
        .await
        .expect_err("no ca_file");
        assert!(error.contains("ca_file"), "{error}");
    }

    /// An offered plaintext endpoint off the loopback is refused before anything is dialled, on
    /// either transport: the probe report a plain-HTTP exchange would send is never built.
    /// Verifies: ADR-0014
    #[tokio::test]
    async fn verify_refuses_a_plaintext_endpoint_off_loopback_without_connecting() {
        let config = ClientConfig::default();
        for endpoint in ["ws://192.0.2.1:9/v1/opamp", "http://192.0.2.1:9/v1/opamp"] {
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                verify(&endpoint_only(endpoint), &config, never_reported),
            )
            .await
            .expect("refused without waiting on a connect")
            .expect_err(endpoint);
            assert!(error.starts_with("refusing"), "{endpoint}: {error}");
            assert!(error.contains(endpoint), "{error} names the endpoint");
        }
    }

    /// A move to plaintext is refused on a loopback IP literal too, without dialling it: whoever
    /// listens there would be this Client's Server, unproven.
    /// Verifies: ADR-0040
    #[tokio::test]
    async fn verify_refuses_a_move_to_plaintext_on_the_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let config: ClientConfig = toml::from_str(
            "endpoint = \"wss://fleet.example/v1/opamp\"\n[tls]\nca_file = \"ca.pem\"\n",
        )
        .expect("config");
        for endpoint in [
            format!("ws://127.0.0.1:{port}/v1/opamp"),
            format!("http://127.0.0.1:{port}/v1/opamp"),
        ] {
            let error = verify(&endpoint_only(&endpoint), &config, never_reported)
                .await
                .expect_err("a move to plaintext was taken");
            assert!(
                error.contains("never moves this Client to plaintext"),
                "{error}"
            );
            assert!(
                error.contains(endpoint.as_str()),
                "{error} names the endpoint"
            );
        }
        let dialled =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(dialled.is_err(), "the refused endpoint was dialled");
    }

    /// A persisted plaintext endpoint that `supervisor.toml` does not name is not applied, so a
    /// host moved there returns to its configured endpoint; one the file names, and a persisted
    /// TLS endpoint, still are.
    /// Verifies: ADR-0040
    #[test]
    fn apply_ignores_a_persisted_plaintext_endpoint_the_file_does_not_name() {
        let configured = |endpoint: &str| ClientConfig {
            endpoint: endpoint.to_string(),
            ..ClientConfig::default()
        };
        let mut config = configured("wss://fleet.example/v1/opamp");
        apply(
            &mut config,
            &offer_with(b"h1", "ws://127.0.0.1:4999/v1/opamp", None, 12),
        );
        assert_eq!(config.endpoint, "wss://fleet.example/v1/opamp");
        assert_eq!(config.heartbeat_interval_secs, 12, "the rest still applies");

        let mut config = configured("ws://127.0.0.1:4320/v1/opamp");
        apply(
            &mut config,
            &offer_with(b"h1", "ws://127.0.0.1:4320/v1/opamp", None, 0),
        );
        assert_eq!(config.endpoint, "ws://127.0.0.1:4320/v1/opamp");

        let mut config = configured("ws://127.0.0.1:4320/v1/opamp");
        apply(
            &mut config,
            &offer_with(b"h1", "wss://fleet.example/v1/opamp", None, 0),
        );
        assert_eq!(config.endpoint, "wss://fleet.example/v1/opamp");
    }

    /// A host name never counts as the loopback, not even `localhost`: an offered plaintext
    /// endpoint naming one is refused, and the listener behind it is never dialled.
    /// Verifies: ADR-0014
    #[tokio::test]
    async fn verify_refuses_a_plaintext_endpoint_on_a_host_name() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let config = ClientConfig::default();
        for endpoint in [
            format!("ws://localhost:{port}/v1/opamp"),
            format!("http://localhost:{port}/v1/opamp"),
        ] {
            let error = verify(&endpoint_only(&endpoint), &config, never_reported)
                .await
                .expect_err("a plaintext host name was accepted");
            assert!(error.starts_with("refusing"), "{endpoint}: {error}");
            assert!(
                error.contains(endpoint.as_str()),
                "{error} names the endpoint"
            );
        }
        let dialled =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(dialled.is_err(), "the refused endpoint was dialled");
    }

    /// The verification connect presents the client certificate in force: a listener that
    /// requires one admits the probe with it and refuses the same probe without it.
    /// Verifies: ADR-0014
    #[tokio::test]
    async fn verify_presents_the_client_certificate_in_force() {
        use opamp::server::listen::{ClientAuth, Handle, Listener, ServerTls};
        use opamp::tls::Identity;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec!["test-ca".to_string()]).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).expect("ca");
        let issuer = Issuer::from_ca_cert_pem(&ca.pem(), ca_key).expect("issuer");
        let issue = |name: &str| {
            let key = KeyPair::generate().expect("key");
            let cert = CertificateParams::new(vec![name.to_string()])
                .expect("params")
                .signed_by(&key, &issuer)
                .expect("signed");
            (cert.pem(), key.serialize_pem())
        };

        let (server_cert, server_key) = issue("localhost");
        let tls = ServerTls {
            identity: Identity {
                cert_pem: server_cert.into_bytes(),
                key_pem: server_key.into_bytes(),
            },
            client_auth: ClientAuth::Required {
                ca_pem: ca.pem().into_bytes(),
            },
        }
        .rustls_config()
        .expect("server config");
        let router = axum::Router::new().route("/v1/opamp", axum::routing::post(|| async { "" }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(
            Listener::new(listener, Handle::new())
                .with_tls(tls)
                .serve(router),
        );

        let (client_cert, client_key) = issue("agent");
        let ca_file = dir.path().join("ca.pem");
        let cert_file = dir.path().join("cert.pem");
        let key_file = dir.path().join("key.pem");
        std::fs::write(&ca_file, ca.pem()).expect("ca");
        std::fs::write(&cert_file, client_cert).expect("cert");
        std::fs::write(&key_file, client_key).expect("key");
        let with_identity = |identity: bool| ClientConfig {
            endpoint: format!("https://localhost:{port}/v1/opamp"),
            state_dir: dir.path().join("state"),
            tls: Some(crate::config::TlsConfig {
                ca_file: Some(ca_file.clone()),
                cert_file: identity.then(|| cert_file.clone()),
                key_file: identity.then(|| key_file.clone()),
            }),
            ..ClientConfig::default()
        };
        let report = || Some(AgentToServer::default());
        let keep = OpAmpConnectionSettings::default();

        verify(&keep, &with_identity(true), report)
            .await
            .expect("the certificate in force is presented");
        assert!(
            verify(&keep, &with_identity(false), report).await.is_err(),
            "a listener requiring a certificate admitted a probe without one"
        );
    }
}
