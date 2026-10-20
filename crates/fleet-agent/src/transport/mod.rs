//! The Client's upstream connection (ADR-0013, ADR-0010). The connection itself — the transport,
//! its TLS, backoff, heartbeat, framing, limits, throttling, the goodbye — is `opamp::client`'s.
//! What is the Client's is which material it is built from, in [`connection`], and [`Upstream`]:
//! the session over the [`Engine`], with the flows that follow a reply.

use std::time::Duration;

use opamp::client::{AfterReply, ClientTls, Connection, Ended, ReportSink, Session, StopSignal};
use opamp::proto::{AgentToServer, ServerToAgent};
use tracing::Instrument as _;

use crate::config::ClientConfig;
use crate::engine::Engine;
use crate::shutdown::Shutdown;

/// How often a download in flight is reported as `Downloading` with its details. The Baseline
/// leaves the cadence open; this is slow enough to stay a rounding error next to the transfer and
/// fast enough that an operator watching a rollout sees it move.
const DOWNLOAD_REPORT_INTERVAL: Duration = Duration::from_secs(5);

impl StopSignal for Shutdown {
    fn requested(&mut self) -> impl std::future::Future<Output = ()> + Send {
        Shutdown::requested(self)
    }
}

/// The Client as an `opamp::client` session: the Engine's *n* Agents over one connection, and what
/// the Client does after a reply.
pub(crate) struct Upstream<'a> {
    pub engine: &'a mut Engine,
    pub config: &'a mut ClientConfig,
    pub shutdown: Shutdown,
    pub telemetry: &'a crate::telemetry::Telemetry,
    /// An enrolment report was answered `BadRequest` on this run: the Client reports as a member
    /// until an exchange fails, since the certificate it presents may be one an operator
    /// provisioned rather than a bootstrap certificate.
    pub enrolment_refused: bool,
}

/// Whether this Client enrols over plain HTTP (ADR-0039 clause 11): it holds no certificate the
/// Server issued, it presents one — the bootstrap certificate, or one an operator provisioned,
/// which it cannot tell apart — and its endpoint is `https://` or `http://`. It then sends one
/// report, its certificate signing request and nothing else, which is what a Gateway relays for an
/// enrolling peer and all a Server reads on an enrolment connection. Over WebSocket it enrols as
/// before.
fn enrols_over_http(config: &ClientConfig) -> bool {
    !config.is_enrolled()
        && (config.bootstrap_identity.is_some() || config.client_identity().is_some())
        && (config.endpoint.starts_with("https://") || config.endpoint.starts_with("http://"))
}

impl Upstream<'_> {
    fn enrolling(&self) -> bool {
        !self.enrolment_refused && enrols_over_http(self.config)
    }

    /// The enrolment report, while this Client enrols over plain HTTP: the request in flight, or a
    /// new one — whatever the Server has declared, since behind a Gateway nothing else reaches it.
    fn enrolment(&mut self) -> Option<Vec<AgentToServer>> {
        if !self.enrolling() {
            return None;
        }
        let csr = crate::csr::request(self.config)?;
        Some(self.engine.enrolment_report(csr).into_iter().collect())
    }
}

impl Session for Upstream<'_> {
    fn connected(&mut self) -> Vec<AgentToServer> {
        self.engine.force_full_all();
        if let Some(enrolment) = self.enrolment() {
            return enrolment;
        }
        self.engine.poll_reports()
    }

    fn routine(&mut self) -> Vec<AgentToServer> {
        if let Some(enrolment) = self.enrolment() {
            return enrolment;
        }
        self.engine.poll_reports()
    }

    fn owed(&mut self) -> Vec<AgentToServer> {
        // An enrolling Client owes nothing but its request, which the next poll re-sends.
        if self.enrolling() {
            return Vec::new();
        }
        self.engine.owed_reports()
    }

    fn on_reply(&mut self, reply: &ServerToAgent) -> Option<Duration> {
        if self.enrolling()
            && reply.error_response.as_ref().is_some_and(|error| {
                error.r#type == opamp::proto::ServerErrorResponseType::BadRequest as i32
            })
        {
            tracing::warn!(
                "the Server refused the enrolment request; reporting as a member until an \
                 exchange fails"
            );
            self.enrolment_refused = true;
        }
        self.engine.handle(reply).retry_after
    }

    async fn after_reply<S: ReportSink>(&mut self, sink: &mut S) -> AfterReply {
        let enrolling = self.enrolling();
        after_reply(
            self.engine,
            self.config,
            &self.shutdown,
            self.telemetry,
            sink,
            enrolling,
        )
        .await
    }

    async fn changed(&mut self) {
        self.engine.changed().await;
    }

    fn exchange_failed(&mut self) {
        // A refusal is judged again: a Gateway marked since, or a window opened, may take it now.
        self.enrolment_refused = false;
        self.engine.force_full_all();
    }

    async fn stop(&mut self) {
        self.engine.shutdown_processes().await;
    }

    fn goodbyes(&mut self) -> Vec<AgentToServer> {
        self.engine.disconnect_messages()
    }
}

/// Sends what the Engine owes now, unless the sink leaves owed reports to its loop.
async fn flush_owed<S: ReportSink>(engine: &mut Engine, sink: &mut S) -> Result<(), ()> {
    if sink.sends_owed_now() {
        sink.send(engine.owed_reports()).await
    } else {
        Ok(())
    }
}

/// The Client's own flows after a reply, the same for both transports (ADR-0010): what the reply
/// left to do, in one order.
///
/// 1. A connection-settings offer (ADR-0014) — verified OpAMP settings end the
///    connection; an offer applied in place owes its acknowledgement now.
/// 2. Ask for a certificate, now that the Server's capabilities are known and an offered
///    certificate is in force (ADR-0021).
/// 3. Offered packages are downloaded and verified (ADR-0026).
/// 4. **The self-update restart, before anything is applied after it.** The `Installing` the
///    package step just owed is the last thing this version says (ADR-0018). It ends the run, so
///    `AfterReply::End` means exactly this.
/// 5. The self-Agent's Supervisor set (ADR-0017), whose retired Agents' goodbyes go out with it.
///
/// While `enrolling` over plain HTTP the request rides the enrolment report instead (ADR-0039).
pub async fn after_reply<S: ReportSink>(
    engine: &mut Engine,
    config: &mut ClientConfig,
    shutdown: &Shutdown,
    telemetry: &crate::telemetry::Telemetry,
    sink: &mut S,
    enrolling: bool,
) -> AfterReply {
    match process_connection_offer(engine, config, telemetry).await {
        OfferOutcome::Reconnect => return AfterReply::Reconnect,
        OfferOutcome::Applied => {
            if flush_owed(engine, sink).await.is_err() {
                return AfterReply::ConnectionLost;
            }
        }
        OfferOutcome::None => {}
    }
    // Only after the offer: one that carries the certificate a request asked for answers it, and a
    // request queued before it would ride the next connection and be signed a second time. A
    // request queued after an earlier reply has left already: an offer always owes a report, which
    // goes out before this runs on WebSocket and is the report the offer answers on plain HTTP.
    if !enrolling {
        engine.request_certificate(|| crate::csr::request(config));
    }
    if flush_owed(engine, sink).await.is_err() {
        return AfterReply::ConnectionLost;
    }
    if process_package_downloads(engine, config, shutdown, sink).await
        && flush_owed(engine, sink).await.is_err()
    {
        return AfterReply::ConnectionLost;
    }
    if engine.restart_for_update() {
        return AfterReply::End;
    }
    if process_self_configuration(engine, config, shutdown, sink).await
        && flush_owed(engine, sink).await.is_err()
    {
        return AfterReply::ConnectionLost;
    }
    AfterReply::Continue
}

/// Downloads, verifies, and applies any package the Engine has queued (ADR-0026). Each is handled
/// in turn — download and verification are the transport's, the swap is the Supervisor's — and its
/// outcome (`Installed`/`InstallFailed`) is reported back through the Engine. Returns whether any
/// package was processed, so the caller flushes the owed status reports.
///
/// While an artifact is on the wire, interim `Downloading` reports go out through `sink`. A failed
/// interim report is not fatal: the download continues, and the terminal status is reported by the
/// caller on the next exchange.
///
/// A shutdown ends a download where it stands — on the wire or waiting out a `Retry-After`
/// (ADR-0026 clause 49) — and nothing is reported for it.
pub async fn process_package_downloads<S: ReportSink>(
    engine: &mut Engine,
    config: &ClientConfig,
    shutdown: &Shutdown,
    sink: &mut S,
) -> bool {
    let mut shutdown = shutdown.clone();
    let downloads = engine.take_package_downloads();
    if downloads.is_empty() {
        return false;
    }
    for (index, package) in downloads {
        // Taken before the download borrows the offer for as long as it runs.
        let (name, version, hash) = (
            package.name.clone(),
            package.version.clone(),
            package.hash.clone(),
        );
        let progress = crate::packages::Progress::default();
        let started = std::time::Instant::now();
        // The install's trace (ADR-0016), opened here because this is where the operation begins:
        // the download and the verification are this task's, the staging and the swap are the
        // Supervisor's, and the span travels to it with the artifact so the two are one trace.
        let span = tracing::info_span!(
            "package.install",
            package = %name,
            version = %version,
            otel.status_code = tracing::field::Empty,
            otel.status_description = tracing::field::Empty,
        );
        // Each Agent stages into its own directory (ADR-0017), so the Supervisor's install is a
        // rename beside the download rather than a copy across filesystems. Keyed by the block
        // name behind the Agent, never by index — the Agent set can change at runtime (ADR-0017).
        let staging_dir = config.staging_dir_for(engine.block_name(index));
        let download =
            crate::packages::download_and_verify(&package, config, &staging_dir, &progress)
                .instrument(span.clone());
        tokio::pin!(download);
        // Poll the download and a ticker together: every tick turns the progress the download has
        // been writing into a status report, without the download itself knowing about reporting.
        let result = loop {
            tokio::select! {
                result = &mut download => break result,
                () = shutdown.requested() => {
                    tracing::info!(package = %name, "a shutdown ends the package download");
                    return false;
                }
                () = tokio::time::sleep(DOWNLOAD_REPORT_INTERVAL) => {
                    engine.package_downloading(index, progress.details(started));
                    let _ = sink.send(engine.owed_reports()).await;
                }
            }
        };
        match result {
            Ok(staged) => {
                engine.apply_package(index, staged, version, hash, &span);
                if engine.restart_for_update() {
                    // A self-update moved the `current` pointer (ADR-0018). Whatever else was
                    // queued is moot: this process is about to be replaced, and the caller ends
                    // the run once the owed `Installing` has gone out.
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(package = %name, error = %e, "package download or verification failed");
                crate::telemetry::failed(&span, &e);
                engine.package_download_failed(index, hash, e);
            }
        }
    }
    true
}

/// Applies the self-Agent's received configuration — its Supervisor set (ADR-0017) — if one is
/// pending, and sends the retired Agents' goodbyes through `sink`. Returns whether an apply ran,
/// so the caller flushes the owed status reports.
pub async fn process_self_configuration<S: ReportSink>(
    engine: &mut Engine,
    config: &mut ClientConfig,
    shutdown: &Shutdown,
    sink: &mut S,
) -> bool {
    let Some(offer) = engine.take_self_config() else {
        return false;
    };
    // A second gate behind the capability the Agent does not declare: on a host that keeps its
    // set no path reaches the apply (ADR-0017 clause 43).
    if !config.server_manages_set() {
        tracing::warn!(
            hash = %hex::encode(&offer.config_hash),
            "refusing to apply a supervisor set: this Client keeps its supervisor set \
             ([supervisors] server_manages_set = false in supervisor.toml)"
        );
        return false;
    }
    let goodbyes = crate::reconfigure::apply(engine, config, offer, shutdown).await;
    if !goodbyes.is_empty() {
        let _ = sink.send(goodbyes).await;
    }
    true
}

/// What handling a connection-settings offer asks of the transport loop.
#[derive(Debug, PartialEq, Eq)]
pub enum OfferOutcome {
    /// No offer was pending.
    None,
    /// The offer was applied — or refused — in place. The acknowledgement is owed, and the
    /// connection stays up. A telemetry-only offer always lands here (ADR-0014 clause 6): no
    /// destination it names is reached over the OpAMP connection, so there is nothing to reconnect
    /// for.
    Applied,
    /// Verified OpAMP settings took effect (ADR-0014): the caller drops the connection so the
    /// runtime re-resolves the effective configuration and reconnects with them.
    Reconnect,
}

/// Handles a pending connection-settings offer, whichever transport is carrying it.
///
/// The two transports differ in how they end a connection, not in what an offer means — so the
/// meaning lives here, once.
///
/// The order of the steps is load-bearing:
///
/// 1. **The OpAMP half, only when there is one.** It is verified by actually connecting, which is
///    ADR-0014's MUST and is scoped to this half alone — the Baseline puts that requirement under
///    `ConnectionSettingsOffers.opamp` and justifies it by not losing access to the *Server*. A
///    telemetry destination cannot be proved that way and is not: a receiver that is momentarily
///    down is not an offer that is wrong.
/// 2. **Persist, then apply telemetry from what was persisted** — never from the raw offer. An
///    offer that says nothing about telemetry — an endpoint move, a heartbeat, a certificate —
///    would otherwise compare against `metrics: None, traces: None, logs: None` and
///    tear down exporters the Server never mentioned. `merge` is what puts those back. What it no
///    longer puts back is a signal left out of an offer that *does* name one: that is a stop, and
///    ADR-0016 is where the difference is decided.
/// 3. **One acknowledgement for the whole message** (ADR-0014 clause 7). The Baseline hashes all
///    settings together, so the Agent answers the message, not its parts: a single status whose
///    `error_message` names everything dropped across both halves.
///
/// A failed verification of the OpAMP half persists and applies **nothing**, telemetry included, and
/// reports `FAILED`. Half-applying an offer whose other half was rejected would leave the Server
/// unable to tell what is running.
pub async fn process_connection_offer(
    engine: &mut Engine,
    config: &ClientConfig,
    telemetry: &crate::telemetry::Telemetry,
) -> OfferOutcome {
    let Some(offer) = engine.take_connection_offer() else {
        return OfferOutcome::None;
    };
    // Opened here rather than on the function, which is called once per exchange and would
    // otherwise trace every poll that had nothing to do (ADR-0016 clause 19). What follows is one
    // operation with an outcome the Server is told about, which is what a span is for here.
    //
    // `reconnect` is a field and not a phase: the reconnection itself happens after this returns,
    // in the transport loop that owns the connection, so a span for it here would measure nothing.
    let span = tracing::info_span!(
        "connection.settings.apply",
        hash = %hex::encode(&offer.hash),
        reconnect = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    );
    let mut errors: Vec<String> = Vec::new();
    let mut reconnect = false;

    if let Some(settings) = &offer.opamp {
        let probe = || engine.probe_report();
        if let Err(e) = crate::connection::verify(settings, config, probe)
            .instrument(tracing::info_span!(parent: &span, "verify"))
            .await
        {
            tracing::warn!(error = %e, "offered connection settings failed verification");
            crate::telemetry::failed(&span, &e);
            engine.connection_settings_outcome(&offer.hash, Err(&e));
            return OfferOutcome::Applied;
        }
        // The issued certificate is stored only now, after connecting with it proved it works — the
        // old one stays in force until here (ADR-0021).
        if let Some(certificate) = &settings.certificate {
            if let Err(e) = crate::csr::accept(&config.state_dir, &certificate.cert) {
                tracing::warn!(error = %e, "cannot store the issued certificate");
            } else {
                tracing::info!("a client certificate was issued and is now in force");
            }
        }
        if let Err(e) = crate::connection::unhonoured(settings) {
            tracing::warn!(error = %e, "connection settings partly applied");
            errors.push(e);
        }
        reconnect = true;
    }

    let store = tracing::info_span!(parent: &span, "store").entered();
    let merged =
        crate::connection::merge(crate::connection::load(&config.state_dir).as_ref(), &offer);
    if let Err(e) = crate::connection::store(&config.state_dir, &merged) {
        tracing::warn!(error = %e, "cannot persist the connection settings");
    }
    errors.extend(telemetry.apply(&merged, &engine.self_description(), config));
    drop(store);

    span.record("reconnect", reconnect);
    if errors.is_empty() {
        crate::telemetry::succeeded(&span);
        engine.connection_settings_outcome(&offer.hash, Ok(()));
    } else {
        let error = errors.join("; ");
        tracing::warn!(error = %error, "connection settings partly applied");
        crate::telemetry::failed(&span, &error);
        engine.connection_settings_outcome(&offer.hash, Err(&error));
    }

    if reconnect {
        tracing::info!("connection settings verified; reconnecting with them");
        OfferOutcome::Reconnect
    } else {
        tracing::info!("telemetry destinations applied");
        OfferOutcome::Applied
    }
}

/// The upstream connection `supervisor.toml` describes, with the client identity in force
/// (ADR-0021).
///
/// # Errors
/// Returns an error when a TLS file cannot be read.
pub fn connection(config: &ClientConfig) -> Result<Connection, String> {
    Ok(connection_with(config, crate::tls::client_tls(config)?))
}

/// The same connection with other TLS material — a candidate certificate under test.
///
/// It carries no `Authorization`: the Server admits by the client certificate alone, and this
/// Client sends no credential upstream (ADR-0021 clause 3).
#[must_use]
pub fn connection_with(config: &ClientConfig, tls: ClientTls) -> Connection {
    Connection {
        endpoint: config.endpoint.clone(),
        authorization: None,
        tls,
        max_message_size: config.max_message_size_bytes,
        // The heartbeat (ReportsHeartbeat, Baseline default 30 s; 0 disables).
        heartbeat: (config.heartbeat_interval_secs > 0)
            .then(|| Duration::from_secs(config.heartbeat_interval_secs)),
        poll: Duration::from_secs(config.poll_interval_secs.max(1)),
    }
}

/// Runs the Engine's Agents over the connection `config` describes, on the transport its endpoint
/// names, until the run ends.
///
/// # Errors
/// Returns an error when the connection cannot be built.
pub async fn run(
    engine: &mut Engine,
    config: &mut ClientConfig,
    shutdown: &mut Shutdown,
    telemetry: &crate::telemetry::Telemetry,
) -> Result<RunOutcome, String> {
    let connection = connection(config)?;
    let mut session = Upstream {
        engine,
        config,
        shutdown: shutdown.clone(),
        telemetry,
        enrolment_refused: false,
    };
    Ok(
        match opamp::client::connection::run(&connection, &mut session, shutdown).await? {
            Ended::Stopped => RunOutcome::Shutdown,
            Ended::Reconnect => RunOutcome::Reconfigured,
            // The only end the Client asks for is the self-update restart (ADR-0018).
            Ended::End => RunOutcome::RestartForUpdate,
        },
    )
}

/// Why a transport run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// The operator stopped the Client; processes are down, goodbyes sent.
    Shutdown,
    /// Verified connection settings took effect (ADR-0014): the runtime re-resolves the
    /// effective configuration and reconnects — possibly on the other transport.
    Reconfigured,
    /// A self-update installed a new version of the Client and moved the `current` pointer
    /// (ADR-0018). The run ends here and the process exits asking for a restart; what comes back
    /// up is the new version, which reports the outcome.
    RestartForUpdate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use crate::supervisor::agent::AgentState;
    use opamp::proto::{
        AgentToServer, DownloadableFile, PackageAvailable, PackageStatusEnum, PackagesAvailable,
        ServerToAgent,
    };
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An Engine holding one self-Agent, and the config that goes with it.
    fn engine_with_state_dir(dir: &tempfile::TempDir) -> (Engine, ClientConfig, Vec<u8>) {
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let state =
            AgentState::new("self".to_string(), storage, crate::host::SystemHost).expect("agent");
        let mut engine = Engine::new(vec![state]);
        let uid = engine.poll_reports()[0].instance_uid.clone();
        let config = ClientConfig {
            state_dir: dir.path().to_path_buf(),
            ..ClientConfig::default()
        };
        (engine, config, uid)
    }

    fn telemetry_only_offer(uid: Vec<u8>, endpoint: &str) -> ServerToAgent {
        ServerToAgent {
            instance_uid: uid,
            connection_settings: Some(opamp::proto::ConnectionSettingsOffers {
                hash: b"telemetry-1".to_vec(),
                own_metrics: Some(opamp::proto::TelemetryConnectionSettings {
                    destination_endpoint: endpoint.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// ADR-0014: an offer carrying only a telemetry destination is applied **in place** — no
    /// verification by connecting, no reconnect — and acknowledged. Before it, the Client required
    /// `opamp` to be present and dropped this message whole: no `APPLYING`, no status, no
    /// exporters, and a Server whose hash gate therefore never closed and re-offered for ever.
    #[tokio::test]
    async fn a_telemetry_only_offer_is_applied_without_reconnecting() {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut engine, config, uid) = engine_with_state_dir(&dir);
        // Loopback is the cleartext exception (ADR-0016) — nothing leaves the machine.
        engine.handle(&telemetry_only_offer(
            uid,
            "http://127.0.0.1:4318/v1/metrics",
        ));

        let telemetry = crate::telemetry::Telemetry::new();
        let outcome = process_connection_offer(&mut engine, &config, &telemetry).await;

        assert_eq!(
            outcome,
            OfferOutcome::Applied,
            "a telemetry destination is not reached over the OpAMP connection, so nothing is \
             gained by dropping it"
        );
        assert!(telemetry.reporting(), "the exporter is in force");

        // Persisted — and honestly: the Server offered no OpAMP settings, so none are claimed.
        let stored = crate::connection::load(&config.state_dir).expect("settings persisted");
        assert!(stored.own_metrics.is_some());
        assert!(
            stored.opamp.is_none(),
            "a synthetic empty block would claim an offer that was never made"
        );

        // And the Server is told, which is what closes its gate.
        let status = engine.owed_reports()[0]
            .connection_settings_status
            .clone()
            .expect("an acknowledgement is owed");
        assert_eq!(status.last_connection_settings_hash, b"telemetry-1");
        assert_eq!(
            status.status,
            opamp::proto::ConnectionSettingsStatuses::Applied as i32,
            "{}",
            status.error_message
        );
        telemetry.shutdown();
    }

    /// And a destination this Client refuses is reported `FAILED` naming the reason, on the same
    /// offer — not warned to a log while the Server is told everything applied.
    /// Verifies: ADR-0016
    #[tokio::test]
    async fn a_refused_telemetry_destination_is_reported_failed_on_the_same_offer() {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut engine, config, uid) = engine_with_state_dir(&dir);
        // Cleartext to a public host name: the Baseline's "MAY refuse", taken (ADR-0016).
        engine.handle(&telemetry_only_offer(
            uid,
            "http://collector.example:4318/v1/metrics",
        ));

        let telemetry = crate::telemetry::Telemetry::new();
        let outcome = process_connection_offer(&mut engine, &config, &telemetry).await;

        assert_eq!(outcome, OfferOutcome::Applied);
        assert!(!telemetry.reporting(), "the destination was refused");

        let status = engine.owed_reports()[0]
            .connection_settings_status
            .clone()
            .expect("an acknowledgement is owed");
        assert_eq!(
            status.status,
            opamp::proto::ConnectionSettingsStatuses::Failed as i32
        );
        assert!(
            status.error_message.contains("cleartext"),
            "the Server must learn *why*: {}",
            status.error_message
        );
    }

    /// A sink that keeps what the transport would have sent.
    struct Recorder(Vec<AgentToServer>);

    impl ReportSink for Recorder {
        async fn send(&mut self, reports: Vec<AgentToServer>) -> Result<(), ()> {
            self.0.extend(reports);
            Ok(())
        }
    }

    /// The Supervisor-set apply refuses to run on a host that keeps its set, whatever put a set in
    /// front of it: nothing is written and nothing is sent (ADR-0017 clause 43).
    /// Verifies: ADR-0017
    #[tokio::test]
    async fn the_supervisor_set_apply_refuses_to_run_on_a_host_that_keeps_its_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut engine, mut config, uid) = engine_with_state_dir(&dir);
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "# the operator's\n").expect("write");
        config.path = Some(path.clone());
        config.supervisor_defaults.server_manages_set = false;
        engine.handle(&ServerToAgent {
            instance_uid: uid,
            remote_config: Some(opamp::proto::AgentRemoteConfig {
                config: None,
                config_hash: b"set-1".to_vec(),
            }),
            ..Default::default()
        });
        let (_tx, shutdown) = crate::shutdown::shutdown_channel();
        let mut sink = Recorder(Vec::new());

        let ran = process_self_configuration(&mut engine, &mut config, &shutdown, &mut sink).await;

        assert!(!ran, "the apply ran");
        assert!(sink.0.is_empty());
        assert!(engine.take_self_config().is_none());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "# the operator's\n"
        );
    }

    /// A shutdown ends a download that is waiting out a `Retry-After` from its Server origin: the
    /// call returns at once, and no failure is reported for the download.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_shutdown_stops_a_download_waiting_out_retry_after() {
        opamp::tls::install_ring_provider();
        let (asked_tx, asked) = tokio::sync::oneshot::channel::<()>();
        let asked_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(asked_tx)));
        let app = axum::Router::new().route(
            "/otelcol",
            axum::routing::get(move || {
                let asked_tx = asked_tx.clone();
                async move {
                    if let Some(tx) = asked_tx.lock().expect("asked").take() {
                        let _ = tx.send(());
                    }
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        [(axum::http::header::RETRY_AFTER, "30")],
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut state = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        state.accept_packages();
        let mut engine = Engine::new(vec![state]);
        let uid = engine.poll_reports()[0].instance_uid.clone();
        let config = ClientConfig {
            endpoint: format!("ws://{addr}/v1/opamp"),
            state_dir: dir.path().to_path_buf(),
            package_key: Some(vec![0; 32]),
            ..ClientConfig::default()
        };
        engine.handle(&ServerToAgent {
            instance_uid: uid,
            packages_available: Some(PackagesAvailable {
                packages: [(
                    "otelcol".to_string(),
                    PackageAvailable {
                        version: "2.0.0".to_string(),
                        file: Some(DownloadableFile {
                            download_url: "/otelcol".to_string(),
                            content_hash: vec![1; 32],
                            signature: vec![1; 64],
                            ..Default::default()
                        }),
                        hash: b"pkg-hash".to_vec(),
                        ..Default::default()
                    },
                )]
                .into(),
                all_packages_hash: b"agg".to_vec(),
            }),
            ..Default::default()
        });
        let (stop, shutdown) = crate::shutdown::shutdown_channel();
        tokio::spawn(async move {
            let _ = asked.await;
            let _ = stop.send(true);
            // Kept until the download has seen it.
            std::future::pending::<()>().await;
        });
        let mut sink = Recorder(Vec::new());
        let processed = tokio::time::timeout(
            Duration::from_secs(10),
            process_package_downloads(&mut engine, &config, &shutdown, &mut sink),
        )
        .await
        .expect("the shutdown ended the wait");
        assert!(!processed);
        let failed = sink
            .0
            .iter()
            .chain(engine.owed_reports().iter())
            .filter_map(|report| report.package_statuses.as_ref())
            .filter_map(|statuses| statuses.packages.get("otelcol"))
            .any(|status| status.status == PackageStatusEnum::InstallFailed as i32);
        assert!(
            !failed,
            "nothing is reported for a download a shutdown ended"
        );
    }

    /// The Baseline permits interim status reports while a package downloads, and this is what
    /// they are for: a transfer that takes longer than a moment stays visible instead of looking
    /// like a stuck install. Driven by a server that trickles the artifact out.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_slow_download_is_reported_as_downloading_with_progress() {
        opamp::tls::install_ring_provider();
        let artifact = vec![7u8; 3072];
        let content_hash = Sha256::digest(&artifact).to_vec();
        // Signed with a key of the test's own: a Client takes nothing unsigned (ADR-0026).
        let keypair = {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
            ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair")
        };
        let signature = keypair
            .sign(&fleet_core::package::statement(
                "otelcol",
                "2.0.0",
                &<sha2::Sha256 as sha2::Digest>::digest(&artifact),
            ))
            .as_ref()
            .to_vec();
        let public = {
            use ring::signature::KeyPair as _;
            keypair.public_key().as_ref().to_vec()
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = artifact.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut scratch = [0u8; 1024];
            let _ = stream.read(&mut scratch).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
                served.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            // Three seconds per third: long enough that the reporting tick fires mid-transfer.
            for chunk in served.chunks(1024) {
                let _ = stream.write_all(chunk).await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().to_path_buf()).expect("storage");
        let mut state = AgentState::supervised(
            "otelcol".to_string(),
            "otelcol".to_string(),
            storage,
            crate::host::SystemHost,
        )
        .expect("agent");
        state.accept_packages();
        let mut engine = Engine::new(vec![state]);
        let uid = engine.poll_reports()[0].instance_uid.clone();
        // A Client that takes packages holds a key, and fetches from its own Server's origin
        // (ADR-0026, ADR-0033).
        let config = ClientConfig {
            endpoint: format!("ws://{addr}/v1/opamp"),
            state_dir: dir.path().to_path_buf(),
            package_key: Some(public),
            ..ClientConfig::default()
        };

        // The offer queues the download the transport then runs.
        engine.handle(&ServerToAgent {
            instance_uid: uid,
            packages_available: Some(PackagesAvailable {
                packages: [(
                    "otelcol".to_string(),
                    PackageAvailable {
                        version: "2.0.0".to_string(),
                        file: Some(DownloadableFile {
                            download_url: format!("http://{addr}/otelcol"),
                            content_hash: content_hash.clone(),
                            signature: signature.clone(),
                            ..Default::default()
                        }),
                        hash: b"pkg-hash".to_vec(),
                        ..Default::default()
                    },
                )]
                .into(),
                all_packages_hash: b"agg".to_vec(),
            }),
            ..Default::default()
        });

        let mut sink = Recorder(Vec::new());
        let (_tx, shutdown) = crate::shutdown::shutdown_channel();
        assert!(process_package_downloads(&mut engine, &config, &shutdown, &mut sink).await);

        // At least one interim report went out while the bytes were still arriving, and it says
        // Downloading — with a percentage that actually moved.
        let downloading: Vec<_> = sink
            .0
            .iter()
            .filter_map(|report| report.package_statuses.as_ref())
            .filter_map(|statuses| statuses.packages.get("otelcol"))
            .filter(|status| status.status == PackageStatusEnum::Downloading as i32)
            .collect();
        assert!(
            !downloading.is_empty(),
            "a transfer this slow must be reported while it runs, not only when it ends"
        );
        let details = downloading[0]
            .download_details
            .expect("Downloading carries its details");
        assert!(
            details.download_percent > 0.0 && details.download_percent < 100.0,
            "a partial transfer reports partial progress, got {}",
            details.download_percent
        );
        assert!(details.download_bytes_per_second > 0.0);

        // And the artifact itself arrived intact, verified against its content hash.
        let staged = dir.path().join("packages").join("otelcol.staged");
        assert_eq!(
            std::fs::read(&staged).expect("the staged artifact"),
            artifact
        );
    }
}
