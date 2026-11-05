//! The own-telemetry offer (ADR-0016): the Server names destinations, and only for the signals an
//! Agent says it can report.

mod support;

use opamp::proto::{AgentCapabilities, AgentToServer, ServerToAgent};
use opamp::uid::InstanceUid;
use prost::Message;

fn offer() -> fleet_server::fleet::TelemetryOffer {
    fleet_server::fleet::TelemetryOffer::from_config(
        &toml::from_str::<fleet_server::config::TelemetryOfferConfig>(
            r#"
            metrics_endpoint = "https://collector.example:4318/v1/metrics"
            traces_endpoint = "https://collector.example:4318/v1/traces"
            logs_endpoint = "https://collector.example:4318/v1/logs"
            [headers]
            Authorization = "Bearer telemetry-token"
            "#,
        )
        .expect("telemetry_offer config"),
    )
}

async fn exchange(server: &support::TestServer, report: AgentToServer) -> ServerToAgent {
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(report.encode_to_vec())
        .send()
        .await
        .expect("send");
    ServerToAgent::decode(response.bytes().await.expect("body")).expect("decode")
}

fn report(capabilities: u64) -> AgentToServer {
    AgentToServer {
        instance_uid: InstanceUid::default().as_bytes().to_vec(),
        sequence_num: 1,
        capabilities: AgentCapabilities::ReportsStatus as u64 | capabilities,
        ..Default::default()
    }
}

/// An Agent declaring all three gets all three, with the configured headers on each.
/// Verifies: ADR-0016
#[tokio::test]
async fn every_declared_signal_is_offered_a_destination() {
    let server = support::spawn_with_telemetry(offer()).await;
    let reply = exchange(
        &server,
        report(
            AgentCapabilities::ReportsOwnMetrics as u64
                | AgentCapabilities::ReportsOwnTraces as u64
                | AgentCapabilities::ReportsOwnLogs as u64,
        ),
    )
    .await;

    let settings = reply.connection_settings.expect("an offer");
    let metrics = settings.own_metrics.expect("a metrics destination");
    assert_eq!(
        metrics.destination_endpoint,
        "https://collector.example:4318/v1/metrics"
    );
    assert_eq!(
        metrics.headers.expect("headers").headers[0].value,
        "Bearer telemetry-token"
    );
    assert!(settings.own_traces.is_some());
    assert!(settings.own_logs.is_some());
    // Nothing else is configured on this Server, so the offer carries telemetry alone.
    assert!(settings.opamp.is_none());
}

/// A withdrawal reaches the Agent (ADR-0016 rule 18): an endpoint configured empty is sent as an
/// empty `destination_endpoint`, which is what stops that signal. It travels without the backend's
/// credential — nobody is going to open that connection — and the offer is still an offer, so the
/// Server declares `OffersConnectionSettings` and the hash gate closes on the acknowledgement like
/// any other.
/// Verifies: ADR-0016
#[tokio::test]
async fn a_withdrawn_signal_is_offered_as_an_empty_destination() {
    let withdrawal = fleet_server::fleet::TelemetryOffer::from_config(
        &toml::from_str::<fleet_server::config::TelemetryOfferConfig>(
            r#"
            metrics_endpoint = ""
            [headers]
            Authorization = "Bearer telemetry-token"
            "#,
        )
        .expect("a withdrawal is a valid [telemetry_offer]"),
    );
    let server = support::spawn_with_telemetry(withdrawal).await;
    let reply = exchange(&server, report(AgentCapabilities::ReportsOwnMetrics as u64)).await;

    let settings = reply.connection_settings.expect("an offer");
    let metrics = settings.own_metrics.expect("a withdrawal is still offered");
    assert_eq!(metrics.destination_endpoint, "");
    assert!(
        metrics.headers.is_none(),
        "a withdrawal carries no credential"
    );
    assert!(
        reply.capabilities & opamp::proto::ServerCapabilities::OffersConnectionSettings as u64 != 0,
        "a Server with a withdrawal to make has something to offer"
    );
}

/// Capability negotiation is binding: a signal the Agent never declared is not offered, because an
/// offer nobody can act on is one that would be re-sent forever.
/// Verifies: ADR-0016
#[tokio::test]
async fn an_undeclared_signal_gets_no_destination() {
    let server = support::spawn_with_telemetry(offer()).await;
    let reply = exchange(&server, report(AgentCapabilities::ReportsOwnLogs as u64)).await;

    let settings = reply.connection_settings.expect("an offer");
    assert!(settings.own_logs.is_some(), "the one it declared");
    assert!(settings.own_metrics.is_none());
    assert!(settings.own_traces.is_none());
}

/// ADR-0014 clause 3: a Server that can offer *anything* declares `OffersConnectionSettings`.
/// Keying the bit on `[connection_offer]` alone left this Server exercising a capability it had not
/// declared — and a Client that took the bitmask literally would then have withheld the
/// acknowledgement, leaving the hash gate open and this offer repeating for ever.
/// Verifies: ADR-0014
#[tokio::test]
async fn a_telemetry_only_server_declares_that_it_offers_connection_settings() {
    let server = support::spawn_with_telemetry(offer()).await;
    let reply = exchange(&server, report(AgentCapabilities::ReportsOwnMetrics as u64)).await;

    assert!(
        reply.capabilities & opamp::proto::ServerCapabilities::OffersConnectionSettings as u64 != 0,
        "the offer below is exactly the capability being exercised"
    );
    assert!(reply.connection_settings.is_some());
}

/// An Agent declaring none of the three is offered nothing at all — not an empty offer it would
/// have to acknowledge.
/// Verifies: ADR-0016
#[tokio::test]
async fn an_agent_that_reports_no_own_telemetry_is_offered_none() {
    let server = support::spawn_with_telemetry(offer()).await;
    let reply = exchange(&server, report(0)).await;
    assert!(reply.connection_settings.is_none());
}
