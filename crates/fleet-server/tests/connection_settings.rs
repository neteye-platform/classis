//! Connection-settings offers (ADR-0014): hash-gated toward capable Agents, retried while an
//! outcome is in flight, and silent once the fleet runs (or refused) exactly what is offered.

mod support;

use fleet_server::config::ConnectionOfferConfig;
use fleet_server::fleet::ConnectionOffer;
use opamp::proto::{
    AgentCapabilities, ConnectionSettingsStatus, ConnectionSettingsStatuses, ServerCapabilities,
    ServerToAgent,
};
use opamp::uid::InstanceUid;
use prost::Message as _;
use support::{full_report, spawn_with, TestServer};

const PROTOBUF: &str = "application/x-protobuf";

fn offer() -> ConnectionOffer {
    let config: ConnectionOfferConfig = toml::from_str(
        "heartbeat_interval_secs = 7\nendpoint = \"wss://fleet.example:4320/v1/opamp\"\n",
    )
    .expect("parse");
    ConnectionOffer::from_config(&config)
}

async fn exchange(server: &TestServer, msg: &opamp::proto::AgentToServer) -> ServerToAgent {
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .body(msg.encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
}

/// The standing offer reaches a capable Agent with what it names — and no `headers`: nothing on
/// the Agent plane reads one (ADR-0014 clause 1).
/// Verifies: ADR-0014
#[tokio::test]
async fn the_offer_reaches_a_capable_agent_and_carries_no_headers() {
    let server = spawn_with(Some(offer())).await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "capable", 1);
    report.capabilities |= AgentCapabilities::AcceptsOpAmpConnectionSettings as u64;

    let reply = exchange(&server, &report).await;
    assert_ne!(
        reply.capabilities & ServerCapabilities::OffersConnectionSettings as u64,
        0,
        "an armed offer is a declared capability"
    );
    let offers = reply.connection_settings.expect("an offer");
    assert!(!offers.hash.is_empty());
    let settings = offers.opamp.expect("opamp settings");
    assert_eq!(settings.heartbeat_interval_seconds, 7);
    assert_eq!(
        settings.destination_endpoint,
        "wss://fleet.example:4320/v1/opamp"
    );
    assert!(settings.headers.is_none(), "an offer carries no headers");
}

/// Verifies: ADR-0014
#[tokio::test]
async fn no_offer_without_the_capability_or_without_a_configured_section() {
    let armed = spawn_with(Some(offer())).await;
    let uid = InstanceUid::default();
    // full_report declares no AcceptsOpAMPConnectionSettings.
    let reply = exchange(&armed, &full_report(&uid, "incapable", 1)).await;
    assert!(
        reply.connection_settings.is_none(),
        "capability negotiation is binding"
    );

    let unarmed = spawn_with(None).await;
    let mut report = full_report(&uid, "capable", 1);
    report.capabilities |= AgentCapabilities::AcceptsOpAmpConnectionSettings as u64;
    let reply = exchange(&unarmed, &report).await;
    assert!(reply.connection_settings.is_none());
    assert_eq!(
        reply.capabilities & ServerCapabilities::OffersConnectionSettings as u64,
        0,
        "no offer configured, no capability declared"
    );
}

/// Verifies: ADR-0014
#[tokio::test]
async fn the_reported_hash_gates_reoffering() {
    let server = spawn_with(Some(offer())).await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "gated", 1);
    report.capabilities |= AgentCapabilities::AcceptsOpAmpConnectionSettings as u64;
    let hash = exchange(&server, &report)
        .await
        .connection_settings
        .expect("an offer")
        .hash;

    let status = |seq: u64, status: ConnectionSettingsStatuses, hash: &[u8]| {
        let mut msg = full_report(&uid, "gated", seq);
        msg.capabilities |= AgentCapabilities::AcceptsOpAmpConnectionSettings as u64
            | AgentCapabilities::ReportsConnectionSettingsStatus as u64;
        msg.connection_settings_status = Some(ConnectionSettingsStatus {
            last_connection_settings_hash: hash.to_vec(),
            status: status as i32,
            error_message: String::new(),
        });
        msg
    };

    // APPLYING echoes the hash but keeps the offer coming — a lost outcome heals by retry.
    let reply = exchange(
        &server,
        &status(2, ConnectionSettingsStatuses::Applying, &hash),
    )
    .await;
    assert!(reply.connection_settings.is_some());

    // APPLIED with the offered hash silences it.
    let reply = exchange(
        &server,
        &status(3, ConnectionSettingsStatuses::Applied, &hash),
    )
    .await;
    assert!(reply.connection_settings.is_none());

    // FAILED with the offered hash silences it too — a refusal is a report, not a loop.
    let reply = exchange(
        &server,
        &status(4, ConnectionSettingsStatuses::Failed, &hash),
    )
    .await;
    assert!(reply.connection_settings.is_none());

    // A stale hash (the offer changed underneath) is offered again.
    let reply = exchange(
        &server,
        &status(5, ConnectionSettingsStatuses::Applied, b"stale"),
    )
    .await;
    assert!(reply.connection_settings.is_some());
}
