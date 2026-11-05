//! The plain-HTTP transport end to end (ADR-0013): protobuf in, protobuf out, gzip accepted, the
//! config offer gated by the hash comparison.

mod support;

use std::io::Write;

use fleet_server::fleet::SERVER_CAPABILITIES;
use opamp::proto::{
    AgentToServer, AgentToServerFlags, RemoteConfigStatus, RemoteConfigStatuses,
    ServerErrorResponseType, ServerToAgent, ServerToAgentFlags,
};
use opamp::uid::InstanceUid;
use prost::Message;
use support::{
    compressed_report, deploy, distribute, full_report, save_configuration, spawn, spawn_with_limit,
};

const PROTOBUF: &str = "application/x-protobuf";

async fn exchange(client: &reqwest::Client, url: &str, msg: &AgentToServer) -> ServerToAgent {
    let response = client
        .post(url)
        .header("content-type", PROTOBUF)
        .body(msg.encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some(PROTOBUF)
    );
    ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
}

#[tokio::test]
async fn a_report_is_answered_and_the_agent_appears_in_the_fleet() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();

    let reply = exchange(&client, &url, &full_report(&uid, "itest", 1)).await;
    assert_eq!(reply.instance_uid, uid.as_bytes());
    assert_eq!(reply.capabilities, SERVER_CAPABILITIES);
    assert!(reply.remote_config.is_none(), "nothing to offer yet");
    assert_eq!(reply.flags, 0, "a full report needs no recovery");

    let agents: serde_json::Value = serde_json::from_slice(
        &client
            .get(format!("http://{}/api/v1/agents", server.rest_addr))
            .send()
            .await
            .expect("get")
            .bytes()
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(agents.as_array().expect("array").len(), 1);
    // Type and name are two columns now (ADR-0016): `service_name` is what kind of Agent this is,
    // `service_instance_name` is which one.
    assert_eq!(agents[0]["service_name"], support::AGENT_TYPE);
    assert_eq!(agents[0]["service_instance_name"], "itest");
    assert_eq!(agents[0]["transport"], "http");
    assert_eq!(agents[0]["connected"], true);
    assert_eq!(
        agents[0]["identifying_attributes"]["service.name"],
        support::AGENT_TYPE
    );
    assert_eq!(
        agents[0]["non_identifying_attributes"]["service.instance.name"],
        "itest"
    );
    // The OS column prefers the human-readable description over the bare os.type.
    assert_eq!(agents[0]["os"], "Testix 1.0 LTS");
    assert_eq!(agents[0]["non_identifying_attributes"]["os.type"], "linux");
    let capabilities = agents[0]["capabilities"].as_array().expect("capabilities");
    assert!(capabilities.contains(&serde_json::json!("ReportsStatus")));
    assert!(capabilities.contains(&serde_json::json!("AcceptsRemoteConfig")));
}

/// Verifies: G-3
#[tokio::test]
async fn the_offer_is_gated_by_the_config_hash() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();
    exchange(&client, &url, &full_report(&uid, "itest", 1)).await;

    // The operator distributes a configuration through the REST API; the fleet view names the
    // hash this Agent's composed configuration should have.
    distribute(server.rest_addr, "fleet", "receivers: {}\n").await;
    let agents: serde_json::Value = serde_json::from_slice(
        &client
            .get(format!("http://{}/api/v1/agents", server.rest_addr))
            .send()
            .await
            .expect("get")
            .bytes()
            .await
            .expect("body"),
    )
    .expect("json");
    let hash_hex = agents[0]["desired_hash"]
        .as_str()
        .expect("hash")
        .to_string();
    assert_eq!(agents[0]["matched_configurations"][0], "fleet");

    // The next poll gets the offer — the Configuration as a named entry.
    let reply = exchange(&client, &url, &compressed_report(&uid, 2)).await;
    let offer = reply.remote_config.expect("an offer");
    assert_eq!(hex::encode(&offer.config_hash), hash_hex);
    let map = offer.config.as_ref().expect("a config map");
    assert!(map.config_map.contains_key("fleet"));

    // The Agent reports it applied — and is never offered the same configuration again.
    let mut ack = compressed_report(&uid, 3);
    ack.remote_config_status = Some(RemoteConfigStatus {
        last_remote_config_hash: offer.config_hash.clone(),
        status: RemoteConfigStatuses::Applied as i32,
        error_message: String::new(),
    });
    let reply = exchange(&client, &url, &ack).await;
    assert!(
        reply.remote_config.is_none(),
        "no redundant reconfiguration"
    );
}

/// A Configuration held by a Deployment reaches the Agents the Deployment's Selector matches, and
/// an Agent outside it is offered nothing and keeps what it runs.
/// Verifies: G-9, ADR-0034
#[tokio::test]
async fn a_selector_aims_a_configuration_at_part_of_the_fleet() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let (inside, outside) = (InstanceUid::default(), InstanceUid::default());
    exchange(&client, &url, &full_report(&inside, "canary-01", 1)).await;
    exchange(&client, &url, &full_report(&outside, "edge-01", 1)).await;

    save_configuration(server.rest_addr, "canary", "receivers: {}\n", "").await;
    deploy(
        server.rest_addr,
        "canary",
        &[("service.instance.name", "canary-01")],
        &["canary"],
    )
    .await;

    let offered = exchange(&client, &url, &compressed_report(&inside, 2)).await;
    assert!(
        offered
            .remote_config
            .and_then(|offer| offer.config)
            .is_some_and(|map| map.config_map.contains_key("canary")),
        "the matching Agent is offered the Configuration"
    );
    let untouched = exchange(&client, &url, &compressed_report(&outside, 2)).await;
    assert!(
        untouched.remote_config.is_none(),
        "an Agent outside the Deployment's Selector is offered nothing"
    );
}

#[tokio::test]
async fn a_queued_restart_is_delivered_once_as_a_command_only_reply() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();

    // The agent declares AcceptsRestartCommand on top of the usual set.
    let mut report = full_report(&uid, "restartable", 1);
    report.capabilities |= opamp::proto::AgentCapabilities::AcceptsRestartCommand as u64;
    exchange(&client, &url, &report).await;

    // A configuration is pending too — the command must never be combined with the offer.
    distribute(server.rest_addr, "fleet", "receivers: {}\n").await;
    let restart = client
        .post(format!(
            "http://{}/api/v1/agents/{uid}/restart",
            server.rest_addr
        ))
        .send()
        .await
        .expect("post");
    assert_eq!(restart.status(), 202);

    // The next exchange carries the command and nothing else; the offer follows afterwards.
    // (A real client always reports its full capability mask, so the follow-ups carry the
    // restart bit too — the Server caches the last non-zero mask.)
    let follow_up = |sequence_num| {
        let mut report = compressed_report(&uid, sequence_num);
        report.capabilities |= opamp::proto::AgentCapabilities::AcceptsRestartCommand as u64;
        report
    };
    let reply = exchange(&client, &url, &follow_up(2)).await;
    let command = reply.command.expect("the restart command");
    assert_eq!(command.r#type, opamp::proto::CommandType::Restart as i32);
    assert!(reply.remote_config.is_none(), "command-only message");
    assert_eq!(reply.flags, 0);

    let reply = exchange(&client, &url, &follow_up(3)).await;
    assert!(reply.command.is_none(), "delivered exactly once");
    assert!(reply.remote_config.is_some(), "the deferred offer arrives");
}

#[tokio::test]
async fn restart_requests_are_validated_against_the_fleet() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();

    // Malformed uid.
    let response = client
        .post(format!(
            "http://{}/api/v1/agents/nonsense/restart",
            server.rest_addr
        ))
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 400);

    // Unknown agent.
    let response = client
        .post(format!(
            "http://{}/api/v1/agents/{}/restart",
            server.rest_addr,
            InstanceUid::default()
        ))
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 404);

    // Known agent without the capability: refused, not silently dropped.
    let uid = InstanceUid::default();
    exchange(&client, &url, &full_report(&uid, "fixed", 1)).await;
    let response = client
        .post(format!(
            "http://{}/api/v1/agents/{uid}/restart",
            server.rest_addr
        ))
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 409);
}

#[tokio::test]
async fn a_components_hash_is_answered_with_a_demand_for_the_full_map() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();

    let with_bit = |mut report: AgentToServer| {
        report.capabilities |= opamp::proto::AgentCapabilities::ReportsAvailableComponents as u64;
        report
    };
    let hash_only = opamp::proto::AvailableComponents {
        components: Default::default(),
        hash: b"h1".to_vec(),
    };

    // Hash-only announcement → the server flags ReportAvailableComponents.
    let mut report = with_bit(full_report(&uid, "componentful", 1));
    report.available_components = Some(hash_only.clone());
    let reply = exchange(&client, &url, &report).await;
    assert_ne!(
        reply.flags & ServerToAgentFlags::ReportAvailableComponents as u64,
        0
    );

    // The full map arrives → stored, the demand stops, and the view names the components.
    let mut answer = with_bit(compressed_report(&uid, 2));
    answer.available_components = Some(opamp::proto::AvailableComponents {
        components: std::collections::HashMap::from([(
            "receiver/otlp".to_string(),
            opamp::proto::ComponentDetails::default(),
        )]),
        hash: b"h1".to_vec(),
    });
    let reply = exchange(&client, &url, &answer).await;
    assert_eq!(
        reply.flags & ServerToAgentFlags::ReportAvailableComponents as u64,
        0
    );

    // A later hash-only heartbeat of the same hash must not degrade the stored map.
    let mut routine = with_bit(compressed_report(&uid, 3));
    routine.available_components = Some(hash_only);
    exchange(&client, &url, &routine).await;
    let view = &server.state.snapshot()[0];
    assert_eq!(view.available_components, ["receiver/otlp"]);
}

#[tokio::test]
async fn no_component_demand_without_the_declared_capability() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();

    // The report carries a components hash but not the capability bit: the flag stays unset —
    // an undeclared capability is never exercised.
    let mut report = full_report(&uid, "quiet", 1);
    report.available_components = Some(opamp::proto::AvailableComponents {
        components: Default::default(),
        hash: b"h".to_vec(),
    });
    let reply = exchange(&client, &url, &report).await;
    assert_eq!(
        reply.flags & ServerToAgentFlags::ReportAvailableComponents as u64,
        0
    );
}

#[tokio::test]
async fn stateless_http_polling_never_triggers_the_duplicate_rekey() {
    // Two pollers sharing one uid are indistinguishable from one over stateless plain HTTP —
    // detection is deliberately WebSocket-only, so no identification is ever minted here.
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();

    let reply = exchange(&client, &url, &full_report(&uid, "poller-a", 1)).await;
    assert!(reply.agent_identification.is_none());
    let reply = exchange(&client, &url, &full_report(&uid, "poller-b", 1)).await;
    assert!(reply.agent_identification.is_none());
    assert_eq!(
        server.state.snapshot().len(),
        1,
        "one record, last writer wins"
    );
}

/// Verifies: ADR-0013
#[tokio::test]
async fn gzip_request_bodies_are_accepted() {
    let server = spawn().await;
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&full_report(&uid, "gzipped", 1).encode_to_vec())
        .expect("gzip");
    let body = encoder.finish().expect("gzip finish");

    let response = client
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .header("content-encoding", "gzip")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    let reply =
        ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode");
    assert_eq!(reply.instance_uid, uid.as_bytes());
}

/// The Baseline (message size limits): the Server MUST enforce a receive limit on the plain-HTTP
/// transport and MUST answer an oversized request with `413 Content Too Large`.
/// Verifies: ADR-0013
#[tokio::test]
async fn an_oversized_request_body_is_refused_with_413() {
    let server = spawn_with_limit(1024).await;

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .body(vec![0u8; 2048])
        .send()
        .await
        .expect("post");

    assert_eq!(response.status(), 413);
}

/// The same limit, applied *after* decompression: a small gzip body that inflates past the limit
/// buys no more memory than an oversized plain one, and is answered the same way.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_gzip_body_that_inflates_past_the_limit_is_refused_with_413() {
    let server = spawn_with_limit(1024).await;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // Compresses to a few dozen bytes — well inside the request-body limit — but inflates far
    // past it, which is precisely the case the Baseline calls out.
    encoder.write_all(&vec![0u8; 64 * 1024]).expect("gzip");
    let body = encoder.finish().expect("gzip finish");
    assert!(body.len() < 1024, "the compressed body is under the limit");

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .header("content-encoding", "gzip")
        .body(body)
        .send()
        .await
        .expect("post");

    assert_eq!(response.status(), 413);
}

/// Verifies: ADR-0013
#[tokio::test]
async fn transport_detection_rejects_a_missing_protobuf_content_type() {
    let server = spawn().await;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 415);
}

#[tokio::test]
async fn malformed_reports_get_a_bad_request_error_response() {
    let server = spawn().await;
    let client = reqwest::Client::new();

    // Garbage bytes: not an AgentToServer at all.
    let response = client
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .body(vec![0xffu8; 32])
        .send()
        .await
        .expect("post");
    let reply =
        ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode");
    let error = reply.error_response.expect("an error response");
    assert_eq!(error.r#type, ServerErrorResponseType::BadRequest as i32);

    // A syntactically valid message with an illegal instance_uid (not 16 bytes).
    let msg = AgentToServer {
        instance_uid: vec![1, 2, 3],
        sequence_num: 1,
        ..Default::default()
    };
    let reply = exchange(&client, &format!("http://{}/v1/opamp", server.addr), &msg).await;
    let error = reply.error_response.expect("an error response");
    assert_eq!(error.r#type, ServerErrorResponseType::BadRequest as i32);
}

#[tokio::test]
async fn a_sequence_gap_demands_a_full_report() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();
    exchange(&client, &url, &full_report(&uid, "gappy", 1)).await;

    // Sequence 2 lost somewhere; a compressed 3 arrives.
    let reply = exchange(&client, &url, &compressed_report(&uid, 3)).await;
    assert_ne!(
        reply.flags & ServerToAgentFlags::ReportFullState as u64,
        0,
        "the recovery path for lost state"
    );
}

#[tokio::test]
async fn an_unknown_compressed_agent_is_asked_for_full_state_and_can_request_identity() {
    let server = spawn().await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();

    // A compressed report from an Agent the Server has never seen.
    let uid = InstanceUid::default();
    let reply = exchange(&client, &url, &compressed_report(&uid, 7)).await;
    assert_ne!(reply.flags & ServerToAgentFlags::ReportFullState as u64, 0);

    // An Agent starting with a temporary identity and RequestInstanceUid gets a fresh one.
    let temporary = InstanceUid::default();
    let mut msg = full_report(&temporary, "newborn", 1);
    msg.flags = AgentToServerFlags::RequestInstanceUid as u64;
    let reply = exchange(&client, &url, &msg).await;
    let assigned = reply.agent_identification.expect("an assigned identity");
    assert_eq!(assigned.new_instance_uid.len(), 16);
    assert_ne!(assigned.new_instance_uid, temporary.as_bytes().to_vec());
    // Addressed to the identity the Agent sent: the Baseline makes a reply's instance_uid match
    // the message's, and an Agent routes by it before it knows the new one.
    assert_eq!(reply.instance_uid, temporary.as_bytes().to_vec());
}

/// A poller past its burst is answered in the body: a `200` carrying the same `Unavailable` a
/// WebSocket gets, never a `429` or a `503`.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_poller_past_its_burst_is_answered_unavailable_in_the_body() {
    let (server, _clock) = support::spawn_with_agent_rate(fleet_server::agent_rate::Limits {
        messages_per_sec: 1,
        burst: 2,
        gateway_messages_per_sec: 1,
        gateway_burst: 2,
    })
    .await;
    let url = format!("http://{}/v1/opamp", server.addr);
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();
    exchange(&client, &url, &full_report(&uid, "poller", 1)).await;
    exchange(&client, &url, &compressed_report(&uid, 2)).await;

    // `exchange` holds the status to 200 and the body to protobuf.
    let reply = exchange(&client, &url, &compressed_report(&uid, 3)).await;
    assert_eq!(reply.instance_uid, uid.as_bytes());
    let error = reply.error_response.expect("an error response");
    assert_eq!(error.r#type, ServerErrorResponseType::Unavailable as i32);
    assert!(matches!(
        error.details,
        Some(opamp::proto::server_error_response::Details::RetryInfo(ref info))
            if info.retry_after_nanoseconds == 30_000_000_000
    ));
    assert_eq!(server.state.snapshot()[0].sequence_num, 2, "not processed");

    // A body that does not decode is counted too; it names no Agent, and neither does its reply.
    let response = client
        .post(&url)
        .header("content-type", PROTOBUF)
        .body(vec![0xff, 0xff, 0xff])
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    let reply =
        ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode");
    assert!(reply.instance_uid.is_empty());
    assert_eq!(
        reply.error_response.expect("an error").r#type,
        ServerErrorResponseType::Unavailable as i32
    );
}
