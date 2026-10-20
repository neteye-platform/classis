//! The WebSocket transport end to end (ADR-0013): framed exchange, the pushed offer on a config
//! change, and disconnect handling.

mod support;

use std::time::Duration;

use fleet_server::fleet::SERVER_CAPABILITIES;
use futures_util::{SinkExt, StreamExt};
use opamp::frame;
use opamp::proto::{AgentDisconnect, RemoteConfigStatus, RemoteConfigStatuses, ServerToAgent};
use opamp::uid::InstanceUid;
use support::{
    compressed_report, deploy, distribute, distribute_with_role, full_report, save_configuration,
    spawn,
};
use tokio_tungstenite::tungstenite::Message;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(addr: std::net::SocketAddr) -> Socket {
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
        .await
        .expect("connect");
    socket
}

/// The limit is not what these tests are about; they use the recommended default.
const LIMIT: usize = frame::DEFAULT_MAX_MESSAGE_SIZE;

async fn send(socket: &mut Socket, msg: &opamp::proto::AgentToServer) {
    socket
        .send(Message::Binary(
            frame::encode_within(msg, LIMIT)
                .expect("within the limit")
                .into(),
        ))
        .await
        .expect("send");
}

async fn recv(socket: &mut Socket) -> ServerToAgent {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("a message within five seconds")
            .expect("an open connection")
            .expect("a frame");
        match message {
            Message::Binary(data) => return frame::decode(&data, LIMIT).expect("decode"),
            // Control frames are not OpAMP messages.
            _ => continue,
        }
    }
}

/// Verifies: ADR-0013
#[tokio::test]
async fn a_framed_report_is_answered() {
    let server = spawn().await;
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();

    send(&mut socket, &full_report(&uid, "ws-test", 1)).await;
    let reply = recv(&mut socket).await;
    assert_eq!(reply.instance_uid, uid.as_bytes());
    assert_eq!(reply.capabilities, SERVER_CAPABILITIES);

    let agents = server.state.snapshot();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].transport, "websocket");
    assert!(agents[0].connected);
}

#[tokio::test]
async fn a_config_change_is_pushed_without_the_agent_asking() {
    let server = spawn().await;
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();
    send(&mut socket, &full_report(&uid, "pushed", 1)).await;
    let first = recv(&mut socket).await;
    assert!(first.remote_config.is_none());

    // The operator distributes a configuration; the connected Agent hears about it immediately.
    distribute(server.rest_addr, "fleet", "exporters: {}\n").await;

    let pushed = recv(&mut socket).await;
    let offer = pushed.remote_config.expect("a pushed offer");
    assert!(!offer.config_hash.is_empty());

    // The Agent acknowledges; re-distributing the same configuration pushes nothing again.
    let mut ack = compressed_report(&uid, 2);
    ack.remote_config_status = Some(RemoteConfigStatus {
        last_remote_config_hash: offer.config_hash.clone(),
        status: RemoteConfigStatuses::Applied as i32,
        error_message: String::new(),
    });
    send(&mut socket, &ack).await;
    let reply = recv(&mut socket).await;
    assert!(reply.remote_config.is_none());

    distribute(server.rest_addr, "fleet", "exporters: {}\n").await;
    let nothing = tokio::time::timeout(Duration::from_millis(500), socket.next()).await;
    assert!(nothing.is_err(), "no redundant reconfiguration is pushed");
}

/// ADR-0023: the operator's role reaches the Agent in `AgentConfigObject.role`, verbatim, and a
/// Configuration without one leaves the field unset.
// Verifies: ADR-0023
#[tokio::test]
async fn a_configuration_role_reaches_the_agent_verbatim() {
    let server = spawn().await;
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();
    send(&mut socket, &full_report(&uid, "collector", 1)).await;
    recv(&mut socket).await;

    distribute(server.rest_addr, "base", "receivers: {}\n").await;
    recv(&mut socket).await;
    distribute_with_role(server.rest_addr, "ruleset", "rules: []\n", "supplementary").await;

    let map = recv(&mut socket)
        .await
        .remote_config
        .expect("an offer")
        .config
        .expect("a config map");
    assert_eq!(
        map.config_map["ruleset"].role, "supplementary",
        "the role travels unchanged"
    );
    assert_eq!(
        map.config_map["base"].role, "",
        "a Configuration without a role leaves the field unset"
    );
}

/// Each Deployment's Selector aims at a subset; every Configuration a Deployment holds is one named
/// entry of the offered config map, and one Configuration may sit in several Deployments. An Agent
/// whose Deployment did not change is left alone.
/// Verifies: ADR-0034, G-9
#[tokio::test]
async fn selectors_target_a_subset_and_compose_named_entries() {
    let server = spawn().await;
    let mut socket = connect(server.addr).await;
    let left = InstanceUid::default();
    let right = InstanceUid::default();
    send(&mut socket, &full_report(&left, "left", 1)).await;
    recv(&mut socket).await;
    send(&mut socket, &full_report(&right, "right", 1)).await;
    recv(&mut socket).await;

    // A Deployment claiming the whole fleet reaches both Agents with its Configuration.
    save_configuration(server.rest_addr, "base", "receivers: {}\n", "").await;
    deploy(
        server.rest_addr,
        "fleet",
        &[("service.name", support::AGENT_TYPE)],
        &["base"],
    )
    .await;
    let mut offered = std::collections::HashMap::new();
    for _ in 0..2 {
        let pushed = recv(&mut socket).await;
        let offer = pushed.remote_config.clone().expect("a pushed offer");
        offered.insert(pushed.instance_uid.clone(), offer);
    }
    assert!(offered.contains_key(left.as_bytes().as_slice()));
    assert!(offered.contains_key(right.as_bytes().as_slice()));

    // Both acknowledge their offers (sequence numbers are per Agent).
    for uid in [&left, &right] {
        let offer = &offered[&uid.as_bytes().to_vec()];
        let mut ack = compressed_report(uid, 2);
        ack.remote_config_status = Some(RemoteConfigStatus {
            last_remote_config_hash: offer.config_hash.clone(),
            status: RemoteConfigStatuses::Applied as i32,
            error_message: String::new(),
        });
        send(&mut socket, &ack).await;
        recv(&mut socket).await;
    }

    // Narrowed to the right Agent, that Deployment moves nobody: what it releases is unchanged.
    // A second Deployment for the left Agent holds the same Configuration and one more, and its
    // press reaches only that Agent, the two composed as two named entries.
    deploy(
        server.rest_addr,
        "fleet",
        &[("service.instance.name", "right")],
        &[],
    )
    .await;
    save_configuration(server.rest_addr, "left-only", "exporters: {}\n", "").await;
    deploy(
        server.rest_addr,
        "left",
        &[("service.instance.name", "left")],
        &["base", "left-only"],
    )
    .await;
    let pushed = recv(&mut socket).await;
    assert_eq!(pushed.instance_uid, left.as_bytes());
    let map = pushed
        .remote_config
        .expect("an offer for left")
        .config
        .expect("a config map");
    let mut names: Vec<&str> = map.config_map.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["base", "left-only"]);

    // The other Agent hears nothing — it keeps running what it already runs (goal 9).
    let nothing = tokio::time::timeout(Duration::from_millis(500), socket.next()).await;
    assert!(nothing.is_err(), "no push toward the other agent");

    let views = server.state.snapshot();
    let view = |name: &str| {
        views
            .iter()
            .find(|a| a.service_instance_name == name)
            .expect("a known agent")
    };
    assert_eq!(view("left").matched_configurations, ["base", "left-only"]);
    assert_eq!(view("right").matched_configurations, ["base"]);
    assert!(view("right").in_sync, "still running its composed set");
    assert!(!view("left").in_sync, "owes the new composition");
}

#[tokio::test]
async fn a_restart_is_pushed_to_a_connected_agent_as_its_own_frame() {
    let server = spawn().await;
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();
    let mut report = full_report(&uid, "restartable", 1);
    report.capabilities |= opamp::proto::AgentCapabilities::AcceptsRestartCommand as u64;
    send(&mut socket, &report).await;
    recv(&mut socket).await;

    let response = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/agents/{uid}/restart",
            server.rest_addr
        ))
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 202);

    let pushed = recv(&mut socket).await;
    let command = pushed.command.expect("the pushed restart command");
    assert_eq!(command.r#type, opamp::proto::CommandType::Restart as i32);
    assert!(pushed.remote_config.is_none(), "command-only frame");
}

#[tokio::test]
async fn agent_disconnect_and_socket_loss_mark_the_agent_disconnected() {
    let server = spawn().await;

    // Polite goodbye: agent_disconnect in the final message.
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();
    send(&mut socket, &full_report(&uid, "leaver", 1)).await;
    recv(&mut socket).await;
    let mut goodbye = compressed_report(&uid, 2);
    goodbye.agent_disconnect = Some(AgentDisconnect {});
    send(&mut socket, &goodbye).await;
    recv(&mut socket).await;
    assert!(!server.state.snapshot()[0].connected);

    // Abrupt loss: the connection dies, the Server notices.
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();
    send(&mut socket, &full_report(&uid, "vanisher", 1)).await;
    recv(&mut socket).await;
    drop(socket);
    let vanished = || {
        server
            .state
            .snapshot()
            .into_iter()
            .find(|a| a.service_instance_name == "vanisher")
            .map(|a| !a.connected)
            .unwrap_or(false)
    };
    for _ in 0..50 {
        if vanished() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the server never noticed the lost connection");
}

#[tokio::test]
async fn a_duplicate_uid_on_a_second_connection_is_rekeyed() {
    // The Baseline's duplicate detection: the same instance_uid alive on another connection
    // (bad UID generators, cloned VMs) — the Server rekeys the newcomer via AgentIdentification.
    let server = spawn().await;
    let mut first = connect(server.addr).await;
    let uid = InstanceUid::default();
    send(&mut first, &full_report(&uid, "original", 1)).await;
    let reply = recv(&mut first).await;
    assert!(reply.agent_identification.is_none());

    let mut second = connect(server.addr).await;
    send(&mut second, &full_report(&uid, "clone", 1)).await;
    let reply = recv(&mut second).await;
    assert_eq!(
        reply.instance_uid,
        uid.as_bytes().to_vec(),
        "the reply is addressed to the identity the newcomer sent, or it routes to no one"
    );
    let assigned = reply
        .agent_identification
        .expect("the duplicate is rekeyed");
    assert_eq!(assigned.new_instance_uid.len(), 16);
    assert_ne!(assigned.new_instance_uid, uid.as_bytes().to_vec());

    // Two distinct, connected Agents — the incumbent kept its identity.
    let agents = server.state.snapshot();
    assert_eq!(agents.len(), 2);
    assert!(agents.iter().all(|a| a.connected));
    assert_eq!(
        agents
            .iter()
            .filter(|a| a.instance_uid == uid.to_string())
            .count(),
        1
    );

    // Only the owning connection may take its Agent down: closing the second connection leaves
    // the original Agent connected, and vice versa (the regression the ownership guard fixes).
    let new_uid = InstanceUid::from_wire(&assigned.new_instance_uid).expect("valid uid");
    send(&mut second, &full_report(&new_uid, "clone", 1)).await;
    recv(&mut second).await;
    drop(second);
    let original_stays = || {
        let agents = server.state.snapshot();
        let disconnected = |name: &str| {
            agents
                .iter()
                .any(|a| a.service_instance_name == name && !a.connected)
        };
        (disconnected("clone") && !disconnected("original")).then_some(())
    };
    for _ in 0..50 {
        if original_stays().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the rekeyed clone never went down alone — or took the original with it");
}

/// Verifies: ADR-0015
#[tokio::test]
async fn two_agents_share_one_connection() {
    // The multiplexing provision of ADR-0015: n Agents over one connection, told apart by
    // instance_uid alone.
    let server = spawn().await;
    let mut socket = connect(server.addr).await;
    let first = InstanceUid::default();
    let second = InstanceUid::default();

    send(&mut socket, &full_report(&first, "left", 1)).await;
    let reply = recv(&mut socket).await;
    assert_eq!(reply.instance_uid, first.as_bytes());

    send(&mut socket, &full_report(&second, "right", 1)).await;
    let reply = recv(&mut socket).await;
    assert_eq!(reply.instance_uid, second.as_bytes());

    let agents = server.state.snapshot();
    assert_eq!(agents.len(), 2);
    assert!(agents.iter().all(|a| a.connected));
}

/// The Baseline (message size limits): a WebSocket message past the receive limit is malformed,
/// and the Server closes the connection with status code 1009 rather than acting on it.
/// Verifies: ADR-0013
#[tokio::test]
async fn an_oversized_frame_closes_the_connection_with_1009() {
    let server = support::spawn_with_limit(1024).await;
    let mut socket = connect(server.addr).await;

    socket
        .send(Message::Binary(vec![0u8; 4096].into()))
        .await
        .expect("send an oversized frame");

    // The close frame is what the peer sees; anything before it would mean the Server processed
    // a message it must have refused.
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("an answer within five seconds")
            .expect("an open connection");
        match message {
            Ok(Message::Close(Some(close))) => {
                assert_eq!(
                    u16::from(close.code),
                    1009,
                    "the Baseline names 1009 (Message Too Big)"
                );
                return;
            }
            Ok(Message::Binary(_)) => panic!("the Server answered an oversized frame"),
            // tungstenite surfaces the close as an error on the next read once it has been
            // handled; either way the connection must be gone, not serving.
            Ok(_) => continue,
            Err(e) => panic!("the connection failed without a 1009 close: {e}"),
        }
    }
}

/// The limits the rate-limit tests serve with: three messages, then one a second.
const SMALL: fleet_server::agent_rate::Limits = fleet_server::agent_rate::Limits {
    messages_per_sec: 1,
    burst: 3,
    gateway_messages_per_sec: 1,
    gateway_burst: 3,
};

/// A member past its burst is answered `Unavailable` with a `retry_info` of exactly 30 s, addressed
/// to the Agent that sent the message; the session stays open, the Agent's record is untouched, and
/// once the bucket refills the next message is processed and asked for a full report.
/// Verifies: ADR-0013
#[tokio::test]
async fn a_session_past_its_burst_is_answered_unavailable_with_retry_info() {
    use opamp::proto::server_error_response::Details;
    use opamp::proto::{ServerErrorResponseType, ServerToAgentFlags};

    let (server, clock) = support::spawn_with_agent_rate(SMALL).await;
    let mut socket = connect(server.addr).await;
    let uid = InstanceUid::default();
    send(&mut socket, &full_report(&uid, "flooding", 1)).await;
    recv(&mut socket).await;
    for sequence in 2..=3 {
        send(&mut socket, &compressed_report(&uid, sequence)).await;
        assert!(recv(&mut socket).await.error_response.is_none());
    }
    let before = server.state.snapshot();

    send(&mut socket, &compressed_report(&uid, 4)).await;
    let reply = recv(&mut socket).await;
    assert_eq!(reply.instance_uid, uid.as_bytes(), "it names the Agent");
    assert_eq!(reply.capabilities, SERVER_CAPABILITIES);
    let error = reply.error_response.expect("an error response");
    assert_eq!(error.r#type, ServerErrorResponseType::Unavailable as i32);
    match error.details {
        Some(Details::RetryInfo(info)) => {
            assert_eq!(info.retry_after_nanoseconds, 30_000_000_000);
        }
        other => panic!("no retry_info: {other:?}"),
    }
    let after = server.state.snapshot();
    assert_eq!(
        after[0].sequence_num, before[0].sequence_num,
        "not processed"
    );
    assert_eq!(after[0].last_seen_ms, before[0].last_seen_ms, "not seen");

    // Still open: once a token is back, the next message is processed, and the gap the throttled
    // one left asks for a full report.
    clock.advance(Duration::from_secs(1));
    send(&mut socket, &compressed_report(&uid, 5)).await;
    let reply = recv(&mut socket).await;
    assert!(reply.error_response.is_none(), "{:?}", reply.error_response);
    assert_ne!(reply.flags & ServerToAgentFlags::ReportFullState as u64, 0);
    assert_eq!(server.state.snapshot()[0].sequence_num, 5);
}

/// A shutdown reaches the WebSocket sessions too: they outlive the HTTP connection they began on,
/// so the drain does not count them, yet the record flush that follows `serve` must find none at
/// work. A session is told why it ends — the close code for a server going away — and it is over,
/// its Agent marked disconnected, by the time `serve` returns.
///
/// Verifies: ADR-0013, ADR-0024
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_closes_the_websocket_sessions_before_serve_returns() {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = std::sync::Arc::new(
        fleet_server::fleet::AppState::new(dir.path().join("fleet-configs"))
            .expect("open the configuration store"),
    );
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = opamp::server::listen::Handle::new();
    let serving =
        tokio::spawn(fleet_server::listen::plane(listener, None, 64, handle.clone()).serve(app));

    let mut socket = connect(addr).await;
    let uid = InstanceUid::default();
    send(&mut socket, &full_report(&uid, "shutdown", 1)).await;
    recv(&mut socket).await;
    assert!(state.snapshot()[0].connected);

    fleet_server::listen::shut_down(&handle);
    tokio::time::timeout(Duration::from_secs(15), serving)
        .await
        .expect("serve returns within the drain")
        .expect("the serve task")
        .expect("serve");

    // By now the session is over: its Agent is no longer carried by any connection.
    assert!(
        !state.snapshot()[0].connected,
        "a WebSocket session outlived serve"
    );
    let close = loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("the session ends within five seconds")
        {
            Some(Ok(Message::Close(frame))) => break frame,
            Some(Ok(_)) => continue,
            other => panic!("the session ended without a close frame: {other:?}"),
        }
    };
    assert_eq!(
        close.expect("a close frame with a code").code,
        CloseCode::Away
    );
}
