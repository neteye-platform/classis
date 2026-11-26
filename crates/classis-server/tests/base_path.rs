//! The Agent plane published under a path: the proxy in front of the Server forwards `/classis`
//! as it is, so the OpAMP endpoint and the package download answer under it and nowhere else.

mod support;

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use opamp::frame;
use opamp::proto::{AgentToServer, ServerToAgent};
use opamp::uid::InstanceUid;
use prost::Message;
use support::{full_report, state_on};
use tokio_tungstenite::tungstenite::Message as Frame;

const PROTOBUF: &str = "application/x-protobuf";

/// The Agent plane alone, without admission, wrapped as the binary wraps it for `base_path`.
async fn serve_under(base_path: &str) -> std::net::SocketAddr {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(state_on(dir.path()));
    let agents =
        classis_server::under_base_path(classis_server::agent_app_open_for_tests(state), base_path);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(
        classis_server::listen::plane(listener, 1024, opamp::server::listen::Handle::new())
            .serve(agents),
    );
    // The state's directory lives as long as the test process: the Server under test is dropped
    // with it.
    std::mem::forget(dir);
    addr
}

async fn post(client: &reqwest::Client, url: &str, message: &AgentToServer) -> reqwest::Response {
    client
        .post(url)
        .header("content-type", PROTOBUF)
        .body(message.encode_to_vec())
        .send()
        .await
        .expect("post")
}

#[tokio::test]
async fn the_opamp_endpoint_answers_under_the_base_path_and_nowhere_else() {
    let addr = serve_under("/classis").await;
    let client = reqwest::Client::new();
    let report = full_report(&InstanceUid::default(), "itest", 1);

    let under = post(&client, &format!("http://{addr}/classis/v1/opamp"), &report).await;
    assert_eq!(under.status(), 200);
    ServerToAgent::decode(under.bytes().await.expect("body").as_ref()).expect("an OpAMP reply");

    let at_root = post(&client, &format!("http://{addr}/v1/opamp"), &report).await;
    assert_eq!(at_root.status(), 404, "the root is not the Agent plane");
}

#[tokio::test]
async fn the_package_download_is_routed_under_the_base_path() {
    let addr = serve_under("/classis").await;
    let client = reqwest::Client::new();
    let query = "none/1.0.0/file?os=linux&arch=amd64";
    // No such package. Under the prefix the download handler answers, and says so in its body;
    // at the root there is no route, which answers with no body at all.
    let under = client
        .get(format!("http://{addr}/classis/api/v1/packages/{query}"))
        .send()
        .await
        .expect("get");
    assert_eq!(under.status(), 404);
    let body = under.text().await.expect("body");
    assert!(body.contains("no set"), "the handler answered: {body:?}");

    let at_root = client
        .get(format!("http://{addr}/api/v1/packages/{query}"))
        .send()
        .await
        .expect("get");
    assert_eq!(at_root.status(), 404);
    assert!(
        at_root.text().await.expect("body").is_empty(),
        "no route at the root"
    );
}

#[tokio::test]
async fn without_a_base_path_the_plane_is_at_the_root() {
    let addr = serve_under("").await;
    let client = reqwest::Client::new();
    let report = full_report(&InstanceUid::default(), "itest", 1);
    let reply = post(&client, &format!("http://{addr}/v1/opamp"), &report).await;
    assert_eq!(reply.status(), 200);
}

/// The WebSocket upgrade, which the Agents use, goes through the prefix as the plain exchange does.
#[tokio::test]
async fn the_websocket_upgrade_is_answered_under_the_base_path() {
    let addr = serve_under("/classis").await;
    let limit = frame::DEFAULT_MAX_MESSAGE_SIZE;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/classis/v1/opamp"))
        .await
        .expect("connect under the prefix");
    let uid = InstanceUid::default();
    let report = full_report(&uid, "itest", 1);
    socket
        .send(Frame::Binary(
            frame::encode_within(&report, limit)
                .expect("within the limit")
                .into(),
        ))
        .await
        .expect("send");
    let reply = loop {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("a message within five seconds")
            .expect("an open connection")
            .expect("a frame");
        if let Frame::Binary(data) = frame {
            break frame::decode::<ServerToAgent>(&data, limit).expect("decode");
        }
    };
    assert_eq!(reply.instance_uid, uid.as_bytes());

    assert!(
        tokio_tungstenite::connect_async(format!("ws://{addr}/v1/opamp"))
            .await
            .is_err(),
        "the root is not the Agent plane"
    );
}

/// A host enrols, takes its token, and is admitted, every call under the prefix the proxy
/// forwards; the same paths at the root are not routes.
#[tokio::test]
async fn a_host_enrols_and_is_admitted_under_the_base_path() {
    use classis_server::enrolment::Enrolment;
    use classis_server::throttle::{Limits, Throttle};

    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    classis_server::fs::open_data_dir(&data, true).expect("the data directory");
    let records = classis_server::Records::Files(data);
    let clock = support::ManualClock::new();
    let limits = Limits {
        max_failures: u32::MAX,
        window_secs: 60,
        backoff_secs: 300,
    };
    let enrolment = Arc::new(
        Enrolment::on(
            &records,
            oauth_token::server::Lifetime::Never,
            clock.clone(),
            Arc::new(Throttle::new(limits, clock)),
        )
        .expect("the enrolment"),
    );
    let key = enrolment
        .spaces()
        .create("lab")
        .expect("a space")
        .to_string();
    let state = Arc::new(state_on(dir.path()));
    let agents =
        classis_server::under_base_path(classis_server::agent_app(state, enrolment), "/classis");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(
        classis_server::listen::plane(listener, 1024, opamp::server::listen::Handle::new())
            .serve(agents),
    );

    let http = reqwest::Client::new();
    let registered = oauth_registration::client::register(
        &http,
        format!("http://{addr}/classis/v1/enrol"),
        &key,
    )
    .await
    .expect("enrolled under the prefix");
    let issued = oauth_token::client::request_token(
        &http,
        format!("http://{addr}/classis/v1/token"),
        &registered.client_id,
        registered.client_secret.as_ref(),
    )
    .await
    .expect("a token under the prefix");

    let report = full_report(&InstanceUid::default(), "itest", 1);
    let opamp = format!("http://{addr}/classis/v1/opamp");
    let admitted = http
        .post(&opamp)
        .header("content-type", PROTOBUF)
        .bearer_auth(issued.access_token.to_string())
        .body(report.encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(admitted.status(), 200);
    let refused = post(&http, &opamp, &report).await;
    assert_eq!(refused.status(), 401, "no token, no admission");

    let at_root = http
        .post(format!("http://{addr}/v1/token"))
        .send()
        .await
        .expect("post");
    assert_eq!(at_root.status(), 404, "the root is not the Agent plane");
}
