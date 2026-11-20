//! No secret reaches the Server's log (ADR-0022 clause 2): the `server` binary, logging at `trace`,
//! is sent a random string in an Agent's `Authorization` header (the credential the proxy in front
//! of the Server checks, which the Server itself ignores) and a wrong and a right password on the
//! Operator plane — and none of the values, nor a hash of them, is in what it wrote to standard
//! error.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use opamp::proto::AgentToServer;
use opamp::uid::InstanceUid;
use prost::Message as _;
use sha2::Digest as _;

/// Kills the server on drop, so a failing assertion never leaks the process.
struct ServerUnderTest(Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Two free ports, distinct: both listeners are held until both ports are read.
fn free_ports() -> (u16, u16) {
    let bind = || std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let (first, second) = (bind(), bind());
    let port = |listener: &std::net::TcpListener| listener.local_addr().expect("addr").port();
    (port(&first), port(&second))
}

#[tokio::test]
async fn no_secret_reaches_the_log() {
    const OPERATOR_PASSWORD: &str = "the operator's own password";
    const WRONG_PASSWORD: &str = "a guess that does not sign in";
    opamp::tls::install_ring_provider();

    let dir = tempfile::tempdir().expect("tempdir");
    let token = "an-agent-credential-of-32-random-characters";
    let (agent_port, operator_port) = free_ports();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{agent_port}\"\ndata_dir = {}\n\n\
             [rest]\nlisten = \"127.0.0.1:{operator_port}\"\n\n\
             [rest.auth.basic_users]\nops = {:?}\n",
            toml::Value::String(dir.path().join("data").display().to_string()),
            classis_server::credentials::hash_basic(OPERATOR_PASSWORD).expect("hash"),
        ),
    )
    .expect("write server.toml");

    let mut running = ServerUnderTest(
        Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "trace")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the server"),
    );
    let (lines, logged) = mpsc::channel();
    let stderr = running.0.stderr.take().expect("stderr");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut log = Vec::new();
    loop {
        let line = logged
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("the server never came up: {}", log.join("\n")));
        let up = line.contains("serving the REST API");
        log.push(line);
        if up {
            break;
        }
    }

    // An Agent reports with a credential for the proxy in front: the Server admits the request and
    // ignores the header.
    let client = reqwest::Client::new();
    let report = AgentToServer {
        instance_uid: InstanceUid::default().as_bytes().to_vec(),
        sequence_num: 1,
        ..Default::default()
    };
    let post = |authorization: String| {
        client
            .post(format!("http://127.0.0.1:{agent_port}/v1/opamp"))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .header(reqwest::header::AUTHORIZATION, authorization)
            .body(report.encode_to_vec())
            .send()
    };
    let response = post(format!("Bearer {token}")).await.expect("report");
    assert!(response.status().is_success(), "{:?}", response.status());

    // A wrong password on the Operator plane, and the right one for the acts after it.
    let url = |path: &str| format!("http://127.0.0.1:{operator_port}{path}");
    let refused = client
        .get(url("/api/v1/agents"))
        .basic_auth("ops", Some(WRONG_PASSWORD))
        .send()
        .await
        .expect("refused sign-in");
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    let listed = client
        .get(url("/api/v1/agents"))
        .basic_auth("ops", Some(OPERATOR_PASSWORD))
        .send()
        .await
        .expect("list");
    assert_eq!(listed.status(), reqwest::StatusCode::OK);
    // An act: the Agent is unknown, and the act is logged all the same, with who made it.
    let act = client
        .post(url(&format!(
            "/api/v1/agents/{}/restart",
            InstanceUid::default()
        )))
        .basic_auth("ops", Some(OPERATOR_PASSWORD))
        .send()
        .await
        .expect("act");
    assert!(act.status().is_client_error(), "{:?}", act.status());

    // What it logged meanwhile: the events of the requests are written by the time their answers
    // are read, and whatever follows within a moment is read too.
    while let Ok(line) = logged.recv_timeout(Duration::from_millis(500)) {
        log.push(line);
    }
    drop(running);
    let log = log.join("\n");
    // Every event of the run is there, the `debug` ones too, so the absence below means something.
    for event in ["admission.admitted", "operator.refused", "operator.act"] {
        assert!(log.contains(event), "no {event} in the log: {log}");
    }
    // An act names the operator who made it.
    assert!(
        log.lines()
            .any(|line| line.contains("operator.act") && line.contains("\"ops\"")),
        "no act names its operator: {log}"
    );

    let basic = |password: &str| {
        base64::engine::general_purpose::STANDARD.encode(format!("ops:{password}"))
    };
    let secrets = [
        ("the Agent's credential", token.to_string()),
        (
            "a hash of the credential",
            hex::encode(sha2::Sha256::digest(token.as_bytes())),
        ),
        ("the wrong password", WRONG_PASSWORD.to_string()),
        ("the wrong Basic credential", basic(WRONG_PASSWORD)),
        ("the operator's password", OPERATOR_PASSWORD.to_string()),
        ("the operator's Basic credential", basic(OPERATOR_PASSWORD)),
    ];
    for (what, secret) in secrets {
        assert!(!log.contains(&secret), "{what} is in the log");
    }
    assert!(
        !log.contains("Bearer"),
        "an Authorization value is in the log"
    );
}
