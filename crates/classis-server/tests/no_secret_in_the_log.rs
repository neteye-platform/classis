//! No secret reaches the Server's log (ADR-0022 clause 2, ADR-0064 clause 6): the `server` binary,
//! logging at `trace`, enrols a host with its Space's key, hands it a token, admits it with the
//! token, is sent a token it never issued, a wrong password on the Operator plane, and the right
//! one for an act — and none of the values, nor a hash of them, is in what it wrote to standard
//! error.
#![cfg(unix)]

mod support;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use opamp::proto::AgentToServer;
use opamp::uid::InstanceUid;
use prost::Message as _;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
use sha2::Digest as _;

/// Kills the server on drop, so a failing assertion never leaks the process.
struct ServerUnderTest(Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A self-signed CA named `name`: its certificate and key as PEM.
fn ca(name: &str) -> (String, String) {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("ca");
    (cert.pem(), key.serialize_pem())
}

/// A certificate for `names`, signed by the CA `(cert, key)`.
fn issue(ca: &(String, String), names: &[&str]) -> (String, String) {
    let issuer =
        Issuer::from_ca_cert_pem(&ca.0, KeyPair::from_pem(&ca.1).expect("ca key")).expect("issuer");
    let key = KeyPair::generate().expect("key");
    let params = CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
    )
    .expect("params");
    let cert = params.signed_by(&key, &issuer).expect("signed");
    (cert.pem(), key.serialize_pem())
}

fn client(ca_pem: &str) -> reqwest::Client {
    opamp::tls::install_ring_provider();
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca")])
        // The certificate is for `localhost`, the listeners are on 127.0.0.1.
        .resolve(
            "localhost",
            "127.0.0.1:0".parse::<std::net::SocketAddr>().expect("addr"),
        )
        .build()
        .expect("client")
}

/// Two free ports, distinct: both listeners are held until both ports are read.
fn free_ports() -> (u16, u16) {
    let bind = || std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let (first, second) = (bind(), bind());
    let port = |listener: &std::net::TcpListener| listener.local_addr().expect("addr").port();
    (port(&first), port(&second))
}

fn path(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write");
    toml::Value::String(path.display().to_string()).to_string()
}

fn sha256_hex(text: &str) -> String {
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// Verifies: ADR-0022, ADR-0028, ADR-0029, ADR-0064
#[tokio::test]
async fn no_secret_reaches_the_log() {
    const OPERATOR_PASSWORD: &str = "the operator's own password";
    const WRONG_PASSWORD: &str = "a guess that does not sign in";
    let unissued = "an-old-fleet-token-of-32-characters";
    let unissued_authorization = format!("Bearer {unissued}");

    let dir = tempfile::tempdir().expect("tempdir");
    // The Space an operator's tooling made before the Server started.
    let key = support::create_space(&dir.path().join("data"), "lab");
    let fleet_ca = ca("classis test CA");
    let server = issue(&fleet_ca, &["localhost"]);
    let (agent_port, operator_port) = free_ports();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{agent_port}\"\ndata_dir = {}\n\n\
             [tls]\ncert_file = {}\nkey_file = {}\n\n\
             [rest]\nlisten = \"127.0.0.1:{operator_port}\"\n\n\
             [rest.auth.basic_users]\nops = {:?}\n",
            toml::Value::String(dir.path().join("data").display().to_string()),
            path(dir.path(), "server.pem", &server.0),
            path(dir.path(), "server-key.pem", &server.1),
            classis_server::credentials::hash_basic(OPERATOR_PASSWORD).expect("hash"),
        ),
    )
    .expect("write server.toml");

    let mut running = ServerUnderTest(
        Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "trace")
            .env("NO_COLOR", "1")
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

    // A host enrols with the key, asks for its token, and is admitted with it.
    let agent = client(&fleet_ca.0);
    let registered = oauth_registration::client::register(
        &agent,
        format!("https://localhost:{agent_port}/v1/enrol"),
        &key,
    )
    .await
    .expect("enrolled");
    let issued = oauth_token::client::request_token(
        &agent,
        format!("https://localhost:{agent_port}/v1/token"),
        &registered.client_id,
        &registered.client_secret,
    )
    .await
    .expect("a token");
    let token = issued.access_token.to_string();
    let secret = registered.client_secret.to_string();
    let report = AgentToServer {
        instance_uid: InstanceUid::default().as_bytes().to_vec(),
        sequence_num: 1,
        ..Default::default()
    };
    let admitted = agent
        .post(format!("https://localhost:{agent_port}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .bearer_auth(&token)
        .body(report.encode_to_vec())
        .send()
        .await
        .expect("report");
    assert!(admitted.status().is_success(), "{:?}", admitted.status());

    // A token the Server never issued, and a key that is not any Space's: both refused.
    let refused = agent
        .post(format!("https://localhost:{agent_port}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::AUTHORIZATION, &unissued_authorization)
        .body(report.encode_to_vec())
        .send()
        .await
        .expect("report");
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    let wrong_key = format!("cle1_lab_{}", "A".repeat(43));
    let refused = oauth_registration::client::register(
        &agent,
        format!("https://localhost:{agent_port}/v1/enrol"),
        &wrong_key,
    )
    .await;
    assert!(refused.is_err(), "a key that is no Space's enrolled a host");

    // A wrong password on the Operator plane, and the right one for every act after it.
    let operator = client(&fleet_ca.0);
    let url = |path: &str| format!("https://localhost:{operator_port}{path}");
    let refused = operator
        .get(url("/api/v1/agents"))
        .basic_auth("ops", Some(WRONG_PASSWORD))
        .send()
        .await
        .expect("refused sign-in");
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);

    // An act under the right password.
    let acted = operator
        .put(url("/api/v1/configurations/base"))
        .basic_auth("ops", Some(OPERATOR_PASSWORD))
        .json(&serde_json::json!({ "body": "receivers: {}\n", "service_name": "otelcol" }))
        .send()
        .await
        .expect("act");
    assert_eq!(acted.status(), reqwest::StatusCode::OK);

    // What it logged meanwhile: the events of the download are written by the time its answer is
    // read, and whatever follows within a moment is read too.
    while let Ok(line) = logged.recv_timeout(Duration::from_millis(500)) {
        log.push(line);
    }
    drop(running);
    let log = log.join("\n");
    // Every event of the run is there, the `debug` ones too, so the absence below means something.
    for event in [
        "operator.refused",
        "operator.act",
        "enrolment.registered",
        "token.issued",
        "admission.admitted",
        "admission.refused",
        "enrolment.refused",
    ] {
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
    let key_secret = key.rsplit('_').next().expect("a secret").to_string();
    let secrets = [
        ("the enrolment key", key.clone()),
        ("the enrolment key's secret", key_secret.clone()),
        ("a hash of the enrolment key", sha256_hex(&key)),
        (
            "a hash of the enrolment key's secret",
            sha256_hex(&key_secret),
        ),
        ("the rejected enrolment key", wrong_key.clone()),
        ("the client secret", secret.clone()),
        ("a hash of the client secret", sha256_hex(&secret)),
        ("the access token", token.clone()),
        ("a hash of the access token", sha256_hex(&token)),
        (
            "a hash of the access token's Authorization value",
            sha256_hex(&format!("Bearer {token}")),
        ),
        ("the unissued token", unissued.to_string()),
        ("a hash of the unissued token", sha256_hex(unissued)),
        (
            "a hash of the Authorization value",
            sha256_hex(&unissued_authorization),
        ),
        ("the wrong password", WRONG_PASSWORD.to_string()),
        ("the wrong Basic credential", basic(WRONG_PASSWORD)),
        ("the operator's password", OPERATOR_PASSWORD.to_string()),
        ("the operator's Basic credential", basic(OPERATOR_PASSWORD)),
        (
            "the client's Basic credential",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{secret}", registered.client_id)),
        ),
    ];
    for (what, secret) in secrets {
        assert!(!log.contains(&secret), "{what} is in the log");
    }
    assert!(
        !log.contains("Bearer"),
        "an Authorization value is in the log"
    );
}
