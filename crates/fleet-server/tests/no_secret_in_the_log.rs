//! No secret reaches the Server's log (ADR-0022 clause 2): the `server` binary, logging at `trace`,
//! is sent an `Authorization` header by an Agent, a wrong password on the Operator plane, and
//! issues a bootstrap certificate whose PKCS#12 file is downloaded — and none of the values, nor a
//! hash of them, is in what it wrote to standard error.
#![cfg(unix)]

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

fn client(ca_pem: &str, identity: Option<&(String, String)>) -> reqwest::Client {
    opamp::tls::install_ring_provider();
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca")])
        // The certificate is for `localhost`, the listeners are on 127.0.0.1.
        .resolve(
            "localhost",
            "127.0.0.1:0".parse::<std::net::SocketAddr>().expect("addr"),
        );
    if let Some((cert, key)) = identity {
        let mut pem = key.as_bytes().to_vec();
        pem.extend_from_slice(cert.as_bytes());
        builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("identity"));
    }
    builder.build().expect("client")
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

/// Verifies: ADR-0022, ADR-0028, ADR-0029
#[tokio::test]
async fn no_secret_reaches_the_log() {
    const OPERATOR_PASSWORD: &str = "the operator's own password";
    const WRONG_PASSWORD: &str = "a guess that does not sign in";
    const BOOTSTRAP_PASSWORD: &str = "the bootstrap file's password";
    let token = "an-old-fleet-token-of-32-characters";
    let authorization = format!("Bearer {token}");

    let dir = tempfile::tempdir().expect("tempdir");
    let fleet_ca = ca("opamp-fleet test CA");
    let bootstrap_ca = ca("opamp-fleet test bootstrap CA");
    let server = issue(&fleet_ca, &["localhost"]);
    let (agent_port, operator_port) = free_ports();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{agent_port}\"\ndata_dir = {}\n\n\
             [tls]\ncert_file = {}\nkey_file = {}\nclient_ca_file = {}\n\n\
             [client_ca]\ncert_file = {}\nkey_file = {}\n\n\
             [enrolment]\nbootstrap_ca_file = {}\nbootstrap_ca_key_file = {}\n\n\
             [rest]\nlisten = \"127.0.0.1:{operator_port}\"\n\n\
             [rest.auth.basic_users]\nops = {:?}\n",
            toml::Value::String(dir.path().join("data").display().to_string()),
            path(dir.path(), "server.pem", &server.0),
            path(dir.path(), "server-key.pem", &server.1),
            path(dir.path(), "client-ca.pem", &fleet_ca.0),
            path(dir.path(), "client-ca.pem", &fleet_ca.0),
            path(dir.path(), "client-ca-key.pem", &fleet_ca.1),
            path(dir.path(), "bootstrap-ca.pem", &bootstrap_ca.0),
            path(dir.path(), "bootstrap-ca-key.pem", &bootstrap_ca.1),
            fleet_server::credentials::hash_basic(OPERATOR_PASSWORD).expect("hash"),
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

    // An Agent of an older version sends a token the Agent plane does not read.
    let agent = client(&fleet_ca.0, Some(&issue(&fleet_ca, &["edge-01"])));
    let report = AgentToServer {
        instance_uid: InstanceUid::default().as_bytes().to_vec(),
        sequence_num: 1,
        ..Default::default()
    };
    let response = agent
        .post(format!("https://localhost:{agent_port}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::AUTHORIZATION, &authorization)
        .body(report.encode_to_vec())
        .send()
        .await
        .expect("report");
    assert!(response.status().is_success(), "{:?}", response.status());

    // A wrong password on the Operator plane, and the right one for every act after it.
    let operator = client(&fleet_ca.0, None);
    let url = |path: &str| format!("https://localhost:{operator_port}{path}");
    let refused = operator
        .get(url("/api/v1/agents"))
        .basic_auth("ops", Some(WRONG_PASSWORD))
        .send()
        .await
        .expect("refused sign-in");
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);

    // A bootstrap certificate issued under a password, and its PKCS#12 file downloaded.
    let issued = operator
        .post(url("/api/v1/bootstrap-certificates"))
        .basic_auth("ops", Some(OPERATOR_PASSWORD))
        .json(&serde_json::json!({
            "subject": { "organization": "Kunde GmbH", "organizational_unit": "Werk Nord" },
            "password": BOOTSTRAP_PASSWORD
        }))
        .send()
        .await
        .expect("issue");
    assert_eq!(issued.status(), reqwest::StatusCode::CREATED);
    let issued: serde_json::Value = issued.json().await.expect("json");
    let serial = issued["serial"].as_str().expect("serial");
    let file = operator
        .get(url(&format!("/api/v1/bootstrap-certificates/{serial}/p12")))
        .basic_auth("ops", Some(OPERATOR_PASSWORD))
        .send()
        .await
        .expect("download");
    assert_eq!(file.status(), reqwest::StatusCode::OK);
    let file = file.bytes().await.expect("body");
    let key_der = fleet_core::pkcs12::file::open(&file, BOOTSTRAP_PASSWORD)
        .expect("opens")
        .private_key_der;

    // What it logged meanwhile: the events of the download are written by the time its answer is
    // read, and whatever follows within a moment is read too.
    while let Ok(line) = logged.recv_timeout(Duration::from_millis(500)) {
        log.push(line);
    }
    drop(running);
    let log = log.join("\n");
    // Every event of the run is there, the `debug` ones too, so the absence below means something.
    for event in [
        "admission.admitted",
        "operator.refused",
        "enrolment.bootstrap_issued",
        "enrolment.bootstrap_p12_downloaded",
    ] {
        assert!(log.contains(event), "no {event} in the log: {log}");
    }

    let basic = |password: &str| {
        base64::engine::general_purpose::STANDARD.encode(format!("ops:{password}"))
    };
    let key_base64 = base64::engine::general_purpose::STANDARD.encode(&key_der);
    let secrets = [
        ("the Agent's token", token.to_string()),
        (
            "a hash of the token",
            hex::encode(sha2::Sha256::digest(token.as_bytes())),
        ),
        (
            "a hash of the Authorization value",
            hex::encode(sha2::Sha256::digest(authorization.as_bytes())),
        ),
        ("the wrong password", WRONG_PASSWORD.to_string()),
        ("the wrong Basic credential", basic(WRONG_PASSWORD)),
        ("the operator's password", OPERATOR_PASSWORD.to_string()),
        ("the operator's Basic credential", basic(OPERATOR_PASSWORD)),
        ("the bootstrap password", BOOTSTRAP_PASSWORD.to_string()),
        ("the bootstrap key, hex", hex::encode(&key_der)),
        // A PEM line of the key is 64 characters of its base64.
        ("the bootstrap key, base64", key_base64[..64].to_string()),
        (
            "the bootstrap key's last bytes",
            key_base64[key_base64.len() - 64..].to_string(),
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
