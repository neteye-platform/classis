//! The `server` binary behind a reverse proxy: it speaks plain HTTP on both planes
//! whatever the address, refuses the sections of TLS and mutual TLS by name, and logs the keys its
//! environment set before it serves.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Kills the server on drop, so a failing assertion never leaks the process.
struct ServerUnderTest(Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `server.toml` for two free ports, and the ports: the Agent plane's, then the Operator plane's.
fn server_toml(dir: &Path, extra: &str) -> (std::path::PathBuf, u16, u16) {
    let agent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let operator = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let ports = (
        agent.local_addr().expect("addr").port(),
        operator.local_addr().expect("addr").port(),
    );
    let config = dir.join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{}\"\n[rest]\nlisten = \"127.0.0.1:{}\"\n{extra}",
            ports.0, ports.1,
        ),
    )
    .expect("write server.toml");
    (config, ports.0, ports.1)
}

/// A section of TLS, mutual TLS or Agent authentication in `server.toml` stops the Server at
/// startup, naming the section and the decision — it is never ignored.
#[test]
fn a_tls_section_stops_the_server_naming_it() {
    for section in [
        "[tls]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\n",
        "[client_ca]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\n",
        "[enrolment]\nbootstrap_ca_file = \"b.pem\"\n",
        "[agents.auth]\njwt_public_key_file = \"k.pem\"\n",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let (config, _, _) = server_toml(dir.path(), section);
        let output = Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .output()
            .expect("run the server");
        assert_eq!(output.status.code(), Some(1), "{section}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let name = section.lines().next().expect("a header");
        assert!(stderr.contains(&format!("{name} is removed")), "{stderr}");
    }
}

/// `server pki` says it is removed, rather than failing as an unknown word.
#[test]
fn the_pki_command_is_removed_by_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["pki", "status"])
        .output()
        .expect("run the server");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("server pki is removed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The Server serves both planes in plain HTTP — the Operator plane's probes without a credential,
/// the Agent plane's endpoint without one — and logs the keys its environment set before it
/// serves, none of their values.
#[tokio::test]
async fn the_server_serves_plain_http_and_logs_the_keys_its_environment_set() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, agent_port, operator_port) = server_toml(dir.path(), "");
    let data = dir.path().join("data-from-the-environment");

    let mut running = ServerUnderTest(
        Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "info")
            .env("CLASSIS_SERVER__DATA_DIR", &data)
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
    let mut noticed = false;
    loop {
        match logged.recv_timeout(Duration::from_secs(30)) {
            Ok(line) if line.contains("serving the REST API") => {
                assert!(
                    line.contains("over HTTP"),
                    "the planes are served over HTTP: {line}"
                );
                break;
            }
            Ok(line) if line.contains("set from the environment") => {
                assert!(
                    line.contains("data_dir (CLASSIS_SERVER__DATA_DIR)"),
                    "the key is named: {line}"
                );
                assert!(
                    !line.contains("data-from-the-environment"),
                    "a value was logged: {line}"
                );
                noticed = true;
            }
            Ok(_) => {}
            Err(_) => panic!("the server never came up"),
        }
    }
    assert!(noticed, "the keys the environment set were not logged");
    assert!(data.is_dir(), "the variable's data_dir was used");

    let client = reqwest::Client::new();
    for path in ["/livez", "/readyz"] {
        let response = client
            .get(format!("http://127.0.0.1:{operator_port}{path}"))
            .send()
            .await
            .expect("probe");
        assert_eq!(response.status(), 200, "{path}");
    }
    let without_credential = client
        .post(format!("http://127.0.0.1:{agent_port}/v1/opamp"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(Vec::new())
        .send()
        .await
        .expect("post");
    assert_ne!(
        without_credential.status(),
        401,
        "the Agent plane asks no credential: whatever it answers, it is not a refusal to admit"
    );
}
