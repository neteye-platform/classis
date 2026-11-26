//! The Server binary answers the operator's socket while serving enrolment over plain HTTP.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use classis_admin::protocol::{Request, Response};

struct ServerUnderTest(Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn the_running_server_administers_spaces_and_enrols_over_plain_http() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("admin.sock");
    let agent = std::net::TcpListener::bind("127.0.0.1:0").expect("agent port");
    let operator = std::net::TcpListener::bind("127.0.0.1:0").expect("operator port");
    let agent_port = agent.local_addr().expect("agent address").port();
    let operator_port = operator.local_addr().expect("operator address").port();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{agent_port}\"\ndata_dir = {}\nadmin_socket = {}\n\n[rest]\nlisten = \"127.0.0.1:{operator_port}\"\n",
            toml::Value::String(dir.path().join("data").display().to_string()),
            toml::Value::String(socket.display().to_string()),
        ),
    )
    .expect("write configuration");
    drop((agent, operator));

    let mut server = ServerUnderTest(
        Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start Server"),
    );
    let (lines, logged) = mpsc::channel();
    let stderr = server.0.stderr.take().expect("stderr");
    let reader = std::thread::spawn(move || {
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
            .unwrap_or_else(|_| panic!("Server did not start: {}", log.join("\n")));
        let ready = line.contains("serving the REST API");
        log.push(line);
        if ready {
            break;
        }
    }

    let create = Request::SpaceCreate { name: "lab".into() };
    let Response::Key { key: original } =
        classis_admin::client::request(&socket, &create).expect("create Space")
    else {
        panic!("Space creation did not return a key");
    };
    assert!(original.starts_with("cle1_lab_"));
    let list = classis_admin::client::request(&socket, &Request::SpaceList).expect("list Spaces");
    assert_eq!(
        list,
        Response::Names {
            names: vec!["lab".into()]
        }
    );

    let http = reqwest::Client::new();
    let endpoint = format!("http://127.0.0.1:{agent_port}/v1/enrol");
    oauth_registration::client::register(&http, &endpoint, &original)
        .await
        .expect("enrol with the original key");
    let rotate = Request::SpaceRotateKey { name: "lab".into() };
    let Response::Key { key: rotated } =
        classis_admin::client::request(&socket, &rotate).expect("rotate key")
    else {
        panic!("rotation did not return a key");
    };
    assert_ne!(original, rotated);
    assert!(
        oauth_registration::client::register(&http, &endpoint, &original)
            .await
            .is_err()
    );
    oauth_registration::client::register(&http, &endpoint, &rotated)
        .await
        .expect("enrol with the rotated key");

    drop(server);
    reader.join().expect("read Server log");
    log.extend(logged.try_iter());
    let log = log.join("\n");
    assert!(
        !log.contains(&original),
        "original key reached the Server log"
    );
    assert!(
        !log.contains(&rotated),
        "rotated key reached the Server log"
    );
}
