//! A service manager stops the Server with `SIGTERM`, and the Server takes it as the shutdown it
//! drains and saves the fleet on — not as the signal's default, which ends the process before the
//! fleet record is flushed. The test reads the Server's log on stderr, where it is written.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Kills the server on drop, so a failing assertion never leaks the process.
struct ServerUnderTest(Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Verifies: ADR-0013, ADR-0024, ADR-0037
#[test]
fn sigterm_shuts_the_server_down_gracefully() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("a self-signed certificate");
    std::fs::write(dir.path().join("cert.pem"), cert.cert.pem()).expect("write cert");
    std::fs::write(dir.path().join("key.pem"), cert.signing_key.serialize_pem())
        .expect("write key");

    // Two distinct free ports: both listeners are held until the configuration names them.
    let agent = TcpListener::bind("127.0.0.1:0").expect("bind");
    let operator = TcpListener::bind("127.0.0.1:0").expect("bind");
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            concat!(
                "listen = \"127.0.0.1:{agent}\"\n",
                "data_dir = {data:?}\n",
                "[tls]\n",
                "cert_file = {cert:?}\n",
                "key_file = {key:?}\n",
                "client_ca_file = {cert:?}\n",
                "[rest]\n",
                "listen = \"127.0.0.1:{operator}\"\n",
            ),
            agent = agent.local_addr().expect("addr").port(),
            operator = operator.local_addr().expect("addr").port(),
            data = dir.path().join("data"),
            cert = dir.path().join("cert.pem"),
            key = dir.path().join("key.pem"),
        ),
    )
    .expect("write server.toml");
    drop((agent, operator));

    let mut server = ServerUnderTest(
        Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the server"),
    );

    // Every log line, read off the server's stderr as it comes.
    let (lines, logged) = mpsc::channel();
    let stderr = server.0.stderr.take().expect("stderr");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let mut saw = |what: &str| loop {
        match logged.recv_timeout(Duration::from_secs(30)) {
            Ok(line) if line.contains(what) => return Ok(()),
            Ok(line) => seen.push(line),
            Err(_) => return Err(seen.join("\n")),
        }
    };
    if let Err(log) = saw("serving the REST API") {
        panic!("the server never came up:\n{log}");
    }

    // SAFETY: kill(2) on the pid of a child this test started and has not yet reaped.
    let sent = unsafe { libc::kill(server.0.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(sent, 0, "send SIGTERM");
    if let Err(log) = saw("shutting down") {
        panic!("the server did not take SIGTERM as a shutdown:\n{log}");
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = server.0.try_wait().expect("poll the server") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the server did not exit after its shutdown"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success(),
        "the server ended with {status:?} instead of shutting down"
    );

    // Started on an empty data_dir, the Server laid out every directory of ADR-0037 clause 2,
    // each owner-only, and nothing else.
    let data = dir.path().join("data");
    let mut found: Vec<String> = std::fs::read_dir(&data)
        .expect("the data directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .filter(|name| !name.ends_with(".json"))
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "agents",
            "audit",
            "blobs",
            "bootstrap",
            "certificates",
            "configurations",
            "deployments",
            "hosts",
            "packages"
        ]
    );
    for name in std::iter::once(String::new()).chain(found) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(data.join(&name))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{name} is not owner-only");
    }
}
