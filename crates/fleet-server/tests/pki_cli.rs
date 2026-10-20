//! `server pki status` as an operator runs it (ADR-0028): what it prints and how it exits, that the
//! Server binary makes no certificate (ADR-0028), and the running Server's warning about a
//! certificate it depends on that is ending.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn server(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_server"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("run the server binary")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Kills the server on drop, so a failing assertion never leaks the process.
struct ServerUnderTest(Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A self-signed CA named `name` that lived `lived` days and has `left` days left: its certificate
/// and key as PEM, and the issuer that signs with it.
fn ca(
    name: &str,
    lived: i64,
    left: i64,
) -> (String, String, rcgen::Issuer<'static, rcgen::KeyPair>) {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(lived);
    params.not_after = now + time::Duration::days(left);
    let pem = params.self_signed(&key).expect("ca").pem();
    let key_pem = key.serialize_pem();
    (pem, key_pem, rcgen::Issuer::new(params, key))
}

/// The Server host's files of a fleet, made here rather than by the operator tool the Server does
/// not depend on (ADR-0028): a server certificate for `localhost`, a client CA that ends in
/// `client_ca_left` days, and a bootstrap CA. Answers `server.toml`'s `[tls]`, `[client_ca]` and
/// `[enrolment]` sections naming them.
fn server_host_files(dir: &Path, client_ca_left: i64) -> String {
    let (_, _, server_ca) = ca("opamp-fleet server CA", 1, 3000);
    let server_key = rcgen::KeyPair::generate().expect("key");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server = params
        .signed_by(&server_key, &server_ca)
        .expect("server certificate");
    let (client_ca, client_ca_key, _) = ca("opamp-fleet client CA", 3600, client_ca_left);
    let (bootstrap_ca, _, _) = ca("opamp-fleet bootstrap CA", 1, 3000);
    let file = |name: &str, contents: &str| {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write");
        toml::Value::String(path.display().to_string()).to_string()
    };
    format!(
        "[tls]\ncert_file = {}\nkey_file = {}\nclient_ca_file = {}\n\n\
         [client_ca]\ncert_file = {}\nkey_file = {}\n\n\
         [enrolment]\nbootstrap_ca_file = {}\n",
        file("server.pem", &server.pem()),
        file("server-key.pem", &server_key.serialize_pem()),
        file("client-ca.pem", &client_ca),
        file("client-ca.pem", &client_ca),
        file("client-ca-key.pem", &client_ca_key),
        file("bootstrap-ca.pem", &bootstrap_ca),
    )
}

// Verifies: ADR-0028
#[test]
fn status_reads_the_server_hosts_certificates_and_the_server_makes_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("server.toml");
    std::fs::write(&config, server_host_files(dir.path(), 3000)).expect("write server.toml");
    let config = config.display().to_string();

    let fine = server(&["pki", "status", "--config", &config], dir.path());
    assert_eq!(fine.status.code(), Some(0), "{}", text(&fine.stderr));
    let listed = text(&fine.stdout);
    for file in ["server.pem", "client-ca.pem", "bootstrap-ca.pem"] {
        assert!(listed.contains(file), "{file} is not listed: {listed}");
    }

    let other = tempfile::tempdir().expect("tempdir");
    let config = other.path().join("server.toml");
    std::fs::write(&config, server_host_files(other.path(), 10)).expect("write server.toml");
    let ending = server(
        &["pki", "status", "--config", &config.display().to_string()],
        other.path(),
    );
    assert_eq!(ending.status.code(), Some(1), "{}", text(&ending.stdout));
    assert!(text(&ending.stdout).contains("ENDS SOON"));

    // The commands that make certificates are the operator tool's (ADR-0028), not the Server's.
    for made in [
        &[
            "pki",
            "init",
            "--server-dir",
            "s",
            "--offline-dir",
            "o",
            "--name",
            "x",
        ][..],
        &[
            "pki",
            "server-cert",
            "--offline-dir",
            "o",
            "--name",
            "x",
            "--out",
            "g",
        ],
        &["pki", "bootstrap-cert", "--offline-dir", "o", "--out", "b"],
        &["pki", "bootstrap-ca", "--out", "b"],
        &["pki", "status", "--offline-dir", "o"],
    ] {
        let refused = server(made, dir.path());
        assert_eq!(refused.status.code(), Some(2), "{made:?} was not refused");
        let usage = text(&refused.stderr);
        assert!(usage.contains("server pki status --config"), "{usage}");
        for gone in ["init", "server-cert", "bootstrap-c", "--offline-dir"] {
            assert!(!usage.contains(gone), "the usage names {gone}: {usage}");
        }
    }
    assert!(!dir.path().join("s").exists(), "nothing was written");
}

// Verifies: ADR-0028
#[test]
fn the_server_warns_at_startup_about_a_ca_that_is_ending_and_serves_on() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sections = server_host_files(dir.path(), 10);

    let agent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let operator = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{}\"\ndata_dir = {:?}\n{}\n[rest]\nlisten = \"127.0.0.1:{}\"\n",
            agent.local_addr().expect("addr").port(),
            dir.path().join("data").display().to_string(),
            sections,
            operator.local_addr().expect("addr").port(),
        ),
    )
    .expect("write server.toml");
    drop((agent, operator));

    let mut running = ServerUnderTest(
        Command::new(env!("CARGO_BIN_EXE_server"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "info")
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
    let mut warned = false;
    loop {
        match logged.recv_timeout(Duration::from_secs(30)) {
            Ok(line) if line.contains("ends soon") && line.contains("client-ca.pem") => {
                warned = true;
            }
            Ok(line) if line.contains("serving the REST API") => break,
            Ok(_) => {}
            Err(_) => panic!("the server never came up"),
        }
    }
    assert!(
        warned,
        "the ending client CA was not warned about before serving"
    );

    // The audit writer runs on its own; give it a moment to reach the file.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let audit = std::fs::read_dir(dir.path().join("data/audit"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
                    .collect::<String>()
            })
            .unwrap_or_default();
        if audit.contains("\"pki.expiring\"") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no pki.expiring entry in the audit: {audit}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
