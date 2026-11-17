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

/// The Server host's files, made here rather than by the operator tool the Server does not depend
/// on (ADR-0028): a server certificate for `localhost` that ends in `server_left` days. Answers
/// `server.toml`'s `[tls]` section naming it and its key.
fn server_host_files(dir: &Path, server_left: i64) -> String {
    let (_, _, server_ca) = ca("classis server CA", 1, 3000);
    let server_key = rcgen::KeyPair::generate().expect("key");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(3600);
    params.not_after = now + time::Duration::days(server_left);
    let server = params
        .signed_by(&server_key, &server_ca)
        .expect("server certificate");
    let file = |name: &str, contents: &str| {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write");
        toml::Value::String(path.display().to_string()).to_string()
    };
    format!(
        "[tls]\ncert_file = {}\nkey_file = {}\n",
        file("server.pem", &server.pem()),
        file("server-key.pem", &server_key.serialize_pem()),
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
    assert!(
        listed.contains("server.pem"),
        "server.pem is not listed: {listed}"
    );

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
        assert!(usage.contains("server pki status [--config"), "{usage}");
        for gone in ["init", "server-cert", "bootstrap-c", "--offline-dir"] {
            assert!(!usage.contains(gone), "the usage names {gone}: {usage}");
        }
    }
    assert!(!dir.path().join("s").exists(), "nothing was written");
}

// Verifies: ADR-0028
#[test]
fn the_server_warns_at_startup_about_a_certificate_that_is_ending_and_serves_on() {
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
            Ok(line)
                if line.contains("ends soon")
                    && line.contains("server.pem")
                    && line.contains("pki.expiring") =>
            {
                warned = true;
            }
            Ok(line) if line.contains("serving the REST API") => break,
            Ok(_) => {}
            Err(_) => panic!("the server never came up"),
        }
    }
    assert!(
        warned,
        "the ending server certificate was not warned about before serving"
    );
}

/// `server pki status` reads the configuration every command reads (ADR-0051 clause 2): without
/// `--config`, the file `CLASSIS_SERVER_CONFIG` names, or no file at all and its keys from
/// `CLASSIS_SERVER__…` variables; and it logs the keys its environment set, never their values
/// (clause 7).
// Verifies: ADR-0051
#[test]
fn status_reads_its_configuration_without_config_from_the_variable_or_the_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let elsewhere = dir.path().join("elsewhere.toml");
    std::fs::write(&elsewhere, server_host_files(dir.path(), 3000)).expect("write");
    let empty = tempfile::tempdir().expect("an empty working directory");

    let named = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["pki", "status"])
        .current_dir(empty.path())
        .env("CLASSIS_SERVER_CONFIG", &elsewhere)
        .output()
        .expect("run");
    assert_eq!(named.status.code(), Some(0), "{}", text(&named.stderr));
    assert!(
        text(&named.stdout).contains("server.pem"),
        "{}",
        text(&named.stdout)
    );

    let missing = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["pki", "status"])
        .current_dir(empty.path())
        .env("CLASSIS_SERVER_CONFIG", dir.path().join("missing.toml"))
        .output()
        .expect("run");
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        text(&missing.stderr).contains("missing.toml"),
        "{}",
        text(&missing.stderr)
    );

    // The same sections, every key a variable.
    let document: toml::Table =
        toml::from_str(&server_host_files(dir.path(), 3000)).expect("sections");
    let mut variables = Vec::new();
    for (section, keys) in &document {
        for (key, value) in keys.as_table().expect("a section") {
            variables.push((
                format!(
                    "CLASSIS_SERVER__{}__{}",
                    section.to_uppercase(),
                    key.to_uppercase()
                ),
                value.as_str().expect("a path").to_string(),
            ));
        }
    }
    let from_environment = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["pki", "status"])
        .current_dir(empty.path())
        .env("RUST_LOG", "info")
        .envs(variables.iter().map(|(name, value)| (name, value)))
        .output()
        .expect("run");
    assert_eq!(
        from_environment.status.code(),
        Some(0),
        "{}",
        text(&from_environment.stderr)
    );
    assert!(text(&from_environment.stdout).contains("server.pem"));
    let log = text(&from_environment.stderr);
    assert!(
        log.lines()
            .any(|line| line.contains("set from the environment")
                && line.contains("tls.cert_file (CLASSIS_SERVER__TLS__CERT_FILE)")),
        "{log}"
    );
    for (_, value) in &variables {
        assert!(!log.contains(value.as_str()), "a value was logged: {log}");
    }
}

/// The Server itself logs, at startup and before it serves, every key its environment set and
/// none of their values (ADR-0051 clause 7).
// Verifies: ADR-0051
#[test]
fn the_server_logs_the_keys_its_environment_set_before_it_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let agent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let operator = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{}\"\n{}\n[rest]\nlisten = \"127.0.0.1:{}\"\n",
            agent.local_addr().expect("addr").port(),
            server_host_files(dir.path(), 3000),
            operator.local_addr().expect("addr").port(),
        ),
    )
    .expect("write server.toml");
    drop((agent, operator));
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
            Ok(line) if line.contains("serving the REST API") => break,
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
    assert!(
        noticed,
        "the keys the environment set were not logged before serving"
    );
    assert!(data.is_dir(), "the variable's data_dir was used");
}
