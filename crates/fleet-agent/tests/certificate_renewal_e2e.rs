//! Renewal before expiry, end to end (ADR-0021 clauses 9 and 11): the real Server signs with a CA
//! whose certificates live seconds, the real Client renews at two thirds of each life. The
//! measure H6 of `docs/HARDENING.md` shortened the default life on the strength of this: a fleet
//! renews before its certificates run out, without anyone's help.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::AppState;

struct ClientUnderTest(Child);

impl Drop for ClientUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A CA of its own, written where `[client_ca]` would name it.
fn client_ca(dir: &Path) -> fleet_server::ca::ClientCa {
    let key = rcgen::KeyPair::generate().expect("ca key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "renewal test CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("ca");
    std::fs::write(dir.join("ca.pem"), cert.pem()).expect("write");
    std::fs::write(dir.join("ca-key.pem"), key.serialize_pem()).expect("write");
    let config: fleet_server::config::ClientCaConfig = toml::from_str(&format!(
        "cert_file = {:?}\nkey_file = {:?}\n",
        dir.join("ca.pem").display().to_string(),
        dir.join("ca-key.pem").display().to_string(),
    ))
    .expect("client_ca config");
    fleet_server::ca::ClientCa::from_config(&config).expect("client ca")
}

/// The Client as a command whose main thread has no more stack than Windows gives one (1 MiB, of
/// which a debug build on Linux needs half for the same frames): on Unix through `ulimit -s`, so
/// that a daemon that runs on the main thread overflows here as it did on Windows. Windows itself
/// runs the binary as it is.
fn windows_sized_main_thread(program: &str) -> Command {
    if cfg!(unix) {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("ulimit -s 512 && exec \"$0\" \"$@\"")
            .arg(program);
        command
    } else {
        Command::new(program)
    }
}

/// The serial, life and host of the certificate the Client holds, if it holds one.
fn issued(state_dir: &Path) -> Option<(Vec<u8>, time::OffsetDateTime, Option<String>)> {
    let pem = std::fs::read(state_dir.join("client-cert.pem")).ok()?;
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem).ok()?;
    let cert = block.parse_x509().ok()?;
    let host = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|name| match name {
                x509_parser::extensions::GeneralName::URI(uri) => uri
                    .strip_prefix(fleet_server::ca::HOST_URI_PREFIX)
                    .map(str::to_string),
                _ => None,
            })
        });
    Some((
        cert.raw_serial().to_vec(),
        cert.validity().not_after.to_datetime(),
        host,
    ))
}

/// Each certificate is replaced before it expires, over and over, and the Client stays with the
/// Server throughout — on a main thread no larger than Windows gives it, which the daemon once
/// overflowed the moment it applied the offered connection settings. The connection presents no certificate here, so the host that every
/// generation carries on is the renewal proof's doing (ADR-0021 clause 27).
/// Verifies: ADR-0021
#[tokio::test]
async fn a_client_renews_each_certificate_before_it_expires() {
    const LIFE: u64 = 9;
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("state")
            .with_client_ca(Some(
                client_ca(dir.path()).with_validity(time::Duration::seconds(LIFE as i64)),
            )),
    );
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let state_dir = dir.path().join("client-state");
    let toml = format!(
        "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"renewer\"\nstate_dir = {:?}\n\
         heartbeat_interval_secs = 1\n",
        state_dir.display().to_string()
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path())).expect("write");
    // The Client's own account of what it did, for the failure message: without it a Client that
    // never connects leaves nothing to read but the count.
    let log_path = dir.path().join("client.log");
    let log = std::fs::File::create(&log_path).expect("client log");
    let _client = ClientUnderTest(
        windows_sized_main_thread(env!("CARGO_BIN_EXE_supervisor"))
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::from(log.try_clone().expect("client log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn the client"),
    );

    // Three generations: each one must arrive while the one before is still valid.
    let deadline = Instant::now() + Duration::from_secs(LIFE * 6);
    let mut seen: Vec<(Vec<u8>, time::OffsetDateTime, Option<String>)> = Vec::new();
    while seen.len() < 3 && Instant::now() < deadline {
        if let Some((serial, not_after, host)) = issued(&state_dir) {
            if seen.last().is_none_or(|(last, _, _)| *last != serial) {
                if let Some((_, previous_end, previous_host)) = seen.last() {
                    assert!(
                        time::OffsetDateTime::now_utc() < *previous_end,
                        "a certificate was renewed only after it had expired"
                    );
                    assert_eq!(&host, previous_host, "a renewal changed the host");
                }
                assert!(host.is_some(), "a certificate names no host");
                seen.push((serial, not_after, host));
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        seen.len() >= 3,
        "only {} certificates in time; the Client logged:\n{}",
        seen.len(),
        std::fs::read_to_string(&log_path).unwrap_or_default()
    );
    assert!(
        state
            .snapshot()
            .first()
            .is_some_and(|agent| agent.connected),
        "the Client stayed with the Server"
    );
}
