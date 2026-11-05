//! Interoperability against `opamp-go`, the OpAMP reference implementation (ADR-0011).
//!
//! The Client and the Server of this project are written from the same reading of the
//! specification, so a misread MUST is symmetric and the rest of the suite cannot see it. Here
//! each end meets another implementation instead: `opamp-go`'s Client against our Server, and our
//! Client against `opamp-go`'s Server, on both transports. The Go side is a puppet under
//! `interop/` that reports what it sees as JSON lines and takes commands on stdin; every scenario
//! and every assertion lives here, where both ends' state can be read.
//!
//! The tests need a Go toolchain, so they are `#[ignore]`d and run in the scheduled interop job
//! (`.github/workflows/interop.yml`), never in `cargo test --workspace`. Locally, with Go on
//! `PATH`:
//!
//! ```text
//! cargo test -p fleet-agent --test interop_opamp_go -- --ignored --nocapture --test-threads=1
//! ```
//!
//! A red run is triaged before it is called a defect: `interop/README.md` names the three
//! outcomes.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fleet_server::fleet::{AgentView, AppState};
use serde_json::{json, Value};

const TIMEOUT: Duration = Duration::from_secs(30);

/// The capability bits of the Baseline's `opamp.proto` the assertions name.
mod bits {
    pub const AGENT_REPORTS_STATUS: u64 = 0x1;
    pub const AGENT_ACCEPTS_REMOTE_CONFIG: u64 = 0x2;
    pub const AGENT_REPORTS_EFFECTIVE_CONFIG: u64 = 0x4;
    pub const AGENT_REPORTS_REMOTE_CONFIG: u64 = 0x1000;
    pub const SERVER_ACCEPTS_STATUS: u64 = 0x1;
    pub const SERVER_OFFERS_REMOTE_CONFIG: u64 = 0x2;
    pub const REPORT_FULL_STATE: u64 = 0x1;
}

/// Builds the harness once per test binary, with the `go` on `PATH`.
fn harness_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop");
        let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("opamp-go-harness");
        let status = Command::new("go")
            .args(["build", "-o"])
            .arg(&binary)
            .arg(".")
            .current_dir(&source)
            .status()
            .unwrap_or_else(|e| {
                panic!("cannot run `go` ({e}): the interop tests need a Go toolchain on PATH")
            });
        assert!(
            status.success(),
            "`go build` of {} failed",
            source.display()
        );
        binary
    })
}

/// One running harness: its event log, filled by a reader thread, and its command pipe.
struct Harness {
    child: Child,
    stdin: ChildStdin,
    events: Arc<Mutex<Vec<Value>>>,
}

impl Harness {
    fn spawn(args: &[&str]) -> Harness {
        let mut child = Command::new(harness_binary())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the opamp-go harness");
        let stdin = child.stdin.take().expect("harness stdin");
        let stdout = child.stdout.take().expect("harness stdout");
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                match serde_json::from_str::<Value>(&line) {
                    Ok(event) => sink.lock().unwrap().push(event),
                    Err(_) => eprintln!("harness: {line}"),
                }
            }
        });
        Harness {
            child,
            stdin,
            events,
        }
    }

    fn send(&mut self, command: Value) {
        writeln!(self.stdin, "{command}").expect("write a harness command");
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e["event"] == name)
            .cloned()
            .collect()
    }

    /// Waits for the first event named `name` that `pred` accepts, failing on a harness error.
    fn wait_for(&self, what: &str, name: &str, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let errors = self.events("error");
            assert!(errors.is_empty(), "the harness reported {errors:?}");
            if let Some(event) = self.events(name).into_iter().find(|e| pred(e)) {
                return event;
            }
            if Instant::now() >= deadline {
                let log = self.events.lock().unwrap();
                let tail: Vec<_> = log.iter().rev().take(12).rev().collect();
                panic!("timed out waiting for {what}; the harness saw last: {tail:#?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Instance UIDs compare as 32 lowercase hex digits, whatever their source spells.
fn uid_hex(uid: &str) -> String {
    uid.trim().replace('-', "").to_ascii_lowercase()
}

async fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Our Server in-process, plaintext on the loopback with an open admission, as the rest of the
/// suite runs it.
struct OurServer {
    addr: SocketAddr,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

impl OurServer {
    async fn start() -> OurServer {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let state = Arc::new(common::fleet_state(dir.path()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Agent plane");
        let addr = listener.local_addr().expect("local addr");
        let app =
            fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
        let handle = opamp::server::listen::Handle::new();
        tokio::spawn(fleet_server::listen::plane(listener, None, 64, handle).serve(app));
        OurServer {
            addr,
            state,
            _dir: dir,
        }
    }

    fn agent(&self, uid: &str) -> Option<AgentView> {
        self.state
            .snapshot()
            .into_iter()
            .find(|a| uid_hex(&a.instance_uid) == uid_hex(uid))
    }
}

/// A TCP relay in front of our Server, so a test can cut every connection the Go Client holds —
/// a WebSocket session outlives its Server's shutdown — and send the reconnect to a fresh Server
/// that has never seen the Agent.
struct Relay {
    addr: SocketAddr,
    upstream: Arc<Mutex<SocketAddr>>,
    connections: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Relay {
    async fn start(upstream: SocketAddr) -> Relay {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the relay");
        let addr = listener.local_addr().expect("local addr");
        let upstream = Arc::new(Mutex::new(upstream));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let (target, held) = (upstream.clone(), connections.clone());
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let to = *target.lock().unwrap();
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                held.lock().unwrap().push(task);
            }
        });
        Relay {
            addr,
            upstream,
            connections,
        }
    }

    fn url(&self, scheme: &str) -> String {
        format!("{scheme}://{}/v1/opamp", self.addr)
    }

    /// Cuts every relayed connection and sends what comes next to `upstream`.
    fn switch_to(&self, upstream: SocketAddr) {
        *self.upstream.lock().unwrap() = upstream;
        for task in self.connections.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

/// The Go Client's own description, as the harness sets it.
const GO_AGENT_TYPE: &str = "opamp-go-harness";

async fn go_client_against_our_server(scheme: &str) {
    let server = OurServer::start().await;
    let relay = Relay::start(server.addr).await;
    let mut go = Harness::spawn(&["client", &relay.url(scheme)]);
    let uid = go.wait_for("the Go Client to start", "started", |_| true)["instance_uid"]
        .as_str()
        .unwrap()
        .to_string();

    // Connect and report: the Agent appears with its description and exactly the capabilities
    // it declared.
    let view = wait_until("the Go Client's Agent to appear described", || {
        server
            .agent(&uid)
            .filter(|a| a.service_name == GO_AGENT_TYPE)
    })
    .await;
    for capability in [
        "ReportsStatus",
        "AcceptsRemoteConfig",
        "ReportsRemoteConfig",
        "ReportsEffectiveConfig",
        "ReportsHeartbeat",
    ] {
        assert!(
            view.capabilities.iter().any(|c| c == capability),
            "{capability} missing from {:?}",
            view.capabilities
        );
    }
    assert_eq!(
        view.transport,
        if scheme == "ws" { "websocket" } else { "http" }
    );

    // sequence_num advances under heartbeats; that it advances without a gap is what the
    // ReportFullState steps below decide, through a gap our Server must notice.
    let first = view.sequence_num;
    wait_until("three more reports", || {
        server.agent(&uid).filter(|a| a.sequence_num >= first + 3)
    })
    .await;

    // The Server's capabilities reach the Go Client (read off the wire on plain HTTP, where the
    // harness can see the reply before opamp-go does).
    if scheme == "http" {
        let reply = go.wait_for("a reply carrying capabilities", "server_reply", |e| {
            e["capabilities"].as_u64().unwrap_or(0) != 0
        });
        let declared = reply["capabilities"].as_u64().unwrap();
        assert_ne!(declared & bits::SERVER_ACCEPTS_STATUS, 0);
        assert_ne!(declared & bits::SERVER_OFFERS_REMOTE_CONFIG, 0);
    }

    // Remote config: offered, acknowledged as APPLIED with its hash, and not offered again.
    common::save(&server.state, "interop", "interop: true\n", GO_AGENT_TYPE);
    common::release_to_every_agent(&server.state, &["interop"]);
    wait_until("the Configuration to be assigned to the Go Client", || {
        server
            .agent(&uid)
            .filter(|a| a.assigned_configurations.iter().any(|c| c == "interop"))
    })
    .await;
    let offer = go.wait_for("the remote config offer", "message", |e| {
        e.get("remote_config_hash").is_some()
    });
    assert_eq!(offer["remote_config_names"], json!(["interop"]));
    wait_until("the Server to see the offer APPLIED and in sync", || {
        server
            .agent(&uid)
            .filter(|a| a.remote_config_status == "APPLIED" && a.in_sync)
    })
    .await;
    let settled = server.agent(&uid).unwrap().sequence_num;
    wait_until("three reports after the acknowledgement", || {
        server.agent(&uid).filter(|a| a.sequence_num >= settled + 3)
    })
    .await;
    let offers = go
        .events("message")
        .into_iter()
        .filter(|e| e.get("remote_config_hash").is_some())
        .count();
    assert_eq!(offers, 1, "the hash gate let an applied offer repeat");

    // Until now nothing was lost, so our Server never asked for the full state.
    if scheme == "http" {
        let asked = go
            .events("server_reply")
            .iter()
            .filter(|e| e["flags"].as_u64().unwrap_or(0) & bits::REPORT_FULL_STATE != 0)
            .count();
        assert_eq!(asked, 0, "ReportFullState without a gap");
    }

    // ReportFullState for an unknown Agent: a second Server that has never seen it asks, and
    // gets the description back.
    let other = OurServer::start().await;
    relay.switch_to(other.addr);
    wait_until("the second Server to recover the full state", || {
        other
            .agent(&uid)
            .filter(|a| a.service_name == GO_AGENT_TYPE)
    })
    .await;
    if scheme == "http" {
        go.wait_for(
            "the ReportFullState flag on the wire",
            "server_reply",
            |e| e["flags"].as_u64().unwrap_or(0) & bits::REPORT_FULL_STATE != 0,
        );
    }

    // ReportFullState for a gap: the description changes while the first Server is not
    // listening, so when the Agent comes back to it, the first Server sees `sequence_num` jump
    // and can learn the change only by asking for the full state.
    go.send(json!({"cmd": "describe", "body": "after-the-gap"}));
    let marked = |a: &AgentView| {
        a.non_identifying_attributes
            .get("interop.mark")
            .map(String::as_str)
            == Some("after-the-gap")
    };
    wait_until("the second Server to see the changed description", || {
        other.agent(&uid).filter(|a| marked(a))
    })
    .await;
    relay.switch_to(server.addr);
    wait_until(
        "the first Server to recover the change after the gap",
        || server.agent(&uid).filter(|a| marked(a)),
    )
    .await;

    // A graceful stop. Whether our Server is told goodbye is not decided here: `opamp-go`'s
    // plain-HTTP Client sends no `agent_disconnect`, and over WebSocket the goodbye and the
    // closing socket mark the Agent disconnected alike (interop/README.md).
    go.send(json!({"cmd": "stop"}));
    let stopped = go.wait_for("the Go Client to stop", "stopped", |_| true);
    assert!(stopped.get("error").is_none(), "stop failed: {stopped}");
}

/// A Server-assigned identity: the Go Client asks for one, our Server mints it, and the Agent
/// continues under the new `instance_uid` alone.
async fn go_client_takes_an_assigned_identity(scheme: &str) {
    let server = OurServer::start().await;
    let go = Harness::spawn(&[
        "client",
        "--request-uid",
        &format!("{scheme}://{}/v1/opamp", server.addr),
    ]);
    let own = go.wait_for("the Go Client to start", "started", |_| true)["instance_uid"]
        .as_str()
        .unwrap()
        .to_string();
    let assigned = go.wait_for("an AgentIdentification", "message", |e| {
        e.get("new_instance_uid").is_some()
    })["new_instance_uid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(uid_hex(&own), uid_hex(&assigned));
    wait_until("the Agent to report under the assigned identity", || {
        server
            .agent(&assigned)
            .filter(|a| a.service_name == GO_AGENT_TYPE)
    })
    .await;
    assert!(
        server.agent(&own).is_none(),
        "the requested identity survived beside the assigned one"
    );
}

// Verifies: ADR-0011
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a Go toolchain; run with --ignored in the interop job"]
async fn opamp_go_client_against_our_server_over_websocket() {
    go_client_against_our_server("ws").await;
    go_client_takes_an_assigned_identity("ws").await;
}

// Verifies: ADR-0011
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a Go toolchain; run with --ignored in the interop job"]
async fn opamp_go_client_against_our_server_over_plain_http() {
    go_client_against_our_server("http").await;
    go_client_takes_an_assigned_identity("http").await;
}

/// Our Client binary, killed on drop so a failing assertion never leaks it.
struct OurClient(Child);

impl OurClient {
    /// SIGTERM, the service managers' stop: the Client shuts down gracefully.
    fn terminate(&mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
        let deadline = Instant::now() + TIMEOUT;
        while self.0.try_wait().expect("poll the Client").is_none() {
            assert!(Instant::now() < deadline, "the Client did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for OurClient {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn our_client(dir: &Path, endpoint: &str) -> (OurClient, PathBuf) {
    our_client_with(dir, endpoint, &common::client_identity(dir))
}

/// Our Client with the `[tls]` table given, which names its certificate and, for a TLS endpoint,
/// the CA it trusts.
fn our_client_with(dir: &Path, endpoint: &str, tls: &str) -> (OurClient, PathBuf) {
    let state_dir = dir.join("client-state");
    let config = format!(
        concat!(
            "endpoint = {endpoint:?}\n",
            "state_dir = {state_dir:?}\n",
            "heartbeat_interval_secs = 1\n",
            "poll_interval_secs = 1\n",
            "name = \"interop\"\n",
            "{identity}",
        ),
        endpoint = endpoint,
        state_dir = state_dir.to_string_lossy(),
        identity = tls,
    );
    let path = dir.join("supervisor.toml");
    std::fs::write(&path, config).expect("write supervisor.toml");
    let child = Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("--config")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the Client");
    (OurClient(child), state_dir)
}

fn our_client_against_go_server(scheme: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut go = Harness::spawn(&["server"]);
    let port = go.wait_for("the Go Server to listen", "listening", |_| true)["port"]
        .as_u64()
        .unwrap();
    let (mut client, state_dir) =
        our_client(dir.path(), &format!("{scheme}://127.0.0.1:{port}/v1/opamp"));

    // Connect and report: the Client's own Agent describes itself as the `supervisor` type and
    // declares what it does.
    let first = go.wait_for(
        "our Client's first described report",
        "agent_message",
        |e| e["has_description"] == true,
    );
    assert_eq!(first["service_name"], "supervisor");
    let uid = first["instance_uid"].as_str().unwrap().to_string();
    let capabilities = first["capabilities"].as_u64().unwrap();
    for bit in [
        bits::AGENT_REPORTS_STATUS,
        bits::AGENT_ACCEPTS_REMOTE_CONFIG,
        bits::AGENT_REPORTS_EFFECTIVE_CONFIG,
        bits::AGENT_REPORTS_REMOTE_CONFIG,
    ] {
        assert_ne!(
            capabilities & bit,
            0,
            "bit {bit:#x} missing from {capabilities:#x}"
        );
    }

    // sequence_num continuity, and a compressed report once nothing changed.
    let seqs = |go: &Harness| -> Vec<u64> {
        go.events("agent_message")
            .iter()
            .filter(|e| e["instance_uid"] == uid.as_str())
            .map(|e| e["sequence_num"].as_u64().unwrap())
            .collect()
    };
    go.wait_for("a compressed report", "agent_message", |e| {
        e["instance_uid"] == uid.as_str() && e["has_description"] == false
    });
    let run = seqs(&go);
    assert!(
        run.windows(2).all(|w| w[1] == w[0] + 1),
        "sequence_num skipped: {run:?}"
    );

    // Capability negotiation, the Server's half: while the Server declares
    // AcceptsEffectiveConfig our Client reports its effective configuration...
    let full = |e: &Value| e["instance_uid"] == uid.as_str() && e["has_description"] == true;
    assert!(
        go.events("agent_message")
            .iter()
            .any(|e| full(e) && e["has_effective_config"] == true),
        "no effective configuration reported to a Server that accepts one"
    );
    // ...and once the Server stops declaring it, a full report leaves it out.
    let without_effective_config = bits::SERVER_ACCEPTS_STATUS | bits::SERVER_OFFERS_REMOTE_CONFIG;
    go.send(json!({"cmd": "capabilities", "body": without_effective_config.to_string()}));
    go.wait_for("the new capabilities to be queued", "queued", |e| {
        e["cmd"] == "capabilities"
    });

    // ReportFullState: asked for it, the next report carries the full description again.
    go.send(json!({"cmd": "report_full_state"}));
    go.wait_for("ReportFullState to go out", "sent", |e| {
        e["what"] == "report_full_state"
    });
    // The flag rides the reply to one report; the report after that one is the full one.
    let asked_at = {
        let log = go.events.lock().unwrap();
        let sent = log
            .iter()
            .position(|e| e["event"] == "sent" && e["what"] == "report_full_state")
            .expect("the flag went out");
        log[..sent]
            .iter()
            .rev()
            .find(|e| e["event"] == "agent_message" && e["instance_uid"] == uid.as_str())
            .and_then(|e| e["sequence_num"].as_u64())
            .expect("a report the flag answered")
    };
    let refreshed = go.wait_for("a full report after the flag", "agent_message", |e| {
        full(e) && e["sequence_num"].as_u64().unwrap() > asked_at
    });
    assert_eq!(
        refreshed["has_effective_config"], false,
        "effective configuration reported to a Server that no longer accepts it"
    );

    // Remote config: an empty Supervisor set offered to the Client's own Agent is applied and
    // acknowledged with the offered hash.
    go.send(json!({"cmd": "offer_config", "name": "supervisor", "body": "# no Supervisors\n"}));
    let hash = go.wait_for("the offer to be queued", "queued", |e| {
        e["cmd"] == "offer_config"
    })["hash"]
        .as_str()
        .unwrap()
        .to_string();
    let applied = go.wait_for("the offer to be acknowledged", "agent_message", |e| {
        e["remote_config_hash"] == hash.as_str()
            && (e["remote_config_status"] == "RemoteConfigStatuses_APPLIED"
                || e["remote_config_status"] == "RemoteConfigStatuses_FAILED")
    });
    assert_eq!(
        applied["remote_config_status"], "RemoteConfigStatuses_APPLIED",
        "the offer failed: {applied}"
    );

    // A Server-assigned identity: adopted at once and persisted.
    go.send(json!({"cmd": "new_uid"}));
    let assigned = go.wait_for("the new identity to be queued", "queued", |e| {
        e["cmd"] == "new_uid"
    })["uid"]
        .as_str()
        .unwrap()
        .to_string();
    go.wait_for(
        "a report under the assigned identity",
        "agent_message",
        |e| e["instance_uid"] == assigned.as_str(),
    );
    let persisted = std::fs::read_to_string(state_dir.join("instance-uid"))
        .expect("read the persisted instance UID");
    assert_eq!(uid_hex(&persisted), uid_hex(&assigned));

    // agent_disconnect: a graceful stop says goodbye under the identity in force.
    client.terminate();
    go.wait_for("agent_disconnect", "agent_message", |e| {
        e["instance_uid"] == assigned.as_str() && e["agent_disconnect"] == true
    });
}

// Verifies: ADR-0011
#[test]
#[ignore = "needs a Go toolchain; run with --ignored in the interop job"]
fn our_client_against_opamp_go_server_over_websocket() {
    our_client_against_go_server("ws");
}

// Verifies: ADR-0011
#[test]
#[ignore = "needs a Go toolchain; run with --ignored in the interop job"]
fn our_client_against_opamp_go_server_over_plain_http() {
    our_client_against_go_server("http");
}

/// A PKI of the test's own, written to files: a CA and the certificates it issues. Nothing in it
/// reaches the network.
struct TestPki {
    dir: tempfile::TempDir,
    ca_pem: String,
    ca_key_pem: String,
}

/// One party's files: the CA it trusts, its certificate, its key.
struct Party {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

/// The name our TLS endpoints are reached by: an IP address in the certificate, so nothing depends
/// on how a host resolves `localhost`.
const LOOPBACK: &str = "127.0.0.1";

impl TestPki {
    fn new(name: &str) -> TestPki {
        let key = rcgen::KeyPair::generate().expect("CA key");
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("CA params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-sign the CA");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("ca.pem"), cert.pem()).expect("write the CA");
        TestPki {
            dir,
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    fn ca_file(&self) -> PathBuf {
        self.dir.path().join("ca.pem")
    }

    /// A certificate for `name` — a DNS name, or an IP address — issued directly by this CA.
    fn issue(&self, name: &str) -> Party {
        let ca_key = rcgen::KeyPair::from_pem(&self.ca_key_pem).expect("CA key");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.ca_pem, ca_key).expect("issuer");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("sign");
        let cert_file = self.dir.path().join(format!("{name}.pem"));
        let key_file = self.dir.path().join(format!("{name}-key.pem"));
        std::fs::write(&cert_file, cert.pem()).expect("write the certificate");
        std::fs::write(&key_file, key.serialize_pem()).expect("write the key");
        Party {
            ca: self.ca_file(),
            cert: cert_file,
            key: key_file,
        }
    }
}

impl Party {
    /// The same party, trusting `ca` instead: a stranger who knows whom to trust.
    fn trusting(self, ca: &Path) -> Party {
        Party {
            ca: ca.to_path_buf(),
            ..self
        }
    }

    /// The harness Client's `--tls` value: the CA it trusts, its certificate and key.
    fn as_client(&self) -> String {
        format!(
            "{},{},{}",
            self.ca.display(),
            self.cert.display(),
            self.key.display()
        )
    }

    /// The harness Server's `--tls` value: its certificate and key, and the CA it requires client
    /// certificates from — the one it trusts.
    fn as_server(&self) -> String {
        format!(
            "{},{},{}",
            self.cert.display(),
            self.key.display(),
            self.ca.display()
        )
    }

    /// Our Client's `[tls]` table: the CA it trusts and the certificate it presents.
    fn tls_table(&self) -> String {
        format!(
            "\n[tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
            self.ca.display().to_string(),
            self.cert.display().to_string(),
            self.key.display().to_string(),
        )
    }
}

/// Our Server's TLS and admission as the binary sets them up (`main.rs`): TLS 1.3 alone and
/// admission by a client certificate its client CA issued, required in the handshake. What does
/// not act at the handshake — revocation, the audit record, rate limits — is left out.
async fn our_tls_server(pki: &TestPki) -> (SocketAddr, Arc<AppState>, tempfile::TempDir) {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(common::fleet_state(dir.path()));
    let server = pki.issue(LOOPBACK);
    let tls = toml::from_str::<fleet_server::config::TlsConfig>(&format!(
        "cert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
        server.cert.display().to_string(),
        server.key.display().to_string(),
        server.ca.display().to_string(),
    ))
    .expect("the [tls] table");
    let planes = fleet_server::tls::server_tls(&tls, None, None).expect("server material");
    let agent_tls = planes.agent.rustls_config().expect("the Agent plane's TLS");
    let admission =
        fleet_server::transport::Admission::new(true).with_enrolment(planes.issuers, None);
    let listener = std::net::TcpListener::bind((LOOPBACK, 0)).expect("bind the Agent plane");
    let addr = listener.local_addr().expect("local addr");
    let app = fleet_server::agent_app(state.clone(), admission);
    let handle = opamp::server::listen::Handle::new();
    tokio::spawn(fleet_server::listen::plane(listener, Some(agent_tls), 64, handle).serve(app));
    (addr, state, dir)
}

/// A harness Client that our Server must refuse: it starts, fails to connect, and never appears.
fn refused_go_client(state: &AppState, args: &[&str]) {
    let go = Harness::spawn(args);
    let uid = go.wait_for("the refused Client to start", "started", |_| true)["instance_uid"]
        .as_str()
        .unwrap()
        .to_string();
    go.wait_for("its connection to fail", "connect_failed", |_| true);
    assert!(go.events("connected").is_empty(), "it was let in");
    assert!(
        state
            .snapshot()
            .iter()
            .all(|a| uid_hex(&a.instance_uid) != uid_hex(&uid)),
        "it reached the fleet"
    );
}

/// `opamp-go`'s Client against our Server's TLS and admission: a member's certificate, offered the
/// way a real `opamp-go` agent offers one, is admitted, reports and takes a configuration; a
/// certificate another CA issued is refused, and so is a peer that offers none.
async fn go_client_against_our_tls_server(scheme: &str) {
    let pki = TestPki::new("interop-fleet-ca");
    let (addr, state, _dir) = our_tls_server(&pki).await;
    let url = format!("{scheme}://{addr}/v1/opamp");
    let agent = |uid: &str| {
        state
            .snapshot()
            .into_iter()
            .find(|a| uid_hex(&a.instance_uid) == uid_hex(uid))
    };

    let member = pki.issue("go-agent");
    let go = Harness::spawn(&["client", "--tls", &member.as_client(), &url]);
    let uid = go.wait_for("the Go Client to start", "started", |_| true)["instance_uid"]
        .as_str()
        .unwrap()
        .to_string();
    wait_until("the admitted Go Client to report its description", || {
        agent(&uid).filter(|a| a.service_name == GO_AGENT_TYPE)
    })
    .await;
    common::save(&state, "interop-tls", "interop: tls\n", GO_AGENT_TYPE);
    common::release_to_every_agent(&state, &["interop-tls"]);
    wait_until("the configuration APPLIED over TLS", || {
        agent(&uid).filter(|a| a.remote_config_status == "APPLIED" && a.in_sync)
    })
    .await;
    drop(go);

    let elsewhere = TestPki::new("someone-elses-ca");
    let stranger = elsewhere.issue("go-agent").trusting(&pki.ca_file());
    refused_go_client(
        &state,
        &[
            "client",
            "--tls",
            &stranger.as_client(),
            "--force-cert",
            &url,
        ],
    );
    let nobody = format!("{},,", pki.ca_file().display());
    refused_go_client(&state, &["client", "--tls", &nobody, &url]);
}

/// Our Client against an `opamp-go` Server requiring a client certificate: with the certificate the
/// Server's client CA issued it reports and applies a configuration; with one another CA issued it
/// tries, and is refused in the handshake.
fn our_client_against_go_tls_server(scheme: &str) {
    let pki = TestPki::new("interop-go-ca");
    let mut go = Harness::spawn(&["server", "--tls", &pki.issue(LOOPBACK).as_server()]);
    let port = go.wait_for("the Go Server to listen", "listening", |_| true)["port"]
        .as_u64()
        .unwrap();
    let endpoint = format!("{scheme}://{LOOPBACK}:{port}/v1/opamp");

    let dir = tempfile::tempdir().expect("tempdir");
    let member = pki.issue("our-agent");
    let (client, _) = our_client_with(dir.path(), &endpoint, &member.tls_table());
    let first = go.wait_for("our Client's first report over TLS", "agent_message", |e| {
        e["has_description"] == true
    });
    assert_eq!(first["service_name"], "supervisor");
    let uid = first["instance_uid"].as_str().unwrap().to_string();
    go.send(json!({"cmd": "offer_config", "name": "supervisor", "body": "# no Supervisors\n"}));
    let hash = go.wait_for("the offer to be queued", "queued", |e| {
        e["cmd"] == "offer_config"
    })["hash"]
        .as_str()
        .unwrap()
        .to_string();
    go.wait_for("the offer APPLIED over TLS", "agent_message", |e| {
        e["instance_uid"] == uid.as_str()
            && e["remote_config_hash"] == hash.as_str()
            && e["remote_config_status"] == "RemoteConfigStatuses_APPLIED"
    });
    drop(client);

    let other = tempfile::tempdir().expect("tempdir");
    let elsewhere = TestPki::new("someone-elses-ca");
    let stranger = elsewhere.issue("our-agent").trusting(&pki.ca_file());
    let (hellos, reported) = (
        go.events("client_hello").len(),
        go.events("agent_message").len(),
    );
    let (mut refused, _) = our_client_with(other.path(), &endpoint, &stranger.tls_table());
    // It tries: handshakes arrive while the Client keeps running.
    let deadline = Instant::now() + TIMEOUT;
    while go.events("client_hello").len() < hellos + 2 {
        assert!(Instant::now() < deadline, "the stranger never tried");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        refused.0.try_wait().expect("poll the Client").is_none(),
        "the Client with the stranger's certificate gave up instead of retrying"
    );
    // And none of those attempts became a message.
    let after = go.events("agent_message");
    assert!(
        after[reported..]
            .iter()
            .all(|e| e["instance_uid"] == uid.as_str()),
        "a certificate another CA issued was admitted: {:?}",
        &after[reported..]
    );
}

// Verifies: ADR-0011, ADR-0013, ADR-0021
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a Go toolchain; run with --ignored in the interop job"]
async fn opamp_go_client_against_our_tls_and_admission() {
    go_client_against_our_tls_server("wss").await;
    go_client_against_our_tls_server("https").await;
}

// Verifies: ADR-0011, ADR-0013, ADR-0021
#[test]
#[ignore = "needs a Go toolchain; run with --ignored in the interop job"]
fn our_client_against_opamp_go_server_requiring_a_client_certificate() {
    our_client_against_go_tls_server("wss");
    our_client_against_go_tls_server("https");
}
