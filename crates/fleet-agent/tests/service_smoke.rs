//! The Client under the machine's **real** service manager — systemd, launchd, or the SCM
//! (ADR-0019, ADR-0018).
//!
//! Every other test in this project stands in for the service manager: the self-update end-to-end
//! test restarts the Client itself, "exactly as systemd would". That is what makes the update loop
//! observable, and it is also the one thing it cannot assert — whether the manager *would*. On
//! Windows that gap is the whole contract: `service-manager`'s `sc.exe` backend silently discards a
//! restart policy, so the Client registers the recovery actions itself and reports
//! `ServiceSpecific(10)` on exit so the SCM reads a failure rather than a clean stop. Nothing has
//! ever proved that this brings a Client back.
//!
//! **Ignored by default, and not part of any ordinary run.** It registers a system service, starts
//! it, and kills it — it needs root or an Administrator, and it changes the machine. The
//! `service-smoke` workflow runs it with `--ignored` on an ephemeral runner; locally, run it only
//! on a host you are willing to have a service installed on:
//!
//! ```console
//! sudo -E cargo test -p fleet-agent --test service_smoke -- --ignored --nocapture
//! ```
//!
//! What it does **not** cover: starting at boot (a runner never reboots), long-running behaviour,
//! and hosts with SELinux or AppArmor in the way. The manual checklist in `README.md` keeps those.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_agent::service::manager::{service_name, NativeService, RESTART_DELAY_SECS};
use fleet_agent::service::{ServiceControl, ServiceLevel, ServiceState};
use fleet_server::fleet::{AgentView, AppState};

/// The operator's name for this Agent — written as `name` in the `supervisor.toml` below and
/// reported as `service.instance.name` (ADR-0016), which is what the fleet view is searched by.
/// Deliberately not `service.name`: that carries the Agent *type*, which for this Client is always
/// `supervisor` (ADR-0019).
///
/// There is no `--instance` to isolate this run under (ADR-0019 clause 6), and the service it
/// registers carries the product's name like any other install. This test therefore takes over the
/// host's one service for its duration, which is what `Registered` exists to undo.
const AGENT_NAME: &str = "service-smoke-client";

fn service() -> NativeService {
    NativeService::new(ServiceLevel::System)
}

/// Uninstalls whatever this test installed, however it ends — a leftover service would make the
/// next run fail for a reason that has nothing to do with the code under test.
struct Registered;

impl Drop for Registered {
    fn drop(&mut self) {
        let _ = service().stop();
        let _ = client(&["service", "uninstall"], &PathBuf::from("supervisor.toml"));
    }
}

/// Runs the real CLI, the way the README's checklist tells an operator to. Driving the binary
/// rather than the library is the point here: `service install` also stages the versioned layout,
/// and an operator's mistake would be in that command line.
fn client(args: &[&str], config: &Path) -> Result<String, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run the client: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "`client {}` failed with {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn wait_for<T>(what: &str, timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return value;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

fn agent(state: &AppState) -> Option<AgentView> {
    state
        .snapshot()
        .into_iter()
        .find(|a| a.service_instance_name == AGENT_NAME)
}

/// The service's process id, asked of the platform's own manager. `None` when nothing is running
/// under that name — which is itself an answer the assertions below use.
fn service_pid() -> Option<u32> {
    // One name on every platform (ADR-0019 clause 3), so this is what systemd, launchd, and the SCM
    // are each asked about.
    let qualified = service_name();
    #[cfg(windows)]
    {
        // `sc queryex` prints `PID                : 1234`.
        let out = Command::new("sc")
            .args(["queryex", qualified])
            .output()
            .expect("run sc queryex");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        parse_after(&text, "PID")
    }
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("systemctl")
            .args(["show", "-p", "MainPID", &format!("{qualified}.service")])
            .output()
            .expect("run systemctl show");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        parse_after(&text, "MainPID")
    }
    #[cfg(target_os = "macos")]
    {
        // `launchctl list <label>` prints a plist; `"PID" = 1234;` is there while it runs.
        let out = Command::new("launchctl")
            .args(["list", qualified])
            .output()
            .expect("run launchctl list");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        parse_after(&text, "\"PID\"")
    }
}

/// The first non-zero number on the line naming `key`, whatever separator the platform's tool puts
/// between the two.
fn parse_after(text: &str, key: &str) -> Option<u32> {
    text.lines()
        .find(|line| line.trim_start().starts_with(key))?
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .find_map(|part| part.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
}

fn kill(pid: u32) {
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status();
    #[cfg(unix)]
    let status = Command::new("kill").args(["-9", &pid.to_string()]).status();
    assert!(
        status.expect("run the kill").success(),
        "could not kill the service's process {pid}"
    );
}

/// A Server the installed service can reach. Bound on the loopback interface, so it is reachable
/// from a service running as `LocalSystem` or `root` — a different account, the same machine.
fn spawn_server() -> (
    std::net::SocketAddr,
    Arc<AppState>,
    std::thread::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("configs"));
    std::mem::forget(dir);
    let (tx, rx) = std::sync::mpsc::channel();
    let served = state.clone();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            tx.send(listener.local_addr().expect("addr")).expect("send");
            axum::serve(
                listener,
                fleet_server::agent_app(served, fleet_server::transport::Admission::open()),
            )
            .await
            .expect("serve");
        });
    });
    let addr = rx.recv().expect("the server's address");
    (addr, state, handle)
}

/// Install → start → the Agent is in the fleet → kill it → the manager brings it back → stop →
/// it stays down → uninstall.
///
/// The kill is the assertion the stand-in service manager cannot make, and the reason this test
/// exists: `RestartPolicy::OnFailure` is what a self-update relies on to come back at all, and on
/// Windows it is a set of recovery actions this Client registers itself.
/// Verifies: ADR-0018, ADR-0019, G-11
#[test]
#[ignore = "installs a real system service; run with --ignored in the service-smoke job"]
fn the_installed_service_starts_comes_back_from_a_crash_and_stays_down_after_a_stop() {
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::NotInstalled,
        "a leftover {} service from an earlier run — remove it before running this",
        service_name()
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("install");
    let (addr, state, _server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n{}",
            common::client_identity(dir.path())
        ),
    )
    .expect("write supervisor.toml");

    client(
        &["service", "install", "--root", &root.to_string_lossy()],
        &config,
    )
    .expect("install the service");
    let _registered = Registered;

    // launchd does not auto-start after an install (a known ADR-0019 gap), so every platform is
    // started explicitly — which is also what the README's checklist tells an operator to do.
    client(&["service", "start"], &config).expect("start the service");
    wait_for(
        "the service to report running",
        Duration::from_secs(60),
        || (service().state().ok()? == ServiceState::Running).then_some(()),
    );

    // The proof that the unit, plist or SCM entry starts a *working* Client: it reaches the Server
    // and appears in the fleet. A malformed program path or working directory dies here.
    wait_for(
        "the Agent to appear in the fleet",
        Duration::from_secs(60),
        || agent(&state).filter(|a| a.connected).map(|_| ()),
    );

    let first = wait_for(
        "the service's process id",
        Duration::from_secs(30),
        service_pid,
    );
    kill(first);
    wait_for(
        "the Agent to drop off the fleet",
        Duration::from_secs(30),
        || agent(&state).filter(|a| !a.connected).map(|_| ()),
    );

    // The restart policy, asserted against the platform that implements it. The delay is the
    // Client's own, so waiting a generous multiple of it is the difference between "not yet" and
    // "never".
    let second = wait_for(
        "the service manager to restart the killed service",
        Duration::from_secs(u64::from(RESTART_DELAY_SECS) * 12),
        || service_pid().filter(|pid| *pid != first),
    );
    assert_ne!(first, second, "a new process, not the one that was killed");
    wait_for(
        "the restarted Agent to reconnect",
        Duration::from_secs(60),
        || agent(&state).filter(|a| a.connected).map(|_| ()),
    );

    // An explicit stop is not a failure: the recovery actions must not fire.
    client(&["service", "stop"], &config).expect("stop the service");
    wait_for(
        "the service to report stopped",
        Duration::from_secs(60),
        || (service().state().ok()? == ServiceState::Stopped).then_some(()),
    );
    std::thread::sleep(Duration::from_secs(u64::from(RESTART_DELAY_SECS) * 3));
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::Stopped,
        "an explicitly stopped service must stay down (ADR-0019)"
    );

    client(&["service", "uninstall"], &config).expect("uninstall the service");
    wait_for(
        "the service to be deregistered",
        Duration::from_secs(30),
        || (service().state().ok()? == ServiceState::NotInstalled).then_some(()),
    );
}

/// A temporary system account for one test, removed however the test ends.
#[cfg(target_os = "linux")]
struct TemporaryAccount(&'static str);

#[cfg(target_os = "linux")]
impl TemporaryAccount {
    fn create(name: &'static str) -> Self {
        let status = Command::new("useradd")
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                name,
            ])
            .status()
            .expect("run useradd");
        assert!(status.success(), "cannot create the account {name}");
        Self(name)
    }
}

#[cfg(target_os = "linux")]
impl Drop for TemporaryAccount {
    fn drop(&mut self) {
        let _ = Command::new("userdel").arg(self.0).status();
    }
}

/// Install under an account, then re-install without `--run-as`, as every package upgrade does:
/// the service still runs as the account, and the unit the Client wrote leaves it the privileges
/// a Managed Process needs for `sudo` and setuid helpers — no `no_new_privs`, and `/` not mounted
/// `nosuid`. `systemd-analyze verify` accepts the unit.
/// Verifies: ADR-0042
#[cfg(target_os = "linux")]
#[test]
#[ignore = "installs a real system service; run with --ignored in the service-smoke job"]
fn a_reregistration_keeps_the_account_and_the_service_keeps_its_privileges() {
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::NotInstalled,
        "a leftover {} service from an earlier run — remove it before running this",
        service_name()
    );
    let account = TemporaryAccount::create("opamp-fleet-smoke");

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("install");
    let (addr, state, _server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n{}",
            common::client_identity(dir.path())
        ),
    )
    .expect("write supervisor.toml");
    // The account must reach its program and read the identity beside the configuration, which
    // lie outside the roots the install hands over.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the temporary directory");
    for file in ["test-client.pem", "test-client-key.pem"] {
        let status = Command::new("chown")
            .arg(account.0)
            .arg(dir.path().join(file))
            .status()
            .expect("run chown");
        assert!(status.success(), "cannot give {file} to the account");
    }

    let root_arg = root.to_string_lossy().into_owned();
    client(
        &[
            "service", "install", "--root", &root_arg, "--run-as", account.0,
        ],
        &config,
    )
    .expect("install the service under the account");
    let _registered = Registered;
    let again = client(&["service", "install", "--root", &root_arg], &config)
        .expect("re-install without --run-as");
    assert!(
        again.contains(&format!("runs as:   {} (kept from", account.0)),
        "{again}"
    );

    client(&["service", "start"], &config).expect("start the service");
    wait_for(
        "the Agent to appear in the fleet",
        Duration::from_secs(60),
        || agent(&state).filter(|a| a.connected).map(|_| ()),
    );
    let pid = wait_for(
        "the service's process id",
        Duration::from_secs(30),
        service_pid,
    );

    let user = Command::new("systemctl")
        .args(["show", "-p", "User", &format!("{}.service", service_name())])
        .output()
        .expect("run systemctl show");
    assert_eq!(
        String::from_utf8_lossy(&user.stdout).trim(),
        format!("User={}", account.0)
    );
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    let no_new_privs = status
        .lines()
        .find(|l| l.starts_with("NoNewPrivs:"))
        .expect("NoNewPrivs line");
    assert_eq!(
        no_new_privs.split_whitespace().nth(1),
        Some("0"),
        "{status}"
    );
    let mounts = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).expect("mountinfo");
    let slash = mounts
        .lines()
        .rev()
        .find(|l| l.split_whitespace().nth(4) == Some("/"))
        .expect("the mount of /");
    let options = slash.split_whitespace().nth(5).expect("mount options");
    assert!(!options.split(',').any(|o| o == "nosuid"), "{slash}");
    let verify = Command::new("systemd-analyze")
        .args([
            "verify",
            &format!("/etc/systemd/system/{}.service", service_name()),
        ])
        .output()
        .expect("run systemd-analyze verify");
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    client(&["service", "stop"], &config).expect("stop the service");
    client(&["service", "uninstall"], &config).expect("uninstall the service");
}
