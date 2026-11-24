//! The Client under the machine's **real** service manager — systemd, launchd, or the SCM.
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
//! sudo -E cargo test -p classis-agent --test service_smoke -- --ignored --nocapture
//! ```
//!
//! What it does **not** cover: starting at boot (a runner never reboots), long-running behaviour,
//! and hosts with SELinux or AppArmor in the way. The manual checklist in `README.md` keeps those.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use classis_agent::service::manager::{service_name, NativeService, RESTART_DELAY_SECS};
use classis_agent::service::{ServiceControl, ServiceLevel, ServiceState};
use classis_server::fleet::{AgentView, AppState};

/// The operator's name for this Agent — written as `name` in the `supervisor.toml` below and
/// reported as `service.instance.name`, which is what the fleet view is searched by.
/// Deliberately not `service.name`: that carries the Agent *type*, which for this Client is always
/// `supervisor`.
///
/// There is no `--instance` to isolate this run under, and the service it
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
    // One name on every platform, so this is what systemd, launchd, and the SCM
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

/// A Server the installed service can reach, and the key of the Space its hosts enrol in.
struct Served {
    key: String,
    _thread: std::thread::JoinHandle<()>,
}

/// A Server the installed service can reach. Bound on the loopback interface, so it is reachable
/// from a service running as `LocalSystem` or `root` — a different account, the same machine. It
/// admits by bearer token, as the binary does.
fn spawn_server() -> (std::net::SocketAddr, Arc<AppState>, Served) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("configs"));
    let admission = common::Admission::new(dir.path());
    let key = admission.key.clone();
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
            axum::serve(listener, admission.app(served))
                .await
                .expect("serve");
        });
    });
    let addr = rx.recv().expect("the server's address");
    (
        addr,
        state,
        Served {
            key,
            _thread: handle,
        },
    )
}

/// Enrols the host the install made, through the real `enrol`: it writes `state.json` in the state
/// directory the registration names, hands it to the account the service runs as, lets the service
/// start at boot and starts it — which is how a service installed here is
/// started.
fn enrol_installed(addr: std::net::SocketAddr, server: &Served, config: &Path) {
    let state_dir = classis_agent::service::manager::registered_state_dir(ServiceLevel::System)
        .expect("read the registration")
        .expect("the install registered a state directory");
    client(
        &[
            "--state-dir",
            &state_dir.to_string_lossy(),
            "enrol",
            &format!("http://{addr}"),
            &server.key,
        ],
        config,
    )
    .expect("enrol the host");
}

/// Install → start → the Agent is in the fleet → kill it → the manager brings it back → stop →
/// it stays down → uninstall.
///
/// The kill is the assertion the stand-in service manager cannot make, and the reason this test
/// exists: `RestartPolicy::OnFailure` is what a self-update relies on to come back at all, and on
/// Windows it is a set of recovery actions this Client registers itself.
/// Verifies: G-11
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
    let (addr, state, server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n"
        ),
    )
    .expect("write supervisor.toml");

    client(
        &["service", "install", "--root", &root.to_string_lossy()],
        &config,
    )
    .expect("install the service");
    let _registered = Registered;

    // An install starts nothing and enables nothing: `enrol` starts the service, and lets it start
    // at boot.
    enrol_installed(addr, &server, &config);
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
        "an explicitly stopped service must stay down"
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
        // `userdel` keeps the account's group while another account is a member of it, as the
        // Client's account is of the process account's: the next run's `useradd` would fail on it.
        let _ = Command::new("groupdel").arg(self.0).status();
    }
}

/// A temporary role account with a group of its own, made with the lines the refusal of a
/// missing process account shows on macOS: `dseditgroup` creates the group, and `sysadminctl
/// -roleAccount` the account, with that group as its primary one. Removed however the test ends.
#[cfg(target_os = "macos")]
struct TemporaryAccount(&'static str);

#[cfg(target_os = "macos")]
impl TemporaryAccount {
    fn create(name: &'static str) -> Self {
        // A role account's uid lies in a range `sysadminctl` names, which macOS releases have
        // moved: the first free id of each range is tried, and the account looked up after.
        for range in [450..500, 300..400] {
            let Some(id) = range.into_iter().find(|id| id_is_free(*id)) else {
                continue;
            };
            let id = id.to_string();
            let group = Command::new("dseditgroup")
                .args(["-o", "create", "-i", &id, name])
                .status()
                .expect("run dseditgroup");
            assert!(group.success(), "cannot create the group {name}");
            let account = Self(name);
            let _ = Command::new("sysadminctl")
                .args(["-addUser", name, "-UID", &id, "-GID", &id, "-roleAccount"])
                .status()
                .expect("run sysadminctl");
            // `sysadminctl`'s exit status is not taken on faith: the account is looked up.
            let found = classis_agent::service::run_as::account_of(id.parse().expect("an id"))
                .expect("the password database");
            if found
                .as_ref()
                .is_some_and(|found| found.name == name && found.gid.to_string() == id)
            {
                return account;
            }
            drop(account);
        }
        panic!("sysadminctl created no role account {name} with a group of its own");
    }
}

/// Whether neither an account nor a group holds `id`.
#[cfg(target_os = "macos")]
fn id_is_free(id: u32) -> bool {
    // SAFETY: a lookup by id; the entry it may return is not read.
    let group = unsafe { libc::getgrgid(id) };
    group.is_null()
        && classis_agent::service::run_as::account_of(id)
            .expect("the password database")
            .is_none()
}

#[cfg(target_os = "macos")]
impl Drop for TemporaryAccount {
    fn drop(&mut self) {
        let _ = Command::new("dscl")
            .args([".", "-delete", &format!("/Users/{}", self.0)])
            .status();
        let _ = Command::new("dseditgroup")
            .args(["-o", "delete", self.0])
            .status();
    }
}

/// The accounts the process account's smoke test creates: on macOS a role account's name begins
/// with `_`.
#[cfg(target_os = "linux")]
const SMOKE_ACCOUNTS: (&str, &str) = ("classis-smoke", "classis-smoke-agents");
#[cfg(target_os = "macos")]
const SMOKE_ACCOUNTS: (&str, &str) = ("_classis-smoke", "_classis-smoke-agents");

/// A temporary directory both accounts reach: under `/tmp` on Linux, and under `/private/tmp` on
/// macOS, where the default one lies in the invoking user's own `0700` directory and `/tmp` is a
/// link.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn shared_tempdir() -> tempfile::TempDir {
    #[cfg(target_os = "macos")]
    return tempfile::tempdir_in("/private/tmp").expect("tempdir");
    #[cfg(target_os = "linux")]
    tempfile::tempdir().expect("tempdir")
}

/// Install under an account, then re-install without `--run-as`, as every package upgrade does:
/// the service still runs as the account, and the unit the Client wrote leaves it the privileges
/// a Managed Process needs for `sudo` and setuid helpers — no `no_new_privs`, and `/` not mounted
/// `nosuid`. `systemd-analyze verify` accepts the unit.
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
    let account = TemporaryAccount::create("classis-smoke");

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("install");
    let (addr, state, server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n"
        ),
    )
    .expect("write supervisor.toml");
    // The account must reach its program, which lies outside the roots the install hands over.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the temporary directory");

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

    enrol_installed(addr, &server, &config);
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

/// Adds the account `member` to the group `group`, as the operator does before naming a process
/// account.
#[cfg(target_os = "linux")]
fn add_to_group(member: &str, group: &str) {
    let status = Command::new("usermod")
        .args(["--append", "--groups", group, member])
        .status()
        .expect("run usermod");
    assert!(status.success(), "cannot add {member} to {group}");
}

#[cfg(target_os = "macos")]
fn add_to_group(member: &str, group: &str) {
    let status = Command::new("dseditgroup")
        .args(["-o", "edit", "-a", member, "-t", "user", group])
        .status()
        .expect("run dseditgroup");
    assert!(status.success(), "cannot add {member} to {group}");
}

/// What the Managed Process below found out about itself, once it has written it: its pid, its
/// account, and what it could and could not reach.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reported(result: &Path, other_than: Option<u32>) -> std::collections::BTreeMap<String, String> {
    wait_for(
        "the Managed Process to report",
        Duration::from_secs(90),
        || {
            let text = std::fs::read_to_string(result).ok()?;
            let report: std::collections::BTreeMap<String, String> = text
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            let pid = report.get("pid")?.parse::<u32>().ok()?;
            (Some(pid) != other_than).then_some(report)
        },
    )
}

/// The account a running process runs as: its uid asked of `ps`, its name of the password
/// database, which no column width shortens.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_of(pid: &str) -> String {
    let out = Command::new("ps")
        .args(["-o", "uid=", "-p", pid])
        .output()
        .expect("run ps");
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let Ok(uid) = uid.parse() else {
        return format!("no process {pid}");
    };
    classis_agent::service::run_as::account_of(uid)
        .expect("the password database")
        .map_or_else(|| format!("uid {uid}"), |account| account.name)
}

/// The uid and primary gid of `account`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ids_of(account: &str) -> (u32, u32) {
    let id = |flag: &str| -> u32 {
        let out = Command::new("id")
            .args([flag, account])
            .output()
            .expect("run id");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("an id")
    };
    (id("-u"), id("-g"))
}

/// The owner, group and mode of `path`, set-ID bits included.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn owner_and_mode(path: &Path) -> (u32, u32, u32) {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path).expect("metadata");
    (meta.uid(), meta.gid(), meta.mode() & 0o7777)
}

/// A Managed Process under a process account: installed with `--run-as` and
/// `--process-account` naming two real accounts, the Client starts its program through the second
/// service, and the program runs as the process account. It reads its `config/`, writes into its
/// data directory, and can neither read a secret of the Client's or its log nor write its own
/// `program/`. After a restart of the second service the Client reaches it again and the program
/// runs again. A re-registration without either flag, as every package upgrade makes, keeps both
/// accounts and leaves the program its data: what it wrote is still its own, and it writes there
/// again. `--no-process-account` returns the program to the Client's account. The in-process tests stand in for the second
/// service under the test's own uid; this is the one place the shipped binary starts a program
/// over the socket under another account. On Linux under systemd, and on macOS under launchd with
/// role accounts made as the refusal of a missing account says.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "installs a real system service; run with --ignored in the service-smoke job"]
fn a_managed_process_runs_under_the_process_account_and_reaches_only_what_it_runs() {
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::NotInstalled,
        "a leftover {} service from an earlier run — remove it before running this",
        service_name()
    );
    let client_account = TemporaryAccount::create(SMOKE_ACCOUNTS.0);
    let process_account = TemporaryAccount::create(SMOKE_ACCOUNTS.1);
    add_to_group(client_account.0, process_account.0);

    let dir = shared_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the temporary directory");
    let root = dir.path().join("install");
    let state = root.join("state");
    let supervisor = state.join("supervisors").join("probe");
    let program = supervisor.join("program");
    let config_dir = supervisor.join("config");
    let data = supervisor.join("data");
    std::fs::create_dir_all(&program).expect("program/");
    std::fs::create_dir_all(&config_dir).expect("config/");
    // A data directory as a process account gets it: the process account's group, `2770`. The
    // command kind names none, so the test makes it as a kind would.
    std::fs::create_dir_all(&data).expect("data/");
    let chgrp = Command::new("chgrp")
        .arg(process_account.0)
        .arg(&data)
        .status()
        .expect("run chgrp");
    assert!(
        chgrp.success(),
        "cannot give data/ to the process account's group"
    );
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o2770)).expect("chmod data/");
    // Where the Managed Process says what it found: writable by anyone, outside every root.
    let out = dir.path().join("out");
    std::fs::create_dir(&out).expect("out/");
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777)).expect("chmod out/");
    let result = out.join("result");

    // The Client's secret where it is protected: `state.json`, which `enrol` writes in the state
    // directory below, owner-only, with the client secret and the token in it.
    let key = state.join("state.json");

    std::fs::write(config_dir.join("settings"), "from the config\n").expect("config entry");
    let script = program.join("probe.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             tmp={out}/result.tmp\n\
             {{\n\
             echo \"pid=$$\"\n\
             echo \"user=$(id -un)\"\n\
             if cat {key} >/dev/null 2>&1; then echo key=read; else echo key=denied; fi\n\
             if ls {logs} >/dev/null 2>&1; then echo logs=read; else echo logs=denied; fi\n\
             if (: > {program}/written) 2>/dev/null; then echo program=written; else echo program=denied; fi\n\
             if (echo $$ >> {data}/written) 2>/dev/null; then echo data=written; else echo data=denied; fi\n\
             echo \"config=$(cat {config}/settings 2>/dev/null)\"\n\
             }} > \"$tmp\"\n\
             mv \"$tmp\" {out}/result\n\
             exec sleep 3600\n",
            out = out.display(),
            key = key.display(),
            logs = state.join("logs").display(),
            program = program.display(),
            data = data.display(),
            config = config_dir.display(),
        ),
    )
    .expect("write the program");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the program");

    let (addr, state_view, server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n\
             [[supervisor]]\ntype = \"command\"\nname = \"probe\"\ncommand = \"probe.sh\"\n",
        ),
    )
    .expect("write supervisor.toml");

    let root_arg = root.to_string_lossy().into_owned();
    client(
        &[
            "service",
            "install",
            "--root",
            &root_arg,
            "--run-as",
            client_account.0,
            "--process-account",
            process_account.0,
        ],
        &config,
    )
    .expect("install the service with a process account");
    let _registered = Registered;
    enrol_installed(addr, &server, &config);
    assert_eq!(
        std::fs::metadata(&key)
            .expect("`enrol` wrote state.json")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the secret the Managed Process is denied is the real one, owner-only"
    );
    wait_for(
        "the Agent to appear in the fleet",
        Duration::from_secs(60),
        || agent(&state_view).filter(|a| a.connected).map(|_| ()),
    );

    let first = reported(&result, None);
    assert_eq!(first["user"], process_account.0, "{first:?}");
    assert_eq!(user_of(&first["pid"]), process_account.0, "{first:?}");
    assert_eq!(first["key"], "denied", "{first:?}");
    assert_eq!(first["logs"], "denied", "{first:?}");
    assert_eq!(first["program"], "denied", "{first:?}");
    assert_eq!(first["config"], "from the config", "{first:?}");
    assert_eq!(first["data"], "written", "{first:?}");

    // The second service restarts, and its programs with it: the Client reaches it again and
    // starts the program again, under the process account.
    let first_pid: u32 = first["pid"].parse().expect("a pid");
    let agents = classis_agent::service::manager::agents_service_name();
    #[cfg(target_os = "linux")]
    let restarted = Command::new("systemctl")
        .args(["restart", &format!("{agents}.service")])
        .status()
        .expect("run systemctl restart");
    #[cfg(target_os = "macos")]
    let restarted = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("system/{agents}")])
        .status()
        .expect("run launchctl kickstart");
    assert!(restarted.success(), "cannot restart the second service");
    let again = reported(&result, Some(first_pid));
    assert_eq!(user_of(&again["pid"]), process_account.0, "{again:?}");

    // Re-registered without either flag, as every package upgrade does: both accounts are kept,
    // and the hand-over leaves the process account its data.
    let again_pid: u32 = again["pid"].parse().expect("a pid");
    client(&["service", "stop"], &config).expect("stop the service");
    let reinstalled = client(&["service", "install", "--root", &root_arg], &config)
        .expect("re-install without --run-as and --process-account");
    assert!(
        reinstalled.contains(&format!("processes: {} (kept from", process_account.0)),
        "{reinstalled}"
    );
    let (client_uid, _) = ids_of(client_account.0);
    let (process_uid, process_gid) = ids_of(process_account.0);
    assert_eq!(
        (owner_and_mode(&data.join("written")), owner_and_mode(&data)),
        (
            (process_uid, process_gid, 0o644),
            (client_uid, process_gid, 0o2770)
        ),
        "the hand-over took the data from the process account"
    );
    client(&["service", "start"], &config).expect("start the service again");
    let upgraded = reported(&result, Some(again_pid));
    assert_eq!(user_of(&upgraded["pid"]), process_account.0, "{upgraded:?}");
    assert_eq!(upgraded["data"], "written", "{upgraded:?}");
    assert_eq!(upgraded["config"], "from the config", "{upgraded:?}");
    assert_eq!(upgraded["key"], "denied", "{upgraded:?}");

    // Dropped while both run: the install stops them before it re-owns, and starts the Client
    // again once it has succeeded, with no `service start`. The Client then
    // starts its program itself again, under its own account.
    let again_pid: u32 = upgraded["pid"].parse().expect("a pid");
    let dropping = client(
        &[
            "service",
            "install",
            "--root",
            &root_arg,
            "--no-process-account",
        ],
        &config,
    )
    .expect("drop the process account");
    assert!(
        dropping.contains(&format!("{agents} was stopped and removed")),
        "{dropping}"
    );
    let dropped = reported(&result, Some(again_pid));
    assert_eq!(dropped["user"], client_account.0, "{dropped:?}");

    client(&["service", "stop"], &config).expect("stop the service");
    client(&["service", "uninstall"], &config).expect("uninstall the service");
}

/// Kills the process it names, however the test ends.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Killed(u32);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-9", &self.0.to_string()])
            .status();
    }
}

/// Everything the Client has written to its log files under `state`.
fn client_log(state: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(state.join("logs")) else {
        return String::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .collect()
}

/// What decides a failed look at the process `pid` of the service `service`: its status (`Uid`,
/// `TracerPid`), its command line, and the service's journal.
#[cfg(target_os = "linux")]
fn diagnosis(pid: u32, service: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let status: Vec<&str> = status
        .lines()
        .filter(|line| line.starts_with("Uid:") || line.starts_with("TracerPid:"))
        .collect();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|line| String::from_utf8_lossy(&line).replace('\0', " "))
        .unwrap_or_default();
    let journal = Command::new("journalctl")
        .args([
            "-u",
            &format!("{service}.service"),
            "-n",
            "50",
            "--no-pager",
        ])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    format!(
        "\n--- /proc/{pid}/status ---\n{}\n--- /proc/{pid}/cmdline ---\n{cmdline}\n--- journalctl -u {service}.service ---\n{journal}",
        status.join("\n")
    )
}

/// Restarts the service named `name` through the service manager.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn restart(name: &str) {
    #[cfg(target_os = "linux")]
    let restarted = Command::new("systemctl")
        .args(["restart", &format!("{name}.service")])
        .status()
        .expect("run systemctl restart");
    #[cfg(target_os = "macos")]
    let restarted = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("system/{name}")])
        .status()
        .expect("run launchctl kickstart");
    assert!(restarted.success(), "cannot restart {name}");
}

/// A Managed Process takes the second service's place: it leaves its process
/// group, so it outlives the Client's connection, removes the second service's socket and listens
/// at its name. The Client, restarted, finds a peer of the process account there and refuses it —
/// it writes it nothing and logs the impostor's process id — and starts no Managed Process until
/// the second service is restarted and serves the socket again. On Linux the second service is not
/// dumpable, and the program it starts is.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "installs a real system service; run with --ignored in the service-smoke job"]
fn a_managed_process_in_the_second_services_place_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::NotInstalled,
        "a leftover {} service from an earlier run — remove it before running this",
        service_name()
    );
    let client_account = TemporaryAccount::create(SMOKE_ACCOUNTS.0);
    let process_account = TemporaryAccount::create(SMOKE_ACCOUNTS.1);
    add_to_group(client_account.0, process_account.0);

    let dir = shared_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the temporary directory");
    let root = dir.path().join("install");
    let state = root.join("state");
    let program = state.join("supervisors").join("probe").join("program");
    std::fs::create_dir_all(&program).expect("program/");
    // Where the Managed Process and the impostor say what they did: writable by anyone.
    let out = dir.path().join("out");
    std::fs::create_dir(&out).expect("out/");
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777)).expect("chmod out/");
    let result = out.join("result");
    let heard = out.join("impostor.log");

    // The impostor: in a session of its own, so the end of the Client's connection, which ends
    // the program's process group, does not end it; it listens at the socket's name and notes how
    // much each peer wrote before closing the connection.
    let socket = classis_agent::service::manager::agents_socket();
    let impostor = program.join("impostor.pl");
    std::fs::write(
        &impostor,
        format!(
            "use strict;\n\
             use POSIX ();\n\
             use IO::Socket::UNIX;\n\
             use Socket qw(SOCK_STREAM);\n\
             POSIX::setsid() or die \"setsid: $!\";\n\
             $| = 1;\n\
             unlink '{socket}';\n\
             my $listener = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => '{socket}', Listen => 8) or die \"listen: $!\";\n\
             chmod 0660, '{socket}' or die \"chmod: $!\";\n\
             print \"listening pid=$$\\n\";\n\
             while (my $peer = $listener->accept) {{\n\
             my ($heard, $buffer) = (0, '');\n\
             while (my $n = sysread($peer, $buffer, 65536)) {{ $heard += $n; }}\n\
             print \"heard=$heard\\n\";\n\
             close $peer;\n\
             }}\n",
            socket = socket.display(),
        ),
    )
    .expect("write the impostor");
    let script = program.join("probe.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             echo \"pid=$$\" > {out}/result.tmp\n\
             mv {out}/result.tmp {out}/result\n\
             if [ ! -e {out}/impostor.started ]; then\n\
             : > {out}/impostor.started\n\
             /usr/bin/perl {impostor} </dev/null >>{heard} 2>&1 &\n\
             fi\n\
             exec sleep 3600\n",
            out = out.display(),
            impostor = impostor.display(),
            heard = heard.display(),
        ),
    )
    .expect("write the program");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the program");

    let (addr, state_view, server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n\
             [[supervisor]]\ntype = \"command\"\nname = \"probe\"\ncommand = \"probe.sh\"\n",
        ),
    )
    .expect("write supervisor.toml");

    let root_arg = root.to_string_lossy().into_owned();
    client(
        &[
            "service",
            "install",
            "--root",
            &root_arg,
            "--run-as",
            client_account.0,
            "--process-account",
            process_account.0,
        ],
        &config,
    )
    .expect("install the service with a process account");
    let _registered = Registered;
    enrol_installed(addr, &server, &config);
    wait_for(
        "the Agent to appear in the fleet",
        Duration::from_secs(60),
        || agent(&state_view).filter(|a| a.connected).map(|_| ()),
    );

    let first = reported(&result, None);
    let first_pid: u32 = first["pid"].parse().expect("a pid");
    assert_eq!(user_of(&first["pid"]), process_account.0, "{first:?}");
    let agents = classis_agent::service::manager::agents_service_name();
    #[cfg(target_os = "linux")]
    {
        let main = parse_after(
            &String::from_utf8_lossy(
                &Command::new("systemctl")
                    .args(["show", "-p", "MainPID", &format!("{agents}.service")])
                    .output()
                    .expect("run systemctl show")
                    .stdout,
            ),
            "MainPID",
        )
        .expect("the second service runs");
        let (process_uid, _) = ids_of(process_account.0);
        // The files under /proc/<pid>/ of a process that is not dumpable belong to root; the
        // directory itself keeps the process's uid whatever it is (task_dump_owner).
        assert_eq!(
            owner_and_mode(Path::new(&format!("/proc/{main}/environ"))).0,
            0,
            "the second service is dumpable{}",
            diagnosis(main, &agents)
        );
        assert_eq!(
            owner_and_mode(Path::new(&format!("/proc/{first_pid}/environ"))).0,
            process_uid,
            "the program the second service started is not dumpable{}",
            diagnosis(first_pid, &agents)
        );
    }

    let impostor_pid: u32 = wait_for(
        "the impostor to listen at the socket",
        Duration::from_secs(30),
        || {
            std::fs::read_to_string(&heard)
                .ok()?
                .lines()
                .find_map(|line| line.strip_prefix("listening pid="))
                .and_then(|pid| pid.trim().parse().ok())
        },
    );
    let _impostor = Killed(impostor_pid);
    assert_eq!(
        user_of(&impostor_pid.to_string()),
        process_account.0,
        "the impostor runs under the process account"
    );

    // The Client restarts: its connection ends, and the program with it; the impostor stays.
    restart(service_name());
    wait_for(
        "the restarted Client to refuse the impostor",
        Duration::from_secs(60),
        || {
            let log = client_log(&state);
            log.lines()
                .any(|line| {
                    line.contains("ERROR")
                        && line.contains("not the second service")
                        && line.contains(&format!("peer_pid={impostor_pid}"))
                        && line.contains(&socket.display().to_string())
                })
                .then_some(())
        },
    );
    std::thread::sleep(Duration::from_secs(u64::from(RESTART_DELAY_SECS) * 3));
    let impostor_heard = std::fs::read_to_string(&heard).expect("what the impostor heard");
    let connections: Vec<&str> = impostor_heard
        .lines()
        .filter_map(|line| line.strip_prefix("heard="))
        .collect();
    assert!(
        !connections.is_empty(),
        "the Client never reached the impostor: {impostor_heard}"
    );
    assert!(
        connections.iter().all(|heard| *heard == "0"),
        "the Client wrote to the impostor: {impostor_heard}"
    );
    let still = reported(&result, None);
    assert_eq!(
        still["pid"], first["pid"],
        "a Managed Process started while the impostor served the socket"
    );

    // The second service restarts and serves its socket again: the Client reaches it, and the
    // program runs again.
    restart(&agents);
    let again = reported(&result, Some(first_pid));
    assert_eq!(user_of(&again["pid"]), process_account.0, "{again:?}");

    client(&["service", "stop"], &config).expect("stop the service");
    client(&["service", "uninstall"], &config).expect("uninstall the service");
}

/// `service <verb>` on Windows, and on a failure what the SCM holds of both services, what the
/// layout grants and what the SCM last logged, so that a failed start or stop says why.
#[cfg(windows)]
fn service_on_windows(verb: &str, config: &Path, root: &Path) {
    if let Err(e) = client(&["service", verb], config) {
        let mut said = String::new();
        let mut run = |program: &str, args: &[&std::ffi::OsStr]| {
            let out = Command::new(program).args(args).output();
            said.push_str(&format!("\n--- {program} {args:?} ---\n"));
            match out {
                Ok(out) => {
                    said.push_str(&String::from_utf8_lossy(&out.stdout));
                    said.push_str(&String::from_utf8_lossy(&out.stderr));
                }
                Err(e) => said.push_str(&e.to_string()),
            }
        };
        for name in [
            service_name().to_string(),
            classis_agent::service::manager::agents_service_name(),
        ] {
            for verb in ["qc", "qprivs", "sdshow", "queryex"] {
                run(
                    "sc",
                    &[std::ffi::OsStr::new(verb), std::ffi::OsStr::new(&name)],
                );
            }
        }
        for path in [
            root.to_path_buf(),
            root.join("versions"),
            root.join("current"),
        ] {
            run("icacls", &[path.as_os_str()]);
        }
        run(
            "wevtutil",
            &[
                std::ffi::OsStr::new("qe"),
                std::ffi::OsStr::new("System"),
                std::ffi::OsStr::new("/c:10"),
                std::ffi::OsStr::new("/rd:true"),
                std::ffi::OsStr::new("/f:text"),
                std::ffi::OsStr::new("/q:*[System[Provider[@Name='Service Control Manager']]]"),
            ],
        );
        panic!("{verb} the service: {e}{said}");
    }
}

/// What the Managed Process below found out about itself on Windows, once it has written it.
#[cfg(windows)]
fn reported_on_windows(result: &Path) -> std::collections::BTreeMap<String, String> {
    wait_for(
        "the Managed Process to report",
        Duration::from_secs(90),
        || {
            let text = std::fs::read_to_string(result).ok()?;
            let report: std::collections::BTreeMap<String, String> = text
                .lines()
                .filter_map(|line| line.trim().split_once('='))
                .map(|(key, value)| (key.to_string(), value.trim().to_string()))
                .collect();
            report.contains_key("done").then_some(report)
        },
    )
}

/// Grants `who` modify on `path` and everything in it, by `icacls.exe`.
#[cfg(windows)]
fn grant_modify(path: &Path, who: &str) {
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(["/grant", &format!("{who}:(OI)(CI)M")])
        .status()
        .expect("run icacls");
    assert!(status.success(), "cannot grant {who} {}", path.display());
}

/// A Managed Process under a process account on Windows: installed with `--run-as`
/// naming the Client's own virtual account and `--process-account` the second service's, the
/// Client starts its program through the second service, on its named pipe, and the program runs
/// as `NT SERVICE\<PRODUCT_NAME>-agents` without `SeImpersonatePrivilege`. It reads its `config/`
/// and writes into its data directory, and can neither read a secret of the Client's or its
/// log nor write its own `program/`. After the second service's process is killed the SCM
/// restarts it, the Client reaches it again and the program runs again. The runner's shell is
/// elevated, as `service install` needs.
///
/// A re-registration without either flag, as an upgrade makes, rewrites both SCM entries in place
/// and keeps both accounts; `--no-process-account` returns the program to the Client's account.
#[cfg(windows)]
#[test]
#[ignore = "installs a real system service; run with --ignored in the service-smoke job"]
fn on_windows_a_managed_process_runs_under_the_process_account_and_reaches_only_what_it_runs() {
    use classis_agent::service::manager::agents_service_name;
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::NotInstalled,
        "a leftover {} service from an earlier run — remove it before running this",
        service_name()
    );
    let client_account = format!(r"NT SERVICE\{}", service_name());
    let process_account = format!(r"NT SERVICE\{}", agents_service_name());

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("install");
    let state = root.join("state");
    let supervisor = state.join("supervisors").join("probe");
    let program = supervisor.join("program");
    let config_dir = supervisor.join("config");
    let data = supervisor.join("data");
    std::fs::create_dir_all(&program).expect("program/");
    std::fs::create_dir_all(&config_dir).expect("config/");
    std::fs::create_dir_all(&data).expect("data/");
    // Where the Managed Process says what it found: writable by everyone, outside every root.
    let out = dir.path().join("out");
    std::fs::create_dir(&out).expect("out/");
    grant_modify(&out, "*S-1-1-0");
    let result = out.join("result");

    // The Client's secret: `state.json`, which `enrol` writes in the state directory below.
    let key = state.join("state.json");
    std::fs::write(config_dir.join("settings"), "from the config\r\n").expect("config entry");
    std::fs::write(
        program.join("probe.cmd"),
        format!(
            "@echo off\r\n\
             (\r\n\
             for /f \"delims=\" %%u in ('whoami') do echo user=%%u\r\n\
             type \"{key}\" >nul 2>&1 && echo key=read || echo key=denied\r\n\
             dir \"{logs}\" >nul 2>&1 && echo logs=read || echo logs=denied\r\n\
             (echo x> \"{program}\\written\") 2>nul && echo program=written || echo program=denied\r\n\
             (echo x>> \"{data}\\written\") 2>nul && echo data=written || echo data=denied\r\n\
             for /f \"usebackq delims=\" %%c in (\"{config}\\settings\") do echo config=%%c\r\n\
             whoami /priv | find /i \"SeImpersonatePrivilege\" >nul && echo impersonate=held || echo impersonate=none\r\n\
             whoami /priv | find /i \"SeChangeNotifyPrivilege\" >nul && echo traverse=held || echo traverse=none\r\n\
             echo done=yes\r\n\
             ) > \"{out}\\result.tmp\"\r\n\
             move /y \"{out}\\result.tmp\" \"{out}\\result\" >nul\r\n\
             ping -n 3600 127.0.0.1 >nul\r\n",
            key = key.display(),
            logs = state.join("logs").display(),
            program = program.display(),
            data = data.display(),
            config = config_dir.display(),
            out = out.display(),
        ),
    )
    .expect("write the program");

    let (addr, state_view, server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n\
             [[supervisor]]\ntype = \"command\"\nname = \"probe\"\ncommand = \"probe.cmd\"\n",
        ),
    )
    .expect("write supervisor.toml");

    let root_arg = root.to_string_lossy().into_owned();
    let installed = client(
        &[
            "service",
            "install",
            "--root",
            &root_arg,
            "--run-as",
            &client_account,
            "--process-account",
            &process_account,
        ],
        &config,
    )
    .expect("install the service with a process account");
    let _registered = Registered;
    assert!(installed.contains(&process_account), "{installed}");
    // A kind's data directory, granted to the process account as the Client grants one a kind
    // names (`storage::create_shared_dir`); the command kind this test runs names none, so the
    // test grants it.
    let process_sid =
        classis_agent::win32::virtual_account_sid(&agents_service_name()).expect("ascii");
    grant_modify(&data, &format!("*{process_sid}"));
    // The second service keeps SeChangeNotifyPrivilege and no other, as the SCM holds it.
    {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .expect("the SCM");
        let registered = manager
            .open_service(agents_service_name(), ServiceAccess::QUERY_CONFIG)
            .expect("the second service");
        // SAFETY: the handle of `registered`, alive across the call.
        let privileges =
            unsafe { classis_agent::win32::required_privileges(registered.raw_handle()) }
                .expect("its required privileges");
        assert_eq!(privileges, ["SeChangeNotifyPrivilege"]);
    }
    enrol_installed(addr, &server, &config);
    assert!(
        key.is_file(),
        "`enrol` wrote the state.json the program is denied"
    );
    wait_for(
        "the Agent to appear in the fleet",
        Duration::from_secs(60),
        || agent(&state_view).filter(|a| a.connected).map(|_| ()),
    );

    let first = reported_on_windows(&result);
    assert!(
        first["user"].eq_ignore_ascii_case(&process_account),
        "{first:?}"
    );
    assert_eq!(first["key"], "denied", "{first:?}");
    assert_eq!(first["logs"], "denied", "{first:?}");
    assert_eq!(first["program"], "denied", "{first:?}");
    assert_eq!(first["config"], "from the config", "{first:?}");
    assert_eq!(first["data"], "written", "{first:?}");
    assert_eq!(first["impersonate"], "none", "{first:?}");
    assert_eq!(first["traverse"], "held", "{first:?}");

    // The second service's process is killed: the SCM restarts it, and the Client starts the
    // program again through it.
    std::fs::remove_file(&result).expect("remove the result");
    let queried = Command::new("sc")
        .args(["queryex", &agents_service_name()])
        .output()
        .expect("run sc queryex");
    let pid = parse_after(&String::from_utf8_lossy(&queried.stdout), "PID")
        .expect("the second service's process id");
    kill(pid);
    let again = reported_on_windows(&result);
    assert!(
        again["user"].eq_ignore_ascii_case(&process_account),
        "{again:?}"
    );

    // Re-registered without either flag, as an upgrade does: the SCM's entries are rewritten in
    // place, and both accounts are kept.
    service_on_windows("stop", &config, &root);
    std::fs::remove_file(&result).expect("remove the result");
    let reinstalled = client(&["service", "install", "--root", &root_arg], &config)
        .expect("re-install without --run-as and --process-account");
    assert!(
        reinstalled.contains(&format!("processes: {process_account} (kept from")),
        "{reinstalled}"
    );
    service_on_windows("start", &config, &root);
    let upgraded = reported_on_windows(&result);
    assert!(
        upgraded["user"].eq_ignore_ascii_case(&process_account),
        "{upgraded:?}"
    );
    assert_eq!(upgraded["data"], "written", "{upgraded:?}");
    assert_eq!(upgraded["key"], "denied", "{upgraded:?}");

    // Re-registered while both run, nothing stopped beforehand, as an MSI upgrade on a running host
    // does: the install stops both and waits for them, and starts both again once it has
    // succeeded — the program reconnects under the process account, and nothing is left recorded.
    // Each service's process by its id and its start time: an id the system hands out again at
    // once is told apart by a later start.
    let pids = || {
        [service_name().to_string(), agents_service_name()].map(|name| {
            let queried = Command::new("sc")
                .args(["queryex", &name])
                .output()
                .expect("run sc queryex");
            let pid = parse_after(&String::from_utf8_lossy(&queried.stdout), "PID")
                .unwrap_or_else(|| panic!("{name} runs with a process"));
            let started = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("(Get-Process -Id {pid}).StartTime.ToUniversalTime().Ticks"),
                ])
                .output()
                .expect("run powershell");
            let started: u64 = String::from_utf8_lossy(&started.stdout)
                .trim()
                .parse()
                .unwrap_or_else(|e| panic!("the start time of {name}'s process {pid}: {e}"));
            (pid, started)
        })
    };
    let running_before = pids();
    std::fs::remove_file(&result).expect("remove the result");
    client(&["service", "install", "--root", &root_arg], &config)
        .expect("re-install while both run");
    for name in [service_name().to_string(), agents_service_name()] {
        wait_for(
            "the service to run again after the re-install",
            Duration::from_secs(60),
            || {
                let queried = Command::new("sc").args(["query", &name]).output().ok()?;
                String::from_utf8_lossy(&queried.stdout)
                    .contains("RUNNING")
                    .then_some(())
            },
        );
    }
    let resumed = reported_on_windows(&result);
    assert!(
        resumed["user"].eq_ignore_ascii_case(&process_account),
        "{resumed:?}"
    );
    let running_after = pids();
    for (before, after) in running_before.iter().zip(&running_after) {
        assert!(
            before.0 != after.0 || after.1 > before.1,
            "stopped and started again, not left running: {before:?}, then {after:?}"
        );
    }
    let recorded = Command::new("reg")
        .args([
            "query",
            &format!(r"HKLM\SOFTWARE\{}\WithdrawalPending", service_name()),
            "/v",
            "Pending",
        ])
        .output()
        .expect("run reg query");
    assert!(
        !recorded.status.success(),
        "a resumed install leaves no record: {}",
        String::from_utf8_lossy(&recorded.stdout)
    );

    // Dropped while both run: the install stops both and waits for them, withdraws what the
    // process account was granted, and starts the Client again, which starts its program itself
    // again, under its own account. The record of the withdrawal is gone with it.
    std::fs::remove_file(&result).expect("remove the result");
    client(
        &[
            "service",
            "install",
            "--root",
            &root_arg,
            "--no-process-account",
        ],
        &config,
    )
    .expect("drop the process account");
    let recorded = Command::new("reg")
        .args([
            "query",
            &format!(r"HKLM\SOFTWARE\{}\WithdrawalPending", service_name()),
            "/v",
            "Pending",
        ])
        .output()
        .expect("run reg query");
    assert!(
        !recorded.status.success(),
        "a completed withdrawal leaves no record: {}",
        String::from_utf8_lossy(&recorded.stdout)
    );
    let dropped = reported_on_windows(&result);
    assert!(
        dropped["user"].eq_ignore_ascii_case(&client_account),
        "{dropped:?}"
    );

    service_on_windows("stop", &config, &root);
    client(&["service", "uninstall"], &config).expect("uninstall the service");
}

/// What the SCM says the service `name` is doing: `RUNNING`, `STOPPED`, … from `sc query`.
#[cfg(windows)]
fn scm_state(name: &str) -> String {
    let out = Command::new("sc")
        .args(["query", name])
        .output()
        .expect("run sc query");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|line| line.trim_start().starts_with("STATE"))
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or_default()
        .to_string()
}

/// Has the SCM start or stop the service `name` alone — `sc start` and `sc stop`, unlike
/// `service start`, which starts the second service too — and waits until it is `state`.
#[cfg(windows)]
fn scm_to(verb: &str, name: &str, state: &str) {
    let _ = Command::new("sc").args([verb, name]).output();
    wait_for(
        &format!("{name} to be {state}"),
        Duration::from_secs(60),
        || (scm_state(name) == state).then_some(()),
    );
}

/// Runs a PowerShell command and fails on its failure.
#[cfg(windows)]
fn powershell(command: &str) {
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .expect("run powershell");
    assert!(
        out.status.success(),
        "{command}\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A task scheduled under `NT AUTHORITY\LocalService`, removed however the test ends.
#[cfg(windows)]
struct ScheduledTask(&'static str);

#[cfg(windows)]
impl ScheduledTask {
    /// Registers `script` as a task under `NT AUTHORITY\LocalService` and starts it.
    fn start(name: &'static str, script: &Path) -> Self {
        let task = Self(name);
        powershell(&format!(
            "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \
             '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{script}\"'; \
             $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\LOCALSERVICE' \
             -LogonType ServiceAccount; \
             Register-ScheduledTask -TaskName '{name}' -Action $action -Principal $principal \
             -Force | Out-Null; \
             Start-ScheduledTask -TaskName '{name}'",
            script = script.display(),
        ));
        task
    }

    /// Ends the task's running instance.
    fn end(&self) {
        powershell(&format!("Stop-ScheduledTask -TaskName '{}'", self.0));
    }
}

#[cfg(windows)]
impl Drop for ScheduledTask {
    fn drop(&mut self) {
        let _ = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Stop-ScheduledTask -TaskName '{0}'; \
                     Unregister-ScheduledTask -TaskName '{0}' -Confirm:$false",
                    self.0
                ),
            ])
            .output();
    }
}

/// On Windows a pipe of the second service's name, made by a task under the process account, `NT
/// AUTHORITY\LocalService`, while the second service is stopped: the Client,
/// restarted, refuses it as a peer the SCM names no process for, writes it nothing and logs it, and
/// starts no Managed Process; once the task has ended and the second service runs again, the Client
/// reaches it and the program runs. The second service is stopped first because a client that opens
/// a pipe both serve would reach either one; the case of a differing process is decided by the test
/// with a fake service manager. A failure midway leaves the second service stopped until
/// `Registered` uninstalls both services.
#[cfg(windows)]
#[test]
#[ignore = "installs a real system service; run with --ignored in the service-smoke job"]
fn on_windows_a_pipe_the_scm_names_no_process_for_is_refused() {
    use classis_agent::service::manager::{agents_service_name, agents_socket};
    assert_eq!(
        service().state().expect("query the service"),
        ServiceState::NotInstalled,
        "a leftover {} service from an earlier run — remove it before running this",
        service_name()
    );
    let client_account = format!(r"NT SERVICE\{}", service_name());
    let process_account = r"NT AUTHORITY\LocalService";

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("install");
    let state = root.join("state");
    let program = state.join("supervisors").join("probe").join("program");
    std::fs::create_dir_all(&program).expect("program/");
    // Where the Managed Process and the impostor say what they did: writable by everyone.
    let out = dir.path().join("out");
    std::fs::create_dir(&out).expect("out/");
    grant_modify(&out, "*S-1-1-0");
    let starts = out.join("starts");
    let heard = out.join("impostor.log");
    let started = || {
        std::fs::read_to_string(&starts)
            .map(|text| text.lines().filter(|line| line.trim() == "started").count())
            .unwrap_or(0)
    };

    std::fs::write(
        program.join("probe.cmd"),
        format!(
            "@echo off\r\n\
             echo started>> \"{starts}\"\r\n\
             ping -n 3600 127.0.0.1 >nul\r\n",
            starts = starts.display(),
        ),
    )
    .expect("write the program");

    // The impostor: the pipe under the second service's name, granting what the Client opens it
    // for, owned by the account that makes it; it notes how much each client wrote before it
    // closed the connection.
    let pipe = agents_socket();
    let pipe_name = pipe
        .to_string_lossy()
        .trim_start_matches(r"\\.\pipe\")
        .to_string();
    let impostor = out.join("impostor.ps1");
    std::fs::write(
        &impostor,
        r#"$log = '@LOG@'
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$security = New-Object System.IO.Pipes.PipeSecurity
$security.SetOwner($me)
$security.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($me, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
$security.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($everyone, [System.IO.Pipes.PipeAccessRights]::ReadWrite, [System.Security.AccessControl.AccessControlType]::Allow)))
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream('@PIPE@', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 4096, 4096, $security)
Add-Content -Path $log -Value "listening pid=$PID"
$buffer = New-Object byte[] 65536
while ($true) {
    $pipe.WaitForConnection()
    $heard = 0
    try { while (($n = $pipe.Read($buffer, 0, $buffer.Length)) -gt 0) { $heard += $n } } catch {}
    Add-Content -Path $log -Value "heard=$heard"
    try { $pipe.Disconnect() } catch {}
}
"#
        .replace("@LOG@", &heard.display().to_string())
        .replace("@PIPE@", &pipe_name),
    )
    .expect("write the impostor");

    let (addr, state_view, server) = spawn_server();
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"{AGENT_NAME}\"\nheartbeat_interval_secs = 1\n\
             [[supervisor]]\ntype = \"command\"\nname = \"probe\"\ncommand = \"probe.cmd\"\n",
        ),
    )
    .expect("write supervisor.toml");

    let root_arg = root.to_string_lossy().into_owned();
    client(
        &[
            "service",
            "install",
            "--root",
            &root_arg,
            "--run-as",
            &client_account,
            "--process-account",
            process_account,
        ],
        &config,
    )
    .expect("install the service with LocalService as the process account");
    let _registered = Registered;
    enrol_installed(addr, &server, &config);
    wait_for(
        "the Agent to appear in the fleet",
        Duration::from_secs(60),
        || agent(&state_view).filter(|a| a.connected).map(|_| ()),
    );
    wait_for(
        "the Managed Process to start",
        Duration::from_secs(90),
        || (started() == 1).then_some(()),
    );

    // The second service stops, and its program with it; the SCM then names no process for it,
    // and the task makes the pipe in its place.
    let agents = agents_service_name();
    scm_to("stop", &agents, "STOPPED");
    let task = ScheduledTask::start("classis-smoke-impostor", &impostor);
    let impostor_pid: u32 = wait_for(
        "the impostor to make the pipe",
        Duration::from_secs(60),
        || {
            std::fs::read_to_string(&heard)
                .ok()?
                .lines()
                .find_map(|line| line.trim().strip_prefix("listening pid="))
                .and_then(|pid| pid.trim().parse().ok())
        },
    );

    // The Client restarts, alone.
    scm_to("stop", service_name(), "STOPPED");
    scm_to("start", service_name(), "RUNNING");
    let pipe_text = pipe.display().to_string();
    wait_for(
        "the restarted Client to refuse the impostor",
        Duration::from_secs(60),
        || {
            client_log(&state)
                .lines()
                .any(|line| {
                    line.contains("ERROR")
                        && line.contains("runs no process as the second service")
                        && line.contains(&format!("peer_pid={impostor_pid}"))
                        && line.contains(&pipe_text)
                })
                .then_some(())
        },
    );
    std::thread::sleep(Duration::from_secs(u64::from(RESTART_DELAY_SECS) * 3));
    let impostor_heard = std::fs::read_to_string(&heard).expect("what the impostor heard");
    let connections: Vec<&str> = impostor_heard
        .lines()
        .filter_map(|line| line.trim().strip_prefix("heard="))
        .collect();
    assert!(
        !connections.is_empty(),
        "the Client never reached the impostor: {impostor_heard}"
    );
    assert!(
        connections.iter().all(|heard| *heard == "0"),
        "the Client wrote to the impostor: {impostor_heard}"
    );
    assert_eq!(
        started(),
        1,
        "a Managed Process started while the impostor served the pipe"
    );

    // The task ends, and the second service runs again: the Client reaches it.
    task.end();
    wait_for("the impostor to end", Duration::from_secs(60), || {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {impostor_pid}"), "/NH"])
            .output()
            .ok()?;
        (!String::from_utf8_lossy(&out.stdout).contains(&impostor_pid.to_string())).then_some(())
    });
    scm_to("start", &agents, "RUNNING");
    wait_for(
        "the Managed Process to start through the second service again",
        Duration::from_secs(90),
        || (started() == 2).then_some(()),
    );

    service_on_windows("stop", &config, &root);
    client(&["service", "uninstall"], &config).expect("uninstall the service");
}
