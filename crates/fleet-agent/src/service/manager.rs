//! Cross-platform service lifecycle over the `service-manager` crate (ADR-0019).
//!
//! `service-manager` targets the platform's native manager (systemd, launchd, Windows SCM) behind
//! one API. This module wraps it in the project's vocabulary. There is **one service per build**
//! (ADR-0019): it is named after the product, takes no suffix, and nothing has to be looked up to
//! address it. Where a process account is registered, a second service, `<PRODUCT_NAME>-agents`,
//! runs beside it under that account (ADR-0059), and every verb acts on both. The installed
//! program is the layout's `current` pointer, so a self-update is a pointer switch — never a
//! re-registration.

use std::ffi::OsString;
// `Path` is used only by the Unix `default_base` variants; Windows builds with -D warnings.
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceLevel as SmLevel, ServiceManager,
    ServiceManagerKind, ServiceStartCtx, ServiceStatus, ServiceStatusCtx, ServiceUninstallCtx,
};

use super::{ServiceControl, ServiceLevel, ServiceState};
use crate::product::{PRODUCT_NAME, PRODUCT_TITLE};

/// Restart after a failure, never after a clean stop (ADR-0019) — with a delay so a Client that
/// fails at startup does not spin, and no retry limit so a host recovers however long it takes.
const RESTART_POLICY: RestartPolicy = RestartPolicy::OnFailure {
    delay_secs: Some(RESTART_DELAY_SECS),
    max_retries: None,
    reset_after_secs: None,
};

/// Read by [`windows_config`](super::windows_config) so both platforms wait the same before a
/// restart — and by the service smoke test, which has to outwait it before it may conclude that a
/// killed service is not coming back (ADR-0010 widens visibility by need).
pub const RESTART_DELAY_SECS: u32 = 5;

/// The name the service is registered under — the same on every platform (ADR-0019), and the
/// **product's** name rather than the program's (ADR-0019 clause 3).
///
/// There is no suffix and nothing to look up: one build installs one service, and a second
/// installation is a second build with its own `PRODUCT_NAME`. The name that identifies an
/// *installation* is the product's; the program inside it is `supervisor` either way, which is why
/// this is not [`layout::COMPONENT`]. A hyphen and never a dot, for the reason [`label`] gives —
/// the grammar `build.rs` enforces guarantees both.
#[must_use]
pub fn service_name() -> &'static str {
    PRODUCT_NAME
}

/// The name of the second service, which starts the Managed Processes under the process account
/// (ADR-0059 clause 2): the product's, with the suffix `-agents`.
#[must_use]
pub fn agents_service_name() -> String {
    format!("{PRODUCT_NAME}-agents")
}

/// The second service's socket, in a directory named after it that only the process account
/// writes and its group reaches (ADR-0059 clauses 4 and 6). On Windows its named pipe,
/// `\\.\pipe\<PRODUCT_NAME>-agents`, whose own security descriptor admits the Client's account
/// alone.
///
/// Under systemd that is the runtime directory systemd creates for it at every start
/// (`RuntimeDirectory=`) and removes when it stops. launchd has no such directory, and `/var/run`
/// is emptied at boot, so on macOS it is a directory `service install` creates for the process
/// account beside the default data root, under `/Library/Application Support`, where it outlasts
/// a reboot; a socket left there by a service that did not stop cleanly is replaced at its next
/// start.
#[cfg(unix)]
#[must_use]
pub fn agents_socket() -> PathBuf {
    agents_socket_dir().join("agents.sock")
}

#[cfg(windows)]
#[must_use]
pub fn agents_socket() -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\{}", agents_service_name()))
}

/// Refuses a root that is the directory of the second service's socket, or lies in it: that
/// directory is the process account's (ADR-0059 clause 9), and a root there would be handed to
/// it, or to the Client beneath what the process account may replace. Named the same, by
/// another case of its letters on macOS, whose file system ignores it by default, or by another
/// path to the same directory.
///
/// # Errors
/// Returns the refusal, naming the root.
#[cfg(unix)]
pub fn check_roots_apart(roots: &[&Path], socket: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let Some(dir) = socket.parent() else {
        return Ok(());
    };
    let key = |path: &Path| {
        path.components()
            .map(|c| {
                let part = c.as_os_str().to_string_lossy();
                if cfg!(target_os = "macos") {
                    part.to_lowercase()
                } else {
                    part.into_owned()
                }
            })
            .collect::<Vec<_>>()
    };
    let named = key(dir);
    let found = std::fs::metadata(dir).ok().map(|m| (m.dev(), m.ino()));
    for root in roots {
        let within = root.ancestors().any(|above| {
            key(above) == named
                || found.is_some_and(|found| {
                    std::fs::metadata(above).is_ok_and(|m| (m.dev(), m.ino()) == found)
                })
        });
        if within {
            return Err(format!(
                "{} is, or lies in, {}, the directory of the second service's socket, which is the \
                 process account's: name another root. Nothing has been installed or written.",
                root.display(),
                dir.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn agents_socket_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support").join(agents_service_name())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn agents_socket_dir() -> PathBuf {
    PathBuf::from("/run").join(agents_service_name())
}

/// How long systemd waits for the second service to stop before it kills it (`TimeoutStopSec=`):
/// longer than the service's own grace for its programs and the drain of their output after it,
/// so a stop ends them through the service rather than through the manager.
pub const AGENTS_STOP_TIMEOUT_SECS: u32 = 30;

/// How long launchd waits for a job to exit after `SIGTERM` before it kills it, where its plist
/// names no `ExitTimeOut` — as the second service's, which `service-manager` renders, does not:
/// launchd's default, which exceeds the time the second service takes to stop what it started
/// (ADR-0059 clause 9).
#[cfg(any(target_os = "macos", all(test, unix)))]
const LAUNCHD_EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// How often the removal of the second service asks launchd whether it still holds the job.
#[cfg(any(target_os = "macos", test))]
const LAUNCHD_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// The name a human reads where the platform has somewhere to put one (ADR-0019): the Windows
/// services list. systemd shows the unit name as its `Description`, and a launchd job *is* its
/// label — neither has a second name to give.
#[must_use]
pub fn display_name() -> &'static str {
    PRODUCT_TITLE
}

/// What the Windows services list shows in its **Description** column — a field of its own, beside
/// the display name rather than derived from it, and left empty by everything that registers the
/// service unless it is set explicitly.
///
/// This column answers "what is this?", so it says what the program does rather than repeating the
/// display name beside it. Windows is the only platform with somewhere to put it — systemd shows
/// the unit name as its `Description` and a launchd job has no such field at all (ADR-0019).
pub const WINDOWS_DESCRIPTION: &str =
    "Places this machine under OpAMP management: connects to a Server, supervises the Agents \
     configured for this host, and updates them and itself from packages the Server offers.";

/// The second service's name in the Windows services list (ADR-0059 clause 2).
#[must_use]
pub fn agents_display_name() -> String {
    format!("{PRODUCT_TITLE} Managed Processes")
}

/// What the Windows services list says the second service does (ADR-0059 clause 2).
pub const AGENTS_WINDOWS_DESCRIPTION: &str =
    "Starts, stops and watches the Agents' programs under their own account, on the request of \
     the OpAMP Fleet Client, which reaches it on a named pipe of its own.";

/// The service label, built so that **every backend renders it identically** (ADR-0019).
///
/// `service-manager` renders a label through two functions that do not agree — `{organization}-`
/// `{application}` for systemd, `{qualifier}.{organization}.{application}` for launchd and the
/// SCM — so any label with more than one part has two spellings in the field. With no qualifier
/// and no organization both reduce to the application alone, which is why this is built by hand
/// rather than parsed from a dotted string, and why the name must stay free of dots.
fn label() -> ServiceLabel {
    ServiceLabel {
        qualifier: None,
        organization: None,
        application: service_name().to_string(),
    }
}

/// The second service's label, built as [`label`] is.
fn agents_label() -> ServiceLabel {
    ServiceLabel {
        qualifier: None,
        organization: None,
        application: agents_service_name(),
    }
}

/// Build the native service manager, selecting user-level when requested.
fn manager(level: ServiceLevel) -> Result<Box<dyn ServiceManager>, String> {
    let mut manager = <dyn ServiceManager>::native()
        .map_err(|e| format!("cannot detect the native service manager: {e}"))?;
    if level == ServiceLevel::User {
        manager
            .set_level(SmLevel::User)
            .map_err(|e| format!("user-level services are not supported here: {e}"))?;
    }
    Ok(manager)
}

/// Everything a `service install` registers.
#[derive(Debug)]
pub struct InstallSpec {
    /// System or user scope.
    pub level: ServiceLevel,
    /// The program to run: the layout's `current` pointer, never a version directory directly.
    pub program: PathBuf,
    /// Absolute path of the TOML configuration file (ADR-0010) the unit carries. The unit holds
    /// the *path*, never the configuration itself — one source of truth.
    pub config_path: PathBuf,
    /// Absolute state directory baked into the unit (a service's working directory is `/` or
    /// `System32`; relative paths would be meaningless).
    pub state_dir: PathBuf,
    /// The account the service runs as (ADR-0042 clause 2) — already resolved by
    /// [`run_as`](super::run_as), so what arrives here exists and needs no password. On Linux and
    /// macOS a system registration always names one, `root` included; on Windows `None` leaves the
    /// logon account the SCM holds, `LocalSystem` on a first registration.
    pub run_as: Option<String>,
    /// The second service, where a process account is registered (ADR-0059); already decided and
    /// checked by [`run_as`](super::run_as).
    pub agents: Option<Agents>,
}

/// The second service a registration names (ADR-0059 clause 2).
#[derive(Debug, Clone)]
pub struct Agents {
    /// The process account it runs under.
    pub account: String,
    /// That account's uid, which the Client accepts as the socket's peer.
    #[cfg(unix)]
    pub uid: u32,
    /// That account's primary group, through which the Client's account reaches the socket.
    #[cfg(unix)]
    pub gid: u32,
    /// The uid of the Client's account, the one peer the second service serves.
    #[cfg(unix)]
    pub client_uid: u32,
    /// That account's SID, which the Client accepts as the owner of the pipe.
    #[cfg(windows)]
    pub sid: crate::win32::Sid,
    /// The SID of the Client's account, the one client the second service serves.
    #[cfg(windows)]
    pub client_sid: crate::win32::Sid,
    /// Where it listens: [`agents_socket`].
    pub socket: PathBuf,
}

/// The installed command line: `run --service --config … --state-dir …`. The hidden `--service`
/// marker is what routes into the Windows SCM dispatcher; it is ignored on Unix.
///
/// Both paths are absolute and both are baked in, which is what makes an upgrade a re-registration
/// rather than a migration (ADR-0053 clause 2): the program path and the rest of the unit are
/// rewritten from the version that registers, and the configuration, identity and state stay
/// where they are.
///
/// Where a process account is registered, the line also names the second service's socket and the
/// process account's uid: that is how the running Client learns that it starts every Managed
/// Process through the second service, and whom to accept as its peer (ADR-0059 clauses 3, 4).
fn service_args(spec: &InstallSpec) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("run"),
        OsString::from("--service"),
        OsString::from("--config"),
        spec.config_path.clone().into_os_string(),
        OsString::from("--state-dir"),
        spec.state_dir.clone().into_os_string(),
    ];
    if let Some(agents) = &spec.agents {
        #[cfg(unix)]
        let process = ("--process-uid", agents.uid.to_string());
        #[cfg(windows)]
        let process = ("--process-sid", agents.sid.to_string());
        args.extend([
            OsString::from("--agents-socket"),
            agents.socket.clone().into_os_string(),
            OsString::from(process.0),
            OsString::from(process.1),
        ]);
    }
    args
}

/// The second service's command line: `run --agents <socket> --client-uid <uid>` (ADR-0059
/// clause 2), on Windows `run --agents <pipe> --client-sid <SID>`. It reads neither the
/// configuration nor the state directory.
fn agents_args(agents: &Agents) -> Vec<OsString> {
    #[cfg(unix)]
    let client = ("--client-uid", agents.client_uid.to_string());
    #[cfg(windows)]
    let client = ("--client-sid", agents.client_sid.to_string());
    vec![
        OsString::from("run"),
        OsString::from("--agents"),
        agents.socket.clone().into_os_string(),
        OsString::from(client.0),
        OsString::from(client.1),
    ]
}

/// Register the service running `spec.program`, **including** the failure recovery
/// that makes ADR-0019's restart-on-failure real on every platform. On Windows that is a second
/// step against the SCM, because `service-manager` silently drops the policy there; on systemd and
/// launchd the manager has already written it.
///
/// # Errors
/// Returns an error if the manager rejects the install (commonly: not running as
/// root/Administrator for a system-level service), or if the recovery actions cannot be set.
pub fn install(spec: &InstallSpec) -> Result<(), String> {
    // The second service first: the Client's unit names it as what it wants and starts after.
    if let Some(agents) = &spec.agents {
        install_agents(spec, agents)?;
    }
    install_service(spec)?;
    // What `service-manager` does not do on Windows, done here (see `windows_config`) — since
    // ADR-0019 that includes the logon account, which its `sc.exe` backend ignores.
    super::windows_config::configure(
        service_name(),
        display_name(),
        WINDOWS_DESCRIPTION,
        spec.run_as.as_deref(),
    )
}

fn install_service(spec: &InstallSpec) -> Result<(), String> {
    let contents = unit_contents(
        spec,
        cfg!(target_os = "linux")
            && matches!(
                ServiceManagerKind::native(),
                Ok(ServiceManagerKind::Systemd)
            ),
    )?;
    register(
        spec.level,
        ServiceInstallCtx {
            label: label(),
            program: spec.program.clone(),
            args: service_args(spec),
            // The systemd system unit is the Client's own text (ADR-0042 clause 6); the user
            // scope and every other manager keep the crate's rendering.
            contents,
            // launchd `UserName` (ADR-0042 clause 2); the systemd system unit carries `User=`
            // itself. The Windows backend ignores this field, which is why `install` sets the
            // logon account through `windows_config`.
            username: spec.run_as.clone(),
            working_directory: None,
            // The Client is file-configured (ADR-0010): the unit carries the config path in the
            // arguments above, never settings as environment variables.
            environment: None,
            autostart: true,
            // Restart only on a crash, never after an explicit stop — what lets a future updater
            // stop the service, switch `current`, and start it without the manager racing it.
            //
            // Honoured natively on systemd (`Restart=on-failure`) and launchd
            // (`KeepAlive{SuccessfulExit:false}`). The Windows backend of `service-manager`
            // *discards* this and only logs a warning, which is why `windows_config` exists.
            restart_policy: RESTART_POLICY,
        },
    )
    .map_err(|e| format!("cannot install the service (system scope needs root/Administrator): {e}"))
}

/// Registers `ctx` with the service manager. On Windows a service the SCM holds already is
/// reconfigured in place, as `sc create` refuses one that exists: its program, arguments and start
/// type are rewritten and its logon account kept, and what `windows_config` sets follows as on a
/// first registration. A re-registration — an upgrade among them — so keeps the second service
/// and the process account it runs under (ADR-0059 clause 1).
fn register(level: ServiceLevel, ctx: ServiceInstallCtx) -> Result<(), String> {
    let manager = manager(level)?;
    #[cfg(windows)]
    if manager
        .status(ServiceStatusCtx {
            label: ctx.label.clone(),
        })
        .map_err(|e| e.to_string())?
        != ServiceStatus::NotInstalled
    {
        return super::windows_config::reregister(
            &ctx.label.to_qualified_name(),
            &ctx.program,
            &ctx.args,
        );
    }
    manager.install(ctx).map_err(|e| e.to_string())
}

/// Registers the second service (ADR-0059 clause 2), which only a host where [`agents_supported`]
/// holds gets, and on macOS then the directory of its socket. The registration first, so an
/// install that may not register a system service is told so before anything else. On Windows
/// what `service-manager` leaves undone follows, as for the Client: the recovery actions, the
/// display name, the description and the logon account — and the required privileges, cut to
/// `SeChangeNotifyPrivilege` ([`windows_config::configure_agents`](super::windows_config)).
///
/// The Client's service is not made to depend on it (`sc config depend=`): the SCM starts no
/// service whose dependency failed to start, and stops none a running one depends on, so a second
/// service that does not come up would hold the Client down with it (StartService,
/// `ERROR_SERVICE_DEPENDENCY_FAIL`), where the Client runs without it (ADR-0059 clause 2). The
/// start names the second service first instead ([`started`]).
fn install_agents(spec: &InstallSpec, agents: &Agents) -> Result<(), String> {
    register(
        spec.level,
        agents_install_ctx(spec, agents, cfg!(target_os = "linux"))?,
    )
    .map_err(|e| {
        format!("cannot install the second service (system scope needs root or Administrator): {e}")
    })?;
    super::windows_config::configure_agents(
        &agents_service_name(),
        &agents_display_name(),
        AGENTS_WINDOWS_DESCRIPTION,
        &agents.account,
    )?;
    // The plist is registered `Disabled`: launchd starts nothing until `service start`, by when
    // the directory is in place.
    #[cfg(target_os = "macos")]
    socket_dir(
        agents
            .socket
            .parent()
            .ok_or_else(|| format!("{} names no directory", agents.socket.display()))?,
        agents.uid,
        agents.gid,
    )?;
    Ok(())
}

/// What `service-manager` is asked to register for the second service. Under systemd
/// (`own_unit`) a system unit of the Client's own text (ADR-0059 clause 9); under launchd the plist
/// the crate renders, as it renders the Client's: `UserName` naming the process account,
/// `KeepAlive` with `SuccessfulExit` false for the restart policy of ADR-0019 clause 11,
/// `RunAtLoad`, and `Disabled`, which keeps the install from starting it until `service start`.
/// It names no `ExitTimeOut`: launchd's default outlasts the service's own stop of its programs.
fn agents_install_ctx(
    spec: &InstallSpec,
    agents: &Agents,
    own_unit: bool,
) -> Result<ServiceInstallCtx, String> {
    Ok(ServiceInstallCtx {
        label: agents_label(),
        program: spec.program.clone(),
        args: agents_args(agents),
        contents: if own_unit {
            Some(agents_unit(spec, agents)?)
        } else {
            None
        },
        username: Some(agents.account.clone()),
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: RESTART_POLICY,
    })
}

/// Whether this host can register the second service (ADR-0059): a system service under systemd
/// on Linux, under launchd on macOS, where a plist's `UserName` applies in the system domain
/// alone (launchd.plist(5)), or under the SCM on Windows.
#[must_use]
pub fn agents_supported(level: ServiceLevel) -> bool {
    let native = ServiceManagerKind::native();
    level == ServiceLevel::System
        && ((cfg!(target_os = "linux") && matches!(native, Ok(ServiceManagerKind::Systemd)))
            || (cfg!(target_os = "macos") && matches!(native, Ok(ServiceManagerKind::Launchd)))
            || (cfg!(windows) && matches!(native, Ok(ServiceManagerKind::Sc))))
}

/// Creates the directory of the second service's socket, or takes the one there, and gives it to
/// the process account and its group, `0750`: only the process account writes it, and the
/// Client's account, a member of that group (ADR-0059 clause 6), reaches the socket. On macOS
/// `service install` does this, as root, for what systemd's `RuntimeDirectory=` does for the unit.
///
/// The directory is made and opened through its held parent, without following a link, and changed
/// through its own handle, so nothing placed at its name is followed. Its mode is set after its
/// owner, whose change may clear it.
///
/// # Errors
/// Returns an error naming the directory when its parent is not held as [`socket_parent`] holds
/// it, or when the directory cannot be created, opened as a directory, or given to the process
/// account.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn socket_dir(dir: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;
    let failed = |e: std::io::Error| format!("cannot prepare {}: {e}", dir.display());
    let (parent, name) = socket_parent(dir).map_err(failed)?;
    // SAFETY: a valid descriptor and a NUL-terminated name.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(failed(e));
        }
    }
    let handle =
        crate::storage::handle::open(parent.as_raw_fd(), &name, crate::storage::handle::DIRECTORY)
            .map_err(failed)?;
    // SAFETY: a valid descriptor, held across both calls.
    if unsafe { libc::fchown(handle.as_raw_fd(), uid, gid) } != 0 {
        return Err(failed(std::io::Error::last_os_error()));
    }
    // SAFETY: as above.
    if unsafe { libc::fchmod(handle.as_raw_fd(), 0o750) } != 0 {
        return Err(failed(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The parent of the socket's directory, held, and the directory's name in it. The parent must be
/// root's or the running account's and writable by neither its group nor others: the rule a link
/// on the way to a root is trusted by (`trusted_link`), so the process account, which owns the
/// directory, can neither move it nor put anything else at its name. The parent alone is held to
/// it: the path to it is the platform's, `/Library/Application Support`, and root's.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn socket_parent(dir: &Path) -> std::io::Result<(std::os::fd::OwnedFd, std::ffi::CString)> {
    use crate::storage::handle;
    use std::os::unix::ffi::OsStrExt as _;
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "names no directory in a parent",
        ));
    };
    let c = |bytes: &[u8]| std::ffi::CString::new(bytes).map_err(std::io::Error::other);
    let held = handle::open(
        libc::AT_FDCWD,
        &c(parent.as_os_str().as_bytes())?,
        handle::DIRECTORY,
    )?;
    let st = handle::fstat(&held)?;
    let own = handle::own();
    if !(st.st_uid == 0 || st.st_uid == own) || handle::mode(&st) & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is writable by another account than root and this one, which could \
                 replace what is in it",
                parent.display()
            ),
        ));
    }
    Ok((held, c(name.as_bytes())?))
}

/// What `service-manager` is handed as the unit's text: the Client's own systemd **system** unit
/// (ADR-0042 clause 6) where systemd is the native manager, and nothing — the crate's own
/// rendering — for the user scope and every other manager.
fn unit_contents(spec: &InstallSpec, systemd: bool) -> Result<Option<String>, String> {
    if !systemd || spec.level != ServiceLevel::System {
        return Ok(None);
    }
    systemd_unit(spec, spec.run_as.as_deref().unwrap_or(ROOT)).map(Some)
}

/// The account that is root, and that decides the unit's directive tier (ADR-0042 clause 7).
const ROOT: &str = "root";

/// What every system unit carries (ADR-0042 clause 7): `/sys/fs/cgroup` becomes read-only. It does
/// not imply `NoNewPrivileges=`, and no supported agent writes the cgroup tree itself.
const EVERY_SYSTEM_UNIT: &[&str] = &["ProtectControlGroups=yes"];

/// What a unit that runs as root carries on top (ADR-0042 clause 7). Root holds `CAP_SYS_ADMIN`,
/// so none of these implies `no_new_privs` there; under any other account each one would, and
/// `sudo` and every setuid helper a Managed Process uses would stop working.
const ROOT_UNIT: &[&str] = &[
    "ProtectKernelTunables=yes",
    "LockPersonality=yes",
    "RestrictRealtime=yes",
];

/// The systemd system unit the Client registers for `account` (ADR-0042 clauses 6 and 7).
///
/// `ExecStart=` quotes the program and every argument, so any absolute path reaches the program as
/// it was given. `Restart=` and `RestartSec=` say what [`RESTART_POLICY`] says. `User=` always
/// names the account, `root` included, so the unit records what was chosen and a re-registration
/// keeps it. What an operator adds or removes goes into a drop-in under
/// `/etc/systemd/system/<PRODUCT_NAME>.service.d/`, which nothing here touches.
///
/// # Errors
/// Returns an error if a path is not UTF-8 (a unit file is text), or if the account name holds a
/// character that would change what the unit says.
pub fn systemd_unit(spec: &InstallSpec, account: &str) -> Result<String, String> {
    use std::fmt::Write as _;
    check_unit_account(account)?;
    let exec = exec_line(&spec.program, service_args(spec))?;
    let mut unit = String::new();
    let _ = writeln!(unit, "[Unit]");
    let _ = writeln!(unit, "Description={}", service_name());
    // The second service is started first (ADR-0059 clause 2): `After=` orders both, and `Wants=`
    // pulls it in at boot and on every start of the Client. Not `Requires=`: a second service that
    // fails, or is stopped on its own, leaves the Client running — it still reports to the Server,
    // its Supervisors report that their programs do not start, and it reaches the service again
    // once the manager has restarted it.
    if spec.agents.is_some() {
        let agents = agents_service_name();
        let _ = writeln!(unit, "Wants={agents}.service");
        let _ = writeln!(unit, "After={agents}.service");
    }
    let _ = writeln!(unit);
    let _ = writeln!(unit, "[Service]");
    let _ = writeln!(unit, "ExecStart={exec}");
    let _ = writeln!(unit, "Restart=on-failure");
    let _ = writeln!(unit, "RestartSec={RESTART_DELAY_SECS}");
    let _ = writeln!(unit, "User={account}");
    let tier: &[&str] = if account == ROOT { ROOT_UNIT } else { &[] };
    for directive in EVERY_SYSTEM_UNIT.iter().chain(tier) {
        let _ = writeln!(unit, "{directive}");
    }
    let _ = writeln!(unit);
    let _ = writeln!(unit, "[Install]");
    let _ = writeln!(unit, "WantedBy=multi-user.target");
    Ok(unit)
}

/// The second service's systemd system unit (ADR-0059 clause 2): the same program as the Client's,
/// under the process account, with the directives ADR-0042 clause 7 sets for that account.
///
/// `RuntimeDirectory=` is where its socket lives: systemd creates it for the process account at
/// every start, `0750`, so only that account and its group — the Client's account is in it
/// (ADR-0059 clause 6) — reach the socket, and removes it at the stop. `TimeoutStopSec=` outlasts
/// the service's own stop of its programs.
///
/// # Errors
/// Returns an error if a path is not UTF-8, or if the account name holds a character that would
/// change what the unit says.
pub fn agents_unit(spec: &InstallSpec, agents: &Agents) -> Result<String, String> {
    use std::fmt::Write as _;
    check_unit_account(&agents.account)?;
    let exec = exec_line(&spec.program, agents_args(agents))?;
    let name = agents_service_name();
    let mut unit = String::new();
    let _ = writeln!(unit, "[Unit]");
    let _ = writeln!(unit, "Description={name}");
    let _ = writeln!(unit);
    let _ = writeln!(unit, "[Service]");
    let _ = writeln!(unit, "ExecStart={exec}");
    let _ = writeln!(unit, "Restart=on-failure");
    let _ = writeln!(unit, "RestartSec={RESTART_DELAY_SECS}");
    let _ = writeln!(unit, "User={}", agents.account);
    let _ = writeln!(unit, "RuntimeDirectory={name}");
    let _ = writeln!(unit, "RuntimeDirectoryMode=0750");
    let _ = writeln!(unit, "TimeoutStopSec={AGENTS_STOP_TIMEOUT_SECS}");
    // Never root (ADR-0059 clause 1), so never the root tier.
    for directive in EVERY_SYSTEM_UNIT {
        let _ = writeln!(unit, "{directive}");
    }
    let _ = writeln!(unit);
    let _ = writeln!(unit, "[Install]");
    let _ = writeln!(unit, "WantedBy=multi-user.target");
    Ok(unit)
}

/// Refuses an account name that would change what a unit says.
///
/// # Errors
/// Returns the refusal, naming the account.
pub fn check_unit_account(account: &str) -> Result<(), String> {
    if account.is_empty()
        || account
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '%' | '\\' | '"'))
    {
        return Err(format!(
            "the account {account:?} cannot be written into a systemd unit or a launchd plist"
        ));
    }
    Ok(())
}

/// `ExecStart=`'s value: the program and every argument, each quoted by [`exec_word`].
fn exec_line(program: &std::path::Path, args: Vec<OsString>) -> Result<String, String> {
    let mut exec = vec![exec_word(program.as_os_str())?];
    for arg in args {
        exec.push(exec_word(&arg)?);
    }
    Ok(exec.join(" "))
}

/// One word of `ExecStart=`, in double quotes: `\` and `"` are escaped, a control character is
/// written as a C escape, `%` as `%%` (no specifier) and `$` as `$$` (no variable).
fn exec_word(word: &std::ffi::OsStr) -> Result<String, String> {
    use std::fmt::Write as _;
    let text = word
        .to_str()
        .ok_or_else(|| format!("{} is not UTF-8, which a unit file must be", word.display()))?;
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '%' => quoted.push_str("%%"),
            '$' => quoted.push_str("$$"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() => {
                let mut bytes = [0; 4];
                for byte in c.encode_utf8(&mut bytes).bytes() {
                    let _ = write!(quoted, "\\x{byte:02x}");
                }
            }
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

/// A system registration of this service as the Client wrote it: the file, and the account it
/// names (ADR-0042 clause 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The systemd unit or the launchd plist.
    pub file: PathBuf,
    /// Its `User=` or `UserName`; `None` where it names none.
    pub account: Option<String>,
}

/// The registration a re-registration finds (ADR-0042 clause 2): the file the Client wrote —
/// `/etc/systemd/system/<PRODUCT_NAME>.service` or `/Library/LaunchDaemons/<PRODUCT_NAME>.plist` —
/// never a drop-in and never the loaded state of the service manager. `None` at user scope, where
/// no account is named; on Windows, where the SCM keeps the logon account itself; and where no
/// file exists.
///
/// # Errors
/// Returns an error if the file exists and cannot be read.
pub fn registration(level: ServiceLevel) -> Result<Option<Registration>, String> {
    if level == ServiceLevel::User {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    return read_registration(
        &service_manager::systemd_global_dir_path().join(format!("{}.service", service_name())),
        unit_account,
    );
    #[cfg(target_os = "macos")]
    return read_registration(
        &Path::new("/Library/LaunchDaemons").join(format!("{}.plist", service_name())),
        plist_account,
    );
    #[cfg(windows)]
    super::windows_config::logon_account(service_name())
}

#[cfg(unix)]
fn read_registration(
    file: &Path,
    account: fn(&str) -> Option<String>,
) -> Result<Option<Registration>, String> {
    match std::fs::read_to_string(file) {
        Ok(text) => Ok(Some(Registration {
            file: file.to_path_buf(),
            account: account(&text),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", file.display())),
    }
}

/// The second service's registration as the Client wrote it (ADR-0059 clause 1):
/// `/etc/systemd/system/<PRODUCT_NAME>-agents.service` and the account its `User=` names, or
/// `/Library/LaunchDaemons/<PRODUCT_NAME>-agents.plist` and its `UserName`, read as
/// [`registration`] reads the Client's. `None` wherever no second service can be registered, and
/// where no file exists.
///
/// # Errors
/// Returns an error if the file exists and cannot be read.
pub fn agents_registration(level: ServiceLevel) -> Result<Option<Registration>, String> {
    if level == ServiceLevel::User {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    return read_registration(&agents_file(), unit_account);
    #[cfg(target_os = "macos")]
    return read_registration(&agents_file(), plist_account);
    #[cfg(windows)]
    super::windows_config::logon_account(&agents_service_name())
}

/// The file the second service's registration is: its unit, or its plist.
#[cfg(target_os = "linux")]
fn agents_file() -> PathBuf {
    service_manager::systemd_global_dir_path().join(format!("{}.service", agents_service_name()))
}

#[cfg(target_os = "macos")]
fn agents_file() -> PathBuf {
    Path::new("/Library/LaunchDaemons").join(format!("{}.plist", agents_service_name()))
}

/// Whether a second service is registered at `level`.
fn agents_registered(level: ServiceLevel) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return level == ServiceLevel::System && agents_file().exists();
    #[cfg(windows)]
    return level == ServiceLevel::System
        && manager(level)
            .and_then(|manager| {
                manager
                    .status(ServiceStatusCtx {
                        label: agents_label(),
                    })
                    .map_err(|e| e.to_string())
            })
            .is_ok_and(|status| status != ServiceStatus::NotInstalled);
}

/// The last `User=` of a unit's `[Service]` section; an empty one resets it, as systemd reads it.
#[cfg(any(target_os = "linux", test))]
fn unit_account(unit: &str) -> Option<String> {
    let mut section = "";
    let mut account = None;
    for line in unit.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
        } else if section == "[Service]" {
            if let Some(value) = line.strip_prefix("User=") {
                let value = value.trim();
                account = (!value.is_empty()).then(|| value.to_string());
            }
        }
    }
    account
}

/// The `UserName` of a plist as `service-manager` writes it: XML, the key followed by its string.
/// No plist parser is linked for this. The job's dictionary holds no other `UserName` key, because
/// the Client sets no environment.
#[cfg(any(target_os = "macos", test))]
fn plist_account(plist: &str) -> Option<String> {
    let (_, after) = plist.split_once("<key>UserName</key>")?;
    let value = after.trim_start().strip_prefix("<string>")?;
    let (value, _) = value.split_once("</string>")?;
    let value = xml_text(value);
    (!value.is_empty()).then_some(value)
}

/// The state directory the system registration of this service carries (ADR-0053 clause 3): the
/// value after `--state-dir` in the command line the Client wrote — `ExecStart=` of the systemd
/// unit, `ProgramArguments` of the launchd plist, the binary path name the SCM holds. Read from
/// what the Client wrote, never a drop-in and never the manager's loaded state, and only an
/// administrator can change any of them. `None` at user scope, where no registration exists, and
/// where it names no absolute `--state-dir`.
///
/// # Errors
/// Returns an error if the registration exists and cannot be read.
pub fn registered_state_dir(level: ServiceLevel) -> Result<Option<PathBuf>, String> {
    if level == ServiceLevel::User {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    return read_state_dir(
        &service_manager::systemd_global_dir_path().join(format!("{}.service", service_name())),
        unit_arguments,
    );
    #[cfg(target_os = "macos")]
    return read_state_dir(
        &Path::new("/Library/LaunchDaemons").join(format!("{}.plist", service_name())),
        plist_arguments,
    );
    #[cfg(windows)]
    scm_command_line().map(|line| line.and_then(|line| state_dir_of(command_line_arguments(&line))))
}

#[cfg(unix)]
fn read_state_dir(
    file: &Path,
    arguments: fn(&str) -> Vec<String>,
) -> Result<Option<PathBuf>, String> {
    match std::fs::read_to_string(file) {
        Ok(text) => Ok(state_dir_of(arguments(&text))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", file.display())),
    }
}

/// The binary path name — the whole command line — the SCM holds for this service, or `None`
/// where no such service is registered.
#[cfg(windows)]
fn scm_command_line() -> Result<Option<String>, String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    /// `ERROR_SERVICE_DOES_NOT_EXIST`.
    const NO_SUCH_SERVICE: i32 = 1060;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("cannot reach the service control manager: {e}"))?;
    let service = match manager.open_service(service_name(), ServiceAccess::QUERY_CONFIG) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NO_SUCH_SERVICE) => {
            return Ok(None)
        }
        Err(e) => return Err(format!("cannot open the service {}: {e}", service_name())),
    };
    let config = service
        .query_config()
        .map_err(|e| format!("cannot read the registration of {}: {e}", service_name()))?;
    Ok(Some(config.executable_path.to_string_lossy().into_owned()))
}

/// The absolute path after the first `--state-dir` among `arguments`.
fn state_dir_of(arguments: Vec<String>) -> Option<PathBuf> {
    let mut arguments = arguments.into_iter();
    arguments.find(|argument| argument == "--state-dir")?;
    let dir = PathBuf::from(arguments.next()?);
    dir.is_absolute().then_some(dir)
}

/// The words of the last `ExecStart=` of a unit's `[Service]` section, as [`systemd_unit`] writes
/// them: each in double quotes with [`exec_word`]'s escapes. An unquoted word ends at whitespace,
/// as `service-manager`'s own rendering writes it.
#[cfg(any(target_os = "linux", test))]
fn unit_arguments(unit: &str) -> Vec<String> {
    let mut section = "";
    let mut line = None;
    for text in unit.lines().map(str::trim) {
        if text.starts_with('[') {
            section = text;
        } else if section == "[Service]" {
            if let Some(value) = text.strip_prefix("ExecStart=") {
                line = Some(value);
            }
        }
    }
    let Some(line) = line else {
        return Vec::new();
    };
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(first) = chars.next() else {
            return words;
        };
        // Bytes, because a `\x` escape writes one byte of a character's UTF-8 encoding.
        let mut word = Vec::new();
        let push = |word: &mut Vec<u8>, c: char| {
            word.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        };
        let quoted = first == '"';
        if !quoted {
            push(&mut word, first);
        }
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted => break,
                c if !quoted && c.is_whitespace() => break,
                '\\' => match chars.next() {
                    Some('n') => word.push(b'\n'),
                    Some('t') => word.push(b'\t'),
                    Some('x') => {
                        let hex: String = chars.by_ref().take(2).collect();
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            word.push(byte);
                        }
                    }
                    Some(other) => push(&mut word, other),
                    None => {}
                },
                '%' | '$' if chars.peek() == Some(&c) => {
                    chars.next();
                    push(&mut word, c);
                }
                c => push(&mut word, c),
            }
        }
        words.push(String::from_utf8_lossy(&word).into_owned());
    }
}

/// The strings of the `ProgramArguments` array of a plist as `service-manager` writes it: XML,
/// the key followed by its array. No plist parser is linked for this.
#[cfg(any(target_os = "macos", test))]
fn plist_arguments(plist: &str) -> Vec<String> {
    let Some((_, after)) = plist.split_once("<key>ProgramArguments</key>") else {
        return Vec::new();
    };
    let Some(array) = after.trim_start().strip_prefix("<array>") else {
        return Vec::new();
    };
    let array = array
        .split_once("</array>")
        .map_or(array, |(inside, _)| inside);
    array
        .split("<string>")
        .skip(1)
        .filter_map(|item| item.split_once("</string>"))
        .map(|(value, _)| xml_text(value))
        .collect()
}

/// The text of an XML string element, its five predefined entities resolved.
#[cfg(any(target_os = "macos", test))]
fn xml_text(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The arguments of a Windows command line as the C runtime splits it (`CommandLineToArgvW`):
/// whitespace separates outside double quotes, `2n` backslashes before a quote are `n` and the
/// quote toggles quoting, `2n+1` are `n` and a literal quote, and backslashes before anything else
/// stand as they are. `service-manager` quotes the binary path name by exactly these rules.
#[cfg(any(windows, test))]
fn command_line_arguments(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut slashes = 1;
                while chars.next_if_eq(&'\\').is_some() {
                    slashes += 1;
                }
                in_word = true;
                if chars.peek() == Some(&'"') {
                    word.extend(std::iter::repeat_n('\\', slashes / 2));
                    if slashes % 2 == 1 {
                        chars.next();
                        word.push('"');
                    }
                } else {
                    word.extend(std::iter::repeat_n('\\', slashes));
                }
            }
            '"' => {
                in_word = true;
                quoted = !quoted;
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// Deregister the service. The install layout and state are never deleted.
///
/// The second service last, as it is stopped last (ADR-0059 clause 2), and stopped first: a
/// deregistration leaves a running service running, and one that outlived its unit would go on
/// running the Managed Processes with nothing left to stop it by.
///
/// Each is tried whatever became of the other: a Client whose deregistration failed leaves no
/// second service registered behind it.
///
/// # Errors
/// Returns every error: the manager cannot uninstall the service, or stop or uninstall the second
/// service.
pub fn uninstall(level: ServiceLevel) -> Result<(), String> {
    let manager = manager(level);
    uninstall_with(manager.as_deref(), &mut || remove_agents(level).map(|_| ()))
}

/// Deregisters the Client through `manager`, then the second service through `remove_agents`,
/// the second whatever became of the first.
///
/// # Errors
/// Returns every error, the Client's first.
fn uninstall_with(
    manager: Result<&dyn ServiceManager, &String>,
    remove_agents: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), String> {
    let client = manager.map_err(Clone::clone).and_then(|manager| {
        manager
            .uninstall(ServiceUninstallCtx { label: label() })
            .map_err(|e| format!("cannot uninstall the service: {e}"))
    });
    let agents = remove_agents();
    match (client, agents) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(client), Err(agents)) => Err(format!("{client}; {agents}")),
    }
}

/// Stops and deregisters the second service, where one is registered (ADR-0059 clause 1,
/// `--no-process-account`), and on macOS removes the directory of its socket once launchd holds
/// it no more, warning where that directory stays. Returns whether there was one.
///
/// # Errors
/// Returns an error if the manager cannot stop or uninstall it, or, on macOS, if launchd still
/// holds it afterwards.
pub fn remove_agents(level: ServiceLevel) -> Result<bool, String> {
    if !agents_registered(level) {
        return Ok(false);
    }
    let manager = manager(level)?;
    #[cfg(target_os = "macos")]
    {
        let name = agents_service_name();
        // As long as launchd gives the job to exit, and a little more for launchd itself.
        remove_launchd_job(
            &*manager,
            agents_label(),
            &mut || launchd_loaded(&name),
            LAUNCHD_EXIT_TIMEOUT + std::time::Duration::from_secs(5),
        )?;
        // What systemd removes with the runtime directory, removed here once the job is gone.
        if let Err(e) = remove_socket_dir(&agents_socket()) {
            println!("warning: {e}");
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // `sc stop` refuses a service that is not running, which systemd's stop does not, and
        // returns before the service has stopped.
        let native = NativeService::new(level);
        if native.to_stop(&agents_label())? {
            (native.halt)(&native, agents_label())
                .map_err(|e| format!("cannot stop the second service: {e}"))?;
        }
        manager
            .uninstall(ServiceUninstallCtx {
                label: agents_label(),
            })
            .map_err(|e| format!("cannot uninstall the second service: {e}"))?;
    }
    Ok(true)
}

/// Which of the two services ran before a stop for a change stopped them, and are to run again
/// once the change has succeeded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Halted {
    pub client: bool,
    pub agents: bool,
}

/// How a stop for a change failed: why, and which services it found running and stopped before it
/// failed — the Client, where it then could not be started again too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaltError {
    pub error: String,
    pub stopped: Halted,
}

/// Stops the Client, then the second service, through `stop`, which answers whether the service
/// ran. Where the second cannot be stopped, the Client is started again through `start` if this
/// stopped it: a halt that fails leaves both as it found them, as far as it can.
///
/// # Errors
/// Returns why a service could not be stopped, and why the Client could not be started again,
/// with what this stopped.
fn halt_with(
    stop: &mut dyn FnMut(&ServiceLabel) -> Result<bool, String>,
    start: &mut dyn FnMut(&ServiceLabel) -> Result<(), String>,
) -> Result<Halted, HaltError> {
    let client = stop(&label()).map_err(|error| HaltError {
        error,
        stopped: Halted::default(),
    })?;
    let stopped = Halted {
        client,
        agents: false,
    };
    match stop(&agents_label()) {
        Ok(agents) => Ok(Halted { client, agents }),
        Err(e) if client => match start(&label()) {
            Ok(()) => Err(HaltError { error: e, stopped }),
            Err(again) => Err(HaltError {
                error: format!(
                    "{e}; and the Client, stopped for it, cannot be started again: {again}"
                ),
                stopped,
            }),
        },
        Err(error) => Err(HaltError { error, stopped }),
    }
}

/// Stops the Client, then the second service, and waits until each has stopped and its process
/// has ended — the second service's programs with it (ADR-0059 clause 4) — so that nothing runs
/// under an account whose rights an install is about to change or take away, or a registration it
/// is about to rewrite. Returns which ran.
///
/// # Errors
/// Returns why one could not be stopped, or that one had not ended within the bound of a stop,
/// with what this stopped; that is started again, and nothing is changed.
#[cfg(windows)]
pub fn halt_for_change(level: ServiceLevel) -> Result<Halted, HaltError> {
    halt_with(
        &mut |label| super::windows_config::stop_and_wait(&label.to_qualified_name(), STOPPING),
        &mut |label| {
            manager(level)?
                .start(ServiceStartCtx {
                    label: label.clone(),
                })
                .map_err(|e| format!("cannot start {label}: {e}"))
        },
    )
}

/// Stops the Client, then the second service, and waits until each has stopped and its process
/// has ended, up to [`STOPPING`] each, so that nothing runs under an account whose files an
/// install is about to re-own (ADR-0059 clause 16). Returns which ran: what systemd reports
/// active or activating, what launchd holds with a process. A job launchd holds without one —
/// waiting to be started again — is removed too, or launchd could start it under the former
/// account meanwhile.
///
/// # Errors
/// Returns why one could not be stopped, or that one had not ended within [`STOPPING`], with what
/// this stopped; what ran is started again — the one whose stop failed among them, whose stop may
/// have taken it down later — and nothing is changed.
#[cfg(unix)]
pub fn halt_for_change(level: ServiceLevel) -> Result<Halted, HaltError> {
    halt_with(
        &mut |label| {
            let now = activity(label)?;
            let ran = matches!(now, Activity::Running | Activity::Starting);
            if now == Activity::Stopped && !held(label)? {
                return Ok(false);
            }
            match stop_for_change(label) {
                Ok(()) => Ok(ran),
                Err(e) if ran => Err(match start_for_change(level, label) {
                    Ok(()) => format!("{e}; it was started again"),
                    Err(again) => format!("{e}; and it cannot be started again: {again}"),
                }),
                Err(e) => Err(e),
            }
        },
        &mut |label| start_for_change(level, label),
    )
}

/// Whether the manager holds `label` though it runs no process for it: a launchd job loaded and
/// waiting. systemd's stop of a stopped unit has nothing to end.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn held(_: &ServiceLabel) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn held(label: &ServiceLabel) -> Result<bool, String> {
    launchd_loaded(&label.to_qualified_name())
}

/// Starts again what [`halt_for_change`] stopped, once the change has succeeded ([`resumed`]): the
/// second service first where nothing pulls it in.
///
/// # Errors
/// Returns why a service could not be started, or that one still starting or stopping did not
/// settle in time.
#[cfg(unix)]
pub fn resume(level: ServiceLevel, halted: Halted) -> Result<(), String> {
    resume_with(
        &resumed(halted, agents_registered(level), PULLED_IN),
        &mut |label| activity(label),
        &mut |label| start_for_change(level, label),
        STOPPING,
    )
}

/// What a stop for a change stopped, for a message: `the Client`, `the second service`, or both;
/// `None` where it stopped nothing.
#[must_use]
pub fn describe_halted(halted: Halted) -> Option<&'static str> {
    match (halted.client, halted.agents) {
        (true, true) => Some("the Client and the second service"),
        (true, false) => Some("the Client"),
        (false, true) => Some("the second service"),
        (false, false) => None,
    }
}

/// Whether an install changes an account a service runs under (ADR-0059 clause 16): the
/// registration names a process account and the install names another or none, or the Client's
/// registration names another account than the install — root where it names none. A first
/// registration changes nothing, and neither does a process account added where none was.
#[must_use]
pub fn account_changes(
    client: Option<&Registration>,
    run_as: Option<&str>,
    agents: Option<&Registration>,
    process: Option<&str>,
) -> bool {
    let process_changes = agents
        .and_then(|agents| agents.account.as_deref())
        .is_some_and(|former| process != Some(former));
    let client_changes = client
        .is_some_and(|client| client.account.as_deref().unwrap_or(ROOT) != run_as.unwrap_or(ROOT));
    process_changes || client_changes
}

/// What a service is doing, as systemd reports it: `active` and `reloading` run, `activating`
/// starts, `deactivating` stops, and anything else — `inactive`, `failed`, a unit it does not
/// know — is stopped.
#[cfg(any(target_os = "linux", test))]
fn systemd_activity(state: &str) -> Activity {
    match state {
        "active" | "reloading" | "refreshing" => Activity::Running,
        "activating" => Activity::Starting,
        "deactivating" => Activity::Stopping,
        _ => Activity::Stopped,
    }
}

/// The process `launchctl print` shows the job with: its own `pid = ` line, one tab deep.
#[cfg(any(target_os = "macos", test))]
fn launchd_pid(print: &str) -> Option<u32> {
    print.lines().find_map(|line| {
        line.strip_prefix("\tpid = ")
            .and_then(|pid| pid.trim().parse::<u32>().ok())
    })
}

/// The process `systemctl show --property=MainPID --value` names: none where it says `0`.
#[cfg(any(target_os = "linux", test))]
fn systemd_main_pid(show: &str) -> Option<u32> {
    show.trim().parse::<u32>().ok().filter(|pid| *pid != 0)
}

/// The process the service manager runs as the second service (ADR-0059 clause 4): systemd the
/// unit's `MainPID`, through its system bus. `None` where it runs none.
///
/// # Errors
/// Returns why systemd could not be asked.
#[cfg(target_os = "linux")]
pub fn agents_process() -> Result<Option<u32>, String> {
    use std::process::Stdio;
    let unit = format!("{}.service", agents_label().to_qualified_name());
    let output = std::process::Command::new("systemctl")
        .args(["show", "--property=MainPID", "--value"])
        .arg(&unit)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemctl show {unit} failed ({}): systemd was not asked",
            output.status
        ));
    }
    Ok(systemd_main_pid(&String::from_utf8_lossy(&output.stdout)))
}

/// The process the service manager runs as the second service (ADR-0059 clause 4): launchd the
/// job's `pid`, read from `launchctl print`, whose output launchd does not promise as an interface.
/// `None` where launchd holds no such job (`launchctl` exits 113, "Could not find service"), or
/// holds it without a process.
///
/// # Errors
/// Returns an error if `launchctl` cannot be run, or fails otherwise.
#[cfg(target_os = "macos")]
pub fn agents_process() -> Result<Option<u32>, String> {
    use std::process::Stdio;
    let output = std::process::Command::new("launchctl")
        .arg("print")
        .arg(format!("system/{}", agents_label().to_qualified_name()))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run launchctl: {e}"))?;
    /// What `launchctl` exits with for a service it does not know.
    const NOT_FOUND: i32 = 113;
    match output.status.code() {
        Some(0) => Ok(launchd_pid(&String::from_utf8_lossy(&output.stdout))),
        Some(NOT_FOUND) => Ok(None),
        _ => Err(format!(
            "launchctl print system/{} failed ({}): launchd was not asked",
            agents_label().to_qualified_name(),
            output.status
        )),
    }
}

/// The process the service manager runs as the second service (ADR-0059 clause 4): the SCM the
/// service's process id (`QueryServiceStatusEx`). `None` where it runs none.
///
/// # Errors
/// Returns why the SCM could not be asked.
#[cfg(windows)]
pub fn agents_process() -> Result<Option<u32>, String> {
    super::windows_config::service_process(&agents_service_name())
}

/// Whether a plist is registered `Disabled`.
#[cfg(any(target_os = "macos", test))]
fn plist_disabled(plist: &str) -> bool {
    plist
        .split_once("<key>Disabled</key>")
        .is_some_and(|(_, after)| after.trim_start().starts_with("<true/>"))
}

/// What `label` is doing, as systemd reports it.
///
/// # Errors
/// Returns an error if `systemctl` cannot be run.
#[cfg(target_os = "linux")]
fn activity(label: &ServiceLabel) -> Result<Activity, String> {
    use std::process::Stdio;
    let output = std::process::Command::new("systemctl")
        .arg("is-active")
        .arg(format!("{}.service", label.to_qualified_name()))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    Ok(systemd_activity(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

/// What `label` is doing, as launchd reports it: running where it holds the job with a process,
/// stopped where it holds it without one or not at all.
///
/// # Errors
/// Returns an error if `launchctl` cannot be run.
#[cfg(target_os = "macos")]
fn activity(label: &ServiceLabel) -> Result<Activity, String> {
    use std::process::Stdio;
    let output = std::process::Command::new("launchctl")
        .arg("print")
        .arg(format!("system/{}", label.to_qualified_name()))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run launchctl: {e}"))?;
    Ok(
        if output.status.success()
            && launchd_pid(&String::from_utf8_lossy(&output.stdout)).is_some()
        {
            Activity::Running
        } else {
            Activity::Stopped
        },
    )
}

/// Stops `label` for a change and waits until it has stopped, up to [`STOPPING`]. systemd's stop
/// is queued and waited out. A launchd job is removed from launchd — `launchctl stop` alone sees
/// a `KeepAlive` job started again — and waited for until launchd holds it no more; its plist
/// stays, and [`start_for_change`] or `service start` loads it again.
///
/// # Errors
/// Returns why the stop could not be asked for, or that the service had not stopped in time.
#[cfg(unix)]
fn stop_for_change(label: &ServiceLabel) -> Result<(), String> {
    use std::process::Stdio;
    let name = label.to_qualified_name();
    #[cfg(target_os = "linux")]
    let (program, args, mut stopped): (_, _, Box<dyn FnMut() -> Result<bool, String>>) = (
        "systemctl",
        vec![
            "stop".to_string(),
            "--no-block".to_string(),
            format!("{name}.service"),
        ],
        Box::new(|| activity(label).map(|now| now == Activity::Stopped)),
    );
    #[cfg(target_os = "macos")]
    let (program, args, mut stopped): (_, _, Box<dyn FnMut() -> Result<bool, String>>) = (
        "launchctl",
        vec!["remove".to_string(), name.clone()],
        Box::new(|| launchd_loaded(&name).map(|loaded| !loaded)),
    );
    let status = std::process::Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if !status.success() && !stopped()? {
        return Err(format!(
            "cannot stop {name}: `{program} {}` failed",
            args.join(" ")
        ));
    }
    let until = std::time::Instant::now() + STOPPING;
    while !stopped()? {
        if std::time::Instant::now() >= until {
            return Err(format!(
                "{name} has not stopped {}s after its stop",
                STOPPING.as_secs()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Ok(())
}

/// Starts `label` again after a stop for a change, through the manager — on macOS from its plist
/// first, where the stop removed the job from launchd ([`load_removed_job`]).
///
/// # Errors
/// Returns why it could not be started.
#[cfg(unix)]
fn start_for_change(level: ServiceLevel, label: &ServiceLabel) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if load_removed_job(level, label)? {
        return Ok(());
    }
    manager(level)?
        .start(ServiceStartCtx {
            label: label.clone(),
        })
        .map_err(|e| format!("cannot start {label}: {e}"))
}

/// Loads a job launchd holds no more from its plist, where that plist is not registered
/// `Disabled`: `RunAtLoad` starts it, and `launchctl start` knows only a job launchd holds. Returns
/// whether it did; a plist registered `Disabled` is left to `service-manager`'s start, which
/// clears the key and loads it.
///
/// # Errors
/// Returns why launchd could not be asked, the plist read, or the job loaded.
#[cfg(target_os = "macos")]
fn load_removed_job(level: ServiceLevel, label: &ServiceLabel) -> Result<bool, String> {
    use std::process::Stdio;
    let name = label.to_qualified_name();
    if level != ServiceLevel::System || launchd_loaded(&name)? {
        return Ok(false);
    }
    let plist = Path::new("/Library/LaunchDaemons").join(format!("{name}.plist"));
    let text = match std::fs::read_to_string(&plist) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("cannot read {}: {e}", plist.display())),
    };
    if plist_disabled(&text) {
        return Ok(false);
    }
    let status = std::process::Command::new("launchctl")
        .arg("load")
        .arg(&plist)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("cannot run launchctl: {e}"))?;
    if status.success() {
        Ok(true)
    } else {
        Err(format!(
            "cannot load {}: `launchctl load` failed",
            plist.display()
        ))
    }
}

/// Which of the two services run now — running, starting, or stopping, which a stop already under
/// way found running — as the SCM reports it, before anything stops them: what a stop for a change
/// will have to start again.
///
/// # Errors
/// Returns why the SCM cannot be asked.
#[cfg(windows)]
pub fn running() -> Result<Halted, String> {
    runs_as(|activity| activity != Activity::Stopped)
}

/// Which of the two services run on, settled — running or paused, not starting or stopping — as
/// the SCM reports it after a stop for a change failed: one still stopping counts as stopped, and
/// one still starting as not yet run again, both to be started again by a resume that waits them
/// out.
///
/// # Errors
/// Returns why the SCM cannot be asked.
#[cfg(windows)]
pub fn running_on() -> Result<Halted, String> {
    runs_as(|activity| activity == Activity::Running)
}

#[cfg(windows)]
fn runs_as(runs: fn(Activity) -> bool) -> Result<Halted, String> {
    let asked =
        |label: ServiceLabel| super::windows_config::activity(&label.to_qualified_name()).map(runs);
    Ok(Halted {
        client: asked(label())?,
        agents: asked(agents_label())?,
    })
}

/// Stops the Client and the second service for their deregistration, and waits for each as
/// [`halt_for_change`] does — but starts nothing again where one cannot be stopped: they are going.
///
/// # Errors
/// Returns why each that could not be stopped was not, after trying both.
#[cfg(windows)]
pub fn halt_for_removal() -> Result<(), String> {
    halt_for_removal_with(&mut |label| {
        super::windows_config::stop_and_wait(&label.to_qualified_name(), STOPPING)
    })
}

/// Stops the Client, then the second service, through `stop`: each tried whatever became of the
/// other, and nothing started again.
///
/// # Errors
/// Returns why each that could not be stopped was not.
#[cfg(any(windows, test))]
fn halt_for_removal_with(
    stop: &mut dyn FnMut(&ServiceLabel) -> Result<bool, String>,
) -> Result<(), String> {
    let failed: Vec<String> = [label(), agents_label()]
        .iter()
        .filter_map(|label| stop(label).err())
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// How the two services stand now, for a message: each running or stopped, as far as the SCM can
/// say.
#[cfg(windows)]
#[must_use]
pub fn describe_activity() -> String {
    let say = |label: ServiceLabel, which: &str| match super::windows_config::activity(
        &label.to_qualified_name(),
    ) {
        Ok(Activity::Stopped) => format!("{which} is stopped"),
        Ok(Activity::Stopping) => format!("{which} is stopping"),
        Ok(Activity::Starting | Activity::Running) => format!("{which} runs"),
        Err(e) => format!("what {which} does is not known ({e})"),
    };
    format!(
        "{}, and {}",
        say(label(), "the Client"),
        say(agents_label(), "the second service")
    )
}

/// What [`resume`] starts, in order: where the Client ran, what `start` starts — the second
/// service first where one is registered now and nothing pulls it in — and where the second
/// service alone ran and is registered still, that one. What did not run stays stopped.
fn resumed(halted: Halted, agents_registered: bool, pulled_in: bool) -> Vec<ServiceLabel> {
    if halted.client {
        return started(agents_registered, pulled_in);
    }
    if halted.agents && agents_registered {
        return vec![agents_label()];
    }
    Vec::new()
}

/// Starts again what a stop for a change stopped, once the change has succeeded ([`resumed`]).
///
/// # Errors
/// Returns why a service could not be started, or that one still starting or stopping did not
/// settle in time.
#[cfg(windows)]
pub fn resume(level: ServiceLevel, halted: Halted) -> Result<(), String> {
    resume_with(
        &resumed(halted, agents_registered(level), PULLED_IN),
        &mut |label| super::windows_config::activity(&label.to_qualified_name()),
        &mut |label| {
            manager(level)?
                .start(ServiceStartCtx {
                    label: label.clone(),
                })
                .map_err(|e| e.to_string())
        },
        STOPPING,
    )
}

/// Starts each of `labels` through `start`, asking `activity` first: one that runs — started by
/// hand meanwhile — is not started twice, which the SCM would refuse; one still starting or
/// stopping is asked again until it has settled, up to `within`; one stopped is started. One that
/// has not settled by then is an error, and what is recorded to run again stays recorded.
///
/// # Errors
/// Returns why a service could not be asked or started, or that it did not settle.
fn resume_with(
    labels: &[ServiceLabel],
    activity: &mut dyn FnMut(&ServiceLabel) -> Result<Activity, String>,
    start: &mut dyn FnMut(&ServiceLabel) -> Result<(), String>,
    within: std::time::Duration,
) -> Result<(), String> {
    for label in labels {
        let which = if *label == agents_label() {
            "the second service"
        } else {
            "the service"
        };
        let until = std::time::Instant::now() + within;
        loop {
            match activity(label)? {
                Activity::Running => break,
                Activity::Stopped => {
                    start(label).map_err(|e| format!("cannot start {which}: {e}"))?;
                    break;
                }
                pending if std::time::Instant::now() >= until => {
                    return Err(format!(
                        "{which} is still {} after {}s, and is not started again",
                        if pending == Activity::Starting {
                            "starting"
                        } else {
                            "stopping"
                        },
                        within.as_secs()
                    ));
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(250)),
            }
        }
    }
    Ok(())
}

/// Stops and deregisters a launchd job, and waits until launchd holds it no more (ADR-0059
/// clause 1).
///
/// A failed stop is passed over only where launchd holds no such job — one registered `Disabled`
/// and never started is not loaded, and `launchctl stop` does not know it; a loaded job that
/// could not be stopped is reported. `service-manager` passes over what `launchctl remove`
/// answers, and the job ends asynchronously, so its absence afterwards is what says it was
/// removed: it is waited for `within`, and a job launchd still holds then is reported.
///
/// # Errors
/// Returns an error if a loaded job cannot be stopped, the manager cannot uninstall it, launchd
/// cannot be asked, or launchd still holds it after `within`.
#[cfg(any(target_os = "macos", test))]
fn remove_launchd_job(
    manager: &dyn ServiceManager,
    label: ServiceLabel,
    loaded: &mut dyn FnMut() -> Result<bool, String>,
    within: std::time::Duration,
) -> Result<(), String> {
    if let Err(e) = manager.stop(service_manager::ServiceStopCtx {
        label: label.clone(),
    }) {
        if loaded()? {
            return Err(format!("cannot stop the second service: {e}"));
        }
    }
    let name = label.to_qualified_name();
    manager
        .uninstall(ServiceUninstallCtx { label })
        .map_err(|e| format!("cannot uninstall the second service: {e}"))?;
    let until = std::time::Instant::now() + within;
    while loaded()? {
        if std::time::Instant::now() >= until {
            return Err(format!(
                "launchd still holds {name} {}s after its removal (`launchctl print \
                 system/{name}`)",
                within.as_secs()
            ));
        }
        std::thread::sleep(LAUNCHD_POLL);
    }
    Ok(())
}

/// Whether launchd holds the job `label` in the system domain: `launchctl print system/<label>`
/// succeeds for a loaded job, running or not, and fails for one it does not know.
///
/// # Errors
/// Returns an error if `launchctl` cannot be run.
#[cfg(target_os = "macos")]
fn launchd_loaded(label: &str) -> Result<bool, String> {
    use std::process::Stdio;
    std::process::Command::new("launchctl")
        .arg("print")
        .arg(format!("system/{label}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|e| format!("cannot run launchctl: {e}"))
}

/// Removes the second service's socket — a link at its name as a link — and then its directory,
/// which `service install` made for it on macOS. Both go by their names in held directories, the
/// directory's parent held as [`socket_parent`] holds it, so no link is followed to them. A
/// directory the process account left anything else in stays, and is named.
///
/// # Errors
/// Returns what was left in place, and why.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn remove_socket_dir(socket: &Path) -> Result<(), String> {
    use crate::storage::handle;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let Some(dir) = socket.parent() else {
        return Ok(());
    };
    let left =
        |path: &Path, e: std::io::Error| format!("{} was left in place: {e}", path.display());
    let gone = |result: libc::c_int| match result {
        0 => Ok(()),
        _ => match std::io::Error::last_os_error() {
            e if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            e => Err(e),
        },
    };
    let (parent, name) = socket_parent(dir).map_err(|e| left(socket, e))?;
    let held = match handle::open(parent.as_raw_fd(), &name, handle::DIRECTORY) {
        Ok(held) => held,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(left(socket, e)),
    };
    let file = socket
        .file_name()
        .map(|file| std::ffi::CString::new(file.as_bytes()))
        .transpose()
        .map_err(|e| left(socket, std::io::Error::other(e)))?
        .ok_or_else(|| left(socket, std::io::Error::other("names no file")))?;
    // SAFETY: a valid descriptor and a NUL-terminated name; unlinkat(2) follows no link at it.
    gone(unsafe { libc::unlinkat(held.as_raw_fd(), file.as_ptr(), 0) })
        .map_err(|e| left(socket, e))?;
    // SAFETY: as above; only an empty directory is removed.
    gone(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) })
        .map_err(|e| left(dir, e))
}

/// The installed service, implementing the [`ServiceControl`] seam.
pub struct NativeService {
    level: ServiceLevel,
    /// The service manager of the host; a test's own in its place.
    manager: fn(ServiceLevel) -> Result<Box<dyn ServiceManager>, String>,
    /// Whether a second service is registered at a level.
    agents_registered: fn(ServiceLevel) -> bool,
    /// What a service is doing, where a stop must ask first: under the SCM, whose `sc stop`
    /// refuses a service that does not run (1062) and one still starting (1061), and whose
    /// stopped and pending states `service-manager` reports alike. `None` where a stop of a
    /// stopped service stops nothing — systemd and launchd.
    activity: Option<Asked>,
    /// How a service that is to be stopped is stopped: by the manager, and under the SCM, whose
    /// stop returns before the service has, by a stop that waits until its process has ended.
    halt: fn(&NativeService, ServiceLabel) -> Result<(), String>,
}

/// How a stop asks what a service is doing.
type Asked = fn(&ServiceLabel) -> Result<Activity, String>;

/// What a service is doing, as a stop needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Running,
    Starting,
    Stopping,
    Stopped,
}

/// How long a stop waits for a service that is still starting before it stops it anyway.
const STARTING: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a stop for a change, and under the SCM every stop, waits for a service and its
/// process to end: longer than the second service takes to stop its programs, which
/// [`AGENTS_STOP_TIMEOUT_SECS`] bounds on systemd.
const STOPPING: std::time::Duration = std::time::Duration::from_secs(60);

/// Stops `label` through the manager.
#[cfg(any(not(windows), test))]
fn halt_by_the_manager(service: &NativeService, label: ServiceLabel) -> Result<(), String> {
    (service.manager)(service.level)?
        .stop(service_manager::ServiceStopCtx { label })
        .map_err(|e| e.to_string())
}

impl NativeService {
    /// A handle to the service at the given level.
    #[must_use]
    pub fn new(level: ServiceLevel) -> Self {
        Self {
            level,
            manager,
            agents_registered,
            #[cfg(windows)]
            activity: Some(|label| super::windows_config::activity(&label.to_qualified_name())),
            #[cfg(not(windows))]
            activity: None,
            #[cfg(windows)]
            halt: |_, label| {
                super::windows_config::stop_and_wait(&label.to_qualified_name(), STOPPING)
                    .map(|_| ())
            },
            #[cfg(not(windows))]
            halt: halt_by_the_manager,
        }
    }

    /// Whether `label` is to be stopped: not where it does not run or is stopping already, and
    /// where it is still starting, once it has started — or once [`STARTING`] has passed.
    ///
    /// # Errors
    /// Returns that the manager cannot say what it is doing.
    fn to_stop(&self, label: &ServiceLabel) -> Result<bool, String> {
        let Some(activity) = self.activity else {
            return Ok(true);
        };
        let until = std::time::Instant::now() + STARTING;
        let mut now = activity(label)?;
        while now == Activity::Starting && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(250));
            now = activity(label)?;
        }
        Ok(!matches!(now, Activity::Stopped | Activity::Stopping))
    }
}

/// Whether the Client's registration starts the second service with it: systemd's `Wants=` in the
/// Client's unit does (ADR-0059 clause 9); a launchd plist names no other job.
const PULLED_IN: bool = cfg!(target_os = "linux");

/// What `start` starts, in order. Where a second service is registered and the Client's unit wants
/// it (`Wants=`, `pulled_in`), the Client alone: the manager starts the second service with it.
/// Where nothing pulls it in — launchd — the second service first, then the Client (ADR-0059
/// clause 2). Neither waits for the other: a Client that starts first reaches the second service
/// once it is up.
fn started(agents: bool, pulled_in: bool) -> Vec<ServiceLabel> {
    let mut labels = Vec::new();
    if agents && !pulled_in {
        labels.push(agents_label());
    }
    labels.push(label());
    labels
}

/// What `stop` stops, in order: the Client, then the second service where one is registered —
/// `Wants=` pulls it in on a start but takes it down on no stop (ADR-0059 clause 2).
fn stopped(agents: bool) -> Vec<ServiceLabel> {
    let mut labels = vec![label()];
    if agents {
        labels.push(agents_label());
    }
    labels
}

/// The state is the Client's.
impl ServiceControl for NativeService {
    fn start(&self) -> Result<(), String> {
        for label in started((self.agents_registered)(self.level), PULLED_IN) {
            let which = if label == agents_label() {
                "the second service"
            } else {
                "the service"
            };
            // A job a stop for a change removed from launchd is loaded again from its plist.
            #[cfg(target_os = "macos")]
            if load_removed_job(self.level, &label)
                .map_err(|e| format!("cannot start {which}: {e}"))?
            {
                continue;
            }
            (self.manager)(self.level)?
                .start(ServiceStartCtx { label })
                .map_err(|e| format!("cannot start {which}: {e}"))?;
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        let mut result = Ok(());
        // Each one even when the one before failed: a stop leaves nothing running it can stop.
        for label in stopped((self.agents_registered)(self.level)) {
            let which = if label == agents_label() {
                "the second service"
            } else {
                "the service"
            };
            let stopped = match self.to_stop(&label) {
                Ok(false) => continue,
                Ok(true) => (self.halt)(self, label),
                Err(e) => Err(e),
            }
            .map_err(|e| format!("cannot stop {which}: {e}"));
            if result.is_ok() {
                result = stopped;
            }
        }
        result
    }

    fn state(&self) -> Result<ServiceState, String> {
        let status = (self.manager)(self.level)?
            .status(ServiceStatusCtx { label: label() })
            .map_err(|e| format!("cannot query the service status: {e}"))?;
        Ok(match status {
            ServiceStatus::NotInstalled => ServiceState::NotInstalled,
            ServiceStatus::Stopped(_) => ServiceState::Stopped,
            ServiceStatus::Running => ServiceState::Running,
        })
    }
}

/// The default **data** root for a scope: `<base>/<PRODUCT_NAME>`, where `supervisor.toml` and the
/// state directory live (ADR-0019 clause 7).
///
/// One level named after the product, and no level below it: a second installation is a second
/// build (ADR-0019 clause 5), so there is nothing for a deeper level to distinguish. `--data-root`
/// overrides it, `--root` collapses both halves into one directory, and no path is ever fixed.
///
/// # Errors
/// Returns an error if the platform's base directory cannot be determined from the environment.
pub fn default_root(level: ServiceLevel) -> Result<PathBuf, String> {
    Ok(per_product(default_base(level)?))
}

/// The default root of the executable layout — `versions/` and the `current` pointer — for a
/// scope.
///
/// **Linux at system scope is the only place this differs from the data root** (ADR-0019 clause 8,
/// carrying ADR-0019). A binary staged under `/var/lib` carries the SELinux type `var_lib_t`,
/// which systemd may never execute: the service would register cleanly and then die at its first
/// start with `status=203/EXEC` on every enforcing host (Fedora, RHEL, SUSE 16). The layout
/// therefore lives under `/opt`, whose `usr_t` label is an entrypoint type systemd runs
/// third-party services from, and which every version the self-update stages later inherits.
///
/// Everywhere else — macOS, Windows, and every user scope — layout and data share
/// [`default_root`]. Windows does not split even under the MSI: `Program Files` holds the
/// installer's payload and nothing the daemon rewrites, because the self-update means the
/// service's own account must be able to write `versions/` and `current` (ADR-0019 clause 13).
///
/// # Errors
/// Returns an error if the platform's base directory cannot be determined from the environment.
pub fn default_layout_root(level: ServiceLevel) -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    if level == ServiceLevel::System {
        return Ok(per_product(PathBuf::from("/opt")));
    }
    default_root(level)
}

/// `<base>/<PRODUCT_NAME>` — one level, named after the product (ADR-0019 clause 7).
fn per_product(base: PathBuf) -> PathBuf {
    base.join(PRODUCT_NAME)
}

#[cfg(target_os = "linux")]
fn default_base(level: ServiceLevel) -> Result<PathBuf, String> {
    match level {
        ServiceLevel::System => Ok(PathBuf::from("/var/lib")),
        ServiceLevel::User => std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".local/share")))
            .ok_or_else(|| "neither XDG_DATA_HOME nor HOME is set".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn default_base(level: ServiceLevel) -> Result<PathBuf, String> {
    match level {
        ServiceLevel::System => Ok(PathBuf::from("/Library/Application Support")),
        ServiceLevel::User => std::env::var_os("HOME")
            .map(|home| Path::new(&home).join("Library/Application Support"))
            .ok_or_else(|| "HOME is not set".to_string()),
    }
}

#[cfg(windows)]
fn default_base(level: ServiceLevel) -> Result<PathBuf, String> {
    let var = match level {
        ServiceLevel::System => "ProgramData",
        ServiceLevel::User => "LOCALAPPDATA",
    };
    std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{var} is not set"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::layout;

    /// ADR-0019's whole mechanism: a label with no qualifier and no organization renders the
    /// same through *both* of the crate's functions, so systemd, launchd, and the SCM show one
    /// name. A dot anywhere in it would split the label again and undo that.
    /// Verifies: ADR-0019
    #[test]
    fn every_backend_renders_the_same_name() {
        let label = label();
        assert_eq!(
            label.to_qualified_name(),
            PRODUCT_NAME,
            "launchd and the SCM"
        );
        assert_eq!(label.to_script_name(), PRODUCT_NAME, "systemd");
        assert!(
            !PRODUCT_NAME.contains('.'),
            "a dot would split the label again"
        );
    }

    /// The service carries the **product's** name and the program carries its own (ADR-0019
    /// clause 9). They are separate constants holding different strings, and the day someone
    /// derives one from the other, one published package Set stops serving every variant.
    /// Verifies: ADR-0019
    #[test]
    fn the_service_is_named_after_the_product_not_the_program() {
        assert_eq!(service_name(), PRODUCT_NAME);
        assert_eq!(service_name(), "opamp-fleet");
        assert_eq!(layout::COMPONENT, "supervisor");
        assert_ne!(
            service_name(),
            layout::COMPONENT,
            "the product names the installation, the program names the file"
        );
    }

    /// No suffix, on any platform: one build installs one service, so there is no second one to
    /// tell apart and nothing for a verb to look up (ADR-0019 clauses 3 and 6).
    /// Verifies: ADR-0019
    #[test]
    fn the_service_name_carries_no_suffix() {
        assert!(!service_name().contains('-') || service_name() == PRODUCT_NAME);
        assert_eq!(
            service_name(),
            PRODUCT_NAME,
            "whatever the product is called, the service is called exactly that"
        );
    }

    /// The display name is prose and the service name is a slug; neither is derived from the
    /// other, because no rule that produces `OpAMP Fleet Agent` from `opamp-fleet` would still
    /// read correctly for the next variant build (ADR-0019 clause 2).
    /// Verifies: ADR-0019
    #[test]
    fn the_names_a_human_reads() {
        assert_eq!(display_name(), PRODUCT_TITLE);
        assert_ne!(display_name(), service_name());
    }

    /// The Windows Description column is its own field: a service can carry a display name and
    /// still show nothing there, which is what it did. It answers "what is this?", so it must not
    /// simply repeat the display name beside it.
    #[test]
    fn the_windows_services_list_has_a_description_to_show() {
        assert!(
            !WINDOWS_DESCRIPTION.is_empty(),
            "an empty one clears the field"
        );
        assert_ne!(
            WINDOWS_DESCRIPTION,
            display_name(),
            "the description says what this is, it does not restate the display name"
        );
    }

    /// Verifies: ADR-0019
    #[test]
    fn the_installed_command_line_is_the_marker_plus_absolute_paths() {
        let spec = InstallSpec {
            level: ServiceLevel::System,
            program: PathBuf::from("/opt/opamp-fleet/current/supervisor"),
            config_path: PathBuf::from("/var/lib/opamp-fleet/supervisor.toml"),
            state_dir: PathBuf::from("/var/lib/opamp-fleet/state"),
            run_as: Some("opamp-fleet".to_string()),
            agents: None,
        };
        let args = service_args(&spec);
        assert!(
            !args.contains(&OsString::from("opamp-fleet")),
            "the account decides who runs the command, it is never part of it (ADR-0019)"
        );
        assert!(
            !args.contains(&OsString::from("--instance")),
            "the flag is removed, not hidden (ADR-0019 clause 6)"
        );
        assert_eq!(args[0], OsString::from("run"));
        assert_eq!(args[1], OsString::from("--service"));
        assert!(args.contains(&OsString::from("/var/lib/opamp-fleet/supervisor.toml")));
        assert!(args.contains(&OsString::from("/var/lib/opamp-fleet/state")));
    }

    /// The Windows recovery actions are configured separately from the policy handed to
    /// `service-manager` (see `windows_config`), so the two could drift into disagreeing about
    /// how long a failed Client waits before it comes back. They read one constant; this is what
    /// says so.
    /// Verifies: ADR-0019
    #[test]
    fn both_platforms_restart_after_the_same_delay() {
        match RESTART_POLICY {
            RestartPolicy::OnFailure {
                delay_secs,
                max_retries,
                ..
            } => {
                assert_eq!(delay_secs, Some(RESTART_DELAY_SECS));
                assert_eq!(max_retries, None, "a host recovers however long it takes");
            }
            other => panic!("the Client restarts only on failure (ADR-0019), got {other:?}"),
        }
        // The systemd system unit is the Client's own text now (ADR-0042 clause 6), so its
        // restart delay is a third place that reads the constant.
        let unit = systemd_unit(&system_spec("/opt/opamp-fleet"), "opamp-fleet").expect("unit");
        assert!(unit.lines().any(|l| l == "Restart=on-failure"), "{unit}");
        assert!(
            unit.lines()
                .any(|l| l == format!("RestartSec={RESTART_DELAY_SECS}")),
            "{unit}"
        );
    }

    fn system_spec(layout: &str) -> InstallSpec {
        InstallSpec {
            level: ServiceLevel::System,
            program: PathBuf::from(format!("{layout}/current/supervisor")),
            config_path: PathBuf::from("/var/lib/opamp-fleet/supervisor.toml"),
            state_dir: PathBuf::from("/var/lib/opamp-fleet/state"),
            run_as: Some("opamp-fleet".to_string()),
            agents: None,
        }
    }

    /// The directive name of each line of `unit` that sets one.
    fn directives(unit: &str) -> Vec<&str> {
        unit.lines()
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim()))
            .collect()
    }

    /// The unit the Client writes holds what `service-manager` rendered before, in the Client's own
    /// text: the product's name as `Description`, a quoted `ExecStart` with the marker and absolute
    /// paths, the restart policy, the account, and the target.
    /// Verifies: ADR-0042
    #[test]
    fn the_system_unit_is_the_clients_own_text() {
        let unit = systemd_unit(&system_spec("/opt/opamp-fleet"), "opamp-fleet").expect("unit");
        let lines: Vec<&str> = unit.lines().collect();
        assert_eq!(lines[0], "[Unit]");
        assert!(lines.contains(&"Description=opamp-fleet"), "{unit}");
        assert!(lines.contains(&"[Service]"), "{unit}");
        assert!(
            lines.contains(
                &"ExecStart=\"/opt/opamp-fleet/current/supervisor\" \"run\" \"--service\" \
                  \"--config\" \"/var/lib/opamp-fleet/supervisor.toml\" \"--state-dir\" \
                  \"/var/lib/opamp-fleet/state\""
            ),
            "{unit}"
        );
        assert!(lines.contains(&"Restart=on-failure"), "{unit}");
        assert!(lines.contains(&"RestartSec=5"), "{unit}");
        assert!(lines.contains(&"User=opamp-fleet"), "{unit}");
        assert!(lines.contains(&"[Install]"), "{unit}");
        assert!(lines.contains(&"WantedBy=multi-user.target"), "{unit}");
        let service = unit.find("[Service]").expect("service section");
        let install = unit.find("[Install]").expect("install section");
        assert!(service < unit.find("ExecStart=").expect("exec") && install > service);
    }

    /// systemd splits `ExecStart=` at spaces and expands `%` and `$`, so a root holding any of them
    /// named the wrong program or the wrong file. Quoted and escaped, it reaches the program as it
    /// was given.
    /// Verifies: ADR-0042
    #[test]
    fn exec_start_survives_spaces_percent_and_dollar() {
        let unit =
            systemd_unit(&system_spec("/srv/my fleet/100%/$HOME"), "opamp-fleet").expect("unit");
        let exec = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("ExecStart");
        assert!(
            exec.starts_with("ExecStart=\"/srv/my fleet/100%%/$$HOME/current/supervisor\" \"run\""),
            "{exec}"
        );
        assert_eq!(
            exec_word(std::ffi::OsStr::new(r#"a\b"c"#)).expect("utf-8"),
            r#""a\\b\"c""#
        );
        assert_eq!(
            exec_word(std::ffi::OsStr::new("a\nb")).expect("utf-8"),
            "\"a\\nb\"",
            "a newline must not end the directive"
        );
    }

    /// Under an account, the unit sets nothing that implies `no_new_privs`, because that would
    /// break `sudo` and every setuid helper the agents use; it carries `ProtectControlGroups=`.
    /// Verifies: ADR-0042
    #[test]
    fn an_account_unit_sets_nothing_that_implies_no_new_privs() {
        let unit = systemd_unit(&system_spec("/opt/opamp-fleet"), "opamp-fleet").expect("unit");
        let set = directives(&unit);
        assert!(
            unit.lines().any(|l| l == "ProtectControlGroups=yes"),
            "{unit}"
        );
        for implies in [
            "NoNewPrivileges",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectClock",
            "ProtectHostname",
            "PrivateDevices",
            "RestrictAddressFamilies",
            "LockPersonality",
            "RestrictRealtime",
            "RestrictSUIDSGID",
            "RestrictNamespaces",
            "MemoryDenyWriteExecute",
            "SystemCallFilter",
            "SystemCallArchitectures",
            "DynamicUser",
        ] {
            assert!(!set.contains(&implies), "{implies} in {unit}");
        }
    }

    /// Under root the three directives that would imply `no_new_privs` for an account imply
    /// nothing, and the unit carries them.
    /// Verifies: ADR-0042
    #[test]
    fn a_root_unit_carries_the_root_tier() {
        let unit = systemd_unit(&system_spec("/opt/opamp-fleet"), "root").expect("unit");
        for directive in [
            "User=root",
            "ProtectControlGroups=yes",
            "ProtectKernelTunables=yes",
            "LockPersonality=yes",
            "RestrictRealtime=yes",
        ] {
            assert!(
                unit.lines().any(|l| l == directive),
                "{directive} in {unit}"
            );
        }
    }

    /// No unit, under any account, carries a directive that takes from a supported agent what it
    /// needs: writing the system for a package install, `/home` for a log receiver, a socket under
    /// `/tmp`, or root's capabilities.
    /// Verifies: ADR-0042
    #[test]
    fn no_unit_carries_what_breaks_a_supported_agent() {
        for account in ["root", "opamp-fleet"] {
            let unit = systemd_unit(&system_spec("/opt/opamp-fleet"), account).expect("unit");
            let set = directives(&unit);
            for breaks in [
                "ProtectSystem",
                "ProtectHome",
                "PrivateTmp",
                "CapabilityBoundingSet",
                "NoNewPrivileges",
                "RestrictSUIDSGID",
                "ProtectProc",
            ] {
                assert!(!set.contains(&breaks), "{breaks} under {account}: {unit}");
            }
        }
        assert!(
            systemd_unit(
                &system_spec("/opt/opamp-fleet"),
                "evil\nExecStartPre=/bin/sh"
            )
            .is_err(),
            "an account name cannot add a directive"
        );
    }

    /// The Client writes the systemd **system** unit only; the user scope and every other manager
    /// keep `service-manager`'s rendering.
    /// Verifies: ADR-0042
    #[test]
    fn a_user_unit_is_left_to_service_manager() {
        let mut spec = system_spec("/opt/opamp-fleet");
        assert!(unit_contents(&spec, true).expect("system").is_some());
        assert_eq!(unit_contents(&spec, false).expect("not systemd"), None);
        spec.level = ServiceLevel::User;
        spec.run_as = None;
        assert_eq!(unit_contents(&spec, true).expect("user"), None);
        spec.level = ServiceLevel::System;
        let unit = unit_contents(&spec, true)
            .expect("no account")
            .expect("unit");
        assert!(
            unit.lines().any(|l| l == "User=root"),
            "a system unit always names its account: {unit}"
        );
    }

    #[cfg(unix)]
    fn agents() -> Agents {
        Agents {
            account: "opamp-fleet-agents".to_string(),
            uid: 997,
            gid: 997,
            client_uid: 998,
            socket: PathBuf::from("/run/opamp-fleet-agents/agents.sock"),
        }
    }

    #[cfg(windows)]
    fn agents() -> Agents {
        Agents {
            account: r"NT SERVICE\opamp-fleet-agents".to_string(),
            sid: crate::win32::Sid::parse("S-1-5-80-1-2-3-4-5").expect("sid"),
            client_sid: crate::win32::Sid::parse("S-1-5-80-6-7-8-9-10").expect("sid"),
            socket: agents_socket(),
        }
    }

    #[cfg(unix)]
    fn with_agents() -> InstallSpec {
        InstallSpec {
            agents: Some(agents()),
            ..system_spec("/opt/opamp-fleet")
        }
    }

    /// The second service is the product's name with `-agents`, one token that every backend
    /// renders alike, and its socket lives in a directory named after it: the runtime directory
    /// under systemd, one that outlasts a reboot on macOS, where `/var/run` is emptied at boot.
    /// Verifies: ADR-0059
    #[test]
    fn the_second_service_is_named_after_the_product() {
        assert_eq!(agents_service_name(), format!("{PRODUCT_NAME}-agents"));
        let label = agents_label();
        assert_eq!(label.to_qualified_name(), agents_service_name());
        assert_eq!(label.to_script_name(), agents_service_name());
        #[cfg(target_os = "linux")]
        assert_eq!(
            agents_socket(),
            PathBuf::from("/run/opamp-fleet-agents/agents.sock")
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            agents_socket(),
            PathBuf::from("/Library/Application Support/opamp-fleet-agents/agents.sock")
        );
    }

    #[cfg(unix)]
    fn macos_agents() -> Agents {
        Agents {
            account: "_opamp-fleet-agents".to_string(),
            socket: PathBuf::from("/Library/Application Support/opamp-fleet-agents/agents.sock"),
            ..agents()
        }
    }

    /// Under launchd the second service's plist is the one `service-manager` renders, as it
    /// renders the Client's: the same program as `run --agents` serving the Client's uid, the
    /// process account in `UserName`, the Client's restart policy, and started by `service start`,
    /// not by the install. Under systemd it is the unit the Client writes.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_second_services_plist_is_the_one_service_manager_renders() {
        let ctx = agents_install_ctx(&with_agents(), &macos_agents(), false).expect("ctx");
        assert!(ctx.contents.is_none(), "{:?}", ctx.contents);
        assert_eq!(ctx.label, agents_label());
        assert_eq!(
            ctx.program,
            PathBuf::from("/opt/opamp-fleet/current/supervisor")
        );
        assert_eq!(ctx.args, agents_args(&macos_agents()));
        assert_eq!(ctx.username.as_deref(), Some("_opamp-fleet-agents"));
        assert!(
            ctx.autostart,
            "RunAtLoad, held back by Disabled until service start"
        );
        assert_eq!(ctx.restart_policy, RESTART_POLICY);
        assert_eq!(
            (ctx.working_directory, ctx.environment),
            (None, None),
            "nothing the Client's plist does not carry either"
        );

        let ctx = agents_install_ctx(&with_agents(), &agents(), true).expect("ctx");
        assert_eq!(
            ctx.contents,
            Some(agents_unit(&with_agents(), &agents()).expect("unit"))
        );
    }

    /// launchd's default exit timeout, which the second service's plist keeps, outlasts the time
    /// the service takes to stop what it started: the grace its programs have to end, and the
    /// drain of their output after it. A stop ends them through the service, not through launchd.
    /// Not on Windows, which has no second service's channel to read the grace from.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn launchds_default_exit_timeout_outlasts_the_second_services_stop() {
        use crate::supervisor::channel::{CLOSE_GRACE, OUTPUT_DRAIN};
        assert_eq!(LAUNCHD_EXIT_TIMEOUT, std::time::Duration::from_secs(20));
        assert!(CLOSE_GRACE + OUTPUT_DRAIN < LAUNCHD_EXIT_TIMEOUT);
    }

    /// A re-registration reads the process account back from the plist as `service-manager`
    /// writes it — through the `plist` crate, which escapes what XML must — and as its `start`
    /// rewrites it without `Disabled`: a name with markup in it comes back as it was given.
    /// Verifies: ADR-0059
    #[test]
    fn the_process_account_is_read_back_from_the_plist_service_manager_writes() {
        use plist::{Dictionary, Value};
        for account in ["_opamp-fleet-agents", "_a&b<c>'d"] {
            let mut keep_alive = Dictionary::new();
            keep_alive.insert("SuccessfulExit".to_string(), Value::Boolean(false));
            let mut dict = Dictionary::new();
            dict.insert("Label".to_string(), Value::String(agents_service_name()));
            dict.insert(
                "ProgramArguments".to_string(),
                Value::Array(vec![Value::String("/opt/a&b/supervisor".to_string())]),
            );
            dict.insert("KeepAlive".to_string(), Value::Dictionary(keep_alive));
            dict.insert("UserName".to_string(), Value::String(account.to_string()));
            dict.insert("RunAtLoad".to_string(), Value::Boolean(true));
            dict.insert("Disabled".to_string(), Value::Boolean(true));
            let mut plist = Value::Dictionary(dict);
            for _ in ["installed", "started"] {
                let mut xml = Vec::new();
                plist.to_writer_xml(&mut xml).expect("xml");
                let xml = String::from_utf8(xml).expect("utf-8");
                assert_eq!(plist_account(&xml).as_deref(), Some(account), "{xml}");
                if let Value::Dictionary(dict) = &mut plist {
                    dict.remove("Disabled");
                }
            }
        }
    }

    /// On Windows the second service is the SCM's `<PRODUCT_NAME>-agents` on the pipe
    /// `\\.\pipe\<PRODUCT_NAME>-agents`: its command line names the pipe and the SID of the
    /// Client's account it serves, the Client's names the pipe and the process account's SID, and
    /// both are registered through the same `service-manager` call as on the other platforms,
    /// the logon account set afterwards (ADR-0059 clauses 2 and 8).
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_both_command_lines_name_the_pipe_and_a_sid() {
        assert_eq!(
            agents_socket(),
            PathBuf::from(format!(r"\\.\pipe\{PRODUCT_NAME}-agents"))
        );
        let spec = InstallSpec {
            agents: Some(agents()),
            ..system_spec(r"C:\ProgramData\opamp-fleet")
        };
        let pipe = agents_socket().into_os_string();
        let client = service_args(&spec);
        assert_eq!(
            client[client.len() - 4..],
            [
                OsString::from("--agents-socket"),
                pipe.clone(),
                OsString::from("--process-sid"),
                OsString::from("S-1-5-80-1-2-3-4-5"),
            ]
        );
        assert_eq!(
            agents_args(&agents()),
            [
                OsString::from("run"),
                OsString::from("--agents"),
                pipe,
                OsString::from("--client-sid"),
                OsString::from("S-1-5-80-6-7-8-9-10"),
            ]
        );
        let ctx = agents_install_ctx(&spec, &agents(), false).expect("ctx");
        assert_eq!((ctx.label, ctx.contents), (agents_label(), None));
        assert_eq!(ctx.restart_policy, RESTART_POLICY);
        assert!(agents_display_name().starts_with(PRODUCT_TITLE));
        assert_ne!(AGENTS_WINDOWS_DESCRIPTION, WINDOWS_DESCRIPTION);
    }

    /// The Client's plist, which `service-manager` renders from the command line, names the
    /// socket and the process account's uid where a process account is registered, as its unit
    /// does under systemd (ADR-0059 clause 8).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_clients_command_line_names_the_second_service() {
        let spec = InstallSpec {
            agents: Some(macos_agents()),
            ..system_spec("/Library/Application Support/opamp-fleet")
        };
        let args = service_args(&spec);
        let tail: Vec<&std::ffi::OsStr> = args[args.len() - 4..]
            .iter()
            .map(OsString::as_os_str)
            .collect();
        assert_eq!(
            tail,
            [
                "--agents-socket",
                "/Library/Application Support/opamp-fleet-agents/agents.sock",
                "--process-uid",
                "997"
            ]
            .map(std::ffi::OsStr::new)
        );
        assert!(!service_args(&system_spec("/opt/opamp-fleet"))
            .iter()
            .any(|a| a.to_string_lossy().contains("agents")));
    }

    /// The directory of the socket is the process account's, `0750`: it alone writes there, and
    /// the Client's account reaches the socket through its group. One already there is taken and
    /// given the same; a link at its name is not followed. Run unprivileged, the test's own
    /// account and group stand in for the process account's.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_sockets_directory_is_the_process_accounts() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_dir_path = dir.path().join("opamp-fleet-agents");
        // SAFETY: geteuid(2) and getegid(2) cannot fail and touch no memory.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        socket_dir(&socket_dir_path, uid, gid).expect("created");
        let meta = std::fs::metadata(&socket_dir_path).expect("metadata");
        assert_eq!(
            (meta.mode() & 0o7777, meta.uid(), meta.gid()),
            (0o750, uid, gid)
        );
        std::fs::set_permissions(&socket_dir_path, std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        socket_dir(&socket_dir_path, uid, gid).expect("taken");
        assert_eq!(
            std::fs::metadata(&socket_dir_path)
                .expect("metadata")
                .mode()
                & 0o7777,
            0o750
        );
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("mkdir");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&elsewhere, &linked).expect("a link");
        assert!(socket_dir(&linked, uid, gid).is_err());
        assert_eq!(
            std::fs::metadata(&elsewhere).expect("metadata").mode() & 0o7777,
            0o755,
            "the link's target is left as it was"
        );
    }

    /// The second service runs the same program under the process account, as `run --agents`
    /// serving the Client's uid, with its socket in a runtime directory only the account and its
    /// group reach, and the directives ADR-0042 clause 7 gives a unit that is not root.
    /// Not on Windows, which registers no second service: the socket is a Unix path, and a Windows
    /// build joins it with its own separator.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_second_services_unit_runs_the_program_under_the_process_account() {
        let unit = agents_unit(&with_agents(), &agents()).expect("unit");
        let lines: Vec<&str> = unit.lines().collect();
        for line in [
            "[Unit]",
            "Description=opamp-fleet-agents",
            "[Service]",
            "ExecStart=\"/opt/opamp-fleet/current/supervisor\" \"run\" \"--agents\" \
             \"/run/opamp-fleet-agents/agents.sock\" \"--client-uid\" \"998\"",
            "Restart=on-failure",
            "RestartSec=5",
            "User=opamp-fleet-agents",
            "RuntimeDirectory=opamp-fleet-agents",
            "RuntimeDirectoryMode=0750",
            "ProtectControlGroups=yes",
            "[Install]",
            "WantedBy=multi-user.target",
        ] {
            assert!(lines.contains(&line), "{line} in {unit}");
        }
        let set = directives(&unit);
        for absent in [
            "NoNewPrivileges",
            "ProtectKernelTunables",
            "LockPersonality",
            "RestrictRealtime",
            "ProtectSystem",
            "ProtectHome",
            "PrivateTmp",
            "Wants",
            "After",
        ] {
            assert!(!set.contains(&absent), "{absent} in {unit}");
        }
        let mut evil = agents();
        evil.account = "evil\nExecStartPre=/bin/sh".to_string();
        assert!(
            agents_unit(&with_agents(), &evil).is_err(),
            "an account name cannot add a directive"
        );
    }

    /// A re-registration keeps the process account the second service's unit names: what the
    /// Client writes there, it reads back.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_second_services_account_is_read_back_from_its_unit() {
        let unit = agents_unit(&with_agents(), &agents()).expect("unit");
        assert_eq!(unit_account(&unit).as_deref(), Some("opamp-fleet-agents"));
    }

    /// systemd waits longer for the second service to stop than the service gives its programs,
    /// so a stop ends them through the service.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_second_service_stops_before_systemd_kills_it() {
        use crate::supervisor::channel::{CLOSE_GRACE, OUTPUT_DRAIN};
        let unit = agents_unit(&with_agents(), &agents()).expect("unit");
        assert!(
            unit.lines()
                .any(|l| l == format!("TimeoutStopSec={AGENTS_STOP_TIMEOUT_SECS}")),
            "{unit}"
        );
        assert!(
            std::time::Duration::from_secs(u64::from(AGENTS_STOP_TIMEOUT_SECS))
                > CLOSE_GRACE + OUTPUT_DRAIN
        );
    }

    std::thread_local! {
        /// What the [`Recording`] service manager was asked, in order, on this test's thread.
        static ASKED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// A service manager that does nothing but note what it is asked, and fails to stop the
    /// Client's service.
    struct Recording;

    impl Recording {
        fn note(what: &str, label: &ServiceLabel) {
            ASKED.with(|asked| asked.borrow_mut().push(format!("{what} {label}")));
        }

        fn asked() -> Vec<String> {
            ASKED.with(|asked| std::mem::take(&mut *asked.borrow_mut()))
        }
    }

    impl ServiceManager for Recording {
        fn available(&self) -> std::io::Result<bool> {
            Ok(true)
        }
        fn install(&self, ctx: ServiceInstallCtx) -> std::io::Result<()> {
            Recording::note("install", &ctx.label);
            Ok(())
        }
        fn uninstall(&self, ctx: ServiceUninstallCtx) -> std::io::Result<()> {
            Recording::note("uninstall", &ctx.label);
            Ok(())
        }
        fn start(&self, ctx: ServiceStartCtx) -> std::io::Result<()> {
            Recording::note("start", &ctx.label);
            Ok(())
        }
        fn stop(&self, ctx: service_manager::ServiceStopCtx) -> std::io::Result<()> {
            Recording::note("stop", &ctx.label);
            if ctx.label == label() {
                return Err(std::io::Error::other("refused"));
            }
            Ok(())
        }
        fn level(&self) -> SmLevel {
            SmLevel::System
        }
        fn set_level(&mut self, _level: SmLevel) -> std::io::Result<()> {
            Ok(())
        }
        fn status(&self, ctx: ServiceStatusCtx) -> std::io::Result<ServiceStatus> {
            Recording::note("status", &ctx.label);
            Ok(ServiceStatus::Running)
        }
    }

    fn recording(
        level: ServiceLevel,
        agents_registered: fn(ServiceLevel) -> bool,
    ) -> NativeService {
        NativeService {
            level,
            manager: |_| Ok(Box::new(Recording)),
            agents_registered,
            activity: None,
            halt: halt_by_the_manager,
        }
    }

    /// Where a stop asks first — under the SCM — a service that does not run or is stopping
    /// already is not stopped again, and one still starting is stopped once it has started
    /// (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[test]
    fn a_stop_passes_over_a_service_that_does_not_run() {
        let client = label().to_string();
        let agents = agents_label().to_string();
        let asking = |activity: Asked| NativeService {
            activity: Some(activity),
            ..recording(ServiceLevel::System, |_| true)
        };
        let _ = asking(|label| {
            Ok(if *label == agents_label() {
                Activity::Stopped
            } else {
                Activity::Running
            })
        })
        .stop();
        assert_eq!(Recording::asked(), vec![format!("stop {client}")]);
        let _ = asking(|_| Ok(Activity::Stopping)).stop();
        assert_eq!(Recording::asked(), Vec::<String>::new());
        static STARTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let _ = asking(|_| {
            Ok(
                if STARTED.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                    Activity::Starting
                } else {
                    Activity::Running
                },
            )
        })
        .stop();
        assert_eq!(
            Recording::asked(),
            vec![format!("stop {client}"), format!("stop {agents}")],
            "stopped once started"
        );
    }

    /// What a stop for a change stopped is started again in the order `start` starts it — the
    /// second service first where nothing pulls it in — and where only the second service ran,
    /// that one alone, while it is registered still; what did not run stays stopped (ADR-0059
    /// clause 2).
    /// Verifies: ADR-0059
    #[test]
    fn a_resume_starts_what_ran_in_the_order_start_starts_it() {
        let both = Halted {
            client: true,
            agents: true,
        };
        assert_eq!(resumed(both, true, false), [agents_label(), label()]);
        assert_eq!(resumed(both, true, true), [label()]);
        assert_eq!(
            resumed(both, false, false),
            [label()],
            "the second one dropped"
        );
        let agents_alone = Halted {
            client: false,
            agents: true,
        };
        assert_eq!(resumed(agents_alone, true, false), [agents_label()]);
        assert!(resumed(agents_alone, false, false).is_empty(), "dropped");
        assert!(resumed(Halted::default(), true, false).is_empty());
    }

    /// An install changes an account where the registration names a process account and the install
    /// names another or none, or where the Client's registration names another account than the
    /// install, root standing in where it names none; a first registration and a process account
    /// added where none was change nothing (ADR-0059 clause 16).
    /// Verifies: ADR-0059
    #[test]
    fn an_account_change_is_a_former_account_named_no_more() {
        let named = |account: Option<&str>| Registration {
            file: PathBuf::from("/etc/systemd/system/unit.service"),
            account: account.map(str::to_string),
        };
        let fleet = named(Some("opamp-fleet"));
        let root = named(None);
        let agents = named(Some("opamp-fleet-agents"));
        let other = named(Some("other-agents"));
        // A first registration.
        assert!(!account_changes(
            None,
            Some("opamp-fleet"),
            None,
            Some("opamp-fleet-agents")
        ));
        // An upgrade that keeps both.
        assert!(!account_changes(
            Some(&fleet),
            Some("opamp-fleet"),
            Some(&agents),
            Some("opamp-fleet-agents")
        ));
        // A process account added where none was.
        assert!(!account_changes(
            Some(&fleet),
            Some("opamp-fleet"),
            None,
            Some("opamp-fleet-agents")
        ));
        // Root, named or left unnamed, is root.
        assert!(!account_changes(Some(&root), Some("root"), None, None));
        assert!(!account_changes(Some(&root), None, None, None));
        // The process account dropped, or another named.
        assert!(account_changes(
            Some(&fleet),
            Some("opamp-fleet"),
            Some(&agents),
            None
        ));
        assert!(account_changes(
            Some(&fleet),
            Some("opamp-fleet"),
            Some(&other),
            Some("opamp-fleet-agents")
        ));
        // Another account for the Client.
        assert!(account_changes(
            Some(&root),
            Some("opamp-fleet"),
            None,
            None
        ));
        assert!(account_changes(Some(&fleet), None, None, None));
    }

    /// What ran, for a stop for a change, is what systemd reports active or activating, and what
    /// launchd holds with a process (ADR-0059 clause 16); a job registered `Disabled` is loaded
    /// by `service-manager`'s start, any other one a stop removed by the Client's.
    /// Verifies: ADR-0059
    #[test]
    fn what_ran_is_what_the_manager_reports_running() {
        assert_eq!(systemd_activity("active"), Activity::Running);
        assert_eq!(systemd_activity("reloading"), Activity::Running);
        assert_eq!(systemd_activity("activating"), Activity::Starting);
        assert_eq!(systemd_activity("deactivating"), Activity::Stopping);
        for stopped in ["inactive", "failed", "unknown", ""] {
            assert_eq!(systemd_activity(stopped), Activity::Stopped, "{stopped}");
        }
        let print = "system/opamp-fleet = {\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/opamp-fleet.plist\n\tstate = running\n\n\tpid = 4242\n\tendpoints = {\n\t\tpid = 7\n\t}\n}\n";
        assert_eq!(launchd_pid(print), Some(4242));
        assert_eq!(launchd_pid(&print.replace("\tpid = 4242\n", "")), None);
        assert!(plist_disabled(
            "<dict>\n\t<key>Disabled</key>\n\t<true/>\n</dict>"
        ));
        assert!(!plist_disabled(
            "<dict>\n\t<key>Disabled</key>\n\t<false/>\n</dict>"
        ));
        assert!(!plist_disabled(
            "<dict>\n\t<key>RunAtLoad</key>\n\t<true/>\n</dict>"
        ));
    }

    /// The second service's process is the one systemd names its unit's `MainPID`, and the one
    /// launchd prints as the job's own `pid` rather than an endpoint's; `0`, or no such line, is
    /// none (ADR-0059 clause 4).
    /// Verifies: ADR-0059
    #[test]
    fn the_second_services_process_is_the_one_the_manager_names() {
        assert_eq!(systemd_main_pid("4242\n"), Some(4242));
        for none in ["0\n", "", "[not set]\n"] {
            assert_eq!(systemd_main_pid(none), None, "{none:?}");
        }
        let print = "system/opamp-fleet-agents = {\n\tstate = running\n\tendpoints = {\n\t\tpid = 7\n\t}\n\tpid = 4242\n}\n";
        assert_eq!(launchd_pid(print), Some(4242));
        assert_eq!(launchd_pid(&print.replace("\tpid = 4242\n", "")), None);
    }

    /// A stop for a change that cannot stop the second service starts the Client again where it
    /// stopped it, and fails: it leaves both as it found them, and the install changes nothing
    /// (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn a_halt_that_fails_changes_nothing() {
        let mut started = Vec::new();
        let failed = halt_with(
            &mut |label| {
                if *label == agents_label() {
                    Err("did not stop in time".to_string())
                } else {
                    Ok(true)
                }
            },
            &mut |label| {
                started.push(label.clone());
                Ok(())
            },
        );
        assert_eq!(
            failed,
            Err(HaltError {
                error: "did not stop in time".to_string(),
                stopped: Halted {
                    client: true,
                    agents: false
                }
            }),
            "with what it stopped"
        );
        assert_eq!(started, [label()], "the Client runs again");

        let mut started = Vec::new();
        let failed = halt_with(
            &mut |label| {
                if *label == agents_label() {
                    Err("did not stop in time".to_string())
                } else {
                    Ok(false)
                }
            },
            &mut |label| {
                started.push(label.clone());
                Ok(())
            },
        );
        assert!(failed.is_err());
        assert!(
            started.is_empty(),
            "a Client that did not run is not started"
        );

        let halted = halt_with(&mut |label| Ok(*label == agents_label()), &mut |_| {
            panic!("nothing is started")
        });
        assert_eq!(
            halted,
            Ok(Halted {
                client: false,
                agents: true
            })
        );
    }

    /// A deregistration of the Client that fails still removes the second service, and both
    /// errors are reported: no second service stays registered behind a Client that could not be
    /// (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn an_uninstall_removes_the_second_service_when_the_clients_fails() {
        struct Refusing;
        impl ServiceManager for Refusing {
            fn available(&self) -> std::io::Result<bool> {
                Ok(true)
            }
            fn install(&self, _ctx: ServiceInstallCtx) -> std::io::Result<()> {
                Ok(())
            }
            fn uninstall(&self, _ctx: ServiceUninstallCtx) -> std::io::Result<()> {
                Err(std::io::Error::other("marked for deletion"))
            }
            fn start(&self, _ctx: ServiceStartCtx) -> std::io::Result<()> {
                Ok(())
            }
            fn stop(&self, _ctx: service_manager::ServiceStopCtx) -> std::io::Result<()> {
                Ok(())
            }
            fn level(&self) -> SmLevel {
                SmLevel::System
            }
            fn set_level(&mut self, _level: SmLevel) -> std::io::Result<()> {
                Ok(())
            }
            fn status(&self, _ctx: ServiceStatusCtx) -> std::io::Result<ServiceStatus> {
                Ok(ServiceStatus::Running)
            }
        }
        let mut removed = 0;
        let both = uninstall_with(Ok(&Refusing), &mut || {
            removed += 1;
            Err("the second service did not stop".to_string())
        });
        assert_eq!(removed, 1, "the second service removed all the same");
        let both = both.expect_err("both failed");
        assert!(
            both.contains("marked for deletion") && both.contains("did not stop"),
            "{both}"
        );

        let mut removed = 0;
        let client = uninstall_with(Ok(&Refusing), &mut || {
            removed += 1;
            Ok(())
        });
        assert_eq!(removed, 1);
        assert!(client.is_err_and(|e| e.contains("marked for deletion")));

        let unreachable = "no service manager".to_string();
        let mut removed = 0;
        let _ = uninstall_with(Err(&unreachable), &mut || {
            removed += 1;
            Ok(())
        });
        assert_eq!(removed, 1, "and where the manager cannot be reached");
    }

    /// A stop for a deregistration tries both services whatever became of the other, and starts
    /// neither again: they are going (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn a_halt_for_removal_tries_both_and_restarts_none() {
        let mut tried = Vec::new();
        let failed = halt_for_removal_with(&mut |which| {
            tried.push(which.clone());
            if *which == label() {
                Err("the Client did not stop in time".to_string())
            } else {
                Ok(true)
            }
        });
        assert_eq!(tried, [label(), agents_label()], "both tried");
        assert_eq!(failed, Err("the Client did not stop in time".to_string()));
        assert_eq!(halt_for_removal_with(&mut |_| Ok(true)), Ok(()));
    }

    /// A resume passes over only a service that runs; it starts one that is stopped, and waits on
    /// one still starting or stopping until it has settled — starting it once it has stopped — or,
    /// where it does not settle in time, fails, so that what is to run again stays recorded
    /// (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn a_resume_passes_over_only_what_runs_and_waits_on_what_is_pending() {
        let both = [agents_label(), label()];
        let mut started = Vec::new();
        let mut asked = 0;
        resume_with(
            &both,
            &mut |label| {
                asked += 1;
                Ok(if *label == agents_label() {
                    Activity::Running
                } else if asked < 4 {
                    Activity::Stopping
                } else {
                    Activity::Stopped
                })
            },
            &mut |label| {
                started.push(label.clone());
                Ok(())
            },
            std::time::Duration::from_secs(5),
        )
        .expect("resumed");
        assert_eq!(started, [label()], "the running one passed over");
        assert!(asked >= 4, "the stopping one asked until it settled");

        let mut started = Vec::new();
        let pending = resume_with(
            &both,
            &mut |_| Ok(Activity::Starting),
            &mut |label| {
                started.push(label.clone());
                Ok(())
            },
            std::time::Duration::ZERO,
        );
        assert!(
            pending.is_err_and(|e| e.contains("still starting")),
            "one that does not settle fails"
        );
        assert!(started.is_empty());

        let mut started = Vec::new();
        resume_with(
            &both,
            &mut |_| Ok(Activity::Stopped),
            &mut |label| {
                started.push(label.clone());
                Ok(())
            },
            std::time::Duration::ZERO,
        )
        .expect("resumed");
        assert_eq!(started, both, "both stopped, both started, in order");
    }

    /// `start` starts the Client alone where its unit wants the second service, and the second
    /// service first where nothing does — launchd — and `stop` stops the Client and then the
    /// second service where one is registered — the second even when the Client's stop failed,
    /// which `stop` still reports (ADR-0059 clause 2).
    /// Verifies: ADR-0059
    #[test]
    fn start_starts_the_client_and_stop_stops_both() {
        let client = label().to_string();
        let agents = agents_label().to_string();
        assert_eq!(started(true, true), vec![label()], "systemd's Wants=");
        assert_eq!(
            started(true, false),
            vec![agents_label(), label()],
            "launchd"
        );
        assert_eq!(started(false, false), vec![label()]);
        let with_agents = recording(ServiceLevel::System, |_| true);
        with_agents.start().expect("start");
        let mut start = vec![format!("start {client}")];
        if !PULLED_IN {
            start.insert(0, format!("start {agents}"));
        }
        assert_eq!(Recording::asked(), start);
        let refused = with_agents.stop().expect_err("the Client's stop failed");
        assert!(refused.contains("cannot stop the service"), "{refused}");
        assert_eq!(
            Recording::asked(),
            vec![format!("stop {client}"), format!("stop {agents}")]
        );

        let alone = recording(ServiceLevel::System, |_| false);
        alone.start().expect("start");
        let _ = alone.stop();
        assert_eq!(
            Recording::asked(),
            vec![format!("start {client}"), format!("stop {client}")]
        );
    }

    /// The removal of a launchd job passes over a failed stop only where launchd holds no such
    /// job, and holds the removal done only once launchd holds it no more, waiting for that a
    /// while. `Recording` refuses to stop the Client's label, which stands for a job that cannot
    /// be stopped; the second service's it stops.
    /// Verifies: ADR-0059
    #[test]
    fn a_launchd_job_is_removed_only_once_launchd_holds_it_no_more() {
        let within = std::time::Duration::from_secs(5);
        let answers = |answers: Vec<bool>| {
            let mut answers = answers.into_iter();
            move || Ok(answers.next().expect("asked once more than expected"))
        };
        let client = label().to_string();
        let agents = agents_label().to_string();

        remove_launchd_job(
            &Recording,
            label(),
            &mut answers(vec![false, false]),
            within,
        )
        .expect("never loaded: nothing to stop");
        assert_eq!(
            Recording::asked(),
            vec![format!("stop {client}"), format!("uninstall {client}")]
        );

        let refused = remove_launchd_job(&Recording, label(), &mut answers(vec![true]), within)
            .expect_err("loaded, and not stopped");
        assert!(
            refused.contains("cannot stop the second service"),
            "{refused}"
        );
        assert_eq!(Recording::asked(), vec![format!("stop {client}")]);

        remove_launchd_job(
            &Recording,
            agents_label(),
            &mut answers(vec![true, false]),
            within,
        )
        .expect("gone after a while");
        assert_eq!(
            Recording::asked(),
            vec![format!("stop {agents}"), format!("uninstall {agents}")]
        );

        let held = remove_launchd_job(
            &Recording,
            agents_label(),
            &mut || Ok(true),
            std::time::Duration::ZERO,
        )
        .expect_err("launchd holds it still");
        assert!(
            held.contains("launchd still holds opamp-fleet-agents"),
            "{held}"
        );
        let _ = Recording::asked();

        let unasked = remove_launchd_job(
            &Recording,
            label(),
            &mut || Err("cannot run launchctl".to_string()),
            within,
        )
        .expect_err("launchd cannot be asked");
        assert_eq!(unasked, "cannot run launchctl");
        let _ = Recording::asked();
    }

    /// No root is the socket's directory or lies in it: named as it is, by a path through a link,
    /// or beneath it. A root beside it, or one it lies in, is the operator's choice.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn no_root_is_the_sockets_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_dir = dir.path().join("opamp-fleet-agents");
        let socket = socket_dir.join("agents.sock");
        let beside = dir.path().join("opamp-fleet");
        let inside = socket_dir.join("data");
        for root in [
            &socket_dir,
            &inside,
            &dir.path().join("opamp-fleet-agents/"),
        ] {
            let refused =
                check_roots_apart(&[&beside, root], &socket).expect_err("not yet there, by name");
            assert!(refused.contains("the second service's socket"), "{refused}");
        }
        check_roots_apart(&[&beside, dir.path()], &socket).expect("beside it, or above it");

        std::fs::create_dir(&socket_dir).expect("mkdir");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&socket_dir, &link).expect("a link");
        check_roots_apart(&[&link], &socket).expect_err("the same directory by another path");
        check_roots_apart(&[&link.join("data")], &socket).expect_err("in it by another path");
        check_roots_apart(&[&beside], &socket).expect("beside it");
        #[cfg(target_os = "macos")]
        check_roots_apart(&[&dir.path().join("OPAMP-fleet-agents")], &socket)
            .expect_err("another case of its letters");
    }

    /// The socket's directory goes with the second service: the socket first — a link at its
    /// name as a link — then the directory; one the process account left anything else in stays,
    /// and is named.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_sockets_directory_goes_with_the_second_service() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_dir = dir.path().join("opamp-fleet-agents");
        let socket = socket_dir.join("agents.sock");
        std::fs::create_dir(&socket_dir).expect("mkdir");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        remove_socket_dir(&socket).expect("removed");
        assert!(!socket_dir.exists());
        drop(listener);
        remove_socket_dir(&socket).expect("nothing left to remove");

        std::fs::create_dir(&socket_dir).expect("mkdir");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"x").expect("write");
        std::os::unix::fs::symlink(&elsewhere, &socket).expect("a link");
        std::fs::write(socket_dir.join("left"), b"x").expect("write");
        let left = remove_socket_dir(&socket).expect_err("something else is there");
        assert!(left.contains(&socket_dir.display().to_string()), "{left}");
        assert!(
            !socket.exists() && elsewhere.exists(),
            "the link alone is gone"
        );
    }

    /// The socket's directory is made and removed only in a parent no other account can write: in
    /// one writable by others, where another account could swap the directory or put a link at
    /// its name, neither is done.
    /// Verifies: ADR-0054, ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_sockets_directory_is_touched_only_in_a_parent_no_other_account_writes() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let open = dir.path().join("open");
        std::fs::create_dir(&open).expect("mkdir");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let socket_dir_path = open.join("opamp-fleet-agents");
        // SAFETY: geteuid(2) and getegid(2) cannot fail and touch no memory.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        assert!(socket_dir(&socket_dir_path, uid, gid).is_err());
        assert!(!socket_dir_path.exists(), "nothing made");

        std::fs::create_dir(&socket_dir_path).expect("mkdir");
        let left = remove_socket_dir(&socket_dir_path.join("agents.sock")).expect_err("refused");
        assert!(left.contains("agents.sock"), "{left}");
        assert!(socket_dir_path.exists(), "nothing removed");
    }

    /// Where a process account is registered, the Client's unit wants the second service and starts
    /// after it, and its command line names the socket and the process account's uid; the CLI
    /// takes both lines as written.
    /// Not on Windows, for the reason the second service's own unit is not.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_clients_unit_names_the_second_service() {
        let unit = systemd_unit(&with_agents(), "opamp-fleet").expect("unit");
        let header = &unit[..unit.find("[Service]").expect("service section")];
        assert!(
            header
                .lines()
                .any(|l| l == "Wants=opamp-fleet-agents.service"),
            "{unit}"
        );
        assert!(
            header
                .lines()
                .any(|l| l == "After=opamp-fleet-agents.service"),
            "{unit}"
        );
        assert!(
            unit.contains(
                "\"--agents-socket\" \"/run/opamp-fleet-agents/agents.sock\" \"--process-uid\" \
                 \"997\""
            ),
            "{unit}"
        );
        let plain = systemd_unit(&system_spec("/opt/opamp-fleet"), "opamp-fleet").expect("unit");
        assert!(!plain.contains("agents"), "{plain}");

        let words = |args: Vec<OsString>| {
            std::iter::once(OsString::from("supervisor"))
                .chain(args)
                .collect::<Vec<_>>()
        };
        let client = crate::cli::parse_from(words(service_args(&with_agents())))
            .expect("the Client's line parses");
        let Some(crate::cli::Command::Run(run)) = client.cli.command else {
            panic!("run");
        };
        assert_eq!(run.agents_socket, Some(agents().socket));
        assert_eq!(run.process_uid, Some(997));
        let second = crate::cli::parse_from(words(agents_args(&agents())))
            .expect("the second service's line parses");
        let Some(crate::cli::Command::Run(run)) = second.cli.command else {
            panic!("run");
        };
        assert_eq!(run.agents, Some(agents().socket));
        assert_eq!(run.client_uid, Some(998));
    }

    /// A re-registration reads the account from the unit the Client wrote: the last `User=` in
    /// `[Service]`, as systemd reads it.
    /// Verifies: ADR-0042
    #[test]
    fn the_units_account_is_its_last_service_user() {
        let unit = "[Unit]\nDescription=opamp-fleet\n\n[Service]\nExecStart=/x\nUser=telegraf\n\
                    \n[Install]\nWantedBy=multi-user.target\n";
        assert_eq!(unit_account(unit).as_deref(), Some("telegraf"));
        assert_eq!(
            unit_account("[Service]\nUser=a\nUser=b\n").as_deref(),
            Some("b")
        );
        assert_eq!(unit_account("[Service]\nUser=a\nUser=\n"), None);
        assert_eq!(
            unit_account("[Unit]\nUser=a\n[Service]\nExecStart=/x\n"),
            None
        );
        assert_eq!(
            unit_account(&systemd_unit(&system_spec("/opt/opamp-fleet"), "root").expect("unit"))
                .as_deref(),
            Some("root"),
            "what the Client writes, it reads back"
        );
    }

    /// The plist's `UserName`, in the XML `service-manager` writes.
    /// Verifies: ADR-0042
    #[test]
    fn a_plists_user_name_is_kept() {
        let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \
                     \"-//Apple//DTD PLIST 1.0//EN\" \
                     \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist \
                     version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>opamp-fleet</string>\
                     \n\t<key>UserName</key>\n\t<string>_opamp&amp;fleet</string>\n</dict>\n\
                     </plist>";
        assert_eq!(plist_account(plist).as_deref(), Some("_opamp&fleet"));
        assert_eq!(
            plist_account("<dict><key>Label</key><string>x</string></dict>"),
            None
        );
    }

    /// The state directory a systemd unit carries is read back from `ExecStart=` exactly as
    /// [`systemd_unit`] wrote it, whatever characters its path holds — and from an unquoted line as
    /// `service-manager`'s own rendering writes one.
    /// Verifies: ADR-0053
    #[test]
    fn a_units_state_directory_is_read_back_from_its_exec_start() {
        let mut spec = system_spec("/opt/opamp-fleet");
        spec.state_dir = PathBuf::from("/srv/fleet state/100%\"$HOME\"\\\u{7}é");
        let unit = systemd_unit(&spec, "opamp-fleet").expect("unit");
        let words: Vec<PathBuf> = unit_arguments(&unit).iter().map(PathBuf::from).collect();
        assert_eq!(words.last(), Some(&spec.state_dir));
        assert_eq!(words[words.len() - 2], PathBuf::from("--state-dir"));

        let rendered = "[Unit]\nDescription=x\n\n[Service]\nExecStart=/opt/x/current/supervisor \
                        run --service --config /var/lib/x/supervisor.toml --state-dir \
                        /var/lib/x/state\nRestart=on-failure\n";
        assert_eq!(
            unit_arguments(rendered)[3..],
            [
                "--config",
                "/var/lib/x/supervisor.toml",
                "--state-dir",
                "/var/lib/x/state"
            ]
        );
    }

    /// The registered state directory is the absolute path after `--state-dir`; a registration
    /// naming none, or a relative one, offers none.
    /// Verifies: ADR-0053
    #[test]
    fn only_an_absolute_state_dir_after_the_flag_is_registered() {
        let absolute = std::env::temp_dir().join("state");
        let words = |rest: &[&str]| -> Vec<String> {
            ["supervisor", "run"]
                .iter()
                .chain(rest)
                .map(ToString::to_string)
                .collect()
        };
        assert_eq!(
            state_dir_of(words(&["--state-dir", absolute.to_str().expect("utf-8")])),
            Some(absolute.clone())
        );
        assert_eq!(state_dir_of(words(&["--service"])), None);
        assert_eq!(state_dir_of(words(&["--state-dir"])), None);
        assert_eq!(state_dir_of(words(&["--state-dir", "state"])), None);
    }

    /// The state directory a launchd plist carries is read from its `ProgramArguments`, in the
    /// XML `service-manager` writes.
    /// Verifies: ADR-0053
    #[test]
    fn a_plists_state_directory_is_read_from_its_program_arguments() {
        let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\
                     \n\t<key>Label</key>\n\t<string>opamp-fleet</string>\n\t\
                     <key>ProgramArguments</key>\n\t<array>\n\t\t<string>/Library/Application \
                     Support/opamp-fleet/current/supervisor</string>\n\t\t<string>run</string>\
                     \n\t\t<string>--service</string>\n\t\t<string>--config</string>\n\t\t\
                     <string>/x/supervisor.toml</string>\n\t\t<string>--state-dir</string>\n\t\t\
                     <string>/Volumes/Fleet &amp; Co/state</string>\n\t</array>\n\t\
                     <key>UserName</key>\n\t<string>--state-dir</string>\n</dict>\n</plist>";
        assert_eq!(
            plist_arguments(plist)[3..],
            [
                "--config",
                "/x/supervisor.toml",
                "--state-dir",
                "/Volumes/Fleet & Co/state"
            ]
        );
        assert!(plist_arguments("<dict></dict>").is_empty());
    }

    /// A registration on disk is read back to the state directory the Client wrote into it, and a
    /// host with no registration offers none.
    /// Verifies: ADR-0053
    #[cfg(unix)]
    #[test]
    fn a_registration_on_disk_offers_the_state_directory_it_was_written_with() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("opamp-fleet.service");
        let mut spec = system_spec("/opt/opamp-fleet");
        spec.state_dir = PathBuf::from("/srv/fleet/state");
        std::fs::write(&file, systemd_unit(&spec, "opamp-fleet").expect("unit")).expect("write");
        assert_eq!(
            read_state_dir(&file, unit_arguments).expect("read"),
            Some(spec.state_dir)
        );
        assert_eq!(
            read_state_dir(&dir.path().join("absent.service"), unit_arguments).expect("read"),
            None
        );
    }

    /// The state directory the SCM's binary path name carries is read with the C runtime's
    /// splitting rules, by which `service-manager` quotes it: a path with spaces, a trailing
    /// backslash and an embedded quote come back as written.
    /// Verifies: ADR-0053
    #[test]
    fn a_windows_command_lines_state_directory_is_split_as_the_runtime_splits_it() {
        let line = r#"C:\ProgramData\opamp-fleet\current\supervisor.exe run --service --config "C:\Program Files\x\supervisor.toml" --state-dir "D:\fleet state\\""#;
        assert_eq!(
            command_line_arguments(line),
            [
                r"C:\ProgramData\opamp-fleet\current\supervisor.exe",
                "run",
                "--service",
                "--config",
                r"C:\Program Files\x\supervisor.toml",
                "--state-dir",
                r"D:\fleet state\",
            ]
        );
        assert_eq!(
            command_line_arguments(r#"a "b\"c" d\\e"#),
            ["a", "b\"c", r"d\\e"]
        );
    }

    /// One level under the platform's base, named after the product — no `client` level asserting
    /// a name the file contradicts, and no level holding the constant `default` (ADR-0019).
    /// Verifies: ADR-0019
    #[cfg(target_os = "linux")]
    #[test]
    fn the_default_root_is_one_level_named_after_the_product() {
        let root = default_root(ServiceLevel::System).expect("system root");
        assert_eq!(root, PathBuf::from("/var/lib/opamp-fleet"));
        let user = default_root(ServiceLevel::User).expect("user root");
        assert!(user.ends_with("opamp-fleet"));
        assert!(
            !root.to_string_lossy().contains("/client/"),
            "the component level is gone"
        );
        assert!(
            !root.to_string_lossy().contains("default"),
            "the instance level is gone"
        );
    }

    /// ADR-0019 clause 8: a system service's binary must not live under
    /// `/var/lib` — SELinux's `var_lib_t` is no entrypoint type, and the service would fail its
    /// first start with `status=203/EXEC` on every enforcing host. The executable layout defaults
    /// to `/opt`; the data root stays under `/var/lib`, so an upgrade re-registers and moves no
    /// state. User scope has no such constraint and keeps one root for both.
    /// Verifies: ADR-0019
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_system_layout_executes_from_opt() {
        let layout = default_layout_root(ServiceLevel::System).expect("layout root");
        assert_eq!(layout, PathBuf::from("/opt/opamp-fleet"));
        assert_ne!(
            layout,
            default_root(ServiceLevel::System).expect("data root"),
            "the split is the fix: data stays in /var/lib, the binary executes from /opt"
        );
        assert_eq!(
            default_layout_root(ServiceLevel::User).expect("user layout"),
            default_root(ServiceLevel::User).expect("user data"),
            "a user service runs in the user's own domain — one root for both"
        );
    }

    /// Linux at system scope is the *only* split (ADR-0019 clause 8). Windows keeps one root
    /// however it was installed, because a layout the daemon rewrites cannot live in the tree the
    /// installer owns — see clause 12 and the `--run-as` hand-over.
    /// Verifies: ADR-0019
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn no_other_platform_splits() {
        for level in [ServiceLevel::System, ServiceLevel::User] {
            assert_eq!(
                default_layout_root(level).expect("layout root"),
                default_root(level).expect("data root"),
            );
        }
    }
}
