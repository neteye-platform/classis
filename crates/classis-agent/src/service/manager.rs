//! Cross-platform service lifecycle over the `service-manager` crate.
//!
//! `service-manager` targets the platform's native manager (systemd, Windows SCM) behind one
//! API. This module wraps it in the project's vocabulary. There is **one service per build**
//!: it is named after the product, takes no suffix, and nothing has to be looked up to
//! address it. Where a process account is registered, a second service, `<PRODUCT_NAME>-agents`,
//! runs beside it under that account, and every verb acts on both. The installed
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

/// Restart after a failure, never after a clean stop — with a delay so a Client that
/// fails at startup does not spin, and no retry limit so a host recovers however long it takes.
const RESTART_POLICY: RestartPolicy = RestartPolicy::OnFailure {
    delay_secs: Some(RESTART_DELAY_SECS),
    max_retries: None,
    reset_after_secs: None,
};

/// Read by [`windows_config`](super::windows_config) so both platforms wait the same before a
/// restart — and by the service smoke test, which has to outwait it before it may conclude that a
/// killed service is not coming back (visibility is widened by need).
pub const RESTART_DELAY_SECS: u32 = 5;

/// The name the service is registered under — the same on every platform, and the
/// **product's** name rather than the program's.
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

/// The name of the second service, which starts the Managed Processes under the process account:
/// the product's, with the suffix `-agents`.
#[must_use]
pub fn agents_service_name() -> String {
    format!("{PRODUCT_NAME}-agents")
}

/// The second service's socket, in a directory named after it that only the process account
/// writes and its group reaches. On Windows its named pipe,
/// `\\.\pipe\<PRODUCT_NAME>-agents`, whose own security descriptor admits the Client's account
/// alone.
///
/// Under systemd that is the runtime directory systemd creates for it at every start
/// (`RuntimeDirectory=`) and removes when it stops.
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
/// directory is the process account's, and a root there would be handed to
/// it, or to the Client beneath what the process account may replace. Named the same, or by
/// another path to the same directory.
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
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
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

#[cfg(unix)]
fn agents_socket_dir() -> PathBuf {
    PathBuf::from("/run").join(agents_service_name())
}

/// How long systemd waits for the second service to stop before it kills it (`TimeoutStopSec=`):
/// longer than the service's own grace for its programs and the drain of their output after it,
/// so a stop ends them through the service rather than through the manager.
pub const AGENTS_STOP_TIMEOUT_SECS: u32 = 30;

/// The name a human reads where the platform has somewhere to put one: the Windows
/// services list. systemd shows the unit name as its `Description`, and has no second name to
/// give.
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
/// the unit name as its `Description`.
pub const WINDOWS_DESCRIPTION: &str =
    "Places this machine under OpAMP management: connects to a Server, supervises the Agents \
     configured for this host, and updates them and itself from packages the Server offers.";

/// The second service's name in the Windows services list.
#[must_use]
pub fn agents_display_name() -> String {
    format!("{PRODUCT_TITLE} Managed Processes")
}

/// What the Windows services list says the second service does.
pub const AGENTS_WINDOWS_DESCRIPTION: &str =
    "Starts, stops and watches the Agents' programs under their own account, on the request of \
     the Classis Client, which reaches it on a named pipe of its own.";

/// The service label, built so that **every backend renders it identically**.
///
/// `service-manager` renders a label through two functions that do not agree — `{organization}-`
/// `{application}` for systemd, `{qualifier}.{organization}.{application}` for the SCM — so any
/// label with more than one part has two spellings in the field. With no qualifier
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
    /// Absolute path of the TOML configuration file the unit carries. The unit holds
    /// the *path*, never the configuration itself — one source of truth.
    pub config_path: PathBuf,
    /// Absolute state directory baked into the unit (a service's working directory is `/` or
    /// `System32`; relative paths would be meaningless).
    pub state_dir: PathBuf,
    /// The account the service runs as — already resolved by
    /// [`run_as`](super::run_as), so what arrives here exists and needs no password. On Linux a
    /// system registration always names one, `root` included; on Windows `None` leaves the logon
    /// account the SCM holds, `LocalSystem` on a first registration.
    pub run_as: Option<String>,
    /// The second service, where a process account is registered; already decided and
    /// checked by [`run_as`](super::run_as).
    pub agents: Option<Agents>,
}

/// The second service a registration names.
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
/// rather than a migration: the program path and the rest of the unit are
/// rewritten from the version that registers, and the configuration, identity and state stay
/// where they are.
///
/// Where a process account is registered, the line also names the second service's socket and the
/// process account's uid: that is how the running Client learns that it starts every Managed
/// Process through the second service, and whom to accept as its peer.
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

/// The second service's command line: `run --agents <socket> --client-uid <uid>`, on Windows `run
/// --agents <pipe> --client-sid <SID>`. It reads neither the
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
/// that makes the restart-on-failure real on every platform. On Windows that is a second
/// step against the SCM, because `service-manager` silently drops the policy there; on systemd the
/// unit has already written it.
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
    // What `service-manager` does not do on Windows, done here (see `windows_config`) — that
    // includes the logon account, which its `sc.exe` backend ignores.
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
            // The systemd system unit is the Client's own text; the user
            // scope and every other manager keep the crate's rendering.
            contents,
            // The systemd system unit carries `User=` itself. The Windows
            // backend ignores this field, which is why `install` sets the logon account through
            // `windows_config`.
            username: spec.run_as.clone(),
            working_directory: None,
            // The Client is file-configured: the unit carries the config path in the
            // arguments above, never settings as environment variables.
            environment: None,
            autostart: true,
            // Restart only on a crash, never after an explicit stop — what lets a future updater
            // stop the service, switch `current`, and start it without the manager racing it.
            //
            // Honoured natively on systemd (`Restart=on-failure`). The Windows backend of
            // `service-manager` *discards* this and only logs a warning, which is why
            // `windows_config` exists.
            restart_policy: RESTART_POLICY,
        },
    )
    .map_err(|e| format!("cannot install the service (system scope needs root/Administrator): {e}"))
}

/// Registers `ctx` with the service manager. On Windows a service the SCM holds already is
/// reconfigured in place, as `sc create` refuses one that exists: its program, arguments and start
/// type are rewritten and its logon account kept, and what `windows_config` sets follows as on a
/// first registration. A re-registration — an upgrade among them — so keeps the second service
/// and the process account it runs under.
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

/// Registers the second service, which only a host where [`agents_supported`]
/// holds gets. The registration first, so an install that may not register a system service is
/// told so before anything else. On Windows what `service-manager` leaves undone follows, as for
/// the Client: the recovery actions, the display name, the description and the logon account —
/// and the required privileges, cut to `SeChangeNotifyPrivilege`
/// ([`windows_config::configure_agents`](super::windows_config)).
///
/// The Client's service is not made to depend on it (`sc config depend=`): the SCM starts no
/// service whose dependency failed to start, and stops none a running one depends on, so a second
/// service that does not come up would hold the Client down with it (StartService,
/// `ERROR_SERVICE_DEPENDENCY_FAIL`), where the Client runs without it. The
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
    )
}

/// What `service-manager` is asked to register for the second service. Under systemd
/// (`own_unit`) a system unit of the Client's own text; under the SCM what the
/// crate renders, the rest set by [`windows_config::configure_agents`](super::windows_config).
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

/// Whether this host can register the second service: a system service under systemd
/// on Linux, or under the SCM on Windows.
#[must_use]
pub fn agents_supported(level: ServiceLevel) -> bool {
    let native = ServiceManagerKind::native();
    level == ServiceLevel::System
        && ((cfg!(target_os = "linux") && matches!(native, Ok(ServiceManagerKind::Systemd)))
            || (cfg!(windows) && matches!(native, Ok(ServiceManagerKind::Sc))))
}

/// What `service-manager` is handed as the unit's text: the Client's own systemd **system** unit
/// where systemd is the native manager, and nothing — the crate's own
/// rendering — for the user scope and every other manager.
fn unit_contents(spec: &InstallSpec, systemd: bool) -> Result<Option<String>, String> {
    if !systemd || spec.level != ServiceLevel::System {
        return Ok(None);
    }
    systemd_unit(spec, spec.run_as.as_deref().unwrap_or(ROOT)).map(Some)
}

/// The account that is root, and that decides the unit's directive tier.
const ROOT: &str = "root";

/// What every system unit carries: `/sys/fs/cgroup` becomes read-only. It does
/// not imply `NoNewPrivileges=`, and no supported agent writes the cgroup tree itself.
const EVERY_SYSTEM_UNIT: &[&str] = &["ProtectControlGroups=yes"];

/// What a unit that runs as root carries on top. Root holds `CAP_SYS_ADMIN`,
/// so none of these implies `no_new_privs` there; under any other account each one would, and
/// `sudo` and every setuid helper a Managed Process uses would stop working.
const ROOT_UNIT: &[&str] = &[
    "ProtectKernelTunables=yes",
    "LockPersonality=yes",
    "RestrictRealtime=yes",
];

/// The systemd system unit the Client registers for `account`.
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
    // The second service is started first: `After=` orders both, and `Wants=`
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

/// The second service's systemd system unit: the same program as the Client's,
/// under the process account, with the directives every system unit carries.
///
/// `RuntimeDirectory=` is where its socket lives: systemd creates it for the process account at
/// every start, `0750`, so only that account and its group — the Client's account is in it
/// — reach the socket, and removes it at the stop. `TimeoutStopSec=` outlasts
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
    // Never root, so never the root tier.
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
            "the account {account:?} cannot be written into a systemd unit"
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
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The systemd unit.
    pub file: PathBuf,
    /// Its `User=`; `None` where it names none.
    pub account: Option<String>,
}

/// The registration a re-registration finds: the file the Client wrote —
/// `/etc/systemd/system/<PRODUCT_NAME>.service` — never a drop-in and never the loaded state of
/// the service manager. `None` at user scope, where
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

/// The second service's registration as the Client wrote it:
/// `/etc/systemd/system/<PRODUCT_NAME>-agents.service` and the account its `User=` names, read as
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
    #[cfg(windows)]
    super::windows_config::logon_account(&agents_service_name())
}

/// The file the second service's registration is: its unit.
#[cfg(target_os = "linux")]
fn agents_file() -> PathBuf {
    service_manager::systemd_global_dir_path().join(format!("{}.service", agents_service_name()))
}

/// Whether a second service is registered at `level`.
fn agents_registered(level: ServiceLevel) -> bool {
    #[cfg(target_os = "linux")]
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

/// The state directory the system registration of this service carries: the
/// value after `--state-dir` in the command line the Client wrote — `ExecStart=` of the systemd
/// unit, the binary path name the SCM holds. Read from
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
/// The second service last, as it is stopped last, and stopped first: a
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

/// Stops and deregisters the second service, where one is registered (`--no-process-account`).
/// Returns whether there was one.
///
/// # Errors
/// Returns an error if the manager cannot stop or uninstall it.
pub fn remove_agents(level: ServiceLevel) -> Result<bool, String> {
    if !agents_registered(level) {
        return Ok(false);
    }
    let manager = manager(level)?;
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
/// has ended — the second service's programs with it — so that nothing runs
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
/// install is about to re-own. Returns which ran: what systemd reports
/// active or activating.
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
            if now == Activity::Stopped {
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

/// Whether an install changes an account a service runs under: the
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

/// The process `systemctl show --property=MainPID --value` names: none where it says `0`.
#[cfg(any(target_os = "linux", test))]
fn systemd_main_pid(show: &str) -> Option<u32> {
    show.trim().parse::<u32>().ok().filter(|pid| *pid != 0)
}

/// The process the service manager runs as the second service: systemd the
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

/// The process the service manager runs as the second service: the SCM the
/// service's process id (`QueryServiceStatusEx`). `None` where it runs none.
///
/// # Errors
/// Returns why the SCM could not be asked.
#[cfg(windows)]
pub fn agents_process() -> Result<Option<u32>, String> {
    super::windows_config::service_process(&agents_service_name())
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

/// Stops `label` for a change and waits until it has stopped, up to [`STOPPING`]. systemd's stop
/// is queued and waited out.
///
/// # Errors
/// Returns why the stop could not be asked for, or that the service had not stopped in time.
#[cfg(unix)]
fn stop_for_change(label: &ServiceLabel) -> Result<(), String> {
    use std::process::Stdio;
    let name = label.to_qualified_name();
    let unit = format!("{name}.service");
    let args = ["stop", "--no-block", &unit];
    let stopped = || activity(label).map(|now| now == Activity::Stopped);
    let status = std::process::Command::new("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if !status.success() && !stopped()? {
        return Err(format!(
            "cannot stop {name}: `systemctl {}` failed",
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

/// Starts `label` again after a stop for a change, through the manager.
///
/// # Errors
/// Returns why it could not be started.
#[cfg(unix)]
fn start_for_change(level: ServiceLevel, label: &ServiceLabel) -> Result<(), String> {
    manager(level)?
        .start(ServiceStartCtx {
            label: label.clone(),
        })
        .map_err(|e| format!("cannot start {label}: {e}"))
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
    /// stopped service stops nothing — systemd.
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
/// Client's unit does; the SCM entry names no dependency.
const PULLED_IN: bool = cfg!(target_os = "linux");

/// What `start` starts, in order. Where a second service is registered and the Client's unit wants
/// it (`Wants=`, `pulled_in`), the Client alone: the manager starts the second service with it.
/// Where nothing pulls it in — the SCM — the second service first, then the Client. Neither waits for the other: a Client that starts first reaches the second service
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
/// `Wants=` pulls it in on a start but takes it down on no stop.
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
/// state directory live.
///
/// One level named after the product, and no level below it: a second installation is a second
/// build, so there is nothing for a deeper level to distinguish. `--data-root`
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
/// **Linux at system scope is the only place this differs from the data root**.
/// A binary staged under `/var/lib` carries the SELinux type `var_lib_t`,
/// which systemd may never execute: the service would register cleanly and then die at its first
/// start with `status=203/EXEC` on every enforcing host (Fedora, RHEL, SUSE 16). The layout
/// therefore lives under `/opt`, whose `usr_t` label is an entrypoint type systemd runs
/// third-party services from, and which every version the self-update stages later inherits.
///
/// Everywhere else — Windows, and every user scope — layout and data share
/// [`default_root`]. Windows does not split even under the MSI: `Program Files` holds the
/// installer's payload and nothing the daemon rewrites, because the self-update means the
/// service's own account must be able to write `versions/` and `current`.
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

/// `<base>/<PRODUCT_NAME>` — one level, named after the product.
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

    /// The whole mechanism of the service name: a label with no qualifier and no organization renders the
    /// same through *both* of the crate's functions, so systemd and the SCM show one name. A dot
    /// anywhere in it would split the label again and undo that.
    #[test]
    fn every_backend_renders_the_same_name() {
        let label = label();
        assert_eq!(label.to_qualified_name(), PRODUCT_NAME, "the SCM");
        assert_eq!(label.to_script_name(), PRODUCT_NAME, "systemd");
        assert!(
            !PRODUCT_NAME.contains('.'),
            "a dot would split the label again"
        );
    }

    /// The service carries the **product's** name and the program carries its own. They are
    /// separate constants holding different strings, and the day someone
    /// derives one from the other, one published package Set stops serving every variant.
    #[test]
    fn the_service_is_named_after_the_product_not_the_program() {
        assert_eq!(service_name(), PRODUCT_NAME);
        assert_eq!(service_name(), "classis");
        assert_eq!(layout::COMPONENT, "supervisor");
        assert_ne!(
            service_name(),
            layout::COMPONENT,
            "the product names the installation, the program names the file"
        );
    }

    /// No suffix, on any platform: one build installs one service, so there is no second one to
    /// tell apart and nothing for a verb to look up.
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
    /// other, because no rule that produces `Classis Agent` from `classis` would still
    /// read correctly for the next variant build.
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

    #[test]
    fn the_installed_command_line_is_the_marker_plus_absolute_paths() {
        let spec = InstallSpec {
            level: ServiceLevel::System,
            program: PathBuf::from("/opt/classis/current/supervisor"),
            config_path: PathBuf::from("/var/lib/classis/supervisor.toml"),
            state_dir: PathBuf::from("/var/lib/classis/state"),
            run_as: Some("classis".to_string()),
            agents: None,
        };
        let args = service_args(&spec);
        assert!(
            !args.contains(&OsString::from("classis")),
            "the account decides who runs the command, it is never part of it"
        );
        assert!(
            !args.contains(&OsString::from("--instance")),
            "the flag is removed, not hidden"
        );
        assert_eq!(args[0], OsString::from("run"));
        assert_eq!(args[1], OsString::from("--service"));
        assert!(args.contains(&OsString::from("/var/lib/classis/supervisor.toml")));
        assert!(args.contains(&OsString::from("/var/lib/classis/state")));
    }

    /// The Windows recovery actions are configured separately from the policy handed to
    /// `service-manager` (see `windows_config`), so the two could drift into disagreeing about
    /// how long a failed Client waits before it comes back. They read one constant; this is what
    /// says so.
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
            other => panic!("the Client restarts only on failure, got {other:?}"),
        }
        // The systemd system unit is the Client's own text now, so its
        // restart delay is a third place that reads the constant.
        let unit = systemd_unit(&system_spec("/opt/classis"), "classis").expect("unit");
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
            config_path: PathBuf::from("/var/lib/classis/supervisor.toml"),
            state_dir: PathBuf::from("/var/lib/classis/state"),
            run_as: Some("classis".to_string()),
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
    #[test]
    fn the_system_unit_is_the_clients_own_text() {
        let unit = systemd_unit(&system_spec("/opt/classis"), "classis").expect("unit");
        let lines: Vec<&str> = unit.lines().collect();
        assert_eq!(lines[0], "[Unit]");
        assert!(lines.contains(&"Description=classis"), "{unit}");
        assert!(lines.contains(&"[Service]"), "{unit}");
        assert!(
            lines.contains(
                &"ExecStart=\"/opt/classis/current/supervisor\" \"run\" \"--service\" \
                  \"--config\" \"/var/lib/classis/supervisor.toml\" \"--state-dir\" \
                  \"/var/lib/classis/state\""
            ),
            "{unit}"
        );
        assert!(lines.contains(&"Restart=on-failure"), "{unit}");
        assert!(lines.contains(&"RestartSec=5"), "{unit}");
        assert!(lines.contains(&"User=classis"), "{unit}");
        assert!(lines.contains(&"[Install]"), "{unit}");
        assert!(lines.contains(&"WantedBy=multi-user.target"), "{unit}");
        let service = unit.find("[Service]").expect("service section");
        let install = unit.find("[Install]").expect("install section");
        assert!(service < unit.find("ExecStart=").expect("exec") && install > service);
    }

    /// systemd splits `ExecStart=` at spaces and expands `%` and `$`, so a root holding any of them
    /// named the wrong program or the wrong file. Quoted and escaped, it reaches the program as it
    /// was given.
    #[test]
    fn exec_start_survives_spaces_percent_and_dollar() {
        let unit = systemd_unit(&system_spec("/srv/my fleet/100%/$HOME"), "classis").expect("unit");
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
    #[test]
    fn an_account_unit_sets_nothing_that_implies_no_new_privs() {
        let unit = systemd_unit(&system_spec("/opt/classis"), "classis").expect("unit");
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
    #[test]
    fn a_root_unit_carries_the_root_tier() {
        let unit = systemd_unit(&system_spec("/opt/classis"), "root").expect("unit");
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
    #[test]
    fn no_unit_carries_what_breaks_a_supported_agent() {
        for account in ["root", "classis"] {
            let unit = systemd_unit(&system_spec("/opt/classis"), account).expect("unit");
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
            systemd_unit(&system_spec("/opt/classis"), "evil\nExecStartPre=/bin/sh").is_err(),
            "an account name cannot add a directive"
        );
    }

    /// The Client writes the systemd **system** unit only; the user scope and every other manager
    /// keep `service-manager`'s rendering.
    #[test]
    fn a_user_unit_is_left_to_service_manager() {
        let mut spec = system_spec("/opt/classis");
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
            account: "classis-agents".to_string(),
            uid: 997,
            gid: 997,
            client_uid: 998,
            socket: PathBuf::from("/run/classis-agents/agents.sock"),
        }
    }

    #[cfg(windows)]
    fn agents() -> Agents {
        Agents {
            account: r"NT SERVICE\classis-agents".to_string(),
            sid: crate::win32::Sid::parse("S-1-5-80-1-2-3-4-5").expect("sid"),
            client_sid: crate::win32::Sid::parse("S-1-5-80-6-7-8-9-10").expect("sid"),
            socket: agents_socket(),
        }
    }

    #[cfg(unix)]
    fn with_agents() -> InstallSpec {
        InstallSpec {
            agents: Some(agents()),
            ..system_spec("/opt/classis")
        }
    }

    /// The second service is the product's name with `-agents`, one token that every backend
    /// renders alike, and its socket lives in a directory named after it: the runtime directory
    /// under systemd.
    #[test]
    fn the_second_service_is_named_after_the_product() {
        assert_eq!(agents_service_name(), format!("{PRODUCT_NAME}-agents"));
        let label = agents_label();
        assert_eq!(label.to_qualified_name(), agents_service_name());
        assert_eq!(label.to_script_name(), agents_service_name());
        #[cfg(target_os = "linux")]
        assert_eq!(
            agents_socket(),
            PathBuf::from("/run/classis-agents/agents.sock")
        );
    }

    /// Under systemd the second service's registration is the unit the Client writes, handed to
    /// `service-manager` as its text.
    #[cfg(unix)]
    #[test]
    fn the_second_services_registration_is_the_unit_the_client_writes() {
        let ctx = agents_install_ctx(&with_agents(), &agents(), true).expect("ctx");
        assert_eq!(
            ctx.contents,
            Some(agents_unit(&with_agents(), &agents()).expect("unit"))
        );
    }

    /// On Windows the second service is the SCM's `<PRODUCT_NAME>-agents` on the pipe
    /// `\\.\pipe\<PRODUCT_NAME>-agents`: its command line names the pipe and the SID of the
    /// Client's account it serves, the Client's names the pipe and the process account's SID, and
    /// both are registered through the same `service-manager` call as on the other platforms,
    /// the logon account set afterwards.
    #[cfg(windows)]
    #[test]
    fn on_windows_both_command_lines_name_the_pipe_and_a_sid() {
        assert_eq!(
            agents_socket(),
            PathBuf::from(format!(r"\\.\pipe\{PRODUCT_NAME}-agents"))
        );
        let spec = InstallSpec {
            agents: Some(agents()),
            ..system_spec(r"C:\ProgramData\classis")
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

    /// The Client's command line names the socket and the process account's uid where a process
    /// account is registered.
    #[cfg(unix)]
    #[test]
    fn the_clients_command_line_names_the_second_service() {
        let args = service_args(&with_agents());
        let tail: Vec<&std::ffi::OsStr> = args[args.len() - 4..]
            .iter()
            .map(OsString::as_os_str)
            .collect();
        assert_eq!(
            tail,
            [
                "--agents-socket",
                "/run/classis-agents/agents.sock",
                "--process-uid",
                "997"
            ]
            .map(std::ffi::OsStr::new)
        );
        assert!(!service_args(&system_spec("/opt/classis"))
            .iter()
            .any(|a| a.to_string_lossy().contains("agents")));
    }

    /// The second service runs the same program under the process account, as `run --agents`
    /// serving the Client's uid, with its socket in a runtime directory only the account and its
    /// group reach, and the directives a unit that is not root carries.
    /// Not on Windows, which registers no second service: the socket is a Unix path, and a Windows
    /// build joins it with its own separator.
    #[cfg(unix)]
    #[test]
    fn the_second_services_unit_runs_the_program_under_the_process_account() {
        let unit = agents_unit(&with_agents(), &agents()).expect("unit");
        let lines: Vec<&str> = unit.lines().collect();
        for line in [
            "[Unit]",
            "Description=classis-agents",
            "[Service]",
            "ExecStart=\"/opt/classis/current/supervisor\" \"run\" \"--agents\" \
             \"/run/classis-agents/agents.sock\" \"--client-uid\" \"998\"",
            "Restart=on-failure",
            "RestartSec=5",
            "User=classis-agents",
            "RuntimeDirectory=classis-agents",
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
    #[cfg(unix)]
    #[test]
    fn the_second_services_account_is_read_back_from_its_unit() {
        let unit = agents_unit(&with_agents(), &agents()).expect("unit");
        assert_eq!(unit_account(&unit).as_deref(), Some("classis-agents"));
    }

    /// systemd waits longer for the second service to stop than the service gives its programs,
    /// so a stop ends them through the service.
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
    /// already is not stopped again, and one still starting is stopped once it has started.
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
    /// that one alone, while it is registered still; what did not run stays stopped.
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
    /// added where none was change nothing.
    #[test]
    fn an_account_change_is_a_former_account_named_no_more() {
        let named = |account: Option<&str>| Registration {
            file: PathBuf::from("/etc/systemd/system/unit.service"),
            account: account.map(str::to_string),
        };
        let fleet = named(Some("classis"));
        let root = named(None);
        let agents = named(Some("classis-agents"));
        let other = named(Some("other-agents"));
        // A first registration.
        assert!(!account_changes(
            None,
            Some("classis"),
            None,
            Some("classis-agents")
        ));
        // An upgrade that keeps both.
        assert!(!account_changes(
            Some(&fleet),
            Some("classis"),
            Some(&agents),
            Some("classis-agents")
        ));
        // A process account added where none was.
        assert!(!account_changes(
            Some(&fleet),
            Some("classis"),
            None,
            Some("classis-agents")
        ));
        // Root, named or left unnamed, is root.
        assert!(!account_changes(Some(&root), Some("root"), None, None));
        assert!(!account_changes(Some(&root), None, None, None));
        // The process account dropped, or another named.
        assert!(account_changes(
            Some(&fleet),
            Some("classis"),
            Some(&agents),
            None
        ));
        assert!(account_changes(
            Some(&fleet),
            Some("classis"),
            Some(&other),
            Some("classis-agents")
        ));
        // Another account for the Client.
        assert!(account_changes(Some(&root), Some("classis"), None, None));
        assert!(account_changes(Some(&fleet), None, None, None));
    }

    /// What ran, for a stop for a change, is what systemd reports active or activating.
    #[test]
    fn what_ran_is_what_the_manager_reports_running() {
        assert_eq!(systemd_activity("active"), Activity::Running);
        assert_eq!(systemd_activity("reloading"), Activity::Running);
        assert_eq!(systemd_activity("activating"), Activity::Starting);
        assert_eq!(systemd_activity("deactivating"), Activity::Stopping);
        for stopped in ["inactive", "failed", "unknown", ""] {
            assert_eq!(systemd_activity(stopped), Activity::Stopped, "{stopped}");
        }
    }

    /// The second service's process is the one systemd names its unit's `MainPID`; `0`, or no
    /// such value, is none.
    #[test]
    fn the_second_services_process_is_the_one_the_manager_names() {
        assert_eq!(systemd_main_pid("4242\n"), Some(4242));
        for none in ["0\n", "", "[not set]\n"] {
            assert_eq!(systemd_main_pid(none), None, "{none:?}");
        }
    }

    /// A stop for a change that cannot stop the second service starts the Client again where it
    /// stopped it, and fails: it leaves both as it found them, and the install changes nothing.
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
    /// errors are reported: no second service stays registered behind a Client that could not be.
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
    /// neither again: they are going.
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
    /// where it does not settle in time, fails, so that what is to run again stays recorded.
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
    /// service first where nothing does — the SCM — and `stop` stops the Client and then the
    /// second service where one is registered — the second even when the Client's stop failed,
    /// which `stop` still reports.
    #[test]
    fn start_starts_the_client_and_stop_stops_both() {
        let client = label().to_string();
        let agents = agents_label().to_string();
        assert_eq!(started(true, true), vec![label()], "systemd's Wants=");
        assert_eq!(
            started(true, false),
            vec![agents_label(), label()],
            "the SCM"
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

    /// No root is the socket's directory or lies in it: named as it is, by a path through a link,
    /// or beneath it. A root beside it, or one it lies in, is the operator's choice.
    #[cfg(unix)]
    #[test]
    fn no_root_is_the_sockets_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_dir = dir.path().join("classis-agents");
        let socket = socket_dir.join("agents.sock");
        let beside = dir.path().join("classis");
        let inside = socket_dir.join("data");
        for root in [&socket_dir, &inside, &dir.path().join("classis-agents/")] {
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
    }

    /// Where a process account is registered, the Client's unit wants the second service and starts
    /// after it, and its command line names the socket and the process account's uid; the CLI
    /// takes both lines as written.
    /// Not on Windows, for the reason the second service's own unit is not.
    #[cfg(unix)]
    #[test]
    fn the_clients_unit_names_the_second_service() {
        let unit = systemd_unit(&with_agents(), "classis").expect("unit");
        let header = &unit[..unit.find("[Service]").expect("service section")];
        assert!(
            header.lines().any(|l| l == "Wants=classis-agents.service"),
            "{unit}"
        );
        assert!(
            header.lines().any(|l| l == "After=classis-agents.service"),
            "{unit}"
        );
        assert!(
            unit.contains(
                "\"--agents-socket\" \"/run/classis-agents/agents.sock\" \"--process-uid\" \
                 \"997\""
            ),
            "{unit}"
        );
        let plain = systemd_unit(&system_spec("/opt/classis"), "classis").expect("unit");
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
    #[test]
    fn the_units_account_is_its_last_service_user() {
        let unit = "[Unit]\nDescription=classis\n\n[Service]\nExecStart=/x\nUser=telegraf\n\
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
            unit_account(&systemd_unit(&system_spec("/opt/classis"), "root").expect("unit"))
                .as_deref(),
            Some("root"),
            "what the Client writes, it reads back"
        );
    }

    /// The state directory a systemd unit carries is read back from `ExecStart=` exactly as
    /// [`systemd_unit`] wrote it, whatever characters its path holds — and from an unquoted line as
    /// `service-manager`'s own rendering writes one.
    #[test]
    fn a_units_state_directory_is_read_back_from_its_exec_start() {
        let mut spec = system_spec("/opt/classis");
        spec.state_dir = PathBuf::from("/srv/fleet state/100%\"$HOME\"\\\u{7}é");
        let unit = systemd_unit(&spec, "classis").expect("unit");
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

    /// A registration on disk is read back to the state directory the Client wrote into it, and a
    /// host with no registration offers none.
    #[cfg(unix)]
    #[test]
    fn a_registration_on_disk_offers_the_state_directory_it_was_written_with() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("classis.service");
        let mut spec = system_spec("/opt/classis");
        spec.state_dir = PathBuf::from("/srv/fleet/state");
        std::fs::write(&file, systemd_unit(&spec, "classis").expect("unit")).expect("write");
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
    #[test]
    fn a_windows_command_lines_state_directory_is_split_as_the_runtime_splits_it() {
        let line = r#"C:\ProgramData\classis\current\supervisor.exe run --service --config "C:\Program Files\x\supervisor.toml" --state-dir "D:\fleet state\\""#;
        assert_eq!(
            command_line_arguments(line),
            [
                r"C:\ProgramData\classis\current\supervisor.exe",
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
    /// a name the file contradicts, and no level holding the constant `default`.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_default_root_is_one_level_named_after_the_product() {
        let root = default_root(ServiceLevel::System).expect("system root");
        assert_eq!(root, PathBuf::from("/var/lib/classis"));
        let user = default_root(ServiceLevel::User).expect("user root");
        assert!(user.ends_with("classis"));
        assert!(
            !root.to_string_lossy().contains("/client/"),
            "the component level is gone"
        );
        assert!(
            !root.to_string_lossy().contains("default"),
            "the instance level is gone"
        );
    }

    /// A system service's binary must not live under
    /// `/var/lib` — SELinux's `var_lib_t` is no entrypoint type, and the service would fail its
    /// first start with `status=203/EXEC` on every enforcing host. The executable layout defaults
    /// to `/opt`; the data root stays under `/var/lib`, so an upgrade re-registers and moves no
    /// state. User scope has no such constraint and keeps one root for both.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_system_layout_executes_from_opt() {
        let layout = default_layout_root(ServiceLevel::System).expect("layout root");
        assert_eq!(layout, PathBuf::from("/opt/classis"));
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

    /// Linux at system scope is the *only* split. Windows keeps one root
    /// however it was installed, because a layout the daemon rewrites cannot live in the tree the
    /// installer owns — see the `--run-as` hand-over.
    #[cfg(windows)]
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
