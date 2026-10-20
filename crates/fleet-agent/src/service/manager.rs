//! Cross-platform service lifecycle over the `service-manager` crate (ADR-0019).
//!
//! `service-manager` targets the platform's native manager (systemd, launchd, Windows SCM) behind
//! one API. This module wraps it in the project's vocabulary. There is **one service per build**
//! (ADR-0019): it is named after the product, takes no suffix, and nothing has to be looked up to
//! address it. The installed program is the layout's `current` pointer, so a self-update is a
//! pointer switch — never a re-registration.

use std::ffi::OsString;
// `Path` is used only by the Unix `default_base` variants; Windows builds with -D warnings.
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceLevel as SmLevel, ServiceManager,
    ServiceManagerKind, ServiceStartCtx, ServiceStatus, ServiceStatusCtx, ServiceStopCtx,
    ServiceUninstallCtx,
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
}

/// The installed command line: `run --service --config … --state-dir …`. The hidden `--service`
/// marker is what routes into the Windows SCM dispatcher; it is ignored on Unix.
///
/// Both paths are absolute and both are baked in, which is what makes an upgrade a re-registration
/// rather than a migration (ADR-0042 clause 1): the program path and the rest of the unit are
/// rewritten from the version that registers, and the configuration, identity and state stay
/// where they are.
fn service_args(spec: &InstallSpec) -> Vec<OsString> {
    vec![
        OsString::from("run"),
        OsString::from("--service"),
        OsString::from("--config"),
        spec.config_path.clone().into_os_string(),
        OsString::from("--state-dir"),
        spec.state_dir.clone().into_os_string(),
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
    manager(spec.level)?
        .install(ServiceInstallCtx {
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
        })
        .map_err(|e| {
            format!("cannot install the service (system scope needs root/Administrator): {e}")
        })
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
    if account.is_empty()
        || account
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '%' | '\\' | '"'))
    {
        return Err(format!(
            "the account {account:?} cannot be written into a systemd unit"
        ));
    }
    let mut exec = vec![exec_word(spec.program.as_os_str())?];
    for arg in service_args(spec) {
        exec.push(exec_word(&arg)?);
    }
    let mut unit = String::new();
    let _ = writeln!(unit, "[Unit]");
    let _ = writeln!(unit, "Description={}", service_name());
    let _ = writeln!(unit);
    let _ = writeln!(unit, "[Service]");
    let _ = writeln!(unit, "ExecStart={}", exec.join(" "));
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
    Ok(None)
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
    let value = value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
    (!value.is_empty()).then_some(value)
}

/// Deregister the service. The install layout and state are never deleted.
///
/// # Errors
/// Returns an error if the manager cannot uninstall the service.
pub fn uninstall(level: ServiceLevel) -> Result<(), String> {
    manager(level)?
        .uninstall(ServiceUninstallCtx { label: label() })
        .map_err(|e| format!("cannot uninstall the service: {e}"))
}

/// The installed service, implementing the [`ServiceControl`] seam.
pub struct NativeService {
    level: ServiceLevel,
}

impl NativeService {
    /// A handle to the service at the given level.
    #[must_use]
    pub fn new(level: ServiceLevel) -> Self {
        Self { level }
    }
}

impl ServiceControl for NativeService {
    fn start(&self) -> Result<(), String> {
        manager(self.level)?
            .start(ServiceStartCtx { label: label() })
            .map_err(|e| format!("cannot start the service: {e}"))
    }

    fn stop(&self) -> Result<(), String> {
        manager(self.level)?
            .stop(ServiceStopCtx { label: label() })
            .map_err(|e| format!("cannot stop the service: {e}"))
    }

    fn state(&self) -> Result<ServiceState, String> {
        let status = manager(self.level)?
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
