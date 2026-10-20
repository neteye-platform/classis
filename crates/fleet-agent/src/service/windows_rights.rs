//! The rights a system-scope install needs, asked for **before** anything is written.
//!
//! On Windows every part of the registration goes through the service control manager and every
//! part of it needs Administrator: `sc create` in the `service-manager` backend, the
//! `CHANGE_CONFIG` handle [`windows_config`](super::windows_config) opens for the recovery actions,
//! and the `sc config` / `sc description` calls after it. A running process cannot raise its own
//! token, so a refusal from inside the install is not something the install can do anything about —
//! ADR-0019 says such an install "must fail with a clear message", and this is where that message
//! comes from.
//!
//! It is a **capability probe, not an identity check**: opening the SCM with
//! `SC_MANAGER_CREATE_SERVICE` asks the exact question the install turns on — may this process
//! register a service? — and answers it without registering one. Reading the token's elevation
//! instead would answer a weaker and different question, because what decides the outcome is the
//! SCM's own access check against the machine's security descriptor, not the shape of the token.
//!
//! It runs before the first write because the writing comes first and `%ProgramData%` lets an
//! ordinary user create folders under it: without this check a non-elevated install staged a
//! version directory and swung the `current` junction at it, and only *then* failed at `sc create`
//! — leaving half an install behind and a UAC path in `windows_config` that was never reached.
//!
//! A no-op on Unix, where there is nothing to probe short of doing it: systemd and launchd refuse
//! at the unit write, and the install roots (`/opt`, `/var/lib`, `/Library/Application Support`)
//! are not writable without root either, so the failure is already both early and plain.

use super::ServiceLevel;

/// Fail with an actionable message if this process may not register a system service. Call this
/// before the install writes anything, which is what lets the message promise that nothing has.
///
/// # Errors
/// Returns an error if the service control manager refuses this process for want of rights, or
/// cannot be reached at all — an install that would fail either way, and better before the layout
/// exists than after.
#[cfg(not(windows))]
pub fn ensure_can_register(_level: ServiceLevel) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
pub fn ensure_can_register(level: ServiceLevel) -> Result<(), String> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    // The SCM has no user-scope services to probe for. `--user` on Windows is refused by the
    // manager itself, with a message of its own that says exactly that.
    if level != ServiceLevel::System {
        return Ok(());
    }

    // Connect *and* create: the two rights the registration actually exercises, asked for together
    // so an administrator is never refused by a probe narrower than the call it stands in for.
    let access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    match ServiceManager::local_computer(None::<&str>, access) {
        Ok(_) => Ok(()),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(ACCESS_DENIED) => {
            Err(NEEDS_ADMINISTRATOR.to_string())
        }
        Err(e) => Err(format!(
            "cannot ask the service control manager whether a service may be registered: {e}"
        )),
    }
}

/// Who keeps full control of a system-scope data root once its inherited rights are cut: LocalSystem
/// and the Administrators group, by SID so a localised group name cannot miss. The service account
/// is granted its own rights afterwards, by the handover.
#[cfg(any(windows, test))]
const KEEPERS: [&str; 2] = ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"];

/// The `icacls.exe` arguments that cut `path` off from the rights it inherits and leave it to
/// [`KEEPERS`]. Without the inheritance flags propagated, what is already inside — the configuration
/// written moments ago — loses the inherited read right with its parent.
#[cfg(any(windows, test))]
fn restrict_args(path: &std::path::Path) -> Vec<std::ffi::OsString> {
    let mut args = vec![path.as_os_str().to_owned(), "/inheritance:r".into()];
    for keeper in KEEPERS {
        args.push("/grant:r".into());
        args.push(keeper.into());
    }
    args
}

/// The Administrators group, by SID: the owner of a system-scope data root (ADR-0019 clause 18).
#[cfg(any(windows, test))]
const OWNER: &str = "*S-1-5-32-544";

/// The `icacls.exe` runs, in order, that take the default data root over and leave it and
/// everything in it to [`KEEPERS`] alone, whoever created it.
///
/// `%ProgramData%` lets every local user create a folder, so the data root may already exist and
/// belong to one of them. Its owner may rewrite its rights at any time, and an explicit grant of
/// theirs survives removing the inherited ones. So every item is first given to the
/// Administrators — a link itself, never what it names — and every explicit right in the tree is
/// reset away, before the root is cut off by [`restrict_args`]. No `/C`: an item that cannot be
/// taken over fails the install instead of staying behind.
#[cfg(any(windows, test))]
fn take_over_commands(path: &std::path::Path) -> Vec<Vec<std::ffi::OsString>> {
    let path = path.as_os_str().to_owned();
    vec![
        vec![
            path.clone(),
            "/setowner".into(),
            OWNER.into(),
            "/T".into(),
            "/L".into(),
        ],
        vec![path.clone(), "/reset".into(), "/T".into(), "/L".into()],
        restrict_args(std::path::Path::new(&path)),
    ]
}

/// What a system-scope install does to the rights of one directory that holds the Client's
/// secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Treatment {
    /// The platform's own data root under `%ProgramData%`: taken over whole
    /// ([`take_over_commands`]), whoever created it.
    TakeOver,
    /// A data root the operator named, a state directory outside it, or a Supervisors' root
    /// outside both that the install creates: cut off from inherited rights ([`restrict_args`]),
    /// nothing else changed.
    Cut,
    /// A Supervisors' root outside the data root and the state directory that already exists: the
    /// operator's, left as it is and named in a warning.
    Untouched,
}

/// Which directories a system-scope install restricts, and how: the data root — taken over when it
/// is the platform default, cut when the operator named it — and the state directory and the
/// Supervisors' root wherever one lies outside every directory already listed. A state directory
/// outside the data root is always cut. A Supervisors' root outside both is cut when the install
/// creates it (`exists` says it does not exist yet) and left untouched when it exists. A directory
/// inside a listed one inherits its rights and is not listed. Decided before the install creates
/// anything.
#[must_use]
pub fn plan(
    data_root: &std::path::Path,
    data_root_named: bool,
    state_dir: &std::path::Path,
    supervisors_root: &std::path::Path,
    exists: impl Fn(&std::path::Path) -> bool,
) -> Vec<(std::path::PathBuf, Treatment)> {
    let first = if data_root_named {
        Treatment::Cut
    } else {
        Treatment::TakeOver
    };
    let mut plan = vec![(data_root.to_path_buf(), first)];
    for (dir, may_exist) in [(state_dir, true), (supervisors_root, false)] {
        if plan.iter().any(|(root, _)| dir.starts_with(root)) {
            continue;
        }
        let treatment = if !may_exist && exists(dir) {
            Treatment::Untouched
        } else {
            Treatment::Cut
        };
        plan.push((dir.to_path_buf(), treatment));
    }
    plan
}

/// Applies a [`plan`] at system scope: creates each directory it cuts or takes over, runs
/// `icacls.exe`, and warns about each it leaves untouched. Returns the directories it created
/// outside the data root, for the handover to grant the service account.
///
/// Every folder created under `%ProgramData%` inherits `BUILTIN\Users:(OI)(CI)(RX)`: any local
/// user could read the configuration and the archive key it may hold, the private key and the
/// stored connection settings. On Unix the Client writes those `0600` in a `0700` directory itself;
/// here the install leaves them to LocalSystem and the Administrators, before the handover grants
/// the service account its own. A user-scope install lives in the user's profile, which is private
/// already.
///
/// # Errors
/// Returns an error when a directory cannot be created, or `icacls.exe` cannot be run or refuses
/// the change.
#[cfg(windows)]
pub fn restrict(
    level: ServiceLevel,
    plan: &[(std::path::PathBuf, Treatment)],
) -> Result<Vec<std::path::PathBuf>, String> {
    let mut created = Vec::new();
    if level != ServiceLevel::System {
        return Ok(created);
    }
    for (index, (dir, treatment)) in plan.iter().enumerate() {
        let commands = match treatment {
            Treatment::TakeOver => take_over_commands(dir),
            Treatment::Cut => vec![restrict_args(dir)],
            Treatment::Untouched => {
                println!(
                    "warning: {} exists already and is left as it is — restrict it to \
                     LocalSystem, the Administrators and the service account yourself",
                    dir.display()
                );
                continue;
            }
        };
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        for args in commands {
            let output = std::process::Command::new("icacls.exe")
                .args(&args)
                .output()
                .map_err(|e| format!("cannot run icacls.exe: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cannot restrict {} to LocalSystem and the Administrators: icacls.exe {} \
                     exited with {} ({})",
                    dir.display(),
                    args[1].to_string_lossy(),
                    output.status,
                    String::from_utf8_lossy(&output.stdout).trim()
                ));
            }
        }
        if index > 0 {
            created.push(dir.clone());
        }
    }
    Ok(created)
}

/// A no-op on Unix, where the Client writes its secrets owner-only itself.
///
/// # Errors
/// Never.
#[cfg(not(windows))]
pub fn restrict(
    _level: ServiceLevel,
    _plan: &[(std::path::PathBuf, Treatment)],
) -> Result<Vec<std::path::PathBuf>, String> {
    Ok(Vec::new())
}

/// `ERROR_ACCESS_DENIED` — the one refusal that means "elevate", matched on the number because the
/// message is localised (the report this check came from read *"OpenSCManager FEHLER 5"*).
#[cfg(any(windows, test))]
const ACCESS_DENIED: i32 = 5;

/// What an operator sees instead of a bare Win32 error: what was refused, why nothing can be done
/// about it from here, and the one thing that fixes it.
#[cfg(any(windows, test))]
const NEEDS_ADMINISTRATOR: &str = "the Windows service control manager denied access: registering \
     a machine-wide service needs Administrator, and a running process cannot raise its own \
     rights. Open a shell with \"Run as administrator\" — from PowerShell, `Start-Process \
     powershell -Verb RunAs` — and run this command again. Nothing has been installed or written.";

#[cfg(test)]
mod tests {
    use super::{
        plan, restrict_args, take_over_commands, Treatment, ACCESS_DENIED, KEEPERS,
        NEEDS_ADMINISTRATOR,
    };
    use std::path::{Path, PathBuf};

    fn strings(args: &[std::ffi::OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// A data root a local user created before the install is theirs: as its owner they could
    /// rewrite its rights at any time, and an explicit grant of theirs survives cutting the
    /// inherited ones. So the whole tree is first given to the Administrators, every explicit
    /// right in it is dropped, and only then is the root cut off and left to the keepers — the
    /// result is the same whoever made the directory.
    /// Verifies: ADR-0019
    #[test]
    fn a_data_root_someone_else_made_is_taken_over_before_it_is_cut_off() {
        let root = Path::new(r"C:\ProgramData\opamp-fleet");
        let commands: Vec<Vec<String>> = take_over_commands(root)
            .iter()
            .map(|args| strings(args))
            .collect();
        assert_eq!(commands.len(), 3, "{commands:?}");
        assert_eq!(
            commands[0],
            [
                root.to_str().unwrap(),
                "/setowner",
                "*S-1-5-32-544",
                "/T",
                "/L"
            ],
            "the Administrators own every item, the links themselves and not what they name"
        );
        assert_eq!(
            commands[1],
            [root.to_str().unwrap(), "/reset", "/T", "/L"],
            "no explicit right survives anywhere in the tree"
        );
        assert_eq!(commands[2], strings(&restrict_args(root)), "then the cut");
        assert!(
            commands.iter().flatten().all(|arg| arg != "/C"),
            "an item that cannot be taken over fails the install rather than being skipped"
        );
    }

    /// Only the platform's own data root is taken over. One the operator named is cut, as is a
    /// state directory outside it, existing or not, and a Supervisors' root outside both that the
    /// install creates; such a Supervisors' root that already exists is the operator's and is left
    /// alone. A directory inside a listed one inherits its rights.
    /// Verifies: ADR-0019
    #[test]
    fn only_the_default_data_root_is_taken_over_and_only_a_created_directory_is_cut() {
        use Treatment::{Cut, TakeOver, Untouched};
        let data = Path::new("/data");
        let made = |dirs: &'static [&'static str]| {
            move |dir: &Path| dirs.iter().any(|d| dir == Path::new(d))
        };
        let entries = |plan: Vec<(PathBuf, Treatment)>| -> Vec<(String, Treatment)> {
            plan.into_iter()
                .map(|(dir, t)| (dir.display().to_string(), t))
                .collect()
        };

        assert_eq!(
            entries(plan(
                data,
                false,
                Path::new("/data/state"),
                Path::new("/data/state/supervisors"),
                made(&[])
            )),
            [("/data".to_string(), TakeOver)]
        );
        assert_eq!(
            entries(plan(
                data,
                true,
                Path::new("/data/state"),
                Path::new("/data/supervisors"),
                made(&[])
            )),
            [("/data".to_string(), Cut)],
            "a data root the operator named is cut, not taken over"
        );
        assert_eq!(
            entries(plan(
                data,
                false,
                Path::new("/var/state"),
                Path::new("/srv/supervisors"),
                made(&[])
            )),
            [
                ("/data".to_string(), TakeOver),
                ("/var/state".to_string(), Cut),
                ("/srv/supervisors".to_string(), Cut)
            ]
        );
        assert_eq!(
            entries(plan(
                data,
                false,
                Path::new("/var/state"),
                Path::new("/srv/supervisors"),
                made(&["/var/state", "/srv/supervisors"])
            )),
            [
                ("/data".to_string(), TakeOver),
                ("/var/state".to_string(), Cut),
                ("/srv/supervisors".to_string(), Untouched)
            ],
            "an existing state directory is still cut; an existing Supervisors' root is the \
             operator's"
        );
        assert_eq!(
            entries(plan(
                data,
                false,
                Path::new("/var/state"),
                Path::new("/var/state/supervisors"),
                made(&[])
            )),
            [
                ("/data".to_string(), TakeOver),
                ("/var/state".to_string(), Cut)
            ]
        );
    }

    /// The data root keeps no inherited right — `BUILTIN\Users` read among them — and full control
    /// only for LocalSystem and the Administrators, each granted by SID.
    /// Verifies: ADR-0019
    #[test]
    fn the_data_root_is_cut_off_from_what_every_local_user_inherits() {
        let args: Vec<String> = restrict_args(std::path::Path::new(r"C:\ProgramData\opamp-fleet"))
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], r"C:\ProgramData\opamp-fleet");
        assert_eq!(
            args[1], "/inheritance:r",
            "inherited rights are removed, not kept"
        );
        assert_eq!(&args[2..], ["/grant:r", KEEPERS[0], "/grant:r", KEEPERS[1]]);
        assert!(KEEPERS[0].starts_with("*S-1-5-18:") && KEEPERS[1].starts_with("*S-1-5-32-544:"));
        assert!(
            !args.iter().any(|arg| arg.contains("S-1-5-32-545")),
            "no grant to Users"
        );
    }

    /// The message *is* the feature: this check exists only so that a refusal says what was
    /// refused and what to do about it (ADR-0019). It must not offer `--user` as the way out —
    /// Windows has no user-scope service, so that would send an operator somewhere with no door.
    #[test]
    fn the_refusal_says_what_to_do_about_it() {
        assert!(NEEDS_ADMINISTRATOR.contains("Administrator"));
        assert!(NEEDS_ADMINISTRATOR.contains("Run as administrator"));
        assert!(
            !NEEDS_ADMINISTRATOR.contains("--user"),
            "a user-scope service is not the way out — the SCM has none"
        );
        assert_eq!(ACCESS_DENIED, 5, "ERROR_ACCESS_DENIED");
    }

    /// On Unix the check has nothing to probe and must never be the thing that stops an install —
    /// including the smoke test's, which runs as root and would otherwise be told it is not.
    #[cfg(not(windows))]
    #[test]
    fn unix_is_never_refused_by_a_probe_it_cannot_run() {
        use crate::service::ServiceLevel;

        for level in [ServiceLevel::System, ServiceLevel::User] {
            assert!(super::ensure_can_register(level).is_ok(), "{level:?}");
        }
    }
}
