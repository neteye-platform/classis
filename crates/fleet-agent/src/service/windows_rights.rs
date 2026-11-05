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
/// and the Administrators group, by their aliases, which no localised name can miss. The service
/// account is granted its own rights afterwards, by the handover.
#[cfg(any(windows, test))]
const KEEPERS: [(&str, &str); 2] = [("S-1-5-18", "SY"), ("S-1-5-32-544", "BA")];

/// `FILE_ALL_ACCESS`: what `icacls` calls `F`.
#[cfg(any(windows, test))]
const FULL: u32 = 0x001f_01ff;

/// The Administrators group, by alias: the owner of a system-scope data root (ADR-0019 clause 18).
#[cfg(any(windows, test))]
const OWNER: &str = "BA";

/// The DACL of a root cut off from the rights it inherits (`/inheritance:r`): protected, its own
/// explicit ACEs kept, and full control for [`KEEPERS`], inherited by everything in it, in place of
/// what they were granted explicitly before.
#[cfg(any(windows, test))]
fn cut(current: &crate::win32::acl::Dacl) -> crate::win32::acl::Dacl {
    use crate::win32::acl::{allow, Dacl};
    let mut dacl = Dacl {
        flags: "PAI".to_string(),
        aces: current.explicit().aces,
    };
    for (sid, alias) in KEEPERS {
        dacl = dacl.granting(sid, &[allow(alias, FULL, "OICI")]);
    }
    dacl
}

/// The DACL of an entry beneath a root that is taken over (`/reset`): no explicit ACE, and what its
/// parent `parent` passes on to it.
#[cfg(any(windows, test))]
fn taken_over(parent: &crate::win32::acl::Dacl, dir: bool) -> crate::win32::acl::Dacl {
    crate::win32::acl::Dacl {
        flags: "AI".to_string(),
        aces: parent.passed_on(dir),
    }
}

/// Takes the default data root `dir` over and leaves it and everything in it to [`KEEPERS`] alone,
/// whoever created it.
///
/// `%ProgramData%` lets every local user create a folder, so the data root may already exist and
/// belong to one of them. Its owner may rewrite its rights at any time, and an explicit grant of
/// theirs survives removing the inherited ones. So the root and every entry in it is given to the
/// Administrators, the root is cut off ([`cut`]) and every entry keeps only what the root passes
/// on to it ([`taken_over`]). Each entry is changed through a handle of its own: a link is changed
/// as itself and never entered, and what the process account `process` owns, with everything
/// beneath it, is left as it is (ADR-0059 clause 10). An entry that cannot be taken over fails the
/// install instead of staying behind.
#[cfg(windows)]
fn take_over(
    dir: &std::path::Path,
    process: Option<&crate::win32::Sid>,
) -> std::io::Result<Vec<crate::win32::files::Passed>> {
    use crate::win32::files::{walk, Access, Entry, Walk};
    let top = open_root(dir, Access::Owner)?;
    top.set_owner(OWNER)?;
    let keepers_alone = crate::win32::acl::Dacl::parse("D:").map_err(std::io::Error::other)?;
    top.set_dacl(&cut(&keepers_alone))?;
    let mut passed = Vec::new();
    let how = Walk {
        access: Access::Owner,
        skip: process,
        lenient: false,
        takes_away: true,
    };
    walk(
        &top,
        how,
        &mut |entry: &Entry, parent: &Entry| {
            entry.set_owner(OWNER)?;
            entry.set_dacl(&taken_over(&parent.dacl()?, entry.dir))?;
            Ok(true)
        },
        &mut passed,
    )?;
    Ok(passed)
}

/// Cuts `dir` off from the rights it inherits and leaves it to [`KEEPERS`] ([`cut`]), and applies
/// what it then passes on to what it already holds — the configuration written moments ago would
/// otherwise keep the read right `BUILTIN\Users` passed on before. Through handles, as
/// [`take_over`] goes, and stopping at an entry protected from what its parent passes on.
///
/// What the process account owns is left as it is, its inherited ACEs included: what a root the
/// operator named passed on to it before the cut — `BUILTIN\Users` reading, say — it keeps until
/// it is written again. Its content is the Managed Processes' own, which the cut does not touch.
#[cfg(windows)]
fn cut_off(
    dir: &std::path::Path,
    process: Option<&crate::win32::Sid>,
) -> std::io::Result<Vec<crate::win32::files::Passed>> {
    use crate::win32::files::{walk, Access, Entry, Walk};
    let top = open_root(dir, Access::Dacl)?;
    top.set_dacl(&cut(&top.dacl()?))?;
    let mut passed = Vec::new();
    let how = Walk {
        access: Access::Dacl,
        skip: process,
        lenient: false,
        takes_away: true,
    };
    walk(
        &top,
        how,
        &mut |entry: &Entry, parent: &Entry| {
            let dacl = entry.dacl()?;
            let inherits = dacl.inheriting(&parent.dacl()?, entry.dir);
            if inherits != dacl {
                entry.set_dacl(&inherits)?;
            }
            Ok(!dacl.protected())
        },
        &mut passed,
    )?;
    Ok(passed)
}

/// The warning that names what a walk of the install passed over.
#[cfg(windows)]
pub(crate) fn passed_warning(passed: &crate::win32::files::Passed) -> String {
    use crate::win32::files::Passed;
    match passed {
        Passed::Owned(path) => format!(
            "{} belongs to the process account and was left as it is, with everything beneath it",
            path.display()
        ),
        Passed::HardLinked(path) => format!(
            "{} has a second hard link and was left as it is: its other name may stand anywhere",
            path.display()
        ),
        Passed::Unreadable(path) => format!(
            "{} could not be opened and was left as it is",
            path.display()
        ),
        Passed::Held(path) => format!(
            "{} is held open for deleting, as the Managed Processes may hold what they write, and \
             was left as it is, with everything beneath it",
            path.display()
        ),
    }
}

/// Opens the root `dir` as itself, held: a root that is a link is refused.
#[cfg(windows)]
fn open_root(
    dir: &std::path::Path,
    access: crate::win32::files::Access,
) -> std::io::Result<crate::win32::files::Entry> {
    let top = crate::win32::files::Entry::open(dir, access, true)?;
    if !top.dir {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is a link or no directory", dir.display()),
        ));
    }
    Ok(top)
}

/// What a system-scope install does to the rights of one directory that holds the Client's
/// secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Treatment {
    /// The platform's own data root under `%ProgramData%`: taken over whole ([`take_over`]),
    /// whoever created it.
    TakeOver,
    /// A data root the operator named, a state directory outside it, or a Supervisors' root
    /// outside both that the install creates: cut off from inherited rights ([`cut`]), nothing
    /// else changed.
    Cut,
    /// A Supervisors' root outside the data root and the state directory that already exists, or
    /// that lies outside every root of the install: the operator's, left as it is and named in a
    /// warning.
    Untouched,
}

/// Which directories a system-scope install restricts, and how: the data root — taken over when it
/// is the platform default, cut when the operator named it — and the state directory and the
/// Supervisors' root wherever one lies outside every directory already listed. A state directory
/// outside the data root is always cut: the install has taken it beneath its roots, from the
/// operator's `--state-dir` or from the registration (ADR-0053 clause 3). A Supervisors' root
/// outside both is cut when the install creates it (`exists` says it does not exist yet) and
/// `ours` says it lies beneath the install's roots, and
/// left untouched otherwise: `supervisor.toml` is the service account's to rewrite, and a directory
/// it names elsewhere would have the install create one wherever that account chose and grant it
/// Modify there. A directory inside a listed one inherits its rights and is not listed. Decided
/// before the install creates anything.
#[must_use]
pub fn plan(
    data_root: &std::path::Path,
    data_root_named: bool,
    state_dir: &std::path::Path,
    supervisors_root: &std::path::Path,
    ours: bool,
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
        let treatment = if !may_exist && (!ours || exists(dir)) {
            Treatment::Untouched
        } else {
            Treatment::Cut
        };
        plan.push((dir.to_path_buf(), treatment));
    }
    plan
}

/// Applies a [`plan`] at system scope: creates each directory it cuts or takes over, cuts it off
/// ([`cut`]) or takes it over ([`take_over`]) one handle at a time with the backup and restore
/// privileges enabled, and warns about each it leaves untouched and about what a walk passed over.
/// What the process account `process` owns is left as it is. Returns the directories it created
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
/// Returns an error when a directory cannot be created, is a link, or an entry's owner or DACL
/// cannot be changed.
#[cfg(windows)]
pub fn restrict(
    level: ServiceLevel,
    plan: &[(std::path::PathBuf, Treatment)],
    process: Option<&str>,
) -> Result<Vec<std::path::PathBuf>, String> {
    let mut created = Vec::new();
    if level != ServiceLevel::System {
        return Ok(created);
    }
    let process = process
        .map(crate::win32::Sid::parse)
        .transpose()
        .map_err(|e| format!("the process account: {e}"))?;
    // For as short as the walks take: an entry another account made, or one a Managed Process
    // protected from the Administrators, is opened all the same, and its owner set.
    let _privileges = crate::win32::BackupPrivileges::enable()
        .map_err(|e| format!("cannot enable the backup and restore privileges: {e}"))?;
    for (index, (dir, treatment)) in plan.iter().enumerate() {
        if *treatment == Treatment::Untouched {
            println!(
                "warning: {} is left as it is — it exists already, or lies outside the data \
                 root, the layout root and the state directory; create it where it is missing \
                 and restrict it to LocalSystem, the Administrators and the service account \
                 yourself",
                dir.display()
            );
            continue;
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let restricted = if *treatment == Treatment::TakeOver {
            take_over(dir, process.as_ref())
        } else {
            cut_off(dir, process.as_ref())
        };
        let passed = restricted.map_err(|e| {
            format!(
                "cannot restrict {} to LocalSystem and the Administrators: {e}",
                dir.display()
            )
        })?;
        for passed in passed {
            if !matches!(passed, crate::win32::files::Passed::Owned(_)) {
                println!("warning: {}", passed_warning(&passed));
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
    _process: Option<&str>,
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
    use super::{cut, plan, taken_over, Treatment, ACCESS_DENIED, NEEDS_ADMINISTRATOR, OWNER};
    use crate::win32::acl::Dacl;
    use std::path::{Path, PathBuf};

    /// A data root a local user created before the install is theirs: as its owner they could
    /// rewrite its rights at any time, and an explicit grant of theirs survives cutting the
    /// inherited ones. So the root and every entry is given to the Administrators, the root keeps
    /// nothing but the keepers, and every entry beneath it nothing but what the root passes on —
    /// the result is the same whoever made the directory.
    /// Verifies: ADR-0019
    #[test]
    fn a_data_root_someone_else_made_is_taken_over_before_it_is_cut_off() {
        assert_eq!(OWNER, "BA", "the Administrators own every entry");
        let root = cut(&Dacl::parse("D:").expect("empty"));
        assert_eq!(
            root.text(),
            "D:PAI(A;OICI;0x1f01ff;;;SY)(A;OICI;0x1f01ff;;;BA)"
        );
        let planted = Dacl::parse("D:(A;OICI;0x1f01ff;;;S-1-5-21-1-2-3-1001)").expect("theirs");
        let dir = taken_over(&root, true);
        assert_eq!(
            dir.text(),
            "D:AI(A;OICIID;0x1f01ff;;;SY)(A;OICIID;0x1f01ff;;;BA)",
            "no explicit right survives beneath the root"
        );
        assert!(!dir.text().contains("S-1-5-21"), "{planted:?}");
        assert_eq!(
            taken_over(&dir, false).text(),
            "D:AI(A;ID;0x1f01ff;;;SY)(A;ID;0x1f01ff;;;BA)"
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
                true,
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
                true,
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
                true,
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
                true,
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
                true,
                made(&[])
            )),
            [
                ("/data".to_string(), TakeOver),
                ("/var/state".to_string(), Cut)
            ]
        );
    }

    /// `supervisor.toml` is the service account's to rewrite (ADR-0042 clause 2). A Supervisors'
    /// root it places outside every root of the install is never created, cut or handed over by
    /// the install — not even when it does not exist yet — or the account would choose where an
    /// Administrator makes a directory and grants it Modify.
    /// Verifies: ADR-0053, ADR-0042
    #[test]
    fn a_supervisors_root_outside_the_installs_roots_is_left_untouched() {
        let planned = plan(
            Path::new("/data"),
            false,
            Path::new("/data/state"),
            Path::new("/windows/system32/plugins"),
            false,
            |_: &Path| false,
        );
        assert_eq!(
            planned,
            [
                (PathBuf::from("/data"), Treatment::TakeOver),
                (
                    PathBuf::from("/windows/system32/plugins"),
                    Treatment::Untouched
                )
            ]
        );
    }

    /// The data root keeps no inherited right — `BUILTIN\Users` read among them — and full control
    /// only for LocalSystem and the Administrators beside its own explicit grants, and what it
    /// holds then inherits that alone, its own explicit grants kept.
    /// Verifies: ADR-0019, ADR-0053
    #[test]
    fn the_data_root_is_cut_off_from_what_every_local_user_inherits() {
        let inherited = Dacl::parse(
            "D:AI(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)(A;OICIID;0x1200a9;;;BU)(A;OICIID;0x1f01ff;;;SY)",
        )
        .expect("dacl");
        let root = cut(&inherited);
        assert_eq!(
            root.text(),
            "D:PAI(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)(A;OICI;0x1f01ff;;;SY)(A;OICI;0x1f01ff;;;BA)"
        );
        assert!(root.protected(), "inherited rights are removed, not kept");
        let config = Dacl::parse("D:AI(A;;0x1;;;LS)(A;ID;0x1200a9;;;BU)").expect("file");
        assert_eq!(
            config.inheriting(&root, false).text(),
            "D:AI(A;;0x1;;;LS)(A;ID;0x1301bf;;;S-1-5-80-1-2-3-4-5)(A;ID;0x1f01ff;;;SY)(A;ID;0x1f01ff;;;BA)",
            "no read right for Users"
        );
    }

    /// A tree under a parent that passes on what every local user may read, cut off or taken over
    /// on real NTFS: the root keeps the keepers alone and is protected, what it holds inherits the
    /// keepers alone, and a junction, the other name of a hard link and what the process account
    /// owns — this test's own account standing in — are not touched; a root that is a link is
    /// refused. The test runs elevated, as an install does.
    /// Verifies: ADR-0019, ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_a_restricted_root_keeps_the_keepers_alone_and_enters_no_link() {
        use super::restrict;
        use crate::service::ServiceLevel;
        use crate::win32::files::{Access, Entry};
        let me = crate::win32::own_sid().expect("own sid");
        let sddl = |path: &Path| {
            Entry::open(path, Access::Read, false)
                .and_then(|entry| entry.dacl())
                .expect("dacl")
                .text()
        };
        let owner = |path: &Path| {
            Entry::open(path, Access::Read, false)
                .and_then(|entry| entry.owner())
                .expect("owner")
        };
        let mklink = |kind: &str, link: &Path, target: &Path| {
            let made = std::process::Command::new("cmd")
                .args(["/c", "mklink", kind])
                .arg(link)
                .arg(target)
                .status()
                .expect("run mklink");
            assert!(made.success(), "cannot make {}", link.display());
        };
        for treatment in [Treatment::Cut, Treatment::TakeOver] {
            let dir = tempfile::tempdir().expect("tempdir");
            let parent = dir.path().join("parent");
            std::fs::create_dir(&parent).expect("parent");
            Entry::open(&parent, Access::Dacl, false)
                .and_then(|entry| {
                    entry.set_dacl(
                        &Dacl::parse(&format!(
                            "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})\
                             (A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;WD)"
                        ))
                        .expect("dacl"),
                    )
                })
                .expect("a parent that passes on reading to everyone");
            let root = parent.join("root");
            let sub = root.join("sub");
            std::fs::create_dir_all(&sub).expect("sub");
            std::fs::write(sub.join("file"), b"x").expect("file");
            std::fs::write(sub.join("kept"), b"x").expect("kept");
            // What the parent passes on, held as inherited — a DACL set on a handle carries no
            // automatic inheritance, so what the system creates beneath it holds it as explicit —
            // and on `kept` an explicit grant to every local user beside it.
            let passed = |dir: bool| {
                let flags = if dir { "OICIID" } else { "ID" };
                format!(
                    "(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)(A;{flags};FA;;;{me})\
                     (A;{flags};0x1200a9;;;BU)(A;{flags};0x1200a9;;;WD)"
                )
            };
            for (path, dacl) in [
                (&root, format!("D:AI{}", passed(true))),
                (&sub, format!("D:AI{}", passed(true))),
                (&sub.join("file"), format!("D:AI{}", passed(false))),
                (
                    &sub.join("kept"),
                    format!("D:AI(A;;0x1200a9;;;BU){}", passed(false)),
                ),
            ] {
                Entry::open(path, Access::Dacl, false)
                    .and_then(|entry| entry.set_dacl(&Dacl::parse(&dacl).expect("dacl")))
                    .expect("inherited as the parent passes it on");
            }
            let outside = dir.path().join("outside");
            std::fs::create_dir(&outside).expect("outside");
            std::fs::write(outside.join("secret"), b"x").expect("secret");
            mklink("/J", &root.join("link"), &outside);
            mklink("/H", &root.join("hard"), &outside.join("secret"));
            let owned = root.join("owned");
            std::fs::create_dir(&owned).expect("owned");
            Entry::open(&owned, Access::Owner, false)
                .and_then(|entry| entry.set_owner(me.as_str()))
                .expect("owned by the stand-in");
            let before = (sddl(&outside), sddl(&outside.join("secret")), sddl(&owned));
            let before_sub = sddl(&sub);

            restrict(
                ServiceLevel::System,
                &[(root.clone(), treatment)],
                Some(me.as_str()),
            )
            .expect("restricted");

            let top = sddl(&root);
            assert!(top.starts_with("D:P"), "{treatment:?}: {top}");
            for path in [&root, &sub, &sub.join("file")] {
                let text = sddl(path);
                assert!(
                    !text.contains(";;;BU)") && !text.contains(";;;WD)"),
                    "{treatment:?} {}: {text} (sub was {before_sub})",
                    path.display()
                );
                assert!(
                    text.contains(";;;SY)") && text.contains(";;;BA)"),
                    "{treatment:?} {}: {text}",
                    path.display()
                );
            }
            assert!(
                sddl(&sub).contains("(A;OICIID;FA;;;SY)"),
                "{treatment:?}: inherited"
            );
            // A cut changes nothing explicit beneath the root, as `icacls /inheritance:r` did not;
            // a take-over resets it away (ADR-0019).
            let kept = sddl(&sub.join("kept"));
            assert_eq!(
                kept.contains("(A;;0x1200a9;;;BU)"),
                treatment == Treatment::Cut,
                "{treatment:?}: {kept}"
            );
            assert!(
                !kept.contains("(A;ID;0x1200a9;;;BU)"),
                "{treatment:?}: {kept}"
            );
            assert_eq!(
                (sddl(&outside), sddl(&outside.join("secret")), sddl(&owned)),
                before,
                "{treatment:?}: no link entered, no other name, nothing of the process account's"
            );
            if treatment == Treatment::TakeOver {
                assert_eq!(owner(&sub).as_str(), "S-1-5-32-544");
            }
            assert!(
                restrict(
                    ServiceLevel::System,
                    &[(root.join("link"), treatment)],
                    Some(me.as_str())
                )
                .is_err(),
                "{treatment:?}: a root that is a link is refused"
            );
        }
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
