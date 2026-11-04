//! The account the system service runs as (ADR-0042 clause 2): decided and resolved before
//! anything is written, and the ownership handover after the layout exists.
//!
//! `service install --run-as <account>` names the account; without the flag a re-registration
//! keeps the account its registration names, and a first registration runs as root (Linux, macOS)
//! or `LocalSystem` (Windows). The installation's files — the configuration, the state directory,
//! and the executable layout, across both roots (ADR-0019 clause 8) — belong to that account
//! afterwards. *What* the service manager is told is [`manager`](super::manager)'s and
//! [`windows_config`](super::windows_config)'s business.
//!
//! **The decision and the resolution come first** because an install that cannot succeed fails
//! before it writes: an account that does not exist (Unix), or a Windows account form that would
//! need a password nobody may pass (ADR-0019), is such an install. On Unix a name is resolved
//! through `id(1)`, POSIX and present on every Linux and macOS host; the owner of a data root is
//! named through `getpwuid_r(3)`, which takes a uid and nothing else.
//!
//! **The handover is `chown` on Unix and an ACL grant on Windows.** On Unix it never follows a
//! link: the account owns the trees it walks and could swap a directory for a link while root walks
//! them. Each directory is opened without following a link and re-owned through that handle, its
//! entries are read from the handle, a symbolic link is re-owned as a link, and a regular file with
//! a second hard link is skipped and named. On Windows the files under `%ProgramData%` stay owned by
//! Administrators and the account is *granted* Modify with inheritance instead — the platform's
//! idiom for "these directories are yours to use", and what lets the service create tomorrow's
//! files (a staged version, a rewritten `supervisor.toml`) in directories it did not create today.
//! The grant is set through each entry's own handle, never through a link, as the Unix walk goes;
//! and what a former account was granted — a process account dropped or replaced, a Client's
//! account replaced — is withdrawn from it (`withdraw`), as a change of owner withdraws it on
//! Unix.

use std::path::{Path, PathBuf};

use super::manager::Registration;
use super::ServiceLevel;

/// Where the account a registration runs under came from (ADR-0042 clause 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `--run-as`.
    Flag,
    /// The unit or plist an earlier registration wrote, which names the account.
    Registered(PathBuf),
    /// The owner of the data root, because the registration names no account.
    DataRootOwner(PathBuf),
    /// No registration names one: root under systemd and launchd, `LocalSystem` or the account the
    /// SCM already holds on Windows.
    Default,
}

impl Source {
    /// The words the install prints after the account.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Flag => "named with --run-as".to_string(),
            Self::Registered(file) => format!("kept from {}", file.display()),
            Self::DataRootOwner(root) => format!(
                "the owner of the data root {}, because the registration names no account",
                root.display()
            ),
            Self::Default => "the default".to_string(),
        }
    }
}

/// The account a registration runs under, and where it came from.
#[derive(Debug)]
pub struct Decision {
    /// The resolved account; `None` where nothing is named — the user scope, and Windows without
    /// `--run-as`, where the SCM keeps the logon account it holds.
    pub run_as: Option<RunAs>,
    /// Where the account came from.
    pub source: Source,
}

/// Decide the account of a `service install` (ADR-0042 clause 2) and resolve it, before anything is
/// written: `--run-as`, else the account `registration` names, else — a registration that names
/// none, on a data root a non-root account owns — that owner, else root.
///
/// # Errors
/// Returns an error if the account does not exist (Unix) or is not one of the passwordless Windows
/// forms; the message names where a kept account came from.
pub fn decide(
    level: ServiceLevel,
    flag: Option<&str>,
    registration: Option<&Registration>,
    data_root: &Path,
    service: &str,
) -> Result<Decision, String> {
    if level == ServiceLevel::User {
        // A `--user` service runs as its user; `--run-as` conflicts with `--user`.
        return Ok(Decision {
            run_as: None,
            source: Source::Default,
        });
    }
    #[cfg(unix)]
    {
        let (account, source) =
            choose(flag, registration, data_root, || data_root_owner(data_root))?;
        let run_as = RunAs::resolve(&account, service, &source, data_root)?;
        Ok(Decision {
            run_as: Some(run_as),
            source,
        })
    }
    #[cfg(not(unix))]
    {
        match choose_on_windows(flag, registration) {
            Some((account, source)) => Ok(Decision {
                run_as: Some(RunAs::resolve(&account, service, &source, data_root)?),
                source,
            }),
            None => Ok(Decision {
                run_as: None,
                source: Source::Default,
            }),
        }
    }
}

/// The order on Windows: `--run-as`, else the logon account the SCM holds for the service, where
/// it holds one other than `LocalSystem`, which a registration that names none runs as. A
/// re-registration — an upgrade of the MSI among them — keeps the account, and with it what the
/// process account needs of it (ADR-0059 clause 1).
#[cfg(any(not(unix), test))]
fn choose_on_windows(
    flag: Option<&str>,
    registration: Option<&Registration>,
) -> Option<(String, Source)> {
    if let Some(account) = flag {
        return Some((account.to_string(), Source::Flag));
    }
    let registration = registration?;
    let account = registration.account.as_ref()?;
    let system = crate::win32::known_account_sid(account)
        .is_some_and(|sid| sid.as_str() == crate::win32::LOCAL_SYSTEM);
    (!system).then(|| {
        (
            account.clone(),
            Source::Registered(registration.file.clone()),
        )
    })
}

/// The order of ADR-0042 clause 2, on what was found. `owner` names the data root's owner when it
/// is not root, and is asked only for a registration that names no account.
#[cfg(unix)]
fn choose(
    flag: Option<&str>,
    registration: Option<&Registration>,
    data_root: &Path,
    owner: impl FnOnce() -> Result<Option<String>, String>,
) -> Result<(String, Source), String> {
    if let Some(account) = flag {
        return Ok((account.to_string(), Source::Flag));
    }
    match registration {
        Some(Registration {
            file,
            account: Some(account),
        }) => Ok((account.clone(), Source::Registered(file.clone()))),
        Some(Registration { account: None, .. }) => Ok(match owner()? {
            Some(owner) => (owner, Source::DataRootOwner(data_root.to_path_buf())),
            None => ("root".to_string(), Source::Default),
        }),
        None => Ok(("root".to_string(), Source::Default)),
    }
}

/// The name of the account that owns `data_root`, or `None` where root owns it or it does not
/// exist yet.
///
/// # Errors
/// Returns an error if a non-root uid owns it that no account on this host carries — the install
/// then fails closed rather than falling back to root.
#[cfg(unix)]
fn data_root_owner(data_root: &Path) -> Result<Option<String>, String> {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(meta) = std::fs::symlink_metadata(data_root) else {
        return Ok(None);
    };
    if meta.uid() == 0 {
        return Ok(None);
    }
    match account_of(meta.uid()).map(|found| found.map(|account| account.name)) {
        Ok(Some(name)) => Ok(Some(name)),
        Ok(None) => Err(format!(
            "the data root {} is owned by uid {}, which no account on this host carries, and the \
             registration names no account. Name one with --run-as <account> or --run-as root. \
             Nothing has been installed or written.",
            data_root.display(),
            meta.uid()
        )),
        Err(e) => Err(format!(
            "cannot name the owner (uid {}) of {}: {e}",
            meta.uid(),
            data_root.display()
        )),
    }
}

/// What the password database says of one uid.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub home: PathBuf,
    /// The primary group.
    pub gid: u32,
}

/// The account of `uid`, through `getpwuid_r(3)`; `None` where no entry names it.
///
/// # Errors
/// Returns the error the lookup failed with.
#[cfg(unix)]
pub fn account_of(uid: u32) -> std::io::Result<Option<Account>> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buffer = vec![0 as libc::c_char; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call and the buffer's length is the one passed;
        // `found` is either null or points at `entry`, whose strings live in `buffer`.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut found,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: `found` points at the filled `entry`, and `pw_name` and `pw_dir` at
        // NUL-terminated strings inside `buffer`, which outlives these reads.
        let (name, home, gid) = unsafe {
            (
                std::ffi::CStr::from_ptr((*found).pw_name),
                std::ffi::CStr::from_ptr((*found).pw_dir),
                (*found).pw_gid,
            )
        };
        return Ok(Some(Account {
            name: name.to_string_lossy().into_owned(),
            home: PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes())),
            gid,
        }));
    }
}

/// The members the group database lists for the group `gid` (`gr_mem`, through `getgrgid_r(3)`):
/// the accounts that hold it as a supplementary group. Empty where no entry names the group.
#[cfg(unix)]
fn group_members(gid: u32) -> std::io::Result<Vec<String>> {
    let mut buffer = vec![0 as libc::c_char; 4096];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut found: *mut libc::group = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call and the buffer's length is the one passed;
        // `found` is either null or points at `entry`, whose strings live in `buffer`.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut found,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1 << 24 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        if found.is_null() {
            return Ok(Vec::new());
        }
        let mut members = Vec::new();
        // SAFETY: `gr_mem` is a null-terminated array of NUL-terminated strings inside `buffer`,
        // which outlives these reads. Each slot is read unaligned: where in the buffer
        // `getgrgid_r` places the array is the libc's choice — glibc aligns it, macOS places it
        // at an offset that follows from the lengths of what it copied there first — so no
        // alignment of the buffer itself makes it aligned.
        unsafe {
            let mut member = (*found).gr_mem;
            while !member.is_null() {
                let name = member.read_unaligned();
                if name.is_null() {
                    break;
                }
                members.push(
                    std::ffi::CStr::from_ptr(name)
                        .to_string_lossy()
                        .into_owned(),
                );
                member = member.add(1);
            }
        }
        return Ok(members);
    }
}

/// The accounts, by name and uid, whose primary group is `gid`, as the password database
/// enumerates them (`getpwent(3)`). A directory service that does not enumerate its accounts is
/// read for the local ones alone.
#[cfg(unix)]
fn primary_group_of(gid: u32) -> Vec<(String, u32)> {
    // `getpwent` walks one cursor per process: no two walks at once.
    static WALK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _walk = WALK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut accounts = Vec::new();
    // SAFETY: the cursor is held under `WALK` from `setpwent` to `endpwent`, each entry is read
    // before the next call, and `pw_name` is a NUL-terminated string in that entry.
    unsafe {
        libc::setpwent();
        loop {
            let entry = libc::getpwent();
            if entry.is_null() {
                break;
            }
            if (*entry).pw_gid == gid {
                accounts.push((
                    std::ffi::CStr::from_ptr((*entry).pw_name)
                        .to_string_lossy()
                        .into_owned(),
                    (*entry).pw_uid,
                ));
            }
        }
        libc::endpwent();
    }
    accounts
}

/// An account the service may run as — validated (Windows) or resolved (Unix), never taken on
/// faith from the command line or from a file.
#[derive(Debug, Clone)]
pub struct RunAs {
    account: String,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(windows)]
    sid: crate::win32::Sid,
}

impl RunAs {
    /// Validate `account` against the platform's rules and resolve what the handover needs.
    /// `service` is the service's name, which is the product's (ADR-0019 clause 3) — on Windows the
    /// one virtual account that may be named is the service's own. `source` and `data_root` go into
    /// the refusal of an account that does not exist.
    ///
    /// # Errors
    /// Returns an error if the account does not exist (Unix) or is not one of the passwordless
    /// Windows forms — in both cases before the install has written anything.
    pub fn resolve(
        account: &str,
        service: &str,
        source: &Source,
        data_root: &Path,
    ) -> Result<Self, String> {
        #[cfg(unix)]
        {
            let _ = service;
            let (uid, gid) = resolve_unix(account).map_err(|missing| {
                missing_account(account, source, data_root, missing.as_deref())
            })?;
            Ok(Self {
                account: account.to_string(),
                uid,
                gid,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (source, data_root);
            windows_account_form(account, service)?;
            Ok(Self {
                account: account.to_string(),
                #[cfg(windows)]
                sid: windows_sid(account)?,
            })
        }
    }

    /// The account's SID, resolved once, before the install has written anything.
    #[cfg(windows)]
    #[must_use]
    pub fn sid(&self) -> &crate::win32::Sid {
        &self.sid
    }

    /// The account as the service manager must be told it.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The account's uid.
    #[cfg(unix)]
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Hand the given paths over to the account — recursively, skipping paths that do not exist
    /// (a configuration file the operator has not written yet is a warning elsewhere, not a
    /// failure here), and a path inside one handed over before it in the same call, which that
    /// walk covered without following a link. The handover is idempotent.
    ///
    /// Where `process` names a process account, its data is left alone (ADR-0059 clause 10): an
    /// entry it owns is skipped with everything beneath it, and an entry in its primary group
    /// keeps that group, a directory its mode too, so a re-registration takes from no Managed
    /// Process what it wrote or reads. Without one, everything is re-owned, group included.
    ///
    /// Returns what was left as it was and is to be named in a warning (Unix): the regular files
    /// with a second hard link — another name for the file may stand outside the roots, and
    /// re-owning it would hand that over too — and each of `paths` the process account owns,
    /// which an operator who names it as a root means the Client to have.
    ///
    /// # Errors
    /// Returns an error naming the first path that could not be handed over.
    pub fn hand_over(
        &self,
        paths: &[&Path],
        process: Option<&ProcessAccount>,
    ) -> Result<Vec<Skipped>, String> {
        let mut skipped = Vec::new();
        let mut walked: Vec<&Path> = Vec::new();
        for path in paths {
            if walked.iter().any(|done| path.starts_with(done))
                || std::fs::symlink_metadata(path).is_err()
            {
                continue;
            }
            self.own(path, process, &mut skipped).map_err(|e| {
                format!(
                    "cannot hand {} over to {}: {e}",
                    path.display(),
                    self.account
                )
            })?;
            walked.push(path);
        }
        Ok(skipped)
    }

    #[cfg(unix)]
    fn own(
        &self,
        path: &Path,
        process: Option<&ProcessAccount>,
        skipped: &mut Vec<Skipped>,
    ) -> std::io::Result<()> {
        let kept = process.map(|process| walk::Kept {
            uid: process.uid,
            gid: process.gid,
        });
        walk::chown_tree(path, self.uid, self.gid, kept, skipped)
    }

    /// On Windows a grant on every entry, each set through its own handle: it never enters a link
    /// or a junction, which is granted as itself, and leaves what the process account owns, with
    /// everything beneath it, as it is (ADR-0059 clause 10).
    #[cfg(windows)]
    fn own(
        &self,
        path: &Path,
        process: Option<&ProcessAccount>,
        skipped: &mut Vec<Skipped>,
    ) -> Result<(), String> {
        use crate::win32::files::{grant_tree, Access, Entry, Passed};
        let sid = &self.sid;
        let [on_dir, on_file] = handover_aces(sid.as_str(), process.is_some());
        let skip = process.map(ProcessAccount::sid);
        // For as short as the hand-over takes: what a Managed Process protected from the
        // Administrators is opened all the same, to be told apart.
        let _privileges = crate::win32::BackupPrivileges::enable()
            .map_err(|e| format!("cannot enable the backup and restore privileges: {e}"))?;
        let top = Entry::open(path, Access::Dacl, true).map_err(|e| e.to_string())?;
        if top.link {
            return Err(format!(
                "{} is a link or a junction, and a root is handed over as no link",
                path.display()
            ));
        }
        if skip.is_some_and(|skip| top.owner().ok().as_ref() == Some(skip)) {
            skipped.push(Skipped::ProcessAccounts(path.to_path_buf()));
            return Ok(());
        }
        let on_top = if top.dir { &on_dir } else { &on_file };
        let passed = grant_tree(
            &top,
            sid.as_str(),
            [on_top.as_slice(), on_dir.as_slice(), on_file.as_slice()],
            skip,
            true,
        )
        .map_err(|e| e.to_string())?;
        skipped.extend(passed.into_iter().map(|passed| match passed {
            Passed::Owned(path) => Skipped::ProcessAccounts(path),
            Passed::HardLinked(path) => Skipped::HardLinked(path),
            Passed::Unreadable(path) | Passed::Held(path) => Skipped::Unreadable(path),
        }));
        Ok(())
    }
}

/// The ACEs the hand-over grants the Client's account `sid` on Windows, for a directory and for a
/// file: modify, inherited by what a directory holds, and where a process account is registered
/// `WRITE_DAC` beside it — the Client grants that account its share of what the install laid out
/// (ADR-0059 clause 6), on directories the install, not the Client, made — and never `WRITE_OWNER`.
#[cfg(any(windows, test))]
fn handover_aces(sid: &str, process_account: bool) -> [Vec<String>; 2] {
    use crate::win32::acl::{allow, MODIFY, WRITE_DAC};
    let mask = if process_account {
        MODIFY | WRITE_DAC
    } else {
        MODIFY
    };
    [vec![allow(sid, mask, "OICI")], vec![allow(sid, mask, "")]]
}

/// Resolve an account name to its uid and primary gid through `id(1)`. `Err(None)` means the
/// account does not exist; `Err(Some(..))` that `id(1)` could not be asked or answered oddly.
#[cfg(unix)]
fn resolve_unix(account: &str) -> Result<(u32, u32), Option<String>> {
    let uid = id(account, "-u")?;
    let gid = id(account, "-g")?;
    Ok((uid, gid))
}

#[cfg(unix)]
fn id(account: &str, flag: &str) -> Result<u32, Option<String>> {
    let output = std::process::Command::new("id")
        .arg(flag)
        .arg("--")
        .arg(account)
        .output()
        .map_err(|e| Some(format!("cannot run id(1): {e}")))?;
    if !output.status.success() {
        return Err(None);
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|e| Some(format!("cannot read what id(1) said: {e}")))
}

/// The refusal of an account that does not exist (ADR-0042 clause 2): it names the account and,
/// for a kept one, the file it came from, shows the line that creates it, and names the flag that
/// names another.
#[cfg(unix)]
fn missing_account(
    account: &str,
    source: &Source,
    data_root: &Path,
    failure: Option<&str>,
) -> String {
    if let Some(failure) = failure {
        return format!(
            "cannot resolve the account {account}: {failure}. Nothing has been installed or \
             written."
        );
    }
    let which = match source {
        Source::Registered(file) => format!(
            "the account {account}, which {} names, does not exist on this host",
            file.display()
        ),
        Source::DataRootOwner(root) => format!(
            "the account {account}, which owns the data root {}, does not exist on this host",
            root.display()
        ),
        Source::Flag | Source::Default => {
            format!("the account {account} does not exist on this host")
        }
    };
    format!(
        "{which}. Create it first (`useradd --system --user-group --no-create-home --home-dir {} \
         --shell /usr/sbin/nologin {account}`), or name another with --run-as <account> or \
         --run-as root. Nothing has been installed or written.",
        data_root.display()
    )
}

/// What the hand-over left as it was, to be named in a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skipped {
    /// A regular file with a second hard link (ADR-0042 clause 2).
    HardLinked(PathBuf),
    /// One of the paths handed over, which the process account owns: left to it with everything
    /// beneath it (ADR-0059 clause 10).
    ProcessAccounts(PathBuf),
    /// An entry that could not be opened to be handed over (Windows).
    Unreadable(PathBuf),
}

impl Skipped {
    /// The warning that names it, for a hand-over to `account`.
    #[must_use]
    pub fn warning(&self, account: &str) -> String {
        match self {
            Skipped::HardLinked(path) => format!(
                "{} has a second hard link and was not handed over to {account}",
                path.display()
            ),
            Skipped::ProcessAccounts(path) => format!(
                "{} belongs to the process account and was not handed over to {account}, nor \
                 anything beneath it; if the Client is to own it, hand it over with chown",
                path.display()
            ),
            Skipped::Unreadable(path) => format!(
                "{} could not be opened and was not handed over to {account}",
                path.display()
            ),
        }
    }
}

/// The account every Managed Process runs under, through the second service (ADR-0059 clause 1):
/// decided and checked before anything is written, like the Client's own.
#[derive(Debug, Clone)]
pub struct ProcessAccount {
    account: String,
    #[cfg(unix)]
    uid: u32,
    /// The primary group: what the Client shares with the Managed Processes belongs to it
    /// (ADR-0059 clause 6).
    #[cfg(unix)]
    gid: u32,
    /// Its SID, which the Client accepts as the owner of the second service's pipe, and which the
    /// Client's shares are granted to (ADR-0059 clauses 4 and 6).
    #[cfg(windows)]
    sid: crate::win32::Sid,
    /// The SID of the Client's account, the one client the second service serves.
    #[cfg(windows)]
    client_sid: crate::win32::Sid,
    /// The second service's unit it was kept from; `None` where `--process-account` named it.
    kept_from: Option<PathBuf>,
}

impl ProcessAccount {
    /// The account as the service manager must be told it.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The account's uid, the one the Client accepts as the second service.
    #[cfg(unix)]
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The account's SID, the one the Client accepts as the second service.
    #[cfg(windows)]
    #[must_use]
    pub fn sid(&self) -> &crate::win32::Sid {
        &self.sid
    }

    /// The SID of the Client's account, which the second service serves.
    #[cfg(windows)]
    #[must_use]
    pub fn client_sid(&self) -> &crate::win32::Sid {
        &self.client_sid
    }

    /// Grants the account read and execute on the layout's `versions` directory and what it
    /// holds, and on nothing else of the layout: the second service runs
    /// `current\supervisor.exe` from it, and a root the install took over or cut off grants it
    /// nothing (ADR-0059 clause 2). A version the self-update stages there later inherits the
    /// grant. On Unix the layout is world-readable, as a program's directory is.
    ///
    /// # Errors
    /// Returns why the grant could not be made.
    #[cfg(windows)]
    pub fn share_layout(&self, versions: &Path) -> Result<(), String> {
        use crate::win32::acl::{allow, READ_EXECUTE};
        use crate::win32::files::{grant_tree, Access, Entry};
        let failed = |e: std::io::Error| format!("cannot share {}: {e}", versions.display());
        let _privileges = crate::win32::BackupPrivileges::enable().map_err(failed)?;
        let top = Entry::open(versions, Access::Dacl, true).map_err(failed)?;
        if !top.dir {
            return Err(format!("{} is a link or no directory", versions.display()));
        }
        let sid = self.sid.as_str();
        let on_dir = [allow(sid, READ_EXECUTE, "OICI")];
        let on_file = [allow(sid, READ_EXECUTE, "")];
        grant_tree(&top, sid, [&on_dir, &on_dir, &on_file], None, true).map_err(failed)?;
        Ok(())
    }

    /// The account's primary group, which the directory of the second service's socket is given.
    #[cfg(unix)]
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The words the install prints after the account.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.kept_from {
            Some(unit) => format!("kept from {}", unit.display()),
            None => "named with --process-account".to_string(),
        }
    }
}

/// What the checks of ADR-0059 clause 1 read of an account, as `id(1)` answers for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    /// The primary group.
    pub gid: u32,
    /// The primary group's name.
    pub group: String,
    /// Every group the account is in, the primary one included.
    pub groups: Vec<u32>,
    /// The primary group's members, as the group database lists them: the accounts that hold it
    /// as a supplementary group. Read for the process account alone.
    pub members: Vec<String>,
    /// The accounts, by name and uid, whose primary group the primary group is — the account
    /// itself among them. Read for the process account alone.
    pub primary_of: Vec<(String, u32)>,
}

/// Decide the process account of a `service install` (ADR-0059 clause 1) and check it against the
/// Client's account `client`, before anything is written: none where `dropped`
/// (`--no-process-account`), else `--process-account`, else the account `registration` — the
/// second service's unit — names, else none, and no second service. `supported` says whether this
/// host can register the second service at all.
///
/// # Errors
/// Returns why the account is refused: where a second service cannot be registered, root, a
/// Client that runs as root, an account that does not exist, the Client's own account, one whose
/// primary group is root's or the Client's primary group, one in the Client's primary group, one
/// whose primary group the Client's account is not in, and one whose primary group has a member
/// other than the Client's account or is the primary group of another account.
pub fn decide_process_account(
    flag: Option<&str>,
    dropped: bool,
    registration: Option<&Registration>,
    client: Option<&RunAs>,
    supported: bool,
) -> Result<Option<ProcessAccount>, String> {
    if dropped {
        return Ok(None);
    }
    let Some((account, kept_from)) = choose_process_account(flag, registration)? else {
        return Ok(None);
    };
    let unsupported = || {
        format!(
            "a process account needs the second service, which only a system service under \
             systemd on Linux, launchd on macOS or the SCM on Windows registers; {account} cannot \
             be named here. Nothing has been installed or written."
        )
    };
    if !supported {
        return Err(unsupported());
    }
    #[cfg(unix)]
    {
        // A system service on Unix always names its account; a user service names none.
        let Some(client) = client else {
            return Err(unsupported());
        };
        // The account goes into the second service's unit: one that cannot be written there is
        // refused here, before the install writes anything, not when the unit is rendered.
        super::manager::check_unit_account(&account)
            .map_err(|e| format!("{e}. Nothing has been installed or written."))?;
        let found = account_ids(&account, true)?;
        let client_ids = account_ids(client.account(), false)?.ok_or_else(|| {
            format!(
                "the Client's account {} cannot be resolved. Nothing has been installed or \
                 written.",
                client.account()
            )
        })?;
        check_process_account(
            &account,
            found.as_ref(),
            client.account(),
            &client_ids,
            kept_from.as_deref(),
        )?;
        let (uid, gid) = found.map_or((0, 0), |ids| (ids.uid, ids.gid));
        Ok(Some(ProcessAccount {
            account,
            uid,
            gid,
            kept_from,
        }))
    }
    #[cfg(windows)]
    {
        let named = |e: String| refuse_on_windows(&account, kept_from.as_deref(), &e);
        // No account: `--run-as` named none, and the SCM holds none but LocalSystem — a first
        // registration runs as LocalSystem — so a process account has nothing to be apart from.
        let Some(client) = client else {
            return Err(named(format!(
                "the Client runs as LocalSystem unless --run-as names its account, and a process \
                 account separates the Managed Processes from a Client that runs under an account \
                 of its own. Name the Client's account with --run-as NT SERVICE\\{}",
                super::manager::service_name()
            )));
        };
        let agents = super::manager::agents_service_name();
        let sid = windows_sid(&account).map_err(named)?;
        let client_sid = client.sid().clone();
        check_windows_process_account(&account, &sid, &agents, client.account(), &client_sid)
            .map_err(named)?;
        Ok(Some(ProcessAccount {
            account,
            sid,
            client_sid,
            kept_from,
        }))
    }
}

/// The SID of an account in one of the passwordless forms: known from its name where it can be,
/// else — a group-managed service account — looked up.
///
/// # Errors
/// Returns that the account does not exist.
#[cfg(windows)]
fn windows_sid(account: &str) -> Result<crate::win32::Sid, String> {
    match crate::win32::known_account_sid(account) {
        Some(sid) => Ok(sid),
        None => crate::win32::lookup_account(account)
            .map_err(|e| format!("{account} cannot be found on this host or its domain ({e})")),
    }
}

/// The SID of the account `former` a registration names, where what it was granted is to be
/// withdrawn (ADR-0059 clauses 1 and 6): none where there is no former account, where it is named
/// as one of `current` — the accounts the registration names now, each with its SID — or resolves
/// to one of their SIDs, or where it is `LocalSystem`, which keeps full control of every root
/// anyway. An account named as before is not looked up again.
///
/// # Errors
/// Returns that `former` cannot be resolved — a group-managed service account whose domain cannot
/// be reached among them — before the install has changed anything: what it was granted would
/// otherwise stay granted.
#[cfg(windows)]
pub fn former_sid(
    former: Option<&str>,
    current: &[(&str, &crate::win32::Sid)],
) -> Result<Option<crate::win32::Sid>, String> {
    let Some(former) = former else {
        return Ok(None);
    };
    if current
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(former))
    {
        return Ok(None);
    }
    let sid = windows_sid(former).map_err(|e| {
        format!(
            "what the former account {former} was granted cannot be withdrawn: {e}. Nothing was \
             changed; run the install again once it can be found"
        )
    })?;
    if sid.as_str() == crate::win32::LOCAL_SYSTEM || current.iter().any(|(_, kept)| **kept == sid) {
        return Ok(None);
    }
    Ok(Some(sid))
}

/// Withdraws from the account of SID `former` — a process account dropped or replaced, or a
/// Client's account replaced — what it was granted in `roots` and what it owns there, on Windows
/// (ADR-0059 clauses 1, 6 and 10): every ACE that allows it, explicit or inherited, on every entry,
/// and what it owns given to the Administrators, as Unix withdraws it by a change of owner. Nothing
/// where `former` is `LocalSystem`, which keeps full control of every root anyway. A root, or a
/// root within one walked already, is walked once, never through a link and never into one.
///
/// # Errors
/// Returns an error naming the first entry whose owner or DACL could not be changed.
#[cfg(windows)]
pub fn withdraw(former: &crate::win32::Sid, roots: &[&Path]) -> Result<Vec<Skipped>, String> {
    use crate::win32::files::{withdraw_tree, Access, Entry, Passed};
    if former.as_str() == crate::win32::LOCAL_SYSTEM {
        return Ok(Vec::new());
    }
    let failed = |root: &Path, e: std::io::Error| {
        format!("cannot withdraw {} from {former}: {e}", root.display())
    };
    let _privileges = crate::win32::BackupPrivileges::enable()
        .map_err(|e| format!("cannot enable the backup and restore privileges: {e}"))?;
    let mut skipped = Vec::new();
    let mut walked: Vec<&Path> = Vec::new();
    for root in roots {
        if walked.iter().any(|done| root.starts_with(done))
            || std::fs::symlink_metadata(root).is_err()
        {
            continue;
        }
        let top = Entry::open(root, Access::Owner, true).map_err(|e| failed(root, e))?;
        if top.link {
            return Err(format!("{} is a link or a junction", root.display()));
        }
        let passed = withdraw_tree(&top, former, "BA").map_err(|e| failed(root, e))?;
        skipped.extend(passed.into_iter().map(|passed| match passed {
            Passed::Owned(path) | Passed::Unreadable(path) | Passed::Held(path) => {
                Skipped::Unreadable(path)
            }
            Passed::HardLinked(path) => Skipped::HardLinked(path),
        }));
        walked.push(root);
    }
    Ok(skipped)
}

/// The refusal of the process account `account`, kept from `kept_from` or named, for `reason`.
#[cfg(windows)]
fn refuse_on_windows(account: &str, kept_from: Option<&Path>, reason: &str) -> String {
    let named = match kept_from {
        Some(from) => format!(
            "the process account {account}, which {} names,",
            from.display()
        ),
        None => format!("the process account {account}"),
    };
    let drop = if kept_from.is_some() {
        format!(" Or drop it with {DROP}")
    } else {
        String::new()
    };
    format!("{named} is refused: {reason}.{drop} {NOTHING}")
}

/// The checks of ADR-0059 clause 1 on Windows: the process account `account`, of SID `sid`, is one
/// of the passwordless forms — the second service `agents`'s own virtual account, a gMSA,
/// `LocalService` or `NetworkService` — never `LocalSystem`, and never the Client's account
/// `client`, of SID `client_sid`, which itself is not `LocalSystem`.
///
/// # Errors
/// Returns the reason, with the way out.
#[cfg(any(windows, test))]
pub(crate) fn check_windows_process_account(
    account: &str,
    sid: &crate::win32::Sid,
    agents: &str,
    client: &str,
    client_sid: &crate::win32::Sid,
) -> Result<(), String> {
    if sid.as_str() == crate::win32::LOCAL_SYSTEM {
        return Err(
            "it is LocalSystem, and a process account never is. A host whose agents need \
             LocalSystem runs as LocalSystem as a whole: no --process-account"
                .to_string(),
        );
    }
    if client_sid.as_str() == crate::win32::LOCAL_SYSTEM {
        return Err(format!(
            "the Client runs as LocalSystem ({client}), and a process account separates the \
             Managed Processes from a Client that runs under an account of its own. Name the \
             Client's account with --run-as <account>, or run everything as LocalSystem without \
             --process-account"
        ));
    }
    if sid == client_sid {
        return Err(format!(
            "it is the account the Client runs as ({client}); the process account is another \
             account, which the Client's does not share"
        ));
    }
    windows_account_form(account, agents)
}

/// The order of ADR-0059 clause 1, on what was found: the flag, else the account the second
/// service's unit names, with that unit, else none.
fn choose_process_account(
    flag: Option<&str>,
    registration: Option<&Registration>,
) -> Result<Option<(String, Option<PathBuf>)>, String> {
    if let Some(account) = flag {
        return Ok(Some((account.to_string(), None)));
    }
    match registration {
        Some(Registration {
            file,
            account: Some(account),
        }) => Ok(Some((account.clone(), Some(file.clone())))),
        Some(Registration {
            file,
            account: None,
        }) => Err(format!(
            "{} names no account for the second service. Name one with --process-account \
             <account>, or drop it with {DROP} Nothing has been installed or written.",
            file.display()
        )),
        None => Ok(None),
    }
}

/// How a refusal that a kept process account causes names the way to drop it (ADR-0059 clause 1).
const DROP: &str = "--no-process-account, and the Client starts its Managed Processes itself.";

/// The checks of ADR-0059 clause 1 on the process account `account` — `found` as `id(1)` answers
/// for it, `None` where it does not exist — against the Client's account `client_name` with
/// `client`. `kept_from` is the unit a kept account came from.
///
/// # Errors
/// Returns the refusal, with the way out.
pub fn check_process_account(
    account: &str,
    found: Option<&Ids>,
    client_name: &str,
    client: &Ids,
    kept_from: Option<&Path>,
) -> Result<(), String> {
    check_process_account_on(Host::THIS, account, found, client_name, client, kept_from)
}

/// The tools an operator changes accounts and groups with, which a refusal names (ADR-0059
/// clause 1): the shadow utilities on Linux, the directory service's on macOS. The binary runs
/// none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Host {
    /// `useradd`, `usermod`, `gpasswd`.
    Linux,
    /// `sysadminctl -roleAccount`, `dseditgroup`, `dscl`.
    MacOs,
}

impl Host {
    /// This host's.
    pub const THIS: Host = if cfg!(target_os = "macos") {
        Host::MacOs
    } else {
        Host::Linux
    };

    /// The lines that create `account` with a primary group of its own and make that group one
    /// of `client`'s. On macOS the group is created first and named in the account's `-GID`, so
    /// it is the account's own rather than `staff`; a role account's name begins with `_`, and
    /// `sysadminctl` says which uids it allows one.
    fn create(self, account: &str, client: &str) -> String {
        match self {
            Host::Linux => format!(
                "`useradd --system --user-group --no-create-home --shell /usr/sbin/nologin \
                 {account}`) and make its group one of the Client's (`{}`)",
                self.add(client, account)
            ),
            Host::MacOs => format!(
                "`dseditgroup -o create -i <gid> {account}`, then `sysadminctl -addUser {account} \
                 -UID <uid> -GID <gid> -roleAccount`, with a gid and a uid no group or account \
                 holds; a role account's name begins with `_`) and make its group one of the \
                 Client's (`{}`)",
                self.add(client, account)
            ),
        }
    }

    /// The line that adds `member` to `group`.
    fn add(self, member: &str, group: &str) -> String {
        match self {
            Host::Linux => format!("usermod --append --groups {group} {member}"),
            Host::MacOs => format!("dseditgroup -o edit -a {member} -t user {group}"),
        }
    }

    /// The line that removes `member` from `group`.
    fn remove(self, member: &str, group: &str) -> String {
        match self {
            Host::Linux => format!("gpasswd --delete {member} {group}"),
            Host::MacOs => format!("dseditgroup -o edit -d {member} -t user {group}"),
        }
    }

    /// How `account` gets a primary group of its own.
    fn own_group(self, account: &str) -> String {
        match self {
            Host::Linux => "`useradd --user-group`".to_string(),
            Host::MacOs => format!(
                "`dseditgroup -o create -i <gid> {account}`, then `dscl . -create \
                 /Users/{account} PrimaryGroupID <gid>`"
            ),
        }
    }
}

/// [`check_process_account`], its refusals naming the tools of `host`.
///
/// # Errors
/// Returns the refusal, with the way out.
pub(crate) fn check_process_account_on(
    host: Host,
    account: &str,
    found: Option<&Ids>,
    client_name: &str,
    client: &Ids,
    kept_from: Option<&Path>,
) -> Result<(), String> {
    refuse_process_account(host, account, found, client_name, client, kept_from).map_err(
        |refusal| {
            // A kept account was not asked for in this install: the refusal says how to drop it.
            match (kept_from, refusal.strip_suffix(NOTHING)) {
                (Some(_), Some(reason)) => format!("{reason}Or drop it with {DROP} {NOTHING}"),
                _ => refusal,
            }
        },
    )
}

const NOTHING: &str = "Nothing has been installed or written.";

fn refuse_process_account(
    host: Host,
    account: &str,
    found: Option<&Ids>,
    client_name: &str,
    client: &Ids,
    kept_from: Option<&Path>,
) -> Result<(), String> {
    let named = match kept_from {
        Some(unit) => format!(
            "the process account {account}, which {} names,",
            unit.display()
        ),
        None => format!("the process account {account}"),
    };
    if account == "root" || found.is_some_and(|ids| ids.uid == 0) {
        return Err(format!(
            "{named} is root, and a process account never is. A host whose agents need root runs \
             as root as a whole: --run-as root, and no --process-account. {NOTHING}"
        ));
    }
    if client.uid == 0 {
        return Err(format!(
            "the Client runs as root, and a process account separates the Managed Processes from \
             a Client that runs under an account of its own. Name the Client's account with \
             --run-as <account>, or run everything as root without --process-account. {NOTHING}"
        ));
    }
    let Some(found) = found else {
        return Err(format!(
            "{named} does not exist on this host. Create it first ({}), or name another with \
             --process-account <account>. {NOTHING}",
            host.create(account, client_name)
        ));
    };
    if found.uid == client.uid {
        return Err(format!(
            "{named} is the account the Client runs as ({client_name}). The process account is \
             another account, which the Client's does not share. {NOTHING}"
        ));
    }
    // What the process account's primary group may read is what the Managed Processes may read
    // (ADR-0059 clause 6): never root's group, and never a group that reaches the Client's files.
    if found.gid == 0 {
        return Err(format!(
            "{named} has the primary group {} (gid 0), and a process account's group is never \
             root's. Give it a group of its own ({}), then install again. {NOTHING}",
            found.group,
            host.own_group(account)
        ));
    }
    if found.gid == client.gid {
        return Err(format!(
            "{named} has the primary group {}, which is the primary group of the Client's account \
             {client_name}: the Managed Processes would read what the Client's group may. Give it \
             a group of its own ({}), then install again. {NOTHING}",
            found.group,
            host.own_group(account)
        ));
    }
    if found.groups.contains(&client.gid) {
        return Err(format!(
            "{named} is a member of the primary group of the Client's account {client_name}: the \
             Managed Processes would read what the Client's group may. Remove it from that group \
             (`{}`), then install again. {NOTHING}",
            host.remove(account, &client.group)
        ));
    }
    if !client.groups.contains(&found.gid) {
        return Err(format!(
            "{named} has the primary group {}, and the Client's account {client_name} is not in \
             it. Add it (`{}`), then install again. {NOTHING}",
            found.group,
            host.add(client_name, &found.group)
        ));
    }
    // The group is the process account's own: whoever else holds it reads what every Managed
    // Process reads, and a Managed Process what the other account's files grant its group. The
    // process account itself, listed as a member of its own group, is no one else.
    if let Some(other) = found
        .members
        .iter()
        .find(|member| *member != client_name && *member != account)
    {
        return Err(format!(
            "{named} has the primary group {group}, and {other} is a member of it beside the \
             Client's account {client_name}: {other} would read what the Managed Processes read. \
             Remove it (`{}`), or give the process account a group of its own, then install \
             again. {NOTHING}",
            host.remove(other, &found.group),
            group = found.group
        ));
    }
    if let Some((other, _)) = found.primary_of.iter().find(|(_, uid)| *uid != found.uid) {
        return Err(format!(
            "{named} has the primary group {group}, which is also the primary group of {other}: \
             the Managed Processes would share it with that account. Give the process account a \
             group of its own ({}), then install again. {NOTHING}",
            host.own_group(account),
            group = found.group
        ));
    }
    Ok(())
}

/// What `id(1)` answers for `account`; `None` where it does not exist. With `holders`, who else
/// holds its primary group too: the members and the accounts it is the primary group of, which
/// only the process account's checks read.
#[cfg(unix)]
fn account_ids(account: &str, holders: bool) -> Result<Option<Ids>, String> {
    let failed = |e: String| format!("cannot resolve the account {account}: {e}");
    let uid = match id(account, "-u") {
        Ok(uid) => uid,
        Err(None) => return Ok(None),
        Err(Some(e)) => return Err(failed(e)),
    };
    let gid =
        id(account, "-g").map_err(|e| failed(e.unwrap_or_else(|| "id -g failed".to_string())))?;
    let group = id_text(account, "-gn").map_err(failed)?;
    let groups = id_text(account, "-G")
        .map_err(failed)?
        .split_whitespace()
        .filter_map(|g| g.parse().ok())
        .collect();
    let (members, primary_of) = if holders {
        (
            group_members(gid).map_err(|e| failed(e.to_string()))?,
            primary_group_of(gid),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(Some(Ids {
        uid,
        gid,
        group,
        groups,
        members,
        primary_of,
    }))
}

/// What `id(1)` prints with `flag` for `account`, trimmed.
#[cfg(unix)]
fn id_text(account: &str, flag: &str) -> Result<String, String> {
    let output = std::process::Command::new("id")
        .arg(flag)
        .arg("--")
        .arg(account)
        .output()
        .map_err(|e| format!("cannot run id(1): {e}"))?;
    if !output.status.success() {
        return Err(format!("id {flag} failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The handover walk on Unix: descriptors, never paths below the top (ADR-0042 clause 2, ADR-0054).
#[cfg(unix)]
mod walk {
    use std::ffi::{CStr, CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use super::Skipped;
    use crate::storage::handle::{entries, fstat, open};

    /// The entry a name stands for, opened as what it is and never through a link. On Linux this
    /// is a path-only handle: it holds a link, a device or a FIFO without opening what it is.
    #[cfg(target_os = "linux")]
    const ENTRY: libc::c_int = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// On macOS `O_SYMLINK` opens a link itself; anything else is opened without blocking on a
    /// FIFO or taking a terminal.
    #[cfg(target_os = "macos")]
    const ENTRY: libc::c_int =
        libc::O_RDONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    /// A directory already held, opened again for reading its entries.
    #[cfg(target_os = "linux")]
    const DIRECTORY: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    /// What the walk leaves to the process account (ADR-0059 clause 10): an entry `uid` owns is
    /// not re-owned and not entered, and an entry in the group `gid` keeps it.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Kept {
        pub(super) uid: u32,
        pub(super) gid: u32,
    }

    /// Re-own `path` and, if it is a directory, everything under it, without following a link.
    /// The top is the one name resolved as a path, and its last component is never followed.
    /// What `kept` names is left as [`Kept`] says.
    pub(super) fn chown_tree(
        path: &Path,
        uid: u32,
        gid: u32,
        kept: Option<Kept>,
        skipped: &mut Vec<Skipped>,
    ) -> io::Result<()> {
        chown_tree_with(path, uid, gid, kept, skipped, &|_| {})
    }

    /// `chown_tree`, calling `between` with each entry's path after its name was read from the
    /// directory and before the entry is opened: the window in which the account can swap it.
    pub(super) fn chown_tree_with(
        path: &Path,
        uid: u32,
        gid: u32,
        kept: Option<Kept>,
        skipped: &mut Vec<Skipped>,
        between: &dyn Fn(&Path),
    ) -> io::Result<()> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        let mut walk = Walk {
            uid,
            gid,
            kept,
            skipped,
            between,
        };
        walk.entry(libc::AT_FDCWD, &name, path)
    }

    /// Re-own the entry `name` in the directory `dir` holds, and nothing below it: through a
    /// handle on the entry itself, a link as a link. An entry that is no directory and has a
    /// second hard link is skipped, whoever owns it; one that already has the owner is left alone.
    /// A missing entry is nothing to do.
    pub(super) fn chown_entry(
        dir: RawFd,
        name: &OsStr,
        path: &Path,
        (uid, gid): (u32, u32),
        skipped: &mut Vec<std::path::PathBuf>,
    ) -> io::Result<()> {
        let name = CString::new(name.as_bytes())?;
        let handle = match open(dir, &name, ENTRY) {
            Ok(handle) => handle,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let st = fstat(&handle)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR && st.st_nlink > 1 {
            skipped.push(path.to_path_buf());
            return Ok(());
        }
        if (st.st_uid, st.st_gid) == (uid, gid) {
            return Ok(());
        }
        chown(&handle, uid, gid)
    }

    struct Walk<'a> {
        uid: u32,
        gid: u32,
        kept: Option<Kept>,
        skipped: &'a mut Vec<Skipped>,
        between: &'a dyn Fn(&Path),
    }

    impl Walk<'_> {
        /// Re-own the entry `name` in `dir` through a handle on the entry itself. Its type and its
        /// link count are read from that handle, and its owner is changed through it, so a name
        /// swapped after it was read changes only what the handle holds. A directory is walked;
        /// anything else with a second hard link is skipped. What the process account owns is
        /// neither re-owned nor walked, and what is in its group keeps that group; a directory
        /// keeps its mode, its set-group-ID bit included ([`Walk::directory`]).
        fn entry(&mut self, dir: RawFd, name: &CStr, path: &Path) -> io::Result<()> {
            let handle = match open(dir, name, ENTRY) {
                Ok(handle) => handle,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            let st = fstat(&handle)?;
            let gid = match self.kept {
                Some(kept) if st.st_uid == kept.uid => {
                    // A root the operator named is meant for the Client: said, not passed over.
                    if dir == libc::AT_FDCWD {
                        self.skipped
                            .push(Skipped::ProcessAccounts(path.to_path_buf()));
                    }
                    return Ok(());
                }
                Some(kept) if st.st_gid == kept.gid => kept.gid,
                _ => self.gid,
            };
            if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                return self.directory(handle, gid, path);
            }
            if st.st_nlink > 1 {
                self.skipped.push(Skipped::HardLinked(path.to_path_buf()));
                return Ok(());
            }
            chown(&handle, self.uid, gid)
        }

        /// Re-own the directory `handle` holds to the group `gid`, then its entries, read from the
        /// handle. Its mode stays as it was: macOS clears a directory's set-group-ID bit on a
        /// change of owner by anyone but root, even one that changes nothing, so a mode the change
        /// took is set again — the bit of a data directory of the process account's group
        /// (ADR-0059 clause 6) among it.
        fn directory(&mut self, handle: OwnedFd, gid: u32, path: &Path) -> io::Result<()> {
            // The path-only handle cannot list entries; `.` through it is that same directory.
            #[cfg(target_os = "linux")]
            let handle = match open(handle.as_raw_fd(), c".", DIRECTORY) {
                Ok(handle) => handle,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            let before = fstat(&handle)?.st_mode;
            chown(&handle, self.uid, gid)?;
            if fstat(&handle)?.st_mode != before {
                // SAFETY: a valid descriptor on the directory, opened to read.
                if unsafe { libc::fchmod(handle.as_raw_fd(), before & 0o7777) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for name in entries(&handle)? {
                let child = path.join(OsStr::from_bytes(name.as_bytes()));
                (self.between)(&child);
                self.entry(handle.as_raw_fd(), &name, &child)?;
            }
            Ok(())
        }
    }

    /// Re-own what `handle` holds, a link as a link. On Linux the handle may be path-only, which
    /// `fchown` refuses; an empty name with `AT_EMPTY_PATH` changes the handle's own entry.
    #[cfg(target_os = "linux")]
    fn chown(handle: &OwnedFd, uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: a valid descriptor and a NUL-terminated (empty) name.
        let rc = unsafe {
            libc::fchownat(
                handle.as_raw_fd(),
                c"".as_ptr(),
                uid,
                gid,
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Re-own what `handle` holds; a handle opened with `O_SYMLINK` holds the link itself.
    #[cfg(target_os = "macos")]
    fn chown(handle: &OwnedFd, uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: a valid descriptor.
        if unsafe { libc::fchown(handle.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Give each of `paths` the owner of `like`, the configuration of an installed Client: what
/// `service config` creates belongs to the account the service runs as (ADR-0019 clause 13), not
/// to the administrator who ran it. A missing path is skipped.
///
/// Each path is re-owned as what it is and nothing is walked: the state directory belongs to that
/// account, which could swap a directory for a link while root walked it, so the caller names
/// exactly the files it wrote. Nor is a link followed on the way (ADR-0054): each path's
/// directory is opened without following a link at its name, and the entry is re-owned through a
/// handle on it, a link as a link. The data root the administrator named, `data_root`, and the
/// configuration's own directory are the two directories reached as their paths say (ADR-0054
/// clause 4); every other is one the account could have swapped. A regular file with a second hard
/// link is skipped, as the handover skips one: another name for it may stand anywhere.
///
/// Returns the files skipped for a second hard link.
///
/// On Windows there is nothing to do: the handover granted the account Modify with inheritance, so
/// what is created under the data root is the account's to use already.
///
/// # Errors
/// Returns an error naming the path whose owner could not be changed, or whose directory is a link.
pub fn match_owner(like: &Path, data_root: &Path, paths: &[&Path]) -> Result<Vec<PathBuf>, String> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut skipped = Vec::new();
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        let Ok(owner) = std::fs::symlink_metadata(like) else {
            return Ok(skipped);
        };
        for path in paths {
            let refused = |e: std::io::Error| {
                format!(
                    "cannot give {} the owner of {}: {e}",
                    path.display(),
                    like.display()
                )
            };
            let held = match (path.parent(), path.file_name().and_then(|n| n.to_str())) {
                (Some(parent), Some(name))
                    if parent == data_root || Some(parent) == like.parent() =>
                {
                    crate::nofollow::HeldDir::open_root(parent).map(|dir| (dir, name))
                }
                _ => crate::nofollow::held_parent(path),
            };
            let (dir, name) = match held {
                Ok(held) => held,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(refused(e)),
            };
            walk::chown_entry(
                dir.as_raw_fd(),
                std::ffi::OsStr::new(name),
                path,
                (owner.uid(), owner.gid()),
                &mut skipped,
            )
            .map_err(refused)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (like, data_root, paths);
    Ok(skipped)
}

/// The passwordless Windows account forms — the only ones `--run-as` accepts, because a password
/// parameter must not exist (ADR-0019: it would stand in the process list and the installer log).
///
/// Compiled wherever it is used — the Windows install, and the tests of any platform: the rule is
/// pure string logic, and testing it must not need a Windows host.
#[cfg(any(windows, test))]
fn windows_account_form(account: &str, service: &str) -> Result<(), String> {
    const NT_SERVICE: &str = r"NT SERVICE\";
    const BUILT_IN: [&str; 2] = [r"NT AUTHORITY\LocalService", r"NT AUTHORITY\NetworkService"];

    if BUILT_IN.iter().any(|b| account.eq_ignore_ascii_case(b)) {
        return Ok(());
    }
    if let Some(name) = account
        .get(..NT_SERVICE.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(NT_SERVICE))
        .and_then(|_| account.get(NT_SERVICE.len()..))
    {
        if name.eq_ignore_ascii_case(service) {
            return Ok(());
        }
        return Err(format!(
            "the virtual account {account} belongs to another service — this service's own is \
             NT SERVICE\\{service}"
        ));
    }
    if account.ends_with('$') {
        // A group-managed service account: the domain manages its password, and grants its
        // *Log on as a service* right through group policy — not this install.
        return Ok(());
    }
    Err(format!(
        "the account {account} would need a password, and a password is never taken on a command \
         line. Passwordless forms: the service's own virtual account \
         (NT SERVICE\\{service}), a group-managed service account (name ending in $), NT \
         AUTHORITY\\LocalService, or NT AUTHORITY\\NetworkService."
    ))
}

/// The warning an install gives where the process account's rights are granted or withdrawn and
/// the Supervisors' root lies outside the roots it acts on (ADR-0059 clause 6): that root is the
/// operator's (ADR-0053 clause 5), left as it is. `None` where it is beneath them, or where no
/// process account is named and none was.
#[must_use]
pub fn supervisors_root_left(root: &Path, ours: bool, process_account: bool) -> Option<String> {
    (process_account && !ours).then(|| {
        format!(
            "warning: the Supervisors' root {} lies outside the data root, the layout root and \
             the state directory, and is left as it is: grant the process account what it is to \
             hold there, or withdraw what a former one held, yourself",
            root.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Supervisors' root outside the install's roots is named in a warning wherever a process
    /// account's rights are granted or withdrawn, and only there (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[test]
    fn a_supervisors_root_outside_the_roots_is_named_where_a_process_account_is_involved() {
        let root = Path::new("/srv/supervisors");
        let warning = supervisors_root_left(root, false, true).expect("a warning");
        assert!(warning.contains("/srv/supervisors"), "{warning}");
        assert_eq!(supervisors_root_left(root, true, true), None);
        assert_eq!(supervisors_root_left(root, false, false), None);
    }

    /// On Windows a re-registration keeps the logon account the SCM holds, as a unit's is kept,
    /// unless `--run-as` names another; `LocalSystem`, the account a registration that names none
    /// runs as, is no account kept (ADR-0059 clause 1).
    /// Verifies: ADR-0059
    #[test]
    fn on_windows_a_reregistration_keeps_the_scms_logon_account() {
        let key = PathBuf::from(r"HKLM\SYSTEM\CurrentControlSet\Services\opamp-fleet");
        let held = |account: &str| Registration {
            file: key.clone(),
            account: Some(account.to_string()),
        };
        assert_eq!(
            choose_on_windows(None, Some(&held(r"NT Service\opamp-fleet"))),
            Some((
                r"NT Service\opamp-fleet".to_string(),
                Source::Registered(key.clone())
            ))
        );
        assert_eq!(
            choose_on_windows(Some(r"NT AUTHORITY\LocalService"), Some(&held("x"))),
            Some((r"NT AUTHORITY\LocalService".to_string(), Source::Flag))
        );
        assert_eq!(choose_on_windows(None, Some(&held("LocalSystem"))), None);
        assert_eq!(choose_on_windows(None, None), None);
    }

    /// On Windows the hand-over enters no junction or symlink a Managed Process placed in its data
    /// directory, with a process account or without, and leaves what the process account owns as
    /// it is, with everything beneath it (ADR-0059 clause 10). This test's own account stands in
    /// for the process account, `LocalService` for the Client's.
    /// Verifies: ADR-0042, ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_the_handover_enters_no_junction_and_leaves_the_process_accounts_own() {
        use crate::win32::files::{Access, Entry};
        let me = crate::win32::own_sid().expect("own sid");
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let data = root.join("data");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&data).expect("data");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret"), b"x").expect("secret");
        let linked = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(data.join("link"))
            .arg(&outside)
            .status()
            .expect("run mklink");
        assert!(linked.success(), "cannot make the junction");
        let hard = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/H"])
            .arg(data.join("hard"))
            .arg(outside.join("secret"))
            .status()
            .expect("run mklink");
        assert!(hard.success(), "cannot make the hard link");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("elsewhere");
        let symlinked = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/D"])
            .arg(data.join("symlink"))
            .arg(&elsewhere)
            .status()
            .expect("run mklink");
        assert!(symlinked.success(), "cannot make the directory symlink");
        let owned = data.join("owned");
        std::fs::create_dir(&owned).expect("owned");
        std::fs::write(owned.join("state"), b"x").expect("state");
        Entry::open(&owned, Access::Owner, false)
            .and_then(|entry| entry.set_owner(me.as_str()))
            .expect("owned by the stand-in");
        let dacl = |path: &Path| {
            Entry::open(path, Access::Read, false)
                .and_then(|entry| entry.dacl())
                .expect("dacl")
                .text()
        };
        let before = (dacl(&outside), dacl(&outside.join("secret")), dacl(&owned));
        let elsewhere_before = dacl(&elsewhere);

        let client = RunAs::resolve(
            r"NT AUTHORITY\LocalService",
            "opamp-fleet",
            &Source::Flag,
            &root,
        )
        .expect("a passwordless form");
        let process = ProcessAccount {
            account: "stand-in".to_string(),
            sid: me.clone(),
            client_sid: crate::win32::Sid::parse(crate::win32::LOCAL_SERVICE).expect("sid"),
            kept_from: None,
        };
        // A Managed Process holding a directory open for deleting — its own, or one of the
        // Client's in its data directory, whose entries it may delete — holds up no hand-over.
        let hold = |path: &Path| {
            use std::os::windows::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .access_mode(0x0001_0000 | 0x0080)
                .share_mode(0x7)
                .custom_flags(0x0200_0000)
                .open(path)
                .expect("held for deleting")
        };
        let theirs = data.join("theirs");
        std::fs::create_dir(&theirs).expect("theirs");
        let _held = (hold(&owned), hold(&theirs));
        let mut skipped = client
            .hand_over(&[&root], Some(&process))
            .expect("hand-over");
        skipped.sort_by_key(|skipped| format!("{skipped:?}"));
        assert_eq!(
            skipped,
            [
                Skipped::HardLinked(data.join("hard")),
                Skipped::ProcessAccounts(owned.clone()),
                Skipped::Unreadable(theirs.clone())
            ]
        );
        assert_eq!(
            (dacl(&outside), dacl(&outside.join("secret")), dacl(&owned)),
            before,
            "nothing through the junction or the hard link, nothing of the process account's; \
             {} became {}; data is {}",
            before.2,
            dacl(&owned),
            dacl(&data)
        );
        // Without a process account the hand-over walks the same tree, and enters no link either.
        client.hand_over(&[&root], None).expect("hand-over");
        assert_eq!(
            (
                dacl(&outside),
                dacl(&outside.join("secret")),
                dacl(&elsewhere)
            ),
            (before.0.clone(), before.1.clone(), elsewhere_before),
            "nothing through the junction, the hard link or the directory symlink"
        );
        for link in [data.join("link"), data.join("symlink")] {
            assert!(
                client.hand_over(&[&link], None).is_err(),
                "a root that is a link is refused: {}",
                link.display()
            );
        }
        assert!(
            dacl(&data).contains(";;;LS)"),
            "the Client's own is granted"
        );
    }

    /// On Windows what a former account was granted is withdrawn from it, and what it owns given
    /// to the Administrators: no ACE allows it anything anywhere in the tree — not on what was
    /// created after the grant, which holds a copy — and it owns nothing (ADR-0059 clauses 1 and
    /// 6). `LocalService` stands in for the former process account; the test runs elevated, as an
    /// install does.
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_a_former_accounts_grants_are_withdrawn() {
        use crate::win32::acl::{allow, READ_EXECUTE};
        use crate::win32::files::{grant_tree, Access, Entry};
        const FORMER: &str = r"NT AUTHORITY\LocalService";
        let local_service = crate::win32::LOCAL_SERVICE;
        let former = former_sid(Some(FORMER), &[])
            .expect("resolved")
            .expect("to withdraw");
        assert_eq!(former.as_str(), local_service);
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let config = root.join("config");
        std::fs::create_dir_all(&config).expect("config");
        std::fs::write(config.join("before"), b"x").expect("before");
        {
            let _privileges = crate::win32::BackupPrivileges::enable().expect("privileges");
            let top = Entry::open(&root, Access::Dacl, true).expect("root");
            let on_dir = [allow(local_service, READ_EXECUTE, "OICI")];
            let on_file = [allow(local_service, READ_EXECUTE, "")];
            grant_tree(
                &top,
                local_service,
                [&on_dir, &on_dir, &on_file],
                None,
                true,
            )
            .expect("granted");
            std::fs::write(config.join("after"), b"x").expect("after the grant");
            Entry::open(&config.join("after"), Access::Owner, false)
                .and_then(|entry| entry.set_owner(local_service))
                .expect("owned by the former account");
        }
        let skipped = withdraw(&former, &[&root]).expect("withdrawn");
        assert!(skipped.is_empty(), "{skipped:?}");
        for path in [
            root.clone(),
            config.clone(),
            config.join("before"),
            config.join("after"),
        ] {
            let entry = Entry::open(&path, Access::Read, false).expect("entry");
            let dacl = entry.dacl().expect("dacl");
            assert_eq!(
                dacl.without(local_service),
                dacl,
                "{}: {}",
                path.display(),
                dacl.text()
            );
            assert_ne!(
                entry.owner().expect("owner").as_str(),
                local_service,
                "{}",
                path.display()
            );
        }
        // An account kept — named as before, or resolving to an account named now — is no former
        // account, and neither is LocalSystem.
        assert_eq!(former_sid(Some(FORMER), &[(FORMER, &former)]), Ok(None));
        assert_eq!(
            former_sid(Some(r"NT AUTHORITY\LOCAL SERVICE"), &[("other", &former)]),
            Ok(None)
        );
        assert_eq!(former_sid(Some("LocalSystem"), &[]), Ok(None));
        assert_eq!(former_sid(None, &[]), Ok(None));

        // A directory beneath, held open for deleting — as another service of the former account
        // could hold one — is no directory to pass over: the withdrawal fails and names it.
        let held = config.join("held");
        std::fs::create_dir(&held).expect("held");
        let _held = {
            use std::os::windows::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .access_mode(0x0001_0000 | 0x0080)
                .share_mode(0x7)
                .custom_flags(0x0200_0000)
                .open(&held)
                .expect("held for deleting")
        };
        let refused = withdraw(&former, &[&root]).expect_err("fails closed");
        assert!(refused.contains("held open for deleting"), "{refused}");
    }

    /// On Windows a former account that cannot be resolved fails the install before it has changed
    /// anything, rather than leaving what it was granted granted (ADR-0059 clause 1).
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_a_former_account_that_cannot_be_found_fails_before_any_change() {
        let refused =
            former_sid(Some(r"NO-SUCH-DOMAIN\no-such-gmsa$"), &[]).expect_err("fails closed");
        assert!(refused.contains("Nothing was changed"), "{refused}");
    }

    /// On Windows the hand-over grants the Client modify, and where a process account is
    /// registered `WRITE_DAC` beside it, so that the Client can grant that account its share
    /// (ADR-0059 clause 6) of directories the install made — never the owner's right.
    /// Verifies: ADR-0059
    #[test]
    fn on_windows_the_handover_lets_the_client_share_with_the_process_account() {
        let sid = "S-1-5-80-1-2-3-4-5";
        assert_eq!(
            handover_aces(sid, false),
            [
                vec![format!("(A;OICI;0x1301bf;;;{sid})")],
                vec![format!("(A;;0x1301bf;;;{sid})")]
            ]
        );
        assert_eq!(
            handover_aces(sid, true),
            [
                vec![format!("(A;OICI;0x1701bf;;;{sid})")],
                vec![format!("(A;;0x1701bf;;;{sid})")]
            ]
        );
        assert_eq!(
            0x1701bf & 0x0008_0000,
            0,
            "no WRITE_OWNER, which full control would bring"
        );
    }

    /// On Windows the process account is one of the passwordless forms — the second service's own
    /// virtual account, a gMSA, `LocalService` or `NetworkService` — never `LocalSystem` and never
    /// the Client's account, and the Client does not run as `LocalSystem` (ADR-0059 clause 1).
    /// Verifies: ADR-0059
    #[test]
    fn on_windows_the_process_account_is_a_passwordless_account_of_its_own() {
        use crate::win32::{known_account_sid, Sid};
        let agents = "opamp-fleet-agents";
        let client = r"NT SERVICE\opamp-fleet";
        let client_sid = known_account_sid(client).expect("virtual");
        let check = |account: &str, sid: Sid| {
            check_windows_process_account(account, &sid, agents, client, &client_sid)
        };
        let virtual_account = r"NT SERVICE\opamp-fleet-agents";
        assert!(check(
            virtual_account,
            known_account_sid(virtual_account).expect("sid")
        )
        .is_ok());
        let local_service = r"NT AUTHORITY\LocalService";
        assert!(check(
            local_service,
            known_account_sid(local_service).expect("sid")
        )
        .is_ok());
        let gmsa = Sid::parse("S-1-5-21-1-2-3-1104").expect("sid");
        assert!(check(r"CORP\fleet-agents$", gmsa).is_ok());

        let system = check(
            "LocalSystem",
            known_account_sid("LocalSystem").expect("sid"),
        )
        .expect_err("LocalSystem");
        assert!(system.contains("LocalSystem as a whole"), "{system}");
        let own = check(client, client_sid.clone()).expect_err("the Client's");
        assert!(own.contains("the account the Client runs as"), "{own}");
        let other = r"NT SERVICE\mssqlserver";
        let foreign = check(other, known_account_sid(other).expect("sid")).expect_err("another's");
        assert!(foreign.contains(agents), "{foreign}");
        assert!(
            check("bob", Sid::parse("S-1-5-21-1-2-3-1001").expect("sid"))
                .expect_err("a password")
                .contains("password")
        );

        let system_sid = known_account_sid("LocalSystem").expect("sid");
        let client_is_system = check_windows_process_account(
            virtual_account,
            &known_account_sid(virtual_account).expect("sid"),
            agents,
            "LocalSystem",
            &system_sid,
        )
        .expect_err("a Client under LocalSystem");
        assert!(client_is_system.contains("--run-as"), "{client_is_system}");
    }

    /// ADR-0019: the accepted Windows forms are exactly the passwordless ones, and the refusal
    /// names them — an operator typing a plain account must learn the forms, not a Win32 error.
    /// Verifies: ADR-0019
    #[test]
    fn windows_forms_are_the_passwordless_ones() {
        let svc = "supervisor";
        assert!(windows_account_form(r"NT SERVICE\supervisor", svc).is_ok());
        assert!(
            windows_account_form(r"nt service\SUPERVISOR", svc).is_ok(),
            "account names compare case-insensitively on Windows"
        );
        assert!(windows_account_form(r"NT AUTHORITY\LocalService", svc).is_ok());
        assert!(windows_account_form(r"nt authority\networkservice", svc).is_ok());
        assert!(
            windows_account_form(r"CORP\fleet-agents$", svc).is_ok(),
            "gMSA"
        );

        assert!(
            windows_account_form("Dienst-äöü", svc).is_err(),
            "no slice panics"
        );
        let other = windows_account_form(r"NT SERVICE\mssqlserver", svc).expect_err("not ours");
        assert!(other.contains(r"NT SERVICE\supervisor"), "{other}");

        let plain = windows_account_form("bob", svc).expect_err("needs a password");
        assert!(plain.contains("password"), "{plain}");
        assert!(plain.contains(r"NT SERVICE\supervisor"), "{plain}");
        assert!(!plain.contains("ADR-"), "{plain}");
    }

    #[cfg(unix)]
    const DATA_ROOT: &str = "/var/lib/opamp-fleet";
    #[cfg(unix)]
    const UNIT: &str = "/etc/systemd/system/opamp-fleet.service";

    #[cfg(unix)]
    fn registered(account: Option<&str>) -> Registration {
        Registration {
            file: PathBuf::from(UNIT),
            account: account.map(str::to_string),
        }
    }

    #[cfg(unix)]
    fn me() -> String {
        let out = std::process::Command::new("id")
            .arg("-un")
            .output()
            .expect("id -un");
        String::from_utf8(out.stdout)
            .expect("utf8")
            .trim()
            .to_string()
    }

    /// An owner lookup that must not be asked.
    #[cfg(unix)]
    fn unasked() -> Result<Option<String>, String> {
        panic!("the data root's owner is asked only for a registration that names no account")
    }

    /// The refusal for a missing Unix account is the actionable message installs fail with — and
    /// it must promise that nothing was written, because resolution runs first.
    /// Verifies: ADR-0019, ADR-0042
    #[cfg(unix)]
    #[test]
    fn a_missing_account_is_refused_with_the_way_out() {
        let err = RunAs::resolve(
            "no-such-account-0062",
            "supervisor",
            &Source::Flag,
            Path::new(DATA_ROOT),
        )
        .expect_err("must not exist");
        assert!(err.contains("does not exist"), "{err}");
        assert!(
            err.contains("useradd --system --user-group --no-create-home --home-dir /var/lib/opamp-fleet --shell /usr/sbin/nologin no-such-account-0062"),
            "{err}"
        );
        assert!(err.contains("--run-as root"), "{err}");
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );
    }

    /// A re-registration without `--run-as` keeps the account the unit names, and says where it
    /// came from — the regression of a plain `service install` on every package upgrade, which
    /// returned a host installed with `--run-as` to root.
    /// Verifies: ADR-0042
    #[cfg(unix)]
    #[test]
    fn a_reregistration_without_run_as_keeps_the_units_account() {
        let unit = registered(Some("telegraf"));
        let (account, source) =
            choose(None, Some(&unit), Path::new(DATA_ROOT), unasked).expect("decided");
        assert_eq!(account, "telegraf");
        assert_eq!(source, Source::Registered(PathBuf::from(UNIT)));
        assert!(source.describe().contains(UNIT), "{}", source.describe());

        // `--run-as` outranks what the unit names.
        let (account, source) =
            choose(Some("other"), Some(&unit), Path::new(DATA_ROOT), unasked).expect("decided");
        assert_eq!((account.as_str(), source), ("other", Source::Flag));

        // And the whole decision, with the account resolved, on a real one.
        let me = me();
        let decision = decide(
            ServiceLevel::System,
            None,
            Some(&registered(Some(&me))),
            Path::new(DATA_ROOT),
            "opamp-fleet",
        )
        .expect("the test's own account resolves");
        assert_eq!(decision.run_as.expect("an account").account(), me);
        assert_eq!(decision.source, Source::Registered(PathBuf::from(UNIT)));
    }

    /// `--run-as root` is how root is chosen, and the unit records it as `User=root`, so the next
    /// re-registration keeps root.
    /// Verifies: ADR-0042
    #[cfg(unix)]
    #[test]
    fn run_as_root_is_written_as_user_root() {
        let decision = decide(
            ServiceLevel::System,
            Some("root"),
            Some(&registered(Some("opamp-fleet"))),
            Path::new(DATA_ROOT),
            "opamp-fleet",
        )
        .expect("root exists");
        let run_as = decision.run_as.expect("an account");
        assert_eq!(run_as.account(), "root");
        let unit = super::super::manager::systemd_unit(
            &super::super::manager::InstallSpec {
                level: ServiceLevel::System,
                program: PathBuf::from("/opt/opamp-fleet/current/supervisor"),
                config_path: PathBuf::from("/var/lib/opamp-fleet/supervisor.toml"),
                state_dir: PathBuf::from("/var/lib/opamp-fleet/state"),
                run_as: Some(run_as.account().to_string()),
                agents: None,
            },
            run_as.account(),
        )
        .expect("unit");
        assert!(unit.lines().any(|l| l == "User=root"), "{unit}");
    }

    /// A unit that names no account, on a data root an account owns, was rewritten by a
    /// re-registration that dropped its account: the install takes the owner, and names the data
    /// root it took it from.
    /// Verifies: ADR-0042
    #[cfg(unix)]
    #[test]
    fn a_unit_without_an_account_on_an_account_owned_data_root_takes_the_owner() {
        let (account, source) = choose(None, Some(&registered(None)), Path::new(DATA_ROOT), || {
            Ok(Some("telegraf".to_string()))
        })
        .expect("decided");
        assert_eq!(account, "telegraf");
        assert_eq!(source, Source::DataRootOwner(PathBuf::from(DATA_ROOT)));
        assert!(
            source.describe().contains(DATA_ROOT),
            "{}",
            source.describe()
        );

        // The owner as the install reads it: a directory this test created is the test's.
        let root = tempfile::tempdir().expect("tempdir");
        let owner = data_root_owner(root.path()).expect("an account owns it");
        let me = me();
        if me == "root" {
            assert_eq!(owner, None, "root owns it, and root is no account to take");
        } else {
            assert_eq!(owner.as_deref(), Some(me.as_str()));
        }
    }

    /// A unit that names no account, on a data root root owns, is an install that ran as root,
    /// and it stays root.
    /// Verifies: ADR-0042
    #[cfg(unix)]
    #[test]
    fn a_unit_without_an_account_on_a_root_owned_data_root_stays_root() {
        let (account, source) = choose(None, Some(&registered(None)), Path::new(DATA_ROOT), || {
            Ok(None)
        })
        .expect("decided");
        assert_eq!((account.as_str(), source), ("root", Source::Default));
        assert_eq!(
            data_root_owner(Path::new("/")).expect("root owns /"),
            None,
            "a root-owned data root names no account"
        );
        assert_eq!(
            data_root_owner(Path::new("/no/such/data/root")).expect("missing"),
            None
        );
    }

    /// Where no unit exists, nothing is kept and the data root is not asked: a first registration
    /// runs as root. The Linux packages name their account themselves.
    /// Verifies: ADR-0042
    #[cfg(unix)]
    #[test]
    fn no_registration_means_root() {
        let (account, source) = choose(None, None, Path::new(DATA_ROOT), unasked).expect("decided");
        assert_eq!((account.as_str(), source), ("root", Source::Default));
        let user =
            decide(ServiceLevel::User, None, None, Path::new(DATA_ROOT), "x").expect("user scope");
        assert!(user.run_as.is_none(), "a user service runs as its user");
    }

    /// A kept account that has been deleted fails closed, before anything is written: the message
    /// names the account and the unit it came from, and the two ways out.
    /// Verifies: ADR-0042
    #[cfg(unix)]
    #[test]
    fn a_kept_account_that_no_longer_exists_is_refused_naming_its_source() {
        let err = decide(
            ServiceLevel::System,
            None,
            Some(&registered(Some("no-such-account-0043"))),
            Path::new(DATA_ROOT),
            "opamp-fleet",
        )
        .expect_err("must not fall back to root");
        assert!(err.contains("no-such-account-0043"), "{err}");
        assert!(err.contains(UNIT), "{err}");
        assert!(err.contains("useradd --system"), "{err}");
        assert!(err.contains("--run-as <account>"), "{err}");
        assert!(err.contains("--run-as root"), "{err}");
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );
    }

    const AGENTS_UNIT: &str = "/etc/systemd/system/opamp-fleet-agents.service";

    /// The Client's account as the checks see it: uid 998, in the groups 998 and 997.
    fn client_ids() -> Ids {
        Ids {
            uid: 998,
            gid: 998,
            group: "opamp-fleet".to_string(),
            groups: vec![998, 997],
            members: Vec::new(),
            primary_of: vec![("opamp-fleet".to_string(), 998)],
        }
    }

    /// A process account of uid and primary group 997.
    fn agents_ids() -> Ids {
        Ids {
            uid: 997,
            gid: 997,
            group: "opamp-fleet-agents".to_string(),
            groups: vec![997],
            members: vec!["opamp-fleet".to_string()],
            primary_of: vec![("opamp-fleet-agents".to_string(), 997)],
        }
    }

    /// `--process-account` names the account; without it a re-registration keeps the one the
    /// second service's unit names, and with neither there is no process account.
    /// Verifies: ADR-0059
    #[test]
    fn a_process_account_is_named_or_kept_from_the_second_services_unit() {
        let unit = Registration {
            file: PathBuf::from(AGENTS_UNIT),
            account: Some("opamp-fleet-agents".to_string()),
        };
        assert_eq!(
            choose_process_account(None, Some(&unit)).expect("kept"),
            Some((
                "opamp-fleet-agents".to_string(),
                Some(PathBuf::from(AGENTS_UNIT))
            ))
        );
        assert_eq!(
            choose_process_account(Some("other"), Some(&unit)).expect("named"),
            Some(("other".to_string(), None)),
            "the flag outranks the unit"
        );
        assert_eq!(choose_process_account(None, None).expect("none"), None);
        let lost = Registration {
            file: PathBuf::from(AGENTS_UNIT),
            account: None,
        };
        let err = choose_process_account(None, Some(&lost)).expect_err("no account to keep");
        assert!(err.contains(AGENTS_UNIT), "{err}");
        assert!(err.contains("--process-account"), "{err}");

        let kept = ProcessAccount {
            account: "opamp-fleet-agents".to_string(),
            #[cfg(unix)]
            uid: 997,
            #[cfg(unix)]
            gid: 997,
            #[cfg(windows)]
            sid: crate::win32::virtual_account_sid("opamp-fleet-agents").expect("ascii"),
            #[cfg(windows)]
            client_sid: crate::win32::virtual_account_sid("opamp-fleet").expect("ascii"),
            kept_from: Some(PathBuf::from(AGENTS_UNIT)),
        };
        assert!(kept.describe().contains(AGENTS_UNIT), "{}", kept.describe());
    }

    /// A process account that exists, is neither root nor the Client's, and whose group the
    /// Client's account is in, is taken.
    /// Verifies: ADR-0059
    #[test]
    fn a_process_account_in_the_clients_groups_is_taken() {
        check_process_account(
            "opamp-fleet-agents",
            Some(&agents_ids()),
            "opamp-fleet",
            &client_ids(),
            None,
        )
        .expect("taken");
    }

    /// Root is never the process account, by name or by uid, and a Client that runs as root has
    /// none: the refusal names `--run-as root` as the way to run everything as root.
    /// Verifies: ADR-0059
    #[test]
    fn the_process_account_is_never_root_and_the_client_never_is() {
        let root = Ids {
            uid: 0,
            gid: 0,
            group: "root".to_string(),
            groups: vec![0],
            members: Vec::new(),
            primary_of: vec![("root".to_string(), 0)],
        };
        for (account, found) in [("root", Some(&root)), ("toor", Some(&root))] {
            let err = check_process_account(account, found, "opamp-fleet", &client_ids(), None)
                .expect_err("root");
            assert!(err.contains("--run-as root"), "{err}");
            assert!(
                err.contains("Nothing has been installed or written"),
                "{err}"
            );
        }
        let err = check_process_account(
            "opamp-fleet-agents",
            Some(&agents_ids()),
            "root",
            &root,
            None,
        )
        .expect_err("a root Client");
        assert!(err.contains("--run-as <account>"), "{err}");
    }

    /// The process account is never the Client's own.
    /// Verifies: ADR-0059
    #[test]
    fn the_process_account_is_never_the_clients() {
        let err = check_process_account(
            "opamp-fleet",
            Some(&client_ids()),
            "opamp-fleet",
            &client_ids(),
            None,
        )
        .expect_err("the Client's own");
        assert!(err.contains("the Client runs as"), "{err}");
    }

    /// An account that does not exist is refused with the lines that create it and give its group
    /// to the Client's account; a kept one names the unit it came from.
    /// Verifies: ADR-0059
    #[test]
    fn a_missing_process_account_is_refused_with_the_way_out() {
        let err = check_process_account_on(
            Host::Linux,
            "opamp-fleet-agents",
            None,
            "opamp-fleet",
            &client_ids(),
            Some(Path::new(AGENTS_UNIT)),
        )
        .expect_err("missing");
        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains(AGENTS_UNIT), "{err}");
        assert!(
            err.contains(
                "useradd --system --user-group --no-create-home --shell /usr/sbin/nologin \
                 opamp-fleet-agents"
            ),
            "{err}"
        );
        assert!(
            err.contains("usermod --append --groups opamp-fleet-agents opamp-fleet"),
            "{err}"
        );
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );
    }

    /// On macOS the refusals name the directory service's tools: a missing account the
    /// `sysadminctl -roleAccount` line that creates it after its own group, and `dseditgroup` for
    /// each membership to add or remove; no Linux tool is named. This host's are the ones an
    /// install shows.
    /// Verifies: ADR-0059
    #[test]
    fn on_macos_the_refusals_show_the_directory_services_lines() {
        assert_eq!(
            Host::THIS,
            if cfg!(target_os = "macos") {
                Host::MacOs
            } else {
                Host::Linux
            }
        );
        let refused = |agents: Option<&Ids>, client: &Ids| {
            check_process_account_on(
                Host::MacOs,
                "_opamp-fleet-agents",
                agents,
                "_opamp-fleet",
                client,
                Some(Path::new("/Library/LaunchDaemons/opamp-fleet-agents.plist")),
            )
            .expect_err("refused")
        };
        let missing = refused(None, &client_ids());
        for line in [
            "/Library/LaunchDaemons/opamp-fleet-agents.plist",
            "dseditgroup -o create -i <gid> _opamp-fleet-agents",
            "sysadminctl -addUser _opamp-fleet-agents -UID <uid> -GID <gid> -roleAccount",
            "dseditgroup -o edit -a _opamp-fleet -t user _opamp-fleet-agents",
            "--no-process-account",
        ] {
            assert!(missing.contains(line), "{line} in {missing}");
        }
        let mut lacking = client_ids();
        lacking.groups = vec![998];
        let mut agents = agents_ids();
        agents.group = "_opamp-fleet-agents".to_string();
        agents.members = vec!["_opamp-fleet".to_string()];
        let err = refused(Some(&agents), &lacking);
        assert!(
            err.contains("dseditgroup -o edit -a _opamp-fleet -t user _opamp-fleet-agents"),
            "{err}"
        );
        let mut member = agents.clone();
        member.groups.push(998);
        let err = refused(Some(&member), &client_ids());
        assert!(
            err.contains("dseditgroup -o edit -d _opamp-fleet-agents -t user opamp-fleet"),
            "{err}"
        );
        let mut shared = agents.clone();
        shared.primary_of.push(("_www".to_string(), 70));
        let err = refused(Some(&shared), &client_ids());
        assert!(
            err.contains("dscl . -create /Users/_opamp-fleet-agents PrimaryGroupID <gid>"),
            "{err}"
        );
        for err in [missing, err] {
            for linux in ["useradd", "usermod", "gpasswd"] {
                assert!(!err.contains(linux), "{linux} in {err}");
            }
        }
    }

    /// The Client reaches what the process account may read through its primary group (ADR-0059
    /// clause 6): an account whose group the Client's account is not in is refused, with the line
    /// that adds it.
    /// Verifies: ADR-0059
    #[test]
    fn a_process_account_whose_group_the_client_lacks_is_refused() {
        let mut client = client_ids();
        client.groups = vec![998];
        let err = check_process_account_on(
            Host::Linux,
            "opamp-fleet-agents",
            Some(&agents_ids()),
            "opamp-fleet",
            &client,
            None,
        )
        .expect_err("not in the group");
        assert!(
            err.contains("usermod --append --groups opamp-fleet-agents opamp-fleet"),
            "{err}"
        );
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );
    }

    /// `--no-process-account` drops a kept process account; a refusal that a kept one causes —
    /// here `--run-as root` beside a registered second service — names that flag, and one an
    /// install named does not (ADR-0059 clause 1).
    /// Verifies: ADR-0059
    #[test]
    fn a_kept_process_account_can_be_dropped_and_its_refusals_say_so() {
        let unit = Registration {
            file: PathBuf::from(AGENTS_UNIT),
            account: Some("opamp-fleet-agents".to_string()),
        };
        assert!(
            decide_process_account(None, true, Some(&unit), None, false)
                .expect("dropped")
                .is_none(),
            "dropped before anything else is asked"
        );
        let root = Ids {
            uid: 0,
            gid: 0,
            group: "root".to_string(),
            groups: vec![0],
            members: Vec::new(),
            primary_of: vec![("root".to_string(), 0)],
        };
        let kept = check_process_account(
            "opamp-fleet-agents",
            Some(&agents_ids()),
            "root",
            &root,
            Some(Path::new(AGENTS_UNIT)),
        )
        .expect_err("a root Client");
        assert!(kept.contains("--no-process-account"), "{kept}");
        assert!(
            kept.ends_with("Nothing has been installed or written."),
            "{kept}"
        );
        let named = check_process_account(
            "opamp-fleet-agents",
            Some(&agents_ids()),
            "root",
            &root,
            None,
        )
        .expect_err("a root Client");
        assert!(!named.contains("--no-process-account"), "{named}");
        let lost = Registration {
            file: PathBuf::from(AGENTS_UNIT),
            account: None,
        };
        let err = choose_process_account(None, Some(&lost)).expect_err("no account to keep");
        assert!(err.contains("--no-process-account"), "{err}");
    }

    /// The process account's primary group is neither root's nor the Client's own, and the
    /// account is not in the Client's primary group (ADR-0059 clause 6): what that group may read
    /// is what every Managed Process may.
    /// Verifies: ADR-0059
    #[test]
    fn a_process_account_whose_group_reaches_the_clients_files_is_refused() {
        let refused = |agents: Ids, client: Ids| {
            check_process_account_on(
                Host::Linux,
                "opamp-fleet-agents",
                Some(&agents),
                "opamp-fleet",
                &client,
                None,
            )
            .expect_err("refused")
        };
        let mut wheel = agents_ids();
        wheel.gid = 0;
        wheel.group = "root".to_string();
        let mut client = client_ids();
        client.groups.push(0);
        let err = refused(wheel, client);
        assert!(err.contains("gid 0"), "{err}");

        let mut shared = agents_ids();
        shared.gid = 998;
        shared.group = "opamp-fleet".to_string();
        let err = refused(shared, client_ids());
        assert!(
            err.contains("primary group of the Client's account"),
            "{err}"
        );

        let mut member = agents_ids();
        member.groups.push(998);
        let err = refused(member, client_ids());
        assert!(err.contains("is a member of the primary group"), "{err}");
        assert!(
            err.contains("gpasswd --delete opamp-fleet-agents opamp-fleet"),
            "{err}"
        );
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );
    }

    /// The process account's primary group is its own (ADR-0059 clause 6): a member beside the
    /// Client's account, or another account whose primary group it is, would read what every
    /// Managed Process reads, and is refused with the way out. The account itself — a member of
    /// its own group (`usermod -aG`), or another name for its uid — is no other account.
    /// Verifies: ADR-0059
    #[test]
    fn a_process_account_whose_group_is_shared_with_another_account_is_refused() {
        let refused = |agents: Ids| {
            check_process_account_on(
                Host::Linux,
                "opamp-fleet-agents",
                Some(&agents),
                "opamp-fleet",
                &client_ids(),
                None,
            )
            .expect_err("refused")
        };
        let mut member = agents_ids();
        member.members.push("www-data".to_string());
        let err = refused(member);
        assert!(err.contains("www-data is a member"), "{err}");
        assert!(
            err.contains("gpasswd --delete www-data opamp-fleet-agents"),
            "{err}"
        );
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );

        let mut primary = agents_ids();
        primary.primary_of.push(("nobody".to_string(), 65534));
        let err = refused(primary);
        assert!(err.contains("primary group of nobody"), "{err}");
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );

        let mut itself = agents_ids();
        itself.members.push("opamp-fleet-agents".to_string());
        check_process_account(
            "opamp-fleet-agents",
            Some(&itself),
            "opamp-fleet",
            &client_ids(),
            None,
        )
        .expect("a member of its own group");

        let mut alias = agents_ids();
        alias.primary_of.push(("agents-alias".to_string(), 997));
        check_process_account(
            "opamp-fleet-agents",
            Some(&alias),
            "opamp-fleet",
            &client_ids(),
            None,
        )
        .expect("its own uid under another name");
    }

    /// The group lookups behind those checks read this host's databases: the test's own primary
    /// group is its own account's primary group, where the password database names the account.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_group_lookups_read_this_hosts_databases() {
        // SAFETY: getegid(2) and geteuid(2) cannot fail and touch no memory.
        let (gid, uid) = unsafe { (libc::getegid(), libc::geteuid()) };
        group_members(gid).expect("the group database");
        if account_of(uid).ok().flatten().map(|a| a.gid) != Some(gid) {
            crate::skipped_unless_ci(
                "the_group_lookups_read_this_hosts_databases",
                "password database entry with the test's own primary group",
            );
            return;
        }
        assert!(
            primary_group_of(gid).iter().any(|(_, found)| *found == uid),
            "{:?}",
            primary_group_of(gid)
        );
    }

    /// The members of a group that has some are read, wherever the libc places them in the
    /// buffer: the groups the test runs in, and on macOS `admin` (gid 80), whose members a GitHub
    /// runner's account is one of. A pointer read where macOS places it unaligned once aborted
    /// the install of a process account there.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_members_of_a_group_are_read_wherever_the_libc_places_them() {
        // SAFETY: getgroups(2) with a count of 0 writes nothing and returns how many there are.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        let mut gids = vec![0 as libc::gid_t; usize::try_from(count).expect("a count")];
        // SAFETY: the buffer holds as many as were counted, and as many as it is told.
        let count = unsafe { libc::getgroups(count, gids.as_mut_ptr()) };
        gids.truncate(usize::try_from(count).expect("the supplementary groups"));
        if cfg!(target_os = "macos") {
            gids.push(80);
        }
        let mut read = Vec::new();
        for gid in gids {
            let members = group_members(gid).expect("the group database");
            assert!(members.iter().all(|m| !m.is_empty()), "{gid}: {members:?}");
            read.extend(members);
        }
        if read.is_empty() {
            crate::skipped_unless_ci(
                "the_members_of_a_group_are_read_wherever_the_libc_places_them",
                "group of the test's with a member",
            );
        }
    }

    /// Where no second service can be registered — the user scope, another service manager, or
    /// another platform for now — a named process account is refused; with none named, nothing
    /// changes. A name no unit can hold is refused here too, before the install writes anything.
    /// Against the accounts of this host: a missing one, and the test's own named as the Client's.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_process_account_is_decided_before_anything_is_written() {
        let me = RunAs::resolve(&me(), "supervisor", &Source::Flag, Path::new(DATA_ROOT))
            .expect("own account resolves");
        assert!(decide_process_account(None, false, None, Some(&me), true)
            .expect("none named")
            .is_none());
        let err = decide_process_account(Some("opamp-fleet-agents"), false, None, Some(&me), false)
            .expect_err("no second service here");
        assert!(err.contains("systemd"), "{err}");
        let err = decide_process_account(Some("opamp-fleet-agents"), false, None, None, true)
            .expect_err("a user service names none");
        assert!(err.contains("systemd"), "{err}");
        let err = decide_process_account(Some("bad\"account"), false, None, Some(&me), true)
            .expect_err("not writable into a unit");
        assert!(
            err.contains("cannot be written into a systemd unit"),
            "{err}"
        );
        assert!(
            err.contains("Nothing has been installed or written"),
            "{err}"
        );
        let err =
            decide_process_account(Some("no-such-account-0059"), false, None, Some(&me), true)
                .expect_err("missing");
        if me.uid() == 0 {
            assert!(err.contains("the Client runs as root"), "{err}");
        } else {
            assert!(err.contains("does not exist"), "{err}");
            let err = decide_process_account(Some(&me.account), false, None, Some(&me), true)
                .expect_err("the Client's own");
            assert!(err.contains("the Client runs as"), "{err}");
        }
    }

    /// The test's own account, and a group it may give its own files: a chown to that pair is one
    /// an unprivileged process is allowed, and a changed group shows what the walk reached. `None`
    /// where the test's user has no second group.
    #[cfg(unix)]
    fn me_with_another_group(owned: &Path) -> (RunAs, Option<u32>) {
        use std::os::unix::fs::MetadataExt as _;
        let me = RunAs::resolve(&me(), "supervisor", &Source::Flag, Path::new(DATA_ROOT))
            .expect("own account resolves");
        let groups = String::from_utf8(
            std::process::Command::new("id")
                .arg("-G")
                .output()
                .expect("id -G")
                .stdout,
        )
        .expect("utf8");
        let current = std::fs::metadata(owned).expect("metadata").gid();
        let other = groups
            .split_whitespace()
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| *g != current);
        (me, other)
    }

    /// A tree as a Supervisor's directory stands where a process account is registered: the
    /// directories clause 6 gives the process account's group — the state directory passed
    /// through, a data directory written — and a configuration entry, all in `group`, beside a
    /// record of the Client's left in the group it was created with. Returns the entries in
    /// `group` with their modes, and the record.
    #[cfg(unix)]
    fn shared_tree(root: &Path, group: u32) -> (Vec<(PathBuf, u32)>, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let state = root.join("state");
        let data = state.join("data");
        let entry = state.join("config.yaml");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(&entry, b"x").expect("write");
        let record = state.join("package.json");
        std::fs::write(&record, b"{}").expect("write");
        let shared = vec![(state, 0o710), (data, 0o2770), (entry, 0o640)];
        for (path, mode) in &shared {
            std::os::unix::fs::chown(path, None, Some(group)).expect("chgrp");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)).expect("chmod");
        }
        (shared, record)
    }

    #[cfg(unix)]
    fn mode_and_group(path: &Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path).expect("metadata");
        (meta.mode() & 0o7777, meta.gid())
    }

    /// Where a process account is registered, the hand-over leaves its group where clause 6 put
    /// it: a directory in the process account's group keeps that group and its mode, and so does
    /// an entry in it, while the rest is handed over as before. A re-registration — every package
    /// upgrade — takes from no Managed Process what it reads or writes.
    /// The test is not root, and macOS, unlike Linux, clears a directory's set-group-ID bit on a
    /// chown by anyone but root, even one that changes nothing: the walk sets the mode again, so
    /// the data directory stays `2770` there too.
    /// Verifies: ADR-0059
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_handover_keeps_the_process_accounts_group_and_its_modes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir");
        let (me, other) = me_with_another_group(&root);
        let Some(group) = other else {
            crate::skipped_unless_ci(
                "the_handover_keeps_the_process_accounts_group_and_its_modes",
                "supplementary group",
            );
            return;
        };
        let (shared, record) = shared_tree(&root, group);
        // Another account's: nothing the test owns is skipped for its owner.
        let process = ProcessAccount {
            account: "agents".to_string(),
            uid: me.uid.wrapping_add(1),
            gid: group,
            kept_from: None,
        };
        let skipped = me.hand_over(&[&root], Some(&process)).expect("handover");
        assert!(skipped.is_empty(), "{skipped:?}");
        for (path, mode) in &shared {
            assert_eq!(mode_and_group(path), (*mode, group), "{}", path.display());
        }
        assert_eq!(mode_and_group(&record).1, me.gid);
        assert_eq!(mode_and_group(&root).1, me.gid);
    }

    /// An entry the process account owns is skipped with everything beneath it, whatever its
    /// group: the hand-over re-owns nothing of what a Managed Process wrote. The test's own
    /// account stands in for the process account, so the top and every entry beneath it are
    /// the process account's.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_handover_skips_what_the_process_account_owns_with_everything_beneath_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir");
        let (mut me, other) = me_with_another_group(&root);
        let Some(group) = other else {
            crate::skipped_unless_ci(
                "the_handover_skips_what_the_process_account_owns_with_everything_beneath_it",
                "supplementary group",
            );
            return;
        };
        let before = mode_and_group(&root).1;
        let (shared, record) = shared_tree(&root, before);
        me.gid = group;
        let process = ProcessAccount {
            account: "agents".to_string(),
            uid: me.uid,
            gid: group.wrapping_add(1),
            kept_from: None,
        };
        me.hand_over(&[&root], Some(&process)).expect("handover");
        for path in [&root, &record] {
            assert_eq!(mode_and_group(path).1, before, "{}", path.display());
        }
        for (path, mode) in &shared {
            assert_eq!(mode_and_group(path), (*mode, before), "{}", path.display());
        }
    }

    /// A root of the hand-over that the process account owns is left to it, and named in a
    /// warning: the operator who names it as a root means the Client to have it. What the process
    /// account owns beneath a root is its data, and is passed over without a word.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_root_the_process_account_owns_is_named_in_a_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("state").join("data")).expect("mkdir");
        let (me, _) = me_with_another_group(&root);
        // The test's own account stands in for the process account.
        let process = ProcessAccount {
            account: "agents".to_string(),
            uid: me.uid,
            gid: me.gid,
            kept_from: None,
        };
        let skipped = me
            .hand_over(&[&root, &root.join("state")], Some(&process))
            .expect("handover");
        assert_eq!(skipped, vec![Skipped::ProcessAccounts(root.clone())]);
        let warning = skipped[0].warning("opamp-fleet");
        assert!(warning.contains(&root.display().to_string()), "{warning}");
        assert!(warning.contains("process account"), "{warning}");
    }

    /// Without a process account the hand-over is what it always was: every entry, in whatever
    /// group, is handed to the Client's account and group.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn without_a_process_account_the_handover_re_owns_every_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir");
        let (me, other) = me_with_another_group(&root);
        let Some(group) = other else {
            crate::skipped_unless_ci(
                "without_a_process_account_the_handover_re_owns_every_group",
                "supplementary group",
            );
            return;
        };
        let (shared, record) = shared_tree(&root, group);
        me.hand_over(&[&root], None).expect("handover");
        for path in shared.iter().map(|(path, _)| path).chain([&record, &root]) {
            assert_eq!(mode_and_group(path).1, me.gid, "{}", path.display());
        }
    }

    /// The handover re-owns a tree including a symlink as a link, and skips what is missing.
    /// Verifies: ADR-0019
    #[cfg(unix)]
    #[test]
    fn the_handover_walks_the_tree_and_skips_what_is_missing() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let versions = root.join("versions/supervisor-1.0.0-abc");
        std::fs::create_dir_all(&versions).expect("mkdir");
        let binary = versions.join(crate::service::layout::BINARY_FILENAME);
        std::fs::write(&binary, b"binary").expect("write");
        std::os::unix::fs::symlink("versions/supervisor-1.0.0-abc", root.join("current"))
            .expect("symlink");

        let (mut me, other) = me_with_another_group(root);
        if let Some(group) = other {
            me.gid = group;
        }
        let missing = root.join("supervisor.toml");
        let skipped = me
            .hand_over(&[root, &missing], None)
            .expect("a missing config file is skipped, the tree is walked");
        assert!(skipped.is_empty(), "{skipped:?}");
        for reached in [root.to_path_buf(), versions, binary, root.join("current")] {
            let gid = std::fs::symlink_metadata(&reached).expect("exists").gid();
            assert_eq!(gid, me.gid, "{}", reached.display());
        }
    }

    /// A directory inside the tree that is a link to one outside it is re-owned as the link; the
    /// walk never reaches what it points to.
    /// Verifies: ADR-0042, ADR-0054
    #[cfg(unix)]
    #[test]
    fn the_handover_never_follows_a_directory_swapped_for_a_link() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join("state")).expect("mkdir");
        std::fs::create_dir_all(outside.join("deeper")).expect("mkdir");
        std::fs::write(outside.join("secret"), b"x").expect("write");
        // `state` was a directory; the account swapped it for a link to one outside the root.
        std::fs::remove_dir(root.join("state")).expect("rmdir");
        std::os::unix::fs::symlink(&outside, root.join("state")).expect("symlink");

        let (mut me, other) = me_with_another_group(&root);
        let before = std::fs::metadata(&outside).expect("outside").gid();
        if let Some(group) = other {
            me.gid = group;
        }
        me.hand_over(&[&root, &root.join("state")], None)
            .expect("handover");
        for untouched in [
            outside.clone(),
            outside.join("secret"),
            outside.join("deeper"),
        ] {
            assert_eq!(
                std::fs::metadata(&untouched).expect("exists").gid(),
                before,
                "{} was reached through the link",
                untouched.display()
            );
        }
        assert_eq!(
            std::fs::symlink_metadata(root.join("state"))
                .expect("link")
                .gid(),
            me.gid,
            "the link itself is re-owned"
        );
    }

    /// A regular file with a second hard link is left as it is and named: its other name may stand
    /// outside the roots.
    /// Verifies: ADR-0042, ADR-0054
    #[cfg(unix)]
    #[test]
    fn the_handover_skips_a_file_with_a_second_hard_link() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir");
        let outside = dir.path().join("outside-file");
        std::fs::write(&outside, b"x").expect("write");
        let linked = root.join("linked");
        std::fs::hard_link(&outside, &linked).expect("hard link");
        std::fs::write(root.join("plain"), b"y").expect("write");

        let (mut me, other) = me_with_another_group(&root);
        let before = std::fs::metadata(&outside).expect("outside").gid();
        if let Some(group) = other {
            me.gid = group;
        }
        let skipped = me.hand_over(&[&root], None).expect("handover");
        assert_eq!(skipped, vec![Skipped::HardLinked(linked.clone())]);
        assert_eq!(std::fs::metadata(&outside).expect("outside").gid(), before);
        assert_eq!(
            std::fs::metadata(root.join("plain")).expect("plain").gid(),
            me.gid
        );
    }

    /// A directory swapped for a link to one outside the tree, after the walk read its name and
    /// before it opened it, is re-owned as the link; nothing outside is reached.
    /// Verifies: ADR-0042, ADR-0054
    #[cfg(unix)]
    #[test]
    fn the_handover_never_follows_a_directory_swapped_for_a_link_mid_walk() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        let state = root.join("state");
        std::fs::create_dir_all(&state).expect("mkdir");
        std::fs::create_dir_all(outside.join("deeper")).expect("mkdir");
        std::fs::write(outside.join("secret"), b"x").expect("write");

        let (mut me, other) = me_with_another_group(&root);
        let before = std::fs::metadata(&outside).expect("outside").gid();
        if let Some(group) = other {
            me.gid = group;
        }
        let mut skipped = Vec::new();
        super::walk::chown_tree_with(&root, me.uid, me.gid, None, &mut skipped, &|entry| {
            if entry == state {
                std::fs::remove_dir(&state).expect("rmdir");
                std::os::unix::fs::symlink(&outside, &state).expect("symlink");
            }
        })
        .expect("handover");
        assert!(skipped.is_empty(), "{skipped:?}");
        for untouched in [
            outside.clone(),
            outside.join("secret"),
            outside.join("deeper"),
        ] {
            assert_eq!(
                std::fs::metadata(&untouched).expect("exists").gid(),
                before,
                "{} was reached through the link",
                untouched.display()
            );
        }
        assert_eq!(
            std::fs::symlink_metadata(&state).expect("link").gid(),
            me.gid,
            "the link itself is re-owned"
        );
    }

    /// An entry swapped for a hard link to a file outside the tree, after the walk read its name
    /// and before it opened it, is skipped and named; the file outside keeps its owner.
    /// Verifies: ADR-0042, ADR-0054
    #[cfg(unix)]
    #[test]
    fn the_handover_skips_an_entry_swapped_for_a_hard_link_mid_walk() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir");
        let outside = dir.path().join("outside-file");
        std::fs::write(&outside, b"x").expect("write");
        std::fs::write(root.join("plain"), b"y").expect("write");
        // The entry starts as a link, the type a by-name re-own trusts.
        let swapped = root.join("swapped");
        std::os::unix::fs::symlink("plain", &swapped).expect("symlink");

        let (mut me, other) = me_with_another_group(&root);
        let before = std::fs::metadata(&outside).expect("outside").gid();
        if let Some(group) = other {
            me.gid = group;
        }
        let mut skipped = Vec::new();
        super::walk::chown_tree_with(&root, me.uid, me.gid, None, &mut skipped, &|entry| {
            if entry == swapped {
                std::fs::remove_file(&swapped).expect("unlink");
                std::fs::hard_link(&outside, &swapped).expect("hard link");
            }
        })
        .expect("handover");
        assert_eq!(
            std::fs::metadata(&outside).expect("outside").gid(),
            before,
            "the file outside was re-owned through its second name"
        );
        assert_eq!(skipped, vec![Skipped::HardLinked(swapped)]);
        assert_eq!(
            std::fs::metadata(root.join("plain")).expect("plain").gid(),
            me.gid
        );
    }
}
