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
        let _ = registration;
        match flag {
            Some(account) => Ok(Decision {
                run_as: Some(RunAs::resolve(account, service, &Source::Flag, data_root)?),
                source: Source::Flag,
            }),
            None => Ok(Decision {
                run_as: None,
                source: Source::Default,
            }),
        }
    }
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
    match account_name(meta.uid()) {
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

/// The account name of `uid`, through `getpwuid_r(3)`.
#[cfg(unix)]
fn account_name(uid: u32) -> std::io::Result<Option<String>> {
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
        // SAFETY: `found` points at the filled `entry`, and `pw_name` at a NUL-terminated string
        // inside `buffer`, which outlives this read.
        let name = unsafe { std::ffi::CStr::from_ptr((*found).pw_name) };
        return Ok(Some(name.to_string_lossy().into_owned()));
    }
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
            })
        }
    }

    /// The account as the service manager must be told it.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Hand the given paths over to the account — recursively, skipping paths that do not exist
    /// (a configuration file the operator has not written yet is a warning elsewhere, not a
    /// failure here), and a path inside one handed over before it in the same call, which that
    /// walk covered without following a link. The handover is idempotent.
    ///
    /// Returns the regular files left as they were because they have a second hard link (Unix):
    /// another name for the file may stand outside the roots, and re-owning it would hand that
    /// over too.
    ///
    /// # Errors
    /// Returns an error naming the first path that could not be handed over.
    pub fn hand_over(&self, paths: &[&Path]) -> Result<Vec<PathBuf>, String> {
        let mut skipped = Vec::new();
        let mut walked: Vec<&Path> = Vec::new();
        for path in paths {
            if walked.iter().any(|done| path.starts_with(done))
                || std::fs::symlink_metadata(path).is_err()
            {
                continue;
            }
            self.own(path, &mut skipped).map_err(|e| {
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
    fn own(&self, path: &Path, skipped: &mut Vec<PathBuf>) -> std::io::Result<()> {
        walk::chown_tree(path, self.uid, self.gid, skipped)
    }

    #[cfg(not(unix))]
    fn own(&self, path: &Path, _skipped: &mut Vec<PathBuf>) -> Result<(), String> {
        // `(OI)(CI)` — inherit to files and subdirectories created later — is a directory-only
        // grant spec; a file takes the bare right. `/T` re-grants across what already exists.
        let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
        let grant = if is_dir {
            format!("{}:(OI)(CI)M", self.account)
        } else {
            format!("{}:M", self.account)
        };
        let mut cmd = std::process::Command::new("icacls.exe");
        cmd.arg(path).arg("/grant").arg(&grant);
        if is_dir {
            cmd.arg("/T");
        }
        let output = cmd
            .output()
            .map_err(|e| format!("cannot run icacls.exe: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "icacls.exe exited with {} ({})",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim()
        ))
    }
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

/// The handover walk on Unix: descriptors, never paths below the top (ADR-0042 clause 2).
#[cfg(unix)]
mod walk {
    use std::ffi::{CStr, CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};

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

    /// Re-own `path` and, if it is a directory, everything under it, without following a link.
    /// The top is the one name resolved as a path, and its last component is never followed.
    pub(super) fn chown_tree(
        path: &Path,
        uid: u32,
        gid: u32,
        skipped: &mut Vec<PathBuf>,
    ) -> io::Result<()> {
        chown_tree_with(path, uid, gid, skipped, &|_| {})
    }

    /// `chown_tree`, calling `between` with each entry's path after its name was read from the
    /// directory and before the entry is opened: the window in which the account can swap it.
    pub(super) fn chown_tree_with(
        path: &Path,
        uid: u32,
        gid: u32,
        skipped: &mut Vec<PathBuf>,
        between: &dyn Fn(&Path),
    ) -> io::Result<()> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        let mut walk = Walk {
            uid,
            gid,
            skipped,
            between,
        };
        walk.entry(libc::AT_FDCWD, &name, path)
    }

    struct Walk<'a> {
        uid: u32,
        gid: u32,
        skipped: &'a mut Vec<PathBuf>,
        between: &'a dyn Fn(&Path),
    }

    impl Walk<'_> {
        /// Re-own the entry `name` in `dir` through a handle on the entry itself. Its type and its
        /// link count are read from that handle, and its owner is changed through it, so a name
        /// swapped after it was read changes only what the handle holds. A directory is walked;
        /// anything else with a second hard link is skipped.
        fn entry(&mut self, dir: RawFd, name: &CStr, path: &Path) -> io::Result<()> {
            let handle = match open(dir, name, ENTRY) {
                Ok(handle) => handle,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            let st = fstat(&handle)?;
            if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                return self.directory(handle, path);
            }
            if st.st_nlink > 1 {
                self.skipped.push(path.to_path_buf());
                return Ok(());
            }
            chown(&handle, self.uid, self.gid)
        }

        /// Re-own the directory `handle` holds, then its entries, read from the handle.
        fn directory(&mut self, handle: OwnedFd, path: &Path) -> io::Result<()> {
            // The path-only handle cannot list entries; `.` through it is that same directory.
            #[cfg(target_os = "linux")]
            let handle = match open(handle.as_raw_fd(), c".", DIRECTORY) {
                Ok(handle) => handle,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            chown(&handle, self.uid, self.gid)?;
            for name in entries(&handle)? {
                let child = path.join(OsStr::from_bytes(name.as_bytes()));
                (self.between)(&child);
                self.entry(handle.as_raw_fd(), &name, &child)?;
            }
            Ok(())
        }
    }

    /// The names in `dir`, read from the handle, without `.` and `..`.
    fn entries(dir: &OwnedFd) -> io::Result<Vec<CString>> {
        // `fdopendir` takes the descriptor it is given; it gets a duplicate, and `dir` stays ours.
        let raw = dir.try_clone()?.into_raw_fd();
        // SAFETY: `raw` is an open directory descriptor this function owns.
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed, so `raw` is still ours to close.
            unsafe { libc::close(raw) };
            return Err(error);
        }
        let mut names = Vec::new();
        let result = loop {
            // SAFETY: errno is thread-local; clearing it tells the end of the stream from a
            // failure, which `readdir` both report as null.
            unsafe { *errno() = 0 };
            // SAFETY: `stream` is the open stream from `fdopendir`.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                break match error.raw_os_error() {
                    Some(0) | None => Ok(()),
                    Some(_) => Err(error),
                };
            }
            // SAFETY: `entry` is valid until the next `readdir` on this stream, and `d_name` is
            // NUL-terminated; the name is copied out at once.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        };
        // SAFETY: `stream` is open and closed once; this closes `raw` with it.
        unsafe { libc::closedir(stream) };
        result.map(|()| names)
    }

    #[cfg(target_os = "linux")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno location.
        unsafe { libc::__errno_location() }
    }

    #[cfg(target_os = "macos")]
    fn errno() -> *mut libc::c_int {
        // SAFETY: returns the calling thread's errno location.
        unsafe { libc::__error() }
    }

    /// What `handle` holds, as the kernel sees it.
    fn fstat(handle: &OwnedFd) -> io::Result<libc::stat> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid descriptor and room for one `stat`.
        if unsafe { libc::fstat(handle.as_raw_fd(), st.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fstat` succeeded and filled it.
        Ok(unsafe { st.assume_init() })
    }

    /// `name` in `dir`, opened with `flags`; the last component never follows a link.
    fn open(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
        // SAFETY: a descriptor or `AT_FDCWD` and a NUL-terminated name; no `O_CREAT`, so no mode.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
/// Each path is re-owned as what it is (`lchown`) and nothing is walked: the state directory
/// belongs to that account, which could swap a directory for a link while root walked it, so the
/// caller names exactly the files it wrote.
///
/// On Windows there is nothing to do: the handover granted the account Modify with inheritance, so
/// what is created under the data root is the account's to use already.
///
/// # Errors
/// Returns an error naming the path whose owner could not be changed.
pub fn match_owner(like: &Path, paths: &[&Path]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let Ok(owner) = std::fs::symlink_metadata(like) else {
            return Ok(());
        };
        for path in paths {
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                continue;
            };
            if (meta.uid(), meta.gid()) == (owner.uid(), owner.gid()) {
                continue;
            }
            std::os::unix::fs::lchown(path, Some(owner.uid()), Some(owner.gid())).map_err(|e| {
                format!(
                    "cannot give {} the owner of {}: {e}",
                    path.display(),
                    like.display()
                )
            })?;
        }
    }
    #[cfg(not(unix))]
    let _ = (like, paths);
    Ok(())
}

/// The passwordless Windows account forms — the only ones `--run-as` accepts, because a password
/// parameter must not exist (ADR-0019: it would stand in the process list and the installer log).
///
/// Compiled wherever it is used — the Windows install, and the tests of any platform: the rule is
/// pure string logic, and testing it must not need a Windows host.
#[cfg(any(not(unix), test))]
fn windows_account_form(account: &str, service: &str) -> Result<(), String> {
    const NT_SERVICE: &str = r"NT SERVICE\";
    const BUILT_IN: [&str; 2] = [r"NT AUTHORITY\LocalService", r"NT AUTHORITY\NetworkService"];

    if BUILT_IN.iter().any(|b| account.eq_ignore_ascii_case(b)) {
        return Ok(());
    }
    if account.len() >= NT_SERVICE.len()
        && account[..NT_SERVICE.len()].eq_ignore_ascii_case(NT_SERVICE)
    {
        let name = &account[NT_SERVICE.len()..];
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

#[cfg(test)]
mod tests {
    use super::*;

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
            .hand_over(&[root, &missing])
            .expect("a missing config file is skipped, the tree is walked");
        assert!(skipped.is_empty(), "{skipped:?}");
        for reached in [root.to_path_buf(), versions, binary, root.join("current")] {
            let gid = std::fs::symlink_metadata(&reached).expect("exists").gid();
            assert_eq!(gid, me.gid, "{}", reached.display());
        }
    }

    /// A directory inside the tree that is a link to one outside it is re-owned as the link; the
    /// walk never reaches what it points to.
    /// Verifies: ADR-0042
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
        me.hand_over(&[&root, &root.join("state")])
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
    /// Verifies: ADR-0042
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
        let skipped = me.hand_over(&[&root]).expect("handover");
        assert_eq!(skipped, vec![linked.clone()]);
        assert_eq!(std::fs::metadata(&outside).expect("outside").gid(), before);
        assert_eq!(
            std::fs::metadata(root.join("plain")).expect("plain").gid(),
            me.gid
        );
    }

    /// A directory swapped for a link to one outside the tree, after the walk read its name and
    /// before it opened it, is re-owned as the link; nothing outside is reached.
    /// Verifies: ADR-0042
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
        super::walk::chown_tree_with(&root, me.uid, me.gid, &mut skipped, &|entry| {
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
    /// Verifies: ADR-0042
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
        super::walk::chown_tree_with(&root, me.uid, me.gid, &mut skipped, &|entry| {
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
        assert_eq!(skipped, vec![swapped]);
        assert_eq!(
            std::fs::metadata(root.join("plain")).expect("plain").gid(),
            me.gid
        );
    }
}
