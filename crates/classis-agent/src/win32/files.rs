//! Files and directories reached one handle at a time, never through a link, and their owner and
//! DACL read and set through that handle (ADR-0059 clauses 6 and 10) — what `storage::handle` is on
//! Unix.
//!
//! Every entry is opened as itself (`FILE_FLAG_OPEN_REPARSE_POINT`): a symbolic link or a junction
//! is the link, never what it names, and a walk enters no link. A directory on the way is held
//! open without `FILE_SHARE_DELETE` for as long as anything beneath it is reached, so nobody can
//! rename it, or replace it with a link, under the walk (CreateFileW): the path from the held
//! directory to the next entry names the same directory throughout. A regular file with a second
//! hard link is passed over and named: its other name may stand anywhere on the volume, and
//! changing it would change that too.
//!
//! A DACL is set with `SetKernelObjectSecurity` on the handle, which changes that one object.
//! Learn points file systems to `SetSecurityInfo` and `SetNamedSecurityInfo` instead, because
//! those propagate what a directory passes on to what it holds (SetSecurityInfo, Remarks); that
//! propagation is exactly what is not wanted here, since nothing documents that it stays out of a
//! junction a process account placed, or out of what the process account owns. What a directory
//! passes on to what it already holds is applied by the walk itself ([`super::acl`]). Whether the
//! system keeps a DACL's protection set this way is not documented either: every DACL set is read
//! back, and one whose protection did not hold fails the change.

use std::fs::File;
use std::io;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};

use super::acl::Dacl;
use super::Sid;

const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// `FILE_READ_DATA`, `FILE_LIST_DIRECTORY` for a directory.
const FILE_READ_DATA: u32 = 0x0001;
const SYNCHRONIZE: u32 = 0x0010_0000;
/// `FILE_FLAG_BACKUP_SEMANTICS`, which opens a directory — and, where the backup and restore
/// privileges are enabled ([`super::BackupPrivileges`]), whatever its DACL says — and
/// `FILE_FLAG_OPEN_REPARSE_POINT`, which opens a link as itself.
const AS_ITSELF: u32 = 0x0200_0000 | 0x0020_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_SHARE_DELETE: u32 = 0x4;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const REPARSE_POINT: u32 = 0x400;
/// `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: i32 = 5;
/// `ERROR_SHARING_VIOLATION`.
const SHARING_VIOLATION: i32 = 32;

/// What an entry is opened for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Its attributes alone: a directory passed through.
    Pass,
    /// Its owner and its DACL, read.
    Read,
    /// Its owner and its DACL, read, and its DACL changed.
    Dacl,
    /// Its owner changed too.
    Owner,
}

impl Access {
    fn mask(self) -> u32 {
        let read = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        match self {
            Access::Pass => read,
            Access::Read => read | READ_CONTROL,
            Access::Dacl => read | READ_CONTROL | WRITE_DAC,
            Access::Owner => read | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
        }
    }
}

/// One entry, opened as itself.
pub struct Entry {
    pub path: PathBuf,
    file: File,
    /// A directory, and no link to one.
    pub dir: bool,
    /// A symbolic link or a junction.
    pub link: bool,
    /// How many names the entry has.
    pub links: u32,
}

impl Entry {
    /// Opens `path` as itself for `access`; held, so that nobody renames it meanwhile, where
    /// `hold`. Holding asks to read the entry's data too (`FILE_READ_DATA`, which lists a
    /// directory): the file system checks the share modes of an open that asks for data or for
    /// deleting alone, so an open for attributes and the DACL alone, whatever it shares, holds
    /// nothing and is held up by nothing.
    ///
    /// # Errors
    /// Returns why it cannot be opened: `NotFound` where it does not exist.
    pub fn open(path: &Path, access: Access, hold: bool) -> io::Result<Entry> {
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | if hold { 0 } else { FILE_SHARE_DELETE };
        let file = std::fs::OpenOptions::new()
            .access_mode(access.mask() | if hold { FILE_READ_DATA } else { 0 })
            .share_mode(share)
            .custom_flags(AS_ITSELF)
            .open(path)?;
        let meta = file.metadata()?;
        let link = meta.file_attributes() & REPARSE_POINT != 0;
        let links = super::link_count(file.as_raw_handle())?;
        Ok(Entry {
            path: path.to_path_buf(),
            dir: meta.is_dir() && !link,
            link,
            links,
            file,
        })
    }

    /// A regular file with more than one name.
    #[must_use]
    pub fn hard_linked(&self) -> bool {
        !self.dir && !self.link && self.links > 1
    }

    /// The entry's owner.
    ///
    /// # Errors
    /// Returns why it could not be read.
    pub fn owner(&self) -> io::Result<Sid> {
        super::file_owner(self.file.as_raw_handle())
    }

    /// The entry's DACL.
    ///
    /// # Errors
    /// Returns why it could not be read.
    pub fn dacl(&self) -> io::Result<Dacl> {
        let text = super::security_text(self.file.as_raw_handle(), DACL_SECURITY_INFORMATION)?;
        Dacl::parse(&text).map_err(io::Error::other)
    }

    /// Sets the entry's DACL to exactly `dacl`, on this object alone, and reads it back: a DACL
    /// the object does not then hold as it was set fails the change.
    ///
    /// The file system sets a DACL by the rules of automatic inheritance (SetPrivateObjectSecurityEx,
    /// `SEF_DACL_AUTO_INHERIT`): an unprotected DACL set on an unprotected object keeps the
    /// object's inherited ACEs and takes only the explicit ones of what is set, so what a parent
    /// passes on could never be replaced that way. A protected DACL is taken as it is set, its
    /// ACEs made explicit, and an unprotected one set on a protected object is taken exactly as it
    /// is set, inherited ACEs included. So an unprotected DACL is set in two steps: its ACEs
    /// protected first, then the DACL itself.
    ///
    /// # Errors
    /// Returns why it could not be set, or what the object holds instead.
    pub fn set_dacl(&self, dacl: &Dacl) -> io::Result<()> {
        if !dacl.protected() {
            let first = Dacl {
                flags: format!("P{}", dacl.flags),
                aces: dacl.aces.clone(),
            };
            self.set(&first.text(), DACL_SECURITY_INFORMATION)?;
        }
        self.set(&dacl.text(), DACL_SECURITY_INFORMATION)?;
        let held = self.dacl()?;
        if !super::same_dacl(&held.text(), &dacl.text())? {
            return Err(io::Error::other(format!(
                "{}: the object holds {} where {} was set",
                self.path.display(),
                held.text(),
                dacl.text()
            )));
        }
        Ok(())
    }

    /// Makes `owner` — a SID or an SDDL alias such as `BA` — the entry's owner.
    ///
    /// # Errors
    /// Returns why it could not be set.
    pub fn set_owner(&self, owner: &str) -> io::Result<()> {
        self.set(&format!("O:{owner}"), OWNER_SECURITY_INFORMATION)
    }

    fn set(&self, sddl: &str, info: u32) -> io::Result<()> {
        super::set_security(self.file.as_raw_handle(), info, sddl)
    }
}

/// Opens `dir`, `root` or beneath it, for `access`, one component at a time from `root`: each held
/// while the next is opened, none a link, and each that is missing created where `create`. Returns
/// the directories on the way, held, and `dir`.
///
/// Holding shares no deleting, so an open fails with a sharing violation where another handle to a
/// component already holds it for deleting. At runtime that is the Client's grant to the process
/// account (`storage::grant`): a Managed Process that holds a directory on the path — one it may
/// delete through what the Client's directory passes on to it — fails the grant of the next
/// Supervisor's directory beneath it. Kept so: what is held for deleting may be renamed away while
/// it is walked, and the process account only stops its own programs' share being granted.
///
/// # Errors
/// Returns why `dir` cannot be reached: a link or a file on the way, a component missing, or one
/// held open for deleting by another handle.
pub fn open_beneath(
    root: &Path,
    dir: &Path,
    access: Access,
    create: bool,
) -> io::Result<(Vec<Entry>, Entry)> {
    let beneath = dir.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not beneath {}", dir.display(), root.display()),
        )
    })?;
    let parts: Vec<_> = beneath.components().collect();
    let mut held = Vec::new();
    let mut path = root.to_path_buf();
    for index in 0..=parts.len() {
        if index > 0 {
            path.push(parts[index - 1]);
        }
        let last = index == parts.len();
        let wanted = if last { access } else { Access::Pass };
        let entry = match Entry::open(&path, wanted, true) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                match std::fs::create_dir(&path) {
                    Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                    _ => {}
                }
                Entry::open(&path, wanted, true)?
            }
            entry => entry?,
        };
        if !entry.dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is a link or no directory", path.display()),
            ));
        }
        if last {
            return Ok((held, entry));
        }
        held.push(entry);
    }
    unreachable!("the loop returns at its last component")
}

/// What a walk passed over, each to be named in a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Passed {
    /// The account the walk leaves alone owns it; nothing beneath it was reached either.
    Owned(PathBuf),
    /// A regular file with a second hard link.
    HardLinked(PathBuf),
    /// It could not be opened to be changed, and the walk may go on without it.
    Unreadable(PathBuf),
    /// A directory something holds open for deleting, which the walk cannot hold: where the
    /// Managed Processes write, they may delete what is there, so whoever holds it is taken to be
    /// the process account, and nothing beneath it was reached.
    Held(PathBuf),
}

/// How a walk goes: what it opens each entry for, whose entries it leaves alone, whether an entry
/// it cannot open is passed over rather than an error — for a walk that only adds — and whether a
/// directory it cannot hold is passed over — for a walk that only adds or hands over, where what
/// it leaves undone leaves the process account with less — or fails the walk, for one that takes
/// away: what it cannot reach safely it must not leave as it was.
#[derive(Debug, Clone, Copy)]
pub struct Walk<'a> {
    pub access: Access,
    pub skip: Option<&'a Sid>,
    pub lenient: bool,
    pub takes_away: bool,
}

impl Walk<'_> {
    /// Opens the entry `path` the walk reached: `Ok(None)` where it is gone, `Err(passed)` inside
    /// where it is passed over. A directory is held; one that cannot be held — something holds it
    /// open for deleting — is the skipped account's, or an error. Whose an entry is that cannot be
    /// opened for the walk is asked of one handle opened to read it alone.
    fn open(&self, path: &Path) -> io::Result<Option<Result<Entry, Passed>>> {
        let opened = match Entry::open(path, self.access, true) {
            Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => {
                match Entry::open(path, self.access, false) {
                    Ok(entry) if entry.dir && !self.owned(&entry) => {
                        if self.takes_away {
                            return Err(io::Error::new(
                                e.kind(),
                                format!(
                                    "{} is held open for deleting, and what it holds cannot be \
                                     reached through it safely; stop the services and what else \
                                     holds it, and install again",
                                    path.display()
                                ),
                            ));
                        }
                        return Ok(Some(Err(Passed::Held(path.to_path_buf()))));
                    }
                    unheld => unheld,
                }
            }
            opened => opened,
        };
        let entry = match opened {
            Ok(entry) => entry,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(ACCESS_DENIED) => {
                let owned = Entry::open(path, Access::Read, false)
                    .ok()
                    .is_some_and(|read| self.owned(&read));
                if owned {
                    return Ok(Some(Err(Passed::Owned(path.to_path_buf()))));
                }
                if self.lenient {
                    return Ok(Some(Err(Passed::Unreadable(path.to_path_buf()))));
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        if self.owned(&entry) {
            return Ok(Some(Err(Passed::Owned(path.to_path_buf()))));
        }
        if entry.hard_linked() {
            return Ok(Some(Err(Passed::HardLinked(path.to_path_buf()))));
        }
        Ok(Some(Ok(entry)))
    }

    /// Whether the skipped account owns `entry`.
    fn owned(&self, entry: &Entry) -> bool {
        self.skip
            .is_some_and(|skip| entry.owner().ok().as_ref() == Some(skip))
    }
}

/// Walks what the directory `top` holds, top-down, calling `visit` for each entry with its
/// parent: never into a link, past every entry the walk's skipped account owns with all beneath
/// it, and past every regular file with a second hard link, each named in `passed`. `visit`
/// answers whether to go into a directory. An entry gone meanwhile is passed over.
///
/// # Errors
/// Returns the first error opening or visiting an entry.
pub fn walk(
    top: &Entry,
    how: Walk<'_>,
    visit: &mut dyn FnMut(&Entry, &Entry) -> io::Result<bool>,
    passed: &mut Vec<Passed>,
) -> io::Result<()> {
    for item in std::fs::read_dir(&top.path)? {
        let path = match item {
            Ok(item) => item.path(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let entry = match how.open(&path)? {
            None => continue,
            Some(Err(skipped)) => {
                passed.push(skipped);
                continue;
            }
            Some(Ok(entry)) => entry,
        };
        if visit(&entry, top)? && entry.dir {
            walk(&entry, how, visit, passed)?;
        }
    }
    Ok(())
}

/// Withdraws from `sid` whatever it is granted on `top` and everything beneath it — every ACE that
/// allows it, explicit or inherited, while one that denies it stays — and gives what it owns to
/// `owner`, as a change of owner withdraws an account's files on Unix: never through a link, and
/// past a file with a second hard link, as every walk goes. What a parent passes on to `sid` is
/// withdrawn from what it holds as well, so nothing created after a grant keeps a copy of it.
///
/// # Errors
/// Returns the first entry whose owner or DACL could not be read or set.
pub fn withdraw_tree(top: &Entry, sid: &Sid, owner: &str) -> io::Result<Vec<Passed>> {
    let mut passed = Vec::new();
    if top.hard_linked() {
        passed.push(Passed::HardLinked(top.path.clone()));
        return Ok(passed);
    }
    withdraw_one(top, sid, owner)?;
    if top.dir {
        let how = Walk {
            access: Access::Owner,
            skip: None,
            lenient: false,
            takes_away: true,
        };
        walk(
            top,
            how,
            &mut |entry, _| {
                withdraw_one(entry, sid, owner)?;
                Ok(true)
            },
            &mut passed,
        )?;
    }
    Ok(passed)
}

fn withdraw_one(entry: &Entry, sid: &Sid, owner: &str) -> io::Result<()> {
    if entry.owner().ok().as_ref() == Some(sid) {
        entry.set_owner(owner)?;
    }
    let dacl = entry.dacl()?;
    let without = dacl.without(sid.as_str());
    if without != dacl {
        entry.set_dacl(&without)?;
    }
    Ok(())
}

/// Grants `sid` the ACEs `[on_top, on_dir, on_file]`: `on_top` on `top`, a directory or a file,
/// `on_dir` on each directory and `on_file` on each file beneath it, each in place of what that
/// account was granted there — never through a link, past what `skip` owns, past a file with a
/// second hard link, and past an entry that cannot be opened, as the grant only adds. Changes
/// nothing where `top` holds `on_top` already and `again` is not asked. Returns what was passed
/// over, `top` itself where it is passed over.
///
/// # Errors
/// Returns the first entry whose DACL could not be read or set.
pub fn grant_tree(
    top: &Entry,
    sid: &str,
    [on_top, on_dir, on_file]: [&[String]; 3],
    skip: Option<&Sid>,
    again: bool,
) -> io::Result<Vec<Passed>> {
    let mut passed = Vec::new();
    if top.hard_linked() {
        passed.push(Passed::HardLinked(top.path.clone()));
        return Ok(passed);
    }
    let own = |entry: &Entry| if entry.dir { on_dir } else { on_file };
    let dacl = top.dacl()?;
    if !again && on_top.iter().all(|ace| dacl.holds(ace)) {
        return Ok(passed);
    }
    top.set_dacl(&dacl.granting(sid, on_top))?;
    if top.dir {
        let how = Walk {
            access: Access::Dacl,
            skip,
            lenient: true,
            takes_away: false,
        };
        walk(
            top,
            how,
            &mut |entry, _| {
                entry.set_dacl(&entry.dacl()?.granting(sid, own(entry)))?;
                Ok(true)
            },
            &mut passed,
        )?;
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory held is held: while the hold is open it cannot be renamed — the open for the
    /// rename asks to delete, which the hold shares with nobody (`ERROR_SHARING_VIOLATION`) — and
    /// once it is closed it can (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[test]
    fn a_held_directory_cannot_be_renamed() {
        /// ERROR_SHARING_VIOLATION.
        const SHARING_VIOLATION: i32 = 32;
        let dir = tempfile::tempdir().expect("tempdir");
        let held = dir.path().join("held");
        let moved = dir.path().join("moved");
        std::fs::create_dir(&held).expect("held");
        let hold = Entry::open(&held, Access::Read, true).expect("hold");
        let refused = std::fs::rename(&held, &moved).expect_err("held");
        assert_eq!(refused.raw_os_error(), Some(SHARING_VIOLATION), "{refused}");
        drop(hold);
        std::fs::rename(&held, &moved).expect("renamed once let go");
    }
}
