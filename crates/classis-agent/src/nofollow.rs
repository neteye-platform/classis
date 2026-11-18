//! File operations in a directory the Client's service account can write, which never follow a
//! link that account could have planted (ADR-0054).
//!
//! `service install` and `service config` run as root or as an Administrator, and they write into
//! the state directory and the executable layout, which belong to the service's account. A plain
//! `fs::write` there follows a symbolic link, a junction or a Windows symbolic link the account put
//! at the name, and the privileged write lands wherever the link points. So every operation here
//! works on a [`HeldDir`]: a directory opened without following a link at its own name, and held
//! while the operation runs.
//!
//! - **Unix.** Each name is opened, created, renamed and removed relative to the held descriptor
//!   (`openat`, `mkdirat`, `renameat`, `unlinkat`) with `O_NOFOLLOW`. A file is written whole to a
//!   new temporary name, created with `O_CREAT | O_EXCL`, its mode set through the descriptor,
//!   synced, and renamed over the name: a rename replaces a link at the name and never follows it.
//! - **Windows.** The directory is opened as what it is (`FILE_FLAG_OPEN_REPARSE_POINT`) and a
//!   reparse point is refused. The handle is held without `FILE_SHARE_DELETE`, so the directory
//!   cannot be renamed or replaced while it is held, and a directory above it cannot be renamed
//!   while something under it is open. A file is read only when it is no reparse point, and
//!   written to a new temporary name (`CREATE_NEW`, which never opens an existing name) and renamed
//!   over the name.
//!
//! The directory a [`HeldDir`] is opened at is resolved as a path up to its parent: those
//! components are the operator's choice, and only the last one lies in a directory the account
//! writes. A directory below it is reached through [`HeldDir::dir`], one held name at a time.

use std::io;
use std::path::{Path, PathBuf};

/// A directory opened without following a link at its name, held while it is used.
pub struct HeldDir {
    path: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    _handle: std::fs::File,
}

impl HeldDir {
    /// Opens the directory at `path`, refusing a link at its last component.
    ///
    /// # Errors
    /// Returns an error when `path` names no directory, or names a link.
    pub fn open(path: &Path) -> io::Result<Self> {
        let (parent, name) = split(path)?;
        sys::open_in(parent, name, false, 0)
    }

    /// Opens a root the operator named — the data root or the layout root — and holds it.
    ///
    /// On Unix the path is followed: the root's name lies in a directory only root writes
    /// (`/var/lib`, `/opt`, `/Library/Application Support`). On Windows it does not: the account
    /// holds Modify, delete included, on the root itself, and Users may create folders in
    /// `%ProgramData%`, so a root that is a reparse point is refused, and the held handle keeps it
    /// from being renamed or replaced while it is held.
    ///
    /// # Errors
    /// Returns an error when `path` names no directory, or on Windows a reparse point.
    pub fn open_root(path: &Path) -> io::Result<Self> {
        sys::open_root(path)
    }

    /// Creates the directory at `path` where it is missing — its parents as plain directories,
    /// itself with `mode` — and opens it as [`open`](Self::open) does. On Unix an existing
    /// directory is narrowed to `mode` too, through the held descriptor.
    ///
    /// # Errors
    /// Returns an error when a directory cannot be created, or `path` names a link.
    pub fn create(path: &Path, mode: u32) -> io::Result<Self> {
        let (parent, name) = split(path)?;
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
        sys::open_in(parent, name, true, mode)
    }

    /// The path this directory was opened at.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory `name` in this one, created with `mode` where it is missing, never through a
    /// link.
    ///
    /// # Errors
    /// Returns an error when it cannot be created or opened, or is a link.
    pub fn dir(&self, name: &str, mode: u32) -> io::Result<Self> {
        check_name(name)?;
        sys::dir(self, name, mode)
    }

    /// The bytes of the regular file `name`, refusing a link.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read, or is no regular file.
    pub fn read(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut self.open_file(name)?, &mut bytes)?;
        Ok(bytes)
    }

    /// The regular file `name`, opened for reading, refusing a link: what its metadata says is
    /// what is read.
    ///
    /// # Errors
    /// Returns an error when the file cannot be opened, or is no regular file.
    pub fn open_file(&self, name: &str) -> io::Result<std::fs::File> {
        check_name(name)?;
        sys::open_file(self, name)
    }

    /// The existing regular file `name`, opened for writing in place, refusing a link.
    ///
    /// # Errors
    /// Returns an error when the file cannot be opened, or is no regular file.
    pub fn open_for_writing(&self, name: &str) -> io::Result<std::fs::File> {
        check_name(name)?;
        sys::open_for_writing(self, name)
    }

    /// Writes `contents` as the file `name`, with `mode` on Unix: whole, to a new temporary name
    /// beside it, renamed over `name`. A link at `name` is replaced, never followed.
    ///
    /// # Errors
    /// Returns an error when the file cannot be written or renamed into place.
    pub fn write(&self, name: &str, contents: &[u8], mode: u32) -> io::Result<()> {
        check_name(name)?;
        // `~` is in no name a config-map entry is stored under (`storage::entry_file_name`), so
        // the temporary name never collides with a file this directory is meant to hold.
        let temporary = format!("{name}~");
        sys::write(self, name, &temporary, contents, mode)
    }

    /// Writes `contents` as the file `name`, with `mode` on Unix, only where nothing is at `name`:
    /// whole, to a new temporary name beside it, then linked to `name`, which refuses a name that
    /// exists — a file, or a link, which is never followed. Two runs that write the same name
    /// cannot both succeed, and neither replaces what the other wrote.
    ///
    /// # Errors
    /// Returns an error of kind `AlreadyExists` when something is at `name`, and another when the
    /// file cannot be written.
    pub fn write_new(&self, name: &str, contents: &[u8], mode: u32) -> io::Result<()> {
        check_name(name)?;
        let temporary = format!("{name}~");
        sys::write_new(self, name, &temporary, contents, mode)
    }

    /// Makes what was created, renamed or removed in this directory durable. On Windows NTFS
    /// journals the directory's entries itself, and a directory handle opened for reading cannot be
    /// flushed, so nothing is done.
    ///
    /// # Errors
    /// Returns an error when the sync fails.
    pub fn sync(&self) -> io::Result<()> {
        sys::sync(self)
    }

    /// Renames `from` to `to` within this directory. A link is renamed as a link.
    ///
    /// # Errors
    /// Returns an error when the rename fails.
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        check_name(from)?;
        check_name(to)?;
        sys::rename(self, from, to)
    }

    /// Removes the file `name`; a link is removed as a link.
    ///
    /// # Errors
    /// Returns an error when the removal fails, a missing file included.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        sys::remove(self, name)
    }

    /// The names of everything in this directory, read through its handle.
    ///
    /// # Errors
    /// Returns an error when the directory cannot be read.
    pub fn names(&self) -> io::Result<Vec<std::ffi::OsString>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            Ok(crate::storage::handle::entries(&self.fd)?
                .into_iter()
                .map(|name| std::ffi::OsString::from_vec(name.into_bytes()))
                .collect())
        }
        #[cfg(windows)]
        {
            std::fs::read_dir(&self.path)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect()
        }
    }

    /// Removes the entry `name` with everything beneath it. A link is removed as a link and never
    /// followed, in this directory or in any directory beneath it.
    ///
    /// # Errors
    /// Returns the first entry that cannot be removed.
    pub fn remove_all(&self, name: &std::ffi::OsStr) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let entry = std::ffi::CString::new(name.as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            crate::storage::handle::remove_tree_at(&self.fd, &entry, &self.path.join(name))
        }
        #[cfg(windows)]
        {
            let path = self.path.join(name);
            let kind = std::fs::symlink_metadata(&path)?.file_type();
            // A real directory is emptied without following a link or a junction in it; a link
            // is removed as itself, a file link or a directory link as each needs.
            if kind.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path).or_else(|_| std::fs::remove_dir(&path))
            }
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for HeldDir {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

/// Reads the regular file at `path`, refusing a link at it or at its directory's name.
///
/// # Errors
/// Returns an error when the file cannot be read, or a link stands at either name.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let (dir, name) = held_parent(path)?;
    dir.read(name)
}

/// Writes `contents` to `path` as [`HeldDir::write`] does, refusing a link at its directory's name.
///
/// # Errors
/// Returns an error when the file cannot be written, or the directory is a link.
pub fn write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let (dir, name) = held_parent(path)?;
    dir.write(name, contents, mode)
}

/// The directory holding `path`, held, and the name of `path` in it.
pub fn held_parent(path: &Path) -> io::Result<(HeldDir, &str)> {
    let (parent, name) = split(path)?;
    let name = name.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a UTF-8 name", path.display()),
        )
    })?;
    Ok((HeldDir::open(parent)?, name))
}

/// `path` as its parent directory and its last component, which must be a name. A path without a
/// parent is in the working directory.
fn split(path: &Path) -> io::Result<(&Path, &std::ffi::OsStr)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no file or directory", path.display()),
        )
    })?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok((parent, name))
}

/// A name within a held directory is one plain component: never a path, `.` or `..`.
fn check_name(name: &str) -> io::Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a plain file name"),
        )),
    }
}

/// The error for a link where a plain entry was required.
fn refused_link(path: &Path) -> io::Error {
    io::Error::other(format!(
        "{} is a link, which is refused: the service's account could have put it there",
        path.display()
    ))
}

#[cfg(unix)]
mod sys {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use super::{refused_link, HeldDir};

    const DIRECTORY: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    fn openat(dir: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
        // SAFETY: a descriptor or `AT_FDCWD`, a NUL-terminated name, and the mode `O_CREAT` reads.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags, mode as libc::c_uint) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// A link at the last component opened with `O_NOFOLLOW` reads as `ELOOP`.
    fn named(e: io::Error, path: &Path) -> io::Error {
        if e.raw_os_error() == Some(libc::ELOOP) {
            refused_link(path)
        } else {
            e
        }
    }

    fn mkdirat(dir: RawFd, name: &CString, mode: u32) -> io::Result<()> {
        // SAFETY: a descriptor or `AT_FDCWD` and a NUL-terminated name.
        if unsafe { libc::mkdirat(dir, name.as_ptr(), mode as libc::mode_t) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        // `mkdirat` never follows a link at the name: one there is `EEXIST`, and the open after it
        // refuses it.
        if e.kind() == io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(e)
        }
    }

    fn fchmod(fd: &OwnedFd, mode: u32) -> io::Result<()> {
        // SAFETY: a valid descriptor.
        if unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn open_root(path: &Path) -> io::Result<HeldDir> {
        let fd = openat(
            libc::AT_FDCWD,
            &c_name(path.as_os_str())?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        Ok(HeldDir {
            path: path.to_path_buf(),
            fd,
        })
    }

    pub(super) fn open_in(
        parent: &Path,
        name: &OsStr,
        create: bool,
        mode: u32,
    ) -> io::Result<HeldDir> {
        let path = parent.join(name);
        let parent_fd = openat(
            libc::AT_FDCWD,
            &c_name(parent.as_os_str())?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let name = c_name(name)?;
        if create {
            mkdirat(parent_fd.as_raw_fd(), &name, mode)?;
        }
        let fd = openat(parent_fd.as_raw_fd(), &name, DIRECTORY, 0).map_err(|e| named(e, &path))?;
        if create {
            fchmod(&fd, mode)?;
        }
        Ok(HeldDir { path, fd })
    }

    pub(super) fn dir(held: &HeldDir, name: &str, mode: u32) -> io::Result<HeldDir> {
        let path = held.path.join(name);
        let c = c_name(OsStr::new(name))?;
        mkdirat(held.fd.as_raw_fd(), &c, mode)?;
        let fd = openat(held.fd.as_raw_fd(), &c, DIRECTORY, 0).map_err(|e| named(e, &path))?;
        Ok(HeldDir { path, fd })
    }

    pub(super) fn open_file(held: &HeldDir, name: &str) -> io::Result<File> {
        open_regular(held, name, libc::O_RDONLY)
    }

    pub(super) fn open_for_writing(held: &HeldDir, name: &str) -> io::Result<File> {
        open_regular(held, name, libc::O_WRONLY)
    }

    fn open_regular(held: &HeldDir, name: &str, access: libc::c_int) -> io::Result<File> {
        let path = held.path.join(name);
        // `O_NONBLOCK`: a FIFO at the name must not stall a privileged run; a regular file ignores it.
        let fd = openat(
            held.fd.as_raw_fd(),
            &c_name(OsStr::new(name))?,
            access | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
        .map_err(|e| named(e, &path))?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        Ok(file)
    }

    /// Writes `contents` to a new file `temporary` in `dir`, which `finish` then puts at its name.
    fn staged(
        held: &HeldDir,
        temporary: &str,
        contents: &[u8],
        mode: u32,
        finish: impl FnOnce(RawFd, &CString) -> io::Result<()>,
    ) -> io::Result<()> {
        let dir = held.fd.as_raw_fd();
        let temporary = c_name(OsStr::new(temporary))?;
        // A leftover from an interrupted run would make `O_EXCL` refuse; a link there goes as a link.
        match unlinkat(dir, &temporary) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let written = openat(
            dir,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
        .and_then(|fd| {
            // The umask may have narrowed the mode the open asked for.
            fchmod(&fd, mode)?;
            let mut file = File::from(fd);
            file.write_all(contents)?;
            file.sync_all()
        })
        .and_then(|()| finish(dir, &temporary));
        if written.is_err() {
            let _ = unlinkat(dir, &temporary);
        }
        written
    }

    pub(super) fn write(
        held: &HeldDir,
        name: &str,
        temporary: &str,
        contents: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        let name = c_name(OsStr::new(name))?;
        staged(held, temporary, contents, mode, |dir, temporary| {
            renameat(dir, temporary, &name)
        })
    }

    pub(super) fn write_new(
        held: &HeldDir,
        name: &str,
        temporary: &str,
        contents: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        let name = c_name(OsStr::new(name))?;
        staged(held, temporary, contents, mode, |dir, temporary| {
            // SAFETY: a valid descriptor and two NUL-terminated names; `linkat(2)` without
            // `AT_SYMLINK_FOLLOW` follows no link, and fails with `EEXIST` where `name` exists.
            if unsafe { libc::linkat(dir, temporary.as_ptr(), dir, name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // The data is at `name` now; the temporary name is only what is left of the staging.
            unlinkat(dir, temporary)
        })
    }

    fn unlinkat(dir: RawFd, name: &CString) -> io::Result<()> {
        // SAFETY: a valid descriptor and a NUL-terminated name; without `AT_REMOVEDIR` a link is
        // removed as a link.
        if unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn renameat(dir: RawFd, from: &CString, to: &CString) -> io::Result<()> {
        // SAFETY: a valid descriptor and two NUL-terminated names; neither is followed.
        if unsafe { libc::renameat(dir, from.as_ptr(), dir, to.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn rename(held: &HeldDir, from: &str, to: &str) -> io::Result<()> {
        renameat(
            held.fd.as_raw_fd(),
            &c_name(OsStr::new(from))?,
            &c_name(OsStr::new(to))?,
        )
    }

    pub(super) fn remove(held: &HeldDir, name: &str) -> io::Result<()> {
        unlinkat(held.fd.as_raw_fd(), &c_name(OsStr::new(name))?)
    }

    pub(super) fn sync(held: &HeldDir) -> io::Result<()> {
        // SAFETY: a valid descriptor.
        if unsafe { libc::fsync(held.fd.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
mod sys {
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write as _};
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;

    use super::{refused_link, HeldDir};

    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    /// The directory at `path` itself, held against a rename or a delete, or refused when it is a
    /// reparse point — a junction, a symbolic link or a mount point.
    fn hold(path: &Path) -> io::Result<HeldDir> {
        let handle = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let meta = handle.metadata()?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused_link(path));
        }
        if !meta.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        Ok(HeldDir {
            path: path.to_path_buf(),
            _handle: handle,
        })
    }

    pub(super) fn open_root(path: &Path) -> io::Result<HeldDir> {
        hold(path)
    }

    fn create_dir(path: &Path) -> io::Result<()> {
        match std::fs::create_dir(path) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
            _ => Ok(()),
        }
    }

    pub(super) fn open_in(
        parent: &Path,
        name: &OsStr,
        create: bool,
        _mode: u32,
    ) -> io::Result<HeldDir> {
        let path = parent.join(name);
        if create {
            create_dir(&path)?;
        }
        hold(&path)
    }

    pub(super) fn dir(held: &HeldDir, name: &str, _mode: u32) -> io::Result<HeldDir> {
        let path = held.path.join(name);
        create_dir(&path)?;
        hold(&path)
    }

    pub(super) fn open_file(held: &HeldDir, name: &str) -> io::Result<File> {
        open_regular(held, name, OpenOptions::new().read(true))
    }

    pub(super) fn open_for_writing(held: &HeldDir, name: &str) -> io::Result<File> {
        open_regular(held, name, OpenOptions::new().write(true))
    }

    fn open_regular(held: &HeldDir, name: &str, options: &mut OpenOptions) -> io::Result<File> {
        let path = held.path.join(name);
        let file = options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let meta = file.metadata()?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused_link(&path));
        }
        if !meta.is_file() {
            return Err(io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        Ok(file)
    }

    /// Writes `contents` to a new file `temporary` in `held`, which `finish` then puts at its name.
    fn staged(
        held: &HeldDir,
        temporary: &str,
        contents: &[u8],
        finish: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let temporary = held.path.join(temporary);
        // A leftover from an interrupted run would make `create_new` refuse; a link goes as a link.
        match std::fs::remove_file(&temporary) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .and_then(|mut file: File| {
                file.write_all(contents)?;
                file.sync_all()
            })
            .and_then(|()| finish(&temporary));
        if written.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        written
    }

    pub(super) fn write(
        held: &HeldDir,
        name: &str,
        temporary: &str,
        contents: &[u8],
        _mode: u32,
    ) -> io::Result<()> {
        staged(held, temporary, contents, |temporary| {
            std::fs::rename(temporary, held.path.join(name))
        })
    }

    pub(super) fn write_new(
        held: &HeldDir,
        name: &str,
        temporary: &str,
        contents: &[u8],
        _mode: u32,
    ) -> io::Result<()> {
        staged(held, temporary, contents, |temporary| {
            // A hard link is made only where nothing is at `name`; the temporary name goes after.
            std::fs::hard_link(temporary, held.path.join(name))?;
            std::fs::remove_file(temporary)
        })
    }

    pub(super) fn rename(held: &HeldDir, from: &str, to: &str) -> io::Result<()> {
        std::fs::rename(held.path.join(from), held.path.join(to))
    }

    pub(super) fn remove(held: &HeldDir, name: &str) -> io::Result<()> {
        std::fs::remove_file(held.path.join(name))
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn sync(_: &HeldDir) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `write_new` writes a name nothing is at, and never replaces what is: a file stands as it
    /// was, a link is no name to take and is not followed, and no temporary name is left behind
    /// (ADR-0064 clause 7).
    /// Verifies: ADR-0064
    #[test]
    fn write_new_refuses_a_name_that_exists_and_follows_no_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let held = HeldDir::open(dir.path()).expect("held");

        held.write_new("new", b"first", 0o600).expect("a new name");
        assert_eq!(
            std::fs::read(dir.path().join("new")).expect("read"),
            b"first"
        );
        let again = held
            .write_new("new", b"second", 0o600)
            .expect_err("a name taken");
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(dir.path().join("new")).expect("read"),
            b"first"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join("new"))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);

            let outside = tempfile::tempdir().expect("outside");
            std::os::unix::fs::symlink(outside.path().join("target"), dir.path().join("link"))
                .expect("link");
            let linked = held
                .write_new("link", b"x", 0o600)
                .expect_err("a link at the name");
            assert_eq!(linked.kind(), io::ErrorKind::AlreadyExists);
            assert!(
                !outside.path().join("target").exists(),
                "the link was followed"
            );
        }

        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert!(
            !names.iter().any(|name| name.ends_with('~')),
            "a temporary name was left: {names:?}"
        );
    }
}
