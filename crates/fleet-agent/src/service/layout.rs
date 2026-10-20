//! The versioned install layout (ADR-0019): what makes a future self-update a pointer switch.
//!
//! ```text
//! <root>/versions/supervisor-<MAJOR.MINOR.PATCH>-<hash>/supervisor
//! <root>/current -> versions/supervisor-…/   # symlink (Unix) / junction (Windows)
//! ```
//!
//! The default state directory is [`STATE_DIR_NAME`] under the *data* root — the same directory
//! as this layout's root everywhere except Linux system installs, where the layout executes from
//! `/opt` while data stays in `/var/lib` (ADR-0019 clause 8).
//!
//! The directory name is Elastic Agent's `<component>-<version>-<hash>` scheme: always the bare
//! version base and the commit short-hash, never the pre-release — whether a directory holds a
//! release or a dev build is answered by the manifest inside it, which records the full ADR-0012
//! version string and the binary's SHA-256 (what a future self-update verifies against). The
//! service's program is `<root>/current/supervisor`, so switching versions never
//! re-registers the service.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The platform's binary filename inside a version directory (ADR-0019).
///
/// It is two contracts at once: the program a service unit is registered against, and the archive
/// member a self-update extracts from an offered package. Changing it after a release is therefore
/// not a rename but a migration — see ADR-0019.
pub const BINARY_FILENAME: &str = if cfg!(windows) {
    "supervisor.exe"
} else {
    "supervisor"
};

/// The **program's** name: the prefix of every version directory, and the same string
/// [`BINARY_FILENAME`] carries without its Windows extension. One definition, so the directory and
/// the file it holds cannot drift.
///
/// Not the product's, and not the service's. ADR-0019 clause 3 registers the service under
/// [`PRODUCT_NAME`](crate::product::PRODUCT_NAME), and clause 9 keeps this constant off it on
/// purpose: the version directory and the archive member a self-update extracts are identical in
/// every variant build, which is what lets one published package Set serve them all.
pub const COMPONENT: &str = "supervisor";

/// The manifest inside each version directory: the full version string and the content hash.
const MANIFEST_FILENAME: &str = "manifest.toml";

/// The state directory's name under its root (ADR-0019) — the *data* root, which ADR-0019
/// clause 3 places beside the configuration rather than inside the executable layout on Linux
/// system installs.
pub const STATE_DIR_NAME: &str = "state";

/// The install layout rooted at an operator-chosen directory (never a fixed path).
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// A layout rooted at `root`; nothing is created until something is staged.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `<root>/versions` — every installed version, side by side.
    #[must_use]
    pub fn versions_dir(&self) -> PathBuf {
        self.root.join("versions")
    }

    /// `<root>/versions/<name>` for a version-directory name.
    #[must_use]
    pub fn version_dir(&self, name: &str) -> PathBuf {
        self.versions_dir().join(name)
    }

    /// `<root>/current` — the stable pointer the service is registered against.
    #[must_use]
    pub fn current(&self) -> PathBuf {
        self.root.join("current")
    }

    /// `<root>/current/supervisor` — the program path an installed service runs.
    #[must_use]
    pub fn current_binary(&self) -> PathBuf {
        self.current().join(BINARY_FILENAME)
    }

    /// Point `current` at `version_dir`.
    ///
    /// On Unix this is atomic: a temporary symlink is `rename`d over `current` (never
    /// unlink-then-relink, which leaves a window with no pointer). On Windows the junction is
    /// recreated; callers only switch while the service is stopped (ADR-0019).
    ///
    /// # Errors
    /// Returns an error if the pointer cannot be created.
    pub fn set_current(&self, version_dir: &Path) -> Result<(), String> {
        #[cfg(unix)]
        {
            let staging = self.root.join(".current.tmp");
            let _ = std::fs::remove_file(&staging);
            std::os::unix::fs::symlink(version_dir, &staging)
                .map_err(|e| format!("cannot create the current pointer: {e}"))?;
            std::fs::rename(&staging, self.current())
                .map_err(|e| format!("cannot switch the current pointer: {e}"))
        }
        #[cfg(windows)]
        {
            let current = self.current();
            if current.exists() {
                std::fs::remove_dir(&current)
                    .map_err(|e| format!("cannot remove the current junction: {e}"))?;
            }
            // A directory junction needs no symlink privilege (unlike a real symlink), which is
            // why ADR-0019 uses one. `mklink /J` is the canonical way to create it.
            //
            // Both paths go through `backslashed` first: `mklink` is a `cmd` builtin, and `cmd`
            // reads `/` as the start of a switch. A root an operator wrote as `C:/fleet` — which
            // every other Windows API here accepts — would otherwise fail as `Invalid switch`,
            // during a self-update, with a message about switches rather than about paths.
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(backslashed(&current))
                .arg(backslashed(version_dir))
                .status()
                .map_err(|e| format!("cannot run mklink: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("mklink /J failed with {status}"))
            }
        }
    }

    /// Detect the layout an executable runs from (`<root>/versions/<version-dir>/supervisor`),
    /// returning the layout and the version directory. `None` for binaries outside a layout
    /// (development builds, `cargo run`).
    #[must_use]
    pub fn enclosing(exe: &Path) -> Option<(Layout, PathBuf)> {
        let version_dir = exe.parent()?;
        let versions = version_dir.parent()?;
        if versions.file_name()? != "versions" {
            return None;
        }
        let root = versions.parent()?;
        Some((Layout::new(root), version_dir.to_path_buf()))
    }

    /// Self-heal a torn pointer switch (ADR-0019): if `current` does not resolve to
    /// `running_dir` — the version directory this binary actually runs from — repoint it.
    /// Returns whether a repair happened.
    ///
    /// # Errors
    /// Returns an error if the pointer cannot be inspected or repaired.
    pub fn heal_current(&self, running_dir: &Path) -> Result<bool, String> {
        let points_at_us = std::fs::canonicalize(self.current())
            .ok()
            .zip(std::fs::canonicalize(running_dir).ok())
            .is_some_and(|(current, running)| current == running);
        if points_at_us {
            return Ok(false);
        }
        self.set_current(running_dir)?;
        Ok(true)
    }
}

/// The version-directory name for a full ADR-0012 version string:
/// `supervisor-<MAJOR.MINOR.PATCH>-<hash>` — never the pre-release (ADR-0019).
#[must_use]
pub fn version_dir_name(full_version: &str) -> String {
    let (base, metadata) = full_version.split_once('+').unwrap_or((full_version, ""));
    let core = base.split_once('-').map_or(base, |(core, _)| core);
    if metadata.is_empty() {
        // An OPAMP_PRODUCT_VERSION-override build outside a repository has no commit to cite.
        format!("{COMPONENT}-{core}")
    } else {
        format!("{COMPONENT}-{core}-{metadata}")
    }
}

/// This executable's path, resolved through the pointer it was started by.
///
/// `std::env::current_exe` is documented to differ exactly here: started through a symbolic link,
/// "some platforms will return the path of the symbolic link and other platforms will return the
/// path of the symbolic link's target". Linux reads `/proc/self/exe` and returns the target; macOS
/// returns the link. The service is registered against `<root>/current/supervisor` — the whole
/// point of the pointer — so on the platforms that return the link, the path is
/// `<root>/current/supervisor`, whose grandparent is not `versions`, and [`Layout::enclosing`] finds
/// no layout at all. What depends on that: the self-update (ADR-0018) and the torn-pointer repair,
/// neither of which would ever run.
///
/// The resolution is what makes the two platforms agree. On Windows the pointer is a junction and
/// the same difference applies, but `canonicalize` answers in the `\\?\` verbatim form there, which
/// `mklink /J` will not take — so the prefix is stripped back off.
///
/// # Errors
/// Returns an error when the executable cannot be located at all.
pub fn running_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate this executable: {e}"))?;
    Ok(resolve(exe))
}

/// The resolution [`running_exe`] performs, apart from it — the function above can only ever ask
/// about the process running it, which on this platform is already resolved.
///
/// An unresolvable path is not a reason to fail: what it names is still where this binary runs
/// from, and every caller is better off with it than with an error.
fn resolve(exe: PathBuf) -> PathBuf {
    match std::fs::canonicalize(&exe) {
        Ok(resolved) => plain(resolved),
        Err(_) => exe,
    }
}

/// A path spelled the only way `cmd` reads as a path: `/` is a switch to it, and a separator to
/// everything else on Windows.
#[cfg(windows)]
fn backslashed(path: &Path) -> std::ffi::OsString {
    match path.to_str() {
        Some(text) => std::ffi::OsString::from(text.replace('/', "\\")),
        // Not UTF-8, so there is nothing safe to rewrite — hand it over as it is and let the
        // failure, if any, come from the path rather than from this.
        None => path.as_os_str().to_os_string(),
    }
}

/// Windows' `canonicalize` answers `\\?\C:\…` (and `\\?\UNC\server\share`); every other platform
/// hands the path back as it is.
#[cfg(windows)]
fn plain(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(match rest.strip_prefix("UNC\\") {
            Some(unc) => format!(r"\\{unc}"),
            None => rest.to_string(),
        }),
        None => path,
    }
}

#[cfg(not(windows))]
fn plain(path: PathBuf) -> PathBuf {
    path
}

/// Writes a version directory's manifest: the full version string and the content hash of the
/// binary beside it, headed by a comment naming what wrote it.
pub(crate) fn write_manifest(
    dir: &Path,
    written_by: &str,
    version: &str,
    sha256: &str,
) -> std::io::Result<()> {
    std::fs::write(
        dir.join(MANIFEST_FILENAME),
        format!("# Written by {written_by}.\nversion = \"{version}\"\nsha256 = \"{sha256}\"\n"),
    )
}

/// Stage the running executable into its version directory, write the manifest, and point
/// `current` at it. Returns the program path to register the service with
/// (`<root>/current/supervisor`). Staging an already-present version replaces its contents — an
/// idempotent re-install, never a silent mix of two builds — except when the staged binary
/// already holds these exact bytes, which is skipped rather than rewritten: `service install`
/// can arrive through the `PATH` symlink (ADR-0019) and then *runs from* the staged file, and
/// Linux refuses to write over a running executable (`ETXTBSY`).
///
/// # Errors
/// Returns an error if the executable cannot be read or the layout cannot be written.
pub fn stage_current_exe(layout: &Layout) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate this executable: {e}"))?;
    let bytes = std::fs::read(&exe).map_err(|e| format!("cannot read {}: {e}", exe.display()))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));

    let version = fleet_core::version::current();
    let dir = layout.version_dir(&version_dir_name(version));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let binary = dir.join(BINARY_FILENAME);
    // Compared with the staged file itself, never trusted from the manifest beside it: the manifest
    // says what was staged, the file is what would run.
    let already_staged = std::fs::read(&binary).is_ok_and(|staged| staged == bytes);
    if !already_staged {
        std::fs::write(&binary, &bytes)
            .map_err(|e| format!("cannot write {}: {e}", binary.display()))?;
        crate::install::make_executable(&binary)?;
    }

    write_manifest(&dir, "`supervisor service install`", version, &sha256).map_err(|e| {
        format!(
            "cannot write {}: {e}",
            dir.join(MANIFEST_FILENAME).display()
        )
    })?;

    layout.set_current(&dir)?;
    Ok(layout.current_binary())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0019
    #[test]
    fn the_directory_name_is_base_plus_hash_never_the_prerelease() {
        assert_eq!(
            version_dir_name("1.2.3+a1b2c3d"),
            "supervisor-1.2.3-a1b2c3d"
        );
        assert_eq!(
            version_dir_name("1.2.3-dev+b4e5f6a"),
            "supervisor-1.2.3-b4e5f6a"
        );
        assert_eq!(
            version_dir_name("0.0.0-dev+a1b2c3d"),
            "supervisor-0.0.0-a1b2c3d"
        );
        // An override build outside a repository carries no metadata.
        assert_eq!(version_dir_name("9.9.9"), "supervisor-9.9.9");
    }

    #[test]
    fn paths_derive_from_the_root() {
        let layout = Layout::new("/opt/x");
        assert_eq!(layout.versions_dir(), PathBuf::from("/opt/x/versions"));
        assert_eq!(layout.current(), PathBuf::from("/opt/x/current"));
        assert!(layout.current_binary().starts_with("/opt/x/current"));
    }

    /// Runs on every platform, because the pointer is *not* the same thing on every platform: a
    /// symlink on Unix, a junction created through `cmd` on Windows (ADR-0019). Gating this to Unix
    /// left the mechanism with the more moving parts as the untested one.
    /// Verifies: ADR-0019
    #[test]
    fn set_current_points_and_repoints() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Canonicalize up front: macOS tempdirs live under /var → /private/var, so a resolved
        // pointer would otherwise never equal the raw path.
        let layout = Layout::new(dir.path().canonicalize().expect("canonical tempdir"));
        let a = layout.version_dir("supervisor-1.0.0-aaaaaaa");
        let b = layout.version_dir("supervisor-2.0.0-bbbbbbb");
        std::fs::create_dir_all(&a).expect("create a");
        std::fs::create_dir_all(&b).expect("create b");

        // Both sides resolved: on Windows `canonicalize` answers in the `\\?\` form, and comparing
        // it against a path built by joining would fail on the prefix rather than on the pointer.
        let resolved = |path: &Path| std::fs::canonicalize(path).expect("resolve");
        layout.set_current(&a).expect("point at a");
        assert_eq!(resolved(&layout.current()), resolved(&a));
        // Repointing replaces the pointer without a gap.
        layout.set_current(&b).expect("repoint at b");
        assert_eq!(resolved(&layout.current()), resolved(&b));
    }

    /// A root an operator wrote with forward slashes — `--root C:/fleet`, which every Windows API
    /// in this Client accepts. `mklink` is a `cmd` builtin and `cmd` reads `/` as a switch, so
    /// passed through as written it fails with `Invalid switch` in the middle of a self-update.
    #[cfg(windows)]
    #[test]
    fn a_root_written_with_forward_slashes_still_gets_its_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir
            .path()
            .canonicalize()
            .expect("canonical tempdir")
            .to_string_lossy()
            .replace('\\', "/");
        let layout = Layout::new(&root);
        let version_dir = layout.version_dir("supervisor-1.0.0-aaaaaaa");
        std::fs::create_dir_all(&version_dir).expect("create the version directory");

        layout.set_current(&version_dir).expect("point current");

        assert_eq!(
            std::fs::canonicalize(layout.current()).expect("resolve"),
            std::fs::canonicalize(&version_dir).expect("resolve"),
        );
    }

    /// Verifies: ADR-0019
    #[cfg(unix)]
    #[test]
    fn stage_writes_binary_manifest_and_pointer() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let layout = Layout::new(dir.path());
        let program = stage_current_exe(&layout).expect("stage");
        assert_eq!(program, layout.current_binary());

        let version_dir = layout.version_dir(&version_dir_name(fleet_core::version::current()));
        let staged = version_dir.join(BINARY_FILENAME);
        assert!(staged.is_file());
        let mode = staged.metadata().expect("metadata").permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "the staged binary must be executable");

        let manifest =
            std::fs::read_to_string(version_dir.join(MANIFEST_FILENAME)).expect("manifest");
        assert!(manifest.contains(&format!("version = \"{}\"", fleet_core::version::current())));
        let sha = manifest
            .lines()
            .find_map(|l| l.strip_prefix("sha256 = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .expect("sha256 line");
        assert_eq!(sha.len(), 64);

        assert_eq!(
            std::fs::canonicalize(layout.current()).expect("resolve current"),
            std::fs::canonicalize(&version_dir).expect("resolve version dir")
        );
    }

    /// `service install` reached through the `PATH` symlink runs *from* the staged file
    /// (ADR-0019); rewriting it would be refused (`ETXTBSY`), so identical bytes must be left
    /// alone. Observed via the modification time: pinned to the epoch, it only stays there when
    /// no write happened.
    /// Verifies: ADR-0019
    #[cfg(unix)]
    #[test]
    fn restaging_identical_bytes_leaves_the_staged_binary_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = Layout::new(dir.path());
        stage_current_exe(&layout).expect("stage");

        let staged = layout
            .version_dir(&version_dir_name(fleet_core::version::current()))
            .join(BINARY_FILENAME);
        let file = std::fs::File::options()
            .write(true)
            .open(&staged)
            .expect("open the staged binary");
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .expect("pin the modification time");
        drop(file);

        stage_current_exe(&layout).expect("restage");
        assert_eq!(
            std::fs::metadata(&staged)
                .expect("metadata")
                .modified()
                .expect("mtime"),
            std::time::SystemTime::UNIX_EPOCH,
            "identical bytes must not be rewritten"
        );
    }

    /// The skip is by content, never by presence: a staged binary holding the wrong bytes — a
    /// torn write, a tamper — is replaced, which is the idempotent re-install staging promises.
    /// Verifies: ADR-0019
    #[cfg(unix)]
    #[test]
    fn restaging_replaces_a_staged_binary_with_different_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = Layout::new(dir.path());
        stage_current_exe(&layout).expect("stage");

        let staged = layout
            .version_dir(&version_dir_name(fleet_core::version::current()))
            .join(BINARY_FILENAME);
        std::fs::write(&staged, b"not-the-client").expect("tamper");

        stage_current_exe(&layout).expect("restage");
        let running =
            std::fs::read(std::env::current_exe().expect("current exe")).expect("read own bytes");
        assert_eq!(
            std::fs::read(&staged).expect("read staged"),
            running,
            "different bytes must be replaced with the running binary's"
        );
    }

    /// Verifies: ADR-0019
    #[cfg(unix)]
    #[test]
    fn a_torn_pointer_is_healed_a_correct_one_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Canonicalize up front — see set_current_points_and_repoints.
        let layout = Layout::new(dir.path().canonicalize().expect("canonical tempdir"));
        let a = layout.version_dir("supervisor-1.0.0-aaaaaaa");
        let b = layout.version_dir("supervisor-2.0.0-bbbbbbb");
        std::fs::create_dir_all(&a).expect("create a");
        std::fs::create_dir_all(&b).expect("create b");

        // Torn swap: current points at a, but the running binary lives in b.
        layout.set_current(&a).expect("point at a");
        assert!(layout.heal_current(&b).expect("heal"), "must repair");
        assert_eq!(std::fs::canonicalize(layout.current()).expect("resolve"), b);
        // Second run: nothing to do.
        assert!(!layout.heal_current(&b).expect("heal again"));
    }

    #[test]
    fn enclosing_detects_a_layout_and_rejects_loose_binaries() {
        let (layout, version_dir) = Layout::enclosing(Path::new(
            "/opt/fleet/versions/supervisor-1.2.3-a1b2c3d/supervisor",
        ))
        .expect("a layout path");
        assert_eq!(layout.current(), PathBuf::from("/opt/fleet/current"));
        assert_eq!(
            version_dir,
            PathBuf::from("/opt/fleet/versions/supervisor-1.2.3-a1b2c3d")
        );
        assert!(Layout::enclosing(Path::new("/usr/bin/supervisor")).is_none());
        assert!(Layout::enclosing(Path::new("supervisor")).is_none());
    }

    /// What the service actually runs is `<root>/current/supervisor`, and on macOS that is the
    /// path `current_exe` hands back — the pointer, not the version directory behind it. The
    /// layout is invisible from there, so the resolution has to happen before anything looks for
    /// it. Provoked here with a symbolic link, which is what the pointer is on this platform anyway.
    /// Verifies: ADR-0019
    #[cfg(unix)]
    #[test]
    fn the_layout_is_found_from_the_pointer_the_service_was_registered_against() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = Layout::new(dir.path().canonicalize().expect("canonical tempdir"));
        let version_dir = layout.version_dir("supervisor-1.2.3-a1b2c3d");
        std::fs::create_dir_all(&version_dir).expect("create the version dir");
        std::fs::write(version_dir.join(BINARY_FILENAME), b"the-client").expect("write the binary");
        layout.set_current(&version_dir).expect("point current");

        // The macOS shape, unresolved: two directories up is the root, not `versions`.
        let through_pointer = layout.current_binary();
        assert!(
            Layout::enclosing(&through_pointer).is_none(),
            "the premise: this path alone says nothing about a layout"
        );

        let (found, running_dir) =
            Layout::enclosing(&resolve(through_pointer)).expect("resolved, the layout is there");
        assert_eq!(running_dir, version_dir);
        assert_eq!(found.current(), layout.current());
    }
}
