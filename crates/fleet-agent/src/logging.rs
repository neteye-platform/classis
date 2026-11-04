//! The Client's own log on disk, while it runs as a service (ADR-0019).
//!
//! The Windows SCM discards a service's stderr, so a Client installed there had no readable log at
//! all; systemd and launchd do capture it, and the file is written on those platforms too so that
//! "where are the logs" has one answer everywhere — including in a container, where neither is
//! present. In the foreground nothing is written: somebody is reading stderr there.
//!
//! This is not the OTLP own-logs bridge (ADR-0016) under another name. That one needs a Server that
//! is already reachable, which is exactly what a bad `supervisor.toml`, an unusable certificate, or a
//! refused endpoint is not.
//!
//! **The destination is not known when logging starts.** `tracing` takes one subscriber per process
//! and `main` installs it before the command line is parsed, so the instance — and with it the state
//! directory — does not exist yet. Rather than a second reloadable layer, the file layer is
//! installed from the start with [`LogFile`] as its writer, which discards everything until
//! [`open`] hands it somewhere to write. Events logged before that still reach stderr.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::{EitherWriter, MakeWriter};

/// The base name of the log file; the rotation appends the date.
const FILE_STEM: &str = "supervisor";
const FILE_SUFFIX: &str = "log";

/// The open file, once there is one. Set at most once per process.
static FILE: OnceLock<NonBlocking> = OnceLock::new();

/// The non-blocking writer's worker lives as long as the process: dropping this guard flushes and
/// stops it, so it is parked here rather than returned to a caller who would have to hold it.
static GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// The `fmt` layer's writer: the rotating file once [`open`] succeeded, and a sink until then.
///
/// A sink rather than an error, because this writer is consulted for every event from the first
/// line of `main` — long before there is an instance, a configuration, or a directory to write in.
pub struct LogFile;

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = EitherWriter<NonBlocking, std::io::Sink>;

    fn make_writer(&'a self) -> Self::Writer {
        match FILE.get() {
            Some(file) => EitherWriter::A(file.clone()),
            None => EitherWriter::B(std::io::sink()),
        }
    }
}

/// Starts writing the rotating log file in `dir`, keeping `keep` days.
///
/// Returns the directory in use, for the one line that tells an operator where to look. Calling it
/// a second time is a no-op: one process writes one log.
///
/// `keep` is a bound the caller cannot escape — `ClientConfig` refuses `0` at load rather than
/// reading it as "keep everything", which is the setting that fills a disk on a host nobody
/// watches.
///
/// With `private`, the directory and the Client's log files in it are kept the Client's alone
/// ([`keep_private`]); without, the directory is only created where it is missing.
pub fn open(dir: &Path, keep: usize, private: bool) -> Result<PathBuf, String> {
    if FILE.get().is_some() {
        return Ok(dir.to_path_buf());
    }
    prepare(dir, private)
        .map_err(|e| format!("cannot create the log directory {}: {e}", dir.display()))?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(FILE_STEM)
        .filename_suffix(FILE_SUFFIX)
        .max_log_files(keep.max(1))
        .build(dir)
        .map_err(|e| format!("cannot open the log file in {}: {e}", dir.display()))?;
    let (file, guard) = tracing_appender::non_blocking(appender);
    let _ = FILE.set(file);
    let _ = GUARD.set(guard);
    Ok(dir.to_path_buf())
}

/// Creates the log directory: with `private`, kept the Client's alone ([`keep_private`]); without,
/// only created where it is missing, and what it holds left as it is.
fn prepare(dir: &Path, private: bool) -> std::io::Result<()> {
    if private {
        keep_private(dir)
    } else {
        std::fs::create_dir_all(dir)
    }
}

/// Creates the log directory owner-only, `0700`, and narrows one that exists, with the Client's
/// log files already in it, to the Client alone: `0700` and `0600` (ADR-0059 clause 6). For a log
/// directory beneath a state directory that the process account's group passes through, which
/// [`is_private`] decides: the log is never among what that group reads. The appender creates each
/// day's file at the umask; the directory is what keeps it.
///
/// Only a regular file the Client owns, with one name, and named as the appender names its files
/// is narrowed; anything else there is left as it is.
fn keep_private(dir: &Path) -> std::io::Result<()> {
    crate::storage::create_private_dir(dir)?;
    #[cfg(unix)]
    for entry in std::fs::read_dir(dir)? {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(&format!("{FILE_STEM}."))
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.path())
        else {
            continue;
        };
        let meta = file.metadata()?;
        // SAFETY: geteuid(2) cannot fail and touches no memory.
        let own = meta.uid() == unsafe { libc::geteuid() };
        if own && meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o700))?;
        }
    }
    Ok(())
}

/// Whether the log directory `dir` is kept the Client's alone ([`keep_private`]): where a process
/// account is registered and `dir` lies beneath the state directory `state_dir`, which its group
/// passes through. A directory an operator chose elsewhere is the operator's, and is left as it is.
///
/// # Errors
/// Where a process account is registered, refuses a `dir` that narrowing would take from the
/// process account's group, or that would put the log where that group reads or writes: one
/// named with `..`, the state directory itself, the Supervisors' root `supervisors_root` or one
/// it lies beneath, and the directory of one of `supervisors` or one beneath it (ADR-0059 clause
/// 6). Another directory beneath the Supervisors' root is not refused: `<state_dir>/logs`, the
/// default, lies there where the Supervisors' root is the state directory itself.
pub fn is_private(
    dir: &Path,
    state_dir: &Path,
    supervisors_root: &Path,
    supervisors: &[&str],
    process_account: bool,
) -> Result<bool, String> {
    if !process_account {
        return Ok(false);
    }
    let refused = |why: &str| {
        Err(format!(
            "the log directory {} {why}, which the process account's group passes through or \
             writes; name another [logging] dir",
            dir.display()
        ))
    };
    if dir
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return refused("is named with '..', and may be the state directory or above it");
    }
    if dir == state_dir {
        return refused("is the state directory");
    }
    if supervisors_root.starts_with(dir) {
        return refused("is the Supervisors' root or holds it");
    }
    let supervisor = dir
        .strip_prefix(supervisors_root)
        .ok()
        .and_then(|beneath| beneath.components().next())
        .and_then(|first| first.as_os_str().to_str())
        .filter(|first| supervisors.contains(first));
    if let Some(supervisor) = supervisor {
        return refused(&format!(
            "is the directory of the Supervisor {supervisor} or lies beneath it"
        ));
    }
    Ok(dir.starts_with(state_dir))
}

/// Where the log goes for a given state directory, unless `[logging] dir` names somewhere else.
///
/// The state directory is the right home: it survives a self-update and `uninstall` deliberately
/// does not delete it (ADR-0019), so a log explaining a failed install is still there afterwards.
pub fn default_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(DIR_NAME)
}

/// The name of the default log directory in the state directory ([`default_dir`]).
pub(crate) const DIR_NAME: &str = "logs";

#[cfg(test)]
mod tests {
    use super::*;

    /// Until a directory is named, the writer swallows everything rather than failing: it is
    /// consulted from the first line of `main`, before any instance exists.
    /// Verifies: ADR-0019
    #[test]
    fn the_writer_discards_until_a_file_is_opened() {
        // `FILE` is process-global and another test may have opened it, so this asserts the
        // mapping rather than the global's state.
        let writer = LogFile.make_writer();
        match (FILE.get(), writer) {
            (None, EitherWriter::B(_)) | (Some(_), EitherWriter::A(_)) => {}
            _ => panic!("the writer must follow whether a file is open"),
        }
    }

    /// Verifies: ADR-0019
    #[test]
    fn the_log_directory_hangs_off_the_state_directory() {
        assert_eq!(
            default_dir(Path::new("/var/lib/opamp/state")),
            Path::new("/var/lib/opamp/state/logs")
        );
    }

    /// The rotation is what bounds the log, so opening has to actually produce a writable file in
    /// a directory it creates.
    #[test]
    fn opening_creates_the_directory_and_a_writable_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("nested").join("logs");
        let used = open(&logs, 7, false).expect("open");
        assert_eq!(used, logs);
        assert!(logs.is_dir(), "the directory is created");

        // The appender names the file after the stem and the day; writing through the layer is
        // covered by the integration test, which drives a real run.
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(FILE_STEM)
            .filename_suffix(FILE_SUFFIX)
            .max_log_files(7)
            .build(&logs)
            .expect("appender");
        use std::io::Write as _;
        let mut appender = appender;
        appender.write_all(b"line\n").expect("write");
        appender.flush().expect("flush");
        let written: Vec<_> = std::fs::read_dir(&logs)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            written
                .iter()
                .any(|n| n.starts_with(FILE_STEM) && n.ends_with(FILE_SUFFIX)),
            "the file is named after the stem and the day: {written:?}"
        );
    }

    /// The log is the Client's alone (ADR-0059 clause 6) where a process account passes through
    /// the state directory it lies in: its directory is made `0700`, and one that exists — made at
    /// the umask by an earlier version — is narrowed to `0700` with the Client's log files in it
    /// `0600`. A file there that the appender did not name is left as it is.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_log_directory_and_its_files_are_the_clients_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o7777;
        let dir = tempfile::tempdir().expect("tempdir");

        let fresh = dir.path().join("fresh").join("logs");
        prepare(&fresh, true).expect("created");
        assert_eq!(mode(&fresh), 0o700);

        let earlier = dir.path().join("earlier");
        std::fs::create_dir(&earlier).expect("mkdir");
        std::fs::set_permissions(&earlier, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let log = earlier.join("supervisor.2026-10-21.log");
        std::fs::write(&log, b"line\n").expect("write");
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let other = earlier.join("other.log");
        std::fs::write(&other, b"line\n").expect("write");
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        prepare(&earlier, true).expect("narrowed");
        assert_eq!(mode(&earlier), 0o700);
        assert_eq!(mode(&log), 0o600);
        assert_eq!(mode(&other), 0o644, "not the appender's");
    }

    /// Where a process account is registered, a log directory narrowing would take from its group
    /// is refused: the state directory itself, the Supervisors' root or a directory above it, a
    /// Supervisor's directory or one beneath it, and a path that reaches any of them through `..`.
    /// A real subdirectory of the state directory is narrowed, and so is one beside a Supervisors'
    /// root the operator moved out of it (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[test]
    fn a_log_directory_the_process_accounts_group_passes_through_is_refused() {
        let state = Path::new("/var/lib/opamp-fleet/state");
        let supervisors = state.join("supervisors");
        for dir in [
            state.to_path_buf(),
            supervisors.clone(),
            supervisors.join("agent"),
            supervisors.join("agent").join("logs"),
            state.join("logs").join("..").join("x"),
            state.join("..").join("x"),
        ] {
            assert!(
                is_private(&dir, state, &supervisors, &["agent"], true).is_err(),
                "{}",
                dir.display()
            );
            assert_eq!(
                is_private(&dir, state, &supervisors, &["agent"], false),
                Ok(false)
            );
        }
        let moved = Path::new("/srv/supervisors");
        assert!(is_private(Path::new("/srv"), state, moved, &["agent"], true).is_err());
        assert_eq!(
            is_private(&state.join("logs"), state, moved, &["agent"], true),
            Ok(true)
        );
        assert_eq!(
            is_private(
                &state.join("logs").join("client"),
                state,
                &supervisors,
                &["agent"],
                true
            ),
            Ok(true)
        );
    }

    /// Where the Supervisors' root is the state directory itself, the default log directory
    /// `<state_dir>/logs` is the Client's and narrowed, unless a Supervisor is named `logs`; a
    /// Supervisor's directory there is refused as anywhere (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[test]
    fn the_default_log_directory_is_kept_where_the_supervisors_root_is_the_state_directory() {
        let state = Path::new("/var/lib/opamp-fleet/state");
        assert_eq!(
            is_private(&default_dir(state), state, state, &["agent"], true),
            Ok(true)
        );
        assert!(is_private(&default_dir(state), state, state, &["logs"], true).is_err());
        assert!(is_private(&state.join("agent"), state, state, &["agent"], true).is_err());
    }

    /// A log directory is kept private only beneath the state directory and only where a process
    /// account is registered; otherwise — and in a directory the operator chose elsewhere, such
    /// as `/var/log` — the directory and what it holds stay as they are (ADR-0059 clause 6).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn a_log_directory_elsewhere_or_without_a_process_account_is_left_as_it_is() {
        use std::os::unix::fs::PermissionsExt as _;
        let state = Path::new("/var/lib/opamp-fleet/state");
        let supervisors = state.join("supervisors");
        assert_eq!(
            is_private(&default_dir(state), state, &supervisors, &["agent"], true),
            Ok(true)
        );
        assert_eq!(
            is_private(&default_dir(state), state, &supervisors, &["agent"], false),
            Ok(false)
        );
        assert_eq!(
            is_private(Path::new("/var/log"), state, &supervisors, &["agent"], true),
            Ok(false)
        );

        let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o7777;
        let dir = tempfile::tempdir().expect("tempdir");
        let chosen = dir.path().join("log");
        std::fs::create_dir(&chosen).expect("mkdir");
        std::fs::set_permissions(&chosen, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let foreign = chosen.join("syslog");
        let log = chosen.join("supervisor.2026-10-21.log");
        for file in [&foreign, &log] {
            std::fs::write(file, b"line\n").expect("write");
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        }
        prepare(&chosen, false).expect("left");
        assert_eq!(mode(&chosen), 0o755);
        assert_eq!(mode(&foreign), 0o644);
        assert_eq!(mode(&log), 0o644);
    }
}
