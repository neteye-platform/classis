//! Turning a verified artifact into a runnable program on disk.
//!
//! The Client installs programs in two quite different ways: a Managed Process is replaced by a
//! Supervisor that outlives it (ADR-0026), and the Client's own binary is staged beside the running
//! version and reached by a restart (ADR-0018). Those two lifecycles are genuinely different and
//! stay where they are — `supervisor::process` owns the first, [`crate::update`] the second.
//!
//! What they share is the step in the middle, and they shared it by writing it twice: unpack the
//! artifact — raw bytes or an archive holding the program (ADR-0026) — to a path, make the result
//! executable, and cope with the kernel refusing to exec a file that was written moments ago. That
//! is what lives here, so each rule is stated once.

use std::path::Path;
use std::time::Duration;

use tracing::info;

/// How many times an exec that failed with [`is_text_file_busy`] is worth retrying.
///
/// The window is a fork racing an exec, so it closes in microseconds; ten tries at
/// [`BUSY_DELAY`] is half a second of patience for a condition that normally clears on the first
/// retry, and still bounded enough that a genuinely stuck file fails rather than hangs.
pub const BUSY_RETRIES: u32 = 10;

/// How long to wait between the retries [`BUSY_RETRIES`] allows.
pub const BUSY_DELAY: Duration = Duration::from_millis(50);

/// `ETXTBSY`: the file cannot be executed because someone holds it open for writing.
///
/// Both callers hit this for the same reason, and it is not a fault of the artifact. A binary
/// written moments ago cannot be exec'd while any process still holds it open for writing —
/// including a child another thread of this Client forked for its own spawn, which inherits the
/// descriptor until it execs. It is transient, so both callers retry briefly rather than condemning
/// a binary that is perfectly good.
///
/// Unix-only as a condition: Windows fails a write to a running image instead, at a different point
/// and with a different remedy, so there is nothing to detect here.
pub fn is_text_file_busy(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ETXTBSY)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// Makes `path` executable.
///
/// Whatever put the bytes there, the mode is ours to set: a downloaded artifact carries the
/// download's permissions, a written one the process umask, and an unpacked one whatever the person
/// who built the archive happened to have. None of those is a decision about whether this program
/// may run.
///
/// A no-op off Unix, where executability is not a file mode.
///
/// # Errors
/// Returns an error when the mode cannot be set.
pub fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot make {} executable: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Writes the program held by `artifact` to `dest` and makes it executable.
///
/// The artifact is the program itself or an archive holding it under `member` (ADR-0026), decided
/// by the leading bytes rather than by a file name. `dest` is overwritten if it exists; its parent
/// directory must already be there.
///
/// This writes one file and nothing else — no staging, no rename, no rollback. Where the bytes end
/// up and what is done with them afterwards is the caller's, because that is exactly where the two
/// install lifecycles differ.
///
/// # Errors
/// Returns an error when the artifact cannot be read, is an archive without `member`, cannot be
/// written to `dest`, or cannot be made executable.
pub fn write_program(
    artifact: &Path,
    dest: &Path,
    member: &str,
    archive_key: Option<&str>,
) -> Result<(), String> {
    let mut out =
        std::fs::File::create(dest).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;

    match crate::archive::detect(artifact)? {
        crate::archive::Kind::Raw => {
            let mut source = std::fs::File::open(artifact)
                .map_err(|e| format!("cannot read {}: {e}", artifact.display()))?;
            std::io::copy(&mut source, &mut out)
                .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
        }
        kind @ (crate::archive::Kind::TarGz
        | crate::archive::Kind::SevenZ
        | crate::archive::Kind::Zip) => {
            let written = match kind {
                crate::archive::Kind::SevenZ => {
                    crate::archive::extract_7z(artifact, member, &mut out, archive_key)?
                }
                crate::archive::Kind::Zip => {
                    crate::archive::extract_zip(artifact, member, &mut out)?
                }
                _ => crate::archive::extract_tar_gz(artifact, member, &mut out)?,
            };
            info!(archive = %artifact.display(), member = %member, bytes = written, "unpacked the program from the archive");
        }
    }
    // The handle has to go before the mode is set and before anyone execs what was written.
    drop(out);

    make_executable(dest)
}
