//! The Client replacing its own binary on the ADR-0019 version directories (ADR-0018): the
//! [`SelfUpdater`] adapter and the start-up check of the process that comes after it.
//!
//! Updating a Managed Process is done by a Supervisor that outlives it (ADR-0026): stop, swap,
//! restart, watch, roll back. Nothing here outlives anything — the process that installs the
//! package is the process that has to exit for the install to take effect. So the work is split
//! across the restart, and this module owns both halves:
//!
//! **Before.** [`install`] stages the new version *beside* the running one in the ADR-0019 layout,
//! proves it by running it (`client self-check`), records an [`UpdateMarker`], and moves the
//! `current` pointer. Nothing is overwritten, so the version being replaced is still on disk and
//! the rollback is a pointer move rather than a download.
//!
//! **After.** [`on_start`] runs before anything else in a fresh process. It finds the marker the
//! previous process left, counts the attempt, and either lets the run proceed on probation — until
//! [`commit`] declares the new version good — or gives up and points `current` back.
//!
//! The probe and the counter cover different failures and neither covers both. A binary that
//! cannot exec at all never reaches [`on_start`] to count anything, which is why it is proved
//! before the pointer moves; a binary that starts and then will not stay up cannot be caught by a
//! probe that only watched it print a line, which is why the counter exists.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::{SelfInstall, SelfUpdater, SELF_CHECK_TOKEN};
use crate::install;
use crate::service::layout::{self, Layout, BINARY_FILENAME};

/// The file [`install`] leaves for the next process to find, in the Client's state directory —
/// which survives the version switch because it is outside `versions/`.
const MARKER_FILE: &str = "update-marker.json";

/// How many starts a new version gets to [`commit`] itself before it is rolled back.
///
/// Each attempt costs the service manager's restart delay, so this is a handful of seconds of
/// crash-looping and not more. One would be too few — a host under load can lose a start to
/// something unrelated to the new binary — and many would leave a fleet crash-looping on a broken
/// version for minutes while it counted.
const MAX_ATTEMPTS: u32 = 3;

/// What the process that switched the pointer tells the one that comes after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMarker {
    /// The version directory that was current before the switch — where a rollback points back.
    pub previous_dir: PathBuf,
    /// The version directory now current.
    pub new_dir: PathBuf,
    /// The version the new directory holds, as the Server offered it.
    pub version: String,
    /// The offered package hash, hex-encoded: the status reported after the restart has to name
    /// the package it is about, and the Agent state machine is gone by then.
    pub package_hash_hex: String,
    /// How many times a process has started and found this marker.
    pub attempts: u32,
    /// The trace the install belongs to, and the span inside it that staged this version
    /// (ADR-0016 clause 20) — hex, as OpenTelemetry writes them.
    ///
    /// **Why a telemetry field is in an operational file.** The install necessarily completes in a
    /// different process than the one that started it, so the span that staged the version is gone
    /// before the commit or the rollback happens. Without these two ids the trace ends one line
    /// before the part it exists to explain. The marker is the only thing that crosses that
    /// boundary, so it is what carries them.
    ///
    /// Absent in a marker an older Client wrote, and absent whenever no destination was offered —
    /// the update proceeds either way, and the following process simply opens its own trace.
    #[serde(default)]
    pub trace: Option<TraceRef>,
}

/// The two ids that name a span in a trace, as [`UpdateMarker`] carries them across the restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRef {
    pub trace_id: String,
    pub span_id: String,
}

/// What [`on_start`] found, and what the run should therefore do.
#[derive(Debug, PartialEq, Eq)]
pub enum Startup {
    /// No update in flight; an ordinary run.
    Ordinary,
    /// This process is the new version on probation. It must [`commit`] once it is up.
    OnProbation(Box<UpdateMarker>),
    /// The new version used up its attempts. `current` has been pointed back and this process
    /// must exit so the manager starts the version it now names.
    RolledBack(Box<UpdateMarker>),
    /// An update finished and the outcome is owed to the Server — either the new version
    /// committing, or the old one reporting why it is back.
    Outcome(Box<UpdateOutcome>),
}

/// The terminal status a restarted Client owes the Server (ADR-0018): the install necessarily
/// completes in a different process than the one that started it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateOutcome {
    pub version: String,
    pub package_hash_hex: String,
    /// `None` is `Installed`; `Some(reason)` is `InstallFailed`.
    pub error: Option<String>,
}

/// The span in which the process that came up after the restart finishes what a previous process
/// started — a continuation of that install's trace when the marker carries one (ADR-0016 clause 20),
/// and an ordinary root span when it does not.
fn continued(marker: &UpdateMarker, span: tracing::Span) -> tracing::Span {
    if let Some(trace) = &marker.trace {
        crate::telemetry::continue_trace(&span, &trace.trace_id, &trace.span_id);
    }
    span
}

fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MARKER_FILE)
}

fn load_marker(state_dir: &Path) -> Option<UpdateMarker> {
    let text = std::fs::read_to_string(marker_path(state_dir)).ok()?;
    match serde_json::from_str(&text) {
        Ok(marker) => Some(marker),
        Err(e) => {
            // A marker we cannot read is worse than none: it would keep a Client on probation
            // forever. Drop it and carry on with whatever is current.
            warn!(error = %e, "the update marker is unreadable; ignoring it");
            let _ = std::fs::remove_file(marker_path(state_dir));
            None
        }
    }
}

fn store_marker(state_dir: &Path, marker: &UpdateMarker) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(marker).expect("an UpdateMarker serializes");
    std::fs::write(marker_path(state_dir), json)
        .map_err(|e| format!("cannot write the update marker: {e}"))
}

/// The [`SelfUpdater`] on this host (ADR-0018): the state directory the marker lives in, the key
/// that opens an encrypted archive, and the marker this process commits if it is itself a freshly
/// installed version.
pub struct Installer {
    state_dir: PathBuf,
    archive_key: Option<String>,
    probation: Option<UpdateMarker>,
}

impl Installer {
    #[must_use]
    pub fn new(
        state_dir: PathBuf,
        archive_key: Option<String>,
        probation: Option<UpdateMarker>,
    ) -> Self {
        Installer {
            state_dir,
            archive_key,
            probation,
        }
    }
}

impl SelfUpdater for Installer {
    fn install(&self, staged: &Path, version: &str, hash: &[u8]) -> Result<SelfInstall, String> {
        let installed = install(
            &self.state_dir,
            staged,
            version,
            hash,
            self.archive_key.as_deref(),
        );
        // Whatever the outcome, the staged artifact has served its purpose.
        let _ = std::fs::remove_file(staged);
        installed
    }

    fn commit_probation(&mut self) {
        if let Some(marker) = self.probation.take() {
            commit(&self.state_dir, &marker);
        }
    }
}

/// Installs a verified artifact as a new version of *this Client* and points `current` at it
/// (ADR-0018).
///
/// # Errors
/// Returns an error — with the previous version still current and still running — when this
/// executable is not in an ADR-0019 layout, when the artifact cannot be staged, or when the staged
/// binary does not answer for itself.
pub fn install(
    state_dir: &Path,
    artifact: &Path,
    version: &str,
    package_hash: &[u8],
    archive_key: Option<&str>,
) -> Result<SelfInstall, String> {
    // The version is Server-controlled and becomes an on-disk directory name below (ADR-0019).
    // Refuse anything that is not a well-formed version *before* it names a path: a value carrying
    // `..` or a separator would otherwise stage the (hash-verified) binary outside `versions/` and
    // repoint `current` at it — an escape the content hash and signature never cover, because they
    // sign the bytes, not the destination. The probe's own version check (ADR-0012) is too late; it
    // runs only after the artifact is already staged on disk.
    if fleet_core::version::parse(version).is_none() {
        return Err(format!(
            "the offered version {version:?} is not a valid version; refusing to self-update"
        ));
    }

    // Refuse a downgrade. An offer for an older release than the one running — even a genuinely
    // signed one — is how a compromised Server pushes a build with a known vulnerability back onto a
    // fleet; the Ed25519 signature covers the Agent type, the version and the hash (ADR-0026), which
    // ties an artifact to its own version but says nothing of how that version orders against the
    // running one, so an old release stays validly signed forever. A rebuild of the same release
    // (Equal) and any newer one still install. Rollback to the *previous* version is a separate
    // mechanism — the crash-loop pointer move ([`on_start`]) — not a Server-offered older version.
    let running = fleet_core::version::current();
    if fleet_core::version::precedence(version, running) == Some(std::cmp::Ordering::Less) {
        return Err(format!(
            "the offered version {version:?} is older than the running {running:?}; \
             refusing to downgrade"
        ));
    }

    let exe = layout::running_exe()?;
    // Outside the versioned layout there is no pointer to switch and no previous version to go
    // back to — a `cargo run` build, or a binary an operator dropped somewhere by hand.
    let (layout, running_dir) = Layout::enclosing(&exe).ok_or_else(|| {
        format!(
            "this Client does not run from a versioned install layout ({}); \
             self-update needs `supervisor service install`",
            exe.display()
        )
    })?;

    let versions = layout.versions_dir();
    let new_dir = layout.version_dir(&layout::version_dir_name(version));
    // Defence in depth: whatever the name derived to, it must be a direct child of `versions/`. The
    // version check above already blocks the known escapes; this keeps the path guarantee from
    // resting on that parsing staying correct in the future.
    if new_dir.parent() != Some(versions.as_path()) {
        return Err(format!(
            "the offered version {version:?} does not map to a directory under {}",
            versions.display()
        ));
    }
    if new_dir == running_dir {
        // Not a failure: this *is* the version the Server wants installed. It reaches here every
        // time a freshly updated Client is offered the package it just installed, which is the
        // ordinary course of events and not something to report as broken.
        info!(version = %version, "the offered version is the one already running");
        return Ok(SelfInstall::AlreadyRunning);
    }
    // The update's own span (ADR-0016). It sits under the install that downloaded the artifact
    // when there is one, which there always is today — this is only ever reached from a package
    // offer — and it is the span the *next* process continues from.
    //
    // No status is recorded on it: this process does not learn the outcome. Staging and restarting
    // is all it does, and claiming success here would call an update good before the version it
    // installed has started once. The `info!` below is the event that says where it got to.
    let update = tracing::info_span!("self.update", version = %version).entered();
    {
        let _stage = tracing::info_span!("stage", dir = %new_dir.display()).entered();
        stage(&new_dir, artifact, version, archive_key)?;
    }

    // Prove it before anything points at it.
    {
        let _probe = tracing::info_span!("probe").entered();
        probe(&new_dir.join(BINARY_FILENAME), version)?;
    }

    let marker = UpdateMarker {
        previous_dir: running_dir,
        new_dir: new_dir.clone(),
        version: version.to_string(),
        package_hash_hex: hex::encode(package_hash),
        attempts: 0,
        trace: crate::telemetry::current_trace()
            .map(|(trace_id, span_id)| TraceRef { trace_id, span_id }),
    };
    // The marker is written *before* the switch: a crash between the two leaves a marker naming a
    // switch that did not happen, which the next start resolves by pointing at what it names.
    store_marker(state_dir, &marker)?;
    layout.set_current(&new_dir)?;
    info!(version = %version, dir = %new_dir.display(), "staged a new Client version; restarting into it");
    drop(update);
    Ok(SelfInstall::Staged)
}

/// Unpacks the artifact into `dir` as this platform's binary and writes the ADR-0019 manifest.
fn stage(
    dir: &Path,
    artifact: &Path,
    version: &str,
    archive_key: Option<&str>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let binary = dir.join(BINARY_FILENAME);
    // The artifact is the program or an archive holding it (ADR-0026) — the same shapes a Managed
    // Process's package comes in, which is why the unpacking is shared with the Supervisor's swap.
    install::write_program(artifact, &binary, BINARY_FILENAME, archive_key)?;

    let bytes =
        std::fs::read(&binary).map_err(|e| format!("cannot read {}: {e}", binary.display()))?;
    layout::write_manifest(
        dir,
        "a self-update",
        version,
        &hex::encode(Sha256::digest(&bytes)),
    )
    .map_err(|e| format!("cannot write the manifest: {e}"))
}

/// Runs `<binary> self-check`, retrying briefly past `ETXTBSY`
/// ([`install::is_text_file_busy`] states why).
///
/// The loop stays here rather than being shared with the Supervisor's: that one drives a
/// `tokio::process` spawn and this one a blocking `std::process` run, and the only thing they would
/// have in common after being generalised over both is the predicate and the two constants they
/// already share.
fn run_self_check(binary: &Path) -> std::io::Result<std::process::Output> {
    let mut attempt = 0;
    loop {
        match std::process::Command::new(binary)
            .arg("self-check")
            .output()
        {
            Err(e) if install::is_text_file_busy(&e) && attempt < install::BUSY_RETRIES => {
                attempt += 1;
                warn!(
                    binary = %binary.display(), attempt,
                    "the staged binary is momentarily busy; retrying the self-check"
                );
                std::thread::sleep(install::BUSY_DELAY);
            }
            other => return other,
        }
    }
}

/// Runs the staged binary and requires it to answer for itself at the expected version.
fn probe(binary: &Path, expected_version: &str) -> Result<(), String> {
    let output = run_self_check(binary)
        .map_err(|e| format!("the staged binary {} does not run: {e}", binary.display()))?;
    if !output.status.success() {
        return Err(format!(
            "the staged binary answered the self-check with {}",
            output.status
        ));
    }
    let answer = String::from_utf8_lossy(&output.stdout);
    let Some(reported) = answer
        .lines()
        .find_map(|line| line.trim().strip_prefix(SELF_CHECK_TOKEN))
    else {
        return Err(
            "the staged binary is not an OpAMP Fleet Client: it did not answer the self-check"
                .to_string(),
        );
    };
    let reported = reported.trim();
    // The commit the binary was built from is provenance, not identity (ADR-0012): it is the one
    // part of the string an operator neither knows nor can type when uploading a release, and
    // SemVer itself says metadata is ignored when versions are compared. The pre-release is *not*
    // dropped — a `-dev` build is not the release it heads for, and this is the last gate that can
    // say so before a fleet installs one. A value that is not a version at all matches nothing.
    if !fleet_core::version::same_release(reported, expected_version) {
        return Err(format!(
            "the staged binary reports version {reported:?}, but the package offered \
             {expected_version:?}"
        ));
    }
    Ok(())
}

/// What this process should do about an update in flight — called once, before the daemon body.
///
/// # Errors
/// Returns an error only when a rollback is needed and the pointer cannot be moved, which leaves
/// the host running a version its own marker says is failing.
pub fn on_start(state_dir: &Path) -> Result<Startup, String> {
    on_start_as(
        state_dir,
        &layout::running_exe()?,
        fleet_core::version::current(),
    )
}

/// [`on_start`] for the process running `exe` at `running_version`.
fn on_start_as(state_dir: &Path, exe: &Path, running_version: &str) -> Result<Startup, String> {
    let Some(mut marker) = load_marker(state_dir) else {
        // Nothing in flight — but an outcome may still be owed from the run that finished one.
        return Ok(
            load_outcome(state_dir).map_or(Startup::Ordinary, |o| Startup::Outcome(o.into()))
        );
    };
    marker.attempts += 1;

    let running_dir = Layout::enclosing(exe).map(|(_, dir)| dir);
    let is_new_version = took_over(running_version, running_dir.as_deref(), &marker);

    if !is_new_version {
        // We are the *old* version and the marker is still here: the switch never took effect, or
        // a rollback already pointed back at us. Either way the update did not happen.
        let reason = format!(
            "the new version {} did not take over; running {} from {} instead",
            marker.version,
            running_version,
            running_dir
                .as_deref()
                .unwrap_or(Path::new("an unknown directory"))
                .display()
        );
        warn!(reason, "a self-update did not take effect");
        // Counted as the rollback phase: nothing was rolled back *here*, but the operation ends the
        // way a rollback ends — the previous version running and the update reported failed — and
        // the trace is read for the outcome, not for which code path produced it.
        let span = continued(
            &marker,
            tracing::info_span!(
                "roll_back",
                version = %marker.version,
                otel.status_code = tracing::field::Empty,
                otel.status_description = tracing::field::Empty,
            ),
        );
        crate::telemetry::failed(&span, &reason);
        drop(span);
        return Ok(Startup::Outcome(
            finish(state_dir, &marker, Some(reason)).into(),
        ));
    }

    if marker.attempts > MAX_ATTEMPTS {
        let reason = format!(
            "the new version {} did not stay up after {MAX_ATTEMPTS} attempts",
            marker.version
        );
        warn!(reason, "rolling the Client back to its previous version");
        let span = continued(
            &marker,
            tracing::info_span!(
                "roll_back",
                version = %marker.version,
                attempts = marker.attempts,
                otel.status_code = tracing::field::Empty,
                otel.status_description = tracing::field::Empty,
            ),
        );
        let _rolling = span.enter();
        let (layout, _) = Layout::enclosing(exe).expect("checked above");
        layout.set_current(&marker.previous_dir)?;
        crate::telemetry::failed(&span, &reason);
        finish(state_dir, &marker, Some(reason));
        return Ok(Startup::RolledBack(marker.into()));
    }

    store_marker(state_dir, &marker)?;
    info!(
        version = %marker.version,
        attempt = marker.attempts,
        "running a freshly installed Client version on probation"
    );
    Ok(Startup::OnProbation(marker.into()))
}

/// Whether the process that came up is the update the marker describes — asked of the directory it
/// runs from **and** of the version it reports for itself.
///
/// The directory alone answers a slightly different question: which version was *pointed at*. On a
/// platform where the running path is the `current` pointer rather than the version behind it,
/// canonicalising it says where the pointer now leads, not which binary the service manager
/// actually started. A commit that trusted that would tell the Server a version this host does not
/// run — and the fleet then holds the package back over a claim the program itself denies, which is
/// the state ADR-0025 is about. What a binary says about itself is the one thing no stale pointer
/// can fake, so both must agree; the build metadata does not take part (ADR-0012).
fn took_over(running_version: &str, running_dir: Option<&Path>, marker: &UpdateMarker) -> bool {
    fleet_core::version::same_release(running_version, &marker.version)
        && running_dir.is_some_and(|dir| {
            std::fs::canonicalize(dir).ok() == std::fs::canonicalize(&marker.new_dir).ok()
        })
}

/// Declares the version this process runs good: the marker goes, and the Server is owed
/// `Installed`. Called once the Client is up and has reached the Server.
pub fn commit(state_dir: &Path, marker: &UpdateMarker) {
    // The last phase of an install that began in a process that no longer exists (ADR-0016).
    let span = continued(
        marker,
        tracing::info_span!(
            "commit",
            version = %marker.version,
            otel.status_code = tracing::field::Empty,
            otel.status_description = tracing::field::Empty,
        ),
    );
    let _committing = span.enter();
    crate::telemetry::succeeded(&span);
    finish(state_dir, marker, None);
    info!(version = %marker.version, "the new Client version committed itself");
}

/// Ends the update the marker describes: the marker goes, and the outcome the Server is owed —
/// failed when `error` says why — is recorded and handed back. Handed back rather than read back
/// from disk, because recording it can fail, and the outcome is still this run's to report.
fn finish(state_dir: &Path, marker: &UpdateMarker, error: Option<String>) -> UpdateOutcome {
    let _ = std::fs::remove_file(marker_path(state_dir));
    let outcome = UpdateOutcome {
        version: marker.version.clone(),
        package_hash_hex: marker.package_hash_hex.clone(),
        error,
    };
    store_outcome(state_dir, &outcome);
    outcome
}

const OUTCOME_FILE: &str = "update-outcome.json";

fn store_outcome(state_dir: &Path, outcome: &UpdateOutcome) {
    let json = serde_json::to_vec_pretty(outcome).expect("an UpdateOutcome serializes");
    if let Err(e) = std::fs::write(state_dir.join(OUTCOME_FILE), json) {
        warn!(error = %e, "cannot record the self-update outcome; the Server will not hear it");
    }
}

fn load_outcome(state_dir: &Path) -> Option<UpdateOutcome> {
    let text = std::fs::read_to_string(state_dir.join(OUTCOME_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Drops the recorded outcome once it has been reported to the Server.
pub fn clear_outcome(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(OUTCOME_FILE));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(dir: &Path, attempts: u32) -> UpdateMarker {
        UpdateMarker {
            trace: None,
            previous_dir: dir.join("versions/opamp-client-1.0.0-aaaaaaa"),
            new_dir: dir.join("versions/opamp-client-2.0.0-bbbbbbb"),
            version: "2.0.0".to_string(),
            package_hash_hex: "abcd".to_string(),
            attempts,
        }
    }

    #[test]
    fn a_marker_round_trips_and_an_unreadable_one_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let written = marker(dir.path(), 1);
        store_marker(dir.path(), &written).expect("store");
        assert_eq!(load_marker(dir.path()), Some(written));

        // A marker we cannot parse would keep a Client on probation forever.
        std::fs::write(marker_path(dir.path()), "not json").expect("corrupt");
        assert_eq!(load_marker(dir.path()), None);
        assert!(
            !marker_path(dir.path()).exists(),
            "the unreadable marker is removed, not left to be re-read"
        );
    }

    /// The trace the install belongs to rides in the marker (ADR-0016 clause 20) — and a marker
    /// written before that field existed still parses.
    ///
    /// The second half is the load-bearing one: an update in flight across a version bump is
    /// exactly when this file is read by a *different* build than the one that wrote it, and a
    /// marker that failed to parse there would put a Client on probation forever over a field that
    /// only decorates a trace.
    /// Verifies: ADR-0016
    #[test]
    fn a_marker_carries_its_trace_and_one_written_without_it_still_parses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut written = marker(dir.path(), 1);
        written.trace = Some(TraceRef {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
        });
        store_marker(dir.path(), &written).expect("store");
        assert_eq!(load_marker(dir.path()), Some(written));

        // A marker an older Client wrote: every field but this one.
        let older = serde_json::json!({
            "previous_dir": dir.path().join("previous"),
            "new_dir": dir.path().join("new"),
            "version": "9.9.9",
            "package_hash_hex": "abcd",
            "attempts": 1,
        });
        std::fs::write(marker_path(dir.path()), older.to_string()).expect("write");
        let loaded = load_marker(dir.path()).expect("a marker without a trace still loads");
        assert_eq!(loaded.trace, None);
        assert_eq!(loaded.version, "9.9.9");
    }

    /// A crafted Server offer whose `version` carries `..` or a path separator must be refused
    /// before it is ever turned into a directory name — otherwise the staged binary lands outside
    /// `versions/` and `current` is pointed at it. The refusal happens ahead of the layout check,
    /// so it holds even where this test binary does not run from an install layout.
    /// Verifies: ADR-0018
    #[test]
    fn install_refuses_a_version_that_would_escape_the_layout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("artifact");
        std::fs::write(&artifact, b"payload").expect("write the artifact");

        for bad in [
            "1.0.0+../../../evil",
            "1.0.0-../x",
            "../../etc/cron.d/x",
            r"1.0.0+a\b",
            "latest",
        ] {
            let err = install(dir.path(), &artifact, bad, b"\x00", None)
                .expect_err("a path-escaping version must be refused");
            assert!(
                err.contains("not a valid version"),
                "{bad:?} was not refused as a version: {err}"
            );
        }
    }

    /// A Server offering an older release than the one running is refused before it can be staged,
    /// even though it may be validly signed — the refusal happens ahead of the layout check, so it
    /// holds regardless of where this test binary runs from. `0.0.1` is below any release this
    /// project builds.
    /// Verifies: ADR-0018, ADR-0043
    #[test]
    fn install_refuses_a_downgrade() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("artifact");
        std::fs::write(&artifact, b"payload").expect("write the artifact");

        let err = install(dir.path(), &artifact, "0.0.1", b"\x00", None)
            .expect_err("an older release must be refused");
        assert!(
            err.contains("refusing to downgrade"),
            "an older version was not refused as a downgrade: {err}"
        );
    }

    #[test]
    fn an_ordinary_start_finds_nothing_to_do() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(on_start(dir.path()).expect("start"), Startup::Ordinary);
    }

    /// Verifies: ADR-0018
    #[test]
    fn committing_replaces_the_marker_with_an_installed_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = marker(dir.path(), 1);
        store_marker(dir.path(), &marker).expect("store");

        commit(dir.path(), &marker);
        assert!(!marker_path(dir.path()).exists(), "no longer on probation");
        let outcome = load_outcome(dir.path()).expect("an outcome is owed");
        assert_eq!(outcome.version, "2.0.0");
        assert_eq!(outcome.error, None, "committing reports Installed");

        // The next start reports it, then it is gone.
        assert!(matches!(
            on_start(dir.path()).expect("start"),
            Startup::Outcome(_)
        ));
        clear_outcome(dir.path());
        assert_eq!(on_start(dir.path()).expect("start"), Startup::Ordinary);
    }

    /// ADR-0025: the directory a process runs from says which version was *pointed at*; only the
    /// binary says which one came up. A commit that trusted the pointer would report a version this
    /// host does not run, and the fleet would then hold the package back over a claim the program
    /// denies — the state ADR-0025 is about, created by the very mechanism meant to end it.
    /// Verifies: ADR-0018
    #[test]
    fn taking_over_needs_the_binary_to_be_the_version_the_marker_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = marker(dir.path(), 1);
        std::fs::create_dir_all(&marker.new_dir).expect("the new version directory");

        assert!(
            took_over("2.0.0", Some(&marker.new_dir), &marker),
            "the version the marker names, running from the directory it named"
        );
        assert!(
            took_over("2.0.0+a1b2c3d", Some(&marker.new_dir), &marker),
            "the build metadata takes no part in it (ADR-0012)"
        );
        assert!(
            !took_over("1.0.0", Some(&marker.new_dir), &marker),
            "the pointer leads to 2.0.0, but 1.0.0 is what came up: the update did not take effect"
        );
        assert!(
            !took_over("2.0.0", Some(&marker.previous_dir), &marker),
            "and the right version from the wrong directory is no take-over either"
        );
        assert!(
            !took_over("2.0.0", None, &marker),
            "a Client outside the layout has no version directory to have taken over"
        );
    }

    /// The old version finding the marker means the switch never took hold — reported as a
    /// failure rather than silently forgotten, since the Server was told `Installing`.
    /// Verifies: ADR-0018
    #[test]
    fn the_old_version_finding_a_marker_reports_the_update_as_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `new_dir` is a path this test binary certainly does not run from.
        store_marker(dir.path(), &marker(dir.path(), 0)).expect("store");

        let startup = on_start(dir.path()).expect("start");
        let Startup::Outcome(outcome) = startup else {
            panic!("expected an owed outcome, got {startup:?}");
        };
        assert_eq!(outcome.version, "2.0.0");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("did not take over")),
            "got {:?}",
            outcome.error
        );
        assert!(!marker_path(dir.path()).exists());
    }

    /// A new version that does not stay up is rolled back: after its last attempt `current` points
    /// at the previous version again, and the Server is owed `InstallFailed` with the reason. The
    /// attempts before it run on probation.
    /// Verifies: ADR-0018, G-10, G-11
    #[test]
    fn a_new_version_that_does_not_stay_up_is_rolled_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("install");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).expect("state");
        let marker = marker(&root, 0);
        for version_dir in [&marker.previous_dir, &marker.new_dir] {
            std::fs::create_dir_all(version_dir).expect("version dir");
            std::fs::write(version_dir.join(BINARY_FILENAME), b"client").expect("binary");
        }
        let layout = Layout::new(&root);
        layout
            .set_current(&marker.new_dir)
            .expect("point at the new version");
        store_marker(&state, &marker).expect("store");
        let exe = marker.new_dir.join(BINARY_FILENAME);

        for attempt in 1..=MAX_ATTEMPTS {
            let startup = on_start_as(&state, &exe, "2.0.0").expect("start");
            assert!(
                matches!(&startup, Startup::OnProbation(m) if m.attempts == attempt),
                "attempt {attempt}: {startup:?}"
            );
        }
        let startup = on_start_as(&state, &exe, "2.0.0").expect("start");
        assert!(matches!(startup, Startup::RolledBack(_)), "{startup:?}");
        assert_eq!(
            std::fs::canonicalize(layout.current()).expect("current resolves"),
            std::fs::canonicalize(&marker.previous_dir).expect("previous resolves"),
            "current points back at the previous version"
        );
        assert!(!marker_path(&state).exists());
        let owed = load_outcome(&state).expect("an outcome is owed");
        assert_eq!(owed.version, "2.0.0");
        assert!(
            owed.error
                .as_deref()
                .is_some_and(|e| e.contains("did not stay up")),
            "{owed:?}"
        );

        // The previous version comes up next and reports the failure.
        let previous = marker.previous_dir.join(BINARY_FILENAME);
        let startup = on_start_as(&state, &previous, "1.0.0").expect("start");
        assert!(
            matches!(&startup, Startup::Outcome(o) if o.error.is_some()),
            "{startup:?}"
        );
    }

    /// A binary that cannot run at all is the failure class no post-restart mechanism can catch,
    /// because it never gets far enough to count an attempt. Refusing it is the whole reason the
    /// probe happens before the pointer moves.
    /// Verifies: ADR-0018
    #[test]
    fn the_probe_refuses_a_binary_that_cannot_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("not-there");
        assert!(probe(&missing, "2.0.0").is_err());
    }

    /// A program that runs happily and answers something else: offered under the configured
    /// package name, and still not this Client. Unix-only because the impostor is a shell script;
    /// what it proves is platform-independent.
    /// Verifies: ADR-0018
    #[cfg(unix)]
    #[test]
    fn the_probe_refuses_a_binary_that_is_not_this_client() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("impostor");
        std::fs::write(&binary, "#!/bin/sh\necho hello\n").expect("write");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let err = probe(&binary, "2.0.0").expect_err("an impostor must be refused");
        assert!(err.contains("not an OpAMP Fleet Client"), "got {err}");
    }

    /// Verifies: ADR-0018
    #[cfg(unix)]
    #[test]
    fn the_probe_refuses_a_client_of_the_wrong_version() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("client");
        std::fs::write(
            &binary,
            format!("#!/bin/sh\necho '{SELF_CHECK_TOKEN}1.0.0'\n"),
        )
        .expect("write");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let err = probe(&binary, "2.0.0").expect_err("a version mismatch must be refused");
        assert!(err.contains("reports version"), "got {err}");
        // The same binary at the version it claims is accepted.
        probe(&binary, "1.0.0").expect("the versions agree");
    }

    /// ADR-0012, and the failure that prompted it: a package is uploaded under the release number,
    /// while the binary in it reports the commit it was built from. Those are the same release.
    /// Verifies: ADR-0012, ADR-0018
    #[cfg(unix)]
    #[test]
    fn the_probe_ignores_the_commit_a_build_came_from() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = self_check_stub(dir.path(), "0.1.1+799e36a");

        probe(&binary, "0.1.1").expect("the release number is what an operator uploads");
        probe(&binary, "0.1.1+799e36a").expect("and the full string still works");
        // A rebuild of the same release passes too; which bytes arrived is the content hash's
        // question (ADR-0026), never this one.
        probe(&binary, "0.1.1+deadbee").expect("same release, other build");
    }

    /// What is deliberately *not* dropped: a development build is not the release it heads for
    /// (ADR-0012), and this is the last gate that can refuse one before a fleet installs it.
    /// Verifies: ADR-0018
    #[cfg(unix)]
    #[test]
    fn the_probe_refuses_a_development_build_offered_as_a_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = self_check_stub(dir.path(), "0.1.1-dev+799e36a");

        let err = probe(&binary, "0.1.1").expect_err("a -dev build is not the release");
        assert!(err.contains("reports version"), "got {err}");
        probe(&binary, "0.1.1-dev").expect("offered as what it is, it installs");
    }

    /// A Server may offer a value that is not a version at all — including the `0.1.1 799e36a` a
    /// query string makes of an unencoded `+` — and the probe refuses it (ADR-0043 clause 13).
    /// Verifies: ADR-0018, ADR-0043
    #[cfg(unix)]
    #[test]
    fn the_probe_refuses_an_offer_that_is_not_a_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = self_check_stub(dir.path(), "0.1.1+799e36a");

        for offered in ["0.1.1 799e36a", "latest", "v0.1.1", ""] {
            assert!(
                probe(&binary, offered).is_err(),
                "{offered:?} must not install"
            );
        }
    }

    /// A stand-in for a staged Client: it answers the self-check with the version it is told to.
    #[cfg(unix)]
    fn self_check_stub(dir: &Path, reports: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("staged-client");
        std::fs::write(
            &binary,
            format!("#!/bin/sh\necho '{SELF_CHECK_TOKEN}{reports}'\n"),
        )
        .expect("write");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        binary
    }
}
