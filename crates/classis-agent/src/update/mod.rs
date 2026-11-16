//! The Client updating itself (ADR-0018): the decisions, apart from the host that carries them out.
//!
//! The Client's own Agent accepts a package like any Supervisor's, but nothing outlives the
//! process that installs it. So the install is split across a restart. Before it, the
//! [`SelfUpdater`] stages, proves and points at the new version. After it, the next process either
//! commits that version or rolls back. This module holds the port and the state the Engine keeps
//! about it: whether self-update is armed, whether the Server has answered this process, and
//! whether the run has to end. The adapter on the ADR-0019 version directories is
//! [`installer`].

pub mod installer;

use std::path::Path;

/// What `client self-check` prints. A package can be offered under the configured name and still
/// be some other program; this is what only this program answers.
pub const SELF_CHECK_TOKEN: &str = "supervisor self-check ok version=";

/// The exit code that asks the service manager for a restart (ADR-0018). Non-zero on purpose:
/// "restart on failure" is what all three managers offer, and there is no "restart on success".
pub const EXIT_RESTART_FOR_UPDATE: i32 = 10;

/// What installs a new version of this Client and closes out one that is on probation.
/// [`SelfUpdate`] decides when; the adapter stages, proves and points at the version directory.
pub trait SelfUpdater: Send {
    /// Installs the verified artifact `staged` as `version`. The staged file has served its purpose
    /// whatever the outcome, and is gone afterwards.
    ///
    /// # Errors
    /// Returns an error — with the previous version still current and still running — when the
    /// artifact cannot be installed.
    fn install(&self, staged: &Path, version: &str, hash: &[u8]) -> Result<SelfInstall, String>;

    /// Commits this process as the new version if it is one on probation; nothing otherwise, and
    /// nothing a second time.
    fn commit_probation(&mut self);
}

/// What installing a new version of this Client came to.
#[derive(Debug, PartialEq, Eq)]
pub enum SelfInstall {
    /// Staged, proved and pointed at: the run ends, and the version that starts next reports.
    Staged,
    /// The offered version is the one running. There is nothing to do, and saying so is not a
    /// failure: the Baseline says an Agent that already has the offered version "does not need to
    /// do anything".
    AlreadyRunning,
}

/// The self-update state of one run: the armed [`SelfUpdater`], if `[packages] self_update` consents,
/// and the two facts that decide what it does next.
#[derive(Default)]
pub struct SelfUpdate {
    updater: Option<Box<dyn SelfUpdater>>,
    /// Set once the Server has answered at all. Reaching the Server is what a new version has to
    /// do to prove itself: a binary that starts, connects, and is spoken to is running.
    server_answered: bool,
    /// Set once an install has moved the `current` pointer: the run must end for the service
    /// manager to start the new version.
    restart: bool,
}

impl SelfUpdate {
    /// Arms self-update with what installs a new version and commits this one if it is itself
    /// freshly installed.
    pub fn arm(&mut self, updater: impl SelfUpdater + 'static) {
        self.updater = Some(Box::new(updater));
    }

    /// The Server answered this process. The first answer commits a version on probation;
    /// committing here rather than on a timer makes the bar "it works", not "it survived a clock".
    pub fn server_answered(&mut self) {
        if self.server_answered {
            return;
        }
        self.server_answered = true;
        if let Some(updater) = &mut self.updater {
            updater.commit_probation();
        }
    }

    /// Installs a verified artifact as a new version of this Client. On success the run has to end,
    /// so [`restart_requested`](Self::restart_requested) turns true.
    ///
    /// # Errors
    /// Returns why the install failed, with the previous version still current and still running.
    pub fn install(
        &mut self,
        staged: &Path,
        version: &str,
        hash: &[u8],
    ) -> Result<SelfInstall, String> {
        // Unreachable while the capability is only declared with the consent of `[packages] self_update`, but a refusal
        // that says so beats an install that should not have been offered.
        let updater = self
            .updater
            .as_ref()
            .ok_or_else(|| "self-update is not enabled".to_string())?;
        let installed = updater.install(staged, version, hash)?;
        if installed == SelfInstall::Staged {
            self.restart = true;
        }
        Ok(installed)
    }

    /// Whether an install has moved the `current` pointer and the run must therefore end, so the
    /// service manager restarts into the new version.
    #[must_use]
    pub fn restart_requested(&self) -> bool {
        self.restart
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Fake {
        outcome: fn() -> Result<SelfInstall, String>,
        commits: Arc<AtomicUsize>,
    }

    impl SelfUpdater for Fake {
        fn install(&self, _: &Path, _: &str, _: &[u8]) -> Result<SelfInstall, String> {
            (self.outcome)()
        }
        fn commit_probation(&mut self) {
            self.commits.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn armed(outcome: fn() -> Result<SelfInstall, String>) -> (SelfUpdate, Arc<AtomicUsize>) {
        let commits = Arc::new(AtomicUsize::new(0));
        let mut update = SelfUpdate::default();
        update.arm(Fake {
            outcome,
            commits: commits.clone(),
        });
        (update, commits)
    }

    #[test]
    fn only_the_first_answer_of_the_server_commits_a_probation() {
        let (mut update, commits) = armed(|| Ok(SelfInstall::Staged));
        update.server_answered();
        update.server_answered();
        assert_eq!(commits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn only_a_staged_install_ends_the_run() {
        let path = Path::new("staged");
        let (mut update, _) = armed(|| Ok(SelfInstall::AlreadyRunning));
        assert_eq!(
            update.install(path, "1.0.0", b"h"),
            Ok(SelfInstall::AlreadyRunning)
        );
        assert!(!update.restart_requested());

        let (mut update, _) = armed(|| Err("no".into()));
        assert!(update.install(path, "1.0.0", b"h").is_err());
        assert!(!update.restart_requested());

        let (mut update, _) = armed(|| Ok(SelfInstall::Staged));
        assert_eq!(update.install(path, "1.0.0", b"h"), Ok(SelfInstall::Staged));
        assert!(update.restart_requested());
    }

    #[test]
    fn an_install_without_self_update_is_refused() {
        let mut update = SelfUpdate::default();
        assert_eq!(
            update.install(Path::new("staged"), "1.0.0", b"h"),
            Err("self-update is not enabled".to_string())
        );
        assert!(!update.restart_requested());
    }
}
