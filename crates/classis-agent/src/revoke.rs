//! `revoke` (ADR-0064 clause 7): a host leaves the fleet, locally, and the Server is never asked.
//!
//! Without its `state.json` a host is gone, and nothing else stored for it may outlive it, so
//! `revoke` deletes the whole content of the state directory: the file, the Agents' identities
//! (a new `enrol` brings new `instance_uid`s), the connection settings, the high-water marks, the
//! logs, the Supervisors' directories. It refuses while the Client's service is running, asks for a
//! confirmation unless it is told not to, and keeps the service from starting at boot again before
//! it deletes anything.
//!
//! `--keep-cache` spares what a re-enrolled host would only download again: `config/` and
//! `packages/`. It is an exception taken out of the default deletion — every entry of the
//! directory is deleted unless the exception names it — so whatever the Client keeps in the state
//! directory in future is deleted under the flag too, without this module being told of it.

use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::path::Path;

use crate::config::PACKAGES_DIR;
use crate::enrolment::{ServiceHost, STATE_FILE};
use crate::nofollow::HeldDir;
use crate::service::ServiceState;
use crate::storage::CONFIG_DIR;

/// What `--keep-cache` spares, among everything the state directory holds.
const CACHE: [&str; 2] = [CONFIG_DIR, PACKAGES_DIR];

/// What `revoke` did.
#[derive(Debug, PartialEq, Eq)]
pub struct Revoked {
    /// Whether a registered service was kept from starting at boot.
    pub service_disabled: bool,
    /// What `--keep-cache` spared.
    pub kept: Vec<OsString>,
}

/// Revokes this host: everything in `state_dir`, but for what `keep_cache` spares.
///
/// `confirm` is asked once, with what is about to be deleted, unless `force` — and not at all when
/// the service is running: that is refused first. Nothing is changed before the confirmation is
/// given and the service, where one is registered, has been kept from starting at boot.
///
/// # Errors
/// Returns why the host was not revoked: nothing to revoke, the service is running, no
/// confirmation, the service could not be disabled, or the first entry that could not be deleted
/// (`state.json` goes first, so a host that fails halfway is already gone).
pub fn revoke(
    state_dir: &Path,
    force: bool,
    keep_cache: bool,
    host: &dyn ServiceHost,
    confirm: &mut dyn FnMut(&str) -> Result<bool, String>,
) -> Result<Revoked, String> {
    let dir = match HeldDir::open(state_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "nothing to revoke: {} does not exist",
                state_dir.display()
            ))
        }
        Err(e) => return Err(format!("cannot open {}: {e}", state_dir.display())),
    };
    let installed = host.registered(state_dir)?;
    if let Some(installed) = &installed {
        if installed.control.state()? == ServiceState::Running {
            return Err(format!(
                "the service is running: stop it first with `supervisor service stop`, so that \
                 nothing writes to {} while it is deleted",
                state_dir.display()
            ));
        }
    }
    let spared: &[&str] = if keep_cache { &CACHE } else { &[] };
    if !force {
        let spared_note = if keep_cache {
            format!(", but {} and {}", CACHE[0], CACHE[1])
        } else {
            String::new()
        };
        let question = format!(
            "Revoke this host? Everything in {} is deleted{spared_note}: its enrolment, its \
             Agents' identities and its logs. The Server is not told, and a host enrolled again \
             is a new one.",
            state_dir.display()
        );
        if !confirm(&question)? {
            return Err("not revoked: it was not confirmed, and nothing was changed".to_string());
        }
    }
    let service_disabled = match &installed {
        Some(installed) => {
            installed.control.disable()?;
            true
        }
        None => false,
    };

    let mut names = dir
        .names()
        .map_err(|e| format!("cannot read {}: {e}", state_dir.display()))?;
    // The file that makes the host what it is goes first.
    names.sort_by_key(|name| name != STATE_FILE);
    let mut kept = Vec::new();
    for name in names {
        if spared.iter().any(|spared| name == *spared) {
            kept.push(name);
            continue;
        }
        dir.remove_all(&name)
            .map_err(|e| format!("cannot delete {}: {e}", state_dir.join(&name).display()))?;
    }
    kept.sort();
    Ok(Revoked {
        service_disabled,
        kept,
    })
}

/// The confirmation `revoke` asks on a terminal.
///
/// # Errors
/// Returns an error when stdin is not a terminal, rather than waiting for an answer that cannot
/// come: `--force` is how an automated run says it means it.
pub fn confirm_on_terminal(question: &str) -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err(
            "`supervisor revoke` asks for a confirmation, and there is no terminal on stdin to \
             ask on. Nothing was changed; run it from a terminal, or pass --force"
                .to_string(),
        );
    }
    dialoguer::Confirm::new()
        .with_prompt(question)
        .default(false)
        .interact()
        .map_err(|e| format!("cannot ask for the confirmation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrolment::Installed;
    use crate::service::ServiceControl;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A service that notes what it was asked, and says it is in the state it was given.
    struct Fake {
        state: ServiceState,
        asked: Rc<RefCell<Vec<&'static str>>>,
    }

    impl ServiceControl for Fake {
        fn start(&self) -> Result<(), String> {
            self.asked.borrow_mut().push("start");
            Ok(())
        }
        fn stop(&self) -> Result<(), String> {
            self.asked.borrow_mut().push("stop");
            Ok(())
        }
        fn enable(&self) -> Result<(), String> {
            self.asked.borrow_mut().push("enable");
            Ok(())
        }
        fn disable(&self) -> Result<(), String> {
            self.asked.borrow_mut().push("disable");
            Ok(())
        }
        fn state(&self) -> Result<ServiceState, String> {
            Ok(self.state)
        }
    }

    struct Host(Option<(ServiceState, Rc<RefCell<Vec<&'static str>>>)>);

    impl ServiceHost for Host {
        fn registered(&self, _: &Path) -> Result<Option<Installed>, String> {
            Ok(self.0.as_ref().map(|(state, asked)| Installed {
                control: Box::new(Fake {
                    state: *state,
                    asked: asked.clone(),
                }),
                run_as: None,
            }))
        }
    }

    fn state_dir_with_everything() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (path, contents) in [
            ("state.json", "{}"),
            ("instance-uid", "x"),
            ("connection-settings.pb", "x"),
            ("config/entry.yaml", "x"),
            ("packages/self.staged", "x"),
            ("logs/client.log", "x"),
            ("supervisors/a/program/bin", "x"),
            ("added-in-a-later-version.json", "x"),
        ] {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, contents).expect("write");
        }
        dir
    }

    fn left(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn yes(_: &str) -> Result<bool, String> {
        Ok(true)
    }

    /// Everything the state directory holds is deleted — also what no list of files names.
    /// Verifies: ADR-0064
    #[test]
    fn everything_in_the_state_directory_is_deleted() {
        let dir = state_dir_with_everything();
        let revoked = revoke(dir.path(), false, false, &Host(None), &mut yes).expect("revoked");
        assert!(left(dir.path()).is_empty(), "{:?}", left(dir.path()));
        assert_eq!(
            revoked,
            Revoked {
                service_disabled: false,
                kept: Vec::new()
            }
        );
    }

    /// `--keep-cache` spares `config/` and `packages/` and deletes the rest, whatever the rest is.
    /// Verifies: ADR-0064
    #[test]
    fn keep_cache_spares_config_and_packages_alone() {
        let dir = state_dir_with_everything();
        let revoked = revoke(dir.path(), true, true, &Host(None), &mut |_| {
            panic!("--force asks nothing")
        })
        .expect("revoked");
        assert_eq!(left(dir.path()), ["config", "packages"]);
        assert!(dir.path().join("config/entry.yaml").exists());
        assert!(dir.path().join("packages/self.staged").exists());
        assert_eq!(
            revoked.kept,
            [OsString::from("config"), OsString::from("packages")]
        );
    }

    /// A service that runs is not revoked from under, and nothing is deleted or disabled.
    /// Verifies: ADR-0064
    #[test]
    fn a_running_service_refuses_the_revocation() {
        let dir = state_dir_with_everything();
        let asked = Rc::default();
        let host = Host(Some((ServiceState::Running, Rc::clone(&asked))));
        let error = revoke(dir.path(), true, false, &host, &mut yes).expect_err("running");
        assert!(error.contains("service stop"), "{error}");
        assert!(dir.path().join("state.json").exists());
        assert!(asked.borrow().is_empty(), "{:?}", asked.borrow());
    }

    /// A stopped service is kept from starting at boot before anything is deleted, and not started.
    /// Verifies: ADR-0064
    #[test]
    fn a_stopped_service_is_disabled() {
        let dir = state_dir_with_everything();
        let asked = Rc::default();
        let host = Host(Some((ServiceState::Stopped, Rc::clone(&asked))));
        let revoked = revoke(dir.path(), true, false, &host, &mut yes).expect("revoked");
        assert!(revoked.service_disabled);
        assert_eq!(*asked.borrow(), ["disable"]);
        assert!(left(dir.path()).is_empty());
    }

    /// Without `--force` the confirmation is asked, with what is deleted; a refusal changes nothing.
    /// Verifies: ADR-0064
    #[test]
    fn a_declined_confirmation_changes_nothing() {
        let dir = state_dir_with_everything();
        let asked = Rc::default();
        let host = Host(Some((ServiceState::Stopped, Rc::clone(&asked))));
        let mut questions = Vec::new();
        let error = revoke(dir.path(), false, false, &host, &mut |question| {
            questions.push(question.to_string());
            Ok(false)
        })
        .expect_err("declined");
        assert!(error.contains("nothing was changed"), "{error}");
        assert_eq!(questions.len(), 1);
        assert!(
            questions[0].contains(&dir.path().display().to_string()),
            "{questions:?}"
        );
        assert!(asked.borrow().is_empty());
        assert!(dir.path().join("state.json").exists());
    }

    /// A link in the state directory is removed as a link: what it points at is not touched.
    /// Verifies: ADR-0064
    #[cfg(unix)]
    #[test]
    fn a_link_is_removed_and_never_followed() {
        let dir = state_dir_with_everything();
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("precious"), "x").expect("write");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("logs/link")).expect("link");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("a-link")).expect("link");
        revoke(dir.path(), true, false, &Host(None), &mut yes).expect("revoked");
        assert!(left(dir.path()).is_empty());
        assert!(outside.path().join("precious").exists());
    }

    /// A state directory that does not exist is not revoked.
    #[test]
    fn a_missing_state_directory_is_nothing_to_revoke() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = revoke(&dir.path().join("none"), true, false, &Host(None), &mut yes)
            .expect_err("nothing");
        assert!(error.contains("nothing to revoke"), "{error}");
    }
}
