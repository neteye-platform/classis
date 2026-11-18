//! `revoke` (ADR-0064 clause 7): a host leaves the fleet, locally, and the Server is never asked.
//!
//! Without its `state.json` a host is gone, and nothing else stored for it may outlive it, so
//! `revoke` deletes the whole content of the state directory: the file, the Agents' identities
//! (a new `enrol` brings new `instance_uid`s), the connection settings, the high-water marks, the
//! logs, the Supervisors' directories. It refuses while the Client's service is running, asks for a
//! confirmation unless it is told not to, and keeps the service from starting at boot again before
//! it deletes anything.
//!
//! What the Client keeps for the host elsewhere goes too, where the configuration puts it outside
//! the state directory ([`Outside`]): the Supervisors' directories under a `supervisor_dir` of its
//! own, each with the identity (`instance-uid`) of the Agent it runs, and the Client's log files in
//! a `[logging] dir` of its own. Left behind, the identities would be reported by Agents the new
//! enrolment gives new `instance_uid`s, and refused.
//!
//! `--keep-cache` spares what a re-enrolled host would only download again: `config/` and
//! `packages/`. It is an exception taken out of the default deletion — every entry of the
//! directory is deleted unless the exception names it — so whatever the Client keeps in the state
//! directory in future is deleted under the flag too, without this module being told of it.

use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use crate::config::{tombstone_of, ClientConfig, PACKAGES_DIR};
use crate::enrolment::{ServiceHost, STATE_FILE};
use crate::nofollow::HeldDir;
use crate::service::ServiceState;
use crate::storage::{CONFIG_DIR, UID_FILE};

/// What `--keep-cache` spares, among everything the state directory holds.
const CACHE: [&str; 2] = [CONFIG_DIR, PACKAGES_DIR];

/// What the configuration puts outside the state directory for this host, and `revoke` deletes
/// beside it (ADR-0064 clause 7). Only places that lie outside the state directory are held: what
/// lies beneath it is deleted with it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outside {
    /// The Supervisors' root, where `supervisor_dir` puts it outside the state directory, and the
    /// names of the configured Supervisors beneath it.
    pub supervisors_root: Option<(PathBuf, Vec<String>)>,
    /// The `[logging] dir`, where it lies outside the state directory.
    pub log_dir: Option<PathBuf>,
}

impl Outside {
    /// What `config` puts outside its state directory.
    #[must_use]
    pub fn of(config: &ClientConfig) -> Self {
        let state_dir = &config.state_dir;
        let root = config.supervisors_root();
        Outside {
            supervisors_root: (!root.starts_with(state_dir)).then(|| {
                let names = config.supervisors.iter().map(|b| b.name.clone()).collect();
                (root, names)
            }),
            log_dir: config
                .logging
                .dir
                .as_deref()
                .map(crate::config_file::absolute)
                .filter(|dir| !dir.starts_with(state_dir)),
        }
    }
}

/// What `revoke` did.
#[derive(Debug, PartialEq, Eq)]
pub struct Revoked {
    /// What was deleted outside the state directory: the directories whose content was.
    pub outside: Vec<PathBuf>,
    /// Whether a registered service was kept from starting at boot.
    pub service_disabled: bool,
    /// What `--keep-cache` spared.
    pub kept: Vec<OsString>,
}

/// Revokes this host: everything in `state_dir`, but for what `keep_cache` spares, and what
/// `outside` names beyond it ([`Outside`]) — `keep_cache` spares nothing there.
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
    outside: &Outside,
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
        let elsewhere: Vec<String> = outside
            .supervisors_root
            .iter()
            .map(|(root, _)| format!("the Supervisors' directories in {}", root.display()))
            .chain(
                outside
                    .log_dir
                    .iter()
                    .map(|dir| format!("the Client's log files in {}", dir.display())),
            )
            .collect();
        let also = if elsewhere.is_empty() {
            String::new()
        } else {
            format!(", and {} too", elsewhere.join(" and "))
        };
        let question = format!(
            "Revoke this host? Everything in {} is deleted{spared_note}{also}: its enrolment, \
             its Agents' identities and its logs. The Server is not told, and a host enrolled \
             again is a new one.",
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
    let outside = wipe_outside(state_dir, outside)?;
    Ok(Revoked {
        outside,
        service_disabled,
        kept,
    })
}

/// Deletes what the Client keeps for the host outside the state directory, and answers the
/// directories it deleted from. Nothing outside the two directories the configuration names is
/// touched, and no link is followed: a link is removed as itself.
///
/// - In the Supervisors' root, a Supervisor's directory goes: one a configured block names, a
///   tombstone of one a purge left, and one that holds an `instance-uid` though no block names it
///   now. Anything else the root holds is not the Client's, and so is an entry that is the state
///   directory or holds it: a `supervisor_dir` above the state directory is no licence to delete
///   the state directory's own `--keep-cache` entries or the installation beside it.
/// - In a `[logging] dir`, the Client's own log files ([`crate::logging::is_log_file`]): an
///   operator may have pointed it at a directory other programs write to.
fn wipe_outside(state_dir: &Path, outside: &Outside) -> Result<Vec<PathBuf>, String> {
    let mut emptied = Vec::new();
    if let Some((root, supervisors)) = &outside.supervisors_root {
        if let Some(dir) = open_existing(root)? {
            for name in dir.names().map_err(|e| read_error(root, &e))? {
                let path = root.join(&name);
                if state_dir.starts_with(&path) || !is_a_supervisors(&name, &path, supervisors) {
                    continue;
                }
                dir.remove_all(&name).map_err(|e| delete_error(&path, &e))?;
            }
            emptied.push(root.clone());
        }
    }
    if let Some(log_dir) = &outside.log_dir {
        if let Some(dir) = open_existing(log_dir)? {
            for name in dir.names().map_err(|e| read_error(log_dir, &e))? {
                if name.to_str().is_some_and(crate::logging::is_log_file) {
                    dir.remove_all(&name)
                        .map_err(|e| delete_error(&log_dir.join(&name), &e))?;
                }
            }
            emptied.push(log_dir.clone());
        }
    }
    Ok(emptied)
}

/// The directory at `path`, opened without following a link at its name; `None` where there is
/// none.
fn open_existing(path: &Path) -> Result<Option<HeldDir>, String> {
    match HeldDir::open(path) {
        Ok(dir) => Ok(Some(dir)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot open {}: {e}", path.display())),
    }
}

fn read_error(dir: &Path, e: &std::io::Error) -> String {
    format!("cannot read {}: {e}", dir.display())
}

fn delete_error(path: &Path, e: &std::io::Error) -> String {
    format!("cannot delete {}: {e}", path.display())
}

/// Whether the entry `name` of the Supervisors' root, at `path`, is a Supervisor's directory.
fn is_a_supervisors(name: &std::ffi::OsStr, path: &Path, supervisors: &[String]) -> bool {
    let named = name
        .to_str()
        .is_some_and(|name| supervisors.iter().any(|s| s == name) || tombstone_of(name).is_some());
    named
        || std::fs::symlink_metadata(path).is_ok_and(|meta| {
            meta.is_dir()
                && std::fs::symlink_metadata(path.join(UID_FILE)).is_ok_and(|uid| uid.is_file())
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
        let revoked = revoke(
            dir.path(),
            &Outside::default(),
            false,
            false,
            &Host(None),
            &mut yes,
        )
        .expect("revoked");
        assert!(left(dir.path()).is_empty(), "{:?}", left(dir.path()));
        assert_eq!(
            revoked,
            Revoked {
                outside: Vec::new(),
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
        let revoked = revoke(
            dir.path(),
            &Outside::default(),
            true,
            true,
            &Host(None),
            &mut |_| panic!("--force asks nothing"),
        )
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
        let error = revoke(
            dir.path(),
            &Outside::default(),
            true,
            false,
            &host,
            &mut yes,
        )
        .expect_err("running");
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
        let revoked = revoke(
            dir.path(),
            &Outside::default(),
            true,
            false,
            &host,
            &mut yes,
        )
        .expect("revoked");
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
        let error = revoke(
            dir.path(),
            &Outside::default(),
            false,
            false,
            &host,
            &mut |question| {
                questions.push(question.to_string());
                Ok(false)
            },
        )
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
        revoke(
            dir.path(),
            &Outside::default(),
            true,
            false,
            &Host(None),
            &mut yes,
        )
        .expect("revoked");
        assert!(left(dir.path()).is_empty());
        assert!(outside.path().join("precious").exists());
    }

    /// The configuration's places outside the state directory are the ones `revoke` is given: a
    /// Supervisors' root and a log directory beneath the state directory are deleted with it and
    /// named by nothing.
    /// Verifies: ADR-0064
    #[test]
    fn only_what_lies_outside_the_state_directory_is_named() {
        let config = |extra: &str| {
            let mut config: ClientConfig =
                toml::from_str(&format!("state_dir = \"/var/lib/classis/state\"\n{extra}"))
                    .expect("config");
            config.state_dir = PathBuf::from("/var/lib/classis/state");
            config
        };
        assert_eq!(Outside::of(&config("")), Outside::default());
        assert_eq!(
            Outside::of(&config("[logging]\ndir = \"/var/lib/classis/state/log\"\n")),
            Outside::default()
        );
        let moved = Outside::of(&config(
            "supervisor_dir = \"/opt/sup\"\n[logging]\ndir = \"/var/log/classis\"\n\n\
             [[supervisor]]\ntype = \"command\"\nname = \"stub\"\ncommand = \"stub\"\n",
        ));
        assert_eq!(
            moved,
            Outside {
                supervisors_root: Some((PathBuf::from("/opt/sup"), vec!["stub".to_string()])),
                log_dir: Some(PathBuf::from("/var/log/classis")),
            }
        );
    }

    /// Outside the state directory `revoke` deletes the Supervisors' directories — named by a
    /// block, left by a purge, or holding an identity no block names now — and the Client's own
    /// log files, and nothing else those two directories hold; `--keep-cache` spares none of it.
    /// Verifies: ADR-0064
    #[test]
    fn the_supervisors_and_log_files_outside_the_state_directory_are_deleted() {
        let dir = state_dir_with_everything();
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        let (root, logs) = (
            elsewhere.path().join("supervisors"),
            elsewhere.path().join("logs"),
        );
        for (path, contents) in [
            ("supervisors/named/program/bin", "x"),
            ("supervisors/named/packages/p", "x"),
            ("supervisors/orphan/instance-uid", "x"),
            ("supervisors/.purge-gone-0123456789abcdef0/x", "x"),
            ("supervisors/someone-elses/data", "x"),
            ("supervisors/notes.txt", "x"),
            ("logs/supervisor.2026-11-17.log", "x"),
            ("logs/other.log", "x"),
            ("logs/supervisor.notes", "x"),
        ] {
            let path = elsewhere.path().join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, contents).expect("write");
        }
        let outside = Outside {
            supervisors_root: Some((root.clone(), vec!["named".to_string()])),
            log_dir: Some(logs.clone()),
        };
        let revoked =
            revoke(dir.path(), &outside, true, true, &Host(None), &mut yes).expect("revoked");
        assert_eq!(left(&root), ["notes.txt", "someone-elses"]);
        assert_eq!(left(&logs), ["other.log", "supervisor.notes"]);
        assert_eq!(revoked.outside, [root, logs]);
        assert_eq!(
            left(dir.path()),
            ["config", "packages"],
            "--keep-cache, in the state directory"
        );
    }

    /// A `supervisor_dir` above the state directory is deleted from without touching the state
    /// directory's own entries, which `--keep-cache` spares, or the installation beside it; and one
    /// that is not there is nothing to delete.
    /// Verifies: ADR-0064
    #[test]
    fn a_supervisors_root_above_the_state_directory_costs_neither_it_nor_the_installation() {
        let data = tempfile::tempdir().expect("data");
        let state = data.path().join("state");
        for (path, contents) in [
            ("state/state.json", "{}"),
            ("state/packages/p", "x"),
            ("supervisor.toml", "x"),
            ("versions/1.0.0/supervisor", "x"),
            ("stub/instance-uid", "x"),
        ] {
            let path = data.path().join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, contents).expect("write");
        }
        let outside = Outside {
            supervisors_root: Some((data.path().to_path_buf(), vec!["stub".to_string()])),
            log_dir: Some(data.path().join("no-logs")),
        };
        let revoked = revoke(&state, &outside, true, true, &Host(None), &mut yes).expect("revoked");
        assert_eq!(left(data.path()), ["state", "supervisor.toml", "versions"]);
        assert_eq!(left(&state), ["packages"]);
        assert_eq!(
            revoked.outside,
            [data.path().to_path_buf()],
            "no log directory to empty"
        );
    }

    /// A link in the Supervisors' root or the log directory is removed as a link, and what it
    /// points at is not touched; a link as the root itself is refused.
    /// Verifies: ADR-0064
    #[cfg(unix)]
    #[test]
    fn outside_the_state_directory_no_link_is_followed() {
        let dir = state_dir_with_everything();
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        let precious = tempfile::tempdir().expect("precious");
        std::fs::write(precious.path().join("precious"), "x").expect("write");
        let (root, logs) = (
            elsewhere.path().join("supervisors"),
            elsewhere.path().join("logs"),
        );
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&logs).expect("logs");
        std::os::unix::fs::symlink(precious.path(), root.join("named")).expect("link");
        std::os::unix::fs::symlink(precious.path(), logs.join("supervisor.2026-11-17.log"))
            .expect("link");
        let outside = Outside {
            supervisors_root: Some((root.clone(), vec!["named".to_string()])),
            log_dir: Some(logs.clone()),
        };
        revoke(dir.path(), &outside, true, false, &Host(None), &mut yes).expect("revoked");
        assert!(left(&root).is_empty() && left(&logs).is_empty());
        assert!(precious.path().join("precious").exists());

        let linked = elsewhere.path().join("linked");
        std::os::unix::fs::symlink(precious.path(), &linked).expect("link");
        let outside = Outside {
            supervisors_root: Some((linked, vec!["precious".to_string()])),
            log_dir: None,
        };
        let dir = state_dir_with_everything();
        revoke(dir.path(), &outside, true, false, &Host(None), &mut yes).expect_err("a link");
        assert!(precious.path().join("precious").exists());
    }

    /// A state directory that does not exist is not revoked.
    #[test]
    fn a_missing_state_directory_is_nothing_to_revoke() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = revoke(
            &dir.path().join("none"),
            &Outside::default(),
            true,
            false,
            &Host(None),
            &mut yes,
        )
        .expect_err("nothing");
        assert!(error.contains("nothing to revoke"), "{error}");
    }
}
