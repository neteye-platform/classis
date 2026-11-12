//! What an install on Windows left to finish, kept until it is done (ADR-0059 clauses 1 and 6): a
//! withdrawal that is due, and the services it stopped that are to run again.
//!
//! What a former account was granted is withdrawn after the SCM names its successor: before, the
//! former account's service could still start and run under it. Once the SCM has switched, nothing
//! names the former account any more — a second service dropped is deregistered, and a changed
//! logon account is overwritten — so an install that failed between the switch and the end of the
//! withdrawal would leave the grants in place with nothing to find them by. And an install stops
//! both services before it changes anything, so one that failed after the stop would leave a
//! service that ran stopped, with nothing to say it ran. Both are therefore written down before
//! the stop, in one write — what runs as it is about to be stopped; where the stop fails, the
//! services to start again are set from what the SCM reports then, and the rest of the record
//! stays — and the withdrawal is struck once it is done, the services once they run again, and the
//! record goes with the last of them. Every install finishes what it finds written. The CLI's
//! `service start` and `service stop`, once they have succeeded, strike the services, whose run
//! state is the operator's from then on; `sc.exe` and the Services console know nothing of the
//! record and strike nothing, and a `service stop` that failed in part strikes nothing either. An
//! uninstall completes the withdrawal once both services are stopped, and deregisters them
//! whether or not it can.
//!
//! The record is text: a line `client <SID>` or `process <SID>` per former account, by the part it
//! had, `root <path>` per root, and `resume client` or `resume agents` per service to start again.
//! On Windows it is the string value [`VALUE`] of the key
//! `HKEY_LOCAL_MACHINE\SOFTWARE\<PRODUCT_NAME>\`[`KEY`], which the install creates owned by the
//! Administrators and carrying a protected DACL that grants `LocalSystem` and the Administrators
//! alone ([`PRIVATE`]) — the owner named rather than left to the policy that may make the creating
//! administrator the owner — and reads only where it still carries that DACL and one of them owns
//! it. Nothing the Client or a Managed Process may write holds it: not the data root, whose DACL
//! the Client may change where a process account is registered, and not a path a later
//! `--data-root` would name differently. The key is the install's own rather than one beneath the
//! service's key in the SCM's tree, whose DACL is the system's, undocumented, and gone with
//! `sc delete`. Unix withdraws by a change of owner and needs no record; the logic is compiled
//! everywhere, over a [`Store`], so that its tests run everywhere.

use std::path::{Path, PathBuf};

use super::manager::{HaltError, Halted};

/// Where a record is kept: a string, or none.
pub trait Store {
    /// The record's text; `None` where nothing is recorded.
    ///
    /// # Errors
    /// Returns why it cannot be read, or why what holds it cannot be trusted.
    fn load(&self) -> Result<Option<String>, String>;
    /// Replaces the record with `text`, in one write.
    ///
    /// # Errors
    /// Returns why it cannot be written.
    fn save(&self, text: &str) -> Result<(), String>;
    /// Removes the record; none there is no error.
    ///
    /// # Errors
    /// Returns why it cannot be removed.
    fn clear(&self) -> Result<(), String>;
    /// Where it is kept, for a message.
    fn describe(&self) -> String;
}

/// The key beneath `SOFTWARE\<PRODUCT_NAME>` that holds the record on Windows.
pub const KEY: &str = "WithdrawalPending";
/// The string value of [`KEY`] that is the record.
pub const VALUE: &str = "Pending";

/// The security descriptor [`KEY`] is created with: owned by the Administrators, full control for
/// `LocalSystem` and the Administrators, nothing for anyone else, inherited from no parent.
#[cfg(windows)]
const PRIVATE: &str = "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)";

/// The part a former account had: the Client's, or the process account's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Client,
    Process,
}

impl Part {
    fn key(self) -> &'static str {
        match self {
            Part::Client => "client",
            Part::Process => "process",
        }
    }
}

/// What is left to finish: the former accounts, by part and SID, whose grants are still to be
/// withdrawn, the roots to withdraw them from, and the services a stop left stopped that ran
/// before it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pending {
    pub formers: Vec<(Part, String)>,
    pub roots: Vec<PathBuf>,
    pub resume: Halted,
}

impl Pending {
    /// Whether nothing is left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.formers.is_empty() && !self.resume.client && !self.resume.agents
    }

    /// Whether a withdrawal is due.
    #[must_use]
    pub fn withdrawal_due(&self) -> bool {
        !self.formers.is_empty()
    }

    /// Adds the former accounts `formers` and the roots `roots`, each once.
    pub fn add(&mut self, formers: impl IntoIterator<Item = (Part, String)>, roots: &[&Path]) {
        for former in formers {
            if !self.formers.contains(&former) {
                self.formers.push(former);
            }
        }
        for root in roots {
            if !self.roots.iter().any(|known| known == root) {
                self.roots.push(root.to_path_buf());
            }
        }
    }

    /// Adds what a stop found running to what is to run again: a service that ran before an
    /// earlier attempt stays to run again though this stop found it stopped.
    pub fn halted(&mut self, halted: Halted) {
        self.resume.client |= halted.client;
        self.resume.agents |= halted.agents;
    }

    /// The record's text.
    ///
    /// # Errors
    /// Returns that a SID or a root cannot be written on one line.
    pub fn text(&self) -> Result<String, String> {
        let mut text = String::new();
        for (part, sid) in &self.formers {
            text.push_str(&line(part.key(), sid)?);
        }
        for root in &self.roots {
            let root = root
                .to_str()
                .ok_or_else(|| format!("{} is no Unicode path", root.display()))?;
            text.push_str(&line("root", root)?);
        }
        if self.resume.client {
            text.push_str("resume client\n");
        }
        if self.resume.agents {
            text.push_str("resume agents\n");
        }
        Ok(text)
    }

    /// Reads the record's text.
    ///
    /// # Errors
    /// Returns the first line that is no line of a record.
    pub fn parse(text: &str) -> Result<Pending, String> {
        let mut pending = Pending::default();
        for line in text.lines().filter(|line| !line.is_empty()) {
            match line.split_once(' ') {
                Some(("client", sid)) => pending.formers.push((Part::Client, sid.to_string())),
                Some(("process", sid)) => pending.formers.push((Part::Process, sid.to_string())),
                Some(("root", root)) => pending.roots.push(PathBuf::from(root)),
                Some(("resume", "client")) => pending.resume.client = true,
                Some(("resume", "agents")) => pending.resume.agents = true,
                _ => return Err(format!("{line:?} is no line of the record")),
            }
        }
        Ok(pending)
    }
}

fn line(key: &str, value: &str) -> Result<String, String> {
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(format!("{value:?} cannot be recorded on one line"));
    }
    Ok(format!("{key} {value}\n"))
}

/// What is recorded in `store`; nothing where there is no record.
///
/// # Errors
/// Returns that the record cannot be read or is not one — on Windows also one whose key no longer
/// carries the DACL it was created with, or that neither `LocalSystem` nor the Administrators own:
/// what it says cannot be trusted, and what it would have withdrawn cannot be known, so the install
/// changes nothing until an Administrator has looked at it and removed it.
pub fn read(store: &dyn Store) -> Result<Pending, String> {
    let refused = |e: String| {
        format!(
            "{} records what an install left to finish and cannot be read: {e}. Nothing was \
             changed",
            store.describe()
        )
    };
    match store.load().map_err(refused)? {
        None => Ok(Pending::default()),
        Some(text) => Pending::parse(&text).map_err(refused),
    }
}

/// Records `pending` in `store`, replacing what was recorded there; where nothing is left, the
/// record goes.
///
/// # Errors
/// Returns why it cannot be written or removed.
pub fn record(store: &dyn Store, pending: &Pending) -> Result<(), String> {
    if pending.is_empty() {
        return store
            .clear()
            .map_err(|e| format!("cannot remove the record in {}: {e}", store.describe()));
    }
    store
        .save(&pending.text()?)
        .map_err(|e| format!("cannot record what is left in {}: {e}", store.describe()))
}

/// Completes the withdrawal `pending` records in `store`: `withdraw` for every former account but
/// those of `kept` — the accounts the registration names now in the same part, which an operator
/// may have switched back to — over every root, and the withdrawal struck from the record once all
/// are done; what else it records stays. A former account named now in the other part is withdrawn
/// all the same: what it is granted in that part is granted again after. A withdrawal that fails
/// leaves the record as it was.
///
/// # Errors
/// Returns the first withdrawal that failed, or that the record cannot be rewritten.
pub fn complete(
    store: &dyn Store,
    pending: &mut Pending,
    kept: &[(Part, &str)],
    mut withdraw: impl FnMut(&str, &[&Path]) -> Result<(), String>,
) -> Result<(), String> {
    {
        let roots: Vec<&Path> = pending.roots.iter().map(PathBuf::as_path).collect();
        let mut done: Vec<&str> = Vec::new();
        for (part, sid) in &pending.formers {
            if kept.contains(&(*part, sid.as_str())) || done.contains(&sid.as_str()) {
                continue;
            }
            withdraw(sid, &roots)?;
            done.push(sid);
        }
    }
    let mut left = pending.clone();
    left.formers.clear();
    left.roots.clear();
    record(store, &left)
        .map_err(|e| format!("the withdrawal is done, and its record is left: {e}"))?;
    *pending = left;
    Ok(())
}

/// Strikes the services to start again from the record in `store`, once they run.
///
/// # Errors
/// Returns that the record cannot be rewritten.
pub fn resumed(store: &dyn Store, pending: &mut Pending) -> Result<(), String> {
    let mut left = pending.clone();
    left.resume = Halted::default();
    record(store, &left)?;
    *pending = left;
    Ok(())
}

/// How a stop for a change went wrong, as [`halt_recorded`] reports it.
#[derive(Debug, PartialEq, Eq)]
pub enum HaltFailed {
    /// The record could not be written; nothing was stopped.
    Unrecorded(String),
    /// The stop failed; the record names what is to run again as the SCM left it.
    Stopped(String),
}

/// Stops both services for a change, recorded around it in `store` (ADR-0059 clauses 1 and 2):
/// what `running` says runs is added to what `pending` already names to run again, and written —
/// with the withdrawal due — before `halt` stops anything; what `halt` found running beyond that is
/// added after it. Where `halt` fails, what is to run again is set from what the SCM reports then,
/// asked through `now`, which counts only a service that runs settled — running or paused — and
/// one still stopping or starting as not running: what ran before this install, and what ran when
/// it began or was stopped by `halt` and runs no more — a restart that failed, or a stop that timed
/// out and is still under way or completed after all. Where the SCM cannot be asked, the record
/// keeps all of that.
///
/// # Errors
/// Returns [`HaltFailed::Unrecorded`] where the record could not be written before the stop, and
/// [`HaltFailed::Stopped`] where the stop, or the record after it, failed.
pub fn halt_recorded(
    store: &dyn Store,
    pending: &mut Pending,
    running: Halted,
    halt: &mut dyn FnMut() -> Result<Halted, HaltError>,
    now: &mut dyn FnMut() -> Result<Halted, String>,
) -> Result<(), HaltFailed> {
    let before = pending.resume;
    pending.halted(running);
    record(store, pending).map_err(HaltFailed::Unrecorded)?;
    match halt() {
        Ok(halted) => {
            let recorded = pending.resume;
            pending.halted(halted);
            if pending.resume != recorded {
                record(store, pending).map_err(HaltFailed::Stopped)?;
            }
            Ok(())
        }
        Err(HaltError { error, stopped }) => {
            let ran = Halted {
                client: running.client || stopped.client,
                agents: running.agents || stopped.agents,
            };
            pending.resume = match now() {
                Ok(now) => Halted {
                    client: before.client || (ran.client && !now.client),
                    agents: before.agents || (ran.agents && !now.agents),
                },
                Err(_) => Halted {
                    client: before.client || ran.client,
                    agents: before.agents || ran.agents,
                },
            };
            match record(store, pending) {
                Ok(()) => Err(HaltFailed::Stopped(error)),
                Err(again) => Err(HaltFailed::Stopped(format!(
                    "{error}; and the record cannot be set to what runs now ({again}), and names \
                     what ran when this install began to be started again"
                ))),
            }
        }
    }
}

/// What an uninstall does, over its seams (ADR-0059 clauses 1 and 6): it stops both services
/// through `halt`, which starts nothing again; completes the recorded withdrawal through
/// `complete`, and then removes the record through `remove` — only where it holds the install lock
/// (`locked`) and both services stopped; and deregisters both through `deregister`, always: an
/// uninstall that left them registered would leave them starting at the next boot. Without the
/// lock the record is left alone — another run may be rewriting it. Every error is reported, after
/// the deregistration; `recorded` says where the record is kept.
///
/// # Errors
/// Returns every step that failed, the deregistration first.
pub fn uninstall_with(
    locked: Result<(), String>,
    halt: &mut dyn FnMut() -> Result<(), String>,
    complete: &mut dyn FnMut() -> Result<(), String>,
    remove: &mut dyn FnMut() -> Result<(), String>,
    deregister: &mut dyn FnMut() -> Result<(), String>,
    recorded: &str,
) -> Result<(), String> {
    let mut unfinished = Vec::new();
    let halted = halt();
    match (locked, halted) {
        (Err(e), _) => unfinished.push(format!(
            "the install lock could not be taken ({e}), so {recorded} was left as it is; \
             `supervisor service uninstall` again finishes it"
        )),
        (Ok(()), Err(e)) => unfinished.push(format!(
            "what former accounts were granted is not withdrawn: the services are not both \
             stopped ({e}). It stays recorded in {recorded}; `supervisor service install` \
             completes it, and a later `supervisor service uninstall` too"
        )),
        (Ok(()), Ok(())) => match complete() {
            Ok(()) => {
                if let Err(e) = remove() {
                    unfinished.push(e);
                }
            }
            Err(e) => unfinished.push(format!(
                "what former accounts were granted is not withdrawn: {e}. It stays recorded in \
                 {recorded}; `supervisor service install` completes it, and a later `supervisor \
                 service uninstall` too"
            )),
        },
    }
    if let Err(e) = deregister() {
        unfinished.insert(0, format!("the services are not deregistered: {e}"));
        return Err(unfinished.join("; "));
    }
    if unfinished.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the services were deregistered, and not all else was done: {}",
            unfinished.join("; ")
        ))
    }
}

/// The record on Windows: [`VALUE`] of `HKEY_LOCAL_MACHINE\<parent>\<KEY>`.
#[cfg(windows)]
pub struct Registry {
    parent: String,
}

#[cfg(windows)]
impl Registry {
    /// The install's record, beneath `SOFTWARE\<PRODUCT_NAME>`.
    #[must_use]
    pub fn of_the_install() -> Registry {
        Registry::beneath(&format!(r"SOFTWARE\{}", super::manager::service_name()))
    }

    /// A record beneath `HKEY_LOCAL_MACHINE\<parent>`.
    #[must_use]
    pub fn beneath(parent: &str) -> Registry {
        Registry {
            parent: parent.to_string(),
        }
    }

    fn key(&self) -> String {
        format!(r"{}\{KEY}", self.parent)
    }

    /// Removes the key, and its parent where that holds nothing else.
    ///
    /// # Errors
    /// Returns why either cannot be removed.
    pub fn remove(&self) -> Result<(), String> {
        use crate::win32::{delete_key, Key, KEY_QUERY_VALUE};
        delete_key(&self.key()).map_err(|e| format!("cannot remove {}: {e}", self.describe()))?;
        let empty = Key::open(&self.parent, KEY_QUERY_VALUE)
            .and_then(|key| key.map(|key| key.is_empty()).transpose())
            .map_err(|e| format!(r"cannot read HKLM\{}: {e}", self.parent))?;
        if empty == Some(true) {
            delete_key(&self.parent)
                .map_err(|e| format!(r"cannot remove HKLM\{}: {e}", self.parent))?;
        }
        Ok(())
    }
}

/// Whether `key` is owned by `LocalSystem` or the Administrators and carries the DACL of
/// [`PRIVATE`].
#[cfg(windows)]
fn check_private(key: &crate::win32::Key) -> Result<(), String> {
    const OWNER: u32 = 0x1;
    const DACL: u32 = 0x4;
    let owner = key.security_text(OWNER).map_err(|e| e.to_string())?;
    if !matches!(
        owner.as_str(),
        "O:SY" | "O:BA" | "O:S-1-5-18" | "O:S-1-5-32-544"
    ) {
        return Err(format!("it is owned by {owner}"));
    }
    let dacl = key.security_text(DACL).map_err(|e| e.to_string())?;
    if !crate::win32::same_dacl(&dacl, PRIVATE).map_err(|e| e.to_string())? {
        return Err(format!("it carries {dacl}"));
    }
    Ok(())
}

#[cfg(windows)]
impl Store for Registry {
    fn load(&self) -> Result<Option<String>, String> {
        use crate::win32::{Key, KEY_QUERY_VALUE, KEY_READ_CONTROL};
        let Some(key) = Key::open(&self.key(), KEY_QUERY_VALUE | KEY_READ_CONTROL)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        check_private(&key)?;
        key.string(VALUE).map_err(|e| e.to_string())
    }

    fn save(&self, text: &str) -> Result<(), String> {
        use crate::win32::{Key, KEY_QUERY_VALUE, KEY_READ_CONTROL, KEY_SET_VALUE};
        let key = Key::create(
            &self.parent,
            KEY,
            PRIVATE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_READ_CONTROL,
        )
        .map_err(|e| e.to_string())?;
        // A key that existed keeps its own descriptor, which may not be the one asked for.
        check_private(&key)?;
        key.set_string(VALUE, text).map_err(|e| e.to_string())
    }

    fn clear(&self) -> Result<(), String> {
        use crate::win32::{Key, KEY_SET_VALUE};
        match Key::open(&self.key(), KEY_SET_VALUE).map_err(|e| e.to_string())? {
            None => Ok(()),
            Some(key) => key.delete_value(VALUE).map_err(|e| e.to_string()),
        }
    }

    fn describe(&self) -> String {
        format!(r"HKLM\{}", self.key())
    }
}

/// The roots a withdrawal walks (ADR-0059 clause 16): the layout root, the data root, the state
/// directory, the configuration file and the fleet files copied beside it, and the Supervisors'
/// root where it lies beneath the first three. One outside them all stays the operator's, and is
/// not among them.
#[must_use]
pub fn roots<'a>(
    layout: &'a Path,
    data: &'a Path,
    state: &'a Path,
    supervisors: &'a Path,
    config: &'a Path,
    copies: &'a [PathBuf],
) -> Vec<&'a Path> {
    let mut roots = vec![layout, data, state];
    if super::layout::beneath(supervisors, &roots).is_ok() {
        roots.push(supervisors);
    }
    roots.push(config);
    roots.extend(copies.iter().map(PathBuf::as_path));
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Supervisors' root the configuration places outside every root the install acts on is not
    /// walked by a withdrawal: it stays the operator's. One beneath them is.
    /// Verifies: ADR-0059
    #[test]
    fn a_withdrawal_walks_no_supervisors_root_outside_the_installs_roots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (layout, data) = (dir.path().join("layout"), dir.path().join("data"));
        let state = data.join("state");
        let outside = dir.path().join("elsewhere").join("supervisors");
        let inside = state.join("supervisors");
        let config = data.join("supervisor.toml");
        let copies = [data.join("ca.pem")];
        let walked = roots(&layout, &data, &state, &outside, &config, &copies);
        assert!(!walked.contains(&outside.as_path()), "{walked:?}");
        assert!(walked.contains(&copies[0].as_path()), "{walked:?}");
        let walked = roots(&layout, &data, &state, &inside, &config, &copies);
        assert!(walked.contains(&inside.as_path()), "{walked:?}");
    }

    /// A record kept in memory, as a test keeps it; one whose removal fails where `stuck`.
    #[derive(Default)]
    struct Memory {
        text: std::cell::RefCell<Option<String>>,
        stuck: bool,
        unwritable: std::cell::Cell<bool>,
    }

    impl Store for Memory {
        fn load(&self) -> Result<Option<String>, String> {
            Ok(self.text.borrow().clone())
        }
        fn save(&self, text: &str) -> Result<(), String> {
            if self.unwritable.get() {
                return Err("access denied".to_string());
            }
            *self.text.borrow_mut() = Some(text.to_string());
            Ok(())
        }
        fn clear(&self) -> Result<(), String> {
            if self.stuck {
                return Err("access denied".to_string());
            }
            *self.text.borrow_mut() = None;
            Ok(())
        }
        fn describe(&self) -> String {
            "memory".to_string()
        }
    }

    /// A withdrawal that failed — an install interrupted after the SCM switched — is still
    /// recorded, and the next install, which finds no former account of its own, completes it from
    /// the record and removes it; one that succeeds leaves no record (ADR-0059 clauses 1 and 6).
    /// Verifies: ADR-0059
    #[test]
    fn an_interrupted_withdrawal_is_completed_by_the_next_install() {
        let store = Memory::default();
        let (root, config) = (Path::new("/root"), Path::new("/etc/supervisor.toml"));
        assert_eq!(read(&store), Ok(Pending::default()), "nothing recorded");

        // The first install: two former accounts, recorded before the switch.
        let mut due = read(&store).expect("read");
        due.add(
            [
                (Part::Process, "S-1-5-19".to_string()),
                (Part::Client, "S-1-5-80-1".to_string()),
            ],
            &[root, config],
        );
        record(&store, &due).expect("recorded");
        let mut asked = Vec::new();
        let interrupted = complete(&store, &mut due, &[], |sid, roots| {
            asked.push((sid.to_string(), roots.len()));
            if sid == "S-1-5-80-1" {
                return Err("held".to_string());
            }
            Ok(())
        });
        assert_eq!(interrupted, Err("held".to_string()));
        assert_eq!(
            asked,
            [("S-1-5-19".to_string(), 2), ("S-1-5-80-1".to_string(), 2)]
        );
        assert!(
            store.text.borrow().is_some(),
            "a withdrawal that failed stays recorded"
        );

        // The next install names no former account; it finds the record, adds what it walks, and
        // completes it — but not for an account the registration names again in the same part,
        // while one named now in the other part is withdrawn all the same.
        let mut due = read(&store).expect("read");
        assert_eq!(
            due.formers,
            [
                (Part::Process, "S-1-5-19".to_string()),
                (Part::Client, "S-1-5-80-1".to_string())
            ]
        );
        due.add(Vec::new(), &[root, Path::new("/state")]);
        assert_eq!(due.roots.len(), 3, "each root once");
        record(&store, &due).expect("recorded");
        let mut asked = Vec::new();
        complete(
            &store,
            &mut due,
            &[(Part::Process, "S-1-5-19"), (Part::Process, "S-1-5-80-1")],
            |sid, roots| {
                asked.push((sid.to_string(), roots.len()));
                Ok(())
            },
        )
        .expect("completed");
        assert_eq!(asked, [("S-1-5-80-1".to_string(), 3)]);
        assert_eq!(
            *store.text.borrow(),
            None,
            "a completed withdrawal leaves no record"
        );
    }

    /// The services a stop left stopped are recorded with the withdrawal, and an install that
    /// fails after the stop leaves them recorded: the next install, whose own stop finds them
    /// stopped, starts again what ran before the first. They are struck once they run, after the
    /// withdrawal, and the record goes with them (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn what_a_failed_install_stopped_is_started_by_the_next() {
        let store = Memory::default();
        // The first attempt: the Client and the second service ran; it fails after the stop.
        let mut first = read(&store).expect("read");
        first.halted(Halted {
            client: true,
            agents: true,
        });
        first.add(
            [(Part::Process, "S-1-5-19".to_string())],
            &[Path::new("/root")],
        );
        record(&store, &first).expect("recorded");

        // The next: its own stop finds both stopped, and it resumes what the first stopped.
        let mut next = read(&store).expect("read");
        next.halted(Halted::default());
        assert_eq!(
            next.resume,
            Halted {
                client: true,
                agents: true
            }
        );
        complete(&store, &mut next, &[], |_, _| Ok(())).expect("completed");
        assert_eq!(
            read(&store).expect("read"),
            Pending {
                resume: next.resume,
                ..Pending::default()
            },
            "the withdrawal is struck, the services are not yet"
        );
        resumed(&store, &mut next).expect("struck");
        assert_eq!(*store.text.borrow(), None, "and the record is gone");
    }

    /// An operator's `service start` or `service stop` after a failed install strikes what that
    /// install recorded to start again — the operator decides when the services run from then on,
    /// and the next install does not start what was stopped by hand — while a withdrawal still due
    /// stays recorded (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn an_operators_start_or_stop_strikes_what_is_to_run_again() {
        let store = Memory::default();
        let mut failed = Pending::default();
        failed.add(
            [(Part::Process, "S-1-5-19".to_string())],
            &[Path::new("/root")],
        );
        failed.halted(Halted {
            client: true,
            agents: true,
        });
        record(&store, &failed).expect("recorded");

        // `service stop` — or `service start` — then strikes what is to run again.
        let mut pending = read(&store).expect("read");
        resumed(&store, &mut pending).expect("struck");
        let left = read(&store).expect("read");
        assert_eq!(left.resume, Halted::default(), "nothing to start again");
        assert_eq!(left.formers, failed.formers, "the withdrawal stays due");

        // The next install's stop finds both stopped and starts nothing again.
        let mut next = read(&store).expect("read");
        next.halted(Halted::default());
        assert_eq!(next.resume, Halted::default());

        // With nothing else recorded, the strike removes the record.
        let only_resume = Memory::default();
        let mut pending = Pending::default();
        pending.halted(Halted {
            client: true,
            agents: false,
        });
        record(&only_resume, &pending).expect("recorded");
        resumed(&only_resume, &mut pending).expect("struck");
        assert_eq!(*only_resume.text.borrow(), None);
    }

    const BOTH: Halted = Halted {
        client: true,
        agents: true,
    };
    const CLIENT: Halted = Halted {
        client: true,
        agents: false,
    };
    const AGENTS: Halted = Halted {
        client: false,
        agents: true,
    };

    /// What runs is recorded before anything is stopped: the stop finds it written, and a record
    /// that cannot be written stops nothing. What the stop found running beyond it is added after
    /// it (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn what_runs_is_recorded_before_the_stop_and_amended_after_it() {
        let store = Memory::default();
        let mut pending = Pending::default();
        pending.add(
            [(Part::Process, "S-1-5-19".to_string())],
            &[Path::new("/root")],
        );
        let mut seen = None;
        halt_recorded(
            &store,
            &mut pending,
            CLIENT,
            &mut || {
                seen = Some(read(&store).expect("read"));
                Ok(BOTH)
            },
            &mut || panic!("asked only after a failed stop"),
        )
        .expect("stopped");
        let seen = seen.expect("stopped");
        assert_eq!(seen.resume, CLIENT, "written before the stop");
        assert!(seen.withdrawal_due(), "with the withdrawal due");
        assert_eq!(read(&store).expect("read").resume, BOTH, "amended after it");

        let store = Memory::default();
        store.unwritable.set(true);
        let mut pending = Pending::default();
        let failed = halt_recorded(
            &store,
            &mut pending,
            BOTH,
            &mut || panic!("nothing is stopped"),
            &mut || panic!("nothing is asked"),
        );
        assert!(
            matches!(failed, Err(HaltFailed::Unrecorded(_))),
            "{failed:?}"
        );
    }

    /// Where the stop fails, what is to run again is set from what the SCM reports then: what ran
    /// before this install, and what ran when it began and runs no more — a restart that failed,
    /// or a stop that timed out and completed after all — and nothing that runs again or never ran
    /// (ADR-0059 clauses 1 and 2).
    /// Verifies: ADR-0059
    #[test]
    fn a_failed_stop_records_what_runs_no_more() {
        // Both ran; the stop of the second timed out, the Client's restart failed, and the second
        // stopped after all: both are to run again.
        let store = Memory::default();
        let mut pending = Pending::default();
        let failed = halt_recorded(
            &store,
            &mut pending,
            BOTH,
            &mut || Err(timed_out(Halted::default())),
            &mut || Ok(Halted::default()),
        );
        assert_eq!(
            failed,
            Err(HaltFailed::Stopped("did not stop in time".to_string()))
        );
        assert_eq!(read(&store).expect("read").resume, BOTH);

        // Both ran, and run again after the failed stop: nothing is to be started.
        let store = Memory::default();
        let mut pending = Pending::default();
        let _ = halt_recorded(
            &store,
            &mut pending,
            BOTH,
            &mut || Err(timed_out(Halted::default())),
            &mut || Ok(BOTH),
        );
        assert_eq!(read(&store), Ok(Pending::default()), "nothing left");

        // An earlier install's record of the second service stays; the Client, which ran and runs
        // no more, joins it.
        let store = Memory::default();
        let mut pending = Pending::default();
        pending.halted(AGENTS);
        let _ = halt_recorded(
            &store,
            &mut pending,
            CLIENT,
            &mut || Err(timed_out(Halted::default())),
            &mut || Ok(AGENTS),
        );
        assert_eq!(read(&store).expect("read").resume, BOTH);

        // Where the SCM cannot be asked, the record written before the stop stays.
        let store = Memory::default();
        let mut pending = Pending::default();
        let _ = halt_recorded(
            &store,
            &mut pending,
            CLIENT,
            &mut || Err(timed_out(Halted::default())),
            &mut || Err("access denied".to_string()),
        );
        assert_eq!(read(&store).expect("read").resume, CLIENT);

        // A stop that timed out leaves the service still stopping, which the SCM reports as not
        // running settled: it is to run again — the resume waits it out.
        let store = Memory::default();
        let mut pending = Pending::default();
        let _ = halt_recorded(
            &store,
            &mut pending,
            AGENTS,
            &mut || Err(timed_out(Halted::default())),
            &mut || Ok(Halted::default()),
        );
        assert_eq!(read(&store).expect("read").resume, AGENTS, "still stopping");

        // A Client that started between the look and the stop, was stopped by it and could not be
        // started again counts, though the look before found it stopped.
        let store = Memory::default();
        let mut pending = Pending::default();
        let _ = halt_recorded(
            &store,
            &mut pending,
            Halted::default(),
            &mut || Err(timed_out(CLIENT)),
            &mut || Ok(Halted::default()),
        );
        assert_eq!(
            read(&store).expect("read").resume,
            CLIENT,
            "what the stop stopped"
        );

        // And where the SCM cannot be asked, too.
        let store = Memory::default();
        let mut pending = Pending::default();
        let _ = halt_recorded(
            &store,
            &mut pending,
            AGENTS,
            &mut || Err(timed_out(CLIENT)),
            &mut || Err("access denied".to_string()),
        );
        assert_eq!(read(&store).expect("read").resume, BOTH);
    }

    fn timed_out(stopped: Halted) -> HaltError {
        HaltError {
            error: "did not stop in time".to_string(),
            stopped,
        }
    }

    /// An uninstall withdraws only once both services are stopped and the install lock is held,
    /// and leaves the record alone otherwise; it deregisters both always — after a failed stop,
    /// without the lock, after a failed withdrawal — and reports every step that failed (ADR-0059
    /// clauses 1 and 6).
    /// Verifies: ADR-0059
    #[test]
    fn an_uninstall_always_deregisters_and_withdraws_only_once_both_are_stopped() {
        #[derive(Default)]
        struct Steps(std::cell::RefCell<Vec<&'static str>>);
        impl Steps {
            fn note(&self, step: &'static str, result: Result<(), String>) -> Result<(), String> {
                self.0.borrow_mut().push(step);
                result
            }
            fn taken(&self) -> Vec<&'static str> {
                std::mem::take(&mut self.0.borrow_mut())
            }
        }
        let steps = Steps::default();
        let run = |locked: Result<(), String>,
                   halt: Result<(), String>,
                   complete: Result<(), String>,
                   deregister: Result<(), String>| {
            uninstall_with(
                locked,
                &mut || steps.note("halt", halt.clone()),
                &mut || steps.note("complete", complete.clone()),
                &mut || steps.note("remove", Ok(())),
                &mut || steps.note("deregister", deregister.clone()),
                "the record",
            )
        };
        let fail = |e: &str| Err(e.to_string());

        assert_eq!(run(Ok(()), Ok(()), Ok(()), Ok(())), Ok(()));
        assert_eq!(steps.taken(), ["halt", "complete", "remove", "deregister"]);

        let after_a_failed_stop = run(Ok(()), fail("did not stop"), Ok(()), Ok(()));
        assert_eq!(steps.taken(), ["halt", "deregister"], "no withdrawal");
        assert!(after_a_failed_stop
            .is_err_and(|e| e.contains("did not stop") && e.contains("the record")),);

        let without_the_lock = run(fail("busy"), Ok(()), Ok(()), Ok(()));
        assert_eq!(
            steps.taken(),
            ["halt", "deregister"],
            "the record left alone"
        );
        assert!(without_the_lock.is_err_and(|e| e.contains("busy")));

        let after_a_failed_withdrawal = run(Ok(()), Ok(()), fail("held"), Ok(()));
        assert_eq!(
            steps.taken(),
            ["halt", "complete", "deregister"],
            "the record kept"
        );
        assert!(after_a_failed_withdrawal.is_err_and(|e| e.contains("held")));

        let all_failed = run(
            fail("busy"),
            fail("did not stop"),
            Ok(()),
            fail("access denied"),
        );
        assert_eq!(steps.taken(), ["halt", "deregister"]);
        let all_failed = all_failed.expect_err("failed");
        assert!(
            all_failed.starts_with("the services are not deregistered: access denied")
                && all_failed.contains("busy"),
            "{all_failed}"
        );
    }

    /// A record whose removal fails is not passed off as removed: the completion says so, and
    /// what it records stays to be read again.
    /// Verifies: ADR-0059
    #[test]
    fn a_failed_clear_keeps_the_record() {
        let store = Memory {
            stuck: true,
            ..Memory::default()
        };
        let mut due = Pending::default();
        due.add(
            [(Part::Client, "S-1-5-20".to_string())],
            &[Path::new("/root")],
        );
        record(&store, &due).expect("recorded");
        let failed = complete(&store, &mut due, &[], |_, _| Ok(())).expect_err("not cleared");
        assert!(failed.contains("its record is left"), "{failed}");
        assert!(
            read(&store).expect("read").withdrawal_due(),
            "still recorded"
        );
        assert!(due.withdrawal_due(), "and still due here");
    }

    /// The record is read back as it was written, and what is no record is refused rather than
    /// passed over.
    /// Verifies: ADR-0059
    #[test]
    fn a_record_reads_back_and_what_is_none_is_refused() {
        let mut pending = Pending::default();
        pending.add(
            [(Part::Client, "S-1-5-20".to_string())],
            &[Path::new("/data root/x")],
        );
        pending.halted(Halted {
            client: false,
            agents: true,
        });
        let text = pending.text().expect("text");
        assert_eq!(text, "client S-1-5-20\nroot /data root/x\nresume agents\n");
        assert_eq!(Pending::parse(&text), Ok(pending));
        assert!(Pending::parse("withdraw everything\n").is_err());
        assert!(Pending::parse("resume everything\n").is_err());
        let mut broken = Pending::default();
        broken.add([(Part::Client, "S-1-5-20\nroot C:\\".to_string())], &[]);
        assert!(broken.text().is_err(), "no SID writes a second line");

        let store = Memory::default();
        store.save("nonsense").expect("saved");
        let refused = read(&store).expect_err("refused");
        assert!(refused.contains("Nothing was changed"), "{refused}");
    }

    /// On Windows the record goes into the registry and comes back as it was written, beneath a
    /// key the install creates owned by the Administrators and carrying a DACL that grants
    /// `LocalSystem` and the Administrators alone — nobody else may write it — and a key that
    /// carries any other DACL, or that another account owns, is refused. A key of the test's own
    /// stands in for the install's; its parent goes with it once empty.
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_the_record_round_trips_through_a_key_only_the_administrators_write() {
        let parent = format!(
            r"SOFTWARE\{}-test-{}",
            super::super::manager::service_name(),
            std::process::id()
        );
        let store = Registry::beneath(&parent);
        let gone = |what: &str| {
            assert!(
                crate::win32::Key::open(what, crate::win32::KEY_QUERY_VALUE)
                    .expect("asked")
                    .is_none(),
                "{what} is gone"
            );
        };
        assert_eq!(read(&store), Ok(Pending::default()), "nothing recorded");
        let mut pending = Pending::default();
        pending.add(
            [(Part::Process, "S-1-5-19".to_string())],
            &[Path::new(r"C:\ProgramData\x y")],
        );
        record(&store, &pending).expect("recorded");
        assert_eq!(read(&store), Ok(pending.clone()), "read back");

        let key = crate::win32::Key::open(&store.key(), crate::win32::KEY_READ_CONTROL)
            .expect("opened")
            .expect("there");
        assert_eq!(key.security_text(0x1).expect("its owner"), "O:BA");
        let dacl = key.security_text(0x4).expect("its DACL");
        assert!(
            crate::win32::same_dacl(&dacl, "D:P(A;;KA;;;SY)(A;;KA;;;BA)").expect("compared"),
            "{dacl}"
        );
        drop(key);

        complete(&store, &mut pending, &[], |_, _| Ok(())).expect("completed");
        assert_eq!(read(&store), Ok(Pending::default()), "cleared");
        store.remove().expect("removed");
        gone(&parent);

        // A key someone else made in its place is refused, read or written: one whose DACL
        // grants more, and one another account owns.
        let _privileges = crate::win32::BackupPrivileges::enable().expect("privileges");
        let mut pending = Pending::default();
        pending.add([(Part::Client, "S-1-5-20".to_string())], &[]);
        for (planted, refusal) in [
            ("O:BAD:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)", "it carries"),
            ("O:LSD:P(A;;KA;;;SY)(A;;KA;;;BA)", "it is owned by"),
        ] {
            let key = crate::win32::Key::create(&parent, KEY, planted, crate::win32::KEY_SET_VALUE)
                .expect("planted");
            key.set_string(VALUE, &pending.text().expect("text"))
                .expect("written");
            drop(key);
            let refused = read(&store).expect_err("refused");
            assert!(refused.contains(refusal), "{planted}: {refused}");
            assert!(record(&store, &pending).is_err(), "and not written to");
            store.remove().expect("removed");
            gone(&parent);
        }
    }
}
