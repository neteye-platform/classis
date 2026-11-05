//! Where a Gateway keeps its bindings across restarts (ADR-0058 clause 3):
//! `<state_dir>/gateway-packages/bindings`, a journal of [`Change`]s.
//!
//! The file begins with a line naming its format and version and holds one change per line, of at
//! most [`MAX_LINE`] bytes. Changes are appended and synced; the file is rewritten whole, as a new
//! file synced and renamed over the old, when the Gateway starts and when it has grown to twice the
//! lines its live bindings and hosts take. It is at most [`MAX_BYTES`]. It is read and written
//! without following a link, `0600` on Unix; on Windows it lies under the state directory's ACL.
//!
//! A line is one of:
//!
//! ```text
//! b <instance_uid> <host>                           bound
//! u <instance_uid>                                  unbound
//! r <instance_uid>                                  reported
//! h <host> <notAfter> <issuer SHA-256> <serial>     where the host's certificate ends
//! ```
//!
//! An `instance_uid` is in its UUID form, `notAfter` in seconds since the Unix epoch, the issuer
//! and serial in lowercase hex as the revocation list names a certificate. A host is written with
//! every byte outside the printable ASCII range, a space and `%` among them, as `%XX`.

use std::fs::File;
use std::io::{self, BufRead as _, Read as _, Seek as _, Write as _};

use opamp::uid::InstanceUid;

use crate::gateway::policy::{Change, End};
use crate::nofollow::HeldDir;

/// The store's file name in the Gateway's directory.
pub const NAME: &str = "bindings";

/// The first line: the format, and its version.
const FORMAT: &str = "opamp-fleet-gateway-bindings";
const VERSION: &str = "1";

/// The longest line, its newline not counted.
pub const MAX_LINE: usize = 512;

/// The largest store.
pub const MAX_BYTES: u64 = 512 << 20;

/// The first line of every store.
fn header() -> String {
    format!("{FORMAT} {VERSION}")
}

/// `host` as a line carries it.
fn encode(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    for byte in host.bytes() {
        if byte.is_ascii_graphic() && byte != b'%' {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The host a line carries, or `None` for anything [`encode`] does not write.
fn decode(field: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(field.len());
    let mut rest = field.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let hex = tail.get(..2)?;
            let decoded = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            if decoded.is_ascii_graphic() && decoded != b'%' {
                return None;
            }
            bytes.push(decoded);
            rest = &tail[2..];
        } else if byte.is_ascii_graphic() {
            bytes.push(byte);
            rest = tail;
        } else {
            return None;
        }
    }
    String::from_utf8(bytes).ok()
}

/// Whether `field` is lowercase hex, `exactly` digits long when given.
fn is_hex(field: &str, exactly: Option<usize>) -> bool {
    !field.is_empty()
        && exactly.is_none_or(|len| field.len() == len)
        && field
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The line `change` is written as, or `None` when it would be longer than [`MAX_LINE`].
#[must_use]
pub fn line(change: &Change) -> Option<String> {
    let line = match change {
        Change::Bound(uid, host) => format!("b {uid} {}", encode(host)),
        Change::Unbound(uid) => format!("u {uid}"),
        Change::Reported(uid) => format!("r {uid}"),
        Change::Ends(host, end) => format!(
            "h {} {} {} {}",
            encode(host),
            end.not_after,
            end.issuer,
            end.serial
        ),
    };
    (line.len() <= MAX_LINE).then_some(line)
}

/// The change one line names, or `None` for anything [`line`] does not write.
fn parse(line: &str) -> Option<Change> {
    let uid = |field: &str| InstanceUid::parse(field).filter(|uid| uid.to_string() == field);
    let fields: Vec<&str> = line.split(' ').collect();
    match fields.as_slice() {
        ["b", id, host] => Some(Change::Bound(uid(id)?, decode(host)?)),
        ["u", id] => Some(Change::Unbound(uid(id)?)),
        ["r", id] => Some(Change::Reported(uid(id)?)),
        ["h", host, not_after, issuer, serial] => {
            let parsed: i64 = not_after.parse().ok()?;
            let canonical = parsed.to_string() == *not_after
                && is_hex(issuer, Some(64))
                && is_hex(serial, None)
                && (serial.len() == 1 || !serial.starts_with('0'));
            canonical.then_some(())?;
            Some(Change::Ends(
                decode(host)?,
                End {
                    not_after: parsed,
                    issuer: (*issuer).to_string(),
                    serial: (*serial).to_string(),
                },
            ))
        }
        _ => None,
    }
}

/// Why the open store cannot be relied on, from its metadata: on Unix it must be the Client
/// account's and `0600`; on every platform no larger than [`MAX_BYTES`].
fn refuse(file: &File) -> Option<String> {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => return Some(format!("cannot read its metadata: {e}")),
    };
    if meta.len() > MAX_BYTES {
        return Some(format!(
            "it holds {} bytes, more than its bound of {MAX_BYTES}",
            meta.len()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != crate::storage::handle::own() {
            return Some(format!(
                "it is owned by uid {}, not by the Client's account",
                meta.uid()
            ));
        }
        if meta.mode() & 0o7777 != 0o600 {
            return Some(format!("its mode is {:o}, not 600", meta.mode() & 0o7777));
        }
    }
    None
}

/// Reads the store in `dir`: its changes in order. A store that does not exist is an empty one; a
/// last line without its newline is a write a crash cut off, and is dropped.
///
/// # Errors
/// Returns why the store cannot be relied on: it is a link or no regular file, it is not the
/// Client account's alone, it is larger than its bound, it names a format or version this build
/// does not read, or a line before its last cannot be parsed.
pub fn load(dir: &HeldDir) -> Result<Vec<Change>, String> {
    let file = match dir.open_file(NAME) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    if let Some(why) = refuse(&file) {
        return Err(why);
    }
    let mut reader = io::BufReader::new(file.take(MAX_BYTES));
    let mut changes = Vec::new();
    let mut headed = false;
    let mut buffer = Vec::new();
    for number in 1usize.. {
        buffer.clear();
        let read = (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buffer)
            .map_err(|e| format!("cannot read it: {e}"))?;
        if read == 0 {
            break;
        }
        let Some(text) = buffer.strip_suffix(b"\n") else {
            if buffer.len() > MAX_LINE {
                return Err(format!("line {number} is longer than {MAX_LINE} bytes"));
            }
            // Cut off by a crash: nothing follows it.
            break;
        };
        let text = std::str::from_utf8(text).ok();
        if !headed {
            match text.and_then(|text| text.split_once(' ')) {
                Some((FORMAT, VERSION)) => headed = true,
                Some((FORMAT, version)) => {
                    return Err(format!(
                        "it is version {version} of its format, which this build does not read"
                    ))
                }
                _ => break,
            }
            continue;
        }
        let change = text
            .and_then(parse)
            .ok_or_else(|| format!("line {number} cannot be parsed"))?;
        changes.push(change);
    }
    if !headed {
        return Err("it does not begin with the line naming its format".to_string());
    }
    Ok(changes)
}

/// The store, open for appending.
pub struct Journal {
    dir: HeldDir,
    /// The store's file; `None` while a rewrite replaces it, or once it could not be opened again.
    file: Option<File>,
    /// The bytes written and synced: where the next line goes.
    len: u64,
    /// How many changes it holds, the reports aside.
    lines: usize,
    /// How many reports it holds, which grow with the Agents carried rather than with the
    /// bindings made.
    reports: usize,
    /// What the file holds may not be what `len` says, or may not be the file at its name: nothing
    /// more is appended until the store is rewritten whole.
    damaged: bool,
    /// The failures a test injects.
    #[cfg(test)]
    pub faults: Faults,
}

/// Where a test makes a write fail.
#[cfg(test)]
#[derive(Default)]
pub struct Faults {
    /// Every write fails, as on a full disk.
    pub all: bool,
    /// The next append fails once its bytes are written, before they are synced.
    pub append: bool,
    /// The next rewrite fails once its new file is renamed into place.
    pub after_rename: bool,
}

/// Where a write may fail by a test's hand.
enum Stage {
    Any,
    Appended,
    Renamed,
}

impl Journal {
    /// Writes `changes` as the whole store in `dir` and opens it for appending.
    ///
    /// # Errors
    /// Returns an error when the store cannot be written, or would be larger than its bound.
    pub fn create(dir: HeldDir, changes: &[Change]) -> io::Result<Journal> {
        let mut journal = Journal {
            dir,
            file: None,
            len: 0,
            lines: 0,
            reports: 0,
            damaged: true,
            #[cfg(test)]
            faults: Faults::default(),
        };
        journal.compact(changes)?;
        Ok(journal)
    }

    /// Rewrites the store whole as `changes`, a new file synced and renamed over the old, the
    /// directory synced after it. The file is closed while it is replaced. When the rename has
    /// not happened the old store stands as it was; when anything fails after it, the journal
    /// appends nothing until a rewrite succeeds.
    ///
    /// # Errors
    /// Returns an error when the store cannot be written, or would be larger than its bound.
    pub fn compact(&mut self, changes: &[Change]) -> io::Result<()> {
        self.fault(&Stage::Any)?;
        let mut bytes = format!("{}\n", header()).into_bytes();
        bytes.extend(lines(changes)?);
        if bytes.len() as u64 > MAX_BYTES {
            return Err(too_large());
        }
        // A file is not replaced while this journal holds it open.
        self.file = None;
        if let Err(e) = self.dir.write(NAME, &bytes, 0o600) {
            // Not renamed: the old store stands, and is opened again as it was.
            self.reopen();
            return Err(e);
        }
        self.len = bytes.len() as u64;
        let reports = changes
            .iter()
            .filter(|change| matches!(change, Change::Reported(_)));
        self.reports = reports.count();
        self.lines = changes.len() - self.reports;
        self.damaged = true;
        // The rename is what a waiting report relies on.
        self.fault(&Stage::Renamed)?;
        self.dir.sync()?;
        self.file = Some(self.dir.open_for_writing(NAME)?);
        self.damaged = false;
        Ok(())
    }

    /// The store's file opened again after a rewrite that did not replace it; a journal that
    /// cannot open it appends nothing more.
    fn reopen(&mut self) {
        match self.dir.open_for_writing(NAME) {
            Ok(file) => self.file = Some(file),
            Err(_) => self.damaged = true,
        }
    }

    /// Appends `changes` and syncs them. On an error the store is cut back to what it held.
    ///
    /// # Errors
    /// Returns an error when a change is longer than a line may be, when the store would grow past
    /// its bound, when the journal is damaged, or when the write or the sync fails.
    pub fn append(&mut self, changes: &[Change]) -> io::Result<()> {
        self.fault(&Stage::Any)?;
        let (false, Some(file)) = (self.damaged, self.file.as_mut()) else {
            return Err(io::Error::other(
                "the store may not hold what was written to it; it is rewritten first",
            ));
        };
        let bytes = lines(changes)?;
        if self.len + bytes.len() as u64 > MAX_BYTES {
            return Err(too_large());
        }
        let written = file
            .seek(io::SeekFrom::Start(self.len))
            .and_then(|_| file.write_all(&bytes));
        let written = written.and_then(|()| self.fault(&Stage::Appended));
        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::other("the store is not open"));
        };
        if let Err(e) = written.and_then(|()| file.sync_data()) {
            if file
                .set_len(self.len)
                .and_then(|()| file.sync_data())
                .is_err()
            {
                self.damaged = true;
            }
            return Err(e);
        }
        self.len += bytes.len() as u64;
        let reports = changes
            .iter()
            .filter(|change| matches!(change, Change::Reported(_)));
        let reports = reports.count();
        self.reports += reports;
        self.lines += changes.len() - reports;
        Ok(())
    }

    #[cfg(test)]
    fn fault(&mut self, stage: &Stage) -> io::Result<()> {
        let fails = match stage {
            Stage::Any => self.faults.all,
            Stage::Appended => std::mem::take(&mut self.faults.append),
            Stage::Renamed => std::mem::take(&mut self.faults.after_rename),
        };
        if fails {
            return Err(io::Error::other("the test fails this write"));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn fault(&mut self, _: &Stage) -> io::Result<()> {
        Ok(())
    }

    /// How many changes the store holds, the reports aside.
    #[must_use]
    pub fn lines(&self) -> usize {
        self.lines
    }

    /// How many reports the store holds.
    #[must_use]
    pub fn reports(&self) -> usize {
        self.reports
    }
}

fn too_large() -> io::Error {
    io::Error::other(format!("the store would grow past {MAX_BYTES} bytes"))
}

/// `changes` as the lines of a store, each with its newline.
fn lines(changes: &[Change]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for change in changes {
        let line = line(change)
            .ok_or_else(|| io::Error::other(format!("a change is longer than {MAX_LINE} bytes")))?;
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::policy::Bindings;

    fn end(serial: &str) -> End {
        End {
            not_after: 1_900_000_000,
            issuer: "ab".repeat(32),
            serial: serial.to_string(),
        }
    }

    fn held(dir: &tempfile::TempDir) -> HeldDir {
        HeldDir::open(dir.path()).expect("held")
    }

    /// What the Gateway writes it reads back: every kind of change, a host with a space, a `%`
    /// and a character beyond ASCII among them.
    /// Verifies: ADR-0058
    #[test]
    fn every_change_reads_back_as_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (uid, odd) = (InstanceUid::default(), "a host%ü".to_string());
        let changes = vec![
            Change::Ends(odd.clone(), end("1f")),
            Change::Bound(uid, odd),
            Change::Reported(uid),
            Change::Unbound(uid),
        ];
        let mut journal = Journal::create(held(&dir), &changes[..2]).expect("create");
        journal.append(&changes[2..]).expect("append");
        assert_eq!(load(&held(&dir)), Ok(changes));
        assert_eq!((journal.lines(), journal.reports()), (3, 1));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(NAME))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A store that does not exist is an empty one.
    /// Verifies: ADR-0058
    #[test]
    fn a_missing_store_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(load(&held(&dir)), Ok(Vec::new()));
    }

    /// A last line without its newline is dropped as a write a crash cut off, and the rest is
    /// read; a line before it that cannot be parsed, an unknown version, a missing first line and a
    /// line longer than its bound make the store unreadable.
    /// Verifies: ADR-0058
    #[test]
    fn only_a_last_line_without_its_newline_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uid = InstanceUid::default();
        let good = format!(
            "{}\n{}\n{}\n",
            header(),
            line(&Change::Ends("h1".into(), end("1"))).expect("line"),
            line(&Change::Bound(uid, "h1".into())).expect("line")
        );
        let write = |contents: &str| {
            HeldDir::open(dir.path())
                .expect("held")
                .write(NAME, contents.as_bytes(), 0o600)
                .expect("write");
            load(&held(&dir))
        };
        let read = write(&format!("{good}u {uid}")).expect("readable");
        assert_eq!(
            read,
            vec![
                Change::Ends("h1".into(), end("1")),
                Change::Bound(uid, "h1".into())
            ],
            "the cut-off removal is dropped"
        );
        for (damaged, why) in [
            (
                format!("{good}q {uid}\nr {uid}\n"),
                "a line before its last",
            ),
            (format!("{good}x\n"), "an unknown kind of line, terminated"),
            (format!("{good}h h1 01 {} 1\n", "ab".repeat(32)), "a time"),
            (format!("{good}h h1 1 {} 01\n", "ab".repeat(32)), "a serial"),
            (format!("{good}b {uid} a b\n"), "a host with a space"),
            (format!("{good}b {uid} %41\n"), "a host escaped needlessly"),
            (
                format!("{good}b {uid} {}\n", "x".repeat(MAX_LINE)),
                "a line too long",
            ),
        ] {
            assert!(write(&damaged).is_err(), "{why} was read");
        }
        assert!(write(&good.replacen(" 1\n", " 2\n", 1)).is_err_and(|e| e.contains("version 2")));
        assert!(write(&good.replacen(&header(), "something else", 1)).is_err());
        assert!(write("").is_err(), "no first line");
        assert!(write(&header()).is_err(), "a first line cut off");
    }

    /// A store larger than its bound is refused before it is read.
    /// Verifies: ADR-0058
    #[test]
    fn a_store_past_its_bound_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        Journal::create(held(&dir), &[]).expect("create");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join(NAME))
            .expect("open");
        file.set_len(MAX_BYTES + 1).expect("grow");
        assert!(load(&held(&dir)).is_err_and(|e| e.contains("bound")));
    }

    /// A store that is a link, a directory, or on Unix one that is not `0600`, is unreadable.
    /// Verifies: ADR-0058
    #[test]
    fn a_store_that_is_no_private_regular_file_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(NAME)).expect("dir");
        assert!(load(&held(&dir)).is_err(), "a directory");
        std::fs::remove_dir(dir.path().join(NAME)).expect("remove");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let elsewhere = dir.path().join("elsewhere");
            std::fs::write(&elsewhere, format!("{}\n", header())).expect("write");
            std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            std::os::unix::fs::symlink(&elsewhere, dir.path().join(NAME)).expect("link");
            assert!(load(&held(&dir)).is_err_and(|e| e.contains("link")));
            std::fs::remove_file(dir.path().join(NAME)).expect("remove");

            Journal::create(held(&dir), &[]).expect("create");
            assert_eq!(load(&held(&dir)), Ok(Vec::new()));
            std::fs::set_permissions(
                dir.path().join(NAME),
                std::fs::Permissions::from_mode(0o640),
            )
            .expect("chmod");
            assert!(load(&held(&dir)).is_err_and(|e| e.contains("640")));
        }
    }

    /// A store rewritten whole from what replaying it leaves reads back to the same bindings, in
    /// the same order, and holds one line per binding and per host.
    /// Verifies: ADR-0058
    #[test]
    fn a_compacted_store_loads_to_the_same_bindings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let [a, b, c] = [(); 3].map(|()| InstanceUid::default());
        let mut journal = Journal::create(
            held(&dir),
            &[
                Change::Ends("h1".into(), end("1")),
                Change::Bound(a, "h1".into()),
                Change::Bound(b, "h1".into()),
                Change::Ends("h2".into(), end("2")),
                Change::Bound(c, "h2".into()),
            ],
        )
        .expect("create");
        journal
            .append(&[
                Change::Reported(a),
                Change::Unbound(c),
                Change::Ends("h1".into(), end("3")),
            ])
            .expect("append");
        let before = Bindings::replay(load(&held(&dir)).expect("load")).expect("replay");
        journal.compact(&before.snapshot()).expect("compact");
        let after = Bindings::replay(load(&held(&dir)).expect("load")).expect("replay");
        assert_eq!(after.snapshot(), before.snapshot());
        assert_eq!(
            after.snapshot(),
            vec![
                Change::Ends("h1".into(), end("3")),
                Change::Bound(b, "h1".into()),
                Change::Bound(a, "h1".into()),
            ],
            "h2 has no binding left, and a was reported after b"
        );
        assert_eq!(journal.lines(), 3);
    }

    /// A change whose line would be longer than its bound is not written, and nothing of the
    /// append is.
    /// Verifies: ADR-0058
    #[test]
    fn a_change_too_long_for_a_line_is_not_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut journal = Journal::create(held(&dir), &[]).expect("create");
        let uid = InstanceUid::default();
        let long = Change::Bound(uid, "x".repeat(MAX_LINE));
        assert!(line(&long).is_none());
        assert!(journal
            .append(&[Change::Ends("h".into(), end("1")), long])
            .is_err());
        assert_eq!(load(&held(&dir)), Ok(Vec::new()));
        assert_eq!(journal.lines(), 0);
    }

    /// A rewrite that fails once its new file is in place leaves the journal appending nothing,
    /// so no change lands in a file that is no longer the store; the next rewrite succeeds and the
    /// journal appends again.
    /// Verifies: ADR-0058
    #[test]
    fn a_rewrite_that_fails_after_its_rename_appends_nothing_until_rewritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let [a, b] = [(); 2].map(|()| InstanceUid::default());
        let held_store = vec![
            Change::Ends("h1".into(), end("1")),
            Change::Bound(a, "h1".into()),
        ];
        let mut journal = Journal::create(held(&dir), &held_store).expect("create");
        journal.faults.after_rename = true;
        assert!(journal.compact(&held_store).is_err());
        assert!(
            journal.append(&[Change::Bound(b, "h1".into())]).is_err(),
            "appended to a file that may not be the store"
        );
        journal.compact(&held_store).expect("compact");
        journal
            .append(&[Change::Bound(b, "h1".into())])
            .expect("append");
        let mut expected = held_store;
        expected.push(Change::Bound(b, "h1".into()));
        assert_eq!(load(&held(&dir)), Ok(expected));
    }

    /// An append that fails after its bytes are written is cut back: the store reads as before,
    /// and the next append lands after what it held.
    /// Verifies: ADR-0058
    #[test]
    fn a_failed_append_is_cut_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let [a, b] = [(); 2].map(|()| InstanceUid::default());
        let first = vec![
            Change::Ends("h1".into(), end("1")),
            Change::Bound(a, "h1".into()),
        ];
        let mut journal = Journal::create(held(&dir), &first).expect("create");
        journal.faults.append = true;
        assert!(journal.append(&[Change::Bound(b, "h1".into())]).is_err());
        assert_eq!(load(&held(&dir)), Ok(first.clone()));
        journal.append(&[Change::Unbound(a)]).expect("append");
        let mut expected = first;
        expected.push(Change::Unbound(a));
        assert_eq!(load(&held(&dir)), Ok(expected));
    }
}
