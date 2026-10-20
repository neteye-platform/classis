//! The audit record on disk (ADR-0022), the adapter behind [`crate::audit::Audit`]: one JSON line
//! per security decision, each carrying the SHA-256 of the line before it, written by one task in
//! the order the decisions were taken.
//!
//! A decision is recorded through [`AuditLog::record`], which never waits on the disk: the entry goes
//! through a bounded channel to the writer task. When the channel is full, or the last write failed,
//! the call answers [`Unavailable`], and the caller refuses what it was about to allow — a security
//! decision is never taken without its record (clause 6). Refusals are aggregated per event and
//! peer past ten a second, never dropped (clause 5), and counted before they reach the channel,
//! where they may take no more than [`REFUSAL_SHARE`] of it: a flood of refusals from however many
//! peers cannot leave an admission or an operator act without room for its record. The store behind the writer is a port; the
//! filesystem adapter is [`crate::fs::FsAuditStore`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tracing::{error, info};

use crate::audit::{Audit, Entry, Field, Unavailable};
use crate::fleet::Clock;

/// The entries waiting for the writer at most (clause 6).
pub const CHANNEL_CAPACITY: usize = 10_000;

/// The refusals of one event from one peer written per second before the rest are counted.
pub const REFUSALS_PER_SECOND: u32 = 10;

/// The entries of the channel refusals may take at once; the rest is kept for every other
/// decision.
pub const REFUSAL_SHARE: usize = CHANNEL_CAPACITY / 2;

/// The hash a chain starts from.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Where the record left off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tail {
    /// The last non-empty line, whatever it holds: the next entry chains to it.
    pub last_line: String,
    /// The highest `seq` an entry near the end carries; the next entry takes the one after it.
    pub last_seq: u64,
    /// Whether the record ends in a line that is not a whole entry — a crash mid-write.
    pub torn: bool,
}

/// The record's port (ADR-0006): where the lines go.
pub trait AuditStore: Send {
    /// Where the record left off, if it holds anything.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    fn tail(&mut self) -> Result<Option<Tail>, String>;

    /// Appends one line, newline added, to the current file, starting one named after `seq` when
    /// there is none.
    ///
    /// # Errors
    /// Returns an error when the line cannot be written and flushed.
    fn append(&mut self, seq: u64, line: &str) -> Result<(), String>;

    /// The size of the current file.
    fn current_bytes(&self) -> u64;

    /// Closes the current file so the next append starts one named after its `seq`, and deletes
    /// the oldest files past `keep`; answers each deleted file's name and its last line.
    ///
    /// # Errors
    /// Returns an error when a file cannot be deleted.
    fn rotate(&mut self, keep: usize) -> Result<Vec<(String, String)>, String>;
}

/// How large a file grows and how many are kept (`[audit]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub keep_files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_bytes: 64 * 1024 * 1024,
            keep_files: 16,
        }
    }
}

/// What the writer is sent: an entry, or a request to write out everything before it.
enum Message {
    Entry(Entry),
    /// Answered once every entry queued before it was taken, its second's aggregates included:
    /// `true` when all of them were written, `false` when the record was failing.
    Drain(std::sync::mpsc::SyncSender<bool>),
}

/// The handle every decision is recorded through.
pub struct AuditLog {
    tx: std::sync::mpsc::SyncSender<Message>,
    failing: Arc<AtomicBool>,
    /// Decisions refused because they could not be recorded, told in the next entry.
    unrecorded: Arc<AtomicU64>,
    clock: Arc<dyn Clock>,
    refusals: Arc<Mutex<Refusals>>,
    /// Refusals in the channel right now, bounded by [`REFUSAL_SHARE`].
    queued_refusals: Arc<AtomicUsize>,
}

/// Which refusals are aggregated together: the event and the peer, an IPv6 peer by its /64.
type RefusalKey = (String, Option<String>);

/// The refusals counted per event and peer, shared by [`AuditLog::record`], which counts them
/// before they are queued, and the writer, which writes the aggregates.
#[derive(Default)]
struct Refusals {
    /// Each event and peer heard from, at most [`REFUSAL_KEYS`] of them.
    window: HashMap<RefusalKey, Slot>,
}

/// The refusals of one event and peer the writer has not yet accounted for.
#[derive(Clone, Copy)]
struct Slot {
    /// The second `count` belongs to.
    second: u64,
    count: u32,
    /// Refusals past the allowance of earlier seconds, not yet written as an aggregate.
    carried: u32,
}

/// The events and peers counted at once at most. Only the writer's tick lets go of them, so while
/// it is stalled a refusal of yet another event or peer finds no room and goes unrecorded.
pub const REFUSAL_KEYS: usize = CHANNEL_CAPACITY;

/// What becomes of one refusal.
#[derive(Debug, PartialEq, Eq)]
enum Counted {
    /// Among the first [`REFUSALS_PER_SECOND`] of its second: written as it is.
    Queue,
    /// Past them: counted for the aggregate.
    Aggregated,
    /// No room to count it.
    NoRoom,
}

impl Refusals {
    /// Counts one refusal.
    fn admit(&mut self, key: RefusalKey, second: u64) -> Counted {
        if !self.window.contains_key(&key) && self.window.len() >= REFUSAL_KEYS {
            return Counted::NoRoom;
        }
        let slot = self.window.entry(key).or_insert(Slot {
            second,
            count: 0,
            carried: 0,
        });
        if slot.second != second {
            slot.carried = slot
                .carried
                .saturating_add(slot.count.saturating_sub(REFUSALS_PER_SECOND));
            slot.second = second;
            slot.count = 0;
        }
        slot.count = slot.count.saturating_add(1);
        if slot.count <= REFUSALS_PER_SECOND {
            Counted::Queue
        } else {
            Counted::Aggregated
        }
    }

    /// Takes the unwritten counts of every second before `second`, letting go of the events and
    /// peers that have nothing left in the current one.
    fn take_passed(&mut self, second: u64) -> Vec<(RefusalKey, u32)> {
        let mut passed = Vec::new();
        self.window.retain(|key, slot| {
            let current = slot.second >= second;
            let unwritten = if current {
                slot.carried
            } else {
                slot.carried
                    .saturating_add(slot.count.saturating_sub(REFUSALS_PER_SECOND))
            };
            if unwritten > 0 {
                passed.push((key.clone(), unwritten));
            }
            slot.carried = 0;
            current
        });
        passed
    }
}

fn refusal_key(entry: &Entry) -> RefusalKey {
    (
        entry.event.clone(),
        // Counted as the throttle counts it: an IPv6 peer by its /64, so new addresses from one
        // block do not each get ten lines a second.
        match entry.fields.get("peer") {
            Some(Field::Text(peer)) => Some(peer.parse::<std::net::IpAddr>().map_or_else(
                |_| peer.clone(),
                |ip| crate::throttle::peer_key(ip).to_string(),
            )),
            _ => None,
        },
    )
}

impl AuditLog {
    /// Opens the chain where `store` left it and starts the writer task.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    pub fn start(
        mut store: Box<dyn AuditStore>,
        limits: Limits,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        let (seq, prev, torn) = match store.tail()? {
            None => (0, GENESIS.to_string(), false),
            Some(tail) => (tail.last_seq, line_hash(&tail.last_line), tail.torn),
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAPACITY);
        let failing = Arc::new(AtomicBool::new(false));
        let unrecorded = Arc::new(AtomicU64::new(0));
        let refusals = Arc::new(Mutex::new(Refusals::default()));
        let queued_refusals = Arc::new(AtomicUsize::new(0));
        let mut writer = Writer {
            store,
            limits,
            clock: clock.clone(),
            seq,
            prev,
            refusals: refusals.clone(),
            queued_refusals: queued_refusals.clone(),
            failing: failing.clone(),
            unrecorded: unrecorded.clone(),
        };
        if torn {
            writer.write(Entry::new("audit.chain_broken", "recorded"));
        }
        // A thread of its own: the writes are blocking file I/O, and must not hold a runtime
        // worker that admission needs.
        std::thread::Builder::new()
            .name("audit".to_string())
            .spawn(move || writer.run(&rx))
            .map_err(|e| format!("cannot start the audit writer: {e}"))?;
        Ok(AuditLog {
            tx,
            failing,
            unrecorded,
            clock,
            refusals,
            queued_refusals,
        })
    }

    /// Waits until every entry queued so far is written, for at most `timeout`; `false` when it
    /// was not, in time or at all because the record is failing. The process exits after this at shutdown, and the writer thread with it, so what
    /// is still queued would otherwise be lost without a trace (ADR-0022).
    #[must_use]
    pub fn drain(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let (done, written) = std::sync::mpsc::sync_channel(1);
        let mut message = Message::Drain(done);
        loop {
            match self.tx.try_send(message) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(back)) => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    message = back;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
        written
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .unwrap_or(false)
    }

    fn unrecorded(&self) -> Unavailable {
        self.unrecorded.fetch_add(1, Ordering::SeqCst);
        Unavailable
    }
}

impl Audit for AuditLog {
    /// Records one decision. Answers [`Unavailable`] while the last write failed or the channel is
    /// full; the decision is then counted and told in the next entry that is written. A refusal
    /// past the per-second allowance of its event and peer is counted for its aggregate and never
    /// queued; one that finds the refusals' share of the channel taken, or no room to be counted
    /// ([`REFUSAL_KEYS`]), is counted as unrecorded.
    fn record(&self, entry: Entry) -> Result<(), Unavailable> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(self.unrecorded());
        }
        if !entry.is_refusal() {
            return self
                .tx
                .try_send(Message::Entry(entry))
                .map_err(|_| self.unrecorded());
        }
        let second = self.clock.now_ms() / 1000;
        let counted = self
            .refusals
            .lock()
            .expect("audit refusals lock")
            .admit(refusal_key(&entry), second);
        match counted {
            Counted::Queue => {}
            Counted::Aggregated => return Ok(()),
            Counted::NoRoom => return Err(self.unrecorded()),
        }
        if self.queued_refusals.fetch_add(1, Ordering::SeqCst) >= REFUSAL_SHARE {
            self.queued_refusals.fetch_sub(1, Ordering::SeqCst);
            return Err(self.unrecorded());
        }
        self.tx.try_send(Message::Entry(entry)).map_err(|_| {
            self.queued_refusals.fetch_sub(1, Ordering::SeqCst);
            self.unrecorded()
        })
    }
}

/// The SHA-256 of a line as written, hex.
#[must_use]
pub fn line_hash(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

/// The writer task's state.
struct Writer {
    store: Box<dyn AuditStore>,
    limits: Limits,
    clock: Arc<dyn Clock>,
    seq: u64,
    prev: String,
    refusals: Arc<Mutex<Refusals>>,
    queued_refusals: Arc<AtomicUsize>,
    failing: Arc<AtomicBool>,
    unrecorded: Arc<AtomicU64>,
}

impl Writer {
    fn run(mut self, rx: &std::sync::mpsc::Receiver<Message>) {
        use std::sync::mpsc::RecvTimeoutError;
        let mut last_tick = std::time::Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(message) => self.handle(message),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.flush_window(u64::MAX);
                    return;
                }
            }
            if last_tick.elapsed() >= Duration::from_secs(1) {
                last_tick = std::time::Instant::now();
                self.tick(rx);
            }
        }
    }

    fn tick(&mut self, rx: &std::sync::mpsc::Receiver<Message>) {
        let second = self.clock.now_ms() / 1000;
        // What was queued before the second ended is written before its aggregates, so they
        // follow the refusals they count.
        for _ in 0..CHANNEL_CAPACITY {
            match rx.try_recv() {
                Ok(message) => self.handle(message),
                Err(_) => break,
            }
        }
        self.flush_window(second);
        // While writing fails nothing is let through, so the writer itself tries again; the first
        // entry that lands says how much went unrecorded.
        if self.failing.load(Ordering::SeqCst) {
            self.append(Entry::new("audit.resumed", "recorded"));
        }
    }

    fn handle(&mut self, message: Message) {
        match message {
            Message::Entry(entry) => self.take(entry),
            Message::Drain(done) => {
                self.flush_window(u64::MAX);
                let _ = done.send(!self.failing.load(Ordering::SeqCst));
            }
        }
    }

    /// Writes an entry that came through the channel.
    fn take(&mut self, entry: Entry) {
        if entry.is_refusal() {
            self.queued_refusals.fetch_sub(1, Ordering::SeqCst);
        }
        self.write(entry);
    }

    /// Writes one aggregate per event and peer whose second has passed.
    fn flush_window(&mut self, second: u64) {
        let passed = self
            .refusals
            .lock()
            .expect("audit refusals lock")
            .take_passed(second);
        for (key, count) in passed {
            self.write_aggregate(&key, count);
        }
    }

    fn write_aggregate(&mut self, (event, peer): &RefusalKey, count: u32) {
        self.write(
            Entry::new(&format!("{event}.aggregated"), "refused")
                .with("peer", peer.clone())
                .with("count", count),
        );
    }

    /// Gives the entry its place in the chain and appends it; rotates first when the file is full.
    fn write(&mut self, entry: Entry) {
        if self.store.current_bytes() >= self.limits.max_file_bytes {
            match self.store.rotate(self.limits.keep_files) {
                Ok(deleted) => {
                    for (file, last) in deleted {
                        self.append(
                            Entry::new("audit.rotated", "recorded")
                                .with("deleted", file)
                                .with("deleted_last_hash", line_hash(&last)),
                        );
                    }
                }
                Err(e) => error!(error = %e, "cannot rotate the audit record"),
            }
        }
        self.append(entry);
    }

    fn append(&mut self, entry: Entry) {
        let seq = self.seq + 1;
        let mut line = Map::new();
        line.insert("seq".into(), seq.into());
        line.insert("time".into(), rfc3339(self.clock.now_ms()).into());
        line.insert("event".into(), entry.event.clone().into());
        line.insert("outcome".into(), entry.outcome.clone().into());
        for (key, value) in &entry.fields {
            let value = match value {
                Field::Text(text) => Value::from(text.clone()),
                Field::Unsigned(n) => Value::from(*n),
                Field::Signed(n) => Value::from(*n),
            };
            line.insert(key.clone(), value);
        }
        let unrecorded = self.unrecorded.swap(0, Ordering::SeqCst);
        if unrecorded > 0 {
            line.insert("unrecorded_before".into(), unrecorded.into());
        }
        line.insert("prev".into(), self.prev.clone().into());
        let text = Value::Object(line).to_string();
        match self.store.append(seq, &text) {
            Ok(()) => {
                self.seq = seq;
                self.prev = line_hash(&text);
                self.failing.store(false, Ordering::SeqCst);
                info!(target: "audit", seq, event = %entry.event, outcome = %entry.outcome, "{text}");
            }
            Err(e) => {
                // A retry that fails was no decision; the entries it carried the count of were.
                let lost = u64::from(entry.event != "audit.resumed");
                self.unrecorded
                    .fetch_add(lost + unrecorded, Ordering::SeqCst);
                if !self.failing.swap(true, Ordering::SeqCst) {
                    error!(error = %e, "cannot write the audit record — refusing what needs one");
                }
            }
        }
    }
}

fn rfc3339(ms: u64) -> String {
    let nanos = i128::from(ms) * 1_000_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Walks lines in order and names the first whose `prev` does not match the line before it
/// (clause 3); `Ok(count)` when the whole chain holds.
///
/// # Errors
/// Returns the position of the first break.
pub fn verify<'a>(lines: impl IntoIterator<Item = (String, &'a str)>) -> Result<u64, String> {
    let mut prev: Option<String> = None;
    let mut count = 0;
    for (place, line) in lines {
        let value: Value =
            serde_json::from_str(line).map_err(|e| format!("{place}: not an audit entry: {e}"))?;
        let stated = value
            .get("prev")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{place}: no prev"))?;
        if let Some(prev) = &prev {
            if stated != prev {
                return Err(format!(
                    "{place}: prev {stated} does not match the entry before it ({prev})"
                ));
            }
        }
        prev = Some(line_hash(line));
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Manual(AtomicU64);

    impl Clock for Manual {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Files in memory: each a name and its lines.
    type Files = Arc<Mutex<Vec<(String, Vec<String>)>>>;

    #[derive(Clone, Default)]
    struct Memory(Files, Arc<AtomicBool>);

    impl AuditStore for Memory {
        fn tail(&mut self) -> Result<Option<Tail>, String> {
            let files = self.0.lock().expect("lock");
            Ok(files.iter().rev().find_map(|(_, lines)| {
                let last_line = lines.last()?.clone();
                let seq = |line: &String| {
                    serde_json::from_str::<Value>(line)
                        .ok()
                        .and_then(|value| value["seq"].as_u64())
                };
                Some(Tail {
                    last_seq: lines.iter().filter_map(seq).max().unwrap_or(0),
                    torn: seq(&last_line).is_none(),
                    last_line,
                })
            }))
        }
        fn append(&mut self, seq: u64, line: &str) -> Result<(), String> {
            if self.1.load(Ordering::SeqCst) {
                return Err("disk full".into());
            }
            let mut files = self.0.lock().expect("lock");
            if files.is_empty() || files.last().is_some_and(|(name, _)| name.is_empty()) {
                files.retain(|(name, _)| !name.is_empty());
                files.push((format!("audit-{seq}.jsonl"), Vec::new()));
            }
            files.last_mut().expect("a file").1.push(line.to_string());
            Ok(())
        }
        fn current_bytes(&self) -> u64 {
            let files = self.0.lock().expect("lock");
            files.last().map_or(0, |(_, lines)| {
                lines.iter().map(|l| l.len() as u64 + 1).sum()
            })
        }
        fn rotate(&mut self, keep: usize) -> Result<Vec<(String, String)>, String> {
            let mut files = self.0.lock().expect("lock");
            let mut deleted = Vec::new();
            while files.len() >= keep {
                let (name, lines) = files.remove(0);
                deleted.push((name, lines.last().cloned().unwrap_or_default()));
            }
            files.push((String::new(), Vec::new()));
            Ok(deleted)
        }
    }

    impl Memory {
        fn lines(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("lock")
                .iter()
                .flat_map(|(_, lines)| lines.clone())
                .collect()
        }
    }

    fn clock() -> Arc<Manual> {
        Arc::new(Manual(AtomicU64::new(1_790_000_000_000)))
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    fn chain_of(memory: &Memory) -> Result<u64, String> {
        let lines = memory.lines();
        verify(
            lines
                .iter()
                .enumerate()
                .map(|(i, l)| (i.to_string(), l.as_str())),
        )
    }

    /// A store that takes its time over every line, as a disk under load does.
    #[derive(Clone, Default)]
    struct Slow(Memory);

    impl AuditStore for Slow {
        fn tail(&mut self) -> Result<Option<Tail>, String> {
            self.0.tail()
        }
        fn append(&mut self, seq: u64, line: &str) -> Result<(), String> {
            std::thread::sleep(Duration::from_millis(2));
            self.0.append(seq, line)
        }
        fn current_bytes(&self) -> u64 {
            self.0.current_bytes()
        }
        fn rotate(&mut self, keep: usize) -> Result<Vec<(String, String)>, String> {
            self.0.rotate(keep)
        }
    }

    /// Draining returns only once every entry queued before it is written, so the shutdown that
    /// follows it loses none of them.
    /// Verifies: ADR-0022
    #[test]
    fn a_drain_returns_once_everything_queued_is_written() {
        let slow = Slow::default();
        let audit =
            AuditLog::start(Box::new(slow.clone()), Limits::default(), clock()).expect("start");
        for n in 0..50 {
            audit
                .record(Entry::new("admission.admitted", "admitted").with("n", n))
                .expect("record");
        }
        assert!(audit.drain(Duration::from_secs(10)));
        assert_eq!(slow.0.lines().len(), 50, "an entry was still queued");
        assert_eq!(chain_of(&slow.0), Ok(50));
    }

    /// A drain over a failing record says so, so the shutdown that follows does not pass the lost
    /// entries over in silence.
    /// Verifies: ADR-0022
    #[test]
    fn a_drain_over_a_failing_record_answers_false() {
        let memory = Memory::default();
        let audit =
            AuditLog::start(Box::new(memory.clone()), Limits::default(), clock()).expect("start");
        memory.1.store(true, Ordering::SeqCst);
        audit
            .record(Entry::new("admission.admitted", "admitted"))
            .expect("queued");
        assert!(!audit.drain(Duration::from_secs(10)));
    }

    /// Verifies: ADR-0022
    #[tokio::test]
    async fn each_entry_carries_the_hash_of_the_one_before() {
        let memory = Memory::default();
        let audit =
            AuditLog::start(Box::new(memory.clone()), Limits::default(), clock()).expect("start");
        for n in 0..3 {
            audit
                .record(Entry::new("admission.admitted", "admitted").with("n", n))
                .expect("record");
        }
        settle().await;
        let lines = memory.lines();
        assert_eq!(lines.len(), 3);
        assert!(
            lines[0].contains(&format!("\"prev\":\"{GENESIS}\"")),
            "{}",
            lines[0]
        );
        assert_eq!(chain_of(&memory), Ok(3));
        let mut tampered = lines.clone();
        tampered[1] = tampered[1].replace("\"n\":1", "\"n\":9");
        assert!(verify(
            tampered
                .iter()
                .enumerate()
                .map(|(i, l)| (i.to_string(), l.as_str()))
        )
        .is_err());
    }

    /// Verifies: ADR-0022
    #[tokio::test]
    async fn the_chain_survives_a_restart_and_a_rotation() {
        let memory = Memory::default();
        let limits = Limits {
            max_file_bytes: 300,
            keep_files: 2,
        };
        {
            let audit = AuditLog::start(Box::new(memory.clone()), limits, clock()).expect("start");
            for n in 0..4 {
                audit
                    .record(Entry::new("issuance.signed", "issued").with("n", n))
                    .expect("record");
            }
            settle().await;
        }
        let audit = AuditLog::start(Box::new(memory.clone()), limits, clock()).expect("restart");
        for n in 4..8 {
            audit
                .record(Entry::new("issuance.signed", "issued").with("n", n))
                .expect("record");
        }
        settle().await;
        let lines = memory.lines();
        assert!(
            lines.iter().any(|l| l.contains("audit.rotated")),
            "{lines:#?}"
        );
        let seqs: Vec<u64> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<Value>(l).expect("json")["seq"]
                    .as_u64()
                    .expect("seq")
            })
            .collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
        // What is kept chains on from what was deleted.
        assert!(chain_of(&memory).is_ok(), "{lines:#?}");
    }

    /// Verifies: ADR-0022
    #[tokio::test]
    async fn a_truncated_file_is_recorded_as_a_broken_chain() {
        let memory = Memory::default();
        memory.0.lock().expect("lock").push((
            "audit-1.jsonl".into(),
            vec![
                "{\"seq\":7,\"prev\":\"00\"}".into(),
                "{\"seq\":8,\"prev\":\"00".into(),
            ],
        ));
        let audit =
            AuditLog::start(Box::new(memory.clone()), Limits::default(), clock()).expect("start");
        audit
            .record(Entry::new("admission.admitted", "admitted"))
            .expect("record");
        settle().await;
        let lines = memory.lines();
        assert!(lines[2].contains("audit.chain_broken"), "{lines:#?}");
        assert!(
            lines[2].contains(&line_hash(&lines[1])),
            "it chains on from the torn line"
        );
        assert!(
            lines[2].contains("\"seq\":8"),
            "it counts on from the last whole entry, never from 1: {}",
            lines[2]
        );
    }

    /// Verifies: ADR-0022
    #[tokio::test]
    async fn refusals_beyond_ten_a_second_are_aggregated_with_their_count() {
        let memory = Memory::default();
        let clock = clock();
        let audit = AuditLog::start(Box::new(memory.clone()), Limits::default(), clock.clone())
            .expect("start");
        for _ in 0..25 {
            audit.refusal(
                Entry::new("admission.refused", "refused")
                    .peer(Some("192.0.2.1".parse().expect("ip"))),
            );
        }
        settle().await;
        clock.0.fetch_add(1_000, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let lines = memory.lines();
        let written = lines
            .iter()
            .filter(|l| l.contains("\"admission.refused\""))
            .count();
        assert_eq!(written, 10);
        let aggregate = lines
            .iter()
            .find(|l| l.contains("admission.refused.aggregated"))
            .expect("an aggregate");
        assert!(aggregate.contains("\"count\":15"), "{aggregate}");
    }

    /// A refusal of the rate limit never waits for its entry: one that finds the channel full is
    /// counted, and the next entry written says so in `unrecorded_before`.
    /// Verifies: ADR-0013, ADR-0022
    #[test]
    fn a_throttle_refusal_that_finds_the_channel_full_is_counted_unrecorded() {
        let memory = Memory::default();
        let audit =
            AuditLog::start(Box::new(memory.clone()), Limits::default(), clock()).expect("start");
        // The writer waits on the store while the test holds it, and the channel fills.
        let held = memory.0.lock().expect("lock");
        let mut queued = 0;
        while audit
            .record(Entry::new("admission.admitted", "admitted"))
            .is_ok()
        {
            queued += 1;
            assert!(queued <= CHANNEL_CAPACITY + 1, "the channel never filled");
        }
        audit.refusal(
            Entry::new("agent_rate.throttled", "throttled")
                .peer(Some("192.0.2.1".parse().expect("ip")))
                .with("bucket", "host"),
        );
        drop(held);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while memory.lines().len() < queued {
            assert!(
                std::time::Instant::now() < deadline,
                "the writer fell behind"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let lines = memory.lines();
        assert!(
            !lines.iter().any(|l| l.contains("agent_rate.throttled")),
            "the refusal found no room"
        );
        assert!(
            lines.iter().any(|l| l.contains("\"unrecorded_before\":2")),
            "the admission that found no room and the refusal are counted"
        );
    }

    /// A flood of refusals — from one peer, and from as many peers as the channel holds entries —
    /// never leaves an admission without room for its record, even while the writer is stalled.
    /// Verifies: ADR-0022
    #[test]
    fn a_flood_of_refusals_leaves_room_for_every_other_record() {
        let memory = Memory::default();
        let clock = clock();
        let audit = AuditLog::start(Box::new(memory.clone()), Limits::default(), clock.clone())
            .expect("start");
        // The writer waits on the store while the test holds it, as it would on a slow disk.
        let held = memory.0.lock().expect("lock");
        for _ in 0..CHANNEL_CAPACITY * 2 {
            audit.refusal(
                Entry::new("operator.refused", "refused")
                    .peer(Some("192.0.2.1".parse().expect("ip"))),
            );
        }
        for n in 0..u32::try_from(CHANNEL_CAPACITY * 2).expect("fits") {
            audit.refusal(
                Entry::new("operator.refused", "refused")
                    .peer(Some(std::net::Ipv4Addr::from(0x0a00_0000 + n).into())),
            );
        }
        assert_eq!(
            audit.record(Entry::new("admission.admitted", "admitted")),
            Ok(()),
            "an admission found the channel full of refusals"
        );
        drop(held);
        // Once the second has passed, the one peer's flood is ten lines and an aggregate.
        clock.0.fetch_add(1_000, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let aggregate = loop {
            let lines = memory.lines();
            if let Some(aggregate) = lines
                .iter()
                .find(|l| l.contains("operator.refused.aggregated") && l.contains("192.0.2.1"))
            {
                break aggregate.clone();
            }
            assert!(std::time::Instant::now() < deadline, "no aggregate");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            aggregate.contains(&format!("\"count\":{}", CHANNEL_CAPACITY * 2 - 10)),
            "{aggregate}"
        );
        let written = memory
            .lines()
            .iter()
            .filter(|l| l.contains("\"operator.refused\"") && l.contains("\"192.0.2.1\""))
            .count();
        assert_eq!(written, REFUSALS_PER_SECOND as usize);
    }

    /// While the writer is stalled, the refusals it has yet to account for are counted for a
    /// bounded number of events and peers; a refusal of one more is unrecorded, not remembered.
    /// The bound is on memory, which no interface shows, so the table is looked at directly.
    /// Verifies: ADR-0022
    #[test]
    fn a_stalled_writer_counts_refusals_for_a_bounded_number_of_peers() {
        let memory = Memory::default();
        let audit =
            AuditLog::start(Box::new(memory.clone()), Limits::default(), clock()).expect("start");
        let held = memory.0.lock().expect("lock");
        for n in 0..u32::try_from(REFUSAL_KEYS * 3).expect("fits") {
            audit.refusal(
                Entry::new("operator.refused", "refused")
                    .peer(Some(std::net::Ipv4Addr::from(0x0a00_0000 + n).into())),
            );
        }
        assert!(
            audit.refusals.lock().expect("lock").window.len() <= REFUSAL_KEYS,
            "every peer of a stalled writer is remembered"
        );
        drop(held);
    }

    /// Verifies: ADR-0022
    #[tokio::test]
    async fn a_write_that_fails_refuses_until_one_succeeds() {
        let memory = Memory::default();
        let audit =
            AuditLog::start(Box::new(memory.clone()), Limits::default(), clock()).expect("start");
        memory.1.store(true, Ordering::SeqCst);
        audit
            .record(Entry::new("admission.admitted", "admitted"))
            .expect("queued");
        settle().await;
        assert_eq!(
            audit.record(Entry::new("admission.admitted", "admitted")),
            Err(Unavailable)
        );
        memory.1.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        audit
            .record(Entry::new("admission.admitted", "admitted"))
            .expect("recording works again once the store does");
        settle().await;
        let resumed = memory
            .lines()
            .into_iter()
            .find(|l| l.contains("audit.resumed"))
            .expect("a resumption entry");
        assert!(resumed.contains("\"unrecorded_before\":2"), "{resumed}");
    }
}
