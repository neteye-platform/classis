//! Enrolment: how a host gets its first client certificate (ADR-0021 clauses 19 to 22).
//!
//! A host enrols with a bootstrap certificate from a CA of its own. Such a connection is admitted
//! only while an operator holds an **enrolment window** open, and the certificate signing request
//! it sends waits in a **pending queue** until an operator approves or rejects it. The window's end
//! and the queue — an approved request with its certificate included — are persisted through the
//! [`EnrolmentStore`] port before the act that changes them is answered (ADR-0037 clause 9), so a
//! restart keeps an open window open until its end and keeps its requests; a window whose end has
//! passed is closed when it is loaded. When the window closes, every pending request expires.
//!
//! A request is keyed by the fingerprint of its public key: a Client re-sends the same request
//! until it is answered, and a re-sent request joins its own entry rather than queueing again.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::fleet::{CertificateSigner, Clock};
use crate::revocation::{CertId, Signed, SubjectValues};

/// The longest an enrolment window may stay open.
pub const MAX_WINDOW_SECS: u64 = 86_400;

/// The most requests the queue holds waiting for an operator at once; a decided one holds no
/// place.
pub const MAX_PENDING: usize = 1024;

/// The most requests of one bootstrap certificate the queue holds at once, unless
/// `[enrolment] max_pending_per_bootstrap` says otherwise (ADR-0046): a quarter of the queue.
pub const DEFAULT_MAX_PENDING_PER_BOOTSTRAP: usize = MAX_PENDING / 4;

/// What a request says about itself, read from the CSR by the adapter that parses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The PEM the Agent sent, signed as it is on approval.
    pub csr_pem: String,
    /// The CSR's subject, for the log only: the host chose it, so it is neither listed nor carried
    /// (ADR-0036 clause 5).
    pub subject: String,
    /// The SHA-256 fingerprint of the requested public key, hex — the key of the queue, and what the
    /// Client logs so an operator can match a request to a host.
    pub key_fingerprint: String,
    /// The `instance_uid` of the message that carried it, for the register (ADR-0021 clause 33).
    pub instance_uid: Vec<u8>,
}

/// Who asked: the bootstrap certificate the request proves (ADR-0039 clause 9), and from where — the
/// peer address of an enrolment connection, or the Gateway's host it came through (ADR-0039
/// clause 4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requester {
    /// The bootstrap certificate's subject as text, for the log.
    pub bootstrap_subject: String,
    /// The values an approval carries into the host certificate, or why the subject breaks the
    /// rules of ADR-0036 clause 1 — read from the certificate verified in the handshake. The queue
    /// lists this as it stands (ADR-0036 clause 5), so an operator sees a refusal before pressing
    /// Approve.
    pub carried: Result<SubjectValues, String>,
    pub bootstrap_fingerprint: String,
    /// The bootstrap certificate's issuer and serial; the serial as
    /// `GET /api/v1/bootstrap-certificates` lists it.
    pub bootstrap: CertId,
    pub peer: Option<IpAddr>,
    /// The host of the Gateway the request came through, in place of a peer address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

/// One pending request as the REST API lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub arrived_ms: u64,
    pub key_fingerprint: String,
    pub requester: Requester,
}

/// Keeps what was signed, and the `instance_uid` it was asked under, before a host can collect it.
pub type Record<'a> = dyn Fn(&Signed, &[u8]) -> Result<(), String> + 'a;

/// What a submitted request comes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Submitted {
    /// Waiting for an operator; the Client asks again. `new` is set when this submission took the
    /// request in, and clear when it was waiting already.
    Waiting { new: bool },
    /// Approved: the issued certificate, PEM.
    Issued(String),
    /// Rejected by an operator.
    Rejected,
    /// The queue is full; the Client is told to come back later.
    Full,
    /// Its bootstrap certificate holds its share of the queue already (ADR-0046); the Client is
    /// told to come back later. `first` is set for the first such refusal of that certificate in
    /// the window, the one that is logged.
    OverShare { first: bool },
    /// No window is open.
    Closed,
}

/// Why an operator's decision could not be applied.
#[derive(Debug, PartialEq, Eq)]
pub enum DecisionError {
    /// No pending request has that id, or it has expired — a `404`.
    NotFound,
    /// The bootstrap certificate the request came with is revoked; the request is withdrawn.
    Revoked,
    /// The bootstrap certificate's subject cannot be carried into a host certificate (ADR-0036
    /// clause 3); the text names the attribute. Nothing is signed.
    Subject(String),
    /// The CA could not sign the request.
    Sign(String),
    /// The decision could not be persisted (ADR-0037 clause 9). A rejection is not taken, and the
    /// request still waits. An approval stands: its certificate is signed and in the register, so
    /// its host collects it, and leaving the request waiting would let a second approval sign
    /// another; a restart may list it again.
    Store(String),
}

/// What an operator's close came to.
#[derive(Debug, PartialEq, Eq)]
pub struct Closed {
    /// The requests that were still waiting and expired with the window, or `None` when no
    /// window was open.
    pub expired_requests: Option<usize>,
    /// Whether the closed window was persisted.
    pub saved: Result<(), String>,
}

/// Why the window could not be opened.
#[derive(Debug, PartialEq, Eq)]
pub enum WindowError {
    /// The duration is outside 1 to [`MAX_WINDOW_SECS`] seconds — a `400`.
    Invalid(String),
    /// The window could not be persisted (ADR-0037 clause 9); it is as it was.
    Store(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Decision {
    /// The issued certificate, PEM, waiting for its host to collect it.
    Approved(String),
    Rejected,
}

/// The window and its requests as they persist (ADR-0037 clause 9): what an [`EnrolmentStore`]
/// keeps, and all it keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persisted {
    /// When the open window closes; absent while it is closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window_until_ms: Option<u64>,
    #[serde(default)]
    requests: Vec<PersistedRequest>,
}

/// One request as it persists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRequest {
    id: String,
    arrived_ms: u64,
    key_fingerprint: String,
    requester: Requester,
    csr_pem: String,
    /// The `instance_uid` the request arrived under, hex.
    instance_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<Decision>,
}

/// The enrolment's port (ADR-0006, ADR-0037): where the window and its queue persist. The
/// filesystem adapter ([`FsEnrolmentStore`](crate::fs::FsEnrolmentStore)) keeps them in
/// `enrolment.json`.
pub trait EnrolmentStore: Send + Sync {
    /// What was persisted last, `None` when nothing was.
    ///
    /// # Errors
    /// Returns an error when it exists but cannot be read.
    fn load(&self) -> Result<Option<Persisted>, String>;

    /// Persists the window and its requests, before the act that changed them is answered.
    ///
    /// # Errors
    /// Returns an error when it cannot be written.
    fn save(&self, persisted: &Persisted) -> Result<(), String>;
}

#[derive(Clone)]
struct Entry {
    pending: Pending,
    csr_pem: String,
    instance_uid: Vec<u8>,
    decision: Option<Decision>,
}

#[derive(Clone, Default)]
struct State {
    window_until_ms: Option<u64>,
    /// Keyed by the id, which is the key fingerprint.
    entries: BTreeMap<String, Entry>,
    /// The bootstrap certificates refused for their share in this window, each logged once
    /// (ADR-0046). Not persisted: a restart may log a certificate once more.
    over_share: std::collections::BTreeSet<CertId>,
}

impl State {
    fn persisted(&self) -> Persisted {
        Persisted {
            window_until_ms: self.window_until_ms,
            requests: self
                .entries
                .values()
                .map(|entry| PersistedRequest {
                    id: entry.pending.id.clone(),
                    arrived_ms: entry.pending.arrived_ms,
                    key_fingerprint: entry.pending.key_fingerprint.clone(),
                    requester: entry.pending.requester.clone(),
                    csr_pem: entry.csr_pem.clone(),
                    instance_uid: hex::encode(&entry.instance_uid),
                    decision: entry.decision.clone(),
                })
                .collect(),
        }
    }

    fn restored(persisted: Persisted) -> Result<Self, String> {
        let mut entries = BTreeMap::new();
        for request in persisted.requests {
            let instance_uid = hex::decode(&request.instance_uid)
                .map_err(|e| format!("request {:?}: invalid instance_uid: {e}", request.id))?;
            entries.insert(
                request.id.clone(),
                Entry {
                    pending: Pending {
                        id: request.id,
                        arrived_ms: request.arrived_ms,
                        key_fingerprint: request.key_fingerprint,
                        requester: request.requester,
                    },
                    csr_pem: request.csr_pem,
                    instance_uid,
                    decision: request.decision,
                },
            );
        }
        Ok(State {
            window_until_ms: persisted.window_until_ms,
            entries,
            over_share: std::collections::BTreeSet::new(),
        })
    }
}

/// The enrolment window and its queue.
pub struct Enrolment {
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    /// The most requests of one bootstrap certificate the queue holds (ADR-0046).
    max_per_bootstrap: usize,
    /// Where the window and its queue persist; `None` keeps them in memory, as a test does.
    store: Option<Box<dyn EnrolmentStore>>,
    changes: watch::Sender<u64>,
}

impl Enrolment {
    /// A window and queue held in memory only.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Enrolment {
            clock,
            state: Mutex::new(State::default()),
            max_per_bootstrap: DEFAULT_MAX_PENDING_PER_BOOTSTRAP,
            store: None,
            changes: watch::channel(0).0,
        }
    }

    /// Restores the window and its queue from `store` (ADR-0037 clause 9), and persists through it
    /// from here on. A window whose end has passed while the Server was down is closed, and its
    /// requests expire with it.
    ///
    /// # Errors
    /// Returns an error when what was persisted cannot be read, or the closed window cannot be
    /// written back.
    pub fn open_on(clock: Arc<dyn Clock>, store: Box<dyn EnrolmentStore>) -> Result<Self, String> {
        let mut state = match store.load()? {
            Some(persisted) => State::restored(persisted)?,
            None => State::default(),
        };
        let ended = state
            .window_until_ms
            .is_some_and(|until| clock.now_ms() >= until);
        if ended || (state.window_until_ms.is_none() && !state.entries.is_empty()) {
            state = State::default();
            store.save(&state.persisted())?;
        }
        Ok(Enrolment {
            clock,
            state: Mutex::new(state),
            max_per_bootstrap: DEFAULT_MAX_PENDING_PER_BOOTSTRAP,
            store: Some(store),
            changes: watch::channel(0).0,
        })
    }

    /// Holds at most `max` requests of one bootstrap certificate in the queue (ADR-0046), clamped
    /// to 1 to [`MAX_PENDING`]; the configuration refuses anything else at startup.
    #[must_use]
    pub fn with_max_pending_per_bootstrap(mut self, max: usize) -> Self {
        self.max_per_bootstrap = max.clamp(1, MAX_PENDING);
        self
    }

    /// Persists `state`, when a store is armed.
    fn save(&self, state: &State) -> Result<(), String> {
        match &self.store {
            Some(store) => store.save(&state.persisted()),
            None => Ok(()),
        }
    }

    /// Persists `state` where nothing waits on the answer, logging a failure.
    fn save_logged(&self, state: &State) {
        if let Err(e) = self.save(state) {
            tracing::warn!(error = %e, "cannot persist the enrolment window and its requests");
        }
    }

    /// Opens the window, or moves its end, to `secs` from now, persisted before it answers when
    /// it closes.
    ///
    /// # Errors
    /// [`WindowError::Invalid`] for a duration outside 1 to [`MAX_WINDOW_SECS`] seconds, and
    /// [`WindowError::Store`] when the window cannot be persisted.
    pub fn open(&self, secs: u64) -> Result<u64, WindowError> {
        if !(1..=MAX_WINDOW_SECS).contains(&secs) {
            return Err(WindowError::Invalid(format!(
                "open_for_secs must be between 1 and {MAX_WINDOW_SECS}, not {secs}"
            )));
        }
        let until = self.clock.now_ms() + secs * 1000;
        let mut state = self.state.lock().expect("enrolment lock");
        // A window that ran out unnoticed is closed first, its requests expiring with it: what is
        // opened now is a new window, not the old one's end moved.
        self.expire(&mut state);
        let mut opened = state.clone();
        opened.window_until_ms = Some(until);
        self.save(&opened).map_err(WindowError::Store)?;
        *state = opened;
        drop(state);
        self.changed();
        Ok(until)
    }

    /// Closes the window now; every pending request expires. It is closed in memory whatever
    /// happens to the write, the safe direction, and written every time, so a close whose write
    /// failed is written by the next. Answers how many requests expired with it when a window was
    /// open — one that ran out is closed by then — and whether the closed window was persisted:
    /// when it was not, a restart may find it open until its end.
    pub fn close(&self) -> Closed {
        let mut state = self.state.lock().expect("enrolment lock");
        let expired_requests = self.expire(&mut state).map(|_| {
            state
                .entries
                .values()
                .filter(|entry| entry.decision.is_none())
                .count()
        });
        state.window_until_ms = None;
        state.entries.clear();
        state.over_share.clear();
        let saved = self.save(&state);
        drop(state);
        self.changed();
        Closed {
            expired_requests,
            saved,
        }
    }

    /// When the open window closes, or `None` while it is closed.
    pub fn window(&self) -> Option<u64> {
        let mut state = self.state.lock().expect("enrolment lock");
        self.expire(&mut state)
    }

    /// Whether a bootstrap certificate may be admitted now.
    pub fn is_open(&self) -> bool {
        self.window().is_some()
    }

    /// Takes in a request, or answers it once it has been decided.
    pub fn submit(&self, request: Request, requester: Requester) -> Submitted {
        let mut state = self.state.lock().expect("enrolment lock");
        if self.expire(&mut state).is_none() {
            return Submitted::Closed;
        }
        if let Some(entry) = state.entries.get(&request.key_fingerprint) {
            return answered(entry);
        }
        // Only the requests that wait for an operator hold a place and a share: a decided one
        // stays until its host collects it or the window closes, and holds neither (ADR-0046).
        let waiting = || {
            state
                .entries
                .values()
                .filter(|entry| entry.decision.is_none())
        };
        if waiting().count() >= MAX_PENDING {
            return Submitted::Full;
        }
        // A re-sent request has its entry and was answered above; only a new one is counted
        // against its bootstrap certificate's share (ADR-0046).
        let held = waiting()
            .filter(|entry| entry.pending.requester.bootstrap == requester.bootstrap)
            .count();
        if held >= self.max_per_bootstrap {
            let first = state.over_share.insert(requester.bootstrap.clone());
            return Submitted::OverShare { first };
        }
        let id = request.key_fingerprint.clone();
        let key = id.clone();
        let pending = Pending {
            id: id.clone(),
            arrived_ms: self.clock.now_ms(),
            key_fingerprint: request.key_fingerprint,
            requester,
        };
        state.entries.insert(
            id,
            Entry {
                pending,
                csr_pem: request.csr_pem,
                instance_uid: request.instance_uid,
                decision: None,
            },
        );
        if let Err(e) = self.save(&state) {
            // Not taken in: the host is told to come back, as it is for a full queue.
            tracing::warn!(error = %e, "cannot persist an enrolment request");
            state.entries.remove(&key);
            return Submitted::Full;
        }
        drop(state);
        self.changed();
        Submitted::Waiting { new: true }
    }

    /// What the request for `key` has come to, without taking one in: `None` when the window is
    /// closed or the queue holds no such request — withdrawn, expired or never filed. What a push
    /// to a waiting connection reads; only an enrolment message files a request.
    pub fn answer(&self, key: &str) -> Option<Submitted> {
        let mut state = self.state.lock().expect("enrolment lock");
        self.expire(&mut state)?;
        state.entries.get(key).map(answered)
    }

    /// The requests waiting for an operator, oldest first.
    pub fn pending(&self) -> Vec<Pending> {
        let mut state = self.state.lock().expect("enrolment lock");
        self.expire(&mut state);
        let mut pending: Vec<Pending> = state
            .entries
            .values()
            .filter(|entry| entry.decision.is_none())
            .map(|entry| entry.pending.clone())
            .collect();
        pending.sort_by_key(|p| p.arrived_ms);
        pending
    }

    /// Approves one request: the CA signs it, and the certificate waits for the Agent to collect.
    ///
    /// # Errors
    /// Returns [`DecisionError::NotFound`] for an unknown, decided or expired id,
    /// [`DecisionError::Revoked`] when the request's bootstrap certificate is revoked,
    /// [`DecisionError::Subject`] when its subject cannot be carried into the host certificate
    /// (ADR-0036 clause 3), and [`DecisionError::Sign`] when the CA refuses the request.
    /// Answers what was signed, and the `instance_uid` the request arrived under, for the register.
    /// `record` keeps what was signed before the host can collect it (ADR-0021 clause 33); a
    /// failure there leaves the request pending. Once it is recorded the approval stands, persisted
    /// or not ([`DecisionError::Store`]).
    ///
    /// The bootstrap certificate the request came with is checked against `revoked` under the same
    /// lock that signs, so a revocation that lands before the approval always wins (ADR-0021
    /// clause 35); such a request is withdrawn and answered [`DecisionError::Revoked`].
    pub fn approve(
        &self,
        id: &str,
        signer: &dyn CertificateSigner,
        host: &str,
        record: &Record<'_>,
        revoked: &dyn Fn(&CertId) -> bool,
    ) -> Result<(), DecisionError> {
        let mut state = self.state.lock().expect("enrolment lock");
        self.expire(&mut state);
        let entry = state
            .entries
            .get_mut(id)
            .filter(|entry| entry.decision.is_none())
            .ok_or(DecisionError::NotFound)?;
        if revoked(&entry.pending.requester.bootstrap) {
            state.entries.remove(id);
            self.save_logged(&state);
            drop(state);
            self.changed();
            return Err(DecisionError::Revoked);
        }
        // The bootstrap certificate's values, under the rules they were issued by, and never the
        // request's (ADR-0036 clauses 2 and 3).
        let subject = entry.pending.requester.carried.clone().map_err(|e| {
            DecisionError::Subject(format!(
                "the bootstrap certificate's subject cannot be carried into a host \
                     certificate: {e}"
            ))
        })?;
        let signed = signer
            .sign(&entry.csr_pem, host, &subject)
            .map_err(DecisionError::Sign)?;
        record(&signed, &entry.instance_uid).map_err(DecisionError::Sign)?;
        entry.decision = Some(Decision::Approved(signed.pem));
        // Persisted before it is answered, the certificate included, so a restart before the host
        // collects it hands it over all the same (ADR-0037 clause 9). A failed write leaves the
        // approval standing in memory, where the next write persists it: the certificate exists.
        let saved = self.save(&state);
        drop(state);
        self.changed();
        saved.map_err(DecisionError::Store)
    }

    /// Rejects one request.
    ///
    /// # Errors
    /// Returns [`DecisionError::NotFound`] for an unknown, decided or expired id.
    pub fn reject(&self, id: &str) -> Result<(), DecisionError> {
        let mut state = self.state.lock().expect("enrolment lock");
        self.expire(&mut state);
        let entry = state
            .entries
            .get_mut(id)
            .filter(|entry| entry.decision.is_none())
            .ok_or(DecisionError::NotFound)?;
        entry.decision = Some(Decision::Rejected);
        if let Err(e) = self.save(&state) {
            if let Some(entry) = state.entries.get_mut(id) {
                entry.decision = None;
            }
            return Err(DecisionError::Store(e));
        }
        drop(state);
        self.changed();
        Ok(())
    }

    /// Withdraws every waiting request whose bootstrap certificate `revoked` names, and answers how
    /// many: a revoked certificate opens nothing, a request it carried included (ADR-0021
    /// clause 35). A decided request is left: an approved one was signed and recorded already, and
    /// dropping it would revoke nothing — the connection of this certificate is refused, and only
    /// one holding the same key can collect it.
    pub fn withdraw(&self, revoked: &dyn Fn(&CertId) -> bool) -> usize {
        let mut state = self.state.lock().expect("enrolment lock");
        let before = state.entries.len();
        state.entries.retain(|_, entry| {
            entry.decision.is_some() || !revoked(&entry.pending.requester.bootstrap)
        });
        let withdrawn = before - state.entries.len();
        if withdrawn > 0 {
            self.save_logged(&state);
        }
        drop(state);
        if withdrawn > 0 {
            self.changed();
        }
        withdrawn
    }

    /// Whether the request for `key` was rejected — its connection then ends.
    pub fn is_rejected(&self, key: &str) -> bool {
        let state = self.state.lock().expect("enrolment lock");
        matches!(
            state
                .entries
                .get(key)
                .and_then(|entry| entry.decision.as_ref()),
            Some(Decision::Rejected)
        )
    }

    /// Fires whenever the window or a request changes, for the connections waiting on them.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// The window's end if it is still open; a window that has run out is closed here, and its
    /// requests expire with it.
    fn expire(&self, state: &mut State) -> Option<u64> {
        let until = state.window_until_ms?;
        if self.clock.now_ms() < until {
            return Some(until);
        }
        state.window_until_ms = None;
        state.over_share.clear();
        let expired = state
            .entries
            .values()
            .filter(|entry| entry.decision.is_none())
            .count();
        state.entries.clear();
        self.save_logged(state);
        tracing::info!(
            event = "enrolment.window",
            outcome = "expired",
            until_ms = until,
            expired_requests = expired,
            "the enrolment window ran out"
        );
        self.changes.send_modify(|rev| *rev += 1);
        None
    }

    fn changed(&self) {
        self.changes.send_modify(|rev| *rev += 1);
    }
}

/// What a request already in the queue is answered.
fn answered(entry: &Entry) -> Submitted {
    match &entry.decision {
        None => Submitted::Waiting { new: false },
        Some(Decision::Approved(cert)) => Submitted::Issued(cert.clone()),
        Some(Decision::Rejected) => Submitted::Rejected,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Manual(AtomicU64);

    impl Clock for Manual {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct Echo;

    impl CertificateSigner for Echo {
        fn sign(
            &self,
            csr_pem: &str,
            _host: &str,
            subject: &SubjectValues,
        ) -> Result<Signed, String> {
            Ok(Signed {
                pem: format!("issued for {csr_pem}"),
                facts: crate::revocation::Facts {
                    id: crate::revocation::CertId::new(b"test CA", "1"),
                    issuer_name: "CN=test CA".to_string(),
                    subject: String::new(),
                    key_fingerprint: String::new(),
                    not_after_ms: u64::MAX,
                    host: None,
                    subject_values: subject.clone(),
                },
            })
        }

        fn check_claims(&self, _csr_pem: &str, _sender: &[u8]) -> Result<(), String> {
            Ok(())
        }

        fn renewal_proof(
            &self,
            _csr_pem: &str,
        ) -> Result<Option<crate::revocation::Facts>, String> {
            Ok(None)
        }

        fn bootstrap_proof_id(
            &self,
            _csr_pem: &str,
        ) -> Result<Option<crate::revocation::CertId>, String> {
            Ok(None)
        }
    }

    fn enrolment() -> (Enrolment, Arc<Manual>) {
        let clock = Arc::new(Manual(AtomicU64::new(1_000_000)));
        (Enrolment::new(clock.clone()), clock)
    }

    fn request(key: &str) -> Request {
        Request {
            csr_pem: format!("csr-{key}"),
            subject: "CN=edge-01".to_string(),
            key_fingerprint: key.to_string(),
            instance_uid: vec![7; 16],
        }
    }

    pub(crate) fn requester() -> Requester {
        Requester {
            bootstrap_subject: "CN=bootstrap".to_string(),
            carried: Ok(SubjectValues::default()),
            bootstrap_fingerprint: "bf".to_string(),
            bootstrap: CertId::new(b"bootstrap CA", "b5"),
            peer: None,
            gateway: None,
        }
    }

    /// The store as memory: what an Enrolment opened on a clone of it reads is what the first one
    /// persisted — a restart without a filesystem.
    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<Option<Persisted>>>);

    impl EnrolmentStore for Memory {
        fn load(&self) -> Result<Option<Persisted>, String> {
            Ok(self.0.lock().expect("memory").clone())
        }
        fn save(&self, persisted: &Persisted) -> Result<(), String> {
            *self.0.lock().expect("memory") = Some(persisted.clone());
            Ok(())
        }
    }

    /// A store whose writes fail while it is told to, and that keeps the last write that did not.
    #[derive(Clone, Default)]
    struct Failing {
        failing: Arc<std::sync::atomic::AtomicBool>,
        saved: Arc<Mutex<Option<Persisted>>>,
    }

    impl Failing {
        fn fail(&self, failing: bool) {
            self.failing.store(failing, Ordering::SeqCst);
        }
    }

    impl EnrolmentStore for Failing {
        fn load(&self) -> Result<Option<Persisted>, String> {
            Ok(None)
        }
        fn save(&self, persisted: &Persisted) -> Result<(), String> {
            if self.failing.load(Ordering::SeqCst) {
                return Err("the disk is full".to_string());
            }
            *self.saved.lock().expect("saved") = Some(persisted.clone());
            Ok(())
        }
    }

    /// An enrolment over a [`Failing`] store, and the store.
    fn failing() -> (Enrolment, Failing) {
        let clock = Arc::new(Manual(AtomicU64::new(1_000_000)));
        let store = Failing::default();
        let enrolment = Enrolment::open_on(clock, Box::new(store.clone())).expect("open");
        (enrolment, store)
    }

    /// An approved enrolment survives a restart: the window stays open until its end, a waiting
    /// request still waits, and the approved one hands its host the certificate it was issued.
    /// Verifies: ADR-0037
    #[test]
    fn an_approved_enrolment_survives_a_restart() {
        let clock = Arc::new(Manual(AtomicU64::new(1_000_000)));
        let memory = Memory::default();
        let until = {
            let enrolment =
                Enrolment::open_on(clock.clone(), Box::new(memory.clone())).expect("open");
            let until = enrolment.open(600).expect("open the window");
            enrolment.submit(request("a"), requester());
            enrolment.submit(request("b"), requester());
            enrolment.submit(request("c"), requester());
            enrolment
                .approve("a", &Echo, "host", &|_, _| Ok(()), &|_| false)
                .expect("approve");
            enrolment.reject("c").expect("reject");
            until
        };

        clock.0.fetch_add(60_000, Ordering::SeqCst);
        let restarted =
            Enrolment::open_on(clock.clone(), Box::new(memory.clone())).expect("reopen");
        assert_eq!(restarted.window(), Some(until), "open until its end");
        assert_eq!(
            restarted.submit(request("a"), requester()),
            Submitted::Issued("issued for csr-a".to_string()),
            "the approved certificate is handed over after the restart"
        );
        assert_eq!(
            restarted
                .pending()
                .into_iter()
                .map(|p| (p.id, p.requester))
                .collect::<Vec<_>>(),
            [("b".to_string(), requester())]
        );
        assert!(restarted.is_rejected("c"));
        restarted
            .approve("b", &Echo, "host", &|_, _| Ok(()), &|_| false)
            .expect("the waiting request can still be approved");
    }

    /// A window whose end passed while the Server was down is closed when it is loaded, and its
    /// requests — an approved one included — expire with it.
    /// Verifies: ADR-0037
    #[test]
    fn a_window_whose_end_passed_while_down_is_closed_on_load() {
        let clock = Arc::new(Manual(AtomicU64::new(1_000_000)));
        let memory = Memory::default();
        {
            let enrolment =
                Enrolment::open_on(clock.clone(), Box::new(memory.clone())).expect("open");
            enrolment.open(60).expect("open the window");
            enrolment.submit(request("a"), requester());
            enrolment
                .approve("a", &Echo, "host", &|_, _| Ok(()), &|_| false)
                .expect("approve");
        }
        clock.0.fetch_add(61_000, Ordering::SeqCst);
        let restarted =
            Enrolment::open_on(clock.clone(), Box::new(memory.clone())).expect("reopen");
        assert_eq!(restarted.window(), None);
        assert_eq!(
            memory.load().expect("load"),
            Some(Persisted::default()),
            "closed on disk too"
        );
        restarted.open(60).expect("open again");
        assert_eq!(
            restarted.submit(request("a"), requester()),
            Submitted::Waiting { new: true },
            "the host enrols again in the next window"
        );
    }

    /// An act whose result cannot be persisted is not taken: the window stays as it was, and a
    /// rejection leaves the request waiting. An approval, whose certificate is signed once it is
    /// recorded, is the exception: `an_approval_that_cannot_be_persisted_signs_nothing_twice`.
    /// Verifies: ADR-0037
    #[test]
    fn an_act_that_cannot_be_persisted_changes_nothing() {
        let (enrolment, store) = failing();
        enrolment.open(600).expect("open the window");
        enrolment.submit(request("a"), requester());
        store.fail(true);
        assert!(matches!(enrolment.open(60), Err(WindowError::Store(_))));
        assert_eq!(
            enrolment.submit(request("b"), requester()),
            Submitted::Full,
            "a request that cannot be kept is not taken in"
        );
        assert!(matches!(
            enrolment.reject("a"),
            Err(DecisionError::Store(_))
        ));
        assert_eq!(enrolment.pending().len(), 1, "the request still waits");
        assert!(enrolment.close().saved.is_err());
        assert!(!enrolment.is_open(), "closed all the same");
    }

    /// Verifies: ADR-0021
    #[test]
    fn the_window_is_closed_by_default_and_bounded() {
        let (enrolment, clock) = enrolment();
        assert!(!enrolment.is_open());
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Closed
        );
        assert!(enrolment.open(0).is_err());
        assert!(enrolment.open(MAX_WINDOW_SECS + 1).is_err());
        enrolment.open(60).expect("open");
        assert!(enrolment.is_open());
        clock.0.fetch_add(60_000, Ordering::SeqCst);
        assert!(!enrolment.is_open(), "the window closes on its own");
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_request_waits_for_an_operator_and_is_answered_once_decided() {
        let (enrolment, _) = enrolment();
        enrolment.open(600).expect("open");
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: true }
        );
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: false },
            "a re-sent request joins its own entry"
        );
        assert_eq!(enrolment.pending().len(), 1);
        enrolment
            .approve("a", &Echo, "host", &|_, _| Ok(()), &|_| false)
            .expect("approve");
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Issued("issued for csr-a".to_string())
        );
        assert!(
            enrolment.pending().is_empty(),
            "a decided request is no longer pending"
        );
        assert_eq!(
            enrolment.approve("a", &Echo, "host", &|_, _| Ok(()), &|_| false),
            Err(DecisionError::NotFound)
        );

        enrolment.submit(request("b"), requester());
        enrolment.reject("b").expect("reject");
        assert_eq!(
            enrolment.submit(request("b"), requester()),
            Submitted::Rejected
        );
        assert_eq!(enrolment.reject("unknown"), Err(DecisionError::NotFound));
    }

    /// Verifies: ADR-0021
    #[test]
    fn closing_the_window_expires_every_request() {
        let (enrolment, clock) = enrolment();
        enrolment.open(60).expect("open");
        enrolment.submit(request("a"), requester());
        enrolment.close().saved.expect("close");
        assert!(enrolment.pending().is_empty());
        enrolment.open(60).expect("open");
        enrolment.submit(request("b"), requester());
        clock.0.fetch_add(61_000, Ordering::SeqCst);
        assert_eq!(
            enrolment.approve("b", &Echo, "host", &|_, _| Ok(()), &|_| false),
            Err(DecisionError::NotFound)
        );
    }

    /// Verifies: ADR-0021
    #[test]
    fn the_queue_is_bounded() {
        let (enrolment, _) = enrolment();
        enrolment.open(600).expect("open");
        // One bootstrap certificate per request, so only the queue's own bound applies (ADR-0046).
        for n in 0..MAX_PENDING {
            let one_each = Requester {
                bootstrap: CertId::new(b"bootstrap CA", &format!("{n:x}")),
                ..requester()
            };
            assert_eq!(
                enrolment.submit(request(&n.to_string()), one_each),
                Submitted::Waiting { new: true }
            );
        }
        assert_eq!(
            enrolment.submit(request("one more"), requester()),
            Submitted::Full
        );
    }

    /// The requests of one bootstrap certificate hold at most their share of the queue; a re-sent
    /// one joins its entry all the same, another certificate's is still queued, and the first
    /// refusal of a certificate in a window is the one marked for the log.
    /// Verifies: ADR-0046
    #[test]
    fn one_bootstrap_certificate_holds_at_most_its_share() {
        let (enrolment, _) = enrolment();
        let enrolment = enrolment.with_max_pending_per_bootstrap(2);
        enrolment.open(600).expect("open");
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: true }
        );
        assert_eq!(
            enrolment.submit(request("b"), requester()),
            Submitted::Waiting { new: true }
        );
        assert_eq!(
            enrolment.submit(request("c"), requester()),
            Submitted::OverShare { first: true }
        );
        assert_eq!(
            enrolment.submit(request("d"), requester()),
            Submitted::OverShare { first: false },
            "logged once per certificate and window"
        );
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: false },
            "a re-sent request is never refused"
        );
        let other = Requester {
            bootstrap: CertId::new(b"bootstrap CA", "c6"),
            ..requester()
        };
        assert_eq!(
            enrolment.submit(request("e"), other),
            Submitted::Waiting { new: true }
        );
        assert_eq!(enrolment.pending().len(), 3);

        enrolment.close().saved.expect("close");
        enrolment.open(600).expect("open again");
        enrolment.submit(request("a"), requester());
        enrolment.submit(request("b"), requester());
        assert_eq!(
            enrolment.submit(request("c"), requester()),
            Submitted::OverShare { first: true },
            "a new window logs again"
        );
    }

    /// The default share is a quarter of the queue.
    /// Verifies: ADR-0046
    #[test]
    fn the_default_share_is_a_quarter_of_the_queue() {
        assert_eq!(DEFAULT_MAX_PENDING_PER_BOOTSTRAP, 256);
        assert_eq!(DEFAULT_MAX_PENDING_PER_BOOTSTRAP * 4, MAX_PENDING);
    }

    /// A signer that fails the test if it is ever asked.
    struct Never;

    impl CertificateSigner for Never {
        fn sign(
            &self,
            _csr_pem: &str,
            _host: &str,
            _subject: &SubjectValues,
        ) -> Result<Signed, String> {
            panic!("a request that must not be signed reached the signer");
        }

        fn check_claims(&self, _csr_pem: &str, _sender: &[u8]) -> Result<(), String> {
            Ok(())
        }

        fn renewal_proof(
            &self,
            _csr_pem: &str,
        ) -> Result<Option<crate::revocation::Facts>, String> {
            Ok(None)
        }

        fn bootstrap_proof_id(
            &self,
            _csr_pem: &str,
        ) -> Result<Option<crate::revocation::CertId>, String> {
            Ok(None)
        }
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_request_whose_bootstrap_certificate_is_revoked_is_withdrawn_unsigned() {
        let (enrolment, _clock) = enrolment();
        enrolment.open(600).expect("open");
        enrolment.submit(request("a"), requester());
        let bootstrap = requester().bootstrap;
        let revoked = |id: &CertId| *id == bootstrap;
        assert_eq!(
            enrolment.approve("a", &Never, "host", &|_, _| Ok(()), &revoked),
            Err(DecisionError::Revoked)
        );
        assert!(enrolment.pending().is_empty(), "the request is withdrawn");
        assert_eq!(
            enrolment.approve("a", &Never, "host", &|_, _| Ok(()), &revoked),
            Err(DecisionError::NotFound),
            "a second approval finds nothing to sign"
        );
    }

    /// An approval signs the values the bootstrap certificate carries, and one whose subject breaks
    /// the rules signs nothing, says why, and leaves the request for the operator to reject.
    /// Verifies: ADR-0036
    #[test]
    fn an_approval_carries_the_bootstrap_values_or_signs_nothing() {
        let (enrolment, _clock) = enrolment();
        enrolment.open(600).expect("open");
        let values = SubjectValues {
            country: "AT".to_string(),
            organization: "Kunde GmbH".to_string(),
            ..SubjectValues::default()
        };
        let carrying = Requester {
            carried: Ok(values.clone()),
            ..requester()
        };
        enrolment.submit(request("good"), carrying);
        let signed = std::cell::RefCell::new(None);
        enrolment
            .approve(
                "good",
                &Echo,
                "host",
                &|issued, _| {
                    *signed.borrow_mut() = Some(issued.facts.subject_values.clone());
                    Ok(())
                },
                &|_| false,
            )
            .expect("approve");
        assert_eq!(signed.into_inner(), Some(values));

        let malformed = Requester {
            carried: Err("organizational_unit appears more than once".to_string()),
            ..requester()
        };
        enrolment.submit(request("bad"), malformed);
        let refused = enrolment.approve("bad", &Never, "host", &|_, _| Ok(()), &|_| false);
        assert!(
            matches!(&refused, Err(DecisionError::Subject(e)) if e.contains("organizational_unit")),
            "{refused:?}"
        );
        assert_eq!(enrolment.pending().len(), 1, "the request still waits");
    }

    /// Verifies: ADR-0021
    #[test]
    fn withdrawing_takes_only_the_waiting_requests_of_a_revoked_certificate() {
        let (enrolment, _clock) = enrolment();
        enrolment.open(600).expect("open");
        let other = Requester {
            bootstrap: CertId::new(b"bootstrap CA", "c6"),
            ..requester()
        };
        enrolment.submit(request("revoked-waiting"), requester());
        enrolment.submit(request("revoked-decided"), requester());
        enrolment.submit(request("other"), other);
        enrolment
            .approve("revoked-decided", &Echo, "host", &|_, _| Ok(()), &|_| false)
            .expect("approve");
        let bootstrap = requester().bootstrap;
        assert_eq!(enrolment.withdraw(&|id| *id == bootstrap), 1);
        let left: Vec<String> = enrolment.pending().into_iter().map(|p| p.id).collect();
        assert_eq!(
            left,
            ["other"],
            "the other certificate's request still waits"
        );
        assert!(
            matches!(
                enrolment.submit(request("revoked-decided"), requester()),
                Submitted::Issued(_)
            ),
            "a decided request is left to its connection, which the revocation refuses"
        );
    }

    /// A window that ran out while nothing looked at it is closed before it is opened again: its
    /// requests expire with it, and the new window starts with an empty queue.
    /// Verifies: ADR-0021
    #[test]
    fn a_window_that_ran_out_unnoticed_is_closed_before_it_opens_again() {
        let (enrolment, clock) = enrolment();
        let enrolment = enrolment.with_max_pending_per_bootstrap(1);
        enrolment.open(60).expect("open");
        enrolment.submit(request("a"), requester());
        enrolment.submit(request("b"), requester());
        clock.0.fetch_add(61_000, Ordering::SeqCst);
        // Nothing reads the window between its end and the next opening.
        enrolment.open(60).expect("open again");
        assert!(
            enrolment.pending().is_empty(),
            "the requests of the window that ran out carried into the new one"
        );
        assert!(
            matches!(
                enrolment.submit(request("c"), requester()),
                Submitted::Waiting { .. }
            ),
            "the old window's request still held the bootstrap certificate's share"
        );
        assert_eq!(
            enrolment.submit(request("d"), requester()),
            Submitted::OverShare { first: true },
            "the old window's refusal of the share carried into the new one"
        );
    }

    /// Only a request that waits for an operator holds a place in the queue and a share of its
    /// bootstrap certificate: one an operator decided does not, so a site that enrols more hosts
    /// than the share in one window goes on once some are approved (ADR-0046).
    /// Verifies: ADR-0046
    #[test]
    fn a_decided_request_holds_no_share_and_no_place() {
        let (enrolment, _) = enrolment();
        let enrolment = enrolment.with_max_pending_per_bootstrap(2);
        enrolment.open(600).expect("open");
        enrolment.submit(request("a"), requester());
        enrolment.submit(request("b"), requester());
        enrolment
            .approve("a", &Echo, "host", &|_, _| Ok(()), &|_| false)
            .expect("approve");
        enrolment.reject("b").expect("reject");
        assert!(matches!(
            enrolment.submit(request("c"), requester()),
            Submitted::Waiting { .. }
        ));
        assert!(matches!(
            enrolment.submit(request("d"), requester()),
            Submitted::Waiting { .. }
        ));
        assert_eq!(
            enrolment.submit(request("e"), requester()),
            Submitted::OverShare { first: true },
            "two waiting requests hold the share"
        );

        let (enrolment, _) = self::enrolment();
        enrolment.open(600).expect("open");
        let one_each = |n: usize| Requester {
            bootstrap: CertId::new(b"bootstrap CA", &format!("{n:x}")),
            ..requester()
        };
        for n in 0..MAX_PENDING {
            enrolment.submit(request(&n.to_string()), one_each(n));
        }
        enrolment.reject("0").expect("reject");
        assert!(
            matches!(
                enrolment.submit(request("one more"), one_each(MAX_PENDING)),
                Submitted::Waiting { .. }
            ),
            "a decided request frees its place in the queue"
        );
        assert_eq!(
            enrolment.submit(request("and another"), one_each(MAX_PENDING + 1)),
            Submitted::Full
        );
    }

    /// An approval whose decision cannot be persisted stands all the same: its certificate was
    /// signed and recorded, so the request is not left waiting for a second approval that would
    /// sign another, and its host collects the one that was signed.
    /// Verifies: ADR-0021, ADR-0037
    #[test]
    fn an_approval_that_cannot_be_persisted_signs_nothing_twice() {
        let (enrolment, store) = failing();
        enrolment.open(600).expect("open the window");
        enrolment.submit(request("a"), requester());
        store.fail(true);
        let recorded = AtomicU64::new(0);
        let record = |_: &Signed, _: &[u8]| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        assert!(matches!(
            enrolment.approve("a", &Echo, "host", &record, &|_| false),
            Err(DecisionError::Store(_))
        ));
        assert_eq!(
            enrolment.approve("a", &Echo, "host", &record, &|_| false),
            Err(DecisionError::NotFound),
            "the request was approved once already"
        );
        assert_eq!(recorded.load(Ordering::SeqCst), 1, "one certificate signed");
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Issued("issued for csr-a".to_string()),
            "its host collects the certificate that was signed"
        );
    }

    /// `submit` says whether it took the request in, decided under the lock that takes it: the
    /// first submission of a key is new and a re-sent one is not, and a request filed anew after
    /// it was withdrawn is new again.
    /// Verifies: ADR-0021
    #[test]
    fn a_submission_says_whether_it_took_the_request_in() {
        let (enrolment, _) = enrolment();
        enrolment.open(600).expect("open");
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: true }
        );
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: false }
        );
        assert_eq!(enrolment.withdraw(&|_| true), 1);
        assert_eq!(
            enrolment.submit(request("a"), requester()),
            Submitted::Waiting { new: true },
            "withdrawn, then filed anew"
        );
    }

    /// Answering a request reads it and never takes one in: a request the queue does not hold is
    /// answered nothing, and stays out of the queue.
    /// Verifies: ADR-0021
    #[test]
    fn answering_a_request_never_takes_one_in() {
        let (enrolment, clock) = enrolment();
        assert_eq!(enrolment.answer("a"), None, "no window");
        enrolment.open(60).expect("open");
        assert_eq!(enrolment.answer("a"), None);
        assert!(enrolment.pending().is_empty());
        enrolment.submit(request("a"), requester());
        assert_eq!(
            enrolment.answer("a"),
            Some(Submitted::Waiting { new: false })
        );
        enrolment
            .approve("a", &Echo, "host", &|_, _| Ok(()), &|_| false)
            .expect("approve");
        assert_eq!(
            enrolment.answer("a"),
            Some(Submitted::Issued("issued for csr-a".to_string()))
        );
        clock.0.fetch_add(61_000, Ordering::SeqCst);
        assert_eq!(enrolment.answer("a"), None, "the window ran out");
    }

    /// Closing answers how many requests were still waiting, counted under the lock that closes,
    /// and no count at all when no window was open — one that ran out included.
    /// Verifies: ADR-0021
    #[test]
    fn closing_says_what_expired_and_only_when_a_window_was_open() {
        let (enrolment, clock) = enrolment();
        assert_eq!(
            enrolment.close().expired_requests,
            None,
            "closed by default"
        );
        enrolment.open(60).expect("open");
        enrolment.submit(request("a"), requester());
        enrolment.submit(request("b"), requester());
        enrolment.reject("b").expect("reject");
        assert_eq!(
            enrolment.close(),
            Closed {
                expired_requests: Some(1),
                saved: Ok(())
            }
        );
        assert_eq!(enrolment.close().expired_requests, None, "closed already");
        enrolment.open(60).expect("open");
        clock.0.fetch_add(61_000, Ordering::SeqCst);
        assert_eq!(
            enrolment.close().expired_requests,
            None,
            "it ran out before"
        );
    }

    /// A close whose write failed is written by the next close: the window is closed in memory
    /// already, and the store must not be left saying it is open, or a restart reopens it.
    /// Verifies: ADR-0037
    #[test]
    fn a_close_that_could_not_be_persisted_is_persisted_by_the_next() {
        let (enrolment, store) = failing();
        enrolment.open(600).expect("open the window");
        store.fail(true);
        assert!(enrolment.close().saved.is_err());
        store.fail(false);
        assert!(enrolment.close().saved.is_ok());
        let saved = store.saved.lock().expect("saved").clone().expect("written");
        assert_eq!(
            saved.window_until_ms, None,
            "the store still says the window is open"
        );
    }
}
