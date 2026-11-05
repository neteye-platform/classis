//! What the Server signed, and what it no longer trusts (ADR-0021).
//!
//! The **register** holds every certificate the client CA signed, with the certificate it renewed
//! as its predecessor, so a revocation reaches every renewal made after the certificate it names.
//! An entry stays while it, or a certificate descended from it, is still valid. The **list** holds
//! revoked certificates, by the CA that issued them and serial. Both persist through a
//! [`LedgerStore`]; a change is written before it is answered, and every revocation is announced,
//! so an open session can end the moment the certificate that admitted it is revoked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::fleet::Clock;

/// The revocations one list holds at most (ADR-0021 clause 37).
pub const MAX_REVOCATIONS: usize = 100_000;

/// The certificates the register holds at most (ADR-0021 clause 33).
pub const MAX_ISSUED: usize = 100_000;

/// The certificates the register holds at most in one chain — below one root, the first
/// certificate a chain renews from: enough for a Gateway's downstream Agents, few enough that one
/// member cannot fill the register (ADR-0021 clause 33).
pub const MAX_DESCENDANTS_PER_ROOT: usize = 10_000;

/// The room the register keeps for enrolments: a renewal is refused once fewer are left, so
/// renewals alone cannot shut out a new host (ADR-0021 clause 33).
pub const ENROLMENT_RESERVE: usize = 1_000;

/// A certificate by its issuer and serial: the issuer as the SHA-256 of its DER-encoded name, hex,
/// so no text form of a name can fail to match; the serial as lowercase hex without separators or
/// leading zeros.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CertId {
    pub issuer: String,
    pub serial: String,
}

impl CertId {
    #[must_use]
    pub fn new(issuer_der: &[u8], serial: &str) -> Self {
        CertId {
            issuer: name_hash(issuer_der),
            serial: normalize_serial(serial),
        }
    }
}

/// The SHA-256 of a DER-encoded name, hex.
#[must_use]
pub fn name_hash(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// The most hex digits a serial has: RFC 5280's 20 octets.
pub const MAX_SERIAL_HEX: usize = 40;

/// `00:0A:1b` and `a1b` are one serial.
#[must_use]
pub fn normalize_serial(serial: &str) -> String {
    let hex: String = serial
        .chars()
        .filter(|c| !matches!(c, ':' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// A CA whose certificates can be revoked: the client CA or the bootstrap CA (ADR-0021 clause 34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// `client` or `bootstrap` — what an operator names.
    pub role: String,
    /// The SHA-256 of its DER-encoded subject, hex.
    pub subject: String,
    /// Its subject as text, for the operator to read.
    pub name: String,
}

/// What a signed certificate says about itself — what the signer reports back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub id: CertId,
    /// The issuer's name as text, for the operator to read.
    pub issuer_name: String,
    pub subject: String,
    /// SHA-256 of the certified public key, hex.
    pub key_fingerprint: String,
    /// Milliseconds since the Unix epoch.
    pub not_after_ms: u64,
    /// The host the certificate was issued to (ADR-0021 clause 7) — the stable identity a host
    /// keeps across renewals and re-keys; `None` for a certificate an operator provisioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The values of its subject a Host carries (ADR-0035 clause 1); empty when it has none.
    #[serde(default, skip_serializing_if = "SubjectValues::is_empty")]
    pub subject_values: SubjectValues,
}

/// The values of a client certificate's subject a Host carries into the effective description of
/// the Agents that arrive over it directly (ADR-0035 clauses 1 and 3). Each holds the first value
/// of its attribute in the subject; empty when the subject has none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectValues {
    /// `C`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    /// `ST`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    /// `L`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub locality: String,
    /// `O`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organization: String,
    /// `OU`, which the description calls the site.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organizational_unit: String,
    /// `organizationIdentifier` (2.5.4.97).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organization_identifier: String,
}

impl SubjectValues {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes().next().is_none()
    }

    /// The `fleet.host.*` attributes these values are (ADR-0035 clause 3), the empty ones left
    /// out.
    pub fn attributes(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("fleet.host.country", self.country.as_str()),
            ("fleet.host.state", self.state.as_str()),
            ("fleet.host.locality", self.locality.as_str()),
            ("fleet.host.organization", self.organization.as_str()),
            ("fleet.host.site", self.organizational_unit.as_str()),
            (
                "fleet.host.organization_id",
                self.organization_identifier.as_str(),
            ),
        ]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
    }
}

/// The certificate a connection presented: what it renews, and the host it speaks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presented {
    pub id: CertId,
    pub host: Option<String>,
    /// Its subject's values, which a Host made at its first report carries (ADR-0035 clause 1).
    pub subject_values: SubjectValues,
    /// Its `not_after`: every admission moves its Host's valid until forward to it (ADR-0047
    /// clause 1).
    pub not_after_ms: u64,
}

/// A Host: what a client certificate's host id names (ADR-0021 clause 7, ADR-0035 clause 1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    /// A Gateway carries other hosts' Agents, so its certificate binds none of them.
    #[serde(default)]
    pub gateway: bool,
    /// The `instance_uid`s that have reported with this host's certificate, hex.
    #[serde(default)]
    pub instance_uids: BTreeSet<String>,
    /// The subject values of the client certificate it was issued, or — for a Host made at its
    /// first report — of the certificate it presented.
    #[serde(default, skip_serializing_if = "SubjectValues::is_empty")]
    pub subject: SubjectValues,
    /// When its enrolment was approved, in milliseconds since the Unix epoch; `None` for a Host a
    /// provisioned certificate made at its first report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_ms: Option<u64>,
    /// The latest `not_after` of a certificate naming it that the Server issued or that it
    /// presented, in milliseconds since the Unix epoch (ADR-0047 clause 1). Every issuance and
    /// every admission moves it forward, never back. Once it has passed, a Host not marked as a
    /// Gateway ends with its bindings. `None` for a Host written before it had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_ms: Option<u64>,
}

impl Host {
    /// Moves its valid until forward to `not_after_ms`, never back; answers whether it moved.
    fn extend(&mut self, not_after_ms: u64) -> bool {
        if self.valid_until_ms >= Some(not_after_ms) {
            return false;
        }
        self.valid_until_ms = Some(not_after_ms);
        true
    }
}

/// The Agents a host's certificate speaks for (ADR-0026 clause 37).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpeaksFor {
    /// A host marked as a Gateway: it carries other hosts' Agents, and the Server keeps no record
    /// of which.
    Any,
    /// The `instance_uid`s bound to the host, hex.
    Agents(BTreeSet<String>),
}

/// A version of the hosts, numbered so no older one is written over a newer.
type HostsVersion = (u64, BTreeMap<String, Host>);

/// The certificates one host may hold at once (ADR-0021 clause 7): the one in force, its renewal,
/// and one more for a renewal whose answer was lost.
pub const MAX_PER_HOST: usize = 3;

/// The `instance_uid`s one host may speak for: a Client carries an Agent per Supervisor.
pub const MAX_UIDS_PER_HOST: usize = 256;

/// A certificate the client CA signed, PEM, and what it says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub pem: String,
    pub facts: Facts,
}

/// One certificate the Server signed (ADR-0021 clause 33).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    #[serde(flatten)]
    pub facts: Facts,
    /// The `instance_uid` of the message that carried the CSR, hex.
    pub instance_uid: String,
    /// On a renewal, the certificate it renewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<CertId>,
    pub issued_ms: u64,
}

/// What a revocation names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Revoked {
    /// A serial under every CA of one role — usually one CA; several while a CA file holds a
    /// rotation.
    Certificate {
        authority: String,
        issuers: Vec<String>,
        serial: String,
    },
}

/// One entry of the list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub id: String,
    pub revoked: Revoked,
    pub revoked_ms: u64,
}

/// Everything the store holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub issued: Vec<Issued>,
    pub revocations: Vec<Revocation>,
    pub hosts: BTreeMap<String, Host>,
}

/// The ledger's port (ADR-0006): where it is kept. A certificate is written on its own, so a
/// renewal costs one small write however large the register is.
pub trait LedgerStore: Send + Sync {
    /// The persisted ledger, empty when there is none yet.
    ///
    /// # Errors
    /// Returns an error when a ledger exists but cannot be read.
    fn load(&self) -> Result<Ledger, String>;

    /// Writes one register entry.
    ///
    /// # Errors
    /// Returns an error when it cannot be written.
    fn put_issued(&self, issued: &Issued) -> Result<(), String>;

    /// Removes one register entry.
    ///
    /// # Errors
    /// Returns an error when it cannot be removed.
    fn remove_issued(&self, id: &CertId) -> Result<(), String>;

    /// Replaces the list.
    ///
    /// # Errors
    /// Returns an error when it cannot be written.
    fn save_revocations(&self, revocations: &[Revocation]) -> Result<(), String>;

    /// Replaces the hosts and what each speaks for.
    ///
    /// # Errors
    /// Returns an error when they cannot be written.
    fn save_hosts(&self, hosts: &BTreeMap<String, Host>) -> Result<(), String>;
}

/// Why a revocation was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeError {
    /// The request names nothing that could be revoked; the text says why.
    Invalid(String),
    /// The list is at [`MAX_REVOCATIONS`].
    Full,
    /// The store could not write it.
    Store(String),
}

/// The register and the list, in memory and in their store.
pub struct Revocations {
    store: Box<dyn LedgerStore>,
    clock: Arc<dyn Clock>,
    authorities: Vec<Authority>,
    state: Mutex<State>,
    /// The version of the hosts last written: one write at a time, never an older over a newer.
    hosts_written: Mutex<u64>,
    changes: watch::Sender<u64>,
}

struct State {
    issued: BTreeMap<CertId, Issued>,
    revocations: Vec<Revocation>,
    /// The root of every entry's chain: the first certificate, registered or not, it descends
    /// from; an enrolment is its own root.
    roots: BTreeMap<CertId, CertId>,
    /// How many register entries descend from each root.
    descendants: BTreeMap<CertId, usize>,
    /// The earliest `not_after` in the register, or valid until of a Host: nothing can be pruned
    /// before it.
    earliest_expiry_ms: u64,
    hosts: BTreeMap<String, Host>,
    /// Counts the changes to `hosts`.
    hosts_version: u64,
    /// Which host each bound `instance_uid` belongs to, hex.
    owners: BTreeMap<String, String>,
    /// Every revoked certificate, once built: `None` after a change it has not caught up with.
    revoked: Option<BTreeSet<CertId>>,
    /// How often the revoked set was built.
    #[cfg(test)]
    rebuilds: usize,
}

impl State {
    /// Every certificate the list names, by issuer and serial.
    fn named(&self) -> BTreeSet<CertId> {
        self.revocations
            .iter()
            .flat_map(|entry| {
                let Revoked::Certificate {
                    issuers, serial, ..
                } = &entry.revoked;
                issuers.iter().map(|issuer| CertId {
                    issuer: issuer.clone(),
                    serial: serial.clone(),
                })
            })
            .collect()
    }

    /// Every revoked certificate (clause 35), built once after the list or the register changed.
    fn revoked(&mut self) -> &BTreeSet<CertId> {
        let revoked = match self.revoked.take() {
            Some(revoked) => revoked,
            None => {
                #[cfg(test)]
                {
                    self.rebuilds += 1;
                }
                self.resolve()
            }
        };
        self.revoked.insert(revoked)
    }

    /// The certificates the list names, and every register entry that renewed one of them, each
    /// chain walked once.
    fn resolve(&self) -> BTreeSet<CertId> {
        let mut revoked = self.named();
        if revoked.is_empty() {
            return revoked;
        }
        let mut answered: BTreeMap<&CertId, bool> = BTreeMap::new();
        for id in self.issued.keys() {
            let mut path = Vec::new();
            let mut current = Some(id);
            let mut found = false;
            // A chain is never longer than the register; the bound also ends a cycle a damaged
            // file could hold.
            for _ in 0..=self.issued.len() {
                let Some(at) = current else { break };
                if let Some(&known) = answered.get(at) {
                    found = known;
                    break;
                }
                if revoked.contains(at) {
                    found = true;
                    break;
                }
                path.push(at);
                current = self
                    .issued
                    .get(at)
                    .and_then(|issued| issued.predecessor.as_ref());
            }
            for at in path {
                answered.insert(at, found);
            }
        }
        revoked.extend(
            answered
                .into_iter()
                .filter(|(_, found)| *found)
                .map(|(id, _)| id.clone()),
        );
        revoked
    }

    /// The root of a registered entry's chain, by walking its predecessor links.
    fn chain_root(&self, id: &CertId) -> CertId {
        let mut current = id.clone();
        // A chain is never longer than the register; the bound also ends a damaged cycle.
        for _ in 0..=self.issued.len() {
            match self
                .issued
                .get(&current)
                .and_then(|issued| issued.predecessor.clone())
            {
                None => return current,
                Some(predecessor) => current = predecessor,
            }
        }
        current
    }

    /// The root a certificate `id` renewing `predecessor` has.
    fn root_below(&self, predecessor: Option<&CertId>, id: &CertId) -> CertId {
        match predecessor {
            None => id.clone(),
            Some(predecessor) => self
                .roots
                .get(predecessor)
                .cloned()
                .unwrap_or_else(|| predecessor.clone()),
        }
    }

    fn insert(&mut self, issued: Issued) {
        let id = issued.facts.id.clone();
        self.remove(&id);
        // A renewal of a revoked certificate is revoked, and so is whatever already names it as
        // its predecessor: built anew. Any other new entry changes no answer.
        if let (Some(revoked), Some(predecessor)) = (&self.revoked, &issued.predecessor) {
            if revoked.contains(predecessor) && !revoked.contains(&id) {
                self.revoked = None;
            }
        }
        let root = self.root_below(issued.predecessor.as_ref(), &id);
        *self.descendants.entry(root.clone()).or_default() += 1;
        self.roots.insert(id.clone(), root);
        self.earliest_expiry_ms = self.earliest_expiry_ms.min(issued.facts.not_after_ms);
        self.issued.insert(id, issued);
    }

    fn remove(&mut self, id: &CertId) {
        if self.issued.remove(id).is_none() {
            return;
        }
        self.revoked = None;
        if let Some(root) = self.roots.remove(id) {
            if let Some(count) = self.descendants.get_mut(&root) {
                *count -= 1;
                if *count == 0 {
                    self.descendants.remove(&root);
                }
            }
        }
    }
}

impl Revocations {
    /// Loads the ledger, and drops what expired while the Server was down.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    pub fn open(
        store: Box<dyn LedgerStore>,
        clock: Arc<dyn Clock>,
        authorities: Vec<Authority>,
    ) -> Result<Self, String> {
        let ledger = store.load()?;
        let revocations = Revocations {
            authorities,
            state: Mutex::new({
                let mut state = State {
                    issued: BTreeMap::new(),
                    revocations: ledger.revocations,
                    roots: BTreeMap::new(),
                    descendants: BTreeMap::new(),
                    earliest_expiry_ms: u64::MAX,
                    owners: ledger
                        .hosts
                        .iter()
                        .flat_map(|(host, entry)| {
                            entry
                                .instance_uids
                                .iter()
                                .map(move |uid| (uid.clone(), host.clone()))
                        })
                        .collect(),
                    hosts: ledger.hosts,
                    hosts_version: 0,
                    revoked: None,
                    #[cfg(test)]
                    rebuilds: 0,
                };
                for issued in ledger.issued {
                    state.earliest_expiry_ms =
                        state.earliest_expiry_ms.min(issued.facts.not_after_ms);
                    state.issued.insert(issued.facts.id.clone(), issued);
                }
                // A Host's valid until may pass before any certificate in the register expires
                // (ADR-0047 clause 1); one written before it had a valid until is pruned at once,
                // so it takes the register's latest `not_after` for it.
                for host in state.hosts.values().filter(|host| !host.gateway) {
                    state.earliest_expiry_ms = state
                        .earliest_expiry_ms
                        .min(host.valid_until_ms.unwrap_or(0));
                }
                // Each root by the predecessor links themselves, not by the order entries load in.
                let ids: Vec<CertId> = state.issued.keys().cloned().collect();
                for id in ids {
                    let root = state.chain_root(&id);
                    *state.descendants.entry(root.clone()).or_default() += 1;
                    state.roots.insert(id, root);
                }
                state
            }),
            store,
            clock,
            hosts_written: Mutex::new(0),
            changes: watch::channel(0).0,
        };
        let forgotten = {
            let mut state = revocations.state.lock().expect("revocation lock");
            revocations.prune(&mut state)?
        };
        revocations.write_forgotten(forgotten);
        Ok(revocations)
    }

    /// The CA an issuer hash belongs to, when it is one of this Server's.
    #[must_use]
    pub fn authority_of(&self, issuer: &str) -> Option<&Authority> {
        self.authorities.iter().find(|a| a.subject == issuer)
    }

    /// The register entry of a certificate, if the client CA signed it.
    #[must_use]
    pub fn issued_entry(&self, id: &CertId) -> Option<Issued> {
        self.state
            .lock()
            .expect("revocation lock")
            .issued
            .get(id)
            .cloned()
    }

    /// Records a certificate the client CA signed, before it is handed out (clause 2).
    ///
    /// # Errors
    /// Returns an error when the register is full — for a renewal, [`ENROLMENT_RESERVE`] short of
    /// full — when the chain already holds [`MAX_DESCENDANTS_PER_ROOT`] certificates, or when the
    /// store cannot write it; the certificate must then not be offered.
    pub fn record(
        &self,
        facts: Facts,
        instance_uid: &[u8],
        predecessor: Option<CertId>,
    ) -> Result<(), String> {
        let mut state = self.state.lock().expect("revocation lock");
        let forgotten = self.prune(&mut state)?;
        let minted = predecessor.is_none();
        let recorded = self.admit(&mut state, facts.clone(), instance_uid, predecessor);
        // The approval that mints a host id writes the Host (ADR-0035 clause 1): an issuance that
        // renews nothing and names a host the register does not know yet.
        // Every issuance moves its Host's valid until forward (ADR-0047 clause 1).
        let hosts = match (&recorded, minted, &facts.host) {
            (Ok(()), true, Some(host)) if !state.hosts.contains_key(host) => {
                let now = self.clock.now_ms();
                state.hosts.insert(
                    host.clone(),
                    Host {
                        subject: facts.subject_values.clone(),
                        approved_ms: Some(now),
                        valid_until_ms: Some(facts.not_after_ms),
                        ..Host::default()
                    },
                );
                Some(Self::hosts_changed(&mut state))
            }
            (Ok(()), _, Some(host))
                if state
                    .hosts
                    .get_mut(host)
                    .is_some_and(|entry| entry.extend(facts.not_after_ms)) =>
            {
                Some(Self::hosts_changed(&mut state))
            }
            _ => forgotten,
        };
        drop(state);
        self.write_forgotten(hosts);
        recorded
    }

    fn admit(
        &self,
        state: &mut State,
        facts: Facts,
        instance_uid: &[u8],
        predecessor: Option<CertId>,
    ) -> Result<(), String> {
        let limit = if predecessor.is_some() {
            MAX_ISSUED - ENROLMENT_RESERVE
        } else {
            MAX_ISSUED
        };
        if state.issued.len() >= limit {
            return Err(format!(
                "the register holds {} certificates already",
                state.issued.len()
            ));
        }
        let root = state.root_below(predecessor.as_ref(), &facts.id);
        if state.descendants.get(&root).copied().unwrap_or(0) >= MAX_DESCENDANTS_PER_ROOT {
            return Err("this certificate's chain has been renewed too often".to_string());
        }
        if let Some(host) = &facts.host {
            let now = self.clock.now_ms();
            let live = state
                .issued
                .values()
                .filter(|issued| {
                    issued.facts.host.as_ref() == Some(host) && issued.facts.not_after_ms > now
                })
                .count();
            if live >= MAX_PER_HOST {
                return Err(format!(
                    "the host already holds {MAX_PER_HOST} valid certificates — one is renewed \
                     when it has run two thirds of its life"
                ));
            }
        }
        let issued = Issued {
            facts,
            instance_uid: hex::encode(instance_uid),
            predecessor,
            issued_ms: self.clock.now_ms(),
        };
        self.store.put_issued(&issued)?;
        state.insert(issued);
        Ok(())
    }

    /// Whether a connection presenting a certificate of `host` may report for `instance_uid`
    /// (ADR-0021 clause 7), binding nothing: [`check_report`](Self::check_report) binds it once
    /// the report is admitted.
    ///
    /// # Errors
    /// Returns the refusal.
    pub fn may_report(&self, host: &str, instance_uid: &[u8]) -> Result<(), String> {
        let state = self.state.lock().expect("revocation lock");
        Self::admits(&state, host, &hex::encode(instance_uid)).map(|_| ())
    }

    /// Whether a connection presenting a certificate of `host` may report for `instance_uid`
    /// (ADR-0021 clause 7). An `instance_uid` first heard from a host is bound to it; one bound to
    /// another host is refused. A Gateway's certificate binds nothing — it carries other hosts'
    /// Agents. A certificate an operator provisioned with a host id makes its Host here, at its
    /// first report, with `subject` — the values of the certificate it presented (ADR-0035
    /// clause 1). Every admitted report moves the Host's valid until forward to `not_after_ms`,
    /// the end of the certificate it presented (ADR-0047 clause 1).
    ///
    /// # Errors
    /// Returns the refusal, or an error when a new binding cannot be written.
    pub fn check_report(
        &self,
        host: &str,
        subject: &SubjectValues,
        not_after_ms: u64,
        instance_uid: &[u8],
    ) -> Result<(), String> {
        let uid = hex::encode(instance_uid);
        let mut state = self.state.lock().expect("revocation lock");
        let binds = Self::admits(&state, host, &uid)?;
        if binds {
            state
                .hosts
                .entry(host.to_string())
                .or_insert_with(|| Host {
                    subject: subject.clone(),
                    ..Host::default()
                })
                .instance_uids
                .insert(uid.clone());
            state.owners.insert(uid, host.to_string());
        }
        let extended = state
            .hosts
            .get_mut(host)
            .is_some_and(|entry| entry.extend(not_after_ms));
        if extended {
            state.earliest_expiry_ms = state.earliest_expiry_ms.min(not_after_ms);
        }
        if binds || extended {
            self.save_hosts(state)
        } else {
            Ok(())
        }
    }

    /// Releases `instance_uid` from the Host it is bound to, when an operator forgets its Agent
    /// (ADR-0047 clause 2): the next host that reports it binds it.
    ///
    /// # Errors
    /// Returns an error when the release cannot be written; it holds in memory all the same, and
    /// the next write of the hosts carries it.
    pub fn release(&self, instance_uid: &[u8]) -> Result<(), String> {
        let uid = hex::encode(instance_uid);
        let mut state = self.state.lock().expect("revocation lock");
        let Some(host) = state.owners.remove(&uid) else {
            return Ok(());
        };
        if let Some(entry) = state.hosts.get_mut(&host) {
            entry.instance_uids.remove(&uid);
        }
        self.save_hosts(state)
    }

    /// Whether `host` may report for `uid`, and whether that would bind it.
    fn admits(state: &State, host: &str, uid: &str) -> Result<bool, String> {
        if state.hosts.get(host).is_some_and(|entry| entry.gateway) {
            return Ok(false);
        }
        match state.owners.get(uid) {
            Some(owner) if owner == host => return Ok(false),
            Some(owner) => {
                let owner_is_gateway = state.hosts.get(owner).is_some_and(|entry| entry.gateway);
                if !owner_is_gateway {
                    return Err("this certificate belongs to another host than that Agent's".into());
                }
            }
            None => {}
        }
        if state
            .hosts
            .get(host)
            .is_some_and(|entry| entry.instance_uids.len() >= MAX_UIDS_PER_HOST)
        {
            return Err(format!(
                "this host already speaks for {MAX_UIDS_PER_HOST} Agents"
            ));
        }
        Ok(true)
    }

    /// The Agents a certificate naming `host` speaks for (ADR-0026 clause 37): the `instance_uid`s
    /// bound to it, or any Agent for a host marked as a Gateway. A host the register does not know
    /// speaks for none.
    #[must_use]
    pub fn speaks_for(&self, host: &str) -> SpeaksFor {
        let state = self.state.lock().expect("revocation lock");
        match state.hosts.get(host) {
            Some(entry) if entry.gateway => SpeaksFor::Any,
            Some(entry) => SpeaksFor::Agents(entry.instance_uids.clone()),
            None => SpeaksFor::Agents(BTreeSet::new()),
        }
    }

    /// Moves a binding to the `instance_uid` the Server re-keyed an Agent to — a re-key never
    /// orphans a host's certificate (ADR-0021 clause 7).
    ///
    /// # Errors
    /// Returns an error when the binding cannot be written.
    pub fn rebind(&self, old: &[u8], new: &[u8]) -> Result<(), String> {
        let (old, new) = (hex::encode(old), hex::encode(new));
        let mut state = self.state.lock().expect("revocation lock");
        let Some(host) = state.owners.remove(&old) else {
            return Ok(());
        };
        if let Some(entry) = state.hosts.get_mut(&host) {
            entry.instance_uids.remove(&old);
            entry.instance_uids.insert(new.clone());
        }
        state.owners.insert(new, host);
        self.save_hosts(state)
    }

    /// Marks `host` as a Gateway, or not; answers whether this Server knows the host.
    ///
    /// # Errors
    /// Returns an error when the change cannot be written.
    pub fn set_gateway(&self, host: &str, gateway: bool) -> Result<bool, String> {
        let mut state = self.state.lock().expect("revocation lock");
        let known = state.hosts.contains_key(host)
            || state
                .issued
                .values()
                .any(|issued| issued.facts.host.as_deref() == Some(host));
        if !known {
            return Ok(false);
        }
        let entry = state.hosts.entry(host.to_string()).or_default();
        entry.gateway = gateway;
        // A Host whose mark is taken away ends with its valid until again (ADR-0047 clause 1).
        let until = entry.valid_until_ms.unwrap_or(0);
        if !gateway {
            state.earliest_expiry_ms = state.earliest_expiry_ms.min(until);
        }
        self.save_hosts(state)?;
        Ok(true)
    }

    /// Writes the hosts as `state` holds them, once its lock is released, so no check of the list
    /// waits for the disk. It returns once they, or a later version of them, are written.
    fn save_hosts(&self, mut state: MutexGuard<'_, State>) -> Result<(), String> {
        let (version, hosts) = Self::hosts_changed(&mut state);
        drop(state);
        self.write_hosts(version, &hosts)
    }

    /// Writes the hosts a prune forgot or an approval wrote. The register does not depend on
    /// them, so a failure is logged and left to the next write of the hosts.
    fn write_forgotten(&self, forgotten: Option<HostsVersion>) {
        if let Some((version, hosts)) = forgotten {
            if let Err(e) = self.write_hosts(version, &hosts) {
                tracing::warn!(error = %e, "cannot write the hosts");
            }
        }
    }

    fn hosts_changed(state: &mut State) -> HostsVersion {
        state.hosts_version += 1;
        (state.hosts_version, state.hosts.clone())
    }

    fn write_hosts(&self, version: u64, hosts: &BTreeMap<String, Host>) -> Result<(), String> {
        let mut written = self.hosts_written.lock().expect("hosts lock");
        if *written >= version {
            return Ok(());
        }
        self.store.save_hosts(hosts)?;
        *written = version;
        Ok(())
    }

    /// Every host this Server knows, and how many valid certificates each holds.
    #[must_use]
    pub fn hosts(&self) -> Vec<(String, Host, usize)> {
        let state = self.state.lock().expect("revocation lock");
        let now = self.clock.now_ms();
        let mut names: BTreeSet<String> = state.hosts.keys().cloned().collect();
        names.extend(
            state
                .issued
                .values()
                .filter_map(|issued| issued.facts.host.clone()),
        );
        names
            .into_iter()
            .map(|name| {
                let live = state
                    .issued
                    .values()
                    .filter(|issued| {
                        issued.facts.host.as_ref() == Some(&name) && issued.facts.not_after_ms > now
                    })
                    .count();
                let host = state.hosts.get(&name).cloned().unwrap_or_default();
                (name, host, live)
            })
            .collect()
    }

    /// Every certificate in the register, oldest first.
    #[must_use]
    pub fn issued(&self) -> Vec<Issued> {
        let state = self.state.lock().expect("revocation lock");
        let mut issued: Vec<Issued> = state.issued.values().cloned().collect();
        issued.sort_by_key(|issued| issued.issued_ms);
        issued
    }

    /// Revokes the certificate with `serial` from the CA of `authority` — `client` or
    /// `bootstrap` (clause 3).
    ///
    /// # Errors
    /// Refuses an authority this Server does not have, a serial that is not hex, a full list, and
    /// a failed write.
    pub fn revoke_certificate(
        &self,
        authority: &str,
        serial: &str,
    ) -> Result<Revocation, RevokeError> {
        let issuers: Vec<String> = self
            .authorities
            .iter()
            .filter(|a| a.role == authority)
            .map(|a| a.subject.clone())
            .collect();
        if issuers.is_empty() {
            let roles: BTreeSet<&str> = self.authorities.iter().map(|a| a.role.as_str()).collect();
            return Err(RevokeError::Invalid(format!(
                "this Server has no {authority:?} CA; name one of {roles:?}"
            )));
        }
        let serial_text = normalize_serial(serial);
        if serial.trim().is_empty() || !serial_text.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RevokeError::Invalid(format!(
                "the serial {serial:?} is not hexadecimal"
            )));
        }
        // RFC 5280 4.1.2.2: a serial is at most 20 octets. The list every Gateway reads is bounded
        // on that length, so a longer one would push it past what a Gateway accepts and leave
        // every Gateway admitting nobody (Q-2).
        if serial_text.len() > MAX_SERIAL_HEX {
            return Err(RevokeError::Invalid(format!(
                "the serial {serial:?} is longer than the 20 octets a certificate serial may have"
            )));
        }
        self.add(Revoked::Certificate {
            authority: authority.to_string(),
            issuers,
            serial: serial_text,
        })
    }

    fn add(&self, revoked: Revoked) -> Result<Revocation, RevokeError> {
        let mut state = self.state.lock().expect("revocation lock");
        if let Some(existing) = state.revocations.iter().find(|e| e.revoked == revoked) {
            return Ok(existing.clone());
        }
        if state.revocations.len() >= MAX_REVOCATIONS {
            return Err(RevokeError::Full);
        }
        let entry = Revocation {
            id: entry_id(&revoked),
            revoked,
            revoked_ms: self.clock.now_ms(),
        };
        state.revocations.push(entry.clone());
        if let Err(e) = self.store.save_revocations(&state.revocations) {
            state.revocations.pop();
            return Err(RevokeError::Store(e));
        }
        state.revoked = None;
        drop(state);
        self.changes.send_modify(|rev| *rev += 1);
        Ok(entry)
    }

    /// The list, oldest first (clause 7).
    #[must_use]
    pub fn list(&self) -> Vec<Revocation> {
        self.state
            .lock()
            .expect("revocation lock")
            .revocations
            .clone()
    }

    /// Lifts one revocation; `Ok(false)` for an unknown id (clause 7). It takes effect at the next
    /// connection and reopens nothing, so it is not announced.
    ///
    /// # Errors
    /// Returns an error when the store cannot write it.
    pub fn lift(&self, id: &str) -> Result<bool, String> {
        let mut state = self.state.lock().expect("revocation lock");
        let Some(index) = state.revocations.iter().position(|e| e.id == id) else {
            return Ok(false);
        };
        let entry = state.revocations.remove(index);
        if let Err(e) = self.store.save_revocations(&state.revocations) {
            state.revocations.insert(index, entry);
            return Err(e);
        }
        state.revoked = None;
        Ok(true)
    }

    /// Whether `certificate`, or a certificate it renewed, is revoked (clause 4).
    #[must_use]
    pub fn is_certificate_revoked(&self, certificate: &CertId) -> bool {
        self.state
            .lock()
            .expect("revocation lock")
            .revoked()
            .contains(certificate)
    }

    /// Every certificate of the CAs of `role` that is revoked, itself or through a certificate it
    /// renewed, with its chain already resolved: what a Gateway refuses
    /// (ADR-0021 clause 43). A certificate the register never held is on it as revoked.
    #[must_use]
    pub fn revoked_certificates(&self, role: &str) -> BTreeSet<CertId> {
        let issuers: BTreeSet<&str> = self
            .authorities
            .iter()
            .filter(|authority| authority.role == role)
            .map(|authority| authority.subject.as_str())
            .collect();
        self.state
            .lock()
            .expect("revocation lock")
            .revoked()
            .iter()
            .filter(|id| issuers.contains(id.issuer.as_str()))
            .cloned()
            .collect()
    }

    /// Whether `host` is marked as a Gateway, and its subject values — what places an Agent that
    /// arrived over it (ADR-0035 clauses 3 and 4). A host the register does not know is neither a
    /// Gateway nor has values.
    #[must_use]
    pub fn placement(&self, host: &str) -> (bool, SubjectValues) {
        self.state
            .lock()
            .expect("revocation lock")
            .hosts
            .get(host)
            .map(|host| (host.gateway, host.subject.clone()))
            .unwrap_or_default()
    }

    /// Whether `host` is marked as a Gateway.
    #[must_use]
    pub fn is_gateway(&self, host: &str) -> bool {
        self.state
            .lock()
            .expect("revocation lock")
            .hosts
            .get(host)
            .is_some_and(|host| host.gateway)
    }

    /// Announces every new revocation; an open session checks itself against the list on each.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Drops the register entries that have expired and from which no valid certificate descends,
    /// and the revocations of certificates those entries held (clause 6). A revoked ancestor of a
    /// valid renewal stays, so the renewal stays revoked.
    ///
    /// A Host not marked as a Gateway whose valid until has passed is forgotten, and every
    /// `instance_uid` bound to it released (ADR-0047 clause 1); what is left of the hosts is
    /// answered for the caller to write once the lock is released.
    fn prune(&self, state: &mut State) -> Result<Option<HostsVersion>, String> {
        let now = self.clock.now_ms();
        if now < state.earliest_expiry_ms {
            return Ok(None);
        }
        let mut needed: BTreeSet<CertId> = BTreeSet::new();
        for issued in state.issued.values() {
            if issued.facts.not_after_ms <= now {
                continue;
            }
            let mut current = Some(&issued.facts.id);
            for _ in 0..=state.issued.len() {
                let Some(id) = current else { break };
                if !needed.insert(id.clone()) {
                    break;
                }
                current = state
                    .issued
                    .get(id)
                    .and_then(|entry| entry.predecessor.as_ref());
            }
        }
        let gone: Vec<CertId> = state
            .issued
            .keys()
            .filter(|id| !needed.contains(*id))
            .cloned()
            .collect();
        // A Host ends when no certificate naming it is valid (ADR-0047 clause 1): once its valid
        // until has passed nobody can speak as it again, so its bindings guard nothing. A
        // Gateway's Host stays while it is marked, as its certificate may be one an operator
        // provisioned and never presented. A Host written before it had a valid until takes the
        // latest `not_after` the register holds for it, and stays until its next admission when
        // the register holds none.
        let mut latest: BTreeMap<&str, u64> = BTreeMap::new();
        for issued in state.issued.values() {
            if let Some(host) = issued.facts.host.as_deref() {
                let until = latest.entry(host).or_default();
                *until = (*until).max(issued.facts.not_after_ms);
            }
        }
        let mut changed = false;
        for (name, host) in &mut state.hosts {
            if let Some(until) = latest.get(name.as_str()) {
                changed |= host.extend(*until);
            }
        }
        let ended: BTreeSet<String> = state
            .hosts
            .iter()
            .filter(|(_, host)| !host.gateway && host.valid_until_ms.is_some_and(|t| t <= now))
            .map(|(name, _)| name.clone())
            .collect();
        if !ended.is_empty() {
            state.hosts.retain(|name, _| !ended.contains(name));
            state.owners.retain(|_, owner| !ended.contains(owner));
            changed = true;
        }
        let forgotten = changed.then(|| Self::hosts_changed(state));
        // Kept entries that have expired are revoked ancestors' chains: the next prune is due when
        // the first entry still valid expires, or the first Host's valid until passes.
        state.earliest_expiry_ms = state
            .issued
            .values()
            .map(|issued| issued.facts.not_after_ms)
            .chain(
                state
                    .hosts
                    .values()
                    .filter(|host| !host.gateway)
                    .filter_map(|host| host.valid_until_ms),
            )
            .filter(|not_after| *not_after > now)
            .min()
            .unwrap_or(u64::MAX);
        if gone.is_empty() {
            return Ok(forgotten);
        }
        for id in &gone {
            self.store.remove_issued(id)?;
            state.remove(id);
        }
        let before = state.revocations.len();
        state.revocations.retain(|entry| {
            let Revoked::Certificate {
                issuers, serial, ..
            } = &entry.revoked;
            !gone
                .iter()
                .any(|id| &id.serial == serial && issuers.contains(&id.issuer))
        });
        if state.revocations.len() != before {
            state.revoked = None;
            self.store.save_revocations(&state.revocations)?;
        }
        Ok(forgotten)
    }
}

/// A stable id: the same revocation twice is one entry.
fn entry_id(revoked: &Revoked) -> String {
    let Revoked::Certificate {
        authority, serial, ..
    } = revoked;
    let text = format!("certificate\n{authority}\n{serial}");
    hex::encode(&Sha256::digest(text.as_bytes())[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Manual(AtomicU64);

    impl Clock for Manual {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<Ledger>>);

    impl LedgerStore for Memory {
        fn load(&self) -> Result<Ledger, String> {
            Ok(self.0.lock().expect("lock").clone())
        }
        fn put_issued(&self, issued: &Issued) -> Result<(), String> {
            let mut ledger = self.0.lock().expect("lock");
            ledger.issued.retain(|i| i.facts.id != issued.facts.id);
            ledger.issued.push(issued.clone());
            Ok(())
        }
        fn remove_issued(&self, id: &CertId) -> Result<(), String> {
            self.0
                .lock()
                .expect("lock")
                .issued
                .retain(|i| &i.facts.id != id);
            Ok(())
        }
        fn save_revocations(&self, revocations: &[Revocation]) -> Result<(), String> {
            self.0.lock().expect("lock").revocations = revocations.to_vec();
            Ok(())
        }
        fn save_hosts(&self, hosts: &BTreeMap<String, Host>) -> Result<(), String> {
            self.0.lock().expect("lock").hosts = hosts.clone();
            Ok(())
        }
    }

    const NOW: u64 = 1_000_000_000;
    /// The end of a certificate presented in a test that does not ask when its Host ends.
    const FAR: u64 = u64::MAX;
    const CA: &[u8] = b"fleet client CA";

    fn open(store: &Memory) -> (Revocations, Arc<Manual>) {
        let clock = Arc::new(Manual(AtomicU64::new(NOW)));
        let revocations = Revocations::open(
            Box::new(store.clone()),
            clock.clone(),
            vec![Authority {
                role: "client".into(),
                subject: name_hash(CA),
                name: "CN=fleet client CA".into(),
            }],
        )
        .expect("open");
        (revocations, clock)
    }

    fn id(serial: &str) -> CertId {
        CertId::new(CA, serial)
    }

    fn facts(serial: &str, not_after_ms: u64) -> Facts {
        Facts {
            id: id(serial),
            issuer_name: "CN=fleet client CA".into(),
            subject: "CN=edge-01".into(),
            key_fingerprint: format!("key-{serial}"),
            not_after_ms,
            host: None,
            subject_values: SubjectValues::default(),
        }
    }

    fn on_host(serial: &str, host: &str) -> Facts {
        Facts {
            host: Some(host.to_string()),
            ..facts(serial, NOW + 1_000_000)
        }
    }

    /// A host holds a bounded number of valid certificates, an Agent is spoken for by the host
    /// that first reported it alone, a re-key keeps its host, and a Gateway speaks for any Agent.
    /// Verifies: ADR-0021
    #[test]
    fn a_host_is_bounded_and_speaks_only_for_its_own_agents() {
        let store = Memory::default();
        let (revocations, _) = open(&store);
        for serial in ["a1", "a2", "a3"] {
            revocations
                .record(on_host(serial, "h1"), &[1; 16], None)
                .expect("within the bound");
        }
        assert!(
            revocations
                .record(on_host("a4", "h1"), &[1; 16], None)
                .is_err(),
            "a fourth valid certificate for one host"
        );
        revocations
            .record(on_host("b1", "h2"), &[2; 16], None)
            .expect("another host");

        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            .expect("first report binds");
        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            .expect("its own Agent");
        assert!(
            revocations
                .check_report("h2", &SubjectValues::default(), FAR, &[1; 16])
                .is_err(),
            "another host spoke for h1's Agent"
        );
        revocations.rebind(&[1; 16], &[3; 16]).expect("rebind");
        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[3; 16])
            .expect("the re-keyed Agent");
        assert!(revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[3; 16])
            .is_err());
        revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[1; 16])
            .expect("the old identity is free");

        assert!(!revocations.set_gateway("unknown", true).expect("set"));
        assert!(revocations.set_gateway("h2", true).expect("set"));
        revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[3; 16])
            .expect("a Gateway speaks for any Agent");

        // The bindings survive a restart.
        let (reopened, _) = open(&store);
        assert!(reopened
            .check_report("h3", &SubjectValues::default(), FAR, &[3; 16])
            .is_err());
        reopened
            .check_report("h2", &SubjectValues::default(), FAR, &[9; 16])
            .expect("still a Gateway");
    }

    /// A host speaks for the `instance_uid`s that reported with its certificate, a host the
    /// register does not know for none, and a Gateway for any Agent.
    /// Verifies: ADR-0026
    #[test]
    fn a_host_speaks_for_the_agents_bound_to_it_and_a_gateway_for_any() {
        let (revocations, _) = open(&Memory::default());
        revocations
            .record(on_host("a1", "h1"), &[1; 16], None)
            .expect("record");
        revocations
            .record(on_host("b1", "h2"), &[2; 16], None)
            .expect("record");
        assert_eq!(
            revocations.speaks_for("h1"),
            SpeaksFor::Agents(BTreeSet::new()),
            "nothing reported yet"
        );
        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            .expect("binds");
        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[3; 16])
            .expect("binds");
        assert_eq!(
            revocations.speaks_for("h1"),
            SpeaksFor::Agents([hex::encode([1; 16]), hex::encode([3; 16])].into())
        );
        assert_eq!(
            revocations.speaks_for("unknown"),
            SpeaksFor::Agents(BTreeSet::new())
        );
        assert!(revocations.set_gateway("h2", true).expect("mark"));
        assert_eq!(revocations.speaks_for("h2"), SpeaksFor::Any);
        revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[1; 16])
            .expect("a Gateway reports for h1's Agent");
        assert_eq!(
            revocations.speaks_for("h2"),
            SpeaksFor::Any,
            "a Gateway binds nothing"
        );
    }

    /// A Host whose only certificate has expired ends at the next prune, a bound Agent or not, and
    /// its `instance_uid`s can be bound by another host; a marked Gateway keeps its Host and its
    /// mark, since its certificate may be one the register never held, and one whose mark was
    /// taken away ends like any other.
    /// Verifies: ADR-0047
    #[test]
    fn a_host_whose_last_certificate_has_expired_ends_with_its_bindings() {
        let store = Memory::default();
        let (revocations, clock) = open(&store);
        let soon = |serial: &str, host: &str| Facts {
            host: Some(host.to_string()),
            ..facts(serial, NOW + 1_000)
        };
        revocations
            .record(soon("a1", "gw"), &[1; 16], None)
            .expect("record");
        revocations
            .record(soon("b2", "h1"), &[2; 16], None)
            .expect("record");
        revocations
            .record(soon("e5", "old"), &[4; 16], None)
            .expect("record");
        revocations
            .record(on_host("c3", "h2"), &[3; 16], None)
            .expect("record");
        assert!(revocations.set_gateway("gw", true).expect("mark"));
        assert!(revocations.set_gateway("old", true).expect("mark"));
        assert!(revocations.set_gateway("old", false).expect("unmark"));
        // h1 reports with the certificate it was issued, so nothing moves its end.
        revocations
            .check_report("h1", &SubjectValues::default(), NOW + 1_000, &[2; 16])
            .expect("binds");
        revocations
            .check_report("gw", &SubjectValues::default(), NOW + 1_000, &[7; 16])
            .expect("a Gateway binds nothing");
        assert!(
            revocations
                .check_report("h2", &SubjectValues::default(), FAR, &[2; 16])
                .is_err(),
            "h1's Agent is h1's while h1 holds a valid certificate"
        );

        clock.0.fetch_add(1_000, Ordering::SeqCst);
        revocations
            .record(on_host("d4", "h2"), &[3; 16], None)
            .expect("a record prunes");
        let names: Vec<String> = revocations
            .hosts()
            .into_iter()
            .map(|(name, ..)| name)
            .collect();
        assert_eq!(names, ["gw", "h2"], "h1 and old end");
        assert!(revocations.is_gateway("gw"), "the Gateway keeps its mark");
        assert_eq!(
            store
                .0
                .lock()
                .expect("lock")
                .hosts
                .keys()
                .collect::<Vec<_>>(),
            // h2 holds a valid certificate, and its approval wrote it (ADR-0035 clause 1).
            ["gw", "h2"],
            "the ending is written"
        );
        revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[2; 16])
            .expect("h1's Agent is released, and another host binds it");
        assert_eq!(
            revocations.speaks_for("h2"),
            SpeaksFor::Agents(["02".repeat(16)].into_iter().collect())
        );
    }

    /// A Host whose certificate an operator provisioned is not in the register, but whose
    /// presented certificate is still valid, keeps its bindings past every register entry's end;
    /// it ends once the presented certificate has.
    /// Verifies: ADR-0047
    #[test]
    fn a_host_with_a_valid_presented_certificate_keeps_its_bindings() {
        let store = Memory::default();
        let (revocations, clock) = open(&store);
        revocations
            .check_report("p1", &SubjectValues::default(), NOW + 5_000, &[5; 16])
            .expect("a provisioned certificate binds");
        revocations
            .record(
                Facts {
                    host: Some("other".into()),
                    ..facts("a1", NOW + 1_000)
                },
                &[1; 16],
                None,
            )
            .expect("record");
        clock.0.fetch_add(2_000, Ordering::SeqCst);
        revocations
            .record(on_host("b2", "h2"), &[2; 16], None)
            .expect("a record prunes");
        assert!(
            revocations
                .check_report("h2", &SubjectValues::default(), FAR, &[5; 16])
                .is_err(),
            "p1's Agent stays p1's"
        );
        assert_eq!(
            store.0.lock().expect("lock").hosts["p1"].valid_until_ms,
            Some(NOW + 5_000)
        );

        clock.0.fetch_add(3_000, Ordering::SeqCst);
        revocations
            .record(on_host("c3", "h3"), &[3; 16], None)
            .expect("a record prunes");
        assert!(!store.0.lock().expect("lock").hosts.contains_key("p1"));
        revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[5; 16])
            .expect("released with its Host");
    }

    /// Every issuance and every admission moves a Host's valid until forward, never back.
    /// Verifies: ADR-0047
    #[test]
    fn a_hosts_valid_until_only_moves_forward() {
        let store = Memory::default();
        let (revocations, _) = open(&store);
        let until = |store: &Memory| store.0.lock().expect("lock").hosts["h1"].valid_until_ms;
        revocations
            .record(on_host("a1", "h1"), &[1; 16], None)
            .expect("approved");
        assert_eq!(until(&store), Some(NOW + 1_000_000));
        revocations
            .record(
                Facts {
                    host: Some("h1".into()),
                    ..facts("a2", NOW + 2_000_000)
                },
                &[1; 16],
                Some(id("a1")),
            )
            .expect("renewed");
        assert_eq!(until(&store), Some(NOW + 2_000_000), "an issuance moves it");
        revocations
            .check_report("h1", &SubjectValues::default(), NOW + 3_000_000, &[1; 16])
            .expect("admitted");
        assert_eq!(
            until(&store),
            Some(NOW + 3_000_000),
            "an admission moves it"
        );
        revocations
            .check_report("h1", &SubjectValues::default(), NOW + 500, &[1; 16])
            .expect("admitted");
        assert_eq!(until(&store), Some(NOW + 3_000_000), "never back");
    }

    /// A Host written before it had a valid until takes the latest `not_after` the register holds
    /// for it, and stays until its next admission when the register holds none.
    /// Verifies: ADR-0047
    #[test]
    fn a_host_written_before_its_valid_until_takes_the_registers() {
        let store = Memory::default();
        {
            let mut ledger = store.0.lock().expect("lock");
            let legacy = |uid: &str| Host {
                instance_uids: [uid.to_string()].into_iter().collect(),
                ..Host::default()
            };
            ledger.hosts.insert("registered".into(), legacy("01"));
            ledger.hosts.insert("unknown".into(), legacy("02"));
            ledger.issued.push(Issued {
                facts: on_host("a1", "registered"),
                instance_uid: "01".into(),
                predecessor: None,
                issued_ms: NOW,
            });
        }
        let (revocations, clock) = open(&store);
        assert_eq!(
            store.0.lock().expect("lock").hosts["registered"].valid_until_ms,
            Some(NOW + 1_000_000),
            "the register's not_after, written"
        );
        clock.0.fetch_add(1_000_000, Ordering::SeqCst);
        revocations
            .record(on_host("b2", "h2"), &[3; 16], None)
            .expect("a record prunes");
        let hosts = store.0.lock().expect("lock").hosts.clone();
        assert!(
            !hosts.contains_key("registered"),
            "ended with its certificate"
        );
        assert_eq!(
            hosts["unknown"].valid_until_ms, None,
            "stays until its next admission"
        );
        revocations
            .check_report(
                "unknown",
                &SubjectValues::default(),
                NOW + 2_000_000,
                &[2; 16],
            )
            .expect("admitted");
        assert_eq!(
            store.0.lock().expect("lock").hosts["unknown"].valid_until_ms,
            Some(NOW + 2_000_000)
        );
    }

    /// Forgetting an Agent releases its binding.
    /// Verifies: ADR-0047
    #[test]
    fn a_released_instance_uid_can_be_bound_by_another_host() {
        let store = Memory::default();
        let (revocations, _) = open(&store);
        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            .expect("binds");
        revocations.release(&[1; 16]).expect("released");
        assert!(store.0.lock().expect("lock").hosts["h1"]
            .instance_uids
            .is_empty());
        revocations
            .check_report("h2", &SubjectValues::default(), FAR, &[1; 16])
            .expect("another host binds it");
        revocations
            .release(&[9; 16])
            .expect("an unbound instance_uid releases nothing");
    }

    /// The issuance that mints a host id — an approval — writes the Host before its first report,
    /// with the certificate's subject values and the time; a renewal writes none, and a report
    /// does not overwrite what the approval wrote.
    /// Verifies: ADR-0035
    #[test]
    fn an_approval_writes_the_host_before_its_first_report() {
        let store = Memory::default();
        let (revocations, _) = open(&store);
        let subject = SubjectValues {
            organization: "Kunde GmbH".into(),
            organizational_unit: "Wien".into(),
            ..SubjectValues::default()
        };
        revocations
            .record(
                Facts {
                    subject_values: subject.clone(),
                    ..on_host("a1", "h1")
                },
                &[1; 16],
                None,
            )
            .expect("approved");
        let written = store.0.lock().expect("lock").hosts.clone();
        let host = written.get("h1").expect("the Host is written");
        assert_eq!(host.subject, subject);
        assert_eq!(host.approved_ms, Some(NOW));
        assert!(host.instance_uids.is_empty(), "nothing reported yet");
        assert_eq!(revocations.placement("h1"), (false, subject.clone()));

        revocations
            .record(on_host("a2", "h9"), &[1; 16], Some(id("a1")))
            .expect("a renewal");
        assert!(
            !store.0.lock().expect("lock").hosts.contains_key("h9"),
            "a renewal mints no Host"
        );

        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            .expect("its first report");
        let host = store.0.lock().expect("lock").hosts["h1"].clone();
        assert_eq!(host.subject, subject, "the approval's values stay");
        assert_eq!(host.instance_uids.len(), 1);
    }

    /// A certificate an operator provisioned with a host id makes its Host at its first report,
    /// with the values of the certificate it presented.
    /// Verifies: ADR-0035
    #[test]
    fn a_provisioned_certificate_makes_its_host_at_its_first_report() {
        let store = Memory::default();
        let (revocations, _) = open(&store);
        let subject = SubjectValues {
            country: "AT".into(),
            ..SubjectValues::default()
        };
        revocations
            .check_report("p1", &subject, FAR, &[5; 16])
            .expect("binds");
        let host = store.0.lock().expect("lock").hosts["p1"].clone();
        assert_eq!(host.subject, subject);
        assert_eq!(host.approved_ms, None, "no approval made it");
    }

    /// A store whose host writes fail.
    #[derive(Clone, Default)]
    struct NoHosts(Memory);

    impl LedgerStore for NoHosts {
        fn load(&self) -> Result<Ledger, String> {
            self.0.load()
        }
        fn put_issued(&self, issued: &Issued) -> Result<(), String> {
            self.0.put_issued(issued)
        }
        fn remove_issued(&self, id: &CertId) -> Result<(), String> {
            self.0.remove_issued(id)
        }
        fn save_revocations(&self, revocations: &[Revocation]) -> Result<(), String> {
            self.0.save_revocations(revocations)
        }
        fn save_hosts(&self, _: &BTreeMap<String, Host>) -> Result<(), String> {
            Err("the disk is full".into())
        }
    }

    /// A store whose host writes fail while `failing` is set.
    #[derive(Clone, Default)]
    struct FailingHosts {
        inner: Memory,
        failing: Arc<std::sync::atomic::AtomicBool>,
    }

    impl LedgerStore for FailingHosts {
        fn load(&self) -> Result<Ledger, String> {
            self.inner.load()
        }
        fn put_issued(&self, issued: &Issued) -> Result<(), String> {
            self.inner.put_issued(issued)
        }
        fn remove_issued(&self, id: &CertId) -> Result<(), String> {
            self.inner.remove_issued(id)
        }
        fn save_revocations(&self, revocations: &[Revocation]) -> Result<(), String> {
            self.inner.save_revocations(revocations)
        }
        fn save_hosts(&self, hosts: &BTreeMap<String, Host>) -> Result<(), String> {
            if self.failing.load(Ordering::SeqCst) {
                return Err("the disk is full".into());
            }
            self.inner.save_hosts(hosts)
        }
    }

    /// An approval whose Host cannot be written is not refused: the certificate is recorded, the
    /// Host is known with the approval's values, and it reaches the store with the next host
    /// write — here its first report.
    /// Verifies: ADR-0035
    #[test]
    fn an_approval_whose_host_cannot_be_written_is_not_refused() {
        let store = FailingHosts::default();
        store.failing.store(true, Ordering::SeqCst);
        let revocations = Revocations::open(
            Box::new(store.clone()),
            Arc::new(Manual(AtomicU64::new(NOW))),
            Vec::new(),
        )
        .expect("open");
        let subject = SubjectValues {
            organization: "Kunde GmbH".into(),
            ..SubjectValues::default()
        };
        revocations
            .record(
                Facts {
                    subject_values: subject.clone(),
                    ..on_host("a1", "h1")
                },
                &[1; 16],
                None,
            )
            .expect("approved all the same");
        assert_eq!(store.inner.0.lock().expect("lock").issued.len(), 1);
        assert!(
            !store.inner.0.lock().expect("lock").hosts.contains_key("h1"),
            "the Host write failed"
        );
        assert_eq!(revocations.placement("h1"), (false, subject.clone()));

        store.failing.store(false, Ordering::SeqCst);
        revocations
            .check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            .expect("its first report");
        let host = store.inner.0.lock().expect("lock").hosts["h1"].clone();
        assert_eq!(
            host.subject, subject,
            "the approval's values reach the store"
        );
        assert_eq!(host.approved_ms, Some(NOW));
    }

    /// A host the prune forgets but cannot write fails neither an issuance nor a start.
    /// Verifies: ADR-0021
    #[test]
    fn a_failed_write_of_forgotten_hosts_fails_no_issuance_or_start() {
        let memory = Memory::default();
        // Its valid until is its certificate's end: a Host without one and without a register
        // entry would stay until its next admission (ADR-0047 clause 1).
        memory.0.lock().expect("lock").hosts = BTreeMap::from([(
            "old".to_string(),
            Host {
                valid_until_ms: Some(NOW - 1),
                ..Host::default()
            },
        )]);
        memory
            .put_issued(&Issued {
                facts: Facts {
                    host: Some("old".into()),
                    ..facts("a1", NOW - 1)
                },
                instance_uid: hex::encode([1; 16]),
                predecessor: None,
                issued_ms: 0,
            })
            .expect("seed");
        let clock = Arc::new(Manual(AtomicU64::new(NOW - 10)));
        let open_at = |clock: Arc<Manual>| {
            Revocations::open(Box::new(NoHosts(memory.clone())), clock, Vec::new())
        };
        let revocations = open_at(clock.clone()).expect("open");
        clock.0.store(NOW, Ordering::SeqCst);
        revocations
            .record(on_host("b2", "h1"), &[2; 16], None)
            .expect("issued all the same");
        let names: Vec<String> = revocations.hosts().into_iter().map(|(n, ..)| n).collect();
        assert_eq!(names, ["h1"], "old is forgotten");

        assert!(
            memory.0.lock().expect("lock").hosts.contains_key("old"),
            "the write failed"
        );
        // Started once b2 has expired too, the Server prunes as it opens.
        clock.0.store(NOW + 1_000_000, Ordering::SeqCst);
        let reopened = open_at(clock).expect("the Server starts");
        assert!(!reopened.hosts().iter().any(|(n, ..)| n == "old"));
    }

    /// A store whose host writes wait for a go-ahead.
    struct Held {
        inner: Memory,
        writing: std::sync::mpsc::SyncSender<()>,
        go: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl LedgerStore for Held {
        fn load(&self) -> Result<Ledger, String> {
            self.inner.load()
        }
        fn put_issued(&self, issued: &Issued) -> Result<(), String> {
            self.inner.put_issued(issued)
        }
        fn remove_issued(&self, id: &CertId) -> Result<(), String> {
            self.inner.remove_issued(id)
        }
        fn save_revocations(&self, revocations: &[Revocation]) -> Result<(), String> {
            self.inner.save_revocations(revocations)
        }
        fn save_hosts(&self, hosts: &BTreeMap<String, Host>) -> Result<(), String> {
            self.writing.send(()).map_err(|e| e.to_string())?;
            self.go
                .lock()
                .expect("lock")
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| "held past the test's patience".to_string())?;
            self.inner.save_hosts(hosts)
        }
    }

    /// A revocation check does not wait for the host register to reach the disk.
    /// Verifies: ADR-0021
    #[test]
    fn a_check_does_not_wait_for_a_host_write() {
        let (writing, written) = std::sync::mpsc::sync_channel(1);
        let (go, held) = std::sync::mpsc::channel();
        let revocations = Arc::new(
            Revocations::open(
                Box::new(Held {
                    inner: Memory::default(),
                    writing,
                    go: Mutex::new(held),
                }),
                Arc::new(Manual(AtomicU64::new(NOW))),
                Vec::new(),
            )
            .expect("open"),
        );
        let reporter = {
            let revocations = revocations.clone();
            std::thread::spawn(move || {
                revocations.check_report("h1", &SubjectValues::default(), FAR, &[1; 16])
            })
        };
        written.recv().expect("the binding is being written");
        assert!(!revocations.is_certificate_revoked(&id("a1")));
        assert_eq!(
            revocations.speaks_for("h1"),
            SpeaksFor::Agents([hex::encode([1; 16])].into())
        );
        go.send(()).expect("go");
        reporter
            .join()
            .expect("reporter")
            .expect("the binding is written");
    }

    /// A revocation check does not wait for the hosts a prune forgot to reach the disk.
    /// Verifies: ADR-0021
    #[test]
    fn a_check_does_not_wait_for_a_prune_to_write_the_hosts() {
        let memory = Memory::default();
        memory.0.lock().expect("lock").hosts =
            BTreeMap::from([("old".to_string(), Host::default())]);
        memory
            .put_issued(&Issued {
                facts: Facts {
                    host: Some("old".into()),
                    ..facts("a1", NOW - 1)
                },
                instance_uid: hex::encode([1; 16]),
                predecessor: None,
                issued_ms: 0,
            })
            .expect("seed");
        let (writing, written) = std::sync::mpsc::sync_channel(1);
        let (go, held) = std::sync::mpsc::channel();
        let clock = Arc::new(Manual(AtomicU64::new(NOW - 10)));
        let revocations = Arc::new(
            Revocations::open(
                Box::new(Held {
                    inner: memory.clone(),
                    writing,
                    go: Mutex::new(held),
                }),
                clock.clone(),
                Vec::new(),
            )
            .expect("open"),
        );
        clock.0.store(NOW, Ordering::SeqCst);
        let issuer = {
            let revocations = revocations.clone();
            std::thread::spawn(move || revocations.record(on_host("b2", "h1"), &[2; 16], None))
        };
        written
            .recv()
            .expect("the forgotten hosts are being written");
        assert!(!revocations.is_certificate_revoked(&id("b2")));
        go.send(()).expect("go");
        issuer.join().expect("issuer").expect("issued");
        assert!(!memory.0.lock().expect("lock").hosts.contains_key("old"));
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_revocation_follows_every_renewal() {
        let (revocations, _) = open(&Memory::default());
        let far = NOW + 1_000_000;
        revocations
            .record(facts("a1", far), &[1; 16], None)
            .expect("record");
        revocations
            .record(facts("b2", far), &[1; 16], Some(id("a1")))
            .expect("record");
        revocations
            .record(facts("c3", far), &[1; 16], Some(id("b2")))
            .expect("record");
        revocations
            .record(facts("d4", far), &[2; 16], None)
            .expect("record");

        revocations
            .revoke_certificate("client", "00:A1")
            .expect("revoke");
        assert!(revocations.is_certificate_revoked(&id("a1")));
        assert!(
            revocations.is_certificate_revoked(&id("c3")),
            "a renewal escaped the revocation of its ancestor"
        );
        assert!(!revocations.is_certificate_revoked(&id("d4")));
        assert!(matches!(
            revocations.revoke_certificate("bootstrap", "01"),
            Err(RevokeError::Invalid(_))
        ));
    }

    /// What clause 35 answers for `id`, worked out from the list and the register as they are
    /// listed: named on the list, itself or a predecessor in its register chain.
    fn expected_revoked(revocations: &Revocations, id: &CertId) -> bool {
        let named: BTreeSet<CertId> = revocations
            .list()
            .iter()
            .flat_map(|entry| {
                let Revoked::Certificate {
                    issuers, serial, ..
                } = &entry.revoked;
                issuers.iter().map(|issuer| CertId {
                    issuer: issuer.clone(),
                    serial: serial.clone(),
                })
            })
            .collect();
        let register: BTreeMap<CertId, Issued> = revocations
            .issued()
            .into_iter()
            .map(|issued| (issued.facts.id.clone(), issued))
            .collect();
        let mut current = Some(id.clone());
        while let Some(id) = current {
            if named.contains(&id) {
                return true;
            }
            current = register.get(&id).and_then(|i| i.predecessor.clone());
        }
        false
    }

    fn assert_answers(revocations: &Revocations, when: &str) {
        let ids: Vec<CertId> = ["a1", "b2", "c3", "d4", "e5", "f6", "ff", "99"]
            .into_iter()
            .map(id)
            .collect();
        for id in &ids {
            assert_eq!(
                revocations.is_certificate_revoked(id),
                expected_revoked(revocations, id),
                "{} {when}",
                id.serial
            );
        }
        let gateway: BTreeSet<CertId> = ids
            .iter()
            .filter(|id| {
                expected_revoked(revocations, id)
                    && (revocations.issued_entry(id).is_some()
                        || revocations.list().iter().any(|entry| {
                            matches!(&entry.revoked, Revoked::Certificate { serial, .. }
                                if *serial == id.serial)
                        }))
            })
            .cloned()
            .collect();
        assert_eq!(
            revocations.revoked_certificates("client"),
            gateway,
            "the Gateways' list {when}"
        );
    }

    /// The answer for every certificate follows the list and the register through revocations,
    /// renewals, lifts, an expiry and a restart.
    /// Verifies: ADR-0021
    #[test]
    fn a_revocation_answers_the_same_through_every_change() {
        let store = Memory::default();
        let (revocations, clock) = open(&store);
        let far = NOW + 1_000_000;
        revocations
            .record(facts("a1", NOW + 1_000), &[1; 16], None)
            .expect("record");
        revocations
            .record(facts("b2", far), &[1; 16], Some(id("a1")))
            .expect("record");
        revocations
            .record(facts("d4", NOW + 1_000), &[2; 16], None)
            .expect("record");
        assert_answers(&revocations, "before any revocation");
        revocations
            .revoke_certificate("client", "a1")
            .expect("revoke");
        assert_answers(&revocations, "after a1 is revoked");
        revocations
            .record(facts("c3", far), &[1; 16], Some(id("b2")))
            .expect("a renewal of a revoked chain");
        assert_answers(&revocations, "after b2 is renewed");
        revocations
            .revoke_certificate("client", "ff")
            .expect("one the register never held");
        revocations
            .record(facts("f6", far), &[3; 16], Some(id("ff")))
            .expect("a renewal of a provisioned certificate");
        assert_answers(&revocations, "after ff is revoked and renewed");
        revocations
            .revoke_certificate("client", "d4")
            .expect("revoke");
        assert_answers(&revocations, "after d4 is revoked");
        let a1 = revocations.list()[0].id.clone();
        assert!(revocations.lift(&a1).expect("lift"));
        assert_answers(&revocations, "after a1 is lifted");
        revocations
            .revoke_certificate("client", "a1")
            .expect("revoke");
        clock.0.fetch_add(1_000, Ordering::SeqCst);
        revocations
            .record(facts("e5", far), &[4; 16], None)
            .expect("a record prunes");
        assert!(revocations.issued_entry(&id("d4")).is_none(), "d4 expired");
        assert_answers(&revocations, "after d4 expired");
        drop(revocations);
        let (reopened, _) = open(&store);
        assert_answers(&reopened, "after a restart");
    }

    /// Checking a certificate does not build the revoked set again: it is built when the list
    /// changes, however many sessions check themselves against it.
    /// Verifies: ADR-0021
    #[test]
    fn a_check_does_not_rebuild_the_revoked_set() {
        let (revocations, _) = open(&Memory::default());
        let far = NOW + 1_000_000;
        revocations
            .record(facts("a1", far), &[1; 16], None)
            .expect("record");
        revocations
            .record(facts("b2", far), &[1; 16], Some(id("a1")))
            .expect("record");
        revocations
            .revoke_certificate("client", "a1")
            .expect("revoke");
        let rebuilds = || revocations.state.lock().expect("lock").rebuilds;
        let before = rebuilds();
        for _ in 0..1_000 {
            assert!(revocations.is_certificate_revoked(&id("b2")));
            assert!(!revocations.is_certificate_revoked(&id("cc")));
        }
        let _ = revocations.revoked_certificates("client");
        assert!(
            rebuilds() - before <= 1,
            "{} rebuilds for 2 001 checks",
            rebuilds() - before
        );
    }

    /// The revoked ancestor of a valid renewal outlives its own expiry, and so does every link
    /// between them.
    /// Verifies: ADR-0021
    #[test]
    fn a_renewal_stays_revoked_after_its_revoked_ancestor_expires() {
        let (revocations, clock) = open(&Memory::default());
        revocations
            .record(facts("a1", NOW + 1_000), &[1; 16], None)
            .expect("record");
        revocations
            .record(facts("b2", NOW + 2_000), &[1; 16], Some(id("a1")))
            .expect("record");
        revocations
            .record(facts("c3", NOW + 9_000), &[1; 16], Some(id("b2")))
            .expect("record");
        revocations
            .revoke_certificate("client", "a1")
            .expect("revoke");
        clock.0.fetch_add(5_000, Ordering::SeqCst);
        revocations
            .record(facts("e5", NOW + 9_000), &[3; 16], None)
            .expect("a record prunes");
        assert!(
            revocations.is_certificate_revoked(&id("c3")),
            "c3 escaped once a1 and b2 expired"
        );
        assert_eq!(revocations.list().len(), 1);
    }

    /// Verifies: ADR-0021
    #[test]
    fn the_list_survives_a_restart_and_can_be_lifted() {
        let store = Memory::default();
        {
            let (revocations, _) = open(&store);
            revocations
                .revoke_certificate("client", "ff")
                .expect("revoke");
        }
        let (revocations, _) = open(&store);
        let listed = revocations.list();
        assert_eq!(listed.len(), 1);
        assert!(revocations.is_certificate_revoked(&id("ff")));
        assert!(revocations.lift(&listed[0].id).expect("lift"));
        assert!(
            !revocations.lift(&listed[0].id).expect("lift"),
            "already gone"
        );
        let (reopened, _) = open(&store);
        assert!(reopened.list().is_empty());
    }

    /// Verifies: ADR-0021
    #[test]
    fn the_list_and_the_register_are_bounded() {
        let store = Memory::default();
        store
            .save_revocations(
                &(0..MAX_REVOCATIONS)
                    .map(|n| Revocation {
                        id: n.to_string(),
                        revoked: Revoked::Certificate {
                            authority: "client".into(),
                            issuers: vec![name_hash(CA)],
                            serial: format!("{n:x}"),
                        },
                        revoked_ms: NOW,
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("seed");
        let (revocations, _) = open(&store);
        assert_eq!(
            revocations.revoke_certificate("client", "abcdef0123"),
            Err(RevokeError::Full)
        );

        let (revocations, _) = open(&Memory::default());
        let far = NOW + 1_000_000;
        revocations
            .record(facts("1", far), &[1; 16], None)
            .expect("record");
        // Renewing the renewals does not escape the bound: it is the chain's, not each link's.
        let mut previous = id("1");
        for n in 1..MAX_DESCENDANTS_PER_ROOT {
            let serial = format!("{:x}", n + 16);
            revocations
                .record(facts(&serial, far), &[1; 16], Some(previous.clone()))
                .expect("record");
            if n % 2 == 0 {
                previous = id(&serial);
            }
        }
        assert!(
            revocations
                .record(facts("ffffff", far), &[1; 16], Some(previous))
                .is_err(),
            "one chain filled the register"
        );
    }

    /// Verifies: ADR-0021
    #[test]
    fn an_expired_register_entry_is_dropped_with_its_revocation() {
        let (revocations, clock) = open(&Memory::default());
        revocations
            .record(facts("a1", NOW + 1_000), &[1; 16], None)
            .expect("record");
        revocations
            .revoke_certificate("client", "a1")
            .expect("revoke");
        revocations
            .revoke_certificate("client", "bb")
            .expect("one the register never held");
        clock.0.fetch_add(1_000, Ordering::SeqCst);
        revocations
            .record(facts("cc", NOW + 9_000), &[2; 16], None)
            .expect("a record prunes");
        assert_eq!(revocations.issued().len(), 1);
        let left = revocations.list();
        assert_eq!(left.len(), 1);
        assert!(matches!(&left[0].revoked, Revoked::Certificate { serial, .. } if serial == "bb"));
    }

    /// A serial longer than RFC 5280's 20 octets is refused, so the list every Gateway reads stays
    /// within what a Gateway accepts; 20 octets, leading zeros and separators aside, are taken.
    /// Verifies: Q-2
    #[test]
    fn a_serial_longer_than_twenty_octets_is_refused() {
        let (revocations, _) = open(&Memory::default());
        assert!(matches!(
            revocations.revoke_certificate("client", &"ab".repeat(21)),
            Err(RevokeError::Invalid(_))
        ));
        revocations
            .revoke_certificate("client", &format!("00:{}", "ab".repeat(20)))
            .expect("20 octets");
    }

    #[test]
    fn a_serial_that_is_not_hex_is_refused() {
        let (revocations, _) = open(&Memory::default());
        assert!(matches!(
            revocations.revoke_certificate("client", "xyz"),
            Err(RevokeError::Invalid(_))
        ));
    }

    /// A reload finds every chain's root from its links, whatever order the entries load in.
    /// Verifies: ADR-0021
    #[test]
    fn a_reload_keeps_each_chain_under_its_root() {
        let store = Memory::default();
        let far = NOW + 1_000_000;
        {
            let (revocations, clock) = open(&store);
            revocations
                .record(facts("a1", far), &[1; 16], None)
                .expect("record");
            // A clock that stepped back: the renewal sorts before its predecessor.
            clock.0.fetch_sub(10, Ordering::SeqCst);
            revocations
                .record(facts("b2", far), &[1; 16], Some(id("a1")))
                .expect("record");
        }
        let (revocations, _) = open(&store);
        let state = revocations.state.lock().expect("lock");
        assert_eq!(state.roots.get(&id("b2")), Some(&id("a1")));
        assert_eq!(state.descendants.get(&id("a1")), Some(&2));
    }
}
