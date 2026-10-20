//! Bootstrap certificates the Server issues (ADR-0028).
//!
//! An operator asks for one with a subject naming at least a customer and a site, and a password
//! (ADR-0036 clauses 1 and 8). The key never leaves in PEM: the Server seals it with its
//! certificate into a PKCS#12 file under that password, keeps the file and hands it out on request
//! until the certificate ends or is revoked; the password it keeps nowhere (ADR-0029). The Server
//! keeps the certificate's facts, never its key in the clear, so it can list what is valid and an
//! operator can revoke one by its serial (ADR-0021 clause 34). A bootstrap certificate opens
//! nothing on its own: it needs an open enrolment window and an operator's approval (ADR-0021
//! clauses 20, 21).
//!
//! The signing is the [`BootstrapSigner`] port, the bootstrap CA in [`crate::ca`] its adapter; the
//! record is the [`BootstrapStore`] port, `bootstrap/` under `data_dir` its adapter (ADR-0037).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::fleet::Clock;
use crate::revocation::{CertId, SubjectValues};

/// A bootstrap certificate's life when the request names none (ADR-0028 clause 23).
pub const DEFAULT_VALIDITY_DAYS: u32 = 10;

/// The longest life a request may ask for (ADR-0028 clause 23).
pub const MAX_VALIDITY_DAYS: u32 = 90;

/// The valid bootstrap certificates the record holds at most (ADR-0028 clause 24).
pub const MAX_VALID: usize = 10_000;

/// The longest value of a subject attribute: RFC 5280's upper bound for the names that have one.
pub const MAX_VALUE_CHARS: usize = 64;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The subject an operator names (ADR-0036 clause 1): six attributes, `organization` and
/// `organizational_unit` required and the others optional. The Server sets the common name. The
/// values describe and select; they authorize nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// C — two upper-case letters, ISO 3166-1 alpha-2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// ST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// L.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// O — the customer, typically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// OU — the site, typically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizational_unit: Option<String>,
    /// organizationIdentifier (2.5.4.97) — a customer or contract number, in no format of the
    /// Server's choosing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_identifier: Option<String>,
}

/// An attribute of a bootstrap certificate's subject, in the order a certificate lists them
/// (ADR-0036 clause 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribute {
    Country,
    State,
    Locality,
    Organization,
    OrganizationalUnit,
    OrganizationIdentifier,
    CommonName,
}

impl Attribute {
    /// The six attributes a host certificate carries over from its bootstrap certificate, in
    /// certificate order (ADR-0036 clauses 1 to 4).
    pub const CARRIED: [Attribute; 6] = [
        Attribute::Country,
        Attribute::State,
        Attribute::Locality,
        Attribute::Organization,
        Attribute::OrganizationalUnit,
        Attribute::OrganizationIdentifier,
    ];

    /// The name a request, a list and a refusal give it.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Attribute::Country => "country",
            Attribute::State => "state",
            Attribute::Locality => "locality",
            Attribute::Organization => "organization",
            Attribute::OrganizationalUnit => "organizational_unit",
            Attribute::OrganizationIdentifier => "organization_identifier",
            Attribute::CommonName => "common_name",
        }
    }

    /// Its object identifier, X.520.
    #[must_use]
    pub fn oid(self) -> &'static str {
        match self {
            Attribute::Country => "2.5.4.6",
            Attribute::State => "2.5.4.8",
            Attribute::Locality => "2.5.4.7",
            Attribute::Organization => "2.5.4.10",
            Attribute::OrganizationalUnit => "2.5.4.11",
            Attribute::OrganizationIdentifier => "2.5.4.97",
            Attribute::CommonName => "2.5.4.3",
        }
    }

    /// Whether a certificate carries it as a `PrintableString`; every other attribute is a
    /// `UTF8String`.
    #[must_use]
    pub fn printable(self) -> bool {
        self == Attribute::Country
    }

    /// Checks a value against ADR-0036 clause 1: a country of exactly two upper-case letters,
    /// any other value 1 to [`MAX_VALUE_CHARS`] characters without a control character.
    ///
    /// # Errors
    /// Returns why the value is refused, naming the attribute.
    pub fn check(self, value: &str) -> Result<(), String> {
        let name = self.key();
        if self == Attribute::Country {
            if value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase()) {
                return Ok(());
            }
            return Err(format!(
                "{name} must be two upper-case letters, an ISO 3166-1 alpha-2 code"
            ));
        }
        let chars = value.chars().count();
        if chars == 0 || chars > MAX_VALUE_CHARS {
            return Err(format!("{name} must be 1 to {MAX_VALUE_CHARS} characters"));
        }
        if value.chars().any(char::is_control) {
            return Err(format!("{name} must not carry a control character"));
        }
        Ok(())
    }

    /// Its value in `values`; empty when they hold none.
    #[must_use]
    pub fn of(self, values: &SubjectValues) -> &str {
        match self {
            Attribute::Country => &values.country,
            Attribute::State => &values.state,
            Attribute::Locality => &values.locality,
            Attribute::Organization => &values.organization,
            Attribute::OrganizationalUnit => &values.organizational_unit,
            Attribute::OrganizationIdentifier => &values.organization_identifier,
            Attribute::CommonName => "",
        }
    }

    /// Puts `value` into `values` as this attribute's; a common name has no place there.
    pub fn set(self, values: &mut SubjectValues, value: String) {
        let slot = match self {
            Attribute::Country => &mut values.country,
            Attribute::State => &mut values.state,
            Attribute::Locality => &mut values.locality,
            Attribute::Organization => &mut values.organization,
            Attribute::OrganizationalUnit => &mut values.organizational_unit,
            Attribute::OrganizationIdentifier => &mut values.organization_identifier,
            Attribute::CommonName => return,
        };
        *slot = value;
    }
}

/// The attributes `values` hold, in certificate order, ending with `common_name`: the subject of
/// a host certificate (ADR-0036 clause 2).
#[must_use]
pub fn carried_attributes(values: &SubjectValues, common_name: &str) -> Vec<(Attribute, String)> {
    let mut attributes: Vec<(Attribute, String)> = Attribute::CARRIED
        .into_iter()
        .filter(|attribute| !attribute.of(values).is_empty())
        .map(|attribute| (attribute, attribute.of(values).to_string()))
        .collect();
    attributes.push((Attribute::CommonName, common_name.to_string()));
    attributes
}

impl Subject {
    /// The attributes to sign, in certificate order, ending with the common name the Server sets.
    ///
    /// # Errors
    /// Returns the `400` text for a missing `organization` or `organizational_unit`, or a value
    /// that breaks ADR-0036 clause 1, naming the attribute.
    pub fn attributes(&self, common_name: &str) -> Result<Vec<(Attribute, String)>, String> {
        for (attribute, value) in [
            (Attribute::Organization, &self.organization),
            (Attribute::OrganizationalUnit, &self.organizational_unit),
        ] {
            if value.is_none() {
                return Err(format!(
                    "subject.{} is required, so every Host names a customer and a site",
                    attribute.key()
                ));
            }
        }
        let named = [
            (Attribute::Country, &self.country),
            (Attribute::State, &self.state),
            (Attribute::Locality, &self.locality),
            (Attribute::Organization, &self.organization),
            (Attribute::OrganizationalUnit, &self.organizational_unit),
            (
                Attribute::OrganizationIdentifier,
                &self.organization_identifier,
            ),
        ];
        let mut attributes = Vec::new();
        for (attribute, value) in named {
            let Some(value) = value else { continue };
            attribute.check(value).map_err(|e| format!("subject.{e}"))?;
            attributes.push((attribute, value.clone()));
        }
        attributes.push((Attribute::CommonName, common_name.to_string()));
        Ok(attributes)
    }
}

/// What an operator asks for (`POST /api/v1/bootstrap-certificates`).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    #[serde(default)]
    pub subject: Subject,
    /// 1 to 90; 10 when absent.
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// The password of the PKCS#12 file the key is sealed in (ADR-0029, ADR-0036 clause 8).
    /// Required; read as absent when it is missing, so the refusal names it.
    #[serde(default)]
    pub password: Option<Password>,
}

/// A password, which no `Debug` and no log line shows (ADR-0029 clause 2).
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Password(pub String);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
}

/// A certificate the signer made, with the key that belongs to it sealed with the certificate into
/// a PKCS#12 file under the password the request named; the key is never handed out in PEM
/// (ADR-0036 clause 8).
#[derive(Clone)]
pub struct Pair {
    pub id: CertId,
    /// The serial as the certificate carries it, hex.
    pub serial: String,
    /// The subject as text.
    pub subject: String,
    /// The SHA-256 of the public key, hex.
    pub key_fingerprint: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub certificate_pem: String,
    /// The PKCS#12 file (ADR-0029 clause 1).
    pub pkcs12: Vec<u8>,
}

impl std::fmt::Debug for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pair")
            .field("serial", &self.serial)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// The port that signs a bootstrap certificate: the bootstrap CA with its key.
pub trait BootstrapSigner: Send + Sync {
    /// The common name a bootstrap certificate carries, derived from the bootstrap CA's
    /// (ADR-0028 clause 28).
    fn leaf_common_name(&self) -> String;

    /// When the bootstrap CA ends, in milliseconds since the epoch.
    fn ca_not_after_ms(&self) -> u64;

    /// The SHA-256 of the bootstrap CA's public key, hex: what tells this CA from the one it
    /// replaced, whose name it shares.
    fn ca_key_fingerprint(&self) -> String;

    /// Makes a fresh key and signs a client-authentication leaf for it, valid from `now_ms`
    /// less the allowance for clocks that disagree until `not_after_ms`. The key is sealed with
    /// the certificate into a PKCS#12 file under `password` and not handed back in PEM
    /// (ADR-0036 clause 8).
    ///
    /// # Errors
    /// Returns an error when no key can be made, the certificate cannot be signed, or the file
    /// cannot be written.
    fn sign(
        &self,
        subject: &[(Attribute, String)],
        now_ms: u64,
        not_after_ms: u64,
        password: &str,
    ) -> Result<Pair, String>;
}

/// What the record keeps of a bootstrap certificate — never its key in the clear (ADR-0028
/// clause 24, ADR-0029 clause 4).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Entry {
    pub id: CertId,
    pub serial: String,
    pub subject: String,
    pub key_fingerprint: String,
    pub issued_ms: u64,
    pub not_after_ms: u64,
    /// The issuing CA's key fingerprint: an entry of a CA since replaced is forgotten.
    #[serde(default)]
    pub ca_key: String,
    /// Whether the store keeps its PKCS#12 file, for download (ADR-0029 clause 4).
    #[serde(default)]
    pub p12: bool,
}

/// The port the record persists through: one document per certificate, keyed by its issuer and
/// serial as every certificate store keys one (ADR-0037 clause 13).
pub trait BootstrapStore: Send + Sync {
    /// Every entry persisted.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    fn load(&self) -> Result<Vec<Entry>, String>;

    /// Persists one entry.
    ///
    /// # Errors
    /// Returns an error when it cannot be written.
    fn put(&self, entry: &Entry) -> Result<(), String>;

    /// Forgets one entry, and its PKCS#12 file with it.
    ///
    /// # Errors
    /// Returns an error when it cannot be removed.
    fn remove(&self, id: &CertId) -> Result<(), String>;

    /// Keeps the PKCS#12 file of one entry, owner-only.
    ///
    /// # Errors
    /// Returns an error when it cannot be written.
    fn put_p12(&self, id: &CertId, file: &[u8]) -> Result<(), String>;

    /// The PKCS#12 file of one entry, `None` when there is none.
    ///
    /// # Errors
    /// Returns an error when it cannot be read.
    fn p12(&self, id: &CertId) -> Result<Option<Vec<u8>>, String>;

    /// Forgets the PKCS#12 file of one entry, keeping the entry.
    ///
    /// # Errors
    /// Returns an error when it cannot be removed.
    fn remove_p12(&self, id: &CertId) -> Result<(), String>;
}

/// Why a bootstrap certificate was not issued.
#[derive(Debug)]
pub enum IssueError {
    /// No `[enrolment] bootstrap_ca_key_file` — `409`.
    NoKey,
    /// The request is not one this Server signs — `400`.
    Invalid(String),
    /// [`MAX_VALID`] valid certificates are on record — `409`.
    Full,
    /// The bootstrap CA has ended; what it signs now would be dead on arrival — `409`.
    CaEnded,
    /// The record or the signer failed — `500`.
    Failed(String),
}

/// Why a bootstrap certificate's entry was not deleted (ADR-0029 clause 15).
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteError {
    /// No certificate on record under that serial — `404`.
    NotFound,
    /// The certificate is not revoked — `409`.
    NotRevoked,
    /// The audit record cannot be written — `503`.
    Unrecorded,
    /// The store failed — `500`.
    Failed(String),
}

/// The bootstrap certificates the Server issued and still holds valid.
pub struct BootstrapCertificates {
    signer: Option<Box<dyn BootstrapSigner>>,
    store: Box<dyn BootstrapStore>,
    clock: Arc<dyn Clock>,
    /// Keyed by issuer and serial.
    entries: Mutex<BTreeMap<CertId, Entry>>,
}

impl BootstrapCertificates {
    /// Opens the record and forgets what has ended, and — with a signer — what a bootstrap CA
    /// since replaced issued, which no longer passes the handshake. Without a signer the Server
    /// issues nothing and still lists what it issued before.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    pub fn open(
        signer: Option<Box<dyn BootstrapSigner>>,
        store: Box<dyn BootstrapStore>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        let current = signer.as_ref().map(|signer| signer.ca_key_fingerprint());
        let mut entries = BTreeMap::new();
        for entry in store.load()? {
            if current
                .as_ref()
                .is_some_and(|ca_key| *ca_key != entry.ca_key)
            {
                store.remove(&entry.id)?;
            } else {
                entries.insert(entry.id.clone(), entry);
            }
        }
        let record = BootstrapCertificates {
            signer,
            store,
            clock,
            entries: Mutex::new(entries),
        };
        record.prune(&mut record.entries.lock().expect("bootstrap record lock"))?;
        Ok(record)
    }

    /// Whether the Server holds the bootstrap CA's key.
    #[must_use]
    pub fn can_issue(&self) -> bool {
        self.signer.is_some()
    }

    /// Issues one bootstrap certificate and records it before answering (ADR-0028 clauses 21 to 24).
    ///
    /// # Errors
    /// See [`IssueError`].
    pub fn issue(&self, request: &IssueRequest) -> Result<Pair, IssueError> {
        let Some(signer) = &self.signer else {
            return Err(IssueError::NoKey);
        };
        let days = request.validity_days.unwrap_or(DEFAULT_VALIDITY_DAYS);
        if !(1..=MAX_VALIDITY_DAYS).contains(&days) {
            return Err(IssueError::Invalid(format!(
                "validity_days must be 1 to {MAX_VALIDITY_DAYS}"
            )));
        }
        let attributes = request
            .subject
            .attributes(&signer.leaf_common_name())
            .map_err(IssueError::Invalid)?;
        let Some(Password(password)) = &request.password else {
            return Err(IssueError::Invalid(
                "password is required: the Server keeps the key only in a PKCS#12 file under it"
                    .to_string(),
            ));
        };
        fleet_core::pkcs12::check_password(password).map_err(IssueError::Invalid)?;
        self.room()?;
        let now = self.clock.now_ms();
        if signer.ca_not_after_ms() <= now {
            return Err(IssueError::CaEnded);
        }
        // Never past the CA (ADR-0028 clause 23).
        let not_after = (now + u64::from(days) * DAY_MS).min(signer.ca_not_after_ms());
        // Outside the record's lock: sealing a PKCS#12 file derives three keys of 600 000
        // iterations, and the list and the download must not wait for it (ADR-0029).
        let pair = signer
            .sign(&attributes, now, not_after, password)
            .map_err(IssueError::Failed)?;
        let mut entries = self.entries.lock().expect("bootstrap record lock");
        self.prune(&mut entries).map_err(IssueError::Failed)?;
        if entries.len() >= MAX_VALID {
            return Err(IssueError::Full);
        }
        let entry = Entry {
            id: pair.id.clone(),
            serial: pair.serial.clone(),
            subject: pair.subject.clone(),
            key_fingerprint: pair.key_fingerprint.clone(),
            issued_ms: now,
            not_after_ms: pair.not_after_ms,
            ca_key: signer.ca_key_fingerprint(),
            p12: true,
        };
        // The file before the entry that says it is there (ADR-0029 clause 4), and gone again
        // when the entry cannot be written: no file is kept that no entry ends.
        self.store
            .put_p12(&entry.id, &pair.pkcs12)
            .map_err(IssueError::Failed)?;
        if let Err(e) = self.store.put(&entry) {
            let _ = self.store.remove_p12(&entry.id);
            return Err(IssueError::Failed(e));
        }
        entries.insert(entry.id.clone(), entry);
        Ok(pair)
    }

    /// Whether the record has room for one more valid certificate.
    fn room(&self) -> Result<(), IssueError> {
        let mut entries = self.entries.lock().expect("bootstrap record lock");
        self.prune(&mut entries).map_err(IssueError::Failed)?;
        if entries.len() >= MAX_VALID {
            return Err(IssueError::Full);
        }
        Ok(())
    }

    /// The valid bootstrap certificates on record, oldest first.
    #[must_use]
    pub fn list(&self) -> Vec<Entry> {
        let mut entries = self.entries.lock().expect("bootstrap record lock");
        // A failed removal leaves an ended entry for the next call; the list still shows only
        // what is valid.
        let _ = self.prune(&mut entries);
        let now = self.clock.now_ms();
        let mut list: Vec<Entry> = entries
            .values()
            .filter(|entry| entry.not_after_ms > now)
            .cloned()
            .collect();
        list.sort_by(|a, b| a.issued_ms.cmp(&b.issued_ms).then(a.serial.cmp(&b.serial)));
        list
    }

    /// The entry of a valid certificate and its PKCS#12 file, `None` when the certificate is not
    /// on record, has ended, or has no file (ADR-0029 clause 4). Whether it is revoked is the
    /// caller's to tell, from the revocation list.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read.
    pub fn p12(&self, serial: &str) -> Result<Option<(Entry, Vec<u8>)>, String> {
        let mut entries = self.entries.lock().expect("bootstrap record lock");
        self.prune(&mut entries)?;
        let Some(entry) = self.in_force(&entries, serial).filter(|entry| entry.p12) else {
            return Ok(None);
        };
        Ok(self.store.p12(&entry.id)?.map(|file| (entry.clone(), file)))
    }

    /// Deletes a revoked certificate's entry and any PKCS#12 file of it (ADR-0029 clause 15).
    /// `revoked` tells whether the entry is revoked, and `recorded` puts the deletion on the audit
    /// record; both run under the record's lock with the removal, so a second request, or a
    /// revocation lifted meanwhile, cannot slip between the check and the deletion.
    ///
    /// # Errors
    /// See [`DeleteError`]; on every error the entry is kept.
    pub fn delete(
        &self,
        serial: &str,
        revoked: impl FnOnce(&Entry) -> bool,
        recorded: impl FnOnce(&Entry) -> bool,
    ) -> Result<Entry, DeleteError> {
        let mut entries = self.entries.lock().expect("bootstrap record lock");
        self.prune(&mut entries).map_err(DeleteError::Failed)?;
        let entry = self
            .in_force(&entries, serial)
            .cloned()
            .ok_or(DeleteError::NotFound)?;
        if !revoked(&entry) {
            return Err(DeleteError::NotRevoked);
        }
        if !recorded(&entry) {
            return Err(DeleteError::Unrecorded);
        }
        self.store.remove(&entry.id).map_err(DeleteError::Failed)?;
        entries.remove(&entry.id);
        Ok(entry)
    }

    /// Forgets the PKCS#12 file of a certificate, which a revocation does before it is answered
    /// (ADR-0029 clause 4). A certificate without one is left as it is.
    ///
    /// # Errors
    /// Returns an error when the file or the entry cannot be written.
    pub fn forget_p12(&self, serial: &str) -> Result<(), String> {
        let mut entries = self.entries.lock().expect("bootstrap record lock");
        let Some(id) = self
            .in_force(&entries, serial)
            .filter(|entry| entry.p12)
            .map(|entry| entry.id.clone())
        else {
            return Ok(());
        };
        // The entry first, so it never names a file that is gone — and a file left by a failed
        // removal is never handed out, since the entry no longer says it is there.
        let mut forgotten = entries[&id].clone();
        forgotten.p12 = false;
        self.store.put(&forgotten)?;
        entries.insert(id.clone(), forgotten);
        self.store.remove_p12(&id)
    }

    /// The entry a REST `{serial}` names: the one of the bootstrap CA in force (ADR-0037
    /// clause 13). Without the CA's key, the Server holds entries of whichever CA issued them, and
    /// the newest of that serial is the one meant.
    fn in_force<'a>(
        &self,
        entries: &'a BTreeMap<CertId, Entry>,
        serial: &str,
    ) -> Option<&'a Entry> {
        let current = self
            .signer
            .as_ref()
            .map(|signer| signer.ca_key_fingerprint());
        entries
            .values()
            .filter(|entry| entry.serial == serial)
            .filter(|entry| {
                current
                    .as_ref()
                    .is_none_or(|ca_key| *ca_key == entry.ca_key)
            })
            .max_by_key(|entry| entry.issued_ms)
    }

    /// Forgets every certificate that has ended (ADR-0028 clause 24).
    fn prune(&self, entries: &mut BTreeMap<CertId, Entry>) -> Result<(), String> {
        let now = self.clock.now_ms();
        let ended: Vec<CertId> = entries
            .values()
            .filter(|entry| entry.not_after_ms <= now)
            .map(|entry| entry.id.clone())
            .collect();
        for id in ended {
            self.store.remove(&id)?;
            entries.remove(&id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FixedClock(AtomicU64);
    impl Clock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[derive(Default)]
    struct MemoryStore(
        Mutex<BTreeMap<CertId, Entry>>,
        Mutex<BTreeMap<CertId, Vec<u8>>>,
        std::sync::atomic::AtomicBool,
    );
    impl BootstrapStore for Arc<MemoryStore> {
        fn load(&self) -> Result<Vec<Entry>, String> {
            Ok(self.0.lock().unwrap().values().cloned().collect())
        }
        fn put(&self, entry: &Entry) -> Result<(), String> {
            if self.2.load(Ordering::SeqCst) {
                return Err("the disk is full".to_string());
            }
            self.0
                .lock()
                .unwrap()
                .insert(entry.id.clone(), entry.clone());
            Ok(())
        }
        fn remove(&self, id: &CertId) -> Result<(), String> {
            self.0.lock().unwrap().remove(id);
            self.1.lock().unwrap().remove(id);
            Ok(())
        }
        fn put_p12(&self, id: &CertId, file: &[u8]) -> Result<(), String> {
            self.1.lock().unwrap().insert(id.clone(), file.to_vec());
            Ok(())
        }
        fn p12(&self, id: &CertId) -> Result<Option<Vec<u8>>, String> {
            Ok(self.1.lock().unwrap().get(id).cloned())
        }
        fn remove_p12(&self, id: &CertId) -> Result<(), String> {
            self.1.lock().unwrap().remove(id);
            Ok(())
        }
    }

    /// Signs nothing real: hands back what it was asked for, so the rules around it can be read.
    struct EchoSigner {
        ca_end_ms: u64,
        serial: AtomicU64,
    }
    impl BootstrapSigner for EchoSigner {
        fn leaf_common_name(&self) -> String {
            fleet_core::naming::leaf_common_name("Acme Bootstrap CA")
        }
        fn ca_not_after_ms(&self) -> u64 {
            self.ca_end_ms
        }
        fn ca_key_fingerprint(&self) -> String {
            format!("ca-{}", self.ca_end_ms)
        }
        fn sign(
            &self,
            subject: &[(Attribute, String)],
            now_ms: u64,
            not_after_ms: u64,
            password: &str,
        ) -> Result<Pair, String> {
            let serial = format!("{:x}", self.serial.fetch_add(1, Ordering::SeqCst) + 1);
            Ok(Pair {
                id: CertId::new(b"issuer", &serial),
                serial,
                subject: subject
                    .iter()
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                key_fingerprint: String::new(),
                not_before_ms: now_ms,
                not_after_ms,
                certificate_pem: String::new(),
                pkcs12: format!("sealed under {password}").into_bytes(),
            })
        }
    }

    fn fixture(ca_end_ms: u64) -> (BootstrapCertificates, Arc<FixedClock>, Arc<MemoryStore>) {
        let clock = Arc::new(FixedClock(AtomicU64::new(1_000)));
        let store = Arc::new(MemoryStore::default());
        let record = BootstrapCertificates::open(
            Some(Box::new(EchoSigner {
                ca_end_ms,
                serial: AtomicU64::new(0),
            })),
            Box::new(store.clone()),
            clock.clone(),
        )
        .expect("open");
        (record, clock, store)
    }

    /// A request with a customer, a site and a password, each replaced by what `json` names.
    fn request(json: serde_json::Value) -> IssueRequest {
        let mut full = serde_json::json!({
            "subject": {"organization": "Kunde GmbH", "organizational_unit": "Werk Nord"},
            "password": "twelve chars",
        });
        for (key, value) in json.as_object().expect("an object") {
            full[key] = value.clone();
        }
        serde_json::from_value(full).expect("request")
    }

    /// The smallest request that issues.
    fn valid() -> IssueRequest {
        request(serde_json::json!({}))
    }

    /// The customer and site every subject needs, with `more` beside them.
    fn with_site(more: serde_json::Value) -> Subject {
        let mut full = serde_json::json!({
            "organization": "Kunde GmbH",
            "organizational_unit": "Werk Nord",
        });
        for (key, value) in more.as_object().expect("an object") {
            full[key] = value.clone();
        }
        serde_json::from_value(full).expect("subject")
    }

    /// A subject takes the six attributes of ADR-0036 clause 1 and nothing else, each within its
    /// bounds, and lists them in certificate order before the common name the Server sets.
    /// Verifies: ADR-0036
    #[test]
    fn a_subject_takes_six_attributes_within_bounds() {
        for unknown in ["common_name", "email", "serial_number", "street"] {
            let refused = serde_json::from_value::<IssueRequest>(
                serde_json::json!({"subject": {unknown: "x"}}),
            );
            assert!(refused.is_err(), "{unknown} is refused");
        }
        let twice = serde_json::from_str::<IssueRequest>(
            r#"{"subject": {"organization": "a", "organization": "b"}}"#,
        );
        assert!(twice.is_err(), "an attribute named twice is refused");
        for (bad, named) in [
            (serde_json::json!({"country": "at"}), "country"),
            (serde_json::json!({"country": "AUT"}), "country"),
            (serde_json::json!({"country": ""}), "country"),
            (serde_json::json!({"country": "Ö1"}), "country"),
            (serde_json::json!({"organization": ""}), "organization"),
            (serde_json::json!({"state": "x".repeat(65)}), "state"),
            (
                serde_json::json!({"organizational_unit": "a\nb"}),
                "organizational_unit",
            ),
            (
                serde_json::json!({"organization_identifier": "a\u{7}b"}),
                "organization_identifier",
            ),
        ] {
            let refused = with_site(bad.clone())
                .attributes("cn")
                .expect_err("refused");
            assert!(
                refused.starts_with(&format!("subject.{named} ")),
                "{bad} is refused naming {named}: {refused}"
            );
        }
        let subject: Subject = serde_json::from_value(serde_json::json!({
            "organization_identifier": "6f1c0b9e-2a4d-4c55-9b1e-0d2f3a4b5c6d",
            "organizational_unit": "Werk Nord",
            "organization": "Kunde GmbH",
            "locality": "Linz",
            "state": "Oberösterreich",
            "country": "AT",
        }))
        .expect("subject");
        assert_eq!(
            subject.attributes("acme bootstrap").expect("valid"),
            vec![
                (Attribute::Country, "AT".to_string()),
                (Attribute::State, "Oberösterreich".to_string()),
                (Attribute::Locality, "Linz".to_string()),
                (Attribute::Organization, "Kunde GmbH".to_string()),
                (Attribute::OrganizationalUnit, "Werk Nord".to_string()),
                (
                    Attribute::OrganizationIdentifier,
                    "6f1c0b9e-2a4d-4c55-9b1e-0d2f3a4b5c6d".to_string()
                ),
                (Attribute::CommonName, "acme bootstrap".to_string()),
            ]
        );
        assert_eq!(
            with_site(serde_json::json!({}))
                .attributes("acme bootstrap")
                .expect("a customer and a site are enough"),
            vec![
                (Attribute::Organization, "Kunde GmbH".to_string()),
                (Attribute::OrganizationalUnit, "Werk Nord".to_string()),
                (Attribute::CommonName, "acme bootstrap".to_string()),
            ]
        );
    }

    /// Organization and organizational unit are required, and a request without either, or
    /// without a password, issues nothing and is refused naming the field (ADR-0036 clauses 1
    /// and 8).
    /// Verifies: ADR-0036
    #[test]
    fn an_issue_without_a_customer_a_site_or_a_password_is_refused_naming_it() {
        let (record, _, store) = fixture(u64::MAX);
        for (json, named) in [
            (
                serde_json::json!({"subject": {"organizational_unit": "Werk Nord"}}),
                "subject.organization ",
            ),
            (
                serde_json::json!({"subject": {"organization": "Kunde GmbH"}}),
                "subject.organizational_unit ",
            ),
            (serde_json::json!({"subject": {}}), "subject.organization "),
            (serde_json::json!({"password": null}), "password "),
        ] {
            let Err(IssueError::Invalid(why)) = record.issue(&request(json.clone())) else {
                panic!("{json} is refused as invalid");
            };
            assert!(
                why.starts_with(named) && why.contains("required"),
                "{json}: {why}"
            );
        }
        assert!(record.list().is_empty(), "nothing issued");
        assert!(store.1.lock().unwrap().is_empty(), "no file kept");
    }

    /// Verifies: ADR-0028
    #[test]
    fn a_certificate_lives_ten_days_by_default_at_most_ninety_and_never_past_its_ca() {
        let (record, _, _) = fixture(u64::MAX);
        let pair = record.issue(&valid()).expect("issued");
        assert_eq!(pair.not_after_ms, 1_000 + 10 * DAY_MS);
        assert_eq!(
            pair.subject, "Kunde GmbH,Werk Nord,Acme Bootstrap Certificate",
            "the common name is the CA's name with ` CA` turned into ` Certificate`"
        );
        for days in [0, 91] {
            let refused = record.issue(&request(serde_json::json!({"validity_days": days})));
            assert!(matches!(refused, Err(IssueError::Invalid(_))), "{days}");
        }
        let (short, _, _) = fixture(1_000 + 3 * DAY_MS);
        let pair = short
            .issue(&request(serde_json::json!({"validity_days": 90})))
            .expect("issued");
        assert_eq!(pair.not_after_ms, 1_000 + 3 * DAY_MS, "cut to the CA's end");
    }

    /// A CA that has ended signs nothing: its certificate would be dead on arrival.
    /// Verifies: ADR-0028
    #[test]
    fn an_ended_ca_issues_nothing() {
        let (record, _, _) = fixture(1_000);
        assert!(matches!(record.issue(&valid()), Err(IssueError::CaEnded)));
    }

    /// After the bootstrap CA is replaced, what the old one issued no longer passes the
    /// handshake, so it is no longer listed.
    /// Verifies: ADR-0028
    #[test]
    fn what_a_replaced_ca_issued_is_forgotten() {
        let (record, clock, store) = fixture(u64::MAX);
        record.issue(&valid()).expect("issued");
        let reopened = BootstrapCertificates::open(
            Some(Box::new(EchoSigner {
                ca_end_ms: u64::MAX - 1,
                serial: AtomicU64::new(100),
            })),
            Box::new(store.clone()),
            clock,
        )
        .expect("open");
        assert!(reopened.list().is_empty());
        assert!(
            store.0.lock().unwrap().is_empty(),
            "removed from the store too"
        );
    }

    /// Verifies: ADR-0028
    #[test]
    fn the_record_lists_what_is_valid_and_forgets_what_ended() {
        let (record, clock, store) = fixture(u64::MAX);
        let first = record
            .issue(&request(serde_json::json!({"validity_days": 1})))
            .expect("issued");
        record
            .issue(&request(serde_json::json!({"validity_days": 5})))
            .expect("issued");
        assert_eq!(record.list().len(), 2);
        assert_eq!(store.0.lock().unwrap().len(), 2, "written before answered");
        clock.0.store(1_000 + 2 * DAY_MS, Ordering::SeqCst);
        let listed = record.list();
        assert_eq!(listed.len(), 1);
        assert_ne!(listed[0].serial, first.serial);
        assert_eq!(store.0.lock().unwrap().len(), 1, "the ended one is removed");
    }

    /// Verifies: ADR-0028
    #[test]
    fn without_the_key_nothing_is_issued() {
        let store = Arc::new(MemoryStore::default());
        let record = BootstrapCertificates::open(
            None,
            Box::new(store),
            Arc::new(FixedClock(AtomicU64::new(0))),
        )
        .expect("open");
        assert!(!record.can_issue());
        assert!(matches!(record.issue(&valid()), Err(IssueError::NoKey)));
    }

    /// A password of eight characters is taken and one of seven is not.
    /// Verifies: ADR-0048
    #[test]
    fn a_password_of_eight_characters_issues_a_file_and_one_of_seven_nothing() {
        let (record, _clock, _store) = fixture(u64::MAX);
        let short = record.issue(&request(serde_json::json!({"password": "seven c"})));
        assert!(
            matches!(&short, Err(IssueError::Invalid(e)) if e == "password must be 8 to 128 characters"),
            "{short:?}"
        );
        assert!(record.list().is_empty(), "nothing issued");
        let sealed = record
            .issue(&request(serde_json::json!({"password": "eight ch"})))
            .expect("issued");
        let (_, file) = record.p12(&sealed.serial).expect("read").expect("kept");
        assert_eq!(file, b"sealed under eight ch");
    }

    /// The Server keeps the file, not the key, and hands it out until the certificate ends or a
    /// revocation forgets it; a password out of bounds issues nothing.
    /// Verifies: ADR-0029, ADR-0036
    #[test]
    fn every_certificate_keeps_a_pkcs12_file_until_it_ends_or_is_forgotten() {
        let (record, clock, store) = fixture(u64::MAX);
        let short = record.issue(&request(serde_json::json!({"password": "abc"})));
        assert!(matches!(short, Err(IssueError::Invalid(_))));
        assert!(record.list().is_empty(), "nothing issued");

        let sealed = record
            .issue(&request(
                serde_json::json!({"validity_days": 1, "password": "twelve chars"}),
            ))
            .expect("issued");
        let (entry, file) = record.p12(&sealed.serial).expect("read").expect("kept");
        assert!(entry.p12);
        assert_eq!(file, b"sealed under twelve chars");
        assert!(store.0.lock().unwrap()[&sealed.id].p12, "the entry says so");

        let other = record
            .issue(&request(serde_json::json!({"password": "twelve chars"})))
            .expect("issued");
        record.forget_p12(&other.serial).expect("forgotten");
        assert_eq!(record.p12(&other.serial).expect("read"), None);
        assert!(
            store.1.lock().unwrap().get(&other.id).is_none(),
            "the file is gone"
        );
        assert!(!store.0.lock().unwrap()[&other.id].p12);

        clock.0.store(1_000 + 2 * DAY_MS, Ordering::SeqCst);
        assert_eq!(record.p12(&sealed.serial).expect("read"), None, "ended");
        assert!(
            store.1.lock().unwrap().get(&sealed.id).is_none(),
            "removed with its entry"
        );
    }

    /// Verifies: ADR-0029
    #[test]
    fn no_debug_shows_a_password_or_a_key() {
        let request = request(serde_json::json!({"password": "do not show me"}));
        assert!(!format!("{request:?}").contains("do not show me"));
        let (record, _, _) = fixture(u64::MAX);
        let pair = record.issue(&valid()).expect("issued");
        assert!(!format!("{pair:?}").contains("twelve chars"));
    }

    /// An entry that cannot be written leaves no PKCS#12 file behind, which nothing would end.
    /// Verifies: ADR-0029
    #[test]
    fn a_failed_entry_keeps_no_pkcs12_file() {
        let (record, _, store) = fixture(u64::MAX);
        store.2.store(true, Ordering::SeqCst);
        let failed = record.issue(&request(serde_json::json!({"password": "twelve chars"})));
        assert!(matches!(failed, Err(IssueError::Failed(_))));
        assert!(
            store.1.lock().unwrap().is_empty(),
            "no file without its entry"
        );
    }

    /// Only a revoked entry is deleted, and only with its deletion on the record; it goes from the
    /// list and the store with its PKCS#12 file, and a second deletion finds nothing.
    /// Verifies: ADR-0029
    #[test]
    fn a_revoked_entry_is_deleted_with_its_pkcs12_file_once() {
        let (record, _, store) = fixture(u64::MAX);
        let sealed = record
            .issue(&request(serde_json::json!({"password": "twelve chars"})))
            .expect("issued");
        let serial = sealed.serial.as_str();
        assert_eq!(
            record.delete(serial, |_| false, |_| true),
            Err(DeleteError::NotRevoked)
        );
        assert_eq!(
            record.delete(serial, |_| true, |_| false),
            Err(DeleteError::Unrecorded)
        );
        assert_eq!(record.list().len(), 1, "kept on either refusal");
        let deleted = record.delete(serial, |_| true, |_| true).expect("deleted");
        assert_eq!(deleted.serial, sealed.serial);
        assert!(record.list().is_empty());
        assert!(store.0.lock().unwrap().is_empty() && store.1.lock().unwrap().is_empty());
        assert_eq!(
            record.delete(serial, |_| true, |_| true),
            Err(DeleteError::NotFound)
        );
    }
}
