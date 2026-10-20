//! The package store (ADR-0026, ADR-0033): the Server's software artifacts, held as **Packages**.
//! A Package is identified by *(Agent type, version)* and holds **one entry per Platform**
//! (ADR-0026) — an uploaded artifact with its SHA-256 content hash, its size and the operator's
//! signature over it (ADR-0033). It aims at nobody: that belongs to the Deployment that holds it
//! (ADR-0026). A stored Package reaches nobody by itself (ADR-0025): what an Agent is offered is
//! composed from the assignment the operator's rollout act wrote; [`resolve`] only computes the
//! **candidate** such an act would release. A Package reaches an Agent only as an **upgrade**
//! over what it reports (ADR-0025), beside the type and platform tests. The
//! immutability of an assigned Package's entries is enforced by the fleet, which knows the
//! assignments.
//!
//! Package *bodies* are opaque bytes: what a package contains and how it is applied is the Agent's
//! business (the specification forbids the Server abstracting over it). The Server's job is to
//! store, hash, offer, and serve — and to hand each Agent the artifact built for the machine it
//! runs on, never another one. It checks a signature against the operator's public key when it
//! holds one, and only reports what it found: the Agent's own check decides (ADR-0033).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::RwLock;

use crate::blobs::BlobStore;
use crate::deployments::Deployment;
use opamp::proto::{
    AgentDescription, DownloadableFile, PackageAvailable, PackageType, PackagesAvailable,
};
use sha2::{Digest, Sha256};

/// The operating system and architecture an artifact is built for (ADR-0026) — and the pair an
/// Agent reports about itself, so the two can be compared.
///
/// Both tokens are **canonical**: the semantic conventions' `os.type` and `host.arch` values, which
/// is what the Baseline points at ("keys/values are according to OpenTelemetry semantic
/// conventions") and what the release artifacts are named by. Older and foreign spellings are
/// folded onto them by [`Platform::new`], on the way in and on the way out alike.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Platform {
    pub os: String,
    pub arch: String,
}

impl Platform {
    /// Canonicalises a spelling into a Platform.
    ///
    /// Unknown tokens are **not** refused, only normalised in case and checked for shape: the fleet
    /// may run a system this table has never heard of, and refusing to serve it would be a worse
    /// failure than serving it under its own name. What is refused is a token that could not be
    /// half of a file name, since that is what an entry is stored as.
    ///
    /// # Errors
    /// Returns an error when either token is empty, longer than 16 characters, or carries anything
    /// but lowercase letters, digits, and `_`.
    pub fn new(os: &str, arch: &str) -> Result<Self, String> {
        Ok(Platform {
            os: token(os, "os", fleet_core::platform::canonical_os)?,
            arch: token(arch, "arch", fleet_core::platform::canonical_arch)?,
        })
    }

    /// The Platform an Agent reports, from the two attributes the Baseline names for it: `os.type`
    /// and `host.arch`. `None` when it reports neither — such an Agent fits no artifact, and is
    /// offered none rather than being guessed at (ADR-0026).
    ///
    /// The reported values go through the same canonicalisation as an uploaded one, which is what
    /// makes a Collector reporting `amd64` and a Supervisor reporting `x86_64` the same machine.
    pub fn reported(description: Option<&AgentDescription>) -> Option<Self> {
        let description = description?;
        // Non-identifying first: that is where an Agent reports its platform, and an identifying
        // copy is the fallback rather than the answer.
        let attribute = |key: &str| {
            opamp::attributes::string_value(&description.non_identifying_attributes, key).or_else(
                || opamp::attributes::string_value(&description.identifying_attributes, key),
            )
        };
        Platform::new(
            attribute(opamp::attributes::OS_TYPE)?,
            attribute(opamp::attributes::HOST_ARCH)?,
        )
        .ok()
    }

    /// How this Platform is written in a file name and a query: `linux-amd64`.
    pub fn tag(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

fn token(raw: &str, what: &str, canonicalise: fn(&str) -> &str) -> Result<String, String> {
    let lowered = raw.trim().to_ascii_lowercase();
    // The spelling table is the Client's too (ADR-0010): what an Agent reports and what an artifact
    // is stored under have to fold onto the same token, or the offer misses.
    let canonical = canonicalise(&lowered).to_string();
    if canonical.is_empty() || canonical.len() > 16 {
        return Err(format!("{what} {raw:?} must be 1–16 characters"));
    }
    if !canonical
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(format!(
            "{what} {raw:?} may hold only lowercase letters, digits, and '_'"
        ));
    }
    Ok(canonical)
}

/// A Package's Agent type or version as it may appear in its identity (ADR-0026): a bounded token
/// that embeds losslessly in file names and URLs. `@` is excluded so the Package directory name —
/// `<agent_type>@<version>` — parses back unambiguously, exactly the trick ADR-0026 played for
/// variants; path separators are excluded because the value becomes half a directory name.
pub fn validate_identity_token(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err(format!("the {what} must be 1–64 characters"));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(format!(
            "the {what} {value:?} may hold only letters, digits, '.', '_', '+', and '-'"
        ));
    }
    Ok(())
}

/// The refusal of a Package version that is a token but not SemVer (ADR-0043 clause 1): it names
/// the version and the rule. It starts with `the ` so the REST API answers it `400`.
pub fn not_semver(version: &str) -> String {
    format!(
        "the version {version:?} is not SemVer — a Package version is a SemVer 2.0.0 version, \
         for example 1.19.0 for upstream's 1.19"
    )
}

/// A Package's identity (ADR-0026): the Agent type it is built for and its version, stated at
/// creation and never edited. A new version is a **new Package**, and the type is as constitutive
/// of "what is this artifact" as the version — an attribute would be editable, and retyping stored
/// bytes to another kind of Agent is exactly the mistake an immutable identity forecloses.
///
/// There is no name beside these two. What a name would have added is a second identity for a thing
/// that already has one, and the only thing it could express — two Packages of one Agent type at
/// one version — is an ambiguity resolution would have to rank its way out of.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageId {
    /// The Agent type this Package is built for, matched **raw** against the `service.name` an
    /// Agent reports (ADR-0026) — there is no canonical set of Agent types to normalise against.
    /// It is also the **wire name**: the `PackagesAvailable` map key and the key an Agent reports
    /// its `PackageStatuses` under, which is why it must not carry the version.
    pub agent_type: String,
    /// The version every entry of this Package shares. A release is one version across its
    /// platforms; the Package is the object that *is* that release.
    pub version: String,
}

impl PackageId {
    /// Validates both parts, and that the version is SemVer (ADR-0043 clause 1): the gate every
    /// write goes through — creating a Package, an entry, a signature, adding it to a Deployment.
    ///
    /// # Errors
    /// Returns the token rule's refusal, or [`not_semver`] when the version is a token but not a
    /// SemVer version.
    pub fn new(agent_type: &str, version: &str) -> Result<Self, String> {
        let id = PackageId::load(agent_type, version)?;
        if !id.is_semver() {
            return Err(not_semver(version));
        }
        Ok(id)
    }

    /// Validates both parts as tokens only: the gate for what the store already holds and for a
    /// route that only reads or deletes. A Package an older Server stored under a version that is
    /// not SemVer loads through here, inert (ADR-0043 clause 3).
    ///
    /// # Errors
    /// Returns an error when either part breaks the token rule of [`validate_identity_token`].
    pub fn load(agent_type: &str, version: &str) -> Result<Self, String> {
        validate_identity_token(agent_type, "agent type")?;
        validate_identity_token(version, "version")?;
        Ok(PackageId {
            agent_type: agent_type.to_string(),
            version: version.to_string(),
        })
    }

    /// Whether the version is SemVer (ADR-0043 clause 2). A Package for which it is not was stored
    /// by an older Server: it is no candidate, and nothing is written to it.
    pub fn is_semver(&self) -> bool {
        fleet_core::version::is_semver(&self.version)
    }

    /// What an operator reads: the Agent type **and** its version. Never the wire name — that one
    /// is stable across versions on purpose (see [`PackageId::agent_type`]), and using it here
    /// would make every version of a Package look like the same row.
    pub fn display_name(&self) -> String {
        format!("{} {}", self.agent_type, self.version)
    }

    /// Parses the `<agent_type>@<version>` form the [`Display`] impl writes — the Package's
    /// directory name, and the persisted shape of a package assignment (ADR-0025).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut parts = text.split('@');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(agent_type), Some(version), None) => PackageId::load(agent_type, version),
            _ => Err(format!(
                "{text:?} is not an <agent type>@<version> package identity"
            )),
        }
    }
}

/// `<agent_type>@<version>`, which is also the Package's directory name. Neither token admits an
/// `@`, so the pair parses back unambiguously — and stays readable in a directory listing, which an
/// opaque hash would not be.
impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.agent_type, self.version)
    }
}

/// A stored Package (ADR-0026): its identity, and one entry per Platform. Nothing else.
///
/// **The Platform fits, the Deployment aims** — the split ADR-0026 named, with the aiming half
/// moved out (ADR-0026). What a Package is has nothing to say about who gets it, which is why
/// there is no Selector here and no kind flag: an Agent's Deployment holds one Package for its
/// type, and that is the whole of the decision.
///
/// Artifacts stay in the blob store, named by their hash (ADR-0037), and are streamed to whoever
/// asks — a program weighs hundreds of megabytes, and a fleet server holding every one of them in
/// memory, plus a copy per download, is the shape this deliberately avoids.
#[derive(Clone)]
pub struct Package {
    pub id: PackageId,
    /// One entry per Platform — a map, so a duplicate for the same combination is unrepresentable.
    /// A Package may sit empty while it is being assembled; rolling one out empty is refused.
    pub entries: BTreeMap<Platform, Entry>,
}

/// One platform's artifact of a Package: an uploaded file, the hash that identifies what an Agent
/// installs, and the operator's signature over it (ADR-0033). The signature lives here because what
/// it covers — `fleet_core::package::statement` — names the Agent type, the version and this hash,
/// and no Deployment: one signature serves every Deployment that holds the Package.
#[derive(Clone)]
pub struct Entry {
    pub platform: Platform,
    /// SHA-256 of the artifact bytes, computed here as they arrive.
    pub content_hash: Vec<u8>,
    /// The artifact's size in bytes.
    pub size: u64,
    /// The operator's Ed25519 signature over the statement for this entry, as `opamp-fleetctl
    /// package sign` makes it. `None` until one is written; new bytes remove it, because a
    /// signature covers the hash (ADR-0033). An entry without one is offered to nobody.
    pub signature: Option<Vec<u8>>,
}

/// What the Server found when it checked an entry's signature (ADR-0033) — feedback for the
/// operator, never a gate: the Agent's own verification is the one that decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureState {
    /// The entry carries no signature, and is offered to nobody.
    Missing,
    /// The signature verifies against the Server's `[packages] verification_key`.
    Valid,
    /// The signature does not verify against that key. Stored and offered all the same: the
    /// Server's key may lag behind the operator's, and the Client's check decides.
    Invalid,
    /// The entry carries a signature, and the Server holds no key to check it with.
    Unchecked,
}

impl SignatureState {
    /// The state as the REST API spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureState::Missing => "missing",
            SignatureState::Valid => "valid",
            SignatureState::Invalid => "invalid",
            SignatureState::Unchecked => "unchecked",
        }
    }
}

/// The length of an Ed25519 signature (RFC 8032).
pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;

/// The signature check's port (ADR-0006, ADR-0033): whether `signature` is the operator's over
/// `statement`. The Ed25519 adapter over `[packages] verification_key`
/// ([`Ed25519Verifier`](crate::config::Ed25519Verifier)) is what the composition root wires.
pub trait SignatureVerifier: Send + Sync {
    fn verifies(&self, statement: &[u8], signature: &[u8]) -> bool;
}

/// Checks one entry's signature over the statement a Client verifies
/// (`fleet_core::package::statement`, ADR-0026 clause 54) with `verifier`, the operator's public
/// key when the Server holds it (ADR-0033).
pub fn signature_state(
    verifier: Option<&dyn SignatureVerifier>,
    id: &PackageId,
    entry: &Entry,
) -> SignatureState {
    let Some(signature) = entry.signature.as_deref() else {
        return SignatureState::Missing;
    };
    let Some(verifier) = verifier else {
        return SignatureState::Unchecked;
    };
    let statement =
        fleet_core::package::statement(&id.agent_type, &id.version, &entry.content_hash);
    if verifier.verifies(&statement, signature) {
        SignatureState::Valid
    } else {
        SignatureState::Invalid
    }
}

impl Package {
    /// The per-package hash the Agent compares to decide whether to download: over the fields that
    /// identify the offer (type, version) and the content. Framed length-prefixed so no boundary
    /// is ambiguous. The Platform needs no place in it — two platforms' artifacts differ in their
    /// content hash by construction.
    fn package_hash(&self, entry: &Entry) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update((self.id.version.len() as u64).to_le_bytes());
        hasher.update(self.id.version.as_bytes());
        hasher.update(&entry.content_hash);
        hasher.finalize().to_vec()
    }

    /// One entry as a wire `PackageAvailable`.
    ///
    /// Every artifact is offered from this Server, as a path the Agent resolves against its own
    /// OpAMP endpoint (ADR-0033): there is no other host to name. `signature` is the entry's own,
    /// for these exact bytes (ADR-0033); the wire is unchanged.
    fn to_available(&self, entry: &Entry, signature: &[u8]) -> PackageAvailable {
        let file = DownloadableFile {
            download_url: format!(
                "/api/v1/packages/{}/{}/file?os={}&arch={}",
                self.id.agent_type, self.id.version, entry.platform.os, entry.platform.arch
            ),
            content_hash: entry.content_hash.clone(),
            signature: signature.to_vec(),
            headers: None,
        };
        PackageAvailable {
            // Always top-level. An Agent has one binary to replace, its Deployment holds one
            // Package for its type, and no Client this project ships installs an addon — so the
            // kind is structural rather than a flag anyone could set (ADR-0026 point 18).
            r#type: PackageType::TopLevel as i32,
            version: self.id.version.clone(),
            file: Some(file),
            hash: self.package_hash(entry),
        }
    }
}

/// One Package as the REST API lists it (ADR-0026): its identity and what it holds for each
/// platform — never the artifact bytes.
pub struct PackageSummary {
    pub id: PackageId,
    /// One entry per Platform, in platform order.
    pub entries: Vec<EntrySummary>,
}

/// One entry of a Package as the REST API shows it.
pub struct EntrySummary {
    pub os: String,
    pub arch: String,
    pub size: u64,
    /// The SHA-256 of the artifact, hex — **the exact value the Agent verifies against**.
    pub content_hash: String,
    /// The per-package hash this entry is offered under, hex — what an Agent echoes back once it
    /// is in sync, and what gates re-offering.
    pub package_hash: String,
    /// The entry's signature, hex, when it carries one (ADR-0033).
    pub signature: Option<String>,
    /// What the Server found when it checked that signature (ADR-0033).
    pub signature_state: SignatureState,
}

impl PackageSummary {
    fn of(set: &Package, key: Option<&dyn SignatureVerifier>) -> Self {
        PackageSummary {
            id: set.id.clone(),
            entries: set
                .entries
                .values()
                .map(|entry| EntrySummary {
                    os: entry.platform.os.clone(),
                    arch: entry.platform.arch.clone(),
                    size: entry.size,
                    content_hash: hex::encode(&entry.content_hash),
                    package_hash: hex::encode(set.package_hash(entry)),
                    signature: entry.signature.as_ref().map(hex::encode),
                    signature_state: signature_state(key, &set.id, entry),
                })
                .collect(),
        }
    }
}

/// The package store's port (ADR-0006, ADR-0037): where Packages persist — each one's identity
/// and entries, every entry naming its artifact by the hash of its bytes. The bytes are the
/// [`BlobStore`]'s. The filesystem adapter ([`FsPackageBackend`](crate::fs::FsPackageBackend)) is
/// what the composition root wires.
pub trait PackageBackend: Send + Sync {
    /// Every persisted Package, once, when the store opens. Anything unreadable, unparsable, or in
    /// a layout this Server does not write fails the open and names where it is (ADR-0026).
    fn load(&self) -> Result<Vec<Package>, String>;

    /// Creates or replaces one Package's metadata.
    fn put(&self, package: &Package) -> Result<(), String>;

    /// Deletes one Package's metadata; its blobs are the store's to collect.
    fn remove(&self, id: &PackageId) -> Result<(), String>;
}

/// The package store (ADR-0026, ADR-0037): every Package, held in memory for the control loop to
/// read, its metadata persisted through a [`PackageBackend`] and its artifacts through a
/// [`BlobStore`].
pub struct PackageStore {
    backend: Box<dyn PackageBackend>,
    blobs: Box<dyn BlobStore>,
    sets: RwLock<BTreeMap<PackageId, Package>>,
    /// The check against the operator's public key, `[packages] verification_key` (ADR-0033).
    /// Each entry's signature is reported by it; `None` reports every signature `unchecked`.
    key: Option<Box<dyn SignatureVerifier>>,
}

impl PackageStore {
    /// Opens the store on `backend` and `blobs`, loading every persisted Package. Every blob is
    /// read once (and the filesystem adapter hashes it again on the way, ADR-0037 clause 4); an
    /// entry naming a blob that is not stored, or of another size, fails the open, and a blob no
    /// entry names is deleted.
    ///
    /// # Errors
    /// Returns an error when a Package cannot be loaded, the blobs cannot be listed, or an entry
    /// names a blob that is not stored as recorded.
    pub fn with_backend(
        backend: Box<dyn PackageBackend>,
        blobs: Box<dyn BlobStore>,
    ) -> Result<Self, String> {
        let stored: BTreeMap<String, u64> = blobs.list()?.into_iter().collect();
        let mut sets = BTreeMap::new();
        for package in backend.load()? {
            for entry in package.entries.values() {
                let sha256 = hex::encode(&entry.content_hash);
                match stored.get(&sha256) {
                    Some(size) if *size == entry.size => {}
                    Some(size) => {
                        return Err(format!(
                        "package {} for {}: blob {sha256} holds {size} bytes, the entry records {}",
                        package.id,
                        entry.platform.tag(),
                        entry.size
                    ))
                    }
                    None => {
                        return Err(format!(
                            "package {} for {}: blob {sha256} is not stored — restore it from a \
                             backup or upload the artifact again",
                            package.id,
                            entry.platform.tag()
                        ))
                    }
                }
            }
            // Kept and read, never a candidate and never written to (ADR-0043 clause 3).
            if !package.id.is_semver() {
                tracing::warn!(
                    package = %package.id,
                    "{} — the package is kept, but it is no candidate and nothing is written to \
                     it; republish its content under a SemVer version and sign it again",
                    not_semver(&package.id.version)
                );
            }
            sets.insert(package.id.clone(), package);
        }
        let store = PackageStore {
            backend,
            blobs,
            sets: RwLock::new(BTreeMap::new()),
            key: None,
        };
        // A blob no entry names is deleted at startup (ADR-0037 clause 4): an upload whose entry
        // was never written, or an entry whose deletion stopped short of its blob.
        for sha256 in stored.keys() {
            if !referenced(&sets, sha256) {
                store.blobs.delete(sha256)?;
            }
        }
        *store.sets.write().expect("sets lock") = sets;
        Ok(store)
    }

    /// Arms the signature check with the operator's public key (ADR-0033), and checks every
    /// stored signature against it now, as the store is loaded: an `invalid` one is logged and
    /// kept, because the Server only reports — the Agent's own verification decides.
    #[must_use]
    pub fn with_verifier(mut self, key: Option<Box<dyn SignatureVerifier>>) -> Self {
        self.key = key;
        for set in self.sets.read().expect("sets lock").values() {
            for entry in set.entries.values() {
                if signature_state(self.key.as_deref(), &set.id, entry) == SignatureState::Invalid {
                    tracing::warn!(
                        package = %set.id,
                        platform = %entry.platform.tag(),
                        "the stored signature does not verify against [packages] verification_key \
                         — kept and offered; the Agent's own check decides"
                    );
                }
            }
        }
        self
    }

    /// Every Package, in identity order — the REST list view; never the artifact bytes.
    pub fn list(&self) -> Vec<PackageSummary> {
        self.sets
            .read()
            .expect("sets lock")
            .values()
            .map(|set| PackageSummary::of(set, self.key.as_deref()))
            .collect()
    }

    /// One stored Package as the REST API presents it; `None` when no such Package exists.
    pub fn summary(&self, id: &PackageId) -> Option<PackageSummary> {
        self.sets
            .read()
            .expect("sets lock")
            .get(id)
            .map(|set| PackageSummary::of(set, self.key.as_deref()))
    }

    /// The artifact of one entry, for the download to stream: its SHA-256 and its size. `None`
    /// when no Package of that identity holds one for that Platform.
    pub fn artifact(&self, id: &PackageId, platform: &Platform) -> Option<(Vec<u8>, u64)> {
        self.sets
            .read()
            .expect("sets lock")
            .get(id)?
            .entries
            .get(platform)
            .map(|entry| (entry.content_hash.clone(), entry.size))
    }

    /// The bytes of the artifact `sha256` names, as a stream.
    ///
    /// # Errors
    /// Returns an error when the blob is not stored or cannot be read.
    pub fn open_artifact(&self, sha256: &[u8]) -> Result<Box<dyn std::io::Read + Send>, String> {
        self.blobs.get(&hex::encode(sha256))
    }

    /// `true` when the store holds no Package — the Server then leaves `OffersPackages` undeclared.
    pub fn is_empty(&self) -> bool {
        self.sets.read().expect("sets lock").is_empty()
    }

    /// The total bytes of the stored blobs (ADR-0037 clause 4): bytes two entries share count
    /// once. An upload still in flight is deliberately not counted — it is not yet an artifact,
    /// and the per-upload limit already bounds it.
    pub fn total_bytes(&self) -> u64 {
        let sets = self.sets.read().expect("sets lock");
        let mut blobs = BTreeMap::new();
        for entry in sets.values().flat_map(|set| set.entries.values()) {
            blobs.insert(entry.content_hash.as_slice(), entry.size);
        }
        blobs.values().sum()
    }

    /// Creates a Package. **Saving never distributes** (ADR-0025), and there is nothing to update:
    /// a Package is its identity and its entries, so creating one that exists is the same request
    /// arriving twice.
    pub fn create(&self, id: &PackageId) -> Result<(), String> {
        let mut sets = self.sets.write().expect("sets lock");
        if sets.contains_key(id) {
            return Ok(());
        }
        let set = Package {
            id: id.clone(),
            entries: BTreeMap::new(),
        };
        self.persist(&set)?;
        sets.insert(id.clone(), set);
        Ok(())
    }

    /// The gate every entry write passes: the Package must exist. The immutability of an
    /// assigned Package (ADR-0025) is the fleet's to enforce — only it knows the assignments.
    ///
    /// # Errors
    /// Returns an error when no Package of that identity exists.
    pub fn writable(&self, id: &PackageId) -> Result<(), String> {
        if self.sets.read().expect("sets lock").contains_key(id) {
            Ok(())
        } else {
            Err(format!("no package set {id}"))
        }
    }

    /// Turns a streamed upload into an entry: the bytes go to the blob store, hashed on the way —
    /// the artifact never passes through memory, an agent binary is far too big to buffer twice
    /// just to store it once — and the entry naming them is written, then visible to the control
    /// loop. A failed stream stores nothing; an entry that cannot be written leaves no blob behind.
    pub fn put_entry_from(
        &self,
        id: &PackageId,
        platform: &Platform,
        bytes: &mut dyn std::io::Read,
    ) -> Result<(), String> {
        self.writable(id)?;
        let (sha256, size) = self.blobs.put(bytes)?;
        let result = if size == 0 {
            Err("the package artifact is empty; refusing to distribute it".to_string())
        } else {
            self.put_entry_record(
                id,
                Entry {
                    platform: platform.clone(),
                    content_hash: hex::decode(&sha256).expect("a blob's hash is hex"),
                    size,
                    // New bytes take the old signature with them: it covered the old hash
                    // (ADR-0033).
                    signature: None,
                },
            )
        };
        if result.is_err() {
            self.collect(&self.sets.read().expect("sets lock"), &sha256);
        }
        result
    }

    /// Creates or replaces one entry from bytes already in hand — the shape the tests and any
    /// small artifact use. A real upload takes [`put_entry_from`](Self::put_entry_from) instead.
    pub fn put_entry(
        &self,
        id: &PackageId,
        platform: &Platform,
        artifact: Vec<u8>,
    ) -> Result<(), String> {
        self.put_entry_from(id, platform, &mut artifact.as_slice())
    }

    /// Writes the operator's signature onto one entry (ADR-0033), and answers what the Server found
    /// when it checked it. An `invalid` signature is stored all the same: the Server only reports.
    ///
    /// # Errors
    /// `no package set …` or `no entry …` when there is nothing to sign (a `404`), and `the
    /// signature …` when it is empty or not the 64 bytes of an Ed25519 signature (a `400`).
    pub fn put_signature(
        &self,
        id: &PackageId,
        platform: &Platform,
        signature: Vec<u8>,
    ) -> Result<SignatureState, String> {
        if signature.is_empty() {
            return Err(
                "the signature is empty — it says nothing; delete the one held instead".to_string(),
            );
        }
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(format!(
                "the signature must be the 64 bytes of an Ed25519 signature (128 hex characters, \
                 as `opamp-fleetctl package sign` prints it), not {} bytes",
                signature.len()
            ));
        }
        let mut sets = self.sets.write().expect("sets lock");
        let set = sets
            .get_mut(id)
            .ok_or_else(|| format!("no package set {id}"))?;
        let entry = set
            .entries
            .get_mut(platform)
            .ok_or_else(|| no_entry(id, platform))?;
        let previous = entry.signature.replace(signature);
        let state = signature_state(self.key.as_deref(), id, entry);
        if let Err(e) = self.backend.put(set) {
            // What did not reach the disk did not happen.
            if let Some(entry) = set.entries.get_mut(platform) {
                entry.signature = previous;
            }
            return Err(e);
        }
        Ok(state)
    }

    /// Takes one entry's signature away (ADR-0033); `Ok(false)` when the entry carries none.
    ///
    /// # Errors
    /// `no package set …` or `no entry …` when the entry does not exist (a `404`).
    pub fn remove_signature(&self, id: &PackageId, platform: &Platform) -> Result<bool, String> {
        let mut sets = self.sets.write().expect("sets lock");
        let set = sets
            .get_mut(id)
            .ok_or_else(|| format!("no package set {id}"))?;
        let entry = set
            .entries
            .get_mut(platform)
            .ok_or_else(|| no_entry(id, platform))?;
        let Some(previous) = entry.signature.take() else {
            return Ok(false);
        };
        if let Err(e) = self.backend.put(set) {
            if let Some(entry) = set.entries.get_mut(platform) {
                entry.signature = Some(previous);
            }
            return Err(e);
        }
        Ok(true)
    }

    /// Writes one entry into the Package's map and its metadata — the single path every entry
    /// write converges on. Replacing the entry for a Platform the Package already holds is what
    /// "no duplicate entries" means in a map: the combination stays unique by construction. The
    /// blob it names must still be stored — a deletion that collected it while the upload was
    /// streaming is refused here rather than recorded — and a blob the replaced entry named is
    /// deleted when no other entry names it.
    fn put_entry_record(&self, id: &PackageId, entry: Entry) -> Result<(), String> {
        let mut sets = self.sets.write().expect("sets lock");
        if !self.blobs.exists(&hex::encode(&entry.content_hash)) {
            return Err("the artifact was removed while it was uploaded; upload it again".into());
        }
        let set = sets
            .get_mut(id)
            .ok_or_else(|| format!("no package set {id}"))?;
        let platform = entry.platform.clone();
        let previous = set.entries.insert(platform.clone(), entry);
        if let Err(e) = self.backend.put(set) {
            match previous {
                Some(previous) => set.entries.insert(platform, previous),
                None => set.entries.remove(&platform),
            };
            return Err(e);
        }
        if let Some(previous) = previous {
            self.collect(&sets, &hex::encode(previous.content_hash));
        }
        Ok(())
    }

    /// Deletes one entry; `Ok(false)` when the Package or the entry does not exist. The fleet
    /// refuses this before calling here when the Package is assigned to an Agent (ADR-0025). The
    /// last entry taken away leaves an **empty Package**, kept: a Package being reassembled is a
    /// normal state, and deleting the Package is its own act. Its blob goes with the last entry
    /// that names it (ADR-0037 clause 4).
    pub fn delete_entry(&self, id: &PackageId, platform: &Platform) -> Result<bool, String> {
        let mut sets = self.sets.write().expect("sets lock");
        let Some(set) = sets.get_mut(id) else {
            return Ok(false);
        };
        let Some(removed) = set.entries.remove(platform) else {
            return Ok(false);
        };
        if let Err(e) = self.backend.put(set) {
            set.entries.insert(platform.clone(), removed);
            return Err(e);
        }
        self.collect(&sets, &hex::encode(removed.content_hash));
        Ok(true)
    }

    /// Deletes a whole Package — entries, metadata, and every blob no other entry names;
    /// `Ok(false)` when none of that identity exists. The fleet removes every assignment that
    /// referenced it, which withdraws the offer; Agents that installed it keep running it
    /// (ADR-0026).
    pub fn delete_set(&self, id: &PackageId) -> Result<bool, String> {
        let mut sets = self.sets.write().expect("sets lock");
        if !sets.contains_key(id) {
            return Ok(false);
        }
        self.backend.remove(id)?;
        let removed = sets.remove(id).expect("checked above");
        for entry in removed.entries.values() {
            self.collect(&sets, &hex::encode(&entry.content_hash));
        }
        Ok(true)
    }

    /// Deletes the blob `sha256` when no entry of `sets` names it (ADR-0037 clause 4). A failure
    /// is logged and left to the next startup, which deletes every blob no entry names.
    fn collect(&self, sets: &BTreeMap<PackageId, Package>, sha256: &str) {
        if referenced(sets, sha256) {
            return;
        }
        if let Err(e) = self.blobs.delete(sha256) {
            tracing::warn!(blob = %sha256, error = %e, "cannot delete an artifact no entry names");
        }
    }

    /// Every entry of every Package `deployment` holds that carries no signature, as
    /// "display name (os/arch, …)" per Package — what a refused rollout names (ADR-0026, ADR-0033).
    /// Empty when every entry is signed.
    pub fn unsigned_in(&self, deployment: &Deployment) -> Vec<String> {
        let sets = self.sets.read().expect("sets lock");
        deployment
            .packages
            .values()
            .filter_map(|id| {
                let set = sets.get(id)?;
                let missing: Vec<String> = set
                    .entries
                    .values()
                    .filter(|entry| entry.signature.is_none())
                    .map(|entry| format!("{}/{}", entry.platform.os, entry.platform.arch))
                    .collect();
                (!missing.is_empty())
                    .then(|| format!("{} ({})", id.display_name(), missing.join(", ")))
            })
            .collect()
    }

    /// One Agent's offer, composed from its **assignment** (ADR-0025): the entry [`offered_entry`]
    /// names, plus the `all_packages_hash` over it (the Baseline's per-Agent aggregate). `None`
    /// when the Agent is offered nothing — it keeps running what it runs. An assignment whose
    /// Package is gone composes nothing rather than failing: a pinned Package cannot be deleted
    /// (ADR-0034 clause 8), so the case is a race, not a state.
    pub fn offer_for_assigned(
        &self,
        assigned: Option<&PackageId>,
        description: Option<&AgentDescription>,
    ) -> Option<PackagesAvailable> {
        let sets = self.sets.read().expect("sets lock");
        let (set, entry, signature) = offered_entry(&sets, assigned, description)?;
        Some(PackagesAvailable {
            packages: [(
                set.id.agent_type.clone(),
                set.to_available(entry, signature),
            )]
            .into(),
            all_packages_hash: aggregate_hash(set, entry),
        })
    }

    /// The aggregate hash over what one Agent is offered, to gate re-offering without building the
    /// whole message. Empty when it is offered nothing, and has nothing to be in sync with.
    pub fn assigned_hash_for(
        &self,
        assigned: Option<&PackageId>,
        description: Option<&AgentDescription>,
    ) -> Vec<u8> {
        let sets = self.sets.read().expect("sets lock");
        match offered_entry(&sets, assigned, description) {
            Some((set, entry, _)) => aggregate_hash(set, entry),
            None => Vec::new(),
        }
    }

    /// The artifact `(id, platform)`, when this Server holds it and it carries a signature — the
    /// half of the download route's test that needs no Agent (ADR-0033 clause 10).
    pub fn offerable(&self, id: &PackageId, platform: &Platform) -> Option<Offerable> {
        let sets = self.sets.read().expect("sets lock");
        let entry = sets.get(id)?.entries.get(platform)?;
        entry.signature.is_some().then(|| Offerable {
            id: id.clone(),
            platform: platform.clone(),
        })
    }

    /// Whether the artifact `(id, platform)` is what this Agent is offered: the download route's
    /// test, composed as [`crate::fleet`] composes it.
    #[cfg(test)]
    pub fn offers(
        &self,
        assigned: Option<&PackageId>,
        description: Option<&AgentDescription>,
        id: &PackageId,
        platform: &Platform,
    ) -> bool {
        self.offerable(id, platform)
            .is_some_and(|artifact| artifact.offered_to(assigned, description))
    }

    /// The Package a rollout act would release to this Agent — the **candidate** (ADR-0025),
    /// never an offer.
    ///
    /// One Deployment claims the Agent (ADR-0026); the Package it holds for the Agent's type has
    /// to fit its platform and be an **upgrade** over what the Agent reports (ADR-0025). `None`
    /// where any of those is missing — including the ordinary case of an Agent no channel claims yet.
    pub fn candidate(
        &self,
        deployment: &Deployment,
        description: Option<&AgentDescription>,
        installed: &InstalledVersions,
    ) -> Option<PackageId> {
        let sets = self.sets.read().expect("sets lock");
        resolve(&sets, deployment, description, installed).map(|(set, _)| set.id.clone())
    }

    /// Whether an explicit rollout act may release this Package to this Agent: it must exist,
    /// hold an entry for the platform the Agent reports, be built for its type, and be an
    /// **upgrade** over what the Agent reports installed under that type (ADR-0025).
    ///
    /// Aim is not checked here: whom a Package reaches is its Deployment's business (ADR-0026),
    /// and the act names the Deployment, so the channel has already been decided by the time this
    /// is asked.
    ///
    /// The upgrade test is the one [`resolve`] applies, so the act and the candidate agree: what
    /// ADR-0025 forbids is aiming an act at an Agent it would move backwards, or not move at all —
    /// the count beside the button and the button itself answer the same question.
    pub fn fits_agent(
        &self,
        id: &PackageId,
        description: Option<&AgentDescription>,
        installed: &InstalledVersions,
    ) -> Result<(), String> {
        let sets = self.sets.read().expect("sets lock");
        let set = sets.get(id).ok_or_else(|| format!("no package set {id}"))?;
        // Nobody's candidate, whatever the Agent reports (ADR-0043 clause 5).
        if !set.id.is_semver() {
            return Err(format!(
                "set {id} is no candidate for any Agent: {}",
                not_semver(&set.id.version)
            ));
        }
        if set.entries.is_empty() {
            return Err(format!(
                "set {id} holds no entries — a set contains one or more entries before it can be \
                 rolled out"
            ));
        }
        let Some(platform) = Platform::reported(description) else {
            return Err(format!(
                "set {id} fits no platform this Agent reports — it reports none"
            ));
        };
        if reported_agent_type(description) != Some(set.id.agent_type.as_str()) {
            return Err(format!(
                "set {id} is built for Agent type {:?}, which this Agent does not report",
                set.id.agent_type
            ));
        }
        if !set.entries.contains_key(&platform) {
            return Err(format!(
                "set {id} holds no entry for {}-{}, which this Agent reports",
                platform.os, platform.arch
            ));
        }
        if !upgrades(set, installed, description) {
            // *Which* of the two versions decided is the operator's first question here (ADR-0025
            // point 8): the running one wherever it can be ordered, the claim only where it cannot.
            // A refusal naming a number without saying which of the two it was would read like the
            // wrong rule applied — and where both are reported and they disagree, saying that the
            // claim was not consulted is the whole explanation.
            let running = reported_service_version(description)
                .filter(|version| fleet_core::version::parse(version).is_some());
            return Err(match (running, claimed_version(set, installed)) {
                (Some(runs), Some(has)) => format!(
                    "set {id} is not an upgrade for this Agent, which runs {runs:?}; its package \
                     status claims {has:?} for package {:?}, which is not consulted while the \
                     Agent reports what it runs",
                    set.id.agent_type
                ),
                (Some(runs), None) => {
                    format!("set {id} is not an upgrade for this Agent, which runs {runs:?}")
                }
                (None, Some(has)) => format!(
                    "set {id} is not an upgrade for this Agent, which reports {has:?} installed \
                     for package {:?} and no version it runs that can be ordered",
                    set.id.agent_type
                ),
                (None, None) => {
                    format!("set {id} is not an upgrade for this Agent, which reports no version")
                }
            });
        }
        Ok(())
    }

    fn persist(&self, set: &Package) -> Result<(), String> {
        self.backend.put(set)
    }
}

/// The entry one Agent is offered, with the signature it travels with — the one test of "offered"
/// that the offer and the download share (ADR-0033 clause 10). The Agent's assignment names the
/// Package; the Package must be built for the Agent type the Agent reports (ADR-0026 clause 9) and
/// hold an entry for the Platform it reports; and that entry must carry a signature, because the
/// Server never offers a Package unsigned (ADR-0033). Whether the Agent accepts packages at all is
/// its record's, and the fleet asks that first.
///
/// An assignment pins *which* release the operator released; which artifact of it this host takes
/// is the machine's own answer, and a host reporting a platform the release does not hold is offered
/// nothing rather than something else.
fn offered_entry<'a>(
    sets: &'a BTreeMap<PackageId, Package>,
    assigned: Option<&PackageId>,
    description: Option<&AgentDescription>,
) -> Option<(&'a Package, &'a Entry, &'a [u8])> {
    let set = sets.get(assigned?)?;
    let platform = Platform::reported(description)?;
    if !fits(description, &set.id, &platform) {
        return None;
    }
    let entry = set.entries.get(&platform)?;
    let signature = entry.signature.as_deref()?;
    Some((set, entry, signature))
}

/// Whether an Agent reporting `description` is one the artifact `(id, platform)` is built for: the
/// Agent type it reports is the Package's, and the Platform it reports is the entry's. The part of
/// [`offered_entry`] that reads the Agent, shared with [`Offerable::offered_to`].
fn fits(description: Option<&AgentDescription>, id: &PackageId, platform: &Platform) -> bool {
    reported_agent_type(description) == Some(id.agent_type.as_str())
        && Platform::reported(description).as_ref() == Some(platform)
}

/// Whether any entry of `sets` names the blob `sha256`.
fn referenced(sets: &BTreeMap<PackageId, Package>, sha256: &str) -> bool {
    sets.values()
        .flat_map(|set| set.entries.values())
        .any(|entry| hex::encode(&entry.content_hash) == sha256)
}

/// The refusal for an entry a Package does not hold.
fn no_entry(id: &PackageId, platform: &Platform) -> String {
    format!("no entry {}-{} in set {id}", platform.os, platform.arch)
}

/// A signed artifact this Server holds, as [`PackageStore::offerable`] found it: what the download
/// route tests each Agent of a host against (ADR-0033 clause 10).
pub struct Offerable {
    id: PackageId,
    platform: Platform,
}

impl Offerable {
    /// Whether an Agent is offered this artifact: [`offered_entry`]'s test for one known, signed
    /// entry. Its assignment names this Package, and the Agent reports this Package's type and this
    /// entry's Platform. Whether it accepts packages at all is its record's, asked first.
    pub fn offered_to(
        &self,
        assigned: Option<&PackageId>,
        description: Option<&AgentDescription>,
    ) -> bool {
        assigned == Some(&self.id) && fits(description, &self.id, &self.platform)
    }
}

/// What an Agent reports it has installed, per package name: `PackageStatuses.packages[name]
/// .agent_has_version` as the Agent last sent it (ADR-0026). A name that is absent — and a name
/// whose reported version is empty, which is how an Agent that has installed nothing reports a
/// package it was offered — means *nothing is installed under that name*.
pub type InstalledVersions = BTreeMap<String, String>;

/// The fourth matching test: a Package reaches an Agent only as an **upgrade** (ADR-0025 points 10
/// to 12).
///
/// An Agent reports up to two versions, and they can contradict each other. **What it runs decides**
/// — the reported `service.version`, a statement about the present. Where it is there and can be
/// ordered, the Package must be strictly greater than it and the claim is not read at all: not to
/// admit a Package the running version refuses, and not to refuse one it admits.
///
/// *What it claims* is the **package status** under this Package's Agent type, derived from what an
/// install once wrote. That record outlives the binary it describes — a staged update that did not take, a host
/// reinstalled from an older artifact — so it cannot overrule the program's own statement, and it
/// does not get a veto over it either. The Baseline defines the field as *"the version of the package
/// that the Agent has"*, which a record naming a version the program denies running is not.
///
/// Where no `service.version` can be ordered — a program numbering itself `1.19` or `24.04.1`, or
/// an Agent reporting none at all — the claim is the whole test (ADR-0025): strictly greater to
/// match, and a claim that cannot itself be ordered **refuses** outright. That is the safe
/// direction for a claim about that very package, and the Client's own
/// (`update::installer::install`): what cannot be ordered must not be installed over what is
/// running.
///
/// An Agent that reports neither has nothing to be greater than: the first rollout, which matches.
fn upgrades(
    set: &Package,
    installed: &InstalledVersions,
    description: Option<&AgentDescription>,
) -> bool {
    use std::cmp::Ordering;
    let greater = |has: &str| {
        fleet_core::version::precedence(&set.id.version, has) == Some(Ordering::Greater)
    };
    // An unorderable `service.version` says nothing at all — it is dropped here rather than
    // refusing, so what remains is either a version to be greater than or no statement.
    let runs = reported_service_version(description)
        .filter(|running| fleet_core::version::parse(running).is_some());
    match runs {
        // The program's own word about the program, in both directions.
        Some(running) => greater(running),
        // No statement about the present: fall back to the record (ADR-0025). An unorderable claim
        // refuses, which `greater` already does by yielding `None`.
        None => match claimed_version(set, installed) {
            Some(claimed) => greater(claimed),
            None => true,
        },
    }
}

/// What an Agent claims to have installed under this Package's Agent type, if it claims anything:
/// a package status reported with an empty version is no claim (ADR-0025).
fn claimed_version<'a>(set: &Package, installed: &'a InstalledVersions) -> Option<&'a str> {
    installed
        .get(&set.id.agent_type)
        .map(String::as_str)
        .filter(|has| !has.is_empty())
}

/// The version an Agent reports as `service.version` — its program's own number, and what a Package
/// is held against when the Agent reports no version for the package itself (ADR-0025). It is also
/// read beside a reported one, as what the Agent actually runs.
fn reported_service_version(description: Option<&AgentDescription>) -> Option<&str> {
    opamp::attributes::string_value(
        &description?.identifying_attributes,
        opamp::attributes::SERVICE_VERSION,
    )
    .filter(|version| !version.is_empty())
}

/// What one Agent's Deployment would release to it, if an operator rolled out now.
///
/// Five tests, and every one of them is a hard gate: the Agent reports a platform and a type
/// (ADR-0026), its Deployment holds a Package for that type (ADR-0026) whose version is SemVer
/// (ADR-0043), that Package holds an entry for the platform, and it is an **upgrade** over what
/// the Agent runs (ADR-0025). Neither
/// report has an "unknown, so anything goes" case — an Agent reporting neither fits nothing. The
/// type needs no second comparison: a Deployment holds each Package under its own Agent type.
///
/// There is no ranking. The Deployment holds at most one Package per Agent type (ADR-0026 clause
/// 23), so a specificity comparison or a version tie-break would have nothing to choose between — an
/// ambiguous state is one a write refuses to create.
fn resolve<'a>(
    sets: &'a BTreeMap<PackageId, Package>,
    deployment: &Deployment,
    description: Option<&AgentDescription>,
    installed: &InstalledVersions,
) -> Option<(&'a Package, &'a Entry)> {
    let platform = Platform::reported(description)?;
    let set = sets.get(deployment.package_for(reported_agent_type(description)?)?)?;
    // A Package an older Server stored under a version that is not SemVer is nobody's candidate
    // (ADR-0043 clause 5).
    if !set.id.is_semver() {
        return None;
    }
    let entry = set.entries.get(&platform)?;
    upgrades(set, installed, description).then_some((set, entry))
}

/// The Agent type an Agent reports, as `service.name` (ADR-0016) — the identifying attribute the
/// Baseline reserves for "a reverse FQDN that uniquely identifies the Agent type".
///
/// `None` for an Agent that has not described itself or reports no type, which fits no Package
/// (ADR-0026). An empty value is `None` too: it is not a type.
pub fn reported_agent_type(description: Option<&AgentDescription>) -> Option<&str> {
    opamp::attributes::string_value(
        &description?.identifying_attributes,
        opamp::attributes::SERVICE_NAME,
    )
}

/// The aggregate over what one Agent is offered — its name and its content. One Package per
/// Agent now, so there is nothing to sort; the shape is kept because it is what the Baseline's
/// `all_packages_hash` is and what the Agent echoes back.
fn aggregate_hash(set: &Package, entry: &Entry) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update((set.id.agent_type.len() as u64).to_le_bytes());
    hasher.update(set.id.agent_type.as_bytes());
    hasher.update(set.package_hash(entry));
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux() -> Platform {
        Platform::new("linux", "amd64").expect("platform")
    }

    fn windows() -> Platform {
        Platform::new("windows", "amd64").expect("platform")
    }

    fn id(agent_type: &str, version: &str) -> PackageId {
        PackageId::new(agent_type, version).expect("package id")
    }

    /// An Agent description reporting a platform and a type, plus whatever else a Selector
    /// should see.
    fn agent(os: &str, arch: &str, extra: &[(&str, &str)]) -> AgentDescription {
        let attr = opamp::attributes::string_attr;
        AgentDescription {
            identifying_attributes: vec![attr("service.name", "otelcol")],
            non_identifying_attributes: [("os.type", os), ("host.arch", arch)]
                .iter()
                .map(|(k, v)| attr(k, v))
                .chain(extra.iter().map(|(k, v)| attr(k, v)))
                .collect(),
        }
    }

    /// An Agent that reports what its program is, as a Client does: `service.version`, identifying,
    /// beside the type (ADR-0016).
    fn running_agent(version: &str) -> AgentDescription {
        let mut description = agent("linux", "amd64", &[]);
        description
            .identifying_attributes
            .push(opamp::attributes::string_attr("service.version", version));
        description
    }

    /// A Set with one uploaded linux entry — stored, which reaches nobody until an assignment names
    /// it (ADR-0025).
    fn stored_set(store: &PackageStore, name: &str, version: &str, artifact: &[u8]) -> PackageId {
        let id = id(name, version);
        store.create(&id).expect("create");
        store
            .put_entry(&id, &linux(), artifact.to_vec())
            .expect("entry");
        id
    }

    /// What an Agent reports installed, as the record hands it to the store (ADR-0025).
    fn installed(versions: &[(&str, &str)]) -> InstalledVersions {
        versions
            .iter()
            .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
            .collect()
    }

    /// A Deployment holding one Package and aiming at everything the tests describe. Aim lives
    /// there now (ADR-0026), so a store test that wants a candidate has to say which channel the
    /// Agent is in — which is the model, not scaffolding.
    fn channel(id: &PackageId) -> Deployment {
        Deployment {
            name: "stable".to_string(),
            selector: BTreeMap::from([("channel".to_string(), "stable".to_string())]),
            packages: BTreeMap::from([(id.agent_type.clone(), id.clone())]),
            configurations: Default::default(),
        }
    }

    /// Signs every entry the Package holds — what an operator does before anything of it is offered
    /// (ADR-0033). The bytes are a stand-in: the store offers a signature it has not checked.
    fn sign_all(store: &PackageStore, id: &PackageId) {
        let platforms: Vec<Platform> = store
            .sets
            .read()
            .expect("sets lock")
            .get(id)
            .map(|set| set.entries.keys().cloned().collect())
            .unwrap_or_default();
        for platform in platforms {
            store
                .put_signature(id, &platform, vec![1u8; 64])
                .expect("signature");
        }
    }

    /// The candidate a rollout act would release to an Agent that has installed nothing.
    fn candidates(store: &PackageStore, description: &AgentDescription) -> Vec<(String, String)> {
        candidates_for(store, description, &InstalledVersions::new())
    }

    /// The candidate a rollout act would release to this Agent, as `(type, version)` — for every
    /// Package the store holds, each read through a channel that offers exactly it. At most one
    /// survives per call; collecting them is how a test asks "which of these would reach it".
    fn candidates_for(
        store: &PackageStore,
        description: &AgentDescription,
        installed: &InstalledVersions,
    ) -> Vec<(String, String)> {
        let ids: Vec<PackageId> = store
            .sets
            .read()
            .expect("sets lock")
            .keys()
            .cloned()
            .collect();
        let mut names: Vec<(String, String)> = ids
            .iter()
            .filter_map(|id| store.candidate(&channel(id), Some(description), installed))
            .map(|id| (id.agent_type, id.version))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// What this Agent is offered, given its assignment, as `(type, version)`.
    fn offered(
        store: &PackageStore,
        assigned: Option<&PackageId>,
        description: &AgentDescription,
    ) -> Vec<(String, String)> {
        if let Some(id) = assigned {
            sign_all(store, id);
        }
        store
            .offer_for_assigned(assigned, Some(description))
            .map(|offer| {
                offer
                    .packages
                    .iter()
                    .map(|(name, p)| (name.clone(), p.version.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// ADR-0026: the identity is the pair and entries are per platform; ADR-0033: each entry's
    /// signature is its own, and the whole Package — entries and signatures — survives a reopen.
    /// Verifies: ADR-0026, ADR-0033
    #[test]
    fn a_set_survives_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
            let set = id("otelcol", "1.2.3");
            store.create(&set).expect("create");
            store
                .put_entry(&set, &linux(), b"linux-bytes".to_vec())
                .expect("linux entry");
            store
                .put_entry(&set, &windows(), b"windows-bytes".to_vec())
                .expect("windows entry");
            store
                .put_signature(&set, &windows(), vec![7u8; 64])
                .expect("signature");
        }
        let store = PackageStore::open(dir.path().to_path_buf()).expect("reopen");
        let summary = store.summary(&id("otelcol", "1.2.3")).expect("summary");
        assert_eq!(summary.entries.len(), 2);
        assert_eq!(summary.entries[0].os, "linux");
        assert_eq!(summary.entries[0].signature, None);
        assert_eq!(summary.entries[0].signature_state, SignatureState::Missing);
        assert_eq!(summary.entries[1].size, 13);
        assert_eq!(
            summary.entries[1].signature.as_deref(),
            Some(hex::encode([7u8; 64]).as_str())
        );
        assert_eq!(
            summary.entries[1].signature_state,
            SignatureState::Unchecked
        );
    }

    /// ADR-0025: a saved Set reaches nobody by itself. It is a visible candidate, and only an
    /// assignment — the operator's rollout act — composes an offer from it.
    #[test]
    fn a_saved_set_reaches_nobody_without_an_assignment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.0.0", b"bytes");
        assert_eq!(
            candidates(&store, &agent("linux", "amd64", &[])),
            [("otelcol".to_string(), "1.0.0".to_string())],
            "the candidate is visible"
        );
        assert!(
            offered(&store, None, &agent("linux", "amd64", &[])).is_empty(),
            "no assignment, no offer"
        );
        assert_eq!(
            offered(&store, Some(&set), &agent("linux", "amd64", &[])),
            [("otelcol".to_string(), "1.0.0".to_string())]
        );
    }

    /// An entry that carries no signature is offered to nobody, and a Deployment holding it names
    /// it as what keeps it from being rolled out (ADR-0033).
    /// Verifies: ADR-0033
    #[test]
    fn an_entry_without_a_signature_is_offered_to_nobody() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.0.0", b"bytes");
        let stable = channel(&set);
        let linux = agent("linux", "amd64", &[]);
        assert!(
            store.offer_for_assigned(Some(&set), Some(&linux)).is_none(),
            "an unsigned entry was offered"
        );
        assert_eq!(store.unsigned_in(&stable).len(), 1);
        assert!(store.unsigned_in(&stable)[0].contains("linux/amd64"));

        sign_all(&store, &set);
        assert!(store.unsigned_in(&stable).is_empty());
        assert!(store.offer_for_assigned(Some(&set), Some(&linux)).is_some());
    }

    /// A signature is written on an entry, offered to an Agent of that Platform with exactly those
    /// bytes, and removed when new bytes are uploaded to the entry — a signature covers the hash
    /// (ADR-0033 clause 6). Removing it takes the offer away.
    /// Verifies: ADR-0033
    #[test]
    fn a_signature_lives_on_its_entry_and_new_bytes_remove_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.0.0", b"first");
        let linux_agent = agent("linux", "amd64", &[]);
        assert_eq!(
            store.put_signature(&set, &linux(), vec![5u8; 64]),
            Ok(SignatureState::Unchecked)
        );
        let offer = store
            .offer_for_assigned(Some(&set), Some(&linux_agent))
            .expect("a signed entry is offered");
        assert_eq!(
            offer.packages["otelcol"]
                .file
                .as_ref()
                .expect("file")
                .signature,
            vec![5u8; 64]
        );

        store
            .put_entry(&set, &linux(), b"second".to_vec())
            .expect("new bytes");
        let summary = store.summary(&set).expect("summary");
        assert_eq!(summary.entries[0].signature_state, SignatureState::Missing);
        assert!(
            store
                .offer_for_assigned(Some(&set), Some(&linux_agent))
                .is_none(),
            "the signature for the old bytes went with them"
        );

        store
            .put_signature(&set, &linux(), vec![6u8; 64])
            .expect("signed again");
        assert_eq!(store.remove_signature(&set, &linux()), Ok(true));
        assert_eq!(store.remove_signature(&set, &linux()), Ok(false));
        assert!(store
            .offer_for_assigned(Some(&set), Some(&linux_agent))
            .is_none());
    }

    /// A signature has to name an entry the Package holds (`no entry`, a `404`), and has to be
    /// one: empty or not 64 bytes is refused (a `400`) and nothing is stored (ADR-0033 clause 6).
    /// Verifies: ADR-0033
    #[test]
    fn a_signature_needs_an_entry_and_the_shape_of_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.0.0", b"bytes");
        assert!(store
            .put_signature(&set, &windows(), vec![1u8; 64])
            .expect_err("no windows entry")
            .starts_with("no entry"));
        assert!(store
            .remove_signature(&set, &windows())
            .expect_err("no windows entry")
            .starts_with("no entry"));
        assert!(store
            .put_signature(&id("otelcol", "9.9.9"), &linux(), vec![1u8; 64])
            .expect_err("no such package")
            .starts_with("no package set"));
        for refused in [Vec::new(), vec![1u8; 63], vec![1u8; 65]] {
            assert!(store
                .put_signature(&set, &linux(), refused)
                .expect_err("refused")
                .starts_with("the signature"));
        }
        assert_eq!(
            store.summary(&set).expect("summary").entries[0].signature,
            None
        );
    }

    /// With the operator's public key the Server reports a signature over the statement `valid` and
    /// any other `invalid` — and stores both; without the key every signature is `unchecked`
    /// (ADR-0033 clause 7). The state is checked again when the store is reopened.
    /// Verifies: ADR-0033
    #[test]
    fn the_server_checks_a_signature_against_its_key_and_only_reports() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair");
        let public = ring::signature::KeyPair::public_key(&keypair)
            .as_ref()
            .to_vec();

        let dir = tempfile::tempdir().expect("tempdir");
        let set = id("otelcol", "1.0.0");
        {
            let store = PackageStore::open(dir.path().to_path_buf())
                .expect("open")
                .with_verifier(Some(Box::new(crate::config::Ed25519Verifier::new(
                    public.clone(),
                ))));
            store.create(&set).expect("create");
            store
                .put_entry(&set, &linux(), b"linux".to_vec())
                .expect("entry");
            store
                .put_entry(&set, &windows(), b"windows".to_vec())
                .expect("entry");
            let hash = Sha256::digest(b"linux").to_vec();
            let good = keypair
                .sign(&fleet_core::package::statement("otelcol", "1.0.0", &hash))
                .as_ref()
                .to_vec();
            assert_eq!(
                store.put_signature(&set, &linux(), good),
                Ok(SignatureState::Valid)
            );
            // A signature over another type's statement does not verify for this one.
            let wrong = keypair
                .sign(&fleet_core::package::statement("promtail", "1.0.0", &hash))
                .as_ref()
                .to_vec();
            assert_eq!(
                store.put_signature(&set, &windows(), wrong),
                Ok(SignatureState::Invalid),
                "an invalid signature is stored and reported, never refused"
            );
            assert!(
                store
                    .offer_for_assigned(Some(&set), Some(&agent("windows", "amd64", &[])))
                    .is_some(),
                "and offered: the Client's check decides"
            );
        }
        let states = |store: &PackageStore| -> Vec<SignatureState> {
            store
                .summary(&set)
                .expect("summary")
                .entries
                .iter()
                .map(|entry| entry.signature_state)
                .collect()
        };
        let reopened = PackageStore::open(dir.path().to_path_buf())
            .expect("reopen")
            .with_verifier(Some(Box::new(crate::config::Ed25519Verifier::new(public))));
        assert_eq!(
            states(&reopened),
            [SignatureState::Valid, SignatureState::Invalid]
        );
        let keyless = PackageStore::open(dir.path().to_path_buf()).expect("reopen");
        assert_eq!(
            states(&keyless),
            [SignatureState::Unchecked, SignatureState::Unchecked]
        );
    }

    /// The gate an explicit rollout act runs (ADR-0025): the Package must hold entries and fit the
    /// Agent's type and platform. **Aim is not among them** — whom a Package reaches is its
    /// Deployment's, and the act names the channel. The version *ranking* stays out too: an Agent
    /// that has installed nothing takes the older Package as readily as the newer one.
    #[test]
    fn fits_agent_checks_fit_but_neither_aim_nor_the_ranking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let empty = id("otelcol", "0.9.0");
        store.create(&empty).expect("create");
        assert!(store
            .fits_agent(
                &empty,
                Some(&agent("linux", "amd64", &[])),
                &InstalledVersions::new()
            )
            .expect_err("empty refused")
            .contains("holds no entries"));

        let old = stored_set(&store, "otelcol", "1.0.0", b"v1");
        let new = stored_set(&store, "otelcol", "2.0.0", b"v2");
        let in_channel = agent("linux", "amd64", &[("channel", "canary")]);
        assert!(
            store
                .fits_agent(&old, Some(&in_channel), &InstalledVersions::new())
                .is_ok(),
            "the older Set fits an Agent that runs nothing yet"
        );
        assert!(store
            .fits_agent(&new, Some(&in_channel), &InstalledVersions::new())
            .is_ok());
        assert!(
            store
                .fits_agent(
                    &old,
                    Some(&agent("linux", "amd64", &[])),
                    &InstalledVersions::new()
                )
                .is_ok(),
            "an Agent outside any channel still *fits* this Package — whom it reaches is the \
             Deployment's question, and the act has already answered it by naming one (ADR-0026)"
        );
        assert!(store
            .fits_agent(
                &new,
                Some(&agent("windows", "amd64", &[])),
                &InstalledVersions::new()
            )
            .expect_err("wrong platform")
            .contains("no entry for"));
        assert!(
            store
                .fits_agent(
                    &new,
                    Some(&AgentDescription::default()),
                    &InstalledVersions::new()
                )
                .is_err(),
            "no platform and no type fits nothing"
        );
        assert!(store
            .fits_agent(
                &id("otelcol", "9.9.9"),
                Some(&in_channel),
                &InstalledVersions::new(),
            )
            .expect_err("unknown set")
            .contains("no package set"));
    }

    /// ADR-0025's fourth test at the gate: an act may only be aimed at an Agent the Set would
    /// move *forward*. Equal is not greater — a Set the Agent already runs changes nothing — and
    /// a reported version that cannot be ordered is refused rather than guessed at.
    #[test]
    fn fits_agent_refuses_what_is_not_an_upgrade() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let old = stored_set(&store, "otelcol", "1.0.0", b"v1");
        let new = stored_set(&store, "otelcol", "2.0.0", b"v2");
        let host = agent("linux", "amd64", &[]);

        let running_v2 = installed(&[("otelcol", "2.0.0")]);
        assert!(store
            .fits_agent(&old, Some(&host), &running_v2)
            .expect_err("backwards")
            .contains("not an upgrade"));
        assert!(store
            .fits_agent(&new, Some(&host), &running_v2)
            .expect_err("the same version")
            .contains("not an upgrade"));
        assert!(
            store
                .fits_agent(&new, Some(&host), &installed(&[("otelcol", "1.0.0")]))
                .is_ok(),
            "forward is what a rollout act is for"
        );
        assert!(
            store
                .fits_agent(&new, Some(&host), &installed(&[("otelcol", "")]))
                .is_ok(),
            "an empty reported version is nothing installed, not an unorderable one"
        );
        assert!(
            store
                .fits_agent(&new, Some(&host), &installed(&[("otelcol", "nightly")]))
                .is_err(),
            "what cannot be ordered must not be installed over what is running"
        );
        assert!(
            store
                .fits_agent(&new, Some(&host), &installed(&[("promtail", "9.9.9")]))
                .is_ok(),
            "another package's version says nothing about this one"
        );
    }

    /// The same test on the way in (ADR-0025): a Set the Agent already runs is no candidate, so
    /// nothing proposes it and no count includes it. The Set the Agent is *behind* still is one.
    #[test]
    fn a_set_that_is_no_upgrade_is_no_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "1.0.0", b"v1");
        stored_set(&store, "otelcol", "2.0.0", b"v2");
        let host = agent("linux", "amd64", &[]);

        assert_eq!(
            candidates_for(&store, &host, &installed(&[("otelcol", "1.0.0")])),
            [("otelcol".to_string(), "2.0.0".to_string())],
        );
        assert!(
            candidates_for(&store, &host, &installed(&[("otelcol", "2.0.0")])).is_empty(),
            "an Agent already at the greatest version is proposed nothing"
        );
        assert!(
            candidates_for(&store, &host, &installed(&[("otelcol", "3.0.0")])).is_empty(),
            "and one ahead of the store is proposed nothing either"
        );
    }

    /// ADR-0025: an Agent that reports no version for the package is held against the version it
    /// reports *running*. This is what reaches the Clients released before the one that reports its
    /// own package version — they cannot state it, and they all state `service.version`.
    #[test]
    fn a_set_is_held_against_the_version_an_agent_reports_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "2.0.0", b"v2");
        let nothing = InstalledVersions::new();

        // The build metadata every Client appends takes no part in it (ADR-0012).
        for running in ["2.0.0", "2.0.0+a1b2c3d", "3.0.0"] {
            assert!(
                candidates_for(&store, &running_agent(running), &nothing).is_empty(),
                "an Agent already running {running} is proposed nothing"
            );
        }
        assert_eq!(
            candidates_for(&store, &running_agent("1.0.0"), &nothing),
            [("otelcol".to_string(), "2.0.0".to_string())],
            "and one genuinely behind is still reached"
        );

        // The act at the gate says the same thing, and says which version it read.
        let refusal = store
            .fits_agent(
                &id("otelcol", "2.0.0"),
                Some(&running_agent("2.0.0")),
                &nothing,
            )
            .expect_err("the same version is no upgrade");
        assert!(
            refusal.contains("not an upgrade") && refusal.contains("runs \"2.0.0\""),
            "the refusal names the version it compared against: {refusal}"
        );
    }

    /// ADR-0025 points 10 and 11: **what an Agent runs decides, in both directions**, and the claim
    /// is not consulted beside it. The record a package status comes from outlives the binary it
    /// describes; the program's own number is the statement about the present.
    ///
    /// Both halves of the trade are asserted here rather than only the convenient one — including
    /// that a Managed Process numbered below its Set can be moved backwards, which is the cost the
    /// ADR records under Consequences.
    // Verifies: ADR-0025
    #[test]
    fn the_version_an_agent_runs_wins_over_the_version_it_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "2.0.0", b"v2");

        // A program above the Set holds it back, whatever the claim admits.
        assert!(
            candidates_for(
                &store,
                &running_agent("9.9.9"),
                &installed(&[("otelcol", "1.0.0")])
            )
            .is_empty(),
            "the program says it is at 9.9.9; a Set at 2.0.0 moves it nowhere"
        );

        // A Collector numbering itself far below the Package that carries it: every version above
        // that number clears the test, the claim notwithstanding. Which of them an Agent gets is
        // not decided here — a channel holds one, and there is nothing to rank.
        let store = PackageStore::open(dir.path().to_path_buf()).expect("reopen");
        stored_set(&store, "otelcol", "1.5.0", b"v15");
        assert_eq!(
            candidates_for(
                &store,
                &running_agent("0.98.0"),
                &installed(&[("otelcol", "2.0.0")])
            ),
            [
                ("otelcol".to_string(), "1.5.0".to_string()),
                ("otelcol".to_string(), "2.0.0".to_string())
            ],
            "both clear 0.98.0 — the claim of 2.0.0 is not consulted while the Agent says what it \
             runs (ADR-0025)"
        );
        assert!(
            store
                .fits_agent(
                    &id("otelcol", "1.5.0"),
                    Some(&running_agent("0.98.0")),
                    &installed(&[("otelcol", "2.0.0")])
                )
                .is_ok(),
            "and the act admits the lower Set too: 1.5.0 is ahead of what the program reports, so \
             the claim of 2.0.0 does not refuse it — the downgrade ADR-0025 admits as its cost"
        );
    }

    /// ADR-0025: a claim the Agent's own program denies does not hold the Set back. A Client that
    /// reports `supervisor 0.4.1` installed while reporting that it runs 0.4.0 has a record about a
    /// binary that is gone — and held to that record it would be offered nothing, for good.
    #[test]
    fn a_claim_the_running_program_denies_no_longer_holds_the_set_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "0.4.1", b"v041");
        let claims_041 = installed(&[("otelcol", "0.4.1")]);

        assert_eq!(
            candidates_for(&store, &running_agent("0.4.0"), &claims_041),
            [("otelcol".to_string(), "0.4.1".to_string())],
            "the version it runs is what it has; the record says only how it once got there"
        );
        assert!(
            store
                .fits_agent(
                    &id("otelcol", "0.4.1"),
                    Some(&running_agent("0.4.0")),
                    &claims_041
                )
                .is_ok(),
            "and the act at the gate agrees, as all three consumers must"
        );

        // Corroborated, and nothing changes: an Agent that runs what it claims is proposed nothing.
        assert!(
            candidates_for(&store, &running_agent("0.4.1"), &claims_041).is_empty(),
            "a claim its program confirms is still the end of it"
        );
        let refusal = store
            .fits_agent(
                &id("otelcol", "0.4.1"),
                Some(&running_agent("0.4.1+a1b2c3d")),
                &claims_041,
            )
            .expect_err("the version it runs is the version offered");
        assert!(
            refusal.contains("runs \"0.4.1+a1b2c3d\"") && refusal.contains("not consulted"),
            "the refusal names the version that decided, and says the claim was not: {refusal}"
        );

        // A program that cannot be ordered says nothing, and the claim becomes the whole test
        // (ADR-0025 point 12) — which here refuses the Set the claim already names.
        assert!(
            candidates_for(&store, &running_agent("nightly"), &claims_041).is_empty(),
            "an unorderable program version says nothing, and the claim stands"
        );
    }

    /// The other face of the one above (ADR-0025): a claim *above* the Set, over a program that
    /// denies running it. A self-update that staged 0.4.2 and did not take leaves
    /// `supervisor 0.4.2` recorded on a host whose program still reports 0.4.0 — and refusing
    /// 0.4.1 to it as a downgrade would keep the host where it is for good.
    #[test]
    fn a_claim_above_the_set_no_longer_holds_it_back_either() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "0.4.1", b"v041");
        let claims_042 = installed(&[("otelcol", "0.4.2")]);

        assert_eq!(
            candidates_for(&store, &running_agent("0.4.0"), &claims_042),
            [("otelcol".to_string(), "0.4.1".to_string())],
            "the record names a binary this host is not running; 0.4.1 still moves it forward"
        );
        assert!(
            store
                .fits_agent(
                    &id("otelcol", "0.4.1"),
                    Some(&running_agent("0.4.0")),
                    &claims_042
                )
                .is_ok(),
            "and the act at the gate agrees, as all three consumers must"
        );

        // The running version decides in *both* directions, so it still refuses what moves nobody:
        // a host already at 0.4.1 is proposed nothing, however high its record reads.
        assert!(
            candidates_for(&store, &running_agent("0.4.1"), &claims_042).is_empty(),
            "equal to what it runs is no upgrade, whatever the claim says"
        );
    }

    /// ADR-0025 point 12: a running version that cannot be ordered says nothing, rather than
    /// refusing, and the claim becomes the whole test. A GLPI Agent numbers itself `1.19` and an
    /// appliance `24.04.1`; failing closed on those would make a program's numbering habit into a
    /// fleet that cannot deliver to it at all.
    #[test]
    fn a_program_version_nothing_can_order_leaves_the_set_reaching() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "2.0.0", b"v2");
        let nothing = InstalledVersions::new();

        for running in ["1.19", "24.04.1", "unknown", "v2.0.0"] {
            assert_eq!(
                candidates_for(&store, &running_agent(running), &nothing),
                [("otelcol".to_string(), "2.0.0".to_string())],
                "{running:?} orders against nothing, so it says nothing"
            );
        }

        // And an Agent reporting no version at all is the first rollout (ADR-0025).
        assert_eq!(
            candidates_for(&store, &agent("linux", "amd64", &[]), &nothing),
            [("otelcol".to_string(), "2.0.0".to_string())],
        );
    }

    /// Only the Package its channel holds is a candidate. A Deployment holds one Package per type
    /// (ADR-0026), so there is no second contender to rank or refuse: the store answers what the
    /// channel points at, or nothing.
    /// Verifies: ADR-0026
    #[test]
    fn only_the_package_its_ring_holds_is_a_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let a = stored_set(&store, "otelcol", "2.0.0", b"a");
        let b = stored_set(&store, "otelcol", "3.0.0", b"b");
        let host = agent("linux", "amd64", &[]);

        // The store holds a greater version, and the channel still decides: the store does not
        // rank its way to the newest Package of the type.
        for held in [&a, &b] {
            assert_eq!(
                store.candidate(&channel(held), Some(&host), &InstalledVersions::new()),
                Some(held.clone()),
                "the channel decides, and it holds exactly one"
            );
        }
        assert_eq!(
            store.candidate(
                &channel(&a),
                Some(&host),
                &installed(&[("otelcol", "2.0.0")])
            ),
            None,
            "and what is no upgrade is still no candidate (ADR-0025)"
        );
    }

    /// A store an older Server wrote, holding `otelcol@1.19`: it opens and warns naming the
    /// Package, the Package is nobody's candidate, and a rollout act aimed at it is refused naming
    /// the version and the SemVer rule (ADR-0043 clauses 3 and 5).
    /// Verifies: ADR-0043
    #[test]
    fn a_stored_package_whose_version_is_not_semver_loads_and_is_no_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let legacy = PackageId::load("otelcol", "1.19").expect("a token");
        {
            let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
            store.create(&legacy).expect("create");
            store
                .put_entry(&legacy, &linux(), b"old".to_vec())
                .expect("entry");
            sign_all(&store, &legacy);
        }

        let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = {
            let logs = logs.clone();
            move || LogBuffer(logs.clone())
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_ansi(false)
            .finish();
        let store = tracing::subscriber::with_default(subscriber, || {
            PackageStore::open(dir.path().to_path_buf())
        })
        .expect("a store holding a non-SemVer Package opens");
        let logs = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf-8");
        assert!(
            logs.contains("WARN") && logs.contains("otelcol@1.19") && logs.contains("SemVer"),
            "one warning names the Package and the rule: {logs}"
        );
        assert!(store.summary(&legacy).is_some(), "the Package is kept");

        let nothing = InstalledVersions::new();
        let host = agent("linux", "amd64", &[]);
        assert_eq!(
            store.candidate(&channel(&legacy), Some(&host), &nothing),
            None,
            "an Agent that reports nothing would take any SemVer Package — not this one"
        );
        let refusal = store
            .fits_agent(&legacy, Some(&host), &nothing)
            .expect_err("no act releases it");
        assert!(
            refusal.contains("\"1.19\"") && refusal.contains("SemVer"),
            "the refusal names the version and the rule: {refusal}"
        );
        // An assignment that already pins it is still offered (ADR-0025 clause 17): the Client
        // refuses the offer, and reports why.
        assert!(store
            .offer_for_assigned(Some(&legacy), Some(&host))
            .is_some());
    }

    /// A `tracing` writer into a shared buffer, so a test can read what was logged.
    struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("logs").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Fit before aim (ADR-0026): an entry for another platform, or a Set for another
    /// Agent type, is never a candidate — and an Agent reporting neither fits nothing.
    /// Verifies: ADR-0026
    #[test]
    fn fit_is_mandatory_platform_and_type() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        stored_set(&store, "otelcol", "1.0.0", b"linux-only");
        let foreign = PackageId::new("promtail", "1.0.0").expect("id");
        store.create(&foreign).expect("create");
        store
            .put_entry(&foreign, &linux(), b"p".to_vec())
            .expect("entry");

        assert!(candidates(&store, &agent("windows", "amd64", &[])).is_empty());
        assert_eq!(
            candidates(&store, &agent("linux", "amd64", &[])),
            [("otelcol".to_string(), "1.0.0".to_string())],
            "the promtail set fits another type and is not a candidate"
        );
        assert_eq!(
            store.candidate(
                &channel(&id("otelcol", "1.0.0")),
                Some(&AgentDescription::default()),
                &InstalledVersions::new()
            ),
            None,
            "no platform and no type fits nothing"
        );
    }

    /// Both sides of the platform comparison are canonicalised (ADR-0026): an artifact uploaded
    /// as `macos`/`x86_64` reaches an Agent reporting `darwin`/`amd64`.
    /// Verifies: ADR-0026
    #[test]
    fn both_sides_of_the_comparison_are_canonicalised() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = id("otelcol", "1.0.0");
        store.create(&set).expect("create");
        let mac = Platform::new("macos", "x86_64").expect("canonicalised");
        assert_eq!((mac.os.as_str(), mac.arch.as_str()), ("darwin", "amd64"));
        store.put_entry(&set, &mac, b"mac".to_vec()).expect("entry");
        assert_eq!(
            candidates(&store, &agent("darwin", "amd64", &[])),
            [("otelcol".to_string(), "1.0.0".to_string())]
        );
        assert_eq!(
            offered(&store, Some(&set), &agent("darwin", "amd64", &[])),
            [("otelcol".to_string(), "1.0.0".to_string())]
        );
    }

    /// The offered download URL is a path the Agent resolves against its own Server (ADR-0033),
    /// and it names the whole identity, so two versions of one name never serve each other's bytes.
    /// Verifies: ADR-0026, ADR-0033
    #[test]
    fn the_offer_carries_a_download_url_naming_the_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.2.3", b"bytes");
        sign_all(&store, &set);
        let offer = store
            .offer_for_assigned(Some(&set), Some(&agent("linux", "amd64", &[])))
            .expect("an offer");
        let url = &offer.packages["otelcol"]
            .file
            .as_ref()
            .expect("file")
            .download_url;
        assert_eq!(
            url,
            "/api/v1/packages/otelcol/1.2.3/file?os=linux&arch=amd64"
        );
    }

    /// The aggregate hash is per Agent and follows its assignments (ADR-0025): it changes when
    /// the assigned Set changes, and is empty for an Agent assigned nothing it fits.
    #[test]
    fn the_aggregate_hash_is_per_agent_and_follows_the_assignment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let v1 = stored_set(&store, "otelcol", "1.0.0", b"v1");
        let hash = |assigned: Option<&PackageId>, os: &str| {
            store.assigned_hash_for(assigned, Some(&agent(os, "amd64", &[])))
        };
        assert!(
            hash(Some(&v1), "linux").is_empty(),
            "an unsigned entry is offered nothing to be in sync with"
        );
        sign_all(&store, &v1);
        let before = hash(Some(&v1), "linux");
        assert!(!before.is_empty());
        assert!(hash(Some(&v1), "windows").is_empty());
        assert!(hash(None, "linux").is_empty());

        let v2 = stored_set(&store, "otelcol", "2.0.0", b"v2");
        sign_all(&store, &v2);
        let after = hash(Some(&v2), "linux");
        assert_ne!(before, after, "a new assigned version moves the aggregate");
    }

    /// Deleting an entry frees its artifact; deleting the Set takes its metadata with it.
    /// Verifies: ADR-0026
    #[test]
    fn deletion_frees_entries_and_sets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = id("otelcol", "1.0.0");
        store.create(&set).expect("create");
        store
            .put_entry(&set, &linux(), b"bytes".to_vec())
            .expect("entry");
        assert!(store.total_bytes() > 0);
        assert!(store.delete_entry(&set, &linux()).expect("delete entry"));
        assert_eq!(store.total_bytes(), 0);
        assert!(!store.delete_entry(&set, &linux()).expect("gone already"));
        assert!(store.delete_set(&set).expect("delete set"));
        assert!(store.summary(&set).is_none());
        assert!(!dir.path().join("packages/otelcol@1.0.0.json").exists());
        assert!(!store.delete_set(&set).expect("gone already"));
    }

    /// The blobs under one entry's bytes (ADR-0037 clause 4): two entries with identical bytes
    /// store one blob, counted once against the store's size; it stays while an entry names it and
    /// goes with the last one — replaced or deleted — and a blob no entry names is deleted when
    /// the store opens.
    /// Verifies: ADR-0037
    #[test]
    fn identical_bytes_are_one_blob_that_goes_with_its_last_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blobs = || {
            std::fs::read_dir(dir.path().join("blobs"))
                .expect("blobs")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .into_string()
                        .expect("utf-8")
                })
                .collect::<Vec<_>>()
        };
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let (one, two) = (id("otelcol", "1.0.0"), id("otelcol", "1.0.1"));
        for set in [&one, &two] {
            store.create(set).expect("create");
            store
                .put_entry(set, &linux(), b"same bytes".to_vec())
                .expect("entry");
        }
        let sha256 = hex::encode(Sha256::digest(b"same bytes"));
        assert_eq!(blobs(), std::slice::from_ref(&sha256), "stored once");
        assert_eq!(store.total_bytes(), 10, "and counted once");
        let metadata =
            std::fs::read_to_string(dir.path().join("packages/otelcol@1.0.0.json")).expect("meta");
        assert!(metadata.contains(&sha256), "named by its hash: {metadata}");

        assert!(store.delete_entry(&one, &linux()).expect("delete"));
        assert_eq!(
            blobs(),
            std::slice::from_ref(&sha256),
            "another entry still names it"
        );
        store
            .put_entry(&two, &linux(), b"new bytes".to_vec())
            .expect("replace");
        assert_eq!(
            blobs(),
            [hex::encode(Sha256::digest(b"new bytes"))],
            "the replaced entry was the last to name it"
        );
        assert!(store.delete_set(&two).expect("delete"));
        assert!(blobs().is_empty(), "the last entry took its blob with it");

        std::fs::write(dir.path().join("blobs").join(&sha256), b"same bytes").expect("orphan");
        PackageStore::open(dir.path().to_path_buf()).expect("reopen");
        assert!(
            blobs().is_empty(),
            "a blob no entry names is deleted at startup"
        );
    }

    /// A corrupt artifact fails the reopen loudly, naming its blob — a corrupt distribution
    /// artifact must never ship (ADR-0026 clause 12, ADR-0037 clause 4).
    /// Verifies: ADR-0026, ADR-0037
    #[test]
    fn a_corrupt_artifact_fails_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = id("otelcol", "1.0.0");
        {
            let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
            store.create(&set).expect("create");
            store
                .put_entry(&set, &linux(), b"good bytes".to_vec())
                .expect("entry");
        }
        let sha256 = hex::encode(Sha256::digest(b"good bytes"));
        std::fs::write(dir.path().join("blobs").join(&sha256), b"tampered").expect("tamper");
        let err = PackageStore::open(dir.path().to_path_buf())
            .map(|_| ())
            .expect_err("must refuse");
        assert!(
            err.contains("does not match") && err.contains(&sha256),
            "{err}"
        );

        std::fs::remove_file(dir.path().join("blobs").join(&sha256)).expect("lose it");
        let err = PackageStore::open(dir.path().to_path_buf())
            .map(|_| ())
            .expect_err("an entry whose blob is gone is refused");
        assert!(err.contains("not stored"), "{err}");
    }

    /// The store's directories, each Package's metadata and each blob are owner-only (ADR-0026,
    /// ADR-0037 clause 1).
    /// Verifies: ADR-0026
    #[cfg(unix)]
    #[test]
    fn the_store_and_its_metadata_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = id("otelcol", "1.0.0");
        store.create(&set).expect("create");
        store
            .put_entry(&set, &linux(), b"bytes".to_vec())
            .expect("entry");
        let mode = |path: std::path::PathBuf| {
            std::fs::metadata(path).expect("meta").permissions().mode() & 0o777
        };
        assert_eq!(mode(dir.path().join("packages")), 0o700);
        assert_eq!(mode(dir.path().join("blobs")), 0o700);
        assert_eq!(mode(dir.path().join("packages/otelcol@1.0.0.json")), 0o600);
        assert_eq!(
            mode(
                dir.path()
                    .join("blobs")
                    .join(hex::encode(Sha256::digest(b"bytes")))
            ),
            0o600
        );
    }

    /// There is no legacy reader: a store holding what an older layout wrote is **named at
    /// startup**, never skipped (ADR-0026 point 19, ADR-0037 clause 6). Skipping is the dangerous
    /// half — a store that merely looks empty offers nothing and says nothing about why, which an
    /// operator reads as "nothing uploaded yet".
    ///
    /// The shapes an older Server left behind are covered: a loose file, a
    /// `<name>@<version>@<type>/set.json` directory, and the `<type>@<version>/package.json`
    /// directory of the layout before ADR-0037.
    /// Verifies: ADR-0026, ADR-0037
    #[test]
    fn a_store_in_an_older_layout_refuses_to_open_and_names_what_is_in_the_way() {
        let older = |relative: &str, contents: &str| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("packages").join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
            std::fs::write(&path, contents).expect("write");
            let error = PackageStore::open(dir.path().to_path_buf())
                .map(|_| ())
                .expect_err("an older layout is refused, never read as an empty store");
            let named = relative.split('/').next().expect("first segment");
            assert!(
                error.contains(named),
                "the error must name what an operator has to move aside, got: {error}"
            );
        };
        older("otelcol@linux-amd64.bin", "bytes");
        older("otelcol@1.0.0@otelcol/set.json", "{}");
        older(
            "otelcol@1.0.0/package.json",
            r#"{"agent_type":"otelcol","version":"1.0.0","entries":[]}"#,
        );
    }

    /// Every artifact is uploaded (ADR-0033 clause 1): an entry an older Server stored as a
    /// reference to a source is not read as something else — the open fails naming the file.
    /// Verifies: ADR-0033
    #[test]
    fn a_referenced_entry_from_an_older_server_fails_the_open_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("packages")).expect("dir");
        std::fs::write(
            dir.path().join("packages/otelcol@1.0.0.json"),
            serde_json::json!({
                "agent_type": "otelcol",
                "version": "1.0.0",
                "entries": [{
                    "os": "linux",
                    "arch": "amd64",
                    "sha256": "00".repeat(32),
                    "size": 1,
                    "source_url": "https://example.com/otelcol.tar.gz"
                }]
            })
            .to_string(),
        )
        .expect("metadata");
        let error = PackageStore::open(dir.path().to_path_buf())
            .map(|_| ())
            .expect_err("a referenced entry is refused");
        assert!(
            error.contains("otelcol@1.0.0.json") && error.contains("source_url"),
            "the error names the file and the field: {error}"
        );
    }

    /// A stored signature is held to the length a write is held to: one that is not 64 bytes fails
    /// the open naming the file, rather than being offered for every Client to refuse.
    /// Verifies: ADR-0033
    #[test]
    fn a_stored_signature_of_the_wrong_length_fails_the_open_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("packages")).expect("dir");
        std::fs::write(
            dir.path().join("packages/otelcol@1.0.0.json"),
            serde_json::json!({
                "agent_type": "otelcol",
                "version": "1.0.0",
                "entries": [{
                    "os": "linux",
                    "arch": "amd64",
                    "sha256": "00".repeat(32),
                    "size": 1,
                    "signature_hex": "ab".repeat(63)
                }]
            })
            .to_string(),
        )
        .expect("metadata");
        let error = PackageStore::open(dir.path().to_path_buf())
            .map(|_| ())
            .expect_err("a short signature is refused");
        assert!(
            error.contains("otelcol@1.0.0.json") && error.contains("signature"),
            "the error names the file and the signature: {error}"
        );
    }

    /// The identity grammar keeps the triple a safe directory name and an unambiguous parse:
    /// `@` and path separators are refused.
    /// Verifies: ADR-0026
    #[test]
    fn identity_tokens_are_bounded() {
        assert!(PackageId::new("otelcol", "1.2.3-rc.1+abc").is_ok());
        assert!(PackageId::new("a@b", "1.0.0").is_err());
        assert!(PackageId::new("otelcol", "1.0.0/../evil").is_err());
        assert!(PackageId::new("", "1.0.0").is_err());
        assert!(PackageId::new("not a type", "1.0.0").is_err());
        assert!(PackageId::new(&"x".repeat(65), "1.0.0").is_err());
    }

    /// A write takes only a SemVer version, while what the store holds loads as a token
    /// (ADR-0043 clauses 1 and 3) — an assignment that pins an older Package parses back.
    /// Verifies: ADR-0043
    #[test]
    fn a_write_takes_a_semver_version_and_a_load_any_token() {
        for not_semver in ["1.19", "24.04.1", "nightly", "1.0.0-01"] {
            let refusal = PackageId::new("otelcol", not_semver).expect_err(not_semver);
            assert!(
                refusal.contains(&format!("{not_semver:?}")) && refusal.contains("SemVer"),
                "{refusal}"
            );
            let held = PackageId::load("otelcol", not_semver).expect("a token loads");
            assert!(!held.is_semver());
            assert_eq!(
                PackageId::parse(&format!("otelcol@{not_semver}")),
                Ok(held),
                "a persisted assignment parses back"
            );
        }
        assert!(PackageId::new("otelcol", "1.19.0").is_ok_and(|id| id.is_semver()));
        assert!(PackageId::load("otelcol", "1.0.0/../evil").is_err());
        assert!(PackageId::load("a@b", "1.0.0").is_err());
    }

    // ---- What is offered, for the offer and the download alike (ADR-0026) ----

    /// The artifact an offer names, as `(type, version, platform)`, read off its `download_url`.
    fn named_by(offer: &PackagesAvailable) -> (String, String, Platform) {
        let available = offer.packages.values().next().expect("one package");
        let url = &available.file.as_ref().expect("file").download_url;
        let rest = url.strip_prefix("/api/v1/packages/").expect("the route");
        let (path, query) = rest.split_once("/file?").expect("the file route");
        let (agent_type, version) = path.split_once('/').expect("type and version");
        let (os, arch) = query
            .strip_prefix("os=")
            .and_then(|q| q.split_once("&arch="))
            .expect("the platform");
        (
            agent_type.to_string(),
            version.to_string(),
            Platform::new(os, arch).expect("platform"),
        )
    }

    /// An Agent of `agent_type` on `os`/amd64.
    fn typed_agent(agent_type: &str, os: &str) -> AgentDescription {
        let mut description = agent(os, "amd64", &[]);
        description.identifying_attributes =
            vec![opamp::attributes::string_attr("service.name", agent_type)];
        description
    }

    /// Every artifact `offer_for_assigned` names is one `offers` answers yes for, and nothing else
    /// is — across assignments, Agent types, Platforms, signed and unsigned entries, and artifacts
    /// the store does not hold (ADR-0033 clause 10). Whether the Agent accepts packages is the
    /// record's, asked by the fleet before either; `fleet` tests that half.
    /// Verifies: ADR-0026, ADR-0033
    #[test]
    fn the_download_and_the_offer_test_one_predicate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let v1 = stored_set(&store, "otelcol", "1.0.0", b"v1-linux");
        store
            .put_entry(&v1, &windows(), b"v1-windows".to_vec())
            .expect("entry");
        let v2 = stored_set(&store, "otelcol", "2.0.0", b"v2-linux");
        let other = stored_set(&store, "other", "1.0.0", b"other-linux");
        let darwin = Platform::new("darwin", "amd64").expect("platform");
        let artifacts: Vec<(PackageId, Platform)> = [&v1, &v2, &other]
            .into_iter()
            .flat_map(|id| [linux(), windows(), darwin.clone()].map(|p| (id.clone(), p)))
            .collect();
        let agents = [
            typed_agent("otelcol", "linux"),
            typed_agent("otelcol", "windows"),
            typed_agent("otelcol", "darwin"),
            typed_agent("other", "linux"),
        ];
        let mut offered = 0;
        // Unsigned first, then v1's windows entry alone, then everything.
        let signing: [&[(&PackageId, Platform)]; 3] = [
            &[],
            &[(&v1, windows())],
            &[(&v1, linux()), (&v2, linux()), (&other, linux())],
        ];
        for signed in signing {
            for (id, platform) in signed {
                store
                    .put_signature(id, platform, vec![1u8; 64])
                    .expect("signature");
            }
            for assigned in [None, Some(&v1), Some(&v2), Some(&other)] {
                for description in &agents {
                    let offer = store.offer_for_assigned(assigned, Some(description));
                    let named = offer.as_ref().map(named_by);
                    offered += usize::from(named.is_some());
                    for (id, platform) in &artifacts {
                        let expected = named.as_ref().is_some_and(|(t, v, p)| {
                            *t == id.agent_type && *v == id.version && p == platform
                        });
                        assert_eq!(
                            store.offers(assigned, Some(description), id, platform),
                            expected,
                            "{id} {} for {description:?}",
                            platform.tag()
                        );
                    }
                }
            }
        }
        assert_eq!(
            offered,
            1 + 4,
            "nothing unsigned, then v1 on windows alone, then each assignment where it fits"
        );
    }

    /// An Agent that reports another Agent type than its assigned Package's is offered nothing, and
    /// cannot fetch it (ADR-0026 clause 9).
    /// Verifies: ADR-0026
    #[test]
    fn an_agent_reporting_another_type_is_offered_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.0.0", b"bytes");
        sign_all(&store, &set);
        let renamed = typed_agent("otelcol-contrib", "linux");
        assert!(store
            .offer_for_assigned(Some(&set), Some(&renamed))
            .is_none());
        assert!(store
            .assigned_hash_for(Some(&set), Some(&renamed))
            .is_empty());
        assert!(!store.offers(Some(&set), Some(&renamed), &set, &linux()));
        assert!(store.offers(
            Some(&set),
            Some(&typed_agent("otelcol", "linux")),
            &set,
            &linux()
        ));
    }

    /// An entry that carries no signature is neither offered nor fetched, though another entry of
    /// the same Package is signed (ADR-0033 clause 6).
    /// Verifies: ADR-0033
    #[test]
    fn an_unsigned_entry_is_not_offered_though_another_is_signed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PackageStore::open(dir.path().to_path_buf()).expect("open");
        let set = stored_set(&store, "otelcol", "1.0.0", b"linux");
        store
            .put_entry(&set, &windows(), b"windows".to_vec())
            .expect("entry");
        store
            .put_signature(&set, &windows(), vec![1u8; 64])
            .expect("signature");
        let linux_agent = agent("linux", "amd64", &[]);
        assert!(store
            .offer_for_assigned(Some(&set), Some(&linux_agent))
            .is_none());
        assert!(!store.offers(Some(&set), Some(&linux_agent), &set, &linux()));
        let windows_agent = agent("windows", "amd64", &[]);
        assert!(store.offers(Some(&set), Some(&windows_agent), &set, &windows()));
    }
}
