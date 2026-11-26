//! The Server's own configuration — TOML, from `server.toml` and its environment.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use opamp::proto::{Header, Headers, OpAmpConnectionSettings, TelemetryConnectionSettings};
use serde::de::IgnoredAny;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::fleet::{ConnectionOffer, TelemetryOffer, AGENTS_PER_HOST};

/// The default Agent-plane address: the Baseline's port, on the loopback. Serving the
/// estate is a line an operator writes deliberately, together with the TLS it needs.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:4320";

/// The default Operator-plane address: the port above the protocol's, on loopback.
/// Loopback because that plane is open until `[rest.auth]` guards it — until then its
/// reachability *is* its protection, so publishing it is a line an operator writes deliberately.
pub const DEFAULT_REST_LISTEN: &str = "127.0.0.1:4321";

/// `server.toml`. Every setting has a default; unknown keys are rejected so a typo fails loudly at
/// startup instead of silently applying a default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address and port the **Agent plane** binds: the OpAMP endpoint and the package download
    /// route the offers point at.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The **Operator plane** — REST API, API docs, and the bundled UI — on its own listener.
    /// Absent means the default, which is loopback.
    #[serde(default)]
    pub rest: RestConfig,
    /// Where the Server keeps all of its state, one subdirectory per domain: created
    /// owner-only when missing, and holding nothing but its fixed layout.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Refused at startup: the state lives under `data_dir`, and `server migrate` moves
    /// an older installation there. Read only so that a leftover key can be named.
    pub config_dir: Option<IgnoredAny>,
    /// Refused at startup: the Server speaks plain HTTP behind a reverse proxy that terminates TLS.
    /// Read only so that a leftover section can be named.
    pub tls: Option<IgnoredAny>,
    /// Refused at startup: the Agent plane has no credential of its own, and a top-level `[auth]`
    /// was never one. Read only so that a leftover section can be named.
    pub auth: Option<IgnoredAny>,
    /// Refused at startup: the Server does not authenticate Agents. Whatever admits them
    /// is outside it, in the proxy. Read only so that a leftover `[agents.auth]` can be named.
    pub agents: Option<IgnoredAny>,
    /// Optional connection settings offered to the fleet; absent means none.
    pub connection_offer: Option<ConnectionOfferConfig>,
    /// Refused at startup: the Server speaks no mutual TLS, so it signs no client certificate.
    /// Read only so that a leftover section can be named.
    pub client_ca: Option<IgnoredAny>,
    /// Optional destinations for the Agents' own telemetry; absent means none is
    /// offered and no Agent reports any.
    pub telemetry_offer: Option<TelemetryOfferConfig>,
    /// Refused at startup, like `config_dir`. Read only so that a leftover key can be
    /// named.
    pub packages_dir: Option<IgnoredAny>,
    /// Where the artifacts' bytes are kept: the filesystem under `data_dir`, or a bucket of an
    /// S3-compatible object store.
    #[serde(default)]
    pub blobs: BlobsConfig,
    /// Where the Server keeps its records: files under `data_dir`, or one PostgreSQL database.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Refused at startup: every package is offered as a path the Client resolves against its own
    /// endpoint, and a Client downloads from no other host. Read only so that a leftover
    /// key can be named.
    pub advertised_url: Option<IgnoredAny>,
    /// The URL hosts reach the Server at from outside its proxy — the base `classis-cli
    /// enrol-command` prints its install command against, and what an operator types into
    /// `classis enrol <url> <key>`. Absent, that command refuses: no Server guesses the domain its
    /// proxy answers for.
    #[serde(default)]
    pub public_url: Option<String>,
    /// The largest OpAMP message the Server accepts or sends, on either transport and in either
    /// direction. The Baseline requires the limit, recommends this default, and asks that it be
    /// configurable — a fleet of small status reports can be served with far less.
    #[serde(default = "default_max_message_size")]
    pub max_message_size_bytes: usize,
    /// The largest package artifact the REST API accepts on upload. Nothing to do with
    /// the OpAMP message limit above: a package is a *program*, routinely hundreds of megabytes,
    /// and it travels over the REST plane, never in an OpAMP message.
    #[serde(default = "default_max_package_size")]
    pub max_package_size_bytes: usize,
    /// The total size of all stored package artifacts the REST API keeps before it refuses a new
    /// upload. Where `max_package_size_bytes` bounds one artifact, this bounds the whole
    /// store — so a caller cannot fill the disk by uploading many artifacts under distinct names.
    /// `0` is refused at load.
    #[serde(default = "default_max_total_package_size")]
    pub max_total_package_bytes: u64,
    /// How long an Agent that declares `ReportsHeartbeat` may be silent before the fleet view calls
    /// it stale. Ignored when `[connection_offer]` names a heartbeat interval — the
    /// period this Server asked for is a better answer than a default.
    #[serde(default = "default_stale_after_secs")]
    pub stale_after_secs: u64,
    /// The most Agent records the fleet holds at once. A report bearing a new `instance_uid` past
    /// this ceiling is refused `Unavailable`, so a peer minting fresh self-asserted UIDs cannot
    /// exhaust memory or disk; existing Agents keep reporting. `0` is refused at load: a fleet that
    /// can hold no Agent is a misconfiguration, not a limit.
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,
    /// The connections the Agent plane holds at once. Past it a connection is closed on
    /// accept; the ones held keep working. A fleet larger than the default raises this together
    /// with the process's file-descriptor limit. `0` is refused at load.
    #[serde(default = "default_agent_max_connections")]
    pub max_connections: usize,
    /// Refused at startup: enrolment with a bootstrap certificate is gone: a host
    /// enrols with its Space's key. Read only so that a leftover section can be named.
    pub enrolment: Option<IgnoredAny>,
    /// How repeated admission failures from one peer address are throttled.
    #[serde(default)]
    pub admission_throttle: AdmissionThrottleConfig,
    /// How often an admitted peer may be heard on the Agent plane.
    #[serde(default)]
    pub agent_rate_limit: AgentRateLimitConfig,
    /// How long an access token is accepted after it is issued, in seconds; `0` — the default —
    /// means it never expires. A token ends when it is replaced all the same.
    #[serde(default)]
    pub token_lifetime_secs: u64,
    /// How the log is written on standard error.
    #[serde(default)]
    pub log: LogConfig,
    /// The Package Signers the Server refuses.
    #[serde(default)]
    pub packages: PackagesConfig,
    /// The path of the Unix socket `classis-cli` administers the Spaces over. The Server creates it
    /// owner-only, and its directory too when that is missing.
    #[serde(default = "default_admin_socket")]
    pub admin_socket: PathBuf,
}

/// The `[log]` section: the format of every line the Server writes to standard error. The level is
/// `RUST_LOG`'s, not a key.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// `"text"` (the default), one human-readable line per event, or `"json"`, one JSON object per
    /// line for a log collector.
    pub format: LogFormat,
}

/// The formats of `[log] format`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// The `[agent_rate_limit]` section. Every key has a default, and none is `0`:
/// no value switches the limit off.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentRateLimitConfig {
    /// Tokens a host's bucket gains per second.
    pub messages_per_sec: u32,
    /// That bucket's capacity; a new bucket starts full.
    pub burst: u32,
}

impl Default for AgentRateLimitConfig {
    fn default() -> Self {
        let limits = crate::agent_rate::Limits::default();
        AgentRateLimitConfig {
            messages_per_sec: limits.messages_per_sec,
            burst: limits.burst,
        }
    }
}

impl AgentRateLimitConfig {
    /// The limits the buckets count by.
    #[must_use]
    pub fn limits(&self) -> crate::agent_rate::Limits {
        crate::agent_rate::Limits {
            messages_per_sec: self.messages_per_sec,
            burst: self.burst,
        }
    }

    fn check(&self) -> Result<(), String> {
        for (key, value) in [
            ("messages_per_sec", self.messages_per_sec),
            ("burst", self.burst),
        ] {
            if value == 0 {
                return Err(format!(
                    "[agent_rate_limit] {key} must be greater than zero — the limit is never \
                     switched off; raise it instead"
                ));
            }
        }
        Ok(())
    }
}

/// The heartbeat the Baseline uses when none is offered.
const BASELINE_HEARTBEAT_SECS: u64 = 30;

/// The `[blobs]` section: which store keeps the artifacts' bytes. One store,
/// the filesystem by default; both are supported in production.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobsConfig {
    /// `"fs"`, one file per blob under `data_dir/blobs/`, or `"s3"`, one object per blob in the
    /// bucket `[blobs.s3]` names. A string rather than an enum so that any other value is refused
    /// by [`check`](Self::check), naming the key.
    #[serde(default = "default_blob_store")]
    pub store: String,
    /// The bucket, when `store = "s3"`; refused beside `store = "fs"`.
    pub s3: Option<S3BlobsConfig>,
}

impl Default for BlobsConfig {
    fn default() -> Self {
        BlobsConfig {
            store: default_blob_store(),
            s3: None,
        }
    }
}

fn default_blob_store() -> String {
    "fs".to_string()
}

impl BlobsConfig {
    /// The bucket's settings when the store is S3, `None` when it is the filesystem.
    #[must_use]
    pub fn s3(&self) -> Option<&S3BlobsConfig> {
        self.s3.as_ref().filter(|_| self.store == "s3")
    }

    /// Loud validation: a known store, the bucket's section exactly
    /// when the store is S3, and an S3 connection that stays off plaintext and holds no half of a
    /// key pair.
    fn check(&self) -> Result<(), String> {
        match (self.store.as_str(), &self.s3) {
            ("fs", None) => Ok(()),
            ("fs", Some(_)) => Err(
                "[blobs.s3] is set but [blobs] store is \"fs\" — set store = \"s3\" to keep \
                 the artifacts in the bucket, or remove [blobs.s3]"
                    .to_string(),
            ),
            ("s3", None) => Err(
                "[blobs] store = \"s3\" needs a [blobs.s3] section naming endpoint, bucket and \
                 region"
                    .to_string(),
            ),
            ("s3", Some(s3)) => s3.check(),
            (other, _) => Err(format!(
                "[blobs] store must be \"fs\" or \"s3\", not {other:?}"
            )),
        }
    }
}

/// The `[blobs.s3]` section: the one bucket that keeps the artifacts,
/// and how the Server reaches it. Every setting of the connection is here and nowhere else; the
/// Server reads no `AWS_*` variable that would change one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3BlobsConfig {
    /// The store's URL, `https://`; `http://` only to 127.0.0.1 or ::1.
    pub endpoint: String,
    /// The bucket. The Server does not create it.
    pub bucket: String,
    /// The region the requests are signed for.
    pub region: String,
    /// Where under the bucket the Server's keys live: empty, or ending in `/`. Objects are kept at
    /// `<prefix>blobs/<sha256>`, an upload in progress at `<prefix>staging/<random>`.
    #[serde(default)]
    pub prefix: String,
    /// One PEM root for a store whose certificate no public root signs.
    pub ca_file: Option<PathBuf>,
    /// The key ID of a static key pair, set together with `secret_access_key_file`. Without both,
    /// the Server uses its platform's workload identity.
    pub access_key_id: Option<String>,
    /// The file holding the secret of that key pair, readable by its owner and group alone.
    pub secret_access_key_file: Option<PathBuf>,
}

impl std::fmt::Debug for S3BlobsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3BlobsConfig")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("ca_file", &self.ca_file)
            .field(
                "access_key_id",
                &self.access_key_id.as_ref().map(|_| "<set>"),
            )
            .field("secret_access_key_file", &self.secret_access_key_file)
            .finish()
    }
}

impl S3BlobsConfig {
    /// Whether the endpoint is plaintext, which [`check`](Self::check) allows on the loopback
    /// alone.
    #[must_use]
    pub fn allows_http(&self) -> bool {
        opamp::endpoint::is_plaintext(&self.endpoint)
    }

    fn check(&self) -> Result<(), String> {
        // Q-1: a package is never sent unencrypted beyond the loopback, to the store neither.
        let endpoint = &self.endpoint;
        match endpoint.split_once("://").map(|(scheme, _)| scheme) {
            Some("https") => {}
            Some("http")
                if opamp::endpoint::is_loopback_literal(opamp::endpoint::host_of(endpoint)) => {}
            Some("http") => {
                return Err(format!(
                    "[blobs.s3] endpoint {endpoint}: plaintext is for 127.0.0.1 and ::1 alone — \
                     use https://"
                ))
            }
            _ => {
                return Err(format!(
                    "[blobs.s3] endpoint {endpoint} must start with https:// (http:// only to \
                     127.0.0.1 or ::1)"
                ))
            }
        }
        for (key, value) in [("bucket", &self.bucket), ("region", &self.region)] {
            if value.trim().is_empty() {
                return Err(format!("[blobs.s3] {key} must not be empty"));
            }
        }
        let prefix = &self.prefix;
        if !prefix.is_empty()
            && (!prefix.ends_with('/')
                || prefix.starts_with('/')
                || prefix
                    .split('/')
                    .rev()
                    .skip(1)
                    .any(|segment| segment.is_empty() || segment == "." || segment == ".."))
        {
            return Err(format!(
                "[blobs.s3] prefix {prefix:?} must be empty or end in `/`, with no empty, `.` or \
                 `..` segment, e.g. \"fleet/\""
            ));
        }
        // `object_store` percent-encodes these in a key it builds, so the Server's keys would
        // not be the ones it lists under the prefix: refused here rather than at the first upload.
        if let Some(c) = prefix
            .chars()
            .find(|c| !c.is_ascii() || c.is_ascii_control() || "\\{^}%`]\">[~<#|*?".contains(*c))
        {
            return Err(format!(
                "[blobs.s3] prefix {prefix:?} holds {c:?}, which the S3 client would \
                 percent-encode — use letters, digits and - _ . / ! ' ( ) & $ @ = ; : + , and \
                 space"
            ));
        }
        if self.access_key_id.is_some() != self.secret_access_key_file.is_some() {
            return Err(
                "[blobs.s3] access_key_id and secret_access_key_file are set together or not at \
                 all — without both, the Server uses its platform's workload identity"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The `[database]` section: where the Server keeps its records. One store,
/// the filesystem under `data_dir` by default; both are supported in production.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// `"fs"`, one file per record under `data_dir`, or `"postgres"`, one database that
    /// `[database.postgres]` names. A string rather than an enum so that any other value is
    /// refused by [`check`](Self::check), naming the key.
    #[serde(default = "default_record_store")]
    pub store: String,
    /// The database, when `store = "postgres"`; refused beside `store = "fs"`.
    pub postgres: Option<PostgresConfig>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            store: default_record_store(),
            postgres: None,
        }
    }
}

fn default_record_store() -> String {
    "fs".to_string()
}

impl DatabaseConfig {
    /// The database's settings when the records live in PostgreSQL, `None` when they are files.
    #[must_use]
    pub fn postgres(&self) -> Option<&PostgresConfig> {
        self.postgres.as_ref().filter(|_| self.store == "postgres")
    }

    /// Loud validation: a known store, the database's section exactly
    /// when the store is PostgreSQL, and a connection that stays off plaintext beyond the loopback.
    fn check(&self) -> Result<(), String> {
        match (self.store.as_str(), &self.postgres) {
            ("fs", None) => Ok(()),
            ("fs", Some(_)) => Err(
                "[database.postgres] is set but [database] store is \"fs\" — set store = \
                 \"postgres\" to keep the records in the database, or remove [database.postgres]"
                    .to_string(),
            ),
            ("postgres", None) => Err(
                "[database] store = \"postgres\" needs a [database.postgres] section naming host, \
                 dbname, user and password_file"
                    .to_string(),
            ),
            ("postgres", Some(postgres)) => postgres.check(),
            (other, _) => Err(format!(
                "[database] store must be \"fs\" or \"postgres\", not {other:?}"
            )),
        }
    }
}

/// The `[database.postgres]` section: the one database that keeps the records,
/// and how the Server reaches it. Every setting of the connection is here and nowhere else; the
/// Server reads no `PG*` variable that would change one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    /// The database's host name or IP address — what its certificate must name.
    pub host: String,
    /// Its port.
    #[serde(default = "default_postgres_port")]
    pub port: u16,
    /// The database. The Server does not create it.
    pub dbname: String,
    /// The role the Server signs in as. The Server does not create it.
    pub user: String,
    /// The file holding the role's password, readable by its owner and group alone.
    pub password_file: PathBuf,
    /// One PEM root for a database whose certificate no public root signs.
    pub ca_file: Option<PathBuf>,
    /// `false` connects without TLS, which is allowed to a loopback IP literal alone (Q-1).
    #[serde(default = "default_postgres_tls")]
    pub tls: bool,
}

fn default_postgres_port() -> u16 {
    5432
}

fn default_postgres_tls() -> bool {
    true
}

impl PostgresConfig {
    fn check(&self) -> Result<(), String> {
        for (key, value) in [
            ("host", &self.host),
            ("dbname", &self.dbname),
            ("user", &self.user),
        ] {
            if value.trim().is_empty() {
                return Err(format!("[database.postgres] {key} must not be empty"));
            }
        }
        if self.port == 0 {
            return Err("[database.postgres] port must not be 0".to_string());
        }
        if self.host.starts_with('/') {
            return Err(format!(
                "[database.postgres] host {:?} names a socket directory — the Server connects \
                 over TCP, to a host name or an IP address",
                self.host
            ));
        }
        // Q-1: a credential never crosses a network unencrypted, the database password neither.
        if !self.tls && !opamp::endpoint::is_loopback_literal(&self.host) {
            return Err(format!(
                "[database.postgres] tls = false is for a host that is a loopback IP literal \
                 (127.0.0.1 or ::1) alone, and host is {:?} — remove tls = false",
                self.host
            ));
        }
        if !self.tls && self.ca_file.is_some() {
            return Err(
                "[database.postgres] ca_file is set but tls = false — a root verifies nothing \
                 without TLS; remove one of them"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The secret in `file`, which no account outside the file's group may read and no account but
/// its owner may write: the key `key` names it in every refusal. Group read is allowed — `0640`, or
/// `0440` with a group of the orchestrator's choice,
/// as Kubernetes mounts a secret with `fsGroup` — and nothing for others, nor group write.
/// Surrounding whitespace is dropped, and an empty secret is refused. The file's bytes and the
/// secret are held in buffers wiped when they are dropped, on every path; a caller
/// whose library takes an owned copy makes it at that call.
///
/// # Errors
/// Returns an error naming the key and the file when it cannot be read, is not UTF-8 text, may be
/// read by others or written by its group, or is empty.
pub fn read_secret_file(key: &str, file: &Path) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::Read as _;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(file)
            .map_err(|e| format!("{key} {}: {e}", file.display()))?
            .permissions()
            .mode();
        if mode & 0o027 != 0 {
            return Err(format!(
                "{key} {} may be read by others or written by its group (mode {:o}) — restrict \
                 it: chmod 600, or 640 to let its group read it",
                file.display(),
                mode & 0o777
            ));
        }
    }
    let failed = |e: std::io::Error| format!("{key} {}: {e}", file.display());
    let mut handle = std::fs::File::open(file).map_err(failed)?;
    // Sized to the file, so the buffer is read at its final size and not grown and left behind.
    let size = handle.metadata().map_err(failed)?.len();
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(
        usize::try_from(size).unwrap_or_default(),
    ));
    handle.read_to_end(&mut bytes).map_err(failed)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{key} {}: not UTF-8 text", file.display()))?;
    let secret = text.trim();
    if secret.is_empty() {
        return Err(format!("{key} {} is empty", file.display()));
    }
    Ok(zeroize::Zeroizing::new(secret.to_string()))
}

/// The most Package Signers `[packages] revoked_signers` names.
pub const MAX_REVOKED_SIGNERS: usize = 64;

/// The Package Signers this Server no longer trusts, each by the SHA-256 of its DER certificate.
/// Empty unless `[packages] revoked_signers` names some.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevokedSigners(std::collections::BTreeSet<[u8; 32]>);

impl RevokedSigners {
    /// The signers `items` name, each as 64 lowercase hex digits.
    ///
    /// # Errors
    ///
    /// More than [`MAX_REVOKED_SIGNERS`] items, an item that is not 64 lowercase hex digits, or an
    /// item named twice, each naming the setting and the item.
    pub fn parse(items: &[String]) -> Result<Self, String> {
        if items.len() > MAX_REVOKED_SIGNERS {
            return Err(format!(
                "[packages] revoked_signers names {} Package Signers, at most {MAX_REVOKED_SIGNERS} \
                 are allowed",
                items.len()
            ));
        }
        let mut fingerprints = std::collections::BTreeSet::new();
        for item in items {
            let mut fingerprint = [0u8; 32];
            let lowercase_hex = item.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !lowercase_hex || hex::decode_to_slice(item, &mut fingerprint).is_err() {
                return Err(format!(
                    "[packages] revoked_signers item {item:?} is not the SHA-256 of a certificate \
                     — 64 lowercase hex digits"
                ));
            }
            if !fingerprints.insert(fingerprint) {
                return Err(format!(
                    "[packages] revoked_signers names {item:?} twice — remove the duplicate"
                ));
            }
        }
        Ok(RevokedSigners(fingerprints))
    }

    /// How many Package Signers are revoked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no Package Signer is revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the Package Signer whose DER certificate is `certificate` is revoked.
    #[must_use]
    pub fn contains(&self, certificate: &[u8]) -> bool {
        self.0
            .contains(&<[u8; 32]>::from(Sha256::digest(certificate)))
    }
}

/// The `[packages]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesConfig {
    /// The Package Signers the Server refuses, each the SHA-256 of its DER certificate as 64
    /// lowercase hex digits. A signature of a listed signer is refused on a write and withheld at
    /// load, as an expired one is. Read at start.
    #[serde(default)]
    pub revoked_signers: Vec<String>,
}

impl PackagesConfig {
    /// The revoked signers the section names.
    ///
    /// # Errors
    ///
    /// The reasons of [`RevokedSigners::parse`].
    pub fn revoked_signers(&self) -> Result<RevokedSigners, String> {
        RevokedSigners::parse(&self.revoked_signers)
    }

    fn check(&self) -> Result<(), String> {
        self.revoked_signers().map(|_| ())
    }
}

/// The adapter behind [`SignatureVerifier`](crate::packages::SignatureVerifier):
/// `classis_core::package::chain::verify_now` up to a set of Package Roots, at the current time —
/// the check the Client makes — and then a refusal of a revoked Package Signer.
#[derive(Debug, Clone)]
pub struct RootsVerifier {
    roots: classis_core::package::Roots,
    revoked: RevokedSigners,
}

impl RootsVerifier {
    /// Up to `roots`, with no signer revoked.
    #[must_use]
    pub fn new(roots: classis_core::package::Roots) -> Self {
        RootsVerifier {
            roots,
            revoked: RevokedSigners::default(),
        }
    }

    /// Refusing `revoked` as well.
    #[must_use]
    pub fn with_revoked(mut self, revoked: RevokedSigners) -> Self {
        self.revoked = revoked;
        self
    }
}

impl crate::packages::SignatureVerifier for RootsVerifier {
    fn verify(&self, statement: &[u8], signature: &[u8]) -> Result<(), String> {
        classis_core::package::chain::verify_now(statement, signature, &self.roots)
            .map_err(|e| e.to_string())?;
        if self.revoked.is_empty() {
            return Ok(());
        }
        let parsed =
            classis_core::package::parse_signature(signature).map_err(|e| e.to_string())?;
        if self.revoked.contains(parsed.signer) {
            return Err(
                "the signature's Package Signer is revoked on this Server — \
                        [packages] revoked_signers names it"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The `[admission_throttle]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdmissionThrottleConfig {
    /// Failures within `window_secs` that put a peer address in back-off.
    pub max_failures: u32,
    pub window_secs: u64,
    /// How long a peer address in back-off is answered `429`.
    pub backoff_secs: u64,
}

impl Default for AdmissionThrottleConfig {
    fn default() -> Self {
        let limits = crate::throttle::Limits::default();
        AdmissionThrottleConfig {
            max_failures: limits.max_failures,
            window_secs: limits.window_secs,
            backoff_secs: limits.backoff_secs,
        }
    }
}

impl AdmissionThrottleConfig {
    /// The limits the throttle counts by.
    #[must_use]
    pub fn limits(&self) -> crate::throttle::Limits {
        crate::throttle::Limits {
            max_failures: self.max_failures,
            window_secs: self.window_secs,
            backoff_secs: self.backoff_secs,
        }
    }
}

/// The `[rest]` section: the Operator plane's own listener. It is a section rather than
/// a bare key because the plane is what grows next — an authentication decision belongs inside it,
/// not beside it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestConfig {
    /// Address and port the REST API, the API docs, and the bundled UI bind.
    #[serde(default = "default_rest_listen")]
    pub listen: SocketAddr,
    /// Optional Basic authentication over the whole plane; required off the loopback.
    pub auth: Option<RestAuthConfig>,
    /// The connections the Operator plane holds at once. `0` is refused at load.
    #[serde(default = "default_rest_max_connections")]
    pub max_connections: usize,
    /// Refused at startup, like `[tls]`. Read only so that a leftover section can be
    /// named.
    pub tls: Option<IgnoredAny>,
}

impl Default for RestConfig {
    fn default() -> Self {
        RestConfig {
            listen: default_rest_listen(),
            auth: None,
            max_connections: default_rest_max_connections(),
            tls: None,
        }
    }
}

/// The `[rest.auth]` section: who may reach the Operator plane. Basic only — the
/// audience is a browser and `curl`, and Basic is the one scheme both speak without a login page.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestAuthConfig {
    /// Accepted Basic credentials, `user = "<Argon2id hash>"`. Several allow
    /// a rotation, or an individual operator's credential to be withdrawn on its own.
    #[serde(default)]
    pub basic_users: BTreeMap<String, String>,
    /// A TOML file holding the `basic_users` table, readable by the Server's account alone; never
    /// beside it, and the one way the environment names credentials.
    pub basic_users_file: Option<PathBuf>,
}

impl std::fmt::Debug for RestAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestAuthConfig")
            .field("basic_users", &self.basic_users.keys().collect::<Vec<_>>())
            .field("basic_users_file", &self.basic_users_file)
            .finish()
    }
}

impl RestAuthConfig {
    /// The check the Operator plane runs on every request.
    ///
    /// # Errors
    /// Returns an error naming an entry that is not a hash this Server keeps.
    pub fn credentials(&self) -> Result<crate::credentials::Credentials, String> {
        crate::credentials::Credentials::new(&self.basic_users, self.challenge())
            .map_err(|e| format!("[rest.auth.basic_users] {e}"))
    }

    /// The `WWW-Authenticate` challenge — what makes a browser ask for the password rather than
    /// show the operator a bare `401` (RFC 7617).
    pub fn challenge(&self) -> String {
        r#"Basic realm="opamp""#.to_string()
    }

    /// A section that authenticates nobody would lock the operator out of their own Server, and an
    /// empty user or password is a half-written credential rather than an intent.
    fn check(&self) -> Result<(), String> {
        if self.basic_users.is_empty() {
            return Err(
                "a [rest.auth] section needs at least one entry in [rest.auth.basic_users] or \
                 in its basic_users_file"
                    .to_string(),
            );
        }
        for (user, password) in &self.basic_users {
            if user.is_empty() || password.is_empty() {
                return Err(format!(
                    "the [rest.auth.basic_users] entry {user:?} needs a name and a password"
                ));
            }
        }
        self.credentials().map(|_| ())
    }
}

/// The `[connection_offer]` section: what every Agent declaring
/// `AcceptsOpAMPConnectionSettings` is offered — a heartbeat interval, an endpoint. Either or both,
/// but never neither. It carries no credential: an offered credential would be one nothing reads.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionOfferConfig {
    /// Offered heartbeat interval — on plain HTTP the polling interval (the Baseline's MUST).
    pub heartbeat_interval_secs: Option<u64>,
    /// Offered OpAMP endpoint, e.g. for a Server move; `ws(s)://` or `http(s)://`.
    pub endpoint: Option<String>,
    /// Refused at startup, each naming itself: the keys of an offered credential. Read only so that
    /// a leftover one is named rather than reported as an unknown field.
    bearer_token_file: Option<IgnoredAny>,
    username: Option<IgnoredAny>,
    password_file: Option<IgnoredAny>,
    bearer_token: Option<IgnoredAny>,
    password: Option<IgnoredAny>,
}

impl ConnectionOfferConfig {
    /// Loud validation: no credential key, at least one offered field, and an endpoint
    /// that keeps the fleet on TLS off the loopback.
    fn check(&self) -> Result<(), String> {
        for (key, value) in [
            ("bearer_token_file", &self.bearer_token_file),
            ("username", &self.username),
            ("password_file", &self.password_file),
            ("bearer_token", &self.bearer_token),
            ("password", &self.password),
        ] {
            if value.is_some() {
                return Err(format!(
                    "[connection_offer] {key} is refused — no credential is offered; remove the \
                     key"
                ));
            }
        }
        if self.heartbeat_interval_secs.is_none() && self.endpoint.is_none() {
            return Err(
                "a [connection_offer] section needs heartbeat_interval_secs or endpoint"
                    .to_string(),
            );
        }
        // An offer never moves a fleet to plaintext, on the loopback neither: whoever listens on
        // that port would be the fleet's Server, unproven.
        if let Some(endpoint) = &self.endpoint {
            opamp::endpoint::check_url(endpoint)
                .map_err(|e| format!("[connection_offer] endpoint {e}"))?;
            if opamp::endpoint::is_plaintext(endpoint) {
                return Err(format!(
                    "[connection_offer] endpoint {endpoint}: an offer never moves a fleet to \
                     plaintext — use wss:// or https://"
                ));
            }
        }
        Ok(())
    }
}

/// The `[telemetry_offer]` section: where Agents send their own telemetry.
///
/// The endpoints are full OTLP/HTTP URLs *with path*, which is what the Baseline requires of them;
/// this Server does not append `/v1/metrics` for you, because guessing a receiver's routing is how
/// telemetry disappears into a 404 nobody looks at.
///
/// **What this section says, it says about all three signals**. A signal left out is
/// offered no destination and is *stopped* on an Agent that was reporting it, and an endpoint set
/// to the empty string is an explicit withdrawal — the one way to say "stop all three", since a
/// Server that offers nothing at all is a Server that says nothing at all. Removing the section
/// keeps that second meaning: it withdraws nothing, so a Server without telemetry of its own does
/// not tear down a fleet another Server pointed at a collector.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryOfferConfig {
    pub metrics_endpoint: Option<String>,
    pub traces_endpoint: Option<String>,
    pub logs_endpoint: Option<String>,
    /// Headers sent with every signal — an access token for the receiving backend, typically.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// A TOML file holding the `headers` table; never beside it, and the one way the environment
    /// names them.
    pub headers_file: Option<PathBuf>,
}

impl TelemetryOfferConfig {
    /// Loud validation: an empty section offers nothing and is never what an operator
    /// meant, and an endpoint that is not an OTLP/HTTP URL would be refused by every Agent.
    ///
    /// An endpoint set to the empty string passes both tests deliberately — it is a withdrawal,
    /// which is a thing to be said rather than a URL to be checked.
    fn check(&self) -> Result<(), String> {
        let endpoints = [
            ("metrics_endpoint", &self.metrics_endpoint),
            ("traces_endpoint", &self.traces_endpoint),
            ("logs_endpoint", &self.logs_endpoint),
        ];
        if endpoints.iter().all(|(_, value)| value.is_none()) {
            return Err(
                "a [telemetry_offer] section needs at least one of metrics_endpoint,                  traces_endpoint, or logs_endpoint"
                    .to_string(),
            );
        }
        for (key, value) in endpoints {
            if let Some(endpoint) = value.as_ref().filter(|endpoint| !endpoint.is_empty()) {
                if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                    return Err(format!(
                        "[telemetry_offer] {key} must be a full OTLP/HTTP URL with path, e.g.                          https://collector.example:4318/v1/metrics"
                    ));
                }
            }
        }
        Ok(())
    }
}

fn default_agent_max_connections() -> usize {
    opamp::server::listen::DEFAULT_MAX_CONNECTIONS
}

fn default_rest_max_connections() -> usize {
    256
}

fn default_listen() -> SocketAddr {
    DEFAULT_LISTEN.parse().expect("default listen address")
}

fn default_rest_listen() -> SocketAddr {
    DEFAULT_REST_LISTEN
        .parse()
        .expect("default REST listen address")
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("fleet-data")
}

fn default_admin_socket() -> PathBuf {
    PathBuf::from(classis_admin::protocol::DEFAULT_SOCKET)
}

fn default_max_message_size() -> usize {
    opamp::frame::DEFAULT_MAX_MESSAGE_SIZE
}

/// Three times the Baseline's own default heartbeat of 30 seconds: one missed beat is a
/// lost packet, and a fleet view that flickers is one nobody trusts.
fn default_stale_after_secs() -> u64 {
    90
}

/// Roomy enough for the real thing: an `otelcol-contrib` binary is a few hundred megabytes.
fn default_max_package_size() -> usize {
    crate::fleet::DEFAULT_MAX_PACKAGE_SIZE
}

/// Roomy for a real package set — a handful of packages across a few platforms, each with a
/// rollback copy — while still bounding the store a caller can grow.
fn default_max_total_package_size() -> u64 {
    crate::fleet::DEFAULT_MAX_TOTAL_PACKAGE_SIZE
}

/// Far above any real fleet, so an authenticated deployment never meets it, yet low enough that the
/// in-memory map and its per-Agent disk mirror stay bounded under a flood of self-asserted UIDs.
fn default_max_agents() -> usize {
    crate::fleet::DEFAULT_MAX_AGENTS
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: default_listen(),
            rest: RestConfig::default(),
            data_dir: default_data_dir(),
            config_dir: None,
            tls: None,
            auth: None,
            agents: None,
            connection_offer: None,
            client_ca: None,
            telemetry_offer: None,
            packages_dir: None,
            blobs: BlobsConfig::default(),
            database: DatabaseConfig::default(),
            advertised_url: None,
            public_url: None,
            max_message_size_bytes: default_max_message_size(),
            max_package_size_bytes: default_max_package_size(),
            max_total_package_bytes: default_max_total_package_size(),
            stale_after_secs: default_stale_after_secs(),
            max_agents: default_max_agents(),
            max_connections: default_agent_max_connections(),
            enrolment: None,
            admission_throttle: AdmissionThrottleConfig::default(),
            agent_rate_limit: AgentRateLimitConfig::default(),
            log: LogConfig::default(),
            packages: PackagesConfig::default(),
            token_lifetime_secs: 0,
            admin_socket: default_admin_socket(),
        }
    }
}

/// Whether two listener addresses cannot both be bound: the same port on the same address, or on
/// an address that covers every interface — `0.0.0.0:4320` and `127.0.0.1:4320` are two spellings
/// of one socket as far as the second `bind` is concerned.
fn listeners_collide(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

/// The rules on `public_url`. The same transport rule as every URL of this product (Q-1): `https://`
/// anywhere, `http://` to a loopback IP literal alone — and no credential, query or fragment, which
/// is what the Client itself refuses on the URL an operator types there. A path prefix is kept:
/// a proxy may mount the Server under one, and the Client resolves its routes against the base.
///
/// Nothing the printed command line cannot carry gets through: `classis-cli enrol-command` puts this
/// URL into a single-quoted argument of a `curl` line and a PowerShell line, and a quote or a
/// control character there ends the argument early.
fn check_public_url(url: &str) -> Result<(), String> {
    // Checked on the raw text first: the URL parser drops tabs and newlines rather than refusing
    // them, which would silently change the base an operator wrote.
    if let Some(c) = url.chars().find(|c| c.is_control() || *c == '\'') {
        return Err(format!(
            "public_url {url:?} holds {c:?} — the URL of the public endpoint carries no quote and \
             no control character; the command line classis-cli prints would break on it"
        ));
    }
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("public_url {url}: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if opamp::endpoint::is_loopback_literal(parsed.host_str().unwrap_or("")) => {}
        "http" => {
            return Err(format!(
                "public_url {url}: plaintext is for 127.0.0.1 and ::1 alone — use https://"
            ))
        }
        _ => {
            return Err(format!(
                "public_url {url} must start with https:// (http:// only to 127.0.0.1 or ::1)"
            ))
        }
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!(
            "public_url {url} must be a scheme, a host and perhaps a path prefix, and nothing \
             else — no user, password, query or fragment"
        ));
    }
    Ok(())
}

impl ServerConfig {
    /// Loads `path` alone, with no environment: [`load_layered`](Self::load_layered) with the file
    /// and no variables.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::load_layered(Some(path), Vec::new()).map(|layered| layered.config)
    }

    /// Builds the configuration from its layers: the built-in defaults, then
    /// `file` when one is read, then every `CLASSIS_SERVER__…` variable among `variables`, each
    /// later layer winning per key. The variables are taken as an argument so that the process
    /// environment is read in one place, [`server_variables`].
    ///
    /// The merged document is deserialized once and held to the same rules as a file alone.
    /// An error caused by a variable names the variable.
    pub fn load_layered(
        file: Option<&Path>,
        variables: Vec<(String, String)>,
    ) -> Result<Layered, String> {
        let text = file
            .map(|path| {
                std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))
            })
            .transpose()?;
        let mut document = match (&text, file) {
            (Some(text), Some(path)) => toml::from_str::<toml::Table>(text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?,
            _ => toml::Table::new(),
        };
        let variables = environment(variables)?;
        for variable in &variables {
            variable.set_in(&mut document)?;
        }
        let origin = match (file, variables.is_empty()) {
            (Some(path), true) => path.display().to_string(),
            (Some(path), false) => format!("{} and the environment", path.display()),
            (None, false) => "the environment".to_string(),
            (None, true) => "the defaults".to_string(),
        };
        // A table read from a file is never beside the same table written inline: one of the two
        // would be silently ignored.
        for (table, file_key) in TABLES_FROM_FILES {
            let section = &table[..table.len() - 1];
            let inline = lookup(&document, table).is_some();
            let mut file_path = section.to_vec();
            file_path.push(file_key);
            if inline && lookup(&document, &file_path).is_some() {
                return Err(format!(
                    "{origin}: [{}] {file_key} and [{}] are both set — name the table in one \
                     place",
                    section.join("."),
                    table.join("."),
                ));
            }
        }
        let mut config: ServerConfig =
            toml::Value::Table(document)
                .try_into()
                .map_err(|e: toml::de::Error| match blamed(&variables, &e) {
                    Some(variable) if e.message().starts_with("unknown field") => format!(
                        "{} names no key of the Server's configuration: {}",
                        variable.name,
                        e.message()
                    ),
                    Some(variable) => format!("{}: {}", variable.name, e.message()),
                    None => {
                        // The file alone, parsed again as text, points at the line — when it
                        // fails alone with the same complaint, whatever the environment set
                        // beside it.
                        let detail = text
                            .as_deref()
                            .and_then(|text| toml::from_str::<ServerConfig>(text).err())
                            .filter(|alone| alone.message() == e.message())
                            .map_or_else(|| e.to_string(), |alone| alone.to_string());
                        format!("cannot parse {origin}: {detail}")
                    }
                })?;
        config
            .read_table_files()
            .and_then(|()| config.check())
            .map_err(|e| format!("{origin}: {e}"))?;
        Ok(Layered {
            config,
            origin,
            from_environment: variables
                .into_iter()
                .map(|variable| (variable.path.join("."), variable.name))
                .collect(),
        })
    }

    /// Fills `basic_users` and `headers` from the files that name them.
    fn read_table_files(&mut self) -> Result<(), String> {
        if let Some(auth) = &mut self.rest.auth {
            if let Some(path) = &auth.basic_users_file {
                auth.basic_users = read_table_file("[rest.auth] basic_users_file", path)?;
            }
        }
        if let Some(telemetry) = &mut self.telemetry_offer {
            if let Some(path) = &telemetry.headers_file {
                telemetry.headers = read_table_file("[telemetry_offer] headers_file", path)?;
            }
        }
        Ok(())
    }

    /// The startup checks every layered document passes, its source aside.
    fn check(&self) -> Result<(), String> {
        // The Agent plane has no credential of its own. A leftover section is
        // refused rather than ignored: an operator is present at a Server upgrade, and a section
        // that silently did nothing would tell them the fleet still needs it.
        if self.auth.is_some() {
            return Err(
                "[auth] is refused — the Agent plane has no credential of its own; \
                 remove the section"
                    .to_string(),
            );
        }
        // The Server does not authenticate Agents: the proxy in front of it admits
        // them. A leftover `[agents.auth]` is refused rather than ignored: an operator who kept it
        // believes the Server still verifies a token, and a section that silently did nothing
        // would leave the Agent plane open without them knowing.
        if self.agents.is_some() {
            return Err(
                "[agents.auth] is removed — the Server does not authenticate Agents; \
                 the reverse proxy in front of it admits them, so the Agent port must be \
                 reachable only through it; remove the section"
                    .to_string(),
            );
        }
        // The Server speaks plain HTTP behind a reverse proxy that terminates TLS. A
        // leftover section is refused rather than ignored: an operator who kept `[tls]` believes
        // the Server still terminates TLS, and a section that silently did nothing would let them
        // publish plaintext without knowing.
        for (section, named) in [
            ("[tls]", self.tls.is_some()),
            ("[rest.tls]", self.rest.tls.is_some()),
            ("[client_ca]", self.client_ca.is_some()),
            ("[enrolment]", self.enrolment.is_some()),
        ] {
            if named {
                return Err(format!(
                    "{section} is removed — the Server speaks plain HTTP behind a reverse proxy \
                     that terminates TLS and admits Agents; remove the section"
                ));
            }
        }
        // One root for all state. A leftover key is refused rather than
        // ignored: the directory it names holds the fleet's trust data, which this Server would
        // otherwise start without.
        for (key, named) in [
            ("config_dir", self.config_dir.is_some()),
            ("packages_dir", self.packages_dir.is_some()),
        ] {
            if named {
                return Err(format!(
                    "{key} is removed — the Server keeps all of its state under data_dir. \
                     Stop the Server, run `server migrate --config-dir <old> \
                     --packages-dir <old> --data-dir <new>`, then replace config_dir and \
                     packages_dir with data_dir"
                ));
            }
        }
        if self.advertised_url.is_some() {
            return Err(
                "advertised_url is removed — every package is offered as a path the Client \
                 resolves against its own Server, and a Client downloads from no other host; \
                 remove the key"
                    .to_string(),
            );
        }
        if let Some(offer) = &self.connection_offer {
            offer.check()?;
        }
        if let Some(telemetry) = &self.telemetry_offer {
            telemetry.check()?;
        }
        if let Some(auth) = &self.rest.auth {
            auth.check()?;
        }
        self.blobs.check()?;
        self.database.check()?;
        self.packages.check()?;
        // The two planes are two listeners. Addresses that collide would surface as the
        // second bind failing with "address already in use" — a message about sockets for what is
        // really a configuration mistake, so it is refused here, by name.
        if listeners_collide(self.listen, self.rest.listen) {
            return Err(format!(
                "listen ({}) and [rest] listen ({}) must be different addresses — the Agent \
                 plane and the Operator plane are separate listeners",
                self.listen, self.rest.listen
            ));
        }
        // A limit of zero would refuse every message, and the Baseline knows no "unlimited": the
        // limit is mandatory, so a value that cannot carry a message fails startup.
        if self.max_message_size_bytes == 0 {
            return Err("max_message_size_bytes must be greater than zero".to_string());
        }
        if self.stale_after_secs == 0 {
            return Err(
                "stale_after_secs must be greater than zero — a budget of nothing would call \
                 every Agent stale the instant it reported"
                    .to_string(),
            );
        }
        if self.max_package_size_bytes == 0 {
            return Err("max_package_size_bytes must be greater than zero".to_string());
        }
        if self.max_total_package_bytes == 0 {
            return Err(
                "max_total_package_bytes must be greater than zero — it bounds the store, not a \
                 switch"
                    .to_string(),
            );
        }
        if self.max_agents == 0 {
            return Err(
                "max_agents must be greater than zero — a fleet that can hold no Agent is a \
                 misconfiguration, not a limit"
                    .to_string(),
            );
        }
        self.agent_rate_limit.check()?;
        if self.max_connections == 0 || self.rest.max_connections == 0 {
            return Err(
                "max_connections and [rest] max_connections must be greater than zero — a \
                 plane that holds no connection serves nobody"
                    .to_string(),
            );
        }
        // The public URL goes into the install command an operator pastes onto a host, so a wrong
        // one is refused at load, by name, and not at the first `enrol-command`.
        if let Some(url) = &self.public_url {
            check_public_url(url)?;
        }
        self.check_secure()
    }

    /// The lifetime of the tokens this Server issues: `token_lifetime_secs`,
    /// with `0` for a token that never expires.
    #[must_use]
    pub fn token_lifetime(&self) -> oauth_token::server::Lifetime {
        std::num::NonZeroU64::new(self.token_lifetime_secs).map_or(
            oauth_token::server::Lifetime::Never,
            oauth_token::server::Lifetime::Seconds,
        )
    }

    /// A warning when one host cannot report for all the Agents it may speak for at the fleet's
    /// heartbeat: `messages_per_sec` times the offered heartbeat interval, or
    /// the Baseline's 30 s, below 256. A limit set too low costs availability, not security, so
    /// the Server starts.
    #[must_use]
    pub fn rate_limit_warning(&self) -> Option<String> {
        let heartbeat = self
            .connection_offer
            .as_ref()
            .and_then(|offer| offer.heartbeat_interval_secs)
            .filter(|secs| *secs > 0)
            .unwrap_or(BASELINE_HEARTBEAT_SECS);
        let carried = u64::from(self.agent_rate_limit.messages_per_sec).saturating_mul(heartbeat);
        (carried < AGENTS_PER_HOST).then(|| {
            format!(
                "[agent_rate_limit] messages_per_sec ({}) times [connection_offer] \
                 heartbeat_interval_secs ({heartbeat}) carries {carried} Agents per host, below \
                 the {AGENTS_PER_HOST} a host may speak for — a host with more Agents is \
                 throttled at every heartbeat",
                self.agent_rate_limit.messages_per_sec
            )
        })
    }

    /// The admission rules: the Operator plane off the loopback requires
    /// authentication. The Agent plane asks nothing of an Agent, and no TLS is asked of the
    /// Server: the reverse proxy in front of it terminates it and admits the Agents.
    fn check_secure(&self) -> Result<(), String> {
        let throttle = &self.admission_throttle;
        if throttle.max_failures == 0 || throttle.window_secs == 0 || throttle.backoff_secs == 0 {
            return Err(
                "[admission_throttle] max_failures, window_secs and backoff_secs must be greater \
                 than zero"
                    .to_string(),
            );
        }
        if !opamp::endpoint::is_loopback_literal(&self.rest.listen.ip().to_string())
            && self.rest.auth.is_none()
        {
            return Err(format!(
                "[rest] listen {} is not the loopback, so [rest.auth] is required — the Operator \
                 plane is the fleet's whole control surface",
                self.rest.listen
            ));
        }
        Ok(())
    }
}

/// The prefix of a variable that sets one key of the Server's configuration.
pub const VARIABLE_PREFIX: &str = "CLASSIS_SERVER__";

/// The variable that names the configuration file when `--config` does not.
/// One underscore: it is no key.
pub const CONFIG_FILE_VARIABLE: &str = "CLASSIS_SERVER_CONFIG";

/// The tables whose keys are data an operator chooses, each with the key that names a file
/// holding it. The environment reaches them only through that key.
const TABLES_FROM_FILES: [(&[&str], &str); 2] = [
    (&["rest", "auth", "basic_users"], "basic_users_file"),
    (&["telemetry_offer", "headers"], "headers_file"),
];

/// A configuration and where it came from.
#[derive(Debug)]
pub struct Layered {
    pub config: ServerConfig,
    /// The file, the environment, both, or the defaults — what an error found later names.
    pub origin: String,
    /// Every key the environment set, as its TOML path, with the variable that set it.
    pub from_environment: Vec<(String, String)>,
}

impl Layered {
    /// The startup log line naming every key the environment set, and never a value; `None` when it
    /// set none.
    #[must_use]
    pub fn environment_notice(&self) -> Option<String> {
        (!self.from_environment.is_empty()).then(|| {
            let keys: Vec<String> = self
                .from_environment
                .iter()
                .map(|(key, variable)| format!("{key} ({variable})"))
                .collect();
            format!("set from the environment: {}", keys.join(", "))
        })
    }
}

/// Which file the Server reads: the one `--config` names, else the one
/// [`CONFIG_FILE_VARIABLE`] names, and either has to exist; without both, `default` when it
/// exists, and no file when it does not.
///
/// # Errors
/// Returns an error naming the path when a named file does not exist.
pub fn config_file(
    named: Option<PathBuf>,
    variable: Option<OsString>,
    default: &Path,
) -> Result<Option<PathBuf>, String> {
    match named.or_else(|| variable.map(PathBuf::from)) {
        Some(path) if path.exists() => Ok(Some(path)),
        Some(path) => Err(format!(
            "the configuration file {} does not exist",
            path.display()
        )),
        None => Ok(default.exists().then(|| default.to_path_buf())),
    }
}

/// The process's `CLASSIS_SERVER__…` variables, the one place the Server reads its environment for
/// its configuration.
///
/// # Errors
/// Returns an error naming a variable whose value is not UTF-8.
pub fn server_variables() -> Result<Vec<(String, String)>, String> {
    std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            name.starts_with(VARIABLE_PREFIX).then_some((name, value))
        })
        .map(|(name, value)| match value.into_string() {
            Ok(value) => Ok((name, value)),
            Err(_) => Err(format!("{name} is not valid UTF-8")),
        })
        .collect()
}

/// One `CLASSIS_SERVER__…` variable, read.
#[derive(Debug)]
struct Variable {
    name: String,
    /// The key it sets, one TOML key per segment.
    path: Vec<String>,
    value: toml::Value,
}

/// The `CLASSIS_SERVER__…` variables among `variables`, in the order of their names, each naming
/// its key upper-cased and carrying a TOML value, and each key set by one of them at most.
fn environment(variables: Vec<(String, String)>) -> Result<Vec<Variable>, String> {
    let mut read = Vec::new();
    for (name, value) in variables {
        let Some(key) = name.strip_prefix(VARIABLE_PREFIX) else {
            continue;
        };
        // The name is the key upper-cased, so a lower-case letter is a second spelling
        // of some key, which would let two variables set it and the later one win unseen.
        if key.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(format!(
                "{name} names no key of the Server's configuration: a variable name is the key \
                 upper-cased"
            ));
        }
        let path: Vec<String> = key.split("__").map(str::to_lowercase).collect();
        if path.iter().any(String::is_empty) {
            return Err(format!(
                "{name} names no key of the Server's configuration: a segment between `__` is \
                 empty"
            ));
        }
        // A bare word is a string, so a path needs no quotes.
        let value = value
            .parse::<toml::Value>()
            .unwrap_or(toml::Value::String(value));
        let variable = Variable { name, path, value };
        for (table, file_key) in TABLES_FROM_FILES {
            if variable.reaches(table) {
                return Err(format!(
                    "{} is refused — the environment never carries [{}]; name a file holding \
                     it with {file_key}",
                    variable.name,
                    table.join(".")
                ));
            }
        }
        read.push(variable);
    }
    read.sort_by(|a, b| a.name.cmp(&b.name));
    // A key and a table above it set by two variables would leave one of them unread; the
    // inline-table case (`CLASSIS_SERVER__REST` beside `CLASSIS_SERVER__REST__LISTEN`) is the same.
    for (i, outer) in read.iter().enumerate() {
        if !outer.value.is_table() {
            continue;
        }
        if let Some(inner) = read[i + 1..]
            .iter()
            .find(|inner| inner.path.starts_with(&outer.path))
        {
            return Err(format!(
                "{} and {} both set [{}] — set it once",
                outer.name,
                inner.name,
                outer.path.join(".")
            ));
        }
    }
    Ok(read)
}

impl Variable {
    /// Whether this variable sets `target` or anything inside it, directly or in a table it sets
    /// whole.
    fn reaches(&self, target: &[&str]) -> bool {
        let (shared, rest) = target.split_at(self.path.len().min(target.len()));
        if !self.path.iter().zip(shared).all(|(a, b)| a == b) {
            return false;
        }
        let mut value = &self.value;
        for segment in rest {
            match value.get(*segment) {
                Some(inner) => value = inner,
                None => return false,
            }
        }
        true
    }

    /// Sets the key in `document`, creating the tables on its way and replacing what was there.
    fn set_in(&self, document: &mut toml::Table) -> Result<(), String> {
        let (last, tables) = self.path.split_last().expect("a path has a segment");
        let mut table = document;
        for (depth, segment) in tables.iter().enumerate() {
            let entry = table
                .entry(segment.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            table = entry.as_table_mut().ok_or_else(|| {
                format!(
                    "{} names no key of the Server's configuration: {} is not a table",
                    self.name,
                    self.path[..=depth].join(".")
                )
            })?;
        }
        table.insert(last.clone(), self.value.clone());
        Ok(())
    }
}

/// The value at `path` in `document`, if there is one.
fn lookup<'a>(document: &'a toml::Table, path: &[&str]) -> Option<&'a toml::Value> {
    let (first, rest) = path.split_first()?;
    let mut value = document.get(*first)?;
    for segment in rest {
        value = value.get(*segment)?;
    }
    Some(value)
}

/// The variable a deserialization error is about, if one is: the one that set the key the error
/// points at, a table holding it, or a key inside an unknown one. `toml` names the table an error
/// is in on its `in `…`` line, and `serde` names an unknown field in the message.
fn blamed<'a>(variables: &'a [Variable], error: &toml::de::Error) -> Option<&'a Variable> {
    let text = error.to_string();
    let mut key: Vec<String> = text
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("in `")?.strip_suffix('`'))
        .map(|path| path.split('.').map(str::to_string).collect())
        .unwrap_or_default();
    if let Some(field) = error
        .message()
        .strip_prefix("unknown field `")
        .and_then(|rest| rest.split('`').next())
    {
        key.push(field.to_string());
    }
    if key.is_empty() {
        return None;
    }
    variables
        .iter()
        .find(|variable| variable.path.starts_with(&key) || key.starts_with(&variable.path))
}

/// A table of names to strings read from its own TOML file. A parse error
/// says what is wrong but quotes no line: the file holds credentials.
fn read_table_file(key: &str, path: &Path) -> Result<BTreeMap<String, String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{key} {}: cannot read it: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e: toml::de::Error| {
        format!("{key} {}: cannot parse it: {}", path.display(), e.message())
    })
}

/// The `[connection_offer]` section as the offer the fleet makes. It carries no
/// `headers`: nothing on the Agent plane reads one.
impl ConnectionOffer {
    /// Compiles the section into the offer.
    #[must_use]
    pub fn from_config(config: &ConnectionOfferConfig) -> Self {
        ConnectionOffer::new(OpAmpConnectionSettings {
            destination_endpoint: config.endpoint.clone().unwrap_or_default(),
            heartbeat_interval_seconds: config.heartbeat_interval_secs.unwrap_or(0),
            ..Default::default()
        })
    }
}

/// The `[telemetry_offer]` section as the destinations the fleet offers.
impl TelemetryOffer {
    pub fn from_config(config: &TelemetryOfferConfig) -> Self {
        let headers = (!config.headers.is_empty()).then(|| Headers {
            headers: config
                .headers
                .iter()
                .map(|(key, value)| Header {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
        });
        let destination = |endpoint: &Option<String>| {
            endpoint
                .as_ref()
                .map(|endpoint| TelemetryConnectionSettings {
                    destination_endpoint: endpoint.clone(),
                    // A withdrawal names nothing else: an empty endpoint stops that
                    // signal, and the backend's credential travelling with it would be a token
                    // handed out for a connection nobody is going to open.
                    headers: headers.clone().filter(|_| !endpoint.is_empty()),
                    ..Default::default()
                })
        };
        TelemetryOffer {
            own_metrics: destination(&config.metrics_endpoint),
            own_traces: destination(&config.traces_endpoint),
            own_logs: destination(&config.logs_endpoint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a configuration needs beyond its own keys to load: nothing. The Server asks the Agent
    /// plane for no credential and no TLS; the name stays so the tests that append it
    /// read as they did.
    const TLS: &str = "";

    #[test]
    fn parses_a_full_config() {
        let cfg: ServerConfig = toml::from_str(
            r#"
            listen = "127.0.0.1:9999"
            data_dir = "state"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.listen.port(), 9999);
    }

    #[test]
    fn defaults_apply_to_an_empty_file() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.listen.port(), 4320);
    }

    /// The Operator plane is a second listener, and by default it is on loopback — the
    /// only protection it has while nothing authenticates it.
    #[test]
    fn the_operator_plane_defaults_to_loopback_and_is_configurable() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.rest.listen.port(), 4321);
        assert!(
            cfg.rest.listen.ip().is_loopback(),
            "the REST API is not published to the network by default"
        );
        let opened: ServerConfig =
            toml::from_str("[rest]\nlisten = \"0.0.0.0:8080\"").expect("parse");
        assert_eq!(opened.rest.listen.to_string(), "0.0.0.0:8080");
    }

    /// Two planes, two sockets: an address that cannot be bound twice is a configuration mistake,
    /// and it is named as one rather than surfacing as "address already in use".
    #[test]
    fn two_planes_on_one_address_are_refused() {
        assert!(listeners_collide(
            "0.0.0.0:4320".parse().unwrap(),
            "0.0.0.0:4320".parse().unwrap()
        ));
        assert!(
            listeners_collide(
                "0.0.0.0:4320".parse().unwrap(),
                "127.0.0.1:4320".parse().unwrap()
            ),
            "a listener on every interface covers the loopback one"
        );
        assert!(!listeners_collide(
            "0.0.0.0:4320".parse().unwrap(),
            "127.0.0.1:4321".parse().unwrap()
        ));
        assert!(!listeners_collide(
            "127.0.0.1:4320".parse().unwrap(),
            "192.168.0.1:4320".parse().unwrap()
        ));
    }

    /// The Baseline requires a message size limit, recommends 64 MiB, and asks that it be
    /// configurable; zero is not "unlimited" but a limit that could carry nothing, so it fails.
    #[test]
    fn the_message_size_limit_defaults_to_the_recommended_value_and_is_configurable() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.max_message_size_bytes, 64 * 1024 * 1024);
        let tightened: ServerConfig =
            toml::from_str("max_message_size_bytes = 65536").expect("parse");
        assert_eq!(tightened.max_message_size_bytes, 65536);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "max_message_size_bytes = 0\n").expect("write");
        let err = ServerConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("max_message_size_bytes"), "{err}");
    }

    /// The secret of a `password_file` or `secret_access_key_file` is held in a buffer wiped when
    /// it is dropped, its surrounding whitespace trimmed inside it: were `read_secret_file` to
    /// return a plain `String` again, this would not compile. A file that is not UTF-8 text is
    /// refused naming the key, without its bytes.
    #[test]
    fn a_secret_file_is_read_into_a_zeroizing_buffer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        let restrict = |path: &Path| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
            #[cfg(not(unix))]
            let _ = path;
        };
        std::fs::write(&path, " s3cret\n").expect("write");
        restrict(&path);
        let held: zeroize::Zeroizing<String> =
            read_secret_file("[blobs.s3] secret_access_key_file", &path).expect("read");
        assert_eq!(held.as_str(), "s3cret");

        std::fs::write(&path, [0xff, 0xfe, b'x']).expect("write");
        restrict(&path);
        let err =
            read_secret_file("[database.postgres] password_file", &path).expect_err("not UTF-8");
        assert!(err.contains("[database.postgres] password_file"), "{err}");
        assert!(err.contains("not UTF-8 text"), "{err}");
    }

    /// Every package is offered as a path, so a leftover `advertised_url` is named and refused
    /// rather than ignored: it would tell the operator a mirror is in use that no Client reaches.
    #[test]
    fn a_leftover_advertised_url_fails_startup_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "advertised_url = \"https://fleet.example:4320\"\n").expect("write");
        let err = ServerConfig::load(&path).expect_err("refused");
        assert!(err.contains("advertised_url is removed"), "{err}");
    }

    /// All state lives under one `data_dir`, `fleet-data` by default, and a leftover `config_dir`
    /// or `packages_dir` fails startup naming the key and `server migrate` — the directory it
    /// names holds trust data this Server would otherwise start without.
    #[test]
    fn a_leftover_config_dir_or_packages_dir_fails_startup_naming_server_migrate() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.data_dir, PathBuf::from("fleet-data"));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for key in ["config_dir", "packages_dir"] {
            std::fs::write(&path, format!("{key} = \"old\"\n")).expect("write");
            let err = ServerConfig::load(&path).expect_err("refused");
            assert!(err.contains(&format!("{key} is removed")), "{err}");
            assert!(err.contains("server migrate"), "{err}");
        }
    }

    #[test]
    fn the_total_package_store_ceiling_defaults_is_configurable_and_rejects_zero() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.max_total_package_bytes, 16 * 1024 * 1024 * 1024);
        let tightened: ServerConfig =
            toml::from_str("max_total_package_bytes = 1048576").expect("parse");
        assert_eq!(tightened.max_total_package_bytes, 1_048_576);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "max_total_package_bytes = 0\n").expect("write");
        let err = ServerConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("max_total_package_bytes"), "{err}");
    }

    /// The token lifetime is the Server setting of `0`, the default, is a token
    /// that never expires, anything else is its life in seconds, and the environment sets it like
    /// any other key.
    #[test]
    fn the_token_lifetime_defaults_to_never_and_is_configurable() {
        use oauth_token::server::Lifetime;
        let default: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(default.token_lifetime_secs, 0);
        assert_eq!(default.token_lifetime(), Lifetime::Never);
        let finite: ServerConfig = toml::from_str("token_lifetime_secs = 3600").expect("parse");
        assert_eq!(
            finite.token_lifetime(),
            Lifetime::Seconds(std::num::NonZeroU64::new(3600).expect("non-zero"))
        );

        let from_environment = ServerConfig::load_layered(
            None,
            variables(&[("CLASSIS_SERVER__TOKEN_LIFETIME_SECS", "90")]),
        )
        .expect("loads")
        .config;
        assert_eq!(from_environment.token_lifetime_secs, 90);
        let err = toml::from_str::<ServerConfig>("token_lifetime_secs = \"soon\"")
            .expect_err("not a number");
        assert!(err.to_string().contains("token_lifetime_secs"), "{err}");
    }

    /// The operator's socket defaults to the path `classis-cli` looks at, and the file and the
    /// environment set it like any other key.
    #[test]
    fn the_admin_socket_defaults_to_the_clis_path_and_is_configurable() {
        let default: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(
            default.admin_socket,
            PathBuf::from(classis_admin::protocol::DEFAULT_SOCKET)
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "admin_socket = \"/var/run/classis.sock\"\n").expect("write");
        assert_eq!(
            ServerConfig::load(&path).expect("loads").admin_socket,
            PathBuf::from("/var/run/classis.sock")
        );

        let from_environment = ServerConfig::load_layered(
            None,
            variables(&[("CLASSIS_SERVER__ADMIN_SOCKET", "/srv/classis/admin.sock")]),
        )
        .expect("loads")
        .config;
        assert_eq!(
            from_environment.admin_socket,
            PathBuf::from("/srv/classis/admin.sock")
        );
    }

    /// What `public_url` takes: an `https://` URL with a proxy's path prefix kept whole, and an
    /// `http://` URL to a loopback IP literal alone. Absent it stays absent, which is what makes
    /// `enrol-command` refuse. What it refuses is what the command line `classis-cli` prints could
    /// not carry, or what the Client itself refuses on the URL an operator types there.
    /// Verifies: Q-1
    #[test]
    fn the_public_url_is_checked_at_load_and_set_like_any_other_key() {
        let load = |url: &str| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("server.toml");
            std::fs::write(&path, format!("public_url = \"{url}\"\n")).expect("write");
            ServerConfig::load(&path)
        };

        let defaults = ServerConfig::load_layered(None, Vec::new())
            .expect("the defaults")
            .config;
        assert!(defaults.public_url.is_none(), "no public URL yet");
        for url in [
            "https://fleet.example",
            "https://neteye.example/neteye/classis",
            "http://127.0.0.1:4320/classis",
            "http://[::1]:4320",
        ] {
            assert_eq!(
                load(url).expect(url).public_url.as_deref(),
                Some(url),
                "kept as written, prefix and all: {url}"
            );
        }

        for (why, url) in [
            ("plaintext off the loopback", "http://fleet.example"),
            ("a name, not a loopback literal", "http://localhost:4320"),
            ("no scheme", "fleet.example"),
            ("a WebSocket scheme", "wss://fleet.example"),
            ("a credential", "https://ops:s3cret@fleet.example"),
            ("a query", "https://fleet.example/?space=acme"),
            ("a fragment", "https://fleet.example#acme"),
            ("no host", "https://"),
            ("nothing", ""),
            ("a single quote", "https://fleet.example'/"),
        ] {
            let err = load(url).expect_err(why);
            assert!(err.contains("public_url"), "{why}: {err}");
        }

        // A control character comes from the environment, which carries the value raw: TOML would
        // have to escape one, and the check runs on the text either way.
        for (why, url) in [
            ("a control character", "https://fleet.example\u{7}x"),
            ("a tab", "https://fleet.example\t/x"),
            ("a newline", "https://fleet.example/x\nsudo sh"),
        ] {
            let err =
                ServerConfig::load_layered(None, variables(&[("CLASSIS_SERVER__PUBLIC_URL", url)]))
                    .expect_err(why);
            assert!(err.contains("public_url"), "{why}: {err}");
            assert!(
                !err.chars().any(|c| c.is_control()),
                "{why}: the refusal quotes it escaped, never raw: {err}"
            );
        }

        let from_environment = ServerConfig::load_layered(
            None,
            variables(&[(
                "CLASSIS_SERVER__PUBLIC_URL",
                "https://fleet.example/classis",
            )]),
        )
        .expect("loads")
        .config;
        assert_eq!(
            from_environment.public_url.as_deref(),
            Some("https://fleet.example/classis")
        );
        let err = ServerConfig::load_layered(
            None,
            variables(&[("CLASSIS_SERVER__PUBLIC_URL", "fleet.example")]),
        )
        .expect_err("the file's rules hold on what the environment set");
        assert!(err.contains("public_url"), "{err}");
    }

    #[test]
    fn the_agent_ceiling_defaults_is_configurable_and_rejects_zero() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.max_agents, crate::fleet::DEFAULT_MAX_AGENTS);
        let tightened: ServerConfig = toml::from_str("max_agents = 500").expect("parse");
        assert_eq!(tightened.max_agents, 500);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "max_agents = 0\n").expect("write");
        let err = ServerConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("max_agents"), "{err}");
    }

    /// The three shapes `[telemetry_offer]` admits: a destination, a withdrawal, and a mistake.
    /// The withdrawal is the one to watch — an empty endpoint is a thing to say, not a URL to
    /// check — and it must not be waved through for a value that is merely wrong.
    #[test]
    fn an_empty_endpoint_is_a_withdrawal_and_a_wrong_one_is_still_an_error() {
        let section = |body: &str| {
            toml::from_str::<TelemetryOfferConfig>(body)
                .expect("parse")
                .check()
        };

        assert!(section("metrics_endpoint = \"https://otlp.example/v1/metrics\"").is_ok());
        assert!(
            section("metrics_endpoint = \"\"").is_ok(),
            "an empty endpoint withdraws the signal"
        );

        let err = section("metrics_endpoint = \"collector:4318\"")
            .expect_err("a bare host is not an OTLP/HTTP URL");
        assert!(err.contains("metrics_endpoint"), "{err}");

        let err = section("").expect_err("an empty section offers nothing");
        assert!(err.contains("at least one"), "{err}");
    }

    /// A typo fails, and so does a section this Server no longer reads, such as the `[audit]` of
    /// an older one.
    #[test]
    fn rejects_unknown_keys() {
        assert!(toml::from_str::<ServerConfig>("listne = \"0.0.0.0:1\"").is_err());
        assert!(toml::from_str::<ServerConfig>("[audit]\nkeep_files = 16\n").is_err());
    }

    /// No credential in `server.toml` authenticates on its own: an operator's password in clear is
    /// refused at startup, the section and the user named and the value never echoed.
    #[test]
    fn a_plaintext_credential_is_refused_naming_its_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for listen in ["127.0.0.1:4321", "0.0.0.0:4321"] {
            std::fs::write(
                &path,
                format!(
                    "[rest]\nlisten = \"{listen}\"\n[rest.auth.basic_users]\nops = \"plain-password\"\n{TLS}"
                ),
            )
            .expect("write");
            let err = ServerConfig::load(&path).expect_err("a password in clear");
            assert!(
                err.contains("[rest.auth.basic_users] user \"ops\""),
                "names the entry: {err}"
            );
            assert!(
                err.contains("hash-credential --basic"),
                "says how to fix it: {err}"
            );
            assert!(!err.contains("plain-"), "never echoes the value: {err}");
        }
    }

    /// What `[packages] revoked_signers` admits: SHA-256 fingerprints as lowercase hex, once each,
    /// at most [`MAX_REVOKED_SIGNERS`] of them, and nothing by default.
    #[test]
    fn revoked_signers_are_lowercase_sha256_fingerprints_named_once() {
        let section = |body: &str| {
            toml::from_str::<PackagesConfig>(body)
                .expect("parse")
                .revoked_signers()
        };
        let one = "ab".repeat(32);
        let two = "cd".repeat(32);

        assert!(section("").expect("default").is_empty());
        let listed = section(&format!("revoked_signers = [\"{one}\", \"{two}\"]")).expect("two");
        assert_eq!(listed.len(), 2);

        for (why, item) in [
            ("uppercase", "AB".repeat(32)),
            ("too short", "ab".repeat(31)),
            ("too long", "ab".repeat(33)),
            ("not hex", "zz".repeat(32)),
            ("empty", String::new()),
        ] {
            let err = section(&format!("revoked_signers = [\"{item}\"]")).expect_err(why);
            assert!(err.contains("revoked_signers"), "{why}: {err}");
        }

        let err =
            section(&format!("revoked_signers = [\"{one}\", \"{one}\"]")).expect_err("a duplicate");
        assert!(err.contains("twice"), "{err}");

        let many: Vec<String> = (0..=MAX_REVOKED_SIGNERS)
            .map(|n| format!("{n:064x}"))
            .collect();
        let err = RevokedSigners::parse(&many).expect_err("over the limit");
        assert!(err.contains("at most"), "{err}");
        assert!(RevokedSigners::parse(&many[..MAX_REVOKED_SIGNERS]).is_ok());
    }

    /// A malformed list stops the Server at load, naming the setting, and the removed
    /// `verification_key` stays refused.
    #[test]
    fn a_malformed_revoked_signers_list_fails_the_configuration_check() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");

        std::fs::write(
            &path,
            "[packages]\nrevoked_signers = [\"not-a-fingerprint\"]\n",
        )
        .expect("write");
        let err = ServerConfig::load(&path).expect_err("a malformed item must fail startup");
        assert!(err.contains("revoked_signers"), "{err}");

        std::fs::write(&path, "[packages]\nverification_key = \"x\"\n").expect("write");
        assert!(
            ServerConfig::load(&path).is_err(),
            "the removed verification_key stays refused"
        );
    }

    /// A signature whose Package Signer is listed is refused after the chain verifies, and any
    /// other signer's is not.
    #[test]
    fn the_verifier_refuses_a_listed_package_signer_and_only_that_one() {
        use crate::packages::SignatureVerifier;
        use classis_core::package::testing::TestRoot;

        let root = TestRoot::new();
        let listed = root.signer();
        let other = root.signer();
        let statement = b"statement";
        let fingerprint = hex::encode(Sha256::digest(&listed.der));
        let revoked = RevokedSigners::parse(&[fingerprint]).expect("one fingerprint");
        let verifier = RootsVerifier::new(root.roots()).with_revoked(revoked);

        let err = verifier
            .verify(statement, &listed.sign(statement))
            .expect_err("the listed signer");
        assert!(err.contains("revoked"), "{err}");
        assert!(
            verifier.verify(statement, &other.sign(statement)).is_ok(),
            "a signer that is not listed"
        );
        assert!(
            RootsVerifier::new(root.roots())
                .verify(statement, &listed.sign(statement))
                .is_ok(),
            "with nobody revoked"
        );
    }

    /// The Agent plane has no credential of its own: a leftover `[auth]` is refused at startup,
    /// named, with the reason, whatever it holds.
    #[test]
    fn an_auth_section_is_refused_at_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for auth in [
            "[auth]\n",
            "[auth]\nbearer_tokens = [\"sha256:00\"]\n",
            "[auth.basic_users]\nfleet = \"plain-password\"\n",
        ] {
            std::fs::write(&path, format!("{auth}{TLS}")).expect("write");
            let err = ServerConfig::load(&path).expect_err(auth);
            assert!(err.contains("[auth]"), "names the section: {err}");
            assert!(
                err.contains("has no credential of its own"),
                "says why: {err}"
            );
            assert!(!err.contains("plain-"), "never echoes a value: {err}");
        }
        std::fs::write(&path, TLS).expect("write");
        ServerConfig::load(&path).expect("no [auth], no refusal");
    }

    #[test]
    fn a_weak_argon2id_hash_is_refused() {
        use argon2::password_hash::PasswordHasher as _;
        let cheap = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(4096, 1, 1, None).expect("params"),
        )
        .hash_password_with_salt(b"secret", b"0123456789abcdef")
        .expect("hash")
        .to_string();
        let auth: RestAuthConfig =
            toml::from_str(&format!("[basic_users]\nops = {cheap:?}\n")).expect("parse");
        let err = auth.check().expect_err("cheaper than the minimum");
        assert!(err.contains("cheaper"), "{err}");
    }

    /// The Operator plane's own credentials, precomputed into the header values that
    /// authenticate, with the challenge that makes a browser ask rather than give up.
    #[test]
    fn rest_auth_verifies_its_hashes_and_carries_the_basic_challenge() {
        let cfg: ServerConfig = toml::from_str(&format!(
            "[rest]\nlisten = \"127.0.0.1:4321\"\n[rest.auth.basic_users]\nfleet = {:?}\n",
            crate::credentials::hash_basic("secret").expect("hash"),
        ))
        .expect("parse");
        let auth = cfg.rest.auth.expect("rest auth");
        // base64("fleet:secret")
        assert!(auth
            .credentials()
            .expect("credentials")
            .verify("Basic ZmxlZXQ6c2VjcmV0"));
        assert_eq!(auth.challenge(), r#"Basic realm="opamp""#);
        assert!(auth.check().is_ok());

        // Absent means open — the zero-configuration default this plane still has.
        let open: ServerConfig = toml::from_str("").expect("parse");
        assert!(open.rest.auth.is_none());
    }

    /// A section that authenticates nobody locks the operator out of their own Server, and a
    /// half-written credential is a mistake rather than an intent — both fail at startup.
    #[test]
    fn an_unusable_rest_auth_section_is_rejected() {
        let empty: RestAuthConfig = toml::from_str("").expect("parses; emptiness is semantic");
        assert!(empty.check().is_err());
        let blank: RestAuthConfig = toml::from_str("[basic_users]\nfleet = \"\"").expect("parse");
        assert!(blank.check().is_err());

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "[rest.auth]\n").expect("write");
        let err = ServerConfig::load(&path).expect_err("an empty section must fail startup");
        assert!(err.contains("[rest.auth.basic_users]"), "{err}");

        // Bearer is not a scheme this plane has, and a typo fails loudly.
        assert!(toml::from_str::<ServerConfig>("[rest.auth]\nbearer_tokens = [\"tok\"]").is_err());
    }

    #[test]
    fn a_connection_offer_needs_at_least_one_field() {
        let empty: ConnectionOfferConfig =
            toml::from_str("").expect("parses; emptiness is semantic");
        assert!(empty.check().is_err());
    }

    /// A credential key is refused by name, whatever else the section offers.
    #[test]
    fn a_connection_offer_refuses_a_credential_key_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for (key, value) in [
            ("bearer_token_file", "\"/etc/fleet/token\""),
            ("username", "\"fleet\""),
            ("password_file", "\"/etc/fleet/password\""),
            ("bearer_token", "\"secret-token\""),
            ("password", "\"secret-password\""),
        ] {
            let offer: ConnectionOfferConfig =
                toml::from_str(&format!("heartbeat_interval_secs = 15\n{key} = {value}\n"))
                    .expect("parses; the refusal is semantic");
            let err = offer.check().expect_err(key);
            assert!(err.contains(&format!("[connection_offer] {key} ")), "{err}");
            assert!(!err.contains("secret-"), "never echoes the value: {err}");

            std::fs::write(
                &path,
                format!("[connection_offer]\nheartbeat_interval_secs = 15\n{key} = {value}\n{TLS}"),
            )
            .expect("write");
            let err = ServerConfig::load(&path).expect_err("refused at startup");
            assert!(err.contains(&format!("[connection_offer] {key} ")), "{err}");
        }
    }

    #[test]
    fn a_connection_offer_rejects_a_bad_endpoint_scheme() {
        let bad: ConnectionOfferConfig =
            toml::from_str("endpoint = \"ftp://x/v1/opamp\"").expect("parse");
        assert!(bad.check().is_err());
        let good: ConnectionOfferConfig =
            toml::from_str("endpoint = \"wss://x/v1/opamp\"").expect("parse");
        assert!(good.check().is_ok());
    }

    #[test]
    fn a_connection_offer_refuses_a_plaintext_endpoint_off_loopback_naming_the_setting() {
        for endpoint in [
            "ws://fleet.example/v1/opamp",
            "http://10.0.0.1:4320/v1/opamp",
        ] {
            let offer: ConnectionOfferConfig =
                toml::from_str(&format!("endpoint = \"{endpoint}\"")).expect("parse");
            let err = offer.check().expect_err(endpoint);
            assert!(err.contains("[connection_offer] endpoint"), "{err}");
        }
    }

    /// An offer never moves a fleet to plaintext, on a loopback IP literal neither.
    #[test]
    fn a_connection_offer_refuses_a_plaintext_endpoint_on_a_loopback_ip_literal() {
        for endpoint in ["ws://127.0.0.1:4320/v1/opamp", "http://[::1]:4320/v1/opamp"] {
            let offer: ConnectionOfferConfig =
                toml::from_str(&format!("endpoint = \"{endpoint}\"")).expect("parse");
            let err = offer.check().expect_err(endpoint);
            assert!(err.contains("[connection_offer] endpoint"), "{err}");
            assert!(err.contains("never moves a fleet to plaintext"), "{err}");
        }
    }

    #[test]
    fn a_connection_offer_refuses_a_plaintext_endpoint_on_localhost() {
        let offer: ConnectionOfferConfig =
            toml::from_str("endpoint = \"ws://localhost:4320/v1/opamp\"").expect("parse");
        assert!(offer.check().is_err());
    }

    /// The Server speaks plain HTTP behind a proxy that terminates TLS: a leftover `[tls]`,
    /// `[rest.tls]`, `[client_ca]` or `[enrolment]` section is refused by name rather than
    /// ignored, so nobody keeps believing the Server terminates TLS.
    #[test]
    fn the_sections_of_mutual_tls_are_refused_naming_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for (section, body) in [
            (
                "[tls]",
                "[tls]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\n",
            ),
            (
                "[rest.tls]",
                "[rest.tls]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\n",
            ),
            (
                "[client_ca]",
                "[client_ca]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\n",
            ),
            (
                "[enrolment]",
                "[enrolment]\nbootstrap_ca_file = \"b.pem\"\n",
            ),
        ] {
            std::fs::write(&path, format!("{TLS}{body}")).expect("write");
            let err = ServerConfig::load(&path).expect_err(section);
            assert!(err.contains(&format!("{section} is removed")), "{err}");
            assert!(err.contains("reverse proxy"), "{err}");
        }
        std::fs::write(&path, TLS).expect("write");
        ServerConfig::load(&path).expect("the token key is all admission needs");
    }

    #[test]
    fn max_connections_defaults_per_plane_and_zero_is_refused() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.max_connections, 10_000);
        assert_eq!(cfg.rest.max_connections, 256);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for body in ["max_connections = 0\n", "[rest]\nmax_connections = 0\n"] {
            std::fs::write(&path, body).expect("write");
            let err = ServerConfig::load(&path).expect_err("zero must fail startup");
            assert!(err.contains("max_connections"), "{err}");
        }
    }

    #[test]
    fn the_log_format_is_text_unless_json_is_named() {
        let parse = |text: &str| toml::from_str::<ServerConfig>(text).expect("parse");
        assert_eq!(parse("").log.format, LogFormat::Text);
        assert_eq!(
            parse("[log]\nformat = \"json\"").log.format,
            LogFormat::Json
        );
        let err = toml::from_str::<ServerConfig>("[log]\nformat = \"xml\"").expect_err("xml");
        assert!(err.to_string().contains("xml"), "{err}");
    }

    #[test]
    fn the_agent_rate_limit_defaults_and_refuses_zero() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(
            cfg.agent_rate_limit.limits(),
            crate::agent_rate::Limits {
                messages_per_sec: 10,
                burst: 300,
            }
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for key in ["messages_per_sec", "burst"] {
            std::fs::write(&path, format!("{TLS}[agent_rate_limit]\n{key} = 0\n")).expect("write");
            let err = ServerConfig::load(&path).expect_err("zero must fail startup");
            assert!(err.contains(&format!("[agent_rate_limit] {key}")), "{err}");
        }
        std::fs::write(
            &path,
            format!("{TLS}[agent_rate_limit]\nmessages_per_second = 5\n"),
        )
        .expect("write");
        let err = ServerConfig::load(&path).expect_err("an unknown key");
        assert!(err.contains("messages_per_second"), "{err}");
        std::fs::write(&path, format!("{TLS}[agent_rate_limit]\nburst = 50\n")).expect("write");
        assert_eq!(
            ServerConfig::load(&path)
                .expect("loads")
                .agent_rate_limit
                .burst,
            50
        );
    }

    #[test]
    fn a_limit_below_the_heartbeat_for_256_agents_warns_naming_both_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                "{TLS}[agent_rate_limit]\nmessages_per_sec = 5\n\
                 [connection_offer]\nheartbeat_interval_secs = 30\n"
            ),
        )
        .expect("write");
        let config = ServerConfig::load(&path).expect("a low limit still starts");
        let warning = config.rate_limit_warning().expect("a warning");
        assert!(
            warning.contains("[agent_rate_limit] messages_per_sec")
                && warning.contains("[connection_offer] heartbeat_interval_secs"),
            "{warning}"
        );

        std::fs::write(&path, TLS).expect("write");
        let config = ServerConfig::load(&path).expect("defaults");
        assert_eq!(config.rate_limit_warning(), None, "10 times 30 carries 300");
    }

    #[test]
    fn the_agent_plane_defaults_to_the_loopback() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.listen, "127.0.0.1:4320".parse().expect("address"));
    }

    /// The Server does not authenticate Agents: it starts without any section for them, and a
    /// leftover `[agents.auth]` is refused naming the section, not ignored.
    #[test]
    fn agents_auth_is_removed_and_a_leftover_one_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No file at all is the defaults, and they start.
        ServerConfig::load_layered(None, Vec::new()).expect("the defaults start");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "listen = \"127.0.0.1:4320\"\n").expect("write");
        ServerConfig::load(&path).expect("no [agents] section is the normal case");
        for leftover in [
            "[agents.auth]\njwt_public_key_file = \"/etc/key.pem\"\n",
            "[agents.auth]\nissuer = \"proxy\"\n",
            "[agents]\n",
        ] {
            std::fs::write(&path, leftover).expect("write");
            let err = ServerConfig::load(&path).expect_err(leftover);
            assert!(err.contains("[agents.auth] is removed"), "{err}");
            assert!(err.contains("reachable only through"), "{err}");
            assert!(!err.contains("/etc/key.pem"), "never echoes a value: {err}");
        }
    }

    #[test]
    fn the_operator_plane_requires_authentication_off_the_loopback() {
        let tls = TLS;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, format!("[rest]\nlisten = \"0.0.0.0:4321\"\n{tls}")).expect("write");
        let err = ServerConfig::load(&path).expect_err("open plane without auth");
        assert!(err.contains("[rest.auth] is required"), "{err}");

        let guarded = format!(
            "[rest]\nlisten = \"0.0.0.0:4321\"\n[rest.auth.basic_users]\nops = {:?}\n",
            crate::credentials::hash_basic("s3cret").expect("hash")
        );
        std::fs::write(&path, format!("{guarded}{tls}")).expect("write");
        ServerConfig::load(&path).expect("guarded plane loads");

        std::fs::write(&path, tls).expect("write");
        ServerConfig::load(&path).expect("a loopback plane needs no authentication");
    }

    /// The variables of a test, as the process environment would hand them over.
    fn variables(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    /// A variable that sets a key to its default, so a configuration that comes from the
    /// environment alone has something to carry.
    const TLS_VARIABLES: [(&str, &str); 1] = [("CLASSIS_SERVER__LISTEN", "127.0.0.1:4320")];

    /// A mistake in the file is named with its line, also when the environment sets other keys
    /// beside it (the file's checks hold as they did).
    #[test]
    fn a_mistake_in_the_file_names_its_line_whatever_the_environment_sets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(
            &path,
            format!("data_dir = \"from-file\"\n\nstale_after_secs = \"soon\"\n{TLS}"),
        )
        .expect("write");
        for set in [
            &[][..],
            &[("CLASSIS_SERVER__DATA_DIR", "/var/lib/fleet")][..],
        ] {
            let err =
                ServerConfig::load_layered(Some(&path), variables(set)).expect_err("not a number");
            assert!(err.contains("line 3"), "{set:?}: {err}");
            assert!(err.contains("stale_after_secs"), "{set:?}: {err}");
        }
    }

    /// A variable sets the key its name spells, over the file's value; a key no variable names
    /// keeps the file's; and a variable that does not start with the prefix configures nothing.
    /// A key of `[database.postgres]` is among them.
    #[test]
    fn the_environment_overrides_the_files_keys_and_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                "data_dir = \"from-file\"\nstale_after_secs = 120\n\
                 [connection_offer]\nheartbeat_interval_secs = 30\n\
                 [rest]\nmax_connections = 100\nlisten = \"127.0.0.1:4400\"\n\
                 [database]\nstore = \"postgres\"\n\
                 [database.postgres]\nhost = \"db.example\"\nport = 5432\ndbname = \"fleet\"\n\
                 user = \"fleet\"\npassword_file = \"/run/secrets/pg\"\n{TLS}"
            ),
        )
        .expect("write");
        let layered = ServerConfig::load_layered(
            Some(&path),
            variables(&[
                ("CLASSIS_SERVER__DATABASE__POSTGRES__PORT", "5433"),
                ("CLASSIS_SERVER__DATA_DIR", "/var/lib/fleet"),
                ("CLASSIS_SERVER__REST__MAX_CONNECTIONS", "200"),
                (
                    "CLASSIS_SERVER__CONNECTION_OFFER__HEARTBEAT_INTERVAL_SECS",
                    "45",
                ),
                ("CLASSIS_SERVER_CONFIG", "ignored.toml"),
                ("CLASSIS_OTHER__DATA_DIR", "ignored"),
            ]),
        )
        .expect("loads");
        let config = layered.config;
        assert_eq!(config.data_dir, PathBuf::from("/var/lib/fleet"));
        assert_eq!(config.rest.max_connections, 200, "the variable wins");
        assert_eq!(config.rest.listen.port(), 4400, "a key no variable names");
        assert_eq!(
            config
                .connection_offer
                .expect("[connection_offer]")
                .heartbeat_interval_secs,
            Some(45)
        );
        let database = config.database.postgres().expect("[database.postgres]");
        assert_eq!(database.port, 5433);
        assert_eq!(database.host, "db.example", "a key no variable names");
        assert_eq!(config.stale_after_secs, 120, "a key no variable names");
        assert!(layered.origin.contains("server.toml"), "{}", layered.origin);
    }

    /// No file named and none in the working directory: the defaults, with the environment over
    /// them, which can be the whole configuration.
    #[test]
    fn without_a_file_the_configuration_is_built_from_defaults_and_the_environment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let default = dir.path().join("server.toml");
        let file = config_file(None, None, &default).expect("no file is no error");
        assert_eq!(file, None);
        let config = ServerConfig::load_layered(file.as_deref(), variables(&TLS_VARIABLES))
            .expect("the environment alone is a configuration")
            .config;
        assert_eq!(config.listen.port(), 4320, "a default");

        std::fs::write(&default, TLS).expect("write");
        assert_eq!(
            config_file(None, None, &default).expect("found"),
            Some(default.clone()),
            "server.toml in the working directory is read when it exists"
        );
    }

    /// A file named by `--config` or by `CLASSIS_SERVER_CONFIG` has to exist; `--config` wins over
    /// the variable.
    #[test]
    fn a_named_configuration_file_that_does_not_exist_fails_startup_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let default = dir.path().join("server.toml");
        std::fs::write(&default, TLS).expect("write");
        let missing = dir.path().join("missing.toml");
        let err = config_file(Some(missing.clone()), None, &default).expect_err("--config");
        assert!(err.contains(&missing.display().to_string()), "{err}");
        let err = config_file(None, Some(missing.clone().into_os_string()), &default)
            .expect_err("CLASSIS_SERVER_CONFIG");
        assert!(err.contains(&missing.display().to_string()), "{err}");
        assert_eq!(
            config_file(
                Some(default.clone()),
                Some(missing.into_os_string()),
                &default
            )
            .expect("--config wins"),
            Some(default)
        );
    }

    /// A variable naming no key fails startup naming the variable, as an unknown key in the file
    /// does; so does one with an empty segment, and one that reaches into a key that is no table.
    #[test]
    fn an_unknown_variable_fails_startup_naming_it() {
        for (name, value) in [
            ("CLASSIS_SERVER__REST__TLSS__CERT_FILE", "ui.pem"),
            ("CLASSIS_SERVER__LISTNE", "127.0.0.1:4320"),
            ("CLASSIS_SERVER__REST____TLS", "x"),
            ("CLASSIS_SERVER__", "x"),
            ("CLASSIS_SERVER__STALE_AFTER_SECS__X", "1"),
            ("CLASSIS_SERVER__REST", "{ lisen = \"127.0.0.1:4321\" }"),
        ] {
            let mut pairs = TLS_VARIABLES.to_vec();
            if name == "CLASSIS_SERVER__STALE_AFTER_SECS__X" {
                pairs.push(("CLASSIS_SERVER__STALE_AFTER_SECS", "90"));
            }
            pairs.push((name, value));
            let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err(name);
            assert!(err.starts_with(&format!("{name} names no key")), "{err}");
        }
    }

    /// A key has one spelling and one variable: a lower-case name, or two variables of which one
    /// sets a table the other reaches into, fails startup naming them.
    #[test]
    fn a_key_is_set_by_one_upper_case_variable() {
        let mut pairs = TLS_VARIABLES.to_vec();
        pairs.push(("CLASSIS_SERVER__listen", "127.0.0.1:4320"));
        let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err("lower case");
        assert!(
            err.starts_with("CLASSIS_SERVER__listen names no key"),
            "{err}"
        );

        let mut pairs = TLS_VARIABLES.to_vec();
        pairs.push(("CLASSIS_SERVER__REST", "{ listen = \"127.0.0.1:4321\" }"));
        pairs.push(("CLASSIS_SERVER__REST__LISTEN", "127.0.0.1:4322"));
        let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err("twice");
        assert!(
            err.contains("CLASSIS_SERVER__REST and CLASSIS_SERVER__REST__LISTEN both set"),
            "{err}"
        );
    }

    /// A value whose type does not fit its key fails startup naming the variable and the type the
    /// key expects.
    #[test]
    fn a_value_of_the_wrong_type_fails_startup_naming_the_variable_and_the_type() {
        for (name, value, expected) in [
            ("CLASSIS_SERVER__STALE_AFTER_SECS", "soon", "u64"),
            ("CLASSIS_SERVER__DATA_DIR", "1234", "path"),
            (
                "CLASSIS_SERVER__CONNECTION_OFFER__HEARTBEAT_INTERVAL_SECS",
                "-1",
                "u64",
            ),
        ] {
            let mut pairs = TLS_VARIABLES.to_vec();
            pairs.push((name, value));
            let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err(name);
            assert!(err.starts_with(&format!("{name}: ")), "{err}");
            assert!(err.contains(&format!("expected {expected}")), "{err}");
        }
    }

    /// A value is a TOML value, and what does not parse as one is the string it is: a path needs
    /// no quotes, a quoted number is a string, a bare one an integer.
    #[test]
    fn a_bare_word_is_a_string_and_a_quoted_number_too() {
        let read = environment(variables(&[
            ("CLASSIS_SERVER__A", "/run/secrets/pg"),
            ("CLASSIS_SERVER__B", "\"1234\""),
            ("CLASSIS_SERVER__C", "1234"),
            ("CLASSIS_SERVER__D", "true"),
            ("CLASSIS_SERVER__E", "[\"a\", \"b\"]"),
            ("CLASSIS_SERVER__F", "{ g = 1 }"),
        ]))
        .expect("read");
        let values: Vec<_> = read.iter().map(|variable| variable.value.clone()).collect();
        assert_eq!(
            values,
            vec![
                toml::Value::String("/run/secrets/pg".into()),
                toml::Value::String("1234".into()),
                toml::Value::Integer(1234),
                toml::Value::Boolean(true),
                toml::Value::Array(vec!["a".into(), "b".into()]),
                toml::Value::Table(toml::Table::from_iter([(
                    "g".to_string(),
                    toml::Value::Integer(1)
                )])),
            ]
        );

        let mut pairs = TLS_VARIABLES.to_vec();
        pairs.push(("CLASSIS_SERVER__DATA_DIR", "\"1234\""));
        let config = ServerConfig::load_layered(None, variables(&pairs))
            .expect("a quoted number is a string")
            .config;
        assert_eq!(config.data_dir, PathBuf::from("1234"));
    }

    /// Credentials never come from the environment: `basic_users` set from it, by key or inside a
    /// table set whole, fails startup naming `basic_users_file`, and the same holds for
    /// `[telemetry_offer] headers` and `headers_file`.
    #[test]
    fn the_environment_names_credentials_by_file_alone() {
        for (name, value, file_key) in [
            (
                "CLASSIS_SERVER__REST__AUTH__BASIC_USERS",
                "{ ops = \"x\" }",
                "basic_users_file",
            ),
            (
                "CLASSIS_SERVER__REST__AUTH__BASIC_USERS__OPS",
                "x",
                "basic_users_file",
            ),
            (
                "CLASSIS_SERVER__REST__AUTH",
                "{ basic_users = { ops = \"x\" } }",
                "basic_users_file",
            ),
            (
                "CLASSIS_SERVER__TELEMETRY_OFFER__HEADERS",
                "{ a = \"x\" }",
                "headers_file",
            ),
            (
                "CLASSIS_SERVER__TELEMETRY_OFFER__HEADERS__AUTHORIZATION",
                "x",
                "headers_file",
            ),
        ] {
            let mut pairs = TLS_VARIABLES.to_vec();
            pairs.push((name, value));
            let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err(name);
            assert!(err.starts_with(name), "{err}");
            assert!(err.contains(file_key), "{err}");
        }
    }

    /// A table named by a file is never beside the same table inline: startup fails naming both.
    #[test]
    fn a_table_file_beside_its_table_fails_startup_naming_both() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for (body, both) in [
            (
                "[rest.auth]\nbasic_users_file = \"users.toml\"\n[rest.auth.basic_users]\nops = \"x\"\n",
                ["basic_users_file", "[rest.auth.basic_users]"],
            ),
            (
                "[telemetry_offer]\nmetrics_endpoint = \"https://c.example/v1/metrics\"\n\
                 headers_file = \"headers.toml\"\n[telemetry_offer.headers]\na = \"x\"\n",
                ["headers_file", "[telemetry_offer.headers]"],
            ),
        ] {
            std::fs::write(&path, format!("{TLS}{body}")).expect("write");
            let err = ServerConfig::load(&path).expect_err("both");
            for named in both {
                assert!(err.contains(named), "{err}");
            }
        }
        // The file key from the environment, the table in the file: the same document.
        std::fs::write(
            &path,
            format!("{TLS}[rest.auth.basic_users]\nops = \"x\"\n"),
        )
        .expect("write");
        let err = ServerConfig::load_layered(
            Some(&path),
            variables(&[("CLASSIS_SERVER__REST__AUTH__BASIC_USERS_FILE", "users.toml")]),
        )
        .expect_err("both");
        assert!(
            err.contains("basic_users_file") && err.contains("[rest.auth.basic_users]"),
            "{err}"
        );
    }

    /// `basic_users_file` holds the `basic_users` table, and the users in it are admitted;
    /// `headers_file` holds the `headers` table.
    #[test]
    fn a_basic_users_file_with_valid_hashes_admits_its_users() {
        let dir = tempfile::tempdir().expect("tempdir");
        let users = dir.path().join("users.toml");
        std::fs::write(
            &users,
            format!(
                "fleet = {:?}\n",
                crate::credentials::hash_basic("secret").expect("hash")
            ),
        )
        .expect("write");
        let headers = dir.path().join("headers.toml");
        std::fs::write(&headers, "Authorization = \"Bearer t\"\n").expect("write");
        let mut pairs = TLS_VARIABLES.to_vec();
        let users_path = users.display().to_string();
        let headers_path = headers.display().to_string();
        pairs.extend([
            ("CLASSIS_SERVER__REST__LISTEN", "0.0.0.0:4321"),
            (
                "CLASSIS_SERVER__REST__AUTH__BASIC_USERS_FILE",
                users_path.as_str(),
            ),
            (
                "CLASSIS_SERVER__TELEMETRY_OFFER__METRICS_ENDPOINT",
                "https://c.example/v1/metrics",
            ),
            (
                "CLASSIS_SERVER__TELEMETRY_OFFER__HEADERS_FILE",
                headers_path.as_str(),
            ),
        ]);
        let config = ServerConfig::load_layered(None, variables(&pairs))
            .expect("loads")
            .config;
        let auth = config.rest.auth.expect("[rest.auth]");
        // base64("fleet:secret")
        assert!(auth
            .credentials()
            .expect("credentials")
            .verify("Basic ZmxlZXQ6c2VjcmV0"));
        assert_eq!(
            config.telemetry_offer.expect("[telemetry_offer]").headers["Authorization"],
            "Bearer t"
        );

        std::fs::write(&users, "fleet = \"plain-password\"\n").expect("write");
        let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err("not a hash");
        assert!(
            err.contains("[rest.auth.basic_users] user \"fleet\""),
            "{err}"
        );
        assert!(!err.contains("plain-"), "never echoes the value: {err}");
        std::fs::write(&users, "fleet = plain-password\n").expect("write");
        let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err("not TOML");
        assert!(err.contains("basic_users_file"), "{err}");
        assert!(!err.contains("plain-"), "never quotes the file: {err}");
    }

    /// The startup log names every key the environment set, and none of their values.
    #[test]
    fn the_startup_log_names_the_keys_the_environment_set_and_no_value() {
        let mut pairs = TLS_VARIABLES.to_vec();
        pairs.push(("CLASSIS_SERVER__DATA_DIR", "/var/lib/secret-place"));
        let layered = ServerConfig::load_layered(None, variables(&pairs)).expect("loads");
        let notice = layered.environment_notice().expect("a notice");
        for key in ["listen", "data_dir"] {
            assert!(notice.contains(key), "{notice}");
        }
        for (_, value) in pairs {
            assert!(!notice.contains(value), "{notice}");
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, TLS).expect("write");
        assert_eq!(
            ServerConfig::load_layered(Some(&path), Vec::new())
                .expect("loads")
                .environment_notice(),
            None
        );
    }

    /// `[blobs]`: the filesystem by default; `"s3"` with its bucket; any other store, a bucket
    /// beside the filesystem, a plaintext endpoint off the loopback, and half a key pair each fail
    /// startup naming the key — with no store to reach.
    #[test]
    fn the_blob_store_is_chosen_and_checked_naming_the_key() {
        let load = |blobs: &str| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("server.toml");
            std::fs::write(&path, format!("{TLS}{blobs}")).expect("write");
            ServerConfig::load(&path)
        };
        let bucket = "[blobs]\nstore = \"s3\"\n[blobs.s3]\nbucket = \"fleet\"\nregion = \"eu-1\"\n";

        let config = load("").expect("the default");
        assert_eq!(config.blobs.store, "fs");
        assert!(config.blobs.s3().is_none());
        let config = load(&format!(
            "{bucket}endpoint = \"https://s3.example\"\nprefix = \"fleet/\"\n"
        ))
        .expect("a bucket over TLS");
        let s3 = config.blobs.s3().expect("s3");
        assert_eq!(
            (s3.bucket.as_str(), s3.prefix.as_str()),
            ("fleet", "fleet/")
        );
        assert!(!s3.allows_http());
        for loopback in ["http://127.0.0.1:9100", "http://[::1]:9100"] {
            let config = load(&format!("{bucket}endpoint = \"{loopback}\"\n")).expect(loopback);
            assert!(config.blobs.s3().expect("s3").allows_http(), "{loopback}");
        }

        for (blobs, named) in [
            ("[blobs]\nstore = \"S3\"\n", "[blobs] store"),
            ("[blobs]\nstore = \"minio\"\n", "[blobs] store"),
            ("[blobs]\nstore = \"s3\"\n", "[blobs.s3]"),
            (
                "[blobs.s3]\nendpoint = \"https://s3.example\"\nbucket = \"b\"\nregion = \"r\"\n",
                "[blobs.s3] is set but [blobs] store",
            ),
            (
                &format!("{bucket}endpoint = \"http://s3.example:9000\"\n"),
                "[blobs.s3] endpoint",
            ),
            (
                &format!("{bucket}endpoint = \"http://localhost:9000\"\n"),
                "[blobs.s3] endpoint",
            ),
            (
                &format!("{bucket}endpoint = \"s3.example\"\n"),
                "[blobs.s3] endpoint",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\nprefix = \"fleet\"\n"),
                "[blobs.s3] prefix",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\nprefix = \"a//\"\n"),
                "[blobs.s3] prefix",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\nprefix = \"50%/\"\n"),
                "[blobs.s3] prefix",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\nprefix = \"a#b/\"\n"),
                "[blobs.s3] prefix",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\nprefix = \"flöte/\"\n"),
                "[blobs.s3] prefix",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\naccess_key_id = \"AK\"\n"),
                "[blobs.s3] access_key_id and secret_access_key_file",
            ),
            (
                &format!(
                    "{bucket}endpoint = \"https://s3.example\"\nsecret_access_key_file = \"s\"\n"
                ),
                "[blobs.s3] access_key_id and secret_access_key_file",
            ),
            (
                &format!("{bucket}endpoint = \"https://s3.example\"\nsecret_access_key = \"x\"\n"),
                "secret_access_key",
            ),
        ] {
            let err = load(blobs).expect_err(blobs);
            assert!(err.contains(named), "{blobs}: {err}");
        }
    }

    /// The store's keys come through the environment like every other key, the secret's file
    /// included, with no code of their own.
    #[test]
    fn the_blob_store_is_configured_from_the_environment_too() {
        let mut pairs = TLS_VARIABLES.to_vec();
        pairs.extend([
            ("CLASSIS_SERVER__BLOBS__STORE", "s3"),
            (
                "CLASSIS_SERVER__BLOBS__S3__ENDPOINT",
                "https://s3.example:9000",
            ),
            ("CLASSIS_SERVER__BLOBS__S3__BUCKET", "fleet"),
            ("CLASSIS_SERVER__BLOBS__S3__REGION", "eu-central-1"),
            ("CLASSIS_SERVER__BLOBS__S3__PREFIX", "server-1/"),
            ("CLASSIS_SERVER__BLOBS__S3__ACCESS_KEY_ID", "classis-server"),
            (
                "CLASSIS_SERVER__BLOBS__S3__SECRET_ACCESS_KEY_FILE",
                "/run/secrets/s3-secret",
            ),
        ]);
        let config = ServerConfig::load_layered(None, variables(&pairs))
            .expect("loads")
            .config;
        let s3 = config.blobs.s3().expect("s3");
        assert_eq!(s3.endpoint, "https://s3.example:9000");
        assert_eq!(s3.prefix, "server-1/");
        assert_eq!(
            s3.secret_access_key_file.as_deref(),
            Some(Path::new("/run/secrets/s3-secret"))
        );
        pairs.push(("CLASSIS_SERVER__BLOBS__S3__ENDPOINT_URL", "https://x"));
        let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err("unknown");
        assert!(
            err.contains("CLASSIS_SERVER__BLOBS__S3__ENDPOINT_URL"),
            "{err}"
        );
    }

    /// `[database]`: the filesystem by default; `"postgres"` with its database. Any other store, a
    /// database beside the filesystem, a missing `[database.postgres]` key, and `tls = false` with a
    /// host that is not a loopback IP literal each fail startup naming the key — with no database
    /// to reach.
    #[test]
    fn the_record_store_is_chosen_and_checked_naming_the_key() {
        let load = |database: &str| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("server.toml");
            std::fs::write(&path, format!("{TLS}{database}")).expect("write");
            ServerConfig::load(&path)
        };
        let section = "[database]\nstore = \"postgres\"\n[database.postgres]\n";
        let full = format!(
            "{section}host = \"db.example\"\ndbname = \"fleet\"\nuser = \"fleet\"\n\
             password_file = \"/run/secrets/db\"\n"
        );

        let config = load("").expect("the default");
        assert_eq!(config.database.store, "fs");
        assert!(config.database.postgres().is_none());
        let config = load(&full).expect("a database over TLS");
        let postgres = config.database.postgres().expect("postgres");
        assert_eq!(
            (postgres.host.as_str(), postgres.port, postgres.tls),
            ("db.example", 5432, true)
        );
        assert!(postgres.ca_file.is_none());
        for loopback in ["127.0.0.1", "::1"] {
            let config = load(&format!(
                "{section}host = \"{loopback}\"\ndbname = \"f\"\nuser = \"f\"\n\
                 password_file = \"p\"\ntls = false\n"
            ))
            .expect(loopback);
            assert!(!config.database.postgres().expect("postgres").tls);
        }

        let without = |key: &str| {
            full.lines()
                .filter(|line| !line.starts_with(&format!("{key} =")))
                .collect::<Vec<_>>()
                .join("\n")
        };
        for (database, named) in [
            (
                "[database]\nstore = \"pg\"\n".to_string(),
                "[database] store",
            ),
            (
                "[database]\nstore = \"Postgres\"\n".to_string(),
                "[database] store",
            ),
            (
                "[database]\nstore = \"postgres\"\n".to_string(),
                "[database.postgres]",
            ),
            (
                "[database.postgres]\nhost = \"h\"\ndbname = \"d\"\nuser = \"u\"\n\
                 password_file = \"p\"\n"
                    .to_string(),
                "[database.postgres] is set but [database] store",
            ),
            (without("host"), "host"),
            (without("dbname"), "dbname"),
            (without("user"), "user"),
            (without("password_file"), "password_file"),
            (format!("{full}tls = false\n"), "tls = false"),
            (
                format!(
                    "{section}host = \"localhost\"\ndbname = \"f\"\nuser = \"f\"\n\
                         password_file = \"p\"\ntls = false\n"
                ),
                "host is \"localhost\"",
            ),
            (format!("{full}password = \"x\"\n"), "password"),
            (format!("{full}sslmode = \"disable\"\n"), "sslmode"),
            (
                format!(
                    "{section}host = \"\"\ndbname = \"f\"\nuser = \"f\"\npassword_file = \"p\"\n"
                ),
                "[database.postgres] host",
            ),
        ] {
            let err = load(&database).expect_err(&database);
            assert!(err.contains(named), "{database}: {err}");
        }
    }

    /// The database's keys come through the environment like every other key, the password's file
    /// included, with no code of their own.
    #[test]
    fn the_record_store_is_configured_from_the_environment_too() {
        let mut pairs = TLS_VARIABLES.to_vec();
        pairs.extend([
            ("CLASSIS_SERVER__DATABASE__STORE", "postgres"),
            ("CLASSIS_SERVER__DATABASE__POSTGRES__HOST", "127.0.0.1"),
            ("CLASSIS_SERVER__DATABASE__POSTGRES__PORT", "5433"),
            ("CLASSIS_SERVER__DATABASE__POSTGRES__DBNAME", "fleet"),
            ("CLASSIS_SERVER__DATABASE__POSTGRES__USER", "fleet"),
            (
                "CLASSIS_SERVER__DATABASE__POSTGRES__PASSWORD_FILE",
                "/run/secrets/db-password",
            ),
            ("CLASSIS_SERVER__DATABASE__POSTGRES__TLS", "false"),
        ]);
        let config = ServerConfig::load_layered(None, variables(&pairs))
            .expect("loads")
            .config;
        let postgres = config.database.postgres().expect("postgres");
        assert_eq!(postgres.host, "127.0.0.1");
        assert_eq!(postgres.port, 5433);
        assert!(!postgres.tls);
        assert_eq!(
            postgres.password_file,
            Path::new("/run/secrets/db-password")
        );
        pairs.push(("CLASSIS_SERVER__DATABASE__POSTGRES__PASSWORD", "x"));
        let err = ServerConfig::load_layered(None, variables(&pairs)).expect_err("unknown");
        assert!(
            err.contains("CLASSIS_SERVER__DATABASE__POSTGRES__PASSWORD"),
            "{err}"
        );
    }
}
