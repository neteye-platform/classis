//! The Server's own configuration file — TOML (ADR-0010).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use opamp::proto::{Header, Headers, OpAmpConnectionSettings, TelemetryConnectionSettings};
use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::fleet::{ConnectionOffer, TelemetryOffer};

/// The default Agent-plane address: the Baseline's port, on the loopback (ADR-0013). Serving the
/// estate is a line an operator writes deliberately, together with the TLS it needs.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:4320";

/// The default Operator-plane address (ADR-0013): the port above the protocol's, on loopback.
/// Loopback because that plane is open until `[rest.auth]` guards it (ADR-0021) — until then its
/// reachability *is* its protection, so publishing it is a line an operator writes deliberately.
pub const DEFAULT_REST_LISTEN: &str = "127.0.0.1:4321";

/// `server.toml`. Every setting has a default; unknown keys are rejected so a typo fails loudly at
/// startup instead of silently applying a default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address and port the **Agent plane** binds: the OpAMP endpoint and the package download
    /// route the offers point at (ADR-0013).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The **Operator plane** — REST API, API docs, and the bundled UI — on its own listener
    /// (ADR-0013). Absent means the default, which is loopback.
    #[serde(default)]
    pub rest: RestConfig,
    /// Where the Server keeps all of its state, one subdirectory per domain (ADR-0037): created
    /// owner-only when missing, and holding nothing but its fixed layout.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Refused at startup: the state lives under `data_dir` (ADR-0037), and `server migrate` moves
    /// an older installation there. Read only so that a leftover key can be named.
    pub config_dir: Option<IgnoredAny>,
    /// TLS for the Agent plane, and for the Operator plane unless `[rest.tls]` names its own
    /// (ADR-0013, ADR-0032). Required: a Server without it is refused at startup. It is an
    /// `Option` only so that its absence can be named.
    pub tls: Option<TlsConfig>,
    /// Refused at startup: the Agent plane admits by client certificate alone and has no credential
    /// of its own (ADR-0021 clause 1). Read only so that a leftover section can be named.
    pub auth: Option<IgnoredAny>,
    /// Optional connection settings offered to the fleet (ADR-0014); absent means none.
    pub connection_offer: Option<ConnectionOfferConfig>,
    /// Optional certificate authority for signing Agent CSRs (ADR-0021); absent means the Server
    /// issues nothing and does not declare `AcceptsConnectionSettingsRequest`.
    pub client_ca: Option<ClientCaConfig>,
    /// Optional destinations for the Agents' own telemetry (ADR-0016); absent means none is
    /// offered and no Agent reports any.
    pub telemetry_offer: Option<TelemetryOfferConfig>,
    /// Refused at startup, like `config_dir` (ADR-0037). Read only so that a leftover key can be
    /// named.
    pub packages_dir: Option<IgnoredAny>,
    /// How the Server checks the signatures on its Package entries (ADR-0033).
    #[serde(default)]
    pub packages: PackagesConfig,
    /// Refused at startup: every package is offered as a path the Client resolves against its own
    /// endpoint, and a Client downloads from no other host (ADR-0033). Read only so that a leftover
    /// key can be named.
    pub advertised_url: Option<IgnoredAny>,
    /// The largest OpAMP message the Server accepts or sends, on either transport and in either
    /// direction. The Baseline requires the limit, recommends this default, and asks that it be
    /// configurable — a fleet of small status reports can be served with far less.
    #[serde(default = "default_max_message_size")]
    pub max_message_size_bytes: usize,
    /// The largest package artifact the REST API accepts on upload (ADR-0026). Nothing to do with
    /// the OpAMP message limit above: a package is a *program*, routinely hundreds of megabytes,
    /// and it travels over the REST plane, never in an OpAMP message.
    #[serde(default = "default_max_package_size")]
    pub max_package_size_bytes: usize,
    /// The total size of all stored package artifacts the REST API keeps before it refuses a new
    /// upload (ADR-0026). Where `max_package_size_bytes` bounds one artifact, this bounds the whole
    /// store — so a caller cannot fill the disk by uploading many artifacts under distinct names.
    /// `0` is refused at load.
    #[serde(default = "default_max_total_package_size")]
    pub max_total_package_bytes: u64,
    /// How long an Agent that declares `ReportsHeartbeat` may be silent before the fleet view calls
    /// it stale (ADR-0024). Ignored when `[connection_offer]` names a heartbeat interval — the
    /// period this Server asked for is a better answer than a default.
    #[serde(default = "default_stale_after_secs")]
    pub stale_after_secs: u64,
    /// The most Agent records the fleet holds at once. A report bearing a new `instance_uid` past
    /// this ceiling is refused `Unavailable`, so a peer minting fresh self-asserted UIDs (ADR-0021)
    /// cannot exhaust memory or disk; existing Agents keep reporting. The real defence against an
    /// anonymous flood is admission by client certificate (ADR-0021) — this is the backstop behind
    /// it. `0` is refused at load: a fleet that can hold no Agent is a misconfiguration, not a
    /// limit.
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,
    /// The connections the Agent plane holds at once (ADR-0013). Past it a connection is closed on
    /// accept; the ones held keep working. A fleet larger than the default raises this together
    /// with the process's file-descriptor limit. `0` is refused at load.
    #[serde(default = "default_agent_max_connections")]
    pub max_connections: usize,
    /// The bootstrap CA a host enrols with (ADR-0021 clause 19); absent means no host enrols, and
    /// an operator provisions every certificate.
    pub enrolment: Option<EnrolmentConfig>,
    /// How repeated admission failures from one peer address are throttled (ADR-0021 clause 24).
    #[serde(default)]
    pub admission_throttle: AdmissionThrottleConfig,
    /// How large the audit record grows and how much of it is kept (ADR-0022).
    #[serde(default)]
    pub audit: AuditConfig,
    /// How often an admitted peer may be heard on the Agent plane (ADR-0013).
    #[serde(default)]
    pub agent_rate_limit: AgentRateLimitConfig,
}

/// The `[agent_rate_limit]` section (ADR-0013 clause 19). Every key has a default, and none is `0`:
/// no value switches the limit off.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentRateLimitConfig {
    /// Tokens a host's or an Agent's bucket gains per second.
    pub messages_per_sec: u32,
    /// That bucket's capacity; a new bucket starts full.
    pub burst: u32,
    /// Tokens the aggregate bucket of a host marked as a Gateway gains per second.
    pub gateway_messages_per_sec: u32,
    /// The aggregate bucket's capacity.
    pub gateway_burst: u32,
}

impl Default for AgentRateLimitConfig {
    fn default() -> Self {
        let limits = crate::agent_rate::Limits::default();
        AgentRateLimitConfig {
            messages_per_sec: limits.messages_per_sec,
            burst: limits.burst,
            gateway_messages_per_sec: limits.gateway_messages_per_sec,
            gateway_burst: limits.gateway_burst,
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
            gateway_messages_per_sec: self.gateway_messages_per_sec,
            gateway_burst: self.gateway_burst,
        }
    }

    fn check(&self) -> Result<(), String> {
        for (key, value) in [
            ("messages_per_sec", self.messages_per_sec),
            ("burst", self.burst),
            ("gateway_messages_per_sec", self.gateway_messages_per_sec),
            ("gateway_burst", self.gateway_burst),
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

/// The Agents a host may speak for at most (ADR-0021 clause 7), which the limit has to carry at
/// the fleet's heartbeat (ADR-0013 clause 20).
const AGENTS_PER_HOST: u64 = 256;

/// The heartbeat the Baseline uses when none is offered.
const BASELINE_HEARTBEAT_SECS: u64 = 30;

/// The `[audit]` section (ADR-0022 clause 4).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// A file reaching this size is closed and a new one started.
    pub max_file_bytes: u64,
    /// How many files are kept; the oldest past this is deleted.
    pub keep_files: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        let limits = crate::audit_log::Limits::default();
        AuditConfig {
            max_file_bytes: limits.max_file_bytes,
            keep_files: limits.keep_files,
        }
    }
}

impl AuditConfig {
    #[must_use]
    pub fn limits(&self) -> crate::audit_log::Limits {
        crate::audit_log::Limits {
            max_file_bytes: self.max_file_bytes,
            keep_files: self.keep_files,
        }
    }
}

/// The `[packages]` section (ADR-0033): the operator's public key, against which the Server checks
/// every entry's signature — as feedback only. The Agent's own check decides what is installed.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesConfig {
    /// The hex-encoded Ed25519 public key, in the format the Client's `[packages]
    /// verification_key` uses. Absent, every signature is reported `unchecked`.
    pub verification_key: Option<String>,
}

impl PackagesConfig {
    /// The decoded key, or `None` when none is set.
    ///
    /// # Errors
    /// Returns an error naming the key when it is not hex or not the 32 bytes of an Ed25519
    /// public key.
    pub fn verification_key(&self) -> Result<Option<Vec<u8>>, String> {
        let Some(text) = &self.verification_key else {
            return Ok(None);
        };
        let key = hex::decode(text.trim())
            .map_err(|e| format!("[packages] verification_key is not valid hex: {e}"))?;
        if key.len() != ring::signature::ED25519_PUBLIC_KEY_LEN {
            return Err(format!(
                "[packages] verification_key must be the {} bytes of an Ed25519 public key \
                 ({} hex characters), not {} bytes",
                ring::signature::ED25519_PUBLIC_KEY_LEN,
                ring::signature::ED25519_PUBLIC_KEY_LEN * 2,
                key.len()
            ));
        }
        Ok(Some(key))
    }
}

/// The Ed25519 adapter behind [`SignatureVerifier`](crate::packages::SignatureVerifier): the
/// operator's public key from `[packages] verification_key`, checked with `ring`, the provider the
/// Client verifies with (ADR-0033).
pub struct Ed25519Verifier(Vec<u8>);

impl Ed25519Verifier {
    /// `key` is the raw public key, as [`PackagesConfig::verification_key`] decodes it.
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Ed25519Verifier(key)
    }
}

impl crate::packages::SignatureVerifier for Ed25519Verifier {
    fn verifies(&self, statement: &[u8], signature: &[u8]) -> bool {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.0)
            .verify(statement, signature)
            .is_ok()
    }
}

/// The `[enrolment]` section (ADR-0021 clause 19).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentConfig {
    /// PEM certificate of the CA that issues bootstrap certificates. A certificate from it can
    /// only enrol: it needs an open enrolment window and an operator's approval.
    pub bootstrap_ca_file: PathBuf,
    /// PEM PKCS#8 key of that CA. With it the Server issues bootstrap certificates on an
    /// operator's request; without it enrolment works with bootstrap certificates made elsewhere
    /// (ADR-0021 clause 19).
    #[serde(default)]
    pub bootstrap_ca_key_file: Option<PathBuf>,
    /// The most requests of one bootstrap certificate the pending queue holds at once, 1 to
    /// [`MAX_PENDING`](crate::enrolment::MAX_PENDING) (ADR-0046).
    #[serde(default = "default_max_pending_per_bootstrap")]
    pub max_pending_per_bootstrap: usize,
}

fn default_max_pending_per_bootstrap() -> usize {
    crate::enrolment::DEFAULT_MAX_PENDING_PER_BOOTSTRAP
}

/// The `[admission_throttle]` section (ADR-0021 clause 24).
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

/// The `[rest]` section (ADR-0013): the Operator plane's own listener. It is a section rather than
/// a bare key because the plane is what grows next — an authentication decision belongs inside it,
/// not beside it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestConfig {
    /// Address and port the REST API, the API docs, and the bundled UI bind.
    #[serde(default = "default_rest_listen")]
    pub listen: SocketAddr,
    /// Optional Basic authentication over the whole plane (ADR-0021); required off the loopback.
    pub auth: Option<RestAuthConfig>,
    /// The connections the Operator plane holds at once (ADR-0013). `0` is refused at load.
    #[serde(default = "default_rest_max_connections")]
    pub max_connections: usize,
    /// The Operator plane's own certificate and key (ADR-0032); without it, `[tls]`'s.
    pub tls: Option<RestTlsConfig>,
}

/// The `[rest.tls]` section (ADR-0032): the certificate the Operator plane serves in place of
/// `[tls]`'s, typically from the operator's own PKI so that browsers trust it as they are. Nothing
/// else: the Operator plane asks for no client certificate, so a `client_ca_file` here is refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestTlsConfig {
    /// PEM certificate chain, the leaf first.
    pub cert_file: PathBuf,
    /// PEM private key of the leaf.
    pub key_file: PathBuf,
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

/// The `[rest.auth]` section (ADR-0021): who may reach the Operator plane. Basic only — the
/// audience is a browser and `curl`, and Basic is the one scheme both speak without a login page.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestAuthConfig {
    /// Accepted Basic credentials, `user = "<Argon2id hash>"` (ADR-0021 clause 26). Several allow
    /// a rotation, or an individual operator's credential to be withdrawn on its own.
    #[serde(default)]
    pub basic_users: BTreeMap<String, String>,
}

impl std::fmt::Debug for RestAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestAuthConfig")
            .field("basic_users", &self.basic_users.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RestAuthConfig {
    /// The check the Operator plane runs on every request (ADR-0021 clause 2).
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
    /// empty user or password is a half-written credential rather than an intent (ADR-0010).
    fn check(&self) -> Result<(), String> {
        if self.basic_users.is_empty() {
            return Err(
                "a [rest.auth] section needs at least one entry in [rest.auth.basic_users]"
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

/// The `[connection_offer]` section (ADR-0014 clause 1): what every Agent declaring
/// `AcceptsOpAMPConnectionSettings` is offered — a heartbeat interval, an endpoint. Either or both,
/// but never neither. It carries no credential: the Agent plane admits by client certificate alone
/// (ADR-0021), so an offered credential would be one nothing reads.
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
    /// Loud validation (ADR-0010): no credential key, at least one offered field, and an endpoint
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
                    "[connection_offer] {key} is refused — the Agent plane admits by client \
                     certificate alone, so no credential is offered; remove the key"
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
        // that port would be the fleet's Server, unproven (ADR-0040 clause 1).
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

/// The `[telemetry_offer]` section (ADR-0016): where Agents send their own telemetry.
///
/// The endpoints are full OTLP/HTTP URLs *with path*, which is what the Baseline requires of them;
/// this Server does not append `/v1/metrics` for you, because guessing a receiver's routing is how
/// telemetry disappears into a 404 nobody looks at.
///
/// **What this section says, it says about all three signals** (ADR-0016). A signal left out is
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
}

impl TelemetryOfferConfig {
    /// Loud validation (ADR-0010): an empty section offers nothing and is never what an operator
    /// meant, and an endpoint that is not an OTLP/HTTP URL would be refused by every Agent.
    ///
    /// An endpoint set to the empty string passes both tests deliberately — it is a withdrawal
    /// (ADR-0016), which is a thing to be said rather than a URL to be checked.
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert_file: PathBuf,
    /// PEM private key.
    pub key_file: PathBuf,
    /// PEM bundle of the certificate authorities a **client** certificate must chain to, required
    /// (ADR-0021). The Agent plane asks for the certificate in the TLS handshake, so a peer without
    /// one, or with one this bundle (or the bootstrap CA of `[enrolment]`) does not verify, never
    /// reaches a route — the package download included. An `Option` only so its absence can be
    /// named at startup.
    pub client_ca_file: Option<PathBuf>,
}

/// The `[client_ca]` section (ADR-0021): the certificate authority this Server signs Agent CSRs
/// with. Present is what arms the CSR flow — `AcceptsConnectionSettingsRequest` is declared only
/// while it is, the same "declare what is actually armed" rule `[connection_offer]` follows.
///
/// It is deliberately *not* the listener's own certificate and key. The Baseline's own schema warns
/// against storing a CA's private key where the server certificate lives, because compromising the
/// Server would then mint fleet members at will.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCaConfig {
    /// PEM certificate of the issuing CA.
    pub cert_file: PathBuf,
    /// PEM private key of the issuing CA.
    pub key_file: PathBuf,
    /// How long an issued certificate is valid. Short is the point: validity plus renewal bounds a
    /// certificate nobody noticed was stolen, and revocation ends one that was (ADR-0021).
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,
}

impl ClientCaConfig {
    /// Loud validation (ADR-0010): a CA that cannot sign, or one whose certificates expire before
    /// the Client would renew them, is a configuration error rather than a runtime surprise.
    fn check(&self) -> Result<(), String> {
        if self.validity_days == 0 {
            return Err("[client_ca] validity_days must be greater than zero".to_string());
        }
        for path in [&self.cert_file, &self.key_file] {
            if !path.exists() {
                return Err(format!("[client_ca] {} does not exist", path.display()));
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

fn default_max_message_size() -> usize {
    opamp::frame::DEFAULT_MAX_MESSAGE_SIZE
}

/// Long enough that a host offline over a holiday still comes back on a valid certificate, short
/// enough that a certificate is not a permanent grant (ADR-0021).
/// Three times the Baseline's own default heartbeat of 30 seconds (ADR-0024): one missed beat is a
/// lost packet, and a fleet view that flickers is one nobody trusts.
fn default_stale_after_secs() -> u64 {
    90
}

/// A month: short enough that a certificate stolen unnoticed is good for weeks, not a quarter;
/// long enough that a host offline for a fortnight still renews on its own (ADR-0021 clause 9).
fn default_validity_days() -> u32 {
    30
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
            connection_offer: None,
            client_ca: None,
            telemetry_offer: None,
            packages_dir: None,
            packages: PackagesConfig::default(),
            advertised_url: None,
            max_message_size_bytes: default_max_message_size(),
            max_package_size_bytes: default_max_package_size(),
            max_total_package_bytes: default_max_total_package_size(),
            stale_after_secs: default_stale_after_secs(),
            max_agents: default_max_agents(),
            max_connections: default_agent_max_connections(),
            enrolment: None,
            admission_throttle: AdmissionThrottleConfig::default(),
            audit: AuditConfig::default(),
            agent_rate_limit: AgentRateLimitConfig::default(),
        }
    }
}

/// Whether two listener addresses cannot both be bound: the same port on the same address, or on
/// an address that covers every interface — `0.0.0.0:4320` and `127.0.0.1:4320` are two spellings
/// of one socket as far as the second `bind` is concerned.
fn listeners_collide(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

impl ServerConfig {
    /// Loads the file, or the defaults when it does not exist (a fresh checkout runs without any
    /// setup). A file that exists but does not parse is an error — never silently ignored.
    pub fn load(path: &Path) -> Result<Self, String> {
        // A missing file is the defaults, held to the same rules: they serve no TLS, so a Server
        // without a configuration is refused below, naming what it needs (ADR-0013).
        let config: ServerConfig = if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))?
        } else {
            ServerConfig::default()
        };
        // The Agent plane has no credential of its own (ADR-0021 clause 1). A leftover section is
        // refused rather than ignored: an operator is present at a Server upgrade, and a section
        // that silently did nothing would tell them the fleet still needs it.
        if config.auth.is_some() {
            return Err(format!(
                "{}: [auth] is refused — the Agent plane admits by client certificate alone; \
                 remove the section",
                path.display()
            ));
        }
        // One root for all state (ADR-0037 clause 1). A leftover key is refused rather than
        // ignored: the directory it names holds the fleet's trust data, which this Server would
        // otherwise start without.
        for (key, named) in [
            ("config_dir", config.config_dir.is_some()),
            ("packages_dir", config.packages_dir.is_some()),
        ] {
            if named {
                return Err(format!(
                    "{}: {key} is removed — the Server keeps all of its state under data_dir \
                     (ADR-0037). Stop the Server, run `server migrate --config-dir <old> \
                     --packages-dir <old> --data-dir <new>`, then replace config_dir and \
                     packages_dir with data_dir",
                    path.display()
                ));
            }
        }
        if config.advertised_url.is_some() {
            return Err(format!(
                "{}: advertised_url is removed — every package is offered as a path the Client \
                 resolves against its own Server, and a Client downloads from no other host \
                 (ADR-0033); remove the key",
                path.display()
            ));
        }
        if let Some(offer) = &config.connection_offer {
            offer
                .check()
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        if let Some(client_ca) = &config.client_ca {
            client_ca
                .check()
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        if let Some(telemetry) = &config.telemetry_offer {
            telemetry
                .check()
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        if let Some(auth) = &config.rest.auth {
            auth.check()
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        // A malformed key fails startup, not the first signature it would have checked (ADR-0033).
        config
            .packages
            .verification_key()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        // The two planes are two listeners (ADR-0013). Addresses that collide would surface as the
        // second bind failing with "address already in use" — a message about sockets for what is
        // really a configuration mistake, so it is refused here, by name.
        if listeners_collide(config.listen, config.rest.listen) {
            return Err(format!(
                "{}: listen ({}) and [rest] listen ({}) must be different addresses — the Agent \
                 plane and the Operator plane are separate listeners",
                path.display(),
                config.listen,
                config.rest.listen
            ));
        }
        // Mutual TLS needs a TLS listener to happen on: `client_ca_file` lives inside `[tls]`, so
        // this can only be a `[client_ca]` without one — issuing certificates for a channel that
        // will never ask for them (ADR-0021).
        if config.client_ca.is_some() && config.tls.is_none() {
            return Err(format!(
                "{}: [client_ca] issues client certificates, which only a TLS listener can ask \
                 for — add a [tls] section, or remove [client_ca]",
                path.display()
            ));
        }
        // A limit of zero would refuse every message, and the Baseline knows no "unlimited": the
        // limit is mandatory, so a value that cannot carry a message fails startup.
        if config.max_message_size_bytes == 0 {
            return Err(format!(
                "{}: max_message_size_bytes must be greater than zero",
                path.display()
            ));
        }
        if config.stale_after_secs == 0 {
            return Err(format!(
                "{}: stale_after_secs must be greater than zero — a budget of nothing would call \
                 every Agent stale the instant it reported",
                path.display()
            ));
        }
        if config.max_package_size_bytes == 0 {
            return Err(format!(
                "{}: max_package_size_bytes must be greater than zero",
                path.display()
            ));
        }
        if config.max_total_package_bytes == 0 {
            return Err(format!(
                "{}: max_total_package_bytes must be greater than zero — it bounds the store, not a \
                 switch",
                path.display()
            ));
        }
        if config.max_agents == 0 {
            return Err(format!(
                "{}: max_agents must be greater than zero — a fleet that can hold no Agent is a \
                 misconfiguration, not a limit",
                path.display()
            ));
        }
        config
            .agent_rate_limit
            .check()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if config.max_connections == 0 || config.rest.max_connections == 0 {
            return Err(format!(
                "{}: max_connections and [rest] max_connections must be greater than zero — a \
                 plane that holds no connection serves nobody",
                path.display()
            ));
        }
        config
            .check_secure()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(config)
    }

    /// A warning when one host cannot report for all the Agents it may speak for at the fleet's
    /// heartbeat (ADR-0013 clause 20): `messages_per_sec` times the offered heartbeat interval, or
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

    /// The transport rules of the specification's Q-1 (ADR-0013): the Agent plane always serves
    /// TLS, and the Operator plane off the loopback requires authentication.
    fn check_secure(&self) -> Result<(), String> {
        let Some(tls) = &self.tls else {
            return Err(
                "[tls] is required — the Agent plane always serves TLS 1.3; set cert_file and \
                 key_file (`opamp-fleetctl pki init` makes a set, scripts/dev-pki.sh a development one)"
                    .to_string(),
            );
        };
        // The certificate is the whole of admission (ADR-0021 clauses 5, 6).
        if tls.client_ca_file.is_none() {
            return Err(
                "[tls] client_ca_file is required — every Agent presents a client certificate in \
                 the handshake"
                    .to_string(),
            );
        }
        if self.enrolment.is_some() && self.client_ca.is_none() {
            return Err(
                "[enrolment] needs [client_ca]: an approved request is signed by it".to_string(),
            );
        }
        if let Some(enrolment) = &self.enrolment {
            let max = crate::enrolment::MAX_PENDING;
            if !(1..=max).contains(&enrolment.max_pending_per_bootstrap) {
                return Err(format!(
                    "[enrolment] max_pending_per_bootstrap must be between 1 and {max}, not {}",
                    enrolment.max_pending_per_bootstrap
                ));
            }
        }
        if self.audit.max_file_bytes == 0 || self.audit.keep_files == 0 {
            return Err(
                "[audit] max_file_bytes and keep_files must be greater than 0 — the record is \
                 never switched off"
                    .to_string(),
            );
        }
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

/// The `[connection_offer]` section as the offer the fleet makes (ADR-0014). It carries no
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

/// The `[telemetry_offer]` section as the destinations the fleet offers (ADR-0016).
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
                    // A withdrawal names nothing else (ADR-0016): an empty endpoint stops that
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

    /// A `[tls]` section with everything admission needs.
    const TLS: &str =
        "[tls]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\nclient_ca_file = \"ca.pem\"\n";

    #[test]
    fn parses_a_full_config() {
        let cfg: ServerConfig = toml::from_str(
            r#"
            listen = "127.0.0.1:9999"
            data_dir = "state"
            [tls]
            cert_file = "cert.pem"
            key_file = "key.pem"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.listen.port(), 9999);
        assert!(cfg.tls.is_some());
    }

    #[test]
    fn defaults_apply_to_an_empty_file() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.listen.port(), 4320);
        assert!(cfg.tls.is_none());
    }

    /// ADR-0013: the Operator plane is a second listener, and by default it is on loopback — the
    /// only protection it has while nothing authenticates it.
    /// Verifies: ADR-0013
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

    /// `[rest.tls]` takes a certificate and its key and nothing else: the Operator plane asks for
    /// no client certificate, so a `client_ca_file` there is refused, and so is a missing key.
    /// Verifies: ADR-0032
    #[test]
    fn rest_tls_takes_a_certificate_and_its_key_and_nothing_else() {
        let cfg: ServerConfig =
            toml::from_str("[rest.tls]\ncert_file = \"ui.pem\"\nkey_file = \"ui-key.pem\"\n")
                .expect("parse");
        let tls = cfg.rest.tls.expect("[rest.tls]");
        assert_eq!(tls.cert_file, PathBuf::from("ui.pem"));
        assert_eq!(tls.key_file, PathBuf::from("ui-key.pem"));
        let refused = toml::from_str::<ServerConfig>(
            "[rest.tls]\ncert_file = \"ui.pem\"\nkey_file = \"ui-key.pem\"\nclient_ca_file = \"ca.pem\"\n",
        )
        .expect_err("a client CA on the Operator plane");
        assert!(refused.to_string().contains("client_ca_file"), "{refused}");
        let refused = toml::from_str::<ServerConfig>("[rest.tls]\ncert_file = \"ui.pem\"\n")
            .expect_err("a certificate without its key");
        assert!(refused.to_string().contains("key_file"), "{refused}");
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert!(cfg.rest.tls.is_none(), "the section is optional");
    }

    /// Two planes, two sockets: an address that cannot be bound twice is a configuration mistake,
    /// and it is named as one rather than surfacing as "address already in use" (ADR-0013).
    /// Verifies: ADR-0013
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

    /// `[packages] verification_key` is the operator's public key, hex, as the Client's key of the
    /// same name: absent by default, decoded when given, and a malformed one fails startup naming
    /// it (ADR-0033 clause 7).
    /// Verifies: ADR-0033
    #[test]
    fn a_malformed_verification_key_fails_startup() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.packages.verification_key(), Ok(None));
        let key = "ab".repeat(32);
        let cfg: ServerConfig =
            toml::from_str(&format!("[packages]\nverification_key = \"{key}\"\n")).expect("parse");
        assert_eq!(cfg.packages.verification_key(), Ok(Some(vec![0xab; 32])));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for malformed in ["not-hex", "abcd"] {
            std::fs::write(
                &path,
                format!("[packages]\nverification_key = \"{malformed}\"\n"),
            )
            .expect("write");
            let err = ServerConfig::load(&path).expect_err("a malformed key fails startup");
            assert!(err.contains("[packages] verification_key"), "{err}");
        }
        let refused = toml::from_str::<ServerConfig>("[packages]\nallowed_sources = []\n")
            .expect_err("the section takes nothing else");
        assert!(refused.to_string().contains("allowed_sources"), "{refused}");
    }

    /// Every package is offered as a path, so a leftover `advertised_url` is named and refused
    /// rather than ignored: it would tell the operator a mirror is in use that no Client reaches.
    /// Verifies: ADR-0033
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
    /// Verifies: ADR-0037
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
    /// The withdrawal is the one ADR-0016 adds — an empty endpoint is a thing to say, not a URL to
    /// check — and it must not be waved through for a value that is merely wrong.
    /// Verifies: ADR-0016
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

    /// Verifies: ADR-0010
    #[test]
    fn rejects_unknown_keys() {
        assert!(toml::from_str::<ServerConfig>("listne = \"0.0.0.0:1\"").is_err());
    }

    /// No credential in `server.toml` authenticates on its own: an operator's password in clear is
    /// refused at startup, the section and the user named and the value never echoed (ADR-0021
    /// clause 26).
    /// Verifies: ADR-0021
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

    /// The Agent plane has no credential of its own: a leftover `[auth]` is refused at startup,
    /// named, with the reason, whatever it holds (ADR-0021 clause 1).
    /// Verifies: ADR-0021
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
                err.contains("admits by client certificate alone"),
                "says why: {err}"
            );
            assert!(!err.contains("plain-"), "never echoes a value: {err}");
        }
        std::fs::write(&path, TLS).expect("write");
        ServerConfig::load(&path).expect("no [auth], no refusal");
    }

    /// Verifies: ADR-0021
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

    /// The Operator plane's own credentials (ADR-0021), precomputed into the header values that
    /// authenticate, with the challenge that makes a browser ask rather than give up.
    /// Verifies: ADR-0021
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
    /// Verifies: ADR-0021
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

        // Bearer is not a scheme this plane has, and a typo fails loudly (ADR-0010, ADR-0021).
        assert!(toml::from_str::<ServerConfig>("[rest.auth]\nbearer_tokens = [\"tok\"]").is_err());
    }

    /// Verifies: ADR-0014
    #[test]
    fn a_connection_offer_needs_at_least_one_field() {
        let empty: ConnectionOfferConfig =
            toml::from_str("").expect("parses; emptiness is semantic");
        assert!(empty.check().is_err());
    }

    /// A credential key is refused by name, whatever else the section offers (ADR-0014 clause 1).
    /// Verifies: ADR-0014
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

    /// Verifies: ADR-0014
    #[test]
    fn a_connection_offer_rejects_a_bad_endpoint_scheme() {
        let bad: ConnectionOfferConfig =
            toml::from_str("endpoint = \"ftp://x/v1/opamp\"").expect("parse");
        assert!(bad.check().is_err());
        let good: ConnectionOfferConfig =
            toml::from_str("endpoint = \"wss://x/v1/opamp\"").expect("parse");
        assert!(good.check().is_ok());
    }

    /// Verifies: ADR-0014
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
    /// Verifies: ADR-0040
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

    /// Verifies: ADR-0014
    #[test]
    fn a_connection_offer_refuses_a_plaintext_endpoint_on_localhost() {
        let offer: ConnectionOfferConfig =
            toml::from_str("endpoint = \"ws://localhost:4320/v1/opamp\"").expect("parse");
        assert!(offer.check().is_err());
    }

    /// The certificate is the whole of admission: a Server without the client CA does not start,
    /// and neither does an `[enrolment]` without a CA to sign what it approves.
    /// Verifies: ADR-0021, Q-1
    #[test]
    fn the_client_ca_is_required_at_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        std::fs::write(
            &path,
            "[tls]\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\n",
        )
        .expect("write");
        let err = ServerConfig::load(&path).expect_err("no client CA");
        assert!(err.contains("client_ca_file is required"), "{err}");

        std::fs::write(&path, TLS).expect("write");
        ServerConfig::load(&path).expect("the client CA is all admission needs");

        std::fs::write(
            &path,
            format!("{TLS}[enrolment]\nbootstrap_ca_file = \"boot.pem\"\n"),
        )
        .expect("write");
        let err = ServerConfig::load(&path).expect_err("enrolment without a CA");
        assert!(err.contains("[enrolment] needs [client_ca]"), "{err}");
    }

    /// The share of the enrolment queue one bootstrap certificate may hold runs from 1 to 1024,
    /// 256 by default; anything else fails startup naming the key.
    /// Verifies: ADR-0046
    #[test]
    fn max_pending_per_bootstrap_runs_from_1_to_1024() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        // `[enrolment]` needs a `[client_ca]` whose files exist; their content is not read here.
        let (cert, key) = (dir.path().join("ca.pem"), dir.path().join("ca-key.pem"));
        std::fs::write(&cert, "").expect("write");
        std::fs::write(&key, "").expect("write");
        let with = |line: &str| {
            format!(
                "{TLS}[client_ca]\ncert_file = {:?}\nkey_file = {:?}\n\
                 [enrolment]\nbootstrap_ca_file = \"boot.pem\"\n{line}",
                cert.display().to_string(),
                key.display().to_string(),
            )
        };
        std::fs::write(&path, with("")).expect("write");
        let config = ServerConfig::load(&path).expect("the default");
        assert_eq!(
            config
                .enrolment
                .expect("enrolment")
                .max_pending_per_bootstrap,
            256
        );
        for ok in [1, 1024] {
            std::fs::write(&path, with(&format!("max_pending_per_bootstrap = {ok}\n")))
                .expect("write");
            ServerConfig::load(&path).expect("within bounds");
        }
        for bad in [0, 1025] {
            std::fs::write(&path, with(&format!("max_pending_per_bootstrap = {bad}\n")))
                .expect("write");
            let err = ServerConfig::load(&path).expect_err("out of bounds");
            assert!(
                err.contains("[enrolment] max_pending_per_bootstrap"),
                "{bad}: {err}"
            );
        }
    }

    /// Verifies: ADR-0013
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

    /// Verifies: ADR-0013
    #[test]
    fn the_agent_rate_limit_defaults_and_refuses_zero() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(
            cfg.agent_rate_limit.limits(),
            crate::agent_rate::Limits {
                messages_per_sec: 10,
                burst: 300,
                gateway_messages_per_sec: 500,
                gateway_burst: 10_000,
            }
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server.toml");
        for key in [
            "messages_per_sec",
            "burst",
            "gateway_messages_per_sec",
            "gateway_burst",
        ] {
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

    /// Verifies: ADR-0013
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

    /// Verifies: ADR-0013
    #[test]
    fn the_agent_plane_defaults_to_the_loopback() {
        let cfg: ServerConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.listen, "127.0.0.1:4320".parse().expect("address"));
    }

    /// Verifies: ADR-0013, ADR-0021, Q-1
    #[test]
    fn a_server_without_tls_is_refused_at_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No file at all is the defaults, and the defaults serve no TLS.
        let missing = ServerConfig::load(&dir.path().join("absent.toml")).expect_err("no tls");
        assert!(missing.contains("[tls] is required"), "{missing}");
        let path = dir.path().join("server.toml");
        std::fs::write(&path, "listen = \"127.0.0.1:4320\"\n").expect("write");
        let err = ServerConfig::load(&path).expect_err("no tls");
        assert!(err.contains("[tls] is required"), "{err}");
    }

    /// Verifies: ADR-0013, ADR-0021
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
}
