//! The Client's own configuration file — TOML (ADR-0010).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// `supervisor.toml`. Every setting has a default; unknown keys are rejected so a typo fails loudly at
/// startup instead of silently applying a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// The Server's OpAMP endpoint. The URL scheme selects the transport (ADR-0013):
    /// `ws://` / `wss://` is the WebSocket transport, `http://` / `https://` the polling one.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// The operator's name for the Client's own Agent, reported as `service.instance.name`
    /// (ADR-0016) — *which* Client this is. Its `service.name` is the type
    /// [`CLIENT_AGENT_TYPE`](crate::supervisor::agent::CLIENT_AGENT_TYPE) — `supervisor`, a
    /// constant (ADR-0019) — so this key cannot state it: every Client in a fleet is the same kind
    /// of thing.
    #[serde(default = "default_name")]
    pub name: String,
    /// The deployment's `service.namespace`. The Baseline asks for it "if it is used in the
    /// environment where the Agent runs", which is knowledge only an operator has — so it is
    /// configured rather than detected, and absent means it is not reported at all. Reported as
    /// an **identifying** attribute of every Agent this Client presents, which is where the
    /// Baseline puts it: it says which deployment the service belongs to.
    pub service_namespace: Option<String>,
    /// How often the plain-HTTP transport polls. The Baseline's default is 30 seconds; ignored on
    /// WebSocket, where the Server pushes.
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// How often each Agent heartbeats over the WebSocket transport (`ReportsHeartbeat`). The
    /// Baseline's default is 30 seconds; `0` disables heartbeats and undeclares the capability.
    /// Ignored on plain HTTP, where every poll is the periodic report.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// Where the Client persists its identity and the received remote configuration.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Where the per-Supervisor directories live (ADR-0017); absent means
    /// `<state_dir>/supervisors`, which is where they have always been. Set it to put the
    /// Managed Processes' programs somewhere `state_dir` cannot go — off a `noexec` mount, or
    /// onto a volume sized for a few hundred megabytes of agent rather than for state.
    pub supervisor_dir: Option<PathBuf>,
    /// Operator-defined attributes (ADR-0041 clause 2), reported as non-identifying attributes of
    /// **every** Agent this Client presents — machine-level tags like `env = "prod"` that
    /// Selectors can match. Attributes the code reports win over configured ones; a configured one
    /// stands against whatever a Managed Process reports. A `[[supervisor]]` block carrying its own
    /// `attributes` fails at startup: tagging one Agent is a Server label's job.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Optional Gateway Mode (ADR-0015); absent means this Client gateways for nobody.
    pub gateway: Option<GatewayConfig>,
    /// Optional TLS trust override for `wss://` / `https://` endpoints.
    pub tls: Option<TlsConfig>,
    /// An `[auth]` section a file written for an earlier version still holds. The Client sends
    /// no credential (ADR-0021 clause 3): the section is read only so that it does not fail the
    /// load — whatever keys it has — and nothing in it is kept. Its presence is what
    /// [`leftover_auth_notice`](Self::leftover_auth_notice) reports, once, at startup.
    #[serde(default, rename = "auth")]
    pub leftover_auth: Option<serde::de::IgnoredAny>,
    /// Package verification (ADR-0026); absent means unsigned packages are accepted on their
    /// content hash alone.
    pub packages: Option<PackagesConfig>,
    /// A `[self_update]` section, which ADR-0018 replaced with `[packages] self_update`. Read only
    /// so that [`checked`](Self::checked) can refuse it, whatever it holds, naming the key that
    /// replaces it.
    #[serde(default, rename = "self_update")]
    pub leftover_self_update: Option<serde::de::IgnoredAny>,
    /// Where this Client's own log goes when it runs as a service (ADR-0019). Absent takes the
    /// defaults: a rotating file in the state directory, seven days kept.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// The fleet's timing policy for every Managed Process (ADR-0017): the graceful-stop budget
    /// and the apply grace. Absent takes the defaults.
    #[serde(default, rename = "supervisors")]
    pub supervisor_defaults: SupervisorsConfig,
    /// How Managed-Process package updates behave once applied (ADR-0026) — the retention of a
    /// superseded version. Absent takes the defaults: one day.
    #[serde(default)]
    pub updates: UpdatesConfig,
    /// The `[packages].verification_key` decoded once at load — the Ed25519 public key a package
    /// signature is checked against. Set from the file at load; not itself a file key.
    #[serde(skip)]
    pub package_key: Option<Vec<u8>>,
    /// The file's own text with secret values masked (see [`redact_secrets`]), kept from load so
    /// the Client's own Agent can report it as its effective configuration — the file *is* what
    /// this Client runs (a file that fails to load fails startup, so a running Client and its file
    /// never disagree). `None` when no file exists and the defaults run.
    #[serde(skip)]
    pub source: Option<String>,
    /// The path this configuration was loaded from — where an accepted Supervisor set is written
    /// back to (ADR-0017). Kept even when the file does not exist yet: the first applied offer
    /// creates it. `None` only for a configuration never loaded from a path (tests, defaults).
    #[serde(skip)]
    pub path: Option<PathBuf>,
    /// `state_dir` as the file wrote it, before [`load`](Self::load) resolved it against the
    /// working directory — what an install decides on (see
    /// [`service_state_dir`](Self::service_state_dir)).
    #[serde(skip)]
    pub state_dir_as_written: PathBuf,
    /// The bootstrap identity a `bootstrap.p12` opened to, held in memory for the enrolment and
    /// never written to disk (ADR-0029 clause 7). Presented while the Client holds no issued
    /// certificate; set by the install, never by the file.
    #[serde(skip)]
    pub bootstrap_identity: Option<BootstrapIdentity>,
    /// The largest OpAMP message the Client accepts or sends, on either transport and in either
    /// direction — the Supervisor Endpoint included. The Baseline requires the limit, recommends
    /// this default, and asks that it be configurable.
    #[serde(default = "default_max_message_size")]
    pub max_message_size_bytes: usize,
    /// The largest package or self-update artifact the Client downloads before verifying it
    /// (ADR-0026). Streaming already caps peak memory at one chunk, but disk is finite: without a
    /// ceiling a Server could answer the artifact GET with an endless body and fill the staging
    /// filesystem before the content hash is ever checked. Matches the Server's own per-package
    /// ceiling; `0` is refused at load, the same as the message limit.
    #[serde(default = "default_max_artifact_size")]
    pub max_artifact_size_bytes: u64,
    /// The `[[supervisor]]` blocks (ADR-0017): each runs one Supervisor managing one local
    /// process, appearing to the Server as its own Agent. Absent means the Client presents
    /// itself as a single Agent, as before.
    #[serde(default, rename = "supervisor")]
    pub supervisors: Vec<SupervisorBlock>,
}

/// A bootstrap certificate and its key as PEM, held in memory (ADR-0029 clause 7). Its `Debug`
/// names neither.
#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for BootstrapIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapIdentity").finish_non_exhaustive()
    }
}

/// One `[[supervisor]]` block (ADR-0017). The common keys are extracted here; everything else
/// stays in [`settings`](Self::settings) for the plugin the `type` selects, which parses it
/// strictly — serde cannot combine `flatten` with `deny_unknown_fields` (serde-rs/serde#1547),
/// so this two-stage split is what keeps a typo anywhere in the block failing loudly at startup.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "toml::Table")]
pub struct SupervisorBlock {
    /// The plugin this block selects (the TOML key `type`), e.g. `"collector"` or `"command"`.
    pub kind: String,
    /// The Supervisor's name: the Agent's `service.instance.name` and its state directory name, so
    /// it follows the instance-name grammar of ADR-0019. Must be unique across blocks.
    ///
    /// It is the operator's name for *this* Agent, never its type — that is
    /// [`service_name`](Self::service_name), which the grammar here could not spell anyway
    /// (ADR-0016): a reverse FQDN has dots, and this value is a path component on three operating
    /// systems.
    pub name: String,
    /// The Agent *type* this Supervisor presents as `service.name` — the Baseline's "reverse FQDN
    /// that uniquely identifies the Agent type" (ADR-0016). `None` falls back to the program's own
    /// file name, and a Managed Process that reports a type of its own overrides both: a
    /// Collector's `opampextension` states the `dist.name` it was built with, which is the truth
    /// this key can only approximate.
    ///
    /// Set it for a Managed Process that reports nothing — the core `otelcol` distribution, every
    /// Foreign Agent — so a Selector can aim at what this Agent *is* (ADR-0026).
    pub service_name: Option<String>,
    /// The Supervisor Endpoint's loopback port; `0` (the default) binds an ephemeral port. Pin
    /// it when the distributed configuration carries the `opampextension` pointing at it.
    pub endpoint_port: u16,
    /// Overrides the global `[supervisors] stop_timeout_secs` for this Supervisor: how long a
    /// graceful stop may take before the Managed Process is killed. `None` — the default — takes
    /// the global value.
    ///
    /// Only a kind that knows nothing about its agent may state it (ADR-0017): how long an agent
    /// needs to shut down is a property of that agent, so a wrapped kind holds the value and the
    /// key is refused in its block.
    pub stop_timeout_secs: Option<u64>,
    /// Overrides the global `[supervisors] apply_grace_secs` for this Supervisor: how long a
    /// freshly (re)started Managed Process must survive before a received configuration is
    /// acknowledged `APPLIED`; exiting within the grace reports `FAILED` (the health-gated
    /// acknowledgement ADR-0017 names). `0` acknowledges on start. `None` takes the global value,
    /// and a wrapped kind refuses the key for the reason above.
    pub apply_grace_secs: Option<u64>,
    /// Overrides the global `[updates] retain_previous_secs` for this Supervisor (ADR-0026): how
    /// long the version a successful update supersedes is kept before deletion. `None` — the
    /// default — takes the global value.
    pub retain_previous_secs: Option<u64>,
    /// Where the program sits *inside* a package that is a whole directory tree (ADR-0026), e.g.
    /// `bin/fluent-bit`. `None` — the default — is the single-file package of ADR-0026: one
    /// member, one file. Setting it is what asks for the tree to be unpacked whole.
    ///
    /// It never decides *whether* packages are taken; the written shape of `binary`/`command`
    /// still does that alone (ADR-0017).
    pub program_path: Option<PathBuf>,
    /// The plugin-specific keys, handed over verbatim for the second-stage strict parse.
    pub settings: toml::Table,
}

/// The subdirectory of a Supervisor's own directory holding its Managed Process (ADR-0017).
///
/// Called `program` and not `bin` on purpose: it holds one file for a single-file package, and a
/// Foreign Agent's whole tree — an executable with the shared objects it loads — is unpacked under
/// the same root (ADR-0026, in [`TREE_DIR`]), so no path on disk moved when that arrived. A
/// directory name is cheap; a layout migration on every host is not.
pub const PROGRAM_DIR: &str = "program";

/// The subdirectory of `program/` holding an unpacked package tree (ADR-0026), with the tree it
/// replaced kept beside it under the same name plus `.rollback`.
///
/// Two fixed names rather than a version directory and a pointer: it is the mechanism the
/// single-file swap already uses, a directory rename is atomic on every platform this Client runs
/// on, and nothing has to be reconciled after a crash halfway through an install. Which version is
/// in there is reported by the Agent, not spelled on disk.
pub const TREE_DIR: &str = "tree";

/// The subdirectory a downloaded artifact is staged in, per Supervisor.
const PACKAGES_DIR: &str = "packages";

/// Where a Supervisor's Managed Process lives — and, as the same fact, whether this Client may
/// replace it (ADR-0017).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// What the process is spawned from, and what a package is installed over.
    ///
    /// Always inside this Supervisor's own `program/` directory (ADR-0017): a Managed Process is
    /// always the fleet's. There is no `owned` flag beside this, because there is nothing for it to
    /// distinguish — every block that parses names a program this Client installs, so
    /// `AcceptsPackages` is a constant of this Client rather than a function of its configuration.
    pub path: PathBuf,
}

/// Resolves the program path of a `[[supervisor]]` block (ADR-0017 clause 21, as amended by
/// ADR-0017).
///
/// `key` is the block's own name for it (`binary`, `command`) so the error names what the operator
/// wrote. **One shape** (ADR-0017): a **bare file name**, resolving to
/// `<supervisor_dir>/program/<value>` — or `program/tree/<program_path>` for a multi-file package
/// (ADR-0026) — a directory this Client creates and owns, so it may replace what is in it. A bare
/// name cannot escape that directory, which is why nothing here has to sanitize a path.
///
/// Everything else is refused, and an **absolute path** gets its own message: it names a program on
/// the machine, so its refusal is the only notice an operator writing such a block will get and it
/// carries the whole explanation rather than a rule number.
///
/// # Errors
/// Returns an error for anything that is not a bare file name, naming the rule and the way across.
pub fn resolve_program(
    key: &str,
    value: &Path,
    program_path: Option<&Path>,
    supervisor_dir: &Path,
    name: &str,
) -> Result<Program, String> {
    // The machine's program, which this Client does not manage (ADR-0017). `has_root` rather than
    // `is_absolute` so the Windows drive-relative form — `\Program Files\otelcol\otelcol.exe`, no
    // drive letter — folds into the same message: it is a near-miss of the absolute form, and both
    // have the same answer.
    if value.is_absolute() || value.has_root() {
        return Err(format!(
            "supervisor {name:?}: `{key} = {}` names a program on the machine, and this Client \
             manages only programs it installs. A program the fleet is to manage must reach the \
             host as a package: build or repack it, upload it as a Set, and name it here with a \
             bare file name — it then lives in this Supervisor's own directory, where an update \
             is a rename this Client can make. To keep the machine's copy instead, take the block \
             out and let whatever put the file there keep it.",
            value.display()
        ));
    }
    let mut components = value.components();
    let bare = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if bare {
        // With a tree the program is one file *inside* the unpacked package (ADR-0026), and the
        // bare name above is what it always was: the consent, readable in the file.
        let path = match program_path {
            Some(inside) => supervisor_dir.join(PROGRAM_DIR).join(TREE_DIR).join(inside),
            None => supervisor_dir.join(PROGRAM_DIR).join(value),
        };
        return Ok(Program { path });
    }
    Err(format!(
        "supervisor {name:?}: `{key} = {}` is not a bare file name — no path separator and no \
         `..`. The program lives in this Supervisor's own directory and is updated from \
         Server-offered packages; name the file, not a path to it",
        value.display()
    ))
}

/// A name validated against the intersection of the systemd-unit, launchd-label, Windows
/// service-name, and directory-name grammars (ADR-0019).
///
/// It names no instance, since there is no instance flag (ADR-0019 clause 6): it governs
/// `[[supervisor]]` block names, and `build.rs` holds a second copy of the same rules for
/// `PRODUCT_NAME` — which cannot borrow this one, because a build script cannot depend on the crate
/// it builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceName(String);

impl InstanceName {
    /// The validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InstanceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Windows reserved device names: legal under the grammar below, but invalid directory names on
/// Windows — an instance must be a directory everywhere. A config-map entry file name is held to
/// the same list (`storage::check_entry_names`).
pub(crate) const WINDOWS_RESERVED: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// The only way to build an [`InstanceName`]: validated against the grammar above. `pub` because
/// callers outside this module need to construct one and there is nothing else to do it with
/// (ADR-0010 widens visibility by need).
///
/// # Errors
/// Returns an error naming the rule the value breaks.
pub fn parse_instance_name(raw: &str) -> Result<InstanceName, String> {
    if raw.is_empty() || raw.len() > 32 {
        return Err("must be 1–32 characters".to_string());
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("only lowercase letters, digits, and '-' are allowed".to_string());
    }
    if raw.starts_with('-') || raw.ends_with('-') {
        return Err("must not start or end with '-'".to_string());
    }
    if WINDOWS_RESERVED.contains(&raw) {
        return Err(format!("{raw:?} is a reserved device name on Windows"));
    }
    Ok(InstanceName(raw.to_string()))
}

impl TryFrom<toml::Table> for SupervisorBlock {
    type Error = String;

    fn try_from(mut table: toml::Table) -> Result<Self, String> {
        let kind = take_string(&mut table, "type")?
            .ok_or_else(|| "a [[supervisor]] block needs a `type`".to_string())?;
        let name = take_string(&mut table, "name")?
            .ok_or_else(|| "a [[supervisor]] block needs a `name`".to_string())?;
        parse_instance_name(&name).map_err(|e| format!("invalid supervisor name {name:?}: {e}"))?;
        // Deliberately not run through `parse_instance_name`: a type may be a reverse FQDN
        // (ADR-0016), which that grammar forbids. Only emptiness is refused — an empty
        // `service.name` would report "no type" as if it were one.
        let service_name = match take_string(&mut table, "service_name")
            .map_err(|e| format!("supervisor {name:?}: {e}"))?
        {
            Some(raw) if raw.trim().is_empty() => {
                return Err(format!(
                    "supervisor {name:?}: `service_name` must not be empty — leave it out to use \
                     the program's file name"
                ));
            }
            other => other,
        };
        let endpoint_port = match take_integer(&mut table, "endpoint_port")? {
            None => 0,
            Some(port) => u16::try_from(port)
                .map_err(|_| format!("supervisor {name:?}: endpoint_port {port} is not a port"))?,
        };
        let stop_timeout_secs = take_secs(&mut table, &name, "stop_timeout_secs")?;
        let apply_grace_secs = take_secs(&mut table, &name, "apply_grace_secs")?;
        let retain_previous_secs = take_secs(&mut table, &name, "retain_previous_secs")?;
        // Not a supervisor key (ADR-0017 clause 13), and refused by name rather than left to the
        // plugin's strict parse: a block carrying it expects a Client that takes it, and what
        // answers it is not another key but a different place entirely.
        if table.contains_key("attributes") {
            return Err(format!(
                "supervisor {name:?}: `[supervisor.attributes]` is no longer a supervisor key — a \
                 Server label tags this Agent from the fleet, keyed by its \
                 `instance_uid` and matched by the same Selectors; the Client-wide `[attributes]` \
                 still describe the host. Remove the table"
            ));
        }
        let program_path = match take_string(&mut table, "program_path")
            .map_err(|e| format!("supervisor {name:?}: {e}"))?
        {
            None => None,
            Some(raw) => Some(
                validate_program_path(&raw)
                    .map_err(|e| format!("supervisor {name:?}: `program_path = {raw:?}` {e}"))?,
            ),
        };
        // `package = "name"` would choose the artifact on the host, a decision that is the Server's
        // Selector's (ADR-0026). Refuse it loudly rather than ignore a key an operator believes in.
        if table.contains_key("package") {
            return Err(format!(
                "supervisor {name:?}: `package` is no longer a supervisor key — the Server \
                 decides which artifact this Agent receives, through the package's Selector \
                 (PUT /api/v1/packages/<name>/selector)"
            ));
        }
        // And `accepts_packages = true` would say *whether*, while the program's path says *where*
        // — two keys for one truth. ADR-0017 leaves one shape, so every Supervisor accepts packages
        // and the key would only be a way to disagree with a constant.
        if table.contains_key("accepts_packages") {
            return Err(format!(
                "supervisor {name:?}: `accepts_packages` is no longer a supervisor key — a \
                 program is named by a bare file name, so it lives in this Supervisor's own \
                 directory and is updated from Server-offered packages; there is no longer a \
                 second shape for the key to distinguish"
            ));
        }
        Ok(SupervisorBlock {
            kind,
            name,
            service_name,
            endpoint_port,
            stop_timeout_secs,
            apply_grace_secs,
            retain_previous_secs,
            program_path,
            settings: table,
        })
    }
}

/// Checks a `program_path` (ADR-0026): a relative path inside the package, and nothing that could
/// reach outside it.
///
/// The same three refusals the archive sanitizer makes, made here instead — at startup, where the
/// operator is still looking at the file, rather than at rollout time on every matched host.
///
/// # Errors
/// Returns an error naming which rule the value breaks.
fn validate_program_path(raw: &str) -> Result<PathBuf, String> {
    use std::path::Component;
    let path = Path::new(raw);
    if raw.trim().is_empty() {
        return Err("names nothing".to_string());
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => return Err("must not contain `.`".to_string()),
            Component::ParentDir => return Err("must not contain `..`".to_string()),
            Component::RootDir | Component::Prefix(_) => {
                return Err(
                    "must be relative — it names a path *inside* the package, not on the host"
                        .to_string(),
                )
            }
        }
    }
    Ok(path.to_path_buf())
}

fn take_string(table: &mut toml::Table, key: &str) -> Result<Option<String>, String> {
    match table.remove(key) {
        None => Ok(None),
        Some(toml::Value::String(s)) => Ok(Some(s)),
        Some(other) => Err(format!(
            "`{key}` must be a string, not {}",
            other.type_str()
        )),
    }
}

/// An optional duration in seconds, which a negative value cannot be.
fn take_secs(table: &mut toml::Table, name: &str, key: &str) -> Result<Option<u64>, String> {
    take_integer(table, key)?
        .map(|secs| {
            u64::try_from(secs)
                .map_err(|_| format!("supervisor {name:?}: {key} must not be negative"))
        })
        .transpose()
}

fn take_integer(table: &mut toml::Table, key: &str) -> Result<Option<i64>, String> {
    match table.remove(key) {
        None => Ok(None),
        Some(toml::Value::Integer(i)) => Ok(Some(i)),
        Some(other) => Err(format!(
            "`{key}` must be an integer, not {}",
            other.type_str()
        )),
    }
}

/// Keys whose values are secrets: `[packages]`'s `archive_key`, and the `bearer_token` and
/// `password` a leftover `[auth]` section may still hold — the Client ignores the section
/// (ADR-0021 clause 3), but the file's text is reported as it stands, so its values stay masked.
/// Paths and public keys are not on the list — a path locates a secret, it is not one, and the
/// `verification_key` is the *public* half of the signing pair.
const SECRET_KEYS: &[&str] = &["bearer_token", "password", "archive_key"];

/// The file's text with every secret value replaced by `***`, for reporting it off the host —
/// the Server persists effective configurations to disk, so a credential must never be in one.
///
/// Text-based on purpose: parsing and re-serialising would drop the operator's comments and
/// ordering, which are half of what a configuration file says. A line assigning a secret key
/// keeps its key with a masked value; any other non-comment line merely *mentioning* a secret
/// key (an inline table, some spelling this scan does not know) is masked whole — over-redaction
/// is the cheap failure here, a leaked credential the expensive one.
pub fn redact_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        let assigned_key = SECRET_KEYS.iter().find(|key| {
            trimmed
                .split_once('=')
                .is_some_and(|(lhs, _)| lhs.trim() == **key)
        });
        if trimmed.starts_with('#') || trimmed.is_empty() {
            out.push_str(line);
        } else if let Some(key) = assigned_key {
            let indent = &line[..line.len() - trimmed.len()];
            out.push_str(indent);
            out.push_str(key);
            out.push_str(" = \"***\"");
        } else if SECRET_KEYS.iter().any(|key| line.contains(key)) {
            out.push_str("# (line redacted: it mentions a credential key)");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !text.ends_with('\n') {
        out.pop();
    }
    out
}

/// The `[packages]` block (ADR-0026): how downloaded package artifacts are verified, and whether
/// this Client takes its own (ADR-0018). Where they come from is not configurable: always this
/// Client's own Server origin (ADR-0033).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesConfig {
    /// Consent for the Server to replace *this Client's* binary (ADR-0018). **Absent means
    /// consent**: a Client the fleet cannot update has to be updated by hand on every host, which
    /// is the state fleet management exists to end. `false` withdraws it; the Supervisors' Agents
    /// still take their packages.
    ///
    /// The consent is narrowed to one package, the Client's own Agent type, and that name is not
    /// configurable: a package with an empty Selector reaches every Agent that accepts packages
    /// (ADR-0026), so without the name the first fleet-wide Collector artifact would be installed
    /// over the Client. Whether the consent takes effect is decided by `verification_key`.
    #[serde(default = "default_self_update")]
    pub self_update: bool,
    /// Hex-encoded Ed25519 public key. Every offered package MUST carry a valid signature against
    /// it; without it this Client takes no packages at all, its own self-update included
    /// (ADR-0026, ADR-0018).
    pub verification_key: Option<String>,
    /// `allowed_sources`, which ADR-0033 removed: a package is downloaded only from this Client's
    /// own Server origin. Read only so that [`ClientConfig::checked`] can refuse it by name — a
    /// list an operator believes is in force, and is not, is worse than a failed start.
    #[serde(default, rename = "allowed_sources")]
    pub leftover_allowed_sources: Option<serde::de::IgnoredAny>,
    /// The key that opens an encrypted `.7z` package artifact (ADR-0026). Unset means artifacts are
    /// expected unencrypted; an encrypted one then fails to install, naming this key.
    ///
    /// One secret for the fleet — a single archive serves every Agent.
    pub archive_key: Option<String>,
}

impl Default for PackagesConfig {
    fn default() -> Self {
        PackagesConfig {
            self_update: default_self_update(),
            verification_key: None,
            leftover_allowed_sources: None,
            archive_key: None,
        }
    }
}

fn default_self_update() -> bool {
    true
}

/// The file name ADR-0019 clause 29 looks for beside a missing `supervisor.toml`, and the one reason
/// a missing file is an error rather than the defaults.
pub const LEGACY_CONFIG_FILE_NAME: &str = "client.toml";

/// The `[logging]` section (ADR-0019): this Client's own log, on disk, while it runs as a service.
///
/// It exists because the Windows SCM discards a service's stderr, so a Client installed there had
/// no readable log at all — and because the OTLP own-logs bridge (ADR-0016) needs a Server that is
/// already reachable, which is precisely what a startup failure is not. In the foreground nothing
/// is written: somebody is reading stderr there.
///
/// It is the machine's, never the Server's. A Server able to redirect or silence a Client's own log
/// could hide its own effects, so nothing here arrives over the wire.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Write the file at all. `false` is for an operator whose platform already collects stderr —
    /// systemd and launchd do — and who does not want the copy.
    #[serde(default = "default_logging_enabled")]
    pub enabled: bool,
    /// Where the file goes. Absent puts it in the instance's state directory, which survives an
    /// update and which `uninstall` deliberately does not delete (ADR-0019) — the lifetime a log
    /// wants, since one that vanished with a failed install would be missing exactly when needed.
    pub dir: Option<PathBuf>,
    /// How many daily files to keep. The bound is not optional: `0` is refused at load rather than
    /// read as "keep everything", because unbounded is the setting that fills a disk on a host
    /// nobody is watching.
    #[serde(default = "default_log_keep_days")]
    pub keep: usize,
}

fn default_logging_enabled() -> bool {
    true
}

fn default_log_keep_days() -> usize {
    7
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            enabled: default_logging_enabled(),
            dir: None,
            keep: default_log_keep_days(),
        }
    }
}

/// The `[supervisors]` section (ADR-0017): the fleet's timing policy for every Managed Process.
///
/// Global here, because these are decisions about *this deployment* — how long an operator is
/// willing to wait for a stop, how long a restart must hold before it counts as applied — and not
/// about one host. A wrapped kind overrides them where its agent's own behaviour demands it, and
/// nothing below that states them: a block of an unwrapped kind may, because there no kind exists
/// to hold the value.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorsConfig {
    /// How long a graceful stop may take before the Managed Process is killed.
    #[serde(default = "default_stop_timeout_secs")]
    pub stop_timeout_secs: u64,
    /// How long a freshly (re)started Managed Process must survive before a received
    /// configuration is acknowledged `APPLIED`; `0` acknowledges on start.
    #[serde(default = "default_apply_grace_secs")]
    pub apply_grace_secs: u64,
    /// The environment variables a Server-delivered block may set, each name exact or ending in
    /// `*` as a prefix (ADR-0017 clause 38). Empty — the default — lets a delivered block keep only
    /// the environment its running block already has.
    #[serde(default)]
    pub delivered_env: Vec<String>,
    /// Whether a Server-delivered block may state `args` and `version_args` its running block does
    /// not already have (ADR-0017 clause 38).
    #[serde(default)]
    pub delivered_args: bool,
    /// The Supervisors whose Agents neither declare nor act on remote configuration (ADR-0017),
    /// by name: each runs only on what the operator placed in its `config/` directory, and a
    /// delivered block brings it no `args`, `version_args` or `env`. Read from this file only —
    /// the Supervisor-set apply never writes this section.
    #[serde(default)]
    pub remote_config_disabled: Vec<String>,
    /// Whether the Server manages the set of `[[supervisor]]` blocks through the Client's own
    /// Agent (ADR-0017 clauses 27 and 41). `false` builds that Agent without remote configuration,
    /// and the blocks in this file are the operator's alone. Read from this file only, like the
    /// rest of the section.
    #[serde(default = "default_server_manages_set")]
    pub server_manages_set: bool,
}

fn default_server_manages_set() -> bool {
    true
}

impl Default for SupervisorsConfig {
    fn default() -> Self {
        SupervisorsConfig {
            stop_timeout_secs: default_stop_timeout_secs(),
            apply_grace_secs: default_apply_grace_secs(),
            delivered_env: Vec::new(),
            delivered_args: false,
            remote_config_disabled: Vec::new(),
            server_manages_set: default_server_manages_set(),
        }
    }
}

/// The `[updates]` section (ADR-0026): how a Managed Process's package updates behave once applied.
/// Global here, overridable per `[[supervisor]]` block, the shape `apply_grace_secs` already has.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatesConfig {
    /// How long the version a successful update supersedes is kept before it is deleted, so an
    /// operator has a fallback window (ADR-0026). `0` deletes it on success, with no
    /// fallback window. A per-Supervisor `retain_previous_secs` overrides this for one block.
    #[serde(default = "default_retain_previous_secs")]
    pub retain_previous_secs: u64,
}

fn default_retain_previous_secs() -> u64 {
    24 * 60 * 60 // one day
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        UpdatesConfig {
            retain_previous_secs: default_retain_previous_secs(),
        }
    }
}

/// The `[gateway]` section (ADR-0015): the Client stands at a network boundary, accepts OpAMP from
/// other Clients, and folds them onto a small pool of upstream connections. Present arms the mode;
/// it composes with `[[supervisor]]` blocks on the same host, since the two modes are orthogonal
/// (ADR-0015).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Where the downstream OpAMP endpoint binds. No default: a Gateway that binds nothing is a
    /// configuration error, and loopback is the Supervisor Endpoint's job.
    pub listen: SocketAddr,
    /// The **cap** on upstream connections, not the count. The pool grows to it as Agents appear
    /// and never beyond, so a Gateway in front of three Agents holds three connections.
    #[serde(default = "default_upstream_connections")]
    pub upstream_connections: usize,
    /// The most distinct Agents a single downstream connection may carry. It bounds the routing
    /// state one peer can make this Gateway hold: a misbehaving or hostile downstream Client
    /// streaming reports under endless fabricated `instance_uid`s would otherwise grow the registry
    /// and pool maps without limit. Generous for a nested Gateway carrying a real sub-fleet; a
    /// report for a *new* Agent past the cap is dropped, the ones already carried keep working. `0`
    /// is refused at load.
    #[serde(default = "default_max_carried_agents")]
    pub max_carried_agents: usize,
    /// The most bytes of package artifacts this Gateway holds for the Agents behind it
    /// (ADR-0026 clause 47), under `<state_dir>/gateway-packages`. An artifact larger than this, or
    /// than `max_artifact_size_bytes`, is not cached and not delivered through the Gateway. `0` is
    /// refused at load.
    #[serde(default = "default_package_cache_bytes")]
    pub package_cache_bytes: u64,
    /// TLS for the downstream hop, required (ADR-0015). Mutual TLS is per hop: what this verifies
    /// is the Agents connecting *here*, and the identity presented *upstream* is the Client's own.
    /// An `Option` only so its absence can be named at load.
    pub tls: Option<GatewayTlsConfig>,
}

/// The downstream hop's TLS material (ADR-0015). Separate from the top-level `[tls]`, which is
/// about reaching the Server: this is about being reached.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTlsConfig {
    /// PEM certificate chain this Gateway presents to the Agents that connect to it.
    pub cert_file: PathBuf,
    /// PEM private key for it.
    pub key_file: PathBuf,
    /// PEM bundle a downstream Agent's client certificate must chain to, required (ADR-0015): a
    /// peer without one fails the handshake. An `Option` only so its absence can be named.
    pub client_ca_file: Option<PathBuf>,
    /// The public certificate of the Server's `[enrolment] bootstrap_ca_file`, optional (ADR-0039
    /// clause 1): a peer whose certificate chains to it alone passes the handshake as an enrolling
    /// peer, which may relay one plain-HTTP enrolment request and nothing else.
    #[serde(default)]
    pub bootstrap_ca_file: Option<PathBuf>,
}

impl GatewayConfig {
    /// Loud validation (ADR-0010): a pool of zero would carry nothing, and the pool is a WebSocket
    /// pool — a polling upstream cannot carry the Server's pushes to the Agents behind it.
    fn check(&self, endpoint: &str) -> Result<(), String> {
        if self.upstream_connections == 0 {
            return Err("[gateway] upstream_connections must be at least 1".to_string());
        }
        if self.max_carried_agents == 0 {
            return Err(
                "[gateway] max_carried_agents must be at least 1 — it bounds routing state, not a \
                 switch"
                    .to_string(),
            );
        }
        if self.package_cache_bytes == 0 {
            return Err(
                "[gateway] package_cache_bytes must be greater than zero — it bounds the package \
                 cache, not a switch"
                    .to_string(),
            );
        }
        if !endpoint.starts_with("ws://") && !endpoint.starts_with("wss://") {
            return Err(format!(
                "[gateway] needs a WebSocket endpoint upstream, and this Client's is {endpoint} — \
                 a polling connection cannot carry the Server's pushes to the Agents behind a \
                 Gateway"
            ));
        }
        // A Gateway admits Agents, so the downstream hop is mutual TLS 1.3 and nothing less — on the
        // loopback too (ADR-0015).
        match &self.tls {
            None => Err(
                "[gateway.tls] is required — a Gateway admits Agents over mutual TLS only; set \
                 cert_file, key_file and client_ca_file"
                    .to_string(),
            ),
            Some(tls) if tls.client_ca_file.is_none() => Err(
                "[gateway.tls] client_ca_file is required — every downstream Agent presents a \
                 certificate that chains to it"
                    .to_string(),
            ),
            Some(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM CA bundle that *replaces* the built-in webpki roots — the self-signed-deployment case.
    /// Optional, so a `[tls]` section can carry a client identity alone and keep the public roots.
    pub ca_file: Option<PathBuf>,
    /// PEM client certificate chain this Client presents (ADR-0021), for a fleet whose Server
    /// demands mutual TLS. Together with [`key_file`](Self::key_file), and useless without it.
    ///
    /// This is the operator-provisioned identity, including the **bootstrap certificate** a host
    /// enrols with. An identity the Server issued outranks it: the Client stores that one in its
    /// state directory and prefers it, exactly as persisted connection settings outrank the
    /// endpoint written here (ADR-0014). Deleting the stored pair falls back to this one.
    pub cert_file: Option<PathBuf>,
    /// PEM private key for [`cert_file`](Self::cert_file). Never leaves the host.
    pub key_file: Option<PathBuf>,
}

impl TlsConfig {
    /// Loud validation (ADR-0010): half an identity is a configuration error, not a fallback to
    /// none — a Server demanding mutual TLS would refuse the connection with no hint why.
    fn check(&self) -> Result<(), String> {
        match (&self.cert_file, &self.key_file) {
            (Some(_), None) => Err("[tls] cert_file needs key_file beside it".to_string()),
            (None, Some(_)) => Err("[tls] key_file needs cert_file beside it".to_string()),
            _ => Ok(()),
        }
    }
}

/// The transport the endpoint's scheme selects (ADR-0013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    WebSocket,
    Http,
}

fn default_endpoint() -> String {
    // The Baseline's default port and path, over TLS: the Agent plane serves nothing else
    // (ADR-0013).
    "wss://127.0.0.1:4320/v1/opamp".to_string()
}

fn default_name() -> String {
    // A *display* name, and deliberately not the program's own (ADR-0019): this key is the one
    // place an operator says which Client this is, and a default that reads exactly like the Agent
    // type would put the same word in both columns of the fleet view — the collapse ADR-0016 ended.
    // Spelled as a person would write it, spaces and capitals included: nothing resolves a path or
    // a service from it, the grammar of ADR-0019 governs the `--instance` and the `[[supervisor]]`
    // block names instead, and the questionnaire asks for this one first (ADR-0019) so that a fleet
    // is told apart by names somebody chose.
    "Supervisor Agent".to_string()
}

fn default_poll_interval_secs() -> u64 {
    30
}

fn default_heartbeat_interval_secs() -> u64 {
    // The Baseline: "The interval between the heartbeats SHOULD be 30 seconds".
    30
}

/// The pool cap when none is configured — the OpAMP Gateway Extension's default (ADR-0015). It is
/// a ceiling, not a cost: connections are opened as Agents appear.
fn default_upstream_connections() -> usize {
    10
}

/// Generous enough for a nested Gateway carrying a real sub-fleet, small enough that a single
/// hostile connection cannot grow the routing maps without bound.
fn default_max_carried_agents() -> usize {
    10_000
}

/// Ten gibibytes: room for a handful of releases of a large Agent across a few Platforms, which is
/// what one rollout behind a Gateway asks for (ADR-0026 clause 47).
fn default_package_cache_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("client-state")
}

fn default_max_message_size() -> usize {
    opamp::frame::DEFAULT_MAX_MESSAGE_SIZE
}

/// One gibibyte — the Server's own `DEFAULT_MAX_PACKAGE_SIZE`. A Server that will not store a
/// larger artifact never offers one, so the two ends agree by default.
fn default_max_artifact_size() -> u64 {
    1 << 30
}

fn default_stop_timeout_secs() -> u64 {
    10
}

fn default_apply_grace_secs() -> u64 {
    3
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            supervisor_defaults: SupervisorsConfig::default(),
            endpoint: default_endpoint(),
            name: default_name(),
            logging: LoggingConfig::default(),
            updates: UpdatesConfig::default(),
            service_namespace: None,
            poll_interval_secs: default_poll_interval_secs(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            state_dir: default_state_dir(),
            supervisor_dir: None,
            attributes: BTreeMap::new(),
            gateway: None,
            tls: None,
            leftover_auth: None,
            packages: None,
            leftover_self_update: None,
            package_key: None,
            source: None,
            path: None,
            state_dir_as_written: default_state_dir(),
            bootstrap_identity: None,
            max_message_size_bytes: default_max_message_size(),
            max_artifact_size_bytes: default_max_artifact_size(),
            supervisors: Vec::new(),
        }
    }
}

impl ClientConfig {
    /// The package this Client consents to be replaced by — its own Agent type, the one name that
    /// can legitimately carry it — or `None` when `[packages] self_update = false` withdraws the
    /// consent (ADR-0018). An absent key or section is consent.
    #[must_use]
    pub fn self_update_package(&self) -> Option<&'static str> {
        self.packages
            .as_ref()
            .is_none_or(|p| p.self_update)
            .then_some(crate::supervisor::agent::CLIENT_AGENT_TYPE)
    }

    /// Checks a configuration as it was read from `path`: every rule a file must meet before
    /// anything starts, so a bad value fails startup rather than the first use of it. `path` only
    /// names the file in the error.
    ///
    /// # Errors
    /// Returns the first rule the configuration breaks, naming the file.
    pub fn checked(self, path: &Path) -> Result<Self, String> {
        let mut config = self;
        config.check_supervisor_names()?;
        // A name no block can ever carry would switch nothing off, silently (ADR-0017 clause 49).
        for name in &config.supervisor_defaults.remote_config_disabled {
            parse_instance_name(name).map_err(|e| {
                format!(
                    "{}: [supervisors] remote_config_disabled: {name:?} is not a supervisor \
                     name: {e}",
                    path.display()
                )
            })?;
        }
        // Plaintext is for the loopback alone, and refused rather than warned about (ADR-0013).
        config
            .transport()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some(tls) = &config.tls {
            tls.check()
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        // Ignoring the old section would turn a written `enabled = false` into consent the moment
        // a key is set; it is refused, whatever it holds, naming its replacement (ADR-0018).
        if config.leftover_self_update.is_some() {
            return Err(format!(
                "{}: [self_update] is no longer read — the consent is `self_update` in [packages] \
                 (true by default, `self_update = false` withdraws it), and the package is always \
                 this Client's own Agent type. Replace the section with that key.",
                path.display()
            ));
        }
        if config
            .packages
            .as_ref()
            .is_some_and(|p| p.leftover_allowed_sources.is_some())
        {
            return Err(format!(
                "{}: [packages] allowed_sources is removed — this Client downloads a package only \
                 from its own Server's origin, and every artifact is uploaded to the Server \
                 (ADR-0033). Remove the key.",
                path.display()
            ));
        }
        if let Some(gateway) = &config.gateway {
            gateway
                .check(&config.endpoint)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        // Decode the package verification key once — a malformed key must fail startup, not the
        // first package offer.
        if let Some(key_hex) = config
            .packages
            .as_ref()
            .and_then(|p| p.verification_key.as_ref())
        {
            let key = hex::decode(key_hex).map_err(|e| {
                format!(
                    "{}: [packages].verification_key is not valid hex: {e}",
                    path.display()
                )
            })?;
            config.package_key = Some(key);
        }
        // A limit of zero would refuse every message, and the Baseline knows no "unlimited": the
        // limit is mandatory, so a value that cannot carry a message fails startup.
        if config.max_message_size_bytes == 0 {
            return Err(format!(
                "{}: max_message_size_bytes must be greater than zero",
                path.display()
            ));
        }
        // A ceiling of zero would refuse every artifact; like the message limit it is a bound, not
        // a switch, so a value that cannot carry a download fails startup rather than silently
        // rejecting every package.
        if config.max_artifact_size_bytes == 0 {
            return Err(format!(
                "{}: max_artifact_size_bytes must be greater than zero",
                path.display()
            ));
        }
        // The retention bound is not optional (ADR-0019). Elsewhere a zero often means "no limit";
        // here that is the one setting that fills a disk on a host nobody is watching, so it fails
        // startup instead of being reachable by typing a digit.
        if config.logging.enabled && config.logging.keep == 0 {
            return Err(format!(
                "{}: [logging] keep must be at least 1 — it is a retention bound, not a switch; \
                 set enabled = false to write no log at all",
                path.display()
            ));
        }
        Ok(config)
    }

    /// The Ed25519 public key package signatures are verified against (ADR-0026), or `None`.
    pub fn package_key(&self) -> Option<&[u8]> {
        self.package_key.as_deref()
    }

    /// The CA bundle that replaces the built-in roots, when one is configured (ADR-0013).
    pub fn ca_file(&self) -> Option<&Path> {
        self.tls.as_ref()?.ca_file.as_deref()
    }

    /// The root the per-Supervisor directories sit under (ADR-0017) — `supervisor_dir` when the
    /// operator set one, and `<state_dir>/supervisors` when they did not.
    #[must_use]
    pub fn supervisors_root(&self) -> PathBuf {
        self.supervisor_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("supervisors"))
    }

    /// One Supervisor's own directory: its state, its `program/`, and its package staging, under
    /// a single root the operator can place (ADR-0017).
    #[must_use]
    pub fn supervisor_dir(&self, name: &str) -> PathBuf {
        self.supervisors_root().join(name)
    }

    /// Where the artifact offered to an Agent is staged, by the name of the Supervisor behind it —
    /// `None` for the Client's own Agent. Inside that Supervisor's own directory, so that the
    /// install which follows is a rename within one filesystem instead of a copy across two
    /// (ADR-0017); the Client's own Agent stages under `state_dir`, beside the versions a
    /// self-update writes (ADR-0018). Keyed by name rather than by Engine index because the Agent
    /// set can change at runtime (ADR-0017), which is exactly when an index stops naming a block.
    #[must_use]
    pub fn staging_dir_for(&self, supervisor: Option<&str>) -> PathBuf {
        match supervisor {
            Some(name) => self.supervisor_dir(name).join(PACKAGES_DIR),
            None => self.state_dir.join(PACKAGES_DIR),
        }
    }

    /// Whether the operator switched remote configuration off for the Supervisor `name`
    /// (ADR-0017).
    #[must_use]
    pub fn remote_config_disabled(&self, name: &str) -> bool {
        self.supervisor_defaults
            .remote_config_disabled
            .iter()
            .any(|listed| listed == name)
    }

    /// Whether the Server manages this Client's Supervisor set (ADR-0017 clause 41).
    #[must_use]
    pub fn server_manages_set(&self) -> bool {
        self.supervisor_defaults.server_manages_set
    }

    /// Supervisor names key state directories and Agent identities — a duplicate would silently
    /// merge two Supervisors into one.
    fn check_supervisor_names(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for block in &self.supervisors {
            if !seen.insert(block.name.as_str()) {
                return Err(format!("duplicate supervisor name {:?}", block.name));
            }
        }
        Ok(())
    }

    /// The operator-defined attributes one Agent reports (ADR-0023): the machine-level table,
    /// with a Supervisor's own entries merged over it per key.
    pub fn agent_attributes(&self, block: Option<&SupervisorBlock>) -> BTreeMap<String, String> {
        // The block half is gone (ADR-0017): tagging one Agent among several is a Server label's
        // job, which does it from the fleet and takes effect at once. The parameter stays because
        // the two call sites still differ in nothing else, and a future per-block statement would
        // land here.
        let _ = block;
        self.attributes.clone()
    }

    /// The one startup notice a leftover `[auth]` section earns (ADR-0021 clause 3), or `None`
    /// when the file has none. The section is ignored and nothing from it is sent; it is not a
    /// reason to refuse the file, since a Client the Server updated must keep connecting.
    #[must_use]
    pub fn leftover_auth_notice(&self) -> Option<&'static str> {
        self.leftover_auth.is_some().then_some(
            "[auth] is ignored: the Server admits this Client by its client certificate alone, \
             and nothing from the section is sent — it can be deleted from the file",
        )
    }

    /// The transport the endpoint names, held to the specification's rule: `wss://` or `https://`,
    /// and `ws://` or `http://` only to `127.0.0.1` or `::1` (ADR-0013).
    pub fn transport(&self) -> Result<TransportKind, String> {
        opamp::endpoint::check_url(&self.endpoint).map_err(|e| format!("endpoint {e}"))?;
        match self.endpoint.split("://").next() {
            Some("ws") | Some("wss") => Ok(TransportKind::WebSocket),
            _ => Ok(TransportKind::Http),
        }
    }
}

#[cfg(test)]
mod tests {

    /// Every directory this Client derives is absolute, however the operator wrote it.
    ///
    /// A Managed Process starts in its own directory (ADR-0017), so a relative path handed to it is
    /// resolved against a directory the Client has left — and `state_dir` defaults to the relative
    /// `client-state`, which would make the ordinary configuration the broken one: the program
    /// would be looked for beneath itself, and a Collector that did start could not open the
    /// configuration written for it.
    #[test]
    fn a_relative_state_dir_yields_absolute_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "state_dir = \"client-state\"\n").expect("write");

        let config = ClientConfig::load(&path).expect("load");
        assert!(
            config.state_dir.is_absolute(),
            "state_dir stayed relative: {}",
            config.state_dir.display()
        );
        for derived in [
            config.supervisors_root(),
            config.supervisor_dir("otelcol"),
            config.staging_dir_for(Some("otelcol")),
            config.staging_dir_for(None),
        ] {
            assert!(
                derived.is_absolute(),
                "a derived directory stayed relative: {}",
                derived.display()
            );
        }

        // An explicit supervisor_dir follows the same rule, and an absolute one is left alone.
        std::fs::write(
            &path,
            "state_dir = \"client-state\"\nsupervisor_dir = \"supervisors\"\n",
        )
        .expect("write");
        assert!(ClientConfig::load(&path)
            .expect("load")
            .supervisors_root()
            .is_absolute());
        // An already-absolute path is handed through untouched. What *is* absolute is the
        // platform's answer, not this test's: on Windows `/var/lib/fleet` has no drive and is
        // root-relative, so it would be joined onto the current one — correctly. The fixture is
        // therefore a path this host calls absolute, written as a TOML **literal** string so a
        // Windows backslash needs no escaping.
        let already = dir.path().join("state");
        assert!(already.is_absolute(), "the fixture must be absolute here");
        std::fs::write(&path, format!("state_dir = '{}'\n", already.display())).expect("write");
        assert_eq!(
            ClientConfig::load(&path).expect("load").state_dir,
            already,
            "an absolute path is handed through untouched"
        );
    }
    use super::*;

    #[test]
    fn defaults_select_websocket_on_port_4320() {
        let cfg = ClientConfig::default();
        assert_eq!(
            cfg.transport().expect("transport"),
            TransportKind::WebSocket
        );
        assert!(cfg.endpoint.contains(":4320/v1/opamp"));
        assert_eq!(cfg.poll_interval_secs, 30);
        // The Baseline's heartbeat default; 0 is the documented way to disable.
        assert_eq!(cfg.heartbeat_interval_secs, 30);
        let disabled: ClientConfig = toml::from_str("heartbeat_interval_secs = 0").expect("parse");
        assert_eq!(disabled.heartbeat_interval_secs, 0);
    }

    /// The Baseline asks for `service.namespace` "if it is used in the environment where the Agent
    /// runs" — so the file is the only thing that can know, and silence means the deployment does
    /// not use one. It must be a top-level key rather than an `[attributes]` entry, because it
    /// identifies the Agent where those merely tag it.
    #[test]
    fn the_service_namespace_is_a_top_level_key_and_absent_by_default() {
        assert!(ClientConfig::default().service_namespace.is_none());
        let untouched: ClientConfig =
            toml::from_str("endpoint = \"wss://h/v1/opamp\"").expect("parse");
        assert!(untouched.service_namespace.is_none());

        let configured: ClientConfig =
            toml::from_str("service_namespace = \"telemetry\"\n").expect("parse");
        assert_eq!(configured.service_namespace.as_deref(), Some("telemetry"));

        assert!(
            toml::from_str::<ClientConfig>("service_namesapce = \"telemetry\"\n").is_err(),
            "a typo fails startup rather than silently reporting no namespace"
        );
    }

    /// ADR-0019. The log is on by default with a bound that cannot be removed, and `[logging]` is
    /// the machine's — so a typo in it fails startup rather than quietly disabling the one thing
    /// that would have explained the next failure.
    /// Verifies: ADR-0019
    #[test]
    fn the_log_file_is_on_by_default_and_its_retention_is_not_optional() {
        let defaults = ClientConfig::default().logging;
        assert!(defaults.enabled);
        assert_eq!(defaults.keep, 7);
        assert!(defaults.dir.is_none(), "the state directory decides");

        let configured: ClientConfig =
            toml::from_str("[logging]\nkeep = 3\ndir = \"/var/log/opamp\"\n").expect("parse");
        assert_eq!(configured.logging.keep, 3);
        assert_eq!(
            configured.logging.dir.expect("dir"),
            PathBuf::from("/var/log/opamp")
        );

        let off: ClientConfig = toml::from_str("[logging]\nenabled = false\n").expect("parse");
        assert!(!off.logging.enabled);

        assert!(
            toml::from_str::<ClientConfig>("[logging]\nkep = 3\n").is_err(),
            "a typo fails startup rather than silently taking the default"
        );

        // `keep = 0` is the one setting that fills a disk on a host nobody watches, so it is not
        // reachable: it fails startup and the message points at the switch that does mean "off".
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "[logging]\nkeep = 0\n").expect("write");
        let err = ClientConfig::load(&path).expect_err("zero retention must fail startup");
        assert!(err.contains("keep"), "{err}");
        assert!(
            err.contains("enabled = false"),
            "it names the way out: {err}"
        );

        // ...but a zero is irrelevant when no file is written at all.
        std::fs::write(&path, "[logging]\nenabled = false\nkeep = 0\n").expect("write");
        assert!(ClientConfig::load(&path).is_ok());
    }

    /// ADR-0019: the rename must not turn a managed host into a silent one. A missing
    /// configuration is ordinarily the defaults and a warning; a missing one with the *old* name
    /// beside it is an upgraded host that would otherwise come up on the development endpoint and
    /// manage nothing, which is the failure nobody sees.
    /// Verifies: ADR-0019
    #[test]
    fn the_configurations_old_name_beside_the_new_one_is_refused_rather_than_defaulted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = dir.path().join(crate::config_init::FILE_NAME);

        // Neither file: an ordinary fresh host, and the defaults are the answer (ADR-0019).
        assert!(ClientConfig::load(&expected).is_ok());

        std::fs::write(
            dir.path().join(LEGACY_CONFIG_FILE_NAME),
            "endpoint = \"wss://h/v1/opamp\"\n",
        )
        .expect("write the file this host was configured with");
        let error = ClientConfig::load(&expected).expect_err("an upgraded host must not go quiet");
        assert!(
            error.contains(LEGACY_CONFIG_FILE_NAME)
                && error.contains(crate::config_init::FILE_NAME),
            "the refusal names both files: {error}"
        );

        // And once renamed, it is an ordinary configuration again.
        std::fs::rename(dir.path().join(LEGACY_CONFIG_FILE_NAME), &expected).expect("rename");
        assert_eq!(
            ClientConfig::load(&expected).expect("loads").endpoint,
            "wss://h/v1/opamp"
        );
    }

    /// ADR-0018: the consent stands unless `[packages] self_update = false` withdraws it, and it
    /// is narrowed to the Client's own Agent type, which no key can change.
    /// Verifies: ADR-0018
    #[test]
    fn self_update_consent_stands_by_default_and_is_narrowed_to_the_agent_type() {
        let default = ClientConfig::default();
        assert_eq!(
            default.self_update_package(),
            Some(crate::supervisor::agent::CLIENT_AGENT_TYPE),
            "a Client with nothing configured consents under its own Agent type"
        );

        // A file that never mentions it is the common case, and it is consent — with or without
        // a [packages] section.
        for text in [
            "endpoint = \"wss://h/v1/opamp\"",
            "[packages]\nverification_key = \"00\"\n",
        ] {
            let untouched: ClientConfig = toml::from_str(text).expect("parse");
            assert_eq!(
                untouched.self_update_package(),
                Some("supervisor"),
                "{text}"
            );
        }

        let explicit: ClientConfig =
            toml::from_str("[packages]\nself_update = true\n").expect("parse");
        assert_eq!(explicit.self_update_package(), Some("supervisor"));

        let withdrawn: ClientConfig =
            toml::from_str("[packages]\nself_update = false\n").expect("parse");
        assert_eq!(withdrawn.self_update_package(), None);

        // There is no key that names another package.
        assert!(
            toml::from_str::<ClientConfig>("[packages]\nself_update_package = \"x\"\n").is_err()
        );
    }

    /// A `[self_update]` section fails the load whatever it holds, naming the key that replaced
    /// it: ignored, a written `enabled = false` would become consent once a key is set.
    /// Verifies: ADR-0018
    #[test]
    fn a_self_update_section_fails_the_load_naming_the_packages_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        for section in [
            "[self_update]\n",
            "[self_update]\nenabled = false\n",
            "[self_update]\npackage = \"supervisor\"\n",
        ] {
            std::fs::write(&path, section).expect("write");
            let err = ClientConfig::load(&path).expect_err(section);
            assert!(err.contains("[self_update] is no longer read"), "{err}");
            assert!(err.contains("`self_update` in [packages]"), "{err}");
        }
    }

    /// `[packages] allowed_sources` fails the load whatever it holds, naming the key as removed:
    /// ignored, it would be a list an operator believes is in force and is not (ADR-0033 clause 13).
    /// Verifies: ADR-0033
    #[test]
    fn allowed_sources_fails_the_load_naming_the_key_as_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        for packages in [
            "[packages]\nallowed_sources = []\n",
            "[packages]\nallowed_sources = [\"https://mirror.example/releases/\"]\n",
        ] {
            std::fs::write(&path, packages).expect("write");
            let err = ClientConfig::load(&path).expect_err(packages);
            assert!(
                err.contains("[packages] allowed_sources is removed"),
                "{err}"
            );
        }
    }

    /// The Baseline requires a message size limit, recommends 64 MiB, and asks that it be
    /// configurable; zero is not "unlimited" but a limit that could carry nothing, so it fails.
    #[test]
    fn the_message_size_limit_defaults_to_the_recommended_value_and_is_configurable() {
        assert_eq!(
            ClientConfig::default().max_message_size_bytes,
            64 * 1024 * 1024
        );
        let tightened: ClientConfig =
            toml::from_str("max_message_size_bytes = 65536").expect("parse");
        assert_eq!(tightened.max_message_size_bytes, 65536);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "max_message_size_bytes = 0\n").expect("write");
        let err = ClientConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("max_message_size_bytes"), "{err}");
    }

    /// The artifact download has a ceiling so a Server cannot fill the staging disk before the hash
    /// is checked; it defaults to the Server's own per-package limit, is configurable, and zero is
    /// a bound that could carry nothing rather than "unlimited", so it fails startup.
    /// Verifies: ADR-0026
    #[test]
    fn the_artifact_size_limit_defaults_is_configurable_and_rejects_zero() {
        assert_eq!(ClientConfig::default().max_artifact_size_bytes, 1 << 30);
        let tightened: ClientConfig =
            toml::from_str("max_artifact_size_bytes = 1048576").expect("parse");
        assert_eq!(tightened.max_artifact_size_bytes, 1_048_576);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "max_artifact_size_bytes = 0\n").expect("write");
        let err = ClientConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("max_artifact_size_bytes"), "{err}");
    }

    /// A single downstream connection's Agent cap bounds the routing state one peer can create; it
    /// has a generous default, and zero is a bound that could carry nothing rather than "unlimited",
    /// so it fails startup.
    /// Verifies: ADR-0015
    #[test]
    fn the_gateway_agent_cap_defaults_and_rejects_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");

        let tls = "[gateway.tls]\ncert_file = \"g.pem\"\nkey_file = \"g-key.pem\"\n\
                   client_ca_file = \"ca.pem\"\n";
        std::fs::write(
            &path,
            format!("endpoint = \"wss://s/v1/opamp\"\n[gateway]\nlisten = \"127.0.0.1:9\"\n{tls}"),
        )
        .expect("write");
        let config = ClientConfig::load(&path).expect("loads with the default cap");
        assert_eq!(config.gateway.expect("gateway").max_carried_agents, 10_000);

        std::fs::write(
            &path,
            format!(
                "endpoint = \"wss://s/v1/opamp\"\n[gateway]\nlisten = \"127.0.0.1:9\"\n\
                 max_carried_agents = 0\n{tls}"
            ),
        )
        .expect("write");
        let err = ClientConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("max_carried_agents"), "{err}");
    }

    /// The Gateway's package cache holds ten gibibytes by default, and zero is a bound that could
    /// hold nothing rather than "unlimited", so it fails startup.
    /// Verifies: ADR-0026
    #[test]
    fn the_package_cache_defaults_to_ten_gib_and_rejects_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        let tls = "[gateway.tls]\ncert_file = \"g.pem\"\nkey_file = \"g-key.pem\"\n\
                   client_ca_file = \"ca.pem\"\n";
        std::fs::write(
            &path,
            format!("endpoint = \"wss://s/v1/opamp\"\n[gateway]\nlisten = \"127.0.0.1:9\"\n{tls}"),
        )
        .expect("write");
        let config = ClientConfig::load(&path).expect("loads with the default bound");
        assert_eq!(
            config.gateway.expect("gateway").package_cache_bytes,
            10_737_418_240
        );

        std::fs::write(
            &path,
            format!(
                "endpoint = \"wss://s/v1/opamp\"\n[gateway]\nlisten = \"127.0.0.1:9\"\n\
                 package_cache_bytes = 0\n{tls}"
            ),
        )
        .expect("write");
        let err = ClientConfig::load(&path).expect_err("zero must fail startup");
        assert!(err.contains("package_cache_bytes"), "{err}");
    }

    /// A Gateway admits Agents, so it never serves without TLS, nor without a client CA to verify
    /// them against — on the loopback neither (ADR-0015).
    /// Verifies: ADR-0015, Q-1
    #[test]
    fn a_gateway_without_mutual_tls_is_refused_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(
            &path,
            "endpoint = \"wss://s/v1/opamp\"\n[gateway]\nlisten = \"127.0.0.1:9\"\n",
        )
        .expect("write");
        let err = ClientConfig::load(&path).expect_err("no TLS");
        assert!(err.contains("[gateway.tls] is required"), "{err}");

        std::fs::write(
            &path,
            "endpoint = \"wss://s/v1/opamp\"\n[gateway]\nlisten = \"127.0.0.1:9\"\n\
             [gateway.tls]\ncert_file = \"g.pem\"\nkey_file = \"g-key.pem\"\n",
        )
        .expect("write");
        let err = ClientConfig::load(&path).expect_err("no client CA");
        assert!(err.contains("client_ca_file is required"), "{err}");
    }

    /// Both keys that would configure package delivery on the host are refused rather than ignored:
    /// `package` would name the artifact (the Server's Selector does, ADR-0026), and
    /// `accepts_packages` would say whether to take one (ADR-0017 derives that from the program's
    /// path). An operator who has either in a file believes it does something.
    /// Verifies: ADR-0026
    #[test]
    fn the_retired_package_keys_are_refused() {
        let block = |extra: &str| {
            format!(
                r#"
                [[supervisor]]
                type = "command"
                name = "agent"
                command = "agent"
                {extra}
                "#
            )
        };
        assert!(
            toml::from_str::<ClientConfig>(&block("")).is_ok(),
            "a block without either key still parses"
        );

        let stale = toml::from_str::<ClientConfig>(&block("package = \"otelcol\""))
            .expect_err("the old naming key must fail loudly");
        assert!(
            stale.to_string().contains("Selector"),
            "the error says what decides instead: {stale}"
        );

        let consent = toml::from_str::<ClientConfig>(&block("accepts_packages = true"))
            .expect_err("the old consent key must fail loudly");
        let message = consent.to_string();
        assert!(
            message.contains("bare file name"),
            "the error states the rule that replaced it: {message}"
        );
    }

    /// One shape (ADR-0017): a bare name, which is what puts the program in a directory this
    /// Client owns and may therefore replace. Everything else is refused rather than guessed at.
    // Verifies: ADR-0017
    #[test]
    fn a_bare_name_resolves_and_everything_else_is_refused() {
        let dir = PathBuf::from("/srv/fleet/otelcol");

        let resolved = resolve_program(
            "binary",
            Path::new("otelcol-contrib"),
            None,
            &dir,
            "otelcol",
        )
        .expect("a bare file name resolves");
        assert_eq!(
            resolved,
            Program {
                path: dir.join(PROGRAM_DIR).join("otelcol-contrib"),
            }
        );

        // `..` in particular never reaches a `join`, which is why nothing downstream has a path
        // to sanitize.
        for refused in ["./otelcol", "bin/otelcol", "../otelcol", "a/../../b", ""] {
            let err = resolve_program("binary", Path::new(refused), None, &dir, "otelcol")
                .expect_err("must be refused: {refused}");
            assert!(err.contains("bare file name"), "{refused}: {err}");
        }
    }

    /// With a tree (ADR-0026) the program is one file *inside* the package, so the spawn path is
    /// the one the configuration writes — and the bare name keeps meaning exactly what ADR-0017
    /// made it mean, which is consent and nothing else.
    /// Verifies: ADR-0026
    #[test]
    fn a_tree_spawns_from_the_path_written_inside_the_package() {
        let dir = PathBuf::from("/srv/fleet/fluent-bit");

        let resolved = resolve_program(
            "command",
            Path::new("fluent-bit"),
            Some(Path::new("bin/fluent-bit")),
            &dir,
            "fluent-bit",
        )
        .expect("a bare name with a program_path resolves");
        assert_eq!(
            resolved,
            Program {
                path: dir.join(PROGRAM_DIR).join(TREE_DIR).join("bin/fluent-bit"),
            },
            "the spawn path is readable in the file, before any package exists"
        );
    }

    /// Refused at startup, where the operator is still looking at the file — not at rollout time
    /// on every matched host, which is where the archive sanitizer would catch the same thing.
    /// Verifies: ADR-0026
    #[test]
    fn a_program_path_must_stay_inside_the_package() {
        assert_eq!(
            validate_program_path("bin/fluent-bit").expect("relative"),
            PathBuf::from("bin/fluent-bit")
        );
        for (refused, because) in [
            ("../../etc/passwd", ".."),
            ("bin/../../x", ".."),
            ("./bin/fluent-bit", "`.`"),
            ("", "nothing"),
            ("   ", "nothing"),
        ] {
            let err = validate_program_path(refused).expect_err("must be refused: {refused}");
            assert!(
                err.contains(because),
                "{refused}: {err} does not say {because}"
            );
        }
        #[cfg(unix)]
        assert!(validate_program_path("/opt/fluent-bit/bin/fluent-bit")
            .expect_err("absolute")
            .contains("relative"));
        #[cfg(windows)]
        assert!(validate_program_path("C:\\fluent-bit\\bin\\fluent-bit.exe")
            .expect_err("absolute")
            .contains("relative"));
    }

    /// ADR-0017: the machine's program is refused, and the message is the only notice an operator
    /// carrying such a block will get — so it must name the way across, not a rule number.
    ///
    /// Whose *spelling* is platform-specific even though the rule is not: on Unix a leading `/`
    /// makes a path absolute, on Windows nothing does until it names a drive. Written per platform
    /// rather than with one string that only happens to work on the machine the tests were first
    /// run on.
    #[test]
    fn an_absolute_program_path_is_refused_and_names_the_way_across() {
        let dir = PathBuf::from("/srv/fleet/otelcol");
        #[cfg(unix)]
        let foreign = "/usr/local/bin/otelcol-contrib";
        #[cfg(windows)]
        let foreign = r"C:\Program Files\otelcol\otelcol-contrib.exe";

        let err = resolve_program("binary", Path::new(foreign), None, &dir, "otelcol")
            .expect_err("a program on the machine must be refused");
        assert!(err.contains("only programs it installs"), "{err}");
        assert!(err.contains("package"), "it names the route: {err}");
        assert!(err.contains("bare file name"), "it names the shape: {err}");
        assert!(err.contains(foreign), "it quotes what was written: {err}");
    }

    /// The case Windows adds and Unix has no equivalent of: `\Program Files\...` carries a root but
    /// no drive, so it resolves against whichever drive the process is on — it *looks* absolute and
    /// is not. It folds into the same refusal as the absolute form (ADR-0017), because it is a
    /// near-miss of it and both have one answer.
    #[cfg(windows)]
    #[test]
    fn a_drive_relative_windows_path_folds_into_the_same_refusal() {
        let dir = PathBuf::from(r"C:\ProgramData\fleet\otelcol");
        let err = resolve_program(
            "binary",
            Path::new(r"\Program Files\otelcol\otelcol.exe"),
            None,
            &dir,
            "otelcol",
        )
        .expect_err("a drive-relative path must be refused");
        assert!(err.contains("only programs it installs"), "{err}");
    }

    /// The per-Supervisor root is `<state_dir>/supervisors` unless the operator moved it, and
    /// everything that Supervisor owns hangs off the same place (ADR-0017).
    #[test]
    fn the_supervisor_root_defaults_under_the_state_dir_and_is_relocatable() {
        let default = ClientConfig {
            state_dir: PathBuf::from("/var/lib/fleet/state"),
            ..ClientConfig::default()
        };
        assert_eq!(
            default.supervisor_dir("otelcol"),
            PathBuf::from("/var/lib/fleet/state/supervisors/otelcol")
        );

        let moved: ClientConfig = toml::from_str(
            r#"
            state_dir = "/var/lib/fleet/state"
            supervisor_dir = "/opt/fleet/supervisors"

            [[supervisor]]
            type = "command"
            name = "agent"
            command = "agent"
            "#,
        )
        .expect("parse");
        assert_eq!(
            moved.supervisor_dir("agent"),
            PathBuf::from("/opt/fleet/supervisors/agent")
        );
        // The Client's own Agent keeps staging beside its versions; a Supervisor stages in its own
        // directory, which is what makes the install a rename rather than a copy.
        assert_eq!(
            moved.staging_dir_for(None),
            PathBuf::from("/var/lib/fleet/state/packages")
        );
        assert_eq!(
            moved.staging_dir_for(Some("agent")),
            PathBuf::from("/opt/fleet/supervisors/agent/packages")
        );
    }

    /// Verifies: ADR-0013
    #[test]
    fn scheme_selects_the_transport() {
        for (endpoint, kind) in [
            ("ws://127.0.0.1/v1/opamp", TransportKind::WebSocket),
            ("wss://x/v1/opamp", TransportKind::WebSocket),
            ("http://[::1]/v1/opamp", TransportKind::Http),
            ("https://x/v1/opamp", TransportKind::Http),
        ] {
            let cfg = ClientConfig {
                endpoint: endpoint.to_string(),
                ..ClientConfig::default()
            };
            assert_eq!(cfg.transport().expect("transport"), kind);
        }
    }

    /// Verifies: ADR-0013
    #[test]
    fn the_default_endpoint_is_wss_on_the_loopback() {
        assert_eq!(
            ClientConfig::default().endpoint,
            "wss://127.0.0.1:4320/v1/opamp"
        );
    }

    /// Verifies: ADR-0013, Q-1
    #[test]
    fn a_plaintext_endpoint_off_the_loopback_is_refused_at_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        for endpoint in [
            "ws://fleet.example/v1/opamp",
            "http://localhost:4320/v1/opamp",
        ] {
            std::fs::write(&path, format!("endpoint = \"{endpoint}\"\n")).expect("write");
            let err = ClientConfig::load(&path).expect_err(endpoint);
            assert!(err.contains("plaintext"), "{err}");
        }
        std::fs::write(&path, "endpoint = \"ws://127.0.0.1:4320/v1/opamp\"\n").expect("write");
        ClientConfig::load(&path).expect("plaintext on a loopback literal loads");
    }

    /// Verifies: ADR-0013, ADR-0010
    #[test]
    fn rejects_an_unknown_scheme_and_unknown_keys() {
        let cfg = ClientConfig {
            endpoint: "ftp://x".to_string(),
            ..ClientConfig::default()
        };
        assert!(cfg.transport().is_err());
        assert!(toml::from_str::<ClientConfig>("endpont = \"ws://x\"").is_err());
    }

    #[test]
    fn supervisor_blocks_split_common_keys_from_plugin_settings() {
        let cfg: ClientConfig = toml::from_str(
            r#"
            [[supervisor]]
            type = "collector"
            name = "otelcol"
            endpoint_port = 4321
            binary = "/usr/local/bin/otelcol"

            [[supervisor]]
            type = "command"
            name = "my-agent"
            command = "/usr/bin/my-agent"
            args = ["--verbose"]
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.supervisors.len(), 2);

        let collector = &cfg.supervisors[0];
        assert_eq!(collector.kind, "collector");
        assert_eq!(collector.name, "otelcol");
        assert_eq!(collector.endpoint_port, 4321);
        // Neither is stated in this block, and unstated now stays unstated: what a Supervisor runs
        // with is resolved against the fleet's `[supervisors]` policy and its kind (ADR-0017),
        // rather than being filled in with a compiled-in number here.
        assert_eq!(collector.stop_timeout_secs, None);
        assert_eq!(collector.apply_grace_secs, None);
        assert_eq!(
            collector.settings.get("binary").and_then(|v| v.as_str()),
            Some("/usr/local/bin/otelcol")
        );
        assert!(!collector.settings.contains_key("type"));

        let command = &cfg.supervisors[1];
        assert_eq!(command.endpoint_port, 0);
        assert!(command.settings.contains_key("args"));
    }

    /// ADR-0026: retention defaults to a day, is set globally by `[updates]`, and a `[[supervisor]]`
    /// block overrides it for itself — the shape `apply_grace_secs` has.
    /// Verifies: ADR-0026
    #[test]
    fn retention_defaults_globally_and_is_overridable_per_supervisor() {
        let default: ClientConfig = toml::from_str("").expect("parse");
        assert_eq!(
            default.updates.retain_previous_secs,
            24 * 60 * 60,
            "one day by default"
        );

        let cfg: ClientConfig = toml::from_str(
            r#"
            [updates]
            retain_previous_secs = 3600

            [[supervisor]]
            type = "command"
            name = "keeps-default"
            command = "agent"

            [[supervisor]]
            type = "command"
            name = "overrides"
            command = "agent"
            retain_previous_secs = 0
            "#,
        )
        .expect("parse");
        assert_eq!(
            cfg.updates.retain_previous_secs, 3600,
            "the global override"
        );
        assert_eq!(
            cfg.supervisors[0].retain_previous_secs, None,
            "a block that says nothing takes the global"
        );
        assert_eq!(
            cfg.supervisors[1].retain_previous_secs,
            Some(0),
            "a block may override to immediate deletion"
        );

        let negative = toml::from_str::<ClientConfig>(
            "[[supervisor]]\ntype = \"command\"\nname = \"x\"\ncommand = \"a\"\nretain_previous_secs = -1\n",
        );
        assert!(negative
            .unwrap_err()
            .to_string()
            .contains("retain_previous_secs"));
    }

    #[test]
    fn a_supervisor_block_needs_type_and_a_valid_name() {
        let missing_type = toml::from_str::<ClientConfig>("[[supervisor]]\nname = \"x\"\n");
        assert!(missing_type.unwrap_err().to_string().contains("`type`"));

        let missing_name = toml::from_str::<ClientConfig>("[[supervisor]]\ntype = \"command\"\n");
        assert!(missing_name.unwrap_err().to_string().contains("`name`"));

        for bad_name in ["Über", "with space", "-lead", "con"] {
            let toml = format!("[[supervisor]]\ntype = \"command\"\nname = \"{bad_name}\"\n");
            assert!(
                toml::from_str::<ClientConfig>(&toml).is_err(),
                "{bad_name:?} should be rejected"
            );
        }
    }

    /// The switch is a list of Supervisor names in `[supervisors]`, empty unless the operator
    /// writes one (ADR-0017 clause 48).
    /// Verifies: ADR-0017
    #[test]
    fn remote_config_disabled_defaults_to_empty_and_lists_supervisor_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "").expect("write");
        let absent = ClientConfig::load(&path).expect("load");
        assert!(absent.supervisor_defaults.remote_config_disabled.is_empty());
        assert!(!absent.remote_config_disabled("otelcol"));

        std::fs::write(
            &path,
            "[supervisors]\nremote_config_disabled = [\"otelcol\", \"icinga2\"]\n",
        )
        .expect("write");
        let listed = ClientConfig::load(&path).expect("load");
        assert_eq!(
            listed.supervisor_defaults.remote_config_disabled,
            ["otelcol", "icinga2"]
        );
        assert!(listed.remote_config_disabled("otelcol"));
        assert!(listed.remote_config_disabled("icinga2"));
        assert!(!listed.remote_config_disabled("telegraf"));
    }

    /// A value no block can ever carry fails startup, naming the key and the value (ADR-0017
    /// clause 29).
    /// Verifies: ADR-0017
    #[test]
    fn a_remote_config_disabled_name_outside_the_instance_name_grammar_fails_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        for bad in ["OtelCol", "with space", "-lead", "", "con"] {
            std::fs::write(
                &path,
                format!("[supervisors]\nremote_config_disabled = [\"ok\", {bad:?}]\n"),
            )
            .expect("write");
            let err = ClientConfig::load(&path).expect_err(bad);
            assert!(err.contains("remote_config_disabled"), "{err}");
            assert!(err.contains(&format!("{bad:?}")), "{err}");
        }
    }

    /// The switch is a boolean in `[supervisors]`, `true` unless the operator writes `false`
    /// (ADR-0017 clause 41).
    /// Verifies: ADR-0017
    #[test]
    fn server_manages_set_defaults_to_true_and_reads_false() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, "").expect("write");
        assert!(ClientConfig::load(&path)
            .expect("load")
            .server_manages_set());
        std::fs::write(&path, "[supervisors]\nstop_timeout_secs = 5\n").expect("write");
        assert!(ClientConfig::load(&path)
            .expect("load")
            .server_manages_set());

        std::fs::write(&path, "[supervisors]\nserver_manages_set = false\n").expect("write");
        assert!(!ClientConfig::load(&path)
            .expect("load")
            .server_manages_set());

        std::fs::write(&path, "[supervisors]\nserver_manages_set = \"no\"\n").expect("write");
        assert!(
            ClientConfig::load(&path).is_err(),
            "a non-boolean is refused"
        );
    }

    #[test]
    fn common_keys_are_type_checked() {
        let bad_port = "[[supervisor]]\ntype = \"command\"\nname = \"x\"\nendpoint_port = 70000\n";
        assert!(toml::from_str::<ClientConfig>(bad_port).is_err());
        let not_an_int =
            "[[supervisor]]\ntype = \"command\"\nname = \"x\"\nendpoint_port = \"a\"\n";
        assert!(toml::from_str::<ClientConfig>(not_an_int).is_err());
        let negative_grace =
            "[[supervisor]]\ntype = \"command\"\nname = \"x\"\napply_grace_secs = -1\n";
        assert!(toml::from_str::<ClientConfig>(negative_grace).is_err());
        let zero_grace: ClientConfig = toml::from_str(
            "[[supervisor]]\ntype = \"command\"\nname = \"x\"\napply_grace_secs = 0\n",
        )
        .expect("parse");
        assert_eq!(zero_grace.supervisors[0].apply_grace_secs, Some(0));
    }

    /// The Agent type is a common key like `name`, and — unlike `name` — is not bound by the
    /// ADR-0019 instance grammar, because the Baseline asks for a reverse FQDN and that grammar
    /// forbids the dots (ADR-0016).
    #[test]
    fn a_block_may_state_its_agent_type_and_a_reverse_fqdn_is_accepted() {
        let cfg: ClientConfig = toml::from_str(
            r#"
            [[supervisor]]
            type = "collector"
            name = "otelcol-edge-01"
            binary = "otelcol"
            service_name = "io.opentelemetry.collector"
            "#,
        )
        .expect("parse");
        let block = &cfg.supervisors[0];
        assert_eq!(block.name, "otelcol-edge-01");
        assert_eq!(
            block.service_name.as_deref(),
            Some("io.opentelemetry.collector")
        );
        // A common key, never handed to the plugin's strict parse.
        assert!(!block.settings.contains_key("service_name"));
    }

    /// Absent is the documented way to fall back to the program's file name. An empty string is
    /// not the same thing — it would report "no type" as though it were one, which a Selector
    /// could then match.
    #[test]
    fn an_empty_agent_type_is_refused_rather_than_treated_as_absent() {
        let err = toml::from_str::<ClientConfig>(
            r#"
            [[supervisor]]
            type = "collector"
            name = "otelcol"
            binary = "otelcol"
            service_name = "  "
            "#,
        )
        .expect_err("empty service_name must be refused");
        assert!(
            err.to_string().contains("`service_name` must not be empty"),
            "unhelpful error: {err}"
        );

        let absent: ClientConfig = toml::from_str(
            "[[supervisor]]\ntype = \"collector\"\nname = \"otelcol\"\nbinary = \"otelcol\"\n",
        )
        .expect("parse");
        assert_eq!(absent.supervisors[0].service_name, None);
    }

    /// The Client-wide table stays — it describes the *host*, and it is what a fresh Agent carries
    /// into its first message, before there is anything for a Server to label. The block's own
    /// table is gone, and refused by name (ADR-0017).
    #[test]
    fn attributes_describe_the_host_and_a_block_no_longer_tags_one_agent() {
        let cfg: ClientConfig = toml::from_str(
            r#"
            [attributes]
            env = "prod"
            role = "machine"

            [[supervisor]]
            type = "command"
            name = "stub"
            command = "/bin/true"
            "#,
        )
        .expect("parse");
        for agent in [None, Some(&cfg.supervisors[0])] {
            let attributes = cfg.agent_attributes(agent);
            assert_eq!(attributes.get("env").map(String::as_str), Some("prod"));
            assert_eq!(attributes.get("role").map(String::as_str), Some("machine"));
        }

        let tagged = "[[supervisor]]\ntype = \"command\"\nname = \"x\"\ncommand = \"/bin/true\"\n\
                      [supervisor.attributes]\nrole = \"edge\"\n";
        let error = toml::from_str::<ClientConfig>(tagged).expect_err("refused");
        assert!(error.to_string().contains("Server label"), "{error}");
    }

    #[test]
    fn non_string_attributes_are_rejected() {
        assert!(toml::from_str::<ClientConfig>("[attributes]\nport = 80\n").is_err());
    }

    /// A file written for an earlier version may still hold `[auth]`, with any of the keys it
    /// took then. It loads — a Client the Server updated must keep connecting — the notice names
    /// the section, and nothing from it reaches the connection: no `Authorization` value, and the
    /// effective configuration reported upstream carries none of its secrets.
    /// Verifies: ADR-0021, ADR-0019
    #[test]
    fn a_leftover_auth_section_is_ignored_with_a_notice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(crate::config_init::FILE_NAME);
        for section in [
            "[auth]\nbearer_token = \"s3cret\"\n",
            "[auth]\nusername = \"fleet\"\npassword = \"s3cret\"\n",
            "[auth]\nbearer_token = \"s3cret\"\nusername = \"fleet\"\n",
            "[auth]\n",
        ] {
            std::fs::write(
                &path,
                format!("endpoint = \"wss://fleet:4320/v1/opamp\"\n{section}"),
            )
            .expect("write");
            let config = ClientConfig::load(&path).expect("a leftover [auth] still loads");

            let notice = config.leftover_auth_notice().expect("a notice");
            assert!(notice.contains("[auth]"), "{notice}");

            let connection = crate::transport::connection(&config).expect("connection");
            assert_eq!(connection.authorization, None, "{section:?} was sent");
            let source = config.source.expect("source");
            assert!(!source.contains("s3cret"), "{source}");
        }

        std::fs::write(&path, "endpoint = \"wss://fleet:4320/v1/opamp\"\n").expect("write");
        let clean = ClientConfig::load(&path).expect("loads");
        assert_eq!(clean.leftover_auth_notice(), None, "no section, no notice");
    }

    #[test]
    fn duplicate_supervisor_names_are_rejected() {
        let cfg: ClientConfig = toml::from_str(
            r#"
            [[supervisor]]
            type = "command"
            name = "twin"
            [[supervisor]]
            type = "collector"
            name = "twin"
            "#,
        )
        .expect("parses; the duplicate is a semantic error");
        assert!(cfg.check_supervisor_names().is_err());
    }

    /// The file's text is reported off the host as the effective configuration, and the Server
    /// persists what it receives — so a credential value must never survive the redaction, while
    /// the operator's comments and layout must (they are half of what the file says).
    #[test]
    fn redaction_masks_credential_values_and_keeps_everything_else() {
        let text = "# the fleet endpoint\nendpoint = \"wss://fleet:4320/v1/opamp\"\n\n\
                    [auth]\n  bearer_token = \"s3cret\"\n\
                    [packages]\narchive_key = \"p4ss\"\nverification_key = \"aabb\"\n";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("s3cret"), "{redacted}");
        assert!(!redacted.contains("p4ss"), "{redacted}");
        assert!(redacted.contains("  bearer_token = \"***\""), "{redacted}");
        assert!(redacted.contains("archive_key = \"***\""), "{redacted}");
        assert!(
            redacted.contains("# the fleet endpoint"),
            "comments stay: {redacted}"
        );
        assert!(
            redacted.contains("endpoint = \"wss://fleet:4320/v1/opamp\""),
            "{redacted}"
        );
        assert!(
            redacted.contains("verification_key = \"aabb\""),
            "the public half of the signing pair is no secret: {redacted}"
        );

        // A spelling the line scan cannot take apart — an inline table — is masked whole:
        // over-redaction is the cheap failure, a leaked credential the expensive one.
        let inline = redact_secrets("auth = { username = \"op\", password = \"hunter2\" }\n");
        assert!(!inline.contains("hunter2"), "{inline}");
    }

    /// `load` is the single place the redaction happens, so everything downstream — the
    /// effective-configuration report above all — can only ever see the mask.
    #[test]
    fn load_stashes_the_source_already_redacted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(crate::config_init::FILE_NAME);
        std::fs::write(
            &path,
            "endpoint = \"wss://fleet:4320/v1/opamp\"\n[auth]\nbearer_token = \"s3cret\"\n",
        )
        .expect("write");
        let cfg = ClientConfig::load(&path).expect("loads");
        let source = cfg.source.expect("the file's text is kept");
        assert!(!source.contains("s3cret"), "{source}");
        assert!(source.contains("endpoint = \"wss://fleet:4320/v1/opamp\""));

        // No file, no text: the defaults run and there is nothing truthful to report.
        assert!(ClientConfig::load(&dir.path().join("absent.toml"))
            .expect("defaults")
            .source
            .is_none());
    }
}
