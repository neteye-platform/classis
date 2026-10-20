//! `server migrate` (ADR-0037 clause 14): moves the state an older Server kept under `config_dir`
//! and `packages_dir` into a new `data_dir`, once, while the Server is stopped.
//!
//! The Server reads no older layout; this is the one place that knows it, and it knows the layout
//! the 0.5 releases wrote and no other. It copies and never moves, so the old directories stay as
//! the backup, and it refuses a `data_dir` that is not empty. What it does with each kind of data:
//!
//! - **Trust data** — the certificate register, the revocation list, the hosts, the bootstrap
//!   entries with their PKCS#12 files, and the audit files — is carried whole; the audit lines are
//!   copied, not rewritten, so the chain holds. Trust data it cannot carry makes it exit non-zero.
//! - **Packages:** each uploaded artifact becomes a blob; each entry takes the signature the
//!   Deployments held for it — the same bytes wherever it was held, so differing ones leave the
//!   entry unsigned, named — and a referenced entry is dropped, named. An artifact whose bytes do
//!   not match its recorded hash is dropped, named.
//! - **Deployments** keep their name, Selector and the Packages that were carried; their
//!   signatures moved onto the entries, and a Package that was not carried leaves them, named.
//! - **Configurations** keep their content; each loses its Selector, and is listed with the
//!   Selector it had, for the operator to place in a Deployment. One without an Agent type is not
//!   carried, because the Server refuses it at startup (ADR-0034 clause 1): it is listed, and its
//!   file stays in the old directory for the operator to save again with a type.
//! - **Agents** are carried with their labels moved into the record. A Package released through a
//!   Deployment stays assigned through it, while both were carried. A 0.5 Server released every
//!   Configuration by itself, never through a Deployment, so no Configuration pin has a place in
//!   an assignment: every one is dropped and listed per Agent, and the Agent keeps running what
//!   it runs — an assignment without Configurations offers no configuration — until a Deployment
//!   holding them is rolled out to it. The retained revisions only those pins referenced are
//!   collected at the first start.
//!
//! When it is done, the new `data_dir` is opened as the Server would open it, so a migration that
//! would not start is reported here rather than at the first start.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::bootstrap::{BootstrapStore as _, Entry as BootstrapEntry};
use crate::configs::{ConfigBackend as _, Configuration};
use crate::deployments::{Deployment, DeploymentBackend as _};
use crate::fs;
use crate::packages::{Entry, Package, PackageBackend as _, PackageId, Platform};
use crate::revocation::{Host, Issued, LedgerStore as _};

/// What a migration did, line by line, and whether all of the trust data made it.
#[derive(Debug, Default)]
pub struct Report {
    /// One line per thing carried, dropped, listed or skipped, in the order it happened.
    pub lines: Vec<String>,
    /// Whether some trust data could not be carried — the migration's exit is then non-zero.
    pub trust_failed: bool,
}

impl Report {
    fn line(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    /// Notes trust data that could not be carried.
    fn failed(&mut self, what: impl std::fmt::Display) {
        self.lines.push(format!("FAILED: {what}"));
        self.trust_failed = true;
    }
}

/// Migrates `config_dir` and `packages_dir`, as a 0.5 Server wrote them, into the new and empty
/// `data_dir`.
///
/// # Errors
/// Returns an error — and writes nothing — when `config_dir` is not a directory or `data_dir` is
/// not empty, and an error naming the path when the new `data_dir` cannot be written.
pub fn run(config_dir: &Path, packages_dir: &Path, data_dir: &Path) -> Result<Report, String> {
    if !config_dir.is_dir() {
        return Err(format!("{} is not a directory", config_dir.display()));
    }
    if std::fs::read_dir(data_dir).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(format!(
            "{} is not empty — the migration writes into a new data directory only, so nothing \
             already there is overwritten",
            data_dir.display()
        ));
    }
    fs::open_data_dir(data_dir)?;
    let mut report = Report::default();
    carry_register(config_dir, data_dir, &mut report)?;
    carry_bootstrap(config_dir, data_dir, &mut report)?;
    carry_audit(config_dir, data_dir, &mut report)?;
    // The signatures come from the Deployments, and the Packages a Deployment keeps are the ones
    // carried: read the Deployments, carry the Packages, then write the Deployments.
    let (read, signatures) = read_deployments(packages_dir, &mut report)?;
    let packages = carry_packages(packages_dir, data_dir, &signatures, &mut report)?;
    let deployments = carry_deployments(read, &packages, data_dir, &mut report)?;
    carry_configurations(config_dir, data_dir, &mut report)?;
    carry_agents(config_dir, data_dir, &deployments, &packages, &mut report)?;
    check_opens(data_dir, &mut report);
    Ok(report)
}

/// The entries of `dir`, or none when it does not exist.
fn listing(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.push((name, path));
    }
    entries.sort();
    Ok(entries)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// The register, the revocation list and the hosts: `config_dir/revocation/`.
fn carry_register(config_dir: &Path, data_dir: &Path, report: &mut Report) -> Result<(), String> {
    let old = config_dir.join("revocation");
    let ledger = fs::FsLedgerStore::open(data_dir)?;
    let mut carried = 0usize;
    for (name, path) in listing(&old.join("issued"))? {
        if !name.ends_with(".json") {
            report.line(format!(
                "skipped: {} — not a register entry",
                path.display()
            ));
            continue;
        }
        match read_json::<Issued>(&path).and_then(|issued| ledger.put_issued(&issued)) {
            Ok(()) => carried += 1,
            Err(e) => report.failed(format!("the register entry {}: {e}", path.display())),
        }
    }
    report.line(format!("carried: {carried} certificate(s) of the register"));

    let list = old.join("revocations.json");
    if list.exists() {
        // Byte for byte: the Server reads the list as it always has, and drops a credential entry
        // it may still hold on its first load (ADR-0021 clause 36).
        match copy_owner_only(&list, &data_dir.join(fs::REVOCATIONS)) {
            Ok(()) => report.line("carried: the revocation list"),
            Err(e) => report.failed(format!("the revocation list: {e}")),
        }
    } else {
        report.line("carried: no revocation list — none was written");
    }

    let hosts = old.join("hosts.json");
    if hosts.exists() {
        match read_json::<BTreeMap<String, Host>>(&hosts)
            .and_then(|hosts| ledger.save_hosts(&hosts).map(|()| hosts.len()))
        {
            Ok(count) => report.line(format!("carried: {count} host(s)")),
            Err(e) => report.failed(format!("the hosts: {e}")),
        }
    }
    for (name, path) in listing(&old)? {
        if !matches!(name.as_str(), "issued" | "revocations.json" | "hosts.json") {
            report.line(format!("skipped: {}", path.display()));
        }
    }
    Ok(())
}

/// The bootstrap certificates: `config_dir/bootstrap-certificates/<serial>.json` and `.p12`,
/// re-keyed by issuer and serial.
fn carry_bootstrap(config_dir: &Path, data_dir: &Path, report: &mut Report) -> Result<(), String> {
    let old = config_dir.join("bootstrap-certificates");
    let store = fs::FsBootstrapStore::open(data_dir)?;
    let listed = listing(&old)?;
    let mut entries = BTreeMap::new();
    for (name, path) in &listed {
        let Some(serial) = name.strip_suffix(".json") else {
            continue;
        };
        match read_json::<BootstrapEntry>(path).and_then(|entry| {
            store.put(&entry)?;
            Ok(entry)
        }) {
            Ok(entry) => {
                entries.insert(serial.to_string(), entry);
            }
            Err(e) => report.failed(format!("the bootstrap entry {}: {e}", path.display())),
        }
    }
    let mut files = 0usize;
    for (name, path) in &listed {
        if name.ends_with(".json") {
            continue;
        }
        let Some(entry) = name
            .strip_suffix(".p12")
            .and_then(|serial| entries.get(serial))
        else {
            report.line(format!(
                "dropped: {} — no bootstrap entry names it",
                path.display()
            ));
            continue;
        };
        match std::fs::read(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))
            .and_then(|file| store.put_p12(&entry.id, &file))
        {
            Ok(()) => files += 1,
            Err(e) => report.failed(format!("the PKCS#12 file {}: {e}", path.display())),
        }
    }
    report.line(format!(
        "carried: {} bootstrap certificate(s), {files} with its PKCS#12 file",
        entries.len()
    ));
    Ok(())
}

/// The audit files, byte for byte, so the chain holds.
fn carry_audit(config_dir: &Path, data_dir: &Path, report: &mut Report) -> Result<(), String> {
    let old = config_dir.join("audit");
    let new = data_dir.join(fs::AUDIT);
    let mut copied = Vec::new();
    for (name, path) in listing(&old)? {
        let is_audit = name
            .strip_prefix("audit-")
            .and_then(|rest| rest.strip_suffix(".jsonl"))
            .is_some_and(|seq| seq.parse::<u64>().is_ok());
        if !is_audit {
            report.line(format!("skipped: {} — not an audit file", path.display()));
            continue;
        }
        match copy_owner_only(&path, &new.join(&name)) {
            Ok(()) => copied.push(new.join(&name)),
            Err(e) => report.failed(format!("the audit file {}: {e}", path.display())),
        }
    }
    let mut texts = Vec::new();
    for file in fs::audit_files(&new)? {
        let text = std::fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        texts.push((file.display().to_string(), text));
    }
    let lines = texts.iter().flat_map(|(name, text)| {
        text.lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(move |(index, line)| (format!("{name}:{}", index + 1), line))
    });
    match crate::audit_log::verify(lines) {
        Ok(count) => report.line(format!(
            "carried: {} audit file(s), {count} entries, the chain holds",
            copied.len()
        )),
        // Copied as they were: a break the old files hold is reported, not repaired.
        Err(e) => report.line(format!(
            "carried: {} audit file(s) as they were — the chain breaks at {e}",
            copied.len()
        )),
    }
    Ok(())
}

/// A Deployment as a 0.5 Server wrote it, with the signatures it held per entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldDeployment {
    name: String,
    selector: BTreeMap<String, String>,
    #[serde(default)]
    packages: Vec<OldPackageRef>,
    #[serde(default)]
    signatures: Vec<OldSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldPackageRef {
    agent_type: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldSignature {
    agent_type: String,
    version: String,
    os: String,
    arch: String,
    signature_hex: String,
}

/// The signatures the Deployments held, per entry — `(identity, platform)` — and per Deployment.
type Signatures = BTreeMap<(PackageId, Platform), BTreeMap<String, String>>;

/// The Deployments as `packages_dir/deployments/<name>.json` holds them, every Package they name
/// included, and the signatures they held.
fn read_deployments(
    packages_dir: &Path,
    report: &mut Report,
) -> Result<(Vec<Deployment>, Signatures), String> {
    let mut deployments = Vec::new();
    let mut signatures = Signatures::new();
    for (name, path) in listing(&packages_dir.join("deployments"))? {
        if !name.ends_with(".json") {
            report.line(format!("skipped: {} — not a Deployment", path.display()));
            continue;
        }
        let read = read_json::<OldDeployment>(&path).and_then(|old| {
            let mut packages = BTreeMap::new();
            for reference in &old.packages {
                let id = PackageId::load(&reference.agent_type, &reference.version)?;
                packages.insert(id.agent_type.clone(), id);
            }
            let mut held = Signatures::new();
            for signature in &old.signatures {
                let id = PackageId::load(&signature.agent_type, &signature.version)?;
                let platform = Platform::new(&signature.os, &signature.arch)?;
                held.entry((id, platform))
                    .or_default()
                    .insert(old.name.clone(), signature.signature_hex.to_lowercase());
            }
            Ok((
                Deployment {
                    name: old.name,
                    selector: old.selector,
                    packages,
                    configurations: BTreeSet::new(),
                },
                held,
            ))
        });
        match read {
            Ok((deployment, held)) => {
                for (entry, by) in held {
                    signatures.entry(entry).or_default().extend(by);
                }
                deployments.push(deployment);
            }
            Err(e) => report.line(format!("dropped: {} — {e}", path.display())),
        }
    }
    Ok((deployments, signatures))
}

/// Writes the Deployments read, each keeping only the Packages that were carried — one deleted
/// before 0.5.5 could stay named in a Deployment, and one whose metadata did not carry is gone too.
/// Answers the names written.
fn carry_deployments(
    read: Vec<Deployment>,
    packages: &BTreeSet<PackageId>,
    data_dir: &Path,
    report: &mut Report,
) -> Result<BTreeSet<String>, String> {
    let backend = fs::FsDeploymentBackend::open(data_dir)?;
    let mut carried = BTreeSet::new();
    for mut deployment in read {
        deployment.packages.retain(|_, id| {
            let kept = packages.contains(id);
            if !kept {
                report.line(format!(
                    "dropped: Package {} from Deployment {} — no such Package was carried",
                    id.display_name(),
                    deployment.name
                ));
            }
            kept
        });
        match backend.put(&deployment) {
            Ok(()) => {
                report.line(format!(
                    "carried: Deployment {} with {} Package(s); its signatures move onto the \
                     entries",
                    deployment.name,
                    deployment.packages.len()
                ));
                carried.insert(deployment.name);
            }
            Err(e) => report.line(format!("dropped: Deployment {} — {e}", deployment.name)),
        }
    }
    Ok(carried)
}

/// A Package as a 0.5 Server wrote it: `<type>@<version>/package.json` beside its artifacts.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldPackage {
    agent_type: String,
    version: String,
    #[serde(default)]
    entries: Vec<OldEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldEntry {
    os: String,
    arch: String,
    content_hash_hex: String,
    #[serde(default)]
    source_url: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    source_headers: BTreeMap<String, String>,
}

/// The Packages: each artifact into the blob store, each entry with the signature its Deployments
/// held. Answers the Packages carried.
fn carry_packages(
    packages_dir: &Path,
    data_dir: &Path,
    signatures: &Signatures,
    report: &mut Report,
) -> Result<BTreeSet<PackageId>, String> {
    use crate::blobs::BlobStore as _;
    let mut carried = BTreeSet::new();
    if !packages_dir.exists() {
        report.line(format!(
            "carried: no Packages — {} does not exist",
            packages_dir.display()
        ));
        return Ok(carried);
    }
    let backend = fs::FsPackageBackend::open(data_dir)?;
    let blobs = fs::FsBlobStore::open(data_dir)?;
    // The blobs a carried entry names: bytes that disagree with their own entry's hash are deleted
    // only when no carried entry holds the same bytes.
    let mut named = BTreeSet::new();
    for (name, path) in listing(packages_dir)? {
        if name == "deployments" {
            continue;
        }
        let meta = path.join("package.json");
        if !path.is_dir() || !meta.is_file() {
            report.line(format!("skipped: {} — not a Package", path.display()));
            continue;
        }
        let old: OldPackage = match read_json(&meta) {
            Ok(old) => old,
            Err(e) => {
                report.line(format!("dropped: {e}"));
                continue;
            }
        };
        // A version that is a token but not SemVer is carried over as read (ADR-0043 clause 3):
        // the new Server keeps it, warns about it, and writes nothing to it.
        let id = match PackageId::load(&old.agent_type, &old.version) {
            Ok(id) => id,
            Err(e) => {
                report.line(format!("dropped: {} — {e}", meta.display()));
                continue;
            }
        };
        let mut entries = BTreeMap::new();
        for entry in old.entries {
            let platform = match Platform::new(&entry.os, &entry.arch) {
                Ok(platform) => platform,
                Err(e) => {
                    report.line(format!("dropped: an entry of {id} — {e}"));
                    continue;
                }
            };
            let tag = platform.tag();
            if let Some(url) = entry.source_url {
                report.line(format!(
                    "dropped: {id} for {tag} — a referenced entry ({url}); every artifact is \
                     uploaded now (ADR-0033)"
                ));
                continue;
            }
            let artifact = path.join(format!("{tag}.bin"));
            let stored = std::fs::File::open(&artifact)
                .map_err(|e| format!("cannot read {}: {e}", artifact.display()))
                .and_then(|mut file| blobs.put(&mut file));
            let (sha256, size) = match stored {
                Ok(stored) if stored.0 == entry.content_hash_hex.to_lowercase() => stored,
                Ok((sha256, _)) => {
                    if !named.contains(&sha256) {
                        let _ = blobs.delete(&sha256);
                    }
                    report.line(format!(
                        "dropped: {id} for {tag} — {} does not match its recorded hash",
                        artifact.display()
                    ));
                    continue;
                }
                Err(e) => {
                    report.line(format!("dropped: {id} for {tag} — {e}"));
                    continue;
                }
            };
            named.insert(sha256.clone());
            let held = signatures.get(&(id.clone(), platform.clone()));
            let distinct: BTreeSet<&String> = held.into_iter().flat_map(|h| h.values()).collect();
            let signature = match distinct.into_iter().collect::<Vec<_>>().as_slice() {
                [] => {
                    report.line(format!(
                        "carried: {id} for {tag}, unsigned — no Deployment held a signature for it"
                    ));
                    None
                }
                [one] => match hex::decode(one) {
                    Ok(signature) => {
                        report.line(format!("carried: {id} for {tag}, signed"));
                        Some(signature)
                    }
                    Err(e) => {
                        report.line(format!(
                            "carried: {id} for {tag}, unsigned — its signature is not hex: {e}"
                        ));
                        None
                    }
                },
                _ => {
                    report.line(format!(
                        "carried: {id} for {tag}, unsigned — Deployments {} held different \
                         signatures for it; sign the entry again",
                        held.map(|h| h.keys().cloned().collect::<Vec<_>>().join(", "))
                            .unwrap_or_default()
                    ));
                    None
                }
            };
            entries.insert(
                platform.clone(),
                Entry {
                    platform,
                    content_hash: hex::decode(&sha256).expect("a blob's hash is hex"),
                    size,
                    signature,
                },
            );
        }
        backend.put(&Package {
            id: id.clone(),
            entries,
        })?;
        carried.insert(id);
    }
    Ok(carried)
}

/// The Configurations: `config_dir/<name>.json`, each Selector dropped and listed; one without an
/// Agent type is listed and not carried.
fn carry_configurations(
    config_dir: &Path,
    data_dir: &Path,
    report: &mut Report,
) -> Result<(), String> {
    let backend = fs::FsConfigBackend::open(data_dir)?;
    for (name, path) in listing(config_dir)? {
        if path.is_dir() {
            if !matches!(
                name.as_str(),
                "agents" | "labels" | "audit" | "revocation" | "bootstrap-certificates"
            ) {
                report.line(format!(
                    "skipped: {} — not part of a 0.5 layout",
                    path.display()
                ));
            }
            continue;
        }
        if !name.ends_with(".json") {
            report.line(format!("skipped: {}", path.display()));
            continue;
        }
        let mut value: Value = match read_json(&path) {
            Ok(value) => value,
            Err(e) => {
                report.line(format!("dropped: {e}"));
                continue;
            }
        };
        let selector = value
            .pointer("/saved/selector")
            .cloned()
            .unwrap_or(Value::Null);
        if let Some(saved) = value.get_mut("saved").and_then(Value::as_object_mut) {
            saved.remove("selector");
        }
        if let Some(retained) = value.get_mut("retained").and_then(Value::as_object_mut) {
            for revision in retained.values_mut() {
                if let Some(revision) = revision.as_object_mut() {
                    revision.remove("selector");
                }
            }
        }
        let config = match serde_json::from_value::<Configuration>(value) {
            Ok(config) => config,
            Err(e) => {
                report.line(format!("dropped: {} — {e}", path.display()));
                continue;
            }
        };
        if let Err(e) = crate::configs::validate_name(&config.name) {
            report.line(format!("dropped: {} — {e}", path.display()));
            continue;
        }
        if crate::configs::check_type(&config.saved).is_err() {
            report.line(format!(
                "listed: Configuration {} was not carried — it has no Agent type (service_name),                  which every Configuration needs (ADR-0034); save it again with a type from {},                  which stays where it is; it had the Selector {}",
                config.name,
                path.display(),
                selector_text(&selector)
            ));
            continue;
        }
        backend.put(&config)?;
        report.line(format!(
            "listed: Configuration {} had the Selector {} — put it into a Deployment whose \
             Selector aims it (ADR-0034)",
            config.name,
            selector_text(&selector)
        ));
    }
    Ok(())
}

/// A Selector as a line shows it: `{key = "value", …}`, `{}` when it matched every Agent.
fn selector_text(selector: &Value) -> String {
    let pairs: Vec<String> = selector
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, value)| format!("{key} = {value}"))
        .collect();
    format!("{{{}}}", pairs.join(", "))
}

/// The Agents: version 2 envelopes in `config_dir/agents/`, with `config_dir/labels/<uid>.json`
/// moved in, written as this Server's records.
fn carry_agents(
    config_dir: &Path,
    data_dir: &Path,
    deployments: &BTreeSet<String>,
    packages: &BTreeSet<PackageId>,
    report: &mut Report,
) -> Result<(), String> {
    let agents = data_dir.join(fs::AGENTS);
    let mut labels = BTreeMap::new();
    for (name, path) in listing(&config_dir.join("labels"))? {
        let Some(uid) = name.strip_suffix(".json") else {
            continue;
        };
        match read_json::<BTreeMap<String, String>>(&path) {
            Ok(set) => {
                labels.insert(uid.to_string(), set);
            }
            Err(e) => report.line(format!("dropped: {e}")),
        }
    }
    let mut carried = 0usize;
    for (name, path) in listing(&config_dir.join("agents"))? {
        let Some(uid) = name.strip_suffix(".json") else {
            report.line(format!("skipped: {} — not an Agent record", path.display()));
            continue;
        };
        if opamp::uid::InstanceUid::parse(uid).is_none() {
            report.line(format!(
                "skipped: {} — not named after an Instance UID",
                path.display()
            ));
            continue;
        }
        let mut envelope: Value = match read_json(&path) {
            Ok(envelope) => envelope,
            Err(e) => {
                report.line(format!("dropped: {e}"));
                continue;
            }
        };
        let Some(fields) = envelope.as_object_mut() else {
            report.line(format!("dropped: {} — not an Agent record", path.display()));
            continue;
        };
        if fields.get("version").and_then(Value::as_u64) != Some(2) {
            report.line(format!(
                "dropped: {} — not the record a 0.5 Server writes (version 2)",
                path.display()
            ));
            continue;
        }
        let pins: BTreeMap<String, String> = fields
            .remove("config_assignments")
            .map(serde_json::from_value)
            .transpose()
            .unwrap_or_default()
            .unwrap_or_default();
        let package = fields.remove("package_assignment");
        let assignment = assignment(uid, package, &pins, deployments, packages, report);
        fields.insert("version".into(), 4.into());
        if let Some(assignment) = assignment {
            fields.insert("assignment".into(), assignment);
        }
        if let Some(set) = labels.remove(uid).filter(|set| !set.is_empty()) {
            fields.insert(
                "labels".into(),
                serde_json::to_value(set).expect("labels serialize"),
            );
        }
        let json = serde_json::to_vec_pretty(&envelope).expect("an envelope serializes");
        fs::replace(&agents.join(&name), &json)?;
        carried += 1;
    }
    report.line(format!(
        "carried: {carried} Agent record(s), their labels inside"
    ));
    for uid in labels.keys() {
        report.line(format!(
            "dropped: the labels of {uid} — no Agent record of that Instance UID"
        ));
    }
    Ok(())
}

/// The assignment an old Agent record translates to: a Package released through a Deployment
/// keeps it, while both were carried. Every Configuration pin is dropped and listed: a 0.5 Server
/// released a Configuration by itself, never through a Deployment, so none has a place in an
/// assignment, and the Agent keeps running it until a Deployment holding it reaches it.
fn assignment(
    uid: &str,
    package: Option<Value>,
    pins: &BTreeMap<String, String>,
    deployments: &BTreeSet<String>,
    packages: &BTreeSet<PackageId>,
    report: &mut Report,
) -> Option<Value> {
    #[derive(Deserialize)]
    struct OldPackageAssignment {
        deployment: String,
        package: String,
    }
    if !pins.is_empty() {
        let pinned = pins
            .iter()
            .map(|(name, hash)| format!("{name}@{}", &hash[..hash.len().min(12)]))
            .collect::<Vec<_>>()
            .join(", ");
        report.line(format!(
            "dropped: the Configuration pins of Agent {uid} ({pinned}) — released without a \
             Deployment; it keeps running them until a Deployment holding them is rolled out"
        ));
    }
    let package =
        package.and_then(|value| serde_json::from_value::<OldPackageAssignment>(value).ok())?;
    let carried = deployments.contains(&package.deployment)
        && packages.iter().any(|id| id.to_string() == package.package);
    if !carried {
        report.line(format!(
            "dropped: the Package assignment of Agent {uid} ({} through {}) — the Package or the \
             Deployment was not carried",
            package.package, package.deployment
        ));
        return None;
    }
    Some(serde_json::json!({
        "deployment": package.deployment,
        "package": package.package,
    }))
}

/// Opens the new `data_dir` as the Server would, so what would not start fails here.
fn check_opens(data_dir: &Path, report: &mut Report) {
    let opened = fs::open_data_dir(data_dir)
        .and_then(|()| crate::fleet::AppState::new(data_dir.to_path_buf()).map(|_| ()))
        .and_then(|()| crate::packages::PackageStore::open(data_dir.to_path_buf()).map(|_| ()))
        .and_then(|()| fs::FsDeploymentBackend::open(data_dir)?.load().map(|_| ()))
        .and_then(|()| fs::FsLedgerStore::open(data_dir)?.load().map(|_| ()))
        .and_then(|()| fs::FsBootstrapStore::open(data_dir)?.load().map(|_| ()))
        .and_then(|()| fs::FsAuditStore::open(data_dir).map(|_| ()));
    match opened {
        Ok(()) => report.line(format!("opened: {} as the Server will", data_dir.display())),
        Err(e) => report.failed(format!("the new data directory does not open: {e}")),
    }
}

/// Copies `from` to `to` byte for byte, owner-only.
fn copy_owner_only(from: &Path, to: &Path) -> Result<(), String> {
    let mut source =
        std::fs::File::open(from).map_err(|e| format!("cannot read {}: {e}", from.display()))?;
    let mut target = fs::create_owner_only(to)?;
    std::io::copy(&mut source, &mut target)
        .and_then(|_| target.sync_all())
        .map(|_| ())
        .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_store::AgentStore as _;
    use crate::configs::{revision_hash, Revision};
    use crate::revocation::{CertId, Facts};
    use sha2::{Digest, Sha256};

    fn write(path: &Path, contents: impl AsRef<[u8]>) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(path, contents).expect("write");
    }

    fn json(value: Value) -> Vec<u8> {
        serde_json::to_vec_pretty(&value).expect("json")
    }

    fn revision(body: &str) -> Revision {
        Revision {
            body: body.to_string(),
            role: String::new(),
            service_name: "otelcol".to_string(),
        }
    }

    /// The layout a 0.5 Server wrote, file by file, in the shapes it wrote them: the register, a
    /// revocation list still holding a credential entry, the hosts, a bootstrap entry with its
    /// PKCS#12 file, a chained audit file, Configurations with Selectors (one of them without an
    /// Agent type), a Deployment with its
    /// signatures, a Package with an uploaded and a referenced entry, Agents in envelope version
    /// 2 and their labels beside them.
    struct Old {
        config_dir: PathBuf,
        packages_dir: PathBuf,
        uploaded: Vec<u8>,
        signature: String,
        issued: Issued,
        bootstrap: BootstrapEntry,
        released: String,
        unreleased: String,
        audit: String,
    }

    fn old_layout(root: &Path) -> Old {
        let config_dir = root.join("fleet-configs");
        let packages_dir = root.join("fleet-packages");

        let issued = Issued {
            facts: Facts {
                id: CertId::new(b"client CA", "0a"),
                issuer_name: "CN=client CA".into(),
                subject: "CN=edge-01".into(),
                key_fingerprint: "k1".into(),
                not_after_ms: u64::MAX / 2,
                host: Some("h1".into()),
                subject_values: Default::default(),
            },
            instance_uid: "00".into(),
            predecessor: None,
            issued_ms: 1,
        };
        let stem = format!("{}-0a", &issued.facts.id.issuer[..16]);
        write(
            &config_dir.join(format!("revocation/issued/{stem}.json")),
            serde_json::to_vec(&issued).expect("json"),
        );
        write(
            &config_dir.join("revocation/revocations.json"),
            json(serde_json::json!([
                {"id": "c1", "revoked": {"credential": {"sha256": "5eed"}}, "revoked_ms": 1},
                {"id": "r2", "revoked": {"certificate":
                    {"authority": "client", "issuers": [issued.facts.id.issuer], "serial": "0b"}},
                 "revoked_ms": 2}
            ])),
        );
        let released = opamp::uid::InstanceUid::default().to_string();
        let unreleased = opamp::uid::InstanceUid::default().to_string();
        write(
            &config_dir.join("revocation/hosts.json"),
            json(serde_json::json!({
                "h1": {"gateway": false, "instance_uids": [released]},
                "gw": {"gateway": true, "instance_uids": []}
            })),
        );

        let bootstrap = BootstrapEntry {
            id: CertId::new(b"bootstrap CA", "b5"),
            serial: "b5".into(),
            subject: "O=Kunde, CN=fleet bootstrap".into(),
            key_fingerprint: "bf".into(),
            issued_ms: 1,
            not_after_ms: u64::MAX / 2,
            ca_key: "ca".into(),
            p12: true,
        };
        write(
            &config_dir.join("bootstrap-certificates/b5.json"),
            serde_json::to_vec(&bootstrap).expect("json"),
        );
        write(&config_dir.join("bootstrap-certificates/b5.p12"), b"sealed");
        write(&config_dir.join("bootstrap-certificates/c6.p12"), b"orphan");

        let first = format!(
            r#"{{"seq":1,"prev":"{}","event":"server.started"}}"#,
            crate::audit_log::GENESIS
        );
        let second = format!(
            r#"{{"seq":2,"prev":"{}","event":"enrolment.window"}}"#,
            crate::audit_log::line_hash(&first)
        );
        let audit = format!("{first}\n{second}\n");
        write(&config_dir.join("audit/audit-1.jsonl"), &audit);

        let (v1, v2) = (
            revision("receivers: {}\n"),
            revision("receivers: {otlp: {}}\n"),
        );
        write(
            &config_dir.join("base.json"),
            json(serde_json::json!({
                "name": "base",
                "saved": {"selector": {"os.type": "linux"}, "body": v2.body,
                          "service_name": "otelcol"},
                "retained": {
                    revision_hash(&v1): {"selector": {"os.type": "linux"}, "body": v1.body,
                                         "service_name": "otelcol"},
                    revision_hash(&v2): {"selector": {"os.type": "linux"}, "body": v2.body,
                                         "service_name": "otelcol"}
                }
            })),
        );
        write(
            &config_dir.join("extra.json"),
            json(serde_json::json!({
                "name": "extra",
                "saved": {"body": "x: 1\n", "service_name": "telegraf"}
            })),
        );
        write(
            &config_dir.join("untyped.json"),
            json(serde_json::json!({
                "name": "untyped",
                "saved": {"selector": {"os.type": "linux"}, "body": "u: 1\n"}
            })),
        );

        let uploaded = b"otelcol 1.0.0 for linux".to_vec();
        let sha256 = hex::encode(Sha256::digest(&uploaded));
        let signature = "ab".repeat(64);
        write(
            &packages_dir.join("otelcol@1.0.0/package.json"),
            json(serde_json::json!({
                "agent_type": "otelcol",
                "version": "1.0.0",
                "entries": [
                    {"os": "linux", "arch": "amd64", "content_hash_hex": sha256},
                    {"os": "windows", "arch": "amd64", "content_hash_hex": "00".repeat(32),
                     "source_url": "https://example.com/otelcol.zip"}
                ]
            })),
        );
        write(
            &packages_dir.join("otelcol@1.0.0/linux-amd64.bin"),
            &uploaded,
        );
        for (name, signed) in [("stable", &signature), ("canary", &signature)] {
            write(
                &packages_dir.join(format!("deployments/{name}.json")),
                json(serde_json::json!({
                    "name": name,
                    "selector": {"channel": name},
                    "packages": [{"agent_type": "otelcol", "version": "1.0.0"}],
                    "signatures": [{"agent_type": "otelcol", "version": "1.0.0", "os": "linux",
                                    "arch": "amd64", "signature_hex": signed}]
                })),
            );
        }

        let envelope = |pins: Value, package: Option<Value>| {
            let mut envelope = serde_json::json!({
                "version": 2,
                "sequence_num": 3,
                "capabilities": 1,
                "transport": "websocket",
                "last_seen_ms": 5,
                "restart_pending": false,
                "effective_config": "receivers: {}\n",
                "config_assignments": pins
            });
            if let Some(package) = package {
                envelope["package_assignment"] = package;
            }
            json(envelope)
        };
        write(
            &config_dir.join(format!("agents/{released}.json")),
            envelope(
                serde_json::json!({"base": revision_hash(&v1)}),
                Some(serde_json::json!({"deployment": "stable", "package": "otelcol@1.0.0"})),
            ),
        );
        write(
            &config_dir.join(format!("agents/{unreleased}.json")),
            envelope(serde_json::json!({"base": revision_hash(&v2)}), None),
        );
        write(
            &config_dir.join(format!("labels/{released}.json")),
            json(serde_json::json!({"channel": "stable"})),
        );

        Old {
            config_dir,
            packages_dir,
            uploaded,
            signature,
            issued,
            bootstrap,
            released,
            unreleased,
            audit,
        }
    }

    /// `server migrate` over the layout a 0.5 Server wrote carries the register, the revocation
    /// list, the hosts, the bootstrap entries, the audit files, the Agents with their labels, and
    /// the artifacts with their signatures; it drops a referenced entry and lists every
    /// Configuration's old Selector, and a Configuration without an Agent type it lists and does
    /// not carry, leaving its file — and the new data directory opens as the Server opens it.
    /// Verifies: ADR-0037
    #[test]
    fn migrate_carries_an_old_layout_into_a_data_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = old_layout(root.path());
        let data_dir = root.path().join("fleet-data");
        let report = run(&old.config_dir, &old.packages_dir, &data_dir).expect("migrate");
        let text = report.lines.join("\n");
        assert!(!report.trust_failed, "{text}");

        // Trust data, whole.
        let ledger = fs::FsLedgerStore::open(&data_dir)
            .expect("open")
            .load()
            .expect("load");
        assert_eq!(ledger.issued, vec![old.issued.clone()]);
        assert_eq!(
            ledger.revocations.len(),
            1,
            "the credential entry is dropped on load"
        );
        assert_eq!(ledger.revocations[0].id, "r2");
        assert!(ledger.hosts["gw"].gateway);
        assert!(ledger.hosts["h1"].instance_uids.contains(&old.released));
        let bootstrap = fs::FsBootstrapStore::open(&data_dir).expect("open");
        assert_eq!(bootstrap.load().expect("load"), vec![old.bootstrap.clone()]);
        assert_eq!(
            bootstrap.p12(&old.bootstrap.id).expect("read"),
            Some(b"sealed".to_vec())
        );
        assert!(text.contains("c6.p12"), "the stray file is named: {text}");
        assert_eq!(
            std::fs::read_to_string(data_dir.join("audit/audit-1.jsonl")).expect("audit"),
            old.audit,
            "copied, not rewritten"
        );
        assert!(text.contains("the chain holds"), "{text}");

        // Packages: the artifact is a blob, signed as its Deployments held it; the referenced
        // entry is dropped with a line.
        let packages = crate::packages::PackageStore::open(data_dir.clone()).expect("packages");
        let id = PackageId::new("otelcol", "1.0.0").expect("id");
        let summary = packages.summary(&id).expect("carried");
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(
            summary.entries[0].signature.as_deref(),
            Some(old.signature.as_str())
        );
        assert_eq!(
            summary.entries[0].content_hash,
            hex::encode(Sha256::digest(&old.uploaded))
        );
        assert!(data_dir
            .join("blobs")
            .join(hex::encode(Sha256::digest(&old.uploaded)))
            .is_file());
        assert!(
            text.contains("dropped: otelcol@1.0.0 for windows-amd64 — a referenced entry"),
            "{text}"
        );

        // Deployments keep their content; Configurations lose their Selector and are listed.
        let deployments = fs::FsDeploymentBackend::open(&data_dir)
            .expect("open")
            .load()
            .expect("load");
        assert_eq!(deployments.len(), 2);
        assert!(deployments
            .iter()
            .all(|d| d.package_for("otelcol") == Some(&id)));
        assert!(
            text.contains("listed: Configuration base had the Selector {os.type = \"linux\"}"),
            "{text}"
        );
        assert!(
            text.contains("listed: Configuration extra had the Selector {}"),
            "{text}"
        );
        assert!(
            text.contains("listed: Configuration untyped was not carried")
                && text.contains("service_name")
                && text.contains(&old.config_dir.join("untyped.json").display().to_string()),
            "{text}"
        );
        assert!(
            !data_dir.join("configurations/untyped.json").exists(),
            "an untyped Configuration is not carried"
        );
        assert!(
            old.config_dir.join("untyped.json").is_file(),
            "its file stays in the old directory"
        );
        assert!(
            text.contains("opened: "),
            "the data directory opens without it: {text}"
        );

        // Agents: labels inside; the release through a Deployment keeps its Package, and every
        // Configuration pin — released without a Deployment — is dropped and listed per Agent.
        let state = crate::fleet::AppState::new(data_dir.clone()).expect("the fleet opens");
        let base = state.configurations().get("base").expect("base");
        assert!(
            base.retained.is_empty(),
            "no pin is carried, so the revisions only the pins referenced are collected"
        );
        let agents = fs::FsAgentStore::open(&data_dir)
            .expect("open")
            .load()
            .expect("load");
        let released = &agents[&opamp::uid::InstanceUid::parse(&old.released).expect("uid")];
        assert_eq!(released.labels["channel"], "stable");
        let assignment = released.assignment.as_ref().expect("kept");
        assert_eq!(assignment.deployment, "stable");
        assert_eq!(assignment.package.as_ref(), Some(&id));
        assert!(
            assignment.configurations.is_empty(),
            "a pin released without a Deployment has no place in one"
        );
        let unreleased = &agents[&opamp::uid::InstanceUid::parse(&old.unreleased).expect("uid")];
        assert!(unreleased.assignment.is_none());
        for uid in [&old.released, &old.unreleased] {
            assert!(
                text.contains(&format!(
                    "dropped: the Configuration pins of Agent {uid} (base@"
                )),
                "{text}"
            );
        }

        // The old directories are the backup: nothing was moved.
        assert!(old.config_dir.join("revocation/revocations.json").is_file());
        assert!(old
            .packages_dir
            .join("otelcol@1.0.0/linux-amd64.bin")
            .is_file());
    }

    /// An entry its Deployments held different signatures for is carried unsigned and named.
    /// Verifies: ADR-0037
    #[test]
    fn differing_signatures_leave_the_entry_unsigned_and_named() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = old_layout(root.path());
        let canary = old.packages_dir.join("deployments/canary.json");
        let text = std::fs::read_to_string(&canary).expect("read");
        std::fs::write(&canary, text.replace(&old.signature, &"cd".repeat(64))).expect("write");
        let data_dir = root.path().join("fleet-data");
        let report = run(&old.config_dir, &old.packages_dir, &data_dir).expect("migrate");
        let text = report.lines.join("\n");
        assert!(
            text.contains("unsigned — Deployments canary, stable held different signatures"),
            "{text}"
        );
        let packages = crate::packages::PackageStore::open(data_dir).expect("packages");
        let id = PackageId::new("otelcol", "1.0.0").expect("id");
        assert_eq!(
            packages.summary(&id).expect("carried").entries[0].signature,
            None
        );
    }

    /// A Package deleted before the migration but still named in a Deployment is not carried
    /// into that Deployment, and the report names it.
    /// Verifies: ADR-0037
    #[test]
    fn a_deployment_naming_a_deleted_package_loses_that_name() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = old_layout(root.path());
        let canary = old.packages_dir.join("deployments/canary.json");
        let text = std::fs::read_to_string(&canary).expect("read");
        std::fs::write(&canary, text.replace("1.0.0", "0.9.0")).expect("write");
        let data_dir = root.path().join("fleet-data");
        let report = run(&old.config_dir, &old.packages_dir, &data_dir).expect("migrate");
        let text = report.lines.join("\n");
        assert!(
            text.contains(
                "dropped: Package otelcol 0.9.0 from Deployment canary — no such Package"
            ),
            "{text}"
        );
        let canary = fs::FsDeploymentBackend::open(&data_dir)
            .expect("deployments")
            .load()
            .expect("load")
            .into_iter()
            .find(|deployment| deployment.name == "canary")
            .expect("carried");
        assert!(canary.packages.is_empty());
    }

    /// A Package whose metadata does not carry leaves every Deployment that named it, and an
    /// Agent's Package assignment through it is dropped with a line — though its directory still
    /// holds a `package.json`.
    /// Verifies: ADR-0037
    #[test]
    fn a_package_that_does_not_carry_leaves_its_deployments_and_assignments() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = old_layout(root.path());
        write(
            &old.packages_dir.join("otelcol@1.0.0/package.json"),
            b"not json",
        );
        let data_dir = root.path().join("fleet-data");
        let report = run(&old.config_dir, &old.packages_dir, &data_dir).expect("migrate");
        let text = report.lines.join("\n");
        assert!(!report.trust_failed, "the new data directory opens: {text}");
        for name in ["canary", "stable"] {
            assert!(
                text.contains(&format!(
                    "dropped: Package otelcol 1.0.0 from Deployment {name} — no such Package"
                )),
                "{text}"
            );
        }
        let deployments = fs::FsDeploymentBackend::open(&data_dir)
            .expect("deployments")
            .load()
            .expect("load");
        assert!(deployments.iter().all(|d| d.packages.is_empty()));
        let agents = fs::FsAgentStore::open(&data_dir)
            .expect("open")
            .load()
            .expect("load");
        let released = &agents[&opamp::uid::InstanceUid::parse(&old.released).expect("uid")];
        assert!(released.assignment.is_none());
        assert!(
            text.contains(&format!(
                "dropped: the Package assignment of Agent {}",
                old.released
            )),
            "{text}"
        );
    }

    /// An artifact whose bytes do not match its own entry's recorded hash is dropped, and the blob
    /// of those bytes stays when another carried entry holds the same bytes.
    /// Verifies: ADR-0037
    #[test]
    fn a_mismatching_artifact_leaves_the_blob_another_entry_holds() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = old_layout(root.path());
        write(
            &old.packages_dir.join("otelcol@1.1.0/package.json"),
            json(serde_json::json!({
                "agent_type": "otelcol",
                "version": "1.1.0",
                "entries": [{"os": "linux", "arch": "amd64", "content_hash_hex": "11".repeat(32)}]
            })),
        );
        write(
            &old.packages_dir.join("otelcol@1.1.0/linux-amd64.bin"),
            &old.uploaded,
        );
        let data_dir = root.path().join("fleet-data");
        let report = run(&old.config_dir, &old.packages_dir, &data_dir).expect("migrate");
        let text = report.lines.join("\n");
        assert!(
            text.contains("dropped: otelcol@1.1.0 for linux-amd64 —")
                && text.contains("does not match its recorded hash"),
            "{text}"
        );
        assert!(!report.trust_failed, "the new data directory opens: {text}");
        let blob = data_dir
            .join("blobs")
            .join(hex::encode(Sha256::digest(&old.uploaded)));
        assert!(blob.is_file(), "otelcol@1.0.0's artifact is still there");
        let packages = crate::packages::PackageStore::open(data_dir).expect("packages");
        let id = PackageId::new("otelcol", "1.0.0").expect("id");
        assert_eq!(packages.summary(&id).expect("carried").entries.len(), 1);
    }

    /// The migration writes into an empty data directory only, and trust data it cannot carry
    /// makes it fail.
    /// Verifies: ADR-0037
    #[test]
    fn migrate_refuses_a_data_directory_that_is_not_empty_and_fails_on_lost_trust_data() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = old_layout(root.path());
        let data_dir = root.path().join("fleet-data");
        write(&data_dir.join("agents/keep.json"), b"{}");
        let error = run(&old.config_dir, &old.packages_dir, &data_dir).expect_err("refused");
        assert!(error.contains("not empty"), "{error}");
        assert_eq!(
            std::fs::read(data_dir.join("agents/keep.json")).expect("untouched"),
            b"{}"
        );

        let data_dir = root.path().join("other");
        write(&old.config_dir.join("revocation/hosts.json"), b"not json");
        let report = run(&old.config_dir, &old.packages_dir, &data_dir).expect("migrate");
        assert!(report.trust_failed);
        assert!(
            report
                .lines
                .iter()
                .any(|line| line.starts_with("FAILED: the hosts")),
            "{:?}",
            report.lines
        );
    }
}
