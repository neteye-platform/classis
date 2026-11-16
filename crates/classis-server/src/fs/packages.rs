//! The package store's metadata on the filesystem (ADR-0026, ADR-0037): the default adapter behind
//! [`PackageBackend`](crate::packages::PackageBackend) — one JSON file per Package under
//! `<data_dir>/packages/`, its entries inside, each naming its artifact by hash. The bytes are the
//! blob store's.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::packages::{Entry, Package, PackageBackend, PackageId, Platform};

/// One file per Package, `<agent_type>@<version>.json`, owner-only.
pub struct FsPackageBackend {
    dir: PathBuf,
}

impl FsPackageBackend {
    /// Opens the store in the data directory `root`, creating `packages/` owner-only: what the
    /// fleet installs is not another local user's business on the Server host.
    pub fn open(root: &Path) -> Result<Self, String> {
        let dir = root.join(super::PACKAGES);
        super::create_private_dir(&dir)?;
        Ok(FsPackageBackend { dir })
    }

    fn path(&self, id: &PackageId) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }
}

impl PackageBackend for FsPackageBackend {
    /// A file that cannot be read, does not parse, or whose name disagrees with the identity it
    /// holds fails the open naming it; so does anything else in the directory (ADR-0037 clause 6).
    fn load(&self) -> Result<Vec<Package>, String> {
        let mut packages = Vec::new();
        for (stem, path) in super::json_files(&self.dir)? {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let meta: PackageMeta = serde_json::from_str(&text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            let id = PackageId::load(&meta.agent_type, &meta.version)
                .map_err(|e| format!("invalid identity in {}: {e}", path.display()))?;
            if id.to_string() != stem {
                return Err(super::misnamed(&path, "identity"));
            }
            let mut entries = BTreeMap::new();
            for entry in meta.entries {
                let platform = Platform::new(&entry.os, &entry.arch)
                    .map_err(|e| format!("invalid platform in {}: {e}", path.display()))?;
                let content_hash = hex::decode(&entry.sha256)
                    .ok()
                    .filter(|_| crate::blobs::is_hash(&entry.sha256))
                    .ok_or_else(|| format!("invalid sha256 in {}", path.display()))?;
                let signature = entry
                    .signature_hex
                    .map(hex::decode)
                    .transpose()
                    .map_err(|e| format!("invalid signature in {}: {e}", path.display()))?;
                // Held to the length a write is held to (ADR-0033 clause 6).
                if let Some(signature) = &signature {
                    if signature.len() != crate::packages::ED25519_SIGNATURE_LEN {
                        return Err(format!(
                            "invalid signature in {}: {} bytes, not {}",
                            path.display(),
                            signature.len(),
                            crate::packages::ED25519_SIGNATURE_LEN
                        ));
                    }
                }
                entries.insert(
                    platform.clone(),
                    Entry {
                        platform,
                        content_hash,
                        size: entry.size,
                        signature,
                    },
                );
            }
            packages.push(Package { id, entries });
        }
        Ok(packages)
    }

    fn put(&self, package: &Package) -> Result<(), String> {
        let meta =
            serde_json::to_vec_pretty(&PackageMeta::of(package)).expect("package serializes");
        super::replace_owner_only(&self.path(&package.id), &meta)
    }

    fn remove(&self, id: &PackageId) -> Result<(), String> {
        super::remove_file(&self.path(id))
    }
}

/// A Package as persisted: `packages/<agent_type>@<version>.json`, entries inline.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageMeta {
    agent_type: String,
    version: String,
    #[serde(default)]
    entries: Vec<EntryMeta>,
}

/// One entry as persisted: its platform, the blob that holds its bytes, named by hash only
/// (ADR-0037 clause 4), their size, and the operator's signature.
///
/// Unknown fields are refused, so an entry an older Server wrote — a reference to a source, or a
/// `content_hash_hex` beside an artifact file — fails the open naming the file rather than loading
/// as something it is not.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryMeta {
    os: String,
    arch: String,
    /// The SHA-256 of the artifact, lowercase hex: the blob's name, and what the Agent verifies.
    sha256: String,
    size: u64,
    /// The operator's Ed25519 signature over this entry, hex (ADR-0033); absent while unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature_hex: Option<String>,
}

impl PackageMeta {
    fn of(package: &Package) -> Self {
        PackageMeta {
            agent_type: package.id.agent_type.clone(),
            version: package.id.version.clone(),
            entries: package
                .entries
                .values()
                .map(|entry| EntryMeta {
                    os: entry.platform.os.clone(),
                    arch: entry.platform.arch.clone(),
                    sha256: hex::encode(&entry.content_hash),
                    size: entry.size,
                    signature_hex: entry.signature.as_ref().map(hex::encode),
                })
                .collect(),
        }
    }
}
