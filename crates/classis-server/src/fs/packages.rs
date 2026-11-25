//! The package store's metadata on the filesystem: the default adapter behind
//! [`PackageBackend`](crate::packages::PackageBackend) — one JSON file per Package under
//! `<data_dir>/packages/`, its entries inside, each naming its artifact by hash. The bytes are the
//! blob store's.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::packages::{Entry, Package, PackageBackend, PackageId, Platform};

/// The largest manifest the Server reads from a Package Repository. One entry, its signature at
/// the longest a `PackageSignature` can be, takes some 4 KiB, so this holds dozens of platforms.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// Reads the manifest of one Package, the file `file_name` of a Package Repository, from `bytes`:
/// at most [`MAX_MANIFEST_BYTES`], which bounds what is held in memory before anything is parsed.
/// The format is the one this adapter writes under `<data_dir>/packages/`, so the data directory
/// of a Server is a repository too.
///
/// # Errors
/// Returns an error naming `file_name` when the manifest is larger than the limit, cannot be read
/// or parsed, holds an identity its name does not match, or an entry that is not well formed.
pub fn read_manifest(file_name: &str, bytes: &mut dyn std::io::Read) -> Result<Package, String> {
    let mut text = Vec::new();
    std::io::Read::take(bytes, MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut text)
        .map_err(|e| format!("cannot read {file_name}: {e}"))?;
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(too_large(file_name));
    }
    let stem = file_name
        .strip_suffix(".json")
        .filter(|stem| !stem.is_empty())
        .ok_or_else(|| format!("{file_name} is not named <agent_type>@<version>.json"))?;
    parse_manifest(stem, file_name, &text)
}

/// The refusal of a manifest larger than [`MAX_MANIFEST_BYTES`].
pub fn too_large(file_name: &str) -> String {
    format!("{file_name} is larger than {MAX_MANIFEST_BYTES} bytes, the limit of a manifest")
}

/// One Package from its manifest `text`, the file `name` whose stem is `stem`. Every signature is
/// `Withheld`: offered to nobody until the store's verifier has checked it.
fn parse_manifest(stem: &str, name: &str, text: &[u8]) -> Result<Package, String> {
    let meta: PackageMeta =
        serde_json::from_slice(text).map_err(|e| format!("cannot parse {name}: {e}"))?;
    let id = PackageId::load(&meta.agent_type, &meta.version)
        .map_err(|e| format!("invalid identity in {name}: {e}"))?;
    if id.to_string() != stem {
        return Err(super::misnamed(Path::new(name), "identity"));
    }
    let mut entries = BTreeMap::new();
    for entry in meta.entries {
        let platform = Platform::new(&entry.os, &entry.arch)
            .map_err(|e| format!("invalid platform in {name}: {e}"))?;
        let content_hash = hex::decode(&entry.sha256)
            .ok()
            .filter(|_| crate::blobs::is_hash(&entry.sha256))
            .ok_or_else(|| format!("invalid sha256 in {name}"))?;
        let signature = entry
            .signature_hex
            .map(hex::decode)
            .transpose()
            .map_err(|e| format!("invalid signature in {name}: {e}"))?;
        // Held to the length a PackageSignature can have.
        if let Some(signature) = &signature {
            if !crate::packages::signature_fits(signature) {
                return Err(format!(
                    "invalid signature in {name}: {} bytes, not 1 to {}",
                    signature.len(),
                    classis_core::package::MAX_SIGNATURE_LEN
                ));
            }
        }
        entries.insert(
            platform.clone(),
            Entry {
                platform,
                content_hash,
                size: entry.size,
                signature: signature.map(crate::packages::Signature::Withheld),
            },
        );
    }
    Ok(Package { id, entries })
}

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
    /// holds fails the open naming it; so does anything else in the directory.
    fn load(&self) -> Result<Vec<Package>, String> {
        let mut packages = Vec::new();
        for (stem, path) in super::json_files(&self.dir)? {
            let text =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            packages.push(parse_manifest(&stem, &path.display().to_string(), &text)?);
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

/// One entry as persisted: its platform, the blob that holds its bytes, named by hash only,
/// their size, and the operator's signature.
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
    /// The operator's Ed25519 signature over this entry, hex; absent while unsigned.
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
                    signature_hex: entry.signature.as_ref().map(|s| hex::encode(s.bytes())),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that never ends, counting the bytes taken from it.
    struct Endless(usize);

    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf.fill(b' ');
            self.0 += buf.len();
            Ok(buf.len())
        }
    }

    /// Verifies: Q-2
    #[test]
    fn a_manifest_is_bounded_before_it_is_parsed() {
        let mut endless = Endless(0);
        let refused = read_manifest("otelcol@1.0.0.json", &mut endless)
            .err()
            .expect("refused");
        assert!(refused.contains("is larger than"), "{refused}");
        assert_eq!(
            endless.0,
            MAX_MANIFEST_BYTES + 1,
            "no more is read than the limit"
        );

        let manifest = br#"{"agent_type": "otelcol", "version": "1.0.0", "entries": []}"#;
        let package = read_manifest("otelcol@1.0.0.json", &mut &manifest[..]).expect("reads");
        assert_eq!(package.id.to_string(), "otelcol@1.0.0");
        for name in ["otelcol@1.0.0", ".json", "otelcol@2.0.0.json"] {
            assert!(
                read_manifest(name, &mut &manifest[..]).is_err(),
                "{name} does not name the manifest"
            );
        }
    }
}
