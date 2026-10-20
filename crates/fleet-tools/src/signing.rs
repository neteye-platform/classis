//! The signing file (ADR-0027): what a Package's signatures cover, carried from the bundled UI to
//! the machine that holds the key, and the signatures carried back.
//!
//! The file is read whole and checked whole before anything is signed — a file with one bad entry
//! signs nothing — and every signature is made over [`fleet_core::package::statement`], the same
//! bytes `package sign` signs from an artifact, so the Client cannot tell the two forms apart.
//!
//! What it does **not** do is check a hash against anything: the hashes are the Server's, and
//! comparing them with upstream's checksums or with the files is the operator's duty (ADR-0027
//! point 4). The tool prints each one as it signs it so the comparison has something to look at.

use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// The one format this tool reads and writes. Another value is refused rather than guessed at: a
/// later format is a new value, never an edit of this one.
pub const FORMAT: &str = "opamp-fleet-signing-v1";

/// A signing file is a handful of lines per platform; anything near this is not one.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Far beyond the platforms a release publishes, and a bound on what one file can make the key do.
const MAX_ENTRIES: usize = 64;

/// One Package's signing file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningFile {
    format: String,
    agent_type: String,
    version: String,
    entries: Vec<Entry>,
}

/// One platform's entry: what the Package holds for it, and once signed, the signature.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    os: String,
    arch: String,
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

/// Reads and checks a signing file: the format, every hash's shape, and no platform twice.
///
/// # Errors
/// Returns what is wrong with the file; nothing has been signed when it does.
pub fn read(path: &Path) -> Result<SigningFile, String> {
    let shown = path.display();
    let size = std::fs::metadata(path)
        .map_err(|e| format!("cannot read {shown}: {e}"))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(format!(
            "{shown} is {size} bytes — a signing file is far smaller"
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let file: SigningFile =
        serde_json::from_str(&text).map_err(|e| format!("{shown} is not a signing file: {e}"))?;
    file.check().map_err(|e| format!("{shown}: {e}"))?;
    Ok(file)
}

impl SigningFile {
    fn check(&self) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!(
                "format {:?} is not {FORMAT:?}, the one this tool signs",
                self.format
            ));
        }
        if self.agent_type.is_empty() || self.version.is_empty() {
            return Err("the agent_type and the version must both be named".to_string());
        }
        // The key never signs a version a Client would refuse (ADR-0043 clause 4).
        crate::package::require_semver(&self.version)?;
        if self.entries.is_empty() {
            return Err("there are no entries to sign".to_string());
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(format!(
                "{} entries — no Package holds more than {MAX_ENTRIES}",
                self.entries.len()
            ));
        }
        let mut seen = HashSet::new();
        for entry in &self.entries {
            let platform = format!("{}/{}", entry.os, entry.arch);
            if entry.os.is_empty() || entry.arch.is_empty() {
                return Err(format!("the entry {platform:?} names no platform"));
            }
            let hex_lower = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
            if entry.sha256.len() != 64 || !entry.sha256.chars().all(hex_lower) {
                return Err(format!(
                    "{platform}: the sha256 must be 64 lowercase hex characters"
                ));
            }
            if !seen.insert(platform.clone()) {
                return Err(format!("{platform} is named twice"));
            }
        }
        Ok(())
    }

    /// Signs every entry's statement, replacing a signature it already carried — the same key
    /// gives the same value again (Ed25519 is deterministic), another key's is the one meant.
    pub fn sign(&mut self, key: &Ed25519KeyPair) {
        for entry in &mut self.entries {
            // `read` let only 64 lowercase hex characters through.
            let hash = hex::decode(&entry.sha256).expect("a checked sha256 is hex");
            let statement = fleet_core::package::statement(&self.agent_type, &self.version, &hash);
            eprintln!(
                "  signing {}@{} {}/{}  {}",
                self.agent_type, self.version, entry.os, entry.arch, entry.sha256
            );
            entry.signature = Some(hex::encode(key.sign(&statement).as_ref()));
        }
    }

    /// Writes the file, signatures and all, in the shape the UI reads back.
    ///
    /// # Errors
    /// Returns the message when the file cannot be written.
    pub fn write(&self, path: &Path) -> Result<(), String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot write the signing file: {e}"))?;
        text.push('\n');
        std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    const HASH_A: &str = "127f9a4866448977b174bc2718e4d53646c7ff571782756837ae9bf1412cfb9e";
    const HASH_B: &str = "ee7df45231deda067856816d7735fe7bc5c2b9d7875bdece0461af056f6cfec8";

    fn key() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("pkcs8");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key")
    }

    fn file_with(dir: &Path, body: &serde_json::Value) -> std::path::PathBuf {
        let path = dir.join("signing.json");
        std::fs::write(&path, body.to_string()).expect("write");
        path
    }

    fn downloaded() -> serde_json::Value {
        serde_json::json!({
            "format": FORMAT,
            "agent_type": "supervisor",
            "version": "0.5.1",
            "entries": [
                { "os": "linux", "arch": "amd64", "sha256": HASH_A },
                { "os": "linux", "arch": "arm64", "sha256": HASH_B },
            ],
        })
    }

    /// Every signature written back verifies, with the public key, over exactly the statement the
    /// Client checks — Agent type, version and that entry's hash — and over no other entry's.
    /// Verifies: ADR-0027
    #[test]
    fn every_entry_is_signed_as_the_client_verifies_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = file_with(dir.path(), &downloaded());
        let key = key();

        let mut file = read(&path).expect("a downloaded file reads");
        file.sign(&key);
        let out = dir.path().join("signed.json");
        file.write(&out).expect("write");

        let signed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).expect("read")).expect("json");
        assert_eq!(signed["format"], FORMAT);
        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            key.public_key().as_ref().to_vec(),
        );
        for (index, hash) in [HASH_A, HASH_B].iter().enumerate() {
            let entry = &signed["entries"][index];
            let signature = hex::decode(entry["signature"].as_str().expect("signed")).expect("hex");
            assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");
            let statement = fleet_core::package::statement(
                "supervisor",
                "0.5.1",
                &hex::decode(hash).expect("hex"),
            );
            public
                .verify(&statement, &signature)
                .expect("the Client's check accepts it");
            let other = if index == 0 { HASH_B } else { HASH_A };
            let elsewhere = fleet_core::package::statement(
                "supervisor",
                "0.5.1",
                &hex::decode(other).expect("hex"),
            );
            assert!(
                public.verify(&elsewhere, &signature).is_err(),
                "a signature holds for its own entry alone"
            );
        }

        // Signing the signed file again gives the same values: re-running is harmless.
        let mut again = read(&out).expect("a signed file reads too");
        again.sign(&key);
        let again_out = dir.path().join("again.json");
        again.write(&again_out).expect("write");
        assert_eq!(
            std::fs::read_to_string(&out).expect("read"),
            std::fs::read_to_string(&again_out).expect("read")
        );
    }

    /// A file that is not exactly this format — another `format`, a hash of the wrong shape, a
    /// platform twice, a field nobody defined, nothing to sign — is refused at reading, so nothing
    /// in it reaches the key.
    /// Verifies: ADR-0027
    #[test]
    fn a_file_that_is_not_exactly_the_format_is_refused_before_anything_is_signed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("format", {
                let mut v = downloaded();
                v["format"] = "opamp-fleet-signing-v2".into();
                v
            }),
            ("uppercase hash", {
                let mut v = downloaded();
                v["entries"][0]["sha256"] = HASH_A.to_uppercase().into();
                v
            }),
            ("short hash", {
                let mut v = downloaded();
                v["entries"][0]["sha256"] = "127f".into();
                v
            }),
            ("platform twice", {
                let mut v = downloaded();
                v["entries"][1]["arch"] = "amd64".into();
                v
            }),
            ("unknown field", {
                let mut v = downloaded();
                v["entries"][0]["size"] = 7.into();
                v
            }),
            ("no entries", {
                let mut v = downloaded();
                v["entries"] = serde_json::json!([]);
                v
            }),
            ("no version", {
                let mut v = downloaded();
                v["version"] = "".into();
                v
            }),
        ];
        for (case, body) in cases {
            let path = file_with(dir.path(), &body);
            assert!(read(&path).is_err(), "{case}: refused");
        }

        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; (MAX_FILE_BYTES + 1) as usize]).expect("write");
        let error = read(&big).expect_err("an oversized file is refused unread");
        assert!(error.contains("far smaller"), "{error}");
    }
}
