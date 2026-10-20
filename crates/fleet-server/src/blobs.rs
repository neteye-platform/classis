//! Artifact bytes, kept by their SHA-256 (ADR-0037 clause 4): the blob port.
//!
//! A Package entry names its artifact by the hash of its bytes and nothing else, so bytes held by
//! two entries are stored once, and a blob's name is its own integrity check. Which blobs are still
//! needed is the package store's to say: it deletes a blob when the last entry naming it goes, and
//! every blob no entry names when it opens.
//!
//! The filesystem adapter ([`FsBlobStore`](crate::fs::FsBlobStore)) keeps one file per blob in
//! `blobs/` under `data_dir`, and hashes every one of them again when it opens. An object store
//! would be another adapter of the same four operations.

use std::io::Read;

/// The blob port (ADR-0037 clause 4). A hash is the lowercase hex SHA-256 of the bytes.
pub trait BlobStore: Send + Sync {
    /// Stores the bytes `bytes` yields, hashing them on the way, and answers their hash and size.
    /// Bytes already stored are stored once. A stream that fails stores nothing.
    ///
    /// # Errors
    /// Returns an error when the stream fails or the bytes cannot be stored.
    fn put(&self, bytes: &mut dyn Read) -> Result<(String, u64), String>;

    /// The bytes of one blob, as a stream.
    ///
    /// # Errors
    /// Returns an error when no such blob is stored or it cannot be read.
    fn get(&self, sha256: &str) -> Result<Box<dyn Read + Send>, String>;

    /// Whether a blob of that hash is stored.
    fn exists(&self, sha256: &str) -> bool;

    /// Deletes one blob; one that is not stored is not an error.
    ///
    /// # Errors
    /// Returns an error when it cannot be deleted.
    fn delete(&self, sha256: &str) -> Result<(), String>;

    /// Every stored blob as `(hash, size)` — what the package store reads once when it opens, to
    /// know each entry's size and to delete what no entry names.
    ///
    /// # Errors
    /// Returns an error when the store cannot be listed.
    fn list(&self) -> Result<Vec<(String, u64)>, String>;
}

/// Whether `value` is a blob's name: 64 lowercase hex characters. Nothing else names a blob, so
/// nothing else can name a path.
#[must_use]
pub fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
