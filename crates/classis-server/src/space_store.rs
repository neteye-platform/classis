//! The Space-record storage port.
//!
//! A Space is its name and its one active enrolment key. The key is persisted *whole*, in
//! recoverable form, so the same key can be read again after a restart; only an explicit rotation
//! replaces it ([`SpaceStore::replace_key`]). That makes a stored Space a secret whatever the
//! backend: the filesystem adapter ([`FsSpaceStore`](crate::fs::FsSpaceStore)) answers with an
//! owner-only directory and file, any other adapter with its own access control.
//!
//! Names are unique ignoring ASCII case: a name keeps the case it was created with, inside its key
//! too, but no two Spaces differ only in case. A name that is looked up is looked up *exactly*, so
//! a key whose space part differs only in case finds nothing. The port is not cached: every call
//! asks the backend, so a rotation is seen by the next lookup whoever made it.
//!
//! Spaces are never deleted: that is out of scope.

use classis_core::enrolment_key::{validate_space_name, EnrolmentKey};
use zeroize::Zeroizing;

/// One Space as it persists: the name as it was created, and the complete key.
#[derive(Clone, PartialEq, Eq)]
pub struct SpaceRecord {
    pub name: String,
    pub key: Zeroizing<String>,
}

impl std::fmt::Debug for SpaceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpaceRecord")
            .field("name", &self.name)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SpaceRecord {
    /// Whether the record is one a store may hold: a name inside the pattern and a key that is the
    /// key of exactly that name. Adapters check it on every write and every read, so a record
    /// that was edited by hand fails loudly instead of being served.
    ///
    /// # Errors
    /// Returns what is wrong, never the key.
    pub fn check(&self) -> Result<(), String> {
        check_key(&self.name, &self.key)
    }
}

/// Whether `key` is a well-formed enrolment key of the Space `name`, spelt exactly as `name` is.
///
/// # Errors
/// Returns what is wrong with the name or the key, never the key.
pub fn check_key(name: &str, key: &str) -> Result<(), String> {
    validate_space_name(name).map_err(|e| format!("space {name:?}: {e}"))?;
    let parsed = EnrolmentKey::parse(key).map_err(|e| format!("the key of space {name:?}: {e}"))?;
    if parsed.space() != name {
        return Err(format!("the key of space {name:?} names another space"));
    }
    Ok(())
}

/// The storage port of the Spaces. Every operation is one step: it either
/// happened whole or left the Space as it was.
pub trait SpaceStore: Send + Sync {
    /// Every Space, name and key, sorted by name. For a copy of the records
    /// (`server migrate-to-postgres`) and for listing names; a record that cannot be read fails
    /// loudly rather than being skipped.
    ///
    /// # Errors
    /// Returns an error when a record cannot be read or is not one a store may hold.
    fn load(&self) -> Result<Vec<SpaceRecord>, String>;

    /// Adds a Space. `Ok(false)`, and nothing written, when a Space of that name — ignoring ASCII
    /// case — exists already.
    ///
    /// # Errors
    /// Returns an error when `space` is not a record a store may hold, or cannot be written.
    fn create(&self, space: &SpaceRecord) -> Result<bool, String>;

    /// The Space called exactly `name`: `None` for a name that is unknown, and for one that
    /// differs from a Space's only in case.
    ///
    /// # Errors
    /// Returns an error when the record cannot be read.
    fn get(&self, name: &str) -> Result<Option<SpaceRecord>, String>;

    /// Replaces the key of the Space called exactly `name`, durably. `Ok(false)` when there is no
    /// such Space.
    ///
    /// # Errors
    /// Returns an error when `key` is not a well-formed key of `name`, or cannot be written; the
    /// old key then stands.
    fn replace_key(&self, name: &str, key: &str) -> Result<bool, String>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A well-formed key of `name` for tests: the secret is `seed` repeated, base64url, 43
    /// characters.
    pub(crate) fn key_of(name: &str, seed: char) -> Zeroizing<String> {
        let secret = seed
            .to_string()
            .repeat(classis_core::enrolment_key::SECRET_LEN);
        Zeroizing::new(
            EnrolmentKey::new(name, &secret)
                .expect("a well-formed key")
                .to_string(),
        )
    }

    pub(crate) fn space(name: &str, seed: char) -> SpaceRecord {
        SpaceRecord {
            name: name.to_string(),
            key: key_of(name, seed),
        }
    }

    #[test]
    fn a_record_is_one_a_store_may_hold_only_with_the_key_of_its_own_name() {
        assert_eq!(space("prod", 'a').check(), Ok(()));
        assert!(
            check_key("Prod", &key_of("prod", 'a')).is_err(),
            "case counts"
        );
        assert!(check_key("_prod", &key_of("prod", 'a')).is_err());
        assert!(check_key("prod", "cle1_prod_short").is_err());
        let shown = format!("{:?}", space("prod", 'q'));
        assert!(shown.contains("prod") && !shown.contains("qqqq"), "{shown}");
        let error = check_key("prod", &key_of("other", 'z')).expect_err("another space");
        assert!(!error.contains("zzzz"), "{error}");
    }
}
