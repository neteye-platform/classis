//! The OAuth-client storage port (ADR-0064 clauses 2 to 4).
//!
//! A client is one host: it is registered with its Space's key, authenticated by its client secret,
//! and admitted by the one access token it holds. The Server keeps only what it needs to *check*
//! those, never a value that could be presented: `SHA-256(client_secret)` and, beside it,
//! `SHA-256(access_token)` with its expiry — the token the client holds *now*. Issuing a token
//! overwrites the hash and the expiry, and that overwrite is the revocation of the token before
//! it ([`ClientStore::replace_token`]): there is no list of issued tokens.
//!
//! The adapters answer the admission question — who holds this token — without scanning: the
//! filesystem adapter from an index it loads when it opens and keeps current, as
//! [`AgentStore`](crate::agent_store::AgentStore) answers what is pinned, and a database from an
//! index of its own. A client is never deleted here (ADR-0064 puts an operator removing a host out
//! of scope).

/// A SHA-256 hash, of a client secret or of an access token.
pub type Hash = [u8; 32];

/// The longest client identifier a store takes.
pub const MAX_CLIENT_ID_LEN: usize = 64;

/// Whether `id` can name a client in every adapter: 1 to [`MAX_CLIENT_ID_LEN`] lowercase ASCII
/// letters, digits and `-`, which is how a UUID is written. No uppercase letter, so that two
/// identifiers are never one file on a filesystem that ignores case.
#[must_use]
pub fn is_valid_client_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_CLIENT_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The access token a client holds now, as the hash that is checked and the end of its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveToken {
    pub hash: Hash,
    /// When the token stops being accepted, in UNIX seconds; `None` — it never expires
    /// (ADR-0064 clause 5).
    pub expires_at: Option<u64>,
}

/// One client as it persists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRecord {
    /// The host's identity, a UUID version 7, made by the registration.
    pub client_id: String,
    /// The Space whose key registered it, as the key named it.
    pub space: String,
    pub secret_hash: Hash,
    /// `client_id_issued_at`, in UNIX seconds.
    pub issued_at: u64,
    /// `None` until a token is issued.
    pub token: Option<ActiveToken>,
}

impl ClientRecord {
    /// Whether the record is one a store may hold: an identifier every adapter can name and a
    /// Space name inside the pattern.
    ///
    /// # Errors
    /// Returns what is wrong.
    pub fn check(&self) -> Result<(), String> {
        if !is_valid_client_id(&self.client_id) {
            return Err(format!(
                "client {:?}: an identifier is 1 to {MAX_CLIENT_ID_LEN} lowercase letters, digits \
                 and '-'",
                self.client_id
            ));
        }
        classis_core::enrolment_key::validate_space_name(&self.space)
            .map_err(|e| format!("client {}: its space: {e}", self.client_id))
    }
}

/// What admission needs to know of the client that holds a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub client_id: String,
    pub space: String,
    /// When the token stops being accepted; `None` — never. Whether it has stopped is the
    /// caller's, which has the clock.
    pub expires_at: Option<u64>,
}

/// What replacing a client's token came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenReplaced {
    /// There is no client of that identifier; nothing was written.
    NoSuchClient,
    /// The token was overwritten. `previous` is the hash of the one it revoked, so a caller can
    /// close what was admitted with it; `None` when the client held none.
    Replaced { previous: Option<Hash> },
}

/// The storage port of the clients (ADR-0064 clauses 2 to 4). Every operation is one step: it
/// either happened whole or left the clients as they were.
pub trait ClientStore: Send + Sync {
    /// Every client, sorted by identifier. For a copy of the records
    /// (`server migrate-to-postgres`); a record that cannot be read fails loudly.
    ///
    /// # Errors
    /// Returns an error when a record cannot be read or is not one a store may hold.
    fn load(&self) -> Result<Vec<ClientRecord>, String>;

    /// Adds a client. `Ok(false)`, and nothing written, when the identifier is taken.
    ///
    /// # Errors
    /// Returns an error when `client` is not a record a store may hold, when its token's hash is
    /// held by another client, or when it cannot be written.
    fn insert(&self, client: &ClientRecord) -> Result<bool, String>;

    /// `SHA-256(client_secret)` of the client, for the check of the token request; `None` for an
    /// unknown client.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    fn secret_hash(&self, client_id: &str) -> Result<Option<Hash>, String>;

    /// Overwrites the client's token — hash and expiry — which revokes the one before it.
    ///
    /// # Errors
    /// Returns an error when the hash is held by another client or the record cannot be written;
    /// the old token then stands.
    fn replace_token(&self, client_id: &str, token: &ActiveToken) -> Result<TokenReplaced, String>;

    /// The client whose active token has this hash; `None` when no client holds it — a token that
    /// was never issued, and one that has been replaced.
    ///
    /// # Errors
    /// Returns an error when the store cannot be read.
    fn find_by_token(&self, token_hash: &Hash) -> Result<Option<Admitted>, String>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn client(id: &str, space: &str, byte: u8) -> ClientRecord {
        ClientRecord {
            client_id: id.to_string(),
            space: space.to_string(),
            secret_hash: [byte; 32],
            issued_at: 1_790_000_000 + u64::from(byte),
            token: None,
        }
    }

    /// Verifies: ADR-0064
    #[test]
    fn a_client_identifier_is_a_name_every_adapter_can_give_a_file() {
        for good in [
            "0192f0c4-7b1e-7d2a-9c3b-4a5d6e7f8091",
            "a",
            "abc-123",
            &"a".repeat(64),
        ] {
            assert!(is_valid_client_id(good), "{good}");
        }
        for bad in [
            "",
            "A",
            "abc_d",
            "a b",
            "../x",
            "a/b",
            "é",
            "a.json",
            &"a".repeat(65),
        ] {
            assert!(!is_valid_client_id(bad), "{bad}");
        }
        assert!(client("0192-a", "prod", 1).check().is_ok());
        assert!(client("A", "prod", 1).check().is_err());
        assert!(client("a", "_prod", 1).check().is_err());
    }
}
