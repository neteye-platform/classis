//! The audit record's port (ADR-0022): what a security decision records, and the trait it is
//! recorded through. The record itself — the hash chain, the file, the writer — is the adapter
//! [`crate::audit_log::AuditLog`].

use std::collections::BTreeMap;
use std::net::IpAddr;

/// One field of an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    Text(String),
    Unsigned(u64),
    Signed(i64),
}

/// What can be a field; `None` is no field at all.
pub trait IntoField {
    fn into_field(self) -> Option<Field>;
}

/// The longest text a field keeps, in bytes. A user name or a path can come from a peer that was
/// not admitted; cut short, a flood of them cannot fill the record or rotate it away.
pub const MAX_TEXT: usize = 256;

fn bounded(text: &str) -> String {
    if text.len() <= MAX_TEXT {
        return text.to_string();
    }
    let mut end = MAX_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

impl IntoField for String {
    fn into_field(self) -> Option<Field> {
        Some(Field::Text(bounded(&self)))
    }
}

impl IntoField for &str {
    fn into_field(self) -> Option<Field> {
        Some(Field::Text(bounded(self)))
    }
}

macro_rules! unsigned {
    ($($t:ty),*) => {$(
        impl IntoField for $t {
            fn into_field(self) -> Option<Field> {
                Some(Field::Unsigned(self as u64))
            }
        }
    )*};
}
unsigned!(u64, u32, u16, usize);

macro_rules! signed {
    ($($t:ty),*) => {$(
        impl IntoField for $t {
            fn into_field(self) -> Option<Field> {
                Some(Field::Signed(i64::from(self)))
            }
        }
    )*};
}
signed!(i64, i32);

impl<T: IntoField> IntoField for Option<T> {
    fn into_field(self) -> Option<Field> {
        self.and_then(IntoField::into_field)
    }
}

/// One decision, before it has a place in the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub event: String,
    pub outcome: String,
    pub fields: BTreeMap<String, Field>,
}

impl Entry {
    #[must_use]
    pub fn new(event: &str, outcome: &str) -> Self {
        Entry {
            event: event.to_string(),
            outcome: outcome.to_string(),
            fields: BTreeMap::new(),
        }
    }

    /// Adds a field; `None` adds nothing.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl IntoField) -> Self {
        if let Some(value) = value.into_field() {
            self.fields.insert(key.to_string(), value);
        }
        self
    }

    /// The peer address, where one is known.
    #[must_use]
    pub fn peer(self, peer: Option<IpAddr>) -> Self {
        self.with("peer", peer.map(|ip| ip.to_string()))
    }

    /// Whether the entry records a refusal — what the record aggregates past a rate.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(self.outcome.as_str(), "refused" | "throttled")
    }
}

/// Recording is not possible right now; the caller refuses what it was about to allow.
#[derive(Debug, PartialEq, Eq)]
pub struct Unavailable;

/// The record every security decision goes to (ADR-0022 clause 6).
pub trait Audit: Send + Sync {
    /// Records one decision; without a record the caller does not take it.
    ///
    /// # Errors
    /// Answers [`Unavailable`] while recording is not possible.
    fn record(&self, entry: Entry) -> Result<(), Unavailable>;

    /// Records a refusal; the caller refuses either way.
    fn refusal(&self, entry: Entry) {
        let _ = self.record(entry);
    }
}
