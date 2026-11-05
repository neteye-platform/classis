//! The Agent's Instance UID — the routing key of the whole protocol (ADR-0015).
//!
//! The Baseline requires the `instance_uid` to be 16 bytes and recommends UUID v7. Both ends route
//! by it and never by the connection, so it gets a real type here instead of `Vec<u8>` scattered
//! through both crates.

use std::fmt;

/// A 16-byte Agent identity, displayed in canonical UUID form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceUid(pub [u8; 16]);

impl InstanceUid {
    /// Parses the wire representation. The Baseline: *"MUST be 16 bytes long"* — anything else is
    /// a protocol error the caller reports, not a value to guess a meaning for.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        <[u8; 16]>::try_from(bytes).ok().map(InstanceUid)
    }

    /// Parses the canonical UUID string form (the persisted representation).
    pub fn parse(s: &str) -> Option<Self> {
        uuid::Uuid::parse_str(s.trim())
            .ok()
            .map(|u| InstanceUid(u.into_bytes()))
    }

    /// The wire representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Generates a fresh identity as a UUID v7, as the Baseline recommends (time-ordered, so fleet
/// listings sort by creation).
impl Default for InstanceUid {
    fn default() -> Self {
        InstanceUid(uuid::Uuid::now_v7().into_bytes())
    }
}

impl fmt::Display for InstanceUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        uuid::Uuid::from_bytes(self.0).fmt(f)
    }
}

impl fmt::Debug for InstanceUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InstanceUid({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_string_and_wire() {
        let uid = InstanceUid::default();
        let parsed = InstanceUid::parse(&uid.to_string()).expect("parse");
        assert_eq!(uid, parsed);
        let wire = InstanceUid::from_wire(uid.as_bytes()).expect("wire");
        assert_eq!(uid, wire);
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert!(InstanceUid::from_wire(&[1, 2, 3]).is_none());
        assert!(InstanceUid::parse("not-a-uuid").is_none());
    }

    #[test]
    fn generates_uuid_v7() {
        let uid = InstanceUid::default();
        assert_eq!(uuid::Uuid::from_bytes(uid.0).get_version_num(), 7);
    }
}
