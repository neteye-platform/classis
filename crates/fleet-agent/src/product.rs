//! The product's name and title, fixed at build time (ADR-0019 clause 2).
//!
//! Three names sit side by side in this program, each naming a different thing, and conflating any
//! two of them couples things that must be free to move apart:
//!
//! | name | names | appears in |
//! |---|---|---|
//! | [`PRODUCT_NAME`] | the **product** | the path, the service, the package, the `PATH` symlink |
//! | [`layout::BINARY_FILENAME`](crate::service::layout::BINARY_FILENAME) | the **program** | the file, its configuration, the archive member |
//! | [`CLIENT_AGENT_TYPE`](crate::supervisor::agent::CLIENT_AGENT_TYPE) | the **Agent type** | `service.name` on the wire, the package Set's key |
//!
//! The last two share the string `supervisor` and are separate constants on purpose. Keeping the
//! program's name off [`PRODUCT_NAME`] is what lets one published package Set serve every variant
//! build: the archive member a self-update extracts is the same in all of them.
//!
//! The values come from `build.rs`, which validates the grammar and fails the build on a name that
//! breaks it — so an illegal name cannot reach a service manager.

/// The product's name: the install directory, the service, the package, the `PATH` symlink.
///
/// Lowercase `[a-z0-9-]`, 1–32 characters, never a Windows reserved device name — the intersection
/// of the systemd-unit, launchd-label, SCM service-name and directory-name grammars, which is the
/// same grammar ADR-0019 set for instance names and for the reason.
pub const PRODUCT_NAME: &str = env!("OPAMP_PRODUCT_NAME");

/// The product's display name: prose, for the three places prose belongs — the Add/Remove Programs
/// entry, the SCM's display column, and the installer dialog's title.
///
/// It is deliberately not derived from [`PRODUCT_NAME`]: no rule that turns `opamp-fleet` into
/// `OpAMP Fleet Agent` would still read correctly for the next variant.
pub const PRODUCT_TITLE: &str = env!("OPAMP_PRODUCT_TITLE");

#[cfg(test)]
mod tests {
    use super::*;

    /// The build script is the only thing that can enforce the grammar, so this asserts what it
    /// let through rather than re-implementing the check.
    /// Verifies: ADR-0019
    #[test]
    fn product_name_satisfies_the_grammar() {
        assert!(!PRODUCT_NAME.is_empty() && PRODUCT_NAME.len() <= 32);
        assert!(PRODUCT_NAME
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
        assert!(!PRODUCT_NAME.starts_with('-') && !PRODUCT_NAME.ends_with('-'));
    }

    /// Verifies: ADR-0019
    #[test]
    fn display_name_is_prose() {
        assert!(!PRODUCT_TITLE.trim().is_empty());
    }
}
