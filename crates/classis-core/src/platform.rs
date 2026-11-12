//! This fleet's platform vocabulary: the spellings of an operating system and an architecture that
//! mean one canonical `os.type` / `host.arch` value (ADR-0026).
//!
//! The canonical tokens are the semantic conventions'; the alias table is this project's leniency,
//! so that a release file name and an Agent's report meet. Both ends read it, because they are two
//! halves of one comparison.

/// Spellings of an operating system that mean a canonical `os.type` value.
///
/// Deliberately short: it exists for what this project does **not** control — an older release file
/// name, a foreign build system, an Agent that predates the convention — not as a general
/// vocabulary. Everything this project produces is already canonical.
const OS_ALIASES: &[(&str, &str)] = &[
    ("macos", "darwin"),
    ("osx", "darwin"),
    ("win", "windows"),
    ("win32", "windows"),
    ("win64", "windows"),
];

/// Spellings of an architecture that mean a canonical `host.arch` value. Rust's own
/// `std::env::consts::ARCH` is among them, which is why an Agent reporting its platform reads the
/// same table the Server matches it against.
const ARCH_ALIASES: &[(&str, &str)] = &[
    ("x86_64", "amd64"),
    ("x86-64", "amd64"),
    ("x64", "amd64"),
    ("aarch64", "arm64"),
];

/// The canonical `os.type` for a spelling of it — the input unchanged when the table has never
/// heard of it.
///
/// One table for both ends, because they are two halves of one comparison: the Client writes this
/// value into its `os.type` attribute and the Server matches an artifact's platform against it
/// (ADR-0026). Two tables that disagreed would not fail — they would offer a host the wrong binary,
/// or none, and say nothing.
#[must_use]
pub fn canonical_os(raw: &str) -> &str {
    canonical(raw, OS_ALIASES)
}

/// The canonical `host.arch` for a spelling of it — the input unchanged when the table has never
/// heard of it. See [`canonical_os`] for why this is shared.
#[must_use]
pub fn canonical_arch(raw: &str) -> &str {
    canonical(raw, ARCH_ALIASES)
}

/// Unknown tokens pass through rather than being refused: the fleet may run a system this table has
/// never heard of, and serving it under its own name is a better failure than not serving it.
fn canonical<'a>(raw: &'a str, aliases: &[(&'static str, &'static str)]) -> &'a str {
    aliases
        .iter()
        .find(|(from, _)| from.eq_ignore_ascii_case(raw))
        .map_or(raw, |(_, to)| *to)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pairs both ends depend on agreeing: the Client writes the left, the Server matches an
    /// artifact's platform against the right (ADR-0026).
    /// Verifies: ADR-0026
    #[test]
    fn folds_the_spellings_this_project_does_not_control() {
        assert_eq!(canonical_os("macos"), "darwin");
        assert_eq!(canonical_os("osx"), "darwin");
        for win in ["win", "win32", "win64"] {
            assert_eq!(canonical_os(win), "windows");
        }
        assert_eq!(canonical_arch("x86_64"), "amd64");
        assert_eq!(canonical_arch("x86-64"), "amd64");
        assert_eq!(canonical_arch("x64"), "amd64");
        assert_eq!(canonical_arch("aarch64"), "arm64");
    }

    /// Rust names the host one way and the semantic conventions another, and this is the table that
    /// bridges them — so what a Client compiled by rustc reports is a token the Server knows.
    /// Verifies: ADR-0026
    #[test]
    fn what_rust_calls_this_machine_folds_onto_a_canonical_token() {
        assert_eq!(
            canonical_os(std::env::consts::OS),
            canonical_os(canonical_os(std::env::consts::OS)),
            "canonicalising twice is canonicalising once"
        );
        assert_eq!(
            canonical_arch("x86_64"),
            canonical_arch("amd64"),
            "rustc's spelling and the convention's are one machine"
        );
        assert_eq!(canonical_os("macos"), canonical_os("darwin"));
    }

    /// A system the table has never heard of is served under its own name rather than refused: a
    /// fleet may run one, and offering it nothing would be the worse failure.
    /// Verifies: ADR-0026
    #[test]
    fn an_unknown_token_passes_through_unchanged() {
        assert_eq!(canonical_os("plan9"), "plan9");
        assert_eq!(canonical_arch("riscv64"), "riscv64");
        assert_eq!(canonical_os(""), "");
        // Already canonical stays put — the table never folds a token onto another canonical one.
        for os in ["linux", "darwin", "windows"] {
            assert_eq!(canonical_os(os), os);
        }
        for arch in ["amd64", "arm64"] {
            assert_eq!(canonical_arch(arch), arch);
        }
    }
}
