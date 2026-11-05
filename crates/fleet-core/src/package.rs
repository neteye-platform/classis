//! What a package signature covers (ADR-0026): not the artifact's bytes alone, but which Agent type
//! the artifact is for, at which version, and its SHA-256 — so a signed artifact cannot be offered
//! as another type's program, or under another version.

/// The bytes an operator signs and a Client verifies for one artifact:
/// `opamp-fleet-package-v1`, the Agent type, the version and the artifact's SHA-256 in lowercase
/// hex, one per line, each line ended by a newline.
#[must_use]
pub fn statement(agent_type: &str, version: &str, content_hash: &[u8]) -> Vec<u8> {
    let mut hex = String::with_capacity(content_hash.len() * 2);
    for byte in content_hash {
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    format!("opamp-fleet-package-v1\n{agent_type}\n{version}\n{hex}\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0026
    #[test]
    fn the_statement_names_type_version_and_hash() {
        assert_eq!(
            statement("otelcol-contrib", "0.110.0", &[0x0a, 0xff]),
            b"opamp-fleet-package-v1\notelcol-contrib\n0.110.0\n0aff\n".to_vec()
        );
        assert_ne!(
            statement("a", "1", &[1]),
            statement("b", "1", &[1]),
            "the type is covered"
        );
        assert_ne!(
            statement("a", "1", &[1]),
            statement("a", "2", &[1]),
            "the version is covered"
        );
    }
}
