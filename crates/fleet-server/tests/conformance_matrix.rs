//! The capability matrix of `docs/CONFORMANCE.md` against the code (goal G-12): every capability
//! of the Baseline has a row, each row's bit is the Baseline's, and a capability is listed as
//! implemented or partial exactly when the side it belongs to declares it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use opamp::proto::{AgentCapabilities, ServerCapabilities};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The rows of the table under `heading`: capability name to (bit, status).
fn matrix(heading: &str) -> BTreeMap<String, (String, String)> {
    let text = std::fs::read_to_string(workspace().join("docs/CONFORMANCE.md")).expect("read");
    let section = text
        .split(&format!("\n## {heading}\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("no section {heading:?}"));
    let section = section.split("\n## ").next().expect("a section");
    section
        .lines()
        .filter(|line| line.starts_with("| `"))
        .map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let unquote = |cell: &str| cell.trim_matches('`').to_string();
            (unquote(cells[1]), (unquote(cells[2]), cells[5].to_string()))
        })
        .collect()
}

/// The non-test Rust source under `dirs`: everything before a file's first `#[cfg(test)]`.
fn source(dirs: &[&str]) -> String {
    fn walk(dir: &Path, out: &mut String) {
        for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "bin") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).expect("read");
                let code = text.split("#[cfg(test)]").next().unwrap_or_default();
                for line in code.lines() {
                    if !line.trim_start().starts_with("//") {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
            }
        }
    }
    let mut out = String::new();
    for dir in dirs {
        walk(&workspace().join(dir), &mut out);
    }
    out
}

/// Checks one table against one enum: `variants` are (Rust name, proto name, bit).
fn check(heading: &str, enum_name: &str, variants: &[(String, String, i32)], code: &str) {
    let rows = matrix(heading);
    let mut problems = Vec::new();
    for (rust, proto, bit) in variants {
        let Some((listed_bit, status)) = rows.get(proto) else {
            problems.push(format!("{proto} has no row"));
            continue;
        };
        let expected = format!("0x{bit:04X}");
        if !listed_bit.eq_ignore_ascii_case(&expected) {
            problems.push(format!(
                "{proto}: bit {listed_bit}, the Baseline says {expected}"
            ));
        }
        let declared = code.contains(&format!("{enum_name}::{rust}"));
        let listed = matches!(status.as_str(), "implemented" | "partial");
        if declared != listed {
            problems.push(format!(
                "{proto}: listed {status:?}, but the code {} it",
                if declared {
                    "declares"
                } else {
                    "never declares"
                }
            ));
        }
    }
    for name in rows.keys() {
        if !variants.iter().any(|(_, proto, _)| proto == name) {
            problems.push(format!("{name} is listed but not in the Baseline"));
        }
    }
    assert!(
        problems.is_empty(),
        "{heading}:\n  {}",
        problems.join("\n  ")
    );
}

fn variants<E: std::fmt::Debug>(
    from: impl Fn(i32) -> Option<E>,
    name: impl Fn(&E) -> &'static str,
    prefix: &str,
) -> Vec<(String, String, i32)> {
    (0..31)
        .map(|shift| 1i32 << shift)
        .filter_map(|bit| from(bit).map(|value| (value, bit)))
        .map(|(value, bit)| {
            (
                format!("{value:?}"),
                name(&value).trim_start_matches(prefix).to_string(),
                bit,
            )
        })
        .collect()
}

/// Verifies: G-12
#[test]
fn the_agent_capability_matrix_matches_what_the_client_declares() {
    check(
        "Agent capabilities",
        "AgentCapabilities",
        &variants(
            |bit| AgentCapabilities::try_from(bit).ok(),
            |value| value.as_str_name(),
            "AgentCapabilities_",
        ),
        &source(&["crates/fleet-agent/src", "crates/opamp/src"]),
    );
}

/// Verifies: G-12
#[test]
fn the_server_capability_matrix_matches_what_the_server_declares() {
    check(
        "Server capabilities",
        "ServerCapabilities",
        &variants(
            |bit| ServerCapabilities::try_from(bit).ok(),
            |value| value.as_str_name(),
            "ServerCapabilities_",
        ),
        &source(&["crates/fleet-server/src"]),
    );
}
