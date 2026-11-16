//! No source of the product is conditional on macOS (ADR-0064 clause 2). Every Rust file under
//! `crates/` is read as text, so a branch is found whatever the host compiles, and whatever the
//! `cfg` it sits in.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Verifies: ADR-0064
#[test]
fn no_rust_source_names_target_os_macos() {
    // Joined here, so this file does not name it. Spaces are dropped before the match, so the
    // spelling without them is found as well.
    let needle = ["target_os", "=", "\"macos\""].concat();
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    files.sort();
    assert!(!files.is_empty(), "no Rust file under {}", crates.display());
    let mut found = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains(&needle) {
                found.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&crates).unwrap().display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a source conditional on macOS: {found:#?}"
    );
}
