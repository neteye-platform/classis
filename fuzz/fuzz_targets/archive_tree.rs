//! A downloaded package artifact unpacked as a program tree: `.tar.gz`, `.zip` or `.7z`. Whatever
//! the archive names, nothing is written outside the destination directory. The destination sits
//! two levels down in a scratch directory, so a member climbing out with `..` lands where the
//! check sees it. Verifies: Q-2
#![no_main]

use std::path::Path;

use fleet_agent::archive;
use libfuzzer_sys::fuzz_target;

/// Every path under `dir` that is neither the artifact, the destination, nor a directory on the
/// way to it.
fn strays(dir: &Path, allowed: &[&Path], found: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if allowed.iter().any(|a| path == *a) {
            continue;
        }
        if allowed.iter().any(|a| a.starts_with(&path)) {
            strays(&path, allowed, found);
            continue;
        }
        found.push(path);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(work) = tempfile::tempdir() else {
        return;
    };
    let artifact = work.path().join("artifact");
    let dest = work.path().join("a").join("b").join("dest");
    if std::fs::write(&artifact, data).is_err() || std::fs::create_dir_all(&dest).is_err() {
        return;
    }
    let program = Path::new("bin/agent");
    let _ = match archive::detect(&artifact) {
        Ok(archive::Kind::TarGz) => archive::extract_tree_tar_gz(&artifact, program, &dest).map(drop),
        Ok(archive::Kind::Zip) => archive::extract_tree_zip(&artifact, program, &dest).map(drop),
        Ok(archive::Kind::SevenZ) => archive::extract_tree_7z(&artifact, program, &dest, None).map(drop),
        _ => Ok(()),
    };
    let mut found = Vec::new();
    strays(work.path(), &[&artifact, &dest], &mut found);
    assert!(found.is_empty(), "written outside the destination: {found:?}");
});
