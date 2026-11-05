//! A downloaded package artifact unpacked for its one program: `.tar.gz`, `.zip` or `.7z`
//! (ADR-0026). Whatever the archive holds, only the one file this Client chose is written.
//! Verifies: Q-2
#![no_main]

use fleet_agent::archive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(work) = tempfile::tempdir() else {
        return;
    };
    let artifact = work.path().join("artifact");
    let out_path = work.path().join("program");
    if std::fs::write(&artifact, data).is_err() {
        return;
    }
    let Ok(mut out) = std::fs::File::create(&out_path) else {
        return;
    };
    let _ = match archive::detect(&artifact) {
        Ok(archive::Kind::TarGz) => archive::extract_tar_gz(&artifact, "agent", &mut out),
        Ok(archive::Kind::Zip) => archive::extract_zip(&artifact, "agent", &mut out),
        Ok(archive::Kind::SevenZ) => archive::extract_7z(&artifact, "agent", &mut out, None),
        _ => Ok(0),
    };
    let mut names: Vec<_> = std::fs::read_dir(work.path())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["artifact", "program"],
        "written beside the chosen file"
    );
});
