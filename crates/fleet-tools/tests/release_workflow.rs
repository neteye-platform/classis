//! The release workflow, read as data (ADR-0028 clauses 17 to 19): which rows build and publish the
//! operator tool, how its archives are named, packed and checked, and that what selects the
//! Client's archives never picks up one of the operator tool's. Read as text, step by step — the
//! workflow is the contract, and parsing its YAML would add a dependency to state what a line says.

use std::collections::BTreeMap;
use std::path::Path;

fn workflow() -> String {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml");
    std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()))
}

/// The rows of the build matrix: each `- { key: value, … }` line, as a map.
fn matrix_rows(workflow: &str) -> Vec<BTreeMap<String, String>> {
    workflow
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("- { ")?.strip_suffix(" }"))
        .map(|row| {
            row.split(", ")
                .map(|pair| {
                    let (key, value) = pair.split_once(": ").expect("key: value");
                    (key.to_string(), value.trim_matches('"').to_string())
                })
                .collect()
        })
        .collect()
}

/// The build job's step called `name`: its lines from `- name:` up to the next step.
fn step<'w>(workflow: &'w str, name: &str) -> &'w str {
    let start = workflow
        .find(&format!("- name: {name}\n"))
        .unwrap_or_else(|| panic!("no step {name:?}"));
    let rest = &workflow[start..];
    let end = rest[1..]
        .find("\n      - ")
        .map_or(rest.len(), |end| end + 1);
    &rest[..end]
}

/// `*` against any run of characters — enough for the shell globs the notes write.
fn glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.starts_with(head)
                && (head.len()..=name.len())
                    .any(|i| name.is_char_boundary(i) && glob(tail, &name[i..]))
        }
    }
}

// Verifies: ADR-0028
#[test]
fn the_operator_tool_is_built_for_four_targets_and_its_version_asserted_where_it_runs() {
    let workflow = workflow();
    let rows = matrix_rows(&workflow);
    assert_eq!(rows.len(), 5, "the Client's five rows");
    let mut tool: Vec<&str> = rows
        .iter()
        .filter(|row| row["operator_tool"] == "true")
        .map(|row| row["target"].as_str())
        .collect();
    tool.sort_unstable();
    assert_eq!(
        tool,
        [
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu"
        ]
    );
    for row in &rows {
        if row["os"] == "windows" {
            assert_eq!(row["operator_tool"], "false", "no Windows operator tool");
        }
    }

    // Every row builds the packer for its runner, the Windows row included.
    let packer = step(&workflow, "Build the packer");
    assert!(!packer.contains("if:"), "{packer}");
    assert!(packer.contains("--bin opamp-fleetctl"), "{packer}");
    assert!(!packer.contains("--target"), "{packer}");

    let build = step(&workflow, "Build the operator tool");
    assert!(build.contains("if: matrix.operator_tool"), "{build}");
    assert!(
        build.contains("-p fleet-tools --bin opamp-fleetctl --target ${{ matrix.target }}"),
        "{build}"
    );

    let agrees = step(
        &workflow,
        "The operator tool agrees with the name it will be given",
    );
    assert!(
        agrees.contains("if: matrix.native && matrix.operator_tool"),
        "{agrees}"
    );
    assert!(
        agrees.contains("release/opamp-fleetctl --version"),
        "{agrees}"
    );
    assert!(
        agrees.contains("${{ needs.version.outputs.full }}"),
        "{agrees}"
    );
}

// Verifies: ADR-0028
#[test]
fn each_archive_is_named_like_the_clients_packed_by_the_tool_and_checksummed() {
    let workflow = workflow();
    assert!(workflow.contains("\n  OPERATOR_TOOL: opamp-fleetctl\n"));
    let pack = step(&workflow, "Pack the operator tool");
    assert!(pack.contains("if: matrix.operator_tool"), "{pack}");
    assert!(
        pack.contains(
            "name=\"${OPERATOR_TOOL}_${{ needs.version.outputs.version }}_${{ matrix.os }}_${{ matrix.arch }}.tar.gz\""
        ),
        "{pack}"
    );
    assert!(
        pack.contains("./target/release/opamp-fleetctl package pack \\"),
        "{pack}"
    );
    assert!(pack.contains("--format tar.gz"), "{pack}");
    // The member is named after the file packed: `opamp-fleetctl`.
    assert!(
        pack.contains("\"target/${{ matrix.target }}/release/opamp-fleetctl\")"),
        "{pack}"
    );
    assert!(!pack.contains("--program-name"), "{pack}");
    assert!(pack.contains("> \"$name.sha256\""), "{pack}");

    // Its checksum travels with it, and the publish job folds every `.sha256` into SHA256SUMS
    // and publishes every `.tar.gz`.
    let upload = workflow
        .split("- uses: actions/upload-artifact@")
        .find(|block| block.contains("steps.pack_tool.outputs.name"))
        .expect("an upload of the operator tool");
    assert!(upload.contains("if: matrix.operator_tool"), "{upload}");
    assert!(
        upload.contains("${{ steps.pack_tool.outputs.name }}.sha256"),
        "{upload}"
    );
    assert!(workflow.contains("cat -- *.sha256 | sort -k2 > SHA256SUMS"));
    assert!(workflow.contains("*.tar.gz *.deb *.rpm *.msi *.cdx.json SHA256SUMS"));

    // No installer carries it.
    for installer in [
        "Build the Debian and RPM packages",
        "Build the MSI",
        "Checksum the installers",
    ] {
        assert!(
            !step(&workflow, installer).contains("opamp-fleetctl")
                && !step(&workflow, installer).contains("OPERATOR_TOOL"),
            "{installer} names the operator tool"
        );
    }
    for packaging in [
        "../fleet-agent/Cargo.toml",
        "../../packaging/windows/supervisor.wxs",
    ] {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(packaging);
        let text = std::fs::read_to_string(&file).expect("read");
        assert!(!text.contains("opamp-fleetctl"), "{packaging}");
    }
}

// Verifies: ADR-0028
#[test]
fn the_notes_upload_loop_selects_the_clients_archives_alone() {
    let workflow = workflow();
    // The notes are written by the publishing step; the verification loop before it is not theirs.
    let loops: Vec<&str> = step(&workflow, "Publish the release")
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("for f in ") && line.contains(".tar.gz"))
        .collect();
    assert_eq!(loops.len(), 1, "{loops:?}");
    let pattern = loops[0]
        .strip_prefix("for f in ")
        .and_then(|rest| rest.strip_suffix("; do"))
        .expect("for f in <glob>; do")
        .replace("${{ env.ARTIFACT }}", "supervisor")
        .replace("\\${v}", "1.2.3");
    for client in [
        "supervisor_1.2.3_linux_amd64.tar.gz",
        "supervisor_1.2.3_windows_amd64.tar.gz",
    ] {
        assert!(glob(&pattern, client), "{pattern} misses {client}");
    }
    for tool in [
        "opamp-fleetctl_1.2.3_linux_amd64.tar.gz",
        "opamp-fleetctl_1.2.3_darwin_arm64.tar.gz",
    ] {
        assert!(!glob(&pattern, tool), "{pattern} matches {tool}");
    }
}

// Verifies: ADR-0028
#[test]
fn the_crate_declares_one_binary_and_no_library() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest: toml::Table = std::fs::read_to_string(dir.join("Cargo.toml"))
        .expect("read")
        .parse()
        .expect("parse");
    assert!(!manifest.contains_key("lib"), "a [lib] section");
    let bins = manifest["bin"].as_array().expect("[[bin]]");
    assert_eq!(bins.len(), 1);
    assert_eq!(bins[0]["name"].as_str(), Some("opamp-fleetctl"));
    assert_eq!(bins[0]["path"].as_str(), Some("src/main.rs"));
    // Nothing Cargo would discover on its own: no `src/lib.rs`, no `src/bin/`.
    assert!(!dir.join("src/lib.rs").exists());
    assert!(!dir.join("src/bin").exists());
}

/// The job called `name`: its lines from `  name:` up to the next line indented by two spaces.
fn job<'w>(workflow: &'w str, name: &str) -> &'w str {
    let start = workflow
        .find(&format!("\n  {name}:\n"))
        .unwrap_or_else(|| panic!("no job {name:?}"))
        + 1;
    let rest = &workflow[start..];
    let end = rest
        .match_indices("\n  ")
        .find(|(i, _)| {
            rest[i + 3..]
                .chars()
                .next()
                .is_some_and(|c| !c.is_whitespace())
        })
        .map_or(rest.len(), |(i, _)| i + 1);
    &rest[..end]
}

/// The words of the first line of `text` that starts with `prefix`, after it.
fn words_after<'w>(text: &'w str, prefix: &str) -> Vec<&'w str> {
    text.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no line {prefix:?} in {text}"))
        .split_whitespace()
        .collect()
}

/// The action a `uses:` value names, without its ref: the pin and its comment are ADR-0049's, and
/// `scripts/check-action-refs.sh` holds them.
fn action(uses: &str) -> &str {
    uses.split_once('@').map_or(uses, |(action, _)| action)
}

/// What every release publishes, as the `publish` job's globs name it (ADR-0045 clause 8).
const PUBLISHED: [&str; 6] = [
    "*.tar.gz",
    "*.deb",
    "*.rpm",
    "*.msi",
    "*.cdx.json",
    "SHA256SUMS",
];

// Verifies: ADR-0045
#[test]
fn only_the_publish_job_may_attest() {
    let workflow = workflow();
    let top = workflow
        .split_once("\npermissions:\n")
        .and_then(|(_, rest)| rest.split_once("\n\n"))
        .map(|(block, _)| block)
        .expect("a top-level permissions block");
    assert_eq!(top, "  contents: read");

    let publish = job(&workflow, "publish");
    let permissions = publish
        .split_once("    permissions:\n")
        .and_then(|(_, rest)| rest.split_once("    steps:\n"))
        .map(|(block, _)| block)
        .expect("the publish job's permissions");
    for grant in ["id-token: write", "attestations: write", "contents: write"] {
        assert!(
            permissions.contains(&format!("      {grant}\n")),
            "{permissions}"
        );
    }
    for grant in ["id-token:", "attestations:"] {
        assert_eq!(
            workflow.matches(grant).count(),
            1,
            "{grant} outside publish"
        );
    }

    // It runs no code of the repository and no action but the two it needs.
    assert!(!publish.contains("actions/checkout"), "{publish}");
    assert!(!publish.contains("cargo "), "{publish}");
    let uses: Vec<&str> = publish
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            line.strip_prefix("- uses: ")
                .or_else(|| line.strip_prefix("uses: "))
        })
        .map(action)
        .collect();
    assert_eq!(uses, ["actions/download-artifact", "actions/attest"]);

    // A dry run stops before it, so it attests nothing.
    assert!(
        publish.contains("    if: needs.version.outputs.publish == 'true'\n"),
        "{publish}"
    );
}

// Verifies: ADR-0045
#[test]
fn the_publish_job_attests_and_verifies_every_asset_before_it_publishes() {
    let workflow = workflow();
    let publish = job(&workflow, "publish");
    assert!(
        publish.contains("    needs: [version, build, sbom]\n"),
        "{publish}"
    );

    let order: Vec<usize> = [
        "Collect the checksums",
        "Attest the assets",
        "Every asset verifies",
        "Publish the release",
    ]
    .iter()
    .map(|name| {
        publish
            .find(&format!("- name: {name}\n"))
            .unwrap_or_else(|| panic!("no step {name:?} in publish"))
    })
    .collect();
    assert!(order.is_sorted(), "{order:?}");

    // One attestation, its subjects the files themselves: every asset and SHA256SUMS.
    let attest = step(publish, "Attest the assets");
    assert!(attest.contains("uses: actions/attest@"), "{attest}");
    assert!(!attest.contains("subject-checksums"), "{attest}");
    let subjects: Vec<&str> = attest
        .split_once("subject-path: |\n")
        .expect("subject-path")
        .1
        .lines()
        .take_while(|line| line.starts_with("            "))
        .map(str::trim)
        .map(|line| line.strip_prefix("artifacts/").unwrap_or(line))
        .collect();
    assert_eq!(subjects, PUBLISHED, "{attest}");

    // Each of them verifies as an operator verifies it, or nothing is published.
    let verify = step(publish, "Every asset verifies");
    assert!(verify.contains("set -euo pipefail"), "{verify}");
    let verified = words_after(verify, "for f in ");
    assert_eq!(
        verified[..PUBLISHED.len() - 1],
        PUBLISHED[..PUBLISHED.len() - 1]
    );
    assert_eq!(verified[PUBLISHED.len() - 1..], ["SHA256SUMS;", "do"]);
    for option in [
        "gh attestation verify \"$f\" --repo \"${{ github.repository }}\"",
        "--signer-workflow \"${{ github.repository }}/.github/workflows/release.yml\"",
        "--deny-self-hosted-runners",
    ] {
        assert!(verify.contains(option), "{option} in {verify}");
    }

    // And exactly that set is published.
    let release = step(publish, "Publish the release");
    assert!(release.contains("gh release create "), "{release}");
    let mut published = vec![PUBLISHED[0]];
    published.extend(words_after(release, "-- *.tar.gz "));
    assert_eq!(published, PUBLISHED, "{release}");
}

// Verifies: ADR-0045
#[test]
fn the_sbom_job_writes_one_sbom_per_program_and_target_with_a_pinned_tool() {
    let workflow = workflow();
    let sbom = job(&workflow, "sbom");
    assert!(sbom.contains("    needs: version\n"), "{sbom}");
    assert!(
        !sbom.contains("    if:"),
        "it runs on a dry run too: {sbom}"
    );
    assert!(!sbom.contains("permissions:"), "{sbom}");
    assert!(sbom.contains("persist-credentials: false"), "{sbom}");
    assert!(!sbom.contains("cache"), "{sbom}");

    // An exact version, built by cargo install; no action installs it.
    let install = step(sbom, "Install the SBOM tool");
    let version = install
        .split_once("run: cargo install --locked cargo-cyclonedx@")
        .expect("cargo install --locked cargo-cyclonedx@<version>")
        .1
        .trim_end();
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "not MAJOR.MINOR.PATCH: {version}"
    );
    let uses: Vec<&str> = sbom
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("- uses: "))
        .map(action)
        .collect();
    assert_eq!(uses, ["actions/checkout", "actions/upload-artifact"]);

    let write = step(sbom, "Write the SBOMs");
    for line in [
        "set -euo pipefail",
        "cargo cyclonedx --describe binaries --target \"$triple\" --format json --spec-version 1.5",
        "mv \"$1/$2_bin.cdx.json\" \"$3.cdx.json\"",
        "sha256sum \"$3.cdx.json\" > \"$3.cdx.json.sha256\"",
        "keep crates/fleet-agent supervisor \"${ARTIFACT}_${v}_${os}_${arch}\"",
        "if [ \"$tool\" = true ]; then\n              \
         keep crates/fleet-tools opamp-fleetctl \"${OPERATOR_TOOL}_${v}_${os}_${arch}\"",
        "git diff --exit-code Cargo.lock",
    ] {
        assert!(write.contains(line), "{line} in {write}");
    }

    // Its targets are the build matrix's rows, in order, with the same operator-tool flag.
    let rows: Vec<String> = write
        .split_once("done <<'EOF'\n")
        .expect("a here-document of targets")
        .1
        .lines()
        .map(str::trim)
        .take_while(|line| *line != "EOF")
        .map(str::to_string)
        .collect();
    let matrix: Vec<String> = matrix_rows(&workflow)
        .iter()
        .map(|row| {
            format!(
                "{} {} {} {}",
                row["target"], row["os"], row["arch"], row["operator_tool"]
            )
        })
        .collect();
    assert_eq!(rows, matrix);
    let tools = matrix.iter().filter(|row| row.ends_with(" true")).count();
    assert_eq!(matrix.len() + tools, 9, "nine SBOMs");

    // Uploaded with their checksums, which publish folds into SHA256SUMS.
    let upload = sbom
        .split_once("- uses: actions/upload-artifact@")
        .expect("an upload")
        .1;
    for path in [
        "*.cdx.json\n",
        "*.cdx.json.sha256\n",
        "if-no-files-found: error",
    ] {
        assert!(upload.contains(path), "{path} in {upload}");
    }
}

// Verifies: ADR-0045
#[test]
fn the_notes_say_how_to_verify() {
    let workflow = workflow();
    let notes = step(&workflow, "Publish the release");
    for line in [
        "## Verifying a download",
        "gh attestation verify SHA256SUMS --repo ${{ github.repository }} \\\\\n",
        "--signer-workflow ${{ github.repository }}/.github/workflows/release.yml\n",
        "sha256sum -c --ignore-missing SHA256SUMS",
        "| check what a binary is built from | the \\`<stem>.cdx.json\\` |",
        "Every asset is attested, and \\`SHA256SUMS\\` covers every asset above.",
    ] {
        assert!(notes.contains(line), "{line} in the notes");
    }
}
