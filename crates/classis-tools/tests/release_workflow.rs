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
    assert!(packer.contains("--bin classisctl"), "{packer}");
    assert!(!packer.contains("--target"), "{packer}");

    let build = step(&workflow, "Build the operator tool");
    assert!(build.contains("if: matrix.operator_tool"), "{build}");
    assert!(
        build.contains("-p classis-tools --bin classisctl --target ${{ matrix.target }}"),
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
    assert!(agrees.contains("release/classisctl --version"), "{agrees}");
    assert!(
        agrees.contains("${{ needs.version.outputs.full }}"),
        "{agrees}"
    );
}

// Verifies: ADR-0028
#[test]
fn each_archive_is_named_like_the_clients_packed_by_the_tool_and_checksummed() {
    let workflow = workflow();
    assert!(workflow.contains("\n  OPERATOR_TOOL: classisctl\n"));
    let pack = step(&workflow, "Pack the operator tool");
    assert!(pack.contains("if: matrix.operator_tool"), "{pack}");
    assert!(
        pack.contains(
            "name=\"${OPERATOR_TOOL}_${{ needs.version.outputs.version }}_${{ matrix.os }}_${{ matrix.arch }}.tar.gz\""
        ),
        "{pack}"
    );
    assert!(
        pack.contains("./target/release/classisctl package pack \\"),
        "{pack}"
    );
    assert!(pack.contains("--format tar.gz"), "{pack}");
    // The member is named after the file packed: `classisctl`.
    assert!(
        pack.contains("\"target/${{ matrix.target }}/release/classisctl\")"),
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
    assert!(workflow.contains("*.tar.gz *.tar.gz.sig *.deb *.rpm *.msi *.cdx.json SHA256SUMS"));

    // No installer carries it.
    for installer in [
        "Build the Debian and RPM packages",
        "Build the MSI",
        "Checksum the installers",
    ] {
        assert!(
            !step(&workflow, installer).contains("classisctl")
                && !step(&workflow, installer).contains("OPERATOR_TOOL"),
            "{installer} names the operator tool"
        );
    }
    for packaging in [
        "../classis-agent/Cargo.toml",
        "../../packaging/windows/supervisor.wxs",
    ] {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(packaging);
        let text = std::fs::read_to_string(&file).expect("read");
        assert!(!text.contains("classisctl"), "{packaging}");
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
        "classisctl_1.2.3_linux_amd64.tar.gz",
        "classisctl_1.2.3_darwin_arm64.tar.gz",
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
    assert_eq!(bins[0]["name"].as_str(), Some("classisctl"));
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

/// The action a `uses:` value names, without its ref: the pin and its comment are ADR-0060's, and
/// `scripts/check-action-refs.sh` holds them.
fn action(uses: &str) -> &str {
    uses.split_once('@').map_or(uses, |(action, _)| action)
}

/// What every release publishes, as the `publish` job's globs name it (ADR-0045 clause 8, with
/// the signatures ADR-0063 clause 15 keeps).
const PUBLISHED: [&str; 7] = [
    "*.tar.gz",
    "*.tar.gz.sig",
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
    let permissions = permissions(publish);
    // `packages: write` pushes the image's attestation and tags the image (ADR-0052 clause 11).
    for grant in [
        "id-token: write",
        "attestations: write",
        "contents: write",
        "packages: write",
    ] {
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
    assert_eq!(
        uses,
        [
            "actions/download-artifact",
            "actions/attest",
            "actions/attest"
        ]
    );

    // It downloads the SBOMs, the two programs' archives and the signatures (ADR-0063 clause 15),
    // and not the tracked certificate, which travels inside each signature, nor the Server's binaries, which ship inside the image alone,
    // nor the archives' lone checksums, which were the signing job's. Every artifact the workflow
    // uploads under another name is one of those, and the pattern names each.
    assert!(
        publish.contains(
            "          pattern: '{sbom,signatures,${{ env.ARTIFACT }}_*,${{ env.OPERATOR_TOOL }}_*}'\n"
        ),
        "{publish}"
    );
    let uploaded: Vec<&str> = workflow
        .split("- uses: actions/upload-artifact@")
        .skip(1)
        .filter_map(|block| block.split("name: ").nth(1))
        .filter_map(|rest| rest.lines().next())
        .collect();
    assert_eq!(
        uploaded,
        [
            "package-signer",
            "sbom",
            "server-linux-${{ matrix.arch }}",
            "${{ steps.pack_tool.outputs.name }}",
            "${{ steps.pack.outputs.name }}",
            "sha256_${{ steps.pack.outputs.name }}",
            "signatures"
        ]
    );

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
        publish.contains("    needs: [version, build, sbom, image, sign]\n"),
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
        "keep crates/classis-agent supervisor \"${ARTIFACT}_${v}_${os}_${arch}\"",
        "if [ \"$tool\" = true ]; then\n              \
         keep crates/classis-tools classisctl \"${OPERATOR_TOOL}_${v}_${os}_${arch}\"",
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
    let servers = matrix.iter().filter(|row| row.contains(" linux ")).count();
    assert_eq!(matrix.len() + tools + servers, 11, "eleven SBOMs");

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
        "Every asset is attested, and \\`SHA256SUMS\\` covers every asset above;",
    ] {
        assert!(notes.contains(line), "{line} in the notes");
    }
}

/// The `permissions:` block of a job: its lines indented below the key, comments included.
fn permissions(job: &str) -> &str {
    let rest = job
        .split_once("    permissions:\n")
        .expect("a permissions block")
        .1;
    let end = rest
        .lines()
        .take_while(|line| line.starts_with("      "))
        .map(|line| line.len() + 1)
        .sum();
    &rest[..end]
}

/// The grants of a permissions block, comments left out.
fn grants(block: &str) -> Vec<&str> {
    block
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect()
}

fn containerfile() -> String {
    let file =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/container/Containerfile");
    std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()))
}

/// The Containerfile's instructions, each with its continuation lines joined: (keyword, arguments).
fn instructions(containerfile: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut continued = false;
    for line in containerfile.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let body = trimmed.strip_suffix('\\').unwrap_or(trimmed).trim();
        if continued {
            let last = out.last_mut().expect("a continued instruction");
            last.1.push(' ');
            last.1.push_str(body);
        } else {
            let (keyword, args) = body.split_once(' ').unwrap_or((body, ""));
            out.push((keyword.to_string(), args.trim().to_string()));
        }
        continued = trimmed.ends_with('\\');
    }
    out
}

/// The arguments of every instruction called `keyword`.
fn all<'i>(instructions: &'i [(String, String)], keyword: &str) -> Vec<&'i str> {
    instructions
        .iter()
        .filter(|(k, _)| k == keyword)
        .map(|(_, args)| args.as_str())
        .collect()
}

const BASE: &str = "gcr.io/distroless/cc-debian13:nonroot";

// Verifies: ADR-0052
#[test]
fn the_containerfile_copies_the_release_binary_onto_a_pinned_distroless_base_and_runs_nothing() {
    let text = containerfile();
    let instructions = instructions(&text);

    // Clause 3: one base, the tag named and the digest pinned.
    let from = all(&instructions, "FROM");
    assert_eq!(from.len(), 1, "{from:?}");
    let digest = from[0]
        .strip_prefix(&format!("{BASE}@sha256:"))
        .unwrap_or_else(|| panic!("not {BASE}@sha256:<digest>: {}", from[0]));
    assert!(
        digest.len() == 64
            && digest
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "not a SHA-256 digest: {digest}"
    );

    // Clause 1: nothing runs, and the one thing copied is the binary the release built.
    for absent in ["RUN", "ADD", "HEALTHCHECK", "SHELL", "ONBUILD"] {
        assert!(all(&instructions, absent).is_empty(), "{absent} in {text}");
    }
    assert_eq!(
        all(&instructions, "COPY"),
        ["--chmod=0755 server-linux-${TARGETARCH} /usr/local/bin/server"]
    );
    assert_eq!(
        all(&instructions, "ENTRYPOINT"),
        ["[\"/usr/local/bin/server\"]"]
    );
    assert!(all(&instructions, "CMD").is_empty(), "{text}");

    // Clause 4: unprivileged and numeric; the data directory is created after USER, so it is the
    // account's, and declared a volume; both planes exposed.
    assert_eq!(all(&instructions, "USER"), ["65532:65532"]);
    let user = instructions.iter().position(|(k, _)| k == "USER");
    let workdir = instructions.iter().position(|(k, _)| k == "WORKDIR");
    assert!(user < workdir, "WORKDIR before USER: {text}");
    assert_eq!(all(&instructions, "WORKDIR"), ["/var/lib/classis", "/"]);
    // The last WORKDIR is where the Server runs and finds its default `server.toml`: never the
    // volume it writes, so nothing it wrote there is read back as its configuration.
    let last = instructions
        .iter()
        .rev()
        .find(|(k, _)| k == "WORKDIR")
        .map(|(_, args)| args.as_str());
    assert_eq!(last, Some("/"), "{text}");
    let volumes = all(&instructions, "VOLUME");
    assert!(
        !volumes
            .iter()
            .any(|v| last.is_some_and(|w| w.trim_end_matches('/') == v.trim_end_matches('/'))),
        "the working directory is the data volume: {text}"
    );
    assert_eq!(all(&instructions, "VOLUME"), ["/var/lib/classis"]);
    assert_eq!(all(&instructions, "EXPOSE"), ["4320 4321"]);

    // It sets nothing but the data directory and the two listen addresses, and no secret.
    let env: Vec<&str> = all(&instructions, "ENV")
        .iter()
        .flat_map(|args| args.split_whitespace())
        .collect();
    assert_eq!(
        env,
        [
            "CLASSIS_SERVER__DATA_DIR=/var/lib/classis",
            "CLASSIS_SERVER__LISTEN=0.0.0.0:4320",
            "CLASSIS_SERVER__REST__LISTEN=0.0.0.0:4321"
        ]
    );
    let set = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(|line| line.matches("CLASSIS_SERVER__").count())
        .sum::<usize>();
    assert_eq!(set, 3, "a CLASSIS_SERVER__ variable beyond the three");

    // Clause 6: what a local build can say of itself. The base is named by the FROM line alone;
    // the release derives its annotations from it, so a new digest is written in one place.
    let labels = all(&instructions, "LABEL").join(" ");
    for key in ["source", "version", "revision", "licenses"] {
        assert!(
            labels.contains(&format!("org.opencontainers.image.{key}=")),
            "{key} in {labels}"
        );
    }
    assert!(
        !labels.contains("org.opencontainers.image.base."),
        "{labels}"
    );
    assert_eq!(
        text.matches(digest).count(),
        1,
        "the base digest outside FROM"
    );
}

// Verifies: ADR-0052
#[test]
fn both_linux_rows_build_the_server_and_assert_its_version() {
    let workflow = workflow();
    let linux: Vec<_> = matrix_rows(&workflow)
        .into_iter()
        .filter(|row| row["os"] == "linux")
        .collect();
    let mut targets: Vec<&str> = linux.iter().map(|row| row["target"].as_str()).collect();
    targets.sort_unstable();
    assert_eq!(
        targets,
        ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
    );
    // Each row runs its own Server, so each asserts it where it was built.
    assert!(linux.iter().all(|row| row["native"] == "true"), "{linux:?}");

    let build = step(&workflow, "Build the Server");
    assert!(build.contains("if: matrix.os == 'linux'"), "{build}");
    assert!(
        build.contains(
            "cargo build --release -p classis-server --bin server --target ${{ matrix.target }} --locked"
        ),
        "{build}"
    );

    let agrees = step(&workflow, "The Server agrees with the release");
    assert!(agrees.contains("if: matrix.os == 'linux'"), "{agrees}");
    assert!(
        agrees.contains("./target/${{ matrix.target }}/release/server --version"),
        "{agrees}"
    );
    assert!(
        agrees.contains("${{ needs.version.outputs.full }}"),
        "{agrees}"
    );
    assert!(agrees.contains("exit 1"), "{agrees}");

    // Uploaded under the name the Containerfile copies, with no checksum: it is not an asset.
    let stage = step(&workflow, "Stage the Server for the image");
    assert!(
        stage.contains(
            "cp \"target/${{ matrix.target }}/release/server\" \"server-linux-${{ matrix.arch }}\""
        ),
        "{stage}"
    );
    let upload = workflow
        .split("- uses: actions/upload-artifact@")
        .find(|block| block.contains("name: server-linux-"))
        .and_then(|block| block.split("\n      - ").next())
        .expect("an upload of the Server");
    assert!(upload.contains("if: matrix.os == 'linux'"), "{upload}");
    assert!(!upload.contains(".sha256"), "{upload}");
}

// Verifies: ADR-0052
#[test]
fn the_sbom_job_describes_the_server_for_both_linux_targets() {
    let workflow = workflow();
    let write = step(job(&workflow, "sbom"), "Write the SBOMs");
    assert!(
        write.contains(
            "if [ \"$os\" = linux ]; then\n              \
             keep crates/classis-server server \"server_${v}_${os}_${arch}\""
        ),
        "{write}"
    );
    // The two rows it applies to are the two Linux rows of the matrix.
    let linux = write
        .lines()
        .map(str::trim)
        .filter(|line| line.split_whitespace().nth(1) == Some("linux"))
        .count();
    assert_eq!(linux, 2, "{write}");
}

// Verifies: ADR-0052
#[test]
fn the_image_job_builds_checks_and_pushes_by_digest_alone() {
    let workflow = workflow();
    assert!(workflow.contains("\n  IMAGE: ghcr.io/neteye-platform/classis-server\n"));
    let image = job(&workflow, "image");
    assert!(image.contains("    needs: [version, build]\n"), "{image}");

    // Clause 11: it can push and read, and nothing else; it never attests.
    assert_eq!(
        grants(permissions(image)),
        ["contents: read", "packages: write"]
    );
    assert!(!image.contains("id-token"), "{image}");
    assert!(!image.contains("attestations"), "{image}");
    let uses: Vec<&str> = image
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            line.strip_prefix("- uses: ")
                .or_else(|| line.strip_prefix("uses: "))
        })
        .collect();
    assert_eq!(
        uses.iter().map(|u| action(u)).collect::<Vec<_>>(),
        ["actions/checkout", "actions/download-artifact"]
    );
    assert!(image.contains("persist-credentials: false"), "{image}");
    assert!(image.contains("pattern: server-linux-*"), "{image}");

    // Clause 9: built for both platforms by the Containerfile, from a shell step, on a builder whose
    // BuildKit image is named by an exact version and its digest.
    let build = step(image, "Build the image");
    let create = build
        .split("docker buildx create ")
        .nth(1)
        .and_then(|rest| rest.split("--use").next())
        .expect("a builder of its own");
    assert!(create.contains("--driver docker-container"), "{create}");
    let pinned = create
        .split("--driver-opt image=moby/buildkit:v")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no pinned BuildKit image: {create}"));
    let (version, digest) = pinned
        .split_once("@sha256:")
        .unwrap_or_else(|| panic!("not pinned by digest: {pinned}"));
    assert!(
        version.split('.').count() == 3
            && version
                .split('.')
                .all(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())),
        "not an exact version: {version}"
    );
    assert!(
        digest.len() == 64
            && digest
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "not a SHA-256 digest: {digest}"
    );
    assert_eq!(workflow.matches("docker buildx create").count(), 1);
    assert!(
        build.contains("--file packaging/container/Containerfile"),
        "{build}"
    );
    assert!(
        build.contains("--platform linux/amd64,linux/arm64"),
        "{build}"
    );
    assert!(
        build.contains("--platform linux/amd64 \\\n") && build.contains("--load"),
        "{build}"
    );

    // The amd64 image: its version, its user, and no shell.
    let check = step(image, "The image checks out");
    assert!(check.contains("set -euo pipefail"), "{check}");
    for line in [
        "docker run --rm \"$img\" --version",
        "${{ needs.version.outputs.full }}",
        "inspect '{{.Config.User}}'",
        "\"65532:65532\"",
        "if docker run --rm --entrypoint /bin/sh \"$img\" -c true",
        "var/lib/classis",
    ] {
        assert!(check.contains(line), "{line} in {check}");
    }
    assert!(!check.contains("needs.version.outputs.publish"), "{check}");

    // On a release alone, by digest and without a tag; the digest goes to publish.
    let push = step(image, "Push the image by digest");
    assert!(
        push.contains("if: needs.version.outputs.publish == 'true'"),
        "{push}"
    );
    assert!(
        push.contains("--platform linux/amd64,linux/arm64"),
        "{push}"
    );
    assert!(
        push.contains(
            "--output \"type=image,name=$IMAGE,push-by-digest=true,name-canonical=true,push=true\""
        ),
        "{push}"
    );
    assert!(push.contains("echo \"digest=$digest\" >> \"$GITHUB_OUTPUT\""));
    assert!(!push.contains("--tag") && !push.contains(" -t "), "{push}");
    assert!(!image.contains("imagetools create"), "{image}");
    assert!(
        image.contains("      digest: ${{ steps.push.outputs.digest }}\n"),
        "{image}"
    );
    for annotation in [
        "source",
        "version",
        "revision",
        "licenses",
        "base.name",
        "base.digest",
    ] {
        assert!(
            push.contains(&format!("\"org.opencontainers.image.{annotation}=")),
            "{annotation} in {push}"
        );
    }
    // The base's two are read off the Containerfile's FROM line, not written a second time.
    for line in [
        "base=$(sed -n 's/^FROM //p' packaging/container/Containerfile)",
        "\"org.opencontainers.image.base.name=${base%@*}\"",
        "\"org.opencontainers.image.base.digest=${base#*@}\"",
    ] {
        assert!(push.contains(line), "{line} in {push}");
    }
}

// Verifies: ADR-0052
#[test]
fn the_publish_job_attests_and_verifies_the_image_before_it_tags_it() {
    let workflow = workflow();
    let publish = job(&workflow, "publish");

    let attest = step(publish, "Attest the image");
    for line in [
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2\n",
        "subject-name: ${{ env.IMAGE }}\n",
        "subject-digest: ${{ needs.image.outputs.digest }}\n",
        "push-to-registry: true\n",
    ] {
        assert!(attest.contains(line), "{line} in {attest}");
    }

    let verify = step(publish, "The image verifies");
    assert!(verify.contains("set -euo pipefail"), "{verify}");
    for line in [
        "gh attestation verify \"oci://${IMAGE}@${{ needs.image.outputs.digest }}\"",
        "--repo \"${{ github.repository }}\"",
        "--signer-workflow \"${{ github.repository }}/.github/workflows/release.yml\"",
        "--deny-self-hosted-runners",
    ] {
        assert!(verify.contains(line), "{line} in {verify}");
    }

    // The exact version, and nothing else, only after both verifications and before the release.
    let tag = step(publish, "Tag the image");
    assert!(tag.contains("set -euo pipefail"), "{tag}");
    assert!(
        tag.contains("tag=\"${IMAGE}:${{ needs.version.outputs.version }}\""),
        "{tag}"
    );
    assert!(
        tag.contains("docker buildx imagetools create --tag \"$tag\" \"${IMAGE}@${digest}\""),
        "{tag}"
    );
    assert_eq!(workflow.matches("imagetools create").count(), 1);
    assert!(!workflow.contains(":latest"), "a latest tag");

    let order: Vec<usize> = [
        "Collect the checksums",
        "Attest the assets",
        "Log in to the registry",
        "Attest the image",
        "Every asset verifies",
        "The image verifies",
        "Tag the image",
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
}

// Verifies: ADR-0052
#[test]
fn the_notes_name_the_image_by_its_digest_and_say_how_to_verify_it() {
    let workflow = workflow();
    let notes = step(&workflow, "Publish the release");
    for line in [
        "\\`${{ env.IMAGE }}@${{ needs.image.outputs.digest }}\\`",
        "gh attestation verify oci://${{ env.IMAGE }}@${{ needs.image.outputs.digest }} \\\\\n",
        "--signer-workflow ${{ github.repository }}/.github/workflows/release.yml\n",
        "docker run -d --name classis-server",
        "-v classis-data:/var/lib/classis",
    ] {
        assert!(notes.contains(line), "{line} in the notes");
    }
}

/// The shell of a step's `run: |` block, dedented: what the runner executes.
fn run_script(step: &str) -> String {
    let body = step
        .split_once("        run: |\n")
        .unwrap_or_else(|| panic!("no run block in {step}"))
        .1;
    body.lines()
        .take_while(|line| line.is_empty() || line.starts_with("          "))
        .map(|line| line.get(10..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The actions a job runs, without their pins.
fn actions(job: &str) -> Vec<&str> {
    job.lines()
        .map(str::trim)
        .filter_map(|line| {
            line.strip_prefix("- uses: ")
                .or_else(|| line.strip_prefix("uses: "))
        })
        .map(action)
        .collect()
}

// Verifies: ADR-0062
#[test]
fn a_release_starts_only_from_a_tag_a_person_pushed() {
    let workflow = workflow();
    // Two triggers: the pushed tag, and a dry run by hand that takes no input.
    let on = workflow
        .split_once("\non:\n")
        .and_then(|(_, rest)| rest.split_once("\n\n"))
        .map(|(block, _)| block)
        .expect("an on: block");
    let triggers: Vec<&str> = on
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    assert_eq!(
        triggers,
        [
            "  workflow_dispatch:",
            "  push:",
            "    tags: [\"version/*\"]"
        ],
        "{on}"
    );
    assert!(!workflow.contains("inputs."), "a run reads no input");

    // The workflow pushes no tag, so no job needs write access to the contents for one.
    assert!(!workflow.contains("git push"), "the workflow pushes");
    assert!(!workflow.contains("git tag "), "the workflow tags");
    let version = job(&workflow, "version");
    assert_eq!(grants(permissions(version)), ["contents: read"]);

    // A run started by hand publishes nothing, on a tag ref neither.
    let read = run_script(step(version, "Read the version out of Cargo.toml"));
    assert!(
        read.contains("if [ \"$GITHUB_EVENT_NAME\" = \"push\" ]; then"),
        "{read}"
    );
    assert!(read.contains("else\n  publish=false\nfi"), "{read}");

    // The tagged commit must be on main (clause 4).
    let on_main = step(version, "The tag is on main");
    assert!(
        on_main.contains("if: steps.read.outputs.publish == 'true'"),
        "{on_main}"
    );
    assert!(
        on_main.contains("git merge-base --is-ancestor \"$GITHUB_SHA\" refs/remotes/origin/main"),
        "{on_main}"
    );
}

// Verifies: ADR-0062
#[test]
fn only_the_sign_job_names_the_signing_environment_and_it_runs_nothing_of_the_repository() {
    let workflow = workflow();
    let sign = job(&workflow, "sign");
    assert_eq!(
        workflow.matches("environment:").count(),
        1,
        "one environment"
    );
    assert!(sign.contains("    environment: signing\n"), "{sign}");
    assert_eq!(workflow.matches("secrets.").count(), 1, "one secret");
    assert!(
        sign.contains("${{ secrets.PACKAGE_SIGNING_KEY }}"),
        "{sign}"
    );

    // A release alone, after the build, on a GitHub-hosted runner, reading and nothing more.
    assert!(
        sign.contains(
            "    if: github.event_name == 'push' && needs.version.outputs.publish == 'true'\n"
        ),
        "{sign}"
    );
    assert!(sign.contains("    needs: [version, build]\n"), "{sign}");
    assert!(sign.contains("    runs-on: ubuntu-latest\n"), "{sign}");
    assert_eq!(grants(permissions(sign)), ["contents: read"]);

    // No checkout, no build, two kinds of action: it fetches the archives' checksums and the
    // tracked certificate, and hands back the signatures (ADR-0063 clause 13).
    assert!(!sign.contains("actions/checkout"), "{sign}");
    assert!(!sign.contains("cargo "), "{sign}");
    assert_eq!(
        actions(sign),
        [
            "actions/download-artifact",
            "actions/download-artifact",
            "actions/upload-artifact"
        ]
    );
    assert!(
        sign.contains("          pattern: sha256_${{ env.ARTIFACT }}_*\n"),
        "{sign}"
    );
    let build = job(&workflow, "build");
    let lone = build
        .split("- uses: actions/upload-artifact@")
        .find(|block| block.contains("name: sha256_"))
        .expect("the archive's lone checksum is uploaded");
    assert!(
        lone.contains("          path: ${{ env.STEM }}.tar.gz.sha256\n"),
        "{lone}"
    );

    // The key is on the runner only between its decoding and a removal that always runs.
    let remove = step(sign, "Remove the signing key");
    assert!(remove.contains("        if: always()\n"), "{remove}");
    assert!(
        remove.contains("rm -f -- \"$RUNNER_TEMP/package-signing-key.pk8\""),
        "{remove}"
    );
    let decode = run_script(step(sign, "Decode the signing key"));
    assert!(decode.contains("umask 077"), "{decode}");
}

/// The `openssl` on the path, required to be OpenSSL 3: LibreSSL, macOS's `openssl`, signs no raw
/// Ed25519 input the way the runner's does.
fn openssl_3() {
    let out = std::process::Command::new("openssl")
        .arg("version")
        .output()
        .unwrap_or_else(|e| {
            panic!("this test runs the signing step with `openssl`, and there is none: {e}")
        });
    let version = String::from_utf8_lossy(&out.stdout);
    assert!(
        version.starts_with("OpenSSL 3."),
        "this test needs OpenSSL 3, the runner's, and found {version:?}"
    );
}

// Verifies: ADR-0062, ADR-0063
#[test]
fn the_signing_step_signs_the_statement_the_client_verifies() {
    use classis_core::package::testing::TestRoot;

    openssl_3();
    let workflow = workflow();
    let script = run_script(step(job(&workflow, "sign"), "Sign every entry"));

    // A Package Signer of a test Root — its PKCS#8 key, as the secret holds it, and its certificate,
    // as `packaging/package-signer.der` does — and two entries' checksums as the build writes them.
    let root = TestRoot::new();
    let signer = root.signer();
    let dir = tempfile::tempdir().expect("tempdir");
    let key_file = dir.path().join("package-signing-key.pk8");
    std::fs::write(&key_file, &signer.pkcs8).expect("key file");
    let cert_file = dir.path().join("package-signer.der");
    std::fs::write(&cert_file, &signer.der).expect("certificate file");
    let entries = dir.path().join("entries");
    std::fs::create_dir(&entries).expect("entries");
    let archives = [
        ("supervisor_1.2.3_linux_amd64.tar.gz", [0x0a_u8; 32]),
        ("supervisor_1.2.3_windows_amd64.tar.gz", [0xf0_u8; 32]),
    ];
    for (name, hash) in &archives {
        std::fs::write(
            entries.join(format!("{name}.sha256")),
            format!("{}  {name}\n", hex::encode(hash)),
        )
        .expect("checksum");
    }
    let script_file = dir.path().join("sign.sh");
    std::fs::write(&script_file, &script).expect("script");
    let run = || {
        std::process::Command::new("bash")
            .arg(&script_file)
            .env("AGENT_TYPE", "supervisor")
            .env("VERSION", "1.2.3")
            .env("KEY", &key_file)
            .env("CERT", &cert_file)
            .env("ENTRIES", &entries)
            .status()
            .expect("bash")
    };
    let status = run();
    assert!(status.success(), "the signing step failed: {status}");

    // Each `.sig` is a PackageSignature in lowercase hex and a newline, and verifies under the
    // Client's own check: up to the Root, over `classis_core::package::statement`.
    for (name, hash) in &archives {
        let sig = std::fs::read_to_string(entries.join(format!("{name}.sig"))).expect("sig");
        assert!(sig.ends_with('\n'), "{sig:?}");
        let hexdigits = sig.trim_end();
        assert!(
            hexdigits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{sig:?}"
        );
        let bytes = hex::decode(hexdigits).expect("hex");
        let parsed = classis_core::package::parse_signature(&bytes).expect("a PackageSignature");
        assert_eq!(
            parsed.signer,
            signer.der.as_slice(),
            "it carries the tracked certificate"
        );
        let statement = classis_core::package::statement("supervisor", "1.2.3", hash);
        assert_eq!(
            classis_core::package::verify_now(&statement, &bytes, &root.roots()),
            Ok(()),
            "the signature of {name} verifies"
        );
        assert_eq!(
            bytes,
            signer.sign(&statement),
            "byte-identical to what `classis_core` writes: Ed25519 is deterministic"
        );
        assert!(entries.join(format!("{name}.sig.sha256")).exists());
        assert!(!entries.join(format!("{name}.statement")).exists());
        assert!(!entries.join(format!("{name}.sig.bin")).exists());
    }

    // A checksum that names another file is refused, and nothing is signed for it.
    std::fs::write(
        entries.join("supervisor_1.2.3_darwin_arm64.tar.gz.sha256"),
        format!("{}  other.tar.gz\n", hex::encode([1_u8; 32])),
    )
    .expect("checksum");
    assert!(
        !run().success(),
        "a checksum naming another file was signed"
    );
    std::fs::remove_file(entries.join("supervisor_1.2.3_darwin_arm64.tar.gz.sha256"))
        .expect("remove");

    // A certificate file that is no DER certificate is refused before anything is signed.
    std::fs::write(&cert_file, b"not a certificate").expect("certificate file");
    assert!(!run().success(), "a non-certificate was carried");
}

// Verifies: ADR-0063
#[test]
fn the_signatures_and_the_tracked_certificate_reach_the_sign_job() {
    let workflow = workflow();
    // The certificate comes from the tracked file, out of the job that has the checkout.
    let version = job(&workflow, "version");
    let tracked = run_script(step(version, "The tracked Package Signer certificate"));
    assert!(
        tracked.contains("cp packaging/package-signer.der package-signer/"),
        "{tracked}"
    );
    assert!(
        version.contains("          name: package-signer\n"),
        "{version}"
    );
    let sign = job(&workflow, "sign");
    assert!(sign.contains("          name: package-signer\n"), "{sign}");
    assert!(
        !job(&workflow, "publish").contains("package-signer"),
        "the certificate travels inside each .sig, and is not published on its own"
    );

    // The signatures are the signing job's, handed back with their checksums.
    assert!(sign.contains("          name: signatures\n"), "{sign}");
    assert!(
        sign.contains("            entries/*.tar.gz.sig\n"),
        "{sign}"
    );

    // The notes tell an operator how to upload them.
    let notes = step(job(&workflow, "publish"), "Publish the release");
    for line in [
        "\\$(cat \"\\$f.sig\")",
        "\"\\$api/packages/supervisor/\\$v/entries/\\$os/\\$arch/signature\"",
    ] {
        assert!(notes.contains(line), "{line} in the notes");
    }
    assert!(!notes.contains("package-signing-key.pub"), "{notes}");
}

// Verifies: ADR-0063
#[test]
fn the_tracked_certificate_is_a_package_signer() {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/package-signer.der");
    let der = std::fs::read(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("a DER certificate");
    assert!(!cert.is_ca(), "a Package Signer is no CA");
    assert!(
        cert.extended_key_usage().ok().flatten().is_none(),
        "a Package Signer carries no extendedKeyUsage"
    );
    assert!(
        classis_core::package::encode_signature(&der, &[0; 64]).len()
            <= classis_core::package::MAX_SIGNATURE_LEN
    );
}
