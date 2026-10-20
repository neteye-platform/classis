# ADR-0045: Every release asset carries a build-provenance attestation, and every shipped program a CycloneDX SBOM per target

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** `.github/workflows/release.yml` (the `sbom` job, the permissions and the attestation and verification steps of the `publish` job, the assets it publishes and the release notes), `crates/fleet-tools/tests/release_workflow.rs`, and every document that tells an operator how to check a release asset (`README.md`, `docs/manual/tools.md`, `CHANGELOG.md`)
- **Supersedes:** [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clause 34; [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clause 20

## Context

A release of `neteye-platform/classis`, a public repository, publishes the following assets
([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clause 34):

- the Client's five `.tar.gz` archives;
- two `.deb`, two `.rpm` and one `.msi`;
- the four archives of the operator tool `opamp-fleetctl`
  ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clauses 17 and 18);
- one `SHA256SUMS`.

The `build` matrix of `release.yml` writes a `.sha256` beside each file. The `publish` job folds
these into `SHA256SUMS`, removes them, and creates the release with `contents: write`. Nothing is
signed. ADR-0019 clause 34 says so, and ADR-0028 clause 20 defers the question: "Provenance for the
release's assets is one decision for all of them". ADR-0028 lists that question as a follow-up.

`SHA256SUMS` proves only that a download matches the file next to it on the same release page.
Anyone who can replace one asset can replace both. Two of these assets carry more weight than the
rest:

- the Client's archive, which a Server hands to a whole fleet as a self-update
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). The
  fleet's package signature then covers the bytes, but it is made over whatever the operator
  downloaded;
- the operator tool, which makes the fleet's certificate authorities and its signing key.

An operator who wants to know that a file came from this repository's release workflow, at a known
commit, has no way to check it today.

GitHub artifact attestations answer that question. A workflow job with `id-token: write` gets a
short-lived Sigstore certificate bound to its workflow identity. It uses that certificate to sign an
in-toto statement with a SLSA v1 build provenance predicate over the files' SHA-256 digests. The
statement is stored in the repository's attestation store. For a public repository, it is also
recorded in the public Rekor transparency log. `gh attestation verify <file> --repo <owner>/<repo>`
checks it. On a public repository this is available on every plan; on a private one it needs
GitHub Enterprise Cloud (read in the `actions/attest` README).

A software bill of materials lists what a binary is built from. An operator runs it through their
own vulnerability scanner without rebuilding, and regulators increasingly ask for one; the EU Cyber
Resilience Act's Annex I asks a manufacturer to draw one up (recalled, not re-read). The two
programs depend on different crates on different targets: `windows-sys` and the service code on
Windows, other code on Linux and macOS. A scanner fed with crates that are not in the binary
reports findings that do not apply.

Constraints from other decisions:

- [ADR-0049](0049-every-github-action-is-pinned-to-a-commit-sha-and-renovate-keeps-it-current.md) pins every action, first-party (`actions/*`) included, to a
  commit SHA with its release in a comment.
- The release workflow installs every tool that writes what ships at an exact version raised by a
  reviewed commit (`cargo install --locked cargo-deb@3.8.0 …`).
  [`scripts/check-build-hardening.sh`](../../scripts/check-build-hardening.sh) check 3 holds that
  rule.
- The workflow already keeps tokens away from code it does not control: the `advisories` job runs
  apart from the job that can push, and no checkout persists credentials. A build script of any
  dependency runs in `build`. A job holding `id-token: write` could mint an attestation for any
  bytes it chose.
- The specification's Q-3 asks that the supply chain be checked before a change merges. A new tool
  in CI is part of it.

## Decision

We will attest the build provenance of every release asset with `actions/attest`, publish one
CycloneDX SBOM for each shipped program on each target, and attest those SBOMs as release assets
like the rest.

1. **Restates ADR-0028 clause 20. Attested, as the Client's artifacts are.** The archives of the
   operator tool carry what every asset of a release carries: their entry in `SHA256SUMS`, and the
   release's build-provenance attestation (clause 4). Each archive also has its program's SBOM for
   its target beside it (clause 2). Provenance for the release's assets is one decision for all of
   them, this one, not a property of this program alone. No archive carries a code signature.

2. **One CycloneDX SBOM per shipped program and target.** The release publishes
   `supervisor_<version>_<os>_<arch>.cdx.json` for each of the Client's five targets, and
   `opamp-fleetctl_<version>_<os>_<arch>.cdx.json` for each of the operator tool's four. The stem is
   that of the archive it describes (ADR-0019 clause 32), and `.cdx.json` is the extension the
   CycloneDX specification recommends. Each SBOM is CycloneDX 1.5 JSON written by `cargo cyclonedx`
   with `--describe binaries` and `--target <triple>`, for:
   - the one binary that ships, `supervisor` or `opamp-fleetctl`;
   - the default features, which the release builds with;
   - every transitive dependency on that target, resolved from the committed `Cargo.lock`.

   The lockfile must be unchanged afterwards. The `.deb`, `.rpm` and `.msi` of a target package the
   binary of its archive unchanged, so the archive's SBOM describes them, and they get none of their
   own. The Server is not a release asset and gets no SBOM.

3. **The SBOMs are written by a job of their own, with an exactly pinned tool.** A job `sbom` of
   `release.yml` runs on `ubuntu-latest` after `version`. It writes all nine SBOMs, since `cargo
   cyclonedx --target` reads the dependency graph for a target without building for it. It writes a
   `.sha256` beside each SBOM and uploads them to the run as the `build` rows upload theirs. It runs
   on a dry run too, so that every dry run exercises it. Its token can read and do nothing else, its
   checkout keeps no credentials, and it restores no cache. It installs the tool with
   `cargo install --locked cargo-cyclonedx@X.Y.Z`, at an exact version raised by a reviewed commit,
   as the packaging tools are. No action installs it.

4. **One build-provenance attestation covers every published asset.** After `SHA256SUMS` is
   assembled and before the release is created, the `publish` job runs `actions/attest` in
   provenance mode, pinned to a commit SHA ([ADR-0049](0049-every-github-action-is-pinned-to-a-commit-sha-and-renovate-keeps-it-current.md)). The subjects are:
   - every file it then publishes: the `.tar.gz` archives, the `.deb`, `.rpm` and `.msi`, the
     `.cdx.json` SBOMs;
   - `SHA256SUMS` itself.

   The digests are computed from the files themselves, not read out of `SHA256SUMS`. The per-file
   `.sha256` files are folded into `SHA256SUMS` and not published, so they are not subjects. The
   attestation is signed through the Sigstore public-good instance, which this public repository
   gets. It is recorded in Rekor and stored in the repository's attestation store.

5. **Only the `publish` job may attest.** `id-token: write` and `attestations: write` are granted to
   `publish` alone, beside its `contents: write`. They appear neither at the workflow's top level,
   which stays `contents: read`, nor on any other job. `publish` checks out no code and runs no
   build. The only actions it runs are `actions/download-artifact` and `actions/attest`. Every other
   step is shell and `gh`. It stays that way while it holds these permissions.

6. **A dry run attests nothing.** `publish` runs only when the run publishes, so a dry run's
   artifacts never receive provenance that a release could later be confused with.

7. **Nothing is published that does not verify.** After attesting and before `gh release create`,
   `publish` runs `gh attestation verify` on every subject, with `--repo` set to this repository,
   `--signer-workflow` set to `<repository>/.github/workflows/release.yml` and
   `--deny-self-hosted-runners`. A file that does not verify fails the job, and no release is
   created.

8. **Restates ADR-0019 clause 34. What is published.** A GitHub release named after the version
   holds:
   - the Client's five archives, the two `.deb`, the two `.rpm` and the `.msi`;
   - the four archives of the operator tool (ADR-0028);
   - the nine SBOMs (clause 2);
   - one `SHA256SUMS` covering every asset.

   Every asset is a subject of the release's build-provenance attestation (clause 4). The notes say:
   - which file is for which purpose;
   - the per-platform install commands;
   - how to verify an asset: `gh attestation verify <file> --repo <repository> --signer-workflow
     <repository>/.github/workflows/release.yml`, and `sha256sum -c --ignore-missing SHA256SUMS`
     once `SHA256SUMS` has verified;
   - the procedure that uploads the Client's archives, selected by their `supervisor_` stem, as one
     package for Agent type `supervisor`;
   - the full baked version string, as provenance. The upload uses the release number, since
     versions are compared without build metadata
     ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)).

   No asset carries a code signature. The attestation is a statement about a file, kept apart from
   it, not a signature inside it. A change to the asset names or containers breaks operators' scripts
   and is named in `CHANGELOG.md` and the release notes of the release that carries it.

**Out of scope:**

- code signatures inside an asset: Authenticode on the `.msi`, `rpm` and `dpkg` signatures, Apple
  notarization;
- the Client verifying an attestation before a self-update. The fleet's package signature
  (ADR-0026) stays the only check on that path;
- an SBOM-predicate attestation that binds each archive to its SBOM (`actions/attest` with
  `sbom-path`);
- SLSA Build Level 3 and an isolated builder;
- reproducible builds;
- an SBOM for the Server, and a VEX document.

## Alternatives considered

- **Sign every asset with `cosign sign-blob`.** This uses the same Sigstore keyless signing and
  needs no GitHub to verify. It adds a third-party installer action, a `.sigstore.json` bundle per
  asset (24 more files), and a verification command with `--certificate-identity` and
  `--certificate-oidc-issuer` that operators type by hand. It signs bytes without saying how they
  were built. The attestation covers both, and its bundle is still checkable with `cosign` (recalled,
  not re-read). Rejected.
- **The SLSA generator's reusable workflow** (`slsa-framework/slsa-github-generator`,
  `generator_generic_slsa3.yml`). This reaches Build Level 3: the provenance is signed in a reusable
  workflow that the calling job cannot influence. It must be referenced by its version tag, not by
  a SHA, because its verifier checks the builder's ref (recalled, not re-read). That contradicts
  ADR-0044 clause 3 for a third-party workflow. It also adds a `.intoto.jsonl` asset and
  `slsa-verifier` as the operator's tool. Rejected. Level 3 is left open (*Out of scope*).
- **`actions/attest-build-provenance@v4` instead of `actions/attest@v4`.** As of v4 it is a wrapper
  over `actions/attest`, and its README tells new implementations to use `actions/attest`. It makes
  the same attestation. Not chosen, so that the release does not depend on a wrapper kept for
  compatibility.
- **Attest in each `build` row.** This is the pattern GitHub documents, attesting where the file is
  made. It gives `id-token: write` to the jobs that run every build script of the dependency graph,
  on five runners. A build script could then attest bytes of its own choosing. Rejected for
  clause 5.
- **Attest in a separate job between `build` and `publish`.** This keeps `id-token` away from
  `contents: write`. `SHA256SUMS` would then be built there and handed on as another artifact.
  `publish` runs no repository code either, so the separation protects nothing. Not chosen.
- **SPDX instead of CycloneDX.** GitHub's dependency graph exports SPDX, but for the whole
  repository and not per target. `cargo-sbom` writes SPDX per crate. `actions/attest` and the common
  scanners (Grype, Trivy, Dependency-Track) read both. `cargo-cyclonedx` is maintained by the
  CycloneDX project itself, resolves a single target, and describes a single binary. Not chosen.
- **One SBOM for the workspace.** One file is simpler to produce. It would list the Server's
  dependencies, the test stubs, dev-dependencies and the crates of every other target, and a scanner
  would report findings for code no asset contains. Rejected.
- **An SBOM per row, written in the `build` job.** It lies next to the build. It would install the
  tool on five runners, Windows and macOS included, while the dependency graph needs no runner of the
  target. Not chosen.
- **`taiki-e/install-action` for `cargo-cyclonedx`.** Its manifest lists `cargo-cyclonedx` 0.5.9
  with a checksum, and a prebuilt binary is faster. The release workflow's rule for the tools that
  write what ships is `cargo install --locked` at an exact version, built from crates.io under the
  tool's own lockfile. A second rule for one tool is not worth the minutes saved. Not chosen.
- **No SBOM.** An operator could derive one from the tagged source. Doing so needs a Rust toolchain,
  this repository's checkout and knowledge of which binary ships, and its result is not attested.
  Rejected.

## Sources / Prior art

- GitHub, *Using artifact attestations to establish provenance for builds* —
  <https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds>.
  Recalled, not re-read.
- `actions/attest` README at `v4` (latest `v4.2.2`), read 2026-10-18 —
  <https://github.com/actions/attest>. It documents:
  - the permissions `id-token: write` and `attestations: write`. The `artifact-metadata: write` it
    also lists is for storage records, which need `push-to-registry` and an organization-owned
    repository, so it is not needed here;
  - `subject-path` with globs and lists, up to 1024 subjects in one attestation;
  - `subject-checksums`, and the SBOM mode;
  - public-good Sigstore for public repositories;
  - availability on private repositories only under Enterprise Cloud.
- `actions/attest-build-provenance` README at `v4` (latest `v4.2.2`), read 2026-10-18: "As of
  version 4, `actions/attest-build-provenance` is simply a wrapper on top of `actions/attest`."
- `gh attestation verify --help`, gh 2.102.0, read 2026-10-18. The SLSA v1 predicate is the default,
  and the help documents `--repo`, `--signer-workflow`, `--deny-self-hosted-runners`,
  `--source-digest`, `--source-ref`, `--bundle` and `--custom-trusted-root` for offline
  verification.
- SLSA v1.0, *Build provenance* — <https://slsa.dev/spec/v1.0/provenance>. Recalled.
- CycloneDX 1.5 specification and its file-name recommendation `*.cdx.json` —
  <https://cyclonedx.org/specification/overview/>. Recalled.
- `cargo-cyclonedx` README and `src/generator.rs`, read 2026-10-18 —
  <https://github.com/CycloneDX/cyclonedx-rust-cargo>. They document:
  - `--describe binaries`, `--target`, `--format json` and `--spec-version` 1.3 to 1.5 (default 1.3);
  - the output name `<bin>_bin.cdx.json` beside the package's `Cargo.toml`;
  - that it runs `cargo metadata`, which can rewrite an outdated `Cargo.lock`.

  crates.io lists 0.5.9 (2026-03-19, MSRV 1.85) as the latest; the toolchain is 1.99.0.
- NTIA, *The Minimum Elements For a Software Bill of Materials* (2021), and the EU Cyber
  Resilience Act, Annex I. Recalled, not re-read.

## Consequences

- Positive: an operator can prove, with one command, that a downloaded asset was built by this
  repository's `release.yml` at a named commit on a GitHub-hosted runner. This includes the archive
  they hand their Server and the tool that makes their keys. `SHA256SUMS` becomes trustworthy once
  it verifies. A scanner gets the exact dependency set of the binary on the platform the operator
  runs.
- Negative / trade-offs: the attestation proves where and from what a file was built, not that the
  source is benign. It cannot be revoked, and an attested file stays attested. Verifying needs `gh`
  and network access to GitHub, or for offline verification a downloaded bundle and trusted root.
  The release takes about as long as before, since the `sbom` job runs beside `build`, but it costs
  one more job and a `cargo install` of the tool. The Rekor log records the digests and the workflow
  identity publicly, which a public repository already shows.
- Negative / trade-offs: the `version` job pushes the tag before anything is built (ADR-0012). An
  attestation or verification failure in `publish` leaves a pushed tag without a release. Re-running
  the failed job publishes it. A new run refuses the spent number, as it does for any `publish`
  failure today.
- Negative / trade-offs: the release now has 24 assets in place of 15. A script that downloads
  `supervisor_<version>_*` without an extension now also matches the SBOMs. The release notes and
  `CHANGELOG.md` say so. The notes' own upload loop and `package fetch` already select `.tar.gz`
  only.
- Follow-ups: an SBOM attestation per archive; the Client checking an attestation on self-update;
  SLSA Build Level 3; code signatures for the installers.

## Enforcement

Tests in `crates/fleet-tools/tests/release_workflow.rs` will carry `Verifies: ADR-0045`. They read
the workflow as text, as the tests of ADR-0028 there do.

- **Permissions.** `id-token: write` and `attestations: write` each occur exactly once, inside the
  `publish` job's `permissions:`. The top-level `permissions:` is `contents: read` alone (clause 5).
- **The `publish` job.** It has no `actions/checkout`, no `cargo` and no `uses:` other than
  `actions/download-artifact@` and `actions/attest@`. Its steps run in this order: `Collect the
  checksums`, the attestation, the verification, `Publish the release`. The attestation's
  `subject-path` names `*.tar.gz`, `*.deb`, `*.rpm`, `*.msi`, `*.cdx.json` and `SHA256SUMS`
  (clauses 4 and 5).
- **Verification.** The verification step runs `gh attestation verify` with `--signer-workflow` and
  `--deny-self-hosted-runners` over the same set (clause 7). `gh release create` publishes
  `*.cdx.json` (clause 8).
- **The `sbom` job.** It `needs: version`, has no `if:` and no `permissions:` beyond the top level,
  and installs `cargo-cyclonedx@<MAJOR.MINOR.PATCH>` with `cargo install --locked`. For every matrix
  row it writes `supervisor_…_<os>_<arch>.cdx.json`, and for every `operator_tool: true` row
  `opamp-fleetctl_…_<os>_<arch>.cdx.json`, each with `--describe binaries --target <triple>
  --spec-version 1.5`, beside a `.sha256`. It fails when `Cargo.lock` changed (clauses 2 and 3).
- **The notes.** The release notes contain `gh attestation verify` and `--signer-workflow`
  (clause 8).

[`scripts/check-build-hardening.sh`](../../scripts/check-build-hardening.sh) check 3 already fails
on a `cargo install` in `release.yml` without an exact version, which covers the tool of clause 3.
Its check 2 already fails on a cache in `release.yml`.

**Not mechanically decidable:** that a real release's assets verify on GitHub, and that each SBOM is
complete for its binary. The first is held at release time by clause 7's step in `publish`, which
fails the release. The second is held by review of the first release's SBOMs against `cargo tree
--target <triple> -e normal -p <package>`.
