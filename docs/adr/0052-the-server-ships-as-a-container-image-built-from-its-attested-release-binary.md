# ADR-0052: The Server ships as a container image built from its attested release binary

- **Status:** 🟢 accepted
- **Date:** 2026-10-23
- **Deciders:** Markus Brigl
- **Applies to:** `packaging/container/Containerfile`, the Linux rows of the
  `build` job, the `sbom` job, a new `image` job and the attestation,
  verification and publishing steps of the `publish` job in
  `.github/workflows/release.yml`, the image
  `ghcr.io/mbrigl/opamp-fleet-server`, `.github/dependabot.yml`,
  `crates/fleet-tools/tests/release_workflow.rs`, and every document that tells
  an operator how to run or verify the Server (`README.md`, `docs/manual/`,
  `CHANGELOG.md`)
- **Supersedes:**
  [ADR-0045](0045-every-release-asset-carries-a-provenance-attestation-and-every-program-an-sbom.md)
  clauses 2, 3, 4, 5 and 8

## Context

The Server is not a release asset. `release.yml` builds the Client for five
targets and the operator tool for four, attests every asset and writes one
CycloneDX SBOM per shipped program and target
([ADR-0045](0045-every-release-asset-carries-a-provenance-attestation-and-every-program-an-sbom.md)).
Clause 2 of ADR-0045 says the Server gets no SBOM, because nothing of it is
published. An operator builds the Server from source with
`cargo build -p fleet-server`, and nothing ties the binary they run to a
reviewed commit.

The Server is to run in a container.
[ADR-0051](0051-the-servers-configuration-may-come-from-its-environment.md) lets
its whole configuration come from the environment,
`FLEET_SERVER__<SECTION>__<KEY>`, with `server.toml` optional and every secret a
file whose path the environment names. What is still missing is the image
itself: a defined runtime, the binary in it, and a way for an operator to check
that the image they pull is the one the release workflow built from the tagged
commit.

The release workflow builds Linux binaries for `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` on GitHub-hosted runners with the pinned toolchain
(`rust-toolchain.toml`), from the committed lockfile, without a cache. A binary
for the GNU targets links glibc and `libgcc_s` dynamically. The Server has no
health endpoint; its two planes listen on `127.0.0.1:4320` and `127.0.0.1:4321`
by default, and off the loopback both require TLS and the Operator plane
requires `[rest.auth]`
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).

The specification's quality goals Q-1 and Q-3 apply to the image as to every
other release artifact: nothing it starts may send a credential unencrypted
beyond the loopback, and nothing in it may enter without the supply-chain checks
a dependency passes.

A reader without this conversation would expect a multi-stage `Dockerfile` that
compiles the Server inside the image build, a `latest` tag, and a `HEALTHCHECK`.
This ADR decides against all three.

## Decision

We will publish, with every release, a multi-architecture image of the Server at
`ghcr.io/mbrigl/opamp-fleet-server:<version>`, built from
`packaging/container/Containerfile` by copying the Server binary the release
workflow built and checked into a distroless glibc base, and attested and
described by an SBOM like every other release artifact.

1. **One Containerfile, no compiler in it.** `packaging/container/Containerfile`
   copies a binary that already exists, `server-linux-${TARGETARCH}`, to
   `/usr/local/bin/server`. It runs no `RUN` step, so a multi-architecture build
   needs no emulation and the image holds exactly the binary the release built,
   tested for its version and described by its SBOM. A developer builds the
   image the same way after
   `cargo build --release -p fleet-server --bin server`.

2. **The release builds the Server for both Linux targets.** The `build` rows
   for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` also run
   `cargo build --release -p fleet-server --bin server --target <triple> --locked`,
   assert that `server --version` reports the release's version, and upload the
   binary to the run. The binary is not a release asset of its own; the image is
   how it ships.

3. **The runtime is `gcr.io/distroless/cc-debian13:nonroot`, pinned by digest.**
   It carries glibc, `libgcc_s`, CA certificates and time zone data, and no
   shell and no package manager. Debian 13's glibc is newer than the build
   runner's, so the binary built there runs on it. The `FROM` line names the tag
   and its digest; a new digest arrives by a reviewed commit.

4. **The image runs unprivileged, and configures nothing that holds a secret.**
   - It runs as UID and GID `65532`, set numerically with `USER 65532:65532`. It
     needs no capability: both planes listen on ports above 1024.
   - It sets `FLEET_SERVER__DATA_DIR=/var/lib/opamp-fleet`,
     `FLEET_SERVER__LISTEN=0.0.0.0:4320` and
     `FLEET_SERVER__REST__LISTEN=0.0.0.0:4321`, declares `/var/lib/opamp-fleet`
     a volume owned by `65532`, and exposes `4320` and `4321`. Its working
     directory is `/`, which that account cannot write, so the `server.toml` the
     Server reads by default is never a file it could have written to its own
     volume. It sets nothing else.
   - It contains no `server.toml`, no certificate, no key and no credential. Off
     the loopback the Server refuses to start without TLS and without
     `[rest.auth]`, so an image started with nothing mounted fails, naming the
     missing key, rather than serving in the clear or without authentication
     (Q-1).
   - Certificates, keys, the PIN, password and credential files are mounted as
     files, and their paths are given through the environment
     ([ADR-0051](0051-the-servers-configuration-may-come-from-its-environment.md)).
     The image works with a read-only root filesystem.

5. **No `HEALTHCHECK`; an orchestrator probes TCP.** The image has no shell and
   the Server has no health endpoint, so the image declares no `HEALTHCHECK`.
   The documented probe is a TCP connection to `4320` for liveness and
   readiness. A health endpoint is a later decision.

6. **Tags are exact versions; the digest is the reference.** The image is tagged
   with the release's version, such as `0.7.0`, and with nothing else: no
   `latest`, no `0.7`. A tag is set only after the image has verified (clause
   9). The release notes name the image by its digest, and the documentation
   tells operators to deploy by digest. The image carries the OCI annotations
   `org.opencontainers.image.source`, `.version`, `.revision`, `.licenses`,
   `.base.name` and `.base.digest`.

7. **Restates ADR-0045 clause 2, with the Server added. One CycloneDX SBOM per
   shipped program and target.** The release publishes
   `supervisor_<version>_<os>_<arch>.cdx.json` for each of the Client's five
   targets, `opamp-fleetctl_<version>_<os>_<arch>.cdx.json` for each of the
   operator tool's four, and `server_<version>_linux_<arch>.cdx.json` for each
   of the Server's two. The stem of the first two is that of the archive it
   describes (ADR-0019 clause 32); the Server's names the binary inside the
   image of that architecture. `.cdx.json` is the extension the CycloneDX
   specification recommends. Each SBOM is CycloneDX 1.5 JSON written by
   `cargo cyclonedx` with `--describe binaries` and `--target <triple>`, for:
   - the one binary that ships, `supervisor`, `opamp-fleetctl` or `server`;
   - the default features, which the release builds with;
   - every transitive dependency on that target, resolved from the committed
     `Cargo.lock`.

   The lockfile must be unchanged afterwards. The `.deb`, `.rpm` and `.msi` of a
   target package the binary of its archive unchanged, so the archive's SBOM
   describes them, and they get none of their own. The image's base layers are
   Debian packages that `cargo cyclonedx` does not see; the image's SBOM is the
   Server's, and the base is named by its digest (clause 6).

8. **Restates ADR-0045 clause 3, with eleven SBOMs. The SBOMs are written by a
   job of their own, with an exactly pinned tool.** A job `sbom` of
   `release.yml` runs on `ubuntu-latest` after `version`. It writes every SBOM
   of clause 7, since `cargo cyclonedx --target` reads the dependency graph for
   a target without building for it. It writes a `.sha256` beside each SBOM and
   uploads them to the run as the `build` rows upload theirs. It runs on a dry
   run too, so that every dry run exercises it. Its token can read and do
   nothing else, its checkout keeps no credentials, and it restores no cache. It
   installs the tool with `cargo install --locked cargo-cyclonedx@X.Y.Z`, at an
   exact version raised by a reviewed commit, as the packaging tools are. No
   action installs it.

9. **The image is built and pushed untagged by a job of its own, and tagged
   after it verifies.**
   - A job `image` runs after `build`. It downloads the two Server binaries,
     builds the image for `linux/amd64` and `linux/arm64` with `docker buildx`
     from a shell step, on a BuildKit builder whose image is pinned by version
     and digest and raised by a reviewed commit, and checks the `linux/amd64`
     image on its own runner: its `server --version` reports the release's
     version, its user is `65532`, and it has no `/bin/sh`. The `arm64` binary's
     version was asserted on its native runner in its `build` row, and the image
     copies it unchanged. On a dry run it stops there.
   - On a release it logs in to `ghcr.io` with the job's token, pushes the image
     by digest and without a tag, and hands the index digest to `publish`. Its
     permissions are `contents: read` and `packages: write`, and it uses no
     action beyond `actions/checkout` and `actions/download-artifact`.
   - `publish` attests the digest (clause 10), verifies it (ADR-0045 clause 7),
     and only then tags it with the version, with
     `docker buildx imagetools create` from a shell step. An image that does not
     verify keeps no tag, and no release is created.

10. **Restates ADR-0045 clause 4, with the image added. One build-provenance
    attestation covers every published asset, and one covers the image.** After
    `SHA256SUMS` is assembled and before the release is created, the `publish`
    job runs `actions/attest@v4` in provenance mode, on its major tag
    (ADR-0044). The subjects are:
    - every file it then publishes: the `.tar.gz` archives, the `.deb`, `.rpm`
      and `.msi`, the `.cdx.json` SBOMs;
    - `SHA256SUMS` itself.

    A second `actions/attest@v4` step attests the image, with `subject-name`
    `ghcr.io/mbrigl/opamp-fleet-server`, `subject-digest` the index digest from
    `image`, and `push-to-registry: true`, so the attestation travels with the
    image. The digests of the files are computed from the files themselves, not
    read out of `SHA256SUMS`. The per-file `.sha256` files are folded into
    `SHA256SUMS` and not published, so they are not subjects. Each attestation
    is signed through the Sigstore public-good instance, which this public
    repository gets, recorded in Rekor and stored in the repository's
    attestation store.

11. **Restates ADR-0045 clause 5, with `packages: write` added. Only the
    `publish` job may attest.** `id-token: write` and `attestations: write` are
    granted to `publish` alone, beside its `contents: write` and
    `packages: write`, which it needs to push the image's attestation and to tag
    the image. They appear neither at the workflow's top level, which stays
    `contents: read`, nor on any other job; `image` holds `packages: write`
    without either. `publish` checks out no code and runs no build. The only
    actions it runs are `actions/download-artifact` and `actions/attest`. Every
    other step, the registry login and the tagging included, is shell and `gh`.
    It stays that way while it holds these permissions.

12. **Restates ADR-0045 clause 8, which restates ADR-0019 clause 34. What is
    published.** A GitHub release named after the version holds:
    - the Client's five archives, the two `.deb`, the two `.rpm` and the `.msi`;
    - the four archives of the operator tool (ADR-0028);
    - the eleven SBOMs (clause 7);
    - one `SHA256SUMS` covering every asset.

    Beside it, `ghcr.io/mbrigl/opamp-fleet-server:<version>` holds the Server's
    image. Every asset is a subject of the release's build-provenance
    attestation, and the image of its own (clause 10). The notes say:
    - which file is for which purpose, and the image's name and digest;
    - the per-platform install commands, and how to run the image;
    - how to verify an asset:
      `gh attestation verify <file> --repo <repository> --signer-workflow <repository>/.github/workflows/release.yml`,
      and `sha256sum -c --ignore-missing SHA256SUMS` once `SHA256SUMS` has
      verified;
    - how to verify the image:
      `gh attestation verify oci://ghcr.io/mbrigl/opamp-fleet-server@<digest>
      --repo <repository>
      --signer-workflow <repository>/.github/workflows/release.yml`;
    - the procedure that uploads the Client's archives, selected by their
      `supervisor_` stem, as one package for Agent type `supervisor`;
    - the full baked version string, as provenance. The upload uses the release
      number, since versions are compared without build metadata
      ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)).

13. **The base image's digest is kept current.** `.github/dependabot.yml` gains
    a `docker` entry for `packaging/container/`, so a new digest of the base
    arrives as a pull request. Where Dependabot does not read a file named
    `Containerfile`, the digest is raised by a reviewed commit on the same
    schedule as the packaging tools.

**Out of scope:** an image of the Client, which stays an operating-system
service
([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md));
a Helm chart, Compose file or Kubernetes manifest for production; a health
endpoint; a code signature beyond the build-provenance attestation, such as a
cosign signature; a PKCS#11 module or other library in the image; images for any
target but `linux/amd64` and `linux/arm64`; a published Server binary outside
the image.

## Alternatives considered

- **A multi-stage build that compiles the Server inside the image.** It needs
  nothing but the Containerfile, but the image's binary is then a second build,
  not the one the `build` row checked for its version and the `sbom` job
  described, and an `arm64` image would compile under emulation for an hour.
  Rejected; the Containerfile copies the release's binary.
- **A musl build on `distroless/static`.** A static binary needs no glibc and
  the base would be smaller. The release builds GNU binaries for the Client and
  the operator tool, and a third toolchain target with its own allocator and DNS
  resolver for one image is more to keep than the few megabytes it saves.
  Rejected for now.
- **`debian:13-slim` or Alpine as the base.** A shell and a package manager help
  debugging, but they are what an attacker with code execution in the container
  uses next, and every package in them is a CVE to track. Rejected; `distroless`
  has a `debug` variant for local debugging.
- **`cc-debian12`.** The build runner's glibc is newer than Debian 12's, so the
  binary might not load. Rejected for `cc-debian13`.
- **A `latest` tag, or a floating `0.7` tag.** Convenient, but a deployment then
  moves without a change in its own configuration, and the attestation names a
  digest, not a tag. Rejected.
- **A `HEALTHCHECK` with a probe binary in the image.** It needs a second
  program in the image or a shell. An orchestrator's TCP probe needs neither.
  Rejected until the Server has a health endpoint.
- **Push and tag the image in the `image` job.** Simpler, but the tag would
  exist before the image's attestation verified, against ADR-0045 clause 7.
  Rejected.
- **A cosign signature beside the attestation.** It adds a second signing scheme
  and a third-party action for what `gh attestation verify` already proves:
  which workflow built which digest from which commit. Rejected.
- **Docker Hub instead of `ghcr.io`.** It needs an account and a token outside
  GitHub; the job's own token reaches `ghcr.io`. Rejected.

## Sources / Prior art

- [Distroless README](https://github.com/GoogleContainerTools/distroless/blob/main/README.md):
  the Debian 13 images `static-debian13`, `base-debian13` and `cc-debian13`, the
  `nonroot` and `debug` tags, no shell, keyless cosign signatures;
  [cc](https://github.com/GoogleContainerTools/distroless/blob/main/cc/README.md)
  (base plus `libgcc1`) and
  [base](https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md)
  (glibc, libssl, CA certificates, tzdata, `/tmp`).
- GitHub Docs,
  [Using artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations):
  `subject-name` without a tag, `subject-digest`, `push-to-registry: true`,
  `packages: write`, and `gh attestation verify oci://…`.
- OCI Image Format,
  [Pre-Defined Annotation Keys](https://github.com/opencontainers/image-spec/blob/main/annotations.md).
- [dependabot-core issue 6067](https://github.com/dependabot/dependabot-core/issues/6067)
  and
  [Chainguard on Dependabot and image digests](https://edu.chainguard.dev/chainguard/containers/staying-secure/updating-images/dependabot/):
  Dependabot's support for a file not named `Dockerfile` is not established,
  hence clause 13's fallback.
- The code as it stands: the `build`, `sbom` and `publish` jobs of
  `.github/workflows/release.yml`, `DEFAULT_LISTEN` and `DEFAULT_REST_LISTEN` in
  `crates/fleet-server/src/config.rs`, and the absence of a health route in
  `crates/fleet-server/src/api.rs`.

## Consequences

- Positive: an operator runs a Server whose binary is the one the release built
  from the tagged commit, and can prove it with one `gh attestation verify`.
- Positive: the image starts only with TLS and authentication configured, runs
  unprivileged with no shell, and carries no secret.
- Positive: the Server's dependencies are described per target for the first
  time.
- Negative / trade-offs: the release builds the Server twice more, pushes to a
  registry, and `publish` gains `packages: write`. The registry is a second
  place a release appears.
- Negative / trade-offs: the base image's own packages are not in the SBOM; they
  are named by the base digest and tracked by its updates.
- Negative / trade-offs: no shell in the image makes debugging inside it harder;
  the `debug` variant of the base is for that, locally.
- Follow-ups: a health endpoint and a `HEALTHCHECK`-free readiness probe on it;
  a musl build on `static`; production deployment examples; whether Dependabot
  updates the `Containerfile`'s digest.

## Enforcement

Tests in `crates/fleet-tools/tests/release_workflow.rs` will carry
`Verifies: ADR-0052`. They read the workflow and the Containerfile as text, as
the tests of ADR-0045 there do.

- **The Containerfile.** `packaging/container/Containerfile` has exactly one
  `FROM`, naming `gcr.io/distroless/cc-debian13:nonroot@sha256:`, no `RUN`,
  `USER 65532:65532`, no `HEALTHCHECK`, a last `WORKDIR` of `/`, and sets no
  `FLEET_SERVER__` variable beyond `DATA_DIR`, `LISTEN` and `REST__LISTEN`
  (clauses 1, 3, 4, 5).
- **The build rows.** Both Linux rows build `-p fleet-server --bin server` with
  `--locked` and assert its version (clause 2).
- **The `sbom` job.** It writes `server_…_linux_<arch>.cdx.json` for both Linux
  rows (clause 7).
- **The `image` job.** Its permissions are `contents: read` and
  `packages: write` alone, it has no `id-token` and no `attestations`, its
  builder's image is pinned by digest, it runs the version, user and shell
  checks, and it pushes no tag (clauses 9 and 11).
- **The `publish` job.** Its image attestation step has `subject-name`,
  `subject-digest` and `push-to-registry: true`; its verification runs
  `gh attestation verify oci://` with `--signer-workflow`; the tagging step
  comes after the verification and before `Publish the release` (clauses 9, 10
  and 11).

**Not mechanically decidable:** that the published image's digest verifies on
GitHub and runs on both architectures. The first is held at release time by the
verification in `publish`, which leaves the image untagged and creates no
release. The second is held for `amd64` by the `image` job's check and for
`arm64` by its `build` row's version check of the same binary; that the `arm64`
image starts is checked by hand on the first release.
