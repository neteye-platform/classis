# ADR-0062: The release run signs every entry of the Client's own package, with a key only a reviewed `version/*` tag reaches

- **Status:** 🟡 proposed
  · clauses 1, 6, 8 and 9 superseded by
  [ADR-0063](0063-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)
- **Date:** 2026-11-13
- **Deciders:** Davide Zeni
- **Applies to:** the triggers and the `version`, `sign` and `publish` jobs of
  `.github/workflows/release.yml`, `packaging/package-signing-key.pub`, the
  GitHub environment `signing`, the repository's rulesets for `main`, for every
  branch and for tags, `crates/classis-tools/tests/release_workflow.rs`, the
  section _Repository settings_ of `README.md`, and every document that tells an
  operator how to upload or verify the Client's release
- **Supersedes:**
  [ADR-0012](0012-versions-resolved-in-the-internal-crate.md) clauses 6 and 8;
  [ADR-0052](0052-the-server-ships-as-a-container-image-built-from-its-attested-release-binary.md)
  clauses 10 and 12

## Context

Every Package a Client installs must carry a valid signature
([`docs/SPECIFICATION.md`](../SPECIFICATION.md), Q-1), and that includes the
Client's own update (G-10, G-11). Today the operator signs.
`classisctl package keygen` makes an Ed25519 key and prints its public half in
hex. `classisctl package sign` signs a statement of Agent type, version and
SHA-256
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
clause 54). Every installation therefore holds a key of its own, and nobody but
the operator can sign the Client's release for it.

The project means to move package signing into its own release pipeline in
steps, and this ADR is the first one. The release run signs each entry of the
Client's own Package, `supervisor` at the release's version, with one key and
in the format the Client and the Server verify today. It publishes the
signatures and the key's public half beside the archives. The Client, the
Server and the operator tool do not change. An operator who places
`package-signing-key.pub` beside the Client's program at install already gets it
as `[packages] verification_key`
([ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
clause 6, which restates ADR-0020 clause 1).

The forces:

- **A key in GitHub is reachable by whoever can make a job read it.**
  - A repository secret is readable by anyone with write access.
  - An environment secret reaches only a job that names the environment, from
    the refs its deployment rule admits, and only after the environment's
    reviewers approve.
  - The deployment rule matches the ref's name, "against the `GITHUB_REF` of
    the workflow run", not the commit the ref points at.
  - A run uses "the version of the workflow that is present in the associated
    commit SHA or Git ref of the event", so a tag decides which workflow runs.
- **Required reviewers exist only on a public repository or on GitHub
  Enterprise.** This repository is public.
- **The release run tags the commit itself** (ADR-0012 clause 6). A run started
  by `workflow_dispatch` therefore runs on `refs/heads/main`, and an environment
  that admits only `version/*` tags would refuse its signing job.
- **Everyone with write access may release.** That is the organisation's
  practice. Another of its repositories, `permissionsync`, has these rules:
  - a ruleset on `main`;
  - signed commits;
  - a tag ruleset that forbids moving or deleting a tag but not creating one.

  Its release workflow holds no long-lived secret, only `GITHUB_TOKEN`, so one
  person alone can publish an image there. Here one person alone would sign
  what every Client of every installation installs.
- **The signing job should run as little code as possible.** A job that checks
  out the repository and builds a tool runs every dependency's build script
  where the key is.

## Decision

We will sign every entry of the Client's own Package in a `sign` job of the
release run. The key is one Ed25519 key, a secret of the GitHub environment
`signing`. Only a run started by a hand-pushed `version/*` tag reaches that job,
and only after a second person with write access approves. The release publishes
each signature, and the key's public half, beside the archives.

1. **One Ed25519 key, made once, outside the release run.**
   - A repository admin makes it with `classisctl package keygen` on a machine
     of their own.
   - They store the base64 of the `package-signing-key.pk8` it writes as the
     secret `PACKAGE_SIGNING_KEY` of the environment `signing`, then delete the
     file. No copy is kept.
   - The public half `keygen` prints is committed as
     `packaging/package-signing-key.pub` by a reviewed pull request. It is 64
     hexadecimal digits and a newline, the form ADR-0029 clause 6 takes.
   - The `version` job, which checks out the tag, uploads that tracked file as
     a run artifact for `publish`. The release never publishes a public half
     derived from the secret.
   - A lost or exposed key is replaced the same way: a new key, a new secret,
     and a new public half under review.

2. **The environment `signing` holds the key, and a second person releases
   it.**
   - Its deployment rule admits the tags `version/*` and no branch.
   - It requires one reviewer, taken from a team of the people with write
     access; GitHub lists at most six users or teams.
   - _Prevent self-review_ is on, so whoever started the run cannot approve it.
   - Administrators may not bypass its rules.
   - Only the `sign` job names it (clause 6).

   Before approving, the reviewer checks that the run was started by the push
   of a `version/*` tag and that the tag names a commit on `main`.

3. **Restates ADR-0012 clause 6, reversed: a person creates the tag, and the
   release run checks it against the file.**
   - A release run starts only on the push of a `version/*` tag.
   - A person with write access creates `version/<version>` and pushes it. The
     tag goes on the commit on `main` that carries the
     `[workspace.package] version` being released, once that commit has merged.
   - The run reads the version with `cargo metadata` and checks out the tag, so
     `build.rs` finds the tag on HEAD.
   - The workflow pushes no tag, and the `version` job holds `contents: read`.
   - The tag ruleset (clause 10) keeps a pushed tag where it was pushed.

4. **The run refuses a tag that is not on `main`.** The `version` job fails
   unless the tagged commit is reachable from `origin/main`. This guards
   against mistakes only. The workflow that runs is the one in the tagged
   commit, and a changed workflow can drop the check. That is why the reviewer
   checks it too (clause 2).

5. **Restates ADR-0012 clause 8, with the publishing run removed: a run started
   by hand is a dry run, and nothing else.** `workflow_dispatch` takes no
   input. A run started by hand builds and packs every target and stops. It
   neither tags, signs nor publishes, and it never reaches the environment
   `signing`. A `-dev` version is expected there and only there.

6. **The `sign` job signs, and does nothing else.**
   - **When it runs.** Only in a run started by the push of a `version/*` tag
     (`github.event_name == 'push'`). The event is checked because
     `workflow_dispatch` can run on a tag ref too. It runs after `version` and
     `build`, on `ubuntu-latest` and never on a self-hosted runner.
   - **What it may do.** It names the environment `signing` and holds
     `contents: read` alone. It checks out no code and builds nothing. The only
     actions it runs are `actions/download-artifact` and
     `actions/upload-artifact`, pinned to a commit SHA
     ([ADR-0060](0060-every-github-action-is-pinned-to-a-commit-sha-and-renovate-keeps-it-current.md)).
     Every other step is shell.
   - **What it signs.**
     - It downloads only the `.sha256` files of the Client's archives.
     - For each one it writes the statement `classis_core::package::statement`
       makes to a file: `opamp-fleet-package-v1`, `supervisor`, the release
       number, and the SHA-256 in lowercase hex, each line ended by a newline.
       The prefix keeps the spelling
       [ADR-0061](0061-the-product-is-named-classis-and-the-strings-signatures-cover-keep-their-old-spelling.md)
       keeps.
     - It signs that file with the runner's
       `openssl pkeyutl -sign -rawin -keyform DER -inkey <key> -in <statement>`.
       OpenSSL takes Ed25519 only with `-rawin` and from a file. The step
       script reads its inputs from environment variables only.
   - **The key on the runner.** The key is decoded into a file under
     `RUNNER_TEMP`, mode `0600`. A step with `if: always()` removes it.
   - **What it writes.**
     - Each signature goes to `<archive>.sig` as 128 lowercase hexadecimal
       digits and a newline. That is the form the REST API takes an entry's
       signature in.
     - A `.sha256` is written beside each `.sig`.
     - The files are uploaded.
   - **Why nothing downstream changes.** Ed25519 signing is deterministic. On
     2026-11-13 OpenSSL 3.5.9 signed a statement with a key from `keygen`'s
     `ring::signature::Ed25519KeyPair::generate_pkcs8`, and its signature was
     byte-identical to `ring`'s. What `classisctl package sign` makes with the
     same key is therefore what this job makes.

7. **Only the Client's own Package is signed.** That means one entry for each of
   the five `supervisor_<version>_<os>_<arch>.tar.gz` archives, for Agent type
   `supervisor`. These get no `.sig`, because they are not artifacts of a
   Package:
   - the operator tool's archives
     ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
     clause 19);
   - the `.deb`, `.rpm` and `.msi`
     ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
     clause 35);
   - the SBOMs.

8. **Restates ADR-0052 clause 10, with the signatures and the key added and the
   action pinned to a commit SHA. One build-provenance attestation covers every
   published asset, and one covers the image.** After `SHA256SUMS` is assembled
   and before the release is created, the `publish` job runs `actions/attest` in
   provenance mode, pinned to a commit SHA (ADR-0060). The subjects are:
   - every file it then publishes: the `.tar.gz` archives, the `.deb`, `.rpm`
     and `.msi`, the `.cdx.json` SBOMs, the `.tar.gz.sig` signatures and
     `package-signing-key.pub`;
   - `SHA256SUMS` itself.

   A second `actions/attest` step attests the image, with `subject-name`
   `ghcr.io/neteye-platform/classis-server`, `subject-digest` the index digest
   from `image`, and `push-to-registry: true`, so the attestation travels with
   the image. The digests of the files are computed from the files themselves,
   not read out of `SHA256SUMS`. The per-file `.sha256` files are folded into
   `SHA256SUMS` and not published, so they are not subjects. Each attestation
   is signed through the Sigstore public-good instance, which this public
   repository gets, recorded in Rekor and stored in the repository's
   attestation store.

9. **Restates ADR-0052 clause 12, which restates ADR-0045 clause 8, which
   restates ADR-0019 clause 34, with the signatures and the key added. What is
   published.** A GitHub release named after the version holds:
   - the Client's five archives, the two `.deb`, the two `.rpm` and the `.msi`;
   - one `.sig` per Client archive, named after it (clause 6);
   - `package-signing-key.pub`, the tracked public half of the key every `.sig`
     verifies against (clause 1);
   - the four archives of the operator tool (ADR-0028);
   - the eleven SBOMs (ADR-0052 clause 7);
   - one `SHA256SUMS` covering every asset.

   Beside it, `ghcr.io/neteye-platform/classis-server:<version>` holds the
   Server's image. Every asset is a subject of the release's build-provenance
   attestation, and the image of its own (clause 8). The notes say:
   - which file is for which purpose, and the image's name and digest;
   - the per-platform install commands, and how to run the image;
   - how to verify an asset:
     `gh attestation verify <file> --repo <repository> --signer-workflow <repository>/.github/workflows/release.yml`,
     and `sha256sum -c --ignore-missing SHA256SUMS` once `SHA256SUMS` has
     verified;
   - how to verify the image:
     `gh attestation verify oci://ghcr.io/neteye-platform/classis-server@<digest>
     --repo <repository>
     --signer-workflow <repository>/.github/workflows/release.yml`;
   - the procedure that uploads the Client's archives, selected by their
     `supervisor_` stem, as one package for Agent type `supervisor`, each entry
     with the signature its `.sig` holds;
   - what `package-signing-key.pub` is for. Placed beside the Client's program
     at install, it becomes `[packages] verification_key` (ADR-0029 clause 6).
     The Server checks the uploaded signatures against it when it holds it
     ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
     clause 7);
   - the full baked version string, as provenance. The upload uses the release
     number, since versions are compared without build metadata (ADR-0012).

10. **The repository's rules follow the organisation's practice, with the
    environment added.** These are GitHub settings, and the _Repository
    settings_ section of `README.md` lists them:
    - **`main`:**
      - a pull request with one approval from a person with write access,
        given after the last push; a push dismisses earlier approvals;
      - conversations resolved and the required checks passing;
      - squash merges and a linear history;
      - no force push and no deletion.
    - **Every branch:** signed commits.
    - **Tags:**
      - no update, no deletion and no force push;
      - signatures required;
      - anyone with write access may create one, since they are authorised to
        release.
    - **The environment `signing`:** as clause 2 states.

**Out of scope:**

- a certificate chain: a root certificate compiled into the Client, a signing
  certificate issued by it, and a container that carries it;
- any change to the Client, the Server or the operator tool, including its
  `package sign` and `keygen` commands;
- signing third-party packages in the release run;
- verifying the `.sig` files in `publish` before the release is created;
- a `CODEOWNERS` file for the workflows;
- how a Package reaches a Server other than by the documented upload.

## Alternatives considered

- **A repository secret.** Anyone with write access can read it, from any
  workflow on any branch.
- **The rules of `permissionsync` as they are, with no reviewer.** Any one of
  the people with write access could sign, alone, a Package that every Client
  trusting the key installs. They could do it from any commit, with a workflow
  they changed themselves. `permissionsync` holds no such secret.
- **Keep the release run tagging, and admit `main` in the environment.** The
  environment would then admit any run on `main`. That includes a
  `pull_request_target` workflow there, whose environment rules GitHub
  evaluates against the default branch. The run would also sign a commit
  nobody tagged by hand.
- **Sign with this project's own tool in the job** (`classisctl package sign`,
  or an internal `cargo xtask`). The job would check out the repository and
  build it, running every dependency's build script beside the key.
- **Sign with a `classisctl` built by the `build` job.** The job holding the key
  would run a binary built where every dependency's build script ran.
- **A cloud KMS reached through OIDC.** It keeps the key out of GitHub, but it
  needs a cloud account and a policy that live outside this repository. Not
  pursued for this step.
- **A Sigstore keyless signature (cosign).** Neither the Client nor the Server
  verifies one. Both verify Ed25519 against a configured key.
- **Sign in `publish`.** `publish` holds `contents: write`, `packages: write`,
  `id-token: write` and `attestations: write`. The key would sit beside every
  one of them, and ADR-0052 clause 11 limits that job to two actions.
- **The certificate chain now.** It needs the root certificate a colleague is
  preparing, and changes to the Client. It is a later step.

## Sources / Prior art

Read on 2026-11-12 and 2026-11-13.

- GitHub Docs, _Deployments and environments_: environment secrets reach only a
  job that names the environment, after approval; up to six required
  reviewers, with _Prevent self-review_; deployment rules matched against
  `GITHUB_REF`; administrator bypass; required reviewers on Free, Pro and Team
  for public repositories only:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments>.
- GitHub Docs, a run uses the workflow of the event's commit or ref:
  <https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows>.
- GitHub Docs, who can read repository secrets:
  <https://docs.github.com/en/actions/reference/security/secure-use>.
- GitHub Docs, rulesets for tags, _Restrict creations_, _Restrict updates_,
  _Restrict deletions_:
  <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>.
- GitHub Changelog, environment rules for `pull_request_target` evaluated
  against the default branch from 2025-12-08:
  <https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/>.
- OpenSSL 3.0, `openssl-pkeyutl`: `-rawin` required for EdDSA, no HashEdDSA,
  input from a file of known size:
  <https://docs.openssl.org/3.0/man1/openssl-pkeyutl/>. `ubuntu-latest` is
  Ubuntu 24.04, which lists OpenSSL 3.0.13:
  <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>,
  <https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md>.
- RFC 8032 §5.1.6, Ed25519 signing:
  <https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6>.
- The rulesets of `neteye-platform/permissionsync`, read through the GitHub
  REST API (`/repos/neteye-platform/permissionsync/rulesets`) on 2026-11-13.
  Its `release-image.yaml` uses `GITHUB_TOKEN` alone.

## Consequences

- **Positive:**
  - An operator trusts the Client's releases by taking one public file. A
    non-interactive install takes it from beside the program without a
    question, and the questionnaire offers it as the default (ADR-0029 clause
    6).
  - No release is signed by one person alone.
  - The signing job builds nothing and runs nothing from this repository's
    sources or dependencies, only the shell of its own steps.
  - The Client, the Server and the operator tool stay as they are.
- **Negative / trade-offs:**
  - A repository admin can change the environment's reviewers and rules, or
    replace the secret. The organisation's audit log records it.
  - An exposed key signs Packages that every installation trusting it accepts,
    until each installation's `verification_key` changes. There is no
    revocation. Reverting the workflow does not undo an installation's trust in
    the key.
  - A lost key means a new public half that every installation must take, by
    hand.
  - Only the reviewer makes sure a tag names a commit on `main`. GitHub does not
    enforce it, and the check of clause 4 guards against mistakes only.
  - A tag can be neither deleted nor moved. A tag pushed to the wrong commit, or
    a run whose approval is rejected or expires, spends that version, and the
    release moves on to the next number (ADR-0012 clause 7).
  - The documentation does not say whether _Prevent self-review_ also stops
    someone who re-runs a job another person started.
  - A release always needs a hand-pushed tag. ADR-0012 rejected hand-typed tags
    for fear of a typed-tag mistake. Its clause 7 now catches that mistake,
    since a run fails when its tag disagrees with `Cargo.toml`.
- **Specification:** "Software is installed only when it is signed with a key
  the operator holds" no longer describes the Client's releases. A change is
  drafted below. Landing it is the human's, and so is naming the accepted ADRs
  whose basis it moves ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 7).
  - _Strategy_: "Software is installed only when it is signed with a key the
    operator chooses to trust, this project's release key or one the operator
    holds, and fetched from the fleet itself: the Server, or a Gateway relaying
    it."
  - _Package_: "…the artifact's content hash, its size and a signature by a key
    the operator trusts. … the Server checks a signature against the public key
    it was given, when it has one, and reports a failed check, but the Agent's
    check decides."
  - A search for the operator's key found these ADRs:
    - ADR-0017;
    - ADR-0026 (Context and Consequences);
    - ADR-0027;
    - ADR-0028;
    - ADR-0033 (Context and clause 7);
    - ADR-0043 (Context and clause 4).

    The two clauses describe a mechanism that still holds with the release key
    configured. Whether their wording moves is for the human to judge.
- **Follow-ups:**
  - `publish` verifying every `.sig` against the tracked
    `packaging/package-signing-key.pub` before the release is created. The
    check is anchored in the reviewed file, never in the secret: checked
    against the secret, a signature would only be compared with itself.
  - A certificate chain: a root certificate compiled into the Client and the
    Server, a signing certificate issued by it, and a container that carries
    the certificate. Replacing the signing key would then need no change on any
    installation.
  - The release run signing the third-party Packages the project distributes.
  - A `CODEOWNERS` entry for `.github/workflows/`.
  - Removing the operator's own signing commands, once nothing needs them.

## Enforcement

Tests in `crates/classis-tools/tests/release_workflow.rs`, each marked
`// Verifies: ADR-0062`:

- **A release starts only from a tag (clauses 3 to 5).**
  - The workflow triggers on `push: tags: ["version/*"]` and on
    `workflow_dispatch` with no input.
  - No job pushes a tag.
  - The `version` job holds `contents: read`.
  - The `version` job refuses a tagged commit not reachable from `origin/main`.
- **Only `sign` names the environment (clauses 2, 6 and 7).**
  - `sign` names `signing`, runs only on a push event, needs `version` and
    `build`, and holds `contents: read` alone.
  - It has no checkout and no step that builds.
  - Its only actions are `download-artifact` and `upload-artifact`, pinned.
  - It downloads only `supervisor_*.tar.gz.sha256`.
  - Its key-removal step runs `if: always()`.
  - No other job names `signing`.
- **The signed statement is the one the Client verifies (clause 6).**
  - The test takes the signing step's script out of the workflow, unchanged,
    and runs it with a test key from `ring` and the system's `openssl`.
  - It checks that the file the script signs equals
    `classis_core::package::statement`.
  - It checks that the `.sig` decodes and verifies under `ring`.
  - The test fails, never skips, when no OpenSSL 3 `openssl` is on the path.
- **The signatures and the key are published and attested (clauses 1, 8 and
  9).**
  - `version` uploads `packaging/package-signing-key.pub` as an artifact.
  - `publish` downloads, attests and publishes the `.sig` files and that file.
  - The notes tell an operator how to use both.
- **The tracked key has the form an install takes (clause 1).**
  `packaging/package-signing-key.pub`, trimmed, is 64 hexadecimal digits.

**Not mechanically decidable:** the repository settings of clauses 2 and 10,
meaning the environment's reviewers and rules and the rulesets. They live on
GitHub, not in a file, and the _Repository settings_ section of `README.md`
lists them for a maintainer to configure and re-check. The reviewer's check that
a tag names a commit on `main` is a review step.
