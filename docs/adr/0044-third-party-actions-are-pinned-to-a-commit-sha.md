# ADR-0044: A third-party GitHub Action is pinned to a commit SHA with its version in a comment, a first-party one to its major tag, and Dependabot keeps both current

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** every `uses:` reference in `.github/workflows/`, `.github/dependabot.yml`, `scripts/check-action-refs.sh` and `scripts/test-check-action-refs.sh`, the `actions` job of `.github/workflows/checks.yml`, and the section *Actions in the workflows* of `SECURITY.md`
- **Supersedes:** [ADR-0007](0007-action-references.md)

## Context

Every `uses:` line in [`.github/workflows/`](../../.github/workflows/) runs code from another
repository with this repository's token. [ADR-0007](0007-action-references.md) references every
action by its major version tag. It accepts that a tag can be moved, on the premise that the
workflows run only first-party actions (`actions/*`), and it names the case for superseding it: "a
project that runs actions it trusts less supersedes this decision with SHA pinning and a stricter
check".

That premise no longer holds. Two third-party actions run in the workflows today:

- `Swatinem/rust-cache@v2` in `ci.yml` (three jobs), `checks.yml` (job `rust`), `interop.yml` and
  `service-smoke.yml`. It restores and saves `target/` and `~/.cargo`, so what it writes is
  compiled into the next run's test binaries.
- `taiki-e/install-action@v2` in `release.yml` (job `advisories`), `audit.yml` and `fuzz.yml`. It
  downloads and runs prebuilt tools, among them the `cargo-deny` that gates every release. The tool
  versions it resolves and the checksums it verifies come from manifests inside the action's own
  repository, at whatever commit the tag points to.

Either repository can move `v2` to a commit of its choosing, and the next run executes that commit.
In March 2025 the version tags of `tj-actions/changed-files` were moved to a commit that printed
the runner's secrets into the workflow logs (CVE-2025-30066). A full commit SHA is the only
reference GitHub treats as immutable.

A bare SHA tells a reader nothing. A trailing `# vX.Y.Z` comment names the release, and Dependabot
reads that comment: when it raises a SHA-pinned action, it rewrites the SHA and the comment in the
same line (recalled, not re-read for this record). The `github-actions` entry of
[`.github/dependabot.yml`](../../.github/dependabot.yml) already runs weekly and groups every action
update into one pull request.

A SHA has one weakness of its own. GitHub resolves `owner/repo@<sha>` for a commit that exists only
in a fork of `owner/repo`, because a fork shares the object store of its parent (recalled, not
re-read). A pull request can therefore name a SHA that no release of the action contains, while
its comment names a real release. Reading the diff does not catch this; resolving the commented
tag does.

GitHub's own actions (`actions/checkout`, `actions/upload-artifact`, `actions/download-artifact`,
`actions/setup-go`) are maintained by the platform that runs the workflow. A compromise of their
repositories is a compromise of GitHub Actions itself, and a SHA would not contain it. On their
major tag they receive fixes without a pull request.

The specification's quality goal Q-3 asks that the supply chain be checked before a change merges.
An action is part of that supply chain even though `cargo deny` does not see it.

## Decision

We will pin every third-party action to a full commit SHA followed by a `# vX.Y.Z` comment naming
its release, keep every first-party action on its major version tag, and let Dependabot raise both.

1. **First-party means owned by `actions`.** An action or reusable workflow whose owner is `actions`
   is first-party. Every other owner is third-party, including `github` (for example
   `github/codeql-action`). A reusable workflow is classified by the same rule as an action.

2. **A first-party action is referenced by its major version tag.** The reference is
   `actions/<name>@vN` or `actions/<name>/<path>@vN`. A commit SHA, a branch, a full version tag and
   an untagged reference are not used.

3. **A third-party action is referenced by a full commit SHA with its release in a comment.** The
   reference is `owner/action@<sha>`, or `owner/action/<path>@<sha>` for an action or reusable
   workflow inside a repository. `<sha>` is the full 40-character lowercase hexadecimal commit ID.
   The same line ends in a comment `# vX.Y.Z` that names the release tag, as three numbers, that the
   SHA was taken from. A major or full version tag, a branch, a short SHA, a SHA without the
   comment, and a comment that names only a major (`# v2`) are not used.

4. **The commented tag resolves to the pinned SHA.** In the action's own repository, the tag the
   comment names must point to exactly the pinned commit. For an annotated tag that is the commit
   the tag object points to, not the tag object's own ID. A SHA that is not the commit of its
   commented tag is refused, whether it comes from a fork or from a moved tag.

5. **Dependabot raises every update.** `.github/dependabot.yml` has an entry with
   `package-ecosystem: github-actions`. For a first-party action it raises the pull request for a
   new major. For a third-party action it raises one for every new release, rewriting the SHA and
   the comment together. Each such pull request is reviewed and merged like any other change.

6. **A `docker://` image carries an explicit tag, and a local action is exempt.** A `docker://`
   reference names `:<tag>` on its last path segment. A local action (`./…`) is part of this
   repository and needs no reference.

**Out of scope:** which actions the workflows use, and whether a further third-party action may be
added; pinning a `docker://` image by digest, which no workflow uses; a lockfile for the project's
toolchain; Dependabot for Dev Container Features, which
[ADR-0002](0002-dev-container-runtime.md) leaves as a follow-up.

## Alternatives considered

- **Pin every action to a SHA, `actions/*` included.** This gives one rule with no exception. It
  turns each patch release of `checkout`, `upload-artifact` and `download-artifact` into a pull
  request. It does not contain the threat it addresses: whoever can move a tag in `actions/*` can
  also change the runner those actions run on. Rejected.
- **Keep the major tags (ADR-0007).** This is the least work. It leaves the release gate's
  `cargo-deny` and every CI cache in the hands of whoever controls two third-party repositories, the
  exact case ADR-0007 names for its own supersession. Rejected.
- **Vendor the actions into `.github/actions/`.** A local copy is immutable and needs no network
  lookup. It also needs no Dependabot, so every upstream fix is a manual port. `taiki-e/install-action`
  is mostly its tool manifests, which change several times a week. Rejected.
- **Pin to a full version tag (`@v2.9.2`).** It names the release readably. A tag can be moved like
  a major tag, so this gives no immutability. Rejected, as ADR-0007 rejected it.
- **Replace the third-party actions with `run:` steps.** `cargo install --locked <tool>@<version>`
  instead of `install-action`, and `actions/cache` with explicit keys instead of `rust-cache`. This
  removes the dependency rather than pinning it. It costs build minutes in every CI job, and a cache
  key of our own is code to maintain. The release workflow already installs its packaging tools this
  way. Not chosen for CI. A later decision may still take it for a single action.

## Sources / Prior art

- GitHub, *Security hardening for GitHub Actions*, section *Using third-party actions* —
  <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>:
  "Pinning an action to a full length commit SHA is currently the only way to use an action as an
  immutable release." Recalled, not re-read for this record.
- GitHub Advisory GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 —
  <https://github.com/advisories/GHSA-mrrh-fwg8-r2c3>: the moved tags of `tj-actions/changed-files`.
- GitHub, *Keeping your actions up to date with Dependabot* —
  <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot>:
  Dependabot updates actions referenced by SHA, and updates a version comment on the same line that
  names the current release. Recalled, not re-read for this record.
- The commits of a fork are reachable through the parent repository's name, reported for Actions
  as "impostor commits" (Chainguard, 2023). Recalled, not re-read for this record.
- OpenSSF Scorecard, check *Pinned-Dependencies*: it flags an action that is not pinned by SHA.
  Recalled, not re-read for this record.
- The tags as of 2026-10-18, read with `git ls-remote`: `Swatinem/rust-cache` `v2` and `v2.9.2`
  peel to commit `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` (both are annotated tags);
  `taiki-e/install-action` `v2` and `v2.87.29` point to commit
  `8cca0918f8471c33515202b73f56ab27f2bed283` (lightweight tags).

## Consequences

- Positive: a moved tag in either third-party repository no longer reaches a run. The `cargo-deny`
  version and checksum that gate a release change only by a reviewed commit. A reference names the
  release it runs, and a SHA from a fork fails the check before it merges.
- Negative / trade-offs: every third-party release is a pull request. `taiki-e/install-action`
  publishes several a week, which the weekly grouped Dependabot run turns into at most one pull
  request a week for all actions. A fix in a third-party action arrives only when that pull request
  is merged. The resolution check needs the network: an unreachable GitHub fails the `actions` job,
  and a tag that upstream deletes or moves fails every pull request until the reference is raised.
  That failure is the signal clause 4 exists for. The comment grammar `vX.Y.Z` excludes an action
  whose tags carry no leading `v`; taking one on means changing this decision.
- Negative / trade-offs: `scripts/check-action-refs.sh` and its self-test now differ from the
  template's. A template release that changes them must be merged by hand, and ADR-0007 stays
  superseded here whatever the template does with it.
- Follow-ups: whether Dependabot *alerts* (as opposed to version updates) match a SHA-pinned
  action against an advisory was not verified for this record. Also open: a networked check that a
  first-party major tag still exists.

## Enforcement

[`scripts/check-action-refs.sh`](../../scripts/check-action-refs.sh) (job `actions` in
[`checks.yml`](../../.github/workflows/checks.yml)) reads every uncommented `uses:` line of the
workflows and fails on any of these:

- an `actions/*` reference that is not a major version tag (clause 2);
- a third-party reference that is not a 40-character lowercase SHA followed by `# vX.Y.Z` (clause 3);
- a `docker://` image without a tag (clause 6);
- a missing `dependabot.yml`, or one without the `github-actions` ecosystem (clause 5).

With `--resolve`, which the `actions` job passes, it also runs `git ls-remote` on each third-party
repository. It fails when the commented tag does not exist or does not peel to the pinned SHA
(clause 4).

[`scripts/test-check-action-refs.sh`](../../scripts/test-check-action-refs.sh) will carry
`Verifies: ADR-0044`. Besides the existing cases, it covers:

- a third-party SHA with its comment passes;
- a third-party major tag, a SHA without a comment, a `# v2` comment, a short SHA and an uppercase
  SHA each fail with a message naming clause 3;
- `actions/checkout` on a SHA fails, and `github/codeql-action/init@v3` fails as third-party;
- a reusable workflow `owner/repo/.github/workflows/w.yml@<sha> # v1.2.3` passes;
- under `--resolve`, with a stub `git` on `PATH`: a lightweight tag that matches passes, and an
  annotated tag whose peeled commit matches passes; a tag that peels to another SHA, a SHA equal to
  the tag object's own ID, and a missing tag each fail.

**Not mechanically decidable:** whether a new third-party action is trustworthy enough to add, and
whether Dependabot is enabled for the repository, which is a setting. Review holds the first; the
repository settings checklist in `README.md` holds the second.
