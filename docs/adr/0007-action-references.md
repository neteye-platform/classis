# ADR-0007: GitHub Actions are referenced by their major version tag and kept current by Dependabot

- **Status:** ⚪ superseded by [ADR-0044](0044-third-party-actions-are-pinned-to-a-commit-sha.md)
- **Date:** 2026-09-20
- **Deciders:** NUC maintainer
- **Applies to:** every `uses:` reference in `.github/workflows/`, and `.github/dependabot.yml`

## Context

Every `uses:` line in [`.github/workflows/`](../../.github/workflows/) runs third-party code with
the repository's token, and how the reference is written decides both how current that code stays
and how far a compromise of its repository reaches. GitHub's hardening guide recommends the full
commit SHA: pinning that way "is currently the only way to use an action as an immutable release",
because a tag "can be moved or deleted if a bad actor gains access to the repository storing the
action". A reader who knows the guide takes the major tag for a mistake and corrects it, which is
the case [`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 2, records however cheap it is to
reverse.

## Decision

We will reference every GitHub Action by its **major version tag** (`uses: owner/action@vN`) and
let **Dependabot** raise the pull request for a new major, from
[`.github/dependabot.yml`](../../.github/dependabot.yml) with the `github-actions` ecosystem. A
commit SHA, a branch, an untagged action, and a full version tag are not used; a `docker://` image
carries an explicit tag; a local action (`./…`) is exempt.

The mutability of the tag is the accepted risk. The exposure is confined to the first-party
actions (`actions/*`) these workflows use, and a project that runs actions it trusts less
supersedes this decision with SHA pinning and a stricter check.

**Out of scope:** which actions the workflows use and whether third-party ones may be added; a
lockfile rule for the project's toolchain; Dependabot for Dev Container Features, the follow-up
[ADR-0002](0002-dev-container-runtime.md) names.

## Alternatives considered

- **The full commit SHA the guide recommends.** Immutable, and it receives no updates at all: every
  fix, security fixes included, arrives as a pull request, and an unmerged one means running
  known-stale code. Right where the actions are not trusted, wrong for first-party ones and few
  maintainers.
- **A full version tag (`@v7.0.1`).** As mutable as the major tag, so nothing is gained, and as
  frozen as a SHA.

## Sources / Prior art

- GitHub, *Security hardening for GitHub Actions* —
  <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>:
  the recommendation this decision deviates from.
- GitHub Advisory GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 —
  <https://github.com/advisories/GHSA-mrrh-fwg8-r2c3>: the version tags of
  `tj-actions/changed-files` were retagged to a commit that printed the runner's secrets into the
  workflow logs, the concrete case of the accepted risk.
- GitHub, *Keeping your actions up to date with Dependabot* —
  <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot>:
  the `github-actions` ecosystem and the schedule keys.

## Consequences

- Positive: the workflows pick up new releases of their major, security fixes included, without a
  pull request, and a new major arrives as a reviewable one; the format matches the Feature pinning
  of [ADR-0002](0002-dev-container-runtime.md) and is held by a check rather than by habit.
- Negative / trade-offs: a repointed tag runs in CI with the repository's token before anyone sees
  a diff.
- Follow-ups: Dependabot for Dev Container Features, once the lock's behaviour under an update is
  known.

## Enforcement

[`scripts/check-action-refs.sh`](../../scripts/check-action-refs.sh) (job `actions` in
[`checks.yml`](../../.github/workflows/checks.yml)) reads every uncommented `uses:` line of the
workflows and fails on a reference that is not a major version tag, on a `docker://` image without
a tag, and on a missing `dependabot.yml` or one without the `github-actions` ecosystem. Its
self-test cites this ADR ([ADR-0003](0003-decisions-verified-by-tests.md)). Not checked: whether
an action is first-party, which is review, and whether Dependabot is enabled for the repository,
which is a setting.
