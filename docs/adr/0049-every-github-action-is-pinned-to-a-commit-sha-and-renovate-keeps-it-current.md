# ADR-0049: Every GitHub Action is pinned to a commit SHA, and Renovate on the organisation preset keeps it and every Cargo dependency current

- **Status:** 🟡 proposed
- **Date:** 2026-10-20
- **Deciders:** Davide Zeni
- **Applies to:** every `uses:` reference in `.github/workflows/`,
  `renovate.json`, the absence of `.github/dependabot.yml`,
  `scripts/check-action-refs.sh` and `scripts/test-check-action-refs.sh`, the
  `actions` job of `.github/workflows/checks.yml`, and the section _Actions in
  the workflows_ of `SECURITY.md`
- **Supersedes:**
  [ADR-0044](0044-third-party-actions-are-pinned-to-a-commit-sha.md)

## Context

This repository now lives in the `neteye-platform` organisation. Every
repository there, for example `permissionsync`, has its dependencies raised by
Renovate, from a `renovate.json` that extends the organisation preset
`github>neteye-platform/repo-commons`, and none has a `.github/dependabot.yml`.
This repository already carries that `renovate.json` and the
`renovate-config-validator` hook in `.pre-commit-config.yaml`. It also still
carries the `.github/dependabot.yml` of
[ADR-0044](0044-third-party-actions-are-pinned-to-a-commit-sha.md), whose clause
5 makes Dependabot the bot that raises every action update. With both enabled,
every update arrives twice.

The preset is not neutral about references. It extends `config:best-practices`,
which includes `helpers:pinGitHubActionDigests`: Renovate pins _every_ action to
a commit SHA, `actions/*` included, with the version in a comment. ADR-0044
clause 2 keeps first-party actions on their major tag, so under the preset
Renovate would raise a pull request that `check-action-refs.sh` refuses.

The preset is not neutral about Cargo either, and it is inconsistent here. It
extends `:pinDependencies` and, through `config:best-practices`,
`:pinDevDependencies`. These set `rangeStrategy: pin` for the `depType`s
`dependencies`, `dev-dependencies` and `dev`. Renovate's Cargo manager gives an
entry of `[workspace.dependencies]` the `depType` `workspace.dependencies`,
which neither preset matches. Almost every version requirement here sits in the
root `[workspace.dependencies]`
([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)).
Left as it is, the preset would rewrite to `=x.y.z` only the `tempfile`
dev-dependencies of three crates and the six dependencies of `fuzz/Cargo.toml`,
and leave the workspace on ranges. The `opamp` crate is `publish = true`, and it
inherits the workspace's requirements. An exact requirement in a published
library forces the consumer's resolver onto that one version.

The workflows call three reusable workflows of `neteye-platform/repo-commons`,
pinned as `@<sha> # main`. `repo-commons` publishes no tags, so no `# vX.Y.Z`
comment can name the release that the SHA came from. ADR-0044 clause 3 requires
one, and `check-action-refs.sh` fails on all three today.

Two threats from ADR-0044 stay true and still shape the decision. A tag can be
moved to a commit of the owner's choosing (CVE-2025-30066). A SHA can name a
commit that exists only in a fork, because a fork shares the object store of its
parent.

The specification's quality goal Q-3 asks that the supply chain be checked
before a change merges. The hard gate stays `cargo deny` in `audit.yml` and
`release.yml`. The bot that raises updates is the half that keeps the gate from
tripping. An action is part of the supply chain even though `cargo deny` does
not see it.

## Decision

We will let Renovate, from a `renovate.json` that extends the organisation
preset, raise every update of the workflows' actions and of the Cargo
dependencies, with every action pinned to a commit SHA and every Cargo
requirement left as a range that `Cargo.lock` pins.

1. **Every action and reusable workflow is referenced by a full commit SHA with
   its ref in a comment.** The reference is `owner/action@<sha>`, or
   `owner/repo/<path>@<sha>` for an action or reusable workflow inside a
   repository. `<sha>` is the full 40-character lowercase hexadecimal commit ID.
   The owner `actions` is no exception. A tag, a branch, a short SHA and a SHA
   without a comment are not used.

2. **The comment names a release, except for the organisation's own
   repositories.** The comment is `# vX.Y.Z`: the release tag, as three numbers,
   that the SHA was taken from. For an owner of `neteye-platform`, the comment
   may name a branch instead (`# main`), because those repositories publish no
   tags. A comment that names only a major (`# v2`), and a branch comment for
   any other owner, are not used.

3. **The commented ref resolves to the pinned SHA.** In the action's own
   repository, a commented tag must point to exactly the pinned commit. For an
   annotated tag that is the commit the tag object points to, not the tag
   object's own ID. A commented branch must contain the pinned commit: the
   commit is an ancestor of the branch head, or is the head. A SHA that its
   comment does not resolve to is refused, whether it comes from a fork, a moved
   tag, or a branch it was never on.

4. **Renovate raises every update, and Dependabot raises none.** `renovate.json`
   at the repository root extends `github>neteye-platform/repo-commons`.
   `.github/dependabot.yml` does not exist. Renovate's `github-actions` manager
   raises a pull request for every new release or branch head and rewrites the
   SHA and the comment together. Its `cargo` manager reads `Cargo.toml` and
   `fuzz/Cargo.toml`. Each pull request is reviewed and merged like any other
   change.

5. **A Cargo version requirement stays a range.** `renovate.json` sets
   `rangeStrategy: update-lockfile` for the `cargo` manager. This overrides the
   preset's `pin`. An in-range update changes only `Cargo.lock` or
   `fuzz/Cargo.lock`. An update outside the range replaces the requirement in
   `Cargo.toml` with a new range. No requirement is written as `=x.y.z`.

6. **A `docker://` image carries an explicit tag, and a local action is
   exempt.** A `docker://` reference names `:<tag>` on its last path segment. A
   local action (`./…`) is part of this repository and needs no reference.

**Out of scope:** which actions the workflows use, and whether a further
third-party action may be added. The content of the organisation preset, which
`repo-commons` decides. Merge policy for Renovate's pull requests (automerge,
schedules beyond the preset's). Whether Renovate is installed for the repository
and may read its Dependabot alerts, which are settings. Pinning a `docker://`
image by digest, which no workflow uses. Renovate for Dev Container Features,
which [ADR-0002](0002-dev-container-runtime.md) leaves as a follow-up.

## Alternatives considered

- **Keep Dependabot (ADR-0044).** It needs no change here. It is the only
  repository of the organisation on Dependabot, and the `renovate.json` that
  this repository already carries makes every update arrive twice. Rejected.
- **Run both bots, Dependabot for actions and Renovate for the rest.** This
  keeps clause 2 of ADR-0044 without an override. It gives two bots, two
  grouping policies and two places to look for one kind of change. Rejected.
- **Renovate, with `actions/*` kept on their major tag.** A `packageRules` entry
  that turns off digest pinning for `actions/**` keeps ADR-0044's model. The
  argument of ADR-0044 still holds: a SHA does not contain a compromise of
  `actions/*`, which is a compromise of GitHub Actions itself. The decider chose
  one rule without an exception, as the organisation's other repositories have.
  The cost, a pull request for each patch release of `actions/*`, is absorbed by
  the preset's `group:allNonMajor` and `group:allDigest`. Not chosen.
- **`=x.y.z` everywhere, as in `permissionsync`.** A `packageRules` entry that
  pins `workspace.dependencies` as well would make the workspace consistent. The
  published `opamp` crate would then impose exact requirements on its consumers,
  and `Cargo.lock` already pins what this repository builds. `permissionsync`
  publishes no library crate, so the same rule costs it nothing. Rejected.
- **The preset as it is.** It needs no override. It pins the dev-dependencies
  and `fuzz/` but not the workspace, so the repository would follow two
  conventions for one kind of line, and the next reader would "fix" one of them.
  Rejected.
- **A branch comment for any owner.** One rule for every repository. Third-party
  actions publish release tags, and a tag that resolves to the pinned SHA is a
  stronger statement than a branch that contains it. Rejected.
- **Reference the reusable workflows of `repo-commons` by a tag.** This gives
  them the same rule as every other action. `repo-commons` publishes no tags,
  and this repository cannot decide that it should. Not possible today. See the
  follow-ups.

## Sources / Prior art

- Renovate, _Config presets_, `config:best-practices` —
  <https://docs.renovatebot.com/presets-config/>, read 2026-10-20: it extends
  `config:recommended`, `docker:pinDigests`, `helpers:pinGitHubActionDigests`,
  `:configMigration`, `:pinDevDependencies`, `abandonments:recommended`,
  `security:minimumReleaseAgeNpm` and `:maintainLockFilesWeekly`.
- Renovate, _Default presets_ — <https://docs.renovatebot.com/presets-default/>,
  read 2026-10-20: `:pinDependencies` is
  `{"packageRules":[{"matchDepTypes":["dependencies"],"rangeStrategy":"pin"}]}`,
  and `:pinDevDependencies` matches `devDependencies`, `dev-dependencies` and
  `dev`.
- Renovate source, `lib/modules/manager/cargo/schema.ts` on `main`, read
  2026-10-20: the `[workspace]` table's `dependencies` are given
  `withDepType(CargoDeps, 'workspace.dependencies')`, and `dependencies`,
  `dev-dependencies` and `build-dependencies` their own names.
- Renovate, _Configuration options_, `rangeStrategy`
  (`docs/usage/configuration-options.md` on `main`, read 2026-10-20):
  "`update-lockfile` = Update the lock file when in-range updates are available,
  otherwise `replace` for updates out of range. Works for … `cargo` …".
- Renovate, _Configuration options_, `vulnerabilityAlerts` (same file): Renovate
  needs the Dependency graph and Dependabot alerts enabled, and in app mode
  `read` access to Dependabot alerts.
- Renovate, _GitHub Actions manager_ —
  <https://docs.renovatebot.com/modules/manager/github-actions/>, read
  2026-10-20: "Renovate will update the commit SHA according to the GitHub tag
  you specified"; "Actions pinned to a bare SHA without a version comment are
  disabled by default"; a tag or branch name may serve as the version comment.
  The page does not say in so many words that the comment is rewritten with the
  SHA. `permissionsync` shows it is: `actions/checkout@3d3c42e5… # v7.0.1` and
  `docker/login-action@dbcb8138… # v4.6.0`, raised by Renovate's grouped
  `fix(deps): update all non-major dependencies` (commit `449b158`).
- `permissionsync` at `449b158` and `repo-commons` at `0a794cd`, read
  2026-10-20: `permissionsync/renovate.json` extends the preset and adds one
  custom manager. Its `Cargo.toml` pins `axum = { version = "=0.8.9", … }` in
  `[dependencies]`, and it has no `[workspace.dependencies]`. Its workflows call
  `repo-commons` as `@<sha> # main`. `repo-commons` has no tags.
- Kept from ADR-0044 and recalled, not re-read for this record: GitHub's
  _Security hardening for GitHub Actions_ on SHA pinning as the only immutable
  reference; GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 (the moved tags of
  `tj-actions/changed-files`); fork commits reachable through the parent's name
  ("impostor commits", Chainguard, 2023).

## Consequences

- Positive: one bot and one configuration, the same as the rest of the
  organisation. One rule for every action, with no first-party exception to
  classify. The three `repo-commons` calls become legal, and a SHA that is not
  on their branch is still refused. Q-3 gains the preset's `vulnerabilityAlerts`
  handling, and its `cargo deny` gate stays as it is. The `Cargo.toml`
  convention stays the one already in place, and the published `opamp` crate
  keeps ranges.
- Negative / trade-offs: the configuration is partly outside this repository. A
  change to the preset on `repo-commons`' `main` reaches this repository with no
  pull request here, because the `extends` names no ref. A pull request for each
  patch release of `actions/*`, which ADR-0044 avoided, though grouped with
  every other non-major update. A security fix arrives as a Renovate pull
  request only while the Dependency graph and Dependabot alerts are on and the
  app may read them; Dependabot security updates themselves are off. A branch
  comment is a weaker statement than a tag: it says the SHA was on `main`, not
  which state of `main` was reviewed.
- Negative / trade-offs: the ancestor check of clause 3 needs more than
  `git ls-remote`, which shows a branch head only. The check fetches the
  branch's commit graph, which costs network and time in the `actions` job.
- Negative / trade-offs: `scripts/check-action-refs.sh`, its self-test and the
  workflows now differ further from the template's. A template release that
  changes them is merged by hand.
- Follow-ups: whether `repo-commons` should publish release tags, so that its
  reusable workflows and the preset could be referenced by one. Whether
  `extends` should name a ref of the preset once one exists.

## Enforcement

[`scripts/check-action-refs.sh`](../../scripts/check-action-refs.sh) (job
`actions` in [`checks.yml`](../../.github/workflows/checks.yml)) reads every
uncommented `uses:` line of the workflows and fails on any of these:

- a reference that is not a 40-character lowercase SHA followed by a comment,
  `actions/*` included (clause 1);
- a comment that is not `# vX.Y.Z`, unless the owner is `neteye-platform` and
  the comment names a branch (clause 2);
- a `docker://` image without a tag (clause 6);
- a missing `renovate.json`, one that does not extend
  `github>neteye-platform/repo-commons`, or an existing `.github/dependabot.yml`
  (clause 4);
- a `renovate.json` without a `packageRules` entry that matches the `cargo`
  manager and sets `rangeStrategy: update-lockfile` (clause 5).

With `--resolve`, which the `actions` job passes, it also checks each reference
against its repository. It fails when a commented tag does not exist or does not
peel to the pinned SHA, or when a commented branch does not exist or does not
contain the pinned SHA (clause 3).

[`scripts/test-check-action-refs.sh`](../../scripts/test-check-action-refs.sh)
will carry `Verifies: ADR-0049`. Its cases cover:

- `actions/checkout@<sha> # v7.0.1` passes, and `actions/checkout@v7` fails with
  a message naming clause 1;
- `neteye-platform/repo-commons/.github/workflows/w.yaml@<sha> # main` passes,
  and `other/repo@<sha> # main` fails with a message naming clause 2;
- a major tag, a SHA without a comment, a `# v2` comment, a short SHA and an
  uppercase SHA each fail;
- no `renovate.json`, one that extends another preset, one without the `cargo`
  rule, and a present `dependabot.yml` each fail;
- under `--resolve`, with a stub `git` on `PATH`: a matching lightweight tag and
  a matching annotated tag pass; a tag that peels to another SHA, a SHA equal to
  the tag object's own ID, and a missing tag fail; a branch that contains the
  SHA passes, and one that does not fail.

**Not mechanically decidable:** an `=x.y.z` requirement written into
`Cargo.toml` by hand, which the check of clause 5 does not see and review holds;
whether a new action is trustworthy enough to add; and whether Renovate is
installed and may read the repository's Dependabot alerts, which are settings.
The repository settings checklist in `README.md` holds the last two.
