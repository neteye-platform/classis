# ADR-0008: The template is released as SemVer tags on `main`, and every repository names the release it carries

- **Status:** 🟢 accepted
- **Date:** 2026-09-20
- **Deciders:** NUC maintainer
- **Applies to:** the tags of the template repository, the **Template** section of `README.md`, and the pull request that lands a release

## Context

The template has no releases: no tag, no version, and no state a maintainer can point to as
coherent beyond the checks being green on every commit. GitHub's template mechanism copies the
default branch at the moment a repository is created, without history and without tags, and
offers no choice of a version. Two things follow. Nobody can say which state of the template a
derived project inherited, so the difference between what it has and what the template now says
cannot be computed, and a template change reaches a derived project by chance. And a project
that wants to take up a change has no unit to take it up in: a commit is too small and `main` is
a moving target.

Three forces limit the answer. The template ships no toolchain, so release tooling is out. Its
maintainers are few and its releases rare, so a chore on every pull request costs more than it
returns. And the tags do not travel with the copy, so whatever names the release has to be a
tracked file the derived repository carries.

## Decision

We will release the template as **annotated tags `vX.Y.Z`** on `main`, versioned by
[SemVer 2.0.0](https://semver.org/spec/v2.0.0.html), and keep a **Template** section in
[`README.md`](../../README.md) whose `Template release` line names the release the repository
carries: in the template the last release cut, in a derived project the release it was created
from, and `unreleased` before the first.

- **Cutting a release is a human's act:** a pull request moves the line to the new version and
  is tagged once merged. The tag's annotation, and the GitHub release built from it, say what
  changed and what a derived project does to take it up.
- **A tag is `vX.Y.Z` and nothing more:** no pre-release suffix and no build metadata, which
  SemVer allows and this template has no use for; what is not ready to be released is not
  tagged.
- **Major, minor, patch:** a major is a change an existing derived project must act on, such as
  a check that would fail on its tree or an inherited ADR superseded; a minor adds a check, an
  ADR, a skill, or a document; a patch changes wording. Before `v1.0.0` a minor may break, per
  SemVer item 4.
- **A derived project moves the line** when it takes up a later release, and only then; a line
  never moved still tells the truth.

**Out of scope:** a changelog file; release automation; how a derived project merges a release,
by subtree, by patch, or by hand; which releases receive fixes, which
[`SECURITY.md`](../../SECURITY.md) states.

## Alternatives considered

- **No versions; the default branch is the template** — the state this ADR ends: every derived
  project carries an unnamed state and no change can be taken up as a unit.
- **CalVer** — a date carries no signal of what a derived project must do; the major is that
  signal.
- **A changelog file kept per pull request** — a chore on every change of a template released
  rarely; the tag annotation and the pull requests between two tags say the same, once.
- **A templating tool with versioned updates (copier, cruft)** — real version selection at
  creation and an update path afterwards, at the price of a Python toolchain on every host that
  creates a project and a template file to maintain. A project that wants the update path adds
  the tool on top of the tag; the tag is what it would pin anyway.
- **Release branches per major** — nothing to maintain for a template with few releases; a tag
  marks the same state.
- **A version file** — a file nobody reads and one more Project Layout entry; the README section
  a reader opens first answers the same question.

## Sources / Prior art

- Semantic Versioning 2.0.0 — <https://semver.org/spec/v2.0.0.html>, item 4 on `0.y.z`.
- GitHub, *Creating a repository from a template* —
  <https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template>:
  the default branch or all branches are copied, a version is not offered.
- GitHub, *About releases* —
  <https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases>: a
  release is built on a tag and carries notes.
- Copier — <https://copier.readthedocs.io/>: `--vcs-ref` at creation and `copier update`
  afterwards, the tool the alternative names.

## Consequences

- Positive: a derived project can say what it inherited and diff its state against a tag; the
  maintainer has a coherent state to point to; the version says whether taking it up is work;
  cutting a release is one line and one tag.
- Negative / trade-offs: the line is moved by hand, and a release nobody cuts leaves `main` ahead
  of the last tag, which harms nothing but names nothing either; a derived project that never
  moves the line reads a state that grows old; tags do not travel, which is why the line exists.
- Follow-ups: a procedure for taking up a release in a derived project, once one has done it.

## Enforcement

Check 14 of [`scripts/check-docs.sh`](../../scripts/check-docs.sh) (job `docs` in
[`checks.yml`](../../.github/workflows/checks.yml)) fails when `README.md` has no
`Template release` line or when the line names neither a `vX.Y.Z` tag nor `unreleased`; its
self-test cites this ADR ([ADR-0003](0003-decisions-verified-by-tests.md)). Not checked: that
the tag exists, because tags do not travel with the copy, and that the line moved with a
release, which is the release pull request's review.
