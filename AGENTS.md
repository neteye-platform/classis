# Agent Guide

> **The single rule file of this project.** Every working rule lives here; where
> another document repeats one, this wording governs. Project conventions go
> into [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md), into checks, and into ADRs.
> A procedure is a skill under [`.agents/skills/`](.agents/skills/) that cites a
> rule here and states none of its own.

## 1. Principles

The human decides _why_ and _what_; the agent works out _how_. A how that binds
future choices is the human's too, recorded with its why in an ADR
([§3](#3-adr-rules)). Four principles win over speed and cleverness:

- **Simplicity.** Build the simplest thing that satisfies the specification. Add
  a dependency or an abstraction only for a present need. Removing code is
  progress. Justify warranted complexity in an ADR.
- **Proportionality.** Ceremony scales with how hard a change is to reverse.
  Skipping ceremony a reader would expect is said out loud.
- **Reflection.** Weigh alternatives and consequences, and write the reasoning
  down.
- **Critical stance.** Take nothing at face value: not the human's framing, not
  your own earlier output, not the existing code. Verify against the
  specification, the ADRs, the code, and authoritative sources. Disagreement,
  with its evidence, and what you could not confirm go into the pull request,
  where "none" is a claim the reviewer checks.

## 2. Start here

Before any non-trivial work, read:

1. [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md): problem, goals, success
   criteria, in the vocabulary of [`docs/GLOSSARY.md`](docs/GLOSSARY.md).
2. [`docs/adr/README.md`](docs/adr/README.md): the ADR index. **Accepted ADRs
   are binding.** A `proposed` ADR binds the work that implements it. Rejected
   and superseded ADRs explain _why_; they are not rules.
3. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the system as it stands
   today. Where it and an accepted ADR disagree, the ADR is right.

This repository began as an import of the upstream project `opamp-fleet`
(git tag `upstream-import`) and is being reduced to the OpAMP client-server
core. Code, documents, and comments that still describe the upstream scope
(fleet management, user interface, REST API, client certificates, packaging)
are leftovers, not requirements: **the specification governs.** The ADRs of
upstream were removed and bind nothing.

## 3. ADR rules

Authority runs **specification → accepted ADRs → task**. The mechanics of the
record are in [`docs/adr/README.md`](docs/adr/README.md).

1. **An ADR records what the code cannot say:** an external constraint (a
   supplier, a customer, a compliance rule, an upstream protocol version), a
   rejected alternative, a choice that a reader without this conversation would
   take for a mistake, or the condition under which a choice must be revisited.
   It never describes how the code works: an agent reads that from the code, and
   a test decides what a test can decide.
2. **No ADR** for implementing within an accepted ADR, bug fixes,
   interface-preserving refactorings, tests, docs, formatting, and dev-only
   tooling. When genuinely unsure, prefer a short `proposed` ADR over a silent
   decision.
3. **Develop the ADR with the human, critically.** Submit it with status
   `proposed`. Skill: `propose-adr`.
4. **Only a human changes the status** of an ADR.
5. **Accepted ADRs are binding.** Never violate or work around one; change it by
   superseding it. ADR numbers are permanent. If the specification and an ADR
   conflict, the specification wins: raise the conflict, never choose silently.
6. **Use the vocabulary of [`docs/GLOSSARY.md`](docs/GLOSSARY.md)** in code,
   comments, and documentation. Add a term in the same change that settles it.
7. **A change to the specification is a decision, not an edit.** Only a human
   lands one, and it names every accepted ADR whose basis it moves. An agent
   drafts specification text; it never lands the change.

## 4. Working style

- **Reply to the human in their own language.** Everything else is English:
  code, comments, commits, docs, ADRs, pull requests.
- **Prefer small, reviewable changes.** Plan and explore before a larger one.
  Commits and pull requests name the ADR they implement (`Implements ADR-NNNN`).
- **Cut work into vertical slices,** each a thin, tested path through every
  layer it touches. The exception is a wide mechanical refactor: expand, migrate
  in batches, contract, every step green.
- **Write to [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md).** Settle a new
  judgement call there in the same change that raised it. One a check can decide
  becomes the check ([§5](#5-quality-bar--definition-of-done)); one that
  constrains future choices becomes an ADR.
- **Keep the context lean.** Subagents return conclusions, not file dumps. A
  degraded session hands off.
- **Session artifacts are not tracked.** Plans, handoff notes, and scratch files
  live under `.scratch/` (gitignored) or outside the tree.
- **Research before a decision that is costly to reverse,** external sources
  included, cited in the ADR. Never pass off recalled interfaces, versions, or
  defaults as verified.
- **When scope or intent is still open, ask the human before implementing.**

## 5. Quality bar & Definition of Done

- **A change is done only when it builds, its tests pass, and linters and
  formatters are clean,** locally and in CI. Never hand off or propose merging
  red.
- **Run [`scripts/check-all.sh`](scripts/check-all.sh) before pushing.** It runs
  the build, test, and lint commands of the README's **Build, Test & Run**
  section with the repository's checks, and CI runs the same on every pull
  request.
- **New behaviour ships with tests; a bug fix ships with a regression test**
  that fails before the fix and passes after. Genuinely untestable: say so and
  why.
- **The suite is the contract an implementation is held to,** so it tests
  through interfaces the implementation can change behind. Before changing what
  exists, pin the behaviour that must stay, tests first where none exist.
- **Every specification criterion (`G-n`, `Q-n`) is cited by a test** with a
  `Verifies: <id>` marker.
- **Never weaken the suite to make it pass. A flaky test is a defect, not
  noise:** no retries, no re-running until green.
- **Review in a fresh context before handing off.** The session that wrote a
  change never reviews it. The reviewer gets the diff, the task, the doubts, and
  the standards, never the reasoning. Findings are fixed before the pull request
  opens. Skill: `review`.
- **A mistake a check could have caught becomes a check,** shipped with the fix.
  A rule in prose is the fallback for what no check can decide.
- **Keep the diff releasable.** No commented-out code, stray debug output, or
  `TODO` standing in for a decision. Unfinished work is an issue or a `proposed`
  ADR, not hidden in the tree.
- **A change to the structure updates
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** in the same change.

## 6. Project rules

- **Commit freely on a branch, never on `main`. A human decides what leaves the
  machine.** Pushing, `gh`, and anything that rewrites or discards history
  (`reset`, `rebase`, `merge`, `restore`, `clean`) wait for an instruction that
  names it and implies no next one. The git hooks under
  [`.githooks/`](.githooks/) refuse a commit on `main` and a push while the
  checks of [§5](#5-quality-bar--definition-of-done) are red.
- **Authenticate `gh` through its web flow;** a human enters the one-time code.
  Never request, store, or hard-code personal access tokens.
- **The Dev Container mounts no host Docker socket** and adds no Feature that
  would; `devcontainer-lock.json` is committed.
- **Changes reach `main` through a pull request.** What no file can enforce is
  listed under [Repository settings](README.md#repository-settings).

## 7. Secrets

- **Never write a secret into a tracked file, commit message, ADR, log, or CI
  output.** Secrets live in environment variables, gitignored `.env*` files, or
  GitHub Actions secrets. A placeholder in a tracked `.env.example` is not a
  secret.
- **A secret that reaches git is compromised.** Rotation comes first and is the
  human's to perform; removing it from the branch tip is cleanup, not
  remediation. Tell the human immediately.
- No check enforces either rule. What the repository's configuration does about
  secrets, and where it stops, is in
  [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md#secrets).
