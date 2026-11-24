# Agent Guide

> **The single rule file of this project.** Every working rule lives here;
> where another document repeats one, this wording governs. Project conventions
> go into [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) and into checks. A
> procedure is a skill under [`.agents/skills/`](.agents/skills/) that cites a
> rule here and states none of its own.

## 1. Principles

The human decides _why_ and _what_; the agent works out _how_. A how that binds
future choices is the human's too ([§3](#3-decisions)). Four principles win over
speed and cleverness:

- **Simplicity.** Build the simplest thing that satisfies the specification. Add
  a dependency or an abstraction only for a present need. Removing code is
  progress. Justify warranted complexity in the pull request.
- **Proportionality.** Ceremony scales with how hard a change is to reverse.
  Skipping ceremony a reader would expect is said out loud.
- **Reflection.** Weigh alternatives and consequences, and write the reasoning
  down.
- **Critical stance.** Take nothing at face value: not the human's framing, not
  your own earlier output, not the existing code. Verify against the
  specification, the architecture overview, the code, and authoritative
  sources. Disagreement,
  with its evidence, and what you could not confirm go into the pull request,
  where "none" is a claim the reviewer checks.

## 2. Start here

Before any non-trivial work, read:

1. [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md): problem, goals, success
   criteria, in the vocabulary of [`docs/GLOSSARY.md`](docs/GLOSSARY.md).
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the system as it stands
   today, and its key decisions.

Scaffold text in those documents, such as a placeholder title, an empty section,
or a `TODO`, is the first work: say so and elaborate it with the human before
implementing.

## 3. Decisions

Authority runs **specification → architecture overview → task**. Working rules
originate here and nowhere else: another document cites a section by its anchor
(`[AGENTS.md §3](AGENTS.md#3-decisions)`) and restates nothing, and a rule this
file does not state is not a rule of this project.

1. **Agree an architecture-relevant decision with the human before building
   it:** a dependency or framework, a public interface, a persistence or
   synchronization strategy, a protocol or data format, anything that constrains
   future technology choices. Its reasoning goes into the pull request.
2. **The key decisions live in
   [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), one line each,** describing
   the system as it is. A change that alters one edits that line in place: no
   numbers, no supersession, no history. Do not cite the overview from code
   comments; a comment explains the code in front of it.
3. **If the specification and the code or the overview conflict, the
   specification wins:** raise the conflict, never choose silently.
4. **Use the vocabulary of [`docs/GLOSSARY.md`](docs/GLOSSARY.md)** in code,
   comments, and documentation. Add a term in the same change that settles it; a
   missing entry is a gap to close there, not a word to invent.
5. **A change to the specification is a decision, not an edit.** Only a human
   lands one. An agent drafts specification text; it never lands the change.

## 4. Working style

- **Reply to the human in their own language.** Everything else is English:
  code, comments, commits, docs, pull requests.
- **Prefer small, reviewable changes.** Plan and explore before a larger one.
- **Cut work into vertical slices,** each a thin, tested path through every
  layer it touches; the first through new ground is the tracer bullet. The one
  exception is a wide mechanical refactor: expand, migrate in batches, contract,
  every step green.
- **Write to [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md).** Settle a new
  judgement call there in the same change that raised it. One a check can decide
  becomes the check ([§5](#5-quality-bar--definition-of-done)); one that
  constrains future choices is a decision ([§3](#3-decisions)).
- **Plan work larger than one session on the issue tracker:** a feature spec cut
  into tracer-bullet tickets. Skill: `plan-feature`.
- **Work with the human:** small steps, reasoning surfaced, feedback sought
  early. A task runs unattended only when its ticket answers for it: a test
  decides its criteria, its scope is isolated and a wrong result costs one
  revert, and it says how a wrong result is noticed and undone, what proves it
  right, and the stop past which the session hands off instead of trying on.
- **Keep the context lean.** Subagents return conclusions, not file dumps.
  Alignment, implementation, and review each start in a fresh session with only
  what they need, never by compacting the old one. The implementing session
  loads what its ticket's _Read first_ names. A degraded session hands off.
- **Session artifacts are not tracked.** Plans, handoff notes, and scratch files
  live under `.scratch/` (gitignored) or outside the tree. What has to outlive
  the session becomes an issue or a change to a tracked document.
- **Research before a decision that is costly to reverse,** external sources
  included, cited in the pull request. Below that bar, research what you are
  actually unsure of. Never pass off recalled interfaces, versions, or defaults
  as verified.
- **Open an issue first when scope or intent is still open.** The trigger is
  disagreement about _why_ and _what_, not size. **When in doubt, ask the human
  before implementing.**

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
  exists, pin the behaviour that must stay, tests first where none exist. A
  rewrite or migration is done when the old suite passes against the new
  implementation.
- **Every specification criterion (`G-n`, `Q-n`) is cited by a test** with a
  `Verifies: <id>` marker.
- **Never weaken the suite to make it pass. A flaky test is a defect, not
  noise:** no retries, no re-running until green.
- **Review in a fresh context before handing off.** The session that wrote a
  change never reviews it. The reviewer gets the diff, the task, the doubts, and
  the standards, never the reasoning, and reports on two axes: does it do what
  was asked; does it meet this bar, simplicity first. Findings are fixed before
  the pull request opens, and every existing test the diff changes or removes
  needs a reason. Skill: `review`.
- **A feature spec closes only after a design revision** in a fresh session over
  the modules its tickets touched and the criteria they serve, filed as
  tickets, checks, an edit to the architecture overview, or a drafted
  specification change; with no spec open, one runs when the human asks for it.
  Skill: `design-revision`.
- **A mistake a check could have caught becomes a check,** shipped with the fix.
  A rule in prose is the fallback for what no check can decide. The design
  revision drops what prevented nothing.
- **Keep the diff releasable.** No commented-out code, stray debug output, or
  `TODO` standing in for a decision. Unfinished work is an issue, not hidden in
  the tree.
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

- **Never write a secret into a tracked file, commit message, log, or CI
  output.** Secrets live in environment variables, gitignored `.env*` files, or
  GitHub Actions secrets. A placeholder in a tracked `.env.example` is not a
  secret.
- **A secret that reaches git is compromised.** Rotation comes first and is the
  human's to perform; removing it from the branch tip is cleanup, not
  remediation. Tell the human immediately.
- No check enforces either rule. What the repository's configuration does about
  secrets, and where it stops, is in
  [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md#secrets).
