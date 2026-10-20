# ADR-0005: The procedures of the rule file are Agent Skills under `.agents/skills/`, each carrying a how and no rule of its own

- **Status:** 🟢 accepted
- **Date:** 2026-09-18
- **Deciders:** NUC maintainer
- **Applies to:** `.agents/skills/`, the pointers under `.claude/skills/`, and every document that describes how a procedure of `AGENTS.md` is carried out

## Context

[`AGENTS.md`](../../AGENTS.md) states rules. Four of them are procedures — developing an ADR
([§3](../../AGENTS.md#3-adr-rules), rule 3), planning work larger than one session
([§4](../../AGENTS.md#4-working-style)), reviewing a change, and revising the design when a
feature spec closes ([§5](../../AGENTS.md#5-quality-bar--definition-of-done)) — and each was
written out in the rule file and again where it is used: the ADR template, the issue templates,
the pull request template. Four copies drift, and every sharpening lands in a file that every
session reads in full whether it reviews, plans, or fixes a typo.

Two forces limit the answer. The rule file is the single source of working rules, and no other
document may state one (ADR-0001) — so wherever a procedure moves, it must carry the *how* and
cite the rule, never restate it. And the template is vendor-neutral: a format one agent reads is a
pointer file's worth of accommodation, not a home for process.

Agent Skills — a directory with a `SKILL.md` whose front matter names it and says when it applies,
loaded in full only when a task matches — are an open specification adopted by every agent this
template names and some forty others. The location is not part of the specification: Codex, Gemini
CLI, and Cursor read `.agents/skills/`; Claude Code reads only `.claude/skills/`, and the request
to read the neutral path is open upstream. Tried on Claude Code 2.1.274 in this container: a
`.claude/skills` that is itself a symlink loads nothing; a real `.claude/skills/` directory
holding one symlink per skill loads all of them.

## Decision

We will keep the four procedures of the rule file — developing an ADR, planning work larger than
one session, reviewing a change, revising the design at the close of a feature spec — as Agent
Skills under `.agents/skills/`, one directory with a `SKILL.md` each, reached by Claude Code
through one symlink per skill under `.claude/skills/`. A skill carries the steps of one procedure,
cites the section of `AGENTS.md` or the ADR that requires it, and states no rule of its own; the
rule file and the templates name the skill and drop the steps.

**Out of scope:** skills a derived project adds for its own domain; whether a skill may run
unattended, which its ticket decides ([§4](../../AGENTS.md#4-working-style)); the checks that
verify a skill's front matter; and what happens to the pointers once Claude Code reads the
neutral path — they are deleted then, as the `CLAUDE.md` pointer will be.

## Alternatives considered

- **Procedures stay in prose** — the state this ADR ends: four copies, and a rule file paid for in
  full by every session.
- **One agent's native commands** — Claude Code commands, Cursor rules — put the process in one
  vendor's format, against ADR-0001's reason for one rule file.
- **A published skills collection or plugin** — brings a process in one piece, with its own
  artifacts and vocabulary; ADR-0004 declined the same trade for the same reason.
- **Procedures as plain files under `docs/`, loaded by pointer** — no progressive disclosure and no
  invocation by name; every session pays for all of them or for none.
- **A copy per agent directory** — `.claude/skills/` and `.agents/skills/` both tracked — is two
  sources that drift, the thing ADR-0001 exists to prevent; a symlink is one.
- **One symlink for the whole directory** — a single pointer instead of one per skill, and the
  obvious first try; Claude Code does not follow it (see Context).

## Sources / Prior art

- Agent Skills specification — <https://agentskills.io/specification>; client list at
  <https://agentskills.io/>.
- Skill locations — Claude Code: <https://code.claude.com/docs/en/skills>; Codex:
  <https://learn.chatgpt.com/docs/build-skills>; Gemini CLI: <https://geminicli.com/docs/cli/skills/>;
  Cursor: <https://cursor.com/docs/context/skills>.
- Matt Pocock's skills — <https://github.com/mattpocock/skills>: a process as a set of named,
  lazily loaded `SKILL.md` files rather than a framework that owns it; *Writing for agents* —
  <https://www.aihero.dev/skills-writing-for-agents>: what applies in one context out of ten goes
  behind a pointer. Addy Osmani, *Agent skills* — <https://addyosmani.com/blog/agent-skills/>:
  process over prose, each phase ending in evidence.
- The open request for Claude Code to read `.agents/skills/` —
  <https://github.com/anthropics/claude-code/issues/31005>; symlinked skill folders load but the
  agent's listing may not show them — <https://github.com/anthropics/claude-code/issues/14836>.

## Consequences

- Positive: one place for each how; the rule file shrinks to rules; a procedure costs context only
  when it runs; a human starts a review or an ADR by name instead of by hoping a paragraph is
  followed; the templates' comments become pointers.
- Negative / trade-offs: a fifth kind of tracked artifact, and one that can smuggle a rule past
  ADR-0001 — only review sees that. A skill is Markdown and is followed as reliably as Markdown
  is; what the template enforces, it enforces through hooks, settings, and CI as before, and this
  decision adds nothing to that. The pointers rest on observed behaviour of one Claude Code
  version, not on documented behaviour.
- Follow-ups: delete the pointers and their check once Claude Code reads the neutral path; a
  check on skill front matter once the reference validator is a dependency worth taking.

## Enforcement

**Not mechanically decidable:** that a skill carries a procedure and no rule, and that the rule
file names the skill instead of the steps, is review. What is checkable is already checked:
[`scripts/check-docs.sh`](../../scripts/check-docs.sh) resolves every link and every section
reference a skill makes, and fails when a skill under `.agents/skills/` has no pointer under
`.claude/skills/`, when a pointer there resolves to no skill, when the pointer is a copy rather
than a symlink, or when a skill lives only in the pointer directory: a skill without its pointer
is invisible to Claude Code and to no other agent, and nothing but this check notices.
