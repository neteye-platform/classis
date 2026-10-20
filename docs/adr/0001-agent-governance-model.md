# ADR-0001: The document set: one specification, one ADR record, one `AGENTS.md`, one overview, one glossary, one conventions file

- **Status:** 🟢 accepted
- **Date:** 2026-09-05
- **Deciders:** NUC maintainer
- **Applies to:** every document that carries rules for humans or agents, the architecture overview, the glossary, and the conventions

## Context

Several coding agents may work in the same repository, and each looks for its instructions in a
different place. Without one written governance their behaviour drifts, rule sets are duplicated
and diverge, and structural decisions are made silently.

Three document roles follow from that: what the project is *for*, what has been *decided*, and what
the working *rules* are. Two more are easy to overlook. The ADR record is a log, and nothing in it
says what the system looks like **now**; reconstructing that from the log is a cost that grows with
it, and an agent starting without memory pays it every session. And the vocabulary is the part of
the specification that changes most often — a term is sharpened in almost every design
conversation — which sits badly in the document meant to change least.

A third shows up once the project is old: how it writes code and tests where no check decides it.
The rule file is the template's, the specification must not churn, and an ADR is for decisions —
so a convention became an ADR it did not deserve, or stayed in someone's head, and a reviewer held
the diff against nothing.

Two things limit the answer. Every further document is a candidate second source of truth that can
go stale. And the specification outranks every ADR while nothing protects it: editing a goal would
be the cheapest route around an accepted decision, and the ADRs resting on the old clause would
keep their force.

## Decision

We will govern this repository through **six documents with six distinct roles**, and no others
that carry a rule:

- [`docs/SPECIFICATION.md`](../SPECIFICATION.md) — the **constitution**: what the project is for.
  Changing it is a decision, not an edit: a human makes it, and names every accepted ADR whose
  basis it moves, so each is reconsidered in the same review and superseded where invalidated. An
  agent drafts specification text; it never lands the change and never judges alone that no ADR is
  affected. While nothing derives from a passage, there is nothing to name.
- [`docs/adr/`](.) — the **decision record**: every architecture-relevant decision, derived from
  the specification.
- [`AGENTS.md`](../../AGENTS.md) — one vendor-neutral **rule file**, the single source of working
  rules for humans and agents alike.
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — the **current state**: the system's parts, their
  responsibilities, and how they fit together. It holds no rule and no decision, cites the ADR
  behind each structural choice, and is updated in the same change as the structure. Where it and
  an accepted ADR disagree, the ADR is right — so it cannot become a second source of truth.
- [`docs/GLOSSARY.md`](../GLOSSARY.md) — the **vocabulary**: it defines terms and decides nothing,
  and is updated inline by whoever resolves a term — an agent included — in the same change as the
  conversation or code that settled it. An entry names one term in bold, says in one or two
  sentences what it *is*, and lists under _Avoid:_ the synonyms it displaces, where there are any.
  Only terms specific to the domain belong. The specification is written in this vocabulary and
  carries none of its own.
- `docs/CONVENTIONS.md` — the **conventions**: how this project writes code
  and tests where no check can decide it. An entry says in a sentence or two what is done and why,
  and is updated inline by whoever settles a convention — an agent included — in the same change
  as the review or code that settled it. Two things are never entries: a convention a check can
  decide, which becomes the check ([`AGENTS.md` §5](../../AGENTS.md#5-quality-bar--definition-of-done)),
  and one that constrains future choices, which is an ADR. The reviewer always has this document;
  the implementer reads it when it needs it.

Every other document — [`README.md`](../../README.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md),
[`SECURITY.md`](../../SECURITY.md), issue and pull request templates, per-agent pointers — points at
the rule file and holds no rule of its own. The exception is a document holding the mechanics of a
record the rule file delegates to it: [`docs/adr/README.md`](README.md) and its
[`template.md`](template.md), delegated by [`AGENTS.md` §3](../../AGENTS.md#3-adr-rules).

**The load-bearing clause is that there is exactly one rule file.** An ADR that supersedes any other
part of this record restates it. The ADR rules of [`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)
are the one block with no ADR behind it — accepted here, and reversible by an ADR on the ADR
process.

**Out of scope:** what `AGENTS.md` says and how other documents cite it; which agents a project uses
and which need a pointer file; how the ADR record is kept; the notation and depth of the overview;
the vocabulary of a repository with more than one bounded context; and which documents a project
created from this template drops.

## Alternatives considered

- **Per-tool instruction files** — guarantees drift between agents and multiplies maintenance.
- **Rules embedded in `README.md`** — mixes human onboarding with agent governance.
- **No overview; the ADR log is the current state** — holds while the log is short and degrades
  silently as it grows.
- **Vocabulary inside the specification** — the right authority for a goal is the wrong authority
  for a word: every renamed term became a human-only specification change, so the vocabulary in the
  tree lagged the vocabulary in use.
- **The full ADR lifecycle for the specification** — immutable clauses would demand a supersession
  for a wording fix; the specification is living intent, not a record.
- **A CI check requiring an ADR reference on every specification change** — cannot tell a typo fix
  from a rewritten goal, so it blocks ordinary edits or is satisfied by a token reference.
- **Conventions in `AGENTS.md`** — the file is the template's; project conventions in it collide
  with every template update and are pushed into every session whether the session writes code or
  not.
- **Conventions as ADRs** — the wrong lifecycle: a convention is refined every few weeks, an ADR is
  superseded; the record fills with decisions nobody would take for one.
- **Conventions only as checks** — the mechanical half. Naming, what a module may know, what a test
  asserts, are judgement calls no linter decides, and they are the half a reviewer needs written
  down most.

## Sources / Prior art

- The `AGENTS.md` convention — <https://agents.md>: one open file for coding agents, the format
  the rule file takes.
- Michael Nygard, *Documenting Architecture Decisions* —
  <https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions>: the ADR form —
  context, decision, status, consequences — and that a record is immutable and superseded.
- GitHub Spec Kit — <https://github.com/github/spec-kit>: a "constitution" written once per
  project that every feature derives from; the specification's role here.
- Matt Pocock, *domain-modeling* skill —
  <https://github.com/mattpocock/skills/blob/main/skills/engineering/domain-modeling/SKILL.md>: a
  glossary "and nothing else", devoid of implementation, next to `docs/adr/`; the model for the
  glossary. *A complete guide to AGENTS.md* on the same author's site —
  <https://www.aihero.dev/a-complete-guide-to-agents-md>: "Every token in your AGENTS.md file
  gets loaded on every single request", so "be ruthless about what goes here".
- Addy Osmani, *AGENTS.md* — <https://addyosmani.com/blog/agents-md/>: every line traceable to
  something that went wrong.
- Birgitta Böckeler, *Context engineering for coding agents* —
  <https://martinfowler.com/articles/exploring-gen-ai/context-engineering-coding-agents.html>:
  build rules files "up gradually, and not pump too much stuff in there right from the start",
  because "what you might have had to put into the context half a year ago might not even be
  necessary anymore"; why conventions live in a document with a retro rather than
  in the rule file.
- Jarosław Wąsowski, *Designing a spec that survives code generation* —
  <https://medium.com/@wasowski.jarek/sdd-designing-a-spec-that-survives-code-generation-spec-first-spec-driven-development-b61fdc234493>:
  specification types with different lifecycles, and that maintaining everything is the wrong
  answer; read in abstract only, the article is paywalled.

## Consequences

- Positive: one place to change a rule; consistent agent behaviour; explicit, reviewable decisions;
  one place that answers what the system looks like; the vocabulary is maintained by the session
  that changes it; the specification stops being a way around an immutable ADR; a convention has a
  place that is neither an ADR nor a head, and the reviewer holds the diff against something
  written.
- Negative / trade-offs: nothing mechanical keeps another document from stating a rule of its own,
  so the documents have to stay small enough for review to see it. A stale overview is worse than
  none because it is believed, and no check can tell the two apart. Naming the ADRs a
  specification change moves is a judgement no check makes. The conventions will attract entries a
  check should decide, and only the retro at the close of a feature spec
  ([`AGENTS.md` §5](../../AGENTS.md#5-quality-bar--definition-of-done)) moves them out.
- Follow-ups: a context map for repositories with more than one bounded context.

## Enforcement

[`scripts/check-docs.sh`](../../scripts/check-docs.sh) (job `docs` in
[`checks.yml`](../../.github/workflows/checks.yml)) verifies what is mechanically checkable: that the
ADR record and its index agree, that links between the documents resolve, and that section
references point at the section they name — which is why a document cites a rule as a link to
its section anchor and never restates it: a renumbering breaks the link, and the check catches
it, where a restated rule would drift unseen. One gate routes a specification change to a human
without judging it: [`.github/CODEOWNERS`](../../.github/CODEOWNERS) requires the owner's review
once the repository enables it ([**Repository settings**](../../README.md#repository-settings)).
That no other document holds a rule, that the
overview matches the system, that the glossary's terms are the ones in use, and that no convention
stands where a check could, is review only.
