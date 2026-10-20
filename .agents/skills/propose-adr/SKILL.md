---
name: propose-adr
description: Develop and submit an Architecture Decision Record. Use when a change is architecture-relevant, when a decision is costly to reverse or constrains future choices, when a reader without this conversation would take a choice for a mistake, or when the human asks for an ADR.
---

# Propose an ADR

The rule is [`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules); the mechanics of the record are in
[`docs/adr/README.md`](../../../docs/adr/README.md). This skill is the order of work. It states no
rule of its own ([ADR-0005](../../../docs/adr/0005-procedures-as-skills.md)).

## 1. Calibrate

Decide with rule 2 of [`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules) whether this needs an ADR
at all. No ADR for implementing within an accepted ADR, a bug fix, an interface-preserving
refactoring, tests, docs, formatting, and dev-only tooling. The rule's third case, what a reader
without this conversation would take for a mistake, is the deliberate deviation from the obvious
path; record it, or the next session "fixes" it. When no ADR is needed, say so and stop here.
When genuinely unsure, prefer a short `proposed` ADR.

## 2. Interrogate the request

Before writing a line of the record, ask the human, in rounds until the answers stop changing the
decision, at least:

- Which goal or quality goal of [`docs/SPECIFICATION.md`](../../../docs/SPECIFICATION.md) does
  this serve, by identifier (`G-n`, `Q-n`)?
- What did the human not say that the decision depends on?
- Which alternative has nobody mentioned yet?
- What happens if no decision is made?
- Does this bind future choices, or is it a *how* that needs no ADR?
- Would someone who lacks this conversation see the result and try to fix it?

Question the framing and your own draft. A draft written ahead of the answers is the first
alternative to reject.

## 3. Write the record

1. Copy [`docs/adr/template.md`](../../../docs/adr/template.md) to `NNNN-short-title.md` with the
   next free number. Complete the header and delete the instruction paragraph.
2. One decision per ADR: one "We will …" sentence. A second one is a second ADR, unless the
   decision is the interplay of an integration ([§3](../../../AGENTS.md#3-adr-rules), rule 1).
3. **Alternatives:** every one the interrogation surfaced, each with why not.
4. **Sources:** what was consulted. A decision costly to reverse is researched first, external
   sources included, and nothing recalled is passed off as verified
   ([§4](../../../AGENTS.md#4-working-style)).
5. **Consequences:** weighed against the specification's quality goals. Follow-ups by topic,
   never by a number that does not exist yet.
6. **Enforcement:** the test that will cite this ADR with a `Verifies:` marker, or a paragraph
   starting `**Not mechanically decidable:**` with the reason
   ([ADR-0003](../../../docs/adr/0003-decisions-verified-by-tests.md)).
7. Add the index row in [`docs/adr/README.md`](../../../docs/adr/README.md), status and *Applies
   to* mirrored verbatim. For a supersession, flip the old ADR's status line in the same change.
8. Run [`scripts/check-docs.sh`](../../../scripts/check-docs.sh).

## 4. Submit

Commit on a branch and hand the ADR to the human as its **own pull request**, status `proposed`,
with no implementation in it. What follows is rule 4 of
[`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules): review findings return as revisions in ADR-only
pull requests, implementation starts once the human has reviewed, and the `Status` line is never
yours to change.
