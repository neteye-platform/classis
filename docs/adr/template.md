# ADR-NNNN: \<short title of the decision>

- **Status:** 🟡 proposed
- **Date:** YYYY-MM-DD
- **Deciders:** <names / roles of the humans who decide>
- **Applies to:** <the paths, components, or kinds of change this decision
  constrains>
- **Supersedes:** [ADR-NNNN](NNNN-short-title.md)

_Complete the header and delete what does not apply. `Status` ships as
`🟡 proposed`; a human flips it to `🟢 accepted`, `🔴 rejected`, or
`⚪ superseded by ADR-NNNN`, keeping exactly one emoji with the word that
belongs to it. `Date` is the date of the last status change: the date the ADR
was proposed until the first flip. Revising a `proposed` ADR does not move it
and needs no note; git carries the history. `Deciders` names the humans who
accept or reject; an agent is never a decider. `Applies to` names what the
decision constrains, concrete paths where it has them, otherwise the kind of
change (every commit, every public interface), in one line without a pipe
character: the index mirrors it verbatim, and that is how a reader finds the
ADRs that bind a change ([mechanics](README.md#mechanics)). `Supersedes` only
when this ADR replaces one existing ADR or several whose decisions have grown
into one, each linked; their status lines flip in the same pull request
([mechanics](README.md#mechanics)). An entry followed by `clause N` replaces
only those clauses; the old ADR then stays active and its status line gains the
suffix `· clause N superseded by ADR-NNNN` instead of the flip. For a decision
recorded only because a reader would take it for a mistake, cheap to reverse and
constraining nothing ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 2), a
sentence each under Context and Decision and `None — cheap to reverse` under
Alternatives, Sources, and Consequences is the whole record; Enforcement stays.
Then delete this paragraph._

## Context

What is the issue, and which forces are at play: requirements from
[`docs/SPECIFICATION.md`](../SPECIFICATION.md), constraints from other ADRs,
technical forces?

Interrogate the request with the human before writing this section
([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 3); the `propose-adr` skill
under [`.agents/skills/`](../../.agents/skills/) lists the questions.

## Decision

What we decided, in one clear, active sentence ("We will …"). A second "We will
…" sentence is a sign of two ADRs
([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)).

**Out of scope:** what this decision deliberately leaves open, so a later ADR
can take it up without contradicting this one. Write "nothing beyond the
sentence above" when the decision is already narrow.

## Alternatives considered

- **\<Alternative A>** — why it was not chosen.
- **\<Alternative B>** — why it was not chosen.

## Sources / Prior art

State of the art and established solutions consulted before deciding: links,
docs, papers, comparable systems.
[`AGENTS.md` §4](../../AGENTS.md#4-working-style) requires citing what informed
the decision. Write "None — trivial/reversible" only when that is genuinely
true.

## Consequences

- Positive: what becomes easier or possible.
- Negative / trade-offs: what becomes harder, what we accept.
- Follow-ups: the questions this decision raises, described by topic, never by
  an ADR number that does not exist yet.

## Enforcement

What keeps this decision true and where it lives: the check, test, CI job, or
review step that fails when it is violated. Name the test that cites this ADR,
or write a paragraph starting `**Not mechanically decidable:**` with the reason
no test can decide it. Accepting an ADR that has neither fails CI
([ADR-0003](0003-decisions-verified-by-tests.md)).
