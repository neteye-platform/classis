---
name: propose-adr
description:
  Develop and submit an Architecture Decision Record. Use when a decision rests
  on something the code cannot say (an external constraint, a rejected
  alternative, a choice a reader would take for a mistake), or when the human
  asks for an ADR.
---

# Propose an ADR

The rule is [`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules); the mechanics of
the record are in [`docs/adr/README.md`](../../../docs/adr/README.md). This
skill is the order of work. It states no rule of its own.

## 1. Calibrate

Decide with rules 1 and 2 of [`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules)
whether this needs an ADR at all. If an agent can learn it by reading the code,
or a test decides it, there is no ADR. When no ADR is needed, say so and stop.

## 2. Interrogate the request

Before writing, ask the human, in rounds until the answers stop changing the
decision:

- Which goal of [`docs/SPECIFICATION.md`](../../../docs/SPECIFICATION.md) does
  this serve?
- What external constraint, not visible in the code, forces this?
- Which alternative has nobody mentioned yet, and why not that one?
- What happens if no decision is made?
- Would someone who lacks this conversation see the result and try to fix it?
- Under which condition must the decision be revisited?

Question the framing and your own draft.

## 3. Write the record

1. Copy [`docs/adr/template.md`](../../../docs/adr/template.md) to
   `NNNN-short-title.md` with the next free number, complete the header, and
   delete the instruction paragraph.
2. One decision per ADR: one "We will …" sentence.
3. Keep it to 10–20 lines. Context is the constraint the code cannot show.
   Alternatives name each rejected option with why not. Consequences name what
   is accepted and when to revisit.
4. Research first when the decision is costly to reverse, external sources
   included, and never pass off recalled facts as verified.
5. Add the row to the index in
   [`docs/adr/README.md`](../../../docs/adr/README.md).

## 4. Submit

Commit on a branch with status `proposed` and hand it to the human. Only a human
changes the status ([`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules), rule 4).
