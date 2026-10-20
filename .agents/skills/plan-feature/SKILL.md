---
name: plan-feature
description: Plan work larger than one agent session on the issue tracker — a feature spec cut into tracer-bullet tickets. Use when a request will not fit one session, or when the human asks for a spec, tickets, or a plan.
---

# Plan a feature

The rule is [`AGENTS.md` §4](../../../AGENTS.md#4-working-style); the artifacts and their
lifecycle are decided in [ADR-0004](../../../docs/adr/0004-feature-layer.md). The shapes are the
issue templates under [`.github/ISSUE_TEMPLATE/`](../../../.github/ISSUE_TEMPLATE/). This skill
is the order of work and states no rule of its own
([ADR-0005](../../../docs/adr/0005-procedures-as-skills.md)).

## 1. Decide the artifact

- Fits one session: plan in the conversation, no issue.
- Larger: a **feature spec** with **tickets** (step 2).

The threshold is a judgement under proportionality ([§1](../../../AGENTS.md#1-principles)). Say
which you chose and why. An effort whose questions cannot all be asked yet is not ready for a
spec: chart it with the human in the conversation until the questions run out.

## 2. Write the spec and cut the tickets

1. Interrogate the request with the human before drafting: which goal it serves by identifier,
   what was not said, which alternative nobody named, what happens without it. If the questions
   do not run out, the scope is too big: split first.
2. Open a *Feature spec* issue synthesised from that conversation: problem and solution from the
   user's side; the existing behaviour it changes, what must stay, and which tests pin it; goals
   served (`G-n`, `Q-n`); user stories; implementation and testing decisions in the project
   vocabulary, without file paths or code; out of scope; ADR impact. A decision that is
   architecture-relevant is an ADR, not a bullet: use `propose-adr`.
3. Cut *Ticket* issues as vertical slices. Each is an end-to-end behaviour that is demoable or
   verifiable on its own, sized to one fresh session, with Given/When/Then acceptance criteria,
   the tickets that block it, and *Read first*: the accepted ADRs whose *Applies to* it touches,
   the glossary terms and conventions in play, the golden path it copies, the seam its tests go
   on. The first slice through new ground is the tracer bullet.
4. Set each ticket's *Mode*: "unattended" only under the conditions of
   [`AGENTS.md` §4](../../../AGENTS.md#4-working-style), each answered on the ticket; the stop
   is concrete, the attempts, time, or criterion past which the session hands off. Otherwise
   "with the human", and why.

## 3. Work and close

A session claims a ticket from the frontier, the open tickets whose blockers are all closed, by
assigning itself before any work. Its pull request names the ticket it closes. The spec closes
only after `design-revision` has run over what its tickets touched. Whatever in the spec has to
last moves into the specification, an ADR, the architecture overview, or the glossary before it
does.
