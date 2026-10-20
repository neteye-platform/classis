---
name: Ticket
about: One tracer-bullet slice of a feature spec (ADR-0004)
title: "[Ticket] "
labels: ticket
---

<!-- A vertical slice: a narrow but complete path through every layer the change touches, demoable
     or verifiable on its own, sized to one fresh agent session. A child of its feature spec.
     Claim it by assigning yourself BEFORE any work, so parallel sessions skip it. Closed by the
     pull request that lands it ("Closes #<this>"). Decided in docs/adr/0004-feature-layer.md. -->

## Parent

<!-- The feature spec this slice belongs to: #<number>. -->

## What to build

<!-- The end-to-end behaviour this ticket makes work, from the user's perspective, not a
     layer-by-layer implementation list. -->

## Acceptance criteria

<!-- Each one decidable by a test or a demo, written as Given / When / Then so the test can copy
     it: the state before, the trigger, the observable result. -->

- [ ] Given …, when …, then …
- [ ] Given …, when …, then …

## Read first

<!-- What the session that works this ticket loads before anything else: the accepted ADRs whose
     "Applies to" it touches, the glossary terms and conventions in play, the golden path it
     copies from, the seam its tests go on. Everything else it explores as needed (AGENTS.md
     [§4](../../AGENTS.md#4-working-style)). -->

-

## Blocked by

<!-- The tickets that must close before this one can start, or "None (can start immediately)".
     Link them as sub-issues or a task list where the tracker allows it. -->

- None (can start immediately)

## Mode

<!-- "unattended" only under the conditions of AGENTS.md [§4](../../AGENTS.md#4-working-style),
     with the questions the plan-feature skill asks answered here: how soon would a wrong result
     be noticed, how cleanly can it be undone, what would prove it right, and when does the
     session stop, meaning the attempts, time, or criterion past which it leaves its state here
     and hands off? Otherwise "with the human", and why. -->

with the human
