---
name: Feature spec
about: Plan a change larger than one agent session (ADR-0004)
title: "[Spec] "
labels: spec
---

<!-- The destination of a piece of work larger than one agent session, written from the user's
     side. It is disposable: it closes when its tickets have merged and the design revision has
     run, and whatever has to last moves into docs/SPECIFICATION.md, an ADR, or
     docs/ARCHITECTURE.md. No file paths or code; they go stale. How it is written is the
     plan-feature skill under .agents/skills/. Decided in docs/adr/0004-feature-layer.md. -->

## Problem

<!-- The problem the user faces, from the user's perspective. -->

## Solution

<!-- What the user can do once this is done, from the user's perspective. -->

## Existing behaviour

<!-- What the system does today that this changes, what must stay as it is, and which tests pin
     it. Where none does, the first ticket writes them (AGENTS.md
     [§5](../../AGENTS.md#5-quality-bar--definition-of-done)). How existing data and callers get
     from the old behaviour to the new. "Greenfield, nothing exists yet" is an answer. -->

## Goals served

<!-- The criteria of docs/SPECIFICATION.md this work meets or advances, by identifier: G-n, Q-n.
     A change that serves none of them is a change the specification does not ask for; say so. -->

- G-

## User stories

<!-- Numbered and extensive: "As an <actor>, I want <capability>, so that <benefit>". -->

1. As a …, I want …, so that …

## Implementation decisions

<!-- Modules touched and the interfaces that change, schema and contract changes, clarifications
     from the human, in the project vocabulary, without file paths or code snippets. Any decision
     that is architecture-relevant is an ADR, not a bullet here
     (AGENTS.md [§3](../../AGENTS.md#3-adr-rules)). -->

-

## Testing decisions

<!-- The seams the change is tested at: existing seams preferred, the highest one possible, as
     few as possible. The prior art in the codebase the new tests copy. -->

-

## Out of scope

<!-- What this work deliberately leaves out, so a ticket cannot drift into it. -->

-

## ADR impact

<!-- Which accepted ADRs bind this work (by number), and whether it needs a new `proposed` ADR
     before implementation starts (AGENTS.md [§3](../../AGENTS.md#3-adr-rules)). "None" is an
     answer; write why. -->
