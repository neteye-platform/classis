---
name: design-revision
description: Revisit the design of what a feature spec touched before the spec closes — survey the modules for entropy, check the architecture overview against the tree, read the ADRs that bind the modules and the criteria the spec served against the system, turn the mistakes made on the way into checks, and drop what nothing justified. Use when a feature spec's tickets have all merged, or when the human asks for a retro or an architecture review.
---

# Revise the design

The rule is [`AGENTS.md` §5](../../../AGENTS.md#5-quality-bar--definition-of-done); that a spec
closes only after this has run, and that it is due after a number of changes without a spec, is
decided in [ADR-0004](../../../docs/adr/0004-feature-layer.md). This skill runs in a fresh
session and states no rule of its own
([ADR-0005](../../../docs/adr/0005-procedures-as-skills.md)).

## 1. Scope

Take the feature spec and its merged tickets. The modules those pull requests touched are the
scope; the rest of the tree is context, not a target. One session, one spec.

Without a spec, when [`scripts/sensor-revision-due.sh`](../../../scripts/sensor-revision-due.sh)
says the revision is due, the scope is the directories it lists: the changes since the last
revision. One session, one count.

## 2. Survey the modules

For each module touched, look for what a pull request cannot see and a check does not:

- a concept spread over several files that belongs in one;
- logic written a second time;
- an interface that widened, one more parameter or one more flag, where a second function or a
  narrower one was due;
- a module with little behaviour behind its surface;
- a dependency that points the wrong way against the structural rule an ADR decided.

One candidate at a time, each with the ADR or convention it offends, or the name of the smell
where none does.

## 3. Check the overview against the tree

Read [`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md) with the tree open. A part it names
that no longer exists, a part that exists and it does not name, a flow that no longer runs as
described: each is a finding, because a stale overview is believed.

## 4. Read the record and the constitution against the system

Take the accepted ADRs whose *Applies to* names a touched module, through the index in
[`docs/adr/README.md`](../../../docs/adr/README.md). Decisions that have grown into one, each ADR
true on its own and the set said in one sentence, are a candidate for one superseding ADR that
consolidates them ([mechanics](../../../docs/adr/README.md#mechanics)).

Then the criteria of [`docs/SPECIFICATION.md`](../../../docs/SPECIFICATION.md) the feature spec
named as served. One whose text no longer says what the tests decide, one the work moved past:
each is a candidate for a specification change. The specification is the human's
([`AGENTS.md` §3](../../../AGENTS.md#3-adr-rules), rule 7): draft the change and the accepted
ADRs it would move; never land it.

## 5. Go through the mistakes

From the tickets' review findings and the pull requests' history, list what went wrong on the
way. For each: could a check have caught it? Then it becomes a check. Could a convention have
prevented it? Then it is an entry in [`docs/CONVENTIONS.md`](../../../docs/CONVENTIONS.md).

Then the reverse: a convention or a check that prevented nothing during this spec is dropped,
unless an ADR or a criterion cites it
([ADR-0003](../../../docs/adr/0003-decisions-verified-by-tests.md)).

## 6. File, do not fix

The conventions and the overview are corrected inline, as their documents ask. Everything else
is filed before the spec closes rather than implemented here: a ticket per candidate the survey
found, a ticket per check to write, a `proposed` ADR through `propose-adr` where a finding is a
decision, a consolidating one included, and a drafted specification change handed to the human
as an issue. Move the `Last design revision` line of
[`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md) to today's date. Then the spec closes.
