---
name: review
description: Review a change in a fresh context before its pull request opens. Use when a change is ready to hand off, when the human asks for a review, or when you are the second session or subagent given a diff to judge. The session that wrote the change never runs this on its own work.
---

# Review a change

The rule is [`AGENTS.md` §5](../../../AGENTS.md#5-quality-bar--definition-of-done). This skill is
what the reviewer is given and the order in which it reports; it states no rule of its own
([ADR-0005](../../../docs/adr/0005-procedures-as-skills.md)).

## 1. Inputs — and nothing else

The reviewer runs in a context that did not write the change and is handed only:

- the diff;
- the task: the ticket or the request, with its acceptance criteria;
- [`AGENTS.md` §1](../../../AGENTS.md#1-principles) and
  [§5](../../../AGENTS.md#5-quality-bar--definition-of-done);
- the *Doubts* section of the pull request draft: what the implementer disagreed with and what
  it could not confirm;
- [`docs/CONVENTIONS.md`](../../../docs/CONVENTIONS.md);
- the golden path named in [`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md);
- the accepted ADRs whose *Applies to* the diff touches, found through the index in
  [`docs/adr/README.md`](../../../docs/adr/README.md);
- the output of the sensors the toolchain ADR names, and of
  [`scripts/check-all.sh`](../../../scripts/check-all.sh), whose tests-kept sensor lists the
  test files deleted and the skip markers added since the base.

If the implementer's reasoning, plan, or conversation is offered, decline it. The review holds
the diff against the standards, not against the story of how it came to be.

## 2. Report on two axes, kept apart

**Does it do what was asked?** Each acceptance criterion against the diff and its tests: met,
not met, or met by a test that does not decide it. Scope the task did not ask for is a finding.

**Does it meet the bar?** Simplicity first ([`AGENTS.md` §1](../../../AGENTS.md#1-principles)):
is there a smaller change that meets the same criteria; what did the diff add that nothing asked
for, such as an abstraction, a dependency, a parameter, a flag, a fallback, or a comment restating
the code; what could be deleted. Then each bullet of
[`AGENTS.md` §5](../../../AGENTS.md#5-quality-bar--definition-of-done) that applies: builds and
passes; new behaviour has tests and a bug fix its regression test; the tests go through
interfaces the implementation can change behind and take their expected values from the
criterion, not from the code under test; every accepted ADR and criterion the change touches is
cited by a test; nothing weakened the suite; the diff is releasable; `ARCHITECTURE.md` moved
with the structure. Then the conventions, the ADRs, and the sensor output; a sensor finding the
implementer suppressed is a finding here. Last, the *Doubts*: each disagreement checked against
its evidence, each unconfirmed point confirmed or left open by name. A "none" is checked like any
other claim.

## 3. Tests that changed

List every existing test the diff changes or removes. Each needs a reason the behaviour changed,
verified against the diff, not against the pull request's claim. One without a reason weakened
the suite and is the first finding.

## 4. Hand back

Findings, concrete and ranked, with file and line, and what the reviewer itself could not
verify. No fixes applied. The implementer fixes them before the pull request opens and records in
the pull request's *Review* section who reviewed, the findings on both axes, and what was fixed.
