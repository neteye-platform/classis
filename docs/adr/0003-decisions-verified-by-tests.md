# ADR-0003: Every accepted decision and every success criterion is verified by a test that cites it

- **Status:** 🟢 accepted
- **Date:** 2026-09-16
- **Deciders:** NUC maintainer
- **Applies to:** every accepted ADR, the Goals and Quality Goals of `docs/SPECIFICATION.md`, and the tests that verify them

## Context

This template drives development from a specification: authority runs **specification → accepted
ADRs → task** ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)). Neither end of that chain is
connected to anything executable. The Definition of Done requires tests for new behaviour
([`AGENTS.md` §5](../../AGENTS.md#5-quality-bar--definition-of-done)), but nothing says which
decision or goal a test protects, and nothing notices a decision that no test protects. The
cheapest *Enforcement* entry an ADR can carry is "review only", and it is the one that protects
nothing.

Two forces limit the answer. Some decisions cannot be decided by a program — that only a human
flips an ADR's status, that an effort was planned on a tracker outside the tree — and demanding
tests for them produces tests that assert a constant. And this template ships no language
toolchain, so the rule can prescribe only something every language's tests can carry.

## Decision

We will fail CI on any accepted ADR that no test cites with a `Verifies: <id>` marker, and report
every criterion under **Goals / Success Criteria** or **Quality Goals** in the specification that
no test cites.

- **Identifiers.** Every list item in those two sections starts with a bold `G-n` (Goals) or `Q-n`
  (Quality Goals), as in `- **G-1** — …`; an item without one fails. Identifiers are never
  renumbered or reused.
- **Marker.** `Verifies:` followed by one or more identifiers (`ADR-0002`, `G-1`), in any tracked
  file that is not Markdown. It is plain text so that every language can carry it.
- **Exception.** An ADR whose decision no test can decide — because only a human can, or because
  it is about how the project works rather than what the system does — says so in its
  *Enforcement* section, in a paragraph starting `**Not mechanically decidable:**` with the reason.
  Criteria have no exception: a criterion no test can decide is not an acceptance criterion, and is
  rewritten until one can.
- **Criteria.** A criterion no test cites is pending work, and the check lists it; it does not
  fail. Nothing in the specification marks the state, so meeting a goal touches the tests, not the
  constitution.
- **Invalid citation.** A marker citing an identifier that does not exist, or an ADR that is
  superseded or rejected, fails.

`proposed` ADRs are out of the check's scope: their implementation and tests land while they are
still proposed, and the acceptance lands with them ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)).

**Out of scope:** whether a citing test is adequate, which stays with review; whether the tests
pass, which is the project's own build-test job; and which test framework, layout, or kind of test a
project uses.

## Alternatives considered

- **Keep review-only enforcement as a legitimate default.** The state this ADR ends. A coverage
  report that fails nothing is the same thing in a new format.
- **Tests without any exception.** Does not remove the undecidable decisions, it hides them behind
  tests that assert a constant — a check that counts the headings of an issue template protects
  the template, not the decision.
- **A pending mark on each criterion in the specification.** Lets the check fail on an unmarked
  criterion, at the price that every pull request meeting a goal becomes a specification change,
  which a human alone may land. The report says the same without touching the document.
- **Count a marker only in test files.** Stronger, but "test file" has no language-neutral
  definition. A project that has one narrows the check through its own ADR.
- **A language-specific mechanism** (annotations, tags, ArchUnit-style rule classes). Stronger where
  it exists, but a template without a toolchain cannot prescribe one; a project can add one on top
  of the marker.

## Sources / Prior art

- Birgitta Böckeler, *Harness engineering* —
  <https://martinfowler.com/articles/harness-engineering.html>: a harness is guides that feed
  forward and sensors that feed back, and the behaviour harness is the least mature; this ADR
  wires a decision to a sensor. *Sensors for coding agents* —
  <https://martinfowler.com/articles/sensors-for-coding-agents.html>: coverage says a line ran,
  not that its effect was verified — why a marker proves a claim, not adequacy.
- Addy Osmani, *Agentic code review* — <https://addyosmani.com/blog/agentic-code-review/>: a
  green check over edited tests means nothing until the edits are confirmed; the reason every
  changed test needs a reason in review.

## Consequences

- Positive: "which test protects this decision?" and "is this goal met?" become lookups; a decision
  nobody verifies fails CI when it is accepted, not when it is found broken later; *Enforcement*
  stops being free text that can say "none".
- Negative / trade-offs: accepting an ADR requires its tests in the same pull request. A marker
  proves a claim, not adequacy — a test that cites and asserts nothing passes, and so does a marker
  in a file that is no test. A criterion that loses its test is visible only in the check's report
  and in the diff that deleted the test. Quality goals must be phrased so a test can decide them.

## Enforcement

`scripts/check-traceability.sh`, run by `scripts/check-all.sh` and as its own job in
[`checks.yml`](../../.github/workflows/checks.yml), fails on every violation listed in the decision
above and lists the criteria without a test. It ships with a self-test that cites this ADR.
