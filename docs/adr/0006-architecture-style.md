# ADR-0006: Application code is structured as ports and adapters, with every dependency pointing at the core

- **Status:** 🟢 accepted
- **Date:** 2026-09-19
- **Deciders:** Markus Brigl
- **Applies to:** every module of the system's code, the golden path, and the structural test that decides the dependency direction

## Context

The specification says what is built and the rule file how work is governed; nothing says how
the code is shaped. Every project built on the template re-decides how its domain relates to its
infrastructure, or drifts without deciding. Two forces make the choice worth taking once, here:

- **Agents work in seams.** A boundary that is explicit lets a session change one side of it
  and produce a diff a reviewer can hold in one reading; without one, changes reach across the
  code base and the review sees everything or nothing.
- **The Definition of Done demands testable behaviour**
  ([`AGENTS.md` §5](../../AGENTS.md#5-quality-bar--definition-of-done)): the suite is the contract
  the implementation is held to, so the domain has to be verifiable without the technology it
  runs on, and a decision about the shape has to be one a test can decide
  ([ADR-0003](0003-decisions-verified-by-tests.md)) — the shape is what entropy erodes first.

Two things limit the answer. The template ships no toolchain, so it can decide the shape but not
ship the test that keeps it. And a shape that is wrong for a project — a small CLI, a library, a
pipeline — must be cheap to decline: an inherited ADR binds a project only once its maintainer
accepts it ([`docs/adr/README.md`](README.md)).

## Decision

We will structure application code as **ports and adapters**: a technology-agnostic **core** that
holds the domain, **ports** owned by the core that say what it needs and offers, and **adapters**
at the edges that bind those ports to a technology — user interface, persistence, network,
external services — with every dependency pointing **inward**: adapters depend on the core, and
the core depends on no adapter and on no technology.

**Out of scope:** where ports and adapters live in a given language and how they are named, and
what counts as a technology there — a standard library or a pure utility library usually does
not — which is the golden path's to show and [`docs/CONVENTIONS.md`](../CONVENTIONS.md)'s to
say; whether a project has one core or several bounded contexts; and the internal structure of
the core.

## Alternatives considered

- **No prescribed shape** — the state this ADR ends: re-decided per project, or not decided and
  drifting, with domain logic bound to the first framework that touched it.
- **Layered (n-tier)** — familiar, but its top-down direction lets the persistence layer shape
  the domain, and a test of the domain needs the database.
- **Clean or onion architecture** — the same dependency rule with more prescribed rings; the
  vocabulary is heavier for the same testable seam.
- **Decide it per project in the harness or toolchain ADR** — every project writes the same
  decision with the same alternatives; one inherited ADR that a project accepts or supersedes
  costs less and records the reasoning once.

## Sources / Prior art

- Alistair Cockburn, *Hexagonal Architecture (Ports and Adapters)* —
  <https://alistair.cockburn.us/hexagonal-architecture/>: the core, the ports it owns, and the
  adapters that plug into them.
- Robert C. Martin, *The Clean Architecture* —
  <https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html>: the dependency
  rule — source code dependencies point inward only — which is the one clause of SOLID's
  dependency inversion a test can decide.

## Consequences

- Positive: the domain is tested without its technology; a technology is an adapter decision,
  swapped behind a port instead of rewritten through the code base; a ticket names the port it
  works behind, so parallel sessions collide less; the structural test the project writes has a
  rule to decide.
- Negative / trade-offs: indirection and interface ceremony that a thin CRUD application or a
  script does not earn — such a project supersedes this ADR rather than ignoring it; the split
  erodes unless its test exists.
- Follow-ups: a context map once a project has more than one core.

## Enforcement

The structural test a derived project writes when it lays down its golden path — one that fails
when a module of the core depends on an adapter or on a technology — cites this ADR with a
`Verifies: ADR-0006` marker, and the flip to accepted lands with it
([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 4). The template itself has no code and ships
no such test, which is why this ADR stays proposed until then. What the test cannot decide — one
responsibility per module, a port no wider than its callers need, a core open to a new adapter
without change to itself, a core that knows an adapter's vocabulary — is review
([`AGENTS.md` §5](../../AGENTS.md#5-quality-bar--definition-of-done)) and the design revision.
