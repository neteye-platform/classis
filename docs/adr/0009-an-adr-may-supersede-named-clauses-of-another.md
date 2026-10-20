# ADR-0009: An ADR may supersede named clauses of another, which stays accepted for the rest

- **Status:** 🟢 accepted
- **Date:** 2026-10-12
- **Deciders:** Markus Brigl
- **Applies to:** the supersession mechanics of `docs/adr/README.md` and `docs/adr/template.md`, the `Supersedes` field and `Status` line of every ADR, and the supersession check of `scripts/check-docs.sh`

## Context

[`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 5, makes an accepted ADR immutable and lets it
change only by supersession. The mechanics in [`README.md`](README.md#mechanics) know one form of
supersession: the old ADR's `Status` line flips to `⚪ superseded by ADR-NNNN`, the whole record
leaves the binding index, and the successor has to carry everything of it that still holds.

That form fits a decision that has been replaced. It does not fit a decision whose detail has
moved while the rest stands. The trigger is a rename: the build-time environment variables that
[ADR-0012](0012-versions-resolved-in-the-internal-crate.md) (clauses 1 and 4) and
[ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) (clause 2)
name are to change their names. A whole supersession would make the successor restate about 1,400
lines of two accepted ADRs to change four identifiers, and the review of that successor would be a
review of both decisions again — the opposite of proportionality
([`AGENTS.md` §1](../../AGENTS.md#1-principles)). The record has numbered clauses for exactly this
reason: ADR-0019 already cites its own clauses by number, and so does the code (`ADR-0019 clause 8`
in `crates/fleet-agent/src/service/manager.rs`).

No ADR has been superseded yet, so nothing depends on the current form being the only one.

## Decision

We will let an ADR supersede named, numbered clauses of an accepted ADR, which stays `🟢 accepted`
for every clause it does not name and records the replaced ones on its `Status` line.

1. **The successor names the clauses.** Its `Supersedes` field reads
   `[ADR-NNNN](NNNN-title.md) clause 2` or `… clauses 1 and 4`, one entry per ADR. An entry without
   clauses is a whole supersession, as before. Only numbered clauses of the Decision section can be
   named; a decision without numbered clauses is superseded whole.
2. **The old ADR's `Status` line records it, and only there.** It keeps its emoji and word and gains
   `· clause 2 superseded by [ADR-NNNN](NNNN-title.md)`, one such suffix per successor. This is the
   `Status` line edit [`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 5, already permits; the
   body stays untouched, and the `Date` does not move because the status did not change. It lands in
   the pull request that proposes the successor, as a whole supersession's flip does.
3. **The old ADR stays in the binding index.** Its row and status are unchanged; a reader who opens
   it sees on the first lines which clauses no longer hold and where their replacement is.
4. **The successor restates the clauses it replaces, not the rest.** Its Decision says what each
   named clause says now; everything else of the old ADR binds unchanged.
5. **A clause superseded twice names its latest successor.** The older successor's own status line
   then carries the partial or whole supersession of that clause; the chain is read like any other.

**Out of scope:** changing `AGENTS.md` — rule 5 already allows a change by supersession and a
`Status` line edit, so nothing there moves. Partial supersession of the specification, which is
not an ADR and changes by rule 7 of [`AGENTS.md` §3](../../AGENTS.md#3-adr-rules).

## Alternatives considered

- **Whole supersession, the successor restating everything** — the rule as it stands. Correct, but
  for a detail it costs a re-review of the entire decision, invites drift between the restatement
  and the original, and empties the index of an ADR whose decision still holds.
- **An amendment note in the old ADR's body** — the cheapest, and exactly the edit rule 5 forbids;
  an accepted body that moves is no longer a record.
- **A new ADR that contradicts the old one without touching it** — two accepted ADRs that disagree,
  with nothing in the older one telling a reader. Rule 5 calls this working around an ADR.
- **A separate errata file** — a seventh place a session would have to read beside the document set
  of [ADR-0001](0001-agent-governance-model.md), for what one `Status` line can carry.
- **Leave the detail as it is** — what happens without a decision: every small correction to an
  accepted ADR is either a disproportionate rewrite or not made, and the code and the record drift.

## Sources / Prior art

- [`docs/adr/README.md`](README.md#mechanics) and `scripts/check-docs.sh` checks 7 and 8 — the
  current mechanics; check 8 already reads `superseded by ADR-NNNN` anywhere on the `Status` line,
  so a single partial suffix passes it unchanged.
- Michael Nygard, *Documenting Architecture Decisions* (2011) — the immutable record superseded
  rather than edited, which this keeps.
- Legislative amendment practice: an amending act replaces named sections and leaves the rest of
  the act in force — the model for naming clauses rather than restating the whole.

## Consequences

- Positive: a detail of an accepted ADR changes by a short ADR reviewed for that detail alone; the
  old decision stays where sessions read it.
- Positive: the record stays honest — a reader of the old ADR is told on its `Status` line which
  clauses no longer hold.
- Negative / trade-offs: a reader of a partially superseded ADR has to open the successor for the
  named clauses, so an ADR read alone is no longer the whole truth; the `Status` line is what keeps
  that visible. Several partial supersessions of one ADR are a sign it should be superseded whole.
- Follow-ups: the mechanics in `docs/adr/README.md` and the template's instruction paragraph
  describe the clause form; check 8 of `scripts/check-docs.sh` handles several suffixes on one
  `Status` line and verifies that a clause-naming `Supersedes` entry is mirrored by a suffix that
  keeps the old ADR active, and the reverse.

## Enforcement

`scripts/check-docs.sh` check 8 (supersession agreement), extended as above, fails when a
`Supersedes` entry names clauses but the old ADR's `Status` line carries no matching
`superseded by` suffix, when a suffix names an ADR whose `Supersedes` field does not name the old
one, or when a partially superseded ADR is `⚪`. Its self-test,
[`scripts/test-check-docs.sh`](../../scripts/test-check-docs.sh), carries a case for each, with a `Verifies: ADR-0009` marker.

**Not mechanically decidable:** that a successor restates exactly the clauses it names and nothing
else of the old decision is review.
