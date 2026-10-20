# ADR-0004: Work larger than one session is planned on the issue tracker: a feature spec cut into tracer-bullet tickets

- **Status:** 🟢 accepted
- **Date:** 2026-09-17
- **Deciders:** NUC maintainer
- **Applies to:** every change larger than one agent session, the issue templates, the pull request template, and the `Last design revision` line of `docs/ARCHITECTURE.md`

## Context

Authority runs specification → accepted ADRs → task ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)),
and nothing in that chain says what *this month's work* is. A change that fits one session is
planned in the conversation. A change that does not has no place to keep its state: each session
starts without memory, re-derives the plan, and drifts. The rule to cut work into vertical slices
([`AGENTS.md` §4](../../AGENTS.md#4-working-style)) has no artifact that carries a slice, and the
condition for running a task unattended has nothing to be written in.

Two more forces come with age. Most work in a system that already exists is change, not addition,
and a plan written from the user's side alone says nothing about what the system does today, what
must stay as it is, and how what exists gets from the old behaviour to the new — the part a session
without memory gets wrong first. And every feature adds structure faster than anyone revisits it:
a concept lands in one more file, a piece of logic is written a second time, an interface widens
by one parameter — none of it wrong in the pull request that brought it, all of it entropy no
check sees. A record protects decisions (ADR-0003); nothing in the process protects the shape.
The moment to look is while the work that added the structure is still known, and a project that
is not writing features never reaches it: one in maintenance, with tickets and fixes only,
revisits its design when somebody remembers to ask.

The artifact cannot live in the specification, which must not churn (ADR-0001); cannot be a
seventh rule-bearing document; and must be disposable by design, because a plan that outlives its
usefulness is noise for every later session — which rules out a tracked document nobody deletes.

## Decision

We will plan every change larger than one agent session on the repository's issue tracker — as a
**feature spec** broken into **tracer-bullet tickets** that each declare which tickets block them
— and treat both as **disposable**: they close when their work merges, and whatever in them has to
last moves into the specification, an ADR, the architecture overview, or the glossary.

A **feature spec** states the problem and the solution from the user's side, the existing
behaviour it changes and what must stay as it is, the goals of the specification it serves by
identifier (`G-n`, `Q-n`), the user stories, the implementation decisions and the seams at which
the change is tested — without file paths or code, which go stale — what is out of scope, and
whether it needs an ADR. A **ticket** states the end-to-end behaviour it delivers, its acceptance
criteria, the tickets that block it, what the session that works it reads first, and whether it is
worked with the human or may run unattended — and, if so, when the session stops
([`AGENTS.md` §4](../../AGENTS.md#4-working-style)). A ticket is sized to one fresh session and is
demoable or verifiable on its own. The frontier — open
tickets whose blockers are all closed — is what an agent picks from; it claims a ticket by
assigning itself before any work, so that parallel sessions skip it. A pull request names the
ticket it closes. A feature spec closes when its tickets have merged and a fresh session has
revisited the design of what they touched — the modules, the accepted ADRs that bind them, and
the specification criteria they serve — and filed what it found
([`AGENTS.md` §5](../../AGENTS.md#5-quality-bar--definition-of-done)).

The revision also comes due **without a spec**, on a count of the work done rather than on a
date. [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) carries on one line the date of the last
revision and the number of changes after which the next is due — `**Last design revision:**
<YYYY-MM-DD or none yet>, due after <N> changes.` — and a sensor counts the changes since that
date. A **change** is a commit that touches anything outside `docs/`, merges excluded. The
number ships as 20 and is the project's to set, on the line rather than in the sensor. The count
is reported, never enforced: once the number is reached the revision runs over the modules those
changes touched, and it moves the date. The line sits in the overview because the revision
corrects that document anyway, and because the overview is the one document that says how the
system stands (ADR-0001).

**Out of scope:** how work smaller than one session is planned; an artifact for an effort too
foggy to be written as a spec; triage states for issues that arrive from outside; whether a due
revision blocks a merge, which it does not; which tracker a project uses — the templates shipped
here are for GitHub Issues, and a project on another tracker supersedes this ADR with the same
shape on its own tracker.

## Alternatives considered

- **Plan in the conversation.** The state this ADR ends: the plan lives in a context window that
  is gone by the next session.
- **A tracked document per feature under `docs/`.** Read by every later session whether still
  true or not; nobody deletes a document, an issue closes itself.
- **Issues only, no spec.** Slices without the destination they serve: nothing says when the
  feature is done or which goal it meets.
- **A decision map while the way is unclear.** A map issue naming the destination, with one child
  decision ticket per question that can be stated now — typed research, prototype, conversation,
  or task — resolved one per session, the spec cut once no question remains. The right shape for
  an effort whose questions cannot all be asked at once, and not in the template because no
  project has had one yet: an artifact nobody has needed is ceremony every reader pays for
  ([`AGENTS.md` §1](../../AGENTS.md#1-principles)). It returns when one does.
- **Plan the whole effort upfront as tickets.** Slices what the first answer will change.
- **A process-owning framework or skills plugin.** Brings artifacts and pipeline in one piece, at
  the price of one vendor's format; the template stays vendor-neutral (ADR-0001).
- **A change spec of its own for work on what exists.** One more artifact for the common case;
  the same two questions — what changes, what stays — fit as a section of the feature spec, and
  "greenfield" is an answer to them.
- **A standing "improve the architecture" chore on a calendar.** Nothing ties it to the work that
  caused the entropy, so it is skipped when busy and pointless when idle; a spec that closes and
  a count of changes are both moments the touched modules are still known.
- **A failing check once the revision is due.** Blocks every pull request until a session that
  ships no behaviour has run; this layer makes entropy visible, not impossible.
- **The number of changes inside the sensor.** The sensor belongs to the template and travels
  with it; how much drift a project tolerates belongs in the project's own document.
- **Counting lines changed rather than commits.** Nearer to entropy and far noisier: a formatter
  run is thousands of lines and no structure at all.

## Sources / Prior art

The shape of this layer follows Matt Pocock's skills — <https://github.com/mattpocock/skills> —
closely, and a reader who knows them should recognise it:

- *to-spec* — <https://www.aihero.dev/skills-to-spec>: the spec as a tracker issue, disposable
  once the work ships.
- *to-tickets* —
  <https://github.com/mattpocock/skills/blob/main/skills/engineering/to-tickets/SKILL.md>:
  tracer-bullet vertical slices sized to one fresh context window, blocking edges on the tracker,
  "what to build" from the user's side, no file paths or snippets because they go stale; the
  expand–contract exception for wide refactors.
- *wayfinder* —
  <https://github.com/mattpocock/skills/blob/main/skills/engineering/wayfinder/SKILL.md>: a map
  issue with child decision tickets typed research, prototype, grilling, or task, resolved one per
  session; the decision map under Alternatives.
- *Tracer bullets* — <https://www.aihero.dev/tracer-bullets>: why the first slice through new
  ground goes end to end.
- *improve-codebase-architecture* —
  <https://github.com/mattpocock/skills/blob/main/skills/engineering/improve-codebase-architecture/SKILL.md>
  — and the repository's README, which quotes Kent Beck, *Extreme Programming Explained*:
  "Invest in the design of the system every day"; the design revision at the close of a spec.

The conditions for unattended work come from Addy Osmani, *Agentic autonomy levels* —
<https://addyosmani.com/blog/agentic-autonomy-levels/>: how quickly will we know we are wrong,
how cleanly can we undo, what would prove us right — the three questions a ticket answers — and
the contract every run gets, whose "stopping condition: when to stop; ideally, a measurable
variable" and budget are the fourth. *Loop engineering* on the same site —
<https://addyosmani.com/blog/loop-engineering/>: a loop that runs "until a condition you wrote is
actually true", with a fresh model deciding whether it is done; why the stop is written on the
ticket rather than judged by the session that is stopping.

## Consequences

- Positive: the slicing rule has a carrier; a session opens the tracker instead of re-deriving the
  plan; "may this run unattended?" and "when does it stop?" are answered by the ticket, so a
  session that is not converging hands off instead of widening its scope; closed issues are an
  audit trail that costs nothing to keep; what the system does today is written down before it is
  changed;
  the design of what a feature touched is revisited while it is still known, and the overview is
  checked against the tree at the same moment; a project that writes no specs revisits its design
  at a rhythm its own changes set, and "when did we last look?" is answered in the tree.
- Negative / trade-offs: a feature now costs an issue and its children before the first slice —
  ceremony a one-session change must not pay, so the threshold is a judgement under the
  proportionality principle ([`AGENTS.md` §1](../../AGENTS.md#1-principles)). An effort whose
  questions cannot all be asked at once has no artifact of its own and is charted in the
  conversation, which is gone by the next session. Blocking on GitHub is sub-issues and task
  lists, weaker than a native dependency. A feature spec stays open one session longer, and the
  revision costs a session that ships no behaviour; what it files is tickets, so nothing obliges
  anyone to work them — the decision makes entropy visible, not impossible. A commit is a coarse
  measure of drift, so a project that squashes reaches the number more slowly than one that does
  not, and the date is moved by hand, by the revision's own change.
- Follow-ups: the decision map, once an effort too foggy to slice has been met; triage states for
  issues arriving from outside; tooling for claiming and the frontier once a project wants it.

## Enforcement

[`scripts/sensor-revision-due.sh`](../../scripts/sensor-revision-due.sh) (job `sensors` in
[`checks.yml`](../../.github/workflows/checks.yml)) reads the `Last design revision` line of the
overview, counts the changes since its date, reports the count, and lists the directories they
touched once the number is reached; it fails when the line is missing or unreadable, because
then it measures nothing. Its self-test cites this ADR
([ADR-0003](0003-decisions-verified-by-tests.md)).

**Not mechanically decidable:** the tracker is outside the tree, so whether an effort was specced
and sliced — and whether a spec was closed without its design revision — is review, as is whether
a due revision was run at all and the date moved with it. The templates under
[`.github/ISSUE_TEMPLATE/`](../../.github/ISSUE_TEMPLATE/) carry the shape, and the pull request
template asks for the ticket a change closes.
