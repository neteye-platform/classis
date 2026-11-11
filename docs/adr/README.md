# Architecture Decision Records

This directory holds the ADRs of the project. An accepted ADR binds humans and
coding agents alike ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)). ADRs derive
from [`docs/SPECIFICATION.md`](../SPECIFICATION.md).

## What an ADR is for

An ADR records information the code does not contain: an external constraint, a
rejected alternative, a choice a reader would take for a mistake, or the
condition under which the choice must be reconsidered. It never describes how
the code works. If an agent can learn it by reading the code, or a test decides
it, it is not an ADR.

## Mechanics

- **File.** Copy [`template.md`](template.md) to `NNNN-short-title.md` with the
  next free number. The `# ADR-NNNN` heading matches the filename.
- **Index.** The table below changes in the same pull request as the ADR it
  describes.
- **Numbers are permanent.** Never renumber or delete an ADR. A superseded ADR
  keeps its file; its `Status` line becomes `⚪ superseded by ADR-NNNN`.
- **Cite only what exists.** Every `ADR-NNNN` reference names a file in this
  directory.

## History

The ADRs inherited from the upstream project `opamp-fleet` were removed. They
are in git under the tag `upstream-import`; they bind nothing here.

## Index

**Status legend:** 🟢 accepted · 🟡 proposed · 🔴 rejected · ⚪ superseded

| ADR | Title | Status |
| --- | ----- | ------ |
