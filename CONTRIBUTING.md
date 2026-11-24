# Contributing

Thanks for your interest in contributing. This project is
**specification-driven**. The working rules in [`AGENTS.md`](AGENTS.md) are the
single source of truth, and they govern coding agents and human contributors
alike. This file carries no rules of its own: it points at them and adds only
the contributor-facing procedure.

## Before you start

Read, in this order:

1. [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md): the constitution, with
   problem, goals, and success criteria, written in the vocabulary of
   [`docs/GLOSSARY.md`](docs/GLOSSARY.md).
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the system as it stands
   today, its parts, their responsibilities, how they fit together, and its key
   decisions.
3. [`AGENTS.md`](AGENTS.md): the working rules, with principles, how decisions
   are made, the quality bar (Definition of Done), and all conventions,
   including language and vocabulary.

Authority runs **specification → architecture overview → individual change**.

## Workflow

1. **Open an issue first** when scope or intent is not yet agreed ([`AGENTS.md`
   §4](AGENTS.md#4-working-style)).
2. **Follow [`AGENTS.md`](AGENTS.md)**: when a decision is agreed first and
   where it is recorded ([§3](AGENTS.md#3-decisions)), when a change counts as
   done ([§5](AGENTS.md#5-quality-bar--definition-of-done)), and the git and
   project rules ([§6](AGENTS.md#6-project-rules)). Run
   [`scripts/check-all.sh`](scripts/check-all.sh) locally before pushing
   ([§5](AGENTS.md#5-quality-bar--definition-of-done)). It runs the same checks
   CI runs on every pull request, in the same order. With the repository's git
   hooks enabled (the Dev Container does it; otherwise `git config
   core.hooksPath .githooks`) a push runs them for you and stops while they are
   red. They need only bash and coreutils, already in the Dev Container. Only
   the shell lint additionally needs [ShellCheck](https://www.shellcheck.net)
   and skips itself where that is missing; CI runs it always.
3. **Open a pull request** against `main`, fill in the PR template, and link the
   issue.

## License of contributions

This project is licensed under either of the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option. Unless you explicitly
state otherwise, any contribution you intentionally submit for inclusion is dual
licensed as above, without any additional terms or conditions (section 5 of the
Apache License 2.0). Do not submit code you are not authorised to license this
way.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. Follow
[`SECURITY.md`](SECURITY.md).
