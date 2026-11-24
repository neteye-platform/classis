# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do not open a public issue
or pull request.

- Use GitHub's
  [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  (**Security → Report a vulnerability**) if enabled, or
- email the maintainers: <si.development+github-security@wuerth-it.com>.

Please include enough detail to reproduce the issue: affected version or commit,
steps, and impact. We aim to acknowledge reports within a reasonable time frame
and will coordinate a fix and disclosure with you.

## Dev Container & agent execution

Classis runs coding agents inside the Dev Container defined in
[`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json). Three
properties shape its security posture:

- **The Dev Container has no access to the host container engine.** The host
  Docker or Podman socket is **not** mounted into the container, so code or
  agents running inside cannot control the host engine. Host containers are
  managed from a host-side VS Code extension (see the README), which keeps that
  capability outside the container's reach. The container is still not a strong
  security boundary, so run only agents and code you trust in it.
- **Nothing leaves the machine without a human.** The agent commits on a branch
  on its own. A push, a `gh` action, and any command that rewrites or discards
  history wait for an explicit instruction ([`AGENTS.md`
  §6](AGENTS.md#6-project-rules)). That rule is documentation: no file in the
  repository can stop an agent from running `git push`, and a gate in one
  agent's own configuration would hold for that agent only, so none is used.
  Authentication uses the web flow of `gh` with no stored tokens. Two halves
  hold for every agent and every human, because they are the repository's own
  git hooks ([`.githooks/`](.githooks/), enabled by the Dev Container): no
  commit on `main`, and no push while the checks are red. Each is bypassable
  with `--no-verify`, which is a deliberate act, not a default.
- **The specification changes only by human decision.** A change to
  [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) is a decision rather than an
  edit ([`AGENTS.md` §3](AGENTS.md#3-decisions)). The gate is the approving
  review that the ruleset on `main` requires of every pull request (see
  [**Repository settings**](README.md#repository-settings)). It does not stop
  the edit; it routes it to a human before it reaches `main`, and it holds for
  every agent alike. It is not specific to these files: any reviewer with write
  access satisfies it, so whether a change to the specification is the decision
  of the right human is review only.

## Secrets

The rule is in [`AGENTS.md` §7](AGENTS.md#7-secrets), and that wording governs:
a secret never enters a tracked file, a commit message, a log, or CI output, and
one that reaches git is rotated rather than deleted from the tip of a branch.
Rotation first, history rewriting only as cleanup, as [GitHub's own
guidance](https://docs.github.com/en/authentication/keeping-your-account-secure/removing-sensitive-data-from-a-repository)
puts it. This section records what the repository's own configuration does about
it, which is less than the rule asks.

Two mechanisms keep environment files out of the way. [`.gitignore`](.gitignore)
leaves `.env*` untracked in every directory, with a secrets-free `.env.example`
as the one tracked exception. [`.claude/settings.json`](.claude/settings.json)
denies Claude Code read access to the same pattern, so their contents cannot
reach the agent's context and from there a file, a commit message, or a log.

Three limits are worth knowing. The deny pattern also covers a tracked
`.env.example`, whose shape an agent is told rather than shown. It is a
permission rule on one agent's file-reading tool, not a sandbox, and it reaches
no other agent; for an agent without an equivalent mechanism the rule is
documentation only, as with the git rules above. And the two together are not
enforcement of the rule: they close one path for one agent. A secret that
arrives by any other path (typed into a commit message, echoed by a workflow
step, pasted into a document) is caught by review or by GitHub's [secret
scanning with push
protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning),
which is a repository setting (see [**Repository
settings**](README.md#repository-settings)) and does nothing until a maintainer
enables it. No check in this repository looks for a secret: a regex scan in
[`scripts/`](scripts/) would be false confidence rather than enforcement, and a
scanning toolchain is a dependency a project adds by decision once it has
credentials the built-in patterns miss.

## Actions in the workflows

Every action the workflows run, GitHub's own `actions/*` included, is pinned to
a full commit SHA, with the ref it was taken from in a comment on the same line:
the release tag as `# vX.Y.Z`, or, for a reusable workflow of the organisation's
own `neteye-platform` repositories, which publish no tags, the branch (`#
main`). CI resolves each ref and checks that it still leads to the pinned
commit: a tag must point to it, a branch must contain it. The organisation
enforces the same pinning as a GitHub setting, which refuses a run that
references an action by a tag. This is held by
[`scripts/check-action-refs.sh`](scripts/check-action-refs.sh). Renovate, on the
organisation preset, raises every update; a branch comment says only that the
commit was on the branch, not which state of it was reviewed.

## Fleet trust model

**Admission is a fleet-wide trust boundary; within it the host is the bound
between Agents**. A host registers with its Space's reusable enrolment key,
obtains client credentials and uses them to obtain an access token. Each OpAMP
HTTP request or WebSocket upgrade, and each package download, requires that
active bearer token. The Server keeps only the token's SHA-256 hash and derives
the host from its client's `client_id`, never from a report or a TLS client
certificate.

An `instance_uid` recorded under one host cannot be reported by another: the
Server refuses it, rather than re-keying the reporter. One host owns at most
256 Agent identities. Gateway Mode and its admission exception are unavailable.
Replacing a token invalidates the previous one and closes its admitted
WebSocket sessions; expiry is checked on the next request or connection, not
by ending an already admitted session. No client-certificate fallback is wired
into the Server.

**A host receives from the Server only what is released to an Agent it speaks
for**. A composed configuration travels only to the Agent it was released to,
and the package download serves an uploaded artifact only to a host one of whose
Agents is offered it. An artifact not offered to that host is answered `404`, as
for an artifact the store does not hold, so a host can neither fetch another
partition's builds nor list the store. The bound is no stronger than the
partition: a host that reports another partition's attributes under a fresh
`instance_uid` is assigned by that partition's next rollout, and the fleet view
shows such an Agent waiting before the press. A Space groups registrations; it
is not an authorization boundary between rollout Selectors.

**What this means for operators:** treat one fleet (one Server, one shared
admission) as a single trust domain, and do not place mutually distrusting
Agents in one fleet; isolate them by separate Server instance or network
segment. Protect the Space's reusable enrolment key, the client's secret and
its access token as credentials. The token authenticates a host, not the truth
of the attributes its Agents report.

## Supported versions

Security fixes land on `main` and ship in the next release. Only the latest
release is supported: before 1.0 no fix is backported to an earlier one, so the
remedy for a vulnerable version is an upgrade — through the fleet's own
self-update where the Client is concerned. Each fix is listed in
[`CHANGELOG.md`](CHANGELOG.md) under the release that carries it.

| Version                         | Supported |
| ------------------------------- | --------- |
| the latest `v<version>` release | ✅        |
| any earlier release             | ❌        |
