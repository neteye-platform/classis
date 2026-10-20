# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do not open a public issue or pull request.

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  (**Security → Report a vulnerability**) if enabled, or
- email the maintainers: <si.development+github-security@wuerth-it.com>.

Please include enough detail to reproduce the issue: affected version or commit, steps, and
impact. We aim to acknowledge reports within a reasonable time frame and will coordinate a fix and
disclosure with you.

## Dev Container & agent execution

OpAMP Fleet runs coding agents inside the Dev Container defined in
[`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json). Three properties shape its
security posture:

- **The Dev Container has no access to the host container engine.** The host Docker or Podman
  socket is **not** mounted into the container ([ADR-0002](docs/adr/0002-dev-container-runtime.md)),
  so code or agents running inside cannot control the host engine. Host containers are managed
  from a host-side VS Code extension (see the README), which keeps that capability outside the
  container's reach. The container is still not a strong security boundary, so run only agents
  and code you trust in it.
- **Nothing leaves the machine without a human.** The agent commits on a branch on its own. A
  push, a `gh` action, and any command that rewrites or discards history wait for an explicit
  instruction ([`AGENTS.md` §6](AGENTS.md#6-project-rules)). That rule is documentation: no file
  in the repository can stop an agent from running `git push`, and a gate in one agent's own
  configuration would hold for that agent only, so none is used. Authentication uses the web flow
  of `gh` with no stored tokens. Two halves hold for every agent and every human, because they are
  the repository's own git hooks ([`.githooks/`](.githooks/), enabled by the Dev Container): no
  commit on `main`, and no push while the checks are red. Each is bypassable with `--no-verify`,
  which is a deliberate act, not a default.
- **The specification and the decision record change only by human decision.** A change to
  [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) is a decision rather than an edit, and only a
  human changes an ADR's status ([`AGENTS.md` §3](AGENTS.md#3-adr-rules)). The gate is the
  approving review that the ruleset on `main` requires of every pull request (see
  [**Repository settings**](README.md#repository-settings)). It does not stop the edit; it routes
  it to a human before it reaches `main`, and it holds for every agent alike. It is not specific to
  these files: any reviewer with write access satisfies it, so whether a change to the
  specification or an ADR is the decision of the right human is review only.

## Secrets

The rule is in [`AGENTS.md` §7](AGENTS.md#7-secrets), and that wording governs: a secret never
enters a tracked file, a commit message, an ADR, a log, or CI output, and one that reaches git is
rotated rather than deleted from the tip of a branch. Rotation first, history rewriting only as
cleanup, as [GitHub's own guidance](https://docs.github.com/en/authentication/keeping-your-account-secure/removing-sensitive-data-from-a-repository)
puts it. This section records what the repository's own configuration does about it, which is
less than the rule asks.

Two mechanisms keep environment files out of the way. [`.gitignore`](.gitignore) leaves `.env*`
untracked in every directory, with a secrets-free `.env.example` as the one tracked exception.
[`.claude/settings.json`](.claude/settings.json) denies Claude Code read access to the same
pattern, so their contents cannot reach the agent's context and from there a file, a commit
message, or a log.

Three limits are worth knowing. The deny pattern also covers a tracked `.env.example`, whose shape
an agent is told rather than shown. It is a permission rule on one agent's file-reading tool, not
a sandbox, and it reaches no other agent; for an agent without an equivalent mechanism the rule is
documentation only, as with the git rules above. And the two together are not enforcement of the
rule: they close one path for one agent. A secret that arrives by any other path (typed into a
commit message, echoed by a workflow step, pasted into an ADR) is caught by review or by GitHub's
[secret scanning with push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning),
which is a repository setting (see [**Repository settings**](README.md#repository-settings)) and
does nothing until a maintainer enables it. No check in this repository looks for a secret: a
regex scan in [`scripts/`](scripts/) would be false confidence rather than enforcement, and a
scanning toolchain is a dependency a project adds through an ADR of its own once it has
credentials the built-in patterns miss.

## Actions in the workflows

Every action the workflows run, GitHub's own `actions/*` included, is pinned to a full commit SHA,
with the ref it was taken from in a comment on the same line: the release tag as `# vX.Y.Z`, or,
for a reusable workflow of the organisation's own `neteye-platform` repositories, which publish no
tags, the branch (`# main`). CI resolves each ref and checks that it still leads to the pinned
commit: a tag must point to it, a branch must contain it. The organisation enforces the same
pinning as a GitHub setting, which refuses a run that references an action by a tag. This is
[ADR-0049](docs/adr/0049-every-github-action-is-pinned-to-a-commit-sha-and-renovate-keeps-it-current.md),
held by [`scripts/check-action-refs.sh`](scripts/check-action-refs.sh). Renovate, on the
organisation preset, raises every update; a branch comment says only that the commit was on the
branch, not which state of it was reviewed.

## Fleet trust model

**Admission is a fleet-wide trust boundary; within it the host is the only bound between Agents**
([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clauses 7, 14
and 27). A peer reaches the OpAMP endpoint by proving *fleet membership* with a client certificate
in the TLS handshake, the one proof the Agent plane admits by. The certificate also names the **host** it was issued to, and an
`instance_uid` first reported with one host's certificate is not spoken for by another's: such a
reporter is re-keyed to an identity of its own. A certificate is not bound to one `instance_uid`,
which is self-asserted and which the Server may re-key, and a Gateway
([ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)) forwards many
Agents' reports under its own certificate.

The consequence, which is a design property rather than a defect: **a host marked as a Gateway, or
a peer behind one, can report under any `instance_uid`** and update that Agent's Server-side record
(health, effective config, remote-config status, and so the Configuration offered to it). This is
*not* a cross-fleet or unauthenticated exposure: it is bounded by admission.

**A host receives from the Server only what is released to an Agent it speaks for**
([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). A composed configuration travels only to the Agent it was released to,
and the package download serves an uploaded artifact only to a host one of whose Agents is
offered it; every other request is answered `404`, as for an artifact the store does not hold, so
a host can neither fetch another partition's builds nor list the store. A Gateway's certificate
speaks for any Agent and may fetch what any Agent is offered; the Gateway passes an artifact on
only to a downstream host whose Agent it relayed that offer to, and answers every other request
`404` alike. Behind a Gateway an `instance_uid` belongs to the host of its first report since the
Gateway started, so a host that reports another host's `instance_uid` first is served that
Agent's offers until the Gateway restarts. A host binds at most `max_carried_agents`
`instance_uid`s, and at the Gateway's cap of 1 000 000 a new binding replaces the least recently
reported one that has neither a route nor an offer, so one host cannot keep another's Agents from
being bound. The bound is no stronger than the partition: a host
that reports another partition's attributes under a fresh `instance_uid` is assigned by that
partition's next rollout, and the fleet view shows such an Agent waiting before the press.

**What this means for operators:** treat one fleet (one Server, one shared admission) as a single
trust domain, mark only real Gateways as such (`PUT /api/v1/hosts/{host}/gateway`), and do not
place mutually distrusting Agents behind one Gateway or in one fleet; isolate them by separate
Server instance or network segment. The alternatives that were weighed are in ADR-0021.

## Supported versions

Security fixes land on `main` and ship in the next release. Only the latest release is supported:
before 1.0 no fix is backported to an earlier one, so the remedy for a vulnerable version is an
upgrade — through the fleet's own self-update where the Client is concerned. Each fix is listed in
[`CHANGELOG.md`](CHANGELOG.md) under the release that carries it.

| Version | Supported |
|---|---|
| the latest `version/*` release | ✅ |
| any earlier release | ❌ |
