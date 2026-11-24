# Security model

How Classis and this repository are secured: the Dev Container the agents
run in, what the repository does about secrets, how the workflows pin their
actions, the trust model of a fleet, and which releases receive fixes. To report
a vulnerability, follow [`SECURITY.md`](../SECURITY.md).

## Dev Container & agent execution

Classis runs coding agents inside the Dev Container defined in
[`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json). Three
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
  §6](../AGENTS.md#6-project-rules)). That rule is documentation: no file in the
  repository can stop an agent from running `git push`, and a gate in one
  agent's own configuration would hold for that agent only, so none is used.
  Authentication uses the web flow of `gh` with no stored tokens. Two halves
  hold for every agent and every human, because they are the repository's own
  git hooks ([`.githooks/`](../.githooks/), enabled by the Dev Container): no
  commit on `main`, and no push while the checks are red. Each is bypassable
  with `--no-verify`, which is a deliberate act, not a default.
- **The specification changes only by human decision.** A change to
  [`docs/SPECIFICATION.md`](SPECIFICATION.md) is a decision rather than an edit
  ([`AGENTS.md` §3](../AGENTS.md#3-decisions)). The gate is the approving review
  that the ruleset on `main` requires of every pull request (see [**Repository
  settings**](../README.md#repository-settings)). It does not stop the edit; it
  routes it to a human before it reaches `main`, and it holds for every agent
  alike. It is not specific to these files: any reviewer with write access
  satisfies it, so whether a change to the specification is the decision of the
  right human is review only.

## Secrets

The rule is in [`AGENTS.md` §7](../AGENTS.md#7-secrets), and that wording
governs: a secret never enters a tracked file, a commit message, a log, or CI
output, and one that reaches git is rotated rather than deleted from the tip of
a branch. Rotation first, history rewriting only as cleanup, as [GitHub's own
guidance](https://docs.github.com/en/authentication/keeping-your-account-secure/removing-sensitive-data-from-a-repository)
puts it. This section records what the repository's own configuration does about
it, which is less than the rule asks.

Two mechanisms keep environment files out of the way.
[`.gitignore`](../.gitignore) leaves `.env*` untracked in every directory, with
a secrets-free `.env.example` as the one tracked exception.
[`.claude/settings.json`](../.claude/settings.json) denies Claude Code read
access to the same pattern, so their contents cannot reach the agent's context
and from there a file, a commit message, or a log.

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
settings**](../README.md#repository-settings)) and does nothing until a
maintainer enables it. The organisation's shared checks scan for secrets too:
gitleaks and `detect-private-key` in the pre-commit run, and the secret rules of
Trivy and Semgrep on every pull request. They match known patterns; a secret in
no pattern's shape passes them.

One secret is the release's own: `PACKAGE_SIGNING_KEY`, the Ed25519 key of the
Package Signer every release signs the Client's archives with. Its certificate,
which the Package Root compiled into the Client and the Server issued, is
`packaging/package-signer.der`, and every `.sig` carries it. Replacing the key
is a new key, a new certificate from the same Root, a new secret and a reviewed
change to that file; no installation changes. It is a secret of the GitHub
environment `Package Signing`, not of the repository. Only the `sign` job names
that environment, and it receives the key only on the push of a `v<version>` tag
and after a second person with write access approves the run. The job checks out
no code and builds nothing, and it removes the key from the runner whatever the
outcome. What this does not close: a repository admin can change the environment
or replace the secret, a changed workflow on a tagged commit runs with the key
once someone approves it, and a key that leaks signs Packages that every
installation accepts until its Package Signer's certificate expires; there is no
revocation.

## Actions in the workflows

Every action the workflows run, GitHub's own `actions/*` included, is pinned to
a full commit SHA, with the ref it was taken from in a comment on the same line:
the release tag as `# vX.Y.Z`, or, for a reusable workflow of the organisation's
own `neteye-platform` repositories, which publish no tags, the branch (`#
main`). CI resolves each ref and checks that it still leads to the pinned
commit: a tag must point to it, a branch must contain it. The organisation
enforces the same pinning as a GitHub setting, which refuses a run that
references an action by a tag. This is held by
[`scripts/check-action-refs.sh`](../scripts/check-action-refs.sh). Renovate, on
the organisation preset, raises every update; a branch comment says only that
the commit was on the branch, not which state of it was reviewed.

## Fleet trust model

**Admission is a fleet-wide trust boundary; within it the host is the only bound
between Agents**. A peer reaches the OpAMP endpoint by proving _fleet
membership_ with a client certificate in the TLS handshake, the one proof the
Agent plane admits by. The certificate also names the **host** it was issued to,
and an `instance_uid` first reported with one host's certificate is not spoken
for by another's: such a reporter is re-keyed to an identity of its own. A
certificate is not bound to one `instance_uid`, which is self-asserted and which
the Server may re-key.

The Client no longer runs as a Gateway, but the Server still keeps
the Gateway mark of its certificate model until that model is removed: **a host
marked as a Gateway can report under any `instance_uid`** and update that
Agent's Server-side record (health, effective config, remote-config status, and
so the Configuration offered to it). This is _not_ a cross-fleet or
unauthenticated exposure: it is bounded by admission.

**A host receives from the Server only what is released to an Agent it speaks
for**.
A composed configuration travels only to the Agent it was released to, and the
package download serves an uploaded artifact only to a host one of whose Agents
is offered it; every other request is answered `404`, as for an artifact the
store does not hold, so a host can neither fetch another partition's builds nor
list the store. A marked host's certificate speaks for any Agent and may fetch
what any Agent is offered. The bound is no stronger than the partition: a host
that reports another partition's attributes under a fresh `instance_uid` is
assigned by that partition's next rollout, and the fleet view shows such an
Agent waiting before the press.

**What this means for operators:** treat one fleet (one Server, one shared
admission) as a single trust domain, mark no host as a Gateway (`PUT
/api/v1/hosts/{host}/gateway`) now that no Client is one, and do not place
mutually distrusting Agents in one fleet; isolate them by separate Server
instance or network segment.

## Supported versions

Security fixes land on `main` and ship in the next release. Only the latest
release is supported: before 1.0 no fix is backported to an earlier one, so the
remedy for a vulnerable version is an upgrade — through the fleet's own
self-update where the Client is concerned. Each fix is listed in the release
notes of the release that carries it.

| Version                          | Supported |
| -------------------------------- | --------- |
| the latest `v<version>` release  | ✅        |
| any earlier release              | ❌        |
