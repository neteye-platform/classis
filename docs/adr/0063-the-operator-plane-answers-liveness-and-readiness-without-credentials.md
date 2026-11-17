# ADR-0063: The Operator plane answers liveness and readiness without credentials

- **Status:** 🟡 proposed
- **Date:** 2026-11-13
- **Deciders:** Luca Tecchio
- **Applies to:** the Operator plane's guard and routes in
  `crates/classis-server/src/api.rs`, the readiness checks of the PostgreSQL and
  blob stores they call, and every document that tells an operator how to probe
  the Server
- **Supersedes:**
  [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 15

## Context

The Server has no health endpoint, and an orchestrator's HTTP probe cannot
reach anything useful: the Agent plane is the fleet's endpoint, not a health
check, and the Operator plane answers `401` without a Basic credential
([ADR-0064](0064-the-server-speaks-plain-http-behind-a-reverse-proxy-and-authenticates-no-agent.md),
[ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 15). A TCP probe says only that the port is open, not that the database
answers or the Server holds its lock. A probe runs from the node, not from the
pod's loopback, and the Server speaks plain HTTP on its planes, so the probe is
a plain `GET`.

## Decision

We will serve `GET /livez` and `GET /readyz` on the Operator plane's own
listener, outside its guard, so that they answer without a credential.

- `/livez` answers `200` while the Server's process serves requests.
- `/readyz` answers `200` when the Server holds its database lock, the database
  answers a query, and the blob store answers; otherwise `503`. The body is one
  word, `ok` or the name of the failed check, and carries no address, error
  text or other detail.
- Both answer `GET` and `HEAD` only, are not counted by the admission
  throttle, and are not logged as an operator act.
- Every other route of the Operator plane stays behind `[rest.auth]` as
  clause 15 says, and the Agent plane is untouched. Clause 15 otherwise stands:
  basic users, the refusal of a non-loopback `listen` without `[rest.auth]`, and
  the challenge on every other route.

**Out of scope:** a health endpoint on the Agent plane, metrics, and a probe
that presents a credential.

## Alternatives considered

- **A third, plaintext listener for probes** — forbidden off the loopback by
  ADR-0013, and an extra port to expose and to deny.
- **A probe with a Basic credential** — puts a password in the pod
  specification, readable by whoever reads it.
- **A TCP probe only** — it cannot tell a Server without its lock from a
  healthy one.

## Sources / Prior art

- Kubernetes,
  [configure liveness, readiness and startup probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/):
  an HTTP probe is a `GET` the kubelet sends from the node.

## Consequences

- Positive: an orchestrator can tell a started Server from a serving one, over
  HTTP and without a secret in its configuration.
- Negative / trade-offs: whoever reaches the Operator plane learns whether the
  Server is ready. The probes cover the Operator plane's listener; the Agent
  plane's listener is up when the process is.
- Follow-ups: a probe for the Agent plane, should the planes ever run in
  separate processes.

## Enforcement

Tests that will carry `Verifies: ADR-0063`:

- `/livez` and `/readyz` answer without a credential on a plane guarded by
  `[rest.auth]`, and every other route still answers `401`.
- `/readyz` answers `503` naming the failed check, and nothing else, when the
  database or the blob store fails.
- Requests for them are not counted by the admission throttle.
