# ADR-0064: The Server speaks plain HTTP behind a reverse proxy and authenticates no Agent

- **Status:** 🟡 proposed
- **Date:** 2026-11-16
- **Deciders:** Luca Tecchio
- **Applies to:** the listeners and the admission of both planes in
  `crates/classis-server/src/main.rs`, `listen.rs`, `transport.rs`,
  `agent_auth.rs` and `config.rs`, the plaintext rule of `Listener::serve` in
  `crates/opamp/src/server/listen.rs`, the `[agents]`, `[tls]`, `[rest.tls]`,
  `[client_ca]` and `[enrolment]` sections of `server.toml`, the peer address
  the admission throttle and the rate limits count, the `pki` command of the
  Server binary, and every document that tells an operator how the Server is
  reached and how an Agent is admitted
- **Supersedes:**
  [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clauses 5 (the Server terminates TLS), 7, 12 and 15 (the Server's listener
  side),
  [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clauses 1, 5, 6, 14, 23 and 24, and
  [ADR-0032](0032-the-operator-plane-may-serve-a-certificate-of-its-own.md)

## Context

The Server is deployed on Kubernetes, in a tenant's namespace, and a reverse
proxy on the PCS nodes sits in front of it, as it does for Keycloak. The proxy
is where TLS ends, and it is where Agents will be authenticated, by a library
the Server does not contain. The Server as built could not live behind it:

- it refused to serve a plaintext listener on any address but the loopback
  ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 15);
- it admitted an Agent by the client certificate of its TLS handshake, which a
  proxy that terminates the handshake hides
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clauses 5 and 6);
- it counted failures per connection address, which behind a proxy is always the
  proxy's (ADR-0021 clause 24).

[`docs/SPECIFICATION.md`](../SPECIFICATION.md) Q-1 says neither end sends a
credential, a configuration or a package unencrypted beyond the loopback, and
admits no Agent without a client certificate. This decision moves what Q-1
requires of the Server's own listener onto the proxy, and gives the Server no
credential check of its own on the Agent plane; **Q-1 is a specification text,
and only a human lands a change to it**
([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 7). Until then this ADR and
Q-1 disagree, and the specification wins: the ADR is proposed so that the
disagreement is read before it is lived with. A text for Q-1 that this decision
would make true: _"Whatever its configuration, the Server sends no credential,
configuration or package to a peer that is not behind a TLS-terminating proxy it
trusts, admits an Agent only through the proxy that authenticates it, and
installs no package without a valid signature."_

An earlier form of this decision admitted Agents by a JWT the Server verified.
It was dropped: the credential will be a random string, checked by a library in
front of the Server, so the Server has nothing to verify. NEAG-34 reimplements
enrolment and decides how an Agent obtains that string.

## Decision

We will serve both planes in plain HTTP on any address, admit every request of
the Agent plane through a seam an authenticator can later plug into, and count
the peer by the address in `X-Forwarded-For`.

- **No TLS on the Server's listeners.** `[tls]`, `[rest.tls]`, `[client_ca]` and
  `[enrolment]` are refused at startup, naming the section; `Listener::serve`
  takes a plaintext listener on any address when the application asks for it
  (`with_plaintext_anywhere`), and the refusal of ADR-0013 clause 15 stays the
  default of every other user of the listener, the Gateway included. Connections
  the Server opens — to PostgreSQL and to S3 — stay TLS 1.3
  ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 5 as it concerns the Server's outbound side).
- **The Server authenticates no Agent.** `/v1/opamp`, over both transports, and
  the package download route admit every request, with or without an
  `Authorization` header: a header that is sent is ignored, never refused. A
  leftover `[agents]` section, `[agents.auth]` included, is refused at startup,
  naming it, so that no operator believes the Server still checks a credential.
- **One seam for the authentication that comes later.** `AgentAuthenticator`
  (`crates/classis-server/src/agent_auth.rs`) is asked about the headers of
  every request of the Agent plane before it is served, and answers `Admitted`
  (optionally naming the host the request speaks for) or `Refusal` (a `401`,
  counted as a failure of the peer's address by the admission throttle). The
  only implementation is `AdmitEveryone`. A library that checks the random
  string implements the trait; no route changes.
- **The identity of an Agent is the `instance_uid` of its OpAMP message.** The
  certificate's host URI, and the `sub` of the token this decision first
  carried, no longer exist, so the Agent records, rates and package visibility
  key on what the Agent says it is, as they did for a request that carried no
  proof. No header names a host: one that no check backs would be a second
  channel for the same claim. An authenticator that knows the host names it in
  `Admitted`.
- **The peer is the address in `X-Forwarded-For`.** The left-most entry that
  parses as an address (bare, with a port, or bracketed IPv6) is the peer the
  admission throttle and the Operator plane's throttle count; without the
  header, the connection's address. The header is trusted from any source.
- **The Operator plane keeps its Basic credential.** `[rest.auth]` stays as
  ADR-0021 clause 15 and ADR-0063 say; off the loopback it is still required.
  The password now crosses the network between the proxy and the Server in the
  clear.
- **What depends on a certificate is disabled, not removed.** With `[client_ca]`
  and `[enrolment]` refused, the Server signs no CSR, issues no bootstrap
  certificate, opens no enrolment window and declares no
  `AcceptsConnectionSettingsRequest`; the register of certificates is opened
  with no authority. Their code and the clauses of ADR-0021 that govern them
  (9–12, 19–22, 25 and 27–43) stay where they are until the ADR of NEAG-34
  supersedes them. `server pki` answers that it is removed.

**Out of scope:** how the proxy terminates TLS and authenticates an Agent; how
an Agent obtains and renews its credential (NEAG-34); the authenticator itself;
a list of proxies `X-Forwarded-For` is trusted from; the Gateway, which keeps
its TLS.

## Alternatives considered

- **Keep mutual TLS and pass the proxy through** — TLS passthrough keeps the
  certificate admission but gives up what a proxy is for here: one per-tenant
  entry, a rotation of its certificate in one place, and the same shape as
  Keycloak. It was the first deployment's choice and is the one this replaces.
- **Verify a JWT in the Server** — built first, then dropped: the credential is
  a random string checked outside the Server, so a verifier, a key to mount and
  a rotation of that key would be code and operations for a check that is not
  the Server's.
- **The proxy verifies the client certificate and forwards its identity in a
  header** — the Server would trust a header from the proxy and need the list of
  proxies that makes the trust real, which this decision does not have. It stays
  open for NEAG-34.
- **Trust `X-Forwarded-For` only from a list of proxy addresses** — the safe
  form, and the one a later ADR should adopt. It was not chosen now because the
  proxy's address is not yet known to the Server's configuration.
- **A second listener in plaintext beside the TLS ones** — two ways in, two
  admission paths, and the TLS ones would remain the code that never runs in the
  deployment this is for.
- **Delete the enrolment, bootstrap and CA code** — a large deletion of code
  NEAG-34 replaces; it is disabled so that the replacement decides what it
  keeps.

## Sources / Prior art

- [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239) and the de-facto
  `X-Forwarded-For`: a client can write the header, so its trust is the proxy's
  to give.
- ADR-0063 and the Kubernetes probes it serves: the same proxy-and-pod shape.

## Consequences

- Positive: the Server runs behind the proxy the deployment already has, with no
  certificate and no key to issue, mount or renew on the Server; the
  authentication can change without the Server.
- Negative / trade-offs:
  - **Any peer that reaches the Agent port is admitted, and may claim any
    identity.** Its OpAMP messages carry the `instance_uid` the Server keys
    everything on, and nothing in the Server checks it. The Agent port must be
    reachable through the authenticating proxy alone — by NetworkPolicy and by
    where the Service is exposed — or the fleet is open to whoever can open a
    connection.
  - **`X-Forwarded-For` is trusted from any source.** Whoever can reach the port
    can write the header and name any address: they can keep their own failures
    from ever filling the throttle, and put another host's address in back-off.
    The proxy is the protection.
  - **Plain HTTP between the proxy and the Server.** An operator's Basic
    password and every package cross that hop in the clear. NetworkPolicies, and
    a proxy in the same trust zone, are what protect them.
  - Q-1 of the specification no longer describes the Server until a human lands
    its new text.
- Follow-ups: the authenticator and how an Agent obtains its credential; a list
  of trusted proxies; the removal of the code this disables.

## Enforcement

Tests that carry `Verifies: ADR-0064`:

- `crates/classis-server/src/agent_auth.rs`: the only implementation admits a
  request with or without a credential.
- `crates/classis-server/tests/http_admission.rs`: the Agent plane admits a
  request over plain HTTP with no credential, and ignores one it carries; the
  package download asks nothing either; failures are counted per forwarded
  address and per connection address without the header.
- `crates/classis-server/src/config.rs`: a Server starts without any section for
  Agents, and a leftover `[agents.auth]` is refused by name; `[tls]`,
  `[rest.tls]`, `[client_ca]` and `[enrolment]` are refused by name.
- `crates/classis-server/tests/http_server.rs`: the binary serves both planes in
  plain HTTP, refuses a TLS section and an `[agents.auth]` section, and says
  `server pki` is removed.

**Not mechanically decidable:** that the network which reaches the Server's port
is the proxy's alone is the deployment's, not a test's.
