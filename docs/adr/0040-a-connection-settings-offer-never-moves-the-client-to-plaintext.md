# ADR-0040: A connection-settings offer never moves the Client to plaintext

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the `endpoint` of the `[connection_offer]` section of
  `server.toml` and its startup check in `crates/fleet-server/src/config.rs`,
  the Client's verification of an offered endpoint in
  `crates/fleet-agent/src/connection.rs`, the loading of its persisted
  `connection-settings.pb`, and every document that tells an operator where an
  offer may move a fleet
- **Supersedes:**
  [ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
  clauses 1, 5 and 9

## Context

A Server may move its fleet to another endpoint by offering connection settings
([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
clause 1). The Client verifies the offered endpoint by connecting to it,
persists it, and from then on prefers it over `supervisor.toml` (ADR-0014
clauses 5 and 9). A move to another `wss://` or `https://` endpoint is taken
only where `[tls] ca_file` is set, so that only a server certificate from the
fleet's own CA is trusted.

A move to `ws://` or `http://` is allowed when the host is a loopback IP
literal. That check does not apply to it, because it has no TLS to verify.
Whoever listens on that port of the Client's host then speaks to the Client as
its Server, with no proof of who it is. Any local account can open such a port.
It can send Supervisor sets and configurations whose language runs commands,
such as a Telegraf `inputs.exec`, and these run as the Client's account. By
default that account is root or LocalSystem
([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
clause 13). A Server needs to send only one such offer, whether it is
compromised or misconfigured. The real Server cannot undo the move, because the
Client never connects to it again, and the persisted endpoint outranks
`supervisor.toml`.

The specification's quality goal Q-1 asks that neither end send a configuration
or a package unencrypted beyond the loopback. A loopback endpoint stays within
that wording, but it leaves the Server's identity unproven. Plaintext on the
loopback exists for development and tests, where an operator writes the endpoint
into `supervisor.toml` and the Client connects to a Server on the same host. No
offer is needed for that.

## Decision

We will refuse every connection-settings offer that would move the Client to a
`ws://` or `http://` endpoint, on the Server at startup and on the Client on
receipt and at load.

1. **Restates ADR-0014 clause 1. The Server's standing offer is
   `[connection_offer]`, and it carries no credential.** It names any of: an
   optional `heartbeat_interval_secs`, and an optional `endpoint` (e.g. for a
   Server move). The `endpoint` is `wss://` or `https://`. A `ws://` or
   `http://` endpoint is refused at startup, on the loopback too, with a message
   naming `[connection_offer] endpoint` and saying that an offer never moves a
   fleet to plaintext. It is never warned about. An empty section fails at
   startup. A credential key — `bearer_token_file`, `username`, `password_file`,
   or the inline `bearer_token` or `password` — is refused at startup with a
   message naming the key: the Agent plane admits by client certificate alone
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
   so an offered credential would be one nothing reads. The OpAMP settings the
   Server offers carry no `headers`.

2. **Restates ADR-0014 clause 5. The OpAMP half is verified by actually
   connecting, then persisted, then reconnected with.** On receipt the Client
   reports `APPLYING`, then checks the candidate's endpoint. A candidate that
   moves to another endpoint — one that differs from the endpoint in force — is
   refused without connecting when it is `ws://` or `http://`, wherever its host
   is. The offer is then reported `FAILED` with an `error_message` naming the
   endpoint and the reason. A candidate that moves to another `wss://` or
   `https://` endpoint is refused the same way unless `[tls] ca_file` is set,
   and is then verified against that CA alone: under the public roots, a Server
   could move the fleet to any host a public CA ever certified, and the move
   would outlive the operator's file (clause 3). Otherwise it connects with the
   candidate — offered fields, falling back to those in force, an offered
   certificate included, offered `headers` never (ADR-0014 clause 8) — over TLS
   1.3, presenting the client certificate in force unless the offer carries one,
   and sending no `Authorization`. Only a candidate that keeps a loopback
   endpoint already in force connects in plaintext. A WebSocket candidate must
   complete its handshake, a plain-HTTP candidate a real exchange. Only then are
   the settings persisted, an issued certificate stored, and the connection
   dropped so the runtime reconnects with them, possibly on the other transport.
   A refused or failed verification keeps everything in force as it was and
   reports `FAILED` with the error.

3. **Restates ADR-0014 clause 9. What is in force is persisted as
   `connection-settings.pb`, and it outranks `supervisor.toml`.** The file in
   `state_dir` is the Baseline's own `ConnectionSettingsOffers`: the merged
   settings in force plus the hash that reports them `APPLIED`, written
   owner-only. OpAMP fields fold — an offer that omits a field leaves the one in
   force — and the file carries an `opamp` block only when an offer or the state
   it folds into had one. How the telemetry destinations fold is
   [ADR-0016](0016-what-an-agent-reports-about-itself.md)'s. At startup the
   persisted settings override `supervisor.toml`'s `endpoint` and heartbeat and
   poll intervals, and the persisted hash restores the status to report. A
   persisted `ws://` or `http://` endpoint that differs from `supervisor.toml`'s
   is the exception. It is not applied, and `supervisor.toml`'s endpoint is used
   instead, with a warning naming both. The persisted OpAMP settings carry no
   `headers`: an `Authorization` header that a file holds from an earlier
   rotation is dropped on load and never sent. `supervisor.toml` stays what the
   operator wrote; deleting the file reverts to it.

**Out of scope:** plaintext that an operator writes into `supervisor.toml`
themselves. It stays allowed on a loopback IP literal
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
Also out of scope: the telemetry destinations an offer sets, which ADR-0016
governs.

## Alternatives considered

- **Allow a move to plaintext only from plaintext.** A Client already on a
  loopback `ws://` endpoint could still be moved to another loopback port. That
  keeps a development convenience, but a Client on a loopback plaintext endpoint
  is still moved to whoever listens on the new port. Development needs no offer
  to change its endpoint, so this buys little. Rejected.
- **Require `[tls] ca_file` for a move to plaintext too.** There is no
  certificate on a plaintext connection to check against the CA, so the
  condition would decide nothing. Rejected.
- **Keep the move and warn.** A warning in the Client's log does not stop a
  takeover that has already happened. Rejected.
- **Leave a persisted plaintext endpoint in force.** A host moved before this
  decision would keep connecting to whoever listens there, and the fix would not
  reach it. Falling back to `supervisor.toml` reaches it at the next start.
  Chosen instead.

## Sources / Prior art

- The code as it stands: `verify` in `crates/fleet-agent/src/connection.rs`
  applies the `ca_file` condition only to a move over TLS, and `check_url` in
  `crates/opamp/src/endpoint.rs` admits `ws://` and `http://` on a loopback IP
  literal. `apply` in the same file lets a persisted endpoint outrank
  `supervisor.toml`.
- The OpAMP specification, _Connection Settings Management_: the Agent should
  verify offered settings before it uses them. Recalled, not re-read for this
  record.

## Consequences

- Positive: a single offer can no longer hand a Client over to a local process.
  A host that was moved to plaintext earlier returns to its configured endpoint
  at its next start.
- Negative / trade-offs: a development setup can no longer move a Client between
  loopback ports by offer; it edits `supervisor.toml`. A `server.toml` whose
  `[connection_offer] endpoint` is `ws://` or `http://` no longer starts; the
  changelog says so.
- Follow-ups: none.

## Enforcement

Tests that will carry `Verifies: ADR-0040`:

- `[connection_offer] endpoint = "ws://127.0.0.1:4320/v1/opamp"` fails at
  startup with a message naming the key.
- An offer that moves a Client to `ws://127.0.0.1:<port>` is reported `FAILED`,
  nothing is persisted, and the Client never connects there. An offer that names
  no endpoint, on a Client whose `supervisor.toml` endpoint is `ws://` on the
  loopback, still applies.
- A persisted `ws://` loopback endpoint that differs from `supervisor.toml`'s is
  not applied at load. A persisted `wss://` endpoint still is.
