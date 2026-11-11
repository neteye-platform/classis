# ADR-0022: The Server keeps no audit record, and every security decision it takes is a structured event on its log

- **Status:** 🟢 accepted
- **Date:** 2026-11-11
- **Deciders:** Davide Zeni
- **Applies to:** every place in `crates/fleet-server/src/` that admits or
  refuses a peer, issues or revokes a certificate, takes an operator's act or
  records a package outcome, the Server's log output set up in
  `crates/fleet-server/src/main.rs`, the top-level keys of `server.toml` in
  `crates/fleet-server/src/config.rs`, and the layout of `data_dir`

## Context

Until now the Server kept an audit record of its own. Every security decision
was appended as one JSON line to an owner-only file under `data_dir/audit/`,
each line carrying the SHA-256 of the line before it. An `[audit]` section in
`server.toml` bounded the files by size and number, `server audit-verify` walked
the chain, refusals from one peer address beyond ten a second were aggregated
into a count, and a decision was not taken while its line could not be written:
admission and operator acts were answered `503`, and a CSR `Unavailable`.

That record is a dependency on the filesystem. The Server is to keep none: its
records may live in PostgreSQL
([ADR-0050](0050-the-servers-records-may-live-in-postgresql.md)) and its
artifacts in an object store
([ADR-0049](0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md)),
and it ships as a container image
([ADR-0052](0052-the-server-ships-as-a-container-image-built-from-its-attested-release-binary.md)).
With PostgreSQL the audit file was the one record that still tied the Server to
a disk of its own. The filesystem stores themselves go in a later step; the
audit record goes now.

The security decisions do not stop mattering. An operator still needs to see
who was admitted, refused, enrolled, issued, revoked and rolled out to. A
container's standard output and standard error are collected by whatever runs
it, and the Server already logs there through `tracing`.

The decisions also must not leak what they concern: no secret, no key, no CSR
body. The Agent plane reads no `Authorization` header, but a Client of an older
version may still send one, and an operator signing in to the Operator plane
presents a password. A peer that was not admitted can cause a refusal at will,
and a log has no rate limit.

## Decision

We will emit every security decision the Server takes as one structured
`tracing` event on its log output, and keep no audit record: no file, no hash
chain, no verification and no `[audit]` section.

1. **One event per decision, refusals included.** An event is emitted for:
   - admission on `/v1/opamp` and on the download route: admitted, refused
     (which check refused, never the presented value), throttled; a message or
     a download over a host's rate; a download a host may not fetch; a report
     that claims an `instance_uid` bound to another host;
   - enrolment: a request queued, asked again, refused, approved, rejected; the
     window opened, or closed by an operator or run out, with the number of
     requests that expired with it;
   - issuance: a certificate signed on an enrolment approval, a CSR or a
     renewal, with its CA role, issuer, serial, subject, key fingerprint, the
     `instance_uid` of the request and the predecessor; a CSR refused, with the
     reason;
   - revocation: a certificate revoked or lifted, and each session it ended; a
     host marked or unmarked as a Gateway; a member refused the Gateways'
     revocation list because its host is not marked as a Gateway, with that
     host;
   - bootstrap certificates: each one issued, each PKCS#12 file downloaded,
     each entry deleted;
   - operator acts: every mutating request of the REST API (`POST`, `PUT`,
     `PATCH`, `DELETE`) once it has run, with its method, path and status and
     without the operator's user name; every refused or throttled operator
     sign-in;
   - packages: a rollout, and each package outcome an Agent reports, installed
     or failed;
   - the Server's own certificates: one ending or ended
     ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
     clause 11).

2. **What an event holds.** `event`, a fixed name such as `admission.refused`;
   the peer address; the Agent's `instance_uid` where one is known; the
   presented certificate's CA role and serial where one is presented; and the
   event's own fields. A certificate appears by its CA role and serial, and an
   issued one also by its issuer and subject; a CSR appears only by its key
   fingerprint. No event holds a secret in any form: an `Authorization` value is
   never logged, not even as a hash, whether an operator presented it or an
   Agent sent it unasked. A text that a peer chose, such as a user name, a path,
   a CSR's subject or the error an Agent reports, is cut at 256 bytes on a
   character boundary, so a peer cannot write lines of any length. The time, the
   level and the order are the log's.

3. **The level says whether a peer can repeat it at will.** A log has no rate
   limit, and nothing aggregates the events.
   - `debug`: what a peer can cause as often as it likes. These are a refusal
     or a throttle of a peer that was not admitted, on the Agent plane, on the
     download route and at an operator sign-in; a message or a download over a
     host's rate; a download a host may not fetch; a member refused the
     Gateways' revocation list; an enrolment request refused, directly or
     through a Gateway, or asked again while it waits; and the admission of a
     request, a plain-HTTP poll, a download or a WebSocket upgrade not yet
     taken, which a peer can repeat every few seconds.
   - `info`: every decision taken. These are a WebSocket session started or
     ended, a new enrolment request, a request refused once per bootstrap
     certificate and window for its share of the queue (ADR-0046), an approval
     or rejection, the window, every issuance, revocation and bootstrap event,
     an operator act, a rollout and a package outcome.
   - `warn`: what an admitted host should never ask for: a CSR refused, and a
     report that claims an `instance_uid` bound to another host; and a
     certificate of the Server's that is ending.
   - `error`: a certificate of the Server's that has ended.

4. **A decision never waits for its event.** Logging cannot hold a decision
   back: no admission, issuance or operator act is refused because an event
   could not be written, and no answer is `503` or `Unavailable` for that
   reason. The Server writes its log to standard error; what keeps it, for how
   long and where, is whatever runs the Server.

5. **The Server writes nothing for the record.** `data_dir` holds no `audit/`
   directory, and the Server neither creates nor reads one. `server.toml`
   refuses an `[audit]` section as an unknown key, as it refuses every key it
   does not name. There is no `server audit-verify`.

**Out of scope:** an audit record in any store; shipping events to a remote
collector; the log's format and the filter an operator sets; an audit record on
the Client.

## Alternatives considered

- **Keep the hash-chained file under `data_dir/audit/`** — tamper evidence
  against an earlier copy, but a dependency on the filesystem the Server is to
  lose, and the one record that kept a Server on PostgreSQL bound to a disk.
  Rejected.
- **Move the record into PostgreSQL now** — keeps a record off the filesystem,
  but needs a chain per Server instance, a schema and a verification of its own,
  and nothing needs it yet. Deferred to a later decision.
- **Keep refusing a decision whose event cannot be written** — a log line
  cannot be confirmed as kept once it leaves the process, so the rule would
  guard nothing. Rejected.
- **Aggregate refusals per peer address, as the record did** — bounds what a
  flood writes, but takes state and code a log level gives for free: an
  operator who needs refusals turns `debug` on. Rejected.
- **OTLP logs to a collector** — central, but a Server without a reachable
  collector would lose its events. Out of scope; it can be added later from the
  `tracing` events.

## Sources / Prior art

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
  — which events to log, and never to log secrets.
- [The Twelve-Factor App, _Logs_](https://12factor.net/logs) — a process writes
  its events to its output stream, and the environment collects them.
- [`tracing`](https://docs.rs/tracing) — structured fields on an event.

## Consequences

- Positive: the Server needs no disk for its security decisions; with
  PostgreSQL and an object store it keeps nothing under `data_dir`.
- Positive: one mechanism instead of two — no writer thread, no channel, no
  rotation, no verification command, and no failure mode that stops admission.
- Negative / trade-offs: tamper evidence is lost. Whoever can write the log, or
  the collector behind it, can edit or remove an event unseen. Retention is
  whatever collects the log, and a Server whose output nobody collects keeps
  nothing an investigation can rely on. This is accepted for now.
- Negative / trade-offs: what a peer can repeat at will — refusals before
  admission, throttles, downloads it may not fetch, plain-HTTP polls — is hidden
  at the default level. An operator who investigates a flood turns `debug` on,
  and then the flood writes one line per refusal.
- Negative / trade-offs: a decision is taken even when its event is lost.
- Follow-ups: an audit record again, as a decision of its own, in PostgreSQL and
  never on the filesystem; shipping the events to a collector.

## Enforcement

Tests that carry `Verifies: ADR-0022`:

- `crates/fleet-server/src/config.rs`, `rejects_unknown_keys`: a `server.toml`
  with an `[audit]` section fails to parse (clause 5).
- `crates/fleet-server/src/fs/mod.rs`,
  `the_data_directory_has_one_layout_and_no_other`: opening a `data_dir`
  creates no `audit/` (clause 5).

- `crates/fleet-server/tests/no_secret_in_the_log.rs`,
  `no_secret_reaches_the_log`: the Server binary at `RUST_LOG=trace` logs no
  `Authorization` or Bearer value, no Basic password in clear or in base64, no
  bootstrap PKCS#12 password and no private key (clause 2).
- `crates/fleet-server/src/fleet.rs`,
  `a_logged_text_is_bounded_on_a_character_boundary`: a text a peer chose is cut
  at 256 bytes on a character boundary (clause 2).

**Not mechanically decidable:** that every security decision emits its event
with the level of clause 3 is review.
