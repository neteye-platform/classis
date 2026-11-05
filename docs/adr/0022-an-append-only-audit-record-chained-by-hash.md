# ADR-0022: The Server keeps an append-only audit record of every security decision, each entry chained to the one before by its hash

- **Status:** 🟢 accepted · clause 4 superseded by
  [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
- **Date:** 2026-10-06
- **Deciders:** Markus Brigl
- **Applies to:** the audit port in `crates/fleet-server/src/audit.rs`, its
  writer in `crates/fleet-server/src/audit_log.rs` and its filesystem adapter,
  every place in `crates/fleet-server/src/` that admits or refuses a peer,
  issues or revokes a certificate, takes an operator's act or records a package
  outcome, the `[audit]` section of `server.toml`, and the `audit/` directory
  under `config_dir`

## Context

The Agent plane admits by client certificate alone
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
so there is no fleet credential to offer, rotate or revoke and none for the
record to cover, and the audit-availability gate of clause 6 holds back
certificate issuance.

Every security measure of the Server decides something about a peer: admission
and its refusal
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
the throttle, an enrolment request and its approval, a certificate issued or
renewed, a revocation and the sessions it ended
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
a rollout
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md))
and a package outcome an Agent reports. Without a record of their own these
leave log lines at best, mixed with everything else, kept as long as whatever
collects the log keeps it, and changeable by whoever can write the log. None of
them is demonstrable afterwards: an investigation cannot say who was admitted
when, who approved a host, or whether a record was removed. Measure H15 of
[`HARDENING.md`](../HARDENING.md) asks for exactly one record per decision,
refusals included — the half that is easy to omit and the half an investigation
needs.

The specification puts security before convenience and holds that no
vulnerability can be ruled out (Strategy _Security before convenience_). A
record that an intruder on the Server host can quietly edit is worth little
against exactly that intruder; a record whose entries each carry the hash of the
one before at least makes an edit or a removal visible to whoever checks it
against a copy taken earlier.

Two forces bound the design. A refused admission is the cheapest thing a remote
peer can cause, so a record per refusal must not let a flood fill the disk. And
the record must not leak what it records: no secret, no key, no CSR body. The
Agent plane reads no `Authorization` header, but a Client of an older version
may still send one, and an operator signing in to the Operator plane presents a
password; neither may reach the record.

## Decision

We will append one JSON object per security decision to an owner-only audit file
under `config_dir/audit/`, each carrying the SHA-256 of the entry before it,
emit the same entry as a `tracing` event with the target `audit`, and bound the
file by size and the refusals by aggregation.

1. **One entry per decision, refusals included.** An entry is written for:
   - admission on `/v1/opamp` and on the download route: admitted, refused
     (which check refused, never the presented value), throttled. A WebSocket
     session and a download are recorded every time; a plain-HTTP poll once per
     peer address and certificate per hour, since a fleet polling every few
     seconds would otherwise crowd everything else out of the record;
   - enrolment: a request queued, approved, rejected; the window opened, or
     closed by an operator or run out, with the number of requests that expired
     with it;
   - issuance: a certificate signed on enrolment or renewal, with its CA role
     and serial, the predecessor, and the `instance_uid` of the request; a CSR
     refused, with the reason;
   - revocation: a certificate revoked or lifted, and each session it ended; a
     member refused the Gateways' revocation list because its host is not marked
     as a Gateway, with that host;
   - operator acts: every mutating route of the REST API, with the operator's
     user name and the route, once before it runs and once with its status
     after; what a revocation, an approval, a rejection or a window act did; and
     every refused or throttled operator sign-in;
   - packages: a rollout, and each package outcome an Agent reports, installed
     or failed.

2. **What an entry holds.** `seq` (a counter from 1 that never repeats), `time`
   (RFC 3339, UTC), `event` (a fixed name such as `admission.refused`),
   `outcome`, the peer address, the Agent's `instance_uid` where one is known,
   the presented certificate's CA role and serial where one is presented, the
   operator where one acted, event-specific fields, and `prev` — the SHA-256,
   hex, of the previous entry's line as written. A certificate appears only by
   role and serial, a CSR only by its key fingerprint. No entry holds a secret
   in any form: an `Authorization` value is never written, not even as a hash,
   whether an operator presented it or an Agent sent it unasked. A text field is
   cut at 256 bytes: a user name or a path can come from a peer that was not
   admitted, and must not be able to fill the record.

3. **The chain.** The first entry of a file carries the hash of the last entry
   of the file before it, or 64 zeros for the first file ever. At startup the
   Server reads the end of the newest file that holds a line, takes `seq` from
   the last whole entry, and chains on from the last line as it stands. A last
   line that is not a whole entry — a crash mid-write — is kept and closed with
   a newline, and the next entry records `audit.chain_broken`, so a truncation
   is itself on the record and `seq` never repeats. `server audit-verify <dir>`
   walks every file in order and names the first entry whose `prev` does not
   match.

4. **The file.** `config_dir/audit/audit-<first seq>.jsonl`, the directory
   `0700` and each file `0600` on Unix, under the data root's restricted ACL on
   Windows. Each entry is one line, written with a single append and synced to
   disk by one writer thread of its own, in the order the decisions were taken;
   a write that fails partway is cut back to the last whole line. A file
   reaching `[audit] max_file_bytes` (default 64 MiB) is closed and a new one
   opened; the Server keeps `[audit] keep_files` files (default 16) and deletes
   the oldest, recording `audit.rotated` with the deleted file's last hash
   first.

5. **Refusals are aggregated, never dropped.** Within one second, refusals of
   the same `event` from the same peer address — an IPv6 one by its /64, as the
   throttle counts it — after the tenth are counted rather than written, and one
   `…aggregated` entry with the count follows when the second ends. A flood of
   refusals therefore costs at most ten lines and a count per address and
   second, and every refusal is still accounted for.

6. **Writing never blocks admission on a slow disk, and never silently fails.**
   Entries go through a bounded channel of 10 000 to the writer thread, and a
   decision goes ahead once its entry is queued. When the channel is full,
   admission and every operator act are refused with `503` and no certificate is
   issued until it drains. When a write fails, the error is logged at `error`,
   and from then on nothing is admitted, no certificate is issued and no
   operator act runs until a write succeeds; the writer retries every second. A
   CSR held back for want of a record is answered `ServerErrorResponse`
   `Unavailable` with `retry_info`, since the Server, not the request, is at
   fault and the Agent asks again. Decisions that were queued when the write
   failed, or refused for want of a record, are counted, and the next entry that
   lands carries the count as `unrecorded_before`. A security decision is never
   taken without its record queued, and a record that is lost is never lost
   silently.

7. **The log carries it too.** Every entry is also emitted as a `tracing` event
   with the target `audit`, the same fields, at `info`, so a log collector
   receives it without reading the file. The file is the record; the log is a
   copy.

**Out of scope:** an audit record on the Client; shipping the record to a remote
store or signing entries with a key; a REST route to read the record; retention
by age.

## Alternatives considered

- **Only the normal log, under a target of its own** — retention and integrity
  would depend on whatever collects the log, and a host without a collector
  keeps nothing an investigation can rely on.
- **OTLP logs to a collector** — central, but a Server without a reachable
  collector loses exactly the record an outage investigation needs; it can be
  added later from the `tracing` copy.
- **Entries without a chain** — simpler, but an edit or a removal is invisible.
- **Signing each entry with a key** — proves more than a chain, but the key
  would live on the same host as the record, so an intruder who can rewrite the
  file can re-sign it; a chain checked against an earlier copy gives most of the
  value without key management.
- **Dropping refusals under load** — cheaper, but an attack is exactly when
  refusals matter; aggregation keeps the count.
- **An audit record on the Client as well** — a second format to maintain; the
  Client reports its package outcomes to the Server, which records them.

## Sources / Prior art

- [`HARDENING.md`](../HARDENING.md), measure H15 and the observable it names.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
  — which events to record, and never to record secrets.
- [JSON Lines](https://jsonlines.org/);
  [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339).
- Hash-chained logs as in [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)
  (Certificate Transparency), in their simplest linear form.

## Consequences

- Positive: an incident becomes an investigation: who was admitted, refused,
  enrolled, approved, issued, revoked and rolled out to, when and by whom, with
  an edit or a removal visible against an earlier copy.
- Negative / trade-offs: a write per decision on the admission path; a disk that
  stops writing stops admission and issuance (clause 6), which is the intended
  order of failure. The record grows with the fleet's traffic and is bounded by
  size, so a large fleet keeps less time than a small one. A record written
  before this decision may still hold `rotation.offered` entries and credential
  hashes cut to eight hex digits; they stay in the chain as written.
- Follow-ups: shipping the record off the host; reading it through the REST API;
  an audit record of the Client's own decisions.

## Enforcement

- `crates/fleet-server/src/audit_log.rs` tests:
  `each_entry_carries_the_hash_of_the_one_before`,
  `the_chain_survives_a_restart_and_a_rotation`,
  `a_truncated_file_is_recorded_as_a_broken_chain`,
  `refusals_beyond_ten_a_second_are_aggregated_with_their_count` (clauses 2, 3,
  5), `a_write_that_fails_refuses_until_one_succeeds` (clause 6).
- `crates/fleet-server/src/fs/audit.rs` test:
  `the_record_is_owner_only_and_continues_where_it_ended` (clauses 3, 4).
- `crates/fleet-server/tests/mutual_tls.rs` tests:
  `an_admission_and_its_refusal_each_leave_one_entry`, which refuses a revoked
  certificate, `an_issued_certificate_is_recorded_with_its_predecessor`,
  `a_revocation_records_the_sessions_it_ended`,
  `an_operator_act_names_the_operator`,
  `an_audit_that_cannot_write_refuses_admission` (clauses 1, 6). That no entry
  holds the operator's password is asserted by
  `an_operator_act_names_the_operator`.
- `crates/fleet-server/tests/mutual_tls.rs`:
  `an_authorization_an_older_client_sends_is_never_written` — an Agent admitted
  on its certificate while sending an `Authorization` header leaves an admission
  entry that holds neither the value nor any hash of it (clause 2);
  `an_audit_that_cannot_write_issues_no_certificate` — with the record
  unavailable, a CSR on a member connection gets no certificate and is answered
  `Unavailable` with `retry_info` (clause 6);
  `an_unmarked_member_asking_for_the_list_leaves_a_refusal` (clause 1).
- `crates/fleet-server/src/fleet.rs` —
  `unavailable_tells_the_agent_when_to_retry` (clause 6).
