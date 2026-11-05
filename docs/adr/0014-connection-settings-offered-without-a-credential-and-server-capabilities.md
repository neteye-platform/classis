# ADR-0014: The Server offers connection settings in the Baseline's classes under one hash, no credential and a plaintext endpoint only on the loopback, the Client proves over TLS 1.3 only what it can, applies no offered header and acknowledges the whole offer, and a Server's capabilities bind what the Client reports

- **Status:** 🟢 accepted · clauses 1, 5 and 9 superseded by
  [ADR-0040](0040-a-connection-settings-offer-never-moves-the-client-to-plaintext.md)
- **Date:** 2026-10-06
- **Deciders:** Markus Brigl
- **Applies to:** the `[connection_offer]` section of `server.toml`, the offer
  composition and capability declaration in `crates/fleet-server/src/fleet.rs`,
  the Client's offer handling in `crates/fleet-agent/src/connection.rs`,
  `crates/fleet-agent/src/transport/mod.rs` and
  `crates/fleet-agent/src/engine.rs`, its persisted `connection-settings.pb`,
  and every gate on a Server capability in
  `crates/fleet-agent/src/supervisor/agent.rs`

## Context

The Agent plane admits by client certificate alone
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
as the [specification](../SPECIFICATION.md) asks. There is no fleet credential
for the Server to offer or for the Client to send: `[connection_offer]` carries
no credential, and an offered header on the OpAMP connection has nothing on the
Server that reads it.

The specification puts security before convenience (Strategy "Security before
convenience", Q-1 "Secure by default"): an offered endpoint is a connection that
leaves the host, so it is TLS 1.3 unless it stays on the loopback. And a Server
could move the fleet to any host a public CA certified, since a Client without
its own CA file trusts the public roots (measure H24 of
[`HARDENING.md`](../HARDENING.md)).

An endpoint, a heartbeat interval or a client certificate that could only be
changed by editing every host's configuration file would bring back the
fleet-wide chore this project exists to remove. The Baseline's answer is
connection settings management. `ConnectionSettingsOffers` carries an
`OpAMPConnectionSettings` (endpoint, headers _"typically used to set access
tokens"_, heartbeat interval, certificate, `tls`, `proxy`), the three
own-telemetry destinations, and `other_connections`, under one `hash` described
as _"Hash of all settings"_. `ConnectionSettingsStatus` reports the last hash
with `APPLYING`/`APPLIED`/`FAILED`, and _"if the hashes are different the Server
MUST include the connection_settings field in the response"_.

The Baseline names _"3 classes of destinations"_ — the OpAMP Server, own
telemetry, and "other" — and says _"Depending on which connection settings are
offered the sequence of operations is slightly different."_ Its verification
MUST sits under `ConnectionSettingsOffers.opamp` and is justified by its scope:
_"The Client MUST verify the offered connection settings by actually connecting
before accepting the setting to ensure it does not lose access to the OpAMP
Server"_. The own-telemetry sequence has no verification step and no reconnect;
it asks that the Server send destinations in its first reply _"unless there is
no OTLP backend that can be used"_, whether or not it has OpAMP settings to
offer, and that the Agent set `connection_settings_status` when new settings are
received.

The heartbeat interval belongs to the same message: for an Agent with
`ReportsHeartbeat` the Server MAY set `heartbeat_interval_seconds`, the Agent
MUST use it, and a plain-HTTP Client MUST use it as its polling interval.
`ConnectionSettingsStatus`, `ReportsConnectionSettingsStatus` and
`heartbeat_interval_seconds` are Development maturity — the same deliberate risk
acceptance taken for `ReportsHeartbeat`.

Capability negotiation is symmetrical: _"after the Agent learns about the
capabilities of the Server the Agent MUST stop using the capabilities that the
Server does not support."_ With `opamp-go` as the behavioural oracle
([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md)),
a third-party Server may implement only the required bits, and this Client has
to notice. Applied literally, field by field, the rule deadlocks: a Server that
sends an offer without declaring `OffersConnectionSettings` and receives no
acknowledgement re-offers forever. And one plausible gate —
`remote_config_status` behind `OffersRemoteConfig` — would be actively harmful.
What needs deciding is the rule that produces the gates, including when not to
gate.

## Decision

We will offer connection settings from `server.toml` as one hash-gated message
in the Baseline's three classes, have the Client verify by connecting only the
OpAMP half, apply the rest in place, persist what it applied and acknowledge the
whole message once, and make the Client's use of Server capabilities a stated
rule: optimistic until the Server speaks, outranked by what the Server actually
sends, and pessimistic only where a message would be an error.

1. **The Server's standing offer is `[connection_offer]`, and it carries no
   credential.** It names any of: an optional `heartbeat_interval_secs`, and an
   optional `endpoint` (e.g. for a Server move). The `endpoint` is `wss://` or
   `https://`; `ws://` or `http://` only when its host is a loopback IP literal
   — `127.0.0.1` or `::1`, never a host name, `localhost` included. An
   `endpoint` that breaks this is refused at startup with a message naming
   `[connection_offer] endpoint`, never warned about, so the Server never offers
   a fleet a plaintext path off the host. An empty section fails at startup. A
   credential key — `bearer_token_file`, `username`, `password_file`, or the
   inline `bearer_token` or `password` — is refused at startup with a message
   naming the key: the Agent plane admits by client certificate alone
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
   so an offered credential would be one nothing reads. The OpAMP settings the
   Server offers carry no `headers`.

2. **One message, one SHA-256 hash, offered on mismatch.** The Server composes
   the OpAMP settings and the own-telemetry destinations into one
   `ConnectionSettingsOffers`, hashes the whole message, and includes it
   whenever an Agent's reported `last_connection_settings_hash` differs. The
   OpAMP half goes only to Agents declaring `AcceptsOpAMPConnectionSettings`;
   each telemetry destination only to an Agent declaring the matching signal
   ([ADR-0016](0016-what-an-agent-reports-about-itself.md)). With only telemetry
   to offer, that is the whole offer, with no `opamp` block. A certificate
   issued in answer to a CSR
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
   clause 9) travels as the standing OpAMP settings plus that certificate, under
   a hash of its own.

3. **The Server declares `OffersConnectionSettings` whenever it can offer
   anything** — a `[connection_offer]`, a `[telemetry_offer]`, or a
   `[client_ca]` whose issued certificate travels as an offer. An undeclared
   capability is never exercised, a declared one never hollow.

4. **An offer is actionable when it carries anything this Client can put in
   force** — OpAMP settings, or any of `own_metrics`, `own_traces`, `own_logs`.
   An offer carrying only `other_connections` is not actionable while
   `AcceptsOtherConnectionSettings` is undeclared: acknowledging what cannot be
   applied is a false report, and a conforming Server does not send it. When
   `other_connections` is implemented it joins the telemetry class of clause 6 —
   no verification by connecting, no reconnect, one acknowledgement.

5. **The OpAMP half is verified by actually connecting, then persisted, then
   reconnected with.** On receipt the Client reports `APPLYING`, then checks the
   candidate's endpoint by clause 1's rule: a `ws://` or `http://` endpoint
   whose host is not a loopback IP literal is refused without connecting, and
   the offer is reported `FAILED` with an `error_message` naming the endpoint
   and the reason. A candidate that moves to another `wss://` or `https://`
   endpoint is refused the same way unless `[tls] ca_file` is set, and is then
   verified against that CA alone: under the public roots, a Server could move
   the fleet to any host a public CA ever certified, and the move would outlive
   the operator's file (clause 9). Otherwise it connects with the candidate —
   offered fields, falling back to those in force, an offered certificate
   included, offered `headers` never (clause 8) — over TLS 1.3, presenting the
   client certificate in force unless the offer carries one, and sending no
   `Authorization`; only a candidate on the loopback connects in plaintext. A
   WebSocket candidate must complete its handshake, a plain-HTTP candidate a
   real exchange. Only then are the settings persisted, an issued certificate
   stored, and the connection dropped so the runtime reconnects with them,
   possibly on the other transport. A refused or failed verification keeps
   everything in force as it was and reports `FAILED` with the error.

6. **A telemetry destination is not verified by connecting, and does not restart
   the connection.** Reachability of an OTLP receiver is not this Client's to
   establish at offer time; a receiver that is down is not an offer that is
   wrong. What is checked before it is put in force is what the Client can
   decide alone — the cleartext rule and the unhonoured fields of
   [ADR-0016](0016-what-an-agent-reports-about-itself.md) — and a refusal is
   reported, not swallowed. A telemetry-only offer is applied in place; its
   acknowledgement rides the reports already owed, and the transport loop
   carries on. The headers of a telemetry destination are an OTLP receiver's,
   not admission: they stay as
   [ADR-0016](0016-what-an-agent-reports-about-itself.md) has them, still
   offered only on member connections
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
   and clause 8 does not reach them.

7. **One offer, one acknowledgement.** A single `connection_settings_status`
   answers each offer, and its `error_message` names everything dropped or
   refused across both halves. If the OpAMP half fails verification, nothing
   from that offer is persisted or applied, the telemetry half included, and the
   offer is reported `FAILED`. Half-applying an offer whose other half was
   rejected would leave the Server unable to tell what is running.

8. **`tls`, `proxy` and `headers` are not honoured, and the acknowledgement says
   so.** An offer is applied for every field the Client honours — endpoint,
   heartbeat, certificate — and then reported `FAILED` with an `error_message`
   naming the dropped fields, offered `headers` by their keys and never their
   values. The hash is echoed either way, so the Server does not re-offer in a
   loop. `TLSConnectionSettings` is refused on merit: a Server able to command
   `insecure_skip_verify` could switch off the check that proves it is the
   Server, and trust is an operator's file
   ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
   clause 5). `ProxyConnectionSettings` has nothing on this Client to configure.
   Both are Development upstream. Offered `headers` on the OpAMP connection are
   refused on merit too: the Agent plane reads no `Authorization` and admits by
   client certificate alone
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
   so an applied header would be a value the Server plants on every connection
   of the fleet, persisted and sent upstream with no reader on this Server, and
   carried to whatever endpoint a later offer moves the fleet to.
   [`CONFORMANCE.md`](../CONFORMANCE.md) records the three refusals.

9. **What is in force is persisted as `connection-settings.pb`, and it outranks
   `supervisor.toml`.** The file in `state_dir` is the Baseline's own
   `ConnectionSettingsOffers`: the merged settings in force plus the hash that
   reports them `APPLIED`, written owner-only. OpAMP fields fold — an offer that
   omits a field leaves the one in force — and the file carries an `opamp` block
   only when an offer or the state it folds into had one. How the telemetry
   destinations fold is
   [ADR-0016](0016-what-an-agent-reports-about-itself.md)'s. At startup the
   persisted settings override `supervisor.toml`'s `endpoint` and heartbeat and
   poll intervals, and the persisted hash restores the status to report. The
   persisted OpAMP settings carry no `headers`: an `Authorization` header that a
   file holds from an earlier rotation is dropped on load and never sent.
   `supervisor.toml` stays what the operator wrote; deleting the file reverts to
   it.

10. **An offered heartbeat replaces the configured interval.** A non-zero
    `heartbeat_interval_seconds` becomes the heartbeat period on WebSocket and
    the polling interval on plain HTTP. The Server judges staleness by the
    heartbeat it offered ([ADR-0024](0024-the-fleet-record.md)).

11. **Settings are connection-scoped; offers are per Agent.** Over one
    connection carrying n Agents
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)),
    the Server offers to each, and the Client keeps one pending offer, verifies
    and switches once per hash, and reports status for every Agent it carries.

12. **The Client is optimistic until the Server has spoken, and bound once it
    has.** Until a `ServerToAgent` with a non-zero `capabilities` field has been
    seen, every report rides; from then on the Server's declaration governs. A
    later `capabilities` of zero is the Baseline's "MAY be omitted", not a
    retraction, so the last non-zero declaration stands.

13. **A received offer outranks the bitmask for the report that answers it.** A
    received `connection_settings` latches the connection-settings status on for
    the life of the Agent, whatever `OffersConnectionSettings` says and even
    when the offer was one this Client could not act on. The alternative is a
    Server that offers and never learns, and therefore never stops.

14. **Reports are gated where the Server's bit governs the report itself.**
    Effective configuration is withheld from a Server that declared capabilities
    without `AcceptsEffectiveConfig`, `package_statuses` from one without
    `AcceptsPackagesStatus`, and `connection_settings_status` from one without
    `OffersConnectionSettings`, subject to clause 13. A withheld report is not
    queued: the dirty flag clears as usual, and the state returns in the full
    snapshot after any reconnect or `ReportFullState`, so a late-declared bit
    never receives a stale status.

15. **Sending is gated pessimistically only where the message would be an
    error.** A CSR is withheld until the Server has declared
    `AcceptsConnectionSettingsRequest`, because a Server that does not sign
    answers it `BadRequest`. This is the one exception to clause 12, and its
    test is narrow: the message would be rejected, not merely unused.

16. **`remote_config_status` is never gated.** `OffersRemoteConfig` says what
    the Server sends; what licenses an inbound status is `AcceptsStatus`, which
    every Server MUST set, and there is no `AcceptsRemoteConfigStatus`. The hash
    is the only input to the Server's re-offer decision, so gating it would put
    the fleet in a re-offer loop the moment a Server stopped declaring the bit;
    and against a Server that never offers a configuration the status is already
    absent, so the gate would do nothing where it was meant to help. The reasons
    are recorded here, at the code, and in
    [`CONFORMANCE.md`](../CONFORMANCE.md).

17. **An undeclared capability is not exercised on the Client's end either.** A
    new capability is gated under clause 14 or 15; a decision not to gate one is
    recorded in `CONFORMANCE.md` with its reason, as clause 16 is.

**Out of scope:** how the Agent plane admits and how it treats a Client of an
older version that still sends `Authorization`
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md));
the audit entries an offer leaves; `AcceptsOtherConnectionSettings`; what own
telemetry is and how its destinations and their headers fold
([ADR-0016](0016-what-an-agent-reports-about-itself.md));
`connection_settings_status` in the fleet view and the REST API; an audit of the
Server's own use of Agent capabilities under the same rule.

## Alternatives considered

- **Keeping an optional offered credential** — the Agent plane reads none
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md));
  an offered credential would be a secret the Server keeps, sends and the fleet
  persists, for no check anywhere.
- **Honouring offered `headers` other than `Authorization`** — no header has a
  reader on this Server, and a generic pass-through would let a Server, or
  whoever can make one send an offer, attach any value to every upstream
  connection of the fleet and keep it there across restarts.
- **Dropping offered `headers` silently and reporting `APPLIED`** — a false
  report; `CONFORMANCE.md` records gaps, not false reports, and a Server
  rotating a token through headers would believe it in force.
- **Refusing an offer wholesale when it carries `headers`** — an older Server
  that still offers a credential would freeze the endpoint, heartbeat and
  certificate the same offer carries.
- **Accepting any scheme the Server offers** — the Client would follow a Server,
  or whoever can make one send an offer, onto a plaintext endpoint off the host
  and hand it the fleet's reports in the clear; Q-1 forbids that whatever the
  configuration, so both ends refuse it.
- **Offering blind, without `ReportsConnectionSettingsStatus`** — the Server
  could never stop re-offering, and rejection would be invisible.
- **Hot reload instead of a Server restart to change the standing offer** — a
  feature this Server does not have; a restart is how `server.toml` changes take
  effect.
- **Every offer always carries an `opamp` block** — the Server would synthesise
  a block it has nothing to put in, every telemetry change would
  verify-and-reconnect the whole fleet, and it contradicts the Baseline's three
  classes and its first-reply SHOULD.
- **Requiring `[connection_offer]` beside `[telemetry_offer]` and documenting
  the gap** — an operator would have to configure an endpoint or heartbeat offer
  to get metrics, a coupling with no reason.
- **A hash and an acknowledgement per class** — the Baseline defines one hash
  over all settings and one status field; splitting them would invent protocol
  semantics.
- **Verifying a telemetry destination by connecting, for symmetry** — a
  momentarily down receiver would turn a correct offer `FAILED` and the Server
  would re-offer settings that were never wrong.
- **Refusing an offer wholesale when it carries `tls` or `proxy`** — an
  unsupported extra would freeze the endpoint move and certificate the same
  offer carries.
- **Honouring `TLSConnectionSettings`** — most of what it can say weakens
  verification.
- **Keeping `APPLIED` for a partly honoured offer and documenting it** —
  `CONFORMANCE.md` records gaps, not false reports; a declared capability is a
  promise a peer relies on.
- **Gating every report on its corresponding bit, no exceptions** — deadlocks
  the acknowledgement against Servers that offer without declaring, and breaks
  `remote_config_status`.
- **Gating nothing, relying on the Server to ignore what it does not want** —
  defensible on the wire, but the Baseline states a MUST and third-party Servers
  are a target.
- **A mechanical bit-to-field table** — the mapping is not one-to-one in either
  direction, so the table would carry exceptions; revisit if the gated fields
  multiply.

## Sources / Prior art

- [OpAMP specification — Connection Settings Management](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md#connection-settings-management)
  (Baseline `v0.20.0`) — the three classes and per-class sequences, the
  verification MUST under `ConnectionSettingsOffers.opamp`, the own-telemetry
  sequence and its first-reply SHOULD, the hash gate MUST, the heartbeat
  obligations, and `OpAMPConnectionSettings.headers` as the field _"typically
  used to set access tokens"_; _Interoperability of Partial Implementations_ for
  the symmetrical capability MUST; `ServerToAgent.capabilities` (_"MAY be
  omitted in subsequent ServerToAgent messages"_); and the `ServerCapabilities`
  comments distinguishing `OffersRemoteConfig` from `AcceptsStatus`.
- [`opamp-go` client callbacks](https://pkg.go.dev/github.com/open-telemetry/opamp-go/client/types)
  — `OnOpampConnectionSettings` hands the offer to the Agent, which accepts
  after its own verification; the library then reconnects.
- [OpAMP Supervisor specification](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/specification/README.md)
  — persists Server-offered connection settings across restarts.
- [`opampextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/opampextension)
  — declares a small subset of capabilities and none of the connection-settings
  ones, the reason a peer's declaration cannot be assumed generous and why this
  behaviour was read from the specification rather than checked against it.

## Consequences

- Positive: the Server can retune every Agent's heartbeat and polling cadence
  and move the fleet to a new endpoint without touching a host, and an issued
  client certificate reaches its Agent the same way. No secret sits in
  `[connection_offer]`, in a file beside it, or in a Client's state directory.
- Positive: a Server with only `[telemetry_offer]` reaches its Agents, and a
  telemetry endpoint move never disconnects the fleet.
- Positive: a conforming but terse Server is safe to talk to; the next
  capability has a stated rule and worked examples of each branch.
- Negative / trade-offs: two lifecycles where "every offer is proved by
  connecting" would be one; the seam is the Baseline's own and is named in one
  predicate.
- Negative / trade-offs: a refused telemetry destination fails an offer whose
  OpAMP half applied fine; the `error_message` says what was dropped, but a
  Server reading only the enum sees a failure. Accepted as the price of one
  hash.
- Negative / trade-offs: a Server that offers a credential in `headers` — one of
  an older version, or a third-party Server — receives `FAILED` for every such
  offer, though the endpoint, heartbeat and certificate it carried are in force.
  The `error_message` names the headers, and the echoed hash stops the re-offer.
- Negative / trade-offs: the persisted settings are a state file an operator
  must know about; several surfaces are Development maturity upstream.
- Negative / trade-offs: clause 13 means a Server that sent one offer receives
  connection-settings status for that Agent's life; a withheld report is lost
  until the next full snapshot; clause 16 is a documented departure from a
  literal field-by-field reading that every review has to be argued out of.
- Follow-ups: `connection_settings_status` in the fleet view and the REST API,
  so a stalled endpoint move is visible; the Server's use of Agent capabilities
  under the same rule.

## Enforcement

The tests below verify the clauses that stand unchanged.

- [`crates/fleet-server/src/config.rs`](../../crates/fleet-server/src/config.rs)
  — `a_connection_offer_needs_at_least_one_field`,
  `a_connection_offer_rejects_a_bad_endpoint_scheme`,
  `a_connection_offer_refuses_a_plaintext_endpoint_off_loopback_naming_the_setting`,
  `a_connection_offer_accepts_a_plaintext_endpoint_on_a_loopback_ip_literal`,
  `a_connection_offer_refuses_a_plaintext_endpoint_on_localhost` (clause 1).
- [`crates/fleet-server/tests/connection_settings.rs`](../../crates/fleet-server/tests/connection_settings.rs)
  — `no_offer_without_the_capability_or_without_a_configured_section`,
  `the_reported_hash_gates_reoffering` (clause 2).
- [`crates/fleet-server/tests/own_telemetry.rs`](../../crates/fleet-server/tests/own_telemetry.rs)
  — `a_telemetry_only_server_declares_that_it_offers_connection_settings`
  (clauses 2, 3).
- [`crates/fleet-agent/src/connection.rs`](../../crates/fleet-agent/src/connection.rs)
  — `verify_refuses_a_plaintext_endpoint_off_loopback_without_connecting`,
  `verify_refuses_a_plaintext_endpoint_on_a_host_name`,
  `verify_presents_the_client_certificate_in_force`,
  `an_offered_move_needs_the_clients_own_ca` (clause 5);
  `offered_tls_and_proxy_are_neither_stored_nor_claimed` (clause 8);
  `merge_leaves_opamp_absent_when_neither_side_has_one`,
  `merge_of_a_telemetry_only_offer_carries_the_opamp_settings_in_force_forward`,
  `merge_keeps_unchanged_fields_from_the_previous_settings`,
  `load_store_round_trips`,
  `stored_settings_and_their_directory_are_owner_only`,
  `apply_overrides_client_toml_where_the_server_spoke`,
  `apply_leaves_untouched_what_the_offer_omits` (clauses 9, 10). The fold and
  apply tests carry endpoint, heartbeat and certificate in their fixtures.
- [`crates/fleet-agent/tests/connection_settings_e2e.rs`](../../crates/fleet-agent/tests/connection_settings_e2e.rs)
  — `an_offer_is_verified_persisted_and_reported_applied`;
  [`crates/fleet-agent/tests/gateway_and_supervisor_e2e.rs`](../../crates/fleet-agent/tests/gateway_and_supervisor_e2e.rs)
  — `a_verified_offer_restarts_the_gateway_and_leaves_the_supervisors_running`
  (clauses 5, 11).
- [`crates/fleet-agent/src/supervisor/agent.rs`](../../crates/fleet-agent/src/supervisor/agent.rs)
  — `an_offer_carries_settings_when_it_names_anything_this_client_applies`
  (clause 4);
  `a_connection_offer_is_acknowledged_applying_and_handed_to_the_transport`,
  `a_failed_offer_still_reports_the_hash_so_the_server_stops_reoffering`,
  `an_offer_is_applied_and_acknowledged` (clauses 5, 7, 8);
  `package_statuses_ride_until_the_server_has_spoken`,
  `package_statuses_stop_once_the_server_says_it_accepts_none`,
  `effective_config_respects_the_servers_capability_set` (clauses 12, 14);
  `a_connection_settings_status_is_reported_to_a_server_that_offered_without_declaring_the_bit`,
  `a_restored_connection_settings_status_is_withheld_from_a_server_that_never_offers`
  (clauses 13, 14);
  `a_remote_config_status_rides_to_a_server_that_offers_no_remote_config`
  (clause 16).
- [`crates/fleet-server/tests/mutual_tls.rs`](../../crates/fleet-server/tests/mutual_tls.rs)
  — `a_csr_to_a_server_that_signs_nothing_is_a_bad_request`, the error clause 15
  keeps a Client from provoking.
- [`crates/fleet-server/src/fleet.rs`](../../crates/fleet-server/src/fleet.rs) —
  `an_offered_heartbeat_interval_sets_the_budget` (clause 10).
- TLS 1.3 is the provider's: `the_provider_offers_tls_1_3_suites_alone` in
  [`crates/opamp/src/tls.rs`](../../crates/opamp/src/tls.rs) (clause 5).

These tests carry `Verifies: ADR-0014`:

- [`crates/fleet-server/src/config.rs`](../../crates/fleet-server/src/config.rs)
  — `a_connection_offer_refuses_a_credential_key_naming_it`, for each of
  `bearer_token_file`, `username`, `password_file`, `bearer_token` and
  `password` (clause 1).
- [`crates/fleet-server/tests/connection_settings.rs`](../../crates/fleet-server/tests/connection_settings.rs)
  — `the_offer_reaches_a_capable_agent_and_carries_no_headers` (clauses 1, 2,
  3).
- [`crates/fleet-agent/src/connection.rs`](../../crates/fleet-agent/src/connection.rs)
  — `offered_headers_are_neither_stored_nor_claimed`, which also checks that the
  `error_message` names the header keys and no value (clause 8);
  `verify_sends_no_authorization_even_when_one_is_offered` (clauses 5, 8);
  `a_persisted_authorization_header_is_dropped_on_load` (clause 9).

**Not mechanically decidable:** clause 6's "no reconnect" for a telemetry-only
offer is held by the `OfferOutcome::Applied` path in
[`transport/mod.rs`](../../crates/fleet-agent/src/transport/mod.rs) and review;
clause 17 governs capabilities not yet added, which only review of each new gate
can hold.
