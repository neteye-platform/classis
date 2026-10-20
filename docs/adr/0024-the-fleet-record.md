# ADR-0024: The Server keeps a persisted record per Agent, derives its status, forgets it only on request, and labels it

- **Status:** 🟢 accepted · clauses 17, 18, 19 and 20 superseded by [ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md) · clause 3 superseded by [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md) · clause 11 superseded by [ADR-0047](0047-a-host-and-its-bindings-end-with-its-last-valid-certificate.md)
- **Date:** 2026-08-11
- **Deciders:** Markus Brigl
- **Applies to:** crates/fleet-server/src/fleet.rs, crates/fleet-server/src/agent_store.rs, crates/fleet-server/src/labels.rs, the /api/v1/agents routes, stale_after_secs in server.toml, the agents/ and labels/ directories under config_dir

## Context

The Server holds one record per Agent: what it last reported, the hashes that keep the Server from
re-offering what already runs (`sequence_num`, remote-config, connection-settings, and package
statuses — success criterion 3), and what an operator queued or decided for it. Four questions
shape that record.

**What survives a restart.** A fleet held only in memory starts empty after every restart: an
Agent that is not reporting at that moment — a laptop that is off, a host under investigation
precisely because it went quiet — vanishes, and every other Agent is demanded `ReportFullState` at
once. The requirement is that the Server's state survives a restart with only each Agent's status
determined dynamically, and that the storage be **replaceable**: filesystem by default, a database
or external store pluggable without touching the rest. The record's access pattern is narrow —
loaded whole at startup, then single-Agent writes and deletions — and its report-derived fields
are prost-generated protobuf messages without serde. Write frequency is the known scale trap:
Elastic Fleet persists every check-in and documents the load as a problem.

**What the Server knows about liveness.** `connected` is a fact about a connection, and behind a
Gateway it is the Gateway's. A plain-HTTP Agent has no socket to close. Silence means something
only from an Agent that promised to report periodically, which is what `ReportsHeartbeat` is.

**What "forget" can mean.** A credential here is fleet-wide and identifies membership, never an
Agent ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)); nothing the Server holds can stop one
Agent from connecting again. And a re-offered configuration is not free: the Collector plugin
restarts its Managed Process when a configuration arrives, so dropping the gates of a live Agent
bounces its process.

**Where rollout rings live.** A staged rollout wants an attribute an operator invents —
`rollout = "canary"`. On the host, moving between rings is a file edit plus a restart per host,
exactly the per-host wiring the project exists to remove. But reported attributes are load-bearing:
`os.type`, `host.arch`, and `service.name` decide which artifact fits a machine, and anything that
could rewrite them could hand a Windows binary to a Linux host.

## Decision

We will persist each Agent's record behind a storage port with a filesystem adapter by default,
keep connectedness runtime-only and derive staleness on read, let an operator forget an Agent that
has stopped reporting without reaching its host, and let the Server attach labels that join what
Selectors match but never restate what an Agent reports.

1. **One record per Agent, keyed by Instance UID.** It holds what the Agent last reported
   (`sequence_num`, capabilities, description, health, effective configuration, remote-config,
   connection-settings, and package statuses, available components), the transport of the last
   report, `last_seen_ms`, a queued restart (`restart_pending`), the assignments rollout acts
   wrote ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)), a mirror of its labels, and
   the runtime facts `connected` and the owning connection. `GET /api/v1/agents` returns every
   record as an `AgentView`.

2. **Records persist behind a port.** The trait `AgentStore: Send + Sync` is the only thing the
   fleet logic knows about persistence, and its surface is the access pattern:
   - `load()` — every record, once, at startup;
   - `put(uid, &PersistedAgent)` — create or replace one record;
   - `remove(uid)` — forget one record; removing what is absent is not an error;
   - `rekey(old, new, &PersistedAgent)` — an identity reassignment, one operation so an adapter
     with atomic rename or transactions can make it one step.

   The port speaks the **typed** record (`PersistedAgent`: scalars plus the prost message types),
   never an encoding. `AppState` takes a `Box<dyn AgentStore>`; the binary wires the default, and
   another backend is a new adapter plus one wiring line.

3. **The default adapter is one JSON file per Agent, `<config_dir>/agents/<instance_uid>.json`.**
   The directory is created owner-only; writes go through a temp file and an atomic rename; every
   file is loaded at startup, and a file that does not parse fails startup naming it. The envelope
   is this adapter's format: scalars and the effective-configuration text are readable JSON, the
   wire-typed fields are protobuf bytes in base64 — the encoding whose compatibility rules the
   Baseline already governs, so a field upstream adds round-trips unread. The envelope carries a
   `version`, and one this Server does not write fails the load rather than being guessed at.

4. **What a report or an operator decided persists; what a connection knows does not.** Persisted:
   `sequence_num`, `capabilities`, `description`, `health`, `effective_config`,
   `remote_config_status`, `connection_settings_status`, `package_statuses`,
   `available_components`, `transport` (informational), `last_seen_ms`, `restart_pending`, and the
   assignments. Not persisted: `connected` and the owning connection. Labels are not duplicated
   into the record; their own store is the single authority and fills the mirror on restore.

5. **The write discipline lives above the port, so no backend can get it wrong.** The fleet keeps
   a digest of each record's durable content as last written and calls `put` only when it changed.
   `last_seen_ms` and `sequence_num` are outside the digest and ride along with whatever write
   happens, so a heartbeat, which changes nothing else, reaches no adapter. On graceful shutdown
   every record is flushed, so an ordinary restart restores current values; after a crash a
   record's last-seen dates from its last durable change. A failed write is logged, never fatal.

6. **Stored records are secret-bearing, whatever the backend.** A reported effective
   configuration carries whatever the Managed Process runs, credentials included, and package
   statuses may carry download headers. The filesystem adapter answers with an owner-only
   directory; any other adapter must answer with its own access control.

7. **`connected` says a connection carrying the Agent is open — nothing more.** Every report sets
   it; only the owning WebSocket closing, or the Agent's `agent_disconnect`, clears it. Behind a
   Gateway it is the Gateway's connection; an Agent that stops polling plain HTTP without saying
   goodbye stays connected. A restored record is disconnected with no owning connection until
   live evidence says otherwise.

8. **`stale` is derived on read, and only an Agent that promised a heartbeat can be stale.** An
   Agent is stale when `now - last_seen_ms` exceeds its budget **and** it declares
   `ReportsHeartbeat`; an Agent that never promised to report periodically is never stale. Nothing
   is stored and no timer runs. `AgentView` carries `stale` beside `connected`, never in place of
   it: `connected: true, stale: true` is precisely the gatewayed Agent that stopped talking.

9. **The budget is three heartbeat intervals.** When the Server offers a heartbeat interval
   (`[connection_offer] heartbeat_interval_secs`, [ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)),
   the budget is three times it; otherwise `stale_after_secs` in `server.toml`, default **90** —
   three times the Baseline's default heartbeat of 30 seconds — and never zero. One missed
   heartbeat is a lost packet; a view that flickers on every hiccup is one nobody trusts.

10. **Staleness changes nothing about how the Server treats an Agent.** A stale Agent keeps its
    configuration, its package state, and its identity, is offered what it always would be, and
    its next report clears the flag. It is an observation, not a state transition.

11. **Forgetting drops what the Server knows and reaches no host.**
    `DELETE /api/v1/agents/{instance_uid}` removes the record from the fleet and from the store.
    No process is stopped, no configuration withdrawn, no package removed, no credential revoked.
    The word in the API description, the UI, and the manual is **forget**, never *delete*,
    *remove*, or *unenrol*. An Agent still running comes back as a stranger: the Server demands
    `ReportFullState`, as for any unknown Agent, and the row returns complete — re-offered its
    configuration, connection settings, and packages.

12. **Only an Agent that is not reporting may be forgotten.** The act succeeds when the record is
    **not connected**, or has been **silent for longer than the staleness budget**, and is refused
    otherwise, because forgetting a live managed Agent restarts its Managed Process — an operator
    who wants that has `POST /api/v1/agents/{instance_uid}/restart`. Silence here is the plain fact,
    **without** the `ReportsHeartbeat` gate of clause 8: with it, a polling Agent that declares no
    heartbeat could never be forgotten at all.

13. **The outcomes are `204`, `409`, `404`, `400`.** `204` when the record is gone; `409` when the
    Agent is still reporting, with the reason; `404` when no such Agent is known, as the restart
    route answers; `400` when the Instance UID does not parse.

14. **Nothing expires on its own.** No retention timer, no inactivity sweep, no ephemeral marking:
    forgetting is one explicit act on one Agent. An automatic policy needs a duration, a scope, and
    an answer for the Agent that is merely on holiday — a decision of its own.

15. **The stored record follows the identity.** Forgetting removes it (clause 11); when the Server
    reassigns an identity (`RequestInstanceUid`, or the duplicate-UID rekey), the record moves
    through `rekey`. Forgetting that left a stored record behind would be a remembering under
    another name.

16. **`PUT /api/v1/agents/{instance_uid}/labels` sets an Agent's labels, whole.** Body
    `{"labels": {…}}`, string to string, replacing what was there; an empty map clears them. An
    empty key or value is refused (`400`), an unknown Agent `404`, and the answer is the Agent's
    view. Whole-map replacement keeps the write idempotent and lets an operator see the resulting
    state in the request sent. `AgentView` carries `labels`.

17. **Labels join what a Selector matches, everywhere one is matched.** Matching runs against an
    **effective description**: what the Agent reported, plus each label whose key it does not
    report, as a non-identifying attribute. Configurations
    ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 3) and Deployments
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)) see the same set, so a label cannot mean one
    thing for one and another for the other.

18. **A label can never restate a reported attribute.** A key the Agent already reports is refused
    at the API with `409`, naming it. At merge time the reported value wins regardless — the case
    of an Agent that *starts* reporting a key labelled before — and the shadowed label is listed in
    `shadowed_labels` on the fleet row rather than dropped in silence. Labels annotate; they do not
    correct.

19. **Labels are the operator's: they outlive the record and never travel to the Agent.** They are
    keyed by Instance UID — the only identity unique across a fleet — and survive a restart.
    **Forgetting an Agent does not clear them**: a host that comes back is in the ring it was put
    in. No capability, no message, nothing the Client reports carries them; everything an Agent
    reports is still something it observed about itself.

20. **Labels persist one file per Agent, `<config_dir>/labels/<instance_uid>.json`.** Temp file and
    atomic rename; an empty set deletes the file; a file that does not parse, or is not named after
    an Instance UID, fails startup. The Configuration store's loader ignores the directory.

21. **A label change moves what is proposed, never what is offered.** Setting labels changes which
    Configurations and Deployments are candidates for the Agent; nothing reaches it until a rollout
    act ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)).

22. **The bundled UI puts each remedy beside its diagnosis.** A stale Agent shows a *Stale* pill
    beside its connection pill. The forget action is offered on every row, not pre-filtered by the
    row's fields: the Server holds the one rule of clause 12 and its `409` reason is shown. Labels
    appear as their own chips, a shadowed one marked, and are searched beside the reported
    attributes.

**Out of scope:** a configuration surface for choosing a storage backend, which earns its keep
with a second adapter; extending the port to the Configuration, label, and package stores; a
retention policy for Agents and labels nobody claims; acting on staleness (alerts, webhooks,
filters); bulk labelling.

## Alternatives considered

- **Keep the fleet in memory.** Loses the inventory exactly when a host cannot repeat it, and turns
  every restart into a fleet-wide `ReportFullState` stampede.
- **A concrete filesystem store, no port.** The simplest thing that persists, but the requirement
  names a database and an external store, and retrofitting a port rewrites the call sites it
  protects; four operations keep the abstraction cheap.
- **A generic key-value port (`uid → bytes`).** Decides the encoding above the port, so a database
  adapter degenerates into a blob table.
- **An embedded database as the default** (SQLite; Bindplane's bbolt-then-Postgres path). A second
  storage idiom for small, per-Agent data loaded whole; the port is what lets a deployment add one.
- **Persist every report, heartbeats included.** Write amplification with near-zero information,
  documented as a scale problem by Elastic Fleet.
- **One periodic snapshot file.** Rewrites the world on every change or waits for a timer, and a
  crash loses the tail.
- **Serde derives on the generated protobuf types.** Welds the on-disk format to prost's field
  names, and JSON of generated types drops unknown fields anyway.
- **Mark a stale Agent disconnected.** `connected` is a fact about a connection, which behind a
  Gateway is up; overwriting it makes the field ambiguous.
- **The Gateway synthesises `agent_disconnect` for a vanished peer.** Asserts a goodbye that never
  happened.
- **Staleness for every Agent, heartbeat or not**, or **inferring the period from the Agent's
  rhythm.** Flags Agents that promised nothing, or guesses — and the first slow fleet-wide restart
  makes every Agent look late.
- **A background sweeper flipping a stored `stale` flag.** A task and a stored state that can
  disagree with the timestamp, for an event nobody consumes.
- **Hide the row instead of dropping the record** (Elastic's *inactive*). Frees nothing; `stale` is
  already the visible signal such a model exists to produce.
- **Forget unconditionally** (Bindplane). Turns a tidy-up into an unannounced restart on a healthy
  host.
- **Gate forgetting on the `stale` flag.** `stale` is false by construction without a heartbeat and
  `connected` never clears for a silent poller, so such an Agent would be unforgettable.
- **Keep the re-offer gates across a forget in a side table.** A record of the Agent under another
  name, which nothing ever removes.
- **Revoke on forget.** There is no per-Agent credential, and an Instance UID is not an
  authenticator — a deny-list of them would be theatre.
- **`POST …/forget` instead of `DELETE`.** The record is the resource the collection returns; the
  naming worry is answered in the description and the UI label.
- **Labels that win over reported attributes** (Bindplane's bootstrapped labels). Here reported
  attributes choose the binary, so a mislabelling would become a mis-installation.
- **Flat tags** (Elastic). A second matching rule beside the key/value Selector that exists.
- **Add/remove operations** (`tagsToAdd` / `tagsToRemove`). Better for bulk work, which deserves its
  own decision.
- **Push labels to the Client to report.** Makes an Agent report as observed what it was told, and
  puts a round trip between labelling a host and targeting it.
- **Key labels by `service.instance.name`.** Not unique across hosts, so labelling one host would
  label its namesakes.
- **A separate `labels_dir` setting.** A third path to know and back up, for data that belongs with
  the Configurations.

## Sources / Prior art

- [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)
  — `ReportsHeartbeat` and its 30-second default; `ReportFullState` as the recovery for lost
  server state; silent on server-side record lifetime, and its "revoke access" is per-connection
  credentials, an operation this project cannot perform per Agent.
- [Elastic Fleet agent monitoring](https://www.elastic.co/docs/reference/fleet/monitor-elastic-agent)
  — a persisted inventory with *offline* derived from `last_checkin`; and
  [fleet-server#749](https://github.com/elastic/fleet-server/issues/749), the write load of
  persisting every check-in.
- [Elastic inactivity timeout](https://www.elastic.co/docs/reference/fleet/set-inactivity-timeout)
  and [unenrolment](https://www.elastic.co/docs/reference/fleet/unenroll-elastic-agent) — the
  hide-then-revoke model, whose second stage rests on per-Agent credentials.
- [Bindplane ephemeral collectors](https://docs.bindplane.com/how-to-guides/collector-management/golden-images-and-ephemeral-collectors)
  — a forgotten collector that returns "will just be treated as a new agent".
- [Bindplane Bolt Store](https://bindplane.com/docs/advanced-setup/backup-and-disaster-recovery/bolt-store)
  and [Postgres Store](https://docs.bindplane.com/how-to-guides/postgres/postgres-store) — one
  store interface, interchangeable backends.
- [Bindplane agents API](https://docs.bindplane.com/cli-and-api/api/agents) and
  [progressive rollouts](https://docs.bindplane.com/feature-guides/deployment-and-management/progressive-rollouts)
  — key/value labels, the opposite collision rule, and stage matching by "every label specified".
- [Elastic agent tags](https://www.elastic.co/docs/reference/fleet/filter-agent-list-by-tags) and
  the [bulk tag update](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-fleet-agents-bulk-update-agent-tags)
  — flat tags, added and removed in bulk.
- [Hexagonal architecture](https://alistair.cockburn.us/hexagonal-architecture/) (Cockburn) — the
  ports-and-adapters pattern behind clause 2.
- [opamp-go](https://github.com/open-telemetry/opamp-go) example server — keeps its agent map in
  memory and offers no persistence design to follow.

## Consequences

- Positive: the fleet view survives a restart, including the Agents not reporting, shown honestly
  as disconnected; restored gates mean a reconnecting Agent's compressed report is accepted and
  nothing that already runs is re-offered; a queued restart survives.
- Positive: storage is a deployment choice behind a four-operation trait, and tests get an
  in-memory fake for free.
- Positive: the fleet view stops asserting what it does not know — gatewayed, polling, and wedged
  Agents become visible by one rule — and a decommissioned host's row can be removed.
- Positive: a rollout ring is a Server-side decision, one API call instead of an edit and a restart
  on the host, for Configurations and packages alike, at no protocol cost.
- Negative / trade-offs: a forgotten Agent that returns costs one re-apply, and for a managed Agent
  one restart of its Managed Process. A disconnected Agent is forgettable at once, so a flapping
  one can be forgotten between two connections.
- Negative / trade-offs: forgetting is not unenrolling; a still-configured Client reappears, and
  only the host can stop it.
- Negative / trade-offs: the store and the label directory grow with every Agent ever seen and
  nothing prunes them; an Agent that declares no heartbeat is never stale; after a crash an
  idle-but-alive Agent can read as silent, and so forgettable, until its next report.
- Negative / trade-offs: the default adapter's files are only half human-readable.
- Negative / trade-offs: targeting depends on Server-side state no Agent reports; a re-keyed Agent
  loses its labels and falls back to what its reported attributes match; an operator who wants to
  correct a badly reported attribute must do it on the host.
- Follow-ups: a storage-backend setting once a second adapter exists; the port for the other
  stores; a retention policy for Agents and labels; bulk forgetting and bulk labelling; staged
  rollouts as a first-class object on top of labels; observability of the store's size.

## Enforcement

- [`fleet.rs`](../../crates/fleet-server/src/fleet.rs) unit tests:
  `an_agent_that_stopped_reporting_is_stale_while_its_connection_is_up`,
  `an_agent_inside_its_budget_is_not_stale`, `an_agent_that_promised_no_heartbeat_never_goes_stale`,
  `an_offered_heartbeat_interval_sets_the_budget`, `a_disconnected_agent_is_forgotten`,
  `an_agent_that_is_still_reporting_is_refused`, `a_connected_agent_that_went_quiet_is_forgotten`,
  `a_silent_agent_is_forgotten_although_it_can_never_be_stale`,
  `forgetting_an_agent_that_was_never_known_says_so`,
  `the_fleet_is_restored_disconnected_after_a_restart`,
  `a_restored_agent_is_not_demanded_a_full_report`, `a_heartbeat_writes_nothing`,
  `forgetting_an_agent_removes_its_stored_record`, `a_rekeyed_agent_moves_its_stored_record`,
  `a_queued_restart_survives_a_restart`.
- [`agent_store.rs`](../../crates/fleet-server/src/agent_store.rs) unit tests:
  `a_record_survives_the_round_trip`, `a_heartbeat_does_not_change_the_durable_digest`,
  `remove_deletes_and_tolerates_absence`, `rekey_moves_the_record`,
  `a_corrupt_record_fails_the_load_by_name`.
- [`labels.rs`](../../crates/fleet-server/src/labels.rs) unit tests:
  `a_label_is_matched_like_a_reported_attribute`, `a_label_never_overrides_what_the_agent_reports`,
  `an_agent_that_reported_nothing_can_still_be_labelled`, `empty_keys_and_values_are_refused`,
  `labels_survive_a_reopen_and_an_empty_set_clears_them`.
- [`rest_api.rs`](../../crates/fleet-server/tests/rest_api.rs):
  `forgetting_an_agent_that_is_still_reporting_is_refused`,
  `a_silent_agent_is_forgotten_and_returns_as_a_stranger`, `forgetting_what_is_not_there_is_reported`,
  `a_label_moves_an_agent_into_a_rollout_ring`, `a_label_may_not_restate_what_the_agent_reports`,
  `forgetting_an_agent_keeps_its_labels`; [`packages.rs`](../../crates/fleet-server/tests/packages.rs)
  `a_label_aims_a_set_at_part_of_the_fleet`.
