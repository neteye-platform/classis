# ADR-0023: Configurations are named, Selector-targeted resources of an OpenAPI-described REST API

- **Status:** 🟢 accepted · clauses 1, 3, 4, 12 and 13 superseded by [ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md) · clause 10 superseded by [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
- **Date:** 2026-08-12
- **Deciders:** Markus Brigl
- **Applies to:** crates/fleet-server/src/configs.rs, crates/fleet-server/src/api.rs, the Configuration routes and the OpenAPI document under /api/v1, config_dir in server.toml, role handling in crates/fleet-agent/src/storage.rs and the Supervisor plugins

## Context

The specification asks for two things that belong to one decision. Goal 9: a configuration can
target a subset of the fleet through a **Selector**. Goal 5: any UI can drive the fleet through an
**OpenAPI-described** REST API. Selectors force the API to grow a real resource model, and that
model is what the OpenAPI document describes.

The forces are largely fixed. Distribution is hash-gated (goal 3). The specification forbids an
abstraction over an agent's configuration language. OpAMP's `AgentConfigMap` is a map of named
entries whose `config_hash` covers the whole map, so composing an Agent's configuration out of
several named parts is the protocol's own mechanism. A Collector takes several `--config` files and
merges them natively.

The Baseline's `AgentConfigObject.role` describes *"the role of the content in the body field. The
values and their semantics are Agent type-specific."* Upstream added it for a case this project has:
a Collector configuration can reference files that are not configuration at all — a fragment
pulled in with `${file:ruleset.yaml}`, a certificate — and those must be on disk beside the
configuration without being handed to the Collector as `--config`.

The Agent type is a reported attribute (`service.name`,
[ADR-0016](0016-what-an-agent-reports-about-itself.md) clause 1). Expressed only as a Selector
pair, limiting a Configuration to a type is easy to forget: an empty Selector matches every Agent,
every Agent this Client presents accepts remote configuration, and a Collector YAML saved without
the pair is composed into the map of every Foreign Agent and the Client's own Agent alike — a
fleet-wide restart-and-rollback churn. And a Selector carrying both *what kind of Agent* and
*which of them* cannot be read apart in the UI or the API.

Prior art splits in two. Elastic Fleet enrolls each agent in exactly one policy, which forbids
composition. Grafana Fleet Management matches pipelines to collectors by attributes, sorts multiple
matches by name and merges them; Bindplane matches agents with Kubernetes-style label selectors.

## Decision

We will hold named **Configurations** — each a Selector, an optional Agent type, an optional role,
and an opaque body — compose every Configuration released to an Agent into one `AgentConfigMap` of
named entries that the Managed Process merges itself, and make a REST API under `/api/v1`,
described by an OpenAPI document generated code-first with `utoipa`, the Server's contract.

1. **A Configuration is `{name, selector, service_name, role, body}`.** The body is the Managed
   Process's own format and is never interpreted by the Server. A body that is empty or only
   whitespace is refused; line endings are normalised to `\n` and a missing final newline is
   added. `selector`, `service_name`, and `role` are optional; an unset `service_name` or `role`
   is absent from the stored JSON and from responses.

2. **The name follows the instance-name grammar of
   [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clause 2** — 1–32 characters of lowercase
   letters, digits, and `-`, not starting or ending with `-`, not a Windows device name — because
   it becomes a file name on the Server, a config-map key on the wire, and an entry file on every
   Client.

3. **A Selector is equality, AND, over what the Agent presents.** It is a string-to-string map; an
   Agent matches when every pair equals a string-valued attribute it reported, identifying
   attributes looked up first, then non-identifying ones, then the Server's labels
   ([ADR-0024](0024-the-fleet-record.md) clause 17). **The empty Selector matches every Agent**,
   and an Agent that has not described itself yet matches only the empty Selector. An
   array-valued attribute (`host.ip`) is displayed but never matched. There are no set-based
   operators (`in`, `exists`); they would extend the same field compatibly.

4. **The type is fitted before the Selector aims.** A set `service_name` is compared **raw**, with
   no canonicalisation, against the `service.name` the Agent reports; a Configuration whose type
   differs reaches that Agent not at all, and only then does the Selector run. **Unset means every
   type**, which keeps the fleet-wide Configuration and cross-type supplementary content (a
   certificate bundle) expressible. An Agent that reports no `service.name` matches only untyped
   Configurations: equality against a missing attribute fails, exactly as a Selector pair does.
   The type is a mutable field of the resource, not part of its identity. A `service.name` pair in
   a Selector keeps working; the field is the documented way to say it.

5. **An Agent's Remote configuration is one `AgentConfigMap` whose entries are Configurations.**
   Each entry is keyed by the Configuration's name, entries are in name order, and each carries
   the body and the role. The Server never merges bodies: the Collector plugin passes each
   configuring entry as its own `--config` and the Collector merges, and every other kind decides
   for itself what the named files mean.

6. **The hash covers what the Agent must do, never whom it reaches.** `config_hash` is SHA-256 over
   the length-prefixed `(name, body, role)` of every entry in name order. An empty role
   contributes nothing, so a Configuration without one hashes as if the field did not exist. The
   Selector and the type are never hashed. An offer is made only to an Agent declaring
   `AcceptsRemoteConfig`, and only while the hash it reports as last received differs.

7. **Nothing released, nothing offered.** An Agent's map is composed from the Configurations an
   operator's rollout act released to it, never from matching alone
   ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)); matching computes the candidates.
   An Agent with nothing released to it is offered nothing and keeps running what it runs.

8. **The role travels verbatim; the Server owns no vocabulary.** The `role` of a Configuration goes
   unchanged into `AgentConfigObject.role` of its entry, so an Agent that interprets roles itself
   sees exactly what the operator set. Two readings are this project's:
   - **empty (the default)** — top-level configuration, which the Managed Process is configured
     with;
   - **`supplementary`** — content the Managed Process reads by path: fragments, certificates,
     rule files.

   Any other value is treated like `supplementary` by a kind that defines nothing further, and is
   never guessed at. A kind may give a value a meaning of its own, which that kind's ADR decides.

9. **On the Client every entry is written, and only unroled entries configure.** Each entry lands
   owner-only in the Supervisor's config directory under its name, so a `${file:...}` reference
   resolves. The role of every roled entry is recorded beside them (`.supplementary`, one
   `<name> <role>` per line, written only while some entry has a role), and a plugin that
   configures its process from the entries leaves every roled one out: the Collector gets one
   `--config` per unroled entry, in sorted order.

10. **Configurations persist as one JSON file each.** `<config_dir>/<name>.json`, `config_dir` in
    `server.toml` defaulting to `fleet-configs`, written through a temp file and an atomic rename,
    loaded at startup; `DELETE` removes the file. A file that does not parse fails startup naming
    it. What the file holds besides the saved fields — the revisions a rollout pins — is
    [ADR-0025](0025-rollout-and-what-reaches-an-agent.md)'s. No database: a handful of small
    files needs none.

11. **The REST API is versioned by path and described by a generated document.** Every route lives
    under `/api/v1`. The OpenAPI document is generated code-first with `utoipa` and `utoipa-axum`:
    handlers and schemas are annotated where they live and routes registered once, so document and
    behaviour cannot drift. It is served at `/api/v1/openapi.json`. The API is served on the
    Operator plane ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)), behind its
    authentication ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)), beside the rendered docs
    page ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)).

12. **The Configuration routes.** `GET /api/v1/configurations` lists them in name order;
    `GET /api/v1/configurations/{name}` returns one (`404` if absent);
    `PUT /api/v1/configurations/{name}` creates or replaces one from a body of `selector`, `body`,
    `role`, `service_name` that refuses unknown fields (`200` with the stored view, `400` for an
    invalid name or an empty body, `500` when it cannot be persisted);
    `DELETE /api/v1/configurations/{name}` answers `204` or `404`. The fleet routes
    (`GET /api/v1/agents`, an Agent's restart, labels, forget) sit beside them
    ([ADR-0024](0024-the-fleet-record.md)), as do the rollout routes
    ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)).

13. **The bundled UI is a client of the same routes and nothing more.** It shows the type as an
    input of its own beside the Selector, suggesting the types the fleet reports, and each
    Configuration's chip shows its type, Selector, and role.

**Out of scope:** when and to whom a Configuration is released, and what deleting one does to the
Agents it was released to ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)); the meaning
of a kind's own role values (each kind's own ADR); set-based Selector operators;
configuration history and audit.

## Alternatives considered

- **Exclusive assignment — one policy per Agent (Elastic Fleet).** Forbids composition of a
  fleet-wide base with a narrower overlay, turns membership into a workflow of its own, and still
  needs grouping criteria, which are Selectors by another name.
- **Priority ordering, first match wins.** A total order between unrelated Configurations is hidden
  coupling, and it forecloses the composition the protocol's config map provides for free.
- **Server-side body merging.** Precisely the abstraction over an agent's configuration language
  the specification rules out, and it would drag a YAML stack into the Server.
- **A hand-written OpenAPI document**, or **`aide`** instead of `utoipa`. A document maintained
  beside the code drifts; `utoipa` is the most widely adopted code-first generator with dedicated
  axum bindings. The document, not the generator, is the contract.
- **SQLite for the Configuration store.** Transactions and history for a resource counted in
  dozens; atomic per-file writes carry the need without a dependency.
- **Unversioned routes, or versioning by header.** Path versioning is what generated clients and
  reverse proxies handle most simply, and renaming routes after portals have generated clients is
  the expensive variant.
- **A `supplementary` boolean instead of a role string.** Clearer to read, but it cannot carry any
  other agent type's vocabulary and would have to be mapped onto `role` on the wire anyway.
- **A separate resource for supplementary files.** Duplicates Selector targeting, hashing,
  persistence, and the REST surface for content that differs in exactly one respect.
- **Carry `role` but let the plugins ignore it.** The operator sets a role, the Server ships it,
  and the Supervisor still hands a certificate to the Collector as `--config`.
- **Express the type only as a Selector pair.** Zero cost, but the failure is fleet-wide churn
  behind one forgotten pair, and the UI cannot guide what it cannot tell apart.
- **A mandatory type — untyped Configurations reach nobody.** Abolishes the fleet-wide
  Configuration and cross-type supplementary content, both legitimate.
- **Pattern or prefix matching on the type** (`otelcol*`). Two types are two Configurations; there
  is no canonical set of types to pattern against.

## Sources / Prior art

- [Grafana Fleet Management architecture](https://grafana.com/docs/grafana-cloud/send-data/fleet-management/introduction/architecture/)
  — attribute matching, multiple matches sorted by name and merged.
- [Bindplane: Fleets](https://docs.bindplane.com/feature-guides/deployment-and-management/fleets)
  — Kubernetes-style label selectors matching agent labels.
- [Bindplane — Bring Your Own Collector](https://docs.bindplane.com/feature-guides/deployment-and-management/bring-your-own-collector)
  — the Agent type as a first-class property that what an agent may receive hangs off.
- [Elastic Agent policies](https://www.elastic.co/docs/reference/fleet/agent-policy) — the
  exclusive-assignment model.
- [Kubernetes labels and selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
  — the equality-based and set-based grammar; this decision takes the equality subset.
- [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)
  and [`opamp.proto`](../../crates/opamp/proto/v0.20.0/opamp/v1/opamp.proto) at the Baseline
  ([`CONFORMANCE.md`](../CONFORMANCE.md)) — `AgentConfigMap` of named entries, `config_hash`
  over the offer, `AgentConfigObject.role`, `service.name` as the Agent type.
- [opamp-spec#184](https://github.com/open-telemetry/opamp-spec/issues/184) and
  [opamp-spec#350](https://github.com/open-telemetry/opamp-spec/pull/350) — the case for `role`:
  top-level configuration versus supplementary content.
- [OpenTelemetry Collector configuration](https://opentelemetry.io/docs/collector/configuration/)
  — multiple `--config` files merged, `${file:...}` reading content that is not configuration.
- [`opamp-go`](https://github.com/open-telemetry/opamp-go) and the Collector's `opampsupervisor` —
  neither defines role values, which is why this project's vocabulary is one value.
- [utoipa](https://github.com/juhaku/utoipa) and
  [`utoipa-axum`](https://docs.rs/utoipa-axum/latest/utoipa_axum/) — code-first OpenAPI
  generation with axum bindings.

## Consequences

- Positive: a portal can generate a client from `/api/v1/openapi.json` and aim a configuration at
  a chosen subset; the hash gate works per Agent; package delivery inherits Selectors instead of
  inventing targeting of its own.
- Positive: a fleet can be given the files its configuration refers to, not only the
  configuration; the Selector stays purely about aim while the type says what kind of Agent.
- Negative / trade-offs: an untyped Collector body is still a fleet-wide churn when released
  widely; optional means forgettable, and the UI asking the question is the mitigation. A
  mistyped type (`otelcol-contib`) is a silent no-op that only the reach shown in the UI reveals.
- Negative / trade-offs: `supplementary` is this project's word, chosen before upstream has one;
  if the Collector's supervisor settles on different values, operators will have configured the
  wrong vocabulary. A field on a public resource can be deprecated but never withdrawn.
- Negative / trade-offs: two server dependencies (`utoipa`, `utoipa-axum`), and OpenAPI
  annotations next to every handler and schema.
- Follow-ups: set-based Selector operators; configuration history and audit; a warning when a
  typed Configuration matches no Agent; whether a change to supplementary content alone should
  restart the Managed Process (it does, like any entry).

## Enforcement

- [`configs.rs`](../../crates/fleet-server/src/configs.rs) unit tests:
  `an_empty_selector_matches_everything_even_an_undescribed_agent`,
  `every_selector_pair_must_equal_a_reported_attribute`, `non_identifying_attributes_match_too`,
  `a_typed_revision_reaches_only_agents_of_its_type`,
  `an_agent_without_a_type_matches_only_untyped_revisions`,
  `composition_is_name_sorted_and_hash_stable`,
  `a_role_travels_into_the_composed_entry_and_into_the_hash`,
  `an_empty_role_leaves_the_hash_where_it_was`, `a_role_survives_a_reopen`,
  `unset_role_and_type_are_absent_from_the_stored_json`,
  `the_store_round_trips_and_survives_a_reopen`, `the_store_rejects_bad_names_and_empty_bodies`.
- [`rest_api.rs`](../../crates/fleet-server/tests/rest_api.rs): `configurations_crud_round_trips`,
  `a_configuration_carries_an_optional_role`, `a_typed_configuration_reaches_only_agents_of_its_type`,
  `invalid_configurations_are_rejected_loudly`, `the_openapi_document_describes_the_contract`,
  `configurations_survive_a_server_restart`.
- [`ws_transport.rs`](../../crates/fleet-server/tests/ws_transport.rs):
  `selectors_target_a_subset_and_compose_named_entries`,
  `a_configuration_role_reaches_the_agent_verbatim`.
- Client: [`storage.rs`](../../crates/fleet-agent/src/storage.rs) unit tests
  `a_roled_entry_is_written_but_not_offered_as_configuration`,
  `an_unknown_role_is_treated_like_supplementary`, `a_roles_value_is_readable_per_entry`,
  `the_state_and_configuration_are_kept_owner_only`; and
  [`supervisor.rs`](../../crates/fleet-agent/tests/supervisor.rs)
  `a_collector_supervisor_leaves_supplementary_entries_out_of_its_config_flags`.
