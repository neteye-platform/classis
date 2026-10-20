# ADR-0041: A Managed Process states only its own `service.*` attributes, and never the host's, the Supervisor's or the operator's

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the fold of a Managed Process's description and the operator
  attributes in `crates/fleet-agent/src/supervisor/agent/description.rs`, the
  attribute keys in `crates/opamp/src/attributes.rs`, the `[attributes]` table
  of `supervisor.toml`, and every document that tells an operator what a Managed
  Process or `[attributes]` contributes to an Agent's description
- **Supersedes:** [ADR-0016](0016-what-an-agent-reports-about-itself.md) clauses
  8 and 9

## Context

A Supervisor-backed Agent's `AgentDescription` has three sources. The Supervisor
states who the Agent is and where it runs: `service.name`,
`service.instance.id`, `service.instance.name`, `service.namespace` where the
operator set `service_namespace`, and the `os.*` and `host.*` attributes of
[ADR-0016](0016-what-an-agent-reports-about-itself.md) clause 5. The operator's
`[attributes]` table adds the keys the code does not report (ADR-0016 clause 9).
The Managed Process reports its own description through the Supervisor Endpoint
or the version probe, and that report is laid over the other two for every key
except `service.instance.id` and `service.instance.name` (ADR-0016 clause 8).

A Managed Process is code that the Supervisor does not vouch for. The Server
ships its program as a package and its configuration as Configurations, and a
Configuration's language can run commands, such as a Telegraf `inputs.exec`.
Whatever such a process reports reaches the Server as the Supervisor's own
statement, and the Server cannot tell the two apart. The fold lets it state:

- **Another host.** Selectors match the effective description, and a reported
  attribute beats every label. A process on host B that reports `host.name` or
  `host.id` of host A is matched by a Deployment aimed at host A. It also
  reports `service.name`, so it can choose the type, and it then receives the
  Configurations meant for host A, with whatever credentials they carry.
- **Another platform.** `os.type` and `host.arch` choose the artifact a package
  offers. A process that reports another platform is offered a binary built for
  another machine, and the Supervisor swaps it over the program. Only the health
  gate catches this.
- **A Client Agent.** The Client's own Agent is recognised by the
  `supervisor.kind.*` attributes that only it reports
  ([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)
  clause 4). A process that reports one makes a second Client Agent in its
  group. Then nobody in the group inherits labels, and every Agent of the host
  is marked ambiguous and drops out of every Deployment aimed by an inherited
  label. Behind a Gateway the group is keyed by the reported `host.id` or
  `host.name`. A process that also reports another machine's `host.id` therefore
  joins that machine's group, and inherits its labels or makes it ambiguous.
- **The operator's values.** An `[attributes]` entry such as `channel` is
  overwritten by the fold. A Server label is shadowed by any key the process
  starts to report (ADR-0035 clause 5), so a process reporting
  `rollout = stable` leaves the canary channel its label put it in.

The process contributes two values that nobody else knows: its type, which is
`dist.name` for a Collector, and its version. Both are `service.*` keys. The
rest of what a Collector's `opampextension` reports is `host.name`, `os.type`,
`host.arch` and `os.description`. The Supervisor reports these from the same
machine in the same spelling
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
The extension may also report attributes written in the Collector's own
configuration, under `agent_description.non_identifying_attributes`, and the
Collector's resource attributes.

## Decision

We will lay over the Supervisor's description only the `service.*` attributes a
Managed Process reports, except `service.instance.id`, `service.instance.name`
and any key whose value the operator set, and drop every other key it reports.

1. **Restates ADR-0016 clause 8. A Managed Process's own description is folded
   in for its `service.*` attributes alone, never for who the Agent is or where
   it runs.** What the process reports, through the Supervisor Endpoint or the
   version probe, is merged per attribute, a later report winning on the same
   key. From the merged report, a key is laid over the Supervisor's description
   only when it starts with `service.` and is none of these:
   - `service.instance.id` and `service.instance.name`. They are the
     Supervisor's: a process cannot know the Supervisor's identity or what the
     operator called it.
   - A key whose value the operator set: `service.namespace` where the top-level
     `service_namespace` is set, and every key that the `[attributes]` table
     puts into the description (clause 2).

   Every other key the process reports is dropped. This covers every `host.*`,
   `os.*` and `supervisor.*` key, `supervisor.kind.*` included, and every key in
   a namespace of its own. Where the Agent runs is the Supervisor's statement,
   because a process's statement about the host is a claim nobody checks, and it
   decides which Selectors match and which artifact is offered. The rule applies
   **by key and in both lists**, whichever list the process reports a key in. An
   admitted key replaces the Supervisor's value in the list the Supervisor
   states it in. Only where the Supervisor states no such key is it added to the
   list the process reported it in. A key is therefore reported once, and a
   Selector and the fleet row read the same value. The process's `service.name`
   wins: `dist.name` is a better type than anything a file can infer. Its
   `service.version` is the Agent's version (ADR-0016 clause 4).

2. **Restates ADR-0016 clause 9. Operator attributes describe the host, and a
   Managed Process never overrides one.** The Client-wide `[attributes]` table
   (string to string; any other value type is refused) is reported as
   non-identifying attributes of every Agent this Client presents. Each is added
   only where the code reports nothing under the same key. What the code reports
   always wins, so an attribute can never restate the type or the instance name.
   An attribute that is added stands against the Managed Process: the fold
   leaves its key alone (clause 1). Tagging one Agent among several is a Server
   label's job ([ADR-0024](0024-the-fleet-record.md) clause 16): a
   `[[supervisor]]` block carrying an `attributes` table fails at startup with a
   message naming the Server label. The Client's own Agent also reports the
   kinds it was compiled with
   ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).

**Out of scope:** what a compromised Client reports. Its code builds the whole
description, and no rule on the Client binds it. Also out of scope: the type a
process claims. `service.name` stays its own word, so a process can still choose
which type's Configurations and packages fit its Agent on its own host. The
Server's precedence of the effective description is also out of scope (ADR-0035
clauses 3 and 5).

## Alternatives considered

- **A deny-list: drop `host.*`, `os.*`, `supervisor.*` and the operator's keys,
  and pass the rest.** This drops today's known attacks. But the Client does not
  know which keys the Server's labels use, so a process could still shadow a
  label such as `rollout` and leave its channel. A key the Supervisor starts to
  report later would also be open until someone adds it to the list. An
  allow-list of `service.*` is closed by default. It costs only the attributes a
  process states in a namespace of its own, which nothing in this project reads.
  Rejected.
- **Keep the fold as it is.** A process on one host can draw another host's
  Configurations, an artifact for another platform, and a whole host out of its
  label-based rollouts. Rejected.
- **Let the Server ignore reported `host.*` and `os.*` for Selectors and the
  artifact choice.** The Server receives one description and cannot tell which
  key the process supplied. Ignoring these keys for every Agent would remove the
  Supervisor's true values with the false ones: "pin one host by `host.name`"
  (ADR-0026) would stop working, the artifact could no longer be chosen, and the
  grouping behind a Gateway (ADR-0035 clause 4) would lose its key. The
  Supervisor knows which value came from the process and can decide where the
  Server cannot. Rejected.
- **Let an operator admit further keys per `[[supervisor]]` block.** That would
  restore a Collector's own tags. But it puts a per-Agent setting back into
  `supervisor.toml`, where tagging one Agent is a Server label's job (ADR-0016
  clause 9). It can be decided later if a need appears. Not taken now.

## Sources / Prior art

- `crates/fleet-agent/src/supervisor/agent/description.rs:118-129`: operator
  attributes are added only where nothing is reported. Lines 142-156: the fold,
  which exempts only `service.instance.id` and `service.instance.name` (143-145)
  and upserts every other key in the list the process used (161-166).
- `crates/fleet-agent/src/supervisor/mod.rs:64-71` and `:104`:
  `supervisor.kind.*` is set only on the Client's own Agent. `:299`: a
  Supervisor-backed Agent gets the same `[attributes]` and none of the kinds.
- `crates/fleet-agent/src/supervisor/process.rs:967-972`: the version probe
  reports `service.version` and nothing else.
  `crates/fleet-agent/src/supervisor/endpoint.rs:220-225`: the Supervisor
  Endpoint passes the whole description on as an event.
- `crates/fleet-server/src/deployments.rs:35-50`: a Selector matches identifying
  attributes first, then non-identifying ones.
  `crates/fleet-server/src/labels.rs:122-125` and `:150-161`: a reported
  attribute beats every label. `:165-179`: a shadowed label is listed.
- `crates/fleet-server/src/packages.rs:66-80`: the platform comes from the
  reported `os.type` and `host.arch`.
  `crates/fleet-server/src/configs.rs:152-170`: the fit uses the reported
  `service.name`.
- `crates/fleet-server/src/labels.rs:191-200`: any `supervisor.kind.*` key makes
  a Client Agent. `:202-217`: the machine behind a Gateway is the reported
  `host.id`, else `host.name`. `crates/fleet-server/src/fleet.rs:821-826`: the
  group behind a Gateway. `:2694-2716`: two Client Agents in a group mean nobody
  inherits and all are marked ambiguous.
- `docs/manual/rollout.md:418`: the manual suggests `channel` in `[attributes]`
  as a way into a channel.
- [`opampextension` `opamp_agent.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/opampextension/opamp_agent.go):
  the identifying `service.name`, `service.version` and `service.instance.id`;
  the non-identifying `os.type`, `host.arch`, `host.name` and `os.description`;
  and the configured `agent_description.non_identifying_attributes` and
  `include_resource_attributes`. Recalled, not re-read for this record.

## Consequences

- Positive: a Managed Process can no longer draw another host's Configurations,
  be offered an artifact for another platform, make its host or another one
  ambiguous, or override the operator's attributes or shadow a Server label
  outside `service.*`. ADR-0035 clause 4's "the attributes it alone reports"
  holds on every honest Client.
- Negative / trade-offs: what a Collector states outside `service.*` no longer
  reaches the Server. This covers attributes in its own
  `agent_description.non_identifying_attributes`, its resource attributes, and
  its own `host.name` where that differs from the Supervisor's, as in a
  container. An operator who tagged a Collector that way moves the tag to a
  Server label, or to `[attributes]` for the whole host. The changelog says so.
- Follow-ups: G-16 says the Supervisor Endpoint relays the Collector's
  description upstream. Whether that sentence should name the part that is
  relayed is a question for a specification change.

## Enforcement

Tests that will carry `Verifies: ADR-0041`:

- In `crates/fleet-agent/src/supervisor/agent.rs`: a process that reports
  `host.name`, `host.id`, `os.type`, `host.arch`, `os.description`,
  `supervisor.kind.collector` and `collector.pipeline`, each once in the
  identifying and once in the non-identifying list. The description carries the
  Supervisor's `host.*` and `os.*` values, and no `supervisor.kind.*` or
  `collector.pipeline`. The same report's `service.name` and `service.version`
  are reported.
- An operator `[attributes]` entry `channel = canary` and a process reporting
  `channel = stable` and `service.team = x`, with
  `[attributes] service.team = y`. Both operator values stand. With
  `service_namespace` set, a process's `service.namespace` is dropped. Without
  it, the process's value is reported.
- A process that reports `service.name` among its non-identifying attributes
  replaces the Supervisor's value in the identifying list, and the description
  carries the key once.
- In `crates/fleet-agent/tests/collector_extension_e2e.rs`: an extension report
  carrying `host.name = elsewhere` and `supervisor.kind.collector = true`
  reaches the Server with the Supervisor's `host.name` and without the kind
  attribute, while its `service.version` and health arrive.
