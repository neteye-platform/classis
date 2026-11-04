# ADR-0055: An Agent's type is its Supervisor's, and a Managed Process never chooses it

- **Status:** 🟢 accepted
- **Date:** 2026-10-24
- **Deciders:** Markus Brigl
- **Applies to:** the fold of a Managed Process's description and the type it
  reads in `crates/fleet-agent/src/supervisor/agent/description.rs` and
  `crates/fleet-agent/src/supervisor/agent.rs`, the Agent type resolution in
  `crates/fleet-agent/src/supervisor/block.rs` and
  `crates/fleet-agent/src/supervisor/mod.rs`, the `service_name` key of a
  `[[supervisor]]` block, and every document that tells an operator where an
  Agent's type comes from
- **Supersedes:** [ADR-0016](0016-what-an-agent-reports-about-itself.md) clause
  1,
  [ADR-0041](0041-a-managed-process-states-only-its-own-service-attributes.md)
  clause 1

## Context

An Agent's type is its `service.name` (ADR-0016 clause 1), and the Server
decides by it. A Configuration fits an Agent whose reported `service.name`
equals the Configuration's type, and a release pins the fitting ones to it
(`crates/fleet-server/src/configs.rs:148-171`). A Deployment's Selector can aim
at `service.name` (`crates/fleet-server/src/deployments.rs:35-50`). A package is
resolved for the type the Agent reports
(`crates/fleet-server/src/packages.rs:1126-1153`).

Today the first source of the type is the Managed Process. ADR-0016 clause 1
puts "what the Managed Process reports" above the kind's own type, the block's
`service_name` and the program's file name, and ADR-0041 clause 1 keeps that:
"The process's `service.name` wins: `dist.name` is a better type than anything a
file can infer". The fold makes no exception for any kind
(`crates/fleet-agent/src/supervisor/agent/description.rs:137-173`), and ADR-0041
names the consequence and leaves it open: "a process can still choose which
type's Configurations and packages fit its Agent on its own host".

A Managed Process is code the Supervisor does not vouch for (ADR-0041, Context).
Every Managed Process is handed the Supervisor Endpoint's token
([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
clause 16), and so is every process it starts, through its environment: a
Telegraf `inputs.exec`, a GLPI deploy task, a script a `command` Agent runs. Any
of them can connect to the Endpoint and report another type. Then the next
release that claims the Agent pins that type's Configurations to it, with
whatever credentials they carry, and the Supervisor writes them into its
`config/`. A Selector on `service.name` claims it for another Deployment. The
fleet view and the telemetry label show the false type.

Packages are already safe from this. The Supervisor refuses an offered package
whose name is not its own type before anything is downloaded, and the high-water
mark is kept per the Supervisor's type
([ADR-0043](0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)
clauses 7 and 8, `crates/fleet-agent/src/supervisor/agent/packages.rs:359-369`).
Both read the Supervisor's value, not the fold. So an honest Collector whose
`dist.name` differs from its block's type is already offered packages it then
refuses.

The process contributes one thing to the type that nobody else knows: a
Collector's `dist.name`. On main no kind states a type of its own
(`crates/fleet-agent/src/supervisor/mod.rs:43-48`, `:556`); `collector` and
`command` take the block's `service_name` or fall back to the program's file
name (`crates/fleet-agent/src/supervisor/block.rs:226-246`).

## Decision

We will take an Agent's type from its Supervisor alone, drop a `service.name`
that a Managed Process reports, and warn when the dropped value differs from the
type.

1. **Restates ADR-0016 clause 1. `service.name` is the Agent type, identifying,
   and the Supervisor states it.** It is resolved in this order, first hit wins:

   | Source                       | When                                                                                                                                                                                                                                            |
   | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | The kind's own type          | a wrapped kind states it (`icinga2`, `telegraf`, `glpi-agent`); a block of such a kind carrying `service_name` fails at startup naming the derived value ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)) |
   | The block key `service_name` | `collector` and `command`; must not be empty, and is not bound by the instance-name grammar, so a reverse FQDN is accepted                                                                                                                      |
   | The program's file name      | the fallback: `otelcol`, `promtail`                                                                                                                                                                                                             |

   The fallback is read from the configuration, never parsed out of a program's
   output. What the Managed Process reports is never a source of the type
   (clause 2). The Baseline's reverse-FQDN shape is a recommendation and is not
   enforced. The Client's own Agent reports the constant `supervisor`
   ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)),
   never its configured name. A Selector or a Configuration's type
   ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 4) on
   `service.name` aims at a type.

2. **Restates ADR-0041 clause 1. A Managed Process's own description is folded
   in for its `service.*` attributes alone, never for who the Agent is, what
   type it is or where it runs.** What the process reports, through the
   Supervisor Endpoint or the version probe, is merged per attribute, a later
   report winning on the same key. From the merged report, a key is laid over
   the Supervisor's description only when it starts with `service.` and is none
   of these:
   - `service.name`. The type is the Supervisor's (clause 1): a process that
     chose it would choose which type's Configurations are pinned to its Agent
     and which Deployment claims it.
   - `service.instance.id` and `service.instance.name`. They are the
     Supervisor's: a process cannot know the Supervisor's identity or what the
     operator called it.
   - A key whose value the operator set: `service.namespace` where the top-level
     `service_namespace` is set, and every key that the `[attributes]` table
     puts into the description (ADR-0041 clause 2).

   Every other key the process reports is dropped. This covers every `host.*`,
   `os.*` and `supervisor.*` key, `supervisor.kind.*` included, and every key in
   a namespace of its own. Where the Agent runs is the Supervisor's statement,
   because a process's statement about the host is a claim nobody checks, and it
   decides which Selectors match and which artifact is offered. The rule applies
   **by key and in both lists**, whichever list the process reports a key in. An
   admitted key replaces the Supervisor's value in the list the Supervisor
   states it in. Only where the Supervisor states no such key is it added to the
   list the process reported it in, and a key the process reports in both lists
   is added once, among the identifying attributes, with its identifying value,
   because the Server reads `service.version` from there. A key is therefore
   reported once, and a Selector and the fleet row read the same value. The
   process's `service.version` is the Agent's version (ADR-0016 clause 4).

3. **A type the process reports that differs from the Supervisor's is named in a
   warning.** When the merged report carries a `service.name` that is not the
   Agent's type, the Client logs a warning naming the Supervisor, both values
   and the block key `service_name`, which is how an operator who wants a
   Collector's `dist.name` as the type sets it. It warns when the reported value
   changes to one that differs from the type, not for every report: a process
   that keeps reporting one value is named once, and one that alternates is
   named at each change. The warning quotes the reported value escaped and cut
   short, so a process can neither forge a log line nor flood the log with one.
   The Agent stays healthy: a Collector whose `dist.name` differs from its file
   name runs as before, under the Supervisor's type. A process that reports the
   Supervisor's type, or no `service.name`, causes no warning.

**Out of scope:** the Endpoint's token and which processes are handed it
(ADR-0015 clause 16); what a Managed Process can read on its host, which
includes the Client's `state_dir` and key while both run under one account
([ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md));
`service.version`, which stays the process's word; and what a compromised Client
reports.

## Alternatives considered

- **Keep the process's type (today).** A process, or anything it starts, chooses
  which type's Configurations are pinned to its Agent and which Deployment
  claims it, and the Server cannot tell that statement from the Supervisor's.
  Rejected.
- **Admit the process's `service.name` only where it equals the Supervisor's.**
  That is this decision, minus the warning: a differing value is dropped either
  way. It says nothing to the operator whose Collector reports a `dist.name`
  they expected to see as the type. Rejected for the warning of clause 3.
- **Report the process's `service.name` under a key of its own, for display.**
  The fleet view could then show `dist.name` beside the type. It is a new
  attribute key, read by nothing that decides, and a key a process fills is one
  more claim nobody checks; the warning tells the operator the same thing where
  they can act on it. Not taken now.
- **Mark the Agent unhealthy while the types differ.** It would force a
  decision. But it would turn an honest Collector that runs fine into a failing
  Agent, and hold back its rollouts, for a naming question. Rejected.
- **Let a wrapped kind's type stand against the process, and keep the fold for
  `collector` and `command`.** `collector` and `command` are the kinds that run
  a program the operator picked without knowing its children, and `command`
  speaks no OpAMP at all, so a type reported on its Endpoint comes from
  something the operator never meant to state one. Rejected.
- **Let the Server ignore a reported `service.name` for the Configuration fit
  and the Selector.** The Server receives one description and cannot tell which
  value the process supplied (ADR-0041, Alternatives). The Supervisor knows.
  Rejected.
- **Stop handing the token to processes that speak no OpAMP.** It narrows who
  can reach the Endpoint, but a Collector's own children still inherit the
  token, and the type would still be the process's word. It is a separate
  decision about ADR-0015 clause 16 and can be taken beside this one.

## Sources / Prior art

- `crates/fleet-agent/src/supervisor/agent/description.rs:137-173`: the fold;
  `:145-146` "The process's `service.name` deliberately _does_ win".
  `crates/fleet-agent/src/supervisor/agent.rs:377-395`: `service_name()` reads
  the same precedence, and `crates/fleet-agent/src/engine.rs:233` uses it for
  the telemetry label.
- `crates/fleet-agent/src/supervisor/block.rs:226-246`: the block's
  `service_name`, the kind's default, the program's file name.
  `crates/fleet-agent/src/supervisor/mod.rs:43-48`, `:556`: the kinds on main
  and the empty `WRAPPED` list.
- `crates/fleet-agent/src/supervisor/process.rs:869-873`: every Managed Process
  is handed `OPAMP_SUPERVISOR_TOKEN`, last, with no cleared environment.
  `crates/fleet-agent/src/supervisor/endpoint.rs:180-225`: a bearer token admits
  a connection, whose description is passed on as an event.
- `crates/fleet-server/src/configs.rs:148-171`, `:351-363` and
  `crates/fleet-server/src/fleet.rs:1238-1267`, `:2368-2385`: the Configuration
  fit by the reported `service.name` at a release, and the pinned assignment
  served after it. `crates/fleet-server/src/deployments.rs:35-50`: a Selector by
  attribute equality. `crates/fleet-server/src/packages.rs:1126-1153`: a package
  resolved for the reported type.
- `crates/fleet-agent/src/supervisor/agent/packages.rs:359-369` and its test in
  `crates/fleet-agent/src/supervisor/agent.rs:1942-1989`: a package for another
  type is refused before anything is fetched; `:62`, `:151`, `:349`: the
  high-water mark keyed by the Supervisor's type.
- `SECURITY.md:113-115`: a host that reports another partition's attributes is
  assigned by that partition's next rollout, the same mechanism one level up.
- [`opampextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/opampextension):
  reports the Collector's build name as the identifying `service.name`.
  Recalled, not re-read for this record.

## Consequences

- Positive: no Managed Process, and nothing it starts, can choose its Agent's
  type, so none can draw another type's Configurations or a Deployment aimed at
  another type. What the Server assigns by type and what the Supervisor installs
  by type read the same value again, so an honest Collector is no longer offered
  packages it then refuses. The type in the fleet view and the telemetry label
  is the one the operator configured.
- Negative / trade-offs: a Collector whose `dist.name` differs from its
  program's file name now reports the file name, or the block's `service_name`,
  as its type. A fleet whose Configurations, Deployments or packages were made
  for `dist.name` stops matching such a Collector until the operator sets
  `service_name = "<dist.name>"` in its block; the warning names the value, and
  the changelog says so.
- Follow-ups: whether a process that speaks no OpAMP should be handed the
  Endpoint's token at all; separating the account that runs the Managed
  Processes from the Client's own, so that a process can read neither the
  Client's key nor another Supervisor's `config/` — the type rule here closes
  only the Endpoint's path while both share one account.

## Enforcement

Tests that will carry `Verifies: ADR-0055`:

- In `crates/fleet-agent/src/supervisor/agent.rs`: a process that reports
  `service.name = other` in the identifying and in the non-identifying list
  leaves the description's `service.name` at the Supervisor's type, once, in the
  identifying list, while the same report's `service.version` is reported;
  `service_name()` returns the Supervisor's type.
- In the same file: the first report of `service.name = other` emits one warning
  naming both values and `service_name`, a second report of the same value emits
  none, a report of `another` emits one more, and a report of the Supervisor's
  own type emits none.
- In `crates/fleet-agent/tests/collector_extension_e2e.rs`: an extension report
  whose `service.name` differs from the block's type reaches the Server under
  the block's type, with its `service.version` and health.
