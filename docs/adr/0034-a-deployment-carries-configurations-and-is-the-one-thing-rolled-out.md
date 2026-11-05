# ADR-0034: A Deployment carries Configurations beside its Packages and is the one thing rolled out, a Configuration is content only, and nothing an assignment pins can be deleted

- **Status:** 🟢 accepted
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** `crates/fleet-server/src/configs.rs`,
  `crates/fleet-server/src/deployments.rs`, the assignments, rollout acts and
  deletions in `crates/fleet-server/src/fleet.rs`, the persisted assignment in
  `crates/fleet-server/src/agent_store.rs` and its filesystem adapter, the
  Configuration, Deployment, Package-deletion and rollout routes of
  `crates/fleet-server/src/api.rs` and the OpenAPI document, the Configurations,
  Deployments and Agents tabs of the bundled UI in
  `crates/fleet-server/static/index.html`, and every document that tells an
  operator how to aim or roll out a Configuration
- **Supersedes:** [ADR-0023](0023-configurations-and-the-rest-api.md) clauses 1,
  3, 4, 12 and 13; [ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clauses
  2, 5, 7 and 20;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clauses 22, 29, 31 and 33

## Context

Two objects aim at the fleet today, by different rules:

- A **Configuration** carries its own Selector and is rolled out by itself
  ([ADR-0023](0023-configurations-and-the-rest-api.md),
  [ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 5). An Agent may
  receive many Configurations, and an empty Selector reaches every Agent.
- A **Package** reaches an Agent only through a **Deployment**
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
  An Agent belongs to at most one Deployment, two matching ones are a conflict,
  and an empty Selector is refused.

So there are two targeting rules, three rollout presses (Agent row, Deployment
row, Configuration form) and two answers to "what does this host run". The
specification called the Deployment "the only thing that is rolled out" while
Configurations were rolled out too. ADR-0026 named the way out among its
alternatives: "Deployments carry Configurations too. The tidier end state, and a
second lifecycle with its own revision model; deferred."

The specification draft this ADR follows takes that step. A Deployment is a
named release of Packages and Configurations aimed by a Selector. A
Configuration is content only. An Agent in no Deployment is offered nothing.

The human settled these points with the author:

- **No fleet-wide base Configuration.** A need for one is solved differently
  later.
- **One rollout act per Deployment, with no option to release only its
  Configurations or only its Packages.** Only what changed reaches an Agent
  anyway: the Configuration revision hash and the Package pin are compared per
  part, and the wire keeps `AgentRemoteConfig` and `PackagesAvailable` apart,
  each behind its own hash gate (G-3).
- **A Configuration keeps its Agent type and its role,** so one Deployment
  serves several Agent types and top-level and supplementary content.
- **A Configuration may sit in several Deployments,** as a Package may.
- **One deletion rule:** a resource that an assignment pins cannot be deleted.
  Today a Deployment is protected (ADR-0026 clause 31), while deleting a
  Configuration or a Package cascades through the assignments (ADR-0025 clause
  7).

Prior art draws the same line. In Elastic Fleet an Agent is enrolled in exactly
one Agent policy, and the policy's revisions carry its configuration. The binary
version was a separate action until 9.1 added a target version to the policy.
Bindplane aims configurations by labels and rolls a new version out explicitly.

The decision serves G-1 (the loop closes), G-3 (no redundant reconfiguration),
G-9 (a subset via a Deployment's Selector) and G-10 (software as well as
configuration).

## Decision

We will make the Deployment the one object that is aimed and released — a
Selector, at most one Package per Agent type, and any number of Configurations —
reduce a Configuration to content, and refuse to delete any Configuration,
Package or Deployment that an assignment pins.

1. **Restates ADR-0023 clause 1. A Configuration is
   `{name, service_name, role, body}`.**
   - The body is the Managed Process's own format, and the Server never
     interprets it. A body that is empty or only whitespace is refused. Line
     endings are normalised to `\n`, and a missing final newline is added.
   - `service_name` is required: a Configuration is written for one Agent type,
     and one without it is refused (`400`), and a stored one fails startup,
     naming the file. `role` is optional; unset, it is absent from the stored
     JSON and from responses.
   - A Configuration has no Selector.

2. **Restates ADR-0023 clause 3. A Selector is equality, AND, over the effective
   description, and it aims a Deployment.**
   - It is a string-to-string map. An Agent matches when every pair equals a
     string-valued entry of its effective description, whose content
     [ADR-0024](0024-the-fleet-record.md) clause 17 states.
   - An array-valued attribute (`host.ip`) is displayed but never matched.
   - There are no set-based operators. They would extend the same field
     compatibly.
   - A Deployment's Selector is never empty (ADR-0026 clause 24), so no Selector
     reaches every Agent by default.

3. **Restates ADR-0023 clause 4. The type is fitted inside the Deployment.**
   - A Configuration reaches only the Agents of its Deployment whose reported
     `service.name` equals its `service_name`, compared raw.
   - Content for several Agent types, a certificate bundle for instance, is one
     Configuration per type.
   - An Agent that reports no `service.name` receives no Configuration.
   - Packages are fitted by type and Platform as ADR-0026 clause 9 says.

4. **Restates ADR-0026 clause 22. A Deployment is a name, a Selector, Packages
   and Configurations.**
   - The name follows the grammar a Configuration's name follows. The Selector
     is clause 2's.
   - The Packages are at most one per Agent type (ADR-0026 clause 23).
   - The Configurations are named, in any number. A Configuration may sit in
     several Deployments.
   - `PUT /api/v1/deployments/{name}` creates a Deployment with `{selector}`,
     `PUT …/selector` re-aims it, and `DELETE` removes it (clause 8).
   - `PUT|DELETE …/packages/{agent_type}/{version}` holds or drops a Package.
     `PUT|DELETE …/configurations/{configuration}` holds or drops a
     Configuration; one the Server does not hold is `404`.
   - A Deployment is persisted owner-only, one JSON file per Deployment, in the
     store the storage decision names. A file that does not parse, or whose name
     disagrees with its content, fails startup naming it. Saving distributes
     nothing.

5. **Restates ADR-0025 clause 2. The assignment is per Agent, persisted, and
   pins one release.**
   - Each Agent's record ([ADR-0024](0024-the-fleet-record.md)) stores what its
     last rollout released to it:
     - the Deployment it was released through;
     - the Package pinned, if any;
     - for every Configuration released, its name and the content hash of the
       revision released.
   - Operator intent survives a Server restart.
   - The Configuration store retains every revision an assignment still
     references, and collects the others when the last reference goes.
   - Editing a Configuration or a Deployment after a rollout changes nothing on
     any Agent. The fleet view shows the change waiting.

6. **Restates ADR-0025 clause 5 and ADR-0026 clause 29. Rollout acts name a
   Deployment, and only a Deployment.**
   - `POST /api/v1/deployments/{name}/rollout` releases to every Agent the
     Deployment claims and would move, and skips Agents another Deployment also
     claims. It answers `assigned_agents`.
   - `POST /api/v1/agents/{instance_uid}/rollout` releases the Deployment that
     claims that Agent. An empty body or `{"deployment": "<name>"}` naming that
     Deployment are both accepted. Naming another Deployment, or an Agent in no
     Deployment or in conflict, is `409`.
   - A rollout **replaces** the Agent's assignment. It pins two things as of the
     press: the Package the Deployment holds for the Agent's type, if it is a
     candidate by ADR-0025 clauses 9–13; and every Configuration of the
     Deployment that fits the Agent's type, at its saved revision. A
     Configuration no longer in the Deployment leaves the Agent's map. The hash
     gates send only what changed.
   - Where the Deployment holds a Package for the Agent's type that is no
     candidate — the Agent already runs it, or it would move the Agent backwards
     — the Package the assignment already pins stays pinned. A press must not
     drop the pin of what an Agent installed (ADR-0025 clause 17). Where the
     Deployment holds no Package for the Agent's type, the pin goes.
   - A release that holds neither a Package nor a Configuration for the Agent
     leaves it with no assignment: it is offered nothing and keeps running what
     it runs. Nothing it was given is removed, so the fleet view shows what it
     keeps as `kept`, never as `remove` (clause 10).
   - The per-Agent act that would change nothing because the Package held for
     the Agent is no candidate is refused (`409`) with the version reasoning
     ADR-0025 clause 16 requires.
   - Two cases are refused (`409`) for every act, and nothing is released:
     - a Deployment holding no Package and no Configuration;
     - a Deployment in which an entry of a Package it holds carries no signature
       ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)).
       The message names each such Package by its display name and the platforms
       it is unsigned for.
   - `POST /api/v1/configurations/{name}/rollout` no longer exists (`404`). A
     bare Package or Configuration cannot be named in an act.

7. **Restates ADR-0026 clause 31. A Deployment freezes nothing that a standing
   offer travels with.**
   - An assignment pins the Package and the revisions, and the signature is the
     entry's (ADR-0033). So the Selector, the Packages and the Configurations of
     a Deployment stay editable in every state.
   - Swapping the version a Deployment holds, or the revision of a
     Configuration, shows as waiting for the Agents already released, and the
     next press moves them.
   - Deleting the Deployment itself is clause 8's rule.

8. **Restates ADR-0025 clause 7. Nothing an assignment pins can be deleted, and
   taking content away never uninstalls.**
   - Deleting a Configuration, a Package or a Deployment is refused (`409`)
     while any Agent's assignment names it. The message says how many Agents pin
     it.
   - The way to delete is to roll those Agents out through a Deployment without
     it, or to forget them ([ADR-0024](0024-the-fleet-record.md)).
   - A deleted Configuration or Package leaves every Deployment that held it.
   - Nothing recalls what an Agent installed: the protocol has no revert, and
     the Agent keeps running it. A rollout that drops a Configuration from an
     Agent's map and keeps another one is an active change: the smaller map is
     applied. One that keeps nothing for the Agent leaves it with no assignment
     and applies nothing (clause 6).

9. **Restates ADR-0023 clause 12. The Configuration routes.**
   - `GET /api/v1/configurations` lists them in name order, each with the
     Deployments that hold it.
   - `GET /api/v1/configurations/{name}` returns one, or `404`.
   - `PUT /api/v1/configurations/{name}` creates or replaces one from a body of
     `body`, `role` and `service_name`. Unknown fields are refused, and a
     `selector` is refused (`400`) with a message naming the Deployment as where
     to aim. The answer is `200` with the stored view, `400` for an invalid name
     or an empty body, or `500` when the Configuration cannot be persisted.
   - `DELETE /api/v1/configurations/{name}` answers `204`, `404`, or `409` under
     clause 8.

10. **Restates ADR-0023 clause 13, ADR-0025 clause 20 and ADR-0026 clause 33.
    The bundled UI splits along the same seam.**
    - The Configurations tab is a master table and a detail form of content:
      name, Agent type, role, body, and the Deployments that hold each
      Configuration. It has no Selector and no rollout press.
    - The Deployments tab is a master table and a detail form. The form holds
      the Selector, the Packages and the Configurations, each added and removed
      in place.
    - The per-row rollout press sits beside the Deployment's counts, never in
      the form.
    - Each Agent row shows what is rolled out to it and what waits, per
      Configuration and for the Package: `new`, `update`, `remove` — dropped
      from a release that keeps something else, so the smaller assignment is
      applied — or `kept` — the release holds nothing for the Agent, so the
      press leaves it with no assignment and it keeps running what it runs. It
      also shows the Deployment the press releases through when the assignment
      names another one, even where the content stays the same. Whatever makes a
      press move the Agent shows here, with a per-Agent _roll out_ press, so the
      count beside a Deployment's press and the rows agree.
    - _Save_, _Upload_ and _OK_ never distribute.

**Out of scope:** a fleet-wide base Configuration, and any "everyone"
Deployment; releasing only a Deployment's Configurations or only its Packages;
parameters and blocks in a Configuration (the specification's G-18, a decision
of its own); where Deployments, Configurations and assignments are stored, which
the storage decision settles; carrying today's Configuration Selectors over,
which the migration lists for the operator because they do not translate.

## Alternatives considered

- **A Configuration without an Agent type reaches every Agent of its
  Deployment** (ADR-0023's "unset means every type"). It keeps cross-type
  content, a certificate bundle for instance, in one Configuration. But a body
  written for one agent's language reaches agents of another, which is rarely
  what an operator meant; the human made the type required.
- **Keep two paths, and only clean up names and the UI.** This is the status
  quo: two targeting rules, three presses, and a specification sentence that is
  untrue.
- **A separate policy object for Configurations beside the Deployment for
  Packages.** Each would get the at-most-one rule, but an Agent would then
  belong to two partitions, which can disagree about it.
- **A rollout option that releases only the Configurations or only the
  Packages.** It was not chosen, because the hash gates already send only what
  changed. The option can be added to the act later without changing the model.
- **A fleet-wide base Configuration, as an empty Selector or an implicit
  "everyone".** It brings back the ranking ADR-0026 removed (clauses 24 and 25).
  The human chose to solve such a need differently later.
- **Keep cascading deletion for Configurations and Packages.** It was cheaper to
  use, but a deletion silently changed what running Agents receive. The
  protection the Deployment already had now applies to all three.
- **Pin the Deployment and resolve its content at offer time.** This would need
  less in each record. But editing a Deployment would then change running Agents
  without a press, against ADR-0025's explicit act.

## Sources / Prior art

- ADR-0023 clauses 1–13, ADR-0025 clauses 1–20, and ADR-0026 clauses 22–33, with
  its alternative "Deployments carry Configurations too".
- Elastic Fleet: Agent policies, one per Agent, with revisions; Agent upgrades,
  and the policy's `required_versions` (target version and percentage, generally
  available since 9.1) —
  <https://www.elastic.co/guide/en/fleet/current/upgrade-elastic-agent.html>,
  <https://www.elastic.co/docs/api/doc/serverless/operation/operation-put-fleet-agent-policies-agentpolicyid>.
- Bindplane: progressive rollouts by label-selected stages —
  <https://docs.bindplane.com/feature-guides/deployment-and-management/progressive-rollouts>.
- OpAMP specification: `AgentRemoteConfig` with `config_hash`,
  `PackagesAvailable` with `all_packages_hash`, two independent messages.
- The working note of 2026-10-17 on the Server's data model, in which the human
  chose each point.

## Consequences

- Positive: one way to aim, one press, and one answer to "what does this host
  run". The specification's sentence that a Deployment is the only thing rolled
  out becomes true.
- Positive: a Package and the Configuration that needs its version arrive in the
  same release.
- Positive: no deletion changes what a running Agent receives.
- Negative / trade-offs: an Agent in no Deployment receives no Configuration
  either. A fresh enrolment needs a Label, an attribute or a subject value that
  places it in a Deployment.
- Negative / trade-offs: today's Configuration Selectors do not carry over. The
  migration lists each one, and the operator places it in a Deployment.
- Negative / trade-offs: deleting something in use takes two steps, a rollout
  without it and then the deletion.
- Follow-ups:
  - Parameters and blocks in a Configuration (G-18).
  - The storage of Deployments, Configurations and assignments, and their
    migration, in the storage decision.
  - A per-part rollout option, if one is ever needed.

## Enforcement

Tests that will carry `Verifies: ADR-0034`:

- A Deployment holding a Package and two Configurations, one typed for another
  Agent type, rolls out to an Agent: the Agent receives the Package and the one
  fitting Configuration.
- Changing only a Configuration's body and rolling out again sends a new config
  map and no new package offer; changing only the Package does the opposite.
- A rollout of a Deployment that no longer holds a Configuration drops it from
  the Agent's map.
- A Deployment that keeps nothing for an Agent shows what it pins as `kept`, and
  the press leaves it with no assignment and offers it nothing.
- A Deployment that newly claims an Agent with the content it already pins shows
  as waiting, and is counted as the Agents its press would move.
- `PUT /api/v1/configurations/{name}` with a `selector` is `400`; the
  Configuration rollout route is `404`.
- Deleting a pinned Configuration, Package or Deployment is `409`. After a
  rollout without it, the deletion succeeds and removes it from every
  Deployment.
- The per-Agent act on an Agent in no Deployment, or in conflict, is `409`.
- Editing a Deployment after a rollout changes no Agent's offer until the next
  press.
