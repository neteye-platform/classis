# ADR-0025: A rollout is an explicit act per Agent that pins what it releases, and a package reaches an Agent only when it fits, is aimed at it, and moves it forward from what it runs

- **Status:** 🟢 accepted · clauses 2, 5, 7 and 20 superseded by [ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md) · clauses 9 and 14 superseded by [ADR-0043](0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)
- **Date:** 2026-10-10
- **Deciders:** Markus Brigl
- **Applies to:** the assignments and rollout acts in `crates/fleet-server/src/fleet.rs`, the saved and retained revisions in `crates/fleet-server/src/configs.rs`, the matching and offer functions of `crates/fleet-server/src/packages.rs`, the rollout routes of `crates/fleet-server/src/api.rs`, the persisted Agent record, the rollout column of the bundled UI, the Client's check of an offer for its own package

## Context

Two questions decide what an Agent runs: **when** a saved Configuration or package reaches it, and
**which** package can reach it at all.

*When.* A Server that offers whatever is stored — or whatever was once marked published — converges
every matching Agent automatically: the WebSocket loops wake, polling recomputes each offer on every
exchange, and an Agent that enrols next week takes the content without anyone deciding that it
should. The operator requirement is stricter than any standing state can express: saving must never
distribute, not on first save and not on a later edit; the fleet view must show per Agent what
could be rolled out to it; distribution happens only when the operator says so — per Agent, or for
every Agent a resource currently aims at; and packages and Configurations follow one model. A
standing property of the *resource* cannot hold for one Agent and not another, and keeps
distributing to Agents that appear later.

*Which.* A package fits an Agent by type and platform
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) clause 9) and is aimed at it by the operator. Fit and aim
alone would count Agents that already run the version, propose it to Agents that need nothing, and
let the act aim backwards under the same label as a forward one — the shape in which a compromised
Server pushes a known-vulnerable build, and one the Client's own install already refuses, because
an Ed25519 signature carries no version ordering and an old release stays validly signed forever.

An Agent reports two versions, and they can contradict each other. `PackageStatus.agent_has_version`
is derived from what an install once wrote — for the Client `<state_dir>/installed-package.json` —
and that record outlives the binary it describes: a staged update that did not take, a host
reinstalled from an older artifact, a state directory restored beside a downgraded binary. The
Baseline defines the field as *"the version of the package that the Agent **has**"*, which *"MUST be
empty if the Agent does not have this package"* — a statement about the present. `service.version`
is the running program's own statement about itself. Clients released before the one that reports
its own package version can state only the latter, and the code that would report the former is
the code they do not have.

## Decision

We will make the rollout the one act that distributes — saving only saves, and per Agent the Server
persists what the operator released, pinned, and composes every offer from that — and we will let a
package become a candidate for an Agent only when it fits, is aimed at it, and is strictly greater
than the version the Agent reports running (or, where that cannot be ordered, than the version it
claims to have).

1. **Saving only saves.** A Configuration holds one revision, the saved one; there is no draft and
   no published state for anything. A `PUT` on a resource — a Configuration, a package, an entry —
   changes what *could* be rolled out and never what *is*. A Selector edit, a label move and an
   enrolment likewise change only what is proposed; no WebSocket loop wakes for any of them.

2. **The assignment is per Agent, persisted, and pins a snapshot.** In each Agent's record
   ([ADR-0024](0024-the-fleet-record.md)) the Server stores what has been rolled out to it: per
   Configuration name, the content hash of the revision released to it; for packages, the concrete
   package released. Operator intent survives a Server restart like a queued restart does. The
   Configuration store retains every revision an assignment still references and collects the
   others when the last reference goes. Editing a Configuration after a rollout changes nothing on
   any Agent; the fleet view shows the newer save waiting. An approval binds a concrete version,
   never "latest".

3. **Offers are composed from assignments only.** An Agent's composed config map and its hash, and
   its package offer and `all_packages_hash`, are computed over **that Agent's** assignments — never
   over stored content and never over a fleet-wide aggregate, which would re-offer on every exchange
   what this Agent is never given. The hash gates (no redundant reconfiguration, no re-offer) work
   unchanged over the assigned content. An assigned package is offered as the entry for the Platform
   the Agent reports; an Agent reporting a Platform the assigned release does not hold is offered
   nothing rather than something else. Matching survives intact, but it only computes the
   **candidate**: what an act would assign if the operator rolled out now.

4. **The fleet view shows, per Agent, what is waiting.** For every Agent the Server derives candidate
   against assignment and reports each difference: a Configuration not yet rolled out (`new`) or
   whose saved revision differs from the assigned one (`update`); a package not yet rolled out or a
   different version than the one assigned. The gap between "could run" and "was released" is shown
   and never acted on by the Server alone.

5. **Two rollout acts, one meaning.** `POST /api/v1/agents/{uid}/rollout` releases to one Agent: a
   named Configuration, or — with an empty body — everything waiting for it. A resource's own
   `rollout` sub-resource releases it to **every Agent it currently fits and aims at** — for a
   Configuration `POST /api/v1/configurations/{name}/rollout` — as a bulk write of the same
   per-Agent assignments, answering how many Agents it assigned (`assigned_agents`). Both pin the
   content as of the press and wake the WebSocket loops. A named resource that does not fit or aim
   at the Agent is `409`, an unknown one `404`. A package with no entries is never rolled out.

6. **An Agent that appears later waits.** A newly enrolled Agent, or one that starts matching after
   a Selector edit or a label move, is assigned nothing until an operator's act; it surfaces in the
   fleet view with everything it could receive marked waiting. Widening an aim is never a
   distribution event.

7. **Taking content away says what it does.** Deleting a Configuration removes every assignment that
   referenced it; that is an active change — an Agent still assigned other Configurations applies
   the smaller map, its entry file is removed and the process restarts — and only an Agent left
   assigned nothing keeps running what it runs. Taking a package away **never uninstalls
   anything**: deleting a package removes every assignment that referenced it and withdraws the
   offer, and neither that nor deleting whatever released it recalls what an Agent installed — the
   protocol has no revert, and the Agent keeps running it.

8. **Immutability follows the assignment.** A package assigned to at least one Agent has immutable
   entries: uploading, referencing or deleting an entry is refused (`409`, saying to create the next
   version as a new package and roll that out), and an upload is refused before its bytes are
   streamed. A package assigned to nobody is freely editable.

9. **A package becomes a candidate when it fits, is aimed at the Agent, and moves it forward.**
   Fit is [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) clause 9's, mandatory and first. The version test
   (clauses 10–13) runs *with* the fit: a package it holds back is nobody's candidate and appears in
   no count and no proposal.

10. **What the Agent runs decides, in both directions.** Where the Agent reports a `service.version`
    among its identifying attributes that parses as a version ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)
    clause 9), the package's version must be **strictly greater** than it by SemVer precedence,
    build metadata ignored. Equal does not match: a package the Agent already runs would reach it
    with nothing.

11. **The claim is not consulted where the running version is.** A non-empty `agent_has_version`
    neither admits a package the running version refuses nor refuses one it admits. A record about
    the past does not overrule, and has no veto over, a statement about the present — so a host
    whose package status claims a version its own program denies running is reachable in either
    direction.

12. **Where the running version cannot be ordered, the claim is the whole test.** A
    `service.version` that does not parse (`1.19`, `24.04.1`) says nothing at all. The package is
    then held against the non-empty `agent_has_version` the Agent reports under the package's wire
    key: strictly greater to match, and a claim that cannot itself be ordered **refuses** — the safe
    direction for a claim about that very package: what cannot be ordered must not be installed over
    what is running.

13. **An Agent that reports neither has nothing to be greater than** — the first rollout, matched on
    fit and aim alone. An **empty** `agent_has_version` is that case, not an unorderable one: it is
    how a package offered, pending or downloading but not yet installed is reported.

14. **A package is numbered in the space its program numbers itself.** For a program that
    self-reports an orderable version — the Client and any OpAMP-aware Managed Process — a package
    numbered below it can never reach it. An operator numbering a package by hand takes the
    program's own number; `opamp-fleetctl package fetch` already names a release that way
    ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)).

15. **The Client applies the same rule to an offer it receives.** For the package that carries the
    Client itself ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)), *already installed* means the
    version this process runs is the offered one — not that a recorded package hash matches. A record
    whose hash equals the offer does not end the offer on a host that is not running it.

16. **Every consumer of matching applies the same test.** The candidate resolution, the reach count
    and the rollout act test alike, so the count, the proposal and the press cannot disagree. A
    per-Agent refusal names the version it compared against and whether that was the running version
    or the claim — and, where both were reported and disagreed, that the claim was not consulted. The
    bulk act skips an Agent it would not move.

17. **The assignment path is version-blind.** An offer composed from an assignment is never filtered
    by the version test: an offer is the Agent's desired state, and dropping an installed package
    from it would tell the Agent the package is no longer wanted. Matching decides what *may become*
    an assignment; it never edits one that exists.

18. **Rollback is not a rollout.** No act moves an Agent to an older version than it runs. An
    operator who wants an Agent back on its predecessor has the Agent's retention window
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)) and, for the Client itself, the pointer move
    of [ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md); a bad version is otherwise taken back by
    publishing the old content as a new, greater version. A deliberate Server-driven downgrade is
    left undecided: it is a separate act with its own authorisation question, and it must never be
    the same press as a rollout.

19. **Zero has more than one meaning, and the view says which.** Where the Server reports whom a
    rollout would reach, it reports both the Agents the resource fits and aims at, version-blind,
    and the Agents an act would actually move. Zero of the first is the aim mistake worth hunting (a
    misspelled type, no entry for any reported platform, an aim no Agent matches); zero of the
    second with Agents aimed at means everyone is up to date — stated plainly, not as a warning. The
    count beside a rollout button is exactly what that button would move.

20. **The bundled UI splits along the same seam.** *Save*, *Upload* and *OK* never distribute. Each
    Agent row shows what is rolled out to it, what waits (`new` or `update`), and a per-Agent
    *roll out* press. A resource's rollout press sits on its table row with its count, never in the
    edit form: the press that changes the fleet is one press, and it is never the press that carries
    the bytes or the text.

**Out of scope:** how a package is aimed and which object its resource-level act names
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)); what a package and its entries are
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)); an opt-in convergence policy for Agents that appear later;
a batched or paused progressive walk; an audit trail of who rolled out what (the operator plane has
no per-operator identity); an operator override to re-install a version the test holds back; a
Server-driven downgrade.

## Alternatives considered

- **A publication gate on the resource** (draft until published, or a draft and a published
  revision). It answers "may the fleet have it?" once, for the whole fleet, forever — it cannot hold
  for one Agent and not another, keeps distributing to Agents that appear later, and leaves two
  lifecycles to hold in mind. Keeping it and adding a per-Agent gate behind it answers no question
  the assignment does not.
- **A standing assignment — "this Agent follows this resource".** Saving would then distribute to
  every assigned Agent, which the requirement forbids; this is Flux's suspend/resume, a gate on
  time, not content. WSUS, Jamf, Bindplane and Chef environments all pin instead.
- **A standing "roll out to all matching, including future matchers" flag.** Publication under a new
  name: an Agent enrolling later takes content nobody released to it.
- **Cohort-level approval only.** Cannot express "this one canary host first".
- **Apply the version test to the reach count only.** The count would no longer describe the button
  beside it: an operator reading "0" could still press it and change the fleet.
- **Let `Equal` match**, as a repair for a failed install. A failed install is not repaired by
  re-delivering bytes the Agent has; the assignment is in place and the Agent's own retention and
  rollback govern what follows. Every up-to-date Agent would be back in every count.
- **Compare against `agent_has_version` alone.** Cannot reach a Client that reports no package
  version, and believes a claim the Agent's own program contradicts.
- **The lower of the two versions, and never move under a claim.** Refuses a package below a claim
  before the running version is read, stranding a host whose claim is wrong upwards.
- **Let the running version decide only for the Client's own package.** The narrower change; it
  makes the matching rule two rules keyed on which package is matched, and every new agent kind
  arrives with the question of which it falls under.
- **Fix the report instead of the rule** (the Client reports the version that came up rather than
  the one staged). Worth doing, but it repairs only claims this Client writes; a reinstall or a
  restored state directory still produces a claim no Client-side fix reaches.
- **Fail closed on an unorderable `service.version`.** Turns a program's numbering habit into a
  fleet that cannot deliver to it, with a symptom that reads like an aim mistake.
- **A per-package "allow downgrade" flag**, or an operator override on the act. A standing second
  mode on the resource where the rule was asked for; an override is unavailable to the bulk act and
  the count. A downgrade, if wanted, is its own act.

## Sources / Prior art

- [WSUS update approval](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/3-approve-and-deploy-updates-in-wsus)
  — nothing reaches clients until an explicit approval, which binds a concrete update; "All
  Computers" is the widest form of the same act. [WSUS updates operations](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/updates-operations)
  — the population read is the computers that **need** an update.
- [Argo CD manual sync](https://argo-cd.readthedocs.io/en/stable/user-guide/auto_sync/) and
  [selective sync](https://argo-cd.readthedocs.io/en/stable/user-guide/selective_sync/) — drift
  displayed as OutOfSync, nothing applied until Sync; the model for clause 4.
- [Bindplane rollouts](https://docs.bindplane.com/feature-guides/deployment-and-management/rollouts)
  — edits create a version, collectors keep the old one, deployment starts on an explicit act.
- [Jamf Pro patch policies](https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Patch_Policies)
  — new versions reported without distribution; deployment binds one version to a scope.
- [Flux Kustomization suspend](https://fluxcd.io/flux/components/kustomize/kustomizations/) and
  [`kubectl rollout pause`](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_rollout/kubectl_rollout_pause/)
  — the time-gated counter-model.
- [Grafana Fleet Management](https://grafana.com/docs/grafana-cloud/send-data/fleet-management/set-up/configuration-pipelines/)
  — the weak-gate counter-model: activation reaches all matching collectors at once.
- [Google Update `RollbackToTargetVersion`](https://chromeenterprise.google/policies/device-rollback-to-target-version/)
  — with the policy unset, "installs that have a version higher than that available will be left
  as-is".
- [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md) —
  `PackagesAvailable` is per Agent, the offered `remote_config` is the Server's composition, hash
  comparison is the anti-redistribution primitive; `PackageStatus.agent_has_version` as quoted in
  Context; an agent package is installed "either to upgrade it to a newer version or to downgrade
  it to an older version".
- [Kubernetes API conventions](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md)
  — `status` is "the most recent observations of actual state"; a controller reconciles against the
  observation, not a record of intent.
- OpenTelemetry semantic conventions, `service.version` — "the version string of the service API or
  implementation".

## Consequences

- Positive: nothing distributes by side effect — not a save, a Selector edit, a label move or an
  enrolment. The canary workflow is "roll out to one Agent, watch it, then roll out to all".
- Positive: the count means what it says, the proposal is only ever work, and neither the view nor
  the act moves an Agent backwards by the press that moves it forward — measured against what the
  Agent runs. A stale claim does not strand a host in either direction.
- Negative / trade-offs: every new Agent needs an operator's press before it runs anything, and the
  resource-level press must be repeated after new Agents appear.
- Negative / trade-offs: per-Agent state diverges across the fleet by design — ten Agents on three
  pinned revisions is an intended state the view must keep legible.
- Negative / trade-offs: a Managed Process numbered above its package can be moved backwards — a
  Collector reporting `0.98.0` while its status claims `2.0.0` matches a package at `1.5.0`. What
  limits it is that nothing moves on its own. Conversely, a program self-reporting a number above
  its package is unreachable by that package's number until the package is re-created at the
  program's number (clause 14). Icinga 2 and the GLPI Agent report no `service.version`, so for them
  the claim decides as before.
- Negative / trade-offs: a program already running a version cannot be replaced by the fleet's
  package of that same version; adopting it means publishing under the next version.
- Follow-ups: an opt-in convergence policy for late Agents; a progressive walk; an audit trail once
  the operator plane has an identity; a diff view between an Agent's assigned revision and the saved
  one; the Client reporting the version that came up after a self-update rather than the staged
  one; showing the package status and the reported `service.version` side by side where they
  disagree; an operator override for a genuine reinstall.

## Enforcement

- `crates/fleet-server/src/configs.rs`: `a_saved_configuration_reaches_nobody_without_an_assignment`,
  `an_assignment_pins_a_snapshot_and_later_edits_wait`, `retain_only_collects_unreferenced_revisions`,
  `candidates_follow_the_fit_and_none_means_nothing_to_roll_out`.
- `crates/fleet-server/src/fleet.rs`: `rollout_acts_assign_and_a_late_agent_waits`.
- `crates/fleet-server/tests/rest_api.rs`: `a_configuration_waits_until_it_is_rolled_out`,
  `an_agent_that_appears_later_waits`, `a_label_moves_an_agent_into_a_rollout_ring`.
- `crates/fleet-server/src/packages.rs`: `a_saved_set_reaches_nobody_without_an_assignment`,
  `fits_agent_checks_fit_but_neither_aim_nor_the_ranking`,
  `fits_agent_refuses_what_is_not_an_upgrade`, `a_set_that_is_no_upgrade_is_no_candidate`,
  `a_set_is_held_against_the_version_an_agent_reports_running`,
  `the_version_an_agent_runs_wins_over_the_version_it_claims`,
  `a_claim_the_running_program_denies_no_longer_holds_the_set_back`,
  `a_claim_above_the_set_no_longer_holds_it_back_either`,
  `a_program_version_nothing_can_order_leaves_the_set_reaching`,
  `the_aggregate_hash_is_per_agent_and_follows_the_assignment`.
- `crates/fleet-server/tests/packages.rs`: `a_set_reaches_an_agent_only_as_an_upgrade`,
  `a_set_waits_until_rolled_out_and_is_immutable_while_assigned`,
  `the_act_names_the_version_it_releases`,
  `the_aggregate_hash_an_agent_echoes_is_the_one_it_was_offered`.
- `crates/fleet-agent/src/supervisor/agent.rs`:
  `the_clients_own_offer_is_settled_by_the_version_it_runs_not_by_a_recorded_hash`;
  `crates/fleet-agent/src/update/installer.rs`: `install_refuses_a_downgrade`.
