# ADR-0017: Supervisor Mode is a hexagonal core whose compiled-in kinds are the authority on their own agents, each Supervisor owns one directory and runs only a program installed there, and the Server manages the set and each Supervisor's configuration only as far as the package signature and the host allow

- **Status:** 🟢 accepted · clause 34 superseded by
  [ADR-0043](0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)
- **Date:** 2026-10-10
- **Deciders:** Markus Brigl
- **Applies to:** crates/fleet-agent/src/supervisor/ (core, ports, process
  runner with its preflight, version probe and process-group stop, endpoint,
  placeholders, start, every kind and the delivered-block check
  (`check_delivered_block`) each kind states, the Client's own Agent in
  `build_engine`, the capability set and the handling of a received or stored
  remote configuration of the Client's own Agent and of a Supervisor's Agent in
  agent.rs), crates/fleet-agent/src/config.rs (supervisor_dir, program
  resolution, the `server_manages_set` and `remote_config_disabled` keys),
  crates/fleet-agent/src/reconfigure.rs (the Supervisor-set apply), the stored
  `remote-config.pb` and entry files in crates/fleet-agent/src/storage.rs, the
  `[[supervisor]]` blocks and the `[supervisors]` section of supervisor.toml
  (among them `delivered_env`, `delivered_args`, `server_manages_set` and
  `remote_config_disabled`), the `[features]` table of
  crates/fleet-agent/Cargo.toml, the artifact documents under docs/artifacts/
  each wrapped kind adds

## Context

The Supervisors that
[ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
binds are the reason the client side exists: many Managed Processes per Client,
each appearing to the Server as its own Agent, multiplexed by `instance_uid`. A
Managed Process takes one of three integration paths
([specification vocabulary](../SPECIFICATION.md)): a Collector carrying the
`opampextension`, which reports its own description, health and effective
configuration to the Supervisor Endpoint; a Collector without it, observed from
the outside; and a Foreign Agent under a Custom Supervisor, whose lifecycle,
configuration and health a Plugin translates into OpAMP.

The specification asks for a hexagonal core: the supervision domain written
against two Ports, the Server-facing side speaking OpAMP and the Managed-Process
side (lifecycle, configuration, health), with Plugins as adapters.
[ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
keeps such seams as modules until a need makes them crates and requires a typo
in the hand-edited TOML to fail loudly at startup. serde cannot combine
`#[serde(flatten)]` with `deny_unknown_fields` (serde-rs/serde#1547), so a block
whose kind-specific keys sit beside the common ones cannot be one strict struct.

The reference `opampsupervisor` runs a local OpAMP server on
`ws://127.0.0.1:{{port}}/v1/opamp` (WebSocket only), passes configuration to the
Collector via `--config`, restarts it on a configuration change, stops it with
SIGTERM then a kill after a timeout, and watchdog-restarts it with exponential
backoff. It configures its agent generically — an absolute `agent.executable`
plus `args` — because it supervises a binary somebody else installed. This
Client is in the opposite position: it installs every program it supervises,
into a directory it owns, from an artifact this project packs (clauses 21 and
24). It is the one end that can know an agent's layout, and
`opamp-fleetctl package fetch` already carries per-agent knowledge (service
name, release source, default Configuration names). Writing that knowledge into
every host's TOML by hand — one block per platform for an agent whose invocation
differs by platform, one key per layout path for an agent that has to be
relocated — is a transcription that goes stale when an artifact moves.

Agents differ in how they are installed, configured, reloaded and removed. Some
re-read their configuration on a signal and lose buffered state when restarted;
systemd treats reload as first-class beside restart (`ExecReload`,
`reload-or-restart`). OpAMP itself only ever drives configuration and packages,
and its only process command is restart.

Agents also differ in how they run. A program that forks a worker can leave it
behind when only its own pid is killed, holding the agent's data and ports. A
package built against a newer system library than a host carries fails only when
it starts, with the dynamic linker's message, and an update that finds this out
after the swap has already stopped what ran. Not every program prints its
version as Semantic Versioning.

A package update swaps files: the running program is renamed aside, the artifact
is written beside it and renamed into place
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
All of that needs write permission on the **directory**. A program in a system
directory such as `/usr/local/bin` cannot be updated by a Client that does not
run as root, and the failure would appear at rollout time on every matched host
rather than at startup on one. A Client that also supervised programs installed
by someone else would have two kinds of Managed Process — one it can update,
roll back and health-gate, one it merely runs — and every package, version and
rollback decision would carry both cases. Repacking vendor software into
relocatable trees (clause 24) brings such agents under fleet ownership instead.

`state_dir` is state: hardened hosts mount `/var/lib` `noexec` and size it for
state, not for several Collector binaries. An artifact staged under one
filesystem and installed on another is copied, a second full write of a program
of several hundred megabytes.

A Foreign Agent is told where its configuration is through its own command line,
and an absolute path written there drifts silently when the Supervisor's
directory moves or the Supervisor is renamed: the process starts happily on a
file nobody writes to.

What the fleet needs to manage on a Client is which Supervisors it runs.
Everything else in `supervisor.toml`
([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md))
— the Server endpoint, the credential, the state directory, the instance name —
is host-local trust and wiring; a Server that could rewrite it could cut a
Client off with one bad push. The specification allows an Agent's effective
configuration to "merge in local configuration". The program a Supervisor spawns
is itself a trust anchor: a Server — or someone who has compromised it without
the package-signing key — that could name any program on the host would have
fleet-wide code execution that bypasses signature verification entirely.

Keeping a delivered block to a program from its own directory — a program that
arrived as a signed package — prevents the "fleet-wide code execution that
bypasses signature verification entirely" the paragraph above describes. It is
not enough on its own: a block's `env` and `args` would pass to that program
unchecked, with placeholders expanded in both (clause 26). A Server that
delivers a shared object as a configuration entry and then a block with
`LD_PRELOAD` pointing at it has the loader run that object as the Client's
account — root or LocalSystem by default — and any signed program that loads a
plugin or a script named in its arguments reaches as far. A kind setting that
names a file the Supervisor reads reaches as far as the host's files: a kind
that reads such a file and sends its content to a peer the block names sends
whatever file a delivered block points it at, to whatever peer that block names.
Both were found by measure H14 of [`HARDENING.md`](../HARDENING.md) and recorded
as H21 and H22. The specification puts security before convenience; what a
compromised Server can make a Supervisor block do on a host must stop at the
signature. What an Agent's own configuration language allows its process to do
stays the product's.

A host must be able to keep its Supervisor set from the Server, while clause 33
makes the Server's set authoritative for a Client once an offer has applied. Who
manages a host's Supervisor set is one question, answered for the fleet and, by
a switch, for one host (clauses 41 to 47). Which Supervisors take their
configuration from the Server is a question of the same host-local section,
answered per Supervisor by clauses 48 to 55.

A remote configuration is one of the channels by which the Server causes code to
run on a host ([`HARDENING.md`](../HARDENING.md), _The channels that put code on
the host_): the Server can write any files into a Supervisor's own `config/`
directory and restart its process, and what the agent's configuration language
allows — a Telegraf `inputs.exec`, an Icinga `CheckCommand`, a Collector
receiver bound to any port — it allows as the process's account. Package
delivery on the same channel stops at a signature the operator's key makes
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md));
a remote configuration has no such stop. An operator may run an agent whose
configuration is too sensitive to take from a compromised Server, or which
another system already configures, and every Supervisor's Agent declaring
`AcceptsRemoteConfig` as part of the constant `AGENT_CAPABILITIES` gives the
host no way to say so. A switch per Supervisor binds a name, not an agent, while
the Server manages the set: the Server can remove a listed Supervisor and
deliver the same agent under another name, which is not listed. Through the set
the Server adds, changes, restarts and purges Supervisors on the host (_The
channels that put code on the host_). The specification puts security before
convenience (Q-1), and the Baseline allows remote configuration to be switched
off: _"Remote configuration capability can be disabled if necessary"_ (OpAMP
specification, _Configuration_).

What the Server may change on a host is bounded by what the host takes, not by
what the Server sends. The Server manages the set of `[[supervisor]]` blocks
through the Client's own Agent, and every other key of `supervisor.toml` — among
them the `[supervisors]` section — is host-local and out of its reach (clause
27). A switch written inside a `[[supervisor]]` block would be one the Server
can delete by delivering the block again without it. The switches therefore live
in `[supervisors]`, the one per Supervisor keyed by the Supervisor's `name`,
which is unique across blocks and names its directory (clause 3).

The Client's own Agent is built by `AgentState::new` in
`crates/fleet-agent/src/supervisor/agent.rs` and declares the constant
`AGENT_CAPABILITIES`: `ReportsStatus`, `AcceptsRemoteConfig`,
`ReportsEffectiveConfig`, `ReportsRemoteConfig`, `ReportsHealth`,
`AcceptsOpAmpConnectionSettings`, `ReportsConnectionSettingsStatus` and
`ReportsOwnMetrics`, `ReportsOwnTraces` and `ReportsOwnLogs`. `build_engine` in
`crates/fleet-agent/src/supervisor/mod.rs` adds `ReportsHeartbeat` when
heartbeats are enabled, and `AcceptsPackages` with `ReportsPackageStatuses` when
`[self_update]` consents and a verification key is configured
([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). Its
effective configuration is the redacted text of `supervisor.toml`. Only
`AcceptsRemoteConfig` and `ReportsRemoteConfig` concern the set. Clauses 50 and
51 build the same mechanism for a Supervisor: `AgentState` can be restored
without both bits, and then ignores an offer that arrives anyway and logs it
once per hash in a bounded set (`ignored_configs`).

The Client's own Agent stores an applied set too. `config_applied` writes it
with `store_remote_config` once the Supervisor-set apply succeeded:
`remote-config.pb` and one copy of each entry under `config/`, both in
`state_dir`. Nothing runs on those files, since the set they carry is already in
`supervisor.toml` (clause 31). Restoring them at start reports
`RemoteConfigStatus` `APPLIED` with the stored hash, which tells the Server the
Client runs that set, and the Server offers a set only while the reported hash
differs ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 6).

The Server offers a remote configuration only to an Agent declaring
`AcceptsRemoteConfig` ([ADR-0023](0023-configurations-and-the-rest-api.md)
clause 6, `offer` in `crates/fleet-server/src/fleet.rs`), as the Baseline
requires, and a Client's capabilities bind what it reports and acts on
([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
clauses 12 and 17); the same rule read the other way means an Agent that does
not declare a capability does not act on it. A Client whose own Agent, or a
Supervisor's Agent, does not declare the bit is therefore offered no remote
configuration, with no change on the Server.

What a Supervisor runs without a remote configuration follows from how each kind
finds its configuration. Every kind reads it from the Supervisor's own `config/`
directory, `<supervisor_dir>/<name>/config/` (clause 21), where
`store_remote_config` writes one file per entry and records roles in
`.supplementary` ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 9):

- `collector` passes every unroled file in `config/` as its own `--config`, then
  the block's `args`; with no such file it does not start and reports _awaiting
  configuration_ (`collector_spec`, clause 6).
- `command` always starts with the block's `args` and `env`; whatever
  configuration the Foreign Agent reads is the one those arguments name,
  `${config_dir}` included.
- a wrapped kind points its agent at the entry its own ADR names, or at a root
  it finds by a role its ADR defines. With no such entry it either does not
  start and reports what it awaits, or starts the agent and the Runner reports
  its exit, as its ADR decides. A setting of a wrapped kind that names a file
  the Supervisor reads is the block's, wherever it points.

A Supervisor's stored `remote-config.pb` itself is read by no kind. It restores,
at start, the `RemoteConfigStatus` `APPLIED` with the stored hash and the
configuration the Agent echoes as its effective one (`AgentState::new`). What a
kind runs on is the entry files beside it. Ignoring the `.pb` alone would leave
a listed Supervisor running the Server's last configuration from those files.

A `[[supervisor]]` block configures its process too, not only the files in
`config/`, and the Server delivers the blocks. A `collector` or `command` block
does it through `args` and `env`: a Collector reads a whole configuration from
`--config=yaml:…` or `--config=env:VAR`, and where the operator set
`[supervisors] delivered_args` or `delivered_env`, a block the Server delivers
may bring new ones (clause 38). The other keys of a block do it as well. A
setting a wrapped kind keeps is a decision about how its agent runs (clause 16)
— which peer it talks to, under what name, which certificate it trusts. Clause
39 lets a delivered block point a file setting at a file inside its own
`config_dir`. For a listed Supervisor no remote configuration writes that file,
so it does not exist, and a kind that falls back to a weaker default when a
named file is missing then runs the operator's agent on what the Server chose.
For a listed Supervisor any key a delivered block may change is a remote
configuration under another name.

## Decision

We will implement Supervisor Mode as a hexagonal supervision core in the Client
crate whose Managed-Process Port is one closed, channel-based lifecycle
vocabulary served by compiled-in kinds, each Supervisor its own Agent over the
Client's one upstream connection with a WebSocket-only Supervisor Endpoint, make
each kind the authority on its own agent so that a `[[supervisor]]` key exists
only where its value is a decision, give every Supervisor one directory it owns
under a root the operator can place, accept only programs this Client installs
into that directory, point Foreign Agents at it by placeholder, and let the
Server replace the set of `[[supervisor]]` blocks — and nothing else in the file
— purging a removed Supervisor's directory with it, unless the host sets
`[supervisors] server_manages_set = false`, while a delivered block may bring no
environment, arguments or host paths that reach past what its package's
signature covers, and let the operator name Supervisors in
`[supervisors] remote_config_disabled`, whose Agents neither declare nor act on
remote configuration and run only on what the operator placed on the host.

1. **Two Ports, as modules.** The Managed-Process Port is a message pair —
   `ProcessCommand` in, `ProcessEvent` out — plus a `Plugin` factory trait that
   validates a block's settings (`check`, side-effect free) and starts the
   adapter task (`start`). Channels keep the trait object-safe without
   `async-trait`, make every adapter a plain tokio task, and keep the core free
   of process handles. The Server-facing Port is the engine seam the transports
   consume — build reports, handle a `ServerToAgent`, produce disconnects — over
   _n_ Agents.

2. **A compiled-in registry selected by `type`, each wrapped kind a Cargo
   feature.** The kinds are `collector` (the Collector Supervisor), `command`
   (the Custom Supervisor for any Foreign Agent), and the wrapped kinds, each of
   which knows one third-party agent (clause 15). A new process kind is one
   module and one registry line (`registry()` in `supervisor/mod.rs`); the core
   stays untouched. Each wrapped kind is a feature of `fleet-agent` named after
   its `type`, and the default features are all of them, so the published build
   carries every kind and a build that leaves one out is built with
   `--no-default-features --features <kinds>`. A new wrapped kind is a feature
   too, in the default set. `collector` and `command` are always compiled in:
   they are the integration paths the specification names, and `command` runs
   any Foreign Agent no wrapper covers. An unknown `type`, one this build does
   not carry, fails startup naming the known ones. Plugins are not loaded
   dynamically. A build's kinds are what its own Agent reports (clause 18). A
   build that leaves a kind out is published under a package name of its own
   (clause 25); a self-update into a build that lacks a kind a block on the host
   names fails its start and is rolled back like any failed attempt
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).

3. **A block is parsed in two stages.** The core takes the common keys — `type`,
   `name`, `service_name`
   ([ADR-0016](0016-what-an-agent-reports-about-itself.md)), `endpoint_port`,
   `program_path`
   ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)),
   `stop_timeout_secs`, `apply_grace_secs`, `retain_previous_secs` — and the
   program key the kind names (`binary` for `collector`, `command` for
   `command`), which clause 22 resolves. Everything else is the kind's, parsed
   with `deny_unknown_fields`. `name` follows the instance-name grammar of
   [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md),
   because it is a directory name, and is unique across blocks.

4. **Each Supervisor is one Agent; the pool is one connection.** Every
   Supervisor has its own persisted `instance_uid`, `sequence_num` and
   capability set, and all of them ride the Client's single upstream connection,
   disambiguated by `instance_uid` alone — the n-over-m model of
   [ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
   with m fixed at one. The Client's own Agent
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)) is
   always present beside them, with or without any `[[supervisor]]` block. The
   Server needs no Supervisor-specific code.

5. **The Supervisor Endpoint is WebSocket-only on loopback.** Bound for every
   Supervisor at start to `127.0.0.1:<endpoint_port>` (`0`, the default, is an
   ephemeral port), so a taken port fails the start rather than later; accepted
   with `tokio-tungstenite`, no HTTP framework in the Client. It declares
   `AcceptsStatus` and `AcceptsEffectiveConfig`, enforces the message size
   limit, and folds **content, not identity**: a connecting process's
   description, health, effective configuration and available components become
   events of the owning Agent, whose `instance_uid` stays the Supervisor's.

6. **Process management follows the reference supervisor.** Spawn via
   `tokio::process`; watchdog-restart an unexpectedly exited process with
   exponential backoff; stop gracefully with SIGTERM → wait up to the stop
   timeout → kill on Unix, signalling the process group where the kind leads one
   (clause 56), `Child::kill` on Windows. On Client shutdown the Managed
   Processes stop first, then each Agent's `agent_disconnect` goes out, within
   the service managers' stop budgets
   ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)).
   The Collector Supervisor passes each written configuration entry as its own
   `--config` (never a supplementary entry,
   [ADR-0023](0023-configurations-and-the-rest-api.md)), appends its extra
   `args`, does not start before a configuration exists, and manipulates no
   YAML.

7. **Configuration status is health-gated.** `RemoteConfigStatus` is `APPLYING`
   on receipt, `APPLIED` only once the Managed Process has been (re)started on
   the new files and survived the apply grace, and `FAILED` with the error
   otherwise. A process that exits within the grace fails the apply and stays
   supervised.

8. **The lifecycle vocabulary is closed and every operation runs in the kind's
   adapter.** `ProcessCommand` is `ApplyConfig`, `ApplyPackage`, `Restart` (the
   Server's restart command: respawn on the current files, no configuration
   acknowledgement), `Shutdown` and `Uninstall`; `ProcessEvent` carries
   description, pid, health, effective configuration, available components, and
   the outcomes `ConfigApplied`, `PackageApplied` and `Uninstalled`. The shared
   `Runner` implements the whole vocabulary — spawn and watchdog, bounded stop,
   restart as the configuration apply, swap-and-gate as the package install,
   stop-only uninstall — and a kind overrides only the steps its agent does
   differently. A kind that overrides nothing is complete.

9. **Reload is an apply strategy, not a command.** `ApplyConfig` is the only
   configuration operation; the adapter applies it by restart (the default) or
   by a reload its kind knows, with systemd's `reload-or-restart` semantics: a
   reload that cannot be delivered, or a process that dies on it, falls back to
   a restart on the new files. The health gate of clause 7 applies to both
   paths. The mechanism is the kind's alone — `collector` and `command` restart,
   and a wrapped kind reloads on a signal its ADR names or restarts — and no
   block declares one: a signal written for a program the kind knows nothing
   about is the one value whose error is invisible.

10. **Install and update run behind the Plugin, in one contract.**
    `ApplyPackage` hands the adapter a verified artifact and expects a
    health-gated outcome with rollback on failure
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
    The swap on `InstallTarget` (one file or a tree) is the shared default; a
    kind whose installation is not a file swap implements the step itself inside
    the same contract. Resolving the program and declaring `AcceptsPackages`
    stay in the core (clauses 22 and 23), because a capability the Server acts
    on must derive from what the core reads, never from per-kind behaviour.

11. **Uninstall undoes what installing did, and the core purges.** A Supervisor
    removed from the set receives `Uninstall` before its directory is purged
    (clause 34): the adapter stops its process, undoes whatever its installs
    left outside the Supervisor's directory, answers `Uninstalled` and exits.
    The generic uninstall is exactly the bounded graceful stop. An `Err` outcome
    is logged with what could not be undone; it does not hold up the removal. A
    Supervisor that is only changed is stopped, never uninstalled.

12. **The core persists a configuration, the adapter delivers it.** Receiving,
    validating, persisting and status-reporting a remote configuration are OpAMP
    mechanics, identical for every kind, and stay in the core. Everything
    between the written files and the running process — pointing it at them,
    merging, restart or reload, applying through an API — is the kind's.

13. **Derivable means derived, and decided elsewhere means not written here.** A
    value this Client can compute from the kind, the platform and its own layout
    is not a block key, and neither is a value the fleet is the better place to
    set. A block carrying such a key fails at startup with a message naming the
    key and what supplies the value — never a silent override. This covers a
    wrapped kind's program key, `program_path`, `service_name`, `endpoint_port`
    and the three timing keys; `command`'s `working_dir` and `reload_signal`;
    and `[supervisor.attributes]`, since a Server label tags one Agent among
    several ([ADR-0024](0024-the-fleet-record.md)) while the Client-wide
    `[attributes]` describe the host. A configuration a freshly self-updated
    version refuses is that update's failed attempt: a run resolves the update
    in flight even when the file does not load, so the host returns to the
    version that could read it
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).

14. **A kind states what it knows, and the spawn applies it.**
    `Plugin::defaults()` returns `KindDefaults`, compile-time constants resolved
    per platform: the program's file name, its `program_path` inside a tree, the
    `service_name` it presents, its timing corrections (clause 17), and whether
    a block may pin `endpoint_port`. Beyond that:
    - **Working directory:** a Managed Process starts in the directory its
      program lives in — `program/` for a single file, the tree root for a tree
      — unless a kind names another; no block sets it. Every path the Client
      hands a process is absolute.
    - **Directories the agent writes into:** a kind lists them in the process
      specification (`ensure_dirs`), and they are created owner-only **before
      every spawn**, so a directory removed under a running fleet returns on the
      next restart. They lie outside `program/`, which a package swap replaces
      whole. An installation that fails for want of a directory is this Client's
      failure, not the operator's.
    - **Version:** asking the program for its version is the kind's —
      `collector` and the wrapped kinds do it themselves, reading the answer as
      clause 58 decides. `version_args` exists only on `command`, where it is
      also the preflight a staged program is run with before the running one
      stops (clause 57).

15. **Each wrapped agent is decided in an ADR of its own.** The rule here is
    general; what a particular kind knows is not, and an upstream that moves a
    path should touch one document: the kind's own ADR. `collector` and
    `command` are decided in clause 16.

16. **What stays in a block, stays for a stated reason.**
    - `collector` is one kind for both distributions and keeps `binary`:
      `otelcol` and `otelcol-contrib` share a lifecycle, a configuration
      mechanism and a supervision story, and which one a host runs is a
      decision. Its `service_name` falls back to the program's file name.
    - `collector` and `command` keep `args` and `env`: a feature gate or a
      per-host value read as `${env:VAR}` is a decision nothing can derive. The
      wrapped kinds build both whole and take neither; an operator who needs to
      change how a wrapped agent runs does it in that agent's configuration,
      which the fleet delivers.
    - `endpoint_port` is a key of `collector` only — the one kind whose Managed
      Process connects to the Endpoint. It cannot be derived: the port appears
      in the Collector configuration the fleet delivers, which this Client
      writes byte for byte and never rewrites. A non-zero value on another kind
      is refused; `0` is the default written out and passes. The default stays
      ephemeral so two Collector Supervisors on one host do not collide.
    - `command` keeps `args`, `env` and `version_args`: without them most
      Foreign Agents never find their configuration and report no version, and
      each fails visibly when wrong.
    - A wrapped kind may keep a key where a decision exists that nobody else can
      make; the kind's own ADR names the key and the decision.

17. **Timing is a fleet policy, then a kind's correction — never a host's.**
    `[supervisors]` holds `stop_timeout_secs` (default 10) and
    `apply_grace_secs` (default 3); `[updates]` holds `retain_previous_secs`
    (default one day,
    [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
    A wrapped kind may correct any of the three where its agent demands it (an
    agent whose shutdown drains for up to a minute), and its blocks may state
    none of them. Only `collector` and `command` blocks may override them,
    because there no kind exists to hold the value.

18. **A Client reports which kinds it carries.** Its own Agent reports one
    non-identifying attribute per compiled-in kind,
    `supervisor.kind.<kind> = "true"`, so a Selector can aim a Supervisor set at
    Clients that can run it. One key per kind, because a Selector is equality
    over string values and the question is about one member of the set. An
    operator's own attribute of the same key is left as written.
    `AvailableComponents` is not used for this: the message is _Development_ in
    the pinned Baseline
    ([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md))
    and Selectors do not match it.

19. **A kind binds itself to one artifact's shape.** The derived paths are those
    of the artifact `opamp-fleetctl package fetch` builds. A tree packed
    differently does not fit, and the answer is to repack it with the tool, not
    to reopen a key.

20. **Every wrapped agent has an artifact document, pinned by two tests.** The
    shape a kind runs and the tool packs is written once, in
    `docs/artifacts/<agent>.md`, for the wrapped kinds only. `collector` needs
    none: its artifact is installed as published, found by the name in `binary`,
    and handed configurations it does not inspect, so there is no second end to
    keep in step. Each document has the same eight sections: source (repository,
    tag form, version reading); assets per platform and their naming; integrity
    (checksum form and location); treatment (as published, or which repack);
    shape in the delivered tree; what the Client derives from it, per platform,
    and why; the Configurations the tool uploads and what the agent reads them
    as; and what can change upstream, with the test that goes red. Each document
    is pinned by **one test per side** — one against the tool's `Plan` (asset
    name, checksum source, action, output name), one against the kind's
    constants (program name, `program_path`, derived directories, arguments),
    `cfg`-gated per platform — and both name the document.

21. **One directory per Supervisor, under a relocatable root.** The top-level
    key `supervisor_dir` defaults to `<state_dir>/supervisors` and is made
    absolute at load. Under it each Supervisor owns `<supervisor_dir>/<name>/`,
    holding everything it needs:

```text
<supervisor_dir>/<name>/
  instance-uid            # its Agent identity
  remote-config.pb        # the last received configuration
  installed-package.json  # what is installed
  config/                 # the written configuration entries
  program/<file>          # the Managed Process — or program/tree/<program_path> for a tree
  packages/               # this Supervisor's download staging
```

One knob moves state and program together. Staging beside `program/` makes a raw
artifact's install a rename on one filesystem. The directory is `program/`, not
`bin/`, because it holds a whole tree for a multi-file package
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
Moving `supervisor_dir` on a running host leaves the old tree behind and
migrates nothing; each Supervisor then registers as a new Agent.

22. **The program key is a bare file name.** `binary` (`collector`) and
    `command` (`command`) take a file name with no path separator and no `..`,
    resolving to `program/<value>` — or to `program/tree/<program_path>` when
    the block names a tree. A wrapped kind names its own program (clause 14).
    Anything else fails at startup:

- an **absolute path** — and on Windows a rooted path without a drive letter —
  with a message naming the block, the value and the way across: a program the
  fleet manages reaches the host as a package and is named here by its bare file
  name;
- any other shape (`./x`, `a/b`, `../x`) with a message naming the rule.

A bare name cannot escape the directory, so nothing has to be sanitised, and it
never searches `$PATH`.

23. **Every Supervisor accepts packages.** Since every program lives in a
    directory this Client owns, every Supervisor's Agent declares
    `AcceptsPackages`; the capability is a constant, not a function of the
    configuration. The `program/` directory is prepared at start, before the
    first package arrives. A block carrying `accepts_packages` fails at startup
    with a message saying the bare file name already makes the program
    updatable. Startup logs, once per Supervisor, where its program is.

24. **A vendor agent is brought in by repacking.** An agent installed by the
    machine's package manager is not supervised here; it is repacked as a
    relocatable artifact and delivered as a package
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
    The manual documents the fleet-delivered route for every agent it describes.

25. **The Client's own consent stays explicit.** `[self_update]` names the
    package it takes
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md));
    nothing about it is derived from a path. A package written over the Client
    takes the host out of reach, which is where implicit consent would be wrong.

26. **Placeholders name a Supervisor's own directories.** In the `args` and
    `env` values of `collector` and `command` blocks, `${supervisor_dir}`
    expands to `<supervisor_dir>/<name>` and `${config_dir}` to
    `<supervisor_dir>/<name>/config`, where the received configuration's entries
    are written ([ADR-0023](0023-configurations-and-the-rest-api.md)) — so
    `args = ["-c", "${config_dir}/fluent-bit-conf"]` cannot drift. They are
    expanded when the Supervisor starts, and **never** in the program key, whose
    written shape is what the operator reads. An unrecognised `${…}` is passed
    through verbatim — neither refused nor emptied — because a Foreign Agent's
    own configuration language may use the same syntax (Fluent Bit's does).

27. **The Server manages the set through the Client's own Agent, and only the
    blocks are read.** A remote configuration offered to the Client's own Agent
    — a Configuration stated for the Agent type `supervisor`
    ([ADR-0023](0023-configurations-and-the-rest-api.md)) — is parsed entry by
    entry as TOML. The union of the entries' `[[supervisor]]` blocks, in
    entry-name order, is the offered set; every other top-level key is ignored.
    The boundary is enforced by what the Client takes, not by policing what the
    Server sends. A duplicate `name` within or across entries, an entry that is
    not TOML, or a block the startup parser would refuse fails the offer.

28. **An offered set is validated as startup would read it, before anything
    stops.** The merge is the running file's globals with the offered blocks.
    Each block passes the same checks startup applies — kind known, program key
    present and well-shaped, `service_name`, `endpoint_port` and timing as this
    decision allows them, retired keys refused, the kind's strict settings parse
    through the side-effect-free `Plugin::check`. A set that fails is reported
    `FAILED` with the reason; nothing is stopped, nothing is written, the
    running set stays in force.

29. **A delivered block may name only a Client-owned program.** The apply path
    checks every offered block's program resolves inside the Supervisor's own
    `program/`. Clause 22 already refuses every other shape for every principal,
    so this check cannot fire today; it stays as defence in depth against a
    future shape, in the apply path that knows the block came from the Server.

30. **The apply is a diff keyed by Supervisor `name`, in a fixed order.**
    Comparing running and offered blocks yields removed, changed (any key
    differs), added and unchanged. Then:
    1. the removed and changed Supervisors stop — a removed one is uninstalled
       (clause 11), a changed one only stopped — and their Agents send
       `agent_disconnect`;
    2. the merged document is written to `supervisor.toml`;
    3. the removed Supervisors' directories are purged (clause 34);
    4. the changed and added Supervisors start from the file just written, an
       added one introducing itself as a new Agent on the running connection.

    Unchanged Supervisors keep running untouched. A failed write restarts the
    stopped Supervisors from the still-standing old file. A crash before the
    write restarts into the old file, one after it into the new one; both
    converge, because startup builds exactly what the file says.

31. **`supervisor.toml` remains the single truth.** No overlay and no second
    file: after an apply the file is the configuration, the same file the
    operator reads and the Client's own Agent reports as its effective
    configuration (refreshed in the same step), and an offline restart runs the
    delivered Supervisors because they are in it. Only the `[[supervisor]]`
    array is replaced, by editing the document with `toml_edit`, so the
    operator's comments, ordering and formatting survive byte for byte and the
    offered blocks keep their text. The write goes through a sibling temporary
    file renamed into place; on Unix it carries the existing file's mode, and a
    file created by the write is `0600`, because it holds the credential.

32. **The status is honest.** The Client's own Agent reports `APPLYING` on
    receipt, `APPLIED` once the file is written and the starts have succeeded,
    and `FAILED` when parsing, validation, the write or a start fails. A started
    Supervisor whose process later crashes is a health fact of that Supervisor's
    Agent, not a failed configuration.

33. **No offer, no change.** A Client to which no Supervisor set is offered runs
    its locally written blocks. The first applied offer replaces the local set,
    and from then on, while `[supervisors] server_manages_set` is true, the
    Server's set is authoritative for that Client's Supervisors (clauses 41 to
    47); the offer is compared against the file, not against the last offer.

34. **A removed Supervisor is purged.** Removal is keyed by name: only a name
    absent from the new set is removed, while a changed block keeps its
    directory, identity and installed package. The purge runs only after the
    write succeeded, because a failed write restarts the old set from whole
    directories. It deletes `<supervisor_dir>/<name>/` recursively — program,
    staging, configuration and `instance-uid` — so a Supervisor later re-added
    under the same name is a new Agent, installed afresh.

35. **The purge never leaves the Supervisor root.** A symlink where a
    Supervisor's directory should be is unlinked, never followed, and a
    directory whose resolved path lies outside the root is left alone with a
    warning.

36. **A directory the purge cannot delete fails nothing.** The Supervisor is
    already stopped and the file written, so the set the Server asked for is
    running; a purge error (a file held open on Windows, permissions) is a
    warning naming the path, and the directory becomes an orphan.

37. **An orphaned directory is reported at startup, never reaped.** A directory
    under the root that no block names — a purge cut short, a block removed by
    hand while the Client was down, a moved root — is logged as a warning with
    its path and left in place. Startup cannot tell a leftover from a block
    temporarily commented out, and deleting would cost that Agent its identity
    and program; removing it is the operator's call.

38. **A delivered block brings no environment and no arguments the operator did
    not allow.** In the apply path, a delivered block's `env` entries, `args`
    and `version_args` must equal those of the running block of the same name,
    or be allowed by the operator in `supervisor.toml`'s `[supervisors]` section
    — keys the Server cannot change (clause 27). `delivered_env` is a list of
    variable names, each exact or ending in `*` as a prefix
    (`["OTEL_*", "GOMAXPROCS"]`), and defaults to none; `delivered_args = true`
    lets delivered blocks state arguments, and defaults to `false`. Names are
    compared without regard to case, as Windows compares them. Whatever the list
    says, a delivered `env` that adds or changes a variable steering which code
    a program loads is refused: `PATH`, every `LD_*` and `DYLD_*`, `GCONV_PATH`,
    `GLIBC_TUNABLES`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `DOTNET_STARTUP_HOOKS`,
    `COR_PROFILER*`, `CORECLR_PROFILER*`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`,
    `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`,
    `PERL5LIB`, `PERL5OPT`, `RUBYOPT`, `BASH_ENV` and `ENV`. So is a new or
    changed value that contains `${config_dir}` or `${supervisor_dir}`: the
    Server delivers files there that no one signed, and an allowed name such as
    `OTEL_JAVAAGENT_EXTENSIONS` would load one. The list is a floor, not a
    guarantee: `delivered_env = ["*"]` leaves only it between a delivered block
    and every other variable a program reads. A block that breaks this fails the
    whole offer before anything stops (clause 28), naming the block and the
    variable or key. A block the operator writes is unaffected: the rule is
    about what the Server may add.

39. **A delivered block names no host path outside its own configuration
    directory.** A kind states which of its settings name a file the Supervisor
    reads, and confines them in a delivered block (`Plugin::check_delivered`);
    by default a kind names none. In a delivered block each such setting must be
    `${config_dir}/` followed by a relative path with no `..`, `.` or root
    component, unless it equals the running block's value and the settings that
    say where the file's content goes are unchanged. The kind's own ADR names
    those settings and what else a delivered block of the kind must state so
    that the Server cannot choose whom the agent trusts; for an operator-written
    block that ADR stands as it is.

40. **What is checked is what is written.** The rewritten `supervisor.toml` is
    rendered before anything stops, with every delivered table and its
    sub-tables placed in the order of the set, and the offer is refused unless
    the rendered file reads back as exactly the set that passed clauses 28, 38
    and 39.

41. **The key.** `[supervisors] server_manages_set` is a boolean and defaults to
    `true`, the behaviour clauses 27 to 40 describe. It is read when the
    configuration is loaded, like every key of the file, and is never taken from
    the Server, since the Supervisor-set apply replaces only the
    `[[supervisor]]` array (clauses 27 and 31). A change takes effect at the
    next start of the Client.

42. **The Client's own Agent declares neither remote-configuration capability.**
    With the key `false` it is built without `AcceptsRemoteConfig` and without
    `ReportsRemoteConfig`. Every other capability stays as the context lists it:
    `ReportsStatus`, `ReportsEffectiveConfig` with `supervisor.toml` as its
    effective configuration, `ReportsHealth`, the connection-settings bits, the
    own-telemetry bits, `ReportsHeartbeat` where enabled, and `AcceptsPackages`
    with `ReportsPackageStatuses` where `[self_update]` consents and a
    verification key is configured. Self-update is a separate consent
    (clause 25) and is not touched. The Server then offers the Client no set
    ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 6).

43. **A set that arrives anyway is ignored.** It is not stored, not applied, and
    no `RemoteConfigStatus` is reported: no Supervisor stops or starts and
    `supervisor.toml` is not written. The Baseline's rule for a part of a
    message the Agent does not support is that it _"SHOULD ignore it"_. The
    Client logs a warning naming the offered hash once per hash it has seen
    since start, remembering at most as many hashes as it does for a Supervisor
    under clause 51 before it starts over. The Supervisor-set apply itself
    refuses to run while the key is `false` and logs the hash it was handed, so
    no path that hands it a set gets past the key.

44. **A stored set from before is not restored, and is removed at start.** When
    the key is `false` and `remote-config.pb` exists in `state_dir`, the Client,
    before it connects:
    - does not restore it, so it reports no `RemoteConfigStatus` and no
      `last_remote_config_hash`;
    - deletes `remote-config.pb` first, so nothing that fails after it can leave
      the stored hash behind;
    - then deletes, as far as it can, each entry copy in `<state_dir>/config/`
      whose bytes are still the ones the stored map holds, leaving every other
      file there, the comparison clause 52 makes for a Supervisor;
    - deletes a `remote-config.pb` that does not decode and leaves `config/` as
      it is;
    - logs once, naming the stored hash and every copy it kept or could not
      remove.

    Nothing runs on these files, and the set they carry is already in
    `supervisor.toml`, so a file that cannot be read or deleted is a warning
    naming the error, and startup continues. Kept, `remote-config.pb` would be
    reported `APPLIED` again once the key returns to `true`, and the Server
    would not offer its set while that hash is unchanged, though the file may by
    then hold the operator's blocks; the warning for `remote-config.pb` itself
    says so.

45. **The blocks in the file stay, and are the operator's.** Setting the key
    rewrites nothing: every `[[supervisor]]` block stays as it is, including
    blocks an earlier applied set wrote, and the Client runs them as written.
    From then on only the operator changes them. An operator who switches the
    key off reviews the blocks first, since some of them may be the Server's. A
    Supervisor's own remote configuration is not affected: each Supervisor's
    Agent keeps taking its configuration unless it is named in
    `remote_config_disabled`. `delivered_args` and `delivered_env` keep their
    meaning and have nothing to act on while no set is delivered.

46. **Together with `remote_config_disabled` it closes what that list leaves
    open.** With the key `false` the Server can neither remove a listed
    Supervisor nor add the same agent under a name that is not listed. The
    Server can still install a signed package into a Supervisor, restart a
    Managed Process, offer connection settings, and configure every Supervisor
    not named in `remote_config_disabled`.

    What the key holds against the Server holds only while every Supervisor
    whose configuration language can run commands as the Client's account — a
    Telegraf `inputs.exec`, an Icinga `CheckCommand`, the configuration a
    `command` kind's program reads — is named in `remote_config_disabled`.
    Otherwise the Server can configure such a Supervisor to rewrite
    `supervisor.toml`, and the key flips at the next start. A signed Client
    build can also still replace the Client's own program where `[self_update]`
    consents
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)),
    and that program reads the key.

47. **Switching it back on hands the set to the Server again.** When the key
    returns to `true`, the next start declares both capabilities, reports no
    hash — unless that earlier start warned that it could not remove
    `remote-config.pb` itself — and is offered whatever set is released to the
    Client's own Agent ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)).
    The first applied offer replaces the `[[supervisor]]` array, the operator's
    blocks included, and purges each Supervisor it removes (clauses 33 and 34).

48. **The key `remote_config_disabled`.** `[supervisors] remote_config_disabled`
    is a list of Supervisor names and defaults to empty. It is read when the
    configuration is loaded, like every key of the file, and is never taken from
    the Server: the Supervisor-set apply keeps the running file's globals and
    replaces only the `[[supervisor]]` array (clauses 27, 28 and 31). A Server
    that deletes a listed Supervisor's block and delivers it again under the
    same name gets a Supervisor that is still listed.

49. **A name that matches no block is a notice, not a refusal.** At startup each
    listed name that no `[[supervisor]]` block carries is logged once as a
    notice naming it, because the set may arrive later from the Server. A listed
    name equal to the Client's own `name` and to no block is logged with a
    notice that the Client's own Agent is not covered; that is clauses 41 to 47.
    A value that breaks the instance-name grammar (clause 3) fails startup
    naming the key and the value, because no block can ever carry it.

50. **A listed Supervisor's Agent declares neither remote-configuration
    capability.** It is built without `AcceptsRemoteConfig` and without
    `ReportsRemoteConfig`. Every other capability stays as it is:
    `ReportsEffectiveConfig`, `AcceptsRestartCommand`, and `AcceptsPackages`
    with `ReportsPackageStatuses` where a verification key is configured. The
    Server then offers it no remote configuration
    ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 6), and nothing
    on the Server changes.

51. **A remote configuration that arrives anyway is ignored.** It is not stored,
    no entry file is written, nothing is handed to the process adapter, and no
    `RemoteConfigStatus` is reported, since the Agent declares no
    `ReportsRemoteConfig`. The Baseline's rule for a part of a message the Agent
    does not support is that it _"SHOULD ignore it"_. The Client logs a warning
    naming the Supervisor and the offered hash once per hash it has seen since
    start, so a Server that resends the same offer on every exchange does not
    flood the log.

52. **A stored remote configuration from before is removed at start, and the
    operator's files stay.** When a listed Supervisor starts — at Client
    startup, or when a delivered set adds or changes it — and a
    `remote-config.pb` exists in its directory, the Client, before the kind is
    started:
    - deletes from `config/` each entry file the stored map names whose bytes
      are still the ones the map holds, and `.supplementary` if its bytes are
      still the ones the map would write;
    - leaves every other file in `config/` untouched, since the operator wrote
      or overwrote it;
    - deletes `remote-config.pb`;
    - logs once, naming the Supervisor, the stored hash, and every file it kept
      because its content had changed.

    A `remote-config.pb` that does not decode is deleted, `config/` is left as
    it is, and the warning says that `config/` may still hold files the Server
    wrote. No status is restored, so a listed Supervisor reports no
    `RemoteConfigStatus` after a restart and no `last_remote_config_hash`.

    Storing an offer (`store_remote_config`) removes the previous entry files,
    writes the new ones, and writes `remote-config.pb` last. A store cut short —
    a crash or a failed write — therefore never leaves a new `.pb` beside the
    previous offer's files, which the comparison above would keep as the
    operator's. What it can leave is the previous `.pb` beside some of the new
    offer's files. The previous map names none of those, so they stay in
    `config/`: a stop after the first new entry file and before the `.pb` is the
    one window in which the drop cannot tell the Server's files from the
    operator's.

53. **What a listed Supervisor runs is the operator's.** The kinds are
    unchanged. A listed Supervisor runs on the files the operator places in
    `<supervisor_dir>/<name>/config/`, under the names its kind reads (the
    context lists them), with roles in `.supplementary` in the format
    `storage.rs` writes. For `collector` and `command` the process also gets the
    block's `args` and `env`, which are the operator's as clause 54 keeps them.
    With remote configuration switched off, nothing else writes into that
    directory. A listed Supervisor with no such file does what its kind does
    before its first remote configuration: a `collector` waits and says so, and
    a wrapped kind waits or lets its agent exit and be reported, as its ADR
    decides.

54. **A delivered block for a listed Supervisor repeats the running block
    whole.** In the Supervisor-set apply, the check of a delivered block
    (`check_delivered_block` in `crates/fleet-agent/src/supervisor/mod.rs`,
    called from `apply_inner` in `crates/fleet-agent/src/reconfigure.rs`)
    ignores `delivered_args` and `delivered_env` (the `SupervisorsConfig` fields
    of `crates/fleet-agent/src/config.rs`) for a block whose name is in
    `remote_config_disabled`, and holds such a block to this:
    - **A block of that name runs:** the delivered block equals it entirely,
      compared as the parsed block. That covers `type`, the core keys
      (`service_name`, `endpoint_port`, `stop_timeout_secs`, `apply_grace_secs`,
      `retain_previous_secs`, `program_path`) and every kind setting, among them
      `args`, `version_args` and `env` and every setting a wrapped kind keeps. A
      key the running block lacks may not appear, and one it has may not change
      or go. Absent and empty differ.
    - **No block of that name runs, because the block is added:** the delivered
      block carries nothing beyond what naming its program requires. That is
      `type` and `name`, plus the kind's program key where the kind does not
      name its own program: `binary` for `collector` and `command` for
      `command`. A wrapped kind's block carries `type` and `name` alone, since a
      wrapped kind installs and names its own program and refuses the key
      (clause 13). A setting the kind keeps is then the operator's to write into
      the host's `supervisor.toml`, and from then on the running block is the
      one a delivered block must equal.

    A block that breaks this fails the whole offer before anything stops, as
    clauses 28 and 38 refuse a block: the set is reported `FAILED` with a reason
    naming the block and the key, nothing is stopped, nothing is written, and
    the running set stays in force. Without this, the Server could configure a
    listed Supervisor through its block instead of its `config/`. It could put a
    configuration on a Collector's command line or into its environment
    (`--config=yaml:…`, `--config=env:VAR`) where `delivered_args` or
    `delivered_env` allow it. It could also, through the settings a wrapped kind
    keeps, change which peer the operator's agent talks to and, with a file
    setting pointed at a file no remote configuration writes, what it trusts
    (the context describes how). Equality closes that route for every key,
    including keys a kind adds later. A list of the keys that matter would have
    to be kept current with every kind. The Server can still remove a listed
    block or deliver it unchanged. Delivering it unchanged is how a Server that
    manages the set keeps it.

55. **Switching it back on hands `config/` to the Server again.** When a name
    leaves the list, the next start declares both capabilities, reports no hash,
    and is offered whatever is released to that Agent
    ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)). The first stored
    offer replaces every file in `config/`
    ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 9), the
    operator's included.

56. **A kind may lead its own process group, and is then stopped as a group.** A
    kind whose agent leaves a worker behind when only its own process dies
    starts it in its own process group (`ProcessSpec::own_process_group`), and
    the Runner's stop signals the group, so the escalation to `SIGKILL` cannot
    leave the worker behind. Leading a group is opt-in per kind; kinds with one
    process keep signalling the pid. Windows has no equivalent yet.

57. **A package is proved to run before it is installed.** For every kind, after
    an artifact is unpacked to its staged name
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
    clause 61) and before the swap, the Runner runs the staged program once with
    a preflight its kind supplies. A failure answers `PackageApplied{Err}`
    carrying the dynamic linker's own message
    (``version `GLIBC_2.39' not found``, _"cannot open shared object file"_),
    and nothing is swapped, so a running Managed Process is never stopped for a
    package that could not run. A kind's preflight is its version arguments,
    with whatever environment its ADR adds; `command` uses its `version_args`,
    so a `command` block without them has no preflight. The health gate and
    rollback of
    [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
    remain the second line.

58. **A version probe may bring its own parser.** `VersionProbe` takes an
    optional parse function, strict Semantic Versioning by default. A kind whose
    program prints its version in another form supplies the parser, and its ADR
    says how the form is read.

**Out of scope:** dynamic plugin loading; plain-HTTP polling on the Supervisor
Endpoint; injecting the `opampextension` configuration into a Collector's
configuration; connection pools larger than one (Gateway Mode,
[ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md));
reporting the kinds through `AvailableComponents`; a machine-readable artifact
manifest shared by tool and kind; reconciling a locally edited `[[supervisor]]`
set against the last applied offer at startup; an opt-in reaping of orphaned
directories; migrating a Supervisor tree when its root moves; a supervise-only
mode for programs this Client does not install, which would need its own
decision and capability model; how a multi-file tree is unpacked and swapped
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md));
keeping some blocks from the Server while it manages the others; how the fleet
view or the REST API shows that a host keeps its set, beyond the capability set
the Server already lists; any change on the Server, the REST API or the bundled
UI for either switch; the restart command and package delivery to a listed
Supervisor, which stay as they are; what a listed Supervisor reports as its
effective configuration when its process reports none (the empty map, as for any
Supervisor before its first remote configuration); a group stop on Windows
through a job object.

## Alternatives considered

- **Dynamic plugin loading (shared libraries).** Rust has no stable ABI, so it
  means a C ABI boundary, unsafe code and version-skew handling for a
  third-party capability nobody needs; the registry keeps a new kind to one
  module.
- **A serde tagged enum instead of a registry and a two-stage parse.** It
  hard-codes every kind's settings into `config.rs` and cannot combine with
  `deny_unknown_fields`.
- **A `Supervisor` trait with async lifecycle methods.** Async trait objects
  need `async-trait` or hand-rolled boxing, and a core that awaits adapter
  methods couples itself to adapter timing. The channel vocabulary is the
  uniform interface.
- **axum (or hyper) for the Supervisor Endpoint, or plain-HTTP support on it.**
  The endpoint serves one loopback WebSocket peer, which `tokio-tungstenite`
  already handles; the reference template is `ws://`, so HTTP polling would have
  no consumer.
- **One upstream connection per Supervisor.** The Server routes by
  `instance_uid` regardless, and n-over-1 is the model Gateway Mode generalises.
- **Injecting the extension configuration à la `opampsupervisor`.** It needs a
  YAML stack and templating in Rust; the operator pins `endpoint_port` on the
  Collector block and the delivered configuration names it.
- **A distinct `Reload` command beside `ApplyConfig`.** Nothing upstream asks
  for a bare reload, so it would have no sender; reload is how an apply is
  executed.
- **Operator-written lifecycle hooks (`reload_cmd`, `uninstall_cmd`,
  `reload_signal`) in TOML.** Kind knowledge belongs in the kind's module,
  written once and tested; a wrong hook silently misbehaves on a host.
- **Moving program resolution and package consent into the plugins.** A
  fleet-visible capability must derive from configuration the core reads.
- **Keep the derivable keys and fix the documentation, or keep them
  undocumented.** A template is a default that cannot be updated, and two
  sources of truth for a value the Client computes is how a host quietly differs
  from what the fleet believes.
- **Split `collector` into `otelcol` and `otelcol-contrib`.** It moves the
  distribution decision from `binary` into `type` and costs a second plugin for
  one lifecycle.
- **A machine-readable manifest per agent, read by tool and Client.** It needs a
  schema, a parser on each side and a policy for a manifest newer than the
  Client; two tests achieve the coupling.
- **Probing the unpacked tree at runtime, or a per-kind defaults file.** A wrong
  guess is silent on a host, and data nothing tests re-creates the
  transcription; a compiled-in constant fails a test when the artifact moves.
- **One list attribute for the kinds.** A Selector could match it only by
  spelling the whole list.
- **Every kind always compiled in.** It is the simpler build, but a host that
  runs one wrapped agent then carries the code, the attack surface and the
  reported capability of all of them.
- **A feature for `collector` and `command` too.** A build without either has no
  way left to run a Collector or an unwrapped agent; the two are the core's own
  paths, not a vendor's.
- **A self-update package derived from the build's kinds.** It names a package
  per combination of features and decides at build time what the operator
  decides in `[self_update]`; the probation already rolls back a build that
  cannot read the host's blocks.
- **A denylist of dangerous variables alone** — `LD_PRELOAD` is one of many;
  `PYTHONPATH`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `BASH_ENV` and every
  program's own plugin variable reach as far, and the list never ends. An
  allow-list the operator writes ends it; the loader variables are refused on
  top because no Managed Process needs them from the Server.
- **No delivered `env` or `args` at all** — safe, but a fleet that steers its
  Collectors with `OTEL_*` variables or a Fluent Bit's `-c ${config_dir}/…` from
  the Server would lose that; the operator's allow-list keeps it where it is
  wanted.
- **Clearing the environment of every Managed Process** — the Client's own
  environment carries what the host's agents expect (proxies, locale); clearing
  it breaks operator-written blocks to protect against delivered ones.
- **An `accepts_packages` flag beside a program path that may be absolute.** Two
  keys for one truth that can disagree, and the configuration could express what
  the filesystem forbids.
- **Probing writability at startup and deriving consent from it.** A
  fleet-visible capability would depend on a `chmod` nobody recorded and race a
  rollout when permissions change.
- **Supervising machine-installed programs without updating them.** Every
  package, version and rollback decision would carry a second case, the fleet's
  picture of a host would depend on which file a block came from, and an
  operator "fixing" a path to an absolute one would silently revoke a
  capability.
- **Letting the Server deliver absolute program paths, or allowlisting some per
  host.** The first hands a Server arbitrary code execution outside package
  signing; the second is host-local policy for a capability the fleet path does
  not need. Warning and applying anyway is not a control.
- **A separate `bin_dir`, or a `supervisor_dir` per block.** Two knobs for a
  separation nobody has asked for; one root per Client matches how the Client's
  own root is treated.
- **Keeping a bare name as a `$PATH` lookup and requiring `./` for the owned
  meaning.** A fourth case, noise in TOML, to keep behaviour fragile under a
  service manager's minimal `PATH`.
- **A `versions/` + `current` layout for Managed Processes.** A Managed Process
  is stopped before its swap and `.rollback` covers the fallback; only the
  running Client needs that layout.
- **Resolving relative arguments against the Supervisor's directory instead of
  placeholders, or exporting the paths as environment variables.** The
  same-looking rule would mean `program/` for one key and the Supervisor root
  for another, and nothing expands variables in `argv`. A general templating
  engine is far past the need.
- **Refusing unknown `${…}` placeholders.** It would break agents whose own
  syntax overlaps to catch a typo.
- **The Server delivering the whole `supervisor.toml`.** Endpoint, credential
  and state directory are the host's trust anchors; one bad push could leave the
  Client unreachable.
- **A separate overlay file for the delivered set** (the `opampsupervisor`
  model). Two files would answer "what does this Client run", and an offline
  restart would depend on state the operator never sees.
- **Restarting the Client, or every Supervisor, to apply.** It cycles every
  healthy Supervisor to change one.
- **Failing an offer that carries a non-Supervisor key.** One stray global key
  would block the Supervisors that came with it; the fleet view shows the file
  that actually runs.
- **Re-serialising the file with the ordinary `toml` writer.** It destroys the
  operator's comments and layout after the first apply.
- **Keeping a removed Supervisor's data, keeping only its identity, a retention
  window, or renaming it aside.** A re-added Supervisor would resurrect a
  disconnected Agent's identity and stale configuration; a split directory is
  unreasoned; retention exists to roll back a living Supervisor, which a removed
  one is not; a renamed copy is a slower leak.
- **Reaping orphaned directories at startup.** Startup cannot tell a leftover
  from a deliberate hand edit, and the destructive reading deletes an identity
  that was not meant to go.
- **Default `false` for `server_manages_set`.** Every existing Client would stop
  following the Server's set at upgrade, including hosts that took one, and
  G-1's loop would no longer close for Supervisor sets until each host's file
  says so. The switch is an operator's narrowing of what the Server may do on
  one host; the default keeps the behaviour clauses 27 to 40 describe.
- **A reserved name in `remote_config_disabled`** (the Client's own `name`, or a
  fixed name such as `supervisor`). The list holds Supervisor names under the
  instance-name grammar, so any reserved literal is a name a block can carry,
  and the Client's own `name` is the operator's to change. One key would mean
  two things: a Supervisor's configuration and the membership of the set. Clause
  49 already answers the Client's own name in the list with a notice that it is
  not covered.
- **A key per `[[supervisor]]` block** (`managed_by_server = false`). The Server
  replaces the blocks (clause 27) and could drop the key by delivering the block
  without it. The decision is also about the set: adding a block is the change
  to stop, and no existing block can say that.
- **Keeping `AcceptsRemoteConfig` and answering every set, or every offer to a
  listed Supervisor, `FAILED`.** The Server would keep offering, the fleet view
  would show a refusal on every rollout, and the Agent would declare a
  capability it does not exercise.
- **Restoring the stored set, or leaving it on disk unrestored.** Restored, the
  Server sees a set reported `APPLIED` that the host no longer follows. Left on
  disk, switching back on restores its hash, and the Server does not offer an
  unchanged set to a file the operator may have changed since.
- **Failing startup when the stored set cannot be removed.** Clause 52 fails
  closed because a Supervisor runs on its files; nothing runs on these, and a
  refusal would take the host off the fleet for an inert file.
- **A top-level key outside `[supervisors]`.** `[supervisors]` already holds
  what the host allows the Server for its Supervisors (`delivered_env`,
  `delivered_args`, `remote_config_disabled`), and the Server never writes it.
- **A separate ADR beside this one for the switch.** It would make clause 33
  untrue for some hosts without changing it; who manages a host's set is one
  decision.
- **A key inside the `[[supervisor]]` block to switch off its remote
  configuration** (`accepts_remote_config = false`). The Server replaces the
  blocks (clause 27), so it could switch the setting back on by delivering the
  block without the key. A delivered-block check that refuses dropping the key
  would make the operator's choice depend on a rule in the apply path, when it
  can depend on a section the apply path never writes.
- **A Client-wide switch of remote configuration for every Supervisor.** It is
  too coarse: a host that wants one agent's configuration kept local loses fleet
  configuration for every other agent it runs.
- **Ignoring only a listed Supervisor's `remote-config.pb` and leaving `config/`
  as it is.** The kinds read the entry files, not the `.pb`, so the Server's
  last configuration would go on running under a switch that says it does not.
- **Wiping the whole `config/` directory at start.** It would delete the files
  an operator placed there before the restart that put the switch in force.
- **Moving the Server's stored files aside instead of deleting them.** They can
  carry secret material ([ADR-0023](0023-configurations-and-the-rest-api.md)
  clause 9), and nothing needs them back: switching back on reports no hash, so
  the Server offers again what is released.
- **A separate host path for a listed Supervisor's local configuration.** It
  would be a second place each kind reads from, and a block key the Server could
  rewrite. `config/` is already where every kind looks.
- **Letting `delivered_args` and `delivered_env` stand for a listed
  Supervisor.** They were written to let the fleet steer a Supervisor's process.
  For a listed one the same keys would let the Server deliver a configuration on
  the command line or in the environment, and the switch would not mean what it
  says.
- **Holding only `args`, `version_args` and `env` of a listed Supervisor's block
  to the running block.** It closes the command line and the environment and
  leaves every other key to the bounds of clauses 38 and 39. The settings a
  wrapped kind keeps then stay deliverable, among them which peer its agent
  talks to, and a file setting pointed at a file no remote configuration writes
  leaves the kind on whatever weaker default it falls back to, with a peer the
  Server chose. Any such list has to be kept current with every kind, and
  equality needs no list.
- **Letting an added listed block carry kind settings within the bounds of
  clauses 38 and 39.** The same keys would reach the agent through the block
  that adds it, before the operator wrote anything. An added block carries what
  names its program, and the operator configures the rest on the host.
- **Refusing startup when a listed name matches no block.** A Server that
  delivers that block later is the normal case, and the refusal would stop the
  whole Client for it.
- **Preflight by static inspection** of required `GLIBC_` symbols. Rejected: a
  start attempt is the definition of "runs here", catches a missing library too,
  and yields the operator's message.

## Sources / Prior art

- [OpenTelemetry `opampsupervisor`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/cmd/opampsupervisor),
  its
  [specification](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/specification/README.md)
  and its
  [embedded extension template](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/supervisor/templates/opampextension.yaml)
  (`ws://127.0.0.1:{{.SupervisorPort}}/v1/opamp`) — local server, config
  handling, restart and stop behaviour; the generic `agent.executable` shape for
  a supervisor that does not install its agent; a per-supervisor
  `storage.directory` beside an absolute `agent.executable`; the
  remote-plus-local configuration merge; it manages only the agent it installs
  and has no Foreign-Agent path expansion
  (`opentelemetry-collector-contrib#36269`);
  `capabilities.accepts_remote_config` is a per-supervisor setting in its local
  file, `false` unless set, and without it the Collector runs on the local
  `agent.config_files` alone.
- [`opampextension` README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/opampextension)
  — a client of both transports reporting effective configuration, health and
  components.
- [serde-rs/serde#1547](https://github.com/serde-rs/serde/issues/1547) —
  `deny_unknown_fields` does not compose with `flatten`.
- [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)
  — `instance_uid` multiplexing; restart as the only process command;
  `AvailableComponents`.
- [Nomad task driver plugins](https://developer.hashicorp.com/nomad/docs/concepts/plugins/task-drivers)
  — one driver interface over arbitrary process kinds, with stop and destroy as
  separate steps.
- [systemd service units](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
  — `ExecReload` and `reload-or-restart`.
- [Puppet package type and providers](https://www.puppet.com/docs/puppet/7/types/package.html)
  — a uniform resource whose platform mechanics live in the provider; the
  manifest states intent.
- Elastic Agent / Fleet integrations (defaults that work unconfigured, paths
  resolved by the agent's own `paths` package) and Datadog Agent integrations
  (`conf.d/<name>.d/conf.yaml`, per-integration defaults) — the tool that owns
  the installation knows the layout.
- [Elastic Agent version management](https://deepwiki.com/elastic/elastic-agent/6-version-management-and-upgrades)
  — a versioned home with a symlink to the active executable; manages only
  binaries it installs.
- [Bindplane collector install and uninstall](https://docs.bindplane.com/deployment/virtual-machine/collector/install-and-uninstall-bindplane-collectors)
  — managed vs detached collectors; removal deletes install directory and state
  as one act.
- [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
  — specifiers expand in arguments but not in the executable path;
  `StateDirectory=` exports `$STATE_DIRECTORY`.
- [OpAMP specification v0.19.0](https://github.com/open-telemetry/opamp-spec/blob/v0.19.0/specification.md)
  and
  [v0.20.0](https://github.com/open-telemetry/opamp-spec/blob/v0.20.0/specification.md)
  — `EffectiveConfig` may merge local configuration; `RemoteConfigStatuses`;
  `agent_disconnect` as an Agent's last word; `AcceptsPackages` as a per-Agent
  capability. For the switch, v0.20.0 _Configuration_ (_"Remote configuration
  capability can be disabled if necessary"_; _"If the bit is not set the Server
  MUST not offer a remote configuration to the Agent"_) and
  _AgentToServer.capabilities_ (an Agent that does not support a capability
  _"SHOULD ignore"_ the part of a message that belongs to it).
- [`toml_edit`](https://docs.rs/toml_edit) — format- and comment-preserving TOML
  editing, what `cargo add` edits manifests with.
- [Debian FAQ: remove vs purge](https://www.debian.org/doc/manuals/debian-faq/uptodate.en.html)
  — purge semantics, chosen because no operator is present after a Server-driven
  removal.
- The code read for the switch: `AGENT_CAPABILITIES`, `AgentState::new`,
  `restore`, `handle`, `apply` and `config_applied` in
  `crates/fleet-agent/src/supervisor/agent.rs`; `build_engine`,
  `start_supervisor` and `remote_config_disabled_notices` in
  `crates/fleet-agent/src/supervisor/mod.rs`; `SupervisorsConfig` in
  `crates/fleet-agent/src/config.rs`; `store_remote_config` and
  `drop_remote_config` in `crates/fleet-agent/src/storage.rs`; the self-Agent
  dispatch in `crates/fleet-agent/src/engine.rs`; the `AcceptsRemoteConfig` gate
  in `crates/fleet-server/src/fleet.rs`; for the switch per Supervisor, `apply`
  in `crates/fleet-agent/src/supervisor/agent.rs`, each kind's configuration
  source in `collector.rs` and `command.rs`, `apply_inner` in
  `crates/fleet-agent/src/reconfigure.rs`, `config_entries` in
  `crates/fleet-agent/src/storage.rs` and `offer` in
  `crates/fleet-server/src/fleet.rs`.
- OpAMP specification v0.20.0, further: the Client MUST set
  `AcceptsRemoteConfig` if the Agent can accept a remote configuration; an Agent
  MAY update its capabilities; the `AgentCapabilities` enum
  (`AcceptsRemoteConfig`, `ReportsRemoteConfig`, `ReportsEffectiveConfig`);
  _Interoperability of Partial Implementations_.

## Consequences

- Positive: many Supervisors per Client, a Foreign Agent managed like a
  Collector, a new kind as one module, and an extension-carrying Collector
  visible through its own reporting — with no Server change, on the tested
  `instance_uid` routing.
- Positive: a wrapped agent's block is `type` and `name`, the same two lines on
  every platform; an artifact whose layout moves is one edit in the kind,
  reaching every host with the next Client version; the platform branches are
  compile-time constants a test can assert.
- Positive: reload-capable agents keep their state across configuration changes;
  retiring a Supervisor undoes what its installation did; a delivered agent
  never fails for a missing directory; a rollout can aim only at Clients
  carrying the kind.
- Positive: an upstream change surfaces as a red test on the side it touches,
  with a document saying what the other side owes.
- Negative / trade-offs: losing the one upstream connection affects every Agent
  riding it, and a reconnect resends full state per Agent. An ephemeral Endpoint
  port cannot serve an extension-carrying Collector; the operator pins it.
- Negative / trade-offs: `APPLIED` means "restarted and survived the grace", not
  "validated"; a process that accepts a configuration and fails later surfaces
  as unhealthy. A reload leaves less evidence than a restart, so an adapter that
  cannot verify its reload says so in its outcome.
- Negative / trade-offs: supporting a new agent well costs a wrapper, a document
  and two tests; `command` keeps "not yet wrapped" usable, but such an agent
  applies by restart and runs in its program's directory. Kind-specific installs
  carry their own rollback burden.
- Negative / trade-offs: an Agent cannot be tagged per block before its first
  message; a label covers it from the first exchange on. One attribute per kind
  reads worse than a list.
- Positive: a build carries only the wrapped kinds its hosts run, and its own
  Agent says which.
- Negative / trade-offs: every combination of features is a build that must keep
  compiling; the gate lints each wrapped kind alone and the build with none
  beside the default, on Linux. A build with fewer kinds needs its own package
  name, or its hosts take the full build at the next self-update.
- Negative / trade-offs: a kind is coupled to one artifact's shape — "bring your
  own tree" is a packaging question, not a configuration one. The documents'
  prose has no test behind it.
- Follow-ups (by topic): extension-configuration injection; plain-HTTP polling
  on the Endpoint; connection pools and their failure semantics; a
  verified-reload gate and making reload vs restart visible upstream; kinds that
  install through OS package managers; the kinds in `AvailableComponents` once
  it leaves _Development_; the next wrapped agent (Fluent Bit is the documented
  candidate); a machine-readable artifact manifest if wrapped agents multiply.
- Positive: an update writes only inside a directory the Client owns — no root,
  no permissions on a system `bin`, no `.rollback` files beside system binaries
  — and hardening can grant write access to exactly one tree. `supervisor_dir`
  takes programs off a `noexec` or undersized `/var`.
- Positive: one kind of Managed Process. Every package feature has one case, and
  a capability can never depend on how a path was spelled; a locally written
  block and a delivered one describe the same thing.
- Positive: a Foreign Agent's configuration path follows a relocated root or a
  rename.
- Positive: Supervisors are fleet-manageable end to end with the same rollout
  and Selector scoping as every Configuration; unchanged Supervisors ride
  through an apply; a delivered set can only run programs that arrive as
  verified packages.
- Positive: a removal is complete — no program-sized leftovers, no stale
  identity.
- Negative / trade-offs: a program installed by the machine cannot be
  supervised; adopting a host that already runs a vendor agent means a repack
  and a package rollout before the Agent appears.
- Negative / trade-offs: one copy of a program per Supervisor; an archive
  artifact is still written twice (unpacked), so the rename saving lands on
  bare-binary artifacts.
- Negative / trade-offs: an unknown placeholder passes through rather than
  failing, unlike an unknown key; an absolute path in an argument still works
  and can still drift.
- Negative / trade-offs: after the first applied offer, while the Server manages
  the set, a local edit to the blocks drifts silently until the next publication
  overwrites it.
- Negative / trade-offs: removal is destructive and final; a Supervisor removed
  by a mis-scoped rollout loses its identity and its program. A crash between
  write and purge leaves an orphan only a human removes.
- Positive: an operator can stop the Server from adding, changing or purging
  Supervisors on a host with one line the Server does not write (Q-1); with
  `remote_config_disabled`, a listed agent can no longer reach the Server's
  configuration under another name, which closes on a host that sets both what
  the list alone leaves open.
- Negative / trade-offs: the line holds against the Server only while every
  Supervisor whose configuration language can run commands as the Client's
  account is in `remote_config_disabled`, and a signed Client build can still
  replace the program that reads it where `[self_update]` consents (clause 46).
- Positive: the switch needs no change on the Server, and the fleet view shows
  it through the Client's capability set, which lacks `AcceptsRemoteConfig`.
- Negative / trade-offs: a host that keeps its set is managed by hand. A
  Supervisor set released to it reaches nothing, and G-1's loop does not close
  for the Client's own Agent there by design.
- Negative / trade-offs: the blocks an earlier set wrote stay in force without
  notice when the switch goes off; the operator has to review them, and the
  manual says so. Switching back on replaces the operator's blocks with the
  first applied set.
- Positive: an operator can close the configuration channel for one agent with
  one line the Server cannot change. A compromised Server can then no longer
  write that agent's configuration or run what its configuration language allows
  (Q-1). Signed package updates still reach it.
- Positive: switching remote configuration off for a Supervisor needs no change
  on the Server, and the fleet view shows why: the Agent's capability set lacks
  `AcceptsRemoteConfig`, and the Server offers it nothing however a rollout is
  aimed.
- Positive: switching off takes the Server's last configuration out of force at
  the next start without destroying what the operator put in its place.
- Negative / trade-offs: a listed Supervisor is configured by hand on its host.
  A rollout aimed at it releases nothing it receives, and G-1's loop does not
  close for that Agent by design.
- Negative / trade-offs: `remote_config_disabled` binds a name, not an agent.
  While the Server still manages the set it can remove a listed Supervisor and
  add the same agent under a name that is not listed. That Agent is new,
  installed afresh from a signed package and visible as such in the fleet, but
  its configuration is the Server's; `server_manages_set = false` closes that.
- Negative / trade-offs: a change to either key takes effect at the next start
  of the Client, like every other key of the file.
- Negative / trade-offs: the per-Agent capability set is no longer the same on
  every host, for the Client's own Agent, or for every Supervisor.
  [`CONFORMANCE.md`](../CONFORMANCE.md) rows for `AcceptsRemoteConfig` and
  `ReportsRemoteConfig` must say they can be withdrawn, for the Client's own
  Agent and per Supervisor (G-12).
- Negative / trade-offs: a Server that manages the set must deliver a listed
  block exactly as it runs. A change the operator makes to it on the host has to
  reach the Server's copy before the next delivered set, or that set fails.
- Follow-ups (by topic): startup reconciliation of a locally edited set; a
  bundled-UI editor for Supervisor sets; an opt-in reap of orphaned directories;
  a purge option on `service uninstall`; pruning stale `.rollback` files on a
  schedule; a supervise-only mode as its own decision; keeping chosen blocks
  from the Server while it manages the rest; showing in the fleet view that a
  host keeps its set; reporting a listed Supervisor's local files as its
  effective configuration when its process reports none; storing an offer so
  that a stop part-way leaves no file the drop of clause 52 cannot attribute.
- Positive: the preflight protects every package — a Collector built against a
  newer libc is refused before the running one is stopped.
- Negative / trade-offs: a group stop exists on Unix only; a kind whose agent
  forks a worker stops it on Windows by the pid alone.

## Enforcement

- Registry, defaults and refusals, in
  `crates/fleet-agent/src/supervisor/mod.rs`:
  `every_wrapped_kinds_block_is_two_lines`,
  `an_unwrapped_kind_still_says_everything_itself`,
  `a_client_reports_the_kinds_it_was_compiled_with`,
  `the_fleets_timing_reaches_a_supervisor_that_says_nothing`,
  `a_build_carries_exactly_the_wrapped_kinds_its_features_name`,
  `a_kind_left_out_of_the_build_is_an_unknown_type`. `scripts/check-rust.sh`
  lints `fleet-agent` on Linux without any wrapped kind and with each one alone,
  and runs its tests without any, so a smaller build stays compiling and the
  second test decides something. Windows and macOS lint the default build only;
  a smaller build there is checked by whoever builds one. That a wrapped kind's
  block needs neither a program nor a type, that restating a derived value is
  refused (clause 13), and that a kind's timing correction reaches its
  Supervisor (clause 17) is shown with a wrapped kind, by the tests its ADR
  names.
- Two-stage parse and retired keys:
  `supervisor_blocks_split_common_keys_from_plugin_settings`,
  `a_supervisor_block_needs_type_and_a_valid_name`,
  `duplicate_supervisor_names_are_rejected`,
  `attributes_describe_the_host_and_a_block_no_longer_tags_one_agent`
  (`crates/fleet-agent/src/config.rs`); `settings_parse_strictly` and
  `the_retired_keys_are_refused_by_name` in `command.rs`,
  `settings_parse_strictly` in `collector.rs`;
  `an_unreadable_configuration_resolves_the_update_in_flight`
  (`crates/fleet-agent/src/service/runtime.rs`).
- Agents over one connection and the Endpoint:
  `poll_reports_carries_every_agent_with_distinct_identities`,
  `a_reply_reaches_only_the_agent_its_uid_names`
  (`crates/fleet-agent/src/engine.rs`);
  `extension_reports_are_folded_into_process_events` (`supervisor/endpoint.rs`);
  `a_config_change_reaches_both_supervised_agents_over_one_connection`
  (`crates/fleet-agent/tests/e2e.rs`).
- Process management and the lifecycle vocabulary, in
  `crates/fleet-agent/tests/supervisor_process.rs`:
  `an_exiting_process_turns_unhealthy_and_is_restarted`,
  `a_process_surviving_the_apply_grace_is_acknowledged_applied`,
  `a_process_exiting_within_the_grace_fails_the_apply_and_stays_supervised`,
  `a_restart_command_cycles_the_process_without_a_config_ack`,
  `a_declared_reload_applies_without_a_restart`,
  `a_process_that_dies_on_the_reload_signal_is_restarted_instead`,
  `an_uninstall_stops_the_process_answers_and_exits`,
  `the_directories_an_agent_writes_into_are_made_before_it_runs`,
  `a_program_named_by_a_relative_path_still_starts_in_its_own_directory`; and
  `retiring_uninstalls_the_removed_and_only_stops_the_changed` (`engine.rs`),
  `a_collector_supervisor_passes_each_config_entry_as_a_config_flag`,
  `sigterm_stops_the_managed_process_and_the_client_cleanly`
  (`crates/fleet-agent/tests/supervisor.rs`).
- Artifact documents (clause 20): each wrapped kind's ADR names the two tests
  that pin its document, one in the kind's module and one in
  `crates/fleet-tools/src/fetch.rs`. Each names its document.
- Preflight (clause 57):
  `a_package_that_cannot_run_here_is_refused_without_stopping_what_runs`
  (`crates/fleet-agent/tests/supervisor_process.rs`) and
  `a_package_that_fails_the_configured_version_check_is_refused`
  (`crates/fleet-agent/tests/packages_e2e.rs`, through `command`'s
  `version_args`).
- Version probe (clause 58):
  `find_semver_extracts_the_first_strict_version_from_free_text`
  (`crates/fleet-agent/src/supervisor/process.rs`, the strict default);
  `the_probe_reports_a_version_description`,
  `a_failing_or_versionless_probe_stays_silent` and
  `a_swapped_binary_is_probed_again_for_its_version`
  (`crates/fleet-agent/tests/supervisor_process.rs`). A kind's own parser is
  tested with that kind.
- [`crates/fleet-agent/src/reconfigure.rs`](../../crates/fleet-agent/src/reconfigure.rs)
  tests: `a_delivered_block_may_not_add_environment_the_operator_did_not_allow`,
  `a_loader_variable_is_refused_whatever_the_operator_allowed`,
  `a_delivered_block_keeps_the_environment_it_already_runs_with`,
  `delivered_arguments_need_the_operators_consent`,
  `a_delivered_value_may_not_point_into_its_own_directories` (clause 38),
  `delivered_tables_from_two_entries_keep_their_sub_tables` (clause 40). The
  confinement of clause 39 is tested with the kind that states a file setting,
  by the tests its ADR names.
- Directory and program, in `crates/fleet-agent/src/config.rs`:
  `the_supervisor_root_defaults_under_the_state_dir_and_is_relocatable`,
  `a_relative_state_dir_yields_absolute_directories`,
  `a_bare_name_resolves_and_everything_else_is_refused`,
  `an_absolute_program_path_is_refused_and_names_the_way_across`,
  `the_retired_package_keys_are_refused`,
  `a_program_path_must_stay_inside_the_package`.
- Consent and start, in `crates/fleet-agent/src/supervisor/mod.rs`:
  `every_supervisor_declares_package_acceptance`,
  `installs_packages_reflects_declared_package_acceptance`,
  `a_tree_supervisor_prepares_its_root_and_leaves_the_tree_to_the_package`,
  `a_program_path_that_is_neither_fails_the_build`,
  `a_block_without_a_program_fails_the_build`,
  `an_orphaned_supervisor_directory_is_not_reaped_at_startup`.
- Placeholders: `the_placeholders_name_this_supervisors_own_directories` and
  `an_unknown_placeholder_is_passed_through_untouched`
  (`crates/fleet-agent/src/supervisor/ports.rs`),
  `a_command_supervisors_arguments_are_expanded_to_its_own_directories`
  (`crates/fleet-agent/tests/supervisor.rs`), `the_spec_carries_the_environment`
  (`collector.rs`).
- The set apply, in `crates/fleet-agent/src/reconfigure.rs`:
  `foreign_top_level_keys_are_ignored`,
  `duplicate_supervisor_names_fail_the_offer`,
  `a_malformed_block_names_its_entry`,
  `blocks_are_collected_across_entries_in_name_order`,
  `a_server_delivered_block_may_not_name_an_absolute_program`,
  `a_server_delivered_block_naming_a_bare_program_is_accepted`,
  `a_delivered_collector_binary_must_be_owned_too`,
  `the_write_replaces_blocks_and_keeps_the_operators_file`,
  `the_rewrite_keeps_the_files_restrictive_mode`,
  `a_freshly_created_file_is_owner_only`,
  `the_plan_is_a_diff_by_name_and_unchanged_blocks_ride_through`,
  `the_purge_deletes_exactly_the_removed_supervisors_directory`,
  `the_purge_does_not_follow_a_symlink_out_of_the_supervisors_root`,
  `an_empty_offer_removes_every_block`;
  `retiring_uninstalls_the_removed_and_only_stops_the_changed`
  (`crates/fleet-agent/src/engine.rs`); and end to end
  `a_config_change_reaches_both_supervised_agents_over_one_connection`
  (`crates/fleet-agent/tests/e2e.rs`), which adds, keeps and removes a
  Supervisor through a delivered set and checks the purge.
- The switch (clauses 41 to 47):
  `server_manages_set_defaults_to_true_and_reads_false`
  (`crates/fleet-agent/src/config.rs`, clause 41);
  `the_own_agent_of_a_host_that_keeps_its_set_declares_neither_remote_config_capability`,
  `a_set_offered_anyway_to_a_host_that_keeps_it_is_neither_stored_nor_applied_nor_reported`
  and `a_set_ignored_by_a_host_that_keeps_it_is_logged_once_per_hash`
  (`crates/fleet-agent/src/supervisor/agent.rs`, clauses 42 and 43);
  `the_supervisor_set_apply_refuses_to_run_on_a_host_that_keeps_its_set`
  (`crates/fleet-agent/src/transport/mod.rs`, clause 43);
  `a_host_that_keeps_its_set_drops_the_stored_set_and_reports_no_status`,
  `a_stored_set_that_cannot_be_removed_does_not_stop_startup`,
  `a_copy_that_cannot_be_removed_still_leaves_no_hash_to_report`,
  `an_undecodable_stored_set_is_deleted_and_config_is_left_alone` and
  `the_removed_stored_set_is_logged_naming_its_hash`
  (`crates/fleet-agent/src/supervisor/mod.rs`, clauses 42, 44 and 47); and end
  to end `a_server_offers_no_supervisor_set_to_a_host_that_keeps_it`
  (`crates/fleet-agent/tests/e2e.rs`, clauses 42, 45 and 47).
- The switch per Supervisor (clauses 48 to 55):
  - `crates/fleet-agent/src/config.rs`:
    `remote_config_disabled_defaults_to_empty_and_lists_supervisor_names`
    (clause 48),
    `a_remote_config_disabled_name_outside_the_instance_name_grammar_fails_startup`
    (clause 49).
  - `crates/fleet-agent/src/supervisor/agent.rs`:
    `a_supervisor_with_remote_config_disabled_declares_neither_remote_config_capability`
    (clause 50: the report's `capabilities` lack both bits and keep
    `ReportsEffectiveConfig`, `AcceptsRestartCommand` and the package bits),
    `a_remote_config_offered_anyway_is_neither_stored_nor_applied_nor_reported`
    (clause 51: no `remote-config.pb`, no entry file, no pending apply, no
    `remote_config_status` in the next report),
    `an_ignored_remote_config_is_logged_once_per_hash` (clause 51).
  - `crates/fleet-agent/src/supervisor/mod.rs`:
    `a_listed_name_without_a_block_is_a_notice_not_a_refusal` (clause 49),
    `a_listed_supervisor_drops_the_stored_remote_config_and_keeps_the_operators_files`
    (clause 52: unchanged entries and `.supplementary` deleted, an overwritten
    entry and an operator's extra file kept, `remote-config.pb` gone, before the
    kind starts),
    `an_undecodable_stored_remote_config_is_deleted_and_config_is_left_alone`
    (clause 52),
    `a_listed_supervisor_reports_no_remote_config_status_after_a_restart`
    (clause 52),
    `the_clients_own_agent_keeps_accepting_its_supervisor_set_when_its_name_is_listed`
    (clause 49).
  - `crates/fleet-agent/src/reconfigure.rs`:
    `a_delivered_set_cannot_switch_remote_config_back_on_for_a_listed_name`
    (clause 48: a set that removes and re-adds the listed block leaves the
    started Agent without `AcceptsRemoteConfig`, and the written file keeps
    `[supervisors]` byte for byte),
    `a_delivered_block_for_a_listed_supervisor_must_equal_the_running_block_whole`
    (clause 54: with `delivered_args = true` and `delivered_env = ["*"]`, a
    delivered block for a listed name that changes `args`, `version_args`, an
    `env` entry or a core key, adds a key or drops one fails the offer naming
    the block and the key; the running block delivered back passes),
    `an_added_listed_supervisor_carries_only_what_names_its_program` (clause 54:
    with no running block, `type`, `name` and `binary` for a `collector`, and
    `command` for a `command`, pass; any further key, an empty `args` or `env`
    among them, fails the offer naming it).
  - `crates/fleet-agent/src/storage.rs`:
    `a_store_cut_short_leaves_no_previous_entry_file_beside_a_new_pb` (clause
    52: a store cut short while it writes the new entry files leaves the
    previous `remote-config.pb` beside no previous entry file, so nothing of the
    previous offer stays unattributed).
  - `crates/fleet-agent/tests/supervisor.rs`:
    `a_listed_collector_runs_on_the_entries_the_operator_placed` (clause 53).
  - `crates/fleet-agent/tests/e2e.rs`:
    `a_server_offers_no_configuration_to_a_listed_supervisor` (clauses 50 and
    55: a released Configuration reaches the unlisted Supervisor and not the
    listed one over the same connection).

**Not mechanically decidable:** the process-group stop (clause 56) has no
dedicated test: a worker left behind shows only with an agent that forks one, so
review of the spawn and of `signal_child` in
`crates/fleet-agent/src/supervisor/process.rs` holds it.
