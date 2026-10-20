# Specification — OpAMP Fleet

> The **specification** of this project: the problem it solves, where it is going, and the
> vocabulary everyone (humans and agents) must use. This document is the **constitution** —
> every Architecture Decision Record in [`adr/`](adr/) derives from it and must not contradict it.

## Problem

A telemetry fleet is a heap of agents on a heap of machines, each configured by a file next to it.
That is fine for one agent and untenable for a fleet: changing what a hundred agents do means reaching
a hundred machines, and nobody can answer, with certainty, what each one is *actually* running right
now. Configuration drifts, rollouts are ad-hoc, and a bad configuration is discovered by the absence
of telemetry rather than by a report.

[OpAMP](https://opentelemetry.io/docs/specs/opamp/) — the Open Agent Management Protocol — exists to
close exactly this loop: an agent accepts configuration over the protocol and reports back what it
applied and how it is doing. But three gaps keep it from managing a real fleet. First, the protocol
needs a **Server** on the other end, and there is no such server in Rust. Second, a real fleet is
**heterogeneous**: alongside OpenTelemetry Collectors it runs agents that do **not** speak OpAMP at
all, and a purely OpAMP-native tool simply cannot see them — so the fleet is never managed from one
place, only the OpAMP-native slice of it is. Third, implementations tend to cover a convenient
**subset** of the protocol and leave the rest undone and undocumented, so an operator cannot tell
what a given pairing of Server and Client will actually do.

**OpAMP Fleet** is a Rust implementation that closes all three: the Server, a Client that manages
OpAMP-native and non-OpAMP processes alike behind the same protocol, and a written record of exactly
how much of the protocol each end implements.

## Mission

Give operators one place — reachable by any UI through a REST API — to decide what every agent in a
heterogeneous fleet is running, and to see what each one is actually running, whether or not the agent
itself speaks OpAMP — on an implementation of OpAMP that is as complete as the protocol allows and
demonstrably in step with its upstream specification.

## Vision

An operator changes a configuration in one place and knows, within seconds, which agents took it and
which did not, and why — across OpAMP-native Collectors and foreign, non-OpAMP agents alike. A change
can address the whole fleet or a chosen subset of it, so a configuration can be rolled out to part of
the fleet before all of it. And what the Server distributes is not only configuration but the agents'
software itself: it can update an agent's binary in place, verified before it is applied and rolled
back on failure. Agents that were never built for OpAMP are brought into the same control loop by
purpose-built supervisor plugins, so the whole fleet's real state is observable rather than assumed,
and a rejected configuration or a failed update is a reported event, not a silent outage.

One Client binary covers the shapes a real deployment needs. It **supervises** local processes — and
because every supervisor also listens on loopback for OpAMP, a Collector carrying its own OpAMP client
reports *to its own supervisor* rather than being watched from the outside. Independently of that, the same binary
can stand at a network boundary as a **gateway**, folding many clients' connections onto a small pool
of upstream ones; a machine may do both at once. Whichever shape it takes, the Server sees only Agents
distinguished by their identity, never by the connection that carried them — so a fleet can grow past
the point where one connection per agent is affordable.

The Server exposes a stable, OpenAPI-described REST API and carries only a rudimentary user interface of
its own,
so any external portal can integrate it easily and render the fleet however it likes. The Client is one
process that can supervise many managed processes at once, installs as a native operating-system
service that updates itself in place, and runs on Linux, macOS, and Windows; growing to a new kind of
managed process means writing a new plugin, not changing the core. Both ends carry a written record of
which parts of the protocol they implement, kept in step with the upstream specification rather than
drifting quietly behind it. The project grows from the smallest thing that closes the loop and widens
only as the protocol and its agents actually allow.

## Strategy

- **Implement the protocol in full, and keep it in sync.** The wire contract is the OpAMP
  specification, implemented faithfully and as completely as the protocol allows on both ends. The
  version implemented against is pinned and recorded as the **Protocol Baseline**; which capabilities
  each end implements — and whether upstream considers each one stable, `[Beta]`, or `[Development]` —
  is written down in [`CONFORMANCE.md`](CONFORMANCE.md) and kept current with the code. Drift from
  upstream is detected, not discovered.
- **Own both ends in Rust.** The Server and the Client are one Rust stack, so the whole control loop is
  code this project controls. Where a reference implementation exists — `opamp-go`, the OpenTelemetry
  Collector's `opampextension`, and the `opampsupervisor` — it stays the behavioural oracle the Rust
  code is checked against, rather than being replaced by it.
- **API-first Server, portal-friendly.** The Server's public contract is an **OpenAPI-described REST
  API**, so any portal can generate a client and drive the fleet through it. The Server bundles only a
  rudimentary UI for basic operation; a richer UI lives wherever the operator wants it — a standalone
  app or an existing portal — and is expected to be built outside this project.
- **One Client, two modes that compose.** The client side is a single deployable with two **Client
  Modes**: **Supervisor Mode** manages local processes, **Gateway Mode** multiplexes other clients'
  connections upstream. They are independent — a Client may run either, or both at once. Serving a
  Collector that carries its own OpAMP client is not a third mode but an intrinsic part of Supervisor
  Mode: a Supervisor always exposes a **Supervisor Endpoint** on loopback, whether or not anything
  connects to it. One binary covers every shape, so an operator learns and deploys one thing.
- **Hexagonal core, plugins at the edge.** The supervision domain sits at the centre; **Ports**
  abstract the Server-facing side and the managed-process side; **Plugins** are the adapters that
  implement concrete process types. A Collector Supervisor and a Custom Supervisor are two plugins
  behind the same ports, and a mode is a composition of ports rather than a fork of the core.
- **Route by `instance_uid`, not by connection.** The protocol states that multiple Agents may be
  multiplexed onto one connection and distinguished by `instance_uid`. Both ends honour that: the
  Server never assumes one connection means one Agent, and the Client maps *n* Agents onto *m*
  connections (*n* ≥ *m* ≥ 1). A connection is transport, not identity.
- **Ship the Client as a self-updating OS service across all platforms; the Server on Linux.** The
  Client installs as a native operating-system service and can replace its own binary in place,
  and it is built for Linux, macOS, and Windows so one client shape manages a heterogeneous fleet. The
  Server targets Linux only.
- **Bring agents the project was never built for into OpAMP.** A Custom Supervisor plugin owns a
  foreign agent — one whose configuration format, lifecycle, and health nothing here already knows —
  and translates all three into OpAMP toward the Server, so heterogeneous agents share one control
  loop and appear in the fleet like any other Agent.
- **Security before convenience.** A fleet manager puts configuration and software onto every host
  it reaches, so a flaw in it is a flaw on all of them at once. Where security and convenience
  conflict, security wins, and the operator meets a refusal that says what to fix, not a warning.
  Every connection that leaves the host is TLS 1.3; plaintext is accepted on the loopback alone. An
  Agent proves fleet membership with a client certificate in the TLS handshake, issued to its host,
  and it obtains that certificate in a separate enrolment that is time-limited and approved. This is
  done with the protocol's own means — client certificates, the CSR flow, and the
  `ConnectionSettings` offers that let the Server renew a Client's certificate — never through a
  private side channel. Software is installed only when it is signed with a key the operator holds
  and fetched from the fleet itself — the Server, or a Gateway relaying it. No vulnerability can be ruled out, so the project
  shrinks the chance of one and the damage it can do: every input from the network is bounded before
  it is parsed, the parsers are fuzzed, and the dependencies are checked before they are merged.
- **Close the loop before widening it.** A working control loop — configure, apply, report back — for
  one managed process comes first. Targeting a subset of the fleet and updating an agent's software
  are core goals, built on top of that loop once it holds, not before it.
- **Distribute software, not only configuration.** The Server can deliver and apply agent binaries, not
  just their configuration — verified before applying and rolled back on failure — but only as far as
  the managed processes actually support it, never pretending to a capability an agent lacks.
- **Configure the whole fleet or a part of it.** A configuration can be directed at the whole fleet or
  at a selected subset, so a change can be rolled out gradually; an Agent outside a target is left
  running what it already runs.
- **One configuration, many hosts.** A Configuration is written once and serves every host it
  reaches: what differs between them is a parameter, filled in from what the Server knows about an
  Agent and its Host, or from what only the host knows. Secrets stay on the host.

## Core Concepts & Vocabulary

Use these exact words in code, comments, documentation, and ADRs.

### The protocol

- **OpAMP** — the Open Agent Management Protocol: the wire protocol between a Server and its Agents.
- **Protocol Baseline** — the pinned upstream `opamp-spec` version this project implements against,
  recorded in [`CONFORMANCE.md`](CONFORMANCE.md). Implementation targets the Baseline; moving to a
  newer upstream version is a deliberate change, not a silent one.
- **Capability** — a feature an Agent or the Server declares it supports (accepting remote
  configuration, reporting health, reporting effective configuration, …), carried as a bit in the
  protocol's capability bitmask. Neither side may assume an undeclared capability. Each capability
  carries an upstream **maturity** — stable, `[Beta]`, or `[Development]` — and is either **required**
  (the protocol mandates it) or **optional**.
- **Capability Set** — the capabilities one end actually declares. The Server's and the Client's sets
  are tracked per capability in [`CONFORMANCE.md`](CONFORMANCE.md).
- **Instance UID** — the identity of an Agent, generated as a **UUID v7** and stable across restarts by
  default. It is the **routing key**: it, and not the connection a message arrived on, determines which
  Agent a message belongs to. The Server may reassign it (via OpAMP's AgentIdentification), and the
  Client then adopts the new value for all further communication.
- **Config hash** — the identity of a configuration. An Agent reports the hash it last received; the
  Server compares it against the hash of the configuration that Agent should have, and sends a new
  configuration only when they differ. This comparison is the control loop.

### The two ends

- **Server** — this project's control plane. It tells Agents which configuration they should be running
  and records what they report back. There is exactly one Server per fleet. It is **API-first**: its
  primary interface is the OpenAPI REST API, and it ships only a rudimentary UI, so any external portal
  can integrate it. The Server runs on Linux only.
- **Client** — this project's client deployable: the process an operator installs on a machine to place
  it under management. One Client process runs in one or more **Client Modes** and may present itself
  to the Server as several **Agents**. It is the OpAMP Client in the protocol's sense.
- **Agent** — one `instance_uid` as the Server sees it: an independently identified, independently
  configured participant in the fleet. The Server does not distinguish an Agent backed by a Supervisor
  from one backed by a Collector's own OpAMP client, nor one reaching it directly from one arriving
  through a Gateway.
- **Host** — what a client certificate the Server issued identifies: one Client installation that
  connects to the Server directly, a Gateway included. It is named by the host id its certificate
  carries and described by the subject values — country, state, locality, organization,
  organizational unit, organization identifier — carried over from the bootstrap certificate it
  enrolled with. Every Agent reaching the Server over that certificate belongs to it, the Agents
  behind a Gateway to the Gateway's Host: the Server does not see the hosts behind a Gateway. Trust
  and revocation act on a Host; a Deployment aims at Agents.
- **REST API** — the Server's stable HTTP interface for reading fleet state and reading and changing
  configuration, described by an **OpenAPI** specification so clients and portals can be generated from
  it rather than hand-written. It is the integration contract any UI or portal builds on.
- **Fleet** — all Agents managed by the Server.

### Client Modes

- **Client Mode** — the role a Client process takes, selected at startup. There are exactly **two**,
  and they are independent: a Client may run **Supervisor Mode**, **Gateway Mode**, or both at once.
  Neither implies the other.
- **Supervisor Mode** — the Client runs **Supervisor** instances that manage local processes. This is
  the mode that closes the control loop for a machine's own agents. Every Supervisor also exposes a
  **Supervisor Endpoint** — that is part of what a Supervisor *is*, not a separate mode to enable.
- **Gateway Mode** — the Client accepts OpAMP connections from other Clients and forwards their
  messages upstream over a **Connection Pool**, so a large number of agents reaches the Server over
  a small number of connections. A Gateway forwards messages unchanged and holds **no authentication
  policy of its own**: it admits a connecting Client by a client certificate from the fleet's client
  CA in its handshake, as the Server would, and the one admission refusal it makes beyond that is
  the Server's — a certificate the Server has revoked. It forwards a Client's reports only for the
  Agents its host first reported, and passes on a package it holds for the Agents behind it only to
  the host whose Agent the Server offered it to through the Gateway. Where the operator gives it the
  bootstrap CA, it also relays a host's enrolment, which the Server decides as any other. Agents
  behind a Gateway remain distinct Agents.
- **Supervisor Endpoint** — the OpAMP endpoint a Supervisor exposes on the loopback interface so that
  a Managed Process carrying an OpAMP client of its own can report to it. It exists because such a
  client — notably the OpenTelemetry Collector's `opampextension` — is a **client only** and therefore
  needs something to connect *to*; the Supervisor is the natural counterpart, since it already holds
  the configuration to hand down and the upstream connection to relay onto. The Supervisor receives
  the process's agent description, health, and effective configuration there and relays them upstream,
  so a Collector reports through its own OpAMP client rather than being observed from the outside.
  It is **always present** while a Supervisor runs; for a Foreign Agent, which speaks no OpAMP, simply
  nothing ever connects to it. It is not addressable from outside the machine and never carries fleet
  traffic — that is the Server's role, and the Gateway's. Despite speaking the Server side of the
  protocol, it is not a **Server** in this vocabulary's sense: it manages no fleet, holds no
  configuration of its own, and serves exactly one Managed Process.

### Connections

- **Connection Pool** — the set of upstream connections a Client maintains to the Server, over which
  *n* Agents are carried by *m* connections (*n* ≥ *m* ≥ 1). Its size is a deployment choice, not a
  consequence of how many Agents exist.
- **Connection Multiplexing** — carrying more than one Agent over one connection, disambiguated by
  `instance_uid`. The protocol provides for this explicitly; both ends of this project support it.

### Supervision

- **Supervisor** — a unit inside a Client in Supervisor Mode that manages exactly one **Managed
  Process**: it applies the configuration it receives, reports health and effective configuration, and
  exposes a **Supervisor Endpoint** for a Managed Process able to use it. Each Supervisor is one
  **Agent** as the Server sees it, but does not necessarily own a connection of its own.
- **Collector Supervisor** — the OpAMP-native Supervisor plugin: it owns an OpenTelemetry **Collector**,
  writes the configuration it receives to disk, and restarts the Collector to apply it.
- **Custom Supervisor** — a Supervisor plugin that manages a **Foreign Agent** and translates that
  agent's lifecycle, configuration, and health into OpAMP toward the Server. It is how a non-OpAMP
  agent is brought into the fleet.
- **Managed Process** — the actual process a Supervisor manages: a Collector, or a Foreign Agent. What
  separates the two is **which Plugin has to exist for it**, not whether it speaks OpAMP: a Collector
  is served by the one Collector Supervisor that ships with the project, a Foreign Agent needs a
  Custom Supervisor written for its kind.
- **Collector** — an OpenTelemetry Collector process, managed by the **Collector Supervisor**. Its
  configuration format, lifecycle, and health are known to that Plugin, so one Plugin serves every
  Collector. Whether it additionally carries the `opampextension` changes only *how it reports*: with
  the extension it reports its own description, health, and effective configuration to the Supervisor
  Endpoint; without it, the Supervisor infers what it can from the outside. Either way the Collector
  never reaches the Server directly, and either way it is not a Foreign Agent.
- **Foreign Agent** — a Managed Process whose kind requires a **Custom Supervisor written for it**,
  because nothing in the project already knows its configuration format, lifecycle, or health. Bringing
  a new one under management means writing a Plugin (goal 8); this is the sense in which it is
  *foreign*. It never speaks OpAMP — if it did it would be an Agent in its own right and need no
  Supervisor at all — but that is a consequence of being foreign, not the definition: a Collector
  without the `opampextension` speaks no OpAMP either and is still not a Foreign Agent, because the
  Collector Supervisor already covers it.
- **Plugin** — a Supervisor implementation loaded by the Client and plugged in behind the hexagonal
  ports. Supporting a new kind of managed process means adding a plugin, not changing the core.
- **Port** — a boundary the supervision domain defines and depends on: the Server-facing side (speaking
  OpAMP) and the Managed-Process side (a Managed Process's lifecycle, configuration, and health). The
  domain is written against ports, never against a concrete process type.
- **Adapter** — a concrete implementation of a Port: the OpAMP client is an adapter on the
  Server-facing side; each Plugin is an adapter on the Managed-Process side.

### Fleet operations

- **Remote configuration** — the configuration the Server distributes to an Agent. It is what the
  Server *wants* that Agent to run.
- **Effective configuration** — the configuration an Agent reports it is *actually* running. It may
  differ from the remote configuration (it may merge in local configuration, or have rejected the
  remote one).
- **Health** — an Agent's self-reported liveness and status.
- **Selector** — the rule by which the Server addresses a **subset** of the fleet: equality pairs over
  an Agent's effective description, which is what the Agent reports, the Labels an operator set, and
  its Host's subject values. It aims a Deployment, so a change reaches the matching Agents and leaves
  the rest running what they already run, and it chooses which blocks of a Configuration an Agent
  receives. One mechanism, not two.
- **Label** — a key and value an operator sets on an Agent, part of its effective description. The
  Labels set on a Client's own Agent hold for every Agent of that Client unless an Agent sets the
  key itself. A Label never overrides what an Agent reports or what its Host's certificate says.
- **Configuration** — a named piece of an agent's own configuration language, written for one Agent
  type, with the parameters it declares. It is content only: it reaches Agents through the
  Deployments that hold it.
- **Parameter** — a named value a Configuration leaves open. A Server-side parameter is filled in
  per Agent from what the Server knows — the Deployment, the Agent's effective description — and is
  validated against its declared type before a rollout releases it. A host-side parameter is filled
  in on the host and never reported back in clear; a secret is always one.
- **Package** — a versioned, downloadable software artifact an Agent installs, identified by the
  **Agent type it is built for and its version**; its display name is derived from the two. It holds
  one entry per platform: the artifact's content hash, its size and the operator's signature. Every
  artifact is uploaded to the Server, which offers only what it holds. An Agent verifies the content
  hash and the signature and installs nothing that fails either; the Server checks a signature
  against the operator's public key when it has one and reports a failed check, but the Agent's
  check decides. An Agent reports the status of each Package. This is how the Server updates an
  agent's software, not only its configuration.
- **Deployment** — a named release: Packages, at most one per Agent type, and Configurations, aimed
  at a subset of the Fleet by a Selector. It is the only thing that is rolled out; a rollout pins
  for each Agent the Package and the Configuration revisions it releases, so editing the Deployment
  afterwards changes nothing an Agent runs. An Agent belongs to **at most one**: two Deployments
  matching one Agent is a conflict, and that Agent is offered nothing new until it is resolved. An
  Agent in no Deployment is offered nothing.
- **Updater** — the separate process that applies a Package: it stops the target (the Managed Process,
  or the Client itself), replaces its binary, restarts it, and rolls back on failure. A running process
  cannot reliably replace its own binary, so this work is handed off across a process boundary.

## Goals / Success Criteria

1. **G-1** — **The loop closes.** A configuration change made on the Server reaches a connected
   Agent without it asking for it, and the Agent reports it as applied.
2. **G-2** — **The Server knows the fleet's state.** For every connected Agent it can report: its
   identity, its health, the configuration it holds, and whether it accepted or rejected it —
   including the error when it rejected it.
3. **G-3** — **No redundant reconfiguration.** An Agent that already runs the intended configuration
   is not sent it again; the config-hash comparison gates every push.
4. **G-4** — **A rejected configuration is visible.** An Agent that refuses a configuration surfaces
   the reason rather than failing silently.
5. **G-5** — **Any UI can drive the fleet.** The OpenAPI-described REST API exposes fleet state and
   configuration as a stable contract; an external UI or portal reads the fleet and changes what it
   runs entirely through that API. The Server bundles only a rudimentary UI of its own.
6. **G-6** — **One Client runs many supervisors.** A single Client process runs multiple Supervisor
   instances concurrently, each appearing to the Server as its own independent Agent.
7. **G-7** — **An agent the project was never built for is managed like any other.** A Foreign Agent
   placed under a Custom Supervisor written for its kind is configured, reports health, and reports
   back through the same control loop, and appears in the fleet indistinguishably from a Collector.
8. **G-8** — **A new process type is a new plugin.** Adding support for another kind of Managed
   Process is done by writing a Plugin against the existing ports, without changing the supervision
   domain core.
9. **G-9** — **A configuration can target a subset of the fleet.** The Server can direct a
   configuration at a selected subset of Agents via a Deployment's Selector; the matching Agents apply it and
   every Agent outside the target keeps running what it already runs, so a change can be rolled out
   gradually rather than all at once.
10. **G-10** — **The Server updates an agent's software, not only its configuration.** Via OpAMP
    package delivery the Server can update an agent's binary — the Collector's, and the Client's own
    — verifying each Package before it is applied, reporting the outcome, and rolling back on
    failure. A failed update is reported, not silent.
11. **G-11** — **The Client runs and updates itself as an OS service, on every platform.** The
    Client installs and runs as a native operating-system service on Linux, macOS, and Windows, and
    can replace its own binary in place — a self-update that survives the service restart and is
    rolled back on failure. The Server runs on Linux.
12. **G-12** — **Protocol coverage is on the record.** [`CONFORMANCE.md`](CONFORMANCE.md) states,
    for every capability of both ends, whether it is implemented, its upstream maturity, and whether
    it is required or optional — and the matrix matches what the code actually does.
13. **G-13** — **The protocol stays in step with upstream.** The Protocol Baseline is visible in the
    repository and a divergence from upstream is detected automatically rather than noticed by
    chance.
14. **G-14** — **n Agents over m connections.** Several Supervisors either share one connection to
    the Server or spread across several, as configured; the Server tells them apart solely by
    `instance_uid` and behaves identically either way.
15. **G-15** — **A Gateway scales connections, not identities.** Many Clients reaching the Server
    through a Client in Gateway Mode appear as their own Agents, fully manageable, while sharing a
    small Connection Pool — and the Gateway makes no authentication decision of its own: it admits
    a Client by a certificate from the fleet's client CA, as the Server does, refuses what the
    Server has revoked, admits no one while it cannot learn what that is, forwards a Client's
    reports only for its own host's Agents, and passes on a package the Server offered through it
    only to the host it was offered to. A host that only a Gateway connects enrols through it.
16. **G-16** — **A Collector reports through its own OpAMP client.** A Collector carrying the
    `opampextension` connects to its Supervisor's Supervisor Endpoint, which relays the Collector's
    statement of what it is (its `service.*` description), its health, and its effective
    configuration upstream — so the Collector's own reporting, rather than external observation, is
    what makes it visible in the fleet. What the host is stays the Supervisor's and the operator's
    to state.
17. **G-17** — **The connection is secured and the Agent is identified.** Client-to-Server traffic
    is TLS-protected on both ends, mutual TLS is required, and the Server accepts only
    authenticated Agent identities.
18. **G-18** — **One Configuration serves many hosts.** A Configuration declares parameters and
    blocks. The Server fills in its Server-side parameters per Agent and validates every value
    against its declared type, so a value that does not fit stops the rollout for that Agent and
    says why; it chooses the blocks an Agent receives by their Selectors. Host-side parameters,
    secrets among them, are filled in on the host and reach the Server only masked.

## Quality Goals

1. **Q-1** — **Secure by default.** Whatever its configuration, neither end sends a credential, a
   configuration or a package unencrypted beyond the loopback, admits an Agent onto the Server
   or a Gateway without a client certificate, or installs a package without a valid signature. A
   configuration that would do any of these is refused at startup, naming the setting.
2. **Q-2** — **Untrusted input is bounded and fuzzed.** Every parser that reads bytes from the
   network or from a downloaded artifact enforces its size limit before it allocates, and has a fuzz
   target that runs in CI.
3. **Q-3** — **The supply chain is checked before it is merged.** No change merges while a
   dependency carries a known vulnerability, an unapproved licence, or a source outside the
   registry, or while the TLS stack accepts a protocol version below 1.3.

## Non-Goals

- **Being a telemetry backend.** OpAMP Fleet manages agents; it does not receive, store, or query the
  telemetry they produce.
- **Replacing an agent's configuration language.** The Server distributes each Managed Process's own
  configuration; it does not invent an abstraction over the Collector's or a Foreign Agent's format.
  Parameters and blocks (G-18) are a text layer over that language — substitution and selection —
  not a model of it.
- **Forking or extending the protocol.** This project implements OpAMP as upstream defines it. Where
  it falls short of the Baseline the gap is recorded in [`CONFORMANCE.md`](CONFORMANCE.md) as a
  deviation; it is never resolved by inventing protocol semantics of this project's own.
- **Shipping a production UI.** The Server provides the OpenAPI REST API and only a rudimentary UI for
  basic operation; a production-grade user interface is external and out of scope for this project to
  build.
- **Authorization and multi-tenancy.** The Server authenticates *that* a peer belongs to the fleet
  (goal 17), but does not distinguish *which* operator may do *what*, nor separate one operator's
  fleet from another's. Roles, permissions, and tenancy are real needs deferred rather than
  half-built. On the Agent plane one bound holds: a host receives from the Server, directly or
  through a Gateway, only the configurations and packages released to an Agent it speaks for.
