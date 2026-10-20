# ADR-0015: One Client binary with two composable modes, carrying n Agents over m connections, and a Gateway that admits by client certificate over mutual TLS 1.3, refuses what the Server revoked, and passes on a package only to the host it was offered to, and a Supervisor Endpoint that admits only the process its Supervisor started

- **Status:** 🟢 accepted · clauses 11 and 13 superseded by
  [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)
- **Date:** 2026-10-06
- **Deciders:** Markus Brigl
- **Applies to:** crates/fleet-agent/src/gateway/,
  crates/fleet-agent/src/supervisor/endpoint.rs, the [gateway] configuration
  section, every place either end keeps per-Agent state, the token threaded
  through `SupervisorContext` and `Runner` in
  crates/fleet-agent/src/supervisor/, the environment every Managed Process is
  started with, and the `opampextension` configuration the documentation shows

## Context

[ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
has a Gateway pass on the uploaded artifacts it holds for the Agents behind it
only to a host whose Agent it relayed the Server's offer of that artifact to,
and answer every other download request `404`. What a downstream peer is
admitted to and what it may receive from the Gateway are one question about the
downstream hop, so the bound belongs in the decision that answers it for
admission: clause 11 names the download bound as the one refusal beyond
admission and states that the bound is the Server's own, applied to what the
Server sent through the Gateway.

The [specification](../SPECIFICATION.md) asks the client side to cover three
shapes: supervise local processes, serve a Collector that speaks OpAMP itself,
and act as a gateway that carries many other Clients upstream over a small
Connection Pool (goal 15). They are not three peers.

**Supervising and serving an OpAMP-speaking Collector are inseparable.** The
Collector's `opampextension` is an OpAMP _client only_; it must be given
something to connect to. The natural counterpart is the Supervisor that owns
that Collector, because it holds the configuration to hand down and the upstream
connection to relay onto. An endpoint without a Supervisor has nothing to relay
to, and a Supervisor without one cannot manage an extension-carrying Collector.
Gatewaying for other machines is genuinely independent: a host may supervise,
gateway, or do both.

**The protocol provides for multiplexing.** The Baseline documents
`ServerToAgent.instance_uid`: _"When communication with multiple Agents is
multiplexed into one WebSocket connection (for example when a terminating proxy
is used) the `instance_uid` field allows to distinguish which Agent the
ServerToAgent message is addressed to."_ Over plain HTTP the same pooling
follows from each request carrying its own `instance_uid`. Any end that keys
Agent state on the connection misroutes messages as soon as a gateway sits in
front of it, and that assumption is the expensive one to remove later.

**A Gateway terminates.** The Gateway terminates the downstream handshake and
presents its own certificate upstream, so the Server never sees a downstream
certificate and cannot refuse it. A certificate the Server has revoked would
stay a member behind a Gateway until it expires unless the Gateway refuses it.
The specification puts security before convenience (Strategy, "Security before
convenience"; G-17, "the Server accepts only authenticated Agent identities").

**Behind a Gateway the handshake is the only proof.** No per-Agent proof crosses
a terminating Gateway: the Server sees the Gateway's certificate, and the
downstream one stays on the downstream hop. A fleet-wide credential did not
identify an Agent behind a Gateway either, and every host held it, so its
removal takes no identity away. A Gateway's certificate already speaks for any
Agent once an operator marks its host as a Gateway
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 7).

**A Gateway must not invent messages.** The specification forbids resolving a
protocol gap by inventing semantics of this project's own. When something fails
on one side of a hop, the tempting fix is to synthesise a message toward the
other, and that is exactly what is not available. Nor is a connection an
identity in either direction: upstream connection state says nothing about
whether a downstream Client is alive.

**A pool that is a fixed cost is a pool nobody keeps small.** The prior art
opens ten connections at startup; ten connections for a gateway in front of
three Agents is worse than three.

**The Supervisor Endpoint is open to every local process unless it asks for a
proof.** Every Supervisor serves it on `127.0.0.1` (clause 2,
[ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
clause 5), where a Collector's `opampextension` reports its description, health
and effective configuration. An endpoint that authenticates nothing lets any
process on the host connect and report in the Collector's name, and the fleet's
view of that Agent becomes forgeable from the inside. On a single-purpose host
that is a small risk; on a shared or multi-user host it is not.
[`HARDENING.md`](../HARDENING.md) asked for a decision either way, and the
specification puts security before convenience. The Supervisor starts the
process it supervises, so it can hand that process a secret no other local
process has: the environment of a child is readable by the child and by root,
not by other accounts. The `opampextension` sends configured headers on its
WebSocket, and a Collector configuration reads an environment variable with
`${env:…}`.

## Decision

We will ship one Client binary with exactly two independent Client Modes,
Supervisor Mode and Gateway Mode, give every Supervisor a Supervisor Endpoint
unconditionally, route by `instance_uid` alone on both ends, and implement
Gateway Mode as a `[gateway]` section serving both transports downstream over
mutual TLS 1.3, admitting each downstream Agent by its client certificate from
the fleet's client CA, refusing every downstream certificate the Server has
revoked, passing on an uploaded artifact only to the host whose Agent the Server
offered it to through the Gateway, and a lazily grown, sticky upstream pool
shared by every Agent it carries that forwards messages unchanged and
synthesises none, and have each Supervisor make a fresh random token at every
start, hand it to its Managed Process as `OPAMP_SUPERVISOR_TOKEN`, and refuse
any connection to its Supervisor Endpoint that does not present it as
`Authorization: Bearer <token>`.

1. **Two modes, freely composable, neither implying the other.** Supervisor Mode
   (`[[supervisor]]` blocks) and Gateway Mode (`[gateway]`) run alone or
   together in one process. A mode is a composition of Ports, not a fork of the
   core: the supervision domain does not learn which mode it is in.

2. **Every Supervisor exposes a Supervisor Endpoint, unconditionally.** It binds
   `127.0.0.1` on the block's `endpoint_port`
   ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md))
   before the Managed Process starts, so a taken port fails startup. It is
   WebSocket-only, declares `AcceptsStatus` and `AcceptsEffectiveConfig`, and
   folds what the process reports into the owning Agent, whose `instance_uid`
   stays the Supervisor's. For a Managed Process that speaks no OpAMP nothing
   ever connects, and that is the whole of the handling. The Supervisor Endpoint
   is not a mode.

3. **Neither end keys state on a connection.** The Server indexes Agents by
   `instance_uid` only; the Client maps Agents onto connections without assuming
   one-to-one. _n_ Agents ride _m_ connections (_n_ ≥ _m_ ≥ 1), and the pool
   size is a deployment choice, not a consequence of the Agent count.

4. **`[gateway]` arms Gateway Mode.**

   | Key                    | Default | Rule                                                                                                                                                                                      |
   | ---------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | `listen`               | none    | Required. A Gateway that binds nothing is a configuration error; loopback is the Supervisor Endpoint's job. A bind failure fails startup.                                                 |
   | `upstream_connections` | `10`    | The pool's cap, not its size. `0` is refused at load.                                                                                                                                     |
   | `max_carried_agents`   | `10000` | The most distinct Agents one downstream connection may carry. Past it a report for a _new_ Agent is dropped and logged; Agents already carried keep working. `0` is refused at load.      |
   | `[gateway.tls]`        | none    | Required, with `cert_file`, `key_file` and `client_ca_file` for the downstream hop. A Gateway without it, or without `client_ca_file`, is refused at startup, on a loopback `listen` too. |

   The Client's own `endpoint` must be `ws://` or `wss://` when `[gateway]` is
   present: a polling connection cannot carry the Server's pushes to the Agents
   behind the Gateway.

5. **The downstream endpoint serves both transports.** A downstream Client picks
   its transport by the scheme of its endpoint
   ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)),
   so the Gateway serves a WebSocket upgrade and a plain-HTTP POST on
   `/v1/opamp`, with the Baseline's message size limit, protobuf media type and
   gzip rules enforced per hop through the shared `opamp::endpoint` helpers
   ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
   clause 17).

6. **axum serves it, as an ordinary dependency of the Client crate behind no
   Cargo feature.** The mode lives in `crates/fleet-agent/src/gateway/`
   (`mod.rs` the endpoint, `pool.rs` the upstream pool, `registry.rs` the
   downstream routes), beside `supervisor/`. The HTTP engine under axum is
   linked through `reqwest` anyway; axum adds the routing layer. TLS on the
   downstream hop uses the same `axum-server` rustls terminator as the Server.

7. **An Agent is assigned to the least-loaded live connection, and stays
   there.** Assignment is by `instance_uid` and sticky while that connection
   lives, which keeps an Agent's `sequence_num` stream and its `ReportFullState`
   exchanges on one upstream socket. Any live upstream connection carries any
   downstream Agent: the pool is not divided by downstream peer, because nothing
   the Gateway sends upstream depends on which peer an Agent came through.

8. **The pool grows lazily to its cap, and never beyond.** The first Agent opens
   the first connection; a new one opens only when every live connection already
   carries an Agent and the cap is not reached. Past the cap, Agents share.
   Existing Agents are not re-balanced when a connection is added.

9. **A dropped upstream connection re-homes its Agents and says nothing on their
   behalf.** An Agent whose connection is gone is re-assigned by clause 7 on its
   next report, which is forwarded over the new connection. The Gateway sends no
   `agent_disconnect` for it. The Server marks those Agents disconnected because
   their owning connection dropped, and their next report corrects that.

10. **A downstream Client that vanishes is reported by its absence, not by a
    message.** An `agent_disconnect` it sends is forwarded like any other
    message. If it just goes away, its routes are released and the Gateway
    forwards nothing. Such an Agent stays connected in the fleet view with a
    `last_seen_ms` that stops advancing, and reads as stale once its staleness
    budget runs out when it declared `ReportsHeartbeat`
    ([ADR-0024](0024-the-fleet-record.md)).

11. **The downstream handshake and the Server's revocation list are a downstream
    Agent's admission; the Gateway holds no policy of its own, and its own hop
    is its own.** Mutual TLS is per hop and mandatory downstream: the handshake
    requires a client certificate that chains to `client_ca_file`
    (`ClientAuth::Required` in `opamp`), so a peer without one never reaches
    OpAMP; `client_ca_file` must be the fleet's client CA, never a bootstrap CA.
    A peer that passed the handshake is admitted unless its certificate is on
    the list of clause 14; that is the one admission refusal the Gateway makes
    beyond the handshake, and it is the Server's. Beyond admission the Gateway
    refuses one thing: it passes on an uploaded artifact from its package cache
    only to a host whose Agent it relayed the Server's offer of that artifact
    to, and answers every other download request `404`
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
    clause 45). What a host may receive is the Server's own bound (ADR-0026
    clause 37), applied to what the Server sent through this Gateway. Three
    parts of that refusal are the Gateway's own: it binds an `instance_uid` to
    the host of the first report for it, it answers `404` for an artifact too
    large for its cache or whose fetch failed, and it answers `503` while a
    fetch runs (ADR-0026 clauses 42, 45, 47). The client CA and the list are the
    Server's, so the Gateway applies the Server's admission policy and holds no
    admission policy of its own
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clauses 7, 13). Upstream the Gateway presents the Client's own identity, so
    every downstream Agent arrives as a member, under the Gateway's certificate.
    The Gateway forwards no `Authorization`: one a downstream peer sends is
    ignored, never refused, and nothing is sent upstream in its place. The
    downstream hop speaks TLS 1.3 only. A downstream certificate is never
    forwarded, and no header is invented for it. There is no plaintext Gateway,
    on the loopback neither, because a Gateway admits Agents.

12. **The Gateway is its own Agent, and only its own.** The Client presents its
    own Agent upstream exactly as any Client does, and never presents itself as
    an Agent it carries.

13. **Routing is by `instance_uid` alone, in both directions.** Upward a report
    goes out on its Agent's connection. Downward the Gateway looks up, per
    `instance_uid`, the downstream connection or pending plain-HTTP exchange
    that last carried the Agent; a `ServerToAgent` for an Agent it does not
    carry is dropped with a log line, never broadcast.

14. **The Gateway refuses what the Server revoked, and admits nobody while it
    cannot know.** The Gateway fetches the revoked certificates of the fleet's
    client CA from its Server
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 43) over its own upstream origin, with its own certificate and no
    `Authorization`, every `REVOCATION_REFRESH` (30 s), conditionally on the
    list it holds. It keeps the list in memory only. A downstream peer whose
    certificate is on the list is answered `401` after the handshake and before
    anything is forwarded, on both transports; an open downstream WebSocket
    session whose certificate the list newly names is closed with `1008` and the
    reason `revoked`, as the Server closes its own, and a report arriving on a
    session the list no longer admits is not forwarded. The Gateway starts
    serving once its first fetch has answered or failed, and at most
    `REVOCATION_FIRST_WAIT` (5 s) after it started, so its first peers are not
    refused for want of a list. While it holds no list fetched within
    `REVOCATION_MAX_AGE` (300 s) — from then until a first fetch succeeds, and
    whenever its Server has not answered for that long — it answers every
    downstream request `503` and closes every downstream session with `1008` and
    the reason `revocation list stale`. The three values are named constants. A
    Gateway the Server refuses the list to holds no list, and admits nobody.

15. **A Supervisor Endpoint token per start.** 32 bytes from the system's secure
    random source, hex, made when the Supervisor starts and kept in memory only.
    A restart of the Supervisor makes a new one.

16. **Handed to the process, last.** The Runner sets `OPAMP_SUPERVISOR_TOKEN` in
    the environment of every Managed Process it starts, after the block's own
    `env`, so no block can replace it.

17. **Asked of every connection to the Supervisor Endpoint.** The endpoint
    compares the `Authorization` value of the upgrade request with
    `Bearer <token>` in constant time and answers `401` before the upgrade when
    it does not match. A refusal is logged at `warn`.

18. **The Collector presents it from its configuration.** A Collector
    configuration that reports through the endpoint names the header:
    `headers: { Authorization: "Bearer ${env:OPAMP_SUPERVISOR_TOKEN}" }`. One
    without it loses its own reports, not its supervision.

**Out of scope:** re-balancing Agents across a grown pool; consolidating the
three places TLS material is configured on a Client; authenticating the
Supervisor to the Managed Process; a Supervisor Endpoint token on disk.

## Alternatives considered

- **Separate deployables (a supervisor binary, a gateway binary).** Both shapes
  share their whole OpAMP stack, so this multiplies packaging and release
  surface to express a startup choice, and it forecloses a machine that
  supervises its own processes and fronts others.
- **A third, independently selectable "local server" mode.** It would let an
  operator configure combinations that cannot work and put a conditional on a
  path that has no reason to vary.
- **Enable the Supervisor Endpoint only for Collector Supervisors, or per
  block.** More precise, but it buys that with a configuration surface and a
  branch to avoid an idle loopback listener. The `opampsupervisor` brings its
  local server up unconditionally too.
- **One connection per Agent, or multiplexing only in Gateway Mode.** The first
  makes Gateway Mode impossible and induces the connection-equals-agent
  assumption on the Server; the second leaves two routing models in the code
  while the Server must support the general one anyway.
- **An admission policy of the Gateway's own.** The specification places
  authentication policy on the Server; a gateway with a policy of its own, such
  as an allow-list or a CA of its choosing, duplicates it and forces every
  change of it to reach every gateway. The Gateway applies two things of the
  Server's: the client CA the Server issues from and the revocation list.
- **A per-Agent proof that travels end to end through the Gateway.** No proof of
  that kind exists on the Agent plane
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
  A fleet-wide credential forwarded in a header proved membership, which the
  downstream handshake already proves, and identified no Agent.
- **Keeping the upstream pool partitioned by downstream peer.** Nothing
  peer-specific travels upstream any more, so a partition buys nothing; it costs
  connections, and at the cap it refuses an Agent while connections of another
  partition sit there.
- **Forwarding the downstream certificate to the Server, which decides.** It
  keeps every decision on the Server, but the Server would trust a certificate
  the Gateway asserts in a header of its own invention, and a pooled upstream
  connection carrying many Agents could no longer be judged by one certificate,
  so the pool would have to split per certificate. It also leaves a revoked peer
  on the Gateway's downstream hop until the Server answers.
- **Using the last list for as long as the Server is away.** A Gateway that
  cannot reach its Server forwards nothing anyway, and a list kept indefinitely
  would admit a certificate revoked while it was away the moment the Server
  returns, until the next fetch. A bound costs nothing a working Gateway does.
- **The list pushed in an OpAMP message.** A `CustomMessage` is `[Development]`
  in the Baseline and not implemented here; a field of the connection-settings
  offer is meant for something else. Either ties the list to an Agent's session
  rather than to the Gateway as a host.
- **A plaintext or server-authenticated-only Gateway hop.** A Gateway admits
  Agents, and the specification admits none without a client certificate in the
  handshake and none over anything but TLS 1.3 beyond the loopback. A loopback
  exception would still let any local process ride the Gateway's upstream
  connections, and a warning in place of a refusal leaves the insecure
  configuration running.
- **A fixed pool opened at startup.** The prior art's shape; it makes the pool a
  cost paid before any Agent arrives.
- **Round-robin instead of least-connections.** With sticky assignment it
  distributes arrivals rather than load, so a Gateway that loses and regains a
  connection stays lopsided.
- **Re-balancing Agents when a connection is added.** It trades stickiness for
  an even spread nobody asked for, and moving a stream between sockets
  mid-flight invites reordering.
- **Synthesising `agent_disconnect` for a vanished downstream Client.** The
  message would say the Agent said goodbye when it did not. Server-side
  staleness is the honest signal.
- **A WebSocket-only downstream endpoint.** The Baseline lets a Client choose
  either transport; a Gateway that silently excludes polling Clients fails as a
  Client that connects to nothing.
- **Hand-rolling the plain-HTTP endpoint on `hyper`.** One route sounds small
  until the Baseline's `413`, `415` and gzip rules are counted.
- **Gateway Mode behind a Cargo feature.** The released binary must have it on
  (goal 15, one binary for every shape), so it saves nothing where claimed, and
  a default-off feature is a branch that `cargo test` and `cargo clippy` never
  compile.
- **A crate of its own, `crates/gateway`.** It needs the configuration, TLS
  material, identity, transports and Agent state of the Client crate, so it
  would depend back on `client`. A crate is not a feature boundary either.
- **A Layer-4 passthrough gateway.** It carries client certificates end to end
  but cannot read OpAMP, so it cannot fold _n_ Agents onto _m_ connections.
- **Reusing the Server crate for the downstream endpoint.** The Client would
  depend on the Server, and the downstream side forwards rather than processes.

- **Reading the download `404` as outside the Gateway's refusal set.** A clause
  11 that called a revoked certificate the one refusal beyond the handshake
  would leave a reader who meets the download bound in the code taking one of
  the two for a mistake. Saying in clause 11 what the bound is, and that it is
  the Server's, keeps the Gateway's whole refusal set in one place.
- **A written statement that single-purpose hosts are assumed, instead of the
  endpoint token** — leaves shared hosts forgeable, where the specification asks
  for the secure default.
- **A Unix socket with file permissions for the Supervisor Endpoint** — the
  `opampextension` speaks WebSocket over TCP, and Windows has no equivalent with
  the same reach.
- **Mutual TLS on the loopback for the Supervisor Endpoint** — a CA and
  certificates per Supervisor for a socket that never leaves the host; the token
  gives the same proof for a fraction of the setup.
- **Checking the peer's process ID** — not portable, and a peer's PID says
  little once it can be reused.

## Sources / Prior art

- [OpAMP specification, `ServerToAgent.instance_uid`](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)
  — the protocol's own provision for multiplexing through a terminating proxy.
- [OpAMP Gateway Extension](https://bindplane.com/blog/opamp-for-opentelemetry-managing-collector-fleets-and-introducing-the-new-opamp-gateway-extension)
  — an OpAMP server downstream and a client upstream, a pool of ten by default
  with least-connections balancing, messages forwarded unchanged, authentication
  delegated to the Server. Alpha; a design reference, not a dependency.
- [`opampsupervisor` specification](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/specification/README.md),
  [`supervisor/supervisor.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/supervisor/supervisor.go)
  and
  [`supervisor/config/config.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/supervisor/config/config.go)
  — a local OpAMP server started unconditionally on `localhost:<port>`
  (`agent::opamp_server_port`, random free port when unset), with the
  extension's configuration injected from an embedded template.
- [`opampextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/opampextension)
  — a client only, with a deliberately small capability set; its configuration
  sends `server.ws.headers`.
- [`HARDENING.md`](../HARDENING.md), _The local endpoint_.

## Consequences

- Positive: one deployable to build, sign, install and update on every platform.
  A fleet scales connections independently of its Agent count, and the Server
  needs no change to sit behind a Gateway.
- Positive: the pool costs what it uses, so the default cap needs no tuning for
  small deployments and still bounds large ones. Every connection serves every
  Agent, so the cap is never reached with connections idle for want of the right
  peer.
- Positive: binding the Supervisor Endpoint to the Supervisor removes a class of
  invalid configurations instead of validating against it.
- Positive: a peer without a certificate from the Gateway's client CA is turned
  away in the handshake, before it reaches OpAMP or the upstream pool, and an
  insecure Gateway configuration cannot start.
- Positive: a revoked certificate is refused behind a Gateway within one
  refresh, and the session it holds there is ended, as it is on the Server.
- Positive: another local account can no longer report in a Managed Process's
  name.
- Negative / trade-offs: behind a Gateway the Server judges no proof of a
  downstream Agent; the Gateway's handshake and the list are the whole
  admission. A compromised Gateway speaks for any Agent, which the admission
  decision already accepts for a marked Gateway
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 7). A Gateway whose `client_ca_file` names anything but the fleet's
  client CA admits what the Server never issued, and the Server cannot see that
  file; the manual and review hold it. An unmarked Gateway is refused the list
  and so admits nobody, which keeps that reliance to the hosts an operator
  marked.
- Negative / trade-offs: every Supervisor binds a loopback port whether or not
  its Managed Process uses it.
- Negative / trade-offs: losing one pooled connection marks every Agent riding
  it disconnected until each reports again: one heartbeat interval with a
  heartbeat configured, otherwise until the Agent has something to say.
- Negative / trade-offs: a downstream Client that vanishes without a goodbye
  stays connected in the fleet view; only staleness tells, and only for an Agent
  that declared `ReportsHeartbeat`.
- Negative / trade-offs: a revocation reaches a Gateway up to
  `REVOCATION_REFRESH` late. A Gateway whose host the operator has not marked as
  a Gateway, or whose Server is away for more than `REVOCATION_MAX_AGE`, admits
  nobody.
- Negative / trade-offs: a Gateway forwards no `Authorization`, so behind a
  Server that still demands one its Agents are refused; the Server is upgraded
  before its Gateways.
- Negative / trade-offs: every Gateway needs a server certificate and a client
  CA, and every Client behind it a certificate chaining to that CA, even on a
  single host or in a test.
- Negative / trade-offs: the binary carries an HTTP routing layer it uses only
  in Gateway Mode, and Supervisor Mode plus Gateway Mode in one process is a
  real test surface.
- Negative / trade-offs: the Gateway now refuses a download request beyond
  admission. What a host may receive is the Server's bound applied to the offers
  the Server sent through the Gateway, and the `404` reads as the Server's for
  an artifact it does not hold. The binding of an `instance_uid` to the host of
  its first report, and the answers for an artifact too large, not fetched or
  still being fetched, are the Gateway's own decisions (ADR-0026 clauses 42, 45,
  47).
- Negative / trade-offs: every Collector configuration that reports through the
  Supervisor Endpoint must name the header; one that does not stops reporting
  its own state. A process running as root, or as the Client's own account, can
  still read the token from the child's environment.
- Follow-ups: re-balancing when the pool grows, if a real fleet is ever lopsided
  enough; consolidating TLS material on the Client if a fourth place appears.

## Enforcement

- [`crates/fleet-agent/tests/gateway_e2e.rs`](../../crates/fleet-agent/tests/gateway_e2e.rs):
  `two_agents_reach_the_server_over_one_folded_connection` (clauses 3, 13),
  `one_agent_opens_one_upstream_connection` (clause 8),
  `a_downstream_connection_carries_no_more_than_its_agent_cap` (clause 4),
  `a_downstream_peer_without_the_protobuf_content_type_is_refused`,
  `a_downstream_peer_may_gzip_its_report`,
  `a_gzip_bomb_is_refused_by_the_gateway` and
  `an_oversized_downstream_message_closes_with_1009` (clause 5).
- [`crates/fleet-agent/tests/gateway_tls.rs`](../../crates/fleet-agent/tests/gateway_tls.rs):
  `a_downstream_agent_with_a_certificate_reaches_the_server_over_tls`,
  `a_downstream_peer_without_a_certificate_is_refused` and
  `the_tls_endpoint_does_not_answer_plaintext` (clause 11).
- [`crates/fleet-agent/tests/gateway_and_supervisor_e2e.rs`](../../crates/fleet-agent/tests/gateway_and_supervisor_e2e.rs):
  `a_host_supervises_and_gateways_at_the_same_time`,
  `a_verified_offer_restarts_the_gateway_and_leaves_the_supervisors_running` and
  `a_gateway_that_cannot_bind_is_loud` (clauses 1, 4).
- [`crates/fleet-server/tests/ws_transport.rs`](../../crates/fleet-server/tests/ws_transport.rs)
  `two_agents_share_one_connection` and
  [`crates/fleet-agent/tests/e2e.rs`](../../crates/fleet-agent/tests/e2e.rs)
  `a_config_change_reaches_both_supervised_agents_over_one_connection` (clause
  3).
- `crates/fleet-agent/src/supervisor/endpoint.rs`:
  `extension_reports_are_folded_into_process_events` and
  `shutdown_stops_the_endpoint` (clause 2); `crates/fleet-agent/src/config.rs`:
  `the_gateway_agent_cap_defaults_and_rejects_zero` (clause 4).
- Each marked `Verifies: ADR-0015`: `crates/fleet-agent/src/config.rs`
  `a_gateway_without_mutual_tls_is_refused_at_load` — no `[gateway.tls]`, and a
  section without `client_ca_file` (clause 4);
  [`crates/fleet-agent/tests/gateway_tls.rs`](../../crates/fleet-agent/tests/gateway_tls.rs)
  `a_gateway_without_tls_on_loopback_does_not_start`,
  `a_gateway_without_a_client_ca_does_not_start` and
  `a_downstream_peer_with_a_certificate_from_another_ca_is_refused` (clauses 4,
  11);
  [`crates/opamp/tests/server_listen.rs`](../../crates/opamp/tests/server_listen.rs)
  `a_client_offering_only_tls_1_2_is_refused`, against the listener and
  `ServerTls` the downstream endpoint is served with (clause 11).
- Clause 14:
  [`crates/fleet-agent/tests/gateway_revocation_e2e.rs`](../../crates/fleet-agent/tests/gateway_revocation_e2e.rs)
  `a_certificate_the_server_revokes_is_refused_behind_the_gateway`,
  `an_unmarked_gateway_admits_nobody` and
  `a_gateway_whose_list_goes_stale_admits_nobody`, run against a Server that
  reads no `Authorization`; `crates/fleet-agent/src/gateway/revocations.rs`
  `the_verdict_follows_the_list_and_its_age`.
- Through the real Gateway and Server, each marked `Verifies: ADR-0015`:
  [`crates/fleet-agent/tests/gateway_tls.rs`](../../crates/fleet-agent/tests/gateway_tls.rs)
  `downstream_peers_with_different_certificates_share_one_upstream_connection` —
  two peers, an `upstream_connections` of `1`, both Agents reach the Server
  (clauses 7, 11);
  `a_downstream_authorization_header_is_ignored_and_not_forwarded` — a peer that
  sends one is admitted and the Server receives none (clause 11);
  `crates/fleet-agent/src/gateway/revocations.rs`
  `the_revocation_list_is_fetched_without_authorization`, even with an `[auth]`
  section left in `supervisor.toml` (clause 14).

- The download bound of clause 11, marked `Verifies: ADR-0015` beside ADR-0026:
  [`crates/fleet-agent/tests/gateway_package_cache.rs`](../../crates/fleet-agent/tests/gateway_package_cache.rs)
  `another_host_and_a_certificate_naming_no_host_are_answered_as_for_an_artifact_not_held`
  and `a_revoked_certificate_is_refused_on_the_download_route`.

- The Supervisor Endpoint token:
  [`crates/fleet-agent/src/supervisor/endpoint.rs`](../../crates/fleet-agent/src/supervisor/endpoint.rs)
  `the_endpoint_admits_only_the_token_it_handed_out` (clauses 15, 17);
  [`crates/fleet-agent/tests/supervisor_process.rs`](../../crates/fleet-agent/tests/supervisor_process.rs)
  `the_managed_process_is_handed_the_endpoint_token` (clause 16).

**Not mechanically decidable:** that no message is synthesised on an Agent's
behalf (clauses 9, 10) is an absence; review holds it.
