# ADR-0016: An Agent reports its type, its operator's name and its host as the conventions define them, and its own telemetry over OTLP/HTTP to the destinations the Server names, in TLS 1.3 and in plaintext only to the loopback

- **Status:** 🟢 accepted · clauses 8 and 9 superseded by
  [ADR-0041](0041-a-managed-process-states-only-its-own-service-attributes.md)
- **Date:** 2026-10-03
- **Deciders:** Markus Brigl
- **Applies to:** AgentDescription building in
  crates/fleet-agent/src/supervisor/agent.rs, the Agent type resolution in
  crates/fleet-agent/src/supervisor/mod.rs, [attributes] and service_namespace
  in supervisor.toml, the fleet view's name and network columns;
  crates/fleet-agent/src/telemetry.rs, the telemetry half of
  crates/fleet-agent/src/connection.rs, the operation spans in the Client's
  transport, engine, reconfigure, packages, update
  (crates/fleet-agent/src/update/) and Supervisor modules, the Server's
  `[telemetry_offer]` (crates/fleet-server/src/config.rs,
  crates/fleet-server/src/fleet.rs), and the OpenTelemetry crates in Cargo.toml

## Context

Everything a Selector matches, every artifact a Package fit chooses, and every
row of the fleet view comes from the `AgentDescription` an Agent reports. What
goes into it is therefore a contract.

**The Baseline reserves `service.name` for the Agent _type_.** It "should be set
to a reverse FQDN that uniquely identifies the Agent type, e.g.
`io.opentelemetry.collector`", and names `service.instance.id` separately as
what identifies the Agent. A `[[supervisor]]` block's `name` is the operator's
name for one instance — a directory, a uniqueness key — and putting it into
`service.name` would give one key two meanings. The collision is not
theoretical: a Collector carrying the `opampextension` reports its own
description, folded over the Supervisor's, and its `service.name` is the
`dist.name` it was built with (`otelcol-contrib`), identical on every host. An
operator's name kept in that key is erased the moment the extension connects,
and three Collectors become three rows of the same name.

The type is the more useful of the two for targeting — "reach the Collectors and
nothing else" — and where no extension reports it (the core `otelcol`
distribution, every Foreign Agent) something else has to. The Baseline has no
attribute for a human-readable instance name; it admits "any user-defined
attributes the end user would like to associate with this Agent" among the
non-identifying ones. Bindplane, the closest shipping server, derives its Agent
Type from `dist.name` and keeps the human name in a separate field.

**Where the Agent runs** is described with the semantic conventions' `os.*` and
`host.*` keys. An operator also wants to see which addresses a host holds. The
connection's peer address is the wrong fact: behind NAT it is the translator's,
behind a Gateway the Gateway's, and a hop must not become the source of an
attribute about someone else's host. The conventions define `host.ip` and
`host.mac` as string arrays, "excluding loopback interfaces", IPv6 in RFC 5952
form and MACs "in IEEE RA hexadecimal form: as hyphen-separated octets in
uppercase".

Beside its description, an Agent reports its own telemetry. The
[specification](../SPECIFICATION.md) puts security before convenience (Strategy
_Security before convenience_, Q-1 _Secure by default_): own telemetry travels
in plaintext only to a loopback IP literal, and every other export is TLS 1.3.

Three capability bits of the Baseline are one feature: `ReportsOwnTraces`
(`0x0020`), `ReportsOwnMetrics` (`0x0040`) and `ReportsOwnLogs` (`0x0080`), all
`[Beta]`. Each means "the Agent can report own \<signal\> to the destination
specified by the Server via `ConnectionSettingsOffers.own_*`". The destination
is a `TelemetryConnectionSettings` whose `destination_endpoint` "MUST be a full
URL an OTLP/HTTP/Protobuf receiver with path", and the Agent "MAY refuse to send
the telemetry if the URL begins with `http://`"
([`opamp.proto`](../../crates/opamp/proto/v0.20.0/opamp/v1/opamp.proto)). The
Baseline asks that the `AgentDescription`'s identifying attributes appear in the
OTLP Resource, and names process metrics — "CPU or RAM usage" — as what own
metrics are for.

**"Own" cannot mean a Managed Process's internals.** Upstream's
`opampsupervisor` answers the offer by configuring the Collector's _internal_
telemetry. That road is closed here: a Supervisor passes a Configuration through
without touching it
([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)),
and the specification's non-goals forbid an abstraction over a Managed Process's
configuration language. What this Client can honestly report is what it observes
from outside: its own process, and the processes it spawned and holds the pids
of.

**All three signals have a subject.** Metrics are process metrics. Logs are what
the Client already writes through `tracing`. Traces are the control loop's
existing lifecycles — a configuration apply, a package install, a self-update —
which already have phases and an outcome the Server is told; they are spans to
map, not an instrumentation project. Making them needs a producer: the log
bridge converts `tracing` _events_ and says so itself (_"This crate does not
convert `tracing` spans into OpenTelemetry spans. Use `tracing-opentelemetry`
for that."_). `tracing-opentelemetry` `0.34` is built against the
`opentelemetry` `0.33` this workspace runs, and with it entering a `tracing`
span activates its OpenTelemetry context, so the log appender picks up the trace
context with no feature flag.

**OTLP has a reference implementation, and it is the standard's own.** This
project vendors the OpAMP schema because it owns that wire contract
([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md)).
OTLP is not its protocol: its wire format, semantic conventions and versioning
are maintained upstream, and `opentelemetry-otlp` is where that maintenance
lands.

**Cleartext stops at the loopback.** The Resource carries identifying attributes
and the log records carry whatever the Client logs, as a continuous stream. The
specification makes every connection that leaves the host TLS 1.3, accepts
plaintext on the loopback alone, and refuses a configuration that breaks this
rather than warning about it. A destination the Server offers is configuration
this Client puts in force, so the rule reaches it. The private address space —
[RFC 1918](https://www.rfc-editor.org/rfc/rfc1918)'s three IPv4 ranges and
[RFC 4193](https://www.rfc-editor.org/rfc/rfc4193)'s `fc00::/7` — is not
routable across the public internet, but a stream sent into it crosses every
switch, VLAN and tenant between the host and the Collector. A name is not an
address: `localhost` resolves wherever the host's resolver says.
[ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
draws the same line for the OpAMP connection, at the literals `127.0.0.1` and
`::1`, and builds every rustls configuration for TLS 1.3 alone.

**The Baseline cannot switch own telemetry off.** For each `own_*` field the
schema says _"If this field is not set then the Agent should assume that the
settings are unchanged"_, and the empty string is not a legal
`destination_endpoint`. Read literally, a destination once in force can be moved
but never ended, short of deleting state on each host. The one widely deployed
Client that implements these fields, `opampsupervisor`, reads them otherwise: it
builds its own-telemetry section from each received message alone, drops a
signal whose endpoint is absent or empty, and logs _"Disabling own telemetry
pipeline in the config"_ when nothing is left — but only enters that path when
the message names at least one of the three. `opamp-go` is this project's
behavioural oracle
([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md));
here the literal reading would leave both ends unable to drive each other.

How an offer is applied, acknowledged and persisted — the telemetry destinations
as a class of offer of their own, without a verifying connection or a reconnect
— is
[ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)'s.
This ADR decides what own telemetry is, what an offer of it means, and what the
Client admits.

## Decision

We will report `service.name` as the Agent type and a separate
`service.instance.name` as the operator's name for the instance, describe the
host with the conventions' `os.*` and `host.*` attributes in their declared
shapes, and let a Managed Process improve everything except who the Agent is.

We will also implement all three own-telemetry capabilities through the
OpenTelemetry Rust SDK, exporting OTLP/HTTP with protobuf bodies only to
destinations the Server offers, read an offer that names any of them as the
complete state of all three, admit cleartext only to a loopback IP literal and
speak TLS 1.3 to every other destination, and invent nothing OTLP already
defines.

1. **`service.name` is the Agent type**, identifying, resolved in this order,
   first hit wins:

   | Source                           | When                                                                                                                                                                                                                                            |
   | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | What the Managed Process reports | the fold of clause 8 — `dist.name` for a Collector with the extension                                                                                                                                                                           |
   | The kind's own type              | a wrapped kind states it (`icinga2`, `telegraf`, `glpi-agent`); a block of such a kind carrying `service_name` fails at startup naming the derived value ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)) |
   | The block key `service_name`     | `collector` and `command`; must not be empty, and is not bound by the instance-name grammar, so a reverse FQDN is accepted                                                                                                                      |
   | The program's file name          | the fallback: `otelcol`, `promtail`                                                                                                                                                                                                             |

   The fallback is read from the configuration, never parsed out of a program's
   output. The Baseline's reverse-FQDN shape is a recommendation and is not
   enforced. The Client's own Agent reports the constant `supervisor`
   ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)),
   never its configured name. A Selector or a Configuration's type
   ([ADR-0023](0023-configurations-and-the-rest-api.md) clause 4) on
   `service.name` aims at a type.

2. **`service.instance.name` is the operator's name for the Agent**,
   non-identifying: the `[[supervisor]]` block's `name`, or the top-level `name`
   for the Client's own Agent. It is always reported. The key is this project's
   — the conventions have none for a human instance name — chosen to read as the
   partner of `service.instance.id`.

3. **The block `name` keeps its local meaning.** It is the Supervisor's
   directory name and the uniqueness key across blocks, bound by the
   instance-name grammar of
   [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
   clause 2: lowercase, digits, `-`, no dots. A type may be a reverse FQDN; an
   instance name is a path component on three operating systems. That is why the
   two cannot share a key.

4. **The identifying attributes** are `service.name`; `service.namespace`, only
   when the top-level `service_namespace` key in `supervisor.toml` is set, since
   only an operator knows the deployment; `service.version` — for the Client's
   own Agent its baked version
   ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)), for a
   Supervisor-backed Agent only what the Managed Process reports, never invented
   from the Client's; and `service.instance.id`, the Instance UID.

5. **Where the Agent runs is reported best effort, and absent rather than
   blank.** Beside `service.instance.name`, the non-identifying attributes are
   `os.type` and `host.arch` in the conventions' vocabulary
   ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)),
   `os.name`, `os.version`, `os.build_id`, `os.description`, `host.name`,
   `host.id`, `host.cpu.model.name`, `host.ip`, and `host.mac`. What the
   platform cannot answer is left out: a placeholder would be something false a
   Selector could match. Nothing is taken from the connection.

6. **`host.ip` and `host.mac` follow the conventions.**
   - Enumerated with `sysinfo`'s `network` feature, the crate the Client already
     carries for its own telemetry — no new dependency.
   - An interface whose every address is loopback is excluded whole, its MAC
     too; an all-zero MAC is no answer.
   - IPv4 dotted-quad, IPv6 RFC 5952 (what `IpAddr`'s `Display` writes), MACs
     hyphen-separated uppercase. Both lists are deduplicated and sorted, so
     enumeration order never re-reports an unchanged host.
   - Read live on every description, so a DHCP move is reported. An empty list
     omits the key.
   - On the wire an `ArrayValue` of strings. The Server's view joins a string
     array with `, `; Selectors match string values only, so an array is
     displayed and searched, never matched.

7. **`host.cpu.model.name` and `os.build_id` come from sources already paid
   for.** The CPU model from the same `sysinfo`, read once per process. The
   build behind `os.version` from what the platform's `os.*` answer already
   carries: os-release's `BUILD_ID` (absent where a distribution stamps none),
   `sw_vers`' BuildVersion, and on Windows the build components of the version
   line (`10.0.26100.2033` → `26100.2033`).

8. **A Managed Process's own description is folded in, except who the Agent
   is.** What the process reports — through the Supervisor Endpoint, or the
   version probe — is merged per attribute, a later report winning on the same
   key, and laid over the Supervisor's. Its `service.name` wins: `dist.name` is
   a better type than anything a file can infer. `service.instance.id` and
   `service.instance.name` are the Supervisor's and are exempt, **by key and in
   both lists**: a process cannot know the Supervisor's identity or what the
   operator called it, and a key reported in the other list would otherwise win
   every Selector while the fleet row showed the Supervisor's value.

9. **Operator attributes describe the host.** The Client-wide `[attributes]`
   table (string to string; any other value type is refused) is reported as
   non-identifying attributes of every Agent this Client presents, each only
   where nothing is reported under the same key — what the code or the Managed
   Process reports always wins, so an attribute can never restate the type or
   the instance name. Tagging one Agent among several is a Server label's job
   ([ADR-0024](0024-the-fleet-record.md) clause 16): a `[[supervisor]]` block
   carrying an `attributes` table fails at startup with a message naming the
   Server label. The Client's own Agent also reports the kinds it was compiled
   with
   ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).

10. **The fleet view shows the instance name first and the type beneath it.**
    `AgentView` carries `service_name` (the type) and `service_instance_name`;
    the bundled UI's name column falls back from instance name to type to
    Instance UID, so a row is never blank and never collapses onto its
    neighbours. A Network column shows the first address of each kind with the
    rest in the tooltip; every attribute is shown as a chip and searchable.

11. **The standard's own implementation, not a copy of its schema.**
    `opentelemetry`, `opentelemetry_sdk` and `opentelemetry-otlp` carry the wire
    format, with the exporter's features stated rather than inherited:

```toml
opentelemetry-otlp = { version = "0.33", default-features = false,
                       features = ["http-proto", "reqwest-client", "trace", "metrics", "logs"] }
```

`reqwest-client` replaces the default blocking client; `grpc-tonic` stays off
because the schema permits no gRPC destination. `tracing-opentelemetry` joins
them at the version built against them — `0.34` against `opentelemetry` `0.33` —
and that pairing is a decision, not a range to widen. No OTLP schema is vendored
([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md)
covers OpAMP only).

12. **Names come from the standard where it has them.** Metric and attribute
    names are taken from `opentelemetry-semantic-conventions` (with
    `semconv_experimental`, since the process metrics are experimental
    upstream), never written as string literals, so a moved convention is a
    compile error on the next bump. The operation span names of clause 18 are
    this project's vocabulary because OpenTelemetry defines none for an agent's
    own lifecycle; they are not to be "corrected" towards a convention that does
    not cover them.

13. **"Own" is what the Client observes from outside.** The Client's own Agent
    reports the Client's process; each Supervisor-backed Agent reports its
    Managed Process, by the pid the Supervisor already holds. No Managed
    Process's configuration is touched to obtain telemetry. CPU and memory for a
    pid come from `sysinfo` (pure Rust, Linux, macOS and Windows), the one gap
    the SDK leaves.

14. **Metrics are process metrics per Agent, every 10 s.**
    `process.memory.usage`, `process.cpu.utilization` and `process.uptime`,
    recorded as gauges, each sample carrying the sampled Agent's
    `service.instance.id`, `service.instance.name` and `service.name` — the
    Resource is the Client's, so a Managed Process's series would otherwise
    carry the Client's identity. Sampling and export share one interval, 10 s,
    the Baseline's recommended reporting interval; the periodic reader is told
    it explicitly, since its default is 60 s. A pid that has gone away records
    nothing.

15. **Logs are the Client's `tracing` output, bridged.**
    `opentelemetry-appender-tracing`'s `OpenTelemetryTracingBridge` turns events
    into OTLP log records at the level the log filter already selects. Stderr
    and the service-mode log file
    ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md))
    keep everything they print; this adds a destination. A record written inside
    an instrumented operation carries that operation's `TraceId` and `SpanId`,
    which is what makes a log-to-trace join answerable at the receiving end.

16. **Traces come from the `tracing` spans this Client writes.**
    `tracing-opentelemetry`'s layer converts them; instrumentation is written in
    `tracing` (`#[instrument]`, `tracing::info_span!`) and no OpenTelemetry type
    appears outside `telemetry.rs`. An outcome becomes the span status through
    the crate's reserved fields `otel.status_code` and
    `otel.status_description`, written through `telemetry::failed` and
    `telemetry::succeeded`; the failure text is the same string the Server is
    told.

17. **Both bridges live in reload slots.** `tracing` has one subscriber per
    process, installed before any destination is known, so the log bridge and
    the span layer each sit in a `tracing_subscriber::reload` slot held open
    from startup, filled when an offer puts a provider in force and emptied when
    it is withdrawn. A slot is emptied before its provider shuts down, so an
    event or span during shutdown never reaches a closing exporter. With no
    destination, an instrumented span costs what a `tracing` span costs with no
    layer interested in it.

18. **Five operations are root spans, and their phases are child spans.**

| Root span                        | Phases                                                                 | Opened in                                                |
| -------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------- |
| `package.install`                | `download`, `verify`, `stage`, `preflight`, `swap`, `gate`, `rollback` | `transport::process_package_downloads`                   |
| `config.apply` (Supervisor set)  | `validate`, `stop`, `write`, `purge`, `start`                          | `reconfigure::apply`                                     |
| `config.apply` (Managed Process) | `reload` or `restart`, `gate`                                          | `engine::handle`, where the Configuration is handed over |
| `connection.settings.apply`      | `verify`, `store`                                                      | `transport::process_connection_offer`                    |
| `self.update`                    | `stage`, `probe`, then `commit` or `roll_back`                         | `update::installer::install`                             |

An install and a Managed Process's apply are begun by the task that received the
message and finished by the Supervisor's own task, so the span travels with the
command through the Port (`ProcessCommand::ApplyConfig` and `ApplyPackage` each
carry one); a trace that ended at the hand-over would stop where the interesting
failures are. A self-update is always reached from a package offer, so
`self.update` is in practice a child of the `package.install` that downloaded
it. The reconnection after `connection.settings.apply` is a field on the root
span, not a phase: it happens after the operation returns, in the transport
loop.

19. **Message handling is not a span.** A transport exchange (a poll, a
    WebSocket receive), a sampler tick and the Supervisor Endpoint's message
    handling have no outcome and no end; at one exchange per Agent per interval
    they would bury the five operations. A span that belongs to an operation is
    therefore opened inside the per-exchange function, where the operation
    begins, never on the function itself. A failed exchange stays a logged
    warning, carrying the trace context of whatever operation is in flight.

20. **A self-update stays one trace across its restart.** The trace id and the
    span id of the `self.update` span go into the update marker
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)) as
    hex, and the process that comes up after the restart opens `commit` or
    `roll_back` as a child of that span, its parent marked remote. A marker
    without ids, or with ids that do not parse, makes the post-restart span open
    its own trace; a trace is never a reason to fail an update. `self.update`
    itself records no status — the process that stages a version does not learn
    whether it stays up.

21. **No sampler.** Every span is exported: the volume is a handful of fleet
    operations per host per day, and a sampler would first drop the rare failed
    rollout a trace exists for.

22. **Every signal is attributed to its Agent.** The OTLP Resource carries the
    `AgentDescription`'s identifying attributes, plus four descriptive ones
    named one by one — `service.instance.name`, `os.type`, `host.arch`,
    `os.description` — each only where the description carries it. No other
    non-identifying attribute (`host.ip`, `host.mac`, operator `[attributes]`)
    is put on the Resource: widening that list is a decision about what leaves
    the host.

23. **A span attribute is data leaving the host, and is chosen one by one.** A
    Supervisor name, a package name and version, a configuration hash, a count —
    never a whole Configuration, an offer's headers, or a URL that can carry a
    credential. A download source is labelled by scheme, host and path only, its
    query dropped, because a pre-signed URL puts its signature there; the
    `Debug` impls that hide package header values must not be defeated by a span
    field.

24. **The exporters send through a client bound to this process's runtime, in
    TLS 1.3, with a bounded export.** The SDK exports from dedicated threads
    that block on the request and have no Tokio reactor, so each request is
    spawned onto the runtime handle captured when the exporter was built. The
    HTTP client is built from this Client's TLS material — its trust anchors,
    and the certificate of clause 32 when one is offered; without one it
    presents none, never the fleet identity the Server sees. It follows no
    redirect, so a destination cannot move an export to another host or to
    plaintext. It speaks TLS 1.3 alone, with TLS 1.3 as its minimum and the
    three TLS 1.3 suites of the ring provider, as every rustls configuration of
    this project does
    ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
    clause 4). A destination that speaks only TLS 1.2 or older fails the
    handshake, and that export fails. The client carries a 5 s timeout — half
    the reporting interval — because neither the periodic reader nor a client
    handed to `opentelemetry-otlp` bounds an export, and a destination that
    stops answering would otherwise hold the exporter until the Client restarts.

25. **Destinations come only from the Server.** There is no destination in
    `supervisor.toml`: the capability is reporting "to the destination specified
    by the Server". With no destination offered, nothing is built and nothing is
    sent. The offer's lifecycle — applied in place, acknowledged on the same
    offer, persisted and put back in force at startup — is
    [ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)'s.

26. **The three capabilities are declared unconditionally.** They state an
    ability — "I can report to a destination you name" — and the offer arms it.
    Declaring them only once a destination is in force would mean the Server
    could never make the first offer.

27. **An offer that names any telemetry destination states all three; one that
    names none changes nothing.** When any of `own_metrics`, `own_traces`,
    `own_logs` is present, the offer is the whole truth about own telemetry: a
    signal it does not name is stopped and leaves the persisted state, not
    carried over. An offer naming none of the three — OpAMP settings only, a
    certificate, a heartbeat change — leaves all three as they are; that keeps
    the classes of offer of
    [ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
    independent.

28. **An empty `destination_endpoint` withdraws that signal.** It is admitted,
    not refused: the exporter is shut down, the destination leaves the persisted
    state, nothing is reported against it, and the offer is acknowledged
    `APPLIED`. It is the only way to stop all three, since by clause 27 an offer
    naming nothing cannot say it. The Server sends it as clause 33 describes.

29. **Cleartext is admitted to the loopback and nowhere else; every other
    destination is TLS 1.3.** An `http://` destination is admitted only when its
    host is one of the loopback IP literals `127.0.0.1` and `::1`. The rest of
    `127.0.0.0/8`, RFC 1918's `10.0.0.0/8`, `172.16.0.0/12` and
    `192.168.0.0/16`, RFC 4193's `fc00::/7`, link-local and carrier-grade NAT
    are not admitted, and are named here so that "loopback" does not quietly
    widen. An `https://` destination is admitted and spoken to in TLS 1.3 alone
    (clause 24); an endpoint that is neither is refused as not an OTLP/HTTP URL.

30. **The judgement is made on a parsed address, never on a name.** The host is
    extracted from the URL — an IPv6 literal from its brackets — parsed as an IP
    address and compared with the two loopback literals; a prefix match is never
    used (`127.0.0.1.example.com` is refused). No name is admitted, `localhost`
    included, and no name is resolved: a name can be made to resolve anywhere,
    and an admission test that a re-resolve can flip, on a destination that is
    persisted and re-applied, is not one an operator can reason about. A
    Collector reached by name is put behind TLS.

31. **A refused destination is reported, never warned about or downgraded.** Its
    exporter is not built, and the refusal reaches the Server in the offer's
    `connection_settings_status`
    ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
    clause 7) with the reason; the cleartext message names the setting and the
    two loopback literals that would be accepted. A refusal, not a warning, is
    the specification's answer to every plaintext connection off the loopback
    (Q-1), and this one is a continuous stream of identifying attributes and log
    records.

32. **`certificate`, `tls` and `proxy` behave as they do on the OpAMP
    settings.** An offered `certificate` is honoured: its `cert` is presented by
    the exporter, paired with the key this Client generated for its CSR — the
    client-certificate machinery of
    [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md),
    reused as-is. A `private_key` in the offer is refused by name, because this
    Client's private key never leaves its host and is never accepted from the
    Server; a `cert` with no key on disk to pair with is refused by name too.
    `ca_cert` is not added to the trust store, as the Baseline advises. `tls`
    and `proxy` are refused and reported by name.

33. **The Server offers destinations from a `[telemetry_offer]` section.**
    `metrics_endpoint`, `traces_endpoint`, `logs_endpoint`, and one
    `[telemetry_offer.headers]` table sent with every signal (typically the
    backend's access token). Endpoints are full OTLP/HTTP URLs with path; the
    Server appends no `/v1/…`. At startup a section naming no endpoint, or an
    endpoint that is not an `http://` or `https://` URL, fails loudly; the
    Server judges nothing about cleartext — that is the Agent's rule, decided
    where the packets originate. What the section says, it says about all three
    signals (clause 27). An endpoint set to `""` is a withdrawal to be sent,
    carries no headers, and counts as something to offer. Removing the section
    withdraws nothing — a Server cannot tell "never offered" from "withdrawn",
    and must not tear down a fleet another Server pointed at a Collector. Each
    Agent is offered a destination only for the signals it declares. How the
    destinations ride in the one hashed `ConnectionSettingsOffers` and when the
    Server declares `OffersConnectionSettings` is
    [ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)'s.

34. **The departure from the Baseline is recorded, not argued upstream.**
    Clauses 27, 28 and 33 depart from the schema's "not set means unchanged" and
    from the `destination_endpoint` MUST. [`CONFORMANCE.md`](../CONFORMANCE.md)
    carries this as a row under _Deviations_, naming the sentences departed
    from, the implementation followed and the reason. Settling the disagreement
    between the schema and `opampsupervisor` is upstream's; this project takes
    no position in `opamp-spec`.

**Out of scope:** the cloud-shaped conventions (`host.image.*`, `host.type`),
which come from provider metadata services; reporting kinds through
`AvailableComponents`; bootstrapping a type by starting a Collector once with a
generated extension-only configuration; a Collector's _internal_ telemetry (an
operator configures the Collector for it); the Server storing or forwarding
telemetry — the specification keeps this project out of the telemetry-backend
business; `AcceptsOtherConnectionSettings`; trace context across a Gateway hop
([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md));
a sampling hint from the Server; a local switch on the Agent that drops the
three capability bits.

## Alternatives considered

- **Keep `service.name` as the instance name and add `service.type`.** A
  Collector's extension reports `service.name` and knows nothing of
  `service.type`, so it would keep overwriting the instance name with its type —
  the collapse this decision prevents.
- **No human instance name at all.** The most conformant reading, but a UID is
  not a name a person can use, and several Supervisors share one `host.name`.
- **`host.name` as the instance name.** A property of the machine, while
  Supervisor Mode runs _n_ Agents on one machine
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
- **The instance name outside `AgentDescription`**, as Bindplane does. Needs a
  channel this project does not have, and makes the name invisible to Selectors,
  which pin one Agent by it.
- **Derive the type from `<program> --version` output.** A name has no grammar
  the way a SemVer does (`Fluent Bit v3.1.0`,
  `promtail, version 3.0.0 (branch: main)`); the configuration fallback gets the
  same value without guessing.
- **Bootstrap the type by starting the Collector with an extension-only
  configuration**, as the upstream Supervisor does. Adds a process start and
  works only for distributions that already report their type through the fold.
- **A dedicated interface-enumeration crate** (`if-addrs`, `mac_address`). A new
  dependency for what an existing one's feature flag provides.
- **Joined strings on the wire.** Bakes a display choice into the protocol and
  departs from the conventions' declared type; the view is the place to join.
- **The Server records the connection's peer address.** Reports the NAT or the
  Gateway, not the host.

- **Vendor `opentelemetry-proto` and encode OTLP by hand.** The cheaper build —
  prost, protox and the `reqwest` already present, no new crate. Rejected: a
  second copied schema is a second protocol to keep in sync with none of the
  Baseline machinery that makes the OpAMP copy safe, and its semantic
  conventions would become string literals nobody re-checks. Owning the bytes is
  right where the bytes are the product; here they are the exhaust.
- **Keep the SDK's default features.** The defaults select
  `reqwest-blocking-client`, and blocking HTTP inside a tokio runtime starves an
  executor.
- **Send OTLP over gRPC.** The schema requires an OTLP/HTTP/Protobuf receiver.
- **Configure the Collector's internal telemetry from the Supervisor**, as
  `opampsupervisor` does. The richer answer for a Collector, and what an
  operator from upstream expects. Rejected: this Client does not touch a Managed
  Process's configuration, and inventing an abstraction over it is a non-goal.
- **Use the OpenTelemetry trace API directly.** No added dependency, and what
  the reference implementation does in Go. Rejected: it puts OTel types and an
  explicit `Context` into domain modules built as logic with `tracing` on top,
  and log correlation would be attached by hand at every site instead of once by
  a layer.
- **Metrics and logs only; stop declaring `ReportsOwnTraces`.** Rejected: the
  operations that fail in a fleet are already multi-phase lifecycles with
  outcomes, and the trace is the one signal that answers _why_ a rollout failed
  rather than _that_ it did.
- **Span every message**, as `opampsupervisor` does. That supervisor manages one
  Collector, where message handling is the work; a Client here multiplexes n
  Agents over one connection on every host of a fleet. The oracle governs
  protocol behaviour, and what a Client measures about itself never reaches the
  wire.
- **One span per operation, no child spans.** _"Which phase failed"_ is the
  question an operator asks of a rollout; a single span answers only _"it
  failed"_, which the reported status already says.
- **Link the post-restart span instead of continuing the trace.** Span links are
  the standard's way across a boundary, but _"did this update land"_ is one
  question and should be one trace. The marker carries the ids either way, so
  this stays reversible.
- **A destination, or a list of trusted networks, in `supervisor.toml`.** A
  locally configured destination is a private extension wearing the capability's
  name, and a per-host allowlist would give a fleet two places to look when
  telemetry does not arrive — one on the host nobody is logged into.
- **Declare the capabilities only while a destination is in force**, as
  `OffersPackages` is. Those describe something the end has; these describe
  something it can do, and the conditional version deadlocks the first offer.
- **Cleartext inside the private address space** — RFC 1918's three ranges and
  `fc00::/7` besides the loopback. Spares the small fleet with one Collector on
  its LAN a certificate, a name and a renewal. Rejected: an unroutable address
  is not a trusted network, the same address is a different machine on another
  site, and the specification accepts plaintext on the loopback alone (Q-1).
- **Admit `localhost` by name.** It is loopback by convention
  ([RFC 6761](https://www.rfc-editor.org/rfc/rfc6761)), but what it resolves to
  is the host resolver's answer, not the URL's, and the OpAMP connection refuses
  it for the same reason
  ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
  clause 8).
- **Resolve names and admit those that resolve to the loopback.** The answer
  would depend on what DNS said when the offer arrived, and the name can be
  re-pointed afterwards without any offer changing.
- **Admit TLS 1.2 to a Collector that offers nothing newer.** Reaches older
  receivers. Rejected: every connection that leaves the host is TLS 1.3, and
  `rustls` is built without TLS 1.2 for the whole project, so a per-destination
  exception would need a second TLS stack.
- **Warn instead of refusing**, as for credentials in cleartext. Proportionate
  to a credential on one request, not to a continuous stream of identifying
  attributes and logs.
- **The literal reading of the offer, with the gap documented.** Leaves no
  fleet-driven off switch, and misconfigures silently in both directions against
  the one peer that implements these fields.
- **Complete state per offer without the empty-endpoint withdrawal.** Cannot
  express "all off": an offer naming nothing means "unchanged", so the last
  remaining signal could never be stopped.
- **Withdraw automatically when `[telemetry_offer]` disappears.** The Server
  holds no record of what it offered, so every Server without the section would
  tombstone Agents another Server configured.
- **A signal of our own** — a `disabled` flag or a custom capability like
  Bindplane's. Inventing protocol semantics is a non-goal, and a bespoke signal
  would be understood by one Server and one Client. Departing towards the
  implementation everyone runs is the only departure that buys interoperability.
- **Raise it against `opamp-spec` and wait.** The protocol is Beta on a slow
  cadence, and this project implements the protocol and records its departures;
  it does not staff the protocol's evolution.

## Sources / Prior art

- [`opamp.proto`](../../crates/opamp/proto/v0.20.0/opamp/v1/opamp.proto),
  `AgentDescription` — `service.name` as the type, `service.instance.id` as the
  identity, and the non-identifying clause admitting user-defined attributes.
- [Bindplane — Bring Your Own Collector](https://docs.bindplane.com/feature-guides/deployment-and-management/bring-your-own-collector)
  — Agent Type from `dist.name`, the human name kept apart.
- [`opampextension` `opamp_agent.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/opampextension/opamp_agent.go)
  — the three identifying attributes a Collector reports, which the fold
  coexists with.
- [OpAMP Supervisor `config.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/supervisor/config/config.go)
  — operator-stated identifying attributes, the need the `service_name` key
  answers.
- [PR #38809 — Control Collectors with only the OpAMP extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/38809)
  — the bootstrap mechanism weighed and declined.
- [Semantic conventions — `service`](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/service.md)
  — no attribute for a human instance name.
- [Semantic conventions — `host`](https://opentelemetry.io/docs/specs/semconv/registry/attributes/host/)
  and
  [`os`](https://opentelemetry.io/docs/specs/semconv/registry/attributes/os/) —
  `host.ip`, `host.mac`, `host.cpu.model.name`, `os.build_id`, their formats and
  loopback exclusion.
- `sysinfo` 0.37 `Networks` API (`mac_address()`, `ip_networks()`), behind its
  `network` feature.
- [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)
  — _Own Telemetry Reporting_, and the vendored
  [`opamp.proto`](../../crates/opamp/proto/v0.20.0/opamp/v1/opamp.proto): the
  three capability bits, `ConnectionSettingsOffers.own_*` ("If this field is not
  set then the Agent should assume that the settings are unchanged") and `hash`,
  `TelemetryConnectionSettings` (the OTLP/HTTP/Protobuf MUST, the "MAY refuse
  `http://`", `certificate`'s withdrawal by omission and the advice on
  `ca_cert`), the identifying attributes in the Resource, and the 10 s
  recommended reporting interval.
- [`opampsupervisor`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/cmd/opampsupervisor)
  — `cmd/opampsupervisor/supervisor/supervisor.go`: `updateOwnTelemetryData`,
  `setupOwnTelemetry`, `processOwnTelemetryConnSettingsMessage`,
  `loadLastReceivedOwnTelemetryConfig` and the dispatch in `onMessage`; and the
  spans it emits,
  [contrib#38724](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/38724)
  and
  [contrib#38797](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/38797).
- `opamp-go`, `client/internal/receivedprocessor.go` — passes `OwnMetrics`,
  `OwnTraces`, `OwnLogs` through per capability, with no merge and no
  persistence.
- Elastic `fleet-server`, `docs/opamp.md` (monitoring-only mode, no connection
  settings management), and Bindplane's `com.bindplane.measurements.v1` —
  self-telemetry routed through the configuration channel instead.
- [`opentelemetry-otlp`](https://docs.rs/opentelemetry-otlp/latest/opentelemetry_otlp/)
  and its [feature flags](https://lib.rs/crates/opentelemetry-otlp/features);
  [`opentelemetry-proto`](https://github.com/open-telemetry/opentelemetry-proto),
  the schema deliberately not copied.
- [`opentelemetry-appender-tracing`](https://docs.rs/opentelemetry-appender-tracing/latest/opentelemetry_appender_tracing/)
  `0.33` — `OpenTelemetryTracingBridge`, its statement that it does not convert
  spans, and the changelog entry removing
  `experimental_use_tracing_span_context` (fixing
  [opentelemetry-rust#3190](https://github.com/open-telemetry/opentelemetry-rust/issues/3190)).
- [`tracing-opentelemetry` 0.34.0](https://docs.rs/tracing-opentelemetry/0.34.0/tracing_opentelemetry/)
  — `OpenTelemetryLayer`, the reserved `otel.*` fields,
  `with_context_activation`; and the history of log/trace correlation between
  the two crates,
  [opentelemetry-rust#1378](https://github.com/open-telemetry/opentelemetry-rust/issues/1378),
  [#2803](https://github.com/open-telemetry/opentelemetry-rust/issues/2803),
  [#2824](https://github.com/open-telemetry/opentelemetry-rust/issues/2824).
- [`sysinfo`](https://docs.rs/sysinfo/latest/sysinfo/) — cross-platform process
  CPU and memory.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3; `rustls`'s
  `ClientConfig` protocol versions and `reqwest`'s
  `ClientBuilder::min_tls_version`.
- [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918),
  [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) and
  [RFC 6761 §6.3](https://www.rfc-editor.org/rfc/rfc6761#section-6.3) — the
  private ranges and `localhost`, none of them admitted for cleartext; Rust's
  `IpAddr` parsing, compared with `Ipv4Addr::LOCALHOST` and
  `Ipv6Addr::LOCALHOST`.

## Consequences

- Positive: an operator's name for an Agent survives its Managed Process
  reporting for itself; the fleet can be aimed by what an Agent _is_, with no
  per-host attribute to maintain.
- Positive: the fleet view shows each host's addresses, the attributes are
  searchable, and the wire stays convention-shaped for any OpenTelemetry-aware
  consumer.
- Positive: three capability bits from one mechanism, and a fleet's Clients
  become observable without a second agent on the host, at a destination the
  Server decides.
- Positive: the wire format and the semantic conventions stay upstream's; a
  moved convention arrives as a version bump.
- Positive: a failed rollout is one trace naming the failing phase, and its log
  lines are joinable to it by `TraceId`. With no destination offered,
  instrumentation costs nothing.
- Positive: own telemetry can be switched off from the fleet — per signal by
  leaving it out of `[telemetry_offer]`, entirely with empty endpoints — and
  both this Server and a supervisor-shaped one can drive this Client and each
  other's Agents with one reading.
- Positive: own telemetry leaves the host encrypted wherever it goes, and the
  admission test reads the same on every host: the loopback literals are this
  machine everywhere.
- Negative / trade-offs: `service.instance.name` is a key this project invents;
  a future convention may contradict it, and renaming it would break Selectors
  matching it.
- Negative / trade-offs: an Agent's reported type changes when a Collector gains
  the extension — from the configured or file-name value to `dist.name` — and a
  Selector on the old value stops matching at that moment.
- Negative / trade-offs: network addresses leave the host and are visible to
  whoever can read the API; virtual adapters appear beside physical ones,
  because best effort reports what the platform says and does not curate.
- Negative / trade-offs: five OpenTelemetry crates and their batching machinery,
  with a global provider model that sits awkwardly beside destinations that
  change at runtime; and `tracing-opentelemetry` is on a release train one step
  behind the others, so an `opentelemetry` bump has a second cadence to wait
  for.
- Negative / trade-offs: exporter diagnostics and the Client's `tracing` output
  share a process; the bridge must not feed exporter errors back into the
  exporter.
- Negative / trade-offs: the Resource carries what describes the Agent, and span
  fields are as easy to add as log fields; clauses 22 and 23 are a discipline,
  not a mechanism.
- Negative / trade-offs: stderr and the log file print the enclosing span on
  every event inside an operation, so familiar lines gain a
  `package.install{…}:` prefix.
- Negative / trade-offs: the update marker carries two ids unrelated to its
  safety role.
- Negative / trade-offs: the `connection.settings.apply` that installs the trace
  exporter is itself not exported — there is nothing to export to until it is
  half done. It corrects itself on the next start, when the persisted
  destination is in force before anything runs.
- Negative / trade-offs: a Collector on the LAN costs a certificate, a name and
  a renewal, or a Collector on each host reached at `127.0.0.1`.
  `http://localhost:4318` is refused, which costs an operator who wrote it the
  literal. A receiver that speaks nothing newer than TLS 1.2 is unreachable
  until it is upgraded or put behind a TLS 1.3 proxy.
- Negative / trade-offs: this is a recorded deviation. The empty
  `destination_endpoint` fails the schema's MUST, so a strict third-party Client
  may reject the message; and a third-party Server that rotates one signal's
  headers by sending that signal alone stops this Client's other two.
- Follow-ups: whether the Server should refuse to compile a `[telemetry_offer]`
  endpoint no Agent will accept (an `http://` address off the loopback);
  surfacing `connection_settings_status` and a stopped reporter in the fleet
  view; watching for upstream settling the offer semantics at the next Baseline
  bump.

## Enforcement

- [`agent.rs`](../../crates/fleet-agent/src/supervisor/agent.rs) unit tests:
  `a_process_reporting_its_type_does_not_take_the_operators_name_with_it`,
  `the_supervisors_own_attributes_survive_whichever_list_a_process_reports_them_in`,
  `the_reported_type_is_the_processs_own_word_where_it_gives_one`,
  `the_clients_own_agent_reports_its_type_and_its_configured_name_separately`,
  `the_clients_own_agent_type_is_the_one_name_this_program_has`,
  `configured_attributes_are_reported_but_never_shadow_reported_ones`,
  `configured_attributes_cannot_restate_the_type_or_the_instance_name`,
  `the_service_namespace_is_absent_until_configured_and_then_identifies`,
  `host_addresses_follow_the_conventions`,
  `os_release_parses_the_fields_the_description_reports`,
  `the_cpu_model_is_reported`,
  `the_agent_reports_the_host_name_a_selector_would_pin_it_by`,
  `the_os_is_reported_as_a_name_and_a_version_not_only_as_prose`.
- [`config.rs`](../../crates/fleet-agent/src/config.rs) unit tests:
  `a_block_may_state_its_agent_type_and_a_reverse_fqdn_is_accepted`,
  `an_empty_agent_type_is_refused_rather_than_treated_as_absent`,
  `attributes_describe_the_host_and_a_block_no_longer_tags_one_agent`,
  `non_string_attributes_are_rejected`;
  [`supervisor/mod.rs`](../../crates/fleet-agent/src/supervisor/mod.rs)
  `a_wrapped_block_that_restates_a_derived_value_is_refused`.
- Server: [`fleet.rs`](../../crates/fleet-server/src/fleet.rs) unit test
  `the_view_joins_a_string_array_attribute`.

- [`crates/fleet-agent/src/telemetry.rs`](../../crates/fleet-agent/src/telemetry.rs)
  tests: `no_destination_builds_nothing` (clause 25),
  `cleartext_is_admitted_by_address_and_nowhere_else`, which refuses
  `localhost`, the rest of `127.0.0.0/8`, the private ranges and an
  address-shaped name,
  `a_cleartext_destination_beyond_the_private_network_is_refused`,
  `a_private_network_destination_is_refused_in_cleartext`, whose refusal names
  the setting and the two loopback literals,
  `a_loopback_destination_is_allowed_in_cleartext` (clauses 29–31),
  `an_empty_endpoint_stops_reporting_and_refuses_nothing` (clause 28),
  `offered_tls_settings_are_refused_by_name`,
  `an_offered_certificate_is_presented_by_the_exporter`,
  `an_offered_certificate_without_its_key_is_refused_and_named`,
  `an_offered_private_key_is_refused_by_name` (clause 32),
  `metrics_are_reported_at_the_interval_the_baseline_recommends` (clause 14),
  `the_resource_carries_the_agents_identifying_attributes`,
  `the_resource_carries_the_platform`,
  `the_resource_carries_no_other_non_identifying_attribute`,
  `an_agent_without_an_instance_name_reports_none` (clause 22),
  `the_exporter_client_speaks_tls_1_3_alone`, which reads the exporter's
  ClientHello off the wire: TLS 1.3 alone in `supported_versions` and only TLS
  1.3 suites, so a destination offering only TLS 1.2 has nothing to negotiate,
  `an_export_to_a_destination_that_never_answers_gives_up` (clause 24),
  `a_span_this_client_writes_reaches_the_offered_destination` (clauses 16–17),
  `a_trace_survives_being_written_down_and_picked_up_again`,
  `an_unreadable_trace_reference_is_ignored` (clause 20).
- [`crates/fleet-agent/src/connection.rs`](../../crates/fleet-agent/src/connection.rs)
  tests: `an_offer_naming_one_signal_stops_the_others`,
  `an_offer_silent_about_telemetry_leaves_all_three_alone` (clause 27),
  `an_empty_endpoint_withdraws_the_signal` (clause 28).
- [`crates/fleet-agent/src/transport/mod.rs`](../../crates/fleet-agent/src/transport/mod.rs):
  `a_refused_telemetry_destination_is_reported_failed_on_the_same_offer` (clause
  31).
- [`crates/fleet-agent/src/update/installer.rs`](../../crates/fleet-agent/src/update/installer.rs):
  `a_marker_carries_its_trace_and_one_written_without_it_still_parses` (clause
  20);
  [`crates/fleet-agent/src/packages.rs`](../../crates/fleet-agent/src/packages.rs):
  `the_download_source_drops_whatever_authorises_it` (clause 23).
- [`crates/fleet-agent/tests/supervisor_process.rs`](../../crates/fleet-agent/tests/supervisor_process.rs):
  `the_phases_of_an_install_hang_off_the_span_that_came_with_it` (clause 18).
- [`crates/fleet-server/tests/own_telemetry.rs`](../../crates/fleet-server/tests/own_telemetry.rs):
  `every_declared_signal_is_offered_a_destination`,
  `a_withdrawn_signal_is_offered_as_an_empty_destination`,
  `an_undeclared_signal_gets_no_destination`,
  `an_agent_that_reports_no_own_telemetry_is_offered_none` (clause 33); and
  [`crates/fleet-server/src/config.rs`](../../crates/fleet-server/src/config.rs):
  `an_empty_endpoint_is_a_withdrawal_and_a_wrong_one_is_still_an_error` (clause
  33).

**Not mechanically decidable:** that no OTLP schema is vendored and no
OpenTelemetry type appears outside `telemetry.rs` (clauses 11, 16), that names
come from the semantic conventions (clause 12), that message handling stays
unspanned and no sampler is configured (clauses 19, 21), that a new span field
carries nothing that should not leave the host (clause 23), and that the
_Deviations_ row stays in step with clauses 27, 28 and 33 (clause 34) — these
are review questions on each change to the files this ADR applies to.
