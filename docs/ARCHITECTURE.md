# Architecture — OpAMP Fleet

> The system **as it stands today**: the parts it is built from, what each is
> responsible for, and how they fit together. It holds no rule and no decision.
> It names the ADR behind each structural choice; where it disagrees with an
> accepted ADR, the ADR is right and this document is stale. It is updated in
> the same change as the structure it describes
> ([ADR-0001](adr/0001-agent-governance-model.md)).
>
> **Kept current by:** Markus Brigl. A document everyone may edit and nobody
> owns is the one that goes stale.
>
> **Last design revision:** none yet, due after 20 changes. The revision that
> ran moves the date; the number is this project's to set; a sensor counts the
> changes outside `docs/` since the date and says when the next is due
> ([ADR-0004](adr/0004-feature-layer.md)).

## Context

What sits outside the system and what crosses its boundary. A diagram earns its
place here more than anywhere else, and none beats one that has stopped being
true.

```text
 operator ── REST / bundled UI ──▶ Operator plane :4321 ─┐
                                                         │  Server (Linux)
 Client ──── OpAMP, mTLS ──────────────▶ Agent plane :4320 ─┘   │
   │  ▲                                                          └─▶ data_dir: fleet state,
   │  └── Gateway (a Client) ◀── OpAMP, mTLS ── other Clients        register, audit record,
   │                                                                 artifacts by SHA-256
   ├── Supervisor Endpoint (loopback) ◀── a Collector's opampextension
   ├── Managed Processes: Collector, any command
   ├── package downloads: the Server's own origin, and no other
   ├── own-telemetry destinations: OTLP/HTTP, as the Server offers them
   └── service manager: systemd, launchd or the Windows SCM
```

- **Operators** drive the fleet through the REST API on the Operator plane,
  guarded by `[rest.auth]` beyond the loopback; the bundled UI uses the same API
  ([ADR-0021](adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
- **Clients** reach the Agent plane over OpAMP — WebSocket or plain HTTP —
  admitted by the client certificate in the TLS 1.3 handshake alone
  ([ADR-0013](adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md),
  ADR-0021). A Client in Gateway Mode carries other Clients' Agents over its own
  upstream connections and refuses what the Server revoked
  ([ADR-0015](adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
- **Managed Processes** run on the Client's host under a Supervisor each; a
  Collector reports through its own `opampextension` to the Supervisor Endpoint,
  which admits only the process its Supervisor started
  ([ADR-0015](adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
- **Package downloads** come from the Server alone: every artifact is uploaded
  to it, and a Client fetches only from its own Server's origin, or from its
  Gateway. What arrives is checked against its hash and the operator's signature
  ([ADR-0026](adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md),
  [ADR-0033](adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)).
- **The service manager** starts the Client and restarts it after a self-update
  ([ADR-0018](adr/0018-the-client-updates-itself-under-its-own-agent-type.md)).
- **Upstream**, the opamp-spec release named as the Protocol Baseline in
  [`CONFORMANCE.md`](CONFORMANCE.md) fixes the wire format.

## Building blocks

The parts the system is made of, each with one responsibility, named in the
vocabulary of [`GLOSSARY.md`](GLOSSARY.md). One level deep, deeper only where
the size of a part earns it. The golden path and the test pattern an agent
copies from are named here.

Five crates in one workspace
([ADR-0010](adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)):

- **`opamp`** — the OpAMP communication layer, publishable on its own
  ([ADR-0010](adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)).
  Always the generated types, framing and the endpoint's body rules. Behind
  `client`, an Agent's protocol state machine, the two transports, and
  `client::connection`, which builds a connection, its TLS and its HTTP client
  from a `Connection` the application fills in. Behind `server`, the endpoint
  around a `Handler`, `server::listen`, the listener with its TLS and its bounds
  on connection setup, and `server::pace`, the floor every body and WebSocket
  message it serves is held to. The server side takes a WebSocket over through
  hyper's upgrade and reads its frames with `tokio-tungstenite`, the library the
  client side uses too. `tls` reads PEM and installs the ring provider. It reads
  no file and knows nothing of this project.
- **`fleet-core`** — what the Server and the Client implement identically beyond
  the protocol: the version, the platform aliases, the statement a package
  signature covers, the renewal proof and the bootstrap proof a CSR carries —
  read from a CSR by the adapter `csr` — the host a certificate that names none
  is taken for, when a certificate counts as ending, and what a certificate is
  called — and the bootstrap certificate's PKCS#12 file, whose rule is core and
  whose reading and writing with `p12-keystore` is the adapter `pkcs12::file`
  (ADR-0029).
- **`fleet-server`** — the Server: the fleet and its Hosts, its Configurations,
  labels, packages and Deployments, the Agent plane and the Operator plane.
- **`fleet-agent`** — the Client in all its modes, the program `supervisor`.
- **`fleet-tools`** — the operator tool, the one program `opamp-fleetctl`: its
  `package` commands fetch, pack, hash and sign package artifacts — or sign a
  Package's signing file from the UI (ADR-0027) — its `pki` commands make the
  fleet's certificates (ADR-0028).

Inside the Server and the Client the code is ports and adapters
([ADR-0006](adr/0006-architecture-style.md)): a **core** that holds the domain
and owns its **ports**, **adapters** that bind a port to a technology, and a
**composition root** — `lib.rs`, `main.rs`, and on the Client `supervisor`,
`service::runtime` and `service::enrol` — that wires the two. Every module's
role is listed in
[`dependency_direction.rs`](../crates/fleet-core/tests/dependency_direction.rs),
which fails when a core module names an adapter or a technology, and when a
module has no role.

- **Server stores** — one port per domain in the core module it serves, shaped
  so a database or an object store could implement it, and speaking in domain
  types, never paths
  ([ADR-0037](adr/0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)):
  `AgentStore` in `agent_store`, which holds each Agent's labels in its record,
  writes a rollout's revisions and assignments as one operation, and answers
  what an assignment pins; `ConfigBackend` under the `ConfigStore` in `configs`;
  `DeploymentBackend` under the `DeploymentStore` in `deployments`;
  `PackageBackend` and `BlobStore` (`blobs`, artifact bytes by SHA-256) under
  the `PackageStore` in `packages`; `BootstrapStore` under the
  `BootstrapCertificates` in `bootstrap`; `EnrolmentStore` under the `Enrolment`
  in `enrolment`; `LedgerStore` in `revocation`; `AuditStore` in `audit_log`.
  The filesystem adapters are in `fs`, which also opens the data directory and
  refuses anything its layout does not name. The core's constructors take the
  ports — `AppState::with_stores`, `PackageStore::with_backend`,
  `PackageOffering::with_deployments`, `BootstrapCertificates::open`,
  `Enrolment::open_on` — and `lib.rs` wires the filesystem adapters in
  `AppState::new`, `PackageStore::open`, `PackageOffering::new` and
  `BootstrapCertificates::on_disk`. `migrate` is the one module that reads the
  layout of an older Server, for `server migrate`, and nothing in the running
  Server calls it.
- **Server listeners** — `tls` reads the `[tls]`, `[rest.tls]` and `[enrolment]`
  files into the material each plane serves with — the Agent plane requiring a
  client certificate in the handshake, the Operator plane asking for none and
  serving `[rest.tls]`'s certificate when the section is present
  ([ADR-0032](adr/0032-the-operator-plane-may-serve-a-certificate-of-its-own.md))
  — and tells a member's certificate from a bootstrap one by its issuer.
  `listen` serves both planes on one handle with one drain and a connection cap
  each
  ([ADR-0013](adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
- **Server admission** — `transport::Admission` requires the client certificate
  on every request to `/v1/opamp` and reads no `Authorization` header, admits a
  bootstrap certificate only while the enrolment window is open, and guards the
  package download with the same certificate. Two core modules hold the state
  behind it: `enrolment`, the operator-opened window and the queue of requests
  an operator approves through `api`, and `throttle`, the per-address back-off
  after repeated failures, which both planes use
  ([ADR-0021](adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
  `revocation` holds the register of issued certificates, the revocation list
  and the Hosts — each with the subject values of its certificate, its Gateway
  mark and the Agents bound to it — behind the `LedgerStore` port
  ([ADR-0021](adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md),
  [ADR-0035](adr/0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)).
  `agent_rate` holds the token buckets that bound how often an admitted host, an
  Agent behind a marked Gateway, and the Gateway as a whole are heard;
  `transport` takes a token for each message before the handler does anything
  else and for each download in the guard
  ([ADR-0013](adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
- **Audit record** — `audit` is the port every security decision is recorded
  through; `audit_log` chains the entries by hash and `fs::FsAuditStore` keeps
  them under `data_dir/audit/`
  ([ADR-0022](adr/0022-an-append-only-audit-record-chained-by-hash.md)).
- **Server ports beyond storage** — `fleet` owns `CertificateSigner`, which the
  local CA in `ca` implements for the CSR flow and the renewal proof (ADR-0021),
  and `Clock`, which `clock::SystemClock` implements. The `[connection_offer]`
  and `[telemetry_offer]` sections become the fleet's offers in `config`.
- **REST views** — what the REST API reads and returns is shaped in `api`, which
  derives its OpenAPI schema
  ([ADR-0023](adr/0023-configurations-and-the-rest-api.md)); the core's types —
  among them the fleet view `AgentView` — carry no schema, and `api` converts
  them.
- **Client supervision** — `supervisor::ports` is the Port a Plugin implements
  ([ADR-0017](adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)),
  and `shutdown` the handle every task stops on; the Plugins and the process
  runner are its adapters. How a `[[supervisor]]` block is read — its plugin,
  program, Agent type and timings — is `supervisor::block`, and what a
  Server-delivered block may bring is `supervisor::delivered`; the registry of
  Plugins stays in `supervisor`, which knows the kinds and hands them to both,
  and which hands `delivered` the Supervisors' root as an absolute path too.
  When a failed process is started again or held is `supervisor::restart`'s
  decision; the runner reads the clock and starts it. `supervisor::agent`, an
  Agent's decisions, names three more ports there: `AgentStorage`, which
  `storage::Storage` implements on the state directory, `HighWaterMarks`, which
  `storage::HighWaterFile` implements on `state_dir` and every Supervisor of the
  Client shares
  ([ADR-0043](adr/0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)),
  and `HostFacts`, which `host::SystemHost` implements from the platform. It
  answers each Server message in `handle` and leaves three channels and its
  description each to a submodule: `packages`, `remote_config`,
  `connection_settings`, and `description`, what the Agent reports about itself.
- **Client configuration** — `config` is what `supervisor.toml` may say and the
  rules it must meet
  ([ADR-0010](adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md));
  `config_file` reads it from disk, makes its directories absolute, and finds
  the identity the state directory holds.
- **Client connection** — `tls` decides which CA and which identity are in
  force, and `transport` describes the upstream `Connection` from
  `supervisor.toml` and runs the Engine over it. The settings verification in
  `connection`, the Gateway's upstream pool and its downstream listener, and the
  Supervisor Endpoint use the same `opamp` building blocks
  ([ADR-0010](adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)).
  The Gateway's `revocations` keeps the list it fetches from its Server and
  refuses what that list names
  ([ADR-0015](adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
  The Gateway's `cache` sees every offer `registry` hands down, fetches each
  artifact offered on the Server's route once into the state directory, and
  serves it on the downstream download route to the hosts it was offered to
  ([ADR-0026](adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
  Which host the Gateway takes to speak for an `instance_uid` is decided in the
  core module `gateway::policy`; the cache holds the bindings. With a bootstrap
  CA the Gateway tells an enrolling peer from a member and relays its one
  plain-HTTP enrolment request without a binding
  ([ADR-0039](adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)).
- **Client engine** — `engine` routes the Server's replies to the Agents over
  one connection
  ([ADR-0015](adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
  The transports, the Gateway, telemetry and the service runtime are adapters
  around it.
- **Client self-update** — `update` is the Client updating itself
  ([ADR-0018](adr/0018-the-client-updates-itself-under-its-own-agent-type.md)).
  It owns the port `SelfUpdater` and `SelfUpdate`, the state the Engine keeps
  about it: armed or not, probation committed, restart due. `update::installer`
  implements the port on the version directories and holds the start-up check of
  the process that follows an install.

## How it runs

The few paths worth following end to end, such as a request, a job, or a build,
and where state lives between them. Only what a newcomer would otherwise
reconstruct from code.

**A Configuration reaches an Agent.** An operator saves a Configuration through
`api`, puts it into a Deployment in `deployments`, and rolls the Deployment out;
`fleet` replaces the assignment of every Agent the Deployment's Selector claims
with one release — the Package for its type and every Configuration that fits
its type, pinned by revision hash in `configs` — composes each Agent's
configuration and pushes the offer over the Agent's WebSocket, or answers the
next poll with it. On the Client, `engine` routes the offer to the Agent's
Supervisor, which writes the entries into the Supervisor's `config/` directory
and restarts its process; the Agent reports `APPLIED` or `FAILED` with the
reason, and the Server stops offering once the reported hash matches
([ADR-0023](adr/0023-configurations-and-the-rest-api.md),
[ADR-0034](adr/0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)).
A Configuration typed for the Client itself carries `[[supervisor]]` blocks,
which `reconfigure` checks and writes into `supervisor.toml` before it starts or
stops anything
([ADR-0017](adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).

**An Agent is placed under its Host.** Each Agent record names the Host it last
arrived over — its own, or the Gateway's behind one. `fleet` derives from it,
per Agent, what its effective description adds to its report: the `fleet.host.*`
values of the Host it arrived over directly, and the labels of its Client Agent
— the Agent reporting `supervisor.kind.*` in the same group, which is the Host,
or behind a Gateway the machine the Agents report. It keeps that placement per
group and places a group again when a report, a label, a forget or a Gateway
mark changes it, so every Selector match reads the same description without a
fleet-wide pass
([ADR-0035](adr/0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)).

**A package reaches an Agent.** An operator uploads an artifact into `packages`
and signs its entry there — `packages` checks the signature against
`[packages] verification_key` when the Server holds one, and only reports — then
puts the Package into a Deployment with a Selector and releases it, together
with the Configurations the Deployment holds. The Agent is offered the package
with its entry's signature; the Client downloads it from its own Server's origin
and nowhere else, and `api` serves it only when `fleet` finds it offered to an
Agent the certificate's host speaks for, by the test `packages` shares with the
offer
([ADR-0026](adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md),
[ADR-0033](adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md));
behind a Gateway the Client downloads it from the Gateway's cache, which
`gateway` fetched once from the Server. The Client checks hash and signature in
`packages`, and the Supervisor swaps the program, keeps the previous one for its
grace period and rolls back if the new one does not stay up. The Client's own
package goes through `update` instead: a version directory beside the running
one, a self-check, the `current` pointer moved, and a restart on probation that
commits or rolls back.

**A host joins and stays.** The Server issues bootstrap certificates on an
operator's request: `bootstrap` checks the subject and the life, records what
was issued, and asks its `BootstrapSigner` port — the bootstrap CA with its key
in `ca` — to make the key, sign, and seal both into the PKCS#12 file it keeps,
the key's only way out
([ADR-0028](adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)).
A fresh host presents a bootstrap certificate while an operator has the
enrolment window open — to the Server, or to a Gateway that relays its request —
and proves it in its CSR
([ADR-0039](adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md));
the request is filed under the certificate it proves and waits until an operator
approves it, and the certificate it gets names a new host and carries the
subject values `tls` read from the bootstrap certificate and `ca` checked again,
never the CSR's; every renewal carries the predecessor's
([ADR-0036](adr/0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)).
The questionnaire of `service install --interactive` and `service config` does
this before the service is registered: `service::enrol` runs the Client's own
Agent over the ordinary `transport` with the bootstrap pair until the issued
certificate is in the state directory
([ADR-0019](adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
From then on the Client renews at two thirds of the certificate's life, proving
with the old key which certificate it renews. A revocation closes the sessions
it concerns at once and follows every renewal.

**Where state lives.** The Server keeps all of its state under one `data_dir`,
one directory per domain and owner-only: `configurations/`, `deployments/`,
`packages/` (metadata) and `blobs/` (the artifacts, named by SHA-256), `agents/`
(each Agent's record, its labels inside), `hosts/`, `certificates/` (the
register), `revocations.json`, `bootstrap/`, `enrolment.json` (the window and
its queue) and `audit/`
([ADR-0037](adr/0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)).
A restart restores the fleet from them and shows each Agent disconnected until
it reports; an installation an older Server wrote is moved there once by
`server migrate`. The Client keeps its state under `state_dir`: the issued
certificate and key, the connection settings the Server offered, and per
Supervisor a directory with `config/` and `program/`. An installed Client runs
from `versions/<version>/` through the `current` pointer
([ADR-0019](adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
