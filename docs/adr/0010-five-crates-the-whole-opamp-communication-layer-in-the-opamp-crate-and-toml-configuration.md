# ADR-0010: Five crates in one Cargo workspace on tokio and axum without its WebSocket — the whole OpAMP communication layer in the publishable `opamp` crate reading WebSocket frames itself, an internal shared crate by measurement — and TOML configuration

- **Status:** 🟢 accepted
- **Date:** 2026-10-10
- **Deciders:** Markus Brigl
- **Applies to:** Cargo.toml, `crates/opamp/` (its manifest and `[features]`,
  `build.rs`, `src/`, `LICENSE`, `NOTICE` and `README.md`), crates/fleet-core/,
  every OpAMP connection and listener of `crates/fleet-server/` and
  `crates/fleet-agent/` (the Server's two planes, the Client's upstream
  connection and its verification probe, the Gateway's downstream endpoint and
  upstream pool, the Supervisor Endpoint), `AgentState` in
  `crates/fleet-agent/src/supervisor/agent.rs`, the Client's `Session` in
  `crates/fleet-agent/src/transport/`, crates/fleet-agent/src/lib.rs and
  main.rs, crates/fleet-tools/, the bundled UI under
  crates/fleet-server/static/, server.toml and supervisor.toml, the per-feature
  lint in `.github/workflows/ci.yml` and `README.md`, and every new crate,
  module placement or dependency

## Context

The [specification](../SPECIFICATION.md) fixes the language (both ends in Rust)
and the deployables: one Server (Linux only, API-first, with a rudimentary
bundled UI) and one Client binary covering every Client Mode
([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
Everything is async I/O: the Server holds many long-lived connections, the
Client a Connection Pool and supervised processes. The Server must serve
protobuf bodies and WebSocket upgrades on one route set. The Dev Container is
lean ([ADR-0002](0002-dev-container-runtime.md)), so a choice that needs OpenSSL
headers, cmake or node carries a real cost, and the UI is explicitly not the
product.

The floor on the pace of every request body and every WebSocket message
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
clause 14) has to see a message's data frames: judged by the bytes a connection
reads, a message that has begun stays open for ever while its peer sends a Ping
between its fragments, which RFC 6455 allows, and every Ping looks like
progress. axum's WebSocket hands over whole messages only, so `opamp` upgrades
the connection itself and reads the frames with the library its client already
uses, and nothing in the workspace uses axum's `ws` feature. And the order of
the Client's flows after a reply matters: with the certificate first, a request
queued there rides the next connection after the offer that answered it, and is
signed a second time.

The OpAMP communication is one publishable crate with a `client` and a `server`
feature, one endpoint around a handler for every server surface, and one state
machine and two drivers around a session for an Agent. That is one decision, and
every change to the crate touches all three parts.

Stopping at the material a connection is built from — an endpoint that hands out
a router and never a listener, a client that lets the application build the TLS
connector, the HTTP client and the headers — leaves each surface writing its own
transport plumbing.

- **Server TLS twice.** `fleet-server/src/tls.rs` and
  `fleet-agent/src/gateway/mod.rs` each build a rustls `ServerConfig` from a
  certificate, a key and an optional client CA, with the same ALPN fix.
- **Listener bounds once.** `fleet-server/src/listen.rs` bounds the header read
  and the TLS handshake
  ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
  The Gateway's downstream listener and the Supervisor Endpoint have neither
  bound.
- **Client connect three times.** The drivers connect, `connection::verify`
  connects again to prove an offer
  ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)),
  and the Gateway's upstream pool connects a third time. Each one builds the
  WebSocket request, the `Authorization` header and the TLS connector by hand.
- **The ring provider and the PEM readers.** Both ends install the provider with
  the same function. The PEM readers sit in `fleet-core` only because both ends
  need them for TLS.

The maintainer wants the whole communication layer in `opamp`, with its
configuration added from outside. Against that stands the argument that TLS and
credentials built inside `opamp` are this project's policy. That reason holds
for the policy and not for the mechanism. Which CA to trust, which certificate
to present and which credential to send is policy. Turning those bytes into a
rustls configuration, refusing redirects, marking the header sensitive and
bounding a listener is mechanism, and it is the same for every OpAMP
implementation.

Three questions recur once the code exists. **What goes into the shared
crates?** A crate boundary costs what a module boundary does not: every
dependency of a shared crate is gained by both ends, and every change to it
recompiles both. Two different things are shared. What the Baseline defines —
the types, the framing, the endpoint's body rules, the attribute keys, and the
server and client sides of the communication — is OpAMP, reusable by anyone, and
lives in the publishable `opamp` crate. What both ends of _this_ project
implement identically beyond the protocol — the baked version and its grammar,
the PEM readers, the platform aliases — is this project's own, and lives in an
internal crate. **How does a test reach the Client?** Cargo hands a test a
helper binary's path (`CARGO_BIN_EXE_<name>`) only in an integration test, and
an integration test links only a package's library. **Where do operator tools
live?** `opamp-fleetctl`, the operator tool
([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)),
runs on an operator's machine and uses a few Client items: the 7z Unix-mode
convention, the unpackers, and the TLS provider helper.

Operators hand-edit both configuration files, often over SSH; a format's failure
modes matter more than its expressiveness. YAML's indentation and implicit
typing (`no` → `false`) are classic sources of silent fleet misconfiguration.
The payloads the Server distributes are the Managed Process's own format and are
not affected.

## Decision

We will build one Cargo workspace of five crates (`opamp`, `fleet-core`,
`fleet-server`, `fleet-agent`, `fleet-tools`) on `tokio` and `axum`, make
`crates/opamp` the whole OpAMP communication layer — the wire layer always, and
behind `client` and `server` each side's connection end to end, its TLS and its
listener included, built from values the application hands it and never from a
file or a configuration format of its own — keep in `fleet-core` what both ends
implement identically beyond the Baseline, as measured, make the Client a
library under a thin binary, keep the operator tool in its own crate depending
on the Client, and configure both binaries from strict TOML files.

1. **The wire layer, without features.** `proto` (generated from the vendored
   Baseline schema with protox,
   [ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md)),
   `frame`, `endpoint`, `uid`, `attributes` and `BASELINE`. They depend on
   `prost`, `uuid` and `flate2` only.

2. **One publishable crate, versioned by the Baseline.** `publish = true` for
   `opamp` alone, with its metadata and opamp-spec's licence beside the schema.
   The `MAJOR.MINOR` is the Baseline's, the patch number is the crate's own, and
   a breaking change waits for the next Baseline. The first `cargo publish` is
   the maintainer's decision.

3. **Two features, neither on by default, each linted alone.** `client` adds
   `tokio`, `tracing`, `ring`, `tokio-tungstenite`, `futures-util`, `reqwest`,
   `rustls` and `webpki-roots`. `server` adds `tokio`, `tracing`, `axum`,
   `axum-server`, `hyper`, `hyper-util`, `tokio-tungstenite`, `futures-util` and
   `rustls`. `hyper` is named for its upgrade, which axum carries anyway;
   `tokio-tungstenite` is the client's own WebSocket library, so both sides
   frame alike. The lint runs with no feature, with `client` and with `server`.
   docs.rs builds with all features.

4. **`opamp::tls` is the TLS both sides share,** compiled with either feature.
   It installs the ring provider, never a system library
   ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
   It reads certificates and a private key from PEM bytes, and an empty result
   is an error. It carries an `Identity`, a certificate chain and its key as
   PEM. It opens no file. Every rustls configuration either side builds speaks
   TLS 1.3 alone, with the three TLS 1.3 suites of the ring provider. The
   process-wide provider carries those suites and no other, so a TLS stack that
   builds its own configuration, such as `reqwest`'s, cannot negotiate TLS 1.2
   either. The `wss://` connector is always built here, never left to the
   WebSocket library, so TLS 1.3 holds even in an application that never
   installed the provider. This is the specification's floor (Q-3), not a
   setting the application can lower.

5. **The server endpoint.** `opamp::server` serves both transports on one path,
   with the media type, gzip, the limit in both directions, framing, the 1009
   close and the per-connection loop. The application implements `Handler`:
   `on_connecting`, `on_message`, `outbound`, `on_outbound`, `on_unreadable` and
   `on_closed`. `router` returns an axum `Router`. The application may add
   routes and admission layers to it. The WebSocket upgrade is an axum route
   that answers the handshake and takes the connection through hyper's upgrade;
   `opamp` frames it with `tokio-tungstenite` over a reader that follows the
   frame headers as they arrive, so it knows whether a data message has begun
   and how much of it has come, apart from the control frames between its
   fragments (ADR-0013 clause 14).

6. **The server listener.** `opamp::server::listen` builds the rustls
   `ServerConfig` from a certificate, a key and a client-certificate rule: none,
   optional or required against a CA. It sets the ALPN protocols. `serve` runs a
   router on a bound listener with the bounds of ADR-0013: a 30-second header
   read with the timer it needs, and a 10-second TLS handshake. It puts the
   verified peer certificate and the peer address into every request, on every
   listener it serves. A handle shuts listeners down, and one handle may drain
   several. How long a drain may take is the application's to state. `serve`
   refuses to listen without TLS on any address but the loopback literals
   `127.0.0.1` and `::1` (Q-1). Every OpAMP listener of this project serves
   through it. Those are the Server's two planes, the Gateway's downstream
   endpoint and the Supervisor Endpoint.

7. **The client state machine and its session.** `opamp::client::protocol`
   decides which fields a report carries and what a reply means, and depends on
   nothing but `opamp` and the standard library. The application implements
   `Session` for one connection carrying any number of Agents: `connected`,
   `routine`, `owed`, `on_reply`, `after_reply`, `changed`, `exchange_failed`,
   `stop` and `goodbyes`. `AfterReply`, `Ended`, `ReportSink`, `StopSignal` and
   `Backoff` are public.

8. **The client connection.** The application describes a connection as
   `opamp::client::Connection`: the endpoint, the `Authorization` value, the
   trust anchors and the identity as PEM, the message limit, the heartbeat and
   the poll interval. `opamp::client` builds everything from that description.
   It picks the transport by scheme. It builds the rustls configuration for
   `wss://` and the HTTP client for `https://`, which follows no redirect, times
   out after 30 seconds and marks the credential sensitive. It refuses `ws://`
   and `http://` to any host but the loopback literals `127.0.0.1` and `::1`,
   before it connects (Q-1). A host name is never loopback, not even
   `localhost`, because a name can be made to resolve anywhere. The same
   description drives the connection, the one-shot probe that proves offered
   settings (ADR-0014), and a single WebSocket for a caller that drives its own
   socket, such as the Gateway's upstream pool.

9. **What stays with the application is the policy and its sources.** The
   application decides which files hold the material, which identity is in
   force, which credential is sent and when it rotates. It parses `server.toml`
   and `supervisor.toml`. It persists and merges connection settings (ADR-0014).
   It runs the CSR flow and the CA, and it decides admission (ADR-0021). Its
   `AgentState` keeps the Client's decisions over one protocol state machine.
   Its flows after a reply run in one order: connection settings, certificate,
   packages, the self-update restart, the Supervisor set
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).
   Connection settings come before the certificate because an offer may carry
   the certificate a request asked for, and a request queued before it is taken
   in would ride the next connection and be signed again.

10. **Behaviour stays, with these deliberate exceptions.** The suites of the
    three surfaces and of the Client run unchanged on the moved code. The
    exceptions follow from one listener and one connect serving every surface:
    - The Gateway's downstream listener and the Supervisor Endpoint gain the
      header-read and handshake bounds that only the Server had.
    - A plaintext Gateway drains for a bounded time on shutdown, as a TLS one
      already did.
    - The Operator plane and the plain listeners carry the peer address and the
      peer certificate into their requests too. Nothing there reads them.
    - The probe of offered settings applies the message limit and marks the
      credential sensitive, as the long-running connection does.
    - TLS 1.2 is no longer offered or accepted by either end, and plaintext off
      the loopback is refused rather than warned about (clauses 4, 6 and 8).

11. **One workspace, five crates, one lockfile, one toolchain.** `crates/opamp`
    (the publishable communication layer), `crates/fleet-core` (the internal
    shared crate), `crates/fleet-server`, `crates/fleet-agent` and
    `crates/fleet-tools`. Versions are pinned once in
    `[workspace.dependencies]`; `rust-toolchain.toml` pins the compiler. Every
    crate but `opamp` is `publish = false`. A further crate needs a concrete
    need a module cannot meet (compile time, reuse, a dependency boundary);
    hexagonal seams live as modules first.

12. **`tokio` and `tracing`.** The multi-threaded `tokio` runtime on both ends;
    `tracing` with `tracing-subscriber` for structured logging; `serde` for the
    REST API's JSON and for configuration files.

13. **`axum` is the workspace's HTTP server stack.** The Server's OpAMP
    endpoint, REST API and UI are axum routes in one router, upgrades included:
    the OpAMP endpoint's upgrade is an axum route whose connection `opamp` takes
    over through hyper (clause 5), so axum's `ws` feature is off; the OpAMP
    endpoint of the Server, the Gateway and the Supervisor Endpoint is
    `opamp::server`'s, and so is the listener it is served on (clauses 5 and 6).
    Which listeners exist is
    [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)'s.

14. **The bundled UI is static assets embedded in the Server binary.** Plain
    HTML, CSS and JS under `crates/fleet-server/static/`, embedded with
    `include_str!`; no frontend toolchain. The REST API is the contract, and the
    UI is one client of it.

15. **CI enforces the Definition of Done on this stack.** `cargo build`,
    `cargo test`, `cargo fmt --check` and `cargo clippy` with warnings denied on
    Linux; the Client is also checked and tested on Windows and macOS, and
    release-built on all three; the Server is built on Linux only.

16. **The internal shared crate holds what both ends implement identically,
    established by measurement.** Code enters `fleet-core` when both ends
    implement it identically, or would have to, and the Baseline does not define
    it; an end and the operator tool count as two ends here, because the tool
    makes what an end must accept — what it defines goes to `opamp` (clause 17).
    Adding it is ordinary work under this clause. Nothing enters to make the
    crate look less small. Each addition is judged by what it costs the two
    ends; a build dependency is the cheaper case, since it links into no
    artifact.

17. **What goes where.**
    - `opamp`, always: `proto` and `frame`, the generated types and the
      WebSocket framing
      ([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md));
      `uid`, the `instance_uid` type; `attributes`, constants for the Baseline
      keys this project matches on (`SERVICE_NAME`, `SERVICE_INSTANCE_NAME`,
      `SERVICE_NAMESPACE`, `SERVICE_VERSION`, `OS_TYPE`, `OS_DESCRIPTION`,
      `HOST_ARCH`) and the accessors over them, where `string_value` states once
      that an empty string is not a value; `endpoint`, with `OPAMP_PATH`
      (`/v1/opamp`), `PROTOBUF_CONTENT_TYPE`, `is_protobuf`, and `decode_body`,
      which applies the Baseline's gzip MUST with the size limit enforced
      _after_ decompression and whose `BodyError` separates unsupported
      encoding, undecodable gzip and too large.
    - `opamp`, behind its features (clauses 3–8): the server endpoint and its
      listener, an Agent's protocol state machine and connection, and `tls` with
      the PEM readers `certificates` and `private_key`. Their path-based
      wrappers and error wording stay in each end, where what the file means is
      known.
    - `fleet-core`: `version`, the version helper
      ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)); `platform`,
      the platform alias table
      ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md));
      `package`, the statement a package signature covers, which the operator
      tool signs and the Client verifies; `pki`, the rule that says when a
      certificate is ending, which the Server and the operator tool apply alike
      ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)),
      as plain date arithmetic without a dependency.

18. **What the measurement leaves where it is.** The Server's router and
    admission, the Server's CA, the Client's CSR flow, the persistence of its
    connection settings, the choice of which TLS and credential material each
    end hands `opamp`, and the Server's `attr_map` (a decision about the REST
    view). Each exists once. A later measurement that finds one written twice
    moves it under clause 16.

19. **The Client is a library with a thin binary on top.**
    `crates/fleet-agent/src/lib.rs` declares the module tree; `src/main.rs`
    keeps only what starting a process needs: parsing the command line, handing
    off to the daemon or the `service` verbs, and the exit code.

20. **Visibility is widened by need.** An item becomes `pub` when a test or
    another workspace target has to reach it. `pub` in the Client means "another
    target here reaches it", not a published interface. Where widening would
    expose an invariant only the module can hold, the item stays private and the
    test moves to where it can see it.

21. **Tests reach what they test through the library.** Integration tests import
    constants rather than restating them, and tests that spawn a real program
    spawn the Client's own cross-platform stubs (`stub_agent`, `stub_crasher`,
    under `crates/fleet-agent/src/bin/`) instead of a shell, so they run on all
    three platforms. A `#[cfg(unix)]` gate sits only on what is genuinely a Unix
    fact, such as a file mode. The stubs stay in `fleet-agent`, because
    `CARGO_BIN_EXE_*` resolves only inside the crate that declares them.

22. **The operator tool is its own crate, depending on the Client.**
    `crates/fleet-tools` produces `opamp-fleetctl` (ADR-0028) and has no
    library. The arrow points one way: `fleet-tools` uses
    `fleet_agent::archive`, `opamp::tls` and the items of `fleet-core` clause 17
    names rather than restating them, and its tests open what the tool produces
    with the Client's own unpacker. Nothing in `fleet-agent`, `fleet-server` or
    `opamp` depends on `fleet-tools`. Tool-only dependencies (the 7z writer,
    release listing) are declared there, so `cargo build -p fleet-agent` does
    not build them. The code that makes the fleet's certificate authorities
    lives there too; no end runs it.

23. **Both binaries are configured from TOML.** `server.toml` and
    `supervisor.toml`, parsed with the `toml` crate into `serde` structs. Each
    binary takes the path from `--config`, defaulting to the file of that name
    in the working directory, and runs on defaults when the file does not exist.
    The file is the whole configuration: no setting is read from the environment
    (`RUST_LOG` filters log output and configures nothing else).

24. **A configuration that does not parse fails startup, loudly.** Every setting
    has a documented default; unknown keys are rejected (`deny_unknown_fields`,
    or the equivalent strict parse for a `[[supervisor]]` block's kind-specific
    keys), and an invalid value or half-written setting is an error naming it.
    The same holds for files a binary reads at startup to restore its state: one
    that does not parse fails startup rather than being skipped or silently
    defaulted.

**Out of scope:** the CSR flow and the Server's CA, which stay in the
application with ADR-0021; finer features, such as one per transport; a release
routine for the crate; where the PEM material comes from on disk; where an
installed service looks for its configuration file on each OS
([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md));
the listener layout
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md));
whether a release ships the operator tools.

## Alternatives considered

- **axum's WebSocket, judged by the bytes the connection reads.** A Ping between
  two fragments of a message looks like progress, so a message stays open for
  ever; treating control frames as no progress closes a peer that only pings.
  TLS records and the bytes read with the upgrade request blur the count too.
- **Parsing the frames below hyper, in the listener's stream.** Below TLS the
  bytes are encrypted; above it, hyper reads ahead of the upgrade request and
  the parser would have to follow every HTTP/1 request on the connection to find
  where the frames begin.
- **A residual written down instead.** The floor would hold for bodies and not
  for the transport that carries the fleet.
- **Keep the material with the application.** Rejected: three surfaces write the
  same connect, and two listeners lack the bounds the third has. The policy
  argument is met by clause 9, which keeps every decision about the material
  with the application.
- **Let `opamp` read the files and the TOML sections itself.** Rejected: a
  published crate would impose this project's file layout and configuration
  format on every user, and a test would need files where it now passes bytes.
- **The choice of TLS material and credential in `opamp`.** That choice is this
  project's policy, not the protocol, so each end makes it and hands `opamp` the
  result (clause 9).
- **Hand `reqwest` a prebuilt rustls configuration**, so that one configuration
  serves both transports. Not chosen: `tls_backend_preconfigured` is documented
  without semver stability and breaks silently on a version mismatch. The PEM
  bytes feed `reqwest`'s own builder instead.
- **Move the CSR flow into `opamp` too.** Not chosen now: OpAMP carries the CSR,
  but generating a key and signing a request is certificate policy, and it would
  add `rcgen` to the published crate. It can follow once a second user wants it.
- **Separate crates per side, or `client` and `server` on by default.**
  Rejected: the sides share a version and break together, and a types-only user
  would pull both dependency sets.
- **Depend on an existing crate.** None fits: `otel-opamp-rs` follows a 2023
  draft and is dormant, and `newrelic-opamp-rs` is licensed for New Relic's
  service only.
- **`actix-web`.** Its own runtime flavour and actor heritage; axum is plain
  `tokio` and `tower`, and is where the OpenTelemetry Rust ecosystem sits.
- **Raw `hyper`.** We would hand-write routing, upgrades and extractors that
  axum provides as a thin layer over hyper anyway.
- **A frontend framework and bundler for the UI.** A node toolchain in the Dev
  Container and CI is a large standing cost for a page the specification caps at
  rudimentary.
- **One shared crate for the protocol and this project's own code.** The git
  build step and the version grammar would sit in a crate others build from a
  registry, outside any checkout (clause 2).
- **Resolving the stub from the test binary's directory.** The suite would pass
  or fail depending on the command that ran it.
- **Moving the supervision core into its own crate for testability.** A library
  target meets the need without turning every internal seam into a crate API.
- **Operator tools inside `fleet-agent`, or `archive` moved into `opamp`.** The
  first keeps tooling in the crate that runs on every managed host; the second
  widens the shared crate with something only the Client implements, since the
  Server never opens an artifact.
- **A separate repository for the tools, or duplicated items.** The tools'
  correctness is defined by what the Client can install, and
  `unix_mode_attributes` must have one definition.
- **YAML.** The OpenTelemetry ecosystem's format, but with indentation and
  implicit-typing failure modes in hand-edited files, and `serde_yaml` is
  unmaintained.
- **JSON, or environment variables and flags only.** JSON has no comments; flags
  cannot carry the Client's per-Supervisor structure, and a file is what an
  installer lays down and an operator diffs.

## Sources / Prior art

- [`opamp-go`](https://github.com/open-telemetry/opamp-go): `server.Start`
  beside `server.Attach`, where `StartSettings` carry the listen address and a
  `tls.Config`; `client.StartSettings` carry the endpoint, the header and a
  `tls.Config`, and the client builds its HTTP and WebSocket connections from
  them. Read 2026-10-01. `protobufs`, `protobufshelpers` and `internal`
  (`wsmessage.go`, `limits.go`) shared; the WebSocket and HTTP machinery inside
  `client` and `server`.
- [`reqwest::ClientBuilder`](https://docs.rs/reqwest/0.13/reqwest/struct.ClientBuilder.html):
  `tls_certs_only`, `identity` and `tls_backend_preconfigured`, with the
  stability warning on the last. Read 2026-10-03 in the vendored 0.13.5 source.
- [`axum-server`](https://docs.rs/axum-server/0.7)
  `RustlsAcceptor::handshake_timeout` and
  [`hyper-util`](https://docs.rs/hyper-util/0.1) `TokioTimer`, as ADR-0013 cites
  them.
- [`rustls-pki-types`](https://docs.rs/rustls-pki-types) `PemObject`, the PEM
  reader rustls itself uses.
- hyper and tonic features, the sans-IO pattern, `quinn` over `quinn-proto`, and
  the Cargo book on publishing and feature unification.
- [`axum`](https://docs.rs/axum/0.8) and [`tokio`](https://tokio.rs/) — the
  router with built-in WebSocket upgrade, and the de-facto async runtime.
- [Bindplane](https://bindplane.com/) — the look-and-feel reference for the
  bundled UI (fleet table, status chips, config drawer).
- [The Cargo Book, environment variables](https://doc.rust-lang.org/cargo/reference/environment-variables.html)
  — `CARGO_BIN_EXE_<name>` is set only for integration tests and benchmarks,
  which build the package's binaries automatically;
  [Cargo targets](https://doc.rust-lang.org/cargo/reference/cargo-targets.html)
  — integration tests and binaries use the package's library;
  [workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html) and
  [RFC 2906](https://rust-lang.github.io/rfcs/2906-cargo-workspace-deduplicate.html)
  — one lockfile, one resolved version per dependency.
- [`ripgrep`](https://github.com/BurntSushi/ripgrep) — a library with a thin
  `main.rs`; `kubectl` beside `kubelet` — an operator tool built with the system
  it drives but not run on a node.
- [TOML v1.0](https://toml.io/), the
  [`toml` crate](https://crates.io/crates/toml), and the
  [`serde_yaml` deprecation notice](https://github.com/dtolnay/serde-yaml);
  [`opampsupervisor` configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/specification/README.md)
  — the YAML prior art not followed for this project's own files.

## Consequences

- Positive: a Rust OpAMP implementer gets a working client or server, TLS
  included, from one dependency and a few values. This project's three surfaces
  share the connect, the listener and the bounds, so a fix lands once.
- Positive: `fleet-core` no longer links `rustls`; it holds the version and the
  platform aliases.
- Positive: one lockfile and one toolchain, and both ends share `opamp`, so they
  cannot drift on the wire types, the Baseline's fixed strings, the gzip rule,
  or the communication around them. A misspelt attribute key is a compile error
  rather than a silent mis-targeting.
- Positive: the Server is one binary embedding its UI. The operations that write
  to a host (binary swap, health gate, rollback, tree install) are tested on all
  three platforms.
- Positive: `crates/fleet-agent` is what runs on a managed host, and its
  manifest says so.
- Negative / trade-offs: the published API grows by `Connection`, the listener
  and the TLS types. `axum-server`'s `Handle` and `tokio-tungstenite`'s socket
  become part of it, so a breaking bump of either waits for the next Baseline.
- Negative / trade-offs: the `server` feature pulls `axum-server` and
  `hyper-util`, and `client` pulls `webpki-roots`. A user who brings their own
  listener pays for one anyway.
- Negative / trade-offs: the listener attaches the per-connection extensions
  with `Router::layer`, which rebuilds the route table once per accepted
  connection. It costs more on a listener with many routes, such as the Operator
  plane, and is unmeasured.
- Negative / trade-offs: `tokio` and axum are a deep commitment; reversing them
  touches every I/O boundary. A UI change needs a Server rebuild.
- Negative / trade-offs: every dependency of `opamp` or `fleet-core` recompiles
  both ends. `endpoint` being framework-free means each caller writes its own
  mapping from `BodyError` to a status code.
- Negative / trade-offs: `pub` inside the Client does not mean "interface", and
  the compiler does not warn about a `pub` item nothing uses.
- Negative / trade-offs: operators coming from OpenTelemetry meet a second
  format for the fleet tooling itself.
- Follow-ups: the CSR flow in `opamp` if a second user wants it; finer features
  if a user asks for one transport alone; a shared test-support target if two
  suites want the same helpers; environment-variable overrides if containerised
  deployments need them.

## Enforcement

- `crates/opamp/src/lib.rs` `the_crate_version_is_the_baselines` fails when the
  crate's `MAJOR.MINOR` and `opamp::BASELINE` disagree (clause 2).
- `cargo publish --dry-run -p opamp` builds from the packaged sources outside
  any checkout, and [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
  lints `opamp` with no feature, with `client` and with `server` (clauses 1–3).
- `crates/opamp/src/tls.rs` tests that an empty or foreign PEM is an error and a
  bundle keeps its order (clause 4).
- `crates/opamp/tests/server_endpoint.rs` drives the endpoint over both
  transports (clause 5); `crates/opamp/tests/server_listen.rs` holds a message
  whose fragments are interleaved with Pings to the floor, and leaves a peer
  that only pings open (clause 5).
- `crates/fleet-agent/tests/enrolment_e2e.rs` issues one certificate per
  enrolment and per renewal (clause 9).
- `crates/opamp/tests/server_listen.rs` proves the header-read bound, the
  required and the optional client certificate, and the peer certificate in the
  request (clause 6).
- `crates/opamp/src/client/protocol.rs`, `ws.rs`, `http.rs` and `backoff.rs`
  keep the client-side MUSTs under test (clause 7).
  `crates/opamp/src/client/connection.rs` tests the scheme choice and the
  cleartext rule, and `crates/opamp/tests/client_connection.rs` the probe on
  both transports, the redirect refusal and a run (clause 8).
- The structural test `crates/fleet-core/tests/dependency_direction.rs` lists
  every module. The application suites run unchanged on the moved code (clauses
  9, 10).
- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml):
  `build-test-lint` (clause 15), `client-platform-check` on Windows and macOS,
  and `release-build` (clauses 15, 21). The workspace manifest lists the five
  members, and Cargo refuses a dependency cycle, so `fleet-agent` cannot come to
  depend on `fleet-tools` (clause 22).
- [`crates/fleet-agent/tests/supervisor_process.rs`](../../crates/fleet-agent/tests/supervisor_process.rs)
  spawns `stub_agent` through `CARGO_BIN_EXE_stub_agent`, and
  [`crates/fleet-agent/tests/self_update_e2e.rs`](../../crates/fleet-agent/tests/self_update_e2e.rs)
  imports `fleet_agent::update::EXIT_RESTART_FOR_UPDATE` (clauses 19, 21).
- `crates/opamp/src/attributes.rs` `an_empty_string_is_not_a_value`;
  `crates/opamp/src/endpoint.rs`
  `a_gzip_bomb_buys_no_more_memory_than_a_plain_body_would`,
  `what_is_not_gzip_under_a_gzip_header_is_refused`,
  `an_encoding_this_endpoint_does_not_implement_names_itself`;
  `crates/opamp/src/tls.rs` `a_file_holding_no_certificate_is_an_error` (clause
  17).
- `crates/fleet-server/src/config.rs` `rejects_unknown_keys` and
  `crates/fleet-agent/src/config.rs`
  `rejects_an_unknown_scheme_and_unknown_keys` (clause 24).

**Not mechanically decidable:** whether a piece of code is implemented
identically by both ends (clauses 16, 18), and whether a widened item is needed
(clause 20), are judgements made in review.
