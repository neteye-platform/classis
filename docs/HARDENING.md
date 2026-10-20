# Hardening the Client–Server Link

**This document is a backlog, not a decision.** Everything below is a *candidate* measure for
hardening the connection between the Client and the Server: written down so it can be picked up
deliberately later instead of being rediscovered, and ordered so the cheap wins are not buried under
the expensive ones. Nothing here is binding. Each measure states what it would cost and what still
has to be established, and the ones that constrain the architecture say so and name the ADR they
would have to supersede — by topic, since the number does not exist yet.

Every measure is stated here in full, so this document can be read on its own. None below is a
conformance question: the Baseline requires none of it.

## Scope

The link this document is about is **Client ↔ Server**. In this project's vocabulary a Supervisor
lives *inside* the Client ([`crates/fleet-agent/src/supervisor/`](../crates/fleet-agent/src/supervisor/)) and
does not speak to the Server itself — the Client carries every Supervisor's Agent over its one
connection (ADR-0015, ADR-0017). Where other OpAMP material says "Supervisor ↔ Server", this is the
link it means.

One adjacent surface is in scope because it terminates on the same host and carries the same
protocol: the **Supervisor Endpoint**, the loopback WebSocket each Supervisor serves for a Managed
Process's `opampextension` ([`endpoint.rs`](../crates/fleet-agent/src/supervisor/endpoint.rs)), which
admits only the process its Supervisor started (ADR-0015).

Out of scope, and deliberately so: **authorization and multi-tenancy**, which the specification
names as non-goals, with one bound on the Agent plane: a host receives from the Server only the
configurations and packages released to an Agent it speaks for (ADR-0026), on the Server and from
a Gateway's package cache alike. The boundary is worth
stating precisely because the host binding (ADR-0021 clause 7) runs close to it — *which Agent is
speaking*, and so *what its host may receive from the Server*, is authentication and belongs here;
*what that Agent is allowed to do* beyond that is authorization and does not.

## What already holds

Stated first so the list below is not read as a list of absences. On this link the project already
has:

- TLS on both transports, on both ends, with a private CA supported on the Client (ADR-0013).
- **One proof on the Agent plane, required in the handshake** (ADR-0021,
  `transport::Admission`): a client certificate the client CA issued, valid and not revoked. No
  configuration admits a peer without one. The plane has no credential: `server.toml` refuses an
  `[auth]` section and a credential key in `[connection_offer]` at startup, and `/v1/opamp` and the
  download route read no `Authorization` header. The Client sends none, and nothing in
  `supervisor.toml` admits a host; its only secret on the Agent plane is its private key.
- Basic authentication over the **whole** Operator plane, the UI included (`[rest.auth]`,
  ADR-0021), required beyond the loopback, on a listener that is loopback until an operator
  publishes it (ADR-0013). A verification that succeeded is remembered by the SHA-256 of the
  header and compared in constant time (`credentials.rs`).
- Client certificates the Server issues itself through the Baseline's CSR flow, with the Agent
  keeping its private key — and with the request's `basicConstraints`, `keyUsage`,
  `extendedKeyUsage`, and SANs **overwritten** rather than carried over, so a CSR cannot ask for the
  powers of a CA ([`ca.rs`](../crates/fleet-server/src/ca.rs)). Through a Gateway a CSR is signed
  only with a renewal proof, so a member behind it cannot obtain a certificate for the Gateway's
  host and its powers; one with a bootstrap proof is an enrolment, which the Server checks and an
  operator approves for a host of its own (ADR-0039).
- Message size limits enforced in both directions on both transports, and at the Supervisor
  Endpoint.
- **TLS 1.3 alone, on every connection of both ends** (ADR-0010, ADR-0013): the process-wide
  provider carries the three TLS 1.3 suites and no other, every configuration pins TLS 1.3, and a
  peer offering only TLS 1.2 fails the handshake. Plaintext is accepted on `127.0.0.1` and `::1`
  alone and refused at startup anywhere else.
- **A certificate in the handshake, and enrolment by approval** (ADR-0021, ADR-0015): every
  Agent presents a client certificate the Agent plane and every Gateway ask for in the TLS
  handshake. A fresh host enrols with a bootstrap certificate from a CA of its own, only inside an
  operator-opened window, and only once an operator approves its request, which proves the
  bootstrap certificate it rests on with a signature of its key (ADR-0039). Repeated admission
  failures from one address are answered `429` before admission checks anything else, on both
  planes. On the Agent plane the TLS handshake and its client-certificate verification come
  before that, and a failed handshake is not counted as an admission failure.
- **Nothing installed unsigned, and downloads only from the Client's own Server** (ADR-0026,
  ADR-0033): a Client without the verification key takes no package, the Server offers no entry
  that carries no signature, and every download hop is held to `https://` and the Client's own
  Server origin before a request is sent. Every artifact is uploaded: the Server sends no request
  for a package anywhere and holds no source credential.
- **A connection cap per plane and bounded HTTP/2** (ADR-0013): `max_connections` closes a
  connection past the cap on accept, before any handshake, while the held ones keep working; HTTP/2
  allows 100 concurrent streams per connection and drops a peer that leaves a ping unanswered.
- **Connection setup bounded on both of the Server's planes** (ADR-0013): a peer has 30 seconds to
  send its request line and headers, and 10 seconds to complete the TLS handshake, before it is hung
  up on — enforced below every other limit in this list, because it applies before a request exists
  and therefore before Admission ever runs.
- Package content hashed and Ed25519-verified always, with no unsigned posture: without a
  verification key, or for an offer without a signature, nothing is downloaded. Archive members are
  validated before anything is written.
- **Revocation that ends sessions** (ADR-0021): the Server keeps a persisted
  list of revoked certificates, by issuing CA and serial — at most 20 octets, as RFC 5280 allows,
  so the list stays within what a Gateway reads — and extended along every renewal it signed.
  Admission refuses them on both transports and on the
  download, a revocation closes exactly the WebSocket sessions it concerns with `1008`, every
  session ends when the certificate that admitted it expires, and a kept-alive connection is
  refused on both transports and on the download once its certificate has expired.
- **A Gateway refuses what the Server revoked** (ADR-0015, ADR-0021): a host marked as a Gateway
  fetches the revoked certificates of the client CA every 30 s and refuses them downstream, closing
  the sessions they hold with `1008`; while it holds no list younger than 300 s it admits nobody.
  It forwards no `Authorization` upstream, and every upstream connection carries its own
  certificate alone. A Gateway that trusts the bootstrap CA lets a peer of it relay one plain-HTTP
  enrolment request and nothing else — no WebSocket, no binding, no offer, no download — and the
  Server checks the request's proof against its own bootstrap CA and revocation list (ADR-0039).
- **A CSR's claim to an `instance_uid` is checked** (ADR-0021): a CSR naming any
  `instance_uid` but its sender's is answered `BadRequest` before it is signed or queued — the
  Baseline's conditional MUST.
- **A certificate names its host, and a host speaks only for its own Agents** (ADR-0021 clauses
  7, 14 and 27): the Server puts a host of its own in every certificate it signs; an
  `instance_uid` first reported with one host's certificate is not spoken for by another's — such a
  reporter is re-keyed — and a host holds at most three valid certificates. A renewal proves the
  certificate it renews with that certificate's key, so it keeps its host and chain through a
  Gateway too. An operator marks a Gateway, whose certificate then speaks for any Agent.
- **Key material and configuration readable by their owner alone** (ADR-0021 clause 8, ADR-0019
  clause 18): on Unix the private key, the stored connection settings and `supervisor.toml` are
  written `0600` in `0700` directories. On Windows a system-scope install gives the default data
  root under `%ProgramData%` to the Administrators, whoever created it, drops every right in it
  that the install does not grant, cuts it off from the read right every local user inherits
  there, and leaves it to LocalSystem, the Administrators and the service account. A data root
  named with `--root` or `--data-root`, a state directory outside the data root, and a Supervisors'
  root outside both that the install creates, is only cut off from inherited rights and left to the
  same accounts; such a Supervisors' root that already exists is left as it is, with a warning, and
  protecting it is the operator's. A local user acting while the install runs is not covered.
- **A delivered Supervisor block reaches no further than the package signature** (ADR-0017): no
  environment or arguments beyond what the running block has or the operator allowed, and no file
  outside its own `config/` directory. Under clause 38's rule — no variable that steers which code
  a program loads, no value pointing where the Server delivers unsigned files — the Client refuses
  the names and placeholders the clause lists, and further loader variables (`PATHEXT`, `COMSPEC`,
  `NODE_PATH`, `PYTHONHOME`, `PERLLIB`, `PERL5DB`, `RUBYLIB`) and new values that start with a path
  under the Supervisors' root.
- **No credential in `server.toml` authenticates on its own** (ADR-0021 clause 26): an operator's
  Basic password is kept as an Argon2id hash of at least the OWASP minimum, and a value in clear is
  refused at startup without being echoed. The Server offers no credential (ADR-0014).
- **An audit record of every security decision** (ADR-0022): admissions and refusals, enrolment,
  issuance, revocation, operator acts and package outcomes, one hash-chained line each; no
  admission without its record, refusals aggregated per peer before they are queued and kept to
  half the queue so they cannot crowd out any other record, and no `Authorization` value in any
  line, not even as a hash.
- **Certificates live 30 days by default** (ADR-0021 clause 9) and are renewed at two thirds of
  that; a test with lives of seconds watches three generations each replace the one before it
  expires (`certificate_renewal_e2e.rs`). A soak on real hosts before a rollout is the operator's.
- **An offered move to another TLS endpoint needs the Client's own CA file** (ADR-0014 clause 5),
  so a Server cannot move the fleet to a host only a public CA vouches for.
- **The Supervisor Endpoint admits only the process its Supervisor started** (ADR-0015): a token
  made at every start, handed to the process in its environment, asked of every connection.
- **A package signature covers the Agent type, the version and the hash** (ADR-0026): a signed
  artifact installs as its own type's program at its own version and nowhere else. **A Package
  version is SemVer** (ADR-0043): the Server creates no other, `package sign` signs no other, and a
  Supervisor takes no other. A Supervisor refuses a package whose version SemVer orders below the
  one its installed-package record names, or below the **high-water mark** of its Agent type — the
  highest version this Client has installed for the type, kept in
  `<state_dir>/package-high-water.json`, which no purge of a Supervisor's directory reaches; a file
  that cannot be read refuses every Supervisor package. Residual: an old build the operator signed
  under a version above the current mark, such as a long-ago pre-release of a later version, is
  still taken; only a signed floor would close that. The Client's own self-update refuses an
  offered version that is not SemVer, and one SemVer orders below the running build.
- `TLSConnectionSettings`, `ProxyConnectionSettings` and offered `headers` refused on merit, so a
  Server cannot command a Client to weaken its own verification or plant a header on every
  connection of the fleet (ADR-0014 clause 8,
  [`CONFORMANCE.md`](CONFORMANCE.md#mutual-tls-and-the-two-fields-still-refused)).

### Where each bound applies today

The list above is per mechanism; this is the same state per **surface**, since a rule that holds on
one listener and not on its neighbour is the failure mode worth seeing at a glance. ✅ in force,
⚠️ partial, ❌ absent.

- **Every listener below that serves OpAMP or the REST API** (`opamp::server::listen`, ADR-0013
  clause 14): ✅ a body or WebSocket message that has begun delivers 64 KiB in every 60 s or is cut
  off — `408`, or a `1008` close — while nothing has a deadline and an idle connection is left alone.
- **Agent plane** — `127.0.0.1:4320` until an operator publishes it (ADR-0013).
  - ✅ TLS handshake ≤ 10 s · ✅ headers ≤ 30 s (HTTP/1) · ✅ message size, in both directions ·
    ✅ gzip bounded *after* decompression · ✅ Admission by client certificate
  - ✅ connections capped (`max_connections`) · ✅ HTTP/2 streams and pings bounded
  - ✅ failed admissions throttled per address · ✅ admitted members rate-limited per host, and
    per Agent within a Gateway's aggregate (ADR-0013), an enrolment through a Gateway per bootstrap
    certificate (ADR-0039)
- **Operator plane** — `127.0.0.1:4321` until an operator publishes it (ADR-0013).
  - ✅ TLS handshake ≤ 10 s · ✅ headers ≤ 30 s · ✅ Basic over the whole plane, required beyond the loopback (ADR-0021) ·
    ✅ Fetch-Metadata CSRF guard on the body-less `POST` routes, by `Origin` where a browser sends
    no Fetch Metadata
  - ✅ a Content-Security-Policy that names the UI's inline scripts by hash and forbids framing ·
    ✅ `nosniff`, `no-referrer` and HSTS (`max-age=31536000`, no subdomains) on every response ·
    ✅ `/api/v1` answers never cached
  - ✅ the package upload has no deadline, but is held to the floor above, and its size to
    `max_package_size_bytes` and the whole store, uploads still arriving included, to
    `max_total_package_bytes` · ✅ capped, HTTP/2-bounded and throttled as above
- **Client → Server**, outbound (`opamp::client::connection`, ADR-0010).
  - ✅ request timeout 30 s on the polling transport · ✅ redirects refused outright ·
    ✅ reconnect backoff · ✅ message size in both directions
- **Gateway endpoint** — the Client serving OpAMP downstream (ADR-0015).
  - ✅ TLS handshake ≤ 10 s · ✅ headers ≤ 30 s (HTTP/1), from the listener every OpAMP endpoint
    is served on (ADR-0010) · ✅ message size, gzip after decompression, per-hop exchange timeout,
    `max_carried_agents` · ✅ no downstream `Authorization` forwarded; every upstream connection
    carries the Gateway's own certificate alone (ADR-0015)
  - ✅ a downstream peer that never finishes its headers after the handshake is hung up on
    ([`gateway_tls.rs`](../crates/fleet-agent/tests/gateway_tls.rs))
  - ✅ an enrolling peer — a bootstrap certificate, with `bootstrap_ca_file` — is refused a
    WebSocket and anything but one enrolment request `403`, binds nothing, and its place upstream
    goes with its exchange (ADR-0039)
  - ✅ an Agent's place in the upstream pool is released when the socket that carried it goes ·
    ⚠️ a plain-HTTP Agent's place is released only when its upstream connection drops, so a peer
    that polls under ever new `instance_uid`s grows the pool's assignments until then
- **Supervisor Endpoint** — loopback, one Managed Process (`supervisor/endpoint.rs`).
  - ✅ headers ≤ 30 s (HTTP/1), from the same listener · ✅ connections served concurrently ·
    ✅ message size in both directions
  - ✅ a half-finished upgrade is dropped while other connections are served, and the endpoint
    serves the next one afterwards
    ([`endpoint.rs`](../crates/fleet-agent/src/supervisor/endpoint.rs))

What follows is therefore not "make it secure" but two narrower things: **close the windows during
which a revoked certificate still works**, and **shrink the surface that sits beside the protocol**.

**Status of each measure below:** 🔴 not taken · 🟡 partly in force · 🟢 in force. Nothing is 🟢 here by
construction: a measure that reaches it moves up into [What already holds](#what-already-holds), the
way the connection-setup bound did when ADR-0013 took it. The ✅/⚠️/❌ marks in that section are the
same three states seen per *surface* rather than per measure.

## The channels that put code on the host

Remote configuration and package delivery are the paths by which the Server causes code to run on an
Agent's host. They deserve at least as much attention as the transport, and arguably more.

**What a remote configuration can and cannot cause on a host.** The Server reaches a Client host
through seven channels. It **can** write any files into a Supervisor's own `config/` directory and
restart its process, except for a Supervisor the host lists in `[supervisors]
remote_config_disabled`, whose Agent takes no remote configuration and whose delivered block must
repeat the one it runs (ADR-0017); add, change, purge and restart Supervisors of the compiled-in
kinds, each running a program from its own `program/` directory, except on a host that sets
`[supervisors] server_manages_set = false`, whose own Agent takes no Supervisor set (ADR-0017);
install any package signed with the operator's key into a Supervisor, and a newer signed Client build into the Client itself; move the
fleet to another TLS endpoint its trust accepts, install a certificate for
the key the Client generated, and set its telemetry destinations; restart a Managed Process; and
re-key an Agent's `instance_uid`. What an Agent's own configuration language allows — a Telegraf
`inputs.exec`, an Icinga `CheckCommand` — it allows as the process's account; that is the product.
The switch of ADR-0017 binds a name: while the Server manages the set, it can remove a listed
Supervisor and deliver the same agent under a name that is not listed, whose configuration is then
the Server's again. A host that also sets `server_manages_set = false` closes that: the Server
can neither remove the listed Supervisor nor add another (ADR-0017). Both keys hold against the
Server only while every Supervisor whose configuration language can run commands as the Client's
account — a Telegraf `inputs.exec`, an Icinga `CheckCommand`, the configuration a `command`
kind's program reads — is in `remote_config_disabled`; otherwise the Server can configure such a
Supervisor to rewrite `supervisor.toml`, and the keys change at the next start. A signed Client
build can still replace the program that reads them where `[packages] self_update` consents
(ADR-0018).

It **cannot**: write outside a Supervisor's `config/` (entry names are sanitized), or store there an
entry Windows cannot hold or two entries in one file (such an offer is refused); name a program
outside a Supervisor's `program/`, by absolute, rooted or escaping path, or a wrapped kind's program
at all; start a kind that is not compiled in; change any key of `supervisor.toml` but the
`[[supervisor]]` array — not the endpoint, `state_dir`, `[tls]`, the verification key or
`self_update`; apply a set with one bad block; purge outside the Supervisors'
root; install anything unsigned, from another origin than its own Server, or with an archive member that climbs
out; serve a host from its download route an artifact that is not offered to an Agent the host
speaks for, or serve a host behind a Gateway an artifact the Gateway did not relay to one of
that host's Agents, or forward a report for an `instance_uid` bound to another host behind a
Gateway — within the residual that the Gateway binds an `instance_uid` to the host of its first
report since the Gateway started (ADR-0039); downgrade the Client or install a program that is not the Client as the Client; install a
Supervisor package below the highest version this Client installed for its type, or under a version
that is not SemVer — not by purging the Supervisor and adding it back under any name (ADR-0043); switch to
plaintext, on the loopback neither, or keep a persisted move to plaintext that `supervisor.toml` does not name; weaken TLS verification, set a proxy or plant a header; hand the Client a private
key. Each of these is enforced in the code, and most by a test.

## Verifying a measure is in force

A hardening measure is the kind of change that looks done as soon as code exists, because the thing
it prevents was already not happening in any test. So each one below states the observable that
proves it — and the rule for all of them is the project's own ([`AGENTS.md` §5](../AGENTS.md#5-quality-bar--definition-of-done)): **the check
must fail before the change and pass after**. A test that passes today verifies nothing about a
measure that has not been taken.

Each open measure adds a row here — its number, and the observable that proves it — and leaves
with the measure when it moves up into [What already holds](#what-already-holds).
