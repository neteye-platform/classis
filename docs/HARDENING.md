# Hardening the Client–Server Link

**This document is a backlog, not a decision.** Everything below is a
_candidate_ measure for hardening the connection between the Client and the
Server: written down so it can be picked up deliberately later instead of being
rediscovered, and ordered so the cheap wins are not buried under the expensive
ones. Nothing here is binding. Each measure states what it would cost and what
still has to be established, and the ones that constrain the architecture say so
and name the key decision they would change.

Every measure is stated here in full, so this document can be read on its own.
None below is a conformance question: the Baseline requires none of it.

## Scope

The link this document is about is **Client ↔ Server**. In this project's
vocabulary a Supervisor lives _inside_ the Client
([`crates/classis-agent/src/supervisor/`](../crates/classis-agent/src/supervisor/))
and does not speak to the Server itself — the Client carries every Supervisor's
Agent over its one connection. Where other OpAMP material says "Supervisor ↔
Server", this is the link it means.

One adjacent surface is in scope because it terminates on the same host and
carries the same protocol: the **Supervisor Endpoint**, the loopback WebSocket
each Supervisor serves for a Managed Process's `opampextension`
([`endpoint.rs`](../crates/classis-agent/src/supervisor/endpoint.rs)), which
admits only the process its Supervisor started.

Out of scope, and deliberately so: **authorization and multi-tenancy**, which
the specification names as non-goals, with one bound on the Agent plane: a host
receives from the Server only the configurations and packages released to an
Agent it speaks for. The boundary is worth stating precisely because
the host binding runs close to it — _which Agent is
speaking_, and so _what its host may receive from the Server_, is authentication
and belongs here; _what that Agent is allowed to do_ beyond that is
authorization and does not.

## What already holds

Stated first so the list below is not read as a list of absences. On this link
the project already has:

- TLS 1.3 on both transports between the Client and the reverse proxy in front
  of the Server, with a private CA supported on the Client; the Server speaks
  plain HTTP, to the proxy alone.
- **One proof on the Agent plane, required on every request**
  (`transport::admit`): an opaque bearer access token, whose SHA-256 is a
  client's one active token and which has not expired. No configuration admits
  a peer without one. A host gets its token by enrolling with its Space's key
  and then with its client credentials at `/v1/token`; the Server keeps only the
  hashes of the secret and the token. `server.toml` refuses an `[auth]` section
  and a credential key in `[connection_offer]` at startup. The Client sends the
  token on every OpAMP exchange on both transports and on every download, a
  header a package offers cannot replace it, and its own telemetry carries it
  only to a destination at the Server's origin. The Agent plane asks no peer for
  a certificate.
- Basic authentication over the **whole** Operator plane, the UI included
  (`[rest.auth]`), required beyond the loopback, on a listener that is
  loopback until an operator publishes it. A verification that
  succeeded is remembered by the SHA-256 of the header and compared in constant
  time (`credentials.rs`).
- **Credentials with no value to steal on the Server, and no certificate
  authority**: client secrets and access tokens are 256 random bits
  and the Server stores only their SHA-256; it issues no certificate and
  holds no CA key for the fleet. Residual: a Space's enrolment key is kept
  whole on the Server's disk, so it can be shown again, and whoever reads the
  data directory or a backup of it can enrol hosts until the key is rotated.
- Message size limits enforced in both directions on both transports, and at the
  Supervisor Endpoint.
- **TLS 1.3 alone, on every connection of both ends**: the
  process-wide provider carries the three TLS 1.3 suites and no other, every
  configuration pins TLS 1.3, and a peer offering only TLS 1.2 fails the
  handshake. Plaintext is accepted on `127.0.0.1` and `::1` alone and refused at
  startup anywhere else.
- **Enrolment by key, then a token on every request**: a host
  registers with its Space's reusable key at `/v1/enrol` (RFC 7591) and obtains
  its token at `/v1/token` (RFC 6749 §4.4, HTTP Basic). A key that was rotated
  enrols nothing, and one rotated between the check and the store refuses the
  registration. An absent or unsupported credential is answered `401` with
  `Bearer realm="fleet"`, a wrong, replaced or expired token `401` with
  `error="invalid_token"`, and a malformed request `400` with
  `error="invalid_request"`. Refused authentications on `/v1/enrol`,
  `/v1/token`, `/v1/opamp` and the download are counted per address in one
  table, and an address past `max_failures` is answered `429` before anything
  else is checked, as on the Operator plane, which has its own table. The two
  OAuth routes read at most 8 KiB of body.
- **Nothing installed unsigned, and downloads only from the Client's own
  Server**: every package is verified up to the Package Roots compiled into the
  Client, the Server offers no entry that carries no signature, and every
  download hop is held to `https://` and the Client's own Server origin before a
  request is sent. Every artifact is uploaded: the Server sends no request for a
  package anywhere and holds no source credential.
- **A connection cap per plane and bounded HTTP/2**: `max_connections` closes a
  connection past the cap on accept, while the held ones keep working; HTTP/2
  allows 100 concurrent streams per connection and drops a peer that leaves a
  ping unanswered.
- **Connection setup bounded on both of the Server's planes**: a peer has 30
  seconds to send its request line and headers before it is hung up on —
  enforced below every other limit in this list, because it applies before a
  request exists and therefore before admission ever runs.
- Package content hashed and verified up to the compiled-in Package Roots
  always, with no unsigned posture and no setting: for an offer without a
  signature, nothing is downloaded. Archive members are validated before
  anything is written.
- **A replaced token ends its sessions**: a client has one active token, and
  issuing a new one overwrites the hash of the old, which is revoked by that.
  The Server closes exactly the WebSocket sessions admitted with the old token
  with `1008`; plain HTTP and the download check the token on every request, so
  an expired or replaced token is refused at the next one. An open WebSocket
  session outlives its token's expiry and meets it at its next connection. A
  token that never expires is the default (`token_lifetime_secs = 0`).
- **A token names its host, and a host speaks only for its own Agents**: the
  Server takes the host from the token of the request, never from the report. A
  report for an `instance_uid` recorded under another client is refused
  outright, and one client owns at most 256 `instance_uid`s.
- **Key material and configuration readable by their owner alone**: on Unix
  `state.json`, which holds the client secret and the access token, the stored
  connection settings and `supervisor.toml` are written `0600` in `0700`
  directories, a state directory `0710` that the process account's group only
  passes through where one is registered. On Windows a system-scope install
  gives the default data root under `%ProgramData%` to the Administrators,
  whoever created it, drops every right in it that the install does not grant,
  cuts it off from the read right every local user inherits there, and leaves it
  to LocalSystem, the Administrators and the service account. A data root named
  with `--root` or `--data-root`, a state directory outside the data root, and a
  Supervisors' root outside both that the install creates beneath the layout
  root, is only cut off from inherited rights and left to the same accounts; a
  Supervisors' root that already exists, or that lies outside the data root, the
  layout root and the state directory, is left as it is, with a warning, and
  protecting it is the operator's. A local user acting while the install runs is
  not covered.
- **A Managed Process can be kept from the Client's key and program**: where the
  operator registers a process account, every program a Supervisor starts — the
  Managed Process, its version probe, a package's preflight — runs under it,
  started by a second service over a Unix socket or named pipe that admits the
  Client's account alone. It reads its own `program/` and `config/` and writes
  its data directories, and nothing else of the Client's: not `state.json`,
  `supervisor.toml`, the logs or the environment, and no program it runs. On
  Windows it holds `SeChangeNotifyPrivilege` alone, so no
  `SeImpersonatePrivilege`, and runs in a job that ends with the Client's
  connection. An install that drops or changes the account withdraws what the
  former one was granted. Residual: the separation is opt-in, and a host without
  a process account runs every Managed Process as the Client; all Managed
  Processes share the one account, so they read one another's `config/`.
- **A Managed Process cannot take the second service's place by its socket or
  pipe, nor, on Linux, reach into it once it has marked itself**: before the
  Client writes anything on a new connection it reads the process at the other
  end — `SO_PEERPIDFD` on Linux, `LOCAL_PEERPID` on macOS,
  `GetNamedPipeServerProcessId` on Windows — and accepts it only where systemd,
  launchd or the SCM runs that process as the second service. A Managed Process
  that replaces the socket or creates an instance of the pipe hears nothing: the
  Client closes the connection, logs an error naming the socket or pipe and the
  process, and waits for the second service as for one that is away. On Linux
  the second service's program marks itself not dumpable before it parses its
  command line or sets up its log, so from then on no process of the process
  account without `CAP_SYS_PTRACE` attaches to it, reads or writes its memory or
  takes its descriptors, whatever `kernel.yama.ptrace_scope` says, and it does
  not listen while it is traced. Residual: on Windows a Managed Process can open
  the second service's process with the rights its account holds on it,
  duplicate its pipe handle or run code in it; on Linux where Yama is absent or
  `ptrace_scope` is 0, a Managed Process can kill the second service and attach
  to the one its service manager starts again between its `execve` and the mark,
  and as its tracer make it read a `TracerPid` of 0; on Linux before 6.5, on
  macOS and on Windows a process that listened and ended can leave its id to the
  second service, which the Client does not tell apart; a Managed Process can
  remove or replace the socket, and the Client then finds the second service
  away; where the service manager cannot be asked — no system bus, a `launchctl
  print` that fails — no Managed Process starts until it answers again.
- **An install acts only on directories an administrator named or its roots
  hold**: `supervisor.toml` belongs to the service's account, and `service
  install` and `service config` run as root or an Administrator. The state
  directory comes from `--state-dir`, else from the registration an earlier
  install wrote, and only then from the file, and from that only beneath the
  data root or the layout root. Beneath a root it is reached with no `..` and
  through no link or junction; anything else is refused before anything is
  written. A Supervisors' root the file places outside them is never created,
  restricted or handed over. The hand-over and the cut act on a link or junction
  itself on every platform.
- **A delivered Supervisor block reaches no further than the package
  signature**: no environment or arguments beyond what the running block has or
  the operator allowed, and no file outside its own `config/` directory. Under
  one rule — no variable that steers which code a program loads, no value
  pointing where the Server delivers unsigned files — the Client refuses the
  names and placeholders that rule covers, and further loader variables
  (`PATHEXT`, `COMSPEC`, `NODE_PATH`, `PYTHONHOME`, `PERLLIB`, `PERL5DB`,
  `RUBYLIB`) and new values that start with a path under the Supervisors' root.
- **A privileged install follows no link the service's account placed**:
  `service install` and `service config` run as root or an Administrator and
  write into the state directory and the layout root, which belong to the
  account. Each file there is read without following a link and written whole to
  a new name, then renamed over its own, so a link at the name is replaced and
  never written through. A state directory, `versions/` or version directory
  that is a link or junction is refused, and on Windows so is a data or layout
  root that is a reparse point; the data root is held open from the install's
  first write to its last. What `service config` re-owns is re-owned as the
  entry itself, and a file with a second hard link is skipped with a warning.
- **No credential in `server.toml` authenticates on its own**: an operator's
  Basic password is kept as an Argon2id hash of at least the OWASP minimum, and
  a value in clear is refused at startup without being echoed. The Server offers
  no credential.
- **A log event for every security decision**: admissions and
  refusals, enrolment, token issuance, session ends, operator acts and package
  outcomes, one structured event each on the Server's log, and no key, client
  secret or token in any event, not even as a hash. What a peer can repeat at
  will — refusals before admission, throttles, polls — is logged at `debug`, so
  a flood stays out of the default log. The Server keeps no audit record:
  retention and integrity are whatever collects the log, and an edited or
  removed line is not detectable.
- **A token is replaced only when the Server refuses it**:
  the Client keeps no expiry and never renews ahead of time, so its own renewal
  never cuts an open session; only a `401` whose Bearer challenge says
  `invalid_token` makes it ask `/v1/token` again with its client secret, and a
  bare `401`, `invalid_request` or `invalid_client` does not. The tests are
  `crates/classis-server/tests/enrolment.rs` and
  `crates/classis-agent/tests/enrolment_e2e.rs`.
- **An offered move to another TLS endpoint needs the Client's own CA file**, so
  a Server cannot move the fleet to a host only a public CA vouches for.
- **The Supervisor Endpoint admits only the process its Supervisor started**: a
  token made at every start, handed to the process in its environment, asked of
  every connection.
- **A package signature covers the Agent type, the version and the hash**: a
  signed artifact installs as its own type's program at its own version and
  nowhere else. **A Package version is SemVer**: the Server creates no other,
  `package sign` signs no other, and a Supervisor takes no other. A Supervisor
  refuses a package whose version SemVer orders below the one its
  installed-package record names, or below the **high-water mark** of its Agent
  type — the highest version this Client has installed for the type, kept in
  `<state_dir>/package-high-water.json`, which no purge of a Supervisor's
  directory reaches; a file that cannot be read refuses every Supervisor
  package. Residual: an old build the operator signed under a version above the
  current mark, such as a long-ago pre-release of a later version, is still
  taken; only a signed floor would close that. The Client's own self-update
  refuses an offered version that is not SemVer, and one SemVer orders below the
  running build.
- `TLSConnectionSettings`, `ProxyConnectionSettings` and offered `headers`
  refused on merit, so a Server cannot command a Client to weaken its own
  verification or plant a header on every connection of the fleet
  ([`CONFORMANCE.md`](CONFORMANCE.md#mutual-tls-and-the-two-fields-still-refused)).

### Where each bound applies today

The list above is per mechanism; this is the same state per **surface**, since a
rule that holds on one listener and not on its neighbour is the failure mode
worth seeing at a glance. ✅ in force, ⚠️ partial, ❌ absent.

- **Every listener below that serves OpAMP or the REST API**
  (`opamp::server::listen`): ✅ a body or WebSocket message
  that has begun delivers 64 KiB in every 60 s or is cut off — `408`, or a
  `1008` close — while nothing has a deadline and an idle connection is left
  alone.
- **Agent plane** — `127.0.0.1:4320` until an operator publishes it.
  - ✅ headers ≤ 30 s (HTTP/1) · ✅ message size, in both directions · ✅ gzip
    bounded _after_ decompression · ✅ Admission by bearer token · ✅
    `/v1/enrol` and `/v1/token` bodies ≤ 8 KiB
  - ✅ connections capped (`max_connections`) · ✅ HTTP/2 streams and pings
    bounded
  - ✅ failed admissions, enrolments and token requests throttled per address,
    the left-most `X-Forwarded-For` entry ·
    ✅ admitted hosts rate-limited per host, and a peer without one per address
- **Operator plane** — `127.0.0.1:4321` until an operator publishes it.
  - ✅ headers ≤ 30 s · ✅ Basic over the whole plane, required beyond the
    loopback · ✅ Fetch-Metadata CSRF guard on the body-less
    `POST` routes, by `Origin` where a browser sends no Fetch Metadata
  - ✅ a Content-Security-Policy that names the UI's inline scripts by hash and
    forbids framing · ✅ `nosniff`, `no-referrer` and HSTS (`max-age=31536000`,
    no subdomains) on every response · ✅ `/api/v1` answers never cached
  - ✅ the package upload has no deadline, but is held to the floor above, and
    its size to `max_package_size_bytes` and the whole store, uploads still
    arriving included, to `max_total_package_bytes` · ✅ capped, HTTP/2-bounded
    and throttled as above
- **Client → Server**, outbound (`opamp::client::connection`).
  - ✅ request timeout 30 s on the polling transport · ✅ redirects refused
    outright · ✅ reconnect backoff · ✅ message size in both directions
- **Supervisor Endpoint** — loopback, one Managed Process
  (`supervisor/endpoint.rs`).
  - ✅ headers ≤ 30 s (HTTP/1), from the same listener · ✅ connections served
    concurrently · ✅ message size in both directions
  - ✅ a half-finished upgrade is dropped while other connections are served, and
    the endpoint serves the next one afterwards
    ([`endpoint.rs`](../crates/classis-agent/src/supervisor/endpoint.rs))

What follows is therefore not "make it secure" but two narrower things: **close
the windows during which a leaked token still works**, and **shrink the
surface that sits beside the protocol**.

**Status of each measure below:** 🔴 not taken · 🟡 partly in force · 🟢 in force.
Nothing is 🟢 here by construction: a measure that reaches it moves up into [What
already holds](#what-already-holds), the way the connection-setup bound did when
it was taken. The ✅/⚠️/❌ marks in that section are the same three states seen
per _surface_ rather than per measure.

## The channels that put code on the host

Remote configuration and package delivery are the paths by which the Server
causes code to run on an Agent's host. They deserve at least as much attention
as the transport, and arguably more.

**What a remote configuration can and cannot cause on a host.** The Server
reaches a Client host through seven channels. It **can** write any files into a
Supervisor's own `config/` directory and restart its process, except for a
Supervisor the host lists in `[supervisors] remote_config_disabled`, whose Agent
takes no remote configuration and whose delivered block must repeat the one it
runs; add, change, purge and restart Supervisors of the compiled-in kinds, each
running a program from its own `program/` directory, except on a host that sets
`[supervisors] server_manages_set = false`, whose own Agent takes no Supervisor
set; install any package a Package Signer of the compiled-in Package Root signed
into a Supervisor, and a newer signed Client build into the Client itself; move
the fleet to another TLS endpoint its trust accepts, and set its telemetry
destinations; restart a Managed Process; and re-key an Agent's `instance_uid`.
What an Agent's own configuration language allows — a Telegraf `inputs.exec`, an
Icinga `CheckCommand` — it allows as the process's account; that is the product.
The `remote_config_disabled` list binds a name: while the Server manages the
set, it can remove a listed Supervisor and deliver the same agent under a name
that is not listed, whose configuration is then the Server's again. A host that
also sets `server_manages_set = false` closes that: the Server can neither
remove the listed Supervisor nor add another. Both keys hold against the Server
only while every Supervisor whose configuration language can run commands as the
Client's account — a Telegraf `inputs.exec`, an Icinga `CheckCommand`, the
configuration a `command` kind's program reads — is in `remote_config_disabled`;
otherwise the Server can configure such a Supervisor to rewrite
`supervisor.toml`, and the keys change at the next start. Where a process
account is registered, such a command runs under it, and it cannot write
`supervisor.toml`. A signed Client build can still replace the program that
reads them where `[packages] self_update` consents.

It **cannot**: write outside a Supervisor's `config/` (entry names are
sanitized), or store there an entry Windows cannot hold or two entries in one
file (such an offer is refused); name a program outside a Supervisor's
`program/`, by absolute, rooted or escaping path, or a wrapped kind's program at
all; start a kind that is not compiled in; change any key of `supervisor.toml`
but the `[[supervisor]]` array — not the endpoint, `state_dir`, `[tls]` or
`self_update`; apply a set with one bad block; purge outside the Supervisors'
root; install anything unsigned, from another origin than its own Server, or
with an archive member that climbs out; serve a host from its download route an
artifact that is not offered to an Agent the host speaks for; take an
`instance_uid` another host's token has reported; downgrade the Client or
install a program that is not the Client as the Client; install a Supervisor
package below the highest version this Client installed for its type, or under a
version that is not SemVer — not by purging the Supervisor and adding it back
under any name; switch to plaintext, on the loopback neither, or keep a
persisted move to plaintext that `supervisor.toml` does not name; weaken TLS
verification, set a proxy or plant a header, so it cannot replace the token the
Client sends. Each of these is enforced in the code, and most by a test.

## Verifying a measure is in force

A hardening measure is the kind of change that looks done as soon as code
exists, because the thing it prevents was already not happening in any test. So
each one below states the observable that proves it — and the rule for all of
them is the project's own
([`AGENTS.md` §5](../AGENTS.md#5-quality-bar--definition-of-done)): **the check
must fail before the change and pass after**. A test that passes today verifies
nothing about a measure that has not been taken.

Each open measure adds a row here — its number, and the observable that proves
it — and leaves with the measure when it moves up into
[What already holds](#what-already-holds).
