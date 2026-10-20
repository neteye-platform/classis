# The Server

[← User Manual](README.md) · [The Client →](client.md)

The Server is the control plane: it holds the configuration the fleet should run, tracks what every
Agent reports back, distributes software, and exposes all of it as an OpenAPI-described REST API. It
runs on Linux, as an ordinary foreground process — unlike the Client, it does not install itself as
a service.

- [What the Server does](#what-the-server-does)
- [Running it](#running-it)
- [Configuration reference](#configuration-reference)
- [Where the Server keeps its state](#where-the-server-keeps-its-state)
- [Upgrading to one data directory](#upgrading-to-one-data-directory)
- [Mutual TLS: proving who is on the connection](#mutual-tls-proving-who-is-on-the-connection)
- [Enrolment: a new host, approved by an operator](#enrolment-a-new-host-approved-by-an-operator)
- [Configurations: what the fleet runs](#configurations-what-the-fleet-runs)
- [Packages and Deployments: distributing software](#packages-and-deployments-distributing-software)
- [The REST API](#the-rest-api)
- [Authentication](#authentication)
- [Upgrading to admission by certificate alone](#upgrading-to-admission-by-certificate-alone)
- [TLS](#tls)
- [The fleet's own telemetry](#the-fleets-own-telemetry)
- [Moving the fleet: connection settings](#moving-the-fleet-connection-settings)
- [What the Server does not do](#what-the-server-does-not-do)

## What the Server does

- **Distributes Configurations and packages through Deployments — when you say so**: a
  Deployment's Selector aims, saving stores, an explicit rollout act of the Deployment releases,
  and every push is gated on a content hash so nothing the Agent already runs is sent again.
- **Tracks the fleet**: which Agents exist, what they report, whether they are connected, healthy,
  and in sync, which Deployment claims them and what it would release, and which packages they
  have installed.
- **Distributes packages**: versioned Sets of uploaded, signed artifacts, held by a Deployment
  beside its Configurations — released only by an explicit rollout act,
  and only ever forwards: a Package reaches an Agent when it is an upgrade over the version that
  Agent reports installed, never when it would move it back or leave it where it is.
- **Restarts a Managed Process on request** — an Agent backed by a Supervisor accepts a restart
  command.
- **Offers new connection settings**: a heartbeat interval or an entirely different endpoint,
  which each Agent verifies by connecting before it switches.
- **Admits an Agent on one proof**: a client certificate in the TLS handshake. It signs Agent
  certificates as a local CA, and enrols a new host only on an operator's approval.
- **Serves two listeners over TLS 1.3**: OpAMP over both transports and the package download on
  one, the REST API, the OpenAPI document and its docs page, and a rudimentary UI on the other.

## Running it

```console
$ server --config /etc/opamp/server.toml
$ server --version
```

| Flag | Meaning |
|---|---|
| `--config <path>` | The TOML configuration file. Defaults to `server.toml` in the working directory. A missing file means the defaults, and the defaults hold no `[tls]`, so the Server refuses to start and names `[tls]`. |
| `--version` | Print the version and exit — the full string, `1.2.3+<commit>` for a release and `1.2.3-dev+<commit>` for a build on the way to one. |

Any other argument prints usage and exits with status 2. Logging goes to stderr and is controlled by
the `RUST_LOG` environment variable (default `info`); everything else is in the configuration file.

Stopping the Server is `SIGTERM`/`Ctrl-C`. Configurations and packages are persisted to disk, so a
restart resumes with the same fleet state; Agents reconnect on their own.

The Server refuses to start without `[tls]` and `[tls] client_ca_file`, and the refusal names what
is missing. It also refuses an `[auth]` section, and a credential key in `[connection_offer]`: the
Agent plane admits by client certificate alone (see
[Upgrading to admission by certificate alone](#upgrading-to-admission-by-certificate-alone)). For
a fleet, `opamp-fleetctl pki init` makes every certificate the Server and a new host need
([Setting up a fleet](setup.md#1-make-the-certificates)); for a first run on one machine,
[`scripts/dev-pki.sh`](../../scripts/dev-pki.sh) makes a development set with it, and a
`server.toml` that uses it; the [quick start](README.md#quick-start-a-closed-loop-on-one-machine)
walks through it.

There are **two listeners, split by audience**: the one
the fleet talks to, and the one you talk to. Both serve TLS 1.3 and nothing older, with the same
certificate.

**The Agent plane** — `listen`, `127.0.0.1:4320` by default. Serving the fleet is one deliberate
line, `listen = "0.0.0.0:4320"`.

| Path | What it is |
|---|---|
| `/v1/opamp` | The OpAMP endpoint. `GET` upgrades to WebSocket, `POST` is the plain-HTTP exchange — the same path serves both. |
| `/api/v1/packages/{agent_type}/{version}/file` | An artifact's bytes: the one `/api/v1` route that belongs to the Agents, because the `download_url` in a package offer is a path the Client resolves against *its own* endpoint. It sits outside the Operator plane's `[rest.auth]` and behind the same TLS handshake as `/v1/opamp`, so a downloading Client presents its client certificate. A certificate from the client CA is required; a bootstrap certificate is answered `401`. A host is served only the artifact offered to one of its own Agents, and every other request is answered `404` ([A host fetches only what its Agents are offered](#a-host-fetches-only-what-its-agents-are-offered)). |

The Agent plane asks every peer for a client certificate in the TLS handshake. A peer without one
fails the handshake and reaches no route (see
[Mutual TLS](#mutual-tls-proving-who-is-on-the-connection)).

**The Operator plane** — `[rest] listen`, `127.0.0.1:4321` by default:

| Path | What it is |
|---|---|
| `/api/v1/…` | The REST API. |
| `/api/v1/openapi.json` | The OpenAPI document — the contract to generate a client from. It describes this plane, so the artifact download above is not in it. |
| `/api/v1/docs` | Interactive API documentation (Redoc, vendored and served from this origin, so it works offline). |
| `/` | The bundled UI: one embedded page, no frontend toolchain. It is deliberately rudimentary — the API is the product. |
| `/ui.css`, `/ui-carbon.css`, `/ui-quiet.css` | The bundled UI's three looks, embedded beside the page; its style combo chooses between them. |

The Agent plane has no credential; the Operator plane has one of its own,
[`[rest.auth]`](#the-operator-plane-restauth). This port carries the authority to reconfigure and
re-package the whole fleet, so its default address is the **loopback**. There `[rest.auth]` is
optional, and the address is what protects the plane. Reach it from another host through an SSH
tunnel (`ssh -L 4321:127.0.0.1:4321 <server-host>`), or publish it deliberately with
`[rest] listen = "0.0.0.0:4321"`. Off the loopback `[rest.auth]` is required, and a Server without
it is refused at startup with a message naming both keys.

Each plane holds a bounded number of connections: `max_connections` for the Agent plane and
`[rest] max_connections` for the Operator plane. A connection past the cap is closed on accept,
before the TLS handshake, and the connections already held keep working. See
[Bounds on every listener](#bounds-on-every-listener).

## Configuration reference

The full annotated example is [`config/server.toml`](../../config/server.toml). Every key is shown
below with its default. `[tls]` with its `client_ca_file` is required; every other key is
optional. An unknown key fails startup rather than being ignored.

### Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | `"127.0.0.1:4320"` | The **Agent plane**, as `address:port`: the OpAMP endpoint and the package downloads. `4320` is the protocol's default port. Serve the fleet with `"0.0.0.0:4320"`. |
| `max_connections` | `10000` | The connections the Agent plane holds at once. A connection past it is closed on accept. Raise it together with the process's file-descriptor limit for a larger fleet. `0` is refused at startup. |
| `data_dir` | `"fleet-data"` | Where the Server keeps **all** of its state, one directory per domain: see [Where the Server keeps its state](#where-the-server-keeps-its-state). Created owner-only when missing. `config_dir` and `packages_dir` are gone: a file naming either fails startup and names `server migrate` ([Upgrading to one data directory](#upgrading-to-one-data-directory)). |
| `max_message_size_bytes` | `67108864` (64 MiB) | The largest OpAMP message accepted or sent, in either direction and on either transport. The protocol requires a limit and recommends this value; a fleet of status reports needs far less. An oversized HTTP request is answered `413`, an oversized WebSocket message closes the connection with `1009`. A request or message that has begun and delivers less than 64 KiB in a minute is answered `408`, or closes its connection with `1008`. |
| `max_package_size_bytes` | `1073741824` (1 GiB) | The largest artifact the package-upload route accepts. A package is a program, not a message — an `otelcol-contrib` binary is a few hundred megabytes — so this bound is far larger, and it applies to that one route. The upload has no deadline, but like every request body it must deliver 64 KiB in each minute once it has begun, or it is answered `408`. |
| `max_total_package_bytes` | `17179869184` (16 GiB) | The total size of all stored artifacts before a new upload is refused `507`. Where `max_package_size_bytes` bounds one artifact, this bounds the whole store, so no caller fills the disk by uploading many artifacts under distinct names. Identical bytes are stored once and counted once. `0` is refused at startup. |
| `max_agents` | `100000` | The most Agent records the fleet holds at once. A report bearing a **new** `instance_uid` past this ceiling is answered `Unavailable` rather than admitted, so an admitted peer minting fresh self-asserted UIDs cannot exhaust memory and disk; Agents already known keep reporting. The defence against an anonymous flood is [admission](#authentication) by client certificate; this is the backstop behind it. `0` is refused at startup. |
| `stale_after_secs` | `90` | How long an Agent that declares `ReportsHeartbeat` may be silent before the fleet view marks it **stale**. Ignored when `[connection_offer]` names a heartbeat interval — then the budget is three of those. Only heartbeating Agents can go stale: one that promised no periodic report is never late. |

### `[rest]`

The Operator plane's listener. Absent means the default.

```toml
[rest]
listen = "127.0.0.1:4321"   # "0.0.0.0:4321" publishes the plane, and then needs [rest.auth]
max_connections = 256
```

| Key | Default | Meaning |
|---|---|---|
| `listen` | `"127.0.0.1:4321"` | Where the REST API, the API docs, and the UI are served, over the TLS of `[rest.tls]`, or of `[tls]` without it. It must differ from `listen` above — two equal addresses are refused at startup by name, rather than surfacing later as *address already in use*. An address other than `127.0.0.1` or `::1` requires `[rest.auth]`. |
| `max_connections` | `256` | The connections the Operator plane holds at once. `0` is refused at startup. |

#### `[rest.auth]`

Basic authentication over that whole plane — see
[Authentication](#the-operator-plane-restauth). Optional on a loopback `listen`, required on any
other.

```toml
[rest.auth.basic_users]
fleet-admin = "$argon2id$v=19$m=19456,t=2,p=1$…"
```

| Key | Default | Meaning |
|---|---|---|
| `basic_users` | *(empty)* | Accepted Basic credentials, `user = "<Argon2id hash>"` — see [Credentials are kept as hashes](#credentials-are-kept-as-hashes). A section without one, or an entry that is not such a hash, fails startup. |

#### `[rest.tls]`

Optional. The certificate and key that plane serves in place of `[tls]`'s, typically from your
organization's PKI so that its browsers trust the UI as they are — see
[The UI's own certificate](setup.md#the-uis-own-certificate). The Agent plane keeps `[tls]`'s.

```toml
[rest.tls]
cert_file = "ui.pem"
key_file = "ui-key.pem"
```

| Key | Default | Meaning |
|---|---|---|
| `cert_file` | — | Required. PEM chain, the leaf first and any intermediates after it. |
| `key_file` | — | Required. PEM private key of the leaf. A key that does not match the certificate refuses the start, naming both files. |

Nothing else belongs in the section — a `client_ca_file` is refused, since this plane asks for no
client certificate. A new pair takes effect when the Server restarts; `server pki status` lists
it, and the running Server warns before it ends.

### `[packages]`

Optional. The operator's public package-signing key, against which the Server checks every entry's
signature — as feedback, never as a gate.

```toml
[packages]
verification_key = "<hex-encoded Ed25519 public key>"
```

| Key | Default | Meaning |
|---|---|---|
| `verification_key` | unset | The hex-encoded Ed25519 public key — the same value as the Clients' `[packages] verification_key`, as `opamp-fleetctl package keygen` prints it. With it, each entry's signature is checked when it is written and when the store is loaded, and reported `valid` or `invalid`; without it, `unchecked`. An `invalid` signature is stored and offered all the same: each Client's own check decides what is installed. A key that is not hex, or not 32 bytes, fails startup naming it. |

### `[tls]`

Required. The Agent plane serves HTTPS and WSS in TLS 1.3 with this certificate and key, and so
does the Operator plane unless [`[rest.tls]`](#resttls) names its own. A
Server without the section is refused at startup with a message naming it. `client_ca_file` is
required too. It belongs to the Agent plane alone, which asks every peer for a client certificate
in the handshake (see [Mutual TLS](#mutual-tls-proving-who-is-on-the-connection)).

```toml
[tls]
cert_file = "cert.pem"
key_file = "key.pem"
client_ca_file = "client-ca.pem"   # the CA every Agent's certificate chains to
```

### `[telemetry_offer]`

Optional. Where Agents send their own telemetry — see
[The fleet's own telemetry](#the-fleets-own-telemetry). At least one endpoint is required if the
section is present.

```toml
[telemetry_offer]
metrics_endpoint = "https://collector.example:4318/v1/metrics"
[telemetry_offer.headers]
Authorization = "Bearer a-telemetry-token"
```

### `[client_ca]`

Optional. Present makes the Server a local CA that signs Agent certificate requests — see
[Issuing certificates](#issuing-certificates-the-csr-flow).

```toml
[client_ca]
cert_file = "client-ca.pem"
key_file = "client-ca-key.pem"
validity_days = 30
```

Without it, every host holds a certificate an operator provisioned, and such a certificate is
served an uploaded artifact only when it names its host as a URI SAN,
`urn:opamp-fleet:host:<id>`. A certificate that names no host fetches nothing from the download
route. A Server started without `[client_ca]` says so once at startup.

### `[enrolment]`

Optional. Present lets a new host enrol with a bootstrap certificate from this CA — see
[Enrolment](#enrolment-a-new-host-approved-by-an-operator). It needs `[client_ca]`, which signs
the approved request.

```toml
[enrolment]
bootstrap_ca_file = "bootstrap-ca.pem"
bootstrap_ca_key_file = "bootstrap-ca-key.pem"   # optional: the Server issues bootstrap certificates
max_pending_per_bootstrap = 256                  # optional: requests of one bootstrap certificate
```

`bootstrap_ca_key_file` is the CA's key, PKCS#8 PEM. With it the Server issues bootstrap
certificates on request ([Bootstrap certificates](#bootstrap-certificates-issued-by-the-server));
without it, hosts enrol with bootstrap certificates made elsewhere from the same CA. A key that is
not the CA's, or that is the client CA's, is refused at startup.

`max_pending_per_bootstrap` is the most requests of one bootstrap certificate, by its issuer and
serial, the pending queue holds at once: 256 by default, a quarter of the queue, from 1 to 1024.
Anything else fails startup naming the key. Raise it when one bootstrap certificate enrols more
than 256 hosts in one window and you would rather not approve them in batches.

### `[admission_throttle]`

Optional; absent means the defaults shown. See
[Repeated failures are throttled](#repeated-failures-are-throttled).

```toml
[admission_throttle]
max_failures = 10
window_secs = 60
backoff_secs = 300
```

### `[agent_rate_limit]`

Optional; absent means the defaults shown. See
[How often a member may be heard](#how-often-a-member-may-be-heard).

```toml
[agent_rate_limit]
messages_per_sec = 10
burst = 300
gateway_messages_per_sec = 500
gateway_burst = 10000
```

### `[connection_offer]`

See [Moving the fleet](#moving-the-fleet-connection-settings). Either key or both is valid, but
not an empty section. The `endpoint` is `wss://` or `https://`; a `ws://` or `http://` endpoint
is refused at startup, on the loopback too. The section carries no credential: `bearer_token_file`, `username`,
`password_file`, `bearer_token` and `password` are each refused at startup by name.

```toml
[connection_offer]
heartbeat_interval_secs = 30
endpoint = "wss://fleet.example:4320/v1/opamp"
```


## Where the Server keeps its state

Everything the Server knows survives a restart under one directory, `data_dir`, in a fixed layout:

| Path | One file per | Holds |
|---|---|---|
| `configurations/<name>.json` | Configuration | Its saved revision and every revision still rolled out somewhere |
| `deployments/<name>.json` | Deployment | Its Selector, its Packages and its Configurations |
| `packages/<agent type>@<version>.json` | Package | Its identity and entries, each naming its artifact by SHA-256 and carrying its signature |
| `blobs/<sha256>` | artifact | The bytes, named by their SHA-256 — identical bytes are stored once |
| `agents/<instance_uid>.json` | Agent | What it reported, its assignment, its labels |
| `hosts/<host>.json` | Host | What its certificate says, and which Agents it speaks for |
| `certificates/<issuer>-<serial>.json` | certificate | The register of what the client CA signed |
| `revocations.json` | — | The revocation list |
| `bootstrap/<issuer>-<serial>.json`, `.p12` | bootstrap certificate | Its record, and its PKCS#12 file when one was made |
| `enrolment.json` | — | The enrolment window and its pending requests |
| `audit/audit-<first seq>.jsonl` | audit file | The audit record |

`<issuer>` is the first 16 hex characters of the SHA-256 of the issuer's DER-encoded name, and
`<serial>` the certificate's serial in lowercase hex. A Host whose name holds a character outside
letters, digits, `.`, `_` and `-` has it written as `%XX` in its file name.

- **Owner-only.** The Server creates `data_dir` and every directory in it `0700` and writes every
  file `0600`: an Agent's reported configuration may hold credentials, and nothing here is another
  local user's business. The Server ships for Linux; built for Windows it sets no ACL, so give
  `data_dir` one that admits only the Server's account and the administrators.
- **One step per write.** Every record is written to a temporary file beside it and renamed into
  place, so a crash leaves the old document or the new one. The register, the revocation list,
  the Hosts, the bootstrap records, the enrolment window and the audit reach the disk before the
  decision they answer is. A temporary file a crash left behind is removed at the next start.
- **Nothing else is read.** A file or directory the layout does not name, a file that does not
  parse, or one whose name disagrees with what it holds stops the start, naming the path — a store
  that merely looked empty would be worse. Every artifact is hashed again at startup, and an artifact
  no Package entry names is deleted then.
- **Backup** is a copy of `data_dir` taken while the Server is stopped; restoring it is putting the
  copy back. A copy taken while it runs may hold an Agent record or an audit line mid-write.

## Upgrading to one data directory

A Server before 0.5.5 kept its state in two directories, `config_dir` (default `fleet-configs`) and
`packages_dir` (default `fleet-packages`). This Server reads neither: a `server.toml` naming either
key stops it at startup. `server migrate` moves an installation once, offline:

1. **Stop the Server.** The migration copies files; a Server still writing them would be copied
   half-way. The older Server takes no lock the migration could test, so this step is yours.
2. **Run the migration**, naming the two old directories and a new, empty one — it refuses a
   `data_dir` that is not empty:

   ```text
   $ server migrate --config-dir /var/lib/opamp-fleet-server/configs \
       --packages-dir /var/lib/opamp-fleet-server/packages \
       --data-dir /var/lib/opamp-fleet-server/data
   ```

   It copies and never moves: the old directories stay as they were, as your backup. It prints one
   line per thing it carried, dropped or listed:

   - **Trust data** — the certificate register, the revocation list, the Hosts, the bootstrap
     certificates with their PKCS#12 files, and the audit files — is carried whole. The audit lines
     are copied, not rewritten, and the migration checks that the chain holds.
   - **Packages**: each artifact becomes a blob. Each entry takes the signature the Deployments
     held for it; where two Deployments held different signatures for one entry it is carried
     **unsigned** and named — sign it again. A referenced entry (one an older Server fetched from a
     URL) is **dropped** and named; upload that artifact. An artifact whose bytes do not match the
     hash its entry recorded is **dropped** and named; upload it again.
   - **Deployments** keep their name, Selector and the Packages that were carried; their
     signatures now live on the entries. A Package that was not carried leaves them, named.
   - **Configurations** keep their content and lose their Selector. Each is **listed** with the
     Selector it had: put it into the Deployment whose Selector aims where that one did. A
     Configuration without an Agent type is **not carried**, because the Server refuses it at
     startup: it is listed by name, and its file stays in the old directory — save it again with
     its `service_name`.
   - **Agents** are carried with their labels inside their record. An Agent whose Package was
     released through a Deployment keeps that Package assigned through it. An older Server rolled
     every Configuration out by itself, never through a Deployment, so every Agent's Configuration
     pins are **dropped** and listed per Agent — also for an Agent that keeps its Package. The
     Agent keeps running the configuration it has: nothing is offered in its place until a
     Deployment holding those Configurations is rolled out to it.

   When it is done it opens the new directory as the Server will. It exits non-zero when it could
   not carry trust data or the new directory would not open — then empty the new directory, fix
   what it named, and run it again.
3. **Edit `server.toml`**: remove `config_dir` and `packages_dir`, and set
   `data_dir = "/var/lib/opamp-fleet-server/data"`.
4. **Start the Server**, put each listed Configuration into its Deployment, sign any entry named
   unsigned, and roll the Deployments out. Keep the old directories until you are satisfied, then
   delete them.

## Mutual TLS: proving who is on the connection

`[tls] client_ca_file` is required, and the Agent plane asks every peer for a client certificate
**in the TLS handshake**:

```toml
[tls]
cert_file = "cert.pem"
key_file = "key.pem"
client_ca_file = "client-ca.pem"
```

The handshake accepts a certificate that chains to `client_ca_file`, and, while `[enrolment]` is
configured, one that chains to the bootstrap CA. A peer that presents no certificate, or one that
chains to neither, fails the handshake and reaches no route. That covers the package download as
much as `/v1/opamp`. The Operator plane asks for no client certificate; a browser reaches it with
the password of [`[rest.auth]`](#the-operator-plane-restauth).

**The certificate is the whole of admission.** A connection is a member's when its certificate was
issued directly by the client CA, is valid, and is not
[revoked](#revocation-withdrawing-a-certificate); any other certificate that passes the handshake
makes an enrolment connection. No configuration admits a peer without a certificate. `/v1/opamp`
and the download route read no `Authorization` header: one a Client sends is ignored, never
refused, and no refusal carries a `WWW-Authenticate` challenge.

A certificate proves **fleet membership, not identity**. Its subject is the Server's, the client
CA's name with ` CA` turned into ` Certificate`, whatever the request asks for, and the Server does
not match it against an Agent's `instance_uid`: the Server itself may re-key an Agent at any time
(`AgentIdentification`), and a certificate that a re-key invalidates is an outage of your own making.

### Issuing certificates: the CSR flow

Add a `[client_ca]` section and the Server becomes a local CA:

```toml
[client_ca]
cert_file = "client-ca.pem"
key_file = "client-ca-key.pem"
validity_days = 30
```

Use a **separate** CA, not the listener's certificate and key: a CA private key stored where the
server certificate lives means compromising the Server mints fleet members at will. Then point
`[tls] client_ca_file` at that CA's certificate, so the certificates it issues are the ones the
listener accepts.

With the section present the Server declares `AcceptsConnectionSettingsRequest`. A Client whose
certificate is two thirds through its validity generates a key **that never leaves its host**,
sends a signing request, and receives the certificate as an ordinary connection-settings offer. It
proves the new certificate by connecting with it before it replaces the one in force. A request
from a peer whose certificate chains to the client CA is signed at once: renewal is automatic. A
request from a host that holds only a bootstrap certificate waits for an operator, as the next
section describes. The Server signs a client-authentication certificate only, and drops any
alternative names the request asks for.

A request is exactly one PEM block labelled `CERTIFICATE REQUEST`, with nothing but whitespace
around it. Anything else — text before or after the block, a second block, another label — is
answered with the protocol's `BadRequest` error response naming that rule, as is a request that
does not parse or one arriving at a Server with no `[client_ca]`. A Gateway forwards no enrolment
request that breaks the rule.

### The first certificate on a host

A host needs a certificate before it can connect at all, and it gets one in one of two ways:

1. **An operator provisions it.** Sign a client certificate with the client CA and write it, with
   its key, into the Client's `[tls] cert_file` and `key_file`. The Client connects with it at
   once and renews it through the CSR flow.
2. **The host enrols.** It is given a bootstrap certificate, and an operator approves its request —
   see [Enrolment](#enrolment-a-new-host-approved-by-an-operator).

**Behind a Gateway, the Gateway's handshake admits the Agents it carries.** Mutual TLS is per hop:
the Gateway checks the Agents connecting to it against the client CA and the Server's revocation
list, and presents its own certificate to the Server. It forwards no `Authorization` header. A
Gateway that names the bootstrap CA's certificate as `[gateway.tls] bootstrap_ca_file` relays the
enrolment request of a host behind it (see
[Enrolment through a Gateway](#enrolment-through-a-gateway)).

**A certificate names its host.** The Server puts `urn:opamp-fleet:host:<id>` into every
certificate it signs: a host is minted when an operator approves an enrolment, a certificate an
operator provisioned is given one on its first renewal, and every renewal keeps it — the Client
proves with its current key which certificate it renews, through a Gateway too. An Agent belongs
to the host that first reported it, until it is forgotten or that host's last certificate has
ended: a connection with another host's certificate that reports for it is given an
`instance_uid` of its own instead. A host holds at most three valid
certificates. A Gateway carries other hosts' Agents, so mark it once its certificate names a
host. **A Gateway admits nobody until its host is marked:** only a marked host is handed the
revocation list a Gateway refuses by (see
[Revocation](#revocation-withdrawing-a-certificate)):

```console
$ curl --cacert ca.pem https://127.0.0.1:4321/api/v1/hosts
[{"host":"0192…","name":"edge-01","gateway":false,"instance_uids":["0192…","0193…"],"certificates":1,
  "subject":{"country":"","state":"","locality":"","organization":"","organizational_unit":"","organization_identifier":""},
  "approved_ms":1760000000000,
  "agents":[{"instance_uid":"0192…","client":true,"client_agent":"0192…","machine":"",…},…]}]
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{"gateway": true}' \
       https://127.0.0.1:4321/api/v1/hosts/0192…/gateway
```

A Gateway's certificate speaks for any Agent; behind it, fleet membership is all the Server
proves, and the Gateway's certificate may fetch the artifact offered to any Agent. A third-party
client that sends no renewal proof renews the certificate it presents, but not through a Gateway:
there the certificate presented is the Gateway's, and a request with neither a renewal proof nor
a bootstrap proof is refused, naming both. A third-party client behind a Gateway gets its next
certificate by enrolling directly or from the operator. A request with a bootstrap proof over a
member's certificate whose host is not marked as a Gateway is refused too, since a member does not
enrol, unless the proof names the certificate the connection presents: a Client on a certificate an
operator provisioned cannot tell it from a bootstrap certificate, and that request renews it.

### Hosts

A **Host** is what a client certificate of this Server names: one Client installation that
connects directly, a Gateway included. The Server writes it when an operator approves its
enrolment, with the time of the approval and the subject values of the certificate it was issued —
country (`C`), state (`ST`), locality (`L`), organization (`O`), organizational unit (`OU`) and
organization identifier. A host certificate the Server issues carries the values of the bootstrap
certificate the host enrolled with, and every renewal carries them on unchanged (see
[Bootstrap certificates](#bootstrap-certificates-issued-by-the-server)); a Host's values change
only when it enrols again. A certificate an operator provisioned with a host id makes its Host at
its first report, with the values of that certificate. Each Host records how long it is valid:
the latest end of a certificate naming it that the Server issued or that the host presented, moved
forward by every issuance and every connection. Once that has passed, nobody can speak as the host
again, so a Host that is not marked as a Gateway is forgotten, and every Agent bound to it is
released for whichever host reports it next. A Gateway's Host stays until its mark is taken away,
since its certificate may be one you provisioned and the Server never saw. A Host written by an
earlier version takes the latest end the register holds for it, and stays until it next connects
when the register holds none.

Every Agent record names the Host it last arrived over: its own on a direct connection, the
Gateway's behind one. This places the Agent in the fleet view and decides which labels it inherits
(see [Labels](#labels-rollout-channels-without-touching-the-host)). It grants nothing: what a
certificate may report for and fetch is decided by the host register as above.

**The Hosts tab** of the bundled UI lists every Host: its name — the `host.name` its Client's own
Agent reports, else the host id — its subject values, whether it is a Gateway, its valid
certificates and when each ends, and how many Agents arrived over it. Marking a Gateway and revoking
a Host's valid certificates are presses on its row. Selecting a Host shows its Agents, grouped by
their Client Agent with that Client's Supervisor Agents beneath it. For a Gateway these are the
Agents behind it, grouped by the machine they report. `GET /api/v1/hosts` answers the same.

**A certificate lives 30 days by default** and is renewed at two thirds of that; a host is ejected
sooner by revoking its certificate ([Revocation](#revocation-withdrawing-a-certificate)).
An expired certificate locks a host out: a Client switched off longer than its validity enrols again
with a bootstrap certificate, or is given a new certificate by an operator.

## Enrolment: a new host, approved by an operator

Enrolment is how a fresh host obtains its first certificate without an operator signing one by
hand. It is armed by `[enrolment]`, and it needs `[client_ca]`, which signs the approved request:

```toml
[enrolment]
bootstrap_ca_file = "bootstrap-ca.pem"
bootstrap_ca_key_file = "bootstrap-ca-key.pem"
```

The **bootstrap CA** is a CA of its own, never the client CA; a bootstrap CA that shares a
certificate or a key with the client CA is refused at startup. A bootstrap certificate opens nothing
by itself. It needs an open enrolment window and an operator's approval, so one bootstrap
certificate may serve many hosts. Keep its validity short.
Without `[enrolment]` no bootstrap certificate passes the handshake.

### Bootstrap certificates, issued by the Server

With `bootstrap_ca_key_file` set, ask the Server for a bootstrap certificate, name whom it is
for, and name the password its PKCS#12 file is encrypted under. The subject takes six
attributes, each at most once; `organization` and `organizational_unit` are required, so every
Host names a customer and a site its Selectors can rely on, and the others are optional:

| Key | Attribute | Value |
| --- | --- | --- |
| `country` | `C` | two upper-case letters, an ISO 3166-1 alpha-2 code such as `AT` |
| `state` | `ST` | 1 to 64 characters without a control character |
| `locality` | `L` | likewise |
| `organization` | `O` | likewise; typically the customer |
| `organizational_unit` | `OU` | likewise; typically the site |
| `organization_identifier` | `organizationIdentifier` (2.5.4.97) | likewise, in any format; a customer or contract number, a UUID for instance |

A request without `organization`, without `organizational_unit` or without `password` is
answered `400` naming it, as is any other key. The certificate lists them in that order, the
country as a `PrintableString` and every other value as a `UTF8String`. The Server sets the common
name: the bootstrap CA's name with ` CA` turned into ` Certificate`. `validity_days` runs from 1
to 90, 10 by default, and never past the bootstrap CA's end.

#### The PKCS#12 file: `bootstrap.p12`

The `password`, 8 to 128 characters without a control character, is required, and the key is in
no answer at all. The Server makes the key, signs the certificate, puts both into one PKCS#12 file
encrypted under that password, keeps the file, and hands it out as often as it is asked, until
the certificate ends or is revoked. It keeps the certificate's serial, subject, key fingerprint
and end beside it. The answer carries the certificate and no `private_key_pem`, with
`Cache-Control: no-store`. A host or a tool that needs the pair as PEM takes it out of the file
with `opamp-fleetctl pki p12-extract` ([`pki`](tools.md#pki)).

A short password is quicker to break offline. Eight characters are out of practical reach of an
offline attack on one file, but should the file leak with a weak password, whoever opens it can
file enrolment requests while the window is open, and your approval of each request is then what
stands in the way. Choose a longer password where you can, and check each host before you approve
it. The rule applies when a certificate is issued: a file issued before opens with the password it
was issued under.

```console
$ cat request.json        # written with an editor, so the password stays out of the shell's history
{"subject": {"country": "AT", "organization": "Example Customer", "organizational_unit": "Vienna",
             "organization_identifier": "K-4711"},
 "validity_days": 14, "password": "correct horse battery staple"}
$ curl --cacert ca.pem -X POST -H 'Content-Type: application/json' -d @request.json \
       https://127.0.0.1:4321/api/v1/bootstrap-certificates
{"serial":"6723…","subject":"C=AT, O=Example Customer, OU=Vienna, organizationIdentifier=K-4711, CN=OpAMP Fleet Bootstrap Certificate",
 "not_before_ms":…,"not_after_ms":…,"certificate_pem":"-----BEGIN CERTIFICATE-----…"}
$ curl --cacert ca.pem -o bootstrap.p12 \
       https://127.0.0.1:4321/api/v1/bootstrap-certificates/6723…/p12
```

The file holds the certificate and its key and nothing else, not the server CA: a host gets
`server-ca.pem` from you as before. It is encrypted with AES-256 under a key derived from the
password (PBKDF2-HMAC-SHA-256, 600 000 iterations) and carries an HMAC-SHA-256 MAC, so OpenSSL 3
opens it with its defaults (`openssl pkcs12 -in bootstrap.p12 -info`). The Server keeps it beside
the certificate's record under `data_dir/bootstrap/`, as `<issuer>-<serial>.p12`, readable by its
own account only. **The password is kept nowhere** — not in the file's directory, not in a log, not in the
audit — so give it to the host by another way than the file. Every download is recorded in the
audit as `enrolment.bootstrap_p12_downloaded` with the serial; a download is answered `503` while
the audit record cannot be written, and `404` for a certificate with no file, a revoked one, an
ended one, an unknown serial, or a certificate an older Server issued without a file. A
revocation removes the file before it is answered; lifting the revocation does not bring it back.

**Every host certificate issued from it carries its subject values.** Approving an enrolment
copies the six values from the bootstrap certificate the host enrolled with into the host
certificate, and every renewal carries them on unchanged, so the Host and its Agents carry them as
`fleet.host.*` (see [Hosts](#hosts)). The common name is never copied, nor anything the host's own
request names. A value fixed at issue stays until the host enrols again: put what is stable and
says whom the host belongs to into the subject, and nothing that changes. The values describe and
select; they authorize nothing. They show on every enrolment request the certificate carries, as
`bootstrap_subject` with its `bootstrap_serial`, so the approver sees whose request it is and what
the host certificate will carry. A bootstrap certificate of your own PKI whose subject breaks these
rules — an attribute twice, a value of the wrong string type or length, no organization or no
organizational unit — lists no `bootstrap_subject` but a `subject_refusal` naming the attribute:
approving it is refused `409`, so reject it and give the host a certificate that follows them. A
renewal carries the values of the certificate it renews as they are, without checking them again.
Every issuance is recorded in the audit as `enrolment.bootstrap_issued`, with `p12` saying a
file was made.

The UI's **Enrolments** tab does the same: it issues a certificate with the values you type, the
customer, the site and the password required and the country chosen from a list, and lists the
valid ones with a **Revoke** press. The password is typed twice. The row of each certificate
offers **Save bootstrap.p12** in this page and in every later one, until the certificate ends or
is revoked; the page never holds a private key. A certificate issued elsewhere offers nothing to
save.

```console
$ curl --cacert ca.pem https://127.0.0.1:4321/api/v1/bootstrap-certificates
[{"serial":"6723…","subject":"O=Example Customer, OU=Vienna, CN=OpAMP Fleet Bootstrap Certificate",
  "key_fingerprint":"…","issued_ms":…,"not_after_ms":…,"revoked":false,"p12":true}]
```

The list holds every valid bootstrap certificate the Server issued, oldest first; an ended one is
dropped, and so is every one of a bootstrap CA since replaced. Revoke one by its serial with the authority `bootstrap`
([Revocation](#revocation-withdrawing-a-certificate)).

A revoked one stays in the list, marked revoked, until it ends. To drop it sooner, delete it —
**Delete** in its row, or:

```console
$ curl --cacert ca.pem -X DELETE https://127.0.0.1:4321/api/v1/bootstrap-certificates/6723…
```

Deleting removes the entry and any `bootstrap.p12` of it, answered `204`, and is recorded in the
audit as `enrolment.bootstrap_deleted`. **The revocation stays**: the certificate is still refused
for as long as it would be valid, and `GET /api/v1/revocations` still lists it. A request that
carries it shows *not issued here*. Only a revoked certificate is deleted; a valid one is answered
`409` — revoke it first — and an unknown serial `404`; while the audit record cannot be written,
nothing is deleted and the answer is `503`.

When issuing, the Server holds at most 10 000 valid ones, revoked ones included until they end or
are deleted, and answers a request beyond that `409`. It answers `409` too while it holds no
`bootstrap_ca_key_file` or once the bootstrap CA has ended, `503` while the audit record cannot be
written, since no key is handed out unrecorded, and `400` for a subject attribute it does not know, a value out of bounds,
`validity_days` outside 1 to 90, or a password outside 8 to 128 characters.

**The window is closed by default.** Open it for as long as you are enrolling hosts, from 1 to
86400 seconds:

```console
$ curl --cacert ca.pem -X POST -H 'Content-Type: application/json' \
       -d '{"open_for_secs": 3600}' https://127.0.0.1:4321/api/v1/enrolment/window
{"open":true,"until_ms":1790000000000}
$ curl --cacert ca.pem https://127.0.0.1:4321/api/v1/enrolment/window
$ curl --cacert ca.pem -X DELETE https://127.0.0.1:4321/api/v1/enrolment/window
```

`POST` opens the window, or moves its end to `open_for_secs` from now. `GET` says whether it is
open and until when. `DELETE` closes it early. The window's end and its pending requests — an
approved one with its certificate included — are written to `data_dir/enrolment.json` before the
act that changes them is answered, so a Server restart keeps an open window open until its end and
keeps its requests: a host whose approval it had not collected yet is handed its certificate after
the restart. A window whose end passed while the Server was down is closed when it starts. When it
closes, every enrolling connection is closed and every pending request expires, an approved one
whose certificate its host has not collected included; that host enrols again in the next window.

**While it is open, an enrolling host may send a certificate request and nothing else.** The
Server creates no Agent record for it and offers it nothing but the issued certificate. The request
waits in a queue of at most 1024, of which the requests of one bootstrap certificate hold at most
`max_pending_per_bootstrap`, 256 by default. A request beyond either bound is answered
`Unavailable` and the host retries later; one beyond its bootstrap certificate's share is recorded
in the audit as `enrolment.refused` with `reason` `bootstrap_share` and the certificate's serial,
once per certificate and window. A re-sent request that already waits is never refused. The Client
keeps its pending key and re-sends the same request until it is answered.

**Match the request to the host by its fingerprint.** The enrolling Client logs the SHA-256
fingerprint of the key it generated:

```text
INFO certificate request generated; an enrolling host waits for an operator's approval key_fingerprint=3f9a…
```

The Server lists each pending request with that fingerprint as its `id`, beside its arrival time,
the peer address, and the bootstrap certificate's six subject values, fingerprint and serial. The
request's own subject is not listed: the host chose it, and nothing copies it.
The Client sends its request as soon as the Server's first answer says it signs certificates,
so the request is listed moments after the host connects:

```console
$ curl --cacert ca.pem https://127.0.0.1:4321/api/v1/enrolments
[{"id":"3f9a…","arrived_ms":1789996400000,"peer":"10.0.4.17","key_fingerprint":"3f9a…",
  "bootstrap_subject":{"country":"AT","state":"","locality":"","organization":"Example Customer",
                       "organizational_unit":"Vienna","organization_identifier":"K-4711"},
  "bootstrap_fingerprint":"…","bootstrap_serial":"6723…"}]
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/enrolments/3f9a…/approve
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/enrolments/3f9a…/reject
```

The UI's **Enrolments** tab shows the same queue: each request with its full key fingerprint, the
bootstrap certificate it carries — its subject values, and its serial and end when the Server
issued it — and an **Approve** and a **Reject** press on its row. Approving asks once more,
quoting the fingerprint to compare with the Client's log. The tab also says whether the window is
open, and opens and closes it.

Approving signs the request with `[client_ca]`, with the bootstrap certificate's subject values,
and offers the certificate on that host's connection. A bootstrap certificate from another PKI is
read under the same rules as one the Server issues, except that a value other than the country may
also be a `PrintableString`, as older PKIs write it; the host certificate carries it as a
`UTF8String`. An attribute that appears twice, a value of another string type or of the wrong
length, or a country that is not two upper-case letters makes the approval fail with `409` naming
the attribute, nothing is signed, and the request waits. Issue the host a bootstrap certificate
that fits, and reject the request. The host stores it as `client-cert.pem` in its state directory and reconnects with it
as a member; from then on it renews by itself. Rejecting answers the request `BadRequest` and
closes the connection. An unknown or expired id is answered `404`, and every enrolment route
answers `404` while `[enrolment]` is not configured. A bootstrap certificate that arrives while
the window is closed is answered `503`, and does not count toward the throttle.

A request whose subject or SANs name an `instance_uid` other than the host's own is answered
`BadRequest` and never enters the queue. The same holds for a renewal.

**A request proves the bootstrap certificate it rests on.** The Client adds a bootstrap proof to
its request: the certificate it enrols with, and a signature made with that certificate's key over
the key it asks to be certified. The Server checks the proof itself, that the certificate is valid
now, is not revoked, and that its key signed the request, and files the request under that
certificate: the subject values, fingerprint and serial listed are the proven certificate's. On a
direct connection the proof must name the certificate the connection presented. A request whose
proof names another certificate or does not verify, and one that carries a renewal proof beside
it, is answered `BadRequest` and never enters the queue. A request without a proof, as a
third-party OpAMP client sends it, is filed under the certificate the connection presented.

The bootstrap certificate stays in the host's `supervisor.toml`, unused once the issued pair is
stored. Approve only what you can match to a host you are setting up.

### Enrolment through a Gateway

A host that reaches the Server only through a Gateway enrols through it, once the Gateway names
the public certificate of `bootstrap_ca_file` as `[gateway.tls] bootstrap_ca_file` (see
[Enrolment through a Gateway](client.md#enrolment-through-a-gateway) for the Gateway's side). The
Gateway relays the host's request over its own certificate, so a request through a Gateway is a
certificate signing request with a bootstrap proof over the certificate of a host marked as a
Gateway. The Gateway relays it only when its proof embeds the very certificate the host presented
to the Gateway, so a host spends no other bootstrap certificate's share or tokens; a proof that
embeds the Gateway's own certificate, byte for byte, is the Gateway's own request and no
enrolment. The Server checks the proof itself, against the bootstrap CA of `[enrolment]` and the
revocation list, and decides the request as any enrolment: it is answered `Unavailable` without an
open window, counts against the queue and its bootstrap certificate's share, and waits for your
approval, which mints a host of its own and never the Gateway's. A proof whose certificate the
bootstrap CA did not issue directly, is no client-authentication leaf as the handshake requires
one (`clientAuth` where it names an extended key usage, not a CA), is not valid now, or is revoked,
is answered `BadRequest` and never queued.

The pending request names the Gateway's host in place of a peer address — `"gateway":"0192…"` in
`GET /api/v1/enrolments`, *via Gateway* in the **Enrolments** tab, and `gateway` in every audit
entry of it: `enrolment.queued`, `enrolment.refused`, `enrolment.approved` and
`enrolment.rejected`. The host collects its certificate in its next request after the approval,
and then reports through the Gateway as a member. The Server does not tell a Gateway whether a
window is open, so a holder of a bootstrap certificate reaches the Server through a Gateway that
trusts the bootstrap CA outside a window too; it is answered `Unavailable`, and the rate limit
bounds what that costs (see [How often a member may be heard](#how-often-a-member-may-be-heard)).

## Revocation: withdrawing a certificate

A certificate stays valid until it expires. To shut a host out sooner, revoke its certificate. The Server refuses it from then on, on both
transports and on the package download, and closes at once every WebSocket session it admitted,
with close code `1008`. No other session is touched, and no restart is needed. The list lives
in `data_dir/revocations.json` and survives a restart.

Every certificate the client CA signs is in a register, with the certificate the host presented
when it renewed. Its `key_fingerprint` is the one the request was listed and approved by:

```console
$ curl --cacert ca.pem https://127.0.0.1:4321/api/v1/certificates
[{"authority":"client","issuer":"CN=OpAMP Fleet Client CA","serial":"5c0f…",
  "subject":"CN=OpAMP Fleet Client Certificate",
  "key_fingerprint":"…","not_after_ms":1797772400000,"instance_uid":"0192…",
  "issued_ms":1789996400000,"predecessor":{"authority":"client","serial":"41ab…"},
  "host":"0192…"}]
```

Revoke a certificate by the CA that issued it — `client` for the client CA, `bootstrap` for the
bootstrap CA of `[enrolment]` — and its serial. A revocation reaches every renewal of that
certificate too, so revoking the one a host enrolled with is enough even after it renewed, and it
stays in force until the last of those renewals has expired. `GET /api/v1/bootstrap-certificates`
lists the serial of every bootstrap certificate the Server issued; colons, case and leading zeros
do not matter. A serial is at most 20 octets, 40 hex digits, as RFC 5280 allows; a longer one is
answered `400`, and a certificate with one is not admitted. A renewal
descends from the certificate its renewal proof names, through a Gateway too; a client that sends
no proof renews from the certificate its connection presented. Behind a Gateway that would be the
Gateway's certificate, with the Gateway's powers, so such a request is refused there: through a
Gateway only a renewal with a proof is signed. A revoked certificate's proof renews nothing.

```console
$ curl --cacert ca.pem -X POST -H 'Content-Type: application/json' \
       -d '{"certificate": {"authority": "client", "serial": "5c0f…"}}' \
       https://127.0.0.1:4321/api/v1/revocations
{"id":"9d2e…","kind":"certificate","revoked_ms":1790000000000,
 "certificate":{"authority":"client","serial":"5c0f…"}}
```

There is no credential to revoke. A request naming `"credential"` is answered `400`, naming the
field and saying that the Agent plane admits by client certificate alone. A credential entry
`revocations.json` holds is dropped when the list is loaded, with one log line giving the number
dropped, and the list is written back without it.

`GET /api/v1/revocations` lists every entry, and `DELETE /api/v1/revocations/<id>` lifts one; the
next connection is admitted again. The list holds at most 100 000 entries; an entry for a
certificate the register held is dropped once neither that certificate nor any renewal of it is
valid. The register holds at most 100 000 certificates and at most 10 000 in one renewal chain,
and keeps the last 1 000 places for enrolments.

Every WebSocket session also ends when the certificate that admitted it expires, with `1008` and
the reason `certificate expired`. A Client renews at two thirds of the life and reconnects with
the new certificate, so a healthy fleet never sees this.

Behind a Gateway the Server sees the Gateway's certificate, not the Agent's, so the Gateway refuses
for it. Every host marked as a Gateway fetches the revoked certificates of the client CA from
`GET /v1/gateway/revocations` on the Agent plane every 30 seconds, renewals already resolved, and
refuses a downstream peer whose certificate is on it with `401`, closing its sessions with `1008`
and the reason `revoked`. A revocation therefore reaches a gatewayed Agent within about 30
seconds. A Gateway that has held no list younger than 300 seconds — its Server unreachable, or its
host not marked — answers every downstream peer `503` and closes their sessions with the reason
`revocation list stale`. Revoking the Gateway's own certificate ends every Agent it carries.

## The audit record

Every security decision leaves one line in `data_dir/audit/`: each admission and refusal on the
Agent plane, each refused operator sign-in, each enrolment request, approval and rejection, each
certificate issued, each revocation and the session it ended, each request for the Gateways'
revocation list from a host not marked as a Gateway, each download a host may not fetch, each
operator act with the operator's name, and each package an Agent reports installed or failed. A
plain-HTTP Agent's admission is recorded once an hour per address and certificate, a WebSocket
session every time. No line holds a secret in any form — an `Authorization` value is never
written, not even as a hash, whether an operator presented it or an Agent sent it unasked — nor a
key or a CSR body.

```console
$ tail -n1 /var/lib/opamp-fleet-server/audit/audit-1.jsonl
{"event":"revocation.revoked","id":"9d2e…","kind":"certificate","authority":"client",
 "serial":"5c0f…","outcome":"revoked","prev":"41b7…","seq":5113,"time":"2026-10-04T09:12:44Z"}
$ server audit-verify /var/lib/opamp-fleet-server/audit
5113 entries in 1 files, the chain holds
```

Each line carries the SHA-256 of the line before it, so a line edited or removed afterwards breaks
the chain where it happened; `audit-verify` names the first entry that does not follow. Against an
intruder on the Server host that only helps with a copy taken before, so ship the directory off the
host. The record also goes to the Server's log under the target `audit`.

The Server never takes a decision it cannot record: when the record cannot be written — a full
disk, a failed device — it admits no Agent and runs no operator act, answering `503`, until it
can. A certificate request in that time is answered `Unavailable` with a time to retry, and the
Agent asks again. Refusals past ten a second from one address are counted into one line, not dropped.
`[audit] max_file_bytes` (64 MiB) and `keep_files` (16) bound the space it takes.

## Configurations: what the fleet runs

A **Configuration** is content: a name, a body of text, the **Agent type** it is written for, and
an optional **role**. It has no Selector and is never rolled out by itself — a
[Deployment](#packages-and-deployments-distributing-software) holds it, and the Deployment's
Selector aims it. One Configuration may sit in several Deployments.

**Names** become file names here, config-map keys on the wire, and entry files on every Client
— including Windows ones. The grammar is therefore narrow: 1–32 characters, lowercase letters,
digits, and `-`, not starting or ending with `-`, and not a Windows reserved device name (`con`,
`nul`, `com1`, …).

**Saving never distributes**. `PUT` stores the Configuration and reaches nobody. A body naming a
`selector` is refused `400`: aim it by putting it into a Deployment. Distribution is the
Deployment's **rollout act** — `POST /api/v1/deployments/{name}/rollout` for every Agent it
claims, or the per-Agent press on the fleet view. Either act pins a snapshot: the Agent keeps
exactly the revision it was rolled out, so a later edit changes nothing anywhere — the fleet view
shows the newer save *waiting* per Agent — until the next act. An Agent that connects (or is
labelled into a Deployment) after the act waits the same way: nothing is distributed by
enrolment, by a Deployment edit, or by a label move.

**Nothing in use can be deleted**: deleting a Configuration that any Agent's assignment pins is
refused `409`, and the answer says how many Agents pin it. Roll those Agents out through a
Deployment that no longer holds it — they apply their config map without the entry — or forget
them, and then delete it. A deleted Configuration leaves every Deployment that held it.

**The type decides which Agents of the Deployment receive it**. `service_name` is required, and
must equal the `service.name` the Agent reports — compared raw. A `PUT` without it is refused
`400`, and a stored Configuration without it stops the Server at startup, naming the file. An
Agent that reports no `service.name` receives no Configuration. Content for several Agent types,
a certificate bundle for instance, is one Configuration per type. That is how one Deployment
serves several Agent types.

The examples on this page call the Operator plane on the loopback, over TLS. `--cacert ca.pem`
names the CA that signed the Server's certificate. Off the loopback, add the
[`[rest.auth]`](#the-operator-plane-restauth) credential with `-u`.

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' \
       -d '{"service_name": "otelcol-contrib", "body": "receivers: {}"}' \
       https://127.0.0.1:4321/api/v1/configurations/contrib-base
$ curl --cacert ca.pem -X PUT https://127.0.0.1:4321/api/v1/deployments/stable/configurations/contrib-base
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/deployments/stable/rollout
```

**A Deployment may hold several Configurations.** An Agent receives every one that fits its type,
as named entries in one config map, and merges them itself. An Agent in no Deployment is offered
nothing and keeps running what it already runs — the Server never blanks an Agent by omission.

**The role marks content that is not configuration**. `role: "supplementary"` means the
Managed Process reads this content *by path* — a rule file, a lookup table — so the Client writes it
into the configuration directory under its own name but never passes it to the process as
configuration. An unset role means top-level configuration, which is what every Configuration was
before the option existed. Any other non-empty value travels to the Agent verbatim and is treated
like `supplementary`.

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' \
       -d '{"service_name": "otelcol-contrib", "body": "rules: []", "role": "supplementary"}' \
       https://127.0.0.1:4321/api/v1/configurations/ruleset
```

**Nothing is sent twice.** The Server composes the entries an Agent was **rolled out**, hashes
them, and compares that hash to what the Agent reports. Equal hashes mean nothing crosses the
wire. This is why repeating a rollout act with unchanged content is free, why a press that changed
only a Configuration sends no package offer (and the reverse), and why a role change *does* reach
the fleet once rolled out: the role is part of the hash.

**How a change travels.** The rollout act is the moment it starts — over WebSocket the Server
pushes it within a second; over plain HTTP it rides the Agent's next poll. The Agent then reports
the configuration back as applied or failed, with the hash it applied — visible on the Agent's
row as `remote_config_status`, `remote_config_error`, and `in_sync`.

**The fleet view shows what waits.** Per Agent, `GET /api/v1/agents` answers what is rolled out
to it (`assigned_deployment`, `assigned_configurations`, `assigned_package`) and what the next
press of its Deployment would change (`pending_configurations`, `pending_packages`, each with a
`change`: `new`, `update` — a newer save or version — `remove` — the Deployment no longer
releases it to this Agent, and the press applies the smaller set — or `kept` — the Deployment
releases nothing to this Agent any more, so the press leaves it with no assignment and it keeps
running what it runs). `pending_deployment` names the Deployment the press releases through when
the assignment names another one, even where the content stays the same. The Server never acts on
the waiting list by itself; the per-Agent
rollout (`POST /api/v1/agents/{instance_uid}/rollout`, with an empty body or
`{"deployment": "…"}` naming the Deployment that claims the Agent) is the operator's press.

## Packages and Deployments: distributing software

The Packages live in `data_dir/packages/` and their artifacts in `data_dir/blobs/`; the Server
declares the capability only while the store holds a Package. Two objects, and the split is the
whole of the model:

- A **Package** is *what* an Agent type runs at a version. Its identity is the **Agent type and
  the version**, the version a SemVer 2.0.0 version, and it holds one entry per platform — the Linux build, the macOS builds, the
  Windows build — each an uploaded artifact with its SHA-256 and the operator's **signature**.
  Nothing else: no name of its own, no Selector. It aims at nobody and is never rolled out.
- A **Deployment** is *where that goes*. A name, the **channel** it aims at, one Package per Agent
  type, and any number of [Configurations](#configurations-what-the-fleet-runs). It is the only
  thing that is rolled out, and one press releases its Packages and its Configurations together.

An Agent belongs to **at most one Deployment**. Two matching the same Agent is a conflict: that
Agent is offered nothing new — no Package and no Configuration — and the fleet view says so on its
row in `package_conflict`. There
is no most-specific-wins and no newest-wins — a rule that decides which artifact a host gets by
comparing every stored object against every other is a rule nobody can evaluate by looking at
anything.

### Channels are a partition, not a default

**A Selector is equality and cannot say "not".** "Everyone except the canary hosts" is not a
writable Selector, so disjoint channels come from *membership*: an attribute every Agent carries.

**The Server prescribes no key.** There is no reserved word and no special handling anywhere — a
Selector is equality over whatever the Agent reports, and the key is one you invent. What follows
are examples, not a schema.

```console
# at provisioning, in the host's supervisor.toml
[attributes]
channel = "stable"

# or from here, without touching the host
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{"labels": {"channel": "beta"}}' \
       https://127.0.0.1:4321/api/v1/agents/<uid>/labels
```

Which key you pick is a decision about *what the partition means*, and three shapes cover most
fleets:

| key | what it says about the host | how a release moves |
|---|---|---|
| `channel` | which stream of versions it follows — `stable`, `beta`, `nightly` | you change **what the channel carries**; the hosts stay where they are |
| `region` | where it runs — `eu-central`, `us-east` | a release follows the sun, one region at a time; or a version stays pinned where a jurisdiction requires it |
| `tenant` | whose it is — `acme`, `globex` | one customer's software moves on that customer's schedule, independently of everyone else's |

`channel` is the one to reach for when the partition is about *release risk*, which is the ordinary
case: a host subscribes to `stable` and stays there for years, while the Deployment named `stable`
is given one version after another. `region` and `tenant` describe the host instead of its
appetite, and both compose — a fleet can carry all three and aim a Deployment at
`{"tenant": "acme", "channel": "stable"}`, which is two equality pairs and needs nothing new.

What they have in common is the reason they work: each names a **property of the host**. A key that
named the Deployment instead — `deployment = "contrib"` — would put the same fact in two places, so
re-aiming a channel would mean editing every host in it. The Selector exists to avoid exactly that.

**A Deployment's Selector may not be empty** — an empty one matches every Agent, so it would
collide with every other channel the moment a second one exists, and it is what a forgotten field
looks like. The price is stated plainly: **there is no "roll out to everyone" any more.** A
fleet-wide delivery needs every Agent to carry the same value, and a freshly enrolled host
belongs to no Deployment until it is labelled. That host shows on the fleet view with no
deployment, which is the ordinary state after an enrolment and not a fault.

### Create the Package, upload its entries, sign them

The identity is the path. The Agent type is compared **raw** against the `service.name` the Agents
report — there is no canonical set of Agent types, so spell it exactly as they do. The create body
has no writable field; `{}` is the whole of it.

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{}' \
       https://127.0.0.1:4321/api/v1/packages/otelcol-contrib/0.109.0
$ curl --cacert ca.pem -X PUT --data-binary @otelcol-contrib_0.109.0_linux_amd64.tar.gz \
       "https://127.0.0.1:4321/api/v1/packages/otelcol-contrib/0.109.0/entries/linux/amd64"
```

Platform spellings are accepted and stored canonically, so the tokens off an upstream release's
file name work as they are: `macos` and `osx` mean `darwin`, `x86_64` and `x64` mean `amd64`,
`aarch64` means `arm64`. An `os`/`arch` this Server has never heard of is stored as given rather
than refused — the fleet may run a system nobody here anticipated.

**Every artifact is uploaded.** The Server holds what it offers and sends no request for a package
anywhere; a Client fetches from its own Server's origin alone (see
[the Client](client.md#where-a-download-may-come-from)).

**Sign each entry** on its own route, with the hex signature `opamp-fleetctl package sign` prints:

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d "{\"signature\": \"$sig\"}" \
       https://127.0.0.1:4321/api/v1/packages/otelcol-contrib/0.109.0/entries/linux/amd64/signature
```

**The signature belongs to the entry.** What it covers — the Agent type, the version and the
artifact's SHA-256 — names no Deployment, so one signature serves every Deployment that holds the
Package. **The Server never offers an unsigned entry**: an entry without one is no candidate, and
the fleet view says the signature is missing. A signature for an entry that does not exist is
`404`, an empty or malformed one `400`. Uploading new bytes to an entry removes its signature,
because it covered the old hash. Supplying a signature on the artifact upload instead answers `400`
naming the route that takes it.

Each entry reports its `signature_state`: `missing`; `valid` or `invalid` when `[packages]
verification_key` is set; `unchecked` when it is not. An `invalid` one is stored, offered, and
shown on the Packages tab as a warning — **the Server only reports**, and each Client's own check
decides. A Client with the right key refuses that artifact, so the warning is the moment to sign
the entry again.

A Package is one file, `data_dir/packages/<agent type>@<version>.json`, naming each entry's
artifact by its SHA-256; the bytes are `data_dir/blobs/<sha256>`. Two entries with identical bytes
share one blob, and a blob goes when the last entry naming it does. Every blob is hashed again at
startup, and one whose content does not match its name **fails the start naming it**, as does a
file in either directory this Server did not write — a store left over from an older layout would
otherwise open successfully and empty, which reads as "nothing uploaded yet".

A Package that no Deployment holds reaches nobody, and the package list says so — `in no
deployment` in the UI, an empty `deployments` array in the API. That is the state a Selector
matching no one used to be.

### Put it in a channel, roll it out

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{"selector": {"channel": "beta"}}' \
       https://127.0.0.1:4321/api/v1/deployments/beta
$ curl --cacert ca.pem -X PUT https://127.0.0.1:4321/api/v1/deployments/canary/packages/otelcol-contrib/0.109.0
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/deployments/canary/rollout
```

**Nothing is offered before that last line.** Everything above stores; the **rollout act** is the
only thing that distributes, for the Package and the channel's Configurations alike. The press
replaces each Agent's assignment with one release: the Package the channel holds for its type,
when that is an upgrade, and every Configuration that fits its type, at its saved revision. A
Package the press cannot move — the Agent already runs it, or it would move it backwards — stays
pinned as it is. Five platforms' artifacts can be
uploaded, signed, put in a channel and then released together, and the window in which a
half-described release is already reaching the fleet does not exist. An Agent that enrols — or is
labelled into the channel — later waits, marked pending on its fleet row, for an act of its own.

**A channel holds at most one Package per Agent type**, because an Agent has one binary to replace. A
second is refused `409` naming the one in the way; `?replace=true` is how you say you mean to swap
the version the channel runs. Adding the same one again is the same request arriving twice and
succeeds.

A rollout of a Deployment holding no Package and no Configuration is refused `409`, and so is one
holding a Package with an unsigned entry — naming each such Package and the platforms it is
unsigned for — and nothing is released. The UI marks such a package `⚠` on the channel's row.

**While a Package is rolled out to at least one Agent its entries are frozen**, signatures
included (the fleet is installing those bytes; uploads and signature writes answer `409`); ship a
change as the next version, which is a new Package. **The channel freezes nothing**: its Selector,
its Packages and its Configurations stay editable in every state, because an Agent's assignment
pins the Package and the revisions themselves. Swapping the version a channel holds, editing a
Configuration or taking one out is how a rollout proceeds: the hosts already released keep what
they have, and the change shows as waiting until the next press.

**Nothing in use can be deleted.** Deleting a Package or a Deployment that an Agent's assignment
pins is refused `409`, saying how many Agents pin it; roll those Agents out through a Deployment
without it, or forget them, first. A deleted Package leaves every Deployment that held it, and
**nothing is uninstalled** — an Agent keeps running what it installed.

### The canary shape

Two channels, disjoint by label, each holding its own version:

```console
$ curl --cacert ca.pem -X PUT -d '{"selector": {"channel": "stable"}}' … /api/v1/deployments/stable
$ curl --cacert ca.pem -X PUT -d '{"selector": {"channel": "beta"}}'   … /api/v1/deployments/beta
```

There are two ways to move, and with a `channel` key the second is the ordinary one:

- **Move a host** — change its label from `stable` to `beta`, and it takes what the beta channel holds.
  This is how a single machine is tried first.
- **Move the release** — give the `stable` channel the version `beta` already carries and press again.
  The hosts never move; the channel they subscribe to is handed the next version. This is how a
  rollout *finishes*.

**Widening the beta channel instead is not how it ends** — it would make both channels claim the same
hosts, which is a conflict, not a rollout.

### Fit runs before aim, and it is mandatory

A Package built for another **Agent type** is not a candidate at all: its type is matched against
the `service.name` the Agent reports, so a Promtail artifact never reaches a Collector even from a
channel that claims it. Then an entry must exist for the **platform** the Agent reports. Only what
survives both is what its channel can release. **An Agent that reports no `service.name`, `os.type`,
or `host.arch` is offered nothing** — there is no artifact that can be known to be meant for it or
to run on it, and guessing is how a fleet-wide outage starts.

### Reading the counts

A Deployment carries three, because zero has three meanings and only the first is a mistake to go
hunting for:

| count | zero means |
|---|---|
| `claiming_agents` | the channel aims at nobody — a Selector naming an attribute nobody reports, or a value nobody carries |
| `targeted_agents` | everyone it claims already holds what a press would release; nothing to do |
| `conflicting_agents` | *non*-zero is the one to act on: another channel claims those Agents too |

On the other side, each Agent's row says which channel claims it (`deployment`) as well as which one
released what it runs (`assigned_deployment`). The two differ on purpose, and reading them together
tells apart four states that would otherwise be the same empty cell — because the next move differs
in each:

| the row shows | what it means | what to do |
|---|---|---|
| no `deployment`, no conflict | no channel's Selector matches this host | label it, or give it a `channel` attribute |
| a `deployment`, nothing assigned, nothing pending | the channel holds nothing this Agent can take — no Configuration for its type, and no Package for its type or its platform | put the right Configuration or Package in the channel, or upload the entry |
| a `deployment` and something pending | it is waiting for a rollout act | press it |
| `package_conflict` | two channels claim it | narrow one Selector |

**A rollout act never moves an Agent backwards.** The version an Agent reports
installed is part of matching: a Package reaches it only if the Package's version is **greater**,
compared as SemVer (major, minor, patch, then the pre-release rules). Equal is not greater — a
Package an Agent already runs reaches it with nothing — and a reported version nothing can order
is refused rather than guessed at. The bulk act leaves the package part of such Agents as it is;
a per-Agent press that would change nothing because of it answers `409` and says which version the
Agent reports.

**An Agent that reports no version for the package is held against the version it reports
*running*** — its `service.version`.
That is what makes the rule reach a Client installed from a `.deb`, an `.rpm` or an MSI, which has
installed no package and has none to report: no Client is offered the version it already runs, and
none is moved backwards. A `service.version` nothing can order (`1.19`, `24.04.1`) simply says
nothing, so an Agent whose program numbers itself its own way stays reachable. Its Packages are
numbered in the program's own space, written as SemVer: `1.19` becomes `1.19.0`, `24.04.1` becomes
`24.4.1`.

**A Package an older Server stored under a version that is not SemVer is kept and inert.** At
startup the Server logs one warning per such Package, naming it. It is nobody's candidate, and every
write to it — an entry, a signature, adding it to a Deployment — is answered `400`. It can be read,
and deleted once no assignment pins it; an assignment that already pins it stays in force and its
offer still goes out, which an upgraded Client refuses and reports. Republish the content under a
SemVer version, sign it again, and roll that out. The Client's own rules — no version below the
highest it has installed for the type — are in
[the Client's manual](client.md#a-supervisor-never-goes-back).

**Where an Agent reports both, what it *runs* decides**. The Package must be greater
than the `service.version` the Agent reports, and the package status is not read beside it —
neither to admit a Package the running version refuses, nor to refuse one it admits. A statement
about the present outranks a record of an install, which outlives the binary it describes. So a
claim the Agent's own program denies never holds the package back, in either direction: a Client
reporting `supervisor 0.4.2` installed while reporting that it runs 0.4.0 — a state directory that
outlived its binary, a self-update that staged and did not take effect — is offered 0.4.1, where
the claim used to refuse it as a downgrade and strand the host for good. The `409` names the
version that decided and says that the claim was not consulted.

**What this costs, and whom it touches.** Where a program reports a version *above* the Package that
carries it, no Package below that number reaches it any more, and where it reports one below, a
Package between the two can move its package backwards — a Collector calling itself `0.98.0` under
an `otelcol` Package at `2.0.0` can be assigned a `1.5.0`. Nothing moves on its own: a rollout is
an explicit act and you see the version you press. This reaches only Agents that report a
`service.version` of their own — the Client itself, and an OpAMP-aware Managed Process such as a
Collector carrying `opampextension`. An Icinga 2 or a GLPI Agent reports none, so its Packages
keep being matched on the package status alone. **Number a Package the way the program it carries
numbers itself**, and neither case arises.

Versions are still kept side by side — a new version is a new Package, and the older artifact
stays in the store — but **taking a bad version back is not a rollout**:

- on the host, the version a package superseded is retained for `retain_previous_secs` and put
  back when the new one fails its health gate (see the Client manual, *Package updates: rollback
  and retention*);
- a Client that will not stay up after its own self-update goes back by itself;
- fleet-wide, what is left is publishing the older content **as a new, greater version** — which
  is honest about the fact that the fleet moves forward, and is the only thing the matching rule
  will carry.

**Deleting.** `DELETE /api/v1/packages/otelcol-contrib/0.109.0` removes the Package — its entries,
artifacts and metadata — and takes it out of every Deployment that held it; the entry route with a
platform removes just that one entry. Both, and `DELETE` on a Deployment, are refused (`409`)
while an Agent's assignment pins what they name: roll those Agents out through another Deployment,
or forget them, first. Nothing is uninstalled by any of them.

**Building and signing**. The helper that ships with the Client writes the
artifact, hashes it, and signs it:

```console
$ opamp-fleetctl package pack --out promtail-3.0.0.tar.gz ./promtail   # prints the sha256
$ opamp-fleetctl package keygen --out fleet-signing.pk8                # prints the public key
$ sig=$(opamp-fleetctl package sign --key fleet-signing.pk8 --agent-type promtail --version 3.0.0 \
      promtail-3.0.0.tar.gz)
```

`pack` writes `.tar.gz` or an AES-256-encrypted `.7z`, and names the member the way the receiving
Supervisor will look for it. A Client opens those two and `.zip`; an artifact that is none of the
three is taken to *be* the program. [The rollout walkthrough](rollout.md) puts the whole sequence
together.

The download route sits on the **Agent plane**, outside `[rest.auth]` and behind the same
TLS handshake as `/v1/opamp`. A downloading Client presents its client certificate, and it presents
it to this Server's own origin and to no other host. Guarding the Operator plane therefore cannot
break a rollout. The content hash and the signature are what protect an installed binary.

`keygen` prints the public key as hex — that value is the Client's `[packages] verification_key`.
A Client without it takes no package at all, its own update included, and says so at startup. Give every Client the
key.

### A host fetches only what its Agents are offered

The download route serves an uploaded artifact only to a host whose certificate speaks for an
Agent that is offered that artifact — its Agent type, version and Platform — by a rollout. A host
speaks for the Agents that reported with its certificate, and a host marked as a Gateway for any
Agent. An artifact stays offered until the Agent's assignment changes, so an Agent that echoed its
offer and then failed to install can fetch it again. A version saved in a Deployment but not yet
released by a rollout is offered to no one and cannot be fetched by anyone.

Every other request for an artifact is answered `404` with the same status, body and headers as
a request for an artifact the store does not hold: an artifact released to another host's Agents,
one released to nobody yet, an entry that carries no signature, and any request over a certificate
that names no host. A malformed type, version or Platform is still answered `400`, and a
certificate that is not a member's still `401`. Each refused fetch leaves a `download.refused`
entry in [the audit record](#the-audit-record) with `check` `not offered`, the host, the
certificate's serial and the type, version and Platform asked for. The certificate is admitted
before the route decides what it may fetch, so a refused fetch leaves both a `download.admitted`
and a `download.refused` entry: a `download.admitted` says the certificate was let in, not that
an artifact was served. Such a refusal is no failed admission, so it does not count toward
[the throttle](#repeated-failures-are-throttled). Each download, served or refused, takes a token
from the host's bucket ([How often a member may be heard](#how-often-a-member-may-be-heard)); for
a Gateway, from its aggregate bucket.

A `404` for an Agent that was offered an artifact therefore means one of three things: its host's
certificate names no host (provision it with `urn:opamp-fleet:host:<id>`, see
[`[client_ca]`](#client_ca)), the Agent now reports another Agent type than the Package was built
for, or a later rollout changed what it is offered.

A Client behind a Gateway receives uploaded artifacts through the Gateway.
Its offer names the path on this route, which it resolves against its own endpoint, the Gateway.
The Gateway fetches each such artifact from this Server once, with its own certificate, as soon
as it relays an offer of it, and serves it on the same path only to the hosts whose Agents it
relayed that offer to. So the Gateway's host must be marked as a Gateway, and each artifact costs
this Server one download, counted against the Gateway's aggregate bucket and recorded under the
Gateway's host, however many Agents behind it install it. A Client that asks while the Gateway is
still fetching is answered `503` with `Retry-After: 30` and asks again. Every artifact is offered
as a path, which a Client behind a Gateway resolves against the Gateway. How
the Gateway holds what it fetches is in
[the Client's manual](client.md#the-package-cache).

## The REST API

The OpenAPI document at `/api/v1/openapi.json` is the contract; `/api/v1/docs` renders it. Every
error response carries a JSON body with an `error` field, so a generated client has something to
show. All of it is served on the Operator plane (`127.0.0.1:4321` by default), over TLS 1.3, and,
when [`[rest.auth]`](#the-operator-plane-restauth) is configured, needs Basic credentials.
`[rest.auth]` is required whenever the plane listens off the loopback.

| Method & path | What it does |
|---|---|
| `GET /api/v1/agents` | The whole fleet: every Agent, its attributes, capabilities, the Deployment that claims it, what is rolled out to it and what waits, package installations, health, and sync state. |
| `POST /api/v1/agents/{instance_uid}/restart` | Queue a restart of that Agent's Managed Process. Delivered on the next exchange — pushed over WebSocket, on the next poll over plain HTTP. Only Supervisor-backed Agents accept it; a Client's own Agent has no process to restart. |
| `PUT /api/v1/agents/{instance_uid}/labels` | Set this Agent's labels — see [Labels: rollout channels without touching the host](#labels-rollout-channels-without-touching-the-host). Body: `{"labels": {…}}`; an empty map clears them. |
| `DELETE /api/v1/agents/{instance_uid}` | Forget this Agent — see [Forgetting an Agent](#forgetting-an-agent) below. Reaches no host. `409` while it is still reporting. |
| `POST /api/v1/agents/{instance_uid}/rollout` | The per-Agent rollout act: releases the Deployment that claims this Agent to it, replacing its assignment. Empty body, or `{"deployment": "…"}` naming that Deployment. `409` when the Agent is in no Deployment, in a conflict, or in another one than named, when the Deployment holds nothing or a Package with an unsigned entry, and when the press would change nothing because the Package it holds is no upgrade (the reason names the version). |
| `GET /api/v1/configurations` | Every Configuration — the saved revision each, with the Deployments that hold it. |
| `GET /api/v1/configurations/{name}` | One Configuration. |
| `PUT /api/v1/configurations/{name}` | Create it, or replace its saved revision. Body: `{"body": "…", "service_name": "…", "role": "…"}` — `role` may be omitted; without `service_name` it is refused `400`, as is a `selector`. **Distributes nothing**. |
| `DELETE /api/v1/configurations/{name}` | Remove it, and take it out of every Deployment that holds it. `409` while an Agent's assignment pins it, saying how many. |
| `GET /api/v1/packages` | Every stored Package (never the artifact bytes), each with its entries — their hash, size, signature and `signature_state` — and the Deployments that hold it. |
| `PUT /api/v1/packages/{agent_type}/{version}` | Create a Package. The body has no writable field — `{}`. **Distributes nothing**. The version is SemVer 2.0.0: any other is answered `400`, naming it — `1.19.0` for upstream's `1.19`. |
| `GET /api/v1/packages/{agent_type}/{version}` | One Package. |
| `PUT /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}` | Upload one platform's artifact (the raw body); new bytes remove the entry's signature. `409` while the Package is rolled out to an Agent. The signature is written through the entry's signature route. |
| `PUT` / `DELETE /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature` | Record or remove that entry's Ed25519 signature. Body: `{"signature": "<hex>"}`. `404` for an entry that does not exist, `400` for an empty or malformed signature, `409` while the Package is rolled out to an Agent. The answer is the Package, with the entry's `signature_state`. |
| `DELETE /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}` | Remove one entry. `409` while the Package is rolled out to an Agent. |
| `DELETE /api/v1/packages/{agent_type}/{version}` | Remove the Package, and take it out of every Deployment that holds it. `409` while an Agent's assignment pins it, saying how many. Uninstalls nothing. |
| `GET /api/v1/packages/{agent_type}/{version}/file?os=…&arch=…` | The artifact bytes — where an offered `download_url` points. **The one route on the Agent plane** (`:4320`), and never guarded by `[rest.auth]`: it is not in the OpenAPI document for the same reason. It requires a client certificate from the client CA in the handshake; a bootstrap certificate is answered `401`. It serves only an artifact offered to an Agent the host speaks for, and answers every other request `404`, as for an artifact that does not exist. |
| `GET /api/v1/deployments` | Every Deployment, with its channel, its Packages, its Configurations, and the three reach counts. |
| `PUT /api/v1/deployments/{name}` | Create one or re-aim it. Body: `{"selector": {…}}` — **never empty** (`400`). **Distributes nothing**. |
| `GET` / `DELETE /api/v1/deployments/{name}` | One Deployment; `DELETE` is `409` while an Agent's assignment names it, saying how many, and uninstalls nothing. |
| `PUT /api/v1/deployments/{name}/selector` | Re-aim it. Never distributes. |
| `PUT /api/v1/deployments/{name}/packages/{agent_type}/{version}` | Put a Package in the channel. `409` on a second of an Agent type it already holds; `?replace=true` swaps it. `404` for a Package nobody uploaded. |
| `DELETE /api/v1/deployments/{name}/packages/{agent_type}/{version}` | Take it out. Never refused for being rolled out: the next press drops it from the Agents' release. |
| `PUT` / `DELETE /api/v1/deployments/{name}/configurations/{configuration}` | Put a Configuration in the channel, or take it out. `404` for a Configuration the Server does not hold, or, on `DELETE`, one the channel does not hold. **Distributes nothing**. |
| `POST /api/v1/deployments/{name}/rollout` | Roll it out to every Agent it claims and would move — its Packages and Configurations in one release, the moment a rollout starts. Agents another Deployment also claims are skipped and reported as conflicts. `409` while the channel holds no Package and no Configuration, and `409` naming each Package and platform while any entry of a Package it holds lacks a signature. |
| `GET` / `POST` / `DELETE /api/v1/enrolment/window` | Read, open or close the enrolment window — see [Enrolment](#enrolment-a-new-host-approved-by-an-operator). `POST` body: `{"open_for_secs": n}`, 1 to 86400. `404` while `[enrolment]` is not configured. |
| `GET /api/v1/enrolments` | The pending enrolment requests, oldest first, each with its `id` — the fingerprint the enrolling Client logs. |
| `POST /api/v1/enrolments/{id}/approve` | Sign that request and hand the host its certificate. `404` for an unknown or expired id. |
| `POST /api/v1/enrolments/{id}/reject` | Refuse that request and close its connection. `404` for an unknown or expired id. |
| `GET` / `POST /api/v1/bootstrap-certificates` | List the valid bootstrap certificates the Server issued, or issue one — see [Bootstrap certificates](#bootstrap-certificates-issued-by-the-server). `POST` body: `{"subject": {…}, "validity_days": n, "password": "…"}`, `subject.organization`, `subject.organizational_unit` and `password` required (`400` naming the one missing); the answer carries the certificate and never its key, which is in the PKCS#12 file. `409` without `[enrolment] bootstrap_ca_key_file`. |

The package routes answer `404` while package delivery is not configured on this Server.

### Whom a rollout actually reaches

The counts live on the **Deployment**, because that is what aims (see *Reading the counts* above).
A Package carries no count of its own — it aims at nobody — and answers the question by naming the
channels that hold it. A Package in no channel is stored and unreachable, which is the state a Selector
matching nobody used to be.

`targeted_agents` is the Agents a rollout act would change — their release differs from what their
assignment pins; `claiming_agents` is who is in the channel
whatever they run; `conflicting_agents` is who this channel cannot reach because a second one claims
them too. It answers for the fleet **as reported so far**: a channel aimed at hosts that have not
connected yet legitimately reaches nobody, which is why these are counts to be read rather than
errors to be raised.

### Labels: rollout channels without touching the host

A Deployment's Selector aims it at the Agents whose attributes match it — and the
attribute a staged rollout actually wants, `channel = "beta"`, is one you invent. Until now it could
only be invented in `[attributes]` in `supervisor.toml`, so moving a host between channels meant
editing a file **on that host** and restarting it.

**Labels are that attribute, set from here**:

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' \
       -d '{"labels": {"channel": "beta"}}' \
       https://127.0.0.1:4321/api/v1/agents/<instance-uid>/labels
```

A label is matched exactly like a reported attribute, by the Selector of the Deployment the Agent
belongs to — which carries its Configurations and its Package alike. So trying a new collector
binary on a few hosts is a Deployment aimed at `channel = beta` plus this call on the hosts that
should get it first — and moving a host back is the same call with the value it had.

The same call carries any other partition: `{"labels": {"region": "eu-central"}}` or
`{"labels": {"tenant": "acme"}}`. The Server treats all of them identically, because it knows none
of them — see [Channels are a partition](#channels-are-a-partition-not-a-default).

It takes effect at once: a connected Agent is pushed whatever its new channel gets, rather than waiting
for its next poll.

**A label may not restate an attribute the Agent reports** — that is refused with `409`, naming the
key. Reported attributes are not annotations: `os.type` and `host.arch` decide which artifact fits
the machine and `service.name` decides which packages fit it at all. If a
label could outrank them, a slip here would offer a host a binary built for another one. Where an
Agent reports something wrong, the fix belongs in that host's `supervisor.toml`, where the wrong value
comes from.

If an Agent *starts* reporting a key that was labelled earlier, the reported value wins and the
fleet row marks the label as shadowed — set, and matching nothing.

**A label whose key starts with `fleet.` is refused with `400`.** That space is the Server's own.

**Label the Client once.** A Client presents an Agent for itself — the one that reports
`supervisor.kind.*` — and one per Supervisor. The labels set on the Client's own Agent hold for its
other Agents too, below their own labels: a Supervisor Agent labelled `ring = late` stays in that
ring whatever its Client is labelled. The Server tells a Client's Agents apart by the Host they
arrived over. Behind a Gateway it groups them by the `host.id` they report, or by `host.name`
where they report no `host.id`. Where such a group holds more than one Client Agent — two Clients
on one machine behind one Gateway — no Agent of it inherits anything, and the fleet view marks them
as ambiguous. The Agents tab shows inherited labels on each Agent, marked as such.

**What a Selector matches** is each Agent's effective description, the same for every Deployment.
For each key it takes the first source that has it:

1. `fleet.host.country`, `fleet.host.state`, `fleet.host.locality`, `fleet.host.organization`,
   `fleet.host.site` (the organizational unit) and `fleet.host.organization_id` — the subject
   values of the Host the Agent arrived over directly. An Agent behind a Gateway has none.
2. What the Agent reported: identifying attributes, then non-identifying ones. A reported
   attribute whose key starts with `fleet.` is left out and listed in `ignored_attributes` on its
   fleet row, so no Agent can claim another Host's values.
3. The Agent's own labels.
4. The labels of its Client Agent.

**Labels are yours, not the Agent's.** They never travel to it; the Agent only ever experiences the
effect, which is the configuration and the software it is offered. They are part of the Agent's
record on the Server and survive a restart. They follow the Agent when the Server re-keys it, and
**forgetting an Agent removes them**: an Agent that comes back starts with the labels of its Client
Agent only, so label the Client Agent rather than each Agent where you can.

### Forgetting an Agent

A host that was decommissioned leaves a row behind, and nothing ages it out. `DELETE
/api/v1/agents/{instance_uid}` — the `✕ forget` action on a fleet row — drops what this Server knows
about that Agent.

**It does nothing on the machine.** No process is stopped, nothing is uninstalled, and nothing is
revoked: a certificate proves *fleet membership* and its host, never which Agent is speaking, so
forgetting one Agent has nothing of it to take away. To shut a host out, [revoke its
certificate](#revocation-withdrawing-a-certificate). A Client that is still running and still pointed at this
Server reports again within its polling or heartbeat interval and the row comes back. Forgetting
tidies the view; **to remove an agent for good, stop it on the host** (`supervisor service
uninstall`) and then forget it here.

It is refused with `409` while the Agent is still reporting — connected, and heard from within the
staleness budget. That is not caution for its own sake: the record holds the hashes that tell this
Server not to re-offer what an Agent already has, so forgetting a live Agent has its configuration
sent again, and a Managed Process restarts whenever a configuration arrives. Stop the agent first,
or wait for it to fall silent. An Agent that is already disconnected can be forgotten at once.

The same applies to one that comes back later: it is offered its configuration, its connection
settings, and its packages afresh. The packages cost nothing — the Client re-installs nothing whose
content hash it already has — but the configuration is applied again, which for a managed agent is
one restart. That is the price of forgetting something that was not really gone.

**Its labels go with it.** They are part of the Agent's record, so an Agent that comes back is
labelled only by what its Client Agent's labels give it. The Host it arrived over stays until
no certificate naming it is valid (see [Hosts](#hosts)).

**Its binding goes with it.** The Agent's `instance_uid` is released from the Host it was bound
to, so its next report binds it to the host whose certificate carries that report. Forgetting an
Agent that still runs elsewhere lets the next host that reports it take it.

Nothing expires on its own: there is no retention sweep and no inactivity timeout, so a row stays
until someone forgets it.

## Authentication

The Agent plane admits by **client certificate alone**; see
[Mutual TLS](#mutual-tls-proving-who-is-on-the-connection). It has no credential of its own, and
`server.toml` has no `[auth]` section: one that is present is refused at startup, naming `[auth]`.
`/v1/opamp` and the download route read no `Authorization` header and send no
`WWW-Authenticate` challenge. A refusal behind the handshake — a revoked certificate, or a
bootstrap certificate on the download route — is answered `401`.

The Operator plane is the one with a credential, [`[rest.auth]`](#the-operator-plane-restauth)
below. It never reaches an Agent's host.

### Credentials are kept as hashes

No credential in `server.toml` authenticates on its own, so a copy of the file — in a backup, a
diff, configuration management — admits no host and signs in no operator. An operator's Basic
password is listed by its Argon2id hash, with at least `m=19456`, `t=2` and `p=1`. A value in clear
or a weaker hash is refused at startup, naming the section and the user without repeating the
value. Make each entry with the Server itself:

```console
$ server hash-credential --basic
secret:
$argon2id$v=19$m=19456,t=2,p=1$…
```

`--basic` is the one scheme; it reads the password from standard input, without showing it on a
terminal, and prints the hash to paste.

The package download route sits outside `[rest.auth]`: it is guarded by the client certificate
the handshake requires, and its content hash and signature protect what it serves.

### Repeated failures are throttled

`[admission_throttle]` limits how often one peer address may fail admission:

```toml
[admission_throttle]
max_failures = 10      # failures within the window that start a back-off
window_secs = 60
backoff_secs = 300     # how long the address is answered 429
```

Every `401` on `/v1/opamp` and on the download route counts as a failure of the peer's IP address.
An address that reaches `max_failures` within `window_secs` is in back-off for `backoff_secs`.
During the back-off each request is answered `429` with `Retry-After` set to the seconds remaining,
before anything else is checked. A WebSocket upgrade is refused the same way before it completes.
A successful admission clears nothing — behind a shared address a member's success would wipe a
guesser's count — so failures only age out of the window. On the Agent plane a `401` follows a
handshake that succeeded, so the throttle bounds what a refused host that keeps retrying costs in
handshakes, revocation lookups and audit entries. The Operator plane counts its own `401`s the same
way, in a table of its own. `0` for any of the three keys is refused at startup.

### How often a member may be heard

A certificate admits a member; `[agent_rate_limit]` bounds how often it is heard after that:

```toml
[agent_rate_limit]
messages_per_sec = 10            # tokens a host's or an Agent's bucket gains per second
burst = 300                      # that bucket's capacity; a new bucket starts full
gateway_messages_per_sec = 500   # tokens a marked Gateway's aggregate gains per second
gateway_burst = 10000            # the aggregate's capacity
```

Each message on `/v1/opamp`, over either transport, takes one token before anything else is done
with it, and so does each request on the package download route once the certificate is admitted.
A message that cannot be decoded is counted too. The bucket is:

- the host the certificate names;
- the certificate's issuer and serial, for a certificate an operator provisioned that names no
  host yet;
- the peer address, an IPv6 one by its /64, on an enrolment connection: one bootstrap certificate
  may serve the whole fleet;
- for a host marked as a Gateway, two buckets, and a message takes a token from both: the bucket
  of the Agent it names, sized by `messages_per_sec` and `burst`, and the Gateway's aggregate,
  sized by the `gateway_` keys. A message naming no valid `instance_uid`, an undecodable one and
  a download count in the aggregate alone. A message carrying an enrolment request through the
  Gateway takes from neither, so enrolments never spend what the Gateway's members need. Once the
  bootstrap certificate its proof names parses and a bootstrap CA of `[enrolment]` issued it, it
  takes a token from that certificate's bucket, sized by `messages_per_sec` and `burst`, and one
  from the Gateway's enrolment aggregate, sized by the `gateway_` keys, so one bootstrap
  certificate cannot spend another's tokens. One that fails that check takes a token from the
  Gateway's bucket for unchecked enrolments alone, sized by `messages_per_sec` and `burst`, and is
  answered `BadRequest`. Marking or unmarking a Gateway takes effect at its
  next message.

A message past the limit is not processed: no record changes and no certificate is signed. It is
answered with the message's own `instance_uid` and `error_response` `Unavailable` with
`retry_info` of 30 seconds, on plain HTTP in the body of a `200`. The connection stays open. A
Client waits the 30 seconds, and the next message the Server processes from that Agent is asked
for a full report, so nothing is lost. A download past the limit is answered `429` with
`Retry-After: 30`; it is no failure toward `[admission_throttle]`, and the Client waits it out
before it asks again, for up to 30 minutes per download. Beyond this limit the Server
honours the protocol's error and retry semantics as well, and answers malformed input with
`BAD_REQUEST`.

Every refusal is recorded as `agent_rate.throttled`, naming the host (or the serial and the CA's
role), the `instance_uid`, the `bucket` that was empty (`agent`, `host` or `gateway`; for an enrolment request through a
Gateway `bootstrap` for its certificate's bucket, `enrolment` for the Gateway's enrolment
aggregate, `unchecked_enrolment` for its bucket for unchecked enrolments) and the
`route` (`opamp` with its `transport`, or `download`). Past ten a second from one address they are
counted in `agent_rate.throttled.aggregated`.

The default `burst` lets one full report from each of the 256 Agents a host may speak for through
after a reconnect. `messages_per_sec` times the offered `[connection_offer]
heartbeat_interval_secs`, or 30 seconds without one, is how many Agents one host can report for at
that interval; the Server logs a warning at startup naming both keys when that is below 256. The
buckets live in memory: the subjects and aggregates up to the certificate register's 100 000, the
Agents behind Gateways up to `max_agents`, and a full table forgets the bucket used least
recently. `0` for any key is refused at startup; no value switches the limit off.

### The Operator plane: `[rest.auth]`

`[rest.auth]` guards **the whole Operator plane** — `/api/v1/…`, the OpenAPI document, the API docs,
and the UI at `/`. With it, every request needs Basic credentials and anything else is answered
`401` with a `WWW-Authenticate: Basic` challenge. On a loopback `[rest] listen` the section is
optional, and the plane's address is what protects it. On any other address it is required: a
Server without it is refused at startup with a message naming both keys.

```toml
[rest]
listen = "0.0.0.0:4321"          # publishing it requires the section below

[rest.auth.basic_users]
fleet-admin = "$argon2id$v=19$m=19456,t=2,p=1$…"
```

Basic, and only Basic, because the audience is a browser and `curl`: the browser answers the
challenge by itself, so the bundled UI needs no login page, no session, and no cookie. Several users
are how a credential is rotated — add the new one, hand it out, remove the old — or how one
operator's is withdrawn without touching anyone else's.

**The operator tools carry it in the URL** they are given, which needs no new flag:

```console
$ curl --cacert ca.pem -u fleet-admin:secret https://127.0.0.1:4321/api/v1/agents
$ opamp-fleetctl package fetch … --server https://fleet-admin:secret@127.0.0.1:4321
```

Two limits worth stating plainly. It is **authentication, not authorization**: everyone listed can
do everything the plane offers — there are no roles, and one Server still manages one fleet. And
Basic sends a reusable password on **every** request. The plane always serves TLS 1.3, so the
password never crosses the network in cleartext, and `server.toml` holds only its Argon2id hash.

## Upgrading to admission by certificate alone

The Agent plane admits a Client by its client certificate alone and reads no `Authorization`
header: a Client or Gateway that sends one is admitted on its certificate, and the header is
ignored. A Client sends no credential, so a Server that still demands one answers it `401`.
**Upgrade the Server first, then its Clients and Gateways.**

1. **Delete the credential from `server.toml`.** Remove the `[auth]` section, and the credential
   keys `bearer_token_file`, `username`, `password_file`, `bearer_token` and `password` from
   `[connection_offer]`; a `[connection_offer]` left with neither `heartbeat_interval_secs` nor
   `endpoint` goes whole. The Server refuses to start while either remains, and says which:

   ```text
   server.toml: [auth] is refused — the Agent plane admits by client certificate alone; remove the section
   server.toml: [connection_offer] bearer_token_file is refused — the Agent plane admits by client certificate alone, so no credential is offered; remove the key
   ```

   A file the offered credential was read from can be deleted. `[rest.auth]` stays as it is.
2. **Start the Server.** Every Client that holds a valid certificate keeps connecting. A credential
   revocation in the persisted list is dropped when it is loaded, with one log line, and the list
   is written back without it.
3. **Upgrade the Clients**, through the self-update or by package. A Client sends no credential,
   ignores a leftover `[auth]` in `supervisor.toml` with a notice at startup, and drops an
   `Authorization` header a credential rotation left in its persisted connection settings,
   rewriting the file without it (see [the Client](client.md#a-leftover-auth)). A Gateway forwards
   no `Authorization` and shares its upstream connections among every Agent it carries.

## TLS

`[tls]` is required, and it turns **both listeners** into HTTPS/WSS listeners: with its certificate
and key, or on the Operator plane with those of [`[rest.tls]`](#resttls) when that section is set.
There is no plaintext port beside either of them. Every connection speaks TLS 1.3 alone, with the
three TLS 1.3 suites of the `ring` provider; a peer that speaks only TLS 1.2 cannot connect. Clients
use `wss://` or `https://` endpoints, and Clients trusting a private CA set `ca_file` in their own
`[tls]` section.

The same section names the CA a **client certificate** must chain to:
see [Mutual TLS](#mutual-tls-proving-who-is-on-the-connection).

### Bounds on every listener

Each plane is bounded before a request is parsed:

- **A connection cap per plane**: `max_connections` (default 10 000) for the Agent plane and
  `[rest] max_connections` (default 256) for the Operator plane. A connection past the cap is
  closed on accept, before the TLS handshake, while the ones already held keep working.
- **The TLS handshake** must complete within 10 seconds, and a peer has 30 seconds to send its
  HTTP/1 request headers.
- **HTTP/2** allows 100 concurrent streams per connection. A keep-alive ping goes out every 30
  seconds, and a peer that leaves one unanswered for 20 seconds is dropped.

Only the caps are keys, because they depend on the size of the fleet. The other bounds are the
same in every deployment.

## The fleet's own telemetry

`[telemetry_offer]` is where the fleet's Clients send their own metrics, logs, and
traces. Each signal is independent, and each is offered only to Agents that declare they can report
it:

```toml
[telemetry_offer]
metrics_endpoint = "https://collector.example:4318/v1/metrics"
traces_endpoint = "https://collector.example:4318/v1/traces"
logs_endpoint = "https://collector.example:4318/v1/logs"
[telemetry_offer.headers]
Authorization = "Bearer a-telemetry-token"
```

The endpoints are **full OTLP/HTTP URLs with path**. This Server appends no `/v1/metrics` for you:
guessing a receiver's routing is how telemetry disappears into a `404` nobody looks at.

**Nothing is configured on the Client.** The capability an Agent declares means "I can report to the
destination *you* name", so this section is the only place a destination comes from — and with no
section, no Agent sends anything.

What arrives: process metrics every 10 seconds (CPU, memory, uptime) for each Client's own process
*and* for every process it supervises; each Client's own log output as OTLP records; and a trace per
fleet operation — `package.install`, `config.apply` (a Managed Process's configuration, and a
Client's Supervisor set), `connection.settings.apply`, and `self.update`. Each carries its phases as
child spans and ends with the outcome the Client reported to this Server, so *which phase* a rollout
failed in is a question the trace answers. Nothing else is traced: the Clients' own message handling
would be a continuous stream with no outcome in it, and would bury the operations that have one.

A log record written during one of those operations carries that trace's id, so a backend holding
both signals can show the lines that explain a failure beside the span that failed. Each Agent's
Resource carries its identifying attributes, so one host's several Agents stay apart at the
receiving end.

Two limits worth knowing before you point this somewhere:

- **A cleartext destination is refused anywhere but the loopback**.
  `http://` is accepted only to the IP literals `127.0.0.1` and `::1`. The rest of `127.0.0.0/8`,
  the private ranges `10/8`, `172.16/12`, `192.168/16` and `fc00::/7`, link-local and carrier-grade
  NAT addresses are refused. The judgement is made on the parsed **address**: a host name over
  `http://` is refused, `localhost` included, and no name is resolved. The Agent refuses such a
  destination and reports the refusal back on the offer; it never warns and sends anyway. Every
  other destination is `https://` in TLS 1.3, so a Collector on the LAN, or one reached by name,
  needs TLS 1.3 in front of it. A destination that speaks only TLS 1.2 fails the handshake.
- **A Collector's internal telemetry does not come this way.** The Client must not touch a Managed
  Process's configuration, so what it reports about a Collector is what it can see from
  outside. Configure the Collector for its own internals as you would without OpAMP.

## Moving the fleet: connection settings

`[connection_offer]` is how the fleet is moved to a new heartbeat interval or a new endpoint
without touching every host. The Server compiles the section into one hash-gated offer, and every
Agent that accepts connection settings gets it, **verifies it by actually connecting**, and
switches only on success. An Agent that cannot connect with the offered settings keeps the ones it
has and reports the failure. An offer goes only to an Agent admitted with a certificate from the
client CA; an enrolling host receives none but the certificate it asked for.

The offer carries **no credential and no `headers`**:
the Agent plane reads no `Authorization`, so an offered one would be a value nothing reads. A
credential key in the section — `bearer_token_file`, `username`, `password_file`, `bearer_token`,
`password` — is refused at startup, naming the key. A Client that is offered `headers` by another
Server applies the rest of the offer and reports it `FAILED`, naming the header keys.

**The offered `endpoint` is never plaintext**. It is `wss://` or `https://`. A `ws://` or
`http://` endpoint is refused at startup with a message naming `[connection_offer] endpoint`, on
`127.0.0.1` and `::1` too: on plaintext no certificate proves the Server, so whoever listens on
that port of a host would be the Server for its Client. A development setup on the loopback names
its plaintext endpoint in `supervisor.toml` instead.

The standing offer carries no `tls` and no `proxy`: there is no configuration surface for them. A
`certificate` travels in an offer only as the answer to an Agent's signing request.

## What the Server does not do

- **It does not require a password on a loopback Operator plane.** `[rest.auth]` is optional
  there, because the address is the guard; it is required the moment the plane listens anywhere
  else.
- **It does not weigh a message by its cost.** Every message and download takes one token of
  `[agent_rate_limit]`, whatever it carries. The Operator plane is not rate-limited; it is
  guarded by `[rest.auth]` and `[admission_throttle]`.
- **It does not fetch packages from anywhere.** Every artifact is uploaded to it; it makes no
  outbound request for a package and holds no credential for a source.
- **It does not refuse an invalid signature.** With `[packages] verification_key` it reports one;
  each Client's own check decides what is installed.
- **It does not install itself as a service.** Run it under whatever supervises services on the
  host — the Client is the end that ships its own service integration.
- **It has no user model and no multi-tenancy.** One Server manages one fleet.
