# The Server

[← User Manual](README.md) · [The Client →](client.md)

The Server is the control plane: it holds the configuration the fleet should
run, tracks what every Agent reports back, distributes software, and exposes all
of it as an OpenAPI-described REST API. It runs on Linux, as an ordinary
foreground process — unlike the Client, it does not install itself as a service.

- [What the Server does](#what-the-server-does)
- [Running it](#running-it)
- [Configuration reference](#configuration-reference)
- [Where the Server keeps its state](#where-the-server-keeps-its-state)
- [Upgrading to one data directory](#upgrading-to-one-data-directory)
- [How a host joins the fleet](#how-a-host-joins-the-fleet)
- [Security decisions in the log](#security-decisions-in-the-log)
- [Configurations: what the fleet runs](#configurations-what-the-fleet-runs)
- [Packages and Deployments: distributing software](#packages-and-deployments-distributing-software)
- [The REST API](#the-rest-api)
- [Authentication](#authentication)
- [The operator's socket](#the-operators-socket)
- [Plain HTTP behind a reverse proxy](#plain-http-behind-a-reverse-proxy)
- [The fleet's own telemetry](#the-fleets-own-telemetry)
- [Moving the fleet: connection settings](#moving-the-fleet-connection-settings)
- [What the Server does not do](#what-the-server-does-not-do)

> **Plain HTTP behind a reverse proxy.** The Server terminates no TLS: both
> planes speak plain HTTP, on any address, and a reverse proxy in front of it
> ends TLS. `[tls]`, `[rest.tls]`, `[client_ca]`, `[enrolment]` and
> `[agents.auth]` are **refused at startup**, naming the section, and `server
> pki` is removed. The Agent plane admits an Agent by the bearer access token
> its host holds ([How a host joins the fleet](#how-a-host-joins-the-fleet)).
> The proxy is where TLS lives and the only thing that should reach the Server's
> ports: the operator's Basic password, every credential of the enrolment and
> every package cross the hop between them in the clear, and the peer's address
> is the one the proxy writes in `X-Forwarded-For` ([Plain HTTP behind a reverse
> proxy](#plain-http-behind-a-reverse-proxy)).

## What the Server does

- **Distributes Configurations and packages through Deployments — when you say
  so**: a Deployment's Selector aims, saving stores, an explicit rollout act of
  the Deployment releases, and every push is gated on a content hash so nothing
  the Agent already runs is sent again.
- **Tracks the fleet**: which Agents exist, what they report, whether they are
  connected, healthy, and in sync, which Deployment claims them and what it
  would release, and which packages they have installed.
- **Distributes packages**: versioned Sets of uploaded, signed artifacts, held
  by a Deployment beside its Configurations — released only by an explicit
  rollout act, and only ever forwards: a Package reaches an Agent when it is an
  upgrade over the version that Agent reports installed, never when it would
  move it back or leave it where it is.
- **Restarts a Managed Process on request** — an Agent backed by a Supervisor
  accepts a restart command.
- **Offers new connection settings**: a heartbeat interval or an entirely
  different endpoint, which each Agent verifies by connecting before it
  switches.
- **Enrols a host with its Space's key and admits it by a bearer token**: a host
  that presents a valid enrolment key registers itself as a client and receives
  credentials, with no operator approval; every request an Agent then sends
  carries an access token
  ([How a host joins the fleet](#how-a-host-joins-the-fleet)).
- **Serves two listeners over plain HTTP**, behind a proxy that terminates TLS:
  OpAMP over both transports, the package download and the enrolment routes on
  one, the REST API, the OpenAPI document and its docs page, and a rudimentary
  UI on the other. Beside them it answers the operator's `classis-cli` on a
  Unix socket ([The operator's socket](#the-operators-socket)).

## Running it

```sh
server --config /etc/opamp/server.toml
server --version
```

| Flag              | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--config <path>` | The TOML configuration file. Without it, the file `CLASSIS_SERVER_CONFIG` names; without both, `server.toml` in the working directory when it exists, and otherwise none — the Server then starts from its defaults and its environment ([Configuration from the environment](#configuration-from-the-environment)). A file named by `--config` or `CLASSIS_SERVER_CONFIG` that does not exist fails startup, naming the path. A Server configured by nothing listens on the loopback. |
| `--version`       | Print the version and exit — the full string, `1.2.3+<commit>` for a release and `1.2.3-dev+<commit>` for a build on the way to one.                                                                                                                                                                                                                                                                                                                                                   |

Any other argument prints usage and exits with status 2. Logging goes to stderr
and its level is controlled by the `RUST_LOG` environment variable (default
`info`); its form by [`[log] format`](#log); everything else is in the
configuration file and the `CLASSIS_SERVER__…` variables over it. `server pki`
is removed: the Server holds no certificate.

Stopping the Server is `SIGTERM`/`Ctrl-C`. Configurations and packages are
persisted to disk, so a restart resumes with the same fleet state; Agents
reconnect on their own.

The Server refuses to start with `[tls]`, `[rest.tls]`, `[client_ca]`,
`[enrolment]`, `[agents.auth]`, an `[auth]` section, or a credential key in
`[connection_offer]`, and the refusal names the section: the Server speaks plain
HTTP, offers no credential to the fleet, and admits an Agent by the access token
its host holds ([How a host joins the fleet](#how-a-host-joins-the-fleet)). For
a fleet, `classisctl pki init` makes the certificate the proxy presents and the
CA that signs it ([Setting up a fleet](setup.md#1-make-the-certificates)).

There are **two listeners, split by audience**: the one the fleet talks to, and
the one you talk to. Both speak plain HTTP; the proxy in front of them ends TLS.

**The Agent plane** — `listen`, `127.0.0.1:4320` by default. Serving the fleet
is one deliberate line, `listen = "0.0.0.0:4320"`.

| Path                                           | What it is                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/v1/enrol`                                    | Where a host registers with its Space's enrolment key ([How a host joins the fleet](#how-a-host-joins-the-fleet)). `POST` only; the key is the credential.                                                                                                                                                                                                                                                                                                                                                      |
| `/v1/token`                                    | Where a registered host asks for its access token, with its client credentials. `POST` only.                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `/v1/opamp`                                    | The OpAMP endpoint. `GET` upgrades to WebSocket, `POST` is the plain-HTTP exchange — the same path serves both. Needs `Authorization: Bearer <access token>`.                                                                                                                                                                                                                                                                                                                                                   |
| `/api/v1/packages/{agent_type}/{version}/file` | An artifact's bytes: the one `/api/v1` route that belongs to the Agents, because the `download_url` in a package offer is a path the Client resolves against _its own_ endpoint. It sits outside the Operator plane's `[rest.auth]` and, like `/v1/opamp`, needs the host's access token. A host is served only the artifact offered to one of its own Agents, and every other request is answered `404` ([A host fetches only what its Agents are offered](#a-host-fetches-only-what-its-agents-are-offered)). |
| `/v1/install.sh`, `/v1/install.ps1`            | The two install scripts, served to a host that holds no credential yet — a host fetches one and pipes it to `sh`/PowerShell to install the Client and enrol it ([How a host joins the fleet](#how-a-host-joins-the-fleet)). `GET`; no token. Their bytes are compiled into the Server and identical for every host.                                                                                                                                                                                             |
| `/v1/install/{os}/{arch}`                      | The Client archive of the release this Server is built from, fetched by those scripts. `GET`; no token. The platform is fixed by this build, never named by the caller; only the signed `supervisor` package the operator has uploaded for this version is served, and every other request — an unknown platform, no such artifact, an unsigned entry, no store — is one identical `404`.                                                                                                                       |

The Agent plane asks no peer for a client certificate. `/v1/enrol`, `/v1/token`
and the install routes stand outside bearer admission — a host that has not
enrolled has nothing to present — and authenticate by what they carry (an
enrolment key, a client secret) or by nothing at all; `/v1/opamp` and the
download route admit a request by its access token, and answer one without a
valid token `401` ([How a host joins the
fleet](#how-a-host-joins-the-fleet)).

**The Operator plane** — `[rest] listen`, `127.0.0.1:4321` by default:

| Path                                         | What it is                                                                                                                           |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `/api/v1/…`                                  | The REST API.                                                                                                                        |
| `/api/v1/openapi.json`                       | The OpenAPI document — the contract to generate a client from. It describes this plane, so the artifact download above is not in it. |
| `/api/v1/docs`                               | Interactive API documentation (Redoc, vendored and served from this origin, so it works offline).                                    |
| `/`                                          | The bundled UI: one embedded page, no frontend toolchain. It is deliberately rudimentary — the API is the product.                   |
| `/ui.css`, `/ui-carbon.css`, `/ui-quiet.css` | The bundled UI's three looks, embedded beside the page; its style combo chooses between them.                                        |

The Agent plane is guarded by access tokens; the Operator plane has a credential
of its own, [`[rest.auth]`](#the-operator-plane-restauth). This port carries the
authority to reconfigure and re-package the whole fleet, so its default address
is the **loopback**. There `[rest.auth]` is optional, and the address is what
protects the plane. Reach it from another host through an SSH tunnel (`ssh -L
4321:127.0.0.1:4321 <server-host>`), or publish it deliberately with `[rest]
listen = "0.0.0.0:4321"`. Off the loopback `[rest.auth]` is required, and a
Server without it is refused at startup with a message naming both keys.

Each plane holds a bounded number of connections: `max_connections` for the
Agent plane and `[rest] max_connections` for the Operator plane. A connection
past the cap is closed on accept, and the connections already held keep working.
See [Bounds on every listener](#bounds-on-every-listener).

### In a container

The Server ships as an image and nowhere else:
`ghcr.io/neteye-platform/classis-server`, for `linux/amd64` and `linux/arm64`, tagged
with each release's exact version and with nothing else — there is no `latest`.
Deploy it **by its digest**, which the release notes name, not by its tag: the
attestation names the digest, and a tag is only a name for it. Verify the digest
before you deploy it:

```console
$ gh attestation verify oci://ghcr.io/neteye-platform/classis-server@sha256:<digest> \
    --repo neteye-platform/classis \
    --signer-workflow neteye-platform/classis/.github/workflows/release.yml
```

The image holds the binaries the release built and checked for its version — the
Server and the operator's `classis-cli`, Linux only — on
`gcr.io/distroless/cc-debian13:nonroot` pinned by digest: glibc, CA certificates
and time zone data, and no shell and no package manager. Its SBOMs are the
release assets `server_<version>_linux_<arch>.cdx.json` and
`classis-cli_<version>_linux_<arch>.cdx.json` for the image's architecture; the
base's own packages are not in them and are named by the
`org.opencontainers.image.base.digest` annotation.

| Property                     | Value                                                                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Entrypoint                   | `/usr/local/bin/server`; arguments after the image name are the Server's, such as `--config`                                                      |
| Operator CLI                 | `/usr/local/bin/classis-cli`, the same release build, Linux only; run it with `docker exec`                                                       |
| User                         | UID and GID `65532`, numeric; no capability is needed, both ports are above 1024                                                                  |
| Data directory               | `/var/lib/classis`, a volume owned by `65532`                                                                                                     |
| Operator's socket            | `/run/classis/admin.sock`, the default `admin_socket`; on a read-only root filesystem its directory must be a writable mount owned by `65532`     |
| Working directory            | `/`, which `65532` cannot write, so the `server.toml` read without `--config` is never one on the volume                                          |
| Ports                        | `4320` (Agent plane) and `4321` (Operator plane)                                                                                                  |
| Environment it sets          | `CLASSIS_SERVER__DATA_DIR=/var/lib/classis`, `CLASSIS_SERVER__LISTEN=0.0.0.0:4320`, `CLASSIS_SERVER__REST__LISTEN=0.0.0.0:4321`, and nothing else |
| Configuration, keys, secrets | none; you mount them as files                                                                                                                     |

Because both planes listen off the loopback inside the container, the Server
requires `[rest.auth]` there. The image carries none, so started with nothing
mounted it names the missing key and stops — it never serves the Operator plane
without authentication. Put the image behind the reverse proxy that terminates
TLS; the Server admits the Agents by their access tokens. Mount every password
or credential file read-only, and name their paths in the configuration. The
image works with a read-only root filesystem; the Server writes under its data
directory and at its admin socket alone, and a socket cannot be created on a
read-only filesystem: give `/run/classis` a writable mount owned by `65532`, or
the Server cannot bind its socket and stops at startup.

```console
$ sudo install -d -m 0700 -o 65532 -g 65532 /var/lib/classis-run
$ docker run -d --name classis-server --read-only \
    -p 4320:4320 -p 4321:4321 \
    -v classis-data:/var/lib/classis \
    -v /var/lib/classis-run:/run/classis \
    -v /etc/classis:/etc/classis:ro \
    ghcr.io/neteye-platform/classis-server@sha256:<digest> \
    --config /etc/classis/server.toml
```

A bind mount for the data directory must be writable by UID `65532`; so must the
one at `/run/classis`. The example assumes rootful Docker without user-namespace
remapping. With a rootless or remapped runtime, create the socket directory with
the mapped UID and GID instead. The image carries `classis-cli` beside the
Server, at `/usr/local/bin/classis-cli` (Linux only). Because the socket mount
puts the socket at the path the CLI looks for by default, run it inside the
container, where it speaks as UID `65532`, the Server's own account and the
socket's owner:

```sh
docker exec classis-server /usr/local/bin/classis-cli space create lab
```

To reach the socket from the host instead, build the CLI from a checkout and name
the host path:

```sh
cargo build --release -p classis-admin
sudo ./target/release/classis-cli --socket /var/lib/classis-run/admin.sock space create lab
```

The caller must be root or the account that owns the socket.

There is no `HEALTHCHECK` — the image has no shell to run one. An orchestrator
probes over HTTP on the Operator plane: `GET /livez` and `GET /readyz` on
`4321`, which answer without a credential
([Liveness and readiness](#liveness-and-readiness)).
A TCP connection to `4320` only shows that the port is open. The `debug` variant
of the base, which has a shell, is for inspecting a problem locally; it is not
published.

To build the image yourself from a checkout, on a system whose glibc is no newer
than Debian 13's, copy both binaries under the names the Containerfile expects:

```console
$ cargo build --release -p classis-server --bin server
$ cargo build --release -p classis-admin --bin classis-cli
$ mkdir -p image
$ cp target/release/server image/server-linux-amd64
$ cp target/release/classis-cli image/classis-cli-linux-amd64
$ docker buildx build --platform linux/amd64 --load -t classis-server:dev \
    -f packaging/container/Containerfile image
```

## Configuration reference

The full annotated example is [`config/server.toml`](../../config/server.toml).
Every key is shown below with its default. Every key is optional; the Server
speaks plain HTTP behind a reverse proxy, so no TLS section is needed. An
unknown key fails startup rather than being ignored.

### Configuration from the environment

Every key can also be set by an environment variable, which is how a container
is configured without a file. The configuration is built from the defaults, then
the file, then the variables, each later one winning per key. A variable is
`CLASSIS_SERVER__` followed by the key's path, its segments joined by `__` and
upper-cased:

```console
CLASSIS_SERVER__DATA_DIR=/var/lib/classis
CLASSIS_SERVER__ADMIN_SOCKET=/run/classis/admin.sock
CLASSIS_SERVER__REST__LISTEN=0.0.0.0:4321
CLASSIS_SERVER__CONNECTION_OFFER__HEARTBEAT_INTERVAL_SECS=30
CLASSIS_SERVER__REST__AUTH__BASIC_USERS_FILE=/run/secrets/basic-users.toml
```

- **A value is a TOML value.** `30` is an integer, `true` a boolean,
  `["a", "b"]` an array, and `{ … }` an inline table that sets the whole table.
  A value that is not TOML is the string it is, so a path needs no quotes; a
  string that looks like another type is quoted: `"1234"`.
- **A variable is checked as strictly as a key.** One that names no key, has an
  empty segment (`CLASSIS_SERVER__REST____TLS`), or holds a value of the wrong
  type fails startup, naming the variable. So does any `CLASSIS_SERVER__…`
  variable in the environment of a process that starts the Server.
- **The environment carries paths to secrets, never secrets.** Every secret is a
  file named by a `*_file` key. The two tables keyed by names you choose,
  `[rest.auth.basic_users]` and `[telemetry_offer.headers]`, are reached from
  the environment only through `basic_users_file` and `headers_file`; a variable
  that sets either table fails startup, naming the file key.
- **The log says which keys the environment set.** At startup the Server logs,
  at `info`, the name of every key a variable set, and never its value. A key
  set in both places takes the variable's value.

`CLASSIS_SERVER_CONFIG`, with one underscore, names the file and sets no key. No
other variable configures the Server.

### Top level

| Key                       | Default                | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `listen`                  | `"127.0.0.1:4320"`     | The **Agent plane**, as `address:port`: the OpAMP endpoint and the package downloads. `4320` is the protocol's default port. Serve the fleet with `"0.0.0.0:4320"`.                                                                                                                                                                                                                                                                                                                                              |
| `max_connections`         | `10000`                | The connections the Agent plane holds at once. A connection past it is closed on accept. Raise it together with the process's file-descriptor limit for a larger fleet. `0` is refused at startup.                                                                                                                                                                                                                                                                                                               |
| `data_dir`                | `"fleet-data"`         | Where the Server keeps **all** of its state, one directory per domain: see [Where the Server keeps its state](#where-the-server-keeps-its-state). Created owner-only when missing — except with `[database] store = "postgres"` and `[blobs] store = "s3"`, where the Server keeps nothing on the filesystem and creates nothing. `config_dir` and `packages_dir` are gone: a file naming either fails startup and names `server migrate` ([Upgrading to one data directory](#upgrading-to-one-data-directory)). |
| `max_message_size_bytes`  | `67108864` (64 MiB)    | The largest OpAMP message accepted or sent, in either direction and on either transport. The protocol requires a limit and recommends this value; a fleet of status reports needs far less. An oversized HTTP request is answered `413`, an oversized WebSocket message closes the connection with `1009`. A request or message that has begun and delivers less than 64 KiB in a minute is answered `408`, or closes its connection with `1008`.                                                                |
| `max_package_size_bytes`  | `1073741824` (1 GiB)   | The largest artifact the package-upload route accepts. A package is a program, not a message — an `otelcol-contrib` binary is a few hundred megabytes — so this bound is far larger, and it applies to that one route. The upload has no deadline, but like every request body it must deliver 64 KiB in each minute once it has begun, or it is answered `408`.                                                                                                                                                 |
| `max_total_package_bytes` | `17179869184` (16 GiB) | The total size of all stored artifacts before a new upload is refused `507`. Where `max_package_size_bytes` bounds one artifact, this bounds the whole store, so no caller fills the disk by uploading many artifacts under distinct names. Identical bytes are stored once and counted once. `0` is refused at startup.                                                                                                                                                                                         |
| `max_agents`              | `100000`               | The most Agent records the fleet holds at once. A report bearing a **new** `instance_uid` past this ceiling is answered `Unavailable` rather than admitted, so an admitted peer minting fresh self-asserted UIDs cannot exhaust memory and disk; Agents already known keep reporting. The defence against an anonymous flood is [admission](#authentication) by client certificate; this is the backstop behind it. `0` is refused at startup.                                                                   |
| `stale_after_secs`        | `90`                   | How long an Agent that declares `ReportsHeartbeat` may be silent before the fleet view marks it **stale**. Ignored when `[connection_offer]` names a heartbeat interval — then the budget is three of those. Only heartbeating Agents can go stale: one that promised no periodic report is never late.                                                                                                                                                                                                          |
| `token_lifetime_secs`     | `0`                    | How long an access token is accepted after it is issued, in seconds. `0` — the default — means it never expires. A token ends when its client is issued a new one all the same ([How a host joins the fleet](#how-a-host-joins-the-fleet)).                                                                                                                                                                                                                                                                      |
| `public_url`              | _(none)_               | The base URL hosts reach the Server at through its proxy — what `classis-cli enrol-command` prints its install command against, and what an operator types into `classis enrol <url> <key>`. Optional; without it `enrol-command` refuses, since the Server never guesses the address its proxy answers for.                                                                                                                                                                                                     |

**`admin_socket`** defaults to `/run/classis/admin.sock`. It names the Unix
socket used by `classis-cli`; a relative path resolves against the Server's
working directory. See [The operator's socket](#the-operators-socket) for its
permissions and startup behavior.

**`public_url`** accepts `https://` anywhere, `http://` only to a loopback IP
literal; a reverse-proxy path prefix is kept, and user, password, query and
fragment are refused. The Server itself still speaks plain HTTP: the proxy at
that address terminates TLS.

### `[rest]`

The Operator plane's listener. Absent means the default.

```toml
[rest]
listen = "127.0.0.1:4321"   # "0.0.0.0:4321" publishes the plane, and then needs [rest.auth]
max_connections = 256
```

| Key               | Default            | Meaning                                                                                                                                                                                                                                                                                      |
| ----------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `listen`          | `"127.0.0.1:4321"` | Where the REST API, the API docs, and the UI are served, in plain HTTP. It must differ from `listen` above — two equal addresses are refused at startup by name, rather than surfacing later as _address already in use_. An address other than `127.0.0.1` or `::1` requires `[rest.auth]`. |
| `max_connections` | `256`              | The connections the Operator plane holds at once. `0` is refused at startup.                                                                                                                                                                                                                 |

#### `[rest.auth]`

Basic authentication over that whole plane — see
[Authentication](#the-operator-plane-restauth). Optional on a loopback `listen`,
required on any other.

```toml
[rest.auth.basic_users]
fleet-admin = "$argon2id$v=19$m=19456,t=2,p=1$…"
```

| Key                | Default   | Meaning                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `basic_users`      | _(empty)_ | Accepted Basic credentials, `user = "<Argon2id hash>"` — see [Credentials are kept as hashes](#credentials-are-kept-as-hashes). A section without one, or an entry that is not such a hash, fails startup.                                                                                                                                           |
| `basic_users_file` | _(none)_  | A TOML file holding the `basic_users` table — its lines are `user = "<Argon2id hash>"`, with no section header. Make it readable by the Server's account alone. Never beside `basic_users`: both fail startup, naming both. The one way the environment names the users ([Configuration from the environment](#configuration-from-the-environment)). |

#### `[rest.tls]`

Removed. The section is refused at startup, naming it: the proxy in front of the
Operator plane serves the UI's certificate.

### `[blobs]`

Optional. Where the artifacts' bytes are kept: one file per artifact under
`data_dir/blobs/`, the default, or one object per artifact in a bucket of an
S3-compatible object store. Both are supported in production; the bytes pass
through the Server in both directions, and no Agent ever reaches the store.

```toml
[blobs]
store = "s3"

[blobs.s3]
endpoint = "https://s3.example.org"
bucket = "fleet-artifacts"
region = "eu-central-1"
prefix = "fleet/"
access_key_id = "<key id>"
secret_access_key_file = "/run/secrets/s3-secret-access-key"
```

| Key                         | Default | Meaning                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `store`                     | `"fs"`  | `"fs"` or `"s3"`. Any other value fails startup naming the key; so do `"s3"` without a `[blobs.s3]` section and a `[blobs.s3]` section beside `"fs"`.                                                                                                                                                                                                                           |
| `s3.endpoint`               | —       | Required with `"s3"`. The store's URL, `https://`. `http://` is accepted to `127.0.0.1` or `::1` alone; any other fails startup naming the key.                                                                                                                                                                                                                                 |
| `s3.bucket`                 | —       | Required with `"s3"`. The bucket. The Server does not create it: one that does not exist, or that refuses the credentials, fails startup at once, naming it and the error; a store that does not answer yet — the name not resolving, the connection refused, a timeout, a server error — is asked again every five seconds for up to 180 seconds, logging each wait at `warn`. |
| `s3.region`                 | —       | Required with `"s3"`. The region the requests are signed for; a store without regions takes any, such as `us-east-1`.                                                                                                                                                                                                                                                           |
| `s3.prefix`                 | empty   | Where in the bucket the Server's keys live: empty, or ending in `/`. Artifacts are kept at `<prefix>blobs/<sha256>`, an upload in progress at `<prefix>staging/<random>`. Letters, digits, space and `- _ . / ! ' ( ) & $ @ = ; : + ,` only: any other character, which the S3 client would percent-encode, fails startup naming the key.                                       |
| `s3.ca_file`                | unset   | One PEM root for a store whose certificate no public root signs.                                                                                                                                                                                                                                                                                                                |
| `s3.access_key_id`          | unset   | The key ID of a static key pair. Set together with `secret_access_key_file` or not at all; one without the other fails startup naming both.                                                                                                                                                                                                                                     |
| `s3.secret_access_key_file` | unset   | The file holding that key pair's secret, readable by the Server's account and at most its group (`0600`, or `0640`/`0440` as an orchestrator mounts a secret for a group); one others can read, or its group can write, fails startup naming the key. The secret is never written into `server.toml`.                                                                           |

Without a key pair the Server uses its platform's workload identity, in this
order: a web identity token (`AWS_WEB_IDENTITY_TOKEN_FILE` with `AWS_ROLE_ARN`),
the container credentials of ECS or EKS
(`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, or
`AWS_CONTAINER_CREDENTIALS_FULL_URI` with
`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`), and the instance metadata service.
Those are the only `AWS_*` variables it reads: endpoint, bucket, region, prefix
and every TLS or HTTP option come from its configuration alone, so
`AWS_ENDPOINT` or `AWS_ALLOW_HTTP` in its environment change nothing, and no
proxy variable is honoured. The connection is TLS 1.3 on the public roots and
`ca_file`.

Every request to the store is bounded: a connection may take 10 seconds, and a
request fails once the store is silent for 30 seconds — before its answer
begins, the upload of one 8 MiB part included, or between two pieces of a
download, which therefore runs as long as bytes keep coming. A request that
failed is tried again at most twice, and not once a minute has passed since the
first attempt. A store that stops answering fails the act that needs it, as a
failed write does.

In the bucket, a key under `<prefix>staging/` is an interrupted upload and is
deleted at startup; any other key under `<prefix>` that is not `blobs/<sha256>`
fails startup naming it. At startup the Server lists the bucket for each
artifact's size and downloads nothing: unlike the filesystem store, it does not
hash the artifacts again. An object altered in the bucket is served, and the
Client's own hash and signature checks refuse it. The bucket, its credentials,
policies, retention and backups are the operator's.

**Switching to `"s3"`** copies what is missing: at the first start with `"s3"`,
every artifact a Package entry names that the bucket lacks is read from
`data_dir/blobs/`, hashed — a file whose content does not match its name fails
the start, naming it — uploaded and logged. The files are left where they are,
and the Server does not write to `data_dir/blobs/` again; removing them once the
bucket holds every artifact is yours. A large `data_dir/blobs/` makes that first
start as long as its upload. Nothing is copied back: switching from `"s3"` to
`"fs"`, an entry whose artifact `data_dir/blobs/` lacks fails the start, naming
the entry.

### `[database]`

Optional. Where the Server keeps its records: one file per record under
`data_dir`, the default, or one PostgreSQL database. Both are supported in
production. Either way the Server loads every record at startup and answers from
memory; the database is the durable copy, written before an act is answered, and
only this Server writes to it while it runs.

```toml
[database]
store = "postgres"

[database.postgres]
host = "db.example.org"
port = 5432
dbname = "fleet"
user = "fleet"
password_file = "/run/secrets/fleet-db-password"
```

| Key                      | Default | Meaning                                                                                                                                                                                                                                                                                                                     |
| ------------------------ | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `store`                  | `"fs"`  | `"fs"` or `"postgres"`. Any other value fails startup naming the key; so do `"postgres"` without a `[database.postgres]` section and a `[database.postgres]` section beside `"fs"`.                                                                                                                                         |
| `postgres.host`          | —       | Required with `"postgres"`. The database's host name or IP address — what its certificate must name.                                                                                                                                                                                                                        |
| `postgres.port`          | `5432`  | Its port.                                                                                                                                                                                                                                                                                                                   |
| `postgres.dbname`        | —       | Required with `"postgres"`. The database. The Server does not create it.                                                                                                                                                                                                                                                    |
| `postgres.user`          | —       | Required with `"postgres"`. The role the Server signs in as. The Server does not create it.                                                                                                                                                                                                                                 |
| `postgres.password_file` | —       | Required with `"postgres"`. The file holding the role's password, readable by the Server's account and at most its group (`0600`, or `0640`/`0440` as an orchestrator mounts a secret for a group); one others can read, or its group can write, fails startup naming it. The password is never written into `server.toml`. |
| `postgres.ca_file`       | unset   | A PEM file of the roots the database's certificate is verified against, for a database no public root signs. Without it, the public roots.                                                                                                                                                                                  |
| `postgres.tls`           | `true`  | `false` connects without TLS, which is accepted when `host` is `127.0.0.1` or `::1` alone; any other host fails startup naming both keys.                                                                                                                                                                                   |

A missing key fails startup naming it. The connection is TLS 1.3, the database's
certificate verified and its host name checked — what libpq calls `verify-full`.
Every setting comes from the configuration alone: `PGHOST`, `PGSSLMODE` and the
other `PG*` variables in the Server's environment change nothing. A database
that cannot be reached at startup stops the start, naming the host and the
database; one lost while the Server runs fails the acts that need it, as a
failed write does. Every call is bounded: it fails when no pooled connection is
free within 5 seconds, when the database does not answer it within 15 seconds (a
rollout gets 20 ms more per record it writes), and the database itself ends a
statement after 10 seconds, a wait for a lock after 5 and a transaction left
open by a client that went away after 60. TCP keepalives notice a database host
that is gone within about half a minute.

The role needs the right to create tables in its default schema: at every start
the Server applies the migrations of its schema the database has not yet seen,
in one transaction, and records them in the table `fleet_schema`. A migration
only adds, so the Server before an upgrade runs on the schema after it. A
database whose schema needs a newer Server stops the start, naming both
versions, and is left unchanged. The Server creates tables and indexes, and
nothing else: the database, the role, its rights and extensions, replication and
backups are the operator's.

At startup the Server waits for the database: a database that does not answer
yet — the name not resolving, the connection refused or reset, the database
starting up, shutting down or out of connections, as during a failover — is
asked again every five seconds for up to 180 seconds, logging each wait at
`warn` with the reason and the time left, and then the Server stops, naming the
database. A refusal that asking again would not change stops it at once: a
rejected password, a certificate that does not verify, a database that does not
exist, a schema that needs a newer Server. Size an orchestrator's startup probe
to allow the wait.

One Server per database schema: the Server holds a lock on the schema it works
in — its role's default — while it runs, and a second one started against the
same database and schema waits for it, asking again every five seconds within
the same 180 seconds so that a Server an orchestrator replaces can take over
once the old one has stopped, and then stops, naming the database. The lock
lives on a connection of its own; when that connection ends while the Server
runs — the database restarted, the session was ended, the host is gone — the
lock is gone with it, and the Server logs an error naming the database and exits
with status 1, so it never writes beside a second Server. An orchestrator
restarts it; it then waits for the lock as above.

With `"postgres"`, `data_dir` holds the artifacts (`blobs/`) with the filesystem
blob store, and nothing else. A record of
the filesystem store found there — `agents/`, `configurations/`, `spaces/`,
`clients/` and the rest — stops the start, naming it and
`server migrate-to-postgres`. A backup takes the database and `data_dir`
together.

### `[agents.auth]`

Removed. The Agent plane admits a request by the access token its host holds
([How a host joins the fleet](#how-a-host-joins-the-fleet)), and there is no
other authentication of Agents to configure. The section is refused at startup
with `[agents.auth] is removed`, and so is a bare `[agents]`.

### `[tls]`

Removed. The Server terminates no TLS: a reverse proxy in front of it does. The
section is refused at startup with `[tls] is removed`, as are `[rest.tls]`,
`[client_ca]` and `[enrolment]`.

### `[telemetry_offer]`

Optional. Where Agents send their own telemetry — see
[The fleet's own telemetry](#the-fleets-own-telemetry). At least one endpoint is
required if the section is present.

```toml
[telemetry_offer]
metrics_endpoint = "https://collector.example:4318/v1/metrics"
[telemetry_offer.headers]
Authorization = "Bearer a-telemetry-token"
```

The headers can instead come from a file,
`headers_file = "/run/secrets/telemetry-headers.toml"`, holding the lines of the
`headers` table with no section header. Never beside `headers`: both fail
startup, naming both. It is the one way the environment names the headers.

### `[client_ca]`

Removed, and with it the CSR flow: a host is admitted by its access token, and
the Server signs no certificate. The section is refused at startup
(`[client_ca] is removed`).

### `[enrolment]`

Removed, and with it the enrolment window, the bootstrap certificates and the
pending queue: a host enrols with its Space's key instead
([How a host joins the fleet](#how-a-host-joins-the-fleet)). The section is
refused at startup (`[enrolment] is removed`).

### `[packages]`

Optional; absent means no Package Signer is revoked.

```toml
[packages]
revoked_signers = [
  "9f2b…64 lowercase hex digits…",
]
```

`revoked_signers` lists the Package Signers this Server refuses, each as the
SHA-256 of its DER certificate in 64 lowercase hex digits, at most 64. Use it
when a Package Signer's key may be exposed: a Package Signer is valid for 10
years and nothing else ends it earlier.

- **The Server refuses a listed signer's signature** with `400` on a write, and
  at startup it sets aside every stored signature of that signer, with a
  warning naming the entry. The entry is offered to nobody and its signature
  stays in the store, as for a signer that has expired.
- **A change takes effect when the Server restarts.** With several Servers, they
  differ until the last one has restarted.
- **A malformed list stops the start**, naming the setting: an item that is not
  64 lowercase hex digits, one named twice, or more than 64.
- **Clients are not told.** The list is the Server's alone, so a Package a
  Client already accepted stays installed. Every version the revoked signer
  signed stays unoffered until it is signed again by another Package Signer.

`openssl x509 -inform DER -in <certificate> -outform DER | sha256sum` gives the
fingerprint of a certificate; the release's certificate is
`packaging/package-signer.der`.

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
[How often a host may be heard](#how-often-a-host-may-be-heard).

```toml
[agent_rate_limit]
messages_per_sec = 10
burst = 300
```

### `[log]`

Optional; absent means the default shown.

```toml
[log]
format = "text"
```

`format` is `"text"` (one human-readable line per event) or `"json"` (one JSON
object per line, for a log collector). Anything else fails startup. The
environment variable is `CLASSIS_SERVER__LOG__FORMAT`. The level is
`RUST_LOG`'s.

### Liveness and readiness

The Operator plane answers two routes beside its guard, with no credential, to
`GET` and `HEAD`:

| Route     | Answer                                                                                                                                                                                               |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/livez`  | `200 ok` while the process serves requests.                                                                                                                                                          |
| `/readyz` | `200 ok` when the Server holds its database lock, the database answers a query and the blob store answers; `503` with the body `database` or `blobs`, naming the check that failed and nothing else. |

Every other route of the plane still answers `401` without a credential, and
neither route counts toward the
[admission throttle](#repeated-failures-are-throttled). Point an orchestrator's
HTTP probe at `4321`. The Agent plane has no such route.

### `[connection_offer]`

See [Moving the fleet](#moving-the-fleet-connection-settings). Either key or
both is valid, but not an empty section. The `endpoint` is `wss://` or
`https://`; a `ws://` or `http://` endpoint is refused at startup, on the
loopback too. The section carries no credential: `bearer_token_file`,
`username`, `password_file`, `bearer_token` and `password` are each refused at
startup by name.

```toml
[connection_offer]
heartbeat_interval_secs = 30
endpoint = "wss://fleet.example:4320/v1/opamp"
```

## Where the Server keeps its state

Everything the Server knows survives a restart under one directory, `data_dir`,
in a fixed layout — or, with [`[database]`](#database) `store = "postgres"`, in
the database, with at most `blobs/` left under `data_dir`. With the filesystem
store the layout is:

| Path                                   | One file per  | Holds                                                                                                                        |
| -------------------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `configurations/<name>.json`           | Configuration | Its saved revision and every revision still rolled out somewhere                                                             |
| `deployments/<name>.json`              | Deployment    | Its Selector, its Packages and its Configurations                                                                            |
| `packages/<agent type>@<version>.json` | Package       | Its identity and entries, each naming its artifact by SHA-256 and carrying its signature                                     |
| `blobs/<sha256>`                       | artifact      | The bytes, named by their SHA-256 — identical bytes are stored once; unused while [`[blobs]`](#blobs) keeps them in a bucket |
| `agents/<instance_uid>.json`           | Agent         | What it reported, its assignment, its labels, and the Device ID of the host it reported under                                |
| `spaces/<name>.json`                   | Space         | Its name and its whole enrolment key — a secret, kept so that it can be read again                                           |
| `clients/<client_id>.json`             | client        | A host's Device ID, its Space, the SHA-256 of its client secret, and the SHA-256 and expiry of its one active access token   |

A Space's file is named by its name in lowercase; the name as it was created is
inside.

- **Owner-only.** The Server creates `data_dir` and every directory in it `0700`
  and writes every file `0600`: an Agent's reported configuration may hold
  credentials, and nothing here is another local user's business. The Server
  ships for Linux; built for Windows it sets no ACL, so give `data_dir` one that
  admits only the Server's account and the administrators.
- **One step per write.** Every record is written to a temporary file beside it
  and renamed into place, so a crash leaves the old document or the new one. A
  Space, a client and a token reach the disk before the request that created
  them is answered. A temporary file a crash left behind is removed at the next
  start.
- **Nothing else is read.** A file or directory the layout does not name, a file
  that does not parse, or one whose name disagrees with what it holds stops the
  start, naming the path — a store that merely looked empty would be worse.
  Every artifact is hashed again at startup — in a bucket, only listed — and an
  artifact no Package entry names is deleted then.
- **Backup** is a copy of `data_dir` taken while the Server is stopped;
  restoring it is putting the copy back. A copy taken while it runs may hold an
  Agent record mid-write. A backup holds every Space's enrolment key in
  `spaces/`: keep it as you keep the key.

## Moving the records into PostgreSQL

An existing `data_dir` is copied into PostgreSQL once, while the Server is
stopped, with the `server.toml` that names the database in
[`[database]`](#database):

```sh
server migrate-to-postgres --from /var/lib/classis/fleet-data \
    --data-dir /var/lib/classis/fleet-data-pg --config /etc/classis/server.toml
```

- It refuses a database that holds any of the Server's tables, and a
  `--data-dir` that is not empty, and checks the database before it creates
  anything.
- It reads every record of the old `data_dir` as a Server's start would, so a
  record a start would refuse stops the copy, naming it, before anything is
  written into the database. It only reads the old `data_dir`: what a start
  would repair there — a missing directory, a leftover temporary file, a mode —
  it leaves as it is.
- With the filesystem blob store it copies `blobs/` into the new `data_dir` byte
  for byte; then it applies the schema and writes every record in one
  transaction.
- It copies rather than moves: the old `data_dir` stays as the backup. It prints
  what it copied, and exits non-zero when it could not copy all of it, leaving
  the database without the Server's tables and the new `data_dir` empty.

Then set `data_dir` to the new directory and `[database] store = "postgres"`,
and start the Server. With an S3 bucket in [`[blobs]`](#blobs), start once with
`"s3"` on the old `data_dir` before the copy, so the bucket holds every
artifact. Moving records back from PostgreSQL to files is not provided.

## Upgrading to one data directory

A Server before 0.5.5 kept its state in two directories, `config_dir` (default
`fleet-configs`) and `packages_dir` (default `fleet-packages`). This Server
reads neither: a `server.toml` naming either key stops it at startup.
`server migrate` moves an installation once, offline:

1. **Stop the Server.** The migration copies files; a Server still writing them
   would be copied half-way. The older Server takes no lock the migration could
   test, so this step is yours.
2. **Run the migration**, naming the two old directories and a new, empty one —
   it refuses a `data_dir` that is not empty:

   ```text
   $ server migrate --config-dir /var/lib/classis-server/configs \
       --packages-dir /var/lib/classis-server/packages \
       --data-dir /var/lib/classis-server/data
   ```

   It copies and never moves: the old directories stay as they were, as your
   backup. It prints one line per thing it carried, dropped or listed:
   - **Certificate data** — the certificate register, the revocation list, the
     Hosts and the bootstrap certificates with their PKCS#12 files — is not
     carried: this Server admits no client certificate. The migration names
     what it skips and leaves it in the old directory.
   - **Audit files** are not carried: this Server keeps no audit record
     ([Security decisions in the log](#security-decisions-in-the-log)). The
     migration names them and leaves them in the old directory; keep them there
     if you need the old record.
   - **Packages**: each artifact becomes a blob. Each entry takes the signature
     the Deployments held for it; where two Deployments held different
     signatures for one entry it is carried **unsigned** and named — sign it
     again. A referenced entry (one an older Server fetched from a URL) is
     **dropped** and named; upload that artifact. An artifact whose bytes do not
     match the hash its entry recorded is **dropped** and named; upload it
     again.
   - **Deployments** keep their name, Selector and the Packages that were
     carried; their signatures now live on the entries. A Package that was not
     carried leaves them, named.
   - **Configurations** keep their content and lose their Selector. Each is
     **listed** with the Selector it had: put it into the Deployment whose
     Selector aims where that one did. A Configuration without an Agent type is
     **not carried**, because the Server refuses it at startup: it is listed by
     name, and its file stays in the old directory — save it again with its
     `service_name`.
   - **Agents** are carried with their labels inside their record. An Agent
     whose Package was released through a Deployment keeps that Package assigned
     through it. An older Server rolled every Configuration out by itself, never
     through a Deployment, so every Agent's Configuration pins are **dropped**
     and listed per Agent — also for an Agent that keeps its Package. The Agent
     keeps running the configuration it has: nothing is offered in its place
     until a Deployment holding those Configurations is rolled out to it.

   When it is done it opens the new directory as the Server will. It exits
   non-zero when the new directory would not open — then empty the new
   directory, fix what it named, and run it again.

3. **Edit `server.toml`**: remove `config_dir` and `packages_dir`, and set
   `data_dir = "/var/lib/classis-server/data"`.
4. **Start the Server**, put each listed Configuration into its Deployment, sign
   any entry named unsigned, and roll the Deployments out. Keep the old
   directories until you are satisfied, then delete them.

## How a host joins the fleet

A host belongs to one **Space**, a named grouping of hosts on this Server. A
Space is not a separate fleet and not an isolation boundary: it appears in no
Selector and in no REST response, and is recorded on each host's client and
returned to the host when it enrols. A host joins with its Space's **enrolment
key**, with no operator approval, and is admitted from then on by an **access
token**.
Each step is one request on the Agent plane, through the reverse proxy in front
of it:

1. **Enrol** — `POST /v1/enrol`, with the enrolment key as a bearer token. The
   host registers itself as an OAuth 2.0 client (RFC 7591) and receives a
   `client_id` and a `client_secret`.
2. **Get a token** — `POST /v1/token`, with those client credentials (RFC 6749
   §4.4). The host receives its access token.
3. **Everything else** carries that token: every OpAMP exchange on `/v1/opamp`,
   on either transport, and every package download, in
   `Authorization: Bearer <token>`.

On the host, `supervisor enrol <base-url> <key>` makes the first two requests
and keeps what it receives in `state.json` ([the Client](client.md)). Nothing on
the host states which Space it joins: the key names it.

### The install one-liner

`classis-cli enrol-command --space <name> --os <linux|windows>` prints a single
command that installs the Client on a host and enrols it, so an operator pastes
one line instead of fetching a package by hand. It prints the host's `curl`
(Linux) or PowerShell one-liner that fetches `/v1/install.sh` or `/v1/install.ps1`
from the Server's public endpoint and runs it with `--url <base>` and `--key
<enrolment-key>`; the key is passed as an argument to `enrol`, never part of a
URL, so it reaches no access log. `--with-key` prints the key alone on the line
before the command.

Two things stand behind it:

- **`public_url` must be set** in `server.toml`. `enrol-command` prints its
  command against the configured public URL; with `public_url` absent it refuses,
  because the Server never guesses the address its proxy answers for. The `space`
  commands answer regardless.
- **The Server's own Client package must be uploaded first.** The scripts fetch
  `/v1/install/{os}/{arch}`, which serves only the signed `supervisor` package of
  the release this Server is built from. Upload that release's Client archive and
  its verified `.sig` to `supervisor@<server-version>` before the first host
  bootstraps, or the archive route answers `404` and no host installs.

TLS is settled before the script runs: the host fetched it over TLS, verifying
the Server against the trust the host already holds (a preprovisioned CA or the
system roots), and the script neither provisions a CA nor relaxes a check. The
install itself is the Client's own `service install` and `enrol`, identical to a
native-package install — a host installed from a URL and one installed from a
`.deb`/`.rpm`/`.msi` end up the same. It refuses a host that already has the
service, where re-registration is `classis service install` and `classis enrol`,
not a second delivery. The Client's later self-updates are verified by their
signature against the compiled-in Package Roots, as always
([Updating the Client itself](client.md#updating-the-client-itself)).

### The enrolment key

A Space's name is 1 to 32 letters, digits and underscores, starting and ending
with a letter or a digit. It keeps the case it was created with, and two Spaces
may not have names that differ only in case. Its key looks like this:

```text
cle1_<space>_<secret>
```

`cle1_` is a fixed prefix, so that secret scanners and log redaction recognise a
key; the secret is 256 random bits written as 43 base64url characters. A Space
has exactly one active key, reusable without limit: a host that presents it is
enrolled at once.

- **The Server keeps the whole key**, not only a hash of it, so that the same
  key can be read again after a restart. It lives in `spaces/` under `data_dir`
  (or in the table `spaces`), readable by the Server's account alone, and so in
  every copy of the records. **Treat the key as a secret**: anyone who has it
  can enrol hosts into the Space until the key is rotated.
- **Reading the key, enrolling a host and restarting the Server never change
  it.** Only a rotation does. The old key then enrols nothing, and the hosts
  already enrolled keep their client and their token.
- **`classis-cli` creates a Space, lists them, and rotates a key**, over the
  operator's socket ([The operator's socket](#the-operators-socket)). No REST
  route does any of it. `create` and `rotate-key` print a new key, and
  `enrol-command` prints the current key of an existing Space (alone with
  `--with-key`), so whoever the socket admits can read it again. The
  Server enrols a host only into a Space that exists in its records.

### `/v1/enrol`

The request is `application/json`, with the key in `Authorization: Bearer
cle1_…` — never in the URL — and `grant_types: ["client_credentials"]`. The
`token_endpoint_auth_method` is `client_secret_basic`, and may be left out. A
request that is not a JSON object, or that gives another value of either field,
or no `grant_types`, is refused `400` with `{"error":
"invalid_client_metadata"}`: the RFC's default grant is not one this Server
supports. Metadata the Server does not understand is ignored.

On success the answer is `201 Created` with the `client_id`, the
`client_secret`, `client_id_issued_at`, a `client_secret_expires_at` of `0` and
the registered metadata, and with the Space the key named as `space`. The Space
comes from the key, never from what the host sends. The `client_id` is a UUID
version 7 and is the host's identity, its **Device ID**: the Server derives it
from the token a request presents, and a host never states one. The Server keeps
the client — its Device ID, its Space, when it was issued — and only the SHA-256
of its secret.

| Status | Header or body                                     | When                                                                          |
| ------ | -------------------------------------------------- | ----------------------------------------------------------------------------- |
| `201`  | the client's credentials                           | The key is the Space's active key                                             |
| `401`  | `WWW-Authenticate: Bearer realm="fleet"`           | No bearer credential, or one of another scheme                                |
| `401`  | `WWW-Authenticate: Bearer error="invalid_token"`   | A key that is malformed, unknown, wrongly spelt or rotated away               |
| `400`  | `WWW-Authenticate: Bearer error="invalid_request"` | More than one `Authorization` header, or one beside `access_token` in the URL |
| `400`  | `{"error": "invalid_client_metadata"}`             | Metadata the Server does not support                                          |
| `413`  | none                                               | A body over 8 KiB                                                             |

Every response carries `Cache-Control: no-store` and `Pragma: no-cache`.

### `/v1/token`

The request is a form (`application/x-www-form-urlencoded`) with
`grant_type=client_credentials`. The client authenticates with HTTP Basic, its
`client_id` and `client_secret` each form-encoded before they become the Basic
user name and password; credentials in the body are not read. Empty parameters
count as omitted, unknown ones are ignored, and repeated ones are refused.

| Status | Header or body                                                                  | When                                                           |
| ------ | ------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `200`  | `access_token`, `token_type: "Bearer"`, and `expires_in` when the token expires | The credentials are right                                      |
| `401`  | `{"error": "invalid_client"}`, `WWW-Authenticate: Basic realm="token"`          | An unknown client, a wrong secret, or no client authentication |
| `400`  | `{"error": "invalid_request"}`                                                  | A missing `grant_type`, repeated parameters, a malformed form  |
| `400`  | `{"error": "unsupported_grant_type"}`                                           | Any grant other than `client_credentials`                      |
| `400`  | `{"error": "invalid_scope"}`                                                    | A non-empty `scope`: this Server defines no scopes             |
| `413`  | none                                                                            | A body over 8 KiB                                              |

The access token is opaque — 256 random bits — and no refresh token is issued.
**A client holds exactly one active token.** A new request at `/v1/token`
replaces the token, and the replacement is the revocation of the old one: there
is no list of issued tokens. The Server keeps only the SHA-256 of the token and
its expiry, beside the hash of the client secret. `token_lifetime_secs` sets how
long a token is accepted; `0`, the default, means never.

### Admission

`/v1/opamp` (WebSocket and plain HTTP) and the package download route admit a
request only with `Authorization: Bearer <token>`, whose hash is a client's
active token and has not expired. The scheme name is case-insensitive and the
token is case-sensitive. A token in the URL is not read.

| Status | `WWW-Authenticate`               | When                                                                          |
| ------ | -------------------------------- | ----------------------------------------------------------------------------- |
| `401`  | `Bearer realm="fleet"`           | No credential, or one of another scheme                                       |
| `401`  | `Bearer error="invalid_token"`   | A token that is wrong, malformed, replaced or expired                         |
| `400`  | `Bearer error="invalid_request"` | More than one `Authorization` header, or one beside `access_token` in the URL |

The check happens when a request is admitted: on every plain-HTTP exchange and
every download, and for a WebSocket session once, at its upgrade.

- **A session outlives the expiry of its token.** An open WebSocket session is
  not ended when its token expires; the Client meets the expiry at its next
  connection.
- **A session ends when its token is replaced.** When a client is issued a new
  token, the Server closes every WebSocket session admitted with the old one,
  with close code `1008` (policy violation) and the reason `token replaced`.
  That is how a stolen token is cut off.
- **Refusals are counted per address.** An authentication refusal on
  `/v1/enrol`, `/v1/token`, `/v1/opamp` or the download counts toward the
  back-off of the peer's address, the left-most `X-Forwarded-For` entry
  ([Repeated failures are throttled](#repeated-failures-are-throttled)).

The host of an admitted request is the client that holds its token. An Agent's
record names the host it reported under, and an `instance_uid` belongs to the
host that reported it first until the Agent is forgotten: a report for an
`instance_uid` recorded under another host is refused, and so is a report that
would make a host speak for more than 256 Agents. Both are logged at `warn`
(`identity.claimed`, `identity.limit`). `GET /api/v1/agents` shows each Agent's
host, as `host`. A host downloads only the artifacts offered to its own Agents
([A host fetches only what its Agents are
offered](#a-host-fetches-only-what-its-agents-are-offered)).

A host that loses its `state.json` is lost for good: its client stays in the
Server's records, with nothing left that can present its secret or its token. A
client is never deleted.

## Security decisions in the log

The Server keeps no audit record and writes nothing for one. Every security
decision it takes is one structured event on its log, which goes to standard
error with everything else it logs ([Running it](#running-it)): each admission
and refusal on the Agent plane, each refused or throttled operator sign-in, each
host enrolled and each token issued, each WebSocket session that starts and each
that a replaced token ends, each download a host may not fetch, each report
refused for claiming another host's Agent, each operator act — every `POST`,
`PUT`, `PATCH` and `DELETE` on the REST API, once it has run, with its method,
path and status and the user name of the Basic credential when one was
presented — each package an Agent reports installed or failed, and each of the
Server's own certificates that is ending or has ended.

Each event names itself in its `event` field — `admission.refused`,
`enrolment.registered`, `token.issued` and so on — and carries, where they
apply, the peer address, the Device ID of the client, the Space and the Agent's
`instance_uid`. `admission.refused` says in `check` which check refused:
`absent`, `scheme`, `malformed`, `invalid_request`, `unknown` or `expired`. No
event holds a secret in any form: an enrolment key, a client secret, an access
token or an `Authorization` value is never logged, not even as a hash. A text a
peer chose, such as a user name, a path or the error an Agent reports, is cut at
256 bytes.

The level says whether a peer can repeat it at will. Nothing aggregates the
events and the log has no rate limit, so what a peer can cause as often as it
likes stays out of the default `info`:

- **`debug`** — a refusal or a throttle of a peer that was not admitted, on the
  Agent plane (`admission.refused`, `admission.throttled`, `enrolment.refused`
  and `token.refused`, with the status) and at an operator sign-in
  (`operator.refused`, `operator.throttled`); a message or a download over a
  host's rate (`agent_rate.throttled`); a download a host may not fetch
  (`download.refused`); and each admitted request (`admission.admitted`): a
  plain-HTTP poll, a download, or a WebSocket upgrade before its session starts.
  Set `RUST_LOG=info,classis_server=debug` while you investigate.
- **`info`** — every decision taken: a host enrolled (`enrolment.registered`), a
  token issued (`token.issued`), a WebSocket session started or ended
  (`session.started`, `session.ended` with the reason `token replaced`), an
  operator act (`operator.act`), a package outcome (`package.outcome`).
- **`warn`** — what an admitted host should never ask for: a report that claims
  an `instance_uid` recorded under another host (`identity.claimed`), or that
  would make a host speak for more Agents than it may (`identity.limit`).
- **`error`** — a store that failed under a request: `admission.failed`,
  `enrolment.failed`, `token.failed`.

```sh
docker logs classis-server 2>&1 | grep 'token.issued'
```

What keeps these lines, for how long, and who may change them is whatever
collects the Server's output — journald, the container runtime, a log shipper.
Nothing makes a line edited or removed afterwards visible; if you need that,
ship the log off the host to a store the Server's host cannot rewrite. A
decision never waits for its line: no request is answered `503` for want of one.

## Configurations: what the fleet runs

A **Configuration** is content: a name, a body of text, the **Agent type** it is
written for, and an optional **role**. It has no Selector and is never rolled
out by itself — a [Deployment](#packages-and-deployments-distributing-software)
holds it, and the Deployment's Selector aims it. One Configuration may sit in
several Deployments.

**Names** become file names here, config-map keys on the wire, and entry files
on every Client — including Windows ones. The grammar is therefore narrow: 1–32
characters, lowercase letters, digits, and `-`, not starting or ending with `-`,
and not a Windows reserved device name (`con`, `nul`, `com1`, …).

**Saving never distributes**. `PUT` stores the Configuration and reaches nobody.
A body naming a `selector` is refused `400`: aim it by putting it into a
Deployment. Distribution is the Deployment's **rollout act** —
`POST /api/v1/deployments/{name}/rollout` for every Agent it claims, or the
per-Agent press on the fleet view. Either act pins a snapshot: the Agent keeps
exactly the revision it was rolled out, so a later edit changes nothing anywhere
— the fleet view shows the newer save _waiting_ per Agent — until the next act.
An Agent that connects (or is labelled into a Deployment) after the act waits
the same way: nothing is distributed by enrolment, by a Deployment edit, or by a
label move.

**Nothing in use can be deleted**: deleting a Configuration that any Agent's
assignment pins is refused `409`, and the answer says how many Agents pin it.
Roll those Agents out through a Deployment that no longer holds it — they apply
their config map without the entry — or forget them, and then delete it. A
deleted Configuration leaves every Deployment that held it.

**The type decides which Agents of the Deployment receive it**. `service_name`
is required, and must equal the `service.name` the Agent reports — compared raw.
A `PUT` without it is refused `400`, and a stored Configuration without it stops
the Server at startup, naming the file. An Agent that reports no `service.name`
receives no Configuration. Content for several Agent types, a certificate bundle
for instance, is one Configuration per type. That is how one Deployment serves
several Agent types.

The examples on this page call the Operator plane on the loopback, in plain
HTTP. Off the loopback, through the proxy, use its `https://` address, and add
the [`[rest.auth]`](#the-operator-plane-restauth) credential with `-u`.

```console
$ curl -X PUT -H 'Content-Type: application/json' \
       -d '{"service_name": "otelcol-contrib", "body": "receivers: {}"}' \
       http://127.0.0.1:4321/api/v1/configurations/contrib-base
$ curl -X PUT http://127.0.0.1:4321/api/v1/deployments/stable/configurations/contrib-base
$ curl -X POST http://127.0.0.1:4321/api/v1/deployments/stable/rollout
```

**A Deployment may hold several Configurations.** An Agent receives every one
that fits its type, as named entries in one config map, and merges them itself.
An Agent in no Deployment is offered nothing and keeps running what it already
runs — the Server never blanks an Agent by omission.

**The role marks content that is not configuration**. `role: "supplementary"`
means the Managed Process reads this content _by path_ — a rule file, a lookup
table — so the Client writes it into the configuration directory under its own
name but never passes it to the process as configuration. An unset role means
top-level configuration, which is what every Configuration was before the option
existed. Any other non-empty value travels to the Agent verbatim and is treated
like `supplementary`.

```console
$ curl -X PUT -H 'Content-Type: application/json' \
       -d '{"service_name": "otelcol-contrib", "body": "rules: []", "role": "supplementary"}' \
       http://127.0.0.1:4321/api/v1/configurations/ruleset
```

**Nothing is sent twice.** The Server composes the entries an Agent was **rolled
out**, hashes them, and compares that hash to what the Agent reports. Equal
hashes mean nothing crosses the wire. This is why repeating a rollout act with
unchanged content is free, why a press that changed only a Configuration sends
no package offer (and the reverse), and why a role change _does_ reach the fleet
once rolled out: the role is part of the hash.

**How a change travels.** The rollout act is the moment it starts — over
WebSocket the Server pushes it within a second; over plain HTTP it rides the
Agent's next poll. The Agent then reports the configuration back as applied or
failed, with the hash it applied — visible on the Agent's row as
`remote_config_status`, `remote_config_error`, and `in_sync`.

**The fleet view shows what waits.** Per Agent, `GET /api/v1/agents` answers
what is rolled out to it (`assigned_deployment`, `assigned_configurations`,
`assigned_package`) and what the next press of its Deployment would change
(`pending_configurations`, `pending_packages`, each with a `change`: `new`,
`update` — a newer save or version — `remove` — the Deployment no longer
releases it to this Agent, and the press applies the smaller set — or `kept` —
the Deployment releases nothing to this Agent any more, so the press leaves it
with no assignment and it keeps running what it runs). `pending_deployment`
names the Deployment the press releases through when the assignment names
another one, even where the content stays the same. The Server never acts on the
waiting list by itself; the per-Agent rollout
(`POST /api/v1/agents/{instance_uid}/rollout`, with an empty body or
`{"deployment": "…"}` naming the Deployment that claims the Agent) is the
operator's press.

## Packages and Deployments: distributing software

The Packages live in `data_dir/packages/` and their artifacts in
`data_dir/blobs/` or the bucket of [`[blobs]`](#blobs); the Server declares the
capability only while the store holds a Package. Two objects, and the split is
the whole of the model:

- A **Package** is _what_ an Agent type runs at a version. Its identity is the
  **Agent type and the version**, the version a SemVer 2.0.0 version, and it
  holds one entry per platform — the Linux build, the macOS builds, the Windows
  build — each an uploaded artifact with its SHA-256 and the operator's
  **signature**. Nothing else: no name of its own, no Selector. It aims at
  nobody and is never rolled out.
- A **Deployment** is _where that goes_. A name, the **channel** it aims at, one
  Package per Agent type, and any number of
  [Configurations](#configurations-what-the-fleet-runs). It is the only thing
  that is rolled out, and one press releases its Packages and its Configurations
  together.

An Agent belongs to **at most one Deployment**. Two matching the same Agent is a
conflict: that Agent is offered nothing new — no Package and no Configuration —
and the fleet view says so on its row in `package_conflict`. There is no
most-specific-wins and no newest-wins — a rule that decides which artifact a
host gets by comparing every stored object against every other is a rule nobody
can evaluate by looking at anything.

### Channels are a partition, not a default

**A Selector is equality and cannot say "not".** "Everyone except the canary
hosts" is not a writable Selector, so disjoint channels come from _membership_:
an attribute every Agent carries.

**The Server prescribes no key.** There is no reserved word and no special
handling anywhere — a Selector is equality over whatever the Agent reports, and
the key is one you invent. What follows are examples, not a schema.

```console
# at provisioning, in the host's supervisor.toml
[attributes]
channel = "stable"

# or from here, without touching the host
$ curl -X PUT -H 'Content-Type: application/json' -d '{"labels": {"channel": "beta"}}' \
       http://127.0.0.1:4321/api/v1/agents/<uid>/labels
```

Which key you pick is a decision about _what the partition means_, and three
shapes cover most fleets:

| key       | what it says about the host                                       | how a release moves                                                                                         |
| --------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `channel` | which stream of versions it follows — `stable`, `beta`, `nightly` | you change **what the channel carries**; the hosts stay where they are                                      |
| `region`  | where it runs — `eu-central`, `us-east`                           | a release follows the sun, one region at a time; or a version stays pinned where a jurisdiction requires it |
| `tenant`  | whose it is — `acme`, `globex`                                    | one customer's software moves on that customer's schedule, independently of everyone else's                 |

`channel` is the one to reach for when the partition is about _release risk_,
which is the ordinary case: a host subscribes to `stable` and stays there for
years, while the Deployment named `stable` is given one version after another.
`region` and `tenant` describe the host instead of its appetite, and both
compose — a fleet can carry all three and aim a Deployment at
`{"tenant": "acme", "channel": "stable"}`, which is two equality pairs and needs
nothing new.

What they have in common is the reason they work: each names a **property of the
host**. A key that named the Deployment instead — `deployment = "contrib"` —
would put the same fact in two places, so re-aiming a channel would mean editing
every host in it. The Selector exists to avoid exactly that.

**A Deployment's Selector may not be empty** — an empty one matches every Agent,
so it would collide with every other channel the moment a second one exists, and
it is what a forgotten field looks like. The price is stated plainly: **there is
no "roll out to everyone" any more.** A fleet-wide delivery needs every Agent to
carry the same value, and a freshly enrolled host belongs to no Deployment until
it is labelled. That host shows on the fleet view with no deployment, which is
the ordinary state after an enrolment and not a fault.

### Create the Package, upload its entries, sign them

The identity is the path. The Agent type is compared **raw** against the
`service.name` the Agents report — there is no canonical set of Agent types, so
spell it exactly as they do. The create body has no writable field; `{}` is the
whole of it.

```console
$ curl -X PUT -H 'Content-Type: application/json' -d '{}' \
       http://127.0.0.1:4321/api/v1/packages/otelcol-contrib/0.109.0
$ curl -X PUT --data-binary @otelcol-contrib_0.109.0_linux_amd64.tar.gz \
       "http://127.0.0.1:4321/api/v1/packages/otelcol-contrib/0.109.0/entries/linux/amd64"
```

Platform spellings are accepted and stored canonically, so the tokens off an
upstream release's file name work as they are: `macos` and `osx` mean `darwin`,
`x86_64` and `x64` mean `amd64`, `aarch64` means `arm64`. An `os`/`arch` this
Server has never heard of is stored as given rather than refused — the fleet may
run a system nobody here anticipated.

**Every artifact is uploaded.** The Server holds what it offers and sends no
request for a package anywhere; a Client fetches from its own Server's origin
alone (see [the Client](client.md#where-a-download-may-come-from)).

**Sign each entry** on its own route. A signature is the certificate of the
Package Signer that made it and that signer's Ed25519 signature, in one DER
value written as lowercase hex; a release's `.sig` holds one for each of the
Client's archives:

```console
$ curl -X PUT -H 'Content-Type: application/json' -d "{\"signature\": \"$sig\"}" \
       http://127.0.0.1:4321/api/v1/packages/otelcol-contrib/0.109.0/entries/linux/amd64/signature
```

**The signature belongs to the entry.** What it covers — the Agent type, the
version and the artifact's SHA-256 — names no Deployment, so one signature
serves every Deployment that holds the Package. **The Server never offers an
unsigned entry**: an entry without one is no candidate, and the fleet view says
the signature is missing. A signature for an entry that does not exist is `404`,
an empty or malformed one `400`. Uploading new bytes to an entry removes its
signature, because it covered the old hash. Supplying a signature on the
artifact upload instead answers `400` naming the route that takes it.

**The Server refuses a signature that does not verify.** It checks each one up
to the Package Roots compiled into it, over the entry's Agent type, version and
SHA-256: the Package Signer's certificate must be issued by one of those Roots
and not expired, and its signature must cover that entry. One that fails
answers `400`, naming the step that failed, and nothing is stored. Each
Client's own check still decides what is installed. Today the release run holds
the only Package Signer, and it signs the Client's own archives alone: a
signature made with a key of your own, as `classisctl package sign` makes one,
is refused, so a Package of any other Agent type, the Collector's above
included, cannot be signed yet.

Each entry reports its `signature_state`: `valid` or `missing`. At startup the
Server checks every stored signature again and sets aside one that does not
verify, one whose Package Signer has expired among them, with a warning in its
log naming the entry and the step.
That entry is offered to nobody and reported `missing` while the Server runs;
the signature stays in the store, so a Server started with a wrong clock loses
nothing: once the clock is right, restart the Server to offer the entry again,
or upload the release's `.sig` to replace it. An entry of a Package already
assigned to an Agent is not writable, so release a new version instead.

A Package is one file, `data_dir/packages/<agent type>@<version>.json`, naming
each entry's artifact by its SHA-256; the bytes are `data_dir/blobs/<sha256>`.
Two entries with identical bytes share one blob, and a blob goes when the last
entry naming it does. Every blob is hashed again at startup, and one whose
content does not match its name **fails the start naming it**, as does a file in
either directory this Server did not write — a store left over from an older
layout would otherwise open successfully and empty, which reads as "nothing
uploaded yet".

A Package that no Deployment holds reaches nobody, and the package list says so
— `in no deployment` in the UI, an empty `deployments` array in the API. That is
the state a Selector matching no one used to be.

### Put it in a channel, roll it out

```console
$ curl -X PUT -H 'Content-Type: application/json' -d '{"selector": {"channel": "beta"}}' \
       http://127.0.0.1:4321/api/v1/deployments/beta
$ curl -X PUT http://127.0.0.1:4321/api/v1/deployments/canary/packages/otelcol-contrib/0.109.0
$ curl -X POST http://127.0.0.1:4321/api/v1/deployments/canary/rollout
```

**Nothing is offered before that last line.** Everything above stores; the
**rollout act** is the only thing that distributes, for the Package and the
channel's Configurations alike. The press replaces each Agent's assignment with
one release: the Package the channel holds for its type, when that is an
upgrade, and every Configuration that fits its type, at its saved revision. A
Package the press cannot move — the Agent already runs it, or it would move it
backwards — stays pinned as it is. Five platforms' artifacts can be uploaded,
signed, put in a channel and then released together, and the window in which a
half-described release is already reaching the fleet does not exist. An Agent
that enrols — or is labelled into the channel — later waits, marked pending on
its fleet row, for an act of its own.

**A channel holds at most one Package per Agent type**, because an Agent has one
binary to replace. A second is refused `409` naming the one in the way;
`?replace=true` is how you say you mean to swap the version the channel runs.
Adding the same one again is the same request arriving twice and succeeds.

A rollout of a Deployment holding no Package and no Configuration is refused
`409`, and so is one holding a Package with an unsigned entry — naming each such
Package and the platforms it is unsigned for — and nothing is released. The UI
marks such a package `⚠` on the channel's row.

**While a Package is rolled out to at least one Agent its entries are frozen**,
signatures included (the fleet is installing those bytes; uploads and signature
writes answer `409`); ship a change as the next version, which is a new Package.
**The channel freezes nothing**: its Selector, its Packages and its
Configurations stay editable in every state, because an Agent's assignment pins
the Package and the revisions themselves. Swapping the version a channel holds,
editing a Configuration or taking one out is how a rollout proceeds: the hosts
already released keep what they have, and the change shows as waiting until the
next press.

**Nothing in use can be deleted.** Deleting a Package or a Deployment that an
Agent's assignment pins is refused `409`, saying how many Agents pin it; roll
those Agents out through a Deployment without it, or forget them, first. A
deleted Package leaves every Deployment that held it, and **nothing is
uninstalled** — an Agent keeps running what it installed.

### The canary shape

Two channels, disjoint by label, each holding its own version:

```sh
curl -X PUT -d '{"selector": {"channel": "stable"}}' … /api/v1/deployments/stable
curl -X PUT -d '{"selector": {"channel": "beta"}}'   … /api/v1/deployments/beta
```

There are two ways to move, and with a `channel` key the second is the ordinary
one:

- **Move a host** — change its label from `stable` to `beta`, and it takes what
  the beta channel holds. This is how a single machine is tried first.
- **Move the release** — give the `stable` channel the version `beta` already
  carries and press again. The hosts never move; the channel they subscribe to
  is handed the next version. This is how a rollout _finishes_.

**Widening the beta channel instead is not how it ends** — it would make both
channels claim the same hosts, which is a conflict, not a rollout.

### Fit runs before aim, and it is mandatory

A Package built for another **Agent type** is not a candidate at all: its type
is matched against the `service.name` the Agent reports, so a Promtail artifact
never reaches a Collector even from a channel that claims it. Then an entry must
exist for the **platform** the Agent reports. Only what survives both is what
its channel can release. **An Agent that reports no `service.name`, `os.type`,
or `host.arch` is offered nothing** — there is no artifact that can be known to
be meant for it or to run on it, and guessing is how a fleet-wide outage starts.

### Reading the counts

A Deployment carries three, because zero has three meanings and only the first
is a mistake to go hunting for:

| count                | zero means                                                                                            |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| `claiming_agents`    | the channel aims at nobody — a Selector naming an attribute nobody reports, or a value nobody carries |
| `targeted_agents`    | everyone it claims already holds what a press would release; nothing to do                            |
| `conflicting_agents` | _non_-zero is the one to act on: another channel claims those Agents too                              |

On the other side, each Agent's row says which channel claims it (`deployment`)
as well as which one released what it runs (`assigned_deployment`). The two
differ on purpose, and reading them together tells apart four states that would
otherwise be the same empty cell — because the next move differs in each:

| the row shows                                     | what it means                                                                                                              | what to do                                                                 |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| no `deployment`, no conflict                      | no channel's Selector matches this host                                                                                    | label it, or give it a `channel` attribute                                 |
| a `deployment`, nothing assigned, nothing pending | the channel holds nothing this Agent can take — no Configuration for its type, and no Package for its type or its platform | put the right Configuration or Package in the channel, or upload the entry |
| a `deployment` and something pending              | it is waiting for a rollout act                                                                                            | press it                                                                   |
| `package_conflict`                                | two channels claim it                                                                                                      | narrow one Selector                                                        |

**A rollout act never moves an Agent backwards.** The version an Agent reports
installed is part of matching: a Package reaches it only if the Package's
version is **greater**, compared as SemVer (major, minor, patch, then the
pre-release rules). Equal is not greater — a Package an Agent already runs
reaches it with nothing — and a reported version nothing can order is refused
rather than guessed at. The bulk act leaves the package part of such Agents as
it is; a per-Agent press that would change nothing because of it answers `409`
and says which version the Agent reports.

**An Agent that reports no version for the package is held against the version
it reports _running_** — its `service.version`. That is what makes the rule
reach a Client installed from a `.deb`, an `.rpm` or an MSI, which has installed
no package and has none to report: no Client is offered the version it already
runs, and none is moved backwards. A `service.version` nothing can order
(`1.19`, `24.04.1`) simply says nothing, so an Agent whose program numbers
itself its own way stays reachable. Its Packages are numbered in the program's
own space, written as SemVer: `1.19` becomes `1.19.0`, `24.04.1` becomes
`24.4.1`.

**A Package an older Server stored under a version that is not SemVer is kept
and inert.** At startup the Server logs one warning per such Package, naming it.
It is nobody's candidate, and every write to it — an entry, a signature, adding
it to a Deployment — is answered `400`. It can be read, and deleted once no
assignment pins it; an assignment that already pins it stays in force and its
offer still goes out, which an upgraded Client refuses and reports. Republish
the content under a SemVer version, sign it again, and roll that out. The
Client's own rules — no version below the highest it has installed for the type
— are in [the Client's manual](client.md#a-supervisor-never-goes-back).

**Where an Agent reports both, what it _runs_ decides**. The Package must be
greater than the `service.version` the Agent reports, and the package status is
not read beside it — neither to admit a Package the running version refuses, nor
to refuse one it admits. A statement about the present outranks a record of an
install, which outlives the binary it describes. So a claim the Agent's own
program denies never holds the package back, in either direction: a Client
reporting `supervisor 0.4.2` installed while reporting that it runs 0.4.0 — a
state directory that outlived its binary, a self-update that staged and did not
take effect — is offered 0.4.1, where the claim used to refuse it as a downgrade
and strand the host for good. The `409` names the version that decided and says
that the claim was not consulted.

**What this costs, and whom it touches.** Where a program reports a version
_above_ the Package that carries it, no Package below that number reaches it any
more, and where it reports one below, a Package between the two can move its
package backwards — a Collector calling itself `0.98.0` under an `otelcol`
Package at `2.0.0` can be assigned a `1.5.0`. Nothing moves on its own: a
rollout is an explicit act and you see the version you press. This reaches only
Agents that report a `service.version` of their own — the Client itself, and an
OpAMP-aware Managed Process such as a Collector carrying `opampextension`. An
Icinga 2 or a GLPI Agent reports none, so its Packages keep being matched on the
package status alone. **Number a Package the way the program it carries numbers
itself**, and neither case arises.

Versions are still kept side by side — a new version is a new Package, and the
older artifact stays in the store — but **taking a bad version back is not a
rollout**:

- on the host, the version a package superseded is retained for
  `retain_previous_secs` and put back when the new one fails its health gate
  (see the Client manual, _Package updates: rollback and retention_);
- a Client that will not stay up after its own self-update goes back by itself;
- fleet-wide, what is left is publishing the older content **as a new, greater
  version** — which is honest about the fact that the fleet moves forward, and
  is the only thing the matching rule will carry.

**Deleting.** `DELETE /api/v1/packages/otelcol-contrib/0.109.0` removes the
Package — its entries, artifacts and metadata — and takes it out of every
Deployment that held it; the entry route with a platform removes just that one
entry. Both, and `DELETE` on a Deployment, are refused (`409`) while an Agent's
assignment pins what they name: roll those Agents out through another
Deployment, or forget them, first. Nothing is uninstalled by any of them.

**Building and signing**. The helper that ships with the Client writes the
artifact, hashes it, and signs it:

```console
$ classisctl package pack --out promtail-3.0.0.tar.gz ./promtail   # prints the sha256
$ classisctl package keygen --out fleet-signing.pk8                # prints the public key
$ sig=$(classisctl package sign --key fleet-signing.pk8 --agent-type promtail --version 3.0.0 \
      promtail-3.0.0.tar.gz)
```

`pack` writes `.tar.gz` or an AES-256-encrypted `.7z`, and names the member the
way the receiving Supervisor will look for it. A Client opens those two and
`.zip`; an artifact that is none of the three is taken to _be_ the program.
[The rollout walkthrough](rollout.md) puts the whole sequence together. `keygen`
and `sign` still exist, but a signature they make comes from no Package Signer,
and this Server and every Client refuse it.

The download route sits on the **Agent plane**, outside `[rest.auth]`. A
downloading Client presents its access token, and it presents it to this
Server's own origin and to no other host. Guarding the Operator plane therefore
cannot break a rollout. The content
hash and the signature are what protect an installed binary.

No key is given to a Client: each one checks a signature up to the Package
Roots compiled into it, and every Client takes packages.

### A host fetches only what its Agents are offered

The download route serves an uploaded artifact only to a host whose Agents are
offered that artifact — its Agent type, version and Platform — by a rollout. A
host is the client whose token the request carries, and it is served for the
Agents that reported under it. An artifact stays offered until the Agent's
assignment changes, so an Agent that echoed its offer and then failed to install
can fetch it again. A version saved in a Deployment but not yet released by a
rollout is offered to no one and cannot be fetched by anyone.

Every other request for an artifact is answered `404` with the same status, body
and headers as a request for an artifact the store does not hold: an artifact
released to another host's Agents, one released to nobody yet, and an entry that
carries no signature. A malformed type, version or Platform is still answered
`400`, and a request without a valid token `401`. Each refused fetch leaves a
`download.refused` event at `debug` in [the log](#security-decisions-in-the-log)
with `check` `not offered`, the host, and the type, version and Platform asked
for. The token is admitted before the route decides what it may fetch, so a
refused fetch leaves both an `admission.admitted` and a `download.refused`
event: an `admission.admitted` says the token was let in, not that an artifact
was served. Such a refusal is no failed authentication, so it does not count
toward [the throttle](#repeated-failures-are-throttled). Each download, served
or refused, takes a token from the host's bucket
([How often a host may be heard](#how-often-a-host-may-be-heard)).

A `404` for an Agent that was offered an artifact therefore means one of two
things: the Agent now reports another Agent type than the Package was built for,
or a later rollout changed what it is offered.

## The REST API

The OpenAPI document at `/api/v1/openapi.json` is the contract; `/api/v1/docs`
renders it. Every error response carries a JSON body with an `error` field, so a
generated client has something to show. All of it is served on the Operator
plane (`127.0.0.1:4321` by default), in plain HTTP behind the proxy, and, when
[`[rest.auth]`](#the-operator-plane-restauth) is configured, needs Basic
credentials. `[rest.auth]` is required whenever the plane listens off the
loopback.

| Method & path                                                                          | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/v1/agents`                                                                   | The whole fleet: every Agent, its attributes, capabilities, the Deployment that claims it, what is rolled out to it and what waits, package installations, health, and sync state.                                                                                                                                                                                                                                                                                         |
| `POST /api/v1/agents/{instance_uid}/restart`                                           | Queue a restart of that Agent's Managed Process. Delivered on the next exchange — pushed over WebSocket, on the next poll over plain HTTP. Only Supervisor-backed Agents accept it; a Client's own Agent has no process to restart.                                                                                                                                                                                                                                        |
| `PUT /api/v1/agents/{instance_uid}/labels`                                             | Set this Agent's labels — see [Labels: rollout channels without touching the host](#labels-rollout-channels-without-touching-the-host). Body: `{"labels": {…}}`; an empty map clears them.                                                                                                                                                                                                                                                                                 |
| `DELETE /api/v1/agents/{instance_uid}`                                                 | Forget this Agent — see [Forgetting an Agent](#forgetting-an-agent) below. Reaches no host. `409` while it is still reporting.                                                                                                                                                                                                                                                                                                                                             |
| `POST /api/v1/agents/{instance_uid}/rollout`                                           | The per-Agent rollout act: releases the Deployment that claims this Agent to it, replacing its assignment. Empty body, or `{"deployment": "…"}` naming that Deployment. `409` when the Agent is in no Deployment, in a conflict, or in another one than named, when the Deployment holds nothing or a Package with an unsigned entry, and when the press would change nothing because the Package it holds is no upgrade (the reason names the version).                   |
| `GET /api/v1/configurations`                                                           | Every Configuration — the saved revision each, with the Deployments that hold it.                                                                                                                                                                                                                                                                                                                                                                                          |
| `GET /api/v1/configurations/{name}`                                                    | One Configuration.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `PUT /api/v1/configurations/{name}`                                                    | Create it, or replace its saved revision. Body: `{"body": "…", "service_name": "…", "role": "…"}` — `role` may be omitted; without `service_name` it is refused `400`, as is a `selector`. **Distributes nothing**.                                                                                                                                                                                                                                                        |
| `DELETE /api/v1/configurations/{name}`                                                 | Remove it, and take it out of every Deployment that holds it. `409` while an Agent's assignment pins it, saying how many.                                                                                                                                                                                                                                                                                                                                                  |
| `GET /api/v1/packages`                                                                 | Every stored Package (never the artifact bytes), each with its entries — their hash, size, signature and `signature_state` (`valid` or `missing`) — and the Deployments that hold it.                                                                                                                                                                                                                                                                                      |
| `PUT /api/v1/packages/{agent_type}/{version}`                                          | Create a Package. The body has no writable field — `{}`. **Distributes nothing**. The version is SemVer 2.0.0: any other is answered `400`, naming it — `1.19.0` for upstream's `1.19`.                                                                                                                                                                                                                                                                                    |
| `GET /api/v1/packages/{agent_type}/{version}`                                          | One Package.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `PUT /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}`                      | Upload one platform's artifact (the raw body); new bytes remove the entry's signature. `409` while the Package is rolled out to an Agent. The signature is written through the entry's signature route.                                                                                                                                                                                                                                                                    |
| `PUT` / `DELETE /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature` | Record or remove that entry's signature: the Package Signer's certificate and its Ed25519 signature in one DER value, as a release's `.sig` holds it. Body: `{"signature": "<hex>"}`, lowercase. `404` for an entry that does not exist, `400` for an empty or malformed signature or one that does not verify up to the Package Roots, naming the step, `409` while the Package is rolled out to an Agent. The answer is the Package, with the entry's `signature_state`. |
| `DELETE /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}`                   | Remove one entry. `409` while the Package is rolled out to an Agent.                                                                                                                                                                                                                                                                                                                                                                                                       |
| `DELETE /api/v1/packages/{agent_type}/{version}`                                       | Remove the Package, and take it out of every Deployment that holds it. `409` while an Agent's assignment pins it, saying how many. Uninstalls nothing.                                                                                                                                                                                                                                                                                                                     |
| `GET /api/v1/packages/{agent_type}/{version}/file?os=…&arch=…`                         | The artifact bytes — where an offered `download_url` points. **The one route on the Agent plane** (`:4320`), and never guarded by `[rest.auth]`: it is not in the OpenAPI document for the same reason. It requires the host's access token, and a request without a valid one is answered `401`. It serves only an artifact offered to an Agent of the host, and answers every other request `404`, as for an artifact that does not exist.                               |
| `GET /api/v1/deployments`                                                              | Every Deployment, with its channel, its Packages, its Configurations, and the three reach counts.                                                                                                                                                                                                                                                                                                                                                                          |
| `PUT /api/v1/deployments/{name}`                                                       | Create one or re-aim it. Body: `{"selector": {…}}` — **never empty** (`400`). **Distributes nothing**.                                                                                                                                                                                                                                                                                                                                                                     |
| `GET` / `DELETE /api/v1/deployments/{name}`                                            | One Deployment; `DELETE` is `409` while an Agent's assignment names it, saying how many, and uninstalls nothing.                                                                                                                                                                                                                                                                                                                                                           |
| `PUT /api/v1/deployments/{name}/selector`                                              | Re-aim it. Never distributes.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `PUT /api/v1/deployments/{name}/packages/{agent_type}/{version}`                       | Put a Package in the channel. `409` on a second of an Agent type it already holds; `?replace=true` swaps it. `404` for a Package nobody uploaded.                                                                                                                                                                                                                                                                                                                          |
| `DELETE /api/v1/deployments/{name}/packages/{agent_type}/{version}`                    | Take it out. Never refused for being rolled out: the next press drops it from the Agents' release.                                                                                                                                                                                                                                                                                                                                                                         |
| `PUT` / `DELETE /api/v1/deployments/{name}/configurations/{configuration}`             | Put a Configuration in the channel, or take it out. `404` for a Configuration the Server does not hold, or, on `DELETE`, one the channel does not hold. **Distributes nothing**.                                                                                                                                                                                                                                                                                           |
| `POST /api/v1/deployments/{name}/rollout`                                              | Roll it out to every Agent it claims and would move — its Packages and Configurations in one release, the moment a rollout starts. Agents another Deployment also claims are skipped and reported as conflicts. `409` while the channel holds no Package and no Configuration, and `409` naming each Package and platform while any entry of a Package it holds lacks a signature.                                                                                         |

The package routes answer `404` while package delivery is not configured on this
Server.

### Whom a rollout actually reaches

The counts live on the **Deployment**, because that is what aims (see _Reading
the counts_ above). A Package carries no count of its own — it aims at nobody —
and answers the question by naming the channels that hold it. A Package in no
channel is stored and unreachable, which is the state a Selector matching nobody
used to be.

`targeted_agents` is the Agents a rollout act would change — their release
differs from what their assignment pins; `claiming_agents` is who is in the
channel whatever they run; `conflicting_agents` is who this channel cannot reach
because a second one claims them too. It answers for the fleet **as reported so
far**: a channel aimed at hosts that have not connected yet legitimately reaches
nobody, which is why these are counts to be read rather than errors to be
raised.

### Labels: rollout channels without touching the host

A Deployment's Selector aims it at the Agents whose attributes match it — and
the attribute a staged rollout actually wants, `channel = "beta"`, is one you
invent. Until now it could only be invented in `[attributes]` in
`supervisor.toml`, so moving a host between channels meant editing a file **on
that host** and restarting it.

**Labels are that attribute, set from here**:

```console
$ curl -X PUT -H 'Content-Type: application/json' \
       -d '{"labels": {"channel": "beta"}}' \
       http://127.0.0.1:4321/api/v1/agents/<instance-uid>/labels
```

A label is matched exactly like a reported attribute, by the Selector of the
Deployment the Agent belongs to — which carries its Configurations and its
Package alike. So trying a new collector binary on a few hosts is a Deployment
aimed at `channel = beta` plus this call on the hosts that should get it first —
and moving a host back is the same call with the value it had.

The same call carries any other partition:
`{"labels": {"region": "eu-central"}}` or `{"labels": {"tenant": "acme"}}`. The
Server treats all of them identically, because it knows none of them — see
[Channels are a partition](#channels-are-a-partition-not-a-default).

It takes effect at once: a connected Agent is pushed whatever its new channel
gets, rather than waiting for its next poll.

**A label may not restate an attribute the Agent reports** — that is refused
with `409`, naming the key. Reported attributes are not annotations: `os.type`
and `host.arch` decide which artifact fits the machine and `service.name`
decides which packages fit it at all. If a label could outrank them, a slip here
would offer a host a binary built for another one. Where an Agent reports
something wrong, the fix belongs in that host's `supervisor.toml`, where the
wrong value comes from.

If an Agent _starts_ reporting a key that was labelled earlier, the reported
value wins and the fleet row marks the label as shadowed — set, and matching
nothing.

**A label whose key starts with `fleet.` is refused with `400`.** That space is
the Server's own.

**Label the Client once.** A Client presents an Agent for itself — the one that
reports `supervisor.kind.*` — and one per Supervisor. The labels set on the
Client's own Agent hold for its other Agents too, below their own labels: a
Supervisor Agent labelled `ring = late` stays in that ring whatever its Client
is labelled. The Server tells a Client's Agents apart by the host they
reported under: the Agents of one host are one group. Where a group holds more
than one Client Agent, no Agent of it inherits anything, and the fleet view
marks them as ambiguous. The Agents tab
shows inherited labels on each Agent, marked as such.

**What a Selector matches** is each Agent's effective description, the same for
every Deployment. For each key it takes the first source that has it:

1. What the Agent reported: identifying attributes, then non-identifying ones. A
   reported attribute whose key starts with `fleet.` is left out and listed in
   `ignored_attributes` on its fleet row, so no Agent can speak in the Server's
   name.
2. The Agent's own labels.
3. The labels of its Client Agent.

**Labels are yours, not the Agent's.** They never travel to it; the Agent only
ever experiences the effect, which is the configuration and the software it is
offered. They are part of the Agent's record on the Server and survive a
restart. They follow the Agent when the Server re-keys it, and **forgetting an
Agent removes them**: an Agent that comes back starts with the labels of its
Client Agent only, so label the Client Agent rather than each Agent where you
can.

### Forgetting an Agent

A host that was decommissioned leaves a row behind, and nothing ages it out.
`DELETE /api/v1/agents/{instance_uid}` — the `✕ forget` action on a fleet row —
drops what this Server knows about that Agent.

**It does nothing on the machine.** No process is stopped, nothing is
uninstalled, and nothing is revoked: a token proves the host, never which Agent
is speaking, so forgetting one Agent leaves the host's client and token as they
are. A Client that is still running and still pointed at this Server reports
again within its polling or heartbeat interval and the row comes back.
Forgetting tidies the view; **to remove an agent for good, stop it on the host**
(`supervisor service uninstall`) and then forget it here.

It is refused with `409` while the Agent is still reporting — connected, and
heard from within the staleness budget. That is not caution for its own sake:
the record holds the hashes that tell this Server not to re-offer what an Agent
already has, so forgetting a live Agent has its configuration sent again, and a
Managed Process restarts whenever a configuration arrives. Stop the agent first,
or wait for it to fall silent. An Agent that is already disconnected can be
forgotten at once.

The same applies to one that comes back later: it is offered its configuration,
its connection settings, and its packages afresh. The packages cost nothing —
the Client re-installs nothing whose content hash it already has — but the
configuration is applied again, which for a managed agent is one restart. That
is the price of forgetting something that was not really gone.

**Its labels go with it.** They are part of the Agent's record, so an Agent that
comes back is labelled only by what its Client Agent's labels give it.

**Its binding goes with it.** The Agent's `instance_uid` is released from the
host it was recorded under, so its next report records it under the host whose
token carries that report. Forgetting an Agent that still runs elsewhere lets
the next host that reports it take it.

Nothing expires on its own: there is no retention sweep and no inactivity
timeout, so a row stays until someone forgets it.

## Authentication

The Agent plane admits by **access token**; see [How a host joins the
fleet](#how-a-host-joins-the-fleet). `server.toml` holds no credential for it,
and an `[auth]` section is refused at startup, naming `[auth]`. `/v1/opamp` and
the download route read `Authorization: Bearer
<token>`, and a request without a valid token is answered `401` with a
`WWW-Authenticate: Bearer` challenge.

The Operator plane is the one with a credential in `server.toml`,
[`[rest.auth]`](#the-operator-plane-restauth) below. It never reaches an Agent's
host.

### Credentials are kept as hashes

No credential in `server.toml` authenticates on its own, so a copy of the file —
in a backup, a diff, configuration management — admits no host and signs in no
operator. An operator's Basic password is listed by its Argon2id hash, with at
least `m=19456`, `t=2` and `p=1`. A value in clear or a weaker hash is refused
at startup, naming the section and the user without repeating the value. Make
each entry with the Server itself:

```console
$ server hash-credential --basic
secret:
$argon2id$v=19$m=19456,t=2,p=1$…
```

`--basic` is the one scheme; it reads the password from standard input, without
showing it on a terminal, and prints the hash to paste.

The package download route sits outside `[rest.auth]`: it is guarded by the
host's access token, and its content hash and signature protect what it serves.

The records in `data_dir` are not `server.toml`. A Space's enrolment key is
stored whole in `spaces/`, so it can be read again, and every client keeps only
the SHA-256 of its secret and of its token ([How a host joins the
fleet](#how-a-host-joins-the-fleet)).

### Repeated failures are throttled

`[admission_throttle]` limits how often one peer address may fail to
authenticate:

```toml
[admission_throttle]
max_failures = 10      # failures within the window that start a back-off
window_secs = 60
backoff_secs = 300     # how long the address is answered 429
```

On the Agent plane a refused authentication counts as a failure of the peer's IP
address: a `401`, or a `400` that carries a `WWW-Authenticate` challenge, from
`/v1/enrol`, `/v1/token`, `/v1/opamp` (either transport) or the package
download. An address that reaches `max_failures` within `window_secs` is in
back-off for `backoff_secs`. During the back-off each request to those routes is
answered `429` with `Retry-After` set to the seconds remaining, before anything
else is checked. A WebSocket upgrade is refused the same way before it
completes. A successful request clears nothing — behind a shared address one
host's success would wipe another's count — so failures only age out of the
window. An IPv6 address is counted by its /64.

A refusal that comes after authentication counts for nothing: an
`invalid_client_metadata` or an `invalid_scope`, a `400 invalid_request` of
`/v1/token` that carries no challenge, or a download answered `404`. The
Operator plane counts its own `401`s the same way, in a table of its own: an
address in back-off on one plane is still answered on the other. `0` for any of
the three keys is refused at startup.

### How often a host may be heard

Admission lets a host in; `[agent_rate_limit]` bounds how often it is heard
after that:

```toml
[agent_rate_limit]
messages_per_sec = 10   # tokens a host's bucket gains per second
burst = 300             # that bucket's capacity; a new bucket starts full
```

Each message on `/v1/opamp`, over either transport, takes one token before
anything else is done with it, and so does each request on the package download
route once its token is admitted. A message that cannot be decoded is counted
too. The bucket is the host's — the client the token names — so every Agent of a
host shares it.

A message past the limit is not processed: no record changes. It is answered
with the message's own `instance_uid` and `error_response` `Unavailable` with
`retry_info` of 30 seconds, on plain HTTP in the body of a `200`. The connection
stays open. A Client waits the 30 seconds, and the next message the Server
processes from that Agent is asked for a full report, so nothing is lost. A
download past the limit is answered `429` with `Retry-After: 30`; it is no
failure toward `[admission_throttle]`, and the Client waits it out before it
asks again, for up to 30 minutes per download. Beyond this limit the Server
honours the protocol's error and retry semantics as well, and answers malformed
input with `BAD_REQUEST`.

Every refusal is logged as `agent_rate.throttled`, naming the host, the peer
address and the route (`opamp` with its `transport` and the `instance_uid`, or
`download`), at `debug`. Nothing aggregates them: a host that floods writes one
line per refusal.

The default `burst` lets one full report from each of the 256 Agents a host may
speak for through after a reconnect. `messages_per_sec` times the offered
`[connection_offer] heartbeat_interval_secs`, or 30 seconds without one, is how
many Agents one host can report for at that interval; the Server logs a warning
at startup naming both keys when that is below 256. The buckets live in memory,
at most 100 000 of them, and a full table forgets the bucket used least
recently. `0` for any key is refused at startup; no value switches the limit
off.

### The Operator plane: `[rest.auth]`

`[rest.auth]` guards **the whole Operator plane** — `/api/v1/…`, the OpenAPI
document, the API docs, and the UI at `/`. With it, every request needs Basic
credentials and anything else is answered `401` with a `WWW-Authenticate: Basic`
challenge. On a loopback `[rest] listen` the section is optional, and the
plane's address is what protects it. On any other address it is required: a
Server without it is refused at startup with a message naming both keys.

```toml
[rest]
listen = "0.0.0.0:4321"          # publishing it requires the section below

[rest.auth.basic_users]
fleet-admin = "$argon2id$v=19$m=19456,t=2,p=1$…"
```

Basic, and only Basic, because the audience is a browser and `curl`: the browser
answers the challenge by itself, so the bundled UI needs no login page, no
session, and no cookie. Several users are how a credential is rotated — add the
new one, hand it out, remove the old — or how one operator's is withdrawn
without touching anyone else's.

**The operator tools carry it in the URL** they are given, which needs no new
flag. On the Server's host, or through an SSH tunnel to it, the plane answers in
plain HTTP:

```sh
curl -u "fleet-admin:$PASSWORD" http://127.0.0.1:4321/api/v1/agents
classisctl package fetch … --server "http://fleet-admin:$PASSWORD@127.0.0.1:4321"
```

From anywhere else, name the HTTPS address of the reverse proxy in front of it
instead, `https://classis.example.org` for instance.

Two limits worth stating plainly. It is **authentication, not authorization**:
everyone listed can do everything the plane offers — there are no roles, and one
Server still manages one fleet. And Basic sends a reusable password on **every**
request. The Server serves no TLS: the password is protected only as far as the
proxy's TLS reaches, crosses the hop between the proxy and the Server in the
clear, and `server.toml` holds only its Argon2id hash.

## The operator's socket

Beside the two listeners the Server answers the operator's `classis-cli` on a
Unix domain socket: `admin_socket`, `/run/classis/admin.sock` by default, bound
on every start. The Server targets Linux; a Windows build binds no socket.

The Server sets the socket to `0600`, owned by its own account, and creates
missing parent directories `0700`. An existing directory keeps its mode: the
socket's parent must be owned by the Server's account or root and not writable
by group or others. Its ancestors must also be owned by one of those accounts
and not writable by group or others, except for sticky directories such as
`/tmp`. Unsafe paths refuse startup rather than changing an existing directory.

Before a byte of a request is read, the peer's account is taken from the
connection's credentials and must be the Server's account or root — whose
`sudo classis-cli` is how an operator who is not the Server's account reaches
it; any other account is refused. The socket has no password of its own.

The socket is created before its mode is set, so binding and `chmod` are not one
atomic step. The protected directory prevents another account replacing the
path, and the peer check refuses any connection from an unauthorized account.

A socket an earlier run left at the path is replaced; a live socket is refused.
Anything else standing there — a file, a directory, a symlink — is not the
Server's to remove, and the start stops with a message naming the path. That is
also the answer a Server gets whose `admin_socket` it cannot write, in a
container with a read-only root filesystem for one: no plane keeps running
behind a refused socket, because the socket is how its Spaces are managed.

Do not start two Servers on the same socket path: simultaneous replacement of a
stale socket can race and leave one unreachable. Once bound, a failed `accept` is
logged and retried, so a transient error (running out of descriptors, typically)
neither ends the loop nor leaves the operator without a socket while both planes
run.

```console
$ classis-cli space create lab
cle1_lab_…
$ classis-cli space list
lab
prod
$ classis-cli space rotate-key lab
cle1_lab_…
```

`create` prints the Space's new enrolment key, `list` one name per line,
`rotate-key` the replacement; the old key enrols nothing from then on.
`--socket <path>` names another socket and must name the one the Server's
`admin_socket` names, since a relative path resolves against the working
directory of whichever process reads it. In development, where
`config/server.toml` puts the socket beside `fleet-data`:

```sh
cargo run -p classis-admin -- --socket fleet-run/admin.sock space create lab
```

`enrol-command` prints the one command that installs a host and enrols it,
against the Server's `public_url` ([the install
one-liner](#the-install-one-liner)). With `public_url` unset it refuses — the
Server never guesses the address its proxy answers for — and the `space` commands
answer regardless.

None of this is on the Operator plane: no REST route creates a Space or touches
its key, `[rest.auth]` does not reach the socket, and the socket answers no
HTTP. The CLI ships inside the Server's image on Linux
(`/usr/local/bin/classis-cli`, run with `docker exec`); from a checkout, build it
with `cargo build --release -p classis-admin`.

## Plain HTTP behind a reverse proxy

Both listeners speak plain HTTP, on whatever address `listen` and
`[rest] listen` name. There is no TLS to configure on the Server, no certificate
to mount and none to renew: a reverse proxy in front of it terminates TLS and
forwards the request, and what protects the hop between them is the network they
share — a NetworkPolicy that lets only the proxy reach the Server's ports.

- **The operator's password crosses that hop in the clear.** So does every
  enrolment key, client secret and access token, and every package.
- **The peer is the address in `X-Forwarded-For`.** The left-most entry that
  parses as an address (`203.0.113.7`, `203.0.113.7:51000` or `[2001:db8::1]`)
  is the peer the admission throttle counts; without the header, the
  connection's address. **The header is trusted from any source**: whoever can
  reach the port can write it, name any address, and so keep their own failures
  from filling the throttle or put another host's address in back-off. Keep the
  Server's ports closed to everything but the proxy. The proxy must discard any
  incoming `X-Forwarded-For` and set it to the verified client address, not
  append to the incoming header; otherwise clients can bypass peer limits.
- **Outbound connections stay TLS 1.3**: to PostgreSQL and to S3.

An Agent that still presents a client certificate is not refused for it: the
certificate is not read.

### Bounds on every listener

Each plane is bounded before a request is parsed:

- **A connection cap per plane**: `max_connections` (default 10 000) for the
  Agent plane and `[rest] max_connections` (default 256) for the Operator plane.
  A connection past the cap is closed on accept, while the ones already held
  keep working.
- **A peer has 30 seconds** to send its HTTP/1 request headers.
- **HTTP/2** allows 100 concurrent streams per connection. A keep-alive ping
  goes out every 30 seconds, and a peer that leaves one unanswered for 20
  seconds is dropped.

Only the caps are keys, because they depend on the size of the fleet. The other
bounds are the same in every deployment.

## The fleet's own telemetry

`[telemetry_offer]` is where the fleet's Clients send their own metrics, logs,
and traces. Each signal is independent, and each is offered only to Agents that
declare they can report it:

```toml
[telemetry_offer]
metrics_endpoint = "https://collector.example:4318/v1/metrics"
traces_endpoint = "https://collector.example:4318/v1/traces"
logs_endpoint = "https://collector.example:4318/v1/logs"
[telemetry_offer.headers]
Authorization = "Bearer a-telemetry-token"
```

The endpoints are **full OTLP/HTTP URLs with path**. This Server appends no
`/v1/metrics` for you: guessing a receiver's routing is how telemetry disappears
into a `404` nobody looks at.

**Nothing is configured on the Client.** The capability an Agent declares means
"I can report to the destination _you_ name", so this section is the only place
a destination comes from — and with no section, no Agent sends anything.

What arrives: process metrics every 10 seconds (CPU, memory, uptime) for each
Client's own process _and_ for every process it supervises; each Client's own
log output as OTLP records; and a trace per fleet operation — `package.install`,
`config.apply` (a Managed Process's configuration, and a Client's Supervisor
set), `connection.settings.apply`, and `self.update`. Each carries its phases as
child spans and ends with the outcome the Client reported to this Server, so
_which phase_ a rollout failed in is a question the trace answers. Nothing else
is traced: the Clients' own message handling would be a continuous stream with
no outcome in it, and would bury the operations that have one.

A log record written during one of those operations carries that trace's id, so
a backend holding both signals can show the lines that explain a failure beside
the span that failed. Each Agent's Resource carries its identifying attributes,
so one host's several Agents stay apart at the receiving end.

Two limits worth knowing before you point this somewhere:

- **A cleartext destination is refused anywhere but the loopback**. `http://` is
  accepted only to the IP literals `127.0.0.1` and `::1`. The rest of
  `127.0.0.0/8`, the private ranges `10/8`, `172.16/12`, `192.168/16` and
  `fc00::/7`, link-local and carrier-grade NAT addresses are refused. The
  judgement is made on the parsed **address**: a host name over `http://` is
  refused, `localhost` included, and no name is resolved. The Agent refuses such
  a destination and reports the refusal back on the offer; it never warns and
  sends anyway. Every other destination is `https://` in TLS 1.3, so a Collector
  on the LAN, or one reached by name, needs TLS 1.3 in front of it. A
  destination that speaks only TLS 1.2 fails the handshake.
- **A Collector's internal telemetry does not come this way.** The Client must
  not touch a Managed Process's configuration, so what it reports about a
  Collector is what it can see from outside. Configure the Collector for its own
  internals as you would without OpAMP.

## Moving the fleet: connection settings

`[connection_offer]` is how the fleet is moved to a new heartbeat interval or a
new endpoint without touching every host. The Server compiles the section into
one hash-gated offer, and every Agent that accepts connection settings gets it,
**verifies it by actually connecting**, and switches only on success. An Agent
that cannot connect with the offered settings keeps the ones it has and reports
the failure.

The offer carries **no credential and no `headers`**: a host presents the access
token it holds, so an offered credential would be a value nothing reads. A
credential key in the section — `bearer_token_file`, `username`,
`password_file`, `bearer_token`, `password` — is refused at startup, naming the
key. A Client that is offered `headers` by another Server applies the rest of
the offer and reports it `FAILED`, naming the header keys.

**The offered `endpoint` is never plaintext**. It is `wss://` or `https://`. A
`ws://` or `http://` endpoint is refused at startup with a message naming
`[connection_offer] endpoint`, on `127.0.0.1` and `::1` too: on plaintext no
certificate proves the Server, so whoever listens on that port of a host would
be the Server for its Client. A development setup on the loopback names its
plaintext endpoint in `supervisor.toml` instead.

The standing offer carries no `tls` and no `proxy`: there is no configuration
surface for them.

## What the Server does not do

- **It does not require a password on a loopback Operator plane.** `[rest.auth]`
  is optional there, because the address is the guard; it is required the moment
  the plane listens anywhere else.
- **It does not weigh a message by its cost.** Every message and download takes
  one token of `[agent_rate_limit]`, whatever it carries. The Operator plane is
  not rate-limited; it is guarded by `[rest.auth]` and `[admission_throttle]`.
- **It does not fetch packages from anywhere.** Every artifact is uploaded to
  it; it makes no outbound request for a package and holds no credential for a
  source.
- **It does not have the last word on a signature.** It refuses one that does
  not verify, but each Client checks again, and its own check decides what is
  installed.
- **It does not install itself as a service.** Run it under whatever supervises
  services on the host — the Client is the end that ships its own service
  integration.
- **It has no user model and no multi-tenancy.** One Server manages one fleet.
- **It keeps no audit record.** Its security decisions are
  [events on its log](#security-decisions-in-the-log); nothing makes a line
  edited or removed afterwards visible.
