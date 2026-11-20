# Setting up a fleet

[← User Manual](README.md) · [The Server](server.md) · [The Client](client.md)

This page takes you from nothing to a running fleet, in order, with nothing but
the project's own two programs. You make the Server's certificate, configure and
start the Server, configure and install a Client, and enrol it. The
[Server](server.md) and [Client](client.md) pages describe every key; this page
says which ones a real deployment needs, and why.

The quick start in the
[manual's index](README.md#quick-start-a-closed-loop-on-one-machine) runs both
ends on one machine with throwaway certificates. Use this page for anything that
crosses a network. [A host's life](lifecycle.md) follows one host from
installation through enrolment to its updates, once the fleet stands.

- [How a host is admitted, at a glance](#how-a-host-is-admitted-at-a-glance)
- [1. Make the certificates](#1-make-the-certificates)
- [2. Configure and start the Server](#2-configure-and-start-the-server)
- [3. Make the package signing key](#3-make-the-package-signing-key)
- [4. Configure and install a Client](#4-configure-and-install-a-client)
- [5. Enrol the Client](#5-enrol-the-client)
- [6. Living with the enrolment](#6-living-with-the-enrolment)
- [When a connection is refused](#when-a-connection-is-refused)

## How a host is admitted, at a glance

Every connection is TLS 1.3. The Server proves itself to the host with its
certificate, and a host proves it belongs to the fleet with a bearer token, sent
as an `Authorization` header on every OpAMP exchange and every package download.
A host presents no certificate. It gets the token in three steps, and the
credentials of each are the ones in this table
([ADR-0064](../adr/0064-a-host-enrols-with-its-spaces-key-and-is-admitted-by-a-bearer-token.md)):

| Credential             | What it is                                                                                       | Where it lives                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| **Enrolment key**      | `cle1_<space>_<secret>`: one per Space, reusable without limit, the proof that a host may enrol. | on the Server's disk, so it can be read again; you give it to `enrol` once per host                 |
| **Client credentials** | the host's `client_id`, its Device ID, and a `client_secret` the Server makes when it enrols.    | in the host's `state.json`; the Server keeps only the SHA-256 of the secret                         |
| **Access token**       | an opaque bearer token, from the `client_id` and `client_secret`; one per host.                  | in the host's `state.json`; the Server keeps only its SHA-256, and a new token replaces the old one |

1. A Space is a named group of hosts on one Server. Its key names it:
   `cle1_lab_…` enrols into the Space `lab`. A valid key enrols a host at once,
   with no approval.
2. The host runs `enrol <base-url> <key>`. It registers with the key as an OAuth
   client (RFC 7591, at `/v1/enrol`), receives its client credentials, asks for
   its token with them (RFC 6749 client credentials, at `/v1/token`), and writes
   all of it to `state.json`, readable by its owner only.
3. The service starts, and every request it makes carries the token. A token
   that the Server stops accepting is replaced by asking again with the client
   credentials, and only then.

The **server CA** is independent of all of this: it signs the Server's
certificate, which a host checks. If the Server's address has a certificate from
a public CA, use that one instead and skip the server CA. The Client then trusts
the built-in roots, and its `ca_file` stays unset. Keep the server CA's key off
the Server host: whoever holds it can stand up a Server every host trusts.

## 1. Make the certificates

The operator tool `classisctl` makes the Server's certificate with its `pki`
commands; no other tool is needed. Every release publishes it for Linux and
macOS ([Getting it](tools.md#getting-it)); download it to the machine where the
offline keys are to stay, typically your own, not the Server host.

Run `pki init` there. Name every address the Clients will dial with `--name`, as
a DNS name or an IP address; repeat it for each:

```console
$ classisctl pki init --server-dir classis-server --offline-dir fleet-offline \
                         --name fleet.example.com --name 10.0.0.5 \
                         --server-path /etc/classis-server/tls --host-path /etc/opamp
classis-server: for the Server host — merge server.toml.fragment into its server.toml
fleet-offline: keep offline — the server CA's key and the package signing key; give every new host server-ca.pem, as supervisor.toml.fragment names it with the package verification key
```

`--server-path` and `--host-path` are where the files will live on the Server
host and on a managed host; the two `.fragment` files name them there. Left out,
they name the directories as `pki init` wrote them. It writes these files, and
nothing else:

| Directory       | File                       | Goes to                                                                                                                                             | Secret? |
| --------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `--server-dir`  | `server.pem`               | the Server (`[tls] cert_file`)                                                                                                                      | no      |
|                 | `server-key.pem`           | the Server (`[tls] key_file`)                                                                                                                       | **yes** |
|                 | `server.toml.fragment`     | the Server's `server.toml`, merged in: its `[tls]` section                                                                                          | no      |
| `--offline-dir` | `server-ca.pem`            | every Client (`[tls] ca_file`), and your browser                                                                                                    | no      |
|                 | `server-ca-key.pem`        | nowhere: keep it offline, to sign the next server certificate                                                                                       | **yes** |
|                 | `package-signing-key.pk8`  | nowhere: keep it offline, to sign every package ([step 3](#3-make-the-package-signing-key))                                                         | **yes** |
|                 | `package-signing-key.pub`  | the public half in hex: every Client's `[packages] verification_key`                                                                                | no      |
|                 | `supervisor.toml.fragment` | every new Client's `supervisor.toml`, merged in: its `[tls] ca_file` and the package verification key ([step 4](#4-configure-and-install-a-client)) | no      |

The directories are created `0700` and every key `0600`. `pki init` refuses to
write over a file that exists, and writes nothing at all then. Run on the Server
host, it says so: move the offline directory off that host before the fleet goes
live.

What it makes, so you need not:

- **A server CA**, `Classis Server CA`, which cannot sign a further CA, valid for
  ten years; replacing it means touching every host. `--product` replaces
  `Classis` in its name and in the server certificate's, and `--organization` and
  `--organizational-unit` add an O and an OU to both, for whoever audits them.
- **A server certificate** valid for 397 days, which keeps it within every
  browser's limit. Its subject says what it is, `Classis Server Certificate`;
  the names it is dialled by are in its subject alternative names. It carries
  every `--name`, and always `127.0.0.1` and `::1` as well, so your browser and
  `curl` reach the Operator plane through an SSH tunnel (step 2). A wildcard or
  a name that is neither a DNS name nor an address is refused.
- **The package signing key**, described in [step 3](#3-make-the-package-signing-key).

`--ca-days` and `--server-days` change the lifetimes. No certificate is made to
outlive the CA that signs it; one asked to is cut to the CA's end, with a notice.
`pki init` makes no certificate for a host: a host holds none.

## 2. Configure and start the Server

A release ships the Server as a container image, not as a binary of its own
([In a container](server.md#in-a-container)); the configuration below is the
same there, mounted into the container. To run it as a process on the host
instead, build the Server from a checkout, on a Linux machine, then copy it to
the Server host and give it an account of its own:

```sh
cargo build --release -p classis-server                 # writes target/release/server
sudo install -m 755 server /usr/local/bin/server    # on the Server host, after copying it there
sudo useradd --system --no-create-home --shell /usr/sbin/nologin classis-server
```

Copy the contents of `--server-dir` to the Server host, to the `--server-path`
you gave (`/etc/classis-server/tls/` above), readable only by the account the
Server runs as. Then write `/etc/classis-server/server.toml`:
`server.toml.fragment` holds its `[tls]` section, and the rest is yours. Give
every path absolutely:

```toml
# The Agent plane: where the fleet connects. 4320 is the protocol's default port.
listen = "0.0.0.0:4320"

# All of the Server's state, owner-only (see the Server's manual, "Where the Server keeps its state").
data_dir = "/var/lib/classis-server/data"

# How long an access token is accepted, in seconds. 0, the default, is for ever: a token
# ends only when its host is issued a new one.
token_lifetime_secs = 0

[tls]
cert_file = "/etc/classis-server/tls/server.pem"
key_file = "/etc/classis-server/tls/server-key.pem"

# The Operator plane: REST API, API docs and UI. On the loopback it needs no password.
[rest]
listen = "127.0.0.1:4321"
```

The Agent plane asks no host for a certificate. Which hosts it admits is decided
by the tokens it has issued, not by this file: `token_lifetime_secs` is the one
setting that bears on them, and `[admission_throttle]` the back-off for repeated
refusals ([Living with the enrolment](#6-living-with-the-enrolment)).

**The Operator plane stays on the loopback** unless you decide otherwise. Reach
it from your machine through an SSH tunnel:

```sh
ssh -L 4321:127.0.0.1:4321 fleet.example.com
```

To publish it instead, set `[rest] listen = "0.0.0.0:4321"` and add a password;
the Server refuses to start with a published plane and no password. Make the
password's hash with the Server itself, which reads the password without echoing
it:

```console
$ server hash-credential --basic
secret:
$argon2id$v=19$m=19456,t=2,p=1$…
```

```toml
[rest.auth.basic_users]
fleet-admin = "$argon2id$v=19$m=19456,t=2,p=1$…"
```

Then add `-u fleet-admin` to every `curl` below; `curl` asks for the password.

**Start it:**

```sh
server --config /etc/classis-server/server.toml
```

The Server runs in the foreground, logs to stderr, and stops on `SIGTERM`. It
does not install itself as a service, so let your service manager run it. A
systemd unit for an account named `classis-server` might look like this:

```ini
# /etc/systemd/system/classis-server.service
[Unit]
Description=Classis Server
After=network-online.target
Wants=network-online.target

[Service]
User=classis-server
ExecStart=/usr/local/bin/server --config /etc/classis-server/server.toml
StateDirectory=classis-server
UMask=0077
Restart=on-failure

# The Server writes under data_dir and nowhere else, binds ports above 1024,
# and needs no privilege, device or kernel interface.
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

`ProtectSystem=strict` leaves the whole file system read-only to the Server
except its `StateDirectory`, `/var/lib/classis-server`, which holds `data_dir`
in the configuration above. A `data_dir` anywhere else needs a `ReadWritePaths=`
line naming it. A `listen` or `[rest] listen` port below 1024 needs
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and
`AmbientCapabilities=CAP_NET_BIND_SERVICE` instead of the empty lines.
`systemd-analyze security classis-server` rates what the unit leaves open.

The Server refuses an unsafe or incomplete configuration at startup and names
the key, for example `[tls] is required` when the section is missing. Fix what
it names and start it again.

**Check it from your machine**, through the tunnel:

```console
$ curl --cacert server-ca.pem https://127.0.0.1:4321/api/v1/agents
[]
```

The UI is at <https://127.0.0.1:4321/>. Import `server-ca.pem` into your
browser's trust store first.

## 3. Make the package signing key

A Client installs software only when an operator's key has signed it, and that
includes its own updates. `pki init` has made that key already:
`package-signing-key.pk8` in the offline directory, and its public half in
`package-signing-key.pub`, which `supervisor.toml.fragment` names as
`[packages] verification_key`.

```console
$ cat offline/package-signing-key.pub
3b6a27bc…        # the public key: every Client's [packages] verification_key
```

Keep `package-signing-key.pk8` with you, not on the Server. A Client without the
public key runs and reports normally, but takes no package. For a fleet set up
without `pki init`, or to replace the key, make one with the operator tool's
`package keygen` ([The operator tool](tools.md#packing-and-signing)):

```console
$ classisctl package keygen --out fleet-signing.pk8
3b6a27bc…
```

## 4. Configure and install a Client

Each managed host needs `server-ca.pem` from `--offline-dir`, unless the Server's
certificate comes from a public CA, and the package verification key. Copy them
to the host: `server-ca.pem` and `package-signing-key.pub`. The simplest place is
the directory you run the Client's program from: the install looks there first,
offers what it finds as its answers, and takes it without a question when it is
not interactive
([Files beside the program](client.md#files-beside-the-program)). Anywhere else,
such as the `--host-path` you gave (`/etc/opamp/` above), you name them
yourself; `supervisor.toml.fragment` holds the `[tls]` and `[packages]` sections
that name them there.

**Install the Client** from the release's `.deb`, `.rpm` or `.msi`. The package
registers the service and leaves it stopped, and does not let it start at boot:
a host runs nothing until it is enrolled (see
[Installing from a native package](client.md#installing-from-a-native-package)).
On Linux the service runs as the system account `classis`, which the package
creates. The install hands the files under the data root to it; a file you name
elsewhere, such as under `/etc/opamp/`, the service reads only if that account
may — choose root with `--run-as root`, or give the file to the account
([Running it under its own account](client.md#running-it-under-its-own-account)).
Then let it write its configuration by asking you:

```console
$ sudo classis service install --interactive
Server OpAMP endpoint [wss://127.0.0.1:4320/v1/opamp]: wss://fleet.example.com:4320/v1/opamp
This Agent's name (service.instance.name) [Supervisor Agent]: host-01
CA certificate of the Server — the CA that signed its certificate (PEM path): /etc/opamp/server-ca.pem
Package verification key (hex Ed25519 public key; empty takes no packages): 3b6a27bc…
copied /var/lib/classis/server-ca.pem
wrote /var/lib/classis/supervisor.toml
```

It then registers the service and ends by telling you the next step: enrol the
host. With the files beside the program, each of the path and key questions
offers the file there, and Enter takes it. Without a terminal,
`service install --endpoint <URL>` run from that directory — or naming it with
`--fleet-files <dir>`, as a host installed from a package needs — takes the CA
and the verification key. Later changes go through `sudo classis service config`,
which asks the same questions with the current values as defaults
([The questionnaire](client.md#the-questionnaire---interactive-and-service-config)).

Or write the file yourself, which suits configuration management. This is what
matters of a file written by hand, at `/var/lib/classis/supervisor.toml` on
Linux:

```toml
endpoint = "wss://fleet.example.com:4320/v1/opamp"   # wss:// pushes changes; https:// polls
name = "host-01"                                      # your name for this host, unique in the fleet

[tls]
ca_file = "/etc/opamp/server-ca.pem"     # trust the server CA, and only it

[packages]
verification_key = "3b6a27bc…"
```

A few things worth knowing about these keys:

- **`ca_file` replaces the built-in trust.** With it set, the Client trusts the
  server CA and no other CA. Leave it out only when the Server's certificate
  comes from a public CA.
- **`name` is what the fleet view shows.** A host is told apart by its Device ID,
  which `enrol` prints and the Server assigns.
- **The file holds no credential.** What a host presents to the Server is in
  `state.json`, which `enrol` writes.
- **A host that should run agents** gets `[[supervisor]]` blocks: see
  [Supervisors](client.md#supervisors-putting-a-process-under-management). Enrol
  it first, then add them.

The service is installed but not running. It starts when the host is enrolled.

## 5. Enrol the Client

**You need the enrolment key of a Space.** This build has no command that makes
a Space, and none that shows or rotates its key: the Operator plane's REST API
has no route for either, `classisctl` has no command for either, and the Server
reads no setting that creates one. A Space exists in this build only where the
Server's library makes it, as its tests do, so there is nothing an operator can
run to get the key this step takes. The rest of this step describes what `enrol`
does with a key once you hold one.

A key reads `cle1_<space>_<secret>`: the prefix, the Space's name, and a secret
of 43 characters. The name is 1 to 32 letters, digits and underscores, starting
and ending with a letter or a digit, and two Spaces' names never differ only in
case. Treat the whole key as a secret: it enrols any host that holds it, until
its Space's key is rotated.

**Enrol the host**, on the host, with the Server's base URL and the key and
nothing else, since the key names the Space:

```console
$ sudo classis enrol https://fleet.example.com:4320 cle1_lab_…
enrolled in the space lab as 0193a6f0-…
  state file: /var/lib/classis/state/state.json
  the service is started, and starts at boot
```

The base URL is the Server's origin on the Agent plane: `https://`, or `http://`
to `127.0.0.1` or `::1` alone, with no credentials, query or fragment; a path
prefix is kept. The Client resolves `/v1/enrol` and `/v1/token` against it, and
trusts what `[tls] ca_file` names. Run it with the rights that start a service:
`sudo` on Linux and macOS, an elevated prompt on Windows. The key stands on the
command line, so it reaches your shell's history and the process list; clear it
from the first.

`enrol` registers the host, asks for its first token, and writes `state.json` in
the state directory (`/var/lib/classis/state/` on Linux), owner-only. Where the
service is registered for that state directory, it hands the file to the account
the service runs as, lets the service start at boot, and starts it. The host
appears on the **Agents** tab as connected within seconds.

`enrol` is refused on a host that holds a `state.json`: the message says the host
is enrolled already and names `revoke` as what ends the enrolment. A host without
a `state.json` runs nothing: the Client, as a service or in the foreground,
refuses to start and names `enrol`.

On a host with no registered service, such as a development checkout, `enrol`
writes the file and says that `run` runs the Client in the foreground.

## 6. Living with the enrolment

**Nothing renews on a schedule.** The access token never expires unless you set
`token_lifetime_secs` on the Server, and no clock on the host renews it ahead of
time. The Client asks for a new token with its client credentials only when the
Server answers a request with `401` and `invalid_token`: because the token
expired, or was replaced. It then rewrites `access_token` in `state.json`, and
nothing else in the file, and tries again. Replacing a token ends the open
WebSocket sessions admitted with the old one, with close code 1008, and the Client
connects again with the new one. A session whose token merely expires stays open
until the Client next connects.

```toml
token_lifetime_secs = 86400    # a day; 0, the default, is for ever
```

**A token is good until it is replaced.** The host is the boundary: whoever holds
its `state.json` can act as the host, and the file holds the client secret as well
as the token. The Server keeps only the SHA-256 of the secret and of the token,
so neither can be read back from it; the enrolment key it does keep in a form it
can return, so protect the Server's `data_dir` and its backups as you would the
keys themselves.

**To take a host out of the fleet**, run `revoke` on it. It is local: it never
contacts the Server, refuses while the service runs, asks for a confirmation
(`--force` skips it), keeps the service from starting at boot again, and deletes
everything in the state directory, `state.json` with it — the Agents' identities,
the logs, the Supervisors' directories. `--keep-cache` spares `config/` and
`packages/`, which a host enrolled again would only download again.

```console
$ sudo classis service stop
$ sudo classis revoke
Revoke this host? Everything in /var/lib/classis/state is deleted: its enrolment, its Agents' identities and its logs. The Server is not told, and a host enrolled again is a new one.
```

A host enrolled again is a new one: a new Device ID, and new `instance_uid`s for
its Agents. The Server keeps what it recorded for the old one. This build has no
command to remove an enrolled host from the Server or to disable its client there;
a host without its `state.json` is gone, and what the Server stored for it is
garbage.

**Repeated failures are backed off.** Past `max_failures` refused authentications
within `window_secs` — a `401`, or a Bearer `400 invalid_request`, on `/v1/enrol`,
`/v1/token`, `/v1/opamp` or the package download — the Server answers an address
`429` with `Retry-After` for `backoff_secs` (10 failures in 60 seconds, then 300
seconds, by default), before it checks anything else. An IPv6 peer counts by its
/64. Change the limits in `[admission_throttle]` ([The Server](server.md)).

**The server certificate is yours to renew**, from the offline directory:

```sh
classisctl pki server-cert --offline-dir fleet-offline --name fleet.example.com --name 10.0.0.5 --out next-server
```

It writes `server.pem` and `server-key.pem` into a new directory. Replace the
Server's two files and restart it; the Clients reconnect on their own. They
trust the server CA, not one particular certificate, so nothing changes on the
hosts.

### The UI's own certificate

The Operator plane — the UI, the REST API and its docs — presents the server
certificate unless `server.toml` names one of its own. Name one when your
organization has a PKI whose root its browsers already trust, so nobody imports
the fleet's server CA:

```toml
[rest.tls]
cert_file = "/etc/classis-server/tls/ui.pem"       # the leaf first, then any intermediates
key_file = "/etc/classis-server/tls/ui-key.pem"
```

The Agent plane keeps the server certificate, and the Clients notice nothing. A
key that does not match its certificate stops the Server at startup, naming both
files. Renew this certificate through your PKI, replace the two files, and
restart the Server; `server pki status` lists it beside the others. A PKI
certificate seldom names `127.0.0.1`, so through an SSH tunnel to a loopback
Operator plane dial the name the certificate carries, for example through an
entry in `/etc/hosts`. `classisctl package fetch --cacert` then names your PKI's
CA, or nothing when the system's roots hold it.

**You are told before anything ends.** At startup and once a day, the Server
reads when its own certificates end. Thirty days before — or in the last third
of the life of a certificate that lives less than 90 days — it logs a warning
naming the file and the date, as the event `pki.expiring`; once one has ended, an
error, as `pki.expired`
([Security decisions in the log](server.md#security-decisions-in-the-log)). It
keeps serving either way. `server pki status --config <server.toml>` says the
same on demand for the Server host's certificates, and
`classisctl pki status --offline-dir <dir>` for the offline directory's. Both
exit by a code that suits a monitoring job: `0` when nothing is ending, `1` when
something is, `2` when something has ended.

```console
$ server pki status --config /etc/classis-server/server.toml
ok        396 days  2027-11-10  serial 0d3d…  O=Example Org, CN=Classis Server Certificate  (/etc/classis-server/tls/server.pem)
```

**The server CA outlasts everything else**, so it lives ten years. This project's
own ends accept a CA past its end, but a browser or another OpAMP implementation
may not, which is why its end is announced. Replacing the server CA means giving
every host the new `ca_file`.

## When a connection is refused

| What you see                                                                                | Where  | What it means                                                                                                                                                     |
| ------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cannot connect … invalid peer certificate: UnknownIssuer`                                  | Client | `ca_file` does not hold the CA that signed the server certificate, or `ca_file` is unset and the certificate comes from a private CA.                             |
| `cannot connect … invalid peer certificate: certificate not valid for name …`               | Client | The host name or address in `endpoint` is not among the server certificate's alternative names.                                                                   |
| The Client refuses to start and names `supervisor enrol`                                    | Client | The host has no `state.json`. Enrol it.                                                                                                                           |
| `cannot enrol at <base-url>: registration refused with 401 Unauthorized`                    | Client | The key is not any Space's current key: it is mistyped, or its Space's key has been replaced.                                                                     |
| `cannot enrol at <base-url>: registration refused with 429 Too Many Requests`               | Client | The host's address failed too often, and the Server is backing it off. The back-off ends by itself.                                                               |
| `this host is enrolled already: … exists`                                                   | Client | A `state.json` is there. `revoke` ends the enrolment first.                                                                                                       |
| `cannot enrol at <base-url>: registration request failed: …`                                | Client | The Server could not be reached, or its certificate was refused: check the base URL and `ca_file`.                                                                |
| `admission failed: the server refused this client (HTTP 401)`                               | Client | A `401` that does not say `invalid_token`: the Client does not ask for a new token for it, and keeps trying after a back-off.                                     |
| `the Server refused the access token (invalid_token); requesting a new one`                 | Client | The token expired or was replaced. The Client asks for a new one by itself; `cannot get a new access token` follows if the Server refuses its client credentials. |
| `cannot connect … HTTP error: 429 Too Many Requests`, or `the server is throttling (429 …)` | Client | The host's address failed admission too often, and the Server is backing it off. Fix what is refused; the back-off ends by itself.                                |
| `token request refused with 401 Unauthorized (invalid_client)`                              | Client | The Server does not know the host's client credentials, or its secret is wrong. Revoke the host and enrol it again.                                               |
| The Server refuses to start, naming a key of `server.toml`                                  | Server | A key it does not know, or a section it requires: `[tls] is required`. An old `[client_ca]`, `[enrolment]` or `client_ca_file` is an unknown key now. Delete it.  |
