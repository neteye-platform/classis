# Setting up a fleet

[← User Manual](README.md) · [The Server](server.md) · [The Client](client.md)

This page takes you from nothing to a running fleet, in order, with nothing but
the project's own two programs. You make the certificates, configure and start
the Server, configure and install a Client, and enrol it. The
[Server](server.md) and [Client](client.md) pages describe every key; this page
says which ones a real deployment needs, and why.

The quick start in the
[manual's index](README.md#quick-start-a-closed-loop-on-one-machine) runs both
ends on one machine with throwaway certificates. Use this page for anything that
crosses a network. [A host's life](lifecycle.md) follows one host from
installation through enrolment to its updates, once the fleet stands.

- [The certificates, at a glance](#the-certificates-at-a-glance)
- [1. Make the certificates](#1-make-the-certificates)
- [2. Configure and start the Server](#2-configure-and-start-the-server)
- [3. Make the package signing key](#3-make-the-package-signing-key)
- [4. Configure and install a Client](#4-configure-and-install-a-client)
- [5. Enrol the Client](#5-enrol-the-client)
- [6. Living with the certificates](#6-living-with-the-certificates)
- [When a connection is refused](#when-a-connection-is-refused)

## The certificates, at a glance

Every connection is TLS 1.3, and a Client proves it belongs to the fleet with a
client certificate in the handshake and nothing else. That takes three
certificate authorities, each with one job:

| CA               | Signs                                                                              | Its key lives     | Its certificate is named in                                                                                                                        |
| ---------------- | ---------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Server CA**    | the Server's own certificate                                                       | offline, with you | the Client's `[tls] ca_file`, and your browser's trust store — unless the UI presents a certificate of its own ([below](#the-uis-own-certificate)) |
| **Client CA**    | every host's certificate, by the Server, automatically                             | on the Server     | the Server's `[tls] client_ca_file` and `[client_ca]`                                                                                              |
| **Bootstrap CA** | bootstrap certificates, which new hosts enrol with, by the Server, on your request | on the Server     | the Server's `[enrolment] bootstrap_ca_file` and `bootstrap_ca_key_file`                                                                           |

How they work together:

1. A new host gets a **bootstrap certificate**, which the Server issues when you
   ask for one. Ask for one per customer, site or batch of hosts, and name it
   after them: you see that name on every request it carries. On its own it
   opens nothing: the Server lets it ask for a certificate only while an
   operator holds the enrolment window open, and it answers only once the
   operator approves the request.
2. The host generates its own key, which never leaves it, and sends a
   certificate request. You approve it by comparing the key's fingerprint, which
   the host logs, with the one the Server lists.
3. The Server signs the request with the **client CA**. From then on the host
   connects with that certificate, and renews it automatically two thirds of the
   way through its life. With the default of 30 days, that is every 20 days.

The **server CA** is independent of the other two. If the Server's address has a
certificate from a public CA, you can use that one instead and skip the server
CA. The Client then trusts the built-in roots, and its `ca_file` stays unset.

Keep the three apart. The client CA and the bootstrap CA must have **different
subject names** and different keys: the Server refuses to start otherwise, since
it tells a bootstrap certificate from a member's by the CA that issued it. Do
not let the server CA sign host certificates either. Its key stays off the
Server: whoever holds it can stand up a Server every host trusts. The client
CA's key has to be on the Server, and with it the bootstrap CA's adds nothing an
intruder there would not already have.

## 1. Make the certificates

The operator tool `opamp-fleetctl` makes every certificate of this page, with
its `pki` commands; no other tool is needed. Every release publishes it for
Linux and macOS ([Getting it](tools.md#getting-it)); download it to the machine
where the offline keys are to stay, typically your own, not the Server host.

Run `pki init` there. Name every address the Clients will dial with `--name`, as
a DNS name or an IP address; repeat it for each:

```console
$ opamp-fleetctl pki init --server-dir fleet-server --offline-dir fleet-offline \
                         --name fleet.example.com --name 10.0.0.5 \
                         --server-path /etc/opamp-fleet-server/tls --host-path /etc/opamp
fleet-server: for the Server host — merge server.toml.fragment into its server.toml
fleet-offline: keep offline — the server CA's key; give every new host server-ca.pem, and the bootstrap.p12 the Server issues (POST /api/v1/bootstrap-certificates), or its pair as bootstrap.pem and bootstrap-key.pem (pki p12-extract), as supervisor.toml.fragment names them
```

`--server-path` and `--host-path` are where the files will live on the Server
host and on a managed host; the two `.fragment` files name them there. Left out,
they name the directories as `pki init` wrote them. It writes these files, and
nothing else:

| Directory       | File                                       | Goes to                                                                                                                                                                                                                                                          | Secret? |
| --------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `--server-dir`  | `server.pem`, `server-key.pem`             | the Server (`[tls] cert_file`, `key_file`)                                                                                                                                                                                                                       | the key |
|                 | `client-ca.pem`, `client-ca-key.pem`       | the Server (`[tls] client_ca_file`, `[client_ca]`)                                                                                                                                                                                                               | the key |
|                 | `bootstrap-ca.pem`, `bootstrap-ca-key.pem` | the Server (`[enrolment] bootstrap_ca_file`, `bootstrap_ca_key_file`)                                                                                                                                                                                            | the key |
|                 | `server.toml.fragment`                     | the Server's `server.toml`, merged in                                                                                                                                                                                                                            | no      |
| `--offline-dir` | `server-ca.pem`                            | every Client (`[tls] ca_file`), and your browser                                                                                                                                                                                                                 | no      |
|                 | `server-ca-key.pem`                        | nowhere: keep it offline, to sign the next server certificate                                                                                                                                                                                                    | **yes** |
|                 | `package-signing-key.pk8`                  | nowhere: keep it offline, to sign every package ([step 3](#3-make-the-package-signing-key))                                                                                                                                                                      | **yes** |
|                 | `package-signing-key.pub`                  | the public half in hex: every Client's `[packages] verification_key`                                                                                                                                                                                             | no      |
|                 | `supervisor.toml.fragment`                 | every new Client's `supervisor.toml`, merged in; it names `bootstrap.pem` and `bootstrap-key.pem`, the pair `pki p12-extract` takes out of the `bootstrap.p12` the Server issues ([step 4](#4-configure-and-install-a-client)), and the package verification key | no      |

The directories are created `0700` and every key `0600`. `pki init` refuses to
write over a file that exists, and writes nothing at all then. Run on the Server
host, it says so: move the offline directory off that host before the fleet goes
live.

What it makes, so you need not:

- **Three CAs with names of their own**, `OpAMP Fleet Server CA`,
  `OpAMP Fleet Client CA` and `OpAMP Fleet Bootstrap CA`, none able to sign a
  further CA. `--product` replaces `OpAMP Fleet` in all three, and
  `--organization` and `--organizational-unit` add an O and an OU to every
  certificate `init` makes, for whoever audits them. The server CA and the
  client CA are valid for ten years; replacing either means touching every host.
  The bootstrap CA is valid for one year; replacing it touches only the Server
  ([step 6](#6-living-with-the-certificates)).
- **A server certificate** valid for 397 days, which keeps it within every
  browser's limit. Its subject says what it is,
  `OpAMP Fleet Server Certificate`; the names it is dialled by are in its
  subject alternative names. It carries every `--name`, and always `127.0.0.1`
  and `::1` as well, so your browser and `curl` reach the Operator plane through
  an SSH tunnel (step 2). A wildcard or a name that is neither a DNS name nor an
  address is refused.
- **Keys the Server can read:** ECDSA P-256 in PKCS#8, the one form the client
  CA's key must have.

`--ca-days` (the server CA and the client CA), `--bootstrap-ca-days` and
`--server-days` change the lifetimes. No certificate is made to outlive the CA
that signs it; one asked to is cut to the CA's end, with a notice. `pki init`
makes no bootstrap certificate: the Server issues those.

## 2. Configure and start the Server

A release ships the Client and the operator tool, not the Server, so build the
Server from a checkout, on a Linux machine, then copy it to the Server host and
give it an account of its own:

```sh
cargo build --release -p fleet-server                 # writes target/release/server
sudo install -m 755 server /usr/local/bin/server    # on the Server host, after copying it there
sudo useradd --system --no-create-home --shell /usr/sbin/nologin opamp-fleet-server
```

Copy the contents of `--server-dir` to the Server host, to the `--server-path`
you gave (`/etc/opamp-fleet-server/tls/` above), readable only by the account
the Server runs as. Then write `/etc/opamp-fleet-server/server.toml`:
`server.toml.fragment` holds its `[tls]`, `[client_ca]` and `[enrolment]`
sections, and the rest is yours. Give every path absolutely:

```toml
# The Agent plane: where the fleet connects. 4320 is the protocol's default port.
listen = "0.0.0.0:4320"

# All of the Server's state, owner-only (see the Server's manual, "Where the Server keeps its state").
data_dir = "/var/lib/opamp-fleet-server/data"

[tls]
cert_file = "/etc/opamp-fleet-server/tls/server.pem"
key_file = "/etc/opamp-fleet-server/tls/server-key.pem"
client_ca_file = "/etc/opamp-fleet-server/tls/client-ca.pem"   # the CA a host's certificate must come from

[client_ca]                                                       # the Server signs host certificates
cert_file = "/etc/opamp-fleet-server/tls/client-ca.pem"           # the same CA as client_ca_file
key_file = "/etc/opamp-fleet-server/tls/client-ca-key.pem"
validity_days = 30

[enrolment]                                                       # new hosts enrol with a bootstrap certificate
bootstrap_ca_file = "/etc/opamp-fleet-server/tls/bootstrap-ca.pem"
bootstrap_ca_key_file = "/etc/opamp-fleet-server/tls/bootstrap-ca-key.pem"   # the Server issues them

# The Operator plane: REST API, API docs and UI. On the loopback it needs no password.
[rest]
listen = "127.0.0.1:4321"
```

`client_ca_file` and `[client_ca] cert_file` name the **same** certificate, as
the fragment writes them. The Server does not check that they match; if they
differed, it would sign certificates that its own handshake refuses.

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
server --config /etc/opamp-fleet-server/server.toml
```

The Server runs in the foreground, logs to stderr, and stops on `SIGTERM`. It
does not install itself as a service, so let your service manager run it. A
systemd unit for an account named `opamp-fleet-server` might look like this:

```ini
# /etc/systemd/system/opamp-fleet-server.service
[Unit]
Description=OpAMP Fleet Server
After=network-online.target
Wants=network-online.target

[Service]
User=opamp-fleet-server
ExecStart=/usr/local/bin/server --config /etc/opamp-fleet-server/server.toml
StateDirectory=opamp-fleet-server
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
except its `StateDirectory`, `/var/lib/opamp-fleet-server`, which holds
`data_dir` in the configuration above. A `data_dir` anywhere else needs a
`ReadWritePaths=` line naming it. A `listen` or `[rest] listen` port below 1024
needs `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and
`AmbientCapabilities=CAP_NET_BIND_SERVICE` instead of the empty lines.
`systemd-analyze security opamp-fleet-server` rates what the unit leaves open.

The Server refuses an unsafe or incomplete configuration at startup and names
the key, for example
`[enrolment] needs [client_ca]: an approved request is signed by it`. Fix what
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
$ opamp-fleetctl package keygen --out fleet-signing.pk8
3b6a27bc…
```

## 4. Configure and install a Client

Each managed host needs `server-ca.pem` from `--offline-dir` and a bootstrap
certificate with its key, which the Server issues as one file, `bootstrap.p12`,
under a password you name. Name whom the certificate is for, the customer and
the site; both are required, and the approver sees them on every request it
carries.

**In the UI**, through the tunnel: open the **Enrolments** tab and fill in
**Bootstrap certificates** with what the host certificates are to carry — the
customer (O) and the site (OU), required, and the country, chosen from a list,
the state, the locality and a customer number (organizationIdentifier), optional
— the days it is valid (10 by default, at most 90), and a password, twice. Press
**Issue**, then **Save bootstrap.p12** in the new certificate's row, now or on
any later day, until the certificate ends or is revoked.

**Over the API**, the same request, written with an editor so the password stays
out of the shell's history:

```console
$ cat request.json
{"subject": {"country": "AT", "organization": "Example Customer", "organizational_unit": "Vienna"},
 "validity_days": 14, "password": "correct horse battery staple"}
$ curl --cacert server-ca.pem -X POST -H 'Content-Type: application/json' -d @request.json \
       https://127.0.0.1:4321/api/v1/bootstrap-certificates > issued.json
$ curl --cacert server-ca.pem -o bootstrap.p12 \
       https://127.0.0.1:4321/api/v1/bootstrap-certificates/$(jq -r .serial issued.json)/p12
```

The private key leaves the Server only inside that file, encrypted under the
password; no answer carries it. The Server keeps the password nowhere: give it
to the host's installer by another way than the file
([The PKCS#12 file](server.md#the-pkcs12-file-bootstrapp12)). One certificate
may go to every host of that customer and site. Every host that enrols with it
is issued a certificate carrying the same subject values, which its Agents carry
as `fleet.host.*` for Selectors to match
([Bootstrap certificates](server.md#bootstrap-certificates-issued-by-the-server)).
Where a host or a tool needs the PEM pair, `bootstrap.pem` and
`bootstrap-key.pem`, as `supervisor.toml.fragment` names them,
`opamp-fleetctl pki p12-extract bootstrap.p12 --out <dir>` writes it
([`pki`](tools.md#pki)).

Copy `server-ca.pem` and `bootstrap.p12` — or `server-ca.pem` and the extracted
pair, the key readable by root only — to the host, together with
`package-signing-key.pub` from the offline directory. The simplest place is the
directory you run the Client's program from: the install looks there first,
offers what it finds as its answers, and takes it without a question when it is
not interactive
([Files beside the program](client.md#files-beside-the-program)). Anywhere else,
such as the `--host-path` you gave (`/etc/opamp/` above), you name them
yourself; `supervisor.toml.fragment` holds the `[tls]` section that names them
there.

**Install the Client** from the release's `.deb`, `.rpm` or `.msi`. The package
registers the service and leaves it stopped (see
[Installing from a native package](client.md#installing-from-a-native-package)).
On Linux the service runs as the system account `opamp-fleet`, which the package
creates. The install hands the files under the data root to it; a file you name
elsewhere, such as under `/etc/opamp/`, the service reads only if that account
may — give the key to the account, not to root alone, or choose root with
`--run-as root`
([Running it under its own account](client.md#running-it-under-its-own-account)).
Then let it write its configuration by asking you. The questions end with the
host's enrolment, so first **open the enrolment window** as
[step 5](#5-enrol-the-client) shows, and have the **Enrolments** tab at hand to
approve the request the install waits for:

```console
$ sudo opamp-fleet service install --interactive
Server OpAMP endpoint [wss://127.0.0.1:4320/v1/opamp]: wss://fleet.example.com:4320/v1/opamp
This Agent's name (service.instance.name) [Supervisor Agent]: host-01
CA certificate of the Server — the CA that signed its certificate (PEM path): /etc/opamp/server-ca.pem
Bootstrap certificate this Client enrols with (PEM, or a PKCS#12 .p12 path): /etc/opamp/bootstrap.pem
Private key of the bootstrap certificate (PEM path): /etc/opamp/bootstrap-key.pem
Package verification key (hex Ed25519 public key; empty takes no packages): 3b6a27bc…
copied /var/lib/opamp-fleet/server-ca.pem
wrote /var/lib/opamp-fleet/supervisor.toml
enrolling with wss://fleet.example.com:4320/v1/opamp: an operator approves this host's request by the key fingerprint logged below (Ctrl-C stops waiting)
INFO certificate request generated; an enrolling host waits for an operator's approval key_fingerprint=3f9a…
enrolled: the issued certificate is in /var/lib/opamp-fleet/state
installed opamp-fleet
```

With the files beside the program, each of the three path questions offers the
file there, and Enter takes it. Answering a `bootstrap.p12` asks its password
instead of a key, with input hidden. Without a terminal,
`service install --endpoint <URL>` run from that directory — or naming it with
`--fleet-files <dir>`, as a host installed from a package needs — takes the CA
and the verification key, enrols with the bootstrap pair or `bootstrap.p12` (its
password from `--bootstrap-password-file <file>`) and waits for the same
approval.

Approve the fingerprint it logs, as step 5 describes, and the install carries
on. The bootstrap pair is used only for this request: it is not copied, and
`/etc/opamp/bootstrap*.pem` can be removed afterwards. Later changes go through
`sudo opamp-fleet service config`, which asks the same questions with the
current values as defaults
([The questionnaire](client.md#the-questionnaire---interactive-and-service-config)).

Or write the file yourself, which suits configuration management. This is what
matters of a file written by hand, at `/var/lib/opamp-fleet/supervisor.toml` on
Linux. It names the bootstrap pair, and the service enrols with it when it
starts:

```toml
endpoint = "wss://fleet.example.com:4320/v1/opamp"   # wss:// pushes changes; https:// polls
name = "host-01"                                      # your name for this host, unique in the fleet

[tls]
ca_file = "/etc/opamp/server-ca.pem"     # trust the server CA, and only it
cert_file = "/etc/opamp/bootstrap.pem"   # the bootstrap certificate, to enrol with
key_file = "/etc/opamp/bootstrap-key.pem"

[packages]
verification_key = "3b6a27bc…"
```

A few things worth knowing about these keys:

- **`ca_file` replaces the built-in trust.** With it set, the Client trusts the
  server CA and no other CA. Leave it out only when the Server's certificate
  comes from a public CA.
- **`name` is what the fleet view shows**, not what the certificate says. The
  certificate the Server issues is named for its role,
  `OpAMP Fleet Client Certificate`, whatever the request asks for; a host is
  told apart by its serial and its host id.
- **A bootstrap pair in the file stays there after enrolment.** Once the host
  holds an issued certificate, it stores the certificate in its state directory
  as `client-cert.pem` and `client-key.pem` and uses that pair instead. The
  bootstrap pair is what it falls back to if you delete them. A file the
  questionnaire wrote names no pair.
- **A host that should run agents** gets `[[supervisor]]` blocks: see
  [Supervisors](client.md#supervisors-putting-a-process-under-management). Enrol
  it first, then add them.

A host configured by hand does not start yet: the enrolment window is still
closed. A host the questionnaire enrolled is ready; start it with
`sudo systemctl start opamp-fleet`.

## 5. Enrol the Client

**Open the window**, for as long as you need to set up hosts. In the
**Enrolments** tab, choose 15 minutes, 1 hour or 4 hours and press **Open
window**; over the API, up to 24 hours:

```console
$ curl --cacert server-ca.pem -X POST -H 'Content-Type: application/json' \
       -d '{"open_for_secs": 3600}' https://127.0.0.1:4321/api/v1/enrolment/window
{"open":true,"until_ms":…}
```

**Start a Client configured by hand** and read the key fingerprint it logs. A
Client the questionnaire enrols logs the fingerprint on the terminal it runs on:

```console
$ sudo systemctl start opamp-fleet
$ journalctl -u opamp-fleet | grep key_fingerprint
INFO certificate request generated; an enrolling host waits for an operator's approval key_fingerprint=3f9a…
```

**Approve it.** Open the UI's **Enrolments** tab: it lists each waiting host
with its full key fingerprint, its peer address, and the bootstrap certificate
it carries: the subject values its host certificate will carry, and the serial
and end it was issued with, or _not issued here_ for one the Server did not
issue. Compare the fingerprint with the one the host logged, check that the
bootstrap certificate is the one you gave that host, then press **Approve**. The
same over the API:

```console
$ curl --cacert server-ca.pem https://127.0.0.1:4321/api/v1/enrolments
[{"id":"3f9a…","arrived_ms":…,"peer":"10.0.4.17","key_fingerprint":"3f9a…",
  "bootstrap_subject":{"country":"AT","organization":"Example Customer","organizational_unit":"Vienna",…},…}]
$ curl --cacert server-ca.pem -X POST https://127.0.0.1:4321/api/v1/enrolments/3f9a…/approve
```

Approve only a fingerprint you can match to a host you are setting up. A request
you do not recognise is rejected with `…/reject`.

The host receives its certificate within seconds, checks it by connecting with
it, stores it, and appears on the **Agents** tab as connected. Its certificate
is listed under `GET /api/v1/certificates`.

**Close the window** when you are done, with **Close window** in the tab or over
the API. It also closes on its own when its time runs out, and on a Server
restart:

```sh
curl --cacert server-ca.pem -X DELETE https://127.0.0.1:4321/api/v1/enrolment/window
```

**A host behind a Gateway enrols through it** once the Gateway trusts the
bootstrap CA: copy the Server's `bootstrap-ca.pem` — the certificate, never its
key — to the Gateway and name it as `[gateway.tls] bootstrap_ca_file`. Point the
host at the Gateway with an `https://` endpoint. Its request then waits in the
**Enrolments** tab like any other, naming the Gateway's host where a direct one
names its address, and the window, the queue and your approval apply as above.
See [Enrolment through a Gateway](client.md#enrolment-through-a-gateway).

## 6. Living with the certificates

**Host certificates renew themselves.** At two thirds of its life the Client
generates a new key, asks for a certificate with its current one, and switches
once it has connected with the new one. No operator is involved, and no window
needs to be open.

**A host that stays offline longer than its certificate's validity is locked
out.** Its stored certificate has expired, and the Client keeps presenting it.
To enrol it again:

1. On the host, stop the service and delete `client-cert.pem` and
   `client-key.pem` from its state directory (`/var/lib/opamp-fleet/state/` on
   Linux), and `client-key.pending.pem` and `client-csr.pending.pem` if they are
   there.
2. If the bootstrap certificate has expired too, have the Server issue a fresh
   one, as [step 4](#4-configure-and-install-a-client) shows.
3. Open the window, run `sudo opamp-fleet service config`, which asks for the
   bootstrap pair again now that the host holds no certificate, and approve the
   fingerprint it logs, as in step 5. Then start the service. A host whose
   `supervisor.toml` names the bootstrap pair can instead simply be started, and
   logs the fingerprint once it reaches the Server.

**To shut a host out**, revoke its certificate by serial. The Server closes its
sessions at once, refuses it from then on, and no renewal of that certificate is
accepted either. A host that has renewed has several certificates listed; revoke
the oldest, the one it enrolled with, and the revocation reaches every renewal
of it:

```console
$ curl --cacert server-ca.pem https://127.0.0.1:4321/api/v1/certificates
[{"authority":"client","serial":"5c0f…","subject":"CN=OpAMP Fleet Client Certificate",…}]
$ curl --cacert server-ca.pem -X POST -H 'Content-Type: application/json' \
       -d '{"certificate": {"authority": "client", "serial": "5c0f…"}}' \
       https://127.0.0.1:4321/api/v1/revocations
```

A bootstrap certificate is revoked the same way, with `"authority": "bootstrap"`
and its serial, or with **Revoke** in its row on the **Enrolments** tab.
`GET /api/v1/bootstrap-certificates` and that tab list every valid one the
Server issued, with its serial, subject and end, and whether it is revoked. See
[Revocation](server.md#revocation-withdrawing-a-certificate) for Gateways and
for lifting a revocation.

**The server certificate is yours to renew**, from the offline directory:

```sh
opamp-fleetctl pki server-cert --offline-dir fleet-offline --name fleet.example.com --name 10.0.0.5 --out next-server
```

It writes `server.pem` and `server-key.pem` into a new directory. Replace the
Server's two files and restart it; the Clients reconnect on their own. They
trust the server CA, not one particular certificate, so nothing changes on the
hosts. `server-cert` also makes a **Gateway's** certificate: give it the
Gateway's names and use the pair as its `[gateway.tls] cert_file` and
`key_file`.

### The UI's own certificate

The Operator plane — the UI, the REST API and its docs — presents the server
certificate unless `server.toml` names one of its own. Name one when your
organization has a PKI whose root its browsers already trust, so nobody imports
the fleet's server CA:

```toml
[rest.tls]
cert_file = "/etc/opamp-fleet-server/tls/ui.pem"       # the leaf first, then any intermediates
key_file = "/etc/opamp-fleet-server/tls/ui-key.pem"
```

The Agent plane keeps the server certificate, and the Clients notice nothing. A
key that does not match its certificate stops the Server at startup, naming both
files. Renew this certificate through your PKI, replace the two files, and
restart the Server; `server pki status` lists it beside the others. A PKI
certificate seldom names `127.0.0.1`, so through an SSH tunnel to a loopback
Operator plane dial the name the certificate carries, for example through an
entry in `/etc/hosts`. `opamp-fleetctl package fetch --cacert` then names your
PKI's CA, or nothing when the system's roots hold it.

**The bootstrap CA is yours to replace once a year**, when the Server warns that
it is ending:

```sh
opamp-fleetctl pki bootstrap-ca --product "OpAMP Fleet" --organization "Example Org" --out next-bootstrap-ca
```

Give it the `--product`, `--organization` and `--organizational-unit` you gave
`pki init`. It writes `bootstrap-ca.pem` and `bootstrap-ca-key.pem`. Replace the
Server's two files of `[enrolment]` with them and restart it. Enrolled hosts
notice nothing: they hold certificates of the client CA. Bootstrap certificates
of the old CA stop working, so have the Server issue new ones to the hosts you
set up next.

**You are told before anything ends.** At startup and once a day, the Server
reads when its own certificate, the client CA and the bootstrap CA end. Thirty
days before — or in the last third of the life of a certificate that lives less
than 90 days — it logs a warning naming the file and the date, and records
`pki.expiring` in the audit; once one has ended, an error and `pki.expired`. It
keeps serving either way. `server pki status --config <server.toml>` says the
same on demand for the Server host's certificates, and
`opamp-fleetctl pki status --offline-dir <dir>` for the offline directory's.
Both exit by a code that suits a monitoring job: `0` when nothing is ending, `1`
when something is, `2` when something has ended.

```console
$ server pki status --config /etc/opamp-fleet-server/server.toml
ok        396 days  2027-11-10  serial 0d3d…  O=Example Org, CN=OpAMP Fleet Server Certificate  (/etc/opamp-fleet-server/tls/server.pem)
ok        3649 days  2036-10-06  serial 4e1b…  O=Example Org, CN=OpAMP Fleet Client CA  (/etc/opamp-fleet-server/tls/client-ca.pem)
ok        3649 days  2036-10-06  serial 2068…  O=Example Org, CN=OpAMP Fleet Bootstrap CA  (/etc/opamp-fleet-server/tls/bootstrap-ca.pem)
```

**The server CA and the client CA outlast everything else**, so they live ten
years. This project's own ends accept a CA past its end, but a browser or
another OpAMP implementation may not, which is why its end is announced.
Replacing the server CA means giving every host the new `ca_file`. Replacing the
client CA means every host enrols again: the Server renews only a certificate
its current client CA issued.

## When a connection is refused

| What you see                                                                                                | Where  | What it means                                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cannot connect … invalid peer certificate: UnknownIssuer`                                                  | Client | `ca_file` does not hold the CA that signed the server certificate, or `ca_file` is unset and the certificate comes from a private CA.                                                                    |
| `cannot connect … invalid peer certificate: certificate not valid for name …`                               | Client | The host name or address in `endpoint` is not among the server certificate's alternative names.                                                                                                          |
| The Client refuses to start: `[tls] cert_file and key_file are required`                                    | Client | The host has no client identity yet. Name the bootstrap pair in `[tls]`.                                                                                                                                 |
| The handshake fails, and the Server never lists the host                                                    | both   | The Client's certificate comes from none of the Server's CAs, or `[enrolment]` is not configured and the host holds only a bootstrap certificate.                                                        |
| `cannot connect … 503 Service Unavailable`, and no request is listed                                        | Client | The enrolment window is closed. Open it; the Client retries by itself.                                                                                                                                   |
| The request is listed, but the host never connects as a member                                              | Server | Nobody approved it yet. The host waits and sends the same request again until you do.                                                                                                                    |
| `admission failed: the server refused this client (HTTP 401)`                                               | Client | The Server refused the certificate after the handshake: it is revoked.                                                                                                                                   |
| `cannot connect … received fatal alert …` on a host that was connected before                               | Client | Its certificate expired while it was offline. Enrol it again, as [Living with the certificates](#6-living-with-the-certificates) describes.                                                              |
| A `429`                                                                                                     | Client | The host's address failed admission too often, and the Server is backing it off. Fix the certificate; the back-off ends by itself.                                                                       |
| The Server refuses to start, naming `shares a CA with [tls] client_ca_file`                                 | Server | The bootstrap CA and the client CA have the same subject name. Make a bootstrap CA with a name of its own.                                                                                               |
| The Server refuses to start, naming `bootstrap_ca_key_file … is not the key of` or `is the client CA's key` | Server | `[enrolment]` names a key that does not belong to the bootstrap CA. Name the bootstrap CA's own key.                                                                                                     |
| `POST /api/v1/bootstrap-certificates` answers `409`, naming `bootstrap_ca_key_file`                         | Server | The Server does not hold the bootstrap CA's key. Name it in `[enrolment]` and restart.                                                                                                                   |
| The Server refuses to start, naming `[client_ca] … does not exist`                                          | Server | A file of `[client_ca]` is missing.                                                                                                                                                                      |
| The Server refuses to start with `cannot read <key file>: …`                                                | Server | The account the Server runs as cannot read the client CA's key, or, when the message ends in `Could not parse key pair`, the key is not PKCS#8. A client CA made by `opamp-fleetctl pki init` always is. |
| Hosts enrol, but their certificates are refused at once                                                     | both   | `[client_ca]` holds a key that does not belong to its certificate, or `client_ca_file` names another CA. The Server checks neither at startup.                                                           |
