# Walkthrough: rolling a Foreign Agent out from the Server

[← User Manual](README.md) · [The Server](server.md) · [The Client](client.md)

This is the end-to-end path for putting a program on every host in the fleet
from one place: a Foreign Agent that speaks no OpAMP, delivered as a package,
configured over the protocol, and updated the same way from then on. It ends
with the Server holding both the binary and the configuration, and no step that
has to be repeated per host.

The example is `promtail` — one static binary, which is the requirement (see
[Limits](#limits-worth-knowing-first)). Substitute any single-file agent.

- [Limits worth knowing first](#limits-worth-knowing-first)
- [1. Configure the Supervisor](#1-configure-the-supervisor)
- [2. Build the artifact](#2-build-the-artifact)
- [3. Sign it](#3-sign-it)
- [4. Give it to the Server](#4-give-it-to-the-server)
- [5. Put it in a deployment](#5-put-it-in-a-deployment)
- [6. Roll it out](#6-roll-it-out)
- [7. Send its configuration](#7-send-its-configuration)
- [8. Watch it land](#8-watch-it-land)
- [9. Ship an update](#9-ship-an-update)
- [Troubleshooting](#troubleshooting)

## Limits worth knowing first

Three properties of package delivery decide whether this path is open to a given
agent. Reading them first is cheaper than discovering them at rollout time.

- **One file by default, a whole tree when you say so.** A statically linked
  single binary — Promtail, Vector, a Go or Rust agent — needs nothing extra. An
  agent that is an executable _plus_ the shared objects it loads, such as Fluent
  Bit, needs `program_path` in its block, which unpacks the whole archive
  instead of one member; see
  [Agents that are more than one file](client.md#agents-that-are-more-than-one-file).
  Everything below applies to both.
- **`.tar.gz`, `.7z`, and `.zip` are opened.** The Client decides what an
  artifact is by its **leading bytes**, not its name, and anything that is none
  of the three is taken to _be_ the program. Only `.7z` may be encrypted; an
  encrypted `.zip` is refused rather than opened. A `.tar.gz` is the right
  container for a tree that runs on Unix, because it is the one that carries
  file modes.
- **The member name must match the configured program.** The Client looks inside
  the archive for the file name its `[[supervisor]]` block names, wherever the
  archive keeps it.

## 1. Configure the Supervisor

The program's _written form_ is the whole of this host's consent to being
updated. A bare file name puts the program in a directory the Client owns.
Together with the fleet's verification key, that is what makes this Agent
declare `AcceptsPackages`:

```toml
[packages]
verification_key = "<the public key from step 3>"

[[supervisor]]
type = "command"
name = "promtail"
command = "promtail"                  # bare: <supervisor_dir>/promtail/program/promtail
args = ["-config.file=${config_dir}/promtail-conf"]
version_args = ["--version"]
```

Without `[packages] verification_key` the Client takes no package at all, and
says so at startup.

Two things this block gets right that are easy to get wrong:

- `command = "promtail"` is **not** looked up in `$PATH`. It names a file in
  that Supervisor's own `program/` directory — which is exactly why the Server
  may write there. An absolute path is refused at startup; a bare file name is
  the only shape a block accepts.
- `${config_dir}` is a placeholder, so the argument cannot drift when
  `supervisor_dir` moves or the Supervisor is renamed. `promtail-conf` is the
  _name of the Configuration on the Server_, which is what the written entry
  file is called.

**Nothing has to be installed on the host first.** Start the Client with the
program absent and the Agent comes up, connects, and reports
`no process installed` — a Supervisor with no process, said plainly, rather than
a spawn error. With the verification key set it declares `AcceptsPackages` all
the same, so the first version arrives the same way every later one does.

**The block does not have to be written on the host either.** A Configuration
typed `supervisor` — the Client's own Agent type — whose body carries this
`[[supervisor]]` block rolls the block itself out to every matching Client,
which writes it into its own `supervisor.toml` and starts the Supervisor — the
walkthrough's remaining steps are the same either way. A Server-delivered block
may name its program **only by a bare file name** — one this Client owns and
updates from signed packages; a block that names an absolute path is refused,
because that would let the Server spawn a machine binary that never passed
through package signing. An absolute-path Supervisor is the operator's to write
in `supervisor.toml` on the host, not the Server's to push.

## 2. Build the artifact

**For the Collector this step and the next two are one command.**
[`opamp-fleetctl package fetch`](tools.md#package-fetch) knows where the
OpenTelemetry Collector (`otelcol`, `otelcol-contrib`) publishes, and asks what
it cannot know — which agent, which of the last five versions, which platforms,
and where to upload:

```sh
opamp-fleetctl package fetch
```

It verifies every download against the SHA-256 upstream published, leaves the
artifact untouched wherever upstream's container is one a Client can open — so
the hash the fleet verifies is the one on the release page — and repacks only
where upstream ships no installable archive. It never rolls anything out:
reaching a host is still [step 5](#6-roll-it-out). The full option list is in
[the tools page](tools.md#package-fetch); if you take that route, read on at
[step 5](#6-roll-it-out).

For anything else — your own agent, or a project that tool has never heard of —
the rest of this step is how an artifact is built by hand.

`opamp-fleetctl package pack` writes the two containers worth writing, with the
member named the way the Supervisor will look for it, and prints the artifact's
SHA-256:

```console
$ opamp-fleetctl package pack --out promtail-3.0.0.tar.gz ./promtail
wrote promtail-3.0.0.tar.gz holding "promtail" — a Supervisor whose program is named "promtail" installs it
sha256 (hex):
84736f3e2d7d3dc260f172df23063bb044aaa7d576dd8f7b8021a58d6c772461
```

| Option                  | Meaning                                                                                                                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--out <path>`          | Where to write the artifact. Required.                                                                                                                                                        |
| `--format tar.gz\|7z`   | The container. `tar.gz` (the default) is what upstream releases ship and needs no key.                                                                                                        |
| `--program-name <name>` | The member name inside the archive. Defaults to the packed file's own name — set it when an upstream build is called `promtail-3.0.0-linux-amd64` but the Supervisor's program is `promtail`. |
| `--archive-key <key>`   | AES-256-encrypts a `7z`. The value goes into `[packages] archive_key` on every Client that receives the package; the Server never learns it.                                                  |

Only the hex hash goes to stdout, so it composes:
`sha=$(opamp-fleetctl package pack …)`.

**A `.tar.gz` is reproducible.** Modification time, owner, and group are zeroed,
so packing the same program twice gives the same bytes and the same hash. That
matters in a system where a hash decides whether anything is distributed: an
artifact differing only by when it was built would be a rollout nobody asked
for. A `.7z` is **not** reproducible — encryption draws a fresh salt each time,
so take the hash from the artifact you actually upload, which is what the
command prints.

An encrypted artifact instead:

```console
$ opamp-fleetctl package pack --format 7z --archive-key "$FLEET_ARCHIVE_KEY" \
      --out promtail-3.0.0.7z ./promtail
```

```toml
# on every Client that receives it
[packages]
archive_key = "…the same value…"
```

Already have an upstream release? Then it is already a `.tar.gz` and needs no
repacking — that is the point of the design. The OpenTelemetry Collector, for
instance, publishes its distributions on the
[collector releases page](https://github.com/open-telemetry/opentelemetry-collector-releases/releases),
one artifact per platform named `<distribution>_<version>_<os>_<arch>.tar.gz`:

```sh
curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.109.0/otelcol-contrib_0.109.0_linux_amd64.tar.gz
```

Check what it holds and whether the member name matches your block:

```sh
tar tzf otelcol-contrib_0.109.0_linux_amd64.tar.gz
opamp-fleetctl package sha256 otelcol-contrib_0.109.0_linux_amd64.tar.gz
```

The member is named after the **distribution** — `otelcol-contrib` in the
Contrib archive, `otelcol` in the core one — so the receiving `[[supervisor]]`
block must name its program the same way (`command = "otelcol-contrib"`, or
`binary = …` for a `collector` block), or the install fails with _"the archive
holds no member named …"_. Repack with `--program-name` when you want a
different name on disk.

## 3. Sign it

```console
$ opamp-fleetctl package keygen --out fleet-signing.pk8     # prints the public key (hex)
$ sig=$(opamp-fleetctl package sign --key fleet-signing.pk8 --agent-type promtail --version 3.0.0 \
      promtail-3.0.0.tar.gz)
```

Put the public key in every Client's `[packages] verification_key`, and —
optionally — in the Server's, which then checks each signature you give it and
says whether it is valid. Signing is not optional: a Client without the key
takes no package, an offer without a signature is refused before anything is
downloaded, and the Server offers no entry that carries no signature. Keep the
private key off the Server host.

The download route requires the Client's certificate, and the content hash and
this signature are what protect an installed binary.

## 4. Give it to the Server

Create the **Package** — its identity is the Agent type and the version, and
nothing else — then upload the artifact as an entry and sign the entry. Every
artifact is uploaded: the Server holds what it offers, and a Client fetches from
its own Server alone. Nothing in this step reaches any host, and nothing in the
next one does either: a stored Package aims at nobody at all.

The calls go to the Operator plane over TLS. `--cacert ca.pem` names the CA that
signed the Server's certificate; off the loopback, add the operator credential
with `-u`. Steps 4 to 6 and 9 can be done in the UI's **Packages** and
**Deployments** tabs as well;
[A host's life](lifecycle.md#releasing-an-update-in-the-ui) shows how.

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{}' \
       https://127.0.0.1:4321/api/v1/packages/promtail/3.0.0
```

The **Agent type** (the first path segment) is compared raw against the
`service.name` the Agents report — for a Supervisor that is its block's
`service_name`, or the program's file name when the block states none. A typo
here is a rollout that reaches nobody, which the channel's reach count in step 6
makes visible. There is no separate package name: what a Package _is_ and which
release it belongs to are the whole of its identity.

**Upload** — the artifact is the body; the platform is the path. The Server
hashes what it stores, so no hash is passed here. `os` and `arch` say which
machines this artifact runs on: the Server offers an Agent only the entry built
for the platform it reported.

```console
$ curl --cacert ca.pem -X PUT --data-binary @promtail-3.0.0.tar.gz \
       "https://127.0.0.1:4321/api/v1/packages/promtail/3.0.0/entries/linux/amd64"
```

The upload carries no signature, and new bytes remove the one the entry held.
**Sign** the entry on its own route, with the signature from step 3:

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d "{\"signature\": \"$sig\"}" \
       https://127.0.0.1:4321/api/v1/packages/promtail/3.0.0/entries/linux/amd64/signature
```

The answer shows the entry's `signature_state`: `valid` or `invalid` when the
Server holds `[packages] verification_key`, `unchecked` when it does not. An
`invalid` one is stored and shown as a warning, never refused — each Client's
own check decides — but a Client with the right key will refuse that artifact,
so fix it before the rollout. Uploading new bytes to an entry removes its
signature: it covered the old hash.

Their values are what an Agent reports as `os.type` and `host.arch` — `linux`,
`darwin`, `windows` and `amd64`, `arm64`. The tokens off an upstream release
file name work too (`macos` is `darwin`, `x86_64` is `amd64`), and the response
says which canonical pair was stored.

**A fleet on several platforms is still one Package.** Store each build as its
own entry, and every host is offered its own binary:

```console
$ curl --cacert ca.pem -X PUT --data-binary @promtail-3.0.0-linux-arm64.tar.gz \
       "https://127.0.0.1:4321/api/v1/packages/promtail/3.0.0/entries/linux/arm64"
```

Sign every entry the Package holds: the Server offers no unsigned entry, and the
rollout in step 6 is refused while any is left. The Agent type has nothing to do
with the member name inside the archive — only the _member_ has to match the
configured program.

For a Package of several platforms, sign them in one go instead: download the
Package's **Signing info**, sign it with
`opamp-fleetctl package sign --signing-info`, and import it on the Packages tab
— the steps, and the comparison of hashes they depend on, are in
[Signing a whole Package at once](tools.md#signing-a-whole-package-at-once).

## 5. Put it in a deployment

A **Deployment** is the channel this release goes to: a name, a Selector, the
Packages it offers, and the Configurations that go with them (step 7). It is the
only thing that is rolled out, and one press releases the Package and the
Configurations together.

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{"selector": {"channel": "beta"}}' \
       https://127.0.0.1:4321/api/v1/deployments/canary
$ curl --cacert ca.pem -X PUT https://127.0.0.1:4321/api/v1/deployments/canary/packages/promtail/3.0.0
```

Each Selector pair must equal an attribute the Agent reported — `channel` here
comes from `[attributes]` in `supervisor.toml`, or from a label you set on the
Server. **The Server prescribes no key**: `channel` says which stream of
versions a host follows, `region` where it runs, `tenant` whose it is, and all
three are yours to invent (see the Server manual, _Channels are a partition_).
**The Selector may not be empty**: an Agent belongs to at most one Deployment,
so a channel matching everybody would collide with every other one. That is the
price of the model and it is worth saying out loud — **there is no "everyone"
shortcut.** A host that carries no such value belongs to no Deployment and
waits.

The signature stays with the entry: one signature serves every Deployment that
holds the Package, because what it covers — the Agent type, the version and the
artifact's SHA-256 — names no Deployment.

## 6. Roll it out

**The rollout act is what distributes** — nothing before this press changed any
host:

```console
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/deployments/canary/rollout
{"assigned_agents": 3}
```

A Deployment holding a Package with an unsigned entry is refused `409`. The
message names each Package and the platforms it is unsigned for, and nothing is
released.

Check the channel's counts first — they are on `GET /api/v1/deployments` and on
its row in the UI. `claiming_agents` is who is in the channel: `0` means the
Selector missed. `targeted_agents` is who the act would actually move, which is
what the press changes. `conflicting_agents` is who this channel cannot reach
because a second Deployment claims them too — resolve that by narrowing a
Selector, because the Server will not pick between two channels.

The act assigns the channel's release — its Package and its Configurations — to
every Agent it claims, **as the fleet is now**. A host that enrols (or is
labelled into the channel) afterwards is not touched: its row on the Agents tab
shows what it would receive _waiting_, with a per-Agent **roll out** control —
press that, or repeat the channel's act, when it should follow. To try one host
first, use the per-Agent act:

```console
$ curl --cacert ca.pem -X POST -H 'Content-Type: application/json' \
       -d '{"deployment": "canary"}' \
       https://127.0.0.1:4321/api/v1/agents/<instance_uid>/rollout
```

It must be the Deployment that actually claims that Agent — an empty body means
the same — and it is refused while a second one claims it too: naming one here
would sidestep the conflict rather than fix it.

**Finishing the rollout** is giving the stable channel the same version and
pressing again. Widening the canary channel instead is _not_ how it ends: both
channels would then claim the same hosts, which is a conflict, not a rollout.

## 7. Send its configuration

The Supervisor writes every Configuration it is released into its `config/`
directory under that Configuration's own name, and the program is pointed at it
by the `-config.file=${config_dir}/promtail-conf` argument from step 1. A
Configuration is content only — it has no Selector — and it reaches the Agents
through the same Deployment as the binary:

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' \
       -d '{"service_name": "promtail", "body": "server:\n  http_listen_port: 9080\n"}' \
       https://127.0.0.1:4321/api/v1/configurations/promtail-conf
$ curl --cacert ca.pem -X PUT https://127.0.0.1:4321/api/v1/deployments/canary/configurations/promtail-conf
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/deployments/canary/rollout
```

The first two calls only store — saving never distributes; the third is the
rollout act. Done before step 6, the one press releases the binary and its
configuration together; done after it, the press sends only the configuration,
because the package offer has not changed and the hash gates send nothing twice.
The `service_name` keeps the body away from every Agent of the channel that is
not a promtail, so one channel can carry the configurations of several Agent
types. The Configuration's name and the file name in the argument are the same
string. Change the Configuration and press the channel again: the Supervisor
rewrites the file and restarts the process so it re-reads it. An Agent keeps the
exact revision it was rolled out — an edit waits, visible per Agent on the fleet
view, until the next act.

## 8. Watch it land

```sh
curl -s --cacert ca.pem https://127.0.0.1:4321/api/v1/agents | jq '.[] | select(.service_name=="promtail")'
```

What to look for, in the order it happens:

| Field                                      | What it tells you                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `capabilities` contains `AcceptsPackages`  | The block's program is named the way step 1 describes, and the Client holds `[packages] verification_key`. If it is missing, nothing else below will happen.                                                                                                                                                                                                  |
| `packages[].status`                        | `Downloading` — with `download_percent` and `download_bytes_per_second`, re-reported every 5 s — then `Installing`, then `Installed` or `InstallFailed`.                                                                                                                                                                                                      |
| `packages[].error`                         | Why an install failed: a missing member, a hash mismatch, a signature that does not verify, a download URL off the Server's origin, a wrong archive key.                                                                                                                                                                                                      |
| `packages[].version`                       | The version the Agent has installed; empty until the first one lands.                                                                                                                                                                                                                                                                                         |
| `service_version`                          | What `version_args` probed from the program — but **probed once, when the Supervisor started**. After an in-place package update it still shows the version that was running then; `packages[].version` above is the field that tracks what was installed. A Collector reporting through its own `opampextension` is the exception: it re-reports for itself. |
| `healthy`, `health_status`                 | `no process installed` before the first package; healthy once it runs.                                                                                                                                                                                                                                                                                        |
| `remote_config_status`, `effective_config` | The configuration half of the release (step 7).                                                                                                                                                                                                                                                                                                               |

Behind that, on the host: the artifact is streamed to
`<supervisor_dir>/promtail/packages/`, verified, unpacked, swapped over
`program/promtail`, made executable, restarted, and **health-gated on
`apply_grace_secs`** — a version that will not stay up is rolled back to its
predecessor.

## 9. Ship an update

An update is steps 2 to 6 again with a new version — a new version is a new
Package, and the old one stays in the store beside it. The channel is the
constant; **what it holds is what changes**, which is why the swap is explicit:

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{}' \
       https://127.0.0.1:4321/api/v1/packages/promtail/3.1.0
$ curl --cacert ca.pem -X PUT --data-binary @promtail-3.1.0.tar.gz \
       "https://127.0.0.1:4321/api/v1/packages/promtail/3.1.0/entries/linux/amd64"
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d "{\"signature\": \"$sig\"}" \
       https://127.0.0.1:4321/api/v1/packages/promtail/3.1.0/entries/linux/amd64/signature
$ curl --cacert ca.pem -X PUT "https://127.0.0.1:4321/api/v1/deployments/canary/packages/promtail/3.1.0?replace=true"
$ curl --cacert ca.pem -X POST https://127.0.0.1:4321/api/v1/deployments/canary/rollout
```

Without `?replace=true` the fourth line answers `409` naming 3.0.0 — a channel
holds one Package per Agent type, and swapping the version it runs is meant to
be something you say rather than something that happens.

The channel is untouched, and 3.0.0 stays in the store beside 3.1.0 — but
**putting 3.0.0 back in the channel is not how you take 3.1.0 back**. A Package
reaches an Agent only as an upgrade over the version that Agent reports
installed, so once the channel reports 3.1.0 the older one reaches nobody: the
channel's act answers `{"assigned_agents": 0}` and the per-Agent act answers
`409`. An Agent that reports no version for the package is measured by the
version it reports _running_ instead, so this holds on a host the fleet has
never installed anything on — and where an Agent reports both, the version it
reports _running_ decides and the package status is not read beside it, so a
record left behind by an install that did not take cannot strand the host.

What takes a bad version back is the host: the version 3.1.0 superseded is kept
for `retain_previous_secs`, and a binary that will not stay up past
`apply_grace_secs` is put back automatically — step 8's health gate. If the new
version is bad in a way the health gate cannot see, publish the old content as a
**new, greater version** (`3.1.1`) and roll that out; the fleet only moves
forward.

## Troubleshooting

| Symptom                                                                             | Cause                                                                                                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The Agent never shows `AcceptsPackages`                                             | The Client has no `[packages] verification_key`, and says so at startup. With the key every Supervisor declares it, so otherwise the Agent is not the one you think it is — check which Supervisor the row belongs to. The startup log states, per Supervisor, what it resolved and what it decided. |
| `InstallFailed`, "holds no member named …"                                          | The archive's member name does not match the configured program. The error lists what the archive _does_ hold; repack with `--program-name`.                                                                                                                                                         |
| `InstallFailed`, "holds no member at …"                                             | A tree package whose `program_path` names nothing in the archive. The error lists what it holds — check the path from its end, not from the archive root.                                                                                                                                            |
| `InstallFailed`, "matches N members"                                                | `program_path` is ambiguous; write more of the path.                                                                                                                                                                                                                                                 |
| `InstallFailed`, "climbs out" / "is an absolute path" / "not a file or a directory" | The archive carries a member this Client will not write — a `..` path, an absolute one, or a link. Nothing was unpacked and the running tree is untouched.                                                                                                                                           |
| An agent shows a package version it is not running                                  | Its record outlived the binary it describes — a version switch that did not take effect, or an older Client reinstalled on top of the state. The fleet reads what the agent reports _running_ beside the claim and offers that version again; the Client drops such a record when it starts.         |
| The agent stops starting right after a successful install                           | The artifact was some container the Client does not open — not gzip, 7z, or zip — so it was installed as if it _were_ the program. Repack as `.tar.gz`.                                                                                                                                              |
| `InstallFailed`, "holds an encrypted member"                                        | An encrypted `.zip`. Encryption is the `.7z` format's job, where `[packages] archive_key` opens it; repack, or publish the zip unencrypted.                                                                                                                                                          |
| `InstallFailed`, wrong archive key                                                  | `[packages] archive_key` is missing or not the one the `.7z` was packed with.                                                                                                                                                                                                                        |
| A package is refused naming `[packages] verification_key`                           | That Client has no key, and a Client without one takes no package. Set the fleet's public key.                                                                                                                                                                                                       |
| `InstallFailed`, the signature does not verify                                      | The Client's `verification_key` is not the key the entry's signature was made with, or the signature belongs to another artifact. With the Server's `[packages] verification_key` set, the Packages tab shows such an entry `invalid` before the rollout.                                            |
| `InstallFailed`, naming an origin                                                   | The download URL, or a redirect hop, leads outside the Client's own Server origin. A Client fetches from its Server alone; this Server offers only paths, so look for a redirect off the Server's origin.                                                                                            |
| The rollout answers `409` naming unsigned platforms                                 | Sign each named entry on the Packages tab (step 4), then press again.                                                                                                                                                                                                                                |
| An Agent is offered nothing                                                         | Two Deployments claim it, and an Agent belongs to at most one; `package_conflict` on its fleet row names both. Narrow one Selector.                                                                                                                                                                  |
| Deleting a Configuration, a Package or a Deployment answers `409`                   | An Agent's assignment pins it; the message says how many. Roll those Agents out through a Deployment without it — or forget them — and delete it then.                                                                                                                                               |
| An Agent shows no deployment at all                                                 | It carries no attribute any channel's Selector matches. That is the ordinary state right after an enrolment — label it into a channel (`PUT /api/v1/agents/<uid>/labels`) or set `channel` in its `[attributes]`.                                                                                    |
| A package shows `in no deployment`                                                  | Stored and unreachable: nothing aims it. Put it in a channel.                                                                                                                                                                                                                                        |
| A channel shows `aims at nobody`                                                    | Its Selector names an attribute nobody reports, or a value nobody carries. Compare it against the attributes on the Agents tab.                                                                                                                                                                      |
| An upload answers `400` about a signature                                           | A signature goes on the entry's own `…/signature` route; the message names it.                                                                                                                                                                                                                       |
| A signature answers `409`                                                           | The Package is rolled out to an Agent, and its entries — signatures included — are frozen. Ship the next version as a new Package.                                                                                                                                                                   |
| The package routes answer `404`                                                     | The Package or entry the path names does not exist — check the Agent type and version against `GET /api/v1/packages`.                                                                                                                                                                                |
| An upload answers `400`, "invalid platform"                                         | `os`/`arch` are required and must be file-name-safe: lowercase letters, digits and `_`, at most 16 characters.                                                                                                                                                                                       |
| An Agent that accepts packages is offered nothing, and there is no conflict         | No signed artifact for its platform. Check its `os.type` and `host.arch` on its fleet row against the platforms the package holds — this is the case the whole mechanism exists to make visible rather than fatal.                                                                                   |
