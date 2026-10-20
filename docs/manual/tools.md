# The operator tool

[← User Manual](README.md) · [The Server](server.md) · [The Client](client.md) ·
[Rollout walkthrough](rollout.md)

One program, `opamp-fleetctl`, ships beside the Server and the Client for the
operator who sets a fleet up and gets software _into_ it. It is not part of the
running system: nothing the Server or a Client does depends on it, and it
belongs on the operator's own machine, not on the Server host — the keys it
makes are the ones to keep off that host.

| Command                                                                              | Use it to                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **[`package fetch`](#package-fetch)**                                                | fetch a release of a known agent — the OpenTelemetry Collector or this fleet's own Client — verify it, and hand it to the Server with its default configuration                           |
| **[`package pack`, `sha256`, `keygen`, `sign`, `public-key`](#packing-and-signing)** | build, hash, and sign a package artifact out of _any_ program you have, and make the package signing key                                                                                  |
| **[`pki init`, `server-cert`, `bootstrap-ca`, `status`, `p12-extract`](#pki)**       | make the fleet's certificate authorities and the Server's or a Gateway's certificate, replace the bootstrap CA, say when the server CA ends, and turn a `bootstrap.p12` into its PEM pair |

Reach for `package fetch` first: for the agents it knows, it replaces every step
of building an artifact by hand. The other `package` commands serve everything
else — your own agent, an internal build, a project `fetch` has never heard of —
and they are also where signing lives, which `fetch` deliberately does not do.

## Getting it

Every release publishes it for Linux and macOS, on amd64 and arm64, as
`opamp-fleetctl_<version>_<os>_<arch>.tar.gz` beside the Client's assets, with
its CycloneDX SBOM `opamp-fleetctl_<version>_<os>_<arch>.cdx.json`, covered by
the same `SHA256SUMS` and by the release's build-provenance attestation. Verify
the archive before you run it, since this program makes the fleet's keys: the
attestation proves it was built by this repository's release workflow, and its
hash must match its line in `SHA256SUMS` (`sha256sum`, or `shasum -a 256` on
macOS). The archive holds the one program, executable:

```console
$ gh attestation verify opamp-fleetctl_<version>_linux_amd64.tar.gz --repo neteye-platform/classis \
    --signer-workflow neteye-platform/classis/.github/workflows/release.yml
$ sha256sum -c --ignore-missing SHA256SUMS
$ tar xzf opamp-fleetctl_<version>_linux_amd64.tar.gz
$ ./opamp-fleetctl --version
```

These archives are downloaded, never uploaded to a Server: they are not packages
of the fleet, and no Client installs one. There is no Windows build; on Windows,
build it from a checkout:

```sh
cargo build --release --bin opamp-fleetctl
./target/release/opamp-fleetctl --help
```

`cargo run --bin opamp-fleetctl -- <command>` runs it from a checkout without
installing it.

Every command writes its **status to stderr** and its **result to stdout**, so a
hash, a key or a signature composes into a shell variable while the running
commentary stays on the terminal:

```sh
sha=$(opamp-fleetctl package pack --out promtail-3.0.0.tar.gz ./promtail)
```

## `package fetch`

### What it does

For three agent types it knows where the release lives, what the assets are
called, and which checksum file goes with them:

| `--agent`         | Where it fetches from                                   | What arrives                                                                                                                                                                                                                        |
| ----------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `otelcol`         | `open-telemetry/opentelemetry-collector-releases`       | the core Collector's `.tar.gz`, as published                                                                                                                                                                                        |
| `otelcol-contrib` | the same repository                                     | the Contrib Collector's `.tar.gz`, as published                                                                                                                                                                                     |
| `supervisor`      | `neteye-platform/classis` — this project's own releases | the `.tar.gz` this fleet's Client is released as, one per platform, as published. It is the package a Client updates _itself_ from; the `.deb`, `.rpm` and `.msi` beside it are for installing a Client by hand and are passed over |

Four things it does on every run:

- **It verifies the download against the SHA-256 upstream published**, before
  the artifact is used for anything. A mismatch stops that platform and leaves
  the file for inspection.
- **It leaves the artifact alone** wherever upstream's container is one a Client
  can open — so the hash the fleet verifies is the hash on the release page, and
  the line from the release to the host is unbroken.
- **It uploads the agent's default configuration with the package** — but only
  the ones the Server does not already have, see
  [below](#the-default-configuration).
- **It never distributes anything.** Uploading stores a Package and saves a
  Configuration; reaching a host is the rollout act, which stays yours
  ([step 6 of the walkthrough](rollout.md#6-roll-it-out)).

### Interactive

Run it with no arguments and it asks for what it cannot know:

```console
$ opamp-fleetctl package fetch
Which agent:
  otelcol          linux, darwin, windows — as the release publishes
> otelcol-contrib  linux, darwin, windows — as the release publishes
  supervisor       linux/amd64+arm64 darwin/arm64+amd64 windows/amd64
Reading the last releases of open-telemetry/opentelemetry-collector-releases …
Which version› 0.158.0
Which platforms (space to select, enter to confirm)
  [x] linux/amd64
  [x] windows/amd64
  [ ] darwin/arm64
Upload these to a fleet Server? yes
Server base URL› https://127.0.0.1:4321
```

The systems beside each agent are what it is published for — enough to see
before the choice that an agent offers nothing for the hosts you run. They are a
hint, not the offer: the platform question below shows what _that release_
actually has. One needs a word:

- The **Collectors** add platforms between releases, so only their operating
  systems are named here; the architectures come from the release itself a step
  later.

The version list is the **three most recent release series**, newest first — a
series being a `major.minor` line, of which only its newest patch is offered.
That is the difference between a list you can go back through and one you
cannot. An older patch of a series already on the list is not a choice anyone
makes, so it is not offered. Release candidates and the tags a repository keeps
for other things (the Collector repository tags its builder alongside) are
filtered out.

The platform list is what _that release actually publishes_, read from its
assets rather than from a table that could go stale — so a platform upstream
added appears without this tool being changed, and one it dropped simply is not
offered. A platform this fleet has no name for (`linux/s390x`, say) is left out,
because a package entry no Agent can match is one nobody would ever be offered.

### Non-interactive

Every prompt has a flag; give all of them and nothing is asked:

```console
$ opamp-fleetctl package fetch --agent otelcol-contrib --version 0.158.0 \
      --platform linux/amd64 --platform windows/amd64 \
      --out-dir ./artifacts --server https://127.0.0.1:4321 --cacert offline/server-ca.pem
```

| Option                 | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--agent <name>`       | `otelcol`, `otelcol-contrib`, or `supervisor` (this fleet's own Client).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `--version <v>`        | The version **as upstream numbers it** — `0.158.0`, `1.19` — never the tag (`v0.158.0`). Omitted, the last five are offered.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `--platform <os/arch>` | Repeatable. `linux/amd64`, `windows/amd64`, `darwin/arm64`, … A platform the release does not publish is refused with the list of those it does.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `--out-dir <path>`     | Where artifacts are written. Created if missing. Defaults to the working directory.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `--server <url>`       | The Operator plane's `https://` URL. Create the Package and upload each artifact as its platform's entry. It stops there: putting the Package in a deployment is an operator act, and the tool prints the call that does it. Cannot be combined with `--no-upload`.                                                                                                                                                                                                                                                                                                                         |
| `--cacert <file>`      | The CA certificate (PEM) the Operator plane's certificate chains to — for a fleet made with [`pki init`](#pki), the `server-ca.pem` in its offline directory, or your PKI's CA when `[rest.tls]` names a certificate of its own ([setup](setup.md#the-uis-own-certificate)). It replaces the system's roots for the calls to the Server alone; the downloads from upstream are still checked against the system's roots. Without it, a Server certificate no system root vouches for ends the upload with `invalid peer certificate: UnknownIssuer`. Cannot be combined with `--no-upload`. |
| `--no-upload`          | Write the artifacts and stop, without the upload question.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

`--version` names the _release to fetch_, not this tool's own version —
`--version 1.19`, not a bare `--version`.

The release is fetched under upstream's own tag, and the Package is named with
the version written as SemVer, because a Package version is SemVer: a number
with fewer than three components is completed with `.0`, and a leading zero is
dropped from a component. `--version 1.19` fetches tag `v1.19` and uploads
Package `1.19.0`; `24.04.1` becomes `24.4.1`. Both keep upstream's order. A
number that cannot be written so is refused before anything is downloaded,
naming it.

### What it prints at the end

The block each artifact needs, because that differs per agent and platform and
is the next thing you need:

```text
Done. What a Supervisor needs to install these:
  linux/amd64  ./artifacts/otelcol-contrib_0.158.0_linux_amd64.tar.gz
      command = "otelcol-contrib"
  windows/amd64  ./artifacts/otelcol-contrib_0.158.0_windows_amd64.tar.gz
      command = "otelcol-contrib.exe"
```

For `--agent supervisor` there is no block to print — nothing supervises a
Client — so the hint is the consent that lets it take the package over itself,
which is also its default:

```text
Done. What a Client needs to take these:
  linux/amd64  ./artifacts/supervisor_1.2.3_linux_amd64.tar.gz
      [packages] self_update = true  (the default)
```

With `--no-upload` (or a declined prompt) it also prints the two `curl` calls
that would have uploaded the artifacts, so the step can be done later or from
somewhere else, and names the default configuration that was not uploaded
either.

### The default configuration

A package alone leaves an Agent with nothing to run: a Supervisor holds at
_awaiting configuration_ until a Configuration of the name its block reads
arrives. So an upload carries the agent's default with it — the same bodies as
[`config/examples/`](../../config/examples/), compiled into the tool so they
travel with the released binary:

| `--agent`         | Configuration          | Agent type                                                                                                         |
| ----------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `otelcol`         | `otelcol-conf`         | `service_name = otelcol`                                                                                           |
| `otelcol-contrib` | `otelcol-contrib-conf` | `service_name = otelcol-contrib`                                                                                   |
| `supervisor`      | none                   | — a Client is configured by `supervisor.toml` on its own host, and the fleet owns only its `[[supervisor]]` blocks |

Two rules keep this from surprising anyone:

- **An existing Configuration is never written over.** The name is asked for
  first, and one the Server already holds is left exactly as you left it, edits
  and all. That is what makes a second upload of a newer version safe.
- **Nothing is distributed.** Saving only saves, and a Configuration reaches a
  host only through a Deployment that holds it, so the default reaches no host
  until you put it into the Deployment that carries the package and roll that
  out. Read it first: these bodies carry example values.

```sh
  stored as the linux/amd64 entry — not distributed: press the rollout when it should reach hosts
  storing the default configuration otelcol-contrib-conf …
  saved — read it over, put it into the deployment that should carry it and press that deployment's rollout when it should reach hosts, since it carries example values
```

and on the next upload of the same agent:

```sh
  otelcol-contrib-conf is already on the Server — left as it is
```

### When an upload is refused

The Server decides some uploads before it reads a byte of the artifact, and says
which:

| What it answers                 | What to do                                                                                                                                                                                                                       |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `409 … immutable`               | The Package is already rolled out to an Agent, so its entries are fixed. Fetch under a new version.                                                                                                                              |
| `507 … max_total_package_bytes` | The package store is at its ceiling. Delete a Package no channel holds, or raise the limit ([the Server's configuration reference](server.md#top-level)).                                                                        |
| `404 … not configured`          | The Server has no package store — a Server started from `server.toml` always has one under `data_dir`, so the URL reaches something else than the Server ([Packages](server.md#packages-and-deployments-distributing-software)). |
| `413 …`                         | The artifact is past `max_package_size_bytes`.                                                                                                                                                                                   |

Because the refusal arrives while the artifact is still being sent, the
connection can reset before the answer is read; the tool then asks the Server
once more with an empty body to recover the reason, so what you see is the
status and message above rather than a bare connection error. A message that
does still begin `cannot reach` is what it says — the Server was not answering —
and it carries the underlying cause (DNS, refused connection, TLS) rather than
only the request that failed.

### What it does not do

- **It does not sign.** Signing needs a key, and where that key lives is a
  decision a tool should not make silently — use
  [`package sign`](#packing-and-signing) and record the signature on each entry
  it uploaded ([step 4](rollout.md#4-give-it-to-the-server)). Until then the
  entries are offered to nobody.
- **It does not aim, and it does not roll out.** A Package reaches a host only
  once a Deployment holds it, and which channel that is is not a decision a
  fetch tool should make. What it stores sits in the store, visible as
  `in no deployment`, until you put it somewhere
  ([step 5](rollout.md#5-put-it-in-a-deployment)); the tool prints the call.

### Prerequisites and limits

- **Network egress** to `api.github.com` and to the release asset host.
- **The upload speaks TLS to the Operator plane**, so the Server's URL is
  `https://`; type it so at the prompt, which suggests `http://`. The tool has
  no CA option and trusts the Server's certificate through this machine's own
  trust store, so a Server whose certificate comes from a private CA needs that
  CA trusted here. Off the loopback, carry the
  [`[rest.auth]`](server.md#the-operator-plane-restauth) credential in the URL:
  `https://fleet-admin:secret@fleet.example:4321`.
- **GitHub rate-limits unauthenticated requests to 60 per hour** per address. A
  run costs two requests (one to list versions, one to read a release), so this
  is only reached by scripting. The error says so rather than leaving you
  guessing.
- **Only amd64 and arm64 (and 386 where published)** are named, matching what
  Agents report as `os.type` and `host.arch`.

## Packing and signing

For a program `package fetch` does not know: these commands build the container,
and they own signing.

```console
$ opamp-fleetctl package keygen --out fleet-signing.pk8   # prints the public key (hex)
$ sha=$(opamp-fleetctl package pack --out promtail-3.0.0.tar.gz ./promtail)
$ sig=$(opamp-fleetctl package sign --key fleet-signing.pk8 --agent-type promtail --version 3.0.0 \
      promtail-3.0.0.tar.gz)
```

| `package` command                                                      | What it prints                            | Use it for                                                                                                                                                                                                                    |
| ---------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `keygen --out <file>`                                                  | the **public** key (hex)                  | the value for every Client's `[packages] verification_key`, and optionally the Server's; the private key goes in the file, ideally not on the Server host                                                                     |
| `pack <program> --out <file>`                                          | the artifact's SHA-256 (hex)              | building a one-file artifact; `--format tar.gz\|7z`, `--program-name <name>`, `--archive-key <key>`                                                                                                                           |
| `sign --key <file> --agent-type <type> --version <version> <artifact>` | the signature (hex)                       | the body of the entry's signature route, `PUT /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature`. It covers the type, the version and the artifact's SHA-256 together, so it holds for that Package alone |
| `public-key --key <file>`                                              | the public key (hex)                      | recovering it from an existing private key                                                                                                                                                                                    |
| `sign --key <file> --signing-info <file> [--out <file>]`               | the signing file, with every entry signed | a Package's **Signing info** from the Packages tab, signed whole and imported there — see [Signing a whole Package at once](#signing-a-whole-package-at-once)                                                                 |
| `sha256 <artifact>`                                                    | the SHA-256 (hex)                         | comparing a file you hold with the `content_hash` the Server shows for its entry, before you sign                                                                                                                             |

Both forms of `sign` sign only a SemVer 2.0.0 version. A `--version`, or a
signing file, whose version is not SemVer (`1.19`, `24.04.1`) is refused before
the key is read, naming the version: a Client refuses such a package, so the key
never signs one.

The options of `pack`, and why a `.tar.gz` packed twice gives the same bytes,
are in [step 2 of the rollout walkthrough](rollout.md#2-build-the-artifact),
which runs the whole path from packing to a running agent.

**Signing is required, fleet-wide.** A Client takes a package only while
`[packages] verification_key` is set, and only when the artifact's signature
verifies against it. The Server offers no entry that carries no signature, and
refuses to roll out a Deployment holding a Package with an unsigned entry. Give
every Client the same public key, and sign every entry of every Package you
release. Give the Server the same public key too (`[packages] verification_key`
in `server.toml`) and it reports each signature `valid` or `invalid` before any
Client sees it — as feedback only: an `invalid` one is stored and offered, and
each Client decides.

### Signing a whole Package at once

A Package of five platforms is five signatures. The Packages tab lists every
entry of the Package with its own signature field; instead of signing each
artifact and typing each signature there, carry them in one file:

1. In the **Packages** tab, select the Package and press **Signing info**. It
   downloads `<agent type>_<version>_signing.json`:

   ```json
   {
     "format": "opamp-fleet-signing-v1",
     "agent_type": "supervisor",
     "version": "1.2.3",
     "entries": [
       { "os": "linux", "arch": "amd64", "sha256": "127f9a48…" },
       { "os": "windows", "arch": "amd64", "sha256": "90cbb340…" }
     ]
   }
   ```

2. **Compare every `sha256` with an independent source before you sign.** For an
   artifact `package fetch` uploaded as published, that is the checksums file of
   the upstream release; for any artifact, it is `opamp-fleetctl package sha256`
   over the file you hold. The tool signs the hashes as the file states them and
   checks them against nothing — a hash you did not compare is one you are
   taking the Server's word for, and a Client accepts whatever your key signed.

3. On the machine that holds the key:

   ```console
   $ opamp-fleetctl package sign --key fleet-signing.pk8 --signing-info supervisor_1.2.3_signing.json
     signing supervisor@1.2.3 linux/amd64  127f9a48…
     signing supervisor@1.2.3 windows/amd64  90cbb340…
   ```

   Every entry gains its `signature`, written back into the file (or to
   `--out <file>`). The file is checked whole first: another `format`, a hash
   that is not 64 lowercase hex characters, a platform named twice or a field
   the format does not define signs nothing. Signing a file again with the same
   key gives the same signatures.

4. In the **Packages** tab, select any Package, choose the signed file and press
   **Import signing file**. Each signature goes to the entry of the Package the
   file names with its platform and SHA-256, one request each; one whose hash is
   not that entry's is skipped. Each platform's answer is listed with its
   `signature_state`: `valid` or `invalid` when the Server holds
   `[packages] verification_key`, `unchecked` when it does not.

One import serves every Deployment that holds the Package: the signature is the
entry's, and it covers the type, the version and the hash, not a Deployment.

## `pki`

The fleet's certificates, made without `openssl` or any other tool.
[Setting up a fleet](setup.md) walks through them in order; in short:

| `pki` command                                                      | What it does                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `init --server-dir <dir> --offline-dir <dir> --name <dns\|ip>…`    | makes the three CAs, the Server's certificate and the package signing key, the certificates named for `--product` (default `OpAMP Fleet`) and, with `--organization` and `--organizational-unit`, for your organization, split into what the Server host needs — the bootstrap CA's key among it — and what stays offline — the server CA's key and the package signing key — with a configuration fragment for each side |
| `server-cert --offline-dir <dir> --name <dns\|ip>… --out <dir>`    | makes another server certificate from the offline server CA, for the Server or a Gateway; it carries the CA's organization unless `--organization` or `--organizational-unit` replaces it                                                                                                                                                                                                                                 |
| `bootstrap-ca --product <name> --out <dir>`                        | makes a new bootstrap CA, valid for a year, to replace the Server's `[enrolment]` files                                                                                                                                                                                                                                                                                                                                   |
| `status --offline-dir <dir>`                                       | says when the server CA in the offline directory ends; exits `0`, `1` when it is ending, `2` when it has ended                                                                                                                                                                                                                                                                                                            |
| `p12-extract <bootstrap.p12> --out <dir> [--password-file <file>]` | writes the file's certificate as `bootstrap.pem` and its key, unencrypted and owner-only, as `bootstrap-key.pem`, the pair a Client's install takes; asks for the password with input hidden, or reads it from the first line of `--password-file`; overwrites neither file                                                                                                                                               |

None of them makes a bootstrap certificate: the Server issues those, on
`POST /api/v1/bootstrap-certificates`
([Setting up a fleet](setup.md#4-configure-and-install-a-client)). The Server
makes no CA and no server certificate. Its own
`server pki status --config <server.toml>` says when the certificates of the
Server host end, by the same rule.
