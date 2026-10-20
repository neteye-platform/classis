# ADR-0026: A Package is one release of an Agent type at a version, a Deployment that signs it is the only thing rolled out, a host or a Gateway fetches only what its Agents are offered, and a Supervisor installs only a signed package from an allowed source and rolls back only to a predecessor

- **Status:** 🟢 accepted · clauses 4, 5, 13, 14, 15, 20, 28, 35, 43 and 53
  superseded by
  [ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
  · clauses 22, 29, 31 and 33 superseded by
  [ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)
  · clause 37 superseded by
  [ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)
  · clauses 1 and 19 superseded by
  [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
  · clause 45 superseded by
  [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)
  · clause 65 superseded by
  [ADR-0043](0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)
- **Date:** 2026-10-10
- **Deciders:** Markus Brigl
- **Applies to:** `crates/fleet-server/src/packages.rs`,
  `crates/fleet-server/src/deployments.rs`, the package, deployment and download
  routes of `crates/fleet-server/src/api.rs` with the download handler
  `download_package`, `packages_dir` and the package limits in
  `crates/fleet-server/src/config.rs`, the package assignment in
  `crates/fleet-server/src/fleet.rs` and
  `crates/fleet-server/src/agent_store.rs`, what a host speaks for in
  `crates/fleet-server/src/revocation.rs` and
  `crates/fleet-server/src/fleet.rs`, the `download.refused` audit entry, the
  startup notice of `crates/fleet-server/src/main.rs` when `[client_ca]` is
  absent, the platform table in `crates/opamp/src/attributes.rs`, the
  `host.arch` the Client reports, the Packages and Deployments tabs of the
  bundled UI, `docs/SPECIFICATION.md` and its Non-Goal "Authorization and
  multi-tenancy", the Gateway's package cache and its download route in
  `crates/fleet-agent/src/gateway/` (`cache.rs`, the route in `mod.rs`, the
  offers `registry.rs` records), the cache directory under the Client's
  `state_dir`, `crates/fleet-agent/src/packages.rs` and the Client's waiting on
  `Retry-After` there, `crates/fleet-agent/src/archive.rs`,
  `crates/fleet-agent/src/install.rs`,
  `crates/fleet-agent/src/supervisor/process.rs`, the package handling in
  `crates/fleet-agent/src/supervisor/agent.rs`, the `[packages]` and `[updates]`
  sections, the `[gateway] package_cache_bytes` key and the `program_path` and
  `retain_previous_secs` keys of `supervisor.toml` and their parsing in
  `crates/fleet-agent/src/config.rs`, `crates/fleet-core/src/package.rs`, the
  `package sign` command of `opamp-fleetctl`, and the deterministic repack of
  `opamp-fleetctl package fetch`

## Context

The [specification](../SPECIFICATION.md) puts security before convenience
(Strategy _Security before convenience_, Quality Goal **Q-1** _Secure by
default_) and says that no vulnerability can be ruled out: no package and no
credential leaves a host unencrypted beyond the loopback; software is installed
only when it is signed with a key the operator holds and fetched from a source
the operator allowed; an Agent installs no package without a valid signature, so
an unsigned fleet is not a policy the Server supports.

Goal 10 asks the Server to update an Agent's binary — the Collector's and the
Client's own: it verifies each Package before it is applied, reports the
outcome, and rolls back on failure; a failed update is reported, not silent. The
Baseline's mechanism is a hash-gated sync. The Agent reports
`PackageStatuses.server_provided_all_packages_hash`; on a mismatch the Server
sends `PackagesAvailable` — per package a type, a version, a per-package `hash`
and a `DownloadableFile{download_url, content_hash, signature, headers}` — and
the Agent downloads, verifies, installs and reports each package through
`Downloading → Installing → Installed | InstallFailed`. The path runs from what
the Server holds and how an artifact gets there, through how an operator aims,
signs and releases it and who may fetch it, to the Agent that downloads,
verifies, unpacks, swaps, health-gates and rolls it back. When content reaches
an Agent and the version test it must pass are
[ADR-0025](0025-rollout-and-what-reaches-an-agent.md)'s.

The store, and which of the held artifacts can be meant for a given Agent at
all:

- **A release is one version across several artifacts.** The release pipeline
  ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md))
  publishes five platform builds of one version, and upstream projects publish
  more. The store needs an object that _is_ that release, or "which version is
  this at" has one answer per platform and a half-finished upload looks like a
  rollout in progress.
- **A mismatched binary is the worst mistake available.** A Windows artifact
  swapped over a Linux host's program, or a Promtail build swapped over a
  Collector, is caught only by the health gate — a fleet-wide outage window for
  a mistake the Server had every attribute in hand to refuse. A filter that
  holds only when an operator remembers to write it is not a guarantee.
- **Three spellings of one platform meet here.** Rust says
  `x86_64`/`aarch64`/`macos`; the semantic conventions — which the Baseline
  names as the vocabulary of `AgentDescription` — and the Collector's
  `opampextension` say `amd64`/`arm64`/`darwin`. A Managed Process's attributes
  are folded over the Supervisor's, so with two spellings a host would report a
  different architecture depending on what runs on it, and a filter written
  against one spelling would stop matching.
- **Upstream publishes archives, at an address, with a checksum.**
  `opentelemetry-collector-releases` publishes `.tar.gz`, `.deb`, `.rpm`, `.msi`
  — never a bare binary — and a `checksums.txt` with a SHA-256 per asset.
  Downloading 400 MiB to upload it again moves the same bytes twice. The
  Baseline's Download Server _"may be on the same host as the OpAMP Server or a
  different host"_, and `DownloadableFile.headers` exists so an Agent can
  authenticate to one.
- **The download is not secret.** Agents fetch artifacts without an operator
  credential, so what protects an installed binary is verification — the content
  hash, and a signature where the Agent holds a key — not transport secrecy. An
  artifact whose confidentiality matters must therefore be unreadable to the
  Server too. What travels with a download is another matter: a referenced
  entry's headers may carry a bearer token, and a plaintext request hands it to
  every network between the Agent and the source.
- **The Agent type is a fact the Server can read.** Every Agent this Client
  presents reports its type as `service.name`
  ([ADR-0016](0016-what-an-agent-reports-about-itself.md)), which the Baseline
  defines as "a reverse FQDN that uniquely identifies the Agent type".

What identifies a Package — its name on the wire, its hash, its layout and
routes — and how a Package is aimed, signed and released:
[ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 9 requires an aim,
its resource-level act ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)
clause 5) needs an object to name, and
[ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 19 asks for counts.
Four observations shape it:

- **A name beside the Agent type is a second identity for one thing.** The type
  decides fit; a free-form name would decide nothing but would group, and the
  only thing it could add — two artifacts of one type under different names — is
  an ambiguity that resolution would have to rank its way out of. In every
  artifact this project ships the two are the same string already
  (`supervisor`).
- **The Baseline's addon kind has no Client behind it.** The Client refuses
  every addon offer, as a defence against a foreign Server writing one over a
  Managed Process's binary; a Server-side kind flag would never change what a
  host installs.
- **Aim on the artifact makes "what is this" and "who gets it" one record**, and
  where several aims match one Agent, "which artifact does this host get"
  becomes a computation across all of them — a specificity ranking with ties to
  refuse — which no operator can read off any one object.
- **A Selector cannot say "not".** Every Selector is equality over the effective
  description ([ADR-0023](0023-configurations-and-the-rest-api.md)); "everyone
  except the canary hosts" is not writable. Disjoint targets must come from
  membership — which is what Server-set labels
  ([ADR-0024](0024-the-fleet-record.md)) and provisioned attributes already are.

What an operator signs off on is a release to a set of machines, not a pile of
bytes; and a rollout should name "what this channel runs", not _n_ artifacts
nothing holds together. The package store and the Agent records are read only in
the shapes this Server writes.

The download route serves an uploaded artifact's bytes on the Agent plane
(clause 13, clause 20). It sits behind the same TLS handshake as `/v1/opamp`
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
clause 8) and requires a certificate from the client CA
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 23). Admission decides fleet membership. None of these says which member
may fetch which artifact. Today `download_package` serves any artifact in the
store to any member that names it: type, version and Platform are all in the
path and the query, and both are easy to guess.

Membership is fleet-wide, but releases are not. A rollout releases a pinned
Package to one Agent at a time
([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clauses 2, 3, 5), and a
Deployment aims at a partition of the fleet by a host property such as
`channel`, `region` or `tenant` (clause 25). With the route open, a host in one
partition can fetch another partition's builds. It can fetch a version the
operator has saved but not yet released, such as the next canary build or a
build licensed to one tenant. A compromised host can also map the whole store by
trying versions. An artifact encrypted with an `archive_key` stays unreadable
(clause 6), but most artifacts are not encrypted. The host that leaks least when
it is compromised is the one that was never given more than its own Agents
receive.

A Client behind a Gateway must receive uploaded artifacts, and the maintainer
decided that the Gateway delivers them from a cache of its own rather than by
relaying each request. Downloads behind a Gateway do not reach the Server. A
Gateway that hands an artifact to a downstream host answers the question of who
receives which uploaded artifact one hop further down, so its rule belongs in
the decision that answers it at the Server. A marked Gateway's certificate
fetches what is offered to any Agent (clause 37), and that breadth is what the
cache fetches with. Clauses 42 to 48 bound what the Gateway passes on to the
hosts behind it, so that a downstream host receives from the Gateway no more
than the Server would serve it directly.

Forces on the download route and the Gateway:

- **The host is the one bound the Server has.** A certificate proves fleet
  membership and the host it was issued to, not an Agent. An `instance_uid`
  belongs to the host whose certificate first reported it. A host marked as a
  Gateway speaks for any Agent
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 7). Admission is a fleet-wide trust boundary, and within it the host is
  the only bound between Agents
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 14). Any test of "may fetch" can be no finer than the host.
- **What reaches an Agent is already decided, per Agent.** Its package offer is
  composed from its assignment alone. The offer is the assigned Package's entry
  for the Platform the Agent reports, signed by the Deployment that released it
  ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 3, clause 28).
  Type fit is a mandatory precondition of every offer (clause 9). The download
  needs no rule of its own. It needs the same test the offer uses.
- **The code has a gap against that clause.** `offer_for_assigned` (through
  `assigned_entry`) tests the Platform but not the Agent type. Type fit is
  checked when the operator rolls out, and is not checked again when the offer
  is composed. An Agent that reports a different `service.name` after the
  rollout is still offered the old type's Package.
- **Configurations already reach only their own Agent.** A composed config map
  travels in the `ServerToAgent` addressed to one `instance_uid`. It is composed
  from what was released to that Agent
  ([ADR-0023](0023-configurations-and-the-rest-api.md) clauses 6, 7,
  [ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 3). It answers
  only reports the host may make for that `instance_uid`. No route on the Agent
  plane serves configurations.
- **Without a cache in the Gateway, downloads behind it do not reach the
  Server.** A Client resolves a path `download_url` against its own OpAMP
  endpoint (`resolve_url` in `crates/fleet-agent/src/packages.rs`). Behind a
  Gateway that endpoint is the Gateway, which serves only `/v1/opamp`
  (`opamp::server::router` without `any_path`). The `GET` is answered `404`
  there. With `advertised_url` set, the offered URL is absolute and names the
  Server. That URL is not the Client's own origin, so `Sources::permit` refuses
  it unless it is listed in `[packages] allowed_sources`. If it is listed, the
  Client fetches it with its anonymous client, which presents no certificate,
  and the Server's handshake refuses it
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 23). A Client behind a Gateway that serves no download route therefore
  receives only referenced artifacts, and the only downloads a Gateway's
  certificate makes are those of the Gateway host's own Agents.
- **A partition is only as strong as the hosts it partitions.** A Selector
  matches the effective description, which is what the Agent reports plus the
  Server's labels (clauses 22, 25). It cannot tell the two sources apart, and
  where they collide, what the Agent reports wins
  (`labels::effective_description`). A compromised host can therefore report
  another partition's key and value, such as the Client's own `[attributes]`
  table would, under a fresh `instance_uid`. That Agent waits in the fleet view
  ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 6). The next
  bulk rollout of that partition's Deployment assigns it, and the host can then
  fetch what was released to it. This holds for a partition set by a Server
  label as well, because a reported attribute with the label's key satisfies the
  same Selector. What this decision bounds is fetching what was released to
  Agents the host does not speak for. It does not bound an Agent the host itself
  places in a partition.
- **Hiding is cheap only if it is complete.** An answer that differs between
  "exists, not yours" and "does not exist" lets a host list the store. HTTP
  allows a server to hide a forbidden resource behind `404` (RFC 9110 §15.5.4).
- **Behind a Gateway, one artifact crosses one link once per Agent.** A Gateway
  stands at a network boundary in front of a site or a segment (specification,
  Gateway Mode; G-15). A rollout that releases one Package to the n Agents
  behind it sends the same bytes n times over the link the Gateway was placed to
  spare, and asks the Server's store and its fleet lock n times.
- **Relaying each request costs what the cache saves.** A Gateway that relays
  the route fetches with its own certificate, because it terminates the
  downstream handshake and presents its own upstream
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
  clause 11); no downstream certificate ever reaches the Server. Every relayed
  request costs one token of the Gateway's aggregate bucket (clause 40,
  [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 22), so a rollout to more Agents than that bucket's burst throttles
  itself by its own size, and every byte still crosses the link once per Agent.
- **The Gateway already sees every offer it carries.** Each `ServerToAgent` for
  an Agent behind it passes through its registry on the way down
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
  clause 13), with the offer's `download_url` and `content_hash`. The registry
  knows which downstream connection carries the Agent, and so the certificate
  that connection presented. The Gateway forwards the message unchanged; reading
  it changes nothing on the wire.
- **The Gateway's certificate is as broad as its mark makes it.** Under clause
  37 it may fetch what is offered to any Agent. A cache gives it no artifact it
  could not fetch already. What a cache must not do is widen what a downstream
  host receives: a Gateway that served whatever it holds to any admitted peer
  would reopen, behind the Gateway, the enumeration and the cross-partition
  fetch that clause 37 closes at the Server.
- **A downstream host is named the way the Server names it.** A host behind a
  Gateway enrols with the Server directly or is provisioned by an operator
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 25). A certificate the Server issued carries
  `urn:opamp-fleet:host:<id>`, and an operator who provisions by hand names the
  host with that SAN URI (clause 37). The Gateway reads it from its own
  handshake. The host register is the Server's, and the Gateway does not hold
  it.
- **Verification stays with the installing Client.** The Client checks the
  content hash and the signature over type, version and hash before it installs,
  whatever host served the bytes (clauses 53, 54). A cache on the path changes
  where the bytes come from, not what is installed. Checking the hash at the
  Gateway as well keeps it from storing or passing on bytes the offer does not
  name, and a corrupted fetch is noticed once there instead of by every Agent
  behind it.

On the Agent, a signature over the artifact's bytes alone says nothing about
what the artifact is for. Any artifact signed with the operator's key installed
as any Supervisor's program, at any version label, older ones included; a
compromised Server could roll a Managed Process back to a signed build with a
known flaw, or hand a Collector a Telegraf binary. Measure H23 of
[`HARDENING.md`](../HARDENING.md) asked for the signature to cover the Agent
type and the version, as a Deployment already pairs them (clause 28), and for a
Client-side refusal of a downgrade. The forces on the Agent:

- **A running process cannot reliably replace its own binary**, so the work
  crosses a process boundary (the specification's _Updater_). For a Managed
  Process that boundary already exists: the Supervisor owns its process's stop,
  spawn and apply-grace health gate
  ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
  The Client's own binary is the other case
  ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).
- **Verification protects the host; the source set bounds what is exposed.** An
  artifact URL may point at the Server's download route or at a mirror or
  release page, so what stands between the bytes and an executed program is the
  content hash and an Ed25519 signature made with a key the operator holds (the
  Baseline's _Code Signing_ section leaves the method to the Agent). The `ring`
  provider the build already carries
  ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md))
  verifies Ed25519. A hash alone proves only that the bytes are the ones the
  offer named, and whoever can make the offer names the hash too. The transport
  still decides what a download exposes: the offer's `headers` are an operator's
  token, the Client's certificate is its fleet identity, and an unbounded set of
  sources is an unbounded set of hosts both could be presented to
  ([`HARDENING.md`](../HARDENING.md) H12, H13, H19).
- **An upstream release is an archive.** `opentelemetry-collector-releases`
  publishes `.tar.gz`, `.deb`, `.rpm` and `.msi`, never a bare binary, with a
  `checksums.txt` of SHA-256 values and sigstore keyless signatures. The GLPI
  Agent publishes its portable Windows build as a `.zip`. An upstream that
  publishes no self-contained build for a platform leaves a tree to be assembled
  from what it does publish. An in-house agent may have to stay confidential
  wherever it is stored. The protocol carries one file per package and leaves
  multi-file packages to "any file format that allows storing multiple files in
  a single file".
- **Many agents are more than one file.** Fluent Bit ships an executable plus
  the shared objects and plugins it loads, and a static build is not available
  upstream. A package that unpacks into a tree gives the archive a say in where
  bytes land — a security boundary this decision creates.
- **The rollback lifecycle must end.** Discarding a first install that will not
  start empties the program directory and the Server re-offers it: a download
  loop. A predecessor that also fails to start must not be respawned forever.
  And "survived the grace" is a first signal, not a final one, so the
  predecessor is worth keeping for a while.

## Decision

We will hold software in a store of packages — each one release of one Agent
type at one version, holding one uploaded or referenced artifact per Platform —
never open, pack or fetch an artifact on the Server, spell a Platform the
semantic conventions' way everywhere, and make type and platform fit a mandatory
precondition of every offer; identify a **Package** by its Agent type and
version alone, holding nothing but its entries, and introduce the **Deployment**
— a named channel aimed by a non-empty Selector, holding one Package per Agent
type and the signature of each artifact — as the only thing that is rolled out,
with an Agent belonging to at most one; serve an uploaded artifact on the
download route only to a member certificate whose host speaks for an Agent to
which that artifact, identified by Agent type, version and Platform, is
currently offered, have a Gateway fetch each uploaded artifact it relays an
offer of once with its own certificate and pass it on only to a downstream host
whose Agent it relayed that offer to, and answer every other request for an
artifact, on the Server and on a Gateway, exactly as we answer one for an
artifact that does not exist; and have each Supervisor take one top-level
package offered for its Agent only when the operator's Ed25519 verification key
is configured, stream it over TLS 1.3 from an allowed source to its own
directory, verify its SHA-256 and its Ed25519 signature before anything is
unpacked, open it on the host whether it is a bare program or a `.tar.gz`, `.7z`
or `.zip` holding one file or a whole tree, swap it in by rename, health-gate it
on the apply grace, roll back only to a real predecessor, stop restarting after
three failed starts, and keep the superseded version for a configurable window.

### The package store

1. **The store lives under `packages_dir` and is the Server's only source of
   software.** `packages_dir` (default `fleet-packages`) holds every package; it
   is managed through the REST API and restored at startup. `OffersPackages` and
   `AcceptsPackagesStatus` are declared only while the store holds a package —
   an undeclared capability is never exercised. The directory is created
   owner-only (`0700`) and every metadata file is written `0600` through a
   temporary file and a rename, because a referenced entry's headers may carry a
   bearer token (clause 5).

2. **A package is one release: one Agent type, one version, fixed at creation.**
   Both are stated when the package is created and never edited; a new version
   is a **new package**, never a change to an old one. There is no untyped
   package and no moment in which one exists. The store keeps every version
   openly as its own package until an operator deletes it — there is no hidden
   "previous" artifact and no automatic pruning, and the store is not where
   rollback happens ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)
   clause 18). The type is compared **raw** (clause 9); the version orders as
   [ADR-0012](0012-versions-resolved-in-the-internal-crate.md) clause 9 orders
   versions.

3. **A package holds one entry per Platform, so a duplicate is
   unrepresentable.** Entries are a map keyed by the canonical `(os, arch)`
   pair. Writing an entry for a Platform the package already holds replaces it;
   deleting the last one leaves an empty package, kept, because a package being
   assembled is a normal state and deleting the package is its own act. One
   entry suffices; five platforms are five entries under one identity. When an
   entry may be written at all is
   [ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 8's rule.

4. **An entry is an uploaded artifact or a reference to one.**
   - **Uploaded:** the body of an entry upload is the artifact. The Server
     streams it to a staging file in the package's own directory (named per
     Platform, so parallel uploads of one release do not collide), hashes it
     while streaming, refuses an empty one, and renames it into place as
     `<os>-<arch>.bin`. One artifact may be at most `max_package_size_bytes`
     (default 1 GiB, `413` beyond), the whole store at most
     `max_total_package_bytes` (default 16 GiB, `507` when the upload would pass
     it — checked before streaming and again after); `0` for either is refused
     at load.
   - **Referenced:** the entry is a `url`, a **mandatory** `sha256` (64 hex
     characters, as a release's `checksums.txt` publishes it) and optional
     `headers`. The `url` is `https://`; `http://` is accepted only when its
     host is a loopback IP literal, `127.0.0.1` or `[::1]` — a host name never
     counts as loopback, `localhost` included. The Server refuses any other
     `url` when the entry is set through the REST API (`400`, naming the rule),
     so neither the artifact nor the headers an Agent sends for it cross a
     network in plaintext. The Server stores only that reference and offers it
     verbatim as the `DownloadableFile`; it never downloads the artifact and has
     nothing to serve. A referenced entry replacing an uploaded one deletes the
     bytes it replaces. The headers are stored in cleartext (owner-only) and
     travel to every Agent offered the entry.

   The checksum is supplied, never derived: for a reference nothing central ever
   sees the bytes, so the operator's `sha256` is the one thing standing between
   a URL and a host, and every Agent checks it.

5. **Setting a source probes it once, as a typo catch and nothing more.** The
   Server sends one `HEAD` over TLS 1.3 with the given headers, a 10-second
   timeout and no redirect following, so it never follows a source onto a
   plaintext `url`. A `4xx` answer refuses the write (`400`, with a hint about
   headers on `401`/`403`); a source the Server cannot reach is stored anyway,
   because the Server is not in the download path. The probe refuses to aim at a
   non-routable address — link-local (the cloud metadata address among it), the
   shared/CGNAT range, unspecified, broadcast, documentation and `0.0.0.0/8` —
   and deliberately not at loopback or the RFC 1918 / unique-local ranges, where
   an operator's mirror legitimately lives, over `https://` as clause 4
   requires. The probe proves nothing about what an Agent will later receive;
   only the `sha256` does.

6. **The Server never creates, packs, repacks, encrypts, decrypts or opens an
   artifact.** What it is given is finished — built, packed and, if it is to be
   confidential, encrypted by whoever produced it. Package bodies are opaque
   bytes: the Server stores or refers, hashes, offers and serves. Unpacking, and
   the archive key that opens an encrypted `.7z`, belong to the Agent (clauses
   55 and 56), so the hash an Agent verifies is the one the artifact was
   published with, and a confidential artifact is unreadable on the Server's
   disk.

7. **A Platform is spelled the semantic conventions' way, end to end.** The
   canonical Platform is an `os.type` value (`linux`, `darwin`, `windows`, …)
   and a `host.arch` value (`amd64`, `arm64`, …). One table in the shared crate
   canonicalises **both** sides before they are compared — what is uploaded and
   what an Agent reports: `macos`, `osx` → `darwin`; `win`, `win32`, `win64` →
   `windows`; `x86_64`, `x64`, `x86-64` → `amd64`; `aarch64` → `arm64`. Anything
   else is lower-cased and passed through, so a platform the table has never
   heard of is still served; a canonical token must match `[a-z0-9_]{1,16}`,
   which keeps it a safe file-name component. The API answers with the canonical
   pair, so a typo shows in the response. The table is compatibility, not
   translation — nothing this project produces needs it:
   - the Client reports `host.arch` as `amd64`/`arm64` and `os.type` as
     `darwin`, mapping Rust's constants, so a Supervisor and a Collector's
     `opampextension` report the same string;
   - the release artifacts carry the same two tokens in their file names (the
     file-name format is
     [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)'s),
     so the upload of a release is a loop over the Client's archives with `os`
     and `arch` read straight out of each name.

8. **A request that names bytes names their Platform; one that names the package
   does not.** The entry upload, the entry source, the entry delete and the
   artifact download all carry `os` and `arch`; creating, reading or deleting a
   package does not. An invalid token is `400`.

9. **Fit is mandatory, comes before everything else, and has no "unknown, so
   anything goes".** A package can be meant for an Agent only when
   - its **Agent type equals** the `service.name` the Agent reports among its
     identifying attributes — compared raw, with no canonicalisation table and
     no prefix or pattern, because there is no authority to canonicalise Agent
     types against and `otelcol` and `otelcol-contrib` are different binaries;
     and
   - it holds an entry for the **Platform** the Agent reports — read from
     `os.type` and `host.arch`, non-identifying attributes first and an
     identifying copy as fallback, canonicalised as in clause 7.
     `os.description` (prose) and `os.version` (a release, not a system) are not
     read.

   An Agent that reports no type, or no `os.type` or `host.arch`, fits nothing.
   A per-Agent rollout act refused on fit says which of the three it was. A
   label can never supply or override these attributes
   ([ADR-0024](0024-the-fleet-record.md)), so a slip there cannot hand a host an
   artifact built for another machine.

10. **The Platform does not travel on the wire.** All Agents of one type are
    offered the package under the same key, each with the download URL and
    content hash of the entry that fits it — two platforms' artifacts differ in
    content hash by construction — so the Client's package handling is identical
    on every target and one `[self_update]` consent works across all five
    release platforms.

11. **The Server decides which artifact an Agent receives, never a file on the
    host.** A `[[supervisor]]` block names no package; one carrying `package`
    fails at startup with a message saying the Server decides. Type fit is also
    the second, independent guard on the Client's own binary: the Server does
    not offer a package of another type to the Client's Agent, whatever it is
    called, and the Client still refuses an offer outside its `[self_update]`
    consent
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)) —
    one side refuses to send, the other to install.

12. **The store opens loudly or not at all.** At startup every package's
    metadata is read and every uploaded artifact is re-hashed by streaming.
    Metadata that cannot be read or parsed, an invalid type, version or
    Platform, a content hash that is not hex, a directory whose name disagrees
    with the identity its metadata states, or an artifact that no longer matches
    its recorded hash fails startup naming the file — a corrupt distribution
    artifact must never ship, and a store that silently drops a package looks
    like one that was never given it.

13. **Uploaded artifacts are served on the Agent plane.** The download route is
    the one `/api/v1` route on the Agent-plane listener
    ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)),
    not on the operator plane and not in the OpenAPI document; it streams the
    file and never holds it in memory. The offered `download_url` is a path the
    Client resolves against its own OpAMP endpoint, or `advertised_url` plus
    that path where downloads must go through another host.

14. **The Packages tab is one table and one detail form.** One row per package —
    Agent type, version, the platforms it holds, and where it is used. Selecting
    a row makes it the current record and shows the form; while nothing is
    current the form is not on screen. **Create** opens the form empty — the
    only moment the identity fields are writable. The form adds and removes
    entries in place (a file, or a source URL with its `sha256`); a file named
    as a release artifact fills the platform and, while creating, the identity.
    **OK** persists, **Cancel** discards, and both conclude the form — only a
    failed save keeps it open beside its message; **Delete** stands alone on the
    left. The form enforces no rule of its own: what it greys out is what the
    Server answers `409` to.

### Deployments

15. **A Package is identified by `(agent_type, version)` and nothing else.**
    Both are tokens of 1–64 characters from letters, digits, `.`, `_`, `+` and
    `-` — no `@`, no path separator — so the pair embeds losslessly in a
    directory name and a URL. A Package has no name of its own, no Selector, no
    kind and no signature. Creating one that exists is the same request arriving
    twice.

16. **Two names are derived, and they answer different questions.** The **wire
    name** is the Agent type alone: the `PackagesAvailable` map key, the key an
    Agent reports its `PackageStatuses` under, and the value the Client's
    `[self_update] package` is compared against
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). It
    must be stable across versions. The **display name** is
    `<agent_type> <version>` — the UI and the log. Using one name in both places
    would break the Client's self-update guard on every release or make the
    fleet view unreadable.

17. **The hashes are fixed constructions, and both are shown.** The per-package
    hash is SHA-256 over the version's length (u64, little-endian), the version,
    and the entry's content hash; the Platform has no place in it.
    `all_packages_hash` is SHA-256 over the Agent type's length, the Agent type,
    and that per-package hash. Each entry in the API carries its `content_hash`
    — the exact value an Agent verifies against — and its `package_hash`, the
    value an Agent echoes once in sync.

18. **Every offered Package is top-level.** `PackageType::Addon` is never
    emitted. The Client's refusal of an addon offer stays where it is (clause
    51): it defends against a foreign Server, not against this one.

19. **The store's layout is fixed, and no other is read.** A Package is
    `<packages_dir>/<agent_type>@<version>/` holding `package.json` (identity
    and every entry's metadata) and one `<os>-<arch>.bin` per uploaded entry.
    The Deployments live in `<packages_dir>/deployments/`, armed by the same
    key. A loose file at the top level, or a directory without `package.json`,
    fails startup naming the path — skipping it would open a store that merely
    looks empty.

20. **The Package routes are the pair.**
    `GET|PUT|DELETE /api/v1/packages/{agent_type}/{version}` (`PUT` takes no
    body); `PUT|DELETE …/entries/{os}/{arch}` with the artifact as the body;
    `PUT …/entries/{os}/{arch}/source` with `{url, sha256, headers}`.
    `GET /api/v1/packages` lists each Package with its entries and the
    Deployments holding it. A `signature` on an entry upload or in a source body
    is refused (`400`) naming the Deployment route instead. The download is
    `GET /api/v1/packages/{agent_type}/{version}/file?os=…&arch=…` on the Agent
    plane. A Package has no Selector route and no rollout route; the OpenAPI
    document follows.

21. **The version test reads the claim under the Agent type**, because that is
    the key an Agent reports its status under;
    [ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clauses 10–13 are
    otherwise unchanged.

22. **A Deployment is a name, a Selector, Packages and signatures.** The name —
    the one human-chosen label in the model — follows the grammar a
    Configuration's name follows: 1–32 lowercase letters, digits and `-`, not
    starting or ending with `-`, no Windows device name. The Selector is
    [ADR-0023](0023-configurations-and-the-rest-api.md)'s equality pairs over
    the effective description, labels included. A Deployment is persisted as
    `<packages_dir>/deployments/<name>.json`, owner-only; a file that does not
    parse or whose name disagrees with its content fails startup naming it.
    `PUT /api/v1/deployments/{name}` creates it with `{selector}`,
    `PUT …/selector` re-aims it, `DELETE` removes it; saving distributes
    nothing.

23. **At most one Package per Agent type.**
    `PUT /api/v1/deployments/{name}/packages/{type}/{version}` adds a Package; a
    second one of a type already held is refused (`409`) naming the one held,
    unless the request says `?replace=true`, which swaps the version the channel
    holds. Writing the held one again succeeds. A Package the store does not
    hold is `404`. Two of one type would collide on the wire key _and_ fit the
    same Agent; refusing at the write turns a resolution-time mystery into an
    error at the moment of the mistake — and, the collision being on the type,
    which is identity, there is no dead end where every write is refused.

24. **A Deployment's Selector is never empty, and no pair has a blank half** —
    `400` at creation and at every edit, with a message naming what to write. An
    empty Selector is the channel that collides with every other, and a
    forgotten field would silently become the base for the whole fleet.

25. **Channels are a partition by a host property, and there is no "everyone".**
    The Server prescribes no key and reserves no word. The key an operator picks
    says what the partition means — `channel` (`stable`, `beta`) for release
    risk, `region` for where it runs, `tenant` for whose it is — and keys
    compose as further equality pairs. Each names a property of the **host**,
    arriving from provisioning through the Client's `[attributes]` table or as a
    Server label, which moves a host between channels without touching it. An
    Agent no Deployment claims waits; it is the ordinary state of a fresh
    enrolment, not an error. The fleet view tells apart an Agent in no
    Deployment, one whose Deployment holds nothing it can take (no Package for
    its type or its Platform), one with something waiting, and one in conflict,
    because the next move differs.

26. **An Agent belongs to at most one Deployment; any overlap is a conflict.**
    Not the most specific, not the newest — none. The Agent's `package_conflict`
    names every Deployment that claims it, and it is offered nothing new until
    an operator narrows a Selector. There is no specificity rule anywhere.

27. **A conflict takes the candidate away, never a standing assignment.** An
    Agent already rolled out to keeps its offer: nothing distributes or
    un-distributes by itself, and creating an overlapping Deployment must not
    withdraw software from a running host.

28. **The signature lives on the Deployment, per `(Package, Platform)`, and the
    wire is unchanged.**
    `PUT|DELETE /api/v1/deployments/{name}/signatures/{type}/{version}/{os}/{arch}`
    with the hex Ed25519 signature (as `opamp-fleetctl package sign` prints it).
    A signature for a Package the Deployment does not hold is `404`, an empty
    one `400`; removing a Package from a Deployment takes its signatures with
    it. What an Agent receives in `DownloadableFile.signature` is the signature
    held by the Deployment its assignment was released through, not whichever
    claims it now. **The Server never offers a Package to an Agent unless the
    Deployment that releases it carries a signature for that Package's
    artifact** — the entry for the Agent's Platform. An entry without one is no
    candidate; the Agent is offered nothing for it, and the fleet view says the
    signature is missing. The Server reports, per Package, the platforms the
    Deployment holds a signature for. The same Package in two Deployments is
    signed in each.

29. **Rollout acts name a Deployment.**
    `POST /api/v1/deployments/{name}/rollout` releases to every Agent it claims
    and would move ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)
    clauses 9–13), skipping Agents another Deployment also claims, and answers
    `assigned_agents`; a Deployment holding no Package is refused (`409`). **A
    Deployment that lacks a signature for any entry of any Package it holds is
    refused (`409`)**, with a message naming each such Package by its display
    name and the platforms it is unsigned for; nothing is released. The
    per-Agent act takes `{"deployment": "<name>"}` and is refused the same way.
    Both pin as of the press, and an Agent's package assignment is one pair —
    the Deployment it was released through and the Package pinned. A bare
    Package cannot be named in an act: that would bypass the Deployment that
    supplies the signature.

30. **The per-Agent act refuses to pick a side.** Naming a Deployment while a
    second one also claims the Agent is `409`, as is naming one that does not
    claim it. Otherwise the conflict is sidestepped for good, and the per-Agent
    path becomes the way into a state the bulk act forbids.

31. **A Deployment freezes exactly what a standing offer travels with.** Once a
    Deployment has released a Package to at least one Agent, the signatures it
    holds for that Package and its hold on that Package (removing it) are
    refused (`409`). The re-offer gate is the package hash, which does not cover
    the signature: a changed signature would never reach an Agent installing
    against the old one, and a removed one would silently turn a signed rollout
    unsigned for any Agent that has not finished. For the same reason **the
    Deployment itself cannot be deleted while an Agent's assignment names it**
    (`409`): the offer would stand without its signatures. Rolling those Agents
    out through another Deployment, or deleting the Package, ends the offer
    first. Everything else stays editable: the Selector always; adding a Package
    for a type the channel does not hold; and **swapping the version a channel
    holds** — the Agents already released keep their pinned Package, the new
    version shows as waiting, and the next press moves them. That is how a
    rollout proceeds.

32. **A Deployment reports three counts.** `claiming_agents` — Agents it claims
    and no other does; zero is the aim mistake worth hunting. `targeted_agents`
    — of those, the Agents a rollout would move. `conflicting_agents` — Agents
    it matches that another Deployment matches too. The UI shows "⚠ n in
    conflict", the "Roll out (n)" press, "n up to date", or "aims at nobody"
    accordingly.

33. **The bundled UI has a Deployments tab, and the Packages tab has no aim.**
    The Deployments tab is a master table and a detail form, with the per-row
    rollout press beside the counts — never in the form. The Packages tab
    carries no Selector, kind or reach; a Package held by no Deployment reads
    "in no deployment". An Agent in no Deployment is shown calmly.

34. **An absent assignment means nothing was rolled out.** An Agent record
    carrying no assignment fields loads as assigned nothing; the Server never
    invents a rollout at startup. Records are written as envelope version 2, and
    an envelope of another version stops the Server with a message saying to
    clear the agents directory.

### The wording the specification needs

[`docs/SPECIFICATION.md`](../SPECIFICATION.md) outranks every ADR
([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules)), so the wording this decision
needs is raised here, to be accepted or amended together with it:

> - **Package** — a versioned, downloadable software artifact an Agent installs,
>   identified by the **Agent type it is built for and its version**; its
>   display name is derived from the two. It is verified against a content hash
>   and against a signature, and an Agent installs nothing that fails either —
>   the signature travelling with the Deployment that offers it. The Server
>   offers Packages; an Agent reports the status of each.
> - **Selector** — the rule by which the Server addresses a **subset** of the
>   fleet for a Configuration or a Deployment. One mechanism with two subjects.
> - **Deployment** — a named set of Packages, aimed at a subset of the Fleet by
>   a Selector and carrying the signature of each Package's artifact. It is the
>   only thing that is rolled out. An Agent belongs to **at most one**: two
>   Deployments matching one Agent is a conflict, and that Agent is offered
>   nothing new until it is resolved.

**Fleet** stays as it stands — all Agents managed by the Server; that the word
was taken is why this object is called a Deployment.

### The download route and the Gateway's cache

35. **"Currently offered" is the offer's own test, shared.** An artifact
    `(agent_type, version, os, arch)` is offered to an Agent when all of the
    following hold:
    - the Agent declares `AcceptsPackages`;
    - it holds a package assignment naming that Package;
    - the Agent type equals the `service.name` it reports;
    - the Platform it reports, canonicalised, is the requested one, and the
      Package holds an uploaded entry for it;
    - the Deployment named in the assignment holds a signature for that entry.

    The offer and the download decide this from the same parts in `packages.rs`:
    one test of the Agent type and the Platform (`fits`), the assignment, and
    the signing Deployment. The download resolves the entry and its signers once
    before it takes the fleet lock, so each record costs no store lookup. A test
    that runs every combination through both keeps them from disagreeing. Adding
    the type test closes the gap against clause 9 in the same change.

36. **An offer stands until the assignment changes, not until it was last
    sent.** The hash gate suppresses re-sending an offer whose
    `all_packages_hash` the Agent has echoed
    ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 3). It does
    not withdraw the offer, so an Agent retrying after a failed install can
    fetch again. Neither connection state nor the version test
    ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 17) enters the
    test. Matching does not enter it either: a version that waits for an
    operator's press is no one's offer, and it cannot be fetched until the press
    releases it.

37. **What a certificate speaks for.** The host a member certificate names
    (`urn:opamp-fleet:host:<id>`,
    [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 7) speaks for the `instance_uid`s bound to it in the host register. A
    host marked as a Gateway speaks for any Agent: the register binds no
    `instance_uid` to it, and the Server keeps no record of which Agents a
    Gateway carries. A Gateway's certificate therefore may fetch what is offered
    to any Agent. A certificate that names no host speaks for no Agent and
    fetches nothing. A Client whose Server signs CSRs holds a host certificate
    after its first connection
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 9). An operator who provisions certificates by hand names the host
    with that SAN URI. A Server started without `[client_ca]` logs one notice at
    startup: uploaded artifacts reach only hosts whose certificate names a host
    (`urn:opamp-fleet:host:<id>`). A request that presents no certificate at all
    exists only behind `Admission::open`, which serves tests and loopback
    development and which no Server configuration serves
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 6). Such a request is not tested for an offer, just as it is not
    tested at admission.

38. **Every other request for an artifact is answered `404`, as for one that
    does not exist.** The status, the body and the headers are the same whether
    the store holds no such artifact, holds only a referenced entry for it, or
    holds an artifact that is not offered to any Agent this host speaks for. The
    Server decides this before it opens a file. Two answers are unchanged:
    - a malformed identity or Platform token is still `400`, which concerns
      syntax and reveals nothing about the store;
    - admission refusals (no member certificate, a bootstrap certificate, a
      revoked certificate) are still `401`
      ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
      clause 23).

39. **The handler decides, after it has parsed the request.** `download_package`
    parses the identity (`PackageId::new`) and the Platform (`query.platform()`)
    as it does now, so one parser decides which artifact is meant and a
    malformed token is answered `400` before any offer is tested. It then reads
    the host from the presented certificate: from the `PeerCertificate`
    extension through `ca::facts`, or from the `Proofs` the guard puts into the
    request. It asks the fleet `Fleet::offers_artifact(host, id, platform)`,
    which reads the host register (`Revocations::speaks_for`) and the Agent
    records under the fleet lock. Only after that does it look for the file.
    `admit_download` keeps only admission
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 23) and records `download.admitted` as now. A request that fails the
    offered test is also recorded as `download.refused`, outcome `refused`, with
    check `not offered`, the host, the certificate's serial and the requested
    type, version and Platform. That entry goes through the refusal aggregation
    of [ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md) clause 5.
    It does not count toward the admission throttle
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 24): the handshake succeeded, so the refusal is not a guess at a
    credential, and counting it would throttle every member behind the same
    address.

40. **Each download request is counted against the requesting host's rate.** It
    costs one token from that host's bucket of
    [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md).
    A download names no `instance_uid`, so for a host marked as a Gateway the
    token comes from the Gateway's aggregate bucket
    ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
    clause 22). That bucket bounds how often a Gateway's request can scan the
    fleet's records under the fleet lock.

41. **Configurations: no change.** An Agent already receives only its own
    composed map, over OpAMP, from what was released to it (Context). This
    decision states that bound for the record and adds nothing to it.

42. **A Gateway fetches an uploaded artifact once, when it relays its offer.**
    When the Gateway relays a `ServerToAgent` whose `packages_available` names a
    file on the Server's download route (clause 43) to an Agent, and records
    that offer (clause 45), it starts fetching each such artifact that it
    neither holds nor is fetching, before any downstream peer asks for it. An
    offer it does not record starts no fetch. The fetch is single-flight per
    artifact. The Gateway resolves the path against its own endpoint and fetches
    from its Server's origin with its own client certificate and no offered
    headers, by the rules every Client's download follows (clause 53). Clause 37
    lets a marked Gateway fetch what is offered to any Agent, and each request
    costs one token of its aggregate bucket (clause 40). The message itself is
    forwarded unchanged and without waiting for the fetch
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
    At most four fetches run at a time; further ones wait for a free slot. A
    `429` or `503` from the Server with `Retry-After` defers the fetch within
    the bound of clause 49, and a deferred fetch gives its slot back while it
    waits and takes one again before it asks anew. Once its first 60 seconds
    have passed, a fetch is cut at the first chunk that finds it below an
    average of 64 KiB/s since then; the read timeout of clause 53 still cuts a
    silent one. A Gateway that shuts down ends its fetches, waiting or not. Any
    other failure — the Server's refusal (an unmarked Gateway is answered `404`,
    clause 38), a network error, a cut, bytes that do not match the hash — is
    logged and remembered for that artifact. It is fetched again only when it
    newly appears in an Agent's offer, that is, in a relayed offer to an
    `instance_uid` whose previous recorded offer did not name it.

43. **Only an artifact the Server hosts is cached.** An offered file is the
    Server's when its `download_url` is a path, beginning `/api/v1/packages/`
    and naming the route's `/file`, which the Server sends while
    `advertised_url` is unset and which a downstream Client resolves against its
    own endpoint, the Gateway. An absolute `download_url` is neither fetched nor
    served by the Gateway. For a referenced artifact's source the downstream
    Client fetches it as it would without a Gateway (clause 53). With
    `advertised_url` set, the Server's route is offered as an absolute URL
    naming the Server, and an uploaded artifact is not delivered behind a
    Gateway at all: the downstream Client's own origin is the Gateway, so
    `Sources::permit` refuses the Server's URL unless
    `[packages] allowed_sources` lists it, and if it is listed the Client
    presents no certificate there and the Server's handshake refuses it
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 23).

44. **The Gateway stores and serves only bytes that match the offer's hash.** An
    artifact is the offered path, query included, together with the offer's
    `content_hash`. The fetch streams the body to a staging file in the cache
    directory and hashes it on the way; peak memory is one chunk. The file is
    renamed into place only when its SHA-256 equals the offered `content_hash`;
    otherwise it is deleted, the mismatch is logged, and nothing is served. The
    Gateway does not check the signature. The downstream Client checks hash and
    signature itself before it installs (clause 54), so the cache cannot make an
    Agent install anything the Agent would not install from the Server.

45. **Downstream, a host receives only what the Gateway relayed to its own
    Agents.** The Gateway serves
    `GET /api/v1/packages/{agent_type}/{version}/file` on its downstream
    listener, behind the handshake and the revocation verdict of its
    `/v1/opamp`: a certificate from `client_ca_file` is required, a revoked one
    is answered `401` and every request is answered `503` while the Gateway
    holds no current list
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
    clauses 11, 14).
    - **Binding.** An `instance_uid` is bound to the host
      (`urn:opamp-fleet:host:<id>`) of the certificate of the first downstream
      connection that reports for it since the Gateway started, as the Server
      binds an `instance_uid` to the host that first reports it
      ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
      clause 7). A report over a certificate that names no host binds nothing. A
      host holds at most `max_carried_agents` bindings
      ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
      clause 4); past that its report for a new `instance_uid` binds nothing,
      and that is logged. The Gateway holds at most 1 000 000 bindings in all;
      past that a new binding takes the place of the least recently reported
      binding whose `instance_uid` has neither a downstream route nor a current
      offer, and when there is none, it binds nothing, and that is logged. Each
      report refreshes when its binding was last reported.
    - **Offers.** An offer relayed to an `instance_uid` is recorded only when
      the downstream connection it is relayed over presents a certificate of the
      host the `instance_uid` is bound to; any other is not recorded, and that
      is logged. An Agent's current offer is the files of the last recorded
      `packages_available` relayed to it: a later one replaces it, one that
      names no Server-hosted file removes it, a message without
      `packages_available` leaves it standing (clause 36), and a downstream
      disconnect does not end it. The offers held are bounded by the offers the
      Server makes through the Gateway. The bindings and the offers are kept in
      memory only, and the offers are indexed by host.
    - **Requests.** A request is served only when the Gateway holds the artifact
      and a current offer of it (the same path and query, byte for byte) to an
      `instance_uid` bound to the host the request's certificate names. A
      certificate that names no host receives nothing. While an offered artifact
      is being fetched, or waits for a fetch slot, the request is answered `503`
      with `Retry-After: 30` instead of waiting, so a Client's read timeout does
      not run out while the Gateway fetches. An offered artifact that is neither
      held nor being fetched is fetched on a request at most once per relayed
      offer of it — the next relayed offer re-arms it — and that request is
      answered `503` with `Retry-After: 30`. After a failed fetch it is not
      fetched again until clause 42 says so.
    - **Everything else** is answered `404`, with the same status, headers and
      body whether no such offer was recorded, it was recorded for another host,
      the artifact could not be fetched or verified, it is too large for the
      cache, or the request names nothing the route knows.

    The bound on what a host receives is clause 37's, applied to what the Server
    sent through the Gateway. The binding, the `404` for an artifact too large
    or not fetched, and the `503` while a fetch runs are the Gateway's own.
    Together they are the one refusal beyond admission that
    [ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
    clause 11 allows a Gateway.

46. **The Gateway logs what it refuses; it keeps no audit record.** The audit
    record is the Server's
    ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)). A
    downstream request answered `404` because no offer of that artifact was
    recorded for the requesting host is logged at `info` with the host (or that
    the certificate names none), the certificate's serial and the requested path
    without its query. An offer not recorded because its `instance_uid` is bound
    to another host is logged at `warn` with both hosts. Both kinds of line are
    aggregated per host: the first five in a minute are logged one by one, and
    the rest of that minute are counted into one line when the next minute's
    first line for that host arrives. The Server records the Gateway's own
    fetches as it records every download (clause 39).

47. **The cache is bounded, and an artifact that does not fit is refused.**
    `[gateway] package_cache_bytes` bounds the bytes the cache holds, stages and
    is deleting together, default `10737418240` (10 GiB); `0` is refused at
    load. The cache lives in `<state_dir>/gateway-packages`, owner-only on Unix,
    emptied when the Gateway starts. Every stored copy has a file name of its
    own, so deleting an old copy never touches a newer copy of the same
    artifact. Before a fetch stages a byte it reserves the artifact's
    `Content-Length`, or the per-artifact limit when the Server sends none,
    against `package_cache_bytes`. To make room the Gateway first deletes
    artifacts no current offer names, least recently used first, and then
    offered ones, least recently used first. A file being deleted stays counted
    until it is gone, and one whose deletion fails stays counted until a later
    attempt deletes it. A held artifact whose file has disappeared is forgotten.
    A fetch that cannot reserve room because other fetches hold it fails (clause
    42). On a verified rename the reservation becomes the held artifact's size;
    on failure it is released. A fetch is cut, and nothing stored, once its
    `Content-Length` or its body exceeds the smaller of `package_cache_bytes`
    and `max_artifact_size_bytes`; the Gateway logs this once per artifact and
    does not fetch that artifact again while it runs. Such an artifact is not
    streamed through: a downstream request for it is answered `404` (clause 45).
    No file operation runs while the cache's shared state is locked.

48. **Downstream download requests are not counted by the Gateway.** A
    downstream request costs a lookup in memory and a read from the cache
    directory. It reaches the Server only through the fetches of clauses 42 and
    45: one per artifact that newly appears in an Agent's offer and is not held,
    and at most one request-triggered fetch per artifact per relayed offer. Two
    artifacts that do not fit the cache together therefore cannot evict each
    other in a loop driven by requests. Each request to the Server costs a token
    of the Gateway's aggregate bucket (clause 40). As on `/v1/opamp`, the
    Gateway applies no rate of its own.

49. **A Client waits as its own Server origin asks before it reports a download
    failed.** A `429` or `503` with a `Retry-After` in seconds, answered by the
    Client's own Server origin — the Gateway behind one, otherwise the Server,
    whose rate limit answers `429` with `Retry-After: 30`
    ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
    clause 24, whose follow-up this is) and whose admission throttle answers
    `429` with the seconds of back-off left
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
    clause 24) — is waited out and the download sent again. Each wait is the
    `Retry-After`, at least 1 second and at most 60 seconds. The asking stops 30
    minutes after the first request of the download, counting the requests as
    well as the waits: a wait that would end past that point is not begun. Past
    it, or for a `429`/`503` without a `Retry-After` in seconds — an HTTP date,
    none, or an unreadable one — or from any other host, a redirect target off
    the Server's origin included, the download fails as before and is reported
    `InstallFailed` (clause 52). While it waits the status stays `Downloading`.
    The bound is on asking, not on a transfer that has begun, which keeps no
    total timeout (clause 53). A Client that shuts down stops waiting and
    reports nothing for that download.

### Delivery on the Agent

50. **The Supervisor is the updater, and only a Client holding a verification
    key takes packages.** With `[packages] verification_key` set, every
    Supervisor-backed Agent declares `AcceptsPackages` and
    `ReportsPackageStatuses` (every Managed Process is one this Client
    installed,
    [ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
    Without it, no Agent of this Client declares `AcceptsPackages` — neither a
    Supervisor nor the Client's own Agent
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)) —
    and the Client says so at startup, once, naming
    `[packages] verification_key` as what to set. A package offered to such an
    Agent regardless is ignored: nothing is downloaded, and an Agent that
    declared no package capability reports no package status. A verified
    artifact travels to the Supervisor as the Port command
    `ProcessCommand::ApplyPackage { staged, version, hash }`, answered by
    `ProcessEvent::PackageApplied`, beside `ApplyConfig`/`ConfigApplied`. No
    further process is spawned for it.

51. **One top-level package per Agent; anything else is refused and reported.**
    An Agent takes the one top-level package of an offer. An offer carrying only
    addons, or two top-level packages, is refused with a reason in
    `PackageStatuses.error_message` and nothing is downloaded — the Baseline
    lets any Server offer addons, and a Supervisor's only use for a package is
    to _be_ the program, so the filter guards against a non-conforming peer
    writing an addon over the binary. An offer whose per-package hash equals the
    installed one is acknowledged by echoing the aggregate hash; a repeat of the
    hash already in flight is ignored.

52. **Status follows the Baseline lifecycle, and every outcome ends the offer.**
    While the bytes arrive the status is `Downloading` with
    `PackageDownloadDetails` (percent from `Content-Length`, `0` when unknown,
    and bytes per second); otherwise a taken offer is `Installing`, with
    `agent_has_version` still the old one; the Supervisor's answer makes it
    `Installed` or `InstallFailed` with the reason. A failed download or
    verification is `InstallFailed` too. Success _and_ failure echo the offered
    `all_packages_hash`, so the Server stops re-offering the same bytes: a
    refusal is a report, not a loop. The installed package (name, version, hash)
    is persisted in the Agent's state, so a restarted Client reports what it
    runs and is not offered it again.

53. **The download is streamed, bounded, staged inside the Supervisor's own
    directory, and goes only to an allowed source.**
    - `download_url` is used as given when it is absolute `https://`; a path is
      resolved against the Server's own origin — the scheme, host and port of
      the Client's OpAMP endpoint, `wss` mapped to `https` (and `ws` to `http`,
      which the endpoint may only be on the loopback).
    - A source is `https://`. `http://` is accepted only when its host is the IP
      literal `127.0.0.1` or `::1`; a host name is never the loopback,
      `localhost` included. Every download is TLS 1.3, on the Client's TLS
      trust.
    - `[packages] allowed_sources` lists `https://` URL prefixes (`http://` only
      on a loopback IP literal), validated at startup: an entry with another
      scheme, a plaintext entry off the loopback, or an entry carrying
      credentials, a query or a fragment fails startup naming it. A URL matches
      an entry when scheme, host and port are equal and its path begins with the
      entry's path at a `/` boundary. The Server's own origin is always allowed
      and needs no entry; the list defaults to empty, which allows the Server's
      own origin alone.
    - The source is checked before the request is sent: a URL that is not
      allowed is refused without a byte fetched, and reported `InstallFailed`
      naming its origin.
    - The offered package name must be 1–64 characters of letters, digits, `.`,
      `_`, `+`, `-`, checked before anything is resolved or written: the staged
      file is named after it.
    - The artifact is streamed to `<supervisor_dir>/packages/<name>.staged` and
      hashed on the way; peak memory is one chunk. The staging directory is
      owner-only (`0700` on Unix), so no other local user can swap the file
      between verification and install. A failure leaves no partial file.
    - `max_artifact_size_bytes` (top level of `supervisor.toml`, default
      `1073741824`, `0` fails startup) bounds the download: a `Content-Length`
      above it is refused before a byte is written, and a chunked body is cut
      the moment it crosses it.
    - Connect timeout 30 s and read timeout 60 s, never a total timeout — a
      large artifact over a slow link legitimately takes minutes.
    - Redirects are followed up to 5, and every hop is checked against the
      scheme rule and the allow-list before it is requested; a hop outside them
      fails the download, naming the origin it pointed at. The offer's `headers`
      are sent on the `GET` only to an allowed source, and re-sent along a
      redirect only while scheme, host and port stay the ones they were given
      for; an invalid header fails the download naming its key only. Header
      values never reach a log or a debug print, and the logged source URL drops
      its query, fragment and credentials.
    - The Client presents its client certificate only to the Server's own
      origin, whose download route is reached through the Agent plane's TLS
      handshake and stays outside the credential check
      ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md),
      [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
      To any other host, and on a hop that leaves the Server's origin, it
      presents none: an identity belongs to the Server, not to whoever hosts an
      artifact.

54. **Verification decides, and the signature is mandatory.** The SHA-256 of the
    streamed bytes must equal `content_hash`, always. The Ed25519 signature must
    then verify against `[packages] verification_key` (hex-encoded Ed25519
    public key, decoded at startup; a malformed key fails startup), always. An
    offer with no signature is refused before anything is downloaded; an invalid
    signature refuses the artifact. Both checks complete on the staged bytes
    before the artifact is opened, so an unverified archive is never parsed
    beyond its hash and signature. There is no unsigned posture: a Client
    without a key takes no packages (clause 50). The signature covers a
    statement of what the artifact is, not its bytes: `opamp-fleet-package-v1`,
    the Agent type (the offered package's name), the version and the artifact's
    SHA-256 in lowercase hex, one per line, each ended by a newline
    (`fleet_core::package::statement`).
    `opamp-fleetctl package sign --agent-type … --version …` makes it. Since the
    hash is in the statement and checked against the streamed bytes first, the
    signature still covers the artifact exactly as published, archive and all —
    and holds for that type and version alone. Where a Deployment keeps the
    signature is clause 28. The same download and verification serve the
    Client's own update
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).

55. **The Agent opens the artifact; nothing between its author and the host
    repacks it.** The hash an Agent verifies is therefore the SHA-256 the
    artifact was published with — integrity runs in one line from the release
    page to the running program. What an artifact is, is decided by its leading
    bytes, never by a name: `1f 8b` is a `.tar.gz`; `37 7a bc af 27 1c` is a
    `.7z`; `PK\x03\x04` or `PK\x05\x06` is a `.zip`; anything else is the
    program itself. These three containers are the whole set the Client opens,
    for every kind and for its own update alike. A `.deb`, `.rpm` or `.msi` is
    not opened.

56. **A `.7z` may be encrypted, and the key lives only on the Agent.**
    `[packages] archive_key` opens an encrypted `.7z` (AES-256); the Server
    never learns it, so a confidential artifact is readable only on the host
    that runs it. It is one secret for the fleet — a single archive serves every
    Agent — and must never be the `[auth]` credential, which the Server rotates
    on its own
    ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md))
    and would leave every archive unopenable. It is masked in the configuration
    the Client reports. An encrypted archive without the key, or with the wrong
    one, fails naming the key. A `.zip` is never encrypted: an encrypted zip
    member refuses the archive and names `.7z` as the way.

57. **A single-file package installs one member, to a place the Client chose.**
    Without `program_path`, the artifact is the program or an archive holding
    it: the member whose _file name_ equals the configured program's is
    extracted, wherever the archive keeps it, and nothing else. The archive
    never chooses a path, so a member named `../../etc/cron.d/x` lands where the
    Client put it like any other. A missing member fails, naming up to eight
    members the archive does hold. Output is bounded at 2 GiB, and the
    decompression needed to _reach_ the member is bounded by the same budget
    from the declared sizes before anything inflates, so a bomb ahead of the
    target is refused rather than skipped through.

58. **A `[[supervisor]]` block's `program_path` makes the package a directory
    tree.** It is a relative path _inside_ the package, e.g. `bin/fluent-bit`;
    absent, the package is one file. It is validated at startup — non-empty,
    relative, no `.` or `..` — and it says _where inside_, never _whether_: the
    program's bare file name stays the consent
    ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
    Being written in the configuration, the spawn path
    `program/tree/<program_path>` is known before any package exists.
    - `program_path` matches a member by its **trailing path components**, so
      `bin/fluent-bit` finds `fluent-bit-3.1.0/bin/fluent-bit` and stays right
      at the next release. No match fails naming what the archive holds; several
      matches fail naming them, answered by writing more of the path.
    - The directory prefix above the match is stripped, and every member below
      it is extracted keeping its relative path. Members outside that prefix are
      not unpacked; they are counted in the install line and named at `debug`.
    - A bare program delivered to a tree Supervisor is placed at `program_path`.

59. **A tree's paths are sanitized and its size is bounded, or nothing is
    written.** Every member is checked before the first byte lands. An absolute
    path, a root or drive prefix, a `..` component, a symbolic or hard link, or
    a 7z anti-item refuses the **whole** archive — a partially unpacked agent is
    worse than none. Extraction is bounded at 2 GiB across all members and at 10
    000 members, from declared sizes before decompression and again on what is
    written.

60. **Modes come from a `.tar.gz` on Unix; the program is always made
    executable.** A tar's member modes are applied. A `.7z` or `.zip` carries
    Windows attributes, so no mode is taken from it. The program — the single
    file or the member at `program_path` — is set `0755` regardless, so whether
    it can run never depends on how the archive was built; an agent with further
    executables beside its program ships as `.tar.gz`.

61. **The swap is a rename, and the apply grace gates it.** On disk, per
    Supervisor:

    | Package     | Live             | Predecessor               | Staged                  |
    | ----------- | ---------------- | ------------------------- | ----------------------- |
    | single file | `program/<file>` | `program/<file>.rollback` | `program/<file>.staged` |
    | tree        | `program/tree/`  | `program/tree.rollback/`  | `program/.staging/`     |

    The artifact is unpacked to the staged name first, beside what runs; a raw
    artifact is moved there rather than copied when it can be. A kind that
    declares a preflight proves the staged program runs before anything is
    stopped
    ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
    clause 57). Then the Managed Process is stopped, the live name renamed to
    the predecessor, the staged name renamed to the live one — so the live name
    is always the old package or the new one, never a mixture — and the process
    is spawned and must survive `apply_grace_secs`
    ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
    Surviving is `Installed`, after which the program is asked for its version
    again. A spawn failing with `ETXTBSY` right after the swap is retried
    briefly rather than rolled back. When there is nothing to run yet (no
    Configuration), the package is installed and reported `Installed`; the
    configuration that arrives starts it.

62. **A failed apply rolls back only to a predecessor.** If the process does not
    start or exits within the grace and a predecessor exists, the predecessor is
    renamed back over the live name and respawned. If there is none — a first
    install — nothing is rolled back: the verified program stays in place and is
    reported `InstallFailed`. A failure never empties `program/`, so the
    "installed ≠ offered, re-offer, re-download" loop cannot start.

63. **A program that keeps failing to start is held, not looped.** A start
    counts as failed when the apply fails its grace, or the process exits before
    it has run `max(apply_grace, 10 s)`. After **three** failed starts in a row
    the Supervisor stops restarting, reports the Agent unhealthy
    (`not restarting: the program keeps failing to start`) and waits. A new
    Configuration, a new package or a restart command is a fresh chance and
    resets the count; a run that outlasted the floor resets it too. This holds
    for a failed package, a rolled-back predecessor that will not start either,
    and a Configuration alike. Three is the self-update's give-up
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)), so
    the two update paths behave alike.

64. **The superseded version is kept for a window, then deleted.** After a
    successful apply the predecessor stays, and a marker beside it
    (`<predecessor>.until`, Unix seconds) records `now + retain_previous_secs`.
    A sweep at startup and every 10 minutes deletes a predecessor past its
    deadline; a marker that will not parse counts as expired, and a predecessor
    without a marker is left alone. `[updates] retain_previous_secs` sets the
    window (default `86400`, one day); a `[[supervisor]]` block's
    `retain_previous_secs` overrides it for that Supervisor; negative values
    fail startup; `0` deletes the predecessor on success. A Supervisor keeps at
    most one predecessor: the next update replaces it and its marker. The marker
    lives in the Supervisor's directory, so the deadline survives a Client
    restart.

65. **A Supervisor takes its own type, and never goes back.** An offered package
    whose name is not the Supervisor's Agent type is refused before anything is
    downloaded, and so is one whose version precedes the installed one by
    Semantic Versioning's precedence. Versions that do not compare are not
    refused on that ground; the signature still binds them. The Client's own
    update keeps its own rules
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).

66. **The Client opens `.zip` as a third container beside `.tar.gz` and `.7z`.**
    It is detected by its leading bytes (clause 55), held to exactly the member
    and tree rules of clauses 57 to 59, read-only, and unencrypted (clause 56: a
    confidential artifact is a `.7z`). Like a `.7z` it carries no Unix modes
    (clause 60), which costs a Windows tree nothing. It is read through the
    [`zip`](https://crates.io/crates/zip) crate with `default-features = false`
    and `deflate` only, so decompression runs on the `flate2`/`miniz_oxide`
    chain the Client already carries and the build stays pure Rust. An upstream
    that publishes its Windows build as a zip therefore has it travel byte for
    byte: the hash an Agent verifies is upstream's own, and the artifact may
    even be a referenced package pointing at the release asset.

67. **Every repack `opamp-fleetctl package fetch` makes is deterministic.**
    Where an upstream publishes no artifact a Client can run as published, the
    tool repacks it on the operator's host, before it is signed, into a
    `.tar.gz` that keeps file modes. The repack has a fixed member order and
    zeroed times and ownership, and it carries no link: every link is
    dereferenced — a linked directory is packed under the linked name too, with
    its contents — a link that names nothing is dropped, and a link leading back
    up the tree is not followed. The member cap of clause 59 is checked while
    packing. Repacking the same release therefore yields the same bytes and the
    same hash, and no accidental rollout.

**Out of scope:** which package reaches which Agent and when
([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)); verifying upstream
sigstore/cosign signatures; a retention policy for superseded Packages;
Deployments carrying Configurations; inequality in Selectors; refusing an
overlapping Selector at write time; whether `[self_update] package` should be
renamed, since its value is an Agent type; addons, and installing them, until a
Client can install one; who can fetch an artifact hosted elsewhere — a
referenced entry (`source`) is fetched from the operator's host under
`[packages] allowed_sources`, with whatever headers the offer carries (clauses 4
and 53), the Server is not in that download path, who can fetch from that host
is decided there, and a Gateway does not cache such an artifact (clause 43); a
bound finer than the host
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 14); roles, permissions and tenancy on the Operator plane; keeping the
Gateway's cache and the offers it serves across a restart of the Gateway, and
the Gateway's own Supervisors fetching through the cache; resuming an
interrupted download with range requests; distributing the archive key, the
verification key or the allow-list; keeping more than one predecessor; scoping
an offered header to a path below an allowed origin; a reproducible tree mode
for `opamp-fleetctl package pack`.

## Alternatives considered

- **Leave the platform or the type to the operator's aim.**
  `os.type`/`host.arch`/`service.name` pairs already filter at zero cost.
  Rejected: opt-in, and forgetting it installs a foreign binary on every host of
  every other platform or type. A rule that is only right when remembered is not
  the rule this needs.
- **An optional Platform meaning "every platform".** The backward-compatible
  reading of a filter; rejected because it makes the guarantee a property of how
  carefully something was uploaded rather than of the Server.
- **Platform as metadata on separate package names** (`otelcol-linux-amd64`).
  Smaller, but five artifacts then need five names and every host a matching
  name in its own configuration — the per-host wiring this store exists to
  remove, at the one place where the blast radius is the Client itself.
- **A version per platform entry.** Allows a per-platform rollout of different
  versions under one object, and is indistinguishable from a half-finished
  upload. Two packages express that case explicitly.
- **Encode the platform in the version** (`3.0.0+linux-amd64`). Needs no schema,
  and contradicts [ADR-0012](0012-versions-resolved-in-the-internal-crate.md):
  build metadata is provenance and is not compared.
- **Canonicalise onto what Rust reports** (`x86_64`, `aarch64`). The smaller
  change; rejected because it makes this project's canonical spelling one that
  neither the conventions, nor the Collector, nor the release artifact uses — a
  private vocabulary maintained by a table, forever.
- **Reject unknown `os`/`arch` tokens against a closed list.** Catches a typo,
  and refuses to serve any platform the list forgot. The canonical pair in the
  response covers the typo far cheaper.
- **Canonicalise or pattern-match Agent types.** There is no authority to
  canonicalise against; a table would encode this project's opinion of every
  distribution, and a pattern is a matching language that outlives its
  convenience.
- **Default the type to a name**, so no extra input is needed. Right most of the
  time and silently wrong for every name chosen for a rollout rather than a
  target.
- **Remember one previous version per package and roll back by swapping.**
  Bounded disk, one button — but hidden, one step deep, and a second history
  beside the store. Keeping every version as its own package makes the history
  the store itself.
- **Import a URL: have the Server download it and serve the bytes.** Better in a
  fleet whose hosts cannot reach the internet — and that is exactly what
  uploading is. As the behaviour of a URL it makes the Server hold and expose
  artifacts it has no need to hold.
- **Derive the checksum by fetching once, or verify the reference by downloading
  at set time.** Records what the Server happened to receive, from where it
  stands — trust on first use with no anchor, and for a reference not even what
  the Agents get.
- **Plaintext referenced urls to LAN mirrors.** An HTTP file share on the
  operator's network is the cheapest mirror, and the `sha256` (and a signature
  where the Agent holds a key) already protects what an Agent installs.
  Rejected: a hash or a signature protects integrity, not confidentiality — the
  artifact and, worse, the download credential in `headers` would cross the
  network readable to anyone on it, and the specification accepts plaintext on
  the loopback alone.
- **An opaque identifier instead of readable tokens.** Robust against any
  character, meaningless in a URL, a file name and the UI; a bounded token
  grammar buys the same safety.
- **Keep a name as an optional field defaulting to the Agent type.** Smallest
  change; the room it leaves is the problem — the degree of freedom that needed
  a ranking.
- **Identity `(name, version)` with the type as an attribute.** The type decides
  fit, and an attribute is editable; retyping stored bytes to another kind of
  Agent is what immutable identity forecloses.
- **Keep the addon kind, and its byte in the hash, against a future need.** No
  Client installs an addon and no artifact here is one; with nothing deployed
  the byte buys no stability and leaves an unexplained constant in a hash
  function.
- **Keep specificity and move it to the Deployment.** Preserves the
  fleet-wide-plus-canary shape and the unreadable computation with it; the
  requirement is a partition.
- **An empty Selector as a catch-all that loses to every other.** A ranking one
  level deep, makes forgetting a field the way to target the whole fleet, and
  overlaps everything by construction.
- **Inequality in Selectors (`key != value`).** Most expressive; the operator
  keeps exclusions in sync by hand, overlap stops being visible by eye, and it
  changes the Selector for Configurations too. Named as a follow-up if the
  partition proves too rigid.
- **Naming a Deployment in the per-Agent act resolves the conflict.** Makes the
  conflict permanently liveable; a rule that can be waived per Agent is not a
  partition.
- **Deployments carry Configurations too.** The tidier end state, and a second
  lifecycle with its own revision model; deferred.
- **Signatures stay on the artifact, and the Deployment names only the required
  key.** No re-signing when a Package moves, but it puts an attribute back on
  the emptied object and the release decision back on the bytes.
- **The Server accepts unsigned Deployments.** An unsigned fleet as a legitimate
  policy, reported rather than refused; it is the convenience the specification
  ranks below security, and it rolls out software the Agent would install with
  nothing proving who released it.
- **Keep a reader for older store and record shapes.** A migration with no
  source is untestable in the only way that matters and untrue as documentation.
- **Leave the route open to every member.** This is the status quo. Membership
  becomes a key to every build the store holds, including builds released to
  another partition and builds released to no one yet. It also lets a
  compromised host list the store. The cost of closing it is one lookup per
  download.
- **Answer `403` for an artifact that exists but is not offered.** This is the
  more literal status code, but it tells a host which type, version and Platform
  the store holds, which is the enumeration this decision closes. RFC 9110
  explicitly allows `404` for this purpose.
- **Bind the fetch to an Agent instead of the host**, by naming an
  `instance_uid` in the `download_url` or in a header. The `instance_uid` is
  self-asserted, and the only thing the Server can check against is the host
  binding. The result is the same bound with an extra request parameter that the
  Baseline's `DownloadableFile` does not need.
- **Signed, expiring download URLs**, like pre-signed object-store links.
  Whoever holds the URL can fetch, and the URL ends up in logs. The Server would
  need a signing key and its rotation. An expiry would also conflict with a
  retry after a failed install, which re-reads an offer the hash gate no longer
  re-sends. The handshake already identifies the host.
- **Allow whatever is a candidate for the host's Agents** (what matching would
  release now). This would let a host fetch a build the operator saved but did
  not release. That breaks the rule that a release happens only by an operator's
  act ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 1).
- **Limit a Gateway to the Agents currently carried on its connections.** The
  Server would have to track which connection or host carries each Agent, which
  it does not do today: the register binds nothing to a Gateway, and `owner` is
  a WebSocket connection id. That tracking would buy nothing, because a
  Gateway's certificate may report under any `instance_uid`
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 14) and so can receive any Agent's offer over OpAMP anyway.
- **Treat a certificate that names no host as membership alone**, able to fetch
  anything offered. This would keep downloads unchanged for hand-provisioned
  certificates without the SAN URI. But it removes the bound for exactly the
  certificates the register cannot track.
- **Bind certificates that name no host by their issuer and serial**, as
  [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  keys its buckets, so that a hand-provisioned certificate speaks for the Agents
  that reported with it. This would keep G-10 working without changes for a
  fleet whose Server signs no CSRs. It was not chosen. It means a second binding
  register next to the host register, and its entries would have to be carried
  across certificate replacements that the Server never sees, because without
  `[client_ca]` the Server does not issue the next certificate. The bound would
  also lapse whenever an operator replaces a certificate by hand. The G-10 cost
  of declining it falls on such fleets: they deliver uploaded artifacts only
  after their certificates name a host, and referenced artifacts are unaffected.
- **Check the offer in the `admit_download` middleware.** The middleware would
  have to parse the path and query a second time, and could answer "not offered"
  for a request the handler would have answered `400`. Two parsers could
  disagree on which artifact is meant.
- **Count `not offered` refusals toward the admission throttle.** That throttle
  counts a peer address, so one misbehaving host would throttle every member
  behind a shared address. The record already holds the refusals, aggregated.
- **Relay the download route through the Gateway, request by request.** The
  Gateway would fetch with its own certificate for every downstream request, so
  the bytes would cross the Gateway's link once per Agent, and every request
  would cost a token of its aggregate bucket (Context). It would also need the
  same downstream bound as the cache, because the Gateway's certificate fetches
  what is offered to any Agent.
- **Fetch on the first downstream request instead of when the offer is
  relayed.** Simpler by one trigger, but the artifact would only start to cross
  the link once an Agent asks, and every Agent behind the Gateway would be
  answered `503` for the whole transfer. Fetching when the offer passes starts
  the transfer as early as the Gateway can know it is needed.
- **Let a downstream request wait for the fetch instead of answering `503`.**
  The Client's read timeout of 60 seconds also bounds the wait for the
  response's headers. A fetch over a slow link outlasts it, the Client reports
  the download failed and echoes the offer's hash, and the Server does not offer
  it again (clause 52). A `503` with `Retry-After` keeps the Client asking
  within the bound of clause 49.
- **Bind an `instance_uid` on the first offer the Gateway relays for it.** A
  host that reports another host's `instance_uid` between that host's report and
  the Server's reply would be bound instead. The first report is what the Server
  binds on as well.
- **Rewrite the offer's `download_url` to name the Gateway.** That would make an
  absolute URL cacheable too, but the Gateway forwards messages unchanged
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)),
  and a Gateway that edits what the Server offers is one more place an offer can
  be made to say something the Server did not.
- **Serve whatever the Gateway holds to any admitted downstream peer.**
  Admission behind a Gateway is fleet membership, as at the Server. Any member
  behind the Gateway could fetch another partition's build once one Agent behind
  the same Gateway was offered it, which clause 37 closes at the Server.
- **Bind a downstream fetch to the connection that carries the Agent instead of
  its host.** A plain-HTTP Client opens a new exchange for every report, a
  WebSocket Client reconnects, and an Agent retrying a failed install may do so
  on a later connection (clause 36). The host is the bound the Server applies,
  and the one the certificate states.
- **Stream an artifact too large for the cache through without storing it.** The
  Gateway would pass on bytes before their hash is checked, and every downstream
  request for that artifact would become an upstream fetch, which the cache
  exists to prevent. An operator who rolls out such an artifact behind a Gateway
  raises `package_cache_bytes`; the refusal is logged.
- **Count downstream download requests in a bucket per downstream host.** It
  would add a rate the Gateway does not apply on `/v1/opamp` either
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
  clause 11). A downstream request reaches the Server at most as the one shared
  fetch, so the Server's bucket for the Gateway already bounds what downstream
  requests cost upstream.
- **Cache referenced artifacts as well.** The Gateway would need the offered
  headers, which are an operator's credential for one host, and would present
  them from a second host; the Client presents them only to the source they were
  given for (clause 53). A referenced source is the operator's own download
  server and can be placed near the Agents.
- **Keep the cache and its offers on disk across a restart.** It saves one fetch
  per artifact after a restart, but a persisted offer outlives what the Server
  last said, and the bound of clause 45 would have to be trusted across a
  process the Gateway does not control. An emptied directory and offers in
  memory need no reconciliation.
- **A Client-side downgrade refusal alone, the signature left over the bytes** —
  keeps every existing signature valid, but a signed artifact of one type stays
  installable as another's program.
- **The type and version in a detached manifest, signed beside the artifact** —
  a second file to carry and keep in step; the statement is a few dozen bytes
  the Client builds from what the offer already says.
- **A separate Updater process for Managed-Process packages**, symmetric with
  the Client's own update. The Supervisor already is a distinct process that
  owns stop, swap, spawn and health gate; another process would buy nothing.
- **Content hash only, signatures later.** Authenticity is what verifying a
  binary means, and retrofitting it onto an install path is the costly change;
  Ed25519 through the `ring` already present costs little.
- **Unsigned operation as a posture of the operator's**, accepted on the content
  hash with a warning at startup. The hash arrives in the same offer as the URL,
  so whoever can make the offer — a compromised Server, a stolen operator login
  — chooses both and runs code on every host it reaches. The specification
  installs software only when it is signed with a key the operator holds, and a
  warning is the convenience it puts second.
- **Refuse startup without a verification key.** A Client that only applies
  configurations would have to hold a key it never uses. Not declaring
  `AcceptsPackages` installs nothing unsigned just as surely, and says so at
  startup.
- **An open download policy: any `https://` source, the hash and signature
  deciding.** Verification protects the host, not what a download presents: the
  offered headers and, toward the Server, the client certificate would go
  wherever an offer or a redirect points, and the Client would fetch from any
  host its network reaches on a Server's word. An allow-list bounds both at the
  cost of a list the operator keeps.
- **Allow-list hosts instead of URL prefixes.** One origin often serves several
  tenants or projects (a release host, an artifact repository); a prefix
  confines the Client to the operator's part of it. A raw string prefix is not
  used either: `https://mirror.example` would match
  `https://mirror.example.attacker.net`, so a match compares the origin exactly
  and the path at a segment boundary.
- **Check only the first URL, not every redirect hop.** A mirror on the list
  could then send the download, and the headers re-attached on its own origin,
  anywhere.
- **Present the client certificate to every source.** It would hand the Client's
  fleet identity to a mirror that has no use for it, and to every host a
  redirect reaches.
- **Unpack on the Server and store a bare binary.** One extraction instead of
  hundreds, no unpacking code on hosts. Rejected: the Server would re-hash its
  own output, so every Agent would verify a number the Server invented instead
  of the one upstream published, and an encrypted artifact would have to be
  decrypted on the Server — key and plaintext on the very machine the encryption
  keeps them from.
- **Support only `.7z`** (one code path, carries a password). Upstream publishes
  no `.7z`, so no release could be used without repacking by hand. **Only
  `.tar.gz` with some outer encryption** — a format someone would have to
  invent, where AES-256 `.7z` is understood by every tool.
- **Repack an upstream zip into `.tar.gz` or `.7z`** and teach the Client
  nothing. Rejected: the fleet would verify a hash the packing host invented
  instead of upstream's, and the referenced-package route would close; one
  read-only container under the existing member rules is cheaper.
- **The archive key in `server.toml`, distributed over OpAMP, or carried as a
  Configuration.** Each puts the key where the Server — whose download route
  anyone who can reach it may call — can open every artifact; as a Configuration
  it would also be echoed back as effective configuration and shown in the fleet
  view.
- **Addon packages for an agent's supplementary files.** Nothing groups a set of
  packages, so there is no consistent version, no ordering and no atomicity: an
  Agent could sit with a new executable and old shared objects.
- **A `strip_components` key, or stripping a lone top directory automatically.**
  The first is one more number to get right by inspecting an artifact; the
  second flattens an archive whose top level is meaningful and changes behaviour
  with the archive's contents. Suffix matching needs nothing written and fails
  loudly when ambiguous.
- **Find the program by searching the unpacked tree.** It removes "what will
  this host run" from the configuration: before the first package there is
  nothing to search.
- **A self-extracting single file.** Re-extracts on every update, hides what is
  installed, makes the reported version the wrapper's, and turns rollback into
  hope.
- **Unpack over the live `program/` in place.** A failed unpack halfway leaves a
  tree that is neither version and destroys the predecessor the health gate
  rolls back to.
- **A version-named directory and a `current` pointer** for trees. A directory
  rename is atomic on every platform the Client runs on; a pointer is a symlink
  on Unix and a junction on Windows — machinery that would run on every package.
  Two fixed names are the single-file swap one level up; the version is read
  from the Agent's report, not from disk.
- **Keep every superseded version.** An unbounded version store on hosts chosen
  for their disk budget; a rollback needs one predecessor.
- **Give up after one failed start.** A transient failure — a briefly held port
  — would strand a rollout; three matches the self-update.
- **Retention on the downloaded artifact instead of the installed predecessor.**
  A rollback restores the installed program, not the download; tying retention
  to the staged file would delete what a fallback needs.

## Sources / Prior art

- [OpAMP specification § Packages (`v0.19.0`)](https://github.com/open-telemetry/opamp-spec/blob/v0.19.0/specification.md),
  also
  [§ Packages, Downloadable Packages, Code Signing](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md#packages)
  — the hash-gated sync and the status lifecycle; `PackagesAvailable` is "the
  packages that are available on the Server **for this Agent**", maps a name to
  one version and hash _for this Agent_, carries `signature` per downloadable
  file, and expects "normally only one top-level package"; the Download Server
  "may be on the same host as the OpAMP Server or a different host"; one
  downloadable file per package, multiple files to be carried "in any file
  format that allows storing multiple files in a single file"; and what a
  package contains "is Agent type-specific and is outside the concerns of the
  OpAMP protocol".
- [OpAMP specification v0.20.0](https://github.com/open-telemetry/opamp-spec/blob/v0.20.0/specification.md),
  section _Packages_: "The PackagesAvailable message describes the packages that
  are available on the Server for this Agent". Its URLs "point to package files
  on a Download Server (which may be on the same host as the OpAMP Server or a
  different host)". Section _Downloading Packages_, step 3: the Agent uses "an
  HTTP GET message" with the offered headers. Section _Packages / Security
  Considerations_ and section _Security_ say nothing about which Agent may fetch
  which file. This decision fills that gap on the Server and changes nothing on
  the wire.
- The vendored schema `crates/opamp/proto/v0.20.0/opamp/v1/opamp.proto`:
  `PackagesAvailable` is the "List of packages that the Server offers to the
  Agent"; `DownloadableFile.download_url`.
- The Baseline's `AgentDescription` — "keys/values are according to
  OpenTelemetry semantic conventions", `os.type` SHOULD be included,
  `service.name` "uniquely identifies the Agent type".
- [OpenTelemetry semantic conventions — `host.arch`](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/host.md)
  and
  [`os.type`](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/os.md)
  — the canonical token sets adopted in clause 7.
- [`opampextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/opampextension/opamp_agent.go)
  — reports `os.type` from `runtime.GOOS` and `host.arch` from `runtime.GOARCH`.
- [OCI Image Index](https://github.com/opencontainers/image-spec/blob/main/image-index.md)
  — one reference resolves to a list of manifests, each with a required
  `platform` object, values from Go's `GOOS`/`GOARCH`; pushed digests are
  immutable.
- [Debian repository format](https://wiki.debian.org/DebianRepository/Format)
  and [RPM repositories](https://rpm-software-management.github.io/) — a
  released package is `(name, version, architecture)` with per-file checksums.
  With the OCI Image Index: the name _is_ what the software is; nothing carries
  a second identity beside it.
- [`opentelemetry-collector-releases` v0.157.0](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.157.0)
  — archives only, never a bare binary; `checksums.txt` with a SHA-256 per
  asset; sigstore keyless `.sig`/`.pem` companions.
- [Bindplane — Bring Your Own Collector](https://docs.bindplane.com/feature-guides/deployment-and-management/bring-your-own-collector)
  — the Agent type as a first-class object reported by the collector, not a
  free-form tag.
- [`opamp-go`](https://github.com/open-telemetry/opamp-go) — its example Server
  offers no packages, so there is no upstream behaviour to copy for where
  artifacts come from or whom they reach; its `PackagesSyncer` is the reference
  download-verify-report component.
- [Collector Supervisor specification](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/specification/README.md)
  — signs the package hash server-side and verifies before applying.
- [WSUS update approval](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/3-approve-and-deploy-updates-in-wsus)
  — approval binds a concrete update to a **computer group**: membership, never
  exclusion.
- [Jamf Pro patch policies](https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Patch_Policies)
  — one version bound to a scope built from groups.
- [Bindplane rollouts](https://docs.bindplane.com/feature-guides/deployment-and-management/rollouts)
  — deployment starts on an explicit act and names a pinned version.
- [Argo CD manual sync](https://argo-cd.readthedocs.io/en/stable/user-guide/auto_sync/)
  — drift displayed, nothing applied until Sync; the waiting view extended to
  "in no Deployment".
- [Kubernetes label selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
  — set-based selectors have `NotIn` and `DoesNotExist`, and grouping still
  leans on membership labels.
- [RFC 9110 §15.5.4](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4): "An
  origin server that wishes to 'hide' the current existence of a forbidden
  target resource MAY instead respond with a status code of 404 (Not Found)."
- [nginx `ngx_http_proxy_module`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html),
  `proxy_cache_lock`: "only one request at a time will be allowed to populate a
  new cache element … Other requests of the same cache element will either wait
  for a response to appear in the cache or the cache lock for this element to be
  released". `proxy_cache_path` `max_size`: when the size is exceeded the cache
  manager "removes the least recently used data". The single-flight fetch and
  the LRU bound of clauses 42 and 47 follow that established shape, with offers
  deciding what is evicted first.
- The code read for the download route: `offer_for_assigned`, `assigned_entry`
  and `to_available` in `crates/fleet-server/src/packages.rs`; `packages_offer`
  and `AgentRecord` in `crates/fleet-server/src/fleet.rs`; `check_report` and
  `Host` in `crates/fleet-server/src/revocation.rs`; `download_package` in
  `crates/fleet-server/src/api.rs`; `admit_download` and `Proofs` in
  `crates/fleet-server/src/transport.rs`; `resolve_url`, `Sources` and
  `send_download` in `crates/fleet-agent/src/packages.rs`; the Gateway's router
  in `crates/fleet-agent/src/gateway/mod.rs`.
- The code read for the Gateway clauses: `Forwarding`, `run_on_timed` and
  `server_tls` in `crates/fleet-agent/src/gateway/mod.rs`; `Registry::deliver`
  in `crates/fleet-agent/src/gateway/registry.rs`; the pool's reader in
  `crates/fleet-agent/src/gateway/pool.rs`; `RevocationList::verdict` in
  `crates/fleet-agent/src/gateway/revocations.rs`; `download_and_verify`,
  `write_stream` and `download_client` in `crates/fleet-agent/src/packages.rs`;
  `to_available` in `crates/fleet-server/src/packages.rs`; `HOST_URI_PREFIX` and
  `facts` in `crates/fleet-server/src/ca.rs`.
- [`sevenz-rust2`](https://crates.io/crates/sevenz-rust2) — pure-Rust 7z with an
  `aes256` feature; its default features pull `bzip2`, so it is taken with
  `default-features = false`.
- [`zip`](https://crates.io/crates/zip) — MIT; its default features pull
  C-binding codecs, so it is taken with `default-features = false` and `deflate`
  only, and reading stays on the `flate2`/`miniz_oxide` chain.
- [Elastic Agent standalone install](https://www.elastic.co/docs/reference/fleet/install-standalone-elastic-agent)
  — the `.tar.gz` tree distribution is the one Fleet can upgrade.
- [Datadog Fleet Automation upgrades](https://docs.datadoghq.com/agent/fleet_automation/upgrade_agents/)
  — two installs side by side "in case a rollback is needed".
- [fluent/fluent-bit#2558](https://github.com/fluent/fluent-bit/pull/2558) —
  `FLB_STATIC_BINARY`, an unmerged draft: why a static Fluent Bit is not the
  answer.
- [RFC 6454 — The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454) —
  scheme, host and port as the unit an allow-list entry, a redirect hop and an
  offered header are compared by.
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) — the one
  protocol version a download is made over, which the probe speaks and a
  referenced `url` is fetched over beyond the loopback.
- [`reqwest::redirect::Policy::custom`](https://docs.rs/reqwest/latest/reqwest/redirect/struct.Policy.html)
  — a policy that sees each hop before it is followed, which is where the
  allow-list applies.
- [`HARDENING.md`](../HARDENING.md) H12, H13 and H19 — the fail-open signature
  check, the unbounded source set, and the offered header as a credential on
  someone else's host.

## Consequences

- Positive: a release is one object — five platforms' artifacts under one
  identity with one version. One upload loop per release, no per-host
  configuration, and the Client's self-update works across a heterogeneous
  fleet.
- Positive: a mismatched binary is refused by construction rather than caught by
  a health gate; the Client's own binary is protected on both sides of the wire.
- Positive: one spelling of a platform from the release file name through the
  upload, the API, the fleet view and what a Collector reports; folding a
  Managed Process's attributes over the Supervisor's cannot change a host's
  architecture.
- Positive: a package can be a URL an operator already has — nothing uploaded,
  nothing duplicated — and for a referenced entry nothing exists on the Server
  to leak.
- Positive: a referenced entry's headers and artifact never cross a network in
  plaintext; the only plaintext source is one on the host itself.
- Negative / trade-offs: a mirror on the operator's network needs a certificate
  its Agents trust; a plain HTTP file share is no longer a source.
- Negative / trade-offs: disk is unbounded by design — every version stays until
  deleted.
- Negative / trade-offs: a mistyped Agent type is a silent no-op — there is no
  canonicalisation to catch it, and the package simply fits nobody. An Agent's
  type can change under a stable configuration (a Collector gaining
  `opampextension` switches to `dist.name`), and with it which packages fit it.
- Negative / trade-offs: an Agent reporting no platform or no type gets no
  package. No Client this project ships is in that position; a foreign OpAMP
  client may be.
- Negative / trade-offs: a referenced entry needs egress from every Agent to its
  source, three hundred downloads from a third party, and the Server cannot
  answer what exactly the Agents will install — a wrong hash, a moved release or
  a revoked token surfaces as `InstallFailed` on Agents. Headers for a private
  source are a fleet-wide secret in flight and at rest on every host.
- Positive: "what is this artifact" is readable off one object with two fields,
  and "which artifact does this host get" off one Deployment. The ranking
  disappears — specificity, the version tie-break and the unbreakable tie. A
  collision between two Deployments is **refused and named** rather than
  silently resolved; that is a discipline, not a proof that one Deployment
  matches.
- Positive: a channel is something an operator can name, sign and release in one
  act.
- Negative / trade-offs: **there is no "roll out to everyone".** A fleet-wide
  delivery needs every Agent to carry the same channel value, and a fresh host
  belongs to no Deployment until labelled or provisioned with one — a discipline
  for provisioning.
- Negative / trade-offs: two builds of one Agent type at one version cannot
  coexist; they must differ in type or version. The same Package in two
  Deployments is signed in each, although the signature over the same bytes with
  the same key is identical. An operator who set `[self_update] package` to
  something other than an Agent type sees that Client refuse the offer on its
  fleet row.
- Negative / trade-offs: nothing reaches an Agent before it is signed — a trial
  rollout needs the signing key too, and a Platform entry uploaded after a
  rollout reaches no Agent until the Deployment signs it.
- Positive (Strategy _Security before convenience_): a compromised host gets
  from the store only what its own Agents were released. What was released to
  another host's Agents stays with them, within the limit the Negative entry on
  partitions names. An unreleased build cannot be fetched by anyone, and the
  store's contents cannot be listed by probing.
- Positive (G-10): the offer and the download share one test, so a Client that
  was offered an artifact can always fetch it. The offer tests type fit as well
  (clause 9).
- Positive (Q-1): no setting turns the bound off. It holds whatever the
  configuration is.
- Negative / trade-offs: a certificate that names no host fetches nothing. Two
  cases are affected: a fleet whose Server signs no CSRs (no `[client_ca]`) and
  whose operator provisions certificates without the host SAN URI, and a
  third-party Agent with such a certificate. Each gets `404` instead of bytes.
  The startup notice (clause 37) and the audit entry say why. The manual
  (`docs/manual/server.md`, `[client_ca]` and the download route) states that
  without `[client_ca]` a hand-provisioned certificate must carry
  `urn:opamp-fleet:host:<id>` to receive uploaded artifacts.
- Negative / trade-offs: a partition is only as strong as the hosts it
  partitions (Context). A compromised host can report another partition's
  attributes under a fresh `instance_uid`, be assigned by that partition's next
  bulk rollout, and then fetch what was released. Today a partition set by a
  Server label is not stronger, because a reported attribute satisfies the same
  Selector. Making labels authoritative for a partition would close this: a
  Selector term that only a label can satisfy, or a reported key that is refused
  when it shadows a label key. That is a follow-up. The fleet view shows such an
  Agent as waiting before the press that assigns it.
- Negative / trade-offs: one lookup under the fleet lock per download. For an
  ordinary host this is a lookup per bound `instance_uid` (at most 256). For a
  Gateway it is a scan of the fleet's records, because it speaks for any Agent.
  The rate limit of clause 40 bounds how often that scan runs. An index from
  artifact to offering Agents is an option if the scan shows up.
- Negative / trade-offs: a Gateway's certificate stays as broad as its mark
  already makes it. This decision makes that explicit and does not narrow it.
- Negative / trade-offs: an Agent that reports a different `service.name` after
  it was rolled out to is no longer offered the old type's Package. That follows
  from clause 9.
- Positive (G-10, G-15): a Client behind a Gateway receives uploaded artifacts,
  through the Gateway, from a Server that keeps clause 37 unchanged. Each
  artifact crosses the Gateway's upstream link once per Gateway instead of once
  per Agent, and costs the Server one download.
- Positive (Strategy _Security before convenience_): a host behind a Gateway
  receives from it only what the Server offered through it to that host's own
  Agents. The Gateway's breadth under clause 37 is not passed on, and a
  downstream host cannot list what the Gateway holds.
- Positive: a nested Gateway is served by the Gateway in front of it like any
  downstream host: the Agents it carries are routed over its connection, which
  presents its certificate.
- Negative / trade-offs: the Gateway now holds artifacts on disk, up to
  `package_cache_bytes` (10 GiB by default), staged fetches included. Its
  `state_dir` needs that space.
- Negative / trade-offs: a Gateway that restarts holds no offers. An Agent whose
  install is still in flight reconnects, and its report re-draws the offer,
  since the Server re-sends an offer whose hash the Agent has not echoed. An
  Agent that echoed the offer with a failed install and then retries is answered
  `404` until the Server sends it a different offer. Pressing the same version
  again yields the same hash, which the hash gate does not re-send; a rollout of
  another version does.
- Negative / trade-offs: a host behind a Gateway holds at most
  `max_carried_agents` bindings, so a host carrying more Agents through one
  Gateway than that cannot have the rest served from the cache. At the global
  cap a flood from many hosts can push out bindings that have neither a route
  nor an offer; such an Agent is bound again by its next report.
- Negative / trade-offs: an `instance_uid` is bound to the host of the first
  report for it after the Gateway starts. Until that first report a host that
  reports another host's `instance_uid` first is bound instead and served its
  offers; the real host's peer is answered `404`, and the Gateway logs each
  offer it does not record. The remedy for such a lockout is a restart of the
  Gateway, after which the real host's next report binds it. Within one Gateway
  this is the bound the Server's host register gives directly connected hosts
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 7).
- Negative / trade-offs: a fetch that failed is not tried again until the
  artifact newly appears in an Agent's offer, so a transient error upstream can
  leave the Agents behind the Gateway without it until the next rollout. A `429`
  or `503` with `Retry-After` is not such a failure.
- Negative / trade-offs: a Client now waits up to 30 minutes, in waits of at
  most 60 seconds, on a `429` or `503` from its own Server origin before it
  reports a download failed (clause 49). A failure the Server or Gateway answers
  that way is reported that much later.
- Negative / trade-offs: an artifact larger than the cache is not delivered
  behind the Gateway at all; the Gateway's log names it, and the downstream
  Agent reports the failed download.
- Negative / trade-offs: with `advertised_url` set, uploaded artifacts are not
  delivered behind a Gateway at all (clause 43). A fleet with Gateways leaves
  `advertised_url` unset.
- Negative / trade-offs: a Gateway whose host is not marked delivers no uploaded
  artifact; its log says that the Server refused the fetch.
- Positive: an upstream release, archive and all, is deliverable as published;
  the SHA-256 from its `checksums.txt` and the operator's signature are checked
  on every host, and a confidential agent stays encrypted everywhere but the
  host that runs it.
- Positive: nothing reaches a host that the operator's key did not sign,
  whatever the Server or an offer claims, and no archive parser sees bytes that
  have not passed both checks.
- Positive: an offered header and the Client's certificate go only where the
  operator allowed — the certificate to the Server alone — so a mirror's
  redirect cannot harvest either.
- Positive: an agent that is an executable plus its libraries is managed like
  any other — the health gate, rollback, retention and version report come with
  it.
- Positive: neither failure loop can start. A first package that will not run
  stays installed and `InstallFailed`; a pair of broken versions is reported and
  held; for a day after a successful update the previous version is still on
  disk.
- Negative / trade-offs: every fleet must create and keep a signing key, and put
  its public half on every host, before it can distribute anything; a fleet that
  has not is told so at startup and takes no packages.
- Negative / trade-offs: the allow-list is configuration on every host, and a
  release host that redirects to a storage or CDN origin needs that origin
  listed too, or the download fails at the hop.
- Negative / trade-offs: every host parses untrusted archives. Path sanitizing,
  link refusal and the size and member bounds are the tested boundary, because a
  tree archive does choose where its bytes land.
- Negative / trade-offs: disk — two copies of a program or tree per Supervisor
  during the retention window, and the artifact ceiling and unpack bound sized
  for agents of hundreds of megabytes.
- Negative / trade-offs: the archive key is a fleet-wide secret in
  `supervisor.toml` on every host, protected only by the file's permissions;
  rotating it means every host and every encrypted archive.
- Negative / trade-offs: a `.7z` or `.zip` tree carries no helper executables'
  modes, and a sloppy `.tar.gz` produces an agent that does not start — a cause
  in the archive, not on the host.
- Negative / trade-offs: two on-disk layouts, chosen by whether one optional key
  is set.
- Positive: an upstream zip travels exactly as published, and a `.zip` is opened
  and held to the same member rules rather than installed as the program.
- Negative / trade-offs: the Client parses a third untrusted archive format,
  which must pass the same traversal, link and bound tests as the other two.
- Negative / trade-offs: a repacked artifact does not match upstream's hash, so
  upstream's checksum is checked at packing time; dereferencing duplicates what
  links shared.
- Follow-ups: a retention policy for superseded packages; warning when a type or
  Platform fits no Agent in the fleet; verifying upstream sigstore provenance
  instead of a pasted checksum; `host.name` and `cloud.*` reporting; whether a
  Configuration should be aimed by the Deployment that already aims its Agent's
  Package; inequality in Selectors; refusing an overlapping Selector at write
  time once a fleet is large enough that a conflict is expensive to notice; a
  Selector term that only a Server label satisfies, so that a partition can hold
  against the host it partitions; sourcing the archive key from an OS keystore
  or a tighter file; distributing keys without letting the Server read
  artifacts; rotating the verification key across a fleet; scoping an offered
  header to a path; a directory mode for the packing tool; range-request
  resumption for large artifacts. `SECURITY.md` (the trust-boundary section) and
  the manual's download-route rows in `docs/manual/server.md` state the bound,
  and `docs/manual/client.md` the Gateway's cache.

## Enforcement

Each test of clauses 35–49 carries a `Verifies:` marker citing this decision
([ADR-0003](0003-decisions-verified-by-tests.md)).

- `crates/fleet-server/src/packages.rs` unit tests: `a_set_survives_a_reopen`,
  `fit_is_mandatory_platform_and_type`,
  `both_sides_of_the_comparison_are_canonicalised`,
  `the_offer_carries_a_download_url_naming_the_identity`,
  `deletion_frees_entries_and_sets`, `a_corrupt_artifact_fails_reopen`,
  `the_store_and_its_metadata_are_owner_only`, `identity_tokens_are_bounded`.
- `crates/fleet-core/src/platform.rs`:
  `folds_the_spellings_this_project_does_not_control`,
  `what_rust_calls_this_machine_folds_onto_a_canonical_token`,
  `an_unknown_token_passes_through_unchanged`.
- `crates/fleet-server/tests/packages.rs`:
  `an_uploaded_set_is_offered_downloaded_and_gated`,
  `the_artifact_is_served_where_the_agents_are_and_not_on_the_operator_plane`,
  `no_offer_without_the_capability`, `an_entry_needs_its_set_first`,
  `an_artifact_larger_than_the_framework_default_uploads_and_downloads_intact`,
  `an_artifact_past_the_configured_limit_is_refused`,
  `the_package_store_has_a_total_size_ceiling`,
  `a_referenced_entry_is_offered_from_its_source_and_not_from_here`,
  `a_source_that_refuses_the_probe_is_rejected_but_an_unreachable_one_is_not`,
  `a_source_url_aimed_at_an_internal_address_is_refused`,
  `a_set_reaches_only_agents_of_its_type`.
- `crates/fleet-server/tests/packages.rs`, clauses 4 and 5:
  `a_plaintext_source_off_the_loopback_is_refused` (a host name, `localhost`
  included, is refused; both loopback literals are accepted) and
  `the_probe_follows_no_redirect`.
- `crates/fleet-server/src/labels.rs`:
  `a_label_never_overrides_what_the_agent_reports`.
- `crates/fleet-agent/src/config.rs`: `the_retired_package_keys_are_refused`.
- `crates/fleet-agent/tests/packages_e2e.rs` and
  `crates/fleet-agent/tests/self_update_e2e.rs` run the real Server and Client
  against one store across the reported Platform.
- `crates/fleet-server/src/deployments.rs`:
  `two_deployments_matching_one_agent_are_a_conflict_that_names_them`,
  `a_narrower_selector_does_not_win_over_a_wider_one`,
  `an_agent_no_ring_claims_is_not_a_conflict`,
  `a_deployment_must_name_the_ring_it_aims_at`,
  `a_deployment_holds_one_package_per_agent_type`,
  `a_signature_needs_its_package_and_leaves_with_it`,
  `the_selector_stays_editable_and_keeps_what_the_ring_holds`.
- `crates/fleet-server/src/fs/deployments.rs`: `a_deployment_survives_a_reopen`,
  `an_unreadable_file_fails_the_open_and_names_it`,
  `the_store_and_its_files_are_owner_only`.
- `crates/fleet-server/src/packages.rs`:
  `only_the_package_its_ring_holds_is_a_candidate`,
  `a_store_in_an_older_layout_refuses_to_open_and_names_what_is_in_the_way`,
  `identity_tokens_are_bounded`.
- `crates/fleet-server/tests/packages.rs`:
  `a_selector_aims_a_rollout_at_part_of_the_fleet`,
  `a_canary_ring_is_a_selector_aim_and_two_acts`,
  `an_agent_two_rings_claim_is_offered_nothing_and_the_view_says_why`,
  `a_label_aims_a_set_at_part_of_the_fleet`,
  `a_deployment_without_a_selector_is_refused`,
  `a_deployment_holds_one_uploaded_package_per_agent_type`,
  `a_deployment_carries_the_signature_and_says_what_is_unsigned`,
  `a_deployments_aim_is_editable_and_deleting_it_is_its_own_act`,
  `the_signature_an_agent_is_offered_comes_from_its_deployment`,
  `a_signature_on_the_artifact_upload_is_refused_by_name`,
  `a_conflict_takes_the_candidate_away_and_leaves_the_assignment_standing`,
  `the_per_agent_act_refuses_to_pick_a_side`,
  `a_ring_freezes_what_it_has_released`,
  `a_deployment_that_released_a_package_refuses_to_be_deleted`,
  `a_packages_entry_shows_the_hash_an_agent_verifies_against`,
  `the_fleet_view_tells_no_ring_apart_from_a_ring_with_nothing_for_this_agent`,
  `a_set_says_how_many_agents_it_reaches`.
- `crates/fleet-server/tests/rest_api.rs`:
  `the_openapi_document_describes_the_contract` (the Deployment routes are in
  the contract, and no Selector or rollout route on a Package is).
- `crates/fleet-server/src/fleet.rs`:
  `a_record_without_assignments_loads_assigned_to_nothing`;
  `crates/fleet-server/src/fs/agents.rs`:
  `a_record_without_assignments_restores_with_none`.
- `crates/fleet-agent/src/supervisor/agent.rs`:
  `an_addon_package_is_refused_instead_of_overwriting_the_binary`.
- The signature (clauses 28 and 29):
  `an_entry_its_deployment_has_not_signed_is_not_a_candidate` in
  `crates/fleet-server/src/packages.rs`;
  `a_rollout_of_a_deployment_with_an_unsigned_package_is_refused_naming_it` and
  `the_per_agent_act_refuses_a_deployment_with_an_unsigned_package` in
  `crates/fleet-server/tests/packages.rs`.
- `crates/fleet-server/src/packages.rs`:
  - `the_download_and_the_offer_test_one_predicate`: for every combination, the
    offer and the download agree on what is offered (clause 35).
  - `an_agent_reporting_another_type_is_offered_nothing` (clause 35).
  - `an_entry_its_deployment_does_not_sign_is_not_offered` (clause 35).
  - `a_referenced_entry_is_never_offered_for_the_route` (clause 35, 38).
- `crates/fleet-server/src/revocation.rs`:
  - `a_host_speaks_for_the_agents_bound_to_it_and_a_gateway_for_any` (clause
    37).
- `crates/fleet-server/src/fleet.rs`:
  - `an_artifact_is_offered_to_a_host_only_through_an_agent_it_speaks_for`
    (clauses 35, 37).
  - `an_offer_still_stands_after_its_hash_is_echoed` (clause 36).
  - `a_version_waiting_for_its_press_is_offered_to_no_host` (clause 36).
- `crates/fleet-server/tests/mutual_tls.rs`:
  - `a_host_fetches_the_artifact_offered_to_its_own_agent` (clause 37).
  - `a_host_is_answered_404_for_an_artifact_offered_only_to_another_host`
    (clauses 37, 38).
  - `an_artifact_not_offered_and_one_not_held_are_answered_alike`, which
    compares status, body and headers byte for byte (clause 38).
  - `a_marked_gateway_fetches_what_is_offered_to_any_agent` (clause 37).
  - `a_certificate_naming_no_host_fetches_nothing` (clause 37).
  - `a_refused_fetch_leaves_one_download_refused_entry_naming_its_check`, which
    also checks that the throttle did not count it (clause 39).
  - `a_malformed_token_is_answered_400_before_the_offer_is_tested` (clause 39).
  - `a_download_costs_a_token_of_the_hosts_bucket` (clause 40).
- `crates/fleet-server/src/main.rs`:
  - `a_server_without_client_ca_says_uploaded_artifacts_need_a_host` (clause
    37).
- Tests served over `Admission::open`, where no certificate is presented, are
  unchanged (clause 37):
  - `crates/fleet-agent/tests/packages_e2e.rs`;
  - `crates/fleet-agent/tests/http_transport_e2e.rs`, the two Servers it starts.
- `crates/fleet-server/tests/packages.rs`:
  - `an_uploaded_set_is_offered_downloaded_and_gated` and
    `an_artifact_larger_than_the_framework_default_uploads_and_downloads_intact`
    use a member certificate that names the reporting Agent's host, so that they
    exercise the offered test.
  - `a_version_waiting_for_its_rollout_cannot_be_fetched` (clause 36).
- `crates/fleet-agent/tests/gateway_tls.rs`:
  - `the_gateway_serves_no_artifact_it_relayed_no_offer_for`: the Server serves
    the artifact, and the Gateway, which relayed no offer of it, answers `404`
    (clause 45).
- `crates/fleet-agent/tests/gateway_package_cache.rs`, against an upstream the
  test controls:
  - `a_relayed_artifact_is_fetched_once_before_any_request_and_served_to_its_host`
    — two Agents of one host are offered the same artifact, the Gateway fetches
    it before any request, requests while it runs are answered `503` with
    `Retry-After: 30`, and the upstream served one fetch (clauses 42, 45).
  - `another_host_and_a_certificate_naming_no_host_are_answered_as_for_an_artifact_not_held`,
    which compares status, headers and body byte for byte (clause 45).
  - `a_host_reporting_another_hosts_instance_uid_before_the_reply_is_not_served`
    — host B reports host A's `instance_uid` between A's report and the Server's
    reply; B is answered byte for byte as for an artifact not held, and A is
    served (clause 45).
  - `a_later_offer_replaces_what_an_agent_was_offered` (clause 45).
  - `a_failed_fetch_is_not_repeated_by_requests_or_re_offers_and_is_retried_when_newly_offered`
    (clauses 42, 48).
  - `a_websocket_downstream_receives_the_offer_and_the_artifact` (clauses 42,
    45).
  - `a_referenced_artifact_is_neither_fetched_nor_served` (clause 43).
  - `an_artifact_that_fails_its_hash_is_neither_stored_nor_served` (clause 44).
  - `an_artifact_larger_than_the_cache_is_refused_and_not_fetched_again` and
    `a_body_without_content_length_is_cut_at_the_limit` (clause 47).
  - `the_download_route_answers_503_while_the_gateway_holds_no_revocation_list`
    and `a_revoked_certificate_is_refused_on_the_download_route` (clause 45).
  - `a_client_behind_a_gateway_installs_from_an_upstream_slower_than_its_read_timeout`
    — the upstream is held until the Client's own download has been answered
    `503` by the Gateway, and its download then completes and verifies (clauses
    45, 49).
- `crates/fleet-agent/tests/gateway_package_cache.rs`, against the real Server
  on mutual TLS:
  - `a_client_behind_a_marked_gateway_receives_an_uploaded_artifact_through_it`
    — the Gateway fetches with its own certificate what the Server offers an
    Agent behind it, and the downstream Client's own download code
    (`download_and_verify`) fetches it from the Gateway and verifies its hash
    and signature (clauses 37, 42, 44, 45).
- `crates/fleet-agent/src/gateway/cache.rs`:
  - `room_is_made_from_artifacts_no_longer_offered_first` (clause 47).
  - `only_a_path_on_the_servers_route_is_cached` (clause 43).
  - `requests_while_fetching_are_answered_busy_and_the_upstream_serves_one`
    (clauses 42, 45).
  - `the_cache_is_emptied_at_start_and_owner_only` (clause 47).
  - `refusals_are_logged_five_a_minute_per_host_and_the_rest_counted` (clause
    46).
  - `an_evicted_offered_artifact_is_fetched_again_on_a_request_once_per_offer`
    (clauses 45, 48).
  - `a_file_whose_deletion_fails_stays_counted_until_deleted` and
    `a_held_artifact_whose_file_disappeared_is_forgotten` (clause 47).
  - `a_fetch_cannot_reserve_room_other_fetches_hold` (clause 47).
  - `no_more_than_four_fetches_run_at_once` (clause 42).
  - `an_offer_over_a_certificate_naming_no_host_records_nothing_and_fetches_nothing`
    (clauses 42, 45).
  - `an_unfinished_fetch_leaves_no_entry_behind` (clause 42).
  - `a_host_flooding_instance_uids_cannot_keep_another_hosts_agent_from_being_bound`
    (clause 45).
  - `a_fetch_below_the_pace_floor_is_cut` (clause 42).
  - `a_deferred_fetch_gives_its_slot_back_while_it_waits` (clause 42).
  - `a_shutdown_ends_a_fetch_that_waits_out_retry_after` (clause 42).
  - `an_artifact_evicted_between_lookup_and_open_is_fetched_again` (clauses 45,
    47).
- `crates/fleet-agent/src/packages.rs`:
  - `a_download_waits_out_retry_after_from_its_server_origin`,
    `a_download_gives_up_once_its_waits_reach_the_bound` and
    `a_retry_after_from_another_host_fails_the_download`,
    `a_retry_after_of_zero_does_not_loop_without_bound`,
    `request_time_counts_against_the_bound`,
    `an_unusable_retry_after_is_not_waited_out` and
    `a_retry_after_after_a_redirect_off_the_origin_is_not_waited_out` (clause
    49).
- `crates/fleet-agent/src/transport/mod.rs`:
  - `a_shutdown_stops_a_download_waiting_out_retry_after` (clause 49).
- `crates/fleet-agent/src/config.rs`:
  - `the_package_cache_defaults_to_ten_gib_and_rejects_zero` (clause 47).
- [`crates/fleet-core/src/package.rs`](../../crates/fleet-core/src/package.rs)
  test: `the_statement_names_type_version_and_hash` (clause 54).
- [`crates/fleet-agent/src/packages.rs`](../../crates/fleet-agent/src/packages.rs)
  test: `a_signature_does_not_carry_over_to_another_type_or_version` (clause
  54).
- [`crates/fleet-agent/src/supervisor/agent.rs`](../../crates/fleet-agent/src/supervisor/agent.rs)
  test: `a_package_for_another_type_or_an_older_version_is_refused` (clause 65).
- Download and verification: `content_hash_mismatch_is_refused`,
  `signature_policy_is_enforced`, `a_traversing_package_name_is_refused`,
  `download_refuses_to_stage_a_traversing_name`,
  `the_cap_triggers_only_past_the_limit`,
  `the_download_source_drops_whatever_authorises_it`,
  `a_download_never_debug_prints_its_header_values` in
  [`packages.rs`](../../crates/fleet-agent/src/packages.rs);
  `a_body_too_large_by_its_content_length_is_refused`,
  `a_chunked_body_is_stopped_once_it_crosses_the_ceiling`,
  `a_download_follows_a_redirect_to_the_mirror`,
  `a_download_carries_the_headers_the_offer_named`,
  `an_offered_header_does_not_follow_a_redirect_to_another_origin`,
  `an_unusable_offered_header_fails_the_download_by_name`,
  `the_staging_directory_is_kept_owner_only` in
  [`tests/packages_download.rs`](../../crates/fleet-agent/tests/packages_download.rs);
  `the_artifact_size_limit_defaults_is_configurable_and_rejects_zero` in
  [`config.rs`](../../crates/fleet-agent/src/config.rs); end to end,
  `a_signed_package_is_downloaded_verified_swapped_and_reported_installed` in
  [`tests/packages_e2e.rs`](../../crates/fleet-agent/tests/packages_e2e.rs).
- Offer and status:
  `an_addon_package_is_refused_instead_of_overwriting_the_binary`,
  `a_package_offer_for_the_named_package_is_acknowledged_installing_and_handed_over`,
  `a_package_offer_hands_its_download_headers_to_the_transport`,
  `a_failed_package_reports_installed_failed_and_keeps_the_old_version` in
  [`supervisor/agent.rs`](../../crates/fleet-agent/src/supervisor/agent.rs);
  `every_supervisor_declares_package_acceptance` in
  [`supervisor/mod.rs`](../../crates/fleet-agent/src/supervisor/mod.rs);
  `a_slow_download_is_reported_as_downloading_with_progress` in
  [`transport/mod.rs`](../../crates/fleet-agent/src/transport/mod.rs).
- Containers, single file and tree: in
  [`archive.rs`](../../crates/fleet-agent/src/archive.rs) the detection tests
  (`detects_gzip_by_its_leading_bytes_and_anything_else_as_raw`,
  `detects_a_7z_by_its_signature`,
  `detects_a_zip_by_its_signature_and_an_empty_one_too`),
  `an_encrypted_7z_opens_with_the_key_and_not_without_it`,
  `an_escaping_member_path_still_lands_only_where_we_put_it`,
  `a_bomb_ahead_of_the_target_is_refused_before_it_is_skipped`,
  `the_same_program_path_finds_the_program_under_any_wrapper`,
  `members_outside_the_programs_own_directory_are_left_out_and_counted`,
  `a_member_that_climbs_out_refuses_the_archive_before_writing_anything`,
  `an_absolute_member_refuses_the_archive`, `a_link_member_refuses_the_archive`,
  `a_hard_link_member_refuses_the_archive`,
  `a_7z_member_that_is_a_link_or_an_anti_item_refuses_the_archive`,
  `an_archive_of_too_many_members_is_refused`,
  `a_tree_that_outgrows_the_total_budget_is_refused`,
  `no_match_and_an_ambiguous_match_are_both_refused_by_name`,
  `a_tree_keeps_the_modes_the_archive_carried`,
  `a_hostile_zip_member_refuses_the_archive`; for the zip container (clause 66)
  further `extracts_the_named_member_from_a_zip_wherever_the_archive_keeps_it`,
  `a_zip_tree_lands_whole_with_the_wrapper_directory_dropped` and
  `a_zip_past_the_budget_is_refused`;
  `a_program_path_must_stay_inside_the_package` and
  `a_tree_spawns_from_the_path_written_inside_the_package` in
  [`config.rs`](../../crates/fleet-agent/src/config.rs).
- Swap, rollback, hold and retention: in
  [`tests/supervisor_process.rs`](../../crates/fleet-agent/tests/supervisor_process.rs)
  `apply_package_swaps_the_binary_and_acknowledges_installed`,
  `a_package_delivered_as_a_tar_gz_is_unpacked_and_installed`,
  `an_install_with_nothing_to_run_yet_keeps_the_binary_and_succeeds`,
  `a_package_that_will_not_stay_up_is_rolled_back_and_fails`,
  `a_first_install_that_will_not_start_is_kept_not_discarded`,
  `a_program_that_keeps_crashing_is_held_not_looped`,
  `a_successful_update_keeps_the_previous_version_for_the_window`,
  `a_tree_package_lands_whole_and_replaces_the_one_before_it`,
  `a_tree_that_will_not_stay_up_is_rolled_back_whole`,
  `a_tree_missing_the_configured_program_is_refused_and_changes_nothing`; in
  [`supervisor/process.rs`](../../crates/fleet-agent/src/supervisor/process.rs)
  `a_retained_backup_is_swept_only_after_its_deadline`,
  `a_sweep_leaves_an_unmarked_backup_alone`,
  `dropping_a_backup_clears_its_marker`;
  `retention_defaults_globally_and_is_overridable_per_supervisor` in
  [`config.rs`](../../crates/fleet-agent/src/config.rs).
- Deterministic repack (clause 67):
  `a_linked_directory_is_packed_under_both_names_and_a_cycle_does_not_hang` in
  [`fetch.rs`](../../crates/fleet-tools/src/fetch.rs) — a linked directory's
  contents under both names, a link that names nothing dropped, a cycle that
  ends, and the packed tree one a Client installs.
- Mandatory signature (clauses 50, 54):
  `without_a_verification_key_no_agent_takes_packages` in
  [`supervisor/mod.rs`](../../crates/fleet-agent/src/supervisor/mod.rs),
  covering the Client's own Agent too; `signature_policy_is_enforced` in
  [`packages.rs`](../../crates/fleet-agent/src/packages.rs);
  `an_unsigned_offer_or_an_unkeyed_client_fetches_nothing` in
  [`tests/packages_download.rs`](../../crates/fleet-agent/tests/packages_download.rs).
- Sources (clause 53), in
  [`packages.rs`](../../crates/fleet-agent/src/packages.rs):
  `an_allowed_source_must_be_a_plain_https_prefix` (the rule startup applies to
  every entry) and `a_source_is_allowed_only_below_a_prefix_or_at_the_server`.
- Download (clause 53), in
  [`tests/packages_download.rs`](../../crates/fleet-agent/tests/packages_download.rs):
  `a_source_that_is_not_allowed_is_refused_without_a_request`,
  `a_redirect_to_a_source_that_is_not_allowed_fails_the_download`,
  `an_offered_header_does_not_follow_a_redirect_to_another_origin`.

**Not mechanically decidable:** that the Server never opens an artifact
(clause 6) is an absence — no test can show a code path that does not exist;
review of every change touching `crates/fleet-server/src/packages.rs` and
`crates/fleet-server/src/api.rs` keeps it. That the probe speaks TLS 1.3 alone
(clause 5) is a client setting no test can observe: a refused handshake counts
as an unreachable source, which is stored like an answering one, so review keeps
it. That every download on the Agent is TLS 1.3 and that the client certificate
reaches only the Server's own origin are settled by construction in
`download_and_verify` — two download clients built on the Client's TLS settings,
the identified one used only for that origin — and no test stands up a TLS
source that inspects the handshake, so review of every change to
[`packages.rs`](../../crates/fleet-agent/src/packages.rs) keeps them. That the
Client names the missing key at startup is a log line in
[`service/runtime.rs`](../../crates/fleet-agent/src/service/runtime.rs) that no
test reads. That a repack yields the same bytes twice (clause 67) has no test of
its own: `pack_tree` in [`fetch.rs`](../../crates/fleet-tools/src/fetch.rs)
fixes order, times and ownership, and review of every change to it keeps them.
