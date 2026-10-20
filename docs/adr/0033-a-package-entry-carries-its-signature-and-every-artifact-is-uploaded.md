# ADR-0033: A Package entry carries its own signature, every artifact is uploaded to the Server, and the Server checks a signature as feedback while the Agent's check decides

- **Status:** 🟢 accepted · clause 5 superseded by [ADR-0043](0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** the entries and their signatures in `crates/fleet-server/src/packages.rs` and `crates/fleet-server/src/fs/packages.rs`, the signatures in `crates/fleet-server/src/deployments.rs`, the package and signature routes of `crates/fleet-server/src/api.rs`, the `[packages]` section and the `advertised_url` key of `server.toml` and their parsing in `crates/fleet-server/src/config.rs`, the Packages and Deployments tabs of the bundled UI in `crates/fleet-server/static/index.html`, the signing-file import, the download source rules and the `[packages]` section of `supervisor.toml` in `crates/fleet-agent/src/packages.rs` and `crates/fleet-agent/src/config.rs`, the Gateway's rule for what it caches in `crates/fleet-agent/src/gateway/cache.rs`, and every document that tells an operator how to add, sign or reference an artifact
- **Supersedes:** [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md) clause 8; [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) clauses 4, 5, 13, 14, 15, 20, 28, 35, 43 and 53; [ADR-0027](0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md) clause 5

## Context

ADR-0026 keeps the operator's Ed25519 signature on the Deployment, per `(Package, Platform)`
(clause 28), and lets an entry be either an uploaded artifact or a reference to one hosted
elsewhere, with optional request headers (clauses 4 and 5). The specification draft that this ADR
follows moves both: a Package holds one entry per platform with the artifact's hash, size and
signature, and every artifact is uploaded to the Server.

What the signature covers decides where it belongs. The signed statement
(`fleet_core::package::statement`, ADR-0026 clause 54) is `opamp-fleet-package-v1`, the Agent
type, the version and the artifact's SHA-256. It names no Deployment. Signing the same Package in
two Deployments therefore stores the same signature twice. A Deployment as the place of the
release decision is an arrangement of the Server's data, not something a Client can verify: anyone
who may write to the Server can copy a signature from one Deployment to another.

Keeping the signature on the Deployment has also cost integrity in the data:

- Deleting a Package left its identity and signatures in every Deployment that held it, until a
  fix on the 0.5.5 line removed them.
- A Package held by a Deployment but assigned to nobody may have its bytes replaced, and the
  signature made for the old bytes stays. The Client then refuses the artifact on the hash. It is
  a failed install, not a hole, but nothing shows it before the rollout.
- A signature may exist for a platform the Package has no entry for.
- ADR-0026 clause 31 has to freeze signature writes separately, because the re-offer hash does not
  cover the signature.

Referenced entries cost more than they save in this project. A base URL per Package was considered
and rejected with the human: it yields neither asset names nor hashes, which differ for every
upstream and which `opamp-fleetctl package fetch` already knows. A referenced entry makes every host
fetch from upstream: hosts need internet access, the Gateway does not cache such an artifact
(clause 43), and a host behind a Gateway without internet receives nothing. Its optional headers
are stored in cleartext and handed to every Agent offered the entry. Once the Package is assigned
they are frozen, so an expired or leaked token can only be replaced by a new Package version.

The Server holds no verification key today (ADR-0027 clause 5), so a wrong signature is noticed
only by the Client that refuses it. The human wants the Server to check signatures when it can,
**as feedback only**: the Agent's check stays the one that decides.

The decision serves G-10 (the Server updates an agent's software, verifying each Package) and
Q-1 (secure by default). The specification's security goal now says software is fetched from the
fleet itself.

## Decision

We will keep each artifact's signature on its Package entry, accept artifacts only as uploads to
the Server and offer them only from it, and have the Server check a signature against the operator's public key and report
the result, while the Agent's own check alone decides what is installed.

1. **Restates ADR-0026 clause 4. An entry is an uploaded artifact, and nothing else.** The body of
   an entry upload is the artifact. The Server streams it to a staging file, hashes it while
   streaming, refuses an empty one, and moves it into place. One artifact may be at most
   `max_package_size_bytes` (default 1 GiB, `413` beyond). The whole store may be at most
   `max_total_package_bytes` (default 16 GiB, `507` when the upload would pass it — checked before
   streaming and again after). `0` for either is refused at load. Where the bytes are kept is the
   storage decision's, not this one's. There is no referenced entry: no `url`, no `sha256` given
   instead of bytes, and no request headers.

2. **Restates ADR-0026 clause 5. The Server sends no request for a package anywhere.** It
   probes no source, follows no URL and holds no credential for one. What it offers is what it
   holds.

3. **Restates ADR-0026 clause 13. Uploaded artifacts are served on the Agent plane, and offered
   as a path.** The download route is the one `/api/v1` route on the Agent-plane listener
   ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)),
   not on the Operator plane and not in the OpenAPI document. It streams the file and never holds
   it in memory. The offered `download_url` is always a path, which the Client resolves against its
   own OpAMP endpoint. `advertised_url` no longer exists: a `server.toml` that names it fails
   startup, naming the key as removed. A download through another host would be refused by every
   Client (clause 13).

4. **Restates ADR-0013 clause 8. The package download stays on the Agent plane, outside the
   credential check, under its `/api/v1` path.** The offered `download_url` is a path the Client
   resolves against its own endpoint. The download is reached through the same TLS handshake as
   `/v1/opamp`, so the Client presents its client certificate to its own Server's origin and to no
   other host. What the handshake requires of that certificate is the admission decision's
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
   The route is served on that one listener only — the Operator plane answers it `404` — and the
   OpenAPI document, generated from the Operator plane's routes, does not carry it; the manual
   documents it as the Agent plane's.

5. **Restates ADR-0026 clause 15. A Package is identified by `(agent_type, version)` and nothing
   else.** Both are tokens of 1–64 characters from letters, digits, `.`, `_`, `+` and `-` — no `@`,
   no path separator. A Package has no name of its own, no Selector and no kind. Its entries carry
   their signatures (clause 6). Creating a Package that exists is the same request arriving twice.

6. **Restates ADR-0026 clause 28. The signature lives on the entry, and the wire is unchanged.**
   - `PUT|DELETE /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature` writes
     or removes the hex Ed25519 signature, as `opamp-fleetctl package sign` prints it.
   - A signature for an entry that does not exist is `404`, an empty or malformed one `400`.
   - Writing new bytes to an entry removes its signature, because a signature covers the hash.
   - A signature write on a Package assigned to an Agent is refused (`409`), like any other write
     to its entries ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 8).
   - What an Agent receives in `DownloadableFile.signature` is the signature of the entry for its
     Platform. An entry without one is no candidate, the Agent is offered nothing for it, and the
     fleet view says the signature is missing.
   - One signature serves every Deployment that holds the Package.

7. **The Server checks a signature when it holds the operator's public key, and only reports.**
   - `server.toml` may name `[packages] verification_key`: the hex Ed25519 public key, in the
     format the Client's key of the same name uses. A malformed key fails startup naming it.
   - With the key, the Server verifies an entry's signature over
     `statement(agent_type, version, content_hash)` when the signature is written and when the
     store is loaded.
   - Each entry reports `signature_state`: `missing`, `valid`, `invalid`, or `unchecked` when no
     key is set.
   - An `invalid` signature is stored and shown with a warning; it is never refused. The
     Client's verification (ADR-0026 clause 54) is the one that decides, and a Server without the
     key works as before.

8. **Restates ADR-0026 clause 14. The Packages tab is one table and one detail form, and it
   signs.**
   - One row per Package: Agent type, version, the platforms it holds, the Deployments that hold
     it, and whether every entry carries a valid signature. Selecting a row makes it the current
     record and shows the form; while nothing is current the form is not on screen.
   - **Create** opens the form empty, the only moment the identity fields are writable.
   - The form adds and removes entries in place, each from a file; a file named as a release
     artifact fills the platform and, while creating, the identity.
   - Each entry shows its hash, size and `signature_state`, with an `invalid` one marked as a
     warning.
   - The signing-file download and import both live here (clause 12).
   - **OK** persists and **Cancel** discards; both conclude the form, and only a failed save keeps
     it open beside its message. **Delete** stands alone on the left. The form enforces no rule of
     its own: what it greys out is what the Server answers `409` to.

9. **Restates ADR-0026 clause 20. The Package routes.**
   - `GET|PUT|DELETE /api/v1/packages/{agent_type}/{version}`; `PUT` takes no body.
   - `PUT|DELETE …/entries/{os}/{arch}` with the artifact as the body.
   - `PUT|DELETE …/entries/{os}/{arch}/signature` with `{signature}`.
   - `GET /api/v1/packages` lists each Package with its entries, each entry's `signature_state`,
     and the Deployments holding it.
   - The former `…/entries/{os}/{arch}/source` route is gone. So are the Deployment signature
     routes `…/deployments/{name}/signatures/…`; a request to either is answered `404`.
   - The download stays `GET /api/v1/packages/{agent_type}/{version}/file?os=…&arch=…` on the
     Agent plane.
   - A Package has no Selector route and no rollout route. The OpenAPI document follows.

10. **Restates ADR-0026 clause 35. "Currently offered" is the offer's own test, shared.** An
   artifact `(agent_type, version, os, arch)` is offered to an Agent when all of the following
   hold:
   - the Agent declares `AcceptsPackages`;
   - it holds a package assignment naming that Package;
   - the Agent type equals the `service.name` it reports;
   - the Platform it reports, canonicalised, is the requested one, and the Package holds an entry
     for it;
   - that entry carries a signature.

   The offer and the download decide this from the same parts in `packages.rs`, and a test that
   runs every combination through both keeps them from disagreeing.

11. **Restates ADR-0026 clause 43. The Gateway caches every offered artifact the Server hosts.**
   - An offered file is the Server's when its `download_url` is a path beginning
     `/api/v1/packages/` and naming the route's `/file`. The Server sends nothing else (clause 3),
     and a downstream Client resolves the path against its own endpoint, the Gateway.
   - An absolute `download_url`, which only a foreign Server could send, is neither fetched nor
     served by the Gateway.

12. **Restates ADR-0027 clause 5. The import is on the Packages tab.** The tab takes a signed
   signing file and puts each entry's signature through
   `PUT /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature`, one call per
   entry, and reports per entry what the Server answered, the `signature_state` included. The
   file format `opamp-fleet-signing-v1` is unchanged: it names no Deployment.

13. **Restates ADR-0026 clause 53. The Client downloads only from its own Server origin.**
    - A `download_url` that is a path is resolved against the Client's own origin: the scheme, host
      and port of its OpAMP endpoint, `wss` mapped to `https` (and `ws` to `http`, which the
      endpoint may only be on the loopback).
    - An absolute `download_url` is accepted only when its origin is that origin. Any other is
      refused without a byte fetched, reported `InstallFailed` naming its origin.
    - Redirects are followed up to 5 and only while every hop stays on that origin.
    - The offer's `headers`, if any, are sent only to that origin and never logged.
    - `[packages] allowed_sources` no longer exists. A `supervisor.toml` that still names it fails
      startup naming the key, so no operator believes a list is in force that is not.
    - Everything else ADR-0026 clause 53 says stays as it is: the streaming, the staging inside
      the Supervisor's own directory, `max_artifact_size_bytes`, the timeouts, the TLS 1.3 and the
      client certificate presented to the Server's origin.

**Out of scope:** where and how the Server keeps the bytes, which a storage decision settles;
refusing an `invalid` signature on the Server; more than one verification key on the Server, or
rotating it; signing on the Server or through it; the Deployment's own shape and rollout, which
the decision on Deployments carrying Configurations settles.

## Alternatives considered

- **Keep the signature on the Deployment (the status quo).** It keeps the place where an operator
  releases and the place where an operator signs together. But the statement does not name the
  Deployment, so the place adds nothing a Client can verify. It costs re-signing per Deployment and
  the integrity gaps listed under Context.
- **Signatures on the artifact, and the Deployment names only the required key** (the alternative
  ADR-0026 rejected). It was rejected because it "puts an attribute back on the emptied object and
  the release decision back on the bytes". The attribute belongs to the bytes: the statement is
  about them. The release decision stays where it is, in adding a Package to a Deployment and
  rolling it out. Naming a key per Deployment is left out, because the Client holds one key.
- **Bind the signature to the Deployment by putting its name into the statement.** That would make
  the release decision verifiable. It changes the statement, the signing file, `package sign` and
  every Client, and needs a signer who does not also roll out to be worth it. The specification
  has no such role (Non-Goal "Authorization and multi-tenancy").
- **Refuse an `invalid` signature on the Server.** This is stricter. The human chose feedback
  only: the Client's check decides, and the Server's key may lag behind the operator's.
- **Keep referenced entries, with the source credential held by the Server per URL prefix, or
  only on the host per allowed source.** Either one would solve the frozen-token problem. Both
  keep hosts fetching from upstream and the Gateway not caching. The human removed the reference
  entirely.
- **A base URL per Package from which entries and hashes are loaded.** A URL yields neither asset
  names nor hashes. That knowledge per agent lives in `opamp-fleetctl package fetch`, which
  uploads.
- **Keep `advertised_url` for a mirror or another host in front of the download.** With the
  Client downloading only from its own Server's origin, an `advertised_url` naming another host
  reaches no Client, and one naming the same origin says what the path already says. A setting
  that cannot work is one an operator can believe in wrongly.
- **Keep `[packages] allowed_sources` on the Client for other OpAMP Servers.** This Client serves
  this Server. A list nothing uses is a setting an operator can believe in wrongly.

## Sources / Prior art

- `crates/fleet-core/src/package.rs`, `statement`: the signed bytes name type, version and hash,
  not a Deployment. Read in the source.
- ADR-0013 clause 8, ADR-0026 clauses 4, 5, 13, 14, 15, 20, 28, 31, 35, 43, 53 and 54, its alternatives, and ADR-0027
  clauses 1–5.
- `crates/fleet-agent/src/archive.rs`: the Client detects raw, `.tar.gz`, `.7z` and `.zip` by their
  leading bytes. The Server never inspects an artifact, so no format field is needed.
- OpAMP specification, `DownloadableFile`: `download_url`, `content_hash`, `signature`, `headers`.
  The wire is unchanged.
- The working note of 2026-10-17 on the Server's data model, in which the human chose each point.

## Consequences

- Positive: signing is done once per artifact, and every Deployment that holds it uses it.
- Positive: no signature outlives its entry or Package. New bytes remove the old signature, and
  ADR-0026 clause 31's separate freeze for signatures is no longer needed.
- Positive: the Server makes no outbound request for packages and stores no source credential (Q-1).
  The Gateway caches every artifact, so hosts behind a Gateway receive every Package.
- Positive: an operator sees a wrong signature on the Packages tab before a rollout, not as a
  failed install.
- Negative / trade-offs: every artifact passes through the Server's storage. Size limits and disk
  (later S3) carry the whole fleet's software.
- Negative / trade-offs: an existing referenced entry cannot be carried over. The migration drops
  it with a warning, and the operator uploads the artifact.
- Negative / trade-offs: a download cannot go through a mirror or another host, and a
  `server.toml` naming `advertised_url` no longer starts. The changelog says to remove the key.
- Negative / trade-offs: a `supervisor.toml` naming `allowed_sources` no longer starts. The
  changelog says to remove the key.
- Negative / trade-offs: adding a Package to a Deployment no longer asks for a signature of its
  own. A Package signed once may be released in any Deployment. This matches what the statement
  already allowed.
- Follow-ups:
  - The Deployment's shape, its rollout and what it refuses, in the decision on Deployments that
    carry Configurations.
  - Where the bytes are kept and how, in the storage decision.
  - A second verification key for rotation, if one is needed.

## Enforcement

Tests that will carry `Verifies: ADR-0033`:

- A signature is written on an entry, offered to an Agent of that Platform, and removed when new
  bytes are uploaded to the entry.
- A signature write on an assigned Package is `409`; on a missing entry `404`.
- One Package held by two Deployments is offered with the same signature through both.
- With `[packages] verification_key` set on the Server, a valid signature reports `valid` and a
  wrong one `invalid`, and both are stored. Without the key the state is `unchecked`.
- A malformed `verification_key` in `server.toml` fails startup.
- The `…/source` route and the Deployment signature routes answer `404`.
- The offered `download_url` is always a path; a `server.toml` naming `advertised_url` fails
  startup naming the key.
- The Client refuses an absolute `download_url` on another origin without fetching. A
  `supervisor.toml` with `[packages] allowed_sources` fails startup naming the key.
- The Gateway caches an artifact offered as the Server's path.
- The offer and the download agree on every combination of capability, assignment, type,
  Platform and signature.
