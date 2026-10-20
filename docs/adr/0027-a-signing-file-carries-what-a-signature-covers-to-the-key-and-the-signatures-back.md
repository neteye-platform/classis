# ADR-0027: A signing file carries what a signature covers from the UI to the key and the signatures back, and `package sign` signs the hashes in it without the artifacts

- **Status:** 🟢 accepted · clause 5 superseded by
  [ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
- **Date:** 2026-10-12
- **Deciders:** Markus Brigl
- **Applies to:** the signing file format `opamp-fleet-signing-v1`, the
  `package sign` command of `opamp-fleetctl` in
  `crates/fleet-tools/src/package.rs` and the module that reads the file, the
  signing-info download of the Packages tab and the signature import of the
  Deployments tab of the bundled UI in `crates/fleet-server/static/index.html`,
  and every document that tells an operator how to sign a Deployment

## Context

A Deployment offers an entry only once it holds the operator's Ed25519 signature
for it, and a rollout is refused while any entry lacks one
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md),
clauses 28 and 54). The signature covers a statement, not the artifact's bytes:
`opamp-fleet-package-v1`, the Agent type, the version and the artifact's SHA-256
in lowercase hex, one per line (`fleet_core::package::statement`). Today
`opamp-fleetctl package sign` makes it from the **artifact file**, one entry per
call, and the operator types each signature into the Deployment form with its
Agent type, version, OS and architecture.

That is where it hurts. A Package of this fleet's own Client carries five
platforms; signing it for one Deployment is five `sign` calls and twenty form
fields. And the artifact has to be on the machine that holds the key, although
`package fetch` uploads it straight from upstream and the Server never gives it
back on the Operator plane — the download route is the Agent plane's and needs a
client certificate. The key is best kept off the Server host (ADR-0026), so the
one machine that should sign is the one least likely to hold hundreds of
megabytes of artifacts.

Everything a signature covers is already known to the Server: the Package's
Agent type and version, and every entry's `content_hash`, which the Packages tab
now shows. What is missing is a way to carry those values to the key and the
signatures back, and a way to sign a hash without its file.

This serves G-10 (the Server updates an agent's software) by taking the toil out
of the one step an operator must do by hand for every release, and G-5 (any UI
can drive the fleet), since the bundled UI is where the operator already reads
the values. It is weighed against Q-1 (secure by default) under Consequences,
because signing a hash the Server supplied is signing what the Server claims.

## Decision

We will carry what a Package's signatures cover in one JSON file,
`opamp-fleet-signing-v1`, that the UI offers for download per Package, that
`opamp-fleetctl package sign --signing-info <file>` signs entry by entry from
its hashes alone and writes back with each entry's signature, and that the UI
imports into a Deployment's signatures.

1. **The file.** One JSON object per Package:

   ```json
   {
     "format": "opamp-fleet-signing-v1",
     "agent_type": "supervisor",
     "version": "0.5.1",
     "entries": [
       {
         "os": "linux",
         "arch": "amd64",
         "sha256": "127f…cfb9e",
         "signature": "9a1c…"
       }
     ]
   }
   ```

   `format` is exactly `opamp-fleet-signing-v1`; a reader refuses any other
   value rather than guess at it. `agent_type`, `version`, `os` and `arch` are
   the names the REST API uses for the same values. `sha256` is the entry's
   `content_hash`, 64 lowercase hex characters. `signature` is absent in the
   downloaded file and 128 hex characters once signed. The platform is **not**
   part of what is signed (ADR-0026 clause 54); it is in the file so the import
   knows which `(os, arch)` signature route each signature belongs to.

2. **The download.** The Packages tab offers the file for the selected Package,
   built in the browser from the `GET /api/v1/packages/{agent_type}/{version}`
   the page already read. No new route: the file is a projection of an existing
   response.

3. **Signing.** `opamp-fleetctl package sign --key <file> --signing-info <file>`
   is the second form of `sign`, exclusive with the artifact form. It checks the
   whole file first — the format, every hash's shape, no platform twice — and
   signs nothing if any of it fails; then it signs
   `statement(agent_type, version, sha256)` for every entry and writes the file
   back with each `signature` filled, to `--out <file>` or in place. An existing
   `signature` is overwritten: signing again with the same key gives the same
   value (Ed25519 is deterministic), and with another key the new one is the one
   meant.

4. **The hashes are the operator's to check.** `sign --signing-info` verifies
   nothing against the artifacts or upstream; it prints each entry's platform
   and hash as it signs, and the manual states the duty: compare the hashes with
   the checksums upstream published or with `opamp-fleetctl package sha256` over
   the files before signing. This is the decision's deliberate trade-off, and
   the reason it is recorded (Consequences).

5. **The import.** The Deployments tab takes a signed file and puts each entry's
   signature through the existing
   `PUT /api/v1/deployments/{name}/signatures/{agent_type}/{version}/{os}/{arch}`,
   one call per entry, and reports per entry what the Server answered. No new
   route, and no check of the signature on the Server: it holds no verification
   key, and every Client verifies each signature before it opens the artifact
   (ADR-0026 clause 54).

**Out of scope:** an import or signing route on the Server, a Server-side
verification key, `sign` writing signatures to a Server itself, a signing file
spanning several Packages, and an external signer (HSM, `openssl`) reading the
file — the statement is documented in ADR-0026 for whoever wants to build one.

## Alternatives considered

- **`sign --signing-info` demands an independent source** — the artifacts
  (`--artifacts <dir>`) or upstream's checksums file (`--checksums <file>`) —
  and refuses an entry whose hash is in neither. The strongest form: what the
  operator signs is always something they hold or upstream published. Not chosen
  by the decider: it brings back the file, or a second download, for the case
  this decision exists to make easy. The check stays a documented duty, and this
  alternative is the natural tightening should that duty prove to be skipped.
- **`sign` fetches upstream's checksums itself** for the agents `package fetch`
  knows. Convenient, but it covers only artifacts that travel as published; a
  repacked artifact has no upstream checksum to find, so the tool would need
  both paths and the rule which applies.
- **The statement itself as the file**, one text file per entry. Any Ed25519
  signer could sign it without this tool, but five platforms are five files, the
  `(os, arch)` an import needs is lost, and the signatures still need a way
  back.
- **A `checksums.txt`-style file** (`<sha256>  <name>`). Comparable to
  upstream's file with `diff`, but the Server knows entries by platform, not by
  file name, and the Agent type and version would ride in comments, which is a
  format nobody can parse strictly.
- **`sign` writes the signatures to the Deployment** over REST (`--server`,
  `--deployment`, `--cacert`). One step fewer, but it puts Operator-plane
  credentials and reachability on the machine that holds the key, which is the
  machine best kept off the network. The UI import keeps the key's machine
  offline; a CLI path can be added later without changing the file.
- **The Server verifies imported signatures** against a configured public key.
  It would catch a wrong key at import instead of at install, but it is new
  configuration and a second place that must hold the right key, for a mistake
  every Client already refuses.

## Sources / Prior art

- [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md),
  clauses 28 (the signature lives on the Deployment per Package and platform)
  and 54 (what a signature covers, and that the Client verifies it), and
  `fleet_core::package::statement`.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), section 5.1.6: Ed25519
  signing is deterministic, which is why re-signing an entry with the same key
  is harmless.
- No external format was surveyed for the file: it is this project's own
  exchange between its UI and its tool, and its fields are the REST API's.

## Consequences

- Positive: a Package of any number of platforms is signed for a Deployment with
  one download, one command and one import, and no artifact has to reach the
  machine that holds the key.
- Positive: the signed file is a record of what the operator released — type,
  version, every hash and its signature — that can be kept beside the key.
- Positive: nothing changes on the wire, on the Server, or on the Client; a
  signature made this way is byte for byte the one the artifact form makes.
- Negative / trade-offs: **what the operator signs is what the Server said.** A
  compromised Server, or a file altered between download and signing, can put
  the hash of an artifact the operator never saw in front of the key; an
  operator who skips the comparison then signs it, and every Client accepts it.
  ADR-0026's guarantee — nothing reaches a host the operator's key did not sign,
  whatever the Server claims — still holds to the letter, but its strength now
  rests on the operator's check rather than on the operator holding the bytes.
  Q-1 holds for a fleet whose operator signs from the artifacts, which stays
  available and documented as the stronger path; this form trades some of it for
  convenience, by the decider's choice.
- Negative / trade-offs: the file format is an interface between the UI and
  `opamp-fleetctl`, and the two ship together; a change to it is a new `format`
  value, never an edit of `v1`.
- Follow-ups: whether to tighten point 4 into a check (the first alternative)
  once the fleet runs releases this way; a Server-side check of imported
  signatures, should a wrong key at import time turn out to be a mistake that is
  made.

## Enforcement

- `opamp-fleetctl`'s tests sign a signing file and verify every written
  signature against `fleet_core::package::statement` with the public key, as the
  Client does; they refuse a file whose `format` is not
  `opamp-fleet-signing-v1`, whose hash is not 64 lowercase hex characters, or
  that names a platform twice, and assert that nothing was signed then. These
  tests carry `Verifies: ADR-0027`.
- A Server test reads the bundled UI and asserts that the download writes
  `opamp-fleet-signing-v1` and the fields the API serves, and that the import
  calls the signature route; the OpenAPI document must still carry those fields.
  It carries `Verifies: ADR-0027`.
- **Not mechanically decidable:** that the operator compares the hashes before
  signing (point 4). The manual states it and the tool prints what it signs; no
  test can decide whether a human looked.
