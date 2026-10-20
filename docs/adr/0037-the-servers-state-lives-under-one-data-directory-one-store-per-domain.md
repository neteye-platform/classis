# ADR-0037: The Server's state lives under one data directory, one store per domain behind a port a database could implement, artifact bytes are kept by their hash, the enrolment queue is persisted, and an old layout is moved by an offline migration

- **Status:** 🟢 accepted · clause 10 superseded by [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** the storage ports in `crates/fleet-server/src/` (`agent_store.rs`, `configs.rs`, `deployments.rs`, `packages.rs`, `bootstrap.rs`, `enrolment.rs`, `revocation.rs`, `audit.rs`) and every adapter under `crates/fleet-server/src/fs/`, the wiring in `crates/fleet-server/src/lib.rs` and `crates/fleet-server/src/main.rs`, `data_dir`, `config_dir` and `packages_dir` in `server.toml` and `crates/fleet-server/src/config.rs`, the `server migrate` command, `config/server.toml`, `docs/ARCHITECTURE.md`, and every document that names where the Server keeps its state
- **Supersedes:** [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clauses 20, 33 and 37; [ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md) clause 4; [ADR-0023](0023-configurations-and-the-rest-api.md) clause 10; [ADR-0024](0024-the-fleet-record.md) clause 3; [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) clauses 1 and 19; [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md) clause 4

## Context

The Server keeps its state in two roots that grew one store at a time:

- **`config_dir`** (default `fleet-configs`). Configurations lie in its top level as `<name>.json`
  (ADR-0023 clause 10). Beside them are `agents/`, `labels/`, `audit/`, `revocation/` (the
  certificate register, the revocation list and the host register, ADR-0021 clauses 33 and 37) and
  `bootstrap-certificates/` (ADR-0029 clause 4). The Configuration loader tells its files from the
  subdirectories only by the `.json` extension. The label directory is not owner-only, unlike every
  other directory.
- **`packages_dir`** (default `fleet-packages`). It holds one directory per Package, with its
  artifacts as `<os>-<arch>.bin`, and the Deployments in `deployments/`
  (ADR-0026 clauses 1 and 19). The package loader skips that one subdirectory by name, and fails
  on anything else it does not know.

Each store is a port with a filesystem adapter
([ADR-0006](0006-architecture-style.md)). The ports are file-shaped (`get`, `put`, `remove` of one
record), and every integrity rule is computed by scanning the whole fleet in memory:

- whether a Package is assigned;
- whether a Deployment pins a Package;
- which revisions are still referenced.

A rollout writes the Configuration file and then each Agent file, with no unit that holds them
together. The enrolment window and its queue live in memory only (ADR-0021 clause 20). A restart
loses an approved certificate that its host has not yet collected, although the register already
lists it. Bootstrap entries are keyed by serial alone, while every other certificate store keys by
issuer and serial.

The decisions this ADR follows change what is stored:

- signatures move onto Package entries, and referenced entries go
  ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md));
- Deployments carry Configurations, and one deletion rule asks "is this pinned?"
  ([ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md));
- Hosts become an entity, and labels move into the Agent record
  ([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md));
- host certificates carry subject values
  ([ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)).

The human decided to put the layout in order now, on the filesystem, before the target
architecture's database and object store. The ports are to be cut so that those can follow as
adapters. The target architecture (working note "server split", not an ADR) names PostgreSQL for
about 100 000 Agents and S3-compatible storage for artifacts, content-addressed. Two things are
decided only once its high-availability questions have an ADR: a PostgreSQL adapter, and replacing
the in-memory fleet as the source of truth.

Existing installations must keep their trust data. Starting empty would lose the revocation list,
and a revoked certificate would be admitted again. The project reads no older store shapes inside
the Server (ADR-0026's alternative "Keep a reader for older store and record shapes", rejected).

The decision serves Q-1 (every directory owner-only, no secret in the wrong place) and G-2 (the
Server knows the fleet's state across restarts).

## Decision

We will keep all of the Server's state under one `data_dir`, in one subdirectory per domain, each
behind a port shaped so that a database or an object store can implement it. We will keep
artifact bytes by their SHA-256, persist the enrolment window and queue, and key bootstrap entries
by issuer and serial. An existing installation is moved by a one-shot, offline `server migrate`,
which the Server names instead of reading an old layout.

1. **One key, one root.** `server.toml` names `data_dir` (default `fleet-data`).
   - `config_dir` and `packages_dir` no longer exist. A `server.toml` that names either fails
     startup, naming the key and `server migrate`.
   - The Server creates every directory under `data_dir` owner-only (`0700`) and writes every
     file `0600`. These are Unix modes: the Server ships on Linux only, and built for Windows it
     sets no ACL, so `data_dir` keeps the access its parent directory hands down. Restricting it
     to the Server's account is then the operator's, as no installer exists for the Server
     there.
   - Every record is written through a temporary file and a rename. Where a record answers a
     security decision (the register, the revocation list, the audit), the rename is synced to
     disk before the decision is answered, as today.

2. **The layout is fixed, and no other is read.** Under `data_dir`:

   | Path | One file per | Domain |
   |---|---|---|
   | `configurations/<name>.json` | Configuration, with its retained revisions | Configurations ([ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)) |
   | `deployments/<name>.json` | Deployment | Deployments |
   | `packages/<agent_type>@<version>.json` | Package: identity and entries, no bytes | Packages ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)) |
   | `blobs/<sha256>` | artifact, named by its lowercase hex SHA-256 | Blobs (clause 4) |
   | `agents/<instance_uid>.json` | Agent: report, assignment, labels | Fleet ([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)) |
   | `hosts/<host>.json` | Host | Hosts |
   | `certificates/<issuer>-<serial>.json` | certificate the Server signed | Certificate register |
   | `revocations.json` | the revocation list | Revocations |
   | `bootstrap/<issuer>-<serial>.json`, `.p12` | bootstrap certificate the Server issued | Bootstrap |
   | `enrolment.json` | the window and its pending requests | Enrolment (clause 9) |
   | `audit/audit-<first seq>.jsonl` | audit file | Audit |

   `<issuer>` is the first 16 hex characters of the SHA-256 of the issuer's DER name, and `<serial>`
   is the serial in the register's lowercase hex form. A file or directory the layout does not
   name, a file that does not parse, or a file whose name disagrees with its content fails startup,
   naming the path. The one exception is a temporary file the Server's own write left behind — a
   regular file whose name ends in `.tmp`, whose rename never happened: it is removed at startup,
   since the record beside it is the one before the write.

3. **One port per domain, shaped for a database.**
   - Every domain in clause 2 is a port in its core module, and the filesystem adapters live under
     `fs/`. A port speaks in domain types, never in paths.
   - What must hold together is one call to the port. A rollout writes the Agents' assignments
     and the revisions they pin through one operation. The filesystem adapter writes the
     revisions before the assignments, so a crash leaves at most an unreferenced revision, which
     the next load collects. A database adapter makes the same call one transaction.
   - Integrity questions are port queries, not scans in the caller. Examples are "is this
     Configuration, Package or Deployment pinned by an assignment?" and "which revisions are
     referenced?". The filesystem adapter may answer them from what it holds in memory.
   - A port never assumes that it is the only writer. Nothing outside the adapter caches its
     records across a request without the adapter's say.

4. **Artifact bytes are kept by their hash, behind a blob port.**
   - The port is `put(stream) → (sha256, size)`, `get(sha256) → stream`, `exists(sha256)` and
     `delete(sha256)`.
   - The filesystem adapter streams an upload to a staging file inside `blobs/`, hashes it on the
     way, and renames it to its hash. Bytes that are already stored are stored once.
   - At startup every blob is hashed again, and one whose content does not match its name fails
     startup, naming it.
   - A blob that no entry references is deleted when its last entry goes, and at startup.
   - The size limits of ADR-0033 clause 1 count the blobs.
   - A Package's metadata names a blob by its hash only.

5. **Restates ADR-0026 clause 1. The store lives under `data_dir` and is the Server's only source
   of software.**
   - `packages/` and `blobs/` hold every Package; they are managed through the REST API and
     restored at startup.
   - `OffersPackages` and `AcceptsPackagesStatus` are declared only while the store holds a
     Package; an undeclared capability is never exercised.
   - The directories are owner-only and every file `0600` (clause 1).

6. **Restates ADR-0026 clause 19. The store's layout is fixed, and no other is read.** A Package
   is `packages/<agent_type>@<version>.json`, holding its identity and every entry's metadata, the
   hash of its blob included. The bytes are in `blobs/`. The Deployments are in `deployments/`. A
   loose file, or one that does not parse, fails startup naming the path; skipping it would open a
   store that merely looks empty.

7. **Restates ADR-0023 clause 10. Configurations persist as one JSON file each.**
   `data_dir/configurations/<name>.json`, written through a temp file and an atomic rename, loaded
   at startup; `DELETE` removes the file. A file that does not parse fails startup naming it. What
   the file holds besides the saved fields — the revisions a rollout pins — is ADR-0025's. No
   database is needed for this today; the port allows one (clause 3).

8. **Restates ADR-0024 clause 3. The default adapter is one JSON file per Agent,
   `data_dir/agents/<instance_uid>.json`.**
   - The directory is created owner-only. Writes go through a temp file and an atomic rename.
     Every file is loaded at startup, and a file that does not parse fails startup naming it.
   - The envelope is this adapter's format: scalars, the labels and the effective-configuration
     text are readable JSON; the wire-typed fields are protobuf bytes in base64. That encoding's
     compatibility rules the Baseline already governs, so a field upstream adds round-trips
     unread.
   - The envelope carries a `version`. One this Server does not write fails the load rather than
     being guessed at.

9. **Restates ADR-0021 clause 20. An operator opens an enrolment window for a bounded time, and it
   is closed by default.**
   - `POST /api/v1/enrolment/window` with `{"open_for_secs": n}` opens the window, or moves its end
     to `n` seconds from now. `n` runs from 1 to 86400, and anything else is answered `400`.
   - `GET /api/v1/enrolment/window` reports whether it is open and until when.
     `DELETE /api/v1/enrolment/window` closes it early.
   - The window's end and its pending requests are persisted in `data_dir/enrolment.json`, an
     approved request with its certificate included, before the act that changes them is
     answered. A restart keeps an open window open until its end and keeps its requests. A window
     whose end has passed is closed when it is loaded.
   - When the window closes, every enrolment connection is closed and every pending request
     expires, an approved one whose certificate the host has not yet collected included. That host
     enrols again in the next window.

10. **Restates ADR-0021 clause 33. The Server keeps a register of what it signed.**
    - For each certificate the register holds:
      - issuer, serial and subject;
      - the SHA-256 fingerprint of its public key;
      - `not_after`;
      - the `instance_uid` of the message that carried the CSR;
      - its host (ADR-0021 clause 7);
      - on a renewal, the certificate it renewed, its **predecessor**.
    - The predecessor is the certificate the CSR's renewal proof names (ADR-0021 clause 27), and
      without a proof the certificate the connection presented. It is never the `instance_uid` the
      message names, because that value is self-asserted and a chain must not be left on its
      say-so.
    - A proof is checked against the client CA and its key, so it holds through a Gateway too. A
      downstream Agent without one renews from the Gateway's certificate, and what it renews
      descends from that.
    - An enrolment has no predecessor and is the root of its chain.
    - An issuer is identified by the SHA-256 of its DER-encoded name, so no text form of a name can
      fail to match.
    - The register lives in `data_dir/certificates/`, one file per certificate, and each entry is
      written before the certificate is offered.
    - It holds at most 100 000 certificates, and at most 10 000 in one chain — below one root, the
      first certificate the chain renews from. It refuses a renewal once fewer than 1 000 places
      are left, so renewals alone cannot shut out an enrolment. A CSR beyond any of these is
      refused.
    - An entry stays while the certificate, or one renewed from it, is still valid.
      `GET /api/v1/certificates` lists it.

11. **Restates ADR-0021 clause 37. The list is persisted and bounded.** It lives in
    `data_dir/revocations.json`, is written atomically before the request is answered, and
    survives a restart. It holds at most 100 000 entries, and a revocation beyond that is answered
    `507`. A certificate entry is dropped with its register entry once neither the certificate nor
    any renewal of it is valid. An entry for a certificate the register never held stays until an
    operator removes it.

12. **Restates ADR-0022 clause 4. The file.**
    - The audit is written to `data_dir/audit/audit-<first seq>.jsonl`. The directory is `0700`
      and each file `0600` on Unix, under the data root's restricted ACL on Windows.
    - Each entry is one line. It is written with a single append and synced to disk by one writer
      thread of its own, in the order the decisions were taken. A write that fails partway is cut
      back to the last whole line.
    - A file reaching `[audit] max_file_bytes` (default 64 MiB) is closed and a new one opened.
      The Server keeps `[audit] keep_files` files (default 16) and deletes the oldest. Before it
      does, it records `audit.rotated` with the deleted file's last hash.

13. **Restates ADR-0029 clause 4. The Server records what it issued, keyed by issuer and serial,
    and keeps a PKCS#12 file until its certificate ends, is revoked or its entry is deleted.**
    - Before it answers, the Server writes the bootstrap certificate's record to
      `data_dir/bootstrap/<issuer>-<serial>.json`: the serial, the subject, the SHA-256
      fingerprint of the public key, the issuing time, `not_after`, and whether a PKCS#12 file was
      made. The PKCS#12 file, when one was made, is written beside it as `<issuer>-<serial>.p12`.
      Both are owner-only and written atomically.
    - `GET /api/v1/bootstrap-certificates` lists every entry with whether it is revoked and
      whether its PKCS#12 file can be downloaded (`p12`).
    - `GET /api/v1/bootstrap-certificates/{serial}/p12` answers `200` with the file as
      `application/x-pkcs12`, `Content-Disposition: attachment; filename="bootstrap.p12"` and
      `Cache-Control: no-store`, as often as it is asked. It answers `404` when the certificate
      has no such file, is revoked, has ended, or its entry was deleted. The `{serial}` names the
      entry of the bootstrap CA in force.
    - An entry and its PKCS#12 file are removed once the certificate has ended, or when an
      operator deletes the entry (ADR-0029 clause 15). A revocation with the authority
      `bootstrap` removes the file before it is answered, and lifting the revocation (ADR-0021
      clause 38) does not bring it back.
    - At most 10 000 valid entries are kept, and a request beyond that is answered `409`.
    - A bootstrap certificate is revoked as ADR-0021 clause 34 states, with the authority
      `bootstrap`.
    - The audit records each issuance as `enrolment.bootstrap_issued`, with serial, subject,
      `not_after` and `p12`. It records each download of a PKCS#12 file as
      `enrolment.bootstrap_p12_downloaded` with the serial. It records each deletion as
      `enrolment.bootstrap_deleted` with the serial and subject
      ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)).
    - When the audit cannot be written, nothing is handed out or deleted, and the request is
      answered `503`.

14. **An old layout is moved by `server migrate`, offline, and the Server never reads it.**
    - `server migrate --config-dir <old> --packages-dir <old> --data-dir <new>` runs while the
      Server is stopped. It refuses a `data_dir` that is not empty, and it copies rather than
      moves, so the old directories stay as the backup.
    - What it does with each kind of data:
      - **Trust data:** the certificate register, the revocation list, the host register,
        bootstrap entries with their PKCS#12 files, and the audit files are carried over whole.
        The audit chain is kept: its lines are copied, not rewritten.
      - **Packages:** artifacts go to `blobs/`. Each entry takes the signature a Deployment held
        for it. The statement names no Deployment, so these are the same bytes wherever the entry
        was held; when two Deployments held different signatures, the migration names the entry
        and takes none. A referenced entry is dropped with a line naming it.
      - **Agents:** records are carried over, with each Agent's labels moved into its record.
      - **Configurations and Deployments:** they keep their content. A Configuration loses its
        Selector, and the migration lists every Configuration with the Selector it had, for the
        operator to place in a Deployment
        ([ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)).
        A Configuration without an Agent type is not carried, because the Server would refuse it
        at startup; the migration names it, and its file stays in the old directory for the
        operator to save again with a type.
    - The migration prints what it carried, dropped and listed, and exits non-zero when it could
      not carry trust data.
    - A Server started on an empty `data_dir` while `server.toml` still names `config_dir` or
      `packages_dir` fails startup, naming `server migrate` (clause 1).

**Out of scope:** a PostgreSQL adapter and the end of the in-memory fleet as the source of truth,
which follow the high-availability decision; an S3 adapter for the blob port, a decision of its
own because it adds a dependency; a separate directory for blobs; keeping the effective
configuration other than as the display text it is today; migrating between two `data_dir`
versions, which the first such change decides.

## Alternatives considered

- **Keep `config_dir` and `packages_dir` and only add the new stores beside them.** This is the
  smallest change. It keeps Configurations in a top level shared with every other store,
  Deployments under the package root, a label directory that is not owner-only, and two keys for
  one state.
- **Two roots: one for state, one for bulk artifacts.** It puts the large bytes on their own
  volume, but it is a second key before anyone needs it. A `blob_dir` can be added when one does.
- **Go straight to PostgreSQL and S3.** It reaches the target in one step. But it binds the model
  change to the high-availability questions that are not decided, and makes every test depend on a
  database.
- **Start empty after the update.** It is the simplest. It loses the revocation list, so revoked
  certificates are admitted again (Q-1).
- **Read the old layout in the Server.** No step for the operator. But the project rejected readers
  for older shapes: they are untestable over time and untrue as documentation, and a one-shot tool
  can be tested against fixtures and then left alone.
- **Keep the enrolment queue in memory.** It is simpler. It loses approved certificates on a
  restart and cannot work across two instances.

## Sources / Prior art

- `crates/fleet-server/src/lib.rs`, `main.rs`, `fs/*.rs`: today's roots, subdirectories and
  loaders. Read in the source.
- ADR-0006 (ports and adapters), ADR-0021 clauses 20, 33 and 37, ADR-0022 clause 4, ADR-0023
  clause 10, ADR-0024 clauses 3 and 20, ADR-0026 clauses 1 and 19 with the rejected reader for old
  shapes, ADR-0029 clause 4.
- The target architecture's working note "server split" (PostgreSQL, S3 content-addressed,
  active-active), recorded outside the ADRs.
- The working note of 2026-10-17 on the Server's data model, in which the human chose each point.

## Consequences

- Positive: one key and one tree. Every directory is owner-only, and each directory is the shape of
  a later table or bucket.
- Positive: identical artifacts are stored once, and a blob's name is its integrity check.
- Positive: an approval survives a restart.
- Positive: integrity rules move behind the ports, so a database adapter can enforce them without
  the in-memory scans.
- Negative / trade-offs: every installation runs `server migrate` once, and changes `server.toml`
  to `data_dir`. The changelog says so, step by step.
- Negative / trade-offs: re-hashing every blob at startup costs time with a large store, as
  re-hashing every `.bin` does today.
- Negative / trade-offs: the migration cannot place today's Configurations, and the operator does
  it from the list.
- Follow-ups:
  - The PostgreSQL adapter, after the high-availability decision.
  - The S3 adapter for blobs, with its dependency.
  - Whether a separate blob directory is needed.

## Enforcement

Tests that will carry `Verifies: ADR-0037`:

- A Server on an empty `data_dir` creates the layout of clause 2, every directory owner-only.
- A `server.toml` naming `config_dir` or `packages_dir` fails startup naming `server migrate`.
- A loose file in `data_dir` or a blob whose content does not match its name fails startup naming
  the path.
- Two entries with identical bytes store one blob. Deleting the last entry deletes the blob.
- An approved enrolment survives a restart, and a window whose end passed while the Server was
  down is closed on load.
- A crash between the revision write and the assignment writes of a rollout leaves a state the next
  load accepts, with the orphaned revision collected.
- `server migrate` over a fixture of the old layout carries the register, the revocation list, the
  hosts, the bootstrap entries, the audit files, the Agents with their labels, and the artifacts
  with their signatures. It drops a referenced entry and lists every Configuration's old Selector.
  It refuses a `data_dir` that is not empty.
