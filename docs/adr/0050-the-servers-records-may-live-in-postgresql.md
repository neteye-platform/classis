# ADR-0050: The Server's records may live in PostgreSQL

- **Status:** 🟢 accepted
- **Date:** 2026-10-23
- **Deciders:** Markus Brigl
- **Applies to:** every storage port in `crates/fleet-server/src/`
  (`agent_store.rs`, `configs.rs`, `deployments.rs`, `packages.rs`,
  `bootstrap.rs`, `enrolment.rs`, `revocation.rs`) and every PostgreSQL adapter
  beside the filesystem adapters, the embedded schema and its migrations, the
  wiring in `crates/fleet-server/src/main.rs`, the `[database]` section of
  `server.toml` and its parsing in `crates/fleet-server/src/config.rs`,
  `config/server.toml`, the `server migrate-to-postgres` command, the
  `tokio-postgres`, `deadpool-postgres` and `tokio-postgres-rustls` dependencies
  in `Cargo.toml` and `deny.toml`, the PostgreSQL adapter's tests and the CI job
  that runs them, the postgres service in `observability/compose.yaml` and its
  forward into the Dev Container, `docs/ARCHITECTURE.md`, and every document
  that names where the Server keeps its records
- **Supersedes:**
  [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
  clauses 1, 2, 6, 7, 8, 9, 11 and 13;
  [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)
  clause 2

## Context

The Server keeps every record as files under one `data_dir`, one subdirectory
per domain, each domain behind a port in its core module with a filesystem
adapter under `fs/`
([ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)).
The ports are shaped for a database: they speak in domain types, what must hold
together is one call, and integrity questions are port queries (ADR-0037 clause
3). ADR-0037 left a PostgreSQL adapter to a decision of its own. Artifact bytes
already have a second store
([ADR-0049](0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md)).

Files bind the records to one host and one disk. A backup is a copy of a
directory taken while the Server writes into it, a restore is the reverse, and
nothing but the Server can read the records consistently. The target
architecture recorded outside the ADRs, the working note "server split", puts
every store in PostgreSQL (D7), with the password read from a file and the
connection verified against the database's certificate and host name (D8a).
Running several Server instances against one database is a further step with its
own questions — presence, leases, notifying the other instances — and waits for
a decision of its own.

What a port stores is secret-bearing whatever the backend
([ADR-0024](0024-the-fleet-record.md) clause 6): effective configurations,
bootstrap PKCS#12 files, the certificate register. The specification's Q-1
forbids sending a credential unencrypted beyond the loopback, which holds for
the Server's traffic to its database. Q-3 bounds what a new dependency may
bring:
[ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
keeps the TLS stack on rustls with _ring_, without `aws-lc-rs` and without
OpenSSL, and TLS 1.3 alone.

A reader without this conversation would expect three things that this ADR
decides against: that PostgreSQL replaces the filesystem, that the Server
creates its database, and that with a database the in-memory fleet stops being
what the Server answers from.

## Decision

We will let the operator choose, in `server.toml`, whether the Server's records
live in files under `data_dir` or in one PostgreSQL database, reached through
`tokio-postgres` over TLS 1.3 with the database's certificate and host name
verified, with one PostgreSQL adapter behind every storage port and one Server
per database schema.

1. **Restates ADR-0037 clause 1. One key chooses the store; `data_dir` stays.**
   - `[database] store` is `"fs"`, the default, or `"postgres"`. Any other value
     fails startup naming the key. Both are supported in production.
   - `server.toml` names `data_dir` (default `fleet-data`) with either store.
     With `"fs"` it holds every record; with `"postgres"` it holds the audit
     record and, with the filesystem blob store, the blobs (clause 2).
   - `config_dir` and `packages_dir` no longer exist. A `server.toml` that names
     either fails startup, naming the key and `server migrate`.
   - The Server creates every directory under `data_dir` owner-only (`0700`) and
     writes every file `0600`. These are Unix modes: the Server ships on Linux
     only, and built for Windows it sets no ACL, so `data_dir` keeps the access
     its parent directory hands down. Restricting it to the Server's account is
     then the operator's, as no installer exists for the Server there.
   - Every file is written through a temporary file and a rename. Where a record
     answers a security decision (the register, the revocation list, the audit),
     the rename is synced to disk before the decision is answered.

2. **Restates ADR-0037 clause 2. The layout of `data_dir` is fixed, and no other
   is read.** With `store = "fs"`, under `data_dir`:

   | Path                                       | One file per                               | Domain                                                                                                   |
   | ------------------------------------------ | ------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
   | `configurations/<name>.json`               | Configuration, with its retained revisions | Configurations ([ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)) |
   | `deployments/<name>.json`                  | Deployment                                 | Deployments                                                                                              |
   | `packages/<agent_type>@<version>.json`     | Package: identity and entries, no bytes    | Packages ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md))      |
   | `blobs/<sha256>`                           | artifact, with the filesystem blob store   | Blobs ([ADR-0049](0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md))                     |
   | `agents/<instance_uid>.json`               | Agent: report, assignment, labels          | Fleet ([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md))     |
   | `hosts/<host>.json`                        | Host                                       | Hosts                                                                                                    |
   | `certificates/<issuer>-<serial>.json`      | certificate the Server signed              | Certificate register                                                                                     |
   | `revocations.json`                         | the revocation list                        | Revocations                                                                                              |
   | `bootstrap/<issuer>-<serial>.json`, `.p12` | bootstrap certificate the Server issued    | Bootstrap                                                                                                |
   | `enrolment.json`                           | the window and its pending requests        | Enrolment (clause 9)                                                                                     |
   | `audit/audit-<first seq>.jsonl`            | audit file                                 | Audit                                                                                                    |

   With `store = "postgres"`, `data_dir` holds `audit/` and, with the filesystem
   blob store, `blobs/`, and nothing else. Beside a bucket, a `blobs/` an
   earlier filesystem blob store left is accepted too, as the place
   [ADR-0049](0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md)
   clause 7 copies from; the Server does not create it there.

   `<issuer>` is the first 16 hex characters of the SHA-256 of the issuer's DER
   name, and `<serial>` is the serial in the register's lowercase hex form. A
   file or directory the layout does not name, a file that does not parse, or a
   file whose name disagrees with its content fails startup, naming the path. A
   path of the filesystem layout found under a `data_dir` used with `"postgres"`
   fails startup naming it and `server migrate-to-postgres`. The one exception
   is a temporary file the Server's own write left behind — a regular file whose
   name ends in `.tmp`, whose rename never happened: it is removed at startup,
   since the record beside it is the one before the write.

3. **One PostgreSQL adapter per port, one transaction per call.**
   - Every port of ADR-0037 clause 3 but the blob port and the audit port gets
     an adapter that keeps its records in tables of the Server's schema:
     Configurations with their revisions, Deployments, Package records, Agents
     with their labels and assignments, Hosts, the certificate register, the
     revocation list, bootstrap entries with their PKCS#12 files, and the
     enrolment window with its queue.
   - What one port call writes is one transaction. A rollout's revisions and
     assignments commit together or not at all, and a bootstrap entry commits
     with its PKCS#12 file.
   - Wire-typed fields of an Agent are kept as protobuf bytes, as the filesystem
     envelope keeps them (clause 8), so a field upstream adds round-trips
     unread. Scalars are columns.
   - Text an Agent or a CSR chose — an Agent's effective configuration, a
     certificate's subject — is kept as `bytea`, and every JSON document as
     `json`: PostgreSQL's `text` and `jsonb` refuse a NUL character, which a
     file keeps, and one Agent's report must never fail the writes of others or
     a rollout. The same bytes round-trip as with the filesystem store.
   - A call that answers a security decision returns only after its transaction
     has committed.
   - The audit record stays in `data_dir/audit/` with either store
     ([ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
     clause 12). Moving it into the database is a later decision on audit chains
     per instance.

4. **The in-memory state stays what the Server answers from.** With either
   store, the Server loads every record through its port at startup, answers
   from memory, and writes through the port before an act is answered, as
   ADR-0024 clause 5 states. The database is the durable copy, not a second
   source: nothing but this Server writes to it while it runs (clause 6).

5. **The Server applies its own schema.**
   - The schema is embedded in the binary as numbered migrations. At startup the
     Server applies, in one transaction, every migration the database has not
     yet seen, and records each in a table of its own.
   - A migration only adds: tables, columns with defaults, indexes. A column or
     table is removed only by a release after the one that stopped using it, so
     the release before a change runs on the schema after it.
   - The schema table names the oldest Server version that understands it. A
     database whose schema a Server does not understand fails that Server's
     startup, naming both versions; the Server changes nothing in it.
   - The Server creates tables, indexes and its schema table, and nothing else.
     The database, the role, its rights and its extensions are the operator's.

6. **One Server per database schema.** At startup the Server takes a
   session-level advisory lock named after the schema it works in — the role's
   default — and holds it on a connection of its own while it runs. A second
   Server against the same database and schema fails startup, naming the
   database; Servers in different schemas of one database share nothing, as the
   tables are the schema's. When the lock's connection ends while the Server
   runs, the lock is gone with it: the Server logs an error naming the database
   and refuses every call from then on, so it never writes beside a second
   Server. Several instances against one schema are a later decision.

7. **The connection is TLS 1.3, verified, and configured in `server.toml`
   alone.**
   - `[database.postgres]` names `host`, `port` (default 5432), `dbname`, `user`
     and `password_file`, and optionally `ca_file`. A missing key fails startup
     naming it.
   - The connection requires TLS. The client is built with the TLS 1.3,
     _ring_-only configuration the rest of the project uses, verifies the
     database's certificate against the public roots or the one PEM root
     `ca_file` names, and verifies that it names `host` — what libpq calls
     `verify-full`. `tokio-postgres-rustls` is built with its `ring` feature and
     without `aws-lc-rs`.
   - Without TLS the Server connects only to a loopback IP literal, and only
     when `[database.postgres] tls = false` says so. `tls = false` with any
     other `host` fails startup naming both keys (Q-1).
   - The password is read from `password_file`, which may be read by its owner
     and its group, as an orchestrator mounts a secret for a group, and by
     nobody else, and written by its owner alone; one that others may read, or
     its group may write, fails startup naming it. No password is written into
     `server.toml`, and the Server reads no `PG*` environment variable.
   - Connections come from a `deadpool-postgres` pool. A database that cannot be
     reached at startup fails startup, naming host and database; one lost while
     the Server runs fails the calls that need it, which answer as a failed
     write answers today.
   - Every call is bounded, since its caller holds the Server's locks while a
     record is written: the wait for a pooled connection, the whole call on the
     client's side, and on the database's side each statement, each wait for a
     lock and a transaction left idle; TCP keepalives notice a host that is
     gone. A database that takes a connection and never answers fails the call
     within its bound.

8. **Restates ADR-0037 clause 8, which restates ADR-0024 clause 3. The
   filesystem adapter keeps one JSON file per Agent,
   `data_dir/agents/<instance_uid>.json`; the PostgreSQL adapter keeps one row
   per Agent.**
   - The directory is created owner-only. Writes go through a temp file and an
     atomic rename. Every file is loaded at startup, and a file that does not
     parse fails startup naming it.
   - The envelope is this adapter's format: scalars, the labels and the
     effective-configuration text are readable JSON; the wire-typed fields are
     protobuf bytes in base64. That encoding's compatibility rules the Baseline
     already governs, so a field upstream adds round-trips unread.
   - The envelope carries a `version`. One this Server does not write fails the
     load rather than being guessed at.
   - The PostgreSQL row holds the same fields, the wire-typed ones as `bytea`
     (clause 3). A row that does not decode fails startup naming its
     `instance_uid`.

9. **Restates ADR-0037 clause 9. An operator opens an enrolment window for a
   bounded time, and it is closed by default.**
   - `POST /api/v1/enrolment/window` with `{"open_for_secs": n}` opens the
     window, or moves its end to `n` seconds from now. `n` runs from 1 to 86400,
     and anything else is answered `400`.
   - `GET /api/v1/enrolment/window` reports whether it is open and until when.
     `DELETE /api/v1/enrolment/window` closes it early.
   - The window's end and its pending requests are persisted through the
     enrolment port — in `data_dir/enrolment.json` with the filesystem store, in
     the database with PostgreSQL — an approved request with its certificate
     included, before the act that changes them is answered. A restart keeps an
     open window open until its end and keeps its requests. A window whose end
     has passed is closed when it is loaded.
   - When the window closes, every enrolment connection is closed and every
     pending request expires, an approved one whose certificate the host has not
     yet collected included. That host enrols again in the next window.

10. **Restates ADR-0039 clause 2. The Server keeps a register of what it
    signed.**
    - For each certificate the register holds:
      - issuer, serial and subject;
      - the SHA-256 fingerprint of its public key;
      - `not_after`;
      - the `instance_uid` of the message that carried the CSR;
      - its host (ADR-0036 clause 2);
      - on a renewal, the certificate it renewed, its **predecessor**.
    - The predecessor is the certificate the CSR's renewal proof names (ADR-0039
      clause 1), and without a proof the certificate the connection presented,
      which is never a Gateway host's. It is never the `instance_uid` the
      message names, because that value is self-asserted and a chain must not be
      left on its say-so.
    - A proof is checked against the client CA and its key, so it holds through
      a Gateway too. Behind a Gateway a certificate is renewed only with a
      proof, in its own chain and host.
    - An enrolment has no predecessor and is the root of its chain.
    - An issuer is identified by the SHA-256 of its DER-encoded name, so no text
      form of a name can fail to match.
    - The register lives in `data_dir/certificates/`, one file per certificate,
      with the filesystem store, and in one row per certificate with PostgreSQL.
      Each entry is written before the certificate is offered.
    - It holds at most 100 000 certificates, and at most 10 000 in one chain —
      below one root, the first certificate the chain renews from. It refuses a
      renewal once fewer than 1 000 places are left, so renewals alone cannot
      shut out an enrolment. A CSR beyond any of these is refused.
    - An entry stays while the certificate, or one renewed from it, is still
      valid. `GET /api/v1/certificates` lists it.

11. **Restates ADR-0037 clause 11, which restates ADR-0021 clause 37. The list
    is persisted and bounded.** It lives in `data_dir/revocations.json` with the
    filesystem store and in the database with PostgreSQL, is written before the
    request is answered — atomically, or in one committed transaction — and
    survives a restart. It holds at most 100 000 entries, and a revocation
    beyond that is answered `507`. A certificate entry is dropped with its
    register entry once neither the certificate nor any renewal of it is valid.
    An entry for a certificate the register never held stays until an operator
    removes it.

12. **Restates ADR-0037 clause 13, which restates ADR-0029 clause 4. The Server
    records what it issued, keyed by issuer and serial, and keeps a PKCS#12 file
    until its certificate ends, is revoked or its entry is deleted.**
    - Before it answers, the Server writes the bootstrap certificate's record:
      the serial, the subject, the SHA-256 fingerprint of the public key, the
      issuing time, `not_after`, and whether a PKCS#12 file was made. With the
      filesystem store the record is `data_dir/bootstrap/<issuer>-<serial>.json`
      and the PKCS#12 file, when one was made, is written beside it as
      `<issuer>-<serial>.p12`; both are owner-only and written atomically. With
      PostgreSQL the record and the file are one row, written in one
      transaction.
    - `GET /api/v1/bootstrap-certificates` lists every entry with whether it is
      revoked and whether its PKCS#12 file can be downloaded (`p12`).
    - `GET /api/v1/bootstrap-certificates/{serial}/p12` answers `200` with the
      file as `application/x-pkcs12`,
      `Content-Disposition: attachment; filename="bootstrap.p12"` and
      `Cache-Control: no-store`, as often as it is asked. It answers `404` when
      the certificate has no such file, is revoked, has ended, or its entry was
      deleted. The `{serial}` names the entry of the bootstrap CA in force.
    - An entry and its PKCS#12 file are removed once the certificate has ended,
      or when an operator deletes the entry (ADR-0029 clause 15). A revocation
      with the authority `bootstrap` removes the file before it is answered, and
      lifting the revocation (ADR-0021 clause 38) does not bring it back.
    - At most 10 000 valid entries are kept, and a request beyond that is
      answered `409`.
    - A bootstrap certificate is revoked as ADR-0021 clause 34 states, with the
      authority `bootstrap`.
    - The audit records each issuance as `enrolment.bootstrap_issued`, with
      serial, subject, `not_after` and `p12`. It records each download of a
      PKCS#12 file as `enrolment.bootstrap_p12_downloaded` with the serial. It
      records each deletion as `enrolment.bootstrap_deleted` with the serial and
      subject ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)).
    - When the audit cannot be written, nothing is handed out or deleted, and
      the request is answered `503`.

13. **Restates ADR-0037 clause 6, which restates ADR-0026 clause 19. The store's
    layout is fixed, and no other is read.** With the filesystem store a Package
    is `packages/<agent_type>@<version>.json`, holding its identity and every
    entry's metadata, the hash of its blob included; the Deployments are in
    `deployments/`. A loose file, or one that does not parse, fails startup
    naming the path; skipping it would open a store that merely looks empty.
    With PostgreSQL a Package and its entries, and each Deployment, are rows of
    the Server's schema, and a row that does not decode fails startup naming it.
    The bytes are in the blob store with either.

14. **Restates ADR-0037 clause 7, which restates ADR-0023 clause 10.
    Configurations persist one record each.** With the filesystem store each is
    `data_dir/configurations/<name>.json`, written through a temp file and an
    atomic rename, loaded at startup; `DELETE` removes the file, and a file that
    does not parse fails startup naming it. With PostgreSQL each is a row, with
    its revisions in rows of their own, and `DELETE` removes them in one
    transaction. What the record holds besides the saved fields — the revisions
    a rollout pins — is ADR-0025's.

15. **An existing `data_dir` is copied into PostgreSQL offline.**
    `server migrate-to-postgres --from <data_dir> --data-dir <new>` runs while
    the Server is stopped, with the `server.toml` that names the database.
    - It refuses a database that holds any of the Server's tables, and a
      `--data-dir` that is not empty.
    - It applies the schema, copies every record of the old `data_dir` into the
      database in one transaction, and copies `audit/` and, with the filesystem
      blob store, `blobs/` into the new `data_dir`, the audit lines unchanged so
      the chain holds.
    - It copies rather than moves: the old `data_dir` stays as the backup. It
      prints what it copied and exits non-zero when it could not copy all of it,
      leaving the database without the Server's tables.
    - Moving records back from PostgreSQL to files is not provided.

16. **The database is external; the adapter only connects to it.** In production
    the database, its role, its replication and its backups are the operator's.
    - For development, PostgreSQL runs as a service of
      `observability/compose.yaml`, the Compose project on the host beside the
      Dev Container ([ADR-0002](0002-dev-container-runtime.md)). The Dev
      Container forwards its port onto its own loopback, so a development Server
      reaches it at `127.0.0.1:5432`, with `tls = false` as clause 7 allows on
      the loopback.
    - The PostgreSQL adapter's tests run against the database that
      `FLEET_TEST_POSTGRES_HOST`, `FLEET_TEST_POSTGRES_PORT`,
      `FLEET_TEST_POSTGRES_DBNAME`, `FLEET_TEST_POSTGRES_USER` and
      `FLEET_TEST_POSTGRES_PASSWORD_FILE` name, over TLS against the root
      `FLEET_TEST_POSTGRES_CA_FILE` names when it is set. CI runs them in a job
      against a PostgreSQL it starts with TLS 1.3 and a certificate of a CA made
      for the run, its image pinned. Where no database is named, the tests are
      skipped and say so; they never start a database of their own. Each test
      works in a schema of its own and drops it afterwards.

**Out of scope:** several Server instances against one database, presence,
leases and notifying other instances; the audit record in the database; paging
and filtering in the database; moving records from PostgreSQL back to files;
anything that runs, provisions, replicates or monitors a production database.

## Alternatives considered

- **PostgreSQL replaces the filesystem, which stays as a test double only.**
  This is where the working note ends up once several instances run. One Server
  needs no database, and every small installation would need one before it gains
  anything. Rejected, as for the blob store.
- **`sqlx`.** Widely used, with a pool and migrations built in. Its compile-time
  checked queries need a database or prepared offline data at build time, and
  its tree is larger. Its TLS feature set has to be kept off `aws-lc-rs` as
  well. Rejected for the smaller `tokio-postgres`, whose queries are plain SQL
  tested against a real database.
- **`diesel`.** An ORM with a query DSL, synchronous at its core, with
  `diesel-async` apart. It brings a model layer the ports do not need. Rejected.
- **SQLite as the second store.** Embedded and simple, but it binds the records
  to one host as files do, and it is no step towards several instances.
  Rejected.
- **The database as the source of truth, queried per request.** It is what
  several instances will need. With one Server per database it adds a round trip
  to every report and changes every read path at once. Rejected for this step;
  the in-memory state stays (clause 4).
- **The Server creates its database and role.** It would need a superuser's
  credentials and takes a decision that belongs to whoever runs the database.
  Rejected.
- **A client certificate towards the database instead of a password.** Managed
  services such as RDS offer no client-certificate sign-in, as the working note
  found. Rejected; the password comes from a file.
- **Accept `PG*` environment variables, as libpq does.** `PGSSLMODE=disable` or
  `PGHOST` in a service's environment would move the Server to plaintext or to
  another database without `server.toml` saying so. Rejected.
- **Migrate at Server startup instead of a command.** It saves a step, but the
  first start would copy a whole `data_dir` while serving nothing, and a failure
  would leave a half-filled database for the next start. Rejected for an offline
  copy, like ADR-0037 clause 14.

## Sources / Prior art

- The working note "server split", sections D7, D8a and D10, recorded outside
  the ADRs.
- `tokio-postgres` 0.7.18
  ([docs.rs](https://docs.rs/tokio-postgres/0.7.18/tokio_postgres/),
  [repository](https://github.com/rust-postgres/rust-postgres)), MIT or
  Apache-2.0: `SslMode::{Disable, Prefer, Require}` and `ChannelBinding` in
  `src/config.rs`.
- `deadpool-postgres` 0.14.2
  ([docs.rs](https://docs.rs/deadpool-postgres/0.14.2/deadpool_postgres/)), MIT
  or Apache-2.0, feature `rt_tokio_1`.
- `tokio-postgres-rustls` 0.14.0
  ([repository](https://github.com/jbg/tokio-postgres-rustls)), MIT, features
  `ring` and `aws-lc-rs`, neither on by default; it passes the host to rustls as
  the server name. A probe built with `tokio-postgres` (`runtime`),
  `deadpool-postgres` (`rt_tokio_1`) and `tokio-postgres-rustls` (`ring`) over a
  TLS 1.3-only, _ring_-only `rustls::ClientConfig` resolved `ring` and `rustls`
  0.23 with no `aws-lc-rs` and no OpenSSL, and built.
- [PostgreSQL: SSL support in libpq](https://www.postgresql.org/docs/current/libpq-ssl.html),
  for `verify-full`, and
  [explicit locking: advisory locks](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS).
- The code as it stands: the ports in `crates/fleet-server/src/` (`AgentStore`,
  `ConfigBackend`, `DeploymentBackend`, `PackageBackend`, `BootstrapStore`,
  `EnrolmentStore`, `LedgerStore`), their adapters under
  `crates/fleet-server/src/fs/`, `server migrate` in
  `crates/fleet-server/src/main.rs` and `crates/fleet-server/src/migrate.rs`,
  and the TLS 1.3 provider in `crates/opamp/src/tls.rs`.

## Consequences

- Positive: the records can live in a database the operator replicates, backs up
  and restores with its own tools, apart from the Server's host.
- Positive: the ports, the core and the REST API do not change, and the
  filesystem store remains the simplest installation.
- Positive: a later step to several instances starts from adapters that exist
  and a schema that is already migrated additively.
- Negative / trade-offs: three new dependencies for `cargo-deny` to check, and a
  feature set that must stay off `aws-lc-rs`.
- Negative / trade-offs: two stores per port to test and document. The
  PostgreSQL tests need a database, so they run in a CI job of their own and
  against the development stack, and are skipped in a plain `cargo test`.
- Negative / trade-offs: with PostgreSQL the Server's state is in two places,
  the database and `data_dir` (the audit record, and blobs with the filesystem
  blob store). A backup takes both.
- Negative / trade-offs: the whole fleet is still loaded at startup and held in
  memory, so a start against a large database takes as long as reading it.
- Follow-ups: several Server instances against one database, with presence,
  leases and notifications; the audit record in the database, one chain per
  instance; paging and filtering the REST API in the database; how a backup
  takes the database and `data_dir` together.

## Enforcement

Tests that will carry `Verifies: ADR-0050`:

- One contract test per port runs against both adapters: what is written is
  loaded back, a call that fails partway leaves nothing of itself, and a
  rollout's revisions and assignments are both present or both absent. Against
  PostgreSQL it runs in the CI job with a PostgreSQL service, and is reported
  skipped where no database is named.
- An unknown `[database] store`, a missing `[database.postgres]` key,
  `tls = false` with a host that is not a loopback IP literal, a `password_file`
  others may read, and one its group may write each fail startup naming the key;
  one its group may read is accepted.
- A second Server against the same database and schema fails startup naming it;
  a Server whose lock's session is ended logs it and refuses every call.
- A database whose schema names an oldest version above the Server's fails
  startup and is left unchanged; a database one migration behind is migrated at
  startup.
- A `data_dir` holding `agents/` used with `store = "postgres"` fails startup
  naming `server migrate-to-postgres`.
- `server migrate-to-postgres` over a fixture `data_dir` carries every record,
  keeps the audit chain verifiable, refuses a database holding the Server's
  tables, and leaves the old `data_dir` unchanged.
- Setting `PGHOST` or `PGSSLMODE` in the environment does not change the
  database or allow plaintext.
- A database that never answers fails startup within the bound of a call, and
  one that stops answering while the Server runs fails the call within it.
- A database certificate that does not name `host`, or that no root of `ca_file`
  signed, is refused.
- `cargo tree` of the Server contains neither `aws-lc-rs` nor `openssl`;
  `cargo-deny` already fails on a licence or source outside the allow list.
