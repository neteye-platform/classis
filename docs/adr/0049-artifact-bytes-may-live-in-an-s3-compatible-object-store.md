# ADR-0049: Artifact bytes may live in an S3-compatible object store

- **Status:** 🟢 accepted
- **Date:** 2026-10-23
- **Deciders:** Markus Brigl, Davide Zeni
- **Applies to:** the blob port in `crates/classis-server/src/blobs.rs`, its
  filesystem adapter in `crates/classis-server/src/fs/blobs.rs` and every S3
  adapter beside it, the wiring in `crates/classis-server/src/main.rs`, the
  `[blobs]` section of `server.toml` and its parsing in
  `crates/classis-server/src/config.rs`, `config/server.toml`, the `object_store`
  dependency in `Cargo.toml` and `deny.toml`, the S3 adapter's tests and the CI
  job that runs them, the rustfs service in `dev/compose.yaml` and its
  forward into the Dev Container, `docs/ARCHITECTURE.md`, and every document
  that names where the Server keeps artifacts
- **Supersedes:**
  [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
  clauses 4 and 5

## Context

The Server keeps every Package artifact as a file named by its SHA-256 under
`data_dir/blobs/`, behind a blob port of five operations: `put`, `get`,
`exists`, `delete` and `list`
([ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
clause 4). Uploads go through the Operator plane, so the Server hashes every
artifact itself
([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)),
and downloads are streamed to an Agent over its admitted connection
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
ADR-0037 cut the port so that an object store could implement it, and left the
S3 adapter to a decision of its own because it adds a dependency.

The artifacts are the largest part of the Server's state: one Package of 1 GiB
is allowed per entry (`max_package_size_bytes`), and the fleet's software
multiplies that. On the Server's host they share a disk with the audit record
and the register, are backed up with them, and bind the Server to one machine.
The target architecture recorded outside the ADRs, the working note "server
split", puts artifacts in S3-compatible storage, content-addressed and
immutable, streamed through the Server in both directions, with the S3 client's
credential chain towards the store. The rest of that architecture — PostgreSQL,
several Server instances — waits for a decision on high availability; the
artifacts do not depend on it.

The specification's goal G-19 asks that the artifacts can live outside the
Server's host. Q-1 forbids sending a package unencrypted beyond the loopback,
which holds for the Server's own traffic to a store as much as for an Agent's.
Q-3 bounds what a new dependency may bring:
[ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
keeps the TLS stack on rustls with _ring_ and no C toolchain, and the Server
speaks TLS 1.3 alone.

A reader without this conversation would expect three things that this ADR
decides against: that S3 replaces the filesystem, that the Server hashes every
stored object again at startup as it hashes every file, and that the store's
endpoint and options come from the `AWS_*` environment variables, as the S3
client reads them by default.

## Decision

We will let the operator choose, in `server.toml`, whether the blob port is
served by the filesystem under `data_dir` or by one bucket of an S3-compatible
object store, reached through the `object_store` crate over TLS 1.3 and streamed
through the Server in both directions.

1. **Restates ADR-0037 clause 4. Artifact bytes are kept by their hash, behind a
   blob port.**
   - The port is `put(stream) → (sha256, size)`, `get(sha256) → stream`,
     `exists(sha256)`, `delete(sha256)` and `list() → [(sha256, size)]`. It is
     synchronous; an adapter that speaks an asynchronous protocol bridges inside
     itself, and no caller changes.
   - A blob is named by the lowercase hex SHA-256 of its bytes and by nothing
     else. Bytes already stored are stored once.
   - A blob that no Package entry references is deleted when its last entry
     goes, and at startup.
   - The size limits of ADR-0033 clause 1 count the blobs.
   - A Package's metadata names a blob by its hash only.

2. **One store, chosen in `server.toml`.** `[blobs] store` is `"fs"`, the
   default, or `"s3"`. Any other value fails startup naming the key. Both are
   supported in production. The store is read and written by one Server, unless
   a later decision on several Server instances says how they share one bucket
   and prefix.

3. **The filesystem store** keeps one file per blob in `data_dir/blobs/`. It
   streams an upload to a staging file inside `blobs/`, hashes it on the way,
   and renames it to its hash. At startup every blob is hashed again, and one
   whose content does not match its name fails startup, naming it.

4. **The S3 store keeps one object per blob under a fixed layout.**
   - `[blobs.s3]` names `endpoint`, `bucket`, `region` and an optional `prefix`.
     Objects live at `<prefix>blobs/<sha256>`; an upload in progress lives at
     `<prefix>staging/<random>`. The Server touches no key outside `<prefix>`. A
     key under `<prefix>blobs/` that is not a hash, or any other key under
     `<prefix>`, fails startup naming the key; a key under `<prefix>staging/` is
     deleted at startup.
   - The Server does not create the bucket. A bucket that does not exist or
     cannot be listed fails startup, naming the bucket and the error.
   - `put` streams the upload into a multipart upload at a staging key and
     hashes it on the way. Once the hash is known, the Server copies the staging
     object to its hash key unless that key already exists, then deletes the
     staging object. A stream that fails leaves no object under `blobs/`.
   - At startup the Server lists `<prefix>blobs/` for each blob's hash and size
     and downloads nothing. The integrity of what it serves rests on the hash it
     computed at upload, on the signature over every artifact, and on the hash
     the Client checks before it installs
     ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
   - `get` streams the object through the Server to the Agent. The fleet never
     reaches the store, and the Server hands out no presigned URL, neither for
     downloads nor for uploads.

5. **The S3 connection is TLS 1.3 and is configured in the Server's
   configuration alone.**
   - `endpoint` is `https://`. An `http://` endpoint is accepted only on the
     loopback, and any other fails startup naming the key (Q-1).
   - The HTTP client is built with the TLS 1.3, _ring_-only configuration the
     rest of the project uses, and `object_store` is built without its
     `aws-lc-rs` feature. `[blobs.s3] ca_file` adds one PEM root for a store
     whose certificate no public root signs.
   - Endpoint, region, bucket, prefix and every TLS or HTTP option come from the
     Server's own configuration — `server.toml` and whatever layer a later
     decision adds to it — and from nothing else. The Server reads no `AWS_*`
     variable that would change them, such as `AWS_ENDPOINT` or
     `AWS_ALLOW_HTTP`.
   - Every request is bounded: its connection, and the silence before its answer
     begins and between two pieces of it, with a bounded number of retries in a
     bounded time. A store that stops answering fails the call that needs it,
     and no request to the store runs while the Server holds the lock its offers
     and listings wait for.
   - A `prefix` holding a character the S3 client would percent-encode fails
     startup naming the key, since the keys the Server writes would not be those
     it lists.

6. **Credentials are never written into `server.toml`.**
   - With `access_key_id` and `secret_access_key_file` set, the Server reads the
     secret from that file and signs with that key pair. An `access_key_id`
     without the file, or the reverse, fails startup naming both keys.
   - The file may be read by its owner and its group, as an orchestrator mounts
     a secret for a group (`0440` with Kubernetes' `fsGroup`), and by nobody
     else, and written by its owner alone: a file others may read, or its group
     may write, fails startup naming the key.
   - Without them, the Server uses the workload identity of its platform, in
     this order: a web identity token (`AWS_WEB_IDENTITY_TOKEN_FILE` with
     `AWS_ROLE_ARN`), the container credentials of ECS or EKS
     (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, or
     `AWS_CONTAINER_CREDENTIALS_FULL_URI` with the EKS Pod Identity token
     `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`), and the instance metadata
     service. These are the only `AWS_*` variables it reads.

7. **Switching from the filesystem to S3 copies what is missing.** When
   `store = "s3"` and `data_dir/blobs/` exists, the Server hashes, at startup,
   every file there that a Package entry references and that the bucket does not
   hold, uploads it as `put` does, and logs each one. A file whose content does
   not match its name fails startup, naming it. The Server does not delete
   `data_dir/blobs/`, does not write to it again, and with `store = "s3"` does
   not create it; removing it is the operator's. The reverse switch copies
   nothing: a Package entry whose blob the chosen store does not hold fails
   startup, naming the entry.

8. **Restates ADR-0037 clause 5, which restates ADR-0026 clause 1. The store is
   the Server's only source of software.**
   - The Package records in the Server's record store and the chosen blob store
     hold every Package; they are managed through the REST API and restored at
     startup.
   - `OffersPackages` and `AcceptsPackagesStatus` are declared only while the
     store holds a Package; an undeclared capability is never exercised.
   - The directories under `data_dir` are owner-only and every file `0600`
     (ADR-0037 clause 1).

9. **The store is external; the adapter only connects to it.** The Server ships
   with no object store and creates nothing in one but the objects of clause 4.
   In production the bucket, its credentials, its policies, its retention and
   its backups are the operator's.
   - For development, rustfs runs as a service of `dev/compose.yaml`, the
     Compose project of the development stores on the host beside the Dev
     Container ([ADR-0002](0002-dev-container-runtime.md)). The Dev Container
     forwards its port onto its own loopback, so a development Server reaches it
     at an `http://127.0.0.1` endpoint that clause 5 allows, through
     `[blobs.s3]` like any other store.
   - The S3 adapter's tests run against the store that `CLASSIS_TEST_S3_ENDPOINT`,
     `CLASSIS_TEST_S3_BUCKET` and the credentials of clause 6 name. CI runs them
     in a job with a rustfs service, its image pinned. Where no store is named,
     the tests are skipped and say so; they never start a store of their own.
   - The project supports S3-compatible stores in general; rustfs is the one
     development and CI use.

**Out of scope:** Package metadata outside `data_dir`, which follows the
decision on PostgreSQL; a bucket shared by several Server instances, which
follows the decision on high availability; Object Lock and bucket versioning,
which the operator may enable but the Server neither needs nor checks;
server-side encryption beyond what the bucket's own default applies; moving
blobs from S3 back to the filesystem; anything that runs, provisions or monitors
a production store.

## Alternatives considered

- **S3 replaces the filesystem, which stays as a test double only.** This is
  where the working note ends up once PostgreSQL holds the metadata. Without
  PostgreSQL the metadata stays under `data_dir` anyway, so S3 alone makes no
  installation stateless, and every installation would need an object store
  before it gains anything. Rejected for now.
- **`aws-sdk-s3`.** The official SDK reads every credential source AWS defines,
  the shared config files included. It brings the largest dependency tree of the
  three options and its own HTTP and TLS stack, which is more for `cargo-deny`
  and Q-3 to check. Rejected.
- **`rust-s3`.** Small, but it lacks web identity and container credentials, so
  it misses the workload identity this decision asks for. Rejected.
- **`object_store` with its default `aws` feature.** It pulls `aws-lc-rs`, a C
  build with cmake, against ADR-0013. The `aws-base`, `ring` and `reqwest`
  features build the same client on _ring_.
- **Hash every object again at startup.** That downloads the whole store at
  every start, which for a fleet's software costs minutes and egress. The
  signature and the Client's own hash check already refuse altered bytes.
  Rejected.
- **Hash every download on its way to the Agent.** It detects an altered object
  on the Server, at the cost of CPU per download, and only after the bytes have
  been sent. The Client refuses them anyway. Rejected.
- **Presigned URLs for downloads or uploads.** They move the traffic off the
  Server, but the fleet would then reach the store directly, outside the
  admission by client certificate, and an upload would bypass the Server's own
  hash and the audit record. Rejected, as the working note decided.
- **Take the store's configuration from the `AWS_*` environment, as the S3
  client does by default.** `AWS_ALLOW_HTTP` or `AWS_ENDPOINT` set in a
  service's environment would then move the Server to plaintext or to another
  store without `server.toml` saying so. Rejected.
- **S3 tests only where a developer names a store.** No service in CI, nothing
  in the development stack. A defect in the S3 adapter would then be found only
  by whoever runs the tests against a store, not by every pull request.
  Rejected.
- **The stores inside the development observability stack.** One stack to
  start and forward on the host, but it tied the stores to a stack the project
  no longer carries. Rejected.
- **MinIO as the reference store.** The working note named it. MinIO no longer
  maintains its open source distribution; rustfs is S3-compatible, Apache-2.0,
  and reached 1.0 in 2026. Rejected in favour of rustfs.
- **An explicit copy command in `classisctl` instead of copying at
  startup.** It keeps startup free of a long first run, but adds a command and a
  state in which the Server refuses to start until it has run. Rejected.

## Sources / Prior art

- The working note "server split", sections D8, D8a and D10, recorded outside
  the ADRs.
- `object_store` 0.14.2
  ([docs.rs](https://docs.rs/object_store/0.14.2/object_store/),
  [repository](https://github.com/apache/arrow-rs-object-store)), MIT or
  Apache-2.0: its features `aws`, `aws-base`, `ring` and `reqwest`; the
  credential providers in `src/aws/builder.rs` (static keys, web identity, ECS
  task, EKS pod, instance metadata); `with_http_connector`, which takes a
  `reqwest::Client`; `with_root_certificate` and `with_allow_http`. A probe
  built with `aws-base`, `ring` and `reqwest` resolved `ring` and `reqwest` 0.13
  with no `aws-lc-rs` and ran.
- [`AmazonS3Builder`](https://docs.rs/object_store/0.12.4/object_store/aws/struct.AmazonS3Builder.html),
  for the environment variables `from_env` reads.
- [RustFS documentation](https://docs.rustfs.com/) and
  [RustFS 1.0 reaches GA](https://linuxiac.com/rustfs-1-0-s3-compatible-object-storage-reaches-ga/):
  Apache-2.0, S3-compatible, multipart uploads, and MinIO's end of maintenance
  of its open source products.
- The code as it stands: the `BlobStore` port in
  `crates/classis-server/src/blobs.rs`, the filesystem adapter in
  `crates/classis-server/src/fs/blobs.rs`, and the TLS 1.3 provider in
  `crates/opamp/src/tls.rs`.

## Consequences

- Positive: G-19. The fleet's software can live in storage that scales, is
  replicated and is backed up apart from the Server, and the Server's disk holds
  only its records.
- Positive: the port is unchanged, so the package store, the REST API and the
  delivery to Agents do not change, and the filesystem store remains the
  simplest installation.
- Positive: workload identity lets a Server in a cloud reach its bucket with no
  secret on disk.
- Negative / trade-offs: a new dependency, `object_store`, with `reqwest`'s
  stream feature and an XML parser, for `cargo-deny` to check. Its feature set
  must stay off `aws-lc-rs`.
- Negative / trade-offs: an object altered in the bucket is not detected by the
  Server; it is served, and the Client refuses it. The Server's integrity check
  at startup covers the filesystem store only.
- Negative / trade-offs: two stores to test and document. The S3 tests need a
  store, so they run in a CI job of their own and against the development stack,
  and are skipped in a plain `cargo test`.
- Negative / trade-offs: a first start on S3 with a large `data_dir/blobs/`
  takes as long as the upload of what is missing.
- Follow-ups: Package metadata and the other stores in PostgreSQL, and several
  Server instances sharing one bucket, after the decision on high availability;
  whether the sweep of unreferenced blobs moves to a background task once the
  store is shared.

## Enforcement

Tests that will carry `Verifies: ADR-0049`:

- One contract test of the blob port runs against both stores: `put` of
  identical bytes stores one blob, `get` returns them, `delete` of an absent
  blob is no error, and `list` names every blob with its size. Against S3 it
  runs in the CI job with a rustfs service, and is reported skipped where no
  store is named.
- A stream that fails during `put` leaves no object under `blobs/`, and a
  leftover staging object is deleted at the next startup.
- A key under the prefix that the layout does not name fails startup, naming it.
- `store = "s3"` with an `http://` endpoint that is not the loopback, with
  `access_key_id` but no `secret_access_key_file`, with a secret file others may
  read or its group may write, or with an unknown `store` value fails startup
  naming the key; a secret file its group may read is accepted.
- Setting `AWS_ENDPOINT` or `AWS_ALLOW_HTTP` in the environment does not change
  the endpoint or allow plaintext.
- A store that takes the connection and never answers fails the call within its
  bound; a slow request holds no reader of the Packages; a store that cannot say
  whether it holds a blob fails the upload with its error and keeps the blob.
- With `store = "s3"` and a `data_dir/blobs/` holding a referenced artifact, the
  first startup uploads it and leaves the file; a file whose content does not
  match its name fails startup.
- With `store = "s3"` and no `data_dir/blobs/`, startup creates none.
- `cargo tree` of the Server contains no `aws-lc-rs`; `cargo-deny` already fails
  on a licence or source outside the allow list.
