# Development stores

The S3-compatible store and the PostgreSQL database a development Server keeps
its artifacts and its records in
([ADR-0049](../docs/adr/0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md),
[ADR-0050](../docs/adr/0050-the-servers-records-may-live-in-postgresql.md)). It
is a Compose project of its own, run on the host:

```sh
docker compose -f dev/compose.yaml up -d     # on the host, from the repository root
```

## Reaching it from the Dev Container

The Dev Container has no Docker socket
([ADR-0002](../docs/adr/0002-dev-container-runtime.md)) and needs none for this:
it reaches the stores **through the host**, over the ports `compose.yaml`
publishes.
[`.devcontainer/forward-dev-stores.sh`](../.devcontainer/forward-dev-stores.sh),
run by `postStartCommand` on every start, listens on `127.0.0.1:9100` and
`127.0.0.1:5432` inside the container and passes each connection on to the same
port on the host, so the same address means the same store on the host and in
the container. The hop to the host stays on this machine.

The host is reached by the name Podman and Docker Desktop both give it,
`host.docker.internal`. Docker Engine on Linux gives it no name; set
`DEV_STORES_HOST` in the container's environment to the host's address on the
bridge (usually `172.17.0.1`).

**The stores are published on the host's loopback alone.** They hold a fixed
development key pair and password, so they are published on `STORES_BIND`,
`127.0.0.1` by default. Whether the forwarder reaches a port bound there depends
on how the container reaches the host:

| Engine                   | `host.docker.internal` leads to                     | `STORES_BIND` to use                                                             |
| ------------------------ | --------------------------------------------------- | -------------------------------------------------------------------------------- |
| Podman (rootless, pasta) | the host's loopback                                 | `127.0.0.1`, the default                                                         |
| Docker Desktop           | the host, through its VM                            | `127.0.0.1`, the default                                                         |
| Docker Engine on Linux   | no such name: `DEV_STORES_HOST`, the bridge gateway | the bridge gateway, the same address as `DEV_STORES_HOST` (usually `172.17.0.1`) |

On Docker Engine a connection from a container arrives on the bridge, never on
the host's loopback, so a port bound to `127.0.0.1` is out of its reach; the
bridge gateway is reachable from the host's containers and not from the network:

```sh
STORES_BIND=172.17.0.1 docker compose -f dev/compose.yaml up -d
```

Check from inside the container with
`curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9100/` — any HTTP
status means the store is reached, a connection error that it is not.

## The S3 store

rustfs is published on port 9100. The Server creates no bucket; create `fleet`
once, with the development key pair of `compose.yaml`:

```sh
curl --aws-sigv4 aws:amz:us-east-1:s3 --user fleet-dev:fleet-dev-secret -X PUT \
  -H "x-amz-content-sha256: $(printf '' | sha256sum | cut -d' ' -f1)" http://127.0.0.1:9100/fleet
```

Then point the Server at it with `[blobs] store = "s3"` and a `[blobs.s3]`
section naming that endpoint, `bucket = "fleet"`, a `region`,
`access_key_id = "fleet-dev"` and a `secret_access_key_file` holding the secret,
mode `0600`. The same settings run the S3 store's tests:
`CLASSIS_TEST_S3_ENDPOINT=http://127.0.0.1:9100 CLASSIS_TEST_S3_BUCKET=fleet
CLASSIS_TEST_S3_ACCESS_KEY_ID=fleet-dev CLASSIS_TEST_S3_SECRET_ACCESS_KEY_FILE=<file>
cargo test -p classis-server s3::`.

## The database

PostgreSQL is published on port 5432. The image creates the database and the
role `fleet`, password `fleet`, on its first start; the Server creates its own
tables. Point the Server at it with `[database] store = "postgres"` and a
`[database.postgres]` section naming `host = "127.0.0.1"`, `dbname = "fleet"`,
`user = "fleet"`, `tls = false` — plaintext, which the loopback alone allows —
and a `password_file` holding `fleet`, mode `0600`. The same settings run the
PostgreSQL store's tests:
`CLASSIS_TEST_POSTGRES_HOST=127.0.0.1 CLASSIS_TEST_POSTGRES_PORT=5432
CLASSIS_TEST_POSTGRES_DBNAME=fleet CLASSIS_TEST_POSTGRES_USER=fleet
CLASSIS_TEST_POSTGRES_PASSWORD_FILE=<file> cargo test -p classis-server postgres::`;
each test works in a schema of its own and drops it.
`CLASSIS_TEST_POSTGRES_CA_FILE` runs them over TLS against a database whose
certificate that root signs.

## Ports

| Port | Service    | What                                                     |
| ---- | ---------- | -------------------------------------------------------- |
| 9100 | rustfs     | S3 API — the development store of the Server's artifacts |
| 5432 | PostgreSQL | The development database of the Server's records         |
