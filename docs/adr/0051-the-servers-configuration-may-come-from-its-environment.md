# ADR-0051: The Server's configuration may come from its environment

- **Status:** 🟢 accepted
- **Date:** 2026-10-23
- **Deciders:** Markus Brigl
- **Applies to:** the loading of `server.toml` in
  `crates/fleet-server/src/config.rs` and the argument parsing in
  `crates/fleet-server/src/main.rs`, every subcommand of the `server` binary
  that reads its configuration, the `[rest.auth]` and `[telemetry_offer]`
  sections and their new `basic_users_file` and `headers_file` keys,
  `config/server.toml`, `docs/ARCHITECTURE.md`, and every document that tells an
  operator how to configure the Server
- **Supersedes:**
  [ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
  clause 23

## Context

Both binaries are configured from TOML, and the file is the whole configuration:
no setting is read from the environment
([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
clause 23). `ServerConfig::load` in `crates/fleet-server/src/config.rs` reads
`server.toml` with `toml::from_str` into structs that carry
`deny_unknown_fields`, and runs on the defaults when the file does not exist.
`parse_args` in `crates/fleet-server/src/main.rs` takes the path from `--config`
and defaults to `server.toml` in the working directory, so a mistyped `--config`
path also starts the Server on its defaults.

The Server is to run in a container. A container is configured by its
orchestrator, and the orchestrator's natural channel is the environment: a
variable per setting, changed per deployment without rebuilding the image or
mounting a file. Every setting of `server.toml` must be reachable that way, the
PostgreSQL connection of
[ADR-0050](0050-the-servers-records-may-live-in-postgresql.md) and the object
store of
[ADR-0049](0049-artifact-bytes-may-live-in-an-s3-compatible-object-store.md)
among them.

Secrets must not travel in the environment. A container's environment is shown
by `docker inspect`, readable in `/proc/<pid>/environ` by the same user, copied
into crash reports and inherited by every child process. Docker's secrets reach
a container as files under `/run/secrets/`, and its official images read a
`…_FILE` variable that names such a file. The Server already keeps every secret
it needs in a file named by a `*_file` key: the PostgreSQL password, the S3
secret key, the CA keys. Two tables of `server.toml` hold sensitive values
inline: `[rest.auth.basic_users]`, whose Argon2id hashes an attacker can attack
offline
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 26), and `[telemetry_offer.headers]`, which typically carries an access
token for the receiving backend.

The keys of those two tables are data — user names and header names — not
schema. An environment variable name is upper-case and limited to letters,
digits and `_` in practice, so a user name like `fleet-admin` or a header like
`X-Scope-OrgID` does not survive the trip through a variable name.

A reader without this conversation would expect two things this ADR decides
against: that the environment may carry a password because twelve-factor apps do
so, and that an unknown variable with the Server's prefix is ignored, as most
programs ignore the environment they do not know.

## Decision

We will layer the Server's configuration as defaults, then an optional
`server.toml`, then every `FLEET_SERVER__…` variable of its environment, each
variable setting one key of the same document and checked as strictly as the
file, and let the environment carry paths to secrets but never a secret itself.

1. **Restates ADR-0010 clause 23. Both binaries are configured from TOML; the
   Server's configuration may also come from its environment.** `server.toml`
   and `supervisor.toml` are parsed with the `toml` crate into `serde` structs.
   The Client takes its path from `--config`, defaulting to the file of that
   name in the working directory, runs on defaults when that file does not
   exist, and reads no setting from the environment. The Server builds one TOML
   document from three sources, each later one winning per key: its built-in
   defaults; `server.toml`, when one is read; and its environment, as clauses 2
   to 6 say. `RUST_LOG` filters log output and configures nothing else in either
   binary.

2. **Which file the Server reads.** `--config <path>` names the file; without
   it, `FLEET_SERVER_CONFIG` names it. A file named either way that does not
   exist fails startup, naming the path. Without both, the Server reads
   `server.toml` in the working directory when it exists and starts from
   defaults and its environment when it does not. Every subcommand that reads
   the configuration — `server pki status`, `server migrate` and the ones that
   follow — reads the same layered document.

3. **One variable per key, named by its path.** A variable `FLEET_SERVER__`
   followed by the key's TOML path, its segments joined by `__` and each segment
   upper-cased, sets that key: `FLEET_SERVER__DATA_DIR` sets `data_dir`,
   `FLEET_SERVER__REST__TLS__CERT_FILE` sets `[rest.tls] cert_file`,
   `FLEET_SERVER__DATABASE__POSTGRES__HOST` sets `[database.postgres] host`. The
   name maps back by lower-casing each segment. `FLEET_SERVER_CONFIG`, with one
   underscore, is the file of clause 2 and no key.

4. **A value is a TOML value, and a bare word is a string.** The value is parsed
   as a TOML value: `5432` is an integer, `true` a boolean, `["a", "b"]` an
   array, `"text"` a string, and an inline table `{ … }` sets a table whole. A
   value that does not parse as TOML is taken as the string it is, so
   `/run/secrets/pg` needs no quotes. A string that parses as another type — a
   token label `1234`, say — is quoted: `"1234"`. A value whose type does not
   fit its key fails startup, naming the variable and the type the key expects.

5. **Tables keyed by data are set whole, and the sensitive ones from a file.** A
   table whose keys are names an operator chooses cannot be reached key by key
   from the environment.
   - `[rest.auth] basic_users_file` names a TOML file holding the `basic_users`
     table, readable by the Server's account alone. Naming it beside
     `[rest.auth.basic_users]` in the same document fails startup, naming both.
     The environment may set `FLEET_SERVER__REST__AUTH__BASIC_USERS_FILE` but
     not `FLEET_SERVER__REST__AUTH__BASIC_USERS`, which fails startup naming the
     file key.
   - `[telemetry_offer] headers_file` names a TOML file holding the `headers`
     table, under the same rules: never beside `headers`, and from the
     environment only as a path.
   - `server.toml` itself may still carry both tables inline; an operator who
     keeps the file outside the container decides how it is protected.
   - A table of this kind added later gets a `…_file` key under the same rules.

6. **The environment carries paths to secrets, never secrets.** Every secret the
   Server reads is named by a key ending in `_file`, and the file holds the
   secret. No key that holds a secret value exists, and none is added; a secret
   a later decision needs gets a `*_file` key. The environment sets such a key
   to a path, typically under `/run/secrets/`.

7. **The environment is checked as strictly as the file.** The variables are
   merged into the document before it is deserialized, so the merged document
   passes the same `deny_unknown_fields` checks and the same startup checks as a
   file. A `FLEET_SERVER__…` variable that names no key fails startup, naming
   the variable, as an unknown key in the file does. An empty segment
   (`FLEET_SERVER__REST____TLS`) fails startup the same way. At startup the
   Server logs, at info level, the name of every key its environment set, and
   never a value.

8. **No other variable configures the Server.** The `AWS_*` variables are read
   as ADR-0049 says: for credentials only, never for an endpoint or an option.
   `FLEET_TEST_*` variables are read by tests alone. Where ADR-0049 says the S3
   connection is configured in `server.toml` alone, the environment of this ADR
   counts as `server.toml`: `FLEET_SERVER__BLOBS__S3__ENDPOINT` sets the
   endpoint, and `AWS_ENDPOINT` still does not.

9. **The merge is the Server's own.** `config.rs` builds a `toml::Table` from
   the file, overlays a table built from the environment, and deserializes the
   result once. No dependency is added.

**Out of scope:** the Client, whose `supervisor.toml` stays its whole
configuration — it runs as an operating-system service on the host it manages,
not in a container; a container image of the Server, which a later decision
takes up; reloading the configuration while the Server runs; a `…_FILE`
companion for every key, since only secrets need one and every secret is already
a file.

## Alternatives considered

- **`figment` with its `Env` provider.** It maps `APP_A__B` to `a.b` with
  `split("__")`, lower-cases names, and parses values with the same TOML-like
  rules this ADR takes. It is a new dependency with its own provider stack, for
  a merge of two tables and a parse of each value that `toml` already does.
  Rejected.
- **The `config` crate.** Layered sources and environment overrides, but a
  larger surface — several formats, its own value type, a builder — and it loses
  `serde`'s field names in some error messages, which ADR-0010's loud validation
  relies on. Rejected.
- **A fixed list of documented variables.** Each needs code and documentation,
  and a key added later is out of reach of a container until someone adds its
  variable. Rejected.
- **Secrets as plain variables beside their `…_file` keys** (`…_PASSWORD` as
  well as `…_PASSWORD_FILE`). Convenient, but the value then shows in
  `docker inspect`, in `/proc/<pid>/environ` and in crash reports. Docker itself
  keeps secrets out of the environment for this reason. Rejected.
- **Ignore unknown `FLEET_SERVER__…` variables.** It tolerates a typo, which
  then leaves a setting silently at its default — the failure ADR-0010 clause 24
  exists to prevent. Rejected.
- **A single underscore as separator.** Keys like `data_dir` and `cert_file`
  contain underscores themselves, so `FLEET_SERVER_REST_TLS_CERT_FILE` has no
  unique reading. Rejected.
- **Generate the file from the environment in the image's entrypoint.** It needs
  a shell or a template tool in the image and duplicates the schema in a script.
  Rejected.

## Sources / Prior art

- [The Twelve-Factor App, III. Config](https://12factor.net/config): config in
  environment variables, changeable per deploy without changing code.
- [Docker, Manage sensitive data with Docker secrets](https://docs.docker.com/engine/swarm/secrets/):
  secrets mounted under `/run/secrets/<name>`, not set as environment variables
  because those can leak, and the `…_FILE` convention of Docker's official
  images.
- [`figment` 0.10.19, `providers::Env`](https://docs.rs/figment/latest/figment/providers/struct.Env.html):
  `split`, lower-casing, and TOML-like value parsing where an undelimited string
  is taken as written.
- The code as it stands: `ServerConfig::load` and the `deny_unknown_fields`
  structs in `crates/fleet-server/src/config.rs`, `parse_args` in
  `crates/fleet-server/src/main.rs`.

## Consequences

- Positive: a container is configured by its orchestrator alone; no file needs
  to be built into the image or mounted, and every key, present and future, is
  reachable without code per variable.
- Positive: a typo in a variable name stops the Server instead of leaving a
  setting at its default, and the log says which keys the environment set.
- Positive: no secret appears in the container's environment; secrets stay
  files, as orchestrators deliver them.
- Negative / trade-offs: two places can set a key, and the environment silently
  wins over the file. The startup log's list of keys set by the environment is
  what tells an operator which won.
- Negative / trade-offs: a string that looks like a number needs quotes inside
  the variable's value, which is easy to forget; the startup error names the
  variable when it happens.
- Negative / trade-offs: an explicitly named configuration file that does not
  exist now stops the Server, where it ran on defaults before.
- Negative / trade-offs: any other process started with a `FLEET_SERVER__…`
  variable in its environment, such as a test runner, refuses to start the
  Server on an unknown one.
- Follow-ups: the container image of the Server; whether `supervisor.toml` gains
  the same layering should the Client ever run in a container.

## Enforcement

Tests that will carry `Verifies: ADR-0051`:

- `FLEET_SERVER__DATA_DIR`, `FLEET_SERVER__REST__TLS__CERT_FILE` and
  `FLEET_SERVER__DATABASE__POSTGRES__PORT=5433` override the file's values, and
  a key the environment does not name keeps the file's.
- Without `--config`, `FLEET_SERVER_CONFIG` and a `server.toml` in the working
  directory, the Server's configuration is built from defaults and its
  environment; a `--config` or `FLEET_SERVER_CONFIG` naming a missing file fails
  startup naming the path.
- `FLEET_SERVER__REST__TLSS__CERT_FILE` fails startup naming the variable; so
  does a value of the wrong type, naming the variable and the expected type.
- A value `/run/secrets/pg` is taken as a string without quotes; `"1234"` is a
  string and `1234` an integer.
- `FLEET_SERVER__REST__AUTH__BASIC_USERS` fails startup naming
  `basic_users_file`; `basic_users_file` beside `basic_users` fails startup
  naming both; a `basic_users_file` with valid hashes admits its users.
- The startup log names every key the environment set and contains none of their
  values.
