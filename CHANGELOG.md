# Changelog

Operator-facing changes to the Server and the Client — what a running deployment
has to be told about, in particular anything that must be edited or moved before
an upgrade. The reasoning behind each change lives in the ADR it names
([`docs/adr/`](docs/adr/)); this file says only what to do.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). A
version is the one `[workspace.package] version` in `Cargo.toml` names, which
the release pipeline creates the `version/*` tag from
([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)). A
section carries a date once its tag exists.

## [Unreleased]

### Removed

- **The Server's audit record.** The Server no longer writes the hash-chained
  record under `<data_dir>/audit`; every security decision is now one
  structured event on its log output, standard error
  ([ADR-0022](docs/adr/0022-security-decisions-are-structured-log-events.md)).
  Keep the log with whatever runs the Server; the refusals a peer can repeat
  at will are logged at `debug`, shown with `RUST_LOG=info,classis_server=debug`.
- **`[audit]` in `server.toml`** is refused at startup as an unknown key, like
  any other.
- **`server audit-verify`** is gone.
- **Client certificates and everything built on them**: the client and
  bootstrap CAs, the CSR flow, certificate renewal, bootstrap certificates and
  their PKCS#12 files, the enrolment window and its approval, the certificate
  register and the revocation list, the Hosts and `/api/v1/hosts`, the
  `fleet.host.*` values Selectors could match, and the `classisctl pki`
  commands that made the two CAs. `[client_ca]` and `[enrolment]` in
  `server.toml` are refused at startup as unknown keys.
- **Gateway Mode**, with its package cache and its bindings.

### Changed

- **A host is admitted by a bearer access token, not a client certificate**
  ([ADR-0064](docs/adr/0064-a-host-enrols-with-its-spaces-key-and-is-admitted-by-a-bearer-token.md)).
  A host enrols with the enrolment key of its Space
  (`supervisor enrol <base-url> <key>`), which writes `state.json` in its state
  directory and starts its service; every OpAMP exchange and package download
  then carries the token. Nothing is migrated: a host enrolled under the old
  model is enrolled again, and no old certificate or key is read.
  `service install` registers the service but starts nothing, and a Client
  without `state.json` refuses to start. New `server.toml` key:
  `token_lifetime_secs` (default `0`, a token never expires). New
  `supervisor revoke [--force] [--keep-cache]` deletes a host's state
  directory locally.
