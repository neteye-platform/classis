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
  at will are logged at `debug`, shown with `RUST_LOG=info,fleet_server=debug`.
- **`[audit]` in `server.toml`** is refused at startup as an unknown key, like
  any other.
- **`server audit-verify`** is gone.

### Fixed

- **Lifting the revocation of a bootstrap certificate never hands out its
  PKCS#12 file again.** When its revocation could not remove the file, the lift
  removes it first; while that fails, the lift is answered `500` and the
  revocation stays.
- **`500` on approving an enrolment request** now means approved and not
  persisted: the certificate is signed and recorded, and its host collects it.
  A restart may list the request again; do not approve it twice.
- **Closing an enrolment window that is not open** is answered `204` and logs
  no event; a close that could not be persisted is persisted by the next one.
- **Approved and rejected requests no longer count** toward the queue's 1024
  places or toward `max_pending_per_bootstrap`.
- **Opening a window that has run out starts a new one**: the requests of the
  old window expire with it instead of carrying over.
