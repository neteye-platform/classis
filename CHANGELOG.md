# Changelog

Operator-facing changes to the Server and the Client — what a running deployment
has to be told about, in particular anything that must be edited or moved before
an upgrade. This file says only what to do.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). A
version is the one `[workspace.package] version` in `Cargo.toml` names, whose
`v<version>` tag a person pushes to release it. A section carries a date once
its tag exists.

## [Unreleased]

### Added

- **`classis-cli`, the operator's commands for Spaces**, which the Server
  answers over a local Unix socket: `space create`, `space list` and
  `space rotate-key`; `enrol-command` refuses until where hosts reach the Server
  publicly is decided. The Server binds that socket on every start, at the new
  `server.toml` key `admin_socket`, default `/run/classis/admin.sock`. **Before
  upgrading:** where the Server does not run as root, set `admin_socket` to a
  path its account can write or provision that directory, or the Server exits at
  startup naming the socket. The program is in no release asset and not in the
  Server's image.

### Changed

- **A host is admitted by a bearer access token, not a client certificate**.
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
- **The Client's default endpoint is `ws://127.0.0.1:4320/v1/opamp`**, plain
  HTTP to a Server on the same machine. A Server on another machine is reached
  through the reverse proxy in front of it: set `endpoint` to its `wss://` or
  `https://` URL.

### Removed

- **Client certificates and everything built on them**: the client and
  bootstrap CAs, the CSR flow, certificate renewal, bootstrap certificates and
  their PKCS#12 files, the enrolment window and its approval, the certificate
  register and the revocation list, the Hosts and `/api/v1/hosts`, the
  `fleet.host.*` values Selectors could match, and the `classisctl pki`
  commands that made the two CAs. `[client_ca]` and `[enrolment]` in
  `server.toml` are refused at startup, naming the section.
- **Gateway Mode**, with its package cache and its bindings.
- **`server.toml.fragment` and `--server-path` of `classisctl pki init`**: the
  Server holds no certificate. `--server-dir` receives the certificate and key
  of the reverse proxy in front of it.

## [0.2.0]

### Added

- **Each release signs the Client's archives**. Beside every
  `supervisor_<version>_<os>_<arch>.tar.gz` the release carries its `.sig`: the
  certificate of the release's Package Signer and its signature, which the
  Server and every Client verify up to the Package Roots compiled into them,
  with nothing to configure. Upload each archive with the signature its `.sig`
  holds; the release notes give the commands.
- **The Server can refuse a Package Signer.**
  `[packages] revoked_signers` in `server.toml` lists signers by the SHA-256 of
  their certificate. The Server refuses their signatures on upload and offers
  nobody the entries they signed, until another signer signs them again.
  Nothing changes while the list is empty; a change takes effect on restart, and
  Clients are not told.
- **A release starts from a pushed tag, `v<version>`.** The `Release` workflow
  no longer creates the tag, and a run started by hand is a dry run. The tag is
  `v` followed by the version, `v0.2.0` for this release; a build recognises a
  release by it.

### Changed

- **Package signatures are verified up to the Package Roots compiled into the
  Client and the Server**. A signature is now the certificate of a Package
  Signer that a compiled-in Package Root issued, and that signer's Ed25519
  signature over the same statement as before, in one DER value. The REST API
  (`PUT …/entries/{os}/{arch}/signature`, `{"signature": "<hex>"}`) and a
  release's `.sig` carry it as lowercase hex. Nothing is configured on either
  side.
  - **A signature made with a key of your own is refused**, by the Server and by
    every Client: one from `classisctl package sign`, by hand or through the
    signing file. Today the release's Package Signer is the only one, so only
    the Client's own Package can be delivered; `otelcol`, other third-party
    Packages and builds of your own cannot, until Package Signers exist for
    them. `classisctl package keygen`, `sign` and `public-key`, the signing file
    and the package key `pki init` writes remain for now; what they make is
    refused.
  - **The Server refuses a signature that does not verify** with `400`, naming
    the step that failed, and stores nothing. At startup it sets aside every
    stored signature that does not verify, one whose Package Signer has expired
    among them, with a warning naming the entry: the entry is offered to nobody,
    and the signature stays in the store.
  - **`signature_state` is `valid` or `missing`.**
  - **The Packages tab takes the hex of a release's `.sig`** for each entry. It
    no longer offers or imports a signing file.
- **Every Client takes packages**. Every Supervisor declares `AcceptsPackages`,
  and the Client's own Agent does while `[packages] self_update` consents, which
  is unchanged. No setting turns packages off.

### Removed

- **The Server's audit record.** The Server no longer writes the hash-chained
  record under `<data_dir>/audit`; every security decision is now one structured
  event on its log output, standard error. Keep the log with whatever runs the
  Server; the refusals a peer can repeat at will are logged at `debug`, shown
  with `RUST_LOG=info,classis_server=debug`.
- **`[audit]` in `server.toml`** is refused at startup as an unknown key, like
  any other.
- **`server audit-verify`** is gone.
- **`[packages] verification_key`**, in `supervisor.toml` and in
  `server.toml`. Either is refused at startup as an unknown key, like any
  other; the `[packages]` section of `server.toml` stays, for
  `revoked_signers`. The install no longer asks for a package key nor reads
  `package-signing-key.pub`, and the
  `supervisor.toml.fragment` of `pki init` names none.

### Fixed

- **Lifting the revocation of a bootstrap certificate never hands out its
  PKCS#12 file again.** When its revocation could not remove the file, the lift
  removes it first; while that fails, and on a Server without `[enrolment]`,
  the lift is answered `500` and the revocation stays.
- **`500` on approving an enrolment request** now means approved and not
  persisted: the certificate is signed and recorded, and its host collects it.
  A restart may list the request again; do not approve it twice.
- **Closing an enrolment window that is not open** is answered `204` and logs
  no event; a close that could not be persisted is persisted by the next one.
- **Approved and rejected requests no longer count** toward the queue's 1024
  places or toward `max_pending_per_bootstrap`.
- **Opening a window that has run out starts a new one**: the requests of the
  old window expire with it instead of carrying over.
