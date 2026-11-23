# Changelog

Operator-facing changes to the Server and the Client — what a running deployment
has to be told about, in particular anything that must be edited or moved before
an upgrade. The reasoning behind each change lives in the ADR it names
([`docs/adr/`](docs/adr/)); this file says only what to do.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). A
version is the one `[workspace.package] version` in `Cargo.toml` names, whose
`v<version>` tag a person pushes to release it
([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md),
[ADR-0065](docs/adr/0065-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)).
A section carries a date once its tag exists.

## [Unreleased]

### Added

- **Each release signs the Client's archives**
  ([ADR-0065](docs/adr/0065-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)).
  Beside every `supervisor_<version>_<os>_<arch>.tar.gz`
  the release carries its `.sig`: the certificate of the release's Package
  Signer and its signature, which the Server and every Client verify up to the
  Package Roots compiled into them, with nothing to configure. Upload each
  archive with the signature its `.sig` holds; the release notes give the
  commands.
- **A release starts from a pushed tag, `v<version>`.** The `Release` workflow
  no longer creates the tag, and a run started by hand is a dry run. The tag is
  `v0.1.0`; a build recognises a release by it
  ([ADR-0065](docs/adr/0065-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)
  clause 11).

### Changed

- **Package signatures are verified up to the Package Roots compiled into the
  Client and the Server**
  ([ADR-0066](docs/adr/0066-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)).
  A signature is now the certificate of a Package Signer that a compiled-in
  Package Root issued, and that signer's Ed25519 signature over the same
  statement as before, in one DER value. The REST API
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
    among them, with a warning naming the entry: the entry is offered to
    nobody, and the signature stays in the store.
  - **`signature_state` is `valid` or `missing`.**
  - **The Packages tab takes the hex of a release's `.sig`** for each entry. It
    no longer offers or imports a signing file.
- **Every Client takes packages**
  ([ADR-0066](docs/adr/0066-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)).
  Every Supervisor declares `AcceptsPackages`, and the Client's own Agent does
  while `[packages] self_update` consents, which is unchanged. No setting turns
  packages off.

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
- **`[packages] verification_key`**, in `supervisor.toml` and in
  `server.toml`, and with it the Server's whole `[packages]` section
  ([ADR-0066](docs/adr/0066-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)).
  Either is refused at startup as an unknown key, like any other. The install
  no longer asks for a package key nor reads `package-signing-key.pub`, and the
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
