# Changelog

Operator-facing changes to the Server and the Client — what a running deployment
has to be told about, in particular anything that must be edited or moved before
an upgrade. The reasoning behind each change lives in the ADR it names
([`docs/adr/`](docs/adr/)); this file says only what to do.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). A
version is the one `[workspace.package] version` in `Cargo.toml` names, whose
`v<version>` tag a person pushes to release it
([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md),
[ADR-0062](docs/adr/0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)).
A section carries a date once its tag exists.

## [Unreleased]

### Added

- **Each release signs the Client's archives**
  ([ADR-0062](docs/adr/0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)).
  Beside every `supervisor_<version>_<os>_<arch>.tar.gz`
  the release carries its `.sig`: the certificate of the release's Package
  Signer and its signature, which the Server and every Client verify up to the
  Package Roots compiled into them, with nothing to configure. Upload each
  archive with the signature its `.sig` holds; the release notes give the
  commands.
- **A release starts from a pushed tag, `v<version>`.** The `Release` workflow
  no longer creates the tag, and a run started by hand is a dry run. The tag is
  `v0.0.1`, no longer `version/0.0.1`; a build recognises a release by it
  ([ADR-0062](docs/adr/0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)
  clause 11).

### Changed

- **The version starts again at `0.0.1`.** Earlier releases were tagged
  `version/0.5.5` to `version/0.7.0`; this one is the first `v<version>` tag.
  A Client at `0.7.0` or earlier takes `0.0.1` for a downgrade and refuses it,
  so install it on each host by hand from the release's `.deb`, `.rpm`, `.msi`
  or archive, as the signature change below requires anyway.
- **Package signatures are verified up to the Package Roots compiled into the
  Client and the Server**
  ([ADR-0063](docs/adr/0063-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)).
  A signature is now the certificate of a Package Signer that a compiled-in
  Package Root issued, and that signer's Ed25519 signature over the same
  statement as before, in one DER value. The REST API
  (`PUT …/entries/{os}/{arch}/signature`, `{"signature": "<hex>"}`) and a
  release's `.sig` carry it as lowercase hex. Nothing is configured on either
  side.
  - **A signature made with a key of your own is refused**, by the Server and by
    every Client: one from `classisctl package sign`, by hand or through the
    signing file, and every 64-byte signature stored before this release.
    Today the release's Package Signer is the only one, so only the Client's
    own Package can be delivered; `otelcol`, other third-party Packages and
    builds of your own cannot, until Package Signers exist for them.
    `classisctl package keygen`, `sign` and `public-key`, the signing file,
    the package key `pki init` writes and the install's key question remain
    for now; what they make is refused or ignored.
  - **The Server refuses a signature that does not verify** with `400`, naming
    the step that failed, and stores nothing. At startup it sets aside every
    stored signature that does not verify — each one stored before this
    release, and one whose Package Signer has expired — with a warning naming
    the entry: the entry is offered to nobody, and the signature stays in the
    store. Upload the release's `.sig` for each entry you need; an entry of a
    Package already assigned to an Agent is not writable, so release a new
    version instead.
  - **`signature_state` is `valid` or `missing`.** `invalid` and `unchecked`
    no longer occur.
  - **A Client from before this release cannot update itself to it**: it
    expects a 64-byte signature checked against its `verification_key`.
    Upgrade each installation once by hand, from the release's `.deb`, `.rpm`,
    `.msi` or archive; it updates itself from then on.
- **Every Client takes packages**
  ([ADR-0063](docs/adr/0063-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)).
  Every Supervisor declares `AcceptsPackages`, and the Client's own Agent does
  while `[packages] self_update` consents, which is unchanged. No setting turns
  packages off: a Client without a verification key no longer takes none.

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
- **`[packages] verification_key` is no longer read**, by the Client or the
  Server
  ([ADR-0063](docs/adr/0063-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)).
  A `supervisor.toml` or `server.toml` that still holds it loads, and the
  program says once at startup that the key is ignored; remove it. A
  `package-signing-key.pub` beside the Client's program at install is still
  written into the file, and ignored.
- **Support for macOS**
  ([ADR-0064](docs/adr/0064-no-program-of-the-product-is-built-for-macos.md)).
  No release carries a macOS build of the Client or of `classisctl`.

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
