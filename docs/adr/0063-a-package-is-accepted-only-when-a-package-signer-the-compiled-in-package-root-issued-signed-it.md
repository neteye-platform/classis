# ADR-0063: A Package is accepted only when a Package Signer the compiled-in Package Root issued signed it

- **Status:** 🟡 proposed
- **Date:** 2026-11-14
- **Deciders:** Davide Zeni
- **Applies to:** `crates/classis-core/src/package.rs` and the Package Roots
  beside it, the package verification of `crates/classis-agent/` and of
  `crates/classis-server/` with the Server's signature routes and stores,
  `[packages] verification_key` in both configurations, the `sign` job of
  `.github/workflows/release.yml`, `packaging/package-signer.der`, and the fuzz
  target of the signature parser
- **Supersedes:**
  [ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)
  clauses 2 and 5;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clauses 50 and 54;
  [ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
  clauses 6 and 7;
  [ADR-0062](0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)
  clauses 1, 6, 8 and 9

## Context

A Client installs nothing without a valid signature
([`docs/SPECIFICATION.md`](../SPECIFICATION.md), Q-1), and that includes its
own update (G-10, G-11). Today one key decides for every Package.
`[packages] verification_key` is a raw Ed25519 public key that the install
writes into each Client's configuration
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
clause 54). ADR-0062 moves the signing of the Client's own Package into the
release run, still against one such key. Its consequences name the cost:
replacing that key means changing `verification_key` on every installation.

The forces:

- **The key is configured per installation.** Replacing it, because it is lost,
  exposed or old, has to reach every host. A Client that missed the change
  refuses every update from then on, including the one that would fix it.
- **A certificate chain removes that step.** A Package Root the Client trusts
  issues the certificate of the key that signs, the Package Signer, and the
  signature carries that certificate. Replacing the Package Signer is then a
  new certificate from the same Root, and no installation changes.
- **The wire has one field for this.** OpAMP's `DownloadableFile.signature` is
  `bytes`, and the protocol is pinned
  ([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md)).
  A certificate can only travel inside that field.
- **Every parser of network input is bounded and fuzzed (Q-2).** The container
  is a new parser on both ends.
- **The Server today only reports.** It checks against an optional key and
  stores an invalid signature with a warning
  ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
  clause 7). With a Root compiled into it, it always holds the anchor.
- **The key also switches packages on.** A Client without `verification_key`
  takes no Package at all (ADR-0026 clause 50; ADR-0018 clause 2). Removing the
  key removes the switch.
- **Packages are uploaded by hand, and stay so.** An operator uploads the
  artifact and its signature to the Server
  ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)).
  Only the content of the signature changes.
- **What has been proven.** On 2026-11-14 a fork of this repository ran the
  release workflow twice with a test Root made locally:
  - one release was signed by Package Signer A, the next by Package Signer B,
    both issued by that Root;
  - a verifier holding only the Root accepted both releases, and refused B's
    signatures under A's certificate and the same files under another Root.

## Decision

We will accept a Package only when its signature carries a Package Signer
certificate that a Package Root compiled into the Client and the Server issued,
and that signer's Ed25519 signature over the Package's statement verifies;
`[packages] verification_key` goes.

1. **The Package Roots are compiled in.**
   - `classis-core` holds the list of Package Root certificates, DER files
     beside `package.rs`, read with `include_bytes!`. The Client and the Server
     use the same list.
   - Today the list holds one Root. It is Ed25519, valid for 40 years, `CA:true`
     with path length 0. Its key is kept outside this repository and outside
     GitHub by its custodian, who issues Package Signers and nothing else.
   - A Root's own validity is not checked, because a trust anchor's dates are
     not (RFC 5280 section 6.2). A Root ends when a release drops it from the
     list. A second Root is added the same way, by a reviewed change to the
     list.
   - Tests pass a test Root of their own to the verifier (clause 4). The
     compiled-in list is never extended at run time.

2. **A Package Signer certificate has one profile.**
   - It is issued directly by a Package Root. There is no intermediate.
   - Its key is Ed25519.
   - It carries a critical basicConstraints without `cA`.
   - It carries no extendedKeyUsage. Any extendedKeyUsage refuses it, so a
     certificate the Root issued for another purpose cannot sign a Package.
   - It carries keyUsage `digitalSignature` for other tools. The verifier
     ignores keyUsage.
   - It is valid for 10 years, and never past its Root's `notAfter`. Both are
     the custodian's rules at issuance; the verifier enforces only the
     certificate's own dates.

3. **A signature is a `PackageSignature`, in DER.**

   ```asn1
   PackageSignature ::= SEQUENCE {
       version    INTEGER { v1(1) },
       signer     Certificate,              -- the Package Signer, RFC 5280
       signature  OCTET STRING (SIZE (64))  -- Ed25519 over the statement
   }
   ```

   - The parser takes DER only, with definite and minimal lengths. It refuses a
     version other than 1, trailing bytes, and a value longer than 2048 bytes,
     before it parses the certificate.
   - The parser has a fuzz target in `fuzz/` (Q-2).
   - `DownloadableFile.signature` carries the DER bytes.
   - The REST API and a release's `.sig` file carry them as lowercase hex. A
     `.sig` adds a newline.

4. **Verification is one function in `classis-core`, used by both ends.** It
   takes the statement, the `PackageSignature` and the Roots, and it fails at
   the first step that does not hold, naming that step.
   - It parses the value (clause 3).
   - It verifies the chain with `rustls-webpki`:
     - `EndEntityCert::verify_for_usage`, with `ED25519` as the only signature
       algorithm;
     - the Roots as trust anchors and no intermediates;
     - an extendedKeyUsage validator that accepts only an absent extension;
     - the verifying host's current time, so an expired Package Signer refuses
       every Package it signed.
   - It verifies the signature with `verify_signature(ED25519, …)` over the
     statement. The algorithm is pinned here, because the chain's algorithms do
     not constrain the Package Signer's own key.
   - No error message prints an OID through `rustls-webpki`'s `Debug`, which
     misprints it.

5. **Restates ADR-0026 clause 54, against the Roots. Verification decides, and
   the signature is mandatory.**
   - The SHA-256 of the streamed bytes must equal `content_hash`, always.
   - The signature must then verify through the compiled-in Roots (clause 4),
     always.
   - An offer with no signature is refused before anything is downloaded. A
     signature that does not verify refuses the artifact.
   - Both checks complete on the staged bytes before the artifact is opened, so
     an unverified archive is never parsed beyond its hash and signature.
   - There is no unsigned posture, and nothing to configure.
   - The signature covers a statement of what the artifact is, not its bytes:
     `opamp-fleet-package-v1`, the Agent type (the offered package's name), the
     version and the artifact's SHA-256 in lowercase hex, one per line, each
     ended by a newline (`classis_core::package::statement`). Since the hash is
     in the statement and checked against the streamed bytes first, the
     signature still covers the artifact exactly as published, archive and
     all, and holds for that type and version alone.
   - The release run's `sign` job makes it (clause 12).
   - The same download and verification serve the Client's own update
     ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).

6. **Restates ADR-0026 clause 50, with the key gone. The Supervisor is the
   updater, and every Client takes packages.**
   - Every Supervisor-backed Agent declares `AcceptsPackages` and
     `ReportsPackageStatuses`, because every Managed Process is one this Client
     installed
     ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
   - The Client's own Agent declares them while its consent stands (clause 7).
   - No setting makes a Client take no package. A package offered to an Agent
     that declared no package capability is ignored: nothing is downloaded, and
     that Agent reports no package status.
   - A verified artifact travels to the Supervisor as the Port command
     `ProcessCommand::ApplyPackage { staged, version, hash }`, answered by
     `ProcessEvent::PackageApplied`, beside `ApplyConfig`/`ConfigApplied`. No
     further process is spawned for it.

7. **Restates ADR-0018 clause 2, with the key gone. The consent is
   `[packages] self_update`, it stands by default, and the one package it admits
   is the Client's own Agent type.**

   ```toml
   [packages]
   self_update = true
   ```

   - `self_update` defaults to `true`; `false` withdraws the consent.
   - **The package name is not configurable**: it is the Agent type compiled
     into the binary, `supervisor` (ADR-0018 clause 1), the constant the
     Client's own Agent reports as `service.name`. The name a Server offers this
     Client's package under is therefore the name the Client reports, and the
     same in every variant build, whatever its product name: one package Set
     serves them all
     ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
     clause 9).
   - An absent key is consent, and so is an absent `[packages]`.
   - While the consent stands, the Client's own Agent declares `AcceptsPackages`
     and `ReportsPackageStatuses`. It **refuses any offered top-level package
     whose name is not its Agent type**, reporting `InstallFailed` with that
     reason and installing nothing.
   - With `self_update = false` it declares no package capability, and no offer
     can reach it; the Supervisor Agents still take theirs.
   - **A `[self_update]` section fails the load**, whatever it holds, with a
     message naming `[packages] self_update` as the key that replaces it.
     Ignoring it would turn a written `enabled = false` into consent; honouring
     it would keep two spellings of one decision alive for good.

8. **Restates ADR-0018 clause 5, against the Roots. An install is a staged
   version, never an overwrite, of a signed artifact.**
   - The artifact is verified like any other package: its SHA-256 must equal
     the offered content hash, and **its signature must verify through the
     compiled-in Roots** (clause 4).
   - An artifact offered without a signature, or whose signature does not
     verify, fails the install with `InstallFailed` naming the reason, and
     nothing is staged.
   - The verified artifact is unpacked as
     [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
     states into
     `<layout root>/versions/supervisor-<MAJOR.MINOR.PATCH>-<hash>/`. The binary
     is made executable, and `manifest.toml` records the version and the
     binary's SHA-256, the same layout `service install` produces.
   - The running binary is never touched.

9. **Restates ADR-0033 clause 6, with the signature's form changed. The
   signature lives on the entry, and the wire field is unchanged.**
   - `PUT|DELETE /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature`
     writes or removes a `PackageSignature` in lowercase hex (clause 3), as a
     release's `.sig` holds it.
   - A signature for an entry that does not exist is `404`. An empty one, one
     that is not hex, and one that does not verify (clause 10) are `400`.
   - Writing new bytes to an entry removes its signature, because a signature
     covers the hash.
   - A signature write on a Package assigned to an Agent is refused (`409`),
     like any other write to its entries
     ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 8).
   - What an Agent receives in `DownloadableFile.signature` is the DER of the
     entry's signature for its Platform. An entry without one is no candidate,
     the Agent is offered nothing for it, and the fleet view says the signature
     is missing.
   - One signature serves every Deployment that holds the Package.

10. **Restates ADR-0033 clause 7, against the Roots. The Server refuses a
    signature that does not verify, and the Agent's check still decides.**
    - The Server verifies through the compiled-in Roots (clause 4), over
      `statement(agent_type, version, content_hash)`.
    - On a write, a signature that does not verify is refused with `400`, naming
      the step that failed. Nothing is stored.
    - On loading the store, an entry whose stored signature does not verify is
      treated as unsigned: the signature is removed, and a warning names the
      entry and the step. A signature stored before this ADR, 64 raw bytes, is
      one of them, and so is one whose Package Signer has expired.
    - Each entry reports `signature_state`, `valid` or `missing`. `invalid` and
      `unchecked` no longer occur.
    - A signature that expires while the Server runs stays stored until the next
      load. The Agent refuses it (clause 5).

11. **`[packages] verification_key` is no longer read.** A Client or Server
    configuration that still holds it loads. The program says at startup, once,
    that the key is ignored and that the compiled-in Roots decide, so a Client
    reinstalled over an old file keeps starting.

12. **Restates ADR-0062 clause 1, with a Package Signer in place of the bare
    key. One Package Signer, made outside the release run.**
    - A repository admin makes an Ed25519 key on a machine of their own and
      sends a request for it to the Root's custodian, who issues the certificate
      (clause 2).
    - The admin stores the base64 of the key in PKCS#8 DER as the secret
      `PACKAGE_SIGNING_KEY` of the environment `signing`, then deletes the key.
      No copy is kept.
    - The certificate is committed as `packaging/package-signer.der` by a
      reviewed pull request.
    - The `version` job, which checks out the tag, uploads that tracked file as
      a run artifact for `sign`.
    - Replacing the Package Signer, because it is lost, exposed or close to its
      end, is the same procedure: a new key, a new certificate from the same
      Root, a new secret, and a reviewed change to the tracked file. No
      installation changes.

13. **Restates ADR-0062 clause 6, with the `PackageSignature` written. The
    `sign` job signs, and does nothing else.**
    - **When it runs.** Only in a run started by the push of a `version/*` tag
      (`github.event_name == 'push'`). The event is checked because
      `workflow_dispatch` can run on a tag ref too. It runs after `version` and
      `build`, on `ubuntu-latest` and never on a self-hosted runner.
    - **What it may do.** It names the environment `signing` and holds
      `contents: read` alone. It checks out no code and builds nothing. The only
      actions it runs are `actions/download-artifact` and
      `actions/upload-artifact`, pinned to a commit SHA
      ([ADR-0060](0060-every-github-action-is-pinned-to-a-commit-sha-and-renovate-keeps-it-current.md)).
      Every other step is shell.
    - **What it signs.**
      - It downloads only the `.sha256` files of the Client's archives, and the
        tracked certificate.
      - For each archive it writes the statement `classis_core::package::statement`
        makes to a file: `opamp-fleet-package-v1`, `supervisor`, the release
        number, and the SHA-256 in lowercase hex, each line ended by a newline.
        The prefix keeps the spelling
        [ADR-0061](0061-the-product-is-named-classis-and-the-strings-signatures-cover-keep-their-old-spelling.md)
        keeps.
      - It signs that file with the runner's
        `openssl pkeyutl -sign -rawin -keyform DER -inkey <key> -in <statement>`.
        OpenSSL takes Ed25519 only with `-rawin` and from a file. The step
        script reads its inputs from environment variables only.
    - **The key on the runner.** The key is decoded into a file under
      `RUNNER_TEMP`, mode `0600`. A step with `if: always()` removes it.
    - **What it writes.**
      - Each `PackageSignature` (clause 3), the certificate and the 64-byte
        signature in one DER value, goes to `<archive>.sig` as lowercase hex and
        a newline. That is the form the REST API takes an entry's signature in.
      - A `.sha256` is written beside each `.sig`.
      - The files are uploaded.

14. **Restates ADR-0062 clause 8, without the bare key. One build-provenance
    attestation covers every published asset, and one covers the image.** After
    `SHA256SUMS` is assembled and before the release is created, the `publish`
    job runs `actions/attest` in provenance mode, pinned to a commit SHA
    (ADR-0060). The subjects are:
    - every file it then publishes: the `.tar.gz` archives, the `.deb`, `.rpm`
      and `.msi`, the `.cdx.json` SBOMs and the `.tar.gz.sig` signatures;
    - `SHA256SUMS` itself.

    A second `actions/attest` step attests the image, with `subject-name`
    `ghcr.io/neteye-platform/classis-server`, `subject-digest` the index digest
    from `image`, and `push-to-registry: true`, so the attestation travels with
    the image. The digests of the files are computed from the files themselves,
    not read out of `SHA256SUMS`. The per-file `.sha256` files are folded into
    `SHA256SUMS` and not published, so they are not subjects. Each attestation
    is signed through the Sigstore public-good instance, which this public
    repository gets, recorded in Rekor and stored in the repository's
    attestation store.

15. **Restates ADR-0062 clause 9, without the bare key. What is published.** A
    GitHub release named after the version holds:
    - the Client's five archives, the two `.deb`, the two `.rpm` and the `.msi`;
    - one `.sig` per Client archive, named after it (clause 13);
    - the four archives of the operator tool
      ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md));
    - the eleven SBOMs
      ([ADR-0052](0052-the-server-ships-as-a-container-image-built-from-its-attested-release-binary.md)
      clause 7);
    - one `SHA256SUMS` covering every asset.

    Beside it, `ghcr.io/neteye-platform/classis-server:<version>` holds the
    Server's image. Every asset is a subject of the release's build-provenance
    attestation, and the image of its own (clause 14). The notes say:
    - which file is for which purpose, and the image's name and digest;
    - the per-platform install commands, and how to run the image;
    - how to verify an asset:
      `gh attestation verify <file> --repo <repository> --signer-workflow <repository>/.github/workflows/release.yml`,
      and `sha256sum -c --ignore-missing SHA256SUMS` once `SHA256SUMS` has
      verified;
    - how to verify the image:
      `gh attestation verify oci://ghcr.io/neteye-platform/classis-server@<digest>
      --repo <repository>
      --signer-workflow <repository>/.github/workflows/release.yml`;
    - the procedure that uploads the Client's archives by hand, selected by
      their `supervisor_` stem, as one package for Agent type `supervisor`, each
      entry with the signature its `.sig` holds;
    - that the Client and the Server check each `.sig` against the Roots they
      carry, with nothing to configure;
    - the full baked version string, as provenance. The upload uses the release
      number, since versions are compared without build metadata
      ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)).

**Out of scope:**

- the operator's signing tools and what asks for or writes the old key:
  `classisctl package keygen`, `sign` and `public-key`, the signing file
  ([ADR-0027](0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md)),
  the package key `pki init` makes, and the install's key question and
  `package-signing-key.pub`. They stay until a later cleanup removes them;
- who besides the release run may hold a Package Signer, and so how
  `otelcol`, other third-party Packages and Foreign Agents' builds are signed.
  Until that is decided no such Package can be delivered;
- what stops a stolen Package Signer before it expires: revocation, shorter
  certificates, or a minimum issue date;
- the `[packages] self_update` consent, kept as ADR-0018 has it (clause 7);
- the Root's ceremony, its custody and the procedure that issues a Package
  Signer, which belong to its custodian;
- `publish` verifying every `.sig` before the release is created, and the
  `sign` job checking that the secret's key matches the tracked certificate;
- the Packages tab of the bundled UI.

## Alternatives considered

- **Keep the raw key beside the chain.** A 64-byte signature would still be
  checked against `verification_key`, and a `PackageSignature` against the
  Roots. Old Clients would keep updating across the change. It keeps the
  per-installation key and the switch it implies, which this ADR exists to
  remove, and two formats on every path.
- **A Root configured per installation**, or compiled in with more anchors
  configurable. It brings back an install step that can be wrong or missing,
  and a Client whose anchor was changed on the host would trust what that host
  chose.
- **The operator's Root, or the operator's key beside the project's Root.** It
  keeps the operator signing their own Packages, as the specification says
  today. It was rejected to make the project's Root the only thing a Client
  trusts. The case of other Packages is left open (Out of scope), not denied.
- **Signature and certificate concatenated.** It needs the smallest parser, but
  it has no version, so a later change of form (an intermediate, a timestamp)
  could not be told from the first.
- **CMS `SignedData` (RFC 5652).** `openssl cms` would read it, but its parser
  is far larger than what a fuzzed, bounded parser should cover (Q-2), for one
  certificate and one signature.
- **Intermediate certificates.** A Root that issues an intermediate which issues
  Package Signers adds a key to guard and a path to verify, with no Package
  Signer that needs it.
- **An extendedKeyUsage of the project's own.** An OID under `2.25` does not fit
  `rcgen`'s `u64` arcs, and an Enterprise Number is a registration. Since the
  Root issues Package Signers only, refusing every extendedKeyUsage is enough.
- **Ignore a Package Signer's expiry for signatures.** An old version would keep
  installing after its Package Signer ends, but expiry would then mean nothing,
  and a later answer to a stolen key would have nothing to build on.
- **Keep the Server reporting only.** It would store a signature every Client is
  going to refuse, and the operator would learn it from a failed rollout.
- **A switch that turns packages off.** `[packages] enabled`, opt-in or
  opt-out. The human decided that every Client takes packages.
- **Revocation now.** Left out of this step by the human; planned replacement
  is what this ADR covers.

## Sources / Prior art

Read on 2026-11-13 and 2026-11-14.

- RFC 5280, <https://www.rfc-editor.org/rfc/rfc5280>:
  - section 4.1.2.5: validity dates through 2049 as `UTCTime`, from 2050 as
    `GeneralizedTime`. A 40-year Root made in 2026 ends in 2066;
  - section 4.2.1.12: "If the extension is present, then the certificate MUST
    only be used for one of the purposes indicated";
  - section 6.2: implementations that use self-signed certificates as trust
    anchors "are free to process or ignore" their information.
- RFC 8410, Ed25519 keys and signatures in X.509,
  <https://www.rfc-editor.org/rfc/rfc8410>.
- RFC 8032 section 5.1.6, Ed25519 signing is deterministic,
  <https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6>.
- ITU-T X.690, the DER rules: definite and minimal lengths.
- `rustls-webpki` 0.103.16, the source, as pinned in `Cargo.lock`:
  - `EndEntityCert::verify_for_usage` takes a list of trust anchors and a list
    of intermediates;
  - its `supported_sig_algs` constrain the signatures on certificates, not the
    end entity's key, hence `verify_signature(ED25519, …)`;
  - `check_basic_constraints` refuses a `CA:true` end entity
    (`CaUsedAsEndEntity`);
  - keyUsage is ignored ("For cert validation, we ignore the KeyUsage
    extension");
  - a trust anchor carries no validity;
  - `ExtendedKeyUsageValidator` is public, so a validator that accepts only an
    absent extension can be written;
  - `OidDecoder` shifts by 8 instead of 7, so an OID printed through `Debug`
    is wrong.
- `rcgen` 0.14.10: issues an Ed25519 Root and Package Signer, writes
  `GeneralizedTime` from 2050, writes `CA:false` as a critical basicConstraints
  with `IsCa::ExplicitNoCa`.
- A throwaway prototype, run on 2026-11-13 and 2026-11-14: 24 cases of the chain
  rules above, and the release workflow of a fork of this repository signing two
  releases with two Package Signers of one test Root (Context).

## Consequences

- **Q-1 holds with nothing to configure.** No Client installs anything that a
  Package Signer of a compiled-in Root did not sign, and no Client is left
  taking no packages because a key is missing.
- **Replacing the Package Signer reaches no installation.** It is a new
  certificate, a new secret and a reviewed file. Replacing a Root is a release
  that adds the new one to the list, and a later one that drops the old one.
- **Q-2 gains one parser on both ends**, bounded at 2048 bytes and fuzzed.
- **A Client released before this ADR cannot update itself to one released
  after it.** It expects 64 raw bytes against its `verification_key`. Each
  installation is upgraded once by hand. No fleet in production depends on the
  old form.
- **The upload stays manual and the same.** Only the signature an operator
  uploads changes: the release's `.sig`.
- **The operator's tools still exist, and what they make is refused.** A
  signature from `classisctl package sign`, by hand or through the signing
  file, is answered `400`. The install may still ask for a key and write
  `verification_key`, which is then ignored (clause 11). The cleanup that
  removes them is a follow-up. ADR-0033 clause 8 marks an `invalid` signature
  as a warning; that state no longer occurs.
- **Other Packages wait.** `otelcol`, other third-party Packages and Foreign
  Agents' builds cannot be delivered as Packages until the question left out of
  scope is decided. G-10 is met for the Client's own Package.
- **An expired Package Signer stops its versions.** With 10-year certificates
  and replacement well before the end, a version older than its Package Signer
  stops installing, a reinstall included, unless it is signed again. A host
  whose clock is wrong refuses valid signatures, as it would refuse the
  Server's TLS certificate.
- **The Server refuses on write and drops on load.** An entry may lose a stored
  signature at startup, named in a warning; an operator who sees a Package
  turn unsigned uploads its `.sig` again.
- **A Root is a single point.** Its key signs every Package Signer, and its
  custody is outside this repository. Losing it means a release that ships a
  new Root, and a hand upgrade for every Client that cannot take it.
- **The specification changes, and the human lands it.** Drafted text:
  - in the security paragraph of _Strategy_, replace "signed with a key the
    operator holds" with "signed by a Package Signer that the project's Package
    Root issued";
  - in _Package_, replace "and the operator's signature" with "and its
    signature, made by a Package Signer the Package Root issued", and replace
    "the Server checks a signature against the operator's public key when it has
    one and reports a failed check, but the Agent's check decides" with "the
    Server refuses a signature that does not verify, and the Agent's check
    decides".
- **Wording elsewhere.** ADR-0010 clause 17 and the context of ADR-0017 speak of
  the statement "the operator signs". The mechanism holds; whether the wording
  moves is for the human to judge.
- **Follow-ups:**
  - removing the operator's signing tools, the signing file, `pki init`'s
    package key and the install's key question;
  - who may hold a Package Signer besides the release run, and how other
    Packages are signed;
  - an answer to a stolen Package Signer before it expires;
  - `publish` verifying every `.sig` through the tracked Roots before the
    release is created.

## Enforcement

Tests carrying `Verifies: ADR-0063`:

- `crates/classis-core`: the verifier accepts a Package Signer of a test Root,
  and refuses each of the following, naming the step:
  - a Package Signer from another Root;
  - an expired Package Signer;
  - a `CA:true` certificate;
  - a certificate with any extendedKeyUsage;
  - an intermediate between Root and Package Signer;
  - a non-Ed25519 Package Signer key;
  - the signature over another type, version or hash;
  - a version other than 1, trailing bytes, more than 2048 bytes, and non-DER
    lengths.
- `fuzz/fuzz_targets/`: a target for the `PackageSignature` parser.
- `crates/classis-server`: a `PUT` of a signature that does not verify answers
  `400` and stores nothing; a stored 64-byte signature is removed at load with a
  warning; `signature_state` takes `valid` and `missing` only; a
  `verification_key` in `server.toml` is ignored with a warning.
- `crates/classis-agent`: every Supervisor-backed Agent declares
  `AcceptsPackages` without any key; an offer whose signature does not verify is
  refused before the artifact is opened; the self-update takes a release signed
  through a test Root; a `verification_key` in the file is ignored with a
  warning.
- `crates/classis-tools/tests/release_workflow.rs`: the `sign` job's script, run
  with a test Root's Package Signer and `openssl`, writes `.sig` files the
  verifier accepts.

**Not mechanically decidable:** that the custodian issues Package Signers only,
with the profile of clause 2, and keeps the Root's key outside GitHub.
