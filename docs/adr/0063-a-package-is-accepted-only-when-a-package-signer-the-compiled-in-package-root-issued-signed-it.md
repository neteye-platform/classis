# ADR-0063: A Package is accepted only when a Package Signer the compiled-in Package Root issued signed it

- **Status:** 🟡 proposed
- **Date:** 2026-11-14
- **Deciders:** Davide Zeni
- **Applies to:** `crates/classis-core/src/package.rs` and the Package Roots
  beside it, the package verification of `crates/classis-agent/` and of
  `crates/classis-server/` with the Server's signature routes and stores, the
  `[packages]` section of `supervisor.toml` and its removal from `server.toml`,
  the fleet's files and the
  questionnaire of the install in `crates/classis-agent/src/config_init.rs`,
  the `supervisor.toml.fragment` of `pki init` in
  `crates/classis-tools/src/pki.rs`, the Packages tab of the bundled UI in
  `crates/classis-server/static/index.html`, and the fuzz target of the
  signature parser
- **Supersedes:**
  [ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)
  clauses 2, 3 and 5;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clauses 50 and 54;
  [ADR-0027](0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md)
  clause 2;
  [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
  clause 3;
  [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  clauses 6, 8 and 9;
  [ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
  clauses 6, 7, 8 and 12

## Context

A Client installs nothing without a valid signature
([`docs/SPECIFICATION.md`](../SPECIFICATION.md), Q-1), and that includes its
own update (G-10, G-11). Today one key decides for every Package.
`[packages] verification_key` is a raw Ed25519 public key that the install
writes into each Client's configuration
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
clause 54).
[ADR-0062](0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)
moves the signing of the Client's own Package into the release run. Against
one such key, replacing it would mean changing `verification_key` on every
installation.

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
   - Today the list holds one Root, `CN=Signing Packages Root CA`, SHA-256
     fingerprint `16b7c670…7e4a810f`. It is Ed25519, valid for 40 years, a CA
     certificate. Its key is kept outside this repository and outside GitHub by
     its custodian, who issues Package Signers and nothing else.
   - A Root's path length is not relied on; this one's is 2. A signature carries
     one certificate and the verifier passes no intermediate (clause 4), so a
     path through an intermediate CA is refused whatever the Root allows.
   - A Root's own validity is not checked, because a trust anchor's dates are
     not (RFC 5280 section 6.2). A Root ends when a release drops it from the
     list. A second Root is added the same way, by a reviewed change to the
     list.
   - Tests pass a test Root of their own to the verifier (clause 4). The
     compiled-in list is never extended at run time, with one exception for
     tests: a debug build also trusts the Root in the DER file that
     `CLASSIS_DEBUG_PACKAGE_ROOT` names, and says so at startup. The
     integration tests run the real binaries that way. A release build
     compiles no such read.

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
     `classis-package-v1`, the Agent type (the offered package's name), the
     version and the artifact's SHA-256 in lowercase hex, one per line, each
     ended by a newline (`classis_core::package::statement`). Since the hash is
     in the statement and checked against the streamed bytes first, the
     signature still covers the artifact exactly as published, archive and
     all, and holds for that type and version alone.
   - The release run's `sign` job makes it (ADR-0062 clause 6).
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
      treated as unsigned while this Server runs: it is offered to nobody, and
      a warning names the entry and the step. One whose Package Signer has
      expired is one of them. The store keeps the signature: a Server started
      with a wrong clock or another list of Roots loses nothing, and offers the
      entry again once it is started right.
    - Each entry reports `signature_state`, `valid` or `missing`.
    - A signature that expires while the Server runs stays stored until the next
      load. The Agent refuses it (clause 5).

11. **Restates ADR-0018 clause 3, with the key gone. Every install path can
    withdraw the consent, none asks for a name, and the answer is written into
    the configuration.**
    - `service install --no-self-update` withdraws it on the non-interactive
      `--endpoint` path
      ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
      clause 42).
    - **The interactive questionnaire asks nothing about it**: it writes the
      consent. It asks for no package key either (clause 13).
    - The MSI shows a checked-by-default checkbox on its endpoint dialog backed
      by the public property `SELFUPDATE` (default `1`). `SELFUPDATE=0` or an
      empty value withdraws it, so `msiexec /qn … SELFUPDATE=0` is how Intune or
      Group Policy declines.
    - Whatever path wrote it, the first configuration carries
      `[packages] self_update = true` or `= false`, so the decision is visible
      and editable on the host; no installer holds state of its own.

12. **Restates ADR-0029 clause 6, without the package key. Beside the program is
    the directory of the running executable, unless `--fleet-files` names
    another.** The install reads it from the operating system
    (`std::env::current_exe`), before the program is staged, so it is where the
    operator ran the program from. `service install --fleet-files <dir>` names
    the directory the install looks in instead, for all of the fleet's files,
    with or without `--interactive`; wherever ADR-0020, ADR-0029 or this ADR
    says "beside the program", that directory is meant when the flag is given. A
    `<dir>` that is not a readable directory fails the install before anything
    is written, naming the flag. The install never looks in both. A file counts
    only when it is a readable regular file under its exact name. **A bootstrap
    identity** is either the bootstrap pair, `bootstrap.pem` with
    `bootstrap-key.pem`, or `bootstrap.p12`; wherever ADR-0020 says "bootstrap
    pair", a bootstrap identity is meant. The bootstrap pair counts only as a
    pair; one of the two alone is named in a warning and not used. When
    `bootstrap.p12` and any file of the pair lie there together, a warning names
    them and none of them is used, so the install never guesses which identity
    is meant. No package key is looked for.

13. **Restates ADR-0029 clause 8, without the package key. The questionnaire
    asks only what has no useful default on a fresh host, and offers no answer
    the Client would refuse.** It asks for the Server `endpoint`, suggesting
    `wss://127.0.0.1:4320/v1/opamp`; a `ws://` or `http://` endpoint is refused
    unless its host is a loopback IP literal — `127.0.0.1` or `::1`; a host name
    is never loopback, `localhost` included — and the question is asked again
    with a message saying that beyond the loopback the endpoint must be `wss://`
    or `https://`. It asks for the Agent `name`, reported as
    `service.instance.name`. It asks for the CA certificate of the Server,
    written as `[tls] ca_file`, for every `wss://` or `https://` endpoint,
    without a question before it. It asks for the bootstrap identity only while
    the Client is not enrolled — while its state directory holds no certificate
    the Server issued: first for the bootstrap certificate, a PEM certificate or
    a PKCS#12 file. A path ending in `.p12` or `.pfx` is read as PKCS#12: the
    password is asked next, with input hidden, unless
    `--bootstrap-password-file` gave it (ADR-0029 clause 10), and a password the
    file does not open under is asked again. Any other path is read as PEM, and
    its private key is asked next. It asks for no package key.

    **Each question's default is what the file holds, else what lies beside the
    program** (clause 12), else none; the password has no default. The bootstrap
    identity is neither copied nor written into the file: the questionnaire
    enrols with it directly against the Server, after the file is written. It
    connects with the identity where it lies, sends the CSR (ADR-0021 clause
    21), prints the request's key fingerprint and waits until an operator
    approves it, then stores the issued certificate in the state directory,
    where the Client looks for it first. An interrupted wait leaves the written
    file and registers nothing; running the install again resumes the request in
    flight, printing its fingerprint. A rejected request stays rejected for its
    key, and the wait goes on until it is interrupted: removing the pending key
    and request from the state directory starts a fresh one. On an enrolled
    Client no file of the identity is asked: the Client renews what it was
    issued. A certificate already issued by the Server's client CA goes in
    `[tls] cert_file` and `key_file`, by editing the file. The identity is
    required while it is asked, and a path that names no readable file, here or
    for the CA, is asked for again.

    **The answered CA is copied beside the written file**, as `server-ca.pem`,
    owner-only on Unix, and the file names the copy. A copy left by an earlier
    answer is replaced. The copy is handed over to the service account with the
    file (ADR-0019 clause 13). The questionnaire asks nothing about the
    self-update: the file carries `[packages] self_update = true` (clause 11).
    Everything else is written as commented defaults. No question asks for a
    credential, and no written file has an `[auth]` section; a leftover `[auth]`
    section is kept and ignored, as ADR-0019 clause 17 stated. The bootstrap
    password is not a credential of either plane: it opens a file on the host
    and is never sent.

14. **Restates ADR-0029 clause 9, without the package key. `service install
    --endpoint <URL>` writes the first configuration without a terminal, with
    what lies beside the program.** It writes the file `--interactive` writes,
    through the same renderer, with the endpoint given rather than asked: the
    same shape, mode `0600`, never overwriting an existing file, validated by
    the rule the Client applies to its endpoint at startup before anything is
    written — a `ws://` or `http://` endpoint whose host is not `127.0.0.1` or
    `::1` is refused, naming the setting, and `localhost` is no exception. It
    conflicts with `--interactive` and carries the self-update answer
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)
    clause 3). For a `wss://` or `https://` endpoint, a `server-ca.pem` beside
    the program — in the directory `--fleet-files` names, when given (clause 12)
    — is copied and written as `[tls] ca_file` as the questionnaire's answer
    would be. No package key is taken or written. Each file it takes is printed.
    It has no flag naming the CA file or the client identity one by one:
    `--fleet-files` names the one directory the fixed names are looked up in,
    and `--bootstrap-password-file` (ADR-0029 clause 10) the password of a
    `bootstrap.p12`, which is not a credential. It takes no credential, since
    there is none. The installers do not write TOML themselves. **The same rule
    binds every default an installer supplies:** no installer writes, prefills
    or prints a value the Client would refuse at startup, and none writes a
    setting that stands in for a client certificate.

15. **Restates ADR-0028 clause 3, with the fragment naming no package key.
    `init` writes two directories, and the split is the point.** `--server-dir`
    receives what the Server host needs: `server.pem` and `server-key.pem`,
    `client-ca.pem` and `client-ca-key.pem`, `bootstrap-ca.pem` and
    `bootstrap-ca-key.pem`, and `server.toml.fragment` naming them in `[tls]`,
    `[client_ca]` and `[enrolment]`, including `bootstrap_ca_key_file`.
    `--offline-dir` receives what stays with the operator: `server-ca.pem` and
    `server-ca-key.pem`; the package signing key, an Ed25519 key in PKCS#8 as
    `package keygen` writes it, as `package-signing-key.pk8`, and its public
    half in hex as `package-signing-key.pub`
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md));
    and `supervisor.toml.fragment` naming `server-ca.pem` in `[tls] ca_file`,
    `bootstrap.pem` and `bootstrap-key.pem` under `--host-path` in `cert_file`
    and `key_file`, where a host puts the pair the Server issues it. The
    fragment names no package key: the Client verifies up to its Package Roots
    (clause 1). No key of the server CA and no package signing key is ever
    written to `--server-dir`. Each fragment names its files by the directory
    they are meant to live in: `--server-path` (default: the absolute path of
    `--server-dir`) and `--host-path` (default: the absolute path of
    `--offline-dir`). The command prints which directory goes where.

16. **Restates ADR-0033 clause 8, with the signature states and the signing
    file changed. The Packages tab is one table and one detail form, and it
    signs.**
    - One row per Package: Agent type, version, the platforms it holds, the
      Deployments that hold it, and whether every entry carries a valid
      signature. Selecting a row makes it the current record and shows the form;
      while nothing is current the form is not on screen.
    - **Create** opens the form empty, the only moment the identity fields are
      writable.
    - The form adds and removes entries in place, each from a file; a file named
      as a release artifact fills the platform and, while creating, the identity.
    - Each entry shows its hash, size and `signature_state`, `valid` or
      `missing` (clause 10). An entry without a signature takes one as the hex
      of the release's `.sig`, through the signature route (clause 9).
    - The tab neither offers nor imports a signing file (clauses 17 and 18).
    - **OK** persists and **Cancel** discards; both conclude the form, and only
      a failed save keeps it open beside its message. **Delete** stands alone
      on the left. The form enforces no rule of its own: what it greys out is
      what the Server answers `409` to.

17. **Restates ADR-0027 clause 2, with the download removed. The Packages tab
    offers no signing file.** What `package sign --signing-info` signs from one
    is refused (clause 10), so the tab offers nothing to take to a key. The
    format and the command stay until the operator's signing tools are removed
    (Out of scope).

18. **Restates ADR-0033 clause 12, with the import removed. The Packages tab
    imports no signing file.** Each entry takes its signature on its own, as the
    hex of the release's `.sig` (clause 16).

**Out of scope:**

- the operator's signing tools: `classisctl package keygen`, `sign` and
  `public-key`, the signing file format and `package sign --signing-info`
  (ADR-0027), and the package key `pki init` makes. They stay until a later
  cleanup removes them;
- who besides the release run may hold a Package Signer, and so how
  `otelcol`, other third-party Packages and Foreign Agents' builds are signed.
  Until that is decided no such Package can be delivered;
- what stops a stolen Package Signer before it expires: revocation, shorter
  certificates, or a minimum issue date;
- the `[packages] self_update` consent, kept as ADR-0018 has it (clause 7);
- the Root's ceremony, its custody and the procedure that issues a Package
  Signer, which belong to its custodian;
- `publish` verifying every `.sig` before the release is created.

## Alternatives considered

- **Keep the raw key beside the chain.** A 64-byte signature would still be
  checked against `verification_key`, and a `PackageSignature` against the
  Roots. It keeps the
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
- **The upload stays manual and the same.** Only the signature an operator
  uploads changes: the release's `.sig`.
- **The operator's tools still exist, and what they make is refused.** A
  signature from `classisctl package sign`, by hand or through the signing
  file, is answered `400`. The cleanup that removes them is a follow-up.
- **Other Packages wait.** `otelcol`, other third-party Packages and Foreign
  Agents' builds cannot be delivered as Packages until the question left out of
  scope is decided, and `classisctl package fetch` uploads Packages no Client
  takes. G-10 is then met for the Client's own Package alone, which the drafted
  change to G-10 below states.
- **An expired Package Signer stops its versions.** With 10-year certificates
  and replacement well before the end, a version older than its Package Signer
  stops installing, a reinstall included, unless it is signed again. A host
  whose clock is wrong refuses valid signatures, as it would refuse the
  Server's TLS certificate.
- **The Server refuses on write and sets aside on load.** An entry whose stored
  signature does not verify at startup turns unsigned, named in a warning, and
  its signature stays on disk. An operator replaces it with the release's
  `.sig`; for a Package already assigned to an Agent that write is refused, as
  every write to its entries is
  ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clause 8), so the
  operator rolls out a new version instead.
- **A Root is a single point.** Its key signs every Package Signer, and its
  custody is outside this repository. Losing it means a release that ships a
  new Root, and a hand upgrade for every Client that cannot take it.
- **The specification changes, and the human lands it, before this ADR merges
  or with it** ([`AGENTS.md` §3](../../AGENTS.md#3-adr-rules), rule 7).
  Drafted text:
  - in the security paragraph of _Strategy_, replace "signed with a key the
    operator holds" with "signed by a Package Signer that the project's Package
    Root issued";
  - in _Package_, replace "and the operator's signature" with "and its
    signature, made by a Package Signer the Package Root issued", and replace
    "the Server checks a signature against the operator's public key when it has
    one and reports a failed check, but the Agent's check decides" with "the
    Server refuses a signature that does not verify, and the Agent's check
    decides";
  - in G-10, replace "the Collector's, and the Client's own" with "the
    Client's own, and the Collector's once a Package Signer is issued for its
    Packages". The Collector's update returns when the follow-up below decides
    who may hold a Package Signer besides the release run.

  Landing it names the accepted ADRs whose basis it moves. A search for the
  operator's key and for the Collector's Packages found these, for the human to
  judge: ADR-0017, ADR-0026 (Context and Consequences), ADR-0027, ADR-0028,
  ADR-0033 (Context), ADR-0034 (Context), ADR-0043 (Context and clause 4) and
  ADR-0056.
- **Wording elsewhere.** ADR-0010 clause 17 and the context of ADR-0017 speak of
  the statement "the operator signs". The mechanism holds; whether the wording
  moves is for the human to judge.
- **Follow-ups:**
  - removing the operator's signing tools, the signing file and `pki init`'s
    package key;
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
  `400` and stores nothing; a stored signature that does not verify turns the
  entry unsigned at load and stays in the store; `signature_state` takes
  `valid` and `missing` only; the bundled UI reads `signature_state` and the
  signature route, and names no signing file, no `verification_key`, and no
  `invalid` or `unchecked` state.
- `crates/classis-agent`: every Supervisor-backed Agent declares
  `AcceptsPackages` without any key; an offer whose signature does not verify is
  refused before the artifact is opened; the self-update takes a release signed
  through a test Root; an `--endpoint` install takes the CA beside the program
  and writes no package key.
- `crates/classis-tools`: the `supervisor.toml.fragment` of `pki init` names no
  package key; `packaging/package-signer.der` chains to the compiled-in Package
  Root (`tests/release_workflow.rs`).

**Not mechanically decidable:**

- that every shipped binary is a release build, which reads no
  `CLASSIS_DEBUG_PACKAGE_ROOT`; the release workflow builds with `--release`;
- that the custodian issues Package Signers only, with the profile of clause 2,
  and keeps the Root's key outside GitHub.
