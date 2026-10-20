# ADR-0029: A bootstrap certificate may be issued as a password-protected PKCS#12 file, which the Server keeps for download until the certificate ends and the Client enrols with

- **Status:** 🟢 accepted · clause 2 superseded by [ADR-0030](0030-a-pkcs12-password-of-4-to-128-characters.md) · clauses 3 and 5 superseded by [ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md) · clause 4 superseded by [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
- **Date:** 2026-10-14
- **Deciders:** Markus Brigl
- **Applies to:** the bootstrap-certificate routes of the Operator plane in `crates/fleet-server/src/api.rs` and the module that issues and records bootstrap certificates, the `bootstrap-certificates/` directory under `config_dir`, the Enrolments tab of the bundled UI in `crates/fleet-server/static/index.html`, `service install`, its flags and the questionnaire of the Client in `crates/fleet-agent/src/cli.rs`, `crates/fleet-agent/src/main.rs` and `crates/fleet-agent/src/config_init.rs`, the steps `packaging/linux/postinst` prints, the enrolment in `crates/fleet-agent/src/service/enrol.rs`, the `p12-keystore` crate in `Cargo.toml`, and every document that tells an operator how to hand out, revoke or list a bootstrap certificate or install a Client
- **Supersedes:** [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clause 37; [ADR-0020](0020-the-client-install-takes-the-fleet-files-it-finds-beside-its-program.md) clauses 1, 2, 3 and 4; [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 12; [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clauses 21, 24 and 25

## Context

A new host enrols with a bootstrap certificate and its private key
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 10). The Server issues the pair on request and hands the key out exactly once, in the
response, unencrypted, and keeps nothing of it
([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clause 21). The UI holds
the key in memory until the page closes (ADR-0028 clause 25). The operator then carries two PEM
files, `bootstrap.pem` and `bootstrap-key.pem`, to the host, where the install finds them beside its
program ([ADR-0020](0020-the-client-install-takes-the-fleet-files-it-finds-beside-its-program.md)).

The forces:

- **The key travels in the clear.** Between the UI and the host the bootstrap key is a plaintext
  file in a download folder, a ticket or a mail. Whoever holds it can join the enrolment queue
  under that bootstrap certificate's subject. An operator still has to approve the request
  (ADR-0021 clause 21), but the subject is what the operator judges by (ADR-0028 clause 29).
- **A key the page drops is gone.** An operator who closes the tab before saving, or who must hand
  the same bootstrap certificate to a second host a day later, has to issue a new one. The record
  then grows by one certificate per mishap, each valid for days.
- **Two files are half a pair waiting to happen.** ADR-0020 clause 1 needs a rule and a warning
  for one half lying alone.
- **PKCS#12 is the format operators' tools know** for "a certificate with its key, under a
  password": OpenSSL, Windows, macOS Keychain and Java import it. OpenSSL 3 writes it by default
  with AES-256-CBC under PBKDF2 and an HMAC-SHA-256 MAC.
- **No crate in the tree reads PKCS#12.** `rustls` and `rcgen` read PEM and DER only. OpenSSL is
  banned from the build (`deny.toml`,
  [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
- **A packaged install never lies beside the fleet's files.** The `.deb` and the `.rpm` deliver the
  program to `/usr/libexec/<PRODUCT_NAME>/`, and the command on `PATH` resolves to the layout under
  `/opt` ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clauses 36 and 38); `std::env::current_exe` resolves symbolic links on Linux. Nobody puts a
  bootstrap identity there, so a host installed from a package has only the questionnaire, and a
  configuration-management run (Ansible, Puppet, a Kickstart `%post`) has no way to enrol it with a
  `bootstrap.p12`. Its post-install must not enrol either: the enrolment waits for an operator, and
  `apt` or `dnf` would hold the package database while it waits.
- **A scripted install has no terminal** (ADR-0020). A password must reach it without being
  typed, without the process list and without the environment, which a child process inherits.
- **A revoked row stays until its certificate ends** — up to 90 days. An operator who revoked a
  batch handed to the wrong customer, or one issued by mistake, looks at those rows for weeks, and
  each still counts toward the record's 10 000 entries. The revocation is what keeps a certificate
  out (ADR-0021 clauses 34 and 39); the record is what the operator reads. The human decided that
  deleting removes the entry and leaves the revocation.

This serves **G-17** (the connection is secured and the Agent is identified), **G-11** (the Client
runs as an OS service, installed by script), **Q-1** (no credential travels unencrypted beyond the
loopback), **Q-2** (a parser of a downloaded artifact is bounded and fuzzed) and **Q-3** (the new
dependency passes the supply-chain gate), and **G-5** (any UI can drive the fleet through the
REST API alone).

## Decision

We will let an operator issue a bootstrap certificate with a password, in which case the Server
makes a PKCS#12 file (`bootstrap.p12`) of the certificate and its key encrypted under that
password, keeps it for download until the certificate ends or is revoked, and never hands out the
key in PEM; and we will have the Client's install find `bootstrap.p12` beside its program, or in the directory
`--fleet-files` names, and enrol with it, taking the password from a hidden question or from
`--bootstrap-password-file`; and we will let an operator delete a revoked bootstrap certificate's
entry from the record, leaving its revocation on the revocation list.

1. **The file.** A `bootstrap.p12` holds one private key and the one bootstrap certificate it
   belongs to, and nothing else: neither the bootstrap CA, nor the server CA, nor any other
   certificate. Key and certificate are encrypted with PBES2 — PBKDF2-HMAC-SHA-256 at 600 000
   iterations and AES-256-CBC — and the file carries an HMAC-SHA-256 MAC at 600 000 iterations. The
   Server writes and the Client reads it with `p12-keystore` (clause 14).

2. **A password is 12 to 128 characters of UTF-8 without control characters.** Anything else is
   answered `400`. The password is not stored, logged or audited anywhere, on the Server or on the
   host. It reaches the Server on the Operator plane, which beyond the loopback serves TLS only
   (ADR-0021 clause 17).

3. **Restates ADR-0028 clause 21. The Server issues a bootstrap certificate on request.**
   `POST /api/v1/bootstrap-certificates` with a JSON body
   `{"subject": {…}, "validity_days": n, "password": "…"}` (`Content-Type: application/json`, as
   `POST /api/v1/revocations`), `password` optional, makes a fresh ECDSA P-256 key and signs a
   certificate with the bootstrap CA's key. The certificate is `CA:FALSE`, `digitalSignature`,
   `clientAuth`, with a 16-byte random serial (ADR-0021 clause 32) and no subject alternative name.
   - **Without `password`** it answers `201` with `serial`, `subject`, `not_before`, `not_after`,
     `certificate_pem` and `private_key_pem`, under `Cache-Control: no-store`. The private key
     exists only in that response: it is not stored, not logged and not audited, and a lost key is
     replaced by issuing again.
   - **With `password`** it makes the PKCS#12 file of clause 1, writes it as clause 4 says, and
     answers `201` with `serial`, `subject`, `not_before`, `not_after` and `certificate_pem`, and
     no `private_key_pem`. The key exists in plaintext only in the Server's memory while it issues;
     it leaves the Server only inside that file.

4. **Restates ADR-0028 clause 24. The Server records what it issued, and keeps a PKCS#12 file
   until its certificate ends, is revoked or its entry is deleted.** Before it answers, the Server writes the serial, the subject, the
   SHA-256 fingerprint of the public key, the issuing time, `not_after` and whether a PKCS#12 file
   was made to one file per certificate under `config_dir/bootstrap-certificates/`, and the
   PKCS#12 file, when one was made, beside it as `<serial>.p12`, owner-only, both written
   atomically. `GET /api/v1/bootstrap-certificates` lists every entry with whether it is revoked
   and whether its PKCS#12 file can be downloaded (`p12`). `GET
   /api/v1/bootstrap-certificates/{serial}/p12` answers `200` with the file as
   `application/x-pkcs12`, `Content-Disposition: attachment; filename="bootstrap.p12"` and
   `Cache-Control: no-store`, as often as it is asked, and `404` when the certificate has no such
   file, is revoked, has ended or its entry was deleted. An entry and its PKCS#12 file are removed
   once the certificate has ended, or when an operator deletes the entry (clause 15). A revocation with the authority `bootstrap` removes the file before it is answered,
   and lifting the revocation (ADR-0021 clause 38) does not bring it back. At most 10 000 valid
   entries are kept, and a request beyond that is answered `409`. A bootstrap certificate is
   revoked as ADR-0021 clause 34 states, with the authority `bootstrap`. Each issuance is recorded
   in the audit as `enrolment.bootstrap_issued` with serial, subject, `not_after` and `p12`, each
   download of a PKCS#12 file as `enrolment.bootstrap_p12_downloaded` with the serial, and each
   deletion as `enrolment.bootstrap_deleted` with the serial and subject
   ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)). When the audit cannot be
   written, nothing is handed out or deleted and the request is answered `503`.

5. **Restates ADR-0028 clause 25. The Enrolments tab issues, lists, revokes and deletes
   bootstrap certificates.** The tab issues one with the organization, the organizational unit, the
   validity and an optional password an operator types, through the route of clause 3. The
   password is typed twice, and the tab sends nothing while the two differ. The row of each
   certificate issued **without** a password in the open page offers its pair for saving as
   `bootstrap.pem` and `bootstrap-key.pem`, the names `supervisor.toml.fragment` gives them
   (ADR-0028 clause 3), as often as the operator likes. The page holds those keys in memory only and
   writes none to browser storage. It drops a key once its certificate is revoked or has ended, and
   every key when it is reloaded or closed, which it asks before while it holds one. The row of
   each certificate whose entry says `p12` offers **Save bootstrap.p12**, in any page and at any
   time, through the route of clause 4. A certificate issued elsewhere, or without a password
   before the page was opened, offers nothing to save. The tab lists the certificates of
   `GET /api/v1/bootstrap-certificates` with a press that revokes a valid one by its serial with the
   authority `bootstrap`, and on a revoked one a **Delete** press that asks first and then deletes
   its entry through the route of clause 15. Each pending request shows the entry its `bootstrap_serial` names
   (ADR-0021 clause 22), with its subject, serial and end, and says so when no entry matches. The
   tab uses no route the REST API does not offer.

6. **Restates ADR-0020 clause 1. Beside the program is the directory of the running
   executable, unless `--fleet-files` names another.** The install reads it from the operating
   system (`std::env::current_exe`), before the program is staged, so it is where the operator ran
   the program from. `service install --fleet-files <dir>` names the directory the install looks in
   instead, for all of the fleet's files, with or without `--interactive`; wherever ADR-0020 or this
   ADR says "beside the program", that directory is meant when the flag is given. A `<dir>` that is
   not a readable directory fails the install before anything is written, naming the flag. The
   install never looks in both. A file counts only when
   it is a readable regular file under its exact name. **A bootstrap identity** is either the
   bootstrap pair, `bootstrap.pem` with `bootstrap-key.pem`, or `bootstrap.p12`; wherever ADR-0020
   says "bootstrap pair", a bootstrap identity is meant. The bootstrap pair counts only as a pair;
   one of the two alone is named in a warning and not used. When `bootstrap.p12` and any file of
   the pair lie there together, a warning names them and none of them is used, so the install
   never guesses which identity is meant. `package-signing-key.pub` counts when its content,
   trimmed, is 64 hexadecimal digits; any other content is named in a warning and not used.

7. **The Client reads a `bootstrap.p12` bounded and in memory.** A file over 64 KiB is refused
   before it is read. It must decrypt and pass its MAC under the password, use only the schemes of
   clause 1's family (PBES2 with PBKDF2-HMAC-SHA-2 and AES; no PBES1, RC2 or 3DES), and hold
   exactly one private key with the one certificate whose public key matches it; anything else is
   refused, naming the file. The key and the certificate are held in memory for the enrolment, and
   the decrypted key is never written to disk. The identity the enrolment then makes and stores is
   the Client's own (ADR-0021 clause 21), as with the pair.

8. **Restates ADR-0020 clause 2. The questionnaire asks only what has no useful default on a fresh
   host, and offers no answer the Client would refuse.** It asks for the Server `endpoint`,
   suggesting `wss://127.0.0.1:4320/v1/opamp`; a `ws://` or `http://` endpoint is refused unless its
   host is a loopback IP literal — `127.0.0.1` or `::1`; a host name is never loopback, `localhost`
   included — and the question is asked again with a message saying that beyond the loopback the
   endpoint must be `wss://` or `https://`. It asks for the Agent `name`, reported as
   `service.instance.name`. It asks for the CA certificate of the Server, written as
   `[tls] ca_file`, for every `wss://` or `https://` endpoint, without a question before it. It
   asks for the bootstrap identity only while the Client is not enrolled — while its state
   directory holds no certificate the Server issued: first for the bootstrap certificate, a PEM
   certificate or a PKCS#12 file. A path ending in `.p12` or `.pfx` is read as PKCS#12: the
   password is asked next, with input hidden, unless `--bootstrap-password-file` gave it
   (clause 10), and a password the file does not open under is asked again. Any other path is read as
   PEM, and its private key is asked next. It asks for the package verification key, written as
   `[packages] verification_key`; an empty answer is accepted, and the install then says that the
   Client installs no package, its own update included, until a key is configured.

   **Each question's default is what the file holds, else what lies beside the program**
   (clause 6), else none; the password has no default. The bootstrap identity is neither copied
   nor written into the file: the questionnaire enrols with it directly against the Server, after
   the file is written. It connects with the identity where it lies, sends the CSR (ADR-0021
   clause 21), prints the request's key fingerprint and waits until an operator approves it, then
   stores the issued certificate in the state directory, where the Client looks for it first. An
   interrupted wait leaves the written file and registers nothing; running the install again
   resumes the request in flight, printing its fingerprint. A rejected request stays rejected for
   its key, and the wait goes on until it is interrupted: removing the pending key and request from
   the state directory starts a fresh one. On an enrolled Client no file of the identity is asked:
   the Client renews what it was issued. A certificate already issued by the Server's client CA goes
   in `[tls] cert_file` and `key_file`, by editing the file. The identity is required while it is
   asked, and a path that names no readable file, here or for the CA, is asked for again.

   **The answered CA is copied beside the written file**, as `server-ca.pem`, owner-only on Unix,
   and the file names the copy. A copy left by an earlier answer is replaced. The copy is handed
   over to the service account with the file (ADR-0019 clause 13). The questionnaire asks nothing
   about the self-update: the file carries `[packages] self_update = true`, and the verification
   key decides whether that takes effect
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). Everything else is
   written as commented defaults. No question asks for a credential, and no written file has an
   `[auth]` section; a leftover `[auth]` section is kept and ignored, as ADR-0019 clause 17 stated.
   The bootstrap password is not a credential of either plane: it opens a file on the host and is
   never sent.

9. **Restates ADR-0020 clause 3. `service install --endpoint <URL>` writes the first
   configuration without a terminal, with what lies beside the program.** It writes the file
   `--interactive` writes, through the same renderer, with the endpoint given rather than asked:
   the same shape, mode `0600`, never overwriting an existing file, validated by the rule the
   Client applies to its endpoint at startup before anything is written — a `ws://` or `http://`
   endpoint whose host is not `127.0.0.1` or `::1` is refused, naming the setting, and `localhost`
   is no exception. It conflicts with `--interactive` and carries the self-update answer
   ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause 3). For a
   `wss://` or `https://` endpoint, a `server-ca.pem` beside the program — in the directory
   `--fleet-files` names, when given (clause 6) — is copied and written as `[tls] ca_file` as the
   questionnaire's answer would be, and a `package-signing-key.pub` beside it is written as
   `[packages] verification_key`. Each file it takes is printed. It has no flag naming the CA file
   or the client identity one by one: `--fleet-files` names the one directory the fixed names are
   looked up in, and `--bootstrap-password-file` (clause 10) the password of a `bootstrap.p12`, which
   is not a credential. It takes no credential, since there is none. The installers do not write
   TOML themselves. **The same rule binds every default an installer supplies:** no installer
   writes, prefills or prints a value the Client would refuse at startup, and none writes a setting
   that stands in for a client certificate.

10. **Restates ADR-0020 clause 4. A non-interactive install enrols with a bootstrap identity it
   finds.** When the configuration — written by `--endpoint` or already on disk — has a `wss://` or
   `https://` endpoint, the Client is not enrolled, and a bootstrap identity lies beside the
   program, the install enrols with it as the questionnaire does (clause 8): it prints the
   request's key fingerprint, waits until an operator approves it or the wait is interrupted, and
   stores the issued certificate. It needs no terminal. An installer that runs the program from a
   directory holding a bootstrap identity therefore waits for an approval; one that runs it from
   where none lies does not. **For `bootstrap.p12` the password comes from
   `service install --bootstrap-password-file <path>`:** the file's first line, a trailing `\n` or
   `\r\n` removed. The file is read once and neither copied, changed nor removed. A
   `bootstrap.p12` taken without the flag, or a file it does not open under, fails the install
   before anything is written, naming the flag; the flag with no `bootstrap.p12` to open fails the
   same way. The flag names a password, not an identity or a credential. There is no environment
   variable and no command-line value for the password.

11. **A packaged host enrols in a step after the package.** The post-install of the `.deb` and the
    `.rpm` stays as ADR-0019 clause 36 states: it runs `service install` from the payload path, finds
    no fleet files and enrols nothing, so `apt` and `dnf` never wait for an approval. The host is
    enrolled by the step clause 13 prints, interactively, or by a script that puts the fleet's files
    in a directory, names it with `--fleet-files`, and runs the non-interactive install of clause 10:

    ```console
    sudo opamp-fleet service install --endpoint wss://<server>/v1/opamp \
      --fleet-files /root/fleet --bootstrap-password-file /root/fleet/bootstrap.pass
    sudo systemctl start opamp-fleet
    ```

    That step waits for the operator's approval as clause 10 states; a configuration-management tool
    runs it as a task that may wait. Removing the directory afterwards is the script's.

12. **The server CA stays a file of its own.** `server-ca.pem` is the trust anchor written as
    `[tls] ca_file` and kept for every later connection and renewal, while the bootstrap identity
    serves once and is removed (ADR-0020). It comes from the operator's offline directory, not from
    the Server it is meant to verify, and the Server never puts it into a PKCS#12 file.

13. **Restates ADR-0019 clause 37. No installer starts the service it registers.** The Linux
    post-install and the MSI register the service and leave it stopped — knowingly departing from
    Debian Policy and `dh_installsystemd` — because a Client with no configuration holds no client
    certificate and is refused at startup, at fleet scale where nobody watches a terminal. The one
    exception is an upgrade of a Linux host whose service was running: it is restarted, so a
    configured host finishes the upgrade on the delivered binary. The post-install prints the two
    remaining steps:

    ```console
    sudo opamp-fleet service install --interactive
    sudo systemctl start opamp-fleet
    ```

    The second `service install` is a re-install, which is idempotent and writes the configuration
    that `service install` refuses to overwrite once it exists. The first step is `--interactive`,
    which asks for the client identity — the bootstrap identity of clause 6 — and not `--endpoint`
    alone: a configuration holding only an endpoint is one the Client refuses at startup, so
    printing it as the whole first step would present an unauthenticated Client as the default.
    After the two steps it prints the scripted form of clause 11 — `--endpoint` with
    `--fleet-files` and, for a `bootstrap.p12`, `--bootstrap-password-file` — as the way to enrol
    without a terminal. The alternative it prints for writing the file by hand names the endpoint
    together with `[tls] cert_file` and `key_file`, the identity the operator adds before the
    start, and names no credential and no `[auth]` section, because the Client reads none
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).

14. **Restates ADR-0021 clause 12. Issuance adds `rcgen`, `time`, `x509-parser` and
    `p12-keystore`, and no system dependency.** `rcgen` (features stated: `crypto`, `ring`, `pem`,
    `x509-parser`) generates the CSR and signs it; `time` expresses validity; `x509-parser` reads a
    certificate's validity for the renewal window. The `ring` backend is the provider
    [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
    already installs, so no OpenSSL and no cmake enter the build. `ring` compiles C and assembly in
    its build script, so a C compiler is needed either way; what this keeps is the absence of
    system libraries. `p12-keystore` (pinned exactly, `default-features = false`, so its `pbes1`
    feature with `rc2` and `des` is not linked) writes the PKCS#12 file in the Server and reads it
    in the Client. It is pure Rust on the RustCrypto crates; it handles the password-based
    encryption only, and the TLS handshake stays on `ring`. `dialoguer` gains its `password`
    feature for the hidden question; its one dependency, `zeroize`, is already in the tree.

15. **Only a revoked entry is deleted, and its revocation stays.**
    `DELETE /api/v1/bootstrap-certificates/{serial}` removes the entry and any PKCS#12 file of a
    certificate whose revocation is on the list, and answers `204`. It answers `409` for a
    certificate that is not revoked — revoke it first — and `404` for a serial the record does not
    hold. It touches the revocation list not at all: the certificate stays refused at the handshake
    for as long as it is valid (ADR-0021 clauses 34 and 39). A request that still carries it is
    shown as *not issued here*, as one with a certificate made elsewhere is. Lifting the revocation
    of a deleted certificate is still possible through `DELETE /api/v1/revocations/{id}` and lets
    it enrol again; the record does not list it again. The route is cross-site protected as every
    changing route of the plane is (ADR-0021 clause 16).

**Out of scope:**

- A PKCS#12 file for anything but a bootstrap certificate: the Client's issued identity, the
  Server's or a Gateway's certificate, and the `pki` commands of `opamp-fleetctl`.
- Changing the password of a kept PKCS#12 file, or making one for a certificate issued without a
  password; the operator issues a new certificate.
- Removing `bootstrap.p12` or the password file from the host after enrolment, as ADR-0020 leaves
  it for the pair.
- Reading a PKCS#12 file made by another tool beyond what clause 7 accepts.
- A `bootstrap.p12` named in `supervisor.toml`, so that the service enrols with it when it starts.
- Asking anything in a package's post-install, or preseeding answers through debconf or RPM
  macros.
- Deleting host certificates or their register entries; deleting a valid, unrevoked bootstrap
  certificate; removing revocation-list entries automatically once the certificate has ended
  (ADR-0021 clause 37 governs that list).

## Alternatives considered

- **One PEM file holding the certificate and the key.** One file, no new dependency, but the key
  still travels in the clear and nothing on the Server is kept to download again.
- **An encrypted PKCS#8 key (`ENCRYPTED PRIVATE KEY`) beside the PEM certificate.** It encrypts the
  key with the same PBES2 scheme, but stays two files, and few operator tools import it as one
  identity the way they import PKCS#12.
- **The `p12` crate.** It reads and writes only the legacy schemes (RC2, 3DES, SHA-1 MAC), which
  OpenSSL 3 no longer writes by default.
- **OpenSSL's PKCS#12 support.** OpenSSL is banned from the build (ADR-0013, `deny.toml`).
- **The Server keeps the PEM key and hands it out again.** It would hold plaintext keys of every
  valid bootstrap certificate; the kept PKCS#12 file is useless without a password the Server
  never stores.
- **The Server keeps the password, or derives it.** Whoever reads `config_dir` would then open
  every kept file, and the password would protect nothing the directory's mode does not.
- **The Server keeps nothing, and the operator keeps the `.p12`.** This is ADR-0028 clause 21 with
  a different file; it was the human's decision that the file stays downloadable in later sessions.
- **The server CA inside the PKCS#12 file.** Tools read further certificates in a PKCS#12 file as
  the chain of its key's certificate and import them as intermediate or root authorities; the
  server CA belongs to no such chain. It outlives the bootstrap identity, so the install would have
  to extract and keep it anyway, and the Server would deliver the anchor that verifies itself.
- **Password from an environment variable or a command-line value.** A command line is visible in
  the process list; an environment variable is inherited by every child, the Supervisor's Managed
  Processes included, and readable under `/proc/<pid>/environ`.
- **Hand out both the PKCS#12 file and the PEM key.** The key would again leave in the clear, and
  the password would protect a copy nobody needs.
- **The service enrols with a `bootstrap.p12` named in `supervisor.toml`** (`[tls] bootstrap_p12`,
  `bootstrap_password_file`). `apt install` alone would then do, but the password file lies beside
  the configuration, readable by the service account, for as long as nobody removes it, and the
  password protects nothing the file's mode does not. ADR-0020 already rejected enrolling on first
  start for the pair.
- **Preseeding the post-install (debconf, RPM macros).** debconf exists for the `.deb` only, keeps
  its answers in its database, and the post-install would wait for the approval while it holds the
  package database.
- **A fixed directory such as `/etc/<PRODUCT_NAME>/bootstrap/` that the install also searches.**
  It saves one flag, but makes the install look in two places, and a forgotten identity there
  would enrol the next install unasked.
- **Delete the revocation with a deleted entry.** A certificate still valid could enrol again the
  moment its row disappeared.
- **Delete a valid certificate as well, revoking it on the way.** One press would do two
  irreversible things; two presses keep revocation the deliberate act it is.
- **Hide revoked rows in the UI only, behind a filter.** The record would keep the entries the
  operator wanted gone, and a script would still see them; the REST API is the integration
  contract (G-5).
- **No decision.** The key travels in the clear, a closed tab costs a new certificate, and a
  scripted install of a PKCS#12 identity is impossible.

## Sources / Prior art

- [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md) clauses 36,
  37 and 38; [ADR-0020](0020-the-client-install-takes-the-fleet-files-it-finds-beside-its-program.md)
  clauses 1–5 and its *Out of scope*, which this ADR narrows by `--fleet-files`; [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clauses 10, 12, 16, 17, 21, 22, 32, 34, 37, 38 and 39;
  [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clauses 3, 21, 24,
  25 and 29; [ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md).
- RFC 7292, PKCS #12 v1.1: <https://www.rfc-editor.org/rfc/rfc7292>. RFC 8018, PKCS #5 v2.1
  (PBES2, PBKDF2): <https://www.rfc-editor.org/rfc/rfc8018>.
- RFC 9579, PBMAC1 in PKCS #12, obsoleted by RFC 9879 — the MAC this ADR does not use, since
  `p12-keystore` 0.4.1 has no PBMAC1 in its source: <https://www.rfc-editor.org/rfc/rfc9579>.
- OpenSSL 3.0 `openssl-pkcs12(1)`, read from the manual page of OpenSSL 3.0.22: AES-256-CBC with
  PBKDF2 and a SHA-256 MAC are the defaults, at 2048 iterations; RC2 and 3DES are the `-legacy`
  option. <https://docs.openssl.org/3.0/man1/openssl-pkcs12/>
- OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA-256 at 600 000 iterations.
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- `p12-keystore` 0.4.1, read for this ADR from its published crate
  (<https://crates.io/crates/p12-keystore/0.4.1>, <https://github.com/ancwrd1/p12-keystore>):
  MIT or Apache-2.0; Rust 1.85; writes `PbeWithHmacSha256AndAes256` with an HMAC-SHA-256 MAC by
  default, 10 000 iterations unless set; refuses MAC, PBES1 and PBKDF2 iteration counts above
  1 000 000 on import (0.3.2); `pbes1` is a default feature that pulls `rc2`, `des` and `cbc`.
  Released 2026-10-13; 0.4.0 on 2026-10-09.
- A probe crate depending on `p12-keystore = "=0.4.1"` with `default-features = false`, compared
  by `cargo tree` against this workspace: 21 crates are new (`p12-keystore`, `pkcs12`
  0.2.0-pre.0, `cms` 0.3.0-pre.1, `pkcs5`, `pkcs8`, `spki`, `der`, `der_derive`, `x509-cert`,
  `pem-rfc7468`, `pbkdf2`, `scrypt`, `salsa20`, `hmac` 0.13, `aes-gcm`, `aead`, `ctr`, `ghash`,
  `polyval`, `universal-hash`, `flagset`); `aes`, `cbc`, `sha1`, `sha2`, `rand` and
  `x509-parser` are already present at the same versions; `rc2` and `des` are absent. `cargo deny`
  was not run locally; the security workflow runs it on the change that adds the crate.
- `dialoguer` 0.12: the feature `password` enables `Password` and depends on `zeroize` only.

## Consequences

- Positive: the key leaves the Server only encrypted, and an operator can hand the same bootstrap
  certificate to a second host, or download it again after closing the tab, without issuing a new
  one (G-17).
- Positive: one file per identity on the host, which operators' tools can also inspect.
- Positive: a scripted install of a PKCS#12 identity needs one flag and one file (G-11), and a host
  installed from a `.deb` or `.rpm` is enrolled by configuration management with one command after
  the package, without the package manager waiting.
- Negative / trade-offs: the Server now keeps key material, encrypted, for up to 90 days per
  bootstrap certificate. Whoever reads `config_dir/bootstrap-certificates/` and guesses a password
  joins the enrolment queue; the 12-character minimum and 600 000 iterations bound the guessing,
  and the operator's approval still stands between the queue and the fleet.
- Negative / trade-offs: 21 crates enter the build, two of them pre-releases (`pkcs12`, `cms`),
  under a version of `p12-keystore` published the day before this ADR. Every bump is reviewed as a
  dependency change (Q-3).
- Negative / trade-offs: a PKCS#12 file made by another tool with legacy schemes or a PBMAC1 MAC is
  refused by the Client; such a file is re-exported with OpenSSL 3's defaults.
- Negative / trade-offs: the password file of a scripted install lies on the host until someone
  removes it, as the pair does today.
- Positive: a revoked certificate leaves the list in two presses instead of staying up to 90 days,
  no longer counts toward the 10 000 entries, and every deletion is on the audit record.
- Negative / trade-offs: a deleted entry's revocation lives on in the revocation list, where only
  `GET /api/v1/revocations` shows it; a pending request that still carries the certificate reads
  *not issued here*, which hides that this Server once issued it.
- Follow-ups: a view of the revocation list in the UI, should operators need to see what a deleted
  entry left behind.
- Follow-ups: the operator manual's installation and enrolment pages, the OpenAPI document of the
  two routes, and a fuzz target for the Client's PKCS#12 reader.

## Enforcement

Tests that will carry `Verifies: ADR-0029`:

- Issuing with a password answers no `private_key_pem`, writes `<serial>.p12` owner-only, and the
  download route returns a file that opens under the password and holds exactly the certificate
  and its key; a password outside 12 to 128 characters is answered `400` (clauses 2–4).
- The download route answers `404` after the certificate is revoked or has ended, and the file is
  gone from `config_dir` (clause 4).
- Issuance and download write their audit entries, and neither entry nor any log line holds the
  password (clauses 2 and 4).
- `bootstrap.p12` is found beside the program; lying beside a file of the pair, neither is taken
  (clause 6).
- With `--fleet-files <dir>` the files are found in `<dir>` and not beside the program, and `--endpoint` copies `server-ca.pem` from it; a `<dir>`
  that is no readable directory fails the install before anything is written (clause 6).
- The post-install's printed text names the scripted form with `--fleet-files` and
  `--bootstrap-password-file`, and no credential (clause 13).
- The Client refuses a file over 64 KiB before reading it, a wrong password, a PBES1 file, and a
  file with no key or a key without its certificate (clause 7).
- A non-interactive install with `bootstrap.p12` and `--bootstrap-password-file` enrols; without
  the flag, or with the flag and no file, it fails before writing anything (clause 10).
- Deleting a revoked entry answers `204`, removes the entry and its PKCS#12 file from
  `config_dir`, writes `enrolment.bootstrap_deleted`, and leaves the revocation on the list: the
  certificate is still refused at the handshake (clauses 4 and 15).
- Deleting a valid entry answers `409`, an unknown serial `404`, and a refused audit `503` with
  the entry kept (clauses 4 and 15).
- A fuzz target for the Client's PKCS#12 reader runs in CI (Q-2).
- `cargo deny` keeps `rc2` and `des` out of the graph: a `[bans]` entry names them (clause 14).

**Not mechanically decidable:** that the UI never stores a typed password and that the server CA
is never put into a PKCS#12 file, and that the tab offers **Delete** only on revoked rows and asks
before it deletes, are held by review (clauses 5, 12 and 15); that the `.deb` and `.rpm`
post-install enrols nothing is held by review of `packaging/linux/postinst` (clause 11).
