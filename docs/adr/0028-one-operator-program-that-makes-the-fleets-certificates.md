# ADR-0028: The operator tools are one program, `opamp-fleetctl`, published with every release for Linux and macOS, that makes the fleet's certificate authorities and the Server's certificate; the Server issues bootstrap certificates whose subject the operator names, under a bootstrap CA of one year; every certificate is named by its product and its role; and the Server says before any of them ends

- **Status:** 🟢 accepted · clauses 21, 24 and 25 superseded by
  [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  · clauses 2 and 15 superseded by
  [ADR-0031](0031-opamp-fleetctl-extracts-a-bootstrap-pkcs12-file-into-pem.md) ·
  clauses 22 and 29 superseded by
  [ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)
  · clause 20 superseded by
  [ADR-0045](0045-every-release-asset-carries-a-provenance-attestation-and-every-program-an-sbom.md)
- **Date:** 2026-10-10
- **Deciders:** Markus Brigl
- **Applies to:** the `pki` commands of `opamp-fleetctl` in
  `crates/fleet-tools/` and the module that carries them, the Server's
  `pki status` command in `crates/fleet-server/src/main.rs` and the module that
  carries it, the ending rule and the naming rule in `crates/fleet-core/`, the
  expiry warnings of the running Server, the bootstrap-certificate routes of the
  Operator plane in `crates/fleet-server/src/api.rs` and the module that issues
  and records bootstrap certificates, the signing of host and bootstrap
  certificates in `crates/fleet-server/src/ca.rs`, the `[enrolment]` and
  `[client_ca]` sections of `server.toml` and their startup checks in
  `crates/fleet-server/src/config.rs`, the `bootstrap-certificates/` directory
  under `config_dir`, the Enrolments tab of the bundled UI in
  `crates/fleet-server/static/index.html`, `scripts/dev-pki.sh` and what reads
  its output (`scripts/seed_test_configs.sh`, `.vscode/launch.json`,
  `.vscode/tasks.json`, the startup message of
  `crates/fleet-server/src/config.rs` that names it), and every document that
  tells an operator how to make, hand out or inspect a certificate or shows a
  certificate's subject; `crates/fleet-tools/` (the program it builds, its
  command tree and the names of its commands), the operator-tool build and its
  archives in `.github/workflows/release.yml`, the release notes, and every
  document or script that names an operator command

## Context

An Agent proves fleet membership with a client certificate in the TLS handshake
and nothing else, and the Server presents a certificate of its own on both
planes
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md),
[ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
That takes three certificate authorities, each with one job: a server CA that
signs the Server's certificate and a Gateway's downstream certificate, the
client CA the Server signs every host's certificate with (ADR-0021 clause 9),
and a bootstrap CA that signs the certificates a new host enrols with (ADR-0021
clause 19). Every host certificate is made by the Server itself, with `rcgen`
(ADR-0021 clause 12), and a host obtains its first one only through an enrolment
an operator opens and approves. Everything before that is the operator's: the
three CAs, the Server's certificate, a Gateway's certificate and the bootstrap
certificates.

The certificates are one of three things this project makes before a fleet does
anything useful; a package signing key and signed package artifacts are the
others (G-10, Q-1). Packing and signing an artifact and fetching a release of a
known agent are commands built from `crates/fleet-tools`. Unless a release
carries them, an operator who wants to roll out a single package needs a
checkout of this repository and a Rust toolchain on their own machine.

The forces:

- **G-17** asks for a secured connection and an identified Agent, and **Q-1**
  for a system that is secure whatever its configuration. A fleet whose first
  step is a hand-written `openssl` command line is secure only as far as that
  command line is right: a missing `extendedKeyUsage`, a CA key in SEC1 form the
  Server cannot load, a bootstrap CA that shares its subject with the client CA,
  or a server certificate that names the wrong host each fail later and
  elsewhere.
- **The requirements are the project's own and are scattered.** The client CA's
  key must be PKCS#8, because `rcgen` loads nothing else. The bootstrap CA must
  have a subject of its own, or the Server refuses to start. The server
  certificate needs the loopback among its names for the loopback Operator plane
  to be reachable through a tunnel. A tool that knows these rules writes them
  once; a manual can only list them.
- **`openssl` is a system dependency of the setup, though not of the build.**
  The build keeps system libraries out (ADR-0021 clause 12), and the operator's
  machine should not need one either. Its command-line behaviour also differs
  between OpenSSL 1.1, 3.x and LibreSSL.
- **Not every key belongs on the Server, and not every key off it.** Whoever
  holds the server CA's key can stand up a Server or a Gateway anywhere that
  every host trusts, so it stays on the operator's machine. The client CA's key
  has to be on the Server, because it signs renewals unattended, and whoever
  holds it mints member certificates directly. The bootstrap CA's key beside it
  adds nothing an attacker on the Server host does not already have: a bootstrap
  certificate opens nothing without an open window and an approval.
- **One bootstrap certificate for the whole fleet says nothing about where a
  request comes from.** The operator approving a request sees the bootstrap
  certificate's subject and fingerprint (ADR-0021 clause 22). When a bootstrap
  certificate per customer names that customer, the approver can tell which
  customer or site a request belongs to.
- **Bootstrap certificates are short-lived and handed out often.** Making each
  one on the offline machine is a trip there every time. On the Server it is one
  request on the Operator plane, which is guarded already (ADR-0021 clause 15),
  and the Server can list what it issued and revoke it by serial (ADR-0021
  clause 34). The operator who approves works in the Enrolments tab; issuing
  there keeps the step they take most often in the tool they approve with, and a
  UI that only the REST API's routes drive keeps G-5.
- **A CA lives as long as what replacing it costs justifies.** Replacing the
  server CA means a new `ca_file` on every host; replacing the client CA means
  every host enrolling again. Replacing the bootstrap CA touches only
  `server.toml` and the bootstrap certificates not yet used, so it can be
  replaced every year at little cost, and a key that is online is replaced on a
  schedule rather than only after a compromise.
- **A CA's end is not enforced where it would show first.** `rustls` treats a
  configured CA as a trust anchor, a name and a key without a validity, so a
  Server and its Clients keep accepting certificates under an expired CA. A
  browser on the Operator plane, `curl`, or another OpAMP implementation may
  refuse what this project's own ends accept, and nothing tells the operator
  that a CA or the Server's own certificate is about to end. The first sign of
  an expired CA is an outage somewhere else.
- **An audit reads certificates, not configuration.** An auditor shown a
  certificate from a host, a Server or a trust store asks who issued it and what
  it is for, and which of the six kinds of certificate a PEM file is should not
  show only in its extensions and its issuer. Nothing reads a subject to decide
  anything: a TLS client checks a server certificate's names against its subject
  alternative names (RFC 9525 section 2), the Server tells an enrolment
  connection from a member's by its issuer (ADR-0021 clause 19), names a host by
  the SAN URI it puts in (ADR-0021 clause 7) and decides a renewal by its proof
  (ADR-0021 clause 27). The subject is free to say what an auditor needs, and
  the name an operator wants there is that of their own installation, which no
  build constant knows.
- **The operator's own machine comes first.** It is where an operator works
  before any Server exists; the Server binary runs on the Server host, where the
  server CA's key is not to be.
- **The keys these tools make do not all belong on the Server host.** Whoever
  holds the package signing key and can make an offer runs code on every host it
  reaches, which is why the Client installs only what a key the operator holds
  has signed
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
  The server CA's key is kept off the Server host for a like reason. A program
  that makes those keys is a program for the operator's machine, and the binary
  that serves the fleet has no use for it.
- **The Server binary is the one program an operator certainly has,** an
  argument for making certificates there rather than in one more binary to
  build. It holds only while no operator tool is published; once one is, it is
  the program an operator downloads first, before any Server or Client exists.
- **One audience, one job.** The certificates, the signing key, the packing and
  the fetch are all done once per fleet or once per release, by the same person,
  on the same machine. A program per task, or a Server subcommand tree for part
  of it, is names too many, and certificate commands have no natural home in a
  program named after packages.
- **Keys need file modes.** Every key these commands write is `0600` in a `0700`
  directory (clause 10). Linux and macOS give that by `chmod`; Windows has no
  such modes, and an ACL that does the same is a piece of work of its own.
- **Names are a public contract,** and the obvious one is taken: `fleetctl` is
  the command-line tool of FleetDM, an actively maintained fleet-management
  product for the same audience, installed with `npm install -g fleetctl` and
  from its GitHub releases. Two `fleetctl` on one `PATH` cannot both be found,
  and a search for either finds the other.
- **The release is a contract too.** It is one workflow run from one version
  ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clause 30), and every row of its build matrix already builds the packer for
  the runner it runs on, Windows included, because the Client's archives are
  packed by it (clause 31 there). Its assets are listed exhaustively (clause 34
  there), and nothing in it is signed: one `SHA256SUMS` covers every asset.

This serves **G-17** (the connection is secured and the Agent is identified),
**G-5** (any UI can drive the fleet) and **Q-1** (secure by default).

## Decision

We will build the operator tools as one program, `opamp-fleetctl`, from
`crates/fleet-tools`, and publish it in every release as a `.tar.gz` for Linux
and macOS on amd64 and arm64. We will give it `pki` commands that make, with
`rcgen`, the three certificate authorities and the Server's and a Gateway's
certificate, keep the bootstrap CA's key on the Server, have the Server issue
bootstrap certificates through the Operator plane and its bundled UI with a
subject the operator names, name every certificate `<product> <Role> CA` or
`<product> <Role> Certificate` with the organization the operator gives, give
`opamp-fleetctl` and the Server a `pki status` command that says when the
certificates each can see end, and have the running Server warn before a
certificate it depends on ends, so that no step of setting up or running a fleet
needs `openssl` or another external tool and no certificate ends unannounced.

1. **Three commands that make, and a status where the files are.**
   `opamp-fleetctl pki init` makes a fleet's certificates and its package
   signing key from nothing. `opamp-fleetctl pki server-cert` makes a server
   certificate from the existing server CA, for the Server or for a Gateway.
   `opamp-fleetctl pki bootstrap-ca` makes a new bootstrap CA to replace the
   Server's. `opamp-fleetctl pki status` says when the certificates in the
   offline directory end, and `server pki status` says when those of the Server
   host end. The Server's command runs and exits like `hash-credential` and
   `audit-verify`, before the Server starts serving. The Server binary carries
   no code that makes a CA or a server certificate. It signs host certificates
   (ADR-0021 clause 9) and bootstrap certificates (clause 21). When a
   certificate counts as ending (clause 11) is one rule in `fleet-core`, plain
   date arithmetic, so both commands and the running Server judge alike, and
   each program reads the certificate itself. None of the commands makes a host
   certificate or a bootstrap certificate.

2. **No dependency beyond ADR-0021 clause 12.** The commands use `rcgen` with
   the features that clause states, and `time`. Every key is ECDSA P-256 and
   written as PKCS#8 PEM, the form `[client_ca]` loads; every certificate is
   PEM; every serial is 16 random bytes, as the client CA's are.

3. **`init` writes two directories, and the split is the point.** `--server-dir`
   receives what the Server host needs: `server.pem` and `server-key.pem`,
   `client-ca.pem` and `client-ca-key.pem`, `bootstrap-ca.pem` and
   `bootstrap-ca-key.pem`, and `server.toml.fragment` naming them in `[tls]`,
   `[client_ca]` and `[enrolment]`, including `bootstrap_ca_key_file`.
   `--offline-dir` receives what stays with the operator: `server-ca.pem` and
   `server-ca-key.pem`; the package signing key, an Ed25519 key in PKCS#8 as
   `package keygen` writes it, as `package-signing-key.pk8`, and its public half
   in hex as `package-signing-key.pub`
   ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md));
   and `supervisor.toml.fragment` naming `server-ca.pem` in `[tls] ca_file`,
   `bootstrap.pem` and `bootstrap-key.pem` under `--host-path` in `cert_file`
   and `key_file`, where a host puts the pair the Server issues it, and the
   public half in `[packages] verification_key`. No key of the server CA and no
   package signing key is ever written to `--server-dir`. Each fragment names
   its files by the directory they are meant to live in: `--server-path`
   (default: the absolute path of `--server-dir`) and `--host-path` (default:
   the absolute path of `--offline-dir`). The command prints which directory
   goes where.

4. **`init` is meant to run where the offline keys are to stay.** That is the
   operator's Linux or macOS machine, the one `opamp-fleetctl` is downloaded to.
   Run on the Server host, it is followed by moving `--offline-dir` off it, and
   the command says so when both directories are on one file system.

5. **The CAs are told apart by role and sign no CA.** The three CAs are
   `CN=<product> Server CA`, `CN=<product> Client CA` and
   `CN=<product> Bootstrap CA` (clause 26), so the bootstrap CA never shares a
   subject with the client CA (ADR-0021 clause 19). Each CA certificate is
   `CA:TRUE` with a path length of 0, `keyCertSign` and `cRLSign`.

6. **A server certificate names what is dialled in its SAN and its role in its
   subject.** `--name` is given at least once and takes a DNS name or an IP
   address; an empty value, a wildcard, or a name that is neither is refused.
   Each becomes a subject alternative name, and `IP:127.0.0.1` and `IP:::1` are
   always added, so the Operator plane on its loopback default is reachable
   through a tunnel with the same certificate. The certificate is `CA:FALSE`,
   `digitalSignature`, `serverAuth`. Its common name is derived from the server
   CA's (clause 28). `pki server-cert` takes O and OU from the server CA, and
   `--organization` and `--organizational-unit` replace either, so a Gateway run
   by another unit says so.

7. **`server-cert` serves the Server and a Gateway alike.**
   `opamp-fleetctl pki server-cert --offline-dir <dir> --name … --out <dir>`
   signs `server.pem` and `server-key.pem` in `--out` with `server-ca-key.pem`.
   For the Server they replace the files of `[tls]`, and the Server is restarted
   on them; for a Gateway they are its `[gateway.tls]` `cert_file` and
   `key_file`
   ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)),
   which the Agents behind it verify against the same `server-ca.pem`. The
   fleet's trust does not change, so no host's configuration does.

8. **A new bootstrap CA replaces the Server's.**
   `opamp-fleetctl pki bootstrap-ca --out <dir>` writes `bootstrap-ca.pem` and
   `bootstrap-ca-key.pem` to `--out`, with the subject a bootstrap CA carries
   (clause 5). The operator copies both to the Server host in place of
   `[enrolment]`'s files and restarts the Server. Bootstrap certificates from
   the old CA stop passing the handshake, and those not yet used are issued
   again.

9. **Lifetimes by default, each overridable, never past the CA.** The server CA
   and the client CA live 3650 days, the bootstrap CA 365 days, a server
   certificate 397 days. `init` takes `--ca-days` for the server CA and the
   client CA, `--bootstrap-ca-days` and `--server-days`. `server-cert` and
   `bootstrap-ca` take `--days` for the one certificate they make. A server
   certificate ends no later than the server CA that signs it, and one asked to
   outlive it is cut to the CA's end with a notice. Bootstrap certificates live
   as clause 23 states. Host certificates are the running Server's, signed for
   `[client_ca] validity_days` as ADR-0021 clause 9 states.

10. **Nothing is overwritten, and nothing is half written.** A command that
    would write a file that exists refuses before it writes anything, naming the
    file. It writes into a new temporary directory beside its target and renames
    into place only once every file is complete. Directories it creates are
    `0700`; every key is `0600`.

11. **The running Server warns before a certificate it depends on ends.** At
    startup and once a day while it runs, the Server reads the end of its own
    certificate (`[tls] cert_file`), of the client CA (`[tls] client_ca_file`
    and `[client_ca] cert_file`) and of the bootstrap CA
    (`[enrolment] bootstrap_ca_file`). One that ends within 30 days — or, for a
    certificate whose whole life is shorter than 90 days, within the last third
    of it — is _ending_: it is logged as a warning naming the file, its subject
    and the date, and recorded in the audit as `pki.expiring`; one that has
    ended is logged as an error and recorded as `pki.expired`
    ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)). Neither
    stops the Server: the hosts it serves decide for themselves, and a Server
    that refuses to start cannot be told to renew.

12. **`pki status` says when each certificate ends.**
    `server pki status --config <server.toml>` lists the files of clause 11.
    `opamp-fleetctl pki status --offline-dir <dir>` lists the server CA. Each
    prints every certificate with its subject, its serial, its end and the days
    left, and exits `0` when none is ending in the sense of clause 11, `1` when
    one is, and `2` when one has ended, so a monitoring job can run it.

13. **The project uses its own commands.** `scripts/dev-pki.sh` makes its
    development set with `cargo run -p fleet-tools -- pki init`, writes a
    complete `server.toml` and `supervisor.toml` from the fragments, and needs
    no `openssl`. Its development Client holds a bootstrap pair the development
    Server issued: `scripts/seed_test_configs.sh --enrol` asks the Server for
    it, writes it where `supervisor.toml` names it, opens the window and
    approves the request. The operator manual describes the `pki` commands and
    the issuing route, reads a serial with `pki status` or from the route's
    answer, and names no external tool. Certificates made elsewhere keep
    working: the Server reads any PEM that meets the requirements these commands
    write down.

14. **Keys are stored unencrypted.** The Server reads the client CA's key, the
    bootstrap CA's key and its own key unattended, and the offline keys are
    protected by where they are kept and by their mode, as every other key of
    the project is.

15. **One program, two command trees.** `opamp-fleetctl package` holds `fetch`,
    `pack`, `sha256`, `sign`, `keygen` and `public-key`, each with the options
    and output it has today. `opamp-fleetctl pki` holds `init`, `server-cert`,
    `bootstrap-ca` and `status` as this ADR states them.
    `opamp-fleetctl --version` prints the version every binary of this project
    prints ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)). No
    other program name exists for any of these commands: no alias, no wrapper,
    no symlink.

16. **The crate builds exactly this program.** `crates/fleet-tools` has no
    library and one binary, `opamp-fleetctl`, and keeps the dependency direction
    of
    [ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
    clause 22: it uses the Client's and the internal crate's items, and nothing
    depends on it. The program is `src/main.rs`, which parses the command line,
    with one module per command tree, `src/package.rs` and `src/pki.rs`; the
    release fetcher behind `package fetch` is `src/fetch.rs`.

17. **Built in the release run, from the release's version, for four targets.**
    `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
    `aarch64-apple-darwin` and `x86_64-apple-darwin`, each in the row of the
    Client's build matrix for the same target. Each row whose target runs on its
    runner asserts that `opamp-fleetctl --version` reports the release version,
    as the Client's build does. The Windows row builds the program for its
    runner only as the packer of the Client's archive; no Windows archive of it
    is published.

18. **One archive per target, named like the Client's.**
    `opamp-fleetctl_<version>_<os>_<arch>.tar.gz`, by the grammar of ADR-0019
    clause 32 and the platform tokens of its clause 30, packed by
    `opamp-fleetctl package pack --format tar.gz` with the one member
    `opamp-fleetctl` and its executable mode. No `.deb`, `.rpm` or `.msi`
    carries it. The four archives are assets of the release beside the Client's
    and are covered by the same `SHA256SUMS`.

19. **It is not a package of the fleet.** The release notes list the four
    archives as the operator tool and say they are downloaded, not uploaded to
    the Server. Everything that selects the Client's archives selects them by
    their `supervisor_` stem, never by version and platform alone: the notes'
    upload loop, which would otherwise put an `opamp-fleetctl` archive into the
    `supervisor` Package as the entry of its platform, and
    `opamp-fleetctl package fetch --agent supervisor`. An upload made by hand
    anyway installs nothing: the Client's self-update refuses an artifact whose
    member is not `supervisor` (ADR-0019 clause 29).

20. **Unsigned, as the Client's artifacts are.** The archives carry what every
    asset of a release carries: their entry in `SHA256SUMS`. Provenance for the
    release's assets is one decision for all of them, not a property of this
    program alone.

21. **The Server issues a bootstrap certificate on request.**
    `POST /api/v1/bootstrap-certificates` with a JSON body
    `{"subject": {…}, "validity_days": n}` (`Content-Type: application/json`, as
    `POST /api/v1/revocations`) makes a fresh ECDSA P-256 key, signs a
    certificate with the bootstrap CA's key and answers `201` with `serial`,
    `subject`, `not_before`, `not_after`, `certificate_pem` and
    `private_key_pem`, under `Cache-Control: no-store`. The certificate is
    `CA:FALSE`, `digitalSignature`, `clientAuth`, with a 16-byte random serial
    (ADR-0021 clause 32) and no subject alternative name. The private key exists
    only in that response: it is not stored, not logged and not audited, and a
    lost key is replaced by issuing again.

22. **The operator names the organization, and the Server the rest.** `subject`
    takes `organization` (O) and `organizational_unit` (OU), each optional and
    at most once, typically the customer and the site. A value is 1 to 64
    characters of UTF-8 without control characters. A key outside this set is
    answered `400`. The Server sets the common name (clause 28); the operator
    never does. The subject is descriptive. It authorizes nothing, and no host
    certificate inherits it.

23. **A bootstrap certificate lives 10 days by default, at most 90, never past
    its CA.** `validity_days` runs from 1 to 90, and anything else is answered
    `400`. A certificate that would outlive the bootstrap CA ends with it, and
    the response's `not_after` says so.

24. **The Server records what it issued.** Before it answers, the Server writes
    the serial, the subject, the SHA-256 fingerprint of the public key, the
    issuing time and `not_after` to one file per certificate under
    `config_dir/bootstrap-certificates/`. `GET /api/v1/bootstrap-certificates`
    lists every entry with whether it is revoked. An entry is removed once its
    certificate has ended. At most 10 000 valid entries are kept, and a request
    beyond that is answered `409`. A bootstrap certificate is revoked as
    ADR-0021 clause 34 states, with the authority `bootstrap`. Each issuance is
    recorded in the audit as `enrolment.bootstrap_issued` with serial, subject
    and `not_after` (ADR-0022).

25. **The Enrolments tab issues, lists and revokes bootstrap certificates.** The
    tab issues one with the organization, the organizational unit and the
    validity an operator types, through the route of clause 21. The row of each
    certificate issued in the open page offers its pair for saving as
    `bootstrap.pem` and `bootstrap-key.pem`, the names
    `supervisor.toml.fragment` gives them (clause 3), as often as the operator
    likes. The page holds those keys in memory only and writes none to browser
    storage. It drops a key once its certificate is revoked or has ended, and
    every key when it is reloaded or closed, which it asks before while it holds
    one. A certificate issued elsewhere, or before the page was opened, offers
    no pair. The tab lists the certificates of
    `GET /api/v1/bootstrap-certificates` with a press that revokes one by its
    serial with the authority `bootstrap`. Each pending request shows the entry
    its `bootstrap_serial` names (ADR-0021 clause 22), with its subject, serial
    and end, and says so when no entry matches. The tab uses no route the REST
    API does not offer.

26. **The product is a flag, with a default.** `opamp-fleetctl pki init` and
    `pki bootstrap-ca` take `--product <name>` (default `OpAMP Fleet`): letters,
    digits, space, `.` and `-`, 1 to 40 characters, no leading or trailing
    space. No build constant enters a certificate.

27. **The operator names an organization for audit.** `init` and `bootstrap-ca`
    take `--organization` (O) and `--organizational-unit` (OU), each optional,
    each 1 to 64 characters of UTF-8 without control characters (the upper bound
    of RFC 5280 Appendix A.1). `init` writes them into all three CAs and the
    server certificate. Attributes are encoded as `UTF8String`, in the order O,
    OU, CN. No other attribute is written.

28. **A leaf's common name is its CA's, with `CA` turned into `Certificate`.**
    Whoever signs a leaf — `opamp-fleetctl` a server certificate, the Server a
    host or a bootstrap certificate — takes the common name of the CA that signs
    it and replaces a trailing ` CA` with ` Certificate`, or appends
    ` Certificate` when there is none. A fleet made by `init` therefore has
    `<product> Server Certificate`, `<product> Client Certificate` and
    `<product> Bootstrap Certificate`, and a fleet whose CAs were made elsewhere
    gets a name from them without a setting of its own. The Server refuses to
    start when the name derived from the client CA or the bootstrap CA would
    exceed 64 characters.

29. **A bootstrap certificate's organization is the operator's choice per
    issue.** The common name of a bootstrap certificate is the one of clause 28.
    Its O and OU are what the issuing request names (clause 22), typically the
    customer and the site, and not the bootstrap CA's; the organization behind
    it is read from its issuer. A host certificate carries no O or OU: its
    issuer names the organization, and its subject stays free for what a later
    decision may carry over from the bootstrap certificate (ADR-0021 clause 7).

30. **A development certificate says so.** `scripts/dev-pki.sh` makes its set
    with `--product "OpAMP Fleet Dev" --organization "Development"`, and
    `scripts/seed_test_configs.sh --enrol` issues its bootstrap certificate with
    the organization `Development`. Every certificate of a development set
    therefore reads `OpAMP Fleet Dev …` and `O=Development`, and one that turns
    up outside a developer's machine is recognized as such.

**Out of scope:** issuing a host certificate by any route other than enrolment,
which the specification rules out; carrying the bootstrap certificate's subject,
or any customer data, into the host certificate issued on approval; customers as
a resource of the Server, and separating them from each other, the subject being
a label; attributes other than O, OU and CN; encrypting keys at rest, a hardware
security module, or a passphrase prompt; replacing the server CA or the client
CA, which every host's configuration or enrolment follows, and holding two
bootstrap CAs at once while one replaces the other; enforcing a CA's end in the
handshake, or limiting the running Server's signatures to its CA's end, which
would change ADR-0021 clause 9; certificate revocation lists or OCSP; ACME and
certificates from a public CA, which the Server reads as they are; a `pki`
command on the Client binary; the Server's `pki status` on Windows or macOS,
where the Server does not run; the operator tool on Windows; native packages,
Homebrew, `npm` or any other installer; signing or attesting the release's
assets; commands that drive the running fleet through the Operator plane beyond
the upload `package fetch` makes.

## Alternatives considered

- **Keep `openssl` and document it better.** Rejected: the rules stay in prose
  an operator has to get right by hand, and a system tool whose behaviour
  differs between versions stays a prerequisite of every fleet.
- **All the commands on the Server binary,** beside `pki status`,
  `hash-credential` and `audit-verify`. The Server binary is certain to be at
  hand, but it is the binary of the host the package signing key and the server
  CA's key are kept away from, and the archive writers and the release fetcher
  would be linked into the binary that faces the fleet — attack surface with no
  use in serving
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 6 has the Server never create or open an artifact). With the operator
  tool published, the one argument for it — no second binary to obtain — is
  gone; the version both share is the release's.
- **Keep the bootstrap CA offline and make bootstrap certificates with
  `opamp-fleetctl`, with subject options.** It gives each customer a subject of
  its own, but each certificate is a trip to the offline machine, and the Server
  neither lists nor knows what was issued until a host presents it. It protects
  a key whose loss is already outweighed by the client CA's key on the Server.
- **One CA for client and bootstrap certificates, with the bootstrap ones marked
  by an extension or found in a register.** It saves one key pair, but it makes
  admission depend on a second check that lets a host in when it fails. With a
  CA of its own a failure falls to the safe side: an enrolment connection.
- **One CA for everything.** It combines the above with the server CA's key
  online: a copy of the Server's key would then impersonate the Server to every
  host.
- **Store the bootstrap certificate's key on the Server for download again,** or
  keep the pair so every row of the Enrolments tab offers it until the
  certificate ends. It is convenient, but it leaves a key on the Server host
  that only the host it is handed to needs, and widens who can read it from the
  request's answer to everyone who can read the record later. Issuing again
  costs nothing, and holding the pair in the open page gives the same
  convenience for the session it is issued in.
- **Let the host send a CSR for its bootstrap certificate.** No key would
  travel, but the bootstrap certificate exists precisely because the host has no
  channel to the Server yet, and one pair per customer is handed to many hosts.
- **The UI lists and revokes, and issuing stays with the API.** The private key
  would then never pass through a browser. The key travels to the operator's
  machine either way, though, in an HTTP response read by `curl` or by the page,
  and the operator who approves would still leave the tab to issue.
- **Free-form subject as an RFC 4514 string.** It is shorter to specify, but it
  lets any attribute type and encoding into the certificate, which the Server
  would then have to show back and compare. A fixed set of named fields is what
  an operator fills in a form.
- **Country, state and locality as well.** They describe where an organization
  sits, which an audit of a private fleet does not ask, and `country` needs an
  encoding of its own (`PrintableString`). O and OU name who is responsible.
- **The product name from the build (`PRODUCT_TITLE`, ADR-0019 clause 2).** It
  needs no flag, but it names the Client product (`OpAMP Fleet Agent`), lives
  only in `crates/fleet-agent`, and is the same for every installation of one
  build. An operator's certificates name their installation.
- **A slug for the fleet (`--fleet opamp-fleet`) and the role in lower case.**
  The smallest naming, but an auditor reads a slug and no organization, and no
  leaf shows its role in its subject.
- **A configuration file for issuer and subject data,** or a setting for the
  leaf names in `server.toml`. Either holds everything in one place, but three
  values are set at most once a year, a file has to be versioned, validated and
  documented, and leaf names set apart from the CA's can drift from it. An
  operator with richer requirements makes the certificates in their own PKI,
  which the Server accepts (clause 13).
- **Keep the CSR's subject in the host certificate,** or the client CA's O and
  OU in every host certificate. The first shows the Agent's name in the
  register, but that name is self-asserted, and the register already lists the
  host and the `instance_uid` of each certificate (ADR-0021 clause 33); the
  second repeats the issuer in the subject and takes the place a customer would
  need if the bootstrap certificate's subject is ever carried over.
- **Match an enrolment request to its bootstrap certificate by the certificate's
  fingerprint.** The record would keep the SHA-256 of the whole certificate as
  well, but the operator revokes and reads the audit by serial, so the
  fingerprint would be a second name for the same entry (ADR-0021 clause 22).
- **Shorter lifetimes for the server CA and the client CA too.** The online
  client CA's key would be replaced more often, but replacing it means every
  host enrols again, and replacing the server CA means a new `ca_file` on every
  host. Without a way to hold two CAs at once, both stay at ten years.
- **Leave the package signing key to `package keygen` alone.** It keeps `init`
  to certificates, but a fleet that skips the second step has no key, and its
  Clients take no package until someone sets `verification_key` by hand. The key
  belongs where `init` already puts what stays offline, and `keygen` remains for
  a second key or a replacement.
- **The whole reading of a certificate's end in `fleet-core`.** One function
  from file to verdict, but it would give the internal crate its first
  dependencies (`x509-parser`, `time`, the PEM reader), which every end then
  compiles for a rule only two programs apply; the date rule alone needs none.
- **`fleet-tools` depending on `fleet-server` for the rule.** No new code in
  `fleet-core`, but the operator tool would link the Server's library, its
  router included, for a dozen lines.
- **`pki status` in one program only.** The Server host does not hold the server
  CA's certificate and the operator's machine does not hold `server.toml`, so
  either program alone sees only part of the certificates, and the server CA's
  end — which every host's trust hangs on — would be visible nowhere.
- **Issue a host certificate from the command line**, offline with the client
  CA's key or through a route of the running Server. Rejected: the specification
  has a host obtain its certificate only through an approved, time-limited
  enrolment over the protocol's own means, never through a side channel, and a
  route would let the operator credential alone mint a member.
- **Limit every signature of the running Server to its CA's end, and refuse
  renewals under an ended CA.** It belongs with ADR-0021 clause 9, which states
  how the Server signs; kept out of this decision, which warns instead (clauses
  11 and 12).
- **Encrypt the offline CA keys with a passphrase.** It needs an encryption
  crate beyond clause 2 and a prompt the commands must handle; kept out of
  scope, not ruled out.
- **Recommend `step` or `cfssl`.** Either makes certificates well, but each is
  one more tool to install and to learn, and neither knows this project's
  requirements.
- **Two programs, one for packages and one for certificates, both published.**
  It lifts the toolchain requirement, but leaves two names for one person's one
  job.
- **Put the commands into the Client binary.** The Client is published already,
  but it lands on every host, and every host would then carry the means to make
  a CA and a signing key.
- **Name it `fleetctl`.** The `kubectl` analogy the crate split already draws,
  but the name belongs to FleetDM's tool (Context).
- **Name it `opamp-operator` or `opamp-fleet`.** The first says who uses it, but
  a name ending in `-ctl` says it is the command-line tool of a system, which is
  what an operator looks for. The second is the build-time product name the
  Client's service is registered under (ADR-0019), so a program of that name
  reads as the Client.
- **All five targets, Windows included.** Windows would need its own way to keep
  a key readable by its owner alone, a piece of work this decision does not take
  on.
- **Linux only.** Simpler by two builds, but an operator on macOS — a likely
  operator machine — would again need a toolchain, and macOS gives the same file
  modes as Linux.
- **Keep the tools out of the release.** No release change at all: every
  operator builds them from a checkout, and a fleet cannot install a single
  signed package without a Rust toolchain on someone's machine.

## Sources / Prior art

- HashiCorp Consul, `consul tls ca create`: a self-signed CA made by the
  product's own binary, with a days option and a default common name.
  <https://developer.hashicorp.com/consul/commands/tls/ca>
- HashiCorp Nomad, `nomad tls ca create` and `nomad tls cert create`: a CA and
  server, client and CLI certificates from the product's own binary.
  <https://developer.hashicorp.com/nomad/commands/tls/ca-create>,
  <https://developer.hashicorp.com/nomad/docs/commands/tls/cert-create>
- Kubernetes, `kubeadm init phase certs ca`: the cluster's CAs generated by the
  setup tool itself, skipping files that exist.
  <https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-init-phase>
- Kubernetes TLS bootstrapping: a short-lived bootstrap token issued by the
  control plane, which approves the CSR it carries.
  <https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/>
- Kubernetes PKI: the CAs are named for their role (`kubernetes`, `etcd-ca`,
  `front-proxy-ca`), and the kubelet's client signer permits one subject only,
  `O=system:nodes`, `CN=system:node:<name>`, whatever the CSR would like.
  <https://kubernetes.io/docs/setup/best-practices/certificates/>,
  <https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/>
- HashiCorp Vault's PKI engine: an issuing CA online, key pairs generated on
  request and returned once, a root kept offline.
  <https://developer.hashicorp.com/vault/docs/secrets/pki>
- `rcgen`: `CertificateParams::self_signed` and `signed_by`,
  `BasicConstraints::Constrained`. <https://docs.rs/rcgen>
- `rustls-pki-types` `TrustAnchor`: a subject, a key and name constraints, no
  validity — why an expired CA goes unnoticed by this project's own ends.
  <https://docs.rs/rustls-pki-types>
- RFC 5280 sections 4.1.2.4, 4.1.2.6 and Appendix A.1: the issuer and subject,
  the attribute types, and the upper bound of 64 characters for organization,
  organizational unit and common name. <https://www.rfc-editor.org/rfc/rfc5280>
- RFC 9525 section 2: the common name must not be used to identify a service.
  <https://www.rfc-editor.org/rfc/rfc9525>
- CA/Browser Forum Baseline Requirements section 7.1.4: a publicly trusted
  server certificate's common name, when present, repeats one of its SANs. The
  rule binds public CAs only; the server CA here is private.
  <https://cabforum.org/working-groups/server/baseline-requirements/>
- Kubernetes publishes `kubectl` per platform as a download of its own, apart
  from the components that run on a node or the control plane.
  <https://kubernetes.io/releases/download/>
- FleetDM's `fleetctl`: installed with `npm install -g fleetctl`, from an
  install script, or from its GitHub releases.
  <https://fleetdm.com/guides/fleetctl>,
  <https://www.npmjs.com/package/fleetctl>
- HashiCorp Nomad and Consul put their certificate commands into the one binary
  that also runs the servers (`nomad tls`, `consul tls`) — the arrangement this
  decision does not follow, because here the operator's offline keys are to stay
  off the server host.
  <https://developer.hashicorp.com/nomad/commands/tls/ca-create>,
  <https://developer.hashicorp.com/consul/commands/tls/ca>
- This project's own requirements: ADR-0021 clauses 7, 9, 12, 15, 19 to 22, 27,
  32 to 34, ADR-0013 clause 9, `docs/SPECIFICATION.md` on how an Agent obtains
  its certificate, ADR-0026 on why a package is signed by a key the operator
  holds, and ADR-0019 clause 29 on the member a package artifact carries and
  clauses 30 to 34 on the release, its naming and its assets.

## Consequences

- Positive: a fleet is set up with two binaries the project builds and nothing
  else (G-17, Q-1); the requirements a hand-made certificate can miss are
  written once, in code that is tested; the offline keys have a place of their
  own from the first command on; an ending CA or server certificate is announced
  30 days ahead in the log, the audit and a command a monitor can run.
- Positive: an operator downloads one program and can make the fleet's
  certificates, a signing key and signed packages without a toolchain (G-10,
  G-17, Q-1); the two keys that stay on the operator's machine, the server CA's
  and the package signing key, each do what nothing on the Server host can; the
  Server binary carries no command that makes them; the packer the release uses
  is the one an operator downloads.
- Positive: an operator issues a bootstrap certificate per customer, site or
  batch from the Operator plane, sees its subject on every enrolment request it
  carries, lists what is valid and revokes one by serial (G-17), from the REST
  API or from the Enrolments tab (G-5); the bootstrap CA is replaced every year
  at the cost of one restart and the unused bootstrap certificates.
- Positive: every certificate says what it is for in plain words, and each CA
  and server certificate names the organization behind it, so an audit reads
  both from the certificate presented; a host certificate's subject is the
  Server's alone, so no self-asserted text from a CSR reaches a signed
  certificate (Q-1); a fleet with CAs from its own PKI gets leaf names that
  match them without a setting; a development certificate is told from a
  production one by its subject alone.
- Negative / trade-offs: the Server binary carries `pki status` and the issuing
  of bootstrap certificates beside serving, and the operator tool a second job
  beside packages; a fresh development set needs a running Server before its
  Client can start, and the development Client enrols, which adds an approval to
  a fresh development setup; keys at rest are only as safe as the place they are
  kept; a host certificate signed by the running Server can still outlive its
  CA, which the warnings announce rather than prevent.
- Negative / trade-offs: a bootstrap certificate's private key travels in an
  HTTP response, over TLS and to an authenticated operator only. A response kept
  by a proxy or a terminal history is a bootstrap key in the open, which only
  lets a host into the enrolment queue. A key issued from the UI passes through
  the browser and lands in the operator's download folder, with the permissions
  that folder gives it; moving it to the host and deleting the copy is the
  operator's job, as it is for the answer `curl` writes.
- Negative / trade-offs: every host certificate of a fleet has the same subject.
  A host is told apart by its SAN, its serial and the register (ADR-0021 clause
  33), not by its subject. A server certificate's common name is not one of its
  names, so it could not be issued by a public CA in this form; it never is, the
  server CA being the fleet's own.
- Negative / trade-offs: four more builds and four more assets per release; the
  release carries a program that makes keys, and like every asset it is checked
  by its `SHA256SUMS` alone; an operator on Windows still builds from a
  checkout.
- Follow-ups: encrypting the offline keys; replacing a CA without every host
  enrolling again, and holding two bootstrap CAs while one replaces the other;
  enforcing a CA's end in the handshake, or limiting the running Server's
  signatures to it; carrying the bootstrap certificate's subject into the host
  certificate on approval; showing the issuer's O and OU wherever the Server
  lists certificates; a view of the certificates' ends in the bundled UI.
- Follow-ups: provenance for every release asset; the operator tool on Windows
  with key files only their owner can read; a command tree for the running
  fleet, if one is ever wanted, under this program's name.

## Enforcement

Tests that will carry `Verifies: ADR-0028`:

- `pki init` writes exactly the files of clause 3 into the two directories: the
  bootstrap CA's key into `--server-dir`, no server-CA key and no package
  signing key into it, `package-signing-key.pk8` (owner-only) and
  `package-signing-key.pub` into `--offline-dir` alone, keys `0600`, directories
  `0700`, fragments that name `--server-path` and `--host-path`; the key signs a
  package the Client's verifier accepts under the `verification_key` the
  fragment names; a second run over the same directories is refused without
  writing anything (clauses 3 and 10).
- The bootstrap CA ends 365 days after it starts, and the server CA and the
  client CA 3650; a server certificate asked to outlive its CA ends with the CA
  (clause 9).
- `pki init --product "Acme Fleet" --organization "Acme AG"
--organizational-unit "IT"`
  writes CAs whose subjects are `O=Acme AG, OU=IT, CN=Acme Fleet Server CA`,
  `… Client CA` and `… Bootstrap CA`, each with a path length of 0 and passing
  the Server's startup check, and a server certificate
  `O=Acme AG, OU=IT, CN=Acme Fleet Server Certificate` with every `--name` and
  the loopback as SANs. Without the flags the CAs are `CN=OpAMP Fleet … CA` and
  carry no O or OU. `--fleet` is an unknown option, and a product or an
  organization outside its grammar, a wildcard or an empty `--name` is refused
  (clauses 5, 6, 26 and 27).
- `pki server-cert` signs with the offline CA, a Client that trusts the old
  `server-ca.pem` accepts the new server certificate, and the certificate copies
  O and OU from the server CA, of which `--organizational-unit` replaces OU
  alone (clauses 6 and 7).
- End to end, in `crates/fleet-tools/tests/`: `opamp-fleetctl pki init` makes
  the set, a Server started on `server.toml.fragment` — `fleet-server` as a
  development dependency of `fleet-tools`, which links into no artifact — issues
  the Client's bootstrap pair before the Client starts, and admits a Client
  started on `supervisor.toml.fragment` through `fleet-agent` once its enrolment
  is approved (clauses 3, 6, 13 and 21).
- The Server binary refuses `pki init`, `pki server-cert`, `pki bootstrap-cert`
  and `pki bootstrap-ca` as unknown commands, and its usage names `pki status`
  alone (clause 1).
- A Server whose client CA ends within 30 days logs the warning and records
  `pki.expiring` at startup, and one whose CA has ended records `pki.expired`
  and keeps serving (clause 11).
- Both `pki status` commands, and the running Server, judge one certificate
  alike (clauses 1 and 11).
- Each `pki status` lists each file with its serial and end, and exits `0`, `1`
  and `2` for a set with no, an ending and an ended certificate (clause 12).
- `scripts/dev-pki.sh` runs with no `openssl` on `PATH` (clause 13).
- `POST /api/v1/bootstrap-certificates` answers `201` with a certificate the
  bootstrap CA signed, `CA:FALSE`, `clientAuth`, the requested subject, and a
  key that matches it, under `Cache-Control: no-store`. Nothing under
  `config_dir` and no audit entry contains the private key (clause 21).
- An unknown subject key such as `common_name` or `country`, a value over 64
  characters or with a control character, and `validity_days` of 0 or 91 are
  each answered `400`. An empty `subject` is accepted, and a certificate asked
  to outlive the bootstrap CA ends with it (clauses 22 and 23).
- An issued certificate appears in `GET /api/v1/bootstrap-certificates`, is
  recorded as `enrolment.bootstrap_issued`, enrols a host whose request lists
  its subject, and, once revoked by its serial, fails admission (clause 24).
- `pki bootstrap-ca` writes a CA the Server starts on (clause 8).
- A host certificate the Server signs from a CSR with `CN=evil, O=Other` has the
  subject `CN=<product> Client Certificate` and nothing else, and a bootstrap
  certificate issued with `organization` and `organizational_unit` has those and
  `CN=<product> Bootstrap Certificate`; under a client CA named `CN=Corp Root`,
  a host certificate is `CN=Corp Root Certificate`, and under a client CA whose
  derived name exceeds 64 characters the Server refuses to start (clauses 28 and
  29).
- The bundled UI names the issuing, listing and revocation routes and the fields
  it reads from them, and `BootstrapView` and `IssuedBootstrap` in the OpenAPI
  document carry those fields (clause 25).
- The command tree: `opamp-fleetctl --help` lists `package` and `pki` and
  nothing else beside `help`; `package --help` lists `fetch`, `pack`, `sha256`,
  `sign`, `keygen` and `public-key`; `pki --help` lists `init`, `server-cert`,
  `bootstrap-ca` and `status`, and `bootstrap-cert` is an unknown command;
  `--version` prints the baked version (clause 15).
- The crate: `crates/fleet-tools` declares exactly one binary target,
  `opamp-fleetctl`, and no library (clause 16).
- The release workflow, read as data: it builds `opamp-fleetctl` for exactly the
  four targets of clause 17, asserts its version where the target runs, names
  each archive `opamp-fleetctl_<version>_<os>_<arch>.tar.gz`, packs it with
  `opamp-fleetctl package pack --format tar.gz`, and includes it in
  `SHA256SUMS`; no `opamp-fleetctl_*_windows_*` asset and no installer names it
  (clauses 17 and 18).
- The release notes' upload loop, read out of the workflow, selects
  `supervisor_<version>_*.tar.gz` and matches no `opamp-fleetctl_` archive, and
  `package fetch --agent supervisor`, given a release that also holds
  `opamp-fleetctl_1.2.3_linux_amd64.tar.gz`, plans only the `supervisor_`
  archives (clause 19).

**Not mechanically decidable:** that no document of the project tells an
operator to use an external tool, and that the operator manual describes issuing
through the Server and names no other way to make a bootstrap certificate
(clause 13), are held by review of every change to the manual; that the release
notes describe the archives as the operator tool and not as packages (clause 19)
by review of the release notes in the workflow; that the UI keeps the private
keys in memory only and drops them as clause 25 states, and that
`scripts/dev-pki.sh` and `scripts/seed_test_configs.sh` pass the development
names of clause 30, by review.
