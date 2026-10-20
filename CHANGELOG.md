# Changelog

Operator-facing changes to the Server and the Client — what a running deployment has to be told
about, in particular anything that must be edited or moved before an upgrade. The reasoning behind
each change lives in the ADR it names ([`docs/adr/`](docs/adr/)); this file says only what to do.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). A version is the one
`[workspace.package] version` in `Cargo.toml` names, which the release pipeline creates the
`version/*` tag from ([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)). A section carries a date once its tag exists.

> **Where this file starts.** Entries begin with release 0.1.0. The work before it — package
> delivery, Selector-targeted packages and Configurations, the Client's own self-update, and the
> rest — is not backfilled here; it is in the git log and in the ADRs. The first four releases were
> all cut on 2026-08-09, so the dates below say less than the order does.

## [0.6.0]

### Added

- **A host behind a Gateway enrols through it**
  ([ADR-0039](docs/adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)). A Gateway with
  `[gateway.tls] bootstrap_ca_file` admits a bootstrap certificate in its handshake and relays one
  thing for it: a plain-HTTP report carrying a certificate signing request with a bootstrap proof
  and nothing else. A WebSocket upgrade or any other report of such a peer is answered `403`, and
  it binds no `instance_uid`, is offered nothing and served no download. The Server decides the
  request as any enrolment — window, queue, the bootstrap certificate's share, approval, a new
  host — and lists it with the Gateway's host in place of a peer address, as `gateway` in
  `GET /api/v1/enrolments` and in every audit entry of it. The Gateway relays a request only when
  its bootstrap proof embeds the very certificate the peer presented in its handshake; one naming
  another certificate is answered `403` and logged. Enrolment requests through a Gateway never
  spend the aggregate its members are counted in. One whose bootstrap certificate a bootstrap CA
  of `[enrolment]` issued takes a token from that certificate's bucket, sized by
  `messages_per_sec` and `burst`, and one from the Gateway's enrolment aggregate, sized by
  `gateway_messages_per_sec` and `gateway_burst`; one whose certificate fails that check takes a
  token from the Gateway's bucket for unchecked enrolments alone, sized by `messages_per_sec` and
  `burst`, and is answered `BadRequest`. A throttled one is audited as `agent_rate.throttled`
  with `bucket` `bootstrap`, `enrolment` or `unchecked_enrolment`, naming the bucket that was
  empty. **What to do:** to let hosts
  behind a Gateway enrol, copy the Server's `[enrolment] bootstrap_ca_file` — the certificate,
  never its key — to the Gateway, name it as `[gateway.tls] bootstrap_ca_file`, and point those
  hosts at the Gateway with an `https://` endpoint. A CA that is in both `client_ca_file` and
  `bootstrap_ca_file` fails the Gateway's startup.

### Security

- **A signing request is read from exactly one PEM block**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 27,
  [ADR-0039](docs/adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)). The Server read
  one signing request with two PEM readers that can pick different blocks out of one crafted
  input: the proof was checked against one request and the key of another was signed. Every
  release from 0.5.0 to 0.5.5 is affected, in renewal: whoever held any client certificate and a
  renewal request another host had sent, while that host's certificate was still valid, obtained
  a certificate for that host over a key of their own, without approval. A Gateway sees every
  renewal request its members send and holds a client certificate, so a compromised or hostile
  Gateway is the most likely attacker. A request is now exactly one `CERTIFICATE REQUEST` block
  with a line break after its first boundary and before its last and nothing but whitespace
  around it, and everything is read from that one block; anything else is answered `BadRequest`
  and nothing is signed or queued. **What to do:** upgrade.

- **Through a Gateway a certificate is renewed only with a renewal proof**
  ([ADR-0039](docs/adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)).
  Behind a Gateway the Server sees the Gateway's certificate. A signing request without a renewal
  proof was issued to the Gateway's host, so any member behind a Gateway could obtain a
  certificate with the Gateway's powers and use it directly against the Server. Such a request is
  now refused, nothing is signed, and the refusal is audited as `issuance.refused`. This Client
  always sends a proof. **What to do:** nothing for Clients of this project. A third-party OpAMP
  client behind a Gateway gets its next certificate by enrolling directly or from the operator.

- **A Gateway forwards a report only for an Agent of the host that sent it**
  ([ADR-0039](docs/adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)).
  Until now any host behind a Gateway could report under another host's `instance_uid`, take
  over its route and receive its configuration and its certificate. The binding that already
  guarded downloads now guards every message: a report for an `instance_uid` bound to another
  host is dropped over WebSocket, answered `403` over plain HTTP, and logged. A host past
  `max_carried_agents` makes room among its own idle Agents and never takes another host's. A certificate without a host URI is bound
  under the host the Server derives for it, so its Agents stay bound across its first renewal.
  **What to do:** nothing. If a host was locked out of its own Agent, restart the Gateway; the
  real host's next report then binds it.

- **A connection-settings offer never moves a Client to plaintext**
  ([ADR-0040](docs/adr/0040-a-connection-settings-offer-never-moves-the-client-to-plaintext.md)).
  An offer could move a Client to `ws://` or `http://` on the loopback, where whoever listens on
  that port became its Server, with no certificate to prove it. The Server now refuses a `ws://`
  or `http://` `[connection_offer] endpoint` at startup, the Client refuses such an offer and
  reports it `FAILED`, and a persisted plaintext endpoint that `supervisor.toml` does not name is
  not applied at startup. **What to do:** a `server.toml` whose `[connection_offer] endpoint` is
  `ws://` or `http://` no longer starts; set a `wss://` or `https://` endpoint or remove the key.
  A development setup on the loopback names its plaintext endpoint in `supervisor.toml`.

- **A Package version is SemVer, and a Supervisor never installs one below its high-water mark**
  ([ADR-0043](docs/adr/0043-a-package-version-is-semver-and-never-installed-below-the-high-water-mark.md)).
  A compromised Server could move a Supervisor back to an old, validly signed build: by offering
  it under a version that cannot be ordered, such as `1.19`, or by purging the Supervisor and
  adding it back, which deleted the record its floor was read from. A Package version must now
  be SemVer on the Server (`400` otherwise), in `opamp-fleetctl package sign` (refused before the
  key is read) and on the Client. Each Client keeps the highest version it has installed per
  Agent type in `<state_dir>/package-high-water.json`, which no purge touches, and every
  Supervisor of that type refuses an offer below it. `package fetch` names the Package of an
  upstream `1.19` as `1.19.0`. The Client's own update keeps its own rules. **What to do:** a
  Server holding a Package under a version that is not SemVer starts, warns about each one, and
  writes nothing to it; such a Package is no candidate, and an upgraded Client refuses its offer.
  Republish its content under a SemVer version (`1.19` becomes `1.19.0`), sign it again and roll
  that out; an Agent whose installed record named the old version takes it as a first rollout.
  Scripts that create Packages under non-SemVer versions get `400`. To move a Supervisor to an
  older version on purpose, stop the Client, remove that type's entry from
  `package-high-water.json`, delete `installed-package.json` of every Supervisor of that type,
  and start the Client — or publish the old content under a new, greater version.

- **The Operator plane sends HSTS.** Every response carries `Strict-Transport-Security:
  max-age=31536000`, without `includeSubDomains`, so a browser that reached the plane once by its
  name never tries `http://` for it again, where an attacker on the network could answer and ask for the
  Basic credentials. **What to do:** nothing; the plane serves TLS on every address already.

- **A certificate serial is at most 20 octets.** `POST /api/v1/revocations` answers a longer serial
  `400`, and a certificate whose serial is longer is neither admitted nor registered, as RFC 5280
  allows no more. Every Gateway reads the revocation list within a bound that assumes this length,
  so megabyte-long serials could have pushed the list past it and left every Gateway admitting
  nobody. **What to do:** nothing; no certificate this Server or `opamp-fleetctl` makes has a
  longer serial.

- **A Managed Process states only its own `service.*` attributes**
  ([ADR-0041](docs/adr/0041-a-managed-process-states-only-its-own-service-attributes.md)).
  What a Managed Process reported about itself was laid over the Supervisor's description for
  every key but its identity and name. A process running a command from its configuration could
  report another host's `host.name` or `host.id` and draw that host's Configurations, report
  another platform and be offered another machine's binary, report a `supervisor.kind.*` key and
  make every Agent of its host ambiguous, or overwrite an `[attributes]` entry such as `channel`.
  The Client now takes only the process's `service.*` attributes, never `service.instance.id`,
  `service.instance.name`, `service.namespace` while `service_namespace` is set, or a key
  `[attributes]` sets, and drops every other key it reports. A Collector's type and version still
  arrive; its own `agent_description.non_identifying_attributes`, its resource attributes and its
  own `host.name` no longer do. **What to do:** if a Selector matched an attribute that only a
  Collector reported, move that tag to a Server label, or to `[attributes]` for the whole host.

- **The Linux packages run the Client under its own account, and an upgrade keeps the account it
  finds** ([ADR-0042](docs/adr/0042-the-linux-packages-run-the-client-under-its-own-account.md)).
  Every packaged Linux host ran the Client, and every command a Server-delivered configuration
  names, as root. A host installed with `--run-as` went back to root at its next package upgrade,
  without a word, because the post-install re-registered without the flag. The `.deb` and the
  `.rpm` now create the system account `opamp-fleet` where it is missing (no password,
  `/usr/sbin/nologin`, home `/var/lib/opamp-fleet`) and run a first installation under it. A
  `service install` without `--run-as` keeps the account its unit or plist names; a unit that lost
  its account, on a data root an account owns, gets that owner back. A kept account that no longer
  exists stops the install before it writes anything, naming the unit. No package removal deletes
  the account. **What to do:** an existing root install stays root, and the account is created on
  it but unused. Move such a host with
  `sudo opamp-fleet service install --run-as opamp-fleet` and
  `sudo systemctl restart opamp-fleet`, after checking that its Agents work without root (GLPI
  Agent's inventory and Deploy, Telegraf inputs that need `sudo`, ports below 1024, logs readable
  only by `adm`). A file the service reads outside the data root must be readable by the account.

- **A third-party GitHub Action is pinned to a commit SHA**
  ([ADR-0044](docs/adr/0044-third-party-actions-are-pinned-to-a-commit-sha.md)). The workflows
  that build, test and release the project ran `Swatinem/rust-cache` and `taiki-e/install-action`
  on their mutable `v2` tag, so whoever could move that tag chose what the next run executed,
  including the `cargo-deny` that gates every release. Both are now pinned to the commit of a named
  release, `# vX.Y.Z` beside it, and every pull request checks that the named tag still points to
  that commit. GitHub's own `actions/*` stay on their major tag. **What to do:** nothing; the
  release assets are unchanged by this.

- **Every release asset is attested, and every shipped program has an SBOM**
  ([ADR-0045](docs/adr/0045-every-release-asset-carries-a-provenance-attestation-and-every-program-an-sbom.md)).
  Until now `SHA256SUMS` proved only that a download matched the file beside it on the same
  release page. Every asset of a release, `SHA256SUMS` included, is now a subject of one SLSA
  build-provenance attestation, signed through Sigstore by the release workflow and recorded in
  its public log, and the workflow verifies each asset before the release is created. A release
  also carries nine more assets: one CycloneDX 1.5 SBOM per program and target,
  `supervisor_<version>_<os>_<arch>.cdx.json` (five) and
  `opamp-fleetctl_<version>_<os>_<arch>.cdx.json` (four), each listing the crates its binary is
  built from on that target; the `.deb`, `.rpm` and `.msi` of a stem are described by its
  archive's SBOM. **What to do:** verify a download with
  `gh attestation verify SHA256SUMS --repo mbrigl/opamp-fleet --signer-workflow mbrigl/opamp-fleet/.github/workflows/release.yml`,
  then `sha256sum -c --ignore-missing SHA256SUMS`; the same `gh attestation verify` checks any
  single asset. A script that downloads `supervisor_<version>_*` or `opamp-fleetctl_<version>_*`
  without an extension now also picks up the `.cdx.json`; select `.tar.gz`. No asset carries a
  code signature.

- **One bootstrap certificate holds at most a quarter of the enrolment queue**
  ([ADR-0046](docs/adr/0046-one-bootstrap-certificate-holds-at-most-a-quarter-of-the-enrolment-queue.md)).
  Whoever held one bootstrap certificate could fill all 1024 places of the pending queue with
  requests for fresh keys, and every other host was refused until the window closed. The requests
  of one bootstrap certificate now hold at most `[enrolment] max_pending_per_bootstrap` places,
  256 by default; a request beyond that is answered `Unavailable`, and audited as
  `enrolment.refused` once per certificate and window. A re-sent request that already waits is
  never refused. **What to do:** nothing, unless one bootstrap certificate enrols more than 256
  hosts in one window: then approve them in batches, or set `max_pending_per_bootstrap` (1 to
  1024) in `[enrolment]`.

- **A bootstrap PKCS#12 password is 8 to 128 characters**
  ([ADR-0048](docs/adr/0048-a-bootstrap-pkcs12-password-of-8-to-128-characters.md)).
  A leaked `bootstrap.p12` under a password of four characters opened offline within hours of GPU
  time, and whoever opened it could take places in the enrolment queue. `POST
  /api/v1/bootstrap-certificates` and the **Enrolments** tab now take 8 to 128 characters without
  a control character, and answer anything shorter `400`. **What to do:** choose a password of at
  least 8 characters for the next bootstrap certificate you issue, and update any script that
  issues one with a shorter password. A file issued before keeps the password it was issued under
  and opens with it.

### Changed

- **An enrolment request proves its bootstrap certificate**
  ([ADR-0039](docs/adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)).
  The Client adds a bootstrap proof to every enrolment request: the bootstrap certificate it
  enrols with and a signature with its key over the requested key, about 1 KiB more in the
  request. The Server checks the proof and files the request under the certificate it names. On
  a direct connection that must be the certificate the connection presented; a request whose proof
  names another or does not verify, and one carrying a renewal proof beside it, is answered
  `BadRequest` and not queued. **What to do:** nothing. A Client of an earlier release, and a
  third-party OpAMP client, enrols as before without the proof.

- **An enrolling Client on `https://` sends its request alone, and a member does not enrol**
  ([ADR-0039](docs/adr/0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)). A Client that holds
  no certificate the Server issued and polls over `https://` now sends its certificate signing
  request as its only report, before the Server's first answer, and re-sends it at every poll until
  the certificate arrives. The Server refuses a request with a bootstrap proof over a member's
  certificate whose host is not marked as a Gateway, unless the proof names that very certificate,
  as a Client on a certificate an operator provisioned sends it; through a Gateway, a request with
  neither a renewal proof nor a bootstrap proof is refused naming both. **What to do:** nothing. A
  Client on a provisioned certificate whose request the Server refuses reports as a member again
  until an exchange fails.

- **A plain `service install` no longer returns a host to root**
  ([ADR-0042](docs/adr/0042-the-linux-packages-run-the-client-under-its-own-account.md)).
  Without `--run-as` a re-registration keeps the account the registration names. Root is chosen
  with `--run-as root`, which the unit records as `User=root`. The install prints the account and
  where it came from, and on every system registration under Linux and macOS, root included, hands
  both roots over to that account. **What to do:** a host you returned to root with a plain
  re-install while its data root still belonged to the account comes back up under the account at
  its next re-registration; run `sudo opamp-fleet service install --run-as root` to keep it root.
  Windows is unchanged: the SCM keeps the logon account it holds.

- **The Client writes its systemd unit itself**
  ([ADR-0042](docs/adr/0042-the-linux-packages-run-the-client-under-its-own-account.md)).
  `ExecStart=` now quotes every word, so a root holding a space, a `%` or a `$` names the right
  program. Every system unit carries `ProtectControlGroups=yes`; a unit running as root also
  carries `ProtectKernelTunables=yes`, `LockPersonality=yes` and `RestrictRealtime=yes`. Nothing
  that sets `no_new_privs` under an account is added, so `sudo` and setuid helpers keep working.
  **What to do:** nothing, the next upgrade rewrites the unit. A host that needs more or less puts
  it in a drop-in under `/etc/systemd/system/opamp-fleet.service.d/`, which no install touches. An
  archive install that only self-updates gets the new unit at its next `service install`.

### Fixed

- **A Host and its bindings end with its last valid certificate, and forgetting an Agent releases
  its binding**
  ([ADR-0047](docs/adr/0047-a-host-and-its-bindings-end-with-its-last-valid-certificate.md)).
  A Host with a bound Agent was never removed, even long after its last certificate expired, and
  forgetting an Agent left its `instance_uid` bound, so the host register only ever grew. Each
  Host now records its valid until — the latest end of a certificate naming it that the Server
  issued or that the host presented — and a Host not marked as a Gateway is removed once it has
  passed, its Agents released. `DELETE /api/v1/agents/{instance_uid}` releases the Agent's
  binding, so whichever host reports it next binds it. Host files under `data_dir/hosts/` gain a
  `valid_until_ms` field; files without it still load, take the latest end the register holds for
  their Host, and stay until the host next connects when the register holds none. **What to do:**
  nothing. Forget an Agent only once it no longer runs, or accept that the next host reporting it
  takes it.

- **The audit record is written out before the Server exits.** Entries still queued for the audit
  writer at shutdown were lost with the process, without a trace in the record. The Server now
  waits up to five seconds for them after both planes have drained, and logs an error if they
  could not be written, or if the record was failing. The audit directory and a new audit file's
  name are synced when they are created, so a crash cannot take the file and the entries already
  synced into it.

## [0.5.5] - 2026-10-18

### Added

- **Two more looks for the UI:** a style combo chooses between the GitKraken look, a Carbon look —
  IBM's Carbon Design System as Würth Phoenix's NetEye wears it, Gray 100 with its purple — or a
  quiet look where colour says only state and selection. Beside it, three buttons choose light,
  dark or System, which follows the operating system's preference as it changes. The two are
  independent: a theme holds across every look. A first visit follows the system; a light or dark
  chosen before in this browser still holds.

- **Coloured effective configurations**
  ([ADR-0038](docs/adr/0038-the-ui-colours-an-agents-effective-configuration-with-shiki.md)). The
  Agents tab colours an Agent's effective configuration, in its cell and in the dialog, with the
  TextMate grammars VS Code uses, in the colours of the look and theme chosen: YAML for
  `otelcol*`, TOML for the fleet's own Client and Telegraf, INI for Fluent Bit; any other type stays
  plain. TOML table headers and keys and INI section headers take the same colours as YAML's keys
  and values, so the three languages look alike. The colouring runs in the browser from a script the Server serves itself as `/shiki.js`,
  so nothing is loaded from elsewhere and the page's policy is unchanged. Nothing to configure.

- **The UI can present a certificate of its own**
  ([ADR-0032](docs/adr/0032-the-operator-plane-may-serve-a-certificate-of-its-own.md)). An optional
  `[rest.tls]` with `cert_file` and `key_file` gives the Operator plane — the UI, the REST API and
  its docs — a certificate of its own, for example from your organization's PKI, so browsers trust
  it without importing the fleet's server CA. The Agent plane keeps `[tls]`'s, and nothing changes
  for the Clients. Without the section the Operator plane serves `[tls]`'s as before, so no
  `server.toml` has to change. `server pki status` and the expiry warnings include it.

- **The Server checks package signatures, as feedback** ([ADR-0033](docs/adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)). An optional
  `[packages] verification_key` in `server.toml` — the same hex public key the Clients hold —
  makes the Server check each entry's signature when it is written and when it starts, and the
  Packages tab and `GET /api/v1/packages` show it as `valid` or `invalid` (`unchecked` without the
  key, `missing` with none). An invalid signature is shown as a warning and kept; each Client's own
  check still decides what is installed. A malformed key fails startup.

- **Hosts, and a Hosts tab** ([ADR-0035](docs/adr/0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)). A Host is what a
  client certificate of this Server names: the Server writes it when you approve its enrolment, or
  at the first report of a provisioned certificate that names a host id, with the certificate's
  subject values. The new Hosts tab lists each Host — its name (the `host.name` its Client's own
  Agent reports, else the host id), its subject values, the Gateway mark, its valid certificates
  and when each ends, and its Agents — and marks a Gateway or revokes a Host's certificates from
  its row. Selecting a Host shows its Agents grouped by Client; for a Gateway, the Agents behind
  it. `GET /api/v1/hosts` adds `name`, `subject`, `approved_ms` and `agents`, and each Agent in
  `GET /api/v1/agents` names its `host`.

- **Selectors can match the Host's certificate, and a Client's own Agent labels its whole Client**
  ([ADR-0035](docs/adr/0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)). An Agent on a direct
  connection carries its Host's subject values as `fleet.host.country`, `fleet.host.state`,
  `fleet.host.locality`, `fleet.host.organization`, `fleet.host.site` (the organizational unit)
  and `fleet.host.organization_id`, which no Agent can report over; an Agent behind a Gateway
  carries none. A host certificate carries the values of the bootstrap certificate it enrolled
  with (see *A bootstrap certificate's subject* below). The labels of a Client's own Agent — the one reporting
  `supervisor.kind.*` — hold for that Client's Supervisor Agents below their own labels; behind a
  Gateway the Agents are grouped by the `host.id` (else `host.name`) they report, and a group with
  two Client Agents inherits nothing and is marked `ambiguous`. The Agents tab marks inherited
  labels. **What to do:** label a Client's own Agent once instead of each of its Agents.

### Changed

- **Every field of the UI's forms says whether it is required or optional.** A caption above
  each field names it and says *required* or *optional* in words — the placeholder that said it
  before vanished as soon as something was typed — and a required field is announced as such to
  screen readers. Nothing about what the Server accepts changed.

- **All of the Server's state lives under one data directory, and `server migrate` moves an
  installation there**
  ([ADR-0037](docs/adr/0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)).
  `server.toml` names `data_dir` (default `fleet-data`) instead of `config_dir` and `packages_dir`;
  a file still naming either fails the start, naming `server migrate`. Under it each domain has a
  directory of its own — `configurations/`, `deployments/`, `packages/`, `blobs/`, `agents/`,
  `hosts/`, `certificates/`, `bootstrap/`, `audit/` — beside `revocations.json` and
  `enrolment.json`, every directory `0700` and every file `0600`; anything else in it, or a file
  whose name disagrees with what it holds, fails the start naming the path. An artifact is kept
  once by its SHA-256 in `blobs/`, hashed again at every start, and deleted with the last entry
  naming it; identical artifacts count once against `max_total_package_bytes`. The audit is
  checked with `server audit-verify <data_dir>/audit`.
  **What to do**, once, with the Server stopped:
  1. Run `server migrate --config-dir <config_dir> --packages-dir <packages_dir> --data-dir <new,
     empty directory>` as the Server's account. It copies — the old directories stay as your
     backup — and prints what it carried, dropped and listed; it exits non-zero when it could not
     carry the register, the revocation list, the Hosts, the bootstrap certificates or the audit.
  2. In `server.toml`, remove `config_dir` and `packages_dir` and set `data_dir` to the new
     directory. Under systemd's `ProtectSystem=strict`, a `data_dir` outside the unit's
     `StateDirectory` needs a `ReadWritePaths=` line.
  3. Start the Server. Put each Configuration the migration listed into a Deployment, sign each
     entry it named unsigned, upload each artifact it dropped, and roll the Deployments out.
  4. Keep the old directories until you are satisfied, then delete them.
  The steps, and what the migration does with each kind of data, are in the Server's manual
  ([Upgrading to one data directory](docs/manual/server.md#upgrading-to-one-data-directory)).

- **The enrolment window and its queue survive a restart**
  ([ADR-0037](docs/adr/0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)).
  They are written to `enrolment.json` before the act that changes them is answered, so an open
  window stays open until its end and a host whose approval it had not collected yet is handed its
  certificate after the restart; a window whose end passed while the Server was down is closed
  when it starts. Opening the window, approving and rejecting answer `500` when that cannot be
  written, and change nothing.

- **A bootstrap certificate's subject names up to six values, and every host certificate issued
  from it carries them**
  ([ADR-0036](docs/adr/0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)).
  `subject` in `POST /api/v1/bootstrap-certificates` takes `country` (two upper-case letters, ISO
  3166-1 alpha-2), `state`, `locality`, `organization`, `organizational_unit` and
  `organization_identifier` (a customer or contract number); `organization` and
  `organizational_unit` are required, and a request without either is answered `400` naming it, so
  every Host names a customer and a site. The Enrolments tab has a field for each, marks the two
  required and offers the countries as a list. Approving an enrolment copies these values
  from the bootstrap certificate the host enrolled with into its host certificate, and every
  renewal carries them on, so its Agents carry them as `fleet.host.*`; the CSR's subject is never
  copied. `GET /api/v1/enrolments` lists the bootstrap certificate's values as the object
  `bootstrap_subject` and no longer lists the request's `subject`. An approval whose bootstrap
  certificate has a malformed subject — an attribute twice, a value of the wrong string type or
  length, a country that is not two upper-case letters, no organization or no organizational
  unit — is answered `409` naming the attribute,
  and nothing is signed; the queue lists such a request with `subject_refusal` giving that reason
  instead of `bootstrap_subject`, and the Enrolments tab shows it on the row. **What to do:** a script that reads `subject` or the text
  `bootstrap_subject` of `GET /api/v1/enrolments` reads the `bootstrap_subject` object instead.
  Host certificates issued before carry no values, and their Hosts have none until the host enrols
  again with a bootstrap certificate that names them. A bootstrap CA of your own PKI must write
  an organization and an organizational unit, the country as a `PrintableString` and every other
  value as a `UTF8String` or a `PrintableString`, each at most once; replace a bootstrap
  certificate that does not. A script that issues bootstrap certificates names `organization` and
  `organizational_unit` in every request.

- **Labels are part of the Agent's record, and forgetting an Agent removes them**
  ([ADR-0035](docs/adr/0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)). Labels follow an Agent
  the Server re-keys, and are gone with an Agent you forget; one that comes back starts with only
  what its Client Agent's labels give it. A label key
  starting `fleet.` is refused `400`, and a reported attribute starting `fleet.` is left out of what
  Selectors match and listed in `ignored_attributes` on the Agent. A label that cannot be written
  is answered `500`. **What to do:** nothing beyond `server migrate` (see *All of the Server's
  state lives under one data directory* above), which moves each Agent's labels into its record.

- **A Deployment carries Configurations, and is the one thing rolled out** ([ADR-0034](docs/adr/0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)). A
  Deployment holds any number of Configurations beside its Packages
  (`PUT|DELETE /api/v1/deployments/{name}/configurations/{configuration}`, or the Deployments
  tab), and one press of its rollout releases both: each Agent it claims gets the Package for its
  type and every Configuration that fits its type, and the hash gates send only what changed. A
  Configuration is content only — `{"body", "service_name", "role"}`; a `PUT` naming a `selector`
  is refused `400`, `GET` lists the Deployments holding each one, and an Agent in no Deployment is
  offered no Configuration. The per-Agent rollout takes an empty body or
  `{"deployment": "<the one that claims it>"}`; naming a Configuration or a Package is refused.
  A Deployment stays editable in every state: taking a Package out of a channel that released it
  is no longer refused. The fleet view shows per Configuration and for the Package what the next
  press would change, including what it drops (`change: "remove"`) and what the Agent keeps
  running because the press leaves it with no assignment (`change: "kept"`), and in
  `pending_deployment` the Deployment the press releases through when the assignment names
  another one. The Configurations tab edits
  content only; the Deployments tab holds the Selector, the Packages and the Configurations.
  **What to do:** `server migrate` (see *All of the Server's state lives under one data
  directory* above) drops each Configuration's Selector and lists it with the Selector it had.
  After the upgrade, put each Configuration into a Deployment whose Selector reaches the Agents it
  was aimed at — an Agent belongs to at most one Deployment, so a fleet-wide Configuration goes
  into every channel — and roll the Deployments out. An Agent keeps the Package it was released
  through a Deployment until then. Every Configuration an Agent was given was released without a
  Deployment, so the migration drops each Agent's Configuration pins and lists them per Agent; the
  Agent keeps running them until a Deployment holding them reaches it.
  `opamp-fleetctl package fetch` stores its default Configurations typed for their Collector, and
  `scripts/seed_test_configs.sh` puts each into a Deployment of that Collector's name.

- **Nothing an Agent's assignment pins can be deleted** ([ADR-0034](docs/adr/0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)). Deleting a Configuration, a
  Package or a Deployment that any Agent's assignment pins answers `409`, saying how many Agents
  pin it, where deleting a Configuration or a Package used to take it out of every assignment.
  A deleted Configuration or Package leaves every Deployment that held it. **What to do:** roll the
  Agents out through a Deployment without it — or forget them — and delete it then.

- **Every Configuration names its Agent type** ([ADR-0034](docs/adr/0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)).
  `service_name` is required: a `PUT /api/v1/configurations/{name}` without it, or with an empty
  one, is answered `400` naming it, and the Configurations tab marks the Agent type required. A
  Configuration reaches only the Agents of its Deployment that report that `service.name`; one
  without a type no longer reaches every Agent, and an Agent that reports no `service.name`
  receives no Configuration. A stored Configuration without a type stops the Server at startup,
  naming its file, and `server migrate` does not carry one: it lists it by name and leaves its file
  in the old directory. **What to do:** give every Configuration a type before the upgrade — save
  it again with `service_name` — and split content meant for several Agent types, a certificate
  bundle for instance, into one Configuration per type; one the migration listed, save again from
  its old file with a type.

- **A package's signature lives on its entry, not on the Deployment** ([ADR-0033](docs/adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)). Sign each
  entry once, with `PUT /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature`
  (`{"signature": "<hex>"}`) or on the Packages tab, where the signing-file import now lives too;
  every Deployment that holds the Package offers that signature. Uploading new bytes to an entry
  removes its signature, and a signature write on a Package rolled out to an Agent is refused
  (`409`) like any other change to its entries. The Deployment signature routes
  (`…/deployments/{name}/signatures/…`) answer `404`, the Deployment view no longer reports
  `signed_platforms`, and the Deployments tab only shows each entry's signature state. Signatures
  stored on a Deployment are not read any more. **What to do:** `server migrate` moves the
  signature the Deployments held onto each entry. An entry two Deployments held different
  signatures for is carried unsigned and named: sign it again, on the Packages tab (import the
  signed signing file there) or through the entry route — until then it is offered to nobody, and
  a rollout of a Deployment holding it is refused naming it.

- **A Client downloads packages only from its own Server's origin** ([ADR-0033](docs/adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)). A path is
  resolved against the origin of its OpAMP endpoint; an absolute URL on any other origin, or a
  redirect off it, is refused before a byte is fetched and reported `InstallFailed` naming that
  origin.

- **The UI's look follows GitKraken Dark as GitKraken Desktop 12.6 ships it:** charcoal panels,
  GitKraken's blue for buttons and the selected row, and its purple for what is selected. Light
  follows GitKraken Light. The theme button and a browser's remembered choice work as before.

- **The enrolment queue names a request's bootstrap certificate by what it was issued for.** The
  Enrolments tab leads with its customer and site, then its serial and end, and marks a revoked
  one; the full subject, issue date and fingerprint are in the tooltip, so the only fingerprint
  beside a request is the key fingerprint you compare. The bootstrap-certificate list counts the
  requests waiting with each certificate.

### Removed

- **Issuing a bootstrap certificate without a password, and its key as PEM**
  ([ADR-0036](docs/adr/0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)).
  `password` is required in `POST /api/v1/bootstrap-certificates`: a request without it is
  answered `400` naming it, every bootstrap certificate is kept as a PKCS#12 file for download, and
  the answer never carries `private_key_pem`. The Enrolments tab requires the password, typed
  twice, and offers **Save bootstrap.p12** on every certificate; its **Save bootstrap.pem** and
  **Save bootstrap-key.pem** are gone, and the page holds no private key. **What to do:** issue
  bootstrap certificates with an organization, an organizational unit and a password, and download
  `bootstrap.p12`; where a host needs the pair as PEM, take it out of the file with
  `opamp-fleetctl pki p12-extract bootstrap.p12 --out <dir>`. A script that read
  `private_key_pem` downloads `GET /api/v1/bootstrap-certificates/{serial}/p12` instead;
  `scripts/seed_test_configs.sh --enrol` does so.

- **A Configuration's own Selector and its rollout route** ([ADR-0034](docs/adr/0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)).
  `POST /api/v1/configurations/{name}/rollout` answers `404`, and the Configurations tab has no
  Selector and no rollout press. **What to do:** aim through a Deployment and press its rollout
  (see *A Deployment carries Configurations* above); a script that calls the route or sends a
  `selector` has to change the same way.

- **Referenced package entries** ([ADR-0033](docs/adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)). An entry is an uploaded artifact and nothing
  else: `PUT …/entries/{os}/{arch}/source`, its `url`, `sha256` and `headers`, and the Server's
  probe of the URL are gone (the route answers `404`), and the Packages tab takes files only. The
  Server sends no request for a package anywhere. **What to do:** before upgrading, upload every referenced artifact as a file to its
  entry (`opamp-fleetctl package fetch` does it for the agents it knows) and sign it; `server
  migrate` drops a referenced entry it still finds, naming it — upload that artifact afterwards.

- **`[packages] allowed_sources` in `supervisor.toml`** ([ADR-0033](docs/adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)). There is no other
  download source than the Client's own Server, and a file that still names the key fails the
  Client's start, naming it. **What to do:** delete `allowed_sources` from every `supervisor.toml`
  before the Client is upgraded.

- **`advertised_url` in `server.toml`** ([ADR-0033](docs/adr/0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)). Every package is offered as a path the Client
  resolves against its own Server, and a Client downloads from no other host, so a URL naming a
  mirror reached no Client. A file that still names the key fails the Server's start, naming it.
  **What to do:** delete `advertised_url` from `server.toml` before the Server is upgraded.

### Fixed

- **The expiry warnings follow the certificate the Server serves.** The daily check read each
  certificate file anew, so a file replaced without a restart silenced the warning while the
  Server still served the old, ending certificate. It now judges what the Server read at startup,
  and says when a file holds another certificate than the one served: restart the Server to serve
  it ([ADR-0028](docs/adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)
  clause 11).
- **An Agent that asks the Server for a new `instance_uid` keeps its labels**
  ([ADR-0024](docs/adr/0024-the-fleet-record.md)). The record moved to the new identity but its
  labels stayed under the old one, so after the next restart the Agent had none and fell out of
  the Deployment its labels put it in. Labels now live in the Agent's record and follow it.
  **What to do:** `server migrate` lists the labels it drops because no Agent record of their
  Instance UID exists — those are the leftovers; set them again on the re-keyed Agent.
- **A deleted Package leaves the Deployments that held it**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
  The Deployment kept the Package and its signatures, so the Deployment still passed the check for
  unsigned Packages, and a Package created again under the same type and version reappeared in it
  with the old signatures. **What to do:** nothing — `server migrate` drops such a name from its
  Deployment and lists it.

### Security

- **Revoking a bootstrap certificate withdraws the enrolment requests waiting with it.** Until
  now such a request stayed in the queue until the window closed, and approving it still signed a
  certificate for its key. The revocation now takes it out of the queue, and an approval of a
  request whose bootstrap certificate is revoked is refused (`409`) with nothing signed. The
  revocation's audit entry counts the withdrawn requests as `withdrawn_requests`
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 35).

## [0.5.4] - 2026-10-15

### Added

- **A bootstrap certificate as one file under a password**
  ([ADR-0029](docs/adr/0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)).
  Issued with a `password` — in the Enrolments tab, typed twice — the Server hands out no PEM key:
  it keeps `bootstrap.p12`, the certificate and its key encrypted under that password, and offers it
  for download (`GET /api/v1/bootstrap-certificates/{serial}/p12`, **Save bootstrap.p12**) until the
  certificate ends or is revoked. The password is 4 to 128 characters
  ([ADR-0030](docs/adr/0030-a-pkcs12-password-of-4-to-128-characters.md)) and is kept nowhere.
  A short password is quick to break offline should the file leak; an operator's approval of each
  enrolment request is then what stands in the way. Each download is audited as
  `enrolment.bootstrap_p12_downloaded`. Without a password nothing changes.
- **The Client enrols with a `bootstrap.p12`.** `service install` finds it beside its program, and
  the questionnaire takes a `.p12` path, asking its password with input hidden. Without a terminal,
  `--bootstrap-password-file <file>` gives the password; an install that would take a
  `bootstrap.p12` without it stops before writing anything.
- **`service install --fleet-files <dir>`** looks for the fleet's files in that directory instead of
  beside the program — what a host installed from a `.deb` or `.rpm` needs to enrol from a script:
  install the package, then run `service install --endpoint <URL> --fleet-files <dir>` and approve
  the request.

- **A revoked bootstrap certificate can be deleted from the list**
  ([ADR-0029](docs/adr/0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md) clause 15):
  **Delete** in its row of the Enrolments tab, or
  `DELETE /api/v1/bootstrap-certificates/{serial}`. The entry and any `bootstrap.p12` go; the
  revocation stays, so the certificate is still refused. A valid certificate is not deleted.
- **`opamp-fleetctl pki p12-extract <bootstrap.p12> --out <dir>`**
  ([ADR-0031](docs/adr/0031-opamp-fleetctl-extracts-a-bootstrap-pkcs12-file-into-pem.md)) writes
  the file's certificate as `bootstrap.pem` and its key, unencrypted and owner-only, as
  `bootstrap-key.pem`: the pair a Client's install takes, without OpenSSL. The password is asked
  for with input hidden, or read from the first line of `--password-file`; neither file is
  overwritten.

### Security

- **A Windows `service install` takes the default data root over.** `%ProgramData%\<product>`
  and everything in it now belong to the Administrators, and every right in it that the install
  does not grant is removed — a directory a local user created there before the install included;
  a `--run-as` account is granted its rights again by the same install. A `supervisor_dir` outside
  the data root and the state directory that the install creates is cut off from inherited rights
  and granted to the `--run-as` account, as a state directory outside the data root is; one that
  already exists is left as it is, and the install warns about it. **What to do:** restrict such an
  existing `supervisor_dir` to LocalSystem, the Administrators and the service account yourself.
- **rustls 0.23.46**, for RUSTSEC-2026-0346 to -0349. None of the four is reachable in this build:
  it enables no `brotli` certificate compression, uses no Encrypted Client Hello and no session
  store of its own, and its *ring* provider offers no post-quantum hybrid group to be downgraded
  from. **What to do:** nothing beyond the upgrade.
- **Release builds check integer overflow.** An arithmetic overflow in the Server, the Client or
  `opamp-fleetctl` panics instead of wrapping into a wrong value. **What to do:** nothing.
- **The Server's systemd unit in [the setup guide](docs/manual/setup.md) is sandboxed**: no new
  privileges, no capabilities, a read-only file system but for its state directory, and no access
  to home directories, devices or kernel settings. **What to do:** a unit copied from an earlier
  guide can take the new lines; a `config_dir` or `packages_dir` outside
  `/var/lib/opamp-fleet-server` then needs a `ReadWritePaths=` line naming it.
- **A client certificate past its end is refused on every request**, not only in the TLS
  handshake: a kept-alive HTTP or HTTP/2 connection gets `401` on `/v1/opamp` and on the download
  route once its certificate has expired
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
  **What to do:** nothing; a Client that renews on time never meets it.
- **A peer is a fleet member only when its certificate verifies against a client CA's key**, not
  when its issuer merely carries a client CA's name. **What to do:** nothing.
- **A revocation is on disk before it is answered**: the Server syncs the file and its directory.
  **What to do:** nothing.
- **A report refused at `max_agents` binds no `instance_uid` to its host**, and the host register
  forgets a host that holds no valid certificate, no Agent and no Gateway mark. **What to do:**
  nothing.
- **The Operator plane answers with security headers**: a Content-Security-Policy that forbids
  framing and runs only the UI's own scripts, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`
  and `Cache-Control: no-store` on `/api/v1`. **What to do:** nothing, unless a proxy in
  front adds headers of its own that conflict.
- **A body-less `POST` whose `Origin` is not the plane's own is refused** (`403`) when the browser
  sends no Fetch Metadata. **What to do:** a TLS-terminating proxy in front keeps the `Host` the
  browser sent.
- **A package source is checked before it is probed**, so a URL the Server refuses never receives
  its headers, and the probe refuses an IPv6 address that carries a blocked IPv4 one (NAT64, 6to4,
  IPv4-compatible) and AWS's `fd00:ec2::254`. **What to do:** nothing.
- **An upload still arriving counts against `max_total_package_bytes`**: one that would take the
  store past it is answered `507` while it streams, and an upload that ends without being stored
  leaves no file behind. **What to do:** nothing.
- **One password check at a time per address on the Operator plane** (an IPv6 address by its
  /64): a second sign-in from the same address waits for the first. Behind a proxy every
  operator shares one address, so first sign-ins are checked one after another. **What to do:**
  nothing.
- **Refused requests cannot crowd out the audit record** (ADR-0022): refusals are counted per
  peer before they are queued and hold at most half of the queue, so admissions and operator acts
  are still recorded under a flood. **What to do:** nothing.
- **A Gateway reads the revocation list within 128 MiB** (ADR-0015, ADR-0021). A larger list
  is refused as unreadable, and a Gateway that holds no list younger than 300 s admits nobody.
  The bound holds every list the Server names with up to eight client CA subjects and serials of
  the length RFC 5280 allows. **What to do:** keep `client_ca_file` to eight certificates or
  fewer, and revoke only serials of real certificates.
- **A Gateway frees what it kept for an Agent once that Agent is gone**: a departed socket's pool
  places and routes, and the route of an exchange that ends without its reply. A plain-HTTP
  Agent's pool place still lasts until its upstream connection drops. **What to do:** nothing.
- **A delivered Supervisor block is held to more of ADR-0017 clause 38's rule.** The clause
  refuses, whatever `[supervisors] delivered_env` allows, a variable that steers which code a
  program loads and a value pointing where the Server delivers files no one signed. Beyond the names
  and placeholders the clause lists, the Client now applies that rule to `PATHEXT`, `COMSPEC`,
  `NODE_PATH`, `PYTHONHOME`, `PERLLIB`, `PERL5DB` and `RUBYLIB`, and to a new or changed value that
  starts with a path under the Supervisors' root. A value the running block already carries still
  passes. **What to do:** an offered set that brings such a variable or value is refused whole;
  write it into the host's `supervisor.toml` by hand instead.
- **A `.tar.gz` package is decompressed no further than its bound** (ADR-0026): the members'
  2 GiB plus 64 MiB for the tar's own headers, GNU long names and PAX records. Memory is not bounded
  per record below that: the tar parser holds a single long-name or PAX record in memory whole, up
  to the same bound. **What to do:** nothing; a real release stays far below it.

## [0.5.3] - 2026-10-13

### Removed

- **The Supervisor kinds `icinga2`, `glpi` and `telegraf`** are no longer in the Client, and
  `opamp-fleetctl package fetch` no longer offers `--agent icinga2`, `glpi-agent` or `telegraf`.
  A `[[supervisor]]` block of one of these types is an unknown type now: the Client refuses to
  start on it, and a Supervisor set the Server delivers with one is refused. **What to do:** before
  upgrading, remove those blocks from `supervisor.toml` and from every Supervisor set on the Server.
  An agent that has to stay under management runs under a `command` block instead.

## [0.5.2] - 2026-10-13

### Added

- **`opamp-fleetctl package fetch --cacert <file>`** uploads to a Server whose certificate a
  fleet's own CA signed — for a fleet made with `pki init`, its `server-ca.pem`. Without it, such a
  Server was refused with `invalid peer certificate: UnknownIssuer`, since only the system's roots
  were trusted. The CA replaces those roots for the calls to the Server alone; downloads from
  upstream keep them.
- **A whole Package signed in one go**
  ([ADR-0027](docs/adr/0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md)).
  The Packages tab lists each entry with its size and full SHA-256 and downloads the Package's
  **Signing info** (`opamp-fleet-signing-v1`); `opamp-fleetctl package sign --signing-info <file>`
  signs every entry from its hash, without the artifacts; the Deployments tab imports the signed
  file into the Deployment's signatures. The tool checks the hashes against nothing: compare them
  with upstream's checksums or `package sha256` over the files before signing.
- **Bootstrap certificates issued and revoked from the Enrolments tab**
  ([ADR-0028](docs/adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)).
  The tab issues a bootstrap certificate for a customer (O) and site (OU) and lists the valid ones
  with a **Revoke** press; the row of each certificate issued in the open page offers its pair as
  `bootstrap.pem` and `bootstrap-key.pem` until the page is reloaded or closed. Each
  waiting request names the bootstrap certificate it carries by customer, site, serial and end;
  `GET /api/v1/enrolments` carries the serial as `bootstrap_serial`.

### Changed

- **The Client's install takes the fleet's files it finds beside its program**
  ([ADR-0020](docs/adr/0020-the-client-install-takes-the-fleet-files-it-finds-beside-its-program.md)).
  `service install` looks in its program's directory for `server-ca.pem`, `bootstrap.pem`,
  `bootstrap-key.pem` and `package-signing-key.pub`. `--interactive` offers them as the answers;
  `--endpoint` copies the CA and writes the verification key, and an install without
  `--interactive` enrols with a bootstrap pair it finds and waits for the operator's approval.
  **What to do:** nothing; to use it, copy the four files beside the program before installing.
  An installer run from a directory that holds a bootstrap pair now waits for an approval.
- **`pki init` makes the package signing key too.** Next to the server CA it writes
  `package-signing-key.pk8` and its public half, `package-signing-key.pub`, into `--offline-dir`,
  and `supervisor.toml.fragment` names that public half as `[packages] verification_key`, so a
  Client set up from the fragment takes signed packages from the start. `package keygen` remains
  for a fleet set up otherwise or to replace the key. **What to do:** nothing; a fleet that has a
  key keeps it.
- **Breaking: every certificate is named by its product and its role, with your organization**
  ([ADR-0028](docs/adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)).
  `opamp-fleetctl pki init` and `pki bootstrap-ca` take `--product` (default `OpAMP Fleet`) in
  place of `--fleet`, and `--organization` and `--organizational-unit` for an O and an OU: the CAs
  are `<product> Server CA`, `Client CA` and `Bootstrap CA`, the server certificate
  `<product> Server Certificate` with its names in the SAN alone. `pki server-cert` carries the
  server CA's O and OU, and its own flags replace either. The Server names the certificates it
  signs from their CA, ` CA` turned into ` Certificate`: a host certificate carries that common
  name and nothing of its request, a bootstrap certificate that and the O and OU asked for. It
  refuses to start on a client CA or bootstrap CA whose certificates' name would exceed 64
  characters. `scripts/dev-pki.sh` names its set `OpAMP Fleet Dev`, `O=Development`. **What to
  do:** replace `--fleet` with `--product` in scripts. Existing CAs keep working; their
  certificates are named from them, `opamp-fleet client CA` giving `opamp-fleet client
  Certificate`.
- **Breaking: the Server issues bootstrap certificates, and the bootstrap CA lives a year**
  ([ADR-0028](docs/adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)).
  With `[enrolment] bootstrap_ca_key_file` set, `POST /api/v1/bootstrap-certificates` issues a
  bootstrap certificate with the organization and unit an operator names — the customer and the
  site, say — and a common name the Server sets, for 10 days or up to 90, and hands out its private key in that answer
  only; `GET /api/v1/bootstrap-certificates` lists the valid ones, each revocable by its serial,
  and every issuance is recorded as `enrolment.bootstrap_issued`. The approver sees the subject on
  every enrolment request it carries. `opamp-fleetctl pki init` now puts the bootstrap CA and its
  key into `--server-dir`, makes no bootstrap certificate, and gives the bootstrap CA 365 days
  (`--bootstrap-ca-days`) while `--ca-days` sets the server CA's and the client CA's;
  `pki bootstrap-cert` and `init --bootstrap-days` are gone, and `pki bootstrap-ca` makes a new
  bootstrap CA to replace the Server's. `pki status --offline-dir` lists the server CA alone.
  `scripts/seed_test_configs.sh --enrol` now asks the Server for the development Client's
  bootstrap pair before it opens the window, so start the Client while it waits. **What to do:**
  nothing for enrolment to keep working. To issue from the Server, copy the bootstrap CA's key
  from the offline directory to the Server host and name it in `[enrolment]
  bootstrap_ca_key_file`; replace a script that calls `pki bootstrap-cert` with the route.
- **A Deployment is made and signed in one form.** The Deployments tab lists every binary of each
  Package it holds, with platform, size and full SHA-256, and gives each unsigned one a signature
  field. A new Deployment takes its Packages and signatures with **OK**. **Import signing file**
  matches each signature to the binary with its platform and SHA-256 and skips one whose hash
  differs; the free-text signature fields are gone.
- **Breaking: the build's product variables are named for the product**
  ([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md) clauses 1 and 4, [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) clause 2).
  `OPAMP_FLEET_PRODUCT_NAME` is now `OPAMP_PRODUCT_NAME`, `OPAMP_FLEET_PRODUCT_DISPLAY_NAME` is
  `OPAMP_PRODUCT_TITLE` and `OPAMP_FLEET_VERSION` is `OPAMP_PRODUCT_VERSION`; the version the build
  resolves is emitted as `OPAMP_PRODUCT_RELEASE`. The old names are no longer read: a build that
  still sets one gets the default product name, title or version without a word. **What to do:**
  rename the variables in every script or pipeline that builds a variant or states a version.

## [0.5.1] - 2026-10-12

### Added

- **The fleet's certificates without `openssl`, and a warning before one ends**
  ([ADR-0028](docs/adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)).
  `opamp-fleetctl pki init` makes the server CA, the client CA and the bootstrap CA, the Server's
  certificate and a bootstrap certificate valid for 10 days, split into a directory for the Server
  host and one that stays offline, with `server.toml` and `supervisor.toml` fragments naming them.
  `opamp-fleetctl pki server-cert` and `pki bootstrap-cert` make the next server or Gateway
  certificate and the next bootstrap certificate from the offline CAs; `opamp-fleetctl pki status
  --offline-dir <dir>` and the Server's `pki status --config <server.toml>` list when each
  certificate ends, with an exit code for monitoring. The running Server warns,
  logs and records `pki.expiring` 30 days before its own certificate or a CA it depends on ends,
  and `pki.expired` once one has. `scripts/dev-pki.sh` no longer needs `openssl`; its development
  Client enrols with the bootstrap certificate, and `scripts/seed_test_configs.sh --enrol`
  approves it. **What to do:** nothing for an existing fleet, whose certificates keep working. A
  development set made before is replaced by deleting `.dev-pki/` and running the script again.

- **Admitted Agents are rate-limited per host**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)). Every OpAMP message
  and every package download takes a token from the bucket of the host the certificate names — for
  a host marked as a Gateway, from the bucket of the Agent the message names and from the
  Gateway's aggregate. A message past the limit is answered `Unavailable` with `retry_info` of
  30 seconds and is not processed; a download past it is answered `429` with `Retry-After: 30`.
  Each refusal is recorded as `agent_rate.throttled`. `[agent_rate_limit]` sets
  `messages_per_sec` (10), `burst` (300), `gateway_messages_per_sec` (500) and `gateway_burst`
  (10 000); `0` is refused. **What to do:** nothing at the defaults. A fleet whose offered
  `heartbeat_interval_secs` is short raises `messages_per_sec`; the Server warns at startup when
  one host cannot report for 256 Agents at that interval.
- **Remote configuration can be switched off per Supervisor**
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
  `[supervisors] remote_config_disabled` in `supervisor.toml` lists Supervisor names whose Agents
  declare neither `AcceptsRemoteConfig` nor `ReportsRemoteConfig` and run only on the files placed
  in `<supervisor_dir>/<name>/config/`. A delivered block brings a listed Supervisor no `args`,
  `version_args` or `env`, whatever `delivered_args` and `delivered_env` allow. At its next start a
  listed Supervisor deletes its stored `remote-config.pb` and the unchanged files that
  configuration wrote, and keeps every file edited or added on the host. A value outside the name
  grammar fails startup. **What to do:** nothing unless you want it. Before listing a Supervisor,
  place the configuration it should run in its `config/` directory; before switching one back on,
  move anything there you want to keep, since the first delivered configuration replaces every
  file in it.
- **A host can keep its Supervisor set from the Server**
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
  `[supervisors] server_manages_set = false` in `supervisor.toml` builds the Client's own Agent
  without `AcceptsRemoteConfig` and `ReportsRemoteConfig`, so the Server offers it no Supervisor
  set; one that arrives anyway is ignored and logged once per hash. Every other capability stays,
  self-update included. The `[[supervisor]]` blocks in the file are then the operator's alone. At
  its next start the Client deletes the `remote-config.pb` in its `state_dir` and the unchanged
  entry copies in `<state_dir>/config/`. Together with `remote_config_disabled`, the Server can no
  longer bring a listed agent back under another name. **What to do:** nothing at the default
  `true`. Before switching it off, review the `[[supervisor]]` blocks, since a set the Server
  delivered earlier may have written some of them; switching it back on lets the first released
  set replace every block.
- **A Gateway delivers uploaded packages to the Clients behind it**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). When it relays an offer of an
  artifact the Server hosts, the Gateway fetches it once with its own certificate, checks its
  SHA-256 against the offer, and serves it on its own listener at the path the offer names, only to
  a host whose Agent it relayed that offer to; everything else is answered `404`. It holds the
  artifacts in `<state_dir>/gateway-packages`, emptied at startup and bounded by `[gateway]
  package_cache_bytes` (10 GiB; `0` is refused). An artifact larger than that is not delivered
  through the Gateway. While the Gateway is still fetching, a request is answered `503` with
  `Retry-After: 30`. Referenced artifacts are fetched from their host directly as before. With
  the Server's `advertised_url` set, uploaded artifacts are not delivered behind a Gateway at all.
  **What to do:** mark the Gateway's host as a Gateway on the Server if it is not yet, leave
  `advertised_url` unset in a fleet with Gateways, and give the Gateway's `state_dir` room for the
  cache.
- **A download waits out `Retry-After` from the Server's own origin**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) clause 49). A `429` or `503` with
  `Retry-After` in seconds — the Server's rate limit, or a Gateway still fetching — is waited out,
  each wait at most 60 seconds and all waits of one download at most 30 minutes, before the
  download is reported failed. **What to do:** nothing.
- **Every `Unavailable` names the Agent it answers**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md) clause 25): the
  Agent-record ceiling, a certificate request held back for its audit record, the full enrolment
  queue and the closed enrolment window now carry the message's `instance_uid`, so the Client and
  a Gateway route the reply to its Agent and the Agent waits as told.
- **A refused request for the Gateways' revocation list is recorded**
  ([ADR-0022](docs/adr/0022-an-append-only-audit-record-chained-by-hash.md) clause 1): a member
  whose host is not marked as a Gateway leaves a `gateway_list.refused` line naming its host.
- **`Unavailable` tells the Agent when to retry**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 21,
  [ADR-0022](docs/adr/0022-an-append-only-audit-record-chained-by-hash.md) clause 6): a full
  enrolment queue, the Agent-record ceiling and a certificate request held back while the audit
  record cannot be written are answered with `retry_info` of 30 seconds; the last was answered
  `BadRequest`, which told the Agent to give up.
- **A certificate names its host, and a host speaks only for its own Agents**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clauses 7,
  14 and 27). Every certificate the Server signs carries `urn:opamp-fleet:host:<id>`; a connection
  reporting for an Agent another host reported first is re-keyed, and a host holds at most three
  valid certificates. A Client's renewal proves, with its current key, which certificate it renews.
  `GET /api/v1/hosts` lists the hosts, and `PUT /api/v1/hosts/{host}/gateway` with
  `{"gateway": true}` marks a Gateway, whose certificate then speaks for any Agent. **What to do:**
  mark each Gateway once its certificate has been renewed; until then the first Agents it carries
  are bound to it.

- **The Supervisor Endpoint admits only the process its Supervisor started**
  ([ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)). Every
  Managed Process finds a token in `OPAMP_SUPERVISOR_TOKEN`, and the endpoint answers any
  connection without `Authorization: Bearer <token>` with `401`. **What to do:** add
  `headers: { Authorization: "Bearer ${env:OPAMP_SUPERVISOR_TOKEN}" }` to the `opampextension`'s
  `server.ws` in every Collector configuration that reports through the endpoint.

- **An audit record of every security decision**
  ([ADR-0022](docs/adr/0022-an-append-only-audit-record-chained-by-hash.md)): admissions and
  refusals, enrolment, issuance, revocation and the sessions it ends, operator acts with the
  operator's name, and package outcomes, as JSON lines in `config_dir/audit/`, each
  chained to the one before by its hash. `server audit-verify <dir>` checks the chain. A Server
  that cannot write the record admits no one and runs no operator act until it can. **What to
  do:** keep `config_dir/audit/` on a disk with room for `[audit] max_file_bytes` times
  `keep_files` (1 GiB by default), and copy it off the host if an intruder must not be able to
  rewrite it unseen.

- **`server.toml` holds no credential that authenticates on its own**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 26). An operator's
  Basic password in `[rest.auth]` is listed as an Argon2id hash; `server hash-credential --basic`
  makes the entry. **What to do:** before upgrading, replace every password in `[rest.auth]` with
  the entry `hash-credential --basic` prints; a Server with a password in clear refuses to start,
  naming the entry.

- **A Server-delivered `[[supervisor]]` block brings nothing that reaches past the package
  signature** ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
  It may set `env`, `args` and `version_args` only as the running block of the same name already
  has them, or as the new `[supervisors] delivered_env` and `delivered_args` allow; never `PATH`,
  `LD_*` or `DYLD_*`.
  **What to do:** where the Server delivers blocks
  with environment or arguments, allow them in each Client's `supervisor.toml`; otherwise the set
  is refused, naming the block and the key, and the running set stays as it is.

- **Revocation that takes effect at once**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
  `POST /api/v1/revocations` revokes a certificate, by issuing CA (`client` or `bootstrap`) and
  serial and with every renewal of it; the Server refuses it and closes every session it admitted.
  `GET /api/v1/certificates` lists what the client CA signed. Every certificate the client CA
  signs now carries a random serial. A WebSocket session ends when its certificate expires. The
  list is kept in `config_dir/revocation/`. **What to do:** nothing; back that directory up with
  the rest of `config_dir`.
- **A CSR naming another Agent's `instance_uid` is refused**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). The Client of
  this project names none and is not affected.
- **`service config` asks the questionnaire of `install --interactive` again on an installed
  Client** — each question offers what `supervisor.toml` holds, only the asked keys change, and a
  host that holds no certificate yet is enrolled with the Server on the spot; nothing is
  registered. It takes the `--user`, `--root` and `--data-root` the Client was installed with
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  **What to do:** nothing; restart the service after it to apply the change.

### Changed

- **The development observability stack runs on the host, from `observability/`,** apart from
  the Dev Container, and keeps the fleet's own telemetry in ClickHouse and Apache Doris side by
  side. `config/server.toml` and the `server.toml` that `scripts/dev-pki.sh` writes carry the
  `[telemetry_offer]` that points at it, commented out, so a development fleet without the stack
  running does not report into nothing. **What to do:** start the stack with
  `docker compose -f observability/compose.yaml up -d`, then uncomment the section.
- **Breaking: a host fetches from the download route only the artifact offered to its own
  Agents** ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
  An uploaded artifact is served only to a certificate whose host speaks for an Agent that a
  rollout assigned it to — the Agents that reported with that certificate, or any Agent for a host
  marked as a Gateway. Everything else is answered `404`, exactly as an artifact the store does
  not hold, and recorded as `download.refused` with `check` `not offered`. A version saved in a
  Deployment but not yet rolled out can no longer be fetched by anyone. An Agent that reports
  another Agent type than its assigned Package's is no longer offered that Package. **What to do:**
  nothing where the Server signs certificates (`[client_ca]`). Without `[client_ca]`, give every
  hand-provisioned certificate the URI SAN `urn:opamp-fleet:host:<id>`; a certificate that names
  no host gets `404` for uploaded artifacts, and the Server says so at startup. Referenced
  artifacts are unaffected.
- **Breaking: the Agent plane admits by a client certificate alone, and the fleet credential is
  gone** ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md),
  [ADR-0014](docs/adr/0014-connection-settings-offered-without-a-credential-and-server-capabilities.md),
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md),
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md),
  [ADR-0022](docs/adr/0022-an-append-only-audit-record-chained-by-hash.md),
  [ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md),
  [ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
  The Server reads no `Authorization` header on `/v1/opamp` or the download route; one an older
  Client sends is ignored. It refuses to start with an `[auth]` section, and with
  `bearer_token_file`, `username`, `password_file`, `bearer_token` or `password` in
  `[connection_offer]`, naming each. The connection-settings offer carries no credential and no
  headers; `POST /api/v1/revocations` with `"credential"` is answered `400`, and a credential
  entry in the persisted revocation list is dropped on load; the audit record has no rotation
  events. The Client sends no `Authorization`, ignores a leftover `[auth]` in `supervisor.toml`
  with one warning at startup, refuses offered `headers` (reporting the offer `FAILED` by their
  keys), and drops an `Authorization` header persisted in `connection-settings.pb`.
  `service install --interactive`, the post-install text and the MSI ask for no credential. A
  Gateway forwards no `Authorization`, and its upstream connections carry any Agent.
  `server hash-credential --bearer` is gone; `--basic` stays. **What to do:** upgrade the Server
  first — a Server of an earlier version answers a Client of this version `401`. Before starting
  it, delete `[auth]` from `server.toml` and the credential keys from `[connection_offer]`,
  deleting the section if neither `heartbeat_interval_secs` nor `endpoint` is left. Then upgrade
  the Clients and Gateways. Delete `[auth]` from each `supervisor.toml` when convenient; every
  Client needs a client certificate.
- **A Gateway refuses a certificate the Server revoked, and admits nobody until its host is
  marked** ([ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md),
  [ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). A host
  marked as a Gateway fetches the revoked certificates of the client CA from
  `GET /v1/gateway/revocations` every 30 s and refuses them downstream with `401`, closing their
  sessions with `1008`. A Gateway with no list younger than 300 s answers every downstream peer
  `503`. **What to do:** upgrade the Server before its Gateways — an older Server has no list to
  hand out. Give each Gateway a certificate the Server issued, by enrolment or by a renewal, since
  only such a certificate names the host there is to mark; then mark that host with
  `PUT /api/v1/hosts/<host>/gateway` before the Gateway is upgraded. An unmarked Gateway admits
  nobody.
- **A package signature now covers the Agent type, the version and the SHA-256**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)), and a
  Supervisor refuses a package for another Agent type or older than the one it runs. **What to
  do:** sign every Deployment's entries again with `opamp-package-sign sign --agent-type <type>
  --version <version> <artifact>` and `PUT` the new signatures; signatures over the bytes alone no
  longer verify.

- **Client certificates live 30 days by default, not 90**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 9);
  a Client renews at two thirds of the life. **What to do:** nothing, unless a host is offline
  longer than about 20 days; then set `[client_ca] validity_days` higher.
- **A Client moves to an offered endpoint only when its own `[tls] ca_file` vouches for it**
  ([ADR-0014](docs/adr/0014-connection-settings-offered-without-a-credential-and-server-capabilities.md) clause 5). **What to
  do:** set `ca_file` on every Client before offering a new endpoint.

- **Every connection off the loopback is TLS 1.3, and plaintext elsewhere is refused at startup**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
  `ws://` and `http://` are accepted only to `127.0.0.1` or `::1` — not to `localhost`, not to a
  private address. That covers the Client's `endpoint`, a `[connection_offer] endpoint`
  ([ADR-0014](docs/adr/0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)), a
  referenced package `url`
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md))
  and an own-telemetry destination
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)). A
  peer that speaks only TLS 1.2 can no longer connect. **What to do:** move every such URL to
  `wss://` or `https://`, and put TLS 1.3 in front of any Collector or mirror that lacks it.
- **The Server requires `[tls]` and listens on the loopback by default.** Without `[tls]` it does
  not start; `listen` defaults to `127.0.0.1:4320`, and the Operator plane serves TLS too.
  `[rest] listen` off the loopback now requires `[rest.auth]`. **What to do:** add `[tls]`
  (`scripts/dev-pki.sh` makes a development set), set `listen = "0.0.0.0:4320"` to serve the
  fleet, and point clients of the REST API at `https://`.
- **The Client's default endpoint is `wss://127.0.0.1:4320/v1/opamp`**, and so is the MSI's
  prefill ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  **What to do:** a Client that relied on the old `ws://` default needs `[tls] ca_file` for the
  Server's certificate.
- **Nothing is installed without a signature**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md),
  [ADR-0018](docs/adr/0018-the-client-updates-itself-under-its-own-agent-type.md),
  [ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). A Client without
  `[packages] verification_key` takes no packages and no self-update. The Server offers no entry
  its Deployment has not signed, and refuses (`409`) to roll out a Deployment with an unsigned
  entry. A download goes only to the Server's own origin or to an https prefix in `[packages]
  allowed_sources`, every redirect hop included. **What to do:** set `verification_key` on every
  Client, sign every entry of every Deployment before rolling it out, and list any mirror in
  `allowed_sources`.
- **Every Agent is admitted by a client certificate, and a new host is approved by an operator**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md),
  [ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md),
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  The Server requires `[tls] client_ca_file`, and asks for the client certificate in
  the TLS handshake — the package download included. A fresh host enrols with a bootstrap
  certificate from `[enrolment] bootstrap_ca_file`, only while an operator holds the enrolment
  window open (`POST /api/v1/enrolment/window`), and only once an operator approves its request
  (`POST /api/v1/enrolments/<id>/approve`). Repeated admission failures from one address are
  answered `429` (`[admission_throttle]`). A Gateway requires `[gateway.tls]` with
  `client_ca_file`. The Client refuses to start without a client certificate.
  **What to do:** give the Server `client_ca_file`, `[client_ca]` and, to enrol hosts,
  `[enrolment]`; give every Client a certificate — an issued one, or a bootstrap certificate to
  enrol with — and every Gateway its client CA.
- **Connection caps:** `max_connections` (10 000) and `[rest] max_connections` (256) bound each
  plane; HTTP/2 is limited to 100 concurrent streams per connection and pings a silent peer away.
  **What to do:** raise `max_connections` for a larger fleet, together with the file-descriptor
  limit.

- **Deleting a Deployment that has released a package is refused** (`409`). Its Agents' offer
  travels with that Deployment's signatures, and deleting it used to leave them offered the
  package unsigned. Roll those Agents out through another Deployment, or delete the package,
  first; the refusal says how many Agents it concerns.
- **The Cargo packages are renamed:** `client` is `fleet-agent`, `server` is `fleet-server`,
  `fleet-common` is `fleet-core` and `package-tools` is `fleet-tools`, each in `crates/` under its
  new name. The programs keep theirs — `supervisor`, `server`, `opamp-package-fetch` and
  `opamp-package-sign`. **What to do:** nothing, unless you build by package — `cargo build -p
  client` becomes `-p fleet-agent`, `-p server` becomes `-p fleet-server`.
- **The Gateway's downstream endpoint and the Supervisor Endpoint bound connection setup** as the
  Server's two planes do: a peer has 30 seconds to send its request headers, and on a TLS Gateway
  10 seconds to complete the handshake
  ([ADR-0010](docs/adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)). A
  plaintext Gateway now drains for at most 35 seconds on shutdown, as a TLS one already did.
  **What to do:** nothing.

- **The operator tools are one program, `opamp-fleetctl`, and every release publishes it for Linux
  and macOS**
  ([ADR-0028](docs/adr/0028-one-operator-program-that-makes-the-fleets-certificates.md)).
  `opamp-fleetctl package` holds `fetch`, `pack`, `sha256`, `sign`, `keygen` and `public-key`,
  with the options and output they had; `opamp-fleetctl pki` holds the certificate commands
  above. A release now carries `opamp-fleetctl_<version>_<os>_<arch>.tar.gz` for `linux` and
  `darwin` on `amd64` and `arm64`, covered by `SHA256SUMS`; it is downloaded, not uploaded to a
  Server. **What to do:** every script that calls the old names breaks, with no alias:
  `opamp-package-fetch …` becomes `opamp-fleetctl package fetch …`, and
  `opamp-package-sign <command> …` becomes `opamp-fleetctl package <command> …`. Keys and
  signatures made before keep working. An upload loop over a release's assets selects `supervisor_<version>_*.tar.gz`,
  not `*_<version>_*.tar.gz`, or it puts an `opamp-fleetctl` archive into the `supervisor`
  Package.
- **Breaking: the self-update consent is `[packages] self_update`, and `[self_update]` fails
  startup** — the consent sits beside the `verification_key` that decides whether it takes effect,
  is `true` by default and `false` withdraws it. The package it takes is always the Client's own
  Agent type, `supervisor`; `[self_update] package` and `service install --self-update-package`
  are gone, and `--interactive` no longer asks about the self-update
  ([ADR-0018](docs/adr/0018-the-client-updates-itself-under-its-own-agent-type.md)).
  **What to do:** on every host, before this release reaches it, replace the
  `[self_update]` section of `supervisor.toml`: `enabled = false` becomes `self_update = false`
  under `[packages]`, and anything else is deleted. A host whose file still has the section does not
  start, and one that takes this release by self-update rolls back to the previous version. A
  reduced build can no longer be told apart by package name; withdraw the consent on its hosts.
- **The development `server.toml` serves the Agent plane on every interface** —
  `scripts/dev-pki.sh` now writes `listen = "0.0.0.0:4320"`, so a Client on another machine
  reaches a development Server. **What to do:** add the line at the top of an existing
  `.dev-pki/server.toml`, or delete `.dev-pki/` and run the script again.
- **`service install --interactive` enrols the host itself, and edits an existing
  `supervisor.toml` instead of keeping it** — the CA is asked for on every `wss://` or `https://`
  endpoint and copied beside the file as `server-ca.pem`. The bootstrap certificate and its key are
  asked for only while the host holds no issued certificate, are neither copied nor written into
  the file, and are used at once: the install sends the enrolment request, logs its key
  fingerprint and waits for an operator's approval before it registers the service. On a
  configured host every question offers what the file holds, and only the asked keys change
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  **What to do:** open the enrolment window before running `--interactive` on a new host, and
  approve the request it waits for. A file that names a bootstrap pair keeps it, and a service
  started on it enrols as before.

### Fixed

- **A Client offered its first own-telemetry destination over a running connection reports
  metrics at once**
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)).
  The sampler decided once per connection whether a destination was in force, so a Client that
  learned of one over the connection already open — a Server given `[telemetry_offer]` and
  restarted after the Client was up — sent logs and traces but no metrics until it next
  reconnected. It now checks at every sample. **What to do:** nothing; a Client restarted after the
  offer was not affected.
- **A new own-telemetry destination no longer holds up the Client's connection**
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)).
  Applying an offer shut the exporters it replaced down in place, and their flush to a destination
  that had gone silent held the OpAMP connection for up to the export timeout per signal. The
  replaced exporters are now detached at once and flushed on a thread of their own; only stopping
  the Client waits for them. **What to do:** nothing.
- **The Server shuts down gracefully on `SIGTERM`**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 13, [ADR-0024](docs/adr/0024-the-fleet-record.md) clause 5). It took only `SIGINT` (Ctrl-C) as a shutdown,
  so a service manager's stop, which sends `SIGTERM`, ended the process without draining the
  planes or saving the Agent records. Both signals now drain and save. **What to do:** nothing.
- **The Server writes its log to stderr**, as the manual says, and stdout carries only what a
  command prints as its result. **What to do:** a log collector that read the Server's stdout reads
  its stderr instead; under systemd both reach the journal unchanged.
- **A Server that shuts down closes its WebSocket sessions before it saves the fleet**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 13, [ADR-0024](docs/adr/0024-the-fleet-record.md) clause 5). The shutdown drain counted
  HTTP connections only, so an Agent's WebSocket session kept being served after the drain and
  after the Agent records were flushed, and ended without a close frame when the process exited.
  A shutdown now tells every session at once, with the close code `1001` (going away), cuts what is
  still open at the end of the drain, and only then saves the records. The Gateway's downstream
  endpoint closes its sessions the same way. **What to do:** nothing; Agents reconnect as before.
- **A re-keyed Agent takes its new identity, instead of leaving an empty record every heartbeat**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 7). When the Server
  gave a reporter a new `instance_uid` — an identity bound to another host's certificate, a
  duplicate on a second connection, or one the Agent asked for — it addressed the reply to the new
  identity rather than to the one the Agent had sent. The Client routes replies by that field, so
  it dropped the reply, never adopted the new identity, and reported under the old one again; each
  report was re-keyed once more. After a certificate was re-issued to a new host, this left a
  record with no type and no platform every heartbeat. The reply now names the identity the Agent
  sent. **What to do:** forget the empty records such a host left behind; its Agent is re-keyed
  once more and keeps the new identity.

- **A request body or a WebSocket message that stalls is cut off**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
  Once its headers had arrived, a peer could hold any connection of the Server, a Gateway or a
  Supervisor Endpoint by sending its body, or a WebSocket message, a byte at a time or not at all.
  Every body and message that has begun must now deliver 64 KiB within each minute: a body that
  falls behind is answered `408`, a message closes its connection with `1008`. Nothing has a
  deadline, so a large upload over a slow link still completes, and an idle connection is left
  alone. **What to do:** nothing.
- **An enrolment and a renewal each issue one certificate, not two**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). A
  Client that received its certificate sent the request it had just been answered for once more
  on its next connection, and the Server signed it again, so every host held a second valid
  certificate it never used. **What to do:** nothing; a duplicate already issued expires with its
  life, or can be revoked by its serial from `GET /api/v1/certificates`.
- **A certificate request goes out at once, with or without heartbeats.** A Client sent a new
  request only with its next heartbeat or poll, so an enrolment waited up to 30 s for its request
  to be listed, and a Client with `heartbeat_interval_secs = 0` on WebSocket never sent it. **What
  to do:** nothing.
- **The certificate register lists a key by the fingerprint its enrolment request carried.**
  `key_fingerprint` in `GET /api/v1/certificates` and in the audit record's issuance lines is now
  the SHA-256 of the public key, as the Client logs it and `GET /api/v1/enrolments` lists it, not
  of the key's SubjectPublicKeyInfo. **What to do:** nothing; certificates registered before keep
  the old value.

- **On Windows, a system-scope install no longer leaves its secrets readable by every local user.**
  Every folder under `%ProgramData%` grants `BUILTIN\Users` read access by inheritance, so
  `supervisor.toml`, the private key and the stored connection settings were readable by any
  account on the host. `service install` now removes the inherited rights
  from the data root and leaves it to LocalSystem, the Administrators and the service account
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clause 18). **What to do:** re-run `service install` on every Windows host, or apply the same
  with `icacls "%ProgramData%\<product>" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r
  *S-1-5-32-544:(OI)(CI)F` followed by a grant to the service account. Revoke the certificate of
  a host other people can log on to, and let it enrol again.
- **A configuration entry named only with dots (`.`, `...`) is stored** as the entry file `config`,
  as an empty name already was. It used to fail the whole configuration with an I/O error.
- **A package is no longer refused as one that "cannot be run" when another program starts at the
  same moment.** The check that runs a staged package before it replaces the running one, and the
  version probe, now wait out the moment Linux refuses to run a freshly written file, as a start
  already did.
- **`service install` keeps the state directory under the data root** — a configuration that
  names no absolute `state_dir` now gets `<data root>/state`, as
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)
  states; before, the install took `client-state` in the working directory of the shell it ran
  from, typically the operator's home directory. **What to do:** on a host installed that way,
  uninstall, delete that `client-state` directory and install again; the host enrols anew.

## [0.4.5] - 2026-08-24

### Changed

- **A package is now `(Agent type, version)`, and a new object — the **Deployment** — carries the
  aim, the signature and the rollout act** ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md),
  [ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). The free-form package name is
  gone; the Agent type is the identity and the name a package carries on the wire.

  **What you must do before starting the upgraded Server:**

  1. **Clear `<config_dir>/agents/`.** The Agent record format changed and there is no reader for
     the old one — the Server refuses to start and names the file. Every Agent re-enrols and
     re-reports on its next message; what is lost is the rollouts you had made, which step 3
     restores.
  2. **Clear `<packages_dir>/`** if it holds anything. There is no migration: the Server refuses to
     start on a directory in the old `<name>@<version>@<type>` layout rather than reading it as an
     empty store.
  3. **Re-upload, then put each package in a deployment and roll it out.** Nothing reaches a host
     until a deployment holds a package and its rollout is pressed.

  **The rule that changes how a rollout is aimed:** an Agent belongs to at most one Deployment, and
  a Deployment's Selector may never be empty. The fleet-wide-package-plus-narrower-canary shape is
  gone — a Selector is equality and cannot express "everyone except", so channels are a **partition**
  over an attribute every Agent carries (`channel = "stable"`, `region = "eu-central"`,
  `tenant = "acme"` — the key is yours, the Server prescribes none), set in the host's
  `[attributes]` or as
  a Server label. **There is no "roll out to everyone" any more**, and a host carrying no such value
  belongs to no deployment until it is labelled.

  **Route changes** (old → new):

  | before | now |
  |---|---|
  | `PUT /api/v1/packages/{name}/{type}/{version}` | `PUT /api/v1/packages/{agent_type}/{version}` — body `{}` |
  | `PUT …/{name}/{type}/{version}/entries/{os}/{arch}?signature=` | `PUT /api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}` — the signature moved (below) |
  | `PUT …/selector` | `PUT /api/v1/deployments/{name}` — body `{"selector": {…}}`, never empty |
  | `POST …/packages/…/rollout` | `POST /api/v1/deployments/{name}/rollout` |
  | `{"package": {…}}` in a per-Agent rollout | `{"deployment": "<name>"}` |
  | — | `PUT /api/v1/deployments/{name}/packages/{agent_type}/{version}` |
  | — | `PUT /api/v1/deployments/{name}/signatures/{agent_type}/{version}/{os}/{arch}` |

  **The signature moved to the Deployment**, because what an operator signs off on is a release to a
  set of machines. Passing one on the artifact upload is refused `400` naming the new route rather
  than ignored. A channel holding no signature offers the artifact unsigned; a Client with
  `[packages] verification_key` set refuses it on arrival, as it always has.

  **`[self_update] package` on the Client must be the Client's own Agent type** — `supervisor`, the
  default. There is no separate package name for it to differ from any more, so a value that is not
  the Agent type refuses every offer that Client will ever get, visibly on its fleet row.

  Addons are no longer offered: an Agent has one binary to replace and its Deployment holds one
  package for its type, so the Baseline's "normally only one top-level package" is structural here.
  No Client this project ships ever installed one.

## [0.4.4] - 2026-08-22

### Changed

- **`working_dir` and `reload_signal` are gone from every block.** A Managed Process now starts in
  the directory its program lives in — this Supervisor's `program/`, or the tree root — instead of
  inheriting whatever directory the service manager left the Client in, usually `/`. And whether a
  program re-reads its configuration on a signal is the program's own convention, which a kind
  holds: it is the one setting whose wrong value stays invisible, because a signal the process
  ignores looks exactly like an apply that worked. **What to do:** delete both lines. An agent
  under `command` now applies a configuration by restarting; if its in-place reload matters, it
  wants a kind of its own.

- **Timing is the fleet's policy, then the agent's correction of it.** `stop_timeout_secs` and
  `apply_grace_secs` join `retain_previous_secs` as fleet-wide settings, in a new `[supervisors]`
  section; a wrapped kind (when a build carries one) overrides them where its agent demands it,
  and only a block of an unwrapped kind may state its own. **What to do:** move a
  value you set on several blocks into `[supervisors]`; delete it from a wrapped block, where the
  kind now holds it.

  ```toml
  [supervisors]
  stop_timeout_secs = 10
  apply_grace_secs = 3
  ```

- **`[supervisor.attributes]` is gone.** Tagging one Agent among several on a host is a Server
  **label**: keyed by that Agent's `instance_uid`, matched by the same Selectors, set with one API
  call and effective at once. **What to do:** delete the table and
  `PUT /api/v1/agents/<uid>/labels` instead. The Client-wide `[attributes]` are unchanged — they
  describe the host, and every Agent on it still carries them.

### Added

- **A Client reports the Supervisor kinds it carries**, one non-identifying attribute per kind
  (`supervisor.kind.collector = "true"`), so a Supervisor set can be aimed with a Selector at the
  Clients that can actually run it — rather than a Server learning from a `FAILED` that it aimed at
  a Client too old to have the plugin.

- **The Client makes the directories a delivered agent writes into.** An agent the fleet installs
  arrives on a host nobody prepared, and some create nothing themselves. A kind now names those directories
  and the Client makes them **before every spawn**, owner-only, so an installation cannot end in a
  crash loop over a missing directory and one removed under a running fleet comes back on the next
  restart. **What to do:** nothing.

### Fixed

- **A Client that updates itself into a configuration it cannot read now rolls back.** The
  self-update's probation ([ADR-0018](docs/adr/0018-the-client-updates-itself-under-its-own-agent-type.md)) counts a failed start
  and returns the host to the previous version after three attempts — but it never saw this one: a
  run resolved its configuration *before* it resolved the update in flight, so a new version that
  refuses the file on this host exited before the attempt was counted. The service manager then
  restarted that version for ever, and the Server heard nothing, because the Client never reached
  it. The resolution now also runs on the failing path, finding the marker through `--state-dir`
  (which an installed service always passes) or the file's own `state_dir`. **What to do:** nothing.
  A host in that state today recovers as soon as it runs a version carrying this fix — and until
  then, the way out is to correct the file or to point `current` back by hand.

## [0.4.3] - 2026-08-21

### Added

- **An Agent reports its own traces.** The `own_traces` destination has been offered, persisted and
  exported to since 0.4.x, with nothing to export: no code created a span, and the bridge in force
  converts `tracing` events rather than spans. Five fleet operations are now traces
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)) — installing a
  package, applying a configuration (a Managed Process's, and the Supervisor set), applying offered
  connection settings, and the Client's own self-update — each with its phases as child spans and
  the outcome the Server is told as the span's status. A failed rollout is one trace naming the
  phase that failed, instead of a hunt through a day of log lines. A self-update stays **one** trace
  across its restart: the trace it belongs to rides in the update marker, so the commit or the
  rollback that a later process performs continues what an earlier one began.

  Two consequences worth knowing before an upgrade. **Exported log records now carry a `TraceId`**
  where they were written inside one of those operations, which is what makes the cross-signal join
  in the development stack answerable. And **stderr and the log file gain a span prefix** on those
  lines — `config.apply{hash=…}: supervisor set applied` — so anything parsing that output by
  column will see a shape it has not seen before. **What to do:** nothing. With no `own_traces`
  destination offered the spans are inert, and the transport's own message handling is deliberately
  *not* traced, so no fleet-wide volume appears where none was asked for.

### Changed

- **An Agent's own metrics now say what the Agent is and where it runs.** Every sample already
  carried the Agent's `service.instance.id` and the operator's name for it; it now also carries
  `service.name` — the Agent *type*
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)), which
  differs per Agent within one Client and therefore belongs on the sample rather than on the
  Resource — while the OTLP Resource carries `os.type`, `host.arch` and `os.description` beside
  what identifies the Client. A series can be read as "this Agent, of this type, on this platform"
  without a lookup elsewhere. Nothing else from the Agent description is sent: not the host's
  addresses, not the operator's own `[attributes]`. **What to do:** nothing — the attributes that
  were there are unchanged, these are additional.

- **The Client says what it is at startup, and what its TLS will use.** Two lines before any work:
  the running version, the configuration file, the state directory, the endpoint and the number of
  Supervisors — the version appeared in no log line until now, so a file a self-update left behind
  ([ADR-0018](docs/adr/0018-the-client-updates-itself-under-its-own-agent-type.md),
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)) could not be attributed to
  the version that wrote it — and then the trust and the client certificate actually in force,
  which is a Server-issued one no `supervisor.toml` mentions when there is one
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). A
  configuration file that is not there is now said out loud as well, because a mistyped `--config`
  otherwise starts cleanly on defaults and supervises nothing. **What to do:** nothing; anything
  parsing the log gains lines, and loses none.

- **More is visible at `debug` when an install or a Managed Process misbehaves.** A tree member left
  unpacked because it sits outside the program's own directory
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)) is now named, not only counted; the Collector
  Supervisor states which config-map entries it hands the Collector on every (re)start; and the
  `command` Supervisor states the fully expanded invocation of its Foreign Agent
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)) — its
  environment by variable name only, never by value. **What to do:** nothing, unless you are
  chasing one of those, in which case `RUST_LOG=debug` now answers it.

## [0.4.2] - 2026-08-21

### Added

- **`opamp-package-fetch` can fetch the Client itself** — `--agent supervisor` reads this project's
  own releases, verifies each `.tar.gz` against the `SHA256SUMS` the release publishes, and uploads
  the five platforms into one Set named and typed `supervisor`
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) is what made this
  possible: the Client's release is now an ordinary fleet package). It replaces the download,
  checksum and `curl` loop from the release notes, and it is the same tool and the same questions as
  for every other agent — with one difference at the end, since nothing supervises a Client: it
  prints the `[self_update] package = "supervisor"` consent rather than a `[[supervisor]]` block,
  and uploads no default configuration, because a Client's own configuration is its host's.
  **What to do:** nothing. The manual procedure still works.

### Changed

- **A `[telemetry_offer]` now says what an Agent reports — and can take a destination away**
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)). Own telemetry
  could be switched on and moved from the Server, and never switched off: a destination once in
  force survived reconnects and restarts, and every message that would have ended it was read as
  "unchanged". An offer that names any of the three signals is now the whole truth about own
  telemetry — a signal it leaves out is **stopped** rather than carried forward — and an endpoint set
  to the empty string is an explicit withdrawal, honoured and acknowledged like any other offer. An
  offer that says nothing about telemetry (an endpoint move, a credential rotation, a certificate)
  still leaves all three alone. **What to do:** if you offer fewer than three signals, check what
  your Agents are reporting before upgrading the Server — under the old reading an Agent could still
  be exporting a signal you removed from the file long ago, and after it that signal stops. To stop
  a fleet entirely, set the endpoints to `""`, restart the Server, and let the Agents acknowledge
  before removing the section: deleting it withdraws nothing, deliberately, so that a Server with no
  telemetry of its own cannot tear down a fleet another Server configured. This departs from the
  Baseline's own wording twice over and is recorded, with the reasoning, in
  [`CONFORMANCE.md`](docs/CONFORMANCE.md#deviations) — it follows the reference implementation
  rather than the schema comment, because the two disagree and only one of them can turn telemetry
  off.

- **Own telemetry now carries the operator's name for the Agent it came from.** `service.instance.name`
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)) is
  non-identifying, so it was filtered out of the OTLP Resource and every series arrived labelled with
  a `service.instance.id` uuid and nothing an operator could place against the fleet view they had
  searched by. The Resource now carries it beside the identifying attributes, and each process-metric
  data point carries the *sampled* Agent's uid and name — so a Supervisor's Managed Process is no
  longer labelled with the Client's identity. **What to do:** nothing on the Agent side. Dashboards
  and alerts keyed on `service.instance.id` keep working unchanged; queries can now group by
  `service.instance.name` instead.

- **The version an Agent reports *running* now decides which packages reach it, and the version its
  package status claims is no longer read beside it**
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)). A Set had to be greater than the lower of the
  two versions an Agent reports *and* never lower than the one its package status claimed. That
  second guard stranded hosts whose record was simply wrong: a Client whose `installed-package.json`
  named `supervisor 0.4.2` after a self-update that staged and did not take, while its program
  reported 0.4.0, was refused a rollout of 0.4.1 as a downgrade — for good. A package status is
  derived from what an install once wrote and outlives the binary it describes; `service.version` is
  the running program's own word. The running one now decides in both directions, and the claim is
  consulted only where no running version can be ordered. **What to do:** nothing, unless you run an
  Agent that reports a `service.version` numbered in a different space than the Set that carries it
  — which means the Client itself, or an OpAMP-aware Managed Process such as a Collector carrying
  `opampextension`; an Icinga 2 or GLPI Agent reports none and is unaffected. For those, a Set
  numbered *below* the program no longer reaches it at all, and one *between* the program's number
  and the claim can now move the package backwards. Number a Set the way the program it carries
  numbers itself and neither arises. A refusal names the version that decided and says whether the
  claim was consulted.

- **An Agent now accepts a cleartext OTLP destination anywhere in the private address space, not
  only on loopback.** `http://` was refused beyond the loopback interface, which meant a Collector
  one hop away on the LAN needed TLS and a certificate in front of it before any Agent would report
  to it. `http://` is now accepted to loopback and to `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16` and `fc00::/7`, and refused everywhere else — reported back with the reason, as
  before, never warned about and never downgraded
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)). The
  judgement is made on the **address**, so a cleartext *host name* is still refused whatever it
  resolves to: an admission test a later DNS change can flip is not one an offer can be trusted
  against. Link-local and carrier-grade NAT are private but not the operator's, and stay refused.
  Bracketed IPv6 loopback (`http://[::1]:4318/…`) was refused by a string comparison that could
  never match it, and now works as it was always documented to.
  **What to do:** a `[telemetry_offer]` may now name the Collector's LAN address directly — for
  example `metrics_endpoint = "http://192.168.10.5:4318/v1/metrics"` — and the TLS terminator put in
  front of it only to satisfy the old rule can go. Name it by address, not by name; a
  `http://collector.lan:4318/…` that worked nowhere before still works nowhere. Nothing already
  configured changes meaning: every destination accepted before is accepted now.

- **A fresh Client calls itself `Supervisor Agent`.** The top-level `name` — your name for *this*
  Client, reported as `service.instance.name` — defaulted to the program's own name, which since
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) reads exactly
  like the Agent *type* it sits beside in the fleet view. It is now a display name instead: spaces
  and capitals, because nothing resolves a path or a service from this key.
  **What to do:** nothing. A host whose configuration names this Client keeps that name; only a
  Client that never had one changes what it calls itself, and the questionnaire still asks for a
  name of yours first.

- **Release artifacts are `.tar.gz` and are named `supervisor_…`**
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  A release published `opamp-fleet-client_<version>_<os>_<arch>.7z`; it now publishes
  `supervisor_<version>_<os>_<arch>.tar.gz`, and the `.deb`, `.rpm` and `.msi` beside it take the
  same name. `.tar.gz` is what every other agent's package already ships as — the only container
  that carries the executable bit, unpacked the same way on every platform — and `supervisor` is the
  name of the Set these files become since
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md). The documented upload
  procedure was building its Set at `.../packages/opamp-fleet-client/opamp-fleet-client/...`, whose
  second field is the Agent type: since ADR-0019 no Client reports that type, so the Set fitted
  nobody and the release was publishing a package the fleet could not install.
  **What to do:** three things, and the second is the one that bites.
  1. Scripts that fetch release assets by name need the new name and extension. There is no
     transition window — the old name published a package that no longer installs.
  2. **A Client already in the field will refuse the renamed package** until its `client.toml`
     agrees. The self-update gate is the package name, so a host configured before ADR-0019 reports
     *"this Agent installs only the package "opamp-fleet-client"; the Server offered "supervisor""*
     and stays on its version — loud, harmless, and stuck. Fix it on the host before rolling out:
     set `package = "supervisor"` under `[self_update]`, or delete the section and take the default,
     which is now that same string.
  3. Nothing else moved. The binary, the service and its display name, the install layout, the dpkg
     and rpm package identity and the MSI's ProductName are all still `opamp-fleet-client`, so an
     `apt`, `dnf` or MSI upgrade across this release is an ordinary upgrade and not a second package
     beside the first.
- **A package Set now reaches an Agent only as an upgrade**
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md), amending
  [ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) and
  [ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)). What an Agent reports installed for a
  package is now part of matching, beside its type, its platform and the Selector: a Set reaches it
  only if the Set's version is **greater**, compared as SemVer. Equal does not count, and a
  reported version that cannot be ordered is refused rather than guessed at. Agents that report no
  package status at all are unaffected — they have nothing installed to be held against.
  **What to do:** stop using an older Set's rollout as the fleet-wide undo — it now answers
  `{"assigned_agents": 0}`, and the per-Agent act answers `409`. A bad version is taken back on the
  host (the health gate and `retain_previous_secs`, unchanged), or by publishing the old content as
  a new, greater version. Scripts reading `GET /api/v1/packages` get one new field beside
  `targeted_agents`: `matching_agents`, whom the Set aims at regardless of version.
  `targeted_agents` keeps its name and now counts only the Agents an act would actually upgrade —
  a `0` there with a non-zero `matching_agents` means the fleet is already up to date, not that
  the aim missed.

- **The program, the service and the configuration file are now called `supervisor`** — the binary
  `opamp-fleet-client` is `supervisor` (`supervisor.exe` on Windows), the service is `supervisor`
  (`supervisor-prod` for a named instance) on systemd, launchd and the SCM, the version directories
  are `supervisor-<version>-<hash>`, the `PATH` symlink is `/usr/bin/supervisor`, the log file is
  `supervisor.<date>.log`, and `client.toml` is **`supervisor.toml`**
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) and
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) on the two names). It completes what ADR-0019 began: one word from the
  Agent type in the fleet view down to the unit you restart. The top-level `name` default follows
  it; a host that set one of its own keeps it.

  **This release cannot be delivered by self-update, and that is not a bug.** A Client extracts its
  own program from an artifact *by name*, so a host on any earlier release asks for
  `opamp-fleet-client`, does not find it, and stays exactly where it is — loud, and harmless. There is no compatibility
  name: carrying both would re-create the two-names-for-one-file problem ADR-0019 removed.

  **What to do on every host**, in this order:

  1. Upgrade with the `.deb`, `.rpm` or MSI (or unpack the archive and run `service install` by
     hand). The Linux post-install retires the old registration for you — it stops and removes the
     `opamp-fleet-client` unit, the old `PATH` symlink and the orphaned version directories, because
     that unit runs a file the new layout no longer has.
  2. **Rename the configuration**: `mv /var/lib/opamp-fleet/client/default/client.toml
     /var/lib/opamp-fleet/client/default/supervisor.toml`. Nothing inside it changes. The installer
     deliberately does not do this for you — a host updated by hand would then be the one left
     without a configuration while the notes said otherwise.
  3. `supervisor service install && systemctl start supervisor`. The post-install skips the
     registration when it finds a configuration still carrying the old name, and prints these two
     commands.

  A host that is upgraded and not renamed **does not start**, by design: the Client refuses a
  missing `supervisor.toml` with a `client.toml` beside it, naming both paths, instead of coming up
  on the development default and managing nothing — which is the failure nobody would notice.

  What keeps its name: the install roots (`/opt/opamp-fleet/client/<instance>` and
  `/var/lib/opamp-fleet/client/<instance>`, so the instance identity and your credential survive),
  the dpkg/rpm package identity and the MSI ProductName (so this stays an upgrade rather than a
  second product beside the first), and the OTLP instrumentation scope.

- **The Client's own Agent now reports the type `supervisor`, and takes its own updates under that
  name** — it used to report and consent to `opamp-fleet-client`
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md), changing one value of
  [ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)). Two strings
  change, and they are the same string: the `service.name` every Client reports, and the default
  `[self_update] package` it consents to. The program, its service and its configuration file take
  the same name in this release — see *The program, the service and the configuration file are now
  called `supervisor`* below, which is the entry that tells you what to do on each host.
  **What to do** on the Server, once the hosts are on this version:

  1. Re-type anything on the Server that aims at the Client's own Agents: Selectors written as
     `service.name = "opamp-fleet-client"`, and Configurations carrying `[[supervisor]]` blocks
     (`"service_name": "supervisor"`).
  2. Publish the Set that carries the Client under the new name *and* type — upload the same
     artifact to `PUT /api/v1/packages/supervisor?version=…`, then
     `PUT /api/v1/packages/supervisor/type` with `{"service_name": "supervisor"}`. Nothing is
     repacked; only the Set's label changes.
  3. In the configuration you are renaming to `supervisor.toml` anyway, fix a package name spelled
     out under `[self_update]`: `package = "opamp-fleet-client"` now matches nothing and must become
     `package = "supervisor"`. Hosts that never wrote the section (the common case) need nothing.

  **Mind the order for the self-update itself:** the Set that delivers *this* version must still be
  named and typed `opamp-fleet-client`, since that is what a host reports and consents to while it
  is being offered; every later one is `supervisor`. Getting any of this wrong delivers nothing
  rather than the wrong thing — an Agent whose type does not fit is offered nothing, and a package
  whose name does not match is refused and reported — but a host in that state is one the fleet has
  quietly stopped updating.

- **The Client now consents to its own updates unless you say otherwise** — a behaviour change on
  hosts that are already installed
  ([ADR-0018](docs/adr/0018-the-client-updates-itself-under-its-own-agent-type.md), superseding
  [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) point 4). Until
  now an absent `[self_update]` section meant *no consent*, so a Client installed the documented way
  declared no package capability at all and the Server could never replace its binary — which made
  the Client the one program in the fleet left to patch by hand on every host. That is now the wrong
  way round: **an absent section is the consent**, narrowed to `package = "opamp-fleet-client"`, this
  Client's own Agent type. An offer under any other name is still refused and reported, and nothing
  is offered at all until an explicit rollout act assigns it
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)).
  **What to do:** if you want a host to keep managing its own Client binary, write this into its
  `client.toml` **before** upgrading — a host that has no `[self_update]` section today starts
  accepting self-update offers once it comes up on this version:

  ```toml
  [self_update]
  enabled = false
  ```

  Hosts that already name a package are unaffected. Every install path can now answer the question:
  `service install --no-self-update` and `--self-update-package <NAME>` for scripted installs, the
  `--interactive` questionnaire (which asks, defaulting to yes), and on Windows a checked-by-default
  checkbox on the MSI's endpoint page or `msiexec /qn … SELFUPDATE=0` for Intune and Group Policy.
  An empty `package` with the consent standing now fails at startup instead of widening the consent.
- **The installer writes its commented defaults above the sections, not below them.** A
  `supervisor.toml` written by `service install` listed `poll_interval_secs` and its neighbours as comments *after*
  `[auth]`, `[tls]` and `[self_update]` — so uncommenting one put a top-level key inside whichever
  section preceded it, and the Client then refused the whole file at startup. **What to do:**
  nothing; files already on disk are untouched, and the fix only affects newly written ones. If you
  hit this, move the uncommented key above the first `[section]`.
- **Both of the Server's listeners now hang up on a connection that never finishes its request**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)). A peer gets 30 seconds for
  its request line and headers and 10 seconds for the TLS handshake; until now it got forever,
  because hyper's own 30-second default is silently discarded while no timer is installed and
  neither axum nor axum-server installs one. The bound is on connection *setup* only: an established
  WebSocket session, a package download, and a package upload are all unaffected, whatever they take.
  Shutdown also drains both planes within ten seconds instead of dropping them (TLS) or waiting on
  every open Agent connection (plain). **What to do:** nothing — no configuration key changed. Only
  a client that needs more than 30 seconds to send its *headers* would notice, and none exists here.
- **A package is proved to run before it replaces what runs**, on every kind that has a way to ask.
  The *staged* program must pass a cheap check before anything is stopped, so a package that cannot
  run on the host is refused with the dynamic linker's own message
  (`version 'GLIBC_2.39' not found`) instead of costing a stop, a swap, a failed start and a
  rollback. The Collector uses its own `--version`; the `command` kind uses
  `version_args`, the arguments an operator has already declared safe to invoke the program with,
  and without that key it keeps no preflight at all. The health gate and rollback of
  [ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) are unchanged behind
  it. **What to do:** nothing, unless a program you supervise cannot answer the arguments you gave
  it — a Collector that does not respond to `--version` within five seconds, or a `command` whose
  `version_args` exit non-zero, now has its *packages* refused as well as reporting no version.
  Nothing that already runs is touched either way.
- **`opamp-package-fetch` names the systems each agent is published for**, in the agent menu
  itself, so a choice is no longer made blind — the Collectors by operating system (their
  architectures come from the release). **What to do:** nothing.
- **`opamp-package-fetch` offers release *series*.** The
  version question used to list the five newest tags, which for an agent that patches often was five
  patches of one line, so the
  one thing an operator looks for there — a version to go back to — was not in it. It now lists the
  **three newest `major.minor` series with the newest patch of each**.
  **What to do:** nothing. To
  fetch a version older than the three offered, pass `--version` directly; it is not restricted to
  the list.
- **A failing Agent no longer takes twenty rows of the fleet view.** The *Health* and
  *Configuration* columns printed the error under their red badge, and an error is a paragraph — a
  Supervisor's whole validation command line, a linker's complaint — so a single broken Agent grew
  its row until the rest of the fleet was off the screen. The badge now carries the finding alone
  and a click opens the reason in a dialog, the way the effective-configuration column already
  worked. **What to do:** nothing; no field of `GET /api/v1/agents` changed, and `health_error` and
  `remote_config_error` are still there for anything reading the API.
- **A Managed Process may be stopped as a process group.** A daemon that runs a worker of its own
  otherwise leaves that worker running when the bounded stop escalates to a kill.
  Opt-in per kind; the existing kinds are unaffected.
- **`opamp-package-fetch` uploads the agent's default configuration with the package.** A package
  alone leaves an Agent with nothing to run — the Supervisor holds at *awaiting configuration*
  until a Configuration of the name its block reads arrives — so an upload now stores that default
  too: the two Collector ones.
  The bodies are the ones in `config/examples/`, compiled into the tool.
  **What to do:** nothing. A Configuration the Server already holds is asked for first and **left
  untouched**, edits included, so a second upload changes nothing; and saving still distributes
  nothing ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)) — read the default over and
  roll it out yourself, since it carries example values.

- **The install path lost two levels, and `--instance` is gone.** The Client installed under
  `<base>/opamp-fleet/client/<instance>` — a product level, a component level asserting `client`
  where the program is called `supervisor`, and an instance level holding the constant `default` on
  every host anyone ever installed. It now installs under `<base>/<product>` alone:
  `/opt/opamp-fleet` and `/var/lib/opamp-fleet` on Linux, `%ProgramData%\opamp-fleet` on Windows,
  `/Library/Application Support/opamp-fleet` on macOS
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)). The product's name is
  fixed at build time (`OPAMP_FLEET_PRODUCT_NAME`, default `opamp-fleet`), and a second
  installation on one host is a **second build** rather than a runtime flag — the flag was
  reachable from no delivery path we ship, was read by nothing at runtime, and could not be
  recovered by anything once typed.
  **What to do:** nothing, on any host installed from a published release — there are none. The
  service is now called `opamp-fleet` rather than `supervisor`, so `systemctl start supervisor`
  becomes `systemctl start opamp-fleet`; `service uninstall|start|stop|status` take no name at all;
  and the `PATH` command is `opamp-fleet`. `--instance` is refused outright rather than ignored.

- **`service install` takes `--data-root`.** `--root` still names one directory and, given alone,
  still collapses the layout and the data into it. `--data-root` names the second half, which is
  what the Linux system-scope split needs — the executable layout under `/opt` because SELinux
  never lets systemd execute a binary labelled `var_lib_t`, the configuration and state under
  `/var/lib`.

- **The MSI puts the program in `Program Files` and everything else under `%ProgramData%`.**
  `INSTALLFOLDER` is now `C:\Program Files\opamp-fleet` and holds the delivered `supervisor.exe`
  and nothing more; the versioned layout, `supervisor.toml` and `state/` go to
  `%ProgramData%\opamp-fleet`. This is the Windows form of the line the `.deb` and `.rpm` already
  drew between `/usr/libexec` and `/opt`: the self-update rewrites the layout at runtime, and
  `Program Files` is not a tree a service account should be able to write — which it would have had
  to, since `--run-as` hands the layout to the account the service runs as. A host installed by the
  MSI and one unpacked from the archive now put the same things in the same places.

- **The `.deb`, `.rpm` and MSI are named after the product.** The package identity is `opamp-fleet`
  and the payload lands in `/usr/libexec/opamp-fleet/supervisor`, so two variant builds can be
  installed side by side without claiming one another's files.

### Removed

- **A `[[supervisor]]` block can no longer name a program on the machine.** `binary` and `command`
  take a bare file name and nothing else; an absolute path — and the Windows drive-relative form
  with it — is refused at startup with a message naming the way across
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)). A Managed Process is
  always one this Client installed, so every Supervisor now declares `AcceptsPackages` and the
  capability is a constant of the Client rather than something derived from a path.
  **What to do:** an agent the machine carries
  is brought under management by repacking it and uploading it as a
  Set. A block naming an
  absolute path will stop the Client at startup rather than starting without it.

### Fixed

- **A package behind an authenticated mirror could not be downloaded.** The Server has always passed
  a referenced Set entry's headers to the Agent verbatim — the credential an operator configures for
  a private source ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)) — and the Client
  dropped them, so the fetch came back `401` and the rollout failed with an opaque transport error.
  The headers now ride the `GET`, as the protocol asks. Because such a header is a credential given
  for *one* host, a download that carries any now follows its redirect chain itself and re-attaches
  them only while scheme, host and port are unchanged: HTTP clients strip only `Authorization`,
  `Cookie` and `Proxy-Authorization` across origins, so a custom token would otherwise have been
  handed to wherever a mirror redirected. Values are never logged, and a header that is not a valid
  HTTP header now fails the download naming its key.
  **What to do:** nothing, unless a referenced entry's download was failing — upgrade the Client and
  retry the rollout. Ordinary uploaded packages are unaffected; a CDN mirror that redirects to signed
  storage keeps working, since a download with no headers follows redirects exactly as before.

- **Own telemetry crashed its exporter thread instead of exporting.** The first export panicked with
  `there is no reactor running, must be called from the context of a Tokio 1.x runtime`, and the
  signal died with the thread. The SDK does not export on the async runtime: each batch processor
  and the metrics reader run on a **dedicated OS thread** and block on the export there, so the
  asynchronous HTTP client the exporters were given had no reactor to work with. That was true from
  the day own telemetry landed — it simply could not be reached until a destination was actually
  offered. The exporters now dispatch each request onto this process's runtime and await the
  result, so the socket work happens where the reactor is.
  **What to do:** nothing. If own telemetry appeared to do nothing before, it should now arrive —
  verified end to end against a local OTLP receiver: logs and metrics both, metrics on their 10 s
  interval, no panic.

- **Own telemetry stopped for good when a destination went silent.** Nothing on the export path
  bounded a request. The SDK's periodic reader documents that it enforces no export timeout and
  stops exporting new metrics if one never returns; the batch processors behind traces and logs
  block on their export the same way and then drop records once their queue fills; and
  `opentelemetry-otlp` applies the timeout it resolves only to an HTTP client it builds itself, not
  to the one this Client hands it. A destination that *refused* always recovered by itself, since
  OTLP/HTTP is a fresh request per interval and the next one simply succeeds. One that accepted the
  connection and then said nothing — a host asleep, a NAT that dropped its mapping, a network gone
  dark — held the exporter thread on a socket that never closed, and that signal stayed dead until
  the Client was restarted. An export now gives up after five seconds, half the reporting interval,
  in time for the next one to be tried on schedule.
  **What to do:** nothing. Telemetry that disappears during a network interruption now comes back by
  itself once the destination answers again. What the outage produced is still lost — there is no
  retry buffer, so expect a gap rather than a backfill.

- **A Server offering only telemetry destinations was ignored, and re-offered for ever.** With a
  `[telemetry_offer]` and no `[connection_offer]`, the Server sends a connection-settings message
  carrying no OpAMP settings — which is what the protocol asks it to do, and what its own test
  asserts. The Client required OpAMP settings to be present and dropped the message whole: no
  acknowledgement, so the Server's hash gate never closed and it re-sent the offer on every
  exchange, while own metrics, traces and logs never started. Such an offer is now applied in place
  and acknowledged, without a verification connection and without a reconnect — the protocol names
  three classes of destination with deliberately different sequences, and scopes its
  verify-by-connecting requirement to the OpAMP settings alone
  ([ADR-0014](docs/adr/0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)). A telemetry
  endpoint change no longer disconnects the fleet either.
  **What to do:** `[telemetry_offer]` alone is now enough; a `[connection_offer]` added only to work
  around this can be removed. A Server that can offer anything at all — settings, telemetry, or a
  `[client_ca]` — now declares `OffersConnectionSettings`, where before it declared the bit only for
  `[connection_offer]` and exercised the capability undeclared for the other two.

- **The Client kept reporting what a Server said it could not accept.** Capability negotiation is a
  MUST in both directions, and only two of the seven Server bits changed any behaviour here: package
  status went to Servers without `AcceptsPackagesStatus`, connection-settings status to Servers
  without `OffersConnectionSettings`. Both are now gated by one stated rule — optimistic until the
  Server has declared anything, binding once it has
  ([ADR-0014](docs/adr/0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)). A Server that
  has actually *sent* an offer still gets its acknowledgement whatever its bitmask says, because
  withholding it would leave that Server re-offering for ever. `remote_config_status` is
  deliberately never gated; the reasons are recorded at the code and in the conformance matrix so
  the non-gate is not mistaken for an omission.
  **What to do:** nothing against this project's Server, which declares what it exercises. This
  matters for third-party Servers (ADR-0011): one implementing only the two mandatory bits now sees
  a Client that respects that.

- **A refused own-telemetry destination was acknowledged as applied.** A destination the Client would
  not use — cleartext beyond loopback, or one carrying `tls`/`proxy` settings — was written to the
  log and the offer was still reported `APPLIED`, so the fleet showed telemetry flowing that was not.
  The refusal now reaches the Server as a `FAILED` status naming what was dropped, including one
  found at startup when persisted settings are put back in force. An offered client `certificate` is
  now honoured rather than ignored ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)):
  the exporter presents it, paired with the key this Client generated for its signing request. A
  `private_key` *in the offer* is refused by name — this Client's private key never leaves its host
  and is never accepted from the Server.
  **What to do:** check the fleet view after upgrading. A destination that was quietly refused will
  now show as `FAILED` with the reason; that is the gap becoming visible, not a new failure.

- **Own metrics were reported six times more slowly than the protocol recommends.** The Baseline's
  recommended reporting interval for own metrics is 10 seconds; this Client sampled every 30 s and
  left the OpenTelemetry SDK's periodic reader at its 60 s default, so a backend saw a value once a
  minute. Both are now 10 s, driven by one constant — exporting more often than sampling would only
  ship each value repeatedly.
  **What to do:** expect roughly six times the metric volume per Agent from a fleet that has an
  `own_metrics` destination offered. Traces and logs are unaffected; neither is on an interval.

- **Buffered spans and log records were lost on every stop.** The daemon returned without flushing
  its OTLP exporters, so the records explaining a shutdown — the ones that matter after a crash and
  restart — never left the host. Both exit paths now flush first.

- **Throttling and backoff follow the protocol.** A `503` or `429` on plain HTTP was treated as a
  generic error and the next poll went out on the ordinary interval; `Retry-After` is now waited out
  (30 s when the Server names no interval). A `413` no longer arms a full state report, which had
  made the *next* request larger than the one just refused. And the reconnect backoff now carries
  jitter, so a fleet coming back after a Server restart spreads over each interval instead of
  arriving on the same instants.
  **What to do:** nothing. A Server that never throttles sees no change.

- **An agent that claims a package version it is not running is offered that version again.** Until
  now the version an Agent reported *installed* for a package settled the matter, so a host whose
  record outlived its binary — a version switch that did not take effect, or an older Client
  reinstalled on top of the state directory — was held back for good: the fleet view showed
  `pkg: supervisor 0.4.1` on an agent reporting 0.4.0, and neither the rollout act nor the waiting
  list would offer it anything. A Set is now held against **both** versions an Agent reports
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)): it must be greater than the
  lower of the two, and never lower than the version the package status claims — so what a program
  says it is running can admit a package, and can never propose moving one backwards. The Client
  side matches: an offer for its own package is settled by the version this process runs rather than
  by a hash in its record, and a self-update is only reported as installed by the version that
  actually came up.
  **What to do:** upgrade the Server — this reaches the agents already out there without touching
  them. Expect an agent whose program numbers itself below its package (a Collector calling itself
  `0.98.0` under an `otelcol` Set at `2.0.0`) to appear as waiting for that Set; rolling it out
  re-installs bytes it already has, and the per-agent refusal now names both versions it read.

- **A Client is no longer offered the version it already runs — or an older one.** A Set reached
  Clients that were already running its version, and a Client running a newer development build was
  offered the older release — a downgrade of the program that manages the host. Both came from the same gap: since
  [ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md) a Set reaches an Agent only
  as an upgrade over what that Agent reports *installed*, and a Client that arrived by `.deb`,
  `.rpm`, MSI or by hand had installed no package, so it reported nothing and there was nothing to
  hold the Set against. A Client now reports the version it runs under the name `[self_update]`
  consents to, from its first report, whatever put the binary there.
  **What to do:** nothing — the fleet view simply gains a package line for every Client, reading
  `Installed` at the version that host runs. One behaviour changes with it: a hand-installed Client
  is no longer taken over by a package published at the version it already is; it comes under
  package management with the next release that is genuinely newer.

- **…and the Server catches the Clients that cannot report it.** The fix above only reaches a host
  once it runs this version — a Client already in the field will never report a package version,
  because the code that would report it is the code it does not have. So the Server now measures
  such an Agent by the version it reports *running*, its `service.version`
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md),
  amending [ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md) point 2). A
  version reported for the package itself still wins over it, and one nothing can order — a GLPI
  Agent's `1.19`, an appliance's `24.04.1` — says nothing rather than blocking, so no Agent becomes
  unreachable by numbering itself its own way.
  **What to do:** upgrade the Server and your existing fleet stops being proposed what it already
  runs. One door closes: a program that reports its version cannot be replaced by the fleet's
  package of that *same* version — publish the artifact under the next version to adopt it. Taking
  a host over from a machine-installed program is unaffected: that route declares no packages at
  all, and the fleet-owned form starts from an empty program directory.

## [0.3.2] - 2026-08-17

### Added

- **Basic authentication for the REST API and the UI**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). `[rest.auth.basic_users]`
  in `server.toml` — `user = "password"`, several allowed — guards the **whole** Operator plane:
  `/api/v1/…`, the OpenAPI document, `/api/v1/docs`, and the UI at `/`. A request without a matching
  credential is answered `401` with a `WWW-Authenticate: Basic` challenge, which is what makes a
  browser ask for the password, so the bundled UI needs no login page and no session. Absent, the
  plane stays open exactly as before — the loopback default of ADR-0013 is what protects it then.
  **What to do:** nothing, unless you publish that plane. If you do, add the section — and pair it
  with `[tls]` or a TLS-terminating proxy, since Basic sends the password on every request; the
  Server warns at startup if you have not. Existing tooling needs no new flag: the credential rides
  the URL (`curl -u user:pass …`, `--server http://user:pass@host:4321`). Two limits, stated
  plainly: everyone listed can do everything (authentication, not authorization), and passwords sit
  in `server.toml` verbatim, as `[auth]`'s already do. The Agent plane is untouched — Agents and
  package downloads carry no operator credential and never will.

### Changed

- **The REST API and the UI moved to their own port, on loopback**
  ([ADR-0013](docs/adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md),
  superseding the single-listener decision of
  [ADR-0010](docs/adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)). The Server now serves two planes,
  split by audience. The **Agent plane** keeps `listen` (`0.0.0.0:4320`): the OpAMP endpoint and the
  package download an offer's `download_url` points at. The **Operator plane** is new — `[rest]
  listen`, `127.0.0.1:4321` by default — and carries the REST API, the API docs, and the bundled UI.
  Nothing authenticates that plane yet ([`[auth]`](config/server.toml) guards the OpAMP endpoint and
  nothing else), so its reachability is its only protection, and it carries the authority to
  reconfigure and re-package the whole fleet: hence loopback. Authenticating it is now a decision
  about one listener instead of a per-path exemption on a shared one — which is the point of the
  move.
  **What to do:** change the address in every operator tool, script, and bookmark from
  `:4320/api/v1/…` to `:4321/api/v1/…`, and open the UI at `http://<server>:4321/`. To reach it from
  another host, either tunnel (`ssh -L 4321:127.0.0.1:4321 <server-host>`) or put
  `[rest]` / `listen = "0.0.0.0:4321"` in `server.toml` deliberately. **Clients need no change at
  all** — the endpoint, the offered `download_url`, and `advertised_url` all keep working as they
  are. The two addresses must differ; equal ones are refused at startup by name.

### Fixed

- **`opamp-package-fetch` says why an upload was refused, instead of "cannot reach".** The Server
  decides some uploads before it reads a byte of the artifact — an identity nobody created, a Set
  already rolled out and therefore immutable
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)), a package store at its ceiling
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). With hundreds of megabytes
  already in flight that answer races the upload, the connection resets, and what the tool could
  report was a transport error naming the one thing that was *not* the problem: the Server had
  answered, and said why. It now asks a second time with an empty artifact — refused in its own
  right, so the probe can store nothing — and reports the Server's status and message. Transport
  errors that are genuine read better too: the cause beneath `reqwest`'s own layer is printed
  rather than swallowed, on downloads as well as uploads.
  **What to do:** nothing. An upload that has been failing with `cannot reach …` will name its
  reason on the next run.

## [0.3.0] - 2026-08-15

### Changed

- **Publication is gone; a rollout is an explicit act, per Agent or per resource**
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)). Saving a Configuration or a
  package Set never distributes anything, and there is no draft/published state any more: what an
  Agent runs is its **assignment**, written only by a rollout act — `POST
  /api/v1/configurations/{name}/rollout` or `POST /api/v1/packages/{name}/{type}/{version}/rollout`
  for every currently matching Agent, or `POST /api/v1/agents/{uid}/rollout` for one. An act pins
  the content as of that press; later saves wait, visible per Agent in the fleet view
  (`pending_configurations`, `pending_packages`), as does an Agent that enrols or starts matching
  later. Selector edits and label moves no longer distribute either. Deleting a Configuration or
  a Set removes it from every assigned Agent. Package rollback is the same act pointed at the
  older version.
  **What to do:** replace every `PUT …/publication` call with the matching `POST …/rollout`;
  after adding hosts, press the resource's rollout (or the new host's) — nothing reaches them by
  itself any more. Existing stores migrate as "rolled out to what was published", so a running
  fleet is not changed by the upgrade. The `published`/`pending_changes` fields left the API.

### Added

- **A package artifact may be a `.zip`.**
  The
  Client now opens three containers, still decided by leading bytes: `.tar.gz`, `.7z`, and
  `.zip` — as a single-file package and as a tree (`program_path`), held to the same member
  rules as the others (no links, no paths climbing out, the same member and size bounds). Zip
  support is **read-only and unencrypted**: an encrypted member is refused with a message
  pointing at `.7z`, which is what `[packages] archive_key` opens. This exists so an upstream
  build published as a zip can be uploaded or
  referenced exactly as published, with upstream's own SHA-256 as the hash every Agent verifies.
  **What to do:** nothing, unless you relied on a `.zip` artifact being installed *as* the
  program. That was never useful — the agent would not start — but it did leave the file in
  place; such an artifact is now unpacked instead. Nothing else changes: `.tar.gz` stays the
  right container for a tree on Unix, being the one that carries file modes.
- **The operator tools moved to their own crate**
  ([ADR-0010](docs/adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)).
  `opamp-package-sign` and the new `opamp-package-fetch` are `crates/package-tools`, not binaries
  of the Client: the crate that runs on every managed host no longer carries tooling that never
  runs there. The binaries keep their names and their behaviour.
  **What to do:** nothing, unless you build them by crate — `cargo build -p client --bin
  opamp-package-sign` becomes `-p package-tools`. `cargo run --bin opamp-package-sign` is
  unchanged, because `--bin` resolves across the workspace. A release ships neither tool, as
  before.
- **`opamp-package-fetch`, an operator tool that fetches an upstream release and makes it a
  package.** It knows where the OpenTelemetry Collector (`otelcol`, `otelcol-contrib`)
  publishes, offers the last five versions and the platforms that release
  actually carries, verifies every download against the SHA-256 upstream published, and uploads
  each artifact as its platform's entry when told to. Interactive by default; `--agent`,
  `--version`, `--platform`, `--out-dir`, `--server` and `--no-upload` make it scriptable.
  Artifacts travel **as published** wherever upstream's container is one a Client can open, so
  the hash the fleet verifies is the one on the release page. See
  [the tools page](docs/manual/tools.md#package-fetch).
  **What to do:** nothing; it is a new tool beside `opamp-package-sign`, which still builds an
  artifact out of any program you have.
- **A `command` Supervisor can reload instead of restart**
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)). A `[[supervisor]]` block of
  `type = "command"` may set `reload_signal = "HUP"` (`"USR1"` and `"USR2"` are also accepted,
  with or without a `SIG` prefix): a configuration change is then applied by sending that signal,
  and the process keeps running with its in-flight state. If the signal cannot be delivered or
  the process dies on it, the Supervisor falls back to the restart, so the apply still lands.
  Linux/macOS only — on Windows a set key is refused at startup.
  **What to do:** nothing; the key is opt-in. Set it only for a program that genuinely re-reads
  its configuration on the signal.

### Changed

- **Removing a Supervisor now deletes its directory**
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)). When an applied Supervisor set
  removes a Supervisor, the Client stops it as before and then deletes
  `<supervisor_dir>/<name>/` whole — the Client-owned program, staged packages, written
  configuration entries, and the `instance-uid`. Re-adding the same name later starts a genuinely
  fresh Agent with a new identity; the Server keeps the old Agent's record as disconnected. A
  program named by an absolute path is the machine's file and stays untouched — only the state
  directory goes. A directory the Client cannot delete, or one orphaned by editing
  `client.toml` by hand while the Client was down, is reported in the log at startup and never
  deleted automatically.
  **What to do:** nothing before the upgrade. Be aware that removing a Supervisor from a Client
  is now destructive on that host — re-adding it restores service, not history.

- **The OpAMP Protocol Baseline moved to `v0.20.0`** ([PR #385](https://github.com/open-telemetry/opamp-spec/pull/385)).
  Upstream renamed the `AgentConfigFile` message to `AgentConfigObject` and clarified that an empty
  configuration-map key is always allowed. This is a **wire-compatible** change — the field numbers
  and the `config_map` shape are unchanged, so a Server and Client on either version interoperate,
  and this project already keyed the map by the Configuration name and never rejected an empty one.
  The vendored schema now lives at `crates/opamp/proto/v0.20.0/`, and the generated Rust type is
  `opamp::proto::AgentConfigObject`. See [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).
  **What to do:** nothing — no operator action, and nothing changes on the wire.

### Fixed

- **The Client stops its Managed Processes cleanly when it updates itself.** The self-update
  restart path exited without running the graceful shutdown ADR-0018 specifies, so the Managed
  Processes were left to the service manager. On systemd the unit's cgroup reaped them; on a manager
  that does not (launchd, the Windows SCM, a foreground or non-cgroup container run) they were
  orphaned, and the restarted Client spawned duplicates that fought over their ports. The self-update
  exit now stops the Managed Processes and sends the goodbyes first, on both transports, exactly as
  an ordinary shutdown does.
  **What to do:** nothing.

### Changed

- **A Managed Process's package updates no longer loop, and keep a fallback**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). Three changes to
  how a Supervisor applies a package (ADR-0026):
  - A **first** install that will not start is no longer discarded — the verified program is kept in
    place and reported `InstallFailed`. Previously it was removed, which emptied `program/` and set
    the Server re-offering the same artifact in a download-crash-rollback loop.
  - A program that **keeps failing to start** is held after a few attempts instead of being
    restarted forever (the give-up the Client's own self-update already uses). The Agent reports
    `not restarting: the program keeps failing to start`.
  - A **successful** update keeps the version it superseded for a window before deleting it, so an
    operator has a fallback. New `[updates] retain_previous_secs` (default one day), overridable per
    `[[supervisor]]` block with `retain_previous_secs`; `0` restores the old delete-on-success.

  **What to do:** nothing to keep working. If a rollout of a package that crashes on start had been
  looping, it now stops on its own; and a superseded version now occupies disk for up to a day per
  Supervisor — lower `retain_previous_secs`, globally or per block, on a host that cannot spare it.

## [0.2.6]

### Added

- **The fleet table shows each Agent's reported health.** A new *Health* column carries the
  Agent's own status string (e.g. `no process installed`) with the reported reason beneath it,
  so a Supervisor whose Managed Process will not start is visible at a glance instead of hiding
  behind a green *Connected* — which only ever said the connection is open. Agents that report
  no health show a neutral `—`. For API consumers, `GET /api/v1/agents` gains `health_error`
  (`ComponentHealth.last_error`) beside the existing `healthy` and `health_status`.
  **What to do:** nothing — the column and field appear on upgrade.

### Security

- **A Server-delivered `[[supervisor]]` block may name only a program the Client owns**
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
  A Configuration typed `opamp-fleet-client` that pushes a Supervisor set (ADR-0017) is now refused
  (`FAILED`, nothing stopped or written) if any block names its program by an **absolute path** —
  that would let the Server spawn a machine binary that never passed through package signing. A
  bare file name — the Client-owned, package-updatable case — is unaffected, as is an absolute-path
  Supervisor an operator writes in `client.toml` by hand.
  **What to do:** if you deliver a Supervisor set over the wire, name each program with a bare file
  name (delivered by package); machine binaries stay in the host's local `client.toml`.

- **The Server bounds how many Agent records it holds** — a new `max_agents` in `server.toml`
  (default 100 000). A report bearing a *new* `instance_uid` past the ceiling is answered
  `Unavailable` (retry later) instead of admitted, so a peer minting fresh self-asserted UIDs
  (ADR-0021) cannot exhaust memory and disk; Agents already known keep reporting.
  **What to do:** nothing for a normal fleet. A very large deployment can raise `max_agents`; the
  real defence against an anonymous flood is `[auth]` (ADR-0021), and this is the backstop while it
  is off.

- **The Server warns at startup when a credential-bearing offer runs without `[auth]`.** A
  `[connection_offer]` credential (ADR-0014) or `[telemetry_offer]` headers (ADR-0016) are handed
  to any Agent that connects; with the OpAMP endpoint open (no `[auth]`), that means any anonymous
  peer. The offer still works — this is a loud log line, not a refusal, so zero-config operation is
  unchanged.
  **What to do:** set `[auth]` to gate credential delivery, or accept the exposure knowingly.

- **Hardening, no operator action.** A Server-offered package whose name could escape the staging
  directory is refused (path traversal); `client.toml` keeps its `0600` mode when a Supervisor set
  is rewritten, so the OpAMP credential is not left world-readable; archive listing and member
  skipping are bounded against a decompression bomb; the certificate the Server issues to an Agent
  is forced to a client-auth leaf regardless of what the CSR requested (no CA certificate from a
  crafted request); and the bundled UI escapes `'` and `` ` `` so agent-reported strings cannot
  break out of an HTML attribute.

## [0.2.5] - 2026-08-12

### Changed

- **Saving a Configuration no longer distributes it** ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)).
  `PUT /api/v1/configurations/{name}` now stores a **draft**; releasing it is its own act,
  `PUT /api/v1/configurations/{name}/publication` with `{"published": true}`, and editing a
  published Configuration stages the change (`pending_changes: true`) until the next publication.
  In the bundled UI the button that used to read *Save & distribute* is now *Save*, and *Publish*
  is what changes the fleet. Retracting (`{"published": false}`) removes the entry from every
  composed config map, which matching Agents apply.
  **What to do:** Configurations stored before the upgrade load as published and stay in force —
  running fleets are untouched. Scripts that `PUT` a Configuration and expect delivery need the
  one extra publication call.

- **A configuration offered to the Client's own Agent now means something — its Supervisor set**
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)). A
  Configuration typed `opamp-fleet-client` carries `[[supervisor]]` blocks; a matching Client
  stops what left the set, writes the blocks into its own `client.toml` (preserving the
  operator's comments and everything outside them), and starts what arrived — unchanged
  Supervisors are not touched. Every other top-level key in the offered document is ignored: the
  endpoint, credentials, and state directory can never arrive over the wire. Previously the
  Client's Agent stored any offered configuration and reported `APPLIED` without doing anything.
  **What to do:** state whom your Configurations are for
  (`service_name`, [ADR-0023](docs/adr/0023-configurations-and-the-rest-api.md)). An
  *untyped* Configuration with a Selector the Client matches now reaches its Agent too, and a
  body that is not TOML `[[supervisor]]` blocks is reported `FAILED` instead of a hollow
  `APPLIED` — the fleet view shows the reason. Nothing changes for the Supervisors' own
  configurations, and a fleet that never publishes a `opamp-fleet-client`-typed Configuration
  keeps running its locally written blocks.

### Added

- **A Configuration can state the Agent type it is for**
  ([ADR-0023](docs/adr/0023-configurations-and-the-rest-api.md)). The optional
  `service_name` field is compared raw against the `service.name` an Agent reports, before the
  Selector; unset keeps today's meaning, every type. The bundled UI offers the types the fleet
  currently reports as suggestions.
  **What to do:** nothing — existing Configurations are untyped and match as before. Prefer the
  field over a `service.name` Selector pair when creating new ones.

## [0.2.4] - 2026-08-12

### Added

- **The Client's own configuration is visible in the fleet view.** The Client's own Agent now
  reports its `client.toml` as its effective configuration — previously the column stayed empty
  for every Client. Credential values (`[auth]`'s `bearer_token` and `password`, `[packages]`'s
  `archive_key`) are masked as `***` before the file leaves the host, since the Server persists
  what it receives. In the fleet table, clicking an Effective-config cell opens the whole
  configuration in a dialog.
  **What to do:** nothing. Note that the redacted file is now part of the Agent record the Server
  stores under `agents/`.

### Changed

- **The Linux service executes from `/opt`.** A default system install's executable layout —
  `versions/` and the `current` pointer — now lives at `/opt/opamp-fleet/client/<instance>`
  instead of under `/var/lib`, where SELinux-enforcing hosts (Fedora, RHEL, SUSE 16) never let
  systemd start it (`status=203/EXEC`); `client.toml` and `state/` stay at
  `/var/lib/opamp-fleet/client/<instance>`, and `--root` still puts everything under the one
  directory it names ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  **What to do:** nothing on a packaged (`.deb`/`.rpm`) host — the upgrade re-registers the unit
  against `/opt`, restarts the service if it was running, moves no data, and cleans the orphaned
  binaries out of `/var/lib`. A *manual* Linux system install (`.7z`, no `--root`) should re-run
  `opamp-fleet-client service install` once after the update, then delete the leftover
  `versions/` and `current` under `/var/lib/opamp-fleet/client/<instance>`.

## [0.2.3] - 2026-08-12

### Added

- **The fleet survives a Server restart.** Agent records now persist — one JSON file per Agent
  under `<config_dir>/agents/`, behind a storage port a database or external store can replace
  ([ADR-0024](docs/adr/0024-the-fleet-record.md)). After a restart
  every Agent the Server knew keeps its row, its last-reported build, health, and configuration
  state, shown as disconnected until it reports again; a reconnecting Agent's compressed heartbeat
  is accepted without a fleet-wide `ReportFullState`, and a queued restart survives. Only
  connectedness stays runtime-only — it is derived from live evidence, never restored. A heartbeat
  writes nothing to disk; a graceful stop (Ctrl-C/SIGINT) flushes current timestamps.
  **What to do:** nothing. Note that forgetting an Agent (`DELETE /api/v1/agents/{uid}`) is now
  also what frees its stored record, and that reported effective configurations — which may embed
  credentials — now persist under the owner-only `agents/` directory.

### Changed

- **A package is now a versioned Set, and the package API changed shape for it.** A Set is
  identified by *name, Agent type, and version* — stated at creation, never edited; it may define
  a Selector, holds one entry per platform (an upload, or a source URL + sha256, optionally
  signed), and **saving never distributes**: every Set is a draft until
  `PUT …/publication` releases it, and a published Set's entries are immutable
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). Among Sets of one name the most
  specific Selector wins and, at equal specificity, the greater version — so a canary ring is one
  Selector edit, and a rollback is retracting the newest version (the hidden one-step history of
  ADR-0026 is gone; old `previous` artifacts migrate to unpublished Sets of their version). The
  routes moved to `/api/v1/packages/{name}/{agent_type}/{version}` with `…/entries/{os}/{arch}`
  beneath; `…/type` and `…/rollback` are gone. The Packages tab is now a master–detail view: a
  table of Sets, a detail form for the selected one (Create/OK/Cancel/Delete, publish as its own
  button), hidden while nothing is selected.
  **What to do:** rewrite any script against the old package routes (see `config/server.toml` and
  the release notes for the new upload loop). The store migrates itself at first start — one Set
  per stored variant version — **except** a package that never got an Agent type: the Server
  refuses to start and names the file; delete it or re-create it as a Set.

- **The web UI is three tabs, and an Agent's details unfold on selection.** Agents, Packages, and
  Configurations each manage from their own tab; the active tab lives in the URL hash
  (`#packages`), so a reload — or a link handed to a colleague — comes back to it, and each tab
  carries its count. The fleet table shows one line per Agent (columns now: Name, Version,
  Operating System, Network, Configuration, Matched configs, Effective config, Seq, Last seen,
  Status); pressing a row makes that Agent the current one and unfolds its attribute chips,
  capabilities, and per-Agent actions beneath it. A Disconnected Agent now reads soft red instead
  of gray, and its badge carries a ✕ that forgets the Agent in place (ADR-0024) — the forget chip
  in the details stays, since an Agent behind a Gateway reads Connected however dead its host is.
  No operator action required.

## [0.2.2] - 2026-08-11

### Added

- **Agents report the host's network addresses, CPU model, and OS build.** Every Agent a Client
  presents now carries the OpenTelemetry `host.ip` and `host.mac` attributes — loopback excluded,
  deduplicated, IPv6 in RFC 5952 form, MACs hyphen-separated uppercase — plus
  `host.cpu.model.name` and, where the platform stamps one, `os.build_id`. The fleet table gains a
  **Network** column — the first address of each kind at a glance, the full lists in the tooltip
  and the attribute chips — and everything stays searchable like any other reported attribute
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)). Addresses are re-read on
  each description, so a DHCP move shows up. No operator action required; note that host addresses
  are now visible to anyone who can read the fleet API.

### Changed

- **The Linux packages put a symlink on `PATH`, and removing them uninstalls every staged
  version.** The `.deb` and `.rpm` now deliver the binary to `/usr/libexec/opamp-fleet-client`;
  `/usr/bin/opamp-fleet-client` becomes a symlink through the install layout's `current` pointer
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)), so
  `opamp-fleet-client --version` — and every other CLI call — answers for the binary the service
  actually runs, even after a fleet self-update or a hand-reinstalled older package. A real removal
  (`apt remove`, `dnf remove`) now also deletes the staged `versions/` and the `current` pointer,
  so a later install comes up on its own binary instead of a surviving newer one; the state
  directory and `client.toml` stay. `apt purge` deletes those too — the instance directory whole.
  **What to do:** nothing on upgrade — the package lays the link itself. Only automation that
  depended on the *delivered* file sitting at `/usr/bin/opamp-fleet-client` must switch to
  `/usr/libexec/opamp-fleet-client`.

- **The MSI's endpoint page comes prefilled with the development default**
  (`http://localhost:4320/v1/opamp`) instead of empty, so a local evaluation install is a
  click-through (ADR-0019). Interactive installs only: clearing the field still means "configure
  later", a value passed as `ENDPOINT=` on the `msiexec` command line still wins, and a silent
  install (`/qn`) without one still writes no configuration — unattended deployments are
  unaffected.

### Fixed

- **The Windows MSI installs.** Every install from the `.msi` failed at the end of the progress
  bar with "A program run as part of the setup did not finish as expected" (error 1722) and rolled
  back. The custom action running `service install` quoted `[INSTALLFOLDER]` directly, and a
  directory property always resolves with a trailing backslash — which the C runtime reads as
  escaping the closing quote, so the root argument swallowed the rest of the command line and the
  install staged into an impossible path. The failed installs rolled back cleanly and left nothing
  behind; no cleanup is needed — install this version's `.msi`.

## [0.2.1] - 2026-08-11

### Fixed

- **The package-source probe can no longer be aimed at internal addresses (SSRF).** `PUT
  /api/v1/packages/{name}/source` probes the operator-supplied URL once; that URL and its headers
  are entirely caller-supplied, so the probe could be pointed at the cloud metadata endpoint
  (`169.254.169.254`) or other internal services and the answer reflected back. The probe now
  refuses a URL that resolves to a link-local, shared/CGNAT, or other never-routable address, and it
  no longer follows redirects (which could bounce a public URL onto such an address). Loopback and
  RFC 1918 / unique-local addresses stay reachable on purpose — an operator's mirror (ADR-0026)
  legitimately lives on an internal network. No operator action required unless a source URL
  deliberately used a link-local or CGNAT host.

- **The body-less state-changing `POST` routes reject cross-site browser requests (CSRF).**
  `POST …/restart` and `POST …/rollback` are CORS "simple requests" a cross-origin page could fire
  at a logged-in operator's browser without a preflight. They now require Fetch Metadata to mark the
  request same-origin — a browser stamps `Sec-Fetch-Site` and forbids page scripts from forging it,
  so a cross-site call is refused with `403`. Non-browser clients (`curl`, a portal) send no such
  header and are unaffected; no API client or token changes. This is not operator authentication,
  which remains a separate decision (ADR-0021).

- **The package store has a whole-store size ceiling.** The upload route bounded a single artifact
  by `max_package_size_bytes` but nothing bounded the *store*, so a caller could fill the disk by
  uploading artifact after artifact under distinct names. Uploads are now also refused (`507`) once
  the stored artifacts reach the new `max_total_package_bytes` (default 16 GiB). **What to do:**
  nothing, unless a fleet's package set legitimately exceeds 16 GiB — then raise
  `max_total_package_bytes` in `server.toml`.

- **A Gateway now serves its downstream hop over TLS, and `[gateway.tls] client_ca_file` gates who
  may connect.** The `[gateway.tls]` section ([ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md),
  [ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)) was read and
  then ignored: the endpoint stayed plaintext and the client CA verified nobody, so the downstream
  `Authorization` credential travelled in the clear and any peer could connect and report under any
  `instance_uid`. The section now takes effect — the Gateway presents its `cert_file`/`key_file`, and
  when `client_ca_file` is set a downstream Agent **must** present a certificate that chains to it or
  the handshake is refused. **What to do:** an operator relying on that section for security must
  confirm downstream Agents now dial `wss://`/`https://` and, if a client CA is configured, carry a
  client certificate — connections that worked only because the boundary was silently off will now
  fail. A Gateway left without a `[gateway.tls]` section still serves plaintext, and now logs a
  warning saying so.

- **A Server-offered self-update version can no longer escape the install layout.** The offered
  version string becomes a directory name under `versions/` (ADR-0019); a crafted value carrying
  `..` or a path separator (e.g. `1.0.0+../../../…`) could place the staged binary outside the layout
  and repoint `current` at it — an escape the package hash and signature never covered, because they
  sign the bytes, not the destination. The version is now validated before it names a path, and the
  staged directory is asserted to stay directly under `versions/`. No operator action required.

- **The Server-rotated connection credential is no longer left world-readable.** The
  `connection-settings.pb` in the state directory holds the `Authorization` value the Server rotates
  in (ADR-0014), which outranks the one in `client.toml`. It was written at the umask default
  (typically `0644`), so on a multi-user host any local user could read the live fleet credential.
  It is now written `0600` and its state directory `0700`. No operator action required.

- **The enrolment private key is written owner-only from the start.** `client-key.pem` (ADR-0021)
  was created at the umask default and narrowed to `0600` only afterwards, leaving a brief window in
  which another local user could read it. The mode is now set in the open call, closing the window.
  No operator action required.

- **A referenced package's private-source token is stored owner-only on the Server.** A referenced
  source (ADR-0026) can carry headers — a bearer token for a private artifact host — that were
  persisted in the package store at the umask default, readable by other local users on the Server
  host. The store directory is now `0700` and its metadata files `0600`. The token remains, by
  design, cleartext at rest and delivered to every targeted Agent; the API and store docs now say so.
  **What to do:** prefer a narrowly-scoped, rotatable token for a private source.

- **The Client's OpAMP endpoint no longer follows HTTP redirects; artifact downloads follow a bounded
  chain.** The OpAMP endpoint is a fixed, operator-configured address, so its HTTP transport and the
  connection-settings probe now refuse redirects — a redirect there could only bounce an
  authenticated session elsewhere. Artifact downloads still follow redirects (a mirror is often a CDN
  that bounces to signed storage, ADR-0026) but are now bounded to a short chain; integrity still
  rests on the content hash and signature, never on where the bytes came from. No operator action
  required unless an OpAMP endpoint was, unusually, served behind an HTTP redirect.

- **The Agent's state and configuration directories are kept owner-only.** The persisted state
  directory and the `config/` directory the Managed Process reads from were created at the umask
  default, and a config-map entry read by path (a `${file:...}` reference, ADR-0023) can be a
  certificate or a key — so on a multi-user host that material was world-readable. The directories
  are now `0700` and the stored configuration protobuf and each entry file `0600`; the Managed
  Process runs as the same user and still reads its own config. No operator action required.

- **The artifact staging directory is kept owner-only.** A downloaded artifact is verified and then
  re-opened by the installer; the staging directory was created at the umask default, so on a
  multi-user host another local user could swap the file in that window and defeat the hash and
  signature check it had already passed (TOCTOU). The directory (`packages/` under the Agent's state
  or supervisor directory) is now `0700`. No operator action required.

- **A Client that installs packages without a verification key now says so at startup.** Package
  signing is opt-in (ADR-0026): with no `[packages] verification_key`, an offered package or
  self-update is accepted on the Server-supplied content hash alone, with no signature binding the
  bytes to a key the operator holds. That is unchanged — but a Client that accepts packages (a
  managed process's, or its own self-update) without a key now logs a warning at startup, so the
  weaker posture is a knowing choice rather than a silent default. **What to do:** to require an
  Ed25519 signature, set `[packages] verification_key` (see `opamp-package-sign`); otherwise nothing.

- **A package or self-update download now has a size ceiling.** The artifact was streamed to disk
  with no bound, so a malicious or compromised Server could answer the download with an endless body
  and fill the staging filesystem before the content hash — checked only once the whole stream lands
  — could reject it. The download is now capped at the new `max_artifact_size_bytes` (default one
  gibibyte, matching the Server's own per-package limit), enforced against an over-large
  `Content-Length` up front and while a chunked body streams in. **What to do:** nothing, unless a
  fleet distributes artifacts larger than 1 GiB — then raise `max_artifact_size_bytes` in
  `client.toml`.

- **A self-update can no longer be talked into a downgrade.** The install decision was "is the
  offered version different from the running one", so a compromised Server could offer an older,
  still-validly-signed release with a known vulnerability and the Client would install it — the
  Ed25519 signature is over the artifact bytes only and carries no version ordering. The Client now
  refuses an offer whose version has lower SemVer precedence than the one running; a rebuild of the
  same release and any newer version still install, and rollback to the *previous* version stays the
  crash-loop mechanism it always was. No operator action required.

- **A single downstream Gateway connection can no longer grow the routing state without bound.** For
  every distinct `instance_uid` a downstream peer reported, the Gateway grew its per-connection,
  registry, and pool maps; one hostile or buggy peer streaming endless fabricated `instance_uid`s
  was an unbounded-memory denial of service. A connection is now capped at the new
  `[gateway] max_carried_agents` (default 10000): past it a report for a *new* Agent is dropped while
  the Agents already carried keep being served. **What to do:** nothing, unless a single nested
  Gateway carries more than 10000 Agents on one connection — then raise `max_carried_agents`.

- **The WebSocket transport marks the `Authorization` header sensitive.** The HTTP transport already
  flagged the credential so it is redacted from any debug formatting of the request; the WebSocket
  path did not, so the value could surface in a log line. It now matches. No operator action
  required.

## [0.2.0] - 2026-08-10

### Added

- **A release now ships native installers: `.deb`, `.rpm` and `.msi`**
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)). They sit *beside* the five `.7z`
  archives, which are unchanged and are still the artifact a Server offers for a Client self-update —
  the Client cannot open a `.deb`. Which to take: the installer to put the Client on a host, the
  archive to update a fleet.

  Each installer delivers the binary and then runs `opamp-fleet-client service install` itself, so
  the layout, the systemd unit and the SCM entry are the ones the Client has always made. No package
  ships a unit file of its own.

  Two behaviours to expect, both deliberate:

  - **`apt install` leaves the service registered and stopped.** This departs from the usual Debian
    enable-and-start. A Client with no configuration dials the development default and manages
    nothing, and a package must not manufacture that state on every host it touches. The post-install
    prints the two remaining steps: `service install --endpoint …`, then `systemctl start`.
  - **After a fleet self-update, `dpkg -l` reports the version the *package* delivered, not the one
    running.** The service runs the binary under `<root>/current/`, which no package manager owns —
    which is exactly what keeps the next `apt upgrade` from reverting a Server-driven update.
    `opamp-fleet-client --version` and the fleet view are the truth.

  The `.msi` asks for the installation folder and the Server endpoint, and takes the same two as
  properties for an unattended install:
  `msiexec /i … /qn INSTALLFOLDER="…" ENDPOINT="wss://…/v1/opamp"`. Nothing is signed yet, so Windows
  shows an unknown publisher and `rpm` reports no signature. macOS keeps the archive only.

- **`service install --endpoint <url>`** writes the first configuration file without asking
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).
  It is what the installers above use, and what a provisioning run that has an endpoint but no
  terminal needs — `--interactive` is an error without one, on purpose. It writes the same file, is
  mutually exclusive with `--interactive`, and keeps an existing configuration rather than
  overwriting it. It takes **no** credential: a flag would stand in the shell history and the process
  list, which is why `--interactive` hides that prompt in the first place.

### Fixed

- **A Gateway now says why it hung up on an oversized message.** The Baseline answers a message past
  the size limit with a WebSocket close of `1009 Message Too Big`, and
  [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) claims it as implemented. The Server's endpoint did
  it; the Gateway's dropped the connection with no status at all, so a downstream Client saw a reset
  socket and could not tell an oversized report from a Gateway that had died — and retried into the
  same wall. An oversized frame is also a close now rather than a message quietly dropped while the
  socket read on.

- **A Gateway now accepts a gzipped report.** Accepting `Content-Encoding: gzip` is a Baseline MUST
  for anything serving OpAMP, and a Client in Gateway Mode
  ([ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)) *is* an OpAMP server to the Agents behind it. The
  Server's endpoint implemented the rule; the Gateway's did not, and handed the compressed bytes
  straight to the protobuf decoder — so an Agent that compressed its reports worked against the
  Server and was answered `400 unreadable report` the moment a Gateway was put in front of it.

  The size limit applies **after** decompression, which is the other half of that MUST: a few
  kilobytes of gzip must not buy the hop gigabytes of memory. A body that decompresses past
  `max_message_size_bytes` is refused with `413`, and decompression stops at the limit rather than
  running to completion first.

  Both endpoints now read one implementation of the rule
  ([ADR-0010](docs/adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)). Nothing to change on any host — an
  affected Agent works through a Gateway as soon as it runs this version.

- **`server --version` now names the build it is, not the release it is heading for.** It printed the
  bare number from `Cargo.toml` — `server 0.1.3` — where the Client on the same commit reported
  `0.1.3-dev+ade2775`. So a Server binary could not be told apart from the release it was on its way
  to, and named no commit; two binaries of one workspace disagreed about their own version.

  Both ends now read the same helper, `opamp::version::current()`, which
  [ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md) always required and the Server had
  opted out of ([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)). A
  development build reports `0.2.0-dev+<commit>` and a released one `0.2.0+<commit>`.

  **Anything matching the Server's `--version` output exactly has to be relaxed** — a check for
  `server 0.2.0` no longer matches a development build. Nothing else changes: the Client's string is
  what it always was, and no Agent, configuration or stored file is touched.

- **The fleet view shows an Agent's Instance UID again.** It had been the line under the agent name
  until [ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md) gave a
  row both the operator's name for an Agent and the type it reports, and the UID moved into the name
  link's tooltip — where nothing on a printed, screenshotted or scrolled-past row carried it. It is a
  third line in the name cell now, below the type, and one click selects the whole of it.

  That UID is what every REST call names an Agent by (`/api/v1/agents/{instance_uid}/…`), so reading
  a row in order to act on it needed the value in front of you rather than under the pointer. Nothing
  else changed: the fleet filter already searched the UID, and the row actions already carried it.

## [0.1.3] - 2026-08-09

### Changed

- **Delete in the package form removes one artifact, not the whole package.** It deletes the
  platform named in the form — the artifact the selected chip stands for — and leaves the other
  platforms of that name alone. Before, one press on a form filled from a `linux-amd64` chip took
  the `darwin-arm64` and `windows-amd64` builds with it.

  The package itself goes when its last artifact does, so nothing is left behind either. Deleting
  uninstalls nothing: an Agent keeps running what it took, exactly as retracting does
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)).

  `DELETE /api/v1/packages/{name}` is unchanged and still deletes the whole package; the form now
  sends the `?os=…&arch=…` form of it that
  [ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) added.

### Removed

- **The ↩ Roll back button is gone from the package form.** The store still remembers the version
  each artifact replaced ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)) and
  `POST /api/v1/packages/{name}/rollback?os=…&arch=…` still puts it back — only the button is
  removed. The package list still shows `0.157.0 ← 0.156.0`, so what "back" would be is still on
  screen; asking for it is now a request rather than a press.

## [0.1.2] - 2026-08-09

### Added

- **The Server can label an Agent** ([ADR-0024](docs/adr/0024-the-fleet-record.md)).
  `PUT /api/v1/agents/{instance_uid}/labels` sets key/value pairs that join what a Selector matches,
  and the bundled UI has a `🏷 labels…` action on every fleet row.

  This removes the last per-host wiring. The attribute a staged rollout wants — `rollout = "canary"`
  — could only live in `[attributes]` in `client.toml`, so moving a host between rings meant editing
  a file on that host and restarting it. Now it is one API call, and it aims **both** halves of the
  targeting: the Configuration an Agent is sent and the package it is offered. A canary rollout of a
  new binary is a Selector of `rollout = canary` on the package plus a label on the hosts that should
  get it first.

  It takes effect immediately — a connected Agent is pushed what its new ring gets.

  **A label may not restate an attribute the Agent reports**; that is refused with `409`, naming the
  key. `os.type` and `host.arch` decide which artifact fits a machine and `service.name` decides
  which packages fit it at all, so a label that could outrank them would let a slip offer a host a
  binary built for another one. Fix a wrong reported value where it comes from, in that host's
  `client.toml`.

  Labels never travel to the Agent, are stored on the Server, and survive a restart. **Forgetting an
  Agent does not clear them**, so a host that comes back is in the ring it was put in; clearing them
  is its own call with an empty map. They are keyed by Instance UID, so an Agent the Server re-keys
  starts with none.

### Changed

- **A package is published before it is offered — uploading only stages it**
  ([ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)). A newly created
  package is a **draft**: its artifact is stored, its type and Selector can be set, and it reaches
  no Agent until it is released.

  ```console
  $ curl -X PUT -H 'Content-Type: application/json' -d '{"published": true}' \
         http://<server>:4320/api/v1/packages/otelcol/publication
  ```

  Uploading used to *be* the rollout: the next Agent that fitted took the artifact, even while the
  package was still half described. Five platforms' artifacts can now be uploaded, typed and aimed,
  and then released together — and the moment a rollout starts is one named act rather than the side
  effect of a file transfer.

  `{"published": false}` **retracts** it: the offer stops for Agents that have not taken the package,
  and **nothing is uninstalled** — an Agent keeps running what it installed, exactly as when a
  Selector stops matching it (ADR-0026). The protocol has no revert; this is not a recall.

  **Nothing that is already running stops.** A package stored before this state existed loads as
  published, so an upgrade withdraws no rollout in flight. And **replacing the artifact of a
  published package still distributes on upload** — that is the ordinary in-place upgrade; stage a
  replacement by retracting first.

  What changes for scripts: creating a *new* package now needs one more call. `targeted_agents`
  keeps counting what a package would reach, drafts included, because checking the aim before
  starting is what staging is for — `published` beside it is where "may the fleet have it" is read.
  In the UI, *Upload* and *Update* leave a package staged and **Offer** releases it; on a released
  package that button reads *Retract*, and the package list marks a draft.

- **The package form in the UI is one intent per button, and every one of them states the Agent
  type.** A package with no type is stored, looks uploaded, and is offered to nobody (ADR-0026) —
  the form used to make that the easiest state to produce by hand, with the type one optional-looking
  field among several and a separate button to remember afterwards.

  Three actions replace *Upload & offer*, *Use source url*, *Set selector* and *Set agent type*:

  | | what it sends |
  | --- | --- |
  | **Upload** | the chosen file as the artifact for the platform named, then the Agent type and the Selector — a complete package from one press, created if the name is new |
  | **Update** | the same without new bytes: a source url replaces the artifact with one hosted elsewhere ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)), and the type and Selector are set either way |
  | **Offer** | whom the package reaches, and nothing else: the type that arms it and the Selector that aims it. No upload, so correcting a rollout that reached nobody is one press |

  None of them runs without an Agent type, so the UI can no longer create a package that reaches
  nobody. *Close* is gone — the **Packages** button that opens the card also closes it.

  **A package chip toggles.** Clicking one fills the form from it; clicking the selected one again
  lets go, and the form describes no package in particular. Nothing is sent and nothing is deleted
  either way. The selection lives in the list, so undoing it is a press in the list rather than a
  button standing among the ones that write.

  The **Agent type** field now offers the types the fleet actually reports, with how many Agents
  report each. The comparison is raw and has no canonical set to fall back on (ADR-0026), so a typo
  is a rollout that silently never starts — picking from the list is the spelling that matches. A
  type no Agent has reported yet can still be typed in.

  The **name** now stands alone on the first line, and is filled in rather than asked for: from the
  chosen artifact's file name, which states the package it belongs to (ADR-0019), else a
  source url's last segment, else the Agent type folded into the ADR-0019 name grammar. It is
  derived again when a request is actually sent, so an artifact chosen and uploaded in one motion is
  named after itself. A name typed by hand outranks all three, and one that names a package that
  exists is not renamed by a correction to that package's type.

  Nothing about the API changed: the artifact, the source, the type and the Selector are still four
  requests over four sub-resources, and a package uploaded by script is still untyped until
  `PUT /api/v1/packages/{name}/type` is called. The type is never guessed from a name or a file
  name — that is the alternative ADR-0026 weighed and rejected.

### Fixed

- **A Client that was downgraded by hand went on reporting the version it had been updated to.**
  After a self-update, `service uninstall` followed by installing an *older* Client left the fleet
  view showing the package pill of the newer version — beside a **Version** column that correctly
  named the old one. The record of what the Client installed lives in
  `<state_dir>/installed-package.json`, and `service uninstall` deliberately deletes neither the
  install layout nor the state, so the older Client came up on top of the record its successor
  wrote.

  The wrong line in the view was the smaller half. The Server gates re-offering on the hash inside
  that record, so the host was **silently out of the rollout for good**: it believed it already ran
  the offered package and would never take it again.

  A record that does not name the version this binary *is* is now discarded at startup, with a
  warning in the log naming both versions. The Client then reports no package, the Server offers it
  again, and **the host is updated back to the published version.** That is the point — the Server
  decides what the fleet runs. To keep a host on an older Client, retract the package first
  (`PUT /api/v1/packages/{name}/publication` with `{"published": false}`,
  [ADR-0025](docs/adr/0025-rollout-and-what-reaches-an-agent.md)); retracting uninstalls
  nothing, so the host stays where it is.

  This is the Client's own package only. A Managed Process's package record is unchanged: only the
  program itself knows its version there, and it is reported by the version probe.

## [0.1.1] - 2026-08-09

### Added

- **A Client running as a service now writes its own log to disk**
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)), at
  `<state_dir>/logs/`, one file per day with seven days kept.

  **On Windows this closes a hole**: the SCM discards a service's stderr, so a Client installed
  there had no readable log at all — a service that would not start left nothing behind to explain
  why. The file is written on Linux and macOS too, where it duplicates `journalctl` and
  Console/`log show`, so that the answer to "where are the logs" is the same on every platform and
  in a container, where neither exists.

  Running the Client in the foreground writes no file; stderr is already in front of you.

  It is not a replacement for `ReportsOwnLogs` (ADR-0016): that ships to a destination the Server
  offers, over a connection that must already work, and the failures most worth reading are the ones
  where it does not.

  The new `[logging]` section moves the directory, changes the retention, or switches it off:

  ```toml
  [logging]
  dir = "/var/log/opamp"   # default: <state_dir>/logs
  keep = 7                 # daily files kept, then deleted
  enabled = false          # write nothing
  ```

  **`keep = 0` is refused at startup** rather than read as "keep everything": on a fleet host the
  unbounded setting is the one that fills a disk, so switching the log off is spelled
  `enabled = false`. A log directory that cannot be written is reported and the Client runs anyway.

- **A package says how many Agents it reaches.** `GET /api/v1/packages` gains `targeted_agents`,
  and the package list in the UI shows `⚠ reaches no agent` when it is zero.

  This closes a silent failure the follow-ups of ADR-0026 and ADR-0016 both named: a
  package can target nobody — through an Agent type that is unset or misspelled, artifacts for
  platforms nobody runs, or a Selector that matches no one — and none of those is an upload error.
  The package stored fine and reached no one, and nothing said so until somebody noticed the version
  had not moved.

  The count is the Server's own resolution of the offer, not a second calculation beside it, so it
  cannot claim a reach the fleet does not get. It counts the fleet **as reported so far**: a package
  staged ahead of the hosts it is meant for reads `0` legitimately, which is why it is a number to
  read rather than a rejected upload.

## [0.1.0] - 2026-08-09

### Added

- **An Agent can be forgotten** ([ADR-0024](docs/adr/0024-the-fleet-record.md)).
  `DELETE /api/v1/agents/{instance_uid}` drops what the Server knows about one Agent, and the
  bundled UI has a `✕ forget` action on every fleet row. A decommissioned host no longer occupies a
  row forever.

  **It reaches no host.** Nothing is stopped, nothing is uninstalled, and no credential is revoked —
  a credential here proves fleet membership, not one Agent's identity, so there is none to revoke.
  A Client that is still configured for this Server therefore reappears on its next report. To
  remove an agent for good, stop it on the machine; forgetting only tidies the view.

  It is refused with `409` while the Agent is still reporting — that is, while it is connected *and*
  something has been heard from it within the staleness budget. Forgetting drops the hashes that stop
  the Server re-offering, so a live Agent would be sent its configuration again, and a managed
  process restarts when one arrives. Stop the agent, or wait for it to fall silent.

  An Agent that was forgotten and comes back is offered its configuration, its connection settings,
  and its packages again. Packages cost nothing — the Client re-installs nothing it already has —
  but the configuration is applied again, which for a managed agent is one restart.

- **A fleet row now says when an Agent stopped talking**
  ([ADR-0024](docs/adr/0024-the-fleet-record.md)). `AgentView` gains
  `stale`, and the bundled UI shows it beside the connection pill.

  It is a second fact, not a replacement: `connected` still means "a connection carrying this Agent
  is open" — behind a Gateway, the *Gateway's* — and `stale` means nothing has been heard from the
  Agent itself for longer than its budget. `connected: true, stale: true` is exactly the gatewayed
  case, and it was invisible before.

  Only an Agent declaring `ReportsHeartbeat` can go stale: that capability is the promise that makes
  silence meaningful. The budget is the offered `heartbeat_interval_secs` times three, or
  `stale_after_secs` in `server.toml` (default 90) when no interval is offered.

  Nothing changes for a stale Agent — it keeps its configuration, its packages, and its identity,
  and its next report clears the flag. Nothing is stored and no timer runs.

- **Gateway Mode** ([ADR-0015](docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)): a Client can now stand at a network
  boundary, accept OpAMP from other Clients, and carry them upstream over a small pool of
  connections. This is the last of the specification's goals to be built.

  ```toml
  [gateway]
  listen = "0.0.0.0:4320"
  upstream_connections = 10       # a cap, not a count
  [gateway.tls]                   # optional; the downstream hop's own TLS
  cert_file = "gateway.pem"
  key_file = "gateway-key.pem"
  client_ca_file = "client-ca.pem"
  ```

  Point the Clients behind it at the Gateway's address instead of the Server's — nothing else about
  them changes, and the Server sees them as the Agents they are. Both transports are served
  downstream, so a polling Client works as well as a WebSocket one.

  **The pool costs what it uses.** `upstream_connections` is a ceiling: connections are opened as
  Agents appear, so a Gateway in front of three Agents holds three. Each Agent sticks to its
  connection for as long as it lives.

  **A Gateway makes no authentication decisions.** It forwards each peer's credential upstream
  untouched. Mutual TLS is per hop: `[gateway.tls]` verifies the Agents connecting *to* it, while
  the identity it presents *to the Server* is its own, from the top-level `[tls]` or the CSR flow.
  The Gateway's upstream endpoint must be `ws://` or `wss://` — a polling connection could not carry
  the Server's pushes to the Agents behind it, and the configuration says so at startup.

  **Two limits to know.** An Agent whose Client vanishes without saying goodbye stays "connected" in
  the fleet view until someone notices: the Gateway forwards no `agent_disconnect` it did not
  receive, because that would put words in an Agent's mouth. And when a pooled connection drops, the
  Server marks every Agent that rode it disconnected until each reports again — one heartbeat
  interval where one is configured.

- **Every Agent can now report its own telemetry** — metrics, logs, and traces — to a destination
  the **Server** names ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)).

  Add a `[telemetry_offer]` section to `server.toml` with any of `metrics_endpoint`,
  `traces_endpoint`, `logs_endpoint` — full OTLP/HTTP URLs **with path**, e.g.
  `https://collector.example:4318/v1/metrics` — plus optional `[telemetry_offer.headers]` for an
  access token. Each signal is offered independently, and only to Agents that declare it.

  Nothing is configured on the Client, and that is deliberate: the capability means "report to the
  destination the Server specifies", so a destination in `client.toml` would be a private extension
  wearing its name. With no offer, nothing is sent and nothing is built.

  **What it sends.** Process metrics every 30 seconds — CPU, memory, uptime — for the Client's own
  process and for each Managed Process it started; the Client's own log output as OTLP records, with
  stderr unchanged; and one span per control-loop operation that already has a lifecycle (a
  configuration being applied, a package being installed, a self-update). The OTLP Resource carries
  the Agent's identifying attributes, so one host's several Agents stay apart at the receiving end.

  **What it does not send:** a Collector's *internal* telemetry. This Client must not touch a
  Managed Process's configuration (ADR-0017), so what it reports is what it observes from the
  outside. Configure the Collector for its own internals as you would without OpAMP.

  **A cleartext destination is refused, not warned about.** `http://` beyond the loopback interface
  is rejected and reported back to the Server, because the stream carries identifying attributes and
  whatever the Client logs. The protocol explicitly permits this refusal.

- **Mutual TLS, with client certificates this Server issues itself**
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). Goal 17 is
  complete: the connection is encrypted, and the peer at each end can now be proved.

  **On the Server**, `[tls]` gains an optional `client_ca_file`. With it set, every request to
  `/v1/opamp` must arrive over a connection carrying a client certificate that bundle verifies.
  Client authentication stays optional at the TLS layer, because the same listener serves the REST
  API and the UI — a browser presents nothing and is unaffected.

  **Every configured proof must succeed** — this is the rule to read twice. `[auth]` alone behaves
  exactly as before. `client_ca_file` alone makes the endpoint certificate-only. **Both configured
  means both required**, not either one. So switching mutual TLS on can never widen admission; what
  it can do is lock out a host that has no certificate yet, which is why the order is: let the fleet
  enrol first, then set `client_ca_file`.

  **On the Client**, `[tls]` gains `cert_file` and `key_file` for an operator-provisioned identity —
  including the bootstrap certificate a fresh host enrols with. `ca_file` is now optional, so a
  `[tls]` section may carry only an identity and keep the public roots.

  **The Server can issue the certificates.** A new `[client_ca]` section in `server.toml`
  (`cert_file`, `key_file`, `validity_days`, default 90) makes the Server a local CA. A Client that
  has no certificate — or holds one two thirds through its life — generates a key **that never
  leaves the host**, sends a signing request, and receives the certificate as an ordinary
  connection-settings offer, which it proves by connecting with before the old one is replaced. It
  asks only when the Server declares that it signs, so a Server without `[client_ca]` is never
  asked.

  **Enrolling before enforcing** is therefore the migration: add `[client_ca]`, let the fleet come
  back with certificates (they appear in each Client's state directory as `client-cert.pem`), then
  add `client_ca_file` and, when every host is on a certificate, delete `[auth]`. A fleet that will
  run Gateways keeps `[auth]`: a Gateway terminates TLS, so the credential is the only per-Agent
  proof that survives the hop.

  **There is no revocation.** Short validity and renewal are what bound a certificate; ejecting a
  host faster than its certificate expires means rotating the CA. And an expired certificate locks
  a host out even with a valid credential — a Client switched off longer than its validity needs
  `client_ca_file` unset for as long as it takes to re-enrol.

- **A released `.7z` unpacks as an executable on Linux and macOS.** The member is packed with a
  Unix mode of `0755` (7-Zip's Unix-attribute convention), so `7z x` yields a binary that runs
  instead of one that needs a `chmod +x` nobody wrote down. `--format tar.gz` already did this in
  its tar header; the two containers now agree. Nothing changes for a package the Server delivers —
  the Client sets the mode itself when it installs one — and nothing changes for the Windows
  artifact, where the bit means something else and 7-Zip does not write it either.

- **`opamp-fleet-client service install --interactive` writes the first configuration.** A freshly downloaded
  Client has no `client.toml` — the release artifact is the bare binary — and installing without one
  produced a service that started, dialled `127.0.0.1`, and managed nothing. The flag asks for what
  a fresh host cannot guess (endpoint, Agent name, credential, a private CA when the endpoint is
  `wss://`/`https://`, and last, defaulting to *no*, consent for the Server to update this Client's
  own binary), writes the file, and validates it before registering the service
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)).

  Nothing about existing invocations changes: the flag is opt-in, an existing file is kept rather
  than overwritten, and `--interactive` without a terminal on stdin fails instead of blocking a
  provisioning run. The credential is typed into a hidden prompt, so it stays out of the shell
  history and the process list, and on Unix the file is created mode `0600`. Installing *without*
  the flag now prints a warning when the configured path holds no file — the silence was the bug.

- **Released builds of the Client, one archive per platform.** A release publishes
  `opamp-fleet-client-<version>-<os>-<arch>.7z` for Linux and macOS on `x86_64` and `aarch64`, and Windows
  on `x86_64`, together with `SHA256SUMS`
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)). Until now there was nothing to
  install but a build of your own.

  **The version is `[workspace.package] version` in `Cargo.toml`**, and the pipeline creates the
  `version/*` tag from it ([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)) — so a release is
  "merge the bump, run the workflow", and no tag is typed by hand. It refuses rather than guesses:
  a version that already has a tag or a release is spent, and the run says so before it builds
  anything — including a dry run, which is the run meant to catch a forgotten bump — and a binary
  that does not report the version its artifacts are named after fails the run.

  **Each archive is also a package artifact**: it holds the Client under the name the install layout
  gives it, so the file is uploaded exactly as downloaded and the published SHA-256 is the one an
  Agent verifies. When you hand one to a Server for a Client self-update, `?version=` takes the
  release number — the one in the file name.

- **`supervisor_dir`** (optional, top-level) places the per-Supervisor directories; the default is
  `<state_dir>/supervisors`, which is where they have always been. Set it to keep the Managed
  Processes' programs off a `noexec` mount, or off a volume sized for state rather than for a few
  hundred megabytes of Collector. Moving it on a running host leaves the old tree behind —
  `instance-uid` included — so each Supervisor re-registers as a **new** Agent on the Server;
  nothing migrates automatically.

- **`${supervisor_dir}` and `${config_dir}` in a `command` Supervisor's `args`, `working_dir`, and
  `env` values** ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)),
  so a Foreign Agent's command line is derived from the same place the Client derives it from:

  ```toml
  args = ["-c", "${config_dir}/fluent-bit-conf"]
  ```

  An absolute path still works and is still wrong the moment `supervisor_dir` moves or the
  Supervisor is renamed — the process then starts happily on a file nobody writes to, with nothing
  reporting a problem. The shipped example carried exactly that mistake and now uses the
  placeholder. Any other `${…}` is passed to the process untouched, so an agent's own variable
  syntax keeps working; the flip side is that a misspelled placeholder is handed over rather than
  refused. The program itself (`binary`, `command`) is never substituted.

- **`opamp-package-sign pack`** builds a package artifact from a single-file program and prints its
  SHA-256, and **`opamp-package-sign sha256`** hashes an existing one — the value
  `PUT /api/v1/packages/{name}/source` needs for an artifact the Server will not hold
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). Until now the project could open the
  two container formats but gave an operator no supported way to produce one, and an encrypted
  `.7z` in particular had no answer at all.

  ```console
  $ opamp-package-sign pack --out promtail-3.0.0.tar.gz ./promtail
  $ opamp-package-sign pack --format 7z --archive-key "$KEY" --out promtail-3.0.0.7z ./promtail
  ```

  The member inside the archive is named after the packed file, which is what a Supervisor looks
  for; `--program-name` covers an upstream build whose file name differs. A `.tar.gz` is
  reproducible — modification time, owner, and group are zeroed — so repacking the same program
  does not produce a new hash and therefore no rollout. **There is no `zip`, and adding one is not
  a matter of a flag:** an artifact that is neither gzip nor 7z is taken to *be* the program, so a
  `.zip` would be installed over the binary unopened.

- **A user manual** at [`docs/manual/`](docs/manual/README.md) — Server and Client documented
  option by option, plus an end-to-end [rollout walkthrough](docs/manual/rollout.md) that installs
  and configures a Foreign Agent entirely from the Server.

- **`program_path` in a `[[supervisor]]` block delivers an agent that is more than one file**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). An executable plus the shared objects it
  loads — Fluent Bit is the case — could not be a package before, because exactly one archive
  member was installed. Naming where the program sits inside the package unpacks the whole archive
  instead:

  ```toml
  [[supervisor]]
  type = "command"
  name = "fluent-bit"
  command = "fluent-bit"            # unchanged: the bare name is still the consent
  program_path = "bin/fluent-bit"   # where the program sits inside the package
  ```

  The tree lands in `<supervisor_dir>/<name>/program/tree/`, and the one it replaced is kept as
  `program/tree.rollback` until the new one has survived `apply_grace_secs` — put back **whole** if
  it has not. The path is matched from its end, so the version-named directory a release wraps
  everything in needs no mention and the value stays right at the next release.

  **Without `program_path` nothing changes**: one member, one file, same layout, same rollback.

  Unpacking a tree means the archive names paths, so every member is checked before anything is
  written and one bad member refuses the whole archive: a `..` or absolute path, a symbolic or hard
  link, more than 10 000 members, or more than 2 GiB unpacked. A `.tar.gz` carries file modes and
  is the right format for a tree; a `.7z` is opened too, but only the program is made executable.

### Changed

- **The connection-settings hash now covers the whole offer**, not just its OpAMP part — it has to,
  now that one offer can also carry telemetry destinations
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)).

  One consequence on upgrade: every Agent's stored hash stops matching, so the Server sends its
  standing offer once more and each Agent verifies and re-applies it. That is one extra exchange per
  Agent, no reconnect and no downtime, and it settles by itself.

- **A connection-settings offer carrying `tls` or `proxy` is no longer acknowledged `APPLIED`.**
  The Client never implemented those two fields and dropped them silently while reporting success,
  so a Server offering either was told the settings were in force when they were not. It now applies
  everything it does honour — endpoint, credential, heartbeat, certificate — and reports `FAILED`
  with an `error_message` naming what it dropped
  ([ADR-0021](docs/adr/0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).

  Nothing to do on any host. A Server whose `[connection_offer]` never carried those fields — this
  project's Server cannot — sees no change at all.

- **The Windows services list now shows a description**: **OpAMP Fleet Client for Windows**. It is a
  field of its own beside the display name, and nothing that registers a service fills it — so the
  Client had a display name and an empty Description column. It is the same text on every instance;
  the display name beside it (`OpAMP Fleet Client (prod)`) is what distinguishes them.

  An already-installed service keeps its empty description until it is registered again — the field
  is written at install time. `service uninstall` then `service install` fills it.

- **A Windows install without Administrator now says so before it writes anything.** `service
  install` asks the service control manager up front whether this process may register a service at
  all, and stops with the one thing that fixes it — open a shell with "Run as administrator" — if it
  may not.

  Before, the refusal came from `sc create` in the middle of the install, as a bare (and localised)
  `OpenSCManager` access-denied error, and only *after* the layout had been written: `%ProgramData%`
  lets an ordinary user create folders, so a staged version directory and a `current` junction were
  left behind by an install that had registered nothing. Delete such a root, or just re-run the
  install from an elevated shell.

  There is no UAC prompt, on any `service` verb: a running process cannot raise its own rights, so
  an elevated shell is the way in. The earlier, unreleased retry of a refused `sc.exe` call through
  `Start-Process -Verb RunAs` is gone — it sat *after* the registration, which is what gets refused
  first, so it could never fire.

- **Every Agent now reports the attributes the protocol names.** Alongside `os.type` and
  `host.arch`, an Agent reports `os.name`, `os.version`, `host.name`, and `host.id` — so a Selector
  can target a distribution release, or pin one machine by its host name.

  **`host.name` in particular was promised and missing.**
  [ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) offers "a Selector matching that host's
  `host.name`" as *the* way to hold one host to one artifact; no Agent reported it, so such a
  Selector silently matched nothing. It works now.

  An attribute the host cannot answer is **left out rather than reported empty** — a container
  without `/etc/machine-id` reports no `host.id` — so a Selector on one reaches exactly the hosts
  that have it. Nothing has to be changed on any host; the new attributes appear on the next
  connection.

- **`service_namespace` in `client.toml`**, for the one attribute the protocol makes conditional on
  the environment ("if it is used in the environment where the Agent runs"). It is reported as an
  *identifying* attribute of every Agent this Client presents, which is where the protocol puts it —
  unlike `[attributes]`, which tags an Agent. Optional; absent reports nothing.

- **`opamp-fleet-client service install` without `--config` now bakes `<root>/client.toml` into the unit**,
  inside the install root, instead of `client.toml` resolved against whatever the working directory
  happened to be
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)). A service
  manager's working directory is `/` or `System32`, so the old default pointed at a file the
  service could not have been relying on unless the install was run from exactly the right
  directory. **If you installed by running `install` from the directory holding your
  `client.toml`,** name it explicitly —
  `opamp-fleet-client service install --config /etc/opamp/client.toml` —
  or move the file to `<root>/client.toml`; the install prints the path it registered either way.

- **What a Client reports as its version now names the release it is heading *for*, not the one it
  descends *from*.** The base comes from `Cargo.toml` and git decides only the rest
  ([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)): a build with no release tag on its commit
  reports `0.1.0-dev+<hash>` where it used to report `0.0.0-dev+<hash>`. Nothing to do — but the
  fleet view, `opamp-fleet-client --version`, and the name of the versioned install directory all
  shift with it,
  so a host that has not changed will still look different after an upgrade. A commit carrying a
  `version/*` tag that names a *different* version than `Cargo.toml` no longer builds at all, rather
  than producing a binary that disagrees with its own tag.

- A Supervisor's package downloads are staged in its own directory
  (`<supervisor_dir>/<name>/packages/`) instead of `<state_dir>/packages/`, which the Client's own
  Agent keeps using. Any `*.staged` file left in the old location by an interrupted download is
  orphaned and can be deleted.
- A package artifact that is a bare program is now **moved** into place rather than copied, saving a
  second full write of it. An artifact that is an archive is still unpacked, so an upstream
  Collector release (`.tar.gz`) is unaffected.

### Fixed

- **An Agent that installed a package went on reporting the version it replaced.** The package
  itself was reported correctly — `Installed`, with the new version, in the fleet view's package
  pill — but the Agent's own `service.version`, which is the fleet table's **Version** column, still
  named the old one. On a first install onto an empty `program/` it named nothing at all, and the
  column stayed empty beside a package the Server had just seen installed.

  Only the program knows its own version, so the Client asks it: it runs the Managed Process's
  version flag (a Collector's `--version`, or a `command` Supervisor's configured `version_args`)
  and reports what it prints. That question was asked once, when the Supervisor started — never
  again after a swap replaced the binary it had asked. A Collector carrying the `opampextension`
  corrected itself the moment it next started and self-reported; one without the extension, and one
  with no configuration to run on yet, had nothing that ever would. Restarting the Client was the
  only cure.

  The program is now asked again after every successful swap, and the two sources — the probe and
  the extension's self-report — are merged per attribute instead of each replacing the other.
  Nothing to change on a host: an affected Agent reports its version within seconds of the next
  install, and a Client restart still fixes an Agent that installed before this version.

- **On macOS, a Client installed as a service could never update itself** — every offer was refused
  with "this Client does not run from a versioned install layout", and a torn `current` pointer was
  never repaired either. The service is registered against `<root>/current/client` (ADR-0019), and
  asking the operating system what is running answers with that path on macOS and with the version
  directory behind it on Linux; only the second shape says where in the layout the binary sits. The
  path is now resolved before the layout is looked for, so both platforms answer the same. Nothing
  to change on a host: an affected Client picks its updates up as soon as it runs this version.

- **A Client that had just updated itself reported the update as failed, and then downloaded the
  artifact again — over and over.** After the restart the Server keeps offering the package until
  the Agent reports a terminal status for it; the Client answered "the offered version is the one
  already running" as an *error*, which is not terminal, so the offer came back and the whole
  artifact was fetched again every couple of seconds for as long as both ends were up. On a fleet
  that is a self-inflicted flood against the Server, and a successful self-update that shows as
  `InstallFailed` in the fleet view. The version already running is now reported `Installed`, which
  is both true and what the Baseline asks for: an Agent that already has the offered version "does
  not need to do anything". No configuration changes; a Client that was in this state leaves it as
  soon as it runs this version.

- **The fleet view now shows why an Agent refused a package offer**, in the new `package_error`
  field of `GET /api/v1/agents`. An offer refused outright has no package status to carry the
  reason — which is exactly what happens when the Client's own Agent is offered a package
  `[self_update]` did not name (ADR-0018) — so the reason was reported by the Client, stored by the
  Server, and shown nowhere. It is now also logged.

### Changed — breaking

- **A package now states the Agent type it is built for, and reaches no Agent of another**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). ADR-0026 made the
  Server refuse to send an artifact to a machine it cannot run on; this does the same for an Agent it
  was not built for. A Promtail artifact can no longer be swapped over a Collector because someone
  forgot the Selector.

  **Every existing package is inert until its type is set**, including one in the middle of a
  rollout. The Server starts normally and logs each untyped package by name; the package view marks
  it. Set the type to the `service.name` its Agents report:

  ```console
  $ curl -X PUT -H 'Content-Type: application/json' \
         -d '{"service_name": "otelcol-contrib"}' \
         http://<server>:4320/api/v1/packages/otelcol/type
  ```

  The value is compared **raw** — there is no canonical set of Agent types to normalise against — so
  a typo is a rollout that never starts rather than an error. Read the type off the Agent's fleet row
  before typing it. It belongs to the package name, not to an artifact, so it is set once for all
  platforms.

  An Agent that reports no `service.name` at all is now offered no package, the same rule ADR-0026
  applies to a missing platform. Every Client this project ships reports one.

  **New route** `PUT /api/v1/packages/{name}/type`; `PackageView` gains `service_name`.

- **`service.name` now reports the Agent *type*, not the Agent's name**
  ([ADR-0016](docs/adr/0016-what-an-agent-reports-about-itself.md)). The name an
  operator gives an Agent moved to a new attribute, `service.instance.name`. Before, a
  `[[supervisor]]` block's `name` was reported as `service.name` — the slot the protocol reserves
  for "a reverse FQDN that uniquely identifies the Agent type" — and a Collector carrying the
  `opampextension` overwrote it with its own type the moment it connected, so every Collector of one
  distribution collapsed onto one name in the fleet view.

  **Any Selector matching `service.name` must be checked.** It now matches a type
  (`otelcol-contrib`, `opamp-fleet-client`), not a Supervisor's name, so one written against a name
  silently stops matching and its Configuration or package quietly stops being delivered. Nothing
  detects this for you. Point it at the new attribute instead:

  ```console
  $ curl -X PUT -H 'Content-Type: application/json' \
         -d '{"selector": {"service.instance.name": "otelcol-edge-01"}}' \
         http://<server>:4320/api/v1/configurations/edge-config/selector
  ```

  Aiming at *what an Agent is* is what `service.name` is now good for — one Selector of
  `{"service.name": "otelcol-contrib"}` reaches every Collector of that distribution, with nothing to
  configure per host.

  The interactive install asks for the same value it always did, under the name it actually
  reports now: `This Agent's name (service.instance.name)`.

  **`client.toml` needs no change**, and no Agent changes its identity: `instance_uid` and
  `service.instance.id` are untouched, so nothing is re-registered. A Managed Process that reports no
  type of its own now presents its program's file name as one; the new optional `service_name` key in
  a `[[supervisor]]` block states a better one.

  **The REST API's `AgentView` gained `service_instance_name`**, and `service_name` keeps its key
  while changing what it holds. Anything reading `service_name` as a display name should read
  `service_instance_name` and fall back to `service_name`, which is what the bundled UI now does.

- **A package now holds one artifact per platform, and `os`/`arch` are required**
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). An Agent is offered only the artifact
  built for the operating system and architecture it reported, and never another — so uploading a
  Windows build no longer installs it over every Linux host in the fleet.

  **Every Server has to be migrated before it will start.** A package stored without a platform is
  refused at startup, naming the file. For each one, upload it again with its platform, or delete it:

  ```console
  $ curl -X PUT --data-binary @otelcol-linux-amd64.tar.gz \
         "http://<server>:4320/api/v1/packages/otelcol?version=0.109.0&os=linux&arch=amd64"
  ```

  **Four routes change.** `PUT /api/v1/packages/{name}` and `PUT …/{name}/source` require `os` and
  `arch`; `POST …/{name}/rollback` and `GET …/{name}/file` require them in the query. `DELETE
  …/{name}` still deletes the whole package, and now takes an optional `?os=…&arch=…` for one
  artifact. Generated clients must be regenerated.

  **`GET /api/v1/packages` answers a new shape.** `version`, `addon`, `source_url` and
  `previous_version` moved out of the package and into a `variants` array, one entry per platform,
  each with its own `os`, `arch` and rollback history. `selector` stays on the package: the Selector
  aims, the platform fits.

  A rollback names one platform and moves only that one — a canary taken back on Linux must not push
  macOS off a version it never left.

- **The Client reports `host.arch` as `amd64`/`arm64`**, the semantic-convention values the protocol
  points at, where it used to report Rust's `x86_64`/`aarch64`
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).

  **A Selector written against `host.arch` must be edited on the Server** — `{"host.arch": "x86_64"}`
  now matches nothing. Change it to `amd64` (or `aarch64` → `arm64`); nothing changes on any host.

  This also closes a quiet defect: a Managed Process's attributes are folded over the Supervisor's,
  and the Collector's `opampextension` already reported `amd64`. The same machine therefore changed
  architecture depending on whether a Collector happened to run on it, and Selectors written against
  either spelling broke without anything having changed.

- **Release artifacts are named `<name>_<version>_<os>_<arch>.7z`** —
  `opamp-fleet-client_1.2.3_linux_amd64.7z`, `opamp-fleet-client_1.2.3_darwin_arm64.7z`. Both halves
  of that changed: the platform tokens, which used to say `macos` and `x86_64`
  ([ADR-0026](docs/adr/0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)), and the separator between the four
  fields, which used to be `-`
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)) — both
  as [ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md) names them now.

  **Anything scripted against the old names breaks**, including a glob like `*-linux-amd64.7z`;
  releases already published keep the names they have, and nothing is renamed.

  The gain is that the name says what it holds without being guessed at. The two platform fields are
  exactly the pair an Agent reports, so uploading a release needs no translation table — and because
  neither a package name (`[a-z0-9-]`) nor a version (`1.2.3-dev`) can contain `_` while both contain
  `-`, the four fields can be read off the file name by splitting it. That is what lets the release
  notes publish an upload loop that takes `os` and `arch` out of each file rather than being handed
  the name and version it has to strip first.

- **The service is registered as `opamp-fleet-client` on every platform**
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)). It used to be
  `opamp-fleet-client.default.service` on systemd and `io.opamp-fleet.client.default` on launchd and
  the Windows SCM — two names nobody chose, both falling out of how a reverse-DNS label happens to
  be split. Now: `systemctl status opamp-fleet-client`, `launchctl list opamp-fleet-client`,
  `sc query opamp-fleet-client`. A named instance appends its own name
  (`opamp-fleet-client-prod`); the default instance carries the bare one.

  **An already-installed service is not found under the new name.** Run
  `service uninstall` with the *old* binary, then `service install` with the new one. The install
  layout and the state directory are untouched by either.

  On Windows the services list now shows **OpAMP Fleet Client** — the readable name ADR-0019
  promised and never actually set.

- **A version is compared and shown without its build metadata**
  ([ADR-0012](docs/adr/0012-versions-resolved-in-the-internal-crate.md)). Two
  things change, and one of them is an API break.

  **Uploading a Client package now takes the release number.** `?version=1.2.3` matches a binary
  reporting `1.2.3+a1b2c3d`, because the commit a build came from is provenance, not identity — and
  it is the one part of the string nobody can type at upload time. (A `+` in a URL query decodes to
  a space, so the old requirement to pass the full string could only be met as `%2B`. That trap is
  gone.) The pre-release is **not** ignored: a `1.2.3-dev` build offered as `1.2.3` is still
  refused. The full string keeps working where you already pass it.

  **`AgentView.service_version` now holds the release, not the build.** It is
  `MAJOR.MINOR.PATCH`, with the pre-release when there is one; what the Agent reported verbatim
  moved to the new **`service_build`** field beside it. **If you read `service_version` from
  `/api/v1/fleet/agents` and need the commit, read `service_build`.** The bundled UI shows the
  release in its Version column, the build on hover, and searches both. An Agent whose reported
  version is not a version at all — a Foreign Agent numbering itself its own way — is shown
  unchanged in both fields.

- **The Client ships as `opamp-fleet-client`.** The release artifact is
  `opamp-fleet-client-<version>-<os>-<arch>.7z`, the file it installs is `opamp-fleet-client`
  (`.exe` on Windows), and the version directory beside it is
  `versions/opamp-fleet-client-<version>-<commit>/`
  ([ADR-0019](docs/adr/0019-the-client-supervisor-installed-service-releases-and-installers.md)). One name from the download
  to the process in `ps` to the Agent in the fleet view.

  **Nothing in a fleet has to be migrated, because nothing has been released yet** — this is the one
  moment the change is free. A *development* service installed under the old layout does have to be
  re-registered: its unit points at `<root>/current/client`, which the new build no longer produces.
  Run `opamp-fleet-client service uninstall` with the old binary, then
  `opamp-fleet-client service install` with the new one.

  The Cargo package stays `client`, so `cargo run -p client` and `cargo build -p client` are
  unchanged — only the binary they produce is renamed. The service label
  (`io.opamp-fleet.client.<instance>`) is unchanged too.

- **`accepts_packages` is no longer a `[[supervisor]]` key** and a configuration still carrying it
  **fails at startup**. Whether a Managed Process takes Server-offered package updates is now
  decided by how its program is named
  ([ADR-0017](docs/adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)):

  | `binary` / `command` | Meaning |
  |---|---|
  | a bare file name (`otelcol-contrib`) | the program lives in `<supervisor_dir>/<name>/program/`, a directory the Client owns — it **takes** package updates |
  | an absolute path (`/usr/local/bin/otelcol`) | the machine's program — it is supervised but never written to |
  | anything else (`./x`, `bin/x`) | a startup error |

  **To keep updates working on a host that had `accepts_packages = true`:** move the program into
  `<supervisor_dir>/<name>/program/`, reduce the configured path to its bare file name, and delete
  the `accepts_packages` line. **To stop at supervision instead:** delete the line and leave the
  absolute path. Either way it is one edit per host — the Client will not start until it is made.

  This also fixes the case that motivated the change: with an absolute path into a directory the
  Client cannot write (`/usr/local/bin` under a non-root Client), an update could be configured but
  never succeed, and it failed at rollout time on every matched host rather than at startup on one.

  **On Windows, "absolute" means the path names a drive.** `\Program Files\otelcol\otelcol.exe`
  carries a root but no drive, so it resolves against whichever drive the process happens to be
  on — it used to be spawned that way and is now refused at startup, with a message saying what is
  missing. Write `C:\Program Files\otelcol\otelcol.exe`.

- **A bare program name is no longer looked up in `$PATH`.** `command = "fluent-bit"` used to mean
  "find it on the path" and now names a file in that Supervisor's `program/` directory. This is
  silent — the process starts from a different path rather than erroring — so check any block whose
  program is not an absolute path. The startup log states, per Supervisor, which program it resolved
  to and whether packages are accepted.
