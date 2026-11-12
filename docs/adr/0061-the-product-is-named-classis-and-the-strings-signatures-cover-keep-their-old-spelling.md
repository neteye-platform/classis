# ADR-0061: The product is named Classis, and the strings a signature or a stored file is bound to keep their old spelling

- **Status:** 🟡 proposed
- **Date:** 2026-11-12
- **Deciders:** Davide Zeni
- **Applies to:** every name the project gives itself — the crates under
  `crates/`, the build-time product name and title in
  `crates/classis-agent/build.rs`, the services, accounts and directories the
  Client installs, the operator program, the container image, the Server's
  environment variables — and the certificate URIs and domain-separation strings
  in `crates/classis-core/src/renewal.rs`,
  `crates/classis-core/src/bootstrap_proof.rs`,
  `crates/classis-core/src/package.rs`, `crates/classis-tools/src/signing.rs`,
  `crates/classis-server/src/ca.rs`, `crates/classis-server/src/postgres/mod.rs`
  and the Gateway in `crates/classis-agent/src/gateway/`

## Context

The project was published as _OpAMP Fleet_: crates `fleet-core`, `fleet-server`,
`fleet-agent` and `fleet-tools`, a Client product `opamp-fleet` titled _OpAMP
Fleet Agent_, the operator program `opamp-fleetctl`, the image
`ghcr.io/mbrigl/opamp-fleet-server`, and the Server's variables
`FLEET_SERVER__…`. The repository now lives at `neteye-platform/classis`, and
the product is to carry that name.

Releases up to `0.7.0` are out, so every name an operator sees is a contract
somebody installed against. Two kinds of name differ in what a rename costs:

- **Names an operator types or reads** — programs, packages, services, accounts,
  directories, variables, the image. A rename moves them; an upgrade has to be
  told what to move, and the CHANGELOG is where it is told.
- **Strings a signature or a stored file is bound to** — the URIs every
  certificate the Server issued carries, `urn:opamp-fleet:host:<id>`,
  `urn:opamp-fleet:renewal:v1:` and `urn:opamp-fleet:bootstrap:v1:`
  ([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md),
  [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)),
  `opamp-fleet-renewal-v1` and `opamp-fleet-bootstrap-v1` in the renewal and
  bootstrap proofs
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
  `opamp-fleet-package-v1` in the package statement
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)),
  the signing file format `opamp-fleet-signing-v1`
  ([ADR-0027](0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md))
  the header `opamp-fleet-gateway-bindings` of a Gateway's binding store
  ([ADR-0058](0058-a-gateways-bindings-outlast-its-restart-and-end-with-their-hosts-certificate.md)),
  and the key `opamp-fleet-server:` of the advisory lock that keeps one Server
  per PostgreSQL schema
  ([ADR-0050](0050-the-servers-records-may-live-in-postgresql.md) clause 6). A
  rename of one of them invalidates every signature made over it and every file
  written with it: an enrolled Host's certificate would no longer name its host,
  a package signed for `0.7.0` would no longer verify, a Gateway would forget
  its bindings on upgrade, and a Server before the rename and one after it would
  write one schema at once. These strings are identifiers of a format, not the
  product's name, and nothing an operator reads.

The subject attributes `fleet.host.*`
([ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md))
and the domain term _Fleet_ of the [glossary](../GLOSSARY.md) name the set of
Agents, not the product, and are not part of the brand at all.

## Decision

We will name the product **Classis** in every name an operator types or reads,
and keep the `opamp-fleet-…` spelling of the strings a signature or a stored
file is bound to.

1. **The crates** are `classis-core`, `classis-server`, `classis-agent` and
   `classis-tools`, under directories of the same names; `opamp` keeps its name.
2. **The Client's product** defaults to the name `classis` and the title
   _Classis Agent_
   ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
   clause 2). Its services are `classis` and `classis-agents`, its account
   `classis` (`_classis` on macOS, `NT SERVICE\classis` on Windows), the account
   of its Managed Processes `classis-agents` (`_classis-agents` on macOS), and
   its directories follow the product name: `/opt/classis`, `/var/lib/classis`,
   `/usr/libexec/classis`, `/run/classis-agents`. Its own telemetry's
   instrumentation scope is `classis-client`.
3. **The operator program** is `classisctl`, its release assets
   `classisctl_<version>_<os>_<arch>…`.
4. **The Server's image** is `ghcr.io/neteye-platform/classis-server`, its
   variables `CLASSIS_SERVER__…` and `CLASSIS_SERVER_CONFIG`
   ([ADR-0051](0051-the-servers-configuration-may-come-from-its-environment.md)),
   its data directory in the image `/var/lib/classis`
   ([ADR-0052](0052-the-server-ships-as-a-container-image-built-from-its-attested-release-binary.md)),
   and the manual's example paths `/etc/classis`, `/etc/classis-server` and
   `/var/lib/classis-server`. Its PostgreSQL connections carry the
   `application_name` `classis-server`. The CA subjects `classisctl` writes read
   _Classis Server CA_, _Classis Client CA_ and _Classis Bootstrap CA_.
5. **These strings keep their spelling:** the certificate URIs
   `urn:opamp-fleet:host:`, `urn:opamp-fleet:renewal:v1:` and
   `urn:opamp-fleet:bootstrap:v1:`, and `opamp-fleet-renewal-v1`,
   `opamp-fleet-bootstrap-v1`, `opamp-fleet-package-v1`,
   `opamp-fleet-signing-v1`, `opamp-fleet-gateway-bindings`, and the advisory
   lock's key `opamp-fleet-server:`. A new version of one of these formats may
   take a new prefix; that is the format's decision, not this one's.
6. **The change is a clean break.** No old name is still read, no old path
   migrated by the program: the CHANGELOG lists what an operator renames or
   moves before upgrading.

**Out of scope:** the domain term _Fleet_ and everything spelled after it — the
glossary entry, `fleet.host.*`, the `fleet` Deployment of the tests,
`--fleet-files`, `crates/classis-server/src/fleet.rs`. The build variables
`OPAMP_PRODUCT_NAME` and `OPAMP_PRODUCT_TITLE`, which name the protocol, not the
product.

## Alternatives considered

- **Rename the strings too** — one spelling everywhere, at the cost of every
  enrolled Host's certificate, package signature, signing file and Gateway
  binding store that exists. Their readers would refuse what the previous
  release wrote, for a word nobody reads.
- **Rename only the crates** — no operator-visible change, but the program, the
  services and the image would carry a name the project no longer has.
- **A transition period** — the Server reading `FLEET_SERVER__…` beside the new
  variables, the install moving an old layout. Code and tests that exist only to
  be removed, for a project before `1.0`.
- **`opamp-classis-…`** — keeps the protocol prefix, so the names stay long;
  `classis` is not taken by another tool on a `PATH` the way `fleetctl` was
  ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)).

## Sources / Prior art

- The ADRs that fixed the old names: ADR-0010 (crates), ADR-0019 (product name
  and layout), ADR-0028 (operator program), ADR-0051 (variables), ADR-0052
  (image); their bodies were rewritten to the new names with the human's
  explicit consent rather than superseded clause by clause, since the rename
  touches about a thousand mentions in fifty ADRs.
- Domain separation keeps a signed statement from being read as another kind of
  statement — the tag only has to be unique and fixed, not descriptive
  ([RFC 9380 §3.1](https://www.rfc-editor.org/rfc/rfc9380#section-3.1), on
  domain separation tags).

## Consequences

- Positive: one name for the product across crates, programs, packages, image
  and documentation.
- Negative / trade-offs: every existing installation has to be moved by hand —
  service, account, directories, variables, image reference. Accepted ADR bodies
  were edited, which [AGENTS.md §3](../../AGENTS.md#3-adr-rules) rule 5 forbids;
  the human made that exception for this rename, and git carries the original
  text.
- Negative / trade-offs: the strings of clause 5 still read `opamp-fleet`, which
  a reader will take for a leftover; clause 5 and the tests below are what stop
  it being "fixed".
- Follow-ups: whether the release that carries this is a new minor version.

## Enforcement

A test pins each string clause 5 keeps, and fails on a rename, each marked
`Verifies: ADR-0061`: the certificate URIs and the renewal and bootstrap
statements in `crates/classis-core/src/renewal.rs`, the host URI in
`crates/classis-server/src/ca.rs` and in the Gateway's
`crates/classis-agent/src/gateway/cache.rs`, the package statement in
`crates/classis-core/src/package.rs`, the signing format in
`crates/classis-tools/src/signing.rs` and as the UI carries it in
`crates/classis-server/tests/rest_api.rs`, the binding store's header in
`crates/classis-agent/src/gateway/store.rs`, and the advisory lock's key in
`crates/classis-server/src/postgres/mod.rs`.

**Not mechanically decidable:** that no operator-facing name still spells the
old brand. A search for `opamp-fleet`, `OpAMP Fleet` and `FLEET_` outside the
strings of clause 5 and the CHANGELOG is the review step.
