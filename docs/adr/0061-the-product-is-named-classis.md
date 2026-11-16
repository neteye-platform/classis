# ADR-0061: The product is named Classis in every name it gives itself

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

The old name also reaches into strings that data is bound to: the URIs every
certificate the Server issues carries
([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md),
[ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)),
the statements the renewal and bootstrap proofs sign
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
the package statement
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)),
the signing file format
([ADR-0027](0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md)),
the header of a Gateway's binding store
([ADR-0058](0058-a-gateways-bindings-outlast-its-restart-and-end-with-their-hosts-certificate.md)),
and the key of the advisory lock that keeps one Server per PostgreSQL schema
([ADR-0050](0050-the-servers-records-may-live-in-postgresql.md) clause 6). A
rename of one of them invalidates every certificate, signature and file made
with the old spelling.

No installation is carried over: this project starts its releases afresh, so
nothing exists that the old spelling would have to keep readable. Renaming those
strings now costs nothing; renaming them after the first release would cost
every enrolled host, signed package and stored file.

## Decision

We will name the product **Classis** in every name it gives itself, the strings
data is bound to included, and start without migrating anything.

1. **The crates** are `classis-core`, `classis-server`, `classis-agent` and
   `classis-tools`, under directories of the same names; `opamp` keeps its name.
2. **The Client's product** defaults to the name `classis` and the title
   _Classis Agent_
   ([ADR-0064](0064-no-program-of-the-product-is-built-for-macos.md)
   clause 6). Its services are `classis` and `classis-agents`, its account
   `classis` (`NT SERVICE\classis` on Windows), the account of its Managed
   Processes `classis-agents`, and its directories follow the product name:
   `/opt/classis`, `/var/lib/classis`, `/usr/libexec/classis`,
   `/run/classis-agents`. Its own telemetry's instrumentation scope is
   `classis-client`.
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
5. **The strings data is bound to** are the certificate URIs
   `urn:classis:host:`, `urn:classis:renewal:v1:` and
   `urn:classis:bootstrap:v1:`, the statements `classis-renewal-v1`,
   `classis-bootstrap-v1` and `classis-package-v1`, the signing file format
   `classis-signing-v1`, the binding store header `classis-gateway-bindings`,
   and the advisory lock's key `classis-server:`. Their versions stay `v1`: the
   format did not change, only its name.
6. **Nothing is migrated.** No old name is still read, no old path moved, and no
   upgrade notes are written: there is no installation to upgrade.

**Out of scope:** the domain term _Fleet_ and everything spelled after it — the
glossary entry, `fleet.host.*`, the `fleet` Deployment of the tests,
`--fleet-files`, `crates/classis-server/src/fleet.rs`. The build variables
`OPAMP_PRODUCT_NAME` and `OPAMP_PRODUCT_TITLE`, which name the protocol, not the
product.

## Alternatives considered

- **Keep the old spelling of the strings data is bound to** — what an
  installation that has to survive the rename needs. None has to, and every
  reader would take the `opamp-fleet` left in them for a leftover, kept from
  being "fixed" only by tests that exist for that alone.
- **Rename only the crates** — no operator-visible change, but the program, the
  services and the image would carry a name the project no longer has.
- **A transition period** — the Server reading `FLEET_SERVER__…` beside the new
  variables, the install moving an old layout. Code and tests that exist only to
  be removed, for installations that do not exist.
- **`opamp-classis-…`** — keeps the protocol prefix, so the names stay long;
  `classis` is not taken by another tool on a `PATH` the way `fleetctl` was
  ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)).

## Sources / Prior art

- The ADRs that fixed the old names: ADR-0010 (crates), ADR-0019 (product name
  and layout), ADR-0028 (operator program), ADR-0051 (variables), ADR-0052
  (image), and those that spelled the strings of clause 5; their bodies were
  rewritten to the new names with the human's explicit consent rather than
  superseded clause by clause, since the rename touches about a thousand
  mentions in fifty ADRs.

## Consequences

- Positive: one name for the product across crates, programs, packages, image,
  formats and documentation, with no exception to explain.
- Negative / trade-offs: a certificate, signature, signing file, binding store
  or Server made by a build from before the rename is not read by one after it;
  accepted because none is in use.
- Negative / trade-offs: accepted ADR bodies were edited, which
  [AGENTS.md §3](../../AGENTS.md#3-adr-rules) rule 5 forbids; the human made
  that exception for this rename, and git carries the original text.
- Follow-ups: from the first release on, a rename of a string of clause 5 is a
  format change with its own decision.

## Enforcement

**Not mechanically decidable:** that no name the project gives itself still
spells the old brand. A search for `opamp-fleet`, `OpAMP Fleet` and `FLEET_`
outside this ADR is the review step; it finds only the domain term _Fleet_ of
the out-of-scope list.
