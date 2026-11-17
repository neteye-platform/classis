# ADR-0064: The Server refuses a Package Signer named in its revoked-signers list

- **Status:** 🟢 accepted
- **Date:** 2026-11-17
- **Deciders:** Davide Zeni
- **Applies to:** the `[packages]` section of `server.toml`, the Package
  verification of `crates/classis-server/` (`RootsVerifier` in `config.rs` and
  the store's load and write checks in `packages.rs`)

## Context

A Client installs nothing without a valid signature
([`docs/SPECIFICATION.md`](../SPECIFICATION.md), Q-1, G-10). The release run
signs the Client's own Package with a Package Signer's key, kept in a GitHub
environment secret
([ADR-0062](0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md)).
A Package Signer is valid for 10 years
([ADR-0063](0063-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)
clause 2), and nothing ends it earlier. An exposed key signs Packages that every
Client accepts until the certificate expires, and ADR-0062 records that as an
accepted trade-off. ADR-0063 leaves "what stops a stolen Package Signer before
it expires" open, and its alternatives list revocation as left out by the human.

The forces:

- A fleet may reach 5,000,000 Agents. Any check a Client makes against the
  network, such as a CRL or OCSP, is new traffic at that scale and a new point
  of failure. The product stays slim, so a mechanism earns its place only when
  it is small.
- The Server already verifies every signature, on a write and when it loads its
  store, and it already withholds an entry whose signature does not verify
  while it keeps the signature (ADR-0063 clause 10). A Package reaches a Client
  only through the Server or a Gateway it feeds.
- A Package Signer's replacement is the Root custodian's work and a release run;
  it happens when an incident does, not on a schedule.

## Decision

We will let the Server refuse a Package Signer named in a list of SHA-256
certificate fingerprints in `server.toml`, so that it offers to nobody every
entry that signer signed.

1. **The list is `[packages] revoked_signers`.** Each item is the SHA-256 of the
   Package Signer's DER certificate, as 64 lowercase hex digits, the notation
   ADR-0063 uses for the Root's fingerprint. The list is empty by default and
   holds at most 64 items.
2. **A malformed list refuses startup.** An item that is not 64 hex digits, a
   duplicate, or a list over the limit stops the Server and names the setting,
   as Q-1 asks of an insecure configuration.
3. **The check follows the chain check.** `RootsVerifier` first verifies the
   signature up to the Roots (ADR-0063 clause 4). It then refuses a signature
   whose certificate's fingerprint is in the list, with a reason that names the
   revocation.
4. **It behaves as an expired Package Signer does.** On a write the Server
   answers `400` and stores nothing. On loading, an entry whose signature names
   a revoked signer is offered to nobody; the signature stays in the store. An
   entry shows `signature_state` `missing`. Removing the item and restarting
   offers the entry again.
5. **The Server reads the list at start.** A change takes effect on restart. The
   Server does not send the list to a Client, and a Client's own check
   (ADR-0063 clause 5) is unchanged.

**Out of scope:** how a Package is signed again after a revocation, which needs
a workflow that signs an existing release's checksums with a new Package Signer;
the Root custodian's issue of that Package Signer; a revocation the Client
knows; a list reloaded without a restart; a revocation of one Package by its
digest; a shorter life for Package Signer certificates.

## Alternatives considered

- **Nothing: keep the 10-year exposure.** This is today's accepted position. It
  leaves a stolen key valid for up to 10 years, with no way for an operator to
  act, against Q-1.
- **A revocation the Client checks, by CRL, OCSP or a list pushed to it.** It
  protects a Client that does not trust the Server. It costs traffic or new
  state on every Client at 5,000,000 Agents, a new protocol path, and a new
  failure mode, which is more than a slim product takes for a rare event.
- **A list kept in the Server's store and changed through the REST API.** It
  takes effect at once and is one truth for several replicas. It needs
  persistence, an endpoint, authorisation and limits, and the Server no longer
  keeps an audit log of changes. A restart for an emergency is acceptable.
- **A denylist of Package digests.** It leaves every legitimate Package valid
  and needs no signing again. It does not stop a new Package signed with the
  stolen key, whose digest is unknown, so it does not answer a stolen key.
- **A revocation with exceptions for digests already released.** It stops new
  Packages and keeps the old ones installable without signing again. It needs
  two lists, and the exceptions are frozen when the revocation lands. A reader
  would not find it slim enough for an event that has not happened.
- **Shorter Package Signer certificates.** It bounds the exposure without a
  list. It forces signing again of every supported version on a schedule, with
  no incident to justify it.
- **A minimum issue date in the certificate.** A signature carries no trusted
  time, and the verifier checks only the certificate's dates (ADR-0063 clause
  4), so nothing tells a Package signed before the theft from one signed after.

## Sources / Prior art

- [ADR-0063](0063-a-package-is-accepted-only-when-a-package-signer-the-compiled-in-package-root-issued-signed-it.md)
  clauses 2, 4, 5 and 10 and its Out of scope and Alternatives sections.
- [ADR-0062](0062-the-release-run-signs-every-entry-of-the-clients-own-package-with-a-key-only-a-reviewed-version-tag-reaches.md),
  Consequences, on the exposed key.
- [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md),
  the Server's revocation list for client certificates, read for how the product
  already revokes. It is a different object and is not reused.
- `crates/classis-server/src/packages.rs` and `config.rs`, read on 2026-11-17,
  for the load and write checks and `RootsVerifier`.
- RFC 5280 section 5 (CRL) and RFC 6960 (OCSP) were not consulted: the decision
  rejects a Client-side check on cost, not on their content.

## Consequences

- Positive:
  - An operator can end the trust in a stolen Package Signer on the Server
    without a release and without touching a Client.
  - It adds one configuration list and one comparison, on a path that exists.
  - No Client sends or receives anything new.
- Negative / trade-offs:
  - Every version signed by a revoked signer is offered to nobody until it is
    signed again by a new Package Signer. A reinstall of an old version waits
    for it.
  - A Server that is compromised, or a Package that reaches a Client by another
    route, is not covered. A Client already running a Package it accepted keeps
    it.
  - A change needs a restart. With several Servers the list differs among them
    until the last one restarts.
- Follow-ups:
  - the workflow that signs an existing release again with a new Package
    Signer;
  - whether a Client should learn a revocation on a connection it already has;
  - the documentation of the list in the Server's manual and in
    `config/server.toml`.

## Enforcement

Four tests cite this ADR with a `Verifies:` marker, with a test Root and a test
Package Signer:

- in `crates/classis-server/src/config.rs`, the list admits only lowercase
  SHA-256 fingerprints, each once, at most 64, and a malformed list fails the
  configuration check;
- in the same file, the verifier refuses a listed signer and no other;
- in `crates/classis-server/src/packages.rs`, a write of a listed signer's
  signature is refused, an entry stored with it loads as `missing` and keeps its
  signature, and it is offered again once the signer is no longer listed.
