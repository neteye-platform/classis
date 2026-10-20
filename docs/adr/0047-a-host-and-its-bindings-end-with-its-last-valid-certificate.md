# ADR-0047: A Host and its bindings end with its last valid certificate, and forgetting an Agent releases its binding

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the host register in `crates/fleet-server/src/revocation.rs` and its filesystem adapter, the forgetting of an Agent in `crates/fleet-server/src/fleet.rs` and the `DELETE /api/v1/agents/{instance_uid}` route of `crates/fleet-server/src/api.rs`, and every document that tells an operator when a Host or a binding ends
- **Supersedes:** [ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md) clause 1; [ADR-0024](0024-the-fleet-record.md) clause 11

## Context

A Host speaks for the `instance_uid`s bound to it, and an `instance_uid` is spoken for by the host
whose certificate first reported it
([ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)
clause 2). A Host is removed when it has no valid certificate, no bound Agent and no Gateway mark
([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)
clause 1).

Nothing releases a binding. Forgetting an Agent removes its record but leaves its `instance_uid`
bound ([ADR-0024](0024-the-fleet-record.md) clause 11; `owners` in
`crates/fleet-server/src/revocation.rs` loses an entry only on a re-key). A Host with a bound
Agent is therefore never removed, even long after its last certificate expired. The register grows
with every approval for the life of the installation, up to 256 bindings per host, and each new
binding rewrites the whole hosts file.

A binding guards against one thing: another host taking over an Agent that a host still speaks for.
Once no certificate naming a host is valid, nobody can speak as that host again — renewal needs a
valid certificate (ADR-0021 clause 27), and a host that enrols again gets a new host id. Its
bindings then guard nothing.

The Server cannot always tell whether a host still holds a valid certificate from its register
alone. A certificate an operator provisioned with a host id is valid without ever having been
registered (ADR-0035 clause 1). What the Server does see is every certificate a host presents.

The specification's quality goal Q-2 asks that what untrusted input makes the Server hold be
bounded.

## Decision

We will release a Host's bindings, and the Host, once no certificate naming it is valid, and
release an Agent's binding when an operator forgets it.

1. **Restates ADR-0035 clause 1. A Host is created when its enrolment is approved, and ends when
   no certificate naming it is valid.**
   - The approval that mints a host id writes the Host. Its record holds:
     - the subject values of the client certificate it was issued: country, state, locality,
       organization, organizational unit, organization identifier. Which of them a certificate
       carries is the decision on carrying the bootstrap certificate's subject over; without it,
       none.
     - its Gateway mark;
     - the `instance_uid`s bound to it;
     - the time of the approval;
     - its **valid until**: the latest `not_after` of a certificate naming it that the Server
       issued or that it presented in a handshake. Every issuance and every admission moves it
       forward, never back.
   - A certificate an operator provisioned with a host id makes a Host at its first report.
   - A Host the approval could not write is written with the next write of the host register, and
     at the latest at its first report, from the values its certificate carries. The approval is
     not refused for it: the certificate is signed and registered by then, and the values are in
     the certificate.
   - Once its valid until has passed, a Host that is not marked as a Gateway is removed, and every
     `instance_uid` bound to it is released. A Gateway's Host stays until its mark is taken away,
     because its certificate may be one the operator provisioned and never presented. A Host
     written before it had a valid until takes the latest `not_after` the register holds for it,
     and stays until its next admission when the register holds none.

2. **Restates ADR-0024 clause 11. Forgetting drops what the Server knows and reaches no host.**
   `DELETE /api/v1/agents/{instance_uid}` removes the record from the fleet and from the store, and
   releases the `instance_uid` from the Host it was bound to. No process is stopped, no
   configuration withdrawn, no package removed, no credential revoked. The word in the API
   description, the UI, and the manual is **forget**, never *delete*, *remove*, or *unenrol*. An
   Agent still running comes back as a stranger: the Server demands `ReportFullState`, as for any
   unknown Agent, and the row returns complete — re-offered its configuration, connection
   settings, and packages. Its first report binds it again, to the host whose certificate carried
   that report.

**Out of scope:** writing the host register incrementally instead of whole; a global bound on the
number of Hosts, which approvals and provisioned certificates already limit.

## Alternatives considered

- **Judge validity by the register alone.** A Host with a provisioned certificate that the
  register never held would lose its bindings while its certificate is still valid, and another
  host could take over its Agents. Rejected.
- **Release only on forget.** Bindings of hosts that are gone for good would stay until an
  operator forgets every one of their Agents. Rejected as the only rule; kept as the second one.
- **Expire bindings after a time without a report.** A host that is off for a while would lose
  its Agents to whoever reports them first while its certificate is still valid. Rejected.
- **Keep everything.** The register grows for the life of the installation. Rejected.

## Sources / Prior art

- The code as it stands: `prune` in `crates/fleet-server/src/revocation.rs` keeps every host with
  a bound `instance_uid`; `owners` loses an entry only in `rebind`; `forget_agent` in
  `crates/fleet-server/src/fleet.rs` does not touch the host register.

## Consequences

- Positive: the host register shrinks with the fleet. A forgotten Agent can be reported by
  whichever host runs it now.
- Negative / trade-offs: forgetting an Agent that still runs lets the next host that reports its
  `instance_uid` bind it — the operator's act decides that, as it decides the forgetting. The host
  record gains one field.
- Follow-ups: writing the host register incrementally.

## Enforcement

Tests that will carry `Verifies: ADR-0047`:

- A Host whose only certificate has expired, with a bound Agent, is removed at the next prune and
  its `instance_uid` can be bound by another host; a Gateway's Host is not removed.
- A Host whose provisioned certificate is not in the register but was presented and is valid keeps
  its bindings.
- Forgetting an Agent releases its binding: another host's report for it binds it.
