# ADR-0046: One bootstrap certificate holds at most a quarter of the enrolment queue

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the pending queue in `crates/fleet-server/src/enrolment.rs` and its answer on an enrolment connection in `crates/fleet-server/src/transport.rs`, the `[enrolment]` section of `server.toml` and its parsing in `crates/fleet-server/src/config.rs`, and every document that tells an operator how many requests may wait
- **Supersedes:** [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 21

## Context

While an enrolment window is open, a host holding a bootstrap certificate may file a CSR, and the
CSR waits in a pending queue for an operator
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
clause 21). The queue is keyed by the request's public key, so a re-sent CSR joins its own entry.
It holds at most 1024 requests in all, and nothing counts them per bootstrap certificate
(`MAX_PENDING` in `crates/fleet-server/src/enrolment.rs`). One connection may file a request for
one key after another.

Whoever holds one bootstrap certificate can therefore fill the whole queue with requests for fresh
keys. Every other host is then answered `Unavailable` until the window closes, and the operator's
list is buried. A bootstrap file may be opened offline when its password is weak
([ADR-0030](0030-a-pkcs12-password-of-4-to-128-characters.md)), and one certificate may be meant
for many hosts: the code says so where it throttles enrolling hosts per address. Revoking the
certificate withdraws its waiting requests (ADR-0021 clause 35), which ends the flood once an
operator notices it.

A bound per certificate must not stop the legitimate case of one bootstrap certificate handed to a
whole site that enrols at once.

The specification's quality goal Q-2 asks that untrusted input be bounded.

## Decision

We will let the requests of one bootstrap certificate take at most a configurable share of the
enrolment queue, a quarter of it by default.

1. **Restates ADR-0021 clause 21. An enrolment connection may only send a CSR, and the CSR waits
   for an operator.** It is admitted only while the window is open; outside a window it is
   answered `503`, which ADR-0021 clause 24 does not count, so hosts waiting for an operator
   cannot throttle the members behind the same address. The Server reads nothing from its messages
   but `connection_settings_request.opamp.certificate_request`: it creates no Agent record, assigns
   nothing and makes no offer but the issued certificate. A message without a CSR is answered with
   the Server's capabilities and nothing else, so the Client learns it may send one. The CSR enters
   a pending queue keyed by its public key, so a re-sent CSR joins its own entry; the Client keeps
   its pending key and re-sends the same CSR until it is answered. The queue holds at most 1024
   requests. The requests of one bootstrap certificate, by its issuer and serial, hold at most
   `[enrolment] max_pending_per_bootstrap` of them, 256 by default; the value runs from 1 to 1024,
   and anything else fails startup naming the key. A CSR beyond either bound is answered
   `ServerErrorResponse` `Unavailable` with `retry_info`, and one beyond the share of its bootstrap
   certificate is audited once per certificate and window as `enrolment.refused` with the reason.
   A re-sent CSR that already has its entry is never refused by either bound. On approval the
   Server signs it (ADR-0021 clause 9) and offers the certificate on that connection the way it
   offers any certificate; the Agent then reconnects with it. On rejection the CSR is answered
   `BadRequest`, and the connection is closed.

**Out of scope:** a rate per bootstrap certificate, as opposed to a share of the queue; a bound per
bootstrap certificate on how many hosts it may enrol in all; enrolment through a Gateway.

## Alternatives considered

- **A small fixed bound, such as 16 per certificate.** This stops a flood sooner, but a bootstrap
  certificate handed to one site cannot then enrol more than 16 hosts in one window. Rejected.
- **No bound, rely on revocation.** Revoking the certificate ends the flood, but only once an
  operator sees it, and every honest host is refused until then. Rejected.
- **A bound per peer address.** Hosts behind one NAT or one Gateway share an address, and one
  attacker can use many. The certificate is what the Server can count reliably. Rejected.
- **Grow the queue.** A larger queue moves the bound but does not stop one certificate from taking
  all of it. Rejected.

## Sources / Prior art

- The code as it stands: `MAX_PENDING` and `submit` in `crates/fleet-server/src/enrolment.rs`;
  `enrol` in `crates/fleet-server/src/transport.rs`, which files one request per CSR whatever key
  it names.
- The bootstrap certificate's `CertId` is already part of every request's `Requester`
  (`crates/fleet-server/src/enrolment.rs`), and revocation already withdraws by it.

## Consequences

- Positive: one bootstrap certificate can block at most a quarter of the queue. Four certificates
  would be needed to fill it, and each can be revoked on its own.
- Negative / trade-offs: a site that enrols more than 256 hosts with one bootstrap certificate in
  one window waits for the operator to approve some, or raises the key. A new key in
  `server.toml`.
- Follow-ups: a rate per bootstrap certificate, which enrolment through a Gateway needs, since all
  of its requests arrive from one address.

## Enforcement

Tests that will carry `Verifies: ADR-0046`:

- With `max_pending_per_bootstrap = 2`, a third request of one bootstrap certificate is answered
  `Unavailable` and audited, a request of another bootstrap certificate is still queued, and a
  re-sent request of the first certificate still joins its entry.
- `max_pending_per_bootstrap = 0` and `= 1025` fail startup naming the key.
