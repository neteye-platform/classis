# ADR-0048: A bootstrap PKCS#12 password is 8 to 128 characters

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the password rule of `crates/fleet-core/src/pkcs12.rs` and its callers, the password field of the Enrolments tab of the bundled UI in `crates/fleet-server/static/index.html`, the `400` text of `POST /api/v1/bootstrap-certificates`, and every document that states how long a bootstrap password is
- **Supersedes:** [ADR-0030](0030-a-pkcs12-password-of-4-to-128-characters.md)

## Context

A bootstrap certificate may be issued as a PKCS#12 file under a password the operator chooses
([ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)).
[ADR-0030](0030-a-pkcs12-password-of-4-to-128-characters.md) allows 4 to 128 characters, so that
an operator can read a password out and type it by hand per host, and accepts that a leaked file
with a four-character password opens offline in hours of GPU time under PBKDF2-HMAC-SHA-256 at
600 000 iterations.

Whoever opens a leaked file can file enrolment requests while a window is open. The approval by an
operator stays the barrier for admission, but the requests themselves now weigh more: they take
places in the queue, of which one bootstrap certificate may hold a quarter
([ADR-0046](0046-one-bootstrap-certificate-holds-at-most-a-quarter-of-the-enrolment-queue.md)),
and they now arrive through Gateways too
([ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md) clause 12). The hardening of the link is the project's first
priority.

Eight characters drawn from the 95 printable ASCII characters have about 6.6 × 10¹⁵ values. At
600 000 PBKDF2 iterations per guess that is out of practical reach of an offline attack on one
file. It is still short enough to read out.

## Decision

We will take a bootstrap password of 8 to 128 characters of UTF-8 without control characters in
place of ADR-0030's 4 to 128.

1. **Restates ADR-0030 clause 1. A password is 8 to 128 characters of UTF-8 without control
   characters.** Anything else is answered `400`. The rule applies where a password is chosen, when
   a bootstrap certificate is issued; a file issued before opens with the password it was issued
   under. The password is not stored, logged or audited anywhere, on the Server or on the host. It
   reaches the Server on the Operator plane, which beyond the loopback serves TLS only
   ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
   clause 17).

**Out of scope:** a strength rule beyond the length, and a password the Server generates. Each can
be added later without contradicting this clause.

## Alternatives considered

- **Keep 4 characters.** Operators type less, but a leaked file opens in hours. Rejected: the
  barrier it leaves is the operator's approval alone.
- **12 characters, as ADR-0029 first had.** Stronger, but operators found it too long to read out
  per host. Rejected.
- **A password the Server generates and shows once.** Strong without a choice to type, but the
  issuing route would return a secret. Left open.

## Sources / Prior art

- NIST SP 800-63B, section 5.1.1.2: a memorized secret of at least 8 characters. Recalled, not
  re-read for this record.
- OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA-256 at 600 000 iterations, the figure ADR-0029
  clause 1 uses. Recalled, not re-read for this record.

## Consequences

- Positive: a leaked `bootstrap.p12` no longer opens in hours.
- Negative / trade-offs: an operator types four more characters per host.
- Follow-ups: a password the Server generates.

## Enforcement

Test that will carry `Verifies: ADR-0048`: `check_password` takes 8 and 128 characters, and answers
7 and 129 characters and a control character with its `400` text. The Server's issuing route
answers `400` for a password of 7 characters and issues one of 8. The tests that verify ADR-0030
move to this ADR.
