# ADR-0030: A bootstrap PKCS#12 password is 4 to 128 characters

- **Status:** ⚪ superseded by [ADR-0048](0048-a-bootstrap-pkcs12-password-of-8-to-128-characters.md)
- **Date:** 2026-10-15
- **Deciders:** Markus Brigl
- **Applies to:** the password rule of `crates/fleet-core/src/pkcs12.rs` and its callers, the password field of the Enrolments tab of the bundled UI in `crates/fleet-server/static/index.html`, the `400` text of `POST /api/v1/bootstrap-certificates`, and every document that states how long a bootstrap password is
- **Supersedes:** [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md) clause 2

## Context

[ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
clause 2 requires a bootstrap password of 12 to 128 characters. The operator types this password
twice: once when issuing the certificate in the Enrolments tab, and once on the host, at the
install's hidden question or into the file `--bootstrap-password-file` reads. Operators find
twelve characters too long for a password that they read out or type in by hand, often for
one host at a time.

The password protects one thing: the bootstrap key inside `bootstrap.p12`. That key does not admit
a host to the fleet. It lets a host file an enrolment request, and only while an operator holds the
enrolment window open. Every request then waits for an operator's approval
(ADR-0021 clauses 10 and 22). A bootstrap certificate lives 10 days by default and 90 at most
(ADR-0028 clause 23), and its `.p12` can be downloaded only by an operator on the Operator plane.

A short password is easier to break offline. A password of four characters drawn from the 95
printable ASCII characters has about 8.1 × 10⁷ values. Under PBKDF2-HMAC-SHA-256 at 600 000
iterations (ADR-0029 clause 1), that is hours of GPU time for whoever holds a leaked file, not
centuries. The specification's quality goal Q-1 asks that nothing be admitted without a client
certificate. That still holds: a broken bootstrap file yields an enrolment request, not an
admission.

## Decision

We will take a bootstrap password of 4 to 128 characters of UTF-8 without control characters in
place of ADR-0029 clause 2's 12 to 128.

1. **Restates ADR-0029 clause 2. A password is 4 to 128 characters of UTF-8 without control
   characters.** Anything else is answered `400`. The password is not stored, logged or audited
   anywhere, on the Server or on the host. It reaches the Server on the Operator plane, which
   beyond the loopback serves TLS only (ADR-0021 clause 17).

**Out of scope:** a strength rule beyond the length, a warning for short passwords, and a password
the Server generates. Each can be added later without contradicting this clause.

## Alternatives considered

- **Keep 12 characters.** This is the stronger file, but operators find it too long for a password
  read out and typed by hand per host. That is the reason for this decision.
- **8 characters.** This gives about 6.6 × 10¹⁵ values of printable ASCII, out of practical reach
  of an offline attack. It was not chosen because the operator asked for four.
- **4 characters, with a warning below 12 in the UI and the API.** This keeps the choice and states
  the risk each time. It was not chosen; the operator is told once, in this record and in the
  documents.
- **A password the Server generates and shows once.** This gives the strength without typing a
  choice, but the operator still has to carry it to the host. It would also turn the issuing route
  into one that returns a secret. It is left open (see *Out of scope*).

## Sources / Prior art

- NIST SP 800-63B, section 5.1.1.2: a memorized secret of at least 8 characters, unless the verifier
  rate-limits online guessing. A `.p12` that has leaked is attacked offline, where no rate limit
  applies. Consulted from memory, not re-read for this record.
- OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA-256 at 600 000 iterations, the figure ADR-0029
  clause 1 uses. It slows each guess, but does not make a small value space large.

## Consequences

- Positive: an operator can hand out a password short enough to read out and type per host.
- Negative / trade-offs: a leaked `bootstrap.p12` with a four-character password can be opened
  offline in hours. Whoever opens it can file enrolment requests while a window is open, so
  approval by an operator is then the only barrier. Operators who approve requests without checking
  the host lose that barrier too. This trade-off is accepted. The documents that tell an operator
  how to issue a bootstrap certificate say so.
- Follow-ups: whether a short password should be marked when the certificate is issued (for example
  in the audit entry, without the password); and whether the Server should offer a generated
  password.

## Enforcement

Test that will carry `Verifies: ADR-0030`: `check_password` takes 4 and 128 characters, and answers
3 and 129 characters and a control character with its `400` text. The Server's issuing route
answers `400` for a password of 3 characters and issues one of 4.
