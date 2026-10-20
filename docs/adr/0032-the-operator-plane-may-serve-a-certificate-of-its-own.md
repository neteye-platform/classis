# ADR-0032: The Operator plane may serve a certificate of its own, from `[rest.tls]`, and serves `[tls]`'s without it

- **Status:** 🟢 accepted
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** the `[rest.tls]` section of `server.toml` and its parsing and startup checks in `crates/fleet-server/src/config.rs`, the TLS material of both planes in `crates/fleet-server/src/tls.rs` and `crates/fleet-server/src/main.rs`, the certificates `server pki status` lists and the running Server watches in `crates/fleet-server/src/pki.rs`, `config/server.toml`, and every document that tells an operator which certificate the Operator plane serves or how a browser or `opamp-fleetctl` trusts it
- **Supersedes:** [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md) clause 9

## Context

The Server has two listeners split by audience
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
clause 10): the Agent plane, which every host dials and which admits by client certificate alone
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
and the Operator plane, which serves the REST API, the API docs and the bundled UI to browsers and
to `opamp-fleetctl`. ADR-0013 clause 9 gives both one certificate and key, `[tls] cert_file` and
`key_file`, and says: "There are no per-listener certificates."

That one certificate is made by `opamp-fleetctl pki` from the fleet's own server CA
([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clauses 1 and 6).
The Clients trust that CA because their `[tls] ca_file` names it. A browser does not: the
operator's manual tells the operator to import the server CA into every browser that opens the UI.
In an organization with its own PKI, the UI is expected to present a certificate from that PKI,
which every managed browser already trusts. The Agent plane cannot take that certificate instead,
because every Client trusts the fleet's server CA and nothing else.

One certificate also puts the key every Client's trust rests on behind the listener that faces
browsers. Both keys still live in one process, so a compromise of the process reaches both. What a
second certificate separates is what an operator handles: the PKI's certificate can be renewed,
replaced or handed to the people who run the PKI without touching the key the fleet trusts.

The decision serves G-17 (the connection is secured) and Q-1 (secure by default) unchanged. TLS 1.3
alone, plaintext on the loopback alone, and no client certificate on the Operator plane stay as
ADR-0013 and ADR-0021 decide them.

The human settled with the author: the Operator-plane certificate comes from the operator's own
PKI, not from `opamp-fleetctl`. A new certificate takes effect when the Server restarts. Without
the new section the Server serves as it does today, so an existing installation starts unchanged
after the update.

## Decision

We will let `server.toml` name a certificate and key for the Operator plane in an optional
`[rest.tls]` section, which the Operator plane serves in place of `[tls]`'s, and keep `[tls]`'s on
the Operator plane when the section is absent.

1. **Restates ADR-0013 clause 9. `[tls]` is required and serves the Agent plane, and the
   Operator plane too unless `[rest.tls]` is present.** `[tls] cert_file` and `key_file` serve the
   Agent plane, with ALPN `h2` and `http/1.1`. A Server without `[tls]` is refused at startup with a
   message naming the section. `[tls] client_ca_file` applies to the Agent plane alone, and what it
   requires is ADR-0021's. Without `[rest.tls]`, the Operator plane serves `[tls] cert_file` and
   `key_file` as well, with the same ALPN.
2. **`[rest.tls]` holds `cert_file` and `key_file`, both required, and nothing else.** `cert_file`
   is a PEM chain, the leaf first and any intermediates after it. `key_file` is its PEM private key.
   A `client_ca_file` or any other key in the section fails at startup: the Operator plane asks for
   no client certificate. The Operator plane serves the pair with ALPN `h2` and `http/1.1` and
   TLS 1.3 alone, as ADR-0013 decides for every listener.
3. **The pair is checked at startup as `[tls]`'s is.** A file that cannot be read, a `cert_file`
   with no certificate, a `key_file` with no usable private key, and a key that does not match the
   certificate each refuse the start with a message naming the file. The Server checks nothing
   else about the certificate: not its names, not its issuer, and not its naming. It is the
   operator's PKI that answers for those.
4. **A new certificate takes effect when the Server restarts.** The files are read once, at
   startup. Replacing them changes nothing that is served until the next start.
5. **`[rest.tls] cert_file` is a certificate the Server depends on.** `server pki status` lists it,
   and the running Server warns before it ends, at startup and daily, under the rule of ADR-0028
   clause 11. A file named in both `[tls]` and `[rest.tls]` is listed once.

**Out of scope:**

- Reloading a certificate without a restart.
- A client certificate for operators on the Operator plane.
- A certificate from `opamp-fleetctl` for the Operator plane. Its `pki server-cert` still makes one
  from the server CA, which `[rest.tls]` may name like any other.
- Selecting a certificate by SNI on one listener.

## Alternatives considered

- **Keep one certificate for both planes.** This is the status quo. Every browser has to trust the
  fleet's server CA, and the UI cannot present the organization's own certificate.
- **`[rest.tls]` required whenever `[rest] listen` is beyond the loopback.** This would enforce the
  separation where browsers reach the UI. It was not chosen: an existing installation that serves
  the UI beyond the loopback would not start after the update until the section is added. The
  human chose the optional section.
- **The UI certificate from `opamp-fleetctl`, signed by the fleet's server CA.** The keys would be
  separated, but browsers would still have to trust the fleet's server CA.
- **One certificate naming both audiences, from the organization's PKI.** The Clients would then
  have to trust the organization's PKI, which widens what a Client accepts as the Server to
  whatever that PKI signs.
- **A reverse proxy in front of the Operator plane that terminates TLS with the PKI's certificate.**
  This needs no change to the Server, but adds a component to run and harden. Unless the Server
  trusts a forwarded header, the audit and the throttling see the proxy's address in place of the
  operator's. An operator may still run one. This decision makes it unnecessary for the
  certificate alone.
- **Reloading the files when they change.** This suits short-lived PKI certificates, but needs a
  file watch or a signal and a resolver that swaps the key at run time. The human chose a restart.
  It is left open (see *Out of scope*).

## Sources / Prior art

- rustls 0.23.46, `CertifiedKey::from_der` in `src/crypto/signer.rs`: loading a certificate and key
  compares the key's SubjectPublicKeyInfo with the certificate's and refuses a mismatch. This is
  what makes clause 3's mismatch a startup failure. It was read in the crate's source, not recalled.
- ADR-0013 clauses 9 and 10, ADR-0021, ADR-0028 clauses 1, 6 and 11, and ADR-0009 for superseding
  one clause.
- `docs/manual/setup.md`: the server CA in "your browser's trust store", which this decision makes
  optional.

## Consequences

- Positive: browsers trust the UI through the organization's PKI, with no fleet CA to import. The
  key every Client trusts is no longer the one that the people who run the UI's certificate
  handle and renew.
- Positive: an existing `server.toml` keeps working unchanged.
- Negative / trade-offs: an operator who uses the section renews two certificates on two
  schedules. The expiry warnings name both.
- Negative / trade-offs: a PKI certificate rarely names `127.0.0.1`. An operator who reaches a
  loopback Operator plane through an SSH tunnel then dials the certificate's host name, for example
  through an `/etc/hosts` entry. The manual says so.
- Negative / trade-offs: `opamp-fleetctl package fetch --cacert` names the CA that the Operator
  plane's certificate chains to. With a PKI certificate, that is the PKI's CA, or nothing when the
  system's roots hold it.
- Follow-ups:
  - The running Server's daily check reads the file, not the certificate it serves. A file replaced
    without a restart silences the warning while the old certificate is still served. This holds
    for `[tls]` today, and is a fix within ADR-0028 clause 11.
  - Whether to reload certificates without a restart.
  - Whether operators should present client certificates on the Operator plane.

## Enforcement

Tests that will carry `Verifies: ADR-0032`:

- With `[rest.tls]`, the Operator plane presents that certificate and the Agent plane presents
  `[tls]`'s. Without it, both present `[tls]`'s.
- A `[rest.tls]` whose key does not match its certificate, one missing `key_file`, and one carrying
  `client_ca_file` are each refused at startup, and the message names the file or the key.
- `pki::depended_on` lists `[rest.tls] cert_file`, and lists a file named in both sections once.
