# ADR-0021: Admission by a client certificate alone — required in the handshake, every enrolment approved by an operator, the Operator plane guarded beyond the loopback, server.toml holding no credential that authenticates on its own, and a CSR naming an instance_uid signed only when it names its sender's — and a revocation list that follows renewal, reaches the Gateways and ends every session whose certificate is revoked or expires

- **Status:** 🟢 accepted · clause 12 superseded by
  [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  · clauses 7 and 22 superseded by
  [ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)
  · clauses 20, 33 and 37 superseded by
  [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
  · clauses 27 and 42 superseded by
  [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)
  · clause 21 superseded by
  [ADR-0046](0046-one-bootstrap-certificate-holds-at-most-a-quarter-of-the-enrolment-queue.md)
- **Date:** 2026-10-06
- **Deciders:** Markus Brigl
- **Applies to:** Admission on `/v1/opamp` in
  `crates/fleet-server/src/transport.rs`, `tls.rs` and `ca.rs`, the Operator
  plane's credential in `crates/fleet-server/src/credentials.rs`, enrolment in
  `crates/fleet-server/src/enrolment.rs`, admission throttling in
  `crates/fleet-server/src/throttle.rs`, the Operator plane's guard and the
  `/api/v1/enrolment/window` and `/api/v1/enrolments` routes in
  `crates/fleet-server/src/api.rs`, the admission of the package download route,
  the Client's identity and enrolment in `crates/fleet-agent/src/config.rs`,
  `tls.rs` and `csr.rs`, the host a certificate is issued to and the renewal
  proof in `crates/fleet-core/src/renewal.rs`,
  `crates/fleet-server/src/revocation.rs` and `fleet.rs`, the `/api/v1/hosts`
  routes, the identity the Client presents on a download in
  `crates/fleet-agent/src/packages.rs`, the reading of a CSR in
  `crates/fleet-server/src/ca.rs`, the CSR handling on a member connection in
  `crates/fleet-server/src/fleet.rs` and on an enrolment connection in
  `crates/fleet-server/src/transport.rs`, the `[tls]`, `[client_ca]`,
  `[enrolment]`, `[admission_throttle]` and `[rest.auth]` sections of
  `server.toml`, the `[tls]` section of `supervisor.toml`, an `[auth]` section
  in either file, and the Server's `hash-credential` command in
  `crates/fleet-server/src/main.rs`; admission on `/v1/opamp` and on the
  download route in `crates/fleet-server/src/transport.rs`, the WebSocket
  session loop there, the certificate register and revocation list in
  `crates/fleet-server/src/revocation.rs` and
  `crates/fleet-server/src/fs/revocation.rs`, the close frame
  `crates/opamp/src/server.rs` sends, the serial numbers
  `crates/fleet-server/src/ca.rs` assigns, the `/api/v1/revocations` and
  `/api/v1/certificates` routes in `crates/fleet-server/src/api.rs`, the
  Gateways' `/v1/gateway/revocations` route on the Agent plane, and the files
  they persist under `config_dir`

## Context

A fleet credential as a second proof beside the client certificate would prove
nothing the certificate does not prove better, and would cost more than any
other part of admission. Such a credential is one value for the whole fleet. It
proves that a peer belongs to the fleet, never which host or Agent it is, and
every host keeps it in clear beside its private key, so whoever takes a host
takes both proofs at once. The client certificate proves membership too, and
also the host: it is issued per host, lives 30 days, is renewed automatically
and can be revoked one at a time. Behind a terminating Gateway a credential
every Agent shares does not tell one Agent from another either. Carrying it
costs a configuration section on both ends, a secret in clear in
`supervisor.toml`, its rotation through connection-settings offers, its
revocation by hash, and a Gateway pool partitioned by the credential each peer
presented. The [specification](../SPECIFICATION.md)'s Strategy _Security before
convenience_ and Q-1 _Secure by default_ ask for an Agent that proves fleet
membership with a client certificate in the TLS handshake, issued to its host.

The Operator plane keeps its own credential. A browser cannot present a client
certificate an operator does not already manage, and `server.toml` must still
hold no credential that authenticates on its own. A Basic password is chosen by
a person and needs a password hash: Argon2id, at least the parameters OWASP
names as its minimum (`m=19456`, `t=2`, `p=1`), compared in constant time.

Goal 17 of the [specification](../SPECIFICATION.md) asks for TLS on both ends,
mutual TLS, and a Server that accepts only authenticated Agent identities. TLS
([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md))
protects the channel and authenticates nobody. The Baseline treats
authentication as transport-level: methods MAY be used and `401` MUST be
returned on failure. Its CSR flow — a regular TLS connection, a keypair and CSR
generated by the Agent, a certificate issued by the Server as a local CA or by a
CA it proxies to, `BadRequest` when issuance fails — keeps the private key on
the host, and it answers the bootstrap chicken-and-egg with _"a bootstrap client
certificate that is already trusted by the Server"_, whose distribution it
leaves out of scope.

Forces that shape the answer:

- **Ecosystem practice is static headers, with client certificates optional.**
  `opamp-go` clients send static headers; the Collector's `opampextension` sets
  `headers` or delegates to `basicauthextension` or `bearertokenauthextension`.
  Every peer of the Agent plane already presents a client certificate in the
  handshake, so admitting on it alone excludes no client.
- **Authorization and tenancy are non-goals** of the specification: _that_ a
  peer belongs to the fleet is in scope, _which_ Agent may do _what_ is not.
- **`instance_uid` is self-asserted.** An Agent chooses it, and the Server may
  re-key it at any time with `AgentIdentification`. A certificate whose validity
  depended on matching it would die on a re-key the Server itself initiated.
- **A Gateway terminates.** A Client in Gateway Mode reads OpAMP to fold many
  Agents onto few connections
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)),
  so the certificate the Server sees belongs to the Gateway. The Gateway's own
  handshake is what proves a downstream peer.
- **A Client updates itself.** A Client of this version may start with a
  `supervisor.toml` written for the previous one, by the self-update of
  ADR-0018, with nobody at the host.
- **The Agent plane serves one route besides `/v1/opamp`:** the package download
  ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 8). A handshake that requires a certificate requires it there too, so
  the Client's downloader must present one — to the Server, never to a mirror
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
- **An approval means something only when the enrolling peer can be told
  apart.** A bootstrap certificate that chains to the same CA as an issued one
  is indistinguishable from it; a CA of its own makes an enrolment connection
  recognisable from its handshake.
- **The Baseline asks a Server to throttle.** `ServerErrorResponse`
  `Unavailable` with `retry_info`, and a plain-HTTP `429` or `503` with
  `Retry-After`, are its forms; the Client already honours both
  ([`HARDENING.md`](../HARDENING.md) H10).
- **The Operator plane's UI is one embedded page with no frontend toolchain.**
  Whatever guards the API must guard that page without a login form, a session
  store or a cookie. Tools whose UI is an operational page (Prometheus,
  Alertmanager, Traefik's dashboard) use HTTP Basic behind TLS; tools whose UI
  is the product (Grafana, BindPlane) ship sessions.

The Baseline, in _Using instance_uid in the CSR_: _"The Server MUST verify that
the instance_uid field in AgentToServer message matches the instance_uid in the
CSR fields"_, so an Agent cannot ask for a certificate in another Agent's name.
It prescribes no field: the `instance_uid` may sit in _"one of the CSR fields
(or part of the field)"_. Clause 7 calls the subject descriptive: the Server
does not require it to match `instance_uid` and drops requested SANs. That alone
leaves the conditional MUST unmet: a CSR that _does_ carry an `instance_uid`
would be signed whatever it carries.
[`CONFORMANCE.md`](../CONFORMANCE.md#mutual-tls-and-the-two-fields-still-refused)
records how it is met.

This project's own Client puts its `service.instance.name` in the common name
and no `instance_uid` anywhere, so it never triggers that check. A peer
implementation may, and interoperability with one is a stated target
([ADR-0011](0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md)).
The difficulty is recognising a claim without reading an ordinary descriptive
subject as one. The Baseline's `instance_uid` is 16 bytes and SHOULD be a UUID
v7; its textual form is the canonical 8-4-4-4-12 hexadecimal form of RFC 9562,
which a host name or a product name does not take by accident.

With an Agent admitted by a client certificate in the handshake and by nothing
else, a certificate is the one proof to revoke and there is no credential beside
it. Without a revocation list, two gaps follow, both recorded in
[`HARDENING.md`](../HARDENING.md) as H1 and H2:

- **A proof cannot be withdrawn.** A stolen certificate stays good until it
  expires, 90 days by default.
- **A session outlives its proof.** The certificate is checked once per
  WebSocket, at the upgrade. A session admitted yesterday keeps running even if
  the certificate that admitted it has since expired, and nothing could end it
  early if the certificate were withdrawn.

The specification puts security before convenience (Strategy _Security before
convenience_) and asks that the Server accept only authenticated Agent
identities (G-17, Q-1). An identity the operator no longer trusts is not
authenticated, however recently it was.

The Baseline names the answer itself: _"Since the Server knows what access
headers and a client certificate the Client uses, the Server can revoke access
to individual Agents by marking the corresponding connection settings as
'revoked' and disconnecting the Client."_ The Server is the only party on this
link that verifies anything, so revocation can be Server state; there is no
third party a CRL or OCSP responder would serve.

Three facts shape the decision:

- **The Server's certificates name no unique serial today.** `rcgen` derives a
  serial from the SHA-256 of the public key when none is set. A re-sent CSR for
  the same key gets the same serial twice, and a serial says nothing the key
  fingerprint does not.
- **Renewal changes the key.** A Client renews at two thirds of its
  certificate's life with a new key (clause 11). A host that renewed shortly
  before its old certificate was revoked would carry on with the new one.
- **A Gateway hides its downstream certificates.** The Server sees the Gateway's
  certificate on a pooled upstream connection
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md));
  the downstream certificate stays on the downstream hop, and nothing of the
  downstream Agent's proof reaches the Server.

## Decision

We will admit a peer to the Agent plane on one proof, a client certificate
required in the TLS handshake, issue a peer's first certificate only through an
enrolment an operator opens and approves, treat what admission proves as fleet
membership and the host a certificate was issued to, guard the Operator plane
with Basic credentials that are required beyond the loopback and kept in
`server.toml` only as a hash, and treat every canonical UUID text in a CSR's
subject or requested SANs as a claim to an `instance_uid`, answering a CSR whose
claims are not all the sender's own with a `ServerErrorResponse` of type
`BadRequest`.

We will also keep a persisted revocation list of certificates, by issuing CA and
serial and extended along every renewal the Server signed, check it at every
admission, end each WebSocket session as soon as the certificate that admitted
it is revoked or expires, and hand the certificates on it, resolved along their
chains, to every host an operator marked as a Gateway.

LOOPBACK below means the IP literals `127.0.0.1` and `::1`; a host name is never
loopback, `localhost` included.

1. **The Agent plane has no credential of its own.** `server.toml` has no
   `[auth]` section; one that is present is refused at startup with a message
   naming `[auth]` and saying that the Agent plane admits by client certificate
   alone. `/v1/opamp` and the download route read no `Authorization` header. One
   that is sent is ignored, never refused, so a Client of the previous version
   is admitted on its certificate. The Agent plane sends no `WWW-Authenticate`
   challenge.

2. **The Operator plane's credential primitive.** A presented Basic password is
   verified against the named user's Argon2id hash, and an unknown user costs
   the same verification against a hash made at startup at the highest cost any
   user's hash has, so the answer's timing does not tell which users exist. A
   password hash runs on a blocking thread, at most four at once; past that a
   request is answered `503` with `Retry-After: 1`. Before a credential is
   checked, the attempt is counted against the throttle of clause 24 — failures
   and attempts under way together may not exceed `max_failures` — and an IPv6
   peer is counted by its /64
   ([`credentials.rs`](../../crates/fleet-server/src/credentials.rs)). A
   verification that succeeded is remembered for ten minutes by the SHA-256 of
   the whole header value, in a table of at most 1 024 entries, and compared in
   constant time with `constant_time_eq`; a failed one is never remembered and
   counts toward the throttle of clause 24.

3. **The Client sends no credential.** `supervisor.toml` has no `[auth]`
   section. One that is present is ignored, with one notice at startup naming
   the section, and nothing from it is sent; a Client updated by the Server must
   keep connecting. An `Authorization` header persisted with earlier connection
   settings is dropped when they are loaded
   ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)).
   A `401` is logged as an admission failure and retried with the transport's
   backoff. The communication layer refuses `ws://` and `http://` to a host that
   is not LOOPBACK
   ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)).

4. **What the Server offers reaches only admitted members.** A
   connection-settings offer and a `[telemetry_offer]` carrying headers are sent
   only on a connection whose certificate was issued by the client CA. An
   enrolment connection (clause 21) receives no offer but the certificate it
   asked for.

5. **Client certificates on both transports, required in the TLS handshake.**
   `[tls] client_ca_file` in `server.toml` is required; a configuration without
   it is refused at startup naming the key. The Agent plane's listener verifies
   with `ClientAuth::Required` in `opamp`, whose roots are the client CA and,
   while `[enrolment]` is configured, the bootstrap CA (clause 19). A peer
   presenting no certificate, or one that chains to neither, fails the handshake
   and reaches no handler. `PeerCertificate` carries the handshake's certificate
   into the request; `/v1/opamp` still answers `401` without one, a second line
   behind the handshake. The Client presents its identity on `wss://` (its
   rustls `ClientConfig`) and on `https://` (a reqwest `Identity::from_pem`).

6. **The certificate is the whole of admission.** A connection is a member's
   when its certificate was issued directly by the client CA, is valid and is
   not revoked (clause 39); any other certificate that passes the handshake
   makes an enrolment connection (clause 19). No configuration admits a peer
   without a certificate. Behind a Gateway, the Gateway's handshake proves the
   downstream peer (clause 13).

7. **A certificate proves membership and its host, not an Agent's identity.**
   The Server does not require the subject to match `instance_uid`,
   `service.instance.name`, or anything else an Agent reports. The request may
   dictate neither the certificate's subject nor its powers: the Server sets the
   subject to the common name ADR-0028 clause 28 derives and nothing else, signs
   a client-authentication leaf only — `CA:FALSE`, `digitalSignature`,
   `clientAuth` — drops every requested SAN, and puts in one of its own, the URI
   `urn:opamp-fleet:host:<id>`. The CSR's subject is still listed with a pending
   enrolment (clause 22) and still searched for claims (clause 29). The host is
   minted when an operator approves an enrolment and carried on by every renewal
   (clause 27); a certificate an operator provisioned without one is given a
   host derived from its issuer and serial when it is first renewed. An
   `instance_uid` is spoken for by the host whose certificate first reported it:
   a connection presenting another host's certificate that reports for it is
   re-keyed through `AgentIdentification` to an identity of its own, and a CSR
   in that message may not claim the old one. A re-key an Agent asks for keeps
   its host. A host holds at most three valid certificates at a time and speaks
   for at most 256 `instance_uid`s. A Gateway carries other hosts' Agents, so an
   operator marks it as one — `PUT /api/v1/hosts/{host}/gateway` — and its
   certificate then speaks for any Agent; behind it, membership alone applies.
   `GET /api/v1/hosts` lists each host, whether it is a Gateway, what it speaks
   for and how many valid certificates it holds.

8. **A Client has two sources for its identity, and the issued one wins.** An
   operator may provision one in `supervisor.toml`'s `[tls]` (`cert_file` and
   `key_file`, both or neither, beside `ca_file`); a Server-issued pair is
   stored in `state_dir` as `client-cert.pem` and `client-key.pem`. The stored
   pair outranks the file, the same precedence persisted connection settings
   have; deleting it reverts to what the operator wrote. The private key is
   written `0600` on Unix and inherits the state directory's ACL on Windows
   ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)).

9. **The Server signs CSRs as a local CA while `[client_ca]` is configured.**
   `[client_ca]` names `cert_file`, `key_file` and `validity_days` (default 30,
   `0` refused; a month bounds what a certificate stolen unnoticed is good for,
   and a host offline for a fortnight still renews on its own); it is its own
   key, never the listener's, because the CA key is the fleet's trust anchor.
   `AcceptsConnectionSettingsRequest` is declared only while the section is
   present. A Client that holds no Server-issued certificate, or holds one in
   its renewal window, generates a keypair and a PEM CSR locally and sends it as
   `ConnectionSettingsRequest.opamp.certificate_request`, only once the Server
   has declared the capability
   ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
   clause 15). A CSR on a connection whose certificate chains to the client CA
   is signed at once; a CSR on an enrolment connection waits for an operator
   (clause 21). A CSR that does not parse, or that arrives while no
   `[client_ca]` is configured, is answered with a `ServerErrorResponse` of type
   `BadRequest`. The issued certificate travels back as an ordinary
   connection-settings offer with no private key in it.

10. **A bootstrap certificate carries a host to its first CSR, and an operator
    approves it.** It is issued by the bootstrap CA, never by the client CA, and
    the Server tells it apart from an issued one by that issuer. The Server
    issues it (ADR-0028 clause 21). Any number may be valid at once, one per
    customer, site or batch as the operator chooses, because none opens anything
    on its own: it needs an open enrolment window (clause 20) and an operator's
    approval (clause 21). A short validity limits its reach. Handing it to a
    host is the operator's job.

11. **Renewal starts at two thirds of the validity, and the old certificate
    stays until the new one is proved.** The Client asks again once its
    certificate is two thirds through its life and keeps presenting the old one
    until the candidate has been verified by connecting with it
    ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
    clause 5); on failure the previous certificate stays in force and the offer
    is reported `FAILED`.

12. **Issuance adds `rcgen`, `time` and `x509-parser`, and no system
    dependency.** `rcgen` (features stated: `crypto`, `ring`, `pem`,
    `x509-parser`) generates the CSR and signs it; `time` expresses validity;
    `x509-parser` reads a certificate's validity for the renewal window. The
    `ring` backend is the provider
    [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
    already installs, so no OpenSSL and no cmake enter the build. `ring`
    compiles C and assembly in its build script, so a C compiler is needed
    either way; what this keeps is the absence of system libraries.

13. **Mutual TLS is per hop, and a Gateway's handshake admits the peers behind
    it.** Between an Agent and the Server through a Gateway there are two
    mutual-TLS connections, each proving the peer at that hop. The Gateway holds
    its own client identity for the upstream leg, obtained through the same CSR
    flow, and admits a downstream peer by its handshake against the fleet's
    client CA and the Server's revocation list
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md),
    which also owns the Gateway's downstream TLS keys). The Server admits the
    Gateway, and the Gateway's mark (clause 7) lets its certificate speak for
    the Agents it carries.

14. **Admission is a fleet-wide trust boundary, and within it the host is the
    only bound between Agents.** A report's `instance_uid` is self-asserted; an
    admitted peer may report under any `instance_uid` its host speaks for
    (clause 7), and through a Gateway under any at all. Per-Agent authorization
    is not added: binding a certificate to one `instance_uid` breaks
    Server-initiated re-keying, certificate renewal and Gateway Mode. Operators
    who need isolation between mutually distrusting Agents put them behind
    separate Servers or network segments. This is stated in
    [`SECURITY.md`](../../SECURITY.md) and in the Server's admission and
    identity module docs.

15. **The Operator plane is guarded as a whole by `[rest.auth]`, Basic only,
    required beyond the loopback.** `[rest.auth] basic_users` is a map of
    `user = "$argon2id$…"` (clause 26); several users allow rotation and the
    withdrawal of one operator's credential. A section with no user, or an entry
    with an empty name or password, fails at startup. A `[rest] listen` that is
    not LOOPBACK without `[rest.auth]` is refused at startup with a message
    naming both keys. While present, every route on that listener — `/api/v1/…`,
    `/api/v1/openapi.json`, `/api/v1/docs` and the UI at `/` — answers `401`
    with `WWW-Authenticate: Basic realm="opamp"` without a matching credential;
    the browser prompts natively and re-sends the header, so the UI needs no
    login page, session or cookie. On a LOOPBACK `listen` the section stays
    optional, and the plane's loopback default
    ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
    clause 7) is what protects it. The Agent plane, the package download
    included, is untouched by it.

16. **A re-sent credential is not a cross-site licence.** The body-less `POST`
    acts on the Operator plane refuse a request whose `Sec-Fetch-Site` says it
    is cross-site (`403`), and every other mutating route is a JSON
    `PUT`/`DELETE` a browser sends only after a preflight this Server answers
    for nobody.

17. **A cleartext operator password is refused, not warned about.** A
    `[rest] listen` that is not LOOPBACK must serve TLS; a configuration that
    would serve that plane in plaintext is refused at startup naming the
    setting. A TLS-terminating proxy in front reaches the plane on a LOOPBACK
    `listen`.

18. **The operators' credential is the only one, and it carries no roles.** It
    never reaches an Agent's host. Every authenticated operator can do
    everything the plane offers.

19. **Enrolment has a CA of its own.** `[enrolment] bootstrap_ca_file` in
    `server.toml` names the CA that issues bootstrap certificates, and
    `[enrolment] bootstrap_ca_key_file` names its key, PKCS#8 PEM. The handshake
    accepts a certificate from the client CA or the bootstrap CA (clause 5).
    While `[enrolment]` is set, a connection is a member's only when its
    certificate was issued directly by a CA in `client_ca_file`. Any other, from
    the bootstrap CA or from an intermediate below either CA, is an enrolment
    connection, so no chain lifts a bootstrap certificate into the fleet. The
    Server refuses to start on a bootstrap CA that shares a certificate with
    `client_ca_file`, a bootstrap CA key that is the client CA's key or does not
    match `bootstrap_ca_file`, or an `[enrolment]` without `[client_ca]`.
    Without `bootstrap_ca_key_file` enrolment works with bootstrap certificates
    made elsewhere, and `POST /api/v1/bootstrap-certificates` is answered `409`,
    naming the missing key. Without `[enrolment]` no bootstrap certificate
    passes the handshake, and a host gets its first certificate from an
    operator.

20. **An operator opens an enrolment window for a bounded time, and it is closed
    by default.** `POST /api/v1/enrolment/window` with `{"open_for_secs": n}`
    opens it, or moves its end to `n` seconds from now; `n` runs from 1 to
    86400, and anything else is answered `400`. `GET /api/v1/enrolment/window`
    reports whether it is open and until when, and
    `DELETE /api/v1/enrolment/window` closes it early. The window and its
    pending requests live in memory only, so a Server restart closes it. When it
    closes, every enrolment connection is closed and every pending request
    expires, an approved one whose certificate the host has not yet collected
    included; that host enrols again in the next window.

21. **An enrolment connection may only send a CSR, and the CSR waits for an
    operator.** It is admitted only while the window is open; outside a window
    it is answered `503`, which clause 24 does not count, so hosts waiting for
    an operator cannot throttle the members behind the same address. The Server
    reads nothing from its messages but
    `connection_settings_request.opamp.certificate_request`: it creates no Agent
    record, assigns nothing and makes no offer but the issued certificate. A
    message without a CSR is answered with the Server's capabilities and nothing
    else, so the Client learns it may send one. The CSR enters a pending queue
    keyed by its public key, so a re-sent CSR joins its own entry; the Client
    keeps its pending key and re-sends the same CSR until it is answered. The
    queue holds at most 1024 requests, and a CSR beyond that is answered
    `ServerErrorResponse` `Unavailable` with `retry_info`. On approval the
    Server signs it (clause 9) and offers the certificate on that connection the
    way it offers any certificate; the Agent then reconnects with it. On
    rejection the CSR is answered `BadRequest`, and the connection is closed.

22. **Pending requests are listed and decided through the REST API.**
    `GET /api/v1/enrolments` lists each pending request with its id, its arrival
    time, the peer address, the CSR's subject, the SHA-256 fingerprint of its
    public key, and the bootstrap certificate's subject, fingerprint and serial
    as `bootstrap_serial`, in the lowercase hex without leading zeros that
    `GET /api/v1/bootstrap-certificates` lists. The Server derives both serials
    with one function, so a request carrying a certificate it issued names that
    entry. `POST /api/v1/enrolments/{id}/approve` and
    `POST /api/v1/enrolments/{id}/reject` decide one request; an unknown or
    expired id is answered `404`. Both are body-less `POST` acts under
    clause 16. The Client logs its request's public-key fingerprint, so an
    operator can match a pending request to a host. Renewal by an Agent that
    holds a certificate from the client CA stays automatic (clause 9) and never
    enters the queue.

23. **The package download is reached with a client certificate.** Its route on
    the Agent plane sits behind the same handshake as `/v1/opamp`
    ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
    clause 8). The route requires a certificate from the client CA; a bootstrap
    certificate is answered `401`. The Client presents its certificate only to
    the Server's own origin — the scheme, host and port of its OpAMP endpoint —
    and presents none to any other host or on a redirect hop that leaves that
    origin
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).

24. **Repeated admission failures from one peer address are throttled.**
    `[admission_throttle]` in `server.toml` sets `max_failures` (default 10),
    `window_secs` (default 60) and `backoff_secs` (default 300). Every `401` on
    `/v1/opamp` and on the download route counts as a failure of the peer's IP
    address. A peer address with `max_failures` failures within `window_secs` is
    in back-off for `backoff_secs`: each plain-HTTP request is answered `429`
    with `Retry-After` set to the remaining seconds, and each WebSocket upgrade
    `GET` is refused the same way before the upgrade completes. A success clears
    nothing — behind a shared address a member's success would wipe a guesser's
    count — so failures only age out of the window. The Operator plane counts
    its own `401`s the same way in a table of its own. Each table holds a
    bounded number of addresses; when it is full, the address heard from least
    recently that is not in back-off is dropped first. On the Agent plane a
    `401` follows a handshake that succeeded — a revoked certificate, or a
    bootstrap certificate on the download route — so the throttle no longer
    stops guessing; it bounds what a refused host that keeps retrying costs in
    handshakes, revocation lookups and audit entries
    ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)).

25. **Enrolment happens directly against the Server.** A Gateway's downstream
    handshake trusts the fleet's client CA and never the bootstrap CA
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)),
    so a CSR a Gateway forwards comes from a peer that already holds a client
    certificate and is signed as a renewal. A host behind a Gateway enrols by
    connecting to the Server once, or is provisioned a client certificate by an
    operator.

26. **No credential in `server.toml` authenticates on its own.** An entry of
    `[rest.auth] basic_users` is an Argon2id PHC string with at least `m=19456`,
    `t=2` and `p=1`, a 32-byte output and a 16-byte salt. Any other value is
    refused at startup with a message naming the section and the user, and never
    echoing the value. `server hash-credential --basic` reads the password from
    standard input, without echo on a terminal, and prints the line to paste.
    The hashing adds the RustCrypto `argon2` crate and no system dependency.

27. **A renewal proves which certificate it renews.** A Client that holds a
    certificate and its key adds to its CSR the SAN URI
    `urn:opamp-fleet:renewal:v1:` followed by the base64url, without padding, of
    the certificate's DER and a signature made with its key over
    `opamp-fleet-renewal-v1\n<SHA-256 of the new SubjectPublicKeyInfo, lowercase
    hex>\n`,
    each prefixed by its length as four big-endian bytes. The Server accepts the
    proof only when the certificate was issued by the client CA, is valid now,
    is not revoked, and its key verifies the signature; the new certificate is
    then issued to that certificate's host, with it as the predecessor (clause
    33). This holds through a Gateway, which presents its own certificate. A
    proof that does not hold is answered `BadRequest`. A CSR without a proof — a
    third-party client's — renews the certificate its connection presented, and
    its host.

28. **A claim is a canonical UUID in text.** Thirty-two hexadecimal digits in
    groups of 8, 4, 4, 4 and 12 joined by hyphens, in either case, standing
    alone or as part of a longer value — the Baseline's "part of the field". The
    `urn:uuid:` prefix of RFC 9562 is read the same way. A run of 32 hex digits
    without hyphens is not a claim: it is what a fingerprint or a hash looks
    like.

29. **Every value is searched.** Each attribute of the subject, read as text
    whichever string type encodes it, and each requested SAN of a type that
    carries text — DNS name, URI, e-mail address — is searched for claims. A SAN
    is read for this check only; clause 7 still drops it from the certificate.

30. **The sender is the message's `instance_uid`.** The `instance_uid` of the
    `AgentToServer` that carries the CSR, as the message states it and before
    any re-key the same message causes, is compared byte for byte with each
    claim. On an enrolment connection it is the same field.

31. **A mismatch is refused, a match or no claim is signed.** A CSR with one
    claim that differs from the sender's is answered `BadRequest`, naming the
    mismatch without echoing the CSR, and never reaches the signer or the
    enrolment queue. A CSR whose claims all match is signed as any other. A CSR
    with no claim is signed as clauses 9 and 27 decide; that is this project's
    own Client.

32. **The Server gives every certificate it signs a random serial.** 16 bytes
    from the system's secure random source, the top bit cleared so the encoding
    stays positive. Two certificates from one key have two serials.

33. **The Server keeps a register of what it signed.** For each certificate:
    issuer, serial, subject, the SHA-256 fingerprint of its public key,
    `not_after`, the `instance_uid` of the message that carried the CSR, its
    host (clause 7), and — on a renewal — the certificate it renewed, its
    **predecessor**: the certificate the CSR's renewal proof names (clause 27),
    and without a proof the certificate the connection presented — never what
    `instance_uid` the message names, because that value is self-asserted and a
    chain must not be left on its say-so. A proof is checked against the client
    CA and its key, so it holds through a Gateway too; a downstream Agent
    without one renews from the Gateway's certificate, and what it renews
    descends from that. An enrolment has no predecessor and is the root of its
    chain. An issuer is identified by the SHA-256 of its DER-encoded name, so no
    text form of a name can fail to match. The register lives under
    `config_dir`, one file per certificate, and each entry is written before the
    certificate is offered. It holds at most 100 000 certificates, at most 10
    000 in one chain — below one root, the first certificate the chain renews
    from — and it refuses a renewal once fewer than 1 000 places are left, so
    renewals alone cannot shut out an enrolment. A CSR beyond any of these is
    refused. An entry stays while the certificate, or one renewed from it, is
    still valid. `GET /api/v1/certificates` lists it.

34. **A revoked certificate is named by its CA and serial.**
    `POST /api/v1/revocations` with
    `{"certificate": {"authority": "client" | "bootstrap", "serial": "<hex>"}}`
    revokes one, under every certificate of that CA file. The client CA covers
    certificates the Server signed and those an operator provisioned from it;
    the bootstrap CA lets a lost bootstrap certificate be revoked. An authority
    this Server does not have is answered `400`, so a typo cannot pass for a
    revocation.

35. **A revocation follows renewal.** A certificate is revoked when it, or any
    predecessor in its register chain, is on the list. A connection that
    presents a revoked one is refused before its CSR is read, and an open
    session re-checks its certificate before a CSR it carries is signed.

36. **There is no credential to revoke.** `POST /api/v1/revocations` with
    `{"credential": …}` is answered `400`, naming the field and saying that the
    Agent plane admits by client certificate alone. A credential entry already
    on the persisted list is dropped when the list is loaded, with one log line
    that names the number of entries dropped, and the list is written back
    without it; the Server starts either way.

37. **The list is persisted and bounded.** It lives under `config_dir`, written
    atomically before the request is answered, and survives a restart. It holds
    at most 100 000 entries, and a revocation beyond that is answered `507`. A
    certificate entry is dropped with its register entry, once neither the
    certificate nor any renewal of it is valid; an entry for a certificate the
    register never held stays until an operator removes it.

38. **A revocation can be lifted.** `GET /api/v1/revocations` lists each entry
    with its id, kind, time, authority and serial;
    `DELETE /api/v1/revocations/{id}` removes one, answered `404` for an unknown
    id. Lifting one takes effect at the next connection; it reopens nothing.

39. **Admission checks the list after the handshake.** On `/v1/opamp` and on the
    download route, a peer whose certificate is revoked is answered `401`
    without a challenge, as every refusal behind the handshake is, and the
    failure counts toward its admission throttle. The answer does not say that
    the certificate was revoked.

40. **A revocation ends the sessions it concerns, and only those.** The Server
    records, per WebSocket session, the issuer and serial of the certificate
    that admitted it. A revocation is checked against every open session at
    once, and a session checks itself once more as it starts, so a revocation
    landing during its admission is not missed; a session it concerns is closed
    with WebSocket close code `1008` (policy violation) and the reason
    `revoked`. Other sessions are not touched. On plain HTTP every request is
    admitted anew, so the next poll is refused.

41. **A session ends when its certificate expires.** A WebSocket session is
    closed with `1008` and the reason `certificate expired` at the `not_after`
    of the certificate that admitted it. A Client renews at two thirds of the
    life and reconnects to prove the new certificate, so a healthy fleet never
    meets this close; it ends what renewal did not replace.

42. **Behind a Gateway the Gateway refuses what the Server revoked.** A
    downstream Agent is revoked by revoking the Gateway's certificate, which
    ends every Agent the Gateway carries and every certificate renewed through
    it without a proof (clause 33); or by revoking its own certificate, which
    the Gateway refuses from the list of clause 43
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
    clause 14), and whose proof renews nothing.

43. **The list reaches the Gateways from a route of their own.**
    `GET /v1/gateway/revocations` on the Agent plane is admitted as `/v1/opamp`
    is — the handshake's client certificate from the client CA, checked against
    the list — and is answered only to a certificate whose host an operator
    marked as a Gateway (`PUT /api/v1/hosts/{host}/gateway`); any other is
    answered `403`. The body is JSON: every certificate of the client CA that is
    revoked by clause 35, its own entry or a predecessor's, each by the SHA-256
    of its issuer's name and its serial, so the Gateway resolves no chain; and a
    version that changes with every change to the list, carried as an `ETag`, so
    a fetch with `If-None-Match` is answered `304`. Bootstrap certificates are
    not on it: a Gateway admits no bootstrap certificate. The route is outside
    the OpenAPI document, as the package download is.

**Out of scope:** per-Agent identity beyond the host; an opt-in strict mode
binding certificate subject to `instance_uid` where Gateway Mode and re-keying
are off; proxying a CSR to an external CA (it would sit behind `[client_ca]`);
how an installer obtains and writes the bootstrap certificate, which
[ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
decides; a view of the pending requests in the bundled UI; counting failed TLS
handshakes, and the `Unavailable` answer of an overloaded Server, which belong
to the connection caps; Bearer tokens on the Operator plane (an additive key);
enrolment by a per-host token, which a fleet that outgrows approval one host at
a time may need; binding the issued certificate to the `instance_uid` (the
certificate proves membership and its host, not an Agent's identity; clause 7
stands); the Client putting its `instance_uid` into its own CSR; claims in CSR
extensions other than the SAN; CRL and OCSP for third parties; what a Gateway
does with the list
([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md));
shortening certificate validity, which the H6 measure of `HARDENING.md` takes up
once this is in force; a revocation view in the bundled UI; an audit record of
revocations.

## Alternatives considered

- **Keep a fleet credential as a second required proof.** Rejected: it is one
  value for every host, so it identifies nobody, and it lies in clear beside the
  private key it is meant to back up. It costs a section on both ends, its
  rotation through offers, its revocation by hash and a Gateway pool partitioned
  by credential, and a fleet gains nothing from it that the certificate does not
  give.
- **Keep the credential optional, checked when configured.** Rejected: two
  admission paths to test and document, and every piece of machinery the
  credential needs stays in the tree for a proof that still identifies nobody.
- **Per-Agent or per-group credentials.** Rejected: identity management that
  brushes against the authorization and tenancy non-goal, beside a certificate
  that is already per host, short-lived and renewed without an operator.
- **A bootstrap token in a header instead of a bootstrap certificate.**
  Rejected: the token rides in HTTP, so the handshake would have to admit peers
  without a certificate. A listener has one client-certificate rule, so that
  means an optional certificate for the whole Agent plane or a third listener
  for enrolment. A token for the whole fleet has to be distributed exactly as
  the bootstrap certificate is.
- **A single-use enrolment token per host instead of the window and the
  approval.** Issuing the token would be the approval, and automation could
  fetch one per host. Not chosen: the handshake would again admit peers without
  a certificate, every host would need a secret of its own delivered to it, and
  a token intercepted on the way enrols a stranger unseen, where an approval
  shows the operator the key's fingerprint. It stays open as a follow-up.
- **Refuse a leftover `[auth]` on the Client at startup**, as the Server does.
  Rejected: a Client updated by the Server starts with the old file and nobody
  at the host, so the whole fleet would stop at once. A section that is ignored
  weakens nothing.
- **Ignore a leftover `[auth]` on the Server too.** Rejected: an operator is
  present at a Server upgrade, and a section that silently does nothing would
  make that operator believe the fleet still needs the credential.
- **Optional proofs, required only by being configured** — an open default is
  convenient in a lab and admits anyone wherever an operator forgot a section;
  the specification puts security before convenience and asks for a refusal that
  names the setting.
- **Warning instead of refusing an exposed Operator plane** — a warning is read
  after the plane has been reachable; the specification asks for a refusal.
- **A bootstrap certificate from the client CA** — indistinguishable from an
  issued one at the handshake, so no approval can be asked of it and every
  leaked bootstrap pair is a member.
- **Approval without a window** — a pending queue that accepts requests at any
  time is a standing invitation; a window that closes by itself bounds both the
  queue and an operator's attention.
- **A persisted enrolment queue** — a request that outlives a restart outlives
  the window it was made in.
- **A download listener of its own instead of a certificate on the download** —
  a third listener serving artifacts to anyone who reaches it, where the Agent
  plane's handshake already proves the peer.
- **Rejecting a report whose `sequence_num` regresses** — an Agent restart
  legitimately resets it, and a forger can imitate a restart; it authorizes
  nothing.
- **Operator-provisioned certificates only, no CSR flow** — leaves every host's
  certificate to be created, delivered and renewed by hand, the errand the
  specification exists to remove. It survives as clause 8's first source.
- **The Server hands out certificate and private key** — every Agent's key would
  exist on the Server, travel the wire and sit in its storage; one compromised
  Server would yield the fleet's identities.
- **Binding the certificate subject to `instance_uid`, or trust-on-first-use
  pinning of the two** — a re-key, a renewal or an Agent moving between Gateways
  would read as impersonation, and one Gateway certificate legitimately carries
  many UIDs.
- **Plaintext operator passwords accepted with a warning** — the secret stays in
  backups and diffs, and a warning is read after the file has travelled; the
  specification asks for a refusal.
- **SHA-256 for Basic passwords** — a person's password falls to a dictionary
  run against a leaked fast hash in minutes.
- **Operator passwords only by file reference, unhashed** — moves the secret out
  of `server.toml` but leaves it usable wherever that file travels; a hash is
  useless to whoever reads it.
- **Pluggable authenticators (OIDC, JWT, external IdP)** — a validator can be
  added behind the Operator plane's seam later.
- **A login page with a session cookie on the Operator plane** — a session
  store, logout, cookie policy and CSRF protection inside a Server whose UI is
  an operational page; Basic gives the same browser experience for none of it.
- **Bearer only on the Operator plane** — a browser cannot send one without
  JavaScript holding a token, which drags the UI into session management.
- **Leaving operator authentication to a reverse proxy** — a property depending
  on an artifact this project neither ships nor tests.
- **Stripping a mismatched `instance_uid` claim and signing anyway.** Rejected:
  it does not meet the Baseline's MUST, and a peer that made a false claim
  learns nothing about why its identity does not hold.
- **Recognising a claim only in one agreed field, such as a `urn:uuid:` SAN.**
  Rejected: the Baseline names no field, and a peer that put its `instance_uid`
  in the common name would pass unchecked.
- **Recognising any 32 hex digits as a claim.** Rejected: key fingerprints and
  hashes take that form, and a descriptive subject carrying one would be refused
  for nothing.
- **Leaving H3 undone.** Rejected: the MUST is conditional but unmet without it,
  and the cost is a parser over values the Server already reads.

- **A maximum session age instead of, or beside, targeted closing.** Rejected. A
  fixed age closes every session of the fleet on a clock, a reconnect storm's
  worth of handshakes for sessions whose proofs are fine, and still leaves a
  revoked one running until the age is reached. The certificate's own
  `not_after` is the bound that already exists and costs a healthy fleet nothing
  (clause 41).
- **Revocation by serial alone, without the renewal chain.** Rejected: a host
  that renewed shortly before the revocation keeps a valid certificate, and the
  operator has to revoke the successor they cannot see. The register costs one
  small entry per issued certificate, dropped on expiry.
- **Revocation by public key fingerprint.** Rejected: renewal changes the key,
  so it has the same hole as serial alone, and an operator reading a certificate
  with `openssl x509` sees the serial, not a key hash.
- **Naming the issuer by its distinguished name as text.** Rejected: RFC 4514
  reverses the order of the parts and escapes commas, OpenSSL's default form
  does neither, and a parser's form is a third; a revocation typed in one would
  silently miss a certificate stored in another. The Server has two CAs at most,
  so their role names them without ambiguity.
- **Linking a renewal to the presented certificate only when the message names
  its owner.** Rejected: the `instance_uid` a message names is self-asserted, so
  one message naming another value would lift a renewal out of its chain.
  Linking always revokes too much behind a Gateway, never too little.
- **Dropping a register entry at its own expiry.** Rejected: the revocation of
  an expired certificate would go with it, and a renewal of that certificate
  would be admitted again.
- **Revocation by Agent, from the fleet view.** Rejected as the primitive:
  `instance_uid` is self-asserted and re-keyable, and behind a Gateway the
  Server sees only the Gateway's certificate. It may come later as a convenience
  on top of clause 34, using the register's `instance_uid`.
- **CRL or OCSP.** Rejected: both serve relying parties other than the issuer.
  Here the issuer is the only relying party, and an online responder would be
  infrastructure guarding nothing extra.
- **Distributing the list to Gateways through a custom message.** Rejected: a
  `CustomMessage` is `[Development]` in the Baseline and not implemented here,
  and it would tie the list to an Agent's session rather than to the Gateway as
  a host. A route of its own on the plane the Gateway already reaches carries it
  with the admission that plane already has.
- **The list for every member, not only marked Gateways.** Rejected: only a
  Gateway acts on it, and every member that could fetch it would learn which
  certificates of the fleet were withdrawn.
- **Ending a session by a re-authentication the Server pushes.** Rejected: the
  Baseline has no message for it, and the specification forbids a private side
  channel.
- **Refusing to start while a credential entry is on the persisted list.**
  Rejected: the entry names nothing the Server still accepts, so it guards
  nothing, and a Server that will not start after an upgrade would shut out the
  whole fleet for no gain in security.

## Sources / Prior art

- [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)
  — authentication MAY, `401` MUST; the client-certificate CSR flow, its
  `BadRequest` MUST, its restriction to the OpAMP connection, the bootstrap
  certificate, and the "header-based authorization … and optionally also
  client-side certificates" layering; `instance_uid` chosen by the Agent and
  assignable by the Server; throttling with `retry_info` and `Retry-After`.
- The vendored Baseline schema: `TLSCertificate`, `ConnectionSettingsRequest`.
- [`opamp-go` `StartSettings`](https://github.com/open-telemetry/opamp-go/blob/main/client/types/startsettings.go)
  — static `Header` and per-request `HeaderFunc`.
- [`opampextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/opampextension),
  [`basicauthextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/basicauthextension),
  [`bearertokenauthextension`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/bearertokenauthextension)
  — the ecosystem's static Basic and Bearer building blocks.
- [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617) (Basic),
  [RFC 9110 §11](https://datatracker.ietf.org/doc/html/rfc9110#name-http-authentication)
  (`401`, `WWW-Authenticate`, `realm`),
  [RFC 6585 §4](https://datatracker.ietf.org/doc/html/rfc6585#section-4) (`429`)
  and
  [RFC 9110 §10.2.3](https://datatracker.ietf.org/doc/html/rfc9110#name-retry-after)
  (`Retry-After`).
- [`constant_time_eq`](https://crates.io/crates/constant_time_eq).
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
  _Argon2id_: "m=19456 (19 MiB), t=2, p=1" as the minimum configuration;
  [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2); the RustCrypto
  [`argon2`](https://crates.io/crates/argon2) crate and the
  [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md).
- [rcgen](https://docs.rs/rcgen/latest/rcgen/struct.CertificateSigningRequestParams.html)
  and its [feature flags](https://lib.rs/crates/rcgen/features);
  [`ring`'s build](https://docs.rs/crate/ring/latest);
  [`reqwest::tls::Identity`](https://docs.rs/reqwest/latest/reqwest/tls/struct.Identity.html)
  (`from_pem` under rustls takes key and certificate in one buffer);
  [`RustlsConfig::from_config`](https://docs.rs/axum-server/latest/axum_server/tls_rustls/struct.RustlsConfig.html)
  and the [`axum-server-mtls`](https://lib.rs/crates/axum-server-mtls) pattern
  for carrying the peer certificate into request extensions; rustls'
  [`WebPkiClientVerifier`](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
  without `allow_unauthenticated`.
- [Kubernetes `certificates.k8s.io`](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)
  and
  [`client-go` certificate rotation](https://github.com/kubernetes/client-go/blob/master/util/certificate/csr/csr.go)
  — local key, submitted CSR, bootstrap identity distinct from the issued one,
  renewal before expiry, and a pending request approved or denied by an
  operator.
- Shared-CA service meshes — a client CA proves membership, not per-caller
  identity, unless an identity document (SPIFFE SVID) is layered on.
- [Prometheus web configuration](https://prometheus.io/docs/prometheus/latest/configuration/https/),
  [Alertmanager](https://prometheus.io/docs/alerting/latest/configuration/),
  [Traefik's dashboard](https://doc.traefik.io/traefik/operations/dashboard/) —
  Basic in front of an operational UI;
  [Grafana](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/)
  and [BindPlane](https://docs.bindplane.com/) — session logins where the UI is
  the product.
- OpAMP specification v0.20.0, _Using instance_uid in the CSR_
  ([opamp-spec](https://github.com/open-telemetry/opamp-spec/blob/v0.20.0/specification.md)).
- [RFC 9562 §4](https://www.rfc-editor.org/rfc/rfc9562#section-4): the UUID
  string representation and the `urn:uuid:` namespace.
- [`HARDENING.md`](../HARDENING.md) — H3 (a CSR naming another Agent's
  `instance_uid`, and the observable it names), H5 (enrolment as an approval),
  H7 (credential storage, and why a Basic password needs a password hash), H9
  (the handshake-level certificate requirement), H10 (throttling), H15 (operator
  audit).
- OpAMP specification v0.20.0, _Revoking Access_: _"the Server can revoke access
  to individual Agents by marking the corresponding connection settings as
  'revoked' and disconnecting the Client."_
  ([opamp-spec](https://github.com/open-telemetry/opamp-spec/blob/v0.20.0/specification.md))
- [RFC 5280 §4.1.2.2](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2): a
  serial is a positive integer of at most 20 octets, unique per issuer.
- [RFC 6455 §7.4.1](https://www.rfc-editor.org/rfc/rfc6455#section-7.4.1): close
  code `1008`, _"an endpoint is terminating the connection because it has
  received a message that violates its policy"_.
- Kubernetes has no client-certificate revocation and relies on short lifetimes
  and rotation
  ([kubernetes#46287](https://github.com/kubernetes/kubernetes/issues/46287),
  [kubelet certificate rotation](https://kubernetes.io/docs/tasks/tls/certificate-rotation/))
  — the position of admission without a revocation list, and the gap this
  closes.

## Consequences

- Positive: goal 17 holds for every configuration — encrypted channel, a peer
  proved in the handshake by a certificate this project issues and renews, no
  configuration that admits a peer without one.
- Positive: a configuration that would weaken admission fails loudly at startup,
  naming the setting, never silently as an open endpoint.
- Positive: the trust model is explicit — one fleet is one trust domain — and
  the Operator plane can be published to a network only behind TLS and a
  password.
- Positive: a copy of `server.toml` admits no host and signs in no operator.
- Positive: a peer without a certificate dies in the handshake, before any
  handler parses a byte of its request; the route check is a second line rather
  than the only one.
- Positive: no secret for the Agent plane exists anywhere. Nothing in
  `supervisor.toml` admits a host, and the Client holds no credential in clear;
  its only secret is the private key, which never leaves it.
- Positive: no machinery for a fleet credential exists — no Agent plane
  `[auth]`, no `hash-credential --bearer`, no credential in connection-settings
  offers
  ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)),
  no revocation by hash (clause 36), no audit events for one
  ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)), and no
  Gateway pool partitioned by credential
  ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)).
- Positive: a compromised host reports only for its own Agents and holds at most
  three valid certificates; it cannot take over another host's Agent record or
  its renewals.
- Positive: the Baseline's conditional MUST on `instance_uid` in the CSR is met;
  a peer cannot ask for a certificate in another Agent's name; nothing changes
  for this project's own Client.
- Positive: an operator can eject a host within seconds, not within a
  certificate's lifetime; a stolen bootstrap certificate can be withdrawn; a
  session can no longer outlive its certificate. Validity can be shortened
  afterwards on evidence rather than as the only defence. The list holds one
  kind of entry, and no revocation shuts out the whole fleet at once.
- Negative / trade-offs: one proof. A stolen certificate and key admit until the
  certificate is revoked or expires.
- Negative / trade-offs: behind a Gateway the Server relies on the Gateway's
  handshake for the peers it carries. A compromised Gateway, or a compromised
  peer behind one, can poison the record of any Agent behind a Gateway. Accepted
  within one fleet; it is not a cross-fleet or unauthenticated exposure.
- Negative / trade-offs: the Server is upgraded before its Clients. A Server of
  the previous version demands the credential a Client of this version no longer
  sends; a Server of this version refuses to start while `server.toml` keeps
  `[auth]` or a credential key in `[connection_offer]`
  ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)
  clause 1), and the manual says to delete them.
- Negative / trade-offs: an operator marks each Gateway by hand; until then the
  first Agents it carries bind to the Gateway's host, and the mark is the
  remedy.
- Negative / trade-offs: the Server is a CA, and its signing key can mint fleet
  members.
- Negative / trade-offs: no lab runs without setup. Every Server needs TLS
  material and a client CA, and every Client a certificate.
- Negative / trade-offs: an expired certificate locks a host out. A Client
  switched off longer than its validity comes back unable to connect; recovery
  is the operator's — delete its stored pair so it presents a bootstrap
  certificate, open a window, approve its request — and is written in the
  manual.
- Negative / trade-offs: a bootstrap certificate still has to be distributed,
  mitigated by it being one for the fleet and opening nothing without a window
  and an approval.
- Negative / trade-offs: every first enrolment needs an operator at the API
  while a window is open; a request nobody approves expires with the window, and
  a Server restart drops every pending request.
- Negative / trade-offs: throttling counts by IP address, so hosts behind one
  NAT or one Gateway share a count, and one misconfigured host can put its
  neighbours into back-off.
- Negative / trade-offs: a Gateway whose client CA names the bootstrap CA would
  turn enrolment through it into automatic issuance; the Server cannot see this,
  and the rule lives in the Gateway's configuration and the manual.
- Negative / trade-offs: browsers cache Basic credentials and offer no clean
  logout.
- Negative / trade-offs: a descriptive subject that happens to contain a
  canonical UUID other than the sender's is refused. An operator who names hosts
  after UUIDs must name them after the Agent's own.
- Negative / trade-offs: the Server gains two persisted stores and a check per
  admission; the register grows with the fleet times its renewals within one
  validity period. Behind a Gateway a revocation takes effect when the Gateway
  next fetches the list, and a Gateway needs its host marked before it admits
  anyone; the list is now the only way the Server's revocation of a downstream
  certificate reaches that Agent. The register's bounds turn an admitted member
  that loops CSRs into a refusal of renewals within its chain, and a host holds
  at most three valid certificates (clause 7). A downstream Agent that renews
  with a proof renews in its own chain and host; one without a proof renews in
  the Gateway's, and can stop renewal for the Gateway and every Agent it carries
  until the certificates it obtained expire. The bounds keep the damage to one
  chain and away from enrolment. An operator tool that still posts
  `{"credential": …}` is answered `400` and has to be changed.
- Follow-ups: enrolment by a per-host token; a strict per-Agent identity mode;
  an external-CA backend; a view of pending enrolments in the bundled UI;
  running the `instance_uid` claim check against opamp-go in the
  interoperability suite.
- Follow-ups: revocation by Agent as a convenience in the bundled UI; an audit
  record of each revocation and each session it closed; shortening certificate
  validity once renewal is proven; bounding issuance per Agent rather than per
  chain, which needs a per-Agent identity this decision leaves out.

## Enforcement

- [`crates/fleet-server/src/config.rs`](../../crates/fleet-server/src/config.rs)
  — `an_auth_section_is_refused_at_startup` (clause 1);
  `the_client_ca_is_required_at_startup` (clauses 5, 19);
  `rest_auth_verifies_its_hashes_and_carries_the_basic_challenge`,
  `an_unusable_rest_auth_section_is_rejected`,
  `the_operator_plane_requires_authentication_off_the_loopback` (clause 15),
  `a_server_without_tls_is_refused_at_startup` (clause 17),
  `a_plaintext_credential_is_refused_naming_its_entry`, which holds the Basic
  cases alone, `a_weak_argon2id_hash_is_refused` (clause 26).
- [`crates/fleet-server/tests/mutual_tls.rs`](../../crates/fleet-server/tests/mutual_tls.rs)
  — `a_member_is_admitted_on_its_certificate_alone` and
  `an_authorization_header_is_ignored` over both transports (clauses 1, 6);
  `a_client_certificate_is_required_in_the_handshake_on_the_agent_plane`
  (clauses 5, 23), `a_csr_is_answered_with_an_issued_certificate`,
  `a_csr_to_a_server_that_signs_nothing_is_a_bad_request` (clause 9),
  `a_bootstrap_ca_sharing_its_subject_with_the_client_ca_is_refused` (clause
  19), `a_bootstrap_certificate_is_refused_outside_an_enrolment_window` (clauses
  10, 21, 24),
  `an_enrolment_request_waits_for_an_operator_and_is_issued_on_approval`
  (clauses 4, 20 to 23),
  `a_rejected_request_is_refused_and_closing_the_window_shuts_enrolment`
  (clauses 20, 21), `an_unknown_enrolment_request_is_answered_404` (clause 22),
  `repeated_failures_from_one_address_are_throttled`,
  `the_operator_plane_counts_its_failures_in_a_table_of_its_own` (clause 24),
  `an_operator_sees_each_host_and_can_mark_a_gateway` (clause 7).
- [`crates/fleet-server/src/credentials.rs`](../../crates/fleet-server/src/credentials.rs)
  — `a_basic_password_is_verified_against_its_argon2id_hash`,
  `an_unknown_user_costs_the_same_verification`,
  `a_basic_verification_is_remembered_and_bounded`,
  `password_hashes_are_bounded_and_off_the_async_workers`,
  `the_comparison_hash_matches_the_costliest_user` (clause 2).
- [`crates/fleet-server/src/throttle.rs`](../../crates/fleet-server/src/throttle.rs)
  — `attempts_under_way_count_and_a_slash_64_is_one_peer` (clause 2),
  `a_peer_that_fails_too_often_waits_out_the_back_off`,
  `a_full_table_keeps_an_address_in_back_off`,
  `the_table_is_bounded_and_drops_the_oldest` (clause 24).
- [`crates/fleet-server/src/main.rs`](../../crates/fleet-server/src/main.rs) —
  `hash_credential_hashes_a_basic_password_alone` (clause 26).
- [`crates/fleet-agent/src/config.rs`](../../crates/fleet-agent/src/config.rs) —
  `a_leftover_auth_section_is_ignored_with_a_notice` (clause 3);
  [`config_file.rs`](../../crates/fleet-agent/src/config_file.rs)
  `admission_needs_a_client_identity_and_nothing_else` (clause 5).
- [`crates/fleet-server/src/tls.rs`](../../crates/fleet-server/src/tls.rs) —
  `a_certificate_not_issued_by_the_client_ca_only_enrols` (clauses 6, 19, 21).
- [`crates/fleet-server/src/enrolment.rs`](../../crates/fleet-server/src/enrolment.rs)
  — `the_window_is_closed_by_default_and_bounded`,
  `closing_the_window_expires_every_request` (clause 20),
  `a_request_waits_for_an_operator_and_is_answered_once_decided`,
  `the_queue_is_bounded` (clauses 21, 22).
- [`crates/fleet-server/src/ca.rs`](../../crates/fleet-server/src/ca.rs) —
  `signs_a_request_into_a_certificate`,
  `the_request_cannot_dictate_the_certificates_powers`,
  `refuses_a_request_that_does_not_parse` (clauses 7, 9),
  `a_renewal_proof_names_the_certificate_and_its_host` (clauses 7, 27).
- [`crates/fleet-server/src/revocation.rs`](../../crates/fleet-server/src/revocation.rs)
  — `a_host_is_bounded_and_speaks_only_for_its_own_agents` (clause 7).
- [`crates/fleet-server/src/fleet.rs`](../../crates/fleet-server/src/fleet.rs) —
  `a_host_cannot_report_for_another_hosts_agent` (clauses 7, 14),
  `unavailable_tells_the_agent_when_to_retry` (clause 21).
- [`crates/fleet-agent/tests/certificate_renewal_e2e.rs`](../../crates/fleet-agent/tests/certificate_renewal_e2e.rs)
  — `a_client_renews_each_certificate_before_it_expires` (clauses 9, 11, 27).
- [`crates/fleet-agent/src/csr.rs`](../../crates/fleet-agent/src/csr.rs) —
  `a_client_without_a_certificate_asks_and_keeps_its_key` (clauses 9, 21),
  `the_private_key_is_written_owner_only`,
  `an_issued_certificate_becomes_the_identity`,
  `a_certificate_without_a_pending_key_is_refused` (clause 8),
  `a_certificate_in_its_renewal_window_is_requested_again` (clause 11).
- [`crates/fleet-agent/tests/packages_download.rs`](../../crates/fleet-agent/tests/packages_download.rs)
  — `the_client_certificate_goes_to_the_servers_origin_alone` (clause 23).
- [`crates/fleet-agent/tests/gateway_tls.rs`](../../crates/fleet-agent/tests/gateway_tls.rs)
  — `a_downstream_agent_with_a_certificate_reaches_the_server_over_tls`,
  `a_downstream_peer_without_a_certificate_is_refused` (clause 13).
- [`crates/fleet-server/tests/rest_auth.rs`](../../crates/fleet-server/tests/rest_auth.rs)
  — `a_request_without_credentials_is_answered_401_with_a_basic_challenge`,
  `the_configured_operator_reaches_the_api`,
  `the_ui_and_the_api_docs_are_guarded_too`,
  `the_agent_plane_is_untouched_by_the_operator_credential` (clauses 15, 18);
  [`crates/fleet-server/tests/rest_api.rs`](../../crates/fleet-server/tests/rest_api.rs)
  — `a_cross_site_state_changing_post_is_refused` (clause 16).
- [`crates/fleet-server/src/ca.rs`](../../crates/fleet-server/src/ca.rs) —
  `a_canonical_uuid_anywhere_in_a_value_is_a_claim`,
  `hex_without_hyphens_is_no_claim`, `a_san_is_read_for_claims`,
  `a_claim_in_a_bmp_or_universal_string_is_read` (clauses 28, 29).
- [`crates/fleet-server/tests/mutual_tls.rs`](../../crates/fleet-server/tests/mutual_tls.rs)
  — `a_csr_claiming_another_instance_uid_is_a_bad_request`,
  `a_csr_claiming_its_own_instance_uid_is_signed`,
  `a_csr_claiming_nothing_is_signed_as_before`, and
  `an_enrolment_csr_claiming_another_instance_uid_never_reaches_the_queue`
  (clauses 30, 31).

- [`crates/fleet-server/src/revocation.rs`](../../crates/fleet-server/src/revocation.rs)
  tests: `a_revocation_follows_every_renewal` (clause 35),
  `the_list_survives_a_restart_and_can_be_lifted` (clauses 37, 38),
  `a_renewal_stays_revoked_after_its_revoked_ancestor_expires` (clauses 35, 37),
  `the_list_and_the_register_are_bounded`,
  `an_expired_register_entry_is_dropped_with_its_revocation` (clauses 33, 37).
- [`crates/fleet-server/src/fs/revocation.rs`](../../crates/fleet-server/src/fs/revocation.rs)
  tests: `the_ledger_survives_a_reopen` (clauses 33, 37);
  `a_persisted_credential_entry_is_dropped_on_load` (clause 36): a list holding
  a credential entry beside a certificate entry loads with the certificate entry
  alone, is written back without the credential entry, and the drop is logged.
- [`crates/fleet-server/src/ca.rs`](../../crates/fleet-server/src/ca.rs) test:
  `two_certificates_from_one_key_have_two_serials` (clause 32).
- [`crates/fleet-server/tests/mutual_tls.rs`](../../crates/fleet-server/tests/mutual_tls.rs)
  tests: `a_revoked_certificate_is_refused_on_both_transports_and_the_download`
  (clauses 34, 38, 39), which also asserts that the `401` carries no
  `WWW-Authenticate` header;
  `a_revocation_closes_the_session_it_concerns_and_no_other` (clause 40),
  `a_session_is_closed_when_its_certificate_expires` (clause 41),
  `a_revocation_reaches_a_certificate_renewed_before_it` (clauses 32, 33, 35),
  `a_revocation_names_its_issuer_by_role_whatever_the_issuer_is_called` (clause
  34), `a_csr_for_another_agent_still_descends_from_the_presented_certificate`
  (clauses 33, 42),
  `a_marked_gateway_is_handed_the_revoked_certificates_with_their_renewals`
  (clause 43, an unmarked member answered `403` and an unchanged list `304`),
  `a_bootstrap_certificate_is_not_handed_the_list` (clause 43);
  `a_credential_revocation_is_answered_400` (clause 36): `{"credential": …}` is
  refused with `400` and the list is unchanged.
- [`crates/fleet-agent/tests/gateway_revocation_e2e.rs`](../../crates/fleet-agent/tests/gateway_revocation_e2e.rs)
  test: `a_certificate_the_server_revokes_is_refused_behind_the_gateway`
  (clauses 42, 43).
- The Server refuses to start on a bootstrap CA key that does not match
  `bootstrap_ca_file` or that is the client CA's key; without
  `bootstrap_ca_key_file` it starts, admits a bootstrap certificate made
  elsewhere, and answers `POST /api/v1/bootstrap-certificates` with `409`
  (clause 19).
- A request carrying a bootstrap certificate the Server issued is listed with
  the `bootstrap_serial` that `GET /api/v1/bootstrap-certificates` lists for it,
  and `PendingEnrolment` in the OpenAPI document carries the field (clause 22).

**Not mechanically decidable:** clause 14 decides what is _not_ built beyond the
host — no test can show the absence of a per-Agent authorization the design
rejects; clause 12 is a dependency choice; and clause 25 rests on a Gateway's
client CA, which the Server cannot see. Review holds them.
