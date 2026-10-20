# ADR-0039: Through a Gateway a CSR proves the certificate it rests on, a report is forwarded only for its host's Agents, and an enrolment is relayed over plain HTTP

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the CSR handling on a member connection in
  `crates/fleet-server/src/fleet.rs` (the host and predecessor a CSR is issued
  to), the certificate register in `crates/fleet-server/src/revocation.rs`, the
  renewal and bootstrap proofs and the reading of a CSR in `crates/fleet-core/`
  and `crates/fleet-server/src/ca.rs`, the Client's renewal and enrolment CSR in
  `crates/fleet-agent/src/csr.rs` and `crates/fleet-agent/src/service/enrol.rs`,
  the requester an enrolment request is filed under in
  `crates/fleet-server/src/enrolment.rs` and
  `crates/fleet-server/src/transport.rs`, the admission throttle's buckets in
  `crates/fleet-server/src/transport.rs` and
  `crates/fleet-server/src/agent_rate.rs`, the downstream admission, the
  enrolling peer, the forwarding and routing of reports and replies and the
  bindings in `crates/fleet-agent/src/gateway/`, the host derived for a
  certificate that names none in `crates/fleet-core/src/host.rs`, the
  `[gateway.tls]` section of `supervisor.toml` and its parsing in
  `crates/fleet-agent/src/config.rs`, and every document that tells an operator
  what a Gateway passes on, how an Agent behind one renews its certificate, or
  how a host behind one enrols
- **Supersedes:**
  [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)
  clause 22;
  [ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
  clauses 11 and 13;
  [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clauses 27 and 42;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 45;
  [ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)
  clause 3;
  [ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
  clause 10

## Context

A Gateway carries other hosts' Agents over its own connection to the Server, and
the Server sees only the Gateway's certificate
([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
clause 11). A host marked as a Gateway speaks for any Agent
([ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)
clause 2). Four things follow that the accepted decisions do not close:

- **A member can take the Gateway's certificate.** A CSR without a renewal proof
  renews the certificate its connection presented, with that certificate's host
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 27). Behind a Gateway that is the Gateway's certificate, and its host
  carries the Gateway mark. Any member behind a Gateway can therefore obtain a
  certificate with the Gateway's powers and use it directly against the Server:
  speak for any `instance_uid`, fetch every offered artifact, read every
  Gateway's revocation list. Three such CSRs also fill the Gateway host's three
  places and block its own renewal.
- **A member can take another host's Agent.** The Gateway routes by
  `instance_uid` alone, the last sender winning (ADR-0015 clause 13). A member
  that reports under another host's `instance_uid` takes its route, receives its
  configuration, which may carry secrets, and its certificate, and speaks in its
  name. The Gateway already binds an `instance_uid` to the host that first
  reports it for downloads
  ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 45); routing does not consult that binding.
- **A host that only a Gateway connects cannot enrol.** Enrolment rests on the
  bootstrap certificate of a direct connection's handshake (ADR-0021 clauses 19
  to 22); a Gateway admits only member certificates and forwards no downstream
  certificate. Such hosts exist; their only way in is a certificate the operator
  makes by hand.
- **One CSR can say two things.** The Server read a CSR with two PEM readers
  that may choose different blocks of one crafted input, so a proof could be
  checked against one request while the key of another was signed.

A renewal proof already travels inside the CSR and holds over any hop: the
Server checks it itself. The same shape can carry the bootstrap certificate.
Hardening the link is the project's first priority, and the specification's
quality goal Q-1 asks that no Agent be admitted without a client certificate.

## Decision

We will have every CSR prove the certificate it rests on — a renewal proof or a
bootstrap proof, read from exactly one PEM block — refuse through a Gateway what
proves neither, forward a downstream report only for an `instance_uid` bound to
the host that sent it, and let a Gateway relay an enrolment over plain HTTP that
the Server decides as any enrolment.

1. **Restates ADR-0021 clause 27. A renewal proves which certificate it
   renews.** A Client that holds a certificate and its key adds to its CSR the
   SAN URI `urn:opamp-fleet:renewal:v1:` followed by the base64url, without
   padding, of the certificate's DER and a signature made with its key over
   `opamp-fleet-renewal-v1\n<SHA-256 of the new SubjectPublicKeyInfo, lowercase
   hex>\n`,
   each prefixed by its length as four big-endian bytes. The Server accepts the
   proof only when the certificate was issued by the client CA, is valid now, is
   not revoked, and its key verifies the signature. The new certificate is then
   issued to that certificate's host, with it as the predecessor (clause 2).
   This holds through a Gateway, which presents its own certificate. A proof
   that does not hold is answered `BadRequest`. A CSR without a renewal proof —
   a third-party client's — renews the certificate its connection presented, and
   its host, unless that host is marked as a Gateway. Then a CSR that carries a
   bootstrap proof is an enrolment through the Gateway (clause 12), and any
   other is answered `BadRequest` with a message saying that a certificate
   requested through a Gateway needs a renewal or a bootstrap proof. Nothing is
   signed, and the refusal is recorded as every refused CSR is
   ([ADR-0022](0022-an-append-only-audit-record-chained-by-hash.md)). This holds
   whatever `instance_uid` the message names, and for the Gateway's own Agent
   too.

2. **Restates ADR-0037 clause 10. The Server keeps a register of what it
   signed.**
   - For each certificate the register holds:
     - issuer, serial and subject;
     - the SHA-256 fingerprint of its public key;
     - `not_after`;
     - the `instance_uid` of the message that carried the CSR;
     - its host (ADR-0036 clause 2);
     - on a renewal, the certificate it renewed, its **predecessor**.
   - The predecessor is the certificate the CSR's renewal proof names (clause
     1), and without a proof the certificate the connection presented, which is
     never a Gateway host's. It is never the `instance_uid` the message names,
     because that value is self-asserted and a chain must not be left on its
     say-so.
   - A proof is checked against the client CA and its key, so it holds through a
     Gateway too. Behind a Gateway a certificate is renewed only with a proof,
     in its own chain and host.
   - An enrolment has no predecessor and is the root of its chain.
   - An issuer is identified by the SHA-256 of its DER-encoded name, so no text
     form of a name can fail to match.
   - The register lives in `data_dir/certificates/`, one file per certificate,
     and each entry is written before the certificate is offered.
   - It holds at most 100 000 certificates, and at most 10 000 in one chain —
     below one root, the first certificate the chain renews from. It refuses a
     renewal once fewer than 1 000 places are left, so renewals alone cannot
     shut out an enrolment. A CSR beyond any of these is refused.
   - An entry stays while the certificate, or one renewed from it, is still
     valid. `GET /api/v1/certificates` lists it.

3. **Restates ADR-0021 clause 42. Behind a Gateway the Gateway refuses what the
   Server revoked.** A downstream Agent is revoked by revoking the Gateway's
   certificate, which ends every Agent the Gateway carries; or by revoking its
   own certificate, which the Gateway refuses from the list of ADR-0021 clause
   43
   ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
   clause 14), and whose proof renews nothing. No certificate is renewed from
   the Gateway's (clause 1), so revoking the Gateway's certificate ends no
   certificate renewed through it.

4. **Restates ADR-0015 clause 11. The downstream handshake and the Server's
   revocation list are a downstream Agent's admission; the Gateway holds no
   policy of its own, and its own hop is its own.** Mutual TLS is per hop and
   mandatory downstream: the handshake requires a client certificate that chains
   to `client_ca_file`, or, where `[gateway.tls] bootstrap_ca_file` names one,
   to that bootstrap CA (`ClientAuth::Required` in `opamp`), so a peer without
   one never reaches OpAMP. `client_ca_file` must be the fleet's client CA,
   never a bootstrap CA; `bootstrap_ca_file` holds the public certificate of
   `[enrolment] bootstrap_ca_file` on the Server and no key, and a CA that is in
   both fails startup naming both keys. A peer whose certificate chains to the
   bootstrap CA alone is an **enrolling peer** (clause 11). A peer that passed
   the handshake is admitted unless its certificate is on the list of ADR-0015
   clause 14; that is the one admission refusal the Gateway makes beyond the
   handshake, and it is the Server's. The list holds the client CA's
   revocations; a revoked bootstrap certificate is refused by the Server, which
   checks every proof against its own list (clause 8). Beyond admission the
   Gateway refuses three things. It forwards no report for an `instance_uid`
   bound to another host, or that it cannot bind (clause 5). It forwards from an
   enrolling peer nothing but what clause 11 allows. And it passes on an
   uploaded artifact from its package cache only to a host whose Agent it
   relayed the Server's offer of that artifact to, and answers every other
   download request `404` (clause 6). What a host may receive is the Server's
   own bound
   ([ADR-0035](0035-a-host-is-what-a-client-certificate-names-and-its-agents-inherit-from-it.md)
   clause 2), applied to what the Server sent through this Gateway. Four parts
   of these refusals are the Gateway's own: it binds an `instance_uid` to the
   host of the first report for it, it refuses a report under a binding that is
   another host's, it answers `404` for an artifact too large for its cache or
   whose fetch failed, and it answers `503` while a fetch runs (ADR-0026 clauses
   42, 47; clause 6). The client CA, the bootstrap CA and the list are the
   Server's, so the Gateway applies the Server's admission policy and holds no
   admission policy of its own (ADR-0021 clause 13,
   [ADR-0036](0036-a-bootstrap-certificates-subject-is-carried-into-the-host-certificate.md)
   clause 2). Upstream the Gateway presents the Client's own identity, so every
   downstream Agent arrives as a member, under the Gateway's certificate. The
   Gateway forwards no `Authorization`: one a downstream peer sends is ignored,
   never refused, and nothing is sent upstream in its place. The downstream hop
   speaks TLS 1.3 only. A downstream certificate is never forwarded, and no
   header is invented for it. There is no plaintext Gateway, on the loopback
   neither, because a Gateway admits Agents.

5. **Restates ADR-0015 clause 13. Routing is by `instance_uid`, for the host it
   is bound to.**
   - Every downstream report of a member first binds its `instance_uid` (clause
     6). It is forwarded upstream only when its `instance_uid` is bound to the
     host of the certificate that sent it, and only then does the connection or
     exchange that carried it become the Agent's route.
   - A report for an `instance_uid` bound to another host, or one the Gateway
     could not bind, is not forwarded and creates no route. Over WebSocket it is
     dropped. Over plain HTTP it is answered `403`, with a message saying that
     the `instance_uid` is not this host's to report for. Either way it is
     logged as every refusal of the Gateway is: the first five per host and
     minute one by one, the rest counted into one line (ADR-0026 clause 46).
   - A report of an enrolling peer binds nothing. It is forwarded as clause 11
     says, and its exchange is its route for its one reply, gone when the reply
     is sent or the exchange ends.
   - Upward a forwarded report goes out on its Agent's connection. Downward the
     Gateway looks up, per `instance_uid`, the downstream connection or pending
     plain-HTTP exchange that last carried the Agent, which is always one of the
     bound host's or an enrolling peer's own exchange. A `ServerToAgent` for an
     Agent it does not carry is dropped with a log line, never broadcast.

6. **Restates ADR-0026 clause 45. Downstream, a host receives only what the
   Gateway relayed to its own Agents.** The Gateway serves
   `GET /api/v1/packages/{agent_type}/{version}/file` on its downstream
   listener, behind the handshake and the revocation verdict of its `/v1/opamp`:
   a certificate from `client_ca_file` is required, a revoked one is answered
   `401` and every request is answered `503` while the Gateway holds no current
   list (ADR-0015 clause 14, clause 4).
   - **Binding.** An `instance_uid` is bound to the host of the certificate of
     the first downstream connection that reports for it since the Gateway
     started, as the Server binds an `instance_uid` to the host that first
     reports it (ADR-0036 clause 2). The host is the one the certificate names
     (`urn:opamp-fleet:host:<id>`). A certificate that names none is a host of
     its own: the host the Server derives from its issuer and serial when it
     first renews it (ADR-0036 clause 2), computed the same way. So it neither
     shares a binding with another certificate nor takes one over, and the
     certificate its renewal brings names the same host. The derived host binds
     for routing only: offers and downloads are recorded and served only for a
     host a certificate names (_Offers_, _Requests_). A host holds at most
     `max_carried_agents` bindings, the number ADR-0015 clause 4 bounds a
     connection by. Past that its report for a new `instance_uid` takes the
     place of that host's own least recently reported binding whose
     `instance_uid` has neither a downstream route nor a current offer, so a
     host whose Agents come and go is never shut out by its own past; when it
     has none, the report binds nothing, and that is logged. The Gateway holds
     at most 1 000 000 bindings in all; past that a new binding takes the place
     of the least recently reported binding whose `instance_uid` has neither a
     downstream route nor a current offer, and when there is none, it binds
     nothing, and that is logged. Each report refreshes when its binding was
     last reported. What a report that binds nothing does is clause 5's.
   - **Offers.** An offer relayed to an `instance_uid` is recorded only when the
     downstream connection it is relayed over presents a certificate of the host
     the `instance_uid` is bound to; any other is not recorded, and that is
     logged. An Agent's current offer is the files of the last recorded
     `packages_available` relayed to it: a later one replaces it, one that names
     no Server-hosted file removes it, a message without `packages_available`
     leaves it standing (ADR-0026 clause 36), and a downstream disconnect does
     not end it. The offers held are bounded by the offers the Server makes
     through the Gateway. The bindings and the offers are kept in memory only,
     and the offers are indexed by host.
   - **Requests.** A request is served only when the Gateway holds the artifact
     and a current offer of it (the same path and query, byte for byte) to an
     `instance_uid` bound to the host the request's certificate names. A
     certificate that names no host receives nothing. While an offered artifact
     is being fetched, or waits for a fetch slot, the request is answered `503`
     with `Retry-After: 30` instead of waiting, so a Client's read timeout does
     not run out while the Gateway fetches. An offered artifact that is neither
     held nor being fetched is fetched on a request at most once per relayed
     offer of it — the next relayed offer re-arms it — and that request is
     answered `503` with `Retry-After: 30`. After a failed fetch it is not
     fetched again until ADR-0026 clause 42 says so.
   - **Everything else** is answered `404`, with the same status, headers and
     body whether no such offer was recorded, it was recorded for another host,
     the artifact could not be fetched or verified, it is too large for the
     cache, or the request names nothing the route knows.

   The bound on what a host receives is ADR-0035 clause 2's, applied to what the
   Server sent through the Gateway. The binding, the `404` for an artifact too
   large or not fetched, and the `503` while a fetch runs are the Gateway's own.
   Together they are the download refusal of clause 4.

7. **The bootstrap proof.** An enrolling Client adds to its CSR the SAN URI
   `urn:opamp-fleet:bootstrap:v1:` followed by the base64url, without padding,
   of the bootstrap certificate's DER and a signature made with its key over
   `opamp-fleet-bootstrap-v1\n<SHA-256 of the new SubjectPublicKeyInfo,
   lowercase hex>\n`,
   the certificate prefixed by its length as four big-endian bytes, as the
   renewal proof is (ADR-0021 clause 27). The statement differs from the
   renewal's, so neither proof can stand for the other. The Client sends it on
   every enrolment, directly or not.

8. **The Server checks the proof itself.** It reads the CSR once, from exactly
   one PEM block with nothing but white space around it, and takes the proof,
   the key it covers, the claims and the key it signs from that one encoding;
   any other input is answered `BadRequest`. It accepts the proof only when the
   certificate was issued by the bootstrap CA of `[enrolment]`, is a
   client-authentication leaf as the handshake requires one (`clientAuth`, not a
   CA), is valid now, is not revoked, and its key verifies the signature over
   the CSR's own key. A proof that does not hold is answered `BadRequest`, and
   nothing is queued. A CSR that carries both a renewal proof and a bootstrap
   proof is answered `BadRequest`.

9. **The request is filed under the certificate it proves.** The requester of an
   enrolment request — the bootstrap certificate's issuer and serial, its
   fingerprint, its subject and the values an approval carries — is read from
   the certificate the request proves. On an enrolment connection a request
   proves the certificate of the handshake: a bootstrap proof there must name
   that certificate, or the request is answered `BadRequest`, and a request
   without one proves the handshake's certificate alone, so a client that sends
   no proof still enrols directly. Where a request may arrive other than on an
   enrolment connection is a decision of its own.

10. **Restates ADR-0036 clause 3. An approval copies the subject from the
    bootstrap certificate the request proves, and validates it again.**

- The Server reads the six attributes from the bootstrap certificate the request
  proves (clause 9). That certificate may come from a foreign PKI, so the Server
  applies ADR-0036 clause 1's rules again.
- An attribute that appears twice, has the wrong encoding or length, or is a
  `country` that is not two upper-case letters, and a missing `organization` or
  `organizational_unit`, make the approval fail (`409`) with a message naming
  the attribute. Nothing is signed, and the request stays waiting until the
  operator rejects it.
- The right encoding is `PrintableString` for `country`. For the other five it
  is `UTF8String` or `PrintableString`, which older PKIs write and which is a
  subset of it; the host certificate carries them as `UTF8String`.
- A `country` is checked by its shape, two upper-case letters, not against the
  ISO 3166-1 list. The Enrolments tab offers the list.
- Other attributes of the bootstrap certificate are not copied. Its common name
  is never copied, because the host certificate's is ADR-0028 clause 28's.

11. **An enrolling peer sends one thing, over plain HTTP.** A WebSocket upgrade
    from an enrolling peer is refused `403`, with a message saying that an
    enrolment through a Gateway is a plain-HTTP exchange. A plain-HTTP report of
    an enrolling peer is forwarded only when it carries a CSR with a bootstrap
    proof (clause 7) and nothing a member reports — no description, health,
    effective configuration, package statuses or connection settings beyond the
    CSR; any other is answered `403` and logged. The Gateway reads the CSR by
    the Server's rule of one PEM block (clause 8) and forwards it only when the
    certificate the proof embeds is, byte for byte, the one the peer presented
    in the handshake; any other is answered `403` and logged. So an enrolling
    peer proves only its own certificate, and spends no other certificate's
    tokens (clause 13). The Gateway does not check the proof's signature: the
    Server does. It records no offer for an enrolling peer and serves it no
    download. The Client re-sends its request until it is answered, as on a
    direct enrolment connection (ADR-0021 clause 21), and collects its
    certificate in the reply to the request that finds it approved. A Client
    that holds no issued certificate and whose endpoint is `https://` or
    `http://` therefore sends its CSR alone from its first report on, so a
    Gateway relays it; answered `BadRequest`, it falls back to the reports of a
    member until an exchange fails, so a host that holds a provisioned member
    certificate is not held up. A Client behind a Gateway names it with an
    `https://` endpoint while it enrols.

12. **The Server decides an enrolment through a Gateway as any enrolment.** A
    CSR that carries a bootstrap proof over the certificate of a host marked as
    a Gateway is an enrolment request: the proof is checked (clause 8), the
    request is filed under the certificate it proves (clause 9), it waits for an
    open window, counts against the queue and against whatever share of it one
    bootstrap certificate may hold, and waits for an operator's approval, which
    mints a host of its own, never the Gateway's. Without an open window it is
    answered `Unavailable`, as on an enrolment connection. The pending request
    names the Gateway's host instead of a peer address, in the queue and in
    every audit entry of it. Through a Gateway the proof carries no chain, so
    its certificate must be issued directly by the bootstrap CA. A CSR with a
    bootstrap proof over a certificate whose host is not marked as a Gateway is
    answered `BadRequest`: a member does not enrol. A proof that names the
    certificate the connection presented is no proof of a bootstrap certificate
    but of that certificate itself, which a Client that cannot tell a
    provisioned member certificate from a bootstrap certificate sends; the CSR
    is then read as one without a proof (clause 1).

13. **Restates ADR-0013 clause 22. Which bucket a message or a download is
    counted in.** The key comes from the certificate admission proved (`Proofs`
    in [`transport.rs`](../../crates/fleet-server/src/transport.rs)):

- **A certificate that names a host:** that host.
- **A member's certificate that names no host** (one an operator provisioned
  that has not been renewed yet): its issuer and serial.
- **A bootstrap certificate on an enrolment connection:** the peer address, an
  IPv6 one by its /64 (`throttle::peer_key`). A bootstrap certificate may be one
  for the whole fleet (ADR-0021 clause 10), so its issuer and serial would put
  every enrolling host in one bucket. The enrolment window, the bound on the
  queue and the operator's approval already bound what enrolment costs (ADR-0021
  clauses 20 and 21).
- **A host marked as a Gateway** (`Revocations::is_gateway`), in two buckets,
  and a message must take a token from both:
  - the bucket of the Agent the message names, keyed by the host and the
    message's `instance_uid` and sized by `messages_per_sec` and `burst`;
  - the Gateway's aggregate, keyed by the host and sized by
    `gateway_messages_per_sec` and `gateway_burst`.

  A message carrying an enrolment request (clause 12) takes from neither, so
  enrolments cannot spend what the Gateway's members need. Once the bootstrap
  certificate its proof embeds is checked as the handshake checks one — issued
  by a bootstrap CA with a signature that verifies against it, valid now, not a
  CA, and `clientAuth` among its key usages where it names any — it takes a
  token from a bucket keyed by the host and that certificate, sized by
  `messages_per_sec` and `burst`, and one from the Gateway's **enrolment
  aggregate**, keyed by the host and sized by `gateway_messages_per_sec` and
  `gateway_burst`, so one bootstrap certificate empties its own bucket long
  before the aggregate and cannot spend another's tokens. One that fails that
  check takes a token from the Gateway's bucket for unchecked enrolments alone,
  keyed by the host and sized by `messages_per_sec` and `burst`: a forged
  certificate never makes a bucket of its own, and forged proofs spend neither
  the members' tokens nor the checked enrolments'.

  A message whose `instance_uid` is not 16 bytes, an undecodable message, and a
  download request through a Gateway name no Agent, so they are counted in the
  aggregate alone. The mark is read per message, so marking or unmarking a
  Gateway takes effect at the next message.

A connection with no certificate exists only behind `Admission::open`, which no
Server configuration serves (ADR-0021 clause 6). It is counted by its peer
address.

**Out of scope:**

- keeping the Gateway's bindings across its restart; after a restart the first
  report for an `instance_uid` binds it again;
- binding at the Server the `instance_uid`s a Gateway carries, so that a member
  connecting directly cannot claim one first;
- a rate per downstream member certificate at the Gateway;
- a bootstrap certificate issued below an intermediate CA, which cannot enrol
  through a Gateway (the proof carries no chain); a member certificate issued
  below an intermediate of the client CA, which a Gateway with
  `bootstrap_ca_file` takes for an enrolling peer, as the Server takes one for
  an enrolling host (ADR-0021 clause 19);
- a proof for a bootstrap certificate from a CA other than `[enrolment]`'s;
- enrolment through nested Gateways, where the outer Gateway sees the inner
  one's certificate;
- a WebSocket push of the approval to an enrolling peer behind a Gateway, and
  telling a Gateway whether a window is open.

## Alternatives considered

- **Issue a proofless CSR through a Gateway to a host of its own.** A
  third-party client behind a Gateway could still renew, but each such CSR would
  mint a host that no operator approved. Rejected.
- **Issue it to the Gateway's host, but without the mark.** The mark belongs to
  the host, and the certificate would still fill one of the Gateway host's three
  places. Rejected.
- **Let the Gateway refuse a CSR without a proof.** A Server that trusts the
  Gateway to do so is only as safe as the oldest Gateway in the fleet; the
  Server sees the presented certificate and decides on its own. Rejected.
- **Persist the Gateway's bindings.** This closes the window after a restart,
  but the Gateway would keep state on disk that it would have to defend.
  Rejected for now.
- **Bind per connection instead of per host.** A reconnect would lose every
  binding; the host is what the certificate proves. Rejected.
- **Forward an unbindable report as before.** That is the unbounded growth the
  per-host cap exists to stop, and an unbound `instance_uid` could later be
  bound by anyone. Rejected.
- **Key a certificate without a host by its issuer and serial as such.** Its
  first renewal brings a certificate that names the derived host, which the
  Gateway would see as another host. Rejected: the derived host is the key
  (clause 6).
- **The Gateway forwards the downstream certificate in a header.** The Server
  would have to trust the Gateway's word for it. Rejected.
- **Reuse the renewal proof's statement for the bootstrap proof.** A statement
  of its own keeps the two apart by construction. Rejected.
- **Require the bootstrap proof on direct enrolment too.** A third-party OpAMP
  client could no longer enrol at all; the handshake already proves the
  certificate on a direct connection. Rejected.
- **Admit enrolling peers without a client certificate.** Anyone on the network
  would then reach the Gateway and, through it, the Server. Rejected.
- **Let the Gateway know whether a window is open; carry enrolment over
  WebSocket; bind the enrolling peer and release the binding on approval.** Each
  needs state the Gateway does not hold. Rejected.
- **Throttle enrolment by bootstrap certificate everywhere.** On a direct
  connection a fleet-wide bootstrap certificate would put every enrolling host
  in one bucket. Rejected for direct connections.

## Sources / Prior art

- The code as it stood: `renews` in `crates/fleet-server/src/fleet.rs` fell back
  to the presented certificate's host; `forward_from_socket` and
  `forward_exchange` in `crates/fleet-agent/src/gateway/mod.rs` forwarded
  without consulting the binding that `PackageCache::bind` already held;
  `renewal_proof` and `sign` in `crates/fleet-server/src/ca.rs` read one CSR
  through x509-parser's and the `pem` crate's PEM readers, which select
  different blocks of a crafted input.
- The OpAMP specification's Agent-initiated CSR flow: the Agent requests, and
  the Server decides what it signs. Recalled, not re-read for this record.
- RFC 4210 (CMP), section 5.3.1: proof of possession by a signature with the key
  of the certificate a request rests on. Recalled, not re-read for this record.

## Consequences

- Positive: a member behind a Gateway can no longer obtain a certificate that
  carries the Gateway's powers, take over another host's Agent, or fill the
  Gateway host's places. Every certificate renewed through a Gateway stays in
  its own chain.
- Positive: a host that only a Gateway connects can enrol, with the same window,
  queue and approval as one that connects directly, and its certificate is its
  own host's.
- Positive: a proof and the key the Server signs always come from the same
  request.
- Negative / trade-offs: a third-party OpAMP client behind a Gateway renews only
  with a proof, which it cannot send; it enrols directly or gets its certificate
  from the operator. After a Gateway restart, whichever host reports an
  `instance_uid` first binds it. A host whose `max_carried_agents` Agents are
  all connected or offered something cannot bring in another until one goes
  idle. A Gateway with `bootstrap_ca_file` lets a holder of a bootstrap
  certificate reach the Server through it outside a window too; the Server
  answers `Unavailable`, and the throttle bounds the cost. An enrolling host
  behind a Gateway learns of its approval at its next poll. Hosts that enrol
  through one Gateway with one bootstrap certificate share that certificate's
  bucket, as hosts behind one address share one on a direct connection.
- Follow-ups: binding at the Server what a Gateway carries; a rate per
  downstream certificate; enrolment through nested Gateways; a push of the
  approval.

## Enforcement

Tests that will carry `Verifies: ADR-0039`:

- A CSR without a proof over a Gateway's certificate is answered `BadRequest`
  naming both proofs, signs nothing, and records `issuance.refused`; over an
  unmarked host's certificate it still renews that certificate; a CSR with a
  valid renewal proof through a Gateway is issued to the proven certificate's
  host, with that certificate as the predecessor.
- A CSR that is not exactly one PEM block — text before or after it, text on its
  boundary lines, two blocks — is refused on the renewal path and on both
  enrolment paths, and no Server code reads a CSR through another PEM reader.
- A report from a second host for an `instance_uid` bound to a first host is not
  forwarded, over WebSocket and over plain HTTP (`403`), and the Server's next
  reply reaches the first host. A report past a host's `max_carried_agents` is
  not forwarded while all its bindings have a route; once one of its own Agents
  is idle, the new report takes that binding's place. Two certificates that name
  no host bind separately, and a certificate that names none and the certificate
  its renewal brings report for the same `instance_uid` without a refusal.
- The bootstrap proof round-trips, and its statement differs from the renewal
  proof's; the Client's enrolment CSR carries one that names its bootstrap
  certificate. On an enrolment connection a proof of another certificate, a bad
  signature or both proofs are answered `BadRequest`; a request without a proof
  is queued under the handshake's certificate; a revoked bootstrap certificate's
  proof is refused.
- A Gateway with `bootstrap_ca_file` admits a bootstrap certificate over plain
  HTTP only, forwards only a CSR whose proof embeds the certificate the peer
  presented, and binds nothing for it; a Gateway without the key refuses the
  certificate in the handshake; a CA in both files fails startup. End to end
  through a Gateway, an enrolment waits in the queue naming the Gateway's host,
  its approval mints a new host, and the enrolling Client then reports as a
  member under its own `instance_uid`.
- Enrolments through a Gateway spend none of its members' tokens; forged proofs
  make no bucket of their own; one bootstrap certificate cannot spend another's
  tokens.
