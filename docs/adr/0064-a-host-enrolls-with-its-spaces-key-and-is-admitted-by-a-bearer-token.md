# ADR-0064: A host enrolls with its space's key and is admitted by a bearer token

- **Status:** 🟡 proposed
- **Date:** 2026-11-16
- **Deciders:** Marco Zanon
- **Applies to:** admission on `/v1/opamp` and on the package download route of
  the Agent plane in `crates/classis-server/src/transport.rs`, the Server's TLS
  in `crates/classis-server/src/tls.rs`, the new `/v1/enroll` and `/v1/token`
  routes, the Server's records of spaces, clients and tokens and their fs and
  PostgreSQL adapters, the crates `crates/oauth-registration/` and
  `crates/oauth-token/`, the Client's `enroll` and `revoke` commands, its
  `state.json`, the `Authorization` header it sends in
  `crates/classis-agent/src/transport/` and `crates/classis-agent/src/packages.rs`,
  the removal of every client certificate, CA, CSR, renewal, PKCS#12 and
  revocation-list path from `crates/`, `crates/classis-agent/src/gateway/`,
  `fuzz/`, `scripts/` and `packaging/`, and every document that tells an
  operator how a host joins the fleet

## Context

Today an Agent proves it belongs to the fleet with a client certificate in the
TLS handshake. The Server holds a client CA and a bootstrap CA, a host enrolls
by sending a CSR inside OpAMP while an operator holds an enrollment window open,
an operator approves each request, certificates are renewed at two thirds of
their life, and a revocation list follows every renewal chain out to the
Gateways. The certificate also carries the host's identity
(`urn:classis:host:<id>`) and the subject values Selectors see as
`fleet.host.*`. All of this is a lot of machinery for one question: _is this
host one we let in?_

The target design is the enrollment LLD ("LLD | Classis Enrollment", see
Sources), _Machine login phase_, option 2:

- Every host belongs to exactly one **space**, identified by its name. Each
  space has exactly one active **enrollment key**, reusable without limit; a
  valid key enrolls the host at once, with no operator approval.
- The host registers itself as an OAuth 2.0 client with that key (RFC 7591,
  dynamic client registration) and receives a `client_id` and a
  `client_secret`.
- With those it obtains an **access token** through the client-credentials
  grant (RFC 6749 §4.4) and presents it as a bearer token (RFC 6750) on every
  request. A new token revokes the previous one.
- The Server has a TLS certificate the hosts already trust; every
  connection is HTTPS with a valid certificate.

The human settled the open points in interrogation: the token is opaque and
the Server keeps only its hash; one registered client is one host; the token
is the host's main credential and the client credentials exist only to rotate
it without losing the host's identity; the token lifetime is a setting whose
Classis default is "never expires"; the two OAuth pieces are two standalone
crates, each with a server and a client half; there is no migration, because
no fleet runs on the certificate model; and Gateway Mode is removed now and
designed again later.

**Conflict with the specification.** `docs/SPECIFICATION.md` still requires a
client certificate in its strategy "Security before convenience", in G-15
(Gateway admission by the client CA), G-17 ("mutual TLS is required") and Q-1
(no Agent admitted "without a client certificate"). The specification wins over
an ADR ([AGENTS.md §3](../../AGENTS.md#3-adr-rules), rule 5). The human has
postponed the specification change; this ADR cannot be accepted before that
change lands, and it names those four passages for it.

**The ADRs this replaces.** The certificate model is spread over many accepted
ADRs. This record is written against the governance reset proposed in pull
request #4, which removes the inherited ADRs, so it supersedes none of them
clause by clause. Until that reset lands, the conflicting ADRs stay in force and
this one stays `proposed`.

## Decision

We will admit a host by an opaque bearer access token, which it obtains through
the OAuth 2.0 client-credentials grant with a client it registered under RFC 7591
using its space's enrollment key, and remove client certificates and everything
built on them.

1. **Spaces and the enrollment key.** A space's name matches
   `^[A-Za-z0-9]([A-Za-z0-9_]{0,30}[A-Za-z0-9])?$`: 1 to 32 letters, digits and
   underscores, starting and ending with a letter or digit. It has exactly one
   active key of the form `cle1_<space>_<secret>`: the fixed prefix `cle1_` (so
   secret scanners and log redaction recognize it), the space name, `_`, and 26
   characters of Crockford base32 (130 random bits). A space name may contain
   `_`, so a key is read from both ends: the prefix, then the last 26
   characters as the secret, then the `_` before them; what lies between is the
   space. The Server stores only `SHA-256(key)` and the space. The key is
   reusable without limit and auto-approves. Replacing it makes the old key
   enroll nothing; hosts already enrolled keep their client and their token.
   How an operator creates a space and replaces its key is outside this
   decision.
2. **Registration** is `POST /v1/enroll` on the Agent plane, following RFC 7591
   with the enrollment key as its _initial access token_:
   `Authorization: Bearer cle1_…`, never in the URL (RFC 6750 §5.3). The Server
   accepts only `grant_types: ["client_credentials"]` and
   `token_endpoint_auth_method: "client_secret_basic"` (or neither, meaning
   these) and answers other metadata with `invalid_client_metadata`. On success
   it answers `201 Created` with `client_id`, `client_secret` (256 random bits),
   `client_id_issued_at`, `client_secret_expires_at: 0` and the `space` the key
   named. An unknown key is answered `401` with
   `WWW-Authenticate: Bearer error="invalid_token"`. The Server stores the
   client, its space and `SHA-256(client_secret)`.
3. **One client is one host.** The `client_id` is the host's identity, the
   _device ID_ of the LLD. Every Agent on the host (the Client's own Agent and
   each Supervisor's) speaks under the host's one token; an `instance_uid` stays
   per Agent and is bound to the host, as before. The host records the space it
   enrolled in, taken from the key, never from what the host sends.
4. **Token** is `POST /v1/token` on the Agent plane: RFC 6749 §4.4,
   `grant_type=client_credentials`, the client authenticated with HTTP Basic
   (§2.3.1). Unknown client or wrong secret is `401 invalid_client`; any other
   grant is `unsupported_grant_type`. On success the Server answers `200` with
   `access_token` (256 random bits), `token_type: "Bearer"` and `expires_in`
   when the token expires, with `Cache-Control: no-store` (§5.1). A client has
   exactly one active token, kept on the client's own record as
   `SHA-256(access_token)` and its expiry, beside `SHA-256(client_secret)`.
   Issuing a token overwrites both, and that overwrite is the revocation of the
   one before: no list of issued tokens, no token ID.
5. **Token lifetime** is the Server setting `token_lifetime_secs`; `0` means the
   token never expires, and `0` is Classis's default. The token crate has no
   default: its server cannot be built without a lifetime.
6. **Admission.** `/v1/opamp` (WebSocket and plain HTTP) and the package
   download route admit a request only with `Authorization: Bearer <token>`
   whose hash is a client's active token and has not expired. A missing token is
   `401` with `WWW-Authenticate: Bearer`; a wrong, replaced or expired one is
   `401` with `error="invalid_token"`. The admitted host is the token's client.
   The check happens when a request is admitted: every plain-HTTP exchange and
   every download, and a WebSocket session once, at its upgrade. An open
   WebSocket session is not ended when its token expires; the Client meets the
   expiry at its next connection. It is ended when its token is replaced: the
   Server closes every session admitted with the old token, with close code
   1008 (policy violation), since replacing the token is how a stolen one is
   cut off. The Agent plane asks for no client certificate. The per-IP back-off
   on refused attempts applies to `/v1/enroll`, `/v1/token` and admission
   alike, and every decision is a log event
   ([ADR-0022](0022-security-decisions-are-structured-log-events.md)) that
   never carries a key, secret or token.
7. **On the host**, `enroll` takes the endpoint and the enrollment key, and
   nothing else: the space is stated in the key alone, so no command takes it a
   second time. `enroll` is refused on a host that holds a `state.json`. It
   registers, obtains a token, and writes `state.json` once in the Client's
   state directory, owner-only as the Client writes every secret: `endpoint`,
   `space` (as the Server returned it), `device_id`, `client_secret` and
   `access_token`. The Client sends the token on every request. Only when a
   request is answered `401 invalid_token` does it request a new token with its
   client credentials, rewrite `access_token` in `state.json` and retry; it
   keeps no expiry and never renews ahead of time, so an open WebSocket session
   is never cut by the Client's own renewal. Nothing else in the file changes
   after `enroll`. The service stays idle while no `state.json` exists.
   `revoke` is local only: it asks for confirmation (`--force` skips it),
   deletes `state.json`, and never contacts the Server; a new `enroll` creates
   a new device ID.
8. **Two standalone crates.** `oauth-registration` (RFC 7591) and `oauth-token`
   (RFC 6749 client credentials) know nothing of Classis. Each has a `server`
   module, an axum handler over a storage trait the application implements,
   and a `client` module, the one request the host makes. Each implements only
   what Classis uses: no redirect URIs, no other grants, no scopes, no refresh
   tokens, no registration management (RFC 7592). Their request parsers bound
   the body before they parse it and have fuzz targets.
9. **Removed, as if it never existed.** Client certificates, the client and
   bootstrap CAs, CSRs and the CSR flow in OpAMP connection settings, the
   renewal and bootstrap proofs, PKCS#12, the enrollment window and operator
   approval, the certificate register and revocation list with their routes,
   the `fleet.host.*` subject values, the `pki` commands that make those CAs,
   their configuration sections, stores and tests, and **Gateway Mode** with
   its code. Nothing is migrated and no old file, key or section is still
   read; the PostgreSQL schema keeps no table for them, since no installation
   exists to upgrade. Package signing and its keys stay.

**Out of scope:** the specification change; the operator's commands for spaces
and keys (create, list, replace, delete) and the ready-to-paste install command;
an operator removing an enrolled host and the garbage collection of orphaned
clients; `install.sh`, `install.ps1`, the download routes for the Client, and the
MSI's `ENDPOINT` and `TOKEN` properties; a redesigned Gateway Mode;
whether a host's space becomes an attribute Selectors match; and whether the
client secret and the access token carry a recognizable prefix like the key.

## Alternatives considered

- **Keep mutual TLS** — the system as it stands. Three CAs, a CSR flow, renewal
  proofs and revocation lists to answer whether a host may connect; enrollment
  needs an operator at a window, and certificates expire under hosts that stay
  offline. The design replaces it on purpose.
- **Request signing, RFC 9421 (the LLD's option 1)** — no bearer value to
  steal, but every request is signed and verified, which needs HTTP message
  signatures on both transports, including the WebSocket upgrade, and a
  library we do not have. Not the flow chosen.
- **A signed JWT access token** — what the LLD sketches. It would let a party
  check a token without the Server, but the Server looks every token up anyway
  to honour revocation, and nothing else checks tokens now the Gateway is gone.
  It adds a signing key to keep and rotate and a JOSE dependency; RFC 6749 §1.4
  leaves the format to the server.
- **Slow, salted hashes (Argon2) for the key, secret and token** — what a
  password needs. These values are 130 to 256 random bits; RFC 6819 §5.1.4.1.3
  asks for a salt only for low-entropy credentials, and a slow hash on every
  request would cost the Server for nothing.
- **An existing OAuth library** — `oxide-auth` (server, last release 0.6.1 in
  June 2024) is built around browser flows we do not use; `oauth2` (client,
  5.0.0) pulls `reqwest` 0.12 beside the workspace's 0.13, `rand` 0.8, `chrono`
  and `thiserror` 1 for one request. Two small crates cost less than either.
- **One crate for both endpoints** — registration and token retrieval are
  separate standards a deployment may use apart; two crates keep each usable
  alone.
- **One client per Agent** — every Supervisor would register and hold its own
  token, multiplying enrollments per machine and changing what a host is.
- **Token in memory only** — a fresh token on every start, and nothing but the
  secret on disk. Rejected: the token is the main credential, and a restart
  should not need the token endpoint.
- **A finite default lifetime** — a stolen token would be worth hours, not
  forever. The human chose "never expires" as Classis's default and a setting
  to shorten it; a token is replaced with one request when it leaks.
- **A record per issued token, keyed by a `jti`** — what the LLD sketches. With
  exactly one active token per client, the client's record already says which
  token is valid; a list of issued tokens would only hold revoked ones.
- **End a WebSocket session when its token expires** — the Server would have to
  watch every session's clock, and a Client holding a working session would be
  pushed into a second request it has no other reason to make. Expiry is met at
  the next admission instead; replacing a token still ends its sessions.
- **Renew the token ahead of its expiry** — the Client would replace the token
  under its own open sessions, and replacing ends them. Renewing on
  `invalid_token` alone needs no clock on the host.
- **Name the space on the command line too (`--space`)** — what the LLD's
  examples show. The key already names it; a second statement can only
  disagree with the first.
- **Refuse Gateway Mode at startup instead of removing it** — keeps code that
  cannot run and still depends on certificates. Rejected: the Gateway will be
  redesigned for tokens.

## Sources / Prior art

- Enrollment LLD: "LLD | Classis Enrollment", Confluence space N4, page
  6883115026, version 2 (2026-11-13), sections _Spaces_, _Enrollment key_,
  _Machine login phase_ option 2, _Wrong space_, _Server endpoints_ and
  _Where the host saves its space_.
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), OAuth 2.0 Dynamic
  Client Registration: §1.2 (initial access token), §3 (presented as a bearer
  token), §3.2.1 (`client_id`, `client_secret`, `client_secret_expires_at`, `0`
  for no expiry, `201 Created`), §3.2.2 (`invalid_client_metadata`).
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), OAuth 2.0: §1.4 (a
  token is "usually opaque to the client"), §2.3.1 (HTTP Basic), §4.4 (client
  credentials), §5.1 (`expires_in`, `Cache-Control: no-store`), §5.2
  (`invalid_client`, `unsupported_grant_type`).
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html), Bearer Token Usage:
  §2.1, §3 and §3.1 (`WWW-Authenticate`, `invalid_token`), §5.3 (no token in a
  URL).
- [RFC 6819](https://www.rfc-editor.org/rfc/rfc6819.html), OAuth 2.0 Threat
  Model: §4.3.2 ("Store access token hashes only") and §5.1.4.1.3 (no cleartext
  storage; a salt for low-entropy credentials).
- crates.io, read 2026-11-16: `oauth2` 5.0.0 and its dependencies, `oxide-auth`
  0.6.1, `jsonwebtoken` 12.0.0.
- The existing code: the OpAMP client's `authorization` header in
  `crates/opamp/src/client/connection.rs`, sent on both transports and redacted
  in `Debug`, which the Client sets to `None` today.

## Consequences

- Positive: a host joins with one command and no operator step; the Server's
  whole PKI goes, and with it renewal, expiry under offline hosts, revocation
  lists and the `pki` tooling for agents. The bearer header the OpAMP client
  already sends carries the credential.
- Positive: a database leak gives away no usable key, secret or token, since
  only hashes are stored.
- Negative / trade-offs: anyone holding a space's key can enroll a host into it
  until the key is replaced; the key is the space's admission secret and must
  be handled as one.
- Negative / trade-offs: a token that never expires is good until it is
  replaced; a stolen `state.json` lets its holder act as the host until a new
  token is issued. The host is the boundary, as it was for the certificate's
  private key.
- Negative / trade-offs: hosts that only a Gateway can reach cannot join until
  Gateway Mode is designed again.
- Negative / trade-offs: Selectors lose the `fleet.host.*` subject values;
  Deployments aimed by them must use Labels or what Agents report.
- Follow-ups: the specification change for the strategy, G-15, G-17 and Q-1;
  the operator commands for spaces and keys; removing a host; the install
  scripts, download routes and MSI properties; Gateway Mode on tokens; whether a
  space is visible to Selectors; replacing "enrolment" with "enrollment" in the
  glossary and the code.

## Enforcement

Tests that cite this ADR with `Verifies: ADR-0064`, written with the
implementation:

- `crates/oauth-registration/` and `crates/oauth-token/`: requests and answers
  as clauses 2, 4 and 8 state, including the refused metadata, grants and
  credentials, and the body bound. The token server's builder takes the
  lifetime as a required argument, so a missing lifetime does not compile.
- Unit tests of the key format: space names inside and outside the pattern of
  clause 1, and keys whose space contains `_` split into the right space and
  secret.
- `crates/classis-server/tests/enrollment.rs`: a valid key enrolls, an unknown
  or replaced key does not; a new token makes the previous one invalid; an
  expired or replaced token is refused on `/v1/opamp` and the download route; an
  open WebSocket session outlives its token's expiry and is closed with 1008
  when its token is replaced; a request with no token is refused; a client's
  record holds only hashes and only its active token; the Agent plane completes
  a handshake with no client certificate.
- `crates/classis-agent/tests/enrollment_e2e.rs`: `enroll` takes no space,
  writes `state.json` owner-only and refuses a second run; the Client requests
  a new token only after `invalid_token`; `revoke` deletes `state.json` without
  contacting the Server; the service idles while no `state.json` exists.
- The fuzz targets of clause 8 run in `fuzz.yml`.

**Not mechanically decidable:** that nothing of the certificate model is left
(clause 9). A search of `crates/`, `config/`, `scripts/`, `packaging/` and
`docs/` for `client_ca`, `bootstrap`, `csr`, `pkcs12`, `revocation` and
`gateway` is the review step.
