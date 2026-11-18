# ADR-0064: A host enrols with its space's key and is admitted by a bearer token

- **Status:** 🟡 proposed
- **Human review:** approved by the user on 2026-11-16 in this conversation.
  Formal acceptance remains pending the specification change and resolution of
  the conflicting accepted ADRs described below; the status is unchanged.
  Revised on 2026-11-17 with the user's implementation decisions: the key
  secret's encoding, the host that owns an Agent, `revoke`, the endpoint, TLS
  termination, the PostgreSQL schema, the `opamp` crate, own telemetry and the
  hosts route.
- **Date:** 2026-11-16
- **Deciders:** Marco Zanon
- **Applies to:** admission on `/v1/opamp` and on the package download route of
  the Agent plane in `crates/classis-server/src/transport.rs`, the Server's TLS
  in `crates/classis-server/src/tls.rs`, the new `/v1/enrol` and `/v1/token`
  routes, the Server's records of spaces, clients and tokens and their fs and
  PostgreSQL adapters, the PostgreSQL schema in
  `crates/classis-server/src/postgres/schema.rs`, the host an Agent's record
  names in `crates/classis-server/src/agent_store.rs` and
  `crates/classis-server/src/fleet.rs`, the crates `crates/oauth-registration/`
  and `crates/oauth-token/`, the unauthorized signal and the removed
  client-certificate and CSR support of `crates/opamp/`, the Client's `enrol`
  and `revoke` commands, its `state.json`, the `Authorization` header it sends
  in `crates/classis-agent/src/transport/`,
  `crates/classis-agent/src/packages.rs` and
  `crates/classis-agent/src/telemetry.rs`, the removal of `/api/v1/hosts` and of
  every client certificate, CA, CSR, renewal, PKCS#12 and revocation-list path
  from `crates/`, `crates/classis-agent/src/gateway/`, `fuzz/`, `scripts/` and
  `packaging/`, and every document that tells an operator how a host joins the
  fleet

## Context

Today an Agent proves it belongs to the fleet with a client certificate in the
TLS handshake. The Server holds a client CA and a bootstrap CA, a host enrols
by sending a CSR inside OpAMP while an operator holds an enrolment window open,
an operator approves each request, certificates are renewed at two thirds of
their life, and a revocation list follows every renewal chain out to the
Gateways. The certificate also carries the host's identity
(`urn:classis:host:<id>`) and the subject values Selectors see as
`fleet.host.*`. All of this is a lot of machinery for one question: _is this
host one we let in?_

The target design is the enrolment LLD ("LLD | Classis Enrollment", see
Sources), _Machine login phase_, option 2:

- Every host belongs to exactly one **space**, identified by its name. Each
  space has exactly one active **enrolment key**, reusable without limit; a
  valid key enrols the host at once, with no operator approval.
- The host registers itself as an OAuth 2.0 client with that key (RFC 7591,
  dynamic client registration) and receives a `client_id` and a
  `client_secret`.
- With those it obtains an **access token** through the client-credentials
  grant (RFC 6749 §4.4) and presents it as a bearer token (RFC 6750) on every
  request. A new token revokes the previous one.
- The Server has a TLS certificate the hosts already trust; every
  connection is HTTPS with a valid certificate.

The human settled the open points in interrogation: the access token is opaque
and the Server keeps only its hash, while the space's enrolment key is kept on
disk in recoverable form and changes only on explicit rotation; one registered
client is one host; the token is the host's main credential and the client
credentials exist only to rotate it without losing the host's identity; the
token lifetime is a setting whose Classis default is "never expires"; the two
OAuth pieces are two standalone crates, each with a server and a client half;
there is no migration, because no fleet runs on the certificate model; and
Gateway Mode is removed now and designed again later. A host that loses its
`state.json` is lost for good, and whatever is stored for it is garbage.

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
this one stays `proposed`. Four of them are named here because the reset alone
does not explain the contradiction:
[ADR-0050](0050-the-servers-records-may-live-in-postgresql.md) clause 5 lets a
migration only add, and clause 9 below rewrites the schema's first migration
instead; ADR-0050 clause 4 has the Server answer from memory, while the stores
of spaces and clients are read per request;
[ADR-0037](0037-the-servers-state-lives-under-one-data-directory-one-store-per-domain.md)
clause 2 fixes the data directory's layout, which gains `spaces/` and
`clients/`; and
[ADR-0016](0016-what-an-agent-reports-about-itself.md) point 32 has an offered
`certificate` behave as on the OpAMP connection, while clause 9 below ignores
it.

## Decision

We will admit a host by an opaque bearer access token, which it obtains through
the OAuth 2.0 client-credentials grant with a client it registered under RFC 7591
using its space's enrolment key, and remove client certificates and everything
built on them.

1. **Spaces and the enrolment key.** A space's name matches
   `^[A-Za-z0-9]([A-Za-z0-9_]{0,30}[A-Za-z0-9])?$`: 1 to 32 letters, digits and
   underscores, starting and ending with a letter or digit. A name keeps the
   case it was created with, but two spaces may not have names that differ
   only in case; a key names its space exactly. It has exactly one
   active key of the form `cle1_<space>_<secret>`: the fixed prefix `cle1_` (so
   secret scanners and log redaction recognize it), the space name, `_`, and a
   secret of 256 random bits written as 43 characters of base64url without
   padding (RFC 4648 §5), made by the same generator as the client secret and
   the access token. A space name may contain `_` and the secret may contain
   `_` and `-`, so a key is read from both ends: the prefix, then the last 43
   characters as the secret, then the `_` before them; what lies between is the
   space. The Server persists the complete enrolment key with its space on
   disk in recoverable form, not only as `SHA-256(key)`, so the same key can be
   retrieved again after a restart. Reading the key, enrolling a host or
   restarting the Server does not replace it: only an explicit rotation
   request creates and persists a new one. The key is reusable without limit
   and auto-approves. Rotation makes the old key enrol nothing; hosts already
   enrolled keep their client and their token. The stored key is protected as
   a secret. The operator's commands for creating a space, retrieving its key
   and requesting rotation are outside this decision.
2. **Registration** is `POST /v1/enrol` on the Agent plane, following RFC 7591
   with an `application/json` request and the enrolment key as its _initial
   access token_: `Authorization: Bearer cle1_…`, never in the URL (RFC 6750
   §5.3). The Client explicitly sends `grant_types: ["client_credentials"]` and
   `token_endpoint_auth_method: "client_secret_basic"`. The latter may be
   omitted and defaults to `client_secret_basic`; omitted `grant_types`
   defaults to `authorization_code` under RFC 7591 §2, which this profile does
   not support. Unsupported values of these understood metadata fields,
   including that default grant, receive `400` with an `application/json`
   body containing `error: "invalid_client_metadata"`. Metadata the Server
   does not understand is ignored, not rejected (§2).

   On success it answers `201 Created`, `Content-Type: application/json`, with
   `client_id` (a UUID version 7, RFC 9562),
   `client_secret` (256 random bits, encoded as in clause 1),
   `client_id_issued_at`, `client_secret_expires_at: 0`, and all registered
   metadata (§3.2.1), including `grant_types: ["client_credentials"]` and
   `token_endpoint_auth_method: "client_secret_basic"`. Classis adds the
   `space` the key named as a response extension, never from client-supplied
   metadata. The response carries `Cache-Control: no-store` and
   `Pragma: no-cache`. Missing, invalid and malformed bearer authentication
   follows clause 6; an unknown or replaced key is an invalid token. The
   Server stores the client, its space and `SHA-256(client_secret)`.
3. **One client is one host.** The `client_id` is the host's identity, the
   _device ID_ of the LLD. The Server derives it from the credential a request
   presents; a host never states an identity of its own. Every Agent on the
   host (the Client's own Agent and each Supervisor's) speaks under the host's
   one token. An `instance_uid` stays per Agent, and the Agent's record names
   the host it reports under: the record's host is the `client_id`, and no
   other store keeps that binding. A report whose `instance_uid` is recorded
   under another client is refused, and one client owns at most 256
   `instance_uid`s. Which packages a host may download follows from the same
   records. The host records the space it enrolled in, taken from the key,
   never from what the host sends.
4. **Token** is `POST /v1/token` on the Agent plane: RFC 6749 §4.4, with a
   UTF-8 `application/x-www-form-urlencoded` body containing
   `grant_type=client_credentials`. The client authenticates with HTTP Basic:
   the client identifier and secret are each form-encoded before they become
   the Basic username and password (§2.3.1), and the Server decodes them in
   reverse order. Client credentials in the body are not supported. Empty
   parameter values count as omitted, unknown request parameters are ignored,
   and repeated parameters or multiple authentication methods are refused
   (§§2.3, 3.2).

   Errors have an `application/json` body with an `error` field (§5.2):

   - Unknown client or wrong Basic secret is `401 invalid_client`, with
     `WWW-Authenticate: Basic realm="token"`; missing client authentication
     receives the same response. An unsupported `Authorization` scheme is
     `401 invalid_client` with a challenge matching the scheme the client used,
     as §5.2 requires; that challenge does not mean the method is supported.
   - A missing or empty `grant_type`, repeated parameters, multiple client
     credentials or an otherwise malformed request is `400 invalid_request`.
   - Another grant type is `400 unsupported_grant_type`.
   - A non-empty `scope` is `400 invalid_scope`: this profile defines no scopes.

   On success the Server answers `200`, `Content-Type: application/json`, with
   `access_token` (256 random bits, encoded as in clause 1, which fits the
   token syntax of RFC 6750 §2.1), `token_type: "Bearer"`, and `expires_in` in
   seconds when the token expires. A non-expiring token omits `expires_in`;
   clause 5 documents that lifetime. No refresh token is issued (§4.4.3).
   Responses containing tokens or credentials carry both
   `Cache-Control: no-store` and `Pragma: no-cache` (§5.1). A client has
   exactly one active token, kept on the client's own record as
   `SHA-256(access_token)` and its expiry, beside `SHA-256(client_secret)`.
   Issuing a token overwrites the token hash and expiry, and that overwrite is
   the revocation of the one before: no list of issued tokens, no token ID.
5. **Token lifetime** is the Server setting `token_lifetime_secs`; `0` means the
   token never expires, and `0` is Classis's default. The token crate has no
   default: its server cannot be built without a lifetime.
6. **Admission.** `/v1/opamp` (WebSocket and plain HTTP) and the package
   download route admit a request only with `Authorization: Bearer <token>`
   whose hash is a client's active token and has not expired. The header uses
   RFC 6750 §2.1's syntax; the authentication scheme is case-insensitive and
   the token value is case-sensitive. Tokens in a URL or a form body are not
   supported, and the Client never sends them there. No authentication, or an
   unsupported authentication scheme, receives `401` with
   `WWW-Authenticate: Bearer realm="fleet"` and no error code. A wrong,
   malformed, replaced or expired token receives `401` with
   `WWW-Authenticate: Bearer error="invalid_token"`. A malformed request,
   including repeated token parameters or more than one token-transmission
   method, receives `400` with
   `WWW-Authenticate: Bearer error="invalid_request"` (§§2, 3, 3.1). The
   admitted host is the token's client.

   Where TLS terminates, on the Server or on a reverse proxy in front of it, is
   left to a later decision. This one changes nothing in the listener rules of
   [ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md),
   and the Agent plane asks for no client certificate.

   The check happens when a request is admitted: every plain-HTTP exchange and
   every download, and a WebSocket session once, at its upgrade. An open
   WebSocket session is not ended when its token expires; the Client meets the
   expiry at its next connection. It is ended when its token is replaced: the
   Server closes every session admitted with the old token, with close code
   1008 (policy violation), since replacing the token is how a stolen one is
   cut off. The per-IP back-off on refused attempts applies to `/v1/enrol`,
   `/v1/token` and admission alike, and every decision is a log event
   ([ADR-0022](0022-security-decisions-are-structured-log-events.md)) that
   never carries a key, secret or token.
7. **On the host**, `enrol` takes the Server's base URL and the enrolment key,
   and nothing else: the space is stated in the key alone, so no command takes
   it a second time. `enrol` is refused on a host that holds a `state.json`. It
   registers, obtains a token, and writes `state.json` once in the Client's
   state directory, owner-only as the Client writes every secret: `endpoint`
   (the base URL, against which `/v1/enrol` and `/v1/token` are resolved),
   `space` (as the Server returned it), `device_id`, `client_secret` and
   `access_token`. For now the Client's OpAMP connection still dials the
   `endpoint` of `supervisor.toml`; deriving it from the base URL is later
   work.

   The Client sends the token on every OpAMP exchange, on both transports, and
   on every package download; a header offered with a package cannot replace
   it. Its own telemetry carries the token only when the destination has the
   Server's origin, so the token never reaches another collector. The `opamp`
   client reports a refused connection's `401` with its `WWW-Authenticate`
   header on both transports, an addition to its public interface. Only a
   `401` whose Bearer challenge contains `error="invalid_token"` makes the
   Client request a new token with its client credentials, rewrite
   `access_token` in `state.json` and retry. A bare `401`, `invalid_request` or
   `invalid_client` does not trigger token replacement. It keeps no expiry and
   never renews ahead of time, so an open WebSocket session is never cut by the
   Client's own renewal. Nothing else in the file changes after `enrol`.

   A host without `state.json` runs nothing. Installing the Client registers
   its service but neither starts it nor lets it start at boot; `enrol`, once
   `state.json` is written and handed to the account the service runs as,
   starts the service and lets it start at boot. The Client, as a service or
   in the foreground, refuses to start without a `state.json` and names
   `enrol`.

   `revoke` is local only and never contacts the Server. It refuses while the
   Client's service is running. It asks for
   confirmation (`--force` skips it), keeps the service from starting at boot
   again, and deletes the Client's whole state
   directory, `state.json` included: without its `state.json` a host is gone,
   and nothing else stored for it may outlive it. `--keep-cache` spares the
   `config/` and `packages/` directories. It is an exception taken out of the
   default deletion, not a list of its own, so whatever the default deletes in
   future is deleted under the flag too. Host state the configuration keeps
   outside the state directory goes as well: the Supervisors' directories,
   with their `instance_uid`s, under a configured Supervisors' root, and the
   Client's own log files in a configured log directory. Nothing else there is
   touched, neither other programs' files nor the installation. A new `enrol`
   creates a new device ID, and the host's Agents start with new
   `instance_uid`s.
8. **Two standalone crates.** `oauth-registration` (RFC 7591) and `oauth-token`
   (RFC 6749 client credentials) know nothing of Classis. Each has a `server`
   module, an axum handler over a storage trait the application implements,
   and a `client` module, the one request the host makes. Each implements only
   what Classis uses: no redirect URIs, no other grants, no scopes, no refresh
   tokens, no registration management (RFC 7592). Their clients ignore
   unrecognized response fields; the token client accepts the `token_type`
   value case-insensitively (RFC 6749 §5.1). Their request parsers bound the
   body at 8 KiB before they parse it, answer a larger one with a plain `413`,
   and have fuzz targets. The parsing of RFC 6750 credentials and challenges
   lives once, in `oauth-token`: `oauth-registration` reads its initial access
   token with it, and Classis admission uses it too.
9. **Removed, as if it never existed.** Client certificates, the client and
   bootstrap CAs, CSRs and the CSR flow in OpAMP connection settings, the
   renewal and bootstrap proofs, PKCS#12, the enrolment window and operator
   approval, the certificate register and revocation list with their routes,
   the Host records and `/api/v1/hosts`, the `fleet.host.*` subject values, the
   `pki` commands that make those CAs, their configuration sections, stores and
   tests, and **Gateway Mode** with its code. The `opamp` crate loses its
   client-certificate and CSR support: the client's TLS identity, the server's
   client-certificate verification and peer certificate, and the CSR in
   reports. That breaks its public interface, which the project accepts while
   it is in development. A TLS client certificate or private key that a
   connection-settings offer carries is ignored, and the rest of the offer
   applies. Nothing is migrated and no old file, key or section
   is still read. The PostgreSQL schema keeps no table for them: its first
   migration is rewritten in place, since no installation exists to upgrade.
   Package signing and its keys stay.

**Out of scope:** the specification change; the operator's commands for spaces
and keys (create, list, replace, delete) and the ready-to-paste install command;
an operator removing an enrolled host and the garbage collection of orphaned
clients and their Agents' records; `install.sh`, `install.ps1`, the download
routes for the Client, and the MSI's `ENDPOINT` and `TOKEN` properties; where
TLS terminates; deriving the OpAMP URL from the base URL in `state.json`; a
redesigned Gateway Mode; whether a host's space becomes an attribute Selectors
match; and whether the client secret and the access token carry a recognizable
prefix like the key.

## Alternatives considered

- **Keep mutual TLS** — the system as it stands. Three CAs, a CSR flow, renewal
  proofs and revocation lists to answer whether a host may connect; enrolment
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
- **Keep only a hash of the enrolment key** — it could verify an enrolling
  host, but could not return the existing key again. Rejected: the enrolment
  key must remain recoverable until the operator explicitly rotates it.
- **Slow, salted hashes (Argon2) for client secrets and access tokens** — what
  a password needs. These values are 256 random bits; RFC 6819 §5.1.4.1.3 asks
  for a salt only for low-entropy credentials, and a slow hash on every request
  would cost the Server for nothing. The enrolment key is stored recoverably,
  not hash-only, for the separate reason above.
- **Crockford base32 for the key's secret** — case-insensitive and free of
  punctuation, but no crate in the workspace writes it, and a hand-written
  codec is code to own. Base64url is already in the workspace and already
  fits a bearer token.
- **An existing OAuth library** — `oxide-auth` (server, last release 0.6.1 in
  June 2024) is built around browser flows we do not use; `oauth2` (client,
  5.0.0) pulls `reqwest` 0.12 beside the workspace's 0.13, `rand` 0.8, `chrono`
  and `thiserror` 1 for one request. Two small crates cost less than either.
- **One crate for both endpoints** — registration and token retrieval are
  separate standards a deployment may use apart; two crates keep each usable
  alone.
- **One client per Agent** — every Supervisor would register and hold its own
  token, multiplying enrolments per machine and changing what a host is.
- **A store of its own for which host owns an `instance_uid`** — what the
  certificate model kept beside its revocation list. The Agent's record
  already names its host; a second store would hold the same fact twice.
- **Keep the Agents' identities across `revoke`** — a re-enrolled host would
  bring its old `instance_uid`s under a new client, and the Server would have
  to decide whose they are. A host without `state.json` is gone; starting
  clean removes the question.
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
- **Send the token to every telemetry destination** — the destination is
  whatever the Server offers and may be a third-party collector; a token that
  never expires must not leave the Server's origin.
- **Refuse Gateway Mode at startup instead of removing it** — keeps code that
  cannot run and still depends on certificates. Rejected: the Gateway will be
  redesigned for tokens.

## Sources / Prior art

- Enrolment LLD: "LLD | Classis Enrollment", Confluence space N4, page
  6883115026, version 2 (2026-11-13), sections _Spaces_, _Enrolment key_,
  _Machine login phase_ option 2, _Wrong space_, _Server endpoints_ and
  _Where the host saves its space_.
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), OAuth 2.0 Dynamic
  Client Registration: §1.2 (initial access token), §2 (metadata defaults and
  ignoring unknown metadata), §§3 and 3.1 (bearer authentication and JSON
  requests), §3.2.1 (credentials, all registered metadata, response extensions
  and `201 Created`), §3.2.2 (JSON errors and `invalid_client_metadata`).
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), OAuth 2.0: §1.4 (a
  token is "usually opaque to the client"), §§2.3 and 2.3.1 (one authentication
  method and form-encoding the Basic credentials), §3.2 (empty, unknown and
  repeated parameters), §4.4 (client credentials, form requests and no refresh
  token), §5.1 (JSON responses, `expires_in`, both cache headers and ignoring
  unknown response fields), §5.2 (JSON errors and the Basic challenge).
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html), Bearer Token Usage:
  §§2 and 2.1 (one token-transmission method and header syntax), §§3 and 3.1
  (Bearer challenges, `invalid_request` and `invalid_token`), §5.3 (avoiding
  tokens in URLs).
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html), Base Encodings: §5
  (the URL- and filename-safe alphabet) and §3.2 (omitting padding).
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html), Universally Unique
  IDentifiers: §5.7 (UUID version 7).
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
- Positive: the Server can return a space's existing enrolment key after a
  restart without rotating it. Its client records keep only hashes of client
  secrets and access tokens, not usable copies of those credentials.
- Negative / trade-offs: the enrolment key is recoverable from the Server's
  persisted state, unlike client secrets and access tokens. A leak of that
  state or its backups can expose a reusable enrolment credential. Anyone
  holding it can enrol hosts until it is explicitly rotated; rotation does
  not invalidate hosts already enrolled. The key must be handled as a secret.
- Negative / trade-offs: a token that never expires is good until it is
  replaced; a stolen `state.json` lets its holder act as the host until a new
  token is issued. The host is the boundary, as it was for the certificate's
  private key.
- Negative / trade-offs: `revoke` without `--keep-cache` throws away the
  host's configuration and package caches, so a re-enrolled host downloads
  them again.
- Negative / trade-offs: the `opamp` crate's public interface breaks for
  anyone who used its client certificates or CSRs.
- Negative / trade-offs: hosts that only a Gateway can reach cannot join until
  Gateway Mode is designed again.
- Negative / trade-offs: Selectors lose the `fleet.host.*` subject values;
  Deployments aimed by them must use Labels or what Agents report.
- Follow-ups: the specification change for the strategy, G-15, G-17 and Q-1;
  the operator commands for spaces and keys; removing a host; where TLS
  terminates; the OpAMP URL derived from the base URL; the install scripts,
  download routes and MSI properties; Gateway Mode on tokens; whether a space
  is visible to Selectors.

## Enforcement

With the implementation, both OAuth crates gain unit tests for their server
and client modules. Each RFC-conformance case cites the RFC number and section
and takes its expected method, encoding, status, headers and response fields
from that section, not from the implementation under test. The two sides are
tested independently; a client/server round trip alone does not prove
conformance. The cases cover valid requests, malformed requests and the errors
listed below, distinguishing RFC requirements from the Classis profile's
choices. Integration tests and fuzzing supplement these unit tests rather than
replace them.

Tests that cite this ADR with `Verifies: ADR-0064`, written with the
implementation:

- Unit tests in `crates/oauth-registration/`: JSON requests and responses;
  an explicit `client_credentials` grant succeeds, omitted `grant_types` and
  unsupported grants fail with `400 invalid_client_metadata`; an omitted
  authentication method defaults to `client_secret_basic`, and unsupported
  methods fail; unknown metadata is ignored; all registered metadata is
  returned; responses containing credentials carry both cache headers; and the
  request body is bounded (clauses 2 and 8).
- Unit tests in `crates/oauth-token/`: UTF-8 form requests; Basic credentials
  containing characters that require form-encoding round-trip correctly;
  empty parameters count as omitted, unknown parameters are ignored and repeated
  parameters or multiple authentication methods fail with `400 invalid_request`;
  missing or incorrect Basic credentials receive `401 invalid_client` and
  `WWW-Authenticate: Basic realm="token"`; an unsupported `Authorization`
  scheme receives `401 invalid_client` with a challenge matching that scheme;
  a missing grant is `400 invalid_request`, another grant is
  `400 unsupported_grant_type`, and a non-empty scope is `400 invalid_scope`;
  JSON responses carry both cache headers when they contain credentials or
  tokens; a finite token has `expires_in` and a non-expiring one omits it; no
  refresh token is returned; and the request body is bounded (clauses 4 and 8).
  The token server's builder takes the lifetime as a required argument, so a
  missing lifetime does not compile.
- Both OAuth clients ignore unrecognized response fields; the token client
  accepts a differently cased `token_type: "bearer"` (clause 8).
- Unit tests of the key format: space names inside and outside the pattern of
  clause 1; a generated secret is 43 base64url characters; keys whose space
  contains `_` and whose secret contains `_` or `-` split into the right space
  and secret.
- Server store tests, for the filesystem and PostgreSQL adapters: a space's
  complete enrolment key is recoverable after reopening the store;
  reading it or enrolling a host leaves it unchanged; explicit rotation
  persists a different key that survives reopening, refuses enrolment with
  the old key and admits with the new one, without invalidating existing
  clients or their access tokens. Client secrets and access tokens are stored
  only as hashes, unlike the enrolment key (clauses 1, 2 and 4).
- `crates/classis-server/tests/enrolment.rs`, over the loopback in plaintext
  (clause 6): a valid key enrols, an unknown or replaced key does not; a new
  token makes the previous one invalid; an expired or replaced token is refused
  on `/v1/opamp` and the download route; an open WebSocket session outlives its
  token's expiry and is closed with 1008 when its token is replaced; a client's
  persisted record holds only hashes of its client secret and its one active
  access token; the Agent plane completes a handshake with no client
  certificate. An Agent's record names the client it reported under; a report
  with an `instance_uid` recorded under another client is refused, as is a
  client's 257th `instance_uid`; a host downloads only what its own Agents are
  offered. The registration, OpAMP and download routes send the Bearer
  challenges of clauses 2 and 6: `realm="fleet"` and no error for absent or
  unsupported authentication, `invalid_token` for an invalid credential, and
  `invalid_request` for a malformed request or multiple token-transmission
  methods. Scheme names are case-insensitive and credential values are not.
- `crates/opamp/` tests: a `401` refusal and its `WWW-Authenticate` header
  reach the caller on both transports (clause 7).
- `crates/classis-agent/tests/enrolment_e2e.rs`: `enrol` takes no space,
  writes `state.json` owner-only and refuses a second run; the Client sends the
  token on OpAMP and downloads, a package's offered header cannot replace it,
  and its own telemetry carries it only to the Server's origin; the Client
  requests a new token only after a `401` Bearer challenge with
  `invalid_token`, not after a bare `401`, `invalid_request` or
  `invalid_client`; `revoke` never contacts the Server and deletes the whole
  state directory, and with `--keep-cache` everything but `config/` and
  `packages/`, refuses while the service runs and leaves it unable to start
  at boot; the Client refuses to start without a `state.json`; installing
  starts nothing, and `enrol` starts the service.
- The fuzz targets of clause 8 run in `fuzz.yml`.

**Not mechanically decidable:** that nothing of the certificate model is left
(clause 9). A search of `crates/`, `config/`, `scripts/`, `packaging/` and
`docs/` for `client_ca`, `bootstrap`, `csr`, `pkcs12`, `revocation` and
`gateway` is the review step.
