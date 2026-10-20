# ADR-0036: A bootstrap certificate's subject may name country, state, locality, organization, organizational unit and organization identifier, and the Server carries it into the host certificate it issues

- **Status:** 🟢 accepted · clause 3 superseded by [ADR-0039](0039-through-a-gateway-a-csr-proves-the-certificate-it-rests-on.md)
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** the bootstrap-certificate routes and the subject they take in `crates/fleet-server/src/api.rs` and `crates/fleet-server/src/bootstrap.rs`, the signing of host certificates in `crates/fleet-server/src/ca.rs` and the approval and renewal paths in `crates/fleet-server/src/fleet.rs`, the enrolment queue's view in `crates/fleet-server/src/enrolment.rs` and `crates/fleet-server/src/api.rs`, the Enrolments tab of the bundled UI in `crates/fleet-server/static/index.html`, and every document that shows a certificate's subject or tells an operator how to issue a bootstrap certificate
- **Supersedes:** [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clauses 7 and 22; [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clauses 22 and 29; [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md) clauses 3 and 5

## Context

An operator issues a bootstrap certificate per customer and site. The subject's O and OU name them
([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md) clause 22). The values
help the approver to see which customer a request belongs to, and are then lost:

- The host certificate issued on approval carries the common name alone
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clause 7). ADR-0028 clause 22 says that "no host certificate inherits it".
- ADR-0028 left the step open. Clause 29 keeps the host certificate's subject "free for what a
  later decision may carry over from the bootstrap certificate", and its Out of scope names
  "carrying the bootstrap certificate's subject … into the host certificate".

The specification draft this ADR follows describes a Host by the subject values "carried over from
the bootstrap certificate it enrolled with": country, state, locality, organization, organizational
unit, organization identifier. The decision that makes the Host an entity puts these values into the
effective description as `fleet.host.*`. A Selector can therefore target a customer or a site by
values the Server issued and no Agent can forge.

ADR-0028 rejected "Country, state and locality as well", because an audit of a private fleet does
not ask where an organization sits. Once the values place a Host, that reason no longer holds. The
human wanted them optional. The human also wanted the customer or contract number, for example a
UUID, in `organizationIdentifier` (X.520, 2.5.4.97).

The human and the author agreed on one rule: **the certificate carries what is stable and assigns
responsibility, and anything that changes belongs elsewhere.** Asset numbers, contacts and notes
are not subject values. The Host record has no editable fields; Labels select.

A bootstrap certificate is handed to many hosts, and it may come from a foreign PKI when the
Server holds no `bootstrap_ca_key_file`. So the Server cannot assume that what it reads from one
is well-formed. The CSR's subject is chosen by the host itself and is never trusted.

The decision serves G-17 (the Agent is identified) and Q-1. The values describe and select; they
authorize nothing, and the specification's Non-Goal "Authorization and multi-tenancy" stands.

## Decision

We will let a bootstrap certificate's subject carry up to six optional attributes, validate them
when it is issued and again when an enrolment is approved, and copy exactly those values into
every host certificate the Server issues from it and into every renewal after it.

1. **Restates ADR-0028 clause 22. The operator names six attributes, organization and
   organizational unit required and the others optional, and the Server the rest.** `subject`
   takes:
   - `country` (C): exactly two upper-case letters, ISO 3166-1 alpha-2, encoded as
     `PrintableString`;
   - `state` (ST), `locality` (L), `organization` (O), `organizational_unit` (OU) and
     `organization_identifier` (2.5.4.97): each 1 to 64 characters of UTF-8 without control
     characters, encoded as `UTF8String`, in no format of the Server's choosing. A UUID is one such
     value.

   `organization` and `organizational_unit` are required: a request without either is answered
   `400`, naming it, so every Host has a customer and a site its Selectors can rely on. The other
   four are optional. Each may appear at most once. A key outside this set is answered `400`. The Server sets the
   common name (ADR-0028 clause 28), and the operator never does. The order in the subject is C, ST, L, O,
   OU, organizationIdentifier, CN. The values describe and select through the effective
   description; they authorize nothing.

2. **Restates ADR-0021 clause 7. A certificate proves membership and its host, and carries its
   bootstrap certificate's subject values.**
   - The Server does not require the subject to match `instance_uid`, `service.instance.name`, or
     anything else an Agent reports.
   - The request dictates neither the certificate's subject nor its powers. The Server sets the
     subject to:
     - the six attributes of clause 1, copied from the certificate named in clause 3 or clause 4;
     - the common name ADR-0028 clause 28 derives.
   - The Server signs a client-authentication leaf only — `CA:FALSE`, `digitalSignature`,
     `clientAuth`. It drops every requested SAN and puts in one of its own, the URI
     `urn:opamp-fleet:host:<id>`.
   - The CSR's subject is still searched for claims (ADR-0021 clause 29) and is never copied.
   - The host is minted when an operator approves an enrolment and carried on by every renewal
     (ADR-0021 clause 27). A certificate an operator provisioned without one is given a host derived from
     its issuer and serial when it is first renewed.
   - An `instance_uid` is spoken for by the host whose certificate first reported it:
     - A connection that presents another host's certificate and reports for it is re-keyed
       through `AgentIdentification` to an identity of its own.
     - A CSR in that message may not claim the old one.
     - A re-key an Agent asks for keeps its host.
   - A host holds at most three valid certificates at a time and speaks for at most 256
     `instance_uid`s.
   - A Gateway carries other hosts' Agents, so an operator marks it as one —
     `PUT /api/v1/hosts/{host}/gateway` — and its certificate then speaks for any Agent. Behind it,
     membership alone applies. `GET /api/v1/hosts` lists each host, whether it is a Gateway, what
     it speaks for and how many valid certificates it holds.

3. **An approval copies the subject from the bootstrap certificate the enrolment connection
   presented, and validates it again.**
   - The Server reads the six attributes from the bootstrap certificate verified in the handshake
     of the connection that carried the request. That certificate may come from a foreign PKI, so
     the Server applies clause 1's rules again.
   - An attribute that appears twice, has the wrong encoding or length, or is a `country` that is
     not two upper-case letters, and a missing `organization` or `organizational_unit`, make the
     approval fail (`409`) with a message naming the attribute. Nothing is signed, and the request stays waiting until the operator rejects it.
   - The right encoding is `PrintableString` for `country`. For the other five it is `UTF8String`
     or `PrintableString`, which older PKIs write and which is a subset of it; the host certificate
     carries them as `UTF8String`.
   - A `country` is checked by its shape, two upper-case letters, not against the ISO 3166-1 list.
     The Enrolments tab offers the list.
   - Other attributes of the bootstrap certificate are not copied. Its common name is never
     copied, because the host certificate's is ADR-0028 clause 28's.

4. **A renewal carries the predecessor's values unchanged.** A renewal (ADR-0021 clause 27) copies
   the six attributes from the certificate it renews, and only from it, without applying clause 1's
   rules again: a host whose certificate was provisioned before them still renews. A value its
   encoding cannot hold fails the renewal. The Server checks that the new certificate carries
   exactly those values. A Host's subject values change only through a new
   enrolment.

5. **Restates ADR-0021 clause 22. Pending requests are listed and decided through the REST API,
   by the values that will be carried.**
   - `GET /api/v1/enrolments` lists each pending request with:
     - its id, its arrival time and the peer address;
     - the SHA-256 fingerprint of its public key;
     - the bootstrap certificate's fingerprint and serial (`bootstrap_serial`), in the lowercase hex
       without leading zeros that `GET /api/v1/bootstrap-certificates` lists;
     - the six subject values an approval would carry, read under clause 3's rules, or, where
       those rules refuse them, `subject_refusal`: the reason, naming the attribute. The operator
       sees before pressing Approve what it will carry or why it will be refused.
   - The CSR's subject is not listed, because it is neither trusted nor carried.
   - The Server derives both serials with one function, so a request carrying a certificate it
     issued names that entry.
   - `POST /api/v1/enrolments/{id}/approve` and `POST /api/v1/enrolments/{id}/reject` decide one
     request; an unknown or expired id is answered `404`. Both are body-less `POST` acts under
     ADR-0021 clause 16.
   - The Client logs its request's public-key fingerprint, so an operator can match a pending
     request to a host.
   - Renewal by an Agent that holds a certificate from the client CA stays automatic (ADR-0021 clause 9)
     and never enters the queue.

6. **Restates ADR-0029 clause 5. The Enrolments tab issues, lists, revokes and deletes
   bootstrap certificates.**
   - The tab issues one through the route of clause 8, with clause 1's six fields, the validity and
     the password the operator types; organization, organizational unit and the password are
     required. The country is chosen from a list of ISO 3166-1 codes.
   - The password is typed twice, and the tab sends nothing while the two differ.
   - The page never holds a private key: every certificate it issues is kept by the Server as a
     PKCS#12 file.
   - The row of each certificate whose entry says `p12` offers **Save bootstrap.p12**, in any page
     and at any time, through the route of ADR-0029 clause 4. A certificate issued elsewhere
     offers nothing to save.
   - The tab lists the certificates of `GET /api/v1/bootstrap-certificates`, each with its subject
     values. A valid one has a press that revokes it by its serial with the authority `bootstrap`.
     A revoked one has a **Delete** press that asks first and then deletes its entry through the
     route of ADR-0029 clause 15.
   - Each pending request shows the subject values, serial and end of the entry its
     `bootstrap_serial` names (clause 5), and says so when no entry matches.
   - The tab uses no route the REST API does not offer.

7. **Restates ADR-0028 clause 29. A bootstrap certificate's subject is the operator's choice per
   issue, and the host certificate carries it.** The common name of a bootstrap certificate is
   ADR-0028 clause 28's. Its other attributes are what the issuing request names (clause 1), not the
   bootstrap CA's; the organization behind the CA is read from its issuer. A host certificate
   carries the bootstrap certificate's values (clauses 3 and 4) and its own common name under ADR-0028 clause 28.

8. **Restates ADR-0029 clause 3. The Server issues a bootstrap certificate on request, always as
   a PKCS#12 file.** `POST /api/v1/bootstrap-certificates` with a JSON body
   `{"subject": {…}, "validity_days": n, "password": "…"}` (`Content-Type: application/json`, as
   `POST /api/v1/revocations`), `password` required — a request without it is answered `400`,
   naming it — makes a fresh ECDSA P-256 key and signs a certificate with the bootstrap CA's key.
   The certificate is `CA:FALSE`, `digitalSignature`, `clientAuth`, with a 16-byte random serial
   (ADR-0021 clause 32) and no subject alternative name. The Server makes the PKCS#12 file of
   ADR-0029 clause 1, writes it as that ADR's clause 4 says, and answers `201` with `serial`,
   `subject`, `not_before`, `not_after` and `certificate_pem`, and no `private_key_pem`. The key
   exists in plaintext only in the Server's memory while it issues; it leaves the Server only
   inside that file. A host that needs the pair as PEM takes it out of the file with
   `opamp-fleetctl pki p12-extract`
   ([ADR-0031](0031-opamp-fleetctl-extracts-a-bootstrap-pkcs12-file-into-pem.md)).

**Out of scope:** attributes beyond the six; per-host values (an asset number, a hostname), which a
bootstrap certificate shared by many hosts cannot carry; changing a Host's values without a new
enrolment; authorization by subject values; the ETSI EN 319 412-1 semantics of
`organizationIdentifier` (`VATAT-…`), which a private fleet PKI does not need.

## Alternatives considered

- **Organization and organizational unit optional, as ADR-0028 had them.** It lets a bootstrap
  certificate name no customer. Then `fleet.host.organization` and `fleet.host.site` are missing
  on some Hosts, and a Selector on them silently skips those. The human made both required.
- **Issuing without a password, the pair handed to the page as PEM (ADR-0029 clause 3).** It
  needs no password to be passed on. But the private key then travels unencrypted in an HTTP
  answer and sits in the page's memory; with the password required it never leaves the Server
  unencrypted, and `opamp-fleetctl pki p12-extract` gives a host the PEM it may need.
- **Keep O and OU only (ADR-0028 as it stands).** It is enough for customer and site, but the human
  wanted the location and a customer number optional beside them.
- **Free key-value pairs as SAN URIs (`urn:opamp-fleet:attr:<key>=<value>`).** They extend without
  bound and map one-to-one onto labels. But they are not standard, other tools do not show them as
  a subject, and they invite per-host values into a certificate shared by many hosts.
- **A private extension under an enterprise OID.** It can carry anything, but needs a Private
  Enterprise Number, and nothing outside this project reads it.
- **`serialNumber` (2.5.4.5), `street`, `postalCode`, `title`, `description`, personal names or an
  e-mail address.** Each is either per host, unstable, free text, or personal data that would land
  in every certificate and audit line.
- **Copy the values from the CSR.** The host chooses them, so a host could name any customer.
- **Store the values on the Host only, not in the certificate.** This is simpler to issue. But the
  certificate would no longer say whom it belongs to, and a Host record rebuilt from the register
  would lose them.
- **Skip the check at approval and trust the bootstrap CA.** A foreign bootstrap CA may write
  anything. A refusal that names the attribute costs one re-issue.

## Sources / Prior art

- ITU-T X.520 / RFC 5280: the attribute types C, ST, L, O, OU and organizationIdentifier
  (2.5.4.97); `countryName` as a two-letter `PrintableString`.
- ETSI EN 319 412-1, section 5.1.4: the structured semantics of `organizationIdentifier` for eIDAS
  certificates, which this decision does not adopt.
- ISO 3166-1 alpha-2 for the country codes.
- ADR-0021 clauses 7, 22 and 27, its consequence "A Gateway hides its downstream certificates",
  ADR-0028 clauses 22, 28 and 29 with its alternatives, and ADR-0029 clauses 3, 4, 5 and 15.
- `crates/fleet-server/src/ca.rs` (the host certificate's subject is set, the CSR's discarded)
  and `crates/fleet-server/src/bootstrap.rs` (`Subject` with O and OU). Read in the source.
- The working note of 2026-10-17 on the Server's data model, in which the human chose each point.

## Consequences

- Positive: a host certificate says whom it belongs to, and the Host's subject values come from a
  certificate the Server signed. A Selector on them cannot be forged by an Agent.
- Positive: the enrolment queue shows the values that will be carried, not a name the host chose.
- Negative / trade-offs: a value fixed at issue stays until the host enrols again. A customer
  renamed means a re-enrolment of its hosts, or Deployments keyed on `organization_identifier`
  instead of the name.
- Negative / trade-offs: a bootstrap certificate from a foreign PKI with a malformed subject can no
  longer be approved. The operator issues one that fits.
- Negative / trade-offs: certificates issued before this decision carry no values. Their Hosts have
  none until they enrol again.
- Follow-ups:
  - How the Host record and the effective description use the values is the Host decision. A
    migration that reads today's register leaves existing Hosts without values.

## Enforcement

Tests that will carry `Verifies: ADR-0036`:

- Issuing without `organization`, without `organizational_unit` or without `password` is `400`,
  naming the field; the answer to an issue never carries `private_key_pem`.
- A foreign bootstrap certificate without OU is refused at approval with `409` naming
  `organizational_unit`.
- Issuing with all six attributes yields a bootstrap certificate whose subject holds them in the
  order of clause 1, with `country` as a `PrintableString`. A lower-case or three-letter country,
  an empty or 65-character value, a control character and an unknown key are each `400`.
- Approving a request copies the bootstrap certificate's values into the host certificate and
  ignores the CSR's subject.
- A bootstrap certificate from another CA with OU twice is refused at approval with `409` naming
  the attribute, and nothing is signed.
- A renewal carries the predecessor's values unchanged.
- `GET /api/v1/enrolments` lists the bootstrap certificate's subject values and no CSR subject.
