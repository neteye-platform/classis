# ADR-0035: A Host is what a client certificate names, the Server keeps it with its Agents and shows it, and an Agent's effective description takes the Host's subject values and its Client Agent's labels

- **Status:** 🟢 accepted · clause 1 superseded by [ADR-0047](0047-a-host-and-its-bindings-end-with-its-last-valid-certificate.md)
- **Date:** 2026-10-17
- **Deciders:** Markus Brigl
- **Applies to:** the host register in `crates/fleet-server/src/revocation.rs` and its filesystem adapter, the host an Agent record names and the effective description in `crates/fleet-server/src/fleet.rs` and `crates/fleet-server/src/labels.rs`, the persisted Agent record in `crates/fleet-server/src/agent_store.rs` and `crates/fleet-server/src/fs/agents.rs`, the label store in `crates/fleet-server/src/fs/labels.rs`, the `/api/v1/hosts` and `/api/v1/agents/{instance_uid}/labels` routes of `crates/fleet-server/src/api.rs`, the Hosts and Agents tabs of the bundled UI in `crates/fleet-server/static/index.html`, and every document that tells an operator what a host is or how labels and Selectors work
- **Supersedes:** [ADR-0024](0024-the-fleet-record.md) clauses 17, 18, 19 and 20; [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md) clause 37

## Context

The Server already knows hosts, but it shows them nowhere and records them only as far as
admission needs:

- A host is minted when an operator approves an enrolment. Its id goes into the client certificate
  as the SAN URI `urn:opamp-fleet:host:<id>`, and every renewal carries it on
  ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)
  clauses 7 and 27).
- The host register (`revocation/hosts.json`) binds a host to the `instance_uid`s it first
  reported for and holds its Gateway mark. A host's entry is written only at its first report.
- The Agent record has no link to its host, and the bundled UI has no view of hosts. Hosts,
  certificates and revocations are reachable through the REST API only.
- Forgetting an Agent leaves its labels (ADR-0024 clause 19) and its binding in place.

Labels live in a store of their own, keyed by `instance_uid`, so that they outlive a forget
(ADR-0024 clauses 19 and 20). This separation caused a defect fixed on the 0.5.5 line: the labels
of an Agent re-keyed on its own request stayed under the old identity. They also cannot be
cleared through the API once their Agent is forgotten, because the label route needs a known
Agent.

The specification draft this ADR follows names the **Host**: what a client certificate the Server
issued identifies, one Client installation that connects directly, a Gateway included. Every Agent
reaching the Server over that certificate belongs to it. The Agents behind a Gateway belong to the
Gateway's Host, because the Server sees only the Gateway's certificate (ADR-0021: "A Gateway hides
its downstream certificates"). The draft makes the Host's subject values part of the effective
description that Selectors match.

The human worked the model out with the author, rejecting each more elaborate variant:

- **A host proof in the description**, a signature by the downstream host's key, was rejected
  because the Gateway only forwards traffic.
- **Gateway-set attributes** were rejected for the same reason, and because a Gateway must stay
  efficient.
- **Virtual hosts derived from `host.id` behind a Gateway** were rejected as well. An approximate
  topology is enough; the exact topology behind a Gateway is out of the project's scope.
- **What replaces them is label inheritance.** The labels set on a host's Client Agent hold for
  all its Agents, so a Gateway's downstream hosts are placed by labelling their Client Agent once.

The decision serves G-2 (the Server knows the fleet's state), G-9 (targeting a subset) and G-17
(the Agent is identified), and Q-1. Reported attributes are self-asserted, so they must never
override what a certificate says.

## Decision

We will keep a Host for every client certificate's host id, name in each Agent record the Host it
arrived over, show Hosts with their Agents in the bundled UI, and build each Agent's effective
description from the Host's subject values, the Agent's report, its own labels and the labels of
its Client's own Agent, in that order of precedence.

1. **A Host is created when its enrolment is approved, and ends when nothing holds it.**
   - The approval that mints a host id writes the Host. Its record holds:
     - the subject values of the client certificate it was issued: country, state, locality,
       organization, organizational unit, organization identifier. Which of them a certificate
       carries is the decision on carrying the bootstrap certificate's subject over; without it,
       none.
     - its Gateway mark;
     - the `instance_uid`s bound to it;
     - the time of the approval.
   - A certificate an operator provisioned with a host id makes a Host at its first report.
   - A Host the approval could not write is written with the next write of the host register, and
     at the latest at its first report, from the values its certificate carries. The approval is
     not refused for it: the certificate is signed and registered by then, and the values are in
     the certificate.
   - A Host is removed when it has no valid certificate, no bound Agent and no Gateway mark, as
     today.

2. **Restates ADR-0026 clause 37. What a certificate speaks for, and which Host an Agent
   belongs to.**
   - A Host speaks for the `instance_uid`s bound to it.
   - A Host marked as a Gateway speaks for any Agent, and the register binds no `instance_uid` to
     it. A certificate that names no host speaks for no Agent and fetches nothing.
   - In addition, each Agent record names the Host it last arrived over: its own Host on a direct
     connection, the Gateway's Host behind a Gateway. This is for the fleet view and for clause 4,
     and it grants nothing. A Server without `[client_ca]` has no Hosts, and its Agent records name
     none.
   - Everything else ADR-0026 clause 37 says stays as it is: the notice at startup without
     `[client_ca]`, and a request without a certificate existing only behind `Admission::open`.

3. **Restates ADR-0024 clause 17. Selectors match an effective description, the same for every
   Selector.** For each key the description takes the first source that has it:
   1. `fleet.host.country`, `fleet.host.state`, `fleet.host.locality`, `fleet.host.organization`,
      `fleet.host.site` (the organizational unit) and `fleet.host.organization_id`, from the
      subject values of the Host the Agent arrived over directly. An Agent behind a Gateway has no
      `fleet.host.*`: its own certificate is not seen.
   2. What the Agent reported: identifying attributes, then non-identifying ones.
   3. The Agent's own labels.
   4. The labels of its Client Agent (clause 4).

4. **An Agent inherits the labels of its Client Agent.**
   - The Client Agent is the Agent a Client presents for itself, recognised by the
     `supervisor.kind.*` attributes it alone reports
     ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
     clause 18).
   - Its labels hold for the other Agents of the same Client:
     - on a direct connection, the Agents bound to the same Host;
     - behind a Gateway, the Agents arriving over the same Gateway Host that report the same
       `host.id`. An Agent that reports no `host.id` is grouped by its `host.name`, apart from the
       groups keyed by `host.id`.
   - Where that grouping finds more than one Client Agent, nothing is inherited, and the fleet view
     marks the Agents as ambiguous.
   - The grouping behind a Gateway rests on what Agents report. It places Agents for convenience
     inside the trust the Gateway already has, and it never decides admission.

5. **Restates ADR-0024 clause 18. `fleet.*` is reserved, and a label never overrides a reported
   attribute or a Host value.**
   - A label whose key starts with `fleet.` is refused (`400`).
   - A label whose key the Agent reports is refused (`409`) as before. If an Agent starts
     reporting a key it was labelled with before, the reported value wins, and the label is listed
     in `shadowed_labels`.
   - A reported attribute whose key starts with `fleet.` is left out of the effective description
     and listed in `ignored_attributes` on the fleet row. An Agent therefore cannot claim another
     Host's subject values.

6. **Restates ADR-0024 clauses 19 and 20. Labels are part of the Agent's record and go with it.**
   - Labels are stored in the Agent's persisted record. There is no separate label store.
   - They follow a re-key as the record does (ADR-0024 clause 15), and forgetting an Agent removes
     them.
   - They never travel to the Agent: no capability, no message and nothing the Client reports
     carries them.

7. **The Hosts tab.** The bundled UI gains a tab that lists the Hosts:
   - Each row shows the Host's display name, its subject values, whether it is a Gateway, its
     valid certificates and their ends, and the number of its Agents.
   - The display name is the `host.name` its Client Agent reports when the Host has exactly one
     Client Agent, else the host id. A Gateway always shows its host id: its own Client Agent
     arrives over the same Host as the Client Agents behind it. The name is shown only and decides
     nothing.
   - The current Host's detail shows its Agents, grouped by their Client Agent with that Client's
     Supervisor Agents beneath it. For a Gateway this covers the Agents behind it, grouped as
     clause 4 groups them. The grouping is presentation only.
   - The Gateway mark and a revocation of the Host's certificates are acts on the row. Labels
     stay on the Agents tab, where the Client Agent's labels are marked as inherited by the others.
   - `GET /api/v1/hosts` adds the subject values and the Agents to what it lists today.

**Out of scope:** the exact topology behind a Gateway; a Host for a machine the Server sees no
certificate of; labels or editable fields on a Host itself; which subject values a certificate
carries (the decision on carrying the bootstrap certificate's subject over); where Hosts and Agent
records are stored (the storage decision).

## Alternatives considered

- **Hosts from the Agents' `host.*` attributes.** These work behind a Gateway and without
  certificates. But they are self-asserted, cloned machines share `host.id`, and they cannot carry
  values a Selector may trust.
- **A host proof: the Client adds its certificate and a signature over its `instance_uid` to each
  Agent's description**, after the renewal proof of ADR-0021 clause 27. It would identify hosts
  behind a Gateway with a Server-verifiable proof. The human rejected it as more than needed.
- **The Gateway adds the downstream host's id to what it forwards.** This gives an exact, verified
  topology. But the Gateway would process instead of forward, which costs efficiency and ADR-0015's
  simplicity. Rejected by the human.
- **Virtual hosts behind a Gateway, keyed by Gateway and `host.id`.** They would give an
  approximate host list. Label inheritance covers the need without a second kind of Host, so the
  human dropped them.
- **`fleet.gateway.*`: the Gateway's subject values on the Agents behind it.** These would be
  verified, but they describe the path, not the host. Rejected by the human.
- **Reported attributes win over Host values, as they win over labels.** This would let any Agent
  report `fleet.host.organization` and be selected by another customer's Deployment.
- **Labels outlive a forget (the status quo).** A forgotten host comes back in its channel. But
  this needs a second store, which caused the re-key defect and leaves labels that cannot be
  cleared. Inheritance from the Client Agent now covers most placements.

## Sources / Prior art

- ADR-0021 clauses 7, 13, 25 and 27, and its consequence "A Gateway hides its downstream
  certificates".
- ADR-0024 clauses 15–21.
- ADR-0026 clause 37.
- ADR-0017 clause 18 (`supervisor.kind.*`).
- ADR-0016: `host.name`, `host.id`, `host.ip` and `host.mac` are reported attributes.
- `crates/fleet-server/src/revocation.rs` `check_report` (the host entry is written at the first
  report) and `crates/fleet-server/src/fleet.rs` (the host minted at approval). Read in the
  source.
- The working note of 2026-10-17 on the Server's data model, in which the human chose each point.

## Consequences

- Positive: an operator sees which Agents run on which Host and behind which Gateway, and acts on
  certificates and Gateway marks where the Host is shown.
- Positive: a Selector can target a customer or site by values the Server issued, which no Agent
  can forge.
- Positive: labelling a Client Agent once places all its Supervisors, and labels have one store.
- Negative / trade-offs: forgetting an Agent drops its labels. A host that comes back starts
  unlabelled unless its Client Agent is labelled.
- Negative / trade-offs: Agents behind a Gateway carry no `fleet.host.*`. A Deployment reaches
  them by labels on their Client Agents.
- Negative / trade-offs: the grouping behind a Gateway is approximate. Two Clients on one machine
  behind one Gateway are shown as ambiguous and inherit nothing.
- Follow-ups:
  - Which subject values a certificate carries, in the decision on carrying the bootstrap
    certificate's subject over.
  - Where Hosts, Agent records and their labels are stored, and how today's label files move, in
    the storage decision.

## Enforcement

Tests that will carry `Verifies: ADR-0035`:

- Approving an enrolment writes a Host before the first report.
- An Agent on a direct connection matches a Selector on `fleet.host.organization`. An Agent
  reporting `fleet.host.organization` itself does not, and the attribute is listed as ignored.
- A label `fleet.x` is `400`.
- A Supervisor Agent matches a Selector on a label set only on its Client Agent. Its own label of
  the same key wins.
- Behind a Gateway, Agents sharing a `host.id` inherit their Client Agent's labels, and two Client
  Agents with one `host.id` inherit nothing and are marked ambiguous.
- Forgetting an Agent removes its labels. A re-keyed Agent keeps them.
- `GET /api/v1/hosts` lists a Host's subject values and its Agents, and an Agent behind a Gateway
  under the Gateway's Host.
