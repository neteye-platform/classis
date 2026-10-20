# Glossary — OpAMP Fleet

> The **vocabulary** of this project: the terms everyone, humans and agents
> alike, uses in code, comments, documentation, and ADRs. It defines words and
> decides nothing. Whoever resolves a term adds it here in the same change
> ([ADR-0001](adr/0001-agent-governance-model.md)).

One term per concept, only terms specific to this domain. Say what a term _is_
in one or two sentences, and list under _Avoid:_ the synonyms it displaces,
where there are any. A term the specification, an ADR, or the code uses without
an entry here is a gap to close, not a convention to invent.

The core vocabulary — Agent, Host, Fleet, Selector, Label, Configuration,
Parameter, Package, Deployment and the rest — is defined in the specification's
[Core Concepts & Vocabulary](SPECIFICATION.md#core-concepts--vocabulary). The
terms below are the ones it uses without defining.

- **Agent type** — the kind of agent an Agent runs, as the `service.name` it
  reports; a Package is built for one, a Configuration is written for one.
  _Avoid:_ service type, product.
- **Client Agent** — the Agent a Client presents for itself, recognised by the
  `supervisor.kind.*` attributes it alone reports; its Labels hold for the
  Client's other Agents, the Supervisor Agents. _Avoid:_ own agent, main agent.
- **Effective description** — what a Selector is matched against: its Host's
  subject values as `fleet.host.*`, an Agent's reported attributes, its Labels,
  and its Client Agent's Labels. _Avoid:_ attributes (alone), metadata.
- **Entry** — one platform's artifact in a Package: operating system and
  architecture, content hash, size and signature. _Avoid:_ file, asset, build.
- **High-water mark** — the highest Package version a Client has installed for
  one Agent type; a Supervisor of that type refuses any offer below it. _Avoid:_
  floor, minimum version.
- **Blob** — the bytes of an Entry's artifact as the Server stores them, named
  by their SHA-256; identical bytes are one blob, whichever Entries name it.
  _Avoid:_ artifact file, binary.
- **Data directory** — the one directory, `data_dir`, under which the Server
  keeps all of its state, one subdirectory per domain. _Avoid:_ config
  directory, package directory, state directory (that is the Client's).
- **Bootstrap certificate** — the short-lived certificate a host presents to ask
  for enrolment; its subject values describe the Host it becomes. _Avoid:_ join
  token, enrolment token.
- **Enrolment** — the time-limited, operator-approved exchange in which a host
  holding a bootstrap certificate obtains its client certificate and becomes a
  Host. _Avoid:_ registration, onboarding, enrollment.
- **Enrolling peer** — a peer of a Gateway whose certificate chains to the
  bootstrap CA alone; the Gateway relays one plain-HTTP enrolment request of it
  and nothing else. _Avoid:_ bootstrap client, enrolling Agent.
- **Rollout** — the explicit act that releases a Deployment to Agents and pins
  what each receives. _Avoid:_ publish, push, deploy.
