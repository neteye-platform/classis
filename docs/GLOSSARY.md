# Glossary — Classis

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
- **Process account** — the account the operator names at a Client's
  registration for every program its Supervisors start; never root or
  `LocalSystem`, and never the Client's own account. On Linux and macOS its
  primary group, the _process account's group_, is its own: the Client's account
  is its one member, and no other account's primary group it is. What the Client
  shares with the Managed Processes belongs to that group, and nothing else
  does; on Windows the same share is made by grants to the account's SID.
  _Avoid:_ agent user, run-as account (that is the Client's), process group
  (that is a Unix process group, which a Managed Process may lead).
- **Second service** — the service `<PRODUCT_NAME>-agents`, registered beside
  the Client where a process account is named, which runs under that account and
  starts, signals and stops those programs on the Client's request, over a
  channel only the Client's account may use. _Avoid:_ helper, launcher, sidecar.
- **Install lock** — on Windows, the mutex `<PRODUCT_NAME>-install\lock` in a
  private namespace only elevated Administrators and `LocalSystem` can create,
  held for the whole of a `service install`, `uninstall`, `start` or `stop` so
  that one runs at a time. _Avoid:_ install mutex, global mutex.
- **Withdrawal** — what an install takes from a former account, a process
  account dropped or replaced or a Client's account replaced: on Linux and macOS
  by giving what it owns, and what is in its group, to the Client; on Windows by
  removing every entry that allows it anything and giving what it owns to the
  Administrators. _Avoid:_ revocation (that is a certificate's), cleanup.
- **Record of what an install left to finish** (_the record_) — on Windows, the
  value `Pending` of `HKLM\SOFTWARE\<PRODUCT_NAME>\WithdrawalPending`: what an
  install left to finish, the former accounts with the roots to withdraw them
  from and the services to start again. _Avoid:_ pending file, state file.
- **Tombstone** — the name, `.purge-<name>-<nonce>`, beneath the Supervisors'
  root that a removed Supervisor's directory is moved to before its purge
  deletes it, a name no Supervisor can carry; one the purge could not delete is
  removed again at the next start and with the next purge. _Avoid:_ trash
  directory, purge directory.
