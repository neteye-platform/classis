# Glossary — Classis

> The **vocabulary** of this project: the terms everyone, humans and agents
> alike, uses in code, comments, and documentation. It defines words and decides
> nothing. Whoever resolves a term adds it here in the same change.

One term per concept, only terms specific to this domain. Say what a term _is_
in one or two sentences, and list under _Avoid:_ the synonyms it displaces,
where there are any. A term the specification or the code uses without an entry
here is a gap to close, not a convention to invent.

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
- **Effective description** — what a Selector is matched against: an Agent's
  reported attributes, its Labels and its Client Agent's Labels, without
  certificate-derived `fleet.host.*` subject values. _Avoid:_ attributes
  (alone), metadata.
- **Entry** — one platform's artifact in a Package: operating system and
  architecture, content hash, size and signature. _Avoid:_ file, asset, build.
- **High-water mark** — the highest Package version a Client has installed for
  one Agent type; a Supervisor of that type refuses any offer below it. _Avoid:_
  floor, minimum version.
- **Package Root** — the self-signed certificate compiled into the Client and
  the Server that every package signature is verified up to; its key is kept
  offline by its custodian and issues Package Signers only. _Avoid:_ root key,
  signing CA.
- **Package Signer** — a certificate a Package Root issued to an Ed25519 key
  that signs Entries; a signature carries it, so replacing it changes no
  installation. _Avoid:_ signing key, release key.
- **Blob** — the bytes of an Entry's artifact as the Server stores them, named
  by their SHA-256; identical bytes are one blob, whichever Entries name it.
  _Avoid:_ artifact file, binary.
- **Data directory** — the one directory, `data_dir`, under which the Server
  keeps all of its state, one subdirectory per domain. _Avoid:_ config
  directory, package directory, state directory (that is the Client's).
- **Operator's socket** — the Server's local Unix socket through which
  `classis-cli` administers Spaces and their enrolment keys.
- **Public URL** — the Server's optional `public_url`: the base URL hosts reach
  it at through its proxy, which `classis-cli enrol-command` prints its install
  command against and an operator types into `classis enrol`. Absent, that command
  refuses; the Server never guesses the address its proxy answers for. _Avoid:_
  advertised URL, endpoint (the Client's own `supervisor.toml` key).
- **Install script** — one of the two files (`install.sh`, `install.ps1`) the
  Server serves on the Agent plane for a host that holds no credential to fetch
  and run, installing the Client and enrolling it in one step — the same
  install a native package does, not a second one. _Avoid:_ bootstrap script,
  installer (that is the `.deb`, `.rpm` or `.msi`).
- **Space** — a named grouping of Hosts on one Server, into which an enrolment
  key admits new Hosts. A Space is not a separate Fleet or a tenant-isolation
  boundary. _Avoid:_ tenant, fleet (for a Space).
- **Enrolment key** — the one reusable initial registration key current to a
  Space. Replacing it invalidates the old key for new registrations while
  enrolled Hosts keep their client credentials and tokens. _Avoid:_ bootstrap
  certificate, access token (for the enrolment key).
- **Enrolment** — the exchange in which a host uses its Space's enrolment key
  to register as an OAuth client and obtain client credentials and an access
  token, without individual operator approval. _Avoid:_ enrollment, onboarding.
- **`client_id`** — the OAuth identifier assigned at enrolment, identifying one
  Host rather than one Agent. _Avoid:_ instance UID (for a Host's identity).
- **Client credentials** — the Host's `client_id` and `client_secret` pair, used
  to obtain or replace an access token without changing the Host's identity.
  _Avoid:_ enrolment key, access token (for the pair).
- **Access token** — the opaque bearer credential with which a Host's Agents
  authenticate to the Server's Agent plane. It is distinct from the enrolment
  key and client secret. _Avoid:_ enrolment key, client secret (for the token).
- **State file** (`state.json`) — the file in the Client's state directory that
  `enrol` creates and token replacement updates: the Server's base URL, the
  Space, the `client_id`, the client secret and the access token. A Host without
  it is not enrolled and runs nothing. _Avoid:_ config, credentials file.
- **Reset** — the Client's local action that removes the Host's local identity
  and state. It does not contact the Server, whose credentials for the Host
  remain valid; a subsequent enrolment makes a new Host. _Avoid:_ Revoke,
  unenrol, deregister (nothing is removed at the Server).
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
  Administrators. _Avoid:_ revocation (that concerns fleet credentials), cleanup.
- **Record of what an install left to finish** (_the record_) — on Windows, the
  value `Pending` of `HKLM\SOFTWARE\<PRODUCT_NAME>\WithdrawalPending`: what an
  install left to finish, the former accounts with the roots to withdraw them
  from and the services to start again. _Avoid:_ pending file, state file.
- **Tombstone** — the name, `.purge-<name>-<nonce>`, beneath the Supervisors'
  root that a removed Supervisor's directory is moved to before its purge
  deletes it, a name no Supervisor can carry; one the purge could not delete is
  removed again at the next start and with the next purge. _Avoid:_ trash
  directory, purge directory.
