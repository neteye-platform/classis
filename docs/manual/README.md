# OpAMP Fleet — User Manual

This manual is for the people who **run** OpAMP Fleet: it says what each end can do, how to start
it, and what every configuration key means. It is split the way a deployment is split — the Server
is one machine, the Clients are all the others — so each half can be read on its own:

| Part | Read it to |
|---|---|
| **[Setting up a fleet](setup.md)** | go from nothing to a running fleet, in order: the three certificate authorities and the files they make, the Server's and the Client's configuration, enrolling a host, and living with the certificates afterwards |
| **[A host's life](lifecycle.md)** | follow one managed host from start to finish, in the UI: issuing its bootstrap certificate, installing the Client, enrolling it, renewal, and the updates of its agents and of the Client itself |
| **[Server](server.md)** | run the control plane: the two listeners, Configurations, packages and the deployments that aim them, the REST API, authentication, enrolment, TLS |
| **[Client](client.md)** | run a managed host, end to end: how it is built, the OS service, the on-disk layout, Supervisors for Collectors and Foreign Agents, package updates, self-update, and Gateway Mode |
| **[Rollout walkthrough](rollout.md)** | both ends at once, end to end: build an artifact, sign it, upload it, aim it, and watch a Foreign Agent be installed and configured entirely from the Server |
| **[Command-line tools](tools.md)** | get software into the fleet: fetch a known agent's release and hand it to the Server, or build, hash, and sign an artifact out of any program |

The two halves interlock in three places, and each is described on both sides: **authentication**
(the Client presents a client certificate the Server accepts, and a new host is
enrolled on an operator's approval), **connection settings** (the Server can move
the fleet to a new endpoint and renews each certificate), and **packages** (the Server decides *which* artifact an
Agent gets, the Client decides *whether* it takes one at all).

## What this manual is not

- **[`docs/SPECIFICATION.md`](../SPECIFICATION.md)** — the problem, the goals, and the vocabulary.
  Every capitalized term here (Agent, Supervisor, Configuration, Selector, Package, Foreign Agent,
  Managed Process) is defined there.
- **[`docs/CONFORMANCE.md`](../CONFORMANCE.md)** — how much of the OpAMP protocol each end
  implements, capability by capability, including what is deliberately missing.
- **[`CHANGELOG.md`](../../CHANGELOG.md)** — what an upgrade needs edited or moved before it will
  start.

## Before you start

Both binaries are built from one Cargo workspace; the build, test, and run commands live in the
[root README](../../README.md), under *Build, Test & Run*, and are not repeated here. It assumes
you can run:

```console
$ cargo run -p fleet-server -- --config config/server.toml
$ cargo run -p fleet-agent -- --config config/supervisor.toml
```

An installed deployment runs the same two programs under the names `server` and `supervisor`; the
`cargo run -p … --` prefix is only how you invoke them from a source checkout.

## Quick start: a closed loop on one machine

This is the smallest complete deployment — one Server, one Client, one Configuration. Neither end
starts without TLS material and a client certificate, so the first step makes a
development set of them.

1. **Create the development certificates.** [`scripts/dev-pki.sh`](../../scripts/dev-pki.sh) makes
   them with the operator tool's `opamp-fleetctl pki init`, so it needs no other tool: the three CAs
   of [Setting up a fleet](setup.md#the-certificates-at-a-glance), a Server certificate for
   `localhost`, `127.0.0.1` and `::1`, and the bootstrap certificate the Client enrols with.
   Everything lands in `.dev-pki/`, which git ignores. The keys are unencrypted and the CAs are
   throwaway, so use the set on a development machine only. The script refuses to overwrite a
   directory that already holds a set.

   ```console
   $ scripts/dev-pki.sh
   ```

   It also writes `.dev-pki/server.toml` and `.dev-pki/supervisor.toml`, which name the set by
   absolute path. Every other key keeps its default.

2. **Start the Server.** It serves two planes on two ports, both over TLS 1.3: the **Agent plane**
   on `127.0.0.1:4320` (the OpAMP endpoint at `/v1/opamp` and the package downloads), and the
   **Operator plane** on `127.0.0.1:4321` (the REST API under `/api/v1/`, the API docs at
   `/api/v1/docs`, and the bundled UI at `/`). Both are on the loopback by default.

   ```console
   $ cargo run -p fleet-server -- --config .dev-pki/server.toml
   ```

3. **Start a Client, and approve its enrolment.** With no `[[supervisor]]` block it presents
   exactly one Agent: itself. It holds the bootstrap certificate and trusts the development server
   CA, so it enrols like any host: it asks for a certificate, and the request waits for an
   approval. In a development set the seed script opens the window and approves it:

   ```console
   $ cargo run -p fleet-agent -- --config .dev-pki/supervisor.toml
   $ scripts/seed_test_configs.sh --enrol
   approved the request with key fingerprint f1e9…
   ```

   On a real fleet you compare the fingerprint with the Client's log first
   ([Enrol the Client](setup.md#5-enrol-the-client)).

4. **Open the UI** at <https://127.0.0.1:4321/>. Your browser does not know the development CA, so
   import `.dev-pki/offline/server-ca.pem` into its trust store first. The Agent is listed as *Connected*, with
   the attributes it reported.

5. **Create a Configuration and roll it out through a Deployment.** In the UI, press
   **Configurations**, then **＋ Create**, give it a name and the Agent type it is for —
   `supervisor`, the type the Client's own Agent reports — enter the configuration text and press
   **OK**. The Client's own Agent is configured with its Supervisor set, and with no Managed
   Process yet a comment is the whole of it: `# no [[supervisor]] block yet`. A Configuration
   aims at nobody by itself: on **Deployments**, press **＋ Create**, name
   the deployment, give it a selector every Agent of this host matches — `os.type=linux` on Linux —
   add the Configuration and press **OK**. Then press the row's **Roll out**, because saving only
   stores; the rollout act is what reaches the fleet. The same steps over the API, with `--cacert`
   naming the development CA:

   ```console
   $ curl --cacert .dev-pki/offline/server-ca.pem -X PUT -H 'Content-Type: application/json' \
          -d '{"service_name": "supervisor", "body": "# no [[supervisor]] block yet\n"}' \
          https://127.0.0.1:4321/api/v1/configurations/base
   $ curl --cacert .dev-pki/offline/server-ca.pem -X PUT -H 'Content-Type: application/json' \
          -d '{"selector": {"os.type": "linux"}}' \
          https://127.0.0.1:4321/api/v1/deployments/dev
   $ curl --cacert .dev-pki/offline/server-ca.pem -X PUT https://127.0.0.1:4321/api/v1/deployments/dev/configurations/base
   $ curl --cacert .dev-pki/offline/server-ca.pem -X POST https://127.0.0.1:4321/api/v1/deployments/dev/rollout
   ```

6. **Watch the loop close.** A WebSocket Client receives it within a second, an HTTP Client on its
   next poll. It stores the configuration, reports it **Applied** with the matching hash, and its
   effective configuration appears in the fleet table. Rolling the same Configuration out again
   sends nothing — every push is gated on a content hash. An Agent that connects *later* is not
   changed by the earlier act: its row on the Agents tab shows the Configuration waiting, with a
   **roll out** control of its own.

   A Configuration reaches only the Agents of the Deployment that report its `service_name`. A
   Collector put under the Client later reports a type of its own and needs a Configuration of
   its own: content for several Agent types is one Configuration per type.

For a deployment that crosses a network, with certificates of your own, follow
[Setting up a fleet](setup.md). From here, [Server](server.md) covers targeting a subset of the
fleet and distributing software, and [Client](client.md) covers putting a real Collector or a
Foreign Agent under management.

## Concepts both halves use

**Agent and `instance_uid`.** The unit the Server manages is an *Agent*, identified by an
`instance_uid` and nothing else — not by the connection that carried it. One Client presents several
Agents: itself, always, plus one per configured Supervisor. All of them share the Client's single
connection, so the Server's fleet view has more rows than there are hosts.

**Attributes.** Every Agent reports attributes — `service.name`, `service.instance.name`,
`service.version`, `service.instance.id`, `os.type`, `os.name`, `os.version`, `os.description`,
`host.name`, `host.arch`, `host.id` — and an operator can add more in `supervisor.toml`, plus
`service.namespace` where a deployment uses one. These are what Selectors match on. An attribute the
host cannot answer is absent rather than empty.

Two of them are easy to confuse, and telling them apart is what aims everything else:
`service.name` is the Agent **type** — `otelcol-contrib`, `promtail`, `supervisor` for the Client's
own Agent — the
same value on every host running that kind of agent, while `service.instance.name` is **your** name
for one Agent, the `[[supervisor]]` block's `name`. Aim at the type to reach every Agent of a kind,
at the instance name to reach exactly one.

**Configuration.** A *Configuration* is a named body of text held by the Server, optionally
stated for one Agent type (`service_name`). It aims at nobody by itself: a Deployment holds it, and
it reaches the Agents of that Deployment whose type it fits. An Agent receives every Configuration
its Deployment holds for it, as named entries, and merges them itself; an Agent in no Deployment is
left running what it already runs.

**Role.** A Configuration may carry the role `supplementary`, which means *content the
Managed Process reads by path* — a rule file, a lookup table — rather than configuration it is
started with. The Client writes it beside the configuration under its own name, and leaves it out of
what the process is configured with.

**Package.** What an Agent type runs at a version — its identity is those two things and nothing
else, and it holds one artifact per platform, each with the operator's signature. It reaches no
Agent of another type, and it aims at nobody by itself.

**Selector and Deployment.** A *Selector* is a set of `key=value` pairs that an Agent's effective
description must equal: the `fleet.host.*` values of the Host it connects over, what it reported,
its labels, and the labels of its Client's own Agent, in that order. It aims a *Deployment*: a name, the **channel** its Selector
names, at most one Package per Agent type, and any number of Configurations. It is the only thing
that is rolled out — one press releases its Packages and Configurations together — and an
Agent belongs to **at most one** — two claiming the same Agent is a conflict the Server reports
rather than resolves. A Selector is equality and cannot say "not", so channels are a partition over an
attribute every Agent carries; there is no fleet-wide default. The Server decides which artifact an
Agent is offered; the Client decides whether it accepts packages at all. Every artifact is verified
by its content hash and by its Ed25519 signature, which the operator puts on each entry of the
Package. A Client without a verification key takes no package, and the Server offers no entry
that carries no signature. Every artifact is uploaded to the Server, and a Client downloads from
its own Server alone.

**Transports.** The URL scheme in the Client's `endpoint` selects the transport: `wss://` for
WebSocket, where the Server pushes changes within seconds, and `https://` for plain-HTTP polling.
The Server accepts both on the same path, at the same time. `ws://` and `http://` are accepted
only to the IP literals `127.0.0.1` and `::1`.

**Security before convenience.** Both ends refuse an insecure configuration at startup, and the
refusal names the setting to fix; neither warns and carries on. Every connection that leaves a host
is TLS 1.3, and plaintext is accepted on the loopback alone — the IP literals `127.0.0.1` and
`::1`, never the name `localhost`. An Agent proves fleet membership with one thing: a client
certificate in the TLS handshake. It holds no credential. A new host gets its certificate
only through an enrolment an operator opens and approves. Software is installed only when it is
signed with the operator's key and fetched from a source the operator allowed.

**Configuration files.** Both ends read one hand-edited TOML file, named with `--config`.
Most keys are optional; the TLS material is not. An unknown key is
refused at startup rather than ignored, and there are no environment-variable fallbacks. The
annotated examples in [`config/`](../../config/) are the reference copies: [`config/server.toml`](../../config/server.toml) and
[`config/supervisor.toml`](../../config/supervisor.toml).

## Not built yet

The manual documents what runs today. These are designed, or partly built, and named here so you do
not go looking for a setting that does not exist. [`docs/CONFORMANCE.md`](../CONFORMANCE.md) is the
authority on all of it.

- **`tls` and `proxy` in connection settings** — a Server offering either is told, in
  its status report, that the Client dropped them. Mutual TLS itself *is* built, and required: see
  [the Server](server.md#mutual-tls-proving-who-is-on-the-connection).
- **Custom messages** (`CustomCapabilities` / `CustomMessage`) — planned, not implemented.
- **Other connection settings** (`AcceptsOtherConnectionSettings`) — deliberately not implemented:
  the protocol leaves their meaning entirely to the Agent, so honouring the capability would mean
  inventing semantics.
