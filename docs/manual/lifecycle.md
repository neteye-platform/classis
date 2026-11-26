# A host's life: installation, enrolment, updates

[← User Manual](README.md) · [Setting up a fleet](setup.md) ·
[The Client](client.md) · [Rollout walkthrough](rollout.md)

This page follows one managed host through its whole life, from the first file
you copy to it to the updates it takes years later. It says what happens at each
stage, who acts, and where, and links to the page that holds the detail. It
assumes a running Server and the enrolment key of a Space;
[Setting up a fleet](setup.md) gets you there.

The Server's UI shows the fleet and releases its updates, and everything the UI
does is a call to the REST API, so a script can do the same. The API calls are
on the pages this one links to.

- [At a glance](#at-a-glance)
- [1. Install the Client](#1-install-the-client)
- [2. Enrol the host](#2-enrol-the-host)
- [3. Updates](#3-updates)
- [4. Taking a host out](#4-taking-a-host-out)

## At a glance

| Stage           | Who acts                       | Where                                 | What happens                                                                                                                |
| --------------- | ------------------------------ | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| 1. Installation | you, on the host               | the host                              | The Client is installed as a service and told the Server's address and the server CA. It is registered, and starts nothing. |
| 2. Enrolment    | you, on the host, once         | the host                              | `enrol` registers the host with its Space's key, gets its token, writes `state.json` and starts the service.                |
| 3. Updates      | you release, the host installs | **Packages** and **Deployments** tabs | A signed Package reaches the hosts of a channel. Each host verifies it, installs it, and rolls back what will not run.      |
| 4. Removal      | you, on the host               | the host                              | `revoke` deletes the host's state, `state.json` with it. The Server is not told.                                            |

## 1. Install the Client

Each host needs the server CA, best kept in a directory such as `/etc/opamp/`:

| File            | From                                  | Notes                                                                                                                                       |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `server-ca.pem` | the offline directory `pki init` made | The CA of the certificate the reverse proxy in front of the Server presents. The Client trusts it, and only it. Not needed for a public CA. |

Install the Client from the release's `.deb`, `.rpm` or `.msi`. The package
registers the service and leaves it stopped, and does not let it start at boot:
a host runs nothing until it is enrolled. Then configure it in one of two ways:

- **Interactively**: `sudo classis service install --interactive` asks for the
  Server's address and the host's name, and the server CA where the proxy's
  certificate needs it, and writes the configuration. On Windows, run it in an
  elevated shell.
- **From a script**, which suits configuration management: after the package,
  run
  `sudo classis service install --endpoint <address> --fleet-files /etc/opamp`.
  The package's own install never asks anything.
- **With a file**: write `supervisor.toml` naming the server CA.

The configuration holds no credential. Details:
[Configure and install a Client](setup.md#4-configure-and-install-a-client) and
[Installing from a native package](client.md#installing-from-a-native-package).

## 2. Enrol the host

Enrolment turns an installed host into a member of the fleet. It needs the
enrolment key of the Space the host is to join, and no operator approves it: a
valid key enrols the host at once. The key stands in no file on the host; give
it to the command.

```console
$ sudo classis enrol https://fleet.example.com:4320 cle1_lab_…
enrolled in the space lab as 0193a6f0-…
  state file: /var/lib/classis/state/state.json
  the service is started, and starts at boot
```

What happens, in order:

1. **The host registers.** It sends the key to the Server's `/v1/enrol` as the
   initial access token of an OAuth 2.0 dynamic client registration (RFC 7591)
   and receives a `client_id`, its **Device ID**, and a `client_secret`. The key
   names the Space, so no command takes it a second time.
2. **The host asks for its token.** It sends its client credentials to
   `/v1/token` (client credentials grant, RFC 6749 §4.4) and receives an opaque
   access token. A new token replaces the one before it.
3. **The host keeps what it has.** It writes `state.json` in its state
   directory, owner-only: the Server's base URL, the Space, the Device ID, the
   client secret and the token. Nothing else in the file changes afterwards but
   the token.
4. **The service starts.** Where the service is registered, `enrol` hands
   `state.json` to the account the service runs as, lets the service start at
   boot, and starts it. The host appears on the **Agents** tab as connected
   within seconds.

From then on every OpAMP exchange and every package download carries the token
as `Authorization: Bearer`. The Client keeps no clock for it and renews nothing
ahead of time: it asks for a new token only when the Server answers `401` with
`invalid_token`, because the token expired (`token_lifetime_secs` on the Server;
0, the default, is for ever) or was replaced. Replacing a token ends the
WebSocket sessions admitted with the old one.

`enrol` is refused on a host that holds a `state.json`. A host without one runs
nothing.

The key comes from the Server: `classis-cli space create <name>` makes a Space
and prints its key, over the Server's admin socket
([The operator's socket](server.md#the-operators-socket)).

Details: [Enrol the Client](setup.md#5-enrol-the-client).

## 3. Updates

A Client updates two kinds of software in the same way: the agents it
supervises, and itself.

### How an update travels

```text
Package            Deployment                    Client, on each host
(agent type,  ──▶  (channel,              ──▶    download ─▶ verify ─▶ install ─▶ health check
 version,           Packages)                                                      └─▶ roll back
 one signed         rollout act
 binary per
 platform)
```

- A **Package** is what an agent type runs at a version, with one binary per
  platform and a signature on each. On its own, it reaches nobody.
- A **Deployment** is a channel: a Selector that names the hosts it aims at,
  such as `channel = stable`, the Packages it offers, and the Configurations
  that go with them. A host belongs to at most one Deployment.
- The **rollout act** releases the Deployment — its Packages and its
  Configurations together — to the hosts it claims. Nothing changes on any host
  before it.
- The **Client** takes a package only when the binary's hash and signature
  verify. The signature must come from a Package Signer that the project's
  Package Root, compiled into the Client and the Server, issued. Today only the
  release's `.sig` files, for the Client's own archives, are such signatures: a
  signature made with a key of your own is refused, so no other program can be
  delivered yet. The Client installs the binary, restarts the program, and
  checks that it stays up. A version that does not stay up is rolled back to
  the one before.

A Package reaches a host only as an **upgrade**: never the version it runs,
never an older one. To take a bad version back, publish the old content as a
new, greater version and roll that out.

### Releasing an update in the UI

1. **Packages** tab: press **＋ Create**, enter the agent type and the version,
   and give the first platform's binary as a file. A file named
   `<agent type>_<version>_<os>_<arch>.tar.gz` fills the fields by itself. Press
   **OK**, then add each further platform with **＋ Add entry**.
2. Still there, give each entry its signature in its field: for the Client's
   own Package, the content of the release's `.sig` of the same name. The
   Server refuses a signature that does not verify, naming why, and stores
   nothing.

3. **Deployments** tab: select the channel, add the Package (it replaces the
   older version of that agent type), and press **OK**.
4. Check the row's counts: how many hosts the channel claims, and how many the
   rollout would move. Press **Roll out (n)**.
5. **Agents** tab: each host shows its progress, `Downloading` with percent and
   speed, then `Installing`, then `Installed` or `InstallFailed` with the
   reason.

A host that joins the channel after the rollout is not updated by itself. Its
row on the **Agents** tab shows the Package waiting, with a **roll out** control
of its own.

Try a release on a few hosts first: give them a channel of their own
(`channel = canary`), roll out there, then give the stable channel the same
version.

Details: [Rollout walkthrough](rollout.md) and
[Package updates](client.md#package-updates).

### The Client updates itself the same way

The Client is always an Agent of its own, of the agent type `supervisor`. A
Package of that type, made from the release archives
`supervisor_<version>_<os>_<arch>.tar.gz` as they are published, each entry
signed with the `.sig` beside its archive, updates the Client itself.

On the host, the new version is staged beside the running one and checked before
anything switches: it must start on this host and report the version offered.
The Client then stops as on any service stop and lets the service manager start
the new version, which commits itself once it reaches the Server. A version that
will not stay up is rolled back to its predecessor after three attempts. Either
way, the Server is told the outcome.

Self-update needs the Client to run as an installed service. To hold a host on
its version, set `self_update = false` under `[packages]`.

Details: [Updating the Client itself](client.md#updating-the-client-itself).

## 4. Taking a host out

Run `revoke` on the host, after stopping its service:

```sh
sudo classis service stop
sudo classis revoke
```

It is local: it never contacts the Server. It asks for a confirmation (`--force`
skips it), keeps the service from starting at boot again, and deletes everything
in the state directory, `state.json` with it, the Agents' identities included.
`--keep-cache` spares `config/` and `packages/`. A host enrolled again is a new
one, with a new Device ID. This build has no command to remove the host from the
Server's records or to disable its client there.

Details: [Living with the enrolment](setup.md#6-living-with-the-enrolment).
