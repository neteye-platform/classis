# The Client

[← User Manual](README.md) · [← The Server](server.md)

The Client is what runs on a managed host: one process, installed as a native
operating-system service on Linux, macOS, and Windows, that supervises local
processes, applies the configuration the Server sends them, reports back what
they are doing, and can replace their binaries — and its own.

Everything about the Client is on this page: what it does, how it is built, how
to run it, where it puts things, and every configuration key.

**Understand it:**

- [What the Client does](#what-the-client-does)
- [How it is built](#how-it-is-built)

**Run it:**

- [Running it](#running-it)
- [Running it as an OS service](#running-it-as-an-os-service)
- [Enrolling the host](#enrolling-the-host)
- [On-disk layout](#on-disk-layout)

**Configure it:**

- [Configuration reference](#configuration-reference)
- [Supervisors: putting a process under management](#supervisors-putting-a-process-under-management)
- [Path placeholders](#path-placeholders)

**Keep it current:**

- [Package updates](#package-updates)
- [Agents that are more than one file](#agents-that-are-more-than-one-file)
- [Updating the Client itself](#updating-the-client-itself)

**When something is wrong:**

- [Connecting to the Server](#connecting-to-the-server)
- [Its own telemetry](#its-own-telemetry)
- [Troubleshooting](#troubleshooting)

## What the Client does

- **Presents one or more Agents to the Server.** The Client is always its own
  Agent, whether or not it supervises anything, so the Server can see which
  version each host runs. Each configured Supervisor is an additional Agent. All
  of them share one connection. The Client's own Agent reports `supervisor.toml`
  itself as its effective configuration — with secret values masked as `***`
  (`[packages]`'s `archive_key`, and `bearer_token` and `password` should a
  leftover `[auth]` still hold them), since the Server persists what it
  receives.
- **Supervises processes**: starts them, watches them, restarts them on a
  configuration change or a Server-issued restart command, stops them gracefully
  on shutdown.
- **Applies received Configurations**: writes each entry to disk under its
  Configuration's name, points the process at it, and reports the configuration
  applied or failed with the hash it applied.
- **Reports health, effective configuration, and version** of each Managed
  Process, and relays the `service.*` attributes a Collector carrying the
  `opampextension` reports about itself.
- **Installs Server-offered packages** over a Managed Process's binary — signed,
  verified, health-gated, and rolled back if the new version will not stay up.
  Every Supervisor takes packages, and there is nothing to configure for it.
- **Updates its own binary** from a signed package while it consents, which it
  does by default, staging the new version beside the running one and asking the
  service manager for a restart.
- **Accepts Server-offered connection settings**: a heartbeat interval or an
  endpoint, which it verifies by connecting before it switches.

## How it is built

The sections below are the load-bearing ideas — what each buys and where each
stops. Skip to [Running it](#running-it) if you only need to operate a host;
come back when something the Client did surprised you and you want to know
whether it was supposed to.

### One process, several Agents

The unit the Server manages is an **Agent**, and one host usually has more than
one. The Client is always an Agent itself; every process it supervises is
another. All of them share a single connection to the Server.

This is why the fleet view has more rows than you have machines, and why the
thing you target with a Selector is not "a host" but an Agent on it.

The multiplexing is possible because **`instance_uid` is the only routing key**.
Nothing on either end is keyed to a connection, which means a connection can
drop and reappear, or an Agent can move between connections, without anything
having to be re-established.

### The Client is its own Agent

Not a special case, not a separate code path: the Client presents itself the
same way it presents anything it supervises, with its own identity, its own
configuration, its own version.

Three things follow, and they are the reason for the design rather than side
effects:

- You can see which version every host runs, whether or not it supervises
  anything.
- The Client can be sent configuration the same way anything else is.
- The Client can be **updated** the same way anything else is — the update
  mechanism did not have to be invented twice.

Its effective configuration is the configuration file itself, with secrets
masked before it goes out, because the Server stores what it receives.

### Two names, and they are not interchangeable

Every Agent reports two names that are easy to confuse:

|                   | means                                                                 | example                         |
| ----------------- | --------------------------------------------------------------------- | ------------------------------- |
| **type**          | what kind of thing this is — the same on every host running that kind | `otelcol-contrib`, `supervisor` |
| **instance name** | _your_ name for this one Agent                                        | `edge-collector-3`              |

Aim at the type to reach every Agent of a kind; aim at the instance name to
reach exactly one. A package is built for a type and reaches no Agent of
another, whatever Deployment holds it; a Configuration stated for a type does
the same.

The Client's own type is `supervisor` — the Agent that supervises the others.
Its instance name defaults to a display name, deliberately not equal to the
type: if both columns of the fleet view said the same word, the distinction they
exist to draw would be invisible on exactly the hosts nobody has named yet.

Under this the identity proper is `instance_uid`, which the Agent asserts
itself. Admission to the fleet is by the access token the host holds, one for
all of its Agents ([Enrolling the host](#enrolling-the-host)); behind it an
Agent is believed about who it is, except that the Server refuses a report for
an `instance_uid` it has recorded under another host.

### The service points at a pointer

The operating-system service is registered against `<root>/current/supervisor`,
never against a version directory. `current` is a pointer; versions sit side by
side beneath it.

That indirection is what makes an update a _pointer swap_ instead of a
re-registration. Registering would need administrative rights every time, and on
Windows the running executable is locked and cannot be overwritten in place at
all. Both problems disappear if the thing the service manager knows never moves.

The same indirection carries the command on your `PATH`, which is a symlink
through `current` — so the installed command reports the running version rather
than whichever one a package happened to deliver.

That command is named after the **product**, while the file it resolves to is
named after the **program**: `classis` on your `PATH`, `supervisor` on disk.
The split is the same one the directories make, and it is what lets two products
built from this source sit on one host without fighting over a single `/usr/bin`
entry. From an unpacked archive there is no symlink and you run the file itself.

Where those directories live, and why the program and the data are sometimes in
different places, is [On-disk layout](#on-disk-layout).

### The configuration file has two owners

The file is TOML, hand-edited, and it fails loudly: an unknown key is refused at
startup rather than ignored, so a typo is a stopped service instead of a setting
silently not taking effect. There are no environment-variable fallbacks — what
the file says is what runs.

But the file is not entirely yours. The Server may send the `[[supervisor]]`
blocks, and when it does the Client rewrites that part of the file and leaves
the rest alone. Your endpoint, your trust, your logging stay yours.

Three guards make that safe to have. The whole offer is **validated before
anything is written** — if one block is bad, nothing changes and the Client
reports the failure naming the block. A delivered block may name only a program
the Client owns, so a Server cannot use configuration delivery to run an
arbitrary binary on your host. And a delivered block **brings nothing that
reaches past the package signature**: it may set environment variables and
arguments only as the running block of the same name already has them, or as you
allow below; never a variable that steers which code a program loads (`PATH`,
`PATHEXT`, `COMSPEC`, `LD_*`, `DYLD_*`, `JAVA_TOOL_OPTIONS`, `PYTHONPATH`,
`PERL5LIB`, `RUBYLIB`, `NODE_PATH` and the like) and never a value pointing into
the Supervisors' own directories, whether by `${config_dir}`,
`${supervisor_dir}` or a path under the Supervisors' root.

```toml
[supervisors]
delivered_env = ["OTEL_*", "GOMAXPROCS"]   # names a delivered block may set; `*` ends a prefix
delivered_args = true                      # a delivered block may state its own arguments
```

Both default to nothing: without them the Server can change which programs run
and with which configuration, but not the environment or the command line they
run with. Allow as little as you need. A name you allow lets the Server set it
to anything outside the refused list, and `delivered_args = true` lets it pass
any argument to a signed program — one that loads a plugin named on its command
line then loads what the Server says.

The first configuration is written by the install, not by you finding a
template: `service install` can ask for what a fresh host cannot guess,
validates it, and only then registers the service. It never overwrites a file
that already exists.

### Supervising is a closed vocabulary

Every supervised process, whatever it is, is driven through the same seven
operations: install, uninstall, start, stop, update, reload, and
apply-configuration. A plugin selected by the block's `type` implements them for
one kind of program.

The vocabulary being closed is the point. A new kind of agent adds an
implementation, not a new concept — so package delivery, health gating and
rollback work for it without anyone extending them. Kinds exist for
OpenTelemetry Collectors and a generic one that runs a command; the generic one
covers most things without a plugin at all.

Each supervised process gets one directory holding everything about it: its
identity, its configuration, its program, and the staging its downloads pass
through. Keeping them together is what makes an install a rename inside one
filesystem rather than a copy across two — a rename either happened or did not.

Remove a block and that directory goes with it, whole. A directory no block
names is reported at startup and never deleted on its own, so a mistyped name
costs you a warning rather than an Agent's identity.

### The Client owns what it runs

A supervised program is always one the Client installed into that Agent's own
directory, named by a bare file name. An absolute path — a program the machine's
package manager installed — is refused at startup.

This is a real restriction and worth stating plainly: **the Client does not
supervise software it cannot replace.** A vendor agent installed by its own MSI
or by `apt` is not managed here until it has been repacked as a relocatable
package and delivered by the fleet.

What it buys is that there is exactly one kind of Managed Process. Every
capability — targeting, version rules, the health gate, rollback — applies to
all of them, and no feature has to be reasoned about twice. The alternative was
a second kind that the fleet could watch but never update, and the seam between
the two ran through every decision that touched packages.

### Packages, updates and connectivity, in one paragraph each

**Packages.** The Server decides which artifact an Agent is offered; the Client
fetches it from its own Server, verifies it by hash and by signature, unpacks it
beside the running program, swaps it in by rename, and watches whether it stays
up. If it does not, the predecessor comes back. The unit is a versioned
**Package** — the Agent type it is built for and its version, each entry signed
— held by a **Deployment** that aims it at a channel; only that deployment is
rolled out, and a Package assigned to any Agent is immutable. In full:
[Package updates](#package-updates).

**Versions.** An Agent reports two numbers that can disagree — the version its
package record claims and the version the program says it is. A Package must
move the Agent forward from the **lower** of the two and never below what the
record claims, so each number is used only in the direction it is trustworthy
for. A version an Agent reports that cannot be ordered blocks nothing on its
own. A Package's own version is SemVer, and a Supervisor takes nothing below the
highest version this Client has installed for its type:
[A Supervisor never goes back](#a-supervisor-never-goes-back).

**Updating itself.** The same machinery, with two differences that exist because
the thing being replaced is the thing doing the replacing: the staged binary is
asked what version it is before anything is committed, and the Client **does not
restart itself** — it swings the pointer and exits, leaving the restart to the
service manager whose job that is. In full:
[Updating the Client itself](#updating-the-client-itself).

**Connectivity.** The URL scheme picks the transport, and every connection off
the host is TLS 1.3. The Client proves membership with one thing: the access
token it got when it enrolled, sent as `Authorization: Bearer` on every OpAMP
exchange and every package download. It asks for a new token only when the
Server says the one it holds is invalid. The Server can move the fleet to a new
endpoint, and the Client proves an offered setting by connecting with it before
it switches. In full: [Enrolling the host](#enrolling-the-host) and
[Connecting to the Server](#connecting-to-the-server).

### What the Client will not do

Knowing the edges is half of knowing the design.

- **It does not authorize per Agent.** Anything admitted to the endpoint is
  believed about who it is; the trust boundary is the endpoint, not the row.
- **It does not run programs it did not install.** See above — this is a
  deliberate narrowing.
- **It does not install an unsigned package**: the signature must come from a
  Package Signer that a Package Root compiled into the Client issued.
- **It does not speak plaintext off the host.** `ws://` and `http://` are
  accepted only to `127.0.0.1` and `::1`; anything else is refused at startup,
  never warned about.
- **It does not restart itself**, on any platform.
- **It does not invent telemetry semantics.** Its own metrics and logs go out
  over OTLP as the OpenTelemetry conventions define them, and nothing beyond.
  Its traces are the one place with no convention to follow — the standard names
  none for an agent's own lifecycle — so the spans are named after the
  operations this project already has a vocabulary for, and their status is the
  standard's, not one of ours.
- **It does not keep state keyed to a connection**, which is what makes
  reconnection uneventful.
- **It does not silently accept a configuration it does not understand** — an
  unknown key stops the start.

On the last point, a related one worth knowing: a Client that holds no
`state.json` does not carry on, whether or not it finds its configuration file.
It refuses to start, as a service or in the foreground, and names `enrol`. A
host that is not enrolled has nothing to present to the Server, and a Client
that came up anyway would manage nothing, which is the failure hardest to
notice. See [Enrolling the host](#enrolling-the-host).

## Running it

```sh
supervisor --config /etc/opamp/supervisor.toml     # foreground; `run` is implied
supervisor run --config /etc/opamp/supervisor.toml # the same thing, said explicitly
classis --version
```

| Global flag         | Meaning                                                                                                                                                                                                                                                                                                                                            |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--config <path>`   | The TOML configuration file. Defaults to `supervisor.toml`. A missing file means the defaults. `service install` is the one place where "not given" means something else: there the file is `supervisor.toml` inside the data root, because a path resolved against this shell's working directory is not one the service manager shares.          |
| `--state-dir <dir>` | Overrides the configuration file's `state_dir`. `service install` bakes this into the unit, so an installed service never depends on a relative path, and every later `service install` keeps the state directory the unit names unless this flag names another. It is how to place the state directory outside the data root and the layout root. Give each Client a state directory of its own: two Clients on one keep replacing each other's access token, so neither stays connected. |

There are no environment-variable fallbacks for configuration — the flags say
only where the file is and which instance is meant. Logging goes to stderr and
is controlled by `RUST_LOG` (default `info`).

The Client stops on `SIGTERM`/`Ctrl-C` (an SCM stop control on Windows) and
sends the OpAMP `agent_disconnect` goodbye before it goes, so the fleet view
shows it as deliberately gone rather than as a host that fell off the network.

## Running it as an OS service

The Client registers _itself_ with systemd, launchd, or the Windows SCM — there
is no packaging step and no unit file to write:

```sh
classis service install --config /etc/opamp/supervisor.toml   # root / Administrator
classis service start
classis service status
classis service stop
classis service uninstall      # deregisters; never deletes the install layout or state
```

An install registers the service and starts nothing, and does not let it start
at boot: a host that is not enrolled runs nothing. `classis enrol` starts it
([Enrolling the host](#enrolling-the-host)); `service start` is for a host that
is enrolled already and was stopped.

| Flag                          | Applies to                          | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--user`                      | every `service` action              | Target the current user's service manager instead of the system one. Useful in development; the default is a system service that starts at boot.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `--root <dir>`                | `service install`, `service config` | The layout root: `versions/` and the `current` pointer. Given alone it also takes the data — `supervisor.toml` and `state/` — so everything lands under the one directory you named, whose file labeling is then yours to manage. Without it the defaults apply per platform and scope, and on Linux system installs they are two directories: `/opt/classis` for the layout, `/var/lib/classis` for the data, because SELinux never lets systemd start a binary labeled for `/var/lib`. macOS uses `/Library/Application Support/classis`, Windows `%ProgramData%\classis`, and user scope the user's own data directory — one directory each. No path is ever fixed. See [On-disk layout](#on-disk-layout). |
| `--data-root <dir>`           | `service install`, `service config` | The data root — `supervisor.toml` and `state/` — when it is to differ from the layout root. A packaged install, the MSI included, passes neither flag and takes the platform defaults.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `--interactive`               | `service install`                   | Ask for the settings a fresh host cannot guess, and write or edit the configuration file, before registering the service. See below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `--endpoint <url>`            | `service install`                   | Write the configuration file with this endpoint instead of asking for it — the same file, from an answer given rather than typed at a prompt. Mutually exclusive with `--interactive`, and it keeps an existing file untouched. `ws://` and `http://` are refused unless the host is `127.0.0.1` or `::1`. It has no sibling for the CA file: it takes it from [beside the program](#files-beside-the-program), or it is a key the operator writes in the file.                                                                                                                                                                                                                                               |
| `--run-as <account>`          | `service install`                   | Run the service as this account, and hand its files over to it. Without it, a re-registration keeps the account the existing registration names. `--run-as root` chooses root. See [Running it under its own account](#running-it-under-its-own-account). System scope only — a `--user` service already runs as its user.                                                                                                                                                                                                                                                                                                                                                                                    |
| `--process-account <account>` | `service install`                   | Run every Managed Process under this account, through a second service that runs under it. Without it, a re-registration keeps the account the second service's registration names. See [Managed Processes under a process account](#managed-processes-under-a-process-account). System scope only.                                                                                                                                                                                                                                                                                                                                                                                                           |
| `--no-process-account`        | `service install`                   | Stop and deregister the second service; the Client starts its Managed Processes itself again. Mutually exclusive with `--process-account`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

### Running it under its own account

The system service — and, unless a
[process account](#managed-processes-under-a-process-account) is registered,
every Managed Process its Supervisors spawn — runs as one account, and the
install hands its files over to it: the configuration file, the state directory,
**and the executable layout**. The layout too because the self-update runs
_inside_ the service — a layout the account cannot write would silently end
[server-driven updates](#updating-the-client-itself) for that host. The account
is the most a Server-delivered command, such as a Telegraf `inputs.exec`,
reaches on the host.

Which account it is:

| `service install` …                                               | runs as                                                                                  |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `--run-as <account>`                                              | that account                                                                             |
| `--run-as root` (Linux, macOS)                                    | root, written as `User=root` / `UserName` `root`, so the next re-registration keeps root |
| no flag, the unit or plist names an account                       | that account, kept                                                                       |
| no flag, the unit names none, the data root belongs to an account | the data root's owner, and the install says so                                           |
| no flag, first registration                                       | root (systemd, launchd), `LocalSystem` (Windows)                                         |

The Linux packages create the account `classis` and name it on a first
installation — see
[Installing from a native package](#installing-from-a-native-package). A
re-registration reads the account from the file the Client wrote,
`/etc/systemd/system/classis.service` or
`/Library/LaunchDaemons/classis.plist`, not from a drop-in. Windows keeps
the logon account the SCM holds. The install prints the account and where it
came from:

```sh
# classis service install
installed classis
  …
  runs as:   classis (kept from /etc/systemd/system/classis.service)
```

On Linux and macOS the account must already exist, named or kept; the install
refuses before it writes anything if it does not, and names the file a kept
account came from. The binary never creates an account:

```sh
# useradd --system --user-group --no-create-home --home-dir /var/lib/classis \
    --shell /usr/sbin/nologin classis
# classis service install --run-as classis
```

The hand-over never follows a link: each directory is opened as itself and
re-owned through that handle, a symbolic link is re-owned as a link, and a file
with a second hard link is left as it is and named in a warning.

On Windows only **passwordless** account forms are accepted — there is
deliberately no password flag: a flag stands in the shell history and the
process list. The recommended form is the service's own virtual account, which
Windows provisions and password-manages by itself:

```sh
> classis service install --run-as "NT SERVICE\classis"
```

A group-managed service account (`DOMAIN\name$`) and the built-ins
`NT AUTHORITY\LocalService` / `NT AUTHORITY\NetworkService` are accepted as
well. The install grants the account Modify on its directories; it does not
touch the _Log on as a service_ right — the default security policy grants it to
`NT SERVICE\ALL SERVICES` (covering the virtual account), the built-ins carry it
inherently, and a gMSA gets it from its domain's group policy. On a host
hardened to remove that default grant, restore the right for the account or the
service will not start.

Two consequences to weigh before using it:

- **The account is a trust boundary.** Whoever holds it can replace the binary
  in the layout, and the packaged `/usr/bin/classis` symlink resolves
  through that layout's `current` pointer — an administrator invoking the CLI
  executes account-owned code.
- **The account's limits are the fleet's.** Under an account other than root,
  GLPI Agent's full inventory and its Deploy task, a Telegraf input without a
  `sudo` rule, a listener on a port below 1024, and a log receiver reading
  `root:adm` files fail — that trade-off is the point. Grant what is missing (a
  `sudoers` entry, `usermod -aG adm classis`, or a drop-in, below), or
  choose root with `classis service install --run-as root`.

Re-running `install` with a different `--run-as` re-registers and re-owns the
same directories. Without the flag it keeps the account; a plain re-install does
not return a host to root.

#### The systemd unit, and what a drop-in adds

On Linux the Client writes its system unit itself. It quotes every word of
`ExecStart=`, so a root holding a space, a `%` or a `$` works, and it carries
only the sandboxing that leaves `sudo`, setuid helpers and every supported agent
working. Most of systemd's sandboxing directives set `no_new_privs` for a unit
that does not run as root, and with it set `sudo` and every setuid helper stop
working for the service and every Managed Process.

| unit runs as | carries                                                                         |
| ------------ | ------------------------------------------------------------------------------- |
| any account  | `ProtectControlGroups=yes`                                                      |
| root         | also `ProtectKernelTunables=yes`, `LockPersonality=yes`, `RestrictRealtime=yes` |

`NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`,
`CapabilityBoundingSet=` and the rest are left out, because a supported agent
needs what each takes away. A re-registration rewrites the unit;
`service install` never touches `/etc/systemd/system/classis.service.d/`, so
what a host can take, or must not have, goes into a drop-in there and survives
every upgrade:

```ini
# /etc/systemd/system/classis.service.d/host.conf
[Service]
# Nothing on this host uses sudo or a setuid helper:
NoNewPrivileges=yes
# A receiver listens on a port below 1024:
AmbientCapabilities=CAP_NET_BIND_SERVICE
# Log files readable by group adm:
SupplementaryGroups=adm
```

```sh
# systemctl daemon-reload && systemctl restart classis
```

A drop-in that removes a directive the unit sets assigns it its default, for
example `ProtectKernelTunables=no`. A `User=` in a drop-in governs the process,
but the install hands the roots to the account the unit names; name the account
with `--run-as` instead.

### Managed Processes under a process account

Without a process account, every Managed Process runs as the Client's account
and can read what the Client can: its `state.json`, which holds the client
secret and the access token, every other Supervisor's `config/`, and the
program it runs, which it can also rewrite. A
**process account** separates them.
`service install --process-account <account>` registers a **second service**,
`classis-agents`, that runs under that account and starts, signals and stops
every program a Supervisor starts — the Managed Process, its version probe, and
the preflight of a staged package — on the Client's request. The Client starts
none of them itself.

```text
service manager ─┬─ classis         Client, its own account   (supervisor run --service …)
                 └─ classis-agents  the process account        (supervisor run --agents …)
                        ▲
                        └── Unix socket / named pipe; only the Client's account is admitted
```

What the separation gives and what it does not:

- A Managed Process, and anything it starts, cannot read the Client's
  `state.json`, package state, logs or environment, nor write the program it
  runs. A command a Configuration makes it run — a Telegraf `inputs.exec`, an
  Icinga `CheckCommand` — runs as the process account.
- All Managed Processes share the one process account, so they still read one
  another's `config/` and environment.
- None of them can take the second service's place through its socket or pipe,
  as far as the platform tells processes apart: a process id that comes round
  again is told apart on Linux 6.5 and later alone, and on Windows a Managed
  Process can still open the second service's process with the rights its
  account holds on it. A Managed Process can replace the socket in the directory
  the process account owns, or on Windows create an instance of the pipe, but
  before the Client writes anything on a connection it reads the process at the
  other end and asks the service manager which process it runs as the second
  service — systemd's `MainPID`, launchd's `pid`, the SCM's process id — and
  speaks only to that one. Any other is told nothing: the Client closes the
  connection, its Supervisors report that the second service cannot be reached,
  and it tries again, on a new connection checked anew, as for a second service
  that is down; it asks the service manager again at each of those tries, every
  200 ms. The log names the socket or pipe and the process that served it:

  ```text
  ERROR classis_agent::supervisor::channel: refused a peer that is not the second service, before writing anything to it; no program starts until the service manager's second service serves the socket socket=/run/classis-agents/agents.sock peer_pid=4711 error=/run/classis-agents/agents.sock is served by process 4711, not by the second service (process 812) unlogged=0
  ```

  Find the process with `ps -p <peer_pid>`, or on Windows
  `tasklist /FI "PID eq <peer_pid>"`, end it, and restart the second service,
  which binds its socket or pipe again. The same refusal, with the reason in
  `error`, follows where the service manager cannot be asked: on Linux that
  needs systemd's system bus, on macOS `launchctl print`.

- A grant an agent needs names the process account, not the Client's: a
  `sudoers` rule for Telegraf's `use_sudo`, the rights Icinga 2 needs on its
  directories, a supplementary group such as `adm`. On Linux, what a Managed
  Process needs from systemd — a capability for a port below 1024, a
  supplementary group — goes into a drop-in for the second service,
  `/etc/systemd/system/classis-agents.service.d/`, which `service install`
  never touches either.
- A restart of the second service stops every Managed Process; the Client starts
  them again once it reaches the service.

The rules every platform holds the account to:

- **The operator creates it.** The binary never creates an account, and an
  install naming one that does not exist is refused before anything is written,
  with the command that creates it.
- **It is never root or `LocalSystem`, and never the Client's account.** A host
  whose agents need root runs as root as a whole: `--run-as root` and no
  `--process-account`, with no second service.
- **The Client runs under an account of its own.** On Linux and macOS a Client
  that runs as root is refused; on Windows one that runs as `LocalSystem` is.
- **System scope only**: systemd on Linux, launchd on macOS, the SCM on Windows.
  `--user` is refused with it.
- **It is kept.** A re-registration without the flag — every package upgrade,
  every MSI upgrade — keeps the account the second service's registration names:
  `/etc/systemd/system/classis-agents.service`,
  `/Library/LaunchDaemons/classis-agents.plist`, or the SCM's entry. The
  install prints it:

  ```console
  # classis service install
  installed classis
    …
    runs as:   classis (kept from /etc/systemd/system/classis.service)
    processes: classis-agents (kept from /etc/systemd/system/classis-agents.service), started by classis-agents
  ```

`service install`, `start`, `stop` and `uninstall` act on both services. The
second service is started first and stopped last. The Client does not depend on
it: while it is down the Client stays connected, its Supervisors report that
their programs do not start, and they start again once it is back. A package
offered meanwhile is staged and stays `Installing`, and a Configuration stays
`APPLYING`, each naming the second service as the reason, until it is reached
again. `service status` reports the Client; ask the service manager for the
second service (`systemctl status classis-agents`,
`launchctl print system/classis-agents`, `sc query classis-agents`).

Both services run the same program from the same `current` pointer, and a
self-update restarts the one that is behind: two ends of different builds refuse
each other, and the one whose version `current` no longer names exits and is
started again by its service manager.

#### On Linux

The Client must run under its own account, which the `.deb` and `.rpm` make
`classis`. The process account needs a primary group of its own whose one
member is the Client's account: the install refuses a group that is gid 0, that
is the Client's primary group, that has another member, or that is another
account's primary group, and a process account that is a member of the Client's
primary group. Create it, put the Client's account into its group, and register:

```console
# useradd --system --user-group --no-create-home --shell /usr/sbin/nologin classis-agents
# usermod --append --groups classis-agents classis
# classis service install --process-account classis-agents
# classis service stop && classis service start
```

Adding a process account where there was none stops nothing; the Client that
runs goes on starting its programs itself until it is restarted, which the last
line does.

What the install registers:

- `/etc/systemd/system/classis-agents.service`, `User=classis-agents`,
  running `run --agents /run/classis-agents/agents.sock --client-uid <uid>`,
  with `RuntimeDirectory=classis-agents`, `RuntimeDirectoryMode=0750`,
  `TimeoutStopSec=30`, `Restart=on-failure` and `ProtectControlGroups=yes`.
  systemd creates the socket's directory at every start, owned by the process
  account, and removes it at the stop.
- In the Client's unit, `Wants=classis-agents.service` and
  `After=classis-agents.service`, never `Requires=`, and
  `--agents-socket <socket> --process-uid <uid>` on its command line.

No data root or layout root may be, or lie in, the socket's directory. The
second service admits only a peer whose uid is the Client's, serves one
connection at a time, and when that connection closes stops every program it
started, by its process group. Its programs get its own environment, with
`HOME`, `USER` and `LOGNAME` of the process account, then the block's `env`,
then the Supervisor Endpoint's token; they keep its umask.

The second service's program marks itself not dumpable (`PR_SET_DUMPABLE`)
before it parses its command line or sets up its log, so from then on no process
of the process account can attach a debugger to it, read its memory or take its
file descriptors, whatever `kernel.yama.ptrace_scope` says. It therefore writes
no core dump, and the files under `/proc/<pid>/` belong to root. The programs it
starts are dumpable as usual. Where Yama is absent or `ptrace_scope` is 0, the
moment between its start and the mark remains open to a Managed Process that
ends it and waits for systemd to start it again. A second service that is traced
at its start does not listen: it exits with
`the second service is traced by process <pid>`, and systemd starts it again.

At its next start the Client lays out what it keeps for the process account's
group; everything else under `state_dir`, its logs among them, stays its own:

| Path                                                                        | Owner : group                    | Mode                            |
| --------------------------------------------------------------------------- | -------------------------------- | ------------------------------- |
| `state_dir`, the Supervisors' root, each Supervisor's directory             | Client : process account's group | `0710`                          |
| `state.json`, `remote-config.pb`, `instance-uid`, package state and staging | Client                           | `0600` / `0700`                 |
| `program/` and its files, the preflight's staging                           | Client : process account's group | `0750`, no group or other write |
| `config/` and its files                                                     | Client : process account's group | `0750` / `0640`                 |
| a kind's data directories                                                   | Client : process account's group | `2770`                          |

A re-registration leaves what the process account owns, and what is in its
group, as it is. A member of a `.tar.gz` package never lands writable by group
or others, on every host: `0777` lands `0755`, `0666` lands `0644`.

#### On macOS

The same rules, with launchd: macOS 13 or later, the Client under an account of
its own (not root), and the process account a role account whose name begins
with `_`, with a primary group of its own that the Client's account joins:

```console
# dseditgroup -o create -i <gid> _classis-agents
# sysadminctl -addUser _classis-agents -UID <uid> -GID <gid> -roleAccount
# dseditgroup -o edit -a <client account> -t user _classis-agents
# classis service install --run-as <client account> --process-account _classis-agents
# classis service stop && classis service start
```

`<gid>` and `<uid>` are ones no group or account holds. The install registers
`/Library/LaunchDaemons/classis-agents.plist` with `UserName` naming the
process account, and creates the socket's directory
`/Library/Application Support/classis-agents/`, owned by the process account
and its group, `0750`; the socket is `agents.sock` in it. The install refuses to
create it where `/Library/Application Support` is writable by an account other
than root, and it removes the directory with the second service's registration.
Modes and ownership are those of the Linux table.

#### On Windows

The Client must run under an account of its own, so name it with `--run-as` on
the same install; a registration that runs as `LocalSystem`, which is what the
MSI's first install makes, is refused. The process account is passwordless, as
`--run-as` is: the second service's own virtual account
`NT SERVICE\classis-agents` (recommended), a gMSA (`DOMAIN\name$`), which is
looked up in its domain, or `NT AUTHORITY\LocalService` / `NetworkService`,
which other services share and so separate less. From an elevated prompt:

```console
> classis service install --run-as "NT SERVICE\classis" ^
    --process-account "NT SERVICE\classis-agents"
```

Where the Client ran, the install starts it again afterwards, and the second
service before it.

What the install registers and sets:

- The SCM entry `classis-agents`, automatic start, under the process
  account, running
  `run --agents \\.\pipe\classis-agents --client-sid <SID>`, with the
  Client's recovery actions. Its required privileges are
  `SeChangeNotifyPrivilege` alone, so no Managed Process holds
  `SeImpersonatePrivilege`. The Client's entry does not depend on it:
  `service start` starts the second service first, then the Client.
- The named pipe `\\.\pipe\classis-agents`, owned by the process account.
  Only the Client's account may read and write data on it, and nobody may create
  an instance of it but the process account; it rejects remote clients, and a
  pipe of that name made by anyone first fails the second service's start. Each
  end checks the other's account.
- A job object per program. Every program, and everything it starts, ends with
  its job when the Client's connection closes; a program that has a broker start
  a process for it — a WMI process creation, a scheduled task — outlives that.
  Windows has no signals: a kind that reloads by a signal is restarted instead.
- ACL grants to the process account's SID. The install grants it read and
  execute on the layout's `versions\`. At its next start the Client grants it
  read and execute on `program/`, the preflight's staging and `config/`, and
  modify without `DELETE` on a kind's data directories. It gets nothing on the
  state directory or a Supervisor's directory, which it passes by
  `SeChangeNotifyPrivilege` alone, and nothing on the Client's key or logs. The
  Client's own account gets `WRITE_DAC` with its Modify, so it can make these
  grants.

**Every `service install` stops both services first**, with a process account or
without one, and every MSI upgrade among them: the Managed Processes stop for as
long as the install runs. Before it stops anything it writes which of the two
ran to `HKLM\SOFTWARE\classis\WithdrawalPending` (the value `Pending`), and
once it has succeeded it starts again what ran, the second service first, and
strikes the record. A first install finds nothing to stop and starts nothing. An
install that fails after its stop leaves both stopped and says how the SCM
reports them; the next `service install` that succeeds starts again what ran,
and `classis service start` starts both at once. Only this program's
`service start` and `service stop` strike the record — `sc.exe` and the Services
console do not.

The record's key is created owned by the Administrators, with full control for
`LocalSystem` and the Administrators and nothing for anyone else. An install
that finds the key owned by anyone but `LocalSystem` or the Administrators, or
carrying another DACL, changes nothing until an Administrator has looked at it
and removed it.

`service install`, `uninstall`, `start` and `stop` run one at a time, under the
install lock: a second waits for the first, for up to 300 seconds, then fails.

The MSI passes no `--process-account`: register one with `service install` after
the MSI, and every later MSI upgrade keeps it. The MSI stops and unregisters the
services only on a real removal from Add or Remove Programs or `msiexec /x`,
never in the middle of an upgrade.

#### Changing or dropping the process account

`service install --process-account <other>` names another account;
`service install --no-process-account` stops and deregisters the second service,
and the Client starts its programs itself again:

```console
# classis service install --no-process-account
installed classis
  …
  processes: started by the Client itself once it restarts; classis-agents was stopped and removed
```

Either way the former account keeps nothing in the roots the install acts on —
the layout root, the data root and the state directory, with a Supervisors' root
that lies beneath them. A Supervisors' root outside them is yours: the install
leaves it as it is and names it in a warning, and you grant or withdraw the
process account's rights there yourself — on Linux and macOS by re-owning what
the former account wrote (`chown -R`). The account itself is never removed;
delete it once nothing else uses it.

- **On Linux and macOS** the withdrawal is a change of owner: what the former
  account owns, and what is in its group, goes to the Client's account and
  group. An install that changes or drops the process account, or names another
  `--run-as`, first stops the Client and then the second service, waiting up to
  60 seconds for each process to end, and once it has succeeded starts again
  what ran, the second service first. Where a service cannot be stopped, the
  install starts again what it stopped and changes nothing but the configuration
  it wrote. An install that fails after the stop leaves the services stopped and
  names them; nothing records them, so no later install starts them —
  `classis service start` does.
- **On Windows** every entry that allows the former account anything is removed
  from the layout root, the data root, the state directory, `supervisor.toml`
  and the fleet files copied beside it, and what it owns there is given to the
  Administrators; an entry that denies it stays, and `LocalSystem` is never
  withdrawn. The former accounts are resolved before anything changes — a gMSA
  whose domain cannot be reached fails the install there — and written to the
  record before the stop; an install that finds a withdrawal recorded completes
  it.

A file with a second hard link is never re-owned or withdrawn; the install names
it in a warning.

#### Uninstalling

`service uninstall` deregisters both services and leaves the files on disk. Stop
them first, as the `.deb` and `.rpm` removal does: `classis service stop`,
then `classis service uninstall`. On macOS the socket's directory goes with
the second service. On Windows `service uninstall` stops both itself and starts
neither again; where it holds the install lock and both are stopped it completes
a recorded withdrawal and removes the record, otherwise it says that the next
`service install` or `service uninstall` completes it. It deregisters both
services in every case.

#### Before going back to an older release

A release before the second service knows nothing of it: its `service install`
rewrites the Client's registration without the second service, but neither
stops, rewrites nor removes `classis-agents`, withdraws nothing from the
process account, and leaves a Windows record unread. The second service then
runs a program that does not know `run --agents` and fails at every start.
Before installing such a release, drop the process account with the release you
run — `classis service install --no-process-account` — and then install the
older one.

#### When the install refuses

Every refusal comes before anything is written and names the way out. The ones
you will meet:

| Message about                                                                                 | What to do                                                                                                              |
| --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `… does not exist on this host. Create it first (…)`                                          | Linux and macOS: create the account with the command it shows, or name another.                                         |
| `… cannot be found on this host or its domain`                                                | Windows: name an account that exists, or a gMSA whose domain is reachable.                                              |
| `… is root, and a process account never is` / `it is LocalSystem`                             | Run everything as root (`--run-as root`, no `--process-account`), or name an account of its own.                        |
| `the Client runs as root` / `the Client runs as LocalSystem`                                  | Name the Client's account with `--run-as`; on Windows `NT SERVICE\classis`.                                             |
| `… is the account the Client runs as`                                                         | Name another account for the processes.                                                                                 |
| `… has the primary group …, and the Client's account … is not in it`                          | Add the Client's account to the group with the command it shows.                                                        |
| `… is a member of it beside the Client's account`, `… also the primary group of …`, `(gid 0)` | Give the process account a group of its own whose one member is the Client's account.                                   |
| `… is a member of the primary group of the Client's account`                                  | Take the process account out of that group with the command it shows (`gpasswd --delete`, `dseditgroup -d`).            |
| `… names no account for the second service`                                                   | The unit or plist was edited: name one with `--process-account`, or drop it with `--no-process-account`.                |
| `a process account needs the second service, which only a system service under systemd …`     | Not available at user scope or under another service manager.                                                           |
| `… is, or lies in, …, the directory of the second service's socket`                           | Name a data root and a layout root outside it.                                                                          |
| `would need a password` / `belongs to another service`                                        | Use a passwordless form: `NT SERVICE\classis-agents`, a gMSA, `LocalService`, `NetworkService`.                         |
| `what the former account … was granted cannot be withdrawn`                                   | Windows: the former account, a gMSA among them, cannot be resolved. Run the install again once its domain is reachable. |
| `… records what an install left to finish and cannot be read`                                 | Windows: the record's key is not the install's own. Look at it, remove it, and install again.                           |
| `another install, uninstall, start or stop still holds the install lock`                      | Windows: wait for the other run, or end it.                                                                             |

At run time, the Client logs
`the second service is refused; no program starts until the process account
serves this build on its socket`
when the second service does not admit it: it serves another account than the
one the Client runs as, or another build. `service install` again writes both
registrations from one decision.

### Files beside the program

`service install` looks in the directory of the program it runs from for the
fleet's files, under the names the operator tools give them — or, with
`--fleet-files <dir>`, in that directory instead, never in both:

| File            | What the install does with it                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `server-ca.pem` | offers it as the CA certificate of the Server; with `--endpoint`, copies it beside `supervisor.toml` and names it in `[tls] ca_file` |

So a host is set up by copying the program and this file into one
directory and running, from there:

```console
$ cd /root/fleet-files && sudo ./classis service install --endpoint wss://fleet.example.com:4320/v1/opamp
copied /var/lib/classis/server-ca.pem
wrote /var/lib/classis/supervisor.toml for wss://fleet.example.com:4320/v1/opamp
installed classis
  …
enrol this host, which starts the service: supervisor enrol <base-url> <key>
```

A value the configuration file already holds wins over a file beside the
program, and an existing configuration is never overwritten. The CA is taken
only for a `wss://` or `https://` endpoint. The files stay where they are.
`service config` runs the installed copy of the program and does not look.

The install registers the service and starts nothing: the host is not enrolled
yet, and a Client without `state.json` refuses to run. The line it ends with
names the next step, which is [Enrolling the host](#enrolling-the-host). At user
scope (`--user`) the line says to start the service yourself after `enrol`, with
`supervisor service start --user`.

### The questionnaire: `--interactive` and `service config`

A release artifact is the bare binary, so a freshly downloaded Client has no
`supervisor.toml` to edit, and without one it would dial the development
default, `ws://127.0.0.1:4320/v1/opamp`. `--interactive` asks for the few
settings a fresh host cannot guess and writes the file before it registers the
service. It needs a terminal, and it does not contact the Server:

```console
$ classis service install --interactive        # root / Administrator
No configuration at /var/lib/classis/supervisor.toml — answering these writes it (everything else keeps its default).
Server OpAMP endpoint [ws://127.0.0.1:4320/v1/opamp]: wss://fleet.example.com/v1/opamp
This Agent's name (service.instance.name) [Supervisor Agent]: host-01
CA certificate of the Server — the CA that signed its certificate (PEM path): /etc/opamp/ca.pem
copied /var/lib/classis/server-ca.pem
wrote /var/lib/classis/supervisor.toml
installed classis
  …
enrol this host, which starts the service: supervisor enrol <base-url> <key>
```

`service config` asks the same questions of an installed Client and registers
nothing. Each question offers what the file holds as its default, so Enter keeps
it; afterwards restart the service to apply what changed:

```console
$ classis service config                       # root / Administrator
Editing /var/lib/classis/supervisor.toml — Enter keeps the value shown (everything not asked stays as it is).
Server OpAMP endpoint [wss://fleet.example.com/v1/opamp]:
This Agent's name (service.instance.name) [host-01]: web-01
CA certificate of the Server — the CA that signed its certificate (PEM path) [/var/lib/classis/server-ca.pem]:
copied /var/lib/classis/server-ca.pem
wrote /var/lib/classis/supervisor.toml
restart the service to apply: supervisor service stop && supervisor service start
```

It finds the file the way `install` does: `--config` when you name one, and
otherwise `supervisor.toml` in the data root of the scope — pass the `--user`,
`--root` and `--data-root` the Client was installed with. The file has to load
before anything is asked; one that does not parse is corrected by hand, and the
error names it.

What the questionnaire asks about is only what has no useful default on a fresh
host:

- **the endpoint**, suggesting `ws://127.0.0.1:4320/v1/opamp`. A `ws://` or
  `http://` endpoint is refused unless its host is `127.0.0.1` or `::1`, and the
  question is asked again;
- **the Agent's name**;
- **the CA certificate of the Server**, the CA that signed the certificate the
  reverse proxy in front of it presents, whenever the endpoint is `wss://` or
  `https://` ([`[tls]`](#tls)). It is copied beside `supervisor.toml` as
  `server-ca.pem`, owner-only, and the file names the copy; the original can be
  removed afterwards. A path that names no readable file is asked for again.

The questionnaire asks for no package key: every package is verified up to the
Package Roots compiled into the Client. A new file is written with
`self_update = true`.

A new file gets everything else as commented defaults. An existing file is
edited in place: only the keys asked about change, and every other key, every
comment, the `[[supervisor]]` blocks and the self-update consent stay as you
wrote them. No question asks for a credential, and the questionnaire writes no
`[auth]` section; on Unix the file is mode `0600` and keeps its owner. Enrolling
is a step of its own, after the install.

Four rules worth knowing before you script around it:

- **Interactivity is never assumed.** Without the flag, `install` asks nothing
  and never touches an existing file. It prints a warning when the path it is
  about to bake into the unit holds no file.
- **Defaults are what is there.** Re-running `--interactive` or `service config`
  on a configured host offers every answer typed into the first one, or edited
  since, and keeps whatever it does not ask about.
- **No terminal, no questionnaire.** `--interactive` or `service config` in a
  provisioning run, a container build, or a pipeline fails with a message
  instead of blocking forever on an answer nobody can give.
- **Where it writes:** the path from `--config` when you name one, and otherwise
  `supervisor.toml` inside the data root. The file is validated by the ordinary
  loader before the service is registered; a file that does not parse, or a
  plaintext endpoint off the loopback, fails the install, and the file stays on
  disk for you to correct.

Where there is an answer but no terminal — a provisioning run, an MSI dialog, a
`%post` script — `--endpoint` writes the same file without asking:

```console
$ classis service install --endpoint wss://fleet.example.com/v1/opamp
wrote /var/lib/classis/supervisor.toml for wss://fleet.example.com/v1/opamp
installed classis
  …
enrol this host, which starts the service: supervisor enrol <base-url> <key>
```

It writes only the endpoint, and the CA found beside the program; everything
else keeps its default. All four rules above hold
unchanged — in particular, an existing file is kept.

### Installing from a native package

A release also ships a `.deb`, an `.rpm` and an `.msi`. They deliver the binary
to `/usr/libexec/classis` (Windows: the folder you choose) and then run
`service install` themselves — the layout, the unit and the SCM entry are the
same ones this page describes, because they are made by the same command. No
package ships a unit file of its own. What lands on `PATH` —
`/usr/bin/classis` — is a symlink through the layout's `current` pointer, so
the command you type is always the binary the service runs.

```sh
sudo apt install ./supervisor_1.2.3_linux_amd64.deb
sudo dnf install ./supervisor_1.2.3_linux_amd64.rpm
```

**The service is registered and left stopped, and does not start at boot.** That
is deliberate: the host has no configuration and is not enrolled, and a Client
without `state.json` refuses to run. Two steps remain:

```sh
sudo classis service install --interactive
sudo classis enrol https://<server> <key>
```

The first asks for the endpoint and the Server's CA. The second enrols the host
with its Space's key, and then starts the service and lets it start at boot
([Enrolling the host](#enrolling-the-host)). An upgrade of a host whose service
was running restarts it on the delivered binary.

**The `.deb` and the `.rpm` run the service under the system account
`classis`.** The post-install creates it where it is missing — no password,
`/usr/sbin/nologin`, the data root as its home — and passes
`--run-as classis` only when no unit is registered yet. Every upgrade runs
`service install` without the flag, which keeps the account the unit names, so a
host moved to another account or to root with `--run-as` stays there. A host
that already ran as root before the packages created the account stays root;
move it with `sudo classis service install --run-as classis` and a
restart. No removal, not even a purge, deletes the account. See
[Running it under its own account](#running-it-under-its-own-account) for what
an account cannot do and how to grant it.

**Without a terminal**, as configuration management installs a host, the package
is installed first and the host enrolled in a step after it — the package's own
install never enrols. Put the fleet's files in a directory and name it:

```console
$ sudo dnf install -y ./supervisor_1.2.3_linux_amd64.rpm
$ sudo classis service install --endpoint wss://fleet.example.com:4320/v1/opamp \
    --fleet-files /root/fleet
$ sudo classis enrol https://fleet.example.com:4320 cle1_lab_…
```

The last step starts the service. Remove the directory afterwards.

On Windows the `.msi` asks for the installation folder, the endpoint, and the
self-update consent. The endpoint field is prefilled with
`ws://127.0.0.1:4320/v1/opamp` in the interactive install only. The folder
holds only the delivered program; `service install` puts the layout,
`supervisor.toml` and the state under `%ProgramData%\classis`. The same file
installs unattended with the same answers, which is how Intune, Group Policy and
SCCM deploy it:

```sh
C:\> msiexec /i supervisor_1.2.3_windows_amd64.msi /qn ^
       INSTALLFOLDER="C:\Program Files\classis" ^
       ENDPOINT="wss://fleet.example.com/v1/opamp"
```

A silent install that names no `ENDPOINT` writes no configuration. The MSI
registers the service but neither starts it nor lets it start at boot, and it
asks for nothing that enrols the host: run `classis enrol <base-url> <key>` from
an elevated prompt, which enrols the host and starts the service
([Enrolling the host](#enrolling-the-host)).

Two things to know about living with a packaged install:

- **`dpkg -l` reports the version it _delivered_, not the one that is running.**
  After a fleet self-update
  ([Updating the Client itself](#updating-the-client-itself)) the service runs
  the binary under `<root>/current/`, which no package manager owns — that
  separation is what keeps the next `apt upgrade` from silently reverting the
  Server's decision. `classis --version` goes through `current` and answers
  for the running binary, as does the fleet view; those two are the truth.
- **Removing the package stops and unregisters the service and uninstalls every
  staged version.** `versions/` and the `current` pointer go with the package;
  the state directory and `supervisor.toml` stay, for the same reason an install
  never overwrites a configuration: it holds what you wrote, and the host's
  enrolment and identity. `apt purge` deletes those too — the instance directory
  whole. A reinstall after a plain remove keeps the host's enrolment, identity
  and configuration and stages its own binary fresh; it registers the service
  without starting it, and `classis service start` starts it, since `enrol`
  refuses a host that still holds its `state.json`.

macOS has no native installer; there, unpack the `.tar.gz` and run
`service install` yourself.

### What the service is called

One name on every platform, and it is the **product's** name — not the
program's:

| Platform            | Service                   |
| ------------------- | ------------------------- |
| **Linux** (systemd) | `classis.service`         |
| **macOS** (launchd) | `classis` (job and plist) |
| **Windows** (SCM)   | `classis`                 |

So the same command works everywhere it exists: `systemctl status classis`,
`launchctl list classis`, `sc query classis`. Where a
[process account](#managed-processes-under-a-process-account) is registered, the
second service is `classis-agents` on every platform.

The name is fixed when the program is built, which is why there is no flag to
change it. A second Client on one host is a second build with its own product
name, and it therefore has its own service, its own package and its own
directories — nothing about it collides with the first.

Where a platform has a second, human-readable name, it is **Classis Agent**.
That is the Windows services list; systemd shows the unit name as its
`Description`, and a launchd job has no name besides its label.

### Where the service's logs are

A Client started by the service manager writes its own log to
**`<state_dir>/logs/`** on every platform, one file per day, seven days kept:

```text
<state_dir>/logs/supervisor.2026-08-09.log
```

**On Windows this is the only copy there is** — the SCM discards a service's
stderr, so `sc query` telling you the service will not start is all the platform
itself offers. On Linux and macOS the same lines are also in
`journalctl -u classis` and Console/`log show`; the file is written anyway
so the answer to "where are the logs" is the same everywhere, including in a
container where neither exists.

Running the Client **in the foreground writes no file** — stderr is right there
in front of you.

The `[logging]` section moves it, changes how many days are kept, or turns it
off:

```toml
[logging]
dir = "/var/log/opamp"   # default: <state_dir>/logs
keep = 7                 # daily files kept, then deleted
enabled = false          # write nothing; for a host whose platform already collects stderr
```

`keep = 0` is **refused at startup**. It is a retention bound, not a switch — on
a fleet host the unbounded setting is the one that eventually fills a disk, so
turning the log off is spelled `enabled = false` and cannot be reached by typing
a zero. If the directory cannot be written, the Client says so and runs anyway:
a monitoring agent that refuses to start because of its own log file has turned
a diagnostic into an outage.

Where a process account is registered, a `dir` the process account's group
passes through or writes is refused the same way, and the Client runs without a
log file: the state directory itself, the Supervisors' root or anything above
it, a Supervisor's directory or anything beneath it, and a path named with `..`.
A directory beneath the state directory is kept the Client's alone, `0700`. The
default `<state_dir>/logs` stays usable where `supervisor_dir` is the state
directory itself, where no Supervisor can be named `logs`.

This is a different thing from the Client's own telemetry (`ReportsOwnLogs`),
which ships log records to a destination the **Server** offers. That needs a
Server it can already reach — which is exactly what a bad `supervisor.toml`, a
host that is not enrolled, or a refused endpoint does not give it. The file on
disk is what explains those.

The Windows services list has a **Description** column beside that name, and it
is a separate field that nothing fills on its own — a service can carry a
display name and still show an empty description, which is what this one did. It
now reads **Classis Agent for Windows** — the display name beside it says
what the service is, and the description says what it is for.

Both are set right after the registration, with `sc.exe config` and
`sc.exe description`.

The service is registered against `current/supervisor` — a pointer, not a
version directory — so switching versions never re-registers it. Where the
layout and the data live on each platform, and what an uninstall leaves behind,
is [On-disk layout](#on-disk-layout).

After a crash the service manager restarts the service; after an explicit stop
it stays down. A known platform gap: on macOS `service status` is advisory and
`install` does not auto-start.

### Windows needs an elevated shell, and says so before it writes

Registering a machine-wide service needs Administrator, and a running process
cannot raise its own rights — there is no UAC prompt to be had from inside a
command that has already started. So `service install` asks the service control
manager up front whether this process may register a service at all, and stops
with a message naming the fix if it may not:

```sh
C:\> classis service install
the Windows service control manager denied access: registering a machine-wide service needs
Administrator, and a running process cannot raise its own rights. Open a shell with "Run as
administrator" — from PowerShell, `Start-Process powershell -Verb RunAs` — and run this command
again. Nothing has been installed or written.
```

That the check comes _before_ the first write is the point of it:
`%ProgramData%` lets an ordinary user create folders, so an install refused only
at `sc create` had already staged a version directory and pointed `current` at
it, leaving half an install behind. `uninstall`, `start`, and `stop` write
nothing beforehand and simply report the manager's own refusal.

## Enrolling the host

A host belongs to exactly one **Space** of its Server, and it joins by enrolling
with that Space's **enrolment key**, `cle1_<space>_<secret>`. The key names the
Space, so no command takes the Space a second time. It is reusable and admits
the host at once: no operator approves a request. Treat it as a secret. This
build of the Server has no operator command that creates a Space or shows or
rotates its key, so this page takes the key as given: you have it from whoever
runs the Server.

A Client without a `state.json` runs nothing. Installing it registers the
service but neither starts it nor lets it start at boot; `enrol` is what
writes `state.json`, and it starts the service.

```console
$ sudo classis enrol https://fleet.example.com:4320 cle1_lab_…
enrolled in the space lab as 0193a6f0-…
  state file: /var/lib/classis/state/state.json
  the service is started, and starts at boot
```

`enrol` takes the Server's base URL and the key, and nothing else. The base URL
is `https://`, or `http://` to `127.0.0.1` or `::1` alone, with no credentials,
query or fragment; a path in front of the routes, as a reverse proxy may add
one, is kept. `/v1/enrol` and `/v1/token` are resolved against it. The Client's
OpAMP connection goes on dialling the `endpoint` of `supervisor.toml`, which
`enrol` does not touch. In order:

1. It reads the configuration the way a run does, and takes its trust from
   `[tls] ca_file` ([`[tls]`](#tls)). `--config` and `--state-dir` say which
   file and which state directory; without them, where a system service is
   registered, it takes the configuration and the state directory that
   registration names.
2. It refuses a host that holds a `state.json` already, before it asks the
   Server anything: the host is enrolled, and
   [`revoke`](#taking-the-host-out-revoke) ends that first.
3. It registers the host with the key as its bearer credential (RFC 7591, at
   `/v1/enrol`). The Server answers with the host's **Device ID**, its
   `client_id`, and a client secret, and names the Space the key belongs to.
   With those it asks `/v1/token` for its first access token (the client
   credentials grant, the secret sent as HTTP Basic). A refusal by the Server,
   at either step, writes nothing.
4. It writes `state.json` once.
5. Where a system service is registered for that state directory, it hands
   `state.json` to the account the service runs as, lets the service start at
   boot, and starts it. Where none is, it says so, and `supervisor run` runs
   the Client in the foreground. A service at user scope names no state
   directory `enrol` could match it on: start it yourself afterwards, with
   `supervisor service start --user`. If a step after the file is written
   fails, the message says that the host is enrolled and what is left to do.

### `state.json`

The file lives in the state directory, owner-only (mode `0600` on Unix), and is
never written through a link:

| Field           | Holds                                                            |
| --------------- | ---------------------------------------------------------------- |
| `endpoint`      | the base URL given to `enrol`                                    |
| `space`         | the Space, as the Server returned it                             |
| `device_id`     | the host's Device ID, the `client_id` the Server gave it         |
| `client_secret` | what replaces the access token without losing the Device ID      |
| `access_token`  | the host's credential, which every request to the Server carries |

Only `access_token` ever changes, and only as
[Renewal](#when-the-token-is-replaced) describes. The Client never formats
either secret into its log. A copy of this file lets whoever holds it act as the
host until a new token is issued, so back it up and move it as you would a
private key.

### What the Client sends

- **On every OpAMP exchange, on both transports**, the header
  `Authorization: Bearer <access_token>`: on the WebSocket upgrade, on every
  plain-HTTP request, and on the connection that verifies an offered setting.
- **On every package download** from the Server's own origin
  ([Where a download may come from](#where-a-download-may-come-from)).
- **On its own telemetry**, only to a destination that has the Server's own
  origin ([Its own telemetry](#its-own-telemetry)). The token never reaches
  another collector.
- **Nothing in a URL, and no TLS client certificate.**

Every Agent on the host, the Client's own and each Supervisor's, speaks under
this one token. The Server derives the host from it, so a host never states an
identity of its own.

### When the token is replaced

The Client keeps no expiry and never renews ahead of time. It asks for a new
token in one case: a `401` whose Bearer challenge says `error="invalid_token"` —
on an OpAMP connection or on a package download. It then asks `/v1/token` with
its client credentials, rewrites `access_token` in `state.json` and nothing else
in it (the file is replaced whole, by a rename, and keeps its owner and mode),
and goes on:

```text
WARN the Server refused the access token (invalid_token); requesting a new one
INFO a new access token is in force
```

A new token ends the one before it, so the Server closes the WebSocket sessions
the old token admitted, with close code 1008, and the Client reconnects with the
new one. Any other `401` — no credential, a malformed request, an unknown
client — asks for no new token: the Client logs `admission failed` and retries
with its usual backoff. If the Server refuses the client credentials too, the
Client logs `cannot get a new access token` and tries again after a backoff.

### Starting without an enrolment

A Client that finds no `state.json` — as a service or in the foreground —
refuses to start, logs `the Client does not start`, and names the command:

```text
this host is not enrolled: /var/lib/classis/state/state.json does not exist, and the Client runs nothing without it. Enrol it with `supervisor enrol <base-url> <key>`
```

A `state.json` that is not the file `enrol` writes is refused the same way, by
name and without quoting what it holds.

### Taking the host out: `revoke`

```console
$ sudo classis service stop
$ sudo classis revoke
Revoke this host? Everything in /var/lib/classis/state is deleted: its enrolment, its Agents' identities and its logs. The Server is not told, and a host enrolled again is a new one. [y/N]
```

`revoke` is local: it never contacts the Server. It acts on the same state
directory `enrol` found, in this order:

1. It refuses while the service runs: stop it first with `service stop`, so that
   nothing writes to the directory while it is deleted. `--force` does not
   override this.
2. It asks for a confirmation, which needs a terminal on stdin; `--force` skips
   it, and without a terminal and without `--force` it changes nothing.
3. It keeps the registered service from starting at boot again.
4. It deletes everything in the state directory, `state.json` first: the
   Agents' identities, the connection settings, the high-water marks, the logs,
   the Supervisors' directories. `--keep-cache` spares `config/` and
   `packages/`, which a re-enrolled host would only download again; it is an
   exception taken out of the default, so whatever the Client keeps there in
   future is deleted under the flag too. A `supervisor_dir` or a `[logging] dir`
   placed outside the state directory is not touched.

```text
revoked: everything in /var/lib/classis/state is deleted
  the service will not start at boot until this host is enrolled again
```

The Server is not told, so it still holds what it recorded for the host. Enrol
again, and the host has a new Device ID and its Agents new `instance_uid`s: the
Server sees new Agents, not the old ones come back. `supervisor.toml` is not in
the state directory and stays.

## On-disk layout

Where a managed host keeps things: the program, its configuration, its state,
and the Agents it supervises. One structure everywhere — only the root differs,
and on two platforms there are two of them.

### The shape

Two roots, and everything hangs off them:

```text
<layout-root>/                       the program, replaceable
  versions/<product>-<version>-<commit>/supervisor
  current -> versions/<product>-…/

<data-root>/                         everything a reinstall cannot recreate
  supervisor.toml
  state/
```

The split is worth reading twice, because it is the rule the rest of this page
follows. The **layout root holds what a package can put back**: program files,
one directory per version, and a pointer at the live one. The **data root holds
what nothing can put back**: the enrolment that makes this host a member of the
fleet, the identity it reports to the Server, the configuration an operator
wrote, and the configuration the fleet sent.

Directories are named after the **product**; the file inside is the **program**.
They are not the same name and are not meant to be — two products built from
this source differ in the first and share the second, which is what lets one
published release update both.

### Where the roots are

| Platform | Scope  | Layout root                               | Data root            |
| -------- | ------ | ----------------------------------------- | -------------------- |
| Linux    | system | `/opt/<product>`                          | `/var/lib/<product>` |
| Linux    | user   | `$XDG_DATA_HOME/<product>`                | _the same_           |
| macOS    | system | `/Library/Application Support/<product>`  | _the same_           |
| macOS    | user   | `~/Library/Application Support/<product>` | _the same_           |
| Windows  | system | `%ProgramData%\<product>`                 | _the same_           |
| Windows  | user   | `%LOCALAPPDATA%\<product>`                | _the same_           |

On Linux, `$XDG_DATA_HOME` falls back to `~/.local/share` when it is unset.

`--root` overrides the layout root and, given alone, collapses both into the one
directory it names — whose file labeling and permissions are then yours to
manage. `--data-root` names the other half. A packaged install passes neither.
No path is ever compiled in.

The MSI's installation folder, `C:\Program Files\<product>` by default, is not a
root. It holds the delivered program alone; the MSI then runs `service install`,
which builds the layout and the data under `%ProgramData%\<product>`.

### Why two roots, and only sometimes

Only Linux at system scope splits, and it has a reason the other platforms lack.

**Linux at system scope** splits because of SELinux. A file created under
`/var/lib` carries a type that an enforcing policy will not let the init system
execute — the service would register cleanly and then die at its first start.
`/opt` carries a type the policy treats as an entry point for third-party
software, and files staged there later inherit it. This is why an update can put
a new version in place without any relabeling step.

**Everywhere else there is one root**, because that reason does not apply: macOS
has no equivalent restriction, and a user-scope service runs in the user's own
context. **Windows keeps one root too, whether the MSI installed it or not.**
The service's own account must be able to write the layout, because the
self-update stages into it. Granting a low-privileged account write access to a
tree under `Program Files` that it executes from would be a privilege-escalation
surface. So the layout stays under `%ProgramData%`, beside the data, and the
MSI's folder under `Program Files` holds only the program it delivered.

### Inside the layout root

```text
<layout-root>/
  versions/
    <product>-1.2.3-a1b2c3d/
      supervisor              (supervisor.exe on Windows)
      manifest.toml           the full version string and the program's hash
    <product>-1.2.2-9f8e7d6/
  current -> versions/<product>-1.2.3-a1b2c3d/
```

Every version sits beside the ones before it, and `current` points at the live
one. The service is registered against `<layout-root>/current/supervisor`, never
against a version directory — which is why switching versions never re-registers
the service.

The version part of a directory name is the plain `MAJOR.MINOR.PATCH`; a
pre-release suffix is not in the name. The trailing part is the commit the build
came from. `current` is a symlink on Linux and macOS, and a directory junction
on Windows, where junctions need no special privilege.

### Inside the data root

```text
<data-root>/
  supervisor.toml           the file you edit
  server-ca.pem             the copy of the answered CA, if the questionnaire wrote the file
  state/
    state.json              the host's enrolment: where it enrolled, its Device ID and credentials
    instance-uid            this host's identity to the Server
    remote-config.pb        the last configuration it received
    connection-settings.pb  Server-offered settings, if any
    installed-package.json  the update it last installed, if any
    package-high-water.json the highest version installed per Agent type — see "A Supervisor never goes back"
    packages/               staging for its own update
    logs/                   the service's rotating log
    supervisors/            one directory per Agent — see below
```

`state.json` and `instance-uid` are the files that matter most. `state.json` is
what the host presents to the Server; without it the Client runs nothing, and
only `enrol` makes another, with a new Device ID ([Enrolling the
host](#enrolling-the-host)). `instance-uid` is what makes this host _the same_
Agent across restarts and upgrades; delete it and the Server sees a host it has
never met, while the old row lingers. Nothing regenerates either, which is why
the data root survives an uninstall.

The state directory is the one `--state-dir` names, else the one the existing
service registration names, so an upgrade never moves it. A first install takes
`state_dir` from the configuration file when that names an absolute path beneath
the data root or the layout root, and refuses one elsewhere: the service's
account may rewrite the file, and the install hands the state directory over to
that account. Left alone, it is `<data-root>/state`.

Logs rotate daily and seven files are kept. On Linux and macOS the service's
output also reaches the system journal; on Windows the file is the only copy,
because the service manager discards a service's console output.

### One directory per Agent

Every `[[supervisor]]` block gets a directory of its own, holding everything
about that Agent:

```text
state/supervisors/<name>/
  instance-uid              this Agent's own identity
  remote-config.pb          the last configuration it received
  installed-package.json    the package its program currently is
  config/                   one file per Configuration it matched
  program/                  its program
  program/tree/             …or the whole unpacked package, for a multi-file one
  packages/                 staging its downloads pass through
```

Two things follow from keeping them together.

**The staging directory sits beside the program**, so installing an update is a
rename inside one filesystem rather than a copy across two. A rename either
happened or did not; a copy can be interrupted halfway.

**Removing an Agent removes the directory**, whole. Take a block out of the
configuration and the Client stops the process and deletes everything above —
program, packages, configuration and identity. A directory that no block names
is reported at startup and never deleted on its own, so a typo in a name does
not destroy an Agent's identity.

Before it deletes a removed Agent's directory, the Client renames it to a
tombstone, `.purge-<name>-<hex>`, beside the others, so an Agent added again
under the same name starts in a fresh directory. `<hex>` is 17 lowercase
hexadecimal digits or more; a directory named alike with a shorter suffix, such
as `.purge-backup-20241001`, is no tombstone. A tombstone that could not be
deleted — a file held open, or one the process account wrote that the second
service could not remove — stays, with a warning, and nothing in it is used
again. The Client removes it again at the next start, beside the start, and with
the next removal of a Supervisor. Where a process account is registered, each
try waits for the second service as long as a purge does; a try that does not
reach it warns, and the next start or removal tries again. Until it is gone,
each startup warns about it. No other directory that no block names is touched.

`config/` is what `${config_dir}` expands to in a process's arguments, which is
how a program is pointed at its own configuration without anyone writing an
absolute path into a block. Where a Configuration carries a role rather than
configuration text, it is written here too and named in a `.supplementary` file
beside the entries, so a program is not started with content it is only meant to
read.

### What the packages add

The `.deb` and `.rpm` deliver exactly one file and let the program lay out the
rest:

```text
/usr/libexec/<product>/supervisor    the payload, off PATH
/usr/bin/<product>  ->  /opt/<product>/current/supervisor
```

The command on your `PATH` resolves through `current`, so it is always the
running version rather than whichever one the package delivered. The payload
keeps a separate copy under `/usr/libexec` because the package manager needs a
file it owns — the layout under `/opt` is the program's, not the package's.

The MSI delivers its program into its installation folder and then runs the same
install the command line would, so a Windows host ends up with the same
structure by a different route.

### What an uninstall leaves behind

| What you do                 | What goes                                                                                                                      | What stays                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `service uninstall`         | the service registration, and the second service's where a process account is registered; on macOS the directory of its socket | everything on disk                                                       |
| `apt remove` / `dnf remove` | the registration, the layout root, the `PATH` symlink                                                                          | the data root: configuration, state, every Agent's identity              |
| `apt purge`                 | all of the above                                                                                                               | nothing the package made                                                 |
| MSI uninstall               | the registration and the installation folder                                                                                   | everything under `%ProgramData%\<product>`: layout, configuration, state |

The process account stays in every case, after `apt purge` too: you created it,
and you delete it once nothing else uses it. On Windows an uninstall that did
not hold the install lock leaves `HKLM\SOFTWARE\classis\WithdrawalPending`
in place and says so; the next `service install` or `service uninstall`
completes it (see [Uninstalling](#uninstalling)).

The pattern is the same everywhere: **removing the program is not removing the
host from the fleet.** A reinstall over a surviving data root comes back as the
same Agent, with the same identity and the same enrolment, and the Agents it
supervises come back as themselves too. What ends the enrolment is
[`revoke`](#taking-the-host-out-revoke), which deletes what the state directory
holds.

This is also why the data root is not under `Program Files` on Windows or under
`/opt` on Linux: an uninstall clears those, and a host's identity and the
configuration someone wrote are not things an uninstall should quietly take with
it.

### Persisted connection settings override the file

`<data-root>/state/connection-settings.pb` takes precedence over `endpoint` and
the intervals in `supervisor.toml`. Delete it to revert to what the file says.

## Configuration reference

The full annotated example is
[`config/supervisor.toml`](../../config/supervisor.toml). Every key is shown
below with its default. Every key is optional. What the host is to its Server —
its Space, its Device ID, its credentials — is not in this file but in
`state.json`, which `enrol` writes ([Enrolling the host](#enrolling-the-host)).
An unknown key fails startup rather than being ignored, with one exception: a
leftover [`[auth]`](#a-leftover-auth) is ignored with a notice.

### Top level

| Key                       | Default                           | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `endpoint`                | `"ws://127.0.0.1:4320/v1/opamp"`  | The Server's OpAMP endpoint. The scheme selects the transport: `wss://` for WebSocket, `https://` for polling, both TLS 1.3. `ws://` and `http://` are accepted only when the host is the IP literal `127.0.0.1` or `::1`; to any other host, the name `localhost` included, the Client refuses to start.                                                                                                                                                                                                                                                                                                                                                                                             |
| `name`                    | `"Supervisor Agent"`              | The Agent's `service.instance.name` — your name for _this_ Client, shown in the fleet view and matchable by a Selector. Its `service.name` is the constant type `supervisor`, the same on every host.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `poll_interval_secs`      | `30`                              | How often the plain-HTTP transport polls. Ignored on WebSocket.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `heartbeat_interval_secs` | `30`                              | Heartbeat interval on WebSocket. `0` disables heartbeats and undeclares the capability; on plain HTTP every poll already is the periodic report.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `max_message_size_bytes`  | `67108864` (64 MiB)               | The largest OpAMP message sent or accepted, in either direction — including on the Supervisor Endpoint. A message past it is never sent, and an oversized one from the Server is refused.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `state_dir`               | `"client-state"`                  | Where the Client persists the host's enrolment (`state.json`), its own Agent's identity, its remote configuration, and any Server-offered connection settings. A self-update artifact is streamed here first, so it needs room for one agent binary.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `supervisor_dir`          | `<state_dir>/supervisors`         | Where the per-Supervisor directories live. Set it when the programs must not live where the state does — `/var/lib` is often mounted `noexec`, and sized for state rather than for a few hundred megabytes of Collector. Where it is the state directory itself, a Supervisor named after what the Client keeps there — `instance-uid`, `config`, `packages`, `logs`, `supervisors` — is refused at startup and in a set the Server offers, and no Supervisor's directory may be the state directory or hold it. Outside the data root, the layout root and the state directory, `service install` creates and hands over nothing for it: create it yourself, writable by the service's account only. |

> **Moving `supervisor_dir` on a running host leaves the old tree behind**,
> `instance-uid` included, so every Supervisor re-registers as a **new** Agent
> on the Server. Nothing migrates automatically.

### `[attributes]`

Operator-defined attributes reported by every Agent this Client presents, so the
Server's Selectors can target them. They are reported as non-identifying
attributes, and they never override what the code reports under the same key; a
Managed Process never overrides them.

```toml
[attributes]
env = "prod"
region = "eu-central"
```

These describe the **host**, and every Agent this Client presents carries them —
including a fresh one, in its very first message, before the Server has ever
seen it.

To tag **one** Agent among several on a host, use a Server **label** instead
(`PUT /api/v1/agents/<uid>/labels`): it is keyed by that Agent's `instance_uid`,
matched by the same Selectors, and takes effect at once without editing a file
on the host. A label on the Client's own Agent holds for every Agent of that
Client, below their own labels. A block's own `[supervisor.attributes]` table
used to do this and no longer exists; a block carrying one fails at startup with
that sentence.

Every Agent additionally reports, without configuration, everything the protocol
names to describe an Agent and where it runs: `service.name`,
`service.instance.name`, `service.instance.id`, `os.type`, `os.name`,
`os.version`, `os.description`, `host.name`, `host.arch`, and `host.id` — plus
`service.version`, which for the Client's own Agent is the Client's baked-in
version and for a Supervisor-backed Agent is whatever the Managed Process
reports about itself.

A Managed Process states only its own `service.*` attributes, such as its
version, which replaces what the Supervisor reports. It never states the Agent's
type: `service.name` is the Supervisor's, taken from the block's `service_name`
or the program's file name, and a type the process reports, such as a
Collector's `dist.name`, is dropped with a warning in the Client log that names
the Supervisor, both values and `service_name`. Everything else it reports is
dropped — `host.*`, `os.*` and `supervisor.*`, and keys in a namespace of its
own such as a Collector's `agent_description.non_identifying_attributes` and
resource attributes. Where the Agent runs is the Supervisor's statement, since
it decides which Selectors match and which artifact is offered. Within
`service.*` the process cannot restate `service.instance.id`,
`service.instance.name`, `service.namespace` while `service_namespace` is set,
or a key `[attributes]` sets. To tag a Collector, use a Server label, or
`[attributes]` for the whole host.

The first two are the pair to keep apart: `service.name` is _what_ this Agent is
— the type, shared by every Agent of that kind — and `service.instance.name` is
_which_ one it is, the name you gave it. Neither is settable through
`[attributes]`: a table entry under either key is ignored, since the Supervisor
already reports both.

An attribute the host cannot answer is **left out, never reported empty** — a
container without `/etc/machine-id` reports no `host.id` at all rather than a
blank one a Selector could match. So a Selector on `host.id` reaches exactly the
hosts that have one.

One attribute is configured rather than detected, because only an operator knows
it — the protocol asks for `service.namespace` "if it is used in the environment
where the Agent runs":

```toml
service_namespace = "telemetry"
```

Unlike `[attributes]`, it _identifies_ the Agent rather than tagging it, which
is where the protocol puts it. Leave it out and nothing is reported.

### `[tls]`

```toml
[tls]
ca_file = "ca.pem"             # trust: replaces the built-in roots
```

`ca_file` is the trust override for `wss://`/`https://` endpoints — the reverse
proxy in front of the Server — whose certificate comes from a private CA, and it
replaces the default trust. Without
it the Client trusts the built-in web PKI roots on `wss://` and the system's
trust store on `https://`. Trust is this file's, never a Server's instruction.
`enrol`, the OpAMP connection, every download and the Client's own telemetry
all use it.

The Client presents no TLS certificate. What admits it is the access token it
holds in `state.json` ([Enrolling the host](#enrolling-the-host)), and nothing
in this file says who it is. A `cert_file` or `key_file` left in `[tls]` by a
release that admitted hosts by certificate is an unknown key, refused at startup
like any other: delete them.

### A leftover `[auth]`

The Client has no credential to configure: what it presents to the Server is
the access token in `state.json`, which `enrol` writes, and it reads none from
this file. A `supervisor.toml` written for an earlier release may still hold an
`[auth]` section. The Client ignores it, whatever keys it holds, sends nothing
from it, and says so once at startup:

```text
WARN [auth] is ignored: this Client reads no credential from the file, and nothing from the section is sent — it can be deleted from the file config=/var/lib/classis/supervisor.toml
```

It is not refused, because a Client the Server updates starts with the file it
already has and nobody at the host. Its values stay masked in the effective
configuration the Client reports. Delete the section when convenient.

### `[packages]`

```toml
[packages]
self_update = true
archive_key = "the key an encrypted .7z was packed with"
```

| Key           | Meaning                                                                                                                                                                                                                                                                       |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `self_update` | Consent for the Server to replace this Client's own binary. `true` by default, and an absent key or `[packages]` section is the consent; `false` withdraws it, and the Supervisors keep taking their packages. See [Updating the Client itself](#updating-the-client-itself). |
| `archive_key` | Opens an encrypted `.7z` artifact. One secret for the fleet — a single archive serves every Agent. The Server never learns this key; the artifact stays encrypted wherever it is stored and is opened only on the host that runs it.                                          |

Note what is _not_ here: which artifact a Supervisor receives is the Server's
decision, expressed as the Deployment that holds the package, never a key in
this file — and where it comes from is not configurable either.
`allowed_sources` no longer exists, and a file that still names it fails startup
naming the key; remove it.

#### Where a download may come from

A download goes to this Client's own Server origin — the scheme, host and port
of its OpAMP endpoint, `wss` mapped to `https` (and `ws` to `http`, which the
endpoint may only be on the loopback) — and nowhere else. Every artifact is
uploaded to the Server, so there is no other source to allow.

- **A path is resolved against that origin.** It is what the Server offers for
  every artifact.
- **An absolute URL is accepted only when its origin is that origin.** Any other
  is refused without a byte fetched and reported `InstallFailed`, naming its
  origin.
- **Redirects are followed up to 5**, and only while every hop stays on that
  origin. A hop that leaves it fails the download, naming the origin it pointed
  at.
- **The offer's headers, if any, go only to that origin**, and are never logged.
- **The access token is presented there**, which is the only place a download
  goes: every request to that origin carries `Authorization: Bearer`, and a
  header the offer names `Authorization` is dropped, so nothing offered
  replaces it. A `401` whose Bearer challenge says `error="invalid_token"` asks
  for a new token ([Enrolling the host](#enrolling-the-host)), and the download
  goes once more with it.
- **A `429` or `503` with `Retry-After` from the Server's own origin is waited
  out**. That origin answers so when its rate limit is reached.
  Each wait is the `Retry-After`, at least 1 and at most 60 seconds, and the
  asking stops 30 minutes after the download's first request; the status stays
  `Downloading` meanwhile, and a shutdown ends it. Past that, or for such an
  answer from any other host, the download fails and is reported
  `InstallFailed`.

Every download is TLS 1.3, on this Client's trust: `[tls] ca_file` when it is
set, the system's trust store otherwise.

Every install path writes `self_update` into the file it creates:
`service install --no-self-update` and the MSI's cleared checkbox, or
`SELFUPDATE=0` on a silent deploy, write `false`; the `--interactive`
questionnaire, which does not ask, and every other path write `true`.

A `[self_update]` section, which earlier releases wrote, fails startup with a
message naming `[packages] self_update` as its replacement. Replace it by hand
before such a host takes this release: `enabled = false` becomes
`self_update = false`, and `package` has no replacement.

## Supervisors: putting a process under management

Each `[[supervisor]]` block runs one Supervisor managing one local process, and
appears to the Server as its own Agent. Without any block the Client presents
itself as a single Agent and manages nothing.

Two plugin types ship today.

**Both know nothing about the agent they run**, so their blocks say everything:
`collector` for an OpenTelemetry Collector, and `command` for any other process
— a **Foreign Agent** that speaks no OpAMP.

**A wrapper**, when a build carries one, knows one agent's program, its layout
on each platform and its invocation, so its block says which host runs it and
little else.

A new kind of process means a new plugin, not a change to the core.

### The Server can manage the set

The `[[supervisor]]` blocks are the fleet-manageable half of `supervisor.toml`.
A Configuration typed for the Client itself — `service_name = "supervisor"` —
carries `[[supervisor]]` blocks in its body, and a Client its Deployment
releases it to applies them as its new set:

- **Only the blocks are read.** Every other top-level key in the offered
  document is ignored — the endpoint, the trust, the state directory
  stay the host's, and can never arrive over the wire. You may roll out a full
  `supervisor.toml`-shaped document; exactly its supervisor half takes effect. A
  duplicate `name` fails the offer, as it would fail the file.
- **The apply is a diff, keyed by `name`.** Removed and changed Supervisors are
  stopped, the merged file is written, changed and added ones are started from
  it. An unchanged Supervisor's process is not touched — a fleet-wide change to
  one collector does not cycle its neighbours.
- **A removed Supervisor is purged**. Once the rewritten file no longer names
  it, its whole directory `<supervisor_dir>/<name>/` is deleted — identity,
  written configuration, staged packages, and the Client-owned program — by way
  of a tombstone ([one directory per Agent](#one-directory-per-agent)). A
  changed Supervisor restarts under its name and keeps its directory; the
  program itself is never touched. Removal is destructive on the host: re-adding
  the same name later starts a genuinely fresh Agent, restoring service, not
  history.
- **`supervisor.toml` stays the single truth.** The blocks are written into the
  file itself, surgically: your comments, ordering, and formatting outside them
  survive. A Client restarting offline starts the Server-delivered set, because
  it is in its file.
- **The outcome is a status, not a silence.** The Client acknowledges
  `APPLYING`, then `APPLIED` once the file is written and the starts are issued
  — or `FAILED` with the reason when the offer does not parse, a block does not
  validate against this host's globals, or the write fails (then nothing is
  applied and the running set stays in force). A body that is not TOML — say, a
  Collector YAML typed for the Client by mistake — is refused the same way.

A Client whose Server never rolls such a Configuration out runs its locally
written blocks exactly as before. Note that once one applied, the Server's set
is authoritative, unless `server_manages_set = false`
([Keeping the Supervisor set on the host](#keeping-the-supervisor-set-on-the-host)):
a later local edit to the blocks stands only until the next rollout act
overwrites it.

### Keeping the Supervisor set on the host

A host whose Supervisors only its operator should add, change or remove takes no
set from the Server:

```toml
[supervisors]
server_manages_set = false   # default true
```

The key is read from this file only, and the Server never writes
`[supervisors]`. A change takes effect when the Client next starts.

- **What the Server sees.** The Client's own Agent declares neither
  `AcceptsRemoteConfig` nor `ReportsRemoteConfig`, so the Server offers it no
  set, whatever a rollout is aimed at. Everything else it declares stays,
  self-update included: it still reports its status, its health and this file as
  its effective configuration, takes connection settings, and takes a signed
  Client package where `[packages] self_update` consents. A set that arrives
  anyway is not stored, not applied and not answered; the Client logs one
  warning per hash.
- **The blocks stay yours.** Nothing in this file is rewritten when you set the
  key. Every `[[supervisor]]` block runs as written, **including blocks a set
  the Server delivered earlier wrote**, and from then on only you change them.
  Review the blocks before you switch the key off.
- **What happens to a set delivered earlier.** At start the Client deletes the
  `remote-config.pb` in its `state_dir` first, then the unchanged copies of that
  set's entries in `<state_dir>/config/`, and logs the stored hash. Nothing runs
  on those files, so one that cannot be deleted is a warning and the Client
  starts; it is not reported either way.
- **Supervisors are not affected.** Each Supervisor's Agent keeps taking its own
  configuration unless it is named in `remote_config_disabled`. With both set,
  the Server can no longer remove a listed Supervisor and add the same agent
  under a name that is not listed.
- **What the key holds, and what it does not.** It holds against the Server only
  while every Supervisor whose configuration language can run commands as the
  Client's account — a Telegraf `inputs.exec`, an Icinga `CheckCommand`, the
  configuration a `command` Supervisor's program reads — is named in
  `remote_config_disabled`. Otherwise the Server can configure such a Supervisor
  to rewrite this file, and the key changes at the next start. Where a
  [process account](#managed-processes-under-a-process-account) is registered,
  those commands run under it, and it cannot write this file. A signed Client
  build can still replace the Client itself where `[packages] self_update`
  consents, and that build reads the key.
- **Switching it back on.** Set the key to `true`, or remove it, and restart the
  Client. Its own Agent declares both capabilities again, reports no hash —
  unless that earlier start warned that it could not remove `remote-config.pb`
  itself — and is offered whatever set is released to it. The first set it
  applies replaces every `[[supervisor]]` block, yours included, and purges each
  Supervisor it removes.

### Switching remote configuration off for one Supervisor

Some agents should not take their configuration from the fleet: one whose
configuration language can run commands, such as Telegraf's `inputs.exec` or an
Icinga `CheckCommand`, or one another system already configures. Name them in
`[supervisors]`:

```toml
[supervisors]
remote_config_disabled = ["otelcol"]   # Supervisor names, by their block's `name`
```

The key is read from this file only. The Server never writes `[supervisors]`, so
a Supervisor set that removes a listed block and delivers it again under the
same name gets a Supervisor that is still listed. Each value must be a valid
Supervisor name, or the Client does not start. A listed name that no block
carries yet is a startup notice, not an error, since the block may arrive later
from the Server. The switch covers Supervisors only: a listed name equal to the
Client's own `name` earns a notice that the Client's own Agent is not covered.
That Agent takes its Supervisor set unless `server_manages_set = false`
([Keeping the Supervisor set on the host](#keeping-the-supervisor-set-on-the-host)).

- **What the Server sees.** A listed Supervisor's Agent declares neither
  `AcceptsRemoteConfig` nor `ReportsRemoteConfig`, so the Server offers it no
  configuration, whatever a rollout is aimed at. It still restarts on command
  and still takes signed packages. A configuration that arrives anyway is not
  stored, not written, not applied and not answered; the Client logs one warning
  per hash.
- **What it runs on.** The files you place in `<supervisor_dir>/<name>/config/`,
  under the names its kind reads: any unroled file for `collector`, and for
  `command` whatever its `args` name. Roles go into `.supplementary`, one
  `<file> <role>` per line. Nothing else writes into that directory while the
  switch is on. Without such a file a `collector` waits and says so.
- **The block stays yours.** A delivered block for a listed Supervisor must
  repeat its running block exactly, every key included, whatever
  `delivered_args` and `delivered_env` allow. A delivered block that adds a
  listed Supervisor carries only `type`, `name` and the key naming its program
  where the kind does not name its own: `binary` for `collector`, `command` for
  `command`, and nothing more for a wrapped kind. Otherwise the whole set is
  refused before anything stops. Any other key would be remote configuration by
  another route: a Collector reads a whole configuration from `--config=yaml:…`
  or an environment variable.
- **What happens to a configuration delivered earlier.** When a listed
  Supervisor starts, the Client deletes the `remote-config.pb` in its directory,
  and from `config/` each file that stored configuration wrote whose content is
  unchanged, `.supplementary` included. A file you edited since, or added
  yourself, stays; the log names the kept files. A `remote-config.pb` that
  cannot be read is deleted and `config/` is left as it is, with a warning that
  it may still hold files the Server wrote. The Supervisor then reports no
  configuration status and no hash. When a file that has to go cannot be read or
  deleted, the Supervisor does not start; at Client startup that stops the whole
  Client with an error naming the Supervisor, so it fails closed rather than run
  the Server's configuration under the switch.
- **Switching it back on.** Remove the name and restart the Client. The Agent
  declares both capabilities again, reports no hash, and is offered whatever is
  released to it. The first configuration it stores replaces every file in
  `config/`, yours included, so move anything you want to keep before switching
  back.

The switch binds a name, not an agent: while the Server manages the set, it can
remove a listed Supervisor and add the same agent under a name that is not
listed. Set `server_manages_set = false` as well to close that. A change to the
list takes effect when the Client next starts.

### Keys every block accepts

| Key                    | Default                      | Meaning                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`                 | —                            | `"collector"` or `"command"` — one section each below. Required.                                                                                                                                                                                                                                                                                                                                           |
| `name`                 | —                            | This Agent's `service.instance.name` — your name for it — and the directory name it owns. Required; 1–32 lowercase letters, digits, and `-`. Must be unique in the file. A Managed Process can never overwrite it.                                                                                                                                                                                         |
| `service_name`         | the program's file name      | This Agent's `service.name`: the Agent **type** it presents. A Managed Process never overrides it: a type the process reports — a Collector with the `opampextension` states the `dist.name` it was built with — is dropped and named in a warning, so set this key to present that value as the type. Unlike `name` it may be a reverse FQDN, as the protocol recommends; only an empty value is refused. |
| `endpoint_port`        | `0` (ephemeral)              | The port of the Supervisor Endpoint on `127.0.0.1`. The endpoint always comes up; pin the port when something is meant to connect to it.                                                                                                                                                                                                                                                                   |
| `stop_timeout_secs`    | global `[supervisors]` value | Graceful-stop budget before the process is killed. **Unwrapped kinds only.**                                                                                                                                                                                                                                                                                                                               |
| `apply_grace_secs`     | global `[supervisors]` value | How long a restarted process must survive before a received configuration is acknowledged `APPLIED`. `0` acknowledges on start. **Unwrapped kinds only.**                                                                                                                                                                                                                                                  |
| `retain_previous_secs` | global `[updates]` value     | How long the version a successful update supersedes is kept before deletion. `0` deletes it on success. **Unwrapped kinds only.** See [Package updates: rollback and retention](#package-updates-rollback-and-retention).                                                                                                                                                                                  |
| `program_path`         | unset                        | Where the program sits _inside_ a package that is a whole directory tree, e.g. `bin/fluent-bit`. Unset means the package is a single file. **Unwrapped kinds only** — a wrapper knows its own tree. See [Agents that are more than one file](#agents-that-are-more-than-one-file).                                                                                                                         |

#### Wrapped and unwrapped kinds

`collector` and `command` know nothing about the agent they run, so their blocks
say everything. A **wrapper**, when a build carries one, knows its agent's
program, its layout and its invocation, so its block says which host runs it and
little else — two lines.

A key a wrapper supplies is **refused by name** rather than silently overridden,
and the message says what supplies the value now. The same check runs on a
Supervisor set the Server offers, so a block that would not work is refused
_before_ any running process is touched.

This Client reports the kinds it was compiled with as attributes of its own
Agent — one key per kind, `supervisor.kind.collector = "true"` — so a Supervisor
set can be aimed, by the Selector of the Deployment that holds it, at the
Clients that can actually run it.

The published build carries every kind. A wrapper, when the code base carries
one, is a Cargo feature named after its `type`, so a build for hosts that run
only some of them leaves the others out:

```sh
cargo build --release -p classis-agent --no-default-features --features <type>
```

`collector` and `command` are always there. A block naming a kind the build does
not carry fails startup, and an offered set naming one is refused, as an unknown
`type` naming the kinds that are there. Such a build carries the same Agent type
as the full one, `supervisor`, and a Package is identified by type and version
alone, so its hosts take the full build at their next self-update. Withdraw the
consent on them (`self_update = false` under [`[packages]`](#packages)) and
update them through their own channel. A full-build host that took the smaller
one keeps running it, reporting fewer kinds, or, when one of its blocks names a
kind the smaller build lacks, fails its start and rolls back.

#### Timing is the fleet's, then the agent's

Three keys describe _time_, and all three are the deployment's policy first:

```toml
[supervisors]
stop_timeout_secs = 10   # graceful-stop budget before the process is killed
apply_grace_secs = 3     # how long a restart must hold before an apply is acknowledged

[updates]
retain_previous_secs = 86400
```

A **wrapped kind**, when a build carries one, **corrects them** where its
agent's own behaviour demands it. Only a block of an **unwrapped** kind may
state its own, because there no kind exists to hold the value.

#### Keys that were removed

Each fails at startup with a message saying what to do instead, and each is
refused the same way in a set the Server offers:

| Key                       | What answers it now                                                            |
| ------------------------- | ------------------------------------------------------------------------------ |
| `package`                 | the Server aims packages by a Deployment's Selector                            |
| `accepts_packages`        | every Agent's program path decides                                             |
| `working_dir`             | the process starts in the directory its program lives in                       |
| `reload_signal`           | a kind that knows the agent holds it; an unwrapped agent applies by restarting |
| `[supervisor.attributes]` | a Server label, keyed by the Agent's `instance_uid`                            |

### `type = "collector"`

| Key                | Meaning                                                                                                                                                                             |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `binary`           | The Collector program, named by a bare file name. See [How a block names its program](#how-a-block-names-its-program).                                                              |
| `args`             | Extra arguments, appended **after** the `--config` flags the Supervisor builds — with [placeholder expansion](#path-placeholders).                                                  |
| `[supervisor.env]` | Additional environment for the Collector process — the natural home for a value the config reads as `${env:VAR}`, e.g. a per-host endpoint. Expanded through the same placeholders. |

The Supervisor writes every received config-map entry into its own `config/`
directory under the Configuration's name and passes each **unroled** entry as
its own `--config`; a `supplementary` entry is written but never passed. A
change restarts the Collector so it re-reads them. The version is probed once
with `--version`, so even a Collector without the extension reports one.

Prebuilt Collector distributions are published on the
[collector releases page](https://github.com/open-telemetry/opentelemetry-collector-releases/releases),
one `.tar.gz` per platform — ready to upload as a package as they are; the
[rollout walkthrough](rollout.md#2-build-the-artifact) shows the download and
what to check before uploading. Mind the member name: the binary inside is
called after the distribution (`otelcol-contrib`, `otelcol`), and `binary` must
say the same.

A Collector **with** the `opampextension` reports its own description, health,
and effective configuration through the Supervisor Endpoint instead of being
watched from outside. Of its description, only its `service.*` attributes reach
the Server, and not its type (see [`[attributes]`](#attributes)): the Agent's
type is the block's `service_name`, else the program's file name, and a
`dist.name` that differs is named in a warning in the Client log. The extension
ships only in the Contrib distribution. Pin `endpoint_port` and make sure the
configuration the Server distributes carries the extension pointing at it:

```toml
[[supervisor]]
type = "collector"
name = "otelcol-contrib"
binary = "otelcol-contrib"
endpoint_port = 4321
```

```yaml
extensions:
  opamp:
    server:
      ws:
        endpoint: ws://127.0.0.1:4321/v1/opamp
        headers:
          Authorization: "Bearer ${env:OPAMP_SUPERVISOR_TOKEN}"
        tls:
          insecure: true
service:
  extensions: [opamp]
```

The endpoint admits only the process its Supervisor started: at every start the
Supervisor makes a new token, hands it to the process as
`OPAMP_SUPERVISOR_TOKEN`, and answers any connection without
`Authorization: Bearer <token>` with `401`. Another program on the host
therefore cannot report in the Collector's name. A Collector configuration
without the header loses its own reports, not its supervision.

A Collector **without** the extension needs no `endpoint_port`: the endpoint
still comes up on an ephemeral port, and nothing ever connects to it. The Agent
type is the block's either way: `service_name`, or the program's file name when
it is left out.

```toml
[[supervisor]]
type = "collector"
name = "otelcol"
binary = "otelcol"
service_name = "otelcol"
```

### `type = "command"`

For a Foreign Agent — anything that speaks no OpAMP and is brought into the
fleet by translating its lifecycle into the protocol.

| Key                | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `command`          | The program, named by a bare file name. See [How a block names its program](#how-a-block-names-its-program).                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `args`             | Its arguments, verbatim — apart from [placeholder expansion](#path-placeholders).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `[supervisor.env]` | Additional environment for the process.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `version_args`     | Arguments that make the program print its version, e.g. `["--version"]`. The program is invoked once with exactly these, and the first SemVer 2.0.0 version in its output becomes the Agent's `service.version`. Opt-in, because a Foreign Agent's version flag is its own convention. **They are also the preflight**: a package's staged program is run with them before what runs is stopped, and a non-zero exit refuses the package with the program's own message — so a build this host cannot run costs a refusal instead of a stop, a swap, a failed start and a rollback. |

The process starts in **the directory its program lives in** — this Supervisor's
own `program/`, or the tree root for a tree package. There is no `working_dir`
key: the old default was whatever directory the service manager left this Client
in, usually `/`, which nobody chose.

There is no `reload_signal` key either. Whether a program re-reads its
configuration on a signal is the program's own convention, and a wrong value
here is the one that stays invisible — a signal the process ignores looks
exactly like an apply that worked. An agent under this kind therefore applies a
configuration **by restarting**; an agent whose in-place reload is worth having
is an agent worth a kind of its own.

The Supervisor writes the received configuration entries the same way a
Collector's does, but it cannot know what to do with them — a Foreign Agent
reads its own configuration file. So you point it at the written entry with its
own flag, and the Supervisor restarts the process on a change so it re-reads it:

```toml
[[supervisor]]
type = "command"
name = "fluent-bit"
command = "fluent-bit"
args = ["-c", "${config_dir}/fluent-bit-conf"]
version_args = ["--version"]
[supervisor.env]
FLB_LOG_LEVEL = "info"
```

Here `fluent-bit-conf` is the _name of the Configuration on the Server_ — that
is what the entry file is called.

## How a block names its program

`binary` and `command` take a **bare file name** — `otelcol-contrib`, not a
path. It names a file in `<supervisor_dir>/<name>/program/`, a directory this
Client creates and owns, which is what lets the Server replace what is in it.
Every Agent therefore consents to package updates, and declares
`AcceptsPackages`.

Anything with a path separator in it — `/usr/local/bin/otelcol`, `./x`, `bin/x`
— is a startup error naming the rule, rather than a guess. A program the
machine's package manager installed is not something this Client supervises; to
bring one under management, repack it as a package and deliver it from the
Server.

One thing to know about a bare name: it is **not** searched for in `$PATH`. It
names a file in that one directory, and the first copy arrives by package like
every later one.

The startup log states, per Supervisor, which program it resolved to.

## Path placeholders

A Foreign Agent is told where its configuration is _through its own command
line_, and an absolute path written there drifts the moment `supervisor_dir`
moves or the Supervisor is renamed — silently, because the process then starts
happily on a file nobody writes to. Two placeholders close that, in a
Supervisor's operator-written strings — a `command`'s `args` and
`[supervisor.env]`, and a `collector`'s `args` and `[supervisor.env]`. A wrapped
kind builds its own paths and needs no placeholder:

| Placeholder         | Expands to                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------- |
| `${supervisor_dir}` | `<supervisor_dir>/<name>` — everything this Supervisor owns                               |
| `${config_dir}`     | `<supervisor_dir>/<name>/config` — where the received configuration's entries are written |

Three rules go with them:

- **Any other `${…}` is passed to the process untouched.** A Foreign Agent's own
  configuration language may use the same syntax — Fluent Bit's does — and a
  Client that ate or refused those would break a working deployment to catch a
  typo. The flip side is that a _misspelled_ placeholder (`${config-dir}`) is
  handed over rather than refused, unlike an unknown TOML key.
- **The program itself is never substituted**, in `binary` or `command`. It is a
  bare file name in a directory this Client owns, so there is no path to expand
  — and what a block runs must be readable in the file itself.
- **Expansion happens once, at startup.** None of these paths change while the
  Client runs.

## Package updates

Every Supervisor accepts packages, and no setting turns that off. The Server
offers it one built for the Agent type it reports, released through the
Deployment that claims it, with the signature of the entry for its platform — so
a Supervisor reporting `promtail` is never handed the Collector's binary,
whatever anyone forgot to aim. What then happens on the host:

1. The artifact is **streamed to disk** in that Supervisor's `packages/`
   directory — never held in memory — over TLS 1.3, from this Client's own
   Server origin and nowhere else (see
   [Where a download may come from](#where-a-download-may-come-from)).
2. It is **verified** before anything is unpacked: the content hash, and the
   signature, always. The signature carries the certificate of the Package
   Signer that made it, and it verifies only when a Package Root compiled into
   the Client issued that certificate, the certificate has not expired by this
   host's clock, and the Package Signer's Ed25519 signature covers this Agent
   type, version and hash. An offer without a signature is refused before
   anything is downloaded, and a signature that does not verify refuses the
   artifact.
3. It is **unpacked** when it is a `.tar.gz`, a `.7z`, or a `.zip` — the member
   whose file name matches the configured program, so an upstream release can be
   uploaded exactly as published. An encrypted `.7z` opens with
   `[packages] archive_key`; an encrypted `.zip` is refused, because encryption
   is what `.7z` is for. A bare program artifact is moved into place rather than
   copied.
4. It is **swapped** over the program in `program/`, the process restarted, and
   the new version **health-gated** on `apply_grace_secs` — one that will not
   stay up is **rolled back**.
5. Progress is reported throughout: `Downloading` (with percent and bytes per
   second, repeated every 5 s, so a transfer of hundreds of megabytes stays
   distinguishable from a stuck install), then `Installing`, then `Installed` or
   `InstallFailed`.

**What can be signed today.** The project's release run holds the only Package
Signer, and it signs the Client's own archives alone. A signature made with a
key of your own, as `classisctl package sign` makes one, is refused by the
Server and by every Client. So a package for a Managed Process — the Collector,
`promtail`, any program of your own — cannot be delivered until Package Signers
exist for it; the Client's own update can
([Updating the Client itself](#updating-the-client-itself)).

[The rollout walkthrough](rollout.md) runs this end to end, from packing the
artifact to watching it land.

One limit worth knowing before you plan a rollout: only a **top-level** package
is installed. An addon is something a Supervisor has no way to apply, so it is
refused with `InstallFailed` rather than written over the binary it was meant to
extend.

### A Supervisor never goes back

A signature binds an artifact to its version, but says nothing about how that
version orders against another, and an old build stays validly signed forever.
So before anything is downloaded a Supervisor refuses an offer:

- for another Agent type than its own;
- whose version is not SemVer 2.0.0 (`1.19`, `24.04.1`, `nightly`);
- whose version is below the one its `installed-package.json` names;
- whose version is below the **high-water mark** of its Agent type: the highest
  version this Client has ever installed for that type.

An offer equal to either is taken. Each refusal is reported in the Agent's
package status, naming the offered version and the one it was compared against.

The marks live in `<state_dir>/package-high-water.json`, a JSON object from
Agent type to version, written owner-only. They are kept per Agent type, not per
Supervisor, so every Supervisor of a type on this Client shares one mark, and
removing a Supervisor and adding it back — under its old name or a new one —
does not reset it: the purge deletes the Supervisor's directory and never this
file. A mark rises when a Supervisor reports a package `Installed`, after its
apply grace; a failed apply and its rollback move nothing. At every start each
Supervisor's installed record raises its type's mark again, so a Client upgraded
from a release without the file, or one whose file was deleted, starts with the
marks its Supervisors already run. An installed record whose version is not
SemVer is dropped at startup with a warning; the program keeps running, and the
Agent reports no version for it.

A mark file that exists but does not parse, or that maps a type to a value that
is not SemVer, is never read as empty: the startup logs an error naming it, and
every Supervisor package offer is refused, naming the file, until you repair or
delete it. The connection, the configurations and the Client's own update are
unaffected. The Client's own Agent keeps no mark: its floor is the binary that
runs ([Updating the Client itself](#updating-the-client-itself)).

**Only the host lowers a mark.** To move a Supervisor to an older version on
purpose: stop the Client, remove that type's entry from
`package-high-water.json` (or delete the file, which resets every type no
remaining record names), delete `installed-package.json` of every Supervisor of
that type, and start the Client. The path that needs no host access is to
publish the old content as a new, greater version.

### Package updates: rollback and retention

What happens when step 4's health gate is _not_ passed:

- **A failed update rolls back to the version it replaced** — but only when
  there _is_ one. A **first** install with nothing behind it is not rolled back
  to nothing: the verified program is **kept in place** and reported
  `InstallFailed`, so `program/` never goes empty and the Server does not
  re-offer the same artifact in a loop.
- **A program that keeps failing to start is held, not restarted forever.**
  After a few attempts in a row the Supervisor stops trying and waits for a
  change — a new configuration, a new package, or a restart — rather than
  spinning (which would hammer the Server with re-downloads). A rolled-back
  predecessor that also will not start is held the same way. The Agent reports
  it plainly (`not restarting: the program keeps failing to start`).
- **A successful update keeps the version it superseded for a window, then
  deletes it**, so an operator has a fallback if the new version proves subtly
  wrong. The window is `retain_previous_secs`: global in `[updates]`, **one
  day** by default, overridable in a block of an unwrapped kind and by a wrapper
  that has a reason to. `0` deletes on success. Each Supervisor keeps at most
  the immediately previous version.

```toml
# Global default for every Supervisor (one day shown; the built-in default):
[updates]
retain_previous_secs = 86400
```

## Agents that are more than one file

An executable plus the shared objects it loads — Fluent Bit is the usual example
— is delivered by naming where the program sits inside the package:

```toml
[[supervisor]]
type = "command"
name = "fluent-bit"
command = "fluent-bit"            # bare: consent, exactly as everywhere else
program_path = "bin/fluent-bit"   # where the program sits inside the package
args = ["-c", "${config_dir}/fluent-bit-conf"]
```

With `program_path` set, the whole archive is unpacked into
`<supervisor_dir>/<name>/program/tree/`, keeping its own structure, and the
program is `program/tree/bin/fluent-bit`. Without it, nothing changes: one
member, one file, as before.

**The path is matched from its end.** An upstream release wraps everything in a
version-named directory — `fluent-bit-3.1.0/bin/fluent-bit` — and that prefix is
dropped, so `bin/fluent-bit` keeps being right at the next release instead of
naming a version. If it matches several members the install is refused and they
are listed; write more of the path to say which.

**The tree that was running is kept whole** as `program/tree.rollback` until the
new one has survived `apply_grace_secs`, and put back whole if it has not — a
rollback of half a tree would run nothing.

What an archive may contain is checked before anything is written, and one bad
member refuses the whole archive:

| Refused                                               | Why                                                                                       |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| a member with `..` in its path, or an absolute path   | It names somewhere outside the directory being unpacked into.                             |
| a symbolic or hard link                               | What it points at is not where it sits, which is the one thing a path check cannot judge. |
| more than 10 000 members, or more than 2 GiB unpacked | An archive that expands without end.                                                      |

Members outside the program's own directory — a `LICENSE` beside the wrapper —
are not written, and the count is logged rather than passed over in silence.

Two more things worth knowing. **A `.tar.gz` carries file modes and is the right
format for a tree** on Unix; a `.7z` and a `.zip` are opened too, but both store
Windows attributes rather than Unix modes, so only the program is made
executable and a helper binary beside it would not be — which costs nothing for
a tree that runs on Windows.

## Updating the Client itself

The Client is always its own Agent, so the Server can always see which version a
host runs. Letting the Server _replace_ that version is a consent that stands by
default, and it takes one package, named after this Client's own Agent type,
`supervisor`:

```toml
[packages]
self_update = true                 # the default
```

The artifact must carry a signature that verifies up to the Package Roots
compiled into the Client, as every package does
([Package updates](#package-updates)). An offer without a signature, or with one
that does not verify, is reported `InstallFailed` and nothing is staged. An
offer older than the running version is refused too: a signature carries no
ordering, so an old release stays validly signed — until its Package Signer's
certificate expires, after which no host installs it.

Every release signs its own archives. Beside each
`supervisor_<version>_<os>_<arch>.tar.gz` it publishes the `.sig` that is that
entry's signature: the certificate of the release's Package Signer and its
signature, in lowercase hex. A fleet updates from the release as published:
upload each archive with the signature its `.sig` holds, as the release notes
show. Nothing is configured on the Server or on any Client for it. The release
publishes no key, and a signature made with a key of your own is refused.

An offer under any other name is refused and reported, never applied. That is
one of two independent guards, and it is the one on this side of the wire: the
Server will not offer a package built for another Agent type either, and this
Client's type is the constant `supervisor`, compiled into the binary and not
configurable — which is why the Package that carries the Client is typed with
it. The Agent type _is_ the name a Package carries on the wire, so the two
cannot drift apart. Neither guard replaces the other — an operator who types a
Collector artifact as `supervisor` gets past the Server, and this name is what
is left.

On an accepted offer the artifact is verified like any other, staged as a new
version _beside_ the running one in the install layout, and proved by running
`supervisor self-check` on it before the `current` pointer moves — which asks
two things at once: does this binary run at all on this host, and is it actually
a Classis Agent at the version offered. The process then shuts down exactly
as an ordinary stop does — Managed Processes stopped gracefully, the goodbyes
sent — and exits, asking the service manager to restart it; it does not restart
itself. A marker in `state_dir` carries the outcome across that restart: the new
version commits itself once it reaches the Server, and one that will not stay up
is rolled back to its predecessor after three attempts. Either outcome is
reported to the Server by whichever version came up.

Self-update therefore requires an installed service — it is the service manager
that performs the restart.

**What the Client says it has is the version it runs**, whether a package put it
there or a `.deb`, an `.rpm`, an MSI or a hand did. It reports that under its
Agent type, the name the consent takes, from its very first report, which is
what lets the Server hold a Package against it: a Package reaches an Agent only
as an **upgrade**, so a Client is never offered the version it already runs, and
never an older one. The practical consequence: a Client installed by hand is not
taken over by the fleet's package the moment one is published at the version it
already is — it comes under package management with the next release that is
actually newer.

**Replacing the binary by hand does not fool it.** What the Client installed is
recorded in `<state_dir>/installed-package.json`, and `service uninstall`
deletes neither the install layout nor the state — so installing an older Client
afterwards comes up on top of that record. A record that does not name the
version the running binary _is_ is discarded at startup, with a warning naming
both versions. The Client then reports the version it actually runs, the Server
sees its published package as the upgrade it now is, and the host is updated
back to it. To hold a host on an older Client, withdraw its consent with
`self_update = false` under `[packages]`.

**Where the artifact comes from.** Every release publishes one archive per
platform, named `supervisor_<version>_<os>_<arch>.tar.gz` — and that file _is_ a
package artifact: it holds the Client under the name the install layout gives
it, so it is uploaded exactly as downloaded, and the SHA-256 the release
published is the one the Agent verifies. Nothing repacks it. The files are named
after the **Package** they become, not after the product inside them: the member
is `supervisor`, which is what a Client looks for, while the file says which
package it is. The fields are separated by `_` because two of them carry `-` — a
package name and a prerelease version (`1.2.3-dev`) — so the last two fields are
the platform and can be read off the name.

**The version in the path is the release number** — the one in the file name —
and the platform is the entry's, spelled as the Agent reports it. The Package is
typed `supervisor`, the Client's own Agent type, each entry is signed, and it
reaches a Client only through a Deployment that holds it.

**In the UI:** on the **Packages** tab, press **＋ Create** and choose the first
release archive: a file named `supervisor_<version>_<os>_<arch>.tar.gz` fills
the agent type, the version and the platform by itself. Press **OK**, add each
further platform's archive with **＋ Add entry**, then give each entry, in its
signature field, the content of the `.sig` of the same name. On the
**Deployments** tab, add
the Package to the channel, press **OK**, and press the row's **Roll out**.

**Over the API**, the same steps:

```console
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d '{}' \
       https://<server>:4321/api/v1/packages/supervisor/1.2.3
$ curl --cacert ca.pem -X PUT --data-binary @supervisor_1.2.3_linux_amd64.tar.gz \
       https://<server>:4321/api/v1/packages/supervisor/1.2.3/entries/linux/amd64
$ sig=$(cat supervisor_1.2.3_linux_amd64.tar.gz.sig)
$ curl --cacert ca.pem -X PUT -H 'Content-Type: application/json' -d "{\"signature\": \"$sig\"}" \
       https://<server>:4321/api/v1/packages/supervisor/1.2.3/entries/linux/amd64/signature
$ curl --cacert ca.pem -X PUT https://<server>:4321/api/v1/deployments/stable/packages/supervisor/1.2.3
```

The type **is** the name the consent takes, because a Package carries its Agent
type on the wire and has no separate name. The _file_ keeps its published name.
The rollout act that releases it is the Deployment's, as for any Package (see
[the rollout walkthrough](rollout.md#6-roll-it-out)).

The staged binary's `self-check` compares that against what it reports, ignoring
the commit the build came from — `1.2.3` and `1.2.3+a1b2c3d` are the same
release, and the content hash is what pins _which_ bytes arrived. What is
**not** ignored is the pre-release: a `1.2.3-dev` build offered as `1.2.3` is
refused, because a build heading for a release is not that release.

`classis --version` prints the full string on any host, which is what to
quote when asking which build a host runs.

## Connecting to the Server

**Choosing a transport.** `wss://` gets configuration changes pushed within a
second. `https://` polls every `poll_interval_secs`, which is the option for a
host that cannot hold a long-lived connection. Nothing else differs: both carry
the same messages, and the Server accepts both at once.

![A Client talking to the Server directly: the handshake with the host certificate, a report and its reply, push and heartbeat over WebSocket, polling over plain HTTP, a package download, and a revocation closing the session](../images/communication-direct.png)

**TLS 1.3, and plaintext on the loopback alone**. Every connection the Client
makes off the host is TLS 1.3, so a peer that speaks only TLS 1.2 cannot be
reached. `ws://` and `http://` are accepted only when the endpoint's host is the
IP literal `127.0.0.1` or `::1`. A host name is never the loopback, `localhost`
included, and a private address is not either. Any other plaintext endpoint
fails at startup with a message naming it.

**One credential on every connection**. The Client sends the access token of
its `state.json` as `Authorization: Bearer`, on both transports and on every
package download, and the Server admits it on that alone
([Enrolling the host](#enrolling-the-host)). A `401` whose challenge says
`error="invalid_token"` — the token was replaced, expired or never was one —
makes the Client ask for a new token and reconnect. Any other `401` is logged as
`admission failed` and retried with the usual backoff, so fixing it on either
side needs no restart. A `429` means the Server is throttling this host's
address after repeated refused attempts; fix the cause, and the back-off ends by
itself.

**Reconnecting.** A dropped connection is retried with capped exponential
backoff, and the Client honours the Server's `UNAVAILABLE` retry hints.

**Server-offered connection settings**. When the Server offers a new heartbeat
interval or endpoint, the Client **verifies the offer by actually connecting
with it**, persists it, and only then switches — across transports if the
offered endpoint demands it. An offer that moves the Client to a `ws://` or
`http://` endpoint is refused without connecting, on `127.0.0.1` and `::1` too,
and the offer is reported `FAILED` naming it: on plaintext no certificate proves
the Server. A plaintext endpoint on the loopback is one you write into
`supervisor.toml` yourself. A persisted plaintext endpoint that
`supervisor.toml` does not name is not applied at startup; the Client connects
to the configured endpoint and logs a warning naming both. A failed verification
leaves the current settings in force and is reported as such, so a bad offer
cannot strand the fleet. The `tls`, `proxy` and `headers` fields are not
honoured: the Client applies everything else and reports the offer `FAILED`,
naming the dropped fields, offered headers by their keys and never their values.
Trust stays the operator's file, never a Server's instruction, and an offered
header would be a value the Server plants on every connection with no reader on
the Agent plane. An `Authorization` header persisted in `connection-settings.pb`
is dropped when the file is loaded, with one log line naming the header keys,
and the file is rewritten without it. See
[`docs/CONFORMANCE.md`](../CONFORMANCE.md).

## Its own telemetry

The Client reports on itself over OpenTelemetry, but only where the Server tells
it to. There is nothing to configure in `supervisor.toml`: the Server offers a
destination per signal in its `[telemetry_offer]`
([the Server](server.md#the-fleets-own-telemetry)), and without an offer the
Client builds no exporter and sends nothing.

- **What it sends:** every 10 seconds the memory, CPU and uptime of its own
  process and of every process it supervises, each under that Agent's identity;
  its own log output; and a trace for each fleet operation — a package
  installed, a configuration applied, connection settings applied, a
  self-update.
- **How:** OTLP over HTTP. A destination is `https://`, in TLS 1.3, or `http://`
  to `127.0.0.1` or `::1` alone; anything else is refused, and the offer is
  reported `FAILED` naming why.
- **Credentials:** the headers the Server offers with a destination are sent as
  offered. A destination that has the Server's own origin carries the host's
  access token as its `Authorization` instead, and no other destination ever
  receives it.
- **When the destination is down:** the Client runs on. Exports leave on threads
  of their own, their queues drop rather than block, and each export gives up
  after 5 seconds. Nothing about a destination is checked by connecting to it,
  so one that is down at the moment is applied as offered and starts receiving
  once it is back. A new offer replaces the exporters at once; the old ones
  flush in the background, and only stopping the Client waits for that flush.

## Troubleshooting

**The Client will not start.** Configuration errors are deliberately fatal and
name the key. The ones you are most likely to meet:

| Message about                                              | What to do                                                                                                                                                      |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accepts_packages` / `package` in a `[[supervisor]]` block | Both keys were removed. Delete them; every Agent consents to packages, and the Server's Deployment decides which artifact.                                      |
| a program that is not a bare file name                     | `binary`/`command` name a file in the Supervisor's own `program/` directory, never a path. See [How a block names its program](#how-a-block-names-its-program). |
| an unknown key                                             | Every key is checked; a typo is refused rather than ignored.                                                                                                    |
| `this host is not enrolled`                                | The state directory holds no `state.json`. Enrol the host with `enrol <base-url> <key>` ([Enrolling the host](#enrolling-the-host)).                            |
| an endpoint refused as plaintext                           | `ws://` and `http://` are accepted only to `127.0.0.1` or `::1`. Use `wss://` or `https://`, and set `[tls] ca_file` for a private CA.                          |
| an unknown key `cert_file` or `key_file` under `[tls]`     | The Client presents no certificate any more. Delete both; `[tls]` keeps `ca_file` alone.                                                                        |
| `[packages] allowed_sources is removed`                    | The key no longer exists: a Client downloads only from its own Server's origin. Delete it.                                                                      |

**`enrol` says the host is enrolled already.** The state directory holds a
`state.json`, and `enrol` never replaces one. `revoke` deletes it, with the rest
of the state directory ([Taking the host out](#taking-the-host-out-revoke)), and
the host can enrol again.

**`enrol` is refused by the Server.** The Server did not accept the key, or the
token request that follows: an unknown key, or one the Server has replaced since
it was handed out, is refused. Nothing is written to the state directory. Ask
for the Space's current key and run `enrol` again.

**The Client logs `admission failed`, and no new token comes.** The Client asks
for a new token only after a `401` whose Bearer challenge says
`error="invalid_token"`. Any other `401` is retried with backoff and asks for
nothing — a request with no credential, or in a scheme the Server does not
take, is answered `401` without an error code. Read the Server's log: at the
`debug` level each refusal names the check that refused it, and never the
credential.

**A Foreign Agent runs but never gets new configuration.** Its command line is
pointing somewhere the Client does not write. Use `${config_dir}` (see
[Path placeholders](#path-placeholders)) and check that the file name matches
the _Configuration's_ name on the Server.

**An Agent shows as connected but out of sync.** Look at `remote_config_status`
and `remote_config_error` on its row in `GET /api/v1/agents` — the Client
reports why it rejected a configuration.

**An Agent is offered no package.** Look at three things. The Client's own
Agent declares `AcceptsPackages` only while `[packages] self_update` consents.
Two Deployments may claim the Agent, which `package_conflict` on its fleet row
names. Or the entry for its platform carries no signature, and the Server offers
no unsigned entry; the Server's log names an entry whose stored signature it
set aside at startup because it does not verify.

**A download fails naming an origin.** The offered URL, or a redirect hop, leads
off this Client's own Server origin (see
[Where a download may come from](#where-a-download-may-come-from)). This Server
offers only paths, so the URL comes from a redirect or from a foreign Server.

**An install refuses the process account, or no program starts behind it.** See
[When the install refuses](#when-the-install-refuses).

**Everything re-registered as new Agents after a move.** `supervisor_dir`
changed, and the `instance-uid` files stayed behind in the old tree. That is
expected; nothing migrates automatically.
