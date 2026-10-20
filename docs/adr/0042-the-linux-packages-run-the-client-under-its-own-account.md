# ADR-0042: The Linux packages run the Client under its own account, a re-registration keeps the account it finds, and the Client writes its systemd unit with the sandboxing every supported agent tolerates

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** `packaging/linux/postinst` and `packaging/linux/postrm`, the
  `[package.metadata.deb]` and `[package.metadata.generate-rpm]` tables of
  `crates/fleet-agent/Cargo.toml`, the `--run-as` flag of `service install` and
  the account a registration takes in `crates/fleet-agent/src/main.rs` and
  `crates/fleet-agent/src/service/run_as.rs`, the systemd unit and the launchd
  plist `crates/fleet-agent/src/service/manager.rs` registers, the ownership
  handover, and every document that tells an operator which account an installed
  Client runs as
- **Supersedes:**
  [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clauses 10, 13, 36 and 38

## Context

The Client runs as a system service. The same account runs every Managed Process
its Supervisors start, and every command their configuration language can name,
such as a Telegraf `inputs.exec` or an Icinga 2 check command
([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).
The Server sends those configurations. So the service's account is the most a
compromised or misconfigured Server reaches on a host.

[ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
clause 13 lets an operator name that account with
`service install --run-as <account>`. Without the flag the service runs as root
under systemd and launchd and as `LocalSystem` under the SCM. The `.deb` and the
`.rpm` create no account and pass no flag (ADR-0019 clause 36 and _Out of
scope_), so every packaged Linux host runs the Client as root.

A re-registration without `--run-as` writes the systemd unit without `User=` and
the launchd plist without `UserName`. `packaging/linux/postinst` runs exactly
that, `service install` with no `--run-as`, on every upgrade (`postinst:43`). A
host installed with `--run-as` therefore runs as root after its next package
upgrade. Nothing reports the change, and the data root stays owned by the
account. Windows keeps the logon account: `windows_config` sets `obj=` only when
`--run-as` is given (`windows_config.rs:130-136`), and the SCM keeps the account
a registration already holds.

The systemd unit is rendered by `service-manager` 0.11 (`contents: None` in
`manager.rs:155`). Its renderer writes `Description`, `ExecStart`, `Restart`,
`RestartSec`, `User` and `WantedBy`, and has no place for any other directive
(`systemd.rs:259-368`). It also joins the arguments of `ExecStart` with spaces
and does not quote them (`systemd.rs:300-309`), so a root path that contains a
space produces a unit that names the wrong program.

Forces:

- **Least privilege** is an operator requirement (ADR-0019, _Context_), and the
  specification puts security before convenience (Strategy "Security before
  convenience", Q-1 "Secure by default").
- **Some agents need root.** GLPI Agent reads the DMI tables (`dmidecode`), and
  its Deploy task installs operating-system packages. Telegraf's `smart` and
  `ipmi` inputs and many Icinga plugins run through `sudo` or a setuid helper
  (`check_icmp`, `check_dhcp`). A listener on a port below 1024 needs
  `CAP_NET_BIND_SERVICE`. A host with such an agent must be able to keep root,
  by a choice the operator makes explicitly, and that choice must survive an
  upgrade.
- **systemd ties most sandboxing to `no_new_privs`.** For a unit without
  `CAP_SYS_ADMIN`, which is every unit with a non-root `User=`,
  `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`,
  `ProtectClock=`, `ProtectHostname=`, `PrivateDevices=` and
  `RestrictAddressFamilies=` imply `NoNewPrivileges=yes`. So do the
  seccomp-based directives: `LockPersonality=`, `RestrictRealtime=`,
  `RestrictSUIDSGID=`, `RestrictNamespaces=`, `MemoryDenyWriteExecute=`,
  `SystemCallFilter=` and `SystemCallArchitectures=`. With `no_new_privs` set,
  `sudo` and every setuid or file-capability helper stop working for the service
  and for each of its Managed Processes.
- **The Client writes the places it needs.** It writes its data root
  (`supervisor.toml`, `state/`) and its layout root (`/opt/<PRODUCT_NAME>`,
  where the self-update stages versions and switches `current`). It also writes
  each Supervisor's directory, and it starts Managed Processes that may write
  anywhere their kind keeps state: Icinga 2 under `/etc/icinga2` and
  `/var/lib/icinga2`, and a GLPI Deploy anywhere a package installs.
- **Upgrades run unattended.** The post-install runs inside `apt upgrade` and
  `dnf upgrade`, often on hosts nobody watches. An upgrade must not change which
  account runs a configured host.

## Decision

We will have the `.deb` and the `.rpm` create the system account
`<PRODUCT_NAME>` and register a first installation to run under it, keep on
every re-registration without `--run-as` the account that the registration
already names, and have the Client write its systemd system unit itself, with
only those sandboxing directives that leave `sudo`, setuid helpers and every
supported agent working.

1. **Restates ADR-0019 clause 10. An upgrade on an installed host is a
   re-registration, never a migration.** `--config` and `--state-dir` keep
   pointing into the data root. A re-registration rewrites the program path
   (`ExecStart`) and the rest of the unit or plist from the version that runs
   it, the directives of clause 7 included. The account stays the one the
   registration names (clause 2). The instance's configuration, identity and
   state never move. A change that would move the data root of an installed host
   must bring its own migration and carries the full weight of this rule.

2. **Restates ADR-0019 clause 13. The system service runs under the account its
   registration names, and both roots belong to it.**
   `service install --run-as <account>` names the account. It applies at system
   scope only and conflicts with `--user`. On Linux and macOS, `--run-as root`
   is how an operator chooses root. It is written as `User=root` or `UserName`
   `root`, so a unit records that root was chosen. Without the flag, the account
   is taken in this order:
   - **A re-registration keeps the account the registration names.** That is
     `User=` in the system unit `/etc/systemd/system/<PRODUCT_NAME>.service`,
     `UserName` in `/Library/LaunchDaemons/<PRODUCT_NAME>.plist`. The install
     reads the file the Client wrote, not a drop-in and not the loaded state of
     the service manager. On Windows the install does not ask the SCM: a
     re-registration without `--run-as` sets no logon account, so the SCM keeps
     the one it holds (`windows_config`), and the install names no account.
   - **A unit or plist that names no account, on a data root that a non-root
     account owns,** was rewritten by a re-registration that dropped its
     account. The install takes the owner of the data root and prints that it
     did, naming the data root. Every other registration that names no account
     stays root.
   - **A first registration**, one where no unit, plist or SCM entry exists,
     runs as root under systemd and launchd and as `LocalSystem` under the SCM.
     The Linux packages name their account themselves (clause 5).

   On Linux and macOS the install prints the account and where it came from:
   `--run-as`, the unit, the plist, the owner of the data root, or the default.
   - **The service runs as the account.** Under systemd this is `User=` in the
     unit the Client writes (clause 6). Under launchd it is `UserName`, through
     `service-manager`'s `username`. On Windows it is an `sc config obj=` step
     in `windows_config`. No _Log on as a service_ grant is performed: the
     default policy grants it to `NT SERVICE\ALL SERVICES`, built-in accounts
     carry it, and a gMSA receives it from its domain. A host hardened against
     the default grant must restore it.
   - **Windows accepts only passwordless forms:** the service's own virtual
     account `NT SERVICE\<PRODUCT_NAME>` (recommended), a gMSA (`name$`), or
     `NT AUTHORITY\LocalService` / `NetworkService`. There is no password
     parameter, because it would stand in the process list and the installer
     log. A form that needs a password is refused with a message naming the
     passwordless forms.
   - **The account must exist** on Linux and macOS, whether it was named or
     kept. An account that does not exist is refused before anything is written,
     and the install fails closed. For a kept account, the message names the
     account and the file or directory it came from. It shows the
     `useradd --system` line that creates the account, and says that
     `--run-as <account>` or `--run-as root` names another. The binary never
     creates an account; that is the packages' job (clause 5).
   - **The hand-over covers both roots, on every registration that runs under an
     account.** That includes a kept account and root. After laying out and
     registering, the install hands the account the data root
     (`supervisor.toml`, `state/`), because the service reads and rewrites them.
     It also hands over the layout root (`versions/`, `current`), because the
     self-update that stages into it is the service itself. On Unix this is an
     ownership change. On Windows it is an inheritable Modify ACL grant. Where
     the roots coincide this is one operation. Where they split, an install that
     hands over only one has not succeeded.
   - **The hand-over never follows a link.** The account owns the trees that
     root walks, and clause 5 makes that walk part of every package upgrade. So
     each directory is opened without following a link, and its owner is changed
     through that open handle. Its entries are read from the handle, and a
     symbolic link is re-owned as a link. A regular file with more than one hard
     link is skipped and named in a warning. Re-running `install` with another
     `--run-as` re-owns the same directories.

3. **Restates ADR-0019 clause 36. The package delivers one file;
   `service install` installs.**

   |                 | delivers                                 | after install                                                                                                                                                               | before removal                           |
   | --------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
   | `.deb` / `.rpm` | `/usr/libexec/<PRODUCT_NAME>/supervisor` | the account `<PRODUCT_NAME>` where it is missing (clause 5), then `… service install --run-as <PRODUCT_NAME>` where no unit is registered, `… service install` where one is | `service stop`, then `service uninstall` |
   | `.msi`          | `INSTALLFOLDER\supervisor.exe`           | `… service install [--endpoint <ENDPOINT>] [--no-self-update]`                                                                                                              | `service stop`, then `service uninstall` |

   **No package ships a systemd unit, a `LaunchDaemon`, a `sysusers.d` entry or
   an MSI `ServiceInstall` element.** `cargo-deb`'s `systemd-units` and WiX's
   `ServiceInstall`/`ServiceControl` are deliberately unused. There is one
   install path on every platform. The ownerships are disjoint by construction:
   the package owns its payload and never anything in the layout.
   `service install` stages a _copy_ into the layout, which is what the service
   runs and what a self-update replaces, so `dpkg -V` and `rpm -V` stay quiet
   through every fleet update. The pre-removal runs only on a real removal. On
   an upgrade it falls straight through, because the successor's post-install
   re-runs `service install`, and unregistering would stop a managed host in the
   middle of `apt upgrade`. It calls the payload path, never the symlink, and
   tolerates a service that is already unregistered. The dpkg/rpm package
   identity is `PRODUCT_NAME` and the MSI's is its display name and
   `UpgradeCode`, so an `apt`, `dnf` or MSI upgrade stays an upgrade.

4. **Restates ADR-0019 clause 38. The CLI on `PATH` is a symlink through
   `current`, and a package removal takes the layout and leaves the account.**
   `/usr/bin/<PRODUCT_NAME>` → `/opt/<PRODUCT_NAME>/current/supervisor`, so the
   operator's first diagnostic command answers for the binary the service runs,
   not for the one the package delivered. The maintainer scripts lay it, rather
   than shipping it as a packaged file, and both formats honour them:

   | hook                                    | does                                                                                                                                                                                       |
   | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
   | `postinst` / `%post`                    | the account where it is missing (clause 5), `service install` as clause 3 states, then `ln -sfn` the symlink                                                                               |
   | `%posttrans` (rpm only)                 | `ln -sfn` again. rpm erases the old package's files _after_ the new `%post`, and that may take the link. dpkg removes them during unpack and needs nothing                                 |
   | `postrm` / `%postun`, real removal only | remove the symlink (only if it is one), and the layout root `/opt/<PRODUCT_NAME>` with every staged version and `current`; on dpkg **purge**, also the data root `/var/lib/<PRODUCT_NAME>` |

   A removal keeps the data root, because the Agent's identity and the
   configuration the operator wrote are not binaries, and a reinstall picks them
   up. The layout goes, so a reinstall comes up on the package it installed
   rather than on a surviving `current`. Purge is dpkg's "leave nothing"; rpm
   has none. **No hook removes the account or its group, on removal or on
   purge.** Files the account owns outside the two roots, such as a Managed
   Process's output, would pass to whichever account is later given the same
   uid. `service uninstall` itself still deletes nothing (ADR-0019 clause 11);
   this cleanup is the package's. Re-staging **skips the write when the staged
   binary already holds the running bytes**, because `service install` invoked
   through the symlink runs from the very file it would overwrite, and Linux
   refuses that (`ETXTBSY`). Symlink, account and cleanup name the default
   system roots only, the only roots a packaged install uses. An install rooted
   with `--root` is a manual one, and nothing packaged touches it.

5. **The Linux packages create the account `<PRODUCT_NAME>` and name it on a
   first registration.** Before `service install`, the post-install checks for
   the account with `getent passwd`. When it is missing, it creates the account
   with
   `useradd --system --user-group --no-create-home --home-dir
   /var/lib/<PRODUCT_NAME> --shell /usr/sbin/nologin <PRODUCT_NAME>`,
   or, where a group of that name already exists without the account, with
   `--gid <PRODUCT_NAME>` in place of `--user-group`, which would refuse it. The
   account gets no password. Its home is the data root, so a Managed Process
   that writes under `$HOME` writes into a directory the account owns. An
   existing account of that name is used as it is, and never modified. The
   account is created on every run, also on a host whose registration stays
   root, so that moving such a host to the account is one command. The
   post-install then passes `--run-as <PRODUCT_NAME>` only when
   `/etc/systemd/system/<PRODUCT_NAME>.service` is absent, and otherwise runs
   `service install` without it, which keeps the account the unit names (clause
   2). A host that chose root with `--run-as root` therefore stays root through
   every upgrade. A variant build creates the account of its own `PRODUCT_NAME`,
   so two variants never share one. The `.deb` declares a dependency on the
   package that ships `useradd`, and the `.rpm` requires the file
   `/usr/sbin/useradd`, which `cargo-generate-rpm` can state only as a plain
   `Requires`.

6. **The Client writes its systemd system unit itself, and `service-manager`
   installs it.** `manager::install` passes `contents: Some(<unit>)` at system
   scope under systemd. `service-manager` still writes the file (mode `0644`),
   enables it, which reloads the manager's configuration, and uninstalls it. The
   unit holds:
   - `[Unit]`: `Description=<PRODUCT_NAME>`, the same as before. The display
     name stays where ADR-0019 clause 2 puts prose.
   - `[Service]`: `ExecStart=` with the program and every argument in double
     quotes. A `\` and a `"` are escaped, a `%` is written `%%` and a `$` is
     written `$$`, so any absolute path reaches the program as it was given.
     Then `Restart=on-failure`, `RestartSec=` set to the restart delay the SCM's
     recovery actions use (ADR-0019 clause 11), `User=` set to the account of
     clause 2, and the directives of clause 7.
   - `[Install]`: `WantedBy=multi-user.target`.

   The user scope and the launchd plist stay as `service-manager` renders them.
   `service install` never writes, reads or removes anything under
   `/etc/systemd/system/<PRODUCT_NAME>.service.d/`. Drop-ins there belong to the
   operator, outrank the unit, and survive every re-registration.

7. **The unit carries only directives that neither set `no_new_privs` nor take
   away what a supported agent needs, and the account decides the set.**
   - **Every system unit** carries `ProtectControlGroups=yes`. Through it
     `/sys/fs/cgroup` becomes read-only. It does not imply `NoNewPrivileges=`,
     and none of the supported agents, OpenTelemetry Collector, Telegraf, Icinga
     2 with its plugins and GLPI Agent with its tasks, writes the cgroup tree
     itself.
   - **A unit that runs as root** (`User=root`) also carries
     `ProtectKernelTunables=yes`, `LockPersonality=yes` and
     `RestrictRealtime=yes`. Under root they imply nothing, because the unit
     holds `CAP_SYS_ADMIN`. They make `/proc/sys` and `/sys` read-only, fix the
     execution domain, and refuse realtime scheduling. No supported agent needs
     any of that.
   - **Under any other account these three are left out**, because each would
     set `no_new_privs` and break `sudo` and the setuid helpers the agents use.
   - **Left out everywhere:** `NoNewPrivileges=`, for the same reason.
     `ProtectSystem=` (`yes`, `full` or `strict`) and `RestrictSUIDSGID=`,
     because a GLPI Deploy task or a configuration-management run under the
     `command` kind installs operating-system packages under root, and Icinga 2
     writes `/etc/icinga2`. `ProtectHome=`, because a root service's home is
     `/root` and a log receiver may read under `/home`. `PrivateTmp=`, because a
     Managed Process may reach a local daemon through a socket under `/tmp`.
     `MemoryDenyWriteExecute=`, because it breaks every JIT a check or exec
     script may run (Java, Node.js, .NET, LuaJIT). `RestrictNamespaces=`,
     because it breaks `ip netns exec` around a check and any sandboxing helper.
     `CapabilityBoundingSet=`, because it takes from root what root was chosen
     for, and from a setuid helper what it grants. `ProtectKernelModules=`,
     because it hides `/usr/lib/modules`, which hardware inventory reads.
     `PrivateDevices=`, because SMART, IPMI and sensor inputs read `/dev`.
     `ProtectKernelLogs=`, because of `dmesg` readers. `ProtectClock=`, because
     it implies a device allow-list. `ProtectHostname=`, because a UTS namespace
     would freeze the host name the Client reports
     ([ADR-0016](0016-what-an-agent-reports-about-itself.md)). `ProtectProc=`,
     because process inputs read other users' `/proc` entries.
     `RestrictAddressFamilies=` and `SystemCallFilter=`, because Managed
     Processes use netlink, raw and packet sockets and arbitrary system calls.

   An operator adds what a host can take (`NoNewPrivileges=yes` where nothing
   uses `sudo`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` for a port below
   1024, `SupplementaryGroups=adm` for logs) or removes what it cannot in a
   drop-in (clause 6). The documentation shows each.

**Out of scope:** Windows. The MSI stays at `LocalSystem` by default
(`packaging/windows/supervisor.wxs`), there is no explicit way to return a
Windows service to `LocalSystem`, and Job Objects are not used. Also out of
scope: macOS sandboxing; account creation by the binary; a `sysusers.d` entry;
moving existing root hosts to the account automatically; a confined SELinux
policy module (ADR-0019, _Out of scope_); directives for user-scope units; and
the trust boundary an administrator crosses when running the account-owned
binary through the `PATH` symlink (see _Consequences_).

## Alternatives considered

- **Keep root as the packaged default.** This is the smallest change, and every
  agent works. But every packaged host then hands a Server-delivered
  `inputs.exec` root, and least privilege stays something an operator must know
  to ask for. Rejected.
- **systemd `DynamicUser=`.** The UID is allocated per start, and the state
  moves under `/var/lib/private`. The layout root `/opt/<PRODUCT_NAME>` cannot
  be owned by an account that does not persist, so the self-update would end.
  `NoNewPrivileges=` and `RestrictSUIDSGID=` are implied and cannot be turned
  off, which breaks `sudo` and setuid plugins. ADR-0019 refused it for the
  persistent identity. Rejected.
- **Only sandbox, and keep root.** This confines a root service a little. Under
  root the directives that would matter (`ProtectSystem=`, `NoNewPrivileges=`,
  `CapabilityBoundingSet=`) are the ones that break the agents root was kept
  for. The account is what bounds a Server-delivered command. Rejected as the
  whole answer; clause 7 keeps the root tier.
- **The Server's unit (`docs/manual/setup.md:199-246`): `ProtectSystem=strict`,
  `NoNewPrivileges=`, `MemoryDenyWriteExecute=` and the rest.** It fits a
  program that writes one directory and spawns nothing. The Client starts other
  programs whose needs it does not know. Rejected.
- **One directive set for every account.** Either the root tier is lost, or
  `no_new_privs` arrives for the account through an implied setting. Rejected
  for the two tiers of clause 7.
- **Add the directives through a drop-in that `service install` writes, and keep
  `service-manager`'s unit.** This means two files to keep in step.
  `service uninstall` would leave a directory `service-manager` does not know,
  and the Client's drop-in would share a directory with the operator's. It also
  leaves the unquoted `ExecStart`. Rejected.
- **A flag that names the account only for a first registration
  (`--run-as-if-new`).** This keeps the check in Rust. But it is a public flag
  forever, for the one caller that can test for a file. Rejected; clause 5's
  test reads the same file that clause 2 reads.
- **Make the binary default to the account `<PRODUCT_NAME>` wherever it
  exists.** An archive install would then depend on what some earlier package
  left behind. Rejected.
- **Read the account from `systemctl show -p User`.** This sees drop-ins. But it
  needs a running manager, which a container image build or a chroot does not
  have, and it reports what is loaded, not what was written. Rejected.
- **Leave hosts whose unit lost its account as root.** Every packaged host
  installed with `--run-as` and upgraded once would stay root without saying so.
  Rejected for the data-root rule of clause 2.
- **Remove the account on purge.** Files it owns elsewhere would pass to a later
  account with the same uid. Debian and Fedora packaging practice both leave
  system accounts in place (recalled, not re-read). Rejected.
- **A `sysusers.d` file in the package.** This is the declarative form that
  Fedora's packaging guidelines prefer (recalled, not re-read). It is a second
  packaged file beside the one clause 3 allows, and Debian's tooling needs its
  own trigger for it. It stays possible later.
- **`AmbientCapabilities=CAP_NET_BIND_SERVICE` by default.** It would give every
  Managed Process on every host a right that few hosts need. Rejected; a drop-in
  adds it where it is needed.

## Sources / Prior art

- The code as it stands:
  - `crates/fleet-agent/src/service/manager.rs:149-175`: `contents: None`, with
    `username` passed through.
  - `crates/fleet-agent/src/main.rs:147-153`: the account is resolved only when
    `--run-as` is given.
  - `main.rs:278-311`: the hand-over runs only then.
  - `crates/fleet-agent/src/service/run_as.rs:136-148`: the missing-account
    message.
  - `run_as.rs:155-167`: `chown_tree` checks with `symlink_metadata`, then calls
    `read_dir` on the path. That leaves a window in which a directory swapped
    for a link is followed; the comment at `run_as.rs:173-175` names the same
    risk.
  - `crates/fleet-agent/src/service/windows_config.rs:124-136`.
  - `packaging/linux/postinst:43`: a plain `service install` on every run.
  - `scripts/check-shell.sh:33-35`: shellcheck scans `*.sh` and `.githooks/`
    only, so `packaging/linux/*` is not linted.
- `service-manager` 0.11.0 `src/systemd.rs`: `install` (130-167) writes
  `contents` verbatim when given and otherwise `make_service` (259-368). `User=`
  is written only at system scope (350-357). The unit goes under
  `/etc/systemd/system` (248-250). Arguments are joined unquoted (300-309). No
  `daemon-reload` is issued; `systemctl enable` reloads by default (recalled,
  not re-read). `src/launchd.rs`: `UserName` (403-405), under
  `/Library/LaunchDaemons` (304-306).
- systemd.exec(5), read for this record in the Debian bookworm (systemd 252) and
  current upstream pages:
  - `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`,
    `ProtectClock=`, `ProtectHostname=`, `PrivateDevices=` and
    `RestrictAddressFamilies=` each say that `NoNewPrivileges=yes` is implied
    when the unit lacks `CAP_SYS_ADMIN` (for example, with `User=`).
  - The `NoNewPrivileges=` entry lists `LockPersonality=`,
    `MemoryDenyWriteExecute=`, `RestrictNamespaces=`, `RestrictRealtime=`,
    `RestrictSUIDSGID=`, `SystemCallArchitectures=`, `SystemCallFilter=` and
    `DynamicUser=` among the settings that override it.
  - `ProtectControlGroups=` mentions neither.
  - `ProtectClock=` implies `DeviceAllow=char-rtc r`.
  - Versions: `ProtectSystem=` 214, `RestrictRealtime=` 231,
    `ProtectKernelTunables=` and `ProtectControlGroups=` 232,
    `LockPersonality=` 235. On an older systemd, an unknown directive is logged
    and ignored (recalled, not re-read).
  - The `NoNewPrivileges=` entry says that in a new mount namespace without
    SELinux, file systems are mounted `MS_NOSUID`. This is read as applying only
    when `no_new_privs` is in effect, which clause 7 keeps off for the account
    (recalled from systemd's `namespace.c`, not re-read). Enforcement checks it
    on a real host.
- systemd.unit(5), specifiers (`%%`), and systemd.service(5), the quoting and
  `$$` of `ExecStart=`: recalled, not re-read.
- `docs/manual/client.md:311-352` and `docs/manual/setup.md:199-246`: what
  operators are told today.
- Telegraf's `use_sudo` inputs, Icinga's setuid plugins, and GLPI Agent's root
  inventory and Deploy task: recalled from their documentation, not re-read.

## Consequences

- Positive: a packaged Linux host runs the Client and every Managed Process as
  an unprivileged account from its first install, so a Server-delivered command
  no longer runs as root. A host installed with `--run-as` keeps its account
  through every upgrade. A host whose unit already lost its account gets it back
  at its next upgrade.
- Positive: the unit is one file the Client renders and tests. A root path with
  a space or a `%` works. Operators loosen or tighten the unit with ordinary
  drop-ins that survive upgrades.
- Negative / trade-offs: on a new install, agents that need root fail under the
  account. These include GLPI Agent's full inventory and Deploy, Telegraf inputs
  without a `sudo` rule, any listener on a port below 1024, and a file log
  receiver reading `root:adm` files. The operator either grants what is missing
  (a `sudoers` entry, a drop-in with `AmbientCapabilities=` or
  `SupplementaryGroups=`, `usermod -aG adm`) or chooses root with
  `sudo opamp-fleet service install --run-as root`. The manual and the
  post-install text say so.
- Negative / trade-offs: the sandbox is thin under the account. The account is
  the confinement, and `ProtectControlGroups=` adds little. The root tier adds
  three directives. Strong confinement stays a per-host drop-in, because systemd
  ties it to `no_new_privs`.
- Negative / trade-offs: existing root installs stay root. Their unit names no
  account, and their data root is root's. The account is created on them at the
  next upgrade but stays unused until the operator runs
  `service install --run-as <PRODUCT_NAME>` and restarts the service. The
  changelog names that step.
- Negative / trade-offs: an operator who returned a host to root with a plain
  re-install, while its data root was still the account's, finds it back on the
  account. Root is chosen with `--run-as root`. The changelog says so. An
  account set only in a drop-in's `User=` governs the process, but is not what
  the hand-over gives the roots to.
- Negative / trade-offs: a kept account that has been deleted stops the
  post-install, and the package stays unconfigured until the operator creates
  the account or names another. That is intended: falling back to root without a
  word is what this decision ends.
- Negative / trade-offs: an archive host that only self-updates keeps the unit
  its last `service install` wrote. New directives reach it at its next
  re-registration.
- Negative / trade-offs: the trust boundary of ADR-0019 clause 13 is now the
  default. The account owns the layout, so `sudo opamp-fleet …` through the
  `PATH` symlink runs code the account can replace. With root as the default,
  every Managed Process held root already. The account narrows that to an
  administrator's own command.
- Follow-ups: a way for an administrator to run the installed CLI without
  executing account-owned code; an explicit return to `LocalSystem` on Windows;
  a virtual-account default in the MSI; a `sysusers.d` entry; and whether the
  unit should order itself after `network-online.target`.

## Enforcement

Tests that will carry `Verifies: ADR-0042`:

- `crates/fleet-agent/src/service/manager.rs`:
  - `the_system_unit_is_the_clients_own_text`: the rendered unit holds
    `Description=<PRODUCT_NAME>`, a quoted `ExecStart` with the marker and
    absolute paths, `Restart=on-failure`, `RestartSec=<RESTART_DELAY_SECS>` and
    `WantedBy=multi-user.target`.
  - `exec_start_survives_spaces_percent_and_dollar`: a root with a space, a `%`
    and a `$` renders `"…"`, `%%` and `$$`.
  - `an_account_unit_sets_nothing_that_implies_no_new_privs`: under
    `User=opamp-fleet` the unit holds `ProtectControlGroups=yes`. It holds none
    of `NoNewPrivileges`, `ProtectKernelTunables`, `ProtectKernelModules`,
    `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `PrivateDevices`,
    `RestrictAddressFamilies`, `LockPersonality`, `RestrictRealtime`,
    `RestrictSUIDSGID`, `RestrictNamespaces`, `MemoryDenyWriteExecute`,
    `SystemCallFilter`, `SystemCallArchitectures` or `DynamicUser`.
  - `a_root_unit_carries_the_root_tier`: under `User=root` the unit adds
    `ProtectKernelTunables=yes`, `LockPersonality=yes` and
    `RestrictRealtime=yes`.
  - `no_unit_carries_what_breaks_a_supported_agent`: no unit holds
    `ProtectSystem`, `ProtectHome`, `PrivateTmp` or `CapabilityBoundingSet`.
  - `a_user_unit_is_left_to_service_manager`: the user scope passes
    `contents: None`.
- `crates/fleet-agent/src/service/run_as.rs` (or the module that decides the
  account):
  - `a_reregistration_without_run_as_keeps_the_units_account`: a unit fixture
    with `User=telegraf` yields `telegraf`, from the unit.
  - `a_plists_user_name_is_kept`.
  - `run_as_root_is_written_as_user_root`.
  - `a_unit_without_an_account_on_an_account_owned_data_root_takes_the_owner`.
  - `a_unit_without_an_account_on_a_root_owned_data_root_stays_root`.
  - `no_registration_means_root`.
  - `a_kept_account_that_no_longer_exists_is_refused_naming_its_source`: the
    message names the account, the unit path, `useradd` and `--run-as`, and says
    that nothing was written.
  - `the_handover_never_follows_a_directory_swapped_for_a_link`: a tree in which
    a directory is replaced by a link to a directory outside it. The outside
    directory's entries keep their owner.
  - `the_handover_skips_a_file_with_a_second_hard_link`.
- `crates/fleet-agent/tests/linux_post_install.rs`:
  - `the_post_install_creates_the_account_before_it_registers`: `getent passwd`
    and the `useradd` line appear before every `service install`. The line is
    `--system`, without a password and with a `nologin` shell.
  - `the_post_install_names_the_account_only_where_no_unit_is_registered`:
    `--run-as opamp-fleet` appears only in the branch where
    `/etc/systemd/system/opamp-fleet.service` is absent, and the other branch
    runs `service install` without `--run-as`.
  - `no_maintainer_script_removes_the_account`: no `userdel` or `groupdel` in
    `postrm`, `prerm` or `posttrans`.
- `scripts/check-shell.sh` lints `packaging/linux/*` as POSIX `sh`. The release
  job's "The RPM carries its scriptlets" step also requires `useradd` and
  `--run-as`.
- `crates/fleet-agent/tests/service_smoke.rs`, run with `--ignored` by the
  `service-smoke` workflow:
  - `a_reregistration_keeps_the_account_and_the_service_keeps_its_privileges`:
    install with `--run-as` a temporary system account, then re-install without
    the flag. Then:
    - `systemctl show -p User` still names the account;
    - `/proc/<MainPID>/status` shows `NoNewPrivs: 0`;
    - `/proc/<MainPID>/mountinfo` shows `/` without `nosuid`;
    - `systemd-analyze verify` accepts the unit.

**Not mechanically decidable:** that every supported agent works under the
account and under root with these units. The kinds' end-to-end tests run without
systemd. The manual checklist in `README.md` gains a step for each wrapped kind
under the packaged account. What `dpkg` and `rpm` do with the maintainer scripts
on a real host is, as for ADR-0019, exercised only by installing a release.
