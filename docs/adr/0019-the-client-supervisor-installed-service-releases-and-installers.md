# ADR-0019: The Client is the program `supervisor`, installs itself as a native service named after a build-time product name from a versioned layout it can rewrite with a first configuration that authenticates and encrypts, and ships as `.tar.gz` archives and native installers that run that install

- **Status:** 🟢 accepted · clauses 17, 19 and 42 superseded by [ADR-0020](0020-the-client-install-takes-the-fleet-files-it-finds-beside-its-program.md) · clause 37 superseded by [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md) · clauses 10, 13, 36 and 38 superseded by [ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md) · clause 34 superseded by [ADR-0045](0045-every-release-asset-carries-a-provenance-attestation-and-every-program-an-sbom.md)
- **Date:** 2026-10-10
- **Deciders:** Markus Brigl
- **Applies to:** `crates/fleet-agent/src/cli.rs`, `crates/fleet-agent/src/main.rs`, `crates/fleet-agent/src/service/`, `crates/fleet-agent/src/config_init.rs`, `crates/fleet-agent/src/logging.rs`, `crates/fleet-agent/src/product.rs`, `crates/fleet-agent/build.rs`, the `[package.metadata.deb]` and `[package.metadata.generate-rpm]` tables of `crates/fleet-agent/Cargo.toml`, `.github/workflows/release.yml`, `packaging/`, the program, Agent type and configuration-file names of the Client, `service install --endpoint`, `service config`, and every path, name or account an installed Client uses

## Context

The Agent plane admits a peer by its client certificate alone
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)), as the specification asks (Strategy
"Security before convenience", Q-1, the Gateway Mode paragraph and G-15). There is no fleet
credential, so no installer asks for one, writes one or names one in the steps it prints, and a
first configuration is complete with the endpoint, the CA where the Server's certificate needs one,
and a client identity.

The specification puts security before convenience (Strategy "Security before convenience", Q-1
"Secure by default"): the first configuration the installer writes must authenticate and must not
send plaintext beyond the loopback. Plaintext is accepted on the loopback alone, a host name is
never the loopback, and a Client without a client certificate is refused at startup. Since
[ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) the Client authenticates with one proof,
the client certificate it presents in the TLS handshake.

The specification commits the Client to install as a native operating-system service that updates
itself in place, on Linux, macOS and Windows (Mission, Strategy, goals 10 and 11). A fleet client
must run without a logged-in user, start at boot, survive the service restart a self-update
causes, and explain itself when it fails on a host nobody watches.

Forces:

- **The three service models differ.** systemd and launchd supervise an ordinary foreground
  process. The Windows Service Control Manager (SCM) launches the process and expects status
  reports within about 30 seconds or kills it with error 1053, and a process cannot reliably detect
  an SCM launch, so the registered command line must carry a marker. The SCM discards a service's
  stderr.
- **What the service points at decides how an update works.** Registering the binary's own path
  would force a re-registration on every update, and Windows locks a running `.exe`. A stable
  pointer into side-by-side version directories makes an update a pointer switch.
- **The layout is rewritten at runtime by the daemon itself** — the self-update stages versions and
  swings the pointer while the service runs ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). So the
  layout must stand where the platform lets the service execute it *and* where the service's own
  account may write it. On Fedora, RHEL and openSUSE Leap 16 / SLES 16 the SELinux targeted policy
  is enforcing by default, and systemd (`init_t`) may not execute a file labelled `var_lib_t`: a
  binary under `/var/lib` installs, registers, and dies at its first start with `status=203/EXEC`
  and an AVC denial the unit's journal never explains, while the same binary runs fine from a
  shell. On Windows, `Program Files` is `TrustedInstaller`-owned and meant to be read-only once
  installation finishes.
- **A name that identifies an installation has to exist before the installation is read.** It
  names the directory the configuration is read from, and `service uninstall` must find the service
  without that file. It must at once be a systemd unit name, a launchd label, an SCM service name
  and a directory name on every platform.
- **Nothing ships the configuration.** A release artifact is the bare binary, and the Client loads
  defaults when its file is absent ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)) — so a service
  installed without one starts, dials the development default, and manages nothing, silently.
  `install` is also the command an Ansible play, an MDM profile or an MSI invokes: a prompt there
  does not fail, it hangs. And a first configuration names a client identity: a certificate and
  its private key, files that must already be on the host.
- **Least privilege** is an operator requirement: the Client, and every Managed Process its
  Supervisors spawn, may have to run under a dedicated account instead of root or `LocalSystem`.

An operator needs something to install, and a fleet needs something to hand its Server. They are
different questions. The fleet needs one artifact per platform that the Client itself can open and
install as a self-update ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). A host needs what its
platform expects — `apt` and `dnf` with an inventory, an upgrade path and a clean removal; on
Windows an `.msi`, the only thing Intune, Group Policy and SCCM deploy.
`opentelemetry-collector-releases` and Elastic Agent both publish native packages *beside* their
archives, for exactly that reason.

Three forces constrain both:

- **`service install` owns the install** (clauses 3, 9 and 11):
  the versioned layout, the `current` pointer, the registration with its single-token name, display
  name and Windows recovery actions. A native package that registered a service of its own would
  write a second registration missing all of that.
- **Self-update and a package manager must not own the same bytes.** The self-update writes new
  version directories and swings `current`. If `dpkg`, `rpm` or the MSI owned those paths, every
  fleet update would leave the host in a state `dpkg -V` reports as modified and the next
  `apt upgrade` silently reverts.
- **A Client with no configuration is a defect, not a default.** It holds no client certificate,
  so it is refused at startup and manages nothing (clauses 19 and 20); a package installed on a
  thousand hosts must not manufacture that state a thousand times.

And one force on the name. The Baseline reserves `service.name` for the Agent *type* and recommends
a reverse FQDN — a recommendation this project does not enforce
([ADR-0016](0016-what-an-agent-reports-about-itself.md)), and which opamp-spec issue 131 records as
an overload of that key. Among Collectors, Foreign Agents and the process that supervises them, the
useful type for the last is the role it plays. What the fleet offers the thing is named after what
the thing is, and so is the thing itself. Artifact names are a public contract: operators script
against them.

## Decision

We will call the fleet's own agent `supervisor` at every layer where it is the program, and make it
a `clap` subcommand CLI that registers, controls and runs itself as a native service on systemd,
launchd and the Windows SCM, under a product name fixed at build time that names the service, the
install path, the package and the `PATH` entry; that executes from a versioned layout behind a
`current` pointer, kept apart from its data on Linux at system scope; that writes its first
configuration when asked and never one the Client would refuse at startup, logs to a bounded file
when it runs as a service, and may run under an operator-named account that owns what it
rewrites; and publish each release as one `.tar.gz` per target named
`supervisor_<version>_<os>_<arch>` — the fleet's artifact — plus a `.deb`, `.rpm` and `.msi` that
deliver the same binary and run its own `service install`.

### The installed service

1. **One CLI, thin, over a `service` module.** The subcommands are `run` — the foreground daemon,
   and the default when no subcommand is given — and `service install | config | uninstall | start |
   stop | status`. The global flags are `--config` (default `supervisor.toml`) and `--state-dir`; every
   service verb takes `--user`. There is no environment-variable configuration: the Client is
   file-configured ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)) and a registered
   service carries the configuration's *path*, never its content. clap's `version` is wired to
   `opamp::version::current()` ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md) clause 5). The daemon code lives in
   `crates/fleet-agent/src/service/` (`runtime`, `layout`, `manager`, `run_as`, and the Windows-only
   `windows`, `windows_config`, `windows_rights`), behind the narrow `ServiceControl` seam
   (`start`, `stop`, `state`) that the self-update depends on. Errors are `Result<_, String>`.

2. **`PRODUCT_NAME` is a build-time constant.** Default **`opamp-fleet`**, overridable with
   `OPAMP_PRODUCT_NAME` for a variant build. `crates/fleet-agent/build.rs` validates it against
   the intersection of the systemd-unit, launchd-label, SCM-name and directory-name grammars —
   lowercase `[a-z0-9-]`, 1–32 characters, no leading or trailing `-`, never a Windows reserved
   device name (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`) — and **fails the build**
   on a name that breaks it, so an illegal name cannot reach a service manager. The display name,
   default **`OpAMP Fleet Agent`**, is the constant `PRODUCT_TITLE`, overridable with
   `OPAMP_PRODUCT_TITLE` and only required to be non-blank: it is prose, cannot be derived from the slug by any rule that would
   read correctly for the next variant, and appears only where prose belongs — the Add/Remove
   Programs entry, the SCM's display column and the installer dialog's title. It is not the Agent
   type, so the fleet view never prints one word in both columns
   ([ADR-0016](0016-what-an-agent-reports-about-itself.md)).

3. **The service is `PRODUCT_NAME`, with no suffix, on every platform.** The label is a single
   token — no qualifier, no organization — so `service-manager` renders the same string for
   systemd, launchd and the SCM, and the name never contains a dot. The `PATH` symlink is
   `/usr/bin/<PRODUCT_NAME>`, so two variants never collide on one `PATH` entry. On Windows the
   SCM additionally carries the display name and a Description that says what the program does.

4. **Three names sit side by side, and none is derived from another.**

   | Name | Names | Appears in |
   |---|---|---|
   | `PRODUCT_NAME` (`opamp-fleet`) | the **product** | the install path, the service, the `.deb`/`.rpm` package, the `/usr/libexec/<PRODUCT_NAME>/` and `Program Files\<PRODUCT_NAME>` payload directories, the `PATH` symlink |
   | `supervisor` (`layout::COMPONENT`, `BINARY_FILENAME`) | the **program** | the file, its configuration `supervisor.toml`, the version directories, the archive member |
   | `supervisor` (`CLIENT_AGENT_TYPE`) | the **Agent type** | `service.name` on the wire, the package Set's key |

   The program's and the Agent type's names are those of clauses 27 and 25; they share a string
   and are separate constants. Keeping the program's name off `PRODUCT_NAME` is what lets **one published
   package Set update every variant build**: the archive member a self-update extracts is the same
   in all of them.

5. **A second installation is a second build.** A variant has its own `PRODUCT_NAME` and therefore
   its own service name, package name, `/usr/libexec` payload directory, `PATH` symlink and MSI
   `UpgradeCode`. The `UpgradeCode` is the one identity that cannot be derived: each variant mints
   one GUID once and records it, because Windows Installer treats a shared `UpgradeCode` as an
   instruction to remove the other installation. An installation is an isolation boundary —
   separate Server, client identity, lifecycle and rollback. Scaling the number of *managed* Agents is
   the multiplexing inside one installation
   ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)); two variants on one host are told apart by
   `service.instance.name` ([ADR-0016](0016-what-an-agent-reports-about-itself.md)).

6. **There is no instance flag.** `--instance` is not a flag at all — not hidden, not accepted and
   ignored — so a command line carrying it fails to parse, and no registered service carries it.
   `service uninstall | start | stop | status` take no name: with one service per build there is
   nothing to look up. The name grammar of clause 2 is also the grammar of `[[supervisor]]` block
   names (`cli::parse_instance_name`).

7. **The install path is `<base>/<PRODUCT_NAME>`, one level, never fixed.** It is named by the
   product, never by its display name.

   | Platform, scope | Executable layout | Data |
   |---|---|---|
   | Linux, system | `/opt/<PRODUCT_NAME>` | `/var/lib/<PRODUCT_NAME>` |
   | Linux, user | `$XDG_DATA_HOME/<PRODUCT_NAME>` (else `~/.local/share/…`) | same |
   | macOS, system | `/Library/Application Support/<PRODUCT_NAME>` | same |
   | macOS, user | `~/Library/Application Support/<PRODUCT_NAME>` | same |
   | Windows, system | `%ProgramData%\<PRODUCT_NAME>` | same |
   | Windows, user | `%LOCALAPPDATA%\<PRODUCT_NAME>` | same |

   The MSI's payload directory is `C:\Program Files\<PRODUCT_NAME>`; it is not the layout
   (clause 8).

8. **Program and data split only on Linux at system scope, and only where the platform gives a
   reason.**
   - **Linux:** the executable layout is under `/opt`, whose default file context `usr_t` is an
     entrypoint type through which systemd starts a third-party service in
     `unconfined_service_t`. Every version the self-update stages later inherits that label, so
     staging needs no SELinux tooling, no policy module and no new runtime dependency — a label
     applied once at install time would expire at the next staged version or relabel. FHS 3.0
     places add-on software under `/opt` and its variable data under `/var`, so the split is the
     standard layout. The data root stays in `/var/lib`.
   - **Windows does not split.** The MSI delivers its payload to `Program Files\<PRODUCT_NAME>` and
     then runs the same `service install` the command line would, which builds the layout and the
     data under `%ProgramData%\<PRODUCT_NAME>`. The layout is not put in `Program Files`: the
     service's own account must be able to write it (clause 13), and granting a low-privileged
     account modify rights on a `TrustedInstaller`-owned tree it executes from is a
     privilege-escalation surface. The line is the one the Linux packages draw between the
     package-owned `/usr/libexec/<PRODUCT_NAME>/` payload and the program-owned `/opt` layout
     (clauses 36 and 38). The MSI passes no root flag,
     so no directory property reaches a command line, and an MSI host and an archive host put the
     same things in the same places.
   - **Two flags.** `--root` names the layout root; given **alone** it collapses layout and data
     into that one directory, whose labelling and permissions are then the operator's business.
     `--data-root` names the data root; alone, it moves only the data. A packaged install passes
     neither and takes the platform defaults.
   - **What a package removal takes.** On **remove** the layout root and the `PATH` symlink — they
     hold nothing but staged binaries — and on **purge** additionally the data root, with the
     configuration and the identity in it. On Windows the MSI's uninstaller empties only
     `INSTALLFOLDER`, and the data under `%ProgramData%` survives: the same remove-versus-purge
     shape. An install rooted elsewhere with `--root` is manual, and no package touches it.

9. **The executable layout is versioned side by side behind a `current` pointer.**

   ```text
   <layout root>/versions/supervisor-<MAJOR.MINOR.PATCH>-<hash>/supervisor[.exe]
   <layout root>/versions/supervisor-…/manifest.toml   # full version string, binary SHA-256
   <layout root>/current -> versions/supervisor-…/      # symlink on Unix, junction on Windows
   ```

   The directory name is the bare base and the commit short-hash of
   [ADR-0012](0012-versions-resolved-in-the-internal-crate.md)'s version, never the pre-release: the release `1.2.3` and a
   development build heading for it are told apart by their commit, and the manifest's full string
   answers release-or-dev. The service's program is `<layout root>/current/supervisor`, so a
   version switch never re-registers anything. On Unix the pointer is switched atomically — a
   temporary symlink `rename`d over `current`, never unlink-then-relink; on Windows the junction
   (which needs no symlink privilege) is recreated only while the service is stopped. At start the
   daemon verifies that `current` resolves to the version directory it runs from and repairs a torn
   switch. Staging a version already present replaces its contents and rewrites its manifest, and
   skips the write when the staged binary already holds the same bytes (an install arriving through
   the `PATH` symlink runs from that file). The default state directory is `<data root>/state` when
   the configuration names no absolute one. Every path is absolute at install time, and the
   registered command line is `run --service --config <abs> --state-dir <abs>`.

10. **An upgrade on an installed host is a re-registration, never a migration.** `--config` and
    `--state-dir` keep pointing into the data root; only the program path (`ExecStart`) changes;
    the instance's configuration, identity and state never move. A change that would move the data
    root of an installed host must bring its own migration and carries the full weight of this
    rule.

11. **The lifecycle runs over `service-manager`, system scope by default.** System scope is a
    systemd system unit, a launchd `LaunchDaemon` or an SCM service, because a fleet client runs
    without a logged-in user and starts at boot; `--user` is a development opt-in, refused on
    Windows, which has no user-scope services.
    - **Restart on failure, never after an explicit stop**, after 5 seconds and with no retry limit
      — what lets the self-update stop the service and switch `current` without the manager racing
      it. systemd and launchd carry the policy natively (`Restart=on-failure`,
      `KeepAlive{SuccessfulExit:false}`); the crate's `sc.exe` backend discards it, so
      `windows_config` sets SCM recovery actions with the same delay and enables them for non-crash
      failures, and sets the display name (`sc config`) and the Description (`sc description`).
    - **A system-scope install that lacks the rights fails before anything is written** — on
      Windows by probing the SCM for `CREATE_SERVICE` first — with a message saying so.
    - **`install` does not start the service** on launchd and says so, printing the follow-up
      `service start`; launchd `status` is advisory.
    - **`uninstall` deregisters only.** It never deletes the layout, the configuration or the state.

12. **Under the manager the daemon is the same `run` loop.** On Linux and macOS it is a plain
    foreground process: `SIGTERM` and `SIGINT` shut it down gracefully, through the transports, so
    the OpAMP `agent_disconnect` goodbye is sent on a service stop too, well within launchd's
    20-second `ExitTimeOut`; `SIGHUP` is explicitly ignored rather than left to terminate it. On
    Windows a `cfg(windows)` shim on the `windows-service` crate registers the control handler,
    reports `StartPending` → `Running` → `StopPending` → `Stopped`, and runs the identical body. The
    hidden `run --service` marker routes into the SCM dispatcher on Windows and, on every platform,
    says no terminal is watching (clause 22).

13. **The system service may run under an operator-named account, and both roots belong to it.**
    `service install --run-as <account>`, system scope only (it conflicts with `--user`); without
    it the service runs as root under systemd and launchd and as `LocalSystem` under the SCM.
    - **The service runs as the account:** systemd `User=`, launchd `UserName`, both through
      `service-manager`'s `username`; on Windows an `sc config obj=` step in `windows_config`. No
      *Log on as a service* grant is performed: the default policy grants it to
      `NT SERVICE\ALL SERVICES`, built-in accounts carry it, and a gMSA receives it from its
      domain; a host hardened against the default grant must restore it.
    - **Windows accepts only passwordless forms:** the service's own virtual account
      `NT SERVICE\<PRODUCT_NAME>` (recommended), a gMSA (`name$`), or
      `NT AUTHORITY\LocalService` / `NetworkService`. There is no password parameter — it would
      stand in the process list and the installer log — and a form needing one is refused with a
      message naming the passwordless forms.
    - **The account must already exist** on Linux and macOS; the install refuses before writing
      anything, showing the `useradd --system` line that creates it. Creating accounts is
      packaging's business, not this binary's.
    - **The hand-over covers both roots.** After laying out and registering, the install hands the
      account the data root (`supervisor.toml`, `state/`), because the service reads and rewrites
      them, and the layout root (`versions/`, `current`), because the self-update that stages into
      it is the service itself — `chown` on Unix (symlinks re-owned as links), an inheritable Modify
      ACL grant on Windows. Where the roots coincide this is one operation; where they split, an
      install that hands over only one has not succeeded. Re-running `install` with another
      `--run-as` re-owns the same directories.

14. **Without `--config`, the configuration is `<data root>/supervisor.toml`.** One rule for every
    platform, and the absolute path registered is the one just written. An explicit `--config`
    wins; because the flag has a default value, the two cases are told apart by clap's value
    source, not by comparing with the default string.

15. **Interactivity is an opt-in flag on `install`, and `service config` is the questionnaire
    alone.** `service install --interactive` runs the questionnaire; without it `install` never
    asks anything, because it is the scripted command. `service config` runs the same
    questionnaire against an installed Client and registers nothing: it finds the file as
    `install` does — `--config`, else `<data root>/supervisor.toml` from `--user`, `--root` and
    `--data-root` — and its state directory the way `install` derives it. The file must load
    before the questionnaire asks: one that does not is corrected by hand. Either with a stdin that
    is not a terminal is an **error**, not a fallback — a provisioning run must fail with a message
    rather than hang.

16. **A configuration file that exists is never overwritten, and the questionnaire edits it in
    place.** No installer-supplied answer and no `install` without `--interactive` touches it:
    `install` proceeds with that file and names it. The questionnaire — `--interactive` and
    `service config` alike — offers the value the file holds as the default of every question and
    changes only the keys it asks for; every other key, every comment, the `[[supervisor]]` blocks
    and the self-update consent stay as written. A re-install can never eat the answers typed into
    the first, or the edits made to the file since.

17. **The questionnaire asks only what has no useful default on a fresh host, and offers no
    answer the Client would refuse.**
    - **The Server `endpoint`**, suggesting `wss://127.0.0.1:4320/v1/opamp`. A `ws://` or
      `http://` endpoint is refused unless its host is a loopback IP literal — `127.0.0.1` or
      `::1`; a host name is never loopback, `localhost` included — and the question is asked
      again with a message saying that beyond the loopback the endpoint must be `wss://` or
      `https://`.
    - **The Agent `name`**, reported as `service.instance.name`.
    - **The CA certificate of the Server**, the CA that signed the Server's certificate, written as
      `[tls] ca_file`. It is asked for every `wss://` or `https://` endpoint, without a question
      before it: the Server always presents a certificate of the fleet's own CA
      ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)).
    - **The bootstrap certificate and its private key, only while the Client is not enrolled** —
      while its state directory holds no certificate the Server issued. They are neither copied
      nor written into the file: the questionnaire enrols with them directly against the Server,
      after the file is written. It connects with the pair where it lies, sends the CSR
      ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md) clause 21), prints the
      request's key fingerprint and waits until an operator approves it, then stores the issued
      certificate in the state directory, where the Client looks for it first. An interrupted wait
      leaves the written file and registers nothing; running the questionnaire again asks again
      and resumes the request in flight, printing its fingerprint. A rejected request stays
      rejected for its key, and the wait goes on until it is interrupted: removing the pending key
      and request from the state directory starts a fresh one.
      Where the file already names `[tls] cert_file` and `key_file`, those are the defaults. On an
      enrolled Client neither is asked: the Client renews what it was issued. A certificate
      already issued by the Server's client CA goes in `[tls] cert_file` and `key_file`, by
      editing the file. The pair is required while it is asked: there is no answer without one,
      and a path that names no readable file, here or for the CA, is asked for again. The
      certificate is the one proof the Server admits a peer by
      ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
    - **The answered CA is copied beside the written file**, as `server-ca.pem`, owner-only on
      Unix, and the file names the copy. The configuration then depends on nothing outside its own
      directory for its trust. A copy left by an earlier answer is replaced. The copy is handed
      over to the service account with the file (clause 13).
    - **The package verification key**, the Ed25519 public key written as
      `[packages] verification_key` ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). An empty
      answer is accepted, and the install then says that the Client installs no package, its own
      update included, until a key is configured.

    It asks nothing about the self-update: the file carries `[packages] self_update = true`, and the
    verification key decides whether that takes effect
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)). Everything else is
    written as commented defaults, so the file stays a starting point for hand-editing. The
    non-interactive answers an installer can give — `--endpoint` (clause 42) and `--no-self-update`
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)) — conflict with
    `--interactive`, go through the same renderer, the same endpoint rule and the same
    never-overwrite write, and never include a client identity. A file written from them alone
    therefore fails clause 19 and stays on disk for the operator to complete.

    **No question asks for a credential, and no written file has an `[auth]` section.** The Agent
    plane admits by the client certificate alone
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)), so there is nothing to ask. A
    Client whose `supervisor.toml` still has an `[auth]` section ignores it and sends nothing
    from it, with one startup notice naming the section
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)); `install` keeps such a file
    (clause 16), and the section is never a reason to fail the install or to warn beyond that
    notice.

18. **The written file is treated as holding a secret:** mode `0600` on Unix; on Windows it
    inherits the data root's ACL, administrator-owned at system scope. It holds no credential. It
    may name where a client identity's private key lies, and it may hold `[packages] archive_key`,
    the fleet's archive decryption secret, which an operator adds by editing the file the
    installer created.

19. **The configuration is validated before the service is registered, by the rules the Client
    applies at startup.** The order is write → load through `ClientConfig::load` → enrol, when
    the questionnaire took a bootstrap pair (clause 17) → stage the layout → register, so a broken
    configuration fails at install and not at the service's first start. The load is the one the Client runs at startup: a `ws://` or `http://` endpoint off the
    loopback fails the install, naming the setting. A missing client identity is what the Client
    refuses at startup; the install names it in a warning and registers the service all the same,
    because a packaged install has an endpoint and no client identity to write, and no installer
    starts the service it registers. The service then refuses to run until the file is complete,
    so nothing ever runs unauthenticated. A file that already exists (clause 16) is validated the
    same way. A written file that fails to load is left on disk and
    named in the error, so a typo is corrected by editing, and a re-run of `install` proceeds with
    the corrected file.

20. **A non-interactive install with no configuration file warns.** Not an error — automation must
    not break — but a printed line naming the path registered and saying the Client refuses to
    start until that file exists with a client identity.

21. **The prompts come from `dialoguer`.** It validates an answer and asks again, offers a
    default and a yes/no confirmation, the same way on three operating systems; `dialoguer` is
    MIT-licensed and brings no TLS or crypto backend. The questionnaire asks for no secret, so no
    prompt hides its input. The terminal check itself is `std::io::IsTerminal`, no dependency.

22. **A Client running as a service writes its own log to a rotating file, on every platform.**
    `run --service` writes it; a foreground run writes stderr alone, because somebody is reading
    it. The file is written on Linux and macOS too, although the journal already holds stderr
    there, so "where are the logs" has one answer everywhere, including a container. It lives in
    `<state dir>/logs/` as `supervisor.<date>.log`: the state directory survives self-updates and
    `uninstall`, so a log explaining a failed start is still there afterwards.

23. **The log is bounded, and `[logging]` is the machine's.** It rotates daily and keeps a fixed
    number of days, 7 by default. `[logging]` in `supervisor.toml` takes `dir` (moves the file),
    `keep` (days kept) and `enabled = false` (off, for an operator whose platform collects stderr).
    `keep = 0` is refused at load rather than read as "forever", and an unknown key fails startup.
    The bound is on age and file count, not bytes: the Client is quiet and backs off when it cannot
    reach the Server. The section never arrives over the wire — a Server able to redirect or silence
    a Client's log could hide its own effects
    ([ADR-0014](0014-connection-settings-offered-without-a-credential-and-server-capabilities.md)).

24. **The file never costs the Client its run.** `tracing` takes one subscriber per process,
    installed before the command line is parsed, so the file layer is installed from the start with
    a writer that discards until the run opens the file; events before that still reach stderr.
    `tracing-appender` (from `tokio-rs/tracing`, beside `tracing-subscriber`) does the rolling,
    non-blocking. A directory that cannot be written or a full disk is reported once and the Client
    runs without the file.

### The name

25. **The Agent type is `supervisor`** — the constant `CLIENT_AGENT_TYPE` every Client reports as
    `service.name` ([`agent.rs`](../../crates/fleet-agent/src/supervisor/agent.rs)), the same on every
    host, because every Client in a fleet is the same kind of thing.

26. **The package that carries the Client is `supervisor` too.** The self-update takes only the
    package named after the Agent type ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause 2), and a Server offers a
    package under the Agent type it is built for ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)) — so
    the release a fleet uploads for its Clients is a package for Agent type `supervisor`, and no
    per-host setting is needed. A Configuration carrying the Client's `[[supervisor]]` blocks
    ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)) is typed `supervisor` as well.

27. **The program is `supervisor`.** `supervisor.exe` on Windows: the binary Cargo builds
    (`[[bin]] name = "supervisor"` in the package `fleet-agent`), the file in every version directory
    (`supervisor-<MAJOR.MINOR.PATCH>-<hash>`), the member a package artifact carries, the payload file
    under `/usr/libexec/<PRODUCT_NAME>/`, the log file, the self-check token and the CLI's own name.
    The configuration file is **`supervisor.toml`**, and the `--config` default with it. What names
    an *installation* — the install path, the service, the dpkg/rpm package, the `PATH` symlink — is
    the product's name, not the program's
    (clauses 2–4). The program's name is not
    derived from the product's, so one published package serves every variant build: the member a
    self-update extracts is the same in all of them. Two names deliberately stay where they are: the
    Cargo package `fleet-agent`, a build-time identifier that never leaves the repository, and the OTLP
    instrumentation scope `opamp-fleet-client`, which names the library a signal came from —
    renaming it would move every operator's dashboards.

28. **The instance name is a separate attribute, and its default is `Supervisor Agent`.** The
    top-level `name` is the operator's name for *this* Client, reported as `service.instance.name`
    ([ADR-0016](0016-what-an-agent-reports-about-itself.md)). Its default is a display name — spaces
    and capitals — and deliberately not `supervisor`: a default equal to the type would print the
    same word in both columns of the fleet view. Nothing resolves a path or a service from this key.

29. **One name per thing, with no alias.** No artifact carries the program twice, no version
    directory holds a compatibility link, and the loader reads no configuration file but the one it
    is given. **A Client that finds no `supervisor.toml` at its configured path but a `client.toml`
    beside it refuses to start**, naming both paths and the `mv` that fixes it: coming up on defaults
    there — dialling the development endpoint and managing nothing — is the one outcome nobody would
    see. An artifact whose member is not `supervisor` is refused by the self-update and the host
    stays on the version it runs.

### The release

30. **A release is one workflow run that builds five targets from one version.** The version and its
    `version/*` tag are decided as [ADR-0012](0012-versions-resolved-in-the-internal-crate.md) states. A first job decides the
    number, builds the Client and asks it `--version`; every artifact is named from that one answer,
    and each target's build asserts its own binary reports the same full version (except the
    cross-compiled macOS x86_64 build, which the runner cannot execute). Every job checks out with
    full history so the baked version is the tag's. A `workflow_dispatch` dry run — the default —
    builds and packs everything, uploads it to the workflow run, and tags and publishes nothing.

    | target | runner | `<os>` | `<arch>` |
    |---|---|---|---|
    | `x86_64-unknown-linux-gnu` | `ubuntu-latest` | `linux` | `amd64` |
    | `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | `linux` | `arm64` |
    | `aarch64-apple-darwin` | `macos-latest` | `darwin` | `arm64` |
    | `x86_64-apple-darwin` | `macos-latest` (cross) | `darwin` | `amd64` |
    | `x86_64-pc-windows-msvc` | `windows-latest` | `windows` | `amd64` |

    Both Linux architectures because arm64 servers are ordinary; both macOS architectures because
    Intel Macs are still deployed, the Intel one cross-compiled from the arm runner rather than
    depending on an Intel runner label that keeps being retired. **Windows on arm64 is out** until a
    deployment asks for it; adding it is one row.

31. **Every archive is a `.tar.gz` written by `opamp-fleetctl package pack --format tar.gz`,** the
    operator tool the same run builds and publishes
    ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)). The packer
    names the single member after the program, with its executable mode, so **the Client's release archive is a
    valid package artifact unmodified**: the operator uploads the file they downloaded, and the
    SHA-256 the packer prints is both the published checksum and the hash an Agent verifies
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). `.tar.gz` because it is the container every
    other agent's package ships as and the one that carries the executable bit and unpacks the same
    way on every platform. `.7z` remains a package container the Client opens and the packer writes,
    including encrypted ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)); a release has no use for
    encryption.

32. **Every asset of the Client is named `supervisor_<version>_<os>_<arch>.<ext>`,** and the
    operator tool's by the same grammar under its own name (ADR-0028). Four fields separated by `_`:
    the package name, the base version `MAJOR.MINOR.PATCH` without build metadata, and the platform
    in the vocabulary an Agent reports as `os.type` and `host.arch`
    ([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)). **All artifacts of a target share the stem** and differ
    in extension alone:

    | | artifact |
    |---|---|
    | archive | `supervisor_1.2.3_linux_amd64.tar.gz` |
    | Debian | `supervisor_1.2.3_linux_amd64.deb` |
    | RPM | `supervisor_1.2.3_linux_amd64.rpm` |
    | Windows | `supervisor_1.2.3_windows_amd64.msi` |

    `_` because it is the one separator no field contains: the name grammar is `[a-z0-9-]` and SemVer
    spells a pre-release with `-`, while neither admits `_`. It is also the shape an operator already
    reads — GoReleaser's default, the Collector's own `otelcol_<version>_linux_amd64.tar.gz`,
    Debian's `<package>_<version>_<arch>.deb`. Where a platform is a *tag* rather than a field of a
    file name — the store's `<os>-<arch>.bin`, the fleet view's platform column — it stays
    `<os>-<arch>`, for the mirror-image reason. Inside the `.deb` and `.rpm` the architecture is the
    ecosystem's own (`amd64`/`arm64`, `x86_64`/`aarch64`), derived by the packaging tool; nothing
    resolves a package by its file name. **A published asset is never renamed or rewritten**: a
    checksum published against a URL stays true.

33. **A file name is read from the right, and an unknown tail fills nothing.** The fleet view's
    upload form reads an artifact's name by matching the platform tokens it knows — including the
    aliases `x86_64`, `aarch64`, `macos` — at the end of the stem, separated by `_` or `-`; the
    version starts at the first separator followed by a digit, and the rest is the name. A tail it
    does not know fills no field rather than a guess, because a wrong platform is an entry no Agent is
    ever offered. Accepting `-` serves upstream artifacts named by upstream. The release notes' upload
    loop selects the `supervisor_` stem and splits the rest on `_`, so it needs to be told no platform.

34. **What is published.** A GitHub release named after the version holds the Client's five
    archives, the two `.deb`, the two `.rpm`, the `.msi`, the four archives of the operator tool
    (ADR-0028) and one `SHA256SUMS` covering every asset. The notes say which file is for which
    purpose, give the per-platform install commands and the procedure that uploads the Client's
    archives, selected by their `supervisor_` stem, as one package for Agent type `supervisor`, and state the full baked
    version string as provenance — the upload uses the release number, since versions are compared
    without build metadata ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)). Nothing is signed. A change to the asset
    names or containers breaks operators' scripts and is named in `CHANGELOG.md` and the release
    notes of the release that carries it.

### The installers

35. **Three classes of asset, and only one is a package artifact.** The Client's archive is opened
    by the Client on a self-update and parsed by the fleet view; the operator tool's archives
    ([ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)) are
    downloaded to an operator's machine and are no package of the fleet; the `.deb`, `.rpm` and `.msi` are opened by
    `dpkg`, `rpm` and Windows Installer and by nothing in the fleet path. The installers are
    **additive operator artifacts**: they never replace the archive, which is the only format the
    fleet can install.

36. **The package delivers one file; `service install` installs.**

    | | delivers | after install | before removal |
    |---|---|---|---|
    | `.deb` / `.rpm` | `/usr/libexec/<PRODUCT_NAME>/supervisor` | `… service install` | `service stop`, then `service uninstall` |
    | `.msi` | `INSTALLFOLDER\supervisor.exe` | `… service install [--endpoint <ENDPOINT>] [--no-self-update]` | `service stop`, then `service uninstall` |

    **No package ships a systemd unit, a `LaunchDaemon` or an MSI `ServiceInstall` element**;
    `cargo-deb`'s `systemd-units` and WiX's `ServiceInstall`/`ServiceControl` are deliberately unused.
    There is one install path on every platform. The ownerships are disjoint by construction: the
    package owns its payload and never anything in the layout; `service install` stages a *copy* into
    the layout, which is what the service runs and what a self-update replaces, so `dpkg -V` and
    `rpm -V` stay quiet through every fleet update. The pre-removal runs only on a real removal — on
    an upgrade it falls straight through, because the successor's post-install re-runs
    `service install`, and unregistering would stop a managed host in the middle of `apt upgrade` —
    and it calls the payload path, never the symlink, and tolerates a service already unregistered.
    The dpkg/rpm package identity is `PRODUCT_NAME` and the MSI's is its display name and
    `UpgradeCode`, so an `apt`, `dnf` or MSI upgrade stays an upgrade.

37. **No installer starts the service it registers.** The Linux post-install and the MSI register the
    service and leave it stopped — knowingly departing from Debian Policy and `dh_installsystemd` —
    because a Client with no configuration holds no client certificate and is refused at startup,
    at fleet scale where nobody watches a terminal. The one exception is an upgrade of a
    Linux host whose service was running: it is restarted, so a configured host finishes the
    upgrade on the delivered binary. The post-install prints the two remaining steps:

    ```console
    sudo opamp-fleet service install --interactive
    sudo systemctl start opamp-fleet
    ```

    The second `service install` is a re-install, which is idempotent and writes the configuration
    that `service install` refuses to overwrite once it exists. The first step is `--interactive`,
    which asks for the client identity — the bootstrap certificate and its private key —
    and not `--endpoint` alone: a configuration holding only an endpoint is one the Client refuses
    at startup, so printing it as the whole first step would present an unauthenticated Client as
    the default. The alternative it prints for writing the file by hand names the endpoint together
    with `[tls] cert_file` and `key_file`, the identity the operator adds before the start, and
    names no credential and no `[auth]` section, because the Client reads none
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).

38. **The CLI on `PATH` is a symlink through `current`, and a package removal takes the layout.**
    `/usr/bin/<PRODUCT_NAME>` → `/opt/<PRODUCT_NAME>/current/supervisor`, so the operator's first
    diagnostic command answers for the binary the service runs, not for the one the package
    delivered. It is laid by the maintainer scripts, which both formats honour, rather than shipped
    as a packaged file:

    | hook | does |
    |---|---|
    | `postinst` / `%post` | `service install`, then `ln -sfn` the symlink |
    | `%posttrans` (rpm only) | `ln -sfn` again — rpm erases the old package's files *after* the new `%post`, which may take the link; dpkg removes them during unpack and needs nothing |
    | `postrm` / `%postun`, real removal only | remove the symlink (only if it is one), and the layout root `/opt/<PRODUCT_NAME>` with every staged version and `current`; on dpkg **purge**, also the data root `/var/lib/<PRODUCT_NAME>` |

    A removal keeps the data root — the Agent's identity and the configuration the operator wrote
    are not binaries, and a reinstall picks them up — while the layout goes, so a reinstall comes up on the
    package it installed rather than on a surviving `current`. Purge is dpkg's "leave nothing"; rpm
    has none. `service uninstall` itself still deletes nothing
    (clause 11); this cleanup is the package's. Re-staging
    **skips the write when the staged binary already holds the running bytes**, because
    `service install` invoked through the symlink runs from the very file it would overwrite and Linux
    refuses that (`ETXTBSY`). Symlink and cleanup name the default system roots only — the only roots
    a packaged install uses; an install rooted with `--root` is a manual one and nothing packaged
    touches it.

39. **The MSI asks for the installation folder, the endpoint and the self-update consent, all as
    public properties.** The UI is a copy of the stock `WixUI_InstallDir` set with one dialog inserted —
    `WelcomeDlg → InstallDirDlg → EndpointDlg → VerifyReadyDlg` — and **no licence page**: neither
    MIT nor Apache-2.0 needs a click-through, and the dialog wants a second copy of the licence as
    RTF. It is a copy with
    the navigation re-pointed, as WiX's customization guide prescribes, because overriding a stock
    set's rows in place depends on control-event ordering the toolset may renumber.

    | property | dialog | effect |
    |---|---|---|
    | `INSTALLFOLDER` | `InstallDirDlg`, via `WIXUI_INSTALLDIR` | where the payload goes; default `C:\Program Files\<PRODUCT_NAME>` |
    | `ENDPOINT` | `EndpointDlg`, an `Edit` control | `service install --endpoint`; empty means none |
    | `SELFUPDATE` | `EndpointDlg`, a checkbox, default `1` | the consent of [ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause 3 |

    `INSTALLFOLDER` is **one directory the operator configures**, holding only the delivered payload.
    The layout and the state directory go to `%ProgramData%\<PRODUCT_NAME>` and no root reaches the
    command line (clause 8), so an uninstall empties the
    folder and the configuration survives where Windows expects data to. All names are upper-case and
    listed `Secure`: Windows Installer resets private properties between the UI and execute sequences,
    and `Secure` lets the same MSI run unattended:

    ```console
    msiexec /i supervisor_1.2.3_windows_amd64.msi /qn ^
      ENDPOINT="wss://fleet.example.com/v1/opamp" SELFUPDATE=0
    ```

    Registration is a **deferred type 18 custom action with `Impersonate="no"`**, after
    `InstallFiles` — the executable it runs is the one being installed — whose formatted command line
    receives the properties without a `CustomActionData` round trip. It is two actions under opposite
    conditions on `ENDPOINT`, because `--endpoint ""` is rejected by the loader while no flag is the
    ordinary configure-later install. Stop and unregister run only on a real uninstall
    (`REMOVE="ALL"`), best-effort, before `RemoveFiles`. **The `UpgradeCode` is minted once and never
    changed** — it is how Windows Installer recognises 1.2.4 as an upgrade of 1.2.3, and a new one
    strands every installed host — paired with `MajorUpgrade`, with the `ProductCode` regenerated per
    build. The MSI asks for no client identity: the certificate and its key are files the
    operator puts on the host, and `EndpointDlg` says that they are added to `supervisor.toml`
    afterwards, or through `service install --interactive` from an elevated prompt. It mentions no
    credential, because the Client reads none
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).

40. **The endpoint dialog is prefilled with the development Server, interactively only.** A
    `SetProperty` in the UI sequence, conditioned on `ENDPOINT` unset and the product not installed,
    sets `wss://127.0.0.1:4320/v1/opamp`. A silent install that names no `ENDPOINT` still writes no
    configuration, so unattended deployment never acquires the development default by omission; a
    command-line value wins; clearing the field is the configure-later answer. The value is the
    loader's default verbatim. `http://localhost` does not qualify on either count: the Agent plane
    always serves TLS, so a development Server answers no plaintext request, and `localhost` is a
    host name, which is never the loopback — only the IP literals `127.0.0.1` and `::1` are — so the
    Client would refuse the value at startup. The scheme selects the transport
    ([ADR-0013](0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)), so the click-through install
    runs WebSocket, as an unconfigured Client would. Like every value an installer writes, the
    prefill passes the rule the Client applies at startup (clause 42).

41. **What builds the installers.** Additional steps in the release's `build` matrix job, after the
    archive is packed, consuming the binary that job built — so the bytes in a `.deb` are provably
    the bytes in the archive:

    | | tool | runs on |
    |---|---|---|
    | `.deb` | `cargo-deb`, `--no-build --no-strip` | both Linux runners, natively |
    | `.rpm` | `cargo-generate-rpm`, no `rpmbuild` needed | both Linux runners, natively |
    | `.msi` | WiX Toolset 6 as the `wix` .NET tool, with its UI extension | the Windows runner |

    Package metadata lives in `crates/fleet-agent/Cargo.toml` under `[package.metadata.deb]` and
    `[package.metadata.generate-rpm]`, reading the workspace's version, licence and description;
    `cargo-deb` derives `Depends` from what the binary links (`$auto`). The RPM `Release` is `1` and
    stays `1`, and no epoch or `~` mangling is needed, because a version is released once and is
    always `MAJOR.MINOR.PATCH` ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md)). The maintainer scripts live in
    `packaging/linux/`, the WiX sources in `packaging/windows/`.

42. **`service install --endpoint <URL>` writes the first configuration without a terminal.** It
    writes the file `--interactive` writes, through the same renderer, with the endpoint *given*
    rather than asked: the same shape, mode `0600`, never overwriting an existing file, validated by
    the rule the Client applies to its endpoint at startup before anything is written: a `ws://` or
    `http://` endpoint whose host is not `127.0.0.1` or `::1` is refused, naming the setting, and
    `localhost` is no exception. It conflicts with `--interactive`; it
    carries the self-update answer ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause 3). It
    has no siblings for the CA file or the client identity, and it takes no credential, since
    there is none ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)). The installers
    do not write TOML themselves; one flag on the command that owns the file is the smaller thing.
    **The same rule binds every default an installer supplies:** no installer writes, prefills or
    prints a value the Client would refuse at startup, and none writes a setting that stands in for
    a client certificate, so a configuration an installer leaves incomplete is one the Client
    refuses at startup, never one it runs on unauthenticated.

**Out of scope:** staging, verifying, rolling back and pruning versions in this layout, and the
self-update consent ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)); whether
variant builds are ever published, and where their `UpgradeCode`s are recorded; how an operator
discovers what is installed on a host; creating the `--run-as` account in the packages; a confined
SELinux policy module; configuration reload on `SIGHUP`; `Type=notify` integration; the startup
rules themselves and the Server's enrolment window and approval, which the installer only applies
and names ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)); signing (an Authenticode
certificate for the MSI, a GPG key for the RPM, the archives); hosting apt and yum repositories;
preseeding the endpoint on Linux; a macOS `.pkg`, which needs a Developer ID and notarization;
packaging the Server, which an operator deploys rather than the fleet.

## Alternatives considered

- **Separate installers or OS packages owning the service** (shipping a unit file, wrapping
  `sc.exe`) — spreads the logic across artifacts and gives two registrations that disagree; the
  packages ship the binary and call `service install`.
- **Hand-write the three backends** — three code paths to own; `service-manager` abstracts exactly
  install/start/stop/status/uninstall, and the wrapper stays thin enough to finish what it omits
  (`windows_config`). **A daemonizing crate or double-fork** — Unix-only, and init systems want to
  supervise a foreground process.
- **Register the binary's own path instead of `current`** — every update would re-register the
  service with administrator rights, and Windows locks the running `.exe`.
- **Environment-variable configuration in the unit** — a second, diverging source of truth. **`anyhow`**
  — the crate uses `Result<_, String>` throughout.
- **A runtime instance flag** — no package can pass it, nothing enumerates instances, the running
  process ignores it, and it keeps an extra level in every path. A build variant is something every
  delivery path carries.
- **Keep the product's name a runtime value read from configuration** — it cannot name the
  directory the configuration is read from, and `uninstall` would need the file to find the
  service.
- **Derive the program's name from `PRODUCT_NAME`** — each variant would need its own published Set
  of the same bytes, because the archive member is extracted by name. **Name the program `agent`** —
  the system's word for every managed thing.
- **Keep the Linux layout under `/var/lib` and fix the label** — a persistent file context
  (`semanage fcontext` + `restorecon`) needs `policycoreutils-python-utils`, and a guarded fallback
  fails silently; `chcon` does not survive an autorelabel and puts SELinux tooling in the runtime
  path on every distribution; a shipped SELinux policy module is the heaviest answer (it stays
  possible if a confined domain is wanted — CIS Server Level 2 flags `unconfined_service_t`).
- **The layout under `/usr/lib` or `/usr/libexec`, or in `Program Files`** — the package manager's
  and the installer's hierarchies are theirs; a layout rewritten at runtime does not belong there,
  and on Windows it would need a privilege-escalating grant.
- **Everything, state included, under `/opt`** — parks variable data in `/opt` against FHS and gives
  back the `Program Files` problem on the other platform.
- **Root/`LocalSystem` only** — refused; least privilege is the requirement. **systemd
  `DynamicUser=`/`StateDirectory=`** — Linux-only, and ephemeral UIDs fight an identity that must
  persist. **Windows accounts with a password** — the password stands in the process list and the
  installer log. **A root-owned layout with self-update disabled under `--run-as`** — breaks goals
  10 and 11 for exactly those installs. **A privileged updater helper** — a second service, an IPC
  surface and a privilege boundary for one flag. **Creating the account in `service install`** —
  three platform APIs for what packaging does in one line.
- **A separate `config init` command** — a second entry point and a second place resolving the
  path. **Interactive by default with `--non-interactive`** (Elastic Agent's shape) — would hang
  every scripted install. **Overwrite with `--force`** — discards answers typed once and the edits
  made since. **`read_line` without a dependency** — re-implements validation, defaults and asking
  again for every question. **`inquire`, `cliclack`** — more than the questions need. **Ship an example configuration in the artifact** —
  it still has to be edited before the service does anything.
- **An installer that may write an unauthenticated or plaintext configuration** — the Client
  refuses that file at startup, so the installer would register a service that cannot start, and
  an answer without a client identity or a `ws://` default teaches the insecure setup as the
  normal one.
  **Treat `localhost` as loopback** — a name resolves through whatever the host's resolver says,
  so only the IP literal guarantees the traffic stays on the host.
- **Keep asking for the fleet credential, as optional, for a Server that still requires it** — the
  Agent plane no longer reads one ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)),
  and the upgrade order is the Server first, so a question kept for older Servers would teach a
  setting nothing reads.
- **Remove a leftover `[auth]` section at install, or refuse the file** — `install` never rewrites
  a file that exists (clause 16), and refusing the section would stop a self-updated Client,
  whose file still has it, from connecting on a host nobody watches; the Client ignores the
  section and says so at startup.
- **The Windows Event Log** — an event source registered at install time, a message resource, and a
  code path only one platform exercises. **A file only on Windows** — makes "where are the logs"
  platform-dependent and leaves containers without one. **Rely on the OTLP own-logs bridge**
  ([ADR-0016](0016-what-an-agent-reports-about-itself.md)) — needs a reachable Server, so it cannot explain the failures
  that prevent one. **Size-based rotation** — `tracing-appender` does not offer it. **`keep = 0` as
  unlimited** — the setting that fills a disk. **Remotely configurable logging** — the Client's own
  configuration stays on the machine. **The log in the version directory** — a self-update would
  scatter it and a rollback take it away.
- **Keep a product name such as `opamp-fleet-client` for the type, the package and the program.**
  The type would repeat a product name the row already carries as its instance name, and the fleet
  could not say what the Client *is*.
- **A reverse FQDN type, `io.opamp-fleet.supervisor`.** A recommendation enforced nowhere else here,
  in a table column where the short form is what gets read.
- **Rename only some layers.** A package name that is not the type splits the self-update's one
  rule into two names; a release named after the product does not fit the type a Client reports; a
  program named differently from its type is the doubled vocabulary this ends.
- **A transitional release carrying both program names.** Re-creates one file with two names in the
  packer, the layout, the loader and the documentation, and needs a second decision about when to
  withdraw the old one.
- **`.7z` releases, or a split container** (`.tar.gz` on Unix, `.zip` on Windows). The Client cannot
  open a `.zip`; `.7z` is a second container where every other agent ships `.tar.gz`.
- **Hyphen-separated file names with a parsing heuristic.** One separator cannot both occur inside a
  field and delimit it; `otelcol-2-1.0.0-linux-amd64` has no right answer.
- **`name_version_os-arch`**, the tighter grammar. A fourth shape nothing else writes, against a
  convention operators read fluently.
- **A sidecar manifest per artifact.** An operator hands one file to a Server; it must describe
  itself.
- **The package owns the whole install** — a shipped unit, `/etc` configuration, an MSI
  `ServiceInstall`. Forks the install path per platform and puts the self-update in conflict with the
  package manager over the same files; a fleet update reverted by `apt upgrade` is worse than no
  package.
- **`nfpm`** for `.deb` and `.rpm`. A good tool and a close call; a second ecosystem's binary to pin,
  restating the metadata the cargo subcommands read from `Cargo.toml`. Worth reconsidering when a
  third format is wanted.
- **`cargo-wix`.** The `.wxs` is hand-written either way for a custom dialog and action, and it
  predates WiX v6. A WiX Burn bundle is awkward in Intune, Group Policy and SCCM.
- **Per-ecosystem file names** (`…-1.2.3-1.x86_64.rpm`). Nothing resolves an RPM by its file name;
  the ecosystem vocabulary survives inside the package metadata.
- **A launcher shim at `/usr/bin`, or `service install` writing `/usr/bin` itself.** A second code
  path to do what one symlink does; and an application writing into the package manager's directory
  crosses the ownership line, while a custom-root install must not touch `/usr/bin`.
- **An MSI endpoint default in both sequences.** Pins every silent install to the loopback.
- **Keep `http://localhost:4320/v1/opamp`, or prefill `http://127.0.0.1` for HTTP polling.** The
  first is plaintext to a host name, which the Client refuses at startup; the second is plaintext
  to a Server whose Agent plane answers only TLS. `https://127.0.0.1` would work, but a second
  value beside the loader's default is one more thing to keep from drifting, and the two are
  pinned by test either way.
- **Let `service install --endpoint` write what the loader merely parses, and leave the security
  rule to the start.** The operator would learn at the first start, on a host nobody watches, what
  the installer could have refused while they were at the keyboard.
- **Rename the dpkg/rpm identity or `UpgradeCode` with the program.** Costs every host a second
  product beside the first.
- **Name the build variables for this project (`OPAMP_FLEET_PRODUCT_NAME`, …)** — a build of
  `acme-agent` would set a variable that names a product the build is not.
- **No prefix (`PRODUCT_NAME`, `PRODUCT_TITLE`)** — common in other toolchains: Xcode exports
  `PRODUCT_NAME` to every build phase, and a stray slug would pass the grammar of clause 2 and
  silently rename the service and move the install path. `OPAMP_` names the protocol, not the
  product, so it holds in every variant.

## Sources / Prior art

- Specification Mission, Strategy and goals 10 and 11 ([`docs/SPECIFICATION.md`](../SPECIFICATION.md));
  Strategy "Security before convenience" and Q-1 "Secure by default".
- Loopback names: [RFC 6761 §6.3](https://www.rfc-editor.org/rfc/rfc6761#section-6.3) (`localhost`
  resolution left to the resolver) and
  [draft-ietf-dnsop-let-localhost-be-localhost](https://datatracker.ietf.org/doc/draft-ietf-dnsop-let-localhost-be-localhost/).
- [`service-manager`](https://docs.rs/service-manager/) and its
  [changelog](https://docs.rs/crate/service-manager/latest/source/CHANGELOG.md) (`RestartPolicy`,
  launchd `install` not auto-starting, `ServiceInstallCtx.username` honoured for systemd and
  launchd only); the launchd status bug
  <https://github.com/chipsenkbeil/service-manager-rs/issues/41>.
- [`windows-service`](https://docs.rs/windows-service/), used by Vector
  (<https://github.com/vectordotdev/vector/pull/2896>) and Mullvad; Windows error 1053
  (<https://learn.microsoft.com/en-us/answers/questions/1389851/>);
  [`SERVICE_STATUS`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status);
  service names ([`GetServiceKeyName`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-getservicekeynamea)).
- Versioned directories and a pointer: Elastic Agent's `<component>-<version>-<hash>` directories
  and upgrade design (<https://github.com/elastic/elastic-agent/blob/main/docs/upgrades.md>); Scoop's
  `current` junction (<https://github.com/ScoopInstaller/Scoop/wiki/The-'Current'-Version-Alias>);
  the Chromium updater (<https://chromium.googlesource.com/chromium/src/+/main/docs/updater/design_doc.md>);
  atomic symlink replacement (<https://blog.moertel.com/posts/2005-08-22-how-to-change-symlinks-atomically.html>).
- systemd [unit names](https://man7.org/linux/man-pages/man5/systemd.unit.5.html),
  [kill](https://man7.org/linux/man-pages/man5/systemd.kill.5.html),
  [daemon(7)](https://man7.org/linux/man-pages/man7/daemon.7.html) on `SIGHUP`,
  [`Restart=on-failure`](https://man7.org/linux/man-pages/man5/systemd.service.5.html); launchd
  (<https://www.launchd.info/>, launchd.plist(5)); Telegraf's Windows service
  (<https://github.com/influxdata/telegraf/blob/master/docs/WINDOWS_SERVICE.md>); the
  `WaitToKillServiceTimeout` budget
  (<https://kb.firedaemon.com/support/solutions/articles/4000086193-increasing-service-shutdown-time>);
  [clap derive](https://docs.rs/clap/latest/clap/_derive/index.html).
- SELinux: `status=203/EXEC` (<https://thomaspowell.com/2026/04/03/the-selinux-203-exec-systemd/>,
  <https://github.com/actions/runner/issues/1606>); `unconfined_service_t`
  (<https://danwalsh.livejournal.com/70577.html>,
  <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/sect-security-enhanced_linux-targeted_policy-unconfined_processes>,
  CIS: <https://access.redhat.com/solutions/6714611>); openSUSE Leap 16.0 enforcing by default
  (<https://doc.opensuse.org/release-notes/x86_64/openSUSE/Leap/16.0/html/release-notes-leap-160/index.html>);
  FHS 3.0 `/opt` (<https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s13.html>); Elastic Agent
  in `/opt/Elastic/Agent` (<https://www.elastic.co/docs/reference/fleet/installation-layout>).
- Microsoft's `Program Files` / `ProgramData` guidance; Windows Installer `UpgradeCode` semantics
  (`MajorUpgrade`, `FindRelatedProducts`, `RemoveExistingProducts`); `cargo-deb` variants and
  `cargo-generate-rpm --set-metadata` for differently named packages from one tree; Elastic Agent
  and Telegraf ship one product per package, multiple instances being multiple installations.
- Service accounts: [Service User Accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts),
  [virtual accounts](https://docs.delinea.com/online-help/privilege-manager/install/upgrades/virtual-accounts.htm),
  [`sc config`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config),
  [`ChangeServiceConfig`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfiga);
  [Elastic Agent unprivileged mode](https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged).
- First configuration: [Elastic Agent command reference](https://www.elastic.co/docs/reference/fleet/agent-command-reference)
  (`install` prompting, `--non-interactive`, `--force` overwriting — the two behaviours inverted
  here); [`dialoguer`](https://crates.io/crates/dialoguer); [`inquire`](https://crates.io/crates/inquire);
  [Rust CLI prompts compared](https://fadeevab.com/comparison-of-rust-cli-prompts/);
  [`std::io::IsTerminal`](https://doc.rust-lang.org/stable/std/io/trait.IsTerminal.html);
  [machine communication](https://rust-cli.github.io/book/in-depth/machine-communication.html),
  [isatty](https://blog.jez.io/cli-tty/); the OpenTelemetry `opampsupervisor`
  (<https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/cmd/opampsupervisor>),
  which has no scaffolding command.
- Logging: [Elastic Agent logging](https://www.elastic.co/docs/reference/fleet/elastic-agent-standalone-logging-config)
  (logs under its data directory, size rotation); [OpenTelemetry Collector #5300](https://github.com/open-telemetry/opentelemetry-collector/issues/5300)
  (file logging for a Windows service, the Event Log output reported unreliable);
  [`tracing-appender`](https://crates.io/crates/tracing-appender).
- [`opentelemetry-collector-releases`](https://github.com/open-telemetry/opentelemetry-collector-releases)
  and [Install the Collector on Linux](https://opentelemetry.io/docs/collector/install/binary/linux/)
  — per-platform archives plus `.deb`, `.rpm`, `.msi`, named `otelcol_<version>_linux_<arch>`.
- [Elastic Agent install documentation](https://www.elastic.co/docs/reference/fleet/install-standalone-elastic-agent)
  — native packages beside archives, and archives as what its fleet upgrades from.
- [GoReleaser — Archives](https://goreleaser.com/customization/archive/) — the default
  `{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}`.
- [Debian FAQ, package basics](https://www.debian.org/doc/manuals/debian-faq/pkg-basics.en.html) and
  [dpkg-name(1)](https://www.man7.org/linux/man-pages/man1/dpkg-name.1.html);
  [Semantic Versioning 2.0.0](https://semver.org/) — `-` is in a version's alphabet, `_` is not.
- [The Cargo Book, environment variables](https://doc.rust-lang.org/cargo/reference/environment-variables.html)
  — `--target` builds the triple while the packer stays a host build.
- [`cargo-deb`](https://github.com/kornelski/cargo-deb) and its
  [systemd notes](https://github.com/kornelski/cargo-deb/blob/main/systemd.md);
  [`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm);
  [`cargo-wix`](https://crates.io/crates/cargo-wix).
- [WiX Toolset](https://github.com/wixtoolset/wix), the [`wix` .NET tool](https://www.nuget.org/packages/wix),
  [WixUI dialog library](https://docs.firegiant.com/wix/tools/wixext/wixui/),
  [`WixUI_InstallDir`](https://documentation.help/WiX-Toolset/WixUI_installdir.html),
  [adding a dialog to a stock set](https://github.com/orgs/wixtoolset/discussions/8075),
  [customizing built-in dialog sets](https://docs.firegiant.com/wix3/wixui/wixui_customizations/).
- Windows Installer: [Public Properties](https://learn.microsoft.com/en-us/windows/win32/msi/public-properties),
  [Custom Action Type 18](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-18),
  [deferred execution custom actions](https://learn.microsoft.com/en-us/windows/win32/msi/deferred-execution-custom-actions);
  type 51 actions in `InstallUISequence` do not run under `/qn`.
- [Debian Policy, `init.d` scripts and services](https://www.debian.org/doc/debian-policy/ch-opersys.html#system-run-levels-and-init-d-scripts)
  — the enable-and-start convention clause 37 departs from.
- [rpm scriptlet ordering](https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/) —
  the new `%post` runs before the old files are erased; `%posttrans` runs last.
- [FHS 3.0 `/usr/libexec`](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch04s07.html) — binaries
  run by other programs, off `PATH`; Debian's `alternatives` — what users invoke is a link that is
  repointed.
- [OpAMP specification, `AgentDescription`](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md),
  [opamp-spec issue #131](https://github.com/open-telemetry/opamp-spec/issues/131) and the
  [resource semantic conventions, `service.name`](https://opentelemetry.io/docs/specs/semconv/resource/#service).
- Xcode Build Settings Reference, `PRODUCT_NAME` — exported to the environment of every Run Script
  build phase. Recalled, not re-verified.

## Consequences

- Positive: one binary installs, controls and deregisters itself as a native service on all three
  platforms, from any location, and still runs in the foreground. A service stop sends the OpAMP
  goodbye. A self-update stages a version and switches `current` without re-registering.
- Positive: the layout says what it is — `/opt/opamp-fleet/current/supervisor`, the product, then
  the program. An illegal name fails the build, not the host. One Set updates every variant build.
  An MSI host and an archive host put the same things in the same places.
- Positive: the `.rpm` produces a service that starts on Fedora, RHEL and SUSE 16 with SELinux
  enforcing, with no labelling step to keep alive.
- Positive: the Client and every Managed Process it spawns can drop root and `LocalSystem`, with no
  password anywhere in the Windows story.
- Positive: a fresh host goes from a binary to a working, registered service in one command, and
  no secret is typed into the installer at all. A Windows service failure becomes readable, and
  the logs cover failures own-telemetry structurally cannot.
- Positive: the first configuration a fresh host gets authenticates and encrypts beyond the
  loopback; an install never registers a service the Client would then refuse to start.
- Negative / trade-offs: a Windows-only runtime path Unix never exercises; system scope needs root
  or Administrator; launchd `status` is advisory and its `install` does not start; real
  registration runs only in the ignored smoke test and a manual checklist.
- Negative / trade-offs: the Linux system install spans two directories, and `--data-root` is the
  flag that must be right where getting it wrong is silent — `--root` alone on an enforcing host
  roots the binary wherever the operator chose. A host mounting `/opt` `noexec` breaks, loudly.
- Negative / trade-offs: a second installation needs a variant build, a minted `UpgradeCode` and a
  package-name entry; a forgotten `UpgradeCode` fails on a Windows host by removing the other
  installation. Two constants hold `supervisor` for different reasons, and conflating them would
  split the fleet's package Sets.
- Negative / trade-offs: the `--run-as` account is a trust boundary — whoever holds it can replace
  the binary in the layout, and the `PATH` symlink through `current` makes an administrator invoking
  the CLI execute account-owned code. Managed Processes inherit the account, so ports below 1024 and
  root-only telemetry sources fail under it.
- Negative / trade-offs: a configuration cannot be generated without installing; the questionnaire
  is a second place following the configuration schema, for the keys it asks. The log duplicates the
  journal on Linux and macOS, is bounded by days and not bytes, and keeps a week of whatever the
  Client logs on disk, so nothing secret may be logged.
- Negative / trade-offs: the questionnaire asks for a certificate and its key and a verification
  key, and an operator must have them in hand before the first install; on a host not yet enrolled
  it also needs the Server reachable, its enrolment window open and an operator approving the
  request while the command waits. A host that cannot reach the Server at install time is
  installed without `--interactive` and completed by editing the file. A
  scripted install that passes `--endpoint` alone no longer registers a service: it writes the
  file, fails validation, and is completed by editing that file and re-running `install`, or by
  provisioning a complete file first.
- Negative / trade-offs: a host whose file was written with a credential keeps that `[auth]`
  section, secret included, until an operator deletes it: neither `install` nor the Client rewrites
  the file. The startup notice names the section on every start until then.
- Positive: one word for one thing, from the Agent type in the fleet view to the file an operator
  edits; the Client's release is an ordinary fleet package in the container every agent uses.
- Positive: the Client's release archive is installable by the fleet unmodified, so the hash published is the
  hash an Agent verifies; a build that lost its tags fails instead of publishing a `-dev` artifact.
- Positive: first contact is one command per platform — `apt install`, `dnf install`, a double
  click — and removal is real. The installers are wrappers around the one install path, and a
  self-update never fights the package manager.
- Positive: a file name parses back into its four fields, and the fleet view reads upstream
  artifacts and ours with one code path.
- Negative — `supervisor` names three things: the specification's Supervisor inside a Client, the
  Agent type, and the program. Documentation never uses the bare word where a file or unit is meant.
  It is also a common word: Debian's `supervisor` package installs `supervisord`/`supervisorctl`
  and does not collide, but the margin is thin.
- Negative — `dpkg -l` and `rpm -q` report the *delivered* version, which diverges from the running
  one after the first self-update; `opamp-fleet --version` and the fleet view are the truth, and the
  manual must say so. Until `service install` has run the symlink dangles, and a broken-by-hand
  layout makes the CLI fail loudly rather than answer for the wrong binary.
- Negative — `apt install` leaves a stopped service, which a Debian user does not expect; a
  click-through MSI install on a production host gets a loopback configuration rather than a
  warning; and an endpoint-only configuration, from `--endpoint` or the MSI, starts nothing until
  the operator adds the client certificate and its key by hand.
- Negative — the prefill reaches a development Server only when that Server presents a
  certificate the Client trusts for `127.0.0.1`.
- Negative — a platform is spelled `linux_amd64` in a file name and `linux-amd64` as a tag; the
  version in a file name is the base version, so the name is not a unique build identifier.
- Negative — three more build tools, one of them .NET, five targets of which two are not what their
  runner natively is, and nothing signed: Windows shows an unknown publisher and `rpm` reports no
  signature. The `UpgradeCode` cannot be revisited without stranding installed hosts.
- Follow-ups: the service smoke test excludes hosts with SELinux or AppArmor in the way, so nothing
  automated exercises clause 8's reason — the manual checklist covers it; `.deb`/`.rpm` account
  creation and `--run-as` wiring, and a virtual-account option in the MSI; whether `uninstall`
  should offer to remove the configuration and log it created; a size cap beside the day count;
  remotely raising a Client's log level, as a decision of its own; signing; apt and yum
  repositories; Linux endpoint preseeding; a macOS `.pkg`; a `PATH` entry through `current` on
  Windows, where the delivered payload and the running binary drift the same way; how variant
  builds would be published and named beside the shared archive stem.

## Enforcement

- `crates/fleet-agent/build.rs` fails the build on a `PRODUCT_NAME` outside the grammar or a blank
  display name, and `product.rs` reads `OPAMP_PRODUCT_NAME` and `OPAMP_PRODUCT_TITLE` through `env!`; `crates/fleet-agent/src/product.rs` `product_name_satisfies_the_grammar`,
  `display_name_is_prose`.
- `crates/fleet-agent/src/service/manager.rs`: `every_backend_renders_the_same_name`,
  `the_service_is_named_after_the_product_not_the_program`, `the_service_name_carries_no_suffix`,
  `the_names_a_human_reads`, `the_installed_command_line_is_the_marker_plus_absolute_paths`,
  `both_platforms_restart_after_the_same_delay`,
  `the_default_root_is_one_level_named_after_the_product`,
  `the_linux_system_layout_executes_from_opt`, `no_other_platform_splits`.
- `crates/fleet-agent/src/cli.rs`: `instance_is_not_a_flag_any_more`, `both_roots_can_be_named`,
  `service_verbs_parse_with_scope_and_root`, `the_installed_command_line_parses`,
  `install_is_not_interactive_unless_asked`, `bare_invocation_has_no_subcommand`.
- `crates/fleet-agent/src/service/layout.rs`: `the_directory_name_is_base_plus_hash_never_the_prerelease`,
  `set_current_points_and_repoints`, `stage_writes_binary_manifest_and_pointer`,
  `restaging_identical_bytes_leaves_the_staged_binary_untouched`,
  `restaging_replaces_a_staged_binary_with_different_bytes`,
  `a_torn_pointer_is_healed_a_correct_one_left_alone`,
  `the_layout_is_found_from_the_pointer_the_service_was_registered_against`.
- `crates/fleet-agent/src/service/run_as.rs`: `windows_forms_are_the_passwordless_ones`,
  `a_missing_account_is_refused_with_the_way_out`,
  `the_handover_walks_the_tree_and_skips_what_is_missing`.
- `crates/fleet-agent/src/config_init.rs`: `an_existing_file_is_never_overwritten`,
  `an_endpoint_given_never_overwrites_an_existing_file`,
  `an_edit_changes_the_asked_keys_and_keeps_the_rest`,
  `the_defaults_are_what_the_file_holds`,
  `the_bootstrap_pair_is_asked_only_before_enrolment`,
  `interactive_without_a_terminal_fails_instead_of_blocking`,
  `the_file_is_not_readable_by_the_rest_of_the_machine`,
  `a_private_ca_is_only_asked_about_where_tls_applies`,
  `the_rendered_file_loads_as_what_was_answered`,
  `a_bad_endpoint_is_refused_before_anything_is_written` (clauses 16–18);
  `the_suggested_endpoint_is_tls_on_the_loopback`,
  `a_plaintext_endpoint_is_accepted_only_on_a_loopback_literal`, which refuses `localhost`
  (clause 17); `a_complete_answer_writes_a_file_the_client_starts_with`, which renders the
  answers without a client identity and the verification key as answered, and passes
  `ClientConfig::check_admission` once the state directory holds an issued certificate
  (clauses 17, 19); `the_answered_ca_is_copied_beside_the_configuration` (clause 17);
  `installer_answers_alone_fail_validation_and_stay_on_disk` (clauses 17, 19);
  `a_rendered_file_has_no_auth_section`, which renders complete answers and asserts
  that the file holds no `[auth]` (clause 17).
- `crates/fleet-agent/src/config_file.rs`: `admission_needs_a_client_identity_and_nothing_else`,
  which asserts that `ClientConfig::check_admission` passes a file with a client identity and no
  `[auth]` and refuses one without an identity, naming `[tls] cert_file` and `key_file` (clauses
  19, 20). `crates/fleet-agent/src/config.rs`, shared with
  [ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md):
  `a_leftover_auth_section_is_ignored_with_a_notice`, which loads a file with an `[auth]`
  section, asserts that it loads, that nothing is sent from it, and that the notice names `[auth]`
  (clause 17).
- Logging: `crates/fleet-agent/tests/logging.rs` (`a_service_run_writes_a_log_file`,
  `a_foreground_run_writes_no_log_file`); `crates/fleet-agent/src/config.rs`
  `the_log_file_is_on_by_default_and_its_retention_is_not_optional`; `crates/fleet-agent/src/logging.rs`
  `the_writer_discards_until_a_file_is_opened`, `the_log_directory_hangs_off_the_state_directory`.
- `crates/fleet-agent/tests/shutdown.rs` `sigterm_shuts_the_client_down_cleanly`;
  `crates/fleet-agent/tests/service_smoke.rs`
  `the_installed_service_starts_comes_back_from_a_crash_and_stays_down_after_a_stop`, run with
  `--ignored` by the `service-smoke` workflow on an ephemeral runner.
- `crates/fleet-agent/tests/msi_exe_command.rs`
  `the_msi_names_no_root_so_no_directory_property_reaches_a_command_line`; the `.rpm` scriptlet
  assertions in [`.github/workflows/release.yml`](../../.github/workflows/release.yml) require the
  removal to take the layout root and the purge the data root.
- [`release.yml`](../../.github/workflows/release.yml): the version job's "The binary agrees" step
  and each target's "The binary agrees with the name it will be given" (clause 30); the pack step
  (clauses 31, 32); "The RPM carries its scriptlets, not their file names", which asserts with
  `rpm -qp --scripts` that `service install`, `service uninstall`, `ln -sfn`, the layout-root and
  data-root removals are in the package, and that the RPM's architecture is the ecosystem's
  (clauses 32, 36, 38).
- [`supervisor/agent.rs`](../../crates/fleet-agent/src/supervisor/agent.rs):
  `the_clients_own_agent_type_is_the_one_name_this_program_has`,
  `the_clients_own_agent_reports_its_type_and_its_configured_name_separately` (clauses 25, 27, 28).
- [`config.rs`](../../crates/fleet-agent/src/config.rs):
  `the_configurations_old_name_beside_the_new_one_is_refused_rather_than_defaulted` (clause 29).
- [`service/layout.rs`](../../crates/fleet-agent/src/service/layout.rs):
  `the_directory_name_is_base_plus_hash_never_the_prerelease`,
  `restaging_identical_bytes_leaves_the_staged_binary_untouched` (clauses 27, 38).
- [`tests/msi_exe_command.rs`](../../crates/fleet-agent/tests/msi_exe_command.rs) parses the WiX source's
  command lines as the C runtime will: `register_service_with_endpoint_survives_the_crt`,
  `register_service_survives_the_crt`,
  `the_msi_names_no_root_so_no_directory_property_reaches_a_command_line`,
  `stop_and_unregister_survive_the_crt` (clauses 36, 39) and
  `endpoint_prefill_is_the_development_server_and_interactive_only`, which asserts
  `wss://127.0.0.1:4320/v1/opamp` and passes it through `ClientConfig::transport`, the endpoint rule
  the Client applies at startup (clause 40). The MSI is not built locally; this test reads
  `packaging/windows/supervisor.wxs` as text on every platform, so the prefill is checked by
  `cargo test` wherever it runs, not by building or installing the MSI.
- [`tests/linux_post_install.rs`](../../crates/fleet-agent/tests/linux_post_install.rs)
  `the_post_install_prints_no_endpoint_the_client_refuses_at_startup` reads
  `packaging/linux/postinst` as text and holds every endpoint it prints to the same rule
  (clauses 37, 42). `the_post_install_steps_ask_for_the_client_identity` checks that its first
  step is `service install --interactive`, that no endpoint-only step is offered, that the manual
  alternative names `cert_file` and `key_file`, and that the printed text names neither `[auth]`
  nor a credential (clause 37).
- [`tests/msi_exe_command.rs`](../../crates/fleet-agent/tests/msi_exe_command.rs):
  `the_endpoint_dialog_names_the_identity_and_no_credential`, which reads
  `packaging/windows/EndpointDlg.wxs` as text and asserts that its note names the client
  certificate and mentions no credential (clause 39).
- `--endpoint` (clause 42): `install_takes_an_endpoint_without_a_terminal` and
  `an_endpoint_and_interactive_are_refused_together` in [`cli.rs`](../../crates/fleet-agent/src/cli.rs);
  `an_endpoint_given_is_written_and_loads`, `a_bad_endpoint_is_refused_before_anything_is_written`,
  `an_endpoint_given_never_overwrites_an_existing_file`,
  `an_endpoint_is_validated_by_the_loaders_own_rule` and
  `a_plaintext_endpoint_is_accepted_only_on_a_loopback_literal`, which refuses a plaintext endpoint
  off the loopback and one naming `localhost`, names the setting, and writes nothing, in
  [`config_init.rs`](../../crates/fleet-agent/src/config_init.rs).
- [`tests/enrolment_e2e.rs`](../../crates/fleet-agent/tests/enrolment_e2e.rs)
  `the_questionnaires_enrolment_stores_the_issued_certificate_and_copies_nothing`, which enrols
  through the questionnaire's enrolment against the real Server, approves the request, and asserts
  that the issued certificate is in the state directory and nothing was written beside the
  configuration (clause 17); [`cli.rs`](../../crates/fleet-agent/src/cli.rs)
  `config_takes_the_install_roots` (clause 15).

**Not mechanically decidable:** that the layout starts under an enforcing SELinux policy — no CI
runner enforces it, so the manual checklist in [`README.md`](../../README.md) carries that step.
The questionnaire's prompts (clause 17) read a terminal, which `cargo test` does not have: that no
answer skips the bootstrap pair on a Client not yet enrolled, that no question asks for a credential, that a CA, certificate or
key path naming no readable file and a refused endpoint are asked for again, and that an empty
verification key is named, are review questions on `ask` in `config_init.rs`.
`service install` (clauses 19, 20) validates only on the way to registering a service, so the
warnings it prints and its load of an existing file are not run by any test; the rules it applies
are `ClientConfig::load` and `ClientConfig::check_admission`, exercised above.

**Not mechanically decidable:** what `dpkg`, `rpm` and Windows Installer do with the maintainer
scripts and the MSI tables on a real host — the upgrade fall-through, the rpm `%posttrans` ordering,
the dialog sequence, the `UpgradeCode`'s permanence — is exercised only by installing a release;
no CI job installs the packages. The fleet view's prefill (clause 33) has no automated test.
