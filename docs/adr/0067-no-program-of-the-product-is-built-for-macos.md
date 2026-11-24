# ADR-0067: No program of the product is built for macOS

- **Status:** 🟢 accepted
- **Date:** 2026-11-16
- **Deciders:** Davide Zeni
- **Applies to:** the platforms every program of the product is built, tested
  and released for: the build matrices of `.github/workflows/ci.yml`,
  `.github/workflows/service-smoke.yml` and `.github/workflows/release.yml`,
  every `target_os = "macos"` branch and every launchd path in
  `crates/classis-agent/`, the platform aliases of
  `crates/classis-core/src/platform.rs`, the platform tokens of the upload form
  in `crates/classis-server/static/`, the variables a delivered block may not
  set in `crates/classis-agent/src/supervisor/delivered.rs`, the platforms
  `classisctl fetch` knows in `crates/classis-tools/src/fetch.rs`, and every
  document that names a platform the product runs on
- **Supersedes:**
  [ADR-0009](0009-an-adr-may-supersede-named-clauses-of-another.md) clause 1;
  [ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)
  clauses 15 and 21; [ADR-0016](0016-what-an-agent-reports-about-itself.md)
  clauses 3, 7 and 13;
  [ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
  clause 38;
  [ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause
  8;
  [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clauses 2, 7, 11, 12, 21, 22, 30 and 33, and the sentence of its Decision;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 7;
  [ADR-0028](0028-one-operator-program-that-makes-the-fleets-certificates.md)
  clauses 4 and 17, and the first sentence of its Decision;
  [ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
  clause 3;
  [ADR-0053](0053-the-state-directory-comes-from-the-registration-not-the-file.md)
  clauses 2, 3 and 5;
  [ADR-0054](0054-no-privileged-install-step-follows-a-link-the-account-placed.md)
  clause 4;
  [ADR-0059](0059-managed-processes-run-under-a-process-account-started-by-a-second-service.md)
  clauses 1, 2, 4, 6, 7, 9, 10, 14 and 16

## Context

The specification asks for a Client that runs as a native service on Linux and
Windows, and for a Server on Linux (G-11). Until this change it asked for macOS
too, and the code, the CI and the release carry it: a launchd backend beside
systemd and the SCM in `crates/classis-agent/src/service/manager.rs`, macOS
account management (`sysadminctl`, `dseditgroup`) in
`crates/classis-agent/src/service/run_as.rs`, the peer checks `getpeereid` and
`LOCAL_PEERPID` in `crates/classis-agent/src/supervisor/channel.rs`, `O_SEARCH`,
`O_SYMLINK` and `/private/var` in `crates/classis-agent/src/storage.rs`, a
`client-macos` CI job and a macOS row in the service smoke test, and two
`apple-darwin` targets in the release run, one of them cross-compiled and never
executed by anything.

No fleet runs a Client on macOS, and none is planned: the product is installed
on Linux and Windows hosts. Every macOS branch is code that no deployment
exercises, that every change to the service, the process account or the channel
has to keep in step with two other platforms, and that every security argument
of ADR-0054 and ADR-0059 has to make a third time. The operator tool
`classisctl` is published for Linux and macOS (ADR-0028 clause 17); its macOS
build serves an operator's workstation and nothing else.

The decision reaches into eleven accepted ADRs, because macOS is named, or
counted as a third platform, in clauses that are otherwise about Linux and
Windows. The human chose to restate every one of those clauses without macOS
rather than leave text that names a platform the product no longer has, so that
no binding clause has to be read past
([ADR-0009](0009-an-adr-may-supersede-named-clauses-of-another.md)). The
proposed [ADR-0061](0061-the-product-is-named-classis.md) names two macOS
account names in its clause 2; being proposed, it is revised in the same change
rather than superseded. Two Decision sentences name macOS as well, those of
ADR-0019 and ADR-0028, and ADR-0009 names numbered clauses only. This ADR
extends that form to a Decision sentence named by its place (clause 37), and
restates the two sentences as clauses of its own, naming each (clauses 35 and
36). Without the extension, ADR-0028's sentence would stand in binding text and
contradict clause 15.

## Decision

We will build, test, release and support the product's programs on Linux and
Windows alone, the Client on both, `classisctl` and the Server on Linux, and
nothing on macOS.

1. **The platforms are Linux and Windows.** The Client is built, tested,
   released and supported on Linux and Windows. `classisctl` is published for
   Linux alone, and the Server runs on Linux alone. No target, runner, archive,
   installer or document of the product names macOS as a platform it runs on.
2. **No code is kept for macOS.** No source of the product is conditional on
   `target_os = "macos"`, and none carries a launchd registration, a macOS
   account step or a macOS system call. Where code is conditional on Unix, Linux
   is the only Unix it is built for, and no branch is kept for another.
3. **Restates ADR-0010 clause 15. CI enforces the Definition of Done on this
   stack.** `cargo build`, `cargo test`, `cargo fmt --check` and `cargo clippy`
   with warnings denied on Linux; the Client is also checked and tested on
   Windows, and release-built on both; the Server is built on Linux only.
4. **Restates ADR-0016 clause 13. "Own" is what the Client observes from
   outside.** The Client's own Agent reports the Client's process; each
   Supervisor-backed Agent reports its Managed Process, by the pid the
   Supervisor already holds. No Managed Process's configuration is touched to
   obtain telemetry. CPU and memory for a pid come from `sysinfo` (pure Rust,
   Linux and Windows), the one gap the SDK leaves.
5. **Restates ADR-0018 clause 8. The restart is the service manager's, triggered
   by a deliberate exit.** Once `current` points at the new directory, the
   Client reports `Installing`, shuts down gracefully — Managed Processes
   stopped, `agent_disconnect` sent — and exits with the distinguished code
   **10**. No unit manipulates itself and nothing has to survive the unit
   stopping. "Restart on a non-zero exit" is what each manager has to be told:

   |                 | What makes the restart happen                                                                                                                                                       |
   | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | Linux (systemd) | `Restart=on-failure`                                                                                                                                                                |
   | Windows (SCM)   | a `Restart` recovery action, **and** `fFailureActionsOnNonCrashFailures` set, **and** the run's exit code reported in the final `SERVICE_STOPPED` status as a service-specific code |

   On Windows all three are required: the `sc.exe` backend of `service-manager`
   registers no recovery actions, the SCM ignores a clean non-zero stop unless
   the non-crash flag is set, and a status of `Win32(0)` is a clean stop
   whatever happened. The registration that sets them is
   [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)'s.
   **Crashing on purpose is never the mechanism**: it throws away the graceful
   shutdown and the `agent_disconnect`, and makes every self-update look like a
   fault.

6. **Restates ADR-0019 clause 2. `PRODUCT_NAME` is a build-time constant.**
   Default **`classis`**, overridable with `OPAMP_PRODUCT_NAME` for a variant
   build. `crates/classis-agent/build.rs` validates it against the intersection
   of the systemd-unit, SCM-name and directory-name grammars — lowercase
   `[a-z0-9-]`, 1–32 characters, no leading or trailing `-`, never a Windows
   reserved device name (`con`, `prn`, `aux`, `nul`, `com1`–`com9`,
   `lpt1`–`lpt9`) — and **fails the build** on a name that breaks it, so an
   illegal name cannot reach a service manager. The display name, default
   **`Classis Agent`**, is the constant `PRODUCT_TITLE`, overridable with
   `OPAMP_PRODUCT_TITLE` and only required to be non-blank: it is prose, cannot
   be derived from the slug by any rule that would read correctly for the next
   variant, and appears only where prose belongs — the Add/Remove Programs
   entry, the SCM's display column and the installer dialog's title. It is not
   the Agent type, so the fleet view never prints one word in both columns
   ([ADR-0016](0016-what-an-agent-reports-about-itself.md)).
7. **Restates ADR-0019 clause 7. The install path is `<base>/<PRODUCT_NAME>`,
   one level, never fixed.** It is named by the product, never by its display
   name.

   | Platform, scope | Executable layout                                         | Data                      |
   | --------------- | --------------------------------------------------------- | ------------------------- |
   | Linux, system   | `/opt/<PRODUCT_NAME>`                                     | `/var/lib/<PRODUCT_NAME>` |
   | Linux, user     | `$XDG_DATA_HOME/<PRODUCT_NAME>` (else `~/.local/share/…`) | same                      |
   | Windows, system | `%ProgramData%\<PRODUCT_NAME>`                            | same                      |
   | Windows, user   | `%LOCALAPPDATA%\<PRODUCT_NAME>`                           | same                      |

   The MSI's payload directory is `C:\Program Files\<PRODUCT_NAME>`; it is not
   the layout (ADR-0019 clause 8).

8. **Restates ADR-0019 clause 11. The lifecycle runs over `service-manager`,
   system scope by default.** System scope is a systemd system unit or an SCM
   service, because a fleet client runs without a logged-in user and starts at
   boot; `--user` is a development opt-in, refused on Windows, which has no
   user-scope services.
   - **Restart on failure, never after an explicit stop**, after 5 seconds and
     with no retry limit — what lets the self-update stop the service and switch
     `current` without the manager racing it. systemd carries the policy
     natively (`Restart=on-failure`); the crate's `sc.exe` backend discards it,
     so `windows_config` sets SCM recovery actions with the same delay and
     enables them for non-crash failures, and sets the display name
     (`sc config`) and the Description (`sc description`).
   - **A system-scope install that lacks the rights fails before anything is
     written** — on Windows by probing the SCM for `CREATE_SERVICE` first — with
     a message saying so.
   - **`uninstall` deregisters only.** It never deletes the layout, the
     configuration or the state.
9. **Restates ADR-0019 clause 12. Under the manager the daemon is the same `run`
   loop.** On Linux it is a plain foreground process: `SIGTERM` and `SIGINT`
   shut it down gracefully, through the transports, so the OpAMP
   `agent_disconnect` goodbye is sent on a service stop too; `SIGHUP` is
   explicitly ignored rather than left to terminate it. On Windows a
   `cfg(windows)` shim on the `windows-service` crate registers the control
   handler, reports `StartPending` → `Running` → `StopPending` → `Stopped`, and
   runs the identical body. The hidden `run --service` marker routes into the
   SCM dispatcher on Windows and, on every platform, says no terminal is
   watching (clause 10).
10. **Restates ADR-0019 clause 22. A Client running as a service writes its own
    log to a rotating file, on every platform.** `run --service` writes it; a
    foreground run writes stderr alone, because somebody is reading it. The file
    is written on Linux too, although the journal already holds stderr there, so
    "where are the logs" has one answer everywhere, including a container. It
    lives in `<state dir>/logs/` as `supervisor.<date>.log`: the state directory
    survives self-updates and `uninstall`, so a log explaining a failed start is
    still there afterwards.
11. **Restates ADR-0019 clause 30. A release is one workflow run that builds
    three targets from one version.** The version and its `version/*` tag are
    decided as [ADR-0012](0012-versions-resolved-in-the-internal-crate.md)
    states. A first job decides the number, builds the Client and asks it
    `--version`; every artifact is named from that one answer, and each target's
    build asserts its own binary reports the same full version. Every job checks
    out with full history so the baked version is the tag's. A
    `workflow_dispatch` dry run — the default — builds and packs everything,
    uploads it to the workflow run, and tags and publishes nothing.

    | target                      | runner             | `<os>`    | `<arch>` |
    | --------------------------- | ------------------ | --------- | -------- |
    | `x86_64-unknown-linux-gnu`  | `ubuntu-latest`    | `linux`   | `amd64`  |
    | `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | `linux`   | `arm64`  |
    | `x86_64-pc-windows-msvc`    | `windows-latest`   | `windows` | `amd64`  |

    Both Linux architectures because arm64 servers are ordinary. **Windows on
    arm64 is out** until a deployment asks for it; adding it is one row.

12. **Restates ADR-0019 clause 33. A file name is read from the right, and an
    unknown tail fills nothing.** The fleet view's upload form reads an
    artifact's name by matching the platform tokens it knows — including the
    aliases `x86_64` and `aarch64` — at the end of the stem, separated by `_` or
    `-`; the version starts at the first separator followed by a digit, and the
    rest is the name. A tail it does not know fills no field rather than a
    guess, because a wrong platform is an entry no Agent is ever offered.
    Accepting `-` serves upstream artifacts named by upstream. The release
    notes' upload loop selects the `supervisor_` stem and splits the rest on
    `_`, so it needs to be told no platform.
13. **Restates ADR-0026 clause 7. A Platform is spelled the semantic
    conventions' way, end to end.** The canonical Platform is an `os.type` value
    (`linux`, `windows`, …) and a `host.arch` value (`amd64`, `arm64`, …). One
    table in the shared crate canonicalises **both** sides before they are
    compared — what is uploaded and what an Agent reports: `win`, `win32`,
    `win64` → `windows`; `x86_64`, `x64`, `x86-64` → `amd64`; `aarch64` →
    `arm64`. Anything else is lower-cased and passed through, so a platform the
    table has never heard of is still served; a canonical token must match
    `[a-z0-9_]{1,16}`, which keeps it a safe file-name component. The API
    answers with the canonical pair, so a typo shows in the response. The table
    is compatibility, not translation — nothing this project produces needs it:
    - the Client reports `host.arch` as `amd64`/`arm64`, mapping Rust's
      constants, and `os.type` as Rust's own `linux`/`windows`, so a Supervisor
      and a Collector's `opampextension` report the same string;
    - the release artifacts carry the same two tokens in their file names (the
      file-name format is
      [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)'s),
      so the upload of a release is a loop over the Client's archives with `os`
      and `arch` read straight out of each name.
14. **Restates ADR-0028 clause 4. `init` is meant to run where the offline keys
    are to stay.** That is the operator's Linux machine, the one `classisctl` is
    downloaded to. Run on the Server host, it is followed by moving
    `--offline-dir` off it, and the command says so when both directories are on
    one file system.
15. **Restates ADR-0028 clause 17. Built in the release run, from the release's
    version, for two targets.** `x86_64-unknown-linux-gnu` and
    `aarch64-unknown-linux-gnu`, each in the row of the Client's build matrix
    for the same target. Each row whose target runs on its runner asserts that
    `classisctl --version` reports the release version, as the Client's build
    does. The Windows row builds the program for its runner only as the packer
    of the Client's archive; no Windows archive of it is published.
16. **Restates ADR-0042 clause 3, which restates ADR-0019 clause 36. The package
    delivers one file; `service install` installs.**

    |                 | delivers                                 | after install                                                                                                                                                                        | before removal                           |
    | --------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- |
    | `.deb` / `.rpm` | `/usr/libexec/<PRODUCT_NAME>/supervisor` | the account `<PRODUCT_NAME>` where it is missing (ADR-0042 clause 5), then `… service install --run-as <PRODUCT_NAME>` where no unit is registered, `… service install` where one is | `service stop`, then `service uninstall` |
    | `.msi`          | `INSTALLFOLDER\supervisor.exe`           | `… service install [--endpoint <ENDPOINT>] [--no-self-update]`                                                                                                                       | `service stop`, then `service uninstall` |

    **No package ships a systemd unit, a `sysusers.d` entry or an MSI
    `ServiceInstall` element.** `cargo-deb`'s `systemd-units` and WiX's
    `ServiceInstall`/`ServiceControl` are deliberately unused. There is one
    install path on every platform. The ownerships are disjoint by construction:
    the package owns its payload and never anything in the layout.
    `service install` stages a _copy_ into the layout, which is what the service
    runs and what a self-update replaces, so `dpkg -V` and `rpm -V` stay quiet
    through every fleet update. The pre-removal runs only on a real removal. On
    an upgrade it falls straight through, because the successor's post-install
    re-runs `service install`, and unregistering would stop a managed host in
    the middle of `apt upgrade`. It calls the payload path, never the symlink,
    and tolerates a service that is already unregistered. The dpkg/rpm package
    identity is `PRODUCT_NAME` and the MSI's is its display name and
    `UpgradeCode`, so an `apt`, `dnf` or MSI upgrade stays an upgrade.

17. **Restates ADR-0053 clause 2, which restates ADR-0042 clause 1. An upgrade
    on an installed host is a re-registration, never a migration.**
    - `--config` keeps pointing into the data root. `--state-dir` keeps pointing
      where the registration has it (clause 18).
    - A re-registration rewrites the program path (`ExecStart`) and the rest of
      the unit from the version that runs it, the directives of ADR-0042 clause
      7 included. The account stays the one the registration names (clause 27).
    - The instance's configuration, identity and state never move.
    - A change that would move the data root or the state directory of an
      installed host must bring its own migration and carries the full weight of
      this rule. An administrator who names another `--state-dir` moves nothing:
      the service then starts on an empty state directory and enrols anew.
18. **Restates ADR-0053 clause 3. The state directory is taken in this order.**

    1. **`--state-dir`**, the global flag (ADR-0019 clause 1), given to
       `service install` or `service config` and made absolute.
    2. **The registration's**, at system scope: the value after `--state-dir` in
       the command line of the registration the Client wrote.
       - Under systemd it is `ExecStart=` of
         `/etc/systemd/system/<PRODUCT_NAME>.service`.
       - Under the SCM it is the service's binary path name, read with
         `QueryServiceConfig`.
       - The install reads what the Client wrote, never a drop-in and never the
         manager's loaded state, as clause 27 reads the account.
       - A registration that names no `--state-dir`, and every user-scope one,
         offers none. A user scope has no administrator between the file and the
         service.
    3. **The file's**: the absolute `state_dir` that `supervisor.toml` names,
       and only beneath the data root or the layout root (ADR-0053 clause 4). A
       relative one names none.
    4. **`<data root>/state`.**

    `service config` finds the state directory by the same order, as ADR-0019
    clause 15 asks of it.

19. **Restates ADR-0053 clause 5. A Supervisors' root outside the roots is the
    operator's.** A `supervisor_dir` outside the data root, the layout root and
    the state directory stays as relocatable as ADR-0059 clause 13 makes it. A
    system-scope install on Windows never creates, restricts or hands over such
    a root. It leaves it as it is and names it in a warning. On Linux an install
    never touches a Supervisors' root.
20. **Restates ADR-0054 clause 4. On Windows, a data root or layout root that is
    a reparse point is refused, and the data root is held.** The account holds
    delete on the roots themselves, so their names are not the operator's alone.
    `service install` and `service config` hold the data root without
    `FILE_SHARE_DELETE` from their first write to their last. On Linux a root's
    name lies in a directory only root writes, and it is followed. This refusal
    is a check of its own beside ADR-0053 clause 4, whose test of what lies
    beneath a root still does not inspect the roots.
21. **Restates ADR-0059 clause 1. The process account is named at registration,
    and kept.** `service install --process-account <account>` names it, at
    system scope only; it conflicts with `--user`. A re-registration without the
    flag keeps the account the second service's registration names (clause 22),
    read the way clause 27 reads the Client's. Without the flag and without such
    a registration, there is no process account and no second service, and the
    Client starts its programs itself, as before (ADR-0059 clauses 11 and 13
    hold on every host).
    - **The operator creates the account.** On Linux it must exist, and an
      install naming one that does not is refused before anything is written,
      with a message that shows the `useradd --system` line that creates it. The
      binary never creates an account (clause 27).
    - **Windows accepts only passwordless forms**, as clause 27 does: the second
      service's own virtual account `NT SERVICE\<PRODUCT_NAME>-agents`
      (recommended), a gMSA, or `NT AUTHORITY\LocalService` / `NetworkService`.
      A gMSA is looked up in its domain, and an account that cannot be found is
      refused before anything is written.
    - **It is never root and never the Client's account.**
      `--process-account root`, `LocalSystem` or the account the Client runs as
      is refused, naming `--run-as root` as the way to run everything as root. A
      host whose agents need root runs as root as a whole (clause 27), with no
      second service.
    - **On Windows the Client then runs under an account of its own.** A process
      account separates the Managed Processes from a Client that runs under its
      own account, so the install refuses one where the Client would run as
      `LocalSystem`: `--run-as` names the Client's account, or the registration
      keeps the one the SCM holds (clause 27). The refusal names `--run-as` as
      the way to name it, with `NT SERVICE\<PRODUCT_NAME>` where no account was
      named.
    - **It is dropped on request.** `service install --no-process-account` stops
      and deregisters the second service, and the Client starts its programs
      itself again. It conflicts with `--process-account`, and a refusal that a
      kept process account causes names it. What the dropped account was granted
      is withdrawn from it (clause 29).
22. **Restates ADR-0059 clause 2, which restates ADR-0019 clause 3. The service
    is `PRODUCT_NAME`, with no suffix, on every platform, and the second service
    is `<PRODUCT_NAME>-agents`.** The label is a single token — no qualifier, no
    organization — so `service-manager` renders the same string for systemd and
    the SCM, and the name never contains a dot. The second service exists only
    where a process account is named (clause 21); its label is the product's
    with the suffix `-agents`. The `PATH` symlink is `/usr/bin/<PRODUCT_NAME>`,
    so two variants never collide on one `PATH` entry. On Windows the SCM
    additionally carries each service's display name and a Description that says
    what the program does.
    - **It is the same program.** The second service runs
      `supervisor run --agents` from the same layout and `current` (ADR-0059
      clause 8), under the process account. The package still delivers one file
      (clause 16).
    - **The two are registered, started, stopped and deregistered together.**
      `service install`, `start`, `stop` and `uninstall` act on both, the second
      service first on start and last on stop: under systemd the Client's
      `Wants=` and `After=` start it first, under the SCM the start names it
      first. Its unit carries the directives ADR-0042 clause 7 sets for its
      account. Under the SCM it is registered as clause 26 says.
    - **On Windows the Client's service does not depend on it.** The SCM starts
      no service whose dependency failed to start (StartService,
      `ERROR_SERVICE_DEPENDENCY_FAIL`), so a dependency would hold the Client
      down with a second service that does not come up. No SCM entry names a
      dependency, and `service start` starts the second service first and then
      the Client.
    - **The Client runs without it, and neither waits for the other.** Under
      systemd the Client's unit wants the second service and is ordered after it
      (`Wants=`, `After=`), never `Requires=`: while the second service is down
      the Client stays reported to the Server, its Supervisors say that their
      programs do not start, and they start again once it is back. A Supervisor
      whose start finds the second service unreachable is not held for failing
      to start; it tries again with backoff. The Client connects again whenever
      the second service has restarted. A program the second service stops
      because it is stopping itself has not exited on its own, and counts for no
      restart policy.
    - **What arrives while the second service is away waits for it.** An offered
      package is staged and kept, never swapped in: it is swapped in, and its
      apply grace runs, once the second service is reached again, so the
      previous program stays in place and a rollback only ever goes back to a
      program that ran. A delivered Configuration is written as today, and its
      acknowledgement is given by the first start of an apply or of the retry
      that reaches the second service and survives the apply grace; a restart
      command's start acknowledges nothing and swaps nothing in (ADR-0017 clause
      8), and the retry follows it at once. A Supervisor held after a package
      that failed leaves no Configuration waiting: it is reported `FAILED`.
      Until then the package stays `Installing` and the Configuration
      `APPLYING`, each naming the second service as the reason. A newer offer or
      Configuration replaces the waiting one, and a Client that stops while one
      waits leaves its files as the record names them.
    - **A self-update restarts whichever end is behind.** The self-update
      switches `current` and restarts the Client as before. A second service
      that meets a Client of another build while `current` no longer names its
      own version exits, so that its service manager starts it from `current`; a
      Client that meets a second service of another build while `current` no
      longer names its own version exits for the same restart. A peer of another
      build is otherwise refused (ADR-0059 clause 5), and only a peer of the
      admitted account can cause either exit (clause 23).
23. **Restates ADR-0059 clause 4. The channel admits the Client's account alone,
    the Client speaks to the second service alone, and the channel ends with the
    Client.** On Linux the second service listens on a Unix socket, on Windows
    on a named pipe. Every connection is checked by the peer's credentials
    (`SO_PEERCRED`, the pipe client's token) and refused unless its user is the
    Client's account. One connection is served at a time. When it closes, the
    second service stops every program it started, by its process group on Linux
    and by its job on Windows, so a Client that restarts finds no process it did
    not start.
    - **The pipe is the process account's, and the Client reaches it for reading
      and writing data alone.** It is `\\.\pipe\<PRODUCT_NAME>-agents`, created
      with a security descriptor that names the process account as its owner and
      carries a protected DACL of two entries: full access for the process
      account, which creates the pipe's instances, and for the Client's account
      read and `FILE_WRITE_DATA` alone (`0x12008b`). The Client is granted
      neither `FILE_GENERIC_WRITE` nor `FILE_APPEND_DATA`, which is
      `FILE_CREATE_PIPE_INSTANCE` on a pipe, so it cannot serve the pipe itself.
      Nobody else is granted anything.
    - **The pipe cannot be taken over.** Its first instance is created as the
      first of its name (`FILE_FLAG_FIRST_PIPE_INSTANCE`), so a pipe someone
      else made under the name first fails the second service's start, and every
      instance rejects remote clients (`PIPE_REJECT_REMOTE_CLIENTS`).
    - **Each end checks the other's account.** The Client opens the pipe at the
      identification level (`SECURITY_IDENTIFICATION`), so the second service
      may identify it and act as nobody, and accepts the pipe only where its
      owner is the process account; on Linux it accepts a peer whose uid is the
      process account's. The second service reads the client's token by
      impersonating it at that level, and refuses a client that is not the
      Client's account. It refuses to run as `LocalSystem`, to serve
      `LocalSystem`, or to serve its own account.
    - **The Client checks the process too.** Before it writes anything on a new
      connection, the Client reads the process at the other end — on Linux
      `SO_PEERPIDFD`, and `SO_PEERCRED` only where the kernel does not know that
      option (`ENOPROTOOPT`), any other error being a process that cannot be
      read; on Windows `GetNamedPipeServerProcessId` — and then asks the service
      manager for the process it runs as the second service: systemd the unit's
      `MainPID`, the SCM the service's process id from `QueryServiceStatusEx`.
      It accepts the connection only where both name the same process. With a
      pidfd it also requires that the process the pidfd refers to is still
      running once the service manager has answered, so the id cannot have
      passed to another process in between. The account is still read as the
      bullet above says, from the peer's uid or the pipe's owner. A connection
      whose process cannot be read, or that the service manager names no process
      for, is refused as one whose process differs.
    - **A refused peer learns nothing.** The Client closes a connection it
      refuses before it sends the handshake or any request. It logs an error
      naming the socket or pipe and the peer's process id, and treats the second
      service as away: it tries again with the backoff it uses for a second
      service that is not running, each time on a new connection checked anew,
      and the Supervisors report the second service unreachable as they do then
      (ADR-0059 clause 3).
    - **The second service closes its process to the Managed Processes where it
      can.** On Linux it marks itself not dumpable (`PR_SET_DUMPABLE` 0) as the
      first thing its program does, before it reads its configuration or sets up
      its log, and does not listen while `/proc/self/status` names a tracer
      (`TracerPid` other than 0), so from then on no process of its own account
      without `CAP_SYS_PTRACE` can attach to it, read or write its memory, or
      take its file descriptors, whatever `kernel.yama.ptrace_scope` says; the
      programs it starts are dumpable as usual, since `execve` resets the mark.
      On Windows the process keeps the default security its account gives it.
    - **Each program runs in a job of its own.** On Windows the second service
      starts every program suspended, assigns it to a new job object with
      `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then lets it run, so
      everything it starts is in that job too. At the end of each connection,
      and so before it reports itself stopped, the second service ends every job
      it holds and waits, up to five seconds, until none holds a process.
24. **Restates ADR-0059 clause 6. The process account reads what it runs and
    writes only its own data.** On Linux the process account's primary group is
    made a supplementary group of the Client's account by the operator, and the
    install refuses to register where it is not, or where the process account's
    primary group is group 0 or the Client's own primary group, where it has a
    member other than the Client's account or is the primary group of an account
    other than the process account, or where the process account is a member of
    the Client's primary group: the group is the process account's own. Every
    file and directory the Client keeps under `state_dir` that the table does
    not name — its logs among them — stays the Client's alone. Then:

    | Path                                                                                          | Owner : group                        | Mode                                       |
    | --------------------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------------ |
    | `state_dir`, each Supervisor's directory                                                      | Client : the process account's group | `0710`                                     |
    | the Client's key, certificates, `remote-config.pb`, `instance-uid`, package state and staging | Client                               | `0600` / `0700`, as today                  |
    | `program/` and its files                                                                      | Client : the process account's group | `0750`, files without group or other write |
    | the preflight's staging directory                                                             | Client : the process account's group | `0750`                                     |
    | `config/` and its files                                                                       | Client : the process account's group | `0750` / `0640`                            |
    | a kind's data directories                                                                     | Client : the process account's group | `2770`                                     |

    A file the Client replaces through the no-follow adapter (ADR-0054 clause 6)
    is created with the owner, group and mode this table names.

    On Windows the same split is made by ACL grants to the process account's
    SID, and no group is checked or shared:

    | The process account                                       | Grant on the directory itself                            | Grant on what it holds                                                       |
    | --------------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------- |
    | passes through (`state_dir`, each Supervisor's directory) | none: it passes by `SeChangeNotifyPrivilege` (clause 26) | none                                                                         |
    | reads (`program/`, the preflight's staging, `config/`)    | read and execute, `(OI)(CI)`                             | read and execute                                                             |
    | writes (a kind's data directories)                        | modify without `DELETE`                                  | modify, `(OI)(CI)` and inherit-only on the directory, explicit on each entry |
    | runs (`versions\` of the layout)                          | read and execute, `(OI)(CI)`                             | read and execute                                                             |

    Every grant is explicit on what exists and inherited by what is created
    after it, and replaces the explicit allow entries the process account held
    there. No other entry grants the process account anything by name, the
    Client's key and logs among them. In a root the install takes over, nothing
    grants it anything through a group either; a root the operator named keeps
    the explicit entries it had.

    - **Every walk goes one handle at a time.** Each entry is opened as itself,
      never through a symbolic link or junction, and no walk enters one. A
      directory on the way is held open without sharing delete, so it cannot be
      renamed or replaced under the walk. A regular file with a second hard link
      is skipped and named in a warning: its other name may stand anywhere on
      the volume. A walk that grants, hands over (clause 27), takes over or cuts
      off leaves an entry the process account owns, with everything beneath it,
      as it is.
    - **What it cannot hold, it either fails on or reports.** A walk that takes
      rights away — a withdrawal (clause 29), or the take-over or cut-off of a
      root a system-scope install restricts to `LocalSystem` and the
      Administrators — fails where it finds a directory it cannot hold, or an
      entry it cannot open, so nothing it cannot reach safely is left as it was.
      A walk that only adds rights — a grant, the hand-over — skips such an
      entry and names it in a warning.
    - **Every DACL set is read back.** A DACL is set on the entry's own handle
      and changes that object alone; what a directory passes on to what it
      already holds is applied by the walk itself. The DACL the object then
      holds is read back and compared with what was set by what it says — the
      same entries in the same order and the same protection, however they are
      spelled — and a difference fails the change.
    - **The install's walks hold the backup, restore and take-ownership
      privileges** for as long as they run, so an entry another account made, or
      one a Managed Process protected from the Administrators, is opened all the
      same.

    An install grants and withdraws the process account's rights in the data
    root, the layout root and the state directory alone: a Supervisors' root
    outside them is the operator's (clause 19), left as it is and named in a
    warning.

25. **Restates ADR-0059 clause 7. A program inherits nothing of the Client's.**
    Its environment is the second service's own, then the block's `env` laid
    over it, then the Supervisor Endpoint's token, last
    ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
    clause 16). On Linux the second service's own has `HOME`, `USER` and
    `LOGNAME` set to the process account's. On Windows it is the environment the
    SCM gives the second service under the process account, unchanged.
26. **Restates ADR-0059 clause 9, which restates ADR-0042 clause 6. The Client
    writes its systemd system units itself, and `service-manager` installs
    them.** `manager::install` passes `contents: Some(<unit>)` at system scope
    under systemd. `service-manager` still writes the file (mode `0644`),
    enables it, which reloads the manager's configuration, and uninstalls it.
    The unit holds:

    - `[Unit]`: `Description=<PRODUCT_NAME>`, the same as before. The display
      name stays where clause 6 puts prose. Where a process account is
      registered, also `Wants=<PRODUCT_NAME>-agents.service` and
      `After=<PRODUCT_NAME>-agents.service` (clause 22).
    - `[Service]`: `ExecStart=` with the program and every argument in double
      quotes. A `\` and a `"` are escaped, a `%` is written `%%` and a `$` is
      written `$$`, so any absolute path reaches the program as it was given.
      Then `Restart=on-failure`, `RestartSec=` set to the restart delay the
      SCM's recovery actions use (clause 8), `User=` set to the account of
      clause 27, and the directives of ADR-0042 clause 7.
    - `[Install]`: `WantedBy=multi-user.target`.

    The user scope's unit stays as `service-manager` renders it.
    `service install` never writes, reads or removes anything under
    `/etc/systemd/system/<PRODUCT_NAME>.service.d/`. Drop-ins there belong to
    the operator, outrank the unit, and survive every re-registration.

    The second service's unit is written the same way: `User=` names the process
    account, `ExecStart=` runs `run --agents <socket> --client-uid <uid>`,
    `RuntimeDirectory=` holds the socket, `TimeoutStopSec=` exceeds the time the
    second service takes to stop what it started, and the directives are those
    of ADR-0042 clause 7 for its account.

    Under the SCM the second service runs under the process account,
    `NT SERVICE\<PRODUCT_NAME>-agents` or the account clause 21 names, set
    without a password. Its command line is
    `run --agents \\.\pipe\<PRODUCT_NAME>-agents --client-sid <SID>`, the Client
    account's SID, and it starts automatically. As the Client's own entry, it
    carries the recovery actions of clause 8 — one restart after the restart
    delay, repeated for every failure, and run on a reported failure too — its
    display name and a Description. Its required privileges are
    `SeChangeNotifyPrivilege` alone (SERVICE_REQUIRED_PRIVILEGES_INFO): the SCM
    removes every other privilege from its token, and so from every program it
    starts, so no Managed Process holds `SeImpersonatePrivilege`. A stop waits
    until the service has reported itself stopped and its process has ended, up
    to 60 seconds.

27. **Restates ADR-0059 clause 10, which restates ADR-0054 clause 1. The system
    service runs under the account its registration names, and both roots belong
    to it, except what the process account keeps there.**
    `service install --run-as <account>` names the account. It applies at system
    scope only and conflicts with `--user`. On Linux, `--run-as root` is how an
    operator chooses root. It is written as `User=root`, so a unit records that
    root was chosen. Without the flag, the account is taken in this order:

    - **A re-registration keeps the account the registration names.** That is
      `User=` in the system unit `/etc/systemd/system/<PRODUCT_NAME>.service`.
      The install reads the file the Client wrote, not a drop-in and not the
      loaded state of the service manager. On Windows it reads the logon account
      the SCM holds for the service (`QueryServiceConfig`) and keeps it, unless
      that is `LocalSystem`, which a registration that names no account runs as.
      The second service's account is read and kept the same way (clause 21). A
      service the SCM holds already is reconfigured in place: its program,
      arguments and start type are rewritten, its logon account is set only by
      the `sc config obj=` step of `windows_config`, and what clause 26 and
      `windows_config` set follows as on a first registration.
    - **A unit that names no account, on a data root that a non-root account
      owns,** was rewritten by a re-registration that dropped its account. The
      install takes the owner of the data root and prints that it did, naming
      the data root. Every other registration that names no account stays root.
    - **A first registration**, one where no unit or SCM entry exists, runs as
      root under systemd and as `LocalSystem` under the SCM. The Linux packages
      name their account themselves (ADR-0042 clause 5).

    The install prints the account and where it came from: `--run-as`, the unit,
    the SCM's entry, the owner of the data root, or the default. On Windows a
    Client that runs as `LocalSystem` by default prints none.

    - **The service runs as the account.** Under systemd this is `User=` in the
      unit the Client writes (clause 26). On Windows it is an `sc config obj=`
      step in `windows_config`. No _Log on as a service_ grant is performed: the
      default policy grants it to `NT SERVICE\ALL SERVICES`, built-in accounts
      carry it, and a gMSA receives it from its domain. A host hardened against
      the default grant must restore it.
    - **Windows accepts only passwordless forms:** the service's own virtual
      account `NT SERVICE\<PRODUCT_NAME>` (recommended), a gMSA (`name$`), or
      `NT AUTHORITY\LocalService` / `NetworkService`. There is no password
      parameter, because it would stand in the process list and the installer
      log. A form that needs a password is refused with a message naming the
      passwordless forms.
    - **The account must exist** on Linux, whether it was named or kept. An
      account that does not exist is refused before anything is written, and the
      install fails closed. For a kept account, the message names the account
      and the file or directory it came from. It shows the `useradd --system`
      line that creates the account, and says that `--run-as <account>` or
      `--run-as root` names another. The binary never creates an account; that
      is the packages' job (ADR-0042 clause 5).
    - **The hand-over covers both roots, on every registration that runs under
      an account.** That includes a kept account and root. After laying out and
      registering, the install hands the account the data root
      (`supervisor.toml`, `state/`), because the service reads and rewrites
      them. It also hands over the layout root (`versions/`, `current`), because
      the self-update that stages into it is the service itself. On Linux this
      is an ownership change. On Windows it is a grant of Modify to the account,
      inherited by what each root holds (`(OI)(CI)`) and set explicitly on every
      entry that exists. Where a process account is registered the grant also
      carries `WRITE_DAC`, so the Client can grant the process account its share
      of what the install laid out (clause 24); it never carries `WRITE_OWNER`.
      Where the roots coincide this is one operation. Where they split, an
      install that hands over only one has not succeeded.
    - **Where a process account is registered, the hand-over leaves its data
      alone.** An entry the process account owns is skipped together with
      everything beneath it, and an entry in the process account's group keeps
      that group, a directory its mode too, so a re-registration — every package
      upgrade — takes from no Managed Process the data it wrote or reads.
    - **The hand-over never follows a link, and neither does any other
      privileged step** (ADR-0054 clause 2). The account owns the trees that
      root walks, and ADR-0042 clause 5 makes that walk part of every package
      upgrade. So each directory is opened without following a link, and its
      owner is changed through that open handle. Its entries are read from the
      handle, and a symbolic link is re-owned as a link. A regular file with
      more than one hard link is skipped and named in a warning (ADR-0054 clause
      5). On Windows the hand-over walks as clause 24 says, with the backup,
      restore and take-ownership privileges held. Re-running `install` with
      another `--run-as` re-owns the same directories, and what the former
      account was granted is withdrawn from it (clause 29).

28. **Restates ADR-0059 clause 14, which restates ADR-0029 clause 13. No
    installer starts a service it registers anew; an upgrade starts again what
    ran.** The Linux post-install and the MSI register the service and leave it
    stopped — knowingly departing from Debian Policy and `dh_installsystemd` —
    because a Client with no configuration holds no client certificate and is
    refused at startup, at fleet scale where nobody watches a terminal. The
    exceptions are upgrades of a host whose services were running. On Linux a
    running service is restarted, so a configured host finishes the upgrade on
    the delivered binary. On Linux an install that names another process account
    than the registration, drops it, or names another `--run-as` stops the
    services first and starts again what ran once it has succeeded (clause 29).
    On Windows every `service install` — every upgrade of the MSI among them,
    with a process account or without one — stops both services before it
    changes any right or SCM entry, and once it has succeeded starts again what
    ran before it; a first install finds nothing to stop and starts nothing. The
    post-install prints the two remaining steps:

    ```console
    sudo classis service install --interactive
    sudo systemctl start classis
    ```

    The second `service install` is a re-install, which is idempotent and writes
    the configuration that `service install` refuses to overwrite once it
    exists. The first step is `--interactive`, which asks for the client
    identity — the bootstrap identity of ADR-0029 clause 6 — and not
    `--endpoint` alone: a configuration holding only an endpoint is one the
    Client refuses at startup, so printing it as the whole first step would
    present an unauthenticated Client as the default. After the two steps it
    prints the scripted form of ADR-0029 clause 11 — `--endpoint` with
    `--fleet-files` and, for a `bootstrap.p12`, `--bootstrap-password-file` — as
    the way to enrol without a terminal. The alternative it prints for writing
    the file by hand names the endpoint together with `[tls] cert_file` and
    `key_file`, the identity the operator adds before the start, and names no
    credential and no `[auth]` section, because the Client reads none
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).

    On Windows the stop and the start go as follows, so that nothing runs under
    an account whose rights the install changes or takes away, nor under a
    registration it rewrites:

    - **The stop comes before every change, and is waited for.** The install
      writes the configuration and the copies beside it while the Client still
      runs. Then, before it restricts, takes over, hands over or withdraws
      anything, and before it rewrites an SCM entry, it stops the Client and
      then the second service, and waits for each until it has reported itself
      stopped and its process has ended (clause 26); the second service's
      programs end with it (clause 23). Where the second service cannot be
      stopped, the Client is started again if the stop stopped it, and the
      install changes nothing more.
    - **What ran is recorded before the stop.** The install asks the SCM which
      of the two run, a service starting or stopping counting as running, and
      writes that, with a withdrawal that is due (clause 29), to the record of
      ADR-0059 clause 17 in one write before it stops anything. A record that
      cannot be written stops nothing. What the stop then finds running beyond
      it is added.
    - **A failed stop records what runs no more.** Where the stop fails, the
      services to start again are set from what the SCM reports then, where only
      a service running or paused counts as running: what an earlier install
      left to start again, and what ran when this install looked or was stopped
      by it and does not run now — `before ∪ ((ran ∪ stopped) ∖ running now)`. A
      service still stopping or starting is so started again by the next
      install, which waits it out. Where the SCM cannot be asked, the record
      keeps all of `before ∪ ran ∪ stopped`.
    - **Success starts again what ran.** Once the registration, the withdrawal,
      the hand-over and the layout's share are done, the install starts what is
      recorded: where the Client ran, the second service and then the Client;
      where the second service alone ran, it alone. A service that runs is
      passed over, and one still starting or stopping is waited out, up to 60
      seconds. Then the services are struck from the record.
    - **A failed install leaves the services stopped, and says so.** Its message
      names how the SCM reports both now and that the next `service install`
      that succeeds starts again what ran, as the record names it, or that
      `service start` starts both now. Until then they stay stopped, an MSI that
      rolled back among the causes.
    - **Only the CLI's `service start` and `service stop` hand the run state to
      the operator.** Once either has succeeded it strikes the services from the
      record, so no later install starts what the operator stopped. `sc.exe` and
      the Services console know nothing of the record and strike nothing, and a
      `service stop` that failed in part strikes nothing either.

29. **Restates ADR-0059 clause 16. A former account keeps no share.** Where an
    install drops the process account (`--no-process-account`), names another,
    or names another `--run-as` for the Client, every share with the former
    account in the roots an install acts on (clause 24) is withdrawn, on every
    platform, except a file with a second hard link, which is named in a warning
    (clause 24). A Supervisors' root outside those roots stays the operator's.

    - **On Linux a change of owner withdraws it.** The hand-over (clause 27)
      gives what the former account owns there, and what is in its group, to the
      Client's account and group, and what the process account named now keeps
      is left to it.
    - **On Linux an account change stops the services first.** Where the
      registration names a process account and the install names another or
      drops it (`--no-process-account`), or where `--run-as` names another
      account than the registration, the install stops the Client and then,
      where one is registered, the second service, before it rewrites a unit or
      changes an owner. It waits for each until its process has ended, up to 60
      seconds each as clause 26's stop does; a service whose process has not
      ended by then has not stopped. So nothing runs under an account whose
      files are being re-owned. What ran is what systemd reports active or
      activating. Once the install has succeeded it starts again what ran of
      what is still registered, the second service first (clause 22). An install
      that changes no account — one that adds a process account where none was
      among them — stops nothing beyond what clause 28 says.
      - **A failed stop changes nothing more.** Where a service cannot be
        stopped, the install starts again what it stopped, changes nothing more,
        and says so.
      - **A failed install leaves the services stopped, and says so.** Its
        message names which services ran before it and that `service start`
        starts them. Linux keeps no record of them, so no later install starts
        them; `service start` does.
    - **On Windows its entries are removed and what it owns is taken over.**
      Every entry that allows the former account anything, explicit or
      inherited, is removed from every entry of the layout root, the data root,
      the state directory, the configuration file and the fleet files copied
      beside it, and an entry the former account owns is given to the
      Administrators. An entry that denies it stays. The walk goes as clause 24
      says and fails closed. `LocalSystem` is never withdrawn: it keeps full
      control of every root.
    - **Former accounts are resolved before anything changes.** The install
      reads the accounts the two SCM entries name and resolves each that is to
      go to its SID before it writes anything; one that cannot be resolved — a
      gMSA whose domain cannot be reached — fails the install there, since its
      grants would otherwise stay. An account named as before is not withdrawn,
      nor one named now in the same part.
    - **The withdrawal is recorded before the SCM forgets the account.** It is
      written, with the SIDs and the roots, to the record of ADR-0059 clause 17
      before the stop of clause 28, and so before the SCM entries are switched.
      It is carried out after the switch and before the hand-over and the
      layout's share, which grant what the accounts named now are to hold, and
      struck from the record only once all of it has succeeded. An install that
      finds a withdrawal recorded completes it.
    - **An uninstall always deregisters, and withdraws only once both services
      are stopped.** `service uninstall` on Windows stops both services and
      waits for each, starting neither again. Where it holds the install lock
      (ADR-0059 clause 17) and both are stopped, it completes a recorded
      withdrawal and removes the record. Otherwise it leaves the record as it is
      and says that the next `service install` or `service uninstall` completes
      it. Either way it then deregisters both services, so none is left to start
      at the next boot.

30. **Restates ADR-0010 clause 21. Tests reach what they test through the
    library.** Integration tests import constants rather than restating them,
    and tests that spawn a real program spawn the Client's own cross-platform
    stubs (`stub_agent`, `stub_crasher`, under `crates/classis-agent/src/bin/`)
    instead of a shell, so they run on both platforms. A `#[cfg(unix)]` gate
    sits only on what is genuinely a Unix fact, such as a file mode. The stubs
    stay in `classis-agent`, because `CARGO_BIN_EXE_*` resolves only inside the
    crate that declares them.
31. **Restates ADR-0016 clause 3. The block `name` keeps its local meaning.** It
    is the Supervisor's directory name and the uniqueness key across blocks,
    bound by the instance-name grammar of clause 6: lowercase, digits, `-`, no
    dots. A type may be a reverse FQDN; an instance name is a path component on
    two operating systems. That is why the two cannot share a key.
32. **Restates ADR-0016 clause 7. `host.cpu.model.name` and `os.build_id` come
    from sources already paid for.** The CPU model from the same `sysinfo`, read
    once per process. The build behind `os.version` from what the platform's
    `os.*` answer already carries: os-release's `BUILD_ID` (absent where a
    distribution stamps none), and on Windows the build components of the
    version line (`10.0.26100.2033` → `26100.2033`).
33. **Restates ADR-0017 clause 38. A delivered block brings no environment and
    no arguments the operator did not allow.** In the apply path, a delivered
    block's `env` entries, `args` and `version_args` must equal those of the
    running block of the same name, or be allowed by the operator in
    `supervisor.toml`'s `[supervisors]` section — keys the Server cannot change
    (ADR-0017 clause 27). `delivered_env` is a list of variable names, each
    exact or ending in `*` as a prefix (`["OTEL_*", "GOMAXPROCS"]`), and
    defaults to none; `delivered_args = true` lets delivered blocks state
    arguments, and defaults to `false`. Names are compared without regard to
    case, as Windows compares them. Whatever the list says, a delivered `env`
    that adds or changes a variable steering which code a program loads is
    refused: `PATH`, every `LD_*`, `GCONV_PATH`, `GLIBC_TUNABLES`,
    `OPENSSL_CONF`, `OPENSSL_ENGINES`, `DOTNET_STARTUP_HOOKS`, `COR_PROFILER*`,
    `CORECLR_PROFILER*`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
    `JDK_JAVA_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5LIB`, `PERL5OPT`,
    `RUBYOPT`, `BASH_ENV` and `ENV`. So is a new or changed value that contains
    `${config_dir}` or `${supervisor_dir}`: the Server delivers files there that
    no one signed, and an allowed name such as `OTEL_JAVAAGENT_EXTENSIONS` would
    load one. The list is a floor, not a guarantee: `delivered_env = ["*"]`
    leaves only it between a delivered block and every other variable a program
    reads. A block that breaks this fails the whole offer before anything stops
    (ADR-0017 clause 28), naming the block and the variable or key. A block the
    operator writes is unaffected: the rule is about what the Server may add.
34. **Restates ADR-0019 clause 21. The prompts come from `dialoguer`.** It
    validates an answer and asks again, offers a default and a yes/no
    confirmation, the same way on both operating systems; `dialoguer` is
    MIT-licensed and brings no TLS or crypto backend. The questionnaire asks for
    no secret, so no prompt hides its input. The terminal check itself is
    `std::io::IsTerminal`, no dependency.
35. **Restates the sentence of ADR-0019's Decision.** We will call the fleet's
    own agent `supervisor` at every layer where it is the program, and make it a
    `clap` subcommand CLI that registers, controls and runs itself as a native
    service on systemd and the Windows SCM, under a product name fixed at build
    time that names the service, the install path, the package and the `PATH`
    entry; that executes from a versioned layout behind a `current` pointer,
    kept apart from its data on Linux at system scope; that writes its first
    configuration when asked and never one the Client would refuse at startup,
    logs to a bounded file when it runs as a service, and may run under an
    operator-named account that owns what it rewrites; and publish each release
    as one `.tar.gz` per target named `supervisor_<version>_<os>_<arch>` — the
    fleet's artifact — plus a `.deb`, `.rpm` and `.msi` that deliver the same
    binary and run its own `service install`.
36. **Restates the first sentence of ADR-0028's Decision.** We will build the
    operator tools as one program, `classisctl`, from `crates/classis-tools`,
    and publish it in every release as a `.tar.gz` for Linux on amd64 and arm64.
37. **Restates ADR-0009 clause 1, extended. A Decision sentence may be named by
    its place.** A `Supersedes` entry may name the first sentence of an accepted
    ADR's Decision section, as `the first sentence of its Decision`, or the
    sentence of its Decision where that section is a single sentence, as `the
    sentence of its Decision`. Other unnumbered text of a Decision is superseded
    only whole. The successor restates the named sentence as a numbered clause of
    its own, as clauses 35 and 36 do; the old ADR's `Status` line records it in
    the form ADR-0009 clause 2 gives a clause, naming the sentence where the
    clause number would stand. The rest of the old Decision binds unchanged.

**Out of scope:**

- A port to macOS, or to any other platform. Should one be asked for, it is a
  new decision that supersedes clause 1, not a revival of the clauses this ADR
  restates.
- The `darwin` archives of releases already published. They stay where they are;
  nothing in the fleet installs them.
- The Context, Alternatives, Consequences and _Out of scope_ text of the earlier
  ADRs that names macOS. It records why those decisions were taken and binds
  nothing.
- An Agent that reports `os.type` `darwin` without a Client, such as a Collector
  with its own `opampextension`. The Server serves it as any platform it has
  never heard of (clause 13); no part of the product is tested against it.

## Alternatives considered

- **Keep macOS.** The status quo. It keeps a third service manager, a third
  account model and a third set of system calls in every change to the service,
  the process account and the channel, and two CI runners and two release
  targets, one of which nothing executes, for a platform no fleet runs the
  Client on.
- **Supersede only the clauses that require macOS** — the CI matrix, the release
  targets, the aliases and the operator tool's platforms — and state once that
  every other mention of macOS binds nothing. Much shorter, but it leaves
  binding text that names a platform the product no longer has, and a general
  reading rule is not a supersession of named clauses
  ([ADR-0009](0009-an-adr-may-supersede-named-clauses-of-another.md)). The human
  rejected it.
- **Leave the Decision sentences of ADR-0019 and ADR-0028 as they are**, because
  ADR-0009 names numbered clauses only. ADR-0028's would then publish
  `classisctl` for macOS in binding text that clause 15 contradicts. The human
  chose to remove them.
- **Supersede ADR-0028 whole** to change its first sentence. It would restate
  every clause about the fleet's certificates to remove two words.
- **Keep `DYLD_*` in the refused variables** of ADR-0017 clause 38, as a
  harmless extra on Linux and Windows. It is macOS's loader, and the human chose
  to keep nothing for macOS.
- **Supersede ADR-0019 and ADR-0059 whole** with consolidated successors. Their
  other clauses are unaffected, and restating them would re-decide what nobody
  asked to change.
- **Keep `classisctl` on macOS** for an operator's workstation. It keeps two
  release targets and a platform in the operator documentation for a
  convenience; an operator runs it on a Linux machine, in a virtual machine or
  in WSL.
- **Publish `classisctl` for Windows instead.** A new platform for the operator
  tool, which nobody asked for; it would be a decision of its own.
- **Keep the aliases `macos` and `osx` on the Server.** They exist for files
  named by others (ADR-0026 clause 7). The human chose to keep nothing for
  macOS. An upload named `darwin` is still served under its own name, so only a
  file spelled `macos` or `osx` loses its match with an Agent that reports
  `darwin`, and no Client reports one.

## Sources / Prior art

- [`docs/SPECIFICATION.md`](../SPECIFICATION.md), G-11 and the goal _Ship the
  Client as a self-updating OS service on Linux and Windows_, as this change
  amends them.
- [ADR-0009](0009-an-adr-may-supersede-named-clauses-of-another.md) — the clause
  form of a supersession and the rule that the successor restates the clauses it
  names.
- The code that carries macOS today, read for this record:
  `crates/classis-agent/src/service/manager.rs` (the launchd backend),
  `crates/classis-agent/src/service/run_as.rs` (`Host::MacOs`, `sysadminctl`,
  `dseditgroup`), `crates/classis-agent/src/supervisor/channel.rs` (`peer_cred`
  is `getpeereid` on macOS; `LOCAL_PEERPID`),
  `crates/classis-agent/src/storage.rs` (`O_SEARCH`, `/private/var`), and the
  `client-macos`, `service-smoke` and `apple-darwin` rows of the workflows.
- [OpenTelemetry semantic conventions, OS](https://opentelemetry.io/docs/specs/semconv/resource/os/)
  — the `os.type` values `linux` and `windows`, which are also the values of
  Rust's
  [`std::env::consts::OS`](https://doc.rust-lang.org/std/env/consts/constant.OS.html)
  on those platforms.

## Consequences

- Positive: the service, the process account and the channel each have two
  implementations instead of three, and each security argument of ADR-0054 and
  ADR-0059 is made for two platforms. CI drops the `client-macos` job and the
  macOS row of the service smoke test, and the release drops two targets, one of
  which was never executed. `cfg(unix)` stops hiding a second Unix behind
  Linux's tests.
- Negative / trade-offs: an operator whose workstation is a Mac runs
  `classisctl` elsewhere. A future macOS port starts from nothing in the tree
  and has to make again the launchd, account and peer-check decisions this ADR
  removes; the earlier ADRs keep their reasoning.
- Negative / trade-offs: this ADR restates thirty-two clauses and two Decision
  sentences to remove a few words from each. A reviewer checks each against the
  text it restates. The differences are the macOS text, the platform counts
  (three becomes two or both), "Unix" read as Linux where it meant Linux and
  macOS, the clause numbers it cites, each now pointing at the clause in force
  (this ADR's where it restates it, the successor's where another ADR did), and
  one positive statement in clause 13: the Client reports Rust's own
  `linux`/`windows` as `os.type`, where it reported `darwin`.
- Follow-ups: the implementation, cut into slices — the CI and release rows; the
  macOS code of the Client and its tests; `classisctl` and the platform aliases;
  the documents (`README.md`, `docs/GLOSSARY.md`, `docs/ARCHITECTURE.md`,
  `docs/HARDENING.md`, `docs/manual/`, and the comments of
  `config/supervisor.toml` and `.devcontainer/devcontainer.json`). Every
  `Verifies:` marker that names a clause this ADR supersedes moves to the clause
  that restates it.

## Enforcement

The implementation adds, each with a `Verifies: ADR-0067` marker:

- a test in `crates/classis-tools/tests/release_workflow.rs` that fails when
  `.github/workflows/release.yml`, `.github/workflows/ci.yml` or
  `.github/workflows/service-smoke.yml` names an `apple-darwin` target or a
  `macos-` runner;
- a structural test beside `crates/classis-core/tests/dependency_direction.rs`
  that fails when a Rust source under `crates/` names `target_os = "macos"`;
- a unit test in `crates/classis-core/src/platform.rs` that `canonical_os`
  passes `macos` and `osx` through unchanged.

**Not mechanically decidable:** that each restated clause differs from the
clause it restates only by its macOS text and its clause references, and that no
document presents macOS as a platform the product runs on, are review.
