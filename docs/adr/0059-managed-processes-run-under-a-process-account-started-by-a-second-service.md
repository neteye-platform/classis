# ADR-0059: Managed Processes run under a process account of their own, started by a second service that runs under it

- **Status:** 🟢 accepted
- **Date:** 2026-10-24
- **Deciders:** Markus Brigl, Davide Zeni
- **Applies to:** the `--process-account` flag of `service install` and the
  second service it registers in `crates/classis-agent/src/main.rs`,
  `crates/classis-agent/src/service/manager.rs`,
  `crates/classis-agent/src/service/run_as.rs`,
  `crates/classis-agent/src/service/windows_config.rs` and
  `crates/classis-agent/src/service/windows_rights.rs`, what a former account is
  withdrawn and the record of what an install left to finish in
  `crates/classis-agent/src/service/withdrawal.rs`, the install lock, the pipe,
  the job objects and the handle-based walks in
  `crates/classis-agent/src/win32.rs` and `crates/classis-agent/src/win32/`,
  `service start`, `service stop` and `service uninstall` on Windows, the stop
  and unregister actions of `packaging/windows/supervisor.wxs`, the steps
  `packaging/linux/postinst` prints, every place a Supervisor starts a program
  in `crates/classis-agent/src/supervisor/process.rs`, the channel between the
  Client and the second service, the modes, ownership and ACLs of the
  Supervisors' directories in `crates/classis-agent/src/storage.rs`, the Client's
  check of the second service's end of the channel and the second service's own
  process attributes in `crates/classis-agent/src/supervisor/channel.rs` and
  `crates/classis-agent/src/supervisor/channel/windows.rs`, the query of the
  second service's process from systemd, launchd and the SCM in
  `crates/classis-agent/src/service/manager.rs` and
  `crates/classis-agent/src/service/windows_config.rs`, and every document that
  tells an operator which account a Managed Process runs as or what the
  separation by a process account holds against a Managed Process
- **Supersedes:**
  [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clauses 3 and 39;
  [ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
  clause 6;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 60;
  [ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
  clauses 21 and 37;
  [ADR-0053](0053-the-state-directory-comes-from-the-registration-not-the-file.md)
  clause 1;
  [ADR-0054](0054-no-privileged-install-step-follows-a-link-the-account-placed.md)
  clause 1;
  [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  clause 13

## Context

[ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md) runs
the Client as a system service under an account of its own. "The same account
runs every Managed Process its Supervisors start" (ADR-0042, Context). Every
Managed Process can therefore read everything the Client can: the whole
`state_dir` with the Client's private key `client-key.pem`
(`crates/classis-agent/src/tls.rs:20`), the `config/` of every other Supervisor,
and the Client's own environment through `/proc`. It can also rewrite its own
`program/` and so outlast the next package. With the Client's key a process can
present itself to the Server for any `instance_uid` of its host
([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).
A Managed Process is code the Supervisor does not vouch for
([ADR-0041](0041-a-managed-process-states-only-its-own-service-attributes.md),
Context), and a Configuration's language can run commands as it: a Telegraf
`inputs.exec`, an Icinga `CheckCommand`, a GLPI deploy task.

A Supervisor starts programs in three places
(`crates/classis-agent/src/supervisor/process.rs`): the Managed Process (`:868`),
the version probe (`:944`) and the preflight of a staged package (`:1043`),
which runs a package before it is trusted. All three run as the Client today.

Separating the accounts needs something that may start a process under another
account. The sources below show:

- On Linux, `CAP_SETUID` and `CAP_SETGID` permit "arbitrary manipulations" of a
  process's user and group IDs, uid and gid 0 included (capabilities(7)). A
  Client that holds them is root in all but name, and SafeSetID still allows
  arbitrary `setgroups()`. A process can signal another account's process only
  with `CAP_KILL` (kill(2)), so the process-group stop of
  [ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
  breaks without it.
- On macOS a non-root process cannot change its user ID (setuid(2)), and
  launchd's `UserName` applies only in the system domain (launchd.plist(5)).
- On Windows a service can start a child under a restricted version of its own
  token without `SeAssignPrimaryTokenPrivilege` (CreateProcessAsUserW), but
  whether the supported agents still reach the network and RPC under such a
  token is unverified. A second service under its own virtual account needs no
  password. Every Managed Process today also inherits `SeImpersonatePrivilege`
  from a `LocalService`-like account.

The second service shares its account with every Managed Process it starts. On
Linux and macOS its socket lies in a directory the process account owns (clause
9), so a Managed Process could remove the socket and bind its own at the name;
on Windows it could create an instance of the pipe, which the pipe's security
descriptor grants the process account. To be there when the Client connects
again it must outlive the Client's last connection, which ends every program the
second service started: on Unix by leaving its process group, on Windows through
a broker outside its job. A check of the peer's account alone would accept it,
and the impostor would receive what the Client sends: each program to start, its
arguments and environment, and the Supervisor Endpoint's token. It would gain no
account it does not already run under, but what it starts would no longer end
with the Client's connection, and what it reports of a program's start and exit
to the Client — and through the Client's health to the Server — would be its own
word.

The account cannot tell the two apart; the process can. Each service manager
knows the process it runs as the second service — systemd its `MainPID`, launchd
the job's `pid`, the SCM the service's process id — and each platform reports
the process at the other end of a local connection: `SO_PEERCRED` and, from
Linux 6.5, `SO_PEERPIDFD` on Linux, `LOCAL_PEERPID` on macOS,
`GetNamedPipeServerProcessId` on Windows.

A process id alone has two limits. It can be reused: a process that listened and
then ended leaves its id behind, and a later process — the restarted second
service among them — can be given it; polkit's check of a caller by process id
failed this way (CVE-2013-4288) and moved to the process's start time and to
pidfds. And a Managed Process under the same account can reach into the real
second service itself instead of replacing its socket: on Linux by `ptrace`,
`/proc/<pid>/mem` or `pidfd_getfd`, where Yama is absent or
`kernel.yama.ptrace_scope` is 0, which permit it for a process that is not a
descendant; on Windows by `OpenProcess` with the rights the process's default
security grants its own account. A process that marks itself not dumpable
(`PR_SET_DUMPABLE` 0) is closed to all three on Linux for any caller without
`CAP_SYS_PTRACE`, whatever Yama says. On macOS `task_for_pid` refuses a caller
of the same user without the debugging entitlement.

## Decision

We will run every Managed Process, and every program a Supervisor starts, under
one process account that the operator names, through a second service that runs
under that account and starts, signals and stops those programs on the Client's
request. The Client speaks to the second service only where its process is the
one the service manager runs as the second service.

1. **The process account is named at registration, and kept.**
   `service install --process-account <account>` names it, at system scope only;
   it conflicts with `--user`. A re-registration without the flag keeps the
   account the second service's registration names (clause 2), read the way
   clause 10 reads the Client's. Without the flag and without such a
   registration, there is no process account and no second service, and the
   Client starts its programs itself, as before (clauses 11 and 13 hold on every
   host).
   - **The operator creates the account.** On Linux and macOS it must exist, and
     an install naming one that does not is refused before anything is written,
     with a message that shows the `useradd --system` line, and on macOS the
     `sysadminctl -roleAccount` line, that creates it. The binary never creates
     an account (clause 10).
   - **Windows accepts only passwordless forms**, as clause 10 does: the second
     service's own virtual account `NT SERVICE\<PRODUCT_NAME>-agents`
     (recommended), a gMSA, or `NT AUTHORITY\LocalService` / `NetworkService`. A
     gMSA is looked up in its domain, and an account that cannot be found is
     refused before anything is written.
   - **It is never root and never the Client's account.**
     `--process-account root`, `LocalSystem` or the account the Client runs as
     is refused, naming `--run-as root` as the way to run everything as root. A
     host whose agents need root runs as root as a whole (clause 10), with no
     second service.
   - **On Windows the Client then runs under an account of its own.** A process
     account separates the Managed Processes from a Client that runs under its
     own account, so the install refuses one where the Client would run as
     `LocalSystem`: `--run-as` names the Client's account, or the registration
     keeps the one the SCM holds (clause 10). The refusal names `--run-as` as
     the way to name it, with `NT SERVICE\<PRODUCT_NAME>` where no account was
     named.
   - **It is dropped on request.** `service install --no-process-account` stops
     and deregisters the second service, and the Client starts its programs
     itself again. It conflicts with `--process-account`, and a refusal that a
     kept process account causes names it. What the dropped account was granted
     is withdrawn from it (clause 16).

2. **Restates ADR-0019 clause 3. The service is `PRODUCT_NAME`, with no suffix,
   on every platform, and the second service is `<PRODUCT_NAME>-agents`.** The
   label is a single token — no qualifier, no organization — so
   `service-manager` renders the same string for systemd, launchd and the SCM,
   and the name never contains a dot. The second service exists only where a
   process account is named (clause 1); its label is the product's with the
   suffix `-agents`. The `PATH` symlink is `/usr/bin/<PRODUCT_NAME>`, so two
   variants never collide on one `PATH` entry. On Windows the SCM additionally
   carries each service's display name and a Description that says what the
   program does.
   - **It is the same program.** The second service runs
     `supervisor run --agents` from the same layout and `current` (clause 8),
     under the process account. The package still delivers one file (ADR-0042
     clause 3).
   - **The two are registered, started, stopped and deregistered together.**
     `service install`, `start`, `stop` and `uninstall` act on both, the second
     service first on start and last on stop: under systemd the Client's
     `Wants=` and `After=` start it first, under launchd and the SCM the start
     names it first. Its unit carries the directives ADR-0042 clause 7 sets for
     its account; its plist names the account in `UserName`. Under the SCM it is
     registered as clause 9 says.
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
     whose start finds the second service unreachable is not held for failing to
     start; it tries again with backoff. The Client connects again whenever the
     second service has restarted. A program the second service stops because it
     is stopping itself has not exited on its own, and counts for no restart
     policy.
   - **What arrives while the second service is away waits for it.** An offered
     package is staged and kept, never swapped in: it is swapped in, and its
     apply grace runs, once the second service is reached again, so the previous
     program stays in place and a rollback only ever goes back to a program that
     ran. A delivered Configuration is written as today, and its acknowledgement
     is given by the first start of an apply or of the retry that reaches the
     second service and survives the apply grace; a restart command's start
     acknowledges nothing and swaps nothing in (ADR-0017 clause 8), and the
     retry follows it at once. A Supervisor held after a package that failed
     leaves no Configuration waiting: it is reported `FAILED`. Until then the
     package stays `Installing` and the Configuration `APPLYING`, each naming
     the second service as the reason. A newer offer or Configuration replaces
     the waiting one, and a Client that stops while one waits leaves its files
     as the record names them.
   - **A self-update restarts whichever end is behind.** The self-update
     switches `current` and restarts the Client as before. A second service that
     meets a Client of another build while `current` no longer names its own
     version exits, so that its service manager starts it from `current`; a
     Client that meets a second service of another build while `current` no
     longer names its own version exits for the same restart. A peer of another
     build is otherwise refused (clause 5), and only a peer of the admitted
     account can cause either exit (clause 4).

3. **Every program a Supervisor starts is started by the second service.** Where
   a process account is registered, the Managed Process, the version probe and
   the preflight of a staged package run under the process account, through the
   second service. The Client starts none of them itself.

4. **The channel admits the Client's account alone, the Client speaks to the
   second service alone, and the channel ends with the Client.** On Linux and
   macOS the second service listens on a Unix socket, on Windows on a named
   pipe. Every connection is checked by the peer's credentials (`SO_PEERCRED`,
   `getpeereid`, the pipe client's token) and refused unless its user is the
   Client's account. One connection is served at a time. When it closes, the
   second service stops every program it started, by its process group on Unix
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
     first of its name (`FILE_FLAG_FIRST_PIPE_INSTANCE`), so a pipe someone else
     made under the name first fails the second service's start, and every
     instance rejects remote clients (`PIPE_REJECT_REMOTE_CLIENTS`).
   - **Each end checks the other's account.** The Client opens the pipe at the
     identification level (`SECURITY_IDENTIFICATION`), so the second service may
     identify it and act as nobody, and accepts the pipe only where its owner is
     the process account; on Unix it accepts a peer whose uid is the process
     account's. The second service reads the client's token by impersonating it
     at that level, and refuses a client that is not the Client's account. It
     refuses to run as `LocalSystem`, to serve `LocalSystem`, or to serve its
     own account.
   - **The Client checks the process too.** Before it writes anything on a new
     connection, the Client reads the process at the other end — on Linux
     `SO_PEERPIDFD`, and `SO_PEERCRED` only where the kernel does not know that
     option (`ENOPROTOOPT`), any other error being a process that cannot be
     read; on macOS `LOCAL_PEERPID`, on Windows `GetNamedPipeServerProcessId` —
     and then asks the service manager for the process it runs as the second
     service: systemd the unit's `MainPID`, launchd the job's `pid`, the SCM the
     service's process id from `QueryServiceStatusEx`. It accepts the connection
     only where both name the same process. With a pidfd it also requires that
     the process the pidfd refers to is still running once the service manager
     has answered, so the id cannot have passed to another process in between.
     The account is still read as the bullet above says, from the peer's uid or
     the pipe's owner. A connection whose process cannot be read, or that the
     service manager names no process for, is refused as one whose process
     differs.
   - **A refused peer learns nothing.** The Client closes a connection it
     refuses before it sends the handshake or any request. It logs an error
     naming the socket or pipe and the peer's process id, and treats the second
     service as away: it tries again with the backoff it uses for a second
     service that is not running, each time on a new connection checked anew,
     and the Supervisors report the second service unreachable as they do then
     (clause 3).
   - **The second service closes its process to the Managed Processes where it
     can.** On Linux it marks itself not dumpable (`PR_SET_DUMPABLE` 0) as the
     first thing its program does, before it reads its configuration or sets up
     its log, and does not listen while `/proc/self/status` names a tracer
     (`TracerPid` other than 0), so from then on no process of its own account
     without `CAP_SYS_PTRACE` can attach to it, read or write its memory, or
     take its file descriptors, whatever `kernel.yama.ptrace_scope` says; the
     programs it starts are dumpable as usual, since `execve` resets the mark.
     On macOS the platform already refuses `task_for_pid` to a caller of the
     same user without the debugging entitlement. On Windows the process keeps
     the default security its account gives it.
   - **Each program runs in a job of its own.** On Windows the second service
     starts every program suspended, assigns it to a new job object with
     `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then lets it run, so
     everything it starts is in that job too. At the end of each connection, and
     so before it reports itself stopped, the second service ends every job it
     holds and waits, up to five seconds, until none holds a process.

5. **The requests are what the Supervisor does today, and both ends are one
   build.** The Client asks the second service to start a program with its
   arguments, environment and working directory, to signal or stop one, and to
   report its exit, and to remove what the process account wrote under a
   Supervisor's directory when that Supervisor is purged; the second service
   streams each program's output back. The programs run with the second
   service's own umask, never one widened for the Client's sake. The messages
   are private to the build: both ends run from `current`, and a peer that
   states another version is refused. Windows has no signals: there the second
   service refuses a signal, a stop ends the program's job with everything in
   it, and a kind that would reload its agent by a signal restarts it, as it
   does without a process account.

6. **The process account reads what it runs and writes only its own data.** On
   Linux and macOS the process account's primary group is made a supplementary
   group of the Client's account by the operator, and the install refuses to
   register where it is not, or where the process account's primary group is
   group 0 or the Client's own primary group, where it has a member other than
   the Client's account or is the primary group of an account other than the
   process account, or where the process account is a member of the Client's
   primary group: the group is the process account's own. Every file and
   directory the Client keeps under `state_dir` that the table does not name —
   its logs among them — stays the Client's alone. Then:

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

   On Windows the same split is made by ACL grants to the process account's SID,
   and no group is checked or shared:

   | The process account                                       | Grant on the directory itself                           | Grant on what it holds                                                       |
   | --------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------- |
   | passes through (`state_dir`, each Supervisor's directory) | none: it passes by `SeChangeNotifyPrivilege` (clause 9) | none                                                                         |
   | reads (`program/`, the preflight's staging, `config/`)    | read and execute, `(OI)(CI)`                            | read and execute                                                             |
   | writes (a kind's data directories)                        | modify without `DELETE`                                 | modify, `(OI)(CI)` and inherit-only on the directory, explicit on each entry |
   | runs (`versions\` of the layout)                          | read and execute, `(OI)(CI)`                            | read and execute                                                             |

   Every grant is explicit on what exists and inherited by what is created after
   it, and replaces the explicit allow entries the process account held there.
   No other entry grants the process account anything by name, the Client's key
   and logs among them. In a root the install takes over, nothing grants it
   anything through a group either; a root the operator named keeps the explicit
   entries it had.
   - **Every walk goes one handle at a time.** Each entry is opened as itself,
     never through a symbolic link or junction, and no walk enters one. A
     directory on the way is held open without sharing delete, so it cannot be
     renamed or replaced under the walk. A regular file with a second hard link
     is skipped and named in a warning: its other name may stand anywhere on the
     volume. A walk that grants, hands over (clause 10), takes over or cuts off
     leaves an entry the process account owns, with everything beneath it, as it
     is.
   - **What it cannot hold, it either fails on or reports.** A walk that takes
     rights away — a withdrawal (clause 16), or the take-over or cut-off of a
     root a system-scope install restricts to `LocalSystem` and the
     Administrators — fails where it finds a directory it cannot hold, or an
     entry it cannot open, so nothing it cannot reach safely is left as it was.
     A walk that only adds rights — a grant, the hand-over — skips such an entry
     and names it in a warning.
   - **Every DACL set is read back.** A DACL is set on the entry's own handle
     and changes that object alone; what a directory passes on to what it
     already holds is applied by the walk itself. The DACL the object then holds
     is read back and compared with what was set by what it says — the same
     entries in the same order and the same protection, however they are spelled
     — and a difference fails the change.
   - **The install's walks hold the backup, restore and take-ownership
     privileges** for as long as they run, so an entry another account made, or
     one a Managed Process protected from the Administrators, is opened all the
     same.

   An install grants and withdraws the process account's rights in the data
   root, the layout root and the state directory alone: a Supervisors' root
   outside them is the operator's (ADR-0053 clause 5), left as it is and named
   in a warning.

7. **A program inherits nothing of the Client's.** Its environment is the second
   service's own, then the block's `env` laid over it, then the Supervisor
   Endpoint's token, last
   ([ADR-0015](0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)
   clause 16). On Linux and macOS the second service's own has `HOME`, `USER`
   and `LOGNAME` set to the process account's. On Windows it is the environment
   the SCM gives the second service under the process account, unchanged.

8. **Restates ADR-0053 clause 1. The executable layout is versioned side by side
   behind a `current` pointer, and the registered command line names the second
   service where there is one.**

   ```text
   <layout root>/versions/supervisor-<MAJOR.MINOR.PATCH>-<hash>/supervisor[.exe]
   <layout root>/versions/supervisor-…/manifest.toml   # full version string, binary SHA-256
   <layout root>/current -> versions/supervisor-…/      # symlink on Unix, junction on Windows
   ```

   - **Directory name.** It is the bare base and the commit short-hash of
     [ADR-0012](0012-versions-resolved-in-the-internal-crate.md)'s version,
     never the pre-release. The release `1.2.3` and a development build heading
     for it are told apart by their commit, and the manifest's full string
     answers release-or-dev.
   - **The program.** The service's program is
     `<layout root>/current/supervisor`, so a version switch never re-registers
     anything.
   - **The switch.** On Unix the pointer is switched atomically: a temporary
     symlink is `rename`d over `current`, never unlink-then-relink. On Windows
     the junction, which needs no symlink privilege, is recreated only while the
     service is stopped. At start the daemon verifies that `current` resolves to
     the version directory it runs from, and repairs a torn switch.
   - **Restaging.** Staging a version already present replaces its contents and
     rewrites its manifest. It skips the write when the staged binary already
     holds the same bytes, because an install arriving through the `PATH`
     symlink runs from that file.
   - **The state directory** is the one ADR-0053 clause 3 decides.
   - **Absolute paths.** Every path is absolute at install time, and the
     registered command line is
     `run --service --config <abs> --state-dir <abs>`, followed, where a process
     account is registered, by `--agents-socket <abs> --process-uid <uid>`
     (clause 2), on Windows by
     `--agents-socket \\.\pipe\<PRODUCT_NAME>-agents --process-sid <SID>`, the
     process account's SID, which the Client accepts as the pipe's owner (clause
     4).

9. **Restates ADR-0042 clause 6. The Client writes its systemd system units
   itself, and `service-manager` installs them.** `manager::install` passes
   `contents: Some(<unit>)` at system scope under systemd. `service-manager`
   still writes the file (mode `0644`), enables it, which reloads the manager's
   configuration, and uninstalls it. The unit holds:
   - `[Unit]`: `Description=<PRODUCT_NAME>`, the same as before. The display
     name stays where ADR-0019 clause 2 puts prose. Where a process account is
     registered, also `Wants=<PRODUCT_NAME>-agents.service` and
     `After=<PRODUCT_NAME>-agents.service` (clause 2).
   - `[Service]`: `ExecStart=` with the program and every argument in double
     quotes. A `\` and a `"` are escaped, a `%` is written `%%` and a `$` is
     written `$$`, so any absolute path reaches the program as it was given.
     Then `Restart=on-failure`, `RestartSec=` set to the restart delay the SCM's
     recovery actions use (ADR-0019 clause 11), `User=` set to the account of
     clause 10, and the directives of ADR-0042 clause 7.
   - `[Install]`: `WantedBy=multi-user.target`.

   The user scope and the launchd plist stay as `service-manager` renders them.
   `service install` never writes, reads or removes anything under
   `/etc/systemd/system/<PRODUCT_NAME>.service.d/`. Drop-ins there belong to the
   operator, outrank the unit, and survive every re-registration.

   The second service's unit is written the same way: `User=` names the process
   account, `ExecStart=` runs `run --agents <socket> --client-uid <uid>`,
   `RuntimeDirectory=` holds the socket, `TimeoutStopSec=` exceeds the time the
   second service takes to stop what it started, and the directives are those of
   ADR-0042 clause 7 for its account.

   Under launchd the second service's plist is the one `service-manager`
   renders, with `UserName` naming the process account; launchd's default exit
   timeout of 20 seconds exceeds the time the second service takes to stop what
   it started. launchd keeps no runtime directory across a boot (`/var/run` is
   emptied), so the socket lives in
   `/Library/Application Support/<PRODUCT_NAME>-agents/`, a directory on a path
   only root writes, made by `service install` and owned by the process account
   and its group at `0750`, and removed with the second service's registration.
   The second service passes through directories it may only search with
   `O_SEARCH`, which macOS has from macOS 13 on: macOS 13 is the oldest macOS a
   Client runs on.

   Under the SCM the second service runs under the process account,
   `NT SERVICE\<PRODUCT_NAME>-agents` or the account clause 1 names, set without
   a password. Its command line is
   `run --agents \\.\pipe\<PRODUCT_NAME>-agents --client-sid <SID>`, the Client
   account's SID, and it starts automatically. As the Client's own entry, it
   carries the recovery actions of ADR-0019 clause 11 — one restart after the
   restart delay, repeated for every failure, and run on a reported failure too
   — its display name and a Description. Its required privileges are
   `SeChangeNotifyPrivilege` alone (SERVICE_REQUIRED_PRIVILEGES_INFO): the SCM
   removes every other privilege from its token, and so from every program it
   starts, so no Managed Process holds `SeImpersonatePrivilege`. A stop waits
   until the service has reported itself stopped and its process has ended, up
   to 60 seconds.

10. **Restates ADR-0054 clause 1. The system service runs under the account its
    registration names, and both roots belong to it, except what the process
    account keeps there.** `service install --run-as <account>` names the
    account. It applies at system scope only and conflicts with `--user`. On
    Linux and macOS, `--run-as root` is how an operator chooses root. It is
    written as `User=root` or `UserName` `root`, so a unit records that root was
    chosen. Without the flag, the account is taken in this order:
    - **A re-registration keeps the account the registration names.** That is
      `User=` in the system unit `/etc/systemd/system/<PRODUCT_NAME>.service`,
      `UserName` in `/Library/LaunchDaemons/<PRODUCT_NAME>.plist`. The install
      reads the file the Client wrote, not a drop-in and not the loaded state of
      the service manager. On Windows it reads the logon account the SCM holds
      for the service (`QueryServiceConfig`) and keeps it, unless that is
      `LocalSystem`, which a registration that names no account runs as. The
      second service's account is read and kept the same way (clause 1). A
      service the SCM holds already is reconfigured in place: its program,
      arguments and start type are rewritten, its logon account is set only by
      the `sc config obj=` step of `windows_config`, and what clause 9 and
      `windows_config` set follows as on a first registration.
    - **A unit or plist that names no account, on a data root that a non-root
      account owns,** was rewritten by a re-registration that dropped its
      account. The install takes the owner of the data root and prints that it
      did, naming the data root. Every other registration that names no account
      stays root.
    - **A first registration**, one where no unit, plist or SCM entry exists,
      runs as root under systemd and launchd and as `LocalSystem` under the SCM.
      The Linux packages name their account themselves (ADR-0042 clause 5).

    The install prints the account and where it came from: `--run-as`, the unit,
    the plist, the SCM's entry, the owner of the data root, or the default. On
    Windows a Client that runs as `LocalSystem` by default prints none.
    - **The service runs as the account.** Under systemd this is `User=` in the
      unit the Client writes (clause 9). Under launchd it is `UserName`, through
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
      kept. An account that does not exist is refused before anything is
      written, and the install fails closed. For a kept account, the message
      names the account and the file or directory it came from. It shows the
      `useradd --system` line that creates the account, and says that
      `--run-as <account>` or `--run-as root` names another. The binary never
      creates an account; that is the packages' job (ADR-0042 clause 5).
    - **The hand-over covers both roots, on every registration that runs under
      an account.** That includes a kept account and root. After laying out and
      registering, the install hands the account the data root
      (`supervisor.toml`, `state/`), because the service reads and rewrites
      them. It also hands over the layout root (`versions/`, `current`), because
      the self-update that stages into it is the service itself. On Unix this is
      an ownership change. On Windows it is a grant of Modify to the account,
      inherited by what each root holds (`(OI)(CI)`) and set explicitly on every
      entry that exists. Where a process account is registered the grant also
      carries `WRITE_DAC`, so the Client can grant the process account its share
      of what the install laid out (clause 6); it never carries `WRITE_OWNER`.
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
      5). On Windows the hand-over walks as clause 6 says, with the backup,
      restore and take-ownership privileges held. Re-running `install` with
      another `--run-as` re-owns the same directories, and what the former
      account was granted is withdrawn from it (clause 16).

11. **Restates ADR-0026 clause 60. Modes come from a `.tar.gz` on Unix, never
    with write for group or others; the program is always made executable.** A
    tar's member modes are applied, each without the group's and others' write
    bits, on every host, whether or not a process account is registered: a
    member written `0777` or `0666` lands `0755` or `0644`, so no account but
    the Client's can rewrite what a Supervisor runs. A `.7z` or `.zip` carries
    Windows attributes, so no mode is taken from it. The program — the single
    file or the member at `program_path` — is set `0755` regardless, so whether
    it can run never depends on how the archive was built; an agent with further
    executables beside its program ships as `.tar.gz`.

12. **Restates ADR-0017 clause 37. An orphaned directory is reported at startup,
    never reaped, except a tombstone, which is reaped.** A directory under the
    root that no block names — a purge cut short, a block removed by hand while
    the Client was down, a moved root — is logged as a warning with its path and
    left in place. Startup cannot tell a leftover from a block temporarily
    commented out, and deleting would cost that Agent its identity and program;
    removing it is the operator's call. A tombstone is different: a purge first
    renames the Supervisor's directory to `.purge-<name>-<nonce>`, a name no
    block can carry, so the name itself records that the Client meant to remove
    it. A tombstone the purge could not delete is removed again at the next
    start and with the next purge, through the second service where a process
    account is registered, and is logged as a warning until it is gone.

13. **Restates ADR-0017 clause 21. One directory per Supervisor, under a
    relocatable root, never on an entry of the Client's.** The top-level key
    `supervisor_dir` defaults to `<state_dir>/supervisors` and is made absolute
    at load. Under it each Supervisor owns `<supervisor_dir>/<name>/`, holding
    everything it needs:

```text
<supervisor_dir>/<name>/
  instance-uid            # its Agent identity
  remote-config.pb        # the last received configuration
  installed-package.json  # what is installed
  config/                 # the written configuration entries
  program/<file>          # the Managed Process — or program/tree/<program_path> for a tree
  packages/               # this Supervisor's download staging
```

One knob moves state and program together. Staging beside `program/` makes a raw
artifact's install a rename on one filesystem. The directory is `program/`, not
`bin/`, because it holds a whole tree for a multi-file package
([ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
Moving `supervisor_dir` on a running host leaves the old tree behind and
migrates nothing; each Supervisor then registers as a new Agent.

Where `supervisor_dir` is `state_dir`, a Supervisor is never named after an
entry the Client keeps there itself (`instance-uid`, `config`, `packages`,
`logs`, `gateway-packages`, `supervisors`), and `supervisor_dir` never is, or
holds, `state_dir` otherwise: a block that would is refused at startup, and an
offered set that carries one fails as a whole (ADR-0017 clause 28). This holds
on every host, with a process account or without one, because a purge of such a
Supervisor would delete the Client's own entry and its share would expose it to
the process account's group. The changelog names the rename this asks of a host
that has one.

14. **Restates
    [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
    clause 13. No installer starts a service it registers anew; an upgrade
    starts again what ran.** The Linux post-install and the MSI register the
    service and leave it stopped — knowingly departing from Debian Policy and
    `dh_installsystemd` — because a Client with no configuration holds no client
    certificate and is refused at startup, at fleet scale where nobody watches a
    terminal. The exceptions are upgrades of a host whose services were running.
    On Linux a running service is restarted, so a configured host finishes the
    upgrade on the delivered binary. On Linux and macOS an install that names
    another process account than the registration, drops it, or names another
    `--run-as` stops the services first and starts again what ran once it has
    succeeded (clause 16). On Windows every `service install` — every upgrade of
    the MSI among them, with a process account or without one — stops both
    services before it changes any right or SCM entry, and once it has succeeded
    starts again what ran before it; a first install finds nothing to stop and
    starts nothing. The post-install prints the two remaining steps:

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
      stopped and its process has ended (clause 9); the second service's
      programs end with it (clause 4). Where the second service cannot be
      stopped, the Client is started again if the stop stopped it, and the
      install changes nothing more.
    - **What ran is recorded before the stop.** The install asks the SCM which
      of the two run, a service starting or stopping counting as running, and
      writes that, with a withdrawal that is due (clause 16), to the record of
      clause 17 in one write before it stops anything. A record that cannot be
      written stops nothing. What the stop then finds running beyond it is
      added.
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

15. **Restates
    [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
    clause 39. The MSI asks for the installation folder, the endpoint and the
    self-update consent, all as public properties, and stops and unregisters
    only on a real removal.** The UI is a copy of the stock `WixUI_InstallDir`
    set with one dialog inserted —
    `WelcomeDlg → InstallDirDlg → EndpointDlg → VerifyReadyDlg` — and **no
    licence page**: Apache-2.0 needs no click-through, and the dialog wants a
    second copy of `LICENSE` as RTF. It is a copy with the navigation
    re-pointed, as WiX's customization guide prescribes, because overriding a
    stock set's rows in place depends on control-event ordering the toolset may
    renumber.

    | property        | dialog                                  | effect                                                                                         |
    | --------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------- |
    | `INSTALLFOLDER` | `InstallDirDlg`, via `WIXUI_INSTALLDIR` | where the payload goes; default `C:\Program Files\<PRODUCT_NAME>`                              |
    | `ENDPOINT`      | `EndpointDlg`, an `Edit` control        | `service install --endpoint`; empty means none                                                 |
    | `SELFUPDATE`    | `EndpointDlg`, a checkbox, default `1`  | the consent of [ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md) clause 3 |

    `INSTALLFOLDER` is **one directory the operator configures**, holding only
    the delivered payload. The layout and the state directory go to
    `%ProgramData%\<PRODUCT_NAME>` and no root reaches the command line
    (ADR-0019 clause 8), so an uninstall empties the folder and the
    configuration survives where Windows expects data to. All names are
    upper-case and listed `Secure`: Windows Installer resets private properties
    between the UI and execute sequences, and `Secure` lets the same MSI run
    unattended:

    ```console
    msiexec /i supervisor_1.2.3_windows_amd64.msi /qn ^
      ENDPOINT="wss://fleet.example.com/v1/opamp" SELFUPDATE=0
    ```

    Registration is a **deferred type 18 custom action with
    `Impersonate="no"`**, after `InstallFiles` — the executable it runs is the
    one being installed — whose formatted command line receives the properties
    without a `CustomActionData` round trip. It is two actions under opposite
    conditions on `ENDPOINT`, because `--endpoint ""` is rejected by the loader
    while no flag is the ordinary configure-later install. Stop and unregister —
    `service stop`, then `service uninstall` — run only on a real removal,
    best-effort, before `RemoveFiles`, under the condition
    `REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`. A major upgrade removes the old
    product with `REMOVE` set to `ALL` as well, and sets `UPGRADINGPRODUCTCODE`
    while it does, which a removal from Add or Remove Programs does not;
    `REMOVE="ALL"` alone would unregister the services in the middle of every
    upgrade, where the successor's `service install` re-registers them (clause
    14,
    [ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
    clause 3). **The `UpgradeCode` is minted once and never changed** — it is
    how Windows Installer recognises 1.2.4 as an upgrade of 1.2.3, and a new one
    strands every installed host — paired with `MajorUpgrade`, with the
    `ProductCode` regenerated per build. The MSI asks for no client identity:
    the certificate and its key are files the operator puts on the host, and
    `EndpointDlg` says that they are added to `supervisor.toml` afterwards, or
    through `service install --interactive` from an elevated prompt. It mentions
    no credential, because the Client reads none
    ([ADR-0021](0021-admission-by-a-client-certificate-alone-and-a-revocation-list-that-follows-renewal.md)).

16. **A former account keeps no share.** Where an install drops the process
    account (`--no-process-account`), names another, or names another `--run-as`
    for the Client, every share with the former account in the roots an install
    acts on (clause 6) is withdrawn, on every platform, except a file with a
    second hard link, which is named in a warning (clause 6). A Supervisors'
    root outside those roots stays the operator's.
    - **On Linux and macOS a change of owner withdraws it.** The hand-over
      (clause 10) gives what the former account owns there, and what is in its
      group, to the Client's account and group, and what the process account
      named now keeps is left to it.
    - **On Linux and macOS an account change stops the services first.** Where
      the registration names a process account and the install names another or
      drops it (`--no-process-account`), or where `--run-as` names another
      account than the registration, the install stops the Client and then,
      where one is registered, the second service, before it rewrites a unit or
      plist or changes an owner. It waits for each until its process has ended,
      up to 60 seconds each as clause 9's stop does; a service whose process has
      not ended by then has not stopped. So nothing runs under an account whose
      files are being re-owned. What ran is what systemd reports active or
      activating, and what launchd reports loaded with a process. Once the
      install has succeeded it starts again what ran of what is still
      registered, the second service first (clause 2). An install that changes
      no account — one that adds a process account where none was among them —
      stops nothing beyond what clause 14 says.
      - **A failed stop changes nothing more.** Where a service cannot be
        stopped, the install starts again what it stopped, changes nothing more,
        and says so.
      - **A failed install leaves the services stopped, and says so.** Its
        message names which services ran before it and that `service start`
        starts them. Unix keeps no record of them, so no later install starts
        them; `service start` does.
    - **On Windows its entries are removed and what it owns is taken over.**
      Every entry that allows the former account anything, explicit or
      inherited, is removed from every entry of the layout root, the data root,
      the state directory, the configuration file and the fleet files copied
      beside it, and an entry the former account owns is given to the
      Administrators. An entry that denies it stays. The walk goes as clause 6
      says and fails closed. `LocalSystem` is never withdrawn: it keeps full
      control of every root.
    - **Former accounts are resolved before anything changes.** The install
      reads the accounts the two SCM entries name and resolves each that is to
      go to its SID before it writes anything; one that cannot be resolved — a
      gMSA whose domain cannot be reached — fails the install there, since its
      grants would otherwise stay. An account named as before is not withdrawn,
      nor one named now in the same part.
    - **The withdrawal is recorded before the SCM forgets the account.** It is
      written, with the SIDs and the roots, to the record of clause 17 before
      the stop of clause 14, and so before the SCM entries are switched. It is
      carried out after the switch and before the hand-over and the layout's
      share, which grant what the accounts named now are to hold, and struck
      from the record only once all of it has succeeded. An install that finds a
      withdrawal recorded completes it.
    - **An uninstall always deregisters, and withdraws only once both services
      are stopped.** `service uninstall` on Windows stops both services and
      waits for each, starting neither again. Where it holds the install lock
      (clause 17) and both are stopped, it completes a recorded withdrawal and
      removes the record. Otherwise it leaves the record as it is and says that
      the next `service install` or `service uninstall` completes it. Either way
      it then deregisters both services, so none is left to start at the next
      boot.

17. **On Windows the install keeps what it left to finish, and runs one at a
    time.**
    - **The record.** What an install left to finish — the former accounts by
      part and SID, the roots to withdraw them from, and the services to start
      again — is the string value `Pending` of
      `HKEY_LOCAL_MACHINE\SOFTWARE\<PRODUCT_NAME>\WithdrawalPending`. The
      install creates the key owned by the Administrators (`O:BA`) with a
      protected DACL that grants `LocalSystem` and the Administrators full
      control and nobody else anything (`D:P(A;;KA;;;SY)(A;;KA;;;BA)`). It reads
      and writes the key only where `LocalSystem` or the Administrators own it
      and it carries that DACL; a key that does not fails the install, which
      changes nothing until an Administrator has looked at it and removed it.
      Nothing the Client or a Managed Process may write holds the record. Unix
      withdraws by a change of owner and keeps no record.
    - **The install lock.** `service install`, `service uninstall`,
      `service start` and `service stop` are serialised by the mutex `lock` in
      the private namespace `<PRODUCT_NAME>-install`, whose boundary holds the
      Administrators' SID and the high integrity level, so only an elevated
      Administrator or `LocalSystem` can create it; the namespace and the mutex
      both carry `O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)`. Only the process that
      created the namespace holds the lock. One that finds the namespace there
      waits on its mutex until the creator lets it go, then begins again in a
      namespace of its own, for up to 300 seconds in all, after which it fails,
      saying that another run holds the lock. A mutex in the namespace owned by
      anyone but `LocalSystem` or the Administrators is refused.
    - **An uninstall without the lock still stops and deregisters.** It leaves
      the record alone, since another run may be rewriting it, and says so.

**Out of scope:** an account per Supervisor; making a process account the
default where none is named; job objects for a host without a process account;
what the Managed Processes can read of one another, which they share by this
decision; a compromised Client, which can place any program under `program/`; on
Windows, a Managed Process that opens the second service's process with the
rights its own account holds on it — to duplicate its pipe handle or run code in
it — which no check of the peer can tell; on Linux where Yama is absent or
`ptrace_scope` is 0, a Managed Process that attaches to the second service
between its `execve` and the mark — after killing it so that its service manager
starts it again — and that, as a tracer, can also make the second service read a
`TracerPid` of 0; a process id reused on Linux before 6.5, on macOS and on
Windows, where the platform gives the Client no handle that pins the peer's
process; the second service noticing that its socket was replaced; a socket the
service manager creates and owns (socket activation); a peer that is the second
service's process but runs a build other than the Client's, which the handshake
already refuses (clause 5).

## Alternatives considered

- **Let the Client switch accounts itself.** On Linux it needs `CAP_SETUID`,
  `CAP_SETGID` and `CAP_KILL` in its unit, which permit uid and gid 0, so a
  compromised Client is root; every child must also clear the ambient and
  inheritable sets, or it inherits them. On macOS the Client must be root. On
  Windows a restricted token is unproven for the agents' network and RPC use.
  Rejected for making the Client root-equivalent.
- **A setuid-root helper bound to the process account.** It is a second file in
  the package, against ADR-0042 clause 3, lives outside the layout the
  self-update rewrites, and is the classic target. Rejected.
- **A root parent that keeps privileges and drops them for the Client and the
  processes**, as nginx and postfix do. It brings back the long-running root
  process ADR-0042 removed. Rejected.
- **Transient units through systemd's D-Bus API, or `sudo -u`.** The first needs
  the polkit right to manage units, which cannot be narrowed to one account and
  exists on Linux only; the second does not relay `SIGKILL` (sudo(8)). Rejected.
- **An account per Supervisor.** It also separates the Supervisors from one
  another, but needs one service or one privilege per account. Not taken now.
- **Keep the key out of the processes' reach instead** (kernel keyring, TPM, a
  key helper). It protects the key alone, and leaves every other Supervisor's
  `config/` and the program directories writable. Rejected.
- **Create the process account in the packages and by `service install`.** The
  packages could create it as they create the Client's (ADR-0042 clause 5). Not
  taken: the operator names and creates it.
- **Make the Client's SCM entry depend on the second service.** It would order
  the start without the CLI, but the SCM starts no service whose dependency
  failed, so a second service that does not come up would hold the Client down.
  Rejected: the Client runs without it (clause 2).
- **Re-register on Windows without stopping the services, as Linux restarts only
  what runs.** A running service would go on under an account whose grants the
  install is taking away, or under a registration it rewrites. Rejected for
  clause 14's stop.
- **A mutex under `Global\` as the install lock.** Any account may create an
  object of that name first and hold it. Rejected for the private namespace of
  clause 17.
- **The record in the data root or beneath the service's SCM key.** The Client
  may change the data root's DACL where a process account is registered, a later
  `--data-root` may name it differently, and the SCM's key carries the system's
  own, undocumented DACL and goes with `sc delete`. Rejected for the install's
  own registry key.

- **A socket the service manager owns.** systemd (`ListenStream=` in a socket
  unit) and launchd (`Sockets`) can create the socket as root in a directory the
  process account cannot write, and hand it to the second service, so a Managed
  Process cannot replace it. It closes the replacement on Linux and macOS
  without asking for a process, but not a Managed Process reaching into the
  second service, and Windows has no such mechanism for a named pipe, so the
  Client would need the process check there anyway; two mechanisms, and a change
  to the units, the plist, the socket's place and the command line. Not taken.
- **Close the Windows process too.** A security descriptor on the second
  service's process that denies its own account, through `OWNER RIGHTS`, the
  rights to write its memory, create threads in it and duplicate its handles,
  and a handle the Client holds on the peer's process to pin its id. More
  Windows code that only CI exercises, for a case of low severity. Not taken
  now; it stays a follow-up.
- **The second service checks that its socket is still its own** and binds it
  again where it was replaced. It narrows the window but does not close it — the
  impostor can replace the socket again between two checks — and does nothing on
  Windows. Rejected; the Client's check closes the replacement.
- **A secret only the Client and the second service share** — a token the second
  service proves at the handshake. The second service would have to keep it
  where its own Managed Processes, running under its account, cannot read it. On
  Linux a process that is not dumpable would keep it so, but the process check
  needs nothing kept, and on Windows the secret would be as open as the process.
  Rejected.
- **Report a refused peer to the Server too.** The Server would see it in the
  fleet view. The Client's health already shows the second service unreachable,
  and the log names the impostor; a new health detail is a protocol matter of
  its own. Not taken now.
- **Keep the replacement as a residual.** The separation holds everywhere else;
  leaving this case means a Managed Process can lie about what runs and keep
  what it starts alive past the Client's connection. Rejected; what remains is
  named under _Out of scope_.

## Sources / Prior art

- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html):
  `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL`, and the ambient set across `execve`.
- [kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html): who may signal
  whom.
- [SafeSetID](https://docs.kernel.org/admin-guide/LSM/SafeSetID.html):
  `setgroups()` stays unrestricted.
- [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html):
  `AmbientCapabilities=`, `NoNewPrivileges=`, `ProtectControlGroups=`.
- [sudo(8)](https://www.sudo.ws/docs/man/sudo.man/): `SIGSTOP` and `SIGKILL` are
  not relayed.
- [nginx `user`](https://nginx.org/en/docs/ngx_core_module.html#user): worker
  credentials.
- [Elastic Agent, unprivileged mode](https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged)
  and
  [Datadog's `ddagentuser`](https://docs.datadoghq.com/agent/guide/windows-agent-ddagent-user/):
  how two fleet agents run without root, the latter with a stored password.
- [launchd.plist(5)](https://keith.github.io/xcode-man-pages/launchd.plist.5.html)
  and [setuid(2)](https://keith.github.io/xcode-man-pages/setuid.2.html) on
  macOS; Apple DTS on
  [role accounts](https://developer.apple.com/forums/thread/692593).
- [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw),
  [Restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens),
  [LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account),
  [service accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts).
- [SERVICE_REQUIRED_PRIVILEGES_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow):
  the SCM removes every privilege not listed from the process token, and never
  removes `SeChangeNotifyPrivilege`.
- [StartService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew):
  `ERROR_SERVICE_DEPENDENCY_FAIL` for a service whose dependency failed to
  start.
- [SetServiceStatus](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus):
  after `SERVICE_STOPPED` the service process can be terminated at any time, so
  a stop waits for the process, not for the state.
- [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights):
  `FILE_APPEND_DATA` and `FILE_CREATE_PIPE_INSTANCE` are one right, so
  `FILE_GENERIC_WRITE` lets a client create an instance; the default descriptor
  grants `Everyone` read.
- [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew):
  `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`.
- [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient):
  an impersonation below `SecurityImpersonation`, such as
  `SecurityIdentification`, is allowed without `SeImpersonatePrivilege`.
- [JOBOBJECT_BASIC_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information):
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ends every process of a job when its last
  handle closes.
- [Object Namespaces](https://learn.microsoft.com/en-us/windows/win32/sync/object-namespaces)
  and
  [AddIntegrityLabelToBoundaryDescriptor](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addintegritylabeltoboundarydescriptor):
  a private namespace is created only by a caller within its boundary and at or
  above its integrity level, and can be opened no more once its creator has
  closed it.
- [SetKernelObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setkernelobjectsecurity),
  [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
  and
  [SetPrivateObjectSecurityEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setprivateobjectsecurityex):
  Learn points file systems to `SetSecurityInfo`, which propagates what a
  directory passes on to what it holds — the propagation clause 6 does not want,
  since nothing documents that it stays out of a junction or out of what the
  process account owns. The rules of automatic inheritance are documented for
  `SetPrivateObjectSecurityEx` alone. That a DACL set on a file's handle follows
  them, and keeps its protection, rests on the Windows CI runs of the tests
  under _Enforcement_, and every DACL set is read back (clause 6).
- Recalled, not re-read for this record: that `SeImpersonatePrivilege` opens
  paths to `SYSTEM`.
- `crates/classis-agent/src/supervisor/process.rs:868`, `:944`, `:1043`: the three
  places a program is started; `:869-873`: the token is set last.
  `crates/classis-agent/src/storage.rs:354`, `:368`: directories `0700` and files
  `0600` for the Client. `crates/classis-agent/src/service/run_as.rs`: the account
  resolution and the hand-over that follows no link.

- `unix(7)`, `SO_PEERCRED`: the peer's credentials as they were when it called
  `connect(2)` or `listen(2)`; `SO_PEERPIDFD` (Linux 6.5): a pidfd for that
  process. `pidfd_open(2)`, `pidfd_send_signal(2)`: a pidfd refers to one
  process and never to a later holder of its id.
- `prctl(2)`, `PR_SET_DUMPABLE`, and `ptrace(2)`, _Ptrace access mode checking_:
  a process that is not dumpable is denied to a caller without `CAP_SYS_PTRACE`
  in the user namespace, which governs `PTRACE_ATTACH`, `/proc/<pid>/mem` and
  `pidfd_getfd(2)`; the mark is reset by `execve(2)`. The Yama documentation
  (`Documentation/admin-guide/LSM/Yama.rst`) for `ptrace_scope`.
- Apple, `<sys/un.h>`: `LOCAL_PEERPID` at `SOL_LOCAL`; `task_for_pid` and the
  `com.apple.security.cs.debugger` entitlement.
- Microsoft Learn, `GetNamedPipeServerProcessId`, `QueryServiceStatusEx`
  (`SC_STATUS_PROCESS_INFO`, `SERVICE_STATUS_PROCESS.dwProcessId`), and _Process
  Security and Access Rights_.
- `systemd.service(5)` (the main process of a service) and
  `org.freedesktop.systemd1(5)` (`MainPID`); `launchctl(1)` (`print`, whose
  output it does not promise as an interface).
- polkit's `unix-process` subject and CVE-2013-4288: a check of a caller by
  process id alone is open to the id's reuse, which polkit answered with the
  process's start time and later pidfds.

## Consequences

- Positive: a Managed Process, and anything it starts, can no longer read the
  Client's key, its certificates and package state, or the Client's environment,
  and can no longer rewrite the program it runs. A staged package's preflight
  runs under the process account too. No process on the host holds a privilege
  it did not have before, and on Windows no Managed Process holds
  `SeImpersonatePrivilege`. A Managed Process cannot take the second service's
  place by replacing its socket or making an instance of its pipe, so the Client
  does not tell it a program, an environment or the Supervisor Endpoint's token,
  and the programs the Client knows of end with its connection, as clause 4
  promises. On Linux, the Managed Processes cannot read the second service's
  memory either, which holds what the Client sends it.
- Negative / trade-offs: a second service and a private protocol between two
  processes of one build. A restart of the second service stops every Managed
  Process. The Managed Processes still share one account, so they read one
  another's `config/` and environment. Grants that name the Client's account for
  an agent — a sudoers rule for Telegraf's `use_sudo`, the rights Icinga 2 needs
  on its directories — must name the process account instead; the manual and the
  changelog say so. The separation is opt-in, so a host gains it only once its
  operator creates the account and names it.
- Negative, on Windows: a job holds what a program starts itself, not what it
  has an out-of-process broker start for it — a WMI process creation, a
  scheduled task — as a process that leaves its process group outlives the stop
  on Unix. `LocalService` and `NetworkService` are shared with other services of
  the host, so as a process account they separate less than the second service's
  own virtual account. Every `service install` on Windows stops the Managed
  Processes for as long as it runs, an MSI upgrade among them, and one that
  fails after its stop leaves both services stopped until the next one succeeds,
  or until `service start`. On Linux and macOS an install that changes or drops
  an account (clause 16) stops them too, and one that fails after that stop
  leaves the services stopped until the operator's `service start`, since no
  record names what ran.
- Negative, of the check of the process: on Windows a Managed Process can still
  take the second service's place by opening its process, and on Linux before
  6.5, on macOS and on Windows by waiting for a process id to come round again;
  both are named, not closed. Every new connection asks the service manager once
  — a `systemctl` or `launchctl` run, or an SCM query — which adds a few
  milliseconds at the Client's start and after the second service restarts. On
  Linux that needs systemd's system bus, and on macOS it reads
  `launchctl print`, whose output is not a promised interface; where either
  fails, every connection is refused and no Managed Process starts until it
  answers again, which is logged. The second service writes no core dump on
  Linux. A Managed Process can still remove or replace the socket, and while it
  does the Client finds the second service away; that is a denial of what the
  process account's own programs run, which the shared account already allows.
- Follow-ups: an account per Supervisor; making the separation the default; job
  objects for the process tree on a host without a process account; closing the
  second service's process on Windows and pinning the peer's process there and
  on macOS; a socket the service manager owns on Linux and macOS; a health
  detail that names a refused peer.

## Enforcement

Tests that will carry `Verifies: ADR-0059`:

- In `crates/classis-agent/src/service/`: `--process-account` with `--user`, with
  `root`, `LocalSystem` or the Client's account, and with an account that does
  not exist is refused before anything is written; a re-registration without the
  flag keeps the account the second service names; the rendered unit and plist
  of the second service carry its account and the directives of ADR-0042 clause
  7; on Windows its required privileges are `SeChangeNotifyPrivilege` alone.
- In `crates/classis-agent/src/supervisor/`: with a process account registered,
  the Managed Process, the version probe and the preflight are started through
  the second service and none by the Client; a connection whose peer is not the
  Client's account is refused; closing the Client's connection stops every
  program the second service started.
- In `crates/classis-agent/src/storage.rs`: the modes and owners of clause 6, and
  that the Client's key stays `0600` and owned by the Client.
- A Linux integration test in `.github/workflows/service-smoke.yml`, run under
  `sudo`, in which a Managed Process under the process account fails to read
  `client-key.pem` and to write its `program/`.
- The Windows service smoke in the same workflow,
  `on_windows_a_managed_process_runs_under_the_process_account_and_reaches_only_what_it_runs`,
  run elevated on `windows-latest`: the second service's required privileges are
  `SeChangeNotifyPrivilege` alone; a Managed Process runs as
  `NT SERVICE\<PRODUCT_NAME>-agents`, holds no `SeImpersonatePrivilege`, cannot
  read the Client's key or logs nor write its `program/`, reads its `config/`
  and writes its data directory; it runs again after the second service's
  process is killed; a re-registration without either flag keeps both accounts,
  and one while both run starts both again; `--no-process-account` returns the
  program to the Client's account.
- On Windows, in `crates/classis-agent/src/`:
  - the pipe and the channel (clause 4):
    `the_pipe_admits_the_clients_account_alone`,
    `a_pipe_made_first_by_another_is_not_taken_over`,
    `the_client_talks_only_to_the_process_account`,
    `a_peer_of_another_account_is_refused`,
    `only_the_clients_account_is_admitted_and_never_local_system`,
    `closing_the_connection_ends_the_whole_job`,
    `a_job_ends_the_process_it_holds` and `a_signal_is_refused`;
  - the command lines (clause 8):
    `on_windows_both_command_lines_name_the_pipe_and_a_sid`;
  - the ACLs and the walks (clauses 6 and 10):
    `the_process_account_is_granted_what_it_reads_and_writes_and_nothing_else`,
    `on_windows_a_share_is_made_through_no_junction`,
    `on_windows_the_handover_enters_no_junction_and_leaves_the_process_accounts_own`,
    `on_windows_the_handover_lets_the_client_share_with_the_process_account`,
    `on_windows_a_restricted_root_keeps_the_keepers_alone_and_enters_no_link`,
    `a_held_directory_cannot_be_renamed` and
    `a_dacl_is_compared_by_what_it_says`;
  - the accounts (clauses 1 and 10):
    `on_windows_the_process_account_is_a_passwordless_account_of_its_own` and
    `on_windows_a_reregistration_keeps_the_scms_logon_account`;
  - the stop and the start (clause 14):
    `a_stop_waits_for_the_process_it_confirmed_and_fails_on_one_that_keeps_changing`,
    `what_runs_is_recorded_before_the_stop_and_amended_after_it`,
    `a_failed_stop_records_what_runs_no_more`,
    `what_a_failed_install_stopped_is_started_by_the_next`,
    `an_operators_start_or_stop_strikes_what_is_to_run_again`,
    `a_resume_starts_what_ran_in_the_order_start_starts_it` and
    `a_resume_passes_over_only_what_runs_and_waits_on_what_is_pending`;
  - the withdrawal (clause 16):
    `on_windows_a_former_accounts_grants_are_withdrawn`,
    `on_windows_a_former_account_that_cannot_be_found_fails_before_any_change`,
    `an_interrupted_withdrawal_is_completed_by_the_next_install` and
    `an_uninstall_always_deregisters_and_withdraws_only_once_both_are_stopped`;
  - the record and the lock (clause 17):
    `on_windows_the_record_round_trips_through_a_key_only_the_administrators_write`
    and `the_install_lock_excludes_across_logon_sessions`.
- In `crates/classis-agent/tests/msi_exe_command.rs`, which reads
  `packaging/windows/supervisor.wxs`: the stop and unregister actions run under
  the condition of clause 15 and no other.
- On Linux and macOS, in `crates/classis-agent/src/service/` (clause 16): an
  install that changes or drops the process account, or changes `--run-as`,
  stops both services and waits for their processes before it re-owns anything,
  and starts again what ran once it has succeeded; a stop that fails, a wait
  that runs out among them, changes nothing more; an install that changes no
  account, or adds a process account where none was, stops nothing.
- The check of the process (clause 4):
  - With a fake service manager that names one process as the second service,
    the Client accepts a peer of that process and the process account, and
    refuses one of the process account whose process differs, one whose process
    cannot be read, and one the service manager names no process for — each
    before it writes anything, each treated as a second service that is away,
    and each retried on a new connection.
  - On Linux, which CI runs with a kernel that has `SO_PEERPIDFD` and where the
    test fails rather than passes without it: a peer whose listening process has
    ended, while another process holds the listening socket, is refused although
    the service manager names a process of the same id; an error of
    `SO_PEERPIDFD` other than `ENOPROTOOPT` refuses the peer and falls back to
    nothing.
  - On Linux the second service, once listening, reports itself not dumpable
    (`PR_GET_DUMPABLE`), and the test, as its parent and without
    `CAP_SYS_PTRACE`, so that Yama permits it, is refused `PTRACE_ATTACH`,
    `/proc/<pid>/mem` and `pidfd_getfd`; a program it starts is dumpable. The
    second service does not listen while it is traced.
  - The service smoke test: on Linux and macOS a Managed Process the second
    service started leaves its process group and replaces the socket, and the
    Client, restarted, refuses it, writes it nothing, logs it, and starts no
    Managed Process until the second service is restarted. On Windows, with
    `NT AUTHORITY\LocalService` as the process account and the second service
    stopped, a task scheduled under that account creates the pipe; the Client,
    restarted, refuses it as a peer the SCM names no process for, writes it
    nothing and logs it, and once the task has ended and the second service runs
    again, reaches the second service. Which instance of a pipe a client opens
    while the second service holds one too is not determined, so the case of a
    differing process is decided on Windows by the test with a fake service
    manager.
