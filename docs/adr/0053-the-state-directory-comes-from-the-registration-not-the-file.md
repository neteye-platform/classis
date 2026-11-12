# ADR-0053: An installed Client's state directory comes from `--state-dir` or its registration, and from `supervisor.toml` only beneath the install's roots

- **Status:** 🟢 accepted · clause 1 superseded by
  [ADR-0059](0059-managed-processes-run-under-a-process-account-started-by-a-second-service.md)
- **Date:** 2026-10-23
- **Deciders:** Markus Brigl, Davide Zeni
- **Applies to:** the state directory `service install` and `service config`
  take in `crates/classis-agent/src/main.rs` and `ClientConfig::service_state_dir`
  in `crates/classis-agent/src/config_file.rs`, the registration a re-registration
  reads in `crates/classis-agent/src/service/manager.rs`, the directories a
  system-scope install restricts in
  `crates/classis-agent/src/service/windows_rights.rs`, the `state_dir` and
  `supervisor_dir` comments of `config/supervisor.toml`, and every document that
  tells an operator where an installed Client keeps its state
- **Supersedes:**
  [ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clause 9 ·
  [ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
  clause 1

## Context

`service install` runs as root, or as an Administrator on Windows. The Linux
post-install and the MSI run it on every upgrade
([ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
clauses 3 and 5,
[ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
clause 39). `service config` runs the same way.

Both take the state directory from `supervisor.toml`: the absolute `state_dir`
the file names, else `<data root>/state` (ADR-0019 clause 9). The file belongs
to the service's account and is the account's to rewrite (ADR-0042 clause 2).
The install does three things to the state directory:

- It cuts the directory off from inherited rights on Windows and grants the
  account Modify on it.
- It hands it over by a recursive ownership change on Linux and macOS.
- It writes the enrolment's files into it as root.

A Supervisors' root that the file places outside the data root and the state
directory is created, cut and granted on Windows too.

So an account the Server reaches, or anything that compromises the Client, can
name any tree: another service's data, a user's profile, a system directory. The
next upgrade then hands that tree to it. That is a privilege escalation from the
service's account to arbitrary file access on Linux, macOS and Windows. A Server
cannot write those keys: it delivers `[[supervisor]]` blocks only (ADR-0017
clause 27). A compromised service account can.

Taking the state directory from the file only beneath the data root or the
layout root, and from `--state-dir` anywhere, closes the escalation, but it
breaks an upgrade:

- The post-install and the MSI pass no `--state-dir`.
- A host whose operator placed the state directory elsewhere fails
  `service install` inside `apt upgrade`, if the file names that directory.
- If the file does not name it, the host is silently re-registered with
  `<data root>/state`. Its identity then moves, which ADR-0042 clause 1 forbids.

The account a registration runs as has met the same problem before, and ADR-0042
clause 2 settled it: a re-registration keeps what the existing registration
names. That registration is the file the Client wrote as root
(`/etc/systemd/system/<PRODUCT_NAME>.service`,
`/Library/LaunchDaemons/<PRODUCT_NAME>.plist`) or the SCM's entry, and only an
administrator can change it.

Forces:

- **Security before convenience** (Strategy, Q-1): no file the service's account
  can write may steer what an administrator's command does to a directory.
- **An upgrade is a re-registration, never a migration** (ADR-0042 clause 1):
  the instance's configuration, identity and state never move.
- **A Supervisors' root is relocatable** (ADR-0017 clause 21), on purpose:
  programs off a `noexec` or undersized `/var`.

## Decision

We will take an installed Client's state directory from `--state-dir`, else from
the service registration that names it, else from `supervisor.toml` only beneath
the data root or the layout root, else `<data root>/state`, and have an install
act on no directory the file places outside those roots.

1. **Restates ADR-0019 clause 9. The executable layout is versioned side by side
   behind a `current` pointer.**

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
   - **The state directory** is the one clause 3 decides.
   - **Absolute paths.** Every path is absolute at install time, and the
     registered command line is
     `run --service --config <abs> --state-dir <abs>`.

2. **Restates ADR-0042 clause 1. An upgrade on an installed host is a
   re-registration, never a migration.**
   - `--config` keeps pointing into the data root. `--state-dir` keeps pointing
     where the registration has it (clause 3).
   - A re-registration rewrites the program path (`ExecStart`) and the rest of
     the unit or plist from the version that runs it, the directives of ADR-0042
     clause 7 included. The account stays the one the registration names
     (ADR-0042 clause 2).
   - The instance's configuration, identity and state never move.
   - A change that would move the data root or the state directory of an
     installed host must bring its own migration and carries the full weight of
     this rule. An administrator who names another `--state-dir` moves nothing:
     the service then starts on an empty state directory and enrols anew.

3. **The state directory is taken in this order.**
   1. **`--state-dir`**, the global flag (ADR-0019 clause 1), given to
      `service install` or `service config` and made absolute.
   2. **The registration's**, at system scope: the value after `--state-dir` in
      the command line of the registration the Client wrote.
      - Under systemd it is `ExecStart=` of
        `/etc/systemd/system/<PRODUCT_NAME>.service`.
      - Under launchd it is `ProgramArguments` of
        `/Library/LaunchDaemons/<PRODUCT_NAME>.plist`.
      - Under the SCM it is the service's binary path name, read with
        `QueryServiceConfig`.
      - The install reads what the Client wrote, never a drop-in and never the
        manager's loaded state, as ADR-0042 clause 2 reads the account.
      - A registration that names no `--state-dir`, and every user-scope one,
        offers none. A user scope has no administrator between the file and the
        service.
   3. **The file's**: the absolute `state_dir` that `supervisor.toml` names, and
      only beneath the data root or the layout root (clause 4). A relative one
      names none.
   4. **`<data root>/state`.**

   `service config` finds the state directory by the same order, as ADR-0019
   clause 15 asks of it.

4. **Beneath a root means beneath it as spelled, through directories only.**
   - A directory is beneath a root when its path starts with the root's path,
     compared component by component as spelled. Nothing is resolved, so another
     spelling of the root is not beneath it.
   - Below the root, no component may be `.` or `..`.
   - Every component below the root that exists must be a directory and not a
     symbolic link or junction. What does not exist yet ends the check.
   - The roots themselves are named by `--root` and `--data-root` or by the
     platform default, and this check does not inspect them. Whether a root may
     itself be a link is a question of its own, which this clause leaves open.
   - This holds for a state directory from any source that lies beneath one of
     the roots: the service's account owns what is under them.
   - A state directory from the file that fails it is refused, naming the
     directory, why, and `--state-dir`. The refusal comes before the install
     writes anything.

5. **A Supervisors' root outside the roots is the operator's.** A
   `supervisor_dir` outside the data root, the layout root and the state
   directory stays as relocatable as ADR-0017 clause 21 makes it. A system-scope
   install on Windows never creates, restricts or hands over such a root. It
   leaves it as it is and names it in a warning. On Linux and macOS an install
   never touches a Supervisors' root.

**Out of scope:**

- The files an enrolment writes as root into the state directory, and whether
  those writes follow a link. That gets a fix of its own.
- The `[tls]` files an enrolment reads as root.
- `[logging] dir`, which only the service's own run uses.

## Alternatives considered

- **Take the file's value only beneath the roots, and `--state-dir` anywhere.**
  It closes the escalation, but a packaged upgrade passes no flag. A relocated
  state directory then either fails `apt upgrade` or is silently moved to
  `<data root>/state`, against clause 2.
- **Trust the file.** That is the escalation this record closes.
- **Have the packages pass `--state-dir`.** The post-install and the MSI do not
  know it. They would have to read it from somewhere an administrator wrote, and
  the registration already is that place.
- **Keep the state directory in a root-owned file of its own.** That is a second
  record of what the registration already says. The two can disagree, and every
  platform needs a place for it.
- **Resolve both paths (`canonicalize`) and compare.** That follows the links
  the account can plant beneath the roots, which is exactly what must not
  decide.
- **Refuse a `supervisor_dir` outside the roots.** That contradicts ADR-0017
  clause 21, and the documented reason for the key is to place it outside. On
  Unix the install never acts on it anyway.
- **Ask the service manager for the loaded unit** (`systemctl show`,
  `launchctl print`). A drop-in or a hand edit would then steer the install.
  ADR-0042 clause 2 rejected the same thing for the account.

## Sources / Prior art

- ADR-0042 clause 2: a re-registration keeps the account the registration names.
  This record applies the same reading to the state directory.
- `systemd.service(5)`, "Command lines": quoting, `%%` and `$$` in `ExecStart=`.
  The Client writes each word in double quotes (ADR-0042 clause 6). The reader
  is held to that writer by tests rather than to the whole grammar.
- `launchd.plist(5)`: `ProgramArguments` is an array of strings.
- Microsoft, "Parsing C command-line arguments" and `CommandLineToArgvW`: how
  the SCM's binary path name splits into arguments. The `service-manager` crate
  quotes it that way. `QueryServiceConfigW` returns it.
- CWE-59 (link following) and CWE-269 (improper privilege management): the
  classes this record closes.

These were consulted from the documentation as recalled, not re-fetched for this
record. The readers are pinned by tests against what the Client itself writes.

## Consequences

- **Positive:**
  - No file the service's account can write moves what an administrator's
    install acts on (Q-1).
  - An upgrade keeps the state directory the registration holds, as clause 2
    requires, including for a relocated one.
  - An operator relocates the state directory once, with `--state-dir`, and
    every later re-registration keeps it.
- **Negative / trade-offs:**
  - A host whose file names a state directory outside the roots while its
    registration names another keeps the registration's. That is silent, apart
    from the printed state directory.
  - A first installation whose file names such a directory is refused until the
    operator names it with `--state-dir`.
  - On Windows a Supervisors' root outside the roots must now be created by the
    operator.
  - A state directory beneath the layout root goes with it when a Linux package
    is removed (ADR-0042 clause 4), the identity included; the data root keeps
    it.
  - A registration is kept wherever it points. One that an earlier install wrote
    from a file the service's account had rewritten stays until an administrator
    names another with `--state-dir`. The install warns of a registered state
    directory outside the roots on every re-registration.
  - The install reads three command-line formats.
- **Follow-ups:**
  - A fix for the enrolment's root writes through links in the state directory.
  - A CHANGELOG entry telling operators with a relocated state directory what to
    do.

## Enforcement

The tests that will cite this ADR with `Verifies: ADR-0053`:

- A re-registration without `--state-dir` keeps the registered state directory
  whatever the file says.
- A file value outside the roots is refused when nothing is registered, and so
  is one reached through `..` or a link.
- `--state-dir` is taken anywhere.
- The systemd, launchd and SCM command lines the Client writes are read back to
  the state directory they carry.
- A Supervisors' root outside the roots is left untouched by the Windows plan.
- `service install` through the real command line refuses before it has created
  anything.
