# ADR-0054: No privileged install step follows a link the service's account placed, and the Client keeps its state through the same no-follow adapter

- **Status:** 🟢 accepted · clause 1 superseded by
  [ADR-0059](0059-managed-processes-run-under-a-process-account-started-by-a-second-service.md)
- **Date:** 2026-10-23
- **Deciders:** Markus Brigl, Davide Zeni
- **Applies to:** every read, write, rename, removal, mode change and ownership
  change `service install` and `service config` make in the data root, the state
  directory and the layout root in `crates/classis-agent/src/main.rs`,
  `crates/classis-agent/src/service/layout.rs` and
  `crates/classis-agent/src/service/run_as.rs`, the state the Client keeps in
  `crates/classis-agent/src/storage.rs`, `crates/classis-agent/src/csr.rs`,
  `crates/classis-agent/src/connection.rs` and `crates/classis-agent/src/tls.rs`,
  and the adapter `crates/classis-agent/src/nofollow.rs` they go through
- **Supersedes:**
  [ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
  clause 2

## Context

`service install` and `service config` run as root, or as an Administrator on
Windows. The Linux post-install and the MSI run `service install` on every
upgrade
([ADR-0042](0042-the-linux-packages-run-the-client-under-its-own-account.md)
clauses 3 and 5). Both commands work in directories that belong to the service's
account, because ADR-0042 clause 2 hands it the data root and the layout root:

- An enrolment writes the pending key, the request, the staged and issued
  certificate, the instance identity and the connection settings into the state
  directory
  ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)
  clause 15,
  [ADR-0029](0029-a-bootstrap-certificate-as-a-password-protected-pkcs12-file-the-server-keeps.md)
  clause 10).
- The install stages the program and its manifest into `versions/` under the
  layout root
  ([ADR-0053](0053-the-state-directory-comes-from-the-registration-not-the-file.md)
  clause 1).
- `service config` gives the files it wrote to the configuration's owner.

ADR-0042 clause 2 says the hand-over never follows a link. It says nothing about
these other steps. Done with plain path operations, each of them goes where a
link points:

- Writing `client-key.pending.pem` truncates whatever file a symbolic link at
  that name points to, and narrows it to `0600`.
- A link at the request, the identity file or the certificate's temporary name
  is written through.
- A state directory that is a link has the directory behind it narrowed to
  `0700` and filled.
- A link at the staged program or its manifest is written through, and the
  program's `chmod 0755` reaches the file behind it.
- `service config` re-owns a file through a state directory that is a link, and
  re-owns a hard link to any file.

On Windows a junction does the same at a directory, and a symbolic link at a
file where the account may create one. The account there holds Modify, delete
included, on the data root and the layout root themselves, and Users may create
folders in `%ProgramData%`.

The staging and the hand-over recur on every package upgrade. The enrolment
recurs wherever an install finds a bootstrap identity beside its program, or
`service config` runs: the account deletes its own issued certificate, and the
next such run enrols again as root. The account is what a compromised Client or
a Managed Process the Server configures reaches
([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)).

Forces:

- **Security before convenience** (Strategy, Q-1): what the service's account
  can write may not steer what an administrator's command writes.
- **Upgrades run unattended** (ADR-0042, _Context_): the exposure recurs with
  every package upgrade, on hosts nobody watches.
- **Some operators place directories through links**, a state directory on
  another disk among them.
- **The runtime reads the files the install writes.** The service, as the
  account, reads and rewrites the same state directory. One rule for both means
  the service refuses at start what the install refuses, and one code path reads
  each file. Replacing a file whole also means a crash leaves the old file or
  the new one, never half of either.

## Decision

We will reach every file and directory the Client keeps in its data root, state
directory and layout root through one no-follow adapter, so that no privileged
install or `service config` step reads, writes, renames, removes, changes the
mode of, or re-owns anything through a link the service's account could have
placed.

1. **Restates ADR-0042 clause 2. The system service runs under the account its
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
     The Linux packages name their account themselves (ADR-0042 clause 5).

   On Linux and macOS the install prints the account and where it came from:
   `--run-as`, the unit, the plist, the owner of the data root, or the default.
   - **The service runs as the account.** Under systemd this is `User=` in the
     unit the Client writes (ADR-0042 clause 6). Under launchd it is `UserName`,
     through `service-manager`'s `username`. On Windows it is an
     `sc config obj=` step in `windows_config`. No _Log on as a service_ grant
     is performed: the default policy grants it to `NT SERVICE\ALL SERVICES`,
     built-in accounts carry it, and a gMSA receives it from its domain. A host
     hardened against the default grant must restore it.
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
     creates an account; that is the packages' job (ADR-0042 clause 5).
   - **The hand-over covers both roots, on every registration that runs under an
     account.** That includes a kept account and root. After laying out and
     registering, the install hands the account the data root
     (`supervisor.toml`, `state/`), because the service reads and rewrites them.
     It also hands over the layout root (`versions/`, `current`), because the
     self-update that stages into it is the service itself. On Unix this is an
     ownership change. On Windows it is an inheritable Modify ACL grant. Where
     the roots coincide this is one operation. Where they split, an install that
     hands over only one has not succeeded.
   - **The hand-over never follows a link, and neither does any other privileged
     step** (clause 2). The account owns the trees that root walks, and ADR-0042
     clause 5 makes that walk part of every package upgrade. So each directory
     is opened without following a link, and its owner is changed through that
     open handle. Its entries are read from the handle, and a symbolic link is
     re-owned as a link. A regular file with more than one hard link is skipped
     and named in a warning (clause 5). Re-running `install` with another
     `--run-as` re-owns the same directories.

2. **No privileged step goes through a link the account could have placed.**
   This covers every read, write, rename, removal, mode change and ownership
   change `service install` and `service config` make in the data root, the
   state directory and the layout root: the enrolment's files, the staged
   program and its manifest, and what `service config` re-owns.
   - **A directory is held.** The directory a step works in is opened without
     following a link at its own name and held open while the step runs. A
     directory below it is reached one held name at a time: `versions/` and the
     version directory below the layout root.
   - **On Unix** each name is opened, created, renamed and removed relative to
     the held descriptor, with `O_NOFOLLOW`. A file is read only when it is a
     regular file.
   - **On Windows** a directory or file that is a reparse point is refused, and
     a held directory is opened without `FILE_SHARE_DELETE`, so it cannot be
     renamed or replaced while held.
   - **A file is written whole under a new name and renamed over its own.** The
     new name is created exclusively (`O_CREAT | O_EXCL`, `CREATE_NEW`), its
     mode is set through its descriptor on Unix, and it is synced before the
     rename. A link at the name is replaced by the rename, never written
     through. The new name is one no file the Client keeps is stored under.
   - **A program is executable from its creation**, never by a mode change after
     it.
   - **What `service config` re-owns** is re-owned through a handle on the entry
     itself, a link as a link, in a directory opened without following a link.
     The data root the administrator named is reached as clause 4 says.

3. **A state directory that is itself a link is refused, at install and at
   service start.** The refusal names the directory. The same holds for
   `versions/` and a version directory below the layout root, and for any
   directory the Client keeps state in through the adapter of clause 6. The path
   up to the directory a step opens is followed. For a state directory directly
   in a root, the default `<data root>/state`, that path is the root's own,
   which clause 4 settles. For one deeper beneath a root, the components between
   the root and its parent are those ADR-0053 clause 4 checks before the install
   writes anything.

4. **On Windows, a data root or layout root that is a reparse point is refused,
   and the data root is held.** The account holds delete on the roots
   themselves, so their names are not the operator's alone. `service install`
   and `service config` hold the data root without `FILE_SHARE_DELETE` from
   their first write to their last. On Linux and macOS a root's name lies in a
   directory only root writes, and it is followed. This refusal is a check of
   its own beside ADR-0053 clause 4, whose test of what lies beneath a root
   still does not inspect the roots.

5. **A file with a second hard link is skipped and named.** Another name for it
   may stand anywhere, and re-owning it would re-own that file too. The
   hand-over and `service config` each leave such a file as it is and print a
   warning naming it.

6. **The Client keeps its state through the same adapter at run time.** The
   instance identity, the key, request and certificates, the connection
   settings, the installed-package record, the high-water marks, and the stored
   remote configuration with its entry files are read and written as clause 2
   states, whoever runs the Client. The Client's run then refuses what the
   install refuses, and a file the runtime replaces is created new: owned by the
   account that runs it and owner-only where it was owner-only before.

**Out of scope:**

- Which directory is the state directory, and whether `supervisor.toml` may name
  it: ADR-0053.
- The `[tls]` files and the CA an operator names, read where their paths point.
- `[logging] dir`, which only the service's own run uses.

## Alternatives considered

- **Do the writes as the account.** Fork, drop to the account's uid, and write.
  The enrolment runs the whole connection engine, which does not fork cleanly in
  a multi-threaded runtime, and Windows has no equivalent short of a second
  process under the account's token. Rejected as not simpler.
- **Check with `lstat` before each write.** It leaves a window between the check
  and the write, which an account looping on the name wins. Rejected.
- **`openat2` with `RESOLVE_NO_SYMLINKS` or `RESOLVE_BENEATH`.** Linux only,
  since 5.6. macOS and Windows still need their own path. Rejected for one
  mechanism on every platform.
- **Refuse every link on the whole path, from `/` down.** That breaks the links
  platforms ship (`/var` on macOS) and directories an operator placed above the
  roots, for no gain: those components lie in directories only root writes.
  Rejected; clause 3 follows them.
- **Keep the runtime on plain path operations, and go no-follow only during an
  install.** The runtime would then accept a state directory the install
  refuses, and two code paths would read the same files. Rejected for clause 6.
- **Keep following a link at a state directory, for operators who placed one.**
  That is the link the account can plant. Rejected; the operator names the real
  path instead.
- **A crate for capability-style directory access (`cap-std`).** It covers both
  platforms, but adds a dependency for what about twenty `libc` calls and `std`
  already do. Rejected for now.

## Sources / Prior art

- CWE-59, "Improper Link Resolution Before File Access", and CWE-367,
  "Time-of-check Time-of-use Race Condition": the classes this record closes.
- POSIX `openat`, `mkdirat`, `renameat`, `unlinkat`, `fchmod`; `open(2)` on
  `O_NOFOLLOW` and `O_EXCL` (an exclusive create fails on an existing link), and
  `rename(2)` (a link at the new name is replaced, not followed). Recalled from
  the Linux and macOS manual pages, not re-read.
- Linux `fchownat(2)` with `AT_EMPTY_PATH` on an `O_PATH` handle;
  `fs.protected_hardlinks`, which Linux sets and macOS lacks. Recalled.
- Microsoft, `CreateFileW`: `FILE_FLAG_OPEN_REPARSE_POINT`,
  `FILE_FLAG_BACKUP_SEMANTICS`, `CREATE_NEW`, and the share modes. NTFS refuses
  to rename a directory with a handle open below it. Recalled, not re-read; the
  Windows tests are the check.
- `run_as::walk`, the hand-over's descriptor-based walk, which clause 1 keeps
  and clause 2 extends to every other step.

## Consequences

- **Positive:**
  - The service's account can no longer make an install or a package upgrade
    overwrite, truncate, narrow, widen or re-own a file it cannot write itself
    (Q-1).
  - The install and the runtime read the state directory by one rule.
  - Every file the Client keeps is replaced whole, so a crash leaves the old
    file or the new one.
- **Negative / trade-offs:**
  - **A state directory that is itself a symbolic link is refused**, at install
    and at service start. The operator moves the directory to its real path:
    names the target with `--state-dir` (ADR-0053) and removes the link.
  - **A link at a file the Client keeps in the state directory is replaced** by
    a plain file at the next write, and refused when read. Nothing the Client
    writes there is meant to be a link.
  - **On Windows, a data root or layout root that is a junction, a symbolic link
    or a mount point is refused.** The operator names the real directory with
    `--root` or `--data-root`.
  - **`versions/` or a version directory that is a link is refused.** The
    operator removes the link; the install stages afresh.
  - A file with a second hard link keeps its owner, and `service config` names
    it. The operator removes the second link and runs the command again.
  - **A file the runtime rewrites is a new file, owned by whoever writes it.** A
    Client run as root against an installed state directory, by hand and outside
    `service install` and `service config`, leaves root-owned owner-only files
    the service's account cannot read. The operator runs such a command as the
    service's account, or runs `service install` again, whose hand-over gives
    the files back.
  - The CHANGELOG names each of these.
- **Follow-ups:**
  - Whether `icacls /T` crosses a junction inside a tree, for the hand-over and
    the cut on Windows.
  - Holding the layout root on Windows from the first write to the last, as the
    data root is held.
  - Reaching a state directory deeper beneath a root one held name at a time
    from the root, which closes the window between ADR-0053 clause 4's check and
    the open.

## Enforcement

The tests that will cite this ADR with `Verifies: ADR-0054`, in
`crates/classis-agent/tests/install_follows_no_link.rs` unless named otherwise:

- Unix:
  - A link at the pending key or the request is replaced by the request, and the
    file behind it keeps its bytes and its mode.
  - A link at the staged certificate, its temporary names, the issued
    certificate and the issued key is replaced when an issued certificate is
    stored.
  - A link at the identity file and at the connection settings is replaced.
  - A state directory that is a link is refused by recovery, the storage, a
    request and the settings store, and nothing is written behind it. These are
    the calls a service start makes.
  - A `versions/` that is a link is refused by staging. A link at the program or
    its manifest is replaced, and the file behind it is neither written nor made
    executable.
  - `service config` refuses to re-own through a linked state directory, re-owns
    through a data root reached as clause 4 says, and names a file with a second
    hard link.
- Windows:
  - A state directory that is a junction is refused.
  - A `versions/` that is a junction is refused, and so is a layout root that is
    one. The data root is opened by the same call, so this test decides its
    refusal too.
  - A file symbolic link at the connection settings is replaced. The test fails
    when the run cannot create one.
- `crates/classis-agent/src/storage.rs`:
  - No entry is lost to another entry's temporary name.
  - A replaced entry is the runtime's own and owner-only.
- The hand-over's tests of ADR-0042 clause 2
  (`the_handover_never_follows_a_directory_swapped_for_a_link`,
  `the_handover_skips_a_file_with_a_second_hard_link`) carry
  `Verifies: ADR-0054` beside `ADR-0042`.
