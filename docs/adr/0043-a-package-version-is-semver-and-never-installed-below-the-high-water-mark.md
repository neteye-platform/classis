# ADR-0043: A Package version is SemVer, and a Supervisor never installs one below the highest version its Agent type has had on the host

- **Status:** 🟢 accepted
- **Date:** 2026-10-19
- **Deciders:** Markus Brigl
- **Applies to:** the version rule of `crates/fleet-core/src/version.rs` and its
  callers, the Package identity and the store's reading of it in
  `crates/fleet-server/src/packages.rs`,
  `crates/fleet-server/src/fs/packages.rs` and
  `crates/fleet-server/src/migrate.rs`, the package routes of
  `crates/fleet-server/src/api.rs`, the candidate test of
  `crates/fleet-server/src/packages.rs`, the `package sign` and `package fetch`
  commands of `opamp-fleetctl` in `crates/fleet-tools/`, the Supervisor's check
  of a package offer in `crates/fleet-agent/src/supervisor/agent/packages.rs`,
  the installed-package record in `crates/fleet-agent/src/storage.rs`, the file
  `package-high-water.json` under the Client's `state_dir`, the purge in
  `crates/fleet-agent/src/reconfigure.rs`, and every document that tells an
  operator how a Package is numbered or how a Supervisor is moved to an older
  version
- **Supersedes:**
  [ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
  clause 34; [ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clauses 9 and
  14;
  [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
  clause 65;
  [ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
  clause 5

## Context

A package signature covers the Agent type, the version and the artifact's
SHA-256 (`fleet_core::package::statement`,
[ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)).
It binds an artifact to its own version, but it says nothing about how that
version orders against another. A build the operator signed once stays validly
signed forever, including a build with a flaw that became known later. So
whatever stops a downgrade must be a rule about versions, and it must hold
against the Server, because the attack comes from the Server.

Today a Supervisor refuses an offer whose version SemVer orders below its
installed one (ADR-0026 clause 65). Two gaps let a compromised Server get past
that:

- **The floor lives in the Supervisor's directory.** The installed version is
  read from `<supervisor_dir>/<name>/installed-package.json`. The Server manages
  the Supervisor set
  ([ADR-0017](0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)
  clause 27), and a Supervisor removed from the set is purged: its directory is
  deleted, record included (ADR-0017 clause 34). A compromised Server can send a
  set without the Supervisor, then a set that adds it back, under the same name
  or another one. The re-added Supervisor has no record. The Server then offers
  an old, validly signed build of that Agent type, and the Supervisor takes it.
- **A version that does not compare is not refused.** ADR-0026 clause 65 says so
  explicitly. `precedence` in `crates/fleet-core/src/version.rs` returns `None`
  for any value that is not SemVer, and the Supervisor then takes the offer. The
  Server stores any token of letters, digits, `.`, `_`, `+` and `-` as a version
  ([ADR-0033](0033-a-package-entry-carries-its-signature-and-every-artifact-is-uploaded.md)
  clause 5). If an operator ever signed a build under a version such as `1.19`,
  which upstream GLPI Agent releases use, the Server can offer that build over
  any installed version, however new.

The Client's own self-update already has neither gap. It refuses an offered
version that does not parse, and one that orders below the running binary
([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md),
`crates/fleet-agent/src/update/installer.rs`). Its floor is the binary that is
running, and no Server act lowers that binary.

The Server side does not move an Agent backwards either. A rollout reaches an
Agent only when it moves the Agent forward
([ADR-0025](0025-rollout-and-what-reaches-an-agent.md) clauses 9–13). Rollback
is not a rollout, and a deliberate Server-driven downgrade is left undecided
(ADR-0025 clause 18). That rule binds an honest Server. A compromised one
ignores it, so the refusal that counts is the Client's.

ADR-0026 allows exactly one move to an older version, and no offer is involved
in it. When an apply fails within the apply grace, the Supervisor renames the
predecessor back over the live program (ADR-0026 clause 62). The predecessor is
kept for `retain_previous_secs` after a successful apply (ADR-0026 clause 64),
but no offer can reach it: clause 65 already refuses an offer that is older than
the installed version.

The specification puts security before convenience. Quality goal Q-1 asks that
software be installed only when it is signed with a key the operator holds.
[`HARDENING.md`](../HARDENING.md) lists both gaps as accepted behaviour today:
"a version on either side that is not SemVer cannot be ordered and is taken, and
with no record — a program the operator placed, or a Supervisor after a purge —
any version is."

## Decision

We will require every Package version to be SemVer 2.0.0, on the Server, in
`package sign` and on the Client. We will also have each Supervisor refuse any
offer below the highest version this Client has ever installed for that Agent
type, kept under `state_dir` where no purge reaches it.

1. **Restates ADR-0033 clause 5. A Package is identified by
   `(agent_type, version)` and nothing else, and the version is SemVer.** Both
   are tokens of 1–64 characters from letters, digits, `.`, `_`, `+` and `-` —
   no `@`, no path separator. The version is, beyond that, a SemVer 2.0.0
   version (clause 2). A request that would create a Package under any other
   version is answered `400`, with a text that names the version and says a
   Package version is SemVer, for example `1.19.0` for upstream's `1.19`. A
   Package that the store already holds under a version that is a token but not
   SemVer is read as clause 3 says; it is not invalid under ADR-0026 clause 12.
   A Package has no name of its own, no Selector and no kind. Its entries carry
   their signatures (ADR-0033 clause 6). Creating a Package that exists is the
   same request arriving twice.

2. **One predicate decides what is SemVer, in the internal crate.** A version is
   SemVer when `fleet_core::version::parse` accepts it
   ([ADR-0012](0012-versions-resolved-in-the-internal-crate.md) clause 9) and no
   numeric pre-release identifier has a leading zero. The Server,
   `opamp-fleetctl` and the Client all call this predicate, and none of them has
   a second copy. Two versions are ordered by `precedence`, build metadata
   ignored, as before. Two builds of one release compare equal.

3. **A Package with an older, non-SemVer version is kept, and nothing new is
   done with it.** At startup the store reads it as before, and the Server logs
   one warning per such Package, naming it and the SemVer rule. Such a Package
   is never a candidate (clause 5). Every write to it is answered `400` with the
   same text as clause 1: an entry, a signature, and adding it to a Deployment.
   It may be deleted like any other Package once nothing pins it
   ([ADR-0034](0034-a-deployment-carries-configurations-and-is-the-one-thing-rolled-out.md)
   clause 8). An assignment that already pins it stays in force, and its offer
   still goes out (ADR-0025 clause 17). The Client refuses that offer (clause
   7), and the fleet view shows the reason the Agent reports. `server migrate`
   carries such a Package over as it reads it. The operator republishes the
   content under a SemVer version, signs it again, and rolls that out.

4. **`opamp-fleetctl package sign` signs only a SemVer version.** It refuses a
   `--version`, and a signing-file entry
   ([ADR-0027](0027-a-signing-file-carries-what-a-signature-covers-to-the-key-and-the-signatures-back.md)),
   whose version is not SemVer. It does so before it reads the key, and names
   the version. The operator's key therefore never signs a version that a Client
   would refuse.

5. **Restates ADR-0025 clause 9. A package becomes a candidate when its version
   is SemVer, it fits, it is aimed at the Agent, and it moves the Agent
   forward.** A Package whose version is not SemVer (clause 3) is nobody's
   candidate, whatever the Agent reports. Fit is
   [ADR-0026](0026-packages-signed-deployments-offered-downloads-and-verified-delivery.md)
   clause 9's, mandatory, and comes first after that. The version test (ADR-0025
   clauses 10–13) runs _with_ the fit: a package it holds back is nobody's
   candidate and appears in no count and no proposal. A per-Agent refusal of a
   non-SemVer Package names the version and the SemVer rule (ADR-0025 clause
   16).

6. **Restates ADR-0025 clause 14. A package is numbered in the space its program
   numbers itself, written as SemVer.** For a program that self-reports an
   orderable version — the Client and any OpAMP-aware Managed Process — a
   package numbered below it can never reach it. An operator who numbers a
   package by hand takes the program's own number. A number with fewer than
   three numeric components is completed with `.0` (`1.19` becomes `1.19.0`),
   and a leading zero is dropped from a numeric component (`24.04.1` becomes
   `24.4.1`). Both keep the program's own order. A number that cannot be written
   as SemVer this way gets a SemVer version that the operator chooses in the
   same order. `opamp-fleetctl package fetch` names a Package by this rule. It
   still fetches the release under upstream's own tag, and it refuses an
   upstream number it cannot write this way, naming it.

7. **Restates ADR-0026 clause 65. A Supervisor takes its own type, only a SemVer
   version, and never goes back.** Each of the following offers is refused
   before anything is downloaded:
   - an offered package whose name is not the Supervisor's Agent type;
   - one whose version is not SemVer (clause 2);
   - one whose version precedes the installed one by SemVer precedence;
   - one whose version precedes the high-water mark of the Supervisor's Agent
     type (clause 8). An offer equal to either is not refused on that ground.
     Every refusal is reported in `PackageStatuses.error_message`, naming the
     offered version and the version it was compared against. The Client's own
     update keeps its own rules (clause 13).

8. **The high-water mark is the highest version this Client has installed for
   each Agent type.** It lives in `<state_dir>/package-high-water.json`, as a
   JSON object that maps an Agent type to a version. The file is written
   owner-only, through a temporary file and a rename. It is keyed by the Agent
   type, not by Supervisor name. The signature binds an artifact to its Agent
   type, and a Supervisor takes only its own type (clause 7). So the type is the
   one key that a Server cannot change without a signature the operator never
   made. A name can be changed by re-adding the Supervisor under another one.
   Every Supervisor of one type on this Client shares the type's mark. The file
   sits outside `supervisor_dir`, and its name contains a `.`, which no
   Supervisor name can contain
   ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)).
   So no purge can delete it, even where an operator places `supervisor_dir` at
   `state_dir` itself. The mark rises when a Supervisor reports a package
   `Installed`, that is, once its program has survived the apply grace (ADR-0026
   clause 61). It never falls. It does not move on `InstallFailed`, and it does
   not move on the rollback of ADR-0026 clause 62.

9. **The mark is seeded at every start from what is installed.** At startup,
   each Supervisor's installed-package record with a SemVer version raises its
   Agent type's mark to at least that version. So a Client that comes from a
   release without the file starts with a mark that matches what its Supervisors
   already run, before its first connection. The same holds for a file that was
   deleted. If a write of the file fails, the Client logs a warning and keeps
   the raised mark in memory. The next start seeds the mark again from the
   record.

10. **An installed-package record whose version is not SemVer is dropped at
    load.** The Client logs a warning that names the Supervisor and the version,
    and deletes the record. Nothing enters the mark from it. The program in
    `program/` keeps running. The Agent then reports no `agent_has_version` for
    the package, so a rollout of the SemVer republish reaches it as a first
    rollout (ADR-0025 clause 13).

11. **A mark file that cannot be read refuses every Supervisor package.** A file
    that exists but does not parse, or that maps a type to a value that is not
    SemVer, is never read as empty. Startup logs an error naming the file. Every
    package offer to a Supervisor is then refused and reported with a reason
    that names the file, until the operator repairs or deletes it. The Client
    keeps its connection, its configurations and its own self-update.

12. **Only the host lowers the mark.** No Server route, no offer, no delivered
    Supervisor block and no key of `supervisor.toml` reads or writes the file.
    An operator who wants a Supervisor on an older version stops the Client and
    deletes the file, or removes that type's entry from it. The operator also
    deletes `installed-package.json` of every Supervisor of that type, because
    clause 9 seeds the mark again from those records. Then the operator starts
    the Client. Deleting the whole file resets the marks of every type that no
    remaining record names. The recommended path still needs no host access:
    publish the old content as a new, greater version (ADR-0025 clause 18).

13. **The Client's own Agent keeps no mark.** Its floor is the version of the
    running binary, which the self-update already enforces. It refuses an
    offered version that is not a version, and one that orders below the running
    build
    ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).
    The crash-loop pointer move back to the previous version is local, takes no
    offer, and stays as ADR-0018 decides it. The Client's Agent type is not a
    key in `package-high-water.json`.

14. **Restates ADR-0017 clause 34. A removed Supervisor is purged, and its Agent
    type's high-water mark stays.** Removal is keyed by name: only a name absent
    from the new set is removed, while a changed block keeps its directory,
    identity and installed package. The purge runs only after the write
    succeeded, because a failed write restarts the old set from whole
    directories. It deletes `<supervisor_dir>/<name>/` recursively — program,
    staging, configuration, installed-package record and `instance-uid`. A
    Supervisor later re-added, under the same name or another, is a new Agent,
    installed afresh. The purge does not touch
    `<state_dir>/package-high-water.json` (clause 8), so whatever the re-added
    Supervisor installs is held to the mark of its Agent type.

**Out of scope:** a deliberate downgrade driven by the Server, which ADR-0025
clause 18 leaves undecided. Also out of scope:

- a signed floor or revocation list that would refuse an old build numbered
  above the mark;
- raising the mark from a version that a Managed Process reports about itself,
  as opposed to one this Client installed;
- an operator command that lowers a mark;
- reporting the mark to the Server;
- the Gateway refusing to cache a non-SemVer offer. The Client's refusal decides
  that, as the Client's signature check decides the rest (ADR-0033 clause 7).

## Alternatives considered

- **SemVer only, without a mark.** This closes the `1.19` path. It leaves the
  purge path open, because after a purge and a re-add there is no installed
  record to compare against, and any signed SemVer build of the type is taken.
  Rejected.
- **A mark per Supervisor name.** A Server that manages the set chooses the
  name, so it re-adds the Supervisor under a new one, and the new name has no
  mark. Rejected.
- **The mark inside the Supervisor's directory**, which is today's
  `installed-package.json`. The purge deletes it, and that is the attack.
  Rejected.
- **Let the purge keep `installed-package.json`.** This is still keyed by name
  and still bypassed by a re-add under another name. It also leaves a record
  about a program that is gone. Rejected.
- **A minimum version inside the signed statement.** Each new signature would
  name the oldest version a host may hold afterwards. An old build carries its
  old signature, which states the old minimum. The floor would only take effect
  once a host had installed something newer, and it would need its own persisted
  store, which is clause 8 again. It would also change the signing format of
  ADR-0027 and every existing signature. Rejected.
- **A signed floor document that the Client fetches, as in TUF's snapshot and
  timestamp roles.** This also catches an old build numbered above the mark. It
  needs freshness, a second key role and a distribution channel that the Server
  could withhold. It is left open (see _Out of scope_).
- **Server side only: refuse non-SemVer versions and track a floor per host on
  the Server.** A compromised Server is the threat, and it would not enforce its
  own floor. Rejected as the only defence. The Server-side refusal of clause 1
  stays, as feedback to the operator.
- **Refuse a non-SemVer offer on the Client only.** This is safe, but the Server
  would still create Packages that no Client takes, and the operator would learn
  this only from the Agents' refusals. Rejected in favour of refusing on both
  ends.
- **Fail the Server's startup on a stored non-SemVer Package.** This is loud,
  but it leaves the operator with a Server that does not start, and with
  assignments that pin a Package nothing can delete while the Server is down.
  Keeping the Package read and inert (clause 3) is just as safe, because the
  Client refuses it. Rejected.
- **Rename a stored `1.19` to `1.19.0`.** The signature covers the version
  string, so a rename voids every signature on the Package. Rejected.

## Sources / Prior art

- The code as it stands:
  - `crates/fleet-agent/src/supervisor/agent/packages.rs:309-326` refuses a
    lower version only when `precedence` returns `Some(Less)`, and only against
    `installed_package`.
  - That record is read from `installed-package.json` in the Supervisor's own
    directory (`crates/fleet-agent/src/storage.rs:24`, `:256-266`;
    `crates/fleet-agent/src/supervisor/mod.rs:260`).
  - `crates/fleet-core/src/version.rs:152-154` (`precedence`) returns `None`
    when either side does not parse.
  - `crates/fleet-server/src/packages.rs:111-123` (`validate_identity_token`)
    checks a version's characters and length only, and `:148-155`
    (`PackageId::new`) is the one gate every write and every load goes through.
  - `crates/fleet-agent/src/reconfigure.rs:216` (`purge_removed`) deletes the
    whole Supervisor directory.
  - `crates/fleet-agent/src/update/installer.rs:205-225` is the self-update's
    refusal of a value that does not parse and of a lower version.
  - `crates/fleet-agent/src/supervisor/process.rs:993-1006` (`is_semver`)
    already holds the leading zero rule of SemVer item 9 that `parse` does not.
  - `crates/fleet-core/src/package.rs:9-15` is the signed statement.
  - `crates/fleet-agent/src/config.rs:328-345` is the Supervisor name grammar,
    which has no `.`.
- Semantic Versioning 2.0.0:
  - item 2: a normal version is `X.Y.Z` of non-negative integers without leading
    zeros.
  - item 9: a numeric pre-release identifier has no leading zero.
  - item 10: build metadata is ignored in precedence.
  - item 11: precedence compares major, minor and patch, then pre-release, and a
    pre-release ranks below its release. Recalled, not re-read for this record.
- The Update Framework (TUF) specification: a client keeps the version of the
  metadata it last trusted and refuses any lower one, as a defence against
  rollback attacks. Freshness of that defence comes from the timestamp role.
  Recalled, not re-read.
- Android Verified Boot: a rollback index is stored in tamper-evident storage
  outside the image it protects, and an image whose index is lower is refused.
  It is the same split as clause 8: the floor does not live where the attacker
  can reset it. Recalled, not re-read.
- Google Update's `RollbackToTargetVersion`, which ADR-0025 cites: with the
  policy unset, a version higher than the one available is left alone.

## Consequences

- Positive: a compromised Server can no longer move a Supervisor's Agent type
  below the highest version this Client has installed for it. Neither purging
  and re-adding the Supervisor nor a non-SemVer label gets past the refusal. The
  Supervisor path and the self-update path now follow the same version rules.
- Negative / trade-offs:
  - **Residual:** an old build that the operator signed under a version above
    the current mark, such as a pre-release of a later version signed long ago,
    is still taken. Only a signed floor would close that (see _Out of scope_).
    An operator who does not want such a build reachable deletes its Package.
  - **A mistaken high version sticks.** If a host installs a Package numbered by
    mistake, such as `100.0.0`, it refuses everything below that until an
    operator lowers the mark on that host (clause 12). The way back without host
    access is to publish under a version above the mistake.
  - **Two Supervisors of one type share a floor.** On one Client, a new
    Supervisor of a type cannot be started on an older version than another
    Supervisor of that type has had.
  - **The mark outlives a reinstall.** `service uninstall` keeps `state_dir`
    ([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)),
    so reinstalling the Client keeps the mark. Removing `state_dir` removes it,
    together with the Client's identity.
  - **Migration:**
    - A Server with a stored non-SemVer Package starts, warns about each one,
      and offers it only where an assignment already pins it. Those offers are
      refused by an upgraded Client.
    - The operator republishes such content under a SemVer version (`1.19`
      becomes `1.19.0`), signs it again and rolls it out. An Agent whose record
      named the old version reaches that rollout as a first rollout (clause 10).
    - An operator with scripts that create Packages under non-SemVer versions
      gets `400`.
    - The changelog states all three.
  - [`HARDENING.md`](../HARDENING.md) changes its list of what a compromised
    Server cannot do in the same change. [`docs/GLOSSARY.md`](../GLOSSARY.md)
    gains the term _high-water mark_.
- Follow-ups: a signed floor or revocation list for builds that should no longer
  be installed at any version; whether a Managed Process's self-reported version
  should raise the mark; an operator command that lowers a mark on a host.

## Enforcement

Tests that will carry `Verifies: ADR-0043`:

- **fleet-core:** the SemVer predicate takes `1.2.3`, `1.19.0` and
  `1.2.3-rc.1+abc`. It refuses `1.19`, `24.04.1`, `v1.2.3`, `1.0.0-01`,
  `nightly` and a value of 65 characters.
- **Server routes:** `PUT /api/v1/packages/otelcol/1.19` is answered `400` with
  a text naming SemVer, and `PUT /api/v1/packages/otelcol/1.19.0` creates the
  Package.
- **Server store:** a store holding `otelcol@1.19/` opens and warns, naming the
  Package. That Package is no candidate for an Agent that reports nothing. An
  entry write, a signature write and adding it to a Deployment are each answered
  `400`. Its `DELETE` succeeds while nothing pins it. An Agent record whose
  assignment pins it loads, and that Agent is still offered the Package.
- **opamp-fleetctl:** `package sign --version 1.19`, and a signing file with an
  entry at `1.19`, each fail naming the version, without reading the key file.
- **Client, non-SemVer offer:** a Supervisor with no installed record and no
  mark refuses an offer at `1.19`. Nothing is downloaded, and `error_message`
  names the version.
- **Client, purge and re-add:** a Supervisor `a` of type `otelcol` installs
  `0.110.0`. A set without `a` purges it. A set that adds `b` of type `otelcol`
  follows, and so does one that adds `a` again. Each re-added Supervisor refuses
  `0.109.0`, naming the mark, and takes `0.110.0+other` and `0.111.0`.
- **Client, when the mark rises:** a failed apply that rolls back to the
  predecessor leaves the mark where it was, and the predecessor runs. An
  `Installed` raises the mark and writes it owner-only.
- **Client, seeding:** with no mark file and an installed record at `0.110.0`,
  an offer at `0.109.0` is refused after a restart.
- **Client, unreadable mark file:** with a mark file that does not parse, every
  Supervisor offer is refused, naming the file, and the Client still connects.
- **Client, lowering the mark on the host:** with the mark entry and the type's
  installed records deleted while the Client is stopped, an offer at `0.109.0`
  is taken.
- **Client, old record:** an installed record at `1.19` is dropped at load with
  a warning, and the Agent reports no `agent_has_version`.
- **opamp-fleetctl fetch:** `package fetch` turns upstream `1.19` into the
  Package version `1.19.0` and fetches tag `1.19`.

The self-update's existing tests `install_refuses_a_downgrade` and
`the_probe_refuses_an_offer_that_is_not_a_version` in
`crates/fleet-agent/src/update/installer.rs` stay, and also carry
`Verifies: ADR-0043` for clause 13.
