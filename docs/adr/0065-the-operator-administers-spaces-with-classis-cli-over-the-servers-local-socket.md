# ADR-0065: The operator administers spaces with classis-cli over the Server's local socket

- **Status:** 🟡 proposed
- **Date:** 2026-11-16
- **Deciders:** Marco Zanon
- **Applies to:** the crate `crates/classis-admin/` and its binary
  `classis-cli`, the Server's admin socket and its setting, the adapter through
  which the Server answers on it, and the arguments `install.sh`, `install.ps1`
  and the Client's MSI take

## Context

ADR-0064 (proposed, branch `feat/token-auth`) admits a host with its Space's
enrollment key and leaves out the operator's side: creating a Space, showing and
replacing its key, and the ready-to-paste install command of the enrollment LLD
(_Installation_, _Common flow_). Four facts bind this record and the code cannot
show them:

- The Server keeps each Space's enrollment key on its disk, so a key can be
  shown again; the credentials it issues to hosts are kept as hashes only.
  ADR-0064 is being revised to say so.
- No second process may open the Server's records while it runs: with
  PostgreSQL the Server holds an advisory lock that keeps one Server per
  database, and the filesystem stores assume one owner. A replaced key must take
  effect in the running Server at once.
- `/usr/bin/classis` is already the Client's command on a host
  (`packaging/linux/postinst` links it to `supervisor`).
- The Server is reached through a frontend endpoint, such as
  `https://neteye.acme-corp.net/neteye/classis`, that it cannot work out for
  itself. It will be configured; where from is not decided yet.

## Decision

We will give the operator the program `classis-cli`, which asks the running
Server over a Unix domain socket, with one JSON request and one JSON answer per
connection, to create, list and re-key Spaces and to print the install command.

1. **Commands.** `space create <name>` and `space rotate-key <name>` print the
   Space's key; `space list` prints the names of the Spaces, never a key;
   `enroll-command --space <name> --os linux|windows` prints the install
   command, and with `--with-key` prints the key alone on the line before it.
   Results go to stdout and everything else to stderr; a refusal exits
   non-zero.
2. **The socket.** The Server creates it at the path its configuration names,
   with a default `classis-cli` shares and `--socket` overrides. It has mode
   `0600` and is owned by the Server's account. Whoever can open the file is the
   operator; there is no other authentication. It exists on Linux only, as the
   Server does.
3. **The wire.** One JSON object each way, the request bounded in size before it
   is parsed, and the connection closed after the answer. No HTTP.
4. **Ownership.** `classis-admin` is one crate: its `protocol`, `server`,
   `client` and `render` modules and the `classis-cli` binary. It depends on no
   other Classis crate. Its `server` answers through a `Spaces` trait of its
   own. The enrollment side's store may implement it, since that store keeps
   the Spaces and their keys, but `Spaces` is not the storage interface of the
   enrollment key and must not become it: enrollment reads keys through its own.
   A Space name's pattern and the key's generation stay with ADR-0064 clause 1:
   `classis-cli` neither checks a name nor makes a key.
5. **The install contract.** `install.sh`, `install.ps1` and the MSI take the
   endpoint and the enrollment key, never a Space, since the key
   `cle1_<space>_<secret>` names it. The Linux and PowerShell one-liners fetch
   the script from the endpoint, which the Server writes into the script it
   serves, and pass the key as `--token` or `-Token`; the MSI takes `ENDPOINT`
   and `TOKEN`. `--os windows` prints the PowerShell one-liner. What the scripts
   do is outside this decision.
6. **No key in a log.** Neither the Server nor `classis-cli` logs a key; it
   reaches stdout only when a command prints it.

**Out of scope:** where the endpoint setting comes from; deleting a Space and
removing a host; the scripts' contents and the download routes; any remote
operator interface.

## Alternatives considered

- **The operator REST API** — an upstream leftover after the governance reset
  (pull request #4). It would put key management on the network and need a
  credential of its own to guard a job done on the Server's machine.
- **`classis-cli` opening the stores itself** — collides with the PostgreSQL
  lock, and a running Server would not see a key replaced under it.
- **A loopback TCP port** — any local user can connect, so it needs its own
  authentication; a socket file is guarded by its permissions.
- **A group-accessible socket (`0660`)** — not needed: the Server's account and
  root are the operators of the machine.
- **HTTP over the socket** — routing and status codes for four requests, and an
  HTTP client in the CLI. JSON messages say the same.
- **Subcommands of the `server` binary, or of `classisctl`** — the first mixes
  the operator's tool into the daemon's hand-parsed arguments; the second runs
  on the operator's own machine and never talks to a Server.
- **The name `classis`** — taken by the Client's command.
- **`enroll-command` reading the key on stdin** — needed only if the Server kept
  the key as a hash; it keeps the key itself.
- **Printing the `msiexec` line for `--os windows` as well** — Intune and SCCM
  operators build it from the documented properties.

## Sources / Prior art

- Enrollment LLD: "LLD | Classis Enrollment", Confluence space N4, page
  6883115026, version 2 (2026-11-13), sections _Enrollment key_,
  _Installation_ and _Server endpoints_.
- ADR-0064 (proposed, branch `feat/token-auth`), clause 1 (Spaces and the key
  format) and its _Out of scope_.
- The existing code: the advisory lock in
  `crates/classis-server/src/postgres/mod.rs`, the single-owner layout in
  `crates/classis-server/src/fs/mod.rs`, and the `/usr/bin/classis` link in
  `packaging/linux/postinst`.

## Consequences

- Positive: key management has no network surface; a replaced key holds in the
  running Server at once; the crate is tested alone against an in-memory
  `Spaces`.
- Negative / trade-offs: only an operator on the Server's machine, or inside its
  container, can manage Spaces; a remote UI will need another interface.
- Negative / trade-offs: root or the Server's account reads every key, as it
  already could from the disk.
- Negative / trade-offs: the one-liners are a promise to scripts that do not
  exist yet.
- Revisit when a remote operator interface is needed, when the Server runs on
  another operating system, or when the key stops being stored where it can be
  read back.

## Enforcement

Tests that cite this ADR with `Verifies: ADR-0065`, written with the
implementation in `crates/classis-admin/`:

- the command tree of `classis-cli` (clause 1);
- every command answered end to end, client to server, over a socket in a
  temporary directory against an in-memory `Spaces`, and a refusal reaching the
  CLI as a non-zero exit (clauses 1 and 3);
- the socket's mode `0600`, and an oversized request refused before it is
  parsed (clauses 2 and 3);
- the rendered Linux and PowerShell commands, with and without `--with-key`:
  they carry the endpoint and the key and no Space argument (clause 5).

**Not mechanically decidable:** that no key reaches a log (clause 6). A review
of every log call on the paths that carry a key is the check.
