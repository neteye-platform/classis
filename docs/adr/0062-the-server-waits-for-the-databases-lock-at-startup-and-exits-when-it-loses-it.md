# ADR-0062: The Server waits for the database and its lock at startup and exits when it loses the lock

- **Status:** 🟡 proposed
- **Date:** 2026-11-13
- **Deciders:** Luca Tecchio
- **Applies to:** the connection and the advisory lock of
  `crates/classis-server/src/postgres/mod.rs`, the bucket check of
  `crates/classis-server/src/s3.rs`, their use in
  `crates/classis-server/src/lib.rs`, and every document that tells an operator
  what a Server does when the database or the bucket does not answer, another
  Server holds the database or its own lock is gone
- **Supersedes:** [ADR-0050](0050-the-servers-records-may-live-in-postgresql.md)
  clause 6

## Context

[ADR-0050](0050-the-servers-records-may-live-in-postgresql.md) clause 6 gives
each database schema one Server: a second one fails startup at once, and a
Server whose lock connection ends logs it, refuses every call from then on, and
keeps running.

An orchestrator that restarts the Server breaks both halves. A replacement
Server starts while the old one is still stopping, finds the lock held and
exits; the orchestrator restarts it with a growing back-off of up to five
minutes, so a routine update takes minutes of downtime. The same happens when
the database or the bucket does not answer yet — the name not resolving, the
connection refused while the database fails over: the Server exits, and the
orchestrator's back-off keeps it down for minutes after the database is back.
And a Server that lost its lock stays up refusing every call: its process looks
alive to the orchestrator, which has no reason to replace it, so only an
operator ends the outage.

## Decision

We will make the Server retry at startup, for a bounded time, the connection to
the database, the lock and the check of the bucket, and exit with status 1 when
the connection that holds the lock ends while the Server runs.

- At startup a Server that finds the lock held tries again every five seconds
  for up to 180 seconds, logging each wait naming the database. When the time
  passes it fails startup as clause 6 did, naming the database. The 180 seconds
  cover a failover of the database, which the orchestrator's own back-off would
  otherwise stretch.
- The same wait covers a database that does not answer yet: the name not
  resolving, the connection refused or reset, no answer in time, the database
  starting up, shutting down or out of connections. Each retry is logged at
  `warn` with the reason and the time left, never a credential. A refusal that
  asking again would not change fails startup at once: a rejected password, a
  database that does not exist, a certificate that does not verify, a schema
  that needs a newer Server.
- The bucket check of `[blobs] store = "s3"` follows the same rule: a store that
  does not answer yet — the name not resolving, the connection refused, a
  timeout, a server error — is asked again for the same wait; a bucket that does
  not exist, credentials or a signature the store refuses, and a certificate
  that does not verify fail startup at once. A bucket that does not exist is not
  asked again because a name that is wrong stays wrong, and the orchestrator
  restarts the Server anyway.
- When the lock's connection ends while the Server runs, the Server logs the
  error naming the database and exits with status 1 at once. It does not take
  the lock again in the same process, so it never writes beside a second Server.
- Everything else of ADR-0050 clause 6 stands: the lock is a session-level
  advisory lock named after the schema, Servers in different schemas share
  nothing, and several Servers against one schema are not allowed.

**Out of scope:** several Servers against one schema, and how long an
orchestrator should wait between stopping a Server and starting the next.

## Alternatives considered

- **Keep clause 6 and let the orchestrator's back-off absorb the wait** — a
  restart then costs up to five minutes of downtime.
- **Retry the lock for as long as it takes** — a Server that never gets the lock
  would look started to a process supervisor while serving nothing.
- **Retry every failure, the credentials included** — a wrong password or a
  wrong name would take 180 seconds to be reported, and say nothing new.
- **Take the lock again at runtime, in the same process** — the Server may have
  written beside a second one while the lock was gone; only a fresh start
  reloads its state from the database.

## Sources / Prior art

- PostgreSQL,
  [explicit locking: advisory locks](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS):
  a session-level lock ends with its session.
- Kubernetes,
  [restart policy and back-off](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#restart-policy):
  a container that exits is restarted with an exponential back-off capped at
  five minutes.

## Consequences

- Positive: a replacement Server takes over as soon as the old one has released
  the lock; a Server that lost it is replaced by its orchestrator.
- Negative / trade-offs: a Server that exits on a lost lock drops the sessions
  of its Agents, which reconnect. A second Server started by mistake now waits
  180 seconds before it fails, and a startup probe has to allow that wait.
- Follow-ups: the orchestrator's rollout strategy for the Server.

## Enforcement

Tests that will carry `Verifies: ADR-0062`:

- A Server started while another holds the database's lock gets the lock once
  the first is gone within the wait, and fails naming the database when the wait
  passes without it; the PostgreSQL tests run where a database is named and are
  reported skipped otherwise.
- A database whose port is refused or whose name does not resolve is asked again
  for the wait and then fails naming it; a certificate that does not verify
  fails at once; a rejected password fails at once, where a database is named.
- A store that answers a server error is asked again until it lists the bucket;
  one that answers that the bucket does not exist, or `AccessDenied`, is asked
  once. Both run against a listener on the loopback and need no store.
- The retry loop's bound and interval are decided by a unit test that needs no
  database.

**Not mechanically decidable:** that the process exits when the lock's
connection ends — a test cannot end its own process, so the decision to exit is
tested and the call to `exit` is reviewed.
