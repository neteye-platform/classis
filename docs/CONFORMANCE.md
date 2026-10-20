# OpAMP Conformance

> What this project implements of the OpAMP protocol, and how far it has got. The
> [specification](SPECIFICATION.md) commits to implementing the protocol **in full and in step with
> upstream** (goals 12 and 13); this document is the evidence for that claim. It is a **living
> document**: a change that adds, removes, or alters protocol behaviour updates the matrix in the
> same change.

## Protocol Baseline

The **Protocol Baseline** is the pinned upstream specification version this project implements
against. It is the single authoritative statement of "which OpAMP" this code speaks.

<!-- protocol-baseline: v0.20.0 -->

| | |
|---|---|
| **Baseline version** | `v0.20.0` |
| **Released upstream** | 2026-08-12 |
| **Upstream specification** | <https://github.com/open-telemetry/opamp-spec> |
| **Upstream status** | Beta — the protocol itself is not yet stable |
| **Last reconciled with upstream** | 2026-10-01 |
| **Interop oracle** | [`opamp-go`](https://github.com/open-telemetry/opamp-go) `v0.25.0` (2026-09-29), which implements `opamp-spec` `v0.20.0`; pinned in [`interop/go.mod`](../interop/go.mod) — see [Interoperability](#interoperability) |

Moving the Baseline to a newer upstream version is a deliberate change — see
[Upgrading the Baseline](#upgrading-the-baseline) for what it obliges.
[`scripts/check-docs.sh`](../scripts/check-docs.sh) compares the pinned version above against the
latest upstream release and warns when they diverge, so falling behind is noticed rather than
discovered later.

Because upstream is itself **Beta**, individual features carry a maturity marker. This document
reproduces those markers rather than inventing its own.

### Known upstream releases since the Baseline

Recorded when the Baseline was last reconciled, so that a future bump is a review of a known list
rather than a rediscovery. Only **released** versions count: the Baseline is always a release, and
what upstream `main` carries before one is not tracked here, since it can still change or be
withdrawn until a release defines it. What is listed is **not** part of the Baseline and is
deliberately not implemented yet; it is what a move past `v0.20.0` would have to take in.

| Upstream release | Effect on this project |
|---|---|
| *(none)* | At the last reconciliation `v0.20.0` was the newest upstream release. |

### What `v0.20.0` brought

The Baseline moved from `v0.19.0` to `v0.20.0` on 2026-08-14; upstream released it on 2026-08-12.

| Upstream change | Taken up as |
|---|---|
| **`AgentConfigFile` renamed to `AgentConfigObject`, empty map key allowed unconditionally** ([#385](https://github.com/open-telemetry/opamp-spec/pull/385)) | Adopted: the vendored schema renames the message and its use in `AgentConfigMap.config_map`, and the generated Rust type follows (`opamp::proto::AgentConfigObject`). A wire-compatible rename — the field numbers and the `config_map` shape are unchanged, so nothing on the wire moved. The empty-key clarification needed no code change: this project already keys the map by the Configuration name and never rejected an empty one. |

### What `v0.19.0` brought

The Baseline moved from `v0.18.0` to `v0.19.0` on 2026-08-04; this is what came with it and where
each item landed, so a reader can check the claim rather than take it.

| Upstream change | Taken up as |
|---|---|
| **Transport message size limits** ([#346](https://github.com/open-telemetry/opamp-spec/pull/346)) | Implemented on both ends and both transports — see [Message size limits](#message-size-limits). |
| **Proto folders restructured** ([#352](https://github.com/open-telemetry/opamp-spec/pull/352)) | Adopted: the vendored schema now lives at `crates/opamp/proto/v0.20.0/opamp/v1/`. Build inputs only — see [Where the schema lives](#where-the-schema-lives). |
| **`ComponentHealth.attributes`** ([#334](https://github.com/open-telemetry/opamp-spec/pull/334)) | Generated from the schema and relayed as part of the health message the Supervisor Endpoint folds upstream; this project sets none of its own. |
| **`agent_disconnect` recommended for plain HTTP** ([#353](https://github.com/open-telemetry/opamp-spec/pull/353)) | Already the behaviour: the Client sends `agent_disconnect` on shutdown over both transports. |
| **`AgentConfigFile.role`** ([#350](https://github.com/open-telemetry/opamp-spec/pull/350)) | Implemented ([ADR-0023](adr/0023-configurations-and-the-rest-api.md)): an optional `role` on the Configuration resource travels verbatim into every entry composed from it. |
| **SDK service namespace identifying attribute** ([#381](https://github.com/open-telemetry/opamp-spec/pull/381)) | Documentation of the OpenTelemetry guidelines; no protocol obligation. |

### Where the schema lives

The `v0.19.0` relocation moved the definitions from `proto/` to `proto/opamp/v1/` while leaving the
protobuf package `opamp.proto.v1` — and therefore the wire format and every generated Rust type
path — untouched. Only the build inputs moved, and adopting it was the one-line change it was
prepared to be, because the path lives in exactly one place:

> **Keep the proto path in exactly one place** — [`crates/opamp/build.rs`](../crates/opamp/build.rs),
> which derives both the file path and the include path from `BASELINE`. Never hard-code a proto
> path anywhere else.

Two details are easy to get wrong when a relocation like this happens again. **Both** files move,
not just `opamp.proto` — relocating one and leaving the other behind fails at import resolution.
And the include root is the directory *above* the package path: the import reads
`opamp/v1/anyvalue.proto` and the file sits at `<root>/opamp/v1/anyvalue.proto`, so the two only
compose when the generator's include root is `<root>`. Pointing it at the directory holding the
files puts them in reach but leaves the import unresolvable.

## Upgrading the Baseline

Moving to a newer upstream version is a deliberate change, not a version-string edit. The procedure:

1. **Read the upstream changelog** between the current Baseline and the target release, and update
   *Known upstream releases since the Baseline* to reflect the new gap.
2. **Re-derive the capability matrix** from the target's `opamp.proto` — bit values, and especially
   maturity markers, since a `[Development]` feature may have become `[Beta]` or changed shape.
3. **Re-check the behaviour table** against the target's `specification.md`. New MUSTs appear between
   releases: transport size limits arrived exactly this way.
4. **Adjust the code** for anything that moved, and record any gap under *Deviations* rather than
   leaving it silent.
5. **Move the `opamp` crate's version** to the target's `MAJOR.MINOR` with patch `0` — its version
   is the Baseline's (ADR-0010). `BASELINE` in `crates/opamp/build.rs` and the version in
   `crates/opamp/Cargo.toml` change together; a test fails the build when they disagree.
6. **Update the marker and the reconciliation date** in [Protocol Baseline](#protocol-baseline) last,
   once the steps above actually hold.

The automated check in [`scripts/check-docs.sh`](../scripts/check-docs.sh) only tells you the Baseline
has fallen behind. It cannot tell you what that costs — that is what step 1 through 4 are for.

## How to read the matrix

- **Maturity** — the upstream marker for the feature, as written in the Baseline: **stable** (no
  marker upstream, but note that the protocol as a whole is still Beta), **Beta**, or
  **Development**. A Development feature may change shape in a future upstream release; implementing
  one is a deliberate acceptance of that risk.
- **Requirement** — whether the protocol mandates the capability. Only two are genuinely
  **required**: `ReportsStatus` on the Agent side (*"This bit MUST be set, since all Agents MUST
  report status"*) and `AcceptsStatus` on the Server side (*"This bit MUST be set, since all Server
  MUST be able to accept status reports"*), both stated in `opamp.proto`. Everything else is
  **optional**: a conforming implementation may omit it, and *"Interoperability of Partial
  Implementations"* obliges each side to **stop using** a capability once it learns the peer lacks
  it — so an undeclared capability must never be assumed, in either direction.
- **Status** — where this project stands: **implemented**, **partial**, **planned**, or **not
  planned** (with a reason, listed under [Deviations](#deviations)).

Status values are deliberately coarse. A capability counts as *implemented* only when the code
declares the bit **and** honours the behaviour behind it end to end. Where the bit is declared but
part of the behaviour behind it is not honoured, the status is *partial* and the note says which
part — a declared capability the peer may rely on is the one place where "mostly" has to be
written down rather than rounded up.

## Agent capabilities

The Client declares these on behalf of each Agent it represents. Bit values are from
`AgentCapabilities` in the Baseline's `opamp.proto`.

| Capability | Bit | Maturity | Requirement | Status | Note |
|---|---|---|---|---|---|
| `ReportsStatus` | `0x0001` | stable | **required** | implemented | MUST be set by every Agent. |
| `AcceptsRemoteConfig` | `0x0002` | stable | optional | implemented | Core of the control loop (goal 1). Declared by every Agent except a Supervisor named in `[supervisors] remote_config_disabled`, whose Agent runs on the files placed on its host and ignores an offer that arrives anyway, as the Baseline's *"Remote configuration capability can be disabled if necessary"* allows ([ADR-0017](adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)), and the Client's own Agent on a host with `[supervisors] server_manages_set = false`, which is offered no Supervisor set and ignores one that arrives anyway ([ADR-0017](adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)). |
| `ReportsEffectiveConfig` | `0x0004` | stable | optional | implemented | Core of the control loop (goal 2). |
| `AcceptsPackages` | `0x0008` | Beta | optional | implemented | Software distribution for Managed Processes (goal 10, ADR-0026). Declared by every Supervisor-backed Agent: its block names its program with a bare file name, which puts it in a directory this Client owns (ADR-0017); the Server chooses which artifact, through the one Deployment that claims the Agent (ADR-0026); the offered artifact is streamed to disk, verified (content hash always, Ed25519 signature when a key is configured), unpacked when it is a `.tar.gz` or a `.7z` — the member named after the Managed Process's binary, since an upstream release ships an archive and nothing repacks it on the way (ADR-0026); the download goes to the Client's own Server origin and nowhere else — an absolute `download_url` on another origin is refused before a byte is fetched, and the redirect chain is followed by hand, up to 5 hops, only while every hop stays on that origin (ADR-0033); the `DownloadableFile.headers` the offer names ride the `GET` to that origin alone, and a header that is not a valid HTTP header fails the download by *key*, never printing its value; an encrypted `.7z` opens with `[packages] archive_key`, which the Server never learns — swapped over that binary by the Supervisor inside `<supervisor_dir>/<name>/program/`, health-gated on `apply_grace_secs`, and rolled back if it will not stay up. A block naming its program by an *absolute* path is refused at startup, since a program the fleet manages is one it delivers (ADR-0017). One that is **more than a single file** — an executable plus the shared objects it loads — is delivered by naming `program_path` in its block (ADR-0026): the whole archive is then unpacked into `<supervisor_dir>/<name>/program/tree/`, the tree it replaced kept beside it and put back whole if the new one will not stay up. Since the archive then names paths, every member is validated before anything is written and one this Client will not write — a `..` or absolute path, a symbolic or hard link, more than 10 000 members, more than 2 GiB unpacked — refuses the whole archive. Only a `TopLevel` package is installed: an `Addon` is what a Supervisor has no way to apply, so it is refused with `InstallFailed` rather than written over the binary it was meant to extend. **The Client updates itself the same way** (goal 11, ADR-0018): it is always its own Agent, and with `[self_update]` in `supervisor.toml` it accepts the one package that section names — anything else is refused, since a package written over the Client takes the host out of reach (ADR-0017 point 25). The artifact is staged as a new version *beside* the running one in the ADR-0019 layout, proved by running `supervisor self-check` on it before the `current` pointer moves, and the process then exits asking the service manager for a restart. A marker in the state directory carries the outcome across that restart: the new version commits itself once it reaches the Server, and a version that will not stay up is rolled back to its predecessor after three attempts. |
| `ReportsPackageStatuses` | `0x0010` | Beta | optional | implemented | `Downloading` while the artifact is on the wire, `Installing` once the Supervisor applies it, then `Installed`/`InstallFailed` (ADR-0026), with the offered `all_packages_hash` echoed once terminal — which is what stops the Server re-offering. The `Downloading` reports repeat every 5 s and carry `PackageDownloadDetails` (percent, bytes per second), so a transfer of hundreds of megabytes stays distinguishable from a stuck install; both that status and the details are `[Development]` upstream. Survives restarts via the persisted installed-package record. Withheld from a Server that has declared capabilities without `AcceptsPackagesStatus` (ADR-0014) — a suppressed status is not queued, it returns with the full snapshot that follows any reconnect or `ReportFullState`. |
| `ReportsOwnTraces` | `0x0020` | Beta | optional | implemented | **Five fleet operations are traces** ([ADR-0016](adr/0016-what-an-agent-reports-about-itself.md)): installing a package, applying a configuration — a Managed Process's, and the Supervisor set — applying offered connection settings, and this Client's own self-update. Each is a root span whose children are its phases and whose status is the outcome the Server is told, so a failed rollout is one trace naming the phase that failed rather than a log hunt. They are the `tracing` spans this Client already writes, converted by `tracing-opentelemetry`; the appender that carries the logs converts events and not spans, which is why the exporter had nothing to export until that layer existed. A self-update stays **one** trace across the restart it needs: the trace rides in the update marker, so the commit or the rollback a later process performs continues what an earlier one began. What is deliberately *not* traced is message handling — a transport exchange, a sampler tick, a Supervisor Endpoint message — which the reference `opampsupervisor` does span; they have no outcome and no end, and at one exchange per Agent per interval they would bury the five operations. Log records written inside an operation carry its `TraceId`, which is what makes a log-to-trace join answerable at the receiving end. Exported OTLP/HTTP with protobuf bodies to the destination the Server names in `ConnectionSettingsOffers.own_*` (ADR-0016) — never to one configured locally, which is what the capability means. Declared unconditionally: it states an ability, and gating it on a destination already in force would mean the Server could never make the first offer. A destination on plain `http://` beyond loopback is **refused and reported**, the Baseline's "MAY refuse" taken; so are its `tls` and `proxy` fields, for the reasons the OpAMP settings row gives. An offered `certificate` **is** honoured (ADR-0016): its `cert` is presented by the OTLP exporter, paired with the key this Client generated for its CSR — the ADR-0021 machinery reused as-is. A `private_key` *in the offer* is refused by name, because this Client's private key never leaves its host and is never accepted from the Server; `ca_cert` is not added to the trust store, which is the Baseline's own advice ("It is not recommended that the Agent accepts this CA as an authority for any purposes"). And "reported" now means reported: a refusal reaches the Server as a `FAILED` `connection_settings_status` naming it, including one found at startup when the persisted settings are put back in force — where saying nothing would have the Client claim on every reconnect that a destination is running which it refused to use. The OTLP Resource carries the Agent's identifying attributes, as the Baseline asks. The exporters are handed an HTTP client bound to this process's Tokio runtime: the SDK exports from a dedicated thread that blocks on the request and has no reactor of its own, so an asynchronous client used there panics rather than exports; that client also bounds the export, which neither the SDK's periodic reader nor `opentelemetry-otlp` does for a client it was handed — without the bound, a destination that stops answering rather than refusing held the exporter thread until the Client restarted. **A destination can also be taken away** ([ADR-0016](adr/0016-what-an-agent-reports-about-itself.md), a recorded [deviation](#deviations)): an offer naming any of the three signals states all three, so one it leaves out is stopped, and an endpoint offered empty withdraws that signal — shut down, dropped from the persisted settings, and acknowledged `APPLIED`, since "stop" is not a refusal to report back. |
| `ReportsOwnMetrics` | `0x0040` | Beta | optional | implemented | Process metrics per Agent, sampled from the outside: the Client's own process for its own Agent, the Managed Process for a Supervisor-backed one, named after the (experimental) process semantic conventions. Sampled **and exported every 10 s**, the Baseline's *"recommended reporting interval"* — one constant drives both, since exporting more often than sampling would ship each value repeatedly and turn a gauge series into a step function. The SDK's periodic reader defaults to 60 s, so the interval is set explicitly rather than inherited; that default is how it silently sat at six times the recommendation. Exported OTLP/HTTP with protobuf bodies to the destination the Server names in `ConnectionSettingsOffers.own_*` (ADR-0016) — never to one configured locally, which is what the capability means. Declared unconditionally: it states an ability, and gating it on a destination already in force would mean the Server could never make the first offer. A destination on plain `http://` beyond loopback is **refused and reported**, the Baseline's "MAY refuse" taken; so are its `tls` and `proxy` fields, for the reasons the OpAMP settings row gives. An offered `certificate` **is** honoured (ADR-0016): its `cert` is presented by the OTLP exporter, paired with the key this Client generated for its CSR — the ADR-0021 machinery reused as-is. A `private_key` *in the offer* is refused by name, because this Client's private key never leaves its host and is never accepted from the Server; `ca_cert` is not added to the trust store, which is the Baseline's own advice ("It is not recommended that the Agent accepts this CA as an authority for any purposes"). And "reported" now means reported: a refusal reaches the Server as a `FAILED` `connection_settings_status` naming it, including one found at startup when the persisted settings are put back in force — where saying nothing would have the Client claim on every reconnect that a destination is running which it refused to use. The OTLP Resource carries the Agent's identifying attributes, as the Baseline asks. The exporters are handed an HTTP client bound to this process's Tokio runtime: the SDK exports from a dedicated thread that blocks on the request and has no reactor of its own, so an asynchronous client used there panics rather than exports; that client also bounds the export, which neither the SDK's periodic reader nor `opentelemetry-otlp` does for a client it was handed — without the bound, a destination that stops answering rather than refusing held the exporter thread until the Client restarted. **A destination can also be taken away** ([ADR-0016](adr/0016-what-an-agent-reports-about-itself.md), a recorded [deviation](#deviations)): an offer naming any of the three signals states all three, so one it leaves out is stopped, and an endpoint offered empty withdraws that signal — shut down, dropped from the persisted settings, and acknowledged `APPLIED`, since "stop" is not a refusal to report back. |
| `ReportsOwnLogs` | `0x0080` | Beta | optional | implemented | The Client's own `tracing` output, bridged to OTLP log records; stderr keeps everything it printed before. Exported OTLP/HTTP with protobuf bodies to the destination the Server names in `ConnectionSettingsOffers.own_*` (ADR-0016) — never to one configured locally, which is what the capability means. Declared unconditionally: it states an ability, and gating it on a destination already in force would mean the Server could never make the first offer. A destination on plain `http://` beyond loopback is **refused and reported**, the Baseline's "MAY refuse" taken; so are its `tls` and `proxy` fields, for the reasons the OpAMP settings row gives. An offered `certificate` **is** honoured (ADR-0016): its `cert` is presented by the OTLP exporter, paired with the key this Client generated for its CSR — the ADR-0021 machinery reused as-is. A `private_key` *in the offer* is refused by name, because this Client's private key never leaves its host and is never accepted from the Server; `ca_cert` is not added to the trust store, which is the Baseline's own advice ("It is not recommended that the Agent accepts this CA as an authority for any purposes"). And "reported" now means reported: a refusal reaches the Server as a `FAILED` `connection_settings_status` naming it, including one found at startup when the persisted settings are put back in force — where saying nothing would have the Client claim on every reconnect that a destination is running which it refused to use. The OTLP Resource carries the Agent's identifying attributes, as the Baseline asks. The exporters are handed an HTTP client bound to this process's Tokio runtime: the SDK exports from a dedicated thread that blocks on the request and has no reactor of its own, so an asynchronous client used there panics rather than exports; that client also bounds the export, which neither the SDK's periodic reader nor `opentelemetry-otlp` does for a client it was handed — without the bound, a destination that stops answering rather than refusing held the exporter thread until the Client restarted. **A destination can also be taken away** ([ADR-0016](adr/0016-what-an-agent-reports-about-itself.md), a recorded [deviation](#deviations)): an offer naming any of the three signals states all three, so one it leaves out is stopped, and an endpoint offered empty withdraws that signal — shut down, dropped from the persisted settings, and acknowledged `APPLIED`, since "stop" is not a refusal to report back. |
| `AcceptsOpAMPConnectionSettings` | `0x0100` | Beta | optional | partial | Server-driven moves of endpoint and heartbeat, and client-certificate renewal (goal 17, ADR-0014, ADR-0021). An offer carrying OpAMP settings is verified by actually connecting (the Baseline's MUST, which it scopes to `ConnectionSettingsOffers.opamp` alone), persisted in the Client's state dir (overriding `supervisor.toml`), then the connection switches — across transports if the offered endpoint demands it. An offer carrying **only** telemetry destinations is a different class and takes a different path (ADR-0014): the Baseline names three classes of destination with deliberately different sequences, so such an offer is applied in place and acknowledged **without** a verification connection and **without** a reconnect — there is nothing to prove by connecting to the OpAMP endpoint, and a receiver that is momentarily down is not an offer that is wrong. Before that it was dropped outright, which left this project's own telemetry-only Server re-offering for ever. What is persisted says only what was offered: no synthetic empty `opamp` block. The two halves fold differently and deliberately (ADR-0016): the `opamp` settings carry only what changes, while the telemetry destinations are stated as a whole by any offer that mentions them. An offered `heartbeat_interval_seconds` becomes the heartbeat (WebSocket) or polling interval (plain HTTP). An offered `certificate` is proved by connecting **with it** before it replaces the one in force, and is then presented on both transports. **Three fields are not honoured**: `tls` and `proxy` (both `[Development]`) and `headers` are dropped, and the Client applies everything else and reports `FAILED` with an `error_message` naming what it dropped — offered headers by their keys, never their values — so a Server learns of the gap instead of being told success. `TLSConnectionSettings` is refused on merit — most of what it can say weakens verification, and `insecure_skip_verify` would let a Server disarm the check that proves it is the Server (ADR-0021). Offered `headers` are refused on merit too (ADR-0014 clause 8): the Agent plane reads no `Authorization` and admits by client certificate alone, so an applied header would be a value the Server plants on every connection of the fleet, persisted and sent upstream with nothing to read it. No header is persisted; an `Authorization` header an earlier version persisted is dropped when the settings are loaded. |
| `AcceptsOtherConnectionSettings` | `0x0200` | Beta | optional | planned | Settings for non-OpAMP destinations. |
| `AcceptsRestartCommand` | `0x0400` | Beta | optional | implemented | Declared by Supervisor-backed Agents only — the self-Agent has no process to restart. Queued via `POST /api/v1/agents/{uid}/restart`, delivered as the Baseline's command-only message on both transports (pushed over WebSocket, on the next poll over plain HTTP). |
| `ReportsHealth` | `0x0800` | stable | optional | implemented | Core of the control loop (goal 2). `ComponentHealth.attributes`, new in `v0.19.0` (`[Development]`), is carried through from what a Managed Process reports; this project adds none of its own. |
| `ReportsRemoteConfig` | `0x1000` | stable | optional | implemented | Reports acceptance or rejection (goals 3 and 4). Declared by every Agent except a Supervisor named in `[supervisors] remote_config_disabled`, which reports no `RemoteConfigStatus` ([ADR-0017](adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)), and the Client's own Agent on a host with `[supervisors] server_manages_set = false`, which reports none either ([ADR-0017](adr/0017-supervisor-mode-kinds-directories-and-what-the-server-may-change.md)). Deliberately **not** gated on the Server's `OffersRemoteConfig` (ADR-0014 clause 16), and the non-gate is a decision rather than an omission: that bit says the Server *can offer* configuration, whereas what licenses an inbound status report is `AcceptsStatus`, which every Server MUST set — there is no `AcceptsRemoteConfigStatus`. Gating it would also be dangerous exactly where it bit, since `last_remote_config_hash` is the sole input to the Server's re-offer decision, and inert where it did not: the status is unset until a configuration has actually been offered. |
| `ReportsHeartbeat` | `0x2000` | Development | optional | implemented | Routine report every `heartbeat_interval_secs` (default 30 s, the Baseline's SHOULD; `0` disables and undeclares the bit) on the WebSocket transport; on plain HTTP every poll is the periodic report. A Server-offered interval (ADR-0014) overrides the configured one on both transports. Declaring this capability is also what lets the Server call the Agent **stale** when it goes quiet for three intervals (ADR-0024) — the capability is the promise that makes silence mean something. |
| `ReportsAvailableComponents` | `0x4000` | Development | optional | implemented | Relayed from the Managed Process's `opampextension` through the Supervisor Endpoint; declared only once components are known. The hash rides full reports, the full map goes out on the Server's `ReportAvailableComponents` flag — which the Server sets while it only holds a hash. |
| `ReportsConnectionSettingsStatus` | `0x8000` | Development | optional | implemented | `APPLYING` on receipt, `APPLIED`/`FAILED` after applying, the hash echoed either way (ADR-0014) — which is what stops the Server re-offering. **One acknowledgement per offer**, whose `error_message` names everything dropped across both halves of it (ADR-0014 clause 7): the Baseline hashes all settings together, so the Agent answers the message, never one part of it. Survives restarts via the persisted settings. Gated on the Server's `OffersConnectionSettings` — *unless* that Server has actually sent an offer, which arms the report whatever its bitmask says (ADR-0014 clause 13); without that exception a Server offering without declaring could never stop offering. |

## Server capabilities

Bit values are from `ServerCapabilities` in the Baseline's `opamp.proto`.

| Capability | Bit | Maturity | Requirement | Status | Note |
|---|---|---|---|---|---|
| `AcceptsStatus` | `0x0001` | stable | **required** | implemented | MUST be set by every Server. |
| `OffersRemoteConfig` | `0x0002` | stable | optional | implemented | Core of the control loop (goal 1). `AgentConfigObject.role` (the field debuted in `v0.19.0` on `AgentConfigFile`, renamed with the message in `v0.20.0`) carries the optional `role` of the Configuration it was composed from (ADR-0023) — empty, and so unset on the wire, unless an operator set one. It is part of the hash that gates every push, so a role change reaches the fleet like any other edit; an empty role is hashed as nothing, which keeps every hash predating the decision exactly where it was. The Client writes a roled entry to the config directory like any other but leaves it out of what the Managed Process is configured with — the Collector plugin passes one `--config` per *unroled* entry, so `supplementary` content is there to be read by path and never handed over as configuration. |
| `AcceptsEffectiveConfig` | `0x0004` | stable | optional | implemented | Core of the control loop (goal 2). |
| `OffersPackages` | `0x0008` | Beta | optional | implemented | Declared only while a non-empty package store is armed (ADR-0026). The store holds **Packages** (ADR-0026): each identified by *(Agent type, version)* and nothing else — no name of its own, no Selector, no kind flag — holding one entry per platform, an uploaded artifact with the operator's Ed25519 signature (ADR-0026, ADR-0033), persisted and managed through the REST API, uploaded under `max_package_size_bytes` and kept by SHA-256 in the data directory and streamed from it (ADR-0037), so neither the store nor a download holds a program in memory. Beside them live **Deployments** (ADR-0026, ADR-0034): a name, the channel a Selector aims at, at most one Package per Agent type, and any number of Configurations. A Deployment is the only thing rolled out. The offer is composed **per Agent** from what an explicit rollout act assigned to it (ADR-0025) — never from matching, which only computes what such an act *would* release — as the Baseline's "available on the Server for this Agent" describes, and its `all_packages_hash` is computed over that same assignment. **An Agent belongs to at most one Deployment**: where two claim it, that is a conflict, it is proposed nothing, and the fleet view names both — there is no specificity ranking and no version tie-break left to decide between them (ADR-0026). Fit runs first and is two mandatory steps: a Package built for another **Agent type** is dropped — the type in its identity is matched against the `service.name` the Agent reports (ADR-0016, ADR-0026), and an Agent reporting none fits nothing — and then every Package without an entry for the Agent's **platform** (ADR-0026). What survives must also be an **upgrade** over what the Agent reports running (ADR-0025). Every entry's `download_url` points at the Agent plane's listener — the one the Client is already connected to, which is why the path resolves against its own endpoint (ADR-0013); every artifact is uploaded, so the Baseline's Download Server is always the OpAMP Server itself (ADR-0033). The `signature` an offer carries is the **entry's own** for those exact bytes on that platform, the same through every Deployment that holds the Package; an entry without one is offered to nobody (ADR-0033). Only `TopLevel` is ever offered: an Agent has one binary to replace and its Deployment holds one Package for its type, so the Baseline's "normally only one top-level package" is structural here rather than a flag anyone can set (ADR-0026). Taking a version back is **not** a rollout: the fleet only moves forward, and what reverses a bad release is the host's own health-gated rollback (ADR-0026). |
| `AcceptsPackagesStatus` | `0x0010` | Beta | optional | implemented | The Server records each Agent's reported `PackageStatuses` and gates re-offering on the `server_provided_all_packages_hash` (ADR-0026). |
| `OffersConnectionSettings` | `0x0020` | Beta | optional | partial | Declared while `server.toml` carries **anything this Server can offer** — a `[connection_offer]`, a `[telemetry_offer]`, or a `[client_ca]` whose issued certificate travels as an ordinary offer (ADR-0014 clause 3). Keying it on the first alone left the other two exercising an undeclared capability. From `[connection_offer]` come heartbeat interval and/or endpoint, compiled into one hash-gated `OpAMPConnectionSettings` offered to Agents declaring `AcceptsOpAMPConnectionSettings` whose reported hash differs (ADR-0014). The offer carries no `headers` and no credential: a credential key in `[connection_offer]` fails startup, naming the key, because the Agent plane admits by client certificate alone (ADR-0014 clause 1). A `certificate` **is** offered, but only as the answer to a CSR (see the row below), never as a standing setting. `tls` and `proxy` are never offered: there is no configuration surface to put them in, which is the Server half of the gap the Agent row names; `headers` are never offered either. The same message carries the own-telemetry destinations of `[telemetry_offer]` (ADR-0016), offered per signal and only to Agents declaring that signal; the hash covers the whole offer, so an Agent acknowledges the message rather than any one part of it. |
| `AcceptsConnectionSettingsRequest` | `0x0040` | Development | optional | implemented | The Agent-initiated CSR flow (ADR-0021). Declared only while `server.toml` carries a `[client_ca]` — the certificate and key the Server signs with, and `validity_days` (default 30). An Agent sends `ConnectionSettingsRequest.opamp.certificate_request.csr`; the Server signs it as a local CA and returns the issued certificate in an ordinary `ConnectionSettingsOffers` under its own hash, so one message can hand over the certificate and whatever standing offer goes with it. The Agent's private key never leaves its host — the Server puts nothing in `private_key`. Admission is the approval: a CSR that arrives has already satisfied every proof the endpoint requires, which is what the Baseline's flow means by awaiting one. A request that does not parse, or one arriving at a Server with no `[client_ca]`, is answered with a `ServerErrorResponse` of type `BadRequest` — the Baseline's MUST. A CSR that *carries* an `instance_uid` other than the sender's is answered `BadRequest` — the Baseline's MUST for that case (ADR-0021). Every certificate it signs gets a random serial and enters a register, so a revocation reaches its renewals (ADR-0021). |

## Protocol behaviour beyond capabilities

Not everything the protocol requires is expressed as a capability bit. These items are tracked
separately because conformance depends on them just as much.

| Area | Requirement | Status | Note |
|---|---|---|---|
| WebSocket transport | Servers SHOULD accept it; Clients MAY choose either | implemented | Varint header followed by the Protobuf message (`opamp::frame`); both ends (ADR-0013). The Client uses it by default; the Server pushes config changes over it, and on shutdown closes every session with the code `1001` (going away) before it saves the fleet. |
| Plain HTTP transport | Servers SHOULD accept it; Clients MAY choose either | implemented | *"Server implementations SHOULD accept both plain HTTP connections and WebSocket connections. OpAMP Client implementations may choose to support either."* Both ends (ADR-0013). The Client polls, by default every 30 s, with an immediate follow-up after a config outcome. |
| Default endpoint | Port 4320, path `/v1/opamp` | implemented | Both defaults in place; address/endpoint configurable on both ends (ADR-0010). |
| Message size limits | Both ends MUST enforce a receive limit and MUST NOT send past it; `413` on HTTP, close `1009` on WebSocket | implemented | New in `v0.19.0` — see [Message size limits](#message-size-limits). Default 64 MiB, the upstream recommendation; `max_message_size_bytes` in `server.toml` and `supervisor.toml` tightens it (ADR-0010). |
| gzip on HTTP | The Server MUST honour `Content-Encoding` | implemented | The Server accepts gzip and identity request bodies; a body that inflates past the message size limit is refused with `413`, so compression buys no memory. Response compression (a SHOULD) is not done yet. |
| `Content-Type` header | The Client MUST set `application/x-protobuf` on plain HTTP | implemented | The Client sets it; the Server requires it on POST (`415` otherwise) and takes a WebSocket upgrade as the other transport. |
| `instance_uid` | MUST be 16 bytes, SHOULD be UUID v7 | implemented | Generated as UUID v7, persisted across restarts (`opamp::uid`); the Server rejects other lengths with `bad_request`. |
| `sequence_num` | Incremented per `AgentToServer` | implemented | The Server detects gaps and requests full state. |
| Unchanged fields omitted | SHOULD be unset when unchanged | implemented | Routine Client polls carry identity and sequence number only; status fields are sent when they change, everything after (re)connect or on demand. |
| `ReportFullState` | The Agent MUST report full state when requested | implemented | The Client complies immediately; the Server sets the flag on sequence gaps and unknown Agents. |
| `agent_disconnect` | MUST be set in the final message; SHOULD be sent on plain HTTP too | implemented | The Client sends it on shutdown on both transports — which `v0.19.0` newly asks of the plain-HTTP transport, so the Server marks the Agent disconnected at once instead of after missed polls; the Server also marks it on abrupt WebSocket loss. |
| `AgentIdentification` | The Agent MUST adopt a new `instance_uid` | implemented | The Client adopts and persists the new identity. |
| `RequestInstanceUid` | Server-generated identity on request | implemented | The Server mints a UUID v7 and re-keys the Agent. The Client does not use the flag (it self-generates), which the protocol permits. |
| Connection multiplexing | Distinguish Agents by `instance_uid` | implemented | Both ends. The Server keys all state on `instance_uid` and serves n Agents over one WebSocket connection (tested). The Client carries one Agent per Supervisor over one shared connection, routed by `instance_uid` alone (ADR-0015, ADR-0017), and in **Gateway Mode** (ADR-0015) it folds many downstream Clients onto a pool of upstream connections — grown lazily to a configured cap, each Agent stuck to its connection by `instance_uid`, messages forwarded unchanged. Tested end to end: two downstream peers on two transports arrive at the Server as two Agents over one upstream connection. |
| Duplicate `instance_uid` | Detection and handling | implemented | The Server rekeys an identity that reports over a second live WebSocket connection: a fresh UUID v7 via `AgentIdentification`, which the Client adopts (the Baseline's SHOULD). Stateless plain-HTTP polling offers nothing to tell two pollers apart, so detection is WebSocket-only. |
| Duplicate WebSocket connections | Handling defined by the spec | implemented | The Client holds one connection by construction and sends `agent_disconnect` before a graceful reconnect. The Server tracks per-connection ownership: only the owning connection marks its Agents disconnected, so a stale socket never takes down an Agent another connection carries. |
| Undefined capability bits | MUST be zero | implemented | Both ends declare only defined bits (`opamp` generated enums). |
| Authentication | HTTP auth methods MAY be used; `401` MUST be returned on failure | implemented | `[Beta]`. The Agent plane authenticates at the transport, by the client certificate the TLS handshake requires (ADR-0021), and uses no HTTP authentication method: `/v1/opamp` and the download route read no `Authorization` header — one a Client of an earlier version sends is ignored, never refused — and a refusal behind the handshake, a revoked certificate, is answered `401` without a `WWW-Authenticate` challenge. The Client sends no `Authorization` on either transport. A `server.toml` holding `[auth]` is refused at startup. The REST API and the UI are a separate plane with their own Basic credentials (`[rest.auth]`, ADR-0021), required off the loopback, which the Baseline says nothing about. Underpins goal 17. |
| Transport security | TLS on both transports | implemented | rustls on both ends (ADR-0013); `wss://` and `https://`, with an optional CA file on the Client that replaces the built-in roots for a private CA. Server-authenticated only — see the next row. |
| Mutual TLS | Client certificates as peer proof | implemented | Both ends (ADR-0021). The Agent plane requires a client certificate in the TLS handshake, verified against `[tls] client_ca_file` (and the bootstrap CA of `[enrolment]`), and the certificate is the whole of admission: a connection is a member's when its certificate was issued directly by the client CA, is valid and is not revoked (ADR-0021). The package download sits behind the same handshake. The Client presents its certificate on both transports, from `supervisor.toml`'s `[tls] cert_file`/`key_file` or, outranking it, the pair the Server issued into the state directory. A certificate proves fleet membership, never which Agent is speaking: the subject is not matched against `instance_uid`, which the Server may re-key at any time through `AgentIdentification`. |
| Capability negotiation | Each side MUST stop using capabilities the peer lacks | implemented | Governed on the Client side by one stated rule (ADR-0014) rather than case by case: **optimistic until the Server has declared anything, binding once it has** — which is the Baseline's own timing, and what makes the first report legal — with `capabilities: 0` read as silence rather than a retraction. A **received message outranks the bitmask** for the report answering it, so a Server that offers without declaring still gets its acknowledgement instead of re-offering for ever. Reporting is gated where the Server's bit governs the report (`package_statuses`, `connection_settings_status`, effective config); *sending* is gated pessimistically only where the message would be refused outright (a CSR to a Server without `AcceptsConnectionSettingsRequest`). `remote_config_status` is deliberately never gated — see its row. The Server, for its part, offers configuration only to Agents declaring `AcceptsRemoteConfig`, telemetry only per declared signal, and a restart only to `AcceptsRestartCommand`. |
| Retrying, throttling, bad request | Defined error and backoff behaviour | implemented | The Server answers malformed input with `BAD_REQUEST` error responses, which the Client does not retry. Throttling is honoured on **both** levels the Baseline defines it at: the protocol's own `UNAVAILABLE` with `retry_info` (either transport), and — on plain HTTP — a `503` or `429`, whose `Retry-After` is waited out; without the header the wait is the Baseline's *"minimum recommended retry interval"* of 30 s. `Retry-After` is read in its delta-seconds form only; an HTTP-date value falls back to that same 30 s rather than pulling in a date parser for it. A `413` is treated as the Baseline's *"MUST NOT retry the same request"*: the report is dropped rather than counted as a lost exchange, since a lost exchange arms a full snapshot and would make the retry **larger** than the report just refused. Reconnects use capped exponential backoff **with jitter** — equal jitter over `[ceiling/2, ceiling)`, so a fleet coming back after a Server restart does not arrive on the same instants. The Server emits throttling itself ([ADR-0013](adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md)): a message from an admitted host past `[agent_rate_limit]` is answered `UNAVAILABLE` with `retry_info` of 30 s on both transports, on plain HTTP in the body of a `200`, and carries the message's `instance_uid`; the connection stays open, as the Baseline leaves the disconnect to the Client. `UNAVAILABLE` there answers one host or Gateway over its rate rather than an overloaded Server; it is the protocol's one retryable answer. |
| `OpAMP-Instance-UID` header | The Client SHOULD set it on plain HTTP | implemented | Sent on every POST, carrying the `instance_uid` of the message in canonical UUID form — so an intermediary or a log can route by Agent without decoding the protobuf body. |
| Interim status reporting | The Client MAY report progress while it downloads and installs | implemented | While an artifact downloads the Client reports `Downloading` with `PackageDownloadDetails` every 5 s, and reports the terminal status once done — the Baseline's "status reports allow the Server to stay informed" for processing that takes a long time. |
| Custom messages | `CustomCapabilities` / `CustomMessage` exchange | planned | `[Development]`. Outside the capability bitmask: each side lists supported custom capabilities as reverse-FQDN strings; a `CustomMessage` for an unsupported capability can be ignored. |

### Message size limits

`v0.19.0` added four rules per transport, and they are not symmetric — two are MUSTs on receiving,
and on sending the Server carries a MUST where the Client carries a SHOULD. What each end does:

| Direction | Requirement | This project |
|---|---|---|
| Server receives, plain HTTP | MUST enforce, including after decompression; answer `413`, and the Client MUST NOT retry | Request bodies are capped before a handler sees them; a gzip body that inflates past the limit is refused the same way, both with `413`. |
| Server receives, WebSocket | MUST enforce after any extension decompression; SHOULD close with `1009` | The socket refuses to buffer past the limit, and the connection is closed with `1009 Message Too Big`. |
| Server sends | MUST NOT send an oversized message; SHOULD record it | A reply or push past the limit is dropped with a log line — never truncated, never shipped. On plain HTTP the exchange fails with `500` rather than carrying a body the Client would have to refuse. |
| Client receives | MUST enforce, including after decompression; discard and record | The WebSocket connection is capped and closed with `1009`; an HTTP response body is read incrementally and abandoned the moment it grows past the limit, so it is never buffered whole. |
| Client sends | SHOULD limit; if exceeded MUST NOT send, SHOULD record | A report past the limit is dropped with a log line; on plain HTTP the request is never made. |

The limit defaults to **64 MiB**, the value upstream recommends, and is configurable on both ends
through `max_message_size_bytes` (ADR-0013). Zero is rejected at startup: the Baseline knows no
"unlimited", so a limit that could carry nothing is a configuration error, not a way to switch the
rule off. The Supervisor Endpoint enforces the same limit as the Server it stands in for.

### Mutual TLS and the two fields still refused

Goal 17 asks for three things: TLS on both ends, mutual TLS, and a Server that accepts only
authenticated Agent identities. **All three hold** — rustls on both transports (ADR-0013), and
client certificates the Server itself issues and requires in every handshake (ADR-0021). What is
left is smaller and deliberate, and this is where it is written down, because none of it is a
capability bit.

- **Three offer fields are not honoured.** `TLSConnectionSettings` and `ProxyConnectionSettings`,
  both `[Development]`, and the OpAMP settings' `headers` are dropped from an offer. The refusal is
  a decision rather than a gap: `insecure_skip_verify`, `ca_pem_contents`, and the rest are largely
  ways to weaken verification, and a Server able to command them could switch off the check that
  proves it is the Server — trust here is an operator's file, not a Server's instruction. There is
  nothing on the Client for `proxy` to configure. Offered `headers` are refused on merit (ADR-0014
  clause 8): the Agent plane reads no `Authorization`, so a header the Server plants would be
  persisted, sent on every connection with nothing to read it, and carried to whatever endpoint a
  later offer names. The Client applies every field it does honour and then reports `FAILED` with an
  `error_message` naming what it dropped — headers by their keys, never their values — so a Server
  offering any of them learns that it did not take. The hash is echoed either way, so this does not
  put the Server into a re-offer loop.
- **A certificate proves membership, not identity.** The Server does not require a peer
  certificate's subject to match the Agent's `instance_uid` or anything else it reports. Binding
  them would mean a certificate dies whenever the Server re-keys an Agent through
  `AgentIdentification` — an outage of the Server's own making. Authorization and multi-tenancy
  remain the specification's non-goal, with one bound: a host receives from the Server only the
  configurations and packages released to an Agent it speaks for. The download route serves an
  uploaded artifact only to such a host and answers every other request `404`, as for an artifact
  it does not hold (ADR-0026). A Gateway passes an uploaded artifact on from its package cache
  only to a downstream host whose Agent it relayed the offer to.
- **Mutual TLS is hop-by-hop.** Where a Gateway stands between an Agent and the Server there are
  two mutual-TLS connections, and the certificate the Server verifies is the Gateway's. The
  Gateway's own handshake against the fleet's client CA, with the Server's revocation list, admits
  the downstream peer, and it forwards no `Authorization` (ADR-0015).
- **Revocation is Server state, as the Baseline's *Revoking Access* describes.** The Server keeps
  a list of revoked certificates, by issuing CA and serial and extended along every renewal it signed; it
  refuses them at admission and closes every WebSocket session they admitted with `1008`
  (ADR-0021). There is no credential to revoke. There is no CRL and no OCSP. Behind a Gateway the
  Server sees the Gateway's certificate, so it hands its Gateways the revoked certificates on a
  route of their own and the Gateway refuses them (ADR-0015) — no message of the protocol is
  involved.

- **A CSR that names an `instance_uid` is checked against its sender.** The Baseline: *"When the
  Server receives a CSR containing the instance_uid in CSR fields the Server MUST verify that the
  instance_uid field in AgentToServer message matches the instance_uid in the CSR fields"*. Every
  canonical UUID text in a CSR's subject or requested SANs is read as such a claim, and a CSR with a
  claim other than the sender's `instance_uid` is answered `BadRequest` before it is signed or
  queued (ADR-0021). This is a different question from the bullet above: the *issued* certificate
  is still not bound to an `instance_uid`. This project's own Client claims nothing, so its
  requests are signed as before.

## Interoperability

Both ends are checked against `opamp-go`, the reference implementation, in a scheduled job
([ADR-0011](adr/0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md),
[`interop.yml`](../.github/workflows/interop.yml)): `opamp-go`'s Client against our Server, and our
Client against `opamp-go`'s Server, on the WebSocket and the plain HTTP transport. The scenarios are
[`crates/fleet-agent/tests/interop_opamp_go.rs`](../crates/fleet-agent/tests/interop_opamp_go.rs);
how a red run is triaged is in [`interop/README.md`](../interop/README.md).

The oracle implements the Baseline's own `opamp-spec` version, so no row of this document lies
beyond its reach. What the job reaches is narrower than the matrix:

| Row | Reached by the oracle | Note |
|---|---|---|
| WebSocket transport, Plain HTTP transport | both directions | Every scenario runs on both. |
| `sequence_num` | both directions | The test checks the numbers our Client sends for gaps; our Server asks for no full state while nothing was lost, and notices the gap when the Agent returns to it after reporting elsewhere. |
| `ReportFullState` | both directions | Our Server asks for it from an Agent it has never seen and after a gap, and learns a description that changed in between; `opamp-go`'s Server asks our Client for it. |
| `AcceptsRemoteConfig`, `ReportsRemoteConfig`, `OffersRemoteConfig` | both directions | Offer, `APPLIED` with the offered hash, and no repeated offer once applied. |
| Capability negotiation | both directions, partly | Each side records what the other declared, and our Client stops reporting its effective configuration once `opamp-go`'s Server stops declaring `AcceptsEffectiveConfig`. `opamp-go`'s Client exposes no Server capabilities, so ours are read off the wire on plain HTTP only. |
| `AgentIdentification`, `RequestInstanceUid` | both directions | Our Server mints the identity `opamp-go`'s Client requests; our Client adopts and persists one `opamp-go`'s Server assigns. |
| `agent_disconnect` | our Client only | Our Client says goodbye on a graceful stop on both transports. Our Server's side is not decided: `opamp-go`'s plain-HTTP Client sends no `agent_disconnect`, and over WebSocket the goodbye and the closing socket mark the Agent disconnected alike. |
| Transport security, Mutual TLS | both directions | Connect, report and a configuration round trip also run over `wss://` and `https://` on TLS 1.3 alone, against our Server's TLS and admission as the binary sets them up, and with our Client presenting its certificate to an `opamp-go` Server that requires one. A certificate another CA issued is refused by both, and our Server refuses a peer that offers none. The certificates come from a PKI the test generates. |
| Authentication | partly | Only the refusal in the handshake is reached; the `401` for a revoked certificate is not, since the test Server keeps no revocation list. |
| Packages, connection settings, own telemetry, Gateway Mode | no | Not in the scenario list of ADR-0011. |

## Deviations

Deliberate departures from the Baseline, each with a reason. A deviation is a recorded decision, not
a gap left unexplained — the specification's non-goal *"Forking or extending the protocol"* forbids
resolving one by inventing semantics of this project's own.

| Deviation | Reason |
|---|---|
| **An own-telemetry offer states all three destinations, and an empty `destination_endpoint` withdraws one** ([ADR-0016](adr/0016-what-an-agent-reports-about-itself.md)) | Departs from two sentences of the schema. `ConnectionSettingsOffers.own_metrics` (and `own_traces`, `own_logs`) says *"If this field is not set then the Agent should assume that the settings are unchanged"*; here that holds for an offer **silent about telemetry**, while an offer that names any of the three states all three, so a signal it leaves out is stopped. And `TelemetryConnectionSettings.destination_endpoint` says *"The value MUST be a full URL an OTLP/HTTP/Protobuf receiver with path"*; an empty value is sent and honoured as an explicit withdrawal. **Why:** taken literally, the delta reading leaves own telemetry impossible to switch off from the fleet — nothing in the Baseline defines a withdrawal for these fields, the way `certificate` defines one for itself — and it disagrees with the only implementation that has these fields: `opampsupervisor` builds its own-telemetry section from the received message alone (`updateOwnTelemetryData` drops a `nil` or empty endpoint; `setupOwnTelemetry` logs *"Disabling own telemetry pipeline in the config"* when nothing is left), with no fold against what it stored. Following the schema here would mean a Server of ours silently disabling a supervisor's other signals, and a supervisor-shaped Server unable to disable ours. The two cannot both be right, and settling that is upstream's to do: this project takes no position in `opamp-spec` and records the departure here instead. |
| *(nothing else)* | One SHOULD is consciously not taken up yet and noted in the matrix: response compression on plain HTTP. |

## Status summary

The base control loop is implemented on both ends and on both transports
([ADR-0011](adr/0011-the-protocol-is-pinned-and-checked-against-opamp-go-on-the-endpoint-as-it-ships.md),
[ADR-0013](adr/0013-tls-1-3-plaintext-on-the-loopback-alone-and-bounded-planes-bodies-and-messages.md),
[ADR-0010](adr/0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)): status reporting, remote configuration gated by the config hash, effective-configuration
and health reporting, identity handling (UUID v7, reassignment, server-generated identity), state
recovery via `ReportFullState`, disconnect handling, and TLS. Supervisor Mode (ADR-0017) puts real
processes behind that loop: each configured Supervisor is its own Agent multiplexed over the
Client's one connection, a received configuration restarts the Managed Process on the written
files and is acknowledged `APPLYING` → `APPLIED` only once the process survived the apply grace
(`apply_grace_secs`, default 3 s) — exiting within it reports `FAILED` — and every Supervisor serves
a loopback WebSocket Supervisor Endpoint that folds a Collector `opampextension`'s description,
health, and effective configuration into its Agent. Configuration targeting (ADR-0034) composes
each Agent's Remote configuration from the named Configurations its Deployment released to it —
the Deployment's Selector aims, a Configuration's Agent type fits — delivered as named
`AgentConfigMap` entries, hash-gated per Agent, with the whole model exposed through the
OpenAPI-described REST API v1. On top of that loop sit the
server-initiated restart command, periodic heartbeats on both transports, available-components
relaying from the Managed Process, and duplicate-`instance_uid` handling with per-connection
disconnect scoping. The Server moves the fleet's heartbeat interval and
endpoint through hash-gated connection-settings offers the Client verifies by actually
connecting, persists, and acknowledges (ADR-0014). Software distribution to Managed
Processes is in place (ADR-0026): the Server stores and offers packages, and each Supervisor
downloads the artifact, verifies it (content hash always, Ed25519 signature when a key is
configured), swaps it over its Managed Process's binary, health-gates it on the apply grace, and
rolls back a binary that will not stay up, reporting `Downloading` with its progress while the
artifact is still on the wire. With the move to Baseline `v0.19.0` both ends also
enforce the protocol's new message size limits in both directions, on both transports and at the
Supervisor Endpoint. The Client also updates **itself** over the same package delivery (goal 11,
ADR-0018): it is always its own Agent now, whether or not it supervises anything, and a named
package is staged beside the running version, proved by running it, and switched into by an exit
the service manager answers with a restart — with a marker carrying the outcome across that
restart and rolling back a version that will not stay up. Mutual TLS closes goal 17 (ADR-0021): the Server verifies client
certificates against a configured CA and admits by that certificate alone, the Client presents one
on both transports, and the Server issues them itself through
the Baseline's CSR flow — the Agent keeps its private key, sends a signing request, and receives the
certificate as an ordinary connection-settings offer it proves by connecting with. Own telemetry closes three more bits (ADR-0016): the Client
reports its own process metrics, its logs, and spans over the control loop's own lifecycles, OTLP
over HTTP to whatever destination the Server names — and refuses a cleartext one outside the
private address space (ADR-0016). Every remaining
*planned* row — other connection settings and custom messages — is future work; the rows above
double as that work list. Two rows still read *partial* rather than
*implemented*: both connection-settings capabilities honour the endpoint, heartbeat, and
certificate an offer carries but not its `tls`, `proxy` and `headers` fields — deliberately, and
never silently (see [Mutual TLS](#mutual-tls-and-the-two-fields-still-refused)).
