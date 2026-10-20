# Development observability stack

OTLP in, Grafana out — logs, metrics, and traces from the Agents' own telemetry (ADR-0016), stored
in one place — twice: in ClickHouse and, side by side, in Apache Doris. It is a Compose project of its own ([`compose.yaml`](compose.yaml)) that runs on the
host, apart from the Dev Container: start it when you want to look, leave it off when you do not.
This is a **development tool**: nothing shipped depends on it, it holds no credentials worth having,
and it retains 24 h of data on a local volume.

```
                                                   ┌─▶ ClickHouse ───┐
Agent ──OTLP/HTTP:4318──▶ OpenTelemetry Collector ─┤                 ├──▶ Grafana :3001
                                                   └─▶ Apache Doris ─┘
                                otel_traces · otel_logs · otel_metrics_gauge, in each
```

"One store" below is about the *shape*: all three signals in one SQL database. Doris is a second
such store next to ClickHouse, fed the same data, so the two can be compared on it — see
[Doris, side by side](#doris-side-by-side).

## Why one store

This stack used to run Tempo, Prometheus and Loki side by side — one backend per signal, which is
the conventional shape. It is now ClickHouse alone. What that changes:

- **One query language.** Every panel is SQL. Before, the same dashboard mixed PromQL, LogQL and
  TraceQL, and knowing one told you nothing about the others.
- **Cross-signal questions become joins.** "Which log lines belong to the operation that failed" is
  a join between `otel_logs` and `otel_traces` on `TraceId`. Across three stores that is not a
  query at all — it is a Grafana datasource link that jumps you elsewhere and loses the rest of
  your filter.
- **One retention setting.** `ttl: 24h` in [otel-collector.yaml](otel-collector.yaml), instead of
  Prometheus' `--storage.tsdb.retention`, Loki's `retention_period` and Tempo's `block_retention`.
- **One process to run.** Four containers became three, and one of them is Grafana.

What it costs, stated plainly rather than discovered later:

- **The service map is gone.** Tempo's metrics-generator produced `traces_spanmetrics_*` and a
  service graph for free. ClickHouse computes the RED metrics from the spans themselves — that part
  is a `count()` and a `quantile()` — but nothing draws a node graph. For a fleet Client the loss is
  small: its spans are *phases of one operation*, not services calling each other, so the panel
  that replaced it groups child spans by how often they fail, which is the question that actually
  gets asked. On a stack tracing a real service mesh, this would be a genuine loss.
- **The datasource is a plugin.** `grafana-clickhouse-datasource` is not built into Grafana, so the
  first `up` needs network access to install it. It also requires **Grafana ≥ 11.6.0**, which is why
  the image here is newer than the one the three-store stack ran.
- **No PromQL.** Recording rules, alerting expressions and any dashboard copied from elsewhere have
  to be rewritten. Nothing here needed them; a stack that does should think twice.
- **Metrics are stored as rows, not as a TSDB.** ClickHouse is very good at this and 24 h of a small
  fleet is nothing to it. At fleet-wide scale over months, a purpose-built TSDB still wins on
  storage per sample.

## Start

On the **host**, from the repository root (Podman's `podman compose` takes the same arguments):

```sh
docker compose -f observability/compose.yaml up -d      # start, in the background
docker compose -f observability/compose.yaml down       # stop; the data is kept
docker compose -f observability/compose.yaml down -v    # stop, and throw the data away
```

Or `cd observability` and leave out the `-f`. ClickHouse, the Collector and Grafana need roughly
2 GB of memory; Doris adds far more — its FE is a JVM with a fixed 8 GB heap, and its BE takes up to
90 % of the host's memory as its own limit. Plan for 12 GB or more while Doris is up, and expect the
first start to take a few minutes: the BE registers with the FE, and only once the FE reports it
alive do the Collector and Grafana start.

Grafana is on <http://localhost:3001> — anonymous access is enabled, so there is nothing to log in
to (`admin` / `admin` if you want to edit and save). It opens on **Fleet Agents — Overview**.

The first start pulls the ClickHouse datasource plugin, so give Grafana a few seconds longer than
usual and make sure the machine has network access. Without it, Grafana starts with no datasource
and every panel reports one.

**Every port is published on every interface of the host**, as the stack has always been. On a
machine that sits on a network you do not trust, bind them to the loopback instead:

```sh
OBSERVABILITY_BIND=127.0.0.1 docker compose -f observability/compose.yaml up -d
```

Whether the Dev Container still reaches a port bound to the host's loopback depends on the
container engine and its network mode, so check with the `curl` under
[Checking that data arrives](#checking-that-data-arrives) from inside the container.

### Reaching it from the Dev Container

The Dev Container has no Docker socket ([ADR-0002](../docs/adr/0002-dev-container-runtime.md)) and
needs none for this: it reaches the Collector **through the host**, over the ports published above.

The Client sends own telemetry in plaintext to a loopback IP literal and nowhere else
([ADR-0016](../docs/adr/0016-what-an-agent-reports-about-itself.md)), so
`http://host.docker.internal:4318` is refused inside the container just like any other address.
That is why the container forwards the host's Collector onto its own loopback:
[`.devcontainer/forward-otlp.sh`](../.devcontainer/forward-otlp.sh), run by `postStartCommand` on
every start, listens on `127.0.0.1:4317` and `127.0.0.1:4318` inside the container and passes each
connection on to the same port on the host. The hop to the host stays on this machine.

| From | Collector (OTLP/HTTP) | Grafana | ClickHouse |
| ---- | --------------------- | ------- | ---------- |
| the host | `http://127.0.0.1:4318` | <http://localhost:3001> | `localhost:9000` / `:8123` |
| the Dev Container | `http://127.0.0.1:4318` (forwarded) | the host's browser | `host.docker.internal:9000` / `:8123` |

So `http://127.0.0.1:4318/v1/logs` means the same Collector on the host and in the container, and a
`server.toml` needs no second spelling. The forwarder is there whether the stack runs or not: while
it is down, an export fails and the Client reports it, and the next one after `up` arrives.

**The forwarder holds 4317 and 4318 on the container's loopback.** A Collector run *inside* the
container as a Managed Process — the first example in `config/supervisor.toml` receives on
`127.0.0.1:4318` — finds the port taken. Give that one another port, or stop the forwarder first
(`pkill -f 'socat TCP-LISTEN:431[78]'`); the script leaves a port alone that something else holds
when the container starts.

The host is reached by the name Podman and Docker Desktop both give it, `host.docker.internal`.
Docker Engine on Linux gives it no name; set `OTLP_FORWARD_HOST` in the container's environment to
the host's address on the bridge (usually `172.17.0.1`).

## Pointing this Server's Agents at it

The destination is not a Client setting — the Server names it, and the Client reports to what it is
offered. The annotated example [`config/server.toml`](../config/server.toml) and the `server.toml`
that `scripts/dev-pki.sh` writes carry it commented out; uncomment it once the stack runs. Any
other `server.toml` needs:

```toml
[telemetry_offer]
metrics_endpoint = "http://127.0.0.1:4318/v1/metrics"
traces_endpoint  = "http://127.0.0.1:4318/v1/traces"
logs_endpoint    = "http://127.0.0.1:4318/v1/logs"
```

Two things this stack is shaped around:

- **Full URLs with path.** The Server appends no `/v1/metrics` for you, and the Collector's OTLP/HTTP
  receiver routes on that path. An endpoint without it disappears into a 404.
- **`http://` only to `127.0.0.1` or `[::1]`.** The Client refuses every other cleartext
  destination — a private address, a host name, even `localhost` — and reports the refusal rather
  than warning about it ([ADR-0016](../docs/adr/0016-what-an-agent-reports-about-itself.md)).
  An Agent on the host, or in the Dev Container through its forwarder, reaches
  `http://127.0.0.1:4318` and is satisfied. An Agent on another machine is not: terminate TLS in
  front of the Collector and offer the `https://` URL.

Agents receive the offer only if they declare the matching capability (`ReportsOwnMetrics`,
`ReportsOwnTraces`, `ReportsOwnLogs`), and each signal is independent — offer one, two, or all three.

**The Collector is not optional any more.** ClickHouse speaks no OTLP, so unlike Tempo, Loki and
Prometheus there is no backend to point an Agent at directly when the Collector is the broken thing.
If it is down, nothing is stored.

## The schema

The Collector's ClickHouse exporter owns it — `create_schema: true` runs `CREATE TABLE IF NOT
EXISTS` at startup, so no `.sql` file here has to be kept in step with the exporter's column list.
Three tables matter:

| Table | Holds | Time column |
| ----- | ----- | ----------- |
| `otel.otel_metrics_gauge` | Every process metric the Client samples — all three are gauges | `TimeUnix` |
| `otel.otel_logs` | The Client's bridged `tracing` output | `Timestamp` |
| `otel.otel_traces` | Root and child spans, `Duration` in nanoseconds | `Timestamp` |

**Where the Agent's identity lives, and why it matters.** The OTLP Resource belongs to the
*Client* — `ResourceAttributes['service.instance.id']` is the Client that sent the sample. The Agent
each sample is *about* is on the data point: `Attributes['service.instance.id']`. That is what
separates a Managed Process from the Client that sampled it, and every "which Agent" panel reads the
latter. Metric names are stored unmodified — `process.memory.usage`, `process.cpu.utilization`,
`process.uptime` — with no Prometheus-style normalisation to unpick.

**The platform is on the Resource too.** `ResourceAttributes['os.type']` and `['host.arch']` — the
two halves ADR-0026 selects a package variant by — plus `['os.description']` for the readable form.
They describe the *host*, not one Agent: this Client samples its own process and the Managed
Processes it holds the pids of, so everything in one export runs on the machine the Resource names.
Nothing else from the `AgentDescription`'s non-identifying attributes is sent — not the host's
addresses, not the operator's own `[attributes]` — see `DESCRIPTIVE_ATTRIBUTES` in
[`telemetry.rs`](../crates/fleet-agent/src/telemetry.rs) for why that is a named list rather than a
filter.

**`service.name` means two different things on the two levels.** On the Resource it is the
*Client's* type (`supervisor`); on the data point it is the type of the Agent the sample is *about*
— `otelcol`, `fluent-bit`, `supervisor` — the Managed Process's own word where it reports one and the
configured type otherwise, which is the same value the fleet view shows. One Client reports all
three side by side, so unlike the platform this differs *within* a single export and cannot live on
the Resource. The dashboard's **Client type** variable filters the former; the **Type** column and
the series label carry the latter.

The metric panels put all of it to work: a series is *grouped* by
`Attributes['service.instance.id']` and *labelled* with a string built in SQL from the Agent's name,
its type and its host's `os.type` — `edge-01 · otelcol · linux`, with empty parts dropped rather
than left as hanging separators. The uid stays the grouping key on purpose: two Agents on different
hosts may well carry the same instance name, and grouping by the readable one would silently average
them into a single series.

## What is already there

Three dashboards are provisioned from `grafana/dashboards/` into the **OpAMP** folder, each with a
**(Doris)** twin over the Doris copy of the data ([Doris, side by side](#doris-side-by-side)):

| Dashboard | Shows |
| --------- | ----- |
| **Fleet Agents — Overview** | All three signals on one page: how many agents report, their memory / CPU / uptime, log volume by level with a live tail, and operation rate with the recent ones. Filterable by client type, agent, and platform. |
| **Fleet Agents — Logs** | The log stream on its own — volume by level and by client, with service / level / substring filters. |
| **Fleet Agents — Traces** | Operation rate, error rate, p50/p95/p99 duration, which phase fails most, and a trace detail view. |

**What fills the traces dashboard.** Five fleet operations, and nothing else
([ADR-0016](../docs/adr/0016-what-an-agent-reports-about-itself.md)): `package.install`,
`config.apply` (twice over — a Managed Process's configuration, and the Supervisor set),
`connection.settings.apply`, and `self.update`. Each is a root span whose children are its phases,
and whose status is the outcome the Server is told — so *"which phase fails most"* has real rows in
it and the trace detail view shows a rollout end to end. The transport's own message handling is
deliberately **not** traced: at one exchange per Agent per interval it would bury those five.

Two things follow, and both are visible here:

- **A log record written inside an operation carries that operation's `TraceId`**, which is what
  makes the join between `otel_logs` and `otel_traces` above answerable. Log lines outside one carry
  none — most of them, since most of what a Client logs is not part of a fleet operation.
- **The very first offer is not in the dashboard.** The span of the `connection.settings.apply` that
  *installs* the exporter starts before there is an exporter to record it, so that one apply is
  missing and every operation after it is there. A Client that already holds persisted settings puts
  the exporter in force at startup and does not have the gap.

Drop any further dashboard JSON into `grafana/dashboards/` — it is picked up within 30 s, no restart.

### Why the line panels set an interval and a null threshold

Dashboard JSON carries no comments, so the reasoning for three settings that look arbitrary lives
here.

Every metric panel queries in *long format* — one row per (bucket, agent) — and Grafana turns that
into one column per agent over a shared time axis. A bucket in which one agent has no sample
becomes a `null` in its column, even when that bucket exists only because *another* agent sampled
there. With `spanNulls: false` and `showPoints: "never"`, two agents whose samples fall into
alternating buckets therefore have a `null` between every pair of their own points, and a line panel
draws nothing at all: legend, tooltip and values are there, the canvas is empty. One agent never
shows it — its rows are contiguous — so the failure appears exactly when a second Client starts
reporting.

The buckets alternate because each Client's `PeriodicReader` runs in its own phase (the samples of
*one* Client share a timestamp, so its Managed Processes stay aligned), and because
`$__timeInterval` resolves from the panel's width — around 5 s over an hour, well below the 10 s
sampling interval ADR-0016 sets.

Hence:

- **`"interval": "30s"`** on the three metric panels — three samples per bucket, so a bucket without
  a sample is a real absence rather than a phase artefact.
- **`"spanNulls": 60000`** instead of `false` — bridges a single missing bucket, and leaves anything
  longer as the visible gap it is. The uptime panel's *"a gap is a process that was not running"*
  still holds; what it no longer reports is the join's own nulls.
- **`"showPoints": "auto"`** — a sample with no neighbour is drawn as a point instead of vanishing.

## Doris, side by side

The Collector writes every signal to Doris as well ([otel-collector.yaml](otel-collector.yaml),
exporter `doris`), and every dashboard has a **(Doris)** twin over the same data. Doris runs as one
FE (`doris-fe`: metadata, SQL on the MySQL port 9030, the HTTP API on 8030) and one BE
(`doris-be`: storage and execution).

**Grafana needs no Doris plugin to query it.** Doris speaks the MySQL protocol, so the `Doris`
datasource is Grafana's built-in MySQL one, and the twins' macros are MySQL's
(`$__timeFilter`, `$__timeGroup`, `$__timeFrom()`). On top of that, the **Grafana Doris app**
(VeloDB's `velodb-doris-app`) adds a log *Discover* page and a Jaeger-like *Traces* page over the
same tables. It is not in Grafana's plugin catalog and it is unsigned: the one-shot
`grafana-doris-app` service installs a pinned release checked against its SHA-256, and
`GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS` names it.

**The twins are generated, never edited.** [`grafana/doris-dashboards.py`](grafana/doris-dashboards.py)
copies each ClickHouse dashboard — layout, units, options — and replaces the datasource, the SQL,
the title, the uid and the links. After changing a ClickHouse dashboard, run it again; a panel it
has no Doris query for fails the run, so a new panel cannot ship without its twin.

**Why the SQL is not a copy.** The Doris exporter owns a schema of its own, and it differs from
ClickHouse's in more than spelling:

| | ClickHouse | Doris |
|---|---|---|
| Columns | `Timestamp`, `ServiceName`, `SeverityText`, `TimeUnix`, `MetricName`, `Value` | `timestamp` everywhere, `service_name`, `severity_text`, `metric_name`, `value` |
| Attributes | `Map`: `ResourceAttributes['service.instance.id']` | `VARIANT`: `CAST(resource_attributes['service.instance.id'] AS STRING)` |
| Span duration | nanoseconds | **microseconds** |
| Span status | `Error`, `Ok`, `Unset` | `STATUS_CODE_ERROR`, `STATUS_CODE_OK`, `STATUS_CODE_UNSET` — mapped back in the twins' SQL |
| Service and Client | in the attribute maps | also as columns: `service_name`, `service_instance_id` (the *Resource's*, i.e. the Client's) |

**Time zone.** The exporter writes `DATETIME` without an offset, in the zone it is given:
`timezone: UTC`, and the datasource's session reads UTC (`timezone: "+00:00"`). Change one and not
the other, and every panel shifts by the difference.

**Fixed addresses.** The Doris images register FE and BE with each other by IP only, so the
project network has a subnet of its own, `10.250.0.0/24`. If that collides with a network on the
host, set `DORIS_SUBNET_PREFIX` (e.g. `DORIS_SUBNET_PREFIX=10.251.7`) — before the first start, since
the BE's address is stored in the FE's metadata volume; afterwards, `down -v` first.

**`vm.max_map_count`.** Doris asks the host for 2000000, far above common defaults (262144 on
many hosts), and rootless Podman cannot change it. The BE image skips that check, so it starts anyway — fine for a development
load. For more, on the host: `sudo sysctl -w vm.max_map_count=2000000`.

**Neither store depends on the other at runtime.** Each exporter queues on its own: a Doris that is
down fills its queue and drops from it, and ClickHouse in the same pipelines never waits. At
*startup* it does matter — the Doris exporter creates its tables when the Collector starts, so the
Collector waits for a healthy BE. To run ClickHouse alone, take `doris` out of the three pipelines.

**What the twins do not verify.** The Doris exporter is `alpha` in the Collector, and so is the
Doris app on Grafana 13: both are checked here against their sources, not by a test in this
repository.

## Starting from an empty store

There is no seeder here: what fills these dashboards is a Client, which is also the only thing that
proves the pipeline end to end. Traces need one operation to happen — roll a configuration out, or
offer a package — since the Client traces operations and not traffic.

ClickHouse deduplicates nothing, so a run repeated against the same window adds its rows again:
gauges and quantiles read the same, anything counted doubles. To start clean:

```sh
curl -s 'http://localhost:8123/?user=otel&password=otel' --data-binary \
  "TRUNCATE TABLE otel.otel_logs; TRUNCATE TABLE otel.otel_traces; TRUNCATE TABLE otel.otel_metrics_gauge"
```

And Doris, through its MySQL port (any MySQL client; `root`, no password):

```sh
mysql -h 127.0.0.1 -P 9030 -uroot otel \
  -e "TRUNCATE TABLE otel_logs; TRUNCATE TABLE otel_traces; TRUNCATE TABLE otel_metrics_gauge"
```

## Checking that data arrives

```sh
# Does the Collector accept OTLP at all?
curl -i -X POST http://127.0.0.1:4318/v1/traces \
     -H 'Content-Type: application/json' --data '{"resourceSpans":[]}'

# What is the Collector itself doing?
docker compose -f observability/compose.yaml logs -f otel-collector   # on the host

# What made it into ClickHouse? One query, all three signals — which is the point of one store.
curl -s 'http://localhost:8123/?user=otel&password=otel' --data-binary "
  SELECT 'metrics' AS signal, count() AS rows, max(TimeUnix)  AS newest FROM otel.otel_metrics_gauge
  UNION ALL
  SELECT 'logs',              count(),        max(Timestamp)         FROM otel.otel_logs
  UNION ALL
  SELECT 'traces',            count(),        max(Timestamp)         FROM otel.otel_traces"
```

The same question to Doris:

```sh
mysql -h 127.0.0.1 -P 9030 -uroot otel -e "
  SELECT 'metrics' AS kind, COUNT(*) AS n, MAX(timestamp) AS newest FROM otel_metrics_gauge
  UNION ALL SELECT 'logs',   COUNT(*), MAX(timestamp) FROM otel_logs
  UNION ALL SELECT 'traces', COUNT(*), MAX(timestamp) FROM otel_traces"
```

If a dashboard stays empty but the counts above are non-zero, the fault is in the panel, not the
pipeline. If the counts are zero, the Collector is the place to look — uncomment `debug` in the
relevant pipeline in [otel-collector.yaml](otel-collector.yaml) and restart that one service, and it
prints what it receives.

A join that the three-store stack could not do at all — every log line written during a failed
operation:

```sql
SELECT t.SpanName, t.StatusMessage, l.Timestamp, l.SeverityText, l.Body
FROM otel.otel_traces AS t
INNER JOIN otel.otel_logs AS l ON l.TraceId = t.TraceId
WHERE t.ParentSpanId = '' AND t.StatusCode = 'Error'
ORDER BY l.Timestamp
```

## Ports

| Port | Service | What for |
| ---- | ------- | -------- |
| 4318 | Collector | OTLP/HTTP — what the Client exports to |
| 4317 | Collector | OTLP/gRPC — for anything else you want to point here |
| 8888 | Collector | The Collector's own metrics |
| 13133 | Collector | Health check |
| 3001 | Grafana | The UI |
| 8123 | ClickHouse | HTTP interface — `curl`-able, and what the checks above use |
| 9000 | ClickHouse | Native protocol — what the Collector and Grafana speak |
| 8030 | Doris FE | HTTP API and web UI; where the Collector's stream load starts |
| 9030 | Doris FE | MySQL protocol — what Grafana, the Doris app and `mysql` speak |
