#!/usr/bin/env python3
"""Writes the Doris twin of every ClickHouse dashboard in dashboards/.

The twins are generated, never edited: layout, units and options come from the ClickHouse
dashboard, and only the datasource, the SQL, the title, the uid and the links are replaced. Run it
after changing a ClickHouse dashboard:

    python3 observability/grafana/doris-dashboards.py

A panel the table below does not translate fails the run, so a new ClickHouse panel cannot ship
without its Doris query.

Why the SQL differs, beyond the dialect (ClickHouse `match`, `countIf`, `argMax`, `quantile`, …):
the Collector's Doris exporter owns a schema of its own — snake_case columns, attributes as
VARIANT (read as `CAST(col['dotted.key'] AS STRING)`), span durations in MICROSECONDS where
ClickHouse has nanoseconds, and status codes spelled `STATUS_CODE_ERROR`. The queries map the
status back to `Error`/`Ok`/`Unset`, so both twins show the same words.

Grafana reaches Doris through its built-in MySQL datasource, so the macros are MySQL's:
`$__timeFilter(col)`, `$__timeGroup(col, $__interval)`, `$__timeFrom()`, `$__timeTo()`.
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARDS = os.path.join(HERE, "dashboards")
DATASOURCE = {"type": "mysql", "uid": "doris"}


def attr(column: str, key: str) -> str:
    """A VARIANT attribute as a string; the exporter stores dotted keys flat."""
    return f"CAST({column}['{key}'] AS STRING)"


AGENT = attr("attributes", "service.instance.id")
LABEL = (
    "CONCAT_WS(' · ', "
    f"NULLIF({attr('attributes', 'service.instance.name')}, ''), "
    f"NULLIF({attr('attributes', 'service.name')}, ''), "
    f"NULLIF({attr('resource_attributes', 'os.type')}, ''))"
)
PLATFORM = (
    f"CONCAT({attr('resource_attributes', 'os.type')}, '/', "
    f"{attr('resource_attributes', 'host.arch')})"
)
OUTCOME = (
    "CASE status_code WHEN 'STATUS_CODE_ERROR' THEN 'Error' "
    "WHEN 'STATUS_CODE_OK' THEN 'Ok' ELSE 'Unset' END"
)
ERRORED = "SUM(CASE WHEN status_code = 'STATUS_CODE_ERROR' THEN 1 ELSE 0 END)"
TIME = "$__timeGroup(timestamp, $__interval) AS `time`"


def gauge_filter(indent: str = "  ") -> str:
    """The overview's client, instance and platform filters."""
    return "\n".join(f"{indent}AND {c}" for c in (
        "service_name REGEXP '${client:regex}'",
        f"{AGENT} REGEXP '${{instance:regex}}'",
        f"{PLATFORM} REGEXP '${{platform:regex}}'",
    ))


GAUGE_FILTER = gauge_filter()


def process_series(metric: str, column: str) -> str:
    return f"""SELECT {TIME},
       {AGENT} AS agent,
       {LABEL} AS label,
       AVG(value) AS {column}
FROM otel.otel_metrics_gauge
WHERE metric_name = '{metric}' AND $__timeFilter(timestamp)
{GAUGE_FILTER}
GROUP BY `time`, agent, label
ORDER BY `time`"""


def latest_per_agent(metric: str, outer: str) -> str:
    return f"""SELECT {outer}(latest)
FROM (SELECT MAX_BY(value, timestamp) AS latest
      FROM otel.otel_metrics_gauge
      WHERE metric_name = '{metric}' AND $__timeFilter(timestamp)
      GROUP BY {AGENT}) AS per_agent"""


LOG_FILTER = """  AND service_name REGEXP '${service:regex}'
  AND severity_text REGEXP '${level:regex}'"""

# (dashboard file, panel title) -> Doris SQL
PANELS = {
    # ---- Fleet Agents — Logs
    ("agents-logs.json", "Lines in window"): f"""SELECT COUNT(*)
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
{LOG_FILTER}""",
    ("agents-logs.json", "Errors in window"): """SELECT SUM(CASE WHEN severity_text = 'ERROR' THEN 1 ELSE 0 END)
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
  AND service_name REGEXP '${service:regex}'""",
    ("agents-logs.json", "Warnings in window"): """SELECT SUM(CASE WHEN severity_text = 'WARN' THEN 1 ELSE 0 END)
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
  AND service_name REGEXP '${service:regex}'""",
    ("agents-logs.json", "Clients logging"): """SELECT COUNT(DISTINCT service_instance_id)
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
  AND service_name REGEXP '${service:regex}'""",
    ("agents-logs.json", "Volume by level"): f"""SELECT {TIME}, severity_text AS level, COUNT(*) AS lines
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
{LOG_FILTER}
GROUP BY `time`, level
ORDER BY `time`""",
    ("agents-logs.json", "Volume by client"): f"""SELECT {TIME},
       service_instance_id AS agent,
       COUNT(*) AS lines
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
{LOG_FILTER}
GROUP BY `time`, agent
ORDER BY `time`""",
    ("agents-logs.json", "Log"): f"""SELECT timestamp,
       body,
       severity_text AS level,
       service_name AS service,
       service_instance_id AS agent,
       {attr('log_attributes', 'code.namespace')} AS target,
       trace_id
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
{LOG_FILTER}
  AND LOCATE(LOWER('${{search}}'), LOWER(body)) > 0
ORDER BY timestamp DESC
LIMIT 1000""",
    # ---- Fleet Agents — Overview
    ("agents-overview.json", "Agents reporting"): f"""SELECT COUNT(DISTINCT {AGENT})
FROM otel.otel_metrics_gauge
WHERE metric_name = 'process.uptime' AND $__timeFilter(timestamp)""",
    ("agents-overview.json", "Clients reporting"): """SELECT COUNT(DISTINCT service_instance_id)
FROM otel.otel_metrics_gauge
WHERE $__timeFilter(timestamp)""",
    ("agents-overview.json", "Memory, all agents"): latest_per_agent("process.memory.usage", "SUM"),
    ("agents-overview.json", "Busiest agent, CPU"): latest_per_agent("process.cpu.utilization", "MAX"),
    ("agents-overview.json", "Log lines / min"): """SELECT COUNT(*) / GREATEST(1, MINUTES_DIFF($__timeTo(), $__timeFrom()))
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)""",
    ("agents-overview.json", "Traces / min"): """SELECT COUNT(*) / GREATEST(1, MINUTES_DIFF($__timeTo(), $__timeFrom()))
FROM otel.otel_traces
WHERE parent_span_id = '' AND $__timeFilter(timestamp)""",
    ("agents-overview.json", "Process memory"): process_series("process.memory.usage", "memory"),
    ("agents-overview.json", "Process CPU"): process_series("process.cpu.utilization", "cpu"),
    ("agents-overview.json", "Process uptime"): process_series("process.uptime", "uptime"),
    # ClickHouse's argMaxIf per metric becomes a latest-per-(agent, metric) inner query pivoted
    # by the outer one: Doris has MAX_BY, but no conditional form of it.
    ("agents-overview.json", "Agents"): f"""SELECT agent AS `Agent`,
       ANY_VALUE(name) AS `Name`,
       ANY_VALUE(type) AS `Type`,
       ANY_VALUE(client) AS `Client`,
       ANY_VALUE(client_version) AS `Client version`,
       ANY_VALUE(os) AS `OS`,
       ANY_VALUE(arch) AS `Arch`,
       MAX(CASE WHEN metric_name = 'process.memory.usage' THEN latest END) AS `Memory`,
       MAX(CASE WHEN metric_name = 'process.cpu.utilization' THEN latest END) AS `CPU`,
       MAX(CASE WHEN metric_name = 'process.uptime' THEN latest END) AS `Uptime`,
       MAX(last_sample) AS `Last sample`
FROM (SELECT {AGENT} AS agent,
             metric_name,
             MAX_BY(value, timestamp) AS latest,
             MAX(timestamp) AS last_sample,
             ANY_VALUE({attr('attributes', 'service.instance.name')}) AS name,
             ANY_VALUE({attr('attributes', 'service.name')}) AS type,
             ANY_VALUE({attr('resource_attributes', 'service.instance.name')}) AS client,
             ANY_VALUE({attr('resource_attributes', 'service.version')}) AS client_version,
             ANY_VALUE({attr('resource_attributes', 'os.type')}) AS os,
             ANY_VALUE({attr('resource_attributes', 'host.arch')}) AS arch
      FROM otel.otel_metrics_gauge
      WHERE $__timeFilter(timestamp)
{gauge_filter('        ')}
      GROUP BY agent, metric_name) AS per_metric
GROUP BY agent
ORDER BY agent""",
    ("agents-overview.json", "Log volume by level"): f"""SELECT {TIME}, severity_text AS level, COUNT(*) AS lines
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
GROUP BY `time`, level
ORDER BY `time`""",
    ("agents-overview.json", "Live log"): f"""SELECT timestamp,
       body,
       severity_text AS level,
       service_name AS service,
       trace_id,
       {attr('log_attributes', 'code.namespace')} AS target
FROM otel.otel_logs
WHERE $__timeFilter(timestamp)
ORDER BY timestamp DESC
LIMIT 500""",
    ("agents-overview.json", "Spans by service"): f"""SELECT {TIME}, service_name AS service, COUNT(*) AS spans
FROM otel.otel_traces
WHERE $__timeFilter(timestamp)
GROUP BY `time`, service
ORDER BY `time`""",
    ("agents-overview.json", "Operation duration, p95"): f"""SELECT {TIME},
       service_name AS service,
       PERCENTILE_APPROX(duration, 0.95) / 1000 AS p95_ms
FROM otel.otel_traces
WHERE parent_span_id = '' AND $__timeFilter(timestamp)
GROUP BY `time`, service
ORDER BY `time`""",
    ("agents-overview.json", "Recent operations"): f"""SELECT trace_id AS `Trace`,
       span_name AS `Operation`,
       timestamp AS `Started`,
       duration / 1000 AS `Duration (ms)`,
       {OUTCOME} AS `Outcome`,
       {attr('span_attributes', 'service.instance.id')} AS `Agent`
FROM otel.otel_traces
WHERE parent_span_id = '' AND $__timeFilter(timestamp)
ORDER BY timestamp DESC
LIMIT 50""",
    # ---- Fleet Agents — Traces
    ("agents-traces.json", "Spans per second, by service"): f"""SELECT {TIME},
       service_name AS service,
       COUNT(*) / ($__interval_ms / 1000) AS spans_per_second
FROM otel.otel_traces
WHERE $__timeFilter(timestamp)
GROUP BY `time`, service
ORDER BY `time`""",
    ("agents-traces.json", "Errored spans per second"): f"""SELECT {TIME},
       service_name AS service,
       {ERRORED} / ($__interval_ms / 1000) AS errored_per_second
FROM otel.otel_traces
WHERE $__timeFilter(timestamp)
GROUP BY `time`, service
ORDER BY `time`""",
    ("agents-traces.json", "Operation duration p50 / p95 / p99"): f"""SELECT {TIME},
       PERCENTILE_APPROX(duration, 0.50) / 1000 AS p50_ms,
       PERCENTILE_APPROX(duration, 0.95) / 1000 AS p95_ms,
       PERCENTILE_APPROX(duration, 0.99) / 1000 AS p99_ms
FROM otel.otel_traces
WHERE parent_span_id = '' AND $__timeFilter(timestamp)
GROUP BY `time`
ORDER BY `time`""",
    ("agents-traces.json", "Phases, by how often they fail"): f"""SELECT span_name AS `Phase`,
       COUNT(*) AS `Runs`,
       {ERRORED} AS `Failed`,
       ROUND(100 * {ERRORED} / COUNT(*), 1) AS `Failed %`,
       PERCENTILE_APPROX(duration, 0.95) / 1000 AS `p95 ms`
FROM otel.otel_traces
WHERE parent_span_id != '' AND $__timeFilter(timestamp)
GROUP BY span_name
ORDER BY `Failed` DESC, `Runs` DESC""",
    ("agents-traces.json", "Operations"): f"""SELECT trace_id AS `Trace`,
       span_name AS `Operation`,
       timestamp AS `Started`,
       duration / 1000 AS `Duration (ms)`,
       {OUTCOME} AS `Outcome`,
       status_message AS `Message`
FROM otel.otel_traces
WHERE parent_span_id = '' AND $__timeFilter(timestamp)
      AND span_name REGEXP '${{operation:regex}}'
ORDER BY timestamp DESC
LIMIT 200""",
    # The trace view takes its frame by field name; the span and resource attributes arrive as
    # JSON arrays of {key, value}, the shape the view reads tags in.
    ("agents-traces.json", "Trace detail"): f"""SELECT trace_id AS traceID,
       span_id AS spanID,
       parent_span_id AS parentSpanID,
       service_name AS serviceName,
       span_name AS operationName,
       CAST(UNIX_TIMESTAMP(timestamp) * 1000 AS DOUBLE) AS startTime,
       CAST(duration AS DOUBLE) / 1000 AS duration,
       CAST(span_attributes AS STRING) AS tags,
       CAST(resource_attributes AS STRING) AS serviceTags,
       CASE WHEN status_code = 'STATUS_CODE_ERROR' THEN 2 ELSE 0 END AS statusCode
FROM otel.otel_traces
WHERE trace_id = '${{trace}}'
ORDER BY startTime ASC, duration DESC""",
}

# Template variables, by dashboard and name.
VARIABLES = {
    ("agents-logs.json", "service"): "SELECT DISTINCT service_name FROM otel.otel_logs ORDER BY 1",
    ("agents-overview.json", "client"): "SELECT DISTINCT service_name FROM otel.otel_metrics_gauge ORDER BY 1",
    ("agents-overview.json", "instance"): f"SELECT DISTINCT {AGENT} FROM otel.otel_metrics_gauge ORDER BY 1",
    ("agents-overview.json", "platform"): f"SELECT DISTINCT {PLATFORM} FROM otel.otel_metrics_gauge ORDER BY 1",
    ("agents-traces.json", "operation"): "SELECT DISTINCT span_name FROM otel.otel_traces WHERE parent_span_id = '' ORDER BY 1",
}

# Grafana SQL formats: ClickHouse's numbers -> the MySQL datasource's names.
FORMATS = {0: "time_series", 1: "table", 2: "table", 3: "table"}


def twin_uid(uid: str) -> str:
    return f"{uid}-doris"


def twin_name(name: str) -> str:
    return name.replace(".json", "-doris.json")


def translate(name: str, dashboard: dict) -> dict:
    out = copy.deepcopy(dashboard)
    out["uid"] = twin_uid(dashboard["uid"])
    out["title"] = f"{dashboard['title']} (Doris)"
    out["tags"] = sorted(set(dashboard.get("tags", [])) | {"doris"})

    for panel in out["panels"]:
        if "datasource" in panel:
            panel["datasource"] = dict(DATASOURCE)
        for target in panel.get("targets", []):
            key = (name, panel["title"])
            if key not in PANELS:
                sys.exit(f"{name}: no Doris query for panel {panel['title']!r}")
            fmt = target.get("format")
            ref = target.get("refId", "A")
            target.clear()
            target.update({
                "refId": ref,
                "datasource": dict(DATASOURCE),
                "editorMode": "code",
                "rawQuery": True,
                "rawSql": PANELS[key],
                "format": FORMATS.get(fmt, "table"),
            })
        # Links into a ClickHouse dashboard become links into its Doris twin.
        for override in panel.get("fieldConfig", {}).get("overrides", []):
            for prop in override.get("properties", []):
                if prop.get("id") == "links":
                    for link in prop["value"]:
                        link["url"] = link["url"].replace(
                            "/d/opamp-agents-traces/", f"/d/{twin_uid('opamp-agents-traces')}/"
                        )

    for var in out.get("templating", {}).get("list", []):
        if var.get("type") != "query":
            continue
        key = (name, var["name"])
        if key not in VARIABLES:
            sys.exit(f"{name}: no Doris query for variable {var['name']!r}")
        var["datasource"] = dict(DATASOURCE)
        var["query"] = VARIABLES[key]
        var["definition"] = VARIABLES[key]
    return out


def main() -> None:
    for name in sorted(os.listdir(DASHBOARDS)):
        if not name.endswith(".json") or name.endswith("-doris.json"):
            continue
        with open(os.path.join(DASHBOARDS, name), encoding="utf-8") as fh:
            dashboard = json.load(fh)
        twin = translate(name, dashboard)
        with open(os.path.join(DASHBOARDS, twin_name(name)), "w", encoding="utf-8") as fh:
            json.dump(twin, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"wrote dashboards/{twin_name(name)}")


if __name__ == "__main__":
    main()
