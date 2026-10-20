#!/usr/bin/env bash
#
# Seeds one minimal test Configuration per example Collector from config/supervisor.toml, each
# stated for the Agent type that should receive it and held by a Deployment of that name whose
# Selector aims at it (ADR-0034) — a Configuration has no Selector of its own:
#
#   otelcol-contrib-conf  →  type otelcol-contrib, deployment otelcol-contrib
#                            (selector service.name = otelcol-contrib; opampextension, self-reporting)
#   otelcol-conf          →  type otelcol, deployment otelcol
#                            (selector service.name = otelcol; core otelcol, observed externally)
#
# A Configuration's name is the file name its entry gets in the Supervisor's config directory,
# so a block that reads one must read exactly that path. Names carry no extension: they follow the
# ADR-0019 grammar (lowercase letters, digits and '-'), which admits no dot.
#
# Two modes:
#   scripts/seed_test_configs.sh [server-url]
#       PUTs each Configuration to a running Server's REST API, puts it into its Deployment and
#       rolls the Deployment out — the act that assigns it to the Agents the Deployment claims
#       (ADR-0025, ADR-0034); a PUT alone reaches nobody.
#       (default server-url: https://127.0.0.1:4321). The Operator plane serves TLS (ADR-0013); the
#       CA curl trusts is $SEED_CACERT, or .dev-pki/offline/server-ca.pem when scripts/dev-pki.sh
#       made one.
#   scripts/seed_test_configs.sh --offline [data-dir]
#       Writes each Configuration as <data-dir>/configurations/<name>.json, owner-only — the
#       Server's own persistence format (ADR-0037), loaded at its next start; no running Server
#       needed. Default data-dir is fleet-data/ in the repository root (the server.toml default).
#       This is what scripts/install_tools.sh runs after installing the processes. A staged Configuration is
#       stored, not assigned, and held by no Deployment: once the Agents have enrolled, put each
#       into a Deployment and roll that out
#       (PUT /api/v1/deployments/<name>/configurations/<configuration>, then
#       POST /api/v1/deployments/<name>/rollout, or the Deployments tab).
#   scripts/seed_test_configs.sh --enrol [server-url]
#       For the development set of scripts/dev-pki.sh, whose Client enrols like any other host
#       (ADR-0028): asks the Server for a fresh bootstrap certificate for the customer and site
#       "Development" under a throwaway password, downloads its bootstrap.p12 — the Server hands
#       the key out in no other form (ADR-0036) — and extracts the pair with
#       `opamp-fleetctl pki p12-extract` where the development supervisor.toml names it
#       ($SEED_BOOTSTRAP_DIR, default .dev-pki/offline/), replacing a pair already there,
#       opens the enrolment window for ten minutes, waits up to two minutes for
#       requests — start the Client then — and approves every one it finds, printing each key
#       fingerprint. Development only — on a real fleet an operator compares each fingerprint with
#       the host's log before approving.
# The first two modes replace an existing Configuration of the same name; the first also re-aims an
# existing Deployment of the same name.
#
# Note on the contrib Collector: once its opampextension self-reports, the reported
# service.name (the dist.name it was built with, "otelcol-contrib") replaces the name derived
# from the binary's file name — which is also "otelcol-contrib", so the Selector and the type
# match before and after and live updates keep flowing. That equality is why the example
# supervisor carries that name; a supervisor whose reported type differs from its initial name
# should be labelled on the Server and its Deployment aimed at the label instead.
#
# Note on the two Foreign Agents: both refuse to start when the file their command line names
# does not exist, so a Supervisor started before the first rollout crash-loops three times and
# then holds. The rollout ends the hold; seeding first avoids the window altogether.
#
# The bodies live in config/examples/; install the processes with scripts/install_tools.sh.
# After seeding: start the Server, uncomment the [[supervisor]] blocks in config/supervisor.toml,
# and start the Client; each Agent then receives exactly its Configuration.

set -euo pipefail

examples="$(cd "$(dirname "$0")/../config/examples" && pwd)"

mode=put
if [ "${1:-}" = "--offline" ]; then
    mode=stage
    data_dir="${2:-$examples/../../fleet-data}"
    configurations="$data_dir/configurations"
    # Owner-only, as the Server keeps everything under data_dir (ADR-0037).
    umask 077
    mkdir -p "$configurations"
elif [ "${1:-}" = "--enrol" ]; then
    mode=enrol
    server="${2:-https://127.0.0.1:4321}"
else
    server="${1:-https://127.0.0.1:4321}"
fi

curl_tls=()
cacert="${SEED_CACERT:-$(dirname "$0")/../.dev-pki/offline/server-ca.pem}"
if [ -f "$cacert" ]; then
    curl_tls=(--cacert "$cacert")
fi

if [ "$mode" = enrol ]; then
    root="$(cd "$(dirname "$0")/.." && pwd)"
    bootstrap_dir="$(cd "${SEED_BOOTSTRAP_DIR:-$root/.dev-pki/offline}" && pwd)"
    # A fresh certificate every time, so one that has ended since the last run is never reused.
    # The Server keeps its key only in a PKCS#12 file under the password the request names
    # (ADR-0036): a throwaway one opens the file once, and nothing keeps it.
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    (
        umask 077
        head -c 18 /dev/urandom | base64 >"$work/password"
    )
    issued=$(jq -n --rawfile password "$work/password" \
        '{subject: {organization: "Development", organizational_unit: "Development"},
          password: ($password | rtrimstr("\n"))}' |
        curl -fsS "${curl_tls[@]}" -X POST -H 'Content-Type: application/json' -d @- \
            "$server/api/v1/bootstrap-certificates")
    serial=$(jq -r .serial <<<"$issued")
    curl -fsS "${curl_tls[@]}" -o "$work/bootstrap.p12" \
        "$server/api/v1/bootstrap-certificates/$serial/p12"
    rm -f "$bootstrap_dir/bootstrap.pem" "$bootstrap_dir/bootstrap-key.pem"
    (cd "$root" && cargo run -q -p fleet-tools -- pki p12-extract "$work/bootstrap.p12" \
        --out "$bootstrap_dir" --password-file "$work/password")
    echo "wrote the bootstrap pair, serial $serial, to $bootstrap_dir"
    curl -fsS "${curl_tls[@]}" -X POST -H 'Content-Type: application/json' \
        -d '{"open_for_secs": 600}' "$server/api/v1/enrolment/window" >/dev/null
    echo "the enrolment window is open; start the Client now"
    for _ in $(seq 120); do
        ids=$(curl -fsS "${curl_tls[@]}" "$server/api/v1/enrolments" | jq -r '.[].id')
        [ -n "$ids" ] && break
        sleep 1
    done
    if [ -z "$ids" ]; then
        echo "no enrolment request arrived within two minutes; is the Client running?" >&2
        exit 1
    fi
    for id in $ids; do
        curl -fsS "${curl_tls[@]}" -X POST "$server/api/v1/enrolments/$id/approve" >/dev/null
        echo "approved the request with key fingerprint $id"
    done
    exit 0
fi

# seed <name> <file> <service_name> <deployment> <selector-json>
#   service_name   the Agent type this Configuration is for (ADR-0034); it fits the Configuration
#                  to the Agents of its Deployment that report it
#   deployment     the Deployment that holds it; its Selector aims it
#   selector-json  the Deployment's Selector, equality pairs as a JSON object, never empty
seed() {
    local name="$1" file="$2" type="$3" deployment="$4" selector="$5"
    local spec
    spec=$(jq -Rs --arg type "$type" '{body: ., service_name: $type}' "$file")
    if [ "$mode" = stage ]; then
        jq --arg name "$name" '{name: $name, saved: .}' <<<"$spec" >"$configurations/$name.json"
        echo "staged $name.json (type $type)"
    else
        curl -fsS "${curl_tls[@]}" -X PUT -H 'Content-Type: application/json' -d @- \
            "$server/api/v1/configurations/$name" <<<"$spec" >/dev/null
        curl -fsS "${curl_tls[@]}" -X PUT -H 'Content-Type: application/json' \
            -d "{\"selector\": $selector}" "$server/api/v1/deployments/$deployment" >/dev/null
        curl -fsS "${curl_tls[@]}" -X PUT \
            "$server/api/v1/deployments/$deployment/configurations/$name" >/dev/null
        curl -fsS "${curl_tls[@]}" -X POST "$server/api/v1/deployments/$deployment/rollout" >/dev/null
        echo "PUT $name (type $type) into deployment $deployment ($selector) and rolled it out"
    fi
}

seed otelcol-contrib-conf "$examples/otelcol-contrib-conf.yaml" otelcol-contrib otelcol-contrib \
    '{"service.name": "otelcol-contrib"}'
seed otelcol-conf "$examples/otelcol-conf.yaml" otelcol otelcol '{"service.name": "otelcol"}'

if [ "$mode" = stage ]; then
    echo "Done — the Server holds these Configurations from its next start; put each into a Deployment and roll that out to assign them."
else
    echo "Done — inspect with: curl ${curl_tls[*]} $server/api/v1/configurations"
fi
