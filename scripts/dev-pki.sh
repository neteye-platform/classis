#!/usr/bin/env bash
#
# Creates the certificates a development Server and Client need, since both refuse to run without
# them (ADR-0013, ADR-0021), with the operator tool's `opamp-fleetctl pki init`
# (ADR-0028) — no openssl. Every certificate of the set says it is a development one:
# `OpAMP Fleet Dev … CA`, `O=Development` (ADR-0028 clause 30).
# Everything lands in one directory, gitignored, and is for a development machine only: the keys
# are unencrypted and the CAs are throwaway.
#
#   server/        what the Server host needs: its certificate, the client CA and the bootstrap CA
#                  with their keys, and server.toml.fragment naming them
#   offline/       what stays with the operator: the server CA with its key, the package signing
#                  key (package-signing-key.pk8, its public half in package-signing-key.pub), and
#                  supervisor.toml.fragment naming where the Client keeps the bootstrap pair
#                  extracted from the bootstrap.p12 the Server issues, and the package
#                  verification key
#   server.toml / supervisor.toml
#                  a Server and a Client configuration that use the set, every other key at its
#                  default but one: server.toml serves the Agent plane on every interface, so
#                  Clients on other machines reach it; it carries the offer of the fleet's own
#                  telemetry to the observability stack in observability/ commented out
#
# The development Client enrols like any other host, with a bootstrap certificate the Server issues
# (ADR-0028): start the Server, run `scripts/seed_test_configs.sh --enrol`, which issues it,
# extracts its pair from the bootstrap.p12 into offline/ and approves the request, and start the
# Client while it waits.
# Trust the server CA, offline/server-ca.pem, in curl and in the browser.
#
# Usage:
#     scripts/dev-pki.sh [directory]      (default: .dev-pki in the repository root)
# Refuses to overwrite a directory that already holds a set.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/.dev-pki}"

if [[ -e "$OUT/server" || -e "$OUT/offline" ]]; then
  echo "$OUT already holds a set; remove the directory to start over" >&2
  exit 1
fi
mkdir -p "$OUT"
chmod 700 "$OUT"
OUT="$(cd "$OUT" && pwd)"  # the configurations name the set by absolute path

(cd "$ROOT" && cargo run -q -p fleet-tools -- pki init \
  --server-dir "$OUT/server" --offline-dir "$OUT/offline" \
  --product "OpAMP Fleet Dev" --organization "Development" --name localhost)

{
  echo '# The Agent plane on every interface, for Clients on other machines (see config/server.toml).'
  echo 'listen = "0.0.0.0:4320"'
  echo
  cat "$OUT/server/server.toml.fragment"
  echo
  echo '# The fleet'"'"'s own telemetry, to the stack in observability/ (see config/server.toml).'
  echo '# [telemetry_offer]'
  echo '# metrics_endpoint = "http://127.0.0.1:4318/v1/metrics"'
  echo '# traces_endpoint = "http://127.0.0.1:4318/v1/traces"'
  echo '# logs_endpoint = "http://127.0.0.1:4318/v1/logs"'
} >"$OUT/server.toml"
{
  echo 'endpoint = "wss://127.0.0.1:4320/v1/opamp"'
  echo
  cat "$OUT/offline/supervisor.toml.fragment"
} >"$OUT/supervisor.toml"

cat <<EOF

Created in $OUT, with a server.toml and a supervisor.toml that use the set:

  cargo run -p fleet-server -- --config $OUT/server.toml
  scripts/seed_test_configs.sh --enrol     # issues the bootstrap certificate, approves the enrolment
  cargo run -p fleet-agent -- --config $OUT/supervisor.toml   # while --enrol waits
EOF
