#!/usr/bin/env bash
#
# The Server speaks plain HTTP, and the `supervisor.toml` this writes dials it on the loopback in
# plain HTTP; the certificates are for a reverse proxy in front of the Server, which a Client on
# another machine reaches over TLS.
#
# Creates the certificates a development proxy and Client need, since the Client refuses to run
# without them, with the operator tool's `classisctl pki init` — no openssl. Every
# certificate of the set says it is a development one: `Classis Dev … CA`, `O=Development`.
# Everything lands in one directory, gitignored, and is for a development machine only: the keys
# are unencrypted and the CAs are throwaway.
#
#   server/        what the reverse proxy in front of the Server needs: its certificate and key
#   offline/       what stays with the operator: the server CA with its key, the package signing
#                  key (package-signing-key.pk8, its public half in package-signing-key.pub), and
#                  supervisor.toml.fragment naming the server CA
#   server.toml / supervisor.toml
#                  a Server and a Client configuration that use the set, every other key at its
#                  default but two: server.toml serves the Agent plane on every interface, so
#                  Clients on other machines reach it, and keeps its operator socket in this
#                  directory; it carries the offer of the fleet's own
#                  telemetry to a Collector on the loopback commented out
#
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

(cd "$ROOT" && cargo run -q -p classis-tools -- pki init \
  --server-dir "$OUT/server" --offline-dir "$OUT/offline" \
  --product "Classis Dev" --organization "Development" --name localhost)

{
  echo '# The Agent plane on every interface, for Clients on other machines (see config/server.toml).'
  echo 'listen = "0.0.0.0:4320"'
  echo
  echo '# The operator Unix socket, always on (see config/server.toml).'
  echo "admin_socket = \"$OUT/admin.sock\""
  echo
  echo '# The fleet'"'"'s own telemetry, to a Collector on the loopback (see config/server.toml).'
  echo '# [telemetry_offer]'
  echo '# metrics_endpoint = "http://127.0.0.1:4318/v1/metrics"'
  echo '# traces_endpoint = "http://127.0.0.1:4318/v1/traces"'
  echo '# logs_endpoint = "http://127.0.0.1:4318/v1/logs"'
} >"$OUT/server.toml"
{
  echo 'endpoint = "ws://127.0.0.1:4320/v1/opamp"'
  echo
  cat "$OUT/offline/supervisor.toml.fragment"
} >"$OUT/supervisor.toml"

cat <<EOF

Created in $OUT, with a server.toml and a supervisor.toml that use the set:

  cargo run -p classis-server -- --config $OUT/server.toml

A Client refuses to start until its host is enrolled with a Space's key. Create a Space
first, while the Server runs, over its operator socket:

  cargo run -p classis-admin -- --socket $OUT/admin.sock space create dev

With a key, and the Server running, enrol the host
before the first run, with the Server's base URL (the https:// form of the endpoint above):

  cargo run -p classis-agent -- --config $OUT/supervisor.toml enrol <base-url> <key>
  cargo run -p classis-agent -- --config $OUT/supervisor.toml
EOF
