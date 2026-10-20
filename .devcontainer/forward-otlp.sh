#!/usr/bin/env bash
#
# Puts the host's OpenTelemetry Collector on this container's loopback: 127.0.0.1:4317 (OTLP/gRPC)
# and 127.0.0.1:4318 (OTLP/HTTP) inside the container are forwarded to the same ports on the host,
# where observability/compose.yaml publishes the Collector.
#
# The detour is ADR-0016's: the Client sends own telemetry in plaintext to a loopback IP literal
# and nowhere else — not to host.docker.internal, not to a private address, not even to the name
# `localhost`. So a server.toml offering `http://127.0.0.1:4318/v1/logs` reaches the Collector
# from inside the container exactly as it does on the host. The hop to the host stays on this
# machine; it never crosses a network.
#
# Run by `postStartCommand` in devcontainer.json, so on every start of the container. Starting it
# again is harmless: a port already forwarded is left as it is. Nothing here needs the stack to be
# up — a connection made while it is down fails, and the next one after `docker compose up` works.
#
# The host is reached by the name both Podman and Docker Desktop give it inside a container. On
# Docker Engine on Linux, which gives it no such name, set OTLP_FORWARD_HOST in the container's
# environment to the host's address (the bridge gateway, usually 172.17.0.1).
#
# Usage:
#     .devcontainer/forward-otlp.sh

set -euo pipefail

HOST="${OTLP_FORWARD_HOST:-host.docker.internal}"

for port in 4317 4318; do
  if ss -Hltn "sport = :$port" | grep -q .; then
    echo "forward-otlp: 127.0.0.1:$port is already listening; left as it is"
    continue
  fi
  setsid -f socat "TCP-LISTEN:$port,bind=127.0.0.1,reuseaddr,fork" "TCP:$HOST:$port" \
    >"/tmp/forward-otlp-$port.log" 2>&1
  echo "forward-otlp: 127.0.0.1:$port -> $HOST:$port"
done
