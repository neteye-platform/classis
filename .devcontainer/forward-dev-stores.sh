#!/usr/bin/env bash
#
# Puts the host's development stores on this container's loopback: 127.0.0.1:9100 (rustfs, the S3
# store a development Server may keep its artifacts in, ADR-0049 clause 9) and 127.0.0.1:5432
# (PostgreSQL, the database it may keep its records in, ADR-0050 clause 16) inside the container
# are forwarded to the same ports on the host, where dev/compose.yaml publishes them. Its
# `[blobs.s3] endpoint` and `[database.postgres] tls = false` may be plaintext on the loopback
# alone, so the same address works on the host and in the container. The hop to the host stays on
# this machine; it never crosses a network.
#
# Run by `postStartCommand` in devcontainer.json, so on every start of the container. Starting it
# again is harmless: a port already forwarded is left as it is. Nothing here needs the stores to
# be up — a connection made while they are down fails, and the next one after `docker compose up`
# works.
#
# The host is reached by the name both Podman and Docker Desktop give it inside a container. On
# Docker Engine on Linux, which gives it no such name, set DEV_STORES_HOST in the container's
# environment to the host's address (the bridge gateway, usually 172.17.0.1).
#
# Usage:
#     .devcontainer/forward-dev-stores.sh

set -euo pipefail

HOST="${DEV_STORES_HOST:-host.docker.internal}"

for port in 9100 5432; do
  if ss -Hltn "sport = :$port" | grep -q .; then
    echo "forward-dev-stores: 127.0.0.1:$port is already listening; left as it is"
    continue
  fi
  setsid -f socat "TCP-LISTEN:$port,bind=127.0.0.1,reuseaddr,fork" "TCP:$HOST:$port" \
    >"/tmp/forward-dev-stores-$port.log" 2>&1
  echo "forward-dev-stores: 127.0.0.1:$port -> $HOST:$port"
done
