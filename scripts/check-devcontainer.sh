#!/usr/bin/env bash
#
# Dev Container check for this repository (ADR-0002).
#
# ADR-0002 keeps the host container engine out of the Dev Container's reach and pins its Features.
# This check reads the files the decision names and fails on what would break it:
#
#   1. Socket: .devcontainer/devcontainer.json mounts no host Docker socket — no 'docker.sock'
#      and no '/var/run/docker' on any line that is not a full-line comment — and adds no
#      Feature whose id names 'docker-in-docker' or 'docker-outside-of-docker', the two that
#      would mount one.
#   2. Pinning: every Feature is referenced by its major version tag alone ('<ref>:N'), never
#      untagged, ':latest', a full version, or a digest in the hand-edited file.
#   3. Lock: .devcontainer/devcontainer-lock.json exists and its 'features' block names exactly
#      the Features of devcontainer.json — a Feature added without a lock entry builds from a
#      mutable tag, and a stale entry says the lock was not regenerated.
#   4. Host side: .vscode/settings.json pins the container-management extension to the host
#      ('"ms-azuretools.vscode-containers": ["ui"]' inside the 'remote.extensionKind' object),
#      which is how host containers are managed without the socket.
#
# Only the default definition is read; a variant under a subdirectory of .devcontainer/ is not.
# devcontainer.json allows comments, so full-line '//' comments are dropped before reading; a
# trailing comment is treated as content. A Feature id is a key directly inside the 'features'
# object, whatever its value — an options object or a version string — found by tracking brace
# depth over the text split at braces and commas, so a block written on one line reads the same
# as one written out. The files are small and hand-written, and no JSON parser is guaranteed on
# PATH.
#
# Pure bash + coreutils/grep/awk. Usage:
#     scripts/check-devcontainer.sh [repository root]
# The root defaults to this repository; scripts/test-check-devcontainer.sh passes fixtures.
# Exit code 0 when the check passes, 1 otherwise.

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
CONFIG=".devcontainer/devcontainer.json"
LOCK=".devcontainer/devcontainer-lock.json"
SETTINGS=".vscode/settings.json"

errors=()
add_error() { errors+=("$1"); }

# uncommented <file> — the file without its full-line '//' comments.
uncommented() { grep -vE '^[[:space:]]*//' "$1"; }

# feature_ids <file> — the keys directly inside the "features" object, one per line.
feature_ids() {
  uncommented "$1" | awk '
    {
      gsub(/\{/, "{\n"); gsub(/\}/, "\n}"); gsub(/,/, ",\n")
      n = split($0, fragments, "\n")
      for (i = 1; i <= n; i++) {
        line = fragments[i]
        if (line ~ /"features"[[:space:]]*:[[:space:]]*\{/) { base = depth; in_features = 1 }
        else if (in_features && depth == base + 1 && line ~ /^[[:space:]]*"[^"]+"[[:space:]]*:/) {
          key = line
          sub(/^[[:space:]]*"/, "", key); sub(/".*$/, "", key)
          print key
        }
        m = split(line, chars, "")
        for (j = 1; j <= m; j++) {
          if (chars[j] == "{") depth++
          else if (chars[j] == "}") { depth--; if (in_features && depth == base) in_features = 0 }
        }
      }
    }'
}

# _contains <needle> <haystack...> — true if needle equals one of the arguments.
_contains() {
  local needle="$1"; shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

features=()
if [[ ! -f "$ROOT/$CONFIG" ]]; then
  add_error "$CONFIG: not found — the Dev Container ADR-0002 governs has nothing to check"
else
  # 1. Socket.
  if uncommented "$ROOT/$CONFIG" | grep -qE 'docker\.sock|/var/run/docker'; then
    add_error "$CONFIG: mounts the host Docker socket — the Dev Container never reaches the host engine (ADR-0002); manage host containers from the host-side extension instead"
  fi

  mapfile -t features < <(feature_ids "$ROOT/$CONFIG")
  for id in "${features[@]}"; do
    if [[ "$id" == *docker-in-docker* || "$id" == *docker-outside-of-docker* ]]; then
      add_error "$CONFIG: Feature '$id' would mount the host Docker socket or nest an engine — neither is added (ADR-0002)"
    fi
    # 2. Pinning.
    [[ "$id" =~ :[0-9]+$ ]] \
      || add_error "$CONFIG: Feature '$id' is not pinned by its major version tag alone ('<ref>:N') — an untagged, mutable, or fully versioned reference is not what the lock resolves (ADR-0002)"
  done

  # 3. Lock.
  if [[ ! -f "$ROOT/$LOCK" ]]; then
    add_error "$LOCK: not found — the lock is committed so that the same commit yields the same Features (ADR-0002)"
  else
    mapfile -t locked < <(feature_ids "$ROOT/$LOCK")
    for id in "${features[@]}"; do
      _contains "$id" "${locked[@]}" \
        || add_error "$LOCK: has no entry for Feature '$id' — regenerate the lock (rebuild the container) so the Feature builds from a resolved digest (ADR-0002)"
    done
    for id in "${locked[@]}"; do
      _contains "$id" "${features[@]}" \
        || add_error "$LOCK: lists Feature '$id', which $CONFIG no longer adds — the lock was not regenerated (ADR-0002)"
    done
  fi
fi

# 4. Host side: the pair has to sit inside the 'remote.extensionKind' object, so the text is
# flattened and matched from that key up to the first closing brace.
if [[ ! -f "$ROOT/$SETTINGS" ]]; then
  add_error "$SETTINGS: not found — it pins the container-management extension to the host side (ADR-0002)"
elif ! uncommented "$ROOT/$SETTINGS" | tr -d ' \t\n' \
       | grep -qE '"remote\.extensionKind":\{[^}]*"ms-azuretools\.vscode-containers":\["ui"\]'; then
  add_error "$SETTINGS: does not pin 'ms-azuretools.vscode-containers' to [\"ui\"] under 'remote.extensionKind' — without it the extension runs in the container and asks for the socket (ADR-0002)"
fi

if ((${#errors[@]})); then
  echo "Dev Container check FAILED:" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi

echo "Dev Container check passed (${#features[@]} Features pinned and locked, no host socket)."
exit 0
