#!/usr/bin/env bash
#
# Self-test of scripts/check-protocol-baseline.sh. Verifies: G-13 ADR-0011
#
# A divergence from upstream is detected automatically rather than noticed by chance (G-13): each
# case writes a conformance document with or without the Baseline marker, puts a stub `curl` first
# on PATH that answers with a given releases list or fails, and asserts the exit code and the line
# the check prints. Nothing reaches the network.
#
# Usage:
#     scripts/test-check-protocol-baseline.sh
# Exit code 0 when every case passes, 1 otherwise.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-protocol-baseline.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
passed=0

# conformance <name> <marker line or empty> — a conformance document, printed as its path.
conformance() {
  local file="$work/$1.md"
  { echo "# OpAMP Conformance"; echo; [[ -n "$2" ]] && echo "$2"; echo "| Baseline |"; } > "$file"
  echo "$file"
}

# stub <name> <releases JSON or 'fail'> — a directory holding a `curl` that records its arguments
# in <dir>/args and then prints the JSON or fails as an unreachable API would, printed as its path.
stub() {
  local dir="$work/bin-$1"
  mkdir -p "$dir"
  if [[ "$2" == "fail" ]]; then
    printf '#!/bin/sh\necho "$@" > "%s/args"\nexit 7\n' "$dir" > "$dir/curl"
  else
    printf '#!/bin/sh\necho "$@" > "%s/args"\ncat <<'\''JSON'\''\n%s\nJSON\n' "$dir" "$2" > "$dir/curl"
  fi
  chmod +x "$dir/curl"
  echo "$dir"
}

# expect <exit code> <name> <path prefix or 'none'> <file> [line] — run the check with the stub
# first on PATH ('none': no curl at all); the output must be exactly the given line, or, when none
# is given, empty.
expect() {
  local want="$1" name="$2" bin="$3" file="$4" needle="${5:-}"
  local out rc path
  if [[ "$bin" == "none" ]]; then
    # A PATH holding what the check needs besides curl: bash, sed and head, but no curl.
    path="$work/no-curl"
    mkdir -p "$path"
    for tool in bash dirname sed head; do ln -sf "$(command -v "$tool")" "$path/$tool"; done
  else
    path="$bin:$PATH"
  fi
  out="$(PATH="$path" bash "$CHECK" "$file" 2>&1)"; rc=$?
  if [[ $rc -eq $want && "$out" == "$needle" ]]; then
    passed=$((passed + 1))
    return
  fi
  failed=$((failed + 1))
  echo "FAIL: $name (expected exit $want${needle:+ with \"$needle\"}, got exit $rc)" >&2
  while IFS= read -r l; do printf '    %s\n' "$l"; done <<< "$out" >&2
}

pinned="$(conformance pinned '<!-- protocol-baseline: v0.20.0 -->')"
unmarked="$(conformance unmarked '')"

same="$(stub same '[{"tag_name": "v0.20.0"}]')"
expect 0 "a Baseline equal to upstream's newest release passes quietly" "$same" "$pinned"
# The releases list is what is asked, never 'releases/latest', which opamp-spec answers with 404.
if [[ "$(cat "$same/args")" == *"/repos/open-telemetry/opamp-spec/releases?per_page=1"* ]]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: the releases list is queried (curl was called with: $(cat "$same/args"))" >&2
fi
expect 0 "a newer upstream release is reported as a warning, not an error" \
  "$(stub newer '[{"tag_name": "v0.21.0"}]')" "$pinned" \
  "Warning: Protocol Baseline is v0.20.0, but open-telemetry/opamp-spec has released v0.21.0. Moving the Baseline is a deliberate change: review the upstream changelog, then update docs/CONFORMANCE.md and the code."
expect 1 "a conformance document without the marker is an error" \
  "$(stub same2 '[{"tag_name": "v0.20.0"}]')" "$unmarked" \
  "Error: $unmarked: no '<!-- protocol-baseline: vX.Y.Z -->' marker found"
expect 0 "an unreachable release API is said, and skipped" \
  "$(stub offline fail)" "$pinned" \
  "Note: could not reach the opamp-spec release API — skipping the Protocol Baseline currency check."
expect 0 "no curl at all is said, and skipped" none "$pinned" \
  "Note: curl unavailable — skipping the Protocol Baseline currency check."

if ((failed)); then
  echo "Protocol Baseline self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Protocol Baseline self-test passed ($passed cases)."
exit 0
