#!/usr/bin/env bash
#
# Sensor: tests kept (AGENTS.md, section 5 — never weaken the suite).
#
# Lists, between a base and a head, what would weaken the test suite and what no toolchain's own
# tools notice: test files deleted or moved out of the tests, and skip or focus markers added. It
# reports and never fails. The reason for each finding belongs in the pull request, which this
# script cannot read; the reviewer of AGENTS.md, section 5, holds the list against it.
#
#   1. Test files: a path with a segment or a basename that contains 'test' or 'spec', in any
#      case — the convention every toolchain of TEMPLATE-SETUP.md shares, and a heuristic: a
#      deleted 'manifest.json' is reported too, and the reviewer sees at once that it is none.
#      A deletion, or a rename to a path that is no longer one, is a finding.
#   2. Markers: an added line, in any file, that carries a skip or focus marker of one of those
#      toolchains (MARKERS below). A focus marker ('it.only', 'fdescribe') runs one test and
#      skips every other. A marker on a deleted line is not read: removing a skip is not a
#      weakening.
#
# Pure bash + git + awk. Usage:
#     scripts/sensor-tests-kept.sh [base [head]]
# Without a base, the merge base of head with origin/main (else main) is used; CI passes the
# pull request's base. A base of zeros, which a push event reports for a new branch, counts as
# none. With nothing to compare — on main without a remote, or base and head the same — it says
# so. Exit code 0 always, except 2 on a base or head that does not resolve.

set -uo pipefail

MARKERS='@Disabled|@Ignore|enabled *= *false|t\.Skip[a-zA-Z]*\(|pytest\.mark\.skip|pytest\.skip\(|unittest\.skip|#\[ignore\]|(^|[^A-Za-z0-9_.])(it|test|describe|context)\.(skip|only)\(|(^|[^A-Za-z0-9_])(xit|xtest|xdescribe|fit|fdescribe|ftest)\(|Skip *= *"'

base="${1:-}"
head="${2:-HEAD}"

[[ "$base" =~ ^0+$ ]] && base=""
if [[ -z "$base" ]]; then
  for candidate in origin/main main; do
    if git rev-parse --verify -q "$candidate^{commit}" >/dev/null; then
      base="$(git merge-base "$candidate" "$head" 2>/dev/null)" && break
    fi
  done
fi
if [[ -z "$base" ]]; then
  echo "Tests kept sensor: nothing to compare — no base given and no main to compare with."
  exit 0
fi
for ref in "$base" "$head"; do
  git rev-parse --verify -q "$ref^{commit}" >/dev/null \
    || { echo "Tests kept sensor: '$ref' does not resolve to a commit." >&2; exit 2; }
done
if [[ "$(git rev-parse "$base^{commit}")" == "$(git rev-parse "$head^{commit}")" ]]; then
  echo "Tests kept sensor: nothing to compare — base and head are the same commit."
  exit 0
fi

# is_test_path <path> — a segment or the basename contains 'test' or 'spec', in any case.
is_test_path() { [[ "${1,,}" =~ (^|/)[^/]*(test|spec)[^/]*(/|$) ]]; }

findings=()

# 1. Test files deleted or moved out.
while IFS=$'\t' read -r status old new; do
  case "$status" in
    D)  is_test_path "$old" && findings+=("deleted test file: $old") ;;
    R*) if is_test_path "$old" && ! is_test_path "$new"; then
          findings+=("test file moved out of the tests: $old -> $new")
        fi ;;
  esac
done < <(git diff --name-status -M --diff-filter=DR "$base" "$head")

# 2. Skip or focus markers on added lines. The regex reaches awk through the environment, so
# that its backslashes are not escape-processed a second time. This script and its self-test
# carry the markers as data and are left out.
while IFS= read -r hit; do
  findings+=("skip or focus marker added: $hit")
done < <(git diff -U0 --no-color "$base" "$head" -- . \
           ':(exclude)scripts/sensor-tests-kept.sh' ':(exclude)scripts/test-sensor-tests-kept.sh' \
         | MARKERS="$MARKERS" awk '
             /^\+\+\+ / { file = substr($0, 7); next }
             /^@@/      { match($0, /\+[0-9]+/); line = substr($0, RSTART + 1, RLENGTH - 1) + 0; next }
             /^\+/      { if ($0 ~ ENVIRON["MARKERS"]) printf "%s:%d: %s\n", file, line, substr($0, 2); line++ }
           ')

short_base="$(git rev-parse --short "$base")"
short_head="$(git rev-parse --short "$head")"
if ((${#findings[@]} == 0)); then
  echo "Tests kept sensor ($short_base..$short_head): nothing to report."
  exit 0
fi
echo "Tests kept sensor ($short_base..$short_head): ${#findings[@]} finding(s) for the reviewer — each needs its reason in the pull request (AGENTS.md, section 5):"
printf '  - %s\n' "${findings[@]}"
exit 0
