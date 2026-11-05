#!/usr/bin/env bash
#
# Self-test of scripts/check-traceability.sh. Verifies: ADR-0003
#
# Each case builds a throwaway git repository under a temporary directory — a specification with
# the two criteria sections, a few ADRs, and a file carrying markers — runs the check against it,
# and asserts the exit code and, for a failing case, the message that names the violation.
#
# The marker text inside fixtures is assembled by 'mark', never written literally, so that the
# check does not read this script's own fixtures as citations when it runs over the repository.
#
# Usage:
#     scripts/test-check-traceability.sh
# Exit code 0 when every case passes, 1 otherwise.

set -uo pipefail

# The fixtures are repositories of their own: an inherited GIT_DIR, GIT_INDEX_FILE or the like, as
# a hook exports, would point their git commands at the repository this runs in.
mapfile -t git_env < <(git rev-parse --local-env-vars)
unset "${git_env[@]}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-traceability.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
passed=0

# mark <ids...> — the marker line for the given identifiers.
mark() { printf 'Verifies: %s\n' "$*"; }

# repo <name> — create an empty fixture repository and print its path.
repo() {
  local dir="$work/$1"
  mkdir -p "$dir/docs/adr" "$dir/tests"
  git -C "$dir" init -q
  echo "$dir"
}

# spec <dir> <goals...> — write the specification; each argument is one list item of the Goals
# section. Quality Goals get one uncited item unless SPEC_QUALITY is set.
spec() {
  local dir="$1"; shift
  {
    echo "# Specification"
    echo
    echo "## Goals / Success Criteria"
    echo
    printf -- '- %s\n' "$@"
    echo
    echo "## Quality Goals"
    echo
    echo "${SPEC_QUALITY:-- **Q-1** — fast enough.}"
    echo
    echo "## Non-Goals"
    echo
    echo "- none"
  } > "$dir/docs/SPECIFICATION.md"
}

# adr <dir> <number> <status emoji + word> [enforcement text]
adr() {
  local dir="$1" n="$2" status="$3" enforcement="${4:-Review only.}"
  {
    echo "# ADR-$n: decision $n"
    echo
    echo "- **Status:** $status"
    echo
    echo "## Decision"
    echo
    echo "We will."
    echo
    echo "## Enforcement"
    echo
    echo "$enforcement"
  } > "$dir/docs/adr/$n-decision.md"
}

# expect <pass|fail> <name> <dir> [needle] — run the check; when a needle is given, its output must contain it.
expect() {
  local want="$1" name="$2" dir="$3" needle="${4:-}"
  local out rc
  git -C "$dir" add -A
  out="$(bash "$CHECK" "$dir" 2>&1)"; rc=$?
  if [[ "$want" == "pass" && $rc -eq 0 && ( -z "$needle" || "$out" == *"$needle"* ) ]] \
     || [[ "$want" == "fail" && $rc -ne 0 && ( -z "$needle" || "$out" == *"$needle"* ) ]]; then
    passed=$((passed + 1))
    return
  fi
  failed=$((failed + 1))
  echo "FAIL: $name (expected $want${needle:+ with needle \"$needle\"}, exit $rc)" >&2
  while IFS= read -r l; do printf '    %s\n' "$l"; done <<< "$out" >&2
}

# --- cases ---------------------------------------------------------------------------------

d="$(repo covered)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟢 accepted"
{ mark ADR-0001; mark G-1; } > "$d/tests/t.txt"
expect pass "accepted ADR and criterion both cited" "$d"

d="$(repo comma-list)"
spec "$d" "**G-1** — it works." "**G-2** — it also works."
adr "$d" 0001 "🟢 accepted"
mark "ADR-0001, G-1 G-2" > "$d/tests/t.txt"
expect pass "several identifiers on one marker line" "$d"

d="$(repo uncited-adr)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟢 accepted"
mark G-1 > "$d/tests/t.txt"
expect fail "accepted ADR without a citing test" "$d" "ADR-0001 is accepted but no test cites it"

d="$(repo proposed-out-of-scope)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟡 proposed"
mark G-1 > "$d/tests/t.txt"
expect pass "proposed ADR needs no citation" "$d"

d="$(repo exempt)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟢 accepted" "**Not mechanically decidable:** only a human can flip the status."
mark G-1 > "$d/tests/t.txt"
expect pass "accepted ADR with a reasoned exemption" "$d"

d="$(repo exempt-no-reason)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟢 accepted" "**Not mechanically decidable:**"
mark G-1 > "$d/tests/t.txt"
expect fail "exemption without a reason" "$d" "declared without a reason"

d="$(repo uncited-criterion)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟡 proposed"
: > "$d/tests/t.txt"
expect pass "criterion without a citing test is listed, not failed" "$d" "criteria without a test: G-1 Q-1"

d="$(repo wrapped-criterion)"
spec "$d" "**G-1** — a criterion whose text
  wraps onto a second line."
adr "$d" 0001 "🟡 proposed"
mark "G-1 Q-1" > "$d/tests/t.txt"
expect pass "a wrapped criterion is read like any other" "$d"

d="$(repo no-identifier)"
spec "$d" "it works, but carries no identifier."
adr "$d" 0001 "🟡 proposed"
: > "$d/tests/t.txt"
expect fail "list item without an identifier" "$d" "without a bold G-n identifier"

d="$(repo duplicate-identifier)"
spec "$d" "**G-1** — it works." "**G-1** — it works twice."
adr "$d" 0001 "🟡 proposed"
mark G-1 > "$d/tests/t.txt"
expect fail "identifier used twice" "$d" "appears twice"

d="$(repo wrong-section)"
SPEC_QUALITY="- **G-2** — a goal filed under quality." spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟡 proposed"
mark "G-1 G-2" > "$d/tests/t.txt"
expect fail "G-n under Quality Goals" "$d" "wrong section"

d="$(repo unknown-criterion)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟡 proposed"
mark "G-1 G-9" > "$d/tests/t.txt"
expect fail "marker citing a criterion that does not exist" "$d" "'G-9', which is not a criterion"

# The number is assembled so that check-docs.sh does not read this fixture as a stale reference.
unknown="ADR-$(printf '%04d' 42)"
d="$(repo unknown-adr)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟡 proposed"
mark "G-1 $unknown" > "$d/tests/t.txt"
expect fail "marker citing an ADR that does not exist" "$d" "'$unknown', which does not exist"

d="$(repo superseded-adr)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "⚪ superseded by ADR-0002"
adr "$d" 0002 "🟢 accepted"
mark "G-1 ADR-0001 ADR-0002" > "$d/tests/t.txt"
expect fail "marker citing a superseded ADR" "$d" "'ADR-0001', which is superseded or rejected"

d="$(repo markdown-not-counted)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟢 accepted"
{ mark ADR-0001; mark G-1; } > "$d/tests/notes.md"
expect fail "markers in Markdown do not count" "$d" "ADR-0001 is accepted but no test cites it"

d="$(repo ignored-not-counted)"
spec "$d" "**G-1** — it works."
adr "$d" 0001 "🟢 accepted"
echo "build/" > "$d/.gitignore"
mkdir -p "$d/build"
{ mark ADR-0001; mark G-1; } > "$d/build/t.txt"
expect fail "markers in gitignored files do not count" "$d" "ADR-0001 is accepted but no test cites it"

# --- the template's own promise ------------------------------------------------------------
#
# TEMPLATE-SETUP.md tells the maintainer of a derived project to accept the inherited ADRs. That
# must not turn CI red, so while this repository is still the template (the setup file exists)
# its own tree with every ADR that step accepts flipped to accepted has to pass: each inherited
# ADR ships with a citing test or an exemption. A derived project deletes the setup file, and
# with it this case: its proposed ADRs may await their tests.

if [[ -f "$ROOT/TEMPLATE-SETUP.md" ]]; then
  d="$work/template-accepted"
  mkdir -p "$d"
  while IFS= read -r -d '' rel; do
    [[ -f "$ROOT/$rel" ]] || continue
    mkdir -p "$d/$(dirname "$rel")"
    cp "$ROOT/$rel" "$d/$rel"
  done < <(git -C "$ROOT" ls-files --cached --others --exclude-standard -z)
  git -C "$d" init -q
  # ADR-0006 is the one step 2 leaves to step 7: its test is the derived project's structural
  # test, so it stays proposed here — as TEMPLATE-SETUP says.
  for f in "$d"/docs/adr/[0-9]*.md; do
    [[ "$(basename "$f")" == 0006-* ]] || sed -i 's/🟡 proposed/🟢 accepted/' "$f"
  done
  expect pass "the inherited ADRs, once accepted, pass — TEMPLATE-SETUP step 2 keeps CI green" "$d"
fi

# --- summary -------------------------------------------------------------------------------

if ((failed)); then
  echo "Traceability self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Traceability self-test passed ($passed cases)."
exit 0
