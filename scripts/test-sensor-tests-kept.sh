#!/usr/bin/env bash
#
# Self-test of scripts/sensor-tests-kept.sh.
#
# Each case builds a throwaway git repository under a temporary directory with a base commit
# holding two test files and one source file, applies one change as a second commit, runs the
# sensor against the pair, and asserts the exit code and the line the reviewer would read. The
# unchanged repository reports nothing; every other case is one thing the sensor reports, or one
# it must stay silent on.
#
# Usage:
#     scripts/test-sensor-tests-kept.sh
# Exit code 0 when every case passes, 1 otherwise.

set -uo pipefail

# The fixtures are repositories of their own: an inherited GIT_DIR, GIT_INDEX_FILE or the like, as
# a hook exports, would point their git commands at the repository this runs in.
mapfile -t git_env < <(git rev-parse --local-env-vars)
unset "${git_env[@]}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENSOR="$ROOT/scripts/sensor-tests-kept.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
passed=0

# fixture <dir> — refuse an empty fixture path: 'git -C ""' would act on this repository.
fixture() { [[ -n "${1:-}" && -d "$1/.git" ]] || { echo "fixture: '$1' is no fixture repository" >&2; exit 1; }; }

# commit <dir> <message> — stage everything and commit with a fixed identity.
commit() {
  fixture "$1"
  git -C "$1" add -A
  git -C "$1" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m "$2"
}

# repo <name> — a repository whose base commit is tagged 'base', printed as its path.
repo() {
  local dir="$work/$1"
  mkdir -p "$dir/tests" "$dir/src"
  git -C "$dir" init -q -b main
  printf 'def test_a():\n    assert True\n' > "$dir/tests/a_test.py"
  printf "it('b', () => {});\n" > "$dir/src/b.spec.ts"
  printf 'print("app")\n' > "$dir/src/app.py"
  commit "$dir" "base"
  git -C "$dir" tag base
  echo "$dir"
}

# expect <exit code> <name> <dir> <needle> [base] — run the sensor in the repository against the
# given base (default 'base'); the output must contain the needle.
expect() {
  local want="$1" name="$2" dir="$3" needle="$4" base="${5-base}"
  local out rc
  fixture "$dir"
  out="$(cd "$dir" && bash "$SENSOR" "$base" 2>&1)"; rc=$?
  if [[ $rc -eq "$want" && "$out" == *"$needle"* ]]; then
    passed=$((passed + 1))
    return
  fi
  failed=$((failed + 1))
  echo "FAIL: $name (expected exit $want with \"$needle\", got exit $rc)" >&2
  while IFS= read -r l; do printf '    %s\n' "$l"; done <<< "$out" >&2
}

# --- cases -----------------------------------------------------------------------------------

d="$(repo unchanged)"
printf 'print("more")\n' >> "$d/src/app.py"
commit "$d" "a source change"
expect 0 "a change that touches no test reports nothing" "$d" "nothing to report"

d="$(repo test-deleted)"
git -C "$d" rm -q tests/a_test.py
commit "$d" "drop a test"
expect 0 "a deleted test file" "$d" "deleted test file: tests/a_test.py"

d="$(repo test-moved-out)"
git -C "$d" mv tests/a_test.py src/helper.py
commit "$d" "move a test out"
expect 0 "a test file renamed to a path that is no test" "$d" "moved out of the tests: tests/a_test.py -> src/helper.py"

d="$(repo test-moved-within)"
git -C "$d" mv tests/a_test.py tests/a_more_test.py
commit "$d" "rename a test"
expect 0 "a test file renamed within the tests" "$d" "nothing to report"

d="$(repo source-deleted)"
git -C "$d" rm -q src/app.py
commit "$d" "drop a source file"
expect 0 "a deleted source file is not a test" "$d" "nothing to report"

d="$(repo skip-added)"
printf "it.skip('c', () => {});\n" >> "$d/src/b.spec.ts"
commit "$d" "skip a test"
expect 0 "a skip marker added, with file and line" "$d" "skip or focus marker added: src/b.spec.ts:2: it.skip('c'"

d="$(repo focus-added)"
printf "describe.only('d', () => {});\n" >> "$d/src/b.spec.ts"
commit "$d" "focus a test"
expect 0 "a focus marker runs one test and skips the rest" "$d" "src/b.spec.ts:2: describe.only("

d="$(repo skip-in-source)"
printf '@unittest.skip("later")\n' >> "$d/src/app.py"
commit "$d" "skip somewhere else"
expect 0 "a marker in a file that is no test is reported too" "$d" "src/app.py:2: @unittest.skip"

d="$(repo skip-removed)"
printf "it.skip('c', () => {});\n" >> "$d/src/b.spec.ts"
commit "$d" "skip a test"
git -C "$d" tag skipped
printf "it('b', () => {});\n" > "$d/src/b.spec.ts"
commit "$d" "unskip it"
expect 0 "a marker on a deleted line is not read" "$d" "nothing to report" skipped

d="$(repo toolchain-markers)"
printf 'func TestX(t *testing.T) {\n\tt.Skip("flaky")\n}\n' > "$d/tests/x_test.go"
printf '#[ignore]\nfn y() {}\n' > "$d/tests/y_test.rs"
printf '@Disabled\nvoid z() {}\n' > "$d/tests/ZTest.java"
commit "$d" "three toolchains"
expect 0 "the Go, Rust, and Java markers" "$d" "3 finding(s)"

d="$(repo same-commit)"
expect 0 "base and head the same commit" "$d" "base and head are the same commit"

d="$(repo bad-base)"
expect 2 "a base that does not resolve" "$d" "does not resolve" nosuchref

d="$(repo zero-base)"
git -C "$d" rm -q tests/a_test.py
commit "$d" "drop a test"
expect 0 "a base of zeros counts as none and falls back to main, which is head" "$d" "nothing to compare" 0000000000000000000000000000000000000000

d="$(repo no-main)"
git -C "$d" branch -m main work
expect 0 "no base and no main" "$d" "no main to compare with" ""

# --- summary ---------------------------------------------------------------------------------

if ((failed)); then
  echo "Tests kept sensor self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Tests kept sensor self-test passed ($passed cases)."
exit 0
