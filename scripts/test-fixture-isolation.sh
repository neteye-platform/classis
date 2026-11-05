#!/usr/bin/env bash
#
# The self-tests that build throwaway git repositories leave the repository they run in alone,
# whatever git environment they inherit. A hook exports GIT_DIR, GIT_INDEX_FILE and the like; a
# self-test run from a hook, or from a shell that kept them, would otherwise point its fixture's
# 'git init', 'git config' and 'git commit' at the real repository.
#
# Each self-test runs with the repository-locating variables aimed at a sentinel repository; the
# sentinel's config, index, refs and HEAD must come out as they went in.
#
# Usage:
#     scripts/test-fixture-isolation.sh
# Exit code 0 when every self-test leaves the sentinel alone, 1 otherwise.

set -uo pipefail

# The sentinel is built and read with this run's own environment, not an inherited one.
mapfile -t git_env < <(git rev-parse --local-env-vars)
unset "${git_env[@]}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF_TESTS=(
  test-git-hooks.sh test-sensor-revision-due.sh test-sensor-tests-kept.sh test-check-docs.sh
  test-check-traceability.sh
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sentinel="$work/sentinel"
git init -q -b main "$sentinel"
git -C "$sentinel" -c user.name=s -c user.email=s@example.invalid \
  commit -q --allow-empty -m sentinel

# state — the sentinel's config, index, refs and HEAD, as one text.
state() {
  cat "$sentinel/.git/config"
  sha256sum "$sentinel/.git/index"
  git -C "$sentinel" for-each-ref --format='%(refname) %(objectname)'
  git -C "$sentinel" symbolic-ref -q HEAD || git -C "$sentinel" rev-parse HEAD
}

failed=0
for test in "${SELF_TESTS[@]}"; do
  before="$(state)"
  out="$(GIT_DIR="$sentinel/.git" GIT_WORK_TREE="$sentinel" GIT_INDEX_FILE="$sentinel/.git/index" \
    GIT_COMMON_DIR="$sentinel/.git" GIT_OBJECT_DIRECTORY="$sentinel/.git/objects" \
    bash "$ROOT/scripts/$test" 2>&1)"
  rc=$?
  after="$(state)"
  if [[ "$before" != "$after" ]]; then
    failed=1
    echo "FAIL: $test changed the repository its git environment named" >&2
    diff <(echo "$before") <(echo "$after") | sed 's/^/    /' >&2
  elif ((rc != 0)); then
    failed=1
    echo "FAIL: $test failed under an inherited git environment (exit $rc)" >&2
    while IFS= read -r l; do printf '    %s\n' "$l"; done <<< "$out" >&2
  fi
done

if ((failed)); then
  exit 1
fi
echo "Fixture isolation passed (${#SELF_TESTS[@]} self-tests)."
