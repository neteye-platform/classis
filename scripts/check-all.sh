#!/usr/bin/env bash
#
# Runs every consistency check this repository enforces, in one command.
#
# AGENTS.md §5 requires these checks to pass before pushing, and
# .github/workflows/checks.yml runs each of them as a job of its own. This script is the local
# equivalent of that workflow and lists the same checks in the same order — a check added to one
# is added to the other in the same change, or the local gate and CI drift apart and "it passed
# locally" stops meaning anything. Check 9 of check-docs.sh verifies that the two lists,
# and the required status checks named in README.md, still agree.
#
# Every check runs even after an earlier one fails, so a single run reports everything that is
# wrong instead of the first thing. The exit code is what a pre-push decision is made on.
#
# Pure bash + coreutils/git, and the Rust toolchain for scripts/check-rust.sh. The individual checks
# state their own dependencies — the shell lint needs ShellCheck and skips itself with a notice
# where it is missing.
#
# Usage:
#     scripts/check-all.sh        (or: bash scripts/check-all.sh)
# Exit code 0 when every check passes, 1 when any of them fails.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

failed=()

# announce <label> — print the heading a check's output follows.
announce() { printf '\n==> %s\n' "$1"; }

# run <label> <script> [args...] — run one check, recording a failure without aborting the run.
run() {
  local label="$1" script="$2"
  shift 2
  announce "$label"
  bash "$ROOT/$script" "$@" || failed+=("$label")
}

run "Documentation self-test" scripts/test-check-docs.sh
run "Protocol Baseline self-test" scripts/test-check-protocol-baseline.sh
run "Documentation consistency" scripts/check-docs.sh
run "Traceability self-test" scripts/test-check-traceability.sh
run "Traceability" scripts/check-traceability.sh
run "Dev Container self-test" scripts/test-check-devcontainer.sh
run "Dev Container" scripts/check-devcontainer.sh
run "Action reference self-test" scripts/test-check-action-refs.sh
run "Action references" scripts/check-action-refs.sh
run "Build hardening self-test" scripts/test-check-build-hardening.sh
run "Build hardening" scripts/check-build-hardening.sh
run "Tests-kept sensor self-test" scripts/test-sensor-tests-kept.sh
run "Tests-kept sensor" scripts/sensor-tests-kept.sh
run "Revision-due sensor self-test" scripts/test-sensor-revision-due.sh
run "Revision-due sensor" scripts/sensor-revision-due.sh
run "Git hooks self-test" scripts/test-git-hooks.sh
run "Fixture isolation" scripts/test-fixture-isolation.sh
run "Shell lint" scripts/check-shell.sh
run "Build, test and lint" scripts/check-rust.sh

printf '\n'
if ((${#failed[@]})); then
  echo "FAILED:" >&2
  printf '  - %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "All checks passed."
