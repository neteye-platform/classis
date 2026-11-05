#!/usr/bin/env bash
#
# Shell lint for this repository.
#
# Runs ShellCheck over every shell script in the repository: every '*.sh' file, the git hooks
# under .githooks/, which git requires to be named without an extension, and the Linux packages'
# maintainer scripts under packaging/linux/, which run as root inside every `apt` and `dnf`
# transaction. Their `#!/bin/sh` line makes ShellCheck hold them to POSIX sh. The scripts under
# scripts/ and the hooks are the repository's entire enforcement layer, so they are held to a
# lint gate themselves.
#
# ShellCheck is the one check dependency beyond bash + coreutils/find. CI does not install it — the
# GitHub-hosted runner image ships it preinstalled. Locally, when shellcheck is not on PATH, the
# check skips itself with a notice instead of failing (CI remains the enforcing gate); in a CI
# run (CI=true) a missing shellcheck is an error, never a silent skip.
#
# Usage:
#     scripts/check-shell.sh        (or: bash scripts/check-shell.sh)
# Exit code 0 when all scripts pass (or shellcheck is unavailable outside CI), 1 otherwise.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v shellcheck >/dev/null 2>&1; then
  if [[ "${CI:-}" == "true" ]]; then
    echo "ERROR: shellcheck not found in a CI run — the runner image is expected to ship it." >&2
    exit 1
  fi
  echo "shellcheck is not installed — skipped (CI enforces this check)."
  echo "Install it to run locally: https://www.shellcheck.net"
  exit 0
fi

scripts=()
while IFS= read -r f; do scripts+=("$f"); done \
  < <(find "$ROOT" -type f \( -name '*.sh' -o -path "$ROOT/.githooks/*" -o -path "$ROOT/packaging/linux/*" \) -not -path '*/.git/*' | sort)

if ((${#scripts[@]} == 0)); then
  echo "No shell scripts found."
  exit 0
fi

if ! shellcheck "${scripts[@]}"; then
  echo
  echo "Shell lint FAILED (see findings above)."
  exit 1
fi

echo "Shell lint passed (${#scripts[@]} scripts)."
exit 0
