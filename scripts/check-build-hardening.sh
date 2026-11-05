#!/usr/bin/env bash
#
# Build and release hardening check for this repository.
#
# What a shipped binary is built from, with which compiler and under which token is decided in a
# handful of files no test reads. This check reads them and fails on what would loosen it:
#
#   1. Checkout: every 'actions/checkout' step of .github/workflows/*.yml|*.yaml sets
#      'persist-credentials: false'. The token is needed to fetch the code, not afterwards; left in
#      .git/config it is readable to every later step and to every build script they run.
#   2. Release cache: .github/workflows/release.yml restores no cache ('Swatinem/rust-cache',
#      'actions/cache'). A cache is written by other runs, and what a release ships is built from
#      the sources and the lockfile alone.
#   3. Release tools: every 'cargo install' in release.yml names the version of each crate it
#      installs ('--version' or 'crate@version'), and every 'tool:' of an install action names one
#      ('tool@version').
#   4. Release gate: release.yml runs 'cargo deny … check advisories', and every job that runs
#      'git push' either runs it earlier itself or names the job that does in its 'needs:', so a
#      version with a known advisory is never tagged. Only a direct 'needs:' counts.
#   5. Compiler: rust-toolchain.toml pins 'channel' to an exact 'MAJOR.MINOR.PATCH' (ADR-0010
#      clause 11), not a moving channel name.
#   6. Release profile: Cargo.toml has a '[profile.release]' with 'overflow-checks = true'.
#   7. Unsafe code: the crate roots in FORBID_UNSAFE carry '#![forbid(unsafe_code)]'. The roots
#      not listed (the Client's library and binaries, the Server's binary) hold documented unsafe.
#
# Full-line '#' comments are not read. Pure bash + coreutils/grep/awk. Usage:
#     scripts/check-build-hardening.sh [repository root]
# The root defaults to this repository; scripts/test-check-build-hardening.sh passes fixtures.
# Exit code 0 when the check passes, 1 otherwise.

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
WORKFLOWS=".github/workflows"
RELEASE="$WORKFLOWS/release.yml"
FORBID_UNSAFE=(
  crates/opamp/src/lib.rs
  crates/fleet-core/src/lib.rs
  crates/fleet-server/src/lib.rs
  crates/fleet-tools/src/main.rs
)

errors=()
add_error() { errors+=("$1"); }

# uncommented <file> — the file with full-line comments blanked, line numbers kept.
uncommented() { sed -E 's/^[[:space:]]*#.*$//' "$1"; }

shopt -s nullglob
workflows=("$ROOT/$WORKFLOWS"/*.yml "$ROOT/$WORKFLOWS"/*.yaml)
shopt -u nullglob

# 1. Checkout. A step runs from its '- ' line to the next line indented as far or less.
checkouts=0
for wf in "${workflows[@]}"; do
  rel="${wf#"$ROOT"/}"
  while IFS= read -r hit; do
    case "$hit" in
      checkout) checkouts=$((checkouts + 1)) ;;
      *) add_error "$rel:$hit: the checkout keeps the token in .git/config — set 'persist-credentials: false' and hand the token only to the step that needs it" ;;
    esac
  done < <(uncommented "$wf" | awk '
    function flush() {
      if (in_step && is_checkout) { print "checkout"; if (!has_pc) print start }
      in_step = 0
    }
    /^[[:space:]]*$/ { next }
    {
      match($0, /^ */); ind = RLENGTH
      if (in_step && ind <= sind) flush()
      if (!in_step && $0 ~ /^ *- /) { in_step = 1; sind = ind; start = NR; is_checkout = 0; has_pc = 0 }
      if (in_step) {
        if ($0 ~ /(^|[ -])uses:[ ]*["\047]?actions\/checkout@/) is_checkout = 1
        if ($0 ~ /persist-credentials:[ ]*["\047]?false["\047]?[ ]*(#.*)?$/) has_pc = 1
      }
    }
    END { flush() }')
done

if [[ -f "$ROOT/$RELEASE" ]]; then
  release="$(uncommented "$ROOT/$RELEASE")"

  # 2. Release cache.
  while IFS= read -r hit; do
    add_error "$RELEASE:${hit%%:*}: a release restores a cache other runs wrote — build it from the sources and the lockfile alone"
  done < <(grep -nE '(^|[ -])uses:[[:space:]]*["'\'']?(Swatinem/rust-cache|actions/cache)(/[A-Za-z]+)?@' <<< "$release")

  # 3. Release tools.
  while IFS= read -r hit; do
    n="${hit%%:*}"
    args="${hit#*cargo install}"
    [[ "$args" == *--version* ]] && continue
    for word in $args; do
      [[ "$word" == -* || "$word" == *@* ]] && continue
      add_error "$RELEASE:$n: 'cargo install' takes $word at whatever version is newest — name it, '--version' or '$word@<version>'"
    done
  done < <(grep -nE 'cargo install' <<< "$release")
  while IFS= read -r hit; do
    n="${hit%%:*}"
    value="$(sed -E 's/^[^:]*:[[:space:]]*tool:[[:space:]]*//; s/[[:space:]]+#.*$//; s/[[:space:]]+$//' <<< "$hit")"
    IFS=', ' read -r -a tools <<< "$value"
    for tool in "${tools[@]}"; do
      [[ -z "$tool" || "$tool" == *@* ]] && continue
      add_error "$RELEASE:$n: the install action takes $tool at whatever version is newest — name it, '$tool@<version>'"
    done
  done < <(grep -nE '^[[:space:]]*tool:' <<< "$release")

  # 4. Release gate. Per job (a key indented two spaces under 'jobs:'): the line of its first
  # advisory check, of its first 'git push', and the jobs its 'needs:' names, inline or as a list.
  declare -A deny_at=() push_at=() needs=()
  while IFS=$'\t' read -r job kind value; do
    case "$kind" in
      deny) deny_at[$job]="${deny_at[$job]:-$value}" ;;
      push) push_at[$job]="${push_at[$job]:-$value}" ;;
      need) needs[$job]+=" $value " ;;
    esac
  done < <(awk '
    /^jobs:/ { in_jobs = 1; next }
    in_jobs && /^[^ \t]/ { in_jobs = 0 }
    !in_jobs { next }
    /^  [A-Za-z0-9_-]+:[ ]*$/ { job = $1; sub(/:$/, "", job); in_needs = 0; next }
    job == "" { next }
    /^    needs:/ {
      v = $0; sub(/^    needs:[ ]*/, "", v); gsub(/[][,"\047]/, " ", v)
      n = split(v, names, /[ ]+/); for (i = 1; i <= n; i++) if (names[i] != "") print job "\tneed\t" names[i]
      in_needs = (v ~ /^[ ]*$/); next
    }
    in_needs && /^      - / { v = $0; sub(/^      - /, "", v); gsub(/["\047 ]/, "", v); print job "\tneed\t" v; next }
    /^    [A-Za-z]/ { in_needs = 0 }
    /cargo deny .*check advisories/ { print job "\tdeny\t" NR }
    /git( .*)? push/ { print job "\tpush\t" NR }
  ' <<< "$release")
  if ((${#deny_at[@]} == 0)); then
    add_error "$RELEASE: runs no 'cargo deny check advisories' — a version with a known advisory would be tagged and released"
  fi
  for job in "${!push_at[@]}"; do
    [[ -n "${deny_at[$job]:-}" && "${deny_at[$job]}" -lt "${push_at[$job]}" ]] && continue
    gated=""
    for deny_job in "${!deny_at[@]}"; do
      [[ "${needs[$job]:-}" == *" $deny_job "* ]] && gated=yes
    done
    [[ -n "$gated" || ${#deny_at[@]} -eq 0 ]] \
      || add_error "$RELEASE:${push_at[$job]}: job '$job' pushes the tag without needing the job that runs 'cargo deny check advisories' — gate the tag on it"
  done
else
  add_error "$RELEASE: not found — the release workflow is what this check guards"
fi

# 5. Compiler.
toolchain="$ROOT/rust-toolchain.toml"
if [[ ! -f "$toolchain" ]]; then
  add_error "rust-toolchain.toml: not found — ADR-0010 clause 11 pins the compiler there"
elif ! uncommented "$toolchain" | grep -qE '^[[:space:]]*channel[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"[[:space:]]*$'; then
  add_error "rust-toolchain.toml: 'channel' is not an exact 'MAJOR.MINOR.PATCH' — a channel name moves under every build (ADR-0010 clause 11)"
fi

# 6. Release profile.
if ! uncommented "$ROOT/Cargo.toml" 2>/dev/null | awk '
    /^[[:space:]]*\[/ { in_release = ($0 ~ /^[[:space:]]*\[profile\.release\][[:space:]]*$/) }
    in_release && /^[[:space:]]*overflow-checks[[:space:]]*=[[:space:]]*true[[:space:]]*$/ { found = 1 }
    END { exit !found }'; then
  add_error "Cargo.toml: no 'overflow-checks = true' under '[profile.release]' — a release build would wrap an overflowing integer silently"
fi

# 7. Unsafe code.
for crate_root in "${FORBID_UNSAFE[@]}"; do
  if [[ ! -f "$ROOT/$crate_root" ]]; then
    add_error "$crate_root: not found — the check names the crate roots that forbid unsafe code"
  elif ! grep -qE '^#!\[forbid\(unsafe_code\)\]' "$ROOT/$crate_root"; then
    add_error "$crate_root: does not carry '#![forbid(unsafe_code)]'"
  fi
done

if ((${#errors[@]})); then
  echo "Build hardening check FAILED:" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi

echo "Build hardening check passed ($checkouts checkouts without a kept token, the release gated and uncached, the compiler pinned)."
exit 0
