#!/usr/bin/env bash
#
# Self-test of scripts/check-build-hardening.sh. Verifies: ADR-0010
#
# Each case builds a fixture under a temporary directory — a release workflow, a second workflow,
# rust-toolchain.toml, Cargo.toml and the crate roots the check names — runs the check against
# it, and asserts the exit code and, for a failing case, the message that names the violation.
# The baseline passes; every other case loosens one thing the check holds, or writes it in a form
# the check has to read like the plain one.
#
# Usage:
#     scripts/test-check-build-hardening.sh
# Exit code 0 when every case passes, 1 otherwise.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-build-hardening.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
passed=0

# release <dir> [line...] — write release.yml: an advisories job, then a version job that tags,
# then a build job whose steps are the given lines (a passing set when none are given).
release() {
  local dir="$1"; shift
  local steps=("$@")
  if ((${#steps[@]} == 0)); then
    steps=(
      "- uses: actions/checkout@v7"
      "  with:"
      "    fetch-depth: 0"
      "    persist-credentials: false"
      "- run: cargo install --locked cargo-deb@3.8.0 cargo-generate-rpm@0.21.0"
    )
  fi
  {
    echo "name: Release"
    echo "on: [workflow_dispatch]"
    echo "jobs:"
    echo "  advisories:"
    echo "    runs-on: ubuntu-latest"
    echo "    steps:"
    echo "      - uses: actions/checkout@v7"
    echo "        with:"
    echo "          persist-credentials: false"
    echo "      - uses: taiki-e/install-action@v2"
    echo "        with:"
    echo "          tool: cargo-deny@0.20.2"
    echo "      - run: cargo deny check advisories"
    echo "  version:"
    echo "    needs: advisories"
    echo "    runs-on: ubuntu-latest"
    echo "    steps:"
    echo "      - name: Tag this commit"
    echo "        run: |"
    echo "          git tag \"\$tag\""
    echo "          git push origin \"\$tag\""
    echo "  build:"
    echo "    runs-on: ubuntu-latest"
    echo "    steps:"
    printf '      %s\n' "${steps[@]}"
  } > "$dir/.github/workflows/release.yml"
}

# workflow <dir> <line...> — write checks.yml with one job whose steps are the given lines.
workflow() {
  local dir="$1"; shift
  {
    echo "name: Checks"
    echo "on: [pull_request]"
    echo "jobs:"
    echo "  docs:"
    echo "    runs-on: ubuntu-latest"
    echo "    steps:"
    printf '      %s\n' "$@"
    echo "      - run: bash scripts/check-docs.sh"
  } > "$dir/.github/workflows/checks.yml"
}

# repo <name> — a fixture that passes the check, printed as its path.
repo() {
  local dir="$work/$1" crate_root
  mkdir -p "$dir/.github/workflows"
  release "$dir"
  workflow "$dir" "- uses: actions/checkout@v7" "  with:" "    persist-credentials: false"
  printf '[toolchain]\nchannel = "1.99.0"\ncomponents = ["rustfmt", "clippy"]\n' > "$dir/rust-toolchain.toml"
  printf '[workspace]\nresolver = "2"\n\n[profile.release]\noverflow-checks = true\n' > "$dir/Cargo.toml"
  for crate_root in crates/opamp/src/lib.rs crates/fleet-core/src/lib.rs \
                    crates/fleet-server/src/lib.rs crates/fleet-tools/src/main.rs; do
    mkdir -p "$dir/$(dirname "$crate_root")"
    printf '//! A crate.\n\n#![forbid(unsafe_code)]\n\npub mod a;\n' > "$dir/$crate_root"
  done
  echo "$dir"
}

# expect <pass|fail> <name> <dir> [needle] — run the check; when a needle is given, its output
# must contain it.
expect() {
  local want="$1" name="$2" dir="$3" needle="${4:-}"
  local out rc
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

d="$(repo baseline)"
expect pass "everything held" "$d" "3 checkouts without a kept token"

# --- 1. checkout ------------------------------------------------------------------------------

d="$(repo checkout-keeps-token)"
workflow "$d" "- uses: actions/checkout@v7"
expect fail "a checkout without persist-credentials" "$d" "checks.yml:7: the checkout keeps the token"

d="$(repo checkout-true)"
workflow "$d" "- uses: actions/checkout@v7" "  with:" "    persist-credentials: true"
expect fail "persist-credentials: true" "$d" "the checkout keeps the token"

d="$(repo checkout-commented)"
workflow "$d" "- uses: actions/checkout@v7" "  with:" "    # persist-credentials: false"
expect fail "persist-credentials only in a comment" "$d" "the checkout keeps the token"

d="$(repo checkout-keyed-form)"
workflow "$d" "- name: Check out" "  uses: actions/checkout@v7" "  with:" "    persist-credentials: false"
expect pass "a checkout written after a name key" "$d" "3 checkouts"

d="$(repo checkout-next-step)"
workflow "$d" "- uses: actions/checkout@v7" "- uses: other/action@v1" "  with:" "    persist-credentials: false"
expect fail "persist-credentials on the next step does not count" "$d" "the checkout keeps the token"

d="$(repo checkout-quoted)"
workflow "$d" "- uses: actions/checkout@v7" "  with:" "    persist-credentials: 'false'"
expect pass "the value in quotes" "$d" "3 checkouts"

# --- 2. release cache -------------------------------------------------------------------------

d="$(repo release-rust-cache)"
release "$d" "- uses: Swatinem/rust-cache@v2"
expect fail "rust-cache in the release" "$d" "a release restores a cache"

d="$(repo release-actions-cache)"
release "$d" "- name: Cache" "  uses: actions/cache/restore@v4"
expect fail "actions/cache in the release" "$d" "a release restores a cache"

d="$(repo cache-elsewhere)"
workflow "$d" "- uses: actions/checkout@v7" "  with:" "    persist-credentials: false" "- uses: Swatinem/rust-cache@v2"
expect pass "a cache outside the release is not this check's" "$d"

# --- 3. release tools -------------------------------------------------------------------------

d="$(repo install-unpinned)"
release "$d" "- run: cargo install cargo-deb cargo-generate-rpm --locked"
expect fail "cargo install without versions" "$d" "takes cargo-deb at whatever version"

d="$(repo install-half-pinned)"
release "$d" "- run: cargo install --locked cargo-deb@3.8.0 cargo-generate-rpm"
expect fail "one crate pinned, one not" "$d" "takes cargo-generate-rpm at whatever version"

d="$(repo install-version-flag)"
release "$d" "- run: cargo install cargo-deb --version 3.8.0 --locked"
expect pass "--version" "$d"

d="$(repo install-action-unpinned)"
release "$d" "- uses: taiki-e/install-action@v2" "  with:" "    tool: cargo-deny"
expect fail "an install action without a version" "$d" "the install action takes cargo-deny"

# --- 4. release gate --------------------------------------------------------------------------

d="$(repo no-gate)"
sed -i '/cargo deny check advisories/d' "$d/.github/workflows/release.yml"
expect fail "no advisory check" "$d" "runs no 'cargo deny check advisories'"

d="$(repo gate-after-tag)"
sed -i '/cargo deny check advisories/d' "$d/.github/workflows/release.yml"
printf '      - run: cargo deny check advisories\n' >> "$d/.github/workflows/release.yml"
expect fail "the advisory check in a job the tag push does not need" "$d" "pushes the tag without needing"

d="$(repo needs-dropped)"
sed -i '/needs: advisories/d' "$d/.github/workflows/release.yml"
expect fail "the tagging job no longer needs the advisory job" "$d" "job 'version' pushes the tag without needing"

d="$(repo needs-other)"
sed -i 's/needs: advisories/needs: build/' "$d/.github/workflows/release.yml"
expect fail "the tagging job needs another job" "$d" "pushes the tag without needing"

d="$(repo needs-inline-list)"
sed -i 's/needs: advisories/needs: [lint, advisories]/' "$d/.github/workflows/release.yml"
expect pass "needs as an inline list" "$d"

d="$(repo needs-block-list)"
sed -i 's/needs: advisories/needs:\n      - lint\n      - advisories/' "$d/.github/workflows/release.yml"
expect pass "needs as a block list" "$d"

d="$(repo gate-in-same-job)"
sed -i '/needs: advisories/d; s/^      - name: Tag this commit$/      - run: cargo deny check advisories\n      - name: Tag this commit/' "$d/.github/workflows/release.yml"
expect pass "the advisory check earlier in the tagging job itself" "$d"

d="$(repo gate-after-push-same-job)"
sed -i '/needs: advisories/d; s/^          git push origin .*$/&\n      - run: cargo deny check advisories/' "$d/.github/workflows/release.yml"
expect fail "the advisory check after the push in the same job" "$d" "pushes the tag without needing"

d="$(repo no-release)"
rm "$d/.github/workflows/release.yml"
expect fail "no release workflow" "$d" "release.yml: not found"

# --- 5. compiler ------------------------------------------------------------------------------

d="$(repo channel-stable)"
sed -i 's/"1.99.0"/"stable"/' "$d/rust-toolchain.toml"
expect fail "a channel name" "$d" "rust-toolchain.toml: 'channel' is not an exact"

d="$(repo channel-minor)"
sed -i 's/"1.99.0"/"1.99"/' "$d/rust-toolchain.toml"
expect fail "a minor version only" "$d" "rust-toolchain.toml: 'channel' is not an exact"

d="$(repo no-toolchain)"
rm "$d/rust-toolchain.toml"
expect fail "no rust-toolchain.toml" "$d" "rust-toolchain.toml: not found"

# --- 6. release profile -----------------------------------------------------------------------

d="$(repo no-overflow)"
printf '[workspace]\nresolver = "2"\n' > "$d/Cargo.toml"
expect fail "no release profile" "$d" "no 'overflow-checks = true'"

d="$(repo overflow-elsewhere)"
printf '[profile.dev]\noverflow-checks = true\n\n[profile.release]\nlto = false\n' > "$d/Cargo.toml"
expect fail "overflow checks under another profile" "$d" "no 'overflow-checks = true'"

d="$(repo overflow-false)"
printf '[profile.release]\noverflow-checks = false\n' > "$d/Cargo.toml"
expect fail "overflow checks off" "$d" "no 'overflow-checks = true'"

# --- 7. unsafe code ---------------------------------------------------------------------------

d="$(repo unsafe-allowed)"
printf '//! A crate.\n\npub mod a;\n' > "$d/crates/fleet-core/src/lib.rs"
expect fail "a crate root without the attribute" "$d" "crates/fleet-core/src/lib.rs: does not carry"

d="$(repo unsafe-commented)"
printf '//! A crate.\n\n// #![forbid(unsafe_code)]\n' > "$d/crates/opamp/src/lib.rs"
expect fail "the attribute in a comment" "$d" "crates/opamp/src/lib.rs: does not carry"

d="$(repo crate-root-gone)"
rm "$d/crates/fleet-tools/src/main.rs"
expect fail "a named crate root missing" "$d" "crates/fleet-tools/src/main.rs: not found"

# --- summary ----------------------------------------------------------------------------------

if ((failed)); then
  echo "Build hardening self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Build hardening self-test passed ($passed cases)."
exit 0
