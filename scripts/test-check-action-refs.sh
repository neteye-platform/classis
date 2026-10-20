#!/usr/bin/env bash
#
# Self-test of scripts/check-action-refs.sh. Verifies: ADR-0044
#
# Each case builds a fixture under a temporary directory — one workflow with one 'uses:' line and
# a dependabot.yml with the github-actions ecosystem — runs the check against it, and asserts the
# exit code and, for a failing case, the message that names the violation. The baseline passes;
# every other case breaks one thing ADR-0044 decides, or writes a reference in a form the check
# has to read like the plain one.
#
# Usage:
#     scripts/test-check-action-refs.sh
# Exit code 0 when every case passes, 1 otherwise.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-action-refs.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
passed=0

# The stub git answers 'git … ls-remote <url> <ref>…' from $work/bin/remotes, lines of
# '<url> <sha> <ref>', printing the lines of that URL whose ref was asked for, as git does. A URL
# listed as '<url> unreachable' fails as an unreachable remote does. Every call is logged to
# $work/bin/calls, one line per URL.
S=6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # the commit an annotated tag peels to
T=63fed3e2fecf6f7b51dc6f043341b79ef82a9ae7 # that tag's own object ID
L=8cca0918f8471c33515202b73f56ab27f2bed283 # the commit a lightweight tag points to
O=1111111111111111111111111111111111111111 # a commit no tag names
mkdir -p "$work/bin"
cat > "$work/bin/git" <<'EOF'
#!/usr/bin/env bash
dir="$(dirname "$0")"
while [[ "${1:-}" == -c ]]; do shift 2; done
[[ "${1:-}" == ls-remote ]] || { echo "stub git: unexpected call: $*" >&2; exit 2; }
url="$2"; shift 2
echo "$url" >> "$dir/calls"
if grep -qxF "$url unreachable" "$dir/remotes"; then
  echo "fatal: unable to access '$url/': Could not resolve host" >&2
  exit 128
fi
while read -r u sha ref; do
  [[ "$u" == "$url" ]] || continue
  for want in "$@"; do [[ "$ref" == "$want" ]] && printf '%s\t%s\n' "$sha" "$ref"; done
done < "$dir/remotes"
exit 0
EOF
chmod +x "$work/bin/git"
cat > "$work/bin/remotes" <<EOF
https://github.com/owner/light $L refs/tags/v1.0.0
https://github.com/owner/annotated $T refs/tags/v2.9.2
https://github.com/owner/annotated $S refs/tags/v2.9.2^{}
https://github.com/owner/moved $O refs/tags/v1.0.0
https://github.com/owner/gone unreachable
EOF
: > "$work/bin/calls"

# workflow <dir> <uses line...> — write checks.yml with one job whose steps are the given lines.
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

# dependabot <dir> <ecosystem line> — write dependabot.yml with one update entry.
dependabot() {
  local dir="$1" ecosystem="$2"
  {
    echo "# Keeps the actions current (a comment the check does not read)."
    echo "version: 2"
    echo "updates:"
    echo "  $ecosystem"
    echo "    directory: /"
    echo "    schedule:"
    echo "      interval: monthly"
  } > "$dir/.github/dependabot.yml"
}

# repo <name> — a fixture that passes the check, printed as its path.
repo() {
  local dir="$work/$1"
  mkdir -p "$dir/.github/workflows"
  workflow "$dir" "- uses: actions/checkout@v7"
  dependabot "$dir" "- package-ecosystem: github-actions"
  echo "$dir"
}

# expect <pass|fail> <name> <dir> [needle] — run the check; when a needle is given, its output
# must contain it. The flags in CHECK_FLAGS are passed before the root, and the stub git under
# $work/bin is first on PATH, so no case reaches the network.
CHECK_FLAGS=()
expect() {
  local want="$1" name="$2" dir="$3" needle="${4:-}"
  local out rc
  out="$(PATH="$work/bin:$PATH" bash "$CHECK" "${CHECK_FLAGS[@]}" "$dir" 2>&1)"; rc=$?
  if [[ "$want" == "pass" && $rc -eq 0 && ( -z "$needle" || "$out" == *"$needle"* ) ]] \
     || [[ "$want" == "fail" && $rc -ne 0 && ( -z "$needle" || "$out" == *"$needle"* ) ]]; then
    passed=$((passed + 1))
    return
  fi
  failed=$((failed + 1))
  echo "FAIL: $name (expected $want${needle:+ with needle \"$needle\"}, exit $rc)" >&2
  while IFS= read -r l; do printf '    %s\n' "$l"; done <<< "$out" >&2
}

# --- cases: references ------------------------------------------------------------------------

d="$(repo baseline)"
expect pass "an action on its major version tag, Dependabot configured" "$d" "1 references: 1 first-party on major tags, 0 third-party"

d="$(repo sha)"
workflow "$d" "- uses: actions/checkout@0e58ed8671d6b60d0890c21b07f8835ace038e67 # v7.0.1"
expect fail "a first-party action on a commit SHA" "$d" "is first-party"

d="$(repo branch)"
workflow "$d" "- uses: actions/checkout@main"
expect fail "a branch" "$d" "is first-party"

d="$(repo full-version)"
workflow "$d" "- uses: actions/checkout@v7.0.1"
expect fail "a full version tag" "$d" "is first-party"

d="$(repo untagged)"
workflow "$d" "- uses: actions/checkout"
expect fail "no ref at all" "$d" "names no ref"

d="$(repo action-in-subdirectory)"
workflow "$d" "- uses: actions/cache/restore@v4"
expect pass "a first-party action inside a repository, on its major tag" "$d" "1 first-party on major tags"

d="$(repo local-action)"
workflow "$d" "- uses: ./.github/actions/setup"
expect pass "a local action is exempt" "$d" "1 references"

d="$(repo docker-tagged)"
workflow "$d" "- uses: docker://alpine:3.20"
expect pass "a docker image with a tag" "$d" "1 references"

d="$(repo docker-untagged)"
workflow "$d" "- uses: docker://alpine"
expect fail "a docker image without a tag" "$d" "carries no tag"

d="$(repo docker-registry-port)"
workflow "$d" "- uses: docker://registry.example:5000/tools/image"
expect fail "a docker image on a registry with a port, without a tag" "$d" "carries no tag"

d="$(repo docker-registry-port-tagged)"
workflow "$d" "- uses: docker://registry.example:5000/tools/image:1.2"
expect pass "a docker image on a registry with a port, with a tag" "$d" "1 references"

d="$(repo commented-out)"
workflow "$d" "# - uses: actions/checkout@main" "- uses: actions/checkout@v7"
expect pass "a commented-out reference is not read" "$d" "1 references"

d="$(repo trailing-comment)"
workflow "$d" "- uses: actions/checkout@v7 # the major tag, ADR-0044"
expect pass "a trailing comment after the reference" "$d" "1 references"

d="$(repo quoted)"
workflow "$d" "- uses: \"actions/checkout@v7\""
expect pass "a quoted reference" "$d" "1 references"

d="$(repo keyed-form)"
workflow "$d" "- name: Check out" "  uses: actions/checkout@v7"
expect pass "a reference written after a name key, not as the list item" "$d" "1 references"

d="$(repo keyed-form-branch)"
workflow "$d" "- name: Check out" "  uses: actions/checkout@main"
expect fail "the same form on a branch" "$d" "is first-party"

d="$(repo two-workflows)"
cp "$d/.github/workflows/checks.yml" "$d/.github/workflows/nightly.yaml"
workflow "$d" "- uses: actions/checkout@v7"
expect pass "a second workflow with a .yaml extension is read" "$d" "2 references"

d="$(repo no-workflows)"
rm -r "$d/.github/workflows"
expect fail "no workflow at all" "$d" "no workflow found"

# --- cases: third-party references ------------------------------------------------------------

d="$(repo third-party-pinned)"
workflow "$d" "- uses: Swatinem/rust-cache@$S # v2.9.2"
expect pass "a third-party action on a SHA with its release in a comment" "$d" "1 references: 0 first-party on major tags, 1 third-party on commit SHAs; Dependabot"

d="$(repo third-party-tag)"
workflow "$d" "- uses: Swatinem/rust-cache@v2"
expect fail "a third-party action on its major tag" "$d" "is a third-party action not pinned to a full commit SHA"

d="$(repo third-party-full-version)"
workflow "$d" "- uses: Swatinem/rust-cache@v2.9.2"
expect fail "a third-party action on a full version tag" "$d" "(ADR-0044 clause 3)"

d="$(repo third-party-no-ref)"
workflow "$d" "- uses: Swatinem/rust-cache"
expect fail "a third-party action with no ref" "$d" "is a third-party action not pinned to a full commit SHA"

d="$(repo third-party-no-comment)"
workflow "$d" "- uses: Swatinem/rust-cache@$S"
expect fail "a SHA without the release comment" "$d" "not '# vX.Y.Z'"

d="$(repo third-party-major-comment)"
workflow "$d" "- uses: Swatinem/rust-cache@$S # v2"
expect fail "a SHA whose comment names only a major" "$d" "carries '# v2', not '# vX.Y.Z'"

d="$(repo third-party-unprefixed-comment)"
workflow "$d" "- uses: Swatinem/rust-cache@$S # 2.9.2"
expect fail "a SHA whose comment has no leading v" "$d" "(ADR-0044 clause 3)"

d="$(repo third-party-short-sha)"
workflow "$d" "- uses: Swatinem/rust-cache@6323deb # v2.9.2"
expect fail "a short SHA" "$d" "is a third-party action not pinned to a full commit SHA"

d="$(repo third-party-uppercase-sha)"
workflow "$d" "- uses: Swatinem/rust-cache@${S^^} # v2.9.2"
expect fail "an uppercase SHA" "$d" "is a third-party action not pinned to a full commit SHA"

d="$(repo github-owner)"
workflow "$d" "- uses: github/codeql-action/init@v3"
expect fail "an action owned by github is third-party" "$d" "is a third-party action not pinned to a full commit SHA"

d="$(repo third-party-in-subdirectory)"
workflow "$d" "- uses: owner/repo/path/to/action@$S # v1.2.3"
expect pass "a third-party action inside a repository, pinned" "$d" "1 third-party on commit SHAs"

d="$(repo third-party-quoted)"
workflow "$d" "- uses: \"owner/a@$S\" # v1.2.3"
expect pass "a quoted third-party reference with its comment" "$d" "1 third-party on commit SHAs"

d="$(repo reusable-workflow)"
{
  echo "name: Checks"
  echo "on: [pull_request]"
  echo "jobs:"
  echo "  call:"
  echo "    uses: owner/repo/.github/workflows/w.yml@$S # v1.2.3"
  echo "  call-tagged:"
  echo "    uses: owner/repo/.github/workflows/w.yml@v1"
} > "$d/.github/workflows/checks.yml"
expect fail "a reusable workflow is classified as an action is" "$d" "'owner/repo/.github/workflows/w.yml@v1' is a third-party action"
sed -i '/call-tagged/,$d' "$d/.github/workflows/checks.yml"
expect pass "a pinned reusable workflow as a job-level key" "$d" "1 third-party on commit SHAs"

d="$(repo offline-does-not-resolve)"
workflow "$d" "- uses: owner/moved@$S # v1.0.0"
: > "$work/bin/calls"
expect pass "without --resolve no tag is looked up" "$d" "1 third-party on commit SHAs; Dependabot"
[[ -s "$work/bin/calls" ]] && { failed=$((failed + 1)); echo "FAIL: the offline run called git ls-remote" >&2; }

# --- cases: --resolve (stub git) --------------------------------------------------------------

CHECK_FLAGS=(--resolve)

d="$(repo resolve-lightweight)"
workflow "$d" "- uses: owner/light@$L # v1.0.0"
expect pass "a lightweight tag that points to the pinned commit" "$d" "third-party on commit SHAs, resolved"

d="$(repo resolve-annotated)"
workflow "$d" "- uses: owner/annotated@$S # v2.9.2" "- uses: owner/annotated/sub/action@$S # v2.9.2"
: > "$work/bin/calls"
expect pass "an annotated tag whose peeled commit is the pinned one, inside a repository too" "$d" "2 third-party on commit SHAs, resolved"
[[ "$(wc -l < "$work/bin/calls")" -eq 1 ]] \
  || { failed=$((failed + 1)); echo "FAIL: one repository and tag was looked up $(wc -l < "$work/bin/calls") times, not once" >&2; }

d="$(repo resolve-tag-object)"
workflow "$d" "- uses: owner/annotated@$T # v2.9.2"
expect fail "the tag object's own ID pinned in place of its commit" "$d" "tag v2.9.2 of owner/annotated is $S, not the pinned commit (ADR-0044 clause 4)"

d="$(repo resolve-moved)"
workflow "$d" "- uses: owner/moved@$S # v1.0.0"
expect fail "a tag that points to another commit" "$d" "tag v1.0.0 of owner/moved is $O, not the pinned commit"

d="$(repo resolve-missing)"
workflow "$d" "- uses: owner/light@$L # v9.9.9"
expect fail "a commented tag that does not exist" "$d" "tag v9.9.9 of owner/light is missing, not the pinned commit"

d="$(repo resolve-unreachable)"
workflow "$d" "- uses: owner/gone@$S # v1.0.0"
expect fail "a repository that cannot be reached" "$d" "git ls-remote of owner/gone failed"

d="$(repo resolve-first-party)"
: > "$work/bin/calls"
expect pass "a first-party action is not looked up" "$d" "1 first-party on major tags, 0 third-party on commit SHAs, resolved"
[[ -s "$work/bin/calls" ]] && { failed=$((failed + 1)); echo "FAIL: a first-party action was looked up" >&2; }

CHECK_FLAGS=()

# --- cases: Dependabot ------------------------------------------------------------------------

d="$(repo dependabot-missing)"
rm "$d/.github/dependabot.yml"
expect fail "no dependabot.yml" "$d" "dependabot.yml: not found"

d="$(repo dependabot-other-ecosystem)"
dependabot "$d" "- package-ecosystem: npm"
expect fail "a dependabot.yml without the github-actions ecosystem" "$d" "has no 'package-ecosystem: github-actions' entry"

d="$(repo dependabot-commented)"
dependabot "$d" "# - package-ecosystem: github-actions"
expect fail "the github-actions ecosystem only in a comment" "$d" "has no 'package-ecosystem: github-actions' entry"

d="$(repo dependabot-quoted)"
dependabot "$d" "- package-ecosystem: \"github-actions\""
expect pass "the ecosystem value in quotes" "$d" "Dependabot configured"

# --- summary ----------------------------------------------------------------------------------

if ((failed)); then
  echo "Action reference self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Action reference self-test passed ($passed cases)."
exit 0
