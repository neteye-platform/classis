#!/usr/bin/env bash
#
# Self-test of scripts/check-action-refs.sh. Verifies: ADR-0049
#
# Each case builds a fixture under a temporary directory — one workflow with one 'uses:' line and
# a renovate.json that extends the organisation preset and carries the cargo rule — runs the check
# against it, and asserts the exit code and, for a failing case, the message that names the
# violation. The baseline passes; every other case breaks one thing ADR-0049 decides, or writes a
# reference in a form the check has to read like the plain one.
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

# The stub git answers from two files under $work/bin, and logs every remote it is asked about to
# $work/bin/calls, one line per URL:
# - 'ls-remote <url> <ref>…' from remotes, lines of '<url> <sha> <ref>': it prints the lines of
#   that URL whose ref was asked for, as git does. A URL listed as '<url> unreachable' fails as an
#   unreachable remote does.
# - 'init --bare <dir>', then '-C <dir> fetch … <url> refs/heads/<b>:…': the fetch succeeds when
#   remotes lists refs/heads/<b> for that URL, and records the URL and branch in <dir>.
# - '-C <dir> merge-base --is-ancestor <sha> refs/heads/<b>': succeeds when branches, lines of
#   '<url> <branch> <sha>', lists that commit on the branch <dir> was fetched from.
S=6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # the commit an annotated tag peels to
T=63fed3e2fecf6f7b51dc6f043341b79ef82a9ae7 # that tag's own object ID
L=8cca0918f8471c33515202b73f56ab27f2bed283 # the commit a lightweight tag points to
O=1111111111111111111111111111111111111111 # a commit no tag names
C=3d3c42e5aac5ba805825da76410c181273ba90b1 # the commit of actions/checkout's v7.0.1
H=0a794cd86afd0dbc3762088170e51988740fb8d4 # a branch head
A=2222222222222222222222222222222222222222 # an ancestor of that head
mkdir -p "$work/bin"
cat > "$work/bin/git" <<'EOF'
#!/usr/bin/env bash
bin="$(dirname "$0")"
while [[ "${1:-}" == -c ]]; do shift 2; done
repo=""
if [[ "${1:-}" == -C ]]; then repo="$2"; shift 2; fi
case "${1:-}" in
  ls-remote)
    url="$2"; shift 2
    echo "$url" >> "$bin/calls"
    if grep -qxF "$url unreachable" "$bin/remotes"; then
      echo "fatal: unable to access '$url/': Could not resolve host" >&2
      exit 128
    fi
    while read -r u sha ref; do
      [[ "$u" == "$url" ]] || continue
      for want in "$@"; do [[ "$ref" == "$want" ]] && printf '%s\t%s\n' "$sha" "$ref"; done
    done < "$bin/remotes"
    exit 0
    ;;
  init)
    mkdir -p "${!#}"
    exit 0
    ;;
  fetch)
    args=("$@"); n=${#args[@]}
    url="${args[n - 2]}"; spec="${args[n - 1]}"; branch="${spec%%:*}"; branch="${branch#refs/heads/}"
    echo "$url" >> "$bin/calls"
    if grep -qxF "$url unreachable" "$bin/remotes"; then
      echo "fatal: unable to access '$url/': Could not resolve host" >&2
      exit 128
    fi
    if ! awk -v u="$url" -v r="refs/heads/$branch" '$1 == u && $3 == r { f = 1 } END { exit !f }' "$bin/remotes"; then
      echo "fatal: couldn't find remote ref refs/heads/$branch" >&2
      exit 128
    fi
    echo "$url $branch" > "$repo/fetched"
    exit 0
    ;;
  merge-base)
    sha="$3"
    read -r url branch < "$repo/fetched"
    grep -qxF "$url $branch $sha" "$bin/branches"
    exit
    ;;
esac
echo "stub git: unexpected call: $*" >&2
exit 2
EOF
chmod +x "$work/bin/git"
cat > "$work/bin/remotes" <<EOF
https://github.com/owner/light $L refs/tags/v1.0.0
https://github.com/owner/annotated $T refs/tags/v2.9.2
https://github.com/owner/annotated $S refs/tags/v2.9.2^{}
https://github.com/owner/moved $O refs/tags/v1.0.0
https://github.com/owner/gone unreachable
https://github.com/actions/checkout $C refs/tags/v7.0.1
https://github.com/neteye-platform/repo-commons $H refs/heads/main
https://github.com/neteye-platform/gone unreachable
EOF
cat > "$work/bin/branches" <<EOF
https://github.com/neteye-platform/repo-commons main $H
https://github.com/neteye-platform/repo-commons main $A
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

# renovate <dir> [extends] [rule…] — write renovate.json extending the given preset (the
# organisation's by default) with the given packageRules entries (the cargo rule by default).
CARGO_RULE='{ "matchManagers": ["cargo"], "rangeStrategy": "update-lockfile" }'
renovate() {
  local dir="$1" extends="${2:-github>neteye-platform/repo-commons}"; shift 2 2>/dev/null || shift
  local rules=("$@")
  ((${#rules[@]})) || rules=("$CARGO_RULE")
  {
    echo "{"
    echo "  \"\$schema\": \"https://docs.renovatebot.com/renovate-schema.json\","
    echo "  \"extends\": [\"$extends\"],"
    echo "  \"packageRules\": ["
    local i
    for i in "${!rules[@]}"; do
      printf '    %s%s\n' "${rules[i]}" "$( ((i + 1 < ${#rules[@]})) && echo ,)"
    done
    echo "  ]"
    echo "}"
  } > "$dir/renovate.json"
}

# repo <name> — a fixture that passes the check, printed as its path.
repo() {
  local dir="$work/$1"
  mkdir -p "$dir/.github/workflows"
  workflow "$dir" "- uses: actions/checkout@$C # v7.0.1"
  renovate "$dir"
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
expect pass "a first-party action on a SHA with its release in a comment, Renovate configured" "$d" "1 references, 1 on commit SHAs; Renovate configured"

d="$(repo first-party-major-tag)"
workflow "$d" "- uses: actions/checkout@v7"
expect fail "a first-party action on its major tag" "$d" "'actions/checkout@v7' is not pinned to a full commit SHA — pin it to the 40-character lowercase SHA and name its ref in a comment, 'owner/action@<sha> # vX.Y.Z' (ADR-0049 clause 1)"

d="$(repo branch)"
workflow "$d" "- uses: actions/checkout@main"
expect fail "a branch" "$d" "is not pinned to a full commit SHA"

d="$(repo full-version)"
workflow "$d" "- uses: actions/checkout@v7.0.1"
expect fail "a full version tag" "$d" "is not pinned to a full commit SHA"

d="$(repo untagged)"
workflow "$d" "- uses: actions/checkout"
expect fail "no ref at all" "$d" "is not pinned to a full commit SHA"

d="$(repo third-party-pinned)"
workflow "$d" "- uses: Swatinem/rust-cache@$S # v2.9.2"
expect pass "a third-party action on a SHA with its release in a comment" "$d" "1 on commit SHAs"

d="$(repo third-party-tag)"
workflow "$d" "- uses: Swatinem/rust-cache@v2"
expect fail "a third-party action on its major tag" "$d" "is not pinned to a full commit SHA"

d="$(repo no-comment)"
workflow "$d" "- uses: Swatinem/rust-cache@$S"
expect fail "a SHA without the release comment" "$d" "not '# vX.Y.Z'"

d="$(repo major-comment)"
workflow "$d" "- uses: Swatinem/rust-cache@$S # v2"
expect fail "a SHA whose comment names only a major" "$d" "carries '# v2', not '# vX.Y.Z'"

d="$(repo unprefixed-comment)"
workflow "$d" "- uses: Swatinem/rust-cache@$S # 2.9.2"
expect fail "a SHA whose comment has no leading v" "$d" "(ADR-0049 clause 2)"

d="$(repo short-sha)"
workflow "$d" "- uses: Swatinem/rust-cache@6323deb # v2.9.2"
expect fail "a short SHA" "$d" "is not pinned to a full commit SHA"

d="$(repo uppercase-sha)"
workflow "$d" "- uses: Swatinem/rust-cache@${S^^} # v2.9.2"
expect fail "an uppercase SHA" "$d" "is not pinned to a full commit SHA"

d="$(repo github-owner)"
workflow "$d" "- uses: github/codeql-action/init@v3"
expect fail "an action owned by github on a tag" "$d" "is not pinned to a full commit SHA"

d="$(repo in-subdirectory)"
workflow "$d" "- uses: actions/cache/restore@$S # v4.2.0" "- uses: owner/repo/path/to/action@$S # v1.2.3"
expect pass "actions inside a repository, pinned" "$d" "2 references, 2 on commit SHAs"

d="$(repo org-branch)"
workflow "$d" "- uses: neteye-platform/repo-commons/.github/actions/setup@$H # main"
expect pass "an action of the organisation on a SHA with its branch in a comment" "$d" "1 on commit SHAs"

d="$(repo other-owner-branch)"
workflow "$d" "- uses: other/repo@$S # main"
expect fail "a branch comment for an owner outside the organisation" "$d" "carries '# main', not '# vX.Y.Z' — end the line in a comment naming the release tag the SHA was taken from, as three numbers; only an owner of neteye-platform may name a branch (ADR-0049 clause 2)"

d="$(repo org-owner-prefix)"
workflow "$d" "- uses: neteye-platform-fork/repo@$S # main"
expect fail "an owner that only starts with the organisation's name" "$d" "only an owner of neteye-platform may name a branch"

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
workflow "$d" "# - uses: actions/checkout@main" "- uses: actions/checkout@$C # v7.0.1"
expect pass "a commented-out reference is not read" "$d" "1 references"

d="$(repo quoted)"
workflow "$d" "- uses: \"actions/checkout@$C\" # v7.0.1"
expect pass "a quoted reference with its comment" "$d" "1 on commit SHAs"

d="$(repo keyed-form)"
workflow "$d" "- name: Check out" "  uses: actions/checkout@$C # v7.0.1"
expect pass "a reference written after a name key, not as the list item" "$d" "1 references"

d="$(repo keyed-form-branch)"
workflow "$d" "- name: Check out" "  uses: actions/checkout@main"
expect fail "the same form on a branch" "$d" "is not pinned to a full commit SHA"

d="$(repo two-workflows)"
cp "$d/.github/workflows/checks.yml" "$d/.github/workflows/nightly.yaml"
expect pass "a second workflow with a .yaml extension is read" "$d" "2 references"

d="$(repo no-workflows)"
rm -r "$d/.github/workflows"
expect fail "no workflow at all" "$d" "no workflow found"

d="$(repo reusable-workflow)"
{
  echo "name: Checks"
  echo "on: [pull_request]"
  echo "jobs:"
  echo "  call:"
  echo "    uses: neteye-platform/repo-commons/.github/workflows/w.yaml@$H # main"
  echo "  call-tagged:"
  echo "    uses: owner/repo/.github/workflows/w.yml@v1"
} > "$d/.github/workflows/checks.yml"
expect fail "a reusable workflow is read as an action is" "$d" "'owner/repo/.github/workflows/w.yml@v1' is not pinned"
sed -i '/call-tagged/,$d' "$d/.github/workflows/checks.yml"
expect pass "a pinned reusable workflow of the organisation as a job-level key" "$d" "1 on commit SHAs"

d="$(repo offline-does-not-resolve)"
workflow "$d" "- uses: owner/moved@$S # v1.0.0" "- uses: neteye-platform/repo-commons@$O # main"
: > "$work/bin/calls"
expect pass "without --resolve no ref is looked up" "$d" "2 on commit SHAs; Renovate"
[[ -s "$work/bin/calls" ]] && { failed=$((failed + 1)); echo "FAIL: the offline run called git" >&2; }

# --- cases: --resolve (stub git) --------------------------------------------------------------

CHECK_FLAGS=(--resolve)

d="$(repo resolve-first-party)"
expect pass "a first-party action whose tag points to the pinned commit" "$d" "1 on commit SHAs, resolved"

d="$(repo resolve-lightweight)"
workflow "$d" "- uses: owner/light@$L # v1.0.0"
expect pass "a lightweight tag that points to the pinned commit" "$d" "on commit SHAs, resolved"

d="$(repo resolve-annotated)"
workflow "$d" "- uses: owner/annotated@$S # v2.9.2" "- uses: owner/annotated/sub/action@$S # v2.9.2"
: > "$work/bin/calls"
expect pass "an annotated tag whose peeled commit is the pinned one, inside a repository too" "$d" "2 on commit SHAs, resolved"
[[ "$(wc -l < "$work/bin/calls")" -eq 1 ]] \
  || { failed=$((failed + 1)); echo "FAIL: one repository and tag was looked up $(wc -l < "$work/bin/calls") times, not once" >&2; }

d="$(repo resolve-tag-object)"
workflow "$d" "- uses: owner/annotated@$T # v2.9.2"
expect fail "the tag object's own ID pinned in place of its commit" "$d" "tag v2.9.2 of owner/annotated is $S, not the pinned commit (ADR-0049 clause 3)"

d="$(repo resolve-moved)"
workflow "$d" "- uses: owner/moved@$S # v1.0.0"
expect fail "a tag that points to another commit" "$d" "tag v1.0.0 of owner/moved is $O, not the pinned commit"

d="$(repo resolve-missing)"
workflow "$d" "- uses: owner/light@$L # v9.9.9"
expect fail "a commented tag that does not exist" "$d" "tag v9.9.9 of owner/light is missing, not the pinned commit"

d="$(repo resolve-unreachable)"
workflow "$d" "- uses: owner/gone@$S # v1.0.0"
expect fail "a repository that cannot be reached" "$d" "git ls-remote of owner/gone failed"

d="$(repo resolve-branch-head)"
workflow "$d" "- uses: neteye-platform/repo-commons/.github/workflows/a.yaml@$H # main" \
              "- uses: neteye-platform/repo-commons/.github/workflows/b.yaml@$A # main"
: > "$work/bin/calls"
expect pass "a branch that contains the pinned commit, as its head and as an ancestor" "$d" "2 on commit SHAs, resolved"
[[ "$(wc -l < "$work/bin/calls")" -eq 1 ]] \
  || { failed=$((failed + 1)); echo "FAIL: one repository and branch was fetched $(wc -l < "$work/bin/calls") times, not once" >&2; }

d="$(repo resolve-branch-not-contained)"
workflow "$d" "- uses: neteye-platform/repo-commons@$O # main"
expect fail "a branch that does not contain the pinned commit" "$d" "branch main of neteye-platform/repo-commons does not contain the pinned commit (ADR-0049 clause 3)"

d="$(repo resolve-branch-missing)"
workflow "$d" "- uses: neteye-platform/repo-commons@$H # develop"
expect fail "a commented branch that does not exist" "$d" "fetching branch develop of neteye-platform/repo-commons failed"

d="$(repo resolve-branch-unreachable)"
workflow "$d" "- uses: neteye-platform/gone@$H # main"
expect fail "an organisation repository that cannot be reached" "$d" "fetching branch main of neteye-platform/gone failed"

CHECK_FLAGS=()

# --- cases: Renovate --------------------------------------------------------------------------

d="$(repo renovate-missing)"
rm "$d/renovate.json"
expect fail "no renovate.json" "$d" "renovate.json: not found"

d="$(repo renovate-other-preset)"
renovate "$d" "config:recommended"
expect fail "a renovate.json that extends another preset" "$d" "does not extend \"github>neteye-platform/repo-commons\""

d="$(repo renovate-no-cargo-rule)"
renovate "$d" "github>neteye-platform/repo-commons" '{ "matchManagers": ["npm"], "rangeStrategy": "update-lockfile" }'
expect fail "a renovate.json without the cargo rule" "$d" "has no packageRules entry with \"matchManagers\": [\"cargo\"]"

d="$(repo renovate-cargo-pin)"
renovate "$d" "github>neteye-platform/repo-commons" '{ "matchManagers": ["cargo"], "rangeStrategy": "pin" }'
expect fail "a cargo rule that pins" "$d" "(ADR-0049 clause 5)"

d="$(repo renovate-split-rule)"
renovate "$d" "github>neteye-platform/repo-commons" '{ "matchManagers": ["cargo"] }' '{ "rangeStrategy": "update-lockfile" }'
expect fail "the two keys in two different rules" "$d" "(ADR-0049 clause 5)"

d="$(repo renovate-reordered)"
renovate "$d" "github>neteye-platform/repo-commons" '{ "description": "ranges", "rangeStrategy": "update-lockfile", "matchManagers": [ "cargo" ] }'
expect pass "the cargo rule with its keys in the other order and a description" "$d" "Renovate configured"

d="$(repo renovate-multiline)"
cat > "$d/renovate.json" <<'EOF'
{
  "extends": [
    "github>neteye-platform/repo-commons"
  ],
  "packageRules": [
    {
      "matchManagers": [
        "cargo"
      ],
      "rangeStrategy": "update-lockfile"
    }
  ]
}
EOF
expect pass "a renovate.json written over several lines" "$d" "Renovate configured"

d="$(repo dependabot-present)"
mkdir -p "$d/.github"
printf 'version: 2\nupdates: []\n' > "$d/.github/dependabot.yml"
expect fail "a dependabot.yml beside renovate.json" "$d" ".github/dependabot.yml: exists"

# --- summary ----------------------------------------------------------------------------------

if ((failed)); then
  echo "Action reference self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Action reference self-test passed ($passed cases)."
exit 0
