#!/usr/bin/env bash
#
# GitHub Actions reference check for this repository (ADR-0049).
#
# ADR-0049 pins every action to a commit SHA with its ref in a comment and lets Renovate, on the
# organisation preset, raise every update. This check reads the files the decision names and fails
# on what would break it:
#
#   1. References: every 'uses:' on an uncommented line of .github/workflows/*.yml|*.yaml is a
#      full 40-character lowercase commit SHA, 'owner/action@<sha>' or 'owner/repo/path@<sha>',
#      whatever the owner, 'actions' included (clause 1). The line ends in a comment naming the ref
#      the SHA was taken from: '# vX.Y.Z', the release tag as three numbers, or, for the owner
#      'neteye-platform' alone, a branch ('# main') (clause 2). A tag, a branch, a short or
#      uppercase SHA, a SHA without the comment, a comment naming only a major, and a branch
#      comment for any other owner fail. A reusable workflow is read by the same rule. A local
#      action ('./…') is exempt; a 'docker://' image carries an explicit ':<tag>' (clause 6).
#   1b. Resolution, with --resolve only (clause 3). For a commented tag, 'git ls-remote' on
#      https://github.com/<owner>/<name> reads the tag, and the commit it points to — the peeled
#      commit for an annotated tag, never the tag object — must be the pinned SHA. For a commented
#      branch, the branch's commit graph is fetched, without blobs, into a temporary bare
#      repository, and the pinned SHA must be the branch head or one of its ancestors. A missing
#      tag or branch, or one that does not lead to the pinned SHA, fails. Each repository and ref
#      is looked up once. This needs the network; the offline run checks 1 and 2 only.
#   2. Renovate: renovate.json exists and extends 'github>neteye-platform/repo-commons', and
#      .github/dependabot.yml does not exist (clause 4). renovate.json carries a packageRules
#      entry that matches the 'cargo' manager and sets 'rangeStrategy' to 'update-lockfile'
#      (clause 5). renovate.json is read as text, newlines folded: the preset must appear as a
#      quoted string, and the two keys of the cargo rule inside one '{…}' that holds no other
#      object, in either order. That is how this repository writes them; a rule split across
#      nested objects is not recognised.
#
# A 'uses:' inside a full-line '#' comment is not read: a comment is not a reference. A trailing
# comment after the reference is read as the ref comment and then dropped, and quotes around
# the value are stripped. Only the block form is read, 'uses:' at the start of a line or list item;
# a flow-style step ('- {uses: …}') is not, and none of this repository's workflows is written that
# way.
#
# Pure bash + coreutils/grep/sed/tr, and git for --resolve. Usage:
#     scripts/check-action-refs.sh [--resolve] [repository root]
# The root defaults to this repository; scripts/test-check-action-refs.sh passes fixtures and a
# stub git. Exit code 0 when the check passes, 1 otherwise.

set -uo pipefail

RESOLVE=0
if [[ "${1:-}" == "--resolve" ]]; then
  RESOLVE=1
  shift
fi

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
WORKFLOWS=".github/workflows"
RENOVATE="renovate.json"
DEPENDABOT=".github/dependabot.yml"
PRESET="github>neteye-platform/repo-commons"
ORG_OWNER="neteye-platform"
PINNED_RE='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$'
VERSION_COMMENT_RE='^v[0-9]+\.[0-9]+\.[0-9]+$'
BRANCH_COMMENT_RE='^[A-Za-z0-9][A-Za-z0-9_./-]*$'

errors=()
add_error() { errors+=("$1"); }

shopt -s nullglob
workflows=("$ROOT/$WORKFLOWS"/*.yml "$ROOT/$WORKFLOWS"/*.yaml)
shopt -u nullglob

if ((${#workflows[@]} == 0)); then
  add_error "$WORKFLOWS: no workflow found — ADR-0049 governs the action references there"
fi

# 1. References.
refs=0
shas=0
pinned=() # "<file:line>|<value>|<tag|branch>|<ref>" of every reference that passed 1, for 1b.
for wf in "${workflows[@]}"; do
  rel="${wf#"$ROOT"/}"
  while IFS= read -r hit; do
    n="${hit%%:*}"
    rest="$(sed -E "s/^[^:]*:[[:space:]]*(- )?uses:[[:space:]]*//" <<< "$hit")"
    comment="$(sed -nE 's/^[^#]*[^[:space:]#][[:space:]]+#[[:space:]]*(.*)$/\1/p' <<< "$rest" | sed -E 's/[[:space:]]+$//')"
    value="$(sed -E "s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"']$//; s/[[:space:]]+$//" <<< "$rest")"
    refs=$((refs + 1))
    case "$value" in
      ./*) ;;
      docker://*)
        # The tag sits on the last path segment; a registry port ('host:5000/image') is not one.
        image="${value#docker://}"
        [[ "${image##*/}" == *:* ]] \
          || add_error "$rel:$n: '$value' carries no tag — an image is referenced with an explicit ':<tag>' (ADR-0049 clause 6)"
        ;;
      *)
        owner="${value%%/*}"
        if ! [[ "$value" =~ $PINNED_RE ]]; then
          add_error "$rel:$n: '$value' is not pinned to a full commit SHA — pin it to the 40-character lowercase SHA and name its ref in a comment, 'owner/action@<sha> # vX.Y.Z' (ADR-0049 clause 1)"
        elif [[ "$comment" =~ $VERSION_COMMENT_RE ]]; then
          shas=$((shas + 1))
          pinned+=("$rel:$n|$value|tag|$comment")
        elif [[ "$owner" == "$ORG_OWNER" && "$comment" =~ $BRANCH_COMMENT_RE ]]; then
          shas=$((shas + 1))
          pinned+=("$rel:$n|$value|branch|$comment")
        else
          # The single quotes are part of the message, inside double quotes.
          # shellcheck disable=SC2016
          add_error "$rel:$n: '$value' ${comment:+carries '# $comment', }not '# vX.Y.Z' — end the line in a comment naming the release tag the SHA was taken from, as three numbers; only an owner of $ORG_OWNER may name a branch (ADR-0049 clause 2)"
        fi
        ;;
    esac
  done < <(grep -nE '^[[:space:]]*(- )?uses:' "$wf")
done

# 1b. Resolution.
if ((RESOLVE)); then
  declare -A resolved=()
  scratch="$(mktemp -d)"
  trap 'rm -rf "$scratch"' EXIT
  # Every repository involved is public: no credentials are offered and no prompt is shown.
  rgit() { GIT_TERMINAL_PROMPT=0 git -c protocol.version=2 -c credential.helper= "$@"; }
  for p in "${pinned[@]}"; do
    where="${p%%|*}"; p="${p#*|}"
    value="${p%%|*}"; p="${p#*|}"
    kind="${p%%|*}"; ref="${p#*|}"
    sha="${value##*@}"
    repo="${value%%@*}"
    owner="${repo%%/*}"; name="${repo#*/}"; name="${name%%/*}"
    url="https://github.com/$owner/$name"
    if [[ "$kind" == tag ]]; then
      key="$owner/$name tag $ref"
      if [[ -z "${resolved[$key]+x}" ]]; then
        if out="$(rgit ls-remote "$url" "refs/tags/$ref" "refs/tags/$ref^{}" 2>&1)"; then
          plain="$(awk -v r="refs/tags/$ref" '$2 == r { print $1 }' <<< "$out")"
          peeled="$(awk -v r="refs/tags/$ref^{}" '$2 == r { print $1 }' <<< "$out")"
          resolved[$key]="${peeled:-${plain:-missing}}"
        else
          resolved[$key]="unreachable"
          add_error "$where: '$value': git ls-remote of $owner/$name failed — $(head -n 1 <<< "$out") (ADR-0049 clause 3)"
          continue
        fi
      fi
      got="${resolved[$key]}"
      [[ "$got" == "unreachable" || "$got" == "$sha" ]] \
        || add_error "$where: '$value': tag $ref of $owner/$name is $got, not the pinned commit (ADR-0049 clause 3)"
    else
      # One bare repository per repository and branch, holding that branch's commits and trees.
      key="$owner/$name branch $ref"
      if [[ -z "${resolved[$key]+x}" ]]; then
        dir="$scratch/${#resolved[@]}"
        if out="$(rgit init -q --bare "$dir" 2>&1 \
                  && rgit -C "$dir" fetch -q --filter=blob:none --no-tags "$url" \
                       "refs/heads/$ref:refs/heads/$ref" 2>&1)"; then
          resolved[$key]="$dir"
        else
          resolved[$key]="unreachable"
          add_error "$where: '$value': fetching branch $ref of $owner/$name failed — $(head -n 1 <<< "$out") (ADR-0049 clause 3)"
          continue
        fi
      fi
      dir="${resolved[$key]}"
      [[ "$dir" == "unreachable" ]] && continue
      rgit -C "$dir" merge-base --is-ancestor "$sha" "refs/heads/$ref" >/dev/null 2>&1 \
        || add_error "$where: '$value': branch $ref of $owner/$name does not contain the pinned commit (ADR-0049 clause 3)"
    fi
  done
fi

# 2. Renovate.
if [[ -f "$ROOT/$DEPENDABOT" ]]; then
  add_error "$DEPENDABOT: exists — Renovate raises every update, and a second bot raises each one twice (ADR-0049 clause 4)"
fi
if [[ ! -f "$ROOT/$RENOVATE" ]]; then
  add_error "$RENOVATE: not found — Renovate, from a renovate.json that extends $PRESET, raises every action and Cargo update (ADR-0049 clause 4)"
else
  config="$(tr '\n' ' ' < "$ROOT/$RENOVATE")"
  grep -qF "\"$PRESET\"" <<< "$config" \
    || add_error "$RENOVATE: does not extend \"$PRESET\" — the organisation preset is the configuration this repository shares (ADR-0049 clause 4)"
  manager='"matchManagers"[[:space:]]*:[[:space:]]*\[[[:space:]]*"cargo"[[:space:]]*\]'
  strategy='"rangeStrategy"[[:space:]]*:[[:space:]]*"update-lockfile"'
  grep -qE "\{[^{}]*(${manager}[^{}]*${strategy}|${strategy}[^{}]*${manager})[^{}]*\}" <<< "$config" \
    || add_error "$RENOVATE: has no packageRules entry with \"matchManagers\": [\"cargo\"] and \"rangeStrategy\": \"update-lockfile\" — without it the preset pins some Cargo requirements to '=x.y.z' and leaves the rest as ranges (ADR-0049 clause 5)"
fi

if ((${#errors[@]})); then
  echo "Action reference check FAILED:" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi

echo "Action reference check passed ($refs references, $shas on commit SHAs$( ((RESOLVE)) && echo ", resolved"); Renovate configured)."
exit 0
