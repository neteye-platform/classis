#!/usr/bin/env bash
#
# GitHub Actions reference check for this repository (ADR-0044).
#
# ADR-0044 pins every third-party action to a commit SHA with its release in a comment, keeps every
# first-party action on its major version tag, and lets Dependabot raise both. This check reads the
# files the decision names and fails on what would break it:
#
#   1. References: every 'uses:' on an uncommented line of .github/workflows/*.yml|*.yaml is one
#      of two classes, told apart by the owner.
#      - First-party, owner 'actions': its major version tag, 'actions/name@vN' or
#        'actions/name/path@vN'. A commit SHA, a branch, a full version and an untagged reference
#        fail (clause 2).
#      - Third-party, every other owner ('github' included): a full 40-character lowercase commit
#        SHA, 'owner/action@<sha>' or 'owner/action/path@<sha>', on a line that ends in a comment
#        '# vX.Y.Z' naming the release the SHA was taken from. A tag, a branch, a short or
#        uppercase SHA, a SHA without the comment and a comment naming only a major fail
#        (clause 3). A reusable workflow is classified by the same rule.
#      A local action ('./…') is exempt; a 'docker://' image carries an explicit ':<tag>'
#      (clause 6).
#   1b. Resolution, with --resolve only: for each third-party reference, 'git ls-remote' on
#      https://github.com/<owner>/<name> reads the commented tag, and the commit it points to —
#      the peeled commit for an annotated tag, never the tag object — must be the pinned SHA. A
#      missing tag, or one that points elsewhere, fails (clause 4). Each repository and tag is
#      looked up once. This needs the network; the offline run checks 1 and 2 only.
#   2. Dependabot: .github/dependabot.yml exists and has an entry with
#      'package-ecosystem: github-actions', the one that raises both kinds of update (clause 5).
#
# A 'uses:' inside a full-line '#' comment is not read: a comment is not a reference. A trailing
# comment after the reference is read as the release comment and then dropped, and quotes around
# the value are stripped. Only the block form is read, 'uses:' at the start of a line or list item;
# a flow-style step ('- {uses: …}') is not, and none of this repository's workflows is written that
# way.
#
# Pure bash + coreutils/grep/sed, and git for --resolve. Usage:
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
DEPENDABOT=".github/dependabot.yml"
FIRST_PARTY_RE='^actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@v[0-9]+$'
THIRD_PARTY_RE='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$'
VERSION_COMMENT_RE='^v[0-9]+\.[0-9]+\.[0-9]+$'

errors=()
add_error() { errors+=("$1"); }

shopt -s nullglob
workflows=("$ROOT/$WORKFLOWS"/*.yml "$ROOT/$WORKFLOWS"/*.yaml)
shopt -u nullglob

if ((${#workflows[@]} == 0)); then
  add_error "$WORKFLOWS: no workflow found — ADR-0044 governs the action references there"
fi

# 1. References.
refs=0
first=0
third=0
pinned=() # "<file:line>|<value>|<tag>" of every third-party reference that passed 1, for 1b.
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
          || add_error "$rel:$n: '$value' carries no tag — an image is referenced with an explicit ':<tag>' (ADR-0044 clause 6)"
        ;;
      *)
        owner="${value%%/*}"
        if [[ "$owner" == "actions" ]]; then
          first=$((first + 1))
          if [[ "$value" != *@* ]]; then
            add_error "$rel:$n: '$value' names no ref — reference it by its major version tag, 'actions/name@vN' (ADR-0044 clause 2)"
          elif ! [[ "$value" =~ $FIRST_PARTY_RE ]]; then
            add_error "$rel:$n: '$value' is first-party — reference it by its major version tag, 'actions/name@vN'; a SHA, a branch and a full version are not used (ADR-0044 clause 2)"
          fi
        else
          third=$((third + 1))
          if ! [[ "$value" =~ $THIRD_PARTY_RE ]]; then
            add_error "$rel:$n: '$value' is a third-party action not pinned to a full commit SHA — pin it to the 40-character lowercase SHA of a release and name the release in a comment, 'owner/action@<sha> # vX.Y.Z' (ADR-0044 clause 3)"
          elif ! [[ "$comment" =~ $VERSION_COMMENT_RE ]]; then
            # The single quotes are part of the message, inside double quotes.
            # shellcheck disable=SC2016
            add_error "$rel:$n: '$value' ${comment:+carries '# $comment', }not '# vX.Y.Z' — end the line in a comment naming the release tag the SHA was taken from, as three numbers (ADR-0044 clause 3)"
          else
            pinned+=("$rel:$n|$value|$comment")
          fi
        fi
        ;;
    esac
  done < <(grep -nE '^[[:space:]]*(- )?uses:' "$wf")
done

# 1b. Resolution.
if ((RESOLVE)); then
  declare -A resolved=()
  for p in "${pinned[@]}"; do
    where="${p%%|*}"; p="${p#*|}"
    value="${p%%|*}"; tag="${p#*|}"
    sha="${value##*@}"
    repo="${value%%@*}"
    owner="${repo%%/*}"; name="${repo#*/}"; name="${name%%/*}"
    key="$owner/$name $tag"
    if [[ -z "${resolved[$key]+x}" ]]; then
      # Every repository involved is public: no credentials are offered and no prompt is shown.
      if out="$(GIT_TERMINAL_PROMPT=0 git -c protocol.version=2 -c credential.helper= \
                  ls-remote "https://github.com/$owner/$name" "refs/tags/$tag" "refs/tags/$tag^{}" 2>&1)"; then
        plain="$(awk -v r="refs/tags/$tag" '$2 == r { print $1 }' <<< "$out")"
        peeled="$(awk -v r="refs/tags/$tag^{}" '$2 == r { print $1 }' <<< "$out")"
        resolved[$key]="${peeled:-${plain:-missing}}"
      else
        resolved[$key]="unreachable"
        add_error "$where: '$value': git ls-remote of $owner/$name failed — $(head -n 1 <<< "$out") (ADR-0044 clause 4)"
        continue
      fi
    fi
    got="${resolved[$key]}"
    [[ "$got" == "unreachable" || "$got" == "$sha" ]] \
      || add_error "$where: '$value': tag $tag of $owner/$name is $got, not the pinned commit (ADR-0044 clause 4)"
  done
fi

# 2. Dependabot.
if [[ ! -f "$ROOT/$DEPENDABOT" ]]; then
  add_error "$DEPENDABOT: not found — Dependabot raises the pull request for a new major of a first-party action and a new release of a pinned one (ADR-0044 clause 5)"
elif ! grep -vE '^[[:space:]]*#' "$ROOT/$DEPENDABOT" \
       | grep -qE "^[[:space:]]*(- )?package-ecosystem:[[:space:]]*[\"']?github-actions[\"']?[[:space:]]*(#.*)?$"; then
  add_error "$DEPENDABOT: has no 'package-ecosystem: github-actions' entry — without it no pull request arrives when an action publishes a new release (ADR-0044 clause 5)"
fi

if ((${#errors[@]})); then
  echo "Action reference check FAILED:" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi

echo "Action reference check passed ($refs references: $first first-party on major tags, $third third-party on commit SHAs$( ((RESOLVE)) && echo ", resolved"); Dependabot configured)."
exit 0
