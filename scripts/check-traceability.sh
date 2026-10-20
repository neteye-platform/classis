#!/usr/bin/env bash
#
# Traceability check for this repository (ADR-0003): every accepted decision and every success
# criterion is verified by a test that cites it.
#
# What is checked:
#   1. Identifiers: every list item under '## Goals / Success Criteria' and '## Quality Goals' in
#      docs/SPECIFICATION.md starts with a bold identifier — **G-n** under Goals, **Q-n** under
#      Quality Goals — and no identifier appears twice.
#   2. Coverage: every 🟢 accepted ADR is cited by at least one marker. An ADR whose
#      '## Enforcement' section carries a paragraph starting '**Not mechanically decidable:**'
#      followed by a reason is exempt.
#   3. Citations: every marker names an identifier that exists, and no ADR that is ⚪ superseded
#      or 🔴 rejected.
#
# A criterion that no marker cites is pending work: the check lists it in its closing line and
# does not fail — nothing in the specification marks the state, so meeting a goal touches the
# tests, not the constitution.
#
# A marker is the word 'Verifies', a colon, and one or more identifiers (ADR-0002, G-1, Q-2)
# separated by spaces or commas, in any tracked file that is not Markdown. Markdown is excluded
# so that the specification and the ADRs can describe markers without being counted as one.
# Whether the citing test asserts anything is review, not this check.
#
# 🟡 proposed ADRs are out of scope: their tests land while they are proposed, and the acceptance
# lands with them (AGENTS.md, section 3).
#
# Pure bash + coreutils/grep/sed, plus git to enumerate the repository's files. The file list
# comes from git — tracked plus new, not-yet-added files, minus everything .gitignore excludes.
#
# Usage:
#     scripts/check-traceability.sh [repository root]
# Exit code 0 when the check passes, 1 otherwise.

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
SPEC="docs/SPECIFICATION.md"
ADR_DIR="docs/adr"
ID_RE='ADR-[0-9]{4}|[GQ]-[0-9]+'

errors=()
add_error() { errors+=("$1"); }

# _contains <needle> <haystack...> — true if needle equals one of the arguments.
_contains() {
  local needle="$1"; shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

# ---------------------------------------------------------------------------------------------
# 1. Criteria: identifiers read off the specification.

criteria=()   # every G-n / Q-n identifier, in order of appearance
section=""    # 'G' or 'Q' while inside one of the two sections, empty otherwise

if [[ ! -f "$ROOT/$SPEC" ]]; then
  add_error "$SPEC: not found — the criteria cannot be read"
else
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^##[[:space:]] ]]; then
      case "$line" in
        "## Goals / Success Criteria"*) section="G" ;;
        "## Quality Goals"*) section="Q" ;;
        *) section="" ;;
      esac
      continue
    fi
    [[ -n "$section" ]] || continue
    [[ "$line" =~ ^[[:space:]]*([-*+]|[0-9]+\.)[[:space:]]+(.*)$ ]] || continue

    body="${BASH_REMATCH[2]}"
    if [[ "$body" =~ ^\*\*([GQ])-([0-9]+)\*\* ]]; then
      kind="${BASH_REMATCH[1]}"
      id="$kind-${BASH_REMATCH[2]}"
      [[ "$kind" == "$section" ]] \
        || add_error "$SPEC: '$id' is listed under the wrong section — G-n belongs under Goals / Success Criteria, Q-n under Quality Goals"
      _contains "$id" "${criteria[@]}" \
        && add_error "$SPEC: identifier '$id' appears twice — identifiers are never reused"
      criteria+=("$id")
    else
      add_error "$SPEC: list item without a bold ${section}-n identifier: '${body:0:60}'"
    fi
  done < "$ROOT/$SPEC"
fi

# ---------------------------------------------------------------------------------------------
# 2. ADRs: which exist, which are accepted, which are inactive, which declare an exemption.

known_adrs=()
accepted=()
inactive=()
exempt=()

for f in "$ROOT/$ADR_DIR"/[0-9][0-9][0-9][0-9]-*.md; do
  [[ -f "$f" ]] || continue
  name="$(basename "$f")"
  id="ADR-${name:0:4}"
  known_adrs+=("$id")
  status_line="$(grep -m1 -F '**Status:**' "$f")"
  case "$status_line" in
    *🟢*)
      accepted+=("$id")
      enforcement="$(sed -n '/^## Enforcement/,$p' "$f")"
      if grep -qE '^\*\*Not mechanically decidable:\*\*' <<< "$enforcement"; then
        if grep -qE '^\*\*Not mechanically decidable:\*\*[[:space:]]*[^[:space:]]' <<< "$enforcement"; then
          exempt+=("$id")
        else
          add_error "$ADR_DIR/$name: 'Not mechanically decidable' declared without a reason — the paragraph has to say why no test can decide it"
        fi
      fi
      ;;
    *🔴* | *⚪*) inactive+=("$id") ;;
  esac
done

# ---------------------------------------------------------------------------------------------
# 3. Markers: every citation in every non-Markdown text file.

cited=()   # identifiers cited, one entry per citation

while IFS= read -r -d '' rel; do
  f="$ROOT/$rel"
  [[ -f "$f" ]] || continue
  case "$rel" in *.md) continue ;; esac
  grep -IqF 'Verifies:' "$f" || continue

  while IFS= read -r hit; do
    lineno="${hit%%:*}"
    mapfile -t ids < <(grep -oE "Verifies:[[:space:]]*($ID_RE)([[:space:],]+($ID_RE))*" <<< "${hit#*:}" \
                       | sed -E 's/^Verifies:[[:space:]]*//' | grep -oE "$ID_RE")
    for id in "${ids[@]}"; do
      cited+=("$id")
      case "$id" in
        ADR-*)
          if ! _contains "$id" "${known_adrs[@]}"; then
            add_error "$rel:$lineno: cites '$id', which does not exist in $ADR_DIR/"
          elif _contains "$id" "${inactive[@]}"; then
            add_error "$rel:$lineno: cites '$id', which is superseded or rejected — a test cannot verify a decision no longer in force"
          fi
          ;;
        *)
          _contains "$id" "${criteria[@]}" \
            || add_error "$rel:$lineno: cites '$id', which is not a criterion of $SPEC"
          ;;
      esac
    done
  done < <(grep -nE "Verifies:[[:space:]]*($ID_RE)" "$f")
done < <(git -C "$ROOT" ls-files --cached --others --exclude-standard -z)

# ---------------------------------------------------------------------------------------------
# 4. Coverage: every accepted ADR is cited; criteria without a citation are listed.

for id in "${accepted[@]}"; do
  _contains "$id" "${exempt[@]}" && continue
  _contains "$id" "${cited[@]}" \
    || add_error "$id is accepted but no test cites it — add a 'Verifies' marker or declare it not mechanically decidable in its Enforcement section"
done

uncovered=()
for id in "${criteria[@]}"; do
  _contains "$id" "${cited[@]}" || uncovered+=("$id")
done

# ---------------------------------------------------------------------------------------------

if ((${#errors[@]})); then
  echo "Traceability check FAILED:" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi

summary="${#accepted[@]} accepted ADRs, ${#criteria[@]} criteria, ${#cited[@]} citations"
if ((${#uncovered[@]})); then
  summary+="; ${#uncovered[@]} criteria without a test: ${uncovered[*]}"
fi
echo "Traceability check passed ($summary)."
exit 0
