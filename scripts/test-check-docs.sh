#!/usr/bin/env bash
#
# Self-test of scripts/check-docs.sh. Verifies: ADR-0001 ADR-0005 ADR-0008 ADR-0009
#
# Each case builds a throwaway git repository under a temporary directory — a rule file with
# numbered sections, a README with a Project Layout block, the required-checks markers, and the
# Template release line, a workflow and a local runner listing the same check, an ADR record with
# its index, and one skill with its pointer — runs the check against it, and asserts the exit
# code and, for a failing case, the message that names the violation. The baseline passes; every
# other case breaks one thing. The skill pointer check (check 11 of check-docs.sh) is covered in
# every direction; of the older checks, one case each pins the message a maintainer would meet
# first — check 9 gets two more for the toolchain job a derived project adds, checks 12 and 13
# (inherited ADRs decided and the template's identity replaced once the setup file is gone) have
# a case for each of their conditions, check 14 (the template release named) one for each
# form the line may take, and check 16 (the user manual cites no ADR) one for each form a
# citation takes.
#
# Section references and ADR numbers inside fixtures are assembled, never written literally, so
# that check-docs.sh does not read this script's own fixtures as references into this repository.
#
# Usage:
#     scripts/test-check-docs.sh
# Exit code 0 when every case passes, 1 otherwise.

set -uo pipefail

# The fixtures are repositories of their own: an inherited GIT_DIR, GIT_INDEX_FILE or the like, as
# a hook exports, would point their git commands at the repository this runs in.
mapfile -t git_env < <(git rev-parse --local-env-vars)
unset "${git_env[@]}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-docs.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
passed=0

# sect <n> — the section sign followed by n, assembled so that this file carries no literal one.
sect() { printf '\302\247%s' "$1"; }

# adr_id <n> — the identifier ADR-000n, assembled for the same reason.
adr_id() { printf 'ADR-%04d' "$1"; }

# adr <dir> <number> <status emoji + word> — write one ADR with the header the index mirrors.
adr() {
  local dir="$1" n="$2" status="$3"
  {
    echo "# $(adr_id "$n"): decision $n"
    echo
    echo "- **Status:** $status"
    echo "- **Applies to:** everything"
    echo
    echo "## Decision"
    echo
    echo "We will."
  } > "$dir/docs/adr/$(printf '%04d' "$n")-decision.md"
}

# index_row <number> <status emoji + word> — one row of the ADR index for the given ADR.
index_row() {
  local n
  n="$(printf '%04d' "$1")"
  echo "| [$n]($n-decision.md) | Decision $n | everything | $2 |"
}

# repo <name> — a fixture repository that passes every check, printed as its path.
repo() {
  local dir="$work/$1"
  mkdir -p "$dir/docs/adr" "$dir/scripts" "$dir/.github/workflows" \
           "$dir/.agents/skills/review" "$dir/.claude/skills"
  git -C "$dir" init -q

  {
    echo "# Agent Guide"
    echo
    echo "## 1. Principles"
    echo
    echo "Be simple."
    echo
    echo "## 2. Rules"
    echo
    echo "Follow them."
  } > "$dir/AGENTS.md"

  {
    echo "# Fixture"
    echo
    echo "## Project Layout"
    echo
    echo '```'
    echo "AGENTS.md             # the rule file"
    echo "docs/adr/             # decisions"
    echo '```'
    echo
    echo "## Repository settings"
    echo
    echo "<!-- required-checks begin -->"
    # shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
    echo '`docs`'
    echo "<!-- required-checks end -->"
    echo
    echo "## Template"
    echo
    echo "- **Template release:** unreleased"
  } > "$dir/README.md"

  {
    echo "jobs:"
    echo "  docs:"
    echo "    steps:"
    echo "      - run: bash scripts/check-docs.sh"
  } > "$dir/.github/workflows/checks.yml"

  echo 'run "Documentation consistency" scripts/check-docs.sh' > "$dir/scripts/check-all.sh"

  {
    echo "# $(printf 'ADR-%s' NNNN): title"
    echo
    echo "- **Status:** 🟡 proposed"
    echo
    echo "*Complete the header and delete this paragraph.*"
  } > "$dir/docs/adr/template.md"

  adr "$dir" 1 "🟡 proposed"
  {
    echo "# Architecture Decision Records"
    echo
    echo "| ADR | Title | Applies to | Status |"
    echo "|-----|-------|------------|--------|"
    index_row 1 "🟡 proposed"
  } > "$dir/docs/adr/README.md"

  printf -- '---\nname: review\ndescription: Review a change.\n---\n\n# Review\n' \
    > "$dir/.agents/skills/review/SKILL.md"
  ln -s ../../.agents/skills/review "$dir/.claude/skills/review"

  echo "$dir"
}

# expect <pass|fail> <name> <dir> [needle] — run the check; when a needle is given, its output
# must contain it.
expect() {
  local want="$1" name="$2" dir="$3" needle="${4:-}"
  local out rc
  git -C "$dir" add -A
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

# --- cases: the baseline -----------------------------------------------------------------

d="$(repo baseline)"
expect pass "a consistent repository passes" "$d"

# --- cases: skill pointers (check 11) ----------------------------------------------------

d="$(repo pointer-missing)"
rm "$d/.claude/skills/review"
expect fail "a skill without its pointer" "$d" ".claude/skills/review: no pointer"

d="$(repo pointer-dangling)"
rm -r "$d/.agents/skills/review"
expect fail "a pointer whose skill is gone" "$d" ".claude/skills/review: dangles"

d="$(repo pointer-copy)"
rm "$d/.claude/skills/review"
cp -r "$d/.agents/skills/review" "$d/.claude/skills/review"
expect fail "a copy where a symlink belongs" "$d" ".claude/skills/review: is a copy"

d="$(repo pointer-wrong-target)"
mkdir -p "$d/.agents/skills/other"
printf -- '---\nname: other\ndescription: Other.\n---\n' > "$d/.agents/skills/other/SKILL.md"
ln -s ../../.agents/skills/review "$d/.claude/skills/other"
expect fail "a pointer at a different skill" "$d" ".claude/skills/other: points at"

d="$(repo pointer-only-skill)"
mkdir -p "$d/.claude/skills/local"
printf -- '---\nname: local\ndescription: Local.\n---\n' > "$d/.claude/skills/local/SKILL.md"
expect fail "a skill that lives only in the pointer directory" "$d" ".claude/skills/local: is not a symlink"

d="$(repo pointer-directory-only)"
rm -r "$d/.agents" "$d/.claude/skills/review"
mkdir -p "$d/.claude/skills/review"
printf -- '---\nname: review\ndescription: Review.\n---\n' > "$d/.claude/skills/review/SKILL.md"
expect fail "skills only in the pointer directory, none for the other agents" "$d" ".claude/skills/review: is not a symlink"

d="$(repo no-skills)"
rm -r "$d/.agents" "$d/.claude"
expect pass "a repository without skills has nothing to check" "$d"

# --- cases: inherited ADRs after setup (check 12) ---------------------------------------

# inherited <dir> <status emoji + word> <deciders> — ADR 1 as an ADR inherited from the template,
# with the given status in the file and the index and the given Deciders line.
inherited() {
  local dir="$1" status="$2" deciders="$3"
  adr "$dir" 1 "$status"
  sed -i "s|^- \*\*Applies to:\*\*|- **Deciders:** $deciders\n- **Applies to:**|" "$dir/docs/adr/0001-decision.md"
  {
    echo "# Architecture Decision Records"
    echo
    echo "| ADR | Title | Applies to | Status |"
    echo "|-----|-------|------------|--------|"
    index_row 1 "$status"
  } > "$dir/docs/adr/README.md"
}

d="$(repo inherited-undecided)"
inherited "$d" "🟡 proposed" "NUC maintainer"
expect fail "an inherited ADR still proposed with the setup file gone" "$d" "0001-decision.md: inherited from the template and still proposed"

d="$(repo inherited-pending)"
inherited "$d" "🟡 proposed" "NUC maintainer"
echo "# Template setup" > "$d/TEMPLATE-SETUP.md"
expect pass "an inherited ADR still proposed while the setup file exists" "$d"

d="$(repo inherited-accepted)"
inherited "$d" "🟢 accepted" "NUC maintainer, project maintainer"
expect pass "an inherited ADR accepted by the project's maintainer" "$d"

d="$(repo own-proposed)"
inherited "$d" "🟡 proposed" "project maintainer"
expect pass "the project's own proposed ADR after setup" "$d"

d="$(repo inherited-wrapped)"
inherited "$d" "🟡 proposed" "project maintainer (reviewing),\n  NUC maintainer"
expect fail "an inherited ADR whose Deciders field wraps, the template's name on the second line" "$d" "0001-decision.md: inherited from the template and still proposed"

# --- cases: template identity after setup (check 13) ------------------------------------

d="$(repo identity-pending)"
sed -i 's/^# Fixture$/# NUC — an Agentic Fixture/' "$d/README.md"
echo "# Template setup" > "$d/TEMPLATE-SETUP.md"
expect pass "the template's title in the README while the setup file exists" "$d"

d="$(repo identity-title)"
sed -i 's/^# Fixture$/# NUC — an Agentic Fixture/' "$d/README.md"
expect fail "the template's title in the README after setup" "$d" "README.md: the title is still the template's"

d="$(repo identity-devcontainer)"
mkdir -p "$d/.devcontainer"
echo '{ "name": "NUC DevContainer" }' > "$d/.devcontainer/devcontainer.json"
expect fail "the template's Dev Container name after setup" "$d" "devcontainer.json: the Dev Container still carries the template's name"

d="$(repo identity-badge)"
echo "[![Checks](https://github.com/hivevm/nuc/actions/workflows/checks.yml/badge.svg)](https://github.com/hivevm/nuc/actions/workflows/checks.yml)" >> "$d/README.md"
expect fail "the template's repository in the README badge after setup" "$d" "README.md: the badge still points at the template"

d="$(repo identity-template-link)"
echo "Created from [NUC](https://github.com/hivevm/nuc)." >> "$d/README.md"
expect pass "a link to the template's repository outside the badge after setup" "$d"

d="$(repo identity-license)"
printf 'MIT License\n\nCopyright (c) 2026 Maintainer\n' > "$d/LICENSE"
expect fail "the placeholder copyright holder after setup" "$d" "LICENSE: the copyright holder is still the placeholder"

d="$(repo identity-license-apache)"
printf 'Apache License\nVersion 2.0, January 2004\n\nCopyright 2026 Maintainer\n' > "$d/LICENSE"
expect fail "the placeholder copyright holder under another license after setup" "$d" "LICENSE: the copyright holder is still the placeholder"

d="$(repo identity-contact)"
echo "- email the maintainer: <!-- TODO: add a security contact address -->." > "$d/SECURITY.md"
expect fail "the placeholder security contact after setup" "$d" "SECURITY.md: the security contact is still the placeholder"

d="$(repo identity-done)"
printf 'MIT License\n\nCopyright (c) 2026 Someone\n' > "$d/LICENSE"
expect pass "identity replaced after setup" "$d"

# --- cases: the template release named (check 14) ---------------------------------------

# release_line <dir> <text> — replace the baseline's Template release line with the given text.
release_line() { sed -i "s/^- \*\*Template release:\*\* unreleased$/$2/" "$1/README.md"; }

d="$(repo release-tag)"
release_line "$d" '- **Template release:** v1.4.0 of the template ([tags](https:\/\/example.invalid\/tags)).'
expect pass "a release tag followed by a sentence" "$d"

d="$(repo release-plain-line)"
release_line "$d" '**Template release:** v0.2.0'
expect pass "the line without a list marker" "$d"

d="$(repo release-linked)"
release_line "$d" '* **Template release:** [v1.4.0](https:\/\/example.invalid\/releases\/tag\/v1.4.0), taken up in full.'
expect pass "the tag as link text after a star marker" "$d"

d="$(repo release-backticked)"
# shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
release_line "$d" '- **Template release:** `v1.4.0`'
expect pass "the tag in backticks" "$d"

d="$(repo release-leading-zero)"
release_line "$d" '- **Template release:** v01.4.0'
expect fail "a leading zero, which SemVer forbids" "$d" "names neither a 'vX.Y.Z' tag nor 'unreleased'"

d="$(repo release-missing)"
release_line "$d" 'Created from the template.'
expect fail "no Template release line" "$d" "no '**Template release:**' line"

d="$(repo release-malformed)"
release_line "$d" '- **Template release:** 1.4'
expect fail "a version that is not a vX.Y.Z tag" "$d" "names neither a 'vX.Y.Z' tag nor 'unreleased'"

d="$(repo release-prerelease)"
release_line "$d" '- **Template release:** v1.4.0-rc1'
expect fail "a pre-release suffix on the tag" "$d" "names neither a 'vX.Y.Z' tag nor 'unreleased'"

d="$(repo release-word)"
release_line "$d" '- **Template release:** latest'
expect fail "a word that is not 'unreleased'" "$d" "names neither a 'vX.Y.Z' tag nor 'unreleased'"

# --- cases: one each for the older checks ------------------------------------------------

d="$(repo broken-link)"
echo "See [the missing file](missing.md)." >> "$d/README.md"
expect fail "a relative link to a file that does not exist" "$d" "broken relative link"

d="$(repo index-status)"
adr "$d" 1 "🟢 accepted"
expect fail "an index status that disagrees with the ADR" "$d" "status for '0001-decision.md'"

d="$(repo numbering-gap)"
adr "$d" 3 "🟡 proposed"
index_row 3 "🟡 proposed" >> "$d/docs/adr/README.md"
expect fail "a gap in the ADR numbering" "$d" "numbers must run 0001..N without gaps"

# consolidation <dir> <flip second: yes|no> [wrap] — ADR 3 supersedes ADRs 1 and 2; the second's
# status is flipped only when asked, so that a check reading the first name alone passes; with
# 'wrap', the second name sits on a continuation line of the field.
consolidation() {
  local dir="$1" flip="$2" wrap="${3:-}" n3 sep=", "
  n3="$(adr_id 3)"
  [[ "$wrap" == "wrap" ]] && sep=",\n  "
  adr "$dir" 1 "⚪ superseded by $n3"
  if [[ "$flip" == "yes" ]]; then adr "$dir" 2 "⚪ superseded by $n3"; else adr "$dir" 2 "🟡 proposed"; fi
  adr "$dir" 3 "🟢 accepted"
  sed -i "s|^- \*\*Applies to:\*\*|- **Supersedes:** [$(adr_id 1)](0001-decision.md)${sep}[$(adr_id 2)](0002-decision.md)\n- **Applies to:**|" \
    "$dir/docs/adr/0003-decision.md"
  {
    echo "# Architecture Decision Records"
    echo
    echo "### Binding"
    echo
    echo "| ADR | Title | Applies to | Status |"
    echo "|-----|-------|------------|--------|"
    [[ "$flip" == "yes" ]] || index_row 2 "🟡 proposed"
    index_row 3 "🟢 accepted"
    echo
    echo "### Superseded and rejected"
    echo
    echo "| ADR | Title | Applies to | Status |"
    echo "|-----|-------|------------|--------|"
    index_row 1 "⚪ superseded by $n3"
    [[ "$flip" == "yes" ]] && index_row 2 "⚪ superseded by $n3"
  } > "$dir/docs/adr/README.md"
}

# --- cases: the two index tables (check 1) ------------------------------------------------

d="$(repo archive-row-above)"
adr "$d" 1 "🔴 rejected"
{
  echo "# Architecture Decision Records"
  echo
  echo "| ADR | Title | Applies to | Status |"
  echo "|-----|-------|------------|--------|"
  index_row 1 "🔴 rejected"
} > "$d/docs/adr/README.md"
expect fail "a rejected row with no archive heading above it" "$d" "sits above the 'Superseded and rejected' heading"

d="$(repo binding-row-below)"
{
  echo "# Architecture Decision Records"
  echo
  echo "## Superseded and rejected"
  echo
  echo "| ADR | Title | Applies to | Status |"
  echo "|-----|-------|------------|--------|"
  index_row 1 "🟡 proposed"
} > "$d/docs/adr/README.md"
expect fail "a proposed row under the archive heading" "$d" "sits below the 'Superseded and rejected' heading"

d="$(repo consolidation)"
consolidation "$d" yes
expect pass "one ADR superseding two, both flipped" "$d"

d="$(repo consolidation-half)"
consolidation "$d" no
expect fail "one ADR superseding two, the second not flipped" "$d" "0002-decision.md: 0003-decision.md supersedes it"

d="$(repo consolidation-wrapped)"
consolidation "$d" yes wrap
expect pass "a Supersedes field wrapped onto a second line, both flipped" "$d"

d="$(repo consolidation-wrapped-half)"
consolidation "$d" no wrap
expect fail "a wrapped Supersedes field, the name on the second line not flipped" "$d" "0002-decision.md: 0003-decision.md supersedes it"

# A header field wraps at the line width like any other: the status and the Applies to text are
# read across the continuation lines, joined by one space.
d="$(repo status-wrapped)"
consolidation "$d" yes
sed -i 's|^- \*\*Status:\*\* ⚪ superseded by |- **Status:** ⚪ superseded by\n  |' "$d/docs/adr/0002-decision.md"
expect pass "a Status field wrapped before the superseding ADR" "$d"

d="$(repo applies-to-wrapped)"
sed -i 's|^- \*\*Applies to:\*\* everything$|- **Applies to:** every part\n  of it|' "$d/docs/adr/0001-decision.md"
sed -i 's/| everything |/| every part of it |/' "$d/docs/adr/README.md"
expect pass "an Applies to field wrapped onto a second line" "$d"

d="$(repo applies-to-wrapped-differs)"
sed -i 's|^- \*\*Applies to:\*\* everything$|- **Applies to:** every part\n  of it|' "$d/docs/adr/0001-decision.md"
sed -i 's/| everything |/| every part |/' "$d/docs/adr/README.md"
expect fail "an Applies to field whose second line the index leaves out" "$d" "is 'every part' in the index but 'every part of it' in the file"

# partial <dir> <status of ADR 1> <Supersedes entry suffix> — ADR 2 supersedes ADR 1, whole or by
# clause (ADR-0009); ADR 1 carries the given status line, ADR 2 the given text after its link.
partial() {
  local dir="$1" status="$2" suffix="$3"
  adr "$dir" 1 "$status"
  adr "$dir" 2 "🟡 proposed"
  sed -i "s|^- \*\*Applies to:\*\*|- **Supersedes:** [$(adr_id 1)](0001-decision.md)$suffix\n- **Applies to:**|" \
    "$dir/docs/adr/0002-decision.md"
  {
    echo "# Architecture Decision Records"
    echo
    echo "### Binding"
    echo
    echo "| ADR | Title | Applies to | Status |"
    echo "|-----|-------|------------|--------|"
    [[ "$status" == ⚪* ]] || index_row 1 "$status"
    index_row 2 "🟡 proposed"
    echo
    echo "### Superseded and rejected"
    echo
    echo "| ADR | Title | Applies to | Status |"
    echo "|-----|-------|------------|--------|"
    [[ "$status" == ⚪* ]] && index_row 1 "$status"
  } > "$dir/docs/adr/README.md"
}

# --- cases: clause supersession (check 8). Verifies: ADR-0009 -------------------------------

d="$(repo partial)"
partial "$d" "🟢 accepted · clause 2 superseded by [$(adr_id 2)](0002-decision.md)" " clause 2"
expect pass "named clauses superseded, the old ADR active with the suffix" "$d"

d="$(repo partial-no-suffix)"
partial "$d" "🟢 accepted" " clauses 1 and 3"
expect fail "named clauses superseded, the old ADR without the suffix" "$d" "0001-decision.md: 0002-decision.md supersedes it"

d="$(repo partial-flipped)"
partial "$d" "⚪ superseded by [$(adr_id 2)](0002-decision.md)" " clause 2"
expect fail "named clauses superseded, the old ADR flipped to superseded whole" "$d" "supersedes only named clauses of it"

d="$(repo whole-suffix-only)"
partial "$d" "🟢 accepted · clause 2 superseded by [$(adr_id 2)](0002-decision.md)" ""
expect fail "a whole supersession, the old ADR left active with a clause suffix" "$d" "supersedes it whole, but its status is 🟢"

d="$(repo partial-unclaimed)"
partial "$d" "🟢 accepted · clause 2 superseded by [$(adr_id 2)](0002-decision.md)" " clause 2"
sed -i '/^- \*\*Supersedes:\*\*/d' "$d/docs/adr/0002-decision.md"
expect fail "a clause suffix whose successor does not claim it" "$d" "0002-decision.md: 0001-decision.md says it supersedes"

d="$(repo partial-two)"
partial "$d" "🟢 accepted · clause 2 superseded by [$(adr_id 2)](0002-decision.md) · clause 4 superseded by [$(adr_id 3)](0003-decision.md)" " clause 2"
adr "$d" 3 "🟡 proposed"
sed -i "s|^- \*\*Applies to:\*\*|- **Supersedes:** [$(adr_id 1)](0001-decision.md) clause 4\n- **Applies to:**|" "$d/docs/adr/0003-decision.md"
sed -i "/^| \[0002\]/a $(index_row 3 '🟡 proposed')" "$d/docs/adr/README.md"
expect pass "two successors superseding different clauses of one ADR" "$d"

d="$(repo section-ref)"
echo "Cited in [\`AGENTS.md\` $(sect 9)](AGENTS.md#9-nowhere)." >> "$d/README.md"
expect fail "a section reference that names no section" "$d" "matches no numbered section"

d="$(repo unknown-adr-ref)"
echo "Decided in $(adr_id 42)." >> "$d/README.md"
expect fail "a reference to an ADR that does not exist" "$d" "matches no ADR file"

d="$(repo check-lists)"
echo 'run "Extra" scripts/check-extra.sh' >> "$d/scripts/check-all.sh"
expect fail "a check the local runner has and CI does not" "$d" "CI and the local gate disagree"

# build_job <dir> <run line> [local] — a toolchain job in the workflow, with a setup step before
# its run line, listed among the required checks; with 'local', the local runner invokes the
# build script too.
build_job() {
  local dir="$1" run="$2" local_gate="${3:-}"
  {
    echo "  build:"
    echo "    steps:"
    echo "      - uses: actions/setup-something@v1"
    echo "      - run: $run"
  } >> "$dir/.github/workflows/checks.yml"
  [[ "$local_gate" == "local" ]] \
    && echo 'run "Build, test, lint" scripts/check-build.sh' >> "$dir/scripts/check-all.sh"
  # shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
  sed -i 's|^`docs`$|`docs`, `build`|' "$dir/README.md"
}

d="$(repo build-job)"
build_job "$d" "bash scripts/check-build.sh" local
expect pass "a toolchain job that runs the build script after a setup step" "$d"

# The commands inline in the job, the local runner untouched: every list agrees, and the pre-push
# hook runs neither the build nor the tests.
d="$(repo build-job-inline)"
build_job "$d" "make test"
expect fail "a toolchain job with its commands inline and nothing in the local runner" "$d" "job 'build' runs no script under scripts/"

# ci_job <dir> <job> [matrix] — a job of the CI workflow, listed among the required checks; with
# 'matrix', the job runs a matrix and its check is named after the values.
ci_job() {
  local dir="$1" job="$2" matrix="${3:-}"
  {
    echo "jobs:"
    echo "  $job:"
    if [[ "$matrix" == "matrix" ]]; then
      echo "    strategy:"
      echo "      matrix:"
      echo "        os: [windows-latest]"
    fi
    echo "    runs-on: windows-latest"
    echo "    steps:"
    echo "      - run: cargo test"
  } > "$dir/.github/workflows/ci.yml"
  # shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
  sed -i "s|^\`docs\`\$|\`docs\`, \`$job\`|" "$dir/README.md"
}

d="$(repo ci-job)"
ci_job "$d" client-windows
expect pass "a required check that is a plain job of the CI workflow" "$d"

d="$(repo ci-job-matrix)"
ci_job "$d" client-windows matrix
expect fail "a required check that is a matrix job of the CI workflow" "$d" "its check reports under another name"

d="$(repo required-unknown)"
# shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
sed -i 's|^`docs`$|`docs`, `nowhere`|' "$d/README.md"
expect fail "a required check that is a job of no workflow" "$d" "is not a job in"

d="$(repo layout-stale)"
sed -i 's|^docs/adr/ |docs/gone/ |' "$d/README.md"
expect fail "a Project Layout entry that no longer exists" "$d" "is not a directory of this repository"

# --- cases: the user manual cites no ADR (check 16) ---------------------------------------

d="$(repo manual-plain)"
mkdir -p "$d/docs/manual"
printf '# Manual\n\nStart the Server, then the Client.\n' > "$d/docs/manual/README.md"
expect pass "a manual that cites no ADR" "$d"

d="$(repo manual-cites-number)"
mkdir -p "$d/docs/manual"
printf '# Manual\n\nThe Client verifies every package (%s).\n' "$(adr_id 1)" > "$d/docs/manual/README.md"
expect fail "a manual that names an ADR" "$d" "docs/manual/README.md:3: cites an ADR"

d="$(repo manual-links-record)"
mkdir -p "$d/docs/manual"
printf '# Manual\n\nSee [why](../adr/%s-decision.md).\n' "$(printf '%04d' 1)" > "$d/docs/manual/README.md"
expect fail "a manual that links into the decision records" "$d" "docs/manual/README.md:3: cites an ADR"

# --- summary -------------------------------------------------------------------------------

if ((failed)); then
  echo "Documentation self-test FAILED ($failed of $((passed + failed)) cases)." >&2
  exit 1
fi
echo "Documentation self-test passed ($passed cases)."
exit 0
