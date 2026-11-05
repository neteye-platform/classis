#!/usr/bin/env bash
#
# Documentation consistency checks for this repository.
#
# Enforces — as CI, not just convention — the documentation rules from AGENTS.md and
# docs/adr/README.md:
#
#   1. ADR index integrity: every docs/adr/NNNN-*.md file is listed in the index table in
#      docs/adr/README.md, every index row points to an existing file, and the status and the
#      'Applies to' cell shown in the index match the **Status:** and **Applies to:** lines
#      inside each ADR — the index routes a reader from a change to the ADRs that bind it
#      (AGENTS.md, section 2), so a row that misstates what its ADR governs misroutes them.
#      A superseded or rejected row sits below the 'Superseded and rejected' heading and an
#      accepted or proposed one above it: the first table is what a session reads, and a
#      row in the wrong one is either a dead decision read as binding or a binding one
#      never read (docs/adr/README.md).
#   2. ADR numbering integrity: the ADR files run 0001..N without gaps, and every file's
#      '# ADR-NNNN' heading matches its filename (docs/adr/README.md).
#   3. Relative-link integrity: every relative Markdown link in every tracked .md file resolves
#      to a file or directory that exists. Links inside fenced code blocks are illustrations,
#      not claims about files on disk, and are skipped (here and in check 6); so is a target that
#      still carries the 'NNNN' placeholder of docs/adr/template.md; an optional link title
#      ('[text](file "title")') is not part of the path. Reference-style links
#      ('[text][label]') are not resolved — this repository uses inline links only.
#
#      Checks 3 to 6 skip ⚪ superseded and 🔴 rejected ADRs (see is_inactive_adr): both
#      describe a repository state that does not exist, so holding their references against the
#      current tree would demand that it still contain what the project decided against.
#   4. Section-reference integrity: in Markdown, YAML and shell files, every section reference
#      (the section sign followed by a number, e.g. in "AGENTS.md, section 6") matches a numbered
#      '## N.' heading in AGENTS.md — the only numbered document in this repository; extend the
#      check if another one appears. The headings there must themselves run 1..N in order: a
#      gap or a repeat is a botched renumbering, and it is the only half of the renumbering
#      hazard a check can see (AGENTS.md, section 3).
#      A citation into an external specification (e.g. "RFC 9110 §11") reuses the section sign
#      for a document that is not in this repository, so it is accepted unverified.
#   5. ADR-reference integrity: every 'ADR-NNNN' reference (with actual digits) names an ADR
#      file that exists in docs/adr/ — anticipated follow-ups are described by topic, never by
#      a number that does not exist yet (docs/adr/README.md).
#   6. ADR link agreement: a Markdown link whose text cites 'ADR-NNNN' points at that ADR's own
#      file — the number and the file it links to must name the same decision
#      (docs/adr/README.md).
#   7. ADR header hygiene: every ADR's '**Status:**' line carries exactly one legend emoji and the
#      word that belongs to it, and no ADR still contains the instruction paragraph from
#      docs/adr/template.md — recognized by a needle read off that template, so rewording it
#      cannot silently disable the check. Check 1 compares index and file emoji-to-emoji, so a
#      leftover list of alternatives and a word contradicting its emoji both survive it — and the
#      word is what a reader believes (docs/adr/README.md).
#   8. Supersession agreement: the '**Supersedes:**' field of the new ADR and the '⚪ superseded by
#      ADR-NNNN' status line of every old one it names — one, or several it consolidates — name
#      each other. Both are written in the same pull request but in two files
#      (docs/adr/README.md), and check 1 cannot see a missing half: it only mirrors the index
#      against whatever status the file carries. Every name of a Supersedes field counts, on
#      whichever line it sits. An entry that names clauses supersedes only those (ADR-0009): its
#      ADR keeps an active status and carries a 'clause N superseded by ADR-NNNN' suffix, while
#      an entry without clauses needs the ⚪ flip.
#   9. Check-list agreement: the jobs in .github/workflows/checks.yml, the invocations in
#      scripts/check-all.sh, and the required status checks named between the 'required-checks'
#      markers in README.md list the same checks. A check that runs in only one of the three is a
#      gate somebody believes in and does not have, and both files already say in their header
#      that a check added to one is added to the other in the same change (AGENTS.md, section 5).
#      A job of the workflow that runs no script under scripts/ fails too: its commands run in
#      CI and never in the local gate. The README may also name a job of
#      .github/workflows/ci.yml, which runs what the local gate cannot (other platforms); that
#      job has to exist and carry neither a 'name:' nor a matrix, or its check reports under a
#      rendered name the ruleset never sees.
#  10. Project Layout integrity: every path listed in the 'Project Layout' block of README.md
#      exists, a trailing '/' meaning a directory. The block is written by hand and nothing else
#      tells a reader that one of its lines has gone stale. The reverse direction is deliberately
#      not checked — the block is a tour of the parts a newcomer needs, not a file listing.
#  11. Skill pointer integrity: every skill under .agents/skills/ (a directory with a SKILL.md)
#      has a symlink of the same name under .claude/skills/ that resolves to it, and every entry
#      under .claude/skills/ is such a symlink (ADR-0005). Claude Code reads only the pointer
#      directory, so a skill without its pointer is invisible to it and to no other agent —
#      nobody notices; a copy instead of a symlink is a second source that drifts, and a skill
#      that lives only in the pointer directory is one no other agent finds. Each message says
#      the command that fixes it. A repository with neither directory has nothing to check.
#  12. Inherited ADRs decided: once TEMPLATE-SETUP.md is gone, no ADR whose '**Deciders:**' field
#      names the NUC maintainer is still 🟡 proposed. Each was accepted, with the project's own
#      maintainer added to Deciders, or superseded (docs/adr/README.md): an inherited ADR nobody
#      accepted is a rule nobody decided, and the test that ADR asks for lands with its
#      acceptance. While the setup file exists the decision is pending by design, and the check
#      is silent.
#  13. Template identity replaced: once TEMPLATE-SETUP.md is gone, none of the template's
#      placeholders is left: the project name NUC in the README title and the Dev Container name,
#      the template's repository in the README badge, the copyright holder in LICENSE, and the
#      security contact in SECURITY.md. Step 1 of the setup
#      replaces each; a placeholder that survives it describes the template, not the project. A
#      file that does not exist has nothing to check.
#  14. Template release named: README.md carries a '**Template release:**' line naming a
#      'vX.Y.Z' tag or 'unreleased' (ADR-0008). Tags do not travel with GitHub's template
#      mechanism, so the line is the one thing that tells a derived project which release of the
#      template it carries; a release moves it, and a project that takes a release up moves it.
#  15. Protocol Baseline currency: the pinned OpAMP specification version in docs/CONFORMANCE.md
#      is compared against the latest upstream release. A divergence is a *warning*, never an
#      error — an upstream release is not a defect in this repository, and failing here would
#      turn CI red for something outside it. Requires network; without one it prints a note and
#      skips, so every other check stays usable offline. The check itself is
#      scripts/check-protocol-baseline.sh, which scripts/test-check-protocol-baseline.sh drives
#      against fixtures; a helper that is missing or fails without saying why is an error here.
#      It concerns this repository only, so it does not run against a fixture root passed by
#      scripts/test-check-docs.sh.
#  16. The user manual cites no ADR: no file under docs/manual/ names an 'ADR-NNNN' or links into
#      docs/adr/. The manual is for the people who run the software and says what to do; a
#      decision record is for those who change it, and a citation sends an operator to a page
#      that does not answer their question. A repository without docs/manual/ has nothing to
#      check.
#
# Checks 5 and 6 read every text file of the repository, not a list of documentation extensions:
# docs/adr/README.md states that code may reference an ADR number, so a verifier restricted to
# documentation file types would leave the references most likely to go stale — those in source
# comments, which no reviewer reads alongside the ADR index — unchecked. Check 4 stays on
# documentation file types on purpose: 'ADR-NNNN' means one thing wherever it appears, but '§' in
# source code is an ordinary character (see is_doc_file), and flagging it there would make a
# project's own string literals fail this repository's CI.
#
# Pure bash + coreutils/grep/sed/awk/find, plus git to enumerate the repository's files — all present
# in the Dev Container base image, so running it adds no toolchain and no dependency that would
# require an ADR. Check 15 additionally uses curl when it is available, and degrades to a skip when
# it is not.
#
# Usage:
#     scripts/check-docs.sh [repository root]        (or: bash scripts/check-docs.sh)
# The root defaults to this repository; scripts/test-check-docs.sh passes fixture repositories.
# Exit code 0 when all checks pass, 1 otherwise. Warnings do not affect the exit code.

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
ADR_DIR="$ROOT/docs/adr"
ADR_INDEX="$ADR_DIR/README.md"

CONFORMANCE="$ROOT/docs/CONFORMANCE.md"
# Check 15 concerns this repository, not the template mechanics a fixture root exercises.
OWN_REPOSITORY=$(( $# == 0 ))

errors=()
add_error() { errors+=("$1"); }

# Warnings report drift that is outside this repository's control (see check 15). They are
# printed but never affect the exit code.
warnings=()
add_warning() { warnings+=("$1"); }

# Print the first legend status emoji (🟢 🟡 🔴 ⚪) read from stdin, if any.
first_status_emoji() { grep -oE '🟢|🟡|🔴|⚪' | head -n1; }

# table_cell <n> — the n-th cell of a Markdown table row read from stdin, trimmed; cells are
# counted from 1 after the leading pipe, so '| a | b |' has cell 1 'a' and cell 2 'b'.
table_cell() {
  awk -F'|' -v n="$1" '{ c = $(n + 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", c); print c }'
}

# applies_to_of <adr file> — the content of its '**Applies to:**' header field, wrapped lines
# joined by one space and trimmed; empty when the field is missing or blank.
applies_to_of() {
  header_field "$1" 'Applies to' | tr -s '[:space:]' ' ' \
    | sed -E 's/^.*\*\*Applies to:\*\*[[:space:]]*//; s/[[:space:]]+$//'
}

# status_of <adr file> — its '**Status:**' header field on one line, wrapped lines joined by one
# space; empty when the field is missing.
status_of() { header_field "$1" Status | tr -s '[:space:]' ' '; }

# _contains <needle> <haystack...> — true if needle equals one of the arguments.
_contains() {
  local needle="$1"; shift
  local item
  for item in "$@"; do [[ "$item" == "$needle" ]] && return 0; done
  return 1
}

# TEXT_FILES — every text file the repository consists of, absolute paths, sorted. Collected once
# by collect_text_files below and then iterated by each check: building the list costs a grep per
# file, so rebuilding it inside every check would multiply that cost by the number of checks, and
# a repository of a few thousand files makes that difference visible in CI.
#
# The list comes from git: tracked files plus new, not-yet-added ones, minus everything
# .gitignore excludes. That keeps generated trees (node_modules/, target/, dist/) out without
# this script having to guess the directory names of a toolchain this repository does not yet know.
# Binary files are dropped by grep -I, which never matches inside one.
# Outside a work tree (an exported tarball) git cannot answer, so fall back to a plain walk.
TEXT_FILES=()
collect_text_files() {
  local f
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    grep -Iq . "$f" 2>/dev/null || continue
    TEXT_FILES+=("$f")
  done < <(
    if git -C "$ROOT" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
      git -C "$ROOT" ls-files --cached --others --exclude-standard \
        | sed "s|^|$ROOT/|"
    else
      find "$ROOT" -type f -not -path '*/.git/*'
    fi | sort
  )
  if ((${#TEXT_FILES[@]} == 0)); then
    add_error "no text files found under $ROOT — the file list is empty, so nothing was checked"
  fi
}

# is_doc_file <file> — true for the file types in which the section sign is a reference into
# AGENTS.md by convention: Markdown, YAML, and shell scripts. In source code the section sign is
# an ordinary character with its own meanings — a statute cited in a German string literal, a
# translated message, a test fixture — none of which are claims about a section of AGENTS.md.
# The ADR checks scan every text file because 'ADR-NNNN' is unambiguous; this notation is not.
is_doc_file() {
  case "$1" in *.md | *.yml | *.yaml | *.sh) return 0 ;; *) return 1 ;; esac
}

# is_inactive_adr <file> — true for an ADR whose status is ⚪ superseded or 🔴 rejected. Both are
# historical record rather than live decisions, and both describe a repository state that does not
# exist: a superseded ADR is frozen with the past it was written against (AGENTS.md,
# docs/adr/README.md), and a rejected one describes a road not taken — the check script, the
# workflow job, the AGENTS.md section it names were never created, or were removed together with
# the rejection. Verifying either one's references would demand that the tree still contain what
# the project decided against, so the reference checks below skip them.
is_inactive_adr() {
  [[ "$1" == "$ADR_DIR"/* ]] && status_of "$1" | grep -q '⚪\|🔴'
}

check_adr_index() {
  if [[ ! -f "$ADR_INDEX" ]]; then
    add_error "ADR index not found: docs/adr/README.md"
    return
  fi

  # ADR files on disk (basenames), excluding the template.
  local disk_files=()
  local f
  while IFS= read -r f; do
    [[ "$(basename "$f")" == "template.md" ]] && continue
    disk_files+=("$(basename "$f")")
  done < <(find "$ADR_DIR" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]-*.md' | sort)

  # Parse the index into parallel arrays: filename, 'Applies to' cell, and status emoji per row.
  # Columns are '| ADR | Title | Applies to | Status |'; the cell is compared verbatim.
  local indexed_files=() indexed_applies=() indexed_status=()
  local line number target filename applies status archive=0
  while IFS= read -r line; do
    [[ "$line" =~ ^#+[[:space:]]+Superseded\ and\ rejected[[:space:]]*$ ]] && { archive=1; continue; }
    [[ "$line" =~ ^\|[[:space:]]*\[([0-9]{4})\]\(([^\)]+)\) ]] || continue
    number="${BASH_REMATCH[1]}"
    target="${BASH_REMATCH[2]}"
    filename="${target%%#*}"
    applies="$(printf '%s' "$line" | table_cell 3)"
    status="$(printf '%s' "$line" | first_status_emoji)"
    indexed_files+=("$filename")
    indexed_applies+=("$applies")
    indexed_status+=("$status")
    if [[ "$filename" != "$number"-* ]]; then
      add_error "ADR index: row for $number links to '$filename', which does not start with '$number-'"
    fi
    case "$status" in
      ⚪|🔴)
        ((archive)) \
          || add_error "ADR index: row for $number is $status but sits above the 'Superseded and rejected' heading — move it there, a session reads the first table as binding"
        ;;
      🟢|🟡)
        ((archive)) \
          && add_error "ADR index: row for $number is $status but sits below the 'Superseded and rejected' heading — move it up, a binding decision there is never read"
        ;;
    esac
  done < "$ADR_INDEX"

  # Every file on disk must be listed.
  local d
  for d in "${disk_files[@]}"; do
    if ! _contains "$d" "${indexed_files[@]}"; then
      add_error "ADR index: file '$d' exists but is not listed in the index"
    fi
  done

  # Every listed file must exist, and its status and 'Applies to' must match the file.
  local i file_status file_applies
  for i in "${!indexed_files[@]}"; do
    f="${indexed_files[$i]}"
    status="${indexed_status[$i]}"
    applies="${indexed_applies[$i]}"
    if [[ ! -f "$ADR_DIR/$f" ]]; then
      add_error "ADR index: lists '$f', but no such ADR file exists"
      continue
    fi
    file_status="$(status_of "$ADR_DIR/$f" | first_status_emoji)"
    if [[ -z "$file_status" ]]; then
      add_error "$f: no '**Status:**' line with a status emoji found"
    elif [[ "$file_status" != "$status" ]]; then
      add_error "ADR index: status for '$f' is ${status:-<none>} in the index but $file_status in the file"
    fi
    file_applies="$(applies_to_of "$ADR_DIR/$f")"
    if [[ -z "$file_applies" ]]; then
      add_error "$f: no '**Applies to:**' line naming what the decision constrains"
    elif [[ "$file_applies" != "$applies" ]]; then
      add_error "ADR index: 'Applies to' for '$f' is '${applies:-<none>}' in the index but '$file_applies' in the file"
    fi
  done
}

# ADR numbers run 0001..N without gaps, and each file's heading carries its own number.
# Superseded ADRs stay on disk, so a gap can only ever mean a deleted ADR or a botched rename.
check_adr_numbering() {
  local f base number expected heading n=0
  while IFS= read -r f; do
    base="$(basename "$f")"
    number="${base%%-*}"
    n=$((n + 1))
    expected="$(printf '%04d' "$n")"
    if [[ "$number" != "$expected" ]]; then
      add_error "ADR numbering: expected '$expected-*.md' at position $n, found '$base' — numbers must run 0001..N without gaps"
      return
    fi
    heading="$(grep -m1 -oE '^# ADR-[0-9]{4}' "$f")"
    if [[ "$heading" != "# ADR-$number" ]]; then
      add_error "$base: heading says '${heading:-<none>}', but the filename says ADR-$number"
    fi
  done < <(find "$ADR_DIR" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]-*.md' | sort)
}

# status_word_for_emoji <emoji> — the status word that belongs to a legend emoji, empty for
# anything else. The legend itself lives above the index in docs/adr/README.md.
status_word_for_emoji() {
  case "$1" in
    🟢) printf 'accepted' ;;
    🟡) printf 'proposed' ;;
    🔴) printf 'rejected' ;;
    ⚪) printf 'superseded' ;;
  esac
}

# instruction_needle — the opening of the instruction paragraph in docs/adr/template.md: the first
# line of its italic block, without the leading '*' and cut to a phrase. Reading the needle off the
# template instead of hard-coding a sentence is what keeps the check alive when the paragraph is
# reworded — which is what a project does with a template. Empty when the template is gone or
# carries no such block; the sub-check then does not run rather than reporting a phantom.
instruction_needle() {
  local line
  line="$(grep -m1 -E '^\*[^*]' "$ADR_DIR/template.md" 2>/dev/null)" || return 0
  printf '%s' "${line:1:40}"
}

# Every ADR's '**Status:**' line carries exactly one legend emoji plus the word that belongs to it,
# and no ADR still carries the instruction paragraph from template.md. check_adr_index reads the
# status through first_status_emoji, so on its own it would accept a line that kept a list of
# alternatives ('🟡 proposed | 🟢 accepted | …') as whatever stands first, and a line whose word
# and emoji disagree passes there on the strength of the emoji — while the word is what a reader
# believes. A missing or emoji-less status line is left to check_adr_index, which reports it.
check_adr_headers() {
  local f base line count emoji expected word needle
  needle="$(instruction_needle)"
  while IFS= read -r f; do
    base="$(basename "$f")"
    line="$(status_of "$f")"
    emoji="$(printf '%s' "$line" | first_status_emoji)"
    if [[ -n "$emoji" ]]; then
      count="$(printf '%s' "$line" | grep -oE '🟢|🟡|🔴|⚪' | wc -l | tr -d ' ')"
      expected="$(status_word_for_emoji "$emoji")"
      read -r word _ <<<"${line#*"$emoji"}"
      if ((count > 1)); then
        add_error "$base: status line carries $count status emoji — keep exactly one"
      elif [[ "$word" != "$expected" ]]; then
        add_error "$base: status line reads '$emoji ${word:-<nothing>}', but $emoji means '$expected'"
      fi
    fi
    if [[ -n "$needle" ]] && grep -qF "$needle" "$f"; then
      add_error "$base: still carries the instruction paragraph from template.md — delete it"
    fi
  done < <(find "$ADR_DIR" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]-*.md' | sort)
}

# superseding_numbers <status line> — the four-digit numbers every 'superseded by ADR-NNNN' on a
# status line names, one per line, empty when it names none: the whole-supersession flip
# ('⚪ superseded by ADR-NNNN') and every clause suffix ('🟢 accepted · clause 2 superseded by
# ADR-NNNN', ADR-0009) alike. The citation may be plain or a Markdown link, so the bracket is
# optional (docs/adr/README.md asks for the link form).
superseding_numbers() {
  grep -oE 'superseded by \[?ADR-[0-9]{4}' <<<"$1" | grep -oE '[0-9]{4}$'
}

# A supersession is written into two files in one pull request: the new ADR's '**Supersedes:**'
# field and the old ADR's status line (docs/adr/README.md). Nothing else compares
# them — check_adr_index only mirrors the index against whatever status a file carries, so a half
# performed flip passes it. Both directions are verified here; a cited number that names no file
# is left to check_adr_refs, which reports it repository-wide.
# header_field <adr file> <name> — the '**<name>:**' header field with its continuation lines:
# a header field wraps at the line width like any other, and a name on the second line counts.
header_field() {
  awk -v field="- **$2:**" '
    index($0, field) == 1                    { in_field = 1; print; next }
    in_field && /^[[:space:]]+[^[:space:]]/  { print; next }
    in_field                                 { exit }
  ' "$1"
}

# supersedes_field <adr file> — the '**Supersedes:**' header field, wrapped lines included.
supersedes_field() { header_field "$1" Supersedes; }

# supersedes_entries <adr file> — one line per ADR the '**Supersedes:**' field names, starting
# with its number: 'NNNN' for a whole supersession, 'NNNN clause' when the entry names clauses
# (ADR-0009). An entry runs from its ADR's name to the next one, wrapped lines included.
supersedes_entries() {
  supersedes_field "$1" | tr '\n' ' ' | sed -E 's/\[?ADR-([0-9]{4})/\n\1 /g' | tail -n +2 \
    | while read -r nr rest || [[ -n "$nr" ]]; do
        if grep -qE '\bclauses?\b' <<<"$rest"; then echo "$nr clause"; else echo "$nr"; fi
      done
}

check_adr_supersessions() {
  local f base nr line target kind target_file target_line target_emoji succ succ_file
  while IFS= read -r f; do
    base="$(basename "$f")"
    nr="${base%%-*}"
    line="$(status_of "$f")"

    # Forward: every ADR this one claims to supersede — one, several whose decisions it
    # consolidates, or named clauses of one (ADR-0009) — must carry the matching status line: ⚪
    # for a whole supersession, an active status with a clause suffix for a partial one.
    while read -r target kind; do
      [[ -n "$target" ]] || continue
      target_file="$(find "$ADR_DIR" -maxdepth 1 -type f -name "$target-*.md" | head -n1)"
      [[ -n "$target_file" ]] || continue
      target_line="$(status_of "$target_file")"
      target_emoji="$(printf '%s' "$target_line" | first_status_emoji)"
      if ! grep -qx "$nr" <<<"$(superseding_numbers "$target_line")"; then
        add_error "$(basename "$target_file"): $base supersedes it, but its status line does not say 'superseded by ADR-$nr'"
      elif [[ "$kind" == "clause" && "$target_emoji" == "⚪" ]]; then
        add_error "$(basename "$target_file"): $base supersedes only named clauses of it, so it stays active — keep its status and add the clause suffix instead of ⚪"
      elif [[ "$kind" != "clause" && "$target_emoji" != "⚪" ]]; then
        add_error "$(basename "$target_file"): $base supersedes it whole, but its status is $target_emoji — flip it to '⚪ superseded by ADR-$nr', or name the clauses in $base's Supersedes field"
      fi
    done < <(supersedes_entries "$f")

    # Backward: every successor a status line names claims this ADR in its Supersedes field.
    while IFS= read -r succ; do
      [[ -n "$succ" ]] || continue
      succ_file="$(find "$ADR_DIR" -maxdepth 1 -type f -name "$succ-*.md" | head -n1)"
      if [[ -n "$succ_file" ]] && ! grep -qE "^$nr( |$)" <<<"$(supersedes_entries "$succ_file")"; then
        add_error "$(basename "$succ_file"): $base says it supersedes, but it carries no '**Supersedes:**' field naming ADR-$nr"
      fi
    done < <(superseding_numbers "$line")
    if [[ "$(printf '%s' "$line" | first_status_emoji)" == "⚪" ]] && [[ -z "$(superseding_numbers "$line")" ]]; then
      add_error "$base: status is ⚪ but the line names no superseding ADR"
    fi
  done < <(find "$ADR_DIR" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]-*.md' | sort)
}

# Print the GitHub-style slug of every ATX heading in a Markdown file.
extract_heading_slugs() {
  local line text
  while IFS= read -r line; do
    [[ "$line" =~ ^#{1,6}[[:space:]]+(.*)$ ]] || continue
    text="${BASH_REMATCH[1]}"
    # Drop a trailing run of '#' (closed ATX headings), then slugify the way GitHub does:
    # lowercase, remove everything but [a-z0-9 _-], then one hyphen per remaining space. A run of
    # spaces yields a run of hyphens: GitHub drops a character such as "&" and keeps the spaces
    # around it, so "Quality bar & Definition of Done" anchors as "quality-bar--definition-of-done".
    printf '%s\n' "$text" \
      | sed -E 's/[[:space:]]+#*[[:space:]]*$//' \
      | tr '[:upper:]' '[:lower:]' \
      | sed -E 's/[^a-z0-9 _-]+//g; s/[[:space:]]/-/g'
  done < "$1"
}

# anchor_resolves <file> <fragment> — true if the fragment exists in the file.
# Handles GitHub line anchors (Lnn, Lnn-Lmm) for any file and heading-slug anchors for
# Markdown files; any other anchor is unverifiable from disk and is accepted.
anchor_resolves() {
  local file="$1" frag="$2" start end lines slug
  if [[ "$frag" =~ ^L([0-9]+)(-L([0-9]+))?$ ]]; then
    start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[3]:-$start}"
    lines="$(wc -l < "$file")"
    # +1 tolerates a final line with no trailing newline (uncounted by wc -l).
    (( start >= 1 && end >= start && end <= lines + 1 ))
    return
  fi
  case "$file" in
    *.md)
      while IFS= read -r slug; do
        [[ "$slug" == "$frag" ]] && return 0
      done < <(extract_heading_slugs "$file")
      return 1 ;;
    *) return 0 ;;
  esac
}

# strip_code_fences <file> — the file with fenced code blocks (``` / ~~~, also inside
# blockquotes) blanked out: links in fences are illustrations, not claims about files on disk.
# Fenced lines become empty lines, so the output keeps the original line count.
strip_code_fences() {
  awk '
    /^[[:space:]>]*(```|~~~)/ { in_fence = !in_fence; print ""; next }
    in_fence                  { print ""; next }
    { print }
  ' "$1"
}

# link_target <linkexpr> — the target of one '[text](target)' expression: trimmed, with an
# optional trailing '"title"' or "'title'" removed (a link title is not part of the path).
LINK_TITLE_RE="^([^[:space:]]+)[[:space:]]+(\"[^\"]*\"|'[^']*')\$"
link_target() {
  local target
  target="$(printf '%s' "$1" | sed -E 's/^\[[^]]*\]\(([^)]+)\)$/\1/')"
  target="$(printf '%s' "$target" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  [[ "$target" =~ $LINK_TITLE_RE ]] && target="${BASH_REMATCH[1]}"
  printf '%s' "$target"
}

check_relative_links() {
  local md rel linkexpr target path_part frag dir target_file
  for md in "${TEXT_FILES[@]}"; do
    case "$md" in *.md) ;; *) continue ;; esac
    rel="${md#"$ROOT"/}"
    is_inactive_adr "$md" && continue
    dir="$(dirname "$md")"
    while IFS= read -r linkexpr; do
      target="$(link_target "$linkexpr")"
      case "$target" in
        http://*|https://*|mailto:*) continue ;;
      esac
      # 'NNNN' is the placeholder docs/adr/template.md uses where a real ADR carries its number,
      # so such a target names no file and claims none exists — the convention checks 5 and 6
      # follow by matching only references with actual digits.
      case "$target" in *NNNN*) continue ;; esac
      # Split into a path part and an optional '#fragment'. An empty path is a same-file anchor.
      path_part="${target%%#*}"
      frag=""
      [[ "$target" == *"#"* ]] && frag="${target#*#}"
      if [[ -z "$path_part" ]]; then
        target_file="$md"
      else
        target_file="$dir/$path_part"
        if [[ ! -e "$target_file" ]]; then
          add_error "$rel: broken relative link -> '$target'"
          continue
        fi
      fi
      # Validate the anchor fragment against the resolved file, when there is one.
      if [[ -n "$frag" && -f "$target_file" ]]; then
        anchor_resolves "$target_file" "$frag" \
          || add_error "$rel: link '$target' has no matching anchor '#$frag' in ${target_file#"$ROOT"/}"
      fi
    done < <(strip_code_fences "$md" | grep -oE '\[[^]]*\]\([^)]+\)')
  done
}

# Section references point into AGENTS.md, whose sections are numbered '## N.' headings. Inserting
# or removing a section renumbers the ones after it, and a bare '§N' would keep pointing at
# whatever now carries that number — valid-looking and wrong. In Markdown a reference is therefore
# written as a link to the section's own anchor, which carries the number *and* the title
# ('AGENTS.md#3-adr-rules'): renumbering or retitling a section makes that anchor stop resolving,
# and check 3 fails on every reference to it. This check verifies the other half — that the number
# in the text and the anchor the link points at name the same section.
#
# Named gap (AGENTS.md, section 5): outside Markdown there are no links, so a '§N' in a workflow or
# a script comment is still only checked for the number existing. Those references live in files a
# maintainer edits next to AGENTS.md; the weaker guarantee is recorded here rather than hidden.
check_section_refs() {
  local agents="$ROOT/AGENTS.md"
  if [[ ! -f "$agents" ]]; then
    add_error "AGENTS.md not found in the repository root"
    return
  fi

  local valid_sections=()
  local n
  while IFS= read -r n; do
    valid_sections+=("$n")
  done < <(sed -nE 's/^## ([0-9]+)\..*/\1/p' "$agents")
  if ((${#valid_sections[@]} == 0)); then
    add_error "AGENTS.md: no numbered '## N.' section headings found"
    return
  fi

  # The numbering itself: 1..N in order, no gap and no repeat. A botched renumbering is what this
  # catches; that a reference still means the section it meant before is what the anchors do.
  local i expected
  for i in "${!valid_sections[@]}"; do
    expected=$((i + 1))
    if [[ "${valid_sections[$i]}" != "$expected" ]]; then
      add_error "AGENTS.md: numbered sections must run 1..N in order — expected '## $expected.' at position $expected, found '## ${valid_sections[$i]}.'"
      break
    fi
  done

  # The anchor each section carries, read with the same slug rule the link check uses.
  local section_slug=() slug
  while IFS= read -r slug; do
    [[ "$slug" =~ ^([0-9]+)- ]] || continue
    n="${BASH_REMATCH[1]}"
    _contains "$n" "${valid_sections[@]}" && section_slug[n]="$slug"
  done < <(extract_heading_slugs "$agents")

  local f rel lineno line clean linkexpr target frag
  for f in "${TEXT_FILES[@]}"; do
    is_doc_file "$f" || continue
    rel="${f#"$ROOT"/}"
    is_inactive_adr "$f" && continue

    case "$f" in
      *.md)
        lineno=0
        while IFS= read -r line; do
          lineno=$((lineno + 1))
          # Inline code spans hold literals, not citations: '`§1`' in a sentence about references
          # is the notation itself. Dropping them also strips the '`AGENTS.md`' inside a link text,
          # which leaves the link expression itself intact.
          # shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
          line="$(sed -E 's/`[^`]*`//g' <<< "$line")"
          # A citation into an external spec (e.g. 'RFC 9110 §11') reuses the section sign for a
          # document outside this repository — accept it unverified, like an external link.
          line="$(sed -E 's/RFC [0-9]+ §[0-9]+//g' <<< "$line")"
          [[ "$line" == *§* ]] || continue
          while IFS= read -r linkexpr; do
            [[ "$linkexpr" =~ §([0-9]+) ]] || continue
            n="${BASH_REMATCH[1]}"
            if ! _contains "$n" "${valid_sections[@]}"; then
              add_error "$rel:$lineno: reference '§$n' matches no numbered section in AGENTS.md"
              continue
            fi
            target="$(link_target "$linkexpr")"
            frag=""
            [[ "$target" == *"#"* ]] && frag="${target#*#}"
            if [[ -z "$frag" ]]; then
              add_error "$rel:$lineno: '§$n' is cited without an anchor — point the link at '#${section_slug[$n]}'"
            elif [[ "$frag" != "${section_slug[$n]}" ]]; then
              add_error "$rel:$lineno: '§$n' links to anchor '#$frag', but section $n of AGENTS.md anchors as '#${section_slug[$n]}'"
            fi
          done < <(grep -oE '\[[^]]*\]\([^)]+\)' <<< "$line")
          # What is left once every link is removed is a reference nothing verifies.
          clean="$(sed -E 's/\[[^]]*\]\([^)]+\)//g' <<< "$line")"
          while IFS= read -r n; do
            if _contains "$n" "${valid_sections[@]}"; then
              add_error "$rel:$lineno: '§$n' stands outside a link — cite a section as a link to its anchor, e.g. [\`AGENTS.md\` §$n](AGENTS.md#${section_slug[$n]})"
            else
              add_error "$rel:$lineno: reference '§$n' matches no numbered section in AGENTS.md"
            fi
          done < <(grep -oE '§[0-9]+' <<< "$clean" | tr -d '§')
        done < <(strip_code_fences "$f")
        ;;
      *)
        while IFS=: read -r lineno line; do
          # A citation into an external spec (e.g. 'RFC 9110 §11') is accepted unverified.
          [[ "$line" == RFC\ * ]] && continue
          n="${line#§}"
          _contains "$n" "${valid_sections[@]}" \
            || add_error "$rel:$lineno: reference '§$n' matches no numbered section in AGENTS.md"
        done < <(grep -noE '(RFC [0-9]+ )?§[0-9]+' "$f")
        ;;
    esac
  done
}

# Every 'ADR-NNNN' reference (with digits — the literal 'ADR-NNNN' placeholder never matches)
# must name an ADR file that already exists. Anticipated follow-up decisions are described by
# topic, not by a reserved number (docs/adr/README.md).
check_adr_refs() {
  local f rel lineno match number
  for f in "${TEXT_FILES[@]}"; do
    rel="${f#"$ROOT"/}"
    [[ "$f" == "$ADR_DIR/template.md" ]] && continue
    is_inactive_adr "$f" && continue
    while IFS=: read -r lineno match; do
      number="${match#ADR-}"
      if ! compgen -G "$ADR_DIR/$number-*.md" > /dev/null; then
        add_error "$rel:$lineno: reference '$match' matches no ADR file in docs/adr/"
      fi
    done < <(grep -noE 'ADR-[0-9]{4}' "$f")
  done
}

# A Markdown link that cites 'ADR-NNNN' in its text must point at that ADR's own file. Both
# halves resolve on their own — the number names a file that exists, the target is a file that
# exists — so a renumbering, a copied line, or a consolidated decision set leaves the two naming
# different ADRs without any single check noticing. Only links into docs/adr/ are compared; a
# reference that deliberately points elsewhere (an index, a section about the decision) is left
# alone.
check_adr_link_targets() {
  local f rel linkexpr text target base number
  for f in "${TEXT_FILES[@]}"; do
    case "$f" in *.md) ;; *) continue ;; esac
    rel="${f#"$ROOT"/}"
    [[ "$f" == "$ADR_DIR/template.md" ]] && continue
    is_inactive_adr "$f" && continue
    while IFS= read -r linkexpr; do
      text="$(printf '%s' "$linkexpr" | sed -E 's/^\[([^]]*)\].*$/\1/')"
      [[ "$text" =~ ADR-([0-9]{4}) ]] || continue
      number="${BASH_REMATCH[1]}"
      target="$(link_target "$linkexpr")"
      base="$(basename "${target%%#*}")"
      # Compare only against ADR filenames; anything else is not a claim about which ADR it is.
      case "$base" in [0-9][0-9][0-9][0-9]-*.md) ;; *) continue ;; esac
      if [[ "$base" != "$number"-* ]]; then
        add_error "$rel: link '$linkexpr' cites ADR-$number but points at '$base'"
      fi
    done < <(strip_code_fences "$f" | grep -oE '\[[^]]*\]\([^)]+\)')
  done
}

# The three places that list this repository's checks have to agree: the jobs in
# .github/workflows/checks.yml, the invocations in scripts/check-all.sh, and the required status
# checks named in README.md. AGENTS.md, section 5 makes check-all.sh the local equivalent of the
# workflow, and the README list is what a maintainer configures the ruleset from — a check that
# runs in only one of the three is a gate somebody believes in and does not have. Both files say
# in their own header that a check added to one is added to the other in the same change; this is
# that sentence, verified. The README may name a job of the CI workflow besides: a gate on
# another platform, which the local runner cannot run and so is not compared with it.
check_check_lists() {
  local rel_wf=".github/workflows/checks.yml" rel_all="scripts/check-all.sh"
  local rel_ci=".github/workflows/ci.yml"
  local wf="$ROOT/$rel_wf" all="$ROOT/$rel_all" readme="$ROOT/README.md"
  local f
  for f in "$wf" "$all" "$readme"; do
    if [[ ! -f "$f" ]]; then
      add_error "${f#"$ROOT"/}: not found — the check lists cannot be compared"
      return
    fi
  done

  # The workflow: job names at two-space indent under 'jobs:', and the check script each job runs.
  # A job that runs no script under scripts/ — its commands written inline — is work CI does and
  # the local gate cannot: the toolchain job of a derived project, written that way, left the
  # pre-push hook without the build and the tests while the two lists still agreed.
  local line job="" job_scripts=0 in_jobs=0
  local wf_jobs=() wf_scripts=()
  # job_done — report the job just parsed when none of its steps ran a script.
  job_done() {
    [[ -n "$job" ]] && ((job_scripts == 0)) \
      && add_error "$rel_wf: job '$job' runs no script under scripts/ — the local gate cannot run what it does"
  }
  while IFS= read -r line; do
    [[ "$line" == "jobs:"* ]] && { in_jobs=1; continue; }
    ((in_jobs)) || continue
    if [[ "$line" =~ ^\ \ ([a-z][a-z0-9-]*):[[:space:]]*$ ]]; then
      job_done
      job="${BASH_REMATCH[1]}"
      job_scripts=0
      wf_jobs+=("$job")
      continue
    fi
    [[ "$line" =~ run:[[:space:]]+bash[[:space:]]+(scripts/[A-Za-z0-9._-]+\.sh) ]] \
      && { wf_scripts+=("${BASH_REMATCH[1]}"); job_scripts=$((job_scripts + 1)); }
  done < "$wf"
  job_done
  if ((${#wf_jobs[@]} == 0)); then
    add_error "$rel_wf: no jobs found under 'jobs:' — the check lists cannot be compared"
    return
  fi

  # The local runner: every 'run <label> <script>' line.
  local all_scripts=()
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*run[[:space:]]+\"[^\"]*\"[[:space:]]+(scripts/[A-Za-z0-9._-]+\.sh) ]] \
      && all_scripts+=("${BASH_REMATCH[1]}")
  done < "$all"
  if ((${#all_scripts[@]} == 0)); then
    add_error "$rel_all: no 'run <label> <script>' invocations found — the check lists cannot be compared"
    return
  fi

  local s
  for s in "${wf_scripts[@]}"; do
    _contains "$s" "${all_scripts[@]}" \
      || add_error "$rel_all: does not run '$s', which $rel_wf runs — CI and the local gate disagree"
  done
  for s in "${all_scripts[@]}"; do
    _contains "$s" "${wf_scripts[@]}" \
      || add_error "$rel_wf: has no job running '$s', which $rel_all runs — CI and the local gate disagree"
  done

  # The README: the job names fenced by the 'required-checks' markers, which a maintainer copies
  # into the ruleset. Rulesets name checks by job name, so a name that is not a job is a required
  # check that never reports and blocks every pull request.
  local in_block=0 name readme_names=()
  while IFS= read -r line; do
    [[ "$line" == *"required-checks begin"* ]] && { in_block=1; continue; }
    [[ "$line" == *"required-checks end"* ]] && { in_block=0; continue; }
    ((in_block)) || continue
    # shellcheck disable=SC2016  # the backticks are literal Markdown, not a command substitution
    while IFS= read -r name; do
      readme_names+=("$name")
    done < <(grep -oE '`[a-z][a-z0-9-]*`' <<< "$line" | tr -d '`')
  done < "$readme"
  if ((${#readme_names[@]} == 0)); then
    add_error "README.md: no job names between the 'required-checks' markers — the required status checks are unverifiable"
    return
  fi

  # The CI workflow: its job ids, and those whose check carries another name — a job with a
  # 'name:' of its own, or a matrix, which appends its values to the name.
  local ci_jobs=() ci_renamed=() ci_job=""
  if [[ -f "$ROOT/$rel_ci" ]]; then
    in_jobs=0
    while IFS= read -r line; do
      [[ "$line" == "jobs:"* ]] && { in_jobs=1; continue; }
      ((in_jobs)) || continue
      if [[ "$line" =~ ^\ \ ([a-z][a-z0-9-]*):[[:space:]]*$ ]]; then
        ci_job="${BASH_REMATCH[1]}"
        ci_jobs+=("$ci_job")
        continue
      fi
      [[ -n "$ci_job" && "$line" =~ ^\ \ \ \ (name|strategy): ]] && ci_renamed+=("$ci_job")
    done < "$ROOT/$rel_ci"
  fi

  for name in "${readme_names[@]}"; do
    _contains "$name" "${wf_jobs[@]}" && continue
    if ((${#ci_jobs[@]})) && _contains "$name" "${ci_jobs[@]}"; then
      ((${#ci_renamed[@]})) && _contains "$name" "${ci_renamed[@]}" \
        && add_error "README.md: required check '$name' is a job in $rel_ci with a 'name:' or a matrix — its check reports under another name, and a ruleset would wait for one that never reports"
      continue
    fi
    add_error "README.md: required check '$name' is not a job in $rel_wf or $rel_ci — a ruleset would wait for a check that never reports"
  done
  for job in "${wf_jobs[@]}"; do
    _contains "$job" "${readme_names[@]}" \
      || add_error "README.md: job '$job' of $rel_wf is missing from the required checks — it would run without gating a merge"
  done
}

# The Project Layout block in README.md is a hand-written inventory, and nothing tells a reader
# that a line of it has gone stale: a renamed or deleted path leaves the block describing a
# repository that no longer exists. Every path it lists therefore has to exist, a trailing '/'
# meaning a directory.
#
# Only that direction is checked. The block is a tour of the parts a newcomer needs, not a listing
# of every file, so a path missing from it is an editorial judgment rather than a defect.
check_project_layout() {
  local readme="$ROOT/README.md"
  if [[ ! -f "$readme" ]]; then
    add_error "README.md: not found — the Project Layout block cannot be checked"
    return
  fi

  local line path in_section=0 in_fence=0 entries=0
  while IFS= read -r line; do
    if ((!in_section)); then
      [[ "$line" == "## Project Layout" ]] && in_section=1
      continue
    fi
    if ((!in_fence)); then
      [[ "$line" =~ ^(\`\`\`|~~~) ]] && { in_fence=1; continue; }
      # A new heading before the fence means the section holds no block at all.
      [[ "$line" =~ ^##[[:space:]] ]] && break
      continue
    fi
    [[ "$line" =~ ^(\`\`\`|~~~) ]] && break
    path="${line%%[[:space:]]*}"
    # Blank lines and the continuation lines of a wrapped comment carry no path.
    [[ -z "$path" || "$path" == "#"* ]] && continue
    entries=$((entries + 1))
    if [[ "$path" == */ ]]; then
      [[ -d "$ROOT/${path%/}" ]] \
        || add_error "README.md: Project Layout lists '$path', which is not a directory of this repository"
    else
      [[ -f "$ROOT/$path" ]] \
        || add_error "README.md: Project Layout lists '$path', which does not exist"
    fi
  done < "$readme"

  if ((entries == 0)); then
    add_error "README.md: no paths found under '## Project Layout' — the inventory is unverifiable"
  fi
}

# Check 11 (see the header). A pointer is resolved with 'cd -P', which every shell has, rather
# than realpath, whose flags differ between GNU and BSD.
check_skill_pointers() {
  local skills="$ROOT/.agents/skills" pointers="$ROOT/.claude/skills"
  local d name p target want
  for d in "$skills"/*/; do
    [[ -f "$d/SKILL.md" ]] || continue
    name="$(basename "$d")"
    p="$pointers/$name"
    if [[ -L "$p" ]]; then
      continue
    elif [[ -e "$p" ]]; then
      add_error ".claude/skills/$name: is a copy of the skill, not a symlink — a second source drifts; replace it: rm -r .claude/skills/$name && ln -s ../../.agents/skills/$name .claude/skills/$name"
    else
      add_error ".claude/skills/$name: no pointer — the skill .agents/skills/$name is invisible to Claude Code; add it: ln -s ../../.agents/skills/$name .claude/skills/$name"
    fi
  done
  for p in "$pointers"/*; do
    [[ -e "$p" || -L "$p" ]] || continue
    name="$(basename "$p")"
    if [[ ! -L "$p" ]]; then
      # A copy of an existing skill was reported above; what is left is a skill living here only.
      [[ -f "$skills/$name/SKILL.md" ]] \
        || add_error ".claude/skills/$name: is not a symlink into .agents/skills/ — a skill lives there, where every agent reads it, and is pointed at from here (ADR-0005)"
      continue
    fi
    if ! target="$(cd -P "$p" 2>/dev/null && pwd -P)"; then
      add_error ".claude/skills/$name: dangles — its target does not exist; point it at .agents/skills/$name or delete it"
      continue
    fi
    want="$(cd -P "$skills/$name" 2>/dev/null && pwd -P)"
    [[ -n "$want" && "$target" == "$want" && -f "$want/SKILL.md" ]] \
      || add_error ".claude/skills/$name: points at '${target#"$ROOT"/}', not at the skill .agents/skills/$name"
  done
}

# Check 12 (see the header). Inherited means the Deciders field still names the template's
# maintainer, on whichever of its lines; a derived project's own ADRs never do.
check_inherited_adrs() {
  [[ -f "$ROOT/TEMPLATE-SETUP.md" ]] && return
  local f base
  while IFS= read -r f; do
    header_field "$f" Deciders | grep -qF 'NUC maintainer' || continue
    [[ "$(status_of "$f" | first_status_emoji)" == "🟡" ]] || continue
    base="$(basename "$f")"
    add_error "$base: inherited from the template and still proposed after setup — accept it with your name in Deciders and the status flipped, or supersede it (docs/adr/README.md)"
  done < <(find "$ADR_DIR" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]-*.md' | sort)
}

# Check 13 (see the header). Each placeholder is a pattern in one file; the file is skipped when
# it does not exist, so a project that dropped one of them is not asked to edit it.
check_template_identity() {
  [[ -f "$ROOT/TEMPLATE-SETUP.md" ]] && return
  # placeholder <file> <grep -E pattern> <message>
  placeholder() {
    [[ -f "$ROOT/$1" ]] || return 0
    grep -qE "$2" "$ROOT/$1" && add_error "$1: $3"
  }
  placeholder README.md '^# NUC — an Agentic' "the title is still the template's; give the project its name"
  # Anchored to the workflow path of the badge: the Template section links the template's
  # repository on purpose, and that link stays.
  placeholder README.md 'github\.com/hivevm/nuc/actions/workflows/' "the badge still points at the template's repository; repoint or delete it"
  placeholder .devcontainer/devcontainer.json '"name": "NUC DevContainer"' "the Dev Container still carries the template's name"
  placeholder LICENSE '^Copyright\b.*\bMaintainer\b' "the copyright holder is still the placeholder; name the maintainer"
  placeholder SECURITY.md 'TODO: add a security contact' "the security contact is still the placeholder"
}

# Check 14 (see the header). The first matching line is read; a Markdown list marker before the
# bold label is allowed, the version may be written as a link or in backticks, and what follows
# it — a sentence, a link target — is not read. After the version only a space, a punctuation
# mark, or the end of the line may follow: a pre-release suffix, build metadata, and a fourth
# number are not a tag ADR-0008 cuts, and SemVer allows no leading zero.
check_template_release() {
  local readme="$ROOT/README.md"
  [[ -f "$readme" ]] || return   # check 10 reports the missing README
  local line value
  line="$(grep -m1 -E '^[[:space:]]*([-*] )?\*\*Template release:\*\*' "$readme")"
  if [[ -z "$line" ]]; then
    add_error "README.md: no '**Template release:**' line — the Template section names the release of the template this repository carries, or 'unreleased' (ADR-0008)"
    return
  fi
  value="${line#*\*\*Template release:\*\*}"
  value="${value#"${value%%[![:space:]]*}"}"
  local num='(0|[1-9][0-9]*)'
  # shellcheck disable=SC2016  # the backticks are Markdown to match, not a command substitution
  local re='^[[`]?(v'"$num"'\.'"$num"'\.'"$num"'|unreleased)($|[][:space:],;:)`]|\.([[:space:]]|$))'
  [[ "$value" =~ $re ]] \
    || add_error "README.md: the Template release line names neither a 'vX.Y.Z' tag nor 'unreleased' — a release moves it to the tag it cuts (ADR-0008)"
}

# The Protocol Baseline — the pinned upstream opamp-spec version all protocol code is written
# against (ADR-0011) — must stay a deliberate choice. scripts/check-protocol-baseline.sh holds the
# check, so its own self-test can drive it against fixtures; here its lines become this report's.
check_protocol_baseline() {
  local helper="$ROOT/scripts/check-protocol-baseline.sh" output rc line said=0
  if [[ ! -r "$helper" ]]; then
    add_error "scripts/check-protocol-baseline.sh is missing — the Protocol Baseline check cannot run"
    return
  fi
  output="$(bash "$helper" "$CONFORMANCE" 2>&1)"; rc=$?
  while IFS= read -r line; do
    case "$line" in
      "Error: "*) add_error "${line#Error: }"; said=1 ;;
      "Warning: "*) add_warning "${line#Warning: }" ;;
      ?*) echo "$line" ;;
    esac
  done <<< "$output"
  # A failure that names no error is the check not running, which must not read as a pass.
  if ((rc != 0 && !said)); then
    add_error "scripts/check-protocol-baseline.sh failed (exit $rc) without naming an error"
  fi
}

# Check 16 (see the header). Every line is read, code fences included: a citation in an example is
# still one an operator follows.
check_manual_cites_no_adr() {
  local dir="$ROOT/docs/manual" file hit
  [[ -d "$dir" ]] || return
  while IFS= read -r file; do
    while IFS= read -r hit; do
      add_error "${file#"$ROOT"/}:${hit%%:*}: cites an ADR — the manual says what to do and why it matters to an operator; the decision record stays in docs/adr/"
    done < <(grep -nE 'ADR-[0-9]{4}|(^|[(/])\.\./adr/|docs/adr/' "$file")
  done < <(find "$dir" -type f -name '*.md' | sort)
}

collect_text_files
check_adr_index
check_adr_numbering
check_adr_headers
check_adr_supersessions
check_relative_links
check_section_refs
check_adr_refs
check_adr_link_targets
check_check_lists
check_project_layout
check_skill_pointers
check_inherited_adrs
check_template_identity
check_template_release
check_manual_cites_no_adr
((OWN_REPOSITORY)) && check_protocol_baseline

if ((${#warnings[@]} > 0)); then
  echo "Warnings:"
  echo
  for w in "${warnings[@]}"; do echo "  - $w"; done
  echo
fi

if ((${#errors[@]} > 0)); then
  echo "Documentation checks FAILED:"
  echo
  for e in "${errors[@]}"; do echo "  - $e"; done
  echo
  echo "${#errors[@]} problem(s) found."
  exit 1
fi

echo "Documentation checks passed."
exit 0
