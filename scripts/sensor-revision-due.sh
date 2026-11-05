#!/usr/bin/env bash
#
# Sensor: design revision due (ADR-0004).
#
# Reads the 'Last design revision' line of docs/ARCHITECTURE.md — the date of the last revision,
# or 'none yet', and the number of changes after which the next is due — counts the commits since
# that date that touch anything outside docs/, merges excluded, and reports the count and whether
# the revision is due. When it is, the directories those commits touched are listed: they are
# the scope the design-revision skill takes. It reports and never fails on the count; it fails
# when the line is missing or unreadable, because then it measures nothing.
#
# The line:  **Last design revision:** <YYYY-MM-DD or none yet>, due after <N> changes.
#
# Pure bash + git + coreutils. Usage:
#     scripts/sensor-revision-due.sh [repository root]
# The root defaults to this repository; scripts/test-sensor-revision-due.sh passes fixtures.
# Exit code 0 when the line was read, 1 otherwise.

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
OVERVIEW="docs/ARCHITECTURE.md"
LINE_RE='\*\*Last design revision:\*\*[[:space:]]+([0-9]{4}-[0-9]{2}-[0-9]{2}|none yet),[[:space:]]+due after[[:space:]]+([1-9][0-9]*)[[:space:]]+changes\.'

if [[ ! -f "$ROOT/$OVERVIEW" ]]; then
  echo "Design revision sensor: $OVERVIEW not found — the 'Last design revision' line lives there (ADR-0004)." >&2
  exit 1
fi
line="$(grep -m1 -F '**Last design revision:**' "$ROOT/$OVERVIEW")"
if [[ -z "$line" ]]; then
  echo "Design revision sensor: $OVERVIEW has no '**Last design revision:**' line — add one: '**Last design revision:** none yet, due after 20 changes.' (ADR-0004)" >&2
  exit 1
fi
if ! [[ "$line" =~ $LINE_RE ]]; then
  echo "Design revision sensor: the 'Last design revision' line of $OVERVIEW is unreadable — it reads '<YYYY-MM-DD or none yet>, due after <N> changes.' (ADR-0004)" >&2
  exit 1
fi
date="${BASH_REMATCH[1]}"
number="${BASH_REMATCH[2]}"

since=()
[[ "$date" == "none yet" ]] || since=(--since="$date")
if git -C "$ROOT" rev-parse --verify -q HEAD >/dev/null; then
  count="$(git -C "$ROOT" rev-list --count --no-merges "${since[@]}" HEAD -- . ':(exclude)docs')"
else
  count=0
fi

from="the first commit"
[[ "$date" == "none yet" ]] || from="$date"
if ((count < number)); then
  echo "Design revision sensor: $count of $number changes outside docs/ since $from — not yet due."
  exit 0
fi
echo "Design revision sensor: $count changes outside docs/ since $from, due after $number — DUE: run the design-revision skill over the directories they touched, then move the line (ADR-0004)."
git -C "$ROOT" log --no-merges "${since[@]}" --name-only --format= HEAD -- . ':(exclude)docs' \
  | awk -F/ 'NF { print (NF > 1 ? $1 "/" : $1) }' | sort | uniq -c | sort -rn \
  | awk '{ printf "  - %s (%s)\n", $2, $1 }'
exit 0
