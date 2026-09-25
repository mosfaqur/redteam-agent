#!/usr/bin/env bash
# check_finding_case_linkage.sh — every finding must trace back to the queue row
# that produced it. A finding with no **Case** field (or a case id that does not
# exist in cases.db) is rejected so results can be re-tested, re-scoped, and
# deduplicated from the queue instead of being one-off prose.
set -euo pipefail

ENG_DIR="${1:?usage: check_finding_case_linkage.sh <engagement_dir>}"
FINDINGS_FILE="$ENG_DIR/findings.md"
DB_FILE="$ENG_DIR/cases.db"

# Legacy engagements (created before this gate existed) have no **Case** fields.
# REDTEAM_SKIP_FINDING_CASE_LINKAGE=1 downgrades the check to a warning and is
# only valid for those pre-existing workspaces.
SKIP_LINKAGE="${REDTEAM_SKIP_FINDING_CASE_LINKAGE:-0}"

[[ -f "$FINDINGS_FILE" ]] || { echo "findings.md not found in $ENG_DIR" >&2; exit 1; }

if [[ ! -f "$DB_FILE" ]]; then
    echo "cases.db not found in $ENG_DIR" >&2
    exit 1
fi

if [[ "$SKIP_LINKAGE" == "1" ]]; then
    finding_count="$(rg -c '^## \[FINDING-[A-Z]{2}-[0-9]{3}\]' "$FINDINGS_FILE" 2>/dev/null || printf '0')"
    printf 'WARN: finding case linkage skipped via REDTEAM_SKIP_FINDING_CASE_LINKAGE=1 (%s finding(s) unverified)\n' "${finding_count:-0}" >&2
    exit 0
fi

sql() { sqlite3 "$DB_FILE" ".timeout 5000" "$1" 2>/dev/null || printf ''; }

failures=0

while IFS=$'\t' read -r finding_id case_field; do
    [[ -n "$finding_id" ]] || continue

    if [[ -z "$case_field" ]]; then
        printf 'finding %s has no **Case** field (use the cases.db id, or `n/a — <reason>`)\n' "$finding_id" >&2
        failures=1
        continue
    fi

    if [[ "$case_field" =~ ^n/a([[:space:]]|$) ]]; then
        reason="${case_field#n/a}"
        reason="$(printf '%s' "$reason" | sed -E 's/^[[:space:]]*[-—:]*[[:space:]]*//')"
        if [[ -z "$reason" ]]; then
            printf 'finding %s uses `n/a` without a reason\n' "$finding_id" >&2
            failures=1
        fi
        continue
    fi

    # Accept `12`, `case 12`, `cases 12,13`, `12,13` — verify each id exists.
    normalized="$(printf '%s' "$case_field" | tr '[:upper:]' '[:lower:]' | sed -E 's/\bcases?\b//g; s/[^0-9, ]//g')"
    ids="$(printf '%s' "$normalized" | tr ' ,' '\n\n' | rg -o '^[0-9]+$' | sort -u | tr '\n' ' ' || true)"
    if [[ -z "$ids" ]]; then
        printf 'finding %s has an unparseable **Case** value: %s\n' "$finding_id" "$case_field" >&2
        failures=1
        continue
    fi

    for case_id in $ids; do
        if [[ "$(sql "SELECT COUNT(*) FROM cases WHERE id=${case_id};")" != "1" ]]; then
            printf 'finding %s references case %s which does not exist in cases.db\n' "$finding_id" "$case_id" >&2
            failures=1
        fi
    done
done < <(python3 - "$FINDINGS_FILE" <<'PY'
import re
import sys

path = sys.argv[1]
current = None
case_value = None
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        heading = re.match(r"^## \[(FINDING-[A-Z]{2}-[0-9]{3})\]", line)
        if heading:
            if current:
                print(f"{current}\t{case_value or ''}")
            current = heading.group(1)
            case_value = None
            continue
        if current and case_value is None:
            field = re.match(r"^\s*[-*]\s+\*\*Case\*\*\s*:\s*(.+?)\s*$", line)
            if field:
                case_value = field.group(1)
    if current:
        print(f"{current}\t{case_value or ''}")
PY
)

if ((failures != 0)); then
    exit 1
fi

finding_count="$(rg -c '^## \[FINDING-[A-Z]{2}-[0-9]{3}\]' "$FINDINGS_FILE" 2>/dev/null || printf '0')"
printf 'finding case linkage: ok (%s finding(s) traced)\n' "${finding_count:-0}"
