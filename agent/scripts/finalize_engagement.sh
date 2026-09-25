#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/time.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/scope.sh"

EMIT_RUNTIME_EVENT="${EMIT_RUNTIME_EVENT:-$SCRIPT_DIR/emit_runtime_event.sh}"

ENG_DIR="${1:?usage: finalize_engagement.sh <engagement_dir>}"
SCOPE_FILE="$ENG_DIR/scope.json"
LOG_FILE="$ENG_DIR/log.md"
REPORT_FILE="$ENG_DIR/report.md"
DB_FILE="$ENG_DIR/cases.db"

[[ -f "$SCOPE_FILE" ]] || { echo "scope.json not found in $ENG_DIR" >&2; exit 1; }
[[ -f "$LOG_FILE" ]] || { echo "log.md not found in $ENG_DIR" >&2; exit 1; }

trim_whitespace() {
    local value="${1:-}"
    printf '%s' "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

continuous_target_matches() {
    local configured target hostname rule normalized_rule target_host
    configured="$(trim_whitespace "${REDTEAM_CONTINUOUS_TARGETS:-${CONTINUOUS_OBSERVATION_TARGETS:-}}")"
    [[ -n "$configured" ]] || return 1

    target="$(jq -r '.target // empty' "$SCOPE_FILE" 2>/dev/null || true)"
    hostname="$(jq -r '.hostname // empty' "$SCOPE_FILE" 2>/dev/null || true)"
    target_host="$(python3 - <<'PY' "$target"
from urllib.parse import urlsplit
import sys
value = sys.argv[1].strip()
if not value:
    raise SystemExit(0)
try:
    print(urlsplit(value).hostname or "")
except ValueError:
    print("")
PY
)"

    while IFS= read -r rule; do
        normalized_rule="$(trim_whitespace "$rule")"
        [[ -n "$normalized_rule" ]] || continue

        if [[ "$normalized_rule" == re:* ]]; then
            normalized_rule="${normalized_rule#re:}"
            if [[ "$target" =~ $normalized_rule ]] || [[ -n "$hostname" && "$hostname" =~ $normalized_rule ]] || [[ -n "$target_host" && "$target_host" =~ $normalized_rule ]]; then
                return 0
            fi
            continue
        fi

        if [[ "$normalized_rule" == *'*'* || "$normalized_rule" == *'?'* ]]; then
            if [[ "$target" == $normalized_rule ]] || [[ -n "$hostname" && "$hostname" == $normalized_rule ]] || [[ -n "$target_host" && "$target_host" == $normalized_rule ]]; then
                return 0
            fi
            continue
        fi

        if [[ "$target" == "$normalized_rule" ]] || [[ -n "$hostname" && "$hostname" == "$normalized_rule" ]] || [[ -n "$target_host" && "$target_host" == "$normalized_rule" ]]; then
            return 0
        fi
    done < <(printf '%s\n' "$configured" | tr ',;' '\n')

    return 1
}

observation_interval_seconds() {
    local raw="${OBSERVATION_SECONDS:-300}"
    if [[ "$raw" =~ ^[0-9]+$ ]] && (( raw > 0 )); then
        printf '%s\n' "$raw"
    else
        printf '300\n'
    fi
}

mark_scope_in_progress_for_observation() {
    local tmp_scope
    tmp_scope="$(mktemp "${TMPDIR:-/tmp}/scope-observation.XXXXXX")"
    jq '
      .status = "in_progress"
      | .current_phase = "report"
      | del(.end_time)
      | .phases_completed = (((.phases_completed // []) + ["report"]) | unique)
    ' "$SCOPE_FILE" >"$tmp_scope"
    mv "$tmp_scope" "$SCOPE_FILE"
    if [[ -f "$EMIT_RUNTIME_EVENT" ]]; then
        bash "$EMIT_RUNTIME_EVENT" \
            "phase.entered" \
            "report" \
            "phase-transition" \
            "operator" \
            "entering report phase" \
            --kind phase_enter \
            --payload-json '{"phase":"report"}' || true
    fi
}

mark_log_in_progress_for_observation() {
    local tmp_log
    tmp_log="$(mktemp "${TMPDIR:-/tmp}/log-observation.XXXXXX")"
    awk '
      /^- \*\*Status\*\*:/ { print "- **Status**: In Progress"; next }
      { print }
    ' "$LOG_FILE" >"$tmp_log"
    mv "$tmp_log" "$LOG_FILE"
}

mark_report_in_progress_for_observation() {
    [[ -f "$REPORT_FILE" ]] || return 0
    local start_time eng_date tmp_report
    start_time="$(jq -r '.start_time // empty' "$SCOPE_FILE" 2>/dev/null || true)"
    if [[ -n "$start_time" ]]; then
        eng_date="$(engagement_header_date_from_utc "$start_time")"
    else
        eng_date="$(engagement_header_date_today)"
    fi
    tmp_report="$(mktemp "${TMPDIR:-/tmp}/report-observation.XXXXXX")"
    awk -v date_line="**Date**: ${eng_date} — In Progress" '
      BEGIN { date_done = 0 }
      /^\*\*Date\*\*:/ {
          print date_line
          date_done = 1
          next
      }
      /^\*\*Target\*\*:/ {
          sub(/\*\*Status\*\*: .*/, "**Status**: In Progress")
          print
          next
      }
      /^\*\*Status\*\*:/ {
          print "**Status**: In Progress"
          next
      }
      { print }
      END {
          if (!date_done) {
              print date_line
          }
      }
    ' "$REPORT_FILE" >"$tmp_report"
    mv "$tmp_report" "$REPORT_FILE"
}

append_observation_hold_log_entry() {
    local interval target
    interval="$(observation_interval_seconds)"
    target="$(jq -r '.target // empty' "$SCOPE_FILE" 2>/dev/null || true)"
    if [[ -x "$SCRIPT_DIR/append_log_entry.sh" ]]; then
        "$SCRIPT_DIR/append_log_entry.sh" "$ENG_DIR" operator "Observation hold active" \
            "entered continuous observation hold" \
            "runtime attached for ${target:-unknown target}; heartbeat every ${interval}s" >/dev/null 2>&1 || true
    fi
}

# Lab objective closure gate. The operator prompt is the primary control, but
# finalize is the last safe gate: a run must not be marked complete while a
# fresh live objective snapshot still shows an unresolved checklist item.
# The checklist and solved-state source come from the resolved lab profile
# (engagements/<...>/lab-profile.json) via scripts/lab_objective.py, so this
# works for any lab (challenge API, scoreboard, flags, or declared objectives).
recall_finalize_guard() {
    local guard output status reason
    [[ "${REDTEAM_SKIP_RECALL_FINALIZE_GUARD:-0}" == "1" ]] && return 0

    guard="$SCRIPT_DIR/lab_objective.py"
    [[ -f "$guard" ]] || return 0
    command -v python3 >/dev/null 2>&1 || return 0

    status=0
    output="$(python3 "$guard" guard "$ENG_DIR" 2>&1)" || status=$?
    [[ $status -eq 0 ]] && return 0

    reason="${output#BLOCK }"
    [[ -n "$reason" ]] || reason="objective snapshot unavailable"
    if [[ -x "$SCRIPT_DIR/append_log_entry.sh" ]]; then
        "$SCRIPT_DIR/append_log_entry.sh" "$ENG_DIR" operator "Run stop" \
            "stop_reason=queue_incomplete" \
            "Lab objective finalize guard blocked completion; unresolved objectives: $reason" >/dev/null 2>&1 || true
    fi
    printf 'Lab objective finalize guard blocked completion; unresolved objectives: %s\n' "$reason" >&2
    exit 2
}

report_freshness_guard() {
    [[ "${REDTEAM_SKIP_REPORT_FRESHNESS_GUARD:-0}" == "1" ]] && return 0

    local findings_file="$ENG_DIR/findings.md"
    local source_count=0
    local report_epoch findings_epoch
    local reasons=()
    local marker source_reported

    if [[ -f "$findings_file" ]]; then
        source_count="$(rg -c '^## \[FINDING-[A-Z]{2}-[0-9]{3}\]' "$findings_file" 2>/dev/null || printf '0')"
        source_count="${source_count:-0}"
    fi

    if [[ ! -f "$REPORT_FILE" ]]; then
        reasons+=("report.md is missing; dispatch report-writer before finalizing")
    else
        if rg -q 'Engagement Report \(PARTIAL' "$REPORT_FILE" 2>/dev/null; then
            reasons+=("report.md is still the compose_partial_report.sh partial stub; dispatch report-writer before finalizing")
        fi
        if [[ -f "$findings_file" ]]; then
            report_epoch="$(stat -c %Y "$REPORT_FILE" 2>/dev/null || printf '0')"
            findings_epoch="$(stat -c %Y "$findings_file" 2>/dev/null || printf '0')"
            if (( report_epoch + 2 < findings_epoch )); then
                reasons+=("report.md is older than findings.md (stale report): report=${report_epoch} findings=${findings_epoch}")
            fi
        fi
        marker="$(rg -o 'findings_reconciliation:[^*]*' "$REPORT_FILE" 2>/dev/null | head -1 || true)"
        if [[ -z "$marker" ]]; then
            reasons+=("report.md has no <!-- findings_reconciliation: source_count=N reported_count=N --> marker")
        else
            source_reported="$(printf '%s' "$marker" | sed -n 's/.*source_count=\([0-9][0-9]*\).*/\1/p')"
            local reported_count
            reported_count="$(printf '%s' "$marker" | sed -n 's/.*reported_count=\([0-9][0-9]*\).*/\1/p')"
            if [[ -z "$source_reported" || -z "$reported_count" ]]; then
                reasons+=("report.md findings_reconciliation marker is malformed: ${marker}")
            elif [[ "$source_reported" != "$source_count" ]]; then
                reasons+=("report.md reconciliation is stale: report says source_count=${source_reported}, findings.md has ${source_count}")
            elif [[ "$reported_count" != "$source_count" ]]; then
                reasons+=("report.md accounted for ${reported_count} of ${source_count} findings")
            fi
        fi
    fi

    if ((${#reasons[@]} == 0)); then
        return 0
    fi

    local reason_text
    reason_text="$(printf '%s; ' "${reasons[@]}")"
    reason_text="${reason_text%; }"
    if [[ -x "$SCRIPT_DIR/append_log_entry.sh" ]]; then
        "$SCRIPT_DIR/append_log_entry.sh" "$ENG_DIR" operator "Run stop" \
            "stop_reason=queue_incomplete" \
            "Report freshness guard blocked completion: ${reason_text}" >/dev/null 2>&1 || true
    fi
    printf 'Report freshness guard blocked completion:\n' >&2
    printf '  - %s\n' "${reasons[@]}" >&2
    exit 2
}

write_finalize_stamp() {
    local findings_file="$ENG_DIR/findings.md"
    local stamp="$ENG_DIR/finalize-stamp.json"
    local source_count=0 active=0 processing=0
    if [[ -f "$findings_file" ]]; then
        source_count="$(rg -c '^## \[FINDING-[A-Z]{2}-[0-9]{3}\]' "$findings_file" 2>/dev/null || printf '0')"
        source_count="${source_count:-0}"
    fi
    if [[ -f "$DB_FILE" ]]; then
        active="$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM cases WHERE stage IN ('ingested','vuln_confirmed','fuzz_pending');" 2>/dev/null || printf '0')"
        processing="$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM cases WHERE status='processing';" 2>/dev/null || printf '0')"
    fi
    jq -n \
        --arg end_time "$END_TIME" \
        --arg target "$(jq -r '.target // ""' "$SCOPE_FILE" 2>/dev/null || true)" \
        --argjson finding_count "${source_count:-0}" \
        --argjson active_stage_cases "${active:-0}" \
        --argjson processing_cases "${processing:-0}" \
        --arg report_sha256 "$(sha256sum "$REPORT_FILE" 2>/dev/null | cut -d' ' -f1 || true)" \
        --arg findings_sha256 "$(sha256sum "$findings_file" 2>/dev/null | cut -d' ' -f1 || true)" \
        '{end_time:$end_time, target:$target, finding_count:$finding_count, active_stage_cases:$active_stage_cases, processing_cases:$processing_cases, report_sha256:$report_sha256, findings_sha256:$findings_sha256}' \
        >"$stamp" 2>/dev/null || true
}

continuous_observation_loop() {
    local target interval
    target="$(jq -r '.target // empty' "$SCOPE_FILE" 2>/dev/null || true)"
    interval="$(observation_interval_seconds)"

    trap 'echo "[observation] stopping continuous observation hold for ${target:-unknown target}"; exit 0' INT TERM

    echo "[observation] Continuous observation hold active for ${target:-unknown target} (heartbeat ${interval}s)"
    while true; do
        printf '[observation] %s continuous observation hold active for %s; heartbeat=%ss\n' "$(engagement_now_utc)" "${target:-unknown target}" "$interval"
        sleep "$interval" &
        wait "$!"
    done
}

if continuous_target_matches; then
    mark_scope_in_progress_for_observation
    mark_log_in_progress_for_observation
    mark_report_in_progress_for_observation
    append_observation_hold_log_entry
    continuous_observation_loop
    exit 0
fi

recall_finalize_guard
report_freshness_guard

END_TIME="$(engagement_now_utc)"
START_TIME="$(jq -r '.start_time // empty' "$SCOPE_FILE" 2>/dev/null || true)"
if [[ -n "$START_TIME" ]]; then
    ENG_DATE="$(engagement_header_date_from_utc "$START_TIME")"
else
    ENG_DATE="$(engagement_header_date_today)"
fi

tmp_scope="$(mktemp "${TMPDIR:-/tmp}/scope-finalize.XXXXXX")"
jq --arg end_time "$END_TIME" '
  .status = "complete"
  | .current_phase = "complete"
  | .end_time = $end_time
  | .phases_completed = (((.phases_completed // []) + ["report"]) | unique)
' "$SCOPE_FILE" >"$tmp_scope"
mv "$tmp_scope" "$SCOPE_FILE"

if [[ -f "$EMIT_RUNTIME_EVENT" ]]; then
    bash "$EMIT_RUNTIME_EVENT" \
        "phase.entered" \
        "complete" \
        "phase-transition" \
        "operator" \
        "entering complete phase" \
        --kind phase_enter \
        --payload-json '{"phase":"complete"}' || true
fi

tmp_log="$(mktemp "${TMPDIR:-/tmp}/log-finalize.XXXXXX")"
awk '
  /^- \*\*Status\*\*:/ { print "- **Status**: Completed"; next }
  { print }
' "$LOG_FILE" >"$tmp_log"
mv "$tmp_log" "$LOG_FILE"

if [[ -f "$REPORT_FILE" ]]; then
    tmp_report="$(mktemp "${TMPDIR:-/tmp}/report-finalize.XXXXXX")"
    awk -v date_line="**Date**: ${ENG_DATE} — Completed" '
      BEGIN { date_done = 0; target_done = 0 }
      /^\*\*Date\*\*:/ {
          print date_line
          date_done = 1
          next
      }
      /^\*\*Target\*\*:/ {
          sub(/\*\*Status\*\*: .*/, "**Status**: Completed")
          print
          target_done = 1
          next
      }
      /^\*\*Status\*\*:/ {
          print "**Status**: Completed"
          next
      }
      { print }
      END {
          if (!date_done) {
              print date_line
          }
      }
    ' "$REPORT_FILE" >"$tmp_report"
    mv "$tmp_report" "$REPORT_FILE"
fi

write_finalize_stamp

rm -f "$ENG_DIR"/tmp-*.md

if [[ -f "$DB_FILE" ]]; then
    printf '.timeout 5000\nPRAGMA wal_checkpoint(TRUNCATE);\n' | sqlite3 "$DB_FILE" >/dev/null
    rm -f "$DB_FILE-wal" "$DB_FILE-shm"
fi
