#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/surfaces.sh"

ENG_DIR="${1:?usage: check_surface_coverage.sh <engagement_dir>}"
SURFACE_FILE="$(surface_file_path "$ENG_DIR")"

[[ -f "$SURFACE_FILE" ]] || { echo "surfaces.jsonl not found in $ENG_DIR" >&2; exit 1; }

out="$(python3 - <<'PY' "$SURFACE_FILE" "$ENG_DIR"
import json,os,sqlite3,sys
path,eng_dir=sys.argv[1:]
unresolved=[]
blocked_deferred=[]
total=0
strict_deferred_types={
    "account_recovery",
    "dynamic_render",
    "object_reference",
    "privileged_write",
}
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        line=line.strip()
        if not line:
            continue
        row=json.loads(line)
        total+=1
        surface_type=row.get("surface_type")
        target=row.get("target")
        status=row.get("status")
        if status == "discovered":
            unresolved.append(f'{surface_type} | {target}')
        elif status == "deferred" and surface_type in strict_deferred_types:
            blocked_deferred.append(f'{surface_type} | {target}')

# Anti-vacuous-pass guard: an empty surfaces.jsonl must not read as "ok".
# Surface coverage can only be empty when there is genuinely nothing to
# cover; that is an explicit operator decision, not a default.
if total == 0:
    case_count=0
    db_path=os.path.join(eng_dir, "cases.db")
    if os.path.exists(db_path):
        try:
            con=sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            case_count=con.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            con.close()
        except sqlite3.Error:
            case_count=-1
    target=""
    scope_path=os.path.join(eng_dir, "scope.json")
    if os.path.exists(scope_path):
        try:
            with open(scope_path, "r", encoding="utf-8") as fh:
                target=(json.load(fh).get("target") or "")
        except (OSError, ValueError):
            target=""
    if os.environ.get("REDTEAM_SURFACE_COVERAGE_ALLOW_EMPTY") == "1":
        print(
            "surface coverage: ok (0 surface record(s), accepted only because "
            "REDTEAM_SURFACE_COVERAGE_ALLOW_EMPTY=1; log the reason)"
        )
    else:
        print("No surface records: surfaces.jsonl has 0 rows.")
        print(f"  target: {target or 'unknown'}")
        print(f"  cases.db rows: {case_count}")
        print("Resolve it in the same turn, do not idle in report:")
        print("  1. ingest real recon/source surfaces with append_surface_jsonl.sh, or")
        print("  2. mark each concrete surface covered/not_applicable/deferred with append_surface.sh, or")
        print("  3. only for an engagement with no coverable surface (e.g. pure")
        print("     network/AD lab), set REDTEAM_SURFACE_COVERAGE_ALLOW_EMPTY=1 and record")
        print("     the reason in a log entry; an empty file alone is never a pass.")
        sys.exit(1)
elif unresolved or blocked_deferred:
    if unresolved:
        print("Uncovered surfaces remain:")
        for item in unresolved:
            print(f"  - {item}")
    if blocked_deferred:
        print("High-risk surfaces cannot remain deferred:")
        for item in blocked_deferred:
            print(f"  - {item}")
        print("Resolve them as covered or not_applicable before finishing Test/Report.")
    sys.exit(1)
else:
    print(f"surface coverage: ok ({total} surface record(s))")
PY
)" || {
    printf '%s\n' "$out" >&2
    exit 1
}

printf '%s\n' "$out"
