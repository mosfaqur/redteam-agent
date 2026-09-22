#!/usr/bin/env bash
# net_ingest.sh — Ingest TCP/UDP service cases into the case queue.
#
# Usage:
#   echo '<jsonl>' | ./scripts/net_ingest.sh <db_path> <source_name>
#   ./scripts/net_ingest.sh <db_path> <source_name> --nmap-xml <nmap.xml>
#
# JSONL input format (one service per line):
#   {"host":"10.0.0.5","port":445,"proto":"tcp","service":"smb",
#    "product":"Samba","version":"4.7.6","banner":"...","state":"open",
#    "source":"recon-specialist"}
#
# Only state=open / open|filtered rows are queued. Service cases are inserted as
# type='service' and routed to network-analyst by the stage dispatcher.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/db.sh"
source "$SCRIPT_DIR/lib/scope.sh"

if [[ $# -lt 2 ]]; then
    echo "Usage: echo '<jsonl>' | $0 <db_path> <source_name> [--nmap-xml FILE]" >&2
    exit 1
fi

DB_PATH="$1"
SOURCE="$2"
shift 2

NMAP_XML=""
while (($#)); do
    case "$1" in
        --nmap-xml)
            NMAP_XML="${2:?--nmap-xml requires a file path}"
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: database not found: $DB_PATH" >&2
    exit 1
fi

db_init "$DB_PATH"

# Precompute the scope list so out-of-scope services are not queued.
ENG_DIR="$(cd "$(dirname "$DB_PATH")" && pwd)"
SCOPE_LIST=()
if [[ -f "$ENG_DIR/scope.json" ]]; then
    while IFS= read -r item; do
        [[ -n "$item" ]] && SCOPE_LIST+=("$item")
    done < <(scope_entries "$ENG_DIR")
fi

count=0

process_line() {
    local line="$1"
    [[ -z "$line" ]] && return 0
    [[ "$line" == \#* ]] && return 0
    [[ "$line" == "{"* ]] || return 0

    local host port proto service product version banner state line_source effective_source inserted
    host="$(jq -r '.host // .ip // empty' <<<"$line" 2>/dev/null || true)"
    port="$(jq -r '.port // .portid // empty' <<<"$line" 2>/dev/null || true)"
    proto="$(jq -r '.proto // .protocol // "tcp"' <<<"$line" 2>/dev/null || true)"
    service="$(jq -r '.service // .name // empty' <<<"$line" 2>/dev/null || true)"
    product="$(jq -r '.product // .service_product // empty' <<<"$line" 2>/dev/null || true)"
    version="$(jq -r '.version // .service_version // empty' <<<"$line" 2>/dev/null || true)"
    banner="$(jq -r '.banner // .extrainfo // empty' <<<"$line" 2>/dev/null || true)"
    state="$(jq -r '.state // "open"' <<<"$line" 2>/dev/null || true)"
    line_source="$(jq -r '.source // .agent // empty' <<<"$line" 2>/dev/null || true)"

    [[ -n "$host" && -n "$port" ]] || return 0
    [[ "$port" =~ ^[0-9]+$ ]] || return 0

    if [[ ${#SCOPE_LIST[@]} -gt 0 ]] && ! host_in_scope "$host" "${SCOPE_LIST[@]}"; then
        return 0
    fi

    case "$state" in
        open|"open|filtered"|"") ;;
        *) return 0 ;;
    esac

    effective_source="$SOURCE"
    if [[ -n "$line_source" && "$line_source" != "null" ]]; then
        effective_source="$line_source"
    fi

    inserted="$(db_insert_service_case "$DB_PATH" \
        "$host" "$port" "$proto" "$service" "$product" "$version" "$banner" \
        "$effective_source" "${NMAP_XML:-}" 2>/dev/null || echo 0)"
    if [[ "$inserted" == "1" ]]; then
        count=$((count + 1))
    fi
}

if [[ -n "$NMAP_XML" ]]; then
    if [[ ! -f "$NMAP_XML" ]]; then
        echo "ERROR: nmap XML not found: $NMAP_XML" >&2
        exit 1
    fi
    while IFS= read -r line; do
        process_line "$line"
    done < <(python3 - "$NMAP_XML" <<'PY'
import json
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
for host in root.findall("host"):
    addr = ""
    for a in host.findall("address"):
        if a.get("addrtype") in ("ipv4", "ipv6"):
            addr = a.get("addr") or ""
            break
    if not addr:
        continue
    ports = host.find("ports")
    if ports is None:
        continue
    for p in ports.findall("port"):
        state = p.find("state")
        st = state.get("state") if state is not None else "open"
        if st not in ("open", "open|filtered"):
            continue
        svc = p.find("service")
        rec = {
            "host": addr,
            "port": int(p.get("portid")),
            "proto": p.get("protocol", "tcp"),
            "state": st,
            "service": svc.get("name", "") if svc is not None else "",
            "product": svc.get("product", "") if svc is not None else "",
            "version": svc.get("version", "") if svc is not None else "",
            "banner": svc.get("extrainfo", "") if svc is not None else "",
        }
        print(json.dumps(rec))
PY
    )
else
    while IFS= read -r line; do
        process_line "$line"
    done
fi

echo "[net_ingest] Inserted $count service case(s) from source '$SOURCE'"
