#!/usr/bin/env bash
# netscan.sh — One-shot TCP + UDP service discovery and queue ingestion.
#
# Usage:
#   ./scripts/netscan.sh <engagement_dir> [target] [--top-ports N] [--no-udp] [--source NAME]
#
# Runs nmap (TCP service scan + UDP top-ports), saves XML/plain output under
# <eng>/scans/, and ingests every open service into cases.db via net_ingest.sh.
# Target defaults to scope.json .target/.hostname.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/container.sh"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <engagement_dir> [target] [--top-ports N] [--no-udp] [--source NAME]" >&2
    exit 1
fi

ENG_DIR="$1"
shift

TARGET=""
TOP_PORTS=50
NO_UDP=0
SOURCE="recon-specialist"

while (($#)); do
    case "$1" in
        --top-ports) TOP_PORTS="${2:?--top-ports requires a number}"; shift 2 ;;
        --no-udp) NO_UDP=1; shift ;;
        --source) SOURCE="${2:?--source requires a name}"; shift 2 ;;
        -*) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

ENG_DIR="$(cd "$ENG_DIR" && pwd)"
export ENGAGEMENT_DIR="$ENG_DIR"
DB="$ENG_DIR/cases.db"

if ! [[ "$TOP_PORTS" =~ ^[0-9]+$ ]]; then
    echo "ERROR: --top-ports must be numeric (got '$TOP_PORTS')" >&2
    exit 2
fi

if [[ ! -f "$DB" ]]; then
    echo "ERROR: cases.db not found in $ENG_DIR" >&2
    exit 1
fi

if [[ -z "$TARGET" ]]; then
    TARGET="$(jq -r '.target // .hostname // empty' "$ENG_DIR/scope.json" 2>/dev/null || true)"
fi
if [[ -z "$TARGET" ]]; then
    echo "ERROR: no target given and scope.json has none" >&2
    exit 1
fi

mkdir -p "$ENG_DIR/scans"

TCP_XML="$ENG_DIR/scans/nmap_tcp.xml"
echo "[netscan] TCP scan: $TARGET"
run_tool nmap -sV -sC -T4 --host-timeout 120s --max-retries 2 "$TARGET" \
    -oX "$TCP_XML" -oN "$ENG_DIR/scans/nmap_tcp.txt"
"$SCRIPT_DIR/net_ingest.sh" "$DB" "$SOURCE" --nmap-xml "$TCP_XML"

if [[ "$NO_UDP" != "1" ]]; then
    UDP_XML="$ENG_DIR/scans/nmap_udp.xml"
    echo "[netscan] UDP scan: $TARGET (top $TOP_PORTS; raw sockets may need root)"
    if run_tool nmap -sU --top-ports "$TOP_PORTS" -T4 --host-timeout 120s --max-retries 2 "$TARGET" \
        -oX "$UDP_XML" -oN "$ENG_DIR/scans/nmap_udp.txt"; then
        [[ -f "$UDP_XML" ]] && "$SCRIPT_DIR/net_ingest.sh" "$DB" "$SOURCE" --nmap-xml "$UDP_XML"
    else
        echo "[netscan] UDP scan failed (often needs root); continuing with TCP results" >&2
    fi
fi

echo "[netscan] Queue:"
"$SCRIPT_DIR/dispatcher.sh" "$DB" stats-by-stage
