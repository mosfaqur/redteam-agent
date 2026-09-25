---
name: network-service-testing
description: Enumerate and test TCP/UDP services (non-HTTP) for misconfigurations, weak auth, and known CVEs
origin: RedteamOpencode
---

# Network Service Testing

## When to Activate

- A service case (`type=service`) is dispatched at stage=`ingested`
- Port scan found non-HTTP services (SMB, DB, mail, DNS, remote access, LDAP, SNMP, FTP, NFS)
- You need to convert an open port into a confirmed vulnerability or a clean result

## Tools

`run_tool nmap` (service + NSE scripts), `run_tool nc`, `run_tool hydra`, `searchsploit`,
protocol clients (`smbclient`, `ldapsearch`, `mysql`, `psql`, `redis-cli`, `mongosh`,
`snmpwalk`, `showmount`, `ftp`, `ssh`, `curl`), Metasploit MCP (exploit phase only).

## Queue Contract

Services enter the queue via `./scripts/net_ingest.sh` as `type=service` with columns
`host`, `port`, `proto`, `service`, `service_product`, `service_version`, `banner`.
Read the batch file (`BATCH_FILE`) and account for every ID in `BATCH_IDS`.

## Methodology

### 1. Confirm
```bash
run_tool nmap -sV -p PORT --host-timeout 60s HOST
run_tool nc -nv HOST PORT
```
Banner/version grab; confirm the service matches the fingerprint before deeper testing.

### 2. Enumerate
Run the protocol-specific enumeration (see the family skills). Always try:
- anonymous / null / guest access
- version + product fingerprint → CVE mapping (`searchsploit <product> <version>`)
- default ports and management interfaces

### 3. Authentication
- Small, evidence-driven default-credential set only (`admin:admin`, `root:root`, product defaults).
- `run_tool hydra -L users.txt -P pass.txt HOST PROTO -t 4 -W 5` — bounded, rate-limited, only when a
  user list or product default is known. Never broad brute force.
- Auth-method analysis (e.g. `ssh-auth-methods`, anonymous LDAP bind, SMB signing).

### 4. Known-Vuln Mapping
```bash
run_tool nmap --script vuln -p PORT HOST
run_tool nmap --script <service>-* -p PORT HOST
searchsploit <product> <version>
```
Prefer the exact service NSE scripts and the version-matched exploit.

### 5. Confirm Exploitability (do not fully exploit)
Prove the primitive with one bounded request/response or a single Metasploit `check`.
Full exploitation and chaining belong to `exploit-developer` (stage=vuln_confirmed).

### 6. Unknown, Embedded, and Proprietary Services

When a known-protocol script does not identify `HOST:PORT`, capture one banner or first response before guessing. Record the byte-level framing and classify the service as `line-protocol`, `length-prefixed`, `TLV`, or `fixed-header binary`. Check the adjacent HTTP admin interface, one session-based JSON-RPC control API, and one config-backup/export endpoint with a single request each; use the observed adjacent management port for `PORT` in those requests. Use the bounded block below only after the case is stable.

```bash
mkdir -p "$DIR/scans"
printf '%s\n' 'cap: 2 capture requests, 3 management requests, 1 handoff record per case' > "$DIR/scans/unknown-cap.txt"
run_tool nc -nv -w 5 HOST PORT </dev/null > "$DIR/scans/unknown-first-response.bin" 2>"$DIR/scans/unknown-first-response.stderr" || true
run_tool nmap -sV -p PORT --host-timeout 60s --max-retries 2 HOST > "$DIR/scans/unknown-nmap.txt" 2>&1
xxd -g 1 -c 16 "$DIR/scans/unknown-first-response.bin" > "$DIR/scans/unknown-first-response.hexdump"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 "https://HOST:PORT/admin/" -D "$DIR/scans/unknown-admin.headers" -o "$DIR/scans/unknown-admin.html"
run_tool curl -sS -k -c "$DIR/scans/unknown-rpc.cookie" -b "$DIR/scans/unknown-rpc.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"system.info","id":1}' "https://HOST:PORT/rpc" -D "$DIR/scans/unknown-rpc.headers" -o "$DIR/scans/unknown-rpc.json"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 "https://HOST:PORT/config-export" -D "$DIR/scans/unknown-config.headers" -o "$DIR/scans/unknown-config.bin"
python3 - "$DIR/scans/unknown-first-response.bin" "$DIR/scans/unknown-framing.txt" "$DIR/scans/unknown-handoff.txt" "$DIR/scans/unknown-outcome.txt" <<'PY'
from pathlib import Path
import sys

capture, framing, handoff, outcome = map(Path, sys.argv[1:])
raw = capture.read_bytes()
if not raw:
    classification = "fixed-header binary"
    basis = "empty capture; no delimiter or length evidence"
elif b"\n" in raw and sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in raw) / len(raw) >= 0.8:
    classification = "line-protocol"
    basis = "printable response contains a line delimiter"
else:
    length_prefixed = False
    for width in (2, 4):
        for endian in ("big", "little"):
            if len(raw) >= width:
                prefix = int.from_bytes(raw[:width], endian)
                if prefix in (len(raw) - width, len(raw)):
                    length_prefixed = True
    offset = 0
    while offset + 4 <= len(raw):
        length = int.from_bytes(raw[offset + 2:offset + 4], "big")
        offset += 4 + length
        if offset > len(raw):
            break
    tlv = len(raw) >= 4 and offset == len(raw)
    if length_prefixed:
        classification = "length-prefixed"
        basis = "leading length matches the captured frame"
    elif tlv:
        classification = "TLV"
        basis = "tag and length fields consume the captured frame"
    else:
        classification = "fixed-header binary"
        basis = "no line delimiter or self-consistent length/TLV boundary"
framing.write_text(
    f"framing_class={classification}\n"
    f"basis={basis}\n"
    f"bytes={len(raw)}\n"
    f"prefix={raw[:16].hex()}\n"
)
handoff.write_text(
    f"handoff skill=SELECTED case=CASE_ID host=HOST port=PORT evidence={capture}\n"
)
outcome.write_text(
    f"service_class={classification} evidence={capture}\n"
)
PY
```

Handoff by evidence: proprietary or binary framing → `custom-protocol-reverse-engineering`; SIP/VoIP signaling or media ports → `voip-sip-testing`; router/camera/NAS/gateway admin interfaces and ubus/rpcd-style RPC → `embedded-device-testing`; a FastCGI/FPM listener (9000/9090) → `fastcgi-service-testing`. Replace `SELECTED` and `CASE_ID` with the mapped skill and current case id, then emit `handoff skill=SELECTED case=CASE_ID host=HOST port=PORT evidence=$DIR/scans/unknown-first-response.bin`. Use `REQUEUE` for the handoff and copy `service_class=... evidence=...` from `$DIR/scans/unknown-outcome.txt` into the `### Case Outcomes` line so the next agent does not re-fingerprint. Do not attempt exploit development in network-analyst.

## High-Value Fast Wins

| Finding | Why it matters |
|---|---|
| Anonymous FTP / SMB / NFS | direct file read/write, credential harvest |
| Null/guest SMB session | user/group/share enumeration |
| Redis / MongoDB / Elasticsearch unauthenticated | data access, often RCE |
| SNMP `public`/`private` community | system/config disclosure |
| DNS zone transfer (AXFR) | full internal name map |
| Default DB credentials | data access / code execution |
| LDAP anonymous bind | directory enumeration |

## Safety / Budget

- Every nmap command: `--host-timeout` ≤120s, `--max-retries 2`.
- Hydra: bounded candidate set, `-t 4` or lower, per-host only.
- Save all output under `$DIR/scans/`. Never `/tmp`.
- Credentials/hashes/tickets found → write to `$DIR/auth.json` immediately.

## Output

- Findings via `./scripts/append_finding.sh "$DIR" network-analyst <body-file>` (prefix `FINDING-NA-NNN`).
- `### Case Outcomes` line per case: `DONE STAGE=vuln_confirmed|clean`, `REQUEUE`, or `ERROR`.
