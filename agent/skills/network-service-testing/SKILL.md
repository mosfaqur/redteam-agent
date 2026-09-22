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
