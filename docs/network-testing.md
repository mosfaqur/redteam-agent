# Network Service Testing (TCP/UDP)

The pipeline tests non-HTTP TCP/UDP services in addition to web apps. Service cases are
first-class queue rows (`type=service`) routed to `network-analyst`, then to
`exploit-developer` when a primitive is confirmed.

## Model

- **Case columns** (`cases`): `host`, `port`, `proto`, `service`, `service_product`,
  `service_version`, `banner`, `scan_ref`. HTTP cases leave these NULL.
- **Identity/dedup**: `method='SERVICE'`, `url='<proto>://host:port'`,
  `url_path='/host/port/proto'`, `params_key_sig=sha1(proto|host|port|service)`.
- **Routing**: `type=service` + stage `ingested` → `network-analyst`;
  `vuln_confirmed` → `exploit-developer`.

## Producer

```bash
# One-shot TCP + UDP discovery + ingest (target defaults to scope.json)
./scripts/netscan.sh "$DIR"
./scripts/netscan.sh "$DIR" 10.0.0.0/24 --top-ports 100
./scripts/netscan.sh "$DIR" 10.10.10.5 --no-udp

# From nmap XML
./scripts/net_ingest.sh "$DIR/cases.db" recon-specialist --nmap-xml "$DIR/scans/nmap_tcp.xml"

# From JSONL (recon-specialist `#### Service Queue` block)
echo '{"host":"10.0.0.5","port":445,"proto":"tcp","service":"smb","state":"open"}' \
  | ./scripts/net_ingest.sh "$DIR/cases.db" recon-specialist
```

Only `state=open` / `open|filtered` rows are queued, and hosts outside `scope.json`
are dropped. `netscan.sh` runs `nmap -sV -sC` (TCP) and `nmap -sU --top-ports`
(UDP; raw sockets may need root) and ingests both. `nmap -oX` is the reliable path.

## Network engagement mode

```bash
/engage 10.0.0.0/24      # or 10.10.10.5, 10.0.0.5-20
```

`engage` detects an IPv4/CIDR/range target and enters network mode: no Katana, no
mitmproxy. `scope.json` gets `"mode": "network"` and the scope list holds the CIDR/range.
`host_in_scope` matches CIDR (`10.0.0.0/24`) and ranges (`10.0.0.5-20`).

```bash
./scripts/dispatcher.sh "$DIR/cases.db" stats-by-stage
# fetch-by-stage ingested service <limit> network-analyst
```

## Service skills

| Skill | Coverage |
|---|---|
| `network-service-testing` | general methodology + queue contract |
| `smb-netbios` | SMB/RPC, null sessions, shares, relay, MS17-010 |
| `database-services` | MySQL, MSSQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| `remote-access-services` | SSH, RDP, VNC, Telnet |
| `mail-dns-services` | SMTP/IMAP/POP3, DNS zone transfer |
| `ldap-kerberos` | LDAP enumeration, AS-REP/Kerberoasting, delegation, ADCS |
| `snmp-ftp-nfs` | SNMP community, FTP anon, NFS exports/no_root_squash |

They cross-reference the existing `references/active-directory/` and
`references/offensive-tactics/` material.

## Depth and safety

- `network-analyst` confirms a primitive (one bounded request, or a single Metasploit
  `check`); `exploit-developer` owns full exploitation and chaining.
- Every nmap command must be time-bounded (`--host-timeout` ≤120s, `--max-retries 2`).
- Hydra is bounded (`-t 4 -W 5`, small candidate sets); no broad brute force.
- Credentials/hashes/tickets found are written to `$DIR/auth.json` immediately.

## Lab profiles

`labs/generic-network.json` (declared AD objectives), `labs/metasploitable.json`
(service-exploit checklist), and selectable `labs/hackthebox.json` / `labs/vulnhub.json` /
`labs/tryhackme.json` (user/root or task objectives) drive the objective/closure gate for
network labs. Select a non-auto-detected profile with
`python3 ./scripts/lab_objective.py detect "$DIR" --profile hackthebox`. Add your own under
`agent/labs/` — no prompt edits needed.
