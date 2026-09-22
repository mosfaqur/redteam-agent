---
name: port-scanning
description: Discover open ports, running services, and their versions on a target
origin: RedteamOpencode
---

# Port Scanning

## When to Activate

- Initial recon of new target, need to discover services before vuln testing
- Verifying firewall rules, new IP discovered

## Tools

`run_tool nmap` (primary), `run_tool nc` (quick checks/banner grab)

## Methodology

### 1. Quick Initial Scan
```bash
run_tool nmap -sV -sC -T4 TARGET -oA $DIR/scans/nmap_initial
```

### 2. Full TCP Scan
```bash
run_tool nmap -sV -sC -T4 -p- TARGET -oN $DIR/scans/nmap_full_tcp.txt
# Speed optimization: discover ports first, then deep scan
run_tool nmap -sS -T4 -p- --min-rate 1000 TARGET -oG $DIR/scans/ports_only.txt
PORTS=$(grep -oP '\d+/open' $DIR/scans/ports_only.txt | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
run_tool nmap -sV -sC -p "$PORTS" TARGET -oN $DIR/scans/nmap_targeted.txt
```

### 3. Service Detection
```bash
run_tool nmap -sV --version-intensity 5 -p PORT1,PORT2 TARGET
run_tool nc -nv TARGET PORT <<< "" 2>&1 | head -5    # Banner grab
printf '\n' | run_tool nc -w 3 TARGET PORT
```

### 4. Script Scanning
```bash
run_tool nmap --script=vuln -p PORT TARGET
run_tool nmap --script=http-enum -p 80,443 TARGET
run_tool nmap --script=smb-enum-shares,smb-enum-users -p 445 TARGET
run_tool nmap --script=ftp-anon -p 21 TARGET
run_tool nmap --script=ssh-auth-methods -p 22 TARGET
```

### 5. UDP Scan
```bash
run_tool nmap -sU --top-ports 50 -T4 TARGET -oN $DIR/scans/nmap_udp.txt
run_tool nmap -sU -p 53,67,68,69,123,161,162,500,514,1900 TARGET
```

### 6. Firewall Evasion (when standard scans blocked)
```bash
run_tool nmap -f -sV -p PORT TARGET                    # Fragment packets
run_tool nmap -D RND:5 -sV -p PORT TARGET              # Decoy scan
run_tool nmap -sV -T2 -p PORT TARGET                   # Slow scan
run_tool nmap --source-port 53 -sV -p PORT TARGET      # Source port trick
```

### 7. Output Parsing
```bash
grep -oP '\d+/open/tcp//\S+' $DIR/scans/nmap_initial.gnmap
grep "open" $DIR/scans/nmap_targeted.txt | grep -v "filtered"
```

### 8. Queue Services (non-HTTP)

Save an XML scan and ingest open TCP/UDP services into the case queue so
`network-analyst` can test them:

```bash
run_tool nmap -sV -sC -T4 --host-timeout 120s TARGET -oX $DIR/scans/nmap.xml
./scripts/net_ingest.sh "$DIR/cases.db" recon-specialist --nmap-xml "$DIR/scans/nmap.xml"
```

Or emit a `#### Service Queue` JSONL block and pipe it to `net_ingest.sh`:

```json
{"host":"10.0.0.5","port":445,"proto":"tcp","service":"smb","product":"Samba","version":"4.7.6","state":"open","source":"recon-specialist"}
```

Then verify: `./scripts/dispatcher.sh "$DIR/cases.db" stats-by-stage` should show
`service` cases at stage `ingested`.

## Common Port Reference

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | Anonymous login |
| 22 | SSH | Version, auth methods |
| 25 | SMTP | Open relay, user enum |
| 53 | DNS | Zone transfer |
| 80/443 | HTTP/S | Web app testing |
| 139/445 | SMB | Shares, null sessions |
| 1433 | MSSQL | 3306 MySQL | 5432 PostgreSQL |
| 3389 | RDP | 5900 VNC | 6379 Redis (often unauth) |
| 8080 | HTTP alt | 27017 MongoDB (often unauth) |
