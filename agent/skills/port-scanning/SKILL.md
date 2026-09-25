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

### 6b. Scan Type Variants (stateless firewall / IDS evasion)
```bash
run_tool nmap -sN -p PORT TARGET     # NULL scan — no flags set
run_tool nmap -sF -p PORT TARGET     # FIN scan
run_tool nmap -sX -p PORT TARGET     # Xmas scan (FIN+PSH+URG)
run_tool nmap -sA -p PORT TARGET     # ACK scan — maps stateful firewall rules, not open/closed
run_tool nmap -O TARGET              # OS fingerprinting — informs which privesc/exploit skill applies later
run_tool nmap -6 -sV -T4 TARGET6     # IPv6 target — many hosts leave the v6 stack unfirewalled while v4 is locked down
```

### 6c. Large-Range / High-Speed Discovery
```bash
# masscan for CIDR ranges nmap's full -p- would take too long to sweep
run_tool masscan -p1-65535 TARGET_CIDR --rate 1000 -oL $DIR/scans/masscan.txt
# Feed masscan hits back into nmap for accurate service/version detection
PORTS=$(awk '/open/{print $3}' $DIR/scans/masscan.txt | tr '\n' ',' | sed 's/,$//')
run_tool nmap -sV -sC -p "$PORTS" TARGET -oN $DIR/scans/nmap_from_masscan.txt
```

### 6d. Targeted Vulnerability & CVE Scripts
```bash
run_tool nmap --script=smb-vuln-ms17-010 -p 445 TARGET            # EternalBlue
run_tool nmap --script=ssl-heartbleed -p 443 TARGET
run_tool nmap --script "*-vuln*" -p PORT TARGET                    # broader vuln-category sweep
run_tool nmap --script=http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 TARGET
run_tool nmap --script=rdp-vuln-ms12-020 -p 3389 TARGET             # BlueKeep-family
```
Any hit here is a direct CVE lead — cross-check the CVE ID against `osint-recon`'s exploit-DB/NVD lookup before handing to `exploit-developer`.

### 6e. Fast Alternative Scanner (naabu)

When `nmap -p-` is too slow for the engagement window and masscan tuning is impractical,
naabu gives a quick SYN-based port list to hand back into nmap for service/version detail:

```bash
run_tool naabu -host TARGET -top-ports 1000 -rate 1000 -o $DIR/scans/naabu.txt
PORTS=$(sed -E 's/.*://' $DIR/scans/naabu.txt | tr '\n' ',' | sed 's/,$//')
run_tool nmap -sV -sC -p "$PORTS" TARGET -oN $DIR/scans/nmap_from_naabu.txt
```

### 6f. Deeper Service-Specific Enumeration Scripts

Beyond the generic `http-enum`/`smb-enum-*` in section 4, run protocol-specific scripts once
a service is confirmed — these often reveal config/version details the generic vuln scripts miss:

```bash
run_tool nmap --script=snmp-info,snmp-interfaces,snmp-processes -p 161 -sU TARGET   # SNMP walk-lite
run_tool nmap --script=mysql-info,mysql-empty-password -p 3306 TARGET
run_tool nmap --script=ms-sql-info,ms-sql-empty-password -p 1433 TARGET
run_tool nmap --script=pgsql-brute --script-args userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt -p 5432 TARGET
run_tool nmap --script=redis-info -p 6379 TARGET
run_tool nmap --script=mongodb-info,mongodb-databases -p 27017 TARGET
run_tool nmap --script=ldap-search,ldap-rootdse -p 389 TARGET
run_tool nmap --script=rdp-enum-encryption -p 3389 TARGET
run_tool nmap --script=dns-zone-transfer --script-args dns-zone-transfer.domain=<domain> -p 53 TARGET
```
Each hit here hands directly to the matching specialist skill (`database-services`,
`ldap-kerberos`, `smb-netbios`, `remote-access-services`, `snmp-ftp-nfs`).

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
