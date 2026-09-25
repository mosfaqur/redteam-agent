---
name: snmp-ftp-nfs
description: Test SNMP community strings, FTP anonymous/backdoor access, and NFS exports (no_root_squash, world-readable)
origin: RedteamOpencode
---

# SNMP / FTP / NFS

## When to Activate

- Ports 161/162 (SNMP), 21 (FTP), 2049/111 (NFS/rpcbind), 69 (TFTP)
- File-sharing or management services in scope

## Tools

`run_tool nmap`, `snmpwalk`, `snmp-check`, `onesixtyone`, `ftp`, `showmount`, `mount`, `tftp`.

## Methodology

### SNMP (161/udp)
```bash
run_tool onesixtyone -c communities.txt HOST
run_tool snmpwalk -v2c -c public HOST
run_tool snmpwalk -v2c -c public HOST 1.3.6.1.2.1.25.4.2.1.2   # processes
run_tool snmp-check HOST -c public
run_tool nmap -sU -p 161 --script snmp-brute,snmp-info HOST
```
Community strings (`public`, `private`, `cisco`) → system, interface, user, and sometimes
credential disclosure.

Additional SNMP checks:
- [ ] SNMPv3 downgrade / weak auth: `snmp-check` with `-v3` to test whether the device also answers v1/v2c on the same community, bypassing v3 auth entirely
- [ ] Write-access community strings (`private` often RW): confirm read-write with a single non-destructive `snmpset` on a scratch OID (e.g. `sysContact`), then revert — do not leave state changed
- [ ] Cisco-specific OIDs for config/password disclosure: `1.3.6.1.4.1.9.9.96.1.1.1.1.8` (running-config) and `1.3.6.1.4.1.9.9.23.1.2.1.1.7` (CDP neighbor table) via `snmpwalk`
- [ ] SNMP-to-RCE pivot: printers/network devices exposing SNMP write access to firmware/config paths — note as an escalation candidate, do not push firmware
- [ ] Version-scoped community brute variants: `onesixtyone` and `snmp-check` default to v1/v2c — explicitly re-test with `-v1` vs `-v2c` separately, since some devices accept a community string on one version but reject it on the other (version-specific ACLs), producing false negatives if only one version is tried
- [ ] SNMPv3 default/blank credentials: many devices ship SNMPv3 enabled with a known default `engineID`/username (e.g. `initial`, vendor-default `usmUser`) and no configured auth/priv — `snmpwalk -v3 -l noAuthNoPriv -u initial HOST`; a v3 endpoint answering `noAuthNoPriv` is functionally as open as a v1 `public` community
- [ ] `GETBULK`-based fast enumeration: `snmpbulkwalk -v2c -c public -Cr50 HOST 1.3.6.1.2.1` walks large subtrees in far fewer round-trips than sequential `GETNEXT` — use for a bounded full-MIB sweep instead of repeated single-OID `snmpwalk` calls
- [ ] Community-string reuse across a device fleet: a community string recovered from one host (via TFTP config disclosure or brute) is frequently reused across the same vendor's devices in-scope — cross-check before re-brute-forcing each host independently

### FTP (21)
```bash
run_tool nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vuln-* HOST
run_tool ftp HOST      # try anonymous / default creds
```
Check vsftpd 2.3.4 backdoor, ProFTPD CVEs, and writable directories (webroot).

Additional FTP checks:
- [ ] FTP bounce (`PORT`) for internal port scanning through the FTP server as a pivot — confirm feasibility only, do not run a full internal scan from here
- [ ] Explicit/implicit FTPS (`AUTH TLS`) downgrade: confirm the server accepts plaintext `USER`/`PASS` even when TLS is advertised
- [ ] Writable-then-executable path: if an anonymous-writable directory is also served by the paired HTTP service (webroot), a dropped file is a direct web-shell primitive — report the path pairing, do not upload
- [ ] FTP bounce (`PORT`) scan confirmation detail: issue `PORT` targeting a known-closed and a known-open internal port, then `LIST`, and diff the response codes/timing — a `150`/`226` on the open port vs `425`/`450` on the closed one confirms the server will proxy the connection, which is the concrete evidence needed (not just that `ftp-bounce` NSE flagged the mode as theoretically possible)
- [ ] Passive vs active mode data-channel confusion: some legacy/misconfigured FTPDs bind the passive data port to an internal-only interface while accepting external control connections — note if PASV returns an RFC1918 address to an external client, since it can leak internal topology or break automated tooling in a way worth documenting
- [ ] vsftpd/ProFTPD/Pure-FTPd CVE version-mapping beyond the 2.3.4 backdoor: ProFTPD `mod_copy` unauthenticated file copy (CVE-2015-3306), ProFTPD `mod_sql`/telnet IAC memory disclosure — cross-reference the banner grab from `ftp-syst` against `searchsploit` before assuming only the 2.3.4 case applies

### NFS (2049/111)
```bash
run_tool showmount -e HOST
run_tool nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-exports HOST
# mount exported share and inspect
mkdir -p $DIR/scans/nfsmnt && run_tool mount -t nfs HOST:/export $DIR/scans/nfsmnt
```
`no_root_squash` → privilege escalation candidate (confirm, then hand off).

Additional NFS checks:
- [ ] UID/GID spoofing: NFSv3 trusts client-asserted UIDs — mount as an arbitrary local UID matching a file owner seen in the export listing to read/write files without a password (classic NFS trust-boundary bypass, not just `no_root_squash`)
- [ ] NFSv4 vs NFSv3 export differences — NFSv4 uses ID mapping (`idmapd`) which can mask or alter the UID-spoofing primitive; note which version is in use
- [ ] SUID binary drop: if a share is writable and `no_root_squash` is set, a root-owned SUID binary can be staged for later local privesc (`linux-privesc`) — confirm write access only, do not stage a binary without exploit-developer
- [ ] Export ACL granularity: `showmount -e` output often lists per-subnet/per-host access (`/export 10.0.0.0/24(rw,no_root_squash)`); confirm the exact allowed source range and whether the scanning host's address falls inside it — a export that appears in the list but denies the mount is a client-IP-restriction finding, not a false positive
- [ ] `no_all_squash` combined with `no_root_squash`: distinguish the two — `no_root_squash` alone still maps other non-root UIDs normally, while the combination preserves arbitrary client-asserted UID/GID including root, which is the strictly more severe misconfiguration; note which flag(s) are actually set if the export config is disclosed (e.g. via a readable `/etc/exports` on a writable share)
- [ ] rpcbind/portmapper (111) standalone enumeration independent of NFS itself: `rpcinfo -p HOST` lists every registered RPC service (not just NFS) — `mountd`, `nlockmgr` (NFS lock manager, historically CVE-rich), `rquotad` — each is a separate attack surface worth noting even when the NFS export list itself is empty

### TFTP (69/udp)
```bash
run_tool nmap -sU -p 69 --script tftp-enum HOST
run_tool tftp HOST -c 'get config'
```
- [ ] TFTP is unauthenticated by design — enumerate common config filenames (`startup-config`, `running-config`, network-device firmware images) since it's frequently left open on switches/routers/VoIP phones for provisioning
- [ ] Cross-reference discovered device configs for embedded credentials/community strings, feeding back into the SNMP and `credential-attacks` steps above

## Confirm-Only Rule

Read-only access proof. If a share is world-writable or `no_root_squash`, record the
escalation candidate as `vuln_confirmed` and let exploit-developer weaponize it.

## Budget

`--host-timeout 120s`. No mass community-string brute force beyond a small list.
