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

### FTP (21)
```bash
run_tool nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vuln-* HOST
run_tool ftp HOST      # try anonymous / default creds
```
Check vsftpd 2.3.4 backdoor, ProFTPD CVEs, and writable directories (webroot).

### NFS (2049/111)
```bash
run_tool showmount -e HOST
run_tool nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-exports HOST
# mount exported share and inspect
mkdir -p $DIR/scans/nfsmnt && run_tool mount -t nfs HOST:/export $DIR/scans/nfsmnt
```
`no_root_squash` → privilege escalation candidate (confirm, then hand off).

### TFTP (69/udp)
```bash
run_tool nmap -sU -p 69 --script tftp-enum HOST
run_tool tftp HOST -c 'get config'
```

## Confirm-Only Rule

Read-only access proof. If a share is world-writable or `no_root_squash`, record the
escalation candidate as `vuln_confirmed` and let exploit-developer weaponize it.

## Budget

`--host-timeout 120s`. No mass community-string brute force beyond a small list.
