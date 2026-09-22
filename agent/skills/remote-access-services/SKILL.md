---
name: remote-access-services
description: Test SSH, RDP, VNC, and Telnet services for weak auth, default creds, and known CVEs
origin: RedteamOpencode
---

# Remote Access Services

## When to Activate

- Ports 22 (SSH), 3389 (RDP), 5900-5901 (VNC), 23 (Telnet), 5985/5986 (WinRM)
- Need a foothold or a credential-validation path

## Tools

`run_tool nmap`, `ssh-audit`, `ssh`, `xfreerdp`/`rdesktop`, `vncviewer`, `nc`, `hydra`,
Metasploit (exploit phase).

## Methodology

### SSH (22)
```bash
run_tool nmap -sV -p 22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey HOST
# weak/default credentials (bounded)
run_tool hydra -l root -P small.txt ssh://HOST -t 4 -W 5
# private keys found in scope
run_tool ssh -i key USER@HOST
```
Check version CVEs (OpenSSH regreSSHion CVE-2024-6387, user enumeration CVE-2018-15473).

### RDP (3389)
```bash
run_tool nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info HOST
run_tool nmap -p 3389 --script rdp-vuln-ms12-020 HOST
# NLA status + hostname/domain disclosure; credential validation
nxc rdp HOST -u USER -p PASS
```
BlueKeep (CVE-2019-0708) — check only; exploit belongs to exploit-developer.

### VNC (5900)
```bash
run_tool nmap -p 5900 --script vnc-info,vnc-brute HOST
# no-auth / weak password
run_tool vncviewer HOST::5900
```
VNC often has no auth or a short password; confirm access, then record.

### Telnet (23)
```bash
run_tool nc -nv HOST 23
# default creds (root/root, admin/admin, product defaults) — bounded
```
Cleartext protocol: capture banners and any default-credential success.

## Confirm-Only Rule

Do not open interactive sessions that block. Use `-oBatchMode`, timeouts, and one-shot
commands. Successful credential validation → `$DIR/auth.json` and `vuln_confirmed`; full
session exploitation/chaining → exploit-developer.

## Budget

`--host-timeout 120s`. Hydra `-t 4 -W 5`, small candidate sets only.
