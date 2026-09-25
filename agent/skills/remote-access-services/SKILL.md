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

Additional SSH checks:
- [ ] Algorithm downgrade / weak KEX-cipher-MAC support: `ssh-audit HOST` flags deprecated `diffie-hellman-group1-sha1`, CBC ciphers, `hmac-md5`
- [ ] Host key reuse across hosts/engagements (shared default images, cloned VMs) — compare host key fingerprints across in-scope hosts
- [ ] `AuthorizedKeysCommand`/agent-forwarding misconfig: if a foothold exists, check `ssh -A` agent-forwarding trust chains for lateral pivoting (confirm only)
- [ ] Public-key auth username enumeration timing side channel (pre-patch OpenSSH) alongside CVE-2018-15473
- [ ] `sshd_config` exposure via banner/version fingerprinting → cross-reference known distro backdoor/CVE lists (e.g. XZ/liblzma backdoor CVE-2024-3094 on affected versions)
- [ ] Forced algorithm downgrade probe (bounded, one connection): `ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -oHostKeyAlgorithms=ssh-rsa -oCiphers=aes128-cbc USER@HOST` — confirm whether the server still completes a handshake using only legacy algorithms even when `ssh-audit` lists them as merely "offered" rather than preferred
- [ ] Host-key trust-on-first-use weakness: if the engagement has prior known_hosts data for this host/IP range, diff the presented key fingerprint against history — a changed host key without an announced rotation is either MITM evidence or a redeployed/cloned image (ties to the host-key-reuse check above)
- [ ] Certificate-based SSH auth (`ssh-keygen -L` on any discovered host cert) — check CA trust anchor scope and principal restrictions if a CA-signed host/user cert is in use; overly broad principal wildcards undermine per-host pinning

### RDP (3389)
```bash
run_tool nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info HOST
run_tool nmap -p 3389 --script rdp-vuln-ms12-020 HOST
# NLA status + hostname/domain disclosure; credential validation
nxc rdp HOST -u USER -p PASS
```
BlueKeep (CVE-2019-0708) — check only; exploit belongs to exploit-developer.

Additional RDP checks:
- [ ] `nxc rdp HOST -u '' -p ''` for NLA-disabled anonymous negotiation exposure
- [ ] RDP session/credential caching: if a foothold exists, check for cached RDP credentials in `mstsc` history or Credential Manager (confirm only, hand extraction to exploit-developer)
- [ ] CVE-2020-0609/0610 (RD Gateway RCE) if a gateway is fronting RDP — check gateway HTTP endpoint fingerprint

### WinRM (5985/5986)
```bash
run_tool nmap -p 5985,5986 --script http-title HOST
nxc winrm HOST -u USER -p PASS
```
- [ ] Confirm WinRM auth (Basic/NTLM/Negotiate) accepts the validated credential; a working WinRM session is an immediate command-exec primitive — report as `vuln_confirmed`, do not open an interactive shell here
- [ ] Check for HTTP (5985) vs HTTPS (5986) — cleartext Basic auth over 5985 is a credential-exposure finding on its own
- [ ] `evil-winrm`/`crackmapexec winrm --local-auth` for local-vs-domain account distinction when spraying

### VNC (5900)
```bash
run_tool nmap -p 5900 --script vnc-info,vnc-brute HOST
# no-auth / weak password
run_tool vncviewer HOST::5900
```
VNC often has no auth or a short password; confirm access, then record.

Additional VNC checks:
- [ ] Explicit auth-type enumeration before connecting: `vnc-info` reports the offered security types (`None`=1, `VNC Auth`=2, `Tight`/`VeNCrypt`=vendor-specific) — a server offering type `None` alongside stronger types may still accept the weak option if the client requests it; confirm the weakest accepted type, not just the first offered
- [ ] RealVNC/UltraVNC repeater mode (`5500`) — a reachable repeater can proxy connections to internal-only VNC targets behind it; note as a pivot candidate, do not traverse
- [ ] Known auth-bypass CVEs by vendor/version: RealVNC 4.1.1/4.1.2 auth-bypass (protocol downgrade to no-auth), UltraVNC pre-1.2.x buffer issues — version-map via the `vnc-info` banner before assuming exploitability
- [ ] VNC file-transfer extension (UltraVNC/TightVNC) exposure — if authenticated access is confirmed, note whether file transfer is enabled as a data-exfil/upload primitive; do not transfer files here

### RDP NLA / CredSSP Downgrade Detail
- [ ] Explicit NLA-vs-legacy security-layer negotiation: `rdp-enum-encryption` reports whether `PROTOCOL_HYBRID` (NLA/CredSSP), `PROTOCOL_SSL`, or `PROTOCOL_RDP` (legacy, cleartext-capable RC4) are offered — a server still offering the legacy `PROTOCOL_RDP` layer alongside NLA allows a client to negotiate down to pre-auth, unencrypted-capable RDP
- [ ] CredSSP downgrade (CVE-2018-0886) — a patched client talking to an unpatched/misconfigured server (or vice versa) can be forced to negotiate CredSSP without encryption-oracle protection; confirm via the `rdp-enum-encryption` protocol list only, do not attempt the MITM
- [ ] `xfreerdp /sec:rdp` vs `/sec:nla` forced-mode connection attempts (bounded, one each) to confirm which legacy security layers the server actually completes a handshake on, beyond what the NSE script reports

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
