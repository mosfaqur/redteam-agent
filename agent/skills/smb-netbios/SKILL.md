---
name: smb-netbios
description: Enumerate and test SMB/NetBIOS/RPC services (null sessions, shares, users, relay, SMB CVEs)
origin: RedteamOpencode
---

# SMB / NetBIOS / RPC

## When to Activate

- Ports 139/445 (SMB), 135 (MSRPC), 137/138 (NetBIOS) open
- Windows/AD lab, file shares, domain controllers

## Tools

`run_tool nmap`, `smbclient`, `smbmap`, `enum4linux-ng`/`enum4linux`, `rpcclient`,
`netexec` (`nxc`/`crackmapexec`), Metasploit (exploit phase).

## Methodology

### 1. Fingerprint
```bash
run_tool nmap -sV -p 139,445 --script smb-os-discovery,smb2-security-mode,smb2-time HOST
run_tool nmap -p 139,445 --script smb-vuln-ms17-010,smb-vuln-ms08-067 HOST
```

### 2. Null / Guest Session
```bash
smbclient -N -L //HOST
smbmap -H HOST -u '' -p ''
rpcclient -U '' -N HOST -c 'enumdomusers;enumdomgroups;querydominfo'
enum4linux-ng -A HOST
```

### 3. Shares & Access
```bash
smbmap -H HOST -u USER -p PASS
smbclient //HOST/SHARE -U USER%PASS
# recursive listing / download for readable shares
```

### 4. Users / Policies / Password Policy
```bash
rpcclient -U 'USER%PASS' HOST -c 'enumdomusers'
nxc smb HOST -u USER -p PASS --users --pass-pol --shares
```

### 5. Known CVEs
- **MS17-010 (EternalBlue)** — `nmap --script smb-vuln-ms17-010`; exploit via Metasploit `exploit/windows/smb/ms17_010_eternalblue`.
- **MS08-067**, **SMBGhost (CVE-2020-0796)** — `nmap --script smb-vuln-cve-2020-0796`.
- Signing disabled → relay candidate (confirm only; exploitation to exploit-developer).

### 6. Relay (confirm feasibility only)
- Note if SMB signing is `disabled`/`not required` (relay prerequisite).
- Do NOT run Responder/ntlmrelayx unattended without explicit operator approval; report the
  candidate and let exploit-developer own the attack.

## References

`references/active-directory/ad-enumeration.md`, `references/offensive-tactics/lateral-movement/smb-wmi-lateral.md`,
`references/offensive-tactics/credential-access/credential-theft-misc.md`.

## Budget

`--host-timeout 120s`. Enumeration only for the confirm stage; exploitation is stage=vuln_confirmed.
