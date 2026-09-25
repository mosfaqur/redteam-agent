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
- **PrintNightmare (CVE-2021-1675/34527)** — check spooler exposure: `rpcdump.py HOST | grep -i spool` or `nxc smb HOST -u USER -p PASS -M spooler`.
- **ZeroLogon (CVE-2020-1472)** — DC-only; `nmap --script smb-vuln-zerologon` or `zerologon-tester.py HOST DC-NAME`; confirm only, exploitation resets the machine account password and is destructive — flag for exploit-developer with explicit warning.
- **noPac/SamAccountName spoofing (CVE-2021-42278/42287)** — check with `nxc smb HOST -u USER -p PASS -M nopac` when a domain foothold exists.
- Signing disabled → relay candidate (confirm only; exploitation to exploit-developer).

### 6. Relay & Coercion (confirm feasibility only)
- Note if SMB signing is `disabled`/`not required` (relay prerequisite): `nxc smb HOST --gen-relay-list relay_targets.txt` across a subnet sweep.
- Check LDAP signing/channel binding on DCs — a second common relay target alongside SMB (`nxc ldap HOST -M ldap-signing`).
- Identify coercion primitives without triggering them: PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), ShadowCoerce (MS-FSRVP), DFSCoerce — note whether the spooler/EFSRPC/FSRVP named pipes are reachable (`nxc smb HOST -u USER -p PASS -M petitpotam` / `-M printerbug` in check-only mode); these feed an ntlmrelayx relay-to-LDAPS/ADCS chain that is exploit-developer's to run.
- Do NOT run Responder/ntlmrelayx/coercion triggers unattended without explicit operator approval; report the
  candidate and let exploit-developer own the attack.

### 7. IPC$ / Named Pipe & Registry Enumeration
- [ ] Enumerate accessible named pipes over IPC$: `smbclient //HOST/IPC$ -U USER%PASS -c 'showconnect'` and `nxc smb HOST -u USER -p PASS --shares`
- [ ] Remote registry read (if `RemoteRegistry` service is running): `reg.py DOMAIN/USER:PASS@HOST query -keyName 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'` for build/patch-level fingerprinting
- [ ] Dump LSA secrets / SAM remotely once local admin is confirmed: `secretsdump.py DOMAIN/USER:PASS@HOST` (hand off to exploit-developer — this is credential extraction, not enumeration)
- [ ] Check for writable shares that host logon scripts or GPO templates (`SYSVOL`, `NETLOGON`) — a writable `SYSVOL`/GPO path is a privesc primitive (GPO abuse), note but do not modify

### 8. Password Spraying (bounded, confirm-only)
- [ ] Validate lockout policy BEFORE any spray: `nxc smb HOST -u USER -p PASS --pass-pol` — respect the observed lockout threshold, spray at most 1 password per account per lockout-reset window
- [ ] Season-based / policy-derived guesses only (e.g. `CompanyName2026!`) against a known valid username list — never brute-force blind

### 9. Alternate Null-Session Variants & RPC Surface (confirm only)
- [ ] SMB1-only null enumeration: some legacy/hardened hosts reject null sessions over SMB2/3 but still answer on SMB1 — force the dialect: `smbclient --option='client min protocol=NT1' --option='client max protocol=NT1' -N -L //HOST`
- [ ] Guest-enabled vs true null session are distinct findings — test blank-username/blank-password (`smbmap -H HOST -u '' -p ''`) separately from a named `guest` account with blank password (`smbmap -H HOST -u guest -p ''`); a host can reject one and accept the other
- [ ] RPC endpoint mapper enumeration independent of any SMB auth state: `rpcdump.py HOST` (impacket) lists every exposed named-pipe/RPC interface (`spoolss`, `efsrpc`, `lsarpc`, `samr`, `netlogon`) — this is the coercion/relay attack surface and is reachable even when `enumdomusers` is disabled
- [ ] RID cycling via `lsarpc`/`samr` as an anonymous-bind fallback: when `enumdomusers` is blocked by `RestrictAnonymous`, SID-to-name resolution often still works — `rpcclient -U '' -N HOST -c 'lookupsids S-1-5-21-<domain-sid>-500'` and increment the RID to enumerate accounts one at a time
- [ ] `RestrictAnonymous`/`RestrictNullSessAccess` registry state (if remote registry is reachable): `reg.py DOMAIN/USER:PASS@HOST query -keyName 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -v RestrictAnonymous` — explains why null-session results differ across hosts in the same domain
- [ ] SMB1 dialect negotiation as an unpatched-host indicator: a host that still negotiates SMB1 (`smbclient -m NT1`) independent of the null-session result is a higher-probability MS17-010/legacy-CVE candidate and should be prioritized for step 5

### 10. Cross-Protocol Relay Chaining (candidate identification only)
- [ ] SMB → ADCS HTTP enrollment (ESC8-class): if `ldap-kerberos` step 5 flagged a CA web-enrollment endpoint (`certsrv`), a captured SMB/HTTP auth via coercion can relay directly into a certificate request — cross-reference, do not chain here
- [ ] SMB → MSSQL relay: `xp_dirtree`/`xp_subdirs`-triggered outbound SMB auth from a linked/discoverable MSSQL instance can be relayed back; note the MSSQL host as a relay-trigger candidate for `database-services` follow-up, do not trigger it
- [ ] LDAP signing/channel-binding weakness on DCs is the other half of the SMB-signing relay picture — see `ldap-kerberos` step for the matching check; report both together when either is disabled

## References

`references/active-directory/ad-enumeration.md`, `references/offensive-tactics/lateral-movement/smb-wmi-lateral.md`,
`references/offensive-tactics/credential-access/credential-theft-misc.md`.

## Budget

`--host-timeout 120s`. Enumeration only for the confirm stage; exploitation is stage=vuln_confirmed.
