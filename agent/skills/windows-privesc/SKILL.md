---
name: windows-privesc
description: Enumerate and confirm Windows privilege-escalation paths through services, tokens, ACLs, and stored credentials
origin: RedteamOpencode
---

# Windows Privilege Escalation

## When to Activate

- A Windows or Active Directory foothold is available and the objective requires SYSTEM, administrator, or a privileged token
- Services, scheduled tasks, token privileges, registry keys, or stored credentials appear writable or abusable

## Tools

`run_tool nmap`, `run_tool nxc`/`run_tool netexec`, `run_tool impacket-psexec`, `run_tool impacket-wmiexec`, `run_tool secretsdump`, `run_tool icacls`, `run_tool sc.exe`, `run_tool schtasks`, `run_tool powershell.exe`, `run_tool whoami`, Metasploit (exploit phase).

## Methodology

### 1. Select a Transport and Establish Identity
Use Impacket or `nxc` when the agent is not yet on the box. Treat SMB 445 and WinRM 5985/5986 as the primary execution transports; use WMI/DCOM 135 and RDP 3389 only when already authorized and reachable.

```bash
run_tool nmap -sV -p 135,445,5985,5986,3389 HOST
run_tool nxc smb HOST -u USER -p PASS -x 'whoami /all'
run_tool nxc winrm HOST -u USER -p PASS -x 'whoami /all'
run_tool nxc rdp HOST -u USER -p PASS
run_tool impacket-psexec DOMAIN/USER:PASS@HOST
```

Run commands plainly after a shell is already on the target:

```powershell
whoami /all
systeminfo
Get-LocalUser
Get-LocalGroupMember Administrators
whoami /priv
```

### 2. Service Paths and Weak ACLs
Read every service path, account, quoting state, directory ACL, and binary ACL. For an unquoted path such as `C:\Program Files\App\service.exe`, record the exact space-delimited prefixes and test only the confirmed writable prefix; do not assume the first directory is exploitable. Check DLL search-order directories and trust boundaries with the same ACL pass.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'sc.exe qc SERVICE'
run_tool nxc smb HOST -u USER -p PASS -x 'sc.exe query SERVICE'
run_tool nxc smb HOST -u USER -p PASS -x 'icacls "C:\Program Files\App\service.exe"'
run_tool nxc smb HOST -u USER -p PASS -x 'icacls "C:\Program Files (x86)\App"'
run_tool nmap -p 445 --script smb-enum-services,smb-enum-pipes HOST
```

Flag writable binaries, writable parent directories, weak service DACLs, and DLL search paths. Confirm one service with a harmless identity read; service creation and reconfiguration remain exploit-developer actions.

### 3. DLL, Registry, and Installation Escalation
Inspect service and application DLL directories, `AppInit_DLLs`, `AlwaysInstallElevated`, auto-run keys, and installer policy. Check both HKLM and HKCU scopes and record trust, ownership, and write access.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"'
```

A writable DLL search location, installer policy, or auto-run key is a bounded confirmation candidate, not a reason to modify the key.

### 4. Token Privileges, Impersonation, and Named Pipes
Capture enabled and disabled token privileges, integrity levels, group memberships, and pipe ACLs. Prioritize `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, and `SeTcbPrivilege`; map the Potato family and named-pipe impersonation to the exact service identity.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'whoami /priv'
run_tool nxc smb HOST -u USER -p PASS -x 'whoami /groups'
run_tool nxc smb HOST -u USER -p PASS -x 'whoami /groups /v'
run_tool nmap -p 445 --script smb-enum-pipes,smb2-security-mode HOST
```

Record whether token duplication is possible, whether a pipe is writable by the current user, and whether a Potato-family prerequisite is present. Hand off the one impersonation chain; do not spray named pipes.

### 5. Scheduled Tasks, Service Abuse, and Auto-Runs
Enumerate task definitions, hidden tasks, service creation rights, and Run-key persistence points. A confirmed writable service or task principal is enough for the confirm stage.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'schtasks /query /fo LIST /v'
run_tool nxc smb HOST -u USER -p PASS -x 'schtasks /query /tn TASK /xml'
run_tool nxc smb HOST -u USER -p PASS -x 'sc.exe sdshow SERVICE'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"'
```

After confirmation, exploit-developer may evaluate `run_tool nxc smb HOST -u USER -p PASS -x 'sc.exe create ...'`, `run_tool nxc smb HOST -u USER -p PASS -x 'sc.exe config ...'`, or `run_tool nxc smb HOST -u USER -p PASS -x 'schtasks /create ...'`; enumeration does not create or reconfigure either object.

### 6. PowerShell, LOLBins, and AMSI
Record PowerShell execution policy, language mode, Constrained Language state, AMSI/provider status, and writable scripts. Confirm policy bypass and AMSI behavior only with an identity marker such as `whoami`.

```bash
run_tool nxc smb HOST -u USER -p PASS -x 'powershell.exe -NoProfile -Command "Get-ExecutionPolicy -List"'
run_tool nxc smb HOST -u USER -p PASS -x 'powershell.exe -NoProfile -Command "Get-MpComputerStatus"'
run_tool nxc smb HOST -u USER -p PASS -x 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "whoami"' # bounded policy check
run_tool nxc smb HOST -u USER -p PASS -x 'where powershell.exe; where certutil.exe; where mshta.exe'
```

Map writable scripts and trusted binaries to LOLBins and PowerShell execution options. Treat an AMSI bypass or constrained-language escape as exploit-developer-owned execution.

### 7. Stored Credentials and Local Secrets
Check local users, SAM-related registry exposure, DPAPI-protected credential stores, credential manager entries, and service-account material. Use a bounded account or store selection and redact values in evidence.

```bash
run_tool secretsdump 'DOMAIN/USER:PASS@HOST'
run_tool nxc smb HOST -u USER -p PASS -x 'cmdkey /list'
run_tool nxc smb HOST -u USER -p PASS -x 'vaultcmd /listcreds:"Windows Credentials"'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query HKLM\SAM /v F'
run_tool nxc smb HOST -u USER -p PASS -x 'reg query HKLM\SECURITY /v F'
```

### Lab objective recall closure

When the active profile lists a privilege objective, requeue the exact service, token, task, or stored-credential workflow that already produced a candidate, save one bounded result under `$DIR/scans/`, and run `python3 ./scripts/lab_objective.py snapshot "$DIR"`. Hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`; do not close on a generic administrator listing.

## References

`references/offensive-tactics/privilege-escalation/privesc-windows.md`, `references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`, `references/offensive-tactics/credential-access/sam-ntds-dumping.md`, `references/offensive-tactics/credential-access/lsass-dumping.md`, `references/offensive-tactics/code-execution/powershell-bypass.md`, `references/offensive-tactics/code-execution/lolbins-execution.md`.

## Confirm-Only Rule

Enumerate and confirm one bounded vector at a time; record the service, token, task, registry, or credential evidence and the next action. The actual escalation chain is owned by `exploit-developer` at `stage=vuln_confirmed`; do not create services, modify tasks, install persistence, or dump bulk secrets here.

## Budget

`--host-timeout 120s`; one transport and one confirmation per vector; no mass pipe, task, or credential enumeration.
