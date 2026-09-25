---
name: linux-privesc
description: Enumerate and confirm Linux privilege-escalation paths across sudo, SUID, services, credentials, and containers
origin: RedteamOpencode
---

# Linux Privilege Escalation

## When to Activate

- A Linux foothold is available and the objective requires root or another user's privileges
- Local enumeration shows sudo rules, unusual binaries, scheduled jobs, writable services, or container sockets

## Tools

`run_tool nmap`, `run_tool linpeas`, `run_tool ps`, `run_tool find`, `run_tool getcap`, `run_tool systemctl`, `run_tool crontab`, `run_tool atq`, `run_tool docker`, `run_tool mount`, `run_tool uname`, `run_tool searchsploit`, Metasploit (exploit phase).

## Methodology

### 1. Establish Context
Collect identity, kernel, init, mounts, namespaces, and capabilities before testing one vector. Save the baseline under `$DIR/scans/`.

```bash
run_tool nmap -sV -sC -p 22,111,2049,2375,2376 HOST
run_tool id
run_tool uname -a
run_tool cat /etc/os-release
run_tool hostnamectl
run_tool ip -brief address
run_tool ip route
run_tool ss -lntup
run_tool ps auxww
run_tool capsh --print
```

### 2. Sudo and File Execution
Enumerate direct and indirect sudo rules, NOPASSWD entries, sudoers includes, and writable commands. Confirm one candidate with `sudo -n -l` or a harmless `id` through the identified rule; leave payload execution to exploit-developer.

```bash
run_tool sudo -l
run_tool sudo -n -l
run_tool ls -l /etc/sudoers /etc/sudoers.d
run_tool grep -R -n -E 'NOPASSWD|ALL|Defaults' /etc/sudoers /etc/sudoers.d
```

### 3. SUID, SGID, and Capabilities
Inventory SUID/SGID files, capabilities, interpreters, editors, archive tools, and shell escapes. Map each binary to a known gadget and keep one bounded confirmation per vector.

```bash
run_tool find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null # SUID/SGID candidates
run_tool getcap -r / 2>/dev/null
run_tool linpeas
run_tool file /usr/bin/find /usr/bin/sudo /usr/bin/pkexec /usr/bin/su
run_tool python3 -c 'import os; print(os.getuid())' # bounded context check
```

Map `python`, `perl`, `ruby`, `awk`, `tar`, `cp`, `vim`, `less`, `find`, `env`, and `nmap` against GTFOBins-style escape conditions. Do not batch-run every gadget.

### 4. Cron, Timers, and PATH
Inspect user and system schedules, timer definitions, at jobs, and every writable component of `PATH`. Flag relative-path service execution, writable scripts, and user-controlled arguments.

```bash
run_tool crontab -l
run_tool ls -l /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
run_tool systemctl list-timers --all
run_tool systemctl list-unit-files --state=enabled
run_tool atq
run_tool sh -lc 'printf "%s\n" "$PATH"; printf "%s\n" "$HOME"' # execution context
```

### 5. Writable Units, Services, and Libraries
Review unit drop-ins, service binaries, shared-library search paths, loader variables, and world-writable files under `/etc` or `PATH`. A writable unit or library is a candidate, not a completed escalation.

```bash
run_tool systemctl cat UNIT
run_tool systemctl show UNIT -p ExecStart -p User -p FragmentPath -p DropInPaths
run_tool find /etc /usr/local/bin /usr/local/sbin -xdev -perm -0002 -ls 2>/dev/null # writable config/PATH
run_tool cat /etc/ld.so.preload
run_tool printenv LD_PRELOAD LD_LIBRARY_PATH PATH
run_tool ldd BINARY
```

Test `LD_PRELOAD` and `LD_LIBRARY_PATH` only with an existing service context and a non-destructive marker. Do not overwrite production libraries.

### 6. Containers, NFS, and Kernel Triage
Check privileged containers, host mounts, cgroup controls, `release_agent` reachability, runtime sockets, and namespace isolation. For NFS, inspect exports for `no_root_squash` and writable paths; for the kernel, correlate the exact version with local exploit intelligence.

```bash
run_tool docker info
run_tool docker ps -a
run_tool docker inspect CONTAINER
run_tool mount
run_tool cat /proc/1/cgroup
run_tool find /sys/fs/cgroup -name release_agent -ls 2>/dev/null
run_tool find /run -type s \( -name 'docker.sock' -o -name 'containerd.sock' \) -ls 2>/dev/null
run_tool showmount -e HOST
run_tool grep -n -E 'no_root_squash|rw' /etc/exports
run_tool rpcinfo -p HOST
run_tool nmap -p 111,2049 --script nfs-showmount,nfs-ls HOST
run_tool uname -r
run_tool searchsploit linux kernel
```

### 7. Bounded Escalation Candidates
Rank candidates by required privilege, persistence side effects, and evidence quality. Confirm one vector at a time with `id`, a harmless file read, or a service-context observation; the actual chain belongs to exploit-developer.

### Lab objective recall closure

When the active profile lists a privilege objective, requeue the exact sudo, capability, SUID, or service workflow that produced the candidate, save one bounded proof under `$DIR/scans/`, and run `python3 ./scripts/lab_objective.py snapshot "$DIR"`. Hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`; do not call a generic `id` result solved.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A08-integrity-failures.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`.

## Confirm-Only Rule

Enumerate and confirm one bounded proof per vector; record the candidate, evidence, and next action. The actual escalation chain is owned by `exploit-developer` at `stage=vuln_confirmed`; do not install persistence or silently alter the target here.

## Budget

`--host-timeout 120s`; one confirmation per vector; no mass gadget, kernel, or container-exploit loops.
