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

### 7. Modern and Less-Common Vectors
Check vectors that linpeas-style enumeration sometimes under-reports. Confirm each with a read-only observation, not execution.

```bash
run_tool busctl list 2>/dev/null # D-Bus services reachable by the current user
run_tool ls -l /var/run/dbus /run/dbus 2>/dev/null
run_tool pkexec --version 2>/dev/null # polkit/pkexec version for known CVEs (e.g. CVE-2021-4034)
run_tool cat /etc/polkit-1/rules.d/*.rules 2>/dev/null
run_tool systemctl list-sockets 2>/dev/null # socket-activated units triggerable by unprivileged connects
run_tool find / -xdev -type f -name '*.timer' -o -name '*.socket' 2>/dev/null
run_tool getcap -r / 2>/dev/null | grep -E 'cap_dac_read_search|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_setuid'
run_tool printenv PYTHONPATH LD_AUDIT PERL5LIB RUBYOPT NODE_OPTIONS
run_tool cat /proc/sys/kernel/core_pattern
run_tool apt-config dump 2>/dev/null | grep -i 'pre-invoke\|post-invoke' # apt/dpkg hook injection
run_tool snap list 2>/dev/null; run_tool ls -l /snap 2>/dev/null
run_tool grep -R -n 'env_keep\|!requiretty\|secure_path' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Map findings to their gadget class: `cap_dac_read_search`/`cap_dac_override` on a binary bypasses file-read/write DAC checks without full root; `cap_sys_ptrace` allows attaching to another user's process memory; `cap_sys_module`/`cap_sys_admin` are near-equivalent to root. A tar/rsync/find invocation running as a privileged cron job over an attacker-writable directory is a wildcard-injection candidate (`tar czf x.tgz *` → craft filenames starting with `--checkpoint=1` style flags) — record the exact cron line and writable directory rather than triggering it. Treat `env_keep` entries (especially `LD_PRELOAD`, `PYTHONPATH`, `BASH_ENV`) inside a `NOPASSWD` sudo rule as a direct escalation path, not just a candidate. A stale `pkexec`/`polkit` version pinned to a known CVE (e.g. CVE-2021-4034/PwnKit, CVE-2021-3560) is a confirm-only version match, not a proof — leave triggering to exploit-developer.

### 8. Systemd Timer, Service, and Generator Hijack
Beyond flagging a writable unit (step 5), enumerate the specific hijack primitives systemd exposes: `OnCalendar`/`OnBootSec` timers paired with a writable `ExecStart` target, `ExecStartPre`/`ExecStartPost` directives pointing at a writable helper, `WantedBy`/`Requires` drop-ins under a user-writable `/etc/systemd/system/UNIT.d/`, and systemd generators under `/run/systemd/generator` or `/lib/systemd/system-generators` that re-run on every boot/reload as root. Also check `systemd-run` delegation and D-Bus policy files that grant `org.freedesktop.systemd1.Manager` methods to non-root units.

```bash
run_tool systemctl list-timers --all
run_tool find /etc/systemd/system /lib/systemd/system -name '*.timer' -exec cat {} \;
run_tool find /etc/systemd/system -maxdepth 2 -type d -name '*.d' -ls
run_tool find /run/systemd/generator /lib/systemd/system-generators -type f -ls 2>/dev/null
run_tool cat /etc/dbus-1/system.d/*.conf 2>/dev/null | grep -B2 -A2 'org.freedesktop.systemd1'
run_tool systemctl show UNIT -p ExecStartPre -p ExecStartPost -p ExecReload
```

A timer whose `ExecStart` binary or script directory is writable by the current user is a direct root-cron-equivalent; record the exact timer name, next trigger, and writable path rather than editing it here.

### 9. Container-Escape-Adjacent Misconfiguration
Extend step 6's container triage with the specific escape primitives rather than stopping at "privileged: true". Check for a writable `release_agent` combined with actual `cgroup.procs` write access (the full PoC chain, not just file presence), a mounted `/var/run/docker.sock` reachable from inside a container, `CAP_SYS_ADMIN`/`CAP_SYS_PTRACE`/`CAP_SYS_MODULE` retained in a container's effective set, a host PID or network namespace shared into the container (`--pid=host`, `--net=host`), and a writable `/proc/sys/kernel/core_pattern` or `/proc/sysrq-trigger` reachable through a shared procfs mount.

```bash
run_tool cat /proc/self/status | grep -i capeff
run_tool nsenter --version 2>/dev/null
run_tool ls -l /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
run_tool cat /proc/self/cgroup
run_tool mount | grep -E 'cgroup|overlay|devpts'
run_tool find / -xdev -maxdepth 3 -name '.dockerenv' -o -name '.containerenv' 2>/dev/null
run_tool cat /proc/1/mountinfo 2>/dev/null | grep -E 'proc|sys'
```

Record the exact escape primitive present (docker.sock reachability, retained capability, or shared namespace) and the evidence path; do not `nsenter` into the host namespace or write to `release_agent` outside a bounded exploit-developer-owned confirmation.

### 10. Bounded Escalation Candidates
Rank candidates by required privilege, persistence side effects, and evidence quality. Confirm one vector at a time with `id`, a harmless file read, or a service-context observation; the actual chain belongs to exploit-developer.

### Lab objective recall closure

When the active profile lists a privilege objective, requeue the exact sudo, capability, SUID, or service workflow that produced the candidate, save one bounded proof under `$DIR/scans/`, and run `python3 ./scripts/lab_objective.py snapshot "$DIR"`. Hand off `objective=<name> status=solved|requeued evidence=<path> next=<exact action>`; do not call a generic `id` result solved.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A08-integrity-failures.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/offensive-tactics/credential-access/credential-theft-misc.md`.

## Confirm-Only Rule

Enumerate and confirm one bounded proof per vector; record the candidate, evidence, and next action. The actual escalation chain is owned by `exploit-developer` at `stage=vuln_confirmed`; do not install persistence or silently alter the target here.

## Budget

`--host-timeout 120s`; one confirmation per vector; no mass gadget, kernel, or container-exploit loops.
