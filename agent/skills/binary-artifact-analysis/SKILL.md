---
name: binary-artifact-analysis
description: Statically analyze compiled clients, firmware, and installers for hardcoded secrets, keys, and architecture
origin: RedteamOpencode
---

# Binary Artifact Analysis

## When to Activate

- A downloadable client, updater, installer, APK, firmware image, or compiled agent is in scope
- The task is to recover hardcoded credentials, keys, certificates, or map protocol endpoints and architecture
- A prior finding or handoff points at a specific artifact with suspected embedded secrets

## Tools

`run_tool curl`, `file`, `strings`, `xxd`, `readelf`, `objdump`, `openssl`, `base64`, `tar`, `unzip`, `python3`, `grep`, `awk`, `sed`

## Methodology

### 1. Acquire and Identify the Artifact

Download one approved artifact with a bounded request, record its type and SHA-256, and keep every derived file under `$DIR/scans/`. Never fetch a second artifact or chase redirects into out-of-scope hosts.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 "https://HOST/download/client.bin" -o "$DIR/scans/artifact.bin"
file "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.filetype"
sha256sum "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.sha256"
wc -c "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.size"
```

Treat the file type as the ground truth for every later step; do not unpack an executable as if it were an archive.

### 2. Extract Strings and Metadata

Pull printable strings and header metadata once. For ELF/PE binaries, record architecture, linked libraries, section names, and embedded version/build strings. Keep the pass bounded; do not dump the whole binary.

```bash
strings -n 8 "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.strings"
grep -nEi 'version|build|compile|gcc|go1\.|\.net|framework|(c) ?[0-9]{4}' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.version.txt"
if file "$DIR/scans/artifact.bin" | grep -qi 'ELF'; then readelf -h -d -S "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.elf.txt" 2>/dev/null; fi
xxd -l 256 "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.header.hex"
if file "$DIR/scans/artifact.bin" | grep -qi 'PE32\|MS-DOS'; then objdump -x "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.pe.txt" 2>/dev/null || true; grep -nEi '\.dll$|kernel32|advapi32|wininet|ws2_32|crypt32' "$DIR/scans/artifact.pe.txt" > "$DIR/scans/artifact.pe-imports.txt" 2>/dev/null || true; fi
```

### 2a. Packer, Obfuscation & Entropy Detection

A high-entropy or packed binary hides the string/secret searches below until unpacked; flag it rather than assuming the artifact is clean.

```bash
grep -nEi 'UPX!|\.upx|petite|aspack|themida|vmprotect|\.enigma|confuser|obfuscat' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.packer-hints.txt"
python3 -c "
import collections,math,sys
data=open('$DIR/scans/artifact.bin','rb').read()
if not data: sys.exit()
counts=collections.Counter(data)
entropy=-sum((c/len(data))*math.log2(c/len(data)) for c in counts.values())
print(f'entropy={entropy:.2f} bits/byte (>7.5 suggests packed/encrypted/compressed payload)')
" > "$DIR/scans/artifact.entropy.txt" 2>/dev/null || true
grep -nc . "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.string-density.txt"
```

A low string count combined with high entropy is the standard packed-binary signature: note it and stop — do not attempt to unpack/decrypt beyond this static confirm-stage pass.

### 3. Recover Hardcoded Credentials, Keys, and Certificates

Search strings for password, key, token, and secret literals; extract any embedded PEM certificates and decode their subjects. Record candidate fields only — do not publish the values into findings verbatim.

```bash
grep -nEi 'pass(word|wd)?|pwd|secret|token|api[-_ ]?key|private[-_ ]?key|BEGIN (RSA|EC|OPENSSH|CERTIFICATE)|aes|nonce|authorization|bearer' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.secret-candidates.txt"
awk '/BEGIN .*CERTIFICATE/{flag=1} flag{print} /END .*CERTIFICATE/{flag=0}' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.certs.pem"
if [ -s "$DIR/scans/artifact.certs.pem" ]; then openssl x509 -in "$DIR/scans/artifact.certs.pem" -noout -subject -issuer -dates -fingerprint -sha256 > "$DIR/scans/artifact.certs.txt" 2>/dev/null || true; fi
```

A recovered credential or key is evidence of a hardcoded secret, not proof of impact; note the field name and its surrounding context, then stop.

### 4. Unpack Archives, Firmware, and Installers

For archive-like artifacts only, list entries first and extract no more than needed to prove exposure. Identify filesystem blobs (SquashFS, CPIO) without mounting or writing to the target.

```bash
if file "$DIR/scans/artifact.bin" | grep -qiE 'gzip|zip|tar|cpio|xz|bzip2'; then tar -tf "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.entries" 2>/dev/null || unzip -l "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.entries" 2>/dev/null || true; fi
grep -nEi 'passwd|shadow|authorized_keys|\.pem|\.key|\.crt|\.conf|\.ini|\.xml|\.json|id_rsa|database' "$DIR/scans/artifact.entries" > "$DIR/scans/artifact.interesting-entries" 2>/dev/null || true
xxd "$DIR/scans/artifact.bin" | grep -niE 'hsqs|sqsh|squashfs|070701' | head -5 > "$DIR/scans/artifact.filesystem-blobs.txt" 2>/dev/null || true
grep -nEi 'u-boot|uboot|barebox|das u-boot|linux version|kernel panic|bootargs|/dev/mtdblock|jffs2|ubifs|yaffs|cramfs|initramfs' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.bootloader-hints.txt"
```

Filesystem/bootloader magic-byte quick reference (hex, first bytes of the blob): SquashFS `68 73 71 73` ("hsqs") or `73 71 73 68`; CPIO newc `30 37 30 37 30 31`; JFFS2 `85 19 03 20`; UBI `55 42 49 23`; UBIFS `31 18 10 06`; gzip `1f 8b`; Device Tree Blob `d0 0d fe ed`; U-Boot legacy image header `27 05 19 56`. A DTB or U-Boot header found mid-file often marks a concatenated multi-partition firmware image — note the offset rather than assuming a single filesystem.

Never bulk-extract an entire firmware image; extract a single interesting entry only when a concrete filename or path justifies it.

### 4a. Symbol Recovery & Static Anti-Debug/Anti-Analysis Triage

Recover what identifiers survived compilation before falling back to raw disassembly, and flag anti-analysis logic that will block a later dynamic pass rather than trying to defeat it here.

```bash
if file "$DIR/scans/artifact.bin" | grep -qi 'ELF'; then
  readelf -sW "$DIR/scans/artifact.bin" 2>/dev/null | grep -vE '^\s*$|UND$' > "$DIR/scans/artifact.symbols.txt"
  nm -C --defined-only "$DIR/scans/artifact.bin" > "$DIR/scans/artifact.symbols-demangled.txt" 2>/dev/null || true
fi
if file "$DIR/scans/artifact.bin" | grep -qi 'PE32\|MS-DOS'; then
  objdump -x "$DIR/scans/artifact.bin" 2>/dev/null | awk '/Ordinal\/Name Pointer/{flag=1} flag' > "$DIR/scans/artifact.pe-exports.txt" || true
fi
grep -nEi 'ptrace|PTRACE_TRACEME|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|TracerPid|__gdb|anti[-_]?debug|SIGTRAP|OutputDebugString' \
  "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.anti-debug-hints.txt"
grep -nEi 'go\.buildid|GOROOT|runtime\.main|__rust_probestack|rustc|swift_|_ZN|\.pdata|\.gopclntab' \
  "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.toolchain-symbols.txt"
```

A populated `artifact.symbols.txt`/`.symbols-demangled.txt` gives function-level names for free — grep those for auth/crypto/network-facing function names (`verify`, `check_license`, `decrypt`, `handle_request`) before assuming a stripped-binary workflow is required. A near-empty symbol table combined with a hit in `artifact.strings` for `strip`/no `.symtab` section (check `readelf -S` for `.symtab` presence) confirms the binary was deliberately stripped — note this as an anti-analysis signal, not a dead end, since dynamic symbols (`.dynsym`, PE export table) often still leak enough for later identification. Anti-debug hints are a flag for the exploit-developer handoff (dynamic analysis will need a bypass, e.g. `ptrace`-based self-trace, environment patching, or an LD_PRELOAD shim) — do not attempt to patch or defeat them from this static-only skill.

### 4b. String/Constant-Based Vulnerability Triage

Before or instead of full disassembly, mine the string and constant table for patterns that reliably correlate with specific vulnerability classes, and record only the candidate + surrounding context.

```bash
grep -nEi '%s.*%s.*%s|strcpy|strcat|sprintf\(|gets\(|system\(|popen\(|exec[lv]p?\(|memcpy\(' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.unsafe-c-api.txt"
grep -nEi 'select \*|union select|drop table|insert into|%s.*where|query.*=.*\+' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.sqli-format-hints.txt"
grep -nEi 'md5|sha1\b|des-ecb|rc4|ECB|hardcoded|default[-_ ]?password|debug[-_ ]?mode|backdoor|god[-_ ]?mode' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.weak-crypto-debug-hints.txt"
grep -nEi 'CVE-[0-9]{4}-[0-9]+|CWE-[0-9]+' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.embedded-cve-refs.txt"
grep -nEo '\b(openssl|zlib|libpng|libcurl|busybox|openssh|sqlite)[-_ ]?[0-9]+(\.[0-9]+){1,3}\b' "$DIR/scans/artifact.strings" -i | sort -u > "$DIR/scans/artifact.bundled-lib-versions.txt"
```

Treat each list as a triage lead, not a finding: an unsafe-C-API hit only confirms the *function* is linked/called somewhere, not that attacker input reaches it — correlate against the endpoint/protocol map from Section 5 before handing off. `artifact.bundled-lib-versions.txt` is the highest-leverage list here — a statically-linked library with a recoverable version string is an immediate, low-effort N-day lookup (chain into `osint-analyst` / CVE correlation) that often outpaces custom vulnerability hunting in the binary itself.

### 5. Map Hardcoded Endpoints, Protocols, and Architecture

Recover hardcoded hostnames, URLs, ports, and protocol constants. Correlate them with the target scope; discard anything out of scope.

```bash
grep -nEoi 'https?://[a-z0-9./:_-]+' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.urls.txt"
grep -nEio '[a-z0-9-]+(\.[a-z0-9-]+)+' "$DIR/scans/artifact.strings" | sort -u > "$DIR/scans/artifact.hostnames.txt"
grep -nEo '(:[0-9]{2,5}|port[ =:]+[0-9]{2,5})' "$DIR/scans/artifact.strings" | sort -u > "$DIR/scans/artifact.ports.txt"
grep -nEi '^[a-z_]+://|socket|connect|bind|listen|sip|rtp|tunnel|keepalive|heartbeat' "$DIR/scans/artifact.strings" > "$DIR/scans/artifact.protocol-hints.txt"
```

Record the recovered architecture only when it maps to an in-scope endpoint or protocol; a hardcoded third-party domain is a note, not a target.

### 6. Classify and Hand Off

Never execute the binary on the target or in the runtime. Classify each recovered secret as credential, key, certificate, or endpoint, then hand off the exact artifact path, the secret field, and the surrounding context to exploit-developer for a bounded validation pass.

```bash
printf '%s\n' \
  "artifact: $DIR/scans/artifact.bin" \
  "type: $(cat "$DIR/scans/artifact.filetype")" \
  "secret class: credential | key | certificate | endpoint" \
  "context: document the surrounding string and any version/build marker" \
  "stage=vuln_confirmed only after exploit-developer validates the secret against the target" \
  > "$DIR/scans/artifact-handoff.txt"
```

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/vuln-checklists/A03-supply-chain-failures.md`, `references/handoff-protocols.md`.

## Confirm-Only Rule

Static extraction is confirm-stage. A recovered secret or key is evidence, not demonstrated impact. Never execute the artifact on the target, never run destructive or dynamic analysis against the target from this skill, and never publish a full secret value into a finding. Hand off to exploit-developer for bounded validation; promotion to `stage=vuln_confirmed` belongs to that handoff.

## Budget

One artifact per engagement case, at most 40 MB download, 15 minutes wall-clock, and one extraction pass per archive; no bulk firmware extraction, no brute force, no target-side execution.
