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
```

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
```

Never bulk-extract an entire firmware image; extract a single interesting entry only when a concrete filename or path justifies it.

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
