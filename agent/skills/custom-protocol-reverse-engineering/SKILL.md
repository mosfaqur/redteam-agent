---
name: custom-protocol-reverse-engineering
description: Reverse engineer and safely test undocumented TCP and UDP protocols
origin: RedteamOpencode
---

# Custom Protocol Reverse Engineering

## When to Activate

- A TCP or UDP service has no usable public protocol documentation
- A device-management daemon, embedded service, or vendor client-server protocol is identified
- A real client, packet capture, or binary traffic is available for an undocumented service
- The goal is to map framing and messages before a bounded parser-safety review

## Tools

`run_tool nmap`, `run_tool nc`, `run_tool tcpdump`, `run_tool tshark`, `timeout`, `jq`, `python3`, `xxd`, `openssl`, `base64`, `grep`, `awk`, `sed`, `printf`, `file`

## Methodology

### 1. Reachability and Passive Capture

For each approved `HOST` and `PORT`, distinguish TCP connect from UDP response behavior, perform a banner grab and collect the first response, and save raw bytes plus hexdumps under `$DIR/scans/`. If a client binary or existing traffic is available, capture one real handshake with `tcpdump`; summarize its fields with `tshark`. Do not guess commands before observing traffic.

```bash
run_tool nmap -Pn -sT -p PORT --host-timeout 60s --max-retries 2 HOST; run_tool nmap -Pn -sU -p PORT --host-timeout 60s --max-retries 2 HOST; run_tool nc -zvw 5 HOST PORT; run_tool nc -zvw 5 -u HOST PORT
run_tool nc -nv -w 5 HOST PORT </dev/null > "$DIR/scans/banner.bin" 2>"$DIR/scans/banner.stderr" || true
run_tool tcpdump -nn -s 512 -c 2 -G 8 -W 1 -w "$DIR/scans/reachability.pcap" "host" HOST "and" "port" PORT & CAP_PID=$!; run_tool nc -nv -w 5 HOST PORT </dev/null > "$DIR/scans/first-response.bin" 2>/dev/null || true; kill "$CAP_PID" 2>/dev/null || true; wait "$CAP_PID" 2>/dev/null || true
if [ -n "${CLIENT_BIN:-}" ] && [ -x "${CLIENT_BIN}" ]; then run_tool tcpdump -nn -s 512 -c 8 -G 8 -W 1 -w "$DIR/scans/client-handshake.pcap" "host" HOST "and" "port" PORT & CAP_PID=$!; timeout 5 "${CLIENT_BIN}" >/dev/null 2>&1 || true; kill "$CAP_PID" 2>/dev/null || true; wait "$CAP_PID" 2>/dev/null || true; fi
xxd -g 1 "$DIR/scans/banner.bin" > "$DIR/scans/banner.hexdump"; xxd -g 1 "$DIR/scans/first-response.bin" > "$DIR/scans/first-response.hexdump"; run_tool tshark -r "$DIR/scans/reachability.pcap" -T fields -e tcp.payload -e udp.payload > "$DIR/scans/reachability.payloads.txt" 2>/dev/null || true
```

### 2. Infer Framing

Treat directions independently. Test length prefixes of 2 and 4 bytes in both endian orders, delimiter-terminated frames, TLV/tag-length pairs, a fixed header + variable body, text line protocol, and length-less binary. Require alignment across repeated frames.

```bash
xxd -g 1 -c 16 "$DIR/scans/first-response.bin" > "$DIR/scans/frame.hexdump"
python3 - "$DIR/scans/first-response.bin" > "$DIR/scans/framing-candidates.txt" <<'PY'
from pathlib import Path
import struct, sys
raw = Path(sys.argv[1]).read_bytes()
for width in (2, 4):
    for endian, code in (("big", ">H" if width == 2 else ">I"), ("little", "<H" if width == 2 else "<I")):
        print(f"{endian}-endian {width}-byte length={struct.unpack_from(code, raw)[0] if len(raw) >= width else 'short'}")
for label, byte in (("newline", 10), ("NUL", 0)):
    print(label, [i for i, value in enumerate(raw) if value == byte][:16])
PY
```

### 3. Check Variable-Length and Self-Describing Encodings

Before committing to a fixed-width length field, test whether the protocol uses a variable-length integer scheme (Protobuf-style base-128 varint, LEB128) or a self-describing tag/length scheme (ASN.1 BER/DER, TLV-nested). These are common in RPC and industrial-control protocols and are easy to misidentify as fixed 2/4-byte lengths.

```bash
python3 - "$DIR/scans/first-response.bin" > "$DIR/scans/varint-candidates.txt" <<'PY'
from pathlib import Path
import sys
raw = Path(sys.argv[1]).read_bytes()
# Protobuf/LEB128-style varint: continuation bit is the high bit of each byte
value, shift, consumed = 0, 0, 0
for b in raw[:10]:
    consumed += 1
    value |= (b & 0x7f) << shift
    if not (b & 0x80):
        break
    shift += 7
print("varint-candidate value", value, "consumed-bytes", consumed)
# ASN.1 BER/DER short/long-form length octet (second byte for a simple SEQUENCE)
if len(raw) >= 2:
    length_octet = raw[1]
    if length_octet & 0x80:
        print("ber-long-form length-of-length", length_octet & 0x7f)
    else:
        print("ber-short-form length", length_octet)
PY
```

Record which candidate (fixed-width, varint, or BER/DER) stays consistent across multiple captured frames; do not commit to a framing model from a single sample.

### 4. Map Structure

Build one small `python3` parser under `$DIR/tools/` and reuse it in every later step. Map offsets and widths for magic, version, flags, opcode, length, checksum, sequence, and body; mark unknowns instead of guessing. Save the field map with the capture.

```bash
python3 - "$DIR/tools/frame_parser.py" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)
Path(sys.argv[1]).write_text('''import struct, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_bytes()
if len(raw) < 14:
    print("short frame", len(raw))
else:
    magic, version, flags, opcode, length, sequence, checksum = struct.unpack_from("<4sBBHHHH", raw)
    print("magic", magic.hex(), "version", version, "flags", hex(flags), "opcode", opcode, "length", length, "sequence", sequence, "checksum", hex(checksum), "body", raw[14:14 + length].hex(), "trailing", len(raw[14 + length:]))
''')
PY
python3 "$DIR/tools/frame_parser.py" "$DIR/scans/first-response.bin" > "$DIR/scans/field-map.txt"
```

### 5. Map the State Machine

Enumerate only observed client→server message types, the minimum handshake order, and per-message fields. Mark missing client traffic as unknown rather than inventing authentication. Record transitions in a table using observed labels:

| Observed state | Client→server message | Fields | Observed next state |
|---|---|---|---|
| `S0` | `M0` | magic, version, flags, length | `S1` |
| `S1` | `M1` | opcode, sequence, body | `S2` or error |
| `S2` | `M2` | opcode, correlation, payload | `S2`, `S3`, or error |
| `S3` | `CLOSE` | sequence, reason | closed |

```bash
python3 "$DIR/tools/frame_parser.py" "$DIR/scans/first-response.bin" > "$DIR/scans/state-input.txt"; run_tool tshark -r "$DIR/scans/client-handshake.pcap" -T fields -e tcp.payload -e udp.payload > "$DIR/scans/client-fields.txt" 2>/dev/null || true
printf '%s\n' 'direction|message|fields|precondition|next_state' 'C->S|OBSERVED|record every observed field|document required predecessor|record only observed transition' > "$DIR/scans/state-machine.tsv"
```

### 6. Discover Encoding and Cryptography

Compare repeated fields across frames. Run the analysis against the first response captured in step 1 (`first-response.bin`), or substitute `client-handshake.pcap` when a client handshake was captured. Test only evidence-guided XOR, ROT-like, short repeating-key, and base64-wrapped transformations. For length-prefixed encryption, record whether the prefix is plaintext and whether it is covered by the cipher. Check for RC4 or AES with static handshake keys/IVs, and extract keys/IVs from captured traffic or local client artifacts only—never guess keys or brute force.

```bash
python3 "$DIR/tools/frame_parser.py" "$DIR/scans/first-response.bin" > "$DIR/scans/crypto-input.txt" 2>/dev/null || true
python3 - "$DIR/scans/first-response.bin" > "$DIR/scans/encoding-candidates.txt" <<'PY'
from pathlib import Path
import sys
raw = Path(sys.argv[1]).read_bytes()
for width in (1, 2, 4, 8, 16):
    chunks = [raw[i:i + width] for i in range(0, len(raw) - width + 1, width)]
    repeated = next((chunk for chunk in chunks if chunks.count(chunk) > 1), None)
    print("repeating-key", width, repeated.hex() if repeated else "none")
for shift in (1, 2, 3, 4, 13, 26):
    print("rot", shift, bytes((value - shift) % 256 for value in raw[:16]).hex())
PY
if [ -s "$DIR/scans/first-response.b64" ]; then base64 -d "$DIR/scans/first-response.b64" > "$DIR/scans/first-response-decoded.bin"; fi; openssl list -cipher-algorithms > "$DIR/scans/openssl-ciphers.txt" 2>/dev/null || true; grep -nEi 'key|iv|nonce|rc4|aes|cipher|encrypt|decrypt' "$DIR/scans/client-fields.txt" > "$DIR/scans/crypto-markers.txt" 2>/dev/null || true
```

### 7. Test Parser Attack Hypotheses

Use exactly one malformed frame per hypothesis (within the 1-2 bounded-probe confirm bound), then stop: overlong length field, malformed/short frame, embedded NUL, integer overflow in size math, format-string characters, unescaped shell metacharacters in text-like fields, command/opcode dispatch with no auth, and — when step 3 identified a varint or BER/DER-style length — one recursive/nested-length frame declaring a nested structure length larger than the outer frame (a common parser-recursion or over-read trigger distinct from a flat overlong length). Do not add variants or repeated streams.

```bash
python3 - "$DIR/scans" <<'PY'
from pathlib import Path
import struct, sys
d = Path(sys.argv[1])
d.joinpath("probe-overlong.bin").write_bytes(struct.pack("<H", 4096)); d.joinpath("probe-short.bin").write_bytes(b"\x01\x00"); d.joinpath("probe-nul.bin").write_bytes(b"\x08\x00A\x00B"); d.joinpath("probe-overflow.bin").write_bytes(struct.pack("<I", 0x7fffffff))
d.joinpath("probe-format.bin").write_bytes(b"\x0c\x00%s%s%n"); d.joinpath("probe-shell.bin").write_bytes(b"\x0c\x00id;printf P\n"); d.joinpath("probe-unauth.bin").write_bytes(b"\x08\x00\x01\x00\x00\x00\x00\x00")
PY
python3 "$DIR/tools/frame_parser.py" "$DIR/scans/probe-short.bin" > "$DIR/scans/probe.parse.txt" 2>/dev/null || true
run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-overlong.bin" || true; run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-short.bin" || true; run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-nul.bin" || true; run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-overflow.bin" || true
run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-format.bin" || true; run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-shell.bin" || true; run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-unauth.bin" || true
```

### 8. Confirm a Crash Safely

Send one bounded malformed frame only. Classify a clean error response, a hang, and a connection reset from the saved bytes and exit behavior. NEVER loop, NEVER send repeated/truncated streams; no flooding, destructive actions, or denial-of-service testing. A timeout alone is an observation, not an availability finding: rule 12 requires a repeatable server-side differential beyond one timeout.

```bash
python3 - "$DIR/scans/probe-crash.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"\x02\x00")
PY
python3 "$DIR/tools/frame_parser.py" "$DIR/scans/probe-crash.bin" > "$DIR/scans/crash.parse.txt" 2>/dev/null || true
run_tool nc -nv -w 5 ${NC_UDP_FLAG:-} HOST PORT < "$DIR/scans/probe-crash.bin" > "$DIR/scans/crash-response.bin" 2>"$DIR/scans/crash-response.stderr" || true
printf '%s\n' 'clean error=response with error' 'hang=bounded timeout without response' 'reset=close/reset without response' > "$DIR/scans/crash-classification.txt"
```

### 9. Binary Diff Against a Known Version or Patch

When a client or server binary is available locally and a prior/patched version can be obtained (vendor update, package repo cache, or a second firmware image), a binary diff often reveals the exact protocol field or opcode a patch changed — far faster than blind structure guessing. Use this only when both binaries are legitimately in scope/possession; never download a target's proprietary binary from an unauthorized source.

```bash
run_tool file "$DIR/tools/client-v1.bin" "$DIR/tools/client-v2.bin"
python3 - "$DIR/tools/client-v1.bin" "$DIR/tools/client-v2.bin" > "$DIR/scans/binary-diff-strings.txt" <<'PY'
import sys, re
from pathlib import Path
def strings(data, minlen=4):
    return set(re.findall(rb'[\x20-\x7e]{%d,}' % minlen, data))
a = strings(Path(sys.argv[1]).read_bytes())
b = strings(Path(sys.argv[2]).read_bytes())
print("added-in-v2:", len(b - a))
for s in sorted(b - a)[:40]:
    print("+", s.decode(errors="replace"))
print("removed-from-v1:", len(a - b))
for s in sorted(a - b)[:40]:
    print("-", s.decode(errors="replace"))
PY
run_tool nm -D "$DIR/tools/client-v1.bin" > "$DIR/scans/symbols-v1.txt" 2>/dev/null || true
run_tool nm -D "$DIR/tools/client-v2.bin" > "$DIR/scans/symbols-v2.txt" 2>/dev/null || true
diff "$DIR/scans/symbols-v1.txt" "$DIR/scans/symbols-v2.txt" > "$DIR/scans/symbol-diff.txt" 2>/dev/null || true
```

New or renamed symbols, added validation-sounding strings (`invalid length`, `bounds check`, `truncated`), or a new opcode constant in the diff are strong hints for which field a vendor patched — cross-reference that field against the parser attack hypotheses in step 7 instead of testing every field blindly.

### 10. Identify Fuzzable Fields Systematically

Rank fields from the structure map (step 4) and state machine (step 5) by fuzz-worthiness before handing anything to `fuzzer` or exploit-developer: a length/size field feeding a buffer or allocation, an offset/index used to walk an array without an observed bounds check, a string/name field with no declared maximum, a nested tag/type field controlling which downstream parser branch runs, and any field whose value round-trips unchanged into a response (echoed fields are prime injection candidates). De-prioritize fields whose value never varies across captured frames (likely fixed magic/version).

```bash
python3 - "$DIR/scans/field-map.txt" > "$DIR/scans/fuzzable-fields.txt" <<'PY'
import sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
rank = {"length": 1, "size": 1, "offset": 2, "index": 2, "opcode": 3, "flags": 3, "sequence": 4, "checksum": 5, "magic": 6, "version": 6}
fields = []
for line in lines:
    for token in line.replace(",", " ").split():
        key = token.split("=")[0].lower() if "=" in token else token.lower()
        if key in rank:
            fields.append((rank[key], key))
for score, name in sorted(set(fields)):
    print(score, name)
PY
printf '%s\n' 'priority: length/size fields > offset/index fields > opcode/type dispatch > echoed fields > sequence/checksum > fixed magic/version (skip)' >> "$DIR/scans/fuzzable-fields.txt"
```

Hand this ranked list to `fuzzer` or exploit-developer instead of an unranked field dump so mutation effort concentrates on fields most likely to reach an unchecked size/allocation/dispatch path.

### 11. Hand Off

Give exploit-developer the exact framed request bytes, field map, transport, state preconditions, expected and observed response, and one confirmed signal. Include capture and hexdump paths. Promote only after a reproducible unauthorized dispatch, exposed operation, or other concrete security signal; never promote a guess, missing client observation, timeout, or isolated crash.

```bash
python3 "$DIR/tools/frame_parser.py" "$DIR/scans/probe-crash.bin" > "$DIR/scans/handoff-fields.txt" 2>/dev/null || true
printf '%s\n' "framed request: $DIR/scans/probe-crash.bin" "field map: $DIR/scans/field-map.txt" "state preconditions: document the observed predecessor state" "confirmed signal: record one reproducible server-side signal" "stage=vuln_confirmed only after confirmation" > "$DIR/scans/exploit-handoff.txt"
```

## References

`references/vuln-checklists/A10-exceptional-conditions.md`, `references/vuln-checklists/A04-cryptographic-failures.md`, `references/handoff-protocols.md`.

## Confirm-Only Rule

Framing, state, encoding, and parser hypotheses are confirm-stage. A case moves to `stage=vuln_confirmed` only with framed, reproducible evidence of unauthorized dispatch, unauthorized data access, or another concrete security signal. A client timeout, hang, or one-off crash remains an observation; availability claims require the server-side differential in vulnerability-analyst rule 12. Full exploitation belongs to exploit-developer.

## Budget

`--host-timeout 120s`; at most 10 captured frames and 8 malformed probes per service; no loops, flooding, brute force, or denial-of-service testing.
