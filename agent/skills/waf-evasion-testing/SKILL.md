---
name: waf-evasion-testing
description: Test protective filtering layers for bounded route and header bypasses
origin: RedteamOpencode
---

# Protective Filtering-Layer Bypass Testing

## When to Activate

- A stateful reverse proxy, WAF, CDN edge, API gateway, or auth/session filter fronts an in-scope application
- The scope includes an origin address, alternate virtual host, cache, or static-resource exemption
- The task is to compare edge decisions with backend behavior using reproducible, bounded requests

## Tools

`run_tool curl`, `openssl`, jq, python3, awk, sed, printf, grep

## Methodology

### 1. Establish the Filter Boundary

Capture the edge response and certificate first, then compare allowed and blocked baselines. Use an origin comparison only when the origin address is explicitly in scope; identify the answering layer in every artifact.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/edge_protected_headers.txt" -o "$DIR/scans/edge_protected_body.txt" https://HOST/protected; run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/edge_open_headers.txt" -o "$DIR/scans/edge_open_body.txt" https://HOST/unprotected
openssl s_client -connect HOST:PORT -servername HOST -showcerts -issuer </dev/null > "$DIR/scans/boundary_tls.txt" 2>&1
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/origin_protected_headers.txt" -o "$DIR/scans/origin_protected_body.txt" https://HOST:PORT/protected; run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/origin_open_headers.txt" -o "$DIR/scans/origin_open_body.txt" https://HOST:PORT/unprotected
# Use the last two requests only with a documented in-scope origin.
```
Compare response headers, server banners, certificate issuer, error-page fingerprints, and status/body differences. Record which layer answered rather than assuming the edge is the origin.

### 2. Discover Rule Shapes

Test one or two variants for each matching class: path, suffix, method, content type, header presence, and cookie. Keep each request independent so the rule dimension is attributable.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/rule_dot.txt" "https://HOST/protected."; run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/rule_semicolon.txt" "https://HOST/protected;a=b" # dot; path parameter
run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/rule_space.txt" "https://HOST/protected%20"; run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/rule_case.txt" "https://HOST/PROTECTED" # space; case
run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/rule_double.txt" "https://HOST/%2570rotected"; run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/rule_separator.txt" "https://HOST/protected%2Fsegment" # double encoding; separator
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/rule_html.txt" "https://HOST/protected.html?format=asset"; run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/rule_css.txt" "https://HOST/protected.css?format=asset" # suffix equivalence
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' -o "$DIR/scans/rule_type_json.txt" "https://HOST/protected"; run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST -H 'Content-Type: application/json' --data '{"probe":1}' -o "$DIR/scans/rule_method_post.txt" "https://HOST/protected" # type; method
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data 'probe=1' -o "$DIR/scans/rule_type_form.txt" "https://HOST/protected"; run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-Request-Marker: present' -o "$DIR/scans/rule_header.txt" "https://HOST/protected" # type; header
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Cookie: session=present' -o "$DIR/scans/rule_cookie.txt" "https://HOST/protected"; run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/rule_query.txt" "https://HOST/protected?file=report" # cookie; query
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/rule_path.txt" "https://HOST/file/report" # path routing
```
Do not combine variants; a changed status, body, or downstream marker is a clue, not proof of a bypass.

### 3. Test Static-Resource and Auth-Filter Differentials

When a session or JWT filter appears to exempt static classes, compare exactly one protected dynamic route with its static-asset equivalent. Enumerate at most eight static-looking routes to size the class, then stop.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/static_dynamic_headers.txt" -o "$DIR/scans/static_dynamic_body.txt" https://HOST/account; run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/static_equivalent_headers.txt" -o "$DIR/scans/static_equivalent_body.txt" https://HOST/account.css
: > "$DIR/scans/static_gap_status.txt"
for route in /account.css /settings.css /orders.css /profile.css /billing.css /search.css /export.css /health.css; do
  run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/static_gap_body.txt" -w '%{http_code}\n' "https://HOST${route}" >> "$DIR/scans/static_gap_status.txt"
done
# Eight sample requests maximum; do not add dynamic routes.
```
Run the pair with the same in-scope session state. Report a class-level gap only when that state reaches the protected route through the static class; distinguish a class observation from demonstrated data or action impact.

### 4. Check Path Normalization Differentials

Compare a plain path with an encoded separator, an encoded dot-segment that may survive one proxy hop, and duplicate slashes. Use one probe per variant and stop after recording the pair.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/path_plain.txt" "https://HOST/protected/segment"
run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/path_encoded_separator.txt" "https://HOST/protected%2Fsegment"
run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/path_dot_segment.txt" "https://HOST/protected/%2e%2e/protected"
run_tool curl -sS --connect-timeout 5 --max-time 20 --path-as-is -o "$DIR/scans/path_duplicate_slash.txt" "https://HOST//protected"
# One request per variant; stop now.
```
Preserve the raw request target in the notes and compare the proxy-decoded form with the backend-decoded form. A different status alone does not prove route confusion.

### 5. Discover Virtual Hosts Safely

Prepare a file of no more than five engagement-approved names at `$DIR/scans/vhost_names.txt`; never add an outside name. Probe its first five entries, then compare `Host` and `X-Forwarded-Host` on the same path.

```bash
awk 'NR <= 5 {print}' "$DIR/scans/vhost_names.txt" |
while read -r vhost; do
  run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/vhost_${vhost}_headers.txt" -o "$DIR/scans/vhost_${vhost}_body.txt" -H "Host: $vhost" https://HOST/protected
done
vhost=$(awk 'NR == 1 {print}' "$DIR/scans/vhost_names.txt")
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/host_headers.txt" -o "$DIR/scans/host_body.txt" -H "Host: $vhost" https://HOST/protected; run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/forwarded_host_headers.txt" -o "$DIR/scans/forwarded_host_body.txt" -H "X-Forwarded-Host: $vhost" https://HOST/protected
```
Record which approved hostname changes origin behavior or an allowlist decision. Keep the probe to five names and seven requests total; do not query third-party hostnames.

### 6. Test Method and Header Overrides

Use one probe for each override class and do not spray combinations. The `example.com` header value is a documentation placeholder for an approved client value.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X GET -H 'X-HTTP-Method-Override: DELETE' -o "$DIR/scans/override_method.txt" https://HOST/protected; run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-Original-URL: /protected' -o "$DIR/scans/override_original_url.txt" https://HOST/
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-Rewrite-URL: /protected' -o "$DIR/scans/override_rewrite_url.txt" https://HOST/; run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-Forwarded-For: example.com' -o "$DIR/scans/override_forwarded_for.txt" https://HOST/allowlisted
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'X-Real-IP: example.com' -o "$DIR/scans/override_real_ip.txt" https://HOST/allowlisted
```
Compare the filter decision with the backend decision. A changed header is not a bypass until the downstream action or protected data is demonstrated.

### 7. Observe Rate Limiting and Ban State

Repeat one known blocked request at most five times. Record status, latency, retry headers, and any request or audit identifier; stop if a ban is indicated, and do not use external solving services, proxy rotation, distributed evasion, or log tampering.

```bash
: > "$DIR/scans/rate_limit_status.txt"
for attempt in 1 2 3 4 5; do
  run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/rate_limit_${attempt}_headers.txt" -o "$DIR/scans/rate_limit_${attempt}_body.txt" -w "$attempt %{http_code} %{time_total}\n" https://HOST/blocked >> "$DIR/scans/rate_limit_status.txt"
done
# Exactly five requests; stop after this block.
```
Treat a threshold or ban as filter behavior only when the same blocked request reproduces it. A slow response alone is not a rate-limit finding.

### 8. Check Cache-Key and Filter-Key Divergence

Run this only when `Age`, `Cache-Control`, `ETag`, or an equivalent cache indicator is evident. Send one request pair differing only in one query-key value, then compare status, body, and cache identity.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/cache_one_headers.txt" -o "$DIR/scans/cache_one_body.txt" "https://HOST/protected?view=one"; run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/cache_two_headers.txt" -o "$DIR/scans/cache_two_body.txt" "https://HOST/protected?view=two"
```
Call this a finding only if the filter decision changes while backend identity or content remains the same; otherwise record it as an observation and do not expand the pair.

### 9. Apply Reporting Discipline

A bypass is a finding only with a reproducible request/response pair, the layer bypassed, the affected route class, and demonstrated business impact. Use this bounded record for every candidate:

```bash
printf '%s\n' \
  'layer: edge, origin, gateway, or auth/session filter' \
  'evidence: request plus saved response headers and body' \
  'route class: suffix, method, header, cookie, path, or vhost dependency' \
  'impact: only an access or action shown by the response' \
  > "$DIR/scans/waf_reporting_record.txt"
# An unproven inference remains an observation.
```

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A06-insecure-design.md`, `references/api-security/API08-security-misconfiguration.md`, `references/tools/recon/curl.md`.

## Confirm-Only Rule

Rule-shape, normalization, vhost, override, rate-limit, and cache tests are confirm-stage. Promote only a reproducible bypass with a named layer, affected route class, and demonstrated business impact; otherwise record an observation and stop at the bound.

## Budget

Technique-class maximums: boundary 4 requests, rule-shape 15, static-gap 8 samples, normalization 4, vhost 7, overrides 5, rate-limit 5, cache 2, with 60s wall-clock per host; no flooding, rotation, CAPTCHA, or out-of-scope names.
