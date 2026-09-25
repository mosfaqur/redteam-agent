---
name: web-cache-attacks
description: Test web cache poisoning, deception, and unkeyed inputs by proving cache-key behavior and serving an injected response to a second request
origin: RedteamOpencode
---

# Web Cache Attacks

## When to Activate

- A reverse proxy, CDN, or application cache serves the same URL, and responses expose `X-Cache`, `Age`, `Vary`, or vendor cache headers
- User-controlled headers, query parameters, paths, or extensions may not be part of the cache key

## Tools

`run_tool curl`, `run_tool ffuf`, `run_tool nuclei`.

## Methodology

### 1. Establish Cache Behavior
Request the same cacheable URL twice with the same method, body, cookies, and query. Save raw headers and bodies; inspect `X-Cache`, `Age`, `Cache-Control`, `Vary`, `ETag`, and vendor-specific status without assuming a header is authoritative.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/cache-base-1.headers" -o "$DIR/scans/cache-base-1.html" "$CACHE_URL"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/cache-base-2.headers" -o "$DIR/scans/cache-base-2.html" "$CACHE_URL"
```

### 2. Test Unkeyed Headers
Change one header at a time: `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`, `Forwarded`, `X-Forwarded-Proto`, and `X-Rewrite-URL`. Use a fresh marker per attempt, preserve the baseline, and do not send a header that breaks routing beyond the bounded test.

```bash
HEADER_MARKER="cache-header-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
REWRITE_MARKER="cache-rewrite-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -H "X-Forwarded-Host: $HEADER_MARKER.example" \
  -D "$DIR/scans/cache-header-$HEADER_MARKER.headers" \
  -o "$DIR/scans/cache-header-$HEADER_MARKER.html" "$CACHE_URL"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -H "X-Original-URL: /$REWRITE_MARKER" \
  -D "$DIR/scans/cache-original-$REWRITE_MARKER.headers" \
  -o "$DIR/scans/cache-original-$REWRITE_MARKER.html" "$CACHE_URL"
```

Repeat with the other listed headers one per request. A reflected header alone is not cache poisoning; compare the next request and cache metadata.

### 3. Test Unkeyed Query Parameters
Try a single innocuous parameter such as a campaign, source, or cache-busting value. Re-request the original URL without the marker; an unchanged cached body containing the marker suggests the parameter was unkeyed, but verify with headers and a second control.

```bash
QUERY_MARKER="cache-query-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$CACHE_URL?utm_source=$QUERY_MARKER" \
  -D "$DIR/scans/cache-query-$QUERY_MARKER.headers" \
  -o "$DIR/scans/cache-query-$QUERY_MARKER.html"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/cache-query-revisit.headers" \
  -o "$DIR/scans/cache-query-revisit.html" "$CACHE_URL"
```

Use `run_tool ffuf` only for a small, reviewed parameter list and a short time budget. If `ffuf` is absent, replay one parameter with `run_tool curl`; do not mistake a key-specific response for an unkeyed response.

### 4. Map the Cache Key
Compare two requests differing only in path, query, method, `Host`, forwarding headers, cookies, and content negotiation. Read `Vary` and cache status on both responses, and distinguish a cache miss, hit, stale hit, bypass, or origin response.

```bash
VARIANT_MARKER="cache-variant-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
run_tool curl -sS --connect-timeout 5 --max-time 20 -I "$CACHE_URL"
run_tool curl -sS --connect-timeout 5 --max-time 20 -I "$CACHE_URL?variant=$VARIANT_MARKER"
```

### 5. Poison, Revisit, and Prove
Use a fresh marker for each poison attempt. The revisit request must omit the attacker-controlled header or parameter; require the marker in the second body plus `X-Cache`, `Age`, or equivalent proof that the response came from cache.

```bash
POISON_MARKER="cache-poison-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -H "X-Forwarded-Host: $POISON_MARKER.example" \
  -D "$DIR/scans/cache-poison-$POISON_MARKER.headers" \
  -o "$DIR/scans/cache-poison-$POISON_MARKER.html" "$CACHE_URL"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/cache-revisit-$POISON_MARKER.headers" \
  -o "$DIR/scans/cache-revisit-$POISON_MARKER.html" "$CACHE_URL"
```

If the cache documents `PURGE`, invalidate only the exact object key after saving evidence. A successful `PURGE` response is not proof of poisoning and must not be used to bypass the second-request test.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PURGE "$CACHE_URL"
```

### 6. Test Cache Deception
Request a dynamic object through a static-looking path or extension, then request the same object with a static suffix. Look for path normalization, extension confusion, and static-suffix bypass; compare body, status, content type, and cache metadata.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/cache-deception-css.headers" \
  -o "$DIR/scans/cache-deception-css.html" "${OBJECT_URL}.css"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/cache-deception-static.headers" \
  -o "$DIR/scans/cache-deception-static.html" "${OBJECT_URL}/asset.js"
```

Use an inert marker or harmless redirect target for triage. Do not count a dynamic response merely because the path ends in a static suffix; require the same object to be served from cache on a second request.

### 7. Read CDN Differences
Treat vendor headers as hints, not universal proof: Cloudflare commonly exposes `CF-Cache-Status` and `Age`; Akamai commonly exposes `X-Cache` and `X-Akamai-*`; Fastly commonly exposes `X-Cache`, `X-Cache-Hits`, and `Fastly-Debug`; CloudFront commonly exposes `X-Cache`, `Age`, and `x-amz-cf-id`. Rules, Workers, forwarding-header trust, normalization, and private bypasses can change behavior.

### 8. Apply the Finding Gate
A reflected marker, a single 200, or a one-off origin response is not a cache finding. For cached XSS or redirect impact, require the first poisoned response and a second request without the injection to return the marker from cache, preserve both raw bodies and headers, and hand the proven case to `exploit-developer`.

If `nuclei` is unavailable, use the `run_tool curl` poison-then-revisit loop directly. If `run_tool curl` is unavailable, stop and record the missing runtime dependency; never substitute a bare host request.

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A06-insecure-design.md`, `references/payloads/xss-payloads.md`, `references/payloads/info-disclosure-probes.md`, `references/tools/recon/curl.md`, `references/tools/fuzzing/ffuf.md`.
