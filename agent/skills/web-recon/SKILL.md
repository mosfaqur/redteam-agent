---
name: web-recon
description: Enumerate web technologies, headers, endpoints, and metadata from a target
origin: RedteamOpencode
---

# Web Reconnaissance

## When to Activate

- Beginning of engagement, new domain/subdomain, need tech stack before deeper testing

## Tools

`run_tool curl`, `run_tool whatweb`, `openssl`, `grep`/`sed`/`jq`

## Methodology

### 1. HTTP Header Analysis
```bash
run_tool curl -sI -L https://TARGET
run_tool curl -sI https://TARGET | grep -iE "^(server|x-powered-by|x-aspnet|x-frame|content-security|strict-transport|set-cookie|www-authenticate)"
run_tool curl -sI -X OPTIONS https://TARGET
```
Note: Server, X-Powered-By, Set-Cookie flags, CSP, missing security headers.

### 2. Technology Fingerprinting
```bash
run_tool whatweb -a 3 https://TARGET
run_tool curl -sL https://TARGET | grep -iE "generator|powered.by|built.with"
run_tool curl -sL https://TARGET | grep -i '<meta' | head -20
```

### 3. CMS Detection
```bash
# WordPress
run_tool curl -s https://TARGET/wp-login.php -o /dev/null -w "%{http_code}"
run_tool curl -s https://TARGET/wp-json/wp/v2/users
run_tool curl -s https://TARGET/wp-content/debug.log -o /dev/null -w "%{http_code}"
run_tool curl -s "https://TARGET/?rest_route=/wp/v2/users"   # REST route fallback when /wp-json is blocked
# Joomla
run_tool curl -s https://TARGET/administrator/ -o /dev/null -w "%{http_code}"
run_tool curl -s https://TARGET/administrator/manifests/files/joomla.xml | grep -i version
# Drupal
run_tool curl -s https://TARGET/CHANGELOG.txt | head -5
run_tool curl -s https://TARGET/core/CHANGELOG.txt | head -5   # Drupal 8+
run_tool curl -s "https://TARGET/user/register?element_parents=account/mail/%23value&ajax_form=1" -o /dev/null -w "%{http_code}"  # CVE-2018-7600 probe surface
# Magento
run_tool curl -s https://TARGET/magento_version
run_tool curl -s https://TARGET/errors/report.php -o /dev/null -w "%{http_code}"
# TYPO3
run_tool curl -s https://TARGET/typo3/sysext/core/Resources/Public/Icons/Extension.svg -o /dev/null -w "%{http_code}"
# Shopify / SaaS storefront
run_tool curl -sI https://TARGET | grep -i "x-shopid\|x-shopify"
# Generic
run_tool curl -s https://TARGET/readme.html -o /dev/null -w "%{http_code}"
run_tool curl -s https://TARGET/package.json -o /dev/null -w "%{http_code}"   # Node app leaking dep manifest
```

### 3b. Favicon / Asset Hashing (Shodan/Censys-style fingerprint pivot)
```bash
run_tool curl -s https://TARGET/favicon.ico -o "$DIR/scans/favicon.ico"
python3 -c "import mmh3,base64,sys; data=open('$DIR/scans/favicon.ico','rb').read(); b64=base64.encodebytes(data); print(mmh3.hash(b64))" 2>/dev/null
# The resulting int32 hash is the same value Shodan indexes as http.favicon.hash — use it to pivot
# to other instances of the same admin panel/product across the internet during OSINT correlation.
```

### 3c. WAF / CDN Fingerprinting
```bash
run_tool curl -sI https://TARGET | grep -iE "cf-ray|x-sucuri|x-akamai|x-iinfo|x-cdn|server: cloudflare|x-cache|via:"
run_tool curl -s "https://TARGET/?id=1' OR '1'='1" -o /dev/null -w "%{http_code}\n"   # canary probe — a 403 on an inert-looking payload signals a WAF; feed that into waf-evasion-testing
run_tool curl -s -A "() { :; }; echo vulnerable" https://TARGET -o /dev/null -w "%{http_code}\n"  # some WAFs fingerprint differently on legacy shellshock-style UAs
```
Note the exact block page/status code returned — it is the baseline `waf-evasion-testing` needs to confirm a bypass later.

### 4. SSL/TLS Analysis
```bash
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"
for proto in tls1 tls1_1 tls1_2 tls1_3; do
  echo | openssl s_client -connect TARGET:443 -$proto 2>/dev/null | grep -q "Protocol" && echo "$proto: supported"
done
```

### 5. Well-Known Files
```bash
run_tool curl -s https://TARGET/robots.txt
run_tool curl -s https://TARGET/sitemap.xml | head -50
# Recurse into sub-sitemaps referenced by a sitemap index
run_tool curl -s https://TARGET/sitemap.xml | grep -oE '<loc>[^<]*</loc>' | sed 's/<[^>]*>//g'
run_tool curl -s https://TARGET/.well-known/security.txt
for path in crossdomain.xml clientaccesspolicy.xml humans.txt .well-known/openid-configuration \
            .well-known/oauth-authorization-server .well-known/change-password .well-known/apple-app-site-association \
            .well-known/assetlinks.json manifest.json browserconfig.xml ads.txt app-ads.txt; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  [ "$code" != "404" ] && echo "$path -> $code"
done
# Every Disallow line in robots.txt is a curated hint list — request each one directly, don't just log it
run_tool curl -s https://TARGET/robots.txt | grep -iE '^(dis)?allow:' | awk '{print $2}'
```

### 6. JS File Extraction (surface-level — deep analysis is source-analyzer's job)
```bash
run_tool curl -sL https://TARGET | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//'
# Quick grep for API paths and secrets in each JS file
```

Only queue endpoints that are directly requestable and evidenced by a real response or real
HTML/form/link extraction. Directory stems, SPA routes, and guessed names should stay as follow-up
notes or surface candidates, not queue inputs.

### 7. HTML Source (surface-level — deep analysis is source-analyzer's job)
```bash
run_tool curl -sL https://TARGET | grep -oE '<!--.*?-->'                           # Comments
run_tool curl -sL https://TARGET | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'  # Emails
run_tool curl -sL https://TARGET | grep -i 'type="hidden"'                         # Hidden fields
run_tool curl -sL https://TARGET | grep -oE 'href="[^"]*"' | sed 's/href="//;s/"//' | sort -u  # Links
```

### 8. HTTP Method & Protocol Probing
```bash
for m in GET HEAD POST PUT DELETE OPTIONS PATCH TRACE CONNECT PROPFIND; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" -X "$m" https://TARGET)
  echo "$m -> $code"
done
# TRACE enabled -> possible XST (Cross-Site Tracing); PROPFIND 207 -> WebDAV exposed
run_tool curl -s -X TRACE https://TARGET -H "X-Canary: reflect-me" | grep -i "X-Canary"
run_tool curl -sI --http2 https://TARGET 2>/dev/null | head -1    # HTTP/2 support (relevant for request-smuggling H2->H1 downgrade cases)
run_tool curl -sI --http3 https://TARGET 2>/dev/null | head -1    # HTTP/3 / QUIC support
```

### 9. Verbose Error & Stack-Trace Fingerprinting
```bash
run_tool curl -s "https://TARGET/nonexistent-$(date +%s)" | head -30   # 404 page often leaks framework/version
run_tool curl -s "https://TARGET/?debug=1" -o /dev/null -w "%{http_code}\n"
run_tool curl -s -H "X-Debug: true" -H "X-Forwarded-For: 127.0.0.1" https://TARGET -o /dev/null -w "%{http_code}\n"  # some apps unlock verbose/debug mode for loopback-looking clients
# Force a 500 with malformed input to capture a stack trace (framework, file paths, DB driver)
run_tool curl -s "https://TARGET/api/health?%00" -o /dev/null -w "%{http_code}\n"
```
Feed any leaked framework/version or file path directly into `info-disclosure-testing` and `sensitive-data-detection`.

### 10. CORS Configuration Probing
```bash
run_tool curl -s -H "Origin: https://evil.example.com" -I https://TARGET | grep -i "access-control"
run_tool curl -s -H "Origin: null" -I https://TARGET | grep -i "access-control-allow-origin"
run_tool curl -s -H "Origin: https://TARGET.evil.com" -I https://TARGET | grep -i "access-control-allow-origin"  # subdomain-suffix bypass check
run_tool curl -s -X OPTIONS -H "Origin: https://evil.example.com" -H "Access-Control-Request-Method: PUT" -I https://TARGET | grep -i "access-control"
```
A reflected arbitrary `Origin` combined with `Access-Control-Allow-Credentials: true` is an immediate finding — hand to `cors-testing` for exploitation.

### 11. Cookie Flag & Session Attribute Analysis
```bash
run_tool curl -sI https://TARGET | grep -i "set-cookie"
# Check each cookie for: Secure, HttpOnly, SameSite=Strict/Lax/None, Domain scope, Path scope, __Host-/__Secure- prefix
```
Missing `Secure`/`HttpOnly`/`SameSite`, an overly broad `Domain=.target.com`, or a session cookie without a `__Host-` prefix are recon signals — feed into `csrf-testing` and session-fixation checks.

### 12. GraphQL / API-Gateway Discovery
```bash
for path in graphql api/graphql v1/graphql graphiql playground .well-known/graphql \
            api/v1 api/v2 api/v3 api-docs swagger swagger-ui swagger.json openapi.json \
            api/health api/status api/version; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  [ "$code" != "404" ] && echo "$path -> $code"
done
run_tool curl -s -X POST https://TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' -o /dev/null -w "%{http_code}\n"
```
Any responsive GraphQL endpoint is a direct handoff to `source-analysis` (introspection dump) and `graphql-testing`.

### 13. TLS Cipher & Protocol Enumeration (depth beyond section 4)
```bash
run_tool nmap --script ssl-enum-ciphers -p 443 TARGET
run_tool testssl --fast TARGET:443 2>/dev/null | grep -iE "vulnerable|weak|offered"
run_tool curl -sI https://TARGET | grep -i "strict-transport-security"   # HSTS presence/max-age/preload
```
Weak cipher suites, missing HSTS, or expired/self-signed certs feed directly into a TLS-misconfiguration finding independent of the app-layer testing above.
