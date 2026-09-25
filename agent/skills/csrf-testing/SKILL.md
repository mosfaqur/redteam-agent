---
name: csrf-testing
description: Cross-site request forgery testing for state-changing operations
origin: RedteamOpencode
---

# CSRF Testing (Cross-Site Request Forgery)

## When to Activate

- State-changing operations (POST, PUT, DELETE, PATCH)
- Cookie-based authentication
- Forms or API calls that modify user data, settings, or permissions

## Tools

- `run_tool curl` (manual request replay)
- Burp Suite (generate CSRF PoC)
- Browser DevTools (inspect cookies, headers)
- Custom HTML PoC pages

## Methodology

### 1. Identify CSRF Protections

- [ ] Check for CSRF token in forms (hidden field `csrf_token`, `_token`, `authenticity_token`)
- [ ] Check for CSRF token in headers (`X-CSRF-Token`, `X-XSRF-Token`)
- [ ] Check `SameSite` attribute on session cookies
- [ ] Check `Referer` / `Origin` header validation
- [ ] Check custom headers requirement (e.g., `X-Requested-With`)
- [ ] Check `Content-Type` enforcement (JSON only = partial protection)

### 2. Test Token Validation

- [ ] Remove CSRF token entirely — does request succeed?
- [ ] Submit empty token value
- [ ] Use token from another session / different user
- [ ] Reuse old/expired token
- [ ] Change token to arbitrary value
- [ ] Check if token is tied to session or independent
- [ ] Swap HTTP method: POST → GET (may skip token check)

### 3. Test SameSite Cookie Bypass

- [ ] `SameSite=None` — no protection, full CSRF possible
- [ ] `SameSite=Lax` — test top-level GET navigation (form method=GET)
- [ ] `SameSite=Lax` — 2-minute window after cookie set (Chrome)
- [ ] No SameSite set — defaults vary by browser (Lax in Chrome)
- [ ] Check if API uses cookies at all (vs Bearer tokens)

### 4. Test Referer/Origin Validation

- [ ] Remove `Referer` header entirely (use `<meta name="referrer" content="no-referrer">`)
- [ ] Set Origin to `null` (sandboxed iframe, data: URI)
- [ ] Subdomain spoofing: `https://target.com.attacker.com`
- [ ] Prefix bypass: `https://attacker.com/target.com`
- [ ] Check regex flaws in validation

### 5. Build CSRF PoC

- [ ] Auto-submit form:
      ```html
      <form action="https://target/change-email" method="POST">
        <input name="email" value="attacker@evil.com">
      </form>
      <script>document.forms[0].submit()</script>
      ```
- [ ] Image tag for GET: `<img src="https://target/delete?id=1">`
- [ ] XHR/fetch for JSON APIs (if CORS allows)
- [ ] Multipart form for file upload CSRF

### 6. High-Value Targets

- [ ] Password change (without current password)
- [ ] Email change
- [ ] Account settings modification
- [ ] Admin actions (create user, change roles)
- [ ] Financial transactions
- [ ] API key generation / rotation

### 7. Chained Attacks

- [ ] CSRF + Self-XSS = stored XSS via CSRF
- [ ] CSRF + login = login CSRF (force victim into attacker's account)
- [ ] CSRF + CORS misconfiguration

### 8. Multipart/JSON Content-Type Bypass

`Content-Type` enforcement is a common CSRF mitigation because plain HTML forms can only send `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain` cross-origin without triggering a CORS preflight. Test whether the server's JSON-only parser can still be reached:
- [ ] `text/plain` body containing raw JSON — some frameworks parse the body regardless of declared `Content-Type`, and `text/plain` is a CORS-safelisted type (no preflight)
- [ ] `application/x-www-form-urlencoded` body shaped as flat JSON-equivalent keys, if the framework's model binder accepts both encodings on the same endpoint
- [ ] Flash/legacy `multipart/form-data` boundary tricks to smuggle a JSON-like body if an old parser is in play — low priority, only worth checking on legacy stacks

### 9. Double-Submit and Custom-Header Token Weaknesses

- [ ] Double-submit cookie pattern: if the token is only validated by comparing the cookie value against a request field (not against a per-session server-side store), a CSRF landing page that itself sets/reads the cookie (via a same-site subdomain or a separate vulnerability) can forge the match
- [ ] Custom-header requirement (e.g. `X-Requested-With: XMLHttpRequest`) is not CSRF protection if the header value is static/predictable and a simple-request-compatible method still reaches the same logic — confirm the header is actually required, not just conventionally sent by the SPA's HTTP client
- [ ] Token leakage via GET: if the CSRF token appears in a URL (query string) it can leak through `Referer` headers on subsequent cross-origin requests or browser history — test whether the app ever transmits the token this way

### 10. Clickjacking as a CSRF-Adjacent Primitive

When state-changing actions require only a click (no unpredictable parameters, e.g. "delete account", "enable 2FA off", "accept invite"), CSRF-token presence doesn't block a clickjacking UI-redress attack because the victim's own authenticated click submits the (correctly tokened) form:
- [ ] Check for `X-Frame-Options: DENY`/`SAMEORIGIN` or a `Content-Security-Policy: frame-ancestors` directive on sensitive pages
- [ ] If absent, build a minimal iframe-overlay PoC (`<iframe src="https://target/sensitive-action" style="opacity:0.001">`) positioned under a decoy UI element to confirm the click reaches the real page
- [ ] Note this is a distinct finding from token-based CSRF — report it as clickjacking/UI redressing even when it was discovered while testing CSRF protections

## What to Record

- Endpoint and action vulnerable to CSRF
- Missing or bypassable protection mechanism
- Working PoC HTML
- Business impact of the forged action
- Severity: Medium (settings change) to High (account takeover, financial)
- Remediation: synchronizer token pattern, SameSite=Strict, Origin validation
