---
name: auth-bypass
description: Test for authentication and authorization flaws including credential attacks, session issues, and access control bypasses
origin: RedteamOpencode
---

# Authentication & Authorization Bypass

## When to Activate

- Login/register/reset forms, protected resources, admin panels
- Token/session/API key auth, role-based access, JWT/OAuth

## Authentication Testing

### 1. Default/Weak Credentials
```
admin:admin  admin:password  admin:123456  root:root  root:toor  test:test  guest:guest
```
Check username enumeration: different errors for valid/invalid users, timing diffs, selective lockout.

### 2. Brute Force (Hydra)
```bash
run_tool hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"
run_tool hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-get /admin
run_tool hydra -l root -P passwords.txt target ssh -t 4
# Rate-limited: -t 1 -W 5
```

### 3. Password Reset Flaws
- Predictable/reusable/non-expiring tokens, token not tied to account
- Host header injection: `Host: attacker.com` in reset request
- Parameter pollution: `email=victim@mail.com&email=attacker@mail.com`
- Lab recovery chains: when a security-question, reset-password, or exposed backup/source artifact exists, do not stop at "unknown answer". Correlate answers from source bundles, backup listings, incident files, leaked credentials, and OSINT hints; replay reset for high-value users (admin/support accounts named in `intel.md`), then immediately verify login and record solved-state/finding evidence. When a lab profile is active (`lab-profile.json`), use its `recall_branches` for the exact account/reset triggers.
- Treat a single wrong security answer as incomplete. Before closure, enumerate candidate answers from source bundles, comments, profile metadata, backup documents, and OSINT snippets; try the highest-confidence candidate set in a bounded pass, and if still blocked return `REQUEUE` with the exact candidate list and artifacts checked.
- If reset remains blocked, emit an explicit `REQUEUE_CANDIDATE` naming the missing answer source and the exact endpoints/artifacts already checked, so a later source-analysis or exploit pass can finish the chain instead of retiring it silently.

### 4. Session Management
- Session fixation: force token onto victim, use after auth
- Token analysis: collect 20+ tokens, check entropy/predictability/sequential patterns
- Invalidation: test logout, password change
- Cookie flags: check HttpOnly, Secure, SameSite, Domain/Path scope

### 5. MFA Bypass
- Direct navigation to post-auth pages, code brute-force (no rate limit), code reuse
- Response manipulation (`"success":false` → `true`), backup code enumeration
- MFA not enforced on all auth paths, disable without re-auth

### 6. Rate-Limit and Lockout Bypass Channels

Test whether the counter keys on something spoofable rather than the credential pair itself:
```
X-Forwarded-For: 1.2.3.4        # increment per rotating IP
X-Forwarded-For: 127.0.0.1      # trusted-proxy bypass, may also skip auth entirely
X-Real-IP / X-Client-IP / True-Client-IP / Forwarded: for=<ip>
```
- Case/whitespace variation on the username (`Admin` vs `admin` vs `admin `) — some lockout counters are case-sensitive and effectively give N attempts per casing variant.
- Alternate the identifier field: email vs username vs numeric user ID vs phone, if the endpoint accepts more than one — each may have its own independent counter.
- Distributed low-and-slow: stay under the lockout window's request-count/time threshold, never exceed 5 requests per identifier in-session per the bounded-probe rule above.
- Race the lockout: fire the N+1th attempt concurrently with the Nth so the counter hasn't incremented yet (chain into `race-condition-testing`).

### 7. WebAuthn / Passkey Downgrade

- Check whether a passkey-enrolled account can still fall back to password or SMS OTP — a downgrade path re-opens every weaker mechanism.
- Test origin/RP-ID validation: does the server verify `clientDataJSON.origin` matches the expected origin, or just that a signature validates?
- Check for missing `userVerification: "required"` enforcement — a bypassable "silent" authenticator assertion.

### 8. Authorization Matrix Across Verbs, Versions, and Formats

Authorization checks are frequently implemented once (e.g. a middleware keyed on exact path) and missed elsewhere. For every protected endpoint, vary independently:
- HTTP verb: `GET`/`POST`/`PUT`/`PATCH`/`DELETE`/`HEAD`/`OPTIONS`/`TRACE`
- API version prefix: `/v1/...` protected but `/v2/...` or unversioned `/api/...` not
- Content negotiation: same endpoint via `Accept: application/xml` or `.json`/`.xml` suffix — some frameworks route format-suffixed requests around auth middleware
- Trailing/duplicate slashes and case folding on the path itself, not just the final segment: `//admin`, `/Admin`, `/admin//`, `/admin%00`
- GraphQL: a REST endpoint's authz check has no bearing on the same resource exposed as a GraphQL field/mutation — test resolvers independently

### 9. Login CSRF / Session Injection

- Attacker logs the victim into the attacker's own account (via CSRF on the login form, or by pre-setting a session cookie before the victim authenticates) so the victim's subsequent actions are attributed to attacker-controlled state — used to harvest search history, saved payment data, or as a pivot for stored XSS in "your activity" pages.
- Check whether the login form is protected by an anti-CSRF token; unauthenticated forms are often skipped under the assumption "no session to attack yet."

### 10. Anti-Automation and Account-State Controls

Classify each CAPTCHA as a simple math/text CAPTCHA, an image/slider challenge, a proof-of-work challenge, or a third-party challenge. Inspect the same response and its related requests for an embedded answer, a predictable nonce, client-side-only validation, or an API that returns the answer, then confirm whether validation is enforced server-side.

For rate limiting and lockout, use no more than five requests. Determine whether failed logins are throttled, whether the counter is per-IP, per-account, or per-session, whether it resets, and whether a successful login clears it. Compare unknown-user, known-user, wrong-password, and disabled/locked-account responses by status code, body length, redirect target, and response time; report account enumeration only when the differential is reproducible.

Test workflow/state bypasses by registering and then logging in without verifying the email, reusing a pre-verification token, and replaying setup or reset tokens out of order. Bypass of a trivially solvable challenge or absent rate limiting is a finding; a locked-out account is an environmental blocker to record, not a bypass.

```bash
MAX_REQUESTS=5
BASE="https://HOST"
run_tool curl -sS --connect-timeout 5 --max-time 20 -c "$DIR/scans/auth-unknown.cookies" \
  -D "$DIR/scans/auth-unknown.headers" -o "$DIR/scans/auth-unknown.body" \
  -w 'status=%{http_code} body_bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  -d 'username=UNKNOWN_USER&password=WRONG_PASSWORD&captcha_response=CAPTCHA_RESPONSE' "$BASE/LOGIN"
run_tool curl -sS --connect-timeout 5 --max-time 20 -c "$DIR/scans/auth-known.cookies" \
  -D "$DIR/scans/auth-known.headers" -o "$DIR/scans/auth-known.body" \
  -w 'status=%{http_code} body_bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  -d 'username=KNOWN_TEST&password=WRONG_PASSWORD&captcha_response=CAPTCHA_RESPONSE' "$BASE/LOGIN"
run_tool curl -sS --connect-timeout 5 --max-time 20 -b "$DIR/scans/auth-known.cookies" -c "$DIR/scans/auth-known.cookies" \
  -D "$DIR/scans/auth-known-repeat.headers" -o "$DIR/scans/auth-known-repeat.body" \
  -w 'status=%{http_code} body_bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  -d 'username=KNOWN_TEST&password=WRONG_PASSWORD&captcha_response=CAPTCHA_RESPONSE' "$BASE/LOGIN"
run_tool curl -sS --connect-timeout 5 --max-time 20 -c "$DIR/scans/auth-disabled.cookies" \
  -D "$DIR/scans/auth-disabled.headers" -o "$DIR/scans/auth-disabled.body" \
  -w 'status=%{http_code} body_bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  -d 'username=DISABLED_TEST&password=WRONG_PASSWORD&captcha_response=CAPTCHA_RESPONSE' "$BASE/LOGIN"
run_tool curl -sS --connect-timeout 5 --max-time 20 -b "$DIR/scans/auth-known.cookies" -c "$DIR/scans/auth-known.cookies" \
  -D "$DIR/scans/auth-success.headers" -o "$DIR/scans/auth-success.body" \
  -w 'status=%{http_code} body_bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  -d 'username=KNOWN_TEST&password=VALID_TEST_PASSWORD&captcha_response=CAPTCHA_RESPONSE' "$BASE/LOGIN"
```

## Authorization Testing

### 1. IDOR
```
GET /api/user/1001/profile → /api/user/1002/profile    # Horizontal
GET /invoice?id=5001 → ?id=5002
# Test: sequential IDs, leaked UUIDs, Base64 decode/modify/re-encode
# param pollution: ?id=1001&id=1002, method swap: GET→PUT/DELETE
# Vertical: regular user → admin endpoints
```

### 2. Forced Browsing
```
/admin  /admin/dashboard  /console  /debug  /internal  /api/admin/users  /graphql
```
Check if 302 redirect body contains protected content (curl without -L).

### 3. HTTP Method Tampering
```
GET /admin/delete → 403, POST /admin/delete → 200
# Override headers: X-HTTP-Method-Override, X-Method-Override, X-Original-Method
```

### 4. Path Traversal for ACL Bypass
```
/admin→403  /ADMIN→200  /admin/→200  /./admin→200  /admin;.js→200
/%2fadmin→200  /admin%20→200  /admin..;/→200 (Tomcat/Spring)
```

### 5. JWT Attacks

See `jwt-testing` for the full algorithm-confusion, `kid`-injection, and `jku`/`x5u` bypass matrix — summary here for quick triage:
```bash
# Decode: echo "HEADER_B64" | base64 -d
# None algorithm: {"alg":"none"}, remove signature → HEADER.PAYLOAD.
# Weak secret: hashcat -a 0 -m 16500 jwt.txt rockyou.txt
# Payload: change role/sub/exp claims
# Key injection: kid="../../dev/null" → sign with empty secret
# jku: point to attacker JWK set URL
jwt_tool TOKEN -T                  # Tamper
jwt_tool TOKEN -C -d wordlist.txt  # Crack
```

### 6. OAuth/SSO Flaws
- Open redirect in redirect_uri (steal auth code): `redirect_uri=https://attacker.com`
- Missing state param (CSRF), token leakage via Referer, scope escalation
- `redirect_uri` validation bypass via suffix/prefix confusion: `https://victim.com.attacker.com`, `https://victim.com@attacker.com`, `https://victim.com%2f%2e%2e%2fattacker.com`, unregistered path traversal on an otherwise-exact-match host (`https://victim.com/../attacker.com`)
- Authorization-code reuse: replay a used code — should be single-use and invalidated after first exchange
- PKCE downgrade: strip `code_challenge`/`code_verifier` from a public client flow, or submit a static/predictable verifier, to check the server still enforces it
- IdP confusion in multi-tenant SSO: submit a token/assertion issued by a *different* legitimate tenant/realm of the same IdP and see if the relying party validates issuer+audience or just signature
- SAML: signature-wrapping (XML Signature Wrapping) — inject a forged assertion alongside the signed original so the parser validates the signed node but processes the forged one; also test `NameID` swap in an unsigned assertion field
- Full details and OAuth/OIDC/SAML-specific tooling: see `oauth-oidc-testing`

### 7. Role/Privilege Manipulation
```
POST /register {"username":"test","password":"test","role":"admin"}
PUT /api/profile {"name":"test","role":"admin","is_staff":true}  # Mass assignment
# Trust headers: X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin
```

## Methodology Checklist

1. Map all auth endpoints (login, register, reset, logout, MFA, OAuth)
2. Create accounts at each privilege level
3. Test each privileged action with lower/no-auth sessions
4. Swap tokens between privilege levels
5. Test every object reference with other accounts' IDs
6. Check JWT/token security
7. Test session lifecycle: fixation, expiration, invalidation
