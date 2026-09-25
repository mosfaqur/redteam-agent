---
name: oauth-oidc-testing
description: Test OAuth 2.0, OIDC, and SAML flows for redirect, token, signature, replay, and tenant-binding flaws
origin: RedteamOpencode
---

# OAuth, OIDC, and SAML Testing

## When to Activate

- A login, SSO, social-login, or tenant-selection flow uses OAuth 2.0, OpenID Connect, or SAML
- Authorization responses expose codes, fragments, assertions, or provider metadata
- Existing engagement auth context can exercise a normal login and one alternate identity

## Tools

`run_tool curl`, `run_tool jwt_tool`; host `jq`, `openssl`, `python3`.

## Methodology

### 1. Discover and Map the Trust Boundaries

Use only the engagement's existing auth context. Follow links and configuration to identify the issuer, authorization and token endpoints, client, registered callbacks, response types, grant types, scopes, and supported signing methods.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/oidc-discovery-headers.txt" -o "$DIR/scans/openid-configuration.json" "https://HOST/.well-known/openid-configuration"
jq -r '[.issuer, .authorization_endpoint, .token_endpoint, .jwks_uri, .registration_endpoint] | .[] | select(. != null)' "$DIR/scans/openid-configuration.json"
```

For issuer-specific paths, repeat discovery only at the issuer URL exposed by the application. Record all participating client, IdP, and relying-party origins.

### 2. Test State and PKCE

Use two isolated state probes: omit `state` once, then reuse a known fixed value across a fresh session. Issue one separate request without `code_challenge`; do not combine failures.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/oauth-no-pkce.txt" -o /dev/null "https://HOST/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2FHOST%2FCALLBACK&scope=openid%20profile&state=FIXED_STATE" # Missing PKCE
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/oauth-no-state.txt" -o /dev/null "https://HOST/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2FHOST%2FCALLBACK&scope=openid%20profile&code_challenge=CHALLENGE&code_challenge_method=S256" # Missing state
```

Require unpredictable, session-bound, single-use `state` and PKCE S256 for public clients. Check whether the callback rejects mismatched or reused values.

### 3. Test Redirect URI Matching

Compare the registered callback with one engagement-controlled lookalike or suffix-confusion candidate. Do not deliver a code to an unapproved host.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/oauth-redirect-match.txt" -o /dev/null "https://HOST/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2FALT_CALLBACK_HOST%2FCALLBACK&state=FIXED_STATE&code_challenge=CHALLENGE&code_challenge_method=S256"
```

Require exact scheme, host, port, and path matching. Reject encoded delimiters, user-info tricks, path prefixes, fragments, query-only additions, and open-redirect sinks.

### 4. Test Code Replay and Implicit Tokens

Redeem an engagement authorization code once, then replay the same code exactly once. Save both token responses and compare error handling.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/token-first.json" -d 'grant_type=authorization_code' -d 'code=AUTH_CODE' -d 'client_id=CLIENT_ID' -d 'redirect_uri=https://HOST/CALLBACK' "https://HOST/oauth/token"
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/token-replay.json" -d 'grant_type=authorization_code' -d 'code=AUTH_CODE' -d 'client_id=CLIENT_ID' -d 'redirect_uri=https://HOST/CALLBACK' "https://HOST/oauth/token"
```

Inspect the implicit flow once without following redirects. Fragments are not normally sent in `Referer`; verify the fragment token is not copied into query strings, logs, analytics, error reports, or unsafe client storage.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/oauth-implicit-headers.txt" -o /dev/null "https://HOST/oauth/authorize?response_type=token&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2FHOST%2FCALLBACK&scope=openid%20profile" # Token in fragment
```

### 5. Evaluate Scopes and Refresh Tokens

Request one broader scope set and compare granted access, ID-token claims, and API behavior against the minimal requested set. Flag unapproved groups, roles, or administrative scopes.

Test one refresh-token replay after rotation. Check binding to client and user, expiration, revocation after logout/password change, replay detection, and exclusion from URLs, logs, local storage, and analytics.

### 6. Inspect and Tamper with ID Tokens

Extract tokens and decode the first two JWT segments locally.

```bash
jq '{token_type, expires_in, scope, access_token, refresh_token, id_token}' "$DIR/scans/token-first.json"
python3 -c 'import base64,json,sys; t=sys.argv[1].split("."); [print(json.dumps(json.loads(base64.urlsafe_b64decode(x+"="*(-len(x)%4))),indent=2)) for x in t[:2]]' "$(jq -r '.id_token' "$DIR/scans/token-first.json")"
```

Use at most two modified tokens: one `alg:none` test, then HS-versus-RS confusion only if needed; otherwise use one signed claim test. Vary `role` or `sub` one claim at a time, and assess `email` through the account-linking test below. Reject unsigned, wrong-key, and altered identity or privilege claims.

### 7. Test OIDC-Specific Controls

Send one authorization request with `nonce`, then exercise the callback with a missing or mismatched value. Require nonce-to-session binding and replay rejection.

Fetch `jwks_uri` with `run_tool curl`; pin expected `kty`, `alg`, `use`, and `kid`. Test one embedded `jwk` or `jku` key-substitution case only if the token header permits it.

If dynamic client registration is enabled, create one temporary lab client with an exact engagement callback and minimal scope. Check unauthenticated registration, redirect restrictions, secret issuance, code-to-client binding, and deletion afterward.

### 8. Test Account Linking and Tenant Binding

Use two modified ID tokens at most: alter `iss` once and `aud` once. Also compare the same email across distinct `iss`, `sub`, tenant, or client contexts.

Require exact issuer, audience, authorized party, subject, tenant, client, and redirect-URI binding. Treat unexpected account linking or cross-tenant acceptance as tenant mixup, not successful authentication by itself.

### 9. Capture and Test SAML Assertions

Capture one SP-initiated AuthnRequest and one valid IdP-initiated response. Decode the response and inspect signatures, `Destination`, `Audience`, `InResponseTo`, `NameID`, `NotBefore`, and `NotOnOrAfter`.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/saml-sp-headers.txt" -o /dev/null "https://HOST/saml/login?RETURN_TO=/"
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/saml-idp-response.html" -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data 'SAMLResponse=ASSERTION' "https://HOST/saml/sso"
openssl base64 -d -A <<< "$SAML_RESPONSE" | python3 -c 'import sys,xml.etree.ElementTree as E; print(E.fromstring(sys.stdin.read()).tag)'
```

Replay one signed assertion once. Then submit one signature-wrapping variant and one unsigned-assertion variant; the service must bind the validated signed assertion to the expected subject, audience, and request.

Test one safe `RelayState` lookalike for open redirect. Test IdP-initiated SSO once for missing-request, tenant, consent, or step-up bypass.

### 10. Mix-Up and Multi-IdP Confusion

When the relying party supports more than one authorization server (multiple social-login providers, or a dev/staging IdP left reachable alongside production), test whether a response from IdP-B is accepted on a callback that expects IdP-A. Compare `iss` validation against the endpoint the flow was actually initiated with, not just signature validity. This is the OAuth "mix-up attack": an attacker who controls one registered IdP can potentially inject a code/token meant to look like it came from the trusted one if the client doesn't bind the response to the specific authorization server it started with.

### 11. Device Authorization Grant (Device Code Flow) Abuse

If the target exposes a device flow (`device_authorization_endpoint` in discovery, or a "enter this code on another device" UI):
- Check the user-code space size and rate limiting — short numeric codes with no throttling are brute-forceable to hijack a pending device session
- Check the polling interval enforcement server-side vs. client-declared — a client ignoring `interval`/`slow_down` may reveal a race window
- Test whether the verification URI requires re-authentication or just an authenticated session with no explicit user consent screen naming the requesting device

### 12. Response Type / Response Mode Manipulation

- [ ] Request an unregistered or hybrid `response_type` (`code token`, `code id_token`, `code id_token token`) to see if the server issues tokens via a less-audited code path
- [ ] Force `response_mode=query` on a flow that expects `fragment` (or vice versa) — moving the token/code into the query string changes what gets logged (server access logs, `Referer` headers) versus what a fragment would have kept client-side only
- [ ] `response_mode=form_post` CSRF: verify the POST target validates state/origin, since form_post responses aren't subject to normal cross-origin fragment protections

### 13. Client Authentication Downgrade

- [ ] If the client is registered as `confidential` (has a `client_secret`), test whether the token endpoint still accepts the request as a `public` client (no secret, or `token_endpoint_auth_method=none`) — a downgrade that removes the client-authentication factor entirely
- [ ] Client secret in a public/mobile/SPA context: check bundled app/JS source for a hardcoded `client_secret` treated as if it were confidential

### 14. RP-Initiated Logout and Session Termination Gaps

- [ ] Trigger `end_session_endpoint` (RP-initiated logout) and confirm the IdP session, all linked RP sessions (single logout), and any long-lived refresh tokens are actually revoked — not just the local cookie cleared
- [ ] Test `post_logout_redirect_uri` validation with the same rigor as `redirect_uri` (Section 3) — it is a common under-validated sibling parameter
- [ ] Confirm a captured access/refresh token issued before logout is rejected afterward, not just no-longer-renewable

## References

`references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/vuln-checklists/A08-integrity-failures.md`, `references/api-security/API02-broken-authentication.md`, `references/payloads/jwt-payloads.md`, `references/tools/recon/curl.md`.
