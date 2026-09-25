---
name: jwt-testing
description: JWT token attack techniques — alg bypass, key confusion, claim tampering
origin: RedteamOpencode
---

# JWT Testing (JSON Web Token Attacks)

## When to Activate

- Application uses JWT for authentication or authorization
- Tokens visible in cookies, Authorization header, or URL params
- Token structure: `xxxxx.yyyyy.zzzzz` (three base64url segments)

## Tools

- jwt_tool (comprehensive JWT testing)
- jwt.io (decode and inspect)
- hashcat (`-m 16500` for JWT cracking)
- john (jwt2john + wordlist)
- Custom scripts for key confusion

## Methodology

### 1. Decode and Analyze

- [ ] Split token: header.payload.signature
- [ ] Base64url-decode header → check `alg`, `typ`, `kid`, `jku`, `jwk`
- [ ] Base64url-decode payload → check `sub`, `role`, `admin`, `exp`, `iat`, `iss`
- [ ] Note expiration time — is it enforced?
- [ ] Collect multiple tokens — compare structure, observe changing fields

### 2. Algorithm None Attack

- [ ] Set header `"alg": "none"` — remove signature
- [ ] Variations: `"alg": "None"`, `"alg": "NONE"`, `"alg": "nOnE"`
- [ ] Empty signature: `header.payload.`
- [ ] Test if server accepts unsigned token

### 3. Weak Secret (HMAC)

- [ ] If `alg: HS256`, brute-force secret:
      `hashcat -m 16500 jwt.txt rockyou.txt`
- [ ] Common secrets: `secret`, `password`, application name, blank string
- [ ] jwt_tool: `python3 jwt_tool.py TOKEN -C -d wordlist.txt`
- [ ] Once secret found, forge arbitrary tokens

### 4. Key Confusion (RS256 → HS256)

- [ ] Obtain public key (JWKS endpoint, TLS cert, `/.well-known/jwks.json`)
- [ ] Change `alg` from `RS256` to `HS256`
- [ ] Sign token with public key as HMAC secret
- [ ] Server may verify HMAC using the public key it already has

### 5. Claim Tampering

- [ ] Change `sub` to another user ID
- [ ] Change `role` from `user` to `admin`
- [ ] Set `admin: true` or `is_admin: 1`
- [ ] Extend `exp` far into the future
- [ ] Change `iss` to see if validated
- [ ] Add unexpected claims the server may process

### 6. Header Injection Attacks

- [ ] `kid` injection: `"kid": "../../dev/null"` (empty key → trivial signature)
- [ ] `kid` SQL injection: `"kid": "key' UNION SELECT 'secret'--"`
- [ ] `jku` spoofing: point to attacker-controlled JWKS
- [ ] `jwk` embedding: include attacker's key in header
- [ ] `x5u` / `x5c`: point to attacker certificate

### 7. Token Lifecycle

- [ ] Use expired token — is expiration enforced?
- [ ] Replay token after logout — is it invalidated?
- [ ] Use token after password change
- [ ] Test token refresh mechanism for flaws
- [ ] Check if tokens are stored and revocable server-side

### 8. Cross-Service Attacks

- [ ] Use token from service A on service B (shared key?)
- [ ] Check audience (`aud`) claim validation
- [ ] Test tokens across environments (staging key on production)

### 9. Algorithm-Confusion Variants Beyond RS256→HS256

- [ ] `PS256`/`ES256` → `HS256`: same confusion attack applies to any asymmetric algorithm if the public key material is derivable and the verifier doesn't pin the expected algorithm family
- [ ] `ES256` curve-confusion: some libraries accept a malformed/degenerate ECDSA signature (`r=0` or `s=0`) as valid — test with an all-zero signature
- [ ] Algorithm downgrade within family: force `RS512`→`RS256` if the verifier accepts any `RS*` and a weaker variant has known library bugs
- [ ] Check if the server's JWT library has a known CVE for the detected `alg`/library combo (grep `intel.md` for the framework/library version and cross-reference)

### 10. `kid` Path and SSRF Variants

- [ ] `kid` path traversal to a predictable local file with known/empty content: `/dev/null`, `/proc/sys/kernel/randomize_va_space` (constant value), a static app asset
- [ ] `kid` pointing at a log file the attacker can poison first (log injection → forge the HMAC key by writing a known string into the log, then sign with it)
- [ ] `jku`/`x5u` SSRF: even if the app validates the JWKS response's key ID rather than blindly trusting it, the fetch itself may be an SSRF primitive against internal hosts — chain into `ssrf-testing`
- [ ] `jku` domain-allowlist bypass: subdomain confusion (`jwks.attacker-controlled-cdn.trusted-domain.com` if the allowlist is a suffix match), open redirect on the trusted domain that 302s to attacker JWKS

### 11. Signature-Stripping and Parser Differentials

- [ ] Duplicate `alg` header keys — some parsers use the first occurrence for validation logic but the last for actual algorithm selection (or vice versa): `{"alg":"HS256","typ":"JWT","alg":"none"}`
- [ ] Whitespace/casing/encoding variance in the header JSON before base64url — different JSON parsers may tolerate what the signature-verification code was tested against, causing a parser differential
- [ ] Truncate the signature segment progressively (`header.payload.AAA` → `header.payload.A`) to check if any prefix-matching or leniency exists
- [ ] Swap final `.` handling: some frameworks split on `.` naively — try appending trailing garbage after a valid signature (`header.payload.sig.extra`) to see if it's ignored rather than rejected

## What to Record

- Token algorithm and claims structure
- Attack type that succeeded (none, weak key, confusion, injection)
- Forged token and the access it granted
- Secret recovered (if HMAC brute-force)
- Severity: Critical (forge any user/admin token) or High (privilege escalation)
- Remediation: strong secrets, enforce algorithm allowlist, validate all claims
