---
name: mfa-bypass-testing
description: Test MFA challenge enforcement, OTP lifecycle, session binding, recovery paths, and alternate authentication routes
origin: RedteamOpencode
---

# MFA Bypass Testing

## When to Activate

- Login, admin actions, password changes, or sensitive exports require a second factor
- OTP, backup codes, remembered devices, recovery, mobile APIs, or legacy login paths exist
- A full bypass reaches a protected resource or privileged action without a fresh second factor

## Tools

`run_tool curl`; host `python3`.

## Methodology

### 1. Establish the Pre-MFA Baseline

Use a dedicated lab account and fresh pre-MFA session. Inventory every login surface, challenge endpoint, post-MFA route, step-up trigger, recovery path, and session cookie from source and engagement auth context.

Request one protected API or data route with only the pre-MFA cookie. Do not count a static SPA shell as authenticated content; verify a protected field, status transition, or privileged action.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/mfa-direct-headers.txt" -o "$DIR/scans/mfa-direct-body.txt" -H "Cookie: session=$PRE_MFA_SESSION" "https://HOST/PROTECTED_ROUTE"
```

Repeat at most once for a second concrete protected route. A redirect to the normal challenge is expected; `200` with protected data is the signal.

### 2. Test OTP Replay

Use one issued OTP within its advertised validity window. Submit it once through the normal endpoint, then replay the same value once after successful validation.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/mfa-otp-first.json" -H 'Content-Type: application/x-www-form-urlencoded' -d "otp=$OTP&session=$MFA_SESSION" "https://HOST/MFA_VERIFY"
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/mfa-otp-replay.json" -H 'Content-Type: application/x-www-form-urlencoded' -d "otp=$OTP&session=$MFA_SESSION" "https://HOST/MFA_VERIFY"
```

Require single use, atomic consumption, and immediate invalidation. Also check reuse from the same or a different session.

### 3. Test Backup, Reset, and Recovery Codes

Use one generated recovery or backup code twice, then test whether it survives password reset or account recovery. Check that reset tokens are hashed, purpose-bound, audience-bound, short-lived, and single-use.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/mfa-recovery-replay.json" -H 'Content-Type: application/x-www-form-urlencoded' -d "recovery_code=$RECOVERY_CODE&session=$RECOVERY_SESSION" "https://HOST/RECOVERY_VERIFY"
```

Enumerate alternate account-recovery actions, not real telecom takeover. Verify that email, security questions, support actions, and reset completion cannot silently restore an old trusted device or bypass a new factor.

### 4. Test Rate Limiting and Lockout

Send no more than two invalid codes on a lab account. Compare status, body, headers, delay, remaining attempts, and whether a valid code still works afterward.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/mfa-rate-headers.txt" -o "$DIR/scans/mfa-rate-body.txt" -H 'Content-Type: application/x-www-form-urlencoded' -d "otp=000000&session=$RATE_TEST_SESSION" "https://HOST/MFA_VERIFY"
```

Do not brute-force a full code space. Hand off more than two invalid probes or any account-wide lockout impact to `exploit-developer`.

### 5. Test Remembered-Device and Session Binding

Compare pre-MFA, post-MFA, remembered-device, logout, password-change, and fresh-browser sessions. Check token rotation, `Secure`, `HttpOnly`, `SameSite`, scope, expiry, server-side revocation, and binding to user, device, and authentication strength.

Copy and replay an engagement-issued remembered-device cookie as a controlled theft simulation before MFA or after logout. Require reauthentication for new sessions, step-up actions, privilege changes, and token elevation; do not steal cookies outside engagement traffic.

### 6. Locate OTP Disclosure

Inspect response bodies, `Location` headers, browser history, JavaScript source, application logs supplied with the lab, analytics calls, and error telemetry. Treat an OTP in a URL, reusable response field, log, or client-readable pre-auth error as sensitive leakage.

```bash
python3 -c 'from pathlib import Path; p=Path("$DIR/scans/mfa-otp-first.json"); print(p.read_text() if p.exists() else "no saved response")'
```

Verify codes are masked, short-lived, and removed after display. Never expose a live code in findings or handoff text.

### 7. Test TOTP Windows and Clock Skew

With an engagement test secret, evaluate only the current, previous, and next 30-second TOTP step. Determine whether the server accepts a stale code, allows an excessive step window, ignores replay counters, or binds codes to the authenticated account and session.

Do not brute-force TOTP secrets. Escalate excessive acceptance or secret disclosure after these bounded probes.

### 8. Test Concurrent OTP Consumption

Send exactly two identical verification requests concurrently. Confirm the server consumes one code atomically and grants at most one successful transition.

```bash
run_tool curl --parallel --parallel-immediate --parallel-max 2 -sS --connect-timeout 5 --max-time 20 -o "$DIR/scans/mfa-race-1.json" -o "$DIR/scans/mfa-race-2.json" -H 'Content-Type: application/x-www-form-urlencoded' -d "otp=$OTP&session=$RACE_SESSION" "https://HOST/MFA_VERIFY" "https://HOST/MFA_VERIFY"
```

Inspect both bodies and final account/session state. Hand deeper multi-endpoint races to `exploit-developer`.

### 9. Test Alternate Authentication Paths

Test at most two alternate paths: one mobile/API login and one GraphQL mutation or legacy endpoint. Compare whether each enforces the same challenge, OTP, step-up, and session binding.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/mfa-alternate-headers.txt" -o "$DIR/scans/mfa-alternate-body.json" -H 'Content-Type: application/json' -d '{"username":"USER","password":"PASSWORD"}' "https://HOST/ALTERNATE_AUTH_PATH"
```

Search discovered routes for impersonation, support, debug, or backdoor endpoints and report them only after confirming they are in scope. Do not create hidden backdoors.

### 10. Assess SMS and Email MFA in the Lab

Check code length, entropy, expiry, attempt limits, delivery identifiers, user enumeration, session/account binding, and disclosure through lab delivery interfaces or artifacts. SIM-swap activity is out of scope; test account-recovery-flow abuse instead.

Treat full access to a protected account or privileged action without completing MFA as **CRITICAL**. Lower severity only when a control weakness exposes partial metadata or requires the legitimate user's active second factor.

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/api-security/API02-broken-authentication.md`, `references/api-security/API05-broken-function-authz.md`, `references/tools/recon/curl.md`.
