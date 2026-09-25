---
name: race-condition-testing
description: Race condition and TOCTOU exploitation — parallel request attacks
origin: RedteamOpencode
---

# Race Condition / TOCTOU Testing

## When to Activate

- Application has single-use actions (coupons, vouchers, invites)
- Financial operations (transfers, purchases, withdrawals)
- Voting, rating, or counting mechanisms
- Inventory or stock management
- Any operation that should execute exactly once

## Tools

- Burp Suite Turbo Intruder
- `run_tool curl --parallel` (HTTP/2 multiplexing)
- Custom Python scripts (asyncio + aiohttp)
- Burp Repeater (send group in parallel)
- GNU parallel

For current-engagement target requests, use plain `run_tool curl` by default and let
`rtcurl` load `auth.json` automatically. Only add explicit `Cookie:` or
`Authorization:` headers when intentionally testing alternate-user races or session
override behavior.

## Methodology

### 1. Identify Race Condition Targets

- [ ] Coupon/promo code redemption
- [ ] Money transfer / payment
- [ ] Gift card activation
- [ ] Vote or like functionality
- [ ] Account creation with unique constraints (email, username)
- [ ] File operations (read-then-write sequences)
- [ ] Inventory purchase (limited stock)
- [ ] Token/OTP validation

### 2. Single-Packet Attack (HTTP/2)

- [ ] Prepare N identical requests
- [ ] Send all in a single TCP packet using HTTP/2 multiplexing:
      ```bash
      run_tool curl --parallel --parallel-max 50 \
        -X POST https://target/redeem-coupon \
        -d "code=DISCOUNT50" \
        # Add explicit Cookie/Auth only when testing a second session or override path
        --url "https://target/redeem-coupon" \
        --url "https://target/redeem-coupon" \
        [repeat N times]
      ```
- [ ] All requests arrive at server simultaneously

### 3. Turbo Intruder Script

- [ ] Use `race-single-packet-attack.py` in Turbo Intruder
- [ ] Configure: capture request, set N copies, send simultaneously
- [ ] Analyze responses: count successes vs expected single success
- [ ] Gate technique: send requests with incomplete body, release all at once

### 4. Limit Overrun Testing

- [ ] Send 20-50 identical requests in parallel
- [ ] Check if action executed more than once
- [ ] Example: redeem coupon 50 times → check if discount applied multiple times
- [ ] Transfer money: send same transfer 20 times → check total deducted vs transferred
- [ ] Vote: send 50 votes → check if count increased by >1

### 5. TOCTOU (Time-of-Check to Time-of-Use)

- [ ] Identify check-then-act sequences:
      1. Server checks balance ≥ amount
      2. Server deducts amount
- [ ] Race between check and deduction = double-spend
- [ ] File access: race between permission check and file read
- [ ] Token validation: race between check and invalidation

### 6. Multi-Endpoint Races

- [ ] Race between different endpoints:
      - Endpoint A: redeem coupon
      - Endpoint B: check coupon status
- [ ] Race between update and read operations
- [ ] Race state changes: apply coupon + checkout simultaneously
- [ ] Session race: change email + password reset at same time

### 7. Partial Construction Race

- [ ] Register user → immediately login before email verification
- [ ] Create object → access before initialization completes
- [ ] Upload file → access before antivirus scan

### 7b. Connection Warming & Last-Byte Synchronization

Network jitter (not server-side locking) is the most common reason a race "doesn't reproduce." Tighten the send window before concluding a target isn't vulnerable:
- [ ] Pre-warm connections: open and idle each TCP/TLS connection to the target before firing (avoids TLS handshake jitter skewing arrival order)
- [ ] Last-byte sync: on HTTP/1.1, send all but the final byte of each request first, then release the final byte for every connection in one tight loop — collapses arrival variance to sub-millisecond
- [ ] Prefer a single HTTP/2 connection with multiplexed streams over N separate HTTP/1.1 connections when the target supports h2 — removes per-connection handshake variance entirely
- [ ] If remote latency is high and jitter dominates, run the race from a host on the same network segment/region as the target, or via a request generator co-located with it, rather than accepting a low hit rate as "not vulnerable"

### 7c. Sub-Endpoint / Workflow-Step Races

- [ ] Multi-step checkout/workflow: race the *last* step (e.g. "confirm order") against a concurrent request to a step that mutates the same state (e.g. "apply coupon" or "change shipping address") — inconsistent step ordering can double-apply a discount or skip a validation step entirely
- [ ] Password/email-change confirmation race: request two different email-change confirmations in parallel with two different target addresses — check whether both succeed or the account ends up in an inconsistent state (verified for neither, or attacker's address wins silently)
- [ ] Rate-limit/lockout race: fire parallel failed-login attempts to see if the lockout counter itself has a TOCTOU window that lets one extra attempt slip through after the "official" limit, useful when chained with `credential-attacks`
- [ ] Idempotency-key race: if the API supports idempotency keys, test whether reusing vs. omitting the key under parallel load still enforces single execution — a common gap is enforcing idempotency only after the first request's transaction commits, not from receipt

### 8. Detection Indicators

- [ ] Multiple 200 responses where only one expected
- [ ] Database constraint violations in some responses (duplicate key)
- [ ] Balance or counter inconsistencies after test
- [ ] Some requests succeed, others get 409/500 → partial protection

### 9. Cleanup

- [ ] Verify actual impact: check database state, balances, counts
- [ ] Document exact number of successful duplicate actions
- [ ] Revert test data if possible

## What to Record

- Endpoint and action with race condition
- Number of parallel requests sent
- Number of successful duplicate executions
- Technique used (single-packet, Turbo Intruder, run_tool curl --parallel)
- Business impact (financial loss, integrity violation, privilege escalation)
- Timing window observed
- Severity: High (financial) to Medium (logic bypass)
- Remediation: database locks, idempotency keys, atomic operations, mutex
