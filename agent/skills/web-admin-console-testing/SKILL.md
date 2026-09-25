---
name: web-admin-console-testing
description: Enumerate and safely test exposed management, monitoring, and admin consoles for default credentials and disclosure
origin: RedteamOpencode
---

# Web Admin & Monitoring Console Testing

## When to Activate

- A management or monitoring console is reachable: Tomcat manager, phpMyAdmin, Druid, Grafana, Kibana, an admin panel, or an API-documentation interface
- The task is to test default/weak credentials or console-specific unauthenticated disclosure
- A recon or port-scan result flags a console path, banner, or service signature

## Tools

`run_tool nmap`, `run_tool curl`, `run_tool nuclei`, `run_tool nikto`, `run_tool whatweb`, `run_tool hydra`, `jq`, `python3`, `awk`, `sed`, `grep`

## Methodology

### 1. Discover and Fingerprint Consoles

Probe the known management ports and a short list of well-known console paths. Capture server banner, title, and framework clues; do not turn this into a full directory or port sweep.

```bash
run_tool nmap -Pn -sV -p 8080,8443,8888,3000,5601,9090 --host-timeout 30s --max-retries 1 HOST > "$DIR/scans/console_ports.txt" 2>&1
run_tool whatweb -a 3 --no-errors --max-redirects 2 https://HOST > "$DIR/scans/console_fingerprint.txt" 2>&1
run_tool curl -sS -k -D "$DIR/scans/console_headers.txt" --connect-timeout 5 --max-time 20 https://HOST/ -o "$DIR/scans/console_index.html"
grep -Eio '<title>[^<]*|^server:[[:space:]]*[^[:space:]]+' "$DIR/scans/console_index.html" "$DIR/scans/console_headers.txt" > "$DIR/scans/console_clues.txt" 2>/dev/null
```

Record which product and version answered; a generic 404 is not a console.

### 2. Identify Console Type and Version

Map the banner, title, and login page to a product and version. Use one versioned probe per concrete path; do not probe guessed paths past the budget.

```bash
for path in /manager /phpmyadmin /druid /grafana /app/kibana /admin /jenkins /login /api/overview /elasticsearch /_cat/indices /portainer /api/status /airflow/health /consul/ui /rabbitmq; do
  run_tool curl -sS -k -o /dev/null -w "$path %{http_code} %{redirect_url}\n" --connect-timeout 5 --max-time 20 "https://HOST${path}"
done > "$DIR/scans/console_paths.txt"
```

Common product-to-path map for identification (do not probe beyond the budgeted list above): Jenkins (`/login`, `/script`, `/api/json`), Elasticsearch/Kibana dev tools (`/_cat/indices`, `/app/kibana#/dev_tools`), RabbitMQ management (`/api/overview` on 15672), Consul UI/API (`/v1/agent/self`), Portainer (`/api/status`), Apache Airflow (`/health`, unauthenticated DAG list on older versions), pgAdmin (`/browser/`).

A 200 or a 302 to a login/redirect identifies a live console; a 401/403 still names the product.

### 3. Test Default and Weak Credentials

Use only a small static list of common defaults (`admin/admin`, `admin/admin123`, `root/root`, `admin/password`, `guest/guest`). This is a static check, not a spray; never use a wordlist or brute force.

```bash
printf '%s\n' 'admin/admin' 'admin/admin123' 'root/root' 'admin/password' 'guest/guest' > "$DIR/scans/console_defaults.txt"
while IFS=/ read -r user pass; do
  run_tool curl -sS -k -c "$DIR/scans/console_session.cookie" -b "$DIR/scans/console_session.cookie" \
    --connect-timeout 5 --max-time 20 \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "username=${user}&password=${pass}" \
    -o "$DIR/scans/console_login_${user}.txt" -D "$DIR/scans/console_login_${user}.headers" "https://HOST/login"
done < "$DIR/scans/console_defaults.txt"
```

Record status, redirect, cookie, and response only. A successful login is evidence of a default credential, not license to enumerate the whole console.

### 4. Test Console-Specific Unauthenticated Disclosure

For each identified console, send one bounded request to its known disclosure surface: monitor/status JSON, datasource or config dump, query/URI viewer, or debug endpoint. Cap downloads and redact values.

```bash
run_tool curl -sS -k --connect-timeout 5 --max-time 20 "https://HOST/druid/index.html" -o "$DIR/scans/console_druid.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 "https://HOST/manager/status" -o "$DIR/scans/console_manager_status.txt"
run_tool curl -sS -k --connect-timeout 5 --max-time 20 "https://HOST/api/health" -o "$DIR/scans/console_health.json"
run_tool curl -sS -k -r 0-2047 --max-filesize 65536 --connect-timeout 5 --max-time 20 "https://HOST/api-docs" -o "$DIR/scans/console_api_docs.json"
jq -r 'paths(scalars) as $p | select(($p[-1] | tostring | ascii_downcase | test("pass|key|token|secret|credential|user|host"))) | $p | join(".")' "$DIR/scans/console_health.json" > "$DIR/scans/console_sensitive_fields.txt" 2>/dev/null || true
```

Report a disclosure only when the bounded response actually returns sensitive data or a state change; a method-not-found or empty body is not a finding.

### 5. Test Function/Object-Level Authorization

When a low-privilege session exists, call one admin-only read and one state-changing method to check whether the console enforces function-level authorization. Never invent a token; never submit destructive writes.

```bash
run_tool curl -sS -k -b "$DIR/scans/console_session.cookie" --connect-timeout 5 --max-time 20 "https://HOST/api/admin/users" -D "$DIR/scans/console_fauth_users.headers" -o "$DIR/scans/console_fauth_users.json"
run_tool curl -sS -k -b "$DIR/scans/console_session.cookie" --connect-timeout 5 --max-time 20 -H 'Content-Type: application/json' --data '{"action":"status"}' "https://HOST/api/admin/action" -D "$DIR/scans/console_fauth_action.headers" -o "$DIR/scans/console_fauth_action.json"
```

Treat a successful admin response to a low-privilege session as a broken-function-authorization finding; a 403/405 is expected behavior.

### 6. Check JMX/RMI and Java-Management Consoles

Java application servers sometimes expose JMX/RMI registries or unauthenticated `/manager` endpoints separately from the HTTP console. Probe the registry port and, for Tomcat, the deployer endpoint; do not attempt a deserialization payload here.

```bash
run_tool nmap -Pn -sV -p 1099,9010,9990 --host-timeout 30s --max-retries 1 HOST > "$DIR/scans/console_jmx_ports.txt" 2>&1
run_tool curl -sS -k --connect-timeout 5 --max-time 20 "https://HOST/manager/text/list" -o "$DIR/scans/console_tomcat_manager_text.txt"
```

An open JMX/RMI port with no authentication banner, or a `/manager/text/list` response without credentials, is a version/exposure finding on its own — record it and hand deserialization or WAR-deployment chains to exploit-developer.

### 7. Map Known CVEs and Confirm Once

Map the product and version to a local CVE list, then run the matching NSE/`nuclei` template set once. Select one matched non-destructive check and retain its response; do not execute an exploit.

```bash
run_tool searchsploit "$PRODUCT" "$VERSION" | sed -n '1,80p' > "$DIR/scans/console_cve_matches.txt"
run_tool nuclei -u "https://HOST" -t exposed-panels -t default-logins -t tech-detect > "$DIR/scans/console_nuclei.txt" 2>&1
```

Report a CVE only when the single check reproduces the affected behavior; otherwise record it as an unconfirmed version match.

### 8. Extend the Product-to-Fingerprint Map

Beyond the path list in step 2, correlate title/banner/header clues against a wider product set so a matched console gets a precise version-to-CVE lookup in step 7 instead of a generic label.

| Product | Fingerprint clue | Default console path |
|---|---|---|
| Apache Tomcat Manager | `Server: Apache-Coyote`, realm prompt on `/manager/html` | `/manager/html`, `/manager/text` |
| phpMyAdmin | `<title>phpMyAdmin</title>`, `pma_username` cookie | `/phpmyadmin`, `/pma` |
| Apache Druid | `<title>Apache Druid</title>`, `/status/health` 200 | `/unified-console.html` |
| Grafana | `X-Grafana-*` headers, `/api/health` JSON with `version` | `/login`, `/api/health` |
| Kibana | `kbn-version` header, `/app/kibana` redirect | `/app/kibana`, `/api/status` |
| Jenkins | `X-Jenkins` header, `/login` form with `j_username` | `/login`, `/script`, `/api/json` |
| RabbitMQ Management | `Server: RabbitMQ` on 15672, `/api/overview` JSON | `/api/overview` |
| Portainer | `<title>Portainer</title>`, `/api/status` JSON | `/api/status` |
| Consul | `X-Consul-*` headers, `/v1/agent/self` JSON | `/v1/agent/self`, `/ui` |
| Apache Airflow | `<title>Airflow</title>`, `/health` JSON with `metadatabase` | `/health`, `/login` |
| pgAdmin | `<title>pgAdmin 4</title>` | `/browser/` |
| Nexus Repository | `Server: Nexus`, `/service/rest/v1/status` | `/service/rest/v1/status`, `/nexus` |
| Weblogic Console | `<title>WebLogic Server Administration Console</title>` | `/console/login/LoginForm.jsp` |
| JBoss/WildFly Admin | `<title>JBoss</title>` or `/management` 401 realm | `/management`, `/console` |
| Splunk Web | `<title>Splunk</title>`, `Server: Splunkd` | `/en-US/account/login` |

Record only the matched fingerprint clue and path status; do not probe products outside the step 2 budget just because they appear in this table.

### 9. Apply Reporting Discipline

A finding requires a reproducible request/response pair, the named console and version, and a concrete impact (default credential, unauthenticated disclosure, or broken function authorization). Enumeration alone is not a finding.

```bash
printf '%s\n' \
  'console: name and version' \
  'evidence: request plus saved response headers and body' \
  'impact: default credential | unauthenticated disclosure | broken function authorization' \
  > "$DIR/scans/console_reporting_record.txt"
```

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/api-security/API05-broken-function-authz.md`, `references/api-security/API08-security-misconfiguration.md`, `references/tools/recon/nuclei.md`, `references/tools/recon/nikto.md`, `references/tools/recon/whatweb.md`.

## Confirm-Only Rule

Discovery, fingerprinting, default-credential checks, and disclosure probes are confirm-stage. Promote only a reproducible finding with a named console, version, and demonstrated impact; otherwise record an observation and stop at the bound. Full console exploitation belongs to exploit-developer.

## Budget

At most 40 target requests per console and 10 minutes wall-clock; 5 default-credential pairs, no wordlists, no brute force, no destructive writes.
