---
name: info-disclosure-testing
description: Information disclosure detection — error messages, files, headers, debug endpoints
origin: RedteamOpencode
---

# Information Disclosure Testing

## When to Activate

- Reconnaissance phase of any engagement
- Verbose error messages observed
- Debug features suspected in production
- Sensitive data exposure assessment

## Tools

- `run_tool curl` (header inspection, file probing)
- Burp Suite (passive scanning, response analysis)
- `run_tool gobuster` / `run_tool ffuf` (file and directory brute-force)
- GitTools (extract .git repositories)
- trufflehog / gitleaks (secret scanning)

## Methodology

### 1. HTTP Header Analysis

- [ ] Check `Server` header — reveals web server and version
- [ ] Check `X-Powered-By` — reveals framework (PHP, ASP.NET, Express)
- [ ] Check `X-Debug-Token` / `X-Debug-Token-Link` — Symfony profiler
- [ ] Check `X-AspNet-Version`, `X-AspNetMvc-Version`
- [ ] Check `X-Request-Id` — internal request tracking
- [ ] Look for custom headers leaking internal hostnames or IPs
- [ ] Send OPTIONS request — check allowed methods

### 2. Error Message Analysis

- [ ] Trigger errors: invalid input, SQL syntax, type mismatch
- [ ] Look for stack traces with file paths, line numbers
- [ ] SQL error messages revealing query structure and DB type
- [ ] Framework debug pages: Django debug, Laravel Ignition, Spring Whitelabel
- [ ] PHP errors: `Warning:`, `Fatal error:`, `Notice:`
- [ ] Detailed 404/500 pages vs generic error pages

### 3. Sensitive File Discovery

- [ ] `/.git/` → `/.git/HEAD`, `/.git/config` (source code recovery)
- [ ] `/.env` — environment variables, database credentials, API keys
- [ ] `/.DS_Store` — macOS directory listing
- [ ] `/robots.txt` — disallowed paths reveal hidden functionality
- [ ] `/sitemap.xml` — full URL inventory
- [ ] `/.svn/entries` — Subversion metadata
- [ ] `/WEB-INF/web.xml` — Java web app configuration
- [ ] `/server-status`, `/server-info` — Apache status pages

### 4. Backup and Temporary Files

- [ ] `index.php.bak`, `config.php.old`, `database.yml~`
- [ ] `backup.zip`, `backup.tar.gz`, `db_dump.sql`
- [ ] `.swp` files (Vim swap): `.index.php.swp`
- [ ] Editor backups: `#file#`, `file~`, `file.save`
- [ ] Copy artifacts: `config.php.orig`, `web.config.bak`
- [ ] Compressed source: `www.zip`, `html.tar.gz`, `source.tgz`

### 5. Debug and Admin Endpoints

- [ ] `/actuator` — Spring Boot actuator (env, health, beans, mappings)
- [ ] `/actuator/env` — environment variables and secrets
- [ ] `/debug`, `/debug/vars`, `/debug/pprof` — Go debug
- [ ] `/_profiler` — Symfony profiler
- [ ] `/elmah.axd` — .NET error log
- [ ] `/trace`, `/metrics`, `/health`, `/info`
- [ ] `/phpinfo.php`, `/info.php` — PHP configuration dump
- [ ] `/console` — Spring Boot H2 console, Rails console

### 6. API Response Analysis

- [ ] Check for excessive data in API responses (PII, internal IDs, timestamps)
- [ ] Compare authenticated vs unauthenticated responses
- [ ] Check if error responses contain more data than success
- [ ] Look for internal IP addresses, hostnames in responses
- [ ] Check pagination: can you request all records?
- [ ] GraphQL introspection for full schema

### 7. Client-Side Disclosure

- [ ] HTML comments: `<!-- TODO: remove before prod -->`, credentials, internal URLs
- [ ] JavaScript source maps: `.js.map` files expose original source
- [ ] Inline secrets in JavaScript: API keys, tokens, credentials
- [ ] Hidden form fields with sensitive defaults
- [ ] Local storage / session storage containing tokens or PII
- [ ] Service worker caching sensitive data

### 8. Version and Technology Detection

- [ ] Default error pages reveal software version
- [ ] Cookie names: `JSESSIONID` (Java), `PHPSESSID` (PHP), `ASP.NET_SessionId`
- [ ] URL patterns: `.jsp`, `.php`, `.aspx`
- [ ] Response behavior fingerprinting
- [ ] `/favicon.ico` hash → identify framework/CMS

### 9. Cloud Metadata & Environment Disclosure

- [ ] If a server-side fetch/proxy/webhook feature exists, test whether it (or a confirmed SSRF) can reach cloud metadata — `169.254.169.254` (AWS IMDSv1/v2, GCP, Azure), `100.100.100.200` (Alibaba Cloud); a returned IAM credential/role token is a Critical finding on its own
- [ ] `/api/config`, `/api/env`, `/config.json`, `/env.js`, `/settings.json` — SPA build-time config accidentally shipping server env vars
- [ ] Kubernetes-adjacent leaks: `/var/run/secrets/kubernetes.io/serviceaccount/token` exposed via an LFI/path-traversal primitive, or a container `/proc/self/environ` read
- [ ] CI/CD leftover: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile` reachable over HTTP if the web root includes the repo checkout
- [ ] Docker/orchestration leftovers: `/Dockerfile`, `docker-compose.yml`, `.dockerignore` reachable at web root

### 10. Timing & Behavioral Side Channels

- [ ] Compare response time for existing vs non-existing usernames/resources (username enumeration via timing, distinct from status-code differences — see `user-enumeration`)
- [ ] Compare response time for correct vs incorrect password prefix on auth endpoints that short-circuit comparison
- [ ] Note any endpoint whose response time scales with an internal collection size (e.g. `?search=` against a growing dataset) — can fingerprint record counts without direct read access
- [ ] Content-Length differences on otherwise-identical 200 responses across privilege levels — smaller body for lower privilege can still leak the *existence* of extra fields

### 11. Third-Party & Supply-Chain Disclosure

- [ ] Check `Server-Timing` header for internal service/component names
- [ ] Check CSP `report-uri`/`report-to` for internal collector hostnames
- [ ] Check `X-Amz-*`, `X-Goog-*`, `X-MS-*` response headers for cloud account/bucket/resource identifiers
- [ ] npm/pip/composer lockfiles reachable at web root (`package-lock.json`, `yarn.lock`, `composer.lock`, `Pipfile.lock`) — exact dependency versions for targeted CVE lookup via `osint-recon`
- [ ] Source-control leftovers beyond `.git`: `.hg/`, `.bzr/`, `_darcs/`, `CVS/`

### 12. Framework-Specific Verbose Error Signatures

- [ ] Django: `DEBUG = True` page shows full traceback, settings, installed apps, SQL query log
- [ ] Laravel: Ignition/Whoops page shows stack trace, env vars, `.env` values inline
- [ ] Rails: `ActionController::RoutingError` / `ActiveRecord` trace shows schema, gem versions
- [ ] Spring Boot: Whitelabel Error Page + `/actuator` combo reveals bean names and package structure
- [ ] Express/Node: default error handler echoes stack trace with local file paths
- [ ] ASP.NET: Yellow Screen of Death (YSOD) shows source code snippet around the exception line
- [ ] Flask: Werkzeug debugger (if `debug=True`) allows interactive console — potential RCE via PIN bypass
- [ ] PHP: `display_errors=On` leaks full path disclosure (`/var/www/html/...`) in warnings
- [ ] Next.js/Nuxt: dev-mode overlay leaks source file + component tree
- [ ] Trigger a type-confusion or malformed-body error (e.g. send array where object expected) to force these pages when normal invalid input is caught gracefully

### 13. Backup / Leftover File Pattern Depth

- [ ] IDE/editor artifacts: `.idea/`, `.vscode/`, `*.sublime-project`, `Thumbs.db`
- [ ] VCS metadata beyond `.git`: `.hg/`, `.bzr/`, `CVS/`, `_darcs/`
- [ ] Container/deploy leftovers: `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `k8s.yaml`, `.github/workflows/*.yml`
- [ ] CI/CD config exposing secrets: `.gitlab-ci.yml`, `.travis.yml`, `Jenkinsfile`, `azure-pipelines.yml`
- [ ] Dependency manifests leaking internal package names: `composer.lock`, `Gemfile.lock`, `poetry.lock`
- [ ] Numeric/dated backups: `backup-2024-01-15.zip`, `site_old.tar.gz`, `www2/`
- [ ] Source-map exposure beyond `.js.map`: check every bundled JS/CSS for a `//# sourceMappingURL=` comment even when the `.map` isn't linked from HTML directly

## What to Record

- Each disclosure finding with exact location (URL, header, response body)
- Data exposed: credentials, source code, internal architecture, PII
- Screenshots/evidence of error messages and debug pages
- Severity: Low (version info) to Critical (credentials, source code)
- Chain potential: how disclosure enables further attacks
- Remediation: custom error pages, remove debug endpoints, restrict files, strip headers
