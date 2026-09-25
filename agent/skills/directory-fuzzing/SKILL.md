---
name: directory-fuzzing
description: Discover hidden directories, files, and endpoints on a web server
origin: RedteamOpencode
---

# Directory Fuzzing

## When to Activate

- Web server identified, need hidden content discovery
- Looking for admin panels, backups, configs, API endpoints
- After identifying web technology (for targeted wordlists)

## Tools

`run_tool ffuf` (primary), `run_tool gobuster` (fallback), `run_tool curl` (verification)

## Methodology

### 1. Baseline Response
```bash
run_tool curl -s -o /dev/null -w "Code: %{http_code}, Size: %{size_download}" https://TARGET/nonexistent12345
```

### 2. Common Path Discovery
```bash
run_tool ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404
run_tool ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac  # Auto-calibrate
run_tool gobuster dir -u https://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50  # Fallback
```

### 3. Extension Fuzzing
```bash
run_tool ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.html,.js,.txt,.bak,.old,.conf,.xml,.json,.yml,.env,.log,.sql,.zip,.tar.gz
# Tech-specific: PHP(.phps,.phtml,.inc) ASP(.aspx,.config) Java(.jsp,.do,.action)
```

### 4. Filter Tuning
```bash
-fc 404,403,301        # Status code filter
-fs 1234               # Response size filter
-fw 42 / -fl 10        # Word/line count filter
-mc 200,301,302,403    # Match only specific codes
```

### 5. Recursive Discovery
```bash
run_tool ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac -recursion -recursion-depth 2
run_tool ffuf -u https://TARGET/admin/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac
```

### 6. Wordlist Escalation
```bash
# L1: /usr/share/wordlists/dirb/common.txt (~4,600)
# L2: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt (~20,000)
# L3: /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt (~220,000)
# Specialized: /usr/share/seclists/Discovery/Web-Content/raft-medium-{directories,files}.txt
# API: /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### 7. Backup and Sensitive Files
```bash
run_tool ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.old,.orig,.save,.swp,.tmp,~,.copy
for f in .env .git/config .htaccess web.config wp-config.php .DS_Store; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$f")
  [ "$code" != "404" ] && echo "$f -> $code"
done
run_tool curl -s https://TARGET/.git/HEAD
run_tool curl -s https://TARGET/.svn/entries | head -5
```

### 8. Backup, Archive, and Leftover-File Discovery

Step 7 covers flat backup suffixes and well-known config files. This step covers what a flat suffix sweep cannot handle: archive containers, database dumps, logs, and source maps. Use at most 13 requests in this pass. Cover `.zip`, `.tar.gz`, `.tgz`, `.rar`, `.7z`, `.sql`, `.dump`, `.log`, `.conf`, `.ini`, and source maps such as `app.js.map`, `style.css.map`, `bundle.map`. Verify each candidate with one ranged `GET`; never download a whole archive. Record status, content type, and downloaded byte count from the saved response artifacts.

For a confirmed archive already available under `$DIR/scans/`, write a listing-only artifact to `$DIR/scans/<name>.listing` with `unzip -l` or `tar -tzf`. Set `ARCHIVE_SAFE=yes` only after reviewing the listing for a huge compression ratio or an absolute or `../` member. If any such condition is present, record the archive-bomb/path-traversal finding and do not extract. Otherwise, extract at most one interesting small text member, capped at 65536 bytes, into `$DIR/scans/` and treat its secrets as sensitive-data evidence. A listing of a database dump or a config backup that contains credentials is a high-severity finding; write the secret values to `auth.json` via the engagement credential rules and redact raw secrets from the finding body.

Static-asset-suffix files exposing dynamic routes belong to the WAF/filter-differential family; hand those cases to `waf-evasion-testing` as the owner so the two skills do not duplicate each other.

```bash
MAX_REQUESTS=13
MAX_MEMBER_BYTES=65536
BASE="https://HOST"
CANDIDATES=(
  "backup.zip"
  "backup.tar.gz"
  "backup.tgz"
  "backup.rar"
  "backup.7z"
  "database.sql"
  "database.dump"
  "application.log"
  "application.conf"
  "application.ini"
  "app.js.map"
  "style.css.map"
  "bundle.map"
)
i=0
for path in "${CANDIDATES[@]}"; do
  if [ "$i" -ge "$MAX_REQUESTS" ]; then
    break
  fi
  i=$((i + 1))
  run_tool curl -sS --connect-timeout 5 --max-time 20 -r 0-1024 --max-filesize 2048 \
    -D "$DIR/scans/leftover-${i}.headers" -o "$DIR/scans/leftover-${i}.body" \
    -w 'status=%{http_code} content_type=%{content_type} content_length=%{size_download}\n' \
    "$BASE/$path"
done
ARCHIVE_KIND=zip
ARCHIVE_NAME="candidate.zip"
ARCHIVE_PATH="$DIR/scans/$ARCHIVE_NAME"
ARCHIVE_LISTING="$DIR/scans/$ARCHIVE_NAME.listing"
if [ "$ARCHIVE_KIND" = "zip" ]; then
  unzip -l "$ARCHIVE_PATH" > "$ARCHIVE_LISTING"
elif [ "$ARCHIVE_KIND" = "tar" ]; then
  tar -tzf "$ARCHIVE_PATH" > "$ARCHIVE_LISTING"
fi
ARCHIVE_SAFE=no
TEXT_MEMBER_SIZE=999999
TEXT_MEMBER="INTERESTING_TEXT_MEMBER"
if [ "$ARCHIVE_SAFE" = "yes" ] && [ "$TEXT_MEMBER_SIZE" -le "$MAX_MEMBER_BYTES" ]; then
  if [ "$ARCHIVE_KIND" = "zip" ]; then
    unzip -p "$ARCHIVE_PATH" "$TEXT_MEMBER" > "$DIR/scans/$ARCHIVE_NAME.member.txt"
  else
    tar -xOzf "$ARCHIVE_PATH" "$TEXT_MEMBER" > "$DIR/scans/$ARCHIVE_NAME.member.txt"
  fi
fi
```

### 9. Virtual Host / Subdomain
```bash
run_tool ffuf -u https://TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.TARGET" -ac
```

### 10b. Path-Normalization & Case-Sensitivity Bypass

Some paths 403/404 only because of casing or trailing-character handling, not because they
don't exist — cheap variants to try on any promising hit before discarding it:

```bash
for variant in "ADMIN" "Admin" "admin/" "admin." "admin%20" "admin%00" "admin..;/" \
               "./admin" "admin/." "%2e/admin" "admin%2f" ";/admin"; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$variant")
  echo "$variant -> $code"
done
# IIS/Tomcat/Nginx path-normalization quirks (`;`, `%2e%2e`, double slashes) can reach a route
# a naive filter blocks — treat any status-code delta from the plain path as a signal, and hand
# a confirmed differential to waf-evasion-testing rather than manually exhausting encodings here.
```

### 10c. IIS Short-Name (8.3) Enumeration

Only relevant when `Server: Microsoft-IIS` is fingerprinted — the legacy `~1` short-name
disclosure lets you brute-force real filenames from truncated 8.3 fragments:

```bash
run_tool curl -s -X OPTIONS "https://TARGET/*~1*/a.aspx" -o /dev/null -w "%{http_code}\n"
run_tool curl -s -H "Translate: f" "https://TARGET/somefile.aspx" -o /dev/null -w "%{http_code}\n"  # source-disclosure header, distinct bug class but same recon pass
```

### 10d. Rate-Limit-Aware Throttling

If early requests return 429 or response times climb, drop `-t` and add a delay before
burning the rest of the wordlist budget on noise the WAF is silently dropping:

```bash
run_tool ffuf -u https://TARGET/FUZZ -w wordlist.txt -ac -t 10 -p 0.3-0.8 -rate 20
```

### 10e. Case Permutation Fuzzing

Case-sensitive filesystems (Linux hosts serving mixed-case-authored content, or filters that
only pattern-match lowercase) can expose a path that's blocked/404 in its canonical casing:

```bash
for word in admin config backup login api; do
  for variant in "$word" "${word^^}" "${word^}" "$(echo "$word" | sed 's/./\u&/')"; do
    code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$variant")
    echo "$variant -> $code"
  done
done
# ffuf equivalent using a pre-cased wordlist
run_tool ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt \
  -X GET -ac -mode clusterbomb
```

### 10f. Framework-Specific Hidden-Route Wordlists

Generic wordlists miss routes a specific framework always mounts by convention. Once a
framework is fingerprinted (via `web-recon`), fuzz its known internal route prefixes directly
instead of relying on a generic dirb list to happen to contain them:

```bash
# Laravel
for p in .env telescope horizon _ignition/execute-solution _ignition/health-check \
         api/documentation storage/logs/laravel.log vendor/composer/installed.json; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$p"); [ "$code" != "404" ] && echo "$p -> $code"
done
# Django
for p in admin django-admin __debug__ media/ static/admin/ api/swagger .env; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$p"); [ "$code" != "404" ] && echo "$p -> $code"
done
# Ruby on Rails
for p in rails/info/properties rails/info/routes rails/mailers assets/config sidekiq; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$p"); [ "$code" != "404" ] && echo "$p -> $code"
done
# Spring Boot (actuator family — see also info-disclosure-testing)
for p in actuator actuator/env actuator/heapdump actuator/mappings actuator/beans swagger-ui.html h2-console; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$p"); [ "$code" != "404" ] && echo "$p -> $code"
done
# Express/Node
for p in .env package.json server.js app.js config/default.json node_modules/.package-lock.json; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$p"); [ "$code" != "404" ] && echo "$p -> $code"
done
# Next.js / Nuxt
for p in _next/static _next/data .next/build-manifest.json _nuxt api/_health; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$p"); [ "$code" != "404" ] && echo "$p -> $code"
done
```

### 10g. Backup-Suffix Sweep Across Every Discovered File

Once section 2/3 finds a real, existing file (e.g. `config.php`, `app.js`), re-fuzz that exact
filename with backup/editor suffixes rather than only sweeping suffixes across a generic
wordlist — real hits concentrate on files known to exist:

```bash
FOUND_FILE="config.php"
for suffix in .bak .old .orig .save .swp .tmp .copy .1 .zip .tar.gz ~ .rar "-copy" ".backup"; do
  code=$(run_tool curl -s -o /dev/null -w "%{http_code}" "https://TARGET/${FOUND_FILE}${suffix}")
  [ "$code" != "404" ] && echo "${FOUND_FILE}${suffix} -> $code"
done
```

### 11. Output
```bash
run_tool ffuf -u https://TARGET/FUZZ -w wordlist.txt -ac -o $DIR/scans/dir_fuzz_results.json -of json
run_tool curl -sI https://TARGET/discovered_path  # Verify
```
