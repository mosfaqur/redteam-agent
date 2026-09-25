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

### 10. Output
```bash
run_tool ffuf -u https://TARGET/FUZZ -w wordlist.txt -ac -o $DIR/scans/dir_fuzz_results.json -of json
run_tool curl -sI https://TARGET/discovered_path  # Verify
```
