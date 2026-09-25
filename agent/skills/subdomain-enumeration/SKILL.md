---
name: subdomain-enumeration
description: Subdomain discovery via subfinder, DNS brute-force, and passive sources
origin: RedteamOpencode
---

# Subdomain Enumeration

## When to Activate

- Beginning of engagement when scope includes wildcard domains (*.target.com)
- Need to discover additional attack surface beyond the primary domain
- Recon phase — run in parallel with other recon tasks
- After finding references to subdomains in JS/HTML source code

## Tools

- `subfinder` — passive subdomain enumeration (multiple sources, API keys optional)
- `run_tool ffuf` — DNS brute-force via vhost fuzzing
- `run_tool curl` / `run_tool nmap` — verify discovered subdomains are live

## Methodology

### 1. Passive Enumeration with subfinder

subfinder queries 40+ passive sources (crt.sh, VirusTotal, Shodan, SecurityTrails, etc.)
without sending traffic to the target.

```bash
# Basic enumeration
run_tool subfinder -d target.com -silent

# With all sources (uses API keys from $DIR/.env if mounted)
run_tool subfinder -d target.com -all -silent -o $DIR/scans/subdomains.txt

# Multiple domains
run_tool subfinder -dL $DIR/scans/domains.txt -silent -o $DIR/scans/subdomains.txt

# JSON output for detailed source info
run_tool subfinder -d target.com -all -json -o $DIR/scans/subdomains.json

# Resolve IPs while enumerating
run_tool subfinder -d target.com -all -silent -nW -oI -o $DIR/scans/subdomains_ips.txt
```

**API keys** enhance results significantly. Configure in `$ENGAGEMENT_DIR/.env`:
```
SUBFINDER_VIRUSTOTAL_API_KEY=...
SUBFINDER_SECURITYTRAILS_API_KEY=...
SUBFINDER_SHODAN_API_KEY=...
```
These are mounted into the container automatically via the .env volume mount.

### 2. DNS Brute-Force with ffuf

Active brute-force for subdomains not found by passive sources:

```bash
# First, baseline — get response size for non-existent subdomain
run_tool curl -s -o /dev/null -w "%{size_download}" -H "Host: nonexistent-xyz.target.com" http://TARGET_IP

# Brute-force with vhost fuzzing
run_tool ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" \
  -w /seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <baseline_size> -t 50 \
  -o $DIR/scans/vhost_fuzz.json -of json

# Larger wordlist if initial results are sparse
run_tool ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" \
  -w /seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -fs <baseline_size> -t 50 \
  -o $DIR/scans/vhost_fuzz_20k.json -of json
```

### 3. Filter, Verify & Fingerprint Subdomains

Three-stage filter: DNS resolution → web port open → fingerprint. Only subdomains that
pass ALL stages enter the engagement pipeline.

```bash
# Stage 1: DNS resolution filter — drop subdomains that don't resolve
> "$ENGAGEMENT_DIR/scans/subdomains_resolved.txt"
while IFS= read -r sub; do
  ip=$(dig +short "$sub" 2>/dev/null | head -1)
  if [ -n "$ip" ] && [ "$ip" != ";;" ]; then
    echo "$sub" >> "$ENGAGEMENT_DIR/scans/subdomains_resolved.txt"
  else
    echo "  [SKIP] $sub — DNS does not resolve"
  fi
done < "$ENGAGEMENT_DIR/scans/subdomains.txt"
echo "Resolved: $(wc -l < $ENGAGEMENT_DIR/scans/subdomains_resolved.txt) / $(wc -l < $ENGAGEMENT_DIR/scans/subdomains.txt)"

# Stage 2: Web port check — try HTTP (80), HTTPS (443), then common alt ports (8080, 8443)
> "$ENGAGEMENT_DIR/scans/subdomains_live.txt"
while IFS= read -r sub; do
  live=""
  for proto_port in "http://$sub" "https://$sub" "http://$sub:8080" "https://$sub:8443"; do
    code=$(run_tool curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 -k "$proto_port" 2>/dev/null)
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      echo "$sub $proto_port $code" >> "$ENGAGEMENT_DIR/scans/subdomains_live.txt"
      live="yes"
      break
    fi
  done
  [ -z "$live" ] && echo "  [SKIP] $sub — no open web port (80/443/8080/8443)"
done < "$ENGAGEMENT_DIR/scans/subdomains_resolved.txt"
echo "Live web: $(wc -l < $ENGAGEMENT_DIR/scans/subdomains_live.txt)"

# Stage 3: Fingerprint live subdomains for prioritization
echo "subdomain|url|status|server|title|size|notes" > "$ENGAGEMENT_DIR/scans/subdomains_fingerprint.csv"
TMPDIR_FINGERPRINT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_FINGERPRINT"' EXIT
while IFS=' ' read -r sub url code; do
  resp=$(run_tool curl -s -o "$TMPDIR_FINGERPRINT/sub_resp.html" -w "%{size_download}" \
    -D "$TMPDIR_FINGERPRINT/sub_headers.txt" --connect-timeout 5 -k "$url" 2>/dev/null)
  size="$resp"
  server=$(grep -i "^server:" "$TMPDIR_FINGERPRINT/sub_headers.txt" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r')
  title=$(grep -oE '<title>[^<]+</title>' "$TMPDIR_FINGERPRINT/sub_resp.html" 2>/dev/null | head -1 | sed 's/<[^>]*>//g')
  notes=""
  grep -qi "debug\|x-debug\|x-powered-by\|x-aspnet" "$TMPDIR_FINGERPRINT/sub_headers.txt" 2>/dev/null && notes="${notes}debug_headers "
  grep -qi "error\|exception\|traceback\|stack.trace" "$TMPDIR_FINGERPRINT/sub_resp.html" 2>/dev/null && notes="${notes}verbose_errors "
  [ "$code" = "401" ] || [ "$code" = "403" ] && notes="${notes}auth_protected "
  echo "$sub|$url|$code|$server|$title|$size|$notes" >> "$ENGAGEMENT_DIR/scans/subdomains_fingerprint.csv"
  echo "  $sub → $code ($server) [$title] ${notes}"
done < "$ENGAGEMENT_DIR/scans/subdomains_live.txt"
```

**Filter summary**: Only subdomains in `subdomains_fingerprint.csv` should enter engagements.
Subdomains that fail DNS or have no web port are logged and skipped — do NOT create
engagements for them.

Fingerprint signals for prioritization:
- **debug_headers**: likely dev/test environment → HIGH priority
- **verbose_errors**: misconfigured → HIGH priority
- **auth_protected**: admin panel or internal tool → test for bypass
- **Small response size**: minimal app or API → less hardened
- **Non-standard server**: unusual tech, potentially unpatched

### 3b. Wildcard DNS Detection (avoid false-positive floods)

Before trusting brute-force hits, confirm the zone doesn't wildcard-resolve everything:

```bash
rand_sub="nonexistent-$(date +%s)-$RANDOM"
wild_ip=$(dig +short "${rand_sub}.target.com" | head -1)
if [ -n "$wild_ip" ]; then
  echo "WILDCARD DNS detected -> $wild_ip — every brute-force guess will 'resolve'; require a distinct HTTP fingerprint, not just DNS resolution, before treating a hit as real"
fi
```

### 3c. Permutation / Mutation Enumeration

Passive + brute-force alone miss environment-style names. Generate permutations from
already-discovered subdomains and known naming conventions, then re-resolve:

```bash
# Manual permutation (dnsgen/altdns-style) when the dedicated tool isn't available
while IFS= read -r sub; do
  base="${sub%%.*}"
  for pat in dev staging stage test qa uat preprod prod internal admin api api-v1 api-v2 \
             beta canary sandbox demo old new backup vpn mail portal partner; do
    echo "${pat}.${sub}"
    echo "${base}-${pat}.target.com"
    echo "${pat}-${base}.target.com"
  done
done < "$ENGAGEMENT_DIR/scans/subdomains.txt" | sort -u > "$ENGAGEMENT_DIR/scans/subdomains_permuted.txt"
# Re-run through the Stage 1-3 resolve/live/fingerprint pipeline above
```

### 3d. Dangling CNAME / Takeover Candidate Flagging

While resolving, flag any subdomain whose CNAME points at a third-party service but the
service-side resource doesn't exist — this is the entry condition for `subdomain-takeover`:

```bash
while IFS= read -r sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  [ -n "$cname" ] && echo "$sub -> CNAME $cname"
done < "$ENGAGEMENT_DIR/scans/subdomains_resolved.txt" | \
  grep -iE "\.(github\.io|herokuapp\.com|azurewebsites\.net|cloudapp\.net|s3\.amazonaws\.com|s3-website|trafficmanager\.net|cloudfront\.net|fastly\.net|zendesk\.com|shopify\.com|wordpress\.com|readme\.io|surge\.sh|netlify\.app|vercel\.app)\.?$" \
  > "$ENGAGEMENT_DIR/scans/subdomains_third_party_cname.txt"
echo "Third-party CNAMEs flagged for takeover check: $(wc -l < $ENGAGEMENT_DIR/scans/subdomains_third_party_cname.txt)"
```

### 3e. Certificate Transparency Monitoring for New Names

CT logs surface subdomains issued *after* the last passive scan (recently stood-up dev/test
hosts) and unlisted second-level combinations:

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | \
  tr 'A-Z' 'a-z' | sed 's/\*\.//g' | sort -u > "$ENGAGEMENT_DIR/scans/subdomains_ct.txt"
comm -23 "$ENGAGEMENT_DIR/scans/subdomains_ct.txt" <(sort -u "$ENGAGEMENT_DIR/scans/subdomains.txt") \
  > "$ENGAGEMENT_DIR/scans/subdomains_ct_new.txt"   # names in CT but missed by subfinder
```

### 3f. Additional Passive Sources / DNS Aggregators

subfinder already queries many of these, but querying directly is useful when API keys aren't
configured or when a source has coverage subfinder's connector lacks:

```bash
# RapidDNS — free passive DNS aggregator, no key required
curl -s "https://rapiddns.io/subdomain/target.com?full=1" | grep -oE '[a-zA-Z0-9.-]+\.target\.com' | sort -u

# BufferOver / DNS.BufferOver — passive DNS dataset
curl -s "https://dns.bufferover.run/dns?q=.target.com" | jq -r '.FDNS_A[]? | split(",")[1]' | sort -u

# crt.sh certificate transparency JSON endpoint
curl -s "https://crt.sh/?q=%25.target.com&output=json" -H "Accept: application/json" | jq -r '.[].name_value' | sort -u

# ProjectDiscovery Chaos dataset (requires API key, curated bug-bounty subdomain lists)
curl -s -H "Authorization: $CHAOS_API_KEY" "https://dns.projectdiscovery.io/dns/target.com/subdomains" | jq -r '.subdomains[]' | sed 's/$/.target.com/'

# DNSDumpster-style web scrape fallback when API access isn't available
curl -s "https://dnsdumpster.com/" -c cookies.txt -o dnsdumpster.html
csrf=$(grep -oP 'csrfmiddlewaretoken.{0,80}value="\K[^"]+' dnsdumpster.html 2>/dev/null)  # requires session token scrape; prefer subfinder/crt.sh when this is brittle

# Merge everything into the master list before Stage 1 resolution
cat "$ENGAGEMENT_DIR/scans/subdomains.txt" rapiddns.txt bufferover.txt chaos.txt | sort -u > "$ENGAGEMENT_DIR/scans/subdomains_merged.txt"
```

### 3g. ASN / Reverse-WHOIS Pivoting

Subdomains that don't share the parent domain's naming convention (rebranded products,
acquisitions, regional TLDs) won't surface from DNS brute-force or CT logs — pivot on the
org's actual network ownership instead:

```bash
# Find ASN(s) owning the target's known IP
whois -h whois.radb.net -- "-i origin $(whois <target-ip> | grep -i 'OriginAS' | awk '{print $2}')" 2>/dev/null

# Enumerate all prefixes announced by that ASN, then reverse-DNS sweep each /24
curl -s "https://api.bgpview.io/asn/<ASN>/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'
for ip in $(nmap -sL -n <prefix> | awk '/Nmap scan report/{print $NF}' | tr -d '()'); do
  dig -x "$ip" +short
done | sort -u

# Reverse WHOIS — find other domains registered by the same org/registrant email
curl -s "https://api.whoisxmlapi.com/v1?apiKey=$WHOISXML_API_KEY&searchType=current&mode=purchase&punycode=true&basicSearchTerms.include=<org-registrant-email>" | jq -r '.domainsList[]'
```

### 3h. Favicon-Hash Cross-Domain Pivot

Reuse the mmh3 favicon hash from `web-recon` section 3b to find sibling subdomains/hosts
running the identical admin panel or product build under a different name entirely:

```bash
curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=http.favicon.hash:<hash>+hostname:target.com" | jq -r '.matches[].hostnames[]'
```

### 4. Recursive Enumeration

If new subdomains are found, enumerate their subdomains too:

```bash
# Feed discovered subdomains back for deeper enumeration
run_tool subfinder -dL $DIR/scans/subdomains.txt -all -silent \
  -o $DIR/scans/subdomains_recursive.txt
```

### 5. Feed Results into Pipeline

Import discovered subdomains as cases for testing:

```bash
# Only import verified live web entries. subdomains_live.txt is: "<subdomain> <url> <status>"
awk '{print $1}' "$ENGAGEMENT_DIR/scans/subdomains_live.txt" | sort -u | while IFS= read -r sub; do
  echo "GET https://$sub"
done | \
  ./scripts/recon_ingest.sh "$ENGAGEMENT_DIR/cases.db" subdomain-enum
```

## What to Record

- **Total subdomains found** (passive + active)
- **Live subdomains** with HTTP status codes
- **Interesting subdomains**: staging, dev, admin, api, internal, test, beta
- **Services** running on non-standard ports
- **Source** of each subdomain (subfinder source, brute-force, JS reference)
- Any subdomain pointing to **different infrastructure** (cloud, CDN, third-party)
