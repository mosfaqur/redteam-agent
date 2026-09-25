---
name: osint-recon
description: Open-source intelligence gathering — CVE lookup, breach search, DNS history, social profiling
origin: RedteamOpencode
---

# OSINT Reconnaissance

## When to Activate

- After TEST phase, intel.md has accumulated tech stack, people, domains, credentials
- Parallel with exploit phase to enrich attack context

## Tools

searchsploit, h8mail, theHarvester, spiderfoot, amass, whois, dig,
waybackurls, curl, jq, exiftool, steghide, zsteg, binwalk, strings

## Methodology

### 1. CVE & Exploit Lookup

From intel.md Technology Stack — for each component+version:

    # Exploit-DB local search
    searchsploit "<component> <version>"
    searchsploit -j "<component> <version>" | jq '.RESULTS_EXPLOIT[]'

    # NVD API (rate limit: 5 req/30s without API key)
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<component>+<version>&resultsPerPage=10" \
      | jq '.vulnerabilities[].cve | {id, descriptions: .descriptions[0].value, metrics: .metrics}'

    # GitHub Advisory Database
    curl -s "https://api.github.com/advisories?affects=<component>&per_page=10" \
      | jq '.[].ghsa_id, .[].summary'

    # GitHub PoC search
    curl -s "https://api.github.com/search/repositories?q=CVE+<component>+poc&sort=updated&per_page=5" \
      | jq '.items[] | {name, html_url, description}'

### 2. Breach & Credential Intelligence

From intel.md Email Addresses and Domains:

    # theHarvester — email and subdomain enumeration
    theHarvester -d <domain> -b all -f scans/osint_harvester.json

    # h8mail — breach lookup for discovered emails
    h8mail -t <email1>,<email2> -o scans/osint_h8mail.csv

    # HIBP API (requires API key in env)
    curl -s -H "hibp-api-key: $HIBP_API_KEY" \
      "https://haveibeenpwned.com/api/v3/breachedaccount/<email>?truncateResponse=false" | jq '.'

    # Paste search
    curl -s -H "hibp-api-key: $HIBP_API_KEY" \
      "https://haveibeenpwned.com/api/v3/pasteaccount/<email>" | jq '.'

### 3. DNS & Infrastructure History

From intel.md Domains & Infrastructure:

    # WHOIS
    whois <domain> | tee scans/osint_whois.txt

    # Certificate transparency
    curl -s "https://crt.sh/?q=%25.<domain>&output=json" \
      | jq '.[0:20] | .[] | {name_value, issuer_name, not_before, not_after}'

    # DNS records
    for type in A AAAA MX NS TXT SOA CNAME; do
      dig +short $type <domain>
    done | tee scans/osint_dns.txt

    # Amass passive enum
    amass enum -passive -d <domain> -o scans/osint_amass.txt

    # Wayback Machine — historical URLs
    curl -s "https://web.archive.org/cdx/search/cdx?url=<domain>/*&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=200" \
      | jq '.[1:][] | {url: .[0], date: .[1], status: .[2]}'

    # SecurityTrails API (requires API key in env)
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
      "https://api.securitytrails.com/v1/domain/<domain>/subdomains" | jq '.subdomains[]'

    # Historical DNS
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
      "https://api.securitytrails.com/v1/history/<domain>/dns/a" | jq '.records[]'

### 4. Social & Organizational Intelligence

From intel.md People & Organizations:

    # theHarvester — people and email enumeration
    theHarvester -d <domain> -b linkedin,google -f scans/osint_social.json

    # SpiderFoot CLI scan
    spiderfoot -s <domain> -m sfp_dnsresolve,sfp_whois,sfp_social,sfp_email \
      -o scans/osint_spiderfoot.json

    # GitHub user/org search
    curl -s "https://api.github.com/search/users?q=<person>+<org>" \
      | jq '.items[] | {login, html_url, type}'

    # GitHub org repos (potential source code leaks)
    curl -s "https://api.github.com/orgs/<org>/repos?per_page=30&sort=updated" \
      | jq '.[] | {name, html_url, description, visibility}'

    # Hunter.io — email pattern discovery (requires API key)
    curl -s "https://api.hunter.io/v2/domain-search?domain=<domain>&api_key=$HUNTER_API_KEY" \
      | jq '.data.emails[] | {value, type, confidence}'

### 5. Image Metadata & Steganography

For images and documents surfaced during recon or leaked through the target:

    # EXIF / metadata extraction from an image
    exiftool image.jpg > scans/osint_exif.txt

    # Extract visible EXIF fields without exiftool
    python3 -c 'from PIL import Image; from PIL.ExifTags import TAGS; \
    import sys; im = Image.open(sys.argv[1]); \
    print({TAGS.get(k, k): v for k, v in im._getexif().items()} if im._getexif() else {})' image.jpg

    # Embedded strings / hidden data (steghide, zsteg, binwalk)
    strings image.png | grep -iE 'flag|pass|key|secret|gps|exif' 
    steghide extract -sf image.jpg -p '' 
    zsteg image.png
    binwalk image.jpg > scans/osint_binwalk.txt

- [ ] Record GPS coordinates, camera serial, device, and timestamps as location/identity intel
- [ ] Treat GPS/lat-lon as a geo-stalking lead only; confirm against another source before acting
- [ ] Check images for steganographic payloads when a challenge or target hints at hidden data

## Priority Order

1. CVE + version match with public PoC (immediate exploit value)
2. Leaked/breached credentials for target emails (direct access)
3. Historical endpoints not in current attack surface (hidden functionality)
4. Organizational intel enriching social engineering context
5. DNS/cert history revealing infrastructure changes

## Output Integration

ALL output goes to intel.md ONLY. osint-analyst does NOT write to findings.md.
- CVE matches → intel.md CVE table + Intelligence Assessment
- Breached credentials → intel.md Breach table + Intelligence Assessment
- Historical URLs → intel.md DNS table (operator decides whether to requeue)
- Social/org intel → intel.md Social table
