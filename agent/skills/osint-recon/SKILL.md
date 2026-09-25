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

### 6. Internet-Wide Asset & Attack-Surface Search

    # Shodan (requires API key) — exposed services/banners tied to the org's ASN or IP range
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=org:%22<org>%22" | jq '.matches[] | {ip_str, port, org, hostnames}'
    # Favicon-hash pivot — reuse the mmh3 hash computed by web-recon to find sibling instances
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=http.favicon.hash:<hash>" | jq '.matches[].ip_str'

    # Censys (requires API creds) — certificate and service search
    curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.organization:%22<org>%22" | jq '.result.hits'

    # ASN / IP-range enumeration for the org (ties recon back to real infrastructure, not just the one hostname in scope)
    whois -h whois.radb.net -- "-i origin $(whois <domain> | grep -i 'OriginAS' | awk '{print $2}')" 2>/dev/null
    curl -s "https://api.bgpview.io/asn/<ASN>/prefixes" | jq '.data.ipv4_prefixes[] | {prefix, description}'

    # Public cloud storage bucket guessing (S3/GCS/Azure) from org/product naming
    for suffix in "" -prod -dev -staging -backup -assets -static -files -data -logs; do
      b="<org>${suffix}"
      curl -s -o /dev/null -w "%{http_code} https://${b}.s3.amazonaws.com/\n" "https://${b}.s3.amazonaws.com/"
      curl -s -o /dev/null -w "%{http_code} https://storage.googleapis.com/${b}/\n" "https://storage.googleapis.com/${b}/"
      curl -s -o /dev/null -w "%{http_code} https://${b}.blob.core.windows.net/\n" "https://${b}.blob.core.windows.net/"
    done

    # GitHub/GitLab code search dorking for leaked secrets referencing the target domain
    curl -s "https://api.github.com/search/code?q=%22<domain>%22+password" -H "Accept: application/vnd.github+json" | jq '.items[] | {repository: .repository.full_name, path, html_url}'
    curl -s "https://api.github.com/search/code?q=%22<domain>%22+(api_key+OR+secret+OR+token)" | jq '.items[] | {path, html_url}'

    # Job postings — tech stack and internal tool names leak through hiring pages
    curl -s "https://api.github.com/search/repositories?q=org:<org-github>&sort=updated&per_page=20" | jq '.items[] | {name, description, language}'

### 7. DNS Attack-Surface Depth

    # Zone transfer attempt (misconfiguration check — low hit rate but zero-cost)
    for ns in $(dig +short NS <domain>); do
      dig axfr <domain> @"$ns"
    done

    # SPF/DKIM/DMARC posture (feeds mail-dns-services and phishing/spoofing risk assessment)
    dig +short TXT <domain> | grep -i spf
    dig +short TXT _dmarc.<domain>
    dig +short TXT default._domainkey.<domain>

    # Reverse DNS sweep across the discovered IP range to surface unlisted vhosts
    for ip in $(dig +short A <domain>); do
      dig -x "$ip" +short
    done

    # Passive DNS via crt.sh subdomain harvest feeding straight into subdomain-enumeration
    curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

### 8. Search-Engine & Source-Repository Dorking

Beyond the direct GitHub code-search calls in Section 6, run manual dork queries against
general search engines and other code hosts — these surface indexed content the GitHub API
search misses (private-looking paths that got crawled, PDFs, exposed panels):

    # Google/Bing dorks (run via WebSearch tool or browser, not curl — most engines block scripted queries)
    site:<domain> filetype:pdf OR filetype:xls OR filetype:sql OR filetype:log
    site:<domain> inurl:admin OR inurl:login OR inurl:internal
    site:<domain> "index of /" intitle:"index of"
    site:pastebin.com "<domain>"
    site:trello.com OR site:notion.so "<domain>"
    intext:"<domain>" ext:env OR ext:config OR ext:yml

    # GitLab code search (self-hosted or gitlab.com)
    curl -s "https://gitlab.com/api/v4/search?scope=blobs&search=<domain>" -H "PRIVATE-TOKEN: $GITLAB_TOKEN" | jq '.[] | {project_id, path, ref}'

    # Bitbucket / SourceHut spot checks — no unauthenticated code-search API; check org existence
    curl -s "https://api.bitbucket.org/2.0/repositories/<org>" | jq '.values[] | {name, links: .links.html.href}'

    # Docker Hub — image tags may leak internal env/config via history or accompanying README
    curl -s "https://hub.docker.com/v2/repositories/<org>/?page_size=25" | jq '.results[] | {name, description}'

    # npm / PyPI package registries — org-published packages can leak internal names, install scripts, tokens
    curl -s "https://registry.npmjs.org/-/v1/search?text=%40<org>&size=20" | jq '.objects[].package | {name, version}'

### 9. Employee & Technology Fingerprinting

    # LinkedIn-derived name-format inference (manual — for phishing/password-spray username patterns)
    # Once 2-3 real employee names are known, derive the org's email convention (first.last@, flast@, etc.)
    # and cross-check candidate addresses against HIBP/h8mail before spraying.

    # BuiltWith / Wappalyzer-style tech fingerprint via public API (requires key) — complements whatweb from web-recon
    curl -s "https://api.builtwith.com/v21/api.json?KEY=$BUILTWITH_API_KEY&LOOKUP=<domain>" | jq '.Results[0].Result.Paths[].Technologies[] | {Name, Tag}'

    # Wayback Machine job-posting / staff-page snapshots — historical "About/Team" pages often outlive current site content
    curl -s "https://web.archive.org/cdx/search/cdx?url=<domain>/team*&output=json&fl=original,timestamp&collapse=urlkey" | jq '.[1:][]'

### 10. Typosquat / Domain-Variation Monitoring

Attacker-registered lookalike domains are both a phishing indicator and, if pointed at the
same infra, an additional in-scope-adjacent attack surface to flag for the client:

    # Generate common typosquat permutations (character swap, omission, homoglyph, TLD swap)
    python3 -c "
d='<domain-without-tld>'
tld='.com'
subs='qwertyuiopasdfghjklzxcvbnm'
variants=set()
for i in range(len(d)):
    variants.add(d[:i]+d[i+1:])                      # omission
    for c in subs:
        variants.add(d[:i]+c+d[i+1:])                # substitution
for v in variants:
    print(v+tld)
" | head -50

    # Bulk-resolve candidates to find registered lookalikes
    while read -r cand; do dig +short A "$cand" | head -1 | grep -q . && echo "$cand REGISTERED"; done < candidates.txt

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
