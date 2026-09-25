---
name: subdomain-takeover
description: Detect and confirm dangling-DNS subdomain takeover conditions without claiming resources
origin: RedteamOpencode
---

# Subdomain Takeover Testing

## When to Activate

- Reuse the engagement asset inventory when DNS aliases, nameservers, mail, or addresses point outside the primary hosting
- Investigate provider “not found” responses, unknown SaaS hosts, or stale development subdomains
- Escalate only when DNS evidence and a provider-specific unclaimed fingerprint agree

## Tools

`run_tool subfinder`, `run_tool curl`, `run_tool nuclei`; host `dig`, `host`.

## Methodology

### 1. Seed the Candidate List

Reuse `$DIR/scans/subdomains.txt`, subfinder output, certificate data, and the asset inventory before sending traffic. Run subfinder only when those inputs lack the root domain, then save the bounded result under the engagement.

```bash
run_tool subfinder -d "ROOT_DOMAIN" -silent -o "$DIR/scans/takeover-subdomains.txt"
```

### 2. Triage Dangling DNS

Resolve every record type; retain aliases even when the final hostname no longer resolves.

```bash
dig +short CNAME "HOST"
dig +short NS "HOST"
dig +short MX "HOST"
dig +short A "HOST"
host -a "HOST"
```

Classify CNAME-to-SaaS, NS-to-deprovisioned-zone, MX-to-decommissioned-mail, and A-to-released-IP candidates separately. A missing final DNS answer alone is not proof of takeover.

### 3. Apply the Proof Standard

| Record class | Candidate condition | Required confirmation |
|---|---|---|
| CNAME | Alias names a deprovisioned SaaS resource | Provider-specific unclaimed body or headers on the alias |
| NS | Zone delegates to a removed or unassigned nameserver set | Provider/registrar control-plane state reflected in authoritative DNS |
| MX | Mail hostname or provider tenant was decommissioned | Provider-specific unassigned mailbox/service response |
| A | Address was released or reassigned after removal | Original provider still serves its unclaimed-resource fingerprint |

Treat a generic CDN, WAF, `404`, NXDOMAIN, timeout, or `X-Cache: MISS` as inconclusive. Correlate the live response with the provider's own unclaimed page body and headers, not merely the DNS target's name.

### 4. Match Provider Fingerprints

| Provider | Typical dangling target | Provider-owned unclaimed signal to corroborate |
|---|---|---|
| Netlify | `*.netlify.app` | `server: Netlify`, `x-nf-request-id`, and the Netlify `Page not found` body |
| Vercel | `*.vercel-dns.com` or `*.vercel.app` | `server: Vercel`, `x-vercel-id`, and `The page could not be found` |
| Heroku | `*.herokuapp.com` | `server: Cowboy` and the provider body `No such app` |
| AWS S3 | Bucket endpoint or alias | `server: AmazonS3`, `x-amz-request-id`, and `NoSuchBucket` or `The specified bucket does not exist` |
| AWS CloudFront | Distribution hostname | `server: CloudFront`, `x-amz-cf-id`, `x-cache: Error from cloudfront`, and the distribution/resource error body |
| GitHub Pages | `*.github.io` | `server: GitHub.com` and `There isn't a GitHub Pages site here.` |
| Azure | `*.azurefd.net`, `*.cloudapp.net`, or `*.trafficmanager.net` | `x-azure-ref` or `x-ms-request-id` with the provider's unassigned-host body such as `404 - Web site not found` |
| Fastly | `*.fastly.net` | `server: Fastly`, `x-served-by`, and `Fastly error: unknown domain` |
| DigitalOcean | Released Droplet address or `*.ondigitalocean.app` | `server: DigitalOcean`, `x-do-request-id`, and the provider's unassigned-domain or unassigned-app body |
| Shopify | `shops.myshopify.com` | Shopify unavailability body such as `Sorry, this shop is currently unavailable.` with matching metadata |
| Bitbucket | `*.bitbucket.io` | `server: Bitbucket` and `Repository not found` |
| Surge | `*.surge.sh` | `server: surge.sh` and `project not found` |
| ReadMe | A ReadMe project hostname | Provider unassigned-page body such as `Project not found`, plus matching ReadMe metadata when exposed |
| Pantheon | `*.pantheonsite.io` | `server: nginx` with the body `The gods are wise, but do not know of the site which you seek.` |
| Tumblr | `*.tumblr.com` (custom domain) | `Whatever you were looking for doesn't currently exist at this address` |
| Unbounce | `*.unbouncepages.com` | `The requested URL was not found on this server.` combined with Unbounce-specific headers |
| Wordpress.com | `*.wordpress.com` | `Do you want to register *.wordpress.com?` |
| Zendesk | `*.zendesk.com` | `Help Center Closed` |
| Firebase/Google Cloud | `*.firebaseapp.com`, `*.web.app` | `404 Not Found` combined with Firebase Hosting-specific headers and lack of a claimed project |
| Cargo | `*.cargocollective.com` | `404 Not Found` with Cargo-specific body text |
| Statuspage | `*.statuspage.io` | `You are being redirected` / statuspage-specific `page not found` body |
| npm/Now (legacy Vercel) | `*.now.sh` | Same family as Vercel — `The deployment could not be found` |

Use multiple matching signals. A signature alone is shared infrastructure and can produce false positives.

### 4b. Non-DNS Takeover Vectors

Not every takeover is a dangling CNAME — apply the same proof discipline (control-plane evidence, not just an error page) to these:

- [ ] **Cloud storage bucket takeover**: a CNAME/alias or hardcoded asset URL points at an S3/GCS/Azure Blob bucket name that returns `NoSuchBucket`/`BucketNotFound` — the bucket name itself is unclaimed and registrable in that cloud account namespace, not just the DNS record
- [ ] **SaaS custom-domain takeover without DNS dangling**: some platforms (Shopify, Webflow, Squarespace) allow attaching *any* unclaimed custom domain to a new tenant account even if the domain currently resolves elsewhere via a stale CNAME — verify via the platform's own domain-claim flow language, never by actually claiming
- [ ] **Package/registry namespace takeover**: an internal build references an npm/PyPI/RubyGems/Docker Hub package name that was never published or was deleted — flag as dependency-confusion-adjacent (see `ci-cd-security`), not classic DNS takeover
- [ ] **GitHub org/repo takeover**: a CI badge, webhook, or `.github.io` Pages source references a GitHub org/repo that was renamed or deleted — the old name becomes claimable and can serve attacker content under the org's trusted path
- [ ] **Third-party email sender takeover** (SPF/DMARC-adjacent): SPF record `include:`s a decommissioned third-party sending domain/service — flag alongside `mail-dns-services` for spoofing risk rather than a web takeover

### 5. Capture the Live Fingerprint

Request the alias over both schemes without following redirects; preserve headers and body for comparison.

```bash
run_tool curl -skS --connect-timeout 5 --max-time 20 -D "$DIR/scans/takeover-https-headers.txt" -o "$DIR/scans/takeover-https-body.html" "https://HOST"
run_tool curl -sS --connect-timeout 5 --max-time 20 -D "$DIR/scans/takeover-http-headers.txt" -o "$DIR/scans/takeover-http-body.html" "http://HOST"
```

Compare the result with a known sibling hostname and the provider fingerprint. Record exact DNS answers, status, redirect target, headers, and matching body phrase.

### 6. Use Nuclei as a Shortcut

Build a shortlist of at most two DNS-consistent candidates. Let takeover templates rank them, then manually verify every result against the proof standard.

```bash
run_tool nuclei -l "$DIR/scans/takeover-shortlist.txt" -tags takeover -severity low,medium,high,critical -c 2 -o "$DIR/scans/takeover-nuclei.txt"
```

Ignore template-only matches that lack the provider-owned unclaimed response.

### 7. Confirm and Handoff

Record the hostname, record type, DNS chain, provider fingerprint, and evidence paths in `$DIR/intel.md`. Stop at confirmation and hand any impact analysis to `exploit-developer`.

Never register, reserve, transfer, create, configure, upload to, or otherwise claim the dangling resource. Do not create a provider account, place an order, change DNS, test ownership by claiming, or perform a destructive takeover.

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A06-insecure-design.md`, `references/tools/recon/nuclei.md`.
