---
name: mail-dns-services
description: Test SMTP/IMAP/POP3 and DNS services (open relay, user enumeration, zone transfer, recursion)
origin: RedteamOpencode
---

# Mail / DNS Services

## When to Activate

- Ports 25/465/587 (SMTP), 110 (POP3), 143/993 (IMAP), 53 (DNS)
- Need user enumeration, open relay, or internal name discovery

## Tools

`run_tool nmap`, `smtp-user-enum`, `swaks`, `dig`, `dnsrecon`, `dnsenum`, `nc`.

## Methodology

### SMTP (25/587/465)
```bash
run_tool nmap -p 25 --script smtp-commands,smtp-open-relay,smtp-enum-users,smtp-vuln-* HOST
# user enumeration
run_tool smtp-user-enum -M VRFY -U users.txt -t HOST
run_tool smtp-user-enum -M RCPT -U users.txt -t HOST
# open relay test (single bounded message)
run_tool swaks --to test@external.tld --server HOST
```
Also try `EXPN`, `RCPT TO`, and banner/software CVE mapping (Exim, Sendmail, Postfix).

Additional SMTP checks:
- [ ] `STARTTLS` stripping: confirm the server advertises `STARTTLS` and whether a downgrade to cleartext AUTH is possible (report only, do not intercept live traffic)
- [ ] SMTP AUTH mechanism enumeration (`AUTH LOGIN`/`PLAIN`/`NTLM`) — NTLM-over-SMTP exposes a relay-able auth handshake, cross-reference with `smb-netbios` relay notes
- [ ] Email spoofing surface: check the domain's SPF (`dig TXT domain | grep spf`), DKIM selector, and DMARC (`dig TXT _dmarc.domain`) records — a missing/`p=none` DMARC plus permissive SPF (`+all`/no SPF) is a phishing/spoofing finding, not an SMTP-server finding
- [ ] SPF lookup-limit exhaustion: count `include:`/`redirect=`/`a`/`mx`/`ptr`/`exists` mechanisms in the record — more than 10 DNS-lookup-causing terms triggers RFC 7208 `permerror`, which most receivers treat as a fail-open (SPF effectively not enforced); flag as a silent SPF bypass distinct from a missing record
- [ ] DKIM selector enumeration: common selectors (`default`, `selector1`/`selector2` for O365, `google`, `k1`, `mail`, `dkim`) via `dig TXT selector._domainkey.domain`; an absent DKIM record for the mail-sending infrastructure in use means DMARC alignment can only ever rely on SPF, narrowing the spoofing-defense surface
- [ ] DMARC policy strength beyond presence: distinguish `p=none` (monitor-only, no enforcement) from `p=quarantine`/`p=reject`, check `pct=` for partial rollout, and check `sp=` (subdomain policy) separately — a strict top-level policy with a missing/weak `sp=` leaves subdomain spoofing open
- [ ] BIMI record (`dig TXT default._bimi.domain`) — informational; a BIMI record without an enforced `p=reject` DMARC is inconsistent and sometimes indicates a half-completed anti-spoofing rollout worth noting
- [ ] Known CVEs: Exim CVE-2019-10149 ("Return of the WIZard" RCE), Postfix/Exim SMTP smuggling (CVE-2023-51764-class request splitting via inconsistent `<CR><LF>.<CR><LF>` handling)
- [ ] SMTP smuggling confirmation (bounded, single probe): send a message whose body contains a non-standard end-of-data sequence (e.g. `<LF>.<CR><LF>` or `<CR><LF>.<LF>` instead of the strict `<CR><LF>.<CR><LF>`) via `swaks --data` and observe whether the server terminates early — treat a successful smuggled-command injection as evidence only, never chain it into a real spoofed delivery to a third party
- [ ] Outbound relay chain fingerprinting: compare the banner/`Received:` header software on this host against the domain's SPF `include:`/MX records — a mismatch (e.g. SPF authorizes only a cloud provider's outbound relay but this host answers directly on 25) can indicate a shadow/legacy MTA that bypasses the documented mail path entirely

### DNS (53)
```bash
run_tool dig @HOST AXFR example.com          # zone transfer
run_tool dig @HOST version.bind CHAOS TXT    # version disclosure
run_tool nmap -sU -p 53 --script dns-zone-transfer,dns-recursion,dns-cache-snoop HOST
# recursion / cache snooping
run_tool dig @HOST google.com
```
A successful AXFR yields a full internal name map — feed domains into `intel.md` and requeue
HTTP recon for discovered names.

Additional DNS checks:
- [ ] DNSSEC validation status: `dig +dnssec @HOST domain` — a signed-but-unvalidated chain or missing DNSSEC on a sensitive zone is informational, not exploitable directly
- [ ] Cache snooping for internal hostnames without full recursion: `dig +norecurse @HOST internal-name.domain` reveals whether other clients have queried it
- [ ] Dangling/orphaned records: any CNAME pointing to a deprovisioned cloud resource (S3, Azure, Heroku, etc.) feeds `subdomain-takeover`; cross-check discovered names there
- [ ] Wildcard DNS misconfig: compare `dig @HOST random-nonexistent-label.domain` against a known-good record — an identical response indicates a wildcard that can mask subdomain enumeration false positives
- [ ] NXNSAttack / NS-record amplification exposure — note only if the resolver is authoritative and recursive on the same instance (rare, high-impact misconfig)
- [ ] Per-NS zone transfer variance: a domain often has multiple authoritative NS records — test AXFR against *each* NS individually (`dig @ns1.domain AXFR example.com`, `dig @ns2.domain AXFR example.com`); secondaries are frequently misconfigured to allow transfer even when the primary correctly restricts it
- [ ] IXFR (incremental transfer) as an AXFR-restriction bypass: `dig @HOST IXFR=<known-serial> example.com` — some servers restrict full AXFR but still answer incremental transfers, which can leak recent zone deltas including newly added internal names
- [ ] Subdomain-scoped zone probing when the root zone refuses transfer: attempt AXFR against any delegated subdomain with its own NS records (`dig NS sub.domain` then `dig @that-ns AXFR sub.domain`) — delegation boundaries are configured independently and are commonly missed

### IMAP / POP3 (110/143/993)
```bash
run_tool nc -nv HOST 143
run_tool nmap -p 110,143 --script imap-capabilities,pop3-capabilities HOST
# default creds bounded; cleartext protocols
```

## Confirm-Only Rule

One open-relay test message max. No mail bombing, no mass user enumeration beyond the
provided wordlist. Record enumerated users to `intel.md`.

## Budget

`--host-timeout 120s`. DNS brute force uses a fixed wordlist and `--max-retries 2`.
