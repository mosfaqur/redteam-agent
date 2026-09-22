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
