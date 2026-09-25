---
name: tls-ssl-testing
description: Enumerate and test TLS protocols, ciphers, certificates, headers, ALPN, and certificate transparency
origin: RedteamOpencode
---

# TLS / SSL Testing

## When to Activate

- TLS on 443, 8443, 9443, or another web/API port; legacy SSL services on nonstandard ports
- Public certificates, HSTS, security headers, ALPN negotiation, or certificate-transparency exposure
- Need to assess downgrade, weak cryptography, chain, hostname, or client trust weaknesses

## Tools

`openssl s_client`, `run_tool nmap`, `run_tool testssl.sh`, `run_tool sslyze`, `run_tool sslscan`, `run_tool curl`, `run_tool nuclei`, `jq`

## Methodology

### 1. Establish the TLS Baseline

Always capture the handshake before using optional scanners. Save the certificate chain and server negotiation for comparison:

```bash
openssl s_client -connect host:443 -servername host -showcerts </dev/null > "$DIR/scans/tls_baseline.txt" 2>&1
run_tool nmap -sV -p 443,8443 HOST --script ssl-enum-ciphers,ssl-cert,ssl-known-key
run_tool testssl.sh --quiet HOST:443
run_tool sslyze --regular HOST:443
run_tool sslscan HOST:443
```

Run `testssl.sh`, `sslyze`, or `sslscan` only when present; keep one bounded pass per host and port.

### 2. Test Protocol Support and Downgrade

Check each legacy and modern protocol explicitly, including SSLv2, SSLv3, TLS1.0, and TLS1.1. Record accepted versions, alert behavior, and whether the endpoint silently falls back:

```bash
openssl s_client -connect HOST:443 -servername HOST -ssl2 </dev/null
openssl s_client -connect HOST:443 -servername HOST -ssl3 </dev/null
openssl s_client -connect HOST:443 -servername HOST -tls1 </dev/null
openssl s_client -connect HOST:443 -servername HOST -tls1_1 </dev/null
openssl s_client -connect HOST:443 -servername HOST -tls1_2 </dev/null
openssl s_client -connect HOST:443 -servername HOST -tls1_3 </dev/null
```

Protocol downgrade is a configuration weakness: SSLv3/TLS1.0/1.1 acceptance can enable POODLE, BEAST, or downgrade attacks; it is not evidence of RCE.

### 3. Review Ciphers and Key Exchange

Enumerate suites and assess key size, authentication, forward secrecy, compression, renegotiation, and export or static-RSA modes:

```bash
run_tool nmap -p 443 --script ssl-enum-ciphers,ssl-cert HOST
run_tool testssl.sh --each-cipher HOST:443
run_tool sslyze --cipher_scans HOST:443
run_tool sslscan --show-certificate HOST:443
```

Flag NULL, EXPORT, anonymous, DES/3DES, RC4, weak MAC, compression, static RSA, and non-forward-secret suites. State the operational impact—passive decryption or downgrade under a suitable attacker position—rather than claiming code execution.

### 4. Validate Certificate Identity and Chain

Inspect validity dates, issuer, key usage, signature algorithm, hostname match, SANs, and the served intermediate chain:

```bash
openssl s_client -connect HOST:443 -servername HOST -showcerts -status </dev/null
openssl s_client -connect HOST:443 -servername HOST -tls1_2 -brief </dev/null
```

Test for expired, self-signed, hostname-mismatched, and wrong-SAN certificates. A missing intermediate can make clients fail or prompt users to bypass warnings; compare the served chain with the expected issuer chain.

### 5. Check Renegotiation, OCSP Stapling, and ALPN

Read the status and extension output from the baseline. Confirm secure renegotiation support, stapled OCSP response, and negotiated ALPN values:

```bash
openssl s_client -connect HOST:443 -servername HOST -status </dev/null > "$DIR/scans/tls_status.txt" 2>&1
openssl s_client -connect HOST:443 -servername HOST -alpn h2,http/1.1 </dev/null > "$DIR/scans/tls_alpn.txt" 2>&1
```

Record weak renegotiation or absent OCSP stapling as certificate-availability and privacy weaknesses. ALPN mismatch can expose downgrade or protocol-handling defects even when the cipher is strong.

### 6. Audit HTTPS Redirects and Security Headers

Check the HTTPS response and the plain-HTTP path with bounded requests:

```bash
run_tool curl -sS -I --connect-timeout 5 --max-time 20 https://HOST/
run_tool curl -sS -I --connect-timeout 5 --max-time 20 http://HOST/
run_tool nuclei -u https://HOST -tags ssl,misconfig
```

Verify HTTP-to-HTTPS redirect, HSTS presence and max-age, CSP, `X-Content-Type-Options`, frame-ancestors, Referrer-Policy, and cookie `Secure` coverage. Missing HSTS enables a first-visit downgrade; missing headers increases browser attack surface but is not RCE by itself.

### 7. Review SAN Scope and Certificate Transparency

Compare certificate SANs with the approved host inventory and look for internal names, wildcard scope, or unrelated tenants:

```bash
openssl s_client -connect HOST:443 -servername HOST -showcerts </dev/null > "$DIR/scans/tls_san_chain.txt" 2>&1
run_tool curl -sS --connect-timeout 5 --max-time 20 "https://crt.sh/?q=%25.HOST&output=json" -o "$DIR/scans/tls_ct.json"
jq -r '[.[].name_value] | unique[]' "$DIR/scans/tls_ct.json" > "$DIR/scans/tls_ct_names.txt"
```

Treat Certificate Transparency log exposure as reconnaissance, not a vulnerability by itself. Report only names corroborated by scope and explain the operational impact of overbroad SANs or leaked naming relationships.

## References

`references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/api-security/API08-security-misconfiguration.md`.

## Confirm-Only Rule

Protocol, cipher, certificate, header, ALPN, SAN, and CT enumeration is confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; report configuration impact such as POODLE, downgrade, interception, or trust warnings, not RCE.

## Budget

`--host-timeout 120s`. One baseline handshake, one legacy-protocol matrix, and one scanner pass per endpoint; no cipher brute force, renegotiation flood, or denial-of-service testing.
