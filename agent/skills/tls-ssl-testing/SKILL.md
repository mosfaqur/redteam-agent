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

### 8. Named CVE Probes and Cross-Protocol Attacks

Check for specific historically high-impact TLS implementation flaws rather than only generic weak-cipher findings:

```bash
run_tool nmap -p 443 --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params HOST
run_tool testssl.sh --heartbleed --robot --ccs-injection --drown HOST:443
```

- **Heartbleed (CVE-2014-0160)** — memory-disclosure via malformed heartbeat; confirm with the nmap/testssl script only, do not repeatedly extract memory
- **DROWN (CVE-2016-0800)** — cross-protocol break via any SSLv2-enabled service sharing the same private key (even on a different port); check every service on the host for SSLv2, not just the TLS port under test
- **Logjam / weak DH (CVE-2015-4000)** — export-grade or <1024-bit DH parameters; `ssl-dh-params` script or `testssl.sh -f`
- **FREAK (CVE-2015-0204)** — export-grade RSA cipher suite acceptance
- **Sweet32 (CVE-2016-2183)** — 64-bit block cipher (3DES/Blowfish) birthday-bound exposure on long-lived connections
- **ROBOT** — Bleichenbacher PKCS#1 v1.5 padding-oracle variant against RSA key exchange; `testssl.sh --robot`
- **ALPACA (cross-protocol confusion)** — a TLS cert valid for both an HTTP host and a non-HTTP service (SMTP/FTP/IMAP with STARTTLS) on the same infrastructure enables request smuggling across protocols; check certificate SAN overlap between the web host and any mail/FTP service found via `mail-dns-services`/`remote-access-services`

### 9. mTLS / Client-Certificate and Session Resumption

- [ ] If the endpoint requests a client certificate, confirm whether the connection still completes without one (misconfigured "optional" mTLS that should be mandatory)
- [ ] Session ticket / session ID resumption: check ticket key rotation cadence — a static/long-lived session ticket key undermines forward secrecy even with a strong cipher suite (`openssl s_client -reconnect`)
- [ ] SNI-based virtual host confusion: request the TLS handshake with one SNI value then send an HTTP `Host:` header for a different hostname — a mismatch that still routes successfully can expose a co-hosted tenant's content

### 10. Downgrade Signaling, Pinning Bypass Indicators, and TLS 1.3 Early Data

Check the anti-downgrade signal itself, not just which protocols are accepted, and probe ALPN/SNI as routing-confusion vectors rather than only negotiation:

```bash
openssl s_client -connect HOST:443 -servername HOST -tls1_1 -fallback_scsv </dev/null > "$DIR/scans/tls_fallback_scsv.txt" 2>&1
openssl s_client -connect HOST:443 -servername HOST -alpn h2 </dev/null > "$DIR/scans/tls_alpn_h2.txt" 2>&1
openssl s_client -connect HOST:443 -servername wrong-host.example </dev/null -alpn http/1.1 > "$DIR/scans/tls_sni_mismatch.txt" 2>&1
openssl s_client -connect HOST:443 -servername HOST -tls1_3 -early_data "$DIR/scans/tls_0rtt_probe.txt" </dev/null > "$DIR/scans/tls_0rtt.txt" 2>&1
```

- **TLS_FALLBACK_SCSV absence** — connect with `-fallback_scsv` at a lower protocol version; a server that does not recognize the SCSV signal and simply accepts the downgraded connection anyway confirms no anti-downgrade defense, distinct from just "TLS1.0/1.1 is enabled."
- **Certificate-pinning bypass indicators** — this is reconnaissance for a mobile/API client's pin set, not a server misconfiguration: note whether the server presents a leaf cert signed by a *different* intermediate/root than the one the client app likely pins to (cross-signed CAs, recently rotated intermediates), since a pin built against the old chain silently breaks or gets bypassed via a permissive TrustManager; report the chain-identity mismatch, do not attempt to defeat client-side pinning here.
- **ALPN/SNI-based routing confusion** — request one SNI value while checking which backend/vhost actually answers (paired with the SNI/Host mismatch check in step 9); separately, request an ALPN protocol list that a frontend proxy interprets differently than the backend (e.g. proxy strips `h2` but backend still expects HTTP/2 framing) — a routing disagreement here can expose a co-hosted tenant or trigger request-smuggling-adjacent behavior at the TLS-terminating layer.
- **TLS 1.3 0-RTT / early-data replay** — if the server advertises `early_data` support, note it as a replay-risk surface: early-data requests are not inherently protected against replay by the TLS layer alone, and any application processing 0-RTT requests as if they were guaranteed-fresh (e.g. non-idempotent actions) is a design weakness worth flagging, not a TLS implementation bug. Confirm advertisement only; do not attempt a real replay against application logic here.

## References

`references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A02-security-misconfiguration.md`, `references/api-security/API08-security-misconfiguration.md`.

## Confirm-Only Rule

Protocol, cipher, certificate, header, ALPN, SAN, and CT enumeration is confirm-stage. Exploitation is owned by exploit-developer at stage=vuln_confirmed; report configuration impact such as POODLE, downgrade, interception, or trust warnings, not RCE.

## Budget

`--host-timeout 120s`. One baseline handshake, one legacy-protocol matrix, and one scanner pass per endpoint; no cipher brute force, renegotiation flood, or denial-of-service testing.
