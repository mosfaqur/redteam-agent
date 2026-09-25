---
name: voip-sip-testing
description: Enumerate and safely test SIP signaling, registration, routing, and RTP media services
origin: RedteamOpencode
---

# VoIP / SIP Testing

## When to Activate

- SIP over UDP or TCP on 5060, SIP over TLS on 5061, or adjacent RTP/SRTP media
- A signaling service needs transport, account, authorization, media, or certificate review
- A lab destination is in scope and testing must avoid real calls or toll fraud

## Tools

`run_tool nmap`, `run_tool sipp`, `run_tool nc`, `run_tool searchsploit`, `tcpdump`, `openssl`, `jq`, `python3`, `awk`, `sed`, `printf`

## Methodology

### 1. Discover and Fingerprint Signaling

Probe UDP, TCP, and TLS separately. Save raw output under `$DIR/scans/`; use one OPTIONS request per reachable transport and record status, headers, methods, realm, and transport hints.

```bash
mkdir -p "$DIR/scans"
timeout 120s run_tool nmap -sU -sV -p 5060,5061 --script sip-invite,sip-reg,sip-user-enum HOST --host-timeout 90s --max-retries 1 > "$DIR/scans/sip_nmap.txt" 2>&1 # fingerprint
timeout 90s run_tool nmap -sT -sV -p 5060,5061 HOST --host-timeout 60s --max-retries 1 > "$DIR/scans/sip_tcp_tls_ports.txt" 2>&1 # transport
printf '%s\r\n' 'OPTIONS sip:user@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-options' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:user@HOST>' 'Call-ID: options@HOST' 'CSeq: 1 OPTIONS' 'Max-Forwards: 70' 'Content-Length: 0' '' '' > "$DIR/scans/sip_options.sip"
if command -v sipp >/dev/null 2>&1; then
  timeout 20s run_tool sipp -sf "$DIR/scans/sip_options.sip" -m 1 -r 1 -rp 1 -t 1 -l 1 HOST:PORT > "$DIR/scans/sip_options_response.txt" 2>&1
else
  timeout 15s run_tool nc -u -w 5 HOST PORT < "$DIR/scans/sip_options.sip" > "$DIR/scans/sip_options_response.txt" 2>&1
fi # OPTIONS
```

Record `User-Agent`/`Server`, `Allow`/`Supported`, realm or domain, `Via`, `Contact`, and transport lists. A 401/407 challenge is evidence of authentication, not successful fingerprinting.

### 2. Enumerate Extensions and Accounts

Use at most 20 identifiers, all justified by the lab scope. Compare reproducible status and header differences: no such user, user not registered, password required, or success.

```bash
for ID in user user2 user3 user4 user5 user6 user7 user8 user9 user10 user11 user12 user13 user14 user15 user16 user17 user18 user19 user20; do
  printf 'INVITE sip:%s@HOST SIP/2.0\r\nVia: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-%s\r\nFrom: <sip:%s@HOST>;tag=probe\r\nTo: <sip:%s@HOST>\r\nCall-ID: %s@HOST\r\nCSeq: 1 INVITE\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n' "$ID" "$ID" "$ID" "$ID" "$ID" | timeout 10s run_tool nc -u -w 5 HOST PORT
  printf '\n'
done > "$DIR/scans/sip_account_probe.txt" 2>&1 # bounded INVITE sweep
sed -n '1,260p' "$DIR/scans/sip_account_probe.txt" | awk '/^(SIP\/2.0|Warning:|Reason:|WWW-Authenticate:|Allow:|Supported:|Server:|User-Agent:)/'
```

Treat 404-style user errors, 401/407 challenges, and 200/202 acceptance separately; do not report enumeration without the same differential on a repeat.

### 3. Test Registration and Digest Authentication

For one authorized account, cap testing at two REGISTER messages. The first checks unauthenticated acceptance and the challenge; the second changes the Contact/Via binding and uses the returned nonce once.

```bash
printf '%s\r\n' 'REGISTER sip:user@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-register-1' 'From: <sip:user@HOST>;tag=register-1' 'To: <sip:user@HOST>' 'Call-ID: register-1@HOST' 'CSeq: 1 REGISTER' 'Contact: <sip:user@HOST>' 'Expires: 60' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 10s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_register_1.txt" 2>&1
NONCE=$(sed -n 's/.*nonce="\([^"]*\)".*/\1/p' "$DIR/scans/sip_register_1.txt" | sed -n '1p')
printf 'REGISTER sip:user@HOST SIP/2.0\r\nVia: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-register-2\r\nFrom: <sip:user@HOST>;tag=register-2\r\nTo: <sip:user@HOST>\r\nCall-ID: register-2@HOST\r\nCSeq: 1 REGISTER\r\nContact: <sip:user@HOST:PORT;transport=udp>\r\nExpires: 60\r\nMax-Forwards: 0\r\nAuthorization: Digest username="user", realm="example.com", nonce="%s", algorithm=MD5, qop=auth, cnonce="probe", response="00000000000000000000000000000000"\r\nContent-Length: 0\r\n\r\n' "$NONCE" | timeout 10s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_register_2.txt" 2>&1 # REGISTER cap
sed -n '1,240p' "$DIR/scans/sip_register_1.txt" "$DIR/scans/sip_register_2.txt" | awk '/^(SIP\/2.0|WWW-Authenticate:|Contact:|Via:|Warning:|Reason:|nonce|algorithm|cnonce|stale)/'
```

Do not add a third REGISTER for that account. Record whether nonce/cnonce are static or replayable, whether MD5 is advertised without staleness enforcement, and whether a second client overwrites the first Contact or ignores Via/branch binding.

### 4. Check Authorization and Routing

Test unauthenticated OPTIONS, INVITE, and SUBSCRIBE, plus an internal extension and a number outside the assigned plan. Use only an in-scope lab alias or reserved test number such as `5550100`; never use premium or international destinations, and never place a real call.

```bash
printf '%s\r\n' 'OPTIONS sip:user@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-auth-options' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:user@HOST>' 'Call-ID: auth-options@HOST' 'CSeq: 1 OPTIONS' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 10s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_auth_options.txt" 2>&1
printf '%s\r\n' 'INVITE sip:user@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-internal' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:user@HOST>' 'Call-ID: internal-invite@HOST' 'CSeq: 1 INVITE' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 10s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_internal_invite.txt" 2>&1
printf '%s\r\n' 'INVITE sip:5550100@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-dial' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:5550100@HOST>' 'Call-ID: dial-plan@HOST' 'CSeq: 1 INVITE' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 10s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_dial_plan.txt" 2>&1
printf '%s\r\n' 'SUBSCRIBE sip:user@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-presence' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:user@HOST>' 'Call-ID: presence@HOST' 'CSeq: 1 SUBSCRIBE' 'Event: presence' 'Expires: 0' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 10s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_presence.txt" 2>&1 # authorization probes
awk '/^(SIP\/2.0|Warning:|Reason:|Call-Info:|P-Asserted-Identity:|Remote-Party-ID:|P-Charging-)/' "$DIR/scans/sip_auth_options.txt" "$DIR/scans/sip_internal_invite.txt" "$DIR/scans/sip_dial_plan.txt" "$DIR/scans/sip_presence.txt"
```

Inspect any NOTIFY, routing decision, presence data, `Reason`, `Call-Info`, identity, or CDR/charging header for disclosure. A route response is evidence only for an in-scope lab destination or reserved test range.

### 5. Review RTP, SRTP, and DTMF Exposure

From one controlled lab call, inspect the SDP for the advertised audio port, `rtpmap`, `crypto`, and DTMF payloads. Make one bounded UDP port pass and one short capture; do not flood or keep a call open.

```bash
timeout 90s run_tool nmap -sU -sV -p 10000-10100 --host-timeout 60s --max-retries 1 HOST > "$DIR/scans/sip_rtp_ports.txt" 2>&1 # advertised media
timeout 12s tcpdump -ni any -c 8 -G 6 'udp and (portrange 10000-10100 or portrange 16384-32767)' -w "$DIR/scans/sip_rtp.pcap" 2> "$DIR/scans/sip_rtp_capture.txt"
awk '/^m=audio/ {s=1} s && /^a=(rtpmap|crypto|fmtp|rtcp)/ {print} /^m=video/ {s=0}' "$DIR/scans/sip_internal_invite.txt" > "$DIR/scans/sip_sdp_media.txt"
```

An open RTP port plus absent SRTP crypto is cleartext media evidence; `application/dtmf-relay` or `telephone-event` and exposed SIP INFO expose signaling. Confirm the result from the one capture, not from port guessing.

### 6. Test SIP over TLS and Certificates

Set `PORT` to the TLS listener. Capture the chain, verify hostname and dates, test a plaintext SIP message, and compare a client handshake with no client certificate.

```bash
timeout 15s openssl s_client -connect HOST:PORT -servername HOST -showcerts -status -verify_hostname HOST -verify_return_error </dev/null > "$DIR/scans/sip_tls_handshake.txt" 2>&1
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$DIR/scans/sip_tls_handshake.txt" | openssl x509 -out "$DIR/scans/sip_cert.pem"
openssl x509 -in "$DIR/scans/sip_cert.pem" -noout -subject -issuer -dates -fingerprint -sha256 > "$DIR/scans/sip_cert_summary.txt"
timeout 15s openssl s_client -connect HOST:PORT -servername HOST -brief </dev/null > "$DIR/scans/sip_tls_no_client_cert.txt" 2>&1 # client cert check
printf '%s\r\n' 'OPTIONS sip:user@HOST SIP/2.0' 'Via: SIP/2.0/TLS HOST:PORT;branch=z9hG4bK-plaintext' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:user@HOST>' 'Call-ID: plaintext-tls@HOST' 'CSeq: 1 OPTIONS' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 10s run_tool nc -w 5 HOST PORT > "$DIR/scans/sip_plaintext_tls.txt" 2>&1
awk '/(Verify return code|Verification error|CertificateRequest|Acceptable client certificate|handshake failure|Cipher|Protocol|CONNECTED|closed|reset|SIP\/2.0)/' "$DIR/scans/sip_tls_handshake.txt" "$DIR/scans/sip_tls_no_client_cert.txt" "$DIR/scans/sip_plaintext_tls.txt"
```

A valid chain and matching hostname are required; a successful no-client-certificate handshake only clears transport-level client authentication, not SIP digest authorization.

### 7. Map Known Vulnerabilities and Confirm Once

Set `PRODUCT` and `VERSION` from the generic fingerprint, map them locally, then run the SIP NSE family. Select at most one matched, non-destructive check and retain its response; do not execute an exploit.

```bash
run_tool searchsploit "$PRODUCT" "$VERSION" | sed -n '1,120p' > "$DIR/scans/sip_cve_matches.txt"
timeout 90s run_tool nmap --script sip-* -p PORT --host-timeout 60s --max-retries 1 HOST > "$DIR/scans/sip_nse.txt" 2>&1 # version mapping
printf '%s\r\n' 'OPTIONS sip:user@HOST SIP/2.0' 'Via: SIP/2.0/UDP HOST:PORT;branch=z9hG4bK-cve-check' 'From: <sip:user@HOST>;tag=probe' 'To: <sip:user@HOST>' 'Call-ID: cve-check@HOST' 'CSeq: 1 OPTIONS' 'Max-Forwards: 0' 'Content-Length: 0' '' '' | timeout 15s run_tool nc -u -w 5 HOST PORT > "$DIR/scans/sip_cve_check.txt" 2>&1
```

Report a CVE only when the single check reproduces the affected behavior; otherwise record it as an unconfirmed version match.

### 8. Apply Safety Rules and Report

No toll fraud, no DoS, no REGISTER floods, no INVITE storms, no malformed-packet fuzzing, and no social-engineering calls. Keep requests, responses, status, and scope notes under `$DIR/scans/`.

```bash
printf '%s\n' 'No toll fraud; no DoS; no REGISTER floods; no INVITE storms; no malformed-packet fuzzing; no social-engineering calls.' > "$DIR/scans/sip_safety_checklist.txt"
awk '/^(OPTIONS|REGISTER|INVITE|SUBSCRIBE|SIP\/2.0|User-Agent:|Server:|Warning:|Reason:)/' "$DIR/scans/sip_options_response.txt" "$DIR/scans/sip_account_probe.txt" "$DIR/scans/sip_register_1.txt" "$DIR/scans/sip_register_2.txt" > "$DIR/scans/sip_evidence_index.txt"
```

A finding needs a reproducible request/response pair and a stated impact: unauthenticated call routing, account takeover, cleartext signaling, or media eavesdropping. Enumeration alone is not account takeover.

## References

`references/vuln-checklists/A02-security-misconfiguration.md`, `references/vuln-checklists/A04-cryptographic-failures.md`, `references/vuln-checklists/A07-authentication-failures.md`, `references/vuln-checklists/A10-exceptional-conditions.md`, `references/tools/recon/nmap.md`.

## Confirm-Only Rule

Enumeration, registration, routing, media, TLS, and version mapping are confirm-stage. Stop after one reproducible request/response pair proves a safe impact; do not claim account takeover, toll fraud, or media interception without evidence.

## Budget

At most 35 SIP messages per host and 10 minutes wall-clock, including the bounded script pass; no unbounded loops or flooding.
