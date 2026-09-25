---
name: request-smuggling
description: HTTP request smuggling via CL.TE/TE.CL desync and cache poisoning
origin: RedteamOpencode
---

# HTTP Request Smuggling Testing

## When to Activate

- Application behind reverse proxy, load balancer, or CDN
- Multiple HTTP servers in request processing chain
- HTTP/1.1 in use between frontend and backend

## Tools

- `run_tool curl` (raw request crafting)
- Burp Suite Repeater (disable auto content-length update)
- smuggler.py (automated detection)
- HTTP Request Smuggler (Burp extension)
- Custom scripts for precise byte-level control

## Methodology

### 1. Identify Architecture

- [ ] Determine if frontend proxy exists (CDN, load balancer, WAF)
- [ ] Check HTTP version between client→frontend and frontend→backend
- [ ] Identify server software from headers (nginx, Apache, HAProxy, Cloudflare)
- [ ] Note: HTTP/2 downgraded to HTTP/1.1 internally = also vulnerable

### 2. CL.TE Detection (Frontend uses Content-Length, Backend uses Transfer-Encoding)

- [ ] Send request with both CL and TE headers:
      ```
      POST / HTTP/1.1
      Host: target.com
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G
      ```
- [ ] If next request gets `GPOST` → CL.TE confirmed
- [ ] Time-based: backend waits for more chunked data → timeout difference

### 3. TE.CL Detection (Frontend uses Transfer-Encoding, Backend uses Content-Length)

- [ ] Send:
      ```
      POST / HTTP/1.1
      Host: target.com
      Content-Length: 3
      Transfer-Encoding: chunked

      1
      G
      0

      ```
- [ ] If next request returns unexpected response → TE.CL confirmed
- [ ] Time-based: backend reads CL bytes only, rest poisons next request

### 4. Transfer-Encoding Obfuscation

- [ ] `Transfer-Encoding: chunked` (standard)
- [ ] `Transfer-Encoding : chunked` (space before colon)
- [ ] `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
- [ ] `Transfer-Encoding: x\r\nTransfer-Encoding: chunked`
- [ ] `Transfer-Encoding:\tchunked` (tab)
- [ ] `Transfer-Encoding: chunked` (extra space)
- [ ] `X: x\r\nTransfer-Encoding: chunked` (header injection)
- [ ] Mixed case: `TrAnSfEr-EnCoDiNg: chunked`
- [ ] Line folding: `Transfer-Encoding:\n chunked`

### 5. Exploitation — Access Control Bypass

- [ ] Smuggle request to internal-only endpoint
- [ ] Access `/admin` path that frontend blocks
- [ ] Bypass IP-based restrictions by smuggling past frontend

### 6. Exploitation — Web Cache Poisoning

- [ ] Smuggle request that poisons cached response
- [ ] Victim receives attacker-controlled content from cache
- [ ] Inject malicious JavaScript via poisoned response

### 7. Exploitation — Credential Theft

- [ ] Smuggle partial request that captures next user's request:
      ```
      POST /store-comment HTTP/1.1
      Content-Length: 400

      comment=
      ```
- [ ] Next user's request (with cookies/auth) appended to comment body
- [ ] Read stolen headers from stored location

### 8. HTTP/2 Specific

- [ ] H2.CL smuggling: HTTP/2 with Content-Length to HTTP/1.1 backend
- [ ] H2.TE smuggling: inject Transfer-Encoding in HTTP/2
- [ ] Request splitting via header injection in HTTP/2 pseudo-headers
- [ ] CRLF injection in HTTP/2 header values

### 8b. CL.0 and 0.CL Variants

- [ ] **CL.0**: frontend forwards `Content-Length` but the backend (often an origin that treats certain endpoints/status paths as bodyless, e.g. after a redirect handler) ignores it and treats the connection as request-terminated at 0 bytes — the leftover body bytes become the start of the next smuggled request. Confirm by sending a body after a normally-bodyless-response endpoint and checking if it desyncs the next request.
- [ ] **0.CL / TE.0**: mirror case where the frontend ignores a header the backend honors. Test each direction independently — smuggling is asymmetric per proxy pair.

### 8c. Client-Side Desync (CSD) — No Intermediary Required

When there is no shared frontend/backend pair to desync (single server, or CDN normalizes CL/TE cleanly), test whether the *browser itself* can be tricked into desyncing its own connection reuse:
- [ ] Find an endpoint that responds to a POST with a redirect or a response the browser treats as if the body wasn't fully consumed (mismatched declared vs. actual body length from the server's own bug)
- [ ] Victim's subsequent same-origin request over the reused TCP/TLS connection gets prefixed with attacker-chosen bytes — leads to client-side request smuggling / cross-user cache poisoning without needing a second hop
- [ ] Primarily relevant when `exploit-developer` is chaining this into a same-origin XSS or session-fixation PoC; note it as a candidate rather than fully proving it in triage

### 8d. Expect-Based and Pipelining Desync

- [ ] `Expect: 100-continue` handling differential: some backends buffer and wait for the body before validating headers, others validate first — send a request with `Expect: 100-continue` plus a smuggled body prefix and observe whether the 100-response is followed inconsistently between frontend/backend
- [ ] HTTP/1.0 pipelining assumptions: if a backend silently reuses a connection expecting HTTP/1.1 semantics while receiving HTTP/1.0-declared requests, connection-reuse mismatches can desync without any CL/TE ambiguity at all

### 9. Validation

- [ ] Confirm desync with timing differential (10+ second difference)
- [ ] Use unique identifiers to track smuggled requests
- [ ] Test multiple times — smuggling can affect other users
- [ ] Be cautious: smuggling is disruptive in shared environments

## What to Record

- Frontend/backend architecture
- Smuggling type: CL.TE, TE.CL, H2.CL, or H2.TE
- Exact request bytes used for detection
- TE obfuscation technique that worked
- Exploitation achieved (access bypass, cache poison, credential theft)
- Severity: Critical (credential theft, cache poisoning) or High (access bypass)
- Remediation: normalize CL/TE handling, use HTTP/2 end-to-end, reject ambiguous requests
