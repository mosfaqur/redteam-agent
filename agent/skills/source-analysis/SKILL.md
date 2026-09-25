---
name: source-analysis
description: Frontend source code analysis for hidden routes, API endpoints, and secrets
origin: RedteamOpencode
---

# Source Code Analysis

## When to Activate

- After recon identifies target's web pages and JS/CSS files
- SPA framework detected (React, Vue, Angular)
- Directory fuzzing sparse — source analysis reveals paths fuzzing misses
- GraphQL/REST API schema discovery needed

## Tools

`run_tool curl`, `grep`/`sed`/`awk`, `jq`

## Local Artifact Guardrails

When the task already provides a saved batch file or engagement workspace artifacts, prefer the local files over re-fetching remote content.

- Start from the saved batch file, then inspect only the directly linked local artifacts you actually need.
- For `page` batches, read the saved HTML/headers first, then only the specific JS/CSS files referenced by that page.
- If a saved case or adjacent crawl metadata shows a concrete in-scope asset returned successfully but the engagement-local body is missing or empty, do one bounded recovery fetch of that exact URL back into the engagement workspace before declaring the case unanalyzable.
- For concrete client-rendered page cases (`/#/...`, `#/...`, or other fragment routes preserved from bundle analysis), plain HTTP refetch of the same URL is not enough because it only replays the root document. Materialize those cases with `./scripts/katana_route_capture.sh "$DIR" "<exact-case-url>"` and inspect the saved route-capture artifact before marking the route exhausted. If the artifact only contains the exact-route seed error (for example `hybrid: response is nil`) or otherwise has zero successful response rows, treat that as failed materialization and requeue the route instead of closing it.
- If route materialization proves the exact client screen exists (for example a route-specific lazy chunk/module loads, a distinct form/panel renders, or the capture shows a concrete stored/render sink), do **not** close the route family just because no brand-new requestable HTTP endpoint appeared. Preserve the exact route as a live `dynamic_render`/`auth_entry` follow-up and name the concrete UI/render action that still needs to be exercised (for example an exact `./scripts/browser_flow.py --url ... --output-dir ... [--cookies-from-auth "$DIR/auth.json"]` step, plus a tiny `--steps-file` when a specific control/form is already evidenced). After route-capture has already proven the exact page exists and you have named that first concrete `browser_flow.py` step, the source-analysis page case itself is exhausted unless new source artifacts arrive that materially change the route evidence. Do **not** keep sending the same page case back through source-analysis just to wait for the first live route execution. That first bounded browser-flow pass belongs to exploit-developer or another live-route execution owner. If that exact route has already been materialized with route-capture and then covered once with bounded `browser_flow.py`, and the only remaining blocker is missing auth/credentials or a later exploit/surface step that is already preserved as a concrete surface record, do **not** keep requeueing the same source-analysis case just to wait. Mark the queue row exhausted and leave the unresolved work on the tracked `dynamic_render` / `auth_entry` / workflow surface instead; otherwise the dispatcher can starve on the same auth-gated route forever. If saved route-capture/browser-flow evidence already shows a successful write-capable workflow or submission (redirect, success snackbar/toast, confirmation dialog, created record, or another distinct post-submit state), that is still not terminal coverage: keep the exact route/workflow alive for exploit and name one bounded abuse replay on the same workflow (duplicate/second submission first, then one evidence-grounded empty/boundary/forged/unauthorized variant when it fits the visible controls or auth context). When the evidence gives you human-visible cues (button text, field labels, placeholders) but not stable selectors, say so explicitly and prefer text-based browser-flow steps such as `click_text`, `type_by_label`, `type_by_placeholder`, `select_by_label`, or `submit_first_form` in the follow-up you hand back. When a visible `<select>` / dropdown gate is the remaining blocker, keep the workflow alive with an explicit `select` or `select_by_label` step instead of treating the route as covered. If a bounded text-helper pass fails on a concrete modal/dialog/site-switch gate, inspect the saved DOM once for a stable selector/id/aria-label on the blocking control and hand back one selector-aware retry (`wait_for_selector` + `click` on that exact selector) before calling the route blocked or escalating to `runtime_error`.
- Keep recovery narrow: exact case URL first, then only directly manifest-linked sibling assets when the manifest/root HTML proves them. Do **not** broaden into fresh crawling, guessed version prefixes, or speculative path construction.
- Do **not** dump or `read` entire large/minified bundles into context. Use targeted searches with strict caps (`grep -n -m`, `sed -n`, `head`, `tail`, `jq`) and keep only the matched lines you need.
- If a JS/CSS bundle is large or minified, treat it like an index: extract concrete routes/endpoints/secrets with bounded regex passes instead of broad whole-file scans.
- When a saved manifest (`asset-manifest.json`, chunk map, preload map, SSR config) lists JS/CSS asset paths, preserve the manifest path exactly as written unless the file itself proves a different absolute base. Do **not** prepend nearby version directories, CDN prefixes, or guessed parent paths just because adjacent config exposes a `versionUrls` map.
- If a fetched `.js`/`.css`/`.json` artifact contains XML/HTML object-storage errors such as `NoSuchKey`, `AccessDenied`, or SPA fallback markup, treat that as a retrieval-path problem rather than real source content. Reconstruct follow-up URLs from the manifest/root HTML exactly, prefer relative-path joins over guessed version prefixes, and clearly mark stale placeholder artifacts as exhausted.
- Avoid the `file` utility in runtime containers; rely on headers, file extensions, `wc -c`, or tiny Python snippets if you need type/size hints.
- Stop after a few bounded passes per artifact and return concise structured results. Do not spend the whole task spelunking one huge bundle.

## Division of Labor

| Task | Agent |
|------|-------|
| Fetch pages, fingerprint, fuzz dirs | recon-specialist |
| Analyze HTML/JS/CSS for hidden content | source-analyzer |
| Fuzz discovered params | fuzzer |
| Test endpoints for vulns | vulnerability-analyst |

## Methodology

### 1. Identify Source Files
List `<script src>`, `<link stylesheet href>`, inline `<script>` blocks, source map refs.

### 2. HTML Analysis
Extract: href/src/action values, hidden fields, data-url/data-api attributes,
HTML comments, meta tags (canonical, CSRF, API base), inline config (`window.__CONFIG__`).

### 3. JavaScript Analysis
```bash
run_tool curl -sL <js-url> | grep -oE '["'"'"'](/[a-zA-Z0-9_/\-\.]+)["'"'"']' | sort -u
```
For saved local bundles, prefer bounded pattern extraction over full reads, for example:
```bash
grep -n -m 80 -E 'fetch\(|axios\.|XMLHttpRequest|\.open\(|/rest/|/api/|/#/' downloads/main.js
```
- API calls: `fetch()`, axios, XHR, `$.ajax` patterns
- SPA routes: React `path="/..."`, Vue `{ path: }`, Angular `{ path: }`
- Secrets: `api_key`, `token`, `secret`, `password` assignments; AWS `AKIA[A-Z0-9]{16}`; JWT `eyJ...`
- Webpack: chunk manifest, chunk URLs, `window.__INITIAL_STATE__`
- Extended secret patterns worth a dedicated grep pass (`grep -nEo` with these patterns, capped output):
  - AWS secret key: `(?i)aws(.{0,20})?secret[^'"]*['"][0-9a-zA-Z/+]{40}['"]`
  - GCP API key: `AIza[0-9A-Za-z\-_]{35}`
  - GCP service-account JSON marker: `"type":\s*"service_account"`
  - Azure connection string: `AccountKey=[A-Za-z0-9+/=]{80,}`
  - Slack token: `xox[baprs]-[0-9A-Za-z-]{10,}`
  - Stripe key: `sk_(live|test)_[0-9a-zA-Z]{24}`
  - GitHub token: `gh[pousr]_[A-Za-z0-9]{36,}`
  - Generic PEM private key header: `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`
  - Firebase config object: `apiKey["']?\s*:\s*["'][^"']+["']` near `authDomain`/`databaseURL`
  - Google Maps / generic third-party API keys embedded client-side (lower severity but still worth recording as `info-disclosure-testing` context)
- Environment-variable leakage: `process.env\.[A-Z_]+`, `import\.meta\.env\.[A-Z_]+` baked into a bundled build often embeds values that were meant to be build-time-only server secrets
- `localStorage.setItem/getItem` and `sessionStorage` key names — enumerate them to know what client-trusted state exists before testing IDOR/auth-bypass on the endpoints that read them
- Feature-flag / kill-switch objects (`featureFlags`, `__flags__`, `config.experiments`) — flipping a client-evaluated flag can unlock UI for admin/beta functionality even when the server never validates it
- When matches explode because of minified code, narrow the regex and rerun instead of accepting giant output
- Preserve concrete SPA/hash routes in your structured output. Do **not** collapse them into a generic note like “hidden routes found”. If the bundle reveals a real client-side route (for example a hidden page, admin panel, legal/policy view, review/feedback/cart/register flow, or sandbox screen), keep the exact route string and hand it back as a route/surface candidate.
- When a route is clearly client-rendered rather than a standalone server endpoint, emit it as a `dynamic_render` surface candidate (or `auth_entry` when it is clearly a login/register/auth screen) so surface coverage can materialize a bounded page visit later.
- If the bundle exposes many routes, prioritize breadth across distinct workflow families instead of spending the entire handoff on near-duplicate variants from one subtree. Keep the highest-signal concrete route for each actionable family you see (for example auth entry, privileged/admin, legal/policy/info, feedback/review/cart, sandbox/payment, hidden feature screens) before adding second-order variants from the same family.
- Within one workflow family, do **not** collapse materially different stages into a single representative when they could change the downstream attack plan. If the bundle clearly shows sibling routes for different stages/outcomes (for example login vs register vs forgot-password, browse/list vs submit/review, or end-user flow vs admin/manage), preserve at least one concrete route/surface for each distinct stage instead of treating one sibling as coverage for the rest.
- When source artifacts expose a reusable workflow primitive by itself (for example a captcha helper, reset/setup token flow, TOTP enrollment path, signed-action helper, or other temporary secret source), also preserve at least one concrete consumer workflow route/surface from that same family. Do not hand the primitive off alone if the adjacent route/workflow is visible in the same bundle or artifact set.
- A recovery/auth helper route is not a substitute for a registration/create flow, and a read-only browse route is not a substitute for a write/submit surface when both are concretely visible in the same artifact set.
- For local lab targets, do **not** mark discovered challenge-tracker / scoreboard / objective routes as merely informational. When the active profile (`lab-profile.json`) or the bundle reveals an objective/scoreboard route, preserve the exact route as a `dynamic_render` surface and requeue or hand off one bounded browser-flow visit before closing it. These routes often expose solved-state evidence even when they add no new API endpoint.
- When a saved artifact is a downloadable backup, vault, dump, config export, or encoded operational note, do not dismiss it just because the first pass found no plaintext. Preserve the concrete download path, verified file type, and a few candidate seed words from filenames or nearby usernames/emails/brand strings so later exploit work can run a bounded offline triage/cracking step.

### 4. CSS Analysis
Extract `url()` refs, `@import` paths, source map refs.

### 5. API Schema Discovery
Probe: /swagger.json, /openapi.json, /api-docs, /graphql (introspection), /application.wadl

If an OpenAPI / Swagger spec is accessible, ingest it into the queue instead of leaving it as
a passive note:

```bash
run_tool curl -sL "https://TARGET/openapi.json" -o $DIR/scans/openapi.json
./scripts/spec_ingest.sh "$ENGAGEMENT_DIR/cases.db" "$ENGAGEMENT_DIR/scans/openapi.json"
./scripts/dispatcher.sh "$ENGAGEMENT_DIR/cases.db" stats
```

This creates `api-spec` cases that should stay with `source-analyzer` long enough to resolve docs/spec carriers into concrete API cases for `vulnerability-analyst`.

### 6. Source Map Analysis
Fetch `.map` only when there is an explicit source map reference or saved map artifact. Do not brute-force nonexistent maps.

When a map exists, extract just the `sources` array and the specific source files needed for the case at hand instead of dumping the whole map.

If the map is a full `.js.map` (not just a `//# sourceMappingURL` reference), the `sourcesContent`
field often embeds the ENTIRE pre-bundled original source tree in plaintext — this is a far
higher-value target than the minified bundle itself:

```bash
jq -r '.sourcesContent // empty | .[]' "$DIR/scans/app.js.map" 2>/dev/null | head -c 200000 > "$DIR/scans/reconstructed_sources.txt"
jq -r '.sources[]' "$DIR/scans/app.js.map" 2>/dev/null   # original file paths — often reveal internal project/module naming
grep -nE 'api_key|secret|password|TODO|FIXME|XXX|internal|debug' "$DIR/scans/reconstructed_sources.txt" | head -50
```
A leaked `sourcesContent` array is itself a finding (full original source disclosure) independent of anything found inside it.

### 7. WASM, Service Workers, and Non-JS Client Assets

- WebAssembly modules (`.wasm`) can embed business logic (pricing, licensing, anti-cheat, crypto)
  that's otherwise server-side elsewhere — `strings <file>.wasm | grep -iE 'key|secret|url|admin'`
  and note the module for `binary-artifact-analysis` if deeper reversing is warranted.
- Service workers (`sw.js`, `service-worker.js`) intercept and cache requests; read their
  `fetch` handler and `caches.open()` calls — a cached response containing auth tokens or PII
  persists client-side even after logout if the SW doesn't clear it.
- Web App Manifest (`manifest.json`) and `.well-known/assetlinks.json`/`apple-app-site-association`
  reveal linked native app package/bundle IDs — pivot into `mobile-app-testing` if a companion
  app exists.
- GraphQL clients often ship a persisted-query manifest (`persisted-queries.json` or a hash map in
  the bundle) — extracting the full query text from a hash-keyed persisted query can reveal fields
  a live introspection probe would otherwise have blocked; hand full extracted queries to `graphql-testing`.

### 8. Webpack Chunk & Module-Federation Enumeration

Lazy-loaded routes/features often live in chunks never referenced by the initially-loaded
bundle — the chunk map itself is a route/feature index:

```bash
grep -noE '\{[0-9]+:"[a-f0-9]{8,20}"' downloads/main.js | head -50          # webpack chunk-id -> hash map
grep -noE '__webpack_require__\.e\("?[0-9a-zA-Z_-]+"?\)' downloads/main.js | sort -u  # dynamic import triggers
grep -noE 'remoteEntry\.js|exposes\s*:\s*\{[^}]*\}' downloads/main.js       # Module Federation remotes — each exposed module is a separately loadable surface
```
Each distinct chunk hash resolves to `/<path>/<chunkid>.<hash>.chunk.js` (or `.js` depending on
output config) — fetch chunks referenced by feature-sounding names (`admin`, `settings`,
`billing`) before generic numeric ones; low-value numeric/vendor chunks are pruned by the
operator's `prune_vendor_cases.py` step downstream, so don't hand-filter them here.

### 9. Parameter & Route Mining for Downstream Fuzzing

Source analysis is the highest-signal source of real parameter names for `parameter-fuzzing` —
don't just note "API calls found," extract the actual argument/field names:

```bash
grep -noE '(fetch|axios\.\w+)\([^)]*\)' downloads/main.js | grep -oE '[?&][a-zA-Z_][a-zA-Z0-9_]*=' | sed 's/[?&]//;s/=//' | sort -u
grep -noE '(body|params|data)\s*:\s*\{[^}]{0,300}\}' downloads/main.js | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*(?=\s*:)' | sort -u
```
Hand the resulting name list to `parameter-fuzzing` as a JS-mined wordlist rather than leaving
it embedded only in prose notes — a concrete file the fuzzer can `-w` directly is higher value
than a paraphrase in the handoff.

## Priority Order

1. Secrets and tokens (immediate high-value)
2. API endpoints not found by fuzzing
3. Frontend routes revealing app structure
4. Hidden form fields and debug endpoints
5. Source maps and debug artifacts
