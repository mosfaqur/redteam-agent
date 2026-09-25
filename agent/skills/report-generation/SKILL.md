---
name: report-generation
description: Engagement report structure and formatting guidelines
origin: RedteamOpencode
---

# Report Generation

## When to Activate

- Engagement complete and findings collected, user invokes `/report`
- User requests summary, deliverable, or final output

## Severity Definitions

| Severity | Criteria |
|----------|----------|
| **HIGH** | Direct CIA impact, exploitable with minimal effort. Data breach, RCE, auth bypass. CVSS 7.0-10.0. |
| **MEDIUM** | Requires conditions or chaining. Stored XSS, IDOR on non-critical data, limited SQLi. CVSS 4.0-6.9. |
| **LOW** | Limited impact or hard to exploit. Reflected XSS, verbose errors, missing headers. CVSS 0.1-3.9. |
| **INFO** | No direct security impact. Observations, best-practice deviations, tech disclosures. CVSS 0.0. |

Include the full CVSS v3.1 vector string alongside the score (e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`), not just the number — it lets a reader independently verify the rating and is required by most client intake pipelines. When a finding's real-world exploitability differs from its base score (e.g. requires an unlikely user-interaction chain, or is trivially wormable beyond what the vector implies), note that explicitly rather than silently adjusting the score.

## Audience-Specific Structuring

The same finding set serves two readers with different decision needs; do not write one narrative and hope it works for both.

- **Executive audience (Executive Summary, cover narrative):** lead with business impact and decision-relevance, not technical mechanism. State what data/system is at risk, in what quantity, and what it would take a real attacker (skill level, access required, time) — not the CWE/CVSS vector. Compare posture to a prior engagement or industry baseline when data exists ("HIGH-severity count down from 6 to 2 since last quarter"). Every sentence should answer "so what should the reader decide or fund," not "what did the tester technically do." No payloads, no stack traces, no tool names in this section.
- **Technical audience (Findings, Appendix):** lead with mechanism and reproducibility. Full request/response pairs, exact parameter names, exact payloads, CWE/CVSS vector strings, and code-level remediation guidance belong here, not in the executive summary. Assume the reader can reproduce the issue from the evidence alone without asking the tester follow-up questions.
- **Bridging the two:** the Attack Path Narrative section is written for a technical-management hybrid reader (security lead, engineering manager) — it should read as a story (what an attacker does, step by step) while still citing exact finding IDs, so it works as the connective tissue between the two other sections without duplicating either one's level of detail.
- Never let executive-summary language leak business-impact claims that aren't backed by a finding in the body (no "could lead to full compromise" unless a specific finding chain demonstrates it) — the technical section is the source of truth the executive section summarizes, never the reverse.

## CVSS Scoring Edge Cases

- **Scope change (S:C):** when a vulnerability in one security-authority component impacts resources beyond its own scope (e.g. a container-escape bug, or a web app vuln that reaches the underlying host), set `S:C` and score Confidentiality/Integrity/Availability against the *impacted* component, not the vulnerable one — this is the most commonly mis-scored vector element.
- **Chained/multi-step findings:** score each individual finding on its own standalone reachability and impact (do not inflate a low-impact IDOR's own CVSS just because it chains into something worse) — the chain's combined impact belongs in the Attack Path Narrative, not in an inflated individual CVSS score. Cross-reference instead of double-counting.
- **Authentication-gated findings:** `PR:N` vs `PR:L` vs `PR:H` should reflect the *minimum* privilege actually required in testing, not the privilege level the tester happened to hold — if a HIGH-privilege test account confirmed the bug but it's also reachable pre-auth, that's `PR:N` and materially changes the score; always retest at the lowest plausible privilege before finalizing the vector.
- **User-interaction requirement (UI:N vs UI:R):** a CSRF or stored-XSS finding that requires a victim to click a link or view a page is `UI:R`, not `UI:N` — do not silently drop this to inflate severity; instead use the exploitability note (see Severity Definitions) to flag if the interaction is trivially achievable (e.g. auto-triggered stored payload viewed by every admin on page load approaches `UI:N` in practice despite the formal vector).
- **Temporal/environmental adjustments:** when a finding sits behind a compensating control the client already has in place (WAF rule, network segmentation, MFA on the affected account) that measurably reduces real-world exploitability but wasn't part of the vulnerable component itself, note it as a temporal/environmental modifier in prose rather than silently lowering the base score — the base score should always reflect the vulnerability in isolation; compensating-control context belongs in the Impact or a dedicated note.
- **Availability-only findings (DoS):** resist defaulting these to LOW — an unauthenticated, trivially-repeatable resource-exhaustion bug against a revenue-critical endpoint can legitimately reach HIGH (`A:H` with low `AC`/no `PR`) even with `C:N/I:N`; score on exploitability and business criticality of the affected component, not a reflexive "DoS is always minor" heuristic.

## Writing Style

Factual, evidence-based. No speculation — state conditions if impact is theoretical.
Quantify where possible. No hyperbole or marketing language.

## Evidence Quality Standards

- **Reproducibility is mandatory**: every finding's evidence must contain enough detail (exact request, exact parameter, exact payload) that a third party can reproduce it without re-deriving the attack. "SQLi found in search" is not evidence; the full request/response pair is.
- **Minimal PoC principle**: demonstrate impact with the smallest safe payload that proves the primitive (e.g. `SLEEP(5)` or a single-row extraction, not a full database dump). Note in the finding that greater impact is available but was not exercised, and why.
- **Redact, don't omit**: mask real user PII, live session tokens, and secrets with a fixed placeholder (`[REDACTED-EMAIL]`, `[REDACTED-TOKEN]`) rather than deleting the field entirely — the reader needs to see *that* sensitive data was present, just not its value.
- **Timestamp every piece of evidence**: findings tied to time-sensitive state (a race condition, a session that later expired, a since-patched endpoint) need a capture timestamp so a re-test months later isn't mistaken for a false positive.
- **Negative evidence for INFO/false-positive candidates**: when a suspected issue was tested but not confirmed exploitable, record what was tried and why it didn't work — this prevents the same dead-end being re-tested in a future engagement and gives the client confidence the surface was actually covered.
- **Chain-of-custody for artifacts**: any downloaded binary, extracted secret, or captured credential referenced in a finding should cite its SHA-256/location in `$DIR/scans/` so the evidence can be independently verified.

## Report Structure

### 1. Executive Summary

```markdown
## Executive Summary
**Target:** [target]  **Scope:** [scope]  **Date:** [start] – [end]  **Tester:** [id]

| Severity | Count |
|----------|-------|
| HIGH | N | MEDIUM | N | LOW | N | INFO | N | **Total** | **N** |

[1-2 paragraph narrative: posture, most impactful findings, top recommendation.]
```

### 2. Methodology

```markdown
## Methodology
**Approach:** [Black/Grey/White-box, Manual/Automated/Hybrid]
**Phases:** 1. Recon 2. Enumeration 3. Vuln Discovery 4. Exploitation 5. Post-Exploitation

| Tool | Purpose |
|------|---------|

**Limitations:** [time, scope, rate limiting, unavailable systems]
```

### 3. Findings (sorted HIGH → INFO, each self-contained)

```markdown
### FINDING-001: [Title] [HIGH]
**OWASP:** A03:2021  **Component:** [endpoint/param]  **CVSS:** [score]

#### Description
[Precise technical explanation]

#### Evidence
**Request:** ```[full HTTP request]```
**Response:** ```[relevant excerpt]```

#### Impact
[Specific: "attacker can retrieve all 12,000 user credentials"]

#### Remediation
1. [Primary fix]  2. [Defense-in-depth]  3. [Monitoring]
**References:** [CWE, CVE links]
```

### 4. Attack Path Narrative

```markdown
## Attack Path Narrative
### Scenario 1: [Title]
**Findings Used:** FINDING-001, FINDING-003  **Starting Point:** [attacker type]
1. **Initial Access** — [FINDING-X] → [foothold]
2. **Escalation** — [FINDING-Y] → [escalate]
3. **Objective** — [outcome]
**Combined Impact:** [what chain achieves]  **Priority Fix:** [which fix breaks chain]
```

If no chains: "No multi-step attack paths identified."

### 5. Appendix

Tool output in `<details>` blocks, generated scripts, scope verification table, timeline.

## Generation Procedure

1. Collect and deduplicate findings
2. Assign severity per definitions, sort HIGH → INFO
3. Populate all template fields (flag missing evidence, never fabricate)
4. Analyze chaining opportunities, write attack path narrative
5. Compile appendix from tool output and scripts
6. Write executive summary LAST
7. Verify: finding IDs match cross-references, severity counts match

## Finding Deduplication & Merging

- Two findings are duplicates (merge into one) when they share the same root cause and vulnerability class, even if discovered on different endpoints — e.g. the same missing-authorization check reachable via five API routes is one finding ("Broken Object-Level Authorization across N endpoints") with all N routes listed as affected components, not five separate findings.
- Two findings are NOT duplicates (keep separate) when they share a vulnerability class but have distinct root causes or distinct exploitation paths — e.g. reflected XSS in a search param and stored XSS in a profile field are both "XSS" but require different fixes and different severity (stored is almost always higher impact).
- When merging, use the highest severity among the merged instances and list every affected component so remediation scope isn't understated.
- Cross-check the finding count in the executive summary table against the actual number of `### FINDING-NNN` headers before finalizing — a mismatch is the most common report-generation defect.

## Remediation Prioritization

When a client has limited fix capacity, group remediations by leverage rather than by finding order:
1. **Fixes that break an attack chain** — a single control (e.g. re-enabling CSRF tokens, fixing one broken-auth endpoint) that neutralizes multiple chained findings at once; call these out explicitly in the Attack Path Narrative's "Priority Fix" field.
2. **Systemic/root-cause fixes** — a framework-level or shared-library change that resolves an entire class of findings (e.g. a missing output-encoding helper used across all templates) versus patching each instance individually.
3. **Point fixes** — findings with no shared root cause and no chain dependency; prioritize by severity alone.

### Effort-vs-Impact Framework (for constrained remediation windows)

When the client explicitly asks "what do we fix first with N hours/sprint," layer an effort estimate onto the leverage grouping above rather than replacing it:

| | Low effort | High effort |
|---|---|---|
| **High impact** | Do immediately — quick wins, no reason to delay (e.g. a missing security header, a default credential) | Schedule first in the roadmap — the biggest risk reduction per engagement, even if it spans a sprint (e.g. a systemic auth redesign) |
| **Low impact** | Batch into routine maintenance — not worth a dedicated remediation sprint | Deprioritize explicitly — state in the report why it's intentionally deferred, so it isn't mistaken for an oversight |

Estimate effort from what's actually observable (single config flag vs. framework-wide code change vs. architectural redesign), and say so explicitly — "low effort: single nginx directive" is more useful to a client than an unstated assumption. Never let an effort estimate downgrade a finding's severity; effort and severity are independent axes and conflating them is a common report-quality defect (a HIGH-severity, high-effort fix is still HIGH severity).
