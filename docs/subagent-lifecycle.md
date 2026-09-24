# Subagent Lifecycle Decisions & Engineering Standards

> **Architectural guidelines and governance standards for creating, activating, merging, and retiring AI subagents.**

---

## 1. Purpose & Application

As autonomous multi-agent systems grow, they are prone to architectural degradation: prompt bloat, overlapping duties, and "ghost" subagents that consume maintenance overhead without executing work.

This document establishes the **formal lifecycle standards** for RedTeam Agent. Consult this specification whenever:
* Proposing a new subagent persona.
* Triaging a subagent with zero observed dispatches across multiple runs ("ghost subagent").
* Refactoring a subagent prompt approaching the **25KB soft size limit**.
* Considering merging two subagents with seemingly overlapping responsibilities.

---

## 2. The Merge-vs-Keep Framework (The 3 Questions)

Whenever evaluating whether to merge two subagents or absorb one into another, apply this 3-question test. **A merge is justified ONLY if all three questions pass with "Same / Yes".**

```
                  ┌─────────────────────────────────────────┐
                  │ Q1: Is the tool stack identical?        │
                  └────────────────────┬────────────────────┘
                                       │
                      YES              │ NO ──► DO NOT MERGE
                                       ▼        (Different failure modes)
                  ┌─────────────────────────────────────────┐
                  │ Q2: Is the reasoning mode identical?    │
                  └────────────────────┬────────────────────┘
                                       │
                      YES              │ NO ──► DO NOT MERGE
                                       ▼        (Cognitive mode-switching churn)
                  ┌─────────────────────────────────────────┐
                  │ Q3: Is head-of-line blocking avoided?   │
                  └────────────────────┬────────────────────┘
                                       │
                      YES              │ NO ──► DO NOT MERGE
                                       ▼        (Long tasks block batch triage)
                             ┌───────────────────┐
                             │ MERGE JUSTIFIED   │
                             └───────────────────┘
```

### Q1 — Is the tool stack identical?
Evaluate the concrete CLI utilities, libraries, and protocols invoked:
* Different tools exhibit different failure modes, exit codes, rate-limit responses, and error recovery patterns.
* Merging disparate toolchains into a single agent inflates prompt instructions and expands the blast radius of operational failures.

### Q2 — Is the cognitive reasoning mode identical?
Subagents exhibit fundamentally different cognitive shapes:
* **Bounded Hypothesis Testing** (`vulnerability-analyst`): Fast, targeted, 1–2 deterministic probes per vulnerability class.
* **Statistical Noise Reduction** (`fuzzer`): High-volume pattern recognition across 1,000+ HTTP responses to filter anomalies.
* **Cross-Source Correlation** (`osint-analyst`): Synthesizing external intelligence across unrelated breach data, DNS records, and CVE databases.
* **Sequential Exploit Construction** (`exploit-developer`): State-dependent payload chaining, shellcode customization, and memory debugging.

> Forcing one agent prompt to mode-switch across differing cognitive paradigms degrades LLM accuracy and wastes context tokens on cognitive reorientation.

### Q3 — Does either side risk head-of-line blocking?
If Agent A performs long-running background tasks (e.g., deep directory fuzzing lasting 10+ minutes) while Agent B handles sub-second per-case API triage, combining them into one agent forces queue triage to stall while the long task runs.

### Evaluation Matrix

| Q1 (Tool Stack) | Q2 (Cognitive Mode) | Q3 (No Blocking) | Action | Rationale |
|---|---|---|---|---|
| **Same** | **Same** | **Yes** | **Merge Justified** | True duplication of function. |
| **Different** | Any | Any | **Do Not Merge** | Tool failure semantics will conflict. |
| Any | **Different** | Any | **Do Not Merge** | Destroys prompt focus; high reasoning tax. |
| Any | Any | **No** | **Do Not Merge** | Long tasks will choke high-throughput queues. |

---

## 3. Ghost Subagent Triage

A **Ghost Subagent** is registered in `opencode.json` and assigned a system prompt, but records **0 dispatches across ≥3 consecutive complete engagement cycles**.

> **Governance Rule**: Ghost subagents must be resolved within one engineering cycle. Never retain a subagent for "speculative future utility."

### Three Valid Outcomes for Ghosts

1. **Activate via Mechanical Trigger (Recommended)**: The role is legitimate, but the dispatch mechanism was missing or broken. Implement a mechanical trigger (Pattern A or B below).
2. **Retire and Absorb**: Permissible only if all three merge questions pass, and absorbing the logic does not push the receiver prompt beyond the 25KB cap.
3. **Delete Outright**: Remove the agent prompt and registry entry if the underlying capability is obsolete or replaced by external tools.

---

## 4. Standard Trigger Patterns

Do not invent custom prose triggers. Autonomous subagent execution must rely strictly on one of two proven architectural trigger patterns:

### Pattern A: Per-Case Stage Transitions
Use when the subagent's task attaches to an **individual case** in `cases.db`.

* **Mechanism**: Upstream agents transition a case's `stage` column by outputting a structured outcome:
  ```markdown
  ### Case Outcomes
  DONE STAGE=fuzz_pending 104
  ```
* **Dispatch**: The Operator's stage-based dispatcher queries cases matching `status='pending' AND stage='<stage>'` and dispatches the assigned subagent.
* **Example**: The `fuzzer` agent is activated when `vulnerability-analyst` triages an endpoint that requires wordlist fuzzing beyond its 500-entry inline budget.

### Pattern B: Flag-File Watcher Scripts
Use when the subagent's task represents **global, engagement-wide correlation** rather than a single endpoint case.

* **Mechanism**: A dedicated shell script runs at the start of each operator loop tick:
  1. Inspects a tracked artifact (`auth.json`, `intel.md`).
  2. Compares current state against a high-water mark file (e.g., `.<thing>-respawn-state.json`).
  3. If state expanded, writes an atomic flag file (e.g., `.<thing>-respawn-required`).
* **Dispatch**: If the flag file exists, the Operator dispatches the subagent and deletes the flag upon completion.
* **Examples**:
  * `auth_respawn_check.sh`: Triggers `recon-specialist` when new credentials appear in `auth.json`.
  * `intel_changed_check.sh`: Triggers `osint-analyst` when new entities are added to `intel.md`.

---

## 5. Architectural Anti-Patterns

### Anti-Pattern 1: Prose-Only Dispatch Contracts
* **The Failure**: Instructing an agent in prose: *"When you detect an interesting parameter, write 'NEEDS_FUZZING' in your response."*
* **Outcome**: Frontier models frequently omit arbitrary conversational markers under high load. Dispatch rates drop to zero.
* **Remedy**: Always use structured `### Case Outcomes` stage transitions or mechanical file-watching scripts.

### Anti-Pattern 2: Merging Ghosts to "Tidy Up"
* **Historical Case**: The `fuzzer` agent was previously merged into `vulnerability-analyst`. While this reduced the agent count, it violated Q2 (rapid triage vs deep statistical fuzzing) and Q3 (fuzz jobs blocked API triage). The merge was subsequently reverted.
* **Remedy**: Fix the trigger mechanism; do not destroy specialization.

### Anti-Pattern 3: Speculative Registration
* **The Failure**: Registering an agent in `opencode.json` with a prompt, but without an active dispatcher pathway.
* **Outcome**: Burns LLM system prompt context during CLI introspection with zero functional return.

---

## 6. Prompt Bloat Prevention Standards

1. **25KB Prompt Soft Cap**: If an agent prompt exceeds 25KB, new domain logic must be moved to a helper script or skill reference (`agent/skills/`), with only a 1-line invocation hook in the prompt.
2. **Reverse 3-Question Test**: Before adding a new capability to an existing agent, verify the 3 questions in reverse. If a merge would have been rejected, the additional capability must also be rejected.
3. **Skill Name Verification**: Every skill referenced in an agent prompt must resolve to a valid directory in `agent/skills/`.

---

## 7. Active Subagent Reference Matrix

| Subagent | Lifecycle State | Activation Trigger | Unique Cognitive Shape |
|---|---|---|---|
| **`operator`** | Primary Engine | Always active | Global strategy, scope enforcement, delegation |
| **`recon-specialist`** | Core Worker | Initial launch + `auth_respawn_check.sh` | Wide-scope discovery, network topology mapping |
| **`network-analyst`** | Core Worker (Pattern A) | `stage=ingested` & `type=service` | Binary/protocol enumeration & service exploitation |
| **`source-analyzer`** | Core Worker (Pattern A) | `stage=ingested` & `type∈{js, page, css}` | Static code analysis, regex pattern harvesting |
| **`vulnerability-analyst`** | Core Worker (Pattern A) | `stage=ingested` & `type∈{api, form}` | Bounded hypothesis testing (1–2 probes/class) |
| **`exploit-developer`** | Core Worker (Pattern A) | `stage=vuln_confirmed` | State-dependent payload chaining & PoC execution |
| **`fuzzer`** | Activated (Pattern A) | `stage=fuzz_pending` | High-volume statistical noise reduction (>500 requests) |
| **`osint-analyst`** | Activated (Pattern B) | `intel_changed_check.sh` flag | External entity and intelligence correlation |
| **`report-writer`** | Core Worker | Completion gate (`active_stages == 0`) | Executive synthesis and risk communication |
