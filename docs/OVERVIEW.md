# RedTeam Agent — Technical Overview & Architecture Specification

> **A comprehensive technical deep dive into RedTeam Agent's multi-agent execution model, streaming SQLite case pipeline, and orchestration engine.**

---

## 1. System Philosophy & Executive Summary

RedTeam Agent is an autonomous cyber operations framework designed to perform end-to-end security evaluations against authorized web applications and network infrastructure. Rather than relying on a single conversational LLM prompt that attempts to alternate between high-level strategy and low-level payload crafting, RedTeam Agent implements a **hierarchical multi-agent architecture** managed by a deterministic state machine.

### Core Tenets
1. **Separation of Strategic and Operational Concerns**: The primary **Operator** maintains high-level situational awareness, enforces scope constraints, and directs task batches. Dedicated **Subagents** execute targeted tasks within narrow, bounded cognitive domains.
2. **Token-Frugal State Decoupling**: Large attack surfaces generate hundreds of endpoints, parameters, and network services. Storing this state in conversational LLM memory leads to catastrophic context exhaustion. RedTeam Agent stores all surface and queue state in an embedded SQLite database (`cases.db`).
3. **Zero-Token Dispatching**: Queue queries, batch locking, state transitions, and health checks run via shell scripts (`dispatcher.sh`), requiring zero LLM tokens for queue administration.
4. **Dual-Domain Execution**: Supports both application-layer web targets (REST, GraphQL, SPAs, WebSockets) and network infrastructure protocols (Active Directory, Kerberos, SMB, databases, remote access, DNS, SNMP).

---

## 2. Global Architecture

```
                                  ┌───────────────────────────────┐
                                  │           OPERATOR            │
                                  │    Strategic State Machine    │
                                  │   (Never tests targets direct)│
                                  └───┬───┬───┬───┬───┬───┬───┬───┘
                                      │   │   │   │   │   │   │
        ┌─────────────────────────────┘   │   │   │   │   │   └─────────────────────────────┐
        ▼                                 ▼   │   ▼   │   ▼                                 ▼
┌──────────────┐                 ┌──────────┐ │ ┌───┐ │ ┌───────────┐                 ┌─────────────┐
│ recon-       │                 │ source-  │ │ │vul│ │ │ exploit-  │                 │ report-     │
│ specialist   │                 │ analyzer │ │ │ana│ │ │ developer │                 │ writer      │
│ (Fingerprint)│                 │ (Static) │ │ │ly │ │ │ (Exploit) │                 │ (Report)    │
└───────┬──────┘                 └────┬─────┘ │ └───┘ │ └─────▲─────┘                 └─────────────┘
        │                             │       ▼       ▼       │
        │                             │    fuzzer  network-   │
        │                             │    (Fuzz)  analyst    │
        ▼                             ▼            (TCP/UDP)──┘
 ┌──────────────┐              ┌─────────────┐
 │  cases.db    │◄─────────────┤ intel.md    │◄─── osint-analyst
 │ (Queue State)│              │ (Secrets &  │     (Correlation)
 └──────────────┘              │  Identities)│
                               └─────────────┘
```

The system comprises five core subsystems:
1. **Operator Engine**: The primary decision loop driving phase progression and delegating work.
2. **Specialized Subagent Pool**: 8 task-specific worker personas with isolated toolsets.
3. **Streaming Case Pipeline**: SQLite-backed case queue with multi-source ingestion and atomic batch dispatch.
4. **Methodology & Reference Library**: 55 offensive attack skills and 79 reference manuals.
5. **Lab Profile & Closure Gate**: Declarative target fingerprinting and objective verification engine.

---

## 3. The Operator Decision Loop

The Operator operates on a strict iterative control loop. It **never** sends attack payloads or executes direct probes against the target; its sole responsibility is coordination and state tracking.

```
       ┌──────────────────────────────┐
       │       1. Assess State        │ ◄── Read scope.json, tail log.md,
       └──────────────┬───────────────┘     run intel_changed_check.sh
                      │
                      ▼
       ┌──────────────────────────────┐
       │     2. Decide Next Action    │ ◄── Prioritize by risk & pending stages
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │      3. Formulate Plan       │ ◄── Target parameters, tool selection
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │     4. Present or Proceed    │ ◄── Interactive vs Autoengage mode
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │    5. Atomic Task Dispatch   │ ◄── Pair fetch_batch with task() call
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │     6. Record Findings       │ ◄── Append to findings.md immediately
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │     7. Reconcile Surfaces    │ ◄── Append to surfaces.jsonl
       └──────────────┬───────────────┘
                      │
                      └───────────────────► Repeat until stop condition holds
```

### Unattended Hardening Guards
* **Directory Scoping (`external_directory` Guard)**: The operator strictly scopes all scratch and temporary outputs to `$DIR/tmp.operator/`. It never references `/tmp`, `/var`, or root directories, preventing OpenCode or Claude Code security approval prompts from stalling autonomous sessions.
* **Atomic Fetch-Dispatch Pairing**: A queue fetch (`fetch_batch_to_file.sh`) and the corresponding subagent dispatch (`task(...)`) must occur within the **same assistant turn**. A fetch without an immediate dispatch leaves cases locked in `processing`, creating queue stalls.
* **Literal Heredoc Ingestion**: Markdown and JSONL evidence are staged via literal heredocs (`<<'EOF'`) to prevent unintended bash variable expansion of payloads containing `$()`, backticks, or backslashes.

---

## 4. The Streaming Case Pipeline (`cases.db`)

### 4.1 Schema Definition (`agent/scripts/schema.sql`)
The pipeline runs on SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) and a 5000ms busy timeout.

```sql
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Request identity (HTTP)
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    url_path TEXT NOT NULL,

    -- Pre-extracted structured parameters
    query_params TEXT,
    body_params TEXT,
    path_params TEXT,
    cookie_params TEXT,

    -- Request details
    headers TEXT,
    body TEXT,
    content_type TEXT,
    content_length INTEGER,

    -- Response telemetry
    response_status INTEGER,
    response_headers TEXT,
    response_size INTEGER,
    response_snippet TEXT,

    -- Classification and routing
    type TEXT NOT NULL DEFAULT 'unknown',
    source TEXT NOT NULL,

    -- Network service identity (for type='service')
    host TEXT,
    port INTEGER,
    proto TEXT,
    service TEXT,
    service_product TEXT,
    service_version TEXT,
    banner TEXT,
    scan_ref TEXT,

    -- Lifecycle state management
    status TEXT NOT NULL DEFAULT 'pending',
    stage TEXT NOT NULL DEFAULT 'ingested',
    assigned_agent TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    consumed_at TEXT,

    -- Deduplication signature
    params_key_sig TEXT,

    UNIQUE(method, url_path, params_key_sig)
);
```

### 4.2 Deduplication Key (`params_key_sig`)
To avoid re-testing identical endpoints with arbitrary parameter values:
* HTTP cases calculate `params_key_sig = sha1(origin + sorted_param_keys)`.
* Service cases set `method='SERVICE'`, `url_path='/<host>/<port>/<proto>'`, and `params_key_sig = sha1(proto|host|port|service)`.

### 4.3 Ingestion Producers
1. **`mitmproxy` (`proxy_addon.py`)**: Intercepts authenticated browser traffic, extracts structured headers, parameters, and cookies, and streams them directly into `cases.db`.
2. **`Katana` (`katana_ingest.sh`)**: Crawls targets headlessly, parses DOM XHR endpoints and JavaScript endpoints, and classifies links.
3. **`recon_ingest.sh`**: Ingests endpoints discovered by `nikto`, `whatweb`, and `gobuster`.
4. **`spec_ingest.sh`**: Parses OpenAPI/Swagger JSON and YAML definitions into discrete HTTP operations.
5. **`net_ingest.sh` & `netscan.sh`**: Parses Nmap XML (`-oX`) output and converts discovered TCP/UDP open ports into `type=service` cases.

### 4.4 Stage-Based Routing Matrix

Rather than imposing artificial phase walls, cases advance individually through discrete lifecycle stages:

| Current Stage | Case Type | Target Subagent | Next Transition State |
|---|---|---|---|
| `ingested` | `service` | `network-analyst` | `vuln_confirmed` (primitive found) or `clean` |
| `ingested` | `api`, `form`, `graphql`, `upload`, `websocket` | `vulnerability-analyst` | `vuln_confirmed`, `fuzz_pending`, or `api_tested` |
| `ingested` | `javascript`, `page`, `stylesheet`, `data`, `unknown`, `api-spec` | `source-analyzer` | `source_analyzed` (carrier retired; new endpoints queued at `ingested`) |
| `vuln_confirmed` | Any | `exploit-developer` | `exploited` (finding generated) or `clean` |
| `fuzz_pending` | Any | `fuzzer` | `vuln_confirmed`, `api_tested`, or `clean` |
| `source_analyzed` | Any | None (Terminal) | Retired carrier case |
| `api_tested` | Any | None (Terminal) | Tested negative |
| `exploited` | Any | None (Terminal) | Finding verified and recorded |
| `clean` | Any | None (Terminal) | Non-vulnerable / out of scope |
| `errored` | Any | None (Terminal) | Eligible for reset via `dispatcher.sh retry-errors` |

---

## 5. The Subagent Pool (8 Specialized Personas)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SUBAGENT SPECIALIZATION                         │
├──────────────────────┬──────────────────────────┬──────────────────────┤
│ Subagent             │ Primary Reasoning Mode   │ Enabled Tools        │
├──────────────────────┼──────────────────────────┼──────────────────────┤
│ recon-specialist     │ Broad surface mapping    │ nmap, whatweb, nikto │
│ network-analyst      │ Protocol enumeration     │ nmap, hydra, smbclient│
│ source-analyzer      │ Static code analysis     │ grep, ast, js-beautify│
│ vulnerability-analyst│ Bounded hypothesis test  │ curl, sqlmap, nuclei │
│ exploit-developer    │ State chaining & exploit │ msfrpcd, custom PoC  │
│ fuzzer               │ Statistical noise triage │ ffuf, wfuzz, seclists│
│ osint-analyst        │ Cross-source correlation │ cve-search, dnsrecon │
│ report-writer        │ Executive documentation  │ markdown, chart gen  │
└──────────────────────┴──────────────────────────┴──────────────────────┘
```

1. **`recon-specialist`**: Performs network and web discovery. Re-evaluates target surfaces whenever valid credentials are saved to `auth.json`.
2. **`network-analyst`**: Evaluates non-HTTP network infrastructure. Follows dedicated methodology skills for SMB, Active Directory, databases, remote access, TLS, Kubernetes, containers, cloud, and CI/CD.
3. **`source-analyzer`**: De-obfuscates and analyzes client-side assets to identify unlinked endpoints, deprecated parameters, and hardcoded API tokens.
4. **`vulnerability-analyst`**: Acts as a rapid gatekeeper. Limits analysis to 1–2 lightweight probes per vulnerability class to prevent rate-limiting and scanner bans.
5. **`exploit-developer`**: Constructive attacker. Takes confirmed vulnerabilities, verifies full execution, escalates privileges, and interfaces with Metasploit RPC via stdio MCP.
6. **`fuzzer`**: Dedicated high-volume testing engine. Takes cases tagged `stage=fuzz_pending` and executes deep dictionary fuzzing across query and POST parameters.
7. **`osint-analyst`**: Triggered via `intel_changed_check.sh` whenever new company names, software versions, or usernames appear in `intel.md`.
8. **`report-writer`**: Aggregates all documented findings from `findings.md`, verifies CVSS scores, checks remediation recommendations, and generates `report.md`.

---

## 6. Lab Profiles & The Objective Closure Gate

To support CTF challenges and intentional vulnerability benchmarks without polluting generic agent prompts with target-specific spoilers, RedTeam Agent uses declarative lab profiles located in [`agent/labs/`](../agent/labs/):

### Declarative Schema
```jsonc
{
  "id": "juice-shop",
  "kind": "web-app",
  "priority": 100,
  "match": {
    "hosts": ["*juice-shop*"],
    "ports": [3000],
    "path_probes": ["/api/Challenges"]
  },
  "objective": {
    "type": "remote", // remote | flag | declared | none | discover
    "source": {
      "url": "/api/Challenges",
      "parser": "juice-shop"
    },
    "checklist": ["Score Board", "Confidential Document"]
  },
  "recall_branches": [
    {
      "objective": "Score Board",
      "vuln_class": "info-disclosure",
      "route": "/#/score-board",
      "trigger": "search_source_for_hidden_paths"
    }
  ]
}
```

### Objective Lifecycle
1. **Detection**: Upon `/engage`, `lab_objective.py detect` evaluates hostnames, active ports, and HTTP path probes to select the highest-priority matching profile.
2. **Snapshot Tracking**: During testing, `lab_objective.py snapshot` queries local flag files or remote scoreboard APIs to identify solved and unsolved objectives.
3. **Closure Guard**: Before the engagement can transition to `report` or `complete`, [`agent/scripts/finalize_engagement.sh`](../agent/scripts/finalize_engagement.sh) executes `lab_objective.py guard`. If declared objectives remain unaddressed, the guard **fails closed**, prompting the operator to investigate un-triggered recall branches.

---

## 7. Runtimes: Docker vs Bare-Metal Kali

The environment abstraction layer in [`agent/scripts/lib/container.sh`](../agent/scripts/lib/container.sh) switches dynamically based on `REDTEAM_RUNTIME_MODE`:

| Operation | `docker` Mode (Default off-Kali) | `local` Mode (Bare-Metal Kali) |
|---|---|---|
| `run_tool <bin> <args...>` | Spawns transient `docker run kali-redteam <bin>` | Directly calls `<bin>` on host `PATH` |
| Interception Proxy | Spawns `redteam-mitmproxy` container | Runs background `mitmdump` process |
| Web Crawler | Spawns `redteam-katana` container | Executes local `$KATANA_LOCAL_BIN` |
| Metasploit RPC | Spawns `docker compose up metasploit` | Starts local `msfrpcd` on port 55553 |
| Tool Diagnostics | Validates Docker daemon and image integrity | Verifies host packages via `check_local_tools.sh` |

---

## 8. Artifacts & Outputs

All engagement artifacts are recorded inside `engagements/<timestamp-target>/`:

```
engagements/20260924-target-local/
├── scope.json              # Engagement boundaries, target hostnames, CIDRs, and modes
├── log.md                  # Comprehensive operator audit log and dispatch decisions
├── findings.md             # Confirmed vulnerability findings with PoCs and CVSS
├── report.md               # Final professional penetration test report
├── intel.md                # Normalized summary of discovered credentials, hosts, and tech
├── intel-secrets.json      # Full, un-redacted captured tokens, hashes, and passwords
├── auth.json               # Active session cookies, Authorization headers, and API keys
├── cases.db                # SQLite database with all evaluated endpoints and state
├── surfaces.jsonl          # Attack surface ledger validating test coverage
├── lab-profile.json        # Resolved target profile and active objective checklist
└── scans/                  # Directory containing raw scanner output (Nmap XML, etc.)
```

> [!CAUTION]
> **Data Handling Notice**
> 
> The files `intel-secrets.json` and `auth.json` contain active authentication material and sensitive credentials discovered during testing. Never share these files without proper sanitization.
