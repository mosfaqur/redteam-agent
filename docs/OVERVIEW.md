# RedTeam Agent — Technical Overview

A detailed description of how this project works: architecture, the case pipeline,
agents, lab profiles, runtimes, and how to extend it.

> **Authorization notice.** This tool is for authorized security testing only.
> Use it exclusively against targets you own or have explicit written permission to
> test (local labs, CTF environments, your own infrastructure).

---

## 1. What this is

An autonomous red-team / penetration-testing orchestration layer that runs inside an
AI coding CLI. It turns a workspace into a full pentest environment driven by a
primary **operator** agent that coordinates specialized subagents through a streaming,
SQLite-backed case queue.

Supported CLIs: **OpenCode** (primary/source of truth), **Claude Code**, **Codex**.

Supported runtimes:

| Runtime | How tools run | Best for |
|---|---|---|
| `docker` (default off-Kali) | one-shot `docker run kali-redteam` per tool call | isolation, zero host setup |
| `local` (bare-metal Kali) | host binaries directly | Kali boxes with the toolchain installed |

Scope of testing:

- **Web applications** — HTTP case pipeline (recon → source → triage → exploit).
- **TCP/UDP services** — service cases (SMB/RPC, databases, mail/DNS, remote access,
  LDAP/Kerberos, SNMP/FTP/NFS).
- **Network / AD labs** — CIDR/range scope, declared objectives (domain admin, root, …).

---

## 2. Architecture at a glance

```
                 ┌───────────────────────────────┐
                 │           OPERATOR             │  primary agent
                 │  coordinates + owns state      │  (never tests directly)
                 └───┬───┬───┬───┬───┬───┬───┬────┘
                     │   │   │   │   │   │   │
   recon-specialist ─┘   │   │   │   │   │   └─ report-writer
   network-analyst ──────┘   │   │   │   │
   source-analyzer ──────────┘   │   │   │
   vulnerability-analyst ────────┘   │   │
   exploit-developer ────────────────┘   │
   fuzzer / osint-analyst ───────────────┘
```

- **Operator** — reads `scope.json`/`log.md`, decides the next action, dispatches
  subagents, records findings/surfaces, drives the closure gate. It does not run
  payloads itself.
- **8 subagents** — each with a focused prompt, tool set, and reasoning mode.
- **Case queue** (`cases.db`) — the state machine; producers add cases, the dispatcher
  hands them to subagents by stage, subagents advance stages.
- **Skills** (38) + **references** (79) — methodology and payload/reference library
  loaded into context or read on demand.
- **Lab profiles** (13) — lab-specific fingerprints, objective sources, and recall
  triggers, kept as data so the prompt stays generic.
- **Orchestrator** (optional) — FastAPI + React web UI for multi-project runs.

---

## 3. The operator loop

After `/engage` initialization, the operator repeats:

1. **Assess state** — read `scope.json`; inspect the newest slice of `log.md`/`findings.md`;
   run `intel_changed_check.sh` and `auth_respawn_check.sh` (flag-file respawn).
2. **Decide** — prioritize by impact.
3. **Dispatch** — always via a subagent (`task(...)`), never directly.
4. **Record** — findings to `findings.md`, surfaces to `surfaces.jsonl`, intel to `intel.md`.
5. **Loop** — until the stop condition holds.

Phases (`recon`, `collect`, `consume_test`, `exploit`, `report`, `complete`) are
**derived labels** computed from stage counts by `update_phase_from_stages.sh`, not gates.

---

## 4. The case pipeline

### 4.1 Producers

| Producer | Adds |
|---|---|
| `mitmproxy` | captured authenticated requests |
| `Katana` (via `katana_ingest.sh`) | crawled endpoints / XHR |
| `recon_ingest.sh` | HTTP endpoints from recon/source JSONL |
| `spec_ingest.sh` | endpoints from OpenAPI/Swagger specs |
| `net_ingest.sh` | TCP/UDP services from nmap XML or JSONL |
| `netscan.sh` | convenience wrapper: nmap TCP+UDP → `net_ingest.sh` |

### 4.2 Case model (`scripts/schema.sql`)

HTTP columns: `method`, `url`, `url_path`, `query_params`, `body_params`,
`path_params`, `cookie_params`, `headers`, `body`, `content_type`, `response_*`.

Service columns (nullable; `type='service'`): `host`, `port`, `proto`, `service`,
`service_product`, `service_version`, `banner`, `scan_ref`.

Shared: `type`, `source`, `status`, `stage`, `assigned_agent`, `params_key_sig`.
Dedup is `UNIQUE(method, url_path, params_key_sig)`; service cases reuse it with
`method='SERVICE'`, `url='<proto>://host:port'`, `url_path='/host/port/proto'`.

### 4.3 Stages and routing

| Stage | Meaning | Next dispatch |
|---|---|---|
| `ingested` | fresh case | `service`→network-analyst; `javascript/page/stylesheet/data/unknown/api-spec`→source-analyzer; `api/form/graphql/upload/websocket`→vulnerability-analyst |
| `source_analyzed` | source carrier analyzed | terminal (follow-ups start fresh) |
| `vuln_confirmed` | exploitable | exploit-developer |
| `fuzz_pending` | needs deep fuzz | fuzzer |
| `api_tested` / `clean` / `exploited` / `errored` | terminal | — |

### 4.4 Dispatcher (zero tokens)

`scripts/dispatcher.sh` performs all queue bookkeeping in shell so the LLM never
spends tokens on it: `stats`, `stats-by-stage`, `fetch`, `fetch-by-stage`,
`done <ids> --stage <s>`, `error`, `set-stage`, `requeue`, `reset-stale`,
`retry-errors`, `migrate`. It auto-migrates missing columns on legacy DBs.

`fetch_batch_to_file.sh` wraps a stage fetch, writes the JSON batch to disk, and prints
compact `BATCH_*` metadata (`BATCH_FILE`, `BATCH_IDS`, `BATCH_AGENT`, `BATCH_COUNT`,
`BATCH_PATHS`, …). The operator must pair a non-empty fetch with the matching
`task(...)` **in the same turn** (atomic fetch→dispatch).

### 4.5 Stop condition

Active stages (`ingested`, `vuln_confirmed`, `fuzz_pending`) = 0, `processing` = 0,
`check_collection_health.sh` passes, `check_surface_coverage.sh` passes, and recon has
returned at least once.

---

## 5. Agents

| Agent | Role | Trigger |
|---|---|---|
| `operator` | coordinator; owns state and decisions | always |
| `recon-specialist` | fingerprinting, dir fuzzing, port scans | initial + auth-respawn |
| `network-analyst` | TCP/UDP service enumeration + testing | `ingested` + `service` |
| `source-analyzer` | static HTML/JS/CSS analysis | `ingested` + source types |
| `vulnerability-analyst` | bounded triage (1–2 probes/family) | `ingested` + API/form types |
| `exploit-developer` | exploitation, chaining, impact | `vuln_confirmed` |
| `fuzzer` | high-volume fuzzing (500+ payloads) | `fuzz_pending` |
| `osint-analyst` | CVE/breach/DNS/social correlation | `intel.md` grew |
| `report-writer` | final/interim report | end of cycle |

Finding IDs are prefixed per agent (`EX`, `VA`, `SA`, `RE`, `NA`, `FZ`, `OS`) and
allocated under a lock by `append_finding.sh`.

---

## 6. Web vs TCP/UDP testing

**Web**: 15 HTTP types classified by `lib/classify.sh` (api, form, graphql, upload,
websocket, api-spec, page, javascript, stylesheet, data, image, video, font, archive,
unknown), tested by the web skills.

**TCP/UDP services**: produced by `net_ingest.sh`/`netscan.sh`, tested by
`network-analyst` using service skills:

| Skill | Coverage |
|---|---|
| `network-service-testing` | general methodology + queue contract |
| `smb-netbios` | SMB/RPC, null sessions, shares, relay, MS17-010 |
| `database-services` | MySQL, MSSQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| `remote-access-services` | SSH, RDP, VNC, Telnet |
| `mail-dns-services` | SMTP/IMAP/POP3, DNS zone transfer |
| `ldap-kerberos` | LDAP enum, AS-REP/Kerberoasting, delegation, ADCS |
| `snmp-ftp-nfs` | SNMP community, FTP anon, NFS exports |

Confirmed primitives (`stage=vuln_confirmed`) are exploited by `exploit-developer`
(optionally via the Metasploit MCP).

**Network engagements**: `/engage 10.10.10.5`, `/engage 10.0.0.0/24`, or
`/engage 10.0.0.5-20` enters network mode (no Katana/mitmproxy). Scope entries may be
CIDRs or ranges; `host_in_scope` matches them and `net_ingest.sh` drops out-of-scope hosts.

---

## 7. Lab profiles

Profiles decouple lab-specific knowledge from the methodology. They live in
`agent/labs/*.json`; the operator resolves one into `engagements/<…>/lab-profile.json`.

Schema highlights:

```jsonc
{
  "id": "juice-shop", "kind": "web-app", "priority": 100,
  "match": { "hosts": [...], "ports": [...], "min_port_overlap": 3, "path_probes": [...] },
  "objective": {
    "type": "remote",           // remote | flag | declared | none | discover
    "source": {"url": "/api/Challenges", "parser": "juice-shop"},
    "checklist": ["Score Board", "..."]
  },
  "recall_branches": [ {"objective": "...", "vuln_class": "...", "route": "...", "trigger": "..."} ]
}
```

- **Detection**: host match, port match (including ports already ingested in `cases.db`
  via `min_port_overlap`), or bounded HTTP path probes. `detect` never downgrades a
  resolved specific profile to `generic`.
- **Objective types**: `remote` (challenge API/scoreboard), `flag` (captured flags),
  `declared` (local checklist, e.g. network/AD), `none` (plain pentest), `discover`
  (probe candidates at runtime).
- **Closure gate**: `lab_objective.py snapshot` reports solved-state; the operator must
  resolve unresolved objectives (using `recall_branches`) before `report-writer`.
  `finalize_engagement.sh` runs `lab_objective.py guard` as the last gate and **fails
  closed** if an explicit objective source is unreachable.

Built-in profiles: `generic`, `generic-web`, `generic-ctf`, `generic-network`,
`juice-shop`, `dvwa`, `webgoat`, `bwapp`, `portswigger`, `metasploitable`,
`hackthebox`, `vulnhub`, `tryhackme`.

Tooling: `scripts/lab_objective.py {detect|list|snapshot|capture|guard|show}`.

---

## 8. Runtimes

`scripts/lib/container.sh` dispatches on `REDTEAM_RUNTIME_MODE`:

| Function | `docker` | `local` |
|---|---|---|
| `run_tool <bin> …` | `docker run … kali-redteam <bin>` | host binary (or `rtcurl`) |
| proxy | container | `mitmdump` |
| Katana | container | `$KATANA_LOCAL_BIN` |
| `check_docker`/`check_images` | validate | no-op success |
| Metasploit | `docker compose up metasploit` | host `msfrpcd` |

`.env` defaults are loaded non-destructively (explicit env wins) and tool paths
autodetect (`configured → PATH → default`). Host-tool preflight/installer:
`scripts/check_local_tools.sh [--install]`.

---

## 9. Installation

```bash
./install.sh -h
```

| Product | Result |
|---|---|
| `docker` | all-in-one image + `run.sh` (isolated runtime) |
| `opencode` | OpenCode config (`.opencode/`, skills, scripts, labs) |
| `claude` | Claude Code config (generates `.claude/agents`, `CLAUDE.md`) |
| `codex` | Codex config (generates `.codex/agents`, `AGENTS.md`) |
| `kali` | bare-metal Kali: OpenCode files + `local` runtime + tool preflight (`--install` auto-installs) |

On Kali, `opencode`/`claude`/`codex` auto-select `local` mode unless
`REDTEAM_RUNTIME_MODE` is exported; `docker` always stays Docker.

---

## 10. Commands

`/engage <url|ip|cidr>`, `/autoengage <target>`, `/resume`, `/status`, `/proxy`,
`/auth`, `/queue`, `/report`, `/stop`, `/confirm`, `/config`, `/subdomain`,
`/vuln-analyze`, `/osint`, `/recon`, `/scan`, `/enumerate`, `/exploit`, `/pivot`.

---

## 11. Outputs

Per engagement (`engagements/<timestamp-target>/`): `scope.json`, `log.md`,
`findings.md`, `report.md`, `intel.md`, `intel-secrets.json`, `auth.json`, `cases.db`,
`surfaces.jsonl`, `lab-profile.json`, `objective-state.json`, plus `scans/`,
`downloads/`, `tools/`, `pids/`.

Sensitive: `intel-secrets.json`, `auth.json`, and any directory with live
credentials/tokens/sessions.

---

## 12. Extending

- **Add a skill**: create `agent/skills/<name>/SKILL.md`; add it to the `instructions`
  array in `agent/.opencode/opencode.json`.
- **Add a lab profile**: drop `agent/labs/<id>.json` (see `agent/labs/README.md`).
  No prompt edits needed.
- **Add/modify an agent**: edit `agent/.opencode/prompts/agents/<name>.txt`, register it
  in `opencode.json`, and re-run `install.sh` for generated CLIs. Operator changes go in
  `agent/operator-core.md` and are rendered by `scripts/render-operator-prompts.sh`.
- **References**: add files under `agent/references/<category>/` and update
  `agent/references/INDEX.md`.

Single-source rule: `agent/` is canonical; `.opencode/` prompts/commands are the source
and `.claude/`/`.codex/` are generated at install time.

---

## 13. Repository layout

```
install.sh                install products
agent/                    canonical agent runtime
  .opencode/              OpenCode config, prompts, commands, plugins
  operator-core.md        shared operator methodology (rendered to CLAUDE/AGENTS/operator.txt)
  scripts/                queue engine, producers, gates, lab_objective.py, netscan.sh
  skills/                 38 attack-methodology skills (web + TCP/UDP)
  references/             79 reference files (OWASP, API, offensive tactics, AD)
  labs/                   lab profiles
  docker/                 Dockerfiles + compose
orchestrator/             optional FastAPI + React web UI
docs/                     documentation (this file, runtime + network guides)
```

---

## 14. Verification / tests

- `scripts/check_operator_prompt_contract.py`, `check_operator_respawn_contract.py`,
  `check_sensitive_data_skill_contract.py`, `check_exploit_developer_prompt_contract.py`
  — static prompt contracts (skip gracefully in installed runtimes).
- `scripts/check_collection_health.sh`, `check_surface_coverage.sh` — pipeline gates.
- `scripts/lab_objective.py guard` — objective closure gate.
- `scripts/check_local_tools.sh` — host toolchain preflight.
