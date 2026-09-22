# Lab Profiles

Lab profiles decouple **lab-specific knowledge** (fingerprints, objective/scoreboard
sources, challenge checklists, concrete recall triggers) from the **generic red-team
methodology** in `operator-core.md` and the skills.

The operator fingerprints the target at engagement start, resolves exactly one
profile into `engagements/<...>/lab-profile.json`, and then runs the **same**
closure gate for every lab. Concrete challenge names and routes live here as data,
not hardcoded in the prompt.

## Files

| File | Kind | Purpose |
|---|---|---|
| `generic.json` | auto | Fallback. Dynamically discovers an objective source (scoreboard / challenge API / flags). Used when no specific profile matches. |
| `generic-web.json` | web-app | Plain web-app pentest with no machine-readable objective source. Closure gate = surface coverage + report completeness. |
| `generic-ctf.json` | ctf | Flag-based CTF. Objectives are captured flags tracked in `objective-state.json`. |
| `generic-network.json` | network | Network / AD labs. Objectives are declared locally (domain admin, host root, ...) and tracked in `objective-state.json`. |
| `metasploitable.json` | network | Metasploitable 2 service-exploit checklist. |
| `juice-shop.json` | web-app | OWASP Juice Shop (extracted from the original hardcoded prompt). |
| `dvwa.json` | web-app | Damn Vulnerable Web Application. |
| `webgoat.json` | web-app | OWASP WebGoat. |
| `bwapp.json` | web-app | bWAPP. |
| `portswigger.json` | web-app | PortSwigger Web Security Academy labs. |

## Schema

```jsonc
{
  "id": "juice-shop",                 // unique id, matches filename stem
  "display_name": "OWASP Juice Shop",
  "kind": "web-app",                  // web-app | ctf | network | auto
  "priority": 100,                    // higher wins when multiple profiles match
  "match": {
    "always": false,                  // true = fallback catch-all
    "hosts": ["juice-shop"],          // exact hostname / hostname-label matches
    "ports": [3000, 8000],            // any-of port match
    "path_probes": [                  // optional bounded HTTP fingerprints
      {"path": "/api/Challenges", "contains": "challenge"}
    ]
  },
  "objective": {
    "type": "remote",                 // remote | flag | declared | none | discover
    "discover": false,                // true = probe `candidates` at runtime
    "source": {"url": "/api/Challenges", "parser": "juice-shop"},
    "candidates": [                    // used when discover=true
      {"url": "/api/Challenges", "parser": "juice-shop"}
    ],
    "id_field": "name",
    "solved_field": "solved",
    "checklist": ["Score Board", "..."] // optional static floor
  },
  "recall_branches": [
    {
      "objective": "Score Board",
      "vuln_class": "info-disclosure",
      "route": "/api/Challenges",
      "trigger": "one bounded live visit/API read; record solved-state evidence"
    }
  ]
}
```

## Objective types

| Type | Solved-state source | Completion tracked by |
|---|---|---|
| `remote` | HTTP endpoint parsed by `parser` | server response |
| `flag` | flag list at `source.url` (or local file) | `objective-state.json` captured flags |
| `declared` | checklist declared in profile / `scope.json` | `objective-state.json` captured objectives |
| `none` | — | not applicable (plain pentest) |
| `discover` | probes `candidates` until one parses | depends on matched parser |

Supported `parser` values (see `scripts/lab_objective.py`):
`juice-shop`, `ctfd`, `generic-json`, `html-scoreboard`, `flag-lines`, `flag-text`.

## Tooling

- `scripts/lab_objective.py detect <dir> [target_url] [--profile <id>]` — resolve and write `lab-profile.json` (use `--profile` for flag/network labs that do not auto-detect)
- `scripts/lab_objective.py snapshot <dir>` — print objective solved-state
- `scripts/lab_objective.py guard <dir>` — exit 1 if any objective is unsolved (finalize gate)
- `scripts/lab_objective.py capture <dir> <objective>` — mark a flag/declared objective captured
- `scripts/lab_objective.py list <dir>` — list the active checklist

Declared-objective profiles (`declared`) read their checklist from `objective.checklist`
or, if empty, from `scope.json.objectives`.

## Adding a lab

1. Copy `generic-web.json` (or `juice-shop.json`) to `labs/<id>.json`.
2. Fill in `match` (host/port/probe) and `objective`.
3. Add `recall_branches` for any concrete challenge triggers.
4. No prompt edits needed — the operator loads it automatically.
