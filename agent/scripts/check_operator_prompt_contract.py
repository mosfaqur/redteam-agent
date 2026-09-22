#!/usr/bin/env python3
"""Static contract checks for rendered operator prompt guardrails.

This intentionally avoids pytest so auditor cycles can run it with the system
Python after prompt regeneration.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "operator-core.md",
    ROOT / "AGENTS.md",
    ROOT / "CLAUDE.md",
    ROOT / ".opencode" / "prompts" / "agents" / "operator.txt",
]
REQUIRED_SNIPPETS = [
    '"remained unsolved"',
    '"no multi-step attack path"',
    'Before dispatching `report-writer`',
    'hard pre-report gate, not a hint and not dependent on the latest handoff wording',
    'If ANY objective remains unresolved, lab objective closure is NOT satisfied',
    'append a `Lab objective gate` log entry naming every unresolved objective',
    'The active profile\'s `objective.checklist` is the static floor',
    'the live gate MUST use the union of that enumerated peak set plus the profile checklist',
    'every checklist/peak objective that is unresolved',
    '`Lab objective gate` log entry',
    'Do not transition to `report`, dispatch `report-writer`, or finalize the run until this explicit gate action is visible in `log.md`',
    'Never emit status-only text such as `[operator] Continuing closure batch.` after a non-empty closure fetch',
    'promotion, non-empty `fetch_batch_to_file.sh`, and exploit-developer handoff are inseparable',
    'A closure branch with `BATCH_COUNT>0` sitting in `processing` without the matching exploit-developer task is a queue-stall bug',
    'a `step_finish` or new `step_start` immediately after a non-empty fetch without an intervening matching `task(...)` is a run-failing orphaned batch',
    'a non-empty fetch for `BATCH_AGENT=vulnerability-analyst` MUST be followed by the vulnerability-analyst task before any file read, queue scan, source batch, status text, or final answer',
    'After `./scripts/update_phase_from_stages.sh "$DIR"` prints `phase: consume_test -> complete`',
    'A standalone final answer such as `[operator] Resume continued... closure work is still ongoing` after queue drain is forbidden',
    'never write temporary dispatcher/log/requeue output under `/tmp`, `/var`, or any other external directory',
    'Keep scratch files under the exact active `$DIR`',
    '`surface coverage and lab objective closure follow-up still required` / `closure work is still ongoing`',
    'Lab profile resolution',
    'python3 ./scripts/lab_objective.py detect "$DIR"',
    'python3 ./scripts/lab_objective.py snapshot "$DIR"',
    'Lab objective closure gate',
    'Never hardcode a lab\'s challenge names, routes, or endpoints in this prompt',
    'recall_branches',
    'Do not use a saved snapshot artifact as the passing evidence',
    'If the profile is `generic`/`generic-web` with no checklist',
]


def main() -> int:
    failures = []
    checked = 0
    for path in FILES:
        if not path.exists():
            # Installed runtimes ship only the operator prompt for their own
            # product (e.g. .opencode/prompts/agents/operator.txt); the shared
            # operator-core.md / CLAUDE.md / AGENTS.md are repo-dev files.
            continue
        checked += 1
        text = path.read_text(encoding="utf-8")
        for snippet in REQUIRED_SNIPPETS:
            if snippet not in text:
                failures.append(f"{path.relative_to(ROOT)} missing {snippet!r}")
    if checked == 0:
        print("operator prompt contract: no operator prompt files present (installed runtime); skipped")
        return 0
    if failures:
        print("operator prompt contract failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("operator prompt contract ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
