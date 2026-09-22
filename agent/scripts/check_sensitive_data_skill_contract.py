#!/usr/bin/env python3
"""Regression guard for the lab objective sensitive-data recall contract."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "sensitive-data-detection" / "SKILL.md"
text = SKILL.read_text(encoding="utf-8")

required_phrases = [
    "Treat the profile's objective checklist as a closure checklist",
    "objective=<name> status=solved|blocked|requeued evidence=<path or response> next=<exact concrete action>",
    "A generic phrase such as \"ftp artifact closure\", \"metrics checked\", \"schema replayed\", \"credential rows dumped\", or \"web3 route inspected\" is not sufficient.",
    "do not close the branch as an environment mismatch in the same handoff",
    "emit `REQUEUE` with the exact path or workflow as the next case instead of `DONE STAGE=exhausted`",
    "When validated credentials land, do not treat auth respawn as bookkeeping separate from recall.",
]

# The sensitive-data recall contract must stay profile-driven: concrete
# challenge names live in labs/*.json, not in the skill.
required_markers = [
    "lab-profile.json",
    "recall_branches",
    "lab_objective.py snapshot",
    "objective source",
]

missing = []
for phrase in required_phrases:
    if phrase not in text:
        missing.append("phrase: " + phrase)
for marker in required_markers:
    if marker not in text:
        missing.append("marker: " + marker)

if missing:
    print("Sensitive-data objective recall contract is missing required items:", file=sys.stderr)
    for item in missing:
        print("- " + item, file=sys.stderr)
    sys.exit(1)

print("sensitive-data objective recall contract OK")
