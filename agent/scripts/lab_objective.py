#!/usr/bin/env python3
"""lab_objective.py — lab profile resolution and objective/closure gate engine.

Zero-dependency (stdlib only). Reads lab profiles from ``<repo>/labs/*.json``,
resolves exactly one against the engagement target, and reports objective
(challenge / flag / declared) solved-state so the operator and
``finalize_engagement.sh`` can run one generic closure gate for every lab.

Subcommands
-----------
  detect   <dir> [target_url]      resolve + write <dir>/lab-profile.json
  list     <dir>                   print the active objective checklist
  snapshot <dir> [--json]          print solved-state for every objective
  capture  <dir> <objective> [--evidence PATH]
                                   mark a flag/declared objective captured
  guard    <dir>                   exit 1 if any objective is unresolved
  show     <dir>                   print the resolved profile path + id

Environment
-----------
  LABS_DIR                          override labs/ location
  REDTEAM_SKIP_RECALL_FINALIZE_GUARD=1
                                    make `guard` a no-op (returns 0)
  LAB_OBJECTIVE_HTTP_TIMEOUT        per-request timeout seconds (default 5)
"""
from __future__ import annotations

import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_AGENT_DIR = SCRIPT_DIR.parent
DEFAULT_LABS_DIR = REPO_AGENT_DIR / "labs"

HTTP_TIMEOUT = float(os.environ.get("LAB_OBJECTIVE_HTTP_TIMEOUT", "5"))
FLAG_RE = re.compile(r"[A-Za-z0-9_]{0,16}\{[^}\s]{2,}\}")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def labs_dir() -> Path:
    override = os.environ.get("LABS_DIR")
    return Path(override) if override else DEFAULT_LABS_DIR


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_scope(eng_dir: Path) -> dict:
    scope = load_json(eng_dir / "scope.json")
    return scope if isinstance(scope, dict) else {}


def target_host_port(target: str) -> tuple[str, int]:
    if not target:
        return "", 0
    if "://" not in target:
        target = "https://" + target
    u = urllib.parse.urlsplit(target)
    host = (u.hostname or "").lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port


def host_matches(host: str, entries: list[str]) -> bool:
    if not host:
        return False
    for raw in entries or []:
        entry = str(raw).strip().lower()
        if not entry:
            continue
        if host == entry:
            return True
        if host.endswith("." + entry):
            return True
        # label match: "juice-shop" matches "juice-shop-lab-123"
        if entry in host.split(".")[0].split("-"):
            return True
    return False


def http_get(url: str) -> tuple[bool, str, str]:
    """Return (ok, body, error)."""
    req = urllib.request.Request(url, headers={"User-Agent": "redteam-lab-objective/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            return True, raw.decode(charset, errors="replace"), ""
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        # A 401/403/404 still tells us the endpoint exists but is not readable.
        return False, body, f"HTTP {exc.code}"
    except (urllib.error.URLError, socket.timeout, ValueError, OSError) as exc:
        return False, "", str(exc)


def join_url(base: str, path: str) -> str:
    if not path:
        return base
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))


# --------------------------------------------------------------------------- #
# parsers: each returns list[{"id": str, "solved": bool|None}]
# --------------------------------------------------------------------------- #
def _item_name(item: dict) -> str:
    for key in ("name", "title", "challenge", "objective", "id"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, (int, float)):
            return str(val)
    return ""


def _item_solved(item: dict) -> bool | None:
    for key in ("solved", "solved_by_me", "complete", "completed", "passed"):
        if key in item:
            return bool(item.get(key))
    status = item.get("status")
    if isinstance(status, str):
        return status.strip().lower() in {"solved", "complete", "completed", "passed", "true"}
    return None


def parse_juice_shop(body: str) -> list[dict]:
    payload = json.loads(body)
    items = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _item_name(item)
        if name:
            out.append({"id": name, "solved": bool(item.get("solved"))})
    return out


def parse_ctfd(body: str) -> list[dict]:
    payload = json.loads(body)
    items = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _item_name(item)
        if name:
            out.append({"id": name, "solved": bool(item.get("solved_by_me", item.get("solved", False)))})
    return out


def parse_generic_json(body: str) -> list[dict]:
    payload = json.loads(body)
    items: Any = payload
    if isinstance(payload, dict):
        for key in ("data", "challenges", "objectives", "items", "results"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
        else:
            # dict of name -> bool
            bool_map = {k: v for k, v in payload.items() if isinstance(v, bool)}
            if bool_map:
                return [{"id": k, "solved": v} for k, v in bool_map.items()]
            return []
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if isinstance(item, dict):
            name = _item_name(item)
            if name:
                out.append({"id": name, "solved": _item_solved(item)})
        elif isinstance(item, str) and item.strip():
            out.append({"id": item.strip(), "solved": None})
    return out


def parse_html_solved(body: str) -> list[dict]:
    low = body.lower()
    if "congratulations" in low and "solved the lab" in low:
        return [{"id": "Solve the lab", "solved": True}]
    if "not solved" in low or "unresolved" in low:
        return [{"id": "Solve the lab", "solved": False}]
    return []


def parse_html_scoreboard(body: str) -> list[dict]:
    out: list[dict] = []
    # data-solved="true/false" or class="... solved/unsolved ..."
    for match in re.finditer(
        r'<[^>]*class="[^"]*(solved|unsolved)[^"]*"[^>]*>(.*?)</[^>]+>',
        body,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        cls, inner = match.group(1).lower(), match.group(2)
        name = re.sub(r"<[^>]+>", " ", inner)
        name = re.sub(r"\s+", " ", name).strip()
        if name:
            out.append({"id": name[:120], "solved": cls == "solved"})
    for match in re.finditer(r'data-(?:challenge|name)="([^"]+)"[^>]*data-solved="(true|false)"', body, flags=re.IGNORECASE):
        out.append({"id": match.group(1).strip(), "solved": match.group(2).lower() == "true"})
    return out


def parse_flag_lines(body: str) -> list[dict]:
    flags = FLAG_RE.findall(body)
    if not flags:
        flags = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return [{"id": f, "solved": None} for f in flags]


def parse_flag_text(body: str) -> list[dict]:
    flags = FLAG_RE.findall(body)
    if flags:
        return [{"id": f, "solved": None} for f in flags]
    text = body.strip()
    return [{"id": text, "solved": None}] if text else []


PARSERS = {
    "juice-shop": parse_juice_shop,
    "ctfd": parse_ctfd,
    "generic-json": parse_generic_json,
    "html-scoreboard": parse_html_scoreboard,
    "html-solved": parse_html_solved,
    "flag-lines": parse_flag_lines,
    "flag-text": parse_flag_text,
}


def parse_body(parser: str, body: str) -> list[dict]:
    fn = PARSERS.get(parser)
    if not fn:
        return []
    try:
        return fn(body)
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
def state_path(eng_dir: Path) -> Path:
    return eng_dir / "objective-state.json"


def load_state(eng_dir: Path) -> dict:
    state = load_json(state_path(eng_dir))
    if not isinstance(state, dict):
        state = {}
    state.setdefault("captured", [])
    state.setdefault("evidence", {})
    state.setdefault("blocked", {})
    state.setdefault("source", {})
    return state


def save_state(eng_dir: Path, state: dict) -> None:
    state_path(eng_dir).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def load_profile(eng_dir: Path) -> dict:
    prof = load_json(eng_dir / "lab-profile.json")
    if isinstance(prof, dict):
        return prof
    return {}


# --------------------------------------------------------------------------- #
# profile detection
# --------------------------------------------------------------------------- #
def load_profiles() -> list[dict]:
    profiles = []
    for path in sorted(labs_dir().glob("*.json")):
        prof = load_json(path)
        if isinstance(prof, dict) and prof.get("id"):
            prof["_path"] = str(path)
            profiles.append(prof)
    return profiles


def detected_service_ports(eng_dir: Path) -> set[int]:
    """Distinct service ports already ingested in cases.db (for network matching)."""
    db = eng_dir / "cases.db"
    if not db.exists():
        return set()
    try:
        import sqlite3
        conn = sqlite3.connect(str(db))
        try:
            rows = conn.execute("SELECT DISTINCT port FROM cases WHERE port IS NOT NULL").fetchall()
        finally:
            conn.close()
        return {int(r[0]) for r in rows if r[0] is not None}
    except Exception:
        return set()


def _as_int_set(values) -> set[int]:
    out: set[int] = set()
    for v in values or []:
        try:
            out.add(int(v))
        except (TypeError, ValueError):
            continue
    return out


def profile_matches(prof: dict, host: str, port: int, base_url: str, detected_ports: set[int] | None = None) -> bool:
    match = prof.get("match") or {}
    if match.get("always"):
        return False  # generic catch-all handled separately

    detected_ports = detected_ports or set()
    ports = _as_int_set(match.get("ports"))
    min_overlap = 0
    try:
        min_overlap = int(match.get("min_port_overlap", 0) or 0)
    except (TypeError, ValueError):
        min_overlap = 0

    # Network profiles can match on a distinctive port signature alone (host is
    # usually a bare IP that carries no fingerprint).
    if min_overlap > 0 and ports:
        if len(ports & detected_ports) >= min_overlap:
            return True

    host_hit = host_matches(host, match.get("hosts") or [])
    port_hit = (not ports) or (port in ports) or bool(ports & detected_ports)

    if host_hit and port_hit:
        return True

    probes = match.get("path_probes") or []
    if probes and base_url:
        for probe in probes:
            if not isinstance(probe, dict):
                continue
            url = join_url(base_url, str(probe.get("path", "")))
            needle = str(probe.get("contains", ""))
            if not needle:
                continue
            ok, body, _err = http_get(url)
            if ok and needle.lower() in body.lower():
                return True
    return False


def cmd_detect(eng_dir: Path, target_override: str | None, profile_override: str | None = None) -> int:
    scope = read_scope(eng_dir)
    target = target_override or str(scope.get("target") or "")
    host, port = target_host_port(target)
    base_url = target if "://" in target else ("https://" + target if target else "")

    profiles = load_profiles()

    chosen = None
    if profile_override:
        for prof in profiles:
            if prof.get("id") == profile_override:
                chosen = prof
                break
        if chosen is None:
            print(f"LAB_PROFILE=none LAB_KIND=unknown NOTE=unknown profile id {profile_override}")
            return 1

    if chosen is None:
        detected = detected_service_ports(eng_dir)
        specific = [p for p in profiles if not (p.get("match") or {}).get("always")]
        specific.sort(key=lambda p: int(p.get("priority", 0)), reverse=True)
        for prof in specific:
            if profile_matches(prof, host, port, base_url, detected):
                chosen = prof
                break

    if chosen is None:
        for prof in profiles:
            if prof.get("id") == "generic":
                chosen = prof
                break
    if chosen is None:
        print("LAB_PROFILE=none LAB_KIND=unknown")
        return 0

    # Don't downgrade an already-resolved specific profile to the generic
    # catch-all (e.g. a bare-IP network target re-detected before ports land).
    if not profile_override and chosen.get("id") == "generic":
        existing = load_profile(eng_dir)
        if existing.get("id") and existing.get("id") != "generic":
            print(f"LAB_PROFILE={existing.get('id')} LAB_KIND={existing.get('kind')} TARGET={target} NOTE=kept existing profile")
            return 0

    resolved = dict(chosen)
    resolved["resolved_from"] = chosen.get("_path", "")
    resolved.pop("_path", None)
    resolved["target"] = target
    (eng_dir / "lab-profile.json").write_text(json.dumps(resolved, indent=2) + "\n", encoding="utf-8")
    print(f"LAB_PROFILE={resolved.get('id')} LAB_KIND={resolved.get('kind')} TARGET={target}")
    return 0


# --------------------------------------------------------------------------- #
# objective resolution
# --------------------------------------------------------------------------- #
def _candidate_sources(profile: dict, state: dict) -> list[dict]:
    """Ordered list of candidate objective sources for this profile."""
    obj = profile.get("objective") or {}
    otype = obj.get("type", "none")
    candidates: list[dict] = []
    if otype == "discover":
        candidates = list(obj.get("candidates") or [])
        cached = state.get("source") or {}
        if cached.get("url") and cached.get("parser"):
            candidates = [cached] + [c for c in candidates if c.get("url") != cached.get("url")]
    else:
        src = obj.get("source") or {}
        if src.get("url"):
            candidates = [src]
        candidates += list(obj.get("candidates") or [])
    return [c for c in candidates if isinstance(c, dict) and c.get("url")]


def _build_objectives(parsed: list[dict], checklist: list[str], captured: set[str]) -> list[dict]:
    solved_map = {str(o["id"]): o.get("solved") for o in parsed}
    objectives: list[dict] = []
    if checklist:
        for name in checklist:
            if name in solved_map:
                s = solved_map[name]
                objectives.append({"id": name, "solved": bool(s), "state": "solved" if s else "unsolved"})
            else:
                # not present in the remote snapshot -> treat as unsolved
                objectives.append({"id": name, "solved": False, "state": "unsolved"})
        return objectives
    for o in parsed:
        name = str(o["id"])
        if o.get("solved") is None:
            # flag-style: solved if captured locally
            solved = name in captured
            objectives.append({"id": name, "solved": solved, "state": "solved" if solved else "unsolved"})
        else:
            objectives.append({"id": name, "solved": bool(o["solved"]), "state": "solved" if o["solved"] else "unsolved"})
    return objectives


def collect_objectives(profile: dict, eng_dir: Path, base_url: str) -> tuple[list[dict], str, bool]:
    """Return (objectives, note, unavailable).

    ``unavailable`` is True only when the profile declares an explicit objective
    source (remote/flag) that could not be read or parsed — the guard then
    fails closed instead of silently passing. A ``discover`` profile that finds
    no objective source is a plain pentest and is not gated (unavailable=False).
    """
    obj = profile.get("objective") or {}
    otype = obj.get("type", "none")
    state = load_state(eng_dir)
    captured = set(state.get("captured") or [])

    if otype == "none":
        return [], "objective type none", False

    if otype == "declared":
        checklist = obj.get("checklist") or []
        if not checklist:
            scope = read_scope(eng_dir)
            extra = scope.get("objectives") or []
            if isinstance(extra, list):
                checklist = [str(x) for x in extra if str(x).strip()]
        return [
            {"id": name, "solved": name in captured, "state": "solved" if name in captured else "unsolved"}
            for name in checklist
        ], "declared checklist", False

    checklist = obj.get("checklist") or []
    last_err = "no objective source"
    for cand in _candidate_sources(profile, state):
        url = join_url(base_url, str(cand["url"]))
        parser = str(cand.get("parser", "generic-json"))
        ok, body, err = http_get(url)
        if not (ok and body):
            last_err = f"{cand['url']}: {err or 'empty response'}"
            continue
        parsed = parse_body(parser, body)
        if not parsed:
            last_err = f"{cand['url']}: returned no parseable objectives (parser={parser})"
            continue
        state["source"] = {"url": cand["url"], "parser": parser}
        save_state(eng_dir, state)
        return _build_objectives(parsed, checklist, captured), f"source={cand['url']}", False

    if otype == "discover":
        # No machine-readable objectives found -> plain pentest, not gated.
        return [], last_err, False
    # remote/flag with an explicit source that failed -> fail closed.
    return [], last_err, True


def print_snapshot(profile: dict, objectives: list[dict], note: str, as_json: bool) -> None:
    pid = profile.get("id", "none")
    kind = profile.get("kind", "unknown")
    otype = (profile.get("objective") or {}).get("type", "none")
    if as_json:
        print(json.dumps({
            "profile": pid, "kind": kind, "objective_type": otype,
            "note": note, "objectives": objectives,
        }, indent=2))
        return
    print(f"LAB_PROFILE={pid} KIND={kind} OBJECTIVE_TYPE={otype}")
    if not objectives:
        print(f"OBJECTIVE_STATE=none NOTE={note}")
        return
    for o in objectives:
        print(f"OBJECTIVE {o['id']} {o['state']}")
    total = len(objectives)
    solved = sum(1 for o in objectives if o["state"] == "solved")
    print(f"SUMMARY total={total} solved={solved} unsolved={total - solved}")


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_list(eng_dir: Path) -> int:
    profile = load_profile(eng_dir)
    if not profile:
        print("no lab-profile.json (run: lab_objective.py detect <dir>)")
        return 0
    obj = profile.get("objective") or {}
    print(f"profile={profile.get('id')} kind={profile.get('kind')} type={obj.get('type')}")
    for name in obj.get("checklist") or []:
        print(name)
    for branch in profile.get("recall_branches") or []:
        if isinstance(branch, dict):
            print(f"[branch] {branch.get('objective')} :: {branch.get('vuln_class')} :: {branch.get('route')}")
    return 0


def cmd_snapshot(eng_dir: Path, as_json: bool) -> int:
    profile = load_profile(eng_dir)
    if not profile:
        print("LAB_PROFILE=none OBJECTIVE_TYPE=none NOTE=no profile resolved")
        return 0
    scope = read_scope(eng_dir)
    target = str(scope.get("target") or profile.get("target") or "")
    base_url = target if "://" in target else ("https://" + target if target else "")
    objectives, note = collect_objectives(profile, eng_dir, base_url)[:2]
    print_snapshot(profile, objectives, note, as_json)
    return 0


def cmd_capture(eng_dir: Path, objective: str, evidence: str) -> int:
    if not objective:
        print("ERROR: capture requires an objective name", file=sys.stderr)
        return 2
    state = load_state(eng_dir)
    if objective not in state["captured"]:
        state["captured"].append(objective)
    if evidence:
        state["evidence"][objective] = evidence
    save_state(eng_dir, state)
    print(f"CAPTURED {objective}" + (f" evidence={evidence}" if evidence else ""))
    return 0


def cmd_guard(eng_dir: Path) -> int:
    if os.environ.get("REDTEAM_SKIP_RECALL_FINALIZE_GUARD") == "1":
        print("PASS recall guard skipped (REDTEAM_SKIP_RECALL_FINALIZE_GUARD=1)")
        return 0
    profile = load_profile(eng_dir)
    if not profile:
        print("PASS no lab profile resolved")
        return 0
    scope = read_scope(eng_dir)
    target = str(scope.get("target") or profile.get("target") or "")
    base_url = target if "://" in target else ("https://" + target if target else "")
    objectives, note, unavailable = collect_objectives(profile, eng_dir, base_url)
    if not objectives:
        if unavailable:
            print(f"BLOCK objective source unavailable ({note})")
            return 1
        # No machine-readable objectives: not a recall-gated lab.
        print(f"PASS no objectives ({note})")
        return 0
    missing = [o["id"] for o in objectives if o["state"] != "solved"]
    if missing:
        print("BLOCK " + ", ".join(missing))
        return 1
    print("PASS all objective checklist items solved")
    return 0


def usage() -> int:
    print(__doc__)
    return 2


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return usage()
    action, eng_dir_arg = argv[1], argv[2]
    eng_dir = Path(eng_dir_arg).resolve()
    rest = argv[3:]

    if action == "detect":
        target = None
        profile_override = None
        args = list(rest)
        if "--profile" in args:
            idx = args.index("--profile")
            profile_override = args[idx + 1] if idx + 1 < len(args) else None
            del args[idx:idx + 2]
        if args:
            target = args[0]
        return cmd_detect(eng_dir, target, profile_override)
    if action == "list":
        return cmd_list(eng_dir)
    if action == "snapshot":
        return cmd_snapshot(eng_dir, "--json" in rest)
    if action == "capture":
        objective = rest[0] if rest else ""
        evidence = ""
        if "--evidence" in rest:
            idx = rest.index("--evidence")
            if idx + 1 < len(rest):
                evidence = rest[idx + 1]
        return cmd_capture(eng_dir, objective, evidence)
    if action == "guard":
        return cmd_guard(eng_dir)
    if action == "show":
        profile = load_profile(eng_dir)
        print(profile.get("resolved_from") or profile.get("_path") or "unresolved")
        return 0
    return usage()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
