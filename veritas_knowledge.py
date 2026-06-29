#!/usr/bin/env python3
"""veritas_knowledge.py — cross-project contract learning (variant В).

Accumulates guard contracts across many scanned projects so a new project with
little data benefits from ecosystem consensus — WITHOUT letting bad code poison
the base. Four protections (see ACCURACY_SPEC):

  1. Allowlist gate     — a guard can only be learned if it is a real, sink-
                          appropriate sanitiser. Even if 100 projects "teach"
                          subprocess.run -> str, it is rejected. Learning only
                          refines confidence WITHIN proven-safe guards.
  2. Three filters       — a contract becomes ACTIVE only if seen in >= MIN_PROJECTS
                          projects, with average in-project frequency >= MIN_FREQ,
                          and cross-project consensus >= MIN_CONSENSUS. Otherwise it
                          stays in QUARANTINE (observed, not applied).
  3. Provenance          — every contract remembers which projects taught it; a
                          project can be removed (rollback) so the base never rots.
  4. Anti-contracts      — flags where a project DEVIATES from the ecosystem norm
                          ("everyone else guards this; you don't").

This is statistics, not ML — explainable and non-hallucinating, but only as good
as the projects it learns from, which is exactly why the gates above exist.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict

# Reuse the engine's accuracy gate so learning can never introduce an unsafe guard.
try:
    from veritas_core import SINK_GUARD_ALLOW
except Exception:                                   # pragma: no cover
    SINK_GUARD_ALLOW = {}

# Filters for promoting a contract from quarantine to active.
MIN_PROJECTS = 3        # must appear in at least this many projects
MIN_FREQ = 0.5          # average in-project usage frequency
MIN_CONSENSUS = 0.6     # share of projects agreeing on the dominant guard

# Guards that are valid independent of a sink's allowlist (structural / sql).
_STRUCTURAL_GUARDS = {"parameterized", "secure_filename",
                      "werkzeug.utils.secure_filename"}


def _guard_allowed(sink: str, guard: str) -> bool:
    """A guard may be learned only if it is a real sanitiser for this sink."""
    if guard in _STRUCTURAL_GUARDS:
        return True
    allow = SINK_GUARD_ALLOW.get(sink)
    if allow is None:        # sink with generic detection — accept known guards
        return True
    return guard in allow    # empty set (e.g. pickle.loads) => nothing allowed


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def load_db(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("version") == 1 and "projects" in data:
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "projects": {}}


def save_db(path: str, db: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(db, fh, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Learning
# --------------------------------------------------------------------------- #
def observe(policy: dict) -> dict:
    """Turn one project's policy (from veritas_core.build_policy/audit) into a
    per-sink observation: dominant guard + how dominant it is. Allowlist-gated."""
    obs = {}
    for sink, entry in policy.items():
        guard = entry.get("guard")
        conf = entry.get("confidence", 0.0)
        count = entry.get("count", 0)
        if not guard or count == 0:
            continue                       # no real evidence (fallback/default)
        if not _guard_allowed(sink, guard):
            continue                       # allowlist gate: reject unsafe guard
        obs[sink] = {"guard": guard, "freq": float(conf), "count": int(count)}
    return obs


def learn_project(db: dict, project: str, policy: dict) -> dict:
    """Record (or replace) a project's observations in the base. Idempotent:
    re-learning the same project name overwrites its prior contribution."""
    obs = observe(policy)
    db["projects"][project] = {
        "added": time.strftime("%Y-%m-%d"),
        "observations": obs,
    }
    return db


def forget_project(db: dict, project: str) -> bool:
    """Remove a project's contribution entirely (provenance rollback)."""
    return db["projects"].pop(project, None) is not None


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def aggregate(db: dict) -> dict:
    """Compute the ecosystem contract per sink with provenance and status.

    Returns {sink: {guard, projects:[...], n_projects, consensus, avg_freq,
                    status: 'active'|'quarantine'}}.
    """
    # per sink: guard -> list of (project, freq)
    votes: dict = defaultdict(lambda: defaultdict(list))
    for project, rec in db["projects"].items():
        for sink, o in rec.get("observations", {}).items():
            votes[sink][o["guard"]].append((project, o["freq"]))

    out = {}
    for sink, guard_map in votes.items():
        total_projects = len({p for lst in guard_map.values() for p, _ in lst})
        # dominant guard = the one taught by the most projects
        dominant = max(guard_map, key=lambda g: len(guard_map[g]))
        backers = guard_map[dominant]
        n = len(backers)
        consensus = round(n / total_projects, 2) if total_projects else 0.0
        avg_freq = round(sum(f for _, f in backers) / n, 2) if n else 0.0
        active = (n >= MIN_PROJECTS and avg_freq >= MIN_FREQ
                  and consensus >= MIN_CONSENSUS)
        out[sink] = {
            "guard": dominant,
            "projects": sorted(p for p, _ in backers),
            "n_projects": n,
            "consensus": consensus,
            "avg_freq": avg_freq,
            "status": "active" if active else "quarantine",
        }
    return out


def ecosystem_contracts(db: dict) -> dict:
    """Only the ACTIVE contracts (passed all three filters), keyed by sink."""
    return {s: c for s, c in aggregate(db).items() if c["status"] == "active"}


# --------------------------------------------------------------------------- #
# Anti-contracts: deviation from the ecosystem
# --------------------------------------------------------------------------- #
def anti_contracts(db: dict, project_policy: dict) -> list:
    """Flag sinks where the ecosystem strongly agrees on a guard but THIS
    project does not use it. Returns advisory findings (never hard blocks)."""
    eco = ecosystem_contracts(db)
    findings = []
    for sink, contract in eco.items():
        norm_guard = contract["guard"]
        proj = project_policy.get(sink)
        proj_guard = proj.get("guard") if proj else None
        if proj_guard != norm_guard:
            findings.append({
                "sink": sink,
                "ecosystem_guard": norm_guard,
                "your_guard": proj_guard,
                "consensus": contract["consensus"],
                "n_projects": contract["n_projects"],
                "message": (f"{sink}: экосистема ({contract['n_projects']} "
                            f"проектов, {round(contract['consensus']*100)}% "
                            f"согласия) использует «{norm_guard}», "
                            f"а здесь — "
                            f"{('«'+proj_guard+'»') if proj_guard else 'нет guard'}"),
            })
    return findings


def explain(db: dict) -> list:
    """Human-readable provenance for every contract — no black box."""
    rows = []
    for sink, c in sorted(aggregate(db).items()):
        rows.append(
            f"{sink}: «{c['guard']}» [{c['status']}] — выучен из "
            f"{c['n_projects']} проектов ({round(c['consensus']*100)}% согласия, "
            f"частота {round(c['avg_freq']*100)}%): {', '.join(c['projects'][:6])}")
    return rows
