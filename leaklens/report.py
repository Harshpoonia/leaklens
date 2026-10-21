"""Terminal + JSON output. Secrets are always masked; raw values never leave memory."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from .scanner import Commit, Finding, ScanResult

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


RED, YEL, GRN, DIM, BOLD = "31", "33", "32", "2", "1"


def _date(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


TIMELINE_LIMIT = 8


@dataclass(frozen=True)
class Event:
    commit: Commit
    kind: str  # "added" | "removed" | "renamed"
    text: str

    @property
    def symbol(self) -> str:
        return {"added": "+", "removed": "-", "renamed": "~"}[self.kind]


def timeline(f: Finding) -> list[Event]:
    """Merge additions and removals into one chronological list.

    If a single commit removes the secret from one path and adds it at another,
    that's a rename/move, not a removal plus a fresh leak.
    """
    by_commit: dict[str, tuple[Commit, list[str], list[str]]] = {}
    for commit, path in f.added_in:
        by_commit.setdefault(commit.sha, (commit, [], []))[1].append(path)
    for commit, path in f.removed_in:
        by_commit.setdefault(commit.sha, (commit, [], []))[2].append(path)

    events: list[Event] = []
    for commit, added, removed in by_commit.values():
        added, removed = sorted(added), sorted(removed)
        while added and removed:
            events.append(Event(commit, "renamed", f"moved {removed.pop(0)} -> {added.pop(0)}"))
        events += [Event(commit, "added", f"added to {p}") for p in added]
        events += [Event(commit, "removed", f"removed from {p}") for p in removed]
    events.sort(key=lambda e: e.commit.timestamp)
    return events


def _status(f: Finding) -> str:
    if f.in_head:
        return _c(RED, "STILL IN YOUR CURRENT CODE")
    return _c(YEL, "deleted from code, but STILL IN GIT HISTORY")


def render_text(res: ScanResult) -> str:
    out: list[str] = []
    out.append(_c(BOLD, f"LeakLens scan: {res.repo}"))
    out.append(_c(DIM, f"{res.blobs_scanned} unique file versions scanned ({res.blobs_total} total in history)\n"))

    if not res.findings:
        out.append(_c(GRN, "No secrets found. Nice."))
        return "\n".join(out)

    high = [f for f in res.findings if f.confidence == "high"]
    out.append(_c(BOLD, f"Found {len(res.findings)} secret(s), {len(high)} high-confidence.\n"))

    for i, f in enumerate(res.findings, 1):
        tag = "" if f.confidence == "high" else _c(DIM, "  [low confidence: verify by hand]")
        out.append(_c(BOLD, f"[{i}] {f.provider}: {f.masked}") + tag)
        out.append(f"    Status : {_status(f)}")
        paths = sorted({f"{p}:{ln}" for _, p, ln in f.locations})
        out.append(f"    Where  : {', '.join(paths[:3])}" + (f" (+{len(paths) - 3} more)" if len(paths) > 3 else ""))

        out.append("    Timeline:")
        events = timeline(f)
        for ev in events[:TIMELINE_LIMIT]:
            out.append(f"      {ev.symbol} {_date(ev.commit.timestamp)}  {ev.commit.sha[:8]}  {ev.text}  ({ev.commit.subject[:50]})")
        if len(events) > TIMELINE_LIMIT:
            out.append(_c(DIM, f"      ... +{len(events) - TIMELINE_LIMIT} more event(s), use --json for the full list"))
        if not events:
            out.append(_c(DIM, "      (no commit info: blob may only exist in a stash or unreachable ref)"))

        out.append(f"    Risk   : {f.explain}")
        if not f.in_head:
            out.append(_c(DIM, "             Deleting the line didn't help: anyone can still read old commits."))
        if f.rotate_url:
            out.append(f"    Fix    : 1) Revoke/rotate it now -> {f.rotate_url}")
            out.append("             2) Put the new key in a .env file and read it with os.environ / process.env")
            out.append("             3) Add .env to .gitignore before your next commit")
        out.append("")

    out.append(_c(BOLD, "Rotation matters more than rewriting history. A leaked key is burned even after you scrub it."))
    return "\n".join(out)


def render_json(res: ScanResult) -> str:
    return json.dumps(
        {
            "repo": res.repo,
            "blobs_total": res.blobs_total,
            "blobs_scanned": res.blobs_scanned,
            "findings": [
                {
                    "rule": f.rule_id,
                    "provider": f.provider,
                    "secret_masked": f.masked,
                    "confidence": f.confidence,
                    "in_head": f.in_head,
                    "locations": [{"blob": b, "path": p, "line": ln} for b, p, ln in f.locations],
                    "added_in": [{"commit": c.sha, "date": _date(c.timestamp), "path": p} for c, p in f.added_in],
                    "removed_in": [{"commit": c.sha, "date": _date(c.timestamp), "path": p} for c, p in f.removed_in],
                    "rotate_url": f.rotate_url,
                }
                for f in res.findings
            ],
        },
        indent=2,
    )
