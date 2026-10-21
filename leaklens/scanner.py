"""Scan blobs, then build a per-secret timeline from commit history."""
from __future__ import annotations

import fnmatch
import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache

from . import walker
from .rules import ALL_KEYWORDS, ENTROPY_CANDIDATE, ENTROPY_THRESHOLD, RULES, shannon_entropy

# Paths that are almost never hand-written secrets but are full of random strings.
SKIP_GLOBS = [
    "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "*.min.js", "*.map", "*.svg", "node_modules/*", "*/node_modules/*",
]
DEFAULT_MAX_BLOB = 2 * 1024 * 1024  # 2 MB: bigger blobs are rarely source


@dataclass(frozen=True)
class Commit:
    sha: str
    timestamp: int
    author: str
    subject: str


@dataclass
class Finding:
    rule_id: str
    provider: str
    secret: bytes
    explain: str
    rotate_url: str
    confidence: str = "high"
    # (blob sha, path, line number) for every place this exact secret appears
    locations: list[tuple[str, str, int]] = field(default_factory=list)
    added_in: list[tuple[Commit, str]] = field(default_factory=list)
    removed_in: list[tuple[Commit, str]] = field(default_factory=list)
    in_head: bool = False

    @property
    def masked(self) -> str:
        s = self.secret.decode("utf-8", "replace")
        # Plain ASCII on purpose: fancy bullets turn into mojibake when output
        # is piped on Windows (cp437) or shown in CI logs.
        if len(s) <= 10:
            return s[:2] + "****"
        return f"{s[:4]}******{s[-3:]}"


@dataclass
class ScanResult:
    repo: str
    blobs_total: int
    blobs_scanned: int
    findings: list[Finding]


# All skip globs compiled into ONE regex. Two reasons:
#  - fnmatch() calls os.path.normcase() on every call. That's a no-op on Linux
#    but a Windows API call (LCMapStringEx) on Windows: profiling showed 40% of
#    scan time there. Git paths always use "/" and are case-sensitive, so we
#    don't want normcase anyway.
#  - One regex match beats looping over 10 patterns.
_SKIP_RX = re.compile("|".join(fnmatch.translate(g) for g in SKIP_GLOBS))


@lru_cache(maxsize=65536)  # the same path shows up once per version of the file
def _skip(path: str) -> bool:
    return bool(_SKIP_RX.match(path) or _SKIP_RX.match(path.rsplit("/", 1)[-1]))


def _line_no(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def scan_blob(blob: walker.Blob, use_entropy: bool) -> list[tuple[str, bytes, int, str]]:
    """Return (rule_id, secret, line, confidence) matches in one blob."""
    data = blob.data
    if b"\x00" in data[:8000]:  # binary file
        return []
    hits: list[tuple[str, bytes, int, str]] = []
    seen: set[bytes] = set()
    # Look for every keyword once per blob, instead of once per rule through a
    # generator. Most blobs contain none, so they skip all regexes in one step.
    present = {k for k in ALL_KEYWORDS if k in data}
    for rule in RULES if present else ():
        if rule.keywords and present.isdisjoint(rule.keywords):
            continue
        for m in rule.pattern.finditer(data):
            secret = m.group(1)
            seen.add(secret)
            hits.append((rule.id, secret, _line_no(data, m.start(1)), "high"))
    if use_entropy:
        for m in ENTROPY_CANDIDATE.finditer(data):
            secret = m.group(1)
            if secret in seen:
                continue
            if shannon_entropy(secret) >= ENTROPY_THRESHOLD:
                hits.append(("generic-high-entropy", secret, _line_no(data, m.start(1)), "low"))
    return hits


def _commit_index(repo: str, wanted: set[str]) -> tuple[dict[str, list], dict[str, list]]:
    """One pass over `git log --raw` to find which commits added/removed each wanted blob."""
    out = walker.git(
        # Merges show no --raw diff by default, so each change is attributed to
        # the commit that actually made it, on whatever branch.
        repo, "log", "--all", "--raw", "--no-abbrev", "--no-renames",
        "--format=\x1e%H\x1f%at\x1f%an\x1f%s",
    ).decode("utf-8", "replace")

    added: dict[str, list] = defaultdict(list)
    removed: dict[str, list] = defaultdict(list)
    for record in out.split("\x1e")[1:]:
        header, _, raw = record.partition("\n")
        sha, ts, author, subject = (header.split("\x1f") + ["", "", "", ""])[:4]
        commit = Commit(sha, int(ts or 0), author, subject)
        for line in raw.splitlines():
            if not line.startswith(":"):
                continue
            meta, _, path = line.partition("\t")
            f = meta.split()
            if len(f) < 5:
                continue
            old, new = f[2], f[3]
            if new in wanted and new != old:
                added[new].append((commit, path, old))
            if old in wanted and new != old:
                removed[old].append((commit, path, new))
    return added, removed


def _head_blobs(repo: str) -> set[str]:
    try:
        out = walker.git(repo, "ls-tree", "-r", "HEAD").decode("utf-8", "replace")
    except walker.GitError:
        return set()
    return {line.split()[2] for line in out.splitlines() if len(line.split()) >= 3}


def scan_repo(repo: str, use_entropy: bool = False, max_blob: int = DEFAULT_MAX_BLOB) -> ScanResult:
    walker.ensure_repo(repo)
    refs = walker.list_blobs(repo, max_blob)
    to_scan = [r for r in refs if not _skip(r.path)]

    rules = {r.id: r for r in RULES}
    by_secret: dict[tuple[str, bytes], Finding] = {}

    for blob in walker.read_blobs(repo, to_scan):
        for rule_id, secret, line, conf in scan_blob(blob, use_entropy):
            key = (rule_id, secret)
            f = by_secret.get(key)
            if f is None:
                r = rules.get(rule_id)
                f = Finding(
                    rule_id=rule_id,
                    provider=r.provider if r else "Unknown (high-entropy string)",
                    secret=secret,
                    explain=r.explain if r else "Looks like a random secret assigned to a sensitive variable name. Check it by hand.",
                    rotate_url=r.rotate_url if r else "",
                    confidence=conf,
                )
                by_secret[key] = f
            f.locations.append((blob.ref.sha, blob.ref.path, line))

    findings = list(by_secret.values())
    if findings:
        wanted = {loc[0] for f in findings for loc in f.locations}
        added, removed = _commit_index(repo, wanted)
        head = _head_blobs(repo)
        for f in findings:
            blob_shas = {loc[0] for loc in f.locations}
            # A file edit swaps one blob for another. If both versions contain
            # the secret, that's neither an addition nor a removal of it.
            for b in blob_shas:
                f.added_in.extend((c, p) for c, p, other in added.get(b, []) if other not in blob_shas)
                f.removed_in.extend((c, p) for c, p, other in removed.get(b, []) if other not in blob_shas)
            f.added_in.sort(key=lambda cp: cp[0].timestamp)
            f.removed_in.sort(key=lambda cp: cp[0].timestamp)
            f.in_head = bool(blob_shas & head)

    findings.sort(key=lambda f: (f.confidence != "high", not f.in_head, f.provider))
    return ScanResult(repo, len(refs), len(to_scan), findings)
