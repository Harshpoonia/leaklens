"""Benchmark LeakLens' blob scanning against two other ways to scan git history.

    blob      LeakLens: scan every unique blob once, then map hits to commits.
    diff      Per-commit diffs (`git log -p`), scanning only added lines.
              This is roughly how Gitleaks / most history scanners work.
    snapshot  Naive: for every commit, scan every file in that commit's tree.
              What most first attempts do. Can be capped with --snapshot-limit
              and extrapolated, because it gets very slow on big repos.

All three use the *same* rules and skip list, so differences are purely about
how history is traversed. Each method also reports which secrets it found, so
you can check that speed isn't coming from missing things.

Usage:
    python bench/benchmark.py PATH_TO_REPO [--runs 3] [--snapshot-limit 300]
    python bench/benchmark.py --synthetic 3000 --files 300   # build a test repo with planted keys
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from leaklens import walker  # noqa: E402
from leaklens.rules import RULES  # noqa: E402
from leaklens.scanner import DEFAULT_MAX_BLOB, _skip, scan_blob, scan_repo  # noqa: E402

Secret = tuple  # (rule_id, secret bytes)


@dataclass
class Result:
    method: str
    seconds: list[float] = field(default_factory=list)
    bytes_scanned: int = 0
    units: int = 0           # blobs / diff hunks / (commit, file) pairs scanned
    secrets: set = field(default_factory=set)
    estimated: bool = False  # True when extrapolated from a sample

    @property
    def median(self) -> float:
        return statistics.median(self.seconds)


# --------------------------------------------------------------------------- methods

def run_blob(repo: str) -> set:
    """Timed: exactly what `leaklens scan` does, including the commit timeline."""
    res = scan_repo(repo)
    return {(f.rule_id, f.secret) for f in res.findings if f.confidence == "high"}


def blob_stats(repo: str) -> tuple[int, int]:
    """Untimed: how much data the blob method reads."""
    refs = [r for r in walker.list_blobs(repo, DEFAULT_MAX_BLOB) if not _skip(r.path)]
    return sum(r.size for r in refs), len(refs)


def run_diff(repo: str) -> tuple[set, int, int]:
    proc = subprocess.Popen(
        ["git", "-C", repo, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
         "--no-renames", "--format=%x1e%H"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    assert proc.stdout
    secrets: set = set()
    path, skip, nbytes, files = "", False, 0, 0
    for line in proc.stdout:
        if line.startswith(b"+++ "):
            path = line[6:].rstrip(b"\n").decode("utf-8", "replace") if line.startswith(b"+++ b/") else ""
            skip = not path or _skip(path)
            files += 1
            continue
        if skip or not line.startswith(b"+"):
            continue
        nbytes += len(line)
        for rule in RULES:
            for m in rule.finditer(line):
                secrets.add((rule.id, m.group(1)))
    proc.wait()
    return secrets, nbytes, files


def run_snapshot(repo: str, limit: int | None) -> tuple[set, int, int, int, int]:
    commits = walker.git(repo, "rev-list", "--all").decode().split()
    total = len(commits)
    if limit and total > limit:
        # Evenly spaced sample across history, so early tiny trees and late big
        # trees are both represented.
        step = total / limit
        commits = [commits[int(i * step)] for i in range(limit)]

    secrets: set = set()
    nbytes = pairs = 0
    for sha in commits:
        out = walker.git(repo, "ls-tree", "-r", "-l", sha).decode("utf-8", "replace")
        refs = []
        for row in out.splitlines():
            meta, _, path = row.partition("\t")
            parts = meta.split()
            if len(parts) < 4 or parts[1] != "blob" or parts[3] == "-":
                continue
            size = int(parts[3])
            if size > DEFAULT_MAX_BLOB or _skip(path):
                continue
            refs.append(walker.BlobRef(parts[2], path, size))
        for blob in walker.read_blobs(repo, refs):
            nbytes += blob.ref.size
            pairs += 1
            for rule_id, secret, _, conf in scan_blob(blob, use_entropy=False):
                if conf == "high":
                    secrets.add((rule_id, secret))
    return secrets, nbytes, pairs, len(commits), total


# --------------------------------------------------------------------------- synthetic repo

def _fake_secret(rng: random.Random, kind: str) -> str:
    al = string.ascii_letters + string.digits
    if kind == "google":
        return "AIza" + "".join(rng.choice(al + "_-") for _ in range(35))
    if kind == "openai":
        return "sk-proj-" + "".join(rng.choice(al) for _ in range(40))
    if kind == "aws":
        return "AKIA" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return "ghp_" + "".join(rng.choice(al) for _ in range(36))


def _code_line(rng: random.Random) -> str:
    w = lambda: "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 10)))  # noqa: E731
    return rng.choice([
        f"def {w()}({w()}, {w()}):",
        f"    {w()} = {w()}.{w()}({rng.randint(0, 999)})",
        f"    return {w()} + {w()}",
        f"# {w()} {w()} {w()} {w()}",
        f"{w().upper()} = \"{w()}\"",
        f"    if {w()} > {rng.randint(0, 99)}:",
    ])


def make_synthetic(path: str, n_commits: int, n_files: int, n_secrets: int, seed: int = 7) -> set:
    """Build a repo with git fast-import. Returns the ground-truth planted secrets."""
    rng = random.Random(seed)
    subprocess.run(["git", "init", "-q", path], check=True)
    files = {f"src/mod_{i:04d}.py": [_code_line(rng) for _ in range(rng.randint(40, 200))]
             for i in range(n_files)}

    # Distinct commits, so exactly n_secrets get planted (a dict of random keys
    # silently dropped collisions).
    plant_at = set(rng.sample(range(2, n_commits + 1), k=min(n_secrets, n_commits - 1)))
    truth: set = set()
    planted: list[tuple[str, str, int]] = []  # (file, secret, commit it was planted in)

    buf: list[bytes] = []

    def data(s: str) -> None:
        b = s.encode()
        buf.append(f"data {len(b)}\n".encode() + b + b"\n")

    ts = 1_600_000_000
    for c in range(1, n_commits + 1):
        if c == 1:
            touched = set(files)  # initial commit adds every file
        else:
            touched = set(rng.sample(sorted(files), k=min(len(files), rng.randint(1, 4))))
            # sorted(): iterating a set of strings follows hash order, which is
            # randomized per process, so the repo came out different every run.
            for f in sorted(touched):
                lines = files[f]
                for _ in range(rng.randint(1, 6)):
                    lines.insert(rng.randrange(len(lines) + 1), _code_line(rng))
        if c in plant_at:
            kind = rng.choice(["google", "openai", "aws", "github"])
            secret = _fake_secret(rng, kind)
            rule = {"google": "google-api-key", "openai": "openai-api-key",
                    "aws": "aws-access-key-id", "github": "github-token"}[kind]
            truth.add((rule, secret.encode()))
            f = rng.choice(sorted(files))
            idx = rng.randrange(len(files[f]) + 1)
            files[f].insert(idx, f'API_KEY = "{secret}"')
            planted.append((f, secret, c))
            touched.add(f)
        # Later, delete some planted secrets from the code: the classic "I removed
        # it" case. Only secrets from an EARLIER commit, otherwise a key is planted
        # and deleted before ever being committed, yet still counted as ground truth.
        if planted and planted[0][2] < c and rng.random() < 0.02:
            f, secret, _ = planted.pop(0)
            files[f] = [ln for ln in files[f] if secret not in ln]
            touched.add(f)

        buf.append(b"commit refs/heads/main\n")
        buf.append(f"mark :{c}\ncommitter Bench <bench@example.com> {ts + c * 3600} +0000\n".encode())
        data(f"commit {c}")
        if c > 1:
            buf.append(f"from :{c - 1}\n".encode())
        for f in sorted(touched):
            buf.append(f"M 100644 inline {f}\n".encode())
            data("\n".join(files[f]) + "\n")
        buf.append(b"\n")

    subprocess.run(["git", "-C", path, "fast-import", "--quiet"], input=b"".join(buf), check=True)
    subprocess.run(["git", "-C", path, "checkout", "-q", "main"], check=True)
    return truth


# --------------------------------------------------------------------------- driver

def human_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def bench(repo: str, runs: int, snapshot_limit: int | None, truth: set | None) -> dict:
    n_commits = int(walker.git(repo, "rev-list", "--all", "--count"))
    results: dict[str, Result] = {m: Result(m) for m in ["blob", "diff", "snapshot"]}

    for i in range(runs):
        for name in ["blob", "diff", "snapshot"]:
            r = results[name]
            t0 = time.perf_counter()
            if name == "blob":
                r.secrets = run_blob(repo)
            elif name == "diff":
                r.secrets, r.bytes_scanned, r.units = run_diff(repo)
            else:
                r.secrets, r.bytes_scanned, r.units, sampled, total = run_snapshot(repo, snapshot_limit)
            dt = time.perf_counter() - t0
            if name == "snapshot" and sampled < total:
                dt *= total / sampled
                r.bytes_scanned = int(r.bytes_scanned * total / sampled)
                r.units = int(r.units * total / sampled)
                r.estimated = True
            r.seconds.append(dt)
        print(f"  run {i + 1}/{runs} done", file=sys.stderr)
    results["blob"].bytes_scanned, results["blob"].units = blob_stats(repo)

    reference = truth if truth is not None else set().union(*(r.secrets for r in results.values() if not r.estimated))
    base = results["blob"].median

    print(f"\nRepo: {repo}")
    print(f"Commits: {n_commits:,}   Runs: {runs} (median shown)")
    if truth is not None:
        print(f"Ground truth: {len(truth)} planted secrets")
    print()
    hdr = f"{'method':<10} {'time':>10} {'vs blob':>9} {'data scanned':>14} {'units':>10} {'found':>7} {'recall':>8}"
    print(hdr)
    print("-" * len(hdr))
    for r in results.values():
        t = f"{r.median:.2f}s" + ("*" if r.estimated else "")
        rel = "1.0x" if r is results["blob"] else f"{r.median / base:.1f}x"
        found = len(r.secrets & reference) if reference else len(r.secrets)
        recall = f"{found / len(reference):.0%}" if reference else "n/a"
        if r.estimated and truth is None:
            recall = "(sample)"
        print(f"{r.method:<10} {t:>10} {rel:>9} {human_bytes(r.bytes_scanned):>14} {r.units:>10,} {len(r.secrets):>7} {recall:>8}")
    if results["snapshot"].estimated:
        print(f"\n* snapshot extrapolated from {snapshot_limit} evenly spaced commits")

    # A recall number alone hides *what* was missed. Spell it out.
    if reference:
        for r in results.values():
            missed = reference - r.secrets
            if missed and not (r.estimated and truth is None):
                shown = ", ".join(f"{rule}:{s[:4].decode()}...{s[-3:].decode()}" for rule, s in sorted(missed))
                print(f"  {r.method} missed {len(missed)}: {shown}")

    return {
        "repo": repo,
        "commits": n_commits,
        "runs": runs,
        "ground_truth": len(truth) if truth is not None else None,
        "results": {
            k: {
                "median_s": round(v.median, 3),
                "all_s": [round(s, 3) for s in v.seconds],
                "bytes_scanned": v.bytes_scanned,
                "units": v.units,
                "secrets_found": len(v.secrets),
                "estimated": v.estimated,
            }
            for k, v in results.items()
        },
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("repo", nargs="?", help="Path to a git repo")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--snapshot-limit", type=int, default=300,
                   help="Max commits for the snapshot method (0 = all). Larger repos get extrapolated.")
    p.add_argument("--synthetic", type=int, metavar="N", help="Build a synthetic repo with N commits instead")
    p.add_argument("--files", type=int, default=300, help="Files in the synthetic repo")
    p.add_argument("--secrets", type=int, default=25, help="Secrets to plant in the synthetic repo")
    p.add_argument("--out", help="Write results as JSON to this file")
    args = p.parse_args()

    limit = args.snapshot_limit or None
    truth = None
    tmp = None
    if args.synthetic:
        tmp = tempfile.mkdtemp(prefix="leaklens-bench-")
        print(f"Building synthetic repo: {args.synthetic} commits, {args.files} files...", file=sys.stderr)
        truth = make_synthetic(tmp, args.synthetic, args.files, args.secrets)
        repo = tmp
    elif args.repo:
        repo = args.repo
    else:
        p.error("give a repo path or --synthetic N")

    report = bench(repo, args.runs, limit, truth)
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nSaved {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
