"""Command-line entry point: `leaklens scan [PATH]`."""
from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .report import render_json, render_text
from .scanner import DEFAULT_MAX_BLOB, scan_repo
from .walker import GitError


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="leaklens", description="Find leaked API keys in your git history.")
    p.add_argument("--version", action="version", version=f"leaklens {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a local git repo's full history")
    s.add_argument("path", nargs="?", default=".", help="Path to the repo (default: current dir)")
    s.add_argument("--entropy", action="store_true", help="Also flag high-entropy strings (noisier)")
    s.add_argument("--json", action="store_true", help="Machine-readable output")
    s.add_argument("--max-blob-mb", type=float, default=DEFAULT_MAX_BLOB / 1024 / 1024,
                   help="Skip file versions larger than this (default: 2)")

    args = p.parse_args(argv)

    t0 = time.perf_counter()
    try:
        res = scan_repo(args.path, use_entropy=args.entropy, max_blob=int(args.max_blob_mb * 1024 * 1024))
    except GitError as e:
        print(f"leaklens: {e}", file=sys.stderr)
        return 2
    elapsed = time.perf_counter() - t0

    if args.json:
        print(render_json(res))
    else:
        print(render_text(res))
        print(f"\n(scanned in {elapsed:.2f}s)")

    # Exit 1 when high-confidence leaks exist, so this works in CI and pre-commit later.
    return 1 if any(f.confidence == "high" for f in res.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
