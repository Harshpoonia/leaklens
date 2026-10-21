# Benchmark results

Three ways to scan full git history, all using the **same rules and skip list**,
so the only difference is how history is traversed.

| Method | What it does |
|---|---|
| **blob** (LeakLens) | Scan each unique file version once, then map hits to commits |
| **diff** | `git log -p`, scan only added lines in each commit (how Gitleaks-style tools work) |
| **snapshot** | For every commit, scan every file in that commit (the naive first attempt) |

Environment (unless noted): 2-core Intel Xeon @ 2.10 GHz, Python 3.13, git 2.43. Median of 3 runs.
Absolute times vary by ±20% with machine load; compare ratios within a run.
Reproduce with `python bench/benchmark.py <repo>`; raw numbers are in `results/`.

## Real repo: psf/requests (6,736 commits, @611c616)

| Method | Time | vs blob | Data scanned | Secrets found |
|---|---:|---:|---:|---:|
| blob | **1.35 s** | 1.0x | 116 MB | 1 |
| diff | 1.39 s | 1.0x | 9 MB | 1 |
| snapshot | ~114 s\* | 84.7x | ~7 GB | 1 |

The one finding is a set of intentional test-certificate private keys in `tests/certs/`.
That's a real match but not a real leak, which points at the next feature: an allowlist for test fixtures.

## Synthetic repo (3,000 commits, 300 files, 25 planted keys)

| Method | Time | vs blob | Data scanned | Recall |
|---|---:|---:|---:|---:|
| blob | **0.83 s** | 1.0x | 32 MB | **100%** |
| diff | 1.24 s | 1.5x | 2 MB | 100% |
| snapshot | ~62 s\* | 74.5x | ~4 GB | 88%\* |

\* Snapshot was run on 300 evenly spaced commits and extrapolated. Its recall is below
100% *because* of the sampling: keys that were added and deleted between two sampled
commits are never seen. That's the "I deleted it, so it's fine" blind spot in miniature.
The benchmark names every missed key, so a recall number never hides what was missed.

> **Benchmark bug found and fixed.** Early versions of the generator iterated a Python
> `set` of filenames, whose order follows per-process hash randomization, so every run
> built a *different* repo. Worse, a key could occasionally be planted and deleted in the
> same commit, so it never existed in history but still counted toward the 25. That showed
> up as every method "missing" one key (24/25). The generator is now deterministic (same
> HEAD under any `PYTHONHASHSEED`), and only deletes keys committed earlier. Numbers on
> this page are from the fixed generator, except the first Windows run below. Comparisons
> *within* a run were always fair, because all three methods scanned the same repo.

## Keyword prefilter

Profiling showed 83% of scan time was regex, not git. Python's regex engine can't
skip ahead on alternations like `(?:AKIA|ASIA)`. Checking for a cheap literal first
(`b"AKIA" in data`) and running the regex only on files that contain it:

| | Without prefilter | With prefilter | Speedup |
|---|---:|---:|---:|
| blob scan of psf/requests | 6.67 s | 1.47 s | **4.5x** |

## Windows (synthetic 3,000 commits, Python 3.14)

| Method | Before fixes | After fixes | Change |
|---|---:|---:|---:|
| blob | 4.00 s | **2.85 s** | **-29%** |
| diff | 2.74 s | 2.85 s | (noise) |
| snapshot | ~902 s\* | ~850 s\* | |

After the fixes, blob ties diff on Windows (1.0x) and is ~298x faster than snapshot.

Before the fixes, diff-based scanning beat blob scanning. Profiling the blob scan (5.2 s under cProfile) showed why:

| Cost | Share | Cause |
|---|---:|---|
| `fnmatch` -> `ntpath.normcase` -> `LCMapStringEx` | ~40% | The skip-list check. `fnmatch` normalizes case through a Windows API on every call (157k calls). It's a no-op on Linux. |
| Pipe `read`/`readline` | ~25% | Windows pipes are slower; blob pushes 33 MB vs ~2 MB for diff |
| Keyword-prefilter generator | ~9% | `any(...)` generator created per rule per blob |
| Pipe `write` | ~7% | One write per SHA |

Fixes: compiled all skip globs into one cached regex (no `normcase`), checked all keywords
once per blob, and sent SHAs in a single write. On Linux this took the blob scan from
0.77 s to **0.57 s**, and on Windows from 4.00 s to **2.85 s**. The remaining Windows
gap is pipe throughput, which an in-process reader (pygit2/libgit2) would remove.

## What these numbers do and don't show

- **Blob vs naive snapshot: about 75–300x faster** across Linux and Windows, with
  identical detection rules. This is the headline result.
- **Blob vs diff: roughly even** (1.0x on requests and on Windows, 1.5x faster on the synthetic repo on Linux).
  Blob reads much more data (full file versions rather than added lines) but skips git's
  diff computation. The win depends on the repo's shape. Don't claim blob beats diff-based tools in general.
- Blob scanning sees **whole files**, so it can match secrets that span lines (private keys)
  and isn't fooled by renames. Diff scanning sees only changed lines.
- Not measured yet: memory use, repos over 50k commits, or monorepos with large binaries.
