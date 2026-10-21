# LeakLens

[![CI](https://github.com/Harshpoonia/leaklens/actions/workflows/ci.yml/badge.svg)](https://github.com/Harshpoonia/leaklens/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**Find leaked API keys anywhere in your git history, see exactly when they were
added and "removed", and learn how to fix them.** Built for students and new developers.

> Deleting a key from your code doesn't remove it from git. Anyone can still read
> old commits, and bots scan public GitHub for keys within minutes.

```
$ leaklens scan .

[1] Google (Gemini / Maps / Firebase): AIza******eIU
    Status : deleted from code, but STILL IN GIT HISTORY
    Where  : StreamlitApp.py:8, YouTubeAPIModule.py:5, youtube_api.py:3
    Timeline:
      + 2023-12-11  43dfd8fe  added to YouTubeAPIModule.py
      + 2023-12-11  c18ca88b  added to streamlitApp.py
      ~ 2026-06-24  9ae61f29  moved streamlitApp.py -> StreamlitApp.py
      - 2026-06-24  2edecbf1  removed from StreamlitApp.py  (Clean project structure and remove API keys)
    Risk   : Anyone can call Google APIs billed to your project...
             Deleting the line didn't help: anyone can still read old commits.
    Fix    : 1) Revoke/rotate it now -> https://console.cloud.google.com/apis/credentials
             2) Put the new key in a .env file and read it with os.environ / process.env
             3) Add .env to .gitignore before your next commit
```

*This is real output. On its first run, LeakLens found a Google API key that had sat in
the history of one of my own projects for almost three years.*

## Quick start

Requires Python 3.9+ and git. No other dependencies.

```bash
pip install git+https://github.com/Harshpoonia/leaklens
leaklens scan path/to/your/repo
```

| Option | What it does |
|---|---|
| `leaklens scan .` | Scan the repo in the current folder |
| `--entropy` | Also flag random-looking custom secrets (noisier, marked low-confidence) |
| `--json` | Machine-readable output (secrets still masked) |
| `--max-blob-mb N` | Skip file versions larger than N MB (default 2) |

Exit codes: `0` clean, `1` leak found, `2` error, so it drops straight into CI.

> **The path must be a git repository** (a folder with a `.git` inside). A GitHub
> "Download ZIP" has no history; use `git clone` instead.

## What it detects

Google (Gemini / Maps / Firebase), OpenAI, AWS access keys, GitHub tokens, Stripe live
keys, MongoDB connection strings with passwords, and private keys. Lockfiles, minified
JS, source maps, SVGs, `node_modules` and binaries are skipped.

## How it works

LeakLens scans each **unique file version (blob) exactly once**, across every branch and tag:

1. `git rev-list --objects --all` lists every object reachable from any ref.
2. `git cat-file --batch-check` keeps only blobs under the size limit.
3. `git cat-file --batch` streams all contents through **one** git process.
4. A keyword prefilter (`b"AKIA" in data`) decides which regexes are worth running.
   Most files match no keyword and skip every regex.
5. For blobs that matched, one pass over `git log --raw` builds the timeline:
   added, renamed, removed, and whether the key is still in the current code.
   Editing *other* lines of a file isn't mistaken for removing the key.

## Performance

Benchmarked against two other ways of scanning history, using identical rules:

| | psf/requests, 6,736 commits (Linux) | Synthetic, 3,000 commits (Windows) |
|---|---:|---:|
| **LeakLens (blob)** | **1.35 s** | **2.85 s** |
| Diff-based (Gitleaks-style) | 1.39 s | 2.85 s |
| Naive (every file, every commit) | ~114 s | ~850 s |

- **About 75-300x faster than naive scanning**, with 100% recall on a 25-key ground-truth repo.
- **On par with diff-based scanning.** It's not faster in general, and the benchmark says so.
- Profiling drove two fixes: a keyword prefilter (**4.5x**) and removing a Windows-only
  `fnmatch` cost (**-29% on Windows**).

Full methodology, raw numbers and caveats: [bench/RESULTS.md](bench/RESULTS.md).
Reproduce with `python bench/benchmark.py --synthetic 3000`.

## Safety

- **Runs locally.** No network requests, no telemetry, no account.
- **Secrets are always masked**, in every output format.
- **Only scan repos you own or have permission to scan.**

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## Related tools

[Gitleaks](https://github.com/gitleaks/gitleaks) and
[TruffleHog](https://github.com/trufflesecurity/trufflehog) are excellent, broader
scanners, and TruffleHog can verify keys live. LeakLens focuses on the step after
detection: **explaining the leak and fixing it**, for people who are new to this.

## Development

```bash
git clone https://github.com/Harshpoonia/leaklens
cd leaklens
pip install -e '.[dev]'
pytest
```

CI runs the tests on Linux, Windows and macOS, and scans this repo's own history on
every push. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a provider.

## Roadmap

- [x] Full-history blob scanning with an add / rename / remove timeline
- [x] Cross-platform benchmarks with ground-truth recall
- [ ] Allowlist for test fixtures (e.g. `tests/certs/*.key`)
- [ ] Opt-in, local-only live-key verification
- [ ] Generate `.env.example`, `.gitignore` and env-var code fixes
- [ ] Pre-commit hook and GitHub Action
- [ ] Rules in YAML so contributors can add providers without touching code

## License

[MIT](LICENSE)
