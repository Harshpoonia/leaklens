# Changelog

## 0.1.0 (2026-10-21)

First public release.

### Added
- Full-history scanning by **unique blob**: every file version is scanned exactly once,
  across all branches and tags.
- Rules for Google (Gemini / Maps / Firebase), OpenAI, AWS, GitHub, Stripe, MongoDB
  connection strings and private keys, plus opt-in entropy detection (`--entropy`).
- Per-secret timeline: when it was added, moved (renamed) and removed, and whether it's
  still in the current code.
- Plain-English risk explanation and rotation link for every finding.
- `--json` output and CI-friendly exit codes (0 clean, 1 leak found, 2 error).
- Benchmark suite comparing blob, diff and snapshot scanning, with a deterministic
  synthetic repo and ground-truth recall (`bench/`).

### Performance
- Keyword prefilter before regexes: 4.5x faster scans.
- Skip globs compiled to one cached regex. Removed a Windows-only cost where `fnmatch`
  called `normcase` (a Windows API call) 157k times: 29% faster on Windows.
- Single batched write when streaming blob ids to git.

### Fixed during development
- Timeline was silently truncated; it now shows a count of hidden events.
- Renames were reported as removals.
- Masked secrets became mojibake when output was piped on Windows; masks are now ASCII.
- Benchmark generator was non-deterministic and could count a never-committed key as
  ground truth.
