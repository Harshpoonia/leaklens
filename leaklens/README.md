# LeakLens

Find leaked API keys anywhere in your git history, see exactly when they were
added and "removed", and learn how to fix them. Built for students and new devs.

```
$ leaklens scan .

[1] Google (Gemini / Maps / Firebase): AIza••••••p6Q
    Status : deleted from code, but STILL IN GIT HISTORY
    Where  : app.py:1
    Timeline:
      + 2026-10-02  4a97d9cf  added to app.py  (add gemini)
      - 2026-10-05  9c1e22ab  removed from app.py  (remove key)
    Risk   : Anyone can call Google APIs billed to your project...
    Fix    : 1) Revoke/rotate it now -> https://console.cloud.google.com/apis/credentials
             2) Put the new key in a .env file and read it with os.environ / process.env
             3) Add .env to .gitignore before your next commit
```

## Install & run

```bash
pip install -e .            # no dependencies, just Python 3.9+ and git
leaklens scan path/to/repo
leaklens scan . --entropy   # also flag random-looking custom secrets (noisier)
leaklens scan . --json      # machine-readable
```

Exit codes: `0` clean, `1` high-confidence leak found, `2` error. That makes it
usable in CI and pre-commit hooks without changes.

## How it works

Most scanners diff every commit, so a file touched in 500 commits gets scanned
500 times. LeakLens scans each **unique file version (blob) exactly once**:

1. `git rev-list --objects --all` lists every object reachable from any branch or tag.
2. `git cat-file --batch-check` filters to blobs and drops huge ones.
3. `git cat-file --batch` streams all contents through **one** git process.
4. Regex rules run over each blob; matches are grouped by secret value.
5. Only for blobs that matched, one pass over `git log --raw` finds the commits
   that introduced or removed them. A commit that edits *other* lines in a file
   containing the secret is correctly not counted as a removal.

## Detected providers

Google (Gemini/Maps/Firebase), OpenAI, AWS access keys, GitHub tokens, Stripe
live keys, MongoDB connection strings with passwords, private keys. Optional
entropy check for secrets assigned to names like `api_key`, `token`, `secret`.

## Safety

- Runs locally. Nothing is uploaded anywhere.
- Secrets are masked in all output, including JSON.
- Only scan repos you own or have permission to scan.

## Related tools

[Gitleaks](https://github.com/gitleaks/gitleaks) and
[TruffleHog](https://github.com/trufflesecurity/trufflehog) are excellent,
broader scanners. LeakLens focuses on explaining and fixing leaks for people
who are new to this.

## Development

```bash
pip install -e '.[dev]'
pytest
```

## Roadmap

- [ ] Rules in YAML so contributors can add providers
- [ ] Opt-in, local-only live-key verification
- [ ] Generate `.env.example`, `.gitignore` and env-var code fixes
- [ ] Pre-commit hook and GitHub Action
- [ ] Benchmarks vs. per-commit diff scanning on large repos
