# Contributing

Thanks for helping. The most useful contributions are **new provider rules** and
**false-positive reports**.

## Setup

```bash
git clone https://github.com/Harshpoonia/leaklens
cd leaklens
pip install -e '.[dev]'
pytest
```

## Adding a provider rule

Rules live in `leaklens/rules.py`. Each rule needs:

| Field | Purpose |
|---|---|
| `id` | Short, stable id, e.g. `slack-bot-token` |
| `pattern` | Regex with **exactly one capture group**: the secret itself |
| `keywords` | Literal strings that must appear for the regex to run (required, it's the main speed optimization) |
| `explain` | One plain-English sentence: what can an attacker do with it? |
| `rotate_url` | Where to revoke or regenerate it |

Then add a test in `tests/test_scanner.py`. **Build fake keys by string concatenation**
(`"xoxb-" + "1234..."`) so the test file doesn't trip LeakLens, GitHub push protection,
or other scanners.

Good rules are specific. A prefix like `xoxb-` or `AKIA` plus a fixed length beats a
generic "long random string" pattern every time.

## Performance changes

Run the benchmark before and after, and include both tables in your PR:

```bash
python bench/benchmark.py --synthetic 3000
```

The synthetic repo is deterministic, so numbers are comparable between runs and machines.

## Reporting false positives

Open an issue with the provider, the file type, and a **masked** example of what matched.
Never paste a real key, even an old one.
