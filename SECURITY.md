# Security

LeakLens handles other people's secrets, so it is designed to be boring and safe.
This page explains what it does and doesn't do, and how to report a problem.

## Design principles

**Runs locally, uploads nothing.**
LeakLens reads your repository through the `git` binary on your own machine. It makes
no network requests. There is no server, telemetry or account.

**Secrets never leave memory unmasked.**
Every output format (terminal and `--json`) shows only a masked form such as
`AIza******eIU`. Raw secret values are not written to disk, logs or reports.

**Only scan what you're allowed to scan.**
LeakLens is for repositories you own or have explicit permission to audit. Scanning
other people's public repos to collect keys is exactly the abuse this project exists
to prevent. Please don't.

**Planned verification will be opt-in and local.**
Phase 2 will add optional live-key checks. They will be off by default, run only on
your machine, use read-only, no-cost endpoints (for example listing models), and
never send keys to any service other than the key's own provider.

## Threat model

| Risk | Mitigation |
|---|---|
| Scanner output leaks the secrets it finds | All output is masked |
| Tool used to harvest third-party keys | Local-only, no bulk-repo mode, no verification by default; documented acceptable use |
| Malicious repository content | Content is only read as bytes and matched with regexes, never executed. Blobs over 2 MB are skipped |
| Supply-chain compromise | Zero runtime dependencies: only the Python standard library and `git` |

## If LeakLens finds a key in your repo

1. **Rotate it first.** Revoke the key at the provider and create a new one.
   A key that was ever pushed is burned, even if you delete it later.
2. Move the new key into a `.env` file (or a secrets manager) and add `.env` to `.gitignore`.
3. Rewriting history (`git filter-repo`) is optional cleanup. It does **not** undo exposure.

## Reporting a vulnerability

If you find a security issue in LeakLens itself (for example, a way to make it print an
unmasked secret), please **don't open a public issue**. Use GitHub's
**Security → Report a vulnerability** on this repository to send a private report.

Please include steps to reproduce. I aim to reply within 7 days.
