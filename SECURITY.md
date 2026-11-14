# Security

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** for this repository (Security tab, "Report a vulnerability"). Do not open a public issue for a security problem, and do not include live phishing links or malware samples in a report: describe them, or give a hash.

Lynceus is a one-person research tool ([README](README.md)); reports are read, but there is no response-time promise.

## How secrets are handled (rules for every change)

1. **No secret is ever committed.** No API key, token, password, OAuth client secret or private key goes into code, tests, docs or configuration in this repository. `.env`, `secrets.dpapi.json`, the data folder (`.data/`) and every key file are git-ignored.
2. **Keys live in the Windows DPAPI store:** `python -m core.secrets set NAME` (read from standard input, never from a command-line argument, so it does not land in shell history). Settings read the environment first, then the DPAPI store, then `.env`; the core names (never prints) any secret still left in `.env`.
3. **Code reads secrets only through `core/config.py`,** typed as `SecretStr` so they never appear in a log, a repr or an error message. Logs are redacted by pattern as a second line of defence.
4. **Test values are fake** and marked with `# pragma: allowlist secret`. The pre-commit hook (`python tasks.py hooks`, then automatic) and CI run `detect-secrets` against `.secrets.baseline` on every change; a new finding stops the commit.
5. **Datasets and live phishing URLs never enter git.** Evaluation data lives in `.data/` with its source and checksum; reports hold counts only.

## What the design defends

The threat model and its controls are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), the residual risks in [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md). In short: hostile files and messages are parsed in a sandbox, suspicious pages are opened only in a locked-down browser container, the core listens on loopback only, outbound fetching refuses private and metadata addresses, the local model is reachable on this computer only and can never lower a verdict, and responses are reversible and audited in an append-only log.
