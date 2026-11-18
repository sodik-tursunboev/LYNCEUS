# Lynceus: Phishing Solution Kit

*Renamed from MIRAGE (2026-11-06; [ADR-021](docs/DECISIONS.md)). Old `MIRAGE_` settings, the old data folder and old registrations are carried over.*

A local-first phishing detector for Windows. It watches your downloads and your browser and (if you connect it) your Gmail or Outlook, and decides what looks like phishing or malware with rules you can read, a model fitted to real data, and (if you turn it on) a local model whose every claim is checked against the evidence. It explains every decision, and only if you let it, quarantines a dangerous file in a way you can undo. It runs in the background without any window open. It is **not** an antivirus, it never deletes your files or email, and nothing it analyses leaves your computer unless you turn on an outside service yourself.

**Status: a one-person research tool, built and verified on one Windows 11 machine.** Not production software for other people yet. The honest list is in [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md); every number below has its interval and data source in [docs/eval/](docs/eval).

## What it catches, measured on data nobody here wrote

| Measurement | Result | Report |
|---|---|---|
| Real phishing URLs, hand-written URL rules alone (E1) | 2.5% | [url-real.md](docs/eval/url-real.md) |
| Fresh PhishTank phishing on domains never seen in training, **with the learned domain model** (AI1) | 1.6% (rules) to **17.1%** | [learned-url.md](docs/eval/learned-url.md) |
| Live phishing pages, domains never seen, rules vs learned model | 12.2% to **54.0%** | [learned-url.md](docs/eval/learned-url.md) |
| Live phishing pages caught when the page is opened in the sandbox (D1) | 16.9% to 37.3% | [detonate.md](docs/eval/detonate.md) |
| False alarms of the learned model: your own browsing / legitimate live pages / PhiUSIIL legitimate | 0 of 86 / 0.8% / 0.3% | [learned-url.md](docs/eval/learned-url.md) |
| Synthetic corpora (written by the rule author: they measure rule correctness, not real detection) | URL precision 0.988, mail precision 1.000 | [dev.md](docs/eval/dev.md), [mail-dev.md](docs/eval/mail-dev.md) |

## What it does

| Part | What | Where |
|---|---|---|
| URL engine | readable rules (look-alike brands, odd ports, login paths, redirects, punycode...) plus a **learned domain model** fitted to 136,875 real domains; a reason for every point | `core/detection`, `rules/url`, `core/learn` |
| Message and file engines | parse email and files **inside a sandbox** (AppContainer + job limits): links, hidden text and CSS, QR codes, PDFs (and links written in their text), archives, macros, scripts, active SVG images | `core/email`, `core/files`, `core/sandbox` |
| Page detonation | on request, opens a page in a throwaway, locked-down browser container (no route to your network), reads forms in frames, retries cloaked pages as a phone, and judges what it shows | `core/detonate`, `rules/page`, `infra/detonator` |
| The brain (off by default) | a local model (Ollama, on this computer only) reads an opened page's text, its own code and its screenshot, and what an email really asks for; **code checks every claim** (the quote is really there, the endpoint was really contacted, the brand does not own the domain) before it counts, and it can never lower a verdict | `core/brain` |
| Threat intelligence | optional: list feeds matched locally, a popular-domain list, query providers asked about a bare domain only; a provider failure is never "safe" | `core/intel`, `core/urls/popular.py` |
| Windows agent | watches Downloads, judges each new file, answers the browser, shows notifications, carries out your decisions, seals quarantined files | `agent/` (.NET) |
| Browser extension | Edge/Chrome MV3: warns before a page that looks like phishing; "this warning is wrong" reports a false alarm | `extension/` |
| Console and workbench | paste a link or drop an email or file and see the verdict, the signs and the evidence; review and undo responses; say "was this right?"; see the state of every guard (Protection), which rules you called wrong (Feedback) and a Guide; dark or light, keyboard shortcuts, phone-width layout | `console/` |
| Live Gmail and Outlook | read-only; new mail is analysed once and missed mail is found again (tested against fakes only so far) | `core/mailbox` |

Every verdict is one of `MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN | ERROR`, with a score, the signals that fired and the evidence behind them. UNKNOWN is never treated as safe. One kind of evidence alone never makes something MALICIOUS: the learned model or the brain alone can only warn.

## How the pieces fit

```
 browser ──(Native Messaging)──> native host ──(named pipe, current user, secret)──> AGENT ─┐
 Downloads folder ──(file watcher)──────────────────────────────────────────────────────>  │ loopback HTTP
                                                                                            v + agent token
 Gmail / Outlook (read-only, optional) ──HTTPS──> CORE (FastAPI) ── sandboxed parsers ── rules ── PostgreSQL
                                          │            │                                         (site names sealed)
                                          │            └── learned model; local brain (optional, loopback only)
                                          └── serves the CONSOLE at http://127.0.0.1:8765/console/ (own session)
```

The core listens on `127.0.0.1` only. The agent starts and supervises the core, so no console window has to stay open.

## Secrets: where keys live (never in this repository)

- **Nothing secret is committed.** `.env` is git-ignored and `.env.example` holds placeholders only. A pre-commit hook and CI run a secret scan (`detect-secrets`) on every change; test values are fake and marked as such.
- **Keys belong in the Windows DPAPI store, not in files:** `python -m core.secrets set NAME` (for example `api_token`, `database_url`, `virustotal_api_key`, `gmail_client_secret`) encrypts the value for your Windows user into `secrets.dpapi.json` (git-ignored). Only your account on your computer can read it back. The core reads it after the environment and before `.env`, and warns at start, by name only, about any secret still left in plain text in `.env`.
- **The agent keeps its own copy of the API token under DPAPI** (`Lynceus.Agent.exe --set-token`, read from standard input). The console never holds that token: it gets a short session for a one-time code.
- **Mailbox tokens, quarantined files and stored site names are encrypted at rest** with DPAPI ([ADR-007](docs/DECISIONS.md)).

See [SECURITY.md](SECURITY.md) for reporting a vulnerability and for the rules contributors follow.

## Run it

You need Windows 11, Python 3.14, the .NET 10 SDK, Node 24 and PostgreSQL (`python tasks.py up` starts one in Docker).

```
git clone https://github.com/sodik-tursunboev/LYNCEUS.git lynceus
cd lynceus
python -m venv .venv
copy .env.example .env                    # settings only; leave secrets out of it
python -m core.secrets set api_token      # paste a long random token, then Enter
python -m core.secrets set database_url   # e.g. postgresql+psycopg://user:password@127.0.0.1:15432/db
python tasks.py up
.\deploy\install.ps1
```

Run these in a normal PowerShell window, not a terminal inside another app ([ADR-024](docs/DECISIONS.md)). `deploy\install.ps1` builds everything, installs the agent and the extension to `%LOCALAPPDATA%\Programs\Lynceus`, registers start at logon and the browser bridge, starts the agent and waits for the core. Running it again is an upgrade. `deploy\uninstall.ps1` removes it. Details, settings and troubleshooting: [docs/OPERATIONS.md](docs/OPERATIONS.md).

Then load the extension (`edge://extensions`, Developer mode, Load unpacked, the folder the script prints) and open the console with `Lynceus.Agent.exe --open-console`.

## For developers

```
python tasks.py deps && python tasks.py sandbox && python tasks.py hooks   # once (deps install from the hash-locked pylock.toml)
python tasks.py test        # Python tests (Postgres tests skip without a database; brain tests use a fake model)
python tasks.py lint        # ruff + mypy
python tasks.py eval        # precision / recall on the labelled corpus
python -m eval.learn_url    # train and measure the learned domain model (needs the E1 datasets, kept outside git)
dotnet test agent/Lynceus.slnx
cd extension && npm ci --ignore-scripts && npm test      # and: npm run test:e2e (real Edge)
cd console   && npm ci --ignore-scripts && npm test      # and: npm run test:e2e (real Edge)
```

## Read next

- [docs/FEATURES.md](docs/FEATURES.md): every feature with an honest status, and the road ahead
- [docs/TECHNICAL_SPEC.md](docs/TECHNICAL_SPEC.md): how it is built and why
- [docs/OPERATIONS.md](docs/OPERATIONS.md): install, run, upgrade, back up, uninstall, troubleshoot
- [docs/PRIVACY.md](docs/PRIVACY.md): what is stored where, and what never leaves the machine
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md): what is defended, what is not
- [docs/DECISIONS.md](docs/DECISIONS.md): every architecture decision and every dependency, with its reason
- [docs/milestones/](docs/milestones): the plan, results and open items of each milestone (latest: [H1](docs/milestones/H1.md), [AI1](docs/milestones/AI1.md))
- [CLAUDE.md](CLAUDE.md): the project rules and command table (start here when changing code)

## Data and credits

The learned domain model was trained on public data: the PhiUSIIL phishing URL dataset (Prasad and Chandra, *Computers & Security*, 2024; UCI ML Repository, CC BY 4.0), PhishTank and OpenPhish feeds, and the Tranco list. Only the model's weights are published, never the datasets ([docs/milestones/E1.md](docs/milestones/E1.md)). Unicode confusables (Unicode License) and the Public Suffix List (MPL 2.0) are bundled with their provenance files.

## License

No license has been chosen yet: until one is added, all rights are reserved by the author.
