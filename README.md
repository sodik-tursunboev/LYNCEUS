# MIRAGE

A local-first phishing detector for Windows. It watches your downloads and your browser and (if you connect it) your Gmail or Outlook, decides what looks like phishing or malware using rules you can read, explains every decision, and, only if you let it, quarantines a dangerous file in a way you can undo. It runs in the background without any window open. It is **not** an antivirus, and it never deletes your files or email: quarantine moves a file (on another drive it copies first and removes the original only after the copy is verified byte for byte) and you can always restore it. Uninstalling with `-RemoveData` is the one way to delete the quarantine folder, and it refuses while quarantined files remain unless you force it.

**Status:** built and verified on one Windows 11 machine with Edge, as one person's local tool. Several parts have never been run against a real outside service (Gmail, Outlook, the threat-intelligence providers) and CI has never run. The honest list is in [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## What it does

| Part | What | Where |
|---|---|---|
| URL engine | scores a URL from readable rules (lookalike brands, odd ports, login paths, tracking, punycode...) with a reason for each point | `core/detection`, `rules/url` |
| Message and file engines | parses email and files **inside a sandbox** (AppContainer + job limits), reads links, QR codes, PDFs, archives; hostile input never touches the main process | `core/email`, `core/files`, `core/sandbox` |
| Threat intelligence | optional: list feeds matched locally, query providers asked about a bare domain only; a provider failure is never "safe" | `core/intel` |
| Windows agent | watches Downloads, judges each new file, answers the browser, shows notifications, carries out your decisions | `agent/` (.NET) |
| Browser extension | Edge/Chrome MV3: warns before a page that looks like phishing, fails open and says so when the agent is down | `extension/` |
| Analysis workbench and console | paste a link or drop an email or file and see the verdict, the signs, the anatomy of the link and the evidence; review and undo responses | `console/` |
| Live Gmail and Outlook | read-only; new mail is analysed once and missed mail is found again (both tested against fakes only) | `core/mailbox` |
| Responses | a dangerous file can be quarantined (reversible, audited, asks first by default) | `core/response`, `agent/` |
| Console | see events with their evidence, decide on pending actions, restore, read the audit log | `console/` |

Every verdict is one of `MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN | ERROR`, with a score, the signals that fired and the evidence behind them. UNKNOWN is never treated as safe, and a provider that timed out is never treated as safe.

## How the pieces fit

```
 browser ──(Native Messaging)──> native host ──(named pipe, current user, secret)──> AGENT ─┐
 Downloads folder ──(file watcher)──────────────────────────────────────────────────────>  │ loopback HTTP
                                                                                            v + bearer token
 Gmail / Outlook (read-only, optional) ──HTTPS──> CORE (FastAPI) ── sandboxed parsers ── rules ── PostgreSQL
                                          │
                                          └── serves the CONSOLE at http://127.0.0.1:8765/console/
```

The core listens on `127.0.0.1` only. The agent starts and supervises the core, so no console window has to stay open.

## Run it

You need Windows 11, Python 3.14, the .NET 10 SDK, Node 24 and PostgreSQL (`python tasks.py up` starts one in Docker).

```
git clone <this repository> mirage
cd mirage
python -m venv .venv
copy .env.example .env      # then edit: set MIRAGE_API_TOKEN, MIRAGE_DATABASE_URL
python tasks.py up
.\deploy\install.ps1
```

`deploy\install.ps1` builds everything, installs the agent and the extension to `%LOCALAPPDATA%\Programs\Mirage`, registers start at logon and the browser bridge, starts the agent and waits for the core. Running it again is an upgrade; your data is never touched. `deploy\uninstall.ps1` removes it. Details, settings and troubleshooting: [docs/OPERATIONS.md](docs/OPERATIONS.md).

Then load the extension (`edge://extensions`, Developer mode, Load unpacked, the folder the script prints) and open the console with `Mirage.Agent.exe --open-console`.

## For developers

```
python tasks.py deps && python tasks.py sandbox && python tasks.py hooks   # once
python tasks.py test        # Python tests (Postgres tests skip without a database)
python tasks.py lint        # ruff + mypy
python tasks.py eval        # precision / recall on the labelled corpus
python -m eval.perf         # latency and throughput on this machine
dotnet test agent/Mirage.slnx
cd extension && npm ci --ignore-scripts && npm test      # and: npm run test:e2e (real Edge)
cd console   && npm ci --ignore-scripts && npm test      # and: npm run test:e2e (real Edge)
```

## Read next

- [CLAUDE.md](CLAUDE.md): the project rules, architecture and command table (start here when changing code)
- [docs/OPERATIONS.md](docs/OPERATIONS.md): install, run, upgrade, back up, uninstall, troubleshoot
- [docs/PRIVACY.md](docs/PRIVACY.md): what is stored where, and what never leaves the machine
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md): what is defended, what is not
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md): measured numbers
- [docs/DECISIONS.md](docs/DECISIONS.md): every architecture decision and every dependency, with its reason
- [docs/milestones/](docs/milestones): the plan, results and open items of each milestone
- [docs/SPEC.md](docs/SPEC.md): the original specification