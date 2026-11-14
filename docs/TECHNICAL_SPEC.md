# Lynceus: Technical Specification

*How Lynceus is built, what it is made of, and how each part works.*
Written 2026-11-10 from the code at commit `a3336bb` (URL ruleset 1.1.0, email and file ruleset 1.3.0, engine 1.0.0, intel ruleset 1.0.0). Every number below was read from the code or from a measurement report in this repository; where something is built but was never run against the real outside service, this document says so.

Companion documents: [FEATURES.md](FEATURES.md) (what Lynceus does, feature by feature), [DECISIONS.md](DECISIONS.md) (24 architecture decisions with their reasons), [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) (the honest list), [THREAT_MODEL.md](THREAT_MODEL.md), [PRIVACY.md](PRIVACY.md), [OPERATIONS.md](OPERATIONS.md), [SPEC.md](SPEC.md) (the original requirements).

---

## 1. Purpose and scope

Lynceus ("Phishing Solution Kit", renamed from MIRAGE, ADR-021) is a **local-first phishing and malicious-file detector for one Windows user**. It:

- watches the browser (Edge, Chrome) and warns before a page that looks like phishing;
- watches the Downloads folder and judges every new file;
- optionally reads a Gmail or Outlook inbox (read-only by default) and judges every new message;
- explains every decision (score, signals, evidence, provider results);
- can quarantine a malicious file or message in a way that can always be undone.

It is **not** an antivirus, not a website where you submit URLs, and not a cloud service. Monitoring runs with every window closed. Nothing leaves the machine unless the user turns on a specific provider.

### 1.1 Design rules (the non-negotiables)

| Rule | What it means in the code |
|---|---|
| Deterministic first | Rules and validated threat intelligence decide. The local language model may add one weak signal, never lower a verdict, never make one MALICIOUS (ADR-023). |
| Five verdicts | `MALICIOUS`, `SUSPICIOUS`, `BENIGN`, `UNKNOWN`, `ERROR`. UNKNOWN is never treated as safe; a provider timeout is never "safe". Messages and files are never BENIGN at all. |
| Explainable | Every verdict carries a risk score, a confidence, the signals that fired, evidence references, provider results with provenance and timestamps, a recommended response and the applied response. |
| One feature is never enough | MALICIOUS needs a high score **and** strong evidence from two independent categories (ADR-013). |
| Untrusted input is never run | Emails and files are parsed in a separate sandboxed process with hard limits (ADR-008). Documents and macros are read, never executed. |
| Privacy | Local storage, no URL text or message content stored, outside services off by default and given the minimum (a bare domain). |
| Reversible responses | Quarantine moves, never deletes; every action is idempotent, audited and restorable (ADR-018). |
| Honesty | A feature counts only with an executable test or a verified integration. Measured numbers are published, including bad ones (E1: 2.5%). |

---

## 2. Architecture

A **modular monolith** (ADR-001): one Python process holds all detection logic; small helper programs carry signals in and decisions out. No microservices, no queue (Redis was deferred until something needs it, ADR-002).

```
                         ┌──────────────── user's Windows session (per-user, no admin) ────────────────┐
 Edge / Chrome           │                                                                              │
  MV3 extension ──Native Messaging──> Lynceus.NativeHost ──named pipe (current user + secret)──┐        │
                         │                                                                      v        │
 Downloads folder ──FileSystemWatcher──────────────────────────────────────────────> Lynceus.Agent (.NET)│
                         │                                    notifications, quarantine, supervisor │    │
                         │                                                                      │ loopback HTTP
                         │                                                                      v + bearer token
 Gmail / Outlook ──HTTPS (optional, read-only)──> CORE: FastAPI on 127.0.0.1:8765 ───────────────────────┤
 OpenPhish / PhishTank lists ──HTTPS download───>   ├─ URL engine (rules/url)                             │
 (VirusTotal, urlscan, URLhaus, RDAP: off, keys)    ├─ message + file engines ──spawn──> SANDBOX worker  │
                         │                          │                                (AppContainer + Job) │
                         │                          ├─ threat intel + hash lists                          │
                         │                          ├─ scoring (core/risk)                                │
                         │                          ├─ local model reviewer ──loopback──> Ollama :11434   │
                         │                          ├─ response engine (actions, audit)                   │
                         │                          ├─ console (React) at /console/  <── browser / Tauri  │
                         │                          └─ PostgreSQL 17 (Docker, 127.0.0.1:55432)             │
                         └──────────────────────────────────────────────────────────────────────────────┘
```

Three layers, as the mission statement puts it: **Sensors** (extension, file watcher, mailbox poller, Analyze page) → **Intelligence** (URL, message and file engines, threat intel, scoring) → **Response** (warning page, notification, quarantine, audit).

### 2.1 Components

| Component | Language / runtime | Folder | Runs as |
|---|---|---|---|
| Core engine and HTTP API | Python 3.14.7, FastAPI, uvicorn | `core/`, `rules/` | child process of the agent, `127.0.0.1:8765` |
| Parser sandbox | Python 3.14 (separate interpreter copy) | `core/sandbox/`, `.sandbox/` | one short-lived restricted process per parse |
| Windows agent | C# / .NET 10 | `agent/Lynceus.Agent` | per-user program started at logon (Run key `LynceusAgent`) |
| Native messaging host | C# / .NET 10 | `agent/Lynceus.NativeHost` | started by the browser (`com.lynceus.agent`) |
| IPC library | C# / .NET 10 | `agent/Lynceus.Ipc` | shared by agent and host |
| Browser extension | TypeScript, Chrome MV3 | `extension/` | Edge or Chrome service worker |
| Console and analysis workbench | React 19 + TypeScript | `console/` | served by the core at `/console/` |
| Native console window | Rust, Tauri 2 | `shell/` | optional desktop window around the console |
| Database | PostgreSQL 17 | `infra/docker-compose.yml` | Docker container, loopback only |
| Local language model | Ollama, `llama3.2:3b` | `core/llm/` (client) | separate Ollama server, loopback only, optional |
| Page detonator (D1) | Chromium via Playwright 1.64.1, in Docker | `infra/detonator/`, `core/detonate/`, `rules/page/` | one throwaway container per page plus the egress-proxy container, on request |
| Installer | PowerShell scripts, WiX 5 MSI | `deploy/` | per-user, no administrator rights |
| Evaluation harness | Python | `eval/`, `corpus/` | on demand |

---

## 3. Technology stack

### 3.1 Core (Python)

| Package | Version | Why |
|---|---|---|
| Python | 3.14.7 (`.venv`) | the engine, rules and sandbox guest |
| FastAPI | ≥ 0.115 | HTTP API, request validation |
| uvicorn | ≥ 0.30 | ASGI server (started with no access log and no server header) |
| pydantic v2 / pydantic-settings | ≥ 2.8 / ≥ 2.4 | contracts (`core/contracts`), settings from `.env` |
| SQLAlchemy 2 | ≥ 2.0 | database access |
| Alembic | ≥ 1.13 | schema migrations `0001` to `0003` |
| psycopg 3 (binary) | ≥ 3.2 | PostgreSQL driver |
| ada-url | ≥ 4.0, < 5 | WHATWG URL parsing, the same algorithm browsers use (ADR-012) |
| httpx | ≥ 0.27 | outbound HTTPS for intel, mailboxes and the local model, behind one egress gate |

Every dependency and its purpose is recorded in ADR-004. Development tools: pytest, ruff, mypy (strict), detect-secrets (`requirements-dev.txt`).

### 3.2 Sandbox parser libraries (hash-pinned, `requirements-sandbox.txt`)

| Package | Version | Used for |
|---|---|---|
| pikepdf (qpdf) | 10.17.0 | PDF structure: JavaScript, Launch, embedded files, link annotations, XFA |
| Pillow | 13.0.0 | image decoding, pixel-bomb checks |
| opencv-python-headless | 5.0.0.93 | QR code detection (FFmpeg plugin removed) |
| numpy | 2.5.4 | OpenCV dependency |
| lxml (libxml2) | 6.1.3 | Office Open XML (XLM macro sheets, relationships) |
| packaging | 26.3 | version checks in the build |

These run only inside the sandbox, installed with `--require-hashes` (pinned to Windows x64 / CPython 3.14 wheels).

### 3.3 Agent (.NET)

| Item | Version |
|---|---|
| Target framework | `net10.0-windows10.0.19041.0` |
| Microsoft.Extensions.Hosting | 10.0.14 (worker host, logging, configuration) |
| System.Security.Cryptography.ProtectedData | 10.0.14 (DPAPI for the API token) |
| Tests | xUnit 2.9.3, Microsoft.NET.Test.Sdk 18.10.1 |

Central package management (`Directory.Packages.props`), solution `agent/Lynceus.slnx`.

### 3.4 Browser extension and console (TypeScript)

| Item | Version |
|---|---|
| TypeScript | 5.9.3 |
| esbuild | 0.28.2 (bundler for both) |
| React / React DOM | 19.2.9 (console only) |
| vitest | 5.0.5 (unit tests) |
| puppeteer-core | 25.16.0 (end-to-end tests against the real installed Edge) |
| @types/chrome | 0.3.6 (extension) |
| Node | 24 |

### 3.5 Desktop shell, installer, database, model

| Item | Version |
|---|---|
| Tauri | 2 (`shell/src-tauri`, Rust 1.99.1) |
| WiX Toolset | 5.0.2 (per-user MSI, `deploy/msi/Lynceus.wxs`; last built `Lynceus-0.4.0-x64.msi`, unsigned) |
| PostgreSQL | 17 in Docker (`infra/docker-compose.yml`, `127.0.0.1:55432`, volume `mirage_pgdata`) |
| Ollama + `llama3.2:3b` | local model server on `127.0.0.1:11434` (optional) |
| Playwright image | `mcr.microsoft.com/playwright/python:v1.64.1-noble` pinned by digest (about 3.5 GB), plus `playwright==1.64.1` from hash-pinned wheels; built as `lynceus-detonator:1.0.0` (D1) |

---

## 4. The core engine

### 4.1 HTTP API (`core/api/app.py`)

The core is one FastAPI application. It listens on **`127.0.0.1` only**, accepts only the `Host` names `127.0.0.1` and `localhost` (against DNS rebinding), and requires a **bearer token** (`LYNCEUS_API_TOKEN`) on every route except `/health`. The OpenAPI document is `docs/openapi.json`; the data contracts are JSON Schemas in `docs/schemas/` (Artifact, Event, Evidence, ProviderResult, Signal, Verdict).

| Method and path | Purpose |
|---|---|
| `GET /health` | liveness (open) |
| `POST /v1/urls/analyze` | judge one URL |
| `POST /v1/emails/analyze` | judge one raw message (`.eml`, up to 10 MiB) |
| `POST /v1/files/analyze` | judge one file (up to 16 MiB minus 4 KiB) |
| `POST /v1/files/check` | judge a file by name, size and hashes only (larger files) |
| `POST /v1/urls/detonate` | D1: the URL verdict, then the page opened in the sandboxed browser, one verdict over both, plus a summary and screenshot of the page (off until `LYNCEUS_DETONATION=true`; 6 a minute) |
| `GET /v1/events`, `GET /v1/events/{verdict_id}` | stored verdicts with their signals and evidence |
| `GET /v1/actions`, `GET /v1/actions/{id}` | response actions |
| `POST /v1/actions/{id}/approve` `/dismiss` `/restore` | user decisions |
| `POST /v1/actions/{id}/result` | the agent reports what it did |
| `GET/POST /v1/allowlist`, `DELETE /v1/allowlist/{sha256}` | per-content allow-list |
| `POST /v1/overrides` | "continue anyway" from the warning page (15 minutes) |
| `GET /v1/audit` | the audit log |
| `GET /v1/intel/health` | state of every intel provider and list |
| `GET /v1/mailbox/status` | live mailbox state |

**Protective limits** (`core/config.py`): JSON bodies 64 KiB; messages 10 MiB; files 16,773,120 bytes; 120 requests per minute in general and a separate 1,200 per minute for URL checks (so browsing cannot starve file checks); at most 4 parses at once (a fifth waits one second, then gets HTTP 503).

### 4.2 Data contracts (`core/contracts`)

A **Verdict** holds: `state`, `risk_score` (0 to 100, absent for UNKNOWN), `confidence` (LOW, MEDIUM, HIGH), `signals` (rule id, category, weight, description, evidence ids, ATT&CK id), `evidence`, `provider_results` (provider, status, finding, fetched-at timestamp), `recommended_response` (`BLOCK` for MALICIOUS, `WARN` for SUSPICIOUS, `NONE` otherwise), `applied_response`, `explanation`, and the engine and ruleset versions that produced it. The ruleset version includes a hash of the rule data (`1.1.0+33f432fb4220`), so any change to a list or weight changes the version.

### 4.3 The scoring model (`core/risk/scoring.py`, ADR-013)

Pure function, every number from the ruleset's `scoring.toml`:

1. Signals are grouped by **category** (for URLs: host, deception, impersonation, redirect, credential, scheme, structure, obfuscation).
2. Inside a category the weights combine by **noisy-OR**, `1 − Π(1 − wᵢ)`, then are **capped** by the category's cap (e.g. structure 0.4, impersonation 0.85). Ten weak hints of the same kind therefore cannot add up to certainty.
3. Across categories the capped values combine by noisy-OR again; `risk = round(100 × result)`.
4. A category is **strong** when its strongest signal is at least `high_weight` (0.5).
5. State:
   - a rule listed as **certain** (an exact known-bad hash, the EICAR test file) → MALICIOUS, risk ≥ 95;
   - risk ≥ 80 **and** at least 2 strong categories → **MALICIOUS** (recommend BLOCK);
   - risk ≥ 45 → **SUSPICIOUS** (recommend WARN);
   - an allow-listed official site with only weak signals → BENIGN;
   - otherwise → **UNKNOWN** (weak signals prove nothing in either direction).
6. Confidence: LOW with 0 or 1 strong categories, MEDIUM with 2, HIGH with 3 or more.

The same function scores URLs, messages, files and intel findings, each with its own configuration.

### 4.4 Storage (`core/db`, PostgreSQL)

Thirteen tables, UUID keys, created by Alembic migrations `0001_initial_schema`, `0002_response_actions`, `0003_mail_actions`:

| Table | Holds |
|---|---|
| `events` | one row per thing judged (source: browser, download, mailbox, analyze page) |
| `artifacts` | the artifact's kind, hashes, size, and for URLs the host only |
| `domains`, `extracted_urls` | hosts linked from messages (no full URL text) |
| `verdicts`, `detections` | the verdict and every signal |
| `evidence`, `detection_evidence` | evidence summaries and their links to signals |
| `evidence_payloads` | reserved for encrypted raw evidence (ADR-007, not implemented; nothing writes it) |
| `provider_results` | intel answers with provenance and timestamps |
| `actions` | response actions and their state |
| `allowlist` | content hashes the user allowed |
| `audit_logs` | append-only record of every user and agent decision |

**Not stored, by design:** URL text (decision D2; hosts only), message bodies, subjects, addresses, attachment names, file names. A test scans every table for these. The database is optional: without `LYNCEUS_DATABASE_URL` verdicts still work, but nothing is kept and no response is proposed.

---

## 5. The URL engine (`core/urls`, `rules/url`, `core/detection`)

### 5.1 Parsing

URLs are parsed with **ada-url**, an implementation of the WHATWG URL standard (the algorithm browsers use), so Lynceus reads an address exactly as Edge will (ADR-012; 554 of 560 web-platform-test cases match, the 6 differences are deliberate). `core/urls/parse.py` adds:

- registered domain and subdomain from the **Public Suffix List** (`core/urls/psl.py`);
- host kind (domain, IPv4, IPv6, obfuscated IP such as `http://3405803781/`);
- **flags** for tricks: backslash, control characters, invisible characters, tab or newline removed from the middle, percent-encoded host, double encoding, dangerous scheme (`javascript:`, `data:`, `file:`);
- a hard limit of 8,192 characters.

320,000 fuzzed inputs produced no exception.

### 5.2 Rules (20, ruleset 1.1.0)

Each rule is a pure function `ParsedUrl → evidence text or None`, registered with an id, a category and an ATT&CK technique; its weight lives in `rules/url/scoring.toml`, its word lists in `rules/url/lists.toml`, its brands in `rules/url/brands.toml` (105 brands, 189 official domains) and lookalike characters in the Unicode confusables table (6,712 entries).

| Rule | Category | Weight | Looks for |
|---|---|---|---|
| `url.ip_literal` | host | 0.30 | an IP address instead of a name |
| `url.ip_obfuscated` | host | 0.55 | an IP written in decimal, hex, octal or IPv4-mapped IPv6 |
| `url.userinfo_deception` | deception | 0.70 | `paypal.com@evil.test`: a brand before the `@` |
| `url.homograph_brand` | impersonation | 0.80 | a brand spelled with lookalike letters (Cyrillic `а`, punycode) |
| `url.mixed_script` | impersonation | 0.55 | Latin and Cyrillic or Greek mixed in one label |
| `url.typosquat` | impersonation | 0.70 | one edit from a brand (`paypa1`, `arnazon`) |
| `url.combosquat` | impersonation | 0.70 | brand plus a lure word (`paypal-login`) |
| `url.brand_in_subdomain` | impersonation | 0.70 | `paypal.com.evil.test` |
| `url.brand_in_domain` | impersonation | 0.30 | a brand inside an unrelated domain (weak) |
| `url.shortener` | obfuscation | 0.20 | a URL shortener: destination unknown |
| `url.open_redirect` | redirect | 0.50 | a redirect parameter sending you to another site (share dialogs on official sites excluded) |
| `url.encoded_target` | redirect | 0.60 | an off-site address hidden by double or base64 encoding |
| `url.credential_bait` | credential | 0.55 | a brand and a login word in the path of a site the brand does not own |
| `url.prefilled_identity` | credential | 0.50 | an email address prefilled in the query |
| `url.login_path` | credential | 0.40 | a path that ends in a login or verify page |
| `url.dangerous_scheme` | scheme | 0.75 | `javascript:`, `data:`, `file:` |
| `url.odd_port` | structure | 0.25 | a port other than 80, 443, 8000, 8080, 8443 |
| `url.excessive_length` | structure | 0.35 | 2,000 characters or more |
| `url.host_shape` | structure | 0.30 | 4+ hyphens or 5+ subdomain levels |
| `url.parser_tricks` | obfuscation | 0.35 | the parser flags above (double encoding only in the path) |

**Allow-listing:** a URL on an official domain of a listed brand, with no off-site target in any parameter, is BENIGN. Shared hosting on official domains (`sites.google.com`, `docs.google.com`, `github.com`, `*.blob.core.windows.net`, and others in `shared_hosts`) is never allow-listed, because anyone can publish there.

### 5.3 Redirect resolver (built, off)

`core/urls/safe_fetch.py` follows redirects with an SSRF guard: every hop and every resolved IP is re-validated; loopback, private, link-local and cloud-metadata addresses are refused; the connection goes to the validated IP. It has 151 offline tests and 13 mutation checks but is **off and not wired in** (ADR-011 unsigned; `LYNCEUS_RESOLVE_REDIRECTS=false`).

---

## 6. The parser sandbox (`core/sandbox`, ADR-008)

Every email and every file is opened by a separate process, never by the core.

### 6.1 Isolation

| Layer | Setting |
|---|---|
| **AppContainer** | per-user profile `lynceus.parser`: no network capability, no access to the user's files except the sandbox folder (read-only) |
| **Job Object** | 512 MB memory (process and job), 10 s CPU, 15 s wall clock, **one process** (cannot start children), kill on close, die on unhandled exception, all UI restrictions (no clipboard, desktop, windows) |
| Input and output | bytes in on standard input, one JSON document out on standard output, at most 4 MiB |
| Interpreter | a private copy of Python in `.sandbox/` with only the guest code and the hash-pinned libraries |
| Output check | the host validates every reply against a closed vocabulary (pydantic `Literal` types, 41 indicator names): anything unexpected is an ERROR, not data |

`python tasks.py sandbox` builds `.sandbox/` and registers the profile; a test fails if the copy is older than the guest source. On any non-Windows system analysis returns ERROR `sandbox_unavailable`.

### 6.2 Guest modules (`core/sandbox/guest/`, standard library plus the pinned parsers)

| Module | Reads |
|---|---|
| `worker.py`, `main.py` | entry point, operation dispatch (`parse_email`, `scan_file`, `macro_excerpt`, ...) |
| `mailparse.py` | MIME tree, headers, addresses, `Authentication-Results`, attachments |
| `htmlscan.py` | links, hidden links, link text vs target, forms, scripts, meta refresh, HTML smuggling, Outlook conditional comments and VML |
| `filetype.py` | real type from magic bytes (PDF, ZIP, RAR, 7z, gzip, bzip2, xz, PE `MZ`, ELF, OLE, RTF, PNG, JPEG, GIF, BMP, TIFF, LNK) vs claimed extension |
| `archives.py` | ZIP, TAR, gzip, bzip2, xz: entries, nested archives (depth 3), bombs, traversal, encryption, Office Open XML macro parts |
| `pdfscan.py` | PDF objects through qpdf: JavaScript, Launch, embedded files, URIs, XFA, encryption |
| `imagescan.py` | QR codes (OpenCV), pixel bombs |
| `contentscan.py`, `textscan.py` | scripts (PowerShell, JScript, VBScript, batch, HTA): downloaders, encoded commands, hidden layers (base64 in base64, up to 4), LOLBins, persistence, defence evasion, injection, credential access |
| `lnkscan.py` | Windows shortcuts: target, arguments, interpreter launch, disguise |
| `pescan.py` | Windows programs: packing, imports for injection and download |
| `olescan.py` | OLE compound files (`.doc`, `.xls`, `.ppt`): VBA projects, p-code, Excel 4.0 macro sheets in BIFF, Equation Editor, embedded objects |
| `vbaeval.py` | bounded VBA evaluator (section 8) |
| `vbaanalyze.py` | macro behaviour analysis (section 8) |
| `xlmscan.py` | Excel 4.0 macros in XML workbooks, with a cell evaluator |
| `filescan.py` | per-file orchestration and the macro excerpt for the model |
| `limits.py` | every hard limit, in one place |

Selected limits from `limits.py`: 500 MIME parts, depth 20; 500 links; 2 MiB of HTML and 50,000 tags; 20 MiB per decoded part, 64 MiB total; 2,000 archive entries, 48 MiB decompressed per attachment; 16 million pixels; 100,000 PDF objects; 1 MiB of a file's content examined; 300,000 characters of macro source.

---

## 7. The message and file engines (`core/email`, `core/files`, `rules/email`)

### 7.1 Messages

`POST /v1/emails/analyze` (or the mailbox poller) hands the raw message to the sandbox (`parse_email`). The reply describes headers, sender, authentication results, the HTML (links, hidden elements, forms, scripts) and every attachment. Up to 8 attachments are then opened, each in its **own** sandbox process (`scan_file`). Every link found is judged by the URL engine. Rules (`rules/email/*.py`) turn this into signals; `core/risk` scores them with `rules/email/scoring.toml` (ruleset 1.3.0).

A message is **never BENIGN** (ADR-014): the best a clean message gets is UNKNOWN.

### 7.2 Files

`POST /v1/files/analyze` sends the bytes to the sandbox (`scan_file`): real type vs extension, then the matching deep scan (script, shortcut, program, PDF, archive, Office, image). The file's SHA-256, SHA-1 and MD5 are matched against the local known-bad hash lists. Files over 16 MiB are judged by name, size, type and hash only (`/v1/files/check`). A file is never BENIGN.

### 7.3 Rules (80, ruleset 1.3.0)

44 `email.*` rules (message structure, sender, authentication, links, HTML, attachments, archives, PDFs, images), 35 `content.*` rules (what is inside a file), 1 `intel.hash_known_bad`. 22 categories, each capped (e.g. `known_bad` 1.0, `code_behavior` 0.9, `sender` 0.8, `content` 0.3). 27 distinct MITRE ATT&CK techniques are tagged across the URL and email/file packs. The full list with plain explanations is in [FEATURES.md](FEATURES.md) §9.

Two rules are **certain** (decide alone): `intel.hash_known_bad` and `content.eicar`.

---

## 8. Macro analysis: reading unknown macros as programs (ADR-023)

Signature lists cannot catch a macro nobody has seen before. Lynceus reads the macro's code and works out what it would do, without running it.

### 8.1 Extraction

- **VBA** from OLE files (`.doc`, `.xls`, `.ppt`) and from `vbaProject.bin` inside Office Open XML (`.docm`, `.xlsm`, `.pptm`): the compressed source streams are decompressed (MS-OVBA).
- **P-code** (the compiled form) is compared with the source text: source that is missing or does not match the p-code means **VBA stomping** (T1564.007), a known way to hide the real macro from scanners.
- **Excel 4.0 (XLM) macros**: in XML workbooks, macro sheets are read and their formulas evaluated; in old binary `.xls` (BIFF), the macro sheet, whether it is hidden or very hidden, and the built-in `Auto_Open` name are found.

### 8.2 The bounded VBA evaluator (`vbaeval.py`)

A small VBA interpreter that runs **only the macro's own string-building code**, so obfuscated commands can be read in plain text.

- Parser: logical lines (continuations, `:` separators), tokenizer, precedence-climbing expression parser; statements `If`, `For`, `For Each`, `While`, `Do`, `Select Case`, `With`, `Dim`, `ReDim`, `Const`, `Exit`, procedure calls.
- 44 pure built-in functions and constants (`Chr`, `Asc`, `Mid`, `Left`, `Right`, `Replace`, `Split`, `StrConv`, `Hex`, `Val`, `Array`, `vbCrLf`, ...). Anything that touches the outside world (objects, files, the shell) returns an opaque value and is never called.
- Entry points: auto-run procedures (`AutoOpen`, `Document_Open`, `Workbook_Open`, ...) plus every procedure nobody calls.
- Hard limits: 400,000 steps, 3 seconds, call depth 24, 256 KiB per string, 200,000 array elements, 400 recovered strings, 40 entry points.

### 8.3 Behaviour analysis (`vbaanalyze.py`)

Over the source and the recovered strings:

| Finding | Rule |
|---|---|
| auto-run code that reaches a dangerous call (`Shell`, `CreateObject("WScript.Shell")`, `URLDownloadToFile`, ...) through the call graph | `content.macro_autoexec_reaches_sink` |
| behaviour visible only after decoding (a command or URL that appears only in recovered strings) | `content.macro_hidden_behavior` |
| Windows API imports through `Declare` (`VirtualAlloc`, `CreateThread`, `RtlMoveMemory`, ...) | `content.macro_api_import` (category `api_abuse`, T1106) |
| dynamic dispatch (`CallByName`, `Application.Run` or `CreateObject` with a computed name, `GetObject("new:...")`, `Evaluate`, `ExecuteExcel4Macro`) | `content.macro_dynamic_dispatch` |
| code that reads from hidden stores (document properties, custom XML parts, document variables, form captions, control tooltips, alternative text) | `content.macro_hidden_data_source` |
| writing a file into Temp, AppData, Public, ProgramData or Startup | `content.macro_file_drop` |
| obfuscation (at least two of: 15+ `Chr` calls, mass concatenation, mostly random-looking names, 40+ element number arrays, 1,500+ character lines, behaviour revealed only by decoding) | `content.macro_obfuscated` |
| stomped or p-code-only VBA | `content.vba_stomped`, `content.vba_pcode_only` |
| Excel 4.0 macros, hidden macro sheets | `content.xlm_macro`, `content.xlm_hidden` |

Measured on the synthetic macro corpus (`tests/macrosamples.py`): 8 of 8 unknown malicious macros flagged, 7 of them MALICIOUS; 0 of 10 ordinary macros fire a new rule; 6 held-out macros written separately. **No real-world Office malware has been run through it.**

### 8.4 The local model reviewer (`core/llm`)

An optional second reader for macros, off by default (`LYNCEUS_LLM_REVIEW=true` turns it on).

- **Model:** `llama3.2:3b` served by **Ollama** on `127.0.0.1:11434`. The client (`core/llm/ollama.py`) goes through the same egress gate as everything else and is refused any non-loopback address.
- **When:** only for a verdict where the deterministic analysis already found a macro (`content.office_macro` or `content.xlm_macro`), for files sent by the agent or the Analyze page and messages posted to the API (not the mailbox poller). One review at a time, 45 seconds at most; a verdict goes out without it if the model is late.
- **Input:** the sandbox op `macro_excerpt`: the macro code with comments stripped (comments are where an attacker would write "ignore your instructions"), plus the decoded strings, at most 12 KB.
- **Output:** a **JSON-schema-constrained** answer: assessment (`malicious`, `suspicious`, `benign`, `unsure`), confidence 0 to 100, behaviours from a fixed list. Free text is never shown.
- **Weight:** advice only. `malicious` (confidence ≥ 60) adds a signal of 0.35, `suspicious` 0.2, in category `llm_review` capped at 0.35, below `high_weight`: it can never be independent evidence. `benign` or `unsure` changes nothing. A second wall in code forbids the advice to lower a verdict or to make one MALICIOUS.
- **Measured:** 24 of 24 test macros answered in valid form and in agreement; only 6 of them were written independently of the model's briefing.

---

## 9. Threat intelligence (`core/intel`, `rules/intel`, ADR-015, ADR-022)

### 9.1 Providers

All providers sit behind one async interface (`core/intel/base.py`) with per-provider timeouts, rate limits, a circuit breaker, a cache and provenance (`core/intel/resilience.py`).

| Provider | Kind | What leaves the machine | Status |
|---|---|---|---|
| OpenPhish community feed | list, downloaded and matched locally | nothing about your browsing | **on** (keyless) |
| PhishTank | list, downloaded and matched locally | nothing about your browsing | **on** (keyless) |
| URLhaus | list | nothing about your browsing | built, needs an abuse.ch key |
| VirusTotal | query | the bare registered domain | built, needs a key, off |
| urlscan.io | query | the bare registered domain | built, needs a key, off |
| RDAP (domain age) | query | the bare registered domain | built, off |
| MalwareBazaar | hash list, downloaded | nothing | built, needs an abuse.ch key |

A background loop in the core refreshes the lists (PhishTank hourly at best, OpenPhish every 12 hours); a list older than its limit reports UNAVAILABLE instead of matching stale data.

### 9.2 Egress gate (`core/intel/egress.py`, `core/intel/http.py`)

Every outbound request in the core goes through one module. Query providers receive only a public registered domain, never a path, query or token. Message links stay local unless `LYNCEUS_INTEL_EMAIL_LINKS=true`. A test (`test_no_stray_network`) fails if any other module opens a network connection.

### 9.3 Correlation (`core/risk/correlate.py`)

Each finding becomes a signal in category `intel.<provider>` (e.g. `intel.phishtank.url` 0.85, `intel.openphish.host` 0.3, `intel.domain_age.week` 0.55), scored with the same model (`rules/intel/scoring.toml`). One provider alone gives at most SUSPICIOUS. A provider that did not answer contributes nothing in either direction and is shown as such. Nothing from intel ever produces BENIGN. The core waits at most `LYNCEUS_INTEL_DEADLINE` (2 s; the agent runs it with 0.5 s) before answering without the late providers.

### 9.4 Known-bad hashes (`core/intel/hashfeed.py`)

Local lists of SHA-256, SHA-1 and MD5 (`python -m core.intel hashes import|check|sync|status`). The EICAR test file is built in. A match is **certain**: MALICIOUS on its own.

---

## 9b. Page detonation (D1, ADR-025)

Reading the address alone misses most real phishing (E1: no URL rule fires on 91.2%). On request, the page is opened in a throwaway browser and judged by what it shows.

**Layout** (created on first use by `core/detonate/runner.py`):

```
 core ──docker run (argument list, no shell)──> browser container  (one per page, --rm)
                                                 network: lynceus-dn-inner (--internal: no route anywhere)
                                                       │ HTTP proxy, the only reachable thing
                                                       v
                                                 lynceus-egress  (egress.py, stdlib)
                                                 networks: inner + lynceus-dn-outer
                                                 resolves names itself; public IPv4, ports 80/443 only;
                                                 connects to the address it checked
                                                       │
                                                       v  the public web (from this computer's connection)
```

**Browser container hardening:** `pwuser` (non-root), Chromium's sandbox **on** (`chromium_sandbox=True`; Playwright's default is off) under Playwright's seccomp profile, `--read-only` with a 256 MB tmpfs `/tmp`, `--cap-drop ALL --cap-add SYS_CHROOT` (the sandbox's chroot), `no-new-privileges`, 1 GB memory and no swap, 1.5 CPUs, 512 processes, 1 GB shared memory, `--init`, no logs, nothing mounted, no published ports; killed at 32 s; at most 3 at once. Chromium flags: QUIC off, WebRTC limited to proxied traffic, loopback sent to the proxy too.

**In the page** (`infra/detonator/detonate.py`): a normal Chrome user agent (the headless one makes kits hide), downloads cancelled, service workers blocked, no permissions, dialogs dismissed, pop-ups closed; navigation 15 s, then up to 4 s for the page to settle; the watchdog ends it at 26 s. It records the redirect chain, title, headings, logo text, visible text (20,000 characters), forms (action, method, field types and names, never values), frames, contacted hosts, script hosts, URLs written in the page's own scripts, anti-analysis markers, attempted downloads, the TLS certificate dates and a JPEG screenshot.

**Back in the core:** the reply is validated against a closed pydantic schema with a size on every field (`core/detonate/models.py`); the screenshot is decoded only in the AppContainer parser sandbox (op `reencode_jpeg`) and is never stored.

**Page rules** (`rules/page`, ruleset 1.0.0):

| Rule | Category | Weight | Fires when |
|---|---|---|---|
| `page.brand_credential` | page.impersonation | 0.80 | the page presents itself as a listed brand (title or headings; not "sign in **with** Google"; logos are not used, payment and app-store marks are everywhere) and asks for credentials (a password, an account on a sign-in page, or a payment card) on a host that brand does not own (its shared hosting counts as not owned). Brands: the URL list plus `rules/page/brands.toml` (commonly impersonated brands; 164 brands in all) |
| `page.form_offsite` | page.exfiltration | 0.65 | a password form posts to another registered domain or a bare IP (single sign-on providers and official domains excepted) |
| `page.collection_endpoint` | page.exfiltration | 0.75 | a page asking for credentials names a Telegram bot, a Discord or Slack webhook, a form-relay service |
| `page.hosting_platform_login` | page.hosting | 0.40 | a sign-in or card form on free hosting, a site builder, serverless hosting, IPFS, a tunnel or dynamic DNS |
| `page.brand_on_hosting` | page.hosting | 0.40 | a page presenting itself as a brand on such hosting, before it asks for anything ("View the shared document") |
| `page.evasion` | page.evasion | 0.45 | a page asking for credentials sets a debugger trap or a window-size check for developer tools, blocks keyboard shortcuts, or writes decoded content into itself (right-click blocking, `navigator.webdriver` checks and heavy decoding are recorded but not counted: legitimate pages do them as often) |
| `page.geofence` | page.evasion | 0.30 | a page asking for credentials looks up the visitor's IP address |
| `page.smuggling` | page.delivery | 0.60 | the page built a file in the browser and started its download |
| `page.drive_by_download` | page.delivery | 0.50 | the page pushed a dangerous file type by itself |

The landing address, when it is on another site, also goes through the 20 URL rules, unless the starting address was a brand's official site (its own redirect, such as visa.com to visa.pl). A sign-in page is one with a password field, a payment-card form, or an account field under a title or heading that talks about signing in. Everything is scored with the URL and intelligence signals by `core/risk/scoring.py`; MALICIOUS still needs two independent strong categories. There is deliberately no rule for "a password field" or "moved to another site" (every login page and single sign-on would trip it). A page that could not be opened adds nothing and the explanation says why.

**Entry points:** `python -m core.cli detonate <url>`, `POST /v1/urls/detonate`, the console's "Open in sandbox" button. Not automatic (D1b).

Since H1 the detonator (image `lynceus-detonator:1.1.0`) also reads forms inside the first ten frames (marked `frame`), retries once as a phone when the desktop visit was refused, blank or a bot check and there is time left in the 26-second watchdog, and returns a bounded excerpt of the page's own code (12,000 characters, inline and same-site scripts) for the script brain.

## 9c. Learned judgment and the checked brain (AI1, ADR-027)

**The learned domain model** (`core/learn`, `rules/url/learned.py`). Features of the **registered domain only**: character 3- to 5-grams of its label, the public suffix and bucketed structure (length, digits, hyphens, letter entropy, brand and keyword words), hashed into 262,144 buckets. Logistic regression, trained in pure Python by `python -m eval.learn_url` on E1's training domains (split by registered domain, threshold chosen on calibration domains). Shipped as `rules/learned/url_host.bin` (signed 16-bit weights) and `url_host.json` (bias, scale, threshold, the weights' SHA-256, checked at load). As the URL rule `url.learned_domain` (category `learned`, cap 0.5) it reports the domain parts that pushed the score; it skips official and popular domains; in mail its category `link.learned` is capped at 0.3. Scoring under 1 ms.

**The brain** (`core/brain`, off unless `LYNCEUS_BRAIN=true`). A local model through `core/llm/ollama.py` (loopback only, schema-constrained answers, size caps, fixed error text) answers closed forms:

| Question | Input | Finding (only if code confirms it) |
|---|---|---|
| Page text (P2) | address, domain, title, headings, visible text, form fields and where they post | `brain.page_impersonation` (a quoted brand on a domain it does not own, on a credential page); `brain.page_pressure` |
| Page code (P4) | the page's own code | `brain.page_script_exfiltration` (typed data sent to another site or a chat bot; the passage is in the code, the endpoint was contacted) |
| Screenshot (P3) | the screenshot re-encoded in the parser sandbox | `brain.page_visual_brand` (a listed brand, off its domain, credential page, confidence 70+) |
| Mail (P5) | sender, subject, the sandbox's message excerpt | `brain.mail_intent` (a costly ask and a pressure tactic, both quoted); `brain.mail_impersonation` |

Untrusted text is fenced between markers it cannot forge; answers are validated against a closed pydantic schema (anything else is no answer); quotes are matched after folding case, width, quotes and whitespace. Findings become signals in category `brain` (cap 0.7): alone SUSPICIOUS at most, with one independent rule category MALICIOUS, never lower than before. A finding that repeats a rule already fired on the same evidence is dropped. One question at a time, one time budget per verdict; a late question keeps the findings already checked. The API applies it after detonation and message analysis; the mailbox poller through `core/mailbox/wiring.py`, on a fresh event loop per message.

---

## 10. The Windows agent (`agent/`, ADR-016)

A per-user .NET program (not a Windows service, so it needs no administrator rights and runs in the user's session where notifications work). Started at logon by `HKCU\...\Run\LynceusAgent`.

| Source file | Job |
|---|---|
| `AgentService.cs`, `Program.cs` | host, startup, command line (`--install`, `--uninstall`, `--status`, `--open-console`, `--console-link`, `--set-token`) |
| `CoreSupervisor.cs` | starts the Python core (`uvicorn` on `127.0.0.1:8765`, no access log, no server header) and restarts it if it exits |
| `FilePipeline.cs`, `Folders.cs`, `FileSignatures.cs` | watches Downloads; waits until a file is quiet for 1 s and can be opened; gives up after 10 minutes of locking; re-scans after watcher overflow; checkpoint across restarts |
| `MarkOfTheWeb.cs` | reads the download's Zone.Identifier to take the source host (never sent beyond the host) |
| `CoreClient.cs`, `CoreHttp.cs` | talks to the core over loopback with the bearer token; retries with back-off (1 s to 60 s, 5 attempts) |
| `Spool.cs` | files waiting for a verdict survive restarts (10,000 at most) |
| `PipeServer.cs`, `RequestHandler.cs` | named pipe for the browser's native host: current user only, per-install secret |
| `Toasts.cs` | Windows notifications |
| `ActionRunner.cs`, `QuarantineStore.cs` | carries out approved quarantine and restore actions, reports results to the core |
| `MailboxWatcher.cs` | notifies when the mailbox needs re-authorization or flags a message |
| `TokenStore.cs` | the API token under **DPAPI** (current user) |
| `ConsoleLink.cs` | opens the console with the token in the address fragment once |
| `RollingLog.cs` | size-limited local log |
| `Installer.cs` | Run key, native-messaging registration for Edge and Chrome |

Settings live in `agent.json` (`%LOCALAPPDATA%\Lynceus`): `CoreUrl`, `WatchFolders`, `StableMillis` 1000, `GiveUpSeconds` 600, `MaxInspectBytes` 16 MiB − 4 KiB, `ResponseMode` `ask` (default) | `auto` | `off`, and the core command line.

---

## 11. The browser extension (`extension/`, Manifest V3)

- **Permissions:** `nativeMessaging`, `webNavigation`, `storage`, `declarativeNetRequestWithHostAccess`; site access (`http://*/*`, `https://*/*`) is optional and asked for on the options page. Minimum Chrome/Edge 116. The extension ID is pinned by a key in the manifest.
- **Flow** (`guard.ts`): on every top-level navigation (`onBeforeNavigate`, and `onCommitted` for where a redirect ended) the service worker asks the agent through the native host (`check_url`). It **never holds the navigation**: the check runs beside it. A SUSPICIOUS or MALICIOUS answer replaces the tab with the extension's warning page.
- **Block before load:** a URL already judged bad gets a `declarativeNetRequest` session redirect rule (exact URL, main frame, up to 500 rules), so the next visit goes to the warning page **before any request is sent** (needs the optional site access).
- **Verdict cache** keyed by a hash of the URL (`store.ts`), not the URL text.
- **"Continue anyway":** allowed only for a URL the extension itself judged bad, recorded by the agent (`/v1/overrides`), valid 15 minutes.
- **Fail open, visibly:** if the agent is down the page loads normally and the toolbar badge shows red `!`; if the agent is up but the core is not, amber `?`.
- Popup shows protection state and counts; frames inside pages are not checked.

---

## 12. Console, analysis workbench and desktop window (`console/`, `shell/`)

A React 19 single-page app built with esbuild into `console/dist` and served by the core at `http://127.0.0.1:8765/console/` (same origin as the API, strict Content Security Policy, token kept in `sessionStorage`).

| Page | Purpose |
|---|---|
| `#/analyze` (workbench) | paste a link, drop an `.eml` or drop any file; see the verdict, the score, every signal with its category colour, the anatomy of the link (scheme, subdomain, registered domain, path, query), the evidence and the provider results |
| `#/events` | every stored verdict with its evidence |
| `#/actions` | pending, applied, failed and restored responses; approve, dismiss, restore |
| `#/allow` | the allow-list |
| `#/audit` | the audit log |

Light and dark themes (colour contrast computed to WCAG AA). The **Tauri 2** shell (`shell/`) wraps the same console in a native window (ADR-019).

---

## 13. The response engine (`core/response`, ADR-018)

The core decides and records; the agent acts; the console asks.

- **Only MALICIOUS** files (and, with the separate write permission, MALICIOUS messages) get a proposed action. SUSPICIOUS is never moved.
- **State machine** (`machine.py`, a table nothing else overrides):
  `PENDING → APPROVED → APPLIED → RESTORE_REQUESTED → RESTORED`, plus `FAILED` (retry by approving again) and `DISMISSED`. Every event is **idempotent**: repeating it is a no-op that says so; an impossible step is refused, never forced.
- **File quarantine** (agent): the file is moved to `%LOCALAPPDATA%\Lynceus\quarantine\<id>\payload.quar` after checking its SHA-256 still equals the judged one. Across drives it is copied, verified byte for byte, then the original removed. The Mark of the Web is kept so a restore puts it back. Nothing is ever deleted.
- **Email quarantine** (M6b): Gmail label / Outlook folder `Lynceus Quarantine`, only with the separate wider permission (`connect --write`), held to a handful of request shapes by a guard that cannot delete or send.
- **Modes** (`ResponseMode`): `ask` (default, the user approves in a notification or the console), `auto` (MALICIOUS files only), `off`.
- **Audit:** every approve, dismiss, restore and result is written to `audit_logs`.
- Restore puts the file back exactly as it was (still dangerous); the allow-list stops further proposals for that exact content.

---

## 14. Live mailboxes (`core/mailbox`, ADR-017)

Off until `LYNCEUS_GMAIL_ENABLED` / `LYNCEUS_OUTLOOK_ENABLED`.

| | Gmail | Outlook / Microsoft 365 |
|---|---|---|
| API | Gmail REST, `history.list` for changes | Microsoft Graph, delta queries |
| Sign-in | OAuth 2.0 with PKCE, loopback redirect | OAuth 2.0 (Microsoft identity platform) |
| Read scope | `gmail.readonly` | `Mail.Read` |
| Write scope (separate, M6b) | `gmail.modify` | `Mail.ReadWrite` |
| Polling | every 60 s, look-back 2 days on first connect and after a lost position | same |
| Token at rest | DPAPI (current user) | DPAPI |
| Status | **tested against a fake Gmail only** | **tested against a fake Graph only** |

Each new message is analysed once (de-duplicated by id, 5,000 ids remembered), missed mail is found again after a gap, and a flagged message produces a notification with rule names and a score (no sender or subject, which the engine never reports).

---

## 15. End-to-end flows

**Browsing.** Tab navigates → extension `check_url` → native host → pipe → agent → `POST /v1/urls/analyze` → URL rules + lists → scoring → verdict back to the extension (tens of milliseconds) → cached; if bad, warning page and a block-before-load rule.

**Download.** Browser writes a file to Downloads → watcher sees it → agent waits for it to settle, reads Mark of the Web host, hashes it → `POST /v1/files/analyze` → sandbox deep scan + hash lists (+ model review if a macro was found) → verdict stored → if MALICIOUS: notification and a PENDING action → user approves → agent quarantines → result recorded and audited.

**Email.** Poller sees a new message → raw bytes → sandbox parse → attachments each in a sandbox → links through the URL engine → scoring → verdict stored → notification if flagged → (with write permission) proposed move to the quarantine label/folder.

**Analyze page.** User pastes a link or drops a file in the console → the same API routes → the full verdict with evidence on screen.

---

## 16. Security model

Full threat model: [THREAT_MODEL.md](THREAT_MODEL.md). Independent adversarial review: [milestones/R1.md](milestones/R1.md).

| Threat | Defence |
|---|---|
| A malicious file exploits a parser | parsing only in the AppContainer + Job sandbox; native parsers pinned by hash; output validated against a closed vocabulary |
| Archive, image or PDF bombs | declared-size and ratio checks (256 MiB, 100×), 48 MiB read budget, 16 M pixels, 100,000 PDF objects; tested with generated bombs |
| SSRF through URL fetching | resolver re-validates every hop and resolved IP, refuses private, loopback, link-local and metadata ranges (built, off) |
| Another web page calls the core | loopback only, `Host` check, bearer token, CORS closed, rate limits |
| Another program talks to the agent | named pipe restricted to the current user plus a per-install secret |
| A web page fakes a "continue anyway" | the override uses the extension's own cached verdict, recorded by the agent |
| Prompt injection into the model | comments stripped, schema-constrained answer, fixed vocabulary, advice capped below decisive weight, cannot lower or decide |
| Secrets leaking | DPAPI for tokens, redacting logs, `detect-secrets` pre-commit scan, `.env` out of git |
| Data leaving the machine | one egress gate; intel off by default and domain-only; a test forbids other network code |
| Installing from a packaged app's private registry (found 2026-11-10) | `install.ps1` and `go-live.ps1` refuse to run there and check Windows' own view through WMI (ADR-024) |

Known open items: one shared API token for all components; the checkout folder inherits write access for other local accounts unless `install.ps1 -HardenAcl` is used; frames inside pages are not checked; evidence encryption at rest (ADR-007) is not implemented.

---

## 17. Configuration

Core settings (`.env`, prefix `LYNCEUS_`; old `MIRAGE_` names still work):

| Setting | Default | Meaning |
|---|---|---|
| `API_TOKEN` | none (required) | bearer token for every API call |
| `DATABASE_URL` | none | PostgreSQL; without it nothing is stored |
| `MAX_CONCURRENT_PARSERS` | 4 | parallel sandbox parses |
| `RATE_LIMIT_PER_MINUTE` / `URL_RATE_LIMIT_PER_MINUTE` | 120 / 1200 | request limits |
| `INTEL_PROVIDERS` | empty | e.g. `openphish,phishtank` |
| `INTEL_DEADLINE` | 2.0 s | longest wait for providers |
| `INTEL_EMAIL_LINKS` | false | let message links reach query providers |
| `PHISHTANK_KEY`, `URLHAUS_AUTH_KEY`, `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY` | none | provider keys |
| `RESOLVE_REDIRECTS` | false | redirect resolver |
| `LLM_REVIEW` / `LLM_URL` / `LLM_MODEL` / `LLM_TIMEOUT` | false / `http://127.0.0.1:11434` / `llama3.2:3b` / 45 s | local model reviewer |
| `DETONATION` / `DETONATION_PER_MINUTE` | false / 6 | page detonation on request (D1) |
| `GMAIL_ENABLED`, `OUTLOOK_ENABLED` (+ client ids, tenant, look-back, poll interval) | false | live mailboxes |
| `DATA_DIR` | `.data` | lists, hashes, tokens |

Agent settings: `agent.json` (section 10). Scoring: `rules/*/scoring.toml`. Word lists and brands: `rules/*/lists.toml`, `rules/url/brands.toml`.

---

## 18. Deployment

| Tool | What it does |
|---|---|
| `python tasks.py up` | starts PostgreSQL 17 in Docker |
| `python tasks.py migrate` | applies Alembic migrations |
| `python tasks.py sandbox` | builds `.sandbox/` and registers the AppContainer profile |
| `python tasks.py detonator` | builds the page-detonation image `lynceus-detonator:1.0.0` (D1) |
| `deploy\install.ps1` | builds agent, extension and console; installs to `%LOCALAPPDATA%\Programs\Lynceus`; registers start at logon and the native-messaging host for Edge and Chrome; starts the agent and waits for the core; `-HardenAcl` restricts the checkout to the user, SYSTEM and Administrators. Running it again upgrades; data is never touched |
| `deploy\go-live.ps1` | the cutover: refuses a private registry, stops old agents, rebuilds the sandbox, removes the old MIRAGE registration, installs, writes the engine settings, starts the agent, checks Windows' own view; `-CheckOnly` verifies without changing anything |
| `deploy\uninstall.ps1` | removes registrations and programs; `-RemoveData` deletes data and refuses while files are still in quarantine |
| `deploy\msi\build-msi.ps1` | builds the per-user WiX MSI (no administrator rights; unsigned) |

Must be run from a normal Start-menu PowerShell: a terminal inside a packaged (MSIX) app writes to a private copy of the registry and AppData (ADR-024).

---

## 19. Testing and measurement

### 19.1 Test suites (latest local runs)

| Suite | Tool | Result |
|---|---|---|
| Core, rules, sandbox, deploy scripts, adversarial, regression | pytest (`python tasks.py test`) | 2,540 passed, 9 skipped |
| Agent | xUnit (`dotnet test agent/Lynceus.slnx`) | 349 passed |
| Extension | vitest + puppeteer on real Edge | 114 unit + 7 end-to-end |
| Console | vitest + puppeteer on real Edge | 60 unit + 12 end-to-end |
| Lint and types | ruff, mypy (strict), TypeScript `strict` | clean |

Also: every rule has at least one positive and one negative fixture (`corpus/rule_fixtures.toml`, enforced by a test); generated bomb fixtures; bounded fuzzing (320,000 URL inputs); tests block all non-loopback network use. **CI has never run** (there is no remote).

### 19.2 Evaluation harness (`eval/`)

- `python -m eval` / `python tasks.py eval`: precision, recall, F1, abstain rate and Wilson 95% intervals on the labelled synthetic corpus (dev split; holdout runs are explicit and logged; the reserve split is sealed).
- `python -m eval.realurl`: the real-data URL evaluation (E1).
- `python -m eval.perf`: latency and throughput.
- `python -m eval.detonate`: page detonation on live pages (D1); URLs split by a fixed hash into a dev half (the only one rules may be tuned on) and a test half (the headline); `--rescore` judges the kept pages again without opening anything.

### 19.3 Results

| Measurement | Result |
|---|---|
| URL rules, synthetic dev (n=150) | precision 1.000, recall 0.966, abstain 33% |
| Messages, synthetic dev (n=119, 2026-11-05) | precision 1.000, recall 0.973; holdout (n=35) recall 1.000 |
| **URL rules on real phishing (E1, n=133,195)** | **2.5% caught**; 3.2% on fresh feeds; 22.9% of OpenPhish's 266 |
| E1: real phishing where no URL rule fires at all | 91.2% (the "lexical ceiling") |
| E1: false alarms on legitimate URLs (n=166,265) | 0.3% |
| E1: owner's own browsing (local only, counts only) | 0 of 87 after ruleset 1.1.0 (was 9.2%) |
| Macro corpus (synthetic) | 8/8 malicious flagged (7 MALICIOUS), 0/10 benign fire a new rule |
| Local model on test macros | 24/24 valid and agreeing (6 held out) |
| **Live phishing pages, URL rules + opened page (D1 test half, 118 alive)** | **37.3%** caught (URL rules alone 16.9%), 9.3% MALICIOUS |
| Live legitimate pages flagged (D1 test half, 186 alive) | 3.8%; the page rules added 1 |

The synthetic numbers measure that the rules do what they were written to do. The E1 number is the honest one for URLs: reading the address alone catches little real phishing; lists catch what they already know. E1 data sources: PhiUSIIL (CC BY 4.0), PhishTank, OpenPhish, Tranco top 1M, the owner's Edge history (read locally, never stored); split by a fixed hash seed into train 60 / test 30 / sealed reserve 10.

### 19.4 Performance (one machine, `docs/PERFORMANCE.md`)

| Path | p50 | p95 |
|---|---|---|
| URL engine, in process | about 0.8 ms per URL | about 1.4 ms |
| API, 8 concurrent clients, URL analysis | 27.5 ms, 279 requests/s | 44 ms |
| Message through the sandbox: plain / HTML / with attachment | 314 / 350 / 699 ms | 364 / 401 / 769 ms |
| File through the sandbox: text / small PDF / zip of 20 | 197 / 458 / 265 ms | 212 / 499 / 289 ms |
| Model review of a macro | 15 to 35 s cold, capped at 45 s | |

Sizes: console bundle 617,624 bytes; extension service worker 13,837 bytes; sandbox folder about 208 MB.

---

## 20. Repository layout

```
core/         FastAPI app
  api/          routes, auth, limits, console serving
  contracts/    pydantic data contracts (Verdict, Signal, Evidence, ...)
  urls/         WHATWG parsing, PSL, link extraction, SSRF-safe fetch
  detection/    URL engine
  email/ files/ message and file engines
  sandbox/      sandbox host, Windows AppContainer/Job code, build; guest/ = code that runs inside
  intel/        providers, feeds, hash lists, egress gate, refresh loop
  risk/         scoring and correlation
  llm/          local model reviewer
  response/     action state machine and routes
  mailbox/      Gmail and Graph clients, OAuth, sync, quarantine
  db/           models, store, audit, migrations
rules/        url/ email/ intel/: rules as code + TOML data
corpus/       synthetic labelled samples, rule fixtures
eval/         evaluation harness (synthetic, real URLs, performance)
agent/        Lynceus.Agent, Lynceus.NativeHost, Lynceus.Ipc, tests (.NET)
extension/    MV3 extension (TypeScript)
console/      React console and workbench
shell/        Tauri desktop window
deploy/       install, go-live, uninstall, ACL, registry view, msi/
infra/        docker compose for PostgreSQL
tests/        unit/ integration/ sandbox/ adversarial/ regression/
docs/         this file, FEATURES, SPEC, DECISIONS, THREAT_MODEL, PRIVACY, OPERATIONS, milestones/, eval/, schemas/
tasks.py      task runner: up, test, eval, lint, migrate, sandbox, deps, serve, fmt, secrets, hooks
```

---

## 21. Architecture decisions (index)

ADR-001 modular monolith · 002 Redis deferred · 003 task runner and git hooks · 004 dependencies · 005 eval scoring rule · 006 M0 conventions · 007 evidence encryption (unsigned) · 008 parser sandbox · 009 local IPC · 010 email transport · 011 resolver egress policy · 012 WHATWG URL parsing with ada-url · 013 rules-only verdicts and the scoring model · 014 message analysis conventions · 015 threat-intel providers and egress · 016 per-user agent, not a service · 017 read-only Gmail poller · 018 response engine · 019 WiX installer and Tauri window · 020 deep content analysis and known-bad hashes · 021 rename to Lynceus · 022 providers on, lists kept fresh · 023 macros read as programs, the model advises · 024 a registration is believed only when Windows shows it.

Full text: [DECISIONS.md](DECISIONS.md).

---

## 22. Development history

81 commits from 2026-11-04 (M0) to 2026-11-10 (E1, URL ruleset 1.1.0), in milestones: M0 foundation · M1 URL engine · M2 messages and files in the sandbox · M3 threat intelligence (v0.1) · M4 agent and extension · M5 / M5b Gmail and Outlook · M6 / M6b responses and email quarantine · M7 hardening and deploy · R1 independent security review · UI1 workbench · R2 installer and window · R3 deep content and hashes · ADR-023 macro analysis and the model · E1 real-data evaluation. Each milestone's plan, acceptance criteria and results: [milestones/](milestones).
