# Decisions (ADR log)

Status values: **Accepted** (in force), **Draft: needs human sign-off** (proposal only; do not build on it yet).
`docs/SPEC.md` is the owner's original spec, saved verbatim (byte-identical; kept out of line-ending conversion). Section references (§) point into it.

| ADR | Title | Status |
|---|---|---|
| 001 | Modular monolith, trimmed layout | Accepted |
| 002 | Redis deferred | Accepted |
| 003 | Task runner and git hooks | Accepted |
| 004 | Dependencies and their purpose | Accepted |
| 005 | Eval scoring rule | Accepted (flag-rate line added in M1, see below) |
| 006 | M0 conventions: contracts, logging, corpus, migrations | Accepted (checked against SPEC §7/§8; one difference to confirm) |
| 007 | Evidence encryption at rest and key management | Draft: needs human sign-off, decide before M1 writes evidence |
| 008 | Parser sandbox | Accepted 2026-11-05: option B, a restricted Windows process |
| 009 | Local IPC | Draft: needs human sign-off, decide before M4 |
| 010 | Email transport | Draft: needs human sign-off, decide before M5 |
| 011 | Resolver egress policy | Draft: needs human sign-off. Code exists but is off and unwired |
| 012 | URL parsing: WHATWG via ada-url | Accepted |
| 013 | Rules-only verdicts and the scoring model | Accepted |
| 014 | Message analysis conventions (M2) | Accepted with the M2 plan; parts marked "deviation" need a glance |
| 015 | Threat-intelligence providers and the egress policy (M3) | Accepted with the M3 plan (D1 to D8 approved) |

---

## ADR-001: Modular monolith, trimmed layout
**Status:** Accepted. **Deviates from SPEC §14**, which permits it ("may adjust this structure when justified by engineering requirements"). The spec's monorepo (`apps/`, one folder per service, `integrations/`, `shared/`) is collapsed into one `core/` package, and the Compose file lives in `infra/`.

- **Context:** one developer, local-first, a single machine. Microservices would add deployment and IPC surface for no measured benefit.
- **Decision:** one FastAPI app with internal packages (`core/api`, `core/contracts`, ... ) and the simpler top-level layout in `CLAUDE.md`. `agent/`, `extension/` and `console/` are created in the milestones that need them (M4, M6); empty folders are not tracked by git.
- **Consequences:** split a package into a service only after a measured need (throughput, isolation, independent deploy). The parser sandbox (ADR-008) is the one expected out-of-process piece.

## ADR-002: Redis deferred
**Status:** Accepted. **Deviates from SPEC §4** (task queue: Redis; §15 phase 1 also lists Redis).

- **Decision:** no queue or cache server until something needs one. PostgreSQL plus in-process asyncio covers M0-M2.
- **Revisit when:** provider fan-out (M3) or the email backlog (M5) shows a measured need for a durable queue, or caching hit rates justify a shared cache.

## ADR-003: Task runner and git hooks
**Status:** Accepted.

- **Context:** Windows development; `make` is not installed; `just` and `task` are not installed. Adding a binary for five commands is more than the job needs.
- **Decision:** `tasks.py`, standard library only (`python tasks.py up|test|eval|lint|migrate`, plus `fmt`, `secrets`, `hooks`, `precommit`). It prefers the project `.venv` interpreter, so no activation is needed, and runs from the repo root. CI runs the same tasks.
- **Git hooks:** a versioned `.githooks/pre-commit` (enabled per clone by `python tasks.py hooks`) runs lint, then the secret scan on staged files. It is written without subshells or pipes on purpose.
- **Rejected:** the `pre-commit` framework. On the development machine Git for Windows' `sh` cannot fork (also breaks Git Bash), so its generated hook script and its remote-hook cloning both fail. Local `.githooks` needs no clone, no remote hook code to trust, and drops a dependency.
- **Consequences:** the hook lints the working tree, not the index, so a partially staged commit can be judged on unstaged edits. The secret scan uses `detect-secrets` with `.secrets.baseline` (one known placeholder: the dummy DB URL in `.env.example`). Fake secrets in tests carry `# pragma: allowlist secret`.

## ADR-004: Dependencies and their purpose
**Status:** Accepted (approved with the M0 plan, 2026-11-04; M1 additions approved 2026-11-04). Versions are lower bounds in `requirements*.txt`; no lock file yet (M7).

| Package | Used for |
|---|---|
| fastapi, uvicorn | HTTP API (`/health` now, analysis endpoints from M1) |
| pydantic, pydantic-settings | contracts (the verdict model) and env-based config |
| sqlalchemy, alembic, psycopg[binary] | schema, migrations, PostgreSQL driver (sync; async is not needed yet) |
| ada-url (`>=4.0,<5`) | WHATWG URL parsing and IDNA (ADR-012). Native library via cffi; Apache-2.0 |
| pytest, httpx | tests; httpx is FastAPI's `TestClient` backend |
| ruff, mypy | lint, format, strict type check |
| detect-secrets | secret scanning in the hook and CI |

- **Logging** uses the standard library with a redacting formatter; no structlog.
- **`idna` was approved for M1 but is not added:** `ada_url.idna` already converts to and from punycode with the same UTS #46 rules the parser uses.
- **httpx** becomes a runtime dependency at the M1 resolver step only.
- **M2a added no dependency.** The plan listed `beautifulsoup4`; the worker uses the standard library's `html.parser` instead (ADR-014).
- **M2b adds the sandbox-only libraries in `requirements-sandbox.txt`** (approved in principle with the M2 plan; licences, versions and wheels checked on pypi.org on 2026-11-05). They are pinned with `==` and wheel hashes, installed with `--require-hashes --only-binary --no-deps` into `.sandbox/runtime` by `python tasks.py sandbox`, and into the dev venv so the scanners can be tested in-process. The host process never imports them.

  | Package | Licence (PyPI metadata) | Used for |
  |---|---|---|
  | pikepdf 10.17.0 | MPL-2.0 (bundles qpdf) | PDF triage: objects, actions, URIs. **Not PyMuPDF** (AGPL). Brings **lxml 6.1.3** (BSD-3-Clause) and **packaging 26.3**, which were not on the approved list: pikepdf imports lxml at load, so they cannot be left out |
  | Pillow 13.0.0 | MIT-CMU | image header check, decode, format allow-list |
  | opencv-python-headless 5.0.0.93 | Apache-2.0 | `QRCodeDetector` only. Brings **numpy 2.5.4** (BSD-3-Clause and others). The wheel bundles an FFmpeg plugin (29 MB, not reviewed); the sandbox build deletes it because nothing here decodes video |

  **OCR is deferred (owner decision, 2026-11-05).** Tesseract is not installed here, and the sandbox allows one process (`ActiveProcessLimit=1`), so an OCR step would need an in-process binding or a change to ADR-008. Image text is not read in M2. Reopen with its own plan when it is wanted: it needs a Tesseract install with Polish data, a decision on how it runs inside the sandbox, and a corpus of screenshots with typed URLs to measure it.
- **M3 added no dependency.** `httpx` was already approved and listed; `bz2`, `asyncio` and `json` are standard library.
- **M4 adds .NET packages (approved with the M4 plan, D7; versions and licences checked on nuget.org on 2026-11-05).** Central version file `agent/Directory.Packages.props`, lock files committed (`packages.lock.json`, content hashes), NuGet audit on. `Microsoft.WindowsAppSDK` was **not** added (spike 2: toasts need only the SDK's own Windows target).

  | Package | Used for |
  |---|---|
  | Microsoft.Extensions.Hosting 10.0.14 (MIT) | the agent's host: lifetime, logging, dependency injection |
  | xunit 2.9.3 (Apache-2.0), Microsoft.NET.Test.Sdk 18.10.1 (MIT) | agent tests |
  | xunit.runner.visualstudio 3.1.5 (Apache-2.0) | lets `dotnet test` run xunit. **Not named in the D7 list**; it cannot be left out |
  | System.Security.Cryptography.ProtectedData 10.0.14 (MIT) | DPAPI (current user) for the stored API token. Not in the shared framework (spike 4) |

- **M4 adds npm dev dependencies for the extension (approved with the M4 plan, D7; versions checked on the npm registry on 2026-11-05; each is at least two weeks old).** Exact versions in `extension/package.json`, `package-lock.json` with integrity hashes, installed with `--ignore-scripts`, `npm audit`: 0 vulnerabilities. None ships in the extension: esbuild bundles only the project's own TypeScript.

  | Package | Licence | Used for |
  |---|---|---|
  | typescript 5.9.3 | Apache-2.0 | type check (strict). **7.x was not chosen**: a new major rewrite, not needed |
  | esbuild 0.28.2 | MIT | bundle the four entry points for the browser |
  | @types/chrome 0.3.6 | MIT | types for the extension APIs (type-only) |
  | vitest 5.0.5 | MIT | unit tests with a fake `chrome` |
  | puppeteer-core 25.16.0 | Apache-2.0 | drive the installed Edge for the end-to-end test (M4 step 6). It downloads no browser |

  No `@types/node` was added: the one test that reads files declares the three Node calls it needs in `extension/test/node-shim.d.ts`.

- **M6 adds npm dev dependencies for the console (approved with the M6 plan, D7; checked on the npm registry on 2026-11-05; each at least two weeks old).** `console/package.json` pins exact versions, `package-lock.json` has integrity hashes, installed with `--ignore-scripts`, `npm audit`: 0 vulnerabilities.

  | Package | Licence | Used for |
  |---|---|---|
  | react 19.2.9, react-dom 19.2.9 | MIT | the console's user interface (bundled into `console/dist/console.js`) |
  | @types/react 19.2.18, @types/react-dom 19.2.7 | MIT | types only |

  `typescript`, `esbuild`, `vitest` and `puppeteer-core` repeat the versions already approved for the extension. No Python or .NET dependency was added.
- **Open:** pytest prints a Starlette deprecation warning saying `TestClient` over `httpx` is deprecated in favour of a package named `httpx2`. Not acted on (a dependency change needs approval); revisit when it stops being a warning.

## ADR-005: Eval scoring rule
**Status:** Accepted.

- **Positive prediction** = SUSPICIOUS or MALICIOUS. **Negative prediction** = BENIGN. **Positive sample** = label `malicious`.
- **UNKNOWN** is an abstention, reported as `abstain_rate`; **ERROR** is reported as `error_rate`. Neither is ever counted as BENIGN, so neither can become a true negative or hide a miss.
- **FN** (headline) = positive samples not flagged, for any reason: engine said BENIGN, abstained, or errored. The breakdown is in the counts. (M1 owner confirmation: UNKNOWN on a malicious sample is a miss.)
- **Headline recall** = TP / (TP + FN). **Recall (answered only)** = TP / (TP + FN where engine said BENIGN) is always shown next to it, never instead of it.
- **Precision** = TP / (TP + FP). **F1** = 2TP / (2TP + FP + FN). Undefined values (zero denominator) print as `n/a`, not 0 or 1.
- **Flag rate (added in M1):** on benign samples, flag rate = FP / benign samples. UNKNOWN on a benign sample counts as not flagged. Reported next to precision, with the abstain rate on its own line.
- **Why:** an engine that abstains on everything hard must not look precise. Headline numbers are computed on the full set; `--split holdout` reports the untouched part.
- **Latency:** per-sample wall time of `analyze()`, p50 / p95 / max (nearest-rank).

## ADR-006: M0 conventions
**Status:** Accepted. Checked against SPEC §7 and §8 on 2026-11-04: every field §7 requires is present (risk score, confidence, signals, evidence references, provider results, timestamp, recommended and applied response). One deliberate difference, for the owner to confirm: §7 lists a risk score on every verdict, but ours is `null` for UNKNOWN and ERROR, because a number (above all 0) would read as a safety judgement.

- **Contracts** (`core/contracts.py`): frozen, `extra=forbid` pydantic models; timestamps must be timezone-aware; JSON Schemas are exported to `docs/schemas/` and a test fails if they drift. Artifacts hold a hash and a locator, never raw email or file content.
- **Verdict invariants:** `risk_score` is `None` exactly when the state is UNKNOWN or ERROR (a 0 would read as "safe"); every signal's evidence must be listed on the verdict; a provider result carries a state only when its status is OK. The same rules are CHECK constraints in the database.
- **`resolve_state`** (provider opinions to one state) is a conservative placeholder: no results is UNKNOWN, only failures is ERROR, BENIGN needs every queried provider to say BENIGN, otherwise the most severe answer wins. M3 replaces it with real correlation.
- **`ResponseAction`** has no delete action: responses are reversible (§8: never auto-delete). Its members follow §8: record only (NONE), notify or warn (WARN), block browser navigation (BLOCK), isolate or quarantine (QUARANTINE). "Request confirmation before destructive actions" is a gate in the response engine (M6), not an action. §13 also lists a `response_actions` table; it arrives with that engine.
- **Logging:** JSON lines. Secret-looking keys and bearer/`password=`-style text are redacted. Any URL (any scheme) is logged only as `url[host=... sha=...]`. Run uvicorn with `--no-access-log` because its access log would carry raw URLs.
- **Corpus:** every seed host must be unregisterable (`.test`, `.invalid`, `.example`, `example.com/.org/.net`, RFC 5737 and 3849 addresses); the loader rejects anything else (M1 relaxes this for benign hard negatives only, via an `origin` field). Each entry has `split`; never tune against holdout. SSRF probe inputs live in `tests/adversarial/`, outside the scored corpus.
- **Migrations:** the initial migration could be edited in place until M3 (v0.1). **It is frozen as of v0.1** (M3 changed no schema; a test pins its hash): from now on the schema changes only through a new, forward-only migration.
- **Source files stay ASCII.** Test inputs that need non-ASCII characters (homoglyphs, zero-width characters) are written as `\uXXXX` escapes, so no invisible or confusable character hides in source.

---

## ADR-007: Evidence encryption at rest and key management
**Status:** Draft: needs human sign-off. Decide before M1 writes any evidence.

- **Context:** CLAUDE.md requires evidence and credentials encrypted at rest. M0 only separates storage: sensitive bytes may exist solely in `evidence_payloads` (`ciphertext`, `key_id`); everything else holds hashes and redacted summaries. Encryption itself is not implemented.
- **Options for the key:**
  - A. Key protected by Windows DPAPI (user scope), stored beside the database. No password to manage; ties data to the Windows user.
  - B. Key from the environment or `.env`. Simple; only acceptable for development and CI.
  - C. Rely on disk encryption (BitLocker) and database permissions only. Does not satisfy the requirement against another process running as the same user.
- **Proposal:** A in production, B behind an explicit dev flag. AES-256-GCM, a fresh nonce per payload, `key_id` recorded for rotation. Needs one new dependency, `cryptography` (ask before adding). Lookups use stored hashes; plaintext is decrypted only for display.
- **Open question:** `artifacts.ref` and `extracted_urls.url` hold URL text, which is private. Proposal: move URL text into encrypted payloads and keep `sha256` + `host` for lookup.
- **M1 consequence (owner decision D2):** M1 persists hashes, host, verdict, signals and redacted evidence only; full URL text waits for this ADR.

## ADR-008: Parser sandbox
**Status:** Accepted 2026-11-05 by the owner (option B). Implementation notes and what was actually verified are at the end of this ADR.

- **Context:** documents, archives and images are hostile input (CLAUDE.md rule 5). The parser must have hard limits (time, memory, size, archive depth and ratio) and no network. The target is an end-user Windows PC.
- **Options:**
  - A. **Container worker** (Docker, no network, read-only filesystem, cgroup limits). Strong, reproducible, same in CI. Requires Docker Desktop on every end-user machine: heavy and not available by default.
  - B. **Restricted Windows process** (Job Object for CPU/memory/process limits, AppContainer or restricted low-integrity token, firewall rule or token that denies network). Native, no dependency, fast start. Weaker isolation than a VM; more Windows-specific code.
  - C. **VM** (Hyper-V or Windows Sandbox). Strongest, but slow to start, heavy, and edition-dependent.
- **Proposal:** B as the product default, with a narrow stdin/stdout protocol between core and the worker; run the same worker under a Linux container in CI to exercise bomb and malformed-file fixtures portably. Revisit C only if the threat assessment demands it.
- **Verify before building:** current AppContainer and Job Object documentation; that network denial really holds on the target Windows editions.

**Implementation (M2 step 1, 2026-11-05)** — `core/sandbox/`:
- **Two layers.** An AppContainer token with no capabilities denies the network and every file not granted to its SID; a Job Object adds hard limits (committed memory, user CPU time, exactly one process, no UI access, kill when the handle closes). The parent adds a wall-clock deadline and an output cap, and kills the job when either is hit.
- **What the worker can touch:** a private copy of the interpreter and the worker code under `.sandbox/` (about 36 MB), read-only. The project root, which holds `.env`, is never granted. The worker's whole environment is four variables with no real user path in them.
- **Side effect outside the project, to know about:** Windows will not start a process in an AppContainer whose profile is not registered, so `python tasks.py sandbox` registers one per user (a registry key and `%LOCALAPPDATA%\Packages\mirage.parser`) and runs `icacls` on `.sandbox` only. `python -m core.sandbox.build --remove` undoes both.
- **Protocol:** stdin is a 4-byte length, a JSON header, then the raw body; the answer is one JSON document on stdout. The parent treats it as untrusted: size-capped, schema-validated, never executed.
- **Fails closed:** a missing or non-starting sandbox raises `SandboxUnavailable`; no caller may parse in-process instead.
- **Proved by 29 tests** (`tests/sandbox`), each with a positive control: the worker's token is an AppContainer; it cannot read your files, the project, `.env` or your home folder, cannot write anywhere, cannot connect even to loopback, cannot start programs; memory, CPU, wall-clock and output limits each stop it while the caller survives; it dies with its parent; nothing outlives a run. **Seven deliberate breakages** of the controls were each caught by a test.
- **Checked by hand, outside pytest:** a real non-loopback connection (this machine's LAN address, and 1.1.1.1:443) succeeds from outside the sandbox and is denied inside it.
- **Not proved, to be honest about:** the Job Object's UI restrictions are untested; the boundary is only as strong as Windows' AppContainer and the Win32 calls (no separate review); the worker is still CPython plus whatever parsers run in it, so a memory-safety bug there is contained, not prevented; start-up costs about 0.7 s per run; the interpreter copy goes stale when Python is upgraded and needs `python tasks.py sandbox` again; Windows only, and the tests skip elsewhere, so a Linux CI would not exercise this.

## ADR-009: Local IPC
**Status:** Accepted (M4 plan D2, approved 2026-11-05; built in M4 step 3).

- **Decision:** option A between host and agent, option B between agent and core. Spike results (M4.md): `PipeOptions.CurrentUserOnly` leaves one ACL entry, the current user; a same-user client connects; the browser refuses a wrong extension ID itself; a host round trip takes under a millisecond. Built: a per-user pipe name, a per-install secret in `%LOCALAPPDATA%\Mirage\pipe.secret` (created once, compared in constant time), a 2 s handshake deadline, at most 4 clients, 64 KiB frames, strictly validated versioned messages (unknown type, unknown field, wrong type, repeated key and odd sizes are all refused), and a host that checks the browser-supplied origin, forwards only validated messages, answers `agent_unavailable` at once when the agent is down, and exits when the browser closes its end. **Not verified:** that remote pipe clients are refused (no way to test here); that another user's process cannot connect (single-user machine).
- **Context:** the chain is extension, Native Messaging host, agent, core. Nothing may expose an unauthenticated port, and a malicious web page or same-user process must not be able to inject events or read verdicts.
- **Known:** Chrome Native Messaging talks to the host over stdin/stdout and the host manifest lists `allowed_origins`, so the browser authenticates the extension to the host.
- **Options for host to agent to core:**
  - A. Windows named pipes with a DACL limited to the current user's SID, plus a per-install secret in the first message.
  - B. Loopback HTTP on a random port with a bearer token and strict `Host` check (DNS rebinding defence). Fits FastAPI; the token must be stored with a DPAPI-protected file.
  - C. Unix domain sockets. Windows supports AF_UNIX; whether the Python and uvicorn versions in use support it there needs checking.
- **Proposal:** A between host and agent, B (or C if verified) between agent and core. Spike in early M4 and decide on measured complexity.
- **Tension to resolve:** `/health` is unauthenticated today. Fine for M0 (started by hand); from M4 it must be authenticated or reachable only through the chosen channel. SPEC §9 requires "strict API authentication" and rate limiting. The M1 analysis endpoint therefore has a bearer token (constant-time compare, refuses to serve without one), a per-process rate limit, a counted body cap, a `Host` allowlist, no CORS, no served docs, a loopback bind and no per-request fetch option. This is the minimum until this ADR is decided, not the final IPC design.

## ADR-010: Email transport
**Status:** Draft: needs human sign-off. Decide before M5. Lean: pull/polling, to stay local-first.

- **Conflict with the spec:** SPEC §11 lists Gmail watch with Pub/Sub notifications and Microsoft Graph change subscriptions with webhook validation (§9 also says "secure webhook validation"). Those are push designs. Graph webhooks and Gmail push need a public HTTPS endpoint; polling and Pub/Sub *pull* do not. The polling baseline below therefore deviates from §11 and needs your sign-off. §11 requires watch/subscription renewal and missed-event recovery either way.
- **Gmail:**
  - Pub/Sub push needs a public HTTPS endpoint: not local-first.
  - Pub/Sub pull works from a local machine but needs a Google Cloud project and a watch that must be renewed.
  - Plain polling of mailbox history needs no cloud project beyond the OAuth client and works behind NAT.
- **Microsoft Graph:** change-notification webhooks need a public endpoint; delta polling of the mailbox does not.
- **Proposal:** polling as the baseline for both (history/delta cursors persisted, so missed events are recovered), read-only scopes first. Gmail Pub/Sub pull stays an optional latency optimisation after M5.
- **Verify before building (CLAUDE.md rule 5):** current scopes, quotas, watch expiry and delta semantics in the official Gmail and Graph documentation. The points above come from general knowledge, not from the current docs.

## ADR-011: Resolver egress policy
**Status:** Draft: needs human sign-off. The code exists (`core/urls/safe_fetch.py`) but is **off, unwired and unreachable from the API**; enabling it needs this ADR signed.

- **What it does:** follows the redirect chain of one URL, hop by hop, to find where it ends. Headers only; the body is never read.
- **Guard, every hop:** parse as a browser would (ADR-012); http and https only; no credentials in the URL; ports 80 and 443 only; no single-label or internal names (`.local`, `.internal`, `.lan`, ...) and no DNS query for them; resolve once; refuse the whole name if any answer is not public; connect to that validated IP, never to the name again; present the name only as `Host` and TLS name, with certificate verification. A relative or scheme-relative redirect is resolved first, then checked like any other.
- **Public address test:** `is_global` alone passes `64:ff9b::7f00:1` and `::127.0.0.1` and reads CGNAT as not private, so the test unwraps IPv4 inside IPv6 (mapped, NAT64, 6to4, Teredo), rejects IPv4-compatible, site-local, NAT64-local, multicast and reserved ranges, and denies the Azure platform address. 40 blocked and 7 allowed addresses are tabled in the tests.
- **Limits:** 5 hops, 8 seconds for the whole chain (DNS, connect and slow headers share one deadline), no cookies, no credentials, no `Referer`, no proxy from the environment (`trust_env=False`), a fresh client per hop. The `User-Agent` is the honest string `MIRAGE-LinkCheck/1.0`, identical for every user.
- **User-Agent finding (live test, 2026-11-04):** plain HTTP to a CDN edge hung for the invented string `Mozilla/5.0 (compatible)` and returned 200 for honest tool strings. A browser-like string failed once in a live run and then passed 6 of 6, cause unproven (my own probing may have been throttled). Honest and boring was chosen over pretending to be a browser.
- **What it costs, and why it is off:** every resolution reveals the user's IP and the visit to the destination; it can burn a single-use link, which is interaction; DNS queries leak the hostname. Redirect following is also not a safety check: phishing kits show scanners something else, and a chain that ends on a normal page proves nothing.
- **Proposal for sign-off:** enable only by the operator's setting (`MIRAGE_RESOLVE_REDIRECTS`), never per request, never from the API; log hosts only; run it inside the parser sandbox or egress boundary chosen in ADR-008 once that exists; and treat its result as one more signal, never as a BENIGN.
- **Verified:** 151 offline tests (fake DNS and fake transport, no sockets); 13 deliberately weakened versions of the guard each fail a test; an opt-in live test with real sockets passed 4 of 4, twice (`MIRAGE_LIVE_FETCH=1`; pinned IP with certificate verification, a real redirect, a wrong-certificate refusal).
- **Not verified:** IPv6-only networks; behaviour behind a corporate proxy or a TLS-inspecting firewall; DNS-over-HTTPS; IDN hostnames over the live path.

## ADR-012: URL parsing: WHATWG via ada-url
**Status:** Accepted (M1, step 1).

- **Context:** the engine must analyse the URL a browser would navigate to. Parsers disagree, and the disagreement is a known evasion: `urllib` reads `http://evil.example\@good.example/` as host `good.example`, while browsers (WHATWG URL Standard) go to `evil.example`; it also returns no host for `http:\\evil.example/`. An analysis of the wrong host is a false BENIGN.
- **Decision:** parse with `ada-url` 4.x (Python bindings to the Ada WHATWG URL parser; Apache-2.0; wheels checked for Windows and Linux x86_64 on Python 3.12 and 3.14). IDNA/punycode through `ada_url.idna`, so the separate `idna` package is not added.
- **Evaluation:** 36 hand-written WHATWG cases (backslash and `@` tricks, decimal/hex/octal/short IPv4, IPv6 forms, IDN, tab/newline stripping, default ports, dot segments, invalid hosts) all matched. 320,000 fuzzed inputs produced no exception and re-parsing every normalised URL returned the same URL. **Official conformance:** the 560 no-base cases of web-platform-tests `urltestdata.json` (commit `c48d587`, BSD-3, `tests/data/wpt/`): ada-url matches all 560; our layer matches 554. The 6 differences are deliberate and pinned by a test (table below). Comparing against it also exposed a real bug, now fixed: unknown schemes such as `ftps:example.com/` were read as scheme-less, inventing a host the browser would never visit. Only `name:port` is now treated as scheme-less.
- **The six WPT deviations:**

  | Input | Standard | MIRAGE | Why it differs | Safe because |
  |---|---|---|---|---|
  | `a` | failure | `https://a/`, `SCHEME_ASSUMED` | Users and mail bodies paste bare hosts; a parser with no base URL would reject them, and those are worth analysing | The flag records the guess; a bare host has no brand or official domain, so it stays UNKNOWN |
  | `a/` | failure | `https://a/`, `SCHEME_ASSUMED` | Same | Same |
  | `a//` | failure | `https://a//`, `SCHEME_ASSUMED` | Same | Same |
  | `http://./` | `http://./` | failure `NO_HOST` | We strip trailing dots so `paypal.com.` and `paypal.com` are one host; here nothing is left | Failure gives UNKNOWN, never BENIGN |
  | `http://../` | `http://../` | failure `NO_HOST` | Same | Same |
  | `http://foo.09..` | `http://foo.09../` | failure `UNPARSEABLE` | Stripping the dots leaves `foo.09`, which ends in a number and is then an invalid IPv4 | We refuse to guess; failure gives UNKNOWN |
- **Our layer on top (`core/urls/parse.py`):**
  - Input is trimmed, tabs and newlines removed, defanged text restored (`hxxp`, `[.]`), and a missing scheme becomes `https` (flagged `SCHEME_ASSUMED`). Input over 8192 characters is rejected before any processing (reason `TOO_LONG`; the engine reports UNKNOWN).
  - Trailing dots on a host are stripped (`TRAILING_DOT`). If stripping would leave no host (`NO_HOST`) or change how the host is classified, the URL is `UNPARSEABLE`: we do not guess.
  - Flags state how the input differed from its normal form (numeric-IP obfuscation, double encoding, userinfo, IDN, invisible characters, backslashes, default port written out, ...). They are facts, not verdicts; rules decide what they mean.
  - Hosts of non-web schemes (`foo://X`) are `OPAQUE`: the standard leaves them as written, so they are not lowercased or checked against the PSL.
  - Failures carry a fixed reason and never echo the input.
- **Public Suffix List:** a snapshot is bundled with recorded source, date, version, hash and license (`core/urls/data/PROVENANCE.md`; a test pins the hash). The lookup is our own implementation of the published algorithm (exception rules first, then the longest rule, then the implicit `*` rule), tested on the wildcard and exception cases and on every rule in the file. The PRIVATE section is treated as suffixes, so `evil.github.io` is its own registered domain.
- **Consequences and limits:**
  - ada-url is a native library. Wheels exist for the platforms above; others (ARM, macOS) are unverified and would need a build toolchain.
  - The PSL snapshot ages. Replace the file and its provenance row together.
  - Empty labels inside a host (`a..b`) are accepted by the standard and kept; a rule may flag them.
  - Homoglyph and brand analysis is not done here; this layer only normalises and reports facts.

## ADR-013: Rules-only verdicts and the scoring model
**Status:** Accepted (M1 decisions D1 and D2, owner changes 3 and 6).

- **No signals is UNKNOWN, not BENIGN.** With no reputation, domain age or page content, silence from the rules proves nothing. Weak signals below the suspicious threshold are also UNKNOWN.
- **BENIGN needs an allowlist match:** the registered domain is an official one in `rules/url/brands.toml`, the scheme is http or https, the host is not on a PSL private suffix and not in `shared_hosts` (official hosts where anyone can publish). With no signals that is BENIGN/HIGH; with weak signals BENIGN/MEDIUM. The allowlist never short-circuits: every rule still runs, and a strong finding on an official domain is still SUSPICIOUS or worse.
- **Score:** noisy-OR of signal weights inside a category, capped per category, then noisy-OR across categories; 0 to 100. Correlated signals cannot add up to certainty.
- **MALICIOUS from rules alone** needs the malicious score and at least two independent categories with a signal of `high_weight` or more. Otherwise the cap is SUSPICIOUS.
- **Confidence:** independent strong categories: 0 or 1 is LOW, 2 is MEDIUM, 3 or more is HIGH.
- **Recommended response (SPEC §8):** MALICIOUS is BLOCK, SUSPICIOUS is WARN, otherwise NONE. Applied response is always NONE in M1.
- **Failures:** unparseable or oversize input is UNKNOWN with the reason in the explanation; an internal exception is ERROR. Neither carries a score.
- **Versions:** every verdict has `engine_version` and `ruleset_version` (semver plus a hash of `scoring.toml`, `brands.toml`, `lists.toml` and `confusables.txt`).
- **Config:** weights, caps and thresholds live in `rules/url/scoring.toml`, TOML read with the standard library. Tune on the dev split only.
- **ATT&CK tags** were checked on attack.mitre.org against v20. URL rules use T1566.002 (Spearphishing Link), credential rules T1598.003 (Phishing for Information: Spearphishing Link), dangerous-scheme rules T1204.001 (User Execution: Malicious Link). T1583.001 (acquiring domains) happens before a URL arrives, so no rule claims to detect it.
- **Known limits:** brand data is unverified general knowledge. Edit-distance matching will flag some ordinary words; `not_typos` and `fuzzy = false` handle the ones we know about.
- **Persistence (D2):** `core/db/store.py` writes one analysis in one transaction: event, artifact, verdict, detections, evidence and their links. `artifacts.ref` is `sha256:<hash>`; `artifacts.host` holds the host (dropped above 253 characters); no URL text, path or query reaches any table, and `extracted_urls` stays empty until ADR-007. A test scans every table for markers placed in the URL.

## ADR-014: Message analysis conventions (M2)
**Status:** Accepted with the M2 plan (amendments 2 to 4). Items marked *deviation* differ from the plan or from CLAUDE.md and need a glance.

- **Pipeline.** `core/email/engine.py`: size check, sandboxed parse (`op: mime`), strict validation of the worker's reply, relative links resolved with `ada_url.join_url`, every distinct link (cap 100) and the sender's domain through the M1 URL engine, message rules, the shared `core/risk/scoring.score`. The host never parses message bytes.
- **The worker's reply is hostile.** `core/email/models.py` is strict and frozen: every field typed and bounded, unknown fields and enum values rejected. A reply that fails validation is ERROR `worker_output_invalid`. Strings it returns are attacker text; rule summaries therefore name facts (a type, a host, a count), never subjects, names or file names.
- **Failures are verdicts, never BENIGN.** Empty or over-size input, a stopped parser, a worker error: UNKNOWN with a reason. Sandbox missing, launcher exception, invalid reply, engine bug: ERROR (`sandbox_unavailable`, `sandbox_error`, `worker_output_invalid`, `error`). None carries a score. There is no in-process fallback.
- **A message is never BENIGN in M2.** No rule firing proves nothing about a message, and there is no allowlist for senders. Weak signals and silence are UNKNOWN; SUSPICIOUS and MALICIOUS work as in ADR-013 (MALICIOUS needs two independent categories). MALICIOUS recommends QUARANTINE; the applied response is always NONE.
- **Link findings reuse URL rules.** A URL rule that fires on a link becomes a signal in category `link.<category>` with its own cap in `rules/email/scoring.toml`; the strongest signal per rule is kept and counted ("3 link(s): ..."). The sender domain is analysed as `https://<domain>/` and six URL impersonation rules are re-exposed as `email.sender.*`.
- **Authentication-Results is trusted only as far as whoever added it.** It is read, never recomputed (no DNS). `none`, `pass` and absent prove nothing; only `fail` and `softfail` count, and the summary names the server that claimed it.
- **HTML with the standard library.** *Deviation from the plan, which listed `beautifulsoup4`.* `html.parser` is enough for tags, attributes, inline-style hiding and link text; it keeps the sandbox runtime to the standard library and the dependency list short. CSS from `<style>` blocks and classes is not evaluated (KNOWN_LIMITATIONS).
- **Storage (ADR-007 stays unsigned).** `save_email_analysis` writes the event, an `EMAIL` artifact (sha256 of the raw message, `host` NULL), the verdict, detections and evidence, plus one `extracted_urls` row per distinct link: the URL's hash and a `domains` row (host and registered domain); `url` stays NULL. A test puts markers in subject, display name, body, path, query and file name and scans every table. The domains table does record which sites a user's mail linked to, in plaintext, as `artifacts.host` already does for URLs.
- **API.** `POST /v1/emails/analyze` takes the raw message (`message/rfc822` or `application/octet-stream`, else 415) with its own body cap (`MIRAGE_MAX_MESSAGE_BYTES`, default 10 MiB, counted not trusted), the same token and rate limit as the URL route, and at most `MIRAGE_MAX_CONCURRENT_PARSERS` (4) sandboxes at once (503 with Retry-After beyond that). Analysis runs in a worker thread so the event loop stays free.
- **ATT&CK tags** verified on attack.mitre.org on 2026-11-05: T1566.001 Spearphishing Attachment, T1204.002 User Execution: Malicious File, T1027.006 HTML Smuggling, T1036.007 Double File Extension, T1036.002 Right-to-Left Override (plus the three from ADR-013). Sender, authentication, structure and content rules have no tag because no technique was verified for them; none is guessed.
- **Rule fixtures.** *Deviation from CLAUDE.md ("fixtures in `corpus/`").* Each message rule's positive and negative message is built at test time in `tests/unit/test_rules_email.py` (a message needs headers, parts and attachments that read better as code), checked against the real guest parser and engine. The 120-message corpus in `corpus/mail/` covers the rules from the other side.
- **Attachments (M2b).** After the message parse, each distinct inspectable attachment (PDF, zip/tar/gz/bz2/xz, png/jpeg/gif/bmp/tiff/webp; by content, not name) is opened by its own sandbox process (`op: inspect`, addressed by part path, the message is re-sent and the part re-found), up to 8 per message, 3 at a time, with 1 GiB / 20 s CPU / 40 s wall. A crash, timeout or invalid reply costs that file only and is reported (`files[].status`, rule `file_inspection_incomplete`); 7z, rar and iso are named, not opened (`unsupported`). Archives are listed and never extracted: entry data is read only to learn its type or, for a nested archive, up to 8 MiB, all charged to a 48 MiB budget; a bomb is reported from its headers. PDFs go through qpdf, which reports facts (JavaScript/Launch/embedded-file/URI counts), never behaviour. Images are refused above 16 megapixels before decoding. URLs found in PDFs (`pdf_uri`) and QR codes (`qr`) become links and go through the URL engine like any other. The guest returns facts (extensions, real types, counts); the host's rules and `lists.toml` decide what is dangerous, so there is one list.
- **Versions.** `ENGINE_VERSION = "email-1.1.0"`. `ruleset_version` is the message pack's semver plus a hash of its `scoring.toml`, `lists.toml` and the URL ruleset's version, so a URL rule change changes it too.

## ADR-015: Threat-intelligence providers and the egress policy (M3)
**Status:** Accepted with the M3 plan (owner approved D1 to D8 on 2026-11-05). Written from each provider's documentation as read that day; unverified points are listed at the end.

- **Two kinds of provider.** *List feeds* (PhishTank, OpenPhish, URLhaus) are downloaded by the operator (`python -m core.intel sync`) and matched on this machine: nothing about an analysed URL leaves it. *Query providers* (RDAP, VirusTotal) ask an outside service about **one public registered domain**. Everything is off until `MIRAGE_INTEL_PROVIDERS` names it; naming a provider is the operator's authorization for what it sends, recorded as an `intel.enable` audit record and a log line. A typo or an unbuilt name stops start-up. There is no per-request provider switch: the API cannot ask for one.
- **The egress gate** (`core/intel/egress.py`, `core/intel/base.py`). A provider is handed a `Query`, never a URL: a query provider gets the registered domain and nothing else (no path, query, fragment, user name, token, port, IP address); a list provider gets the host and a hash. The domain must sit under a suffix the Public Suffix List knows, so single labels, IP addresses, `.test`, `.local`, `.internal` and the like are refused and **the synthetic corpus can never be sent**. Links found in messages go to list feeds only unless `MIRAGE_INTEL_EMAIL_LINKS=true`. Tests capture every outgoing request end to end; weakened versions of each rule fail them.
- **One network module.** `httpx` is imported only in `core/intel/http.py` (plus the unwired `safe_fetch.py`); a test enforces both, and another that no analysis engine imports `core.intel`. The client follows no redirects, caps every response, and raises fixed-text errors: some providers put the key in the URL, and httpx's own INFO log (which prints URLs) is held at WARNING.
- **Orchestration** (`core/intel/orchestrator.py`). Concurrent, each provider under its own timeout and an overall deadline (default 2 s); a slow provider is recorded `TIMEOUT` and its late answer still warms the cache. Per provider: cache (OK answers only, keyed by a hash of the name), circuit breaker (opens on repeated errors or timeouts, one half-open trial; `RATE_LIMITED` and a missing local feed do not count), rate limiter set to the documented limits (VirusTotal 4/min and 500/day; RDAP a conservative 30/min), pause after a 429. Every path ends in a stated `ProviderResult`; an answer of BENIGN, a malformed answer or an exception is an ERROR with no opinion; exception text never reaches results or logs. State is in memory.
- **Correlation** (`core/risk/correlate.py`, `rules/intel/scoring.toml`). Each provider is its own evidence category. One provider listing the exact URL: SUSPICIOUS with HIGH confidence, recommend WARN. Two independent providers, or one plus a strong local category: MALICIOUS through the existing two-category rule (ADR-013). Absence from a list, a clean VirusTotal report and an old domain are nothing. A provider that failed, timed out, was paused or was not asked changes neither the state nor the score and is named in the explanation. With nobody asked the local verdict is returned untouched. Domain age (RDAP) and engine counts (VirusTotal) are signals with configurable bands. `resolve_state` (the M0 placeholder) is no longer used.
- **Feeds** (`core/intel/feeds.py`). One file per feed in `MIRAGE_DATA_DIR/feeds` (default `.data/`, git-ignored), replaced atomically. Entries are `sha256` of the normalized URL without its fragment; a listed host with other paths is only a weak SUSPICIOUS and is ignored for official, multi-tenant and shared-platform hosts. Sync is due-checked, conditional (ETag), size- and expansion-capped, follows redirects only to https hosts on the feed's allowlist, refuses an empty list or one under half the size of the last good one, and keeps the previous copy on every failure. A missing or stale list is UNAVAILABLE, not clean.
- **Deviations from the M3 plan:** feeds are files, not tables, and the cache is in memory, so no schema change was needed and migration `0001` is frozen as it is (a test pins its hash). The gate is stricter than planned (no public IPs).
- **Keys** (D5, ADR-007 still unsigned): `MIRAGE_PHISHTANK_KEY`, `MIRAGE_URLHAUS_AUTH_KEY`, `MIRAGE_VIRUSTOTAL_API_KEY` are `SecretStr` read from `.env` in plaintext, never logged, stored or put in results; PhishTank and URLhaus carry theirs inside the download URL, VirusTotal in a header.
- **Terms** (D1): v0.1 is a single person's local, non-commercial tool. VirusTotal's public API, Safe Browsing, OpenPhish's community feed, URLhaus and urlscan's free tier restrict use in a product or business; distributing MIRAGE would need commercial terms for each (Web Risk, VirusTotal Premium, urlscan commercial, a review of PhishTank's terms).
- **Not built (D2):** urlscan (free search has no verdicts; a submission makes urlscan fetch the page, the riskiest option: deferred to an on-demand investigation feature), Web Risk (needs billing), and the Safe Browsing v5 local-list stretch goal.
- **Export** (D7, `core/export.py`): JSON lines, one verdict per line, Elastic-Common-Schema field names where one exists, `mirage.*` otherwise; hashes and hosts only; deterministic; to a file or stdout, never pushed.
- **Unverified, to check with real keys before relying on it:** every adapter against its live service; the URLhaus export path and CSV layout; PhishTank registration and rate limits; VirusTotal's domain-object field names and Terms of Service; RDAP registries' rate limits and query logging; the urlscan auth header. **Residual risks:** an RDAP server named by the bootstrap file is checked by name, not by resolved address (a name resolving to a private address is not blocked; the connect-by-validated-IP machinery is in the unsigned `safe_fetch`); request counts reset on restart.

## ADR-016: The Windows agent is a per-user program, not a service (M4)
**Status:** Accepted (M4 plan D1, approved 2026-11-05). A deviation from SPEC §4, which says "Worker Service".

- **Context:** a Windows service runs in session 0: it cannot show a notification to the user, and it has neither the user's Downloads folder nor the user's DPAPI key.
- **Decision:** the agent is a .NET Generic Host program (`Microsoft.Extensions.Hosting`) that runs **as the logged-on user**, started at logon by `HKCU\...\Run`, windowless, unelevated, one instance per user. `Mirage.Agent --install | --uninstall | --status` manage that and the browser bridge registration without administrator rights. The agent starts and supervises the core (a configured command; the token by environment variable) so no console needs to be open.
- **Consequences:** protection starts at logon and ends at logoff, and an administrator cannot see another user's downloads. Service mode and a machine-wide install wait for the M7 installer; the host already separates the work (`AgentService`) from how it is launched, so `AddWindowsService` is a later, small change.
- **Rejected:** a service plus a per-user helper (two programs and a second IPC hop for no M4 benefit); a scheduled task at logon (same result as the Run entry with more moving parts).

## ADR-017: Live mailbox: a read-only Gmail poller in the core (M5)
**Status:** Accepted by the owner's instruction to proceed with M5 (2026-11-05); every choice below is the recommendation in `docs/milestones/M5.md` and can be reversed. Not yet exercised against real Google.

- **Decision:** a background thread inside the API process polls Gmail every 60 s with `history.list` (`messageAdded`, INBOX) from a saved `historyId`, fetches each new message with `format=raw`, and runs it through the same sandboxed message engine as `/v1/emails/analyze`. Off unless `MIRAGE_GMAIL_ENABLED=true`.
- **Scope:** `gmail.readonly` only (the narrowest scope that returns the raw message; `gmail.metadata` cannot). Enforced twice: the consent request names exactly that scope, and a token answer that reports any other scope is refused and not stored. A transport hook refuses any request that is not HTTPS to `gmail.googleapis.com`, `oauth2.googleapis.com` or `accounts.google.com`, and any non-GET to Gmail, before it leaves.
- **Sign-in:** authorization code + PKCE (S256) with a one-shot listener on `127.0.0.1`, `state` checked in constant time, `Host` checked, five wrong tries and it gives up. No Google client library: the flow is two requests. The client id (and secret, if Google issues one for the desktop client) is the operator's own, from the environment.
- **Token at rest:** the refresh token is encrypted with DPAPI (current user) via `ctypes` and kept in a file under the data folder. Never in the database, `.env`, logs or git.
- **Storage:** exactly what M2 stores for a message (verdict, signals, URL hashes and hosts). No body, subject, address or raw message is written; the Gmail message id is kept only as a SHA-256 in the poller's state file. A test plants markers in sender, recipient, subject, body, link path and query, message id and access token, and searches the database, state file and logs for them.
- **Recovery:** the position is moved forward only after every message in the range is stored; ids already analysed are skipped by hash, so at-least-once becomes exactly-once. HTTP 404 on an old `historyId` triggers a bounded re-list of the last N days (default 2). A message deleted before it is fetched is counted. An analysis that ends in ERROR is tried again up to three polls, holding the position, then recorded.
- **Failure rules:** 429/5xx/network only delay the next poll (honouring `Retry-After`); 401 and a revoked refresh token mark the mailbox `reauth_needed`; a message over the size cap is stored as UNKNOWN `too_large`. Nothing becomes "no phishing found".
- **Alerts:** the core exposes counts and the rule ids of recently flagged mail at `GET /v1/mailbox/status`; the agent polls it and shows a notification. Neither side ever knows the sender or subject.
- **Consequences:** while the Google project is in "Testing" status the refresh token expires after 7 days and after any password change, so the user must reconnect; `gmail.readonly` is a restricted scope, so publishing needs Google's verification, which this project does not pursue. Throughput is bounded by quota (a raw fetch costs 60 of 6,000 units a minute).
- **Rejected:** Pub/Sub push (needs a public endpoint or a cloud project), Google's client libraries (size, no gain for two requests), keeping the token in `.env`, a modify scope (M6, explicit).

### Addendum (M5b, 2026-11-05): Outlook / Microsoft 365 through Microsoft Graph
Built on the owner's "move next", same status as Gmail: against a fake Graph only (`docs/milestones/M5b.md`, which lists what was and was not verifiable in Microsoft's documentation). No new dependency.
- **Shape:** the sync talks to a `MailSource` protocol (position, list recent, changes, raw message); `GmailClient` and `GraphClient` implement it. Recovery, de-duplication, retry and storage rules are the Gmail ones, unchanged. The position is the opaque `@odata.deltaLink` (the state file accepts any printable string up to 4,096 characters, not only digits).
- **Scope:** `Mail.Read` + `offline_access`. After sign-in the granted scopes are checked against an allow list (`Mail.Read`, `offline_access`, `openid`, `profile`, `email`, `User.Read`); an extra scope, above all one that writes or sends, or no scope list at all, is refused and nothing stored.
- **Egress:** adds `graph.microsoft.com` (GET only, the same hook as Gmail) and `login.microsoftonline.com`. A `nextLink` or `deltaLink` in an answer is followed only if it is HTTPS to Graph's `/v1.0/` API; the tenant in the sign-in URL must match `[A-Za-z0-9.-]{1,64}`.
- **Tokens:** Microsoft replaces the refresh token on every use; the token source stores the new one each time (tested). Own file (`outlook.token`) and state (`outlook-state.json`). `disconnect --provider outlook` deletes the local copies only; the app's access is removed in the Microsoft account's app-permissions page (no revoke call is used).
- **Sign-in:** the loopback redirect is `http://localhost:<port>` (Microsoft matches `localhost` and ignores the port); the listener still binds `127.0.0.1` only and accepts the Host names `localhost` and `127.0.0.1`.
- **Status:** `GET /v1/mailbox/status` shows one entry per provider plus a combined `state`: a problem wins (`reauth_needed`, then `error`), otherwise `connected` if any provider is. Flagged mail from both is merged.
- **Unverified, treated conservatively:** the delta-token lifetime and the error for an old one (HTTP 410 and 404 both mean "start again from the last N days"); whether `Mail.Read` needs administrator consent on a work account; Outlook's per-mailbox throttling numbers (`429` and `Retry-After` are honoured, the numbers are not assumed).
- **Outlook (M5b):** the poller's interface (list recent, follow changes, fetch raw) maps to Microsoft Graph `Mail.Read` and delta queries; not started, needs an Azure app registration from the owner.

## ADR-018: The response engine: the core decides and records, the agent acts, the console asks (M6)
**Status:** Accepted (M6 plan D1 to D8, approved as recommended on 2026-11-05).

- **Decision:** a stored MALICIOUS file verdict that the agent sent with its file id gets one *action* (`FILE_QUARANTINE`) in state PENDING, unless the exact file (SHA-256) is on the allow list. A table-driven state machine (`core/response/machine.py`) is the only thing that says what may happen next; every event is idempotent and an impossible one is refused (HTTP 409), never forced. The core stores ids, hashes, states and reason codes, never a path or a file name. Every change and its audit row are written in one transaction, compare-and-set on the old state.
- **Who acts:** only the **agent** touches files, and only for an action the core has marked APPROVED (a PENDING one is approved by the agent only in `auto` mode, as "policy"; the default `ask` waits for the console). The agent reports back `applied` / `failed` / `restored` / `restore_failed` with a reason code; the core refuses an `applied` report for an action that was never approved. The console can ask (approve, dismiss, restore, allow-list) but cannot claim a result.
- **Quarantine mechanics (`QuarantineStore`):** nothing moves unless the file's SHA-256 equals the judged one, hashed through a handle that blocks writers; same volume: rename, then re-verify; another volume: copy, fsync, verify the copy, re-check the original is unchanged, then remove it; a record is written before anything irreversible so a crash at any step is resumed, not repeated; restore never overwrites (a taken name gets `(restored N)`), re-verifies the quarantined copy, puts back time, attributes and Mark of the Web, and **keeps the quarantine copy**. There is no purge in M6.
- **No delete path, with one stated exception:** the only deletions in the agent are its own host manifest on uninstall, a half-written copy or stale record it made itself, and the original after a byte-verified copy to another volume. A test pins the exact list so a new delete call fails the build until reviewed.
- **Console:** React + TypeScript bundled with esbuild, served by the core at `/console/` (same origin as the API) with a strict CSP; the token stays in `sessionStorage`; every state-changing button is a two-step confirmation that says what will happen. Deviation from the SPEC (Tauri): Rust and the C++ build tools are not installed here; the same bundle can be wrapped by a Tauri shell in M7.
- **Rejected:** letting the console or the core pick file paths (the core never has them); purge or delete in the console (M7 at the earliest, with its own decision); auto-quarantining SUSPICIOUS files; email quarantine (needs `gmail.modify`, M6b).
