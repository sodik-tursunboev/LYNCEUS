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
| 008 | Parser sandbox | Draft: needs human sign-off, decide before M2 |
| 009 | Local IPC | Draft: needs human sign-off, decide before M4 |
| 010 | Email transport | Draft: needs human sign-off, decide before M5 |
| 011 | Resolver egress policy | Reserved for the M1 resolver step (draft, needs sign-off) |
| 012 | URL parsing: WHATWG via ada-url | Accepted |
| 013 | Rules-only verdicts and the scoring model | Accepted |

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
- **Migrations:** the initial migration may be edited in place until M3 (v0.1); nothing is deployed before then. After that, forward-only.
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
**Status:** Draft: needs human sign-off. Decide before M2.

- **Context:** documents, archives and images are hostile input (CLAUDE.md rule 5). The parser must have hard limits (time, memory, size, archive depth and ratio) and no network. The target is an end-user Windows PC.
- **Options:**
  - A. **Container worker** (Docker, no network, read-only filesystem, cgroup limits). Strong, reproducible, same in CI. Requires Docker Desktop on every end-user machine: heavy and not available by default.
  - B. **Restricted Windows process** (Job Object for CPU/memory/process limits, AppContainer or restricted low-integrity token, firewall rule or token that denies network). Native, no dependency, fast start. Weaker isolation than a VM; more Windows-specific code.
  - C. **VM** (Hyper-V or Windows Sandbox). Strongest, but slow to start, heavy, and edition-dependent.
- **Proposal:** B as the product default, with a narrow stdin/stdout protocol between core and the worker; run the same worker under a Linux container in CI to exercise bomb and malformed-file fixtures portably. Revisit C only if the threat assessment demands it.
- **Verify before building:** current AppContainer and Job Object documentation; that network denial really holds on the target Windows editions.

## ADR-009: Local IPC
**Status:** Draft: needs human sign-off. Decide before M4.

- **Context:** the chain is extension, Native Messaging host, agent, core. Nothing may expose an unauthenticated port, and a malicious web page or same-user process must not be able to inject events or read verdicts.
- **Known:** Chrome Native Messaging talks to the host over stdin/stdout and the host manifest lists `allowed_origins`, so the browser authenticates the extension to the host.
- **Options for host to agent to core:**
  - A. Windows named pipes with a DACL limited to the current user's SID, plus a per-install secret in the first message.
  - B. Loopback HTTP on a random port with a bearer token and strict `Host` check (DNS rebinding defence). Fits FastAPI; the token must be stored with a DPAPI-protected file.
  - C. Unix domain sockets. Windows supports AF_UNIX; whether the Python and uvicorn versions in use support it there needs checking.
- **Proposal:** A between host and agent, B (or C if verified) between agent and core. Spike in early M4 and decide on measured complexity.
- **Tension to resolve:** `/health` is unauthenticated today. Fine for M0 (started by hand); from M4 it must be authenticated or reachable only through the chosen channel. SPEC §9 requires "strict API authentication" and rate limiting, so the M1 analysis endpoint needs a bearer token (proposed amendment in `milestones/M1.md`) on top of binding `127.0.0.1`, checking the `Host` header, having no CORS, and never exposing a per-request fetch option.

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
**Status:** Reserved. To be drafted at the M1 resolver step (last step of M1) and signed off before the resolver can be enabled.

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
