# MIRAGE

Local-first phishing detection and threat-intelligence system for Windows.
**Mission:** detect phishing before the user interacts, investigate the evidence, protect the user, explain every decision.

Read this file at the start of every session. Full spec: `docs/SPEC.md` (read only the sections the current milestone needs).
**Current milestone: M0** → `docs/milestones/M0.md`

## What it is
- A continuous endpoint anti-phishing system: Windows agent + Chrome/Edge extension + local analysis engine + desktop console for investigation.
- Not an antivirus, not a manual URL-submission site, not a dashboard. Monitoring must keep running with the UI closed.

## Non-negotiables
1. **Deterministic first.** Rules and validated intelligence decide. An LLM may explain or summarize, never be the sole decider. No LLM features before M3 is done.
2. **Verdicts:** `MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN | ERROR`. UNKNOWN is never treated as BENIGN. A provider timeout or error is never "safe".
3. **Explainable.** Every verdict carries a risk score, confidence, signals, evidence references, provider results (with provenance and timestamps), a recommended response and the applied response. Scoring is configurable. One feature alone (e.g. a PDF containing a URI) never makes something malicious.
4. **Privacy.** Local-first. Private URLs, tokens, full emails and attachments never leave the machine without explicit user authorization. No secrets in logs or git. Credentials and evidence encrypted at rest.
5. **Untrusted input.** Never execute documents, scripts or embedded content on the host. Parse in the sandboxed worker with hard limits (time, memory, size, archive depth and ratio, no network).
6. **SSRF.** URL fetching must never reach loopback, private, link-local or cloud-metadata addresses. Re-validate every redirect hop and every resolved IP.
7. **Responses** are reversible, idempotent, auditable, permission-gated and fail-safe. Never auto-delete user files or emails. Email access is read-only by default; modify/quarantine is a separate, explicit capability.
8. **Honesty.** Never claim a feature works without an executable test or a verified integration. Never mark a milestone done with unmet acceptance criteria. A successful API response is not a successful detection.

## Architecture
Sensors → Intelligence → Response. **Modular monolith first:** one FastAPI app with internal packages, no microservices without a measured need.

| Part | Tech |
|---|---|
| Core engine + API | Python 3.12+, FastAPI, pydantic v2 |
| Storage | PostgreSQL, SQLAlchemy 2 + Alembic migrations from day one, UUID ids. Sensitive evidence kept apart from metadata; store hashes and references, not duplicate raw emails |
| Windows agent (M4) | C# / .NET Worker Service |
| Browser extension (M4) | TypeScript, Chrome MV3, Edge-compatible |
| Console (M6) | Tauri + React/TypeScript. Viewer and restore tool, not the monitoring engine |
| Queue | None until something needs one, then Redis (deviation from SPEC §4) |

Layout (deliberately simpler than SPEC §14; see `docs/DECISIONS.md`):

```
core/        FastAPI app: api, contracts, urls, email, documents, intel, detection, risk, response
rules/       rules-as-code: url/ email/ document/ correlation/
corpus/      labelled samples + manifest (synthetic or authorized datasets only)
eval/        precision/recall/F1 harness
agent/       C# worker service (M4)
extension/   MV3 extension (M4)
console/     Tauri app (M6)
tests/       unit/ integration/ adversarial/ regression/
docs/        SPEC.md, DECISIONS.md, THREAT_MODEL.md, milestones/
infra/       docker compose, postgres
```

## Detection conventions
- Rules are pure functions: artifact in, signals out. Each rule has an id, category, weight, evidence fields, an ATT&CK tag where one applies (T1566.001, T1566.002, T1204...) and at least one positive and one negative fixture in `corpus/`.
- Quality is measured, not demoed. Every milestone records TP/FP/FN, precision, recall, F1 and latency from `eval/`. UNKNOWN is reported as an abstain rate, never counted as BENIGN. No regression without a written reason.
- Providers sit behind one interface: async, per-provider timeouts, rate-limit handling, circuit breakers, caching, provenance and timestamps. Never depend on a single provider. Check each provider's current docs, terms and quotas before building its adapter. Mocks in dev and CI.
- Browser (MV3): don't rely on blocking webRequest. Use declarativeNetRequest redirects fed by cached verdicts. Never hold navigation waiting on providers.

## Testing and dev safety
- Tests alongside every feature: pytest (core), xUnit (agent), plus adversarial and regression suites.
- Test data is synthetic or from authorized datasets. No real victims, no live malicious URLs, never execute suspicious samples. Fixtures like ZIP bombs are generated at test time with bounded size.
- Never hardcode credentials. `.env.example` holds placeholders only.

## How to work
1. One milestone at a time. Never generate the whole app in one pass.
2. Before starting, write the plan to `docs/milestones/Mx.md` (modules affected, security implications, acceptance criteria) and wait for approval.
3. Build in small steps with tests. Prefer maintainable over clever.
4. Ask before: adding a dependency (state its purpose in DECISIONS.md), changing the verdict model, widening OAuth scopes or permissions, or sending any data off the machine.
5. Don't invent API capabilities. Check current official docs for every third-party integration.
6. When done: run tests and eval, report failures honestly, update docs, list known limitations, name the next milestone.
7. Keep context small. Read only the relevant spec sections and files.

## Milestones
Spec phase 1 = M0 + M1. Spec phases 2-7 = M2-M7.

| | Scope | Done when |
|---|---|---|
| M0 | Foundation: repo, contracts, DB, corpus + eval harness, ADRs, threat model v0 | tests green; eval runs end to end on the seed corpus |
| M1 | URL engine: normalization, rule pack, scoring, SSRF-safe redirect resolver | reproducible verdicts with evidence; metrics reported |
| M2 | Email and file inspection: MIME, hidden links, PDF, QR/OCR, archives, all sandboxed | EML/HTML/PDF/image samples give evidence-backed indicators; malformed MIME and bomb fixtures handled |
| M3 | Threat intel, correlation, JSON/SIEM export | any provider down still returns a verdict. **This is v0.1** |
| M4 | Windows agent + MV3 extension | works with the UI closed; blocks a test phishing URL; flags a test file |
| M5 | Live email: Gmail read-only first, then Outlook | test mailbox analyzed automatically; missed events recovered |
| M6 | Response engine + console | quarantine is reversible, idempotent, audited; restore works |
| M7 | Hardening: adversarial and perf tests, installer, docs | limits documented; reproducible deploy |

Deferred: admin console, multi-user/cloud, LLM explanations (after M3), Redis (until needed).

## Commands
Task runner: `python tasks.py <task>` (ADR-003). Keep this list current.

| Task | Does |
|---|---|
| `up` | start Postgres via Docker Compose |
| `test` | pytest (integration tests skip when no database is reachable) |
| `eval` | run the engine over the dev split, write `docs/eval/dev.{json,md}`. `--split holdout` is explicit and logged; reserve cannot be selected |
| `lint` | ruff check + format check + mypy |
| `migrate` | `alembic upgrade head` (needs `MIRAGE_DATABASE_URL`) |
| `serve` | run the API on `127.0.0.1:8765`, no access log (needs `MIRAGE_API_TOKEN`) |
| `fmt` | `ruff format` + `ruff check --fix` |
| `secrets` | secret scan against `.secrets.baseline` (file names appended by caller) |
| `hooks` | enable `.githooks` for this clone (run once) |

Setup on a fresh clone: `python -m venv .venv`, `.venv\Scripts\pip install -r requirements-dev.txt`, `python tasks.py hooks`. `tasks.py` finds `.venv` by itself.
