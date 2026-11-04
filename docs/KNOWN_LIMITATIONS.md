# Known limitations (end of M0)

Written to be read before trusting anything in the repo. Items marked **unverified** have code or config but were never run.

## Not verified
- **PostgreSQL in CI.** Verified locally on PostgreSQL 17 through Docker (2026-11-04): all 21 PostgreSQL migration tests pass and `migrate` applies. CI has no PostgreSQL service yet, so those tests skip there.
- **CI.** `.github/workflows/ci.yml` has never run: there is no remote. Its steps are the same `tasks.py` commands that pass locally. Action versions are pinned by tag, not commit SHA.
- **Python 3.12.** CI targets the declared floor (3.12); everything was run on 3.14.7 only.
- **Linux/macOS.** Developed and tested on Windows 11 only.
- **Spec reconciliation (2026-11-04).** `docs/SPEC.md` is now in the repo and was read. Contracts match §7 and §8 except that `risk_score` is null for UNKNOWN/ERROR (to confirm). §13 lists entities not yet in the schema: users, devices, integrations, response_actions, allowlist, blocklist (added in M4 to M6). ADR-010's polling baseline deviates from §11 (push) and needs sign-off. §9 requires strict API authentication and rate limiting, which the M0 `/health` endpoint does not have.

## Detection and eval
- There is no detection logic. The stub engine returns UNKNOWN for everything: abstain rate 1.0, recall 0.0, precision undefined, by design.
- The corpus is 30 hand-written synthetic URLs (19 malicious, 11 benign; 20 dev, 10 holdout). One sample moves recall by 5 points, so M0 numbers prove the pipeline, not quality.
- Shortener seeds are labelled by assumption (the destination is hypothetical) and one benign shortener is indistinguishable from the malicious ones without resolving. That is deliberate; expect an abstain.
- Seeds were written by the same author who will write the rules. The holdout split exists to limit tuning, but it is small and not independent.
- Latency numbers measure the stub only.
- `resolve_state` is a conservative placeholder, not correlation.

## Security gaps
- **Evidence is not encrypted yet.** The schema isolates it (`evidence_payloads`), nothing writes it. `artifacts.ref` and `extracted_urls.url` store URL text in plaintext. (ADR-007)
- `audit_logs` is append-only by convention, not enforced by the database.
- Signal-to-evidence links (`Signal.evidence_ids`) are validated in the contract but not persisted; a `detection_evidence` table is needed when rules start producing evidence.
- **Log redaction is heuristic** (key names plus regexes). It is tested against known patterns only. Email addresses and other personal data in free text are not redacted. A URL hash can be brute-forced for guessable URLs. Anything not routed through `core/log.py` (for example uvicorn's own access log) bypasses it; run uvicorn with `--no-access-log`.
- `/health` is unauthenticated (acceptable while started by hand; see ADR-009).
- No SSRF guard, sandbox or IPC exists yet; the threat model lists them as planned, not done.

## Tooling and process
- Dependencies are lower-bounded, not pinned; no lock file until M7. pytest prints one Starlette deprecation warning about `TestClient` and `httpx` (see ADR-004).
- The git hook must be enabled once per clone (`python tasks.py hooks`). It lints the working tree rather than the index.
- Git for Windows' `sh` cannot fork on this machine (symptoms: Git Bash fails, `git clone` of hook repos fails). Likely security software; unresolved. It is why the project uses plain `.githooks` instead of the pre-commit framework.
- Empty future folders (`agent/`, `extension/`, `console/`) are not created; `rules/` holds only a README.
- Uvicorn has not been started in this session; `/health` is tested through FastAPI's `TestClient` only.

## Next milestone
M1, the URL engine. Plan: `docs/milestones/M1.md` (proposed, awaiting approval).
