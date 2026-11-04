# Known limitations (end of M1)

Written to be read before trusting anything in the repo. "Not verified" means code or config exists that was never run.

## What the M1 engine cannot catch
- **It sees only the URL string.** No reputation, domain age, WHOIS, page content, meta-refresh or JavaScript redirects, QR codes, email or files. A freshly registered phishing domain with no brand name or keyword in it is UNKNOWN, never BENIGN.
- **It rarely says MALICIOUS on its own.** MALICIOUS needs two independent strong categories (ADR-013). On the synthetic corpus 13 of 87 malicious dev samples and 3 of 30 malicious holdout samples reached it; the rest are SUSPICIOUS, which recommends WARN, not BLOCK. Blocking confidence has to come from threat-intel providers (M3).
- **Shorteners are unknowable offline.** The one holdout miss is a shortener. Following redirects would help, but the resolver is off (below).
- **The brand list is general knowledge, not verified.** 105 brands, Polish and global; every entry is `verified = false`. A wrong official domain means a false positive or a wrongly BENIGN fake. Only listed brands are protected; there are no non-Latin brands, and keywords are ASCII only.
- **UNKNOWN is common by design:** 32% of dev and 26% of holdout. On benign samples it means "no rule fired", not "safe".
- **Edit-distance matching can flag ordinary words** near a brand name. `not_typos` and `fuzzy = false` cover the cases found so far; the corpus has 0 false positives, but it was written by the rule author.
- **Script detection is approximate** (Unicode character names, not the Scripts table). It separates Latin, Cyrillic and Greek well; rarer pairs are unproven.
- **`url.credential_bait` never fired** on either split. It passes its fixtures but has no corpus coverage.

## How far the numbers can be trusted
- 253 synthetic URLs from seeded templates (150 dev, 49 holdout, 54 sealed reserve), written by the same author as the rules. **They measure rule correctness, not the real-world detection rate.** The holdout shares the dev templates, so it tests new brands and variants, not new attack styles; it came out like dev (precision 1.000, recall 0.967), which is what shared templates predict.
- The holdout was run **once**, on 2026-11-04, and logged in `docs/eval/holdout_runs.md`. Nothing in the rules or data changed afterwards. It has 49 samples, so recall's 95% interval is 0.833 to 0.994.
- A holdout failure should be fixed by moving those samples to dev and drawing a new holdout from the reserve. The reserve has never been run.
- **Latency is an order of magnitude, not a benchmark.** The same code measured 1.4 ms and 14 ms p50 on the same machine hours apart (A/B of old and new commits, no regression). `url.typosquat` is about two thirds of analysis time.
- Parser: 554 of 560 WPT cases match; the 6 differences are deliberate (ADR-012). 320,000 fuzzed inputs produced no exception.

## Security gaps
- **No URL text is stored** (decision D2), but `artifacts.host` keeps the host of every analysed URL in plaintext, which records which sites a user checked. Evidence payload encryption (ADR-007) is not implemented, and nothing writes `evidence_payloads`.
- **No audit records.** `audit_logs` exists and is append-only by convention only; nothing writes to it, including API calls, although SPEC §9 asks for audit logging.
- **API access is minimal:** one static bearer token from `.env` shared by every caller, no rotation, a per-process rate limit, loopback only and no TLS. The real design is ADR-009 (draft). `/health` is open.
- **The redirect resolver is off and unwired** (ADR-011, draft). The guard has 151 offline tests, 13 mutation checks and a manual live run. Not verified: IPv6-only networks, corporate proxies, TLS-inspecting firewalls, DNS-over-HTTPS. A resolved chain is never proof of safety: phishing kits show scanners something else.
- Log redaction is pattern-based and tested on known patterns only. Dependencies are lower-bounded, not pinned.

## Not verified
- **CI has never run.** There is no remote. Its steps are the commands that pass locally. It has no PostgreSQL service, so the PostgreSQL tests would skip there. This is the one open item in M0.
- **Python 3.12 and Linux/macOS.** Everything ran on Windows 11 with Python 3.14.7. The `ada-url` wheels for Linux and 3.12 exist but were only downloaded, not run.
- PostgreSQL 17 is verified locally through Docker (migrations, the store, and the API with a real uvicorn). No Docker in CI.

## Tooling and process
- The git hook must be enabled once per clone (`python tasks.py hooks`). Git for Windows' `sh` cannot fork on this machine, which is why hooks are plain `.githooks`.
- pytest prints a Starlette deprecation warning about `TestClient` and `httpx` (ADR-004).
- Tests block non-loopback network use (`tests/conftest.py`); the manual live test turns the block off on purpose.
- `agent/`, `extension/` and `console/` do not exist yet. ADR-007 to ADR-011 are drafts waiting for your sign-off.

## Next
`docs/milestones/M2.md` (proposed, awaiting approval).
