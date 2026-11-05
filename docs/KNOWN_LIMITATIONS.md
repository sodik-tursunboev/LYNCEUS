# Known limitations (M1 done, M2 in progress)

Written to be read before trusting anything in the repo. "Not verified" means code or config exists that was never run.

## What the M2a message engine cannot do (MIME, headers, HTML, links, attachment inventory)
- **Attachments are inventoried, not opened.** Type by file signature, name flags, size and hash only. PDFs, images (QR, OCR), archives and Office files are not looked inside until M2b, and Office documents are out of M2 entirely. A harmless-looking `.pdf` that is a real PDF with a malicious link is not caught yet.
- **A message is never BENIGN** (ADR-014). The best a clean message gets is UNKNOWN. That is correct and also means there is no "this is fine" answer to show a user.
- **CSS is read only where it is written on the element.** `style="display:none"` and the common tricks (zero size, off-screen, clipped, transparent) are caught; hiding through a `<style>` block, a class or a stylesheet is not. Text and link order are not rendered, so overlaid or reordered text can fool the link-text rules.
- **Link text is compared to its target only for anchors,** and only when the text contains something that parses as a domain with a known suffix. "Click here" over a bad link is not a mismatch; it is still analysed as a link.
- **Relative links are skipped** unless the message sets `<base href>` (counted in the report as `relative_links_skipped`). Past 100 distinct links the rest are counted, not analysed. Past 500 links, or 2 MiB of HTML, or 50,000 tags, the scan stops and says so (`limits_hit`).
- **`Authentication-Results` is whatever the header says.** It is added by the receiving server, so a forged header from a sender who is not stripped by their provider reads like a pass; the rule only counts `fail` and `softfail`. Nothing is recomputed (no DNS, by design).
- **Brand and sender checks inherit the M1 gaps:** an unverified brand list, and no typosquat/combosquat catch for a digit-swapped brand plus keyword (`paypa1-secure.test`): the M1 rules were left alone after the holdout was spent.
- **Non-English coverage is thin:** urgency and credential phrases are English and Polish only, from general knowledge, not measured.
- **Storage keeps hosts in plaintext** (`domains`), so the database records which sites a user's mail linked to. No message text, URL, address or file name is stored (a test scans every table), and ADR-007 is still unsigned.

## What the sandbox does not cover
- **Windows only.** The restricted process (AppContainer plus Job Object) is Windows-specific; on any other system analysis returns ERROR `sandbox_unavailable`, and the sandbox tests are skipped. A Linux container route is not built.
- **Per-user setup.** Building registers an AppContainer profile (`python tasks.py sandbox`; `python -m core.sandbox.build --remove` undoes it). The sandbox is rebuilt from scratch each time, and a stale copy is caught by a test, not by the runtime.
- **It is a mitigation, not a proof.** Kernel or interpreter escapes are out of scope; the limits are memory, CPU time, wall time, output size and one process. A hostile message can still burn those limits (and does, by design, end as UNKNOWN with a reason).
- **Concurrency is capped at 4** (`MIRAGE_MAX_CONCURRENT_PARSERS`); a fifth request waits one second, then gets 503.

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
