# Known limitations (v0.1: M0 to M3)

Written to be read before trusting anything in the repo. "Not verified" means code or config exists that was never run.

## Threat intelligence (M3): what it is and is not
- **No adapter has been run against its live service.** They are built from the providers' documentation and tested against synthetic fixtures and a mock transport. Unverified: the URLhaus export path and CSV layout, PhishTank registration and rate limits, VirusTotal's domain-object field names and Terms of Service, RDAP registries' rate limits and query logging. A wrong assumption about a reply shape shows up as a stated provider ERROR, never as a wrong verdict, but the first real run will probably need fixes. You must register for the keys (VirusTotal, PhishTank, URLhaus) yourself.
- **The real-world value of the providers is unmeasured.** The corpus is synthetic and its hosts are unregisterable, so no listed URL or young domain can be in it; the eval is unchanged by M3. Whether list feeds, domain age or VirusTotal add detection, and how many false positives they add, is unknown until they run on real traffic. Decision D8 (measuring the URL rules on a downloaded PhishTank snapshot kept outside git) is still open for you to run.
- **Terms limit what v0.1 may be.** VirusTotal's public API, Safe Browsing, OpenPhish's community feed, URLhaus and urlscan's free tier restrict use in a product or business. v0.1 is a single person's local, non-commercial tool; distributing it needs commercial terms for each provider (ADR-015).
- **Query providers do tell someone something.** With RDAP or VirusTotal on, the registered domain of each URL you analyse reaches a registry or VirusTotal (which says it adds queried indicators to its public dataset), along with your IP address and, for VirusTotal, your account. Only a public registered domain is sent, never a path or a token, and it is off by default, but it is still a record of the sites you looked at. Message links stay local unless you set `MIRAGE_INTEL_EMAIL_LINKS`.
- **Feeds are third-party data, hours old.** A list is only as current as the last `sync` (PhishTank hourly at best, OpenPhish every 12 hours); a list older than its limit reports UNAVAILABLE. Entries are exact URL matches, so a phishing page moved to a new path is invisible until it is listed; a listed host with other paths is a weak signal (and ignored for shared platforms). Phishing kits that show scanners something else are not helped by any of this.
- **A listing is evidence, not proof.** One provider alone gives SUSPICIOUS (WARN). PhishTank and URLhaus entries can be wrong or stale; urlscan's own FAQ warns against unattended blocking on provider verdicts. Nothing here ever produces BENIGN.
- **State is in memory.** The cache and the rate-limit counters reset on restart (a restart can spend part of VirusTotal's 500 a day twice). The circuit breaker is per process.
- **Residual SSRF risk in RDAP:** the registry server named by IANA's bootstrap file is checked by name (https, public suffix, no IP literal or credentials) but not by the address it resolves to. Fixing it means using the connect-by-validated-IP code in `safe_fetch`, which stays unsigned (ADR-011) and unwired.
- **Keys are plaintext in `.env`** (ADR-007 unsigned), and PhishTank and URLhaus keys travel in the download URL (hidden from logs and results, visible to the provider and any proxy).
- **Not built:** urlscan (deferred to an on-demand investigation feature), Web Risk (needs billing), Safe Browsing v5 (the stretch goal), OCR (M2). The email ruleset has no explicit caps for `link.intel.*`.

## What the M2a message engine cannot do (MIME, headers, HTML, links, attachment inventory)
- **What is opened:** PDFs, zip/tar/gz/bz2/xz archives, and png/jpeg/gif/bmp/tiff/webp images (QR codes), each in its own sandbox process, up to 8 attachments per message (the rest are reported as `skipped`). **Not opened:** 7z, rar and iso (named only), Office documents (out of M2: macro-enabled files are flagged by name and type, never read), password-protected archives and PDFs (reported, contents unknown), and anything else.
- **No OCR (deferred by decision, ADR-004).** Text inside images is not read. A phishing lure that is only a screenshot with a typed URL is invisible; a QR code is decoded.
- **PDF triage is features, not behaviour.** It counts JavaScript, Launch, embedded files and link annotations through qpdf. It does not render, so a link hidden under an image, a form that posts elsewhere, or content in an XFA template are only as visible as the dictionary entries. Links in the page content stream (not annotations) are not extracted.
- **QR decoding is OpenCV's detector, tuned on synthetic codes.** Real photographs, tilted, low-contrast or logo-overlaid codes will be missed; on a miss the image is simply a clean image. A QR code to a login-looking domain with no brand and no other signal is UNKNOWN (dev sample `m2b-025`), and a PDF whose only feature is an embedded file is UNKNOWN (`m2b-018`): both are counted as misses.
- **Archive limits are declared, not measured.** A bomb is recognised from headers and a read budget (48 MiB); a malicious archive that stays under the thresholds (256 MiB declared and 100x expansion) is just an archive. Entry names and contents are never kept; only extensions, real types and counts reach the rules.
- **HTML smuggling is pattern counting** (`new Blob`, `atob`, large base64, `download` on a data link) on the first 200,000 characters of script. Heavy obfuscation, string splitting or loading the payload from a remote file defeats it.
- **Cost.** Each opened attachment starts a sandbox; importing the image libraries takes about 3 seconds cold. A message with several attachments takes seconds, not milliseconds, and the sandbox folder is about 208 MB.
- **A message is never BENIGN** (ADR-014). The best a clean message gets is UNKNOWN. That is correct and also means there is no "this is fine" answer to show a user.
- **CSS is read only where it is written on the element.** `style="display:none"` and the common tricks (zero size, off-screen, clipped, transparent) are caught; hiding through a `<style>` block, a class or a stylesheet is not. Text and link order are not rendered, so overlaid or reordered text can fool the link-text rules.
- **Link text is compared to its target only for anchors,** and only when the text contains something that parses as a domain with a known suffix. "Click here" over a bad link is not a mismatch; it is still analysed as a link.
- **Relative links are skipped** unless the message sets `<base href>` (counted in the report as `relative_links_skipped`). Past 100 distinct links the rest are counted, not analysed. Past 500 links, or 2 MiB of HTML, or 50,000 tags, the scan stops and says so (`limits_hit`).
- **`Authentication-Results` is whatever the header says.** It is added by the receiving server, so a forged header from a sender who is not stripped by their provider reads like a pass; the rule only counts `fail` and `softfail`. Nothing is recomputed (no DNS, by design).
- **Brand and sender checks inherit the M1 gaps:** an unverified brand list, and no typosquat/combosquat catch for a digit-swapped brand plus keyword (`paypa1-secure.test`): the M1 rules were left alone after the holdout was spent.
- **Non-English coverage is thin:** urgency and credential phrases are English and Polish only, from general knowledge, not measured.
- **Storage keeps hosts in plaintext** (`domains`), so the database records which sites a user's mail linked to. No message text, URL, address or file name is stored (a test scans every table), and ADR-007 is still unsigned.

## How far the message numbers can be trusted (M2)
- 180 synthetic messages from templates (dev 119, holdout 35, reserve 26), written by the author of the rules. **They measure rule correctness, not detection of real phishing.** No real mailbox, phishing feed or authorized dataset was used.
- **Dev (not tuned beyond writing the rules, `docs/eval/mail-dev.md`):** TP 72, FP 0, FN 2, precision 1.000 (95% interval 0.949 to 1.000), recall 0.973 (0.907 to 0.993) counting abstentions as misses. Both misses are documented hard cases. **All 45 benign messages are UNKNOWN, never BENIGN** (abstain rate 0.395): a message gets no allowlist, so a flag rate of 0 shows that nothing benign was flagged, not that anything was recognised as safe.
- **Holdout, run once on 2026-11-05, logged in `docs/eval/mail_holdout_runs.md` (`docs/eval/mail-holdout.md`):** n = 35, TP 22, FP 0, FN 0, recall 1.000 (95% interval 0.851 to 1.000). 12 of the 35 (the attachment messages, `m2c-*`) were written blind to the rules and the other 23 come with the first corpus, but all 35 share templates with dev, so a perfect score is what shared templates predict; it is not evidence of 100% real-world recall. The reserve (26) has never been run.
- **24 rules have no hit on dev** (12 message rules, among them archive traversal, image bomb, XFA, link flood, meta refresh, the typosquat/homograph sender rules and `file_inspection_incomplete`, and 12 URL rules). They pass their positive and negative test messages but have no corpus coverage, so their weights are untested guesses.
- Latency (p50 about 0.35 s, p95 about 1.1 s) includes starting the sandbox once or more per message on a shared machine; order of magnitude only.

## What the sandbox does not cover
- **Windows only.** The restricted process (AppContainer plus Job Object) is Windows-specific; on any other system analysis returns ERROR `sandbox_unavailable`, and the sandbox tests are skipped. A Linux container route is not built. The parser libraries are pinned to Windows x64 / CPython 3.14 wheels (`requirements-sandbox.txt`).
- **Native parsers are the new attack surface:** qpdf, libxml2 (through lxml), Pillow's decoders, OpenCV and numpy now run on attacker bytes. They are inside the sandbox, on pinned versions, with the FFmpeg plugin removed, and fuzzed here only by random-bytes tests; they have not been audited or run under a fuzzer.
- **Concurrency is up to 4 requests x 4 sandboxes** (one parse plus 3 attachment inspections each), 16 processes at most.
- **Per-user setup.** Building registers an AppContainer profile (`python tasks.py sandbox`; `python -m core.sandbox.build --remove` undoes it). The sandbox is rebuilt from scratch each time, and a stale copy is caught by a test, not by the runtime.
- **It is a mitigation, not a proof.** Kernel or interpreter escapes are out of scope; the limits are memory, CPU time, wall time, output size and one process. A hostile message can still burn those limits (and does, by design, end as UNKNOWN with a reason).
- **Concurrency is capped at 4 requests** (`MIRAGE_MAX_CONCURRENT_PARSERS`); a fifth waits one second, then gets 503.

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
