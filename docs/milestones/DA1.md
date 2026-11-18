# DA1: deep analysis and fewer false alarms

**Asked by the owner (2026-11-16):** "We must turn Lynceus into deep analysis, not add other features. Add deep analysis and reduce false positives." This plan needs approval before any code (CLAUDE.md, "How to work").

**Decisions (owner, 2026-11-16):** plan approved. P3 automatic page opening: **browser and email links** (the owner accepted that opening an emailed link can tell the sender the address is read and can use up a one-time link). P2: reading the verdicts stored on this computer to find real false alarms: **yes, locally**.

**More decisions (owner, 2026-11-16, "again more deeply: fewer false alarms, more real phishing and malware caught"):** the owner will create a free abuse.ch Auth-Key and store it (`python -m core.secrets set urlhaus_auth_key`), so URLhaus (malware download links) and the MalwareBazaar hash sync can be turned on: today the known-malware hash list holds only the 3 EICAR test hashes. Domain age (RDAP): **measure first** on about 600 domains from the public test data (phishing feeds and Tranco, never the owner's browsing), then the owner decides on using it for their own links.

**Status: built, measured and switched on (2026-11-17). All nine measurable acceptance criteria hold (`python -m eval.da1_accept`). The owner chose domain age and browser auto-opening on; both are live and checked. Not committed.**

## Where Lynceus is shallow today (measured)

- **The address alone has a ceiling.** On 133,195 real phishing URLs, **91.2% trigger no URL rule at all** (`docs/eval/url-real.md`). Reading the address cannot catch them; only the page can.
- **The page helps, but only when you ask.** Opening the page in the sandbox raised live phishing caught from **16.9% to 37.3%** (`docs/eval/detonate.md`), yet the browser check and the mailbox never open a page by themselves.
- **63% of live phishing pages pass even when opened.** The page rules read only the title and headings for a brand, and a sign-in form for intent. They miss: a brand named only in the body, in a logo's text or in the favicon; kits that load the real brand's logo and styles from the brand's own servers; pages that ask for a card number, a one-time code or an ID number rather than a password; pages on a certificate issued hours ago.
- **False alarms are concentrated in two address rules.** On legitimate URLs, `url.brand_in_domain` fired 567 times and `url.typosquat` 495 times (E1). On live legitimate pages 7 of 186 were flagged, nearly all by the address rules (`url.typosquat`, `url.login_path`), not by the page. On your own browsing nothing was flagged (0 of 86), and mail has no real-world measurement yet.

## What DA1 does (no new screens, no new product features: the engine judges more deeply)

**P1. Deep page judgment, from what the sandbox already captures.** New page rules, each with a positive and a negative fixture, tuned only on the D1 **dev** half of the 1,098 kept live pages:
- *Brand claimed anywhere on the page*: in the visible text, a logo's text, the favicon's address or the page's own image names, together with a form that asks for credentials, on a domain the brand does not own.
- *Borrowed brand assets*: the page loads the brand's logo, styles or scripts from the brand's own servers (a kit's habit) while being hosted elsewhere and asking for credentials.
- *What is being harvested*: fields for a card number and security code, a one-time code, a national ID or a recovery phrase, named by their type, name and label, on a domain that is not the brand's and not popular.
- *A certificate issued in the last days* on a page that asks for credentials (weak on its own: plenty of real sites renew often).
- Every page finding stays one category of evidence: none makes a page MALICIOUS alone (ADR-013 holds).

**P2. Fewer false alarms.**
- *The two noisy address rules*: re-examine every legitimate hit of `url.typosquat` and `url.brand_in_domain` on the E1 **train** split and the D1 dev half; tighten what is mechanical (ordinary words near a brand, brands inside longer words, short brands), measured before and after.
- *Page evidence clears weak address-only suspicion*: when the page was opened and shows no credential form, no brand claim and nothing hidden, a verdict that rests only on weak address signals (login path, a brand word in the domain) drops from SUSPICIOUS to UNKNOWN. Never to BENIGN, never when any strong signal fired, never for a list hit. Adopted only if it costs at most one caught phishing page on the dev half.
- *Your real false alarms* (only with your OK): read the verdicts already stored on this computer (your downloads, your browsing, your feedback in "Rules you called wrong") locally, list every flag, and say which are wrong and why. Nothing leaves the computer.

**P3. Deep analysis without a click (optional, your decision below).** For a link the browser check already found suspicious, or unknown with at least one signal, and not on the popular list, the core opens the page in the sandbox in the background and updates the verdict; the warning page and the console show the deeper result. It needs Docker running; without it nothing changes.

**P4. Measurement.** Before and after, with Wilson 95% intervals: the D1 **test** half run once (phishing caught, legitimate flagged), E1 legitimate sets, your browsing (0 of 86 must stay 0), the synthetic mail corpus (no regression). If Docker is available, a fresh live run of today's feeds for P1 and P3.

## What the D1 dev half showed (2026-11-16, before writing any rule)

Explored on the **dev** half of the kept pages only (the test half was not loaded). Today, with the AI1 learned model, the address alone already flags 52 of 107 live dev phishing pages and the page brings it to 60; 47 are still missed.

- **The missed pages mostly show no phishing at the moment they were opened.** Only 5 of the 47 ask for credentials. 26 show under 200 characters of text (a script that had not drawn the page yet, or a stub waiting for a click), and the forms on the rest belong to the site the kit was planted on or to Google (a kit that sends a scanner to Google). Rules that read the captured page cannot catch what the page did not show.
- **Signals that look deep but do not separate:** a brand named in the body text (on 51% of legitimate pages off the brands' domains), loading files from a big brand's servers (49% of legitimate pages), and bouncing to a famous site (6 of 107 phishing, 5 of 187 legitimate). Not adopted.
- **One signal that does separate:** a TLS certificate issued less than 7 days before the visit: 31% of live phishing pages, 8% of legitimate ones (17 of the 47 misses). Weak on its own (a site on a 90-day certificate renews often), usable next to a credential ask or lure words.
- **A measurement gap:** every legitimate page in D1 is a popular site or a brand's own site, so it cannot show what a rule costs on ordinary unknown sites, which is exactly where such a rule fires. Measuring it needs a new live run on long-tail legitimate sites (Tranco ranks 100,001 to 1,000,000), which needs Docker.

**What this changes:** the largest gains are in seeing more of the page, not in reading the captured page harder: opening risky links automatically (P3), and on a near-empty page waiting for it to finish drawing and looking a second time. Rules from the captured pages are limited to the certificate signal and wider credential detection, each measured on long-tail legitimate pages before adoption.

## Results so far (2026-11-16)

**P2, your real false alarms (read locally, counts only here).** The database on this computer held 150 verdicts (5 to 11 November; it was unreachable from 11 to 16 November, so nothing was stored then, now fixed). Real use produced **6 flags, all false alarms of one kind**: installers you downloaded, called SUSPICIOUS (75) because "it can run code" (`email.dangerous_attachment`), the weight that rule has for an email attachment. No browser verdict had ever been stored, and no feedback had been given. 15 downloads from 5 November ended in ERROR before the parser sandbox was set up.
- **Fixed:** for a downloaded file whose name is an installer type (`.exe`, `.msi`, `.msix`, `.appx` and their bundles) and whose content really is a program, being a program weighs 0.3 (shown, never enough alone). `.scr`, `.bat`, `.vbs`, `.hta`, a program named as a document, a double extension and a right-to-left name keep the full weight. Replayed on the 6 real flags: **all 6 now UNKNOWN**.
- **Deeper instead:** `file.origin_flagged`, the site the file came from (the agent reads Windows' download mark), judged by the URL rules. An installer from a site whose own address looks like phishing is SUSPICIOUS; from an ordinary site it adds nothing (that is not evidence of safety).
- Synthetic mail corpus (dev): unchanged, TP 73, FP 0, FN 1.

**P1.** `page.fresh_certificate` records a sign-in page under a certificate issued less than 7 days before the visit; the visit time is now stamped by the core. It is **evidence only (weight 0)**: a test showed that even 0.25, next to the login-path sign an ordinary new sign-in page carries, makes it SUSPICIOUS. A weight waits for the long-tail legitimate run.

**P3.** Built: `LYNCEUS_AUTO_DETONATION=browser,mail` (with `LYNCEUS_DETONATION=true`) opens a link in the sandbox when its address is SUSPICIOUS, or UNKNOWN with a sign, and it is off the brands' domains and the popular list: links the browser extension checks and up to 10 links per stored message. Each address at most once an hour, at most 8 waiting and 2 running; every opening is audited (by: auto, from: browser or mail, the page's status, never the address) and stored as an event; the browser's next check of that address gets the deeper verdict when it is graver. 11 tests (selection, once per window, never lowering, bounded queue, a failing page not stopping the next, mail links, the setting). **Not run live yet:** it needs the detonator image (`python tasks.py detonator`) and Docker.

**Found while testing:** the mailbox poller's state save could fail outright when Windows briefly locked the file (an existing test failed 2 runs in 4); it now retries a few times. 8 runs in 8 pass.

## Results (2026-11-17)

### Acceptance: every measurable criterion holds

`python -m eval.da1_accept` reads the reports in `docs/eval` and prints `DA1 ACCEPTANCE MET` only if all nine hold; a test proves it fails each one when it should (gates G1 and G2 in `GATES-DA1.md`). The test halves were each run once with the final rules.

| Criterion | Before | Now |
|---|---|---|
| D1 test half: live phishing caught, address rules + page, pages still alive (`docs/eval/detonate-da1.md`) | 37.3% (29.1 to 46.3), 44 of 118 | **55.9% (46.9 to 64.6), 66 of 118** |
| D1 test half: legitimate pages flagged | 7 of 186 | **1 of 186** (0.5%, 0.1 to 3.0) |
| E1 test split: legitimate `url.typosquat` hits | 20 | **15** |
| E1 test split: legitimate `url.brand_in_domain` hits | 79 | **57** |
| E1 test split: phishing flagged (PhiUSIIL 30,090; PhishTank 14,075; OpenPhish 92) | 37.73%; 26.44%; 70.65% | 37.71%; 26.43%; 70.65% (each inside its old interval) |
| Your browsing flagged | 0 of 86 | **0 of 92** |
| Synthetic mail corpus | TP 73, FP 0, FN 1 | TP 73, FP 0, FN 1 |

**Read the first row honestly.** The criterion compared against D1's numbers of 2026-11-11, which predate the learned domain model (AI1). Most of the rise is that model reading the address (address rules alone on the same alive pages: 16.9% then, 50.0% now); the page adds 5.9 points on top (7 pages caught only because of the page). What DA1 itself added to live phishing is the second model (+2.5 points on D1's unseen-domain pages, 59.0% to 61.5%, same sets, same day).

### The learned domain model, version 2 (adopted)

Model 2 reads more of the name's shape (vowel share, longest run of consonants, letter and digit switches, hyphen-separated parts, suffix length, suffix with the name's length and hyphens). Its threshold now sits at 0.4% of the calibration domains' legitimate names (was 0.5%). Training is deterministic: a retrain reproduces the shipped weights byte for byte. Same sets, same day, whole address engine (`docs/eval/learned-url.md`):

| Set | Shipped before (model 1, old typosquat) | Now |
|---|---|---|
| PhiUSIIL legitimate flagged | 0.42% (153 of 36,365) | 0.31% (114) |
| Tranco legitimate flagged | 1.69% (227 of 13,457) | 1.53% (206) |
| 3,000 long-tail sites (Tranco 100,001 to 1M) flagged | 2.50% (75) | 2.40% (72) |
| D1 legitimate pages (unseen domains), address only | 3.5% (9 of 259) | 3.5% (9 of 259) |
| PhiUSIIL phishing flagged | 34.9% | 35.4% |
| PhishTank phishing flagged | 18.0% | 18.5% |
| OpenPhish phishing flagged | 57.9% (44 of 76) | 57.9% |
| D1 live phishing (unseen domains), address only | 59.0% (213 of 361) | 61.5% (222 of 361) |
| Your browsing | 0 of 92 | 0 of 92 |

It catches slightly more and flags slightly fewer on every set, but the gain is small: **about 2.4% of ordinary long-tail sites still get a warning from their address alone**, mostly the learned model on random-looking names on cheap endings (14 of the 19 `.top` sites in the sample). Many of those are spam or gambling sites rather than harmless ones, so part of that rate is a fair warning.

**Tried and dropped:** a two-level model (the model may warn alone only above a stricter level, chosen on long-tail sites). It cut long-tail warnings by a third (2.0% to 1.3% of the same 3,000 sites) but cost 1.6 to 6.1 points of phishing caught (PhishTank 18.5% to 16.9%, PhiUSIIL 35.4% to 32.1%, D1 live pages 61.5% to 55.4%).

### The two noisy address rules

- **`url.typosquat`** needs a brand term of six letters or more for a misspelling, and the brand's first letter or its whole name inside the domain. It removed 19 of 27 legitimate hits and 8 of 148 phishing hits on E1's train split (finance for binance, sedex for fedex, mail for gmail, bank and vbank for mbank). On the test split: legitimate flagged 56 to 51 of 40,685, phishing flagged 11,352 to 11,347 of 30,090. A small trade, not a large one.
- **`url.brand_in_domain`** is silent where the brand sits entirely inside a longer word (`goldappleboutique`, `scrapbookingstore`). It removes 28% of its legitimate hits (79 to 57) and 3% of its phishing hits, and **changes no verdict** (the rule is too weak to flag alone); it only makes the evidence shown more honest.

### Live pages today (`docs/eval/da1-live.md`, 1,000 pages, test half shown)

- Of 183 phishing pages opened hours after their feed was published, **45 (24.6%) were still alive and 101 answered the sandbox with a 403**. Where readable: caught 60.0% by the address, **68.9% with the page** (31 of 45); 4 only because of the page.
- Legitimate: 3 of 185 alive pages flagged with the page (1.6%). On the long-tail sample 2 of 103 (1.9%, 0.5 to 6.8); sign-in pages 2 of 21.
- **Automatic opening would pick 76.5% of phishing links (140 of 183) and 1.0% of legitimate ones (3 of 307).**
- **Second look** at a near-empty page: needed by 0 of 45 phishing pages and 3 of 185 legitimate (none flagged). Unproven here; kept because it costs 5 seconds only on near-empty pages.
- **`page.fresh_certificate`**: 2 of 45 alive phishing pages, 0 of 185 legitimate. Far too few to set a weight: **it stays evidence only (weight 0)**.

### P3 automatic opening: what is and is not verified

14 tests (selection, once an hour, never lowering, bounded queue, a failing page not stopping the next, mail links, the setting, the API path) use a fake detonator and pass. **Run end to end with the real container on 2026-11-17** (see "The owner's two decisions" below): a flagged address was opened automatically, the page read or found dead, one audit record, the verdict never lowered. The acceptance criterion's literal form (a locally served `.test` page) cannot run, because the container refuses addresses on this computer by design; a public risky-looking site stood in for it. The "page not analysed" wording is not shown for a browser check: when a page cannot be opened the address verdict stands and the audit log records the page status.

### Domain age (RDAP): measured on public data, your decision (`docs/eval/rdap-age.md`)

600 public domains (300 from today's phishing feeds, 250 ordinary Tranco sites at ranks 100,001 to 1,000,000, 50 from the top 10,000), asked at their registries, paced at 25 a minute (the first, unpaced run measured the provider's own limit and was discarded). The registry gave an age for 88.0% of the phishing domains, 74.0% of the long-tail ones and 96.0% of the top ones; the rest sit under a top-level domain with no RDAP server or failed.

| of domains with a known age | phishing (264) | ordinary long-tail (185) | top 10,000 (48) |
|---|---|---|---|
| under 7 days | 8.0% (21) | 0.0% (0 of 185, up to 2.0%) | 0.0% |
| under 30 days | **32.6% (27.2 to 38.4), 86** | **0.0% (0 of 185, up to 2.0%)** | 0.0% |
| under 90 days | 56.8% (150) | 3.8% (7) | 0.0% |
| under 1 year | 76.9% (203) | 17.3% (32) | 4.2% |

With the weights already in the code (week 0.55, month 0.4, quarter 0.15): phishing flagged **49.0% to 53.0%** (12 more of 300), ordinary long-tail sites flagged 6 to 6 (none newly), top sites 0 to 0. It is the strongest single signal measured on the ordinary-looking own domains that make up 75% of the misses.

What it does not show: the phishing sample is fresh feed entries (young by selection), and a legitimate brand-new site (a new shop, a new company domain) would be young too and was not in the sample; about a quarter of long-tail domains gave no age, so it helps only where the registry answers. What it costs to switch on: the registered domain of each site you visit that is not on the popular list is asked at its registry, from your connection (since DA2, established sites are no longer asked). **Recommendation: switch it on** (`rdap` in `LYNCEUS_INTEL_PROVIDERS`), and watch the console for young legitimate sites flagged.

### The owner's two decisions (2026-11-17): both switched on

1. **Domain age (RDAP): on.** `rdap` is in `LYNCEUS_INTEL_PROVIDERS` (now `openphish,phishtank,virustotal,urlhaus,rdap`). Checked live through the product's own path: `registered 501 days ago`, `191 days ago` on ordinary long-tail sites; google.com is not asked at all (DA2).
2. **Automatic opening: on, browser links only** (`LYNCEUS_AUTO_DETONATION=browser`; the mail source is moot, no mailbox is linked). On the data, address-flagged links the sandbox can read gain 5.9 points of catch from the page (7 of 118 on the test half; 4 of 45 today), it opens 1.0% of legitimate links needlessly, and 3 in 4 live phishing pages are already dead or refuse the sandbox. The cost is a visit from your connection to a live site and a possible second visit to a one-time link; to switch it off, remove the line from `.env` and restart the core.

**Checked end to end on 2026-11-17** (a throwaway core with its own token and empty data folder, no outside providers, the real sandbox container, a risky-looking address sent with the browser's source header; nothing of the owner's core, database or settings touched): one risky-looking `.top` address (SUSPICIOUS) was opened and the page was dead; a second (SUSPICIOUS) was opened and the page was read. Both left one audit record `by: auto, from: browser, page: dead|ok`, and the address is in no audit line. The verdict stayed SUSPICIOUS when the page showed nothing graver (a page never lowers a verdict) and when it could not be opened (the address verdict stands). The plan's literal criterion (a locally served `.test` page) cannot run: the container refuses addresses on this computer by design.

### What I measured about the limits (2026-11-17), and what would move the numbers

- **Misses:** 75% of missed phishing (21,899 of 29,125) are ordinary-looking own domains, many hacked real sites; caught 24.7% bare and 17.2% with a path. Free hosting platforms: 78.5% bare, 34.6% with a path. Short links (5.3% of phishing) show 0.4% only because the test reads the address alone; the extension checks the page a redirect ends on.
- **No legitimate addresses with paths exist in the evaluation data** (all 121,258 PhiUSIIL and 44,920 Tranco legitimate addresses are bare home pages; only 89 of your 92 browsing URLs have a path). Every false-alarm figure here is for home pages. The rules that fire on paths are validated on those 89 URLs only. This is the largest unknown; a path-reading model cannot be trained honestly until it is fixed (a first try flagged 100% of phishing by learning "has a path").
- **Page-based clearing** ("the page shows nothing, so lower a weak warning") would also clear 5 of 175 caught phishing pages and cannot be tested for benefit (3 flagged legitimate pages). Not adopted.
- **Ranked sites:** treating Tranco 100,001 to 1,000,000 as established for the learned model would cost 80 of 14,360 phishing addresses it flags (0.56%); its benefit cannot be measured on Tranco-drawn sites (circular).

Ranked next steps, with what each needs: (1) a legitimate deep-link corpus from Common Crawl's public index (only domain names leave), which unlocks honest false-alarm measurement and a path-aware model; (2) VirusTotal lookups of downloaded files' SHA-256 (hash only; today the local list holds 3,340 hashes of the last 48 hours), needing your OK; (3) ranked sites as established for the model only; (4) domain age (below); (5) reading the page in your real browser through the extension, which sees what a cloaked kit shows a real visitor, the biggest project, needing a wider extension permission and your OK.

### Tests and tooling changed while finishing

A shared test fixture (`no_learned_model`) keeps tests about address rules, providers and pages independent of the learned model's retraining; the agent's host-program test no longer finds the real agent running on this computer (it moves the agent home, which changes the pipe name); a test-only code string in the console shell is allow-listed for the secret scan. `python -m eval.da1_rules`, `eval.da1_accept` and `eval.rdap_age` (now paced under the provider's 30 per minute) are new or changed evaluation tools.

## Security and privacy

P1 and P2 open nothing new: they judge pages already captured. P3 opens pages automatically, which means visits from your internet connection and, for a one-time link, a second visit; that is why it is your decision and limited to links the browser was already opening. Reading your stored verdicts (P2) stays on this computer and goes into no report beyond counts. No change to the verdict model, no new dependency, no outside service.

## Acceptance (ledger in `GATES.md` once approved)

1. On the D1 **test** half: live phishing caught rises above today's 37.3% (the new interval's lower bound above today's point), with legitimate pages flagged no higher than today's 7 of 186.
2. Legitimate address-rule hits of `url.typosquat` and `url.brand_in_domain` on the E1 **test** split fall, with phishing caught on E1 not lower than today's interval.
3. Your browsing: still 0 flagged. Synthetic mail corpus: no new false alarm, no new miss.
4. Every new or changed rule has a positive and a negative fixture; all suites pass (Python, agent, console, e2e).
5. If P3 is chosen: a browser link to a made-up `.test` phishing page served locally is judged from its address first, then automatically from its page, and the warning updates; with Docker stopped the address verdict stands and says the page was not analysed.

## Not in DA1

The local brain stays off and unmeasured (it waits for the study run, as decided in AI1). Mail stays measured on synthetic messages only until your Gmail is connected (H1 B2). No new screens.
