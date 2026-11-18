# DA2: honest false-alarm data, file reputation, and less leaving the computer

**Chosen by the owner (2026-11-17), from DA1's ranked list:** "Corpus + hash lookups". This note is the plan and then the results; it was written before the code.

**Status: built and measured (2026-11-17). The file lookup is ready and checked on a real core but switched OFF, waiting for the owner's yes (it sends the hash of downloaded programs). Not committed.**

## Why (measured in DA1, `docs/milestones/DA1.md`)

- Every legitimate address in the evaluation data is a bare home page (121,258 PhiUSIIL and 44,920 Tranco; only 89 of the owner's 92 browsing URLs have a path). The rules that read paths and queries have never been measured for false alarms on real deep links, and a path-reading model cannot be trained honestly without such data.
- Malware: the local known-bad list holds 3,340 hashes from MalwareBazaar's last 48 hours. VirusTotal knows nearly every known sample.
- Found while wiring VirusTotal: with it on, the core asks it about the registered domain of **every** site the browser checks, popular ones included. That is more than "one domain" suggests.

## What DA2 does

**P1. A deep-link corpus (`python -m eval.deeplinks`).** A seeded sample of public Tranco domains in four rank bands (100 domains each, 400 in all; the first plan of 1,200 would have taken more than a day at the archive's current speed); a few archived pages of each from the Internet Archive's public index (one public domain name per request, an honest user agent, at most four requests at once, backing off). Split into dev and test by a hash of the registered domain, fixed before measuring. The whole address engine is measured twice: as the product runs (popular list on) and as it treats an unknown site (list off). Rules may be changed only by looking at dev; test is read once. Counts only in the report.
Common Crawl's index was tried first and rejected: it answered with 502 and 504 errors at 10 seconds and asks not to be overloaded.

**P2. File reputation (`LYNCEUS_FILE_REPUTATION=true`).** For a downloaded file of a program-like type (executables, installers, scripts, shortcuts, disk images, archives, macro-enabled Office files; never PDFs, pictures, plain documents), the core asks VirusTotal what its engines say about the file's SHA-256. **Only the hash leaves** (never the file, its name or its folder); an unknown hash returns "no report", which proves nothing. Several engines flagging it is decisive (MALICIOUS), a few make it SUSPICIOUS, one or two are shown and never alone enough. A failed, slow or limited lookup leaves the verdict exactly as it was. Thresholds are chosen on 100 clean Microsoft binaries from this computer (hashes of universal Windows files; they say nothing about the owner) and 100 recent MalwareBazaar hashes, then reported as they are. Free-key limits: 4 a minute, 500 a day, non-commercial use.

**P3. Established sites are not asked.** Outside providers (VirusTotal, RDAP) stop receiving the registered domain of a site on the popular list (Tranco's top 100,000) or a brand's own domain: they add nothing there, and it was the bulk of what was being sent. List feeds stay local and unchanged.

## Security and privacy

P1 sends public domain names to the Internet Archive once, to build a test set; it never touches the owner's data. P2 sends the SHA-256 of downloaded programs to VirusTotal: a hash cannot be turned back into a file, but it does tell VirusTotal that this file exists on a computer using this key, and VirusTotal says any queried indicator is added to its dataset and visible to the community. It is off by default and the owner chose it. P3 reduces what leaves. No new dependency.

## Acceptance (ledger: `GATES-DA2.md`)

1. An established site's domain is never sent to an outside provider; an unknown site's still is.
2. The file lookup request carries the hash and the key header only; an unreadable, slow, limited or "unknown" answer never changes a verdict; no answer is ever BENIGN.
3. On the clean and the malware sets, the measured numbers are reported, and none of 100 clean Microsoft binaries reaches the flagged tier.
4. The corpus holds addresses with paths from all four bands, measured on dev and test as above; false alarms found on dev are examined by rule, and what is changed is measured on test once.
5. All suites pass; the secret scan finds nothing.

## Not in DA2

A path-reading learned model (it needs the corpus first; only then can it be trained and judged), domain age and automatic opening (DA1's two decisions), reading pages in the user's real browser, linking mailboxes.

## Results (2026-11-17)

### P3. Established sites are no longer sent to outside services

Before this, with VirusTotal or RDAP on, the registered domain of every site the browser checked went out (within the free key's limits), google.com included: more than "one domain" suggested. `core/intel/egress.py` now returns no name for a domain on the popular list (Tranco top 100,000) or a brand's own domain, so neither provider is asked; the local list feeds still see every address. Checked live: google.com is skipped by both providers (`not a public name, or an established site: not sent out`), ordinary long-tail sites are still asked. 3 tests; the intel suite (206 tests) passes.

### P2. File reputation at VirusTotal (`LYNCEUS_FILE_REPUTATION`, off)

`docs/eval/filerep.md`: of 100 Microsoft programs from this computer's Windows folders, **100 had a report and none had a single engine flagging it**; of 100 recent MalwareBazaar hashes, 97 had a report, **89 (91.8%, 84.6 to 95.8) reached 4 or more engines and 84 (86.6%, 78.4 to 92.0) reached 10 or more**. The thresholds were set before the run (10 and 4) and held; moving them would have gained at most 5 hashes. Checked end to end on a throwaway core with a real clean Windows program: one lookup, audited as `file.reputation / report`, the verdict unchanged, a `.txt` not asked, neither the hash nor the name in the audit line. 23 tests of the lookup (the request is the hash and the key header only; cached; 4 a minute and 500 a day; a malformed, refused or slow reply is no answer), 5 of the verdict tiers, 13 of the name filter, 10 of the API path (only when switched on, only program-like names, never a locally known file, any failure leaves the verdict alone, start-up refused without the key).

Limits: the clean set is Microsoft's own programs, the easiest case; third-party legitimate software with a few detections is untested here, and ten engines is treated as exact identification (a click is still needed before anything moves). A program renamed to a document type is not asked about. VirusTotal's pages do not state what an unknown file returns: a 404 is read as "no report".

### P1. False alarms on legitimate deep links (`docs/eval/deeplinks.md`)

1,640 archived pages of 358 public domains (498 with a query string), four Tranco rank bands, split by a hash of the domain: dev 757, test 883 (the test half was read twice, not once, so it is a check and not an untouched sample). Every legitimate address elsewhere in the evaluation data is a bare home page, so this is the first measurement of the rules that read paths and queries. **As the product runs: 25 of 757 flagged on dev before any change (3.3%).** The false alarms were not random; reading them rule by rule:

| rule | dev false alarms | cause | decision (cost measured on E1 train phishing) |
|---|---|---|---|
| `url.encoded_target` | 5 | a chat widget's `referrer=` parameter carries the embedding page's address, base64-encoded | `referrer`, `referer`, `ref`, `origin` are not targets: cost 0 of 88,938 |
| `url.credential_bait` | 1 | `utm_medium=twitter` names a brand | ignore `utm_*` parameters: cost 0 of 558 hits |
| `url.learned_domain` | 3 | tenants of a platform (`www0707.wixsite.com`): the model reads the tenant label | **left alone**: a first attempt to silence the model on platform domains matched too widely and silenced every tenant on a private suffix (`name.netlify.app`, `name.pages.dev`), where the model is useful; the verification re-run caught it (phishing flagged on E1 fell by more than half) and the change was removed. `wixsite.com` is itself a public suffix, so there is no "platform's own domain" for the model to be silent on |
| `url.credential_bait` | 3 | `auth` inside "oauth", a brand inside a news slug | whole-word login words would lose 183 of 558 phishing hits: **rejected** |
| `url.open_redirect` | 4 | Azure sign-in addresses (`redirect_uri`) | **left alone**: the same pattern is how illicit-consent phishing looks |
| `url.brand_in_subdomain` | 4 | `adobe.goskope.com`, `apple.itsc.locum.ru` | **left alone**: two domains are not evidence; the rule is a strong one |
| `url.learned_domain` | 5 | piracy and adult sites (`egybesst.skin`, `jav777.xyz`) | a fair warning, left alone |
| `url.typosquat` | 5 (list off only) | a Hungarian news site as a look-alike of BLIK | **tried and reverted**: it only appears with the popular list off, and the change stopped catching `ollx.test`, the fixture's look-alike of OLX (three letters), caught by the project's own fixture |

After the two adopted changes: **dev 19 of 757 (2.51%, 1.61 to 3.89); test 20 of 883 (2.27%, 1.47 to 3.47); all 39 of 1,640 (2.38%, 1.74 to 3.23)**. (The test half was read twice: the first reading, 17 of 883, was taken with the faulty platform change described above; it was read again after the fix, and no tuning decision was taken from either reading.) As the product runs, about 1 legitimate page in 42 gets a warning; by rank band (all): top 1,000 3.53% (9 of 255, wixsite and netlify tenants and a few brand pages), 1,001 to 10,000 2.42%, 10,001 to 100,000 0.67%, 100,001 to 1M 3.26%. The remaining flags are `url.learned_domain` 22 (mostly spam, piracy, adult and tenant sites), `url.credential_bait` 9, `url.open_redirect` 6, `url.brand_in_subdomain` 4, `url.host_shape` 2, `url.login_path` 2. With the popular list off (how an unknown small site is treated): 3.6%.

The corpus came from the Internet Archive, which is slow (15 to 45 seconds a query) and holds some junk; Common Crawl's index was tried first and answered with 502 and 504 errors. 400 of the planned 1,200 domains were asked, then a top-up round of 180, which left 358 domains with usable pages.