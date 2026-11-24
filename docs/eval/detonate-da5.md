# Page detonation on live pages (D1)

2026-11-22T20:32:02+00:00. Seed `lynceus-d1-2026-11-11`. **The test half is shown.** The URLs were split in two by a hash fixed before any page was opened, and rules may be changed only by looking at the dev half (dev, for comparison: phishing caught with the page 57.0% (47.5 to 66.0), 61 of 107; legitimate flagged 1.1% (0.3 to 3.8), 2 of 187). Every page was opened in the detonator container only (`docs/milestones/D1.md`); nothing was typed or submitted. URLs and per-URL rows stay in `.data/eval/d1/`; this report holds counts only. Intervals are Wilson 95%.

**Baseline = the URL rules alone, without the lists**: every phishing URL here comes from a list, so the lists would catch all of them by construction. The question is what the page adds for a phishing URL no list knows yet.

## Phishing (today's OpenPhish feed and the newest PhishTank entries)

| | Result |
|---|---|
| pages still alive | 52.9% (46.4 to 59.4), 118 of 223 |
| **caught, URL rules alone (alive pages)** | 49.2% (40.3 to 58.1), 58 of 118 |
| **caught, URL rules + page (alive pages)** | 56.8% (47.8 to 65.4), 67 of 118 |
| MALICIOUS with the page (alive pages) | 18.6% (12.6 to 26.6), 22 of 118 |
| caught only because of the page | 9 |
| alive pages with a password field | 24.6% (17.7 to 33.1), 29 of 118 |
| caught, all URLs (dead pages count as misses) | URL alone 58.3% (51.7 to 64.6), 130 of 223; with page 63.2% (56.7 to 69.3), 141 of 223 |

## Legitimate (brand home pages, a Tranco top-10,000 sample, and /login on another Tranco sample)

| | Result |
|---|---|
| pages alive | 50.1% (45.1 to 55.2), 186 of 371 |
| flagged, URL rules alone (alive) | 0.0% (0.0 to 2.0), 0 of 186 |
| **flagged, URL rules + page (alive)** | 0.5% (0.1 to 3.0), 1 of 186 |
| false alarms added by the page | 2 |
| **legitimate pages with a password form, flagged** | 3.8% (0.7 to 18.9), 1 of 26 |

## By source (alive pages, URL rules + page)

| Source | n | alive | flagged |
|---|---|---|---|
| openphish (phish) | 165 | 89 | 57.3% (46.9 to 67.1), 51 of 89 |
| phishtank (phish) | 58 | 29 | 55.2% (37.5 to 71.6), 16 of 29 |
| brand_home (legit) | 58 | 52 | 0.0% (0.0 to 6.9), 0 of 52 |
| tranco (legit) | 148 | 93 | 0.0% (0.0 to 4.0), 0 of 93 |
| tranco_login (legit) | 165 | 41 | 2.4% (0.4 to 12.6), 1 of 41 |

## DA1: what the deeper look adds, and what automatic opening would cost (test half)

| | phishing | legitimate |
|---|---|---|
| alive pages read on a second look (the first showed almost nothing) | 0.0% (0.0 to 3.2), 0 of 118 | 0.0% (0.0 to 2.0), 0 of 186 |
| ... of those, flagged | n/a (n=0) | n/a (n=0) |
| `page.fresh_certificate` (evidence only, no weight) | 0.0% (0.0 to 3.2), 0 of 118 | 0.0% (0.0 to 2.0), 0 of 186 |
| would be opened automatically (address SUSPICIOUS, or UNKNOWN with a sign, not popular) | 55.2% (48.6 to 61.5), 123 of 223 | 0.3% (0.0 to 1.5), 1 of 371 |

## Page rules that fired (alive pages)

| Rule | phishing | legitimate |
|---|---|---|
| `page.brand_credential` | 19 | 1 |
| `page.brand_on_hosting` | 7 | 2 |
| `page.cloaked` | 3 | 1 |
| `page.collection_endpoint` | 12 | 0 |
| `page.evasion` | 1 | 0 |
| `page.form_offsite` | 1 | 0 |
| `page.geofence` | 10 | 0 |
| `page.hosting_platform_login` | 17 | 0 |

Landing-address URL rules (the page moved to another site): phishing 3, legitimate 0.

## Page status

- phishing: {'ok': 109, 'http_403': 65, 'partial': 9, 'error': 4, 'http_404': 11, 'dead': 20, 'http_400': 1, 'http_410': 1, 'http_503': 3}
- legitimate: {'ok': 169, 'http_403': 31, 'partial': 18, 'dead': 98, 'http_404': 50, 'http_521': 1, 'http_500': 2, 'http_400': 1, 'http_405': 1}
- median time per page: phishing 5.1 s, legitimate 5.8 s
