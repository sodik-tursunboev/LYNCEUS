# Page detonation on live pages (D1)

2026-11-11T14:08:42+00:00. Seed `lynceus-d1-2026-11-11`. **The test half is shown.** The URLs were split in two by a hash fixed before any page was opened, and rules may be changed only by looking at the dev half (dev, for comparison: phishing caught with the page 33.6% (25.4 to 43.0), 36 of 107; legitimate flagged 2.7% (1.1 to 6.1), 5 of 187). Every page was opened in the detonator container only (`docs/milestones/D1.md`); nothing was typed or submitted. URLs and per-URL rows stay in `.data/eval/d1/`; this report holds counts only. Intervals are Wilson 95%.

**Baseline = the URL rules alone, without the lists**: every phishing URL here comes from a list, so the lists would catch all of them by construction. The question is what the page adds for a phishing URL no list knows yet.

## Phishing (today's OpenPhish feed and the newest PhishTank entries)

| | Result |
|---|---|
| pages still alive | 52.9% (46.4 to 59.4), 118 of 223 |
| **caught, URL rules alone (alive pages)** | 16.9% (11.2 to 24.7), 20 of 118 |
| **caught, URL rules + page (alive pages)** | 37.3% (29.1 to 46.3), 44 of 118 |
| MALICIOUS with the page (alive pages) | 9.3% (5.3 to 15.9), 11 of 118 |
| caught only because of the page | 24 |
| alive pages with a password field | 24.6% (17.7 to 33.1), 29 of 118 |
| caught, all URLs (dead pages count as misses) | URL alone 16.1% (11.9 to 21.5), 36 of 223; with page 27.4% (21.9 to 33.6), 61 of 223 |

## Legitimate (brand home pages, a Tranco top-10,000 sample, and /login on another Tranco sample)

| | Result |
|---|---|
| pages alive | 50.1% (45.1 to 55.2), 186 of 371 |
| flagged, URL rules alone (alive) | 3.8% (1.8 to 7.6), 7 of 186 |
| **flagged, URL rules + page (alive)** | 3.8% (1.8 to 7.6), 7 of 186 |
| false alarms added by the page | 1 |
| **legitimate pages with a password form, flagged** | 3.8% (0.7 to 18.9), 1 of 26 |

## By source (alive pages, URL rules + page)

| Source | n | alive | flagged |
|---|---|---|---|
| openphish (phish) | 165 | 89 | 42.7% (32.9 to 53.1), 38 of 89 |
| phishtank (phish) | 58 | 29 | 20.7% (9.8 to 38.4), 6 of 29 |
| brand_home (legit) | 58 | 52 | 0.0% (0.0 to 6.9), 0 of 52 |
| tranco (legit) | 148 | 93 | 5.4% (2.3 to 12.0), 5 of 93 |
| tranco_login (legit) | 165 | 41 | 4.9% (1.3 to 16.1), 2 of 41 |

## Page rules that fired (alive pages)

| Rule | phishing | legitimate |
|---|---|---|
| `page.brand_credential` | 19 | 1 |
| `page.brand_on_hosting` | 7 | 2 |
| `page.collection_endpoint` | 12 | 0 |
| `page.evasion` | 1 | 0 |
| `page.form_offsite` | 1 | 0 |
| `page.geofence` | 10 | 0 |
| `page.hosting_platform_login` | 17 | 0 |

Landing-address URL rules (the page moved to another site): phishing 2, legitimate 0.

## Page status

- phishing: {'ok': 109, 'http_403': 65, 'partial': 9, 'error': 4, 'http_404': 11, 'dead': 20, 'http_400': 1, 'http_410': 1, 'http_503': 3}
- legitimate: {'ok': 169, 'http_403': 31, 'partial': 18, 'dead': 98, 'http_404': 50, 'http_521': 1, 'http_500': 2, 'http_400': 1, 'http_405': 1}
- median time per page: phishing 5.1 s, legitimate 5.8 s
