# Page detonation on live pages (D1)

2026-11-22T20:27:11+00:00. Seed `lynceus-d1-2026-11-11`. **The test half is shown.** The URLs were split in two by a hash fixed before any page was opened, and rules may be changed only by looking at the dev half (dev, for comparison: phishing caught with the page 77.8% (65.1 to 86.8), 42 of 54; legitimate flagged 0.0% (0.0 to 4.5), 0 of 81). Every page was opened in the detonator container only (`docs/milestones/D1.md`); nothing was typed or submitted. URLs and per-URL rows stay in `.data/eval/d1/`; this report holds counts only. Intervals are Wilson 95%.

**Baseline = the URL rules alone, without the lists**: every phishing URL here comes from a list, so the lists would catch all of them by construction. The question is what the page adds for a phishing URL no list knows yet.

## Phishing (today's OpenPhish feed and the newest PhishTank entries)

| | Result |
|---|---|
| pages still alive | 24.6% (18.9 to 31.3), 45 of 183 |
| **caught, URL rules alone (alive pages)** | 60.0% (45.5 to 73.0), 27 of 45 |
| **caught, URL rules + page (alive pages)** | 68.9% (54.3 to 80.5), 31 of 45 |
| MALICIOUS with the page (alive pages) | 8.9% (3.5 to 20.7), 4 of 45 |
| caught only because of the page | 4 |
| alive pages with a password field | 15.6% (7.7 to 28.8), 7 of 45 |
| caught, all URLs (dead pages count as misses) | URL alone 80.3% (74.0 to 85.4), 147 of 183; with page 82.5% (76.4 to 87.3), 151 of 183 |

## Legitimate (brand home pages, a Tranco top-10,000 sample, and /login on another Tranco sample)

| | Result |
|---|---|
| pages alive | 53.2% (45.4 to 60.9), 83 of 156 |
| flagged, URL rules alone (alive) | 0.0% (0.0 to 4.4), 0 of 83 |
| **flagged, URL rules + page (alive)** | 1.2% (0.2 to 6.5), 1 of 83 |
| false alarms added by the page | 2 |
| **legitimate pages with a password form, flagged** | 7.1% (1.3 to 31.5), 1 of 14 |

## By source (alive pages, URL rules + page)

| Source | n | alive | flagged |
|---|---|---|---|
| openphish (phish) | 137 | 29 | 69.0% (50.8 to 82.7), 20 of 29 |
| phishtank (phish) | 46 | 16 | 68.8% (44.4 to 85.8), 11 of 16 |
| brand_home (legit) | 58 | 50 | 0.0% (0.0 to 7.1), 0 of 50 |
| tranco (legit) | 18 | 12 | 0.0% (0.0 to 24.2), 0 of 12 |
| tranco_login (legit) | 80 | 21 | 4.8% (0.8 to 22.7), 1 of 21 |

## DA1: what the deeper look adds, and what automatic opening would cost (test half)

| | phishing | legitimate |
|---|---|---|
| alive pages read on a second look (the first showed almost nothing) | 0.0% (0.0 to 7.9), 0 of 45 | 3.6% (1.2 to 10.1), 3 of 83 |
| ... of those, flagged | n/a (n=0) | 0.0% (0.0 to 56.1), 0 of 3 |
| `page.fresh_certificate` (evidence only, no weight) | 4.4% (1.2 to 14.8), 2 of 45 | 0.0% (0.0 to 4.4), 0 of 83 |
| would be opened automatically (address SUSPICIOUS, or UNKNOWN with a sign, not popular) | 76.5% (69.9 to 82.1), 140 of 183 | 0.6% (0.1 to 3.5), 1 of 156 |

## Page rules that fired (alive pages)

| Rule | phishing | legitimate |
|---|---|---|
| `page.brand_credential` | 4 | 1 |
| `page.brand_on_hosting` | 11 | 2 |
| `page.cloaked` | 1 | 0 |
| `page.collection_endpoint` | 4 | 0 |
| `page.fresh_certificate` | 2 | 0 |
| `page.geofence` | 4 | 0 |
| `page.hosting_platform_login` | 2 | 0 |

Landing-address URL rules (the page moved to another site): phishing 0, legitimate 0.

## Page status

- phishing: {'http_403': 101, 'ok': 44, 'dead': 30, 'partial': 1, 'http_451': 3, 'http_404': 2, 'error': 1, 'http_500': 1}
- legitimate: {'ok': 76, 'http_403': 16, 'partial': 7, 'error': 3, 'dead': 31, 'http_404': 21, 'http_521': 1, 'http_500': 1}
- median time per page: phishing 4.3 s, legitimate 8.9 s
