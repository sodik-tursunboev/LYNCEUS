# Domain age (RDAP) as a phishing signal (DA1)

2026-11-17 14:36Z. Seed `lynceus-da3-rdap-b`. One registered domain name per sample was sent to its registry through the product's RDAP provider; nothing else was sent. Public test data only (today's phishing feeds; Tranco ranks 100,001 to 1,000,000 as ordinary sites off the popular list; a few Tranco top-10,000 sites); never the owner's browsing. Shared hosting left out. Intervals are Wilson 95%.

## Did the registry answer with a date?

| set | domains | age known | no date or no record | failed or skipped |
|---|---|---|---|---|
| phish | 300 | 85.0% (80.5 to 88.6), 255 of 300 | 18 | 27 |
| legit_tail | 250 | 76.8% (71.2 to 81.6), 192 of 250 | 2 | 56 |
| legit_top | 50 | 0.0% (0.0 to 7.1), 0 of 50 | 0 | 50 |

## How young (of the domains with a known age)

| set | under 7 days | under 30 days | under 90 days | under 365 days |
|---|---|---|---|---|
| phish | 9.8% (6.7 to 14.1), 25 of 255 | 36.5% (30.8 to 42.5), 93 of 255 | 61.6% (55.5 to 67.3), 157 of 255 | 83.9% (78.9 to 87.9), 214 of 255 |
| legit_tail | 0.0% (0.0 to 2.0), 0 of 192 | 1.0% (0.3 to 3.7), 2 of 192 | 4.7% (2.5 to 8.7), 9 of 192 | 23.4% (18.0 to 29.9), 45 of 192 |
| legit_top | n/a (n=0) | n/a (n=0) | n/a (n=0) | n/a (n=0) |

## What it does to verdicts (today's weights: week 0.55, month 0.4, quarter 0.15)

| set | flagged by the address rules | flagged with domain age | newly flagged |
|---|---|---|---|
| phish | 51.7% (46.0 to 57.3), 155 of 300 | 54.7% (49.0 to 60.2), 164 of 300 | 9 |
| legit_tail | 4.8% (2.8 to 8.2), 12 of 250 | 4.8% (2.8 to 8.2), 12 of 250 | 0 |
| legit_top | 0.0% (0.0 to 7.1), 0 of 50 | 0.0% (0.0 to 7.1), 0 of 50 | 0 |

Provider status counts: {'OK': 467, 'UNAVAILABLE': 63, 'ERROR': 9, 'skipped': 61}.
