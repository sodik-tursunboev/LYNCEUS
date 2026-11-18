# Domain age (RDAP) as a phishing signal (DA1)

2026-11-17 13:26Z. Seed `lynceus-da1-rdap`. One registered domain name per sample was sent to its registry through the product's RDAP provider; nothing else was sent. Public test data only (today's phishing feeds; Tranco ranks 100,001 to 1,000,000 as ordinary sites off the popular list; a few Tranco top-10,000 sites); never the owner's browsing. Shared hosting left out. Intervals are Wilson 95%.

## Did the registry answer with a date?

| set | domains | age known | no date or no record | failed or skipped |
|---|---|---|---|---|
| phish | 300 | 88.0% (83.8 to 91.2), 264 of 300 | 11 | 25 |
| legit_tail | 250 | 74.0% (68.2 to 79.0), 185 of 250 | 4 | 61 |
| legit_top | 50 | 96.0% (86.5 to 98.9), 48 of 50 | 0 | 2 |

## How young (of the domains with a known age)

| set | under 7 days | under 30 days | under 90 days | under 365 days |
|---|---|---|---|---|
| phish | 8.0% (5.3 to 11.9), 21 of 264 | 32.6% (27.2 to 38.4), 86 of 264 | 56.8% (50.8 to 62.7), 150 of 264 | 76.9% (71.4 to 81.6), 203 of 264 |
| legit_tail | 0.0% (0.0 to 2.0), 0 of 185 | 0.0% (0.0 to 2.0), 0 of 185 | 3.8% (1.8 to 7.6), 7 of 185 | 17.3% (12.5 to 23.4), 32 of 185 |
| legit_top | 0.0% (0.0 to 7.4), 0 of 48 | 0.0% (0.0 to 7.4), 0 of 48 | 0.0% (0.0 to 7.4), 0 of 48 | 4.2% (1.2 to 14.0), 2 of 48 |

## What it does to verdicts (today's weights: week 0.55, month 0.4, quarter 0.15)

| set | flagged by the address rules | flagged with domain age | newly flagged |
|---|---|---|---|
| phish | 49.0% (43.4 to 54.6), 147 of 300 | 53.0% (47.4 to 58.6), 159 of 300 | 12 |
| legit_tail | 2.4% (1.1 to 5.1), 6 of 250 | 2.4% (1.1 to 5.1), 6 of 250 | 0 |
| legit_top | 0.0% (0.0 to 7.1), 0 of 50 | 0.0% (0.0 to 7.1), 0 of 50 | 0 |

Provider status counts: {'OK': 512, 'UNAVAILABLE': 75, 'ERROR': 11, 'TIMEOUT': 1, 'skipped': 1}.
