# Phishing that appeared after the model was fitted (DA4)

2026-11-22 15:35Z. Fresh files: openphish.txt (2026-11-22T15:33:00Z), phishtank.json.bz2 (2026-11-22T15:33:06Z). 43,227 addresses, of which 1,529 are on a registered domain that none of E1's data held and are kept. Intervals are Wilson 95%.

## The whole address engine, as the product runs it

| set | flagged (SUSPICIOUS or MALICIOUS) |
|---|---|
| E1 test split (feeds of 2026-11-10), PhishTank | 26.4% (25.7 to 27.2), 3720 of 14075 |
| E1 test split, OpenPhish | 70.7% (60.7 to 79.0), 65 of 92 |
| fresh feeds (2026-11-22), new domains, PhishTank | 58.0% (55.2 to 60.7), 723 of 1247 |
| fresh feeds, new domains, OpenPhish | 88.3% (84.0 to 91.5), 249 of 282 |

## The domain-name model alone

The fresh train part holds 770 domains; threshold at 0.4% of E1's calibration legitimate names for both.

| read on | fitted on E1 train only (threshold 0.9863) | fitted on E1 train and the fresh train part (threshold 0.9908) |
|---|---|---|
| fresh test domains | 61.3% (56.2 to 66.1), 226 of 369 | 63.4% (58.4 to 68.2), 234 of 369 |
| E1 test phishing | 49.4% (48.7 to 50.0), 10620 of 21504 | 49.5% (48.8 to 50.1), 10639 of 21504 |
| E1 test legitimate | 0.4% (0.3 to 0.4), 182 of 47307 | 0.4% (0.4 to 0.5), 209 of 47307 |
