# Learned domain model (AI1 P1)

2026-11-14 00:32Z. Logistic regression on registered-domain features, 136,875 training domains, 6 epochs, seed `lynceus-ai1-p1`. Split by registered domain; threshold 0.9828 chosen on calibration domains (at most 0.5% of their legitimate hosts flagged). Test domains were never seen in training.

## Test domains (E1): the URL rules, the model, and either

| set | URL rules | model | rules or model |
|---|---|---|---|
| edge_history legit | 0.0% (0.0 to 10.7), 0 of 32 | 0.0% (0.0 to 10.7), 0 of 32 | 0.0% (0.0 to 10.7), 0 of 32 |
| openphish phish | 22.4% (14.5 to 32.9), 17 of 76 | 40.8% (30.4 to 52.0), 31 of 76 | 57.9% (46.7 to 68.3), 44 of 76 |
| phishtank phish | 1.6% (1.4 to 1.8), 270 of 17302 | 17.1% (16.6 to 17.7), 2960 of 17302 | 18.0% (17.4 to 18.6), 3117 of 17302 |
| phiusiil legit | 0.1% (0.1 to 0.1), 32 of 36365 | 0.3% (0.3 to 0.4), 121 of 36365 | 0.4% (0.4 to 0.5), 153 of 36365 |
| phiusiil phish | 1.8% (1.7 to 2.0), 484 of 26653 | 33.8% (33.2 to 34.4), 9008 of 26653 | 34.9% (34.3 to 35.5), 9297 of 26653 |
| tranco legit | 0.9% (0.8 to 1.1), 128 of 13457 | 0.8% (0.6 to 0.9), 101 of 13457 | 1.7% (1.5 to 1.9), 228 of 13457 |

## D1 live pages (2026-11-11), domains the model never saw

| set | URL rules | model |
|---|---|---|
| D1 phish (domains the model never saw) | 12.2% (9.2 to 16.0), 44 of 361 | 54.0% (48.9 to 59.1), 195 of 361 |
| D1 legit (domains the model never saw) | 3.1% (1.6 to 6.0), 8 of 259 | 0.8% (0.2 to 2.8), 2 of 259 |

Your browsing (never trained on), flagged by the model: 0.0% (0.0 to 4.3), 0 of 86.
