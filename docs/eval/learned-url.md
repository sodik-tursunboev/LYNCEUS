# Learned domain model (AI1 P1; model 2 since DA1)

2026-11-17 15:17Z. Logistic regression on registered-domain features, 136,875 training domains, 6 epochs, seed `lynceus-ai1-p1`. Split by registered domain; test domains were never seen in training. Threshold 0.9881, chosen on the calibration domains (at most 0.4% of their legitimate hosts above it). Flagged means SUSPICIOUS or MALICIOUS from the address alone, without the popular-domain list. Intervals are Wilson 95%.

| set | URL rules alone | model alone | the product with this model |
|---|---|---|---|
| phiusiil legit | 0.1% (0.1 to 0.1), 27 of 36365 | 0.2% (0.2 to 0.3), 85 of 36365 | 0.3% (0.3 to 0.4), 114 of 36365 |
| phiusiil phish | 1.8% (1.7 to 2.0), 480 of 26653 | 34.3% (33.7 to 34.9), 9141 of 26653 | 35.4% (34.8 to 36.0), 9442 of 26653 |
| phishtank phish | 1.5% (1.4 to 1.7), 267 of 17302 | 17.6% (17.0 to 18.1), 3038 of 17302 | 18.5% (17.9 to 19.1), 3195 of 17302 |
| openphish phish | 22.4% (14.5 to 32.9), 17 of 76 | 40.8% (30.4 to 52.0), 31 of 76 | 57.9% (46.7 to 68.3), 44 of 76 |
| tranco legit | 0.9% (0.7 to 1.0), 116 of 13457 | 0.7% (0.5 to 0.8), 90 of 13457 | 1.5% (1.3 to 1.8), 206 of 13457 |
| edge_history legit | 0.0% (0.0 to 10.7), 0 of 32 | 0.0% (0.0 to 10.7), 0 of 32 | 0.0% (0.0 to 10.7), 0 of 32 |
| long-tail sites (Tranco 100,001 to 1M, home pages) | 0.1% (0.0 to 0.3), 3 of 3000 | 2.3% (1.8 to 2.9), 69 of 3000 | 2.4% (1.9 to 3.0), 72 of 3000 |
| D1 live phish pages, address only (domains never seen) | 12.2% (9.2 to 16.0), 44 of 361 | 56.5% (51.3 to 61.5), 204 of 361 | 61.5% (56.4 to 66.4), 222 of 361 |
| D1 live legit pages, address only (domains never seen) | 3.1% (1.6 to 6.0), 8 of 259 | 0.8% (0.2 to 2.8), 2 of 259 | 3.5% (1.8 to 6.5), 9 of 259 |
| your browsing (never trained on) | 0.0% (0.0 to 4.0), 0 of 92 | 0.0% (0.0 to 4.0), 0 of 92 | 0.0% (0.0 to 4.0), 0 of 92 |
