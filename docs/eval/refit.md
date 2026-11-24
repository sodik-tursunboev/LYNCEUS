# DA5 1e: the learned model refitted on fresher feeds, measured in the whole engine

2026-11-22 20:30Z. Candidate fitted on E1's train split plus 770 fresh train-part phishing domains (feeds of 2026-11-22), threshold 0.9908 at 0.4% of E1's calibration legitimate names. Flagged means SUSPICIOUS or MALICIOUS from the address alone, the engine as shipped (ranked tier and the two narrowed conditions on). The candidate is NOT adopted by this tool. Intervals are Wilson 95%.

| set | flagged, shipped model | flagged, candidate |
|---|---|---|
| E1 test: openphish phish | 69.56% (59.54 to 78.03), 64 of 92 | 71.74% (61.81 to 79.92), 66 of 92 |
| E1 test: phishtank phish | 26.32% (25.60 to 27.05), 3704 of 14075 | 26.84% (26.12 to 27.58), 3778 of 14075 |
| E1 test: phiusiil legit | 0.11% (0.08 to 0.14), 44 of 40685 | 0.13% (0.10 to 0.17), 53 of 40685 |
| E1 test: phiusiil phish | 37.51% (36.96 to 38.06), 11287 of 30090 | 38.23% (37.68 to 38.78), 11503 of 30090 |
| E1 test: tranco legit | 0.00% (0.00 to 0.03), 0 of 14911 | 0.00% (0.00 to 0.03), 0 of 14911 |
| deep links, dev half | 1.72% (1.01 to 2.92), 13 of 757 | 1.85% (1.10 to 3.08), 14 of 757 |
| deep links, test half | 1.13% (0.62 to 2.07), 10 of 883 | 1.13% (0.62 to 2.07), 10 of 883 |
| fresh feeds, phishing on the fresh TEST part | 64.56% (60.09 to 68.80), 297 of 460 | 66.96% (62.53 to 71.10), 308 of 460 |
| long tail, 3,000 home pages (Tranco 100,001 to 1M) | 0.10% (0.03 to 0.29), 3 of 3000 | 0.10% (0.03 to 0.29), 3 of 3000 |
| your browsing (all) | 0.00% (0.00 to 3.81), 0 of 97 | 0.00% (0.00 to 3.81), 0 of 97 |
