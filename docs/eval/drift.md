# Does the learned model age? (DA3)

2026-11-18 11:14Z. Domain-name model only (no URL rules), same test domains for both models, threshold at 0.4% of the calibration domains' legitimate names for each. The older model has never seen a 2026 feed. Intervals are Wilson 95%.

| test set | shipped (all sources) (threshold 0.9863) | older (PhiUSIIL and Tranco only) (threshold 0.9943) |
|---|---|---|
| PhishTank phishing (2026) | 68.2% (66.8 to 69.6), 2865 of 4199 | 55.1% (53.6 to 56.6), 2315 of 4199 |
| OpenPhish phishing (2026) | 50.0% (37.1 to 62.9), 27 of 54 | 44.4% (32.0 to 57.6), 24 of 54 |
| PhiUSIIL phishing (2024) | 45.8% (45.0 to 46.5), 8109 of 17719 | 44.2% (43.5 to 45.0), 7838 of 17719 |
| legitimate (Tranco and PhiUSIIL) | 0.4% (0.3 to 0.4), 182 of 47307 | 0.4% (0.3 to 0.4), 169 of 47307 |
