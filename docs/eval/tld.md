# Less dependence on a cheap ending? (DA4)

2026-11-22 15:46Z. Domain-name model only (no URL rules), fitted on E1's train split, threshold at 0.4% of the calibration domains' legitimate names for each variant, read on the test split. The ten endings most used by phishing in the train split: .com, .web.app, .firebaseapp.com, .repl.co, .net, .top, .r2.dev, .square.site, .xyz, .org. Intervals are Wilson 95%.

| test set | shipped (threshold 0.9863) | name only (threshold 0.9895) | swap to .com (threshold 0.99) | swap to common (threshold 0.9924) | swap both ways (threshold 0.9976) | either shipped or swap to .com (each at 0.2%) (threshold 0.9943) |
|---|---|---|---|---|---|---|
| PhishTank phishing, as it stands | 68.2% (66.8 to 69.6), 2865 of 4199 | 40.4% (38.9 to 41.9), 1697 of 4199 | 64.8% (63.3 to 66.2), 2719 of 4199 | 64.9% (63.5 to 66.3), 2726 of 4199 | 48.7% (47.2 to 50.2), 2045 of 4199 | 66.8% (65.4 to 68.2), 2806 of 4199 |
| OpenPhish phishing, as it stands | 50.0% (37.1 to 62.9), 27 of 54 | 46.3% (33.7 to 59.4), 25 of 54 | 51.8% (38.9 to 64.6), 28 of 54 | 50.0% (37.1 to 62.9), 27 of 54 | 51.8% (38.9 to 64.6), 28 of 54 | 50.0% (37.1 to 62.9), 27 of 54 |
| PhiUSIIL phishing, as it stands | 45.8% (45.0 to 46.5), 8109 of 17719 | 27.7% (27.1 to 28.4), 4916 of 17719 | 42.6% (41.9 to 43.4), 7557 of 17719 | 42.3% (41.6 to 43.1), 7501 of 17719 | 32.2% (31.5 to 32.9), 5698 of 17719 | 44.0% (43.2 to 44.7), 7788 of 17719 |
| all test phishing, as it stands | 49.4% (48.7 to 50.0), 10620 of 21504 | 30.0% (29.3 to 30.6), 6442 of 21504 | 46.2% (45.6 to 46.9), 9943 of 21504 | 46.0% (45.3 to 46.6), 9887 of 21504 | 35.3% (34.7 to 36.0), 7594 of 21504 | 47.7% (47.0 to 48.3), 10250 of 21504 |
| all test phishing, moved to .com | 17.0% (16.5 to 17.5), 3642 of 21479 | 30.0% (29.4 to 30.6), 6442 of 21479 | 32.6% (32.0 to 33.2), 6998 of 21479 | 23.9% (23.4 to 24.5), 5138 of 21479 | 29.1% (28.5 to 29.7), 6242 of 21479 | 28.1% (27.5 to 28.7), 6035 of 21479 |
| legitimate, as it stands | 0.4% (0.3 to 0.4), 182 of 47307 | 0.4% (0.3 to 0.4), 183 of 47307 | 0.5% (0.4 to 0.5), 219 of 47307 | 0.4% (0.3 to 0.4), 164 of 47307 | 0.4% (0.3 to 0.4), 184 of 47307 | 0.4% (0.3 to 0.4), 168 of 47307 |
| legitimate (8,000), moved to a cheap ending | 36.5% (35.4 to 37.5), 2917 of 7999 | 0.5% (0.4 to 0.7), 39 of 8000 | 16.1% (15.3 to 16.9), 1289 of 8000 | 19.3% (18.4 to 20.2), 1544 of 8000 | 0.2% (0.1 to 0.3), 13 of 8000 | 30.7% (29.7 to 31.7), 2453 of 7999 |
