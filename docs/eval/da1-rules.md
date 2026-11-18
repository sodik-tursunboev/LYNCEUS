# DA1: the typosquat and brand-in-domain changes on E1's test split

2026-11-17 15:11Z. **A** = before DA1. **B** = typosquat tightened. **C** = typosquat and brand-in-domain tightened (shipped). Flagged means SUSPICIOUS or MALICIOUS from the address alone, with the learned model and the popular-domain list on. The changes were chosen on the train split; this is the first time they meet the test split. Intervals are Wilson 95%.

| set | flagged A | flagged B | flagged C | typosquat hits A to C | brand_in_domain hits A to C |
|---|---|---|---|---|---|
| edge_history legit | 0.00% (0.00 to 9.64), 0 of 36 | 0.00% (0.00 to 9.64), 0 of 36 | 0.00% (0.00 to 9.64), 0 of 36 | 0 to 0 | 0 to 0 |
| openphish phish | 70.65% (60.67 to 78.98), 65 of 92 | 70.65% (60.67 to 78.98), 65 of 92 | 70.65% (60.67 to 78.98), 65 of 92 | 12 to 12 | 11 to 11 |
| phishtank phish | 26.44% (25.71 to 27.17), 3721 of 14075 | 26.43% (25.71 to 27.16), 3720 of 14075 | 26.43% (25.71 to 27.16), 3720 of 14075 | 14 to 13 | 75 to 73 |
| phiusiil legit | 0.14% (0.11 to 0.18), 56 of 40685 | 0.12% (0.10 to 0.17), 51 of 40685 | 0.12% (0.10 to 0.17), 51 of 40685 | 20 to 15 | 79 to 57 |
| phiusiil phish | 37.73% (37.18 to 38.28), 11352 of 30090 | 37.71% (37.16 to 38.26), 11347 of 30090 | 37.71% (37.16 to 38.26), 11347 of 30090 | 82 to 77 | 496 to 482 |
| tranco legit | 0.00% (0.00 to 0.03), 0 of 14911 | 0.00% (0.00 to 0.03), 0 of 14911 | 0.00% (0.00 to 0.03), 0 of 14911 | 0 to 0 | 0 to 0 |
