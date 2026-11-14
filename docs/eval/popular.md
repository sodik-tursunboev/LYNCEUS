# Popular-domain list: before and after (H1 B1)

2026-11-13 22:59Z. List pinned to E1's Tranco copy, top 100,000 registered domains. Nothing was opened or fetched. Legitimate sets drawn from Tranco are cleared by construction and marked *circular*; read the other legitimate sets for the false-alarm change. Rules were changed by looking at D1 dev and E1 train only.

## D1: live pages, URL rules + page (alive pages)

| set | on popular domains | flagged before | flagged after | cleared | newly flagged |
|---|---|---|---|---|---|
| dev brand_home legit | 100.0% (90.8 to 100.0), 38 of 38 | 0.0% (0.0 to 9.2), 0 of 38 | 0.0% (0.0 to 9.2), 0 of 38 | 0 | 0 |
| dev openphish phish | 4.6% (1.8 to 11.2), 4 of 87 | 34.5% (25.3 to 44.9), 30 of 87 | 34.5% (25.3 to 44.9), 30 of 87 | 0 | 0 |
| dev phishtank phish | 10.0% (2.8 to 30.1), 2 of 20 | 30.0% (14.5 to 51.9), 6 of 20 | 30.0% (14.5 to 51.9), 6 of 20 | 0 | 0 |
| dev tranco legit (from Tranco: circular) | 98.2% (93.5 to 99.5), 106 of 108 | 2.8% (0.9 to 7.8), 3 of 108 | 1.8% (0.5 to 6.5), 2 of 108 | 1 | 0 |
| dev tranco_login legit (from Tranco: circular) | 97.5% (87.1 to 99.6), 39 of 40 | 5.0% (1.4 to 16.5), 2 of 40 | 0.0% (0.0 to 8.8), 0 of 40 | 2 | 0 |
| test brand_home legit | 96.1% (86.8 to 98.9), 49 of 51 | 0.0% (0.0 to 7.0), 0 of 51 | 0.0% (0.0 to 7.0), 0 of 51 | 0 | 0 |
| test openphish phish | 7.9% (3.9 to 15.4), 7 of 89 | 42.7% (32.9 to 53.1), 38 of 89 | 41.6% (31.9 to 51.9), 37 of 89 | 1 | 0 |
| test phishtank phish | 3.5% (0.6 to 17.2), 1 of 29 | 20.7% (9.8 to 38.4), 6 of 29 | 20.7% (9.8 to 38.4), 6 of 29 | 0 | 0 |
| test tranco legit (from Tranco: circular) | 100.0% (96.0 to 100.0), 93 of 93 | 5.4% (2.3 to 12.0), 5 of 93 | 0.0% (0.0 to 4.0), 0 of 93 | 5 | 0 |
| test tranco_login legit (from Tranco: circular) | 97.6% (87.4 to 99.6), 40 of 41 | 4.9% (1.4 to 16.1), 2 of 41 | 2.4% (0.4 to 12.6), 1 of 41 | 1 | 0 |

## E1: URL rules alone

| set | on popular domains | flagged before | flagged after | cleared | newly flagged |
|---|---|---|---|---|---|
| test edge_history legit | 78.8% (62.3 to 89.3), 26 of 33 | 0.0% (0.0 to 10.4), 0 of 33 | 0.0% (0.0 to 10.4), 0 of 33 | 0 | 0 |
| test openphish phish | 7.6% (3.7 to 14.9), 7 of 92 | 22.8% (15.4 to 32.4), 21 of 92 | 22.8% (15.4 to 32.4), 21 of 92 | 0 | 0 |
| test phishtank phish | 52.5% (51.7 to 53.3), 7390 of 14075 | 3.2% (2.9 to 3.5), 447 of 14075 | 3.2% (2.9 to 3.5), 445 of 14075 | 2 | 0 |
| test phiusiil legit | 10.0% (9.7 to 10.3), 4073 of 40685 | 0.1% (0.1 to 0.1), 27 of 40685 | 0.1% (0.0 to 0.1), 20 of 40685 | 7 | 0 |
| test phiusiil phish | 14.3% (13.9 to 14.7), 4312 of 30090 | 2.2% (2.0 to 2.4), 658 of 30090 | 2.2% (2.0 to 2.4), 657 of 30090 | 1 | 0 |
| test tranco legit (from Tranco: circular) | 99.3% (99.2 to 99.5), 14813 of 14911 | 1.0% (0.8 to 1.1), 146 of 14911 | 0.0% (0.0 to 0.0), 0 of 14911 | 146 | 0 |
| train edge_history legit | 67.9% (54.5 to 78.9), 36 of 53 | 0.0% (0.0 to 6.8), 0 of 53 | 0.0% (0.0 to 6.8), 0 of 53 | 0 | 0 |
| train openphish phish | 5.8% (3.1 to 10.2), 10 of 174 | 23.0% (17.4 to 29.8), 40 of 174 | 23.0% (17.4 to 29.8), 40 of 174 | 0 | 0 |
| train phishtank phish | 51.8% (51.2 to 52.4), 14706 of 28380 | 3.0% (2.9 to 3.3), 867 of 28380 | 3.0% (2.8 to 3.2), 857 of 28380 | 10 | 0 |
| train phiusiil legit | 10.2% (9.9 to 10.4), 8177 of 80573 | 0.1% (0.1 to 0.1), 61 of 80573 | 0.1% (0.0 to 0.1), 45 of 80573 | 16 | 0 |
| train phiusiil phish | 14.7% (14.4 to 15.0), 8884 of 60384 | 2.2% (2.1 to 2.3), 1317 of 60384 | 2.2% (2.1 to 2.3), 1312 of 60384 | 5 | 0 |
| train tranco legit (from Tranco: circular) | 99.3% (99.2 to 99.4), 29803 of 30009 | 0.9% (0.8 to 1.0), 271 of 30009 | 0.0% (0.0 to 0.0), 1 of 30009 | 270 | 0 |
