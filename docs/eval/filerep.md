# File reputation at VirusTotal (DA2)

2026-11-17 14:36Z. Seed `lynceus-da2-filerep`. Thresholds in force: {'vt_certain': 10, 'vt_flagged': 4, 'vt_flagged_weight': 0.6, 'vt_weak_weight': 0.1}. Only SHA-256 hashes were asked about: clean = Microsoft-made programs from this computer's Windows folders (the same on every Windows computer of that version); malware = a sample of the recent MalwareBazaar hashes in the local known-bad list. Intervals are Wilson 95%.

| | clean programs | recent malware hashes |
|---|---|---|
| hashes asked | 100 | 100 |
| VirusTotal had a report | 100 | 97 |
| no report (never seen) | 0 | 3 |
| lookup failed | 0 | 0 |
| engines flagging: breakdown (of reports) | {'0 engines': 100} | {'malicious tier': 84, 'weak (1 to 3)': 4, 'flagged tier': 5, '0 engines': 4} |
| at or above the flagged tier | 0.0% (0.0 to 3.7), 0 of 100 | 91.8% (84.6 to 95.8), 89 of 97 |
| at or above the malicious tier | 0.0% (0.0 to 3.7), 0 of 100 | 86.6% (78.4 to 92.0), 84 of 97 |
| most engines flagging any one clean program | 0 | |
