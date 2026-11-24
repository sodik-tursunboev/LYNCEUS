# Incident view: gate (DA5 phase 3, item 2)

Counts only, from `python -m eval.incidents check` on scripted timelines in a throwaway
database, inserted in a shuffled order. No host, address or hash is recorded here.

| What | Count |
|---|---|
| chains seeded (mail link, click, download; eight orders and shapes) | 8 |
| chains found as one incident with exactly their members | 8 |
| labelled edges expected | 20 |
| labelled edges found | 20 |
| edges found that were not expected | 0 |
| edges without a label | 0 |
|   by mail link and click (same URL hash) | 9 |
|   by download origin (same host tag, inside the gap) | 10 |
|   by the same file seen again (same SHA-256) | 1 |
| benign-only timelines seeded | 6 |
| incidents made by them | 0 |
| decoy timelines seeded | 6 |
| decoy events in them | 24 |
| incidents made by decoys | 0 |
| incidents returned in all | 8 |
| reads that changed a stored row (every table compared before and after) | 0 |

Result: INCIDENT GATE MET
