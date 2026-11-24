# Re-check queue (DA5, Phase 3 item 1)

2026-11-24 07:30Z. Counts only. A stored address that a feed update lists is raised once (one alert per address and feed, one audit line, the old verdict untouched). The corpus is the 1,640 legitimate deep links of DA2, stored as pages in a throwaway database; the fake feed lists one unrelated address. The control lists one corpus address.

| case | count |
|---|---|
| scripted: alerts before the listing | 0 |
| scripted: alerts after the listing | 1 |
| scripted: alerts after rerun 1 (same list) | 1 |
| scripted: alerts after rerun 2 (snapshot lost) | 1 |
| scripted: alerts after rerun 3 (list grew) | 1 |
| scripted: audit lines | 1 |
| deep links: stored pages | 1,640 |
| deep links: feed entries | 1 |
| deep links: alerts | 0 |
| deep links: control: exact-address alerts | 1 |

RETRO GATE MET
